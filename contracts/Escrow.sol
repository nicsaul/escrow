// SPDX-License-Identifier: GPL-3.0

pragma solidity >=0.8.0 <0.9.0;


import './openzeppelin/token/ERC20/utils/SafeERC20.sol';
import "./openzeppelin/access/AccessControl.sol";
import "./openzeppelin/access/AccessControlEnumerable.sol";
import "./openzeppelin/security/ReentrancyGuard.sol";
import "./openzeppelin/utils/Address.sol";

// https://docs.openzeppelin.com/contracts/3.x/api/access#TimelockController
contract EscrowFactory is AccessControlEnumerable, ReentrancyGuard {
	using Address for address payable;
	using SafeERC20 for IERC20;

	bytes32 public constant JUDGE_ROLE = keccak256("JUDGE_ROLE");

	event VaultChanged(address indexed admin, address indexed vault);
	event Withdrawn(address indexed admin, uint256 amount);
	event FeeChanged(address indexed admin, uint256 indexed fee);
	event DisputeDurationChanged(address indexed admin, uint256 indexed duration);
	event EscrowCreated();

	address payable private vault;
	uint256 public fee;
	uint256 public disputeDuration; // seconds

	mapping(address => address[]) private payeeToEscrow;
	mapping(address => address[]) private payerToEscrow;

	constructor(
		uint256 _fee,
		address payable _vault,
		uint256 _duration,
		uint256 _disputeDuration
	) {
		require(_fee > 0 && _fee < 99, "fee must be between 1 and 99");
		require(_duration > 0, "duration must be positive");
		require(_disputeDuration > 0, "disputeDuration must be positive");

		vault = _vault;
		fee = _fee;
		disputeDuration = _disputeDuration;

		_setupRole(DEFAULT_ADMIN_ROLE, msg.sender);
		_setupRole(DEFAULT_ADMIN_ROLE, address(this));
	}

	function getJudges() public view returns (address[] memory) {
		address[] memory judges;
		for (uint256 i = 0; i < getRoleMemberCount(JUDGE_ROLE); ++i) {
			judges[i] = getRoleMember(JUDGE_ROLE, i);
		}
		return judges;
	}

	function _create(
		address payable payee,
		uint256 amount,
		address token,
		uint256 duration
	) public payable nonReentrant returns (address) {
		require(amount > 0, "Amount must be positive");
		require(duration > 0, "Duration must be positive");
		require(getRoleMemberCount(JUDGE_ROLE) > 0, "No judges registered");
		address[] memory judges = getJudges();
		address payable payer = payable(msg.sender);

		uint256 allowance = IERC20(token).allowance(msg.sender, address(this));
		require(allowance >= amount, "Check the token allowance");

		Escrow escrow = new Escrow (
			token,
			payer,
			payee,
			vault,
			judges,
			duration,
			disputeDuration,
			fee
		);

		IERC20(token).safeTransferFrom(msg.sender, address(escrow), amount);

		payeeToEscrow[payee].push(address(escrow));
		payerToEscrow[payer].push(address(escrow));

		emit EscrowCreated(); // add stuff
	}

	// admin only, get remaining balance
	function withdraw() external onlyRole(DEFAULT_ADMIN_ROLE) {
		uint256 balance = address(this).balance;
		vault.sendValue(balance);
		emit Withdrawn(msg.sender, balance);
	}

	// admin only, changes vault address
	function setVault(address payable newVault)
		external
		onlyRole(DEFAULT_ADMIN_ROLE)
	{
		require(vault != newVault, "Cannot change for current vault");
		vault = newVault;
		emit VaultChanged(msg.sender, newVault);
	}

	// admin only, changes fee for future created escrows
	function setFee(uint256 newFee) external onlyRole(DEFAULT_ADMIN_ROLE) {
		require(newFee > 0 && newFee < 99, "fee must be between 1 and 99");
		require(fee != newFee, "Cannot change for current fee");
		fee = newFee;
		emit FeeChanged(msg.sender,fee);
	}

	function setDisputeDuration(uint256 newDisputeDuration)
		external
		onlyRole(DEFAULT_ADMIN_ROLE)
	{
		require(newDisputeDuration > 0, "newDisputeDuration must be positive");
		disputeDuration = newDisputeDuration;
		emit DisputeDurationChanged(msg.sender, disputeDuration);
	}
}

contract Escrow is AccessControl, ReentrancyGuard {
	using Address for address payable;

	event Created(
		address indexed payee,
		address indexed payer,
		uint256 date,
		address indexed token,
		uint256 amount
	);
	event Disputed(address indexed payer, uint256 date);
	event Released(
		address indexed payee,
		address indexed judge,
		address indexed token,
		uint256 amount,
		uint256 fee
	);
	event Refunded(
		address indexed payer,
		address indexed judge,
		address indexed token,
		uint256 amount
	);
	event Closed(
		address indexed vault,
		address indexed judge,
		address indexed token,
		uint256 amount
	);

	enum State {
		PENDING,
		RELEASED,
		REFUNDED,
		DISPUTED,
		CLOSED
	}

	bytes32 public constant JUDGE_ROLE = keccak256("JUDGE_ROLE");

	address public token;
	address payable public payee; // seller
	address payable public payer; // buyer
	address payable private vault; // multisig
	uint256 public vaultFee;
	uint256 public dueDate;
	uint256 public dueDateToDispute;

	State public state;

	constructor(
		address _token,
		address payable _payer,
		address payable _payee,
		address payable _vault,
		address[] memory _judges,
		uint256 _duration, // seconds
		uint256 _disputeDuration, // seconds
		uint256 _vaultFee
	) payable {
		require(msg.value > 0, "Value should be greater than 0");
		require(_judges.length > 0, "No judges");

		_setupRole(DEFAULT_ADMIN_ROLE, msg.sender);
		_setupRole(DEFAULT_ADMIN_ROLE, address(this));

		for (uint256 i = 0; i < _judges.length; ++i) {
			_setupRole(JUDGE_ROLE, _judges[i]);
		}

		state = State.PENDING;

		token = _token;
		payer = _payer;
		payee = _payee;
		vault = _vault;
		vaultFee = _vaultFee;

		dueDate = block.timestamp + _duration;
		dueDateToDispute = dueDate + _disputeDuration;
	}

	modifier notDisputed() {
		require(state != State.DISPUTED, "Escrow has been disputed");
		_;
	}

	modifier onlyPendingOrDisputed() {
		require(
			state == State.PENDING || state == State.DISPUTED,
			"State must be pending"
		);
		_;
	}

	function dispute() external nonReentrant {
		require(msg.sender == payer, "Only payer can execute");
		require(
			block.timestamp > dueDate,
			"Can only dispute after escrow expired"
		);
		require(block.timestamp < dueDateToDispute, "dispute period is over");
		state = State.DISPUTED;
		// emit event
	}

	function claim() external nonReentrant notDisputed {
		require(
			block.timestamp > dueDateToDispute,
			"Can only claim funds after disputing period ends"
		);
		// require(isDisputed == false, "Escrow has been disputed");
		require(msg.sender == payee, "Only payee can execute");
		_release();
	}

	function release()
		external
		onlyRole(JUDGE_ROLE)
		onlyPendingOrDisputed
		nonReentrant
	{
		_release();
	}

	function _release() private {
		uint256 balance = address(this).balance;
		uint256 fee = (balance * vaultFee) / 100;
		uint256 value = balance - fee;
		vault.sendValue(fee);
		payee.sendValue(value);
		state = State.RELEASED;
		// emit event
	}

	function refund()
		external
		onlyRole(JUDGE_ROLE)
		onlyPendingOrDisputed
		nonReentrant
	{
		// no requiere?
		payer.sendValue(address(this).balance);
		state = State.REFUNDED;
		// emit event
	}

	function close()
		external
		onlyRole(DEFAULT_ADMIN_ROLE)
		onlyPendingOrDisputed
		nonReentrant
	{
		uint256 balance = address(this).balance;
		vault.sendValue(balance);
		state = State.CLOSED;
		// emit event
	}

	function balanceOf() public view returns (uint256) {
		return address(this).balance;
	}
}
