// +build seccomp

package seccomp

import (
	"github.com/pkg/errors"
	libseccomp "github.com/seccomp/libseccomp-golang"
	"golang.org/x/sys/unix"
)

// BuildFilter does a basic validation for the provided seccomp profile
// string and returns a filter for it.
func BuildFilter(profile *Seccomp) (*libseccomp.ScmpFilter, error) {
	defaultAction, err := toAction(profile.DefaultAction, nil)
	if err != nil {
		return nil, errors.Wrapf(err, "convert default action %s", profile.DefaultAction)
	}

	filter, err := libseccomp.NewFilter(defaultAction)
	if err != nil {
		return nil, errors.Wrapf(err, "create filter for default action %s", defaultAction)
	}

	// Add extra architectures
	for _, arch := range profile.Architectures {
		scmpArch, err := libseccomp.GetArchFromString(string(arch))
		if err != nil {
			return nil, errors.Wrapf(err, "validate Seccomp architecture %s", arch)
		}

		if err := filter.AddArch(scmpArch); err != nil {
			return nil, errors.Wrap(err, "add architecture to seccomp filter")
		}
	}

	// Unset no new privs bit
	if err := filter.SetNoNewPrivsBit(false); err != nil {
		return nil, errors.Wrap(err, "set no new privileges flag")
	}

	// Add a rule for each syscall
	for _, call := range profile.Syscalls {
		if call == nil {
			return nil, errors.New("encountered nil syscall while initializing seccomp")
		}

		if err = matchSyscall(filter, call); err != nil {
			return nil, errors.Wrap(err, "filter matches syscall")
		}
	}

	return filter, nil
}

func matchSyscall(filter *libseccomp.ScmpFilter, call *Syscall) error {
	if call == nil || filter == nil {
		return errors.New("cannot use nil as syscall to block")
	}

	if len(call.Name) == 0 {
		return errors.New("empty string is not a valid syscall")
	}

	// If we can't resolve the syscall, assume it's not supported on this kernel
	// Ignore it, don't error out
	callNum, err := libseccomp.GetSyscallFromName(call.Name)
	if err != nil {
		return nil
	}

	// Convert the call's action to the libseccomp equivalent
	callAct, err := toAction(call.Action, call.ErrnoRet)
	if err != nil {
		return errors.Wrapf(err, "convert action %s", call.Action)
	}

	// Unconditional match - just add the rule
	if len(call.Args) == 0 {
		if err = filter.AddRule(callNum, callAct); err != nil {
			return errors.Wrapf(err, "add seccomp filter rule for syscall %s", call.Name)
		}
	} else {
		// Linux system calls can have at most 6 arguments
		const syscallMaxArguments int = 6

		// If two or more arguments have the same condition,
		// Revert to old behavior, adding each condition as a separate rule
		argCounts := make([]uint, syscallMaxArguments)
		conditions := []libseccomp.ScmpCondition{}

		for _, cond := range call.Args {
			newCond, err := toCondition(cond)
			if err != nil {
				return errors.Wrapf(err, "create seccomp syscall condition for syscall %s", call.Name)
			}

			argCounts[cond.Index] += 1

			conditions = append(conditions, newCond)
		}

		hasMultipleArgs := false
		for _, count := range argCounts {
			if count > 1 {
				hasMultipleArgs = true
				break
			}
		}

		if hasMultipleArgs {
			// Revert to old behavior
			// Add each condition attached to a separate rule
			for _, cond := range conditions {
				condArr := []libseccomp.ScmpCondition{cond}

				if err = filter.AddRuleConditional(callNum, callAct, condArr); err != nil {
					return errors.Wrapf(err, "add seccomp rule for syscall %s", call.Name)
				}
			}
		} else {
			// No conditions share same argument
			// Use new, proper behavior
			if err = filter.AddRuleConditional(callNum, callAct, conditions); err != nil {
				return errors.Wrapf(err, "add seccomp rule for syscall %s", call.Name)
			}
		}
	}

	return nil
}

// toAction converts an internal `Action` type to a `libseccomp.ScmpAction`
// type.
func toAction(act Action, errnoRet *uint) (libseccomp.ScmpAction, error) {
	switch act {
	case ActKill:
		return libseccomp.ActKill, nil
	case ActKillProcess:
		return libseccomp.ActKillProcess, nil
	case ActErrno:
		if errnoRet != nil {
			return libseccomp.ActErrno.SetReturnCode(int16(*errnoRet)), nil
		}
		return libseccomp.ActErrno.SetReturnCode(int16(unix.EPERM)), nil
	case ActTrap:
		return libseccomp.ActTrap, nil
	case ActAllow:
		return libseccomp.ActAllow, nil
	case ActTrace:
		if errnoRet != nil {
			return libseccomp.ActTrace.SetReturnCode(int16(*errnoRet)), nil
		}
		return libseccomp.ActTrace.SetReturnCode(int16(unix.EPERM)), nil
	case ActLog:
		return libseccomp.ActLog, nil
	default:
		return libseccomp.ActInvalid, errors.Errorf("invalid action %s", act)
	}
}

// toCondition converts an internal `Arg` type to a `libseccomp.ScmpCondition`
// type.
func toCondition(arg *Arg) (cond libseccomp.ScmpCondition, err error) {
	if arg == nil {
		return cond, errors.New("cannot convert nil to syscall condition")
	}

	op, err := toCompareOp(arg.Op)
	if err != nil {
		return cond, errors.Wrap(err, "convert compare operator")
	}

	condition, err := libseccomp.MakeCondition(
		arg.Index, op, arg.Value, arg.ValueTwo,
	)
	if err != nil {
		return cond, errors.Wrap(err, "make condition")
	}

	return condition, nil
}

// toCompareOp converts an internal `Operator` type to a
// `libseccomp.ScmpCompareOp`.
func toCompareOp(op Operator) (libseccomp.ScmpCompareOp, error) {
	switch op {
	case OpEqualTo:
		return libseccomp.CompareEqual, nil
	case OpNotEqual:
		return libseccomp.CompareNotEqual, nil
	case OpGreaterThan:
		return libseccomp.CompareGreater, nil
	case OpGreaterEqual:
		return libseccomp.CompareGreaterEqual, nil
	case OpLessThan:
		return libseccomp.CompareLess, nil
	case OpLessEqual:
		return libseccomp.CompareLessOrEqual, nil
	case OpMaskedEqual:
		return libseccomp.CompareMaskedEqual, nil
	default:
		return libseccomp.CompareInvalid, errors.Errorf("invalid operator %s", op)
	}
}
