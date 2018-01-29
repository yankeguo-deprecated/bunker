/**
 * utils/common.go
 *
 * Copyright (c) 2018 Yanke Guo <guoyk.cn@gmail.com>
 *
 * This software is released under the MIT License.
 * https://opensource.org/licenses/MIT
 */

package utils

// ComposedError a error composed by multiple errors
type ComposedError struct {
	Errors []error
}

// ComposeError create a ComposedError from multiple errors, if all errors are nil, nil returned
func ComposeError(errs ...error) (c *ComposedError) {
	for _, err := range errs {
		if err != nil {
			if c == nil {
				c = &ComposedError{Errors: make([]error, 0)}
			}
			c.Errors = append(c.Errors, err)
		}
	}
	return
}

func (e *ComposedError) Error() (str string) {
	for _, err := range e.Errors {
		str = str + err.Error() + ";"
	}
	return
}
