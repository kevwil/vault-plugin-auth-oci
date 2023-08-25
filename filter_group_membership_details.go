// Copyright © 2019, Oracle and/or its affiliates.

package ociauth

import "github.com/oracle/oci-go-sdk/v65/common"

// Do not edit this file. This is based on standard OCI GO SDK format

// FilterGroupMembershipDetails stores the Principal and list of Group or Dynamic Group Ids required for the filtering request
type FilterGroupMembershipDetails struct {
	Principal Principal `json:"principal"`
	GroupIds  []string  `json:"groupIds"`
}

// Prints the values of pointers in FilterGroupMembershipDetails,
// producing a human friendly string for a struct with pointers. Useful when debugging the values of a struct.
func (m FilterGroupMembershipDetails) String() string {
	return common.PointerString(m)
}
