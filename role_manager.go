// Copyright 2018 The casbin Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package auth0rolemanager

import (
	"errors"

	"github.com/auth0/go-auth0/management"
	"github.com/casbin/casbin/log"
	"github.com/casbin/casbin/rbac"
)

type RoleManager struct {
	clientID     string
	clientSecret string
	tenant       string

	nameToIDMap map[string]string
	idToNameMap map[string]string

	mgmtClient *management.Management
	//authzClient *auth0.Auth0
}

// NewRoleManager is the constructor of an Auth0 RoleManager instance.
// clientID is the Client ID.
// clientSecret is the Client Secret.
// tenant is your tenant name. If your domain is: abc.auth0.com, then abc is your tenant name.
func NewRoleManager(clientID string, clientSecret string, tenant string) rbac.RoleManager {
	rm := RoleManager{}
	rm.clientID = clientID
	rm.clientSecret = clientSecret
	rm.tenant = tenant

	rm.nameToIDMap = map[string]string{}
	rm.idToNameMap = map[string]string{}

	err := rm.initialize()
	if err != nil {
		panic(err)
	}
	rm.loadMapping()

	return &rm
}

func (rm *RoleManager) initialize() error {
	var err error
	rm.mgmtClient, err = management.New(
		rm.tenant,
		management.WithClientCredentials(rm.clientID, rm.clientSecret),
	)

	return err
}

func pager[T any](f func(...management.RequestOption) (T, error), pageNum int) (T, int, error) {
	list, err := f(management.Page(pageNum), management.PerPage(100))
	return list, pageNum + 1, err
}

func (rm *RoleManager) loadMapping() {
	log.LogPrintf("Loading (ID, name) mapping for users:")

	usersFun := rm.mgmtClient.User.List
	for p := 0; ; p++ {
		users, _, err := pager(usersFun, p)
		if err != nil {
			log.LogPrintf("Error loading users: '%v'", err)
			return
		}

		for _, user := range users.Users {
			rm.nameToIDMap[*user.Email] = *user.ID
			rm.idToNameMap[*user.ID] = *user.Email
			log.LogPrintf("%s -> %s", user.ID, user.Email)
		}
		if !users.HasNext() {
			break
		}
	}

	log.LogPrintf("Loading (ID, name) mapping for roles:")
	rolesFun := rm.mgmtClient.Role.List
	for p := 0; ; p++ {
		roles, _, err := pager(rolesFun, p)
		if err != nil {
			log.LogPrintf("Error loading roles: '%v'", err)
			return
		}
		for _, group := range roles.Roles {
			rm.nameToIDMap[*group.Name] = *group.ID
			rm.idToNameMap[*group.ID] = *group.Name
			log.LogPrintf("%s -> %s", group.ID, group.Name)
		}
		if !roles.HasNext() {
			break
		}

	}
}

func (rm *RoleManager) getAuth0UserGroups(name string) ([]string, error) {
	res := []string{}

	if _, ok := rm.nameToIDMap[name]; !ok {
		return nil, errors.New("ID not found for the user")
	}

	f := func(opts ...management.RequestOption) (*management.RoleList, error) {
		return rm.mgmtClient.User.Roles(rm.nameToIDMap[name], opts...)
	}

	for p := 0; ; p++ {
		roles, _, err := pager(f, p)
		if err != nil {
			return nil, err
		}
		for _, role := range roles.Roles {
			res = append(res, *role.Name)
		}
		if !roles.HasNext() {
			break
		}
	}
	return res, nil
}

func (rm *RoleManager) getAuth0GroupUsers(name string) ([]string, error) {
	res := []string{}

	if _, ok := rm.nameToIDMap[name]; !ok {
		return nil, errors.New("ID not found for the role")
	}

	f := func(opts ...management.RequestOption) (*management.UserList, error) {
		return rm.mgmtClient.Role.Users(rm.nameToIDMap[name], opts...)
	}
	for p := 0; ; p++ {
		users, _, err := pager(f, 0)
		if err != nil {
			return nil, err
		}

		for _, user := range users.Users {
			res = append(res, *user.Email)
		}
		if !users.HasNext() {
			break
		}
	}

	return res, nil
}

// Clear clears all stored data and resets the role manager to the initial state.
func (rm *RoleManager) Clear() error {
	return nil
}

// AddLink adds the inheritance link between role: name1 and role: name2.
// domain is not used.
func (rm *RoleManager) AddLink(_ string, _ string, _ ...string) error {
	return errors.New("not implemented")
}

// DeleteLink deletes the inheritance link between role: name1 and role: name2.
// domain is not used.
func (rm *RoleManager) DeleteLink(_ string, _ string, _ ...string) error {
	return errors.New("not implemented")
}

// HasLink determines whether role: name1 inherits role: name2.
// domain is not used.
func (rm *RoleManager) HasLink(name1 string, name2 string, domain ...string) (bool, error) {
	if len(domain) >= 1 {
		return false, errors.New("error: domain should not be used")
	}

	roles, err := rm.GetRoles(name1)
	if err != nil {
		return false, err
	}

	for _, role := range roles {
		if role == name2 {
			return true, nil
		}
	}
	return false, nil
}

// GetRoles gets the roles that a subject inherits.
// domain is not used.
func (rm *RoleManager) GetRoles(name string, domain ...string) ([]string, error) {
	if len(domain) >= 1 {
		return nil, errors.New("error: domain should not be used")
	}

	return rm.getAuth0UserGroups(name)
}

// GetUsers gets the users that inherits a subject.
// domain is not used.
func (rm *RoleManager) GetUsers(name string, domain ...string) ([]string, error) {
	if len(domain) >= 1 {
		return nil, errors.New("error: domain should not be used")
	}

	return rm.getAuth0GroupUsers(name)
}

// PrintRoles prints all the roles to log.
func (rm *RoleManager) PrintRoles() error {
	return errors.New("not implemented")
}
