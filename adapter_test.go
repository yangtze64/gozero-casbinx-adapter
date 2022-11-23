package casbinx

import (
	"fmt"
	"github.com/casbin/casbin/v2"
	"github.com/casbin/casbin/v2/model"
	"github.com/zeromicro/go-zero/core/stores/sqlx"
	"testing"
)

var (
	mysqlConn = sqlx.NewMysql("root:123456@tcp(127.0.0.1:3307)/hp_ims")
	adapter   = NewAdapter(mysqlConn)
	m, _      = model.NewModelFromString(RBAC_deny_restful)
	csb, _    = casbin.NewEnforcer(m, adapter)
)

func TestPolicy(t *testing.T) {

	//err := csb.LoadFilteredPolicy(&Filter{
	//	Ptype: []string{
	//		"p",
	//	},
	//	V0: []string{
	//		"YCJ", "YCJ1",
	//	},
	//	V2: []string{
	//		"GET", "POST",
	//	},
	//})
	//if err != nil {
	//	t.Error(err)
	//}
	//
	//policy := csb.GetPolicy()
	//fmt.Println(policy)

	err := csb.LoadPolicy()
	if err != nil {
		t.Error(err)
	}

	addPolicy, err := csb.AddPolicy("YCJ", "/abc", "GET", "allow")
	if err != nil {
		t.Error(err)
	}
	fmt.Println(addPolicy)

	policies, err := csb.AddPolicies([][]string{{"YCJ", "/def", "POST", "allow"}, {"YCJ", "/ghi", "POST", "deny"}, {"YCJ", "/jkl", "*", "allow"}})
	if err != nil {
		t.Error(err)
	}
	fmt.Println(policies)

	policy := csb.GetPolicy()
	fmt.Println(policy)

	group, err := csb.AddGroupingPolicy("YCJ", "root")
	if err != nil {
		t.Error(err)
	}
	fmt.Println(group)

	hasNamedPolicy := csb.HasNamedPolicy("p", "YCJ", "/def", "POST", "allow")
	fmt.Println("hasNamedPolicy:", hasNamedPolicy)

	namedPolicy := csb.GetFilteredNamedPolicy("p", 0, "YCJ")
	fmt.Println("GetFilteredNamedPolicy:", namedPolicy)
	//
	//filteredRemove, err := csb.RemoveFilteredNamedPolicy("p", 0, "YCJ")
	//if err != nil {
	//	t.Error(err)
	//}
	//fmt.Println(filteredRemove)

	//update, err := csb.UpdateFilteredNamedPolicies("p", [][]string{{"YCJ1", "/def", "POST", "allow"}, {"YCJ1", "/ghi", "POST", "deny"}, {"YCJ1", "/jkl", "*", "allow"}, {"YCJ1", "/abc", "GET", "allow"}}, 0, "YCJ")
	//if err != nil {
	//	t.Error(err)
	//}
	//fmt.Println("update:", update)
	//
	//updatePolicies, err := csb.UpdatePolicies([][]string{{"YCJ", "/def", "POST", "allow"}, {"YCJ", "/ghi", "POST", "deny"}, {"YCJ", "/jkl", "*", "allow"}}, [][]string{{"YCJ1", "/def", "POST", "allow"}, {"YCJ2", "/ghi", "POST", "deny"}, {"YCJ3", "/jkl", "*", "allow"}})
	//if err != nil {
	//	t.Error(err)
	//}
	//fmt.Println("updatePolicies:", updatePolicies)
	//
	//update, err := csb.UpdatePolicy([]string{"YCJ", "/abc", "GET", "allow"}, []string{"YCJ", "/abc", "POST", "allow"})
	//if err != nil {
	//	t.Error(err)
	//}
	//fmt.Println(update)
	//
	//remove, err := csb.RemovePolicies([][]string{{"YCJ", "/abc", "POST", "allow"}, {"YCJ", "/jkl", "*", "allow"}})
	//if err != nil {
	//	t.Error(err)
	//}
	//fmt.Println(remove)

	//csb.ClearPolicy()
	//err = csb.SavePolicy()
	//if err != nil {
	//	t.Error(err)
	//}

}
