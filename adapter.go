package casbinx

import (
	"context"
	"fmt"
	"github.com/casbin/casbin/v2/model"
	"github.com/casbin/casbin/v2/persist"
	"github.com/pkg/errors"
	"github.com/zeromicro/go-zero/core/stores/sqlx"
	"log"
	"strings"
)

var (
	defaultTableName = "casbin_policy"
	TableField       = struct {
		Id    string
		Ptype string
		V0    string
		V1    string
		V2    string
		V3    string
		V4    string
		V5    string
	}{
		Id:    "`id`",
		Ptype: "`ptype`",
		V0:    "`v0`",
		V1:    "`v1`",
		V2:    "`v2`",
		V3:    "`v3`",
		V4:    "`v4`",
		V5:    "`v5`",
	}
	policyFields      = fmt.Sprintf("%s,%s,%s,%s,%s,%s,%s", TableField.Ptype, TableField.V0, TableField.V1, TableField.V2, TableField.V3, TableField.V4, TableField.V5)
	policyPlaceholder = "?, ?, ?, ?, ?, ?, ?"
)

type (
	Adapter struct {
		ctx        context.Context
		db         sqlx.SqlConn
		tableName  string
		isFiltered bool
	}
	CasbinPolicy struct {
		Id    int64  `db:"id"`
		Ptype string `db:"ptype"`
		V0    string `db:"v0"`
		V1    string `db:"v1"`
		V2    string `db:"v2"`
		V3    string `db:"v3"`
		V4    string `db:"v4"`
		V5    string `db:"v5"`
	}
	// Filter  defines the filtering rules for a FilteredAdapter's policy.
	// Empty values are ignored, but all others must match the filter.
	Filter struct {
		Ptype []string
		V0    []string
		V1    []string
		V2    []string
		V3    []string
		V4    []string
		V5    []string
	}
)

func NewAdapter(db sqlx.SqlConn, table ...string) *Adapter {
	return NewAdapterCtx(context.Background(), db, table...)
}

func NewAdapterCtx(ctx context.Context, db sqlx.SqlConn, table ...string) *Adapter {
	tableName := defaultTableName
	if len(table) > 0 {
		tableName = table[0]
	}
	return &Adapter{
		ctx:       ctx,
		db:        db,
		tableName: tableName,
	}
}

func (a *Adapter) WithCtx(ctx context.Context) {
	a.ctx = ctx
}

// LoadPolicy loads all policy rules from the storage.
func (a *Adapter) LoadPolicy(model model.Model) error {
	var lines []CasbinPolicy
	query := fmt.Sprintf("SELECT %s FROM %s", policyFields, a.tableName)
	err := a.db.QueryRowsPartialCtx(a.ctx, &lines, query)
	if err != nil {
		return err
	}
	for _, line := range lines {
		err = a.loadPolicyLine(line, model)
		if err != nil {
			log.Println(err)
		}
	}
	return nil
}

// SavePolicy saves all policy rules to the storage.
func (a *Adapter) SavePolicy(model model.Model) error {
	policys := make([]CasbinPolicy, 0, 64)
	for ptype, ast := range model["p"] {
		for _, rule := range ast.Policy {
			line := savePolicyLine(ptype, rule)
			policys = append(policys, *line)
		}
	}
	for ptype, ast := range model["g"] {
		for _, rule := range ast.Policy {
			line := savePolicyLine(ptype, rule)
			policys = append(policys, *line)
		}
	}
	err := a.db.TransactCtx(a.ctx, func(ctx context.Context, session sqlx.Session) error {
		err := a.deleteAll(ctx, session)
		if err != nil {
			return err
		}
		if len(policys) > 0 {
			err = a.batchInsertPolicy(ctx, &policys, session)
			if err != nil {
				return err
			}
		}
		return nil
	})
	return err
}

// AddPolicy adds a policy rule to the storage.
// This is part of the Auto-Save feature.
func (a *Adapter) AddPolicy(sec string, ptype string, rule []string) error {
	line := savePolicyLine(ptype, rule)
	return a.insertPolicy(a.ctx, line, a.db)
}

// RemovePolicy removes a policy rule from the storage.
// This is part of the Auto-Save feature.
func (a *Adapter) RemovePolicy(sec string, ptype string, rule []string) error {
	line := savePolicyLine(ptype, rule)
	return a.deleteRow(a.ctx, line, a.db)
}

// ClearPolicy clears all current policy in all instances
func (a *Adapter) ClearPolicy() error {
	err := a.deleteAll(a.ctx, a.db)
	return err
}

// UpdatePolicy updates policy rule from all instance.
func (a *Adapter) UpdatePolicy(sec string, ptype string, oldRule, newRule []string) error {
	oldLine := savePolicyLine(ptype, oldRule)
	newLine := savePolicyLine(ptype, newRule)
	return a.updatePolicy(a.ctx, oldLine, newLine, a.db)
}

// UpdatePolicies updates some policy rules from all instance
func (a *Adapter) UpdatePolicies(sec string, ptype string, oldrules, newRules [][]string) error {
	oldLen := len(oldrules)
	newLen := len(newRules)
	if oldLen == 0 || newLen == 0 || oldLen != newLen {
		return errors.New("UpdatePolicies the numbers of oldRules and newRules are different")
	}
	err := a.db.TransactCtx(a.ctx, func(ctx context.Context, session sqlx.Session) error {
		for i, _ := range oldrules {
			oldLine := savePolicyLine(ptype, oldrules[i])
			newLine := savePolicyLine(ptype, newRules[i])
			err := a.updatePolicy(ctx, oldLine, newLine, session)
			if err != nil {
				return err
			}
		}
		return nil
	})
	return err
}

func (a *Adapter) GetFilteredNamedPolicy(sec string, ptype string, fieldIndex int, fieldValues ...string) ([][]string, error) {
	lines, err := a.getFilteredNamedPolicy(sec, ptype, fieldIndex, fieldValues...)
	if err != nil {
		return nil, err
	}
	rules := policySliceToStringSlice(lines)
	return rules, nil
}

func (a *Adapter) getFilteredNamedPolicy(sec string, ptype string, fieldIndex int, fieldValues ...string) (*[]CasbinPolicy, error) {
	line, err := getFilteredPolicy(sec, ptype, fieldIndex, fieldValues...)
	if err != nil {
		return nil, err
	}
	cond, bind := a.genCondBind(line)
	lines, err := a.findByCond(a.ctx, cond, bind, a.db)
	if err != nil {
		return nil, err
	}
	return lines, nil
}

// UpdateFilteredPolicies deletes old rules and adds new rules.
func (a *Adapter) UpdateFilteredPolicies(sec string, ptype string, newRules [][]string, fieldIndex int, fieldValues ...string) ([][]string, error) {
	newLen := len(newRules)
	if newLen == 0 {
		return nil, errors.New("UpdateFilteredPolicies newRules len is 0")
	}
	line, err := getFilteredPolicy(sec, ptype, fieldIndex, fieldValues...)
	if err != nil {
		return nil, err
	}
	cond, bind := a.genCondBind(line)
	newLines := stringSliceToPolicySlice(ptype, newRules)
	err = a.db.TransactCtx(a.ctx, func(ctx context.Context, session sqlx.Session) error {
		err = a.deleteByCond(ctx, cond, bind, session)
		if err != nil {
			return err
		}
		err = a.batchInsertPolicy(ctx, newLines, session)
		if err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	lines, err := a.findByCond(a.ctx, cond, bind, a.db)
	oldLines := policySliceToStringSlice(lines)
	return oldLines, nil
}

// RemoveFilteredPolicy removes policy rules that match the filter from the storage.
// This is part of the Auto-Save feature.
func (a *Adapter) RemoveFilteredPolicy(sec string, ptype string, fieldIndex int, fieldValues ...string) error {
	line, err := getFilteredPolicy(sec, ptype, fieldIndex, fieldValues...)
	if err != nil {
		return err
	}
	cond, bind := a.genCondBind(line)
	err = a.db.TransactCtx(a.ctx, func(ctx context.Context, session sqlx.Session) error {
		err = a.deleteByCond(ctx, cond, bind, session)
		return err
	})
	return err
}

// AddPolicies adds policy rules to the storage.
func (a *Adapter) AddPolicies(sec string, ptype string, rules [][]string) error {
	lens := len(rules)
	if lens <= 0 {
		return errors.New("AddPolicies rules len is 0")
	}
	policys := make([]CasbinPolicy, 0, lens)
	for _, rule := range rules {
		line := savePolicyLine(ptype, rule)
		policys = append(policys, *line)
	}
	err := a.batchInsertPolicy(a.ctx, &policys, a.db)
	return err
}

// RemovePolicies removes policy rules from the storage.
func (a *Adapter) RemovePolicies(sec string, ptype string, rules [][]string) error {
	lens := len(rules)
	if lens <= 0 {
		return errors.New("RemovePolicies rules len is 0")
	}
	policys := make([]CasbinPolicy, 0, lens)
	for _, rule := range rules {
		line := savePolicyLine(ptype, rule)
		policys = append(policys, *line)
	}
	err := a.db.TransactCtx(a.ctx, func(ctx context.Context, session sqlx.Session) error {
		err := a.removePolicyByPolicySlice(ctx, &policys, session)
		return err
	})
	return err
}

func (a *Adapter) removePolicyByPolicySlice(ctx context.Context, policySlice *[]CasbinPolicy, session sqlx.Session) error {
	for _, policy := range *policySlice {
		err := a.deleteRow(ctx, &policy, session)
		if err != nil {
			return err
		}
	}
	return nil
}

// LoadFilteredPolicy loads only policy rules that match the filter.
func (a *Adapter) LoadFilteredPolicy(model model.Model, filter interface{}) error {
	if filter == nil {
		return a.LoadPolicy(model)
	}
	filterValue, ok := filter.(*Filter)
	if !ok {
		return errors.New("invalid filter type")
	}
	lines, err := a.findByFilter(a.ctx, filterValue, a.db)
	if err != nil {
		return err
	}

	for _, line := range *lines {
		err = a.loadPolicyLine(line, model)
		if err != nil {
			log.Println(err)
		}
	}
	a.isFiltered = true
	return nil
}

// IsFiltered returns true if the loaded policy has been filtered.
func (a *Adapter) IsFiltered() bool {
	return a.isFiltered
}

func (a *Adapter) loadPolicyLine(line CasbinPolicy, model model.Model) error {
	lineText := line.Ptype
	args := [6]string{line.V0, line.V1, line.V2, line.V3, line.V4, line.V5}
	for _, arg := range args {
		if arg != "" {
			lineText += ", " + arg
		}
	}
	err := persist.LoadPolicyLine(lineText, model)
	return err
}

// 批量新增
func (a *Adapter) batchInsertPolicy(ctx context.Context, policys *[]CasbinPolicy, session sqlx.Session) error {
	lens := len(*policys)
	if lens <= 0 {
		return errors.New("batchInsertPolicy policys len is 0")
	}
	args := make([]interface{}, 0, lens*7)
	sql := "INSERT INTO `%s` (%s) VALUES "
	for i, line := range *policys {
		sql += "(" + policyPlaceholder + ")"
		if i+1 != lens {
			sql += ","
		}
		args = append(args, line.Ptype, line.V0, line.V1, line.V2, line.V3, line.V4, line.V5)
	}
	sql += " ON DUPLICATE KEY UPDATE %s = VALUES(%s)"
	sql = fmt.Sprintf(sql, a.tableName, policyFields, TableField.Ptype, TableField.Ptype)
	fmt.Println("sql:", fmt.Sprintf("%#+v", sql))
	fmt.Println("args:", fmt.Sprintf("%#+v", args))
	_, err := session.ExecCtx(ctx, sql, args...)
	return err
}

func (a *Adapter) insertPolicy(ctx context.Context, policy *CasbinPolicy, session sqlx.Session) error {
	query := fmt.Sprintf("INSERT INTO %s (%s) VALUES (%s)", a.tableName, policyFields, policyPlaceholder)
	_, err := a.db.ExecCtx(a.ctx, query, policy.Ptype, policy.V0, policy.V1, policy.V2, policy.V3, policy.V4, policy.V5)
	return err
}

func (a *Adapter) updatePolicy(ctx context.Context, oldPolicy, policy *CasbinPolicy, session sqlx.Session) error {
	sql := "UPDATE %s SET %s = ?, %s = ?, %s = ?, %s = ?, %s = ?, %s = ?, %s = ? WHERE %s = ? AND %s = ? AND %s = ? AND %s = ? AND %s = ? AND %s = ? AND %s = ?"
	sql = fmt.Sprintf(sql, a.tableName, TableField.Ptype, TableField.V0, TableField.V1, TableField.V2, TableField.V3, TableField.V4, TableField.V5,
		TableField.Ptype, TableField.V0, TableField.V1, TableField.V2, TableField.V3, TableField.V4, TableField.V5)
	_, err := session.ExecCtx(ctx, sql, policy.Ptype, policy.V0, policy.V1, policy.V2, policy.V3, policy.V4, policy.V5, oldPolicy.Ptype, oldPolicy.V0, oldPolicy.V1, oldPolicy.V2, oldPolicy.V3, oldPolicy.V4, oldPolicy.V5)
	return err
}

func (a *Adapter) deleteRow(ctx context.Context, policy *CasbinPolicy, session sqlx.Session) error {
	query := fmt.Sprintf("DELETE FROM %s WHERE %s = ? AND %s = ? AND %s = ? AND %s = ? AND %s = ? AND %s = ? AND %s = ?",
		a.tableName, TableField.Ptype, TableField.V0, TableField.V1, TableField.V2, TableField.V3, TableField.V4, TableField.V5)
	_, err := session.ExecCtx(ctx, query, policy.Ptype, policy.V0, policy.V1, policy.V2, policy.V3, policy.V4, policy.V5)
	return err
}

func (a *Adapter) deleteAll(ctx context.Context, session sqlx.Session) error {
	_, err := session.ExecCtx(ctx, fmt.Sprintf("DELETE FROM %s", a.tableName))
	return err
}

// GenCondBind 生成条件和bind
func (a *Adapter) genCondBind(policy *CasbinPolicy) (string, []interface{}) {
	cond := "%s = ?"
	field := []interface{}{
		TableField.Ptype,
	}
	bind := []interface{}{
		policy.Ptype,
	}
	if policy.V0 != "" {
		cond += " AND %s = ?"
		field = append(field, TableField.V0)
		bind = append(bind, policy.V0)
	}
	if policy.V1 != "" {
		cond += " AND %s = ?"
		field = append(field, TableField.V1)
		bind = append(bind, policy.V1)
	}
	if policy.V2 != "" {
		cond += " AND %s = ?"
		field = append(field, TableField.V2)
		bind = append(bind, policy.V2)
	}
	if policy.V3 != "" {
		cond += " AND %s = ?"
		field = append(field, TableField.V3)
		bind = append(bind, policy.V3)
	}
	if policy.V4 != "" {
		cond += " AND %s = ?"
		field = append(field, TableField.V4)
		bind = append(bind, policy.V4)
	}
	if policy.V5 != "" {
		cond += " AND %s = ?"
		field = append(field, TableField.V5)
		bind = append(bind, policy.V5)
	}
	return fmt.Sprintf(cond, field...), bind
}

func (a *Adapter) deleteByCond(ctx context.Context, cond string, bind []interface{}, session sqlx.Session) error {
	query := fmt.Sprintf("DELETE FROM %s WHERE %s", a.tableName, cond)
	_, err := session.ExecCtx(ctx, query, bind...)
	if err != nil {
		return err
	}
	return nil
}

func (a *Adapter) findByCond(ctx context.Context, cond string, bind []interface{}, session sqlx.Session) (*[]CasbinPolicy, error) {
	query := fmt.Sprintf("SELECT %s FROM %s WHERE %s", policyFields, a.tableName, cond)
	var policys []CasbinPolicy
	err := session.QueryRowsPartialCtx(ctx, &policys, query, bind...)
	if err != nil {
		return nil, err
	}
	return &policys, nil
}

func (a *Adapter) findByFilter(ctx context.Context, filter *Filter, session sqlx.Session) (*[]CasbinPolicy, error) {
	if filter == nil {
		return nil, errors.New("FindByFilter filter is nil")
	}
	PtypeLen := len(filter.Ptype)
	v0Len := len(filter.V0)
	v1Len := len(filter.V1)
	v2Len := len(filter.V2)
	v3Len := len(filter.V3)
	v4Len := len(filter.V4)
	v5Len := len(filter.V5)
	if PtypeLen == 0 && v0Len == 0 && v1Len == 0 && v2Len == 0 && v3Len == 0 && v4Len == 0 && v5Len == 0 {
		return nil, errors.New("FindByFilter filter element all len is 0")
	}
	fields := make([]interface{}, 0, 2)
	values := make([]interface{}, 0, 1)
	sql := "SELECT %s FROM %s WHERE"
	fields = append(fields, policyFields, a.tableName)
	if PtypeLen > 0 {
		if !strings.HasSuffix(sql, "WHERE") {
			sql += " AND"
		}
		sql += " %s IN("
		fields = append(fields, TableField.Ptype)
		for _, s := range filter.Ptype {
			sql += "?,"
			values = append(values, s)
		}
		sql = strings.TrimRight(sql, ",") + ")"
	}
	if v0Len > 0 {
		if !strings.HasSuffix(sql, "WHERE") {
			sql += " AND"
		}
		sql += " %s IN("
		fields = append(fields, TableField.V0)
		for _, s := range filter.V0 {
			sql += "?,"
			values = append(values, s)
		}
		sql = strings.TrimRight(sql, ",") + ")"
	}
	if v1Len > 0 {
		if !strings.HasSuffix(sql, "WHERE") {
			sql += " AND"
		}
		sql += " %s IN("
		fields = append(fields, TableField.V1)
		for _, s := range filter.V1 {
			sql += "?,"
			values = append(values, s)
		}
		sql = strings.TrimRight(sql, ",") + ")"
	}
	if v2Len > 0 {
		if !strings.HasSuffix(sql, "WHERE") {
			sql += " AND"
		}
		sql += " %s IN("
		fields = append(fields, TableField.V2)
		for _, s := range filter.V2 {
			sql += "?,"
			values = append(values, s)
		}
		sql = strings.TrimRight(sql, ",") + ")"
	}
	if v3Len > 0 {
		if !strings.HasSuffix(sql, "WHERE") {
			sql += " AND"
		}
		sql += " %s IN("
		fields = append(fields, TableField.V3)
		for _, s := range filter.V3 {
			sql += "?,"
			values = append(values, s)
		}
		sql = strings.TrimRight(sql, ",") + ")"
	}
	if v4Len > 0 {
		if !strings.HasSuffix(sql, "WHERE") {
			sql += " AND"
		}
		sql += " %s IN("
		fields = append(fields, TableField.V4)
		for _, s := range filter.V4 {
			sql += "?,"
			values = append(values, s)
		}
		sql = strings.TrimRight(sql, ",") + ")"
	}
	if v5Len > 0 {
		if !strings.HasSuffix(sql, "WHERE") {
			sql += " AND"
		}
		sql += " %s IN("
		fields = append(fields, TableField.V5)
		for _, s := range filter.V5 {
			sql += "?,"
			values = append(values, s)
		}
		sql = strings.TrimRight(sql, ",") + ")"
	}
	sql = fmt.Sprintf(sql, fields...)
	fmt.Println("sql:", sql)
	fmt.Println("values:", values)
	var policys []CasbinPolicy
	err := session.QueryRowsPartialCtx(ctx, &policys, sql, values...)
	if err != nil {
		return nil, err
	}
	return &policys, nil
}

func getFilteredPolicy(sec string, ptype string, fieldIndex int, fieldValues ...string) (*CasbinPolicy, error) {
	if fieldIndex < 0 && fieldIndex > 5 {
		return nil, errors.New("GetFilteredNamedPolicy fieldIndex must be a number from 0 to 5")
	}
	valLen := len(fieldValues)
	if valLen == 0 {
		return nil, errors.New("GetFilteredNamedPolicy fieldValues len is 0")
	}
	line := CasbinPolicy{}
	line.Ptype = ptype
	if fieldIndex <= 0 && 0 < fieldIndex+valLen {
		line.V0 = fieldValues[0-fieldIndex]
	}
	if fieldIndex <= 1 && 1 < fieldIndex+valLen {
		line.V1 = fieldValues[1-fieldIndex]
	}
	if fieldIndex <= 2 && 2 < fieldIndex+valLen {
		line.V2 = fieldValues[2-fieldIndex]
	}
	if fieldIndex <= 3 && 3 < fieldIndex+valLen {
		line.V3 = fieldValues[3-fieldIndex]
	}
	if fieldIndex <= 4 && 4 < fieldIndex+valLen {
		line.V4 = fieldValues[4-fieldIndex]
	}
	if fieldIndex <= 5 && 5 < fieldIndex+valLen {
		line.V5 = fieldValues[5-fieldIndex]
	}
	return &line, nil
}

func policyToStringSlice(policy *CasbinPolicy) []string {
	rule := []string{policy.V0, policy.V1, policy.V2, policy.V3, policy.V4, policy.V5}
	return rule
}

func policySliceToStringSlice(policys *[]CasbinPolicy) [][]string {
	var rules [][]string
	lens := len(*policys)
	if lens > 0 {
		rules = make([][]string, 0, lens)
		for _, line := range *policys {
			rule := policyToStringSlice(&line)
			rules = append(rules, rule)
		}
	}
	return rules
}

func stringSliceToPolicySlice(ptype string, rules [][]string) *[]CasbinPolicy {
	lens := len(rules)
	policys := make([]CasbinPolicy, 0, lens)
	for _, rule := range rules {
		line := savePolicyLine(ptype, rule)
		policys = append(policys, *line)
	}
	return &policys
}

func savePolicyLine(ptype string, rule []string) *CasbinPolicy {
	line := CasbinPolicy{}
	line.Ptype = ptype
	ruleLen := len(rule)
	if ruleLen > 0 {
		line.V0 = rule[0]
	}
	if ruleLen > 1 {
		line.V1 = rule[1]
	}
	if ruleLen > 2 {
		line.V2 = rule[2]
	}
	if ruleLen > 3 {
		line.V3 = rule[3]
	}
	if ruleLen > 4 {
		line.V4 = rule[4]
	}
	if ruleLen > 5 {
		line.V5 = rule[5]
	}
	return &line
}
