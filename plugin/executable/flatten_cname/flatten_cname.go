/*
 * Copyright (C) 2020-2022, IrineSistiana
 *
 * This file is part of mosdns.
 *
 * mosdns is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * mosdns is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

package flatten_cname

import (
	"context"
	"github.com/IrineSistiana/mosdns/v5/pkg/query_context"
	"github.com/IrineSistiana/mosdns/v5/plugin/executable/sequence"
	"github.com/miekg/dns"
)

const PluginType = "flatten_cname"

func init() {
	// You can register a quick setup func for sequence. So that users can
	// init your plugin in the sequence directly in one string.
	sequence.MustRegExecQuickSetup(PluginType, QuickSetup)
}

var _ sequence.Executable = (*flattenCname)(nil)

// flattenCname implements handler.ExecutablePlugin.
type flattenCname struct{}

// Exec implements handler.Executable.
func (s *flattenCname) Exec(_ context.Context, qCtx *query_context.Context) error {
	q := qCtx.Q()

	r := qCtx.R()
	if r == nil {
		return nil
	}

	// Remove CNAME answers for A,AAAA Q
	switch qt := q.Question[0].Qtype; qt {
	case dns.TypeA, dns.TypeAAAA:
		rr := r.Answer[:0]
		for _, ar := range r.Answer {
			if ar.Header().Rrtype != dns.TypeCNAME {
				rr = append(rr, ar)
			}
			ar.Header().Name = q.Question[0].Name
		}
		r.Answer = rr
	}
	return nil
}

func QuickSetup(_ sequence.BQ, _ string) (any, error) {
	return &flattenCname{}, nil
}
