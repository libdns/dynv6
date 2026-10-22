package dynv6

import (
	"context"
	"fmt"
	"time"

	"github.com/libdns/libdns"
)

// Provider for dynv6 HTTP REST API
type Provider struct {
	// Token is required for authorization.
	// You can generate one at: https://dynv6.com/keys
	Token string `json:"token,omitempty"`
}

// interne dynv6-Record-Struktur (vereinfacht)
type record struct {
	ID   int64         `json:"id,omitempty"`
	Name string        `json:"name,omitempty"`
	Type string        `json:"type,omitempty"`
	Data string        `json:"data,omitempty"`
	TTL  time.Duration `json:"ttl,omitempty"`
}

// Helpfunction: extracts .Data from the libdns.Record. Every libdns.Record
// (libdns.Address, libdns.TXT, ...) converts to libdns.RR via RR(), so typed
// records work too, not only libdns.RR itself.
func getDataFromRecord(r libdns.Record) string {
	return r.RR().Data
}

// Converts a intern dynv6-Record to a libdns.Record. Returns the typed record
// (libdns.Address for A/AAAA, libdns.TXT, ...) as libdns v1 expects from
// providers, so callers that look for e.g. libdns.Address find it; falls back
// to libdns.RR when the record cannot be parsed.
func (r *record) toLibdnsRecord() libdns.Record {
	rr := libdns.RR{
		Name: r.Name,
		Type: r.Type,
		Data: r.Data,
		TTL:  r.TTL,
	}
	if parsed, err := rr.Parse(); err == nil {
		return parsed
	}
	return rr
}

// Creates a dynv6-Record from the libdns.Record
func fromLibdnsRecord(zone string, r *libdns.Record) (*record, error) {
	if *r == nil {
		return nil, fmt.Errorf("nil record")
	}
	rr := (*r).RR()
	return &record{
		Name: rr.Name,
		Type: rr.Type,
		Data: rr.Data,
		TTL:  rr.TTL,
	}, nil
}

// GetRecords lists all the records in the zone.
func (p *Provider) GetRecords(ctx context.Context, zone string) ([]libdns.Record, error) {
	zoneDetails, err := p.getZoneByName(ctx, zone)
	if err != nil {
		return nil, err
	}
	dynv6Records, err := p.getRecords(ctx, zoneDetails.ID)
	if err != nil {
		return nil, err
	}
	var recs []libdns.Record
	for _, r := range dynv6Records {
		recs = append(recs, r.toLibdnsRecord())
	}
	return recs, nil
}

// AppendRecords adds records to the zone and returns the records that were created.
func (p *Provider) AppendRecords(ctx context.Context, zone string, recs []libdns.Record) ([]libdns.Record, error) {
	zoneDetails, err := p.getZoneByName(ctx, zone)
	if err != nil {
		return nil, err
	}
	results := []libdns.Record{}
	for _, r := range recs {
		dynv6Rec, err := fromLibdnsRecord(zone, &r)
		if err != nil {
			return results, err
		}
		result, err := p.addRecord(ctx, zoneDetails.ID, dynv6Rec)
		if err != nil {
			return results, err
		}
		results = append(results, result.toLibdnsRecord())
	}
	return results, nil
}

// SetRecords sets the records in the zone, either by updating existing records or creating new ones, and returns the records that were updated.
func (p *Provider) SetRecords(ctx context.Context, zone string, recs []libdns.Record) ([]libdns.Record, error) {
	zoneDetails, err := p.getZoneByName(ctx, zone)
	if err != nil {
		return nil, err
	}
	existingRecords, err := p.getRecords(ctx, zoneDetails.ID)
	if err != nil {
		return nil, err
	}
	results := []libdns.Record{}
	for _, r := range recs {
		existingRecord := findRecord(existingRecords, &r)
		var result *record
		if existingRecord != nil {
			// record found, update it
			updateRecord := *existingRecord
			updateRecord.Data = getDataFromRecord(r)
			result, err = p.updateRecord(ctx, zoneDetails.ID, &updateRecord)
			if err != nil {
				return results, err
			}
		} else {
			// no record found, add a new one
			newRecord, err := fromLibdnsRecord(zone, &r)
			if err != nil {
				return results, err
			}
			result, err = p.addRecord(ctx, zoneDetails.ID, newRecord)
			if err != nil {
				return results, err
			}
		}
		results = append(results, result.toLibdnsRecord())
	}
	return results, nil
}

// DeleteRecords deletes records from the zone and returns the records that were deleted.
func (p *Provider) DeleteRecords(ctx context.Context, zone string, recs []libdns.Record) ([]libdns.Record, error) {
	zoneDetails, err := p.getZoneByName(ctx, zone)
	if err != nil {
		return nil, err
	}
	existingRecords, err := p.getRecords(ctx, zoneDetails.ID)
	if err != nil {
		return nil, err
	}
	results := []libdns.Record{}
	for _, r := range recs {
		existingRecord := findRecordWithValue(existingRecords, &r)
		if existingRecord == nil {
			return results, fmt.Errorf("Record not found: %+v", r)
		}
		err = p.deleteRecord(ctx, zoneDetails.ID, existingRecord.ID)
		if err != nil {
			return results, err
		}
		results = append(results, r)
	}
	return results, nil
}

// Interface guards
var (
	_ libdns.RecordGetter   = (*Provider)(nil)
	_ libdns.RecordAppender = (*Provider)(nil)
	_ libdns.RecordSetter   = (*Provider)(nil)
	_ libdns.RecordDeleter  = (*Provider)(nil)
)
