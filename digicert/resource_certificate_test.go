// Copyright (c) HashiCorp, Inc.

package digicert

import (
	"fmt"
	"log"
	"os"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
	digicertapi "github.com/myklst/terraform-provider-st-digicert/digicertAPI"
)

const (
	DC_ACTION_RENEW        = "renew"
	DC_ACTION_RENEW_2      = "renew2"
	DC_ACTION_REISSUE      = "reissue"
	DC_ACTION_REISSUE_2    = "reissue2"
	DC_ACTION_ISSUE        = "issued"
	DC_ACTION_STATE_IMPORT = "stateImport"
)

func getDigicertClient() *CertificateResource {
	client, err := digicertapi.NewClient(os.Getenv("DIGICERT_API_KEY"))
	if err != nil {
		panic(err)
	}

	return &CertificateResource{client}
}

// Acceptance Test use only
func (r *CertificateResource) revokedAllOrders() error {
	orders, err := r.client.GetOrders("")
	if err != nil {
		return err
	}

	var order_ids []int
	for _, order := range orders.Orders {
		order_ids = append(order_ids, order.ID)
	}

	if len(order_ids) == 0 {
		log.Println("No order issued.")
	} else {
		log.Println("Order Id is : ", order_ids)
	}

	for _, o_id := range order_ids {
		if err := r.client.RevokeAllCert(o_id); err != nil {
			panic(err)
		}
	}

	return nil
}

func revokeAllOrder() resource.TestCheckFunc {
	// revoke all the order after test as order cannot be revoked by terraform
	r := getDigicertClient()
	if err := r.revokedAllOrders(); err != nil {
		panic(err)
	}

	return nil
}

// =============================================
// Duplicate order placement
// =============================================
func TestDigicert_DuplicateOrder(t *testing.T) {
	defer revokeAllOrder()
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config:      testDigicertConfigDuplicateOrder(),
				ExpectError: regexp.MustCompile("duplication order placement, sige-test3.com already placed order on Digicert"),
			},
		},
	})
}

// =================================================
// Issue cert if there are no available order to use
// =================================================
func TestDigicert_Issue(t *testing.T) {
	defer revokeAllOrder()

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// apply with one cert
			{
				Config:  testDigicertConfigSingleDomain("sige-test5.com", []string{"*.sige-test5.com"}, 0),
				Destroy: false,
			},
			// add one more cert
			{
				Config: testDigicertConfigTwoDomains("sige-test5.com", "sige-test4.com", []string{"*.sige-test5.com"}, []string{"*.sige-test4.com"}, 0, 0, 365, 365),
				Check:  testDigicertCertificateChecking(DC_ACTION_ISSUE),
			},
		},
	})
}

// ===============================================
// Issue cert if there is available order to use
// ===============================================
func TestDigicert_ReissueToOtherOrder(t *testing.T) {
	defer revokeAllOrder()

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Create a cert and destroy it. It will create an order in Digicert.
			{
				Config: testDigicertConfigSingleDomain("sige-test5.com", []string{"*.sige-test5.com"}, 0),
			},
			// Create a cert to reissue into the order just created.
			{
				Config: testDigicertConfigSingleDomain("sige-test4.com", []string{"*.sige-test4.com"}, 0),
				Check:  testDigicertCertificateChecking(DC_ACTION_REISSUE_2),
			},
		},
	})
}

// ====================================================
// Renew Order - There is no order is available to use
// ====================================================
func TestDigicert_Renew(t *testing.T) {
	defer revokeAllOrder()

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// create two cert: sige-test4.com and sige-test5.com with 365 expiry days;
			{
				Config:  testDigicertConfigTwoDomains("sige-test5.com", "sige-test4.com", []string{"*.sige-test5.com"}, []string{"*.sige-test4.com"}, 0, 0, 365, 365),
				Destroy: false,
			},
			// destroy the cert of sige-test4.com
			{
				Config:  testDigicertConfigSingleDomain("sige-test5.com", []string{"*.sige-test5.com"}, 0),
				Destroy: false,
			},
			// Make the sige-test5.com minimun days remaining of expired day larger than both expiry days.
			// To trigger renew action.
			{
				ExpectNonEmptyPlan: true,
				Config:             testDigicertConfigSingleDomain("sige-test5.com", []string{"*.sige-test5.com"}, 366),
				Check:              testDigicertCertificateChecking(DC_ACTION_RENEW),
			},
		},
	},
	)
}

// ============================================================
// Renew Order - There is no order is available to use (case 2)
// ============================================================
func TestDigicert_Renew2(t *testing.T) {
	defer revokeAllOrder()

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// create two cert
			{
				Config:  testDigicertConfigTwoDomains("sige-test5.com", "sige-test4.com", []string{"*.sige-test5.com"}, []string{"*.sige-test4.com"}, 0, 0, 365, 365),
				Destroy: false,
			},
			// set the minimun days remaining to exceed sige-test5.com's order expiry days,
			// Since sige-test4.com is still issued, therfore the expected outcome is it will perform renew action.
			{
				Config:             testDigicertConfigTwoDomains("sige-test5.com", "sige-test4.com", []string{"*.sige-test5.com"}, []string{"*.sige-test4.com"}, 366, 0, 365, 365),
				ExpectNonEmptyPlan: true,
				Check:              testDigicertCertificateChecking(DC_ACTION_RENEW_2),
			},
		},
	},
	)
}

// =================================================
// Renew Order - Self order is available to reissue
// =================================================
func TestDigicert_RenewToSelfOrder(t *testing.T) {
	defer revokeAllOrder()

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// create a cert
			{
				Config:  testDigicertConfigSingleDomain("sige-test5.com", []string{"*.sige-test5.com"}, 0),
				Destroy: false,
			},
			// set the minimun days remaining to exceed sige-test5.com's cert expiry days, but not it order's expiry days.
			// expected outcome is it will reissue to the order itself.
			{
				Config:             testDigicertConfigSingleDomain("sige-test5.com", []string{"*.sige-test5.com"}, 4),
				ExpectNonEmptyPlan: true,
				Check:              testDigicertCertificateChecking(DC_ACTION_REISSUE_2),
			},
		},
	})
}

// ==================================================
// Renew Order - There is available order to reissue
// ==================================================
func TestDigicert_RenewToOtherOrder(t *testing.T) {
	defer revokeAllOrder()

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// create two cert: sige-test5.com with 365 expiry days; sige-test4.com with 367 expiry days
			{
				Config:  testDigicertConfigTwoDomains("sige-test5.com", "sige-test4.com", []string{"*.sige-test5.com"}, []string{"*.sige-test4.com"}, 0, 0, 365, 367),
				Destroy: false,
			},
			// revoke the cert of sige-test4.com
			{
				Config:  testDigicertConfigSingleDomain("sige-test5.com", []string{"*.sige-test5.com"}, 0),
				Destroy: false,
			},
			// set the minimun days remaining to exceed sige-test5.com's order expiry days,  but not sige-test4.com's order's expiry days.
			// expected outcome is it will reissue to the  sige-test4.com's order.
			{
				ExpectNonEmptyPlan: true,
				Config:             testDigicertConfigSingleDomain("sige-test5.com", []string{"*.sige-test5.com"}, 365),
				Check:              testDigicertCertificateChecking(DC_ACTION_REISSUE),
			},
		},
	})
}

// ==================
// State import test
// ==================
func TestDigicert_StateImport(t *testing.T) {
	defer revokeAllOrder()

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testDigicertConfigSingleDomain("sige-test5.com", []string{"*.sige-test5.com"}, 0),
			},
			{
				ResourceName:  "st-digicert_certificate.certificate",
				ImportStateId: "sige-test5.com",
				ImportState:   true,
			},
		},
	})
}

func testDigicertCertificateChecking(action string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		r := getDigicertClient()
		orders, err := r.client.GetOrders("")
		if err != nil {
			return err
		}

		renewCount := 0
		issuedCount := 0
		reissuedCount := 0
		revokedCount := 0

		// will only have one renewed order and issued order
		for _, ord := range orders.Orders {
			order, err := r.client.GetOrderInfo(ord.ID)
			if err != nil {
				return err
			}
			// if the order is renewed, no need to check its' certificate status
			if order.IsRenewed {
				renewCount++
			} else {
				switch order.Certificate.Status {
				case "": // certificate's status will be empty if the action is issue
					issuedCount++
				case "issued":
					reissuedCount++
				case "revoked":
					revokedCount++
				}
			}
		}

		// Renew case 1 : There is an order cert's status is revoked, but the expiry date is not suitable to reissue.
		//                Therefore, perform renew action.
		if (renewCount != 1 || issuedCount != 1 || reissuedCount != 0 || revokedCount != 1) && action == DC_ACTION_RENEW {
			return fmt.Errorf("%s,\n%s",
				fmt.Sprintf("Order status is not as expected, current : renewCount= %d, issuedCount= %d, reissuedCount= %d, revokedCount= %d \n", renewCount, issuedCount, reissuedCount, revokedCount),
				"Expected: renewCount= 1, issuedCount= 1, reissuedCount= 0, revokedCount= 1")
		}
		// Renew case 2 : There is no order cert's status is revoked. Therefore, perform renew action.
		if (renewCount != 1 || issuedCount != 2 || reissuedCount != 0 || revokedCount != 0) && action == DC_ACTION_RENEW_2 {
			return fmt.Errorf("%s\n%s",
				fmt.Sprintf("Order status is not as expected, current : renewCount= %d, issuedCount= %d, reissuedCount= %d, revokedCount= %d \n", renewCount, issuedCount, reissuedCount, revokedCount),
				"Expected: renewCount= 1, issuedCount= 2, reissuedCount= 0, revokedCount= 1")
		}
		// Reissue case 1 : Two domains for testing, use during renew phase.
		if (renewCount != 0 || issuedCount != 0 || reissuedCount != 1 || revokedCount != 1) && action == DC_ACTION_REISSUE {
			return fmt.Errorf("%s\n%s",
				fmt.Sprintf("Order status is not as expected, current : renewCount= %d, issuedCount= %d, reissuedCount= %d, revokedCount= %d \n", renewCount, issuedCount, reissuedCount, revokedCount),
				"Expected: renewCount= 0, issuedCount= 0, reissuedCount= 1, revokedCount= 1")
		}
		// Reissue case 2 : Only create single domain for testing
		if (renewCount != 0 || issuedCount != 0 || reissuedCount != 1 || revokedCount != 0) && action == DC_ACTION_REISSUE_2 {
			return fmt.Errorf("%s\n%s",
				fmt.Sprintf("Order status is not as expected, current : renewCount= %d, issuedCount= %d, reissuedCount= %d, revokedCount= %d \n", renewCount, issuedCount, reissuedCount, revokedCount),
				"Expected: renewCount= 0, issuedCount= 0, reissuedCount= 1, revokedCount= 0")
		}
		// Issue, When there is no available order to reissue.
		if (renewCount != 0 || issuedCount != 2 || reissuedCount != 0 || revokedCount != 0) && action == DC_ACTION_ISSUE {
			return fmt.Errorf("%s\n%s",
				fmt.Sprintf("Order status is not as expected, current : renewCount= %d, issuedCount= %d, reissuedCount= %d, revokedCount= %d \n", renewCount, issuedCount, reissuedCount, revokedCount),
				"Expected: renewCount= 0, issuedCount= 2, reissuedCount= 0, revokedCount= 0")
		}

		return nil
	}
}

func testDigicertConfigDuplicateOrder() string {
	return fmt.Sprintf(`
provider "st-digicert" {
  api_key = "%s"
}

resource "st-digicert_certificate" "certificate" {
  common_name        = "sige-test3.com"
  sans               = ["*.sige-test5.com"]
  organization_id    = 2048388
  min_days_remaining = 365

  product_name = "GeoTrust TrueBusiness ID OV"
  dns_challenge {
    provider = "route53"
    config = {
      AWS_ACCESS_KEY_ID = "%s"
      AWS_SECRET_ACCESS_KEY = "%s"
    }
  }
}

resource "st-digicert_certificate" "certificate2" {
  depends_on = [ "st-digicert_certificate.certificate" ]
  common_name        = "sige-test3.com"
  sans               = ["*.sige-test5.com"]
  organization_id    = 2048388
  min_days_remaining = 365
  product_name = "GeoTrust TrueBusiness ID OV"

  dns_challenge {
    provider = "route53"
    config = {
      AWS_ACCESS_KEY_ID = "%s"
      AWS_SECRET_ACCESS_KEY = "%s"
    }
  }
}

`, os.Getenv("DIGICERT_API_KEY"),
		os.Getenv("AWS_ACCESS_KEY_ID"),
		os.Getenv("AWS_SECRET_ACCESS_KEY"),
		os.Getenv("AWS_ACCESS_KEY_ID"),
		os.Getenv("AWS_SECRET_ACCESS_KEY"))
}

func testDigicertConfigSingleDomain(commonName1 string, sans1 []string, min_days_remaining1 int) string {
	return fmt.Sprintf(`
provider "st-digicert" {
  api_key = "%s"
}

resource "st-digicert_certificate" "certificate" {
  common_name        = "%s"
  sans               = %+q
  organization_id    = 2048388
  min_days_remaining = %d
  product_name       = "GeoTrust TrueBusiness ID OV"

  dns_challenge {
    provider = "route53"
    config = {
      AWS_ACCESS_KEY_ID = "%s"
      AWS_SECRET_ACCESS_KEY = "%s"
    }
  }
}

`, os.Getenv("DIGICERT_API_KEY"),
		commonName1,
		sans1,
		min_days_remaining1,
		os.Getenv("AWS_ACCESS_KEY_ID"),
		os.Getenv("AWS_SECRET_ACCESS_KEY"),
	)
}

func testDigicertConfigTwoDomains(commonName1 string, commonName2 string, sans1 []string,
	sans2 []string, min_days_remaining1 int, min_days_remaining2 int, orderValidDays1 int, orderValidDays2 int) string {
	return fmt.Sprintf(`
provider "st-digicert" {
  api_key = "%s"
}

resource "st-digicert_certificate" "certificate" {
  common_name        = "%s"
  sans               = %+q
  organization_id    = 2048388
  min_days_remaining = %d
  product_name       = "GeoTrust TrueBusiness ID OV"
  order_validity_days = %d

  dns_challenge {
    provider = "route53"
    config = {
      AWS_ACCESS_KEY_ID = "%s"
      AWS_SECRET_ACCESS_KEY = "%s"
    }
  }
}

resource "st-digicert_certificate" "certificate2" {
  common_name        = "%s"
  sans               = %+q
  organization_id    = 2048388
  min_days_remaining = %d
  product_name       = "GeoTrust TrueBusiness ID OV"
  order_validity_days = %d

  dns_challenge {
    provider = "route53"
    config = {
      AWS_ACCESS_KEY_ID = "%s"
      AWS_SECRET_ACCESS_KEY = "%s"
    }
  }
}

`, os.Getenv("DIGICERT_API_KEY"),
		commonName1,
		sans1,
		min_days_remaining1,
		orderValidDays1,
		os.Getenv("AWS_ACCESS_KEY_ID"),
		os.Getenv("AWS_SECRET_ACCESS_KEY"),
		commonName2,
		sans2,
		min_days_remaining2,
		orderValidDays2,
		os.Getenv("AWS_ACCESS_KEY_ID"),
		os.Getenv("AWS_SECRET_ACCESS_KEY"),
	)
}
