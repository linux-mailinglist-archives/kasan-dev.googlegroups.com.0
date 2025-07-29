Return-Path: <kasan-dev+bncBCQ2XPNX7EOBBNHXUPCAMGQEGJBL7WI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x540.google.com (mail-ed1-x540.google.com [IPv6:2a00:1450:4864:20::540])
	by mail.lfdr.de (Postfix) with ESMTPS id 6D6EFB151A2
	for <lists+kasan-dev@lfdr.de>; Tue, 29 Jul 2025 18:49:58 +0200 (CEST)
Received: by mail-ed1-x540.google.com with SMTP id 4fb4d7f45d1cf-60c9d8a169csf6437598a12.0
        for <lists+kasan-dev@lfdr.de>; Tue, 29 Jul 2025 09:49:58 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1753807798; cv=pass;
        d=google.com; s=arc-20240605;
        b=UDNL8ZMhRddEn6vkg8CeqtzdQqR5/xkcIs3nnQVPdx7+8VuBqt3hxWd0sVi8xqb5FY
         Rg0wPJ+7xevSTns1TTp6q/x62NE+PO4f61l42MCsvepVDaj2jz07bRu1PuZKDxwBAKdr
         fdoNDR6w+hdwqyxJucjMt3r9FkBoy3Ca4pqo5RsCMVArW5T+riqRw+2eTBz5kf0AuVJZ
         DvqPHcz2pBjiSrVNhBPz1/QhM/XI0lqUknwdntwRCrVx1qtjvAQ9bflwoGJPwj35Swd/
         qMTEhDH2Y3Zo6XbOhTRsxomeBQULbjmVLqYMmmskoJqaBFHoyO67cqI4A4FXknyE+v0q
         P60A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:message-id
         :mime-version:subject:date:from:dkim-signature;
        bh=d4snbLij+KXpuJ+RdmJpcRKlVG7Avp6Ii50XXzF0ekY=;
        fh=i36zwOCJMDvH6pg4RwTWcUG4+oDJp4LSIfyTdIXVjfs=;
        b=OvBdeGDMqZiUR/D7maO8qCJVmFXwrVHy0YoREqc7O3P0023eGqTYZspjU/yzprML6w
         eSdN4Q9o6lbLZ8PRNmu00pyR1X3/1pzigSEsEb1MW+HO67Ac3M4wpoeP2/be+eHPUPxH
         cVkcGrK55RDAlKDSvn0UAlN7G562+yMyN+tFIDvEHYsTtwYRsDE+MDzpWvVNbQHWKHjG
         0HDVNGKq27f3GKr0wDW4WIZRQ7mkDB34K/YV88X14EtdSf/nL7tJsCxj78Z7uF1JmiFT
         hoIT47/W2UCEPwIWtr6qpEDcVauMajEeGJKo7Lcj6SgLLPtzu2DXPQUhH4ybZT1gIhjY
         0rSg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=wRnsjbVL;
       spf=pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::32e as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1753807798; x=1754412598; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to
         :message-id:mime-version:subject:date:from:from:to:cc:subject:date
         :message-id:reply-to;
        bh=d4snbLij+KXpuJ+RdmJpcRKlVG7Avp6Ii50XXzF0ekY=;
        b=GCd9W/QIcrfkY7hhpQTz+gCpa7FlcMhayUhgz012q8BESPqoFd+VAQUw1EKeRyP19l
         A11Ca+DzHm7RjZ9gAVT62V0oVfNrSO5PaQCQ+6C/FTmAPBjfSKO/hDoaQPKxrmqil3eP
         sjiK5r3IQ44o5h+RLXfv4GmrkO5bHrVXomYmMKGRYHaW7x9gnRNt0KQ7GHGEFucsJtp/
         +Tnrtza6/9XWssm1H9Gcyp7PGdEEVP3bu2oEr/W7MFaCiCYJgBtAq+FiY+lDu1N2V2aK
         GIijKHrttvSnS7jN1n6cx8W/RSEXavlGmJrwMa0hsa5U+WqFFRJsl+Gy0GVm2ZdFd1cA
         ROHQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1753807798; x=1754412598;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to
         :message-id:mime-version:subject:date:from:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=d4snbLij+KXpuJ+RdmJpcRKlVG7Avp6Ii50XXzF0ekY=;
        b=IyVJUaDc5OJ51jyulRu2kdU3fDqCkzw453DSEs8JLlL4D9bF+iwtgOGspcA/7X8eQv
         mkEvvfQNGGoFPBtK/Y1k3Q9YTFwVX4Ai6V8/KXTPB0fAtOK/qpIz3tsrQ48e0zxHjnQU
         XxVusHDxdgFWO2oxuxEq+OSV2lEc9ai536VWyLOncsLlA67W2CQHeSxFtqVFxuz/VNfM
         AINosRK0FWWI6CZf8GbhsKO7ZkSsJR4vPfmCk8ODPrmY7wFypvsxPq4nrO09PvgBVsr2
         A6i+Miq5zVmTkyn9h2uK+CTKjxOcGTLy09JDj0wxEvba0Bdqku/vGsc0jspanvz27j8D
         lNMw==
X-Forwarded-Encrypted: i=2; AJvYcCUSecBGpvMjh9grasWwQt+FwKmdjjmEPTiPH2EK3W0BjXRF8FRN33uf+X8Ioy/05TqsELIBoA==@lfdr.de
X-Gm-Message-State: AOJu0Yzhj9lJOccSWA812z/+pkGC3qwDSCMfpy7jk4+Xu3Bu/EVVfCzP
	yv9MHNh/tW9XCWKFz664ZkmcLYobYMDv1E9frPpzst86xV+okLiEchIl
X-Google-Smtp-Source: AGHT+IG1NBAgcUkeH/8khtU39yo77U8LrToM2jSVS+Ez6/NV41Tt4KATszSaR25JEaZ4p7p/3YPjLg==
X-Received: by 2002:a05:6402:2343:b0:612:a86b:ac79 with SMTP id 4fb4d7f45d1cf-61586ee28b3mr202590a12.2.1753807797130;
        Tue, 29 Jul 2025 09:49:57 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfrDqe4jW8u+VRa/egT5kcOvXwgRz1TNiGeJiWzjj5fJQ==
Received: by 2002:a05:6402:348a:b0:605:b948:8854 with SMTP id
 4fb4d7f45d1cf-614c0ab03cfls5322957a12.1.-pod-prod-06-eu; Tue, 29 Jul 2025
 09:49:54 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXUqNdgx/3LlJM3aszmJmGklGuLkSEyfW+KFa0Ej0ERMLFM3PJuAzTxgYFsAmyQ3DzvPOgJXz6/sMk=@googlegroups.com
X-Received: by 2002:a17:906:7313:b0:af2:3f43:d738 with SMTP id a640c23a62f3a-af8fd71f01emr25111566b.17.1753807794465;
        Tue, 29 Jul 2025 09:49:54 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1753807794; cv=none;
        d=google.com; s=arc-20240605;
        b=INttDMAMzbSjupNBhiU5je5+prHqa6GRozIb/KABfUEXnn4fj6y0T2Y/E/L53SCN1M
         9z/CMPTuGvyyl6ZazsxQ7PXnD8IXWwRR3GIEjuubQ+adz+U4hEHtwfuYp6ngzo5pZ2eg
         XBK+mbwqbDFqbxnjBjOsESmiZht0OPMxR06RUh7TPRA+4vTIZ3krkT7WX6qay6mouZJ+
         jIm3DKIiawFvuFe4M1ePvAqxGXjslmZREbvZozVQNl4qWDCrXljn4zG1Oh9QOsQdO20V
         5B6152ZwkdLVV787BM6bkg6gnJ6IvHlrpDt9wlVmMzKpuxoopX5M6K9mHUF5XqD6jIIR
         Vr2A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:message-id:content-transfer-encoding:mime-version:subject
         :date:from:dkim-signature;
        bh=eqFobIPQpQgCyyuokHwscyB7gthAuwhYB6CrRv1tkIY=;
        fh=1SNVD8Qh6Th/beSNL0QWRysCbpFuSr5Hk6zn5NEGntw=;
        b=BpGkATtkyGCzBnW1ZupA05Tq6zM4lJ+qq2IxFzTnNp5eQoMB4OHRRCM5E9PIJExOsz
         PAcNPGK7Imq08Rr7rwyvYMVAiZrdwKm3331imRw+6UnshkZwGoqWZcjlvmrYoiCJEHCC
         vtIDeU6GGVQtIhLOPTukPucJEQ3LrvTWqP5LyH0d9n7HpqiMTmIcc/ewcGHSUxVi/fMy
         QBSsPhjXbUWFUqDeEirCqsUqLvjKx3zsUJPTQbfZU+3bFc4hhyFnB2qdFKu8Q+HIGHVD
         cHLpzm+k9JvZoftNKTZZwydJ1EUk4zB52eZzJbWwV2fs1Ohk1fkZ0UxaBQE7LgUq1IIj
         I/Yw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=wRnsjbVL;
       spf=pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::32e as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x32e.google.com (mail-wm1-x32e.google.com. [2a00:1450:4864:20::32e])
        by gmr-mx.google.com with ESMTPS id a640c23a62f3a-af6358ea5besi26477666b.2.2025.07.29.09.49.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 29 Jul 2025 09:49:54 -0700 (PDT)
Received-SPF: pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::32e as permitted sender) client-ip=2a00:1450:4864:20::32e;
Received: by mail-wm1-x32e.google.com with SMTP id 5b1f17b1804b1-455b63bfa52so1355e9.0
        for <kasan-dev@googlegroups.com>; Tue, 29 Jul 2025 09:49:54 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCU6G90L/WgE81qsjIkU5VrTExdjONi5Wk0zqeLVRkrRaEg1LnQYxylSGa8Rrpwu4hABOPO5TVkzLqE=@googlegroups.com
X-Gm-Gg: ASbGncszwbCXbr+0uoGbExu7u7yP2tl8DzFWhE9bBUPI1srYBgmsEWzBwS1p/PC62ST
	MF/kZDQZ5R+sftth+hAA4HtCTMD9mGGlQ0IoYKcYtrHVu3DXlIXfJajRuAqX8JIKFGqIEP6zT1U
	jtx6eSVqa/lI+mgo8s5hjkrYJdz0KD3GrpxKjX/kvV0OqIkXB2rIWS6PRBsbn43CkTvbxsDIkft
	URpq9SEEm7wweFqCDONc54SkMcuAVRGTgU4INVlBlQVYE1f4yK4vrpgYMs+WOOOKwmocDscgmxH
	af0oS8EPEpPKABaQqSH+CQn4Br06GH8apAJl3QhY4qYQCE6cgHe0ZwGIUCwopwUmmpPqR5hl80Q
	Ohwx+KUiLs2s=
X-Received: by 2002:a05:600c:1c9e:b0:442:feea:622d with SMTP id 5b1f17b1804b1-4588dc6d080mr2038245e9.1.1753807793858;
        Tue, 29 Jul 2025 09:49:53 -0700 (PDT)
Received: from localhost ([2a00:79e0:9d:4:fcf7:d8ea:691d:7dd3])
        by smtp.gmail.com with UTF8SMTPSA id 5b1f17b1804b1-4588d900725sm24490935e9.1.2025.07.29.09.49.52
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 29 Jul 2025 09:49:53 -0700 (PDT)
From: "'Jann Horn' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 29 Jul 2025 18:49:40 +0200
Subject: [PATCH v2] kasan: add test for SLAB_TYPESAFE_BY_RCU quarantine
 skipping
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Message-Id: <20250729-kasan-tsbrcu-noquarantine-test-v2-1-d16bd99309c9@google.com>
X-B4-Tracking: v=1; b=H4sIAKT7iGgC/33NywrCMBCF4VcpszYQJ6axfRXpIomjDkJqcylC6
 bsbzMKdy/8szrdBosiUYOw2iLRy4jnUwEMH/mHDnQRfawNK1NLgWTxtskHk5KIvIsxLsdGGzIF
 EppSF9gaV6g1J3UM9eUW68fsLXKbWkZZSndzGH1PVhqg/CKE0zg2DJDyN6xGmff8A68MMc8QAA
 AA=
X-Change-ID: 20250728-kasan-tsbrcu-noquarantine-test-5c723367e056
To: Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
 Alexander Potapenko <glider@google.com>, 
 Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, 
 Vincenzo Frascino <vincenzo.frascino@arm.com>, 
 Andrew Morton <akpm@linux-foundation.org>
Cc: Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com, 
 linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
 Jann Horn <jannh@google.com>
X-Mailer: b4 0.15-dev
X-Developer-Signature: v=1; a=ed25519-sha256; t=1753807789; l=2477;
 i=jannh@google.com; s=20240730; h=from:subject:message-id;
 bh=xC2SGCiiovnqO7RAnpaQ8tLK7DE0kascKCn2FPGbvbY=;
 b=7zrrhKfOV53X6HcBNKhvT/AH+5h+FvXFq+iJcJVzFIKzpNbAkLCHo7AVIcx12OW73XbYHN9uW
 P6My267RH23AaWkKXPCuOAPAQBR5RpcleEVFcaYXJutPWNe59pnR50F
X-Developer-Key: i=jannh@google.com; a=ed25519;
 pk=AljNtGOzXeF6khBXDJVVvwSEkVDGnnZZYqfWhP1V+C8=
X-Original-Sender: jannh@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=wRnsjbVL;       spf=pass
 (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::32e as
 permitted sender) smtp.mailfrom=jannh@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
X-Original-From: Jann Horn <jannh@google.com>
Reply-To: Jann Horn <jannh@google.com>
Precedence: list
Mailing-list: list kasan-dev@googlegroups.com; contact kasan-dev+owners@googlegroups.com
List-ID: <kasan-dev.googlegroups.com>
X-Spam-Checked-In-Group: kasan-dev@googlegroups.com
X-Google-Group-Id: 358814495539
List-Post: <https://groups.google.com/group/kasan-dev/post>, <mailto:kasan-dev@googlegroups.com>
List-Help: <https://groups.google.com/support/>, <mailto:kasan-dev+help@googlegroups.com>
List-Archive: <https://groups.google.com/group/kasan-dev
List-Subscribe: <https://groups.google.com/group/kasan-dev/subscribe>, <mailto:kasan-dev+subscribe@googlegroups.com>
List-Unsubscribe: <mailto:googlegroups-manage+358814495539+unsubscribe@googlegroups.com>,
 <https://groups.google.com/group/kasan-dev/subscribe>

Verify that KASAN does not quarantine objects in SLAB_TYPESAFE_BY_RCU slabs
if CONFIG_SLUB_RCU_DEBUG is off.

Signed-off-by: Jann Horn <jannh@google.com>
---
changes in v2:
 - disable migration to ensure that all SLUB operations use the same
   percpu state (vbabka)
 - use EXPECT instead of ASSERT for pointer equality check so that
   expectation failure doesn't terminate the test with migration still
   disabled
---
 mm/kasan/kasan_test_c.c | 38 ++++++++++++++++++++++++++++++++++++++
 1 file changed, 38 insertions(+)

diff --git a/mm/kasan/kasan_test_c.c b/mm/kasan/kasan_test_c.c
index 5f922dd38ffa..0d50402d492c 100644
--- a/mm/kasan/kasan_test_c.c
+++ b/mm/kasan/kasan_test_c.c
@@ -1073,6 +1073,43 @@ static void kmem_cache_rcu_uaf(struct kunit *test)
 	kmem_cache_destroy(cache);
 }
 
+/*
+ * Check that SLAB_TYPESAFE_BY_RCU objects are immediately reused when
+ * CONFIG_SLUB_RCU_DEBUG is off, and stay at the same address.
+ */
+static void kmem_cache_rcu_reuse(struct kunit *test)
+{
+	char *p, *p2;
+	struct kmem_cache *cache;
+
+	KASAN_TEST_NEEDS_CONFIG_OFF(test, CONFIG_SLUB_RCU_DEBUG);
+
+	cache = kmem_cache_create("test_cache", 16, 0, SLAB_TYPESAFE_BY_RCU,
+				  NULL);
+	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, cache);
+
+	migrate_disable();
+	p = kmem_cache_alloc(cache, GFP_KERNEL);
+	if (!p) {
+		kunit_err(test, "Allocation failed: %s\n", __func__);
+		goto out;
+	}
+
+	kmem_cache_free(cache, p);
+	p2 = kmem_cache_alloc(cache, GFP_KERNEL);
+	if (!p2) {
+		kunit_err(test, "Allocation failed: %s\n", __func__);
+		goto out;
+	}
+	KUNIT_EXPECT_PTR_EQ(test, p, p2);
+
+	kmem_cache_free(cache, p2);
+
+out:
+	migrate_enable();
+	kmem_cache_destroy(cache);
+}
+
 static void kmem_cache_double_destroy(struct kunit *test)
 {
 	struct kmem_cache *cache;
@@ -2098,6 +2135,7 @@ static struct kunit_case kasan_kunit_test_cases[] = {
 	KUNIT_CASE(kmem_cache_double_free),
 	KUNIT_CASE(kmem_cache_invalid_free),
 	KUNIT_CASE(kmem_cache_rcu_uaf),
+	KUNIT_CASE(kmem_cache_rcu_reuse),
 	KUNIT_CASE(kmem_cache_double_destroy),
 	KUNIT_CASE(kmem_cache_accounted),
 	KUNIT_CASE(kmem_cache_bulk),

---
base-commit: 0df7d6c9705b283d5b71ee0ae86ead05bd3a55a9
change-id: 20250728-kasan-tsbrcu-noquarantine-test-5c723367e056
prerequisite-change-id: 20250723-kasan-tsbrcu-noquarantine-e207bb990e24:v1
prerequisite-patch-id: 4fab9d3a121bfcaacc32a40f606b7c04e0c6fdd0

-- 
Jann Horn <jannh@google.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250729-kasan-tsbrcu-noquarantine-test-v2-1-d16bd99309c9%40google.com.
