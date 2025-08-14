Return-Path: <kasan-dev+bncBCQ2XPNX7EOBBH7Z67CAMGQEPLAKAQA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43c.google.com (mail-wr1-x43c.google.com [IPv6:2a00:1450:4864:20::43c])
	by mail.lfdr.de (Postfix) with ESMTPS id 36EF8B26A88
	for <lists+kasan-dev@lfdr.de>; Thu, 14 Aug 2025 17:11:29 +0200 (CEST)
Received: by mail-wr1-x43c.google.com with SMTP id ffacd0b85a97d-3b9dc5c288esf807065f8f.1
        for <lists+kasan-dev@lfdr.de>; Thu, 14 Aug 2025 08:11:29 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755184288; cv=pass;
        d=google.com; s=arc-20240605;
        b=ggD3/RuoEw1GL7+EcALcp27MbL8HWcheU18HFzC7OGHwOljD24n9ph4uYcCJ3aCl6X
         4LDwudR+EtLN9QoYxsZOYW3UgpskiCe0fabdi15UJuvAverzfCMBn/dmHBL/8Dn1OqQQ
         EtsinEPWG5QPB9dultsIn7mwJlRIzu2UHDCvPS57o6QABhHkmcqgOnugcYHTNjcVq5P3
         PSIpqzkR5I63yqNTVlL+P5dMSnUOTkq4qKMQ0hpl4uA/nNMd+6/X8MLLXLJvcg8nRxkS
         QBNKNIM6FhhlL+p1vn/Jrco4/dx9yVLm6gTS72JxaAgVU0mnnpqsr3m5PCQ+u2dxgQ4J
         OHRA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:message-id
         :mime-version:subject:date:from:dkim-signature;
        bh=rDW10ox0g59eZ5tINPFMv49rmui3ajjbq+C8kqA3Qac=;
        fh=SEjGkLJEABUcXb8xJjWp/VPdnu5qjjWCaguNIEr9HgU=;
        b=SHB5sFHK4kAKL10D9zAC43SweZpOSrDgH6+PIXQTXPwkElQpXk+geHZlC/1RBMOZsF
         fW20bjHxs+BWrGqqTfKkQqBqmU8gWmcciCixmW+4Xwbba7tGeNNmsv85ajvRxNvZow7H
         FmfobfT8cKljF+MFh8E6IM7z4vCmCT8URXc/Wig22LxmYnw4CZDGmKxarLLoRz7+j4Up
         agpvUfyLnQdeISW6F1YDhDCn+XpGaUBNcJtCK/asqNBii02A6PimAd/ZWxNy+phx7iaD
         RagLIZyNgOb4uwHTl/7liEtOJyKgJiPbHxedpTb87QhOCkEhvmihFrLR8z4zXuw0pNOV
         w5NA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=23FJDgZn;
       spf=pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::32b as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755184288; x=1755789088; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to
         :message-id:mime-version:subject:date:from:from:to:cc:subject:date
         :message-id:reply-to;
        bh=rDW10ox0g59eZ5tINPFMv49rmui3ajjbq+C8kqA3Qac=;
        b=SeD2SyvmdhX8ksFegSHq/4HoM7u7NXccX3SM2MA6ahX7uqRb1eJ9g+4rLqsNlZR7Za
         eTId3F3NjwSUZ1Jk2vx+XwQNIrqF8OLUK1AHq/4qpTdsbq2yExWbC6UlydKOtikH5rYE
         3fbu0wyC17V3ZE8QQUF4M7oIUeiV6yMOpA7FyNBb6HgLw6eIjVspbfh2jEY4sbYb4egs
         Dwjo+bEU9bHolLWu12Sd1dddHLlB3SwGVNDQmQQqGTVN0CKC2jAIkfVuOkfwPiC3n/Ih
         S8H5aprsDfSCn6IaO8OGnpZmSdufu+apkfQtA9m1AyH1SByfOqGZh1ULRWXGZ22zsu3k
         CM2A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755184288; x=1755789088;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to
         :message-id:mime-version:subject:date:from:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=rDW10ox0g59eZ5tINPFMv49rmui3ajjbq+C8kqA3Qac=;
        b=fLNocdfshH1P0oWWZFMipadRYgZ2G+pdN73s03v3M+U8lkKqds3qpmsbyL59oD4O5L
         HE/rzvh+lBjJ+DgnutytskgMYfykX1el0dqYzKAaJF8Iiozn3D41r6dxjHbyihg5ph2L
         J5wSv7jUjiStFJ1ZiIF/XzrJIxPz4Lajfniij/v+b6dVJ7RAbFwWoaSDTgmKTm/IvfBs
         7ibFr+Hjl+oP4zSsUfqOVfetHrgMyKpUc89I+csYSPMxI8xm4CP+oV2ZdF4GdagTTcnm
         tU+PAMVFf2555nYNk8z/JBF/0eTsc7uka9OpYLXLq3uuasGWAYARtG2Kwcz4+IuHAPl2
         LLtw==
X-Forwarded-Encrypted: i=2; AJvYcCXK7N2heM/Q21CAfq8+U3T9qApaAGD0Uu83v4sLk7Khi2E9wWVf61K9ccVrLZ6FoOCOte4aiQ==@lfdr.de
X-Gm-Message-State: AOJu0YxH4rwCJdtuwAKdZe9xXFyFu7faO9ejp0w1r4+gQMk6SExbPh2F
	9xZdhOamlHu31Ex4YXJ5TU10r/kHU/3xmxkH/f7lowHKymzfKg9L68zm
X-Google-Smtp-Source: AGHT+IFLXjX7AOvHZWxj0+uNV21e/Wk7qg1b34ESHx5WlV854tXb5SoEwxOH194//XuogkFs8LhXYA==
X-Received: by 2002:a05:6000:2891:b0:3b8:f2f1:728c with SMTP id ffacd0b85a97d-3b9edf39836mr2866523f8f.34.1755184288374;
        Thu, 14 Aug 2025 08:11:28 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZengeow5XMv9TOFRCHbCyRRFKWRPsleK8F9O0wjgOuZSQ==
Received: by 2002:a5d:5f4d:0:b0:3b7:868d:435f with SMTP id ffacd0b85a97d-3b9bffd4a5cls572349f8f.1.-pod-prod-09-eu;
 Thu, 14 Aug 2025 08:11:25 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCX7lpfUiPExfgS0Xy2Usu0+Ss0nUK4JzX4ld9JJszzo+JB/QYqAbcNJb3YQMJH6tLPYiOJrg8e88YA=@googlegroups.com
X-Received: by 2002:a05:6000:2209:b0:3b8:ebbe:1792 with SMTP id ffacd0b85a97d-3b9e415b796mr3285246f8f.10.1755184285307;
        Thu, 14 Aug 2025 08:11:25 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755184285; cv=none;
        d=google.com; s=arc-20240605;
        b=IzBstJDKh16UNf10Gk/kis6O9hqvdcZGdhgo7T4qVtTI5S6+SJyCOLKobKs3/jjeha
         RJqW0DtfWEk6ShDSS3HB+H3lBGUG62skatYObqEgRz+RDQt3vRV/1i/UsPUubmxq94j0
         U/jrQXrWXkNYjr1K4W3MX1t/CGnIIx+wAOF/4S4nnRRwGscycycTXbgHa3fZAqsyeUJZ
         lXjEHwYqrZlV7mrB1HVjLw6UOs34rjPuz2mIvu7OL/H6/rGoTEWIzPAWugWJbO5aoRPZ
         rfFWIYYBAI7QmVGUHUKRVYly02n23KyuZXFPVTBASo2OjfjHd7d9CBZ/f8C7adywDOV9
         Yx0g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:message-id:content-transfer-encoding:mime-version:subject
         :date:from:dkim-signature;
        bh=SskdpEkHcdWpBQfUP2UXfkwhjkYyC/FVECNBfHZs9y8=;
        fh=k8hvLNV00Rq1nhkl1O8/OUmqmqP8Ver97f6ly6E6nck=;
        b=Pc4qcgIMI+dmv3qJot1HOtJ+xEJv9bkx5L6iLvHfM5x/UwSPx/5PyQPalWKW5rRu0k
         k3cwk8IDIT0O8OorciqmupXEYUGcmZDxdl/lSWtJNcLcHuNZTuCD7xlo2sPUswHbyovg
         CIAf7OCBI0ldtXGeyUi/y+7aGVwqo4Aj1g6XT8VgEnEDljUR+qCpjorxmwKYQGqPlZYL
         igBsnsCEmyBnGJJGyTDPtxFFQG+mtTEOkjgP7lpPsxFcUlqySVNSRvO6iiQnSyUoetfk
         sflPcAJc3XJCXIegpqPqXXr7x115ezZkfMe3xs9r8R8TBFg/MExNz3rAse67PEq47b69
         siHw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=23FJDgZn;
       spf=pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::32b as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x32b.google.com (mail-wm1-x32b.google.com. [2a00:1450:4864:20::32b])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-3b79d191683si181090f8f.4.2025.08.14.08.11.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 14 Aug 2025 08:11:25 -0700 (PDT)
Received-SPF: pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::32b as permitted sender) client-ip=2a00:1450:4864:20::32b;
Received: by mail-wm1-x32b.google.com with SMTP id 5b1f17b1804b1-459fbc92e69so77745e9.0
        for <kasan-dev@googlegroups.com>; Thu, 14 Aug 2025 08:11:25 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXNbe7/w0x68wp6NjJLbJdTHHvXiYS1wCtvFEsPWmsUwvXxDvPBdpzQ7jSQNPAkh3nGDsCK2/5j6Fw=@googlegroups.com
X-Gm-Gg: ASbGncs3ICikBVDBnL3KN85Cy+LkUDYFu3LJHJd57qLA5XYkLXX/O3v/7VayTDTE90g
	bHwo7vsRWY0iusHEodqbjH7SsFuDoka5KOH8Tlid4A5FzzrMRBKhHLlD6QJrS7xYLjUCG65I4rO
	smkJkztVlhdNOwFoNMZGP2t61CFFvVQ6IhZnH2ULUMk/kKgDpWc5UNF2MAOxjMpZLp32yUdSCq0
	u6yIMzBCU4/lMMNkHQQ4XI6OgKqR5asuxaQug7KI85e1Exu1imjY6v2jDBXDJGyizVwp+Bw1gdd
	OlSEYrrt4VGrPYpHJ8uLunggNaoCYkPRu7jWz7fi2Slzut+60YeEzr6uzWWNZAQITHVUW0tQtHz
	f6SNMe3mp5Dm197i9
X-Received: by 2002:a05:600c:c4a6:b0:439:8f59:2c56 with SMTP id 5b1f17b1804b1-45a1b177b3amr2085275e9.2.1755184284501;
        Thu, 14 Aug 2025 08:11:24 -0700 (PDT)
Received: from localhost ([2a00:79e0:9d:4:3dd3:b636:a51b:d0a4])
        by smtp.gmail.com with UTF8SMTPSA id ffacd0b85a97d-3ba54b6c93fsm1524246f8f.12.2025.08.14.08.11.23
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 14 Aug 2025 08:11:23 -0700 (PDT)
From: "'Jann Horn' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 14 Aug 2025 17:11:10 +0200
Subject: [PATCH v3] kasan: add test for SLAB_TYPESAFE_BY_RCU quarantine
 skipping
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Message-Id: <20250814-kasan-tsbrcu-noquarantine-test-v3-1-9e9110009b4e@google.com>
X-B4-Tracking: v=1; b=H4sIAI38nWgC/4WPwRKCIBRFf8VhHQ1CarjqPxoXgC9lKkhApsbx3
 yN1pl0tz1ucc9+EPDgNHtXZhBxE7bU1CdguQ6oXpgOs28SIElqQih7xVXhhcPDSqREbO4zCCRO
 0ARzAB1yoijJWVkCKEiXJw8FFP5fAuVnZwTCmTliP30ydbRH2IwKUVFJyToAe6pijj7PXPlj3W
 n6IdJFuJv5vbqQ4x21eypZzRrjip87a7gZ7Ze+omef5DVQWozEhAQAA
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
X-Developer-Signature: v=1; a=ed25519-sha256; t=1755184280; l=2857;
 i=jannh@google.com; s=20240730; h=from:subject:message-id;
 bh=1jDJoKW+0uL8pCUw24xwM3FK0vdRrfgga7GPmYtrP6Q=;
 b=7eqsCi6f+oUTHibo06jMfimP7X6uftqxmyns3NemnHriDHDs4/42buGL0Ep6842p7TLguABrF
 82V650jX80EB7QQQKwD0jNYibeGS0nG/peuF5xjkz/gf8dq6hlxxyc7
X-Developer-Key: i=jannh@google.com; a=ed25519;
 pk=AljNtGOzXeF6khBXDJVVvwSEkVDGnnZZYqfWhP1V+C8=
X-Original-Sender: jannh@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=23FJDgZn;       spf=pass
 (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::32b as
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

Acked-by: Vlastimil Babka <vbabka@suse.cz>
Signed-off-by: Jann Horn <jannh@google.com>
---
Changes in v3:
 - add vbabka's ack
 - make comment more verbose (andreyknvl)
 - Link to v2: https://lore.kernel.org/r/20250729-kasan-tsbrcu-noquarantine-test-v2-1-d16bd99309c9@google.com
Changes in v2:
 - disable migration to ensure that all SLUB operations use the same
   percpu state (vbabka)
 - use EXPECT instead of ASSERT for pointer equality check so that
   expectation failure doesn't terminate the test with migration still
   disabled
---
 mm/kasan/kasan_test_c.c | 40 ++++++++++++++++++++++++++++++++++++++++
 1 file changed, 40 insertions(+)

diff --git a/mm/kasan/kasan_test_c.c b/mm/kasan/kasan_test_c.c
index 5f922dd38ffa..0affadb201c2 100644
--- a/mm/kasan/kasan_test_c.c
+++ b/mm/kasan/kasan_test_c.c
@@ -1073,6 +1073,45 @@ static void kmem_cache_rcu_uaf(struct kunit *test)
 	kmem_cache_destroy(cache);
 }
 
+/*
+ * Check that SLAB_TYPESAFE_BY_RCU objects are immediately reused when
+ * CONFIG_SLUB_RCU_DEBUG is off, and stay at the same address.
+ * Without this, KASAN builds would be unable to trigger bugs caused by
+ * SLAB_TYPESAFE_BY_RCU users handling reycled objects improperly.
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
@@ -2098,6 +2137,7 @@ static struct kunit_case kasan_kunit_test_cases[] = {
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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250814-kasan-tsbrcu-noquarantine-test-v3-1-9e9110009b4e%40google.com.
