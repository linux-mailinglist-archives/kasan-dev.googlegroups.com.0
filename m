Return-Path: <kasan-dev+bncBAABBW7ITKPQMGQEP7R4URY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43a.google.com (mail-wr1-x43a.google.com [IPv6:2a00:1450:4864:20::43a])
	by mail.lfdr.de (Postfix) with ESMTPS id 7098869290C
	for <lists+kasan-dev@lfdr.de>; Fri, 10 Feb 2023 22:17:16 +0100 (CET)
Received: by mail-wr1-x43a.google.com with SMTP id k12-20020a5d6d4c000000b002bff57fc7fcsf1588692wri.19
        for <lists+kasan-dev@lfdr.de>; Fri, 10 Feb 2023 13:17:16 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1676063836; cv=pass;
        d=google.com; s=arc-20160816;
        b=jBqSvTs4M4LgEMKjcInIYxEyB+HdhXyZ7p224+8MQVPINb+LBL2P7TlPBrUmVORW5w
         3VB5LSu634ffx13qD2Gb2vkbJUfXiF0bZaAc509yXzVAFa8FVQMVDYfVbEgSlLLq+L7/
         JMmvvLCMhxUNNce54cFADJDR+DTf22wrTs6wbwhq9jlSIzJF/lktMwj1TGmBLx1IgHhE
         ySi+ODbj4F0MZyoXB+XNjStoT/tkjlAenO5tW4kM1qGs1xiTv/zVYVf5sYBDq+xkK9RG
         6AYUTe9OO7FPnnBfCibZKF98nHSRmOREUfPmwyVRtbi0ipTjfl9Lxl/1I4zRnoES7XhL
         bhSA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=bDuTURYYXDylqQbvOjM+FAEPnbfLhVR5NBtfP+NEgNc=;
        b=cd/sQkbm3t0Sq7wmUPZqfh2qt8YOhqkZBJX1eAKXAJ2523jGraRf+Lid/t28LNDr3z
         UnScZZ+VHB66NLOzX3HKkMFG4us8CexWxaCD1zCthHuGel0HRXG1JYszko7jDvgeOnls
         jCKmGjZFwH0pReqhSbcDdUUzG26A99PF1pFYu1Eno8o7q0f/n/ZKsKI59MYz57nHw8KH
         UWmQy/pTjNQG74ZA335t6Osf27Bkiqc+y9BV3v8/jOxrzs3PLGQxmwuCW4iTiLTD7vE/
         2UlO5oV8E2DyPsbgaX8DRR+RgrqnuNs+RTYnytuYoH+VnP8MYRfeq2KXWzQL93dtS4/r
         RQrA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=c+1AHXrK;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.45 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=bDuTURYYXDylqQbvOjM+FAEPnbfLhVR5NBtfP+NEgNc=;
        b=DfyD8MXNssclbPUlRSHrs3x6HJZNFt+T7NNsej3OS7p/S7vpou2RNDkvdfWgyPRahV
         49gQ+utY1+560nEsjWmI9E1O5NJvVLdRxCZkxcYjgYRu6KGB/arjWFtnR4BJIyl4M76H
         cenhV3L0THAcBnzkLMOSGhLCIm2f7A7Ff5ox6Moj199UtuPyjv3W+3pPuCBsOx2VAjqW
         mKLRu/rmC4ZSGXSYZ0jSDR/3uDRzK1EBnjVNd79/7iMK+aHl4sRJII30IYsYDRRrGylg
         09QdutlZBAr0jgWN/jUYPBhO+MgohyJQpx5Hj3Ul77vLFRQPePEnFsp5ZNDZa1yQxYfl
         duCg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=bDuTURYYXDylqQbvOjM+FAEPnbfLhVR5NBtfP+NEgNc=;
        b=NdI6OMPBWXON9Bo3HrThUL8C0I/AC1T4Ioza3M1UTxQYRF0E0Iro7rOwrsj1i4WdKU
         k42/G2mAqFETjJtbZJkf2CWp7Qtpkzd1s/d2/jVePyrkQMpRzE2At6rpG/oIl0Gtsaku
         nMzVkaVRvGrYKCMHVOJrRy9yPWKqHpYRhpZwoxKDxYK5cl4Or+HpgVfpgOGKpFIP7ifo
         n9bJo04zKvadD4KQyo0KtGlWU7Yf/v/4mdRl/sslBviOdrSnCob0BO2x8wND4cJNmpJS
         iwrzBdkYjSMxmcJZJa8jr8eAiRETXct/+tD1Wv7QErLph0kBXLayd0Ks0znUQs8OFwVr
         fo8w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKUHiFp+U3ZSkVTJDyRbR/kGCLYmKmgQDcmnzaznI7jlm6RfdfE/
	DI0cnRV87DKW3Q35Gs5UJ9o=
X-Google-Smtp-Source: AK7set97LWcD3boXpA97vHE6mahGGAcRhG8pl9Tb077gM3XmOq4MOPdynhStykHwgClWIBDtM74bXg==
X-Received: by 2002:a05:600c:54c5:b0:3df:a04a:1b5 with SMTP id iw5-20020a05600c54c500b003dfa04a01b5mr1251886wmb.88.1676063835988;
        Fri, 10 Feb 2023 13:17:15 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:58cd:0:b0:2bf:ccef:53a6 with SMTP id o13-20020a5d58cd000000b002bfccef53a6ls2228379wrf.0.-pod-prod-gmail;
 Fri, 10 Feb 2023 13:17:15 -0800 (PST)
X-Received: by 2002:adf:f310:0:b0:2bf:ad61:6018 with SMTP id i16-20020adff310000000b002bfad616018mr16099078wro.10.1676063835174;
        Fri, 10 Feb 2023 13:17:15 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1676063835; cv=none;
        d=google.com; s=arc-20160816;
        b=AFa7Cs8g191WxPf2QT6lWAyer3jVyjtf3VWLTikM+bOfQAfcp2RA/TXh2/Jz429KUm
         QEOIRJwJYUFd9blvtsw04FAV28WyLCCpeVtTgAADhsi3/bPHcY0/isFT4+AZz5Kv2J9v
         A1zl5bfxOIN/e77v3rnIu1UnkglmXp2uUehJ0J0TPBNWVSX5c8ChUO8dRb2ZmU3KekFN
         KPYuDnigWk8ON25lzCp8dAxKAAqKP15R23DeYvpQbfSh4vX3HvkaWMMevJVjCOz6SGKp
         tQIpnnCq3mBfMJYBr0gWSKPbnF5+fr3WqaZYDvu9ZndnmbjuA3l6YvG8RyLlle0ytunY
         0vfg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=GEKMsp8Q42qNZP01Wy8jBcM+2lagQkM9mc2pThcVWag=;
        b=eXPHmMAI4KNoXp0Cb1PFc6hsrOt/XAwUZ5aOFHzMCeB+ZZNipJUjJ62wrSNTHxfzv1
         rJ9mO8TY9J+6UznVZijyjidaDjaZNsZYn2Ctq/w8PFN/6HnI55P7QLplrXdifsqd8K3u
         G4mLZBgN74x2mPtkGePQbiCSTbmYdpTc7jRi9kmEzSFwy6tDkmf6yza/VKJt0qIO/hx0
         9WqGVlGhf4YcPxkh0Zodh5aXTwMiPE/F+ljx3VXhjQdUJqlLPzeym2AMxZOD1tjmoYlp
         QXoVqvUk83Q63aklb7jFnI05WRDFrTStTmldZUcfE3CvEqj/xfidvzCxM/RR7EhvpkBp
         wcDA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=c+1AHXrK;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.45 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-45.mta1.migadu.com (out-45.mta1.migadu.com. [95.215.58.45])
        by gmr-mx.google.com with ESMTPS id 1-20020a056000156100b002c54cdd5f0bsi57746wrz.4.2023.02.10.13.17.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 10 Feb 2023 13:17:15 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.45 as permitted sender) client-ip=95.215.58.45;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Vlastimil Babka <vbabka@suse.cz>,
	kasan-dev@googlegroups.com,
	Evgenii Stepanov <eugenis@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH v2 08/18] lib/stackdepot: rename hash table constants and variables
Date: Fri, 10 Feb 2023 22:15:56 +0100
Message-Id: <f166dd6f3cb2378aea78600714393dd568c33ee9.1676063693.git.andreyknvl@google.com>
In-Reply-To: <cover.1676063693.git.andreyknvl@google.com>
References: <cover.1676063693.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=c+1AHXrK;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.45 as
 permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Content-Type: text/plain; charset="UTF-8"
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

From: Andrey Konovalov <andreyknvl@google.com>

Give more meaningful names to hash table-related constants and variables:

1. Rename STACK_HASH_SCALE to STACK_HASH_TABLE_SCALE to point out that it
   is related to scaling the hash table.

2. Rename STACK_HASH_ORDER_MIN/MAX to STACK_BUCKET_NUMBER_ORDER_MIN/MAX
   to point out that it is related to the number of hash table buckets.

3. Rename stack_hash_order to stack_bucket_number_order for the same
   reason as #2.

No functional changes.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

---

Changes v1->v2:
- Rename STACK_HASH_SCALE to STACK_HASH_TABLE_SCALE.
---
 lib/stackdepot.c | 42 +++++++++++++++++++++---------------------
 1 file changed, 21 insertions(+), 21 deletions(-)

diff --git a/lib/stackdepot.c b/lib/stackdepot.c
index de1afe3fb24d..d1ab53197353 100644
--- a/lib/stackdepot.c
+++ b/lib/stackdepot.c
@@ -76,17 +76,17 @@ static bool __stack_depot_early_init_requested __initdata = IS_ENABLED(CONFIG_ST
 static bool __stack_depot_early_init_passed __initdata;
 
 /* Use one hash table bucket per 16 KB of memory. */
-#define STACK_HASH_SCALE	14
+#define STACK_HASH_TABLE_SCALE 14
 /* Limit the number of buckets between 4K and 1M. */
-#define STACK_HASH_ORDER_MIN	12
-#define STACK_HASH_ORDER_MAX	20
+#define STACK_BUCKET_NUMBER_ORDER_MIN 12
+#define STACK_BUCKET_NUMBER_ORDER_MAX 20
 /* Initial seed for jhash2. */
 #define STACK_HASH_SEED 0x9747b28c
 
 /* Hash table of pointers to stored stack traces. */
 static struct stack_record **stack_table;
 /* Fixed order of the number of table buckets. Used when KASAN is enabled. */
-static unsigned int stack_hash_order;
+static unsigned int stack_bucket_number_order;
 /* Hash mask for indexing the table. */
 static unsigned int stack_hash_mask;
 
@@ -137,28 +137,28 @@ int __init stack_depot_early_init(void)
 	 * in fuzzing scenarios, which leads to a large number of different
 	 * stack traces being stored in stack depot.
 	 */
-	if (kasan_enabled() && !stack_hash_order)
-		stack_hash_order = STACK_HASH_ORDER_MAX;
+	if (kasan_enabled() && !stack_bucket_number_order)
+		stack_bucket_number_order = STACK_BUCKET_NUMBER_ORDER_MAX;
 
 	if (!__stack_depot_early_init_requested || stack_depot_disabled)
 		return 0;
 
 	/*
-	 * If stack_hash_order is not set, leave entries as 0 to rely on the
-	 * automatic calculations performed by alloc_large_system_hash.
+	 * If stack_bucket_number_order is not set, leave entries as 0 to rely
+	 * on the automatic calculations performed by alloc_large_system_hash.
 	 */
-	if (stack_hash_order)
-		entries = 1UL << stack_hash_order;
+	if (stack_bucket_number_order)
+		entries = 1UL << stack_bucket_number_order;
 	pr_info("allocating hash table via alloc_large_system_hash\n");
 	stack_table = alloc_large_system_hash("stackdepot",
 						sizeof(struct stack_record *),
 						entries,
-						STACK_HASH_SCALE,
+						STACK_HASH_TABLE_SCALE,
 						HASH_EARLY | HASH_ZERO,
 						NULL,
 						&stack_hash_mask,
-						1UL << STACK_HASH_ORDER_MIN,
-						1UL << STACK_HASH_ORDER_MAX);
+						1UL << STACK_BUCKET_NUMBER_ORDER_MIN,
+						1UL << STACK_BUCKET_NUMBER_ORDER_MAX);
 	if (!stack_table) {
 		pr_err("hash table allocation failed, disabling\n");
 		stack_depot_disabled = true;
@@ -181,13 +181,13 @@ int stack_depot_init(void)
 		goto out_unlock;
 
 	/*
-	 * Similarly to stack_depot_early_init, use stack_hash_order
+	 * Similarly to stack_depot_early_init, use stack_bucket_number_order
 	 * if assigned, and rely on automatic scaling otherwise.
 	 */
-	if (stack_hash_order) {
-		entries = 1UL << stack_hash_order;
+	if (stack_bucket_number_order) {
+		entries = 1UL << stack_bucket_number_order;
 	} else {
-		int scale = STACK_HASH_SCALE;
+		int scale = STACK_HASH_TABLE_SCALE;
 
 		entries = nr_free_buffer_pages();
 		entries = roundup_pow_of_two(entries);
@@ -198,10 +198,10 @@ int stack_depot_init(void)
 			entries <<= (PAGE_SHIFT - scale);
 	}
 
-	if (entries < 1UL << STACK_HASH_ORDER_MIN)
-		entries = 1UL << STACK_HASH_ORDER_MIN;
-	if (entries > 1UL << STACK_HASH_ORDER_MAX)
-		entries = 1UL << STACK_HASH_ORDER_MAX;
+	if (entries < 1UL << STACK_BUCKET_NUMBER_ORDER_MIN)
+		entries = 1UL << STACK_BUCKET_NUMBER_ORDER_MIN;
+	if (entries > 1UL << STACK_BUCKET_NUMBER_ORDER_MAX)
+		entries = 1UL << STACK_BUCKET_NUMBER_ORDER_MAX;
 
 	pr_info("allocating hash table of %lu entries via kvcalloc\n", entries);
 	stack_table = kvcalloc(entries, sizeof(struct stack_record *), GFP_KERNEL);
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/f166dd6f3cb2378aea78600714393dd568c33ee9.1676063693.git.andreyknvl%40google.com.
