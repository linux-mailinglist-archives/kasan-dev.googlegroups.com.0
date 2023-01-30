Return-Path: <kasan-dev+bncBAABBLO34CPAMGQE7FR2HNI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33b.google.com (mail-wm1-x33b.google.com [IPv6:2a00:1450:4864:20::33b])
	by mail.lfdr.de (Postfix) with ESMTPS id 7686E681BC4
	for <lists+kasan-dev@lfdr.de>; Mon, 30 Jan 2023 21:50:54 +0100 (CET)
Received: by mail-wm1-x33b.google.com with SMTP id iz20-20020a05600c555400b003dc53fcc88fsf2495352wmb.2
        for <lists+kasan-dev@lfdr.de>; Mon, 30 Jan 2023 12:50:54 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1675111854; cv=pass;
        d=google.com; s=arc-20160816;
        b=pYZOYJrOt0Qoj0qGYCWmTUfJ/oYkzQbqYJ8qvi1M8xaIcRQsgtlZLSF5CHTXRZDu51
         4KbHNrszhg0MP040+fIw3EJp/6ULq4lZzr2md/9I1WZ/DaZANH0JJlPoefpD+WNSAbAN
         prThqH8fI1TOLcHsrDxLPZg9FmkooNvKSUOaOHHoT/s0Jo89/Qjq7vduBxPK/LL8K04a
         Ukk+p5V21rg+e4OEFb01q5A5oHeZgTvOeW8sA+/1YX28hKq7LthQ5lWVxa8WvjZjGSjk
         S061kRLdlbOxfF0WjmbVtRTaFr+b1fMSoSsYDFWStIeDCXRlvxMtrdfE/O/47KGUECsF
         zw5A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=cUflGMxQZzL350vZWXN2PtZEqIB5ulkK6RRbqYOz+hA=;
        b=p2Yot1QB+ruiupQtNdCoDjI84CA1EIyk8TmE4tZWrOBXTXyVxbnIPjn5jbjvUP0Oga
         Gp7f4lyQmhGge6HDNLzW/7Zh5RelwRXXuubd30zATWT+CJTjHI3MjxFWwaxhSz6WQNX2
         GPtYc9lkYFez8gwpysKYbcGjB/vaveN/hs4kBfc/qJepMcDMPPjFHfnI8McNiczRxKWQ
         d3XIyHft8WvTDCDHT5jLJI2YsGTdPH7YQv49aG1Eu6UzLIn5Fd5hW8XdZOEJlpg41WMW
         OG6CnjMIjPIrp+mQGQru0h0R94llxppig+1bbeBfQpYQns519/Dah+9+oGL1uGelqoM5
         XzlA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=oaNF1e2Z;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 91.218.175.103 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=cUflGMxQZzL350vZWXN2PtZEqIB5ulkK6RRbqYOz+hA=;
        b=lSt+Exd6fbIaWU0SRBGPby+GZy+v+kG4fkKWEyRtj/XQ7lTkjXPl0udnoqaUWN3oQg
         RqmEQB0HHQ9Fvvnwn+Qq5sUxpq4c7Nt5fn4+YFGOndQbYT81tP4xoTrsp9XAJKURRTVI
         QL/hEHWUU0jylI8oWg9OpLXfh2FxjoGbEE19M08d1cSd3azxPc+pGLIf+XTb3dRtk2Ex
         D9Ag4UVSgZzNLmzqtRSa/aQ95Na+C13L9sllery5QjuCbRRBNvCteQtG2dWOZY9UDLD1
         YCTdZfdch9b2D92LP4ALZN+TYAxE6tc3BJDmyw8A2QXJhgfbHSXMQqSTpAIW2fhvs3Se
         lFLA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=cUflGMxQZzL350vZWXN2PtZEqIB5ulkK6RRbqYOz+hA=;
        b=2FL0rRHoseNWByK/L63xywBAS9FDdxgonkjP+sWL9mU47s5cW+ChoVPhalNsAhBVgf
         +QnI8PYIqjy0KGw0Utt6tdVVuiy0IwKGP50JUdlelfOM2M9w4r3yUE6gZGuS7qjFe9Mq
         YyNfZPLc3elKgA5XsIYQUxBRQMovHyY0qMl0yn+tkxemT0Nq7/wRcbfzv6i5Ajq3TVv6
         20W3xd0j7zNcHK/rlkh+rKhRLppcXVVRCN2Xvg9ia8MI2OCYO8JN2bLQ4exlC6AXahLk
         JEVfVS5tGvvj/+sTgYzYb7Uw4u2N1EkS7C4I/POCWwhRkmlplJuMeagNFgtCyst6YWXF
         obGA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AFqh2ko4b81kg8OBwyRtW07Iu2yjAiZ/V4IXHJPfo811SmK+2ADvPc/a
	pbSorE2psRUaxatMSlcDNs0=
X-Google-Smtp-Source: AMrXdXvSBO1nRjMjIBa+bxY7hIuM82PgDHX9DGPbjQuYvUDHWmqP5wOnWPhwKb7kBiR9CY0YVoqtNQ==
X-Received: by 2002:a7b:cbc7:0:b0:3da:fef7:218 with SMTP id n7-20020a7bcbc7000000b003dafef70218mr3366283wmi.94.1675111854057;
        Mon, 30 Jan 2023 12:50:54 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6000:42:b0:2bf:ccef:53a6 with SMTP id
 k2-20020a056000004200b002bfccef53a6ls3444235wrx.0.-pod-prod-gmail; Mon, 30
 Jan 2023 12:50:53 -0800 (PST)
X-Received: by 2002:adf:eb43:0:b0:2bd:d542:e010 with SMTP id u3-20020adfeb43000000b002bdd542e010mr41002870wrn.46.1675111853093;
        Mon, 30 Jan 2023 12:50:53 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1675111853; cv=none;
        d=google.com; s=arc-20160816;
        b=qZYVf+3nzWGMExrfOTGCLhtfSqOFPo+Gylcpd15NE5By3ltf+wInn3eUgf4M6qzc6+
         3EE4bLwQAxKN12HKnQLnCzBF3N4CdJFNd0UT99k9UgNYcg2cIJYFnMeACxWR7uLWeni9
         9HHaEVhO5Rkx/kg9MkuHE8g0PPLfmDsBCv3gYLVPD3DJj1PZk6/ekN+EdGuOnNNdTL5/
         sVhmX0F47HIB0OicghxAlBp7/Z6v0PuoMy+RH6/KWk4PDcZFRE7sXsJBMdWeTPnIMRK9
         fZ5VgyjsFjm91Dc5VfOVjgT6YZ1/R9z+HY4L6Q+AFHMpvmeVcr2aEGpYsrvp0lTN6RK3
         Cyiw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=4ThIc/E8It52Ai7wF9nGezLQDQ6i5NEX+ZonMvNBuyU=;
        b=UjOYtVvevk4Trt+wEUAoh87BUW5MK7p942rnTU70qCF35YD2oNA1vdrrOiB+0693tL
         /8Wfmct1mnAnk7a5zwVHp+6K8MmV1ArjQqJnMRj8uvHptAy6S/VpozXIjhXjxM31HnqX
         Lm8BmhUsbo7kgQBHaGGOXsclZ2P3udoIFzey2I0ZEYInIdorBOO23dT7RNZvWT7EheHX
         UUa40BsuSIdYUVsYZiNGUGlTIwsYYoe/c422mp3i+iJwc4nOaDS3A8ttTzTDNvK0g3/+
         x/lJfgzbybX47gCmwtRYhwYU9du6PyyRVta9c0og1p7JGog1gTneekjYYnfmEV55wMvr
         AFeQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=oaNF1e2Z;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 91.218.175.103 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-103.mta0.migadu.com (out-103.mta0.migadu.com. [91.218.175.103])
        by gmr-mx.google.com with ESMTPS id y9-20020a056000168900b00241d0141fbcsi671296wrd.8.2023.01.30.12.50.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 30 Jan 2023 12:50:53 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 91.218.175.103 as permitted sender) client-ip=91.218.175.103;
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
Subject: [PATCH 09/18] lib/stackdepot: rename hash table constants and variables
Date: Mon, 30 Jan 2023 21:49:33 +0100
Message-Id: <5456286e2c9f3cd5abf25ad2e7e60dc997c71f66.1675111415.git.andreyknvl@google.com>
In-Reply-To: <cover.1675111415.git.andreyknvl@google.com>
References: <cover.1675111415.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=oaNF1e2Z;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 91.218.175.103
 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
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

1. Rename STACK_HASH_SCALE to STACK_TABLE_SCALE to point out that it is
   related to scaling the hash table.

2. Rename STACK_HASH_ORDER_MIN/MAX to STACK_BUCKET_NUMBER_ORDER_MIN/MAX
   to point out that it is related to the number of hash table buckets.

3. Rename stack_hash_order to stack_bucket_number_order for the same
   reason as #2.

No functional changes.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 lib/stackdepot.c | 42 +++++++++++++++++++++---------------------
 1 file changed, 21 insertions(+), 21 deletions(-)

diff --git a/lib/stackdepot.c b/lib/stackdepot.c
index 89aee133303a..cddcf029e307 100644
--- a/lib/stackdepot.c
+++ b/lib/stackdepot.c
@@ -76,17 +76,17 @@ static bool __stack_depot_early_init_requested __initdata = IS_ENABLED(CONFIG_ST
 static bool __stack_depot_early_init_passed __initdata;
 
 /* Use one hash table bucket per 16 KB of memory. */
-#define STACK_HASH_SCALE	14
+#define STACK_TABLE_SCALE 14
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
+						STACK_TABLE_SCALE,
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
+		int scale = STACK_TABLE_SCALE;
 
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/5456286e2c9f3cd5abf25ad2e7e60dc997c71f66.1675111415.git.andreyknvl%40google.com.
