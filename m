Return-Path: <kasan-dev+bncBAABBLG34CPAMGQEL25MHRY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x538.google.com (mail-ed1-x538.google.com [IPv6:2a00:1450:4864:20::538])
	by mail.lfdr.de (Postfix) with ESMTPS id 0F8A3681BC3
	for <lists+kasan-dev@lfdr.de>; Mon, 30 Jan 2023 21:50:54 +0100 (CET)
Received: by mail-ed1-x538.google.com with SMTP id f11-20020a056402354b00b0049e18f0076dsf8927119edd.15
        for <lists+kasan-dev@lfdr.de>; Mon, 30 Jan 2023 12:50:54 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1675111853; cv=pass;
        d=google.com; s=arc-20160816;
        b=rCkMaUlSzUtyuZD4BZdlRSqdvcsoRtoe7LrPrHJuVYG9LuRTKhqHYmUObIvD7wK1t8
         R/JAHy2LXZmPEExy9O8HRgtUbBPvgpDXp7UtKZQE+O8zRWtXzU7iOhPmpKT+DC0/zeRY
         buSfI9uoZbQSbSgwgOKvdbTtpzKAOnC/ohhfEhlXxd6pWbfVleCH8CAvpqS5CaD1BN/l
         HMwP5NHlQSt+jB5Y7+UJWIQcmrfKurX4ZWvGFLcHGy0m9hRudhhviV8LevKs5++xaEwW
         53caPHbriDK4k5kqCPwxeMMH/1Wdfv7Ou+f0DSxZ6j5w31DbnMPVazO8QaWXWdmnuQWn
         gQUQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=DSk2H3+okq//IhIjIDVQfOZ/Zm+71Ly7rTWDjXOEEHA=;
        b=qhYnu2ia/fuL4iGB/bcnJceVMAyGhuRJ4o+fE4tkuAxfs+B8y5lrp6ktKdB/Y2DUff
         xwFuR3ty83myPcDp38lFazA9Jki3cyHqf2OPv+9J887cJteHmg0YE4f1jyfYILw7gnTi
         z0GsQZxVqGQA4bU88mnKwHOpSiPP2YcPgam3je45LgnchSDX+WqVx8rufTfhPnkpVzpI
         IUutUXjZVt22lhA9pys5KubBasiKOgKg5vpvreoFz2cnx+KGLQzL9qhhcSjy7go6Ndqh
         ehLHvx0iOD9RQscBhUw18ynXnSwLP08+fOS2tslImcQiKl/81A8FSZcFLtSgebyWZOa+
         kP0Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b="qTAqH/h3";
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:1004:224b::eb as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=DSk2H3+okq//IhIjIDVQfOZ/Zm+71Ly7rTWDjXOEEHA=;
        b=QDORuazUjet20Ybs11T5A/4h0pKRZtS0ig/5EdxFPOejZqISvadVg4M+U8cf4I7I8R
         uhY4NS7Pma7ncL4/zwoMdMSfQJs3Ed+qIdMTM2+1+utpRAYcePv6ZWt+NM+t+rGLTQF4
         BPjLLPB2MYMbsQjZ5z7VufCPJe4lAjamAdR8VXF1VoGkHJBjKfo4IHvp8euJgv6ehPJV
         wWAvk0JKjLKK3/jimPy7LCFpqVKZy4/i8dWfAK42qQpWBZN8rSJ+Yk1GbXE/gSr3wj+2
         OXe3gSoSJ+kH6czHyVRq2DMgfK2nXQreNryBoVln1TlZoik/l1ucgUfOr6rh3l3Fc5i7
         vsIg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=DSk2H3+okq//IhIjIDVQfOZ/Zm+71Ly7rTWDjXOEEHA=;
        b=BDZmbDKKPS10QR0fr1DORRldnKGZ7GmRzSEtm4VUQsot4kQXkwH3ayKzm+wAUQgMXY
         rKmjMusPYpqZI805WiIrDRpyi5z5EoDLwc/slA1cavVMzvailpTSYJQveue96o07tU6Z
         tqPVMe4wpp/IgtzC3+AlOq0OUSSurmAJo/wT5Ohoe8DF/6PuR/SmXFIro8rKyRE8BSZc
         G6rjEzwGaw8U7LUqr8CgNNz1UlwzIeiVyycDygAL9WSPO9lkx3Rzxc1CorOXdSqU8TZd
         cCfXA3eSFSt7eZXg6TzNSl/+ckAhrWV57QKSKwnoL6+CyxbBf7fj9LyTPJZalu1OUkq+
         YJ2A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AFqh2krCZYvzzsMpXIhAjF96tLNaMRE4yGlXLiUbHRR7UtPj2dl1Zu+1
	ehOmyCKzeEE25KPMIA4Nk5c=
X-Google-Smtp-Source: AMrXdXsFvCv3AXrbVX1ctALJTgu3mwRCuQJVLZBvZDqSpKPKUWMUqOV2q++aW0/Oz4K7A7TU3Ck4dw==
X-Received: by 2002:a17:906:2447:b0:7c0:f45e:22ff with SMTP id a7-20020a170906244700b007c0f45e22ffmr11223614ejb.104.1675111852809;
        Mon, 30 Jan 2023 12:50:52 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:b42:b0:49e:5b8c:71c4 with SMTP id
 bx2-20020a0564020b4200b0049e5b8c71c4ls13207156edb.3.-pod-prod-gmail; Mon, 30
 Jan 2023 12:50:51 -0800 (PST)
X-Received: by 2002:a05:6402:3596:b0:4a1:f44f:4292 with SMTP id y22-20020a056402359600b004a1f44f4292mr1050118edc.16.1675111851873;
        Mon, 30 Jan 2023 12:50:51 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1675111851; cv=none;
        d=google.com; s=arc-20160816;
        b=EIUQ0mXe6Eg/CMij6SMm1kFgLkQYAXDmUigzwIch7NGAWDPXnAyTucx5805zsIMtYq
         My9vgi8W++NqCZjNbc+XGbqPlTtgcvu+RvDnEwOp/DJA6XSgxFnwjPA5wFduo81oOffe
         cdTkClwHj2Oqn+l0Vxb4YinvGqAONEZuHeybqXCLvyeV+2bZw3bG55/ygMi3DS7jqGyI
         AEPHzIlBrlm2l98wnYtFsaUR/wTqpJwXJdLzuSrnXSDO/s6xugMsqlXIMWXEYM6UWUjj
         iLFKNjWKGKwrCMn53u6s6trndCqriuIM1RAUH57EdEqQnUNblGwWj+aMhuAns7KTXY21
         lCMg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=TXUvy5WDZhr7BlKZ84VBiDQ9FKi0bXR5FVmrmN5uemo=;
        b=dn0KIt3jyYyfPi/956vX+41pIPZEyIcxo0AJyIbFiGjCQ9sq9JJ2qpCD5bpjMAWvlq
         bRYLtstcc3YlUju8rJXblv18DQEb00liDaauRCpRZ0UyGm2LExH4UAywe86Lx9Ra4hNy
         CQxZpNZ4xRUDYzZMzPZuQMOL016LPxzJKwW8AYCmihAkVJ5HDEmGENA4lVsSbrFIe8YG
         xwJdpMJWFSdCwu39RBDY6Bk0haX7136SW82piyzIDacVp6akR5Z/XpYt9BAJ0/pdYQLI
         g+mzK3YHHlLwLx28/6M52ZZS2JvWG9hnsPUEYNmdBySmavMCVesNUh0sP11P5sqw2TqG
         dwAQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b="qTAqH/h3";
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:1004:224b::eb as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-235.mta0.migadu.com (out-235.mta0.migadu.com. [2001:41d0:1004:224b::eb])
        by gmr-mx.google.com with ESMTPS id es12-20020a056402380c00b0047014e8771fsi612775edb.3.2023.01.30.12.50.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 30 Jan 2023 12:50:51 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:1004:224b::eb as permitted sender) client-ip=2001:41d0:1004:224b::eb;
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
Subject: [PATCH 06/18] lib/stackdepot: annotate init and early init functions
Date: Mon, 30 Jan 2023 21:49:30 +0100
Message-Id: <be09b64fb196ffe0c19ce7afc4130efba5425df9.1675111415.git.andreyknvl@google.com>
In-Reply-To: <cover.1675111415.git.andreyknvl@google.com>
References: <cover.1675111415.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b="qTAqH/h3";       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:1004:224b::eb as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
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

Add comments to stack_depot_early_init and stack_depot_init to explain
certain parts of their implementation.

Also add a pr_info message to stack_depot_early_init similar to the one
in stack_depot_init.

Also move the scale variable in stack_depot_init to the scope where it
is being used.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 lib/stackdepot.c | 27 +++++++++++++++++++++------
 1 file changed, 21 insertions(+), 6 deletions(-)

diff --git a/lib/stackdepot.c b/lib/stackdepot.c
index 6e8aef12cf89..b06f6a5caa83 100644
--- a/lib/stackdepot.c
+++ b/lib/stackdepot.c
@@ -115,24 +115,34 @@ void __init stack_depot_request_early_init(void)
 	__stack_depot_early_init_requested = true;
 }
 
+/* Allocates a hash table via memblock. Can only be used during early boot. */
 int __init stack_depot_early_init(void)
 {
 	unsigned long entries = 0;
 
-	/* This is supposed to be called only once, from mm_init() */
+	/* This function must be called only once, from mm_init(). */
 	if (WARN_ON(__stack_depot_early_init_passed))
 		return 0;
-
 	__stack_depot_early_init_passed = true;
 
+	/*
+	 * If KASAN is enabled, use the maximum order: KASAN is frequently used
+	 * in fuzzing scenarios, which leads to a large number of different
+	 * stack traces being stored in stack depot.
+	 */
 	if (kasan_enabled() && !stack_hash_order)
 		stack_hash_order = STACK_HASH_ORDER_MAX;
 
 	if (!__stack_depot_early_init_requested || stack_depot_disabled)
 		return 0;
 
+	/*
+	 * If stack_hash_order is not set, leave entries as 0 to rely on the
+	 * automatic calculations performed by alloc_large_system_hash.
+	 */
 	if (stack_hash_order)
-		entries = 1UL <<  stack_hash_order;
+		entries = 1UL << stack_hash_order;
+	pr_info("allocating hash table via alloc_large_system_hash\n");
 	stack_table = alloc_large_system_hash("stackdepot",
 						sizeof(struct stack_record *),
 						entries,
@@ -142,7 +152,6 @@ int __init stack_depot_early_init(void)
 						&stack_hash_mask,
 						1UL << STACK_HASH_ORDER_MIN,
 						1UL << STACK_HASH_ORDER_MAX);
-
 	if (!stack_table) {
 		pr_err("hash table allocation failed, disabling\n");
 		stack_depot_disabled = true;
@@ -152,6 +161,7 @@ int __init stack_depot_early_init(void)
 	return 0;
 }
 
+/* Allocates a hash table via kvmalloc. Can be used after boot. */
 int stack_depot_init(void)
 {
 	static DEFINE_MUTEX(stack_depot_init_mutex);
@@ -160,11 +170,16 @@ int stack_depot_init(void)
 	mutex_lock(&stack_depot_init_mutex);
 	if (!stack_depot_disabled && !stack_table) {
 		unsigned long entries;
-		int scale = STACK_HASH_SCALE;
 
+		/*
+		 * Similarly to stack_depot_early_init, use stack_hash_order
+		 * if assigned, and rely on automatic scaling otherwise.
+		 */
 		if (stack_hash_order) {
 			entries = 1UL << stack_hash_order;
 		} else {
+			int scale = STACK_HASH_SCALE;
+
 			entries = nr_free_buffer_pages();
 			entries = roundup_pow_of_two(entries);
 
@@ -179,7 +194,7 @@ int stack_depot_init(void)
 		if (entries > 1UL << STACK_HASH_ORDER_MAX)
 			entries = 1UL << STACK_HASH_ORDER_MAX;
 
-		pr_info("allocating hash table of %lu entries with kvcalloc\n",
+		pr_info("allocating hash table of %lu entries via kvcalloc\n",
 				entries);
 		stack_table = kvcalloc(entries, sizeof(struct stack_record *), GFP_KERNEL);
 		if (!stack_table) {
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/be09b64fb196ffe0c19ce7afc4130efba5425df9.1675111415.git.andreyknvl%40google.com.
