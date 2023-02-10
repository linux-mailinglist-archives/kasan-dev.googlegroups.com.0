Return-Path: <kasan-dev+bncBAABBHPITKPQMGQEOH5GRWQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x637.google.com (mail-ej1-x637.google.com [IPv6:2a00:1450:4864:20::637])
	by mail.lfdr.de (Postfix) with ESMTPS id 5CC06692903
	for <lists+kasan-dev@lfdr.de>; Fri, 10 Feb 2023 22:16:14 +0100 (CET)
Received: by mail-ej1-x637.google.com with SMTP id i7-20020a17090685c700b008ab19875638sf4243647ejy.3
        for <lists+kasan-dev@lfdr.de>; Fri, 10 Feb 2023 13:16:14 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1676063774; cv=pass;
        d=google.com; s=arc-20160816;
        b=hKxWdGolL+iuZqmHdW3XoI2AUiLCDJi+s98p+vmPD8O0b3fYu9iTuxyV8kByzbwBLx
         qGVl14hCsWErgy/K9VBiEM9c5SrZ1EOZNKrlZBKl45Ihz3qKC0TPvNpLOHwquzuI2rx4
         x64Q/0q7U05Q/0Ig9UXZueRBhpcFoQbXTDHDDVRi85dQBz6IZt/m1oTMhp95TewFM44Y
         gT9/u6Dc11pgWEkd4h3GqzWybrj3UhU1GzKUHQ1gvcMZ9/cVa3snh9+wXkWBdNWe0/XQ
         HorfS2zBzt+FCgb7ua//r18TAPHcCTi8UPsdK9+f5M3O4nzBt0ctAP2zmGe9u0AUTyHm
         P1mQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=lkCpVupCeCuKU8wcwzwWz1jpKatfJefP33ihLKynWlc=;
        b=tWv7/NudB5tH9TX3j2pKYy0b9IGL/Xkz8lqF3NTNuJFTRgGyqfBTgBpNorsxWSOKb3
         Mcaj7Xdso8kQ8NRQyO0UtXvebyr/t5/nsDLVhx9buKrwUdz0WVdqX4JUGo8nNSZNhcDW
         kZZo8TdrS6e64ACxM94lbYn+iKgLP78dUR0MSZEYN8RNz11maYfNugecUdymyqLUzhkv
         beb+qYkg9tqiWpSYNgDbBUgPpUpRm7Va/ymF1lrr7CQG3VqUvrdg6C6+8JmJxtxQRCrb
         ozjEvW1668w7BsAijb8OZsOE9/v7CNrhxZ9StwwmRogFVsCKPuIuzl4J+4GMmeZvrmLF
         IDsg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=NMUMtEuq;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 91.218.175.156 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=lkCpVupCeCuKU8wcwzwWz1jpKatfJefP33ihLKynWlc=;
        b=Y46osZGx32VflYj8ithq53YVbA5Cyq9hvloEKH9rLy11dTMm8y/S9tPUrbXhDjL/DM
         dZen43lMXpp4qhoS/HKmsUROelALchrfpawL/bzrB3aVKIUL2gVs7XS665w8q/e7ub7d
         3QttjmcLv4H5nC1bnhkKIVuG1v78kWSI8ghfhEJuMY3WydnjzqMaWBEH398rJNGTHigI
         pgOFIZZ1zHjuNnJZlXe0UzqAzq8YrYF/MFqRQ2UcLygIh4bFEkwlNIoos3TJSi0PYec4
         6GYqk66O9aN4nREB6hep86J8KXxF1ac2nsnEXqnRGCECPU+nJj8aUMUgAtjjN4X2fFb1
         hzVg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=lkCpVupCeCuKU8wcwzwWz1jpKatfJefP33ihLKynWlc=;
        b=01YoPx23HKlWVOH+/e7GueXBsZyuGyV4WiTxxDeQ38WMyXfpFUEXz97ujEBGZ/9CrQ
         oYOLlEoAF9MBwOy/nSG4mYbDZNeMaS5UGWzM5bq9V8PenZJ3aWmh2eerylvYiKkgeBXc
         4xMfIFqvW7SQ9LJfXC9wdMlLRnAA9YidPg3yE0vmpNLWxlBHA+NLnBSIV6bNRbyvlgeC
         WOhxpfugorDLNSSVMRM2xlRRi2kEtjFSgEp6qCvLW7XS5GkZSOTotmTZAG2eejWdEMQm
         4MA5i6WvVZ1Kdbo5/UYdvs7XNwCoOPgOWnoPygNJ3ag+odXz39YpxMoNyr7Eulf+aNEE
         0F5g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKVV4/5iocJfvp6so7uY27waeTNtvEUnDaQDYT3J+2VaTGhhuH89
	FozlaOtDkYZBjcZvLuzPOPM=
X-Google-Smtp-Source: AK7set8Sdmgld6eaXQQN2Kx1VD/VFKJm3YNliztRL3v3OMuefenDLuXDsBpEFwW2pgw8Ar3WjPm19Q==
X-Received: by 2002:a17:906:3d69:b0:877:e539:810b with SMTP id r9-20020a1709063d6900b00877e539810bmr1559586ejf.2.1676063773829;
        Fri, 10 Feb 2023 13:16:13 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:296a:b0:877:7adf:37b with SMTP id
 x10-20020a170906296a00b008777adf037bls4610573ejd.8.-pod-prod-gmail; Fri, 10
 Feb 2023 13:16:12 -0800 (PST)
X-Received: by 2002:a17:907:6d92:b0:882:c358:5bfd with SMTP id sb18-20020a1709076d9200b00882c3585bfdmr25947054ejc.59.1676063772839;
        Fri, 10 Feb 2023 13:16:12 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1676063772; cv=none;
        d=google.com; s=arc-20160816;
        b=pgMgbhS+xG4TFHJL4taUSglYBt7akWiqaaZ1Bq2WCmc31hNB1Ir9PjNnGWQJaBboR9
         KReaMlDw8DTTFYZgti9gRuHly0/l2/6h7C859TJwF9bLLP4jo/C/FaQaDWD5/1fzjxPC
         tnbhIjd4DRljA9vbl+NJrcMJNcl5KgsAEnE/Jq2+EanK/a4FZjPgX4d2JjPIMsBkkZg/
         p8yIuyX8i14Gn9yQmDfDpwsETj5ivnsnGckf9SXy/owNi80GKtVUZzuoTxTmmNNQ1urq
         O60QaIkj11uaEWwqHTbuZgQzsxbT87l/8qLjKlQKXb0R5L4LrN4HkbRWkp8NRsih/7Da
         CjEQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=b3Y1ZbtnHRjNaHONV9sUdyWjn+clMFk+2c4Skh5NOGM=;
        b=kDdP2kcD7a3m07053yo6/qnFs0sRleeeUg0VLqc70ZAJtgZhB0/07w9TiVvmTyzjSe
         xPtWLXPHYb76/BOkJYHYyZrqW85xpBJYsz60c6U5xqlXf3dOD8xmIbgoorcQm+/JRXdl
         YbEkns7LeHN7twYtuATX4z/HaF7U0A/nOlcMAvVuJ9+Rlk0SsowOz8a5Hn9cvdaS3XfT
         qnPVn2jwotgaWRnK5wLFPiF1AQr9AYWlTMRzkxeyh3Au+9LMlbMTV3oYkGTXTND0Lyvm
         jVFCTMeHNXxiSPYGjDFLq6IPaV96dWamRHkI/dEoxgJbk6Gok0pzTDY3x/++AMnFDBtZ
         mbUw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=NMUMtEuq;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 91.218.175.156 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-156.mta0.migadu.com (out-156.mta0.migadu.com. [91.218.175.156])
        by gmr-mx.google.com with ESMTPS id k16-20020a1709067ad000b008778ede684dsi274105ejo.1.2023.02.10.13.16.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 10 Feb 2023 13:16:12 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 91.218.175.156 as permitted sender) client-ip=91.218.175.156;
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
Subject: [PATCH v2 05/18] lib/stackdepot: annotate init and early init functions
Date: Fri, 10 Feb 2023 22:15:53 +0100
Message-Id: <d17fbfbd4d73f38686c5e3d4824a6d62047213a1.1676063693.git.andreyknvl@google.com>
In-Reply-To: <cover.1676063693.git.andreyknvl@google.com>
References: <cover.1676063693.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=NMUMtEuq;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 91.218.175.156
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

Add comments to stack_depot_early_init and stack_depot_init to explain
certain parts of their implementation.

Also add a pr_info message to stack_depot_early_init similar to the one
in stack_depot_init.

Also move the scale variable in stack_depot_init to the scope where it
is being used.

Reviewed-by: Alexander Potapenko <glider@google.com>
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 lib/stackdepot.c | 27 +++++++++++++++++++++------
 1 file changed, 21 insertions(+), 6 deletions(-)

diff --git a/lib/stackdepot.c b/lib/stackdepot.c
index 202e07c4f02d..9fab711e4826 100644
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
 
+/* Allocates a hash table via kvcalloc. Can be used after boot. */
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/d17fbfbd4d73f38686c5e3d4824a6d62047213a1.1676063693.git.andreyknvl%40google.com.
