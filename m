Return-Path: <kasan-dev+bncBC7OBJGL2MHBBQEKUSWQMGQEBHKDY4Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x138.google.com (mail-lf1-x138.google.com [IPv6:2a00:1450:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id 721EF8317E9
	for <lists+kasan-dev@lfdr.de>; Thu, 18 Jan 2024 12:02:26 +0100 (CET)
Received: by mail-lf1-x138.google.com with SMTP id 2adb3069b0e04-50ea338a0f9sf6250e87.0
        for <lists+kasan-dev@lfdr.de>; Thu, 18 Jan 2024 03:02:26 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1705575746; cv=pass;
        d=google.com; s=arc-20160816;
        b=HPa8ps0qxyu5PuqxahxS7JGl/4rQxoq5crbgufj6q8zlQJMZGk19bOLN65SSageQC3
         CO6mJTywdoRja3pN3oEWDQ8YUwDLj35vsVCtLH4EYm+Rwq1AO1TIx8QR9k+g/tWSl7F8
         ZKr1yJVVPiQzDKGbvhm4vuz0KC4KNyBH7Aq0EIQNMVQn/Bm5x0X9zYElIbBxGKXFdyZD
         Rv3UQ4w96qZaZ5kndd0Y0AZWV/jV0bypFcdBLzrM1f6v1U9BQBumaa1HKdHiVnKB2W1e
         jKLn16NzN8LYXpCyR3Va0Ibt5HMpMymZkqMz8ct+8Uj/crD7jneESAggisgIv5kwGBiP
         FhLA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:mime-version:date:dkim-signature;
        bh=xu/dPmyxQMJemriT7P+QTcAbZfRPjsy+iDqNLAnU8Mc=;
        fh=Q/d4OiL4ksp/XPthBLW72yTulI/JdIQ/Oi/Sg+RVXvU=;
        b=ny7p9kcKdJQwiu7EoFU6h7MGxEzmk6jSVX8VLUbUESMbp7RVtrIEHFFRJrPVenmS15
         lqlIilgzrgwSU8ZjtNo3/DZae6hfMmMSAsJRkzqGfMzldQIeR3J5N4mgFdrhpd7yzIdD
         CvthrSmozlJX7XLbIy3/rJS/tI77FLN4AD0xKKzx+jP2hwNF6Viz4+ytEIp4TAcBdiJr
         X0Qb6XLCiAarjJolhEyHfIusKgyXLFicEmrUQEIZ6+6A1LFUjSJaXJ32k+hWctwn74mx
         eJYjV31Zws3H7oE8+k0IXq2KU1xjMVZ4jkBMqzq/adaSIQvC3pJDPtzfLadrIwG059Yi
         aR/A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=aRIcyTBM;
       spf=pass (google.com: domain of 3pqwpzqukcsaahranckkcha.8kig6o6j-9arckkchacnkqlo.8ki@flex--elver.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3PQWpZQUKCSAAHRANCKKCHA.8KIG6O6J-9ARCKKCHACNKQLO.8KI@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1705575746; x=1706180546; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:mime-version:date:from:to:cc:subject:date
         :message-id:reply-to;
        bh=xu/dPmyxQMJemriT7P+QTcAbZfRPjsy+iDqNLAnU8Mc=;
        b=svAKpzWO67lKLkmJ+7zz99YOaND2ioqpajE7Jg2GZq2WndkGreZs0h2VvT+SdkMZvB
         8PIXwvjs5SbCifdZfXiVoQL37R3m9RjvLcWrUV2mc3vQ0ypV1OmU8MDZ3LJ49GamiM8i
         9NZt00IvrXPoM2NKCnLZ6HzINFHfAGwP7yCJshypvyoi0bXVGitIksNmejDKsRKScwTd
         KlcRvUBYlmzanSWbBIsIJmw19qhp3HK1Zq8jtfnDECuS92Li2/VKuVeOikO3qJ2KALmh
         Pp80mWMmyVM1w3T1LMRMfO78c8D6Q97yTWmCIlxyjG7sDasYh/nsnZqqJ28oswF59Ooe
         6khg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1705575746; x=1706180546;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:mime-version:date:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=xu/dPmyxQMJemriT7P+QTcAbZfRPjsy+iDqNLAnU8Mc=;
        b=b1SDlTPyM5IWPVygtV69utGnP+dieu0Pz9EDjyWYX5EYE44h826nZa8LF824f9rvwO
         OUzWcgRIB8Rwm9wb7zgzeWd+9mCZ15iI5MYx4iWJUlgJCbdSlP53ePckWVqTUVV8iq6m
         3y8S5qfo5xZlE6ylLC8xv8pxIk7CCMgQv60I7WG8Nh9QW39NQjyzlkTXX7WC1gWfDh5k
         +Z9OFBdBI6G04uq6X+es3YsVMr+OoUDBZT9k83q336KuwwZWL8jRmqYjJTzefSSHS/7o
         g8TsI37Y9P4tZ6axNXAQyMtfIzGSLS4nlxJe5qopgZY0wZsCbWYtMGHKGQ8kXAqyoH9C
         6Hag==
X-Gm-Message-State: AOJu0YwNWvaRwWL7xR8cdGjjSJJNzRj9/zbv8EPPxTolokF8IFy6I75F
	eNfZVz9/+caqMTLyiXwluv4IGbFDou7o5CmLNyXu+Ex890FhHahu
X-Google-Smtp-Source: AGHT+IHnjMVwMltFAov7sQa1alawyCqRJNjBTkJ2fzNSNBmrWlATE1oyFoH1z0fIMr3eAul4FIB10g==
X-Received: by 2002:ac2:5b0d:0:b0:50e:ca18:917 with SMTP id v13-20020ac25b0d000000b0050eca180917mr27851lfn.7.1705575745197;
        Thu, 18 Jan 2024 03:02:25 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:5f68:0:b0:50f:983:5054 with SMTP id c8-20020ac25f68000000b0050f09835054ls878210lfc.1.-pod-prod-06-eu;
 Thu, 18 Jan 2024 03:02:22 -0800 (PST)
X-Received: by 2002:a2e:a98b:0:b0:2cd:129b:2c07 with SMTP id x11-20020a2ea98b000000b002cd129b2c07mr586692ljq.37.1705575742321;
        Thu, 18 Jan 2024 03:02:22 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1705575742; cv=none;
        d=google.com; s=arc-20160816;
        b=Nusjn6zEjS8AITLo8GrLRPoLDScAtGyuP1DH8UnQtXfqwkTEWwAg3j6I+GRHGy7haa
         6xDZsIk60iKCHoGVURf6K8ZGX9Ns3xKNqjELIXwCSC1qMflC+2dvfoqIj4uMxach0DxG
         0KQ1ZJ+p8dyS6vcimrVDkMRdhH5N72lGV4x9UNQj+yXIcoXAYTYZSSItryOtnveWnMNv
         6QzUPTvNIPzTn2gqdoVWKDJfJxgdw9n309dUi33fAdcRXQa7bwWPtS6QMsWBoS5WZAfO
         chFWQevNBhjD7TBBZG78kE3OuQN90Map+IDmDt3sd7zXcp0HPzUQ5SHdaNUDX6oZ3Qs1
         FxUA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:mime-version:date:dkim-signature;
        bh=nt/piPitvuHRj/PfEKvId5IXLv15chj5uEnJGFs8RjM=;
        fh=Q/d4OiL4ksp/XPthBLW72yTulI/JdIQ/Oi/Sg+RVXvU=;
        b=Lfbd5Y0bbK3vb74tn/gWOmm6FqpBIAhO5hLveH6Kvjk+7N+A8OL6Jkat9lRe0yXJPk
         Kf+6KKoeOZo/ACQZkIJH18WHEGFH6/1Flp58rmnntDYDwh4hrJkbLZgyIDtH5GTqKccz
         wrc8VGGdNQvuFEZCijdUNT0U/GO0lAhbMs6aXcTCovfPWViQ24JlR2BJGdyNxCTBqjPp
         S60Z8azAt7yOHUB0hxdOSiW6xLaV5YPPPSBf8UEtqrSalSnOZ4RJpSNbWu5poxt2tTYz
         a1NOf6OvNLLpThbuJCk+QA7FRJ2EdIAlJoso72u3migmGo1B9yiX5/mRCDlec3mIJTFT
         prTw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=aRIcyTBM;
       spf=pass (google.com: domain of 3pqwpzqukcsaahranckkcha.8kig6o6j-9arckkchacnkqlo.8ki@flex--elver.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3PQWpZQUKCSAAHRANCKKCHA.8KIG6O6J-9ARCKKCHACNKQLO.8KI@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ed1-x54a.google.com (mail-ed1-x54a.google.com. [2a00:1450:4864:20::54a])
        by gmr-mx.google.com with ESMTPS id b15-20020a50cccf000000b0055535b942ebsi853228edj.0.2024.01.18.03.02.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 18 Jan 2024 03:02:22 -0800 (PST)
Received-SPF: pass (google.com: domain of 3pqwpzqukcsaahranckkcha.8kig6o6j-9arckkchacnkqlo.8ki@flex--elver.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) client-ip=2a00:1450:4864:20::54a;
Received: by mail-ed1-x54a.google.com with SMTP id 4fb4d7f45d1cf-558fe4c0c46so3134793a12.1
        for <kasan-dev@googlegroups.com>; Thu, 18 Jan 2024 03:02:22 -0800 (PST)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:9c:201:9d7e:25fb:9605:2bef])
 (user=elver job=sendgmr) by 2002:a05:6402:3712:b0:559:f7b9:319c with SMTP id
 ek18-20020a056402371200b00559f7b9319cmr5073edb.5.1705575741753; Thu, 18 Jan
 2024 03:02:21 -0800 (PST)
Date: Thu, 18 Jan 2024 12:01:29 +0100
Mime-Version: 1.0
X-Mailer: git-send-email 2.43.0.381.gb435a96ce8-goog
Message-ID: <20240118110216.2539519-1-elver@google.com>
Subject: [PATCH 1/2] stackdepot: add stats counters exported via debugfs
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, Andrew Morton <akpm@linux-foundation.org>
Cc: Andrey Konovalov <andreyknvl@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vlastimil Babka <vbabka@suse.cz>, linux-kernel@vger.kernel.org, 
	linux-mm@kvack.org, kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=aRIcyTBM;       spf=pass
 (google.com: domain of 3pqwpzqukcsaahranckkcha.8kig6o6j-9arckkchacnkqlo.8ki@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3PQWpZQUKCSAAHRANCKKCHA.8KIG6O6J-9ARCKKCHACNKQLO.8KI@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

Add a few basic stats counters for stack depot that can be used to derive if
stack depot is working as intended. This is a snapshot of the new stats after
booting a system with a KASAN-enabled kernel:

 $ cat /sys/kernel/debug/stackdepot/stats
 pools: 838
 allocations: 29861
 frees: 6561
 in_use: 23300
 freelist_size: 1840

Generally, "pools" should be well below the max; once the system is booted,
"in_use" should remain relatively steady.

Signed-off-by: Marco Elver <elver@google.com>
Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>
---
 lib/stackdepot.c | 53 ++++++++++++++++++++++++++++++++++++++++++++++++
 1 file changed, 53 insertions(+)

diff --git a/lib/stackdepot.c b/lib/stackdepot.c
index a0be5d05c7f0..80a8ca24ccc8 100644
--- a/lib/stackdepot.c
+++ b/lib/stackdepot.c
@@ -14,6 +14,7 @@
 
 #define pr_fmt(fmt) "stackdepot: " fmt
 
+#include <linux/debugfs.h>
 #include <linux/gfp.h>
 #include <linux/jhash.h>
 #include <linux/kernel.h>
@@ -115,6 +116,23 @@ static bool new_pool_required = true;
 /* Lock that protects the variables above. */
 static DEFINE_RWLOCK(pool_rwlock);
 
+/* Statistics counters for debugfs. */
+enum depot_counter_id {
+	DEPOT_COUNTER_ALLOCS,
+	DEPOT_COUNTER_FREES,
+	DEPOT_COUNTER_INUSE,
+	DEPOT_COUNTER_FREELIST_SIZE,
+	DEPOT_COUNTER_COUNT,
+};
+static long counters[DEPOT_COUNTER_COUNT];
+static const char *const counter_names[] = {
+	[DEPOT_COUNTER_ALLOCS]		= "allocations",
+	[DEPOT_COUNTER_FREES]		= "frees",
+	[DEPOT_COUNTER_INUSE]		= "in_use",
+	[DEPOT_COUNTER_FREELIST_SIZE]	= "freelist_size",
+};
+static_assert(ARRAY_SIZE(counter_names) == DEPOT_COUNTER_COUNT);
+
 static int __init disable_stack_depot(char *str)
 {
 	return kstrtobool(str, &stack_depot_disabled);
@@ -277,6 +295,7 @@ static void depot_init_pool(void *pool)
 		stack->handle.extra = 0;
 
 		list_add(&stack->list, &free_stacks);
+		counters[DEPOT_COUNTER_FREELIST_SIZE]++;
 	}
 
 	/* Save reference to the pool to be used by depot_fetch_stack(). */
@@ -376,6 +395,7 @@ depot_alloc_stack(unsigned long *entries, int size, u32 hash, void **prealloc)
 	/* Get and unlink the first entry from the freelist. */
 	stack = list_first_entry(&free_stacks, struct stack_record, list);
 	list_del(&stack->list);
+	counters[DEPOT_COUNTER_FREELIST_SIZE]--;
 
 	/* Limit number of saved frames to CONFIG_STACKDEPOT_MAX_FRAMES. */
 	if (size > CONFIG_STACKDEPOT_MAX_FRAMES)
@@ -394,6 +414,8 @@ depot_alloc_stack(unsigned long *entries, int size, u32 hash, void **prealloc)
 	 */
 	kmsan_unpoison_memory(stack, DEPOT_STACK_RECORD_SIZE);
 
+	counters[DEPOT_COUNTER_ALLOCS]++;
+	counters[DEPOT_COUNTER_INUSE]++;
 	return stack;
 }
 
@@ -426,6 +448,10 @@ static void depot_free_stack(struct stack_record *stack)
 	lockdep_assert_held_write(&pool_rwlock);
 
 	list_add(&stack->list, &free_stacks);
+
+	counters[DEPOT_COUNTER_FREELIST_SIZE]++;
+	counters[DEPOT_COUNTER_FREES]++;
+	counters[DEPOT_COUNTER_INUSE]--;
 }
 
 /* Calculates the hash for a stack. */
@@ -690,3 +716,30 @@ unsigned int stack_depot_get_extra_bits(depot_stack_handle_t handle)
 	return parts.extra;
 }
 EXPORT_SYMBOL(stack_depot_get_extra_bits);
+
+static int stats_show(struct seq_file *seq, void *v)
+{
+	/*
+	 * data race ok: These are just statistics counters, and approximate
+	 * statistics are ok for debugging.
+	 */
+	seq_printf(seq, "pools: %d\n", data_race(pools_num));
+	for (int i = 0; i < DEPOT_COUNTER_COUNT; i++)
+		seq_printf(seq, "%s: %ld\n", counter_names[i], data_race(counters[i]));
+
+	return 0;
+}
+DEFINE_SHOW_ATTRIBUTE(stats);
+
+static int depot_debugfs_init(void)
+{
+	struct dentry *dir;
+
+	if (stack_depot_disabled)
+		return 0;
+
+	dir = debugfs_create_dir("stackdepot", NULL);
+	debugfs_create_file("stats", 0444, dir, NULL, &stats_fops);
+	return 0;
+}
+late_initcall(depot_debugfs_init);
-- 
2.43.0.381.gb435a96ce8-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240118110216.2539519-1-elver%40google.com.
