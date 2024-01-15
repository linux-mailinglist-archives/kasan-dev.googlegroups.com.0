Return-Path: <kasan-dev+bncBC7OBJGL2MHBBB7VSOWQMGQEAOZYXWY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x237.google.com (mail-lj1-x237.google.com [IPv6:2a00:1450:4864:20::237])
	by mail.lfdr.de (Postfix) with ESMTPS id E916982D5E2
	for <lists+kasan-dev@lfdr.de>; Mon, 15 Jan 2024 10:27:36 +0100 (CET)
Received: by mail-lj1-x237.google.com with SMTP id 38308e7fff4ca-2ccb53bc5cesf59947931fa.3
        for <lists+kasan-dev@lfdr.de>; Mon, 15 Jan 2024 01:27:36 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1705310856; cv=pass;
        d=google.com; s=arc-20160816;
        b=DlOwNtuumEou5PlDzRr/wUV+HdEtJyWyQQ204yu0u/huav41pN6Lhhs37xCK6znHUj
         MXWLsxiGcyoGnDG0Q6X0HhnHVVthOKZv2xpN32DEK6KsqmrZxnolthEnuJKBkBuLo4r3
         GKitsvL79eMD+GEPhdU+INM2RQM5269Ux8cQaoAp4WYAdGPMZceZjcjT+03s03HuUJ62
         6mdBB+/NS4omIvvSIb4xTrR1xy3OGcL+ukx/TFHPU1AzdJr5+iTxJP1T+exBKJj5EuZi
         PCF4ZmLoOjXfNMzcVYt9QS4uHlm4E6J+iiCrw43L4vDZWLMRmXn6g4dTf5BmzQTELTa0
         13hg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:mime-version:date:dkim-signature;
        bh=r/4fZuTwpD+SJgEC8N/FIy90I7oHCjBjyc+E8DllQIg=;
        fh=Q/d4OiL4ksp/XPthBLW72yTulI/JdIQ/Oi/Sg+RVXvU=;
        b=1A/avHlzXpMkyZgUnYxcLGxzT+PuBJ4Ou8I4KvACw/dgQ9TDuapnHPPDVmA/trNZYs
         FPfNWExZxOF6ZVX1bMclUdhkhWdSPpvBsRdD4TuqMLTwHDe+c0TGoEyXCcujK1qJtjbP
         cz3Hk8bss9hITmrwnh4ZDmEdWGRUQwjU6pmFWszuhq+aaG4auHAFFJSn6zwuK5Ri5mR8
         FIz9uejW8zk6lxbfNE6dHVzitLnHtkPL3Jc2qfhvihckGetAR+/kyVfmt7MR1LmPElRM
         4UKxrT6uYsxhFzhkxomoqpoVrkfPdzjSJtY5uttYswLEvl9U698ldxG2qDAfTmmTHyBk
         Fc+w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=P4wKmmVd;
       spf=pass (google.com: domain of 3hpqkzqukcuehoyhujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--elver.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=3hPqkZQUKCUEhoyhujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1705310856; x=1705915656; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:mime-version:date:from:to:cc:subject:date
         :message-id:reply-to;
        bh=r/4fZuTwpD+SJgEC8N/FIy90I7oHCjBjyc+E8DllQIg=;
        b=t7RCEhTFUAVlteqdyToK+MB7CD1C7/NrkoyMZR212t4n80T+60UeZWkXn2IUXjD8eQ
         g7wvj0IC1uDcjVH5zx/wZdVDgLneKToJ95i2G5zLk1nzqua774QxHBojXCEpa/JgGsms
         owlYxcHYX4P7J+I6XmXZn2R10sNR6MVEmckUJPerS+5n3FxiQzwzcOmOrYfBndxAfj8+
         o5lAAP8rebIyiADUg1Ahs/lPH42ur+nlA/V3/Zxu/I2NbfvU2nHgZCmJZGQm6dCljwaO
         8wufjg1txEIxm0STASzpfVs/kHXVTMpga/Ct8VqdWOyANvydb9eQZI83wFnX50ItpN+Z
         hkaQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1705310856; x=1705915656;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:mime-version:date:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=r/4fZuTwpD+SJgEC8N/FIy90I7oHCjBjyc+E8DllQIg=;
        b=l8OOB1uXIDb+XnN6QtZqyz8KyBkUtIZnqwuwDS525b2BNdUKtsjJKMjjCmQc3cwmee
         l2JDpnPmHj1WsmvK4Q1POFO7woGinSxav0k1RcrzF/UVz5cC0yPwdjk8nm3ofToV6pDo
         +YTQd0IRJCSJ9e0nPnz7c2aFWhD14e0AVoMjERH5kZK9FzkBYoNiPfp0SqPVRiyJkI/u
         t3wiX2roRaBgm9hR5hHG9ryiw31hd0JlUCW4UVmHZdkyyIWcbLKXyW8v7ZbD6G6poIxb
         35GaWikpngJg8uQWs6vysaDDexT8kaEuR/Ni612JTApDxuPMMw1yykqtj4DxeG/snQZx
         i2Ug==
X-Gm-Message-State: AOJu0YwSrw52pYcdPqD6XK0foIWjgXJR9/gH7T+GCDv31Vh4dNM/wx8R
	Ez6jCQV6NsDn8AUouRcpqRc=
X-Google-Smtp-Source: AGHT+IExwBVLP05GWMxqh/edc66aSt24xVlM/w87w5Jzlp3bAJwOVmH9SggVGrR+WlIp/dJbMVHS2Q==
X-Received: by 2002:a2e:9647:0:b0:2cd:80c8:c06b with SMTP id z7-20020a2e9647000000b002cd80c8c06bmr2047827ljh.101.1705310855577;
        Mon, 15 Jan 2024 01:27:35 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:1a13:b0:2cd:5356:101b with SMTP id
 by19-20020a05651c1a1300b002cd5356101bls981133ljb.1.-pod-prod-01-eu; Mon, 15
 Jan 2024 01:27:33 -0800 (PST)
X-Received: by 2002:ac2:4421:0:b0:50e:6d96:4b27 with SMTP id w1-20020ac24421000000b0050e6d964b27mr1733218lfl.60.1705310853250;
        Mon, 15 Jan 2024 01:27:33 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1705310853; cv=none;
        d=google.com; s=arc-20160816;
        b=YwNRNetvhLuclVq3BHjNe3rvn5yqcD4Cu4h2d9jDyVIC24sjRIvWnxV8UOCGam++MY
         8MhOVBeJesd02uA0syApcsCi0GsTgR37zLkK0dmicTO8JCG04Mkh17CVsWfJucr5Q/PN
         2RkGFlRts1CkTkgJY93IUW4jGeQUlOQ0rbexv4Q9RL+NGNFgmNP97qEYSop7cDH/pRM8
         wgim+h9vPqlWJZz0W7XJPLZKskUrvumLsj8vMnaGeMcf8RtLXL7jVr+W5RR+d96EpSw2
         U5U3+sGAMkxqrbwHircJnuO6MOlqbpsHCxynmu/IVGPHUpApaEeroXt0wWT1C7k1BFnY
         UKxw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:mime-version:date:dkim-signature;
        bh=bmhCfln9ac1sszz1cn9mo233ZA1ZqqWQM/ks4o+Avbk=;
        fh=Q/d4OiL4ksp/XPthBLW72yTulI/JdIQ/Oi/Sg+RVXvU=;
        b=XRZk1HTefCBdgaPQDcNQCeLgGLU0B8JX4UFPqU2ZWo30GOxoY7i7t2VVYMvRpngTAt
         3/I8Mu2347ojpG0ji9ND6jc1lVYl+BptJVtTSlIqJjKXODBH0DDjCBD8YwV2i4ON1UDB
         cUyEJx/AZlGK7FTmo+dJ1h24H/MNw973h/ZlZ97cy++/Nz5aIbH3xd+KIVPXX5FZ4cWo
         BFcsyVSsHIllaFvTdiRdNKbBFGFPcSO8SUPPkQMXyunoFmYxAOgepePaGX+dcaAm/ZDA
         WodX2QzdUDBHHD4b2tpdXuLNEkbHt02k5Iqx2k8LeGYeGH4tlltRsxYm/OiR6LpGy23Q
         1wiQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=P4wKmmVd;
       spf=pass (google.com: domain of 3hpqkzqukcuehoyhujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--elver.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=3hPqkZQUKCUEhoyhujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ej1-x64a.google.com (mail-ej1-x64a.google.com. [2a00:1450:4864:20::64a])
        by gmr-mx.google.com with ESMTPS id fb9-20020a056512124900b0050e7bef1793si266423lfb.8.2024.01.15.01.27.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 15 Jan 2024 01:27:33 -0800 (PST)
Received-SPF: pass (google.com: domain of 3hpqkzqukcuehoyhujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--elver.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) client-ip=2a00:1450:4864:20::64a;
Received: by mail-ej1-x64a.google.com with SMTP id a640c23a62f3a-a2bffe437b5so257837866b.1
        for <kasan-dev@googlegroups.com>; Mon, 15 Jan 2024 01:27:33 -0800 (PST)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:9c:201:38c7:85d7:36f7:e198])
 (user=elver job=sendgmr) by 2002:a17:906:54a:b0:a2c:7164:ff8d with SMTP id
 k10-20020a170906054a00b00a2c7164ff8dmr38908eja.3.1705310852357; Mon, 15 Jan
 2024 01:27:32 -0800 (PST)
Date: Mon, 15 Jan 2024 10:27:18 +0100
Mime-Version: 1.0
X-Mailer: git-send-email 2.43.0.275.g3460e3d667-goog
Message-ID: <20240115092727.888096-1-elver@google.com>
Subject: [PATCH RFC 1/2] stackdepot: add stats counters exported via debugfs
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, Andrew Morton <akpm@linux-foundation.org>
Cc: Andrey Konovalov <andreyknvl@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vlastimil Babka <vbabka@suse.cz>, linux-kernel@vger.kernel.org, 
	linux-mm@kvack.org, kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=P4wKmmVd;       spf=pass
 (google.com: domain of 3hpqkzqukcuehoyhujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=3hPqkZQUKCUEhoyhujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--elver.bounces.google.com;
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
2.43.0.275.g3460e3d667-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240115092727.888096-1-elver%40google.com.
