Return-Path: <kasan-dev+bncBC7OD3FKWUERBLEMXKMAMGQEAP4RDYI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd39.google.com (mail-io1-xd39.google.com [IPv6:2607:f8b0:4864:20::d39])
	by mail.lfdr.de (Postfix) with ESMTPS id ABF4D5A6FB0
	for <lists+kasan-dev@lfdr.de>; Tue, 30 Aug 2022 23:50:37 +0200 (CEST)
Received: by mail-io1-xd39.google.com with SMTP id bh11-20020a056602370b00b00688c8a2b56csf7509574iob.13
        for <lists+kasan-dev@lfdr.de>; Tue, 30 Aug 2022 14:50:37 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1661896236; cv=pass;
        d=google.com; s=arc-20160816;
        b=uIpUVJne7e5gO7OR+wCUPc0UBJdv2HwI+iKa/4n48QNNI8F6YigBSP7eT3JtT13vW/
         aZvE7KymwGiO9WeJmISrw4q0Gn2JG7eX1f5Pwc+fM6eePaTQSkxuFlJHT6EFO8VobFL4
         mGUMGKLcEaCAN1pKSl4U5rslqzkxS7r8e0G7Ow9yb44lghW1eWECYwSvn8T+b6uunNrI
         kBg9PAD6PC84H4c4twJGaSvsDjtMlA7XQ2KHdX6uVGHo4zanxm3oxUdHXn37imUBqJ+r
         tSu5dty6RjqtpRkyGjDEnP1fzac8ZpwPBJl1WuDrObbDQp8WiU2JKAbCGGMhdRb9fxDZ
         M1pg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=O7OhkvWvbQWb0J993HZtnAyPE3p3kKAg101sK57HuJ8=;
        b=PSJ5lI/70NnD7piZ/LwboSC2Vh6Sfj4ee9iRtHtr2H0qjzN+TfmaipXY2GDQBSShcx
         pAOMEOoUboL3aFMmoE7iwqEZycoxr9NdWZbUl2xkb+6rWoFI7XCnwUL0esbtZ9s7IevE
         uG1yz/lBVXR/+BDEJq1k28L53yb+ytHLf15BKVeS2qmBMSP/kJs+yR6KDM3BM/bJaJpK
         6BzkpWKn+zKNxEuG2BBauN0wSmNY8celano9XXSozCPrikRUoAEHVw78HFBOVxbtUXDZ
         dFqefO/59weIkqSC+JT68R3s34w6RroTegb7YCSHMA6V7xk0GKxTuju0F5wAdeBLtwfd
         vZOw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=dJIIXMoa;
       spf=pass (google.com: domain of 3k4yoywykczaceby7v08805y.w864ucu7-xyf08805y0b8e9c.w86@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::64a as permitted sender) smtp.mailfrom=3K4YOYwYKCZACEBy7v08805y.w864uCu7-xyF08805y0B8E9C.w86@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc;
        bh=O7OhkvWvbQWb0J993HZtnAyPE3p3kKAg101sK57HuJ8=;
        b=b9EkTnYsPsW6nEP9kgud3Yc5IvnjmRULZ/2+bJ/I2Spt6zeCugzR0YCUtmgfNzphmR
         hcFxqAvv+Kt3LM5ZO4ABUh+JeLTVDl5DzmB7zE2DbiKjO1nDTCAx5yfzi8eJZqZiPorz
         cLRTWnk/gxiW8vFjAIcKviPj0IuE7GR1JhRhF9JoF0QDtDADEgWRDbt7A0L2hd6kRxAm
         EOa1e5quzYsTEEfryv6U0RRgclJzpZ30hLIn+x34XU7yNvjbaJso0Ez0+ui0yVUatEn3
         Ia+ct0WuEMWvwEjAJResFo2VbmXSMGtQ8SqxDmu3H6PV01fHsc5mKVpufymMRgy/jjdg
         cXsw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-gm-message-state:from:to:cc;
        bh=O7OhkvWvbQWb0J993HZtnAyPE3p3kKAg101sK57HuJ8=;
        b=0JOulEow4nfJpYis3VnBRMw4ndjHiJFc79W88S0hDSWVE2XsUh67/xAWHCIIj8dB1H
         vQ9/rbUGFKHwHGm395DCXG45jo2VrucysjgzI4kKcJdG8mBHajbJhdvELUaMMdUa1oVR
         D3b+fRtnbh04Vlf0sdUQ5rZzzz9MN+K6zMcKM3ydXxKgTNWGJf3GjuVhQWzYBSl3jDTQ
         SCVSn6b5V4f2kgjR+CqeW7R2b81Rn2NWnyJ2SJxv0WHX3jKULwE00I80j5Paxfb0IlTG
         lsJ5c1mLt0DFPtSDw5oEVxikd6qwreySNa4Yyj7Quc3OzayWqsR7Cdot2w6kiCtqcQ9G
         OJHg==
X-Gm-Message-State: ACgBeo0aiijeMhCzeaklQnptEcC9Zp77DsZhqT/hr+dTJuEuP0VSyGNU
	VTpD7AXNOUHf0WGOy+oi3iM=
X-Google-Smtp-Source: AA6agR6Et+VLTZemYou7fNZH6ehkzjxsq73lMMKWE8yxH220Yw+iKem6C3Jx6WSszmXju0vBo5hTCQ==
X-Received: by 2002:a5e:c319:0:b0:68b:2683:8e26 with SMTP id a25-20020a5ec319000000b0068b26838e26mr8046895iok.129.1661896236640;
        Tue, 30 Aug 2022 14:50:36 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a02:b092:0:b0:349:e63e:93 with SMTP id v18-20020a02b092000000b00349e63e0093ls3347743jah.9.-pod-prod-gmail;
 Tue, 30 Aug 2022 14:50:36 -0700 (PDT)
X-Received: by 2002:a05:6638:16cf:b0:34a:263f:966d with SMTP id g15-20020a05663816cf00b0034a263f966dmr10640851jat.124.1661896236251;
        Tue, 30 Aug 2022 14:50:36 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1661896236; cv=none;
        d=google.com; s=arc-20160816;
        b=svR0A1d2VS8QW323F5oR1xFE4Z0OhAvug3Uy0nO295kDpHOt26g6EEqo72XU0JaGAA
         XVBdj+Q3/UA6b8pFLiWSRie5oast0T8HKOzql9hbDw5b/svonGFrypj7lT5gJ3ygBdVw
         UMDqYi252G3WfCxThYF1hqdVXwDQXABCKQx+rpRHa9q7sT1kT4L0GRf+Y8JcVRvgLcpw
         RCjuhUjbd741I6cCbFStUH05IqnJv4eLAYNJErWEyFTY7yFIsSHYudlhXS+OqO+7pUPW
         nVXl8e4TCv1CpZ0WLjJ3z5P7iecpI5bM3hmAvv4G4CNpxGPMu+Dfp6qgAYJ+49woeQoV
         /Bng==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=kZY1PfnIfhpzKe2fg2QNhEi4K+n6/AZeM4PXPDl+jSs=;
        b=JgpcgJe15QYRcuXwBRFdZDEArsCLX68USVJ5bAfwlpHZ3TDI947qZNIgBOJw80VKS3
         rX1GlbvZY7Y9vDf6I/nkAl0457hf9FVjQkmsu5OTASBnF4q1OXN4Bz5GM45mgJEnrvR9
         pR61IuWOgWW3NQOXJk3pCW968Qo/BdLRf3Jv1OHZqdvo+of7HatBRivMpQN9PJEp8FYJ
         xVIWDMqMvWc+da5rgQHtZsnvb9ZVnwVQjDK/cZ0MgNRWe4YDRGyNsYf8KcWEMgrAqY0U
         dt2yrAQtYYQqVgNMvf/R5w2XvdUlfVii+dkddOR0jF303qclB3UmRjMzzRxTNMQHFkPF
         2Tcw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=dJIIXMoa;
       spf=pass (google.com: domain of 3k4yoywykczaceby7v08805y.w864ucu7-xyf08805y0b8e9c.w86@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::64a as permitted sender) smtp.mailfrom=3K4YOYwYKCZACEBy7v08805y.w864uCu7-xyF08805y0B8E9C.w86@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pl1-x64a.google.com (mail-pl1-x64a.google.com. [2607:f8b0:4864:20::64a])
        by gmr-mx.google.com with ESMTPS id h25-20020a02c4d9000000b003497810ec1dsi565964jaj.1.2022.08.30.14.50.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 30 Aug 2022 14:50:36 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3k4yoywykczaceby7v08805y.w864ucu7-xyf08805y0b8e9c.w86@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::64a as permitted sender) client-ip=2607:f8b0:4864:20::64a;
Received: by mail-pl1-x64a.google.com with SMTP id f1-20020a170902ce8100b001731029cd6bso8598762plg.1
        for <kasan-dev@googlegroups.com>; Tue, 30 Aug 2022 14:50:36 -0700 (PDT)
X-Received: from surenb-desktop.mtv.corp.google.com ([2620:15c:211:200:a005:55b3:6c26:b3e4])
 (user=surenb job=sendgmr) by 2002:a63:5c4a:0:b0:41d:bd7d:6084 with SMTP id
 n10-20020a635c4a000000b0041dbd7d6084mr19548657pgm.411.1661896235530; Tue, 30
 Aug 2022 14:50:35 -0700 (PDT)
Date: Tue, 30 Aug 2022 14:49:16 -0700
In-Reply-To: <20220830214919.53220-1-surenb@google.com>
Mime-Version: 1.0
References: <20220830214919.53220-1-surenb@google.com>
X-Mailer: git-send-email 2.37.2.672.g94769d06f0-goog
Message-ID: <20220830214919.53220-28-surenb@google.com>
Subject: [RFC PATCH 27/30] Code tagging based latency tracking
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
To: akpm@linux-foundation.org
Cc: kent.overstreet@linux.dev, mhocko@suse.com, vbabka@suse.cz, 
	hannes@cmpxchg.org, roman.gushchin@linux.dev, mgorman@suse.de, 
	dave@stgolabs.net, willy@infradead.org, liam.howlett@oracle.com, 
	void@manifault.com, peterz@infradead.org, juri.lelli@redhat.com, 
	ldufour@linux.ibm.com, peterx@redhat.com, david@redhat.com, axboe@kernel.dk, 
	mcgrof@kernel.org, masahiroy@kernel.org, nathan@kernel.org, 
	changbin.du@intel.com, ytcoode@gmail.com, vincent.guittot@linaro.org, 
	dietmar.eggemann@arm.com, rostedt@goodmis.org, bsegall@google.com, 
	bristot@redhat.com, vschneid@redhat.com, cl@linux.com, penberg@kernel.org, 
	iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com, glider@google.com, 
	elver@google.com, dvyukov@google.com, shakeelb@google.com, 
	songmuchun@bytedance.com, arnd@arndb.de, jbaron@akamai.com, 
	rientjes@google.com, minchan@google.com, kaleshsingh@google.com, 
	surenb@google.com, kernel-team@android.com, linux-mm@kvack.org, 
	iommu@lists.linux.dev, kasan-dev@googlegroups.com, io-uring@vger.kernel.org, 
	linux-arch@vger.kernel.org, xen-devel@lists.xenproject.org, 
	linux-bcache@vger.kernel.org, linux-modules@vger.kernel.org, 
	linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: surenb@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=dJIIXMoa;       spf=pass
 (google.com: domain of 3k4yoywykczaceby7v08805y.w864ucu7-xyf08805y0b8e9c.w86@flex--surenb.bounces.google.com
 designates 2607:f8b0:4864:20::64a as permitted sender) smtp.mailfrom=3K4YOYwYKCZACEBy7v08805y.w864uCu7-xyF08805y0B8E9C.w86@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Suren Baghdasaryan <surenb@google.com>
Reply-To: Suren Baghdasaryan <surenb@google.com>
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

From: Kent Overstreet <kent.overstreet@linux.dev>

This adds the ability to easily instrument code for measuring latency.
To use, add the following to calls to your code, at the start and end of
the event you wish to measure:

  code_tag_time_stats_start(start_time);
  code_tag_time_stats_finish(start_time);

Stastistics will then show up in debugfs under
/sys/kernel/debug/time_stats, listed by file and line number.

Stastics measured include weighted averages of frequency, duration, max
duration, as well as quantiles.

This patch also instruments all calls to init_wait and finish_wait,
which includes all calls to wait_event. Example debugfs output:

fs/xfs/xfs_trans_ail.c:746 module:xfs func:xfs_ail_push_all_sync
count:          17
rate:           0/sec
frequency:      2 sec
avg duration:   10 us
max duration:   232 us
quantiles (ns): 128 128 128 128 128 128 128 128 128 128 128 128 128 128 128

lib/sbitmap.c:813 module:sbitmap func:sbitmap_finish_wait
count:          3
rate:           0/sec
frequency:      4 sec
avg duration:   4 sec
max duration:   4 sec
quantiles (ns): 0 4288669120 4288669120 5360836048 5360836048 5360836048 5360836048 5360836048 5360836048 5360836048 5360836048 5360836048 5360836048 5360836048 5360836048

net/core/datagram.c:122 module:datagram func:__skb_wait_for_more_packets
count:          10
rate:           1/sec
frequency:      859 ms
avg duration:   472 ms
max duration:   30 sec
quantiles (ns): 0 12279 12279 15669 15669 15669 15669 17217 17217 17217 17217 17217 17217 17217 17217

Signed-off-by: Kent Overstreet <kent.overstreet@linux.dev>
---
 include/asm-generic/codetag.lds.h  |   3 +-
 include/linux/codetag_time_stats.h |  54 +++++++++++
 include/linux/io_uring_types.h     |   2 +-
 include/linux/wait.h               |  22 ++++-
 kernel/sched/wait.c                |   6 +-
 lib/Kconfig.debug                  |   8 ++
 lib/Makefile                       |   1 +
 lib/codetag_time_stats.c           | 143 +++++++++++++++++++++++++++++
 8 files changed, 233 insertions(+), 6 deletions(-)
 create mode 100644 include/linux/codetag_time_stats.h
 create mode 100644 lib/codetag_time_stats.c

diff --git a/include/asm-generic/codetag.lds.h b/include/asm-generic/codetag.lds.h
index 16fbf74edc3d..d799f4aced82 100644
--- a/include/asm-generic/codetag.lds.h
+++ b/include/asm-generic/codetag.lds.h
@@ -10,6 +10,7 @@
 
 #define CODETAG_SECTIONS()		\
 	SECTION_WITH_BOUNDARIES(alloc_tags)		\
-	SECTION_WITH_BOUNDARIES(dynamic_fault_tags)
+	SECTION_WITH_BOUNDARIES(dynamic_fault_tags)	\
+	SECTION_WITH_BOUNDARIES(time_stats_tags)
 
 #endif /* __ASM_GENERIC_CODETAG_LDS_H */
diff --git a/include/linux/codetag_time_stats.h b/include/linux/codetag_time_stats.h
new file mode 100644
index 000000000000..7e44c7ee9e9b
--- /dev/null
+++ b/include/linux/codetag_time_stats.h
@@ -0,0 +1,54 @@
+/* SPDX-License-Identifier: GPL-2.0 */
+#ifndef _LINUX_CODETAG_TIMESTATS_H
+#define _LINUX_CODETAG_TIMESTATS_H
+
+/*
+ * Code tagging based latency tracking:
+ * (C) 2022 Kent Overstreet
+ *
+ * This allows you to easily instrument code to track latency, and have the
+ * results show up in debugfs. To use, add the following two calls to your code
+ * at the beginning and end of the event you wish to instrument:
+ *
+ * code_tag_time_stats_start(start_time);
+ * code_tag_time_stats_finish(start_time);
+ *
+ * Statistics will then show up in debugfs under /sys/kernel/debug/time_stats,
+ * listed by file and line number.
+ */
+
+#ifdef CONFIG_CODETAG_TIME_STATS
+
+#include <linux/codetag.h>
+#include <linux/time_stats.h>
+#include <linux/timekeeping.h>
+
+struct codetag_time_stats {
+	struct codetag		tag;
+	struct time_stats	stats;
+};
+
+#define codetag_time_stats_start(_start_time)	u64 _start_time = ktime_get_ns()
+
+#define codetag_time_stats_finish(_start_time)			\
+do {								\
+	static struct codetag_time_stats			\
+	__used							\
+	__section("time_stats_tags")				\
+	__aligned(8) s = {					\
+		.tag	= CODE_TAG_INIT,			\
+		.stats.lock = __SPIN_LOCK_UNLOCKED(_lock)	\
+	};							\
+								\
+	WARN_ONCE(!(_start_time), "codetag_time_stats_start() not called");\
+	time_stats_update(&s.stats, _start_time);		\
+} while (0)
+
+#else
+
+#define codetag_time_stats_finish(_start_time)	do {} while (0)
+#define codetag_time_stats_start(_start_time)	do {} while (0)
+
+#endif /* CODETAG_CODETAG_TIME_STATS */
+
+#endif
diff --git a/include/linux/io_uring_types.h b/include/linux/io_uring_types.h
index 677a25d44d7f..3bcef85eacd8 100644
--- a/include/linux/io_uring_types.h
+++ b/include/linux/io_uring_types.h
@@ -488,7 +488,7 @@ struct io_cqe {
 struct io_cmd_data {
 	struct file		*file;
 	/* each command gets 56 bytes of data */
-	__u8			data[56];
+	__u8			data[64];
 };
 
 static inline void io_kiocb_cmd_sz_check(size_t cmd_sz)
diff --git a/include/linux/wait.h b/include/linux/wait.h
index 91ced6a118bc..bab11b7ef19a 100644
--- a/include/linux/wait.h
+++ b/include/linux/wait.h
@@ -4,6 +4,7 @@
 /*
  * Linux wait queue related types and methods
  */
+#include <linux/codetag_time_stats.h>
 #include <linux/list.h>
 #include <linux/stddef.h>
 #include <linux/spinlock.h>
@@ -32,6 +33,9 @@ struct wait_queue_entry {
 	void			*private;
 	wait_queue_func_t	func;
 	struct list_head	entry;
+#ifdef CONFIG_CODETAG_TIME_STATS
+	u64			start_time;
+#endif
 };
 
 struct wait_queue_head {
@@ -79,10 +83,17 @@ extern void __init_waitqueue_head(struct wait_queue_head *wq_head, const char *n
 # define DECLARE_WAIT_QUEUE_HEAD_ONSTACK(name) DECLARE_WAIT_QUEUE_HEAD(name)
 #endif
 
+#ifdef CONFIG_CODETAG_TIME_STATS
+#define WAIT_QUEUE_ENTRY_START_TIME_INITIALIZER	.start_time = ktime_get_ns(),
+#else
+#define WAIT_QUEUE_ENTRY_START_TIME_INITIALIZER
+#endif
+
 #define WAIT_FUNC_INITIALIZER(name, function) {					\
 	.private	= current,						\
 	.func		= function,						\
 	.entry		= LIST_HEAD_INIT((name).entry),				\
+	WAIT_QUEUE_ENTRY_START_TIME_INITIALIZER					\
 }
 
 #define DEFINE_WAIT_FUNC(name, function)					\
@@ -98,6 +109,9 @@ __init_waitqueue_entry(struct wait_queue_entry *wq_entry, unsigned int flags,
 	wq_entry->private	= private;
 	wq_entry->func		= func;
 	INIT_LIST_HEAD(&wq_entry->entry);
+#ifdef CONFIG_CODETAG_TIME_STATS
+	wq_entry->start_time	= ktime_get_ns();
+#endif
 }
 
 #define init_waitqueue_func_entry(_wq_entry, _func)			\
@@ -1180,11 +1194,17 @@ do {										\
 void prepare_to_wait(struct wait_queue_head *wq_head, struct wait_queue_entry *wq_entry, int state);
 bool prepare_to_wait_exclusive(struct wait_queue_head *wq_head, struct wait_queue_entry *wq_entry, int state);
 long prepare_to_wait_event(struct wait_queue_head *wq_head, struct wait_queue_entry *wq_entry, int state);
-void finish_wait(struct wait_queue_head *wq_head, struct wait_queue_entry *wq_entry);
+void __finish_wait(struct wait_queue_head *wq_head, struct wait_queue_entry *wq_entry);
 long wait_woken(struct wait_queue_entry *wq_entry, unsigned mode, long timeout);
 int woken_wake_function(struct wait_queue_entry *wq_entry, unsigned mode, int sync, void *key);
 int autoremove_wake_function(struct wait_queue_entry *wq_entry, unsigned mode, int sync, void *key);
 
+#define finish_wait(_wq_head, _wq_entry)					\
+do {										\
+	codetag_time_stats_finish((_wq_entry)->start_time);			\
+	__finish_wait(_wq_head, _wq_entry);					\
+} while (0)
+
 typedef int (*task_call_f)(struct task_struct *p, void *arg);
 extern int task_call_func(struct task_struct *p, task_call_f func, void *arg);
 
diff --git a/kernel/sched/wait.c b/kernel/sched/wait.c
index b9922346077d..e88de3f0c3ad 100644
--- a/kernel/sched/wait.c
+++ b/kernel/sched/wait.c
@@ -367,7 +367,7 @@ int do_wait_intr_irq(wait_queue_head_t *wq, wait_queue_entry_t *wait)
 EXPORT_SYMBOL(do_wait_intr_irq);
 
 /**
- * finish_wait - clean up after waiting in a queue
+ * __finish_wait - clean up after waiting in a queue
  * @wq_head: waitqueue waited on
  * @wq_entry: wait descriptor
  *
@@ -375,7 +375,7 @@ EXPORT_SYMBOL(do_wait_intr_irq);
  * the wait descriptor from the given waitqueue if still
  * queued.
  */
-void finish_wait(struct wait_queue_head *wq_head, struct wait_queue_entry *wq_entry)
+void __finish_wait(struct wait_queue_head *wq_head, struct wait_queue_entry *wq_entry)
 {
 	unsigned long flags;
 
@@ -399,7 +399,7 @@ void finish_wait(struct wait_queue_head *wq_head, struct wait_queue_entry *wq_en
 		spin_unlock_irqrestore(&wq_head->lock, flags);
 	}
 }
-EXPORT_SYMBOL(finish_wait);
+EXPORT_SYMBOL(__finish_wait);
 
 int autoremove_wake_function(struct wait_queue_entry *wq_entry, unsigned mode, int sync, void *key)
 {
diff --git a/lib/Kconfig.debug b/lib/Kconfig.debug
index b7d03afbc808..b0f86643b8f0 100644
--- a/lib/Kconfig.debug
+++ b/lib/Kconfig.debug
@@ -1728,6 +1728,14 @@ config LATENCYTOP
 	  Enable this option if you want to use the LatencyTOP tool
 	  to find out which userspace is blocking on what kernel operations.
 
+config CODETAG_TIME_STATS
+	bool "Code tagging based latency measuring"
+	depends on DEBUG_FS
+	select TIME_STATS
+	select CODE_TAGGING
+	help
+	  Enabling this option makes latency statistics available in debugfs
+
 source "kernel/trace/Kconfig"
 
 config PROVIDE_OHCI1394_DMA_INIT
diff --git a/lib/Makefile b/lib/Makefile
index e54392011f5e..d4067973805b 100644
--- a/lib/Makefile
+++ b/lib/Makefile
@@ -233,6 +233,7 @@ obj-$(CONFIG_PAGE_ALLOC_TAGGING) += pgalloc_tag.o
 
 obj-$(CONFIG_CODETAG_FAULT_INJECTION) += dynamic_fault.o
 obj-$(CONFIG_TIME_STATS) += time_stats.o
+obj-$(CONFIG_CODETAG_TIME_STATS) += codetag_time_stats.o
 
 lib-$(CONFIG_GENERIC_BUG) += bug.o
 
diff --git a/lib/codetag_time_stats.c b/lib/codetag_time_stats.c
new file mode 100644
index 000000000000..b0e9a08308a2
--- /dev/null
+++ b/lib/codetag_time_stats.c
@@ -0,0 +1,143 @@
+// SPDX-License-Identifier: GPL-2.0-only
+
+#include <linux/codetag_time_stats.h>
+#include <linux/ctype.h>
+#include <linux/debugfs.h>
+#include <linux/kernel.h>
+#include <linux/module.h>
+#include <linux/seq_buf.h>
+
+static struct codetag_type *cttype;
+
+struct user_buf {
+	char __user		*buf;	/* destination user buffer */
+	size_t			size;	/* size of requested read */
+	ssize_t			ret;	/* bytes read so far */
+};
+
+static int flush_ubuf(struct user_buf *dst, struct seq_buf *src)
+{
+	if (src->len) {
+		size_t bytes = min_t(size_t, src->len, dst->size);
+		int err = copy_to_user(dst->buf, src->buffer, bytes);
+
+		if (err)
+			return err;
+
+		dst->ret	+= bytes;
+		dst->buf	+= bytes;
+		dst->size	-= bytes;
+		src->len	-= bytes;
+		memmove(src->buffer, src->buffer + bytes, src->len);
+	}
+
+	return 0;
+}
+
+struct time_stats_iter {
+	struct codetag_iterator ct_iter;
+	struct seq_buf		buf;
+	char			rawbuf[4096];
+	bool			first;
+};
+
+static int time_stats_open(struct inode *inode, struct file *file)
+{
+	struct time_stats_iter *iter;
+
+	pr_debug("called");
+
+	iter = kzalloc(sizeof(*iter), GFP_KERNEL);
+	if (!iter)
+		return -ENOMEM;
+
+	codetag_lock_module_list(cttype, true);
+	codetag_init_iter(&iter->ct_iter, cttype);
+	codetag_lock_module_list(cttype, false);
+
+	file->private_data = iter;
+	seq_buf_init(&iter->buf, iter->rawbuf, sizeof(iter->rawbuf));
+	iter->first = true;
+	return 0;
+}
+
+static int time_stats_release(struct inode *inode, struct file *file)
+{
+	struct time_stats_iter *i = file->private_data;
+
+	kfree(i);
+	return 0;
+}
+
+static ssize_t time_stats_read(struct file *file, char __user *ubuf,
+			       size_t size, loff_t *ppos)
+{
+	struct time_stats_iter *iter = file->private_data;
+	struct user_buf	buf = { .buf = ubuf, .size = size };
+	struct codetag_time_stats *s;
+	struct codetag *ct;
+	int err;
+
+	codetag_lock_module_list(iter->ct_iter.cttype, true);
+	while (1) {
+		err = flush_ubuf(&buf, &iter->buf);
+		if (err || !buf.size)
+			break;
+
+		ct = codetag_next_ct(&iter->ct_iter);
+		if (!ct)
+			break;
+
+		s = container_of(ct, struct codetag_time_stats, tag);
+		if (s->stats.count) {
+			if (!iter->first) {
+				seq_buf_putc(&iter->buf, '\n');
+				iter->first = true;
+			}
+
+			codetag_to_text(&iter->buf, &s->tag);
+			seq_buf_putc(&iter->buf, '\n');
+			time_stats_to_text(&iter->buf, &s->stats);
+		}
+	}
+	codetag_lock_module_list(iter->ct_iter.cttype, false);
+
+	return err ?: buf.ret;
+}
+
+static const struct file_operations time_stats_ops = {
+	.owner	= THIS_MODULE,
+	.open	= time_stats_open,
+	.release = time_stats_release,
+	.read	= time_stats_read,
+};
+
+static void time_stats_module_unload(struct codetag_type *cttype, struct codetag_module *mod)
+{
+	struct codetag_time_stats *i, *start = (void *) mod->range.start;
+	struct codetag_time_stats *end = (void *) mod->range.stop;
+
+	for (i = start; i != end; i++)
+		time_stats_exit(&i->stats);
+}
+
+static int __init codetag_time_stats_init(void)
+{
+	const struct codetag_type_desc desc = {
+		.section	= "time_stats_tags",
+		.tag_size	= sizeof(struct codetag_time_stats),
+		.module_unload	= time_stats_module_unload,
+	};
+	struct dentry *debugfs_file;
+
+	cttype = codetag_register_type(&desc);
+	if (IS_ERR_OR_NULL(cttype))
+		return PTR_ERR(cttype);
+
+	debugfs_file = debugfs_create_file("time_stats", 0666, NULL, NULL, &time_stats_ops);
+	if (IS_ERR(debugfs_file))
+		return PTR_ERR(debugfs_file);
+
+	return 0;
+}
+module_init(codetag_time_stats_init);
-- 
2.37.2.672.g94769d06f0-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220830214919.53220-28-surenb%40google.com.
