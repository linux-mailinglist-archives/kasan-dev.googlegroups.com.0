Return-Path: <kasan-dev+bncBC7OBJGL2MHBBGHIUO4QMGQE2JEP3WA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x340.google.com (mail-wm1-x340.google.com [IPv6:2a00:1450:4864:20::340])
	by mail.lfdr.de (Postfix) with ESMTPS id 8B6F29BBA23
	for <lists+kasan-dev@lfdr.de>; Mon,  4 Nov 2024 17:19:37 +0100 (CET)
Received: by mail-wm1-x340.google.com with SMTP id 5b1f17b1804b1-4315d98a75fsf30344005e9.2
        for <lists+kasan-dev@lfdr.de>; Mon, 04 Nov 2024 08:19:37 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1730737177; cv=pass;
        d=google.com; s=arc-20240605;
        b=Y80Cb6p/Qs8IJCycpq+2R0PEU/pMrZi8cW1tuuBEWHA8bqiGgIokYNlZlM51JewUxX
         SAAmo5HMZwQf2hVmJxuDOg2YFbqe7Do3JXMN6rT6Ifo4kQpSa/fWhjEhCzqk2s/GS2U2
         Oa7K/KyTuu+3brBnW8g3D/ar6eiX6tzXoWWbgBWZnXmw4GmrWpLdakfvszzruQiohNuc
         ykn+WgawheqFcdzW3y1ER3D1ltJC1r969l1ljmidzO16Bu5F3do7HQe1icJC/HmFpPfX
         kwH6d7IGYLvv3n/JllJRsPWa3pibUvziGlQd0epS3rVRPvgVBM6wB33u0ry20UveupCh
         CJ8w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=GEVtw/tKNGYJydG1PVxjHJWSiqugzqGhea+I2IOizNQ=;
        fh=UhLNI9OXRmxagSItJtI+/ULCAc5v+Dr3Gdco+Yc8cW8=;
        b=fGfsT5dTFHVXYNHkhuxAgGfdpTYcEGMLoB2SLEPq/Aq1b4pfa8euW667P+6NO0JZNN
         PFvRs7SyFYh79QyCLm8r9vl5IHbab2titFYD2i9DuaFnpd2iIfcSEZB+rMxmLJdZfT6i
         rHdWSDBgdCjo9tkIwd8xTNA/NSve8qdu7Rv+CsqjEAeR4xURwu2PUFdnjYOm1Wk3gsT5
         svPGqyZA0rhLx0kCHMUzewFT3k1Axw4t2dCwaLfxM3XZysWwpemz9dCzlc8a7CRxt2e7
         Cpw62TlddUi0zD2geHUOZLjsWoVbZucT0tTUZvDv2MqpPnywTPn8gVO3OiiRxK5CnraD
         SsVQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=nrzcrR88;
       spf=pass (google.com: domain of 3fvqozwukceehoyhujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--elver.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=3FvQoZwUKCeEHOYHUJRRJOH.FRPNDVDQ-GHYJRRJOHJURXSV.FRP@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1730737177; x=1731341977; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=GEVtw/tKNGYJydG1PVxjHJWSiqugzqGhea+I2IOizNQ=;
        b=klSsfwlX7ZJE1YHskJsImkGQUgYyQZu82lYS32a0ZkNCqNm7eMLFSsUQWLD4JP0vSA
         mXMi5Zb1REchlfD47hSGHBuZHuy8MSABQe9eqDnLFnVqa2zQTdOzxBPU/v0uQr+2+XN7
         E2N79ylL5mVCg4xV0sDn+KSiZk6+lKnlUxs7/Ftohv+PMnyRO5P62CWqU2Iv35YyMHhQ
         7B0MFk1VujDox1uC5YrXxctf19+wUgOe4INmkOPdIkvN5VeNO3qK4ldKNwRcFY3bJ984
         Z9DbMHsQPRe9RAJNUfLfolRON7Jypniz3bAvZixLRsEPPLht3QyGnAuOwHKr10/zdCRn
         lLJw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1730737177; x=1731341977;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=GEVtw/tKNGYJydG1PVxjHJWSiqugzqGhea+I2IOizNQ=;
        b=mCcHbVuZBZarnmM8BjHJbyQj53ck5cV2Bwej9Rn3b4xw0YHsbeYYXs6nWOHnfMgHz2
         AukJhQbfF/cUaQ4HhhwgvMkc9pYrTRvJE3W/nnwRMa2Z+O0hs7nP6olF0MFNrsiss194
         rfdxAtSW6JO5z9BHz5PMRWnM3ua5i+AQ4G70HghXJLcvUqcOigPD2o/c55vZRc5hBdM0
         fS+erAUeUb7A+YE4ruwQ8XO+CRGfDz88lU4sqwBXJ0mDe+03hHUEoRwBi4FF7nfN+4kq
         cRWI2icU7mymUZFyceIDkGuFCHN+q5UBlnN8xDLLEokUv6jMMUNenaxtR2oOQqgebi9U
         4mvw==
X-Forwarded-Encrypted: i=2; AJvYcCU7FTccN1AxjAmD0M0Q7AjKJrvYl8HTO2x7niNWkbXcoJxIEDdSxfR/sawEwABYN4u/3q97Rw==@lfdr.de
X-Gm-Message-State: AOJu0Yz6Hy3SGxtlJmpU/xdCjPS90gA6H7XIq//aMcmdz3QnRHcgsUQa
	2Kv0QQoXBOisdYDxH0pq4pNf+zRqPZHo3llhxqKQMklxynKKYqiF
X-Google-Smtp-Source: AGHT+IEf5AovnwsQiKJ52j3x7FMXjCK2DP1+sTugd2iUkSyDifpiYnGtMhFkS0II4p2SJS3BRfiyFg==
X-Received: by 2002:a05:600c:1552:b0:42c:de34:34be with SMTP id 5b1f17b1804b1-4319ac76422mr304222685e9.3.1730737176833;
        Mon, 04 Nov 2024 08:19:36 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:4fc3:b0:431:4fa0:2e0a with SMTP id
 5b1f17b1804b1-4327b80876fls23664195e9.1.-pod-prod-09-eu; Mon, 04 Nov 2024
 08:19:35 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWviMnIG94ZjSfTm53WOIuosWopWMqEO6DYK3PsBEpuET35AeIO/EpRMqiXFjAh8qXTiK9QIsKRWJw=@googlegroups.com
X-Received: by 2002:a05:600c:3593:b0:430:54a4:5ad7 with SMTP id 5b1f17b1804b1-4319ac76449mr299996145e9.1.1730737174756;
        Mon, 04 Nov 2024 08:19:34 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1730737174; cv=none;
        d=google.com; s=arc-20240605;
        b=B4bJdzHPSPllFsrHW3lv/Zh0IOlVSo31PtNXzMsPVRh1kvQf6Ro92dfEfAXoz7k8Lx
         AhYqtyuwkqdjPyBWik83z5mulecIg83ftk/Psoji2F9d7ZlZLW7E/dR7tCcVr4aEhDUT
         fWuIwuGNo+VIw+s1YLEhjhIASTVLiY4ol56bEbIXb4Zi+br/ycx8z52Q5du4EsBodgtf
         YzdmV5LNua2zEDAEJcxt1NKL8x/YGAXK3v1qO9hXwJWW4UVfpvh64eJc9pVQL3Lb6a9l
         hxrgMFNnInQGirzo3Y5qyegZjoKnrlE4weap2vI5JpzzIXqbC4ANzvPHMh6tK3Qg5ki+
         9ppQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=D01NtyTMk6i2oodCmqKoOULZz5EC2eZ4CIhcaLc7Lms=;
        fh=K568823xJCjX/cjvy0OInMO/mHStZlSIEX9kAzqZ6xs=;
        b=CQJ3fYfqMXnbD/CxVX5Gqv6rl5ts/0qkc9R4Wyi57j3KLxf65Nmnp4MF4dnVY0MAxd
         ATnGMvD8kfB0GXYlP1/6Wa+IiHRLFcHpuTQHZmRiYgMrA+FJZiLXOdgUWC9+bBwbi0jo
         1CfVeXDJsBtTUfRPrbzsjvshFeeEtLhwJeVmzDePXIyV0x0P07IvW/WM9ATFP8a6u7ZR
         vnBqrVDxd0INAqVszqFeoO+EkTjmNHEvUQAPIW5HfY0R4nppkqnz0KZ9Gen3fjyHq4+F
         E8r3GxKu4rNOfqXM0B/U/KQUd2R78qSTpVbsGO4Hll3wK1dk3PPpjKcu7J8krbE7KAp9
         T+Hw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=nrzcrR88;
       spf=pass (google.com: domain of 3fvqozwukceehoyhujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--elver.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=3FvQoZwUKCeEHOYHUJRRJOH.FRPNDVDQ-GHYJRRJOHJURXSV.FRP@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-ej1-x649.google.com (mail-ej1-x649.google.com. [2a00:1450:4864:20::649])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-431b43ab92csi6901815e9.0.2024.11.04.08.19.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 04 Nov 2024 08:19:34 -0800 (PST)
Received-SPF: pass (google.com: domain of 3fvqozwukceehoyhujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--elver.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) client-ip=2a00:1450:4864:20::649;
Received: by mail-ej1-x649.google.com with SMTP id a640c23a62f3a-a9a1b8d4563so150326966b.3
        for <kasan-dev@googlegroups.com>; Mon, 04 Nov 2024 08:19:34 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCXs00aWyQiKUA0XpqkNJc0rk0PyvLz5+i2FVbgER3m9he2KbmozHy0zrcOw5+FvTS0k6bBlRtNkwgs=@googlegroups.com
X-Received: from elver.muc.corp.google.com ([2a00:79e0:9c:201:dc4d:3b27:d746:73ee])
 (user=elver job=sendgmr) by 2002:a17:906:c0c1:b0:a99:fa8a:9783 with SMTP id
 a640c23a62f3a-a9e654bee59mr296866b.3.1730737174017; Mon, 04 Nov 2024 08:19:34
 -0800 (PST)
Date: Mon,  4 Nov 2024 16:43:08 +0100
In-Reply-To: <20241104161910.780003-1-elver@google.com>
Mime-Version: 1.0
References: <20241104161910.780003-1-elver@google.com>
X-Mailer: git-send-email 2.47.0.163.g1226f6d8fa-goog
Message-ID: <20241104161910.780003-5-elver@google.com>
Subject: [PATCH v2 4/5] seqlock, treewide: Switch to non-raw seqcount_latch interface
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, Peter Zijlstra <peterz@infradead.org>, Ingo Molnar <mingo@redhat.com>, 
	Will Deacon <will@kernel.org>, Waiman Long <longman@redhat.com>, Boqun Feng <boqun.feng@gmail.com>
Cc: "Paul E. McKenney" <paulmck@kernel.org>, Thomas Gleixner <tglx@linutronix.de>, 
	Mark Rutland <mark.rutland@arm.com>, Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=nrzcrR88;       spf=pass
 (google.com: domain of 3fvqozwukceehoyhujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=3FvQoZwUKCeEHOYHUJRRJOH.FRPNDVDQ-GHYJRRJOHJURXSV.FRP@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
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

Switch all instrumentable users of the seqcount_latch interface over to
the non-raw interface.

Link: https://lore.kernel.org/all/20241030204815.GQ14555@noisy.programming.kicks-ass.net/
Co-developed-by: Peter Zijlstra (Intel) <peterz@infradead.org>
Signed-off-by: Peter Zijlstra (Intel) <peterz@infradead.org>
Signed-off-by: Marco Elver <elver@google.com>
---
v2:
* New patch.
---
 arch/x86/kernel/tsc.c        |  5 +++--
 include/linux/rbtree_latch.h | 20 +++++++++++---------
 kernel/printk/printk.c       |  9 +++++----
 kernel/time/sched_clock.c    | 12 +++++++-----
 kernel/time/timekeeping.c    | 12 +++++++-----
 5 files changed, 33 insertions(+), 25 deletions(-)

diff --git a/arch/x86/kernel/tsc.c b/arch/x86/kernel/tsc.c
index dfe6847fd99e..67aeaba4ba9c 100644
--- a/arch/x86/kernel/tsc.c
+++ b/arch/x86/kernel/tsc.c
@@ -174,10 +174,11 @@ static void __set_cyc2ns_scale(unsigned long khz, int cpu, unsigned long long ts
 
 	c2n = per_cpu_ptr(&cyc2ns, cpu);
 
-	raw_write_seqcount_latch(&c2n->seq);
+	write_seqcount_latch_begin(&c2n->seq);
 	c2n->data[0] = data;
-	raw_write_seqcount_latch(&c2n->seq);
+	write_seqcount_latch(&c2n->seq);
 	c2n->data[1] = data;
+	write_seqcount_latch_end(&c2n->seq);
 }
 
 static void set_cyc2ns_scale(unsigned long khz, int cpu, unsigned long long tsc_now)
diff --git a/include/linux/rbtree_latch.h b/include/linux/rbtree_latch.h
index 6a0999c26c7c..2f630eb8307e 100644
--- a/include/linux/rbtree_latch.h
+++ b/include/linux/rbtree_latch.h
@@ -14,7 +14,7 @@
  *
  * If we need to allow unconditional lookups (say as required for NMI context
  * usage) we need a more complex setup; this data structure provides this by
- * employing the latch technique -- see @raw_write_seqcount_latch -- to
+ * employing the latch technique -- see @write_seqcount_latch_begin -- to
  * implement a latched RB-tree which does allow for unconditional lookups by
  * virtue of always having (at least) one stable copy of the tree.
  *
@@ -132,7 +132,7 @@ __lt_find(void *key, struct latch_tree_root *ltr, int idx,
  * @ops: operators defining the node order
  *
  * It inserts @node into @root in an ordered fashion such that we can always
- * observe one complete tree. See the comment for raw_write_seqcount_latch().
+ * observe one complete tree. See the comment for write_seqcount_latch_begin().
  *
  * The inserts use rcu_assign_pointer() to publish the element such that the
  * tree structure is stored before we can observe the new @node.
@@ -145,10 +145,11 @@ latch_tree_insert(struct latch_tree_node *node,
 		  struct latch_tree_root *root,
 		  const struct latch_tree_ops *ops)
 {
-	raw_write_seqcount_latch(&root->seq);
+	write_seqcount_latch_begin(&root->seq);
 	__lt_insert(node, root, 0, ops->less);
-	raw_write_seqcount_latch(&root->seq);
+	write_seqcount_latch(&root->seq);
 	__lt_insert(node, root, 1, ops->less);
+	write_seqcount_latch_end(&root->seq);
 }
 
 /**
@@ -159,7 +160,7 @@ latch_tree_insert(struct latch_tree_node *node,
  *
  * Removes @node from the trees @root in an ordered fashion such that we can
  * always observe one complete tree. See the comment for
- * raw_write_seqcount_latch().
+ * write_seqcount_latch_begin().
  *
  * It is assumed that @node will observe one RCU quiescent state before being
  * reused of freed.
@@ -172,10 +173,11 @@ latch_tree_erase(struct latch_tree_node *node,
 		 struct latch_tree_root *root,
 		 const struct latch_tree_ops *ops)
 {
-	raw_write_seqcount_latch(&root->seq);
+	write_seqcount_latch_begin(&root->seq);
 	__lt_erase(node, root, 0);
-	raw_write_seqcount_latch(&root->seq);
+	write_seqcount_latch(&root->seq);
 	__lt_erase(node, root, 1);
+	write_seqcount_latch_end(&root->seq);
 }
 
 /**
@@ -204,9 +206,9 @@ latch_tree_find(void *key, struct latch_tree_root *root,
 	unsigned int seq;
 
 	do {
-		seq = raw_read_seqcount_latch(&root->seq);
+		seq = read_seqcount_latch(&root->seq);
 		node = __lt_find(key, root, seq & 1, ops->comp);
-	} while (raw_read_seqcount_latch_retry(&root->seq, seq));
+	} while (read_seqcount_latch_retry(&root->seq, seq));
 
 	return node;
 }
diff --git a/kernel/printk/printk.c b/kernel/printk/printk.c
index beb808f4c367..19911c8fa7b6 100644
--- a/kernel/printk/printk.c
+++ b/kernel/printk/printk.c
@@ -560,10 +560,11 @@ bool printk_percpu_data_ready(void)
 /* Must be called under syslog_lock. */
 static void latched_seq_write(struct latched_seq *ls, u64 val)
 {
-	raw_write_seqcount_latch(&ls->latch);
+	write_seqcount_latch_begin(&ls->latch);
 	ls->val[0] = val;
-	raw_write_seqcount_latch(&ls->latch);
+	write_seqcount_latch(&ls->latch);
 	ls->val[1] = val;
+	write_seqcount_latch_end(&ls->latch);
 }
 
 /* Can be called from any context. */
@@ -574,10 +575,10 @@ static u64 latched_seq_read_nolock(struct latched_seq *ls)
 	u64 val;
 
 	do {
-		seq = raw_read_seqcount_latch(&ls->latch);
+		seq = read_seqcount_latch(&ls->latch);
 		idx = seq & 0x1;
 		val = ls->val[idx];
-	} while (raw_read_seqcount_latch_retry(&ls->latch, seq));
+	} while (read_seqcount_latch_retry(&ls->latch, seq));
 
 	return val;
 }
diff --git a/kernel/time/sched_clock.c b/kernel/time/sched_clock.c
index 29bdf309dae8..fcca4e72f1ef 100644
--- a/kernel/time/sched_clock.c
+++ b/kernel/time/sched_clock.c
@@ -71,13 +71,13 @@ static __always_inline u64 cyc_to_ns(u64 cyc, u32 mult, u32 shift)
 
 notrace struct clock_read_data *sched_clock_read_begin(unsigned int *seq)
 {
-	*seq = raw_read_seqcount_latch(&cd.seq);
+	*seq = read_seqcount_latch(&cd.seq);
 	return cd.read_data + (*seq & 1);
 }
 
 notrace int sched_clock_read_retry(unsigned int seq)
 {
-	return raw_read_seqcount_latch_retry(&cd.seq, seq);
+	return read_seqcount_latch_retry(&cd.seq, seq);
 }
 
 static __always_inline unsigned long long __sched_clock(void)
@@ -132,16 +132,18 @@ unsigned long long notrace sched_clock(void)
 static void update_clock_read_data(struct clock_read_data *rd)
 {
 	/* steer readers towards the odd copy */
-	raw_write_seqcount_latch(&cd.seq);
+	write_seqcount_latch_begin(&cd.seq);
 
 	/* now its safe for us to update the normal (even) copy */
 	cd.read_data[0] = *rd;
 
 	/* switch readers back to the even copy */
-	raw_write_seqcount_latch(&cd.seq);
+	write_seqcount_latch(&cd.seq);
 
 	/* update the backup (odd) copy with the new data */
 	cd.read_data[1] = *rd;
+
+	write_seqcount_latch_end(&cd.seq);
 }
 
 /*
@@ -279,7 +281,7 @@ void __init generic_sched_clock_init(void)
  */
 static u64 notrace suspended_sched_clock_read(void)
 {
-	unsigned int seq = raw_read_seqcount_latch(&cd.seq);
+	unsigned int seq = read_seqcount_latch(&cd.seq);
 
 	return cd.read_data[seq & 1].epoch_cyc;
 }
diff --git a/kernel/time/timekeeping.c b/kernel/time/timekeeping.c
index 7e6f409bf311..18752983e834 100644
--- a/kernel/time/timekeeping.c
+++ b/kernel/time/timekeeping.c
@@ -411,7 +411,7 @@ static inline u64 timekeeping_get_ns(const struct tk_read_base *tkr)
  * We want to use this from any context including NMI and tracing /
  * instrumenting the timekeeping code itself.
  *
- * Employ the latch technique; see @raw_write_seqcount_latch.
+ * Employ the latch technique; see @write_seqcount_latch.
  *
  * So if a NMI hits the update of base[0] then it will use base[1]
  * which is still consistent. In the worst case this can result is a
@@ -424,16 +424,18 @@ static void update_fast_timekeeper(const struct tk_read_base *tkr,
 	struct tk_read_base *base = tkf->base;
 
 	/* Force readers off to base[1] */
-	raw_write_seqcount_latch(&tkf->seq);
+	write_seqcount_latch_begin(&tkf->seq);
 
 	/* Update base[0] */
 	memcpy(base, tkr, sizeof(*base));
 
 	/* Force readers back to base[0] */
-	raw_write_seqcount_latch(&tkf->seq);
+	write_seqcount_latch(&tkf->seq);
 
 	/* Update base[1] */
 	memcpy(base + 1, base, sizeof(*base));
+
+	write_seqcount_latch_end(&tkf->seq);
 }
 
 static __always_inline u64 __ktime_get_fast_ns(struct tk_fast *tkf)
@@ -443,11 +445,11 @@ static __always_inline u64 __ktime_get_fast_ns(struct tk_fast *tkf)
 	u64 now;
 
 	do {
-		seq = raw_read_seqcount_latch(&tkf->seq);
+		seq = read_seqcount_latch(&tkf->seq);
 		tkr = tkf->base + (seq & 0x01);
 		now = ktime_to_ns(tkr->base);
 		now += __timekeeping_get_ns(tkr);
-	} while (raw_read_seqcount_latch_retry(&tkf->seq, seq));
+	} while (read_seqcount_latch_retry(&tkf->seq, seq));
 
 	return now;
 }
-- 
2.47.0.163.g1226f6d8fa-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20241104161910.780003-5-elver%40google.com.
