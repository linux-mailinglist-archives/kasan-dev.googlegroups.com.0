Return-Path: <kasan-dev+bncBC7OBJGL2MHBB44RYO2QMGQEN7M2XQA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33b.google.com (mail-ot1-x33b.google.com [IPv6:2607:f8b0:4864:20::33b])
	by mail.lfdr.de (Postfix) with ESMTPS id AAB01947B28
	for <lists+kasan-dev@lfdr.de>; Mon,  5 Aug 2024 14:43:32 +0200 (CEST)
Received: by mail-ot1-x33b.google.com with SMTP id 46e09a7af769-7092e450d23sf12140221a34.3
        for <lists+kasan-dev@lfdr.de>; Mon, 05 Aug 2024 05:43:32 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1722861811; cv=pass;
        d=google.com; s=arc-20160816;
        b=F05ZV2T7nLNVfDVGBb6aHV6gTP504ZecHaWwdh72EaQWu2XmCwmt58CjTq7T71NLMi
         M2ZnoNy6mi7KwTXUMWR3VzLFl2iXWvkdRWkJR/BKsnKt2QvH9rng4uilUfrlzKkgJ9Tw
         m/vqhpzAeqE4FALW0GIrBOHGgHWtkBfUKX+UoWwCAv4uUbdoZwPMpJb434moxq27e1rX
         tpBlt6rzWhN4D8JmnVHNxLqelE4D34OCwEMDeXy4oqjipENTlVUmJ/SQHT4GOsn/utfV
         BdOgs8icnhsIyifCuw5646lk4C4xCrKhY3342jqTyxccOeMw0iwjbEgDCCVD76mipt5K
         X2hg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:mime-version:date:dkim-signature;
        bh=Ll8nkFY1gzi1qfZ7VarFFwUBwoa0ZeK92/THjJ3vE18=;
        fh=X8WLItMX9WNKxe1BPk8IwrSsDhXmmOaIjuFoYuoy6tg=;
        b=dFqPD3fpwZQSr3svuzUMBr1lHMxAfsDf0X0WJbY2oJm928FFxGHqx1FnBk7i0yKwo5
         C3HuvjVuV/svsxx6VccfPmYQhzUnor9iFoPRYAZdQxUwhbpywLoe376UEBH5qygrGIpT
         EFJMw74cdLfMAT+WI1aHHQzkpBsIvMtDaH6RviPTOyrptXrY6Xt2JFhXl3wMjyNw6cQE
         o+OKVqab3ONUHRRAQy5/DU/rWb27PK/ZptX0P33Q7X9im/MNooL/kiPtK3UyiDaoa5OB
         eQrAWUplQtS7sfpgh88C8AGIRqazdj+pXgib3X07Sc1+JMidu7D1ZOv79+jzQfyC9z03
         tonQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=3NSEryoe;
       spf=pass (google.com: domain of 38ciwzgukcyikr1kxmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=38ciwZgUKCYIkr1kxmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1722861811; x=1723466611; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:mime-version:date:from:to:cc:subject:date
         :message-id:reply-to;
        bh=Ll8nkFY1gzi1qfZ7VarFFwUBwoa0ZeK92/THjJ3vE18=;
        b=MV5MKmAkwsDrMZ7ydJyn0Qxf7b5X9p2b55PLc6ZiKbrHhO+8ETWyodneCPxZhLbRuC
         9TatO0aNJB1mOKUMjaIntX32cmgAo6mYpD8ILeptoxR+0vnp/heZUv0JbrD81yDFb6NO
         r/oz6VEalYNACiZ+iFd7cau/sAV5rr4IutPqNVs/K8I2tCDCfxvRTZyr/qOCxfqV2TQC
         B2V3leL+4vE53n4VZqc/L5efxBjSbAjCoh7euwn0SWMSMbxEUIlILiCbzodwJqwrcaP3
         42xJQs+njp5IgOX+Cuo4u/T7XF4bJlQ6/WM5BcX1kDp252E0Jjnexs2k2MFSKBuHJVaa
         kQHQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1722861811; x=1723466611;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:mime-version:date:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=Ll8nkFY1gzi1qfZ7VarFFwUBwoa0ZeK92/THjJ3vE18=;
        b=R6ouLPkMGVQQVxKfo49gRcluLSz4E7KKiczS5Je3N/tZlhVrEHxnWA/w9/0e/AEv1F
         8e763f9Cn+dz7JRUuJHszIKgtL0S6aArNskZfPu3rVyMQx4mABOrGE3FGfLouPPz96DX
         otpm3NGigC43KNiD57Nqksp3gvDaN4P3lsjn9YJkSRgD0sjlBO11yBQinpjNagyMrbxP
         essZSOEYLTIc5wCvsjZGvr3uzdwNN5BL/8kCulw/Nt49js0iKXDDiIdbuD4Zfzs74Rrf
         0IDlEfNzpID7mChIj14RdqZB5t39XZvJl8dNvhm6er4Gs57RFOLX7KCdroVHHnuhTprT
         lYbw==
X-Forwarded-Encrypted: i=2; AJvYcCXNMuFXnGFQS9B3Y+HquFIDTcnIcqSg5SqXdxZdmxp40wtFtC/bQ0Tq3MK9MoSGUqLbjsWs182H6gn5jtkcArsp05dDqZHOwA==
X-Gm-Message-State: AOJu0Yxzof1qfKKO50+SkFmYkOwrQRZylcJahAd6dVcxxAuW08cqNEYL
	l6NQRUMMHxksfUoPVFZptb39QvoZgdN026eHxcBCwGzOGNa75G/l
X-Google-Smtp-Source: AGHT+IEHWryDolG0LGncyol5mYxwlOY9TGfWu1Mn6/aUYlYKazyykCKuodgdYk1BTdpPe4sAtPLy9A==
X-Received: by 2002:a05:6830:6d15:b0:709:5b1e:f40f with SMTP id 46e09a7af769-709b321c4damr20133791a34.11.1722861811181;
        Mon, 05 Aug 2024 05:43:31 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:7f51:0:b0:450:4704:398 with SMTP id d75a77b69052e-451973ab1bels29026191cf.0.-pod-prod-03-us;
 Mon, 05 Aug 2024 05:43:30 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUj51mWlCNjVcWHy1W3Mu9MYc41r4oNPowkm7EjbR91DHzJX3Y26Pc/ZeX3CPp2I6DV3hTjEuxs8/U0uJ/LQ3kA2kvE3NLQv0ewVw==
X-Received: by 2002:a05:620a:28c6:b0:7a1:df6f:3625 with SMTP id af79cd13be357-7a34ef544e1mr1506868885a.37.1722861810371;
        Mon, 05 Aug 2024 05:43:30 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1722861810; cv=none;
        d=google.com; s=arc-20160816;
        b=WglDDHUPCNNx4bys6Bcvmd2cVfCycrcderzWAe0px7Fr0QAfguTW7E2BtZCqEY57SZ
         zJK5NpuVkdyQP5IyHT/ONMf2AjaUZy0ewHDK6nCbfia4uuwTm6VYuJ4/Azqp/XymhYoo
         nzD3xd7xhze/wqg9pYHflhx3jhPs6dnCw1KEnX7caUHcjgCrEwYVXLmNwzzqoQyI/uam
         ddGMWXLmfseAClklFxQZLFbKb5Vv90M3CYtAeP+c0zEbBDpjC92k0AN6T4/5KYqQwQdL
         A2z2eGZ+yxbacqaZTWNpKXTuqP65aNxs+VjUmacDudizG12S/5/3NV4WRBbKBIqEa+wk
         O7sw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:mime-version:date:dkim-signature;
        bh=LrC8PMqmgoYq1tMdewJcFduXfqGeN4f8xWTu+1cWz7M=;
        fh=liE5Qn9kx13axrzmUQGUukBlDTaEieXMXNeZapzLzZU=;
        b=yJW9gCer91FuzcwH5gaZW28lF0ttQXncxwVsXjENanCS8JieFjuKWJuj0ej8ZhKncN
         gwKnSEqNefL+4smUL3oC39Yy2aDPWNdiQ94sZ47iY7HV0NLY4XkrgbZWJl1e1+3nRSbq
         CuCFXdQtfRpNkgNmxvdI33umm4jeE4XtChE6lI1O0tcKCIlHGICEBqqwq5CV2BNbmTHl
         USpFELqKp7ATlogwxgA1VjFUrnm+FBIkxVLhdjiBmf/BGo7gv6bJCCqbsdJMsgdi9YZ5
         97/EPkXFJkyV9oYOMkewzNfJtZJPYeuMNNr3+4Ojy9eUs9oIpFEAx3VxNQfXBx5R/5m8
         SXKQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=3NSEryoe;
       spf=pass (google.com: domain of 38ciwzgukcyikr1kxmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=38ciwZgUKCYIkr1kxmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-yw1-x1149.google.com (mail-yw1-x1149.google.com. [2607:f8b0:4864:20::1149])
        by gmr-mx.google.com with ESMTPS id af79cd13be357-7a34f5fb7efsi24566585a.0.2024.08.05.05.43.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 05 Aug 2024 05:43:30 -0700 (PDT)
Received-SPF: pass (google.com: domain of 38ciwzgukcyikr1kxmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) client-ip=2607:f8b0:4864:20::1149;
Received: by mail-yw1-x1149.google.com with SMTP id 00721157ae682-650b621f4cdso209299677b3.1
        for <kasan-dev@googlegroups.com>; Mon, 05 Aug 2024 05:43:30 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUZWuYK4q+Dam6Os4+fOAeMYGhWKC0GiOuTRieqdWSxS0tjZ+WJd4HzFnJCCmqaQ0VzbHGSeJwaMB17khFeUqH40N0BahOMlAUSEA==
X-Received: from elver.muc.corp.google.com ([2a00:79e0:9c:201:575f:bb7d:b516:3c23])
 (user=elver job=sendgmr) by 2002:a05:6902:100c:b0:dfa:8ed1:8f1b with SMTP id
 3f1490d57ef6-e0bde22affamr334185276.1.1722861809962; Mon, 05 Aug 2024
 05:43:29 -0700 (PDT)
Date: Mon,  5 Aug 2024 14:39:39 +0200
Mime-Version: 1.0
X-Mailer: git-send-email 2.46.0.rc2.264.g509ed76dc8-goog
Message-ID: <20240805124203.2692278-1-elver@google.com>
Subject: [PATCH] kfence: introduce burst mode
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, Andrew Morton <akpm@linux-foundation.org>
Cc: Andrey Konovalov <andreyknvl@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Jann Horn <jannh@google.com>, kasan-dev@googlegroups.com, 
	linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org, linux-mm@kvack.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=3NSEryoe;       spf=pass
 (google.com: domain of 38ciwzgukcyikr1kxmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=38ciwZgUKCYIkr1kxmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--elver.bounces.google.com;
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

Introduce burst mode, which can be configured with kfence.burst=$count,
where the burst count denotes the additional successive slab allocations
to be allocated through KFENCE for each sample interval.

The idea is that this can give developers an additional knob to make
KFENCE more aggressive when debugging specific issues of systems where
either rebooting or recompiling the kernel with KASAN is not possible.

Experiment: To assess the effectiveness of the new option, we randomly
picked a recent out-of-bounds [1] and use-after-free bug [2], each with
a reproducer provided by syzbot, that initially detected these bugs with
KASAN. We then tried to reproduce the bugs with KFENCE below.

[1] Fixed by: 7c55b78818cf ("jfs: xattr: fix buffer overflow for invalid xattr")
    https://syzkaller.appspot.com/bug?id=9d1b59d4718239da6f6069d3891863c25f9f24a2
[2] Fixed by: f8ad00f3fb2a ("l2tp: fix possible UAF when cleaning up tunnels")
    https://syzkaller.appspot.com/bug?id=4f34adc84f4a3b080187c390eeef60611fd450e1

The following KFENCE configs were compared. A pool size of 1023 objects
was used for all configurations.

	Baseline
		kfence.sample_interval=100
		kfence.skip_covered_thresh=75
		kfence.burst=0

	Aggressive
		kfence.sample_interval=1
		kfence.skip_covered_thresh=10
		kfence.burst=0

	AggressiveBurst
		kfence.sample_interval=1
		kfence.skip_covered_thresh=10
		kfence.burst=1000

Each reproducer was run 10 times (after a fresh reboot), with the
following detection counts for each KFENCE config:

                    | Detection Count out of 10 |
                    |    OOB [1]  |    UAF [2]  |
  ------------------+-------------+-------------+
  Default           |     0/10    |     0/10    |
  Aggressive        |     0/10    |     0/10    |
  AggressiveBurst   |     8/10    |     8/10    |

With the Default and even the Aggressive configs the results are
unsurprising, given KFENCE has not been designed for deterministic bug
detection of small test cases.

However, when enabling burst mode with relatively large burst count,
KFENCE can start to detect heap memory-safety bugs even in simpler test
cases with high probability (in the above cases with ~80% probability).

Signed-off-by: Marco Elver <elver@google.com>
---
 Documentation/dev-tools/kfence.rst |  7 +++++++
 include/linux/kfence.h             |  2 +-
 mm/kfence/core.c                   | 14 ++++++++++----
 3 files changed, 18 insertions(+), 5 deletions(-)

diff --git a/Documentation/dev-tools/kfence.rst b/Documentation/dev-tools/kfence.rst
index 936f6aaa75c8..541899353865 100644
--- a/Documentation/dev-tools/kfence.rst
+++ b/Documentation/dev-tools/kfence.rst
@@ -53,6 +53,13 @@ configurable via the Kconfig option ``CONFIG_KFENCE_DEFERRABLE``.
    The KUnit test suite is very likely to fail when using a deferrable timer
    since it currently causes very unpredictable sample intervals.
 
+By default KFENCE will only sample 1 heap allocation within each sample
+interval. *Burst mode* allows to sample successive heap allocations, where the
+kernel boot parameter ``kfence.burst`` can be set to a non-zero value which
+denotes the *additional* successive allocations within a sample interval;
+setting ``kfence.burst=N`` means that ``1 + N`` successive allocations are
+attempted through KFENCE for each sample interval.
+
 The KFENCE memory pool is of fixed size, and if the pool is exhausted, no
 further KFENCE allocations occur. With ``CONFIG_KFENCE_NUM_OBJECTS`` (default
 255), the number of available guarded objects can be controlled. Each object
diff --git a/include/linux/kfence.h b/include/linux/kfence.h
index 88100cc9caba..0ad1ddbb8b99 100644
--- a/include/linux/kfence.h
+++ b/include/linux/kfence.h
@@ -124,7 +124,7 @@ static __always_inline void *kfence_alloc(struct kmem_cache *s, size_t size, gfp
 	if (!static_branch_likely(&kfence_allocation_key))
 		return NULL;
 #endif
-	if (likely(atomic_read(&kfence_allocation_gate)))
+	if (likely(atomic_read(&kfence_allocation_gate) > 0))
 		return NULL;
 	return __kfence_alloc(s, size, flags);
 }
diff --git a/mm/kfence/core.c b/mm/kfence/core.c
index c5cb54fc696d..c3ef7eb8d4dc 100644
--- a/mm/kfence/core.c
+++ b/mm/kfence/core.c
@@ -99,6 +99,10 @@ module_param_cb(sample_interval, &sample_interval_param_ops, &kfence_sample_inte
 static unsigned long kfence_skip_covered_thresh __read_mostly = 75;
 module_param_named(skip_covered_thresh, kfence_skip_covered_thresh, ulong, 0644);
 
+/* Allocation burst count: number of excess KFENCE allocations per sample. */
+static unsigned int kfence_burst __read_mostly;
+module_param_named(burst, kfence_burst, uint, 0644);
+
 /* If true, use a deferrable timer. */
 static bool kfence_deferrable __read_mostly = IS_ENABLED(CONFIG_KFENCE_DEFERRABLE);
 module_param_named(deferrable, kfence_deferrable, bool, 0444);
@@ -827,12 +831,12 @@ static void toggle_allocation_gate(struct work_struct *work)
 	if (!READ_ONCE(kfence_enabled))
 		return;
 
-	atomic_set(&kfence_allocation_gate, 0);
+	atomic_set(&kfence_allocation_gate, -kfence_burst);
 #ifdef CONFIG_KFENCE_STATIC_KEYS
 	/* Enable static key, and await allocation to happen. */
 	static_branch_enable(&kfence_allocation_key);
 
-	wait_event_idle(allocation_wait, atomic_read(&kfence_allocation_gate));
+	wait_event_idle(allocation_wait, atomic_read(&kfence_allocation_gate) > 0);
 
 	/* Disable static key and reset timer. */
 	static_branch_disable(&kfence_allocation_key);
@@ -1052,6 +1056,7 @@ void *__kfence_alloc(struct kmem_cache *s, size_t size, gfp_t flags)
 	unsigned long stack_entries[KFENCE_STACK_DEPTH];
 	size_t num_stack_entries;
 	u32 alloc_stack_hash;
+	int allocation_gate;
 
 	/*
 	 * Perform size check before switching kfence_allocation_gate, so that
@@ -1080,14 +1085,15 @@ void *__kfence_alloc(struct kmem_cache *s, size_t size, gfp_t flags)
 	if (s->flags & SLAB_SKIP_KFENCE)
 		return NULL;
 
-	if (atomic_inc_return(&kfence_allocation_gate) > 1)
+	allocation_gate = atomic_inc_return(&kfence_allocation_gate);
+	if (allocation_gate > 1)
 		return NULL;
 #ifdef CONFIG_KFENCE_STATIC_KEYS
 	/*
 	 * waitqueue_active() is fully ordered after the update of
 	 * kfence_allocation_gate per atomic_inc_return().
 	 */
-	if (waitqueue_active(&allocation_wait)) {
+	if (allocation_gate == 1 && waitqueue_active(&allocation_wait)) {
 		/*
 		 * Calling wake_up() here may deadlock when allocations happen
 		 * from within timer code. Use an irq_work to defer it.
-- 
2.46.0.rc2.264.g509ed76dc8-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240805124203.2692278-1-elver%40google.com.
