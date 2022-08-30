Return-Path: <kasan-dev+bncBC7OD3FKWUERBI4MXKMAMGQEFBLBRVI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x739.google.com (mail-qk1-x739.google.com [IPv6:2607:f8b0:4864:20::739])
	by mail.lfdr.de (Postfix) with ESMTPS id 06F0B5A6FA8
	for <lists+kasan-dev@lfdr.de>; Tue, 30 Aug 2022 23:50:29 +0200 (CEST)
Received: by mail-qk1-x739.google.com with SMTP id h8-20020a05620a284800b006b5c98f09fbsf10411923qkp.21
        for <lists+kasan-dev@lfdr.de>; Tue, 30 Aug 2022 14:50:29 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1661896228; cv=pass;
        d=google.com; s=arc-20160816;
        b=ZVTbikXBFY0wJ2DJcqhWJU/UttZq2NEzjHRyj0WrnsUKgr9SXC3Vf+C533P7BGEroH
         2Y8+XVmS1fjVnZSeAZGR/iyz2Zb99LXXKUKV/iwNbAzLz64CWmlmYDWySGIpQWA48C0D
         tSL6D0PtyvisZfEdpQT4OSLg7sLxCUp/GYSSIyJA2JS46LA+Z42gc13jZ8ek1XrnfjKn
         AzvKyfXMuvoyGw2Pgfa76co/5ExciaDmKU+YIjIvUTEGXdOGNZmVqaIMi2SG3bZehwin
         FrIOrFy+Gtxn9ssn3u4n5cj7wRuMWj3utqX1RDDS2+9p6G+yIVjpXizpWeLtf4s8liX6
         /VuA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=CyuyWIpTyxxNa8BqnCc5AhDLW1E1Gm8X1eei1qOwcpI=;
        b=TNuDSx/0skjwNMJFTcscMFcfgg4sbssgE87ncs1x/BTsTyk8iecQNr2Ww7ddgBiwNu
         zCor3YK+06qWqTdR/BcNLcmkPrTFIN4544bznDRecgJMRwjMcuFfDuPQ0DXqZf4gAbW4
         QBMswXPv7aVx5b7oAsW7h7yHNbycl0DDDIBws0mQwAgtS8JihrUuMFk64WvM4oEHDFiA
         Mo1uoz6sGtVPk2RT6K1e4depN8YDlmD9PI+CirBsu5io+JSUT84GK3sg4fQGj3DFm3MR
         HHrJdDTfU1UwlZypvcydf/pQ9HGuSnVbsiKIyIlDfoBkAJTRe08WgWSYyoFau9ugyAzK
         786g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=Ij75nFrU;
       spf=pass (google.com: domain of 3i4yoywykcyg463qzns00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=3I4YOYwYKCYg463qzns00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc;
        bh=CyuyWIpTyxxNa8BqnCc5AhDLW1E1Gm8X1eei1qOwcpI=;
        b=KTsQCKZ3oH9WAsQISX+ByaCxrdLMB3/OcBDlvl0m5GE/8/IEBQ15lpUZZvQEscFlOn
         gMUeThoqzleeNGi8/hauxkGb2953BOZmCvKgFE0OPL0EaohTGs0sNHq5jKyrReU2HWZs
         3q1AD8bIaxtgFE7zoveRJvD+KO9bA360okxnzT/4Ewf2gJwe7chTXDerPfWAfS9cgR30
         LUYvofLICDezxXa3L10oEl375Ic0HOhTF/vI0IajJ5KmIw/RPEw1fhCIP6LJCF+tNeOB
         KJFar00b6srIhmhdyeMc7VT8jLjzvpk3UI4RqoBJ+LGWQeG8c1+V7ruIu5dmShUPH/ul
         Q1qA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-gm-message-state:from:to:cc;
        bh=CyuyWIpTyxxNa8BqnCc5AhDLW1E1Gm8X1eei1qOwcpI=;
        b=aTK2gKUDdqMIfDbBIAZ6lJTImRaYTbaMK2m1slSEJOSfAQ0uzM3YZoF8i+emA21tup
         nJH6AJtrmDuoIIhQJ5IRswo8/pmqvT8Yuhh3TohKfO17JQiyBE4aFSVqTm3kuSUThPGj
         l5aUQQq3nVQ4sLwydzyH6SH8IxMmj6u7YqcNME0AQ7olKDajXvLnz7X7X1Vyp5yv76ya
         wv8O+HgcfKnoUZlfl/JQcXrNhM8eq058KReUFXQMO8TcUwO/7ECca0IYoUHwKJRulDgg
         V7LDqvaJpI8fnKBtVeeXcJ0FmBwuX7gMvfg/bK3XsHxsDe9VbtNKT5dBWKR4flJyWpHy
         RH1Q==
X-Gm-Message-State: ACgBeo3afE8bM3hpsRu2P98xIX3rFIdEc/TM5PV4TYp9ZztOHzYaq+HH
	fhWnABhK0+xaYKpu3JEOb7M=
X-Google-Smtp-Source: AA6agR4ozl4Y6Zv7wsJI+KwTk8rEnqeygpRiEwAaGezHluNGMnckSU6YSv9wqcxrIdg4BsHoYuhPIA==
X-Received: by 2002:a05:622a:1703:b0:344:6780:8664 with SMTP id h3-20020a05622a170300b0034467808664mr16514405qtk.69.1661896227937;
        Tue, 30 Aug 2022 14:50:27 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0c:a947:0:b0:498:f330:9b60 with SMTP id z7-20020a0ca947000000b00498f3309b60ls5376953qva.5.-pod-prod-gmail;
 Tue, 30 Aug 2022 14:50:27 -0700 (PDT)
X-Received: by 2002:a05:6214:cce:b0:499:606:1526 with SMTP id 14-20020a0562140cce00b0049906061526mr8666115qvx.64.1661896227537;
        Tue, 30 Aug 2022 14:50:27 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1661896227; cv=none;
        d=google.com; s=arc-20160816;
        b=KVMh6FyFLY2g08lx1HeuMiC+O+7bDbXIfojQQTU58w9SUCl3gA/89/9aGG3Voamupa
         /5R1F7CRE324MlLaIswJeWsWaHvXas7cp2wdY2bTCAjSDV/uvBWUSqrVgJMacmgIprXI
         a0hugTU1Vfz/MpG8k/ucixhM0lCnEATLQwSFR/vYWHlhi8w5863kzpy9XPCGK2lF4VFf
         G2Zlm6XEWoOwjz0/nWPuOAkPxZLaG0ORmT0ad4nOf2pt9ia8SLKKB6Ra7I94F+W/nxtm
         tr+VR78FnXdvUy9z13EHaM8WYnZAbdb5wmT8k8yl2hrik1Q3B3FR7e92anCGXJIIe1k7
         cpMA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=PJDqdE16VQFkhBtAZQdE7ryguEFDkMx7mMptHwdJxIQ=;
        b=iQdB/mHPb468kbKqpW6TwDJErLlMo5u9f2D58eukx6oAGeGaORItVU5odFg86DpwpQ
         ngnc+hmZPUVlGqXkay1ktRaKheLzaIu/1npJqMfQsVXb8yjjQKs2RGJhcKguvQBMMsgY
         tNWX61NwXmwiv3TVzBaTff8UI1dw5x1GMenB9XMjh7PQNnDfiffA/8dPERHfig8huX1q
         f3sAREMMkJiBzOjuV20TqRca4ccsA0PRNppOmmD1aNBZt94SwSmrxarQBmurUoQBjZm1
         SABRvnwD+LM0xZMX5F2XJuoAp1SUHMFQbl+dtht0AU0M4ccTWmSQUDZEYyh/L4NOk6mv
         H8lA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=Ij75nFrU;
       spf=pass (google.com: domain of 3i4yoywykcyg463qzns00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=3I4YOYwYKCYg463qzns00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x114a.google.com (mail-yw1-x114a.google.com. [2607:f8b0:4864:20::114a])
        by gmr-mx.google.com with ESMTPS id d21-20020ac84e35000000b00341a027f09fsi592982qtw.4.2022.08.30.14.50.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 30 Aug 2022 14:50:27 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3i4yoywykcyg463qzns00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) client-ip=2607:f8b0:4864:20::114a;
Received: by mail-yw1-x114a.google.com with SMTP id 00721157ae682-31f5960500bso188570157b3.14
        for <kasan-dev@googlegroups.com>; Tue, 30 Aug 2022 14:50:27 -0700 (PDT)
X-Received: from surenb-desktop.mtv.corp.google.com ([2620:15c:211:200:a005:55b3:6c26:b3e4])
 (user=surenb job=sendgmr) by 2002:a81:54c4:0:b0:329:d0e1:cfcf with SMTP id
 i187-20020a8154c4000000b00329d0e1cfcfmr15741208ywb.451.1661896227243; Tue, 30
 Aug 2022 14:50:27 -0700 (PDT)
Date: Tue, 30 Aug 2022 14:49:13 -0700
In-Reply-To: <20220830214919.53220-1-surenb@google.com>
Mime-Version: 1.0
References: <20220830214919.53220-1-surenb@google.com>
X-Mailer: git-send-email 2.37.2.672.g94769d06f0-goog
Message-ID: <20220830214919.53220-25-surenb@google.com>
Subject: [RFC PATCH 24/30] wait: Clean up waitqueue_entry initialization
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
	linux-kernel@vger.kernel.org, Ingo Molnar <mingo@redhat.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: surenb@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=Ij75nFrU;       spf=pass
 (google.com: domain of 3i4yoywykcyg463qzns00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--surenb.bounces.google.com
 designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=3I4YOYwYKCYg463qzns00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--surenb.bounces.google.com;
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

Cleanup for code tagging latency tracking:

Add an initializer, WAIT_FUNC_INITIALIZER(), to be used by initializers
for structs that include wait_queue_entries.

Also, change init_wait(), init_wait_entry etc.  to be a wrapper around
the new __init_waitqueue_entry(); more de-duplication prep work.

Signed-off-by: Kent Overstreet <kent.overstreet@linux.dev>
Cc: Ingo Molnar <mingo@redhat.com>
Cc: Peter Zijlstra <peterz@infradead.org>
---
 include/linux/sbitmap.h  |  6 +----
 include/linux/wait.h     | 52 +++++++++++++++++++---------------------
 include/linux/wait_bit.h |  7 +-----
 kernel/sched/wait.c      |  9 -------
 4 files changed, 27 insertions(+), 47 deletions(-)

diff --git a/include/linux/sbitmap.h b/include/linux/sbitmap.h
index 8f5a86e210b9..f696c29d9ab3 100644
--- a/include/linux/sbitmap.h
+++ b/include/linux/sbitmap.h
@@ -596,11 +596,7 @@ struct sbq_wait {
 #define DEFINE_SBQ_WAIT(name)							\
 	struct sbq_wait name = {						\
 		.sbq = NULL,							\
-		.wait = {							\
-			.private	= current,				\
-			.func		= autoremove_wake_function,		\
-			.entry		= LIST_HEAD_INIT((name).wait.entry),	\
-		}								\
+		.wait = WAIT_FUNC_INITIALIZER((name).wait, autoremove_wake_function),\
 	}
 
 /*
diff --git a/include/linux/wait.h b/include/linux/wait.h
index 58cfbf81447c..91ced6a118bc 100644
--- a/include/linux/wait.h
+++ b/include/linux/wait.h
@@ -79,21 +79,38 @@ extern void __init_waitqueue_head(struct wait_queue_head *wq_head, const char *n
 # define DECLARE_WAIT_QUEUE_HEAD_ONSTACK(name) DECLARE_WAIT_QUEUE_HEAD(name)
 #endif
 
-static inline void init_waitqueue_entry(struct wait_queue_entry *wq_entry, struct task_struct *p)
-{
-	wq_entry->flags		= 0;
-	wq_entry->private	= p;
-	wq_entry->func		= default_wake_function;
+#define WAIT_FUNC_INITIALIZER(name, function) {					\
+	.private	= current,						\
+	.func		= function,						\
+	.entry		= LIST_HEAD_INIT((name).entry),				\
 }
 
+#define DEFINE_WAIT_FUNC(name, function)					\
+	struct wait_queue_entry name = WAIT_FUNC_INITIALIZER(name, function)
+
+#define DEFINE_WAIT(name) DEFINE_WAIT_FUNC(name, autoremove_wake_function)
+
 static inline void
-init_waitqueue_func_entry(struct wait_queue_entry *wq_entry, wait_queue_func_t func)
+__init_waitqueue_entry(struct wait_queue_entry *wq_entry, unsigned int flags,
+		       void *private, wait_queue_func_t func)
 {
-	wq_entry->flags		= 0;
-	wq_entry->private	= NULL;
+	wq_entry->flags		= flags;
+	wq_entry->private	= private;
 	wq_entry->func		= func;
+	INIT_LIST_HEAD(&wq_entry->entry);
 }
 
+#define init_waitqueue_func_entry(_wq_entry, _func)			\
+	__init_waitqueue_entry(_wq_entry, 0, NULL, _func)
+
+#define init_waitqueue_entry(_wq_entry, _task)				\
+	__init_waitqueue_entry(_wq_entry, 0, _task, default_wake_function)
+
+#define init_wait_entry(_wq_entry, _flags)				\
+	__init_waitqueue_entry(_wq_entry, _flags, current, autoremove_wake_function)
+
+#define init_wait(wait)		init_wait_entry(wait, 0)
+
 /**
  * waitqueue_active -- locklessly test for waiters on the queue
  * @wq_head: the waitqueue to test for waiters
@@ -283,8 +300,6 @@ static inline void wake_up_pollfree(struct wait_queue_head *wq_head)
 	(!__builtin_constant_p(state) ||					\
 		state == TASK_INTERRUPTIBLE || state == TASK_KILLABLE)		\
 
-extern void init_wait_entry(struct wait_queue_entry *wq_entry, int flags);
-
 /*
  * The below macro ___wait_event() has an explicit shadow of the __ret
  * variable when used from the wait_event_*() macros.
@@ -1170,23 +1185,6 @@ long wait_woken(struct wait_queue_entry *wq_entry, unsigned mode, long timeout);
 int woken_wake_function(struct wait_queue_entry *wq_entry, unsigned mode, int sync, void *key);
 int autoremove_wake_function(struct wait_queue_entry *wq_entry, unsigned mode, int sync, void *key);
 
-#define DEFINE_WAIT_FUNC(name, function)					\
-	struct wait_queue_entry name = {					\
-		.private	= current,					\
-		.func		= function,					\
-		.entry		= LIST_HEAD_INIT((name).entry),			\
-	}
-
-#define DEFINE_WAIT(name) DEFINE_WAIT_FUNC(name, autoremove_wake_function)
-
-#define init_wait(wait)								\
-	do {									\
-		(wait)->private = current;					\
-		(wait)->func = autoremove_wake_function;			\
-		INIT_LIST_HEAD(&(wait)->entry);					\
-		(wait)->flags = 0;						\
-	} while (0)
-
 typedef int (*task_call_f)(struct task_struct *p, void *arg);
 extern int task_call_func(struct task_struct *p, task_call_f func, void *arg);
 
diff --git a/include/linux/wait_bit.h b/include/linux/wait_bit.h
index 7725b7579b78..267ca0fe9fd9 100644
--- a/include/linux/wait_bit.h
+++ b/include/linux/wait_bit.h
@@ -38,12 +38,7 @@ int wake_bit_function(struct wait_queue_entry *wq_entry, unsigned mode, int sync
 #define DEFINE_WAIT_BIT(name, word, bit)					\
 	struct wait_bit_queue_entry name = {					\
 		.key = __WAIT_BIT_KEY_INITIALIZER(word, bit),			\
-		.wq_entry = {							\
-			.private	= current,				\
-			.func		= wake_bit_function,			\
-			.entry		=					\
-				LIST_HEAD_INIT((name).wq_entry.entry),		\
-		},								\
+		.wq_entry = WAIT_FUNC_INITIALIZER((name).wq_entry, wake_bit_function),\
 	}
 
 extern int bit_wait(struct wait_bit_key *key, int mode);
diff --git a/kernel/sched/wait.c b/kernel/sched/wait.c
index 9860bb9a847c..b9922346077d 100644
--- a/kernel/sched/wait.c
+++ b/kernel/sched/wait.c
@@ -289,15 +289,6 @@ prepare_to_wait_exclusive(struct wait_queue_head *wq_head, struct wait_queue_ent
 }
 EXPORT_SYMBOL(prepare_to_wait_exclusive);
 
-void init_wait_entry(struct wait_queue_entry *wq_entry, int flags)
-{
-	wq_entry->flags = flags;
-	wq_entry->private = current;
-	wq_entry->func = autoremove_wake_function;
-	INIT_LIST_HEAD(&wq_entry->entry);
-}
-EXPORT_SYMBOL(init_wait_entry);
-
 long prepare_to_wait_event(struct wait_queue_head *wq_head, struct wait_queue_entry *wq_entry, int state)
 {
 	unsigned long flags;
-- 
2.37.2.672.g94769d06f0-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220830214919.53220-25-surenb%40google.com.
