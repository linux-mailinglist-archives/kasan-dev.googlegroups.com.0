Return-Path: <kasan-dev+bncBCT4XGV33UIBBTMOTC6AMGQESB67ILA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83c.google.com (mail-qt1-x83c.google.com [IPv6:2607:f8b0:4864:20::83c])
	by mail.lfdr.de (Postfix) with ESMTPS id CC170A100E2
	for <lists+kasan-dev@lfdr.de>; Tue, 14 Jan 2025 07:42:22 +0100 (CET)
Received: by mail-qt1-x83c.google.com with SMTP id d75a77b69052e-467944446a0sf78719281cf.1
        for <lists+kasan-dev@lfdr.de>; Mon, 13 Jan 2025 22:42:22 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1736836941; cv=pass;
        d=google.com; s=arc-20240605;
        b=LTqGv9zZhCS14ku1O54+xMKH9bRJW7EMqSWRdE0t3BtaDnY9RFMieNacNwKPTWH3yT
         dJDYOhM503gSBfQFZy9h+wWh6hG3x8LZTrs/2RQAMMSlCcnvKmGmdl6eedgndRLeHDbZ
         aDXP89zfkg0qA2nmxH68lRexyR+OMaJAJP5skU3CN239fPm5aVo9yseLjPJgMbsAsRDi
         sHhuUr3VA8Bfe91/KOTiAnavd98O8vKrNlxf6bPy00ZTjSAA2rKOgWZWe3RLTnnp3z6q
         3y/CbBvv0bT8r675OhI3KWFv9fCDGX5O3CvAyVI+ljPplgCnBh5SZAaGf46uar+WBNzK
         O08g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:message-id:subject:from:to:date
         :mime-version:sender:dkim-signature;
        bh=kLRqf5KnANE2tlqnZ+EN9RXEgTe5zvkxH4I4C3ueSVs=;
        fh=87RKRxz2A86sANyEjwklXfyHyubD1qGurHtUc92FUPM=;
        b=RH/ETgrSyRAxA94LSYVbIJM2ISpKvlNezzgShlolGp8sGkcW7xE1lJ8Xb57QJb6qBB
         fjuV0P6UGlQ3ElAQt69fbgsZ6arDTMPNSxfZJbW9/+Q5BMDg3ABMq20nr3/wxpXRiG+D
         +K7WY0A8dXVhgLlsx+Xf+ODj2g5FFVItY5egpXvzlRyxkcIxT8nThVK6SVO/puUm6GWW
         SNwhIIP/iVu3AjuYKwDMu9rSQ+bqUMhiIrJMolOaCX3Vm3BLVguTmh37mfFZOB8oSJlE
         QtOr3xEqb83PTq921jlsDDtt4q1tf3ODO2arade4OMitUbet10GWo47G9WQO5pZytmyv
         I6/Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b="2AR76Tu/";
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1736836941; x=1737441741; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:message-id:subject:from:to:date:mime-version
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=kLRqf5KnANE2tlqnZ+EN9RXEgTe5zvkxH4I4C3ueSVs=;
        b=MbKI1KAiyICcumf1h/BM8RJvgt2W8UWm/3I3wqTtMTgnXkwAP7zAZPF15HKAMGtTiQ
         xqDaqRTRoiCmEc5S7F1+bgc5LJ7jY/lPa7LRx7+HYKm3+mId8lk5gt5BC2FBq8Lcuo1d
         HT1aZyqVwP4cH7r7Zx0eT0TauqwpBnzl4mOSUxcK1GYx31LpqVcScoaFHvccyK8HunND
         JQJrhMSAiLJ4xEoU+n8Tj7Mxiu4DyhQ6Ud6HK1mGbNFGAqy5PdogdyokhIuYrpoW/icW
         yK4oOGzVNTcZNKR67mRiCsJ4/Qciwv7zVSeH3vBv0AI+7K6gLnN6JZ3+naCrRmsFtwfG
         Dupg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1736836941; x=1737441741;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:message-id
         :subject:from:to:date:x-beenthere:mime-version:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=kLRqf5KnANE2tlqnZ+EN9RXEgTe5zvkxH4I4C3ueSVs=;
        b=MMgd4MafjFBg4sfeM9MKRJDNd6MysOheRaf/j9ifwciwbC0yCzd4+8eM7PiRNlEIaC
         GYsvJMjt1B+G0gwuGEeLBqhrW7d+j1V4ScwSJV34NfE01wpTsPwgUDwK6FKWSH3DbzBw
         FCUIiaSI0qurc7Snvpdvy1bdqGQ8XkaYmnyXrWsHy10QZv64lzNTyk8A3W66hOVsHMHS
         qgZzxiA8q1X7eBahME9KXXaZy1+a0c7pATdvUecd1ysaIDHnE4PB0oe/0jHaYXxAU3Ki
         6iqTSofR2E+GXfKbPbcouX8CA0cev5w+AuYmfd7wX/L0rftwNPibP0ojVqWQhH3IZmXU
         G4qQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXjqBrcwtixQy8Zgj4X2CUL8bS9peFrckoGNjGzkWuDhj5hz6tV0H2U4lupbBcbVbHTaLwH+Q==@lfdr.de
X-Gm-Message-State: AOJu0YzwdDBnWZNPAGgDHkYKDGqVppgrVy/1b7MrqkFO1zNFKWDry22l
	xsCsPYNwp5qmGUpgZNSOlPZZadpIXHI3mQANaRvij/jUcprjAxk6
X-Google-Smtp-Source: AGHT+IFfNfTt7O5p0JGCzLz9dmWBSJo+sM7dN3Ihs5wXy0MBWkD+m9vWQiFGJgYKnsqT4eL84h/WJA==
X-Received: by 2002:a05:622a:2c6:b0:467:83f1:71d2 with SMTP id d75a77b69052e-46c7108ed5fmr355199501cf.45.1736836941508;
        Mon, 13 Jan 2025 22:42:21 -0800 (PST)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:622a:a029:b0:469:63f:ce11 with SMTP id
 d75a77b69052e-46c7aa0b7fdls61208171cf.0.-pod-prod-05-us; Mon, 13 Jan 2025
 22:42:20 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWidh+ZZlLJZDCVmK/HCQx0bm4oELQigo6gFfOlb3gkHotSX/jSFcRZHfVKJSMpc7AjPAWOb87kzS8=@googlegroups.com
X-Received: by 2002:a05:620a:1a03:b0:7b6:d252:b4ef with SMTP id af79cd13be357-7bcd97b04f6mr4149063285a.53.1736836940730;
        Mon, 13 Jan 2025 22:42:20 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1736836940; cv=none;
        d=google.com; s=arc-20240605;
        b=Hnbpo/+w+E1QE3eQ1UREIvXMHuAyDn7HNMb8+ArFDfszn7bVYtXWUuNF+rEWu2Slkc
         0h5Ktiq0ITfqiYPr2JcEUo7HaHU6eUu+FlQ1+FJwHSYkHUBw2kOI/+ROfn/PF8I8LZ9f
         MBmgSx9KS88mjjhmE/1xxh2xw3IqI6T6NlO7N2f9WJwQGTOxd5vBFWrdBrf0ygTldH4C
         GRFDgQ0Dpp1A7zxdwSvSmt5KLM1RGLD9VV1Ka9x6j/MM2Uzt4wiWkvy+3U3DYItL91oe
         8r9XA5MzuFpHeWAfgH1Xhs9HsplpUmsF0cuv+V7eSGTcP/AAkFcL6BBO8l7zjZxY2e5X
         GBzQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=message-id:subject:from:to:date:dkim-signature;
        bh=iSlwjIjQxwJo2CZdeZImWr4VUVfJHavlJw4BkrLMUw0=;
        fh=tpBIT5b+ejHfRAZFMZ0BR/AzrT5gSlhMRnZrC78Ap5I=;
        b=luIDW/lOLvJAd4knn77YyQzxsZ3L+6WZ6mv91PgJGKCrBwhtd/wSAbV1QXwViCZfud
         iJnj/dInpUaickJULY+12YmCHzCUDdoS7gb3goW1n1ktH+KNdPxiBKcfYrEwC5syrvEi
         1IN8Il0Kx4K7iqBdMxxtGjcw0v2HwK/XsF48MJgRfbqb5MmCa7HZ4p3mYHYEoQml6I+D
         StFlBsXKJvjf6FWPKAspGzb/JoobgXn+I7bZTZnoQU3CctXO0jX2NkGBuaZx5oEEe8x9
         sowmtetE7F+qDpVg1tjThu6/JCtA7IPniPAE9gy+lQX2fg6B6q2rFzUOVlq31mu6nISz
         UQdQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b="2AR76Tu/";
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id af79cd13be357-7bce33006cfsi41957685a.6.2025.01.13.22.42.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 13 Jan 2025 22:42:20 -0800 (PST)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id 433A45C5471;
	Tue, 14 Jan 2025 06:41:39 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id B185BC4CEDD;
	Tue, 14 Jan 2025 06:42:19 +0000 (UTC)
Date: Mon, 13 Jan 2025 22:42:19 -0800
To: mm-commits@vger.kernel.org,vschneid@redhat.com,vincenzo.frascino@arm.com,vincent.guittot@linaro.org,vbabka@suse.cz,urezki@gmail.com,tj@kernel.org,tglx@linutronix.de,ryabinin.a.a@gmail.com,rostedt@goodmis.org,roman.gushchin@linux.dev,rientjes@google.com,qiang.zhang1211@gmail.com,penberg@kernel.org,paulmck@kernel.org,neeraj.upadhyay@kernel.org,mingo@redhat.com,mgorman@suse.de,mathieu.desnoyers@efficios.com,lorenzo.stoakes@oracle.com,longman@redhat.com,Liam.Howlett@Oracle.com,kasan-dev@googlegroups.com,juri.lelli@redhat.com,josh@joshtriplett.org,joel@joelfernandes.org,jiangshanlai@gmail.com,jannh@google.com,iamjoonsoo.kim@lge.com,glider@google.com,frederic@kernel.org,elver@google.com,dvyukov@google.com,dietmar.eggemann@arm.com,cl@linux.com,bsegall@google.com,boqun.feng@gmail.com,bigeasy@linutronix.de,andreyknvl@gmail.com,42.hyeyoo@gmail.com,peterz@infradead.org,akpm@linux-foundation.org
From: Andrew Morton <akpm@linux-foundation.org>
Subject: [merged mm-stable] kasan-make-kasan_record_aux_stack_noalloc-the-default-behaviour.patch removed from -mm tree
Message-Id: <20250114064219.B185BC4CEDD@smtp.kernel.org>
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=korg header.b="2AR76Tu/";
       spf=pass (google.com: domain of akpm@linux-foundation.org designates
 139.178.84.217 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
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


The quilt patch titled
     Subject: kasan: make kasan_record_aux_stack_noalloc() the default behaviour
has been removed from the -mm tree.  Its filename was
     kasan-make-kasan_record_aux_stack_noalloc-the-default-behaviour.patch

This patch was dropped because it was merged into the mm-stable branch
of git://git.kernel.org/pub/scm/linux/kernel/git/akpm/mm

------------------------------------------------------
From: Peter Zijlstra <peterz@infradead.org>
Subject: kasan: make kasan_record_aux_stack_noalloc() the default behaviour
Date: Fri, 22 Nov 2024 16:54:51 +0100

kasan_record_aux_stack_noalloc() was introduced to record a stack trace
without allocating memory in the process.  It has been added to callers
which were invoked while a raw_spinlock_t was held.  More and more callers
were identified and changed over time.  Is it a good thing to have this
while functions try their best to do a locklessly setup?  The only
downside of having kasan_record_aux_stack() not allocate any memory is
that we end up without a stacktrace if stackdepot runs out of memory and
at the same stacktrace was not recorded before To quote Marco Elver from
https://lore.kernel.org/all/CANpmjNPmQYJ7pv1N3cuU8cP18u7PP_uoZD8YxwZd4jtbof9nVQ@mail.gmail.com/

| I'd be in favor, it simplifies things. And stack depot should be
| able to replenish its pool sufficiently in the "non-aux" cases
| i.e. regular allocations. Worst case we fail to record some
| aux stacks, but I think that's only really bad if there's a bug
| around one of these allocations. In general the probabilities
| of this being a regression are extremely small [...]

Make the kasan_record_aux_stack_noalloc() behaviour default as
kasan_record_aux_stack().

[bigeasy@linutronix.de: dressed the diff as patch]
Link: https://lkml.kernel.org/r/20241122155451.Mb2pmeyJ@linutronix.de
Fixes: 7cb3007ce2da ("kasan: generic: introduce kasan_record_aux_stack_noalloc()")
Signed-off-by: Peter Zijlstra (Intel) <peterz@infradead.org>
Signed-off-by: Sebastian Andrzej Siewior <bigeasy@linutronix.de>
Reported-by: syzbot+39f85d612b7c20d8db48@syzkaller.appspotmail.com
Closes: https://lore.kernel.org/all/67275485.050a0220.3c8d68.0a37.GAE@google.com
Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>
Reviewed-by: Marco Elver <elver@google.com>
Reviewed-by: Waiman Long <longman@redhat.com>
Cc: Alexander Potapenko <glider@google.com>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>
Cc: Ben Segall <bsegall@google.com>
Cc: Boqun Feng <boqun.feng@gmail.com>
Cc: Christoph Lameter <cl@linux.com>
Cc: David Rientjes <rientjes@google.com>
Cc: Dietmar Eggemann <dietmar.eggemann@arm.com>
Cc: Dmitry Vyukov <dvyukov@google.com>
Cc: Frederic Weisbecker <frederic@kernel.org>
Cc: Hyeonggon Yoo <42.hyeyoo@gmail.com>
Cc: Ingo Molnar <mingo@redhat.com>
Cc: Jann Horn <jannh@google.com>
Cc: Joel Fernandes (Google) <joel@joelfernandes.org>
Cc: Joonsoo Kim <iamjoonsoo.kim@lge.com>
Cc: Josh Triplett <josh@joshtriplett.org>
Cc: Juri Lelli <juri.lelli@redhat.com>
Cc: <kasan-dev@googlegroups.com>
Cc: Lai Jiangshan <jiangshanlai@gmail.com>
Cc: Liam R. Howlett <Liam.Howlett@Oracle.com>
Cc: Lorenzo Stoakes <lorenzo.stoakes@oracle.com>
Cc: Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
Cc: Mel Gorman <mgorman@suse.de>
Cc: Neeraj Upadhyay <neeraj.upadhyay@kernel.org>
Cc: Paul E. McKenney <paulmck@kernel.org>
Cc: Pekka Enberg <penberg@kernel.org>
Cc: Roman Gushchin <roman.gushchin@linux.dev>
Cc: Steven Rostedt <rostedt@goodmis.org>
Cc: syzkaller-bugs@googlegroups.com
Cc: Tejun Heo <tj@kernel.org>
Cc: Thomas Gleixner <tglx@linutronix.de>
Cc: Uladzislau Rezki (Sony) <urezki@gmail.com>
Cc: Valentin Schneider <vschneid@redhat.com>
Cc: Vincent Guittot <vincent.guittot@linaro.org>
Cc: Vincenzo Frascino <vincenzo.frascino@arm.com>
Cc: Vlastimil Babka <vbabka@suse.cz>
Cc: Zqiang <qiang.zhang1211@gmail.com>
Signed-off-by: Andrew Morton <akpm@linux-foundation.org>
---

 include/linux/kasan.h     |    2 --
 include/linux/task_work.h |    3 ---
 kernel/irq_work.c         |    2 +-
 kernel/rcu/tiny.c         |    2 +-
 kernel/rcu/tree.c         |    4 ++--
 kernel/sched/core.c       |    2 +-
 kernel/task_work.c        |   14 +-------------
 kernel/workqueue.c        |    2 +-
 mm/kasan/generic.c        |   18 ++++++------------
 mm/slub.c                 |    2 +-
 10 files changed, 14 insertions(+), 37 deletions(-)

--- a/include/linux/kasan.h~kasan-make-kasan_record_aux_stack_noalloc-the-default-behaviour
+++ a/include/linux/kasan.h
@@ -491,7 +491,6 @@ void kasan_cache_create(struct kmem_cach
 void kasan_cache_shrink(struct kmem_cache *cache);
 void kasan_cache_shutdown(struct kmem_cache *cache);
 void kasan_record_aux_stack(void *ptr);
-void kasan_record_aux_stack_noalloc(void *ptr);
 
 #else /* CONFIG_KASAN_GENERIC */
 
@@ -509,7 +508,6 @@ static inline void kasan_cache_create(st
 static inline void kasan_cache_shrink(struct kmem_cache *cache) {}
 static inline void kasan_cache_shutdown(struct kmem_cache *cache) {}
 static inline void kasan_record_aux_stack(void *ptr) {}
-static inline void kasan_record_aux_stack_noalloc(void *ptr) {}
 
 #endif /* CONFIG_KASAN_GENERIC */
 
--- a/include/linux/task_work.h~kasan-make-kasan_record_aux_stack_noalloc-the-default-behaviour
+++ a/include/linux/task_work.h
@@ -19,9 +19,6 @@ enum task_work_notify_mode {
 	TWA_SIGNAL,
 	TWA_SIGNAL_NO_IPI,
 	TWA_NMI_CURRENT,
-
-	TWA_FLAGS = 0xff00,
-	TWAF_NO_ALLOC = 0x0100,
 };
 
 static inline bool task_work_pending(struct task_struct *task)
--- a/kernel/irq_work.c~kasan-make-kasan_record_aux_stack_noalloc-the-default-behaviour
+++ a/kernel/irq_work.c
@@ -147,7 +147,7 @@ bool irq_work_queue_on(struct irq_work *
 	if (!irq_work_claim(work))
 		return false;
 
-	kasan_record_aux_stack_noalloc(work);
+	kasan_record_aux_stack(work);
 
 	preempt_disable();
 	if (cpu != smp_processor_id()) {
--- a/kernel/rcu/tiny.c~kasan-make-kasan_record_aux_stack_noalloc-the-default-behaviour
+++ a/kernel/rcu/tiny.c
@@ -250,7 +250,7 @@ EXPORT_SYMBOL_GPL(poll_state_synchronize
 void kvfree_call_rcu(struct rcu_head *head, void *ptr)
 {
 	if (head)
-		kasan_record_aux_stack_noalloc(ptr);
+		kasan_record_aux_stack(ptr);
 
 	__kvfree_call_rcu(head, ptr);
 }
--- a/kernel/rcu/tree.c~kasan-make-kasan_record_aux_stack_noalloc-the-default-behaviour
+++ a/kernel/rcu/tree.c
@@ -3083,7 +3083,7 @@ __call_rcu_common(struct rcu_head *head,
 	}
 	head->func = func;
 	head->next = NULL;
-	kasan_record_aux_stack_noalloc(head);
+	kasan_record_aux_stack(head);
 	local_irq_save(flags);
 	rdp = this_cpu_ptr(&rcu_data);
 	lazy = lazy_in && !rcu_async_should_hurry();
@@ -3817,7 +3817,7 @@ void kvfree_call_rcu(struct rcu_head *he
 		return;
 	}
 
-	kasan_record_aux_stack_noalloc(ptr);
+	kasan_record_aux_stack(ptr);
 	success = add_ptr_to_bulk_krc_lock(&krcp, &flags, ptr, !head);
 	if (!success) {
 		run_page_cache_worker(krcp);
--- a/kernel/sched/core.c~kasan-make-kasan_record_aux_stack_noalloc-the-default-behaviour
+++ a/kernel/sched/core.c
@@ -10590,7 +10590,7 @@ void task_tick_mm_cid(struct rq *rq, str
 		return;
 
 	/* No page allocation under rq lock */
-	task_work_add(curr, work, TWA_RESUME | TWAF_NO_ALLOC);
+	task_work_add(curr, work, TWA_RESUME);
 }
 
 void sched_mm_cid_exit_signals(struct task_struct *t)
--- a/kernel/task_work.c~kasan-make-kasan_record_aux_stack_noalloc-the-default-behaviour
+++ a/kernel/task_work.c
@@ -55,26 +55,14 @@ int task_work_add(struct task_struct *ta
 		  enum task_work_notify_mode notify)
 {
 	struct callback_head *head;
-	int flags = notify & TWA_FLAGS;
 
-	notify &= ~TWA_FLAGS;
 	if (notify == TWA_NMI_CURRENT) {
 		if (WARN_ON_ONCE(task != current))
 			return -EINVAL;
 		if (!IS_ENABLED(CONFIG_IRQ_WORK))
 			return -EINVAL;
 	} else {
-		/*
-		 * Record the work call stack in order to print it in KASAN
-		 * reports.
-		 *
-		 * Note that stack allocation can fail if TWAF_NO_ALLOC flag
-		 * is set and new page is needed to expand the stack buffer.
-		 */
-		if (flags & TWAF_NO_ALLOC)
-			kasan_record_aux_stack_noalloc(work);
-		else
-			kasan_record_aux_stack(work);
+		kasan_record_aux_stack(work);
 	}
 
 	head = READ_ONCE(task->task_works);
--- a/kernel/workqueue.c~kasan-make-kasan_record_aux_stack_noalloc-the-default-behaviour
+++ a/kernel/workqueue.c
@@ -2180,7 +2180,7 @@ static void insert_work(struct pool_work
 	debug_work_activate(work);
 
 	/* record the work call stack in order to print it in KASAN reports */
-	kasan_record_aux_stack_noalloc(work);
+	kasan_record_aux_stack(work);
 
 	/* we own @work, set data and link */
 	set_work_pwq(work, pwq, extra_flags);
--- a/mm/kasan/generic.c~kasan-make-kasan_record_aux_stack_noalloc-the-default-behaviour
+++ a/mm/kasan/generic.c
@@ -524,7 +524,11 @@ size_t kasan_metadata_size(struct kmem_c
 			sizeof(struct kasan_free_meta) : 0);
 }
 
-static void __kasan_record_aux_stack(void *addr, depot_flags_t depot_flags)
+/*
+ * This function avoids dynamic memory allocations and thus can be called from
+ * contexts that do not allow allocating memory.
+ */
+void kasan_record_aux_stack(void *addr)
 {
 	struct slab *slab = kasan_addr_to_slab(addr);
 	struct kmem_cache *cache;
@@ -541,17 +545,7 @@ static void __kasan_record_aux_stack(voi
 		return;
 
 	alloc_meta->aux_stack[1] = alloc_meta->aux_stack[0];
-	alloc_meta->aux_stack[0] = kasan_save_stack(0, depot_flags);
-}
-
-void kasan_record_aux_stack(void *addr)
-{
-	return __kasan_record_aux_stack(addr, STACK_DEPOT_FLAG_CAN_ALLOC);
-}
-
-void kasan_record_aux_stack_noalloc(void *addr)
-{
-	return __kasan_record_aux_stack(addr, 0);
+	alloc_meta->aux_stack[0] = kasan_save_stack(0, 0);
 }
 
 void kasan_save_alloc_info(struct kmem_cache *cache, void *object, gfp_t flags)
--- a/mm/slub.c~kasan-make-kasan_record_aux_stack_noalloc-the-default-behaviour
+++ a/mm/slub.c
@@ -2311,7 +2311,7 @@ bool slab_free_hook(struct kmem_cache *s
 			 * We have to do this manually because the rcu_head is
 			 * not located inside the object.
 			 */
-			kasan_record_aux_stack_noalloc(x);
+			kasan_record_aux_stack(x);
 
 			delayed_free->object = x;
 			call_rcu(&delayed_free->head, slab_free_after_rcu_debug);
_

Patches currently in -mm which might be from peterz@infradead.org are

x86-disable-execmem_rox-support.patch

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250114064219.B185BC4CEDD%40smtp.kernel.org.
