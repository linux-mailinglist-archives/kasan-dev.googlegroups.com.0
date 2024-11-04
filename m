Return-Path: <kasan-dev+bncBDBK55H2UQKRBTXHUK4QMGQEXCPIRYY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x438.google.com (mail-wr1-x438.google.com [IPv6:2a00:1450:4864:20::438])
	by mail.lfdr.de (Postfix) with ESMTPS id 136249BB3BA
	for <lists+kasan-dev@lfdr.de>; Mon,  4 Nov 2024 12:45:20 +0100 (CET)
Received: by mail-wr1-x438.google.com with SMTP id ffacd0b85a97d-381d0582ad3sf1410139f8f.0
        for <lists+kasan-dev@lfdr.de>; Mon, 04 Nov 2024 03:45:20 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1730720719; cv=pass;
        d=google.com; s=arc-20240605;
        b=NA7yOOz5+HPFggN/an8Eg5kWwaQaMIDH4xta1XuS19+LSsx9h66S8Ywr6XpFr5t+Bc
         QjwNvVUaTKwnhMPzisoZGsEJ387em7RU/+rLCU9EuhjEraJUPuFckIBcHpZOanAKOvkI
         cjhQnzUyBn8UdewEVuv6XdR9gF8C7nVT4XdEeMZgQPRmLjSmLuA9pa6pButhIxk0TkPG
         q5x+ZC75KI2hCP/zMwi5GTdFiNO7KbPvhruMt0nAqYc5mGKWrZMHjd90nsptn7VrP0nz
         VkFzSFZR5lX2balZ/M9WfkontVXFP2TGtfGc7S+yaPZIPcG/Z2Z84qBjMhV0VXN0hA/E
         cXmw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=oT2wUcJfs9SzISsQ6VqfnYfgHv9/YmpigvSzSzjJJSc=;
        fh=LnyPKGH7jXiSRPvEpcWa2QyAYVTsiQt1QZO/m1FpKxY=;
        b=Schcy0Hb/g9wy5BjYImVpJe/8qq2QmGw09Yy4e+9xtVRZ3zH/pjdhpbpt1OkR6LBT8
         fh9WzyxMX8TN8Buw3Jwy3XieQptM6UoKvMcPIDeZRM+raRZwWxJaK+hHtrCPxk1ZENmR
         /j419GIIktio1VUJzmUwnoHWfcfnBMWrAKb3LYhCwrHx0pXW70fLgLyVHcdA7Fkp75z4
         7gYwhNKw4MLTovX7SwMfmz0zcQJbUjuNma+4uR0wbvXkRCwCKZPnvx5J33HJj/53jC1U
         I3Qf/Uo0pGVh/T/5E/m0FtecPDnJcYxLP2QfxfLzsPy8uJqB/7tjOyND3J6Nrn7kujXp
         VdDQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=IQjV1Okq;
       spf=none (google.com: peterz@infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1730720719; x=1731325519; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=oT2wUcJfs9SzISsQ6VqfnYfgHv9/YmpigvSzSzjJJSc=;
        b=J7VZyfOwkHXnRZjAGgxgvxo4KPl3BsVjKjh7BzIx++PQM9BQT0m/tvRzYVrfmiUwTJ
         OqToIMIzLrW7hCmu5NHUmFyp+qBqbqD5GyNKnU5Rn382RuAYnZ5C4VDO8QIQy/P3kSKf
         BbcA00Fd+MIubeLoeGWe5/0yhptngpL3QMCVrQ4FFoq4xZQTaxNRnYaDzQMKrP3ClB0k
         OoJkGWW/EF6ULBVo+s+Z0y+0Jft1w+7SJOOgPpzs6qaL1vHJbQlR1nuJLwbPpgCsd/29
         yOmKCrC1ChRn+S9syQtjLTLXIWtPBFWmn1m/GN7I5absJJEiKqJKXWKW/Y7ZVJ/M27Bc
         XJMQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1730720719; x=1731325519;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=oT2wUcJfs9SzISsQ6VqfnYfgHv9/YmpigvSzSzjJJSc=;
        b=TeYfi77lN/KqU952ifzdw9Az+KJi8ZmICS7EhAJgPjuBPOdYTzDipJZhHZO/hzrbi+
         K8lt4v4A32bG5SOVmjkmS/QgXjvlL0pesEQpz8GBSd+J9G6vjNo9ZTnSb6Gd9oiZOglD
         OgHfNg6HIy7DNGhIIfgup04Cu0zTpDIdGBv2f8CFZsbppuLp84xKEgP1MM+1q9Z9FoTE
         WL/jZzH+rk3RcQehU21KWYDNCE1ChL+CNKAF6ZO+GGovCO1J/4Q2d5hzYB60YXsnEXwi
         EwkJ2agEV+JQQLcNXz2jQSmkk+RaBqSM3FKazGLLmUxNH2lkAPaLH21mfYY0tO3Yjjv0
         CV1A==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUivwXy0nJpvMtQSES1S39cdGe2DXCj0glcG61GBukB8CDKExuUVgweJKzeH4pEI8EjklLZow==@lfdr.de
X-Gm-Message-State: AOJu0YxcRYV3jrk/90FZ2P1uaCzqZmMUr46z7E9buyFvWsCTBx8lPMuX
	km5VlvzyJP3OUAuiAWYonNVBCmf9PPHtVdlho1c9WT3sdaF1Rq/f
X-Google-Smtp-Source: AGHT+IGhhRIx+/UthqgkypCRrIblTJJ49tWVzbWACEzfwzKClGh32x2fxxKdXT70qiCuGs1L5LYbsQ==
X-Received: by 2002:a05:6000:1564:b0:37d:4a16:81d7 with SMTP id ffacd0b85a97d-381c7a4679emr12653170f8f.8.1730720719162;
        Mon, 04 Nov 2024 03:45:19 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:1548:b0:42c:c82f:e2f with SMTP id
 5b1f17b1804b1-4327b81bfa0ls7413065e9.2.-pod-prod-05-eu; Mon, 04 Nov 2024
 03:45:17 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWn9WiP3vjiSkDzmDwNQNbwYmfBktvbIzwOcslwkVfKECYq7kUtDMzyhcw0spTUm+NAMZ+u96pYEiA=@googlegroups.com
X-Received: by 2002:a5d:5f8d:0:b0:37d:47e0:45fb with SMTP id ffacd0b85a97d-381c7a5d20emr15030605f8f.21.1730720717183;
        Mon, 04 Nov 2024 03:45:17 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1730720717; cv=none;
        d=google.com; s=arc-20240605;
        b=WkMCS24dyERmBCVtI09gXvsYOyuAMBeeS+baGEx1ljBl+P3biumryIV/I1e0eXUbAX
         CMtspOGqGtl4Zz+qKxrbeoOzHLjNEiIMhdDPENMJiJnH6uwls4KPv7UObBhzUqdfy3xd
         zNJyP1YQY9D60MDfZYgCGuerdbuAGWhMW0NPJCI5uSjEUcf019ORChUztx2q5N90YiOq
         RBL/O1P6FuYNCelVeb2BRVuXWX5vS80batlP4nvpmE6QD7w20ykEwS7Y/cOTH5+Vju50
         pRhejKSrG8ZJGl5FYHSXMGvUmU0vh2zsPS29oY70gnLeLGKTwiXuhAtmWvozkJHqQjaY
         GmCw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=mYq2E5JqCpFxnnaQge2hIZbWTa3Or6pRl9pnrxRgOwA=;
        fh=B+qf3DsxH8cNw20ykEZBfUp9Zd5pclis1HJbhHMvE6Y=;
        b=JJstHOlLPmALJkOtiHV7eRJrMEiFf4HBxVBKzAHD+DddhrAwHi1Lm1mQF7umUHcNyX
         OnNIU7jE599uOSIXeOOzGNFJV+sFShqPXO0EzgnDode5NSCpvtjwDKEAKOj7tPB/Ai+2
         Vv32j27NcpPl0JftwXAhcDrAQTQ3ik6aK0I68zFBgGQSEY8S2ja9sO2j5eR/h1HHkafK
         sozvmOnlPnpp1Tu+FS2TKOclsqvvGY6MFYdkQE0Jp1U/X49RhLvAuGcyjd/ix2ukfA/b
         3eFm8Qk7SsQkOn5Hx1GT7RDEjasXXNPS4FWeSJK52JaWIP8uA9Et3Qz9lUodA1LxdfZE
         EK9g==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=IQjV1Okq;
       spf=none (google.com: peterz@infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
Received: from casper.infradead.org (casper.infradead.org. [2001:8b0:10b:1236::1])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-381c10bda52si183832f8f.2.2024.11.04.03.45.17
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 04 Nov 2024 03:45:17 -0800 (PST)
Received-SPF: none (google.com: peterz@infradead.org does not designate permitted sender hosts) client-ip=2001:8b0:10b:1236::1;
Received: from j130084.upc-j.chello.nl ([24.132.130.84] helo=noisy.programming.kicks-ass.net)
	by casper.infradead.org with esmtpsa (Exim 4.98 #2 (Red Hat Linux))
	id 1t7vW6-000000017vV-2NZE;
	Mon, 04 Nov 2024 11:45:07 +0000
Received: by noisy.programming.kicks-ass.net (Postfix, from userid 1000)
	id 58C81300324; Mon,  4 Nov 2024 12:45:06 +0100 (CET)
Date: Mon, 4 Nov 2024 12:45:06 +0100
From: Peter Zijlstra <peterz@infradead.org>
To: Vlastimil Babka <vbabka@suse.cz>
Cc: syzbot <syzbot+39f85d612b7c20d8db48@syzkaller.appspotmail.com>,
	Liam.Howlett@oracle.com, akpm@linux-foundation.org,
	jannh@google.com, linux-kernel@vger.kernel.org, linux-mm@kvack.org,
	lorenzo.stoakes@oracle.com, syzkaller-bugs@googlegroups.com,
	Sebastian Andrzej Siewior <bigeasy@linutronix.de>,
	Marco Elver <elver@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	kasan-dev <kasan-dev@googlegroups.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Waiman Long <longman@redhat.com>, dvyukov@google.com,
	vincenzo.frascino@arm.com, paulmck@kernel.org, frederic@kernel.org,
	neeraj.upadhyay@kernel.org, joel@joelfernandes.org,
	josh@joshtriplett.org, boqun.feng@gmail.com, urezki@gmail.com,
	rostedt@goodmis.org, mathieu.desnoyers@efficios.com,
	jiangshanlai@gmail.com, qiang.zhang1211@gmail.com, mingo@redhat.com,
	peterz@infradead.org, juri.lelli@redhat.com,
	vincent.guittot@linaro.org, dietmar.eggemann@arm.com,
	bsegall@google.com, mgorman@suse.de, vschneid@redhat.com,
	tj@kernel.org, cl@linux.com, penberg@kernel.org,
	rientjes@google.com, iamjoonsoo.kim@lge.com, vbabka@suse.cz,
	roman.gushchin@linux.dev, 42.hyeyoo@gmail.com, rcu@vger.kernel.org
Subject: Re: [syzbot] [mm?] WARNING: locking bug in __rmqueue_pcplist
Message-ID: <20241104114506.GC24862@noisy.programming.kicks-ass.net>
References: <67275485.050a0220.3c8d68.0a37.GAE@google.com>
 <ee48b6e9-3f7a-49aa-ae5b-058b5ada2172@suse.cz>
 <b9a674c1-860c-4448-aeb2-bf07a78c6fbf@suse.cz>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <b9a674c1-860c-4448-aeb2-bf07a78c6fbf@suse.cz>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=casper.20170209 header.b=IQjV1Okq;
       spf=none (google.com: peterz@infradead.org does not designate permitted
 sender hosts) smtp.mailfrom=peterz@infradead.org
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

On Mon, Nov 04, 2024 at 12:25:03PM +0100, Vlastimil Babka wrote:
> On 11/4/24 12:11, Vlastimil Babka wrote:

> >>  __alloc_pages_noprof+0x292/0x710 mm/page_alloc.c:4771
> >>  alloc_pages_mpol_noprof+0x3e8/0x680 mm/mempolicy.c:2265
> >>  stack_depot_save_flags+0x666/0x830 lib/stackdepot.c:627
> >>  kasan_save_stack+0x4f/0x60 mm/kasan/common.c:48
> >>  __kasan_record_aux_stack+0xac/0xc0 mm/kasan/generic.c:544
> >>  task_work_add+0xd9/0x490 kernel/task_work.c:77
> > 
> > It seems the decision if stack depot is allowed to allocate here depends on
> > TWAF_NO_ALLOC added only recently. So does it mean it doesn't work as intended?
> 
> I guess __run_posix_cpu_timers() needs to pass TWAF_NO_ALLOC too?

Yeah, or we just accept that kasan_record_aux_stack() is a horrible
thing and shouldn't live in functions that try their bestest to
locklessly setup async work at all.

That thing has only ever caused trouble :/

Also see 156172a13ff0.

How about we do the below at the very least?

---
 include/linux/kasan.h     |  2 --
 include/linux/task_work.h |  1 -
 kernel/irq_work.c         |  2 +-
 kernel/rcu/tiny.c         |  2 +-
 kernel/rcu/tree.c         |  4 ++--
 kernel/sched/core.c       |  2 +-
 kernel/task_work.c        | 12 +-----------
 kernel/workqueue.c        |  2 +-
 mm/kasan/generic.c        | 16 +++-------------
 mm/slub.c                 |  2 +-
 10 files changed, 11 insertions(+), 34 deletions(-)

diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index 00a3bf7c0d8f..1a623818e8b3 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -488,7 +488,6 @@ void kasan_cache_create(struct kmem_cache *cache, unsigned int *size,
 void kasan_cache_shrink(struct kmem_cache *cache);
 void kasan_cache_shutdown(struct kmem_cache *cache);
 void kasan_record_aux_stack(void *ptr);
-void kasan_record_aux_stack_noalloc(void *ptr);
 
 #else /* CONFIG_KASAN_GENERIC */
 
@@ -506,7 +505,6 @@ static inline void kasan_cache_create(struct kmem_cache *cache,
 static inline void kasan_cache_shrink(struct kmem_cache *cache) {}
 static inline void kasan_cache_shutdown(struct kmem_cache *cache) {}
 static inline void kasan_record_aux_stack(void *ptr) {}
-static inline void kasan_record_aux_stack_noalloc(void *ptr) {}
 
 #endif /* CONFIG_KASAN_GENERIC */
 
diff --git a/include/linux/task_work.h b/include/linux/task_work.h
index 2964171856e0..db1690e01346 100644
--- a/include/linux/task_work.h
+++ b/include/linux/task_work.h
@@ -21,7 +21,6 @@ enum task_work_notify_mode {
 	TWA_NMI_CURRENT,
 
 	TWA_FLAGS = 0xff00,
-	TWAF_NO_ALLOC = 0x0100,
 };
 
 static inline bool task_work_pending(struct task_struct *task)
diff --git a/kernel/irq_work.c b/kernel/irq_work.c
index 2f4fb336dda1..73f7e1fd4ab4 100644
--- a/kernel/irq_work.c
+++ b/kernel/irq_work.c
@@ -147,7 +147,7 @@ bool irq_work_queue_on(struct irq_work *work, int cpu)
 	if (!irq_work_claim(work))
 		return false;
 
-	kasan_record_aux_stack_noalloc(work);
+	kasan_record_aux_stack(work);
 
 	preempt_disable();
 	if (cpu != smp_processor_id()) {
diff --git a/kernel/rcu/tiny.c b/kernel/rcu/tiny.c
index b3b3ce34df63..4b3f31911465 100644
--- a/kernel/rcu/tiny.c
+++ b/kernel/rcu/tiny.c
@@ -250,7 +250,7 @@ EXPORT_SYMBOL_GPL(poll_state_synchronize_rcu);
 void kvfree_call_rcu(struct rcu_head *head, void *ptr)
 {
 	if (head)
-		kasan_record_aux_stack_noalloc(ptr);
+		kasan_record_aux_stack(ptr);
 
 	__kvfree_call_rcu(head, ptr);
 }
diff --git a/kernel/rcu/tree.c b/kernel/rcu/tree.c
index b1f883fcd918..7eae9bd818a9 100644
--- a/kernel/rcu/tree.c
+++ b/kernel/rcu/tree.c
@@ -3083,7 +3083,7 @@ __call_rcu_common(struct rcu_head *head, rcu_callback_t func, bool lazy_in)
 	}
 	head->func = func;
 	head->next = NULL;
-	kasan_record_aux_stack_noalloc(head);
+	kasan_record_aux_stack(head);
 	local_irq_save(flags);
 	rdp = this_cpu_ptr(&rcu_data);
 	lazy = lazy_in && !rcu_async_should_hurry();
@@ -3807,7 +3807,7 @@ void kvfree_call_rcu(struct rcu_head *head, void *ptr)
 		return;
 	}
 
-	kasan_record_aux_stack_noalloc(ptr);
+	kasan_record_aux_stack(ptr);
 	success = add_ptr_to_bulk_krc_lock(&krcp, &flags, ptr, !head);
 	if (!success) {
 		run_page_cache_worker(krcp);
diff --git a/kernel/sched/core.c b/kernel/sched/core.c
index 5de31c312189..dafc668a156e 100644
--- a/kernel/sched/core.c
+++ b/kernel/sched/core.c
@@ -10519,7 +10519,7 @@ void task_tick_mm_cid(struct rq *rq, struct task_struct *curr)
 		return;
 
 	/* No page allocation under rq lock */
-	task_work_add(curr, work, TWA_RESUME | TWAF_NO_ALLOC);
+	task_work_add(curr, work, TWA_RESUME);
 }
 
 void sched_mm_cid_exit_signals(struct task_struct *t)
diff --git a/kernel/task_work.c b/kernel/task_work.c
index c969f1f26be5..2ffd5a6db91b 100644
--- a/kernel/task_work.c
+++ b/kernel/task_work.c
@@ -64,17 +64,7 @@ int task_work_add(struct task_struct *task, struct callback_head *work,
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
diff --git a/kernel/workqueue.c b/kernel/workqueue.c
index 9949ffad8df0..65b8314b2d53 100644
--- a/kernel/workqueue.c
+++ b/kernel/workqueue.c
@@ -2180,7 +2180,7 @@ static void insert_work(struct pool_workqueue *pwq, struct work_struct *work,
 	debug_work_activate(work);
 
 	/* record the work call stack in order to print it in KASAN reports */
-	kasan_record_aux_stack_noalloc(work);
+	kasan_record_aux_stack(work);
 
 	/* we own @work, set data and link */
 	set_work_pwq(work, pwq, extra_flags);
diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
index 6310a180278b..ac9f6682bb2f 100644
--- a/mm/kasan/generic.c
+++ b/mm/kasan/generic.c
@@ -521,12 +521,12 @@ size_t kasan_metadata_size(struct kmem_cache *cache, bool in_object)
 			sizeof(struct kasan_free_meta) : 0);
 }
 
-static void __kasan_record_aux_stack(void *addr, depot_flags_t depot_flags)
+void kasan_record_aux_stack(void *addr)
 {
 	struct slab *slab = kasan_addr_to_slab(addr);
 	struct kmem_cache *cache;
 	struct kasan_alloc_meta *alloc_meta;
-	void *object;
+	void *object
 
 	if (is_kfence_address(addr) || !slab)
 		return;
@@ -538,17 +538,7 @@ static void __kasan_record_aux_stack(void *addr, depot_flags_t depot_flags)
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
diff --git a/mm/slub.c b/mm/slub.c
index 5b832512044e..b8c4bf3fe0d0 100644
--- a/mm/slub.c
+++ b/mm/slub.c
@@ -2300,7 +2300,7 @@ bool slab_free_hook(struct kmem_cache *s, void *x, bool init,
 			 * We have to do this manually because the rcu_head is
 			 * not located inside the object.
 			 */
-			kasan_record_aux_stack_noalloc(x);
+			kasan_record_aux_stack(x);
 
 			delayed_free->object = x;
 			call_rcu(&delayed_free->head, slab_free_after_rcu_debug);

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20241104114506.GC24862%40noisy.programming.kicks-ass.net.
