Return-Path: <kasan-dev+bncBCKLNNXAXYFBBUXK6K4QMGQEJWK63HY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x240.google.com (mail-lj1-x240.google.com [IPv6:2a00:1450:4864:20::240])
	by mail.lfdr.de (Postfix) with ESMTPS id 12CE69D2A45
	for <lists+kasan-dev@lfdr.de>; Tue, 19 Nov 2024 16:57:09 +0100 (CET)
Received: by mail-lj1-x240.google.com with SMTP id 38308e7fff4ca-2fb45ca974bsf24913201fa.2
        for <lists+kasan-dev@lfdr.de>; Tue, 19 Nov 2024 07:57:09 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1732031828; cv=pass;
        d=google.com; s=arc-20240605;
        b=I5i8cvXDa7x/blR7lQxkKwcFSxsQVCJyInxY/krye6++6EQC95EwcddrvAMeg3+jFz
         /I39IUC0coZdcD3pCP9go10WAhJMJAiCMdz2Y2od6rwg+DOUUO6+BAStzlG9G2d2Wwux
         r0X5rLUSR3TnMn+4UUlWOGC/Yi+/8XoF+BgrcXBMWaYicF+bVcwHOjOFtRbfnGxMV1ik
         aY6Bm9H6vY7El88LF4i1W5foJQgebk3BLYktMptMdPhkFHPwbZAu3EievGk3vphOhMET
         lqpMrxo/raF3jCYKYhyap4JmrQ89hB2QkNyTi/nSeTP9cwJesnuCp/L6XgFchT7vNmNe
         6qnA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=7MMtZxfwWn9SFcm8Z8EKm3uIwPzLsejIWwJP8ZK8/8o=;
        fh=fFkOruyOTVHLA4pg6iWcSQUPHQq+Lh/SEyh2bMlRakA=;
        b=lbnwm3uIYyqoWAnLhCFT/XPVflMXA1x+9S1mvJ1kXMHQXnFQDOCU1dre+lKWz43tGW
         DB3NM2JzAkwMmI/y1qjbkD4ixq/276tXVclN/gSct8paIECHFD8G6yqEFfR8T2ePmcKY
         KGSpdihxFjqC82ULYpd2LHFF+4bukabb6JyDLLonzQ1Rv3TQRVc3+JiHpSWLIAU4o771
         nIFSPqwm/ay6ayvr+d5naKQxQBpcfMLDjlW4keGMAebR+gjPiBGawZGuh9JtPEsDpvqv
         TMldHaar3bo7HF9xY3kyC1yXaIlUPLRbV9TCv0u8TwxBhy9ltIAJyHqFwz6xDiaSezyb
         1bBQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=zVS+9zO4;
       dkim=neutral (no key) header.i=@linutronix.de header.s=2020e header.b=M9Vih6ak;
       spf=pass (google.com: domain of bigeasy@linutronix.de designates 193.142.43.55 as permitted sender) smtp.mailfrom=bigeasy@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1732031828; x=1732636628; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=7MMtZxfwWn9SFcm8Z8EKm3uIwPzLsejIWwJP8ZK8/8o=;
        b=hXkVrIwhOSqdzxmiuOdFkI+DnrrhWwtfFFyYJKG3uEm7uW9GJ6RLOOn3+8uQapGSqj
         wx5goi4drQsTlk/nng2D48eRzrAYozFBtENjiLwU0SqOmMQHAmoEt+ebKQv6yuOEtPq7
         ory++9LJR0YJX5WhgK8K+6RHf8X8Lh7MPQ1+dFn+zEwhTxFOSbij/hX9vDyLNfAMpIy3
         nZ3PLBAOcmj/s3bTRSVsxOXJ9xYuXvFcnR6PENAkAsfYVXvlF1lQDKznlY9SYWky3ZQa
         CpW1bjridvyhH58Pxd99MNU/4hZFK9V8IXyt7bku5UmVq11GHfeh4xK8esIV87MWrAfq
         iAjw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1732031828; x=1732636628;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=7MMtZxfwWn9SFcm8Z8EKm3uIwPzLsejIWwJP8ZK8/8o=;
        b=okIQm/FE3oMhDzjpN26IFQepsOeG3kvAXPvquwhpTF6FzdXX6U+eCdzV7DaotPjY7B
         O+mtdRpkrMlPGHa25JmCkze1cQPujtvn/VGLaCFhXau/Q+EwpdBDpBLM4cE7oKaRVyDL
         8kN7CjXhS7hjk1CDLsbBmQZaNaGcbRmCFLeMFfCgm/mbd7EkWFeSkPPWUPS+2CinUt7w
         eXw543CqOSGShENYQBxgxfialSD7W60wjKBrKN5x2KQYZlc4jqYX5e/9CoE+fTVP9q9N
         MywXEhynezZ4rHRRpCrUiq7UYkD8bPPGL2yUrbiwPm5myhSNugAyGdh69y+JMSnxLqNc
         Jxsg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCV8RGw/2RIBxFsdYiXG1ZkNknwkc2Odst5pwP0Ic4/HY27eFc4SHs+SbWNRMEFYBd3TMt0r/A==@lfdr.de
X-Gm-Message-State: AOJu0Yyfmmo+ljQns32JeAb1noqhcSGTkUyrQF0yer0VhSWH8njzt18/
	9Jae4UctCVCGKB7FhbQeCUhiwV3SScyiiAAaRc5hoD1Slwzv0PDc
X-Google-Smtp-Source: AGHT+IH9tyycO/xWzPTrg8UScmVrUDTVnphmGqCiwxqsfVZ3iYFtOfOhDQFKNWKOt1b07AgME8P/Xw==
X-Received: by 2002:a2e:be24:0:b0:2fb:6394:d6bd with SMTP id 38308e7fff4ca-2ff60667e5amr69370321fa.12.1732031827313;
        Tue, 19 Nov 2024 07:57:07 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:81d4:0:b0:2ff:6268:ddcb with SMTP id 38308e7fff4ca-2ff6268de5bls733301fa.1.-pod-prod-02-eu;
 Tue, 19 Nov 2024 07:57:04 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWgXhkHIbNIR0TvACO6cVfliZko+plaZrYJRqvxCI0sw2VQGipgKo7j8ofQOjbllozG6WDzzREP5lw=@googlegroups.com
X-Received: by 2002:a2e:9a12:0:b0:2fb:39e3:592e with SMTP id 38308e7fff4ca-2ff6069381dmr83295241fa.19.1732031824545;
        Tue, 19 Nov 2024 07:57:04 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1732031824; cv=none;
        d=google.com; s=arc-20240605;
        b=VrtQ5sKz8b/HOk4Pg/U48gpwRvHcyiwEad//tw8Sm3pf31UEtpW+OnKujriff4Hcdy
         P6oM71J1Lw05ZkZsfZP37Bjx/NneqkVz6rX3obhX3T+o34z6Lj01J/7PMElOGSWU0QgD
         sH+D8vR7WVF033rndwb4i+kTaIzaZo9Mi1bj14LN/jno0Rb9vUU2Gj740i0iMV3HPmXg
         dciTcTMFZVXiQPMu/O+yj9TIKBVoK1oS7VXdPHcFfkSy8In7VzOZpY8BqHINgNU4QpCS
         vB+DuxUhubBr4Eyy0bHLVlYfPXmonAi+G0U0P6TgBMiZ58if8FU09YNWMVVvxWZW7RvZ
         66/A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:dkim-signature:dkim-signature:date;
        bh=/MZupiwZEv7S6PjpR394r6GaOTkxg+//UpoNKUISypU=;
        fh=vektmY4eQf8T6N3L51UsQHpin9swO/yJnOJZ+o+zk0g=;
        b=bEl/OyKyqGa8IYPJj4h9qx5bWUPiR59sRraZVNU6vBn3omfb/3+OEV0PT9x8wdOYSA
         SJ0rhUy9ixFXRZ/cMzga7rs4R9JeaatwzgHxdWTHM3PnLE4f4FdA5WWJma0Hx1YAMNyc
         MMLDVjHTQ08ViAETicjWTyrmEu3PChYJrAotEjvRuvp2u0SuSCoLSuuQ+Ik1p+SwsQff
         KlJTnJwWQqNZ+wNMPz+LjP0OrRjHSiD+OBVP/i2vnR+48b1eT2VDKex/T+3AUKlkBmf1
         bpDvYA4ZjYc4a9gfDlacNNSCb2kLGjEpow1rwaWDxjdziccg4lmDFsrqF8UBozZMWNwZ
         0ASw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=zVS+9zO4;
       dkim=neutral (no key) header.i=@linutronix.de header.s=2020e header.b=M9Vih6ak;
       spf=pass (google.com: domain of bigeasy@linutronix.de designates 193.142.43.55 as permitted sender) smtp.mailfrom=bigeasy@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
Received: from galois.linutronix.de (Galois.linutronix.de. [193.142.43.55])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-2ff69b3c7c6si1280151fa.7.2024.11.19.07.57.04
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 19 Nov 2024 07:57:04 -0800 (PST)
Received-SPF: pass (google.com: domain of bigeasy@linutronix.de designates 193.142.43.55 as permitted sender) client-ip=193.142.43.55;
Date: Tue, 19 Nov 2024 16:57:01 +0100
From: Sebastian Andrzej Siewior <bigeasy@linutronix.de>
To: Marco Elver <elver@google.com>, Peter Zijlstra <peterz@infradead.org>
Cc: Vlastimil Babka <vbabka@suse.cz>,
	syzbot <syzbot+39f85d612b7c20d8db48@syzkaller.appspotmail.com>,
	Liam.Howlett@oracle.com, akpm@linux-foundation.org,
	jannh@google.com, linux-kernel@vger.kernel.org, linux-mm@kvack.org,
	lorenzo.stoakes@oracle.com, syzkaller-bugs@googlegroups.com,
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
	juri.lelli@redhat.com, vincent.guittot@linaro.org,
	dietmar.eggemann@arm.com, bsegall@google.com, mgorman@suse.de,
	vschneid@redhat.com, tj@kernel.org, cl@linux.com,
	penberg@kernel.org, rientjes@google.com, iamjoonsoo.kim@lge.com,
	Thomas Gleixner <tglx@linutronix.de>, roman.gushchin@linux.dev,
	42.hyeyoo@gmail.com, rcu@vger.kernel.org
Subject: [PATCH] kasan: Remove kasan_record_aux_stack_noalloc().
Message-ID: <20241119155701.GYennzPF@linutronix.de>
References: <67275485.050a0220.3c8d68.0a37.GAE@google.com>
 <ee48b6e9-3f7a-49aa-ae5b-058b5ada2172@suse.cz>
 <b9a674c1-860c-4448-aeb2-bf07a78c6fbf@suse.cz>
 <20241104114506.GC24862@noisy.programming.kicks-ass.net>
 <CANpmjNPmQYJ7pv1N3cuU8cP18u7PP_uoZD8YxwZd4jtbof9nVQ@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANpmjNPmQYJ7pv1N3cuU8cP18u7PP_uoZD8YxwZd4jtbof9nVQ@mail.gmail.com>
X-Original-Sender: bigeasy@linutronix.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linutronix.de header.s=2020 header.b=zVS+9zO4;       dkim=neutral
 (no key) header.i=@linutronix.de header.s=2020e header.b=M9Vih6ak;
       spf=pass (google.com: domain of bigeasy@linutronix.de designates
 193.142.43.55 as permitted sender) smtp.mailfrom=bigeasy@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
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

From: Peter Zijlstra <peterz@infradead.org>

kasan_record_aux_stack_noalloc() was introduced to record a stack trace
without allocating memory in the process. It has been added to callers
which were invoked while a raw_spinlock_t was held.
More and more callers were identified and changed over time. Is it a
good thing to have this while functions try their best to do a
locklessly setup? The only downside of having kasan_record_aux_stack()
not allocate any memory is that we end up without a stacktrace if
stackdepot runs out of memory and at the same stacktrace was not
recorded before. Marco Elver said in
	https://lore.kernel.org/all/20210913112609.2651084-1-elver@google.com/
that this is rare.

Make the kasan_record_aux_stack_noalloc() behaviour default as
kasan_record_aux_stack().

[bigeasy: Dressed the diff as patch. ]

Reported-by: syzbot+39f85d612b7c20d8db48@syzkaller.appspotmail.com
Closes: https://lore.kernel.org/all/67275485.050a0220.3c8d68.0a37.GAE@google.com
Signed-off-by: Peter Zijlstra (Intel) <peterz@infradead.org>
Signed-off-by: Sebastian Andrzej Siewior <bigeasy@linutronix.de>
---

Didn't add a Fixes tag, didn't want to put 
   7cb3007ce2da2 ("kasan: generic: introduce kasan_record_aux_stack_noalloc()")

there.

 include/linux/kasan.h     |  2 --
 include/linux/task_work.h |  3 ---
 kernel/irq_work.c         |  2 +-
 kernel/rcu/tiny.c         |  2 +-
 kernel/rcu/tree.c         |  4 ++--
 kernel/sched/core.c       |  2 +-
 kernel/task_work.c        | 14 +-------------
 kernel/workqueue.c        |  2 +-
 mm/kasan/generic.c        | 14 ++------------
 mm/slub.c                 |  2 +-
 10 files changed, 10 insertions(+), 37 deletions(-)

diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index 00a3bf7c0d8f0..1a623818e8b39 100644
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
index 2964171856e00..0646804860ff1 100644
--- a/include/linux/task_work.h
+++ b/include/linux/task_work.h
@@ -19,9 +19,6 @@ enum task_work_notify_mode {
 	TWA_SIGNAL,
 	TWA_SIGNAL_NO_IPI,
 	TWA_NMI_CURRENT,
-
-	TWA_FLAGS = 0xff00,
-	TWAF_NO_ALLOC = 0x0100,
 };
 
 static inline bool task_work_pending(struct task_struct *task)
diff --git a/kernel/irq_work.c b/kernel/irq_work.c
index 2f4fb336dda17..73f7e1fd4ab4d 100644
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
index b3b3ce34df631..4b3f319114650 100644
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
index b1f883fcd9185..7eae9bd818a90 100644
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
index a1c353a62c568..3717360a940d2 100644
--- a/kernel/sched/core.c
+++ b/kernel/sched/core.c
@@ -10485,7 +10485,7 @@ void task_tick_mm_cid(struct rq *rq, struct task_struct *curr)
 		return;
 
 	/* No page allocation under rq lock */
-	task_work_add(curr, work, TWA_RESUME | TWAF_NO_ALLOC);
+	task_work_add(curr, work, TWA_RESUME);
 }
 
 void sched_mm_cid_exit_signals(struct task_struct *t)
diff --git a/kernel/task_work.c b/kernel/task_work.c
index c969f1f26be58..d1efec571a4a4 100644
--- a/kernel/task_work.c
+++ b/kernel/task_work.c
@@ -55,26 +55,14 @@ int task_work_add(struct task_struct *task, struct callback_head *work,
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
diff --git a/kernel/workqueue.c b/kernel/workqueue.c
index 9949ffad8df09..65b8314b2d538 100644
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
index 6310a180278b6..b18b5944997f8 100644
--- a/mm/kasan/generic.c
+++ b/mm/kasan/generic.c
@@ -521,7 +521,7 @@ size_t kasan_metadata_size(struct kmem_cache *cache, bool in_object)
 			sizeof(struct kasan_free_meta) : 0);
 }
 
-static void __kasan_record_aux_stack(void *addr, depot_flags_t depot_flags)
+void kasan_record_aux_stack(void *addr)
 {
 	struct slab *slab = kasan_addr_to_slab(addr);
 	struct kmem_cache *cache;
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
index 5b832512044e3..b8c4bf3fe0d07 100644
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
2.45.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20241119155701.GYennzPF%40linutronix.de.
