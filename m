Return-Path: <kasan-dev+bncBCT4XGV33UIBBMNFT65AMGQEBVAOFJA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13a.google.com (mail-il1-x13a.google.com [IPv6:2607:f8b0:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id 624799DB16B
	for <lists+kasan-dev@lfdr.de>; Thu, 28 Nov 2024 03:17:23 +0100 (CET)
Received: by mail-il1-x13a.google.com with SMTP id e9e14a558f8ab-3a7807feadfsf3332165ab.2
        for <lists+kasan-dev@lfdr.de>; Wed, 27 Nov 2024 18:17:23 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1732760242; cv=pass;
        d=google.com; s=arc-20240605;
        b=Iv7DM8u4jeZZRTblOjQ3624xfkrYGaNrqKw4ASZsj2gmpIFzrOP8pkmzIWeHum9aVR
         atBxYtQl6WvYzwDbTFoAuGSy0irz+YbLwxroPMLQCgZIbE3Vu3HbwuiWdqnen+9rKw12
         SCvF6XIae/jxGAxrZqjELY9NakuSeTpc8/UluSJAq9bergsY+zTAsSDTVWhf0i+Nn2n3
         lGJYJigP2Q0qqVfD+QScrtaVxsH8lHa5nrFLoximMdSQHFZ51Dt5+cHNL18YLGV/BK+Z
         gDWpfAMeFaBoXytIzVvf+PILY2pk2hApnpe4n4eFn8y+qCUutkBahzs+t3KU2a5Beus4
         t9IA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:message-id:subject:from:to:date
         :mime-version:sender:dkim-signature;
        bh=YPnml5VksA2e/tlLCvtx6r686mQSol/21NaZzDNNytQ=;
        fh=Tz7Xn1OZUlunQOLvU1VGQ7cj9OkRl8weRj13kbMRkBA=;
        b=H5n2Iz3/r+PjMWEVoHPsi61J+ruELDsa2/yobG9t+v4eIsXhlYdPXh7aIKy4R8IiCd
         WMIAkxemkDC/lU/ifpq6JeTKOhQLo8T7dXR/qUcSRD2Ul8B3S2CMqKQWjyLwKk5DCvRS
         srwzBYB35ndVOSpWkbJZgpAbF2/qFoLbLThIVZVPNpnkm1nqfaKyUuEIhaWnemeLkkKq
         CIESdZOZn1oICUXXTPUvkilhBJlSRHUlHwWJnplPKr4Nyx7t0xMW/kU9jMlgsQV0KQ0Q
         5bEQ4zHV59vkQh5C6naINv76CbBkYFDwVw/pYtpjgg/IQUuy9nFFNf1eTVMIfrB7b0DT
         jX0A==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=cfaKeO4A;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1732760242; x=1733365042; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:message-id:subject:from:to:date:mime-version
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=YPnml5VksA2e/tlLCvtx6r686mQSol/21NaZzDNNytQ=;
        b=IoatK1zuYw9UnqYquOgNtaBEJ1y8KUh6GbXGhInffConadgdQDE0E2wBp6TSoR+Gjk
         UAn2JUYmWU4S5aiBWjjqhrfZMC5KnX63JYz4x5OOPBEumYQG1qIvUUmEO88COwa1RUsE
         MbEQfDJLPMErLlaDA2p5g4YHpXPGWlq06S2mvpdgJxdB1xUwcq+8JzjHv3E8up+ircaT
         3PuYTrvi6V7LqOKeXjQthfmRjDBXOdilI8AlMeNYwekbB84Lv9YIbPxPkYx3cf2PYmK9
         tzvM6+MUZf/pnqjrcwBxfESgpp7f59eEiIKbbF/5EPUKosFWwqEwq3uAbFQ8YkkcABg9
         Tz9A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1732760242; x=1733365042;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:message-id
         :subject:from:to:date:x-beenthere:mime-version:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=YPnml5VksA2e/tlLCvtx6r686mQSol/21NaZzDNNytQ=;
        b=G5AgrVK5wW7K0OBFBhvRqk1A91HXRyPo4amLN587L3h+Z4cxQHCwSTGU5i+zgTuTey
         5ZwDkWE7fXNvvIKyresQBpJ6U8jeXR+oIDGaNSngzg3MkgYziqX0mJX3RYUbuiGFGSfv
         5SwfXqxYr+Hmp0x3/EJ2wNNlHfO3barae38A7uI/l0Jr+7+sTLqJAUQBwJsjzMro04nt
         BgbZpZvxgoeIHloo3jvldRY2ZZITxF49dFeZo38SnfdCc5UXEyu8jyBZk+OGJbGZBnL1
         6QQIXx+csJGCCjv/iMG1NutputqKISKPfPi1O7NAMtVU3inkF2B8giLHZzd9i6FMAq23
         TykA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCU2YEMnWJYqfnlVf7hplXaxGJ4J0GSi8328HaGz5qEPFSif2F3yiDsi3l9t3noZSnGjtwiaxQ==@lfdr.de
X-Gm-Message-State: AOJu0Ywq4afRQdueSR6+hKKGk3jDNx6WghkXRlPnl3OdgM1XhNNMXrA6
	H73DgoPFfDf21NWFwQAvrqbLfTQMxuW4h2EwkTD5owa/lDUanjRK
X-Google-Smtp-Source: AGHT+IFFnOoDIVZCDkDiXGYB3EqH8Rzz9HOzyMfghxbIQa0oSlRFsTu3YuTWoUsa6po9t6qp1OogpA==
X-Received: by 2002:a05:6e02:1c83:b0:3a7:93af:ef55 with SMTP id e9e14a558f8ab-3a7c5568698mr51100035ab.12.1732760241993;
        Wed, 27 Nov 2024 18:17:21 -0800 (PST)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:1686:b0:3a7:c5aa:7b33 with SMTP id
 e9e14a558f8ab-3a7cbd478b4ls3241565ab.0.-pod-prod-04-us; Wed, 27 Nov 2024
 18:17:21 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXBqUNGPJMJCr838yZzeMktdjI3WXWk2MS46T//L1UhjBB18aRK7ey5p4uMoK3ueC1BWKEFll+F3OQ=@googlegroups.com
X-Received: by 2002:a05:6602:6d16:b0:843:e667:f196 with SMTP id ca18e2360f4ac-843ecf9dc3bmr654982139f.4.1732760240735;
        Wed, 27 Nov 2024 18:17:20 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1732760240; cv=none;
        d=google.com; s=arc-20240605;
        b=JdgkMxD1dmSbCFT9rvlhHhCxPJPo5Fuo952+YjBxnuEj+EwFkOCiiq1lBu7knALPbr
         DNWPx8S8eovYtGjp+Vs0jBWmdlShHxRs7fqqT1MdcF9mDh7RnsbUisMQOx2THOvIX9oc
         ZLkdAA/Y0phHC07nu2cuAuLBrjyN3o92JmY5MxatBO3y3yjacQLCuzDTbk5fWmprgY4Q
         utGm+CFDK+x7vJPh/wt/gfAsPsdeNJJ0qCCuHJsnzUTyBf2PlT7fgRM7q51JBdzAkQ0Q
         9P6I0T6XBrJq0TBQiR1wGy2DdyDlD5QGnQt/gX87sEzbcrPL/IyYK8bojk8JOsLet7VA
         43OQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=message-id:subject:from:to:date:dkim-signature;
        bh=ZblMgEdJ109OdgnqpLkslgKzyofq7mxmyG+4/DsTU8E=;
        fh=tpBIT5b+ejHfRAZFMZ0BR/AzrT5gSlhMRnZrC78Ap5I=;
        b=gBwDoo0BXg7g5D20sa0WTvPgCYyRc7L+l1xtVQIop56sN/E1SMHqdlhVAEb0qkgbke
         NkIpOgp+TL+pBK7DuRYmJEU89aMNvqHBnAOmTZ8FLKfzWDltrlNOlZcc3+mdattcloKi
         SidJ/DT5CVW/aEobiZSWajgr1RDvgWOOt3+Slm0W/wc2OftksErLaH1YKR11LQaGW2JI
         yGVk5ytTfzBVN8r62BNQNOh1qpC7u03z4kVh+QOyFNahBtJVOndkzKqjwmB8Bkg1byHD
         b5Mq98AtZJWfXN0/BZoanO9otvlKcs0qp3r7xgJDf/D5XRdfpZlrm3hQnnXj4mrEfZQq
         KI7w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=cfaKeO4A;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id ca18e2360f4ac-84405ea0d07si1860839f.1.2024.11.27.18.17.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 27 Nov 2024 18:17:20 -0800 (PST)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id 901935C568C;
	Thu, 28 Nov 2024 02:16:36 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 6D43DC4CECC;
	Thu, 28 Nov 2024 02:17:19 +0000 (UTC)
Date: Wed, 27 Nov 2024 18:17:18 -0800
To: mm-commits@vger.kernel.org,vschneid@redhat.com,vincenzo.frascino@arm.com,vincent.guittot@linaro.org,vbabka@suse.cz,urezki@gmail.com,tj@kernel.org,tglx@linutronix.de,ryabinin.a.a@gmail.com,rostedt@goodmis.org,roman.gushchin@linux.dev,rientjes@google.com,qiang.zhang1211@gmail.com,penberg@kernel.org,paulmck@kernel.org,neeraj.upadhyay@kernel.org,mingo@redhat.com,mgorman@suse.de,mathieu.desnoyers@efficios.com,lorenzo.stoakes@oracle.com,longman@redhat.com,Liam.Howlett@Oracle.com,kasan-dev@googlegroups.com,juri.lelli@redhat.com,josh@joshtriplett.org,joel@joelfernandes.org,jiangshanlai@gmail.com,jannh@google.com,iamjoonsoo.kim@lge.com,glider@google.com,frederic@kernel.org,elver@google.com,dvyukov@google.com,dietmar.eggemann@arm.com,cl@linux.com,bsegall@google.com,boqun.feng@gmail.com,bigeasy@linutronix.de,andreyknvl@gmail.com,42.hyeyoo@gmail.com,peterz@infradead.org,akpm@linux-foundation.org
From: Andrew Morton <akpm@linux-foundation.org>
Subject: + kasan-make-kasan_record_aux_stack_noalloc-the-default-behaviour.patch added to mm-unstable branch
Message-Id: <20241128021719.6D43DC4CECC@smtp.kernel.org>
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=korg header.b=cfaKeO4A;
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


The patch titled
     Subject: kasan: make kasan_record_aux_stack_noalloc() the default behaviour
has been added to the -mm mm-unstable branch.  Its filename is
     kasan-make-kasan_record_aux_stack_noalloc-the-default-behaviour.patch

This patch will shortly appear at
     https://git.kernel.org/pub/scm/linux/kernel/git/akpm/25-new.git/tree/patches/kasan-make-kasan_record_aux_stack_noalloc-the-default-behaviour.patch

This patch will later appear in the mm-unstable branch at
    git://git.kernel.org/pub/scm/linux/kernel/git/akpm/mm

Before you just go and hit "reply", please:
   a) Consider who else should be cc'ed
   b) Prefer to cc a suitable mailing list as well
   c) Ideally: find the original patch on the mailing list and do a
      reply-to-all to that, adding suitable additional cc's

*** Remember to use Documentation/process/submit-checklist.rst when testing your code ***

The -mm tree is included into linux-next via the mm-everything
branch at git://git.kernel.org/pub/scm/linux/kernel/git/akpm/mm
and is updated there every 2-3 working days

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
Fixes: 7cb3007ce2da2 ("kasan: generic: introduce kasan_record_aux_stack_noalloc()")
Signed-off-by: Peter Zijlstra (Intel) <peterz@infradead.org>
Signed-off-by: Sebastian Andrzej Siewior <bigeasy@linutronix.de>
Reported-by: syzbot+39f85d612b7c20d8db48@syzkaller.appspotmail.com
Closes: https://lore.kernel.org/all/67275485.050a0220.3c8d68.0a37.GAE@googl=
e.com
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
@@ -2296,7 +2296,7 @@ bool slab_free_hook(struct kmem_cache *s
 			 * We have to do this manually because the rcu_head is
 			 * not located inside the object.
 			 */
-			kasan_record_aux_stack_noalloc(x);
+			kasan_record_aux_stack(x);
 
 			delayed_free->object = x;
 			call_rcu(&delayed_free->head, slab_free_after_rcu_debug);
_

Patches currently in -mm which might be from peterz@infradead.org are

kasan-make-kasan_record_aux_stack_noalloc-the-default-behaviour.patch

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20241128021719.6D43DC4CECC%40smtp.kernel.org.
