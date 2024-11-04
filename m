Return-Path: <kasan-dev+bncBCKLNNXAXYFBBG6OUK4QMGQEXWMWL3Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23c.google.com (mail-lj1-x23c.google.com [IPv6:2a00:1450:4864:20::23c])
	by mail.lfdr.de (Postfix) with ESMTPS id ED4A99BB18A
	for <lists+kasan-dev@lfdr.de>; Mon,  4 Nov 2024 11:51:08 +0100 (CET)
Received: by mail-lj1-x23c.google.com with SMTP id 38308e7fff4ca-2f759001cb1sf30648961fa.0
        for <lists+kasan-dev@lfdr.de>; Mon, 04 Nov 2024 02:51:08 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1730717468; cv=pass;
        d=google.com; s=arc-20240605;
        b=FFDQ6ZKC9khdKRSG/jdyyjxB9rWoMiCkiMhbxReBcvySfuBtoPCnS+LoQoVNvZRvzi
         KD+aSZDogkmJdX9+OL4ehSYWbgjz1MvyUUsEFZUxrACabZJVE36fKpva92ZTVncUWsCL
         sGugEhtigQgDxHcYu9suTASIYvYP985o7x9fx0hdBZ79pqDxyAkw9lfhKluxpwM0W2ri
         bEVlUmHqQJWieMdikaqjK5YyaH6KkBv0gy9P4fbUoP9I8gsRVVJ+sJaCmaQuZ1lBjKAz
         dHizoM1ZsoUcPWNKbKplTcEtz2tOqDoerxfqRi3Qi5c5IKC191RFfL3/AkzBX8PoKqYy
         X5Fg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=Qh8ObitUbRik8kvW7saYAkTHH3AB9++NILlRg63bS7U=;
        fh=HG7pe7QlPGvhudzSm/tAbPhZu5HQ4s1PuJARldV2mTQ=;
        b=Ai8B1dxLC/taPh1hU49B5Qwd7YE4QXNMwsd6OzVbQyb5VH8H9Ixilv4/WIwbG1HRKs
         zqPOqHBeB3WoLCDxGECYKyc/HG3jYTOm5sztwEZcU2uPe3TrJdiaVZjAz8pEJSGe5ckc
         otQPrqjZEmVm5AprDEPpgSOCZu/GGNXU98oxRHl9k9eTMTY4ofRZgqmA+nS96WF+TrBe
         47MOlqOA4cOePvNqzTm+oL/GKsdzY0IIAOts52F+lCNzxUpcCDoHr09VEzhGm02Q/gzE
         kJOfHcjorotw5wbsFW9cynKpCvzt9eqmqRG93wsSK2UaJ0aZ48F95d7YP9/O8UUXPm+o
         bSrg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=SukzN7T5;
       dkim=neutral (no key) header.i=@linutronix.de;
       spf=pass (google.com: domain of bigeasy@linutronix.de designates 193.142.43.55 as permitted sender) smtp.mailfrom=bigeasy@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1730717468; x=1731322268; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Qh8ObitUbRik8kvW7saYAkTHH3AB9++NILlRg63bS7U=;
        b=cjYVsdQp44cjznwuY8nF95/JuzK0psH0IQcS4toOVxy4z3Cfeb5XqChCty74myZh+D
         jrWtdVv3zOJqXEKR57RAVPRnaK86FZNv9J8nrlA1ismgNs+yY+8Vs07WYa7TekWftnx6
         b0Yr/pTyn52iOddUrUG3jgaBtIatNcdXlvN8IyaqaORpcR9Q2zDC28ehNa8f2JEkrRpf
         pH+jZ9j6+y1l4tzJxdu74Fd5ZhHtSd5YH73s5dKzu4sZgwH0jJKu5ak7wI0ej1MGR0tE
         tPKznPJpuoibYWTSL3gKXdWEbVZEQJwF4799bRMSI1J3P2WxnVgnmpAwmiYtsboZk92n
         Q+TA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1730717468; x=1731322268;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=Qh8ObitUbRik8kvW7saYAkTHH3AB9++NILlRg63bS7U=;
        b=ZkSkffNd9Q3O5amS7d22P86x3mosZbx0QBYQsr7K0QVlcNWBCMGOb3a6qsuI9Odh6t
         7QH4/ot++SeImRzp0+afZo3ki+jFRRhlYKG4eUsHrgdO5bw9Rco1T2ExkcN5YHl8FZQf
         KklnVlsnHS/CBWor99pnlGk9H15VrPIa1ZelBJvSqVaAW/KAMHjWqq795/3MbkyP7+w4
         2kgAcUlBbyK3SHrPpo9U9RN1BXq8449Wqh5qQenl/CR6kyIFSY9wqTsZnMiiEb1ko1PQ
         nSgcxxwC1SOhVkeQP8tJ/cCXBDpY4f3y0sq34ynu9nKgvSeqn6Gg2Xc48GAJ9F/92R8z
         Xj9w==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUKopEohTdnx3gpId9UoPzvjHbHsWcbCB6IL47j9QjfQv+EZebhfPKm2nv1DXZucI80ZIp6xQ==@lfdr.de
X-Gm-Message-State: AOJu0YzvhQzmtGtw1oO1g3RM8958SiU/S6fuCfHGYVAw+jTQ8cOJaafg
	1TzvuUW8hxI2+Jq5xy/1K48zX1/fMJ8nFKSkL2FcZc5I4ZKbvaNb
X-Google-Smtp-Source: AGHT+IGN3niG7rjW8I7t1uOCyUUxoUJsI0geQS56w9KhbKHy/I1fAH314Y1f6os1/IltU3pHoV4Wqw==
X-Received: by 2002:a2e:a545:0:b0:2fa:fcf0:7c2a with SMTP id 38308e7fff4ca-2fedb7ca5b3mr82859691fa.24.1730717467571;
        Mon, 04 Nov 2024 02:51:07 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:1f0a:0:b0:2fb:4dc3:c906 with SMTP id 38308e7fff4ca-2fdeb6c575dls6716991fa.1.-pod-prod-05-eu;
 Mon, 04 Nov 2024 02:51:05 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCX/Um2b2JiBQS/Y3oay+4FrxFzbPnI66mAtFMkFdhZEPNakvuKSqOGWTaHQNbdVnaabftJsZQzmM6U=@googlegroups.com
X-Received: by 2002:a05:651c:158f:b0:2fb:5206:1675 with SMTP id 38308e7fff4ca-2fedb7d8957mr79807431fa.27.1730717465326;
        Mon, 04 Nov 2024 02:51:05 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1730717465; cv=none;
        d=google.com; s=arc-20240605;
        b=ZiaoDcxRqUkrOu38OLChEPd5lEAWCbVW800dvyNE50AdOMpWY+0xslDcsorRdeOaFk
         YTyvPhpyATJeMBFlR1pUV9eojHrq7m0hTD8nENmiUumejIz6XM1zflteFmYj00R4buIk
         A/fzxZd9cCpU4Ge1h0M4XxuhxSpVXnX9P616+n+bBs/OG9Dg4ZbwY9AJ/EWG+HLdik18
         Qo6Rn8NhRnSDTrkQdyQ2uIvQBLDkHUnxhzvdaWjSTrZvDNPygqNxEVzUiQL2pPvrx1Kb
         +amr8YYaP9oYbPRKBLc/0cvyNhVU7YbC9GLEuVUz/FQ668FUPDKWBbzJVvGgJx4JGi74
         DITA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:dkim-signature:dkim-signature:from;
        bh=GcwZ4Huf0ok76UUKQ+LdAyCTe3RrRb5PN85tcNXwRJk=;
        fh=nGK+SoD1ex8by9wamSKwhZcZoH8mNV5YxsuUiQLVlHg=;
        b=A0ZSHBeetV9r3EF6cBqZTNgmpI9XFKGolre68gawLWZacOMcF9PUiN6hYnMKgKBvPN
         hRu5vSHQGUxPdoko1M3G4qBNL7rim7SBb69JELukj4MdIj6BgKf80F+NLnSbTPV7YHXx
         XENGMUS8V0+2ocnf+q34nW48R6ZnBtezdeJXOxtIG0Bw2rxXoqfETer053Kto04a8eZM
         CHB4GHgmflBULmmywi9y6YiZjXSRVImuZjAT8icKcin6iyxr/EzuDc6+pfX4YtgLnrkh
         x3TjJID+2XRtRRr8ILqIJdrPG0d3C4BDa2X30lE6Y5+LryLSd1OqA/+ntcVyZFNvPy+d
         nWjw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=SukzN7T5;
       dkim=neutral (no key) header.i=@linutronix.de;
       spf=pass (google.com: domain of bigeasy@linutronix.de designates 193.142.43.55 as permitted sender) smtp.mailfrom=bigeasy@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
Received: from galois.linutronix.de (Galois.linutronix.de. [193.142.43.55])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-431bb78931bsi5802825e9.1.2024.11.04.02.51.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 04 Nov 2024 02:51:05 -0800 (PST)
Received-SPF: pass (google.com: domain of bigeasy@linutronix.de designates 193.142.43.55 as permitted sender) client-ip=193.142.43.55;
From: Sebastian Andrzej Siewior <bigeasy@linutronix.de>
To: "Paul E. McKenney" <paulmck@kernel.org>
Cc: Boqun Feng <boqun.feng@gmail.com>,
	Vlastimil Babka <vbabka@suse.cz>,
	Marco Elver <elver@google.com>,
	linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	sfr@canb.auug.org.au,
	longman@redhat.com,
	cl@linux.com,
	penberg@kernel.org,
	rientjes@google.com,
	iamjoonsoo.kim@lge.com,
	akpm@linux-foundation.org,
	Tomas Gleixner <tglx@linutronix.de>,
	Peter Zijlstra <peterz@infradead.org>,
	Sebastian Andrzej Siewior <bigeasy@linutronix.de>
Subject: [PATCH 2/2] scftorture: Use a lock-less list to free memory.
Date: Mon,  4 Nov 2024 11:50:53 +0100
Message-ID: <20241104105053.2182833-2-bigeasy@linutronix.de>
In-Reply-To: <20241104105053.2182833-1-bigeasy@linutronix.de>
References: <88694240-1eea-4f4c-bb7b-80de25f252e7@paulmck-laptop>
 <20241104105053.2182833-1-bigeasy@linutronix.de>
MIME-Version: 1.0
X-Original-Sender: bigeasy@linutronix.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linutronix.de header.s=2020 header.b=SukzN7T5;       dkim=neutral
 (no key) header.i=@linutronix.de;       spf=pass (google.com: domain of
 bigeasy@linutronix.de designates 193.142.43.55 as permitted sender)
 smtp.mailfrom=bigeasy@linutronix.de;       dmarc=pass (p=NONE sp=QUARANTINE
 dis=NONE) header.from=linutronix.de
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

scf_handler() is used as a SMP function call. This function is always
invoked in IRQ-context even with forced-threading enabled. This function
frees memory which not allowed on PREEMPT_RT because the locking
underneath is using sleeping locks.

Add a per-CPU scf_free_pool where each SMP functions adds its memory to
be freed. This memory is then freed by scftorture_invoker() on each
iteration. On the majority of invocations the number of items is less
than five. If the thread sleeps/ gets delayed the number exceed 350 but
did not reach 400 in testing. These were the spikes during testing.
The bulk free of 64 pointers at once should improve the give-back if the
list grows. The list size is ~1.3 items per invocations.

Having one global scf_free_pool with one cleaning thread let the list
grow to over 10.000 items with 32 CPUs (again, spikes not the average)
especially if the CPU went to sleep. The per-CPU part looks like a good
compromise.

Reported-by: "Paul E. McKenney" <paulmck@kernel.org>
Closes: https://lore.kernel.org/lkml/41619255-cdc2-4573-a360-7794fc3614f7@paulmck-laptop/
Signed-off-by: Sebastian Andrzej Siewior <bigeasy@linutronix.de>
---
 kernel/scftorture.c | 47 +++++++++++++++++++++++++++++++++++++++++----
 1 file changed, 43 insertions(+), 4 deletions(-)

diff --git a/kernel/scftorture.c b/kernel/scftorture.c
index e5546fe256329..ba9f1125821b8 100644
--- a/kernel/scftorture.c
+++ b/kernel/scftorture.c
@@ -97,6 +97,7 @@ struct scf_statistics {
 static struct scf_statistics *scf_stats_p;
 static struct task_struct *scf_torture_stats_task;
 static DEFINE_PER_CPU(long long, scf_invoked_count);
+static DEFINE_PER_CPU(struct llist_head, scf_free_pool);
 
 // Data for random primitive selection
 #define SCF_PRIM_RESCHED	0
@@ -133,6 +134,7 @@ struct scf_check {
 	bool scfc_wait;
 	bool scfc_rpc;
 	struct completion scfc_completion;
+	struct llist_node scf_node;
 };
 
 // Use to wait for all threads to start.
@@ -148,6 +150,40 @@ static DEFINE_TORTURE_RANDOM_PERCPU(scf_torture_rand);
 
 extern void resched_cpu(int cpu); // An alternative IPI vector.
 
+static void scf_add_to_free_list(struct scf_check *scfcp)
+{
+	struct llist_head *pool;
+	unsigned int cpu;
+
+	cpu = raw_smp_processor_id() % nthreads;
+	pool = &per_cpu(scf_free_pool, cpu);
+	llist_add(&scfcp->scf_node, pool);
+}
+
+static void scf_cleanup_free_list(unsigned int cpu)
+{
+	struct llist_head *pool;
+	struct llist_node *node;
+	struct scf_check *scfcp;
+	unsigned int slot = 0;
+	void *free_pool[64];
+
+	pool = &per_cpu(scf_free_pool, cpu);
+	node = llist_del_all(pool);
+	while (node) {
+		scfcp = llist_entry(node, struct scf_check, scf_node);
+		node = node->next;
+		free_pool[slot] = scfcp;
+		slot++;
+		if (slot == ARRAY_SIZE(free_pool)) {
+			kfree_bulk(slot, free_pool);
+			slot = 0;
+		}
+	}
+	if (slot)
+		kfree_bulk(slot, free_pool);
+}
+
 // Print torture statistics.  Caller must ensure serialization.
 static void scf_torture_stats_print(void)
 {
@@ -296,7 +332,7 @@ static void scf_handler(void *scfc_in)
 		if (scfcp->scfc_rpc)
 			complete(&scfcp->scfc_completion);
 	} else {
-		kfree(scfcp);
+		scf_add_to_free_list(scfcp);
 	}
 }
 
@@ -363,7 +399,7 @@ static void scftorture_invoke_one(struct scf_statistics *scfp, struct torture_ra
 				scfp->n_single_wait_ofl++;
 			else
 				scfp->n_single_ofl++;
-			kfree(scfcp);
+			scf_add_to_free_list(scfcp);
 			scfcp = NULL;
 		}
 		break;
@@ -391,7 +427,7 @@ static void scftorture_invoke_one(struct scf_statistics *scfp, struct torture_ra
 				preempt_disable();
 		} else {
 			scfp->n_single_rpc_ofl++;
-			kfree(scfcp);
+			scf_add_to_free_list(scfcp);
 			scfcp = NULL;
 		}
 		break;
@@ -428,7 +464,7 @@ static void scftorture_invoke_one(struct scf_statistics *scfp, struct torture_ra
 			pr_warn("%s: Memory-ordering failure, scfs_prim: %d.\n", __func__, scfsp->scfs_prim);
 			atomic_inc(&n_mb_out_errs); // Leak rather than trash!
 		} else {
-			kfree(scfcp);
+			scf_add_to_free_list(scfcp);
 		}
 		barrier(); // Prevent race-reduction compiler optimizations.
 	}
@@ -442,6 +478,7 @@ static void scftorture_invoke_one(struct scf_statistics *scfp, struct torture_ra
 		schedule_timeout_uninterruptible(1);
 }
 
+
 // SCF test kthread.  Repeatedly does calls to members of the
 // smp_call_function() family of functions.
 static int scftorture_invoker(void *arg)
@@ -479,6 +516,8 @@ static int scftorture_invoker(void *arg)
 	VERBOSE_SCFTORTOUT("scftorture_invoker %d started", scfp->cpu);
 
 	do {
+		scf_cleanup_free_list(scfp->cpu);
+
 		scftorture_invoke_one(scfp, &rand);
 		while (cpu_is_offline(cpu) && !torture_must_stop()) {
 			schedule_timeout_interruptible(HZ / 5);
-- 
2.45.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20241104105053.2182833-2-bigeasy%40linutronix.de.
