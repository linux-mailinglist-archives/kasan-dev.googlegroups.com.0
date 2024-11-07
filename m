Return-Path: <kasan-dev+bncBCKLNNXAXYFBBA6EWK4QMGQEBPU4AXQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53f.google.com (mail-ed1-x53f.google.com [IPv6:2a00:1450:4864:20::53f])
	by mail.lfdr.de (Postfix) with ESMTPS id B7E709C03B2
	for <lists+kasan-dev@lfdr.de>; Thu,  7 Nov 2024 12:18:30 +0100 (CET)
Received: by mail-ed1-x53f.google.com with SMTP id 4fb4d7f45d1cf-5c943824429sf548231a12.1
        for <lists+kasan-dev@lfdr.de>; Thu, 07 Nov 2024 03:18:30 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1730978308; cv=pass;
        d=google.com; s=arc-20240605;
        b=LP+QJNIe2Re5YiLOD0EavpuIdzaIbHtV8AbwGLtcCdiIry1dRDsJGo3PFWbqganPh8
         Z8tMZZSPbchVvOCDLtN20bFEBBzR7uGoITkRc3aCEU2EPRlOGGAnAoV1zzqVh1/vPxKZ
         FqOPdlvyHoLIaaMCin0MiQfy3cJe84izhP/dpiFw7NjpQrNPhItKmNfyMmm1EmRS00wS
         VENUjo6KIdRMhXP/Cj0Ms5+3QIwMzXsANxw3zaGjjExMo/vcZQTr41Q9S6bFCkjpfHEp
         SER8OOOa5ewcGpnfnvnJ6BppGtK336xi5hbxTruJrOJ3EP5NksrLE+i5uBZSUrj6HJ7q
         rS9w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=r7Yfo0skpp+qpviMTKTxsRUZuNy0UrjF+kyzXuJwpGA=;
        fh=mEcWzvIf8BmvBZdNe7yjMUZABMJ1qXKJ/mXGKiwNiug=;
        b=clQ9wNRYz32/E/rXnRFI+KD+22VNyc37FVRx5PNk/T7aKg3P6uXjw0cG0afdMcKwBw
         Nefbwn/hC2MDh7+WJv73j8ZlIIznhmcQg+YCejTC8Fj5ic775gR6K9ZKXKrt6R9z5IMv
         8dv/t59xFZUWKDkrwHtjxG8c1+SNokORY8jTvnjMSVOo3uMSkapQfJDCMEHOjLyWydqo
         W1wpkiCjWZvN6ykrEi4Tzm8vjUo28Y37kli93DqmTtnEOhjEjNwV6ShmgpzWwmifkRnB
         LBhJk5X1UwPa7rJ/zHDNXRa6ShAs6FYb2aJDuReRWdcjOr03b2Gr1edre8+a8iX+LMEK
         qJ+Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=hebjJzYt;
       dkim=neutral (no key) header.i=@linutronix.de header.s=2020e;
       spf=pass (google.com: domain of bigeasy@linutronix.de designates 193.142.43.55 as permitted sender) smtp.mailfrom=bigeasy@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1730978308; x=1731583108; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=r7Yfo0skpp+qpviMTKTxsRUZuNy0UrjF+kyzXuJwpGA=;
        b=mqm4T/9549l3rE+P27u4BFuhSVp+fme9dbvT9+dGcNb3Js2zjGQKDNAPcRjXAEo3wT
         HDh0utVDnSpOPE68pKvLuIlX1aDmlg4gre9aWp2amVKiXSewEvnYJ2W4Ns3d0bioBXfy
         oW9FLGMXZORivXHRECDltRZfiNInlvrulwqDE/Ei8tDpwybyh0cMdQ+gbjwdFJe5jgkG
         x9z8M8poTvgd36TZ6iLQOWhowLhVnb2xAGrwfmvYysAXBEF0dW11Zm0CImB/+buByfhn
         LsfYuizQoWvEQyukRAdhUlbZj/EOAD/cDu0K53v6vA5SnZiU+SLd/a7+TaQfMgwf6Mwv
         zJ6w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1730978308; x=1731583108;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=r7Yfo0skpp+qpviMTKTxsRUZuNy0UrjF+kyzXuJwpGA=;
        b=YKdI5w6SM9c21NUS/Dug3O6XuAw+P/gZ98Kns+LHWlNeAj/FY978hRSlVa1KIA3e0Y
         s8ehgxHTuQfTTRA5g3OKyJiUo3YZBM4OCkhTLaoMjLNzO6BVyLd9vc1VEqKRPBRRK5w7
         qAh/kTwZVU9dr1NUkA0hiw1LuWHppVEwJZKSH2c8ucj5XwNzZjvqWMpHWqlVes91FHPO
         zvcMuNJlz2ZZ3lj4WsyHSKziqBfpiGIsesI7B41P/yYhUeG6CoM47lhCTcB8m2PTY7TK
         kRSMHxnpj/z/ZxETX4Lcbumfl7FV9tRC0g4ph/vfTVIm+bI6bJCoVfavz1pj2nkSiSxf
         oMYg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWRcSNB/lJzA2Bi1cbJhKimC5LatIk48J6UZTxELe1tIvhvkEN4twKJ36FoRJR8PuDJT5mYWQ==@lfdr.de
X-Gm-Message-State: AOJu0YxI1UzsP5AMUr2hUXNnoDteVoIGJ1mvt11dNnWax2J9ixrH7+4q
	s2xP2Fe6NWLEhCNafOB5KxNRJsRvdAI4A3vC+qE4/aWEbmh2WC+a
X-Google-Smtp-Source: AGHT+IHxSiGptB/1kRp6hdlw3zRM68H1oeSfiygTo+M36Pf5+68znxhsJKUR0v14csf3+wOikibhOw==
X-Received: by 2002:a05:6402:2343:b0:5ca:152c:5b5b with SMTP id 4fb4d7f45d1cf-5cbbf8e8291mr33294761a12.21.1730978307612;
        Thu, 07 Nov 2024 03:18:27 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:2030:b0:5c8:acf3:12a7 with SMTP id
 4fb4d7f45d1cf-5cefc3c63d4ls218406a12.2.-pod-prod-09-eu; Thu, 07 Nov 2024
 03:18:25 -0800 (PST)
X-Received: by 2002:a05:6402:3488:b0:5cb:7295:49b with SMTP id 4fb4d7f45d1cf-5cbbfac2935mr32644265a12.34.1730978305174;
        Thu, 07 Nov 2024 03:18:25 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1730978305; cv=none;
        d=google.com; s=arc-20240605;
        b=K2xg2Dw20N8ZNWclmkiH3P/HPXih94jtxuzVqxws+SN0NIAeWzXQjXBljiPKEzFBpr
         F+0BxPes7+FUj26Nyl9Lw8aj6lpoDwqtzKNSIpA7sGYBAHhe67AMeYhqBshONjJcTeXT
         yM1I5GXFQp0wbxxsNeDB8x2UbFf9qEDehywWkYmBXBb/AkvE/Eg6lKop8th/MOwX4778
         3RZFk6cSR3F/rw9p6H8hCoqv0GFsJJdbuQce+5LbvODJnlqBEDOAaKmnufAr4s9EGVcb
         fVG52gQXkCgJVxfEQ1hZxJ3+RipGCJjlTU5TUjR/kyAAvmQpzfG8okG+LpaJvK4/XQc8
         3s3Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:dkim-signature:dkim-signature:from;
        bh=UREpr2g7dNESBp66vCKny1OLw5nYLTave8FGBQMbiqs=;
        fh=iWXmJmSNHIKwihjAFTZHxJXx+Bx4TM7umj/iDaR++1w=;
        b=VlmvK5/z7odxFy/A2DwVBsQRPLoAVe/n6Z+4uxo64izqBr6DkD1wh3Pybg6Y6xQnEr
         gx0GYVYh9dXHY58VrmXMsDQngETIEH2KytBE7981inHsemw0Z9G4Xb3uzck/Fgwhjffg
         SsY9P1x779teBgPjLauRrYVohDybK3jfFP71RbNtIgqOGYu2knY7VOzeB2pC+PfO3zhh
         Q/lcf4+b4yWQ9qfEmBgU9edBh7Q0al+GB9XNj7uFnl+6ZhwmYyVhWpeIBWNNzzHJc5mW
         E74fBk33pB1P+jOYDYIFQldLUkBsegIxsbge4vvGoGchuX/P3bYymHyVDNp5bpOe6bvB
         vHdQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=hebjJzYt;
       dkim=neutral (no key) header.i=@linutronix.de header.s=2020e;
       spf=pass (google.com: domain of bigeasy@linutronix.de designates 193.142.43.55 as permitted sender) smtp.mailfrom=bigeasy@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
Received: from galois.linutronix.de (Galois.linutronix.de. [193.142.43.55])
        by gmr-mx.google.com with ESMTPS id 4fb4d7f45d1cf-5cf03b618a6si18151a12.1.2024.11.07.03.18.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 07 Nov 2024 03:18:25 -0800 (PST)
Received-SPF: pass (google.com: domain of bigeasy@linutronix.de designates 193.142.43.55 as permitted sender) client-ip=193.142.43.55;
From: Sebastian Andrzej Siewior <bigeasy@linutronix.de>
To: kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org,
	linux-mm@kvack.org
Cc: "Paul E. McKenney" <paulmck@kernel.org>,
	Boqun Feng <boqun.feng@gmail.com>,
	Marco Elver <elver@google.com>,
	Peter Zijlstra <peterz@infradead.org>,
	Tomas Gleixner <tglx@linutronix.de>,
	Vlastimil Babka <vbabka@suse.cz>,
	akpm@linux-foundation.org,
	cl@linux.com,
	iamjoonsoo.kim@lge.com,
	longman@redhat.com,
	penberg@kernel.org,
	rientjes@google.com,
	sfr@canb.auug.org.au,
	Sebastian Andrzej Siewior <bigeasy@linutronix.de>
Subject: [PATCH v2 3/3] scftorture: Use a lock-less list to free memory.
Date: Thu,  7 Nov 2024 12:13:08 +0100
Message-ID: <20241107111821.3417762-4-bigeasy@linutronix.de>
In-Reply-To: <20241107111821.3417762-1-bigeasy@linutronix.de>
References: <20241107111821.3417762-1-bigeasy@linutronix.de>
MIME-Version: 1.0
X-Original-Sender: bigeasy@linutronix.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linutronix.de header.s=2020 header.b=hebjJzYt;       dkim=neutral
 (no key) header.i=@linutronix.de header.s=2020e;       spf=pass (google.com:
 domain of bigeasy@linutronix.de designates 193.142.43.55 as permitted sender)
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
 kernel/scftorture.c | 39 +++++++++++++++++++++++++++++++++++----
 1 file changed, 35 insertions(+), 4 deletions(-)

diff --git a/kernel/scftorture.c b/kernel/scftorture.c
index 555b3b10621fe..1268a91af5d88 100644
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
@@ -148,6 +150,31 @@ static DEFINE_TORTURE_RANDOM_PERCPU(scf_torture_rand);
 
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
+
+	pool = &per_cpu(scf_free_pool, cpu);
+	node = llist_del_all(pool);
+	while (node) {
+		scfcp = llist_entry(node, struct scf_check, scf_node);
+		node = node->next;
+		kfree(scfcp);
+	}
+}
+
 // Print torture statistics.  Caller must ensure serialization.
 static void scf_torture_stats_print(void)
 {
@@ -296,7 +323,7 @@ static void scf_handler(void *scfc_in)
 		if (scfcp->scfc_rpc)
 			complete(&scfcp->scfc_completion);
 	} else {
-		kfree(scfcp);
+		scf_add_to_free_list(scfcp);
 	}
 }
 
@@ -363,7 +390,7 @@ static void scftorture_invoke_one(struct scf_statistics *scfp, struct torture_ra
 				scfp->n_single_wait_ofl++;
 			else
 				scfp->n_single_ofl++;
-			kfree(scfcp);
+			scf_add_to_free_list(scfcp);
 			scfcp = NULL;
 		}
 		break;
@@ -391,7 +418,7 @@ static void scftorture_invoke_one(struct scf_statistics *scfp, struct torture_ra
 				preempt_disable();
 		} else {
 			scfp->n_single_rpc_ofl++;
-			kfree(scfcp);
+			scf_add_to_free_list(scfcp);
 			scfcp = NULL;
 		}
 		break;
@@ -428,7 +455,7 @@ static void scftorture_invoke_one(struct scf_statistics *scfp, struct torture_ra
 			pr_warn("%s: Memory-ordering failure, scfs_prim: %d.\n", __func__, scfsp->scfs_prim);
 			atomic_inc(&n_mb_out_errs); // Leak rather than trash!
 		} else {
-			kfree(scfcp);
+			scf_add_to_free_list(scfcp);
 		}
 		barrier(); // Prevent race-reduction compiler optimizations.
 	}
@@ -479,6 +506,8 @@ static int scftorture_invoker(void *arg)
 	VERBOSE_SCFTORTOUT("scftorture_invoker %d started", scfp->cpu);
 
 	do {
+		scf_cleanup_free_list(cpu);
+
 		scftorture_invoke_one(scfp, &rand);
 		while (cpu_is_offline(cpu) && !torture_must_stop()) {
 			schedule_timeout_interruptible(HZ / 5);
@@ -538,6 +567,8 @@ static void scf_torture_cleanup(void)
 
 end:
 	torture_cleanup_end();
+	for (i = 0; i < nthreads; i++)
+		scf_cleanup_free_list(i);
 }
 
 static int __init scf_torture_init(void)
-- 
2.45.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20241107111821.3417762-4-bigeasy%40linutronix.de.
