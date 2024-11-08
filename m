Return-Path: <kasan-dev+bncBCKLNNXAXYFBBE6WW64QMGQEIRYASWY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23e.google.com (mail-lj1-x23e.google.com [IPv6:2a00:1450:4864:20::23e])
	by mail.lfdr.de (Postfix) with ESMTPS id 2D3769C1AE4
	for <lists+kasan-dev@lfdr.de>; Fri,  8 Nov 2024 11:42:29 +0100 (CET)
Received: by mail-lj1-x23e.google.com with SMTP id 38308e7fff4ca-2fb6261384asf14417901fa.0
        for <lists+kasan-dev@lfdr.de>; Fri, 08 Nov 2024 02:42:29 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1731062548; cv=pass;
        d=google.com; s=arc-20240605;
        b=J9BFRMzldpVn8bcASpyhtjyTf3kue3DfZaUX9RsQd8o6p6t8JlzGBLwBvFgV90o91q
         qEex7d64FdI/UdwLYuwhhrMKsLwm55FZiFlp3wx0wsI0QSmm2OLvw/vvuwZqtyKvQevP
         6Z7NPC8wqR4HVe6BhPBZaGHjTt7a1SIaPDJshnv84JYMhl/9tZ4dwqnDxhjLSyCsO0Ee
         8DNM5wL2/KP2kdR5O4Gxtx1CfDiQhNPD2DLWPrkBNKwQThqTt8wCv41QgkSOVPJd6Vhp
         nVwypH99OrdXmPTFLpQRMXGuQzAZyUWm0+rUgV8gIh37FDWSUUQyma084gxMTcN7B3DD
         pEjA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=7Kmb+Fs2V80bpjklUAk1d/2fsG9sj+jjGohp7p9SwtY=;
        fh=HaghXidbp95XfOci3fAD1m6oujPL+RGx3YUQPNzEZiU=;
        b=MuNsvPDj1U+M029ePlgGU2S3Kq7oRUtyZm21AsstsJhAzYSnTHGZBzqY+25cpCfsiG
         yoiKZO9v9NGnBOq86Yrn4Zb/A3jh0b6FYDYLXtqSqnuBDrdkBBhvXtWfamP9JUrvdt3Q
         tnyf9TXISXIFQccIsBcAmjBFu9dVP5AbMDlm7M7ikYsgQLN+qS5DInhTpo9ebRUZVyB9
         ydJ/RSP6qU2/LMaBliqpbQTMFSvjvojK6W0unaFHpysKIh46CbFJlGT1QFmnUHXx6Mtq
         +y6KC2lE1eh0kiVUrcLPaxF9IuKQJIYSuKciHlivknd28RGhvr2ozVZ9zYShpn05exMv
         6Zdg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=xdgOfCvu;
       dkim=neutral (no key) header.i=@linutronix.de header.s=2020e;
       spf=pass (google.com: domain of bigeasy@linutronix.de designates 193.142.43.55 as permitted sender) smtp.mailfrom=bigeasy@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1731062548; x=1731667348; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=7Kmb+Fs2V80bpjklUAk1d/2fsG9sj+jjGohp7p9SwtY=;
        b=AxeSF5iukSmZNAJNJSdmi34vlB+x5/FkT/XyK4DhlEPwPitNclwkBDiyz583LAlXHE
         f46+KWpbjkASM+SuUAvOXU+Bc6Q618fWV89B+9c/5cdCm1ppbFthenSnVDqa29ViPaKc
         otwg2D6nk8x851ADFska1oHb9aB6YCL3Rf6L9Dj9FkqjvrCIlSYPSJdjh/iQ4eUaW6oR
         r3Hj0xG5BKb85r4xWJTjUFKFAN31LGvi3vc6B5NCK9xBE8nBR8ZfiyNn+Y5nnzSOkIo4
         aywadyQGAsGeyHJSx5l7CTnE4qm+FO40DsKAcNTjGqX0TiQ3wMRhh8826hhj9PNdT1ns
         IYHQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1731062548; x=1731667348;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=7Kmb+Fs2V80bpjklUAk1d/2fsG9sj+jjGohp7p9SwtY=;
        b=nveVTUEKepKqgFDYtYIEK+lsTk0NN0gYU3xHI2yTSJ1sx4MjtquzA4ReSZfaYZNS+3
         xgb3SEsXU4T6CIYhk6gJNIGkvmMksrpuzJNLG/5z1/WqokrqzEvX7RGLbP7ypt/SfncQ
         ow9+1vm8My9waAclYdI+zmpJOfM8jRrTvYJBhAeCuq1v2xP9YSyyS7CsnpygrQgvedp1
         CMjMepVWHOh7QS3qWjUAeQ62c23ROOBDGv0BzP5GJMfEUXfsL0fKcFRV91a62Zkan62L
         8LSafuBb32ha9agmApSKTzoJ/B8Z7y3fHdRRCewSbJOXRiUu9UR1bYfwg5RYhFCEMfrf
         vQqQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXQH2rEOLiSAu8pi9xpCkQvojQw+f05A9u/53ZBXs80ikcxMga6/wJCrqgY8ESYsNC4TgVxqQ==@lfdr.de
X-Gm-Message-State: AOJu0Yzcs1oX2BEO9RPN1sARrXYEGCBQttkIxiD5Qe9yBTB2LADlshS7
	EO7L/Em1KcOHfM3iHV6K1PcQ/alJoTwZsr/NMDUpXI7deWP1cGNM
X-Google-Smtp-Source: AGHT+IF3jwa8v5hsJtlmY2EXf9HyeVKkzYPnXX31t6blLu6Q3vJUOty9A9pxgpVBb+2TtKljv3Jrxg==
X-Received: by 2002:a05:6512:401d:b0:539:f922:bd4e with SMTP id 2adb3069b0e04-53d86231852mr1187487e87.23.1731062548075;
        Fri, 08 Nov 2024 02:42:28 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:ac4:b0:53c:5873:6327 with SMTP id
 2adb3069b0e04-53d8177a236ls437606e87.1.-pod-prod-01-eu; Fri, 08 Nov 2024
 02:42:25 -0800 (PST)
X-Received: by 2002:a05:6512:1581:b0:539:e0ee:4f5f with SMTP id 2adb3069b0e04-53d86230988mr1330410e87.18.1731062545358;
        Fri, 08 Nov 2024 02:42:25 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1731062545; cv=none;
        d=google.com; s=arc-20240605;
        b=Jabj4Jd9L8XYxsswrF9s+8B0mCDoNAFY0RR4l5lQtL/ihRS2iNYgECgJ3bIeRLRpDa
         M9H22Tz/+XRjayhSQ5SDOfgThmE12fUrIaMiJGe/X+JTdclJIL4inKiYVAe0vyT8coOz
         yMMj+GJq1LO+6aXbFg2NyhcpqVALDLYCDQoTqNazF9c0DRlEGH5JrQQu+itxjxXNmZvC
         1RRgFHdgWsCVVSbhd3PzKHypuTts42Ux+1p/cP6vvWqoic/pC+XcCCnq3QTh0r3KuP/T
         AFpbXEYHZdeT8xRy4gGfYZczIw5HP6hyz7jPju2zF09wYLEpjVHGdvLNjC4A9sUAoXnx
         Wl7w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:dkim-signature:dkim-signature:from;
        bh=5s/mGxOR1k0iGJwjIgx4Nn5xFVAEP6Fy1K6QavY6cWI=;
        fh=iWXmJmSNHIKwihjAFTZHxJXx+Bx4TM7umj/iDaR++1w=;
        b=UCZ30pzQl01ft4FsCTOjWFZ2eNs7tX9TehYvLrWP4r/lcKMkvGmECy+oG0n8UfsdRY
         LWzrDmpx/n1hhWXGW+I3BFFuPlJqMcFDvW3s8rYibunp374KG0+j3fOF6sEOwvJX6+g8
         BBpN+/wxL+xzXH/IIdw9WuyNGWlculHYSb2NKlp4nqVEbdksPEU/frjxCCeQVPo71cyd
         ChvLFW7JtHWHDLro+P7niNFu3R7mmXpaFxp4RIvAXRX1n+asfrtClPROXaML/sWXpK1W
         VUO9XaiEDBdwcn8rx72ccH6ifvjVYM4x6V3KHRC3acL7dpZbQWmK/b2IWI04RjzFqkDG
         OVrg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=xdgOfCvu;
       dkim=neutral (no key) header.i=@linutronix.de header.s=2020e;
       spf=pass (google.com: domain of bigeasy@linutronix.de designates 193.142.43.55 as permitted sender) smtp.mailfrom=bigeasy@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
Received: from galois.linutronix.de (Galois.linutronix.de. [193.142.43.55])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-53d8267d7fdsi66971e87.1.2024.11.08.02.42.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 08 Nov 2024 02:42:25 -0800 (PST)
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
Subject: [PATCH v3 4/4] scftorture: Use a lock-less list to free memory.
Date: Fri,  8 Nov 2024 11:39:34 +0100
Message-ID: <20241108104217.3759904-5-bigeasy@linutronix.de>
In-Reply-To: <20241108104217.3759904-1-bigeasy@linutronix.de>
References: <20241108104217.3759904-1-bigeasy@linutronix.de>
MIME-Version: 1.0
X-Original-Sender: bigeasy@linutronix.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linutronix.de header.s=2020 header.b=xdgOfCvu;       dkim=neutral
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
Tested-by: Paul E. McKenney <paulmck@kernel.org>
Signed-off-by: Sebastian Andrzej Siewior <bigeasy@linutronix.de>
---
 kernel/scftorture.c | 40 ++++++++++++++++++++++++++++++++++++----
 1 file changed, 36 insertions(+), 4 deletions(-)

diff --git a/kernel/scftorture.c b/kernel/scftorture.c
index e3c60f6dd5477..eeafd3fc16820 100644
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
@@ -529,6 +558,9 @@ static void scf_torture_cleanup(void)
 	kfree(scf_stats_p);  // -After- the last stats print has completed!
 	scf_stats_p = NULL;
 
+	for (i = 0; i < nr_cpu_ids; i++)
+		scf_cleanup_free_list(i);
+
 	if (atomic_read(&n_errs) || atomic_read(&n_mb_in_errs) || atomic_read(&n_mb_out_errs))
 		scftorture_print_module_parms("End of test: FAILURE");
 	else if (torture_onoff_failures())
-- 
2.45.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20241108104217.3759904-5-bigeasy%40linutronix.de.
