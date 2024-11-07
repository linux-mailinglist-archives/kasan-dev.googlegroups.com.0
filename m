Return-Path: <kasan-dev+bncBCS4VDMYRUNBBYPNWS4QMGQE3U37KNY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x540.google.com (mail-pg1-x540.google.com [IPv6:2607:f8b0:4864:20::540])
	by mail.lfdr.de (Postfix) with ESMTPS id C93409C1156
	for <lists+kasan-dev@lfdr.de>; Thu,  7 Nov 2024 22:53:39 +0100 (CET)
Received: by mail-pg1-x540.google.com with SMTP id 41be03b00d2f7-7ea8baba60dsf1375432a12.3
        for <lists+kasan-dev@lfdr.de>; Thu, 07 Nov 2024 13:53:39 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1731016418; cv=pass;
        d=google.com; s=arc-20240605;
        b=DZNNqmw7MzIl9Fn1kgbOispk5CEFp/Gnp4DkeXbtuS1EqxuW11mbRMocaErH9cQhpV
         VWDnKDKQUzcfI2Ia4l8zCK3eWqawwwCXgRb1qkU1A3tiTGNGcHnFYUTUXDPKe1H8weyp
         IFhxqDSsDeMympfkM1d/KLoUsESyhg1vSPLCw0+L8qCvfbLxzqbthMBWdjAXpP9HPx0M
         IOElfD6yBL4il+0QHe3o6l/QZvv9x527/1Epw/CiLn/8lBy0XZU8hZh0TFp6FVQUg81Q
         ILX6UT4XWWivkATAVRwUqSMR+VBWQIicy4OcnqceqArsuPPJsWYbGVwBv7Emu//rhV7T
         l4ww==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:reply-to:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=iWHSMs8DlT1fagTau4g7sEauQF7MjnxLqxON/RvyQ8w=;
        fh=cBLf4leFCdfhNBczMdaNbsE3Kvf9BtOYM8ZnM/ZbIfQ=;
        b=deYv13kFPxBY2FpYTZOaTxgAYJVg1GfQBdUQCNRLS8dPQ3cbs3RpoFGZ6GNJJ5VnL/
         /81th6ABXaxnE1m/AmTbMDq5qxuQ5rNdXi6rcjMbraKOFUJnHwXK4tjSSz3wZxRSsRt+
         r0sFsqfAjYcTcaOx6mDPjGMpbKI7Dkfm4QEFjZujC7xjxerCXIqoWitNKL6biU89DzCr
         6pCOlz8Rrq5+Q78M0VLwE+x8BA7Twvwt0/dRm3XcuJ6WKCcl3VzEZWb+QZOr1jS3RqXN
         2w46vQTchR+eWnGSkGz/tpG+J2DDtav87leU2Fh8hbfe86UQZUXCt4/zHACfOAi1brJZ
         YOpg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="cbPWwZD/";
       spf=pass (google.com: domain of srs0=4mwd=sc=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom="SRS0=4mwd=SC=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1731016418; x=1731621218; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:reply-to:message-id:subject:cc:to:from:date:from:to:cc
         :subject:date:message-id:reply-to;
        bh=iWHSMs8DlT1fagTau4g7sEauQF7MjnxLqxON/RvyQ8w=;
        b=Y8d8cmTRal3UaaCYI70N+f6u2wz/hdwEntCpumk+XgWGIiva4TTwRAZ4i3LBZlIin5
         2mn3kEOV2fv1AT/jaY4JrGy8WaRxt+ZLSpiqGoDmsk4GuZhcfvlu4eSajJhD2wdlSm5O
         SEMfuac40YgQPSnG9ZhDQsDTIjc5ghXropTgT33TzI+uXuDhUq7YAGYZ5a0ScQm8S3m6
         qTas4b3shAV1JK9EuAuK1tBvrLo6lvWtny9j9ScBQ3nKE1nn5U5l/yAwcsFokmbUiYqz
         8oTXYgi0tX/7DYBLVisB8t13MHO28w6VFIJzixXNSYWLec4ylGY5n1WHSoms58ni1gUw
         7Cnw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1731016418; x=1731621218;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:reply-to:message-id
         :subject:cc:to:from:date:x-beenthere:x-gm-message-state:from:to:cc
         :subject:date:message-id:reply-to;
        bh=iWHSMs8DlT1fagTau4g7sEauQF7MjnxLqxON/RvyQ8w=;
        b=gO/qY+eJVInb0oTu/TXIqfqYwxp5P+cv2doa0PzUWuVfneh0BjaM55a4NhkAE1NN0G
         2ibX0LI0LqYUMudSfuhYNmWinC7ygWREPA3Rj5mqve7PHuhUEuQH5rtHf+bDa1BTCJz0
         9gSNm42+03ZkkjvyWq3CXqVVO2hVk4jhHaBysPo8gCQfoTxTs3dXIJ7Z6w54fIhtmbfT
         3JaeQObe/MHXwto0P+2zC/PiV2ysKxv8xNGQmG3XnjZ5asyE+Rnu90I8DyKAEMMhFZRh
         wo+RMzkwJVmetAS+JwSWVMXkBa2Se2YW5BU9z5pxzJoPcCfKEKPHthIsYhTlHf0fwgHQ
         Tx2w==
X-Forwarded-Encrypted: i=2; AJvYcCWi+Gm4tUReyG1byVnl4FmhgA+PPCtSI5V87caKJU8SYdmEwZiKu6sUc7vMpyvqhVPLkhb62A==@lfdr.de
X-Gm-Message-State: AOJu0Yy/xK49GxjHFBSVXF08N4DZQ+mvmRILE7VBIzR5ij5D4agmykjn
	hABcqBy6WiXbwiBpkG7VcqCgChoTpu7dPELPPFq1fA+LMMkRId4Y
X-Google-Smtp-Source: AGHT+IFw9MO3C4/WSEDZvcdm33sbgSPQ0YDJUIfZ/nnzEgVZvmUIImRXZB+MaELoP42OHTBm/7ponQ==
X-Received: by 2002:a17:90b:4c48:b0:2e1:a81f:5520 with SMTP id 98e67ed59e1d1-2e9b166bbaamr1146677a91.1.1731016417847;
        Thu, 07 Nov 2024 13:53:37 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:6286:b0:2e2:a2ab:516c with SMTP id
 98e67ed59e1d1-2e9a4051a19ls1070849a91.1.-pod-prod-02-us; Thu, 07 Nov 2024
 13:53:36 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUr2fsULjQcVpIX0Ews/H0IoUITcQ7B3Ym2Al7NE6XnKO5DLhnQfHgq2ponMv0714Esx7V9AVQfbj0=@googlegroups.com
X-Received: by 2002:a17:90b:3bc7:b0:2e2:c64c:a1c9 with SMTP id 98e67ed59e1d1-2e9b1740f5bmr970157a91.24.1731016416343;
        Thu, 07 Nov 2024 13:53:36 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1731016416; cv=none;
        d=google.com; s=arc-20240605;
        b=Ks2ACO/4OLUTqWC5bP2JHUaFIjSXRpCS4l+WDmzXYJGi9XVZD2nuYV1X0w+eTGYJsS
         1wLE08gFreyxvqvJOtpPCCIPnOP2LosP+yNsUkIzZ5biJ0OhZcSKBDS+H11rdPxk+jho
         V/tZ/szGV2YfPwWC35HoJYBRQYH6h3F5BQY3n5JQ19RhgnJn7/dfFe8Jr8fTt9KUCI2R
         shtEtudL2P/njU7+O/9WY0F8Z+OU9GdqQIKIKYXTTv4HpsQhsGeZ7T3nWGuW1fTuoHpl
         B4KOX7oOdrVU2wylLjFmf+HMYplpXS/4qhiNeCTNTHTpbsojTlyQUIb6NtTnPxnmAoP5
         rhlQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=cRm0isev75vj6KIAyinBLv/nOPwuVxeywRUyjldZpww=;
        fh=yIs5K4xDMrEq+My51TTmB1y48I0qd9EjjSdtSz1cYDY=;
        b=kwx28XIguiT+EMESxkgL4Jp+8e0bTZB1s2klPL9RuKxAJaL5TjUE+D46vCpT8LkOL7
         HycB4pcHIn/JkxX+qQl2iV2WYEhYLW9yB2OaNbfCCsXX3adldAI+5rgOEUxC2xmhSj45
         fHYUaZJlge2jQ6UXjbKCZLpL70vSDDdVVfOKwbeI3Q8pwok9QO7HHOpfpPRhLUq8xESh
         nIy8K3mqd8fUuwavPNmDJhBduDm55dpHgGolTxKKjKbBuuLf2Oymk4tGl9q1OhQb6zOi
         wbsBlkaJ8UnPhQMXJTKHRn8R7jZfSbe+jp5pEkRvub/OiLjhHEMK6x/dNWR2FKb5AiQs
         WAZw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="cbPWwZD/";
       spf=pass (google.com: domain of srs0=4mwd=sc=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom="SRS0=4mwd=SC=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-2e98ca46a88si316388a91.1.2024.11.07.13.53.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 07 Nov 2024 13:53:36 -0800 (PST)
Received-SPF: pass (google.com: domain of srs0=4mwd=sc=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id DE3775C543B;
	Thu,  7 Nov 2024 21:52:50 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 3A300C4CECC;
	Thu,  7 Nov 2024 21:53:35 +0000 (UTC)
Received: by paulmck-ThinkPad-P17-Gen-1.home (Postfix, from userid 1000)
	id D6585CE0F1C; Thu,  7 Nov 2024 13:53:34 -0800 (PST)
Date: Thu, 7 Nov 2024 13:53:34 -0800
From: "'Paul E. McKenney' via kasan-dev" <kasan-dev@googlegroups.com>
To: Boqun Feng <boqun.feng@gmail.com>
Cc: Sebastian Andrzej Siewior <bigeasy@linutronix.de>,
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org,
	linux-mm@kvack.org, Marco Elver <elver@google.com>,
	Peter Zijlstra <peterz@infradead.org>,
	Tomas Gleixner <tglx@linutronix.de>,
	Vlastimil Babka <vbabka@suse.cz>, akpm@linux-foundation.org,
	cl@linux.com, iamjoonsoo.kim@lge.com, longman@redhat.com,
	penberg@kernel.org, rientjes@google.com, sfr@canb.auug.org.au
Subject: Re: [PATCH v2 3/3] scftorture: Use a lock-less list to free memory.
Message-ID: <8714bdf6-e257-446c-855f-0f4e65e2921e@paulmck-laptop>
Reply-To: paulmck@kernel.org
References: <20241107111821.3417762-1-bigeasy@linutronix.de>
 <20241107111821.3417762-4-bigeasy@linutronix.de>
 <Zy0m5TBz3Ne55syG@Boquns-Mac-mini.local>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <Zy0m5TBz3Ne55syG@Boquns-Mac-mini.local>
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b="cbPWwZD/";       spf=pass
 (google.com: domain of srs0=4mwd=sc=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org
 designates 139.178.84.217 as permitted sender) smtp.mailfrom="SRS0=4mwd=SC=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: "Paul E. McKenney" <paulmck@kernel.org>
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

On Thu, Nov 07, 2024 at 12:45:25PM -0800, Boqun Feng wrote:
> On Thu, Nov 07, 2024 at 12:13:08PM +0100, Sebastian Andrzej Siewior wrote:
> > scf_handler() is used as a SMP function call. This function is always
> > invoked in IRQ-context even with forced-threading enabled. This function
> > frees memory which not allowed on PREEMPT_RT because the locking
> > underneath is using sleeping locks.
> > 
> > Add a per-CPU scf_free_pool where each SMP functions adds its memory to
> > be freed. This memory is then freed by scftorture_invoker() on each
> > iteration. On the majority of invocations the number of items is less
> > than five. If the thread sleeps/ gets delayed the number exceed 350 but
> > did not reach 400 in testing. These were the spikes during testing.
> > The bulk free of 64 pointers at once should improve the give-back if the
> > list grows. The list size is ~1.3 items per invocations.
> > 
> > Having one global scf_free_pool with one cleaning thread let the list
> > grow to over 10.000 items with 32 CPUs (again, spikes not the average)
> > especially if the CPU went to sleep. The per-CPU part looks like a good
> > compromise.
> > 
> > Reported-by: "Paul E. McKenney" <paulmck@kernel.org>
> > Closes: https://lore.kernel.org/lkml/41619255-cdc2-4573-a360-7794fc3614f7@paulmck-laptop/
> > Signed-off-by: Sebastian Andrzej Siewior <bigeasy@linutronix.de>
> > ---
> >  kernel/scftorture.c | 39 +++++++++++++++++++++++++++++++++++----
> >  1 file changed, 35 insertions(+), 4 deletions(-)
> > 
> > diff --git a/kernel/scftorture.c b/kernel/scftorture.c
> > index 555b3b10621fe..1268a91af5d88 100644
> > --- a/kernel/scftorture.c
> > +++ b/kernel/scftorture.c
> > @@ -97,6 +97,7 @@ struct scf_statistics {
> >  static struct scf_statistics *scf_stats_p;
> >  static struct task_struct *scf_torture_stats_task;
> >  static DEFINE_PER_CPU(long long, scf_invoked_count);
> > +static DEFINE_PER_CPU(struct llist_head, scf_free_pool);
> >  
> >  // Data for random primitive selection
> >  #define SCF_PRIM_RESCHED	0
> > @@ -133,6 +134,7 @@ struct scf_check {
> >  	bool scfc_wait;
> >  	bool scfc_rpc;
> >  	struct completion scfc_completion;
> > +	struct llist_node scf_node;
> >  };
> >  
> >  // Use to wait for all threads to start.
> > @@ -148,6 +150,31 @@ static DEFINE_TORTURE_RANDOM_PERCPU(scf_torture_rand);
> >  
> >  extern void resched_cpu(int cpu); // An alternative IPI vector.
> >  
> > +static void scf_add_to_free_list(struct scf_check *scfcp)
> > +{
> > +	struct llist_head *pool;
> > +	unsigned int cpu;
> > +
> > +	cpu = raw_smp_processor_id() % nthreads;
> > +	pool = &per_cpu(scf_free_pool, cpu);
> > +	llist_add(&scfcp->scf_node, pool);
> > +}
> > +
> > +static void scf_cleanup_free_list(unsigned int cpu)
> > +{
> > +	struct llist_head *pool;
> > +	struct llist_node *node;
> > +	struct scf_check *scfcp;
> > +
> > +	pool = &per_cpu(scf_free_pool, cpu);
> > +	node = llist_del_all(pool);
> > +	while (node) {
> > +		scfcp = llist_entry(node, struct scf_check, scf_node);
> > +		node = node->next;
> > +		kfree(scfcp);
> > +	}
> > +}
> > +
> >  // Print torture statistics.  Caller must ensure serialization.
> >  static void scf_torture_stats_print(void)
> >  {
> > @@ -296,7 +323,7 @@ static void scf_handler(void *scfc_in)
> >  		if (scfcp->scfc_rpc)
> >  			complete(&scfcp->scfc_completion);
> >  	} else {
> > -		kfree(scfcp);
> > +		scf_add_to_free_list(scfcp);
> >  	}
> >  }
> >  
> > @@ -363,7 +390,7 @@ static void scftorture_invoke_one(struct scf_statistics *scfp, struct torture_ra
> >  				scfp->n_single_wait_ofl++;
> >  			else
> >  				scfp->n_single_ofl++;
> > -			kfree(scfcp);
> > +			scf_add_to_free_list(scfcp);
> >  			scfcp = NULL;
> >  		}
> >  		break;
> > @@ -391,7 +418,7 @@ static void scftorture_invoke_one(struct scf_statistics *scfp, struct torture_ra
> >  				preempt_disable();
> >  		} else {
> >  			scfp->n_single_rpc_ofl++;
> > -			kfree(scfcp);
> > +			scf_add_to_free_list(scfcp);
> >  			scfcp = NULL;
> >  		}
> >  		break;
> > @@ -428,7 +455,7 @@ static void scftorture_invoke_one(struct scf_statistics *scfp, struct torture_ra
> >  			pr_warn("%s: Memory-ordering failure, scfs_prim: %d.\n", __func__, scfsp->scfs_prim);
> >  			atomic_inc(&n_mb_out_errs); // Leak rather than trash!
> >  		} else {
> > -			kfree(scfcp);
> > +			scf_add_to_free_list(scfcp);
> >  		}
> >  		barrier(); // Prevent race-reduction compiler optimizations.
> >  	}
> > @@ -479,6 +506,8 @@ static int scftorture_invoker(void *arg)
> >  	VERBOSE_SCFTORTOUT("scftorture_invoker %d started", scfp->cpu);
> >  
> >  	do {
> > +		scf_cleanup_free_list(cpu);
> > +
> >  		scftorture_invoke_one(scfp, &rand);
> >  		while (cpu_is_offline(cpu) && !torture_must_stop()) {
> >  			schedule_timeout_interruptible(HZ / 5);
> > @@ -538,6 +567,8 @@ static void scf_torture_cleanup(void)
> >  
> >  end:
> >  	torture_cleanup_end();
> > +	for (i = 0; i < nthreads; i++)
> 
> This needs to be:
> 
> 	for (i = 0; i < nr_cpu_ids; i++)
> 
> because nthreads can be larger than nr_cpu_ids, and it'll access a
> out-of-bound percpu section.

I clearly did not test thoroughly enough.  Good catch!!!

							Thanx, Paul

> Regards,
> Boqun
> 
> > +		scf_cleanup_free_list(i);
> >  }
> >  
> >  static int __init scf_torture_init(void)
> > -- 
> > 2.45.2
> > 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/8714bdf6-e257-446c-855f-0f4e65e2921e%40paulmck-laptop.
