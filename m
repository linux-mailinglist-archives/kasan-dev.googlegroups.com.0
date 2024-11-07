Return-Path: <kasan-dev+bncBCS4VDMYRUNBB2UOWS4QMGQEFN6QZLY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd37.google.com (mail-io1-xd37.google.com [IPv6:2607:f8b0:4864:20::d37])
	by mail.lfdr.de (Postfix) with ESMTPS id EFE0D9C0DD2
	for <lists+kasan-dev@lfdr.de>; Thu,  7 Nov 2024 19:31:08 +0100 (CET)
Received: by mail-io1-xd37.google.com with SMTP id ca18e2360f4ac-83ac354a75fsf162920539f.0
        for <lists+kasan-dev@lfdr.de>; Thu, 07 Nov 2024 10:31:08 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1731004267; cv=pass;
        d=google.com; s=arc-20240605;
        b=RKgTjCYGqLbauVMYdiGMwoRmWdHElDPzXYuZPRsbVZO2xC24+Fmd/3yZz3PS+YiO8H
         tH6Ef990zDZaDwvDJ978u9EyezRvkFerhI+ueFPbCRU68LCGmLlolZDuXUtnp4LxGu9N
         cTqPZMx3lKVRNtCoJsJmiFkIB3mgXtZuZjW7anlO4qYuCYlx8woohAmViABy7hE5963e
         C77xLtN4NJ3O3aHQfqsmNf1jFScxcAj4tffNEb8CQ8s1Rq1FbdEuKGyUTBfzRVNwCKSP
         vcBPwgm2xqECAztPmR2qeO6YFB7x2NIaQnyj0irLpVL2a/zVmBMt/i5tvyEFifJ9se09
         znNA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:reply-to:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=nIol/YpbE9ZakmAo+O/ZBDxkS/SrD6/ScEu4+IPbQ1M=;
        fh=3mb2axaA6xHCWkJzplbbY5ecxNoeGw4msCcHp3+YinY=;
        b=lpW2dXP4b4tF7h1CRgjwEyX3CiHkqt4DjF5mGecrls92djX/RGpj4wPviwpMq1D/nk
         +5RBqO+/KDb0DKKZuTFdGQ1CfZyn2U4Tq6SZHJPW9vFDo49uegSbpc0wBm35apqQGSYt
         piIrSeV5V7+JJhLVuPmaaJPHWYT1mqTOo9hl3A8B2yq+mSi86ONmTryo203QqxYMiqZB
         6t9HWnDa0AT5buRYYoa1v7FEWdtJL+QJPNRV5q+nAduYEc6JCilAXZpuHH8wwzYyxkRJ
         +wjVIF3wQBCtsk6otVdA4tjx7dVdUxOP5pPzpKcnJ//Rib3GHDC1tTL7XoCqRapYcBtX
         ei9Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=o1vzfRD0;
       spf=pass (google.com: domain of srs0=4mwd=sc=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom="SRS0=4mwd=SC=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1731004267; x=1731609067; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:reply-to:message-id:subject:cc:to:from:date:from:to:cc
         :subject:date:message-id:reply-to;
        bh=nIol/YpbE9ZakmAo+O/ZBDxkS/SrD6/ScEu4+IPbQ1M=;
        b=qcA4hpMGXNFjBL1RCba6jKxfUSKUjhF4jers9Eu5psIr55OzVqIvGogDiPECRwjHI6
         IGscn1ubE7RujkJWAqUeQpqJvEFwItaLLIZ6ebxVtNGsoO/gLKL0zLd/JFfZs1pS+RQn
         JxbfwOfSptFlcifQnIYMP5Cd3we3yZi+8svBhTsam2lp5BlwPnt3Zk+F2I9iXwzOJkvd
         IyJiR0cqepoRjbuEoaVkXzt2qR7n7MioDmabeWfDRUC6sabl21Q6EY8EwzcL6ZT43gY1
         I9m3cKlLvLkfSumJBTfk7eWJaV+/cMZ3ruiwZDX9Gw/xUtBnu9rYbulFTIJtfBBaCxAF
         DU5w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1731004267; x=1731609067;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:reply-to:message-id
         :subject:cc:to:from:date:x-beenthere:x-gm-message-state:from:to:cc
         :subject:date:message-id:reply-to;
        bh=nIol/YpbE9ZakmAo+O/ZBDxkS/SrD6/ScEu4+IPbQ1M=;
        b=S0rq+JwNKUGXMNlIzPjCX5A5gb+9KGw9KlvkyX8wbc5o6Qewac6WvaZLk+HifUAiJd
         M0FrdbSqYS/fITEYDSlougZWt8Zx4V6u74qya3IxbUWhF3a58vID4EP821MZrKKg2Ezw
         8HVvh9f7aPWKTOmNHwqh6L5SnNnRTKPiwbbjhs+2vugaHjUPbNBdQojUJ748RLLeOhYt
         B2Ots/SJ/5YbvTyyXnrLwAhkxJXaF0DFIOdwqEC8Gr/t/XTkLEBxhhfLzyo7w+gMIOJv
         4bsdkL6jog7HEaugCHEVGEDCUJsAsQYg7ggbkO5I9EAsrkKqw85JddOckaK6uHFumrrs
         scpA==
X-Forwarded-Encrypted: i=2; AJvYcCVBoZDml3W48GlHX3BB6NVelqXQpfnEkmLf2766tzJoKNGrxxiWX6eVG+ODsSEQrdZtgx16jQ==@lfdr.de
X-Gm-Message-State: AOJu0YxLykZnlHPHhrn6PTgFvnwQY2e2LJIhQ/+n+CCwbdJxbQTJg7d5
	n2g1DSX46vw74UXooCef8qrhDiyW6SPEH1GZtzoFvgb6xJa+V2Wv
X-Google-Smtp-Source: AGHT+IHMQyoJ9hJvThjzxeOlK1+gBpRxrsqxVl9nT3Ec+o50tAV6uFN4tcXwidTr8JN9KIlKypb0kQ==
X-Received: by 2002:a05:6e02:214e:b0:3a2:f7b1:2f70 with SMTP id e9e14a558f8ab-3a6f1a759aamr2161095ab.21.1731004266995;
        Thu, 07 Nov 2024 10:31:06 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:5b2:b0:3a6:cb15:42b1 with SMTP id
 e9e14a558f8ab-3a6e81b2e9bls7520075ab.2.-pod-prod-05-us; Thu, 07 Nov 2024
 10:31:06 -0800 (PST)
X-Received: by 2002:a05:6e02:160b:b0:3a3:4164:eec9 with SMTP id e9e14a558f8ab-3a6f1a15cb8mr2562805ab.14.1731004266119;
        Thu, 07 Nov 2024 10:31:06 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1731004266; cv=none;
        d=google.com; s=arc-20240605;
        b=Wobq7n4Hply4eIMm7cTPC7vKeUI3UcYIO8tTeIIekSsun4vm7XcVftKA8+ZG5haDxr
         KwrHOJjOMYi/NCgMJ1z5dPRLE2Z2gwXndC4F2xIU/Xk3MaB8vk/zJFhJb/3P9uuaXCtM
         3BBHhu1jvui0kEjWxGPgsmgWTaysgGraUk+02FRLSS4iM2eoQLsbLnLiOE8a/2NcujpA
         tnIGahT/w1hTLykZFpX63pS81dmCvaAdpRC7tkl8zaoHwq6V95WR7IYdCFrDbazPxjdm
         6NybHaWyXuCElt7ECX4nphwG+suh0EuIHU9K6x5PMsaUK41OqH7QzM+X8pi3cWmPeuoV
         MylA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=hM76lvTyXMM6D75BpOC6JBGUh4jsFp0x+8KJFC2o35g=;
        fh=tOqXiQFh1MBU1c50ResMmGGq4rksEebGvCbKk5tb3A8=;
        b=eS4DW/zho/CRMqKttbzyqHlR4yQ88R58zJgi97q/RbSjtlRps1Pg/O2S7/FjkBZIjc
         PhsA0TJvJTiHThZu0jt+O9gOjyIJux3CcmkmGbXr0BzaXQUfhv/M5FqhVy0nQ7jk0WGe
         /ESk/aF3FYwwSm/J/3AuwzLulVDb6FvE11CVQ20F3OXqbjd3b4fLpmS88eXwVkP0lzR9
         OdAw1tMRXN+XZPq1/lhJW7WR+/ioy4IyltCdLFR6vcJhaOJ8zS0vBLvJRLQgA5d/5HNG
         ZwQNm9WDVwTpGV7fpQpKyEDuk5CR7iWn/bTv+ZYypGpbu6n/GTMMDjRc+hjMFySVj9b0
         Cn2g==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=o1vzfRD0;
       spf=pass (google.com: domain of srs0=4mwd=sc=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom="SRS0=4mwd=SC=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id e9e14a558f8ab-3a6ead5b0e6si792355ab.4.2024.11.07.10.31.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 07 Nov 2024 10:31:06 -0800 (PST)
Received-SPF: pass (google.com: domain of srs0=4mwd=sc=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id DE3E65C4957;
	Thu,  7 Nov 2024 18:30:20 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 9B5E0C4CECC;
	Thu,  7 Nov 2024 18:31:04 +0000 (UTC)
Received: by paulmck-ThinkPad-P17-Gen-1.home (Postfix, from userid 1000)
	id 46D3ECE0886; Thu,  7 Nov 2024 10:31:04 -0800 (PST)
Date: Thu, 7 Nov 2024 10:31:04 -0800
From: "'Paul E. McKenney' via kasan-dev" <kasan-dev@googlegroups.com>
To: Sebastian Andrzej Siewior <bigeasy@linutronix.de>
Cc: kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org,
	linux-mm@kvack.org, Boqun Feng <boqun.feng@gmail.com>,
	Marco Elver <elver@google.com>,
	Peter Zijlstra <peterz@infradead.org>,
	Tomas Gleixner <tglx@linutronix.de>,
	Vlastimil Babka <vbabka@suse.cz>, akpm@linux-foundation.org,
	cl@linux.com, iamjoonsoo.kim@lge.com, longman@redhat.com,
	penberg@kernel.org, rientjes@google.com, sfr@canb.auug.org.au
Subject: Re: [PATCH v2 3/3] scftorture: Use a lock-less list to free memory.
Message-ID: <abeb5162-2751-4eb1-ad0d-00a6a7ca5e70@paulmck-laptop>
Reply-To: paulmck@kernel.org
References: <20241107111821.3417762-1-bigeasy@linutronix.de>
 <20241107111821.3417762-4-bigeasy@linutronix.de>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20241107111821.3417762-4-bigeasy@linutronix.de>
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=o1vzfRD0;       spf=pass
 (google.com: domain of srs0=4mwd=sc=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org
 designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom="SRS0=4mwd=SC=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
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

On Thu, Nov 07, 2024 at 12:13:08PM +0100, Sebastian Andrzej Siewior wrote:
> scf_handler() is used as a SMP function call. This function is always
> invoked in IRQ-context even with forced-threading enabled. This function
> frees memory which not allowed on PREEMPT_RT because the locking
> underneath is using sleeping locks.
> 
> Add a per-CPU scf_free_pool where each SMP functions adds its memory to
> be freed. This memory is then freed by scftorture_invoker() on each
> iteration. On the majority of invocations the number of items is less
> than five. If the thread sleeps/ gets delayed the number exceed 350 but
> did not reach 400 in testing. These were the spikes during testing.
> The bulk free of 64 pointers at once should improve the give-back if the
> list grows. The list size is ~1.3 items per invocations.
> 
> Having one global scf_free_pool with one cleaning thread let the list
> grow to over 10.000 items with 32 CPUs (again, spikes not the average)
> especially if the CPU went to sleep. The per-CPU part looks like a good
> compromise.
> 
> Reported-by: "Paul E. McKenney" <paulmck@kernel.org>
> Closes: https://lore.kernel.org/lkml/41619255-cdc2-4573-a360-7794fc3614f7@paulmck-laptop/
> Signed-off-by: Sebastian Andrzej Siewior <bigeasy@linutronix.de>

Nice!!!

One nit at the end below.

> ---
>  kernel/scftorture.c | 39 +++++++++++++++++++++++++++++++++++----
>  1 file changed, 35 insertions(+), 4 deletions(-)
> 
> diff --git a/kernel/scftorture.c b/kernel/scftorture.c
> index 555b3b10621fe..1268a91af5d88 100644
> --- a/kernel/scftorture.c
> +++ b/kernel/scftorture.c
> @@ -97,6 +97,7 @@ struct scf_statistics {
>  static struct scf_statistics *scf_stats_p;
>  static struct task_struct *scf_torture_stats_task;
>  static DEFINE_PER_CPU(long long, scf_invoked_count);
> +static DEFINE_PER_CPU(struct llist_head, scf_free_pool);
>  
>  // Data for random primitive selection
>  #define SCF_PRIM_RESCHED	0
> @@ -133,6 +134,7 @@ struct scf_check {
>  	bool scfc_wait;
>  	bool scfc_rpc;
>  	struct completion scfc_completion;
> +	struct llist_node scf_node;
>  };
>  
>  // Use to wait for all threads to start.
> @@ -148,6 +150,31 @@ static DEFINE_TORTURE_RANDOM_PERCPU(scf_torture_rand);
>  
>  extern void resched_cpu(int cpu); // An alternative IPI vector.
>  
> +static void scf_add_to_free_list(struct scf_check *scfcp)
> +{
> +	struct llist_head *pool;
> +	unsigned int cpu;
> +
> +	cpu = raw_smp_processor_id() % nthreads;
> +	pool = &per_cpu(scf_free_pool, cpu);
> +	llist_add(&scfcp->scf_node, pool);
> +}
> +
> +static void scf_cleanup_free_list(unsigned int cpu)
> +{
> +	struct llist_head *pool;
> +	struct llist_node *node;
> +	struct scf_check *scfcp;
> +
> +	pool = &per_cpu(scf_free_pool, cpu);
> +	node = llist_del_all(pool);
> +	while (node) {
> +		scfcp = llist_entry(node, struct scf_check, scf_node);
> +		node = node->next;
> +		kfree(scfcp);
> +	}
> +}
> +
>  // Print torture statistics.  Caller must ensure serialization.
>  static void scf_torture_stats_print(void)
>  {
> @@ -296,7 +323,7 @@ static void scf_handler(void *scfc_in)
>  		if (scfcp->scfc_rpc)
>  			complete(&scfcp->scfc_completion);
>  	} else {
> -		kfree(scfcp);
> +		scf_add_to_free_list(scfcp);
>  	}
>  }
>  
> @@ -363,7 +390,7 @@ static void scftorture_invoke_one(struct scf_statistics *scfp, struct torture_ra
>  				scfp->n_single_wait_ofl++;
>  			else
>  				scfp->n_single_ofl++;
> -			kfree(scfcp);
> +			scf_add_to_free_list(scfcp);
>  			scfcp = NULL;
>  		}
>  		break;
> @@ -391,7 +418,7 @@ static void scftorture_invoke_one(struct scf_statistics *scfp, struct torture_ra
>  				preempt_disable();
>  		} else {
>  			scfp->n_single_rpc_ofl++;
> -			kfree(scfcp);
> +			scf_add_to_free_list(scfcp);
>  			scfcp = NULL;
>  		}
>  		break;
> @@ -428,7 +455,7 @@ static void scftorture_invoke_one(struct scf_statistics *scfp, struct torture_ra
>  			pr_warn("%s: Memory-ordering failure, scfs_prim: %d.\n", __func__, scfsp->scfs_prim);
>  			atomic_inc(&n_mb_out_errs); // Leak rather than trash!
>  		} else {
> -			kfree(scfcp);
> +			scf_add_to_free_list(scfcp);
>  		}
>  		barrier(); // Prevent race-reduction compiler optimizations.
>  	}
> @@ -479,6 +506,8 @@ static int scftorture_invoker(void *arg)
>  	VERBOSE_SCFTORTOUT("scftorture_invoker %d started", scfp->cpu);
>  
>  	do {
> +		scf_cleanup_free_list(cpu);
> +
>  		scftorture_invoke_one(scfp, &rand);
>  		while (cpu_is_offline(cpu) && !torture_must_stop()) {
>  			schedule_timeout_interruptible(HZ / 5);
> @@ -538,6 +567,8 @@ static void scf_torture_cleanup(void)
>  
>  end:
>  	torture_cleanup_end();
> +	for (i = 0; i < nthreads; i++)
> +		scf_cleanup_free_list(i);

It would be better for this to precede the call to torture_cleanup_end().
As soon as torture_cleanup_end() is invoked, in theory, another torture
test might start.  Yes, in practice, this would only matter if the next
module was again scftorture and you aren't supposed to modprobe a given
module until after the prior rmmod has completed, which would prevent
this scf_cleanup_free_list() from interacting with the incoming instance
of scftorture.

But why even allow the possibility?

							Thanx, Paul

>  }
>  
>  static int __init scf_torture_init(void)
> -- 
> 2.45.2
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/abeb5162-2751-4eb1-ad0d-00a6a7ca5e70%40paulmck-laptop.
