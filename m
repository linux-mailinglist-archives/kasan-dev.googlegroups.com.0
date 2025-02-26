Return-Path: <kasan-dev+bncBD56ZXUYQUBRBD7R7S6QMGQEHECYV6I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x340.google.com (mail-ot1-x340.google.com [IPv6:2607:f8b0:4864:20::340])
	by mail.lfdr.de (Postfix) with ESMTPS id B7BA2A46581
	for <lists+kasan-dev@lfdr.de>; Wed, 26 Feb 2025 16:51:44 +0100 (CET)
Received: by mail-ot1-x340.google.com with SMTP id 46e09a7af769-72737f93386sf1437614a34.3
        for <lists+kasan-dev@lfdr.de>; Wed, 26 Feb 2025 07:51:44 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1740585103; cv=pass;
        d=google.com; s=arc-20240605;
        b=dW+2JImpHd9Zf1iquFf0zf2LPdAzxmUjbCSa2UNGQ8pJt3kyC7TEWEfrciNlN0I324
         h+XWsSFB2idhzIvTmZy4iEHOPVSk9nF0pIjNsUx5FAwv3aPyDnH2cQHurO1WVnGJKd7P
         qZT+vx930MwPnlKc87MuKPLz0QjnTTidODmxf8FkGGNq4YtpNdZJ7Ww+4NGyns7yMEDi
         ms0EelQKvxFGoej1yPAKAyMT8Uv8iZMfgowClXNVmif//BqNEPM0fVRWPRjXyBxNizky
         9cW/mai8iQH/Jm0GPW6HgXgsdADQwJvFqBTuiqLxhw0vYvwFMMlhpJaFvfs8f1UHJnSU
         wjgQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=WUykdhydkLq5Hro99RBvhVLUCwk/r/Tyj7KIu8Fc2f8=;
        fh=jyRljCAlxoBypGoqRYvyTaTmctqAD1StALTXef1FyHA=;
        b=K4a8UDrEqDboryOLQGwsluE+i+hg0AiKxTPC5YxU4AVDJ8qKOPHR1FAKslaJShGHiC
         ZBvAkhpK0Uce+sjvZ1WObijLfkP0wb2FMHNr9Ypqq5PIiFQ4TSENqQDmtFqtBTzorEXV
         UIpVcnLLJd6H33vWW521aX9g/+9Rm7zOTmBFC3gPAb8aivJbF/fLgTaTRe4yZLfzxArN
         ctV7rUNHseyxkWUk7yu7RKT8d03wavXVZoRgnHcKkmlMF8NbygQbqGWXNsNfwmkBRQPc
         8k7Trj2Pbi/25AUnyM2R58IiUFwM7nslucMRtBLGtMyd46BModfhHG9G+oQ11m+4AoEJ
         R4mQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="J/wtZVHD";
       spf=pass (google.com: domain of kbusch@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=kbusch@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1740585103; x=1741189903; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=WUykdhydkLq5Hro99RBvhVLUCwk/r/Tyj7KIu8Fc2f8=;
        b=RA+wPfSEyrwTh4Z+oQaGsbcAt6qACOQ93TxrT3xB0aNy7NWap4nL8hfB72J3ymDzaT
         vQeSBqPWVhv2BiRixwyITvFqV+UPv5BQ8DH7r5txuhyW8WrKnzZW1GqMzMz6Bu21XTT2
         yCX9/b+VSTx7kQEFEZxaJPptj34bK5IsHpnCMfYGUrFrK34gtbug/qcSOiOqcqFYDr4+
         8OIvgELahTrktx8n+8PC15L4ltnU83xiqCBrJuM6Fpwn+dyiBg4WCwtKlfcmGCYVSuL2
         c9SX5DKXx2w0p83n/EzxpeS4Xdvtl6SYiI1pR/NzMRdBBuQ4ql2Wn8+sQD6U1KKjZGII
         ZJpw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1740585103; x=1741189903;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=WUykdhydkLq5Hro99RBvhVLUCwk/r/Tyj7KIu8Fc2f8=;
        b=hCsIMzCB7z3o5LTacFE5vbZ/VTrGO6Y0nZg/fmltMMzT9whHbhmlnFYMDXMiWcb+Go
         5GTDfAjL7qjGTB5JDn7TrkBc5xNvv4ANb62QTCYTydGMo10IQ2hhI7ze98otgPfy+vLi
         pLgcplqHvpqh4TnS4ggZJCaz3iGHZ+oJ4GPvDOaHBfxYWiMMLlAmw80srnGDiSoP8AbI
         LHYm7ASvlN01ZTDVZOcvJcblwsKGiWmKiz9wWgYGHdgwP72lmfXsG3JMrepdsDAcTmef
         Um9j05F36B2bTPgJOqgEtLcUYCqEZmg37PwV/NQSKxYurZnG9U9IkOPPUPKgmhsZR6Mn
         w2VQ==
X-Forwarded-Encrypted: i=2; AJvYcCV5L3Bj9rJP7UgrAPUAHJm2jLXcv3oA4HpAJ6ztb+ubwKstkE/RhWb8IV0f+8PgzpIBFGLfvA==@lfdr.de
X-Gm-Message-State: AOJu0YxpMs0IbBkHuhL3kGdWo5MuoJy8kHQa3hqNnrWQJW8XE9Hg/Avb
	/3LjkJheoJt1OadRaNXAFKc0osHnGdu9EBSe22PecpB4d/lCksmo
X-Google-Smtp-Source: AGHT+IEg52IxKe2z3Q6KM3txNHZXi39Vgat0KjzFHBowGPIcGhWQXfZBe8d/pf10ceX9DWZNkexHXg==
X-Received: by 2002:a05:6830:6f88:b0:727:24c6:87e8 with SMTP id 46e09a7af769-7274c54f9admr16663300a34.19.1740585103410;
        Wed, 26 Feb 2025 07:51:43 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h=Adn5yVHLroJnVdnEAJM/SpsixSNGEMfdq481DBeiRMFhuYeAUQ==
Received: by 2002:a05:6870:2f13:b0:29d:e970:3ca4 with SMTP id
 586e51a60fabf-2c15475539fls437fac.1.-pod-prod-02-us; Wed, 26 Feb 2025
 07:51:42 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCV1jaInQmaFAt/NHHCoEvGZ6BGrYQfVw0gchIE6Zwmo7cQfg9FoyM7txy/7AIxqqsrCFwL8FCJsSdk=@googlegroups.com
X-Received: by 2002:a05:6870:9123:b0:296:e6d9:a2e1 with SMTP id 586e51a60fabf-2bd5159fcbfmr14857677fac.11.1740585102109;
        Wed, 26 Feb 2025 07:51:42 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1740585102; cv=none;
        d=google.com; s=arc-20240605;
        b=G1nJeGjFS4mH2qNy1cohwfnREBnIg6DDYnUKCqWVFX81rdOLKcMmN4Q9ZRxlhMOssG
         ICm/aiu7ZK+TcOzIRG59HUG3Xxht2oVtWDTXI3khmfWVQMg/KhvQiTnCF2R9E3w6e5IA
         y1yVORRIUW3Z24NCDBGT2DQPagd6zr1r2PTeAFtl8JmTsveHS25PgPWTPh7NDdlEQ97n
         BEpiTMo3pFAF6Tc7hgsOaPLzdjFIs5vP9xOX0qVOJLV32MoXG2t7tl4HhlbnBdNWBY2K
         LWVq30w573vMersn/hXiFHonJFCCjfL4WDFekEI/K9dmgOxuuoyGU4+icGnH1+7KIbzQ
         naaw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=X3/aU7lmziMQt0GRz0RQ3LAAu7nNKTl6wiF2Hu6gTiY=;
        fh=8RM8XZOq8qrbeemgqYQvRCdZMlONcc7j6hRpoyw2YXw=;
        b=B6HkCPG18gu/eUgtcmZtD4aKZS0xgMzJSrvyunJXkAQjsjcHldMTDUU9Dh9gebX5XX
         N7fBccoAl6LzisrmGLUx6rqaC7sJzvIq4XujUy2m5KyERZho8+VeeoUY7pq4bHjyJFk7
         YkjbSOn8QZ23zyiOMxeIiFqZoO88n8of1kAcYj2/eYuPfCl9Gej6LvbnPmI2wJXSEEQf
         XSpOW4eQis7nLID7bx9rlm2hmScG/V8xm7egZz+NpC+YFK5Z+ysanKP7esAoKvdFupNH
         r1KVe/q2K0VfU9uD+3/M9qJR1rRnDK7svxVV+Aj7wRw9TbfMhlH88eGusPMqDO+7CmYh
         U3aw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="J/wtZVHD";
       spf=pass (google.com: domain of kbusch@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=kbusch@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id 586e51a60fabf-2c111249f7esi184179fac.2.2025.02.26.07.51.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 26 Feb 2025 07:51:42 -0800 (PST)
Received-SPF: pass (google.com: domain of kbusch@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id CCED35C5D9D;
	Wed, 26 Feb 2025 15:51:02 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 6B506C4CED6;
	Wed, 26 Feb 2025 15:51:39 +0000 (UTC)
Date: Wed, 26 Feb 2025 08:51:37 -0700
From: "'Keith Busch' via kasan-dev" <kasan-dev@googlegroups.com>
To: Uladzislau Rezki <urezki@gmail.com>
Cc: Keith Busch <keith.busch@gmail.com>, Vlastimil Babka <vbabka@suse.cz>,
	"Paul E. McKenney" <paulmck@kernel.org>,
	Joel Fernandes <joel@joelfernandes.org>,
	Josh Triplett <josh@joshtriplett.org>,
	Boqun Feng <boqun.feng@gmail.com>, Christoph Lameter <cl@linux.com>,
	David Rientjes <rientjes@google.com>,
	Steven Rostedt <rostedt@goodmis.org>,
	Mathieu Desnoyers <mathieu.desnoyers@efficios.com>,
	Lai Jiangshan <jiangshanlai@gmail.com>,
	Zqiang <qiang.zhang1211@gmail.com>,
	Julia Lawall <Julia.Lawall@inria.fr>,
	Jakub Kicinski <kuba@kernel.org>,
	"Jason A. Donenfeld" <Jason@zx2c4.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Roman Gushchin <roman.gushchin@linux.dev>,
	Hyeonggon Yoo <42.hyeyoo@gmail.com>, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org, rcu@vger.kernel.org,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>, Dmitry Vyukov <dvyukov@google.com>,
	kasan-dev@googlegroups.com, Jann Horn <jannh@google.com>,
	Mateusz Guzik <mjguzik@gmail.com>, linux-nvme@lists.infradead.org,
	leitao@debian.org
Subject: Re: [PATCH v2 6/7] mm, slab: call kvfree_rcu_barrier() from
 kmem_cache_destroy()
Message-ID: <Z784iRR13v6SkJv5@kbusch-mbp>
References: <20240807-b4-slab-kfree_rcu-destroy-v2-0-ea79102f428c@suse.cz>
 <20240807-b4-slab-kfree_rcu-destroy-v2-6-ea79102f428c@suse.cz>
 <Z7iqJtCjHKfo8Kho@kbusch-mbp>
 <2811463a-751f-4443-9125-02628dc315d9@suse.cz>
 <Z7xbrnP8kTQKYO6T@pc636>
 <ef97428b-f6e7-481e-b47e-375cc76653ad@suse.cz>
 <Z73p2lRwKagaoUnP@kbusch-mbp>
 <CAOSXXT6-oWjKPV1hzXa5Ra4SPQg0L_FvxCPM0Sh0Yk6X90h0Sw@mail.gmail.com>
 <Z74Av6tlSOqcfb-q@pc636>
 <Z74KHyGGMzkhx5f-@pc636>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <Z74KHyGGMzkhx5f-@pc636>
X-Original-Sender: kbusch@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b="J/wtZVHD";       spf=pass
 (google.com: domain of kbusch@kernel.org designates 2604:1380:4641:c500::1 as
 permitted sender) smtp.mailfrom=kbusch@kernel.org;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Keith Busch <kbusch@kernel.org>
Reply-To: Keith Busch <kbusch@kernel.org>
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

On Tue, Feb 25, 2025 at 07:21:19PM +0100, Uladzislau Rezki wrote:
> WQ_MEM_RECLAIM-patch fixes this for me:

This is successful with the new kuint test for me as well. I can't
readily test this in production where I first learned of this issue (at
least not in the near term), but for what it's worth, this looks like a
good change to me.

Reviewed-by: Keith Busch <kbusch@kernel.org>
 
> <snip>
> diff --git a/mm/slab_common.c b/mm/slab_common.c
> index 4030907b6b7d..1b5ed5512782 100644
> --- a/mm/slab_common.c
> +++ b/mm/slab_common.c
> @@ -1304,6 +1304,8 @@ module_param(rcu_min_cached_objs, int, 0444);
>  static int rcu_delay_page_cache_fill_msec = 5000;
>  module_param(rcu_delay_page_cache_fill_msec, int, 0444);
> 
> +static struct workqueue_struct *rcu_reclaim_wq;
> +
>  /* Maximum number of jiffies to wait before draining a batch. */
>  #define KFREE_DRAIN_JIFFIES (5 * HZ)
>  #define KFREE_N_BATCHES 2
> @@ -1632,10 +1634,10 @@ __schedule_delayed_monitor_work(struct kfree_rcu_cpu *krcp)
>         if (delayed_work_pending(&krcp->monitor_work)) {
>                 delay_left = krcp->monitor_work.timer.expires - jiffies;
>                 if (delay < delay_left)
> -                       mod_delayed_work(system_unbound_wq, &krcp->monitor_work, delay);
> +                       mod_delayed_work(rcu_reclaim_wq, &krcp->monitor_work, delay);
>                 return;
>         }
> -       queue_delayed_work(system_unbound_wq, &krcp->monitor_work, delay);
> +       queue_delayed_work(rcu_reclaim_wq, &krcp->monitor_work, delay);
>  }
> 
>  static void
> @@ -1733,7 +1735,7 @@ kvfree_rcu_queue_batch(struct kfree_rcu_cpu *krcp)
>                         // "free channels", the batch can handle. Break
>                         // the loop since it is done with this CPU thus
>                         // queuing an RCU work is _always_ success here.
> -                       queued = queue_rcu_work(system_unbound_wq, &krwp->rcu_work);
> +                       queued = queue_rcu_work(rcu_reclaim_wq, &krwp->rcu_work);
>                         WARN_ON_ONCE(!queued);
>                         break;
>                 }
> @@ -1883,7 +1885,7 @@ run_page_cache_worker(struct kfree_rcu_cpu *krcp)
>         if (rcu_scheduler_active == RCU_SCHEDULER_RUNNING &&
>                         !atomic_xchg(&krcp->work_in_progress, 1)) {
>                 if (atomic_read(&krcp->backoff_page_cache_fill)) {
> -                       queue_delayed_work(system_unbound_wq,
> +                       queue_delayed_work(rcu_reclaim_wq,
>                                 &krcp->page_cache_work,
>                                         msecs_to_jiffies(rcu_delay_page_cache_fill_msec));
>                 } else {
> @@ -2120,6 +2122,10 @@ void __init kvfree_rcu_init(void)
>         int i, j;
>         struct shrinker *kfree_rcu_shrinker;
> 
> +       rcu_reclaim_wq = alloc_workqueue("rcu_reclaim",
> +               WQ_UNBOUND | WQ_MEM_RECLAIM, 0);
> +       WARN_ON(!rcu_reclaim_wq);
> +
>         /* Clamp it to [0:100] seconds interval. */
>         if (rcu_delay_page_cache_fill_msec < 0 ||
>                 rcu_delay_page_cache_fill_msec > 100 * MSEC_PER_SEC) {
> <snip>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/Z784iRR13v6SkJv5%40kbusch-mbp.
