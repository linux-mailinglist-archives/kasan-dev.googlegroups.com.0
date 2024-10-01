Return-Path: <kasan-dev+bncBC7OBJGL2MHBBA4H6C3QMGQEYFTU4BY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43d.google.com (mail-wr1-x43d.google.com [IPv6:2a00:1450:4864:20::43d])
	by mail.lfdr.de (Postfix) with ESMTPS id 793D298BF54
	for <lists+kasan-dev@lfdr.de>; Tue,  1 Oct 2024 16:13:25 +0200 (CEST)
Received: by mail-wr1-x43d.google.com with SMTP id ffacd0b85a97d-37cccd94a69sf2678970f8f.0
        for <lists+kasan-dev@lfdr.de>; Tue, 01 Oct 2024 07:13:25 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1727792005; cv=pass;
        d=google.com; s=arc-20240605;
        b=RC4+GXc/yvupqvBsJ0KWnleGt9nwX87gVKumcMWLZrTe2Udfi2wXQBUEkol9iTBuga
         ukoO53OQiFPImEZKE9Vxv5Z1KTfo6g5sZ9HhSHm5DEvMNSo61olthWAIW0LerJcV69Zc
         +OAOWzncASS362Y0LURezXP+Fbf44DAoIddT1nrjbdulUb357CNnWwEfIu2Vm+63Kllf
         yAuXQBgSmrNcZflGmlQBPHC+1+e+dF6yMLYsdqn9jSWGF2kUAnw3aDXspl95CODtKwOc
         RjhvywbEXPcK0HLlHo/uH/UROs1MQZPvp9v9+PGzWpQndfLK+kdM569JPgVkqsxZA/bM
         buYw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=8mWFN4QrAFpOd6dF7e1AcGYhtAXDa/rgCnxhS99QDy4=;
        fh=BbUvvC2bNrlkKwWbIk4L4JPBr9Ljk8JJxJKvZlc4jbk=;
        b=CKXeQvLJnA9xlmFeVcDCzVTKdfv9TOj6WswiYcBc1zC3R6ulCQ21M+nna0L8Z9LQf3
         /ykUCPXCqieJQbP/2oeRdPyeLbNbRYKJ4zy+q14wRyXoHYUq+GDfOUDdVR5eAhXQtnhv
         S3r32xsWhD63AKGxpY2tW31hcoyVDpFSP9Lst1MEOs8QdRq2E03o3MHyoVRqHciCCXxN
         2IrQI1Ew28y4oNu7+wTdX95qzryhlELkplq4y4OaOwvQDdWCrM5e0ZXfr7VLit8h1WV0
         2oEcihwGfLJQnolWrBU9fgNEB7PI1McSBvrGn5vXeVMvAXcV3n9y7wuoCk7QAHIss04K
         nS/w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=vjy7eVp0;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::329 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1727792005; x=1728396805; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:user-agent
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=8mWFN4QrAFpOd6dF7e1AcGYhtAXDa/rgCnxhS99QDy4=;
        b=hrAIr+KVoI2mxUjxl6t+YCkhtwrnWkPPfQJBCY0WqZiwfe7LOdjlTOojWw72zRbh5Q
         n/Y7W0Pl/DWm8f2ohLWmCS3o1htl3i3pcZxTciMiQ9DPyAH/ghpogYNkBFMyESMDvySC
         MQ5ll1s/NogHORcWSzCJA9oas+QqH0gIz9KSauO+F3MFQ55Ob287pndKn4KTmkadVVtj
         Nt5LdMnYfZWxbYyEZ/2TI4nHYY2W9Jhjk9t4nHlrzKMXbfNk+3zyN4xOyg7BpVSa0iYE
         Y43/dN59fPR/VjrpOkhs7SeTIZ+T7tD8ELlGim3hwO95gOBdtqPkClnGtBNDejVmaNbo
         Cnzg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1727792005; x=1728396805;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:user-agent
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:x-beenthere:x-gm-message-state:from:to:cc
         :subject:date:message-id:reply-to;
        bh=8mWFN4QrAFpOd6dF7e1AcGYhtAXDa/rgCnxhS99QDy4=;
        b=fkLlW349V1+upklAhuvR7KYXgMfWrNw019w83Vn9E1q0AIw/OA4cEko8YcIj6IXsxK
         3M/x96jrqB6M1GcQpXtFDNTdDGS9ZEPHA428cVEcJkQhUpE5oipEQ2UNHlyWarX0/YoE
         5ihXOoUhe7RXarolYhiNiZcPgartbo2OTrhvWmrdITVnkkiCRWwId0K2NEn3YoAA0glM
         WcAaSMFicge746vDzRcSrmMOPeucouqBr8wPa2bbSABMN+nOxuGtqNNAE5OYI4M/eHOw
         o+FSTf35Yzy3Tj+4B8r891FMqN6brIyUa849Br8VN8q3XZObKtjzFM0r6+PCepXURHeA
         yHJA==
X-Forwarded-Encrypted: i=2; AJvYcCXErqMYnWRsL8NL74R7zPFDssZhmLcF2nTyk0wmvsLucUC/FJ7u4lzNA5Xr3FuVkgF4cuonpQ==@lfdr.de
X-Gm-Message-State: AOJu0YyXJoQBpnv9IJVoIlF5BZq4vG8UCSmzokLmxIK3upRQV5112DRP
	XoPPMHxGqomzYlR1uHNDQrgc4k5Px2VbmJlpz88qrzfoAeg6h171
X-Google-Smtp-Source: AGHT+IFbzititnTRiP+kkTy8/AnYdJPc6gKzQYRwLCKowFLJoehPrS6plu7x6CoDBauv0nSgXUU9/w==
X-Received: by 2002:a5d:564a:0:b0:374:b71f:72c0 with SMTP id ffacd0b85a97d-37cd5a9ed70mr9043912f8f.21.1727792004187;
        Tue, 01 Oct 2024 07:13:24 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:56ce:0:b0:374:c9ad:49bf with SMTP id ffacd0b85a97d-37ccdaee53cls883578f8f.0.-pod-prod-02-eu;
 Tue, 01 Oct 2024 07:13:22 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUgQjFgorV4DfXhpXRaKYwpn44Gv3jfsprhR2Tjrrg49asQu23ImZWNDctrnyGgRVEgtZd0CBNxi1w=@googlegroups.com
X-Received: by 2002:adf:fc09:0:b0:371:a844:d326 with SMTP id ffacd0b85a97d-37cd5b10634mr8559628f8f.43.1727792002013;
        Tue, 01 Oct 2024 07:13:22 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1727792001; cv=none;
        d=google.com; s=arc-20240605;
        b=OhlUEVH1cFx3AOl9BPCSr3IeuL/2cdYKfjvsnpm49/+e+pF3d7J0OgHHuHHf8/a9Zw
         HTlnIGUWieI8RnazffWfLz2Wswcrs/F3F32kw1muqIR4JysEqE+CfsT3f6gTVbg0ap2T
         1ux5prfLpcrUHcwNOjp+JM4h8ukiELmxBRsbR38VSDA3u/C9ArK1bnwEImHIlch87roj
         QsDpYOsghpgeCZQWxaDqt/Yf5V/35HteIUkewJhz9/0LMQ2hytNuoeE5h9C2OSVCydck
         uRdqSyKDBWwJ8zE0mpkGWiaDHn3hVOYQ2O6oK7yAoejdK9zTgAElBZsuwV8IfLOj4VBl
         /50w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=5uAVLa6jHgMD7nykfCkBu85ErdpyyKq2zMpzHNmQ1oM=;
        fh=pvb1qwsvaXKi+iNUIJyzeaC9/9hlhiME2jC5xNt1o/Q=;
        b=Tj+n89fBlWIRudSy2vIe2sex6aDqKdaZT22VXIv3gqIua99SuBETzCRRPUX5BLWgbD
         mh/c5cfF8eXJ3Y+ru27SSzDahLSfK7AuiFFc+xSgVIkFVLcwQtypjMPBKVjbSJw5qkWR
         ALvOy0t6aneffvBkXr5IIIPfdyfHZ/fsL7BGf0wNC4QqrOHQZ14dCQA+h2VTeE6VtHDI
         jtV13yLp75S9r7BadQCAqgvYtMTWYYV9+YwsP5g+50skFMizdrLU11X3AiH3JpY4Hu/q
         CBn06+pxf7jP1cWriP84wdY08gWqG31zAD+e/K0qQw8MmXT+Y1YTD8+OW2Ok7/LZS5NZ
         MRQw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=vjy7eVp0;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::329 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x329.google.com (mail-wm1-x329.google.com. [2a00:1450:4864:20::329])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-42f73046aeasi1145175e9.0.2024.10.01.07.13.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 01 Oct 2024 07:13:21 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::329 as permitted sender) client-ip=2a00:1450:4864:20::329;
Received: by mail-wm1-x329.google.com with SMTP id 5b1f17b1804b1-42cb1e623d1so51779425e9.0
        for <kasan-dev@googlegroups.com>; Tue, 01 Oct 2024 07:13:21 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCX56oP9AnCAlLtRZyjbOzZSuphzSDPx3zKySYE7LI32HKMLMRz03iGmYD5rdeP0jnR2mX4SCpUhTGk=@googlegroups.com
X-Received: by 2002:a05:600c:5125:b0:42c:b22e:fc2e with SMTP id 5b1f17b1804b1-42f5844b601mr126150115e9.15.1727792001106;
        Tue, 01 Oct 2024 07:13:21 -0700 (PDT)
Received: from elver.google.com ([2a00:79e0:9c:201:72e:46e:f572:615b])
        by smtp.gmail.com with ESMTPSA id 5b1f17b1804b1-42e969ddad1sm182122035e9.9.2024.10.01.07.13.20
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 01 Oct 2024 07:13:20 -0700 (PDT)
Date: Tue, 1 Oct 2024 16:13:14 +0200
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: ran xiaokai <ranxiaokai627@163.com>
Cc: tglx@linutronix.de, dvyukov@google.com, kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org, Ran Xiaokai <ran.xiaokai@zte.com.cn>
Subject: Re: [PATCH 3/4] kcsan, debugfs: fix atomic sleep by converting
 spinlock_t to rcu lock
Message-ID: <ZvwDevIahZ5352mO@elver.google.com>
References: <20240925143154.2322926-1-ranxiaokai627@163.com>
 <20240925143154.2322926-4-ranxiaokai627@163.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20240925143154.2322926-4-ranxiaokai627@163.com>
User-Agent: Mutt/2.2.12 (2023-09-09)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=vjy7eVp0;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::329 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

On Wed, Sep 25, 2024 at 02:31PM +0000, ran xiaokai wrote:
> From: Ran Xiaokai <ran.xiaokai@zte.com.cn>
> 
> In a preempt-RT kernel, most of the irq handlers have been
> converted to the threaded mode except those which have the
> IRQF_NO_THREAD flag set. The hrtimer IRQ is such an example.
> So kcsan report could be triggered from a HARD-irq context, this will
> trigger the "sleeping function called from invalid context" bug.
> 
> [    C1] BUG: sleeping function called from invalid context at kernel/locking/spinlock_rt.c:48
> [    C1] in_atomic(): 1, irqs_disabled(): 1, non_block: 0, pid: 0, name: swapper/1
> [    C1] preempt_count: 10002, expected: 0
> [    C1] RCU nest depth: 0, expected: 0
> [    C1] no locks held by swapper/1/0.
> [    C1] irq event stamp: 156674
> [    C1] hardirqs last  enabled at (156673): [<ffffffff81130bd9>] do_idle+0x1f9/0x240
> [    C1] hardirqs last disabled at (156674): [<ffffffff82254f84>] sysvec_apic_timer_interrupt+0x14/0xc0
> [    C1] softirqs last  enabled at (0): [<ffffffff81099f47>] copy_process+0xfc7/0x4b60
> [    C1] softirqs last disabled at (0): [<0000000000000000>] 0x0
> [    C1] Preemption disabled at:
> [    C1] [<ffffffff814a3e2a>] paint_ptr+0x2a/0x90
> [    C1] CPU: 1 UID: 0 PID: 0 Comm: swapper/1 Not tainted 6.11.0+ #3
> [    C1] Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS rel-1.12.0-0-ga698c8995f-prebuilt.qemu.org 04/01/2014
> [    C1] Call Trace:
> [    C1]  <IRQ>
> [    C1]  dump_stack_lvl+0x7e/0xc0
> [    C1]  dump_stack+0x1d/0x30
> [    C1]  __might_resched+0x1a2/0x270
> [    C1]  rt_spin_lock+0x68/0x170
> [    C1]  ? kcsan_skip_report_debugfs+0x43/0xe0
> [    C1]  kcsan_skip_report_debugfs+0x43/0xe0
> [    C1]  ? hrtimer_next_event_without+0x110/0x110
> [    C1]  print_report+0xb5/0x590
> [    C1]  kcsan_report_known_origin+0x1b1/0x1d0
> [    C1]  kcsan_setup_watchpoint+0x348/0x650
> [    C1]  __tsan_unaligned_write1+0x16d/0x1d0
> [    C1]  hrtimer_interrupt+0x3d6/0x430
> [    C1]  __sysvec_apic_timer_interrupt+0xe8/0x3a0
> [    C1]  sysvec_apic_timer_interrupt+0x97/0xc0
> [    C1]  </IRQ>
> 
> To fix this, we can not simply convert the report_filterlist_lock
> to a raw_spinlock_t. In the insert_report_filterlist() path:
> 
> raw_spin_lock_irqsave(&report_filterlist_lock, flags);
>   krealloc
>     __do_kmalloc_node
>       slab_alloc_node
>         __slab_alloc
>           local_lock_irqsave(&s->cpu_slab->lock, flags)
> 
> local_lock_t is now a spinlock_t which is sleepable in preempt-RT
> kernel, so kmalloc() and similar functions can not be called with
> a raw_spinlock_t lock held.
> 
> Instead, we can convert it to rcu lock to fix this.
> Aso introduce a mutex to serialize user-space write operations.
> 
> Signed-off-by: Ran Xiaokai <ran.xiaokai@zte.com.cn>
[...]
> -	spin_lock_irqsave(&report_filterlist_lock, flags);
> -	if (report_filterlist.used == 0)
> +	rcu_read_lock();
> +	list = rcu_dereference(rp_flist);
> +
> +	if (!list)
> +		goto out;
> +
> +	if (list->used == 0)
>  		goto out;
>  
>  	/* Sort array if it is unsorted, and then do a binary search. */
> -	if (!report_filterlist.sorted) {
> -		sort(report_filterlist.addrs, report_filterlist.used,
> +	if (!list->sorted) {
> +		sort(list->addrs, list->used,
>  		     sizeof(unsigned long), cmp_filterlist_addrs, NULL);
> -		report_filterlist.sorted = true;
> +		list->sorted = true;
>  	}

This used to be under the report_filterlist_lock, but now there's no
protection against this happening concurrently.

Sure, at the moment, this is not a problem, because this function is
only called under the report_lock which serializes it. Is that intended?

> -	ret = !!bsearch(&func_addr, report_filterlist.addrs,
> -			report_filterlist.used, sizeof(unsigned long),
> +	ret = !!bsearch(&func_addr, list->addrs,
> +			list->used, sizeof(unsigned long),
>  			cmp_filterlist_addrs);
> -	if (report_filterlist.whitelist)
> +	if (list->whitelist)
>  		ret = !ret;
[...]
> +
> +	memcpy(new_list, old_list, sizeof(struct report_filterlist));
> +	new_list->whitelist = whitelist;
> +
> +	rcu_assign_pointer(rp_flist, new_list);
> +	synchronize_rcu();
> +	kfree(old_list);

Why not kfree_rcu()?

> +out:
> +	mutex_unlock(&rp_flist_mutex);
> +	return ret;
>  }
[...]
> +	} else {
> +		new_addrs = kmalloc_array(new_list->size,
> +					  sizeof(unsigned long), GFP_KERNEL);
> +		if (new_addrs == NULL)
> +			goto out_free;
> +
> +		memcpy(new_addrs, old_list->addrs,
> +				old_list->size * sizeof(unsigned long));
> +		new_list->addrs = new_addrs;
>  	}

Wait, for every insertion it ends up copying the list now? That's very
wasteful.

In general, this solution seems overly complex, esp. the part where it
ends up copying the whole list on _every_ insertion.

If the whole point is to avoid kmalloc() under the lock, we can do
something much simpler.

Please test the patch below - it's much simpler, and in the common case
I expect it to rarely throw away the preemptive allocation done outside
the critical section because concurrent insertions by the user should be
rarely done.

Thanks,
-- Marco

------ >8 ------

From: Marco Elver <elver@google.com>
Date: Tue, 1 Oct 2024 16:00:45 +0200
Subject: [PATCH] kcsan: turn report_filterlist_lock into a raw_spinlock

<tbd... please test>

Reported-by: Ran Xiaokai <ran.xiaokai@zte.com.cn>
Signed-off-by: Marco Elver <elver@google.com>
---
 kernel/kcsan/debugfs.c | 76 +++++++++++++++++++++---------------------
 1 file changed, 38 insertions(+), 38 deletions(-)

diff --git a/kernel/kcsan/debugfs.c b/kernel/kcsan/debugfs.c
index 1d1d1b0e4248..5ffb6cc5298b 100644
--- a/kernel/kcsan/debugfs.c
+++ b/kernel/kcsan/debugfs.c
@@ -46,14 +46,8 @@ static struct {
 	int		used;		/* number of elements used */
 	bool		sorted;		/* if elements are sorted */
 	bool		whitelist;	/* if list is a blacklist or whitelist */
-} report_filterlist = {
-	.addrs		= NULL,
-	.size		= 8,		/* small initial size */
-	.used		= 0,
-	.sorted		= false,
-	.whitelist	= false,	/* default is blacklist */
-};
-static DEFINE_SPINLOCK(report_filterlist_lock);
+} report_filterlist;
+static DEFINE_RAW_SPINLOCK(report_filterlist_lock);
 
 /*
  * The microbenchmark allows benchmarking KCSAN core runtime only. To run
@@ -110,7 +104,7 @@ bool kcsan_skip_report_debugfs(unsigned long func_addr)
 		return false;
 	func_addr -= offset; /* Get function start */
 
-	spin_lock_irqsave(&report_filterlist_lock, flags);
+	raw_spin_lock_irqsave(&report_filterlist_lock, flags);
 	if (report_filterlist.used == 0)
 		goto out;
 
@@ -127,7 +121,7 @@ bool kcsan_skip_report_debugfs(unsigned long func_addr)
 		ret = !ret;
 
 out:
-	spin_unlock_irqrestore(&report_filterlist_lock, flags);
+	raw_spin_unlock_irqrestore(&report_filterlist_lock, flags);
 	return ret;
 }
 
@@ -135,9 +129,9 @@ static void set_report_filterlist_whitelist(bool whitelist)
 {
 	unsigned long flags;
 
-	spin_lock_irqsave(&report_filterlist_lock, flags);
+	raw_spin_lock_irqsave(&report_filterlist_lock, flags);
 	report_filterlist.whitelist = whitelist;
-	spin_unlock_irqrestore(&report_filterlist_lock, flags);
+	raw_spin_unlock_irqrestore(&report_filterlist_lock, flags);
 }
 
 /* Returns 0 on success, error-code otherwise. */
@@ -145,6 +139,9 @@ static ssize_t insert_report_filterlist(const char *func)
 {
 	unsigned long flags;
 	unsigned long addr = kallsyms_lookup_name(func);
+	unsigned long *delay_free = NULL;
+	unsigned long *new_addrs = NULL;
+	size_t new_size = 0;
 	ssize_t ret = 0;
 
 	if (!addr) {
@@ -152,32 +149,33 @@ static ssize_t insert_report_filterlist(const char *func)
 		return -ENOENT;
 	}
 
-	spin_lock_irqsave(&report_filterlist_lock, flags);
+retry_alloc:
+	/*
+	 * Check if we need an allocation, and re-validate under the lock. Since
+	 * the report_filterlist_lock is a raw, cannot allocate under the lock.
+	 */
+	if (data_race(report_filterlist.used == report_filterlist.size)) {
+		new_size = (report_filterlist.size ?: 4) * 2;
+		delay_free = new_addrs = kmalloc_array(new_size, sizeof(unsigned long), GFP_KERNEL);
+		if (!new_addrs)
+			return -ENOMEM;
+	}
 
-	if (report_filterlist.addrs == NULL) {
-		/* initial allocation */
-		report_filterlist.addrs =
-			kmalloc_array(report_filterlist.size,
-				      sizeof(unsigned long), GFP_ATOMIC);
-		if (report_filterlist.addrs == NULL) {
-			ret = -ENOMEM;
-			goto out;
-		}
-	} else if (report_filterlist.used == report_filterlist.size) {
-		/* resize filterlist */
-		size_t new_size = report_filterlist.size * 2;
-		unsigned long *new_addrs =
-			krealloc(report_filterlist.addrs,
-				 new_size * sizeof(unsigned long), GFP_ATOMIC);
-
-		if (new_addrs == NULL) {
-			/* leave filterlist itself untouched */
-			ret = -ENOMEM;
-			goto out;
+	raw_spin_lock_irqsave(&report_filterlist_lock, flags);
+	if (report_filterlist.used == report_filterlist.size) {
+		/* Check we pre-allocated enough, and retry if not. */
+		if (report_filterlist.used >= new_size) {
+			raw_spin_unlock_irqrestore(&report_filterlist_lock, flags);
+			kfree(new_addrs); /* kfree(NULL) is safe */
+			delay_free = new_addrs = NULL;
+			goto retry_alloc;
 		}
 
+		if (report_filterlist.used)
+			memcpy(new_addrs, report_filterlist.addrs, report_filterlist.used * sizeof(unsigned long));
+		delay_free = report_filterlist.addrs; /* free the old list */
+		report_filterlist.addrs = new_addrs;  /* switch to the new list */
 		report_filterlist.size = new_size;
-		report_filterlist.addrs = new_addrs;
 	}
 
 	/* Note: deduplicating should be done in userspace. */
@@ -185,8 +183,10 @@ static ssize_t insert_report_filterlist(const char *func)
 		kallsyms_lookup_name(func);
 	report_filterlist.sorted = false;
 
-out:
-	spin_unlock_irqrestore(&report_filterlist_lock, flags);
+	raw_spin_unlock_irqrestore(&report_filterlist_lock, flags);
+
+	if (delay_free)
+		kfree(delay_free);
 
 	return ret;
 }
@@ -204,13 +204,13 @@ static int show_info(struct seq_file *file, void *v)
 	}
 
 	/* show filter functions, and filter type */
-	spin_lock_irqsave(&report_filterlist_lock, flags);
+	raw_spin_lock_irqsave(&report_filterlist_lock, flags);
 	seq_printf(file, "\n%s functions: %s\n",
 		   report_filterlist.whitelist ? "whitelisted" : "blacklisted",
 		   report_filterlist.used == 0 ? "none" : "");
 	for (i = 0; i < report_filterlist.used; ++i)
 		seq_printf(file, " %ps\n", (void *)report_filterlist.addrs[i]);
-	spin_unlock_irqrestore(&report_filterlist_lock, flags);
+	raw_spin_unlock_irqrestore(&report_filterlist_lock, flags);
 
 	return 0;
 }
-- 
2.46.1.824.gd892dcdcdd-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ZvwDevIahZ5352mO%40elver.google.com.
