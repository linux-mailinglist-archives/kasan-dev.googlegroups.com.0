Return-Path: <kasan-dev+bncBCKLNNXAXYFBBENSZW6QMGQEQI3OEHY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33e.google.com (mail-wm1-x33e.google.com [IPv6:2a00:1450:4864:20::33e])
	by mail.lfdr.de (Postfix) with ESMTPS id DF282A387E0
	for <lists+kasan-dev@lfdr.de>; Mon, 17 Feb 2025 16:43:14 +0100 (CET)
Received: by mail-wm1-x33e.google.com with SMTP id 5b1f17b1804b1-4398e841963sf2475225e9.3
        for <lists+kasan-dev@lfdr.de>; Mon, 17 Feb 2025 07:43:14 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1739806994; cv=pass;
        d=google.com; s=arc-20240605;
        b=WVR9rOnbAg8MnPaw4u94LkiDCbQwBC2fno2HVGH9/8oeOlMfUim18mZduRUwpFBlOi
         kATSpJ2qEhK2d31lKELaFYyXpRgcwH/1mljt+lhPrgd3ESfm65xHvWZhsDS5c431Maqv
         AR+9itdusNty/N4kQ5nSiXsUEINTibuvS8Nb4k5eS6BYhdAidVyaOmLjyaH2WXhkWwHE
         PQgSc4VKp7MCMAvXDhap9PaSY8TwTNyXINg/OZXi2ix2qxb0R61/qdPhPd2cc/4KaaT4
         lp+fCmznle10FYtAZ9qsipvt8r6buypzgu1PIq4JjMFCndh+pvTL4h1JAFN6+lab8UBH
         N09g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=5b14acNq9PXdwSddd/a0dxJt1pOyi9hArmKEpgFdFWI=;
        fh=s6HQacDowYRALNoUZuVWJ32IklCHuOrUOwEpYDVG+kY=;
        b=IBogUBUxGUvPDfLh8J1KnCKwqoQRCSkTwd1iz3d5hBPBAjorVrsD666u2Q7SmNELRn
         yVKU54nqwNZYTySb++naaRd8tx+Ry4AXORAz4dD9rTHPc2os4dHq8KTGjrbAvJprzZOi
         6V8pHXhHlFhQvu+JtrD70suwQgUbk2QXHv4mPF3GTTfiuQmZ2vtCdkzAK0eL5whDroDl
         uACOIP0HFd+EIHEGTO/SzwU5Cmt6uJj1Q9KOKjHiVk4KfaMg5qx/7zMICDf7l41GVIAC
         H9Oeoi+rdvKIK/HPzkblCmbInXx0QTbrb9hva92UbyMdWNSFA4/g6NA19BAETsTEifKi
         nrjQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=YnKadfTX;
       dkim=neutral (no key) header.i=@linutronix.de;
       spf=pass (google.com: domain of bigeasy@linutronix.de designates 193.142.43.55 as permitted sender) smtp.mailfrom=bigeasy@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1739806994; x=1740411794; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=5b14acNq9PXdwSddd/a0dxJt1pOyi9hArmKEpgFdFWI=;
        b=pz9vtixJWQvxoEJfsri15tSrQ8hrOK9yAt4bS7t0sjml5CSH/I5D95h68DJH+aDClz
         /+L1YlGrKIVQVWEc73to+qsTmd2IUBhqocGex60k4xPZkPT6GQNat0cfVwUFbZzgsmqV
         5t8UtfsIMt3GcPU8wi3rBWdO08wLxoL9zyPyFlRhpEYdnVEs0RkIzADNHZRQRcjLBom+
         KJkm9VawFehHNzb688G/AEcQakG6bSOz98BHmbkv2s1FwVHTOzxXwnhEbkdlTbdNHaoa
         IgIDl7T8j87l7QxFnVf0hPVvrbNRoPNpEx9/FNORjdT++Ckf+nZoeZMYQ3hsZprYAsX8
         gJGA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1739806994; x=1740411794;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=5b14acNq9PXdwSddd/a0dxJt1pOyi9hArmKEpgFdFWI=;
        b=NPKOYEFzeWtxyASDj9Rwut7zeGjO8ExaEumXmhorc+dH0l6uVuZnGyjzFDNKj6YfDy
         j2KRD27UYtVjN2d+6aEz3glGfM8MwJuKQtJlkPk7XM1dOQuI/GQ45i8Zw2JeK7cAO+/1
         rabaimntk42284nI+tYjlU4jE6N0HJ9ROAXRRMC/o/iX/9MRpyl2+WIKeMQe7zDGMBxy
         GreDQXdn9JbT9h/dYiWxNuSinYelRkqCqy0ZHrHCojDflfAifHTgDJN+Aj5WnK/StMgn
         fXSoy/UblRgTKcnNNsoDbJblwRAWH40NYhQK4pzcciHLsMbK6z6/GxHQHuXIBh8yXBW1
         CcDQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVMM11CgZzP9ePvpZLEjYmpWDX/yDUaKJHOMTCvIA2+q/YS+yOIBlvHs8OlvludN56tJBqgwQ==@lfdr.de
X-Gm-Message-State: AOJu0YzIT55jj87KyibZhUJoIvEEdvXTGiUHC0NaEMmjevddA02dLHTa
	k4YZ41dXIhLYtFiTYhfSH9PliCgFprZmcm+NB2GWOtjL8kmkqSD8
X-Google-Smtp-Source: AGHT+IH1JnCH2EicnuVANjQy4FPOEmR6TtX4wevAycEFaIJosEtSO6nj+qMDVv1rmdjqZxmVFmU5cw==
X-Received: by 2002:a05:600c:358f:b0:439:62eb:3cc5 with SMTP id 5b1f17b1804b1-4396e744cf9mr96255735e9.23.1739806993417;
        Mon, 17 Feb 2025 07:43:13 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h=Adn5yVGH/nTJNjFLNivIyZfiCSGsaOmoWg4oHBogufGnD2qKFQ==
Received: by 2002:a7b:c44e:0:b0:439:8ddc:117b with SMTP id 5b1f17b1804b1-4398ddc1456ls2197575e9.0.-pod-prod-02-eu;
 Mon, 17 Feb 2025 07:43:11 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVwC5JMULhoPOr5+sM/L7muByOpd3bWqsaLQlPNSGEwDNLyf9Yzn8zIWLshCECVS8NPMx/Pife5kDM=@googlegroups.com
X-Received: by 2002:a05:600c:a386:b0:439:84ba:5760 with SMTP id 5b1f17b1804b1-43984ba58ecmr40427645e9.5.1739806991046;
        Mon, 17 Feb 2025 07:43:11 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1739806991; cv=none;
        d=google.com; s=arc-20240605;
        b=IRr1TCUrOb3x6v6ErHy7mLikz86EFFldUPjt/upqmTXOAEr3h3NxzRWCGtV54j/MD2
         g7QGQjROooKDteQ85rV4OPmaVACq1EHoKX/sdHePDG14BRxjGSqTecbTYwIPBxKw2EHs
         LH7zrZjjWLbZbOq9h6LFew+Eeh6r7gzBPfHzvmaP/7bdS7PbrX5r/B8vIwMDfiIs7k7D
         RVugUPTkciwu1fW/Ht12bhyfTx+TY61M2O5A6bdFyg4lEdbGtoLMq9OGyWcfN/LigNL3
         Ri/0MDW/j7JVSluyVbFk/SIemfwvdXYZIN3KO7MTeI30QHdVQ5CtoNRDSbPKLm7Y/Ed6
         jr6w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:dkim-signature:dkim-signature:date;
        bh=JDZt4WFEIPWOyU577sCBTfPji3aQbE2kJD7pIg8nvy0=;
        fh=EYelCbwDivU5OmAyrzgUNGMGzA8KutW3mLJ1/tSmiKw=;
        b=NpkOadJRzvS9TCYlSvG5WsAzdKxniSOPPuoNzPzFtq2v5Zm/I3YH7uUTPhnzWTM2rK
         Loo9fzFw2LIQ9ClaZ0vKp5+nFf2MKTvu8Kac5NcKowcxx52iu1Gtaz9VWtGQCkTyqSgA
         0LaKKbjIPuUdJiJSYEJ8j9VAaz96sqqfVlMdQ58mCItmtqMSMiNeMKIn3pKSICHNDGuT
         Tp+vu5s6kjifbRh8dnFyaLqc9llhSwk960NLB0iz6UQCADV8X7FOejcy/Yp7o1jcMaw8
         2IssD+gSX+avWounDANBriQ73mytDakyB3YqyJ+R72bEKRyFx2X3ZcOtuI0BrQ5pbIWF
         vA/Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=YnKadfTX;
       dkim=neutral (no key) header.i=@linutronix.de;
       spf=pass (google.com: domain of bigeasy@linutronix.de designates 193.142.43.55 as permitted sender) smtp.mailfrom=bigeasy@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
Received: from galois.linutronix.de (Galois.linutronix.de. [193.142.43.55])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-43984224b41si1877515e9.1.2025.02.17.07.43.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 17 Feb 2025 07:43:11 -0800 (PST)
Received-SPF: pass (google.com: domain of bigeasy@linutronix.de designates 193.142.43.55 as permitted sender) client-ip=193.142.43.55;
Date: Mon, 17 Feb 2025 16:43:09 +0100
From: Sebastian Andrzej Siewior <bigeasy@linutronix.de>
To: Waiman Long <longman@redhat.com>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Clark Williams <clrkwllms@kernel.org>,
	Steven Rostedt <rostedt@goodmis.org>, kasan-dev@googlegroups.com,
	linux-mm@kvack.org, linux-kernel@vger.kernel.org,
	linux-rt-devel@lists.linux.dev, Nico Pache <npache@redhat.com>
Subject: Re: [PATCH v3] kasan: Don't call find_vm_area() in RT kernel
Message-ID: <20250217154309.C2CMqCjE@linutronix.de>
References: <20250217042108.185932-1-longman@redhat.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20250217042108.185932-1-longman@redhat.com>
X-Original-Sender: bigeasy@linutronix.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linutronix.de header.s=2020 header.b=YnKadfTX;       dkim=neutral
 (no key) header.i=@linutronix.de;       spf=pass (google.com: domain of
 bigeasy@linutronix.de designates 193.142.43.55 as permitted sender)
 smtp.mailfrom=bigeasy@linutronix.de;       dmarc=pass (p=NONE sp=QUARANTINE
 dis=NONE) header.from=linutronix.de
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

On 2025-02-16 23:21:08 [-0500], Waiman Long wrote:

I would skip the first part. The backtrace is not really helpful here.

> The following bug report appeared with a test run in a RT debug kernel.
> 
> [ 3359.353842] BUG: sleeping function called from invalid context at kernel/locking/spinlock_rt.c:48
> [ 3359.353848] in_atomic(): 1, irqs_disabled(): 1, non_block: 0, pid: 140605, name: kunit_try_catch
> [ 3359.353853] preempt_count: 1, expected: 0
>   :
> [ 3359.353933] Call trace:
>   :
> [ 3359.353955]  rt_spin_lock+0x70/0x140
> [ 3359.353959]  find_vmap_area+0x84/0x168
> [ 3359.353963]  find_vm_area+0x1c/0x50
> [ 3359.353966]  print_address_description.constprop.0+0x2a0/0x320
> [ 3359.353972]  print_report+0x108/0x1f8
> [ 3359.353976]  kasan_report+0x90/0xc8
> [ 3359.353980]  __asan_load1+0x60/0x70
> 
> Commit e30a0361b851 ("kasan: make report_lock a raw spinlock")
> changes report_lock to a raw_spinlock_t to avoid a similar RT problem.

s/to avoid.*//. This has nothing to do with the problem at hand.

> The print_address_description() function is called with report_lock
> acquired and interrupt disabled.  However, the find_vm_area() function
> still needs to acquire a spinlock_t which becomes a sleeping lock in
> the RT kernel. IOW, we can't call find_vm_area() in a RT kernel and
> changing report_lock to a raw_spinlock_t is not enough to completely
> solve this RT kernel problem.

This function is always invoked under the report_lock which is a
raw_spinlock_t. The context under this lock is always atomic even on
PREEMPT_RT. find_vm_area() acquires vmap_node::busy.lock which is a
spinlock_t, becoming a sleeping lock on PREEMPT_RT and must not be
acquired in atomic context.

> Fix this bug report by skipping the find_vm_area() call in this case
> and just print out the address as is.

Please use PREEMPT_RT instead of RT.

Don't invoke find_vm_area() on PREEMPT_RT and just print the address.
Non-PREEMPT_RT builds remain unchanged. Add a DEFINE_WAIT_OVERRIDE_MAP()
is to tell lockdep that this lock nesting allowed because the PREEMPT_RT
part (which is invalid) has been taken care of.

> For !RT kernel, follow the example set in commit 0cce06ba859a
> ("debugobjects,locking: Annotate debug_object_fill_pool() wait type
> violation") and use DEFINE_WAIT_OVERRIDE_MAP() to avoid a spinlock_t
> inside raw_spinlock_t warning.


> Fixes: e30a0361b851 ("kasan: make report_lock a raw spinlock")
> Signed-off-by: Waiman Long <longman@redhat.com>

Reviewed-by: Sebastian Andrzej Siewior <bigeasy@linutronix.de>

> ---
>  mm/kasan/report.c | 43 ++++++++++++++++++++++++++++++-------------
>  1 file changed, 30 insertions(+), 13 deletions(-)
> 
>  [v3] Rename helper to print_vmalloc_info_set_page.
> 
> diff --git a/mm/kasan/report.c b/mm/kasan/report.c
> index 3fe77a360f1c..7c8c2e173aa4 100644
> --- a/mm/kasan/report.c
> +++ b/mm/kasan/report.c
> @@ -370,6 +370,34 @@ static inline bool init_task_stack_addr(const void *addr)
>  			sizeof(init_thread_union.stack));
>  }
>  
> +/*
> + * RT kernel cannot call find_vm_area() in atomic context. For !RT kernel,
> + * prevent spinlock_t inside raw_spinlock_t warning by raising wait-type
> + * to WAIT_SLEEP.
> + */

Do we need this comment? I lacks context of why it is atomic. And we
have it in the commit description.

> +static inline void print_vmalloc_info_set_page(void *addr, struct page **ppage)
> +{
> +	if (!IS_ENABLED(CONFIG_PREEMPT_RT)) {
> +		static DEFINE_WAIT_OVERRIDE_MAP(vmalloc_map, LD_WAIT_SLEEP);
> +		struct vm_struct *va;
> +
> +		lock_map_acquire_try(&vmalloc_map);
> +		va = find_vm_area(addr);
> +		if (va) {
> +			pr_err("The buggy address belongs to the virtual mapping at\n"
> +			       " [%px, %px) created by:\n"
> +			       " %pS\n",
> +			       va->addr, va->addr + va->size, va->caller);
> +			pr_err("\n");
> +
> +			*ppage = vmalloc_to_page(addr);
> +		}
> +		lock_map_release(&vmalloc_map);
> +		return;
> +	}
> +	pr_err("The buggy address %px belongs to a vmalloc virtual mapping\n", addr);
> +}
> +
>  static void print_address_description(void *addr, u8 tag,
>  				      struct kasan_report_info *info)
>  {

Sebastian

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250217154309.C2CMqCjE%40linutronix.de.
