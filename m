Return-Path: <kasan-dev+bncBCV5TUXXRUIBBRP6536QKGQEVBZ45SQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13e.google.com (mail-lf1-x13e.google.com [IPv6:2a00:1450:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id C19E82C0AD1
	for <lists+kasan-dev@lfdr.de>; Mon, 23 Nov 2020 14:55:19 +0100 (CET)
Received: by mail-lf1-x13e.google.com with SMTP id d20sf6145705lfn.16
        for <lists+kasan-dev@lfdr.de>; Mon, 23 Nov 2020 05:55:19 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1606139718; cv=pass;
        d=google.com; s=arc-20160816;
        b=WX/Wg+ykR7in8gCzMv717Qg2Urmh26wNlO6nuewU3NmbbqJEQO4RDMMIBXaWGC8SzJ
         bgeiGan48ovB7YxWPA57TcCf2GbeglzDCTmTvK6af5K1O8xtRFWwBExkx7a5+34Kc/Ar
         44RoZ6fTfRj4td5CPvyZl7Fb/sCU3LGn6wAOmt29lyTWHrfOKKXKeptrDfo+MGmuB1kp
         HWzGsVgdD0zLPSLq+FxfjJ69j5Sxn43nmnH9x5qvdFvdbgryD0x/4nmkm18i3xFvxaeS
         l/5kU/7CDuUY7/rWohIZd45N9pnWU/xSPkWiLHWzprtQZmKS//ddgrBQU3UWOJOdMDsF
         29Aw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=3QrLHVwgVrv+HpE+d1Xol7ZEiMZMzCrexnVUFzwzq30=;
        b=qFRrfRDxJf7sgMv8MfP4g7GETCxkPRLKdsdNKR8AWX3SIUr+Nv4EwR71wWR9qWI2YV
         6ygU5nAbN0OUx2cGbmbSLDJSQMWkv/PEiRntiN2HeU/LVFr3EpIg8shXZjdXR47dWp8H
         thJwmPLG83oAvEfUJxDXYUF/6/RbFe+qeVwX8/eE9eBoL4nqfRxxC7HbB7OJwpG3oj4m
         dTzcB2/NzaXbJKA66vS74cy9TMr6k6sGwpI+LaBvwC202ztQGfFl3FIA8AnluFaQ1+8u
         wrx+xyC+a2Z+jKZoMXGy5RoRW3CV5xrcP6ZjO2gweAT+5WF/dK2+RnJkuiJegoaGg3tI
         BsZg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=Uqui2mMb;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=3QrLHVwgVrv+HpE+d1Xol7ZEiMZMzCrexnVUFzwzq30=;
        b=Bpmn7BFJm1slu94H8eqZVOjjy9+Quxxh2K9+E5j63nQ0c/P+RFhND8PdSlsjL8vEDH
         NcO6qsaogmVhwwg5LlEoExA7Q5og7kbgLRrdLp3LeOcicf9YeTCGUDr3OU9ubS4Y+6pw
         qrEQEUQ1vUHrWTmsA6GU0kh7HfjoyRVt7vbSx/5OyFoejzA2zDWtcB+QGFh7ylHkiZUq
         hQMJuZnf6bszEJTumpujer76F47k81iOVBBYqmwpaEOy5JVS4zNOfSZV88eGo1ynC+aU
         6iM43kXD2gyueWJSKH6a9pgPZCi3HL4ZDXmWaUSMaxDgsgQ7f+iP7WR21kSqEcvWBP22
         iIcg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=3QrLHVwgVrv+HpE+d1Xol7ZEiMZMzCrexnVUFzwzq30=;
        b=JSBKfV08GoAenm+lRYA3aMQK5CyvvVTFtvF82xHL9Oo7VS2vOVfVExyfUOfTQqVzpG
         WHtDmJzsTO+896DI7FNCbLlN2Jz20kTZ0CnbDCIJ2/1r2nlHRrGlaGqc1QuUqhjOmnrq
         SDOneDkmIQaESh9TF3IeKY7QB8ccns6PBWOO9hHPzQ5ZradGrnmHfQn38X1PvPBDS/Sx
         bS1KE0sua2EvI2IOOeWpIXpXZO8ABvvFHrQXLiNTYUolDdnACocmiawjpvWliBrYNCZb
         8F/lkg+NSM7fWnjacEh/Cej2QdWAC5fPJZsLL5kMvOdh72pvCOgRGwFUnVSJTgVNmFYu
         jBHA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531vELHjctpd15paJiifEdDNn0KsV+DTnkuucQ1e1KFHtljxve/B
	2asJqjQZBI6L6RD+SxFc+Sw=
X-Google-Smtp-Source: ABdhPJznPakScDu8wIFwf94ZwXVepgLRTBL/4giEex+Ato6Rihi3Kq0jMltxv/LsIdB4Ei6NtG4fzQ==
X-Received: by 2002:ac2:5e91:: with SMTP id b17mr12639911lfq.442.1606139718224;
        Mon, 23 Nov 2020 05:55:18 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:99da:: with SMTP id l26ls242072ljj.10.gmail; Mon, 23 Nov
 2020 05:55:16 -0800 (PST)
X-Received: by 2002:a2e:8684:: with SMTP id l4mr3616509lji.423.1606139716905;
        Mon, 23 Nov 2020 05:55:16 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1606139716; cv=none;
        d=google.com; s=arc-20160816;
        b=bkZjufAmrbvM53Ty/NaEr1bebOCYBasNsOuHpf3tiMgKbduUpes+VjKZp8ZNSljtOv
         Q+xirYAmSsCs+gmYLmPbBHqwl44igQNS+iLnQbi+i62Csk4iMMxchEP0HZ124gBL/HWZ
         8k5XV1RwWLHtKq1Y8UBkKKl3r7+7eW+Cl/oS98IlcfkjpgG6VOS+ofFgLHrZ5CIzDmni
         aZHFvdGzHn/QQmGfU21K3ULX7qSu7g140Mwr1jXxtBsbAkTzUMas8Bat7wU2vJxYrIQT
         MShrwdkYAytwVZB6TBrLzyL/0IaIxYb4jcPK0WXyYmMSGd4dk+iSSNqj0l8Pj+A+x6r0
         kyLg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=uUPaDYAemmJYHuwFkYYuuftPgDPHYdEdgPTzaW0nVXY=;
        b=DJ8zwUgJspYf63zu7hf6uiX97KwkC4R8eeCY+t2By9UunyD0BMM8vDIN7YFa/Yl7N+
         +UkbfxjWqYAmCf9Qv+pzViwvuupLdlGaTvbGac8dr7iPuoy7e3th8l7Q9VHbc5Qyy5g4
         ReZzx6PhgaRbPp90OfpUk9bmJGF5MGY6qm+gcd7qkniYRV4cwkTMZvNszr7wwgo7X8sF
         QIlDIyJ5cnkrTp/aqIi1G4GiJoeHCmvWxnSAJsQKaLxmQzB0ygxpYpaq1zNTGbW683Nt
         XlLTsLRvN44F5WTxqTKBDp9FQjZkmDcECYVWtCrJXD/J2SG/fXW4QtxzqRpPyB3tqBJB
         DuhQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=Uqui2mMb;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from casper.infradead.org (casper.infradead.org. [2001:8b0:10b:1236::1])
        by gmr-mx.google.com with ESMTPS id b27si290720ljf.8.2020.11.23.05.55.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 23 Nov 2020 05:55:15 -0800 (PST)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) client-ip=2001:8b0:10b:1236::1;
Received: from j217100.upc-j.chello.nl ([24.132.217.100] helo=noisy.programming.kicks-ass.net)
	by casper.infradead.org with esmtpsa (Exim 4.92.3 #3 (Red Hat Linux))
	id 1khCJE-0006V8-Ss; Mon, 23 Nov 2020 13:55:13 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id 7BF013069B1;
	Mon, 23 Nov 2020 14:55:12 +0100 (CET)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 1000)
	id 5D477201D16D7; Mon, 23 Nov 2020 14:55:12 +0100 (CET)
Date: Mon, 23 Nov 2020 14:55:12 +0100
From: Peter Zijlstra <peterz@infradead.org>
To: Marco Elver <elver@google.com>
Cc: paulmck@kernel.org, will@kernel.org, tglx@linutronix.de,
	mingo@kernel.org, mark.rutland@arm.com, boqun.feng@gmail.com,
	dvyukov@google.com, kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org
Subject: Re: [PATCH v2] kcsan: Avoid scheduler recursion by using
 non-instrumented preempt_{disable,enable}()
Message-ID: <20201123135512.GM3021@hirez.programming.kicks-ass.net>
References: <20201123132300.1759342-1-elver@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20201123132300.1759342-1-elver@google.com>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=casper.20170209 header.b=Uqui2mMb;
       spf=pass (google.com: best guess record for domain of
 peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
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

On Mon, Nov 23, 2020 at 02:23:00PM +0100, Marco Elver wrote:
> When enabling KCSAN for kernel/sched (remove KCSAN_SANITIZE := n from
> kernel/sched/Makefile), with CONFIG_DEBUG_PREEMPT=y, we can observe
> recursion due to:
> 
> 	check_access() [via instrumentation]
> 	  kcsan_setup_watchpoint()
> 	    reset_kcsan_skip()
> 	      kcsan_prandom_u32_max()
> 	        get_cpu_var()
> 		  preempt_disable()
> 		    preempt_count_add() [in kernel/sched/core.c]
> 		      check_access() [via instrumentation]
> 
> Avoid this by rewriting kcsan_prandom_u32_max() to only use safe
> versions of preempt_disable() and preempt_enable() that do not call into
> scheduler code.
> 
> Note, while this currently does not affect an unmodified kernel, it'd be
> good to keep a KCSAN kernel working when KCSAN_SANITIZE := n is removed
> from kernel/sched/Makefile to permit testing scheduler code with KCSAN
> if desired.
> 
> Fixes: cd290ec24633 ("kcsan: Use tracing-safe version of prandom")
> Signed-off-by: Marco Elver <elver@google.com>
> ---
> v2:
> * Update comment to also point out preempt_enable().
> ---
>  kernel/kcsan/core.c | 15 ++++++++++++---
>  1 file changed, 12 insertions(+), 3 deletions(-)
> 
> diff --git a/kernel/kcsan/core.c b/kernel/kcsan/core.c
> index 3994a217bde7..10513f3e2349 100644
> --- a/kernel/kcsan/core.c
> +++ b/kernel/kcsan/core.c
> @@ -284,10 +284,19 @@ should_watch(const volatile void *ptr, size_t size, int type, struct kcsan_ctx *
>   */
>  static u32 kcsan_prandom_u32_max(u32 ep_ro)
>  {
> -	struct rnd_state *state = &get_cpu_var(kcsan_rand_state);
> -	const u32 res = prandom_u32_state(state);
> +	struct rnd_state *state;
> +	u32 res;
> +
> +	/*
> +	 * Avoid recursion with scheduler by using non-tracing versions of
> +	 * preempt_disable() and preempt_enable() that do not call into
> +	 * scheduler code.
> +	 */
> +	preempt_disable_notrace();
> +	state = raw_cpu_ptr(&kcsan_rand_state);
> +	res = prandom_u32_state(state);
> +	preempt_enable_no_resched_notrace();

This is a preemption bug. Does preempt_enable_notrace() not work?

>  
> -	put_cpu_var(kcsan_rand_state);
>  	return (u32)(((u64) res * ep_ro) >> 32);
>  }
>  
> -- 
> 2.29.2.454.gaff20da3a2-goog
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201123135512.GM3021%40hirez.programming.kicks-ass.net.
