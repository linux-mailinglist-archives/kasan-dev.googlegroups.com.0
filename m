Return-Path: <kasan-dev+bncBDBK55H2UQKRBMWO6OLQMGQEQN6YQEI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x440.google.com (mail-wr1-x440.google.com [IPv6:2a00:1450:4864:20::440])
	by mail.lfdr.de (Postfix) with ESMTPS id 9071A596EEA
	for <lists+kasan-dev@lfdr.de>; Wed, 17 Aug 2022 15:03:47 +0200 (CEST)
Received: by mail-wr1-x440.google.com with SMTP id t12-20020adfa2cc000000b00224f577fad1sf2080684wra.4
        for <lists+kasan-dev@lfdr.de>; Wed, 17 Aug 2022 06:03:47 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1660741427; cv=pass;
        d=google.com; s=arc-20160816;
        b=RiD8w1f/J1ZweULGFybjAwbwqRPsiQqsaNRyO0yctjbpqKU+meR2COH/lfuxpxZffV
         I61f8xFEdGOomS5zK4JmsBp4zBLHI+UP5f4NIFtFB8h3VTHYZcDPJZ4bqPmzVI5gSFBZ
         7RJwBoG7MKsK2UbfGdrtsIrIvp37+baV0h0keDSs9SlPsVNAYo9z+dgujUFhljFM1dMR
         XS5Hymw97E0mOTnfLLsJsbxNIFvhrRbzrDBN+yzHfiFjU7S0C7G4MzfNtUgQ4PCTzlw3
         C9NCQXcdS/nTuTupOCHOhAJW0fU9lG32+70x2kIIAAeyczueaptyBtOIGwYAtmX4OfgA
         Dq2g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=T/xdMV6pjGO3p6oPdepztmgHg9ep+/bpMmGOoXwbG7Q=;
        b=m7tc0w6060VZDKIFcjaKv570HWzjRR7mQrYSRaJmD7AqJtEBaiT1u8bXStFgC8Ggj8
         vWxL7N/+m10AdJHZCHqS3R7DL/wU1W0NN+plYlYXD6fjjvLTvkCuBgSrkmhsP8SBnkq1
         Hadd90AEx+G/DZ7yoC/F/oaWoV5iY9ORlk1mNX9zIJicTp9NYAT08ej7MIzd77BSr5PV
         rOSEtM/3O39yg6KmHl5lRwP0ehAnh1n6bUFRf4P+CR8xCLmdeTp4o1GnE1flwsaXpPJ2
         RCzMjJKp4Eia+zt7UMgnTFYtrup7mHjJgNCCwMhnBLpUlSE9EwvNP5A9FgRakC04cAdi
         NZAw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=TUYGDjo5;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1:d65d:64ff:fe57:4e05 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc;
        bh=T/xdMV6pjGO3p6oPdepztmgHg9ep+/bpMmGOoXwbG7Q=;
        b=hylUOzmcVvV4cptzP/yh5sHNrG5I5XSVK1yOk8xuzkjQ3JtqWNoex2+ShaZjOprPAT
         rhZkgvDaA3tgGi3wLJ4HqCabTTPsg0kmWP873Suo8m8IIJwJyGfLRCBxIruIvTThqWnL
         GbyqRjRsDczVSfWhAFMWEfeTFrzK9CSS98BNCn7dWzXXGlZpXvJcGTqVX/JXggWrI2Ws
         RMLyUXpzTNAwGLX5TfZv5Xt5jQmHFvfCSFg+SvflheTdw1FTOxh2sJWCg8+UpgHhLwW8
         +RZQj4lB529BvGNc8LsxRBWCbT+getDJnEJUybNpALLlZaAhaKxCHvHT3arLn3S3bV7R
         wnNg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:sender:from:to:cc;
        bh=T/xdMV6pjGO3p6oPdepztmgHg9ep+/bpMmGOoXwbG7Q=;
        b=OcMYr5TzVaLGD4bnmJC8u7G4Pb1EiZFl3d//ZyieOzaicVsxyHhem3htEZWrmjd23m
         hoJ+kmkdqK4VXHFEBKnEdMfdnikjRZUxuZ6ubIbjVMwxkp06w9CxLySpzH7RfBJcRI54
         m1O+ddf0QjsaKZoZVXRnQziDY3cTVFamIbgTPUbh4otSTz/AdtbXBR8BmwQPzAUxvpIJ
         LTuhQRMTAf8goJdFgtaeuI0HFh2OuMc7FdGSXEzPIVSgGV3C9CjyTkyHWeuPq5Vji8L6
         EEc3GWDj4aKHZlXP1yPT9M2tcC9vkL6fp2s2YHPU4QQy51/MaM8GVh+QzelvJ783qA/e
         TIKA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACgBeo32oYJPP2FaGG0he5oZZV8IzNUchg7ycE8ZFNfvnJXC5AqFQ70c
	v913cRWWv/+IhsSPrqTKx0E=
X-Google-Smtp-Source: AA6agR4dDoHa8S+/QXVTpZEF7QX/BfE629wDoClEQANoXSFQnLac8PjzOqh1WadBlYr0RgfArOboMg==
X-Received: by 2002:a05:6000:144d:b0:21f:a4a0:dbfa with SMTP id v13-20020a056000144d00b0021fa4a0dbfamr14315425wrx.701.1660741427099;
        Wed, 17 Aug 2022 06:03:47 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6000:3c1:b0:220:80cc:8add with SMTP id
 b1-20020a05600003c100b0022080cc8addls2896444wrg.2.-pod-prod-gmail; Wed, 17
 Aug 2022 06:03:46 -0700 (PDT)
X-Received: by 2002:a05:6000:1446:b0:222:c466:58a0 with SMTP id v6-20020a056000144600b00222c46658a0mr14646497wrx.53.1660741425988;
        Wed, 17 Aug 2022 06:03:45 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1660741425; cv=none;
        d=google.com; s=arc-20160816;
        b=Jg87NCpVaJkkAP93PrQ4Z/DVGKporGFyEHoCZfrJO3dJw8tGI+vF4zcrs6b+LlNovd
         9WFnOs0euRc0QJbgxIf+2LJ3WJYGvj+RLvv0kUXeJtrXPDVF+KdZtKc4Vi9EbfAqYHxd
         SsE2BdkIn5QbPJMr9IOOG8WA29jUW1q865ytoH2YzCnsNu8dpLMUQrEMSTDTaSampAQ8
         M+k0+IGMl+mt9pfk626hLZLm5SVMJqHrxpISoF0PP0mvYSKJyZtc+sJ6PzNrqqzhV4+M
         OXGvxnZodOxrC5onmjVZ7imzdG971r/OVK4+5J6a3layViUbAY3p/dWzHkTyv599p/Q0
         xzWw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=8tSVbs/LntHCfdjrxtk7ceXw6TPtMo4nIYUkIIRtVa4=;
        b=J5l2vS6UHdr5z/wYx8BaA8ghSplk8oOPskE1crNBFyvyYS2wteiZ9Icggybh6fXWkX
         WDM0PDZ62Ba/wCkK1JkHBN1AvxcwNi/4J19frMv7nGP/ecyKz6Da1AzCQVnQmcuGjijU
         +2R7z5pKZOBYSDd3kK3WxglzdMJHwr+yzMohRbz+zRjqOGbbCsna3L4aXZ3EJSwi3E1m
         zkeBmI2ut9cpkQzRAkIn4zoJXo93NYPb7XbGCL/W+N8CP7WMYLGWgMZI+2bSVrZ2VRe2
         yZRClkfJihNeUE/fGF084AxEkTVCbqnjKSk8VywZI1efdIpDQqkMqdK6DpnzbolCRjlK
         3Z9g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=TUYGDjo5;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1:d65d:64ff:fe57:4e05 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from desiato.infradead.org (desiato.infradead.org. [2001:8b0:10b:1:d65d:64ff:fe57:4e05])
        by gmr-mx.google.com with ESMTPS id ay9-20020a5d6f09000000b002236ac50ec6si731636wrb.6.2022.08.17.06.03.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 17 Aug 2022 06:03:45 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1:d65d:64ff:fe57:4e05 as permitted sender) client-ip=2001:8b0:10b:1:d65d:64ff:fe57:4e05;
Received: from j130084.upc-j.chello.nl ([24.132.130.84] helo=worktop.programming.kicks-ass.net)
	by desiato.infradead.org with esmtpsa (Exim 4.94.2 #2 (Red Hat Linux))
	id 1oOIht-003I0R-UD; Wed, 17 Aug 2022 13:03:41 +0000
Received: by worktop.programming.kicks-ass.net (Postfix, from userid 1000)
	id 84568980256; Wed, 17 Aug 2022 15:03:37 +0200 (CEST)
Date: Wed, 17 Aug 2022 15:03:37 +0200
From: Peter Zijlstra <peterz@infradead.org>
To: Marco Elver <elver@google.com>
Cc: Frederic Weisbecker <frederic@kernel.org>,
	Ingo Molnar <mingo@kernel.org>,
	Thomas Gleixner <tglx@linutronix.de>,
	Arnaldo Carvalho de Melo <acme@kernel.org>,
	Mark Rutland <mark.rutland@arm.com>,
	Alexander Shishkin <alexander.shishkin@linux.intel.com>,
	Jiri Olsa <jolsa@redhat.com>, Namhyung Kim <namhyung@kernel.org>,
	Dmitry Vyukov <dvyukov@google.com>,
	Michael Ellerman <mpe@ellerman.id.au>,
	linuxppc-dev@lists.ozlabs.org, linux-perf-users@vger.kernel.org,
	x86@kernel.org, linux-sh@vger.kernel.org,
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org
Subject: Re: [PATCH v3 11/14] perf/hw_breakpoint: Reduce contention with
 large number of tasks
Message-ID: <YvznKYgRKjDRSMkT@worktop.programming.kicks-ass.net>
References: <20220704150514.48816-1-elver@google.com>
 <20220704150514.48816-12-elver@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20220704150514.48816-12-elver@google.com>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=desiato.20200630 header.b=TUYGDjo5;
       spf=pass (google.com: best guess record for domain of
 peterz@infradead.org designates 2001:8b0:10b:1:d65d:64ff:fe57:4e05 as
 permitted sender) smtp.mailfrom=peterz@infradead.org
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

On Mon, Jul 04, 2022 at 05:05:11PM +0200, Marco Elver wrote:
> +static bool bp_constraints_is_locked(struct perf_event *bp)
> +{
> +	struct mutex *tsk_mtx = get_task_bps_mutex(bp);
> +
> +	return percpu_is_write_locked(&bp_cpuinfo_sem) ||
> +	       (tsk_mtx ? mutex_is_locked(tsk_mtx) :
> +			  percpu_is_read_locked(&bp_cpuinfo_sem));
> +}

> @@ -426,18 +521,28 @@ static int modify_bp_slot(struct perf_event *bp, u64 old_type, u64 new_type)
>   */
>  int dbg_reserve_bp_slot(struct perf_event *bp)
>  {
> -	if (mutex_is_locked(&nr_bp_mutex))
> +	int ret;
> +
> +	if (bp_constraints_is_locked(bp))
>  		return -1;
>  
> -	return __reserve_bp_slot(bp, bp->attr.bp_type);
> +	/* Locks aren't held; disable lockdep assert checking. */
> +	lockdep_off();
> +	ret = __reserve_bp_slot(bp, bp->attr.bp_type);
> +	lockdep_on();
> +
> +	return ret;
>  }
>  
>  int dbg_release_bp_slot(struct perf_event *bp)
>  {
> -	if (mutex_is_locked(&nr_bp_mutex))
> +	if (bp_constraints_is_locked(bp))
>  		return -1;
>  
> +	/* Locks aren't held; disable lockdep assert checking. */
> +	lockdep_off();
>  	__release_bp_slot(bp, bp->attr.bp_type);
> +	lockdep_on();
>  
>  	return 0;
>  }

Urggghhhh... this is horrible crap. That is, the current code is that
and this makes it worse :/

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YvznKYgRKjDRSMkT%40worktop.programming.kicks-ass.net.
