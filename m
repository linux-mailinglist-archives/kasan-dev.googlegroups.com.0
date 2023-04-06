Return-Path: <kasan-dev+bncBDBK55H2UQKRBEOUXSQQMGQEU5QSXIY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x339.google.com (mail-wm1-x339.google.com [IPv6:2a00:1450:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id 92BD16DA28E
	for <lists+kasan-dev@lfdr.de>; Thu,  6 Apr 2023 22:22:42 +0200 (CEST)
Received: by mail-wm1-x339.google.com with SMTP id bi7-20020a05600c3d8700b003edecc610absf20600872wmb.7
        for <lists+kasan-dev@lfdr.de>; Thu, 06 Apr 2023 13:22:42 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1680812562; cv=pass;
        d=google.com; s=arc-20160816;
        b=Ubk3roIIzRHu1DVIAzrvly427Zzrxm4YONT2RJEByvZFogNCTNc6ahfvRriJSeZWF7
         aTzNS0pmexAQFM7/09Y3HIPudB+CugN+/E3hFnjj50Tbbzdf/VyESph45taJvUrDy16Y
         7vysAcvtMyqABEju4Klth8gxhLvQiFN16LCNRFHfxELBTWkSwCIMk4s2Qsig56g7gHhC
         gVpMPdJNgjrQiuFC7SUDv/hTFBXssmyVzXTgFUBjEO6LuwKXMQsujcmcpnRDrLPx532M
         YMLcDSSAOlVb9g9uh/ei71ZtgWUreuZsP/PZ6l+tqplEK2beyBacFEbClUzPsn5hPjCw
         AbeA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=DuEInHNo2fn8JGNOqC/J3/DLtUCHw/EpRTIuQewwzd8=;
        b=gJr9sLdaw9sSYTE8JFLdsAWCe3AUZ/zCbKATmjPIJrRzapnXJyHPyScjC8+9QdreUw
         xWu5U4n1mkj2V8FuiTSDfZRGGRZ1OCgCG7UCyQ6P8VnvAju1N6xI4+LETufG/R2gfqef
         Zr7tyIvyuaPd2OXpfOICEAabivgHcXpYc2tG+OxG8tPfywsiiT61RWMWeTfc3N/I2C+I
         cDDERy5meyS2dIi2zlIzOgQD4ZK8Ul3Z7JVh8qRU+XMe7vmjSHhE6FkrOil6ybIYqR0V
         iqZX0chZQKQ+vuAcDDOXM6AW6H411Ea5YhIn1b7hZUvpZnawFmOIeakrJWG400Fw39pp
         Lo3Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=QMxAnedN;
       spf=none (google.com: infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1680812562;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=DuEInHNo2fn8JGNOqC/J3/DLtUCHw/EpRTIuQewwzd8=;
        b=JZFBpoUG5lzd9fz07ktMGLb1Fh+BRJjCjT/DYCIkEaDaDqCfx/rWyKVcPBR15IPxbT
         9gsosTISjSrB0N0AlTzGrsizsP66vobcKmivCyHWgsRPSizGohnUbq8CN5IhfD7f+zOT
         9GpuYIPee5bhkKoK/q6heNLS2J++qh3WS9CDGiEPR/2VwM3zgAp1rVoHmuB6vMyU4RFU
         lPUgbA2UqQmWwmc4ehdfUZ2tpUnKE1cZ7bgVXyt61AFLXDYGL6BCMfqdLqMx6som1UBm
         AlQres1H/antty0wJIKHueNYzyWXAy8AdnOr1fJDDneD6BUWiOHaEDhwMWjq+iIu+w5n
         mfqA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112; t=1680812562;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=DuEInHNo2fn8JGNOqC/J3/DLtUCHw/EpRTIuQewwzd8=;
        b=hgp5aMsZELU+BH3LO2ofuSzkIWx3UksgOdfG3V34ctAF+/xpRd9ADTokSwtYT+YRqQ
         505Vdl646myM7nLoa4zmbN/ObVWR4YBW0dvXmPvcsqs0Gy1AX5MRgTYaKi6RvH8V8WUI
         za9tQgOOJilie16tt29bsMXTpsqF9RZShjYfQhOu/ZdCxmFJZLFG020Xt8dtgjN5Iq1U
         thJYlpg0SYcNPDoVo/zlp0TqYjMW672udab345gQ63N8asai+r8gMWmAEuU5BVfpdujM
         cACS+7oGUEjF0q3qZmdRBFMyXglPWFgY8rcfnzgC4weS5Y6ETEWCu67IggMsj9Uk9uTc
         iXng==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AAQBX9ftN9qsWHAJobj43QENlZLyt57ugzkDElmCCqreJJuWY/eS6wCP
	rHXKs1Gt0XsDzsGQWQbAtfg=
X-Google-Smtp-Source: AKy350a7K4GtJpo6A+2oJs6F7gqIYZa7z9D0zRFw087fLikFa3Yl4WVDHWdHeiDCI14rT3TJ33tpyA==
X-Received: by 2002:a7b:c455:0:b0:3df:97fd:221f with SMTP id l21-20020a7bc455000000b003df97fd221fmr2632581wmi.5.1680812561847;
        Thu, 06 Apr 2023 13:22:41 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:3b17:b0:3f0:68c7:dc5d with SMTP id
 m23-20020a05600c3b1700b003f068c7dc5dls1641558wms.3.-pod-canary-gmail; Thu, 06
 Apr 2023 13:22:40 -0700 (PDT)
X-Received: by 2002:a1c:6a13:0:b0:3df:e468:17dc with SMTP id f19-20020a1c6a13000000b003dfe46817dcmr7805602wmc.40.1680812560211;
        Thu, 06 Apr 2023 13:22:40 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1680812560; cv=none;
        d=google.com; s=arc-20160816;
        b=AJHWuO5BmF5IMCl//LKUa6HuApk3c6iMobJAZsOHNdTNfu9MvjhZ+5VapKgzxEpU1S
         cywVSPw5uXiGZYYtCw2bQfOJFdRVtR/1MrYT0YqMSeNKH0i2rKd+hRCSez0wHrS5+4S2
         71/04i7ubTw9oKqxvM9shiNPSXQsxDj2YK0vmvrHKhcx3WrU0h7HAY9NZYm+5NeAogLM
         mHczJYf5o/ck5wRg6Dv5zmD0oe16Hf/wOb0PxTFhroBixhroVth/NEUMGMmLdFH9DncR
         yH3MYCm+Q7sJqgggiU5qUwoF9eMAZK8IRn1mu8qtimokF1D9dLTyOJPdIJrje/5ta6Ij
         IYog==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=hPBwWzsuf10OLaAVTCaYjPLONJGSSpf1kqp034sRoAQ=;
        b=PHfDpVZebPYpJbujNvZk6h0FzgdImHUAd2le7hNrWW1rJ9jeiJZK2s8dGSFHXXzgyd
         1V1CvI51O64vexhzDXxrvnDiVZIg0qpdCgNR3sehWJvS+rQJ4aVuH8ZJ8BFyK6df418c
         8a8uYLm7MN7D0E1KWjMhVQDAU2WYuXzNe14GVgE8cp29tpZKkyexhs/oV8UWjuL5SRHJ
         stf32p0BnMRMN7wt/SziInyubIlL1PNgm18D90OkmI8+4XcAeS3/1yoPhyGbbdMnVFQP
         tsTSTPUuuFhCkwDVE2sQurg8BdhfSJaBCFQw8f/Xcy1RjV9a+Un74gP4HEK8fTGnnb6U
         JjFA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=QMxAnedN;
       spf=none (google.com: infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
Received: from casper.infradead.org (casper.infradead.org. [2001:8b0:10b:1236::1])
        by gmr-mx.google.com with ESMTPS id ay5-20020a05600c1e0500b003f0603058a9si305757wmb.0.2023.04.06.13.22.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 06 Apr 2023 13:22:40 -0700 (PDT)
Received-SPF: none (google.com: infradead.org does not designate permitted sender hosts) client-ip=2001:8b0:10b:1236::1;
Received: from j130084.upc-j.chello.nl ([24.132.130.84] helo=noisy.programming.kicks-ass.net)
	by casper.infradead.org with esmtpsa (Exim 4.94.2 #2 (Red Hat Linux))
	id 1pkW7o-0008k6-W2; Thu, 06 Apr 2023 20:22:37 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id D2DB3300202;
	Thu,  6 Apr 2023 22:22:27 +0200 (CEST)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 1000)
	id B702A212E36AE; Thu,  6 Apr 2023 22:22:27 +0200 (CEST)
Date: Thu, 6 Apr 2023 22:22:27 +0200
From: Peter Zijlstra <peterz@infradead.org>
To: Marco Elver <elver@google.com>
Cc: Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@kernel.org>,
	Oleg Nesterov <oleg@redhat.com>,
	"Eric W. Biederman" <ebiederm@xmission.com>,
	linux-kernel@vger.kernel.org, linux-kselftest@vger.kernel.org,
	Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com
Subject: Re: [PATCH v6 1/2] posix-timers: Prefer delivery of signals to the
 current thread
Message-ID: <20230406202227.GD405948@hirez.programming.kicks-ass.net>
References: <20230316123028.2890338-1-elver@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20230316123028.2890338-1-elver@google.com>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=casper.20170209 header.b=QMxAnedN;
       spf=none (google.com: infradead.org does not designate permitted sender
 hosts) smtp.mailfrom=peterz@infradead.org
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

On Thu, Mar 16, 2023 at 01:30:27PM +0100, Marco Elver wrote:
> From: Dmitry Vyukov <dvyukov@google.com>
> 
> POSIX timers using the CLOCK_PROCESS_CPUTIME_ID clock prefer the main
> thread of a thread group for signal delivery.     However, this has a
> significant downside: it requires waking up a potentially idle thread.
> 
> Instead, prefer to deliver signals to the current thread (in the same
> thread group) if SIGEV_THREAD_ID is not set by the user. This does not
> change guaranteed semantics, since POSIX process CPU time timers have
> never guaranteed that signal delivery is to a specific thread (without
> SIGEV_THREAD_ID set).
> 
> The effect is that we no longer wake up potentially idle threads, and
> the kernel is no longer biased towards delivering the timer signal to
> any particular thread (which better distributes the timer signals esp.
> when multiple timers fire concurrently).
> 
> Signed-off-by: Dmitry Vyukov <dvyukov@google.com>
> Suggested-by: Oleg Nesterov <oleg@redhat.com>
> Reviewed-by: Oleg Nesterov <oleg@redhat.com>
> Signed-off-by: Marco Elver <elver@google.com>

Acked-by: Peter Zijlstra (Intel) <peterz@infradead.org>

> ---
>  kernel/signal.c | 25 ++++++++++++++++++++++---
>  1 file changed, 22 insertions(+), 3 deletions(-)
> 
> diff --git a/kernel/signal.c b/kernel/signal.c
> index 8cb28f1df294..605445fa27d4 100644
> --- a/kernel/signal.c
> +++ b/kernel/signal.c
> @@ -1003,8 +1003,7 @@ static void complete_signal(int sig, struct task_struct *p, enum pid_type type)
>  	/*
>  	 * Now find a thread we can wake up to take the signal off the queue.
>  	 *
> -	 * If the main thread wants the signal, it gets first crack.
> -	 * Probably the least surprising to the average bear.
> +	 * Try the suggested task first (may or may not be the main thread).
>  	 */
>  	if (wants_signal(sig, p))
>  		t = p;
> @@ -1970,8 +1969,23 @@ int send_sigqueue(struct sigqueue *q, struct pid *pid, enum pid_type type)
>  
>  	ret = -1;
>  	rcu_read_lock();
> +	/*
> +	 * This function is used by POSIX timers to deliver a timer signal.
> +	 * Where type is PIDTYPE_PID (such as for timers with SIGEV_THREAD_ID
> +	 * set), the signal must be delivered to the specific thread (queues
> +	 * into t->pending).
> +	 *
> +	 * Where type is not PIDTYPE_PID, signals must just be delivered to the
> +	 * current process. In this case, prefer to deliver to current if it is
> +	 * in the same thread group as the target, as it avoids unnecessarily
> +	 * waking up a potentially idle task.
> +	 */
>  	t = pid_task(pid, type);
> -	if (!t || !likely(lock_task_sighand(t, &flags)))
> +	if (!t)
> +		goto ret;
> +	if (type != PIDTYPE_PID && same_thread_group(t, current))
> +		t = current;
> +	if (!likely(lock_task_sighand(t, &flags)))
>  		goto ret;
>  
>  	ret = 1; /* the signal is ignored */
> @@ -1993,6 +2007,11 @@ int send_sigqueue(struct sigqueue *q, struct pid *pid, enum pid_type type)
>  	q->info.si_overrun = 0;
>  
>  	signalfd_notify(t, sig);
> +	/*
> +	 * If the type is not PIDTYPE_PID, we just use shared_pending, which
> +	 * won't guarantee that the specified task will receive the signal, but
> +	 * is sufficient if t==current in the common case.
> +	 */
>  	pending = (type != PIDTYPE_PID) ? &t->signal->shared_pending : &t->pending;
>  	list_add_tail(&q->list, &pending->list);
>  	sigaddset(&pending->signal, sig);
> -- 
> 2.40.0.rc1.284.g88254d51c5-goog
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230406202227.GD405948%40hirez.programming.kicks-ass.net.
