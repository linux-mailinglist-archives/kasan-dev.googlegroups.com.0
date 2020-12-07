Return-Path: <kasan-dev+bncBDAMN6NI5EERBEGUXH7AKGQE66VLJNY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23f.google.com (mail-lj1-x23f.google.com [IPv6:2a00:1450:4864:20::23f])
	by mail.lfdr.de (Postfix) with ESMTPS id D6C202D17BB
	for <lists+kasan-dev@lfdr.de>; Mon,  7 Dec 2020 18:44:48 +0100 (CET)
Received: by mail-lj1-x23f.google.com with SMTP id j3sf4892906lji.19
        for <lists+kasan-dev@lfdr.de>; Mon, 07 Dec 2020 09:44:48 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1607363088; cv=pass;
        d=google.com; s=arc-20160816;
        b=nr+cJ7ZTHhf99oeogTU0c6M8TIoUdJMXcxyDj6ZbDyV5uVZeSNLniJBCH6xQQyEeLY
         zlgMV8m0dmvi99G+VduegNYhsdi1jIGmy+Y5Z1+8ocvBNF7na7ZbW45yFSEPl1Eyt3kh
         KMkmWcuOp85Pi1jEZnIEBdLNYLVLOYBkkql+iO0PjYRZN/nf+9IVJpzV7RyTqV/BPqIp
         J73uXkeSVxfdIv9hcMzgqPE+qObU2LbaiGh+p6WO5XJgmYf+A9mqkdkxwLFtyfOid6Xt
         fzvQMnJijEum6N4N1WOkP0ttDr9xZhEvGd3kRElTjhVNno+4r2qO76+JWy6qu4Q7whe6
         SfeA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :references:in-reply-to:subject:cc:to:from:sender:dkim-signature;
        bh=Y6Ga/beKOY6sxva+8GQPYb3shfXbAupAxqBUK26bSMY=;
        b=vDJO7RdgtPupP9OSjMqMT/z2lbbiTW29Oq1zti6zpyRhMAHmfO7FJEr8yr+kbMnVdL
         taCvoBAqcb5TeUtxuWgCcAE+olG2cXB/MzksnryZtyxeqjY2W+HtZ1Ql1ZBlr5binyjw
         tDYId67DEwwCh8FOc8XrB/JQ7yfpLjYj8R7+l2DU0J+WtmMsxwKVfI2eGoBOIY38IAug
         HrpEDHfGgbspffLETQJG2AcI1olqXbjufkQlpPVmgaG6q+PFJ8hOz8ErmgA23+dnfsH+
         eU4ByVgk0Acn9g2fU/XqlZMI5IriB4jYVEcM8QJstybxvcDlIEo2Tu1HcWvXXTsCWOdi
         +Ygw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=C9+xbwFq;
       dkim=neutral (no key) header.i=@linutronix.de header.s=2020e header.b=f3NkeE7M;
       spf=pass (google.com: domain of tglx@linutronix.de designates 193.142.43.55 as permitted sender) smtp.mailfrom=tglx@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:in-reply-to:references:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Y6Ga/beKOY6sxva+8GQPYb3shfXbAupAxqBUK26bSMY=;
        b=rm1OV4r6tkezAU/4uFOuM0Kc80YTOdwkgXVNcfkFujjWfCAa3nzLq+war1FoDR6T0I
         THzGodvUMdvN+mCJrmCfQPGHu9R360TrBAjYRbGMy4T9e43lXX8s1aiQjTl2RFCNLYA9
         AcAFoAll0FlOj9B5AXa69pEcJrvzdi7Hq+b6L83LPBS64//K79ra7tQ+A6tBzfM6eint
         sLHLWIwg/cD94Bxda/ExhVLb1mR/H1D6Z6WQPxEMqLF1HX9mJ/EOYc3yXVmxbFsVautz
         BqkU/IYasefewfenXS6DAbd80VvTmI0p7BzRtF+ZKt0ZdiEeunvqGGrsarMnTrs2PYUU
         YR6g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:in-reply-to:references
         :date:message-id:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Y6Ga/beKOY6sxva+8GQPYb3shfXbAupAxqBUK26bSMY=;
        b=p0jgCmWJR2alv8n/g9QVec8bUyGDI+G5vWJz2LwbrvejHg5W0qK2ytqNM9S2K118g/
         ZGYKr+cUBFhCxiqofVuKJKKv3y2XXnVI85StUDOYwuhDnnGn/uR+ouIszUU/+aYRT3bX
         GQobTIPU40HIOThULR0WGXZA7RqYDejB+HQYqiKDb3T0g3rz8dwftMMdwjN89Qj3s9xq
         kwTO3ThI6Ky33ghUG0jeFWlFniAPwK6dJ2EqFp7FjgFvIshApfLsST9J60raSMxuWAaP
         Jrv5rLHhLzMhVv08QyZdqjSeEOWvAgMILPgg+oDPU5JCJ+7Sqd46P3c/5LYoUbbdxFbK
         8Oqw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533g7sLlmb8mnlg09XjA3x9wxCsW7XAPazWa2aZziQih/Ev+JOhf
	prITootz1WtlYr9oWXIfMCc=
X-Google-Smtp-Source: ABdhPJyxIaqdfwE1Uj9K0o5rVQ+Uje5HyEBSBZdXmopC3x+Unx010w63Il1fzrNK36nQPZuoL0ofRA==
X-Received: by 2002:a2e:8652:: with SMTP id i18mr1250099ljj.63.1607363088463;
        Mon, 07 Dec 2020 09:44:48 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:9059:: with SMTP id n25ls2944400ljg.3.gmail; Mon, 07 Dec
 2020 09:44:47 -0800 (PST)
X-Received: by 2002:a2e:99c8:: with SMTP id l8mr8546128ljj.469.1607363087445;
        Mon, 07 Dec 2020 09:44:47 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1607363087; cv=none;
        d=google.com; s=arc-20160816;
        b=OyIM2K+Qz7+TsjZvDQDOtbIse/6833ye5Tk1sv/Mva0dnyp1jxzBGH9ZRXHX7ayNFL
         kM3E/QJDxJuW/9FmQ9KfDLswkH6Ijf/a+G5h0pzY2gftjFzj+OBFx7UdGLWMcN5HYcau
         wLgX6a+fQxCffAP/RLX16/2pKxSiq/HqH6+vVUTDUmKvQk5Pvsz64n7TUMNcWnIRZy5D
         QcSSnHqC+nlrvJAHaQuogjwc914W1NKan74ABcV/K5tWxF8TfrFXI4jVMkDsMJeKGDmb
         e5rFYZwrmcGEngCIEK9d3xldpLTkgVUbI3GcCWoFekSq+Kq4oANHJh9a7NvICAvsXlVe
         xvgw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:references:in-reply-to:subject:cc:to
         :dkim-signature:dkim-signature:from;
        bh=1QUndeheCuNlov7jkNGxkSugjzDYPAV/QAtYJEVlMGg=;
        b=aqKvALZJpbaS0x5sK6cLwjNNfVE9D+xHXYvXGGwQKCUJSE25vzqAnZ5MY7Ng4MEX0B
         vH2YXPibjMx880n7IuQP9pM9sOTVXWXlx4js1lnVjZGALJdyZRGD23vkoLkqn+mVTY+1
         8bxH1YrSQ1qs2yJVpNFn6TNjJUn3/7HK7ERIq46ItRhkyHvZcWYEFkJBG36PR/PkrjRp
         CwQ+TSiucvFVQHm0SqETzwWuPAmRF8iRJTq35Qq+rRshx+zxYSjLWlh+RPxZaDypN8h4
         qEN7oRxd1fwo5kRxtV3istszMPc4PM8MrAm2SoxJLGF+0XQzGRRjnUZqdU9nRqC8L2gk
         QtYg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=C9+xbwFq;
       dkim=neutral (no key) header.i=@linutronix.de header.s=2020e header.b=f3NkeE7M;
       spf=pass (google.com: domain of tglx@linutronix.de designates 193.142.43.55 as permitted sender) smtp.mailfrom=tglx@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
Received: from galois.linutronix.de (Galois.linutronix.de. [193.142.43.55])
        by gmr-mx.google.com with ESMTPS id h21si188394ljj.6.2020.12.07.09.44.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 07 Dec 2020 09:44:47 -0800 (PST)
Received-SPF: pass (google.com: domain of tglx@linutronix.de designates 193.142.43.55 as permitted sender) client-ip=193.142.43.55;
From: Thomas Gleixner <tglx@linutronix.de>
To: Peter Zijlstra <peterz@infradead.org>
Cc: LKML <linux-kernel@vger.kernel.org>, Marco Elver <elver@google.com>, kasan-dev <kasan-dev@googlegroups.com>, "Paul E. McKenney" <paulmck@kernel.org>, Ingo Molnar <mingo@kernel.org>, Frederic Weisbecker <frederic@kernel.org>, Will Deacon <will@kernel.org>, Naresh Kamboju <naresh.kamboju@linaro.org>
Subject: Re: [patch 1/3] tick: Remove pointless cpu valid check in hotplug code
In-Reply-To: <20201207115953.GR3021@hirez.programming.kicks-ass.net>
References: <20201206211253.919834182@linutronix.de> <20201206212002.582579516@linutronix.de> <20201207115953.GR3021@hirez.programming.kicks-ass.net>
Date: Mon, 07 Dec 2020 18:44:46 +0100
Message-ID: <871rg15x4h.fsf@nanos.tec.linutronix.de>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: tglx@linutronix.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linutronix.de header.s=2020 header.b=C9+xbwFq;       dkim=neutral
 (no key) header.i=@linutronix.de header.s=2020e header.b=f3NkeE7M;
       spf=pass (google.com: domain of tglx@linutronix.de designates
 193.142.43.55 as permitted sender) smtp.mailfrom=tglx@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
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

On Mon, Dec 07 2020 at 12:59, Peter Zijlstra wrote:
> On Sun, Dec 06, 2020 at 10:12:54PM +0100, Thomas Gleixner wrote:
>
>>  void tick_handover_do_timer(void)
>>  {
>> +	if (tick_do_timer_cpu == smp_processor_id())
>> +		tick_do_timer_cpu = cpumask_first(cpu_online_mask);
>
> For the paranoid amongst us, would it make sense to add something like:
>
> 	/*
> 	 * There must always be at least one online CPU.
> 	 */
> 	WARN_ON_ONCE(tick_do_timer_cpu >= nr_cpu_ids);

And add that to all places which look at online mask during hotplug.

If we really care we can add it somewhere central in the hotplug
code. If that ever triggers then the wreckaged tick duty is just
uninteresting.

Thanks,

        tglx

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/871rg15x4h.fsf%40nanos.tec.linutronix.de.
