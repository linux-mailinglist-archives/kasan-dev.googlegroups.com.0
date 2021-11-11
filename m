Return-Path: <kasan-dev+bncBC7OBJGL2MHBBQV4WOGAMGQENZMCPOQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x338.google.com (mail-wm1-x338.google.com [IPv6:2a00:1450:4864:20::338])
	by mail.lfdr.de (Postfix) with ESMTPS id BE84044D3CD
	for <lists+kasan-dev@lfdr.de>; Thu, 11 Nov 2021 10:11:30 +0100 (CET)
Received: by mail-wm1-x338.google.com with SMTP id y9-20020a1c7d09000000b003316e18949bsf2394156wmc.5
        for <lists+kasan-dev@lfdr.de>; Thu, 11 Nov 2021 01:11:30 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1636621890; cv=pass;
        d=google.com; s=arc-20160816;
        b=v4k5NJFEao3zuAd71V8rGWzVYX6+v0MHTww9dM9syT5/+4GOj6mr8KqukD3rRtV+a7
         jzOhw0zBPepBCeJaS/rC1e9DRFYU0BTcBW8HF1TglPlo/yT8UeBDzbxPPrzeM1hIVXum
         K46OMGHGyblSjLn7coQTOjvzzpf9dFcOe7JnwMgX35PlilQOdLXmvn6TSVgRU8UMcSp6
         OvFI32o1lc+rEuwNjh7Vi30tAMD3BdSwW8ZBRVeok1XJjKDyRfUErxav2PCstHiBVcpi
         DQKb42/pHqm13WjSEt3sgR0EpNAGn8ldKLsdRMEMzFr6si9riVxZ8Z9hCyXut9Q4NEth
         3Mwg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=8LSKUXT4uMX8s8n1SfjaS4eLm4VtH/WRIoTR4eUmbek=;
        b=EZEXzn0ENlVEU5nMKrYdmJLeKRfnApP+RJRMoGHO/EUpkOinLl8uHQqxp4J91+tvME
         jjzddGXKdr5E3TpfNLk8gDmOp9hjVhEb/EwIyOuH5KEp1E36LIuMDaZu4CfIunoSe4s/
         UgLmrxLJqGDuCmsfUeWBbFOZLaZLiudVoFddLACm2wlEkZnSghSisdI5G+xFLidmDKG4
         a2L35qYt1YoKilALAyjG7FUJgAnfuPVWCAHBbp2/IRzSt7xEq0Gq6CnCWk2IruFBcbKv
         W4v48AqC7+op3wlogTtFkbp/GJtAg1EqK8ACfsHOO5egchZQ/AzdpYOoo2dhstYdJHa4
         zsTg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=WV4O0X4u;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::32d as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=8LSKUXT4uMX8s8n1SfjaS4eLm4VtH/WRIoTR4eUmbek=;
        b=RA/kQAnboMlImSE5RLIe95ffc03F9Zi44kuD1OsTqf7IvWJnE3URKDDCRANYlGw54b
         BiDHr6D53j1jR/ZlPPa70b1ina8HDFfjTrMNmUN4ggzpxzUT1y81c8zKKrmI7wLvJUdY
         FG2vIVkBE/XLf7m3GYuU3fxsi49lY2Jq/JSGko1TOPjq9cSRdr+rQ7cCl6YNEjyTYiMk
         3wmP3zH8cEb1JdgTPRnquKJhKxCdcC+D+XRgEUoLQ8FP034vnMDzsgWf7yFWz+2eCVgO
         V8aAyT39ZOYCN3ZkFX9bMfsqWdjnXLMk3cjfzsBcH/crqYHpSNBKVHic74hpB3aen4vB
         cy8g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=8LSKUXT4uMX8s8n1SfjaS4eLm4VtH/WRIoTR4eUmbek=;
        b=e0f5m9PhJPIOshqD6bVKWR9mJmvOs8eXvizTB9MCgh6mrABOjJ1bxzcq/6e904Njjz
         PvgQNqb9AJ1P3/vdPrGnWIoklXB+ko89S43zd32wtmsaaPLSzJm8tG9opUXIDxUzX9gv
         D/DScBA0sCR9NBavAFQI99fERZ8UwA/0Zjq8hRHbVTC5gKVbVywFd94Djotq5JiOtYql
         kvTdkPbAQD5SBd3q62nfKqahxFQ8WIjBBRF8EhVKj0X7bAkHCNEecMUbJlI0fBSrP5Jv
         VinuUGPsZ8AytCKmqpNQQreXYtC66WAccKWNwG3pdIRioaVqouu1RrYcPK86dfS4JBmC
         iWTQ==
X-Gm-Message-State: AOAM531h+T+NPwlLp1dRC2GWpPlUnLGPX5evdnFrTMGMVdm6KXohMZDp
	8quOr52iYfLdFCQBRveMog0=
X-Google-Smtp-Source: ABdhPJyprAb367VsBzXy3zFkxPXDR8uYZWr+hq1eZB75CGwXF0aecmEodTO1BdXMGGFva2aMfjmTlQ==
X-Received: by 2002:a7b:c744:: with SMTP id w4mr6765709wmk.50.1636621890529;
        Thu, 11 Nov 2021 01:11:30 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:fe0b:: with SMTP id n11ls782150wrr.0.gmail; Thu, 11 Nov
 2021 01:11:29 -0800 (PST)
X-Received: by 2002:a5d:4846:: with SMTP id n6mr6734324wrs.249.1636621889529;
        Thu, 11 Nov 2021 01:11:29 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1636621889; cv=none;
        d=google.com; s=arc-20160816;
        b=h70BFBFIGq/ss5sxjsIL/rWiZ5ydH94eQ0kMH9ng/Zt7sl5V6n5anhsxP6/uyVxtdK
         cuOli21uH/EGtQFy3vWp3QfMI+Emxm1u6vd9QbXSgWdqlKS3pK362yZLoue4XFuScceZ
         MzmjtVQ7xNWAK6WrjkxXOmL843O/p24Sc6nQcXeRXWxRPqV4/iE7V4RpjRGEb/h+WA3C
         SSDTLsnBJtBUr4K/G03jAPRQDZC7g4KCX/zFingc0D4GW/DOI8CUAM+IABVlxFJG31a9
         u43XG/HTG965o/YQtvJWr/LW8IpH2vr8dNRF1lql0X9QiYc5BHTWPEAYRZri0G4HC6yS
         3MTA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=RJN505w6CL42PiEBXtyIsEZEsP4VhYdScJ4DvF6IvUE=;
        b=iIEcqlL/GxUl5U94UKCc5qhdasyGkoSSHwPHJ2rljMHNAQuQzItuZRj7EC006g49ht
         0shdScFhDdmuS460kNNOQSsSZjqHuS1B+kKs5S4Y3SrxXHJOqAWDFClicJzAAq7ja8xB
         503CcyoptooG3z90ThSlY1FcGYiYr1bZKgEGC4zVlb+8dwye8TA/fzUqbl+OvM05Tuns
         9OiGY3SGyqyL61yuAQC8F0iyGfl/SWME49LZgIHjOi88T6kg0YLEqRv9X66LCWDPFW79
         34kTVUeUEklOEatFbtIXam9mV+V3qXst09vSrWO3YRBU0QrFJ/8s7m5EndUvC+rEZcgw
         BY5A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=WV4O0X4u;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::32d as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x32d.google.com (mail-wm1-x32d.google.com. [2a00:1450:4864:20::32d])
        by gmr-mx.google.com with ESMTPS id q74si550615wme.0.2021.11.11.01.11.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 11 Nov 2021 01:11:29 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::32d as permitted sender) client-ip=2a00:1450:4864:20::32d;
Received: by mail-wm1-x32d.google.com with SMTP id o4-20020a1c7504000000b0032cab7473caso5096678wmc.1
        for <kasan-dev@googlegroups.com>; Thu, 11 Nov 2021 01:11:29 -0800 (PST)
X-Received: by 2002:a1c:a9c6:: with SMTP id s189mr6684146wme.38.1636621889057;
        Thu, 11 Nov 2021 01:11:29 -0800 (PST)
Received: from elver.google.com ([2a00:79e0:15:13:fd21:69cc:1f2b:9812])
        by smtp.gmail.com with ESMTPSA id s13sm8531050wmc.47.2021.11.11.01.11.28
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 11 Nov 2021 01:11:28 -0800 (PST)
Date: Thu, 11 Nov 2021 10:11:21 +0100
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: Valentin Schneider <valentin.schneider@arm.com>
Cc: linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com,
	linuxppc-dev@lists.ozlabs.org, linux-kbuild@vger.kernel.org,
	Peter Zijlstra <peterz@infradead.org>,
	Ingo Molnar <mingo@kernel.org>,
	Frederic Weisbecker <frederic@kernel.org>,
	Mike Galbraith <efault@gmx.de>, Dmitry Vyukov <dvyukov@google.com>,
	Michael Ellerman <mpe@ellerman.id.au>,
	Benjamin Herrenschmidt <benh@kernel.crashing.org>,
	Paul Mackerras <paulus@samba.org>,
	Steven Rostedt <rostedt@goodmis.org>,
	Masahiro Yamada <masahiroy@kernel.org>,
	Michal Marek <michal.lkml@markovi.net>,
	Nick Desaulniers <ndesaulniers@google.com>
Subject: Re: [PATCH v2 4/5] kscan: Use preemption model accessors
Message-ID: <YYzeOQNFmuieCk3T@elver.google.com>
References: <20211110202448.4054153-1-valentin.schneider@arm.com>
 <20211110202448.4054153-5-valentin.schneider@arm.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20211110202448.4054153-5-valentin.schneider@arm.com>
User-Agent: Mutt/2.0.5 (2021-01-21)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=WV4O0X4u;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::32d as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
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

Subject s/kscan/kcsan/

On Wed, Nov 10, 2021 at 08:24PM +0000, Valentin Schneider wrote:
> Per PREEMPT_DYNAMIC, checking CONFIG_PREEMPT doesn't tell you the actual
> preemption model of the live kernel. Use the newly-introduced accessors
> instead.
> 
> Signed-off-by: Valentin Schneider <valentin.schneider@arm.com>

Reviewed-by: Marco Elver <elver@google.com>

Though it currently doesn't compile as a module due to missing
EXPORT_SYMBOL of is_preempt*().

> ---
>  kernel/kcsan/kcsan_test.c | 4 ++--
>  1 file changed, 2 insertions(+), 2 deletions(-)
> 
> diff --git a/kernel/kcsan/kcsan_test.c b/kernel/kcsan/kcsan_test.c
> index dc55fd5a36fc..14d811eb9a21 100644
> --- a/kernel/kcsan/kcsan_test.c
> +++ b/kernel/kcsan/kcsan_test.c
> @@ -1005,13 +1005,13 @@ static const void *nthreads_gen_params(const void *prev, char *desc)
>  	else
>  		nthreads *= 2;
>  
> -	if (!IS_ENABLED(CONFIG_PREEMPT) || !IS_ENABLED(CONFIG_KCSAN_INTERRUPT_WATCHER)) {
> +	if (!is_preempt_full() || !IS_ENABLED(CONFIG_KCSAN_INTERRUPT_WATCHER)) {
>  		/*
>  		 * Without any preemption, keep 2 CPUs free for other tasks, one
>  		 * of which is the main test case function checking for
>  		 * completion or failure.
>  		 */
> -		const long min_unused_cpus = IS_ENABLED(CONFIG_PREEMPT_NONE) ? 2 : 0;
> +		const long min_unused_cpus = is_preempt_none() ? 2 : 0;
>  		const long min_required_cpus = 2 + min_unused_cpus;
>  
>  		if (num_online_cpus() < min_required_cpus) {
> -- 
> 2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YYzeOQNFmuieCk3T%40elver.google.com.
