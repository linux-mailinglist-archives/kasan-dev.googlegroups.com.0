Return-Path: <kasan-dev+bncBDAOBFVI5MIBB67ZZGGAMGQESENCMDQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33a.google.com (mail-wm1-x33a.google.com [IPv6:2a00:1450:4864:20::33a])
	by mail.lfdr.de (Postfix) with ESMTPS id 640B1450852
	for <lists+kasan-dev@lfdr.de>; Mon, 15 Nov 2021 16:30:04 +0100 (CET)
Received: by mail-wm1-x33a.google.com with SMTP id 145-20020a1c0197000000b0032efc3eb9bcsf9814491wmb.0
        for <lists+kasan-dev@lfdr.de>; Mon, 15 Nov 2021 07:30:04 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1636990204; cv=pass;
        d=google.com; s=arc-20160816;
        b=CeHsf8aSjCV0oZh6Fpsv338ueOq56JaA9QcCIRKA6OEeGOuvDxVY9KSx45I96abxam
         IrB65Idh9WYSPS00tvHA4os7zl86gBCwnSNdf0smL3d9YL9nME3hgAJ0k7WSE/832Eg/
         JxhzpaMpYnAtmJ/75nzT3QzsfWQfGJQNHDvjxy/fs6I8UjaOe8Tc1uDvtxufRFt/CIZH
         n+dPhizXurfKlXlxG8LgZXkHCsNVDx9hKPULatSkiojcCr6OTQdoSeHvla1GFnGSa8mV
         OJJLIkOmBvS9/HaFHi6L0VRZF41/U8KBjwRKjt3uwlKdmKkoHLpB4NDOW6P2TCBh7eDc
         sgEw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :references:in-reply-to:subject:cc:to:from:sender:dkim-signature;
        bh=BbvhovK3lsVF38Y4CMiRMRKT2Fg466/vlLjj0rHvoIk=;
        b=kNnbxDPFZegJAZYbWw5cO66Iew6BSfZ8WmKaREYHmj+JhRQV+36CXqQ9IVoevdOQI9
         rZ6/YJGwh/eEtaBCWn6+DXXWaKp67vVhV2bBJmgYoYtrp0dexAyjQr3ESuy7ePyarnUP
         VpbAPSrfKy03C+ImOAprP7O1ObNOP2Bc/vbPet4e5P12QQyYAt8L1gmUygHBLRS3Evfr
         c7KuA91zoLQ/2xvS5L0F82lYdgAGU5+2NLNZP4Bkl9e1e999qdP6WIzoBFa0icweBYM+
         ZY0ikwjU+7A6ee9PnXHBaCuQm1q5NTHyezI8ZsLz6gPv4h1FOpUd9r1vSJAEGtjJ/hTT
         JcNQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of valentin.schneider@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=valentin.schneider@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:in-reply-to:references:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=BbvhovK3lsVF38Y4CMiRMRKT2Fg466/vlLjj0rHvoIk=;
        b=XHuwcBySYYiX19UYv8b3QN4Ah3yAwwULwZinog4uNL+M9+GHtfq6FEPPQuKsyqr5Zz
         3gWuO7RDydmBquVrCeGEvr+bDSpAYgLE/cajuaGjn3FU3Cyec4+XlP1s2kZwMag+K2lj
         GHSsHwZRwHph75DBnunfvACHSmekqov+i2/hPpuYn0d6wAGcUoi/McOULsXWLvwEBgJT
         /5EFnKevMCErtrPcQFncwtJsrBvX5BcySTcNOr1rkOuxjC+Y1MLU1d5cASPJsgUZBfsY
         w0cPFhLBg2EmnIS3m0XoJWAioTRGFjR+OtCAUMW8Jn2hFvLS39mEs5KagxJbfeQmMSmO
         ZaRg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:in-reply-to:references
         :date:message-id:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=BbvhovK3lsVF38Y4CMiRMRKT2Fg466/vlLjj0rHvoIk=;
        b=e3GmBI+Danyd1Ivi2g/teYzeCvVxFjKfmjkbeJVzYHoZkR6TpWoC2oaGN2oskkzdyy
         OJY5AzelZ1nC9UxP1COPtel2CiZsX6KtnIsQipvyFop4HTyDFjGw2NC14/WrJbXWGVD9
         aNTEbIq6mE3UUdLfRwS7Rdfgo7dOGdb7g67V8i8T97zNVTL5MWvgLmlr3n5AwptI3Lqp
         ThgNnPNxxzJ9NsAnvuFr6KsQB8+PsbduKjHP+GuOI3B+IZrOy9SY8/M+qPGwCFfB+Pbf
         VFxECKyv6NNt8KecRw4uWimsLXMqjjDu9D1BEBTxYM3Di2/vjaT35TYoKXhzq00rPk/x
         W3oA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532NtpKnT5vU3ZGouhwjztgDJxB0guCac4jTpcuZdu61HV/j9Xr+
	+EuxkNm1T54rllV5XRlNkVg=
X-Google-Smtp-Source: ABdhPJyqtMdX/28xg4glNC4uK0j2oOC9vyQJdz3z8EYKZToQkDdxczpT2rVegou2FcJyONkg6ZGt8w==
X-Received: by 2002:a5d:628f:: with SMTP id k15mr49519094wru.363.1636990204113;
        Mon, 15 Nov 2021 07:30:04 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:6a05:: with SMTP id m5ls10898272wru.3.gmail; Mon, 15 Nov
 2021 07:30:03 -0800 (PST)
X-Received: by 2002:adf:fc90:: with SMTP id g16mr47425673wrr.53.1636990203329;
        Mon, 15 Nov 2021 07:30:03 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1636990203; cv=none;
        d=google.com; s=arc-20160816;
        b=OPT1s4fytMaLQQWuBbvjFzNAHU/2+7SGGivKxdn2Umc8IfS8LAtkvW7bttDgAPhw6R
         033ouc963bjartBj9tLj4YjI5hknr0o5OxndLeJJ0ZBmWAf7xWcxI522mrI2XPlUEVxu
         0CiRju5X5z6LExs0CoQu1QY86aVwoRORumCAFc6xZaoYpu9kQAsA1hXgk18ET+AvOmtW
         WKczIiVmvE74TlkIbQ3lHyoQijyeBncJKkv61OXIsz5Tmj5Rbxy6eK3fiR0TIUYYunzY
         UEnf8pTfgW2aKP62JMgzHEHn0We1DwBX5fg5TXhUiSfnSA4lGLzof1VxhdZEfdthTBA5
         UEPA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:references:in-reply-to:subject:cc:to
         :from;
        bh=LUmFveSO3zhUUmaQCQRLwp5HCF7es6iaWdQtkJmd/vw=;
        b=SI/w4hQohbLxr+WZbwrgeBqUCO2v/1NUDCdJei59AjRl1li6RK8IgEdzXNAmFl4F0q
         t6W0WJdkbaMX5yMagXH4/t4LuHiXimx1N15JzQr+gTdKC2nmgotSnEA8/DLBF4+pYhBm
         DB5MMI8XyUILdemxu9/YE97AEhxcvLrXyq8taYeIPapoxSfxkdb/hUuEdcd5owShk73R
         pCrPTO7Vr4eW7GFANLEEqli7LBvVg+J9q00cEd33pcgFVyQvCgbsTnS3FEzX6mIHXAw+
         B6HgIIvt7ehExhVD93Wsnnh4pbnsEW4r7dQnSBGMV8bsuNs3kBRiQROIbNJY/BEe587f
         ib4Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of valentin.schneider@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=valentin.schneider@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id x20si1019179wrg.3.2021.11.15.07.30.03
        for <kasan-dev@googlegroups.com>;
        Mon, 15 Nov 2021 07:30:03 -0800 (PST)
Received-SPF: pass (google.com: domain of valentin.schneider@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 6EF1C6D;
	Mon, 15 Nov 2021 07:30:02 -0800 (PST)
Received: from e113632-lin (e113632-lin.cambridge.arm.com [10.1.196.57])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 557F03F766;
	Mon, 15 Nov 2021 07:30:00 -0800 (PST)
From: Valentin Schneider <valentin.schneider@arm.com>
To: Michael Ellerman <mpe@ellerman.id.au>, linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com, linuxppc-dev@lists.ozlabs.org, linux-kbuild@vger.kernel.org
Cc: Peter Zijlstra <peterz@infradead.org>, Ingo Molnar <mingo@kernel.org>, Frederic Weisbecker <frederic@kernel.org>, Mike Galbraith <efault@gmx.de>, Marco Elver <elver@google.com>, Dmitry Vyukov <dvyukov@google.com>, Benjamin Herrenschmidt <benh@kernel.crashing.org>, Paul Mackerras <paulus@samba.org>, Steven Rostedt <rostedt@goodmis.org>, Masahiro Yamada <masahiroy@kernel.org>, Michal Marek <michal.lkml@markovi.net>, Nick
 Desaulniers <ndesaulniers@google.com>
Subject: Re: [PATCH v2 3/5] powerpc: Use preemption model accessors
In-Reply-To: <87o86rmgu8.fsf@mpe.ellerman.id.au>
References: <20211110202448.4054153-1-valentin.schneider@arm.com> <20211110202448.4054153-4-valentin.schneider@arm.com> <87o86rmgu8.fsf@mpe.ellerman.id.au>
Date: Mon, 15 Nov 2021 15:29:53 +0000
Message-ID: <87lf1pqvwu.mognet@arm.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: valentin.schneider@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of valentin.schneider@arm.com designates 217.140.110.172
 as permitted sender) smtp.mailfrom=valentin.schneider@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
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


Doh, thought I had sent this one out already...

On 11/11/21 15:55, Michael Ellerman wrote:
> Valentin Schneider <valentin.schneider@arm.com> writes:
>> Per PREEMPT_DYNAMIC, checking CONFIG_PREEMPT doesn't tell you the actual
>> preemption model of the live kernel. Use the newly-introduced accessors
>> instead.
>>
>> sched_init() -> preempt_dynamic_init() happens way before IRQs are set up,
>> so this should be fine.
>
> Despite the name interrupt_exit_kernel_prepare() is called before IRQs
> are setup, traps and page faults are "interrupts" here.
>
> So I'm not sure about adding that call there, because it will trigger a
> WARN if called early in boot, which will trigger a trap and depending on
> the context we may not survive.
>
> I'd be happier if we can make it a build-time check.
>

This can't be done at build-time for PREEMPT_DYNAMIC, but that can be
punted off to whoever will implement ppc support for that :-) AFAICT if
this can't use preempt_dynamic_mode (due to how "late" it is setup), the
preempt_schedule_irq() needs to go and ppc needs to use irqentry_exit() /
irqentry_exit_cond_resched().

I dropped that for v2.

> cheers
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/87lf1pqvwu.mognet%40arm.com.
