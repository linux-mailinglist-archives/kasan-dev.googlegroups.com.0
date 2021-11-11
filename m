Return-Path: <kasan-dev+bncBCR5PSMFZYORBR6EWKGAMGQEQ7LBPCQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3c.google.com (mail-oo1-xc3c.google.com [IPv6:2607:f8b0:4864:20::c3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 29B4A44D10E
	for <lists+kasan-dev@lfdr.de>; Thu, 11 Nov 2021 05:55:37 +0100 (CET)
Received: by mail-oo1-xc3c.google.com with SMTP id o6-20020a4ad486000000b002b8d8eef8f3sf2443582oos.16
        for <lists+kasan-dev@lfdr.de>; Wed, 10 Nov 2021 20:55:37 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1636606535; cv=pass;
        d=google.com; s=arc-20160816;
        b=rybU+u0DmbhLhUtdyesYzx/dBB5llzpk8AgukY/nCLh1bLy3Llova5FSw/L8MRV7+y
         mXWS7ANap2PsSLTkPE41QfIITcsCwe8KI2qiGAtPmwy+DRicY3O1PTFzVbmcoaoXEreu
         wHRLPf4Mp7GSiCWwRJ6DRh1q0I6IshtnN1DnLfjZf0pvqrryptJVPfakK/3fU7SuqUNl
         hJtvJxZcrhQzHkb6bl25ppO+zw7Ev0pYffXvfp7rufa5dqY0UG5qzJcKG606TNzj9M9O
         TZ9wn0QhNK3+X8pzNmdn/O0F0dignMo61Tlu8ntkFbPG84+Z8e2PH2REyrYQiVG2q1uq
         P7RA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :references:in-reply-to:subject:cc:to:from:sender:dkim-signature;
        bh=EQX5x0nUyunu6DFZWx65VbQlvNjFYFR7AdmFMBebWVo=;
        b=ur4j0LThiJKH2OxeDnUPJHEXVqw02Fc0S0I3KG9bP+nClLWhMjRuaNubKG05zFahRy
         kbZ0l26Hg9trD64Hf604UyaTyZv2pymfzlFSsbMtdt7FYyO6myoa2oLYp8vO4MuhQLmi
         SSCxefjF25TWUwMKzAkoWoneSNZFbXT6x/sk+5YYajA/lm5I6WsSudMW3M2AQq8/muq/
         2JtpqQVJymMM4zK0qEjK76snoDE41OUeaR2vQt/tDsRkzkXHUR7SXTEU+IRk0LPxrT0G
         qIHLSggPTuXNoAIgMbYso3DHO0q9sMCMQSl2cPwv/1StY+GDStYVdHCJzp2I/c1N/9cs
         cDCg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ellerman.id.au header.s=201909 header.b="qCM/P8yF";
       spf=pass (google.com: domain of mpe@ellerman.id.au designates 150.107.74.76 as permitted sender) smtp.mailfrom=mpe@ellerman.id.au
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:in-reply-to:references:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=EQX5x0nUyunu6DFZWx65VbQlvNjFYFR7AdmFMBebWVo=;
        b=ZJLZlMd3ty2OzuzB7q68J9fCTaXzQLpTnMp3aZZIn4Akiz/krFxfa4Cgu30aXdyjsU
         VBHgTRThKd2DLwQuT5PC7nn06k+llJsqeSKffFteg0OEH1Ne9OW3ExylDcguBQVlZCsw
         JTl4Ny+oexTrByd5JSU43/9tbKOzh4ULU0O0zSlRr5KC4opSRc7gBIh6YykA8u92VQyV
         QCMJ8DWCLIEgVxc8vVcvtXyCJZYhl55BLZk2Kxgh7JRPkGHUNWdNhbUFoA8XEDgKAtHx
         3ZWsxLN+sqjAtrYN1Cy1QAlRRIuJMvjr8ViglZhikwwbX91zUGSXdysiZIFArJupKkAF
         FXnw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:in-reply-to:references
         :date:message-id:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=EQX5x0nUyunu6DFZWx65VbQlvNjFYFR7AdmFMBebWVo=;
        b=KcEC4S21spfVvWTkAkAh/TagDdvJt0orfZ5Mdtv7K58kyGqzf3F6ywRm9IqJAhyrR4
         oQQc6SrUkp0OpSeWdbqjay8qoinH9IDCK1kwzy53kB+XuDf8vPrGPJRRt+xpuxWg93jI
         jxTx7otcFmI4V7QMPsFHDnGZjVLuOMjJeCElYMBGQxcCbD1V2OXLCUpm2nAFsKgGIX/Z
         r82ztsDcHo7NxPsKYFE2VGe8qcZW2DO4PefyQjIkU8yRruNvuvhCpCSYmrYsYTOL9Zdm
         osRDHNzLGLg/iLaLpUObtjEWJ+ti6BWy/zV0ev0mWYheAFQCJTyuSZiKwDLDhDiWRoyV
         8FhQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531Fg9Ya7TCMiSPmDPtZlnvNiTfb29Aji/NLDjYH6SljntGP9QMH
	/aJAp49FX4LGlZ1npqZqXss=
X-Google-Smtp-Source: ABdhPJxKnjay3MSdMfzrTbNZF9ah3OaU0pHku5RbwAGyfFdYD9WPKXS0Nwj55NZqHb1ZY2PuahxA4w==
X-Received: by 2002:a05:6808:1305:: with SMTP id y5mr3826186oiv.83.1636606535609;
        Wed, 10 Nov 2021 20:55:35 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:4599:: with SMTP id x25ls751758ote.9.gmail; Wed, 10 Nov
 2021 20:55:35 -0800 (PST)
X-Received: by 2002:a9d:7855:: with SMTP id c21mr3779162otm.167.1636606535217;
        Wed, 10 Nov 2021 20:55:35 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1636606535; cv=none;
        d=google.com; s=arc-20160816;
        b=ulJ+6QaVFLnh/K6njRye7k4bwSdcl8cqj38JRWwW8hMAEe5YVWCLWRIgCE9xi3ZYhL
         9y16jYy6q4J34iizVQVVeC1onoST/KzAWEJQS1oJJjzPev12uqogIIANHDsgqYY4/Cgb
         wmDj2aM93i0XJpazFo0s1anLUBNPN5zxOwIEJB58FVqbxWHKjHul5VxedOkSvy6p7+Ey
         K5RqPdIvGqu9zRFA4ErkFpoHbLF3DMQcipglbkDfQnqTVdCRGJEtWOANGCfSFsr5pWhs
         JszvGu9mTXGYypf3rPUEXtKDGe4+fEW/JxytXXzr6QduwipJw/BLWB5sVygZWl22oedV
         6FWw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:references:in-reply-to:subject:cc:to
         :from:dkim-signature;
        bh=GCVMUlmIvsbs8ofijos/QMPB8fyrPXIzfNWltTIec0g=;
        b=R4V/g6LpnpfR2+PGpIlBVS/fBig2jl/RnTig1XR5Anb7UCklJZ0lCRm9wbWDGW/AKZ
         4qXj49pxNSZUGg0ktzYQkRcctWCSMarrjTf6S6LA8+lbSjrzL5tIT5n5Viw8+m+ImOGq
         TIxcraCbdqaQvq7VnOt5NgG49TUWMoTrsu6cvZP3d5gSWpVmKh3RMvK9ooK5LIihFGqU
         rG2i9FTxjRjQ5XSkb/OlfMKuwZUVKqpQftV6/awG/T9+u24lgSw4Ug5oBqqSXGgaymWR
         iOYdbr4+8QD8FRFpEKZMvsKQOEWOYpX3sJCWC8eXjAfPSbQSAMMyt5mwLiqiImJ2B0Zc
         3ZMg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ellerman.id.au header.s=201909 header.b="qCM/P8yF";
       spf=pass (google.com: domain of mpe@ellerman.id.au designates 150.107.74.76 as permitted sender) smtp.mailfrom=mpe@ellerman.id.au
Received: from gandalf.ozlabs.org (gandalf.ozlabs.org. [150.107.74.76])
        by gmr-mx.google.com with ESMTPS id d17si301284oiw.0.2021.11.10.20.55.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 10 Nov 2021 20:55:34 -0800 (PST)
Received-SPF: pass (google.com: domain of mpe@ellerman.id.au designates 150.107.74.76 as permitted sender) client-ip=150.107.74.76;
Received: from authenticated.ozlabs.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange ECDHE (P-256) server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by mail.ozlabs.org (Postfix) with ESMTPSA id 4HqTtS41wYz4xbs;
	Thu, 11 Nov 2021 15:55:28 +1100 (AEDT)
From: Michael Ellerman <mpe@ellerman.id.au>
To: Valentin Schneider <valentin.schneider@arm.com>,
 linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com,
 linuxppc-dev@lists.ozlabs.org, linux-kbuild@vger.kernel.org
Cc: Peter Zijlstra <peterz@infradead.org>, Ingo Molnar <mingo@kernel.org>,
 Frederic Weisbecker <frederic@kernel.org>, Mike Galbraith <efault@gmx.de>,
 Marco Elver <elver@google.com>, Dmitry Vyukov <dvyukov@google.com>,
 Benjamin Herrenschmidt <benh@kernel.crashing.org>, Paul Mackerras
 <paulus@samba.org>, Steven Rostedt <rostedt@goodmis.org>, Masahiro Yamada
 <masahiroy@kernel.org>, Michal Marek <michal.lkml@markovi.net>, Nick
 Desaulniers <ndesaulniers@google.com>
Subject: Re: [PATCH v2 3/5] powerpc: Use preemption model accessors
In-Reply-To: <20211110202448.4054153-4-valentin.schneider@arm.com>
References: <20211110202448.4054153-1-valentin.schneider@arm.com>
 <20211110202448.4054153-4-valentin.schneider@arm.com>
Date: Thu, 11 Nov 2021 15:55:27 +1100
Message-ID: <87o86rmgu8.fsf@mpe.ellerman.id.au>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: mpe@ellerman.id.au
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ellerman.id.au header.s=201909 header.b="qCM/P8yF";       spf=pass
 (google.com: domain of mpe@ellerman.id.au designates 150.107.74.76 as
 permitted sender) smtp.mailfrom=mpe@ellerman.id.au
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

Valentin Schneider <valentin.schneider@arm.com> writes:
> Per PREEMPT_DYNAMIC, checking CONFIG_PREEMPT doesn't tell you the actual
> preemption model of the live kernel. Use the newly-introduced accessors
> instead.
>
> sched_init() -> preempt_dynamic_init() happens way before IRQs are set up,
> so this should be fine.

Despite the name interrupt_exit_kernel_prepare() is called before IRQs
are setup, traps and page faults are "interrupts" here.

So I'm not sure about adding that call there, because it will trigger a
WARN if called early in boot, which will trigger a trap and depending on
the context we may not survive.

I'd be happier if we can make it a build-time check.

cheers

> diff --git a/arch/powerpc/kernel/interrupt.c b/arch/powerpc/kernel/interrupt.c
> index de10a2697258..c56c10b59be3 100644
> --- a/arch/powerpc/kernel/interrupt.c
> +++ b/arch/powerpc/kernel/interrupt.c
> @@ -552,7 +552,7 @@ notrace unsigned long interrupt_exit_kernel_prepare(struct pt_regs *regs)
>  		/* Returning to a kernel context with local irqs enabled. */
>  		WARN_ON_ONCE(!(regs->msr & MSR_EE));
>  again:
> -		if (IS_ENABLED(CONFIG_PREEMPT)) {
> +		if (is_preempt_full()) {
>  			/* Return to preemptible kernel context */
>  			if (unlikely(current_thread_info()->flags & _TIF_NEED_RESCHED)) {
>  				if (preempt_count() == 0)
> diff --git a/arch/powerpc/kernel/traps.c b/arch/powerpc/kernel/traps.c
> index aac8c0412ff9..1cb31bbdc925 100644
> --- a/arch/powerpc/kernel/traps.c
> +++ b/arch/powerpc/kernel/traps.c
> @@ -265,7 +265,7 @@ static int __die(const char *str, struct pt_regs *regs, long err)
>  	printk("%s PAGE_SIZE=%luK%s%s%s%s%s%s %s\n",
>  	       IS_ENABLED(CONFIG_CPU_LITTLE_ENDIAN) ? "LE" : "BE",
>  	       PAGE_SIZE / 1024, get_mmu_str(),
> -	       IS_ENABLED(CONFIG_PREEMPT) ? " PREEMPT" : "",
> +	       is_preempt_full() ? " PREEMPT" : "",
>  	       IS_ENABLED(CONFIG_SMP) ? " SMP" : "",
>  	       IS_ENABLED(CONFIG_SMP) ? (" NR_CPUS=" __stringify(NR_CPUS)) : "",
>  	       debug_pagealloc_enabled() ? " DEBUG_PAGEALLOC" : "",
> -- 
> 2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/87o86rmgu8.fsf%40mpe.ellerman.id.au.
