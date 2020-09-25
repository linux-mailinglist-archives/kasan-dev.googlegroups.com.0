Return-Path: <kasan-dev+bncBDDL3KWR4EBRBUFLW75QKGQE3AEY5FA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83b.google.com (mail-qt1-x83b.google.com [IPv6:2607:f8b0:4864:20::83b])
	by mail.lfdr.de (Postfix) with ESMTPS id 66C712785F6
	for <lists+kasan-dev@lfdr.de>; Fri, 25 Sep 2020 13:34:41 +0200 (CEST)
Received: by mail-qt1-x83b.google.com with SMTP id w3sf1082739qtn.16
        for <lists+kasan-dev@lfdr.de>; Fri, 25 Sep 2020 04:34:41 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1601033680; cv=pass;
        d=google.com; s=arc-20160816;
        b=ssw8g7Y/e6+dIMwNzYxOvEdz49qmLUrHfF+h07P9qPG24kKHPR3T2ZpmRlbg7rsZ0H
         n/VzGivsGsd3D/oPB3WtmTBljw1FitDnAmJqoTg/qRSEQC6HmyPGjKFRZqhP1HzQb6VI
         ronVgMyXAnylanacripUMIO8Soy1rAif9HiP4FwhSbSUchW1GuLBNqc53DPyff8lDDH8
         2vJMFPGbroQ7UNXY/n6jFmUODloDgRIre3+eFpu7B/q83/bTr16F6e6p9EsfSyYAdWpI
         dmo8XL4p3+v369ZeslmigGpkxUyqoS5sei06OPUqms9XHUyOfabYIUYJCBwFQeyeNX76
         EJ1A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=R28Atx534btWUlMjY6UpqYJxtoaVyX7oos+SIO4HJPQ=;
        b=l7otA2slwA1qpxhH5Svopgty4y6dJC7BqgW7s8hW/AmXev32iS22mYVI1hb8KBUiXs
         orz9QtTav6QndMsr+aNL2EcFeY8jhMM0XUwE7vXUklHzI9W8k5vLyMyp0NA1WRG/rKg2
         vF1KL1Dor8tQe0YY5c21JP6I/FbAuhmlZuo8+79NR4PKMuQvJBw33A3V6KLY+l40HaoU
         xPlvH0EbKARN0d4RsYk5wCQU8zVq38RZ7GTGNzkzU5IfzEctdrxM1d/nxEDtIh1TMzOL
         i61qN/mkR0K5WjfbiPKiEG0uKKqSbYrqHJFaTF59QBaS1fFniAcW1fx6cPStdMdof3Dz
         t0gg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=R28Atx534btWUlMjY6UpqYJxtoaVyX7oos+SIO4HJPQ=;
        b=UPt3EL+4n4TBQL0DPq/pDoZ8cF9Pk/iExPJ8EoN80gxd+Hcb7vsmh8rEaY0dMu5F7S
         Rle4pYvEijj+hxCNvylvVAwfyRKQzpOhZ92qyBlM76pje4+sqc4tG73rpKWxB++DlDzK
         Ir1m+xxpY+4FERZ+1TTh9Z/RAFpROkwU4257BSjnW/InLQzQqY6c628HZrLeTMZudgvw
         irTe/KM4kyX5NasyyZlmNuIULbwkKzzLegJeN7K7n2ViaiY+abxrm86UVUTBFx/mY01w
         dw5E8TZg1yzQOdSzDjXnF9kHynj28ViWNAILbAZ4hGQQQ8BPETL5gcJOd9rJnvDehKI0
         CtKQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=R28Atx534btWUlMjY6UpqYJxtoaVyX7oos+SIO4HJPQ=;
        b=bW4iejf00uzCcPkaeB44txLiOJwdrfPTUvNjID/ugf7ils8Y30UOULTFCcsaa0N5En
         bYokzYxc7/hViqDknwf7Iubb8RRvSNltSuQ9A/iL8DcOU56D6nxebHPHqG4e//nP2XCF
         0ICEpdDDaV+gwy4pzb0BBYpAZkRuIIfwN4WUrWn2xMEtHNxJF5/zkCZDXww6/E7RjNtl
         mrcuk+RbPtPjssTvllDes2fDzhXgL1Nkfbkb5z2jaKKg+rhLBA/WT2RANPXWA/zT59qR
         KPbJyXMqQnUSWJrPVCp8oKo+zT8fozjsw68sfkONMBlBu5pcyLAPD9J8gN+ufoQgfJqG
         dJXA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532eOS42QM3QMd564/QbNVEPxr3GKVoOwP6CxtewmuOaiJV389+R
	+CVW7O2JvPSyfU/m3FUF9dk=
X-Google-Smtp-Source: ABdhPJyRpHpilC/N3fNRPTPqb6e8WDTjm7EYEc7kY47I5pM/wNq8483zrFonaakM4XTYEvLv3Vr9uA==
X-Received: by 2002:aed:2794:: with SMTP id a20mr3758759qtd.387.1601033680349;
        Fri, 25 Sep 2020 04:34:40 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:620a:1112:: with SMTP id o18ls1105015qkk.2.gmail; Fri,
 25 Sep 2020 04:34:39 -0700 (PDT)
X-Received: by 2002:a37:4e45:: with SMTP id c66mr3649717qkb.36.1601033679688;
        Fri, 25 Sep 2020 04:34:39 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1601033679; cv=none;
        d=google.com; s=arc-20160816;
        b=CnP5tobIQjIRr88gikDJeEHTaQ+5T1iZEvU3aqBgUXbkDJ4DV5K88evN+ZmtPkPHX1
         yO+eXavU7riZ34XBszUP0eVLN8fqhKFHtszjawAj5b/Q9GJi4tqT0E/XJowK4u30sEfk
         WfcTzYr/n8F2qVYLmvpm+31ZtmCXOS4QvRyqMJvAZOqjHEi+kYbFd0p6rCfIytMDw14P
         TeR4aUwBSVPj/SXevT2COie57PYRUMLFsANY5CZlNyYpmqmrnSl+eyXgeSxQLQ7h/7eC
         2zqI+h9oqLgzCA1JlfxPa39ugVntw8xmInaLJnqk9lWfdx6iW8Dlp/ZZwf+Zr9/2XY9t
         /sHg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=ueXHMeQ/RMtEtjZh4q3SmnKsrYqYhwEBEXAhovG/G58=;
        b=hut/Clnd5Hzbpn7jd3Y/nnG/KaNZTEixj8BsaymRFPRZ81ErLP22GuGVV4A8gts4lT
         v6SzjXBMQK1nl6xLglsOtQObgAAzG+hVE9P3fOli7bqxDiaPqMCGBaUlBNZxnu0/EpBz
         K639MrJkS+3AljvS0fBc2viwGPKBffQ8+0mImTFD64Sy42uCa7Ol2r3qtV1minVBdFRw
         0LzHPet8Of3DQ33ncyNzup7RuKlecUd1zx+2ow9VQTuxKvPm6ns5YoyGjTFB32FVyeq/
         ryOLZCwpfdIX4M+lT16hv/QLqfxHDdffuypIkdrXQVQYElluFjQEa6P003OdQXIE7EZC
         64CA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id a27si137878qtw.4.2020.09.25.04.34.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 25 Sep 2020 04:34:39 -0700 (PDT)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from gaia (unknown [31.124.44.166])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 358C421741;
	Fri, 25 Sep 2020 11:34:36 +0000 (UTC)
Date: Fri, 25 Sep 2020 12:34:33 +0100
From: Catalin Marinas <catalin.marinas@arm.com>
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	kasan-dev@googlegroups.com,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Elena Petrova <lenaptr@google.com>,
	Branislav Rankov <Branislav.Rankov@arm.com>,
	Kevin Brodsky <kevin.brodsky@arm.com>,
	Will Deacon <will.deacon@arm.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org
Subject: Re: [PATCH v3 29/39] arm64: mte: Switch GCR_EL1 in kernel entry and
 exit
Message-ID: <20200925113433.GF4846@gaia>
References: <cover.1600987622.git.andreyknvl@google.com>
 <4e503a54297cf46ea1261f43aa325c598d9bd73e.1600987622.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <4e503a54297cf46ea1261f43aa325c598d9bd73e.1600987622.git.andreyknvl@google.com>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: catalin.marinas@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as
 permitted sender) smtp.mailfrom=cmarinas@kernel.org
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

On Fri, Sep 25, 2020 at 12:50:36AM +0200, Andrey Konovalov wrote:
> diff --git a/arch/arm64/kernel/entry.S b/arch/arm64/kernel/entry.S
> index ff34461524d4..c7cc1fdfbd1a 100644
> --- a/arch/arm64/kernel/entry.S
> +++ b/arch/arm64/kernel/entry.S
> @@ -175,6 +175,49 @@ alternative_else_nop_endif
>  #endif
>  	.endm
>  
> +	.macro mte_set_gcr, tmp, tmp2
> +#ifdef CONFIG_ARM64_MTE
> +alternative_if_not ARM64_MTE
> +	b	1f
> +alternative_else_nop_endif

You don't need the alternative here. The macro is only invoked in an
alternative path already (I'd be surprised if it even works, we don't
handle nested alternatives well).

> +	/*
> +	 * Calculate and set the exclude mask preserving
> +	 * the RRND (bit[16]) setting.
> +	 */
> +	mrs_s	\tmp2, SYS_GCR_EL1
> +	bfi	\tmp2, \tmp, #0, #16
> +	msr_s	SYS_GCR_EL1, \tmp2
> +	isb
> +1:
> +#endif
> +	.endm
> +
> +	.macro mte_set_kernel_gcr, tsk, tmp, tmp2

What's the point of a 'tsk' argument here?

> +#ifdef CONFIG_KASAN_HW_TAGS
> +#ifdef CONFIG_ARM64_MTE

Does KASAN_HW_TAGS depend on ARM64_MTE already? Just to avoid too may
ifdefs. Otherwise, you can always write it as:

#if defined(CONFIG_KASAN_HW_TAGS) && defined(CONFIG_ARM64_MTE)

to save two lines (and its easier to read).

> +alternative_if_not ARM64_MTE
> +	b	1f
> +alternative_else_nop_endif
> +	ldr_l	\tmp, gcr_kernel_excl
> +
> +	mte_set_gcr \tmp, \tmp2
> +1:
> +#endif
> +#endif
> +	.endm
> +
> +	.macro mte_set_user_gcr, tsk, tmp, tmp2
> +#ifdef CONFIG_ARM64_MTE
> +alternative_if_not ARM64_MTE
> +	b	1f
> +alternative_else_nop_endif
> +	ldr	\tmp, [\tsk, #THREAD_GCR_EL1_USER]
> +
> +	mte_set_gcr \tmp, \tmp2
> +1:
> +#endif
> +	.endm
> +
>  	.macro	kernel_entry, el, regsize = 64
>  	.if	\regsize == 32
>  	mov	w0, w0				// zero upper 32 bits of x0
> @@ -214,6 +257,8 @@ alternative_else_nop_endif
>  
>  	ptrauth_keys_install_kernel tsk, x20, x22, x23
>  
> +	mte_set_kernel_gcr tsk, x22, x23
> +
>  	scs_load tsk, x20
>  	.else
>  	add	x21, sp, #S_FRAME_SIZE
> @@ -332,6 +377,8 @@ alternative_else_nop_endif
>  	/* No kernel C function calls after this as user keys are set. */
>  	ptrauth_keys_install_user tsk, x0, x1, x2
>  
> +	mte_set_user_gcr tsk, x0, x1
> +
>  	apply_ssbd 0, x0, x1
>  	.endif
>  
> diff --git a/arch/arm64/kernel/mte.c b/arch/arm64/kernel/mte.c
> index 393d0c794be4..c3b4f056fc54 100644
> --- a/arch/arm64/kernel/mte.c
> +++ b/arch/arm64/kernel/mte.c
> @@ -22,6 +22,8 @@
>  #include <asm/ptrace.h>
>  #include <asm/sysreg.h>
>  
> +u64 gcr_kernel_excl __ro_after_init;
> +
>  static void mte_sync_page_tags(struct page *page, pte_t *ptep, bool check_swap)
>  {
>  	pte_t old_pte = READ_ONCE(*ptep);
> @@ -116,6 +118,13 @@ void *mte_set_mem_tag_range(void *addr, size_t size, u8 tag)
>  	return ptr;
>  }
>  
> +void mte_init_tags(u64 max_tag)
> +{
> +	u64 incl = GENMASK(max_tag & MTE_TAG_MAX, 0);
> +
> +	gcr_kernel_excl = ~incl & SYS_GCR_EL1_EXCL_MASK;
> +}
> +
>  static void update_sctlr_el1_tcf0(u64 tcf0)
>  {
>  	/* ISB required for the kernel uaccess routines */
> @@ -151,7 +160,11 @@ static void update_gcr_el1_excl(u64 excl)
>  static void set_gcr_el1_excl(u64 excl)
>  {
>  	current->thread.gcr_user_excl = excl;
> -	update_gcr_el1_excl(excl);
> +
> +	/*
> +	 * SYS_GCR_EL1 will be set to current->thread.gcr_user_incl value
                                                      ^^^^^^^^^^^^^
That's gcr_user_excl now.

> +	 * by mte_restore_gcr() in kernel_exit,

I don't think mte_restore_gcr is still around in this patch.

-- 
Catalin

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200925113433.GF4846%40gaia.
