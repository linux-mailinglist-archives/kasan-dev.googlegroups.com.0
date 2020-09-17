Return-Path: <kasan-dev+bncBDDL3KWR4EBRBS5IR35QKGQEYHOG3XY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x439.google.com (mail-pf1-x439.google.com [IPv6:2607:f8b0:4864:20::439])
	by mail.lfdr.de (Postfix) with ESMTPS id BF05226E12C
	for <lists+kasan-dev@lfdr.de>; Thu, 17 Sep 2020 18:52:28 +0200 (CEST)
Received: by mail-pf1-x439.google.com with SMTP id 135sf1801141pfu.9
        for <lists+kasan-dev@lfdr.de>; Thu, 17 Sep 2020 09:52:28 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1600361547; cv=pass;
        d=google.com; s=arc-20160816;
        b=yLIxkK7Qq+QbMjvTuE7HyGh5twFvu8V+7Q1aCo5wcKprHhh6OVald3b932pMbfSlU2
         aSX4Jw5yN1VqtBPsQFt8ZyHVZUoPo+6NVdZsvsSAus6j/HrAVEc6HqUzdQo9NTXDAjlu
         gHWsG8m8WqBlQQMbMNYQkUg0QlyQbHiB+3EM3LH77k6FU7c2mnSKoI8M6OlAEcz2/Brc
         ql7IjXOyN88Y/6WQiWDCBGHo0VGP3OWV+EVXxzbYDC8fkzzUdFEri3v9M1PbGDIDGV8n
         +MCAVS+uSZKD4BYh4U+1s0rXpHpVB4m3r1kPOhWgEUtR/UlsUG93Qk04kQzsJv1L1AF7
         AuIg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=X6mBnfgXkKI8tDeybN4Sq14qEg+F129WTH4mv1BnkU8=;
        b=lJXBY252vVJtiu4vXbpaHyKUCJnr24feMre1H4gPEQmEUow2Y0Y9Cl8BA1CM5btUF3
         f0OUz30k+5bDcbYHULyVqAah69YB2/dphSab0YPalDh1jIhryNwTVvdaBHdP0pSphxVI
         WBOxI+eg6KKmXGv3k+DP32ELNVoAO2Nu4sWlKMr9PNpIKIAh9Mg3qXouGLm0maDr+IYZ
         m6XF2Onxydvn1tMjzuH2FXMF/8BjmZe+cefwgWSNE3/XTyS0aDqHboucg4AtNv59cioT
         TarZtDZfW8NBdFHKlHQ9Sp/IheFARlwH2ZKrRp80lgfeldaZ1ToBQaava/MlRj/5NprQ
         vHYQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=X6mBnfgXkKI8tDeybN4Sq14qEg+F129WTH4mv1BnkU8=;
        b=fTMrF0OsqfvOEj2xvD7RfGAxoEIR0KOg9O5Bq74IgqCPp+4jISS26OEk/5YfeuyN0j
         T9yyqSAd+ysxYb1OJu/fkcdZ6+J+Dmpa9OCi4yiUe+nZ5RLVlIEtob8tTL9yUXGAajGt
         tUL5DK/YMKwRwcQqMuVGLHlz765VEIRaIoF2aSryfagoH7DUEILTu197XQ7UXnzGPOF2
         nC7nvRnVjwODWFZ+aaapKxNaazYuQmVpnrzJEPkK8u3pn3FxolW02FL48K7MmN46BfPr
         zylwoTjrcD0IKb/bD2xqKAGCMv0o+h3jri1sEuyttjsNG9whYs8OnmcgK8JgLSOi3DQq
         iRwg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=X6mBnfgXkKI8tDeybN4Sq14qEg+F129WTH4mv1BnkU8=;
        b=qx1oXu9WwqBD9r1qHuag2ShdlpNGiP/cXvxLh9PdPFm6PwiAfdHUESyio5OCufUlhk
         M0Nh5RsWD7rNN7FfMx56x/Dp8kE+dKOuNzmbHcYsquTJm+wYxJDTgwy15H+pqfdsQ8MU
         ZnjcNKJ5tEbhXBizjVWM75ub+SpuX6f1IUR7Wz5VNOKPp3OsCxjJ4zxR7U75LkMUOx3A
         RlDK/+cqWYPnX4cvsIlpogDgmubvYPdH33AOAEmguu9ahVYcnBQVEZkscYljktk3s/4S
         lsAkwltHiBYc6MUCOPrLXuGmRQjbrGjkHVbkFtq5pJTosUOrqyBdvufeOR3wsTonP5pi
         p0qg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530LbOyfLQZcn3xiHail4W+crJa9Yl7+FwAjv8lxsAIr4S8PIJt8
	FSKQ2I7AAnSEXLiPe5XvdM0=
X-Google-Smtp-Source: ABdhPJwphHnf5z/Wt/AnGj7fQxVartB5eYAlHY8Zmt4x/DJaMLR3Vxu0gVMnsAIU6901eVLyKXOtUw==
X-Received: by 2002:a17:90a:72c7:: with SMTP id l7mr9624932pjk.19.1600361547435;
        Thu, 17 Sep 2020 09:52:27 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:c7d3:: with SMTP id gf19ls1252975pjb.0.canary-gmail;
 Thu, 17 Sep 2020 09:52:26 -0700 (PDT)
X-Received: by 2002:a17:902:309:b029:d1:e5e7:ca3f with SMTP id 9-20020a1709020309b02900d1e5e7ca3fmr12212420pld.43.1600361546762;
        Thu, 17 Sep 2020 09:52:26 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1600361546; cv=none;
        d=google.com; s=arc-20160816;
        b=tqAlR9G2BDg6pKs57cTCM2NlH2Z8igOZM242/jjipChC04WVBwNyWX6ecFLSqe4TBf
         Zq3iWcDPwEzLjIaKwCRywXqPyUQ3d7AGoXzoF5zd9nbs5M/yX0U4rckKzHtuTCm8fXaM
         Fi8VG+pr2Syu6uMmnAdLP9R57B9Rg1PSQu4Y8lgNfzTZquqrbRjq+lpwTkejwcxd7twU
         uog2dS/Q6PluC/Se2FLgaCjjaI41DmheDwSGOpDh3EPfx4XNv5tBJSDxamMZfZtvmqlr
         N8tHhvcceuWrwhvMUGuIDFuoHZUXAHqlgbs922lc19vUiLn/Wgq69WnQN1HgzqbhN1Bv
         L0eQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=yCxfBr/UERnedxmUpbcLop45vyxzMKQtWWF/bAPvn1M=;
        b=S4xNRn9jHXqRcO7QMM11mBu88kysqlccJXOrOZJqD8MXn6zdoQNHdXQvcQ2Vqbp+JR
         CLHnwZhvjgAAnZwQRcgChhLD7DuZineqAt8i6r0V9y86kmfWofECvdvsZ/ceZV+3HFfB
         EKgOLOrp/OnsAKWcbZQrxzZWEOk/qzhNYT/sKACeRApiEmPiw1gK1p792+6wE1Vzgqyr
         mwBft8WKXaT5FtYxI04d4cWK1Lq25A5aHoW+6UYc38+8IleUDiaZBOC1PaF6w9QPPWr1
         TMwK26Ncjg8/aarzY4ofY4nBs4R3/TZPAGCT6f867br6pdMhDQ1YEfCvnl7BCl3nX5Mb
         RjaA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id h5si42658pfc.0.2020.09.17.09.52.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 17 Sep 2020 09:52:26 -0700 (PDT)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from gaia (unknown [31.124.44.166])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id E9B5A2078D;
	Thu, 17 Sep 2020 16:52:23 +0000 (UTC)
Date: Thu, 17 Sep 2020 17:52:21 +0100
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
Subject: Re: [PATCH v2 27/37] arm64: mte: Switch GCR_EL1 in kernel entry and
 exit
Message-ID: <20200917165221.GF10662@gaia>
References: <cover.1600204505.git.andreyknvl@google.com>
 <c801517c8c6c0b14ac2f5d9e189ff86fdbf1d495.1600204505.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <c801517c8c6c0b14ac2f5d9e189ff86fdbf1d495.1600204505.git.andreyknvl@google.com>
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

On Tue, Sep 15, 2020 at 11:16:09PM +0200, Andrey Konovalov wrote:
> diff --git a/arch/arm64/kernel/cpufeature.c b/arch/arm64/kernel/cpufeature.c
> index eca06b8c74db..3602ac45d093 100644
> --- a/arch/arm64/kernel/cpufeature.c
> +++ b/arch/arm64/kernel/cpufeature.c
> @@ -1721,6 +1721,9 @@ static void cpu_enable_mte(struct arm64_cpu_capabilities const *cap)
>  
>  	/* Enable in-kernel MTE only if KASAN_HW_TAGS is enabled */
>  	if (IS_ENABLED(CONFIG_KASAN_HW_TAGS)) {
> +		/* Enable the kernel exclude mask for random tags generation */
> +		write_sysreg_s((SYS_GCR_EL1_RRND | gcr_kernel_excl), SYS_GCR_EL1);

Nitpick: no need for extra braces, the comma has lower precedence.

> +
>  		/* Enable MTE Sync Mode for EL1 */
>  		sysreg_clear_set(sctlr_el1, SCTLR_ELx_TCF_MASK, SCTLR_ELx_TCF_SYNC);
>  		isb();
> diff --git a/arch/arm64/kernel/entry.S b/arch/arm64/kernel/entry.S
> index ff34461524d4..79a6848840bd 100644
> --- a/arch/arm64/kernel/entry.S
> +++ b/arch/arm64/kernel/entry.S
> @@ -175,6 +175,28 @@ alternative_else_nop_endif
>  #endif
>  	.endm
>  
> +	.macro mte_restore_gcr, el, tsk, tmp, tmp2
> +#ifdef CONFIG_ARM64_MTE
> +alternative_if_not ARM64_MTE
> +	b	1f
> +alternative_else_nop_endif
> +	.if	\el == 0
> +	ldr	\tmp, [\tsk, #THREAD_GCR_EL1_USER]
> +	.else
> +	ldr_l	\tmp, gcr_kernel_excl
> +	.endif
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
>  	.macro	kernel_entry, el, regsize = 64
>  	.if	\regsize == 32
>  	mov	w0, w0				// zero upper 32 bits of x0
> @@ -214,6 +236,8 @@ alternative_else_nop_endif
>  
>  	ptrauth_keys_install_kernel tsk, x20, x22, x23
>  
> +	mte_restore_gcr 1, tsk, x22, x23
> +
>  	scs_load tsk, x20
>  	.else
>  	add	x21, sp, #S_FRAME_SIZE
> @@ -332,6 +356,8 @@ alternative_else_nop_endif
>  	/* No kernel C function calls after this as user keys are set. */
>  	ptrauth_keys_install_user tsk, x0, x1, x2
>  
> +	mte_restore_gcr 0, tsk, x0, x1

Some nitpicks on these macros to match the ptrauth_keys_* above. Define
separate mte_set_{user,kernel}_gcr macros with a common mte_set_gcr that
is used by both.

> +
>  	apply_ssbd 0, x0, x1
>  	.endif
>  
> diff --git a/arch/arm64/kernel/mte.c b/arch/arm64/kernel/mte.c
> index 858e75cfcaa0..1c7d963b5038 100644
> --- a/arch/arm64/kernel/mte.c
> +++ b/arch/arm64/kernel/mte.c
> @@ -18,10 +18,13 @@
>  
>  #include <asm/barrier.h>
>  #include <asm/cpufeature.h>
> +#include <asm/kprobes.h>

What's this apparently random kprobes.h include?

>  #include <asm/mte.h>
>  #include <asm/ptrace.h>
>  #include <asm/sysreg.h>
>  
> +u64 gcr_kernel_excl __ro_after_init;
> +
>  static void mte_sync_page_tags(struct page *page, pte_t *ptep, bool check_swap)
>  {
>  	pte_t old_pte = READ_ONCE(*ptep);
> @@ -120,6 +123,13 @@ void *mte_set_mem_tag_range(void *addr, size_t size, u8 tag)
>  	return ptr;
>  }
>  
> +void mte_init_tags(u64 max_tag)
> +{
> +	u64 incl = GENMASK(max_tag & MTE_TAG_MAX, 0);
> +
> +	gcr_kernel_excl = ~incl & SYS_GCR_EL1_EXCL_MASK;
> +}

Do we need to set the actual GCR_EL1 register here? We may not get an
exception by the time KASAN starts using it.

-- 
Catalin

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200917165221.GF10662%40gaia.
