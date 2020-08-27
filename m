Return-Path: <kasan-dev+bncBDDL3KWR4EBRBIM2T35AKGQEIPKPZSI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3b.google.com (mail-oo1-xc3b.google.com [IPv6:2607:f8b0:4864:20::c3b])
	by mail.lfdr.de (Postfix) with ESMTPS id A039E2543DE
	for <lists+kasan-dev@lfdr.de>; Thu, 27 Aug 2020 12:38:26 +0200 (CEST)
Received: by mail-oo1-xc3b.google.com with SMTP id h21sf2718431oov.16
        for <lists+kasan-dev@lfdr.de>; Thu, 27 Aug 2020 03:38:26 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1598524705; cv=pass;
        d=google.com; s=arc-20160816;
        b=JkkzEcgrtsBUFHAx8SW8UUTf9CX86XipoE0wsg5EHqE43b4IsOTynhWZRe903HWoLp
         zxMKz/ehXz4ghbcQzU6BZurfcNn1Z6pa0fn19GHOc0nPWzvGfoXohuUqS41xX4cyQ3pY
         mVXDUgWWfh+RJTGrAvO/N19WhDhRvElwtRMfuXiIoP9ydEt83ys0AtvnmMSAmUUy3bMc
         48N7fJtEh6ouPSZEnY6XIfozaVCfqAJj6NzwmHUmlW8inclDaj+NwjzfcL1ZnMHRnrjy
         xWOTt0foDwj+pjZJj2Rc8YsO/gKAlZ3w+z6DxgVhtI+WzXwK62Z1achVVo7/2CeapP8B
         Q5zg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=3uWkqVXThgnOKLWBNnl94iIyUnUoTAj+7G2IlvKTh0I=;
        b=06Akf4EmN5uKfsJFsrvUGvlZgqVTLlBtZv53sNZNA+gSBVAK6ijE9m0u1rCPRG+P6O
         ecMf0GE62mr2Len98QSVcDCGRaBcVSLfYEksHl5v4CFcQOB8n/it8GEZmtbSlx9Kd9AF
         WF9EY1Q62Nk/hYdl6h9nqwepqUm7o+TeA5yp3n29PpTS6osUPNvntd5RA5SDxWJqh9IB
         5EZRtWEowVi5hH8YRA3H4lz4QzUJmP1JLOche0+rhNO1rTf9xnKWGNABKlHcGjsjHL25
         FOkwgEog6ndarvCoBDZaEQBsRGwD2iRCiFgKLT7jyuD5QJbaqYlsIqXfSJ3y4x/S2NJb
         /3Cg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=3uWkqVXThgnOKLWBNnl94iIyUnUoTAj+7G2IlvKTh0I=;
        b=Zl05nRVCcUE9GSqYUBxn2iArz2TE2WEQJMpTLtXMv5SHsrhHi8UB7JSw+K8CoQRwvT
         UMPsf8bSRFfD7tHSOlsi0CNa8dUFy0MwBdbvfhdhEJ5E5R9IRuxx2kb9Zy9Ynjr2/FTT
         AeGzfWxE5QmAlN58wtvThYFn+u8V798RZp9agMHIdWHjDRUYaWnlW4jjjgQBqzF5AxO8
         s5kfHLI4HLq3r3mMg9Bk+xGvykydMOVY83fFbycQGI6HNcmaLThLlxmkukb4iKAXfloG
         WRoKuQacOXOy51YLbKbB/kC5QlngHSrRcjQRvN57/N5UFMrTjTNw9BZmdiIKyVHlIYZn
         Jfbg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=3uWkqVXThgnOKLWBNnl94iIyUnUoTAj+7G2IlvKTh0I=;
        b=YWOXQtoNYLzeUOBn8cZcDa3r3SVXTC4YYN9FPSZjzciDDoRhr0atZkrdKa9FhTd5uZ
         4TqWh9mYGUAstjMvMtqxToMYEUwLBH/FraYOWEforlqn4klFu84/oWkXrFy94qXfNJhq
         WVhyoR5DTW0YaATKdfiH8/PWoZgX58rHJrAlXHM96MNjNUsRBg7zvVf+kNdmL0btN8R+
         gb6u+n9sAeEXy6ozV/EbZ59EVeBcd+WjFRrwKbgv5oXcaqHpAX03VOKwiTlyUSlpiiIb
         dHhtuLd6Kd0GmHoTar+8MHDOjgD0+YQRn+euPisD7PACfFaz+3W/pkHADgbbAigksETY
         CbJA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530rJ9NcaCAdoiiW55QAaVYR9JouqCXaMhqOhDfVHQNgjtleUpxS
	N4m98NQXPurn45XHhOXxqOU=
X-Google-Smtp-Source: ABdhPJw6wHzKBFpDoG8XwSV2Jgo5XXWBrTI3MCxXoFT6NeIOaXp7RutX9F3w9L3RDRkQUSRhyGL9QA==
X-Received: by 2002:aca:130e:: with SMTP id e14mr6614157oii.21.1598524705632;
        Thu, 27 Aug 2020 03:38:25 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:6f14:: with SMTP id n20ls505746otq.3.gmail; Thu, 27 Aug
 2020 03:38:25 -0700 (PDT)
X-Received: by 2002:a9d:6e19:: with SMTP id e25mr13514302otr.198.1598524705275;
        Thu, 27 Aug 2020 03:38:25 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1598524705; cv=none;
        d=google.com; s=arc-20160816;
        b=R9snzHvJNbMkKn7WFkRHkaMdSBzSZ0uDDaq5NYTgCZ7evbq0bpw+U+GaA05h7p0yUu
         0a7X12T1pOxKOMp+G6GIcWIly2+LG7g0Q7q+oa+/M1/SGVrMk6PtH6AuRwRlVSnu2aK7
         SYfMyZKxi3Ip/u+ks0XuuNmJCG+POWi+J5LPcuZIB741IFwdUVbSSaVKlB3ZkfJcmisN
         5Wx4eQVMC6hPLTPpAmiRudJk46eXO8kJ2j3MAhx0z31XFBS7j+aKGogXchxyJC4YaNl6
         m89Ck6jvaOf0PIZK5fGcicPvZljrxsRgt+vCagO+X0wEU0EvLMlVTmJ3H1fteQIM7Dnw
         hfFA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=kLKV3z1Pox1GbQ0wFhMdSGZpPCmAOSh4fnlFLF70yGw=;
        b=pqupVwSgshzMcQXx12gWjCdVidJP4FFUwKxyMdnI81jdegE98zyW3JOIzWva8Tl9VL
         KdbB9I1c89qU2EbQEn75F7OMSG0bnLtv9BU6YLbah8hXnnxKdi0ngozQCid5Ch4fow2x
         JHXIG+2yNCL/oryWWyefJZyQz7ZaCrDAF15SPUtIfARViP3G6BFy2kDv3/Xj4rhztXZh
         3Iem3xQN4LnuKeOwH1NZGLK4GI9Twjt4Qhq6Gs5B8QGz2H0lK7X+FLCa+IBqoCGUEx3a
         aU4bGN823YwKUcP42PDUDwszdONNl4l9Qr6lePFLjArxwlz5yQaXLhEaRRdTwMIQh+if
         Tzxw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id d1si17492oom.0.2020.08.27.03.38.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 27 Aug 2020 03:38:25 -0700 (PDT)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from gaia (unknown [46.69.195.127])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 01EF022B40;
	Thu, 27 Aug 2020 10:38:21 +0000 (UTC)
Date: Thu, 27 Aug 2020 11:38:19 +0100
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
Subject: Re: [PATCH 24/35] arm64: mte: Switch GCR_EL1 in kernel entry and exit
Message-ID: <20200827103819.GE29264@gaia>
References: <cover.1597425745.git.andreyknvl@google.com>
 <ec314a9589ef8db18494d533b6eaf1fd678dc010.1597425745.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <ec314a9589ef8db18494d533b6eaf1fd678dc010.1597425745.git.andreyknvl@google.com>
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

On Fri, Aug 14, 2020 at 07:27:06PM +0200, Andrey Konovalov wrote:
> diff --git a/arch/arm64/kernel/entry.S b/arch/arm64/kernel/entry.S
> index cde127508e38..a17fefb0571b 100644
> --- a/arch/arm64/kernel/entry.S
> +++ b/arch/arm64/kernel/entry.S
> @@ -172,6 +172,29 @@ alternative_else_nop_endif
>  #endif
>  	.endm
>  
> +	/* Note: tmp should always be a callee-saved register */

Why callee-saved? Do you preserve it anywhere here?

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
> @@ -209,6 +232,8 @@ alternative_else_nop_endif
>  
>  	ptrauth_keys_install_kernel tsk, x20, x22, x23
>  
> +	mte_restore_gcr 1, tsk, x22, x23
> +
>  	scs_load tsk, x20
>  	.else
>  	add	x21, sp, #S_FRAME_SIZE
> @@ -386,6 +411,8 @@ alternative_else_nop_endif
>  	/* No kernel C function calls after this as user keys are set. */
>  	ptrauth_keys_install_user tsk, x0, x1, x2
>  
> +	mte_restore_gcr 0, tsk, x0, x1
> +
>  	apply_ssbd 0, x0, x1
>  	.endif
>  
> @@ -957,6 +984,7 @@ SYM_FUNC_START(cpu_switch_to)
>  	mov	sp, x9
>  	msr	sp_el0, x1
>  	ptrauth_keys_install_kernel x1, x8, x9, x10
> +	mte_restore_gcr 1, x1, x8, x9
>  	scs_save x0, x8
>  	scs_load x1, x8
>  	ret

Since we set GCR_EL1 on exception entry and return, why is this needed?
We don't have a per-kernel thread GCR_EL1, it's global to all threads,
so I think cpu_switch_to() should not be touched.

> diff --git a/arch/arm64/kernel/mte.c b/arch/arm64/kernel/mte.c
> index 7717ea9bc2a7..cfac7d02f032 100644
> --- a/arch/arm64/kernel/mte.c
> +++ b/arch/arm64/kernel/mte.c
> @@ -18,10 +18,14 @@
>  
>  #include <asm/barrier.h>
>  #include <asm/cpufeature.h>
> +#include <asm/kasan.h>
> +#include <asm/kprobes.h>
>  #include <asm/mte.h>
>  #include <asm/ptrace.h>
>  #include <asm/sysreg.h>
>  
> +u64 gcr_kernel_excl __read_mostly;

Could we make this __ro_after_init?

> +
>  static void mte_sync_page_tags(struct page *page, pte_t *ptep, bool check_swap)
>  {
>  	pte_t old_pte = READ_ONCE(*ptep);
> @@ -115,6 +119,13 @@ void * __must_check mte_set_mem_tag_range(void *addr, size_t size, u8 tag)
>  	return ptr;
>  }
>  
> +void mte_init_tags(u64 max_tag)
> +{
> +	u64 incl = ((1ULL << ((max_tag & MTE_TAG_MAX) + 1)) - 1);

I'd rather use GENMASK here, it is more readable.

-- 
Catalin

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200827103819.GE29264%40gaia.
