Return-Path: <kasan-dev+bncBDDL3KWR4EBRB4PATOAAMGQEJ4VMLMI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43b.google.com (mail-pf1-x43b.google.com [IPv6:2607:f8b0:4864:20::43b])
	by mail.lfdr.de (Postfix) with ESMTPS id 1451A2FB9B9
	for <lists+kasan-dev@lfdr.de>; Tue, 19 Jan 2021 15:45:07 +0100 (CET)
Received: by mail-pf1-x43b.google.com with SMTP id e4sf13373930pfc.11
        for <lists+kasan-dev@lfdr.de>; Tue, 19 Jan 2021 06:45:07 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1611067505; cv=pass;
        d=google.com; s=arc-20160816;
        b=zCk5uANHsKS0VhojA1qIoBGsyHqpo8d2S5+FeRXZFYeGuBd8K0uML5s5mIKNSRFYjt
         j/bKtPqiprXMTKkNGa+wOclPNo01YqnEuNYxBB7cs5MSKKHIuu3Co9cqr/LoViOHYK3b
         zclHXPAc8xKjCecrMQi3QB+1MB1IcUwd/GCsLxPoLNRJSgiXEAR0+c5J6oG63VFL//Pl
         MOL7Sd700r/zOvrvptdDVWp4hNJwraGKYGhDx9B9wWauIIlIUGbYnTDA7UWWIWWogb4A
         Gf2qjEby+lkygdnzdhIHOQX6tiBLOmefApzmTIuOYUe1BtbRHBPoNyNZd72caDDiAp9L
         upiQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=7FErh3Psdww6vqTMbsTIUxaCyW7QEiJbsc1sPbUQdjY=;
        b=gsCaOa2xjrU1Xt69mN4/8+GiM/UF8IhtSgRGkq4H6jqNjgaBgLSm/4goaLewFAx8Gl
         vPJA/VFSx8dHyDst1btja4UneZUsieWyOi/SFPC/ALwTcGJxhvYgMGyq4h5XcG5H6vEp
         PFuv5UdipGQ2L9niLPx+7tx7VLztaBMGghgDgaEEz/+pWPQ67DmAQW88jryi+SvnRzDS
         XWcsZFGm+hlzZRpXSm1BF/9IY0TFJeaNtsZDeMBFne9uYqfvnSWKTOys4EZJHoDR6Qtc
         Nd+NS6m7LAlWcLrYXkSx/i92Fnkwx7huwlMbYZLPIwv+o5PKvPy8UfLCZn8BfT4Atb2a
         2R0g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=7FErh3Psdww6vqTMbsTIUxaCyW7QEiJbsc1sPbUQdjY=;
        b=EpP15mg+fgT/Dhl646FuHMAmh0fN1NEEiGz2iV1PIPEoTAIemAjqHrNqSeIDQbM0P5
         9AeHIIgs61PoIubhgqlkfZXqkvDlDZXJ7yZFmDTXZ3Mv1ijSMDAkr02xxIQ9jQ0//Jjk
         uHTSJJf3geG9B+hVU62aTuQBIsmR8afjnZ2/Sb4RtrCfMeoODi0W7rw/wmgDn28bfgIs
         YMhyNO2nidNj4NpJQpmbUr9EKK2JyjA1nmor5iHypE8P1gpP3/JpwPr87UfruFDFT6v1
         J0qqzEWvTsbC9rTg+W8AXfpc+SRussWWbALJY+V3h5rvaNWhV7jpMTph24K/BMHt1oAp
         va6Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=7FErh3Psdww6vqTMbsTIUxaCyW7QEiJbsc1sPbUQdjY=;
        b=a2j//u+dLyGca3S4QcKSygnbzVCp8t7pzSvWTlnNLtaM1MBYqHcgBoWpKaxR9+fncM
         9R6jCnlPr3e1hnlZ5gqSELJlDfKSnGyvSVD7f3GG+bgnFzRbK03rWHlGosJEwtaZjr/B
         RcoY478TkG0SNikjRc733BDP5CRaMUwcmiqtPQIeZb+201LhpkvSm++gdxMEpJa6n1FD
         O3Ql9ZbLj0KrCWC2NydIvAYjfRWnxMNoRIPooBIyNJEcLlrX9Vk8x8GBxRx070oVt6+w
         WIqbE1VZaw0oygmEakXzxTCPpZRR9dzX4dwL/BilcO3LX2/VPXTnG/3BFLJmRMYnb2Om
         Sgxw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530UZV4+WP01wJimtJgVejABI9Q+5yFKH+6rinGpE5Gyo9d5VdMk
	ZS9n7evEhBl1uHDFV8DiwLw=
X-Google-Smtp-Source: ABdhPJyNkElafy71cCeZVntcqAWNT04MiJulfQ0MKX2/K8QFgNPDCUjBu233SsJK2J4zt4nh+Tdq2w==
X-Received: by 2002:a65:624a:: with SMTP id q10mr4727665pgv.194.1611067505834;
        Tue, 19 Jan 2021 06:45:05 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:511:: with SMTP id r17ls4365pjz.1.canary-gmail; Tue,
 19 Jan 2021 06:45:05 -0800 (PST)
X-Received: by 2002:a17:90a:f309:: with SMTP id ca9mr5564515pjb.11.1611067505246;
        Tue, 19 Jan 2021 06:45:05 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1611067505; cv=none;
        d=google.com; s=arc-20160816;
        b=H3gqucVYdVE/vTVC9MfDke9fL+pRf4hklb8Loba1rFsaajgCDLribwmApcRCIF4QOG
         nw5C3XadJL/0pZLK3fyRK8FZaU48TMyGwrRWp1SsBbpwvBFQXbU7Eot2sCwgcKlqKAjN
         14RZJstzEGkzNXEhfhqSaTUS5+T8fAkGsYDcmPlEACvpCR92dz98HR+WJxL8e2t9ElFl
         OhmiG6CNY7JXUTTRoGtBwSvwgeM4Wz8AtUBpNMLSetlwXeTvI8IEplycNYm5iWpUImK8
         Hb3cGc/z1a9S4LGHqbx8DCtFVUANFsMybl41H1CaOPvPTmn1J9u/BiNlikJbAPCtIHZp
         hv3g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=/+Qceo7jeOzL2Hid+7UmrKETlKYLgG8Bd6Dfg2hXqHk=;
        b=Tlb0mkFssTPXqFTqYpBuFZOp+634CfllGfe0uIff3jYSJ+2APmKS3AyGXZp8fcnIHY
         EpvB7HYc6tqWhzDgjpIOz4UukSB60A9JYzYnr2a5JiqgZhIkWWaxdZVofcxlHa8A8hi4
         iCe6dsbwAZqChzd0vprxfUEqtdcMzpFGb9yAomf+a4MA5QN3kCdmy/M2jr1LgCwXQ15W
         Pj9Llf1WcK2lWXP+6OuOCeMua9rC7DzzpHHehXw3AkcpowPiXQQvfC3nL3nkDmx+3JUN
         ceEaT3YI3V6RdA7AKEeZHNbhwkO/hBu0oT0PQPOSKaE7AA35LSPnyjXb8b93ViCNf2q6
         z6+Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id d2si1699026pfr.4.2021.01.19.06.45.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 19 Jan 2021 06:45:05 -0800 (PST)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id 08120207FB;
	Tue, 19 Jan 2021 14:45:02 +0000 (UTC)
Date: Tue, 19 Jan 2021 14:45:00 +0000
From: Catalin Marinas <catalin.marinas@arm.com>
To: Vincenzo Frascino <vincenzo.frascino@arm.com>
Cc: linux-arm-kernel@lists.infradead.org, linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com, Will Deacon <will@kernel.org>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Branislav Rankov <Branislav.Rankov@arm.com>,
	Andrey Konovalov <andreyknvl@google.com>
Subject: Re: [PATCH v4 5/5] arm64: mte: Inline mte_assign_mem_tag_range()
Message-ID: <20210119144459.GE17369@gaia>
References: <20210118183033.41764-1-vincenzo.frascino@arm.com>
 <20210118183033.41764-6-vincenzo.frascino@arm.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20210118183033.41764-6-vincenzo.frascino@arm.com>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: catalin.marinas@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as
 permitted sender) smtp.mailfrom=cmarinas@kernel.org;       dmarc=fail (p=NONE
 sp=NONE dis=NONE) header.from=arm.com
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

On Mon, Jan 18, 2021 at 06:30:33PM +0000, Vincenzo Frascino wrote:
> mte_assign_mem_tag_range() is called on production KASAN HW hot
> paths. It makes sense to inline it in an attempt to reduce the
> overhead.
> 
> Inline mte_assign_mem_tag_range() based on the indications provided at
> [1].
> 
> [1] https://lore.kernel.org/r/CAAeHK+wCO+J7D1_T89DG+jJrPLk3X9RsGFKxJGd0ZcUFjQT-9Q@mail.gmail.com/
> 
> Cc: Catalin Marinas <catalin.marinas@arm.com>
> Cc: Will Deacon <will@kernel.org>
> Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
> ---
>  arch/arm64/include/asm/mte.h | 26 +++++++++++++++++++++++++-
>  arch/arm64/lib/mte.S         | 15 ---------------
>  2 files changed, 25 insertions(+), 16 deletions(-)
> 
> diff --git a/arch/arm64/include/asm/mte.h b/arch/arm64/include/asm/mte.h
> index 237bb2f7309d..1a6fd53f82c3 100644
> --- a/arch/arm64/include/asm/mte.h
> +++ b/arch/arm64/include/asm/mte.h
> @@ -49,7 +49,31 @@ long get_mte_ctrl(struct task_struct *task);
>  int mte_ptrace_copy_tags(struct task_struct *child, long request,
>  			 unsigned long addr, unsigned long data);
>  
> -void mte_assign_mem_tag_range(void *addr, size_t size);
> +static inline void mte_assign_mem_tag_range(void *addr, size_t size)
> +{
> +	u64 _addr = (u64)addr;
> +	u64 _end = _addr + size;
> +
> +	/*
> +	 * This function must be invoked from an MTE enabled context.
> +	 *
> +	 * Note: The address must be non-NULL and MTE_GRANULE_SIZE aligned and
> +	 * size must be non-zero and MTE_GRANULE_SIZE aligned.
> +	 */
> +	do {
> +		/*
> +		 * 'asm volatile' is required to prevent the compiler to move
> +		 * the statement outside of the loop.
> +		 */
> +		asm volatile(__MTE_PREAMBLE "stg %0, [%0]"
> +			     :
> +			     : "r" (_addr)
> +			     : "memory");
> +
> +		_addr += MTE_GRANULE_SIZE;
> +	} while (_addr != _end);
> +}

While I'm ok with moving this function to C, I don't think it solves the
inlining in the kasan code. The only interface we have to kasan is via
mte_{set,get}_mem_tag_range(), so the above function doesn't need to
live in a header.

If you do want inlining all the way to the kasan code, we should
probably move the mte_{set,get}_mem_tag_range() functions to the header
as well (and ideally backed by some numbers to show that it matters).

Moving it to mte.c also gives us more control on how it's called (we
have the WARN_ONs in place in the callers).

-- 
Catalin

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210119144459.GE17369%40gaia.
