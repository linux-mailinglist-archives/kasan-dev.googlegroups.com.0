Return-Path: <kasan-dev+bncBD4NDKWHQYDRBAV2UWYQMGQECFX7NQI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x538.google.com (mail-pg1-x538.google.com [IPv6:2607:f8b0:4864:20::538])
	by mail.lfdr.de (Postfix) with ESMTPS id DFE758B1384
	for <lists+kasan-dev@lfdr.de>; Wed, 24 Apr 2024 21:27:00 +0200 (CEST)
Received: by mail-pg1-x538.google.com with SMTP id 41be03b00d2f7-604dea821d3sf200071a12.1
        for <lists+kasan-dev@lfdr.de>; Wed, 24 Apr 2024 12:27:00 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1713986819; cv=pass;
        d=google.com; s=arc-20160816;
        b=WOKE8PO5Vkhq2mDib5bN3KXWE3nwWXKJIlnxjHjSyBvsvQA+sbz/CtOL3/xWI7R0ey
         qoV7pkx1095aeFn8MH8Sbc3kGTXIais5zaniK++hCKoR5OeYJiSxj3WTTgM+VhP/iTGn
         Q6K8yG4m0hSytx4RoRcP47qZAmwc5IVjtautxlhjh9kCTIGPKfMPmVCrFMgsejBD7EVS
         YKs1a9jE0mR2k94G0KOCyjLsF7r0usduILwaZGEhmLjszw9vTo/XIiTAlrS8xqip9EXk
         NI/EVlouRrZ263vCHqPTPpC81Bp9+BEDDltrKXc/80Dy7f0TZM6Gn0480FsF/IqO+fnc
         uHMA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=On/2wtI/cKiXq2GrfN40heKqq9dBcmxPYuHXv/JmTDM=;
        fh=sk+RAQDcl450RCSun3gMObpmbwoSjLIiHAkbpkzJPEI=;
        b=RL/ixG/S8ReLgiCJA86MUXukfw3FShdGM1N4ODL7Xzw6K11dXIcLzNvXgqeryxLo1Q
         xhEoELQ4ODjLtHCHOct4QDls2sQBl2xXiMmKYgDrbWQrHp7nqMMmtdMNogcfRVU7BCWl
         EO8zD1gIx8XTWvZcJM141DTNhijgCl+xetp1jmRBKdO3SVYF6bHIkJOA67nn0b3AfCgh
         j16zZOjHa5xQq5w9TU1XGaQm5fySkUgw/AN85ZhbdfEtK+Cpo4v9LDfInnXF2P4lapeZ
         iPVRM1mmg2JkuteLVhyDcYPB85bQNf67GEkGRynSgrtV0kp87xDb3l/0MWF0VObOlAP8
         DKjQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="B/TlF1tj";
       spf=pass (google.com: domain of nathan@kernel.org designates 2604:1380:40e1:4800::1 as permitted sender) smtp.mailfrom=nathan@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1713986819; x=1714591619; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=On/2wtI/cKiXq2GrfN40heKqq9dBcmxPYuHXv/JmTDM=;
        b=CX2yZeRp3zqMBrPsoGQw0Bx/cnCq5j3kOolHBzF4m674k456586Yj+YQxgkeB9be4v
         l0zCwLRqBJ7OkINzv696PJoP5H0vK1FVdCHOvDSS9Dt1neUMxFnEqfqhyliTsxyXiU9c
         UykHjFaD2zbWse6iU2Tb05nKTqMv/oUCSPITLQOKOP9+EDNEEl0WyO/oyIny+IaFLBus
         RMSsovyUtP1k4t5TUwAaHCmQuxffx+doc7qgUEs2IA52LB3KhBU/gx62pa1NbkNyGd9l
         2oBAAv52abeVLMhzMKkz644U+BYpJuGOiQ1tpob0Y9ibOrUE3xMGrqfvbQOcnDUPiUge
         8Twg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1713986819; x=1714591619;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=On/2wtI/cKiXq2GrfN40heKqq9dBcmxPYuHXv/JmTDM=;
        b=lej/p8hYXJFXJ8tFpl9Zvv7h0zS/c0lLOKwfNXvf0Ft91gI1n+edWByqzrgBBwXNF/
         2w4HZY7z+3EEF8X9NGWMQPkj2TfcmDt34rLQjPdhPHhdsSIjXfxz4APeeumWigFY9gkq
         wE2O9qDs2iYjB8x/nqnUHgFUK+obP5OYv/b29CnGsSOEcItbnGZMhz66e8cM0fDIu/tp
         9bKh47SxEQx3iBbc1dLCeCCx7JFSZbK2k3jIJ7InMIhyWckEXB7cPB6Y/DcvreliywgG
         lJ64bkAyshFZLpuEicd/w3tNw6tedST/j2F+21WvUjQsF8x5HHHgfdaBAuDkLldUlpCL
         wa1A==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVcvX5tREaTeF1SM5W0gscqgHBYMCXdfwS60CguYbZ3KBAXvbSnU+3CJ4uWr6Q2yjIeycDfCN3sgRT+VWJ+rYzLrJAJVFK3Bw==
X-Gm-Message-State: AOJu0Yx27zeh+glNp7VMBK5p3gLn1JnXRrGaADryek/AEdm24eTvDU85
	wlgygMycDlFqpUKGlmGEPIAr8L3lPTdeKo9PILWoUhABQczOAkLc
X-Google-Smtp-Source: AGHT+IHOruHovz+90QWmFbMqvWcz7ZHIaCFwPSPK2ZJChIKq50b8Qd8gSfsrRWQuQPHwKdR4wwYzdA==
X-Received: by 2002:a17:902:930a:b0:1e4:fea2:29b7 with SMTP id bc10-20020a170902930a00b001e4fea229b7mr3690759plb.59.1713986819063;
        Wed, 24 Apr 2024 12:26:59 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:dac1:b0:1e8:422d:9e61 with SMTP id
 d9443c01a7336-1eaa15f1015ls1737555ad.1.-pod-prod-05-us; Wed, 24 Apr 2024
 12:26:58 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCW7ddbmFHlp/AwJRo9+ieRQa/jwbtGFikhrBwFOUv1IMCJPZe9KPCEmlLpuVKbUqob0Kmjk/sqq4Z1fHJJttpTs1l1Ngo0ypU5LYw==
X-Received: by 2002:a17:902:ed0b:b0:1e4:2b90:7589 with SMTP id b11-20020a170902ed0b00b001e42b907589mr3359015pld.61.1713986817848;
        Wed, 24 Apr 2024 12:26:57 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1713986817; cv=none;
        d=google.com; s=arc-20160816;
        b=PjnbtGPiMFNje0rIA5qQ6CLC7zX1ZdZQuNPUxB3uJwsw58pmhzrfamqITzcW3ADkIA
         2kCy90rwxWcpZO8Nqcp5zo2HFK+CJssytefwQ2Kooo93DdT+TH35H2fCb440ybHtJM1B
         /V+O5BCOAf65Hmv0ah8Ln72qn5+4S5yDBFRYPUHvot1CSiwuqypKo99aCX3LllbqHXjy
         ssK3J3PtliNHCpTydRP2uQ7RSxoqOoDJFdQcVGEot1bJKkFSNPobMxvm0WTHfJsbJsda
         SU9DO1rzwejjtjhHwdUf+rPZNM0WrIkjem3eic0LqS0WdreZubVIDcGlczThFVqdNFmR
         LMvg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=cE+or9qS5CHOShv/B7RhGLs2+2ylv2Hh/oS9p+uqdWQ=;
        fh=b/qlHPXLF95PwVLQeHJLInt3c19/N1No3Q8SPLWOjoQ=;
        b=qZoo06Q2DbKPQpkWAQDbeUKWVhzSeyPWNvXwzvsFyY8ayISQ2is5iO5OcoAMwSWq3p
         SS64eWwlOSg1dGY3yGYG6eAaoeMfIxN1Y3kpWbXURrg5kRpVxhMStgy/GZXofrLUGE66
         hsNx3Csbj8YRWrNjyBGZ9TrL7ABA4mdyAOT53EK9r2qoPY0bvtpyUnITZwpXWKlR2c4s
         /Yuh5HqFqFPqtoV/ox9KDvIQlT8gQA+RA7DvNiPWVy7MgGldieXMj2+Dia9z02So/fOa
         sQGcbHxRGMu7pTBKscq7nvX4asLwgn7OE0H7zkY7JR78LIYjcofjYacMcZMfTtYMhdPc
         OL+Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="B/TlF1tj";
       spf=pass (google.com: domain of nathan@kernel.org designates 2604:1380:40e1:4800::1 as permitted sender) smtp.mailfrom=nathan@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from sin.source.kernel.org (sin.source.kernel.org. [2604:1380:40e1:4800::1])
        by gmr-mx.google.com with ESMTPS id w2-20020a170902904200b001dd61b4ef8esi953656plz.12.2024.04.24.12.26.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 24 Apr 2024 12:26:57 -0700 (PDT)
Received-SPF: pass (google.com: domain of nathan@kernel.org designates 2604:1380:40e1:4800::1 as permitted sender) client-ip=2604:1380:40e1:4800::1;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sin.source.kernel.org (Postfix) with ESMTP id AB32BCE1711;
	Wed, 24 Apr 2024 19:26:55 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 341AAC113CD;
	Wed, 24 Apr 2024 19:26:54 +0000 (UTC)
Date: Wed, 24 Apr 2024 12:26:52 -0700
From: Nathan Chancellor <nathan@kernel.org>
To: Kees Cook <keescook@chromium.org>
Cc: Marco Elver <elver@google.com>, Andrey Konovalov <andreyknvl@gmail.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Nick Desaulniers <ndesaulniers@google.com>,
	Bill Wendling <morbo@google.com>,
	Justin Stitt <justinstitt@google.com>, llvm@lists.linux.dev,
	kasan-dev@googlegroups.com, linux-hardening@vger.kernel.org,
	linux-kernel@vger.kernel.org
Subject: Re: [PATCH] ubsan: Avoid i386 UBSAN handler crashes with Clang
Message-ID: <20240424192652.GA3341665@dev-arch.thelio-3990X>
References: <20240424162942.work.341-kees@kernel.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20240424162942.work.341-kees@kernel.org>
X-Original-Sender: nathan@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b="B/TlF1tj";       spf=pass
 (google.com: domain of nathan@kernel.org designates 2604:1380:40e1:4800::1 as
 permitted sender) smtp.mailfrom=nathan@kernel.org;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=kernel.org
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

Hi Kees,

On Wed, Apr 24, 2024 at 09:29:43AM -0700, Kees Cook wrote:
> When generating Runtime Calls, Clang doesn't respect the -mregparm=3
> option used on i386. Hopefully this will be fixed correctly in Clang 19:
> https://github.com/llvm/llvm-project/pull/89707
> but we need to fix this for earlier Clang versions today. Force the
> calling convention to use non-register arguments.
> 
> Reported-by: ernsteiswuerfel

FWIW, I think this can be

  Reported-by: Erhard Furtner <erhard_f@mailbox.org>

since it has been used in the kernel before, the reporter is well known
:)

> Closes: https://github.com/KSPP/linux/issues/350
> Signed-off-by: Kees Cook <keescook@chromium.org>
> ---
> Cc: Marco Elver <elver@google.com>
> Cc: Andrey Konovalov <andreyknvl@gmail.com>
> Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>
> Cc: Nathan Chancellor <nathan@kernel.org>
> Cc: Nick Desaulniers <ndesaulniers@google.com>
> Cc: Bill Wendling <morbo@google.com>
> Cc: Justin Stitt <justinstitt@google.com>
> Cc: llvm@lists.linux.dev
> Cc: kasan-dev@googlegroups.com
> Cc: linux-hardening@vger.kernel.org
> ---
>  lib/ubsan.h | 41 +++++++++++++++++++++++++++--------------
>  1 file changed, 27 insertions(+), 14 deletions(-)
> 
> diff --git a/lib/ubsan.h b/lib/ubsan.h
> index 50ef50811b7c..978828f6099d 100644
> --- a/lib/ubsan.h
> +++ b/lib/ubsan.h
> @@ -124,19 +124,32 @@ typedef s64 s_max;
>  typedef u64 u_max;
>  #endif
>  
> -void __ubsan_handle_add_overflow(void *data, void *lhs, void *rhs);
> -void __ubsan_handle_sub_overflow(void *data, void *lhs, void *rhs);
> -void __ubsan_handle_mul_overflow(void *data, void *lhs, void *rhs);
> -void __ubsan_handle_negate_overflow(void *_data, void *old_val);
> -void __ubsan_handle_divrem_overflow(void *_data, void *lhs, void *rhs);
> -void __ubsan_handle_type_mismatch(struct type_mismatch_data *data, void *ptr);
> -void __ubsan_handle_type_mismatch_v1(void *_data, void *ptr);
> -void __ubsan_handle_out_of_bounds(void *_data, void *index);
> -void __ubsan_handle_shift_out_of_bounds(void *_data, void *lhs, void *rhs);
> -void __ubsan_handle_builtin_unreachable(void *_data);
> -void __ubsan_handle_load_invalid_value(void *_data, void *val);
> -void __ubsan_handle_alignment_assumption(void *_data, unsigned long ptr,
> -					 unsigned long align,
> -					 unsigned long offset);
> +/*
> + * When generating Runtime Calls, Clang doesn't respect the -mregparm=3
> + * option used on i386. Hopefully this will be fixed correctly in Clang 19:
> + * https://github.com/llvm/llvm-project/pull/89707
> + * but we need to fix this for earlier Clang versions today. Force the

It may be better to link to the tracking issue upstream instead of the
pull request just in case someone comes up with an alternative fix (not
that I think your change is wrong or anything but it seems like that
happens every so often).

I also get leary of the version information in the comment, even though
I don't doubt this will be fixed in clang 19.

> + * calling convention to use non-register arguments.
> + */
> +#if defined(__clang__) && defined(CONFIG_X86_32)

While __clang__ is what causes CONFIG_CC_IS_CLANG to get set and there
is some existing use of it throughout the kernel, I think
CONFIG_CC_IS_CLANG makes it easier to audit the workarounds that we
have, plus this will be presumably covered to

  CONFIG_CLANG_VERSION < 190000

when the fix actually lands. This file is not expected to be used
outside of the kernel, right? That is the only thing I could think of
where this distinction would actually matter.

> +# define ubsan_linkage asmlinkage

Heh, clever...

> +#else
> +# define ubsan_linkage /**/

Why is this defined as a comment rather than just nothing?

> +#endif
> +
> +void ubsan_linkage __ubsan_handle_add_overflow(void *data, void *lhs, void *rhs);
> +void ubsan_linkage __ubsan_handle_sub_overflow(void *data, void *lhs, void *rhs);
> +void ubsan_linkage __ubsan_handle_mul_overflow(void *data, void *lhs, void *rhs);
> +void ubsan_linkage __ubsan_handle_negate_overflow(void *_data, void *old_val);
> +void ubsan_linkage __ubsan_handle_divrem_overflow(void *_data, void *lhs, void *rhs);
> +void ubsan_linkage __ubsan_handle_type_mismatch(struct type_mismatch_data *data, void *ptr);
> +void ubsan_linkage __ubsan_handle_type_mismatch_v1(void *_data, void *ptr);
> +void ubsan_linkage __ubsan_handle_out_of_bounds(void *_data, void *index);
> +void ubsan_linkage __ubsan_handle_shift_out_of_bounds(void *_data, void *lhs, void *rhs);
> +void ubsan_linkage __ubsan_handle_builtin_unreachable(void *_data);
> +void ubsan_linkage __ubsan_handle_load_invalid_value(void *_data, void *val);
> +void ubsan_linkage __ubsan_handle_alignment_assumption(void *_data, unsigned long ptr,
> +						       unsigned long align,
> +						       unsigned long offset);
>  
>  #endif
> -- 
> 2.34.1
> 
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240424192652.GA3341665%40dev-arch.thelio-3990X.
