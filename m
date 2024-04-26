Return-Path: <kasan-dev+bncBD4NDKWHQYDRBIWNV6YQMGQEDCTDJBA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x38.google.com (mail-oa1-x38.google.com [IPv6:2001:4860:4864:20::38])
	by mail.lfdr.de (Postfix) with ESMTPS id E87148B3E60
	for <lists+kasan-dev@lfdr.de>; Fri, 26 Apr 2024 19:38:43 +0200 (CEST)
Received: by mail-oa1-x38.google.com with SMTP id 586e51a60fabf-22ef8156ac3sf3294822fac.1
        for <lists+kasan-dev@lfdr.de>; Fri, 26 Apr 2024 10:38:43 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1714153122; cv=pass;
        d=google.com; s=arc-20160816;
        b=QANW6ZN2gbdfvb0MfVFvP0lDNAxZrRtIs+GVO7qY8GUXD9OVRrGHhnW4at1FQc4tj8
         quJNJXUY3gVJiPlJwBeHkXrj5KH9ZPCnPBuiK/lj+JUBO5CcAWNyPYI6mbvedsz8YIdK
         S1qUdgL1pHikTNSE7nR8/tSSobmYvsP+5uRvzzz/DWEgZcD+UQurMUkdtaclG+CvqYV1
         +w1R4sW6RXJ/arqT5+4aYhlAltp/oK8I3Ens7BL9SKetUwij6SOnq0HdY2tMJmFHKGIU
         KTZay302P1/wCPTQ9+oZx2g+kCWTPaK1EIwzHxLbbOJGJp28MeZck8Z/Mb0Q4k5svEB0
         gXkw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=iYAdJhaCRLPhp47JZDZ/5o04IPidU77KQTemnvwedDw=;
        fh=QkQKGGFrXJD8h9DXlU3S0Oe2qwwqeax9k9Hql5rTUDA=;
        b=pN2kDNnX5J8WdlVAUW23tB0rWhEp1UhD6gtvYeRwoNuATZ/JQd61NQm7QsNsMiKbA3
         1VacINySpV8gIxppuc9eRetIKUOo1yMRhH6IciQRsAK/zKtSELfe+JVE9cI1/sjGR9PQ
         Ry5B3gixgnSECnNM8S+W+X9453mqPxVZDPtATiMksimyTGYgMTs2ovI9exahXwbJc4pl
         5YmNdSfT5vw4oDBiBXZcTf4Zgk0Th627MzKiFhEnSD1xS7GejE1ddpvaEfvgiW4+zrfw
         xT2/YQVeh4VXbIVechhJpDs+QtLB+UE/10obK08CGPIpeu1YFJMM9qAL6c7q8HN/ULON
         +4Mw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=d3MiS9GB;
       spf=pass (google.com: domain of nathan@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=nathan@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1714153122; x=1714757922; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=iYAdJhaCRLPhp47JZDZ/5o04IPidU77KQTemnvwedDw=;
        b=biavbgnZDoWOre22B0ZkO0dqWZy+yCJt9QalMHtkVIT/XVk5ptK11DH9LxzpzuLChv
         yvigutMr4qpVAT7Kw725OfVvGQD879WY8q0oTKqwnMxzx2Blb2trmaJBMBeyn+VVehLv
         Z6unQfdL7cj8d5eE9qwo6xk+jzrkdbGdPcBnkZZWPJPg7aXKSizZXnFvJ+hDLGs4dqfB
         9zOsJurxMYKeCaY5D47XVrqEPyUYTZbJLFUYVFrlHeEMZB+o1KaCg7JTzfRek7O2av5z
         GExd5U8Zke+1wc2GEjWxQCL3rmZJ2abymo1IWBsQAGdgB6pvtKtSTRnWlFu59sVJ9Li9
         rp9Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1714153122; x=1714757922;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=iYAdJhaCRLPhp47JZDZ/5o04IPidU77KQTemnvwedDw=;
        b=MesobE6jMaJL15SJDnl9SqRZo+a/PP/R9c/XtvNGcYxspX8WStQNyAK4USmZ9aFNcK
         5GeSPCX8ATLxSbBkS1ReVLkYZRLQgLhck5sNp5dDdbiVrxibgx54FwSRTOnhhnydXNG8
         iMnEzsaA0okgh6DMJoT9Hu4bNNhRxXZ3o2epsWeV2/EFrqHGHSUQeGPqnmIiSXmzLk+S
         MVi/on8cxNGrkNLkoYXmOigIcb9pCCJiaK/79zkmp9TMj/sdkWbjH4tCleQ5mXJT/x+U
         Un7GSiMcpKzhk1DIaGAs8IxaUlo/bjtzl9quzPqOW/n+8JBxWoGhxJ4JA04gc3VSMWVo
         rkWQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUvmZUkeWRdwqo5VuniVdt63wKuKqxqFfzXgNCpZpiqFN/8FxSZdxxlAxtD/vNXyyvxhtrTt0J1f7n1yEY075dBrZyoG4591Q==
X-Gm-Message-State: AOJu0YwKe8pZcEDFoJD3HFDXL2k1QMkERW9CHvze+yASyy8QdbayTfVE
	FNSpPeqnYE8S9dfVdlMsrdecfESIHE0gVX4NlkGU+Q4lX41xt+rY
X-Google-Smtp-Source: AGHT+IGjiATCVTtKxm+feGOdQssBizL0jUngVNX0c26It4XlwCN3Un7pz9ogOoow1PJK7TAjtybuAQ==
X-Received: by 2002:a05:6870:4189:b0:22a:a01f:c90a with SMTP id y9-20020a056870418900b0022aa01fc90amr233530oac.21.1714153122420;
        Fri, 26 Apr 2024 10:38:42 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6871:e78d:b0:235:efa6:2f21 with SMTP id
 586e51a60fabf-23b40f36d02ls1111306fac.0.-pod-prod-00-us; Fri, 26 Apr 2024
 10:38:41 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUeCABbc993RGoIsLPqE40JdzSnCSLsypMw7qPMcOZlCXNJzGWSkpT1c/z0c9iN8ndErN0HqoqMmZEuMDOrVzTY/DP0wLmMchOq1g==
X-Received: by 2002:a05:6871:b0c:b0:229:e5e6:1a36 with SMTP id fq12-20020a0568710b0c00b00229e5e61a36mr1619468oab.20.1714153121042;
        Fri, 26 Apr 2024 10:38:41 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1714153121; cv=none;
        d=google.com; s=arc-20160816;
        b=b+0O/mxu0Ibvgnskd/fxdzcFNkQuleDqKSYk1thsoiVaVegEP9yydKxaK1by940j7j
         pScZwbokPAt1gkpnxrNY646CCRGYUfEDcHTuVk2q9KJ4kXJT6cRtoNOTfRxtGlzLdrj2
         2J6yQlc8vTHK6F2RuKp/Ta2ZpCqSCgaMX/a35O3z48KHrjToYzUAfhDjVM1lQ42lHFn6
         b9m1uPGg5TwS+wapLVBII2L/h8415/BwloE6XCEnf+kw4rWSZ4Ozm37o1H1a+do9B45h
         XM+Wz2mmp1GLVS3dn36Prw/JHHWo6fqB5zBxDRgzHyXS/1VM43ScTK/kpvTlgXu0NTJT
         6RAA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=fe5EQQLoTXZFn1bLQXPTwoyrsdAh1Ibszp1SAcmbFC8=;
        fh=s2DUDp1s6XhCCvcI9eEh+J/TVMMDL5Ek3FPgyCtRWQo=;
        b=EvszhXn9yltSbczl3yZvwGP3Q64n5cB7jmXT1QOnmMs8tRs3I0jxmgk/mIZGbv8wKt
         XWtLO706EbyRmnJuVc4B19H1oHL/owJbCIc3ra2XUiLanTWszs+AZL/s6Gl9v6Gji3wm
         6tPpFqGSys9NoaSVKVhOEMSfzbxbcMwqqZGtGygdWYWiDD+iu6VejFF+T4lBegfqMk0i
         kkrizHKwDw3fsPk6qON53Fa+RUgm9frMKzaaxFLzotOd+ntmg1wThiILpZxtKCZMchAI
         19oagwhNuq5HnsNWagYP/GbD8SBOvQcsYbtXPe6GqQR8LyIgxT0UQiavJox49O/B2Wn6
         Xc7A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=d3MiS9GB;
       spf=pass (google.com: domain of nathan@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=nathan@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id fs15-20020a056870f78f00b0023609ee0c41si2310190oab.0.2024.04.26.10.38.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 26 Apr 2024 10:38:41 -0700 (PDT)
Received-SPF: pass (google.com: domain of nathan@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id B00D561FE7;
	Fri, 26 Apr 2024 17:38:40 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 4FFB6C113CD;
	Fri, 26 Apr 2024 17:38:39 +0000 (UTC)
Date: Fri, 26 Apr 2024 10:38:37 -0700
From: Nathan Chancellor <nathan@kernel.org>
To: Kees Cook <keescook@chromium.org>
Cc: Marco Elver <elver@google.com>, Erhard Furtner <erhard_f@mailbox.org>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Nick Desaulniers <ndesaulniers@google.com>,
	Bill Wendling <morbo@google.com>,
	Justin Stitt <justinstitt@google.com>, llvm@lists.linux.dev,
	kasan-dev@googlegroups.com, linux-hardening@vger.kernel.org,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-kernel@vger.kernel.org
Subject: Re: [PATCH v2] ubsan: Avoid i386 UBSAN handler crashes with Clang
Message-ID: <20240426173837.GA2744190@dev-arch.thelio-3990X>
References: <20240424224026.it.216-kees@kernel.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20240424224026.it.216-kees@kernel.org>
X-Original-Sender: nathan@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=d3MiS9GB;       spf=pass
 (google.com: domain of nathan@kernel.org designates 139.178.84.217 as
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

On Wed, Apr 24, 2024 at 03:40:29PM -0700, Kees Cook wrote:
> When generating Runtime Calls, Clang doesn't respect the -mregparm=3
> option used on i386. Hopefully this will be fixed correctly in Clang 19:
> https://github.com/llvm/llvm-project/pull/89707
> but we need to fix this for earlier Clang versions today. Force the
> calling convention to use non-register arguments.
> 
> Reported-by: Erhard Furtner <erhard_f@mailbox.org>
> Closes: https://github.com/KSPP/linux/issues/350
> Signed-off-by: Kees Cook <keescook@chromium.org>

Acked-by: Nathan Chancellor <nathan@kernel.org>

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
>  v2:
>    - use email address in Reported-by
>    - link to upstream llvm bug in ubsan.h comment
>    - drop needless /**/
>    - explicitly test Clang version
>  v1: https://lore.kernel.org/lkml/20240424162942.work.341-kees@kernel.org/
> ---
>  lib/ubsan.h | 41 +++++++++++++++++++++++++++--------------
>  1 file changed, 27 insertions(+), 14 deletions(-)
> 
> diff --git a/lib/ubsan.h b/lib/ubsan.h
> index 50ef50811b7c..07e37d4429b4 100644
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
> + * option used on i386: https://github.com/llvm/llvm-project/issues/89670
> + * Fix this for earlier Clang versions by forcing the calling convention
> + * to use non-register arguments.
> + */
> +#if defined(CONFIG_X86_32) && \
> +    defined(CONFIG_CC_IS_CLANG) && CONFIG_CLANG_VERSION < 190000
> +# define ubsan_linkage asmlinkage
> +#else
> +# define ubsan_linkage
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

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240426173837.GA2744190%40dev-arch.thelio-3990X.
