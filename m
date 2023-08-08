Return-Path: <kasan-dev+bncBDV37XP3XYDRBHPNZCTAMGQEHA5R3SI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x140.google.com (mail-lf1-x140.google.com [IPv6:2a00:1450:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id 9EC38773A2D
	for <lists+kasan-dev@lfdr.de>; Tue,  8 Aug 2023 14:35:43 +0200 (CEST)
Received: by mail-lf1-x140.google.com with SMTP id 2adb3069b0e04-4fe275023d4sf5417685e87.2
        for <lists+kasan-dev@lfdr.de>; Tue, 08 Aug 2023 05:35:43 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1691498143; cv=pass;
        d=google.com; s=arc-20160816;
        b=TcGDElEwDNNGT0MlvxAud2e1f4nR9VKdQnUz0TMUuVXlJEQqZWM3Z8q/XJnWF5vxhW
         GZGipLfub6ALeoFMAp+u0uAe/4xhrTSAo9VVIq5hSuX6CXESbGQ98FjO1AFnu8GnIF6g
         F5LFOkl3T7YXDPV8QTW8Owz27suYi8k85KF/zCKcp+7+S/7aY9h2pkyxmnMgrf5p8o1k
         dvPcXUh3Kj0WPg8e1E5gW1nXiuTSiHBNQC+qIPiKys+KvR/xSGM56QNfkPMDi/3higVV
         gd+WGnXDnPSDrNVhOaziV+e066XwbdoxverBntK2Viw7LmS/94GbWqLsHy0TN9ece7To
         0Hbw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=pJcQVenZf/Ug9dCs2bSxxjODByKtUszG5Z+Xz5ab+ks=;
        fh=OPkJlFMJKH10AVva8ynbVQRaZC9KW3M1lUV94+OTNXA=;
        b=xQTjahxyZE4TOqf4K1MxgYxZXHI9lcKpHuBFWuV/Krn2+dFaFMTX/Va+QyTGh2ZHKw
         fnIWYRWH9624L6DxIeYgCrGwil8Ed+SA+yNPKKv4mHH/zAgvVl2pSBewgZ5adHDcj5+v
         QkEwtP6auH//I+4W3mfWRIW1rBPu9SRBY8dFvUe7xDTGYbBY9zXnijNOGKie37pizBSz
         MHmi0SswRNl3muhYBkq57Q4qNuFSHbWUIU1mJ8TAiakXekX6V4tKiM9sDJWDkC0ygBAt
         CBJGMiMDf3rAgHqI+bybnebED+wueKdEVppK5sQHqXutq/XuR7xv3Xqmya4lhhQjDcgA
         mwwg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1691498143; x=1692102943;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=pJcQVenZf/Ug9dCs2bSxxjODByKtUszG5Z+Xz5ab+ks=;
        b=BCIh/7wDESmYV930kXPVywxTGqIvOquExZndReUUOo9L1Us/qaYt5nkz4ipqrCvmPd
         rd5ka/e4dbzmLNduASysqFI1h7HwE3JeF474NyPiRoqOJUz2rZBxgx/zDidShN23gWZG
         gLE0Crh3/I6M2c9DGyWPu14saROprvlhhEltjYbhfixrzSkdvAYRD7ci11m7adTGwwak
         gcBVsimi3LLrQimtvF7j41JpfprfXZHIS6cSjo5qQEs1DnvyKbZFcSpeSdowaECAX6ra
         lcLxU8IyWg5iUC7WXD2jXMmQBJgV2IRLx66M5Vx2Ltk3hjabwbNcP6bYHFfOpydSZUYX
         MT3Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1691498143; x=1692102943;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=pJcQVenZf/Ug9dCs2bSxxjODByKtUszG5Z+Xz5ab+ks=;
        b=K1SzdL/cL8GguYj9YJBt+6EMYoJdPwL28Q4K9YN7qOyW+Nk8vUaJ53q5wrUawFJTdA
         +l7fLnJAPGacBbQSnnUk/vwLbkq1TJ+Yhh1vmXWeMY44aNYqA9cqmpD2Q4BPWXyybcYO
         BUXynzsxIkHdNE/nBFeMhdx+pPqrynQquI9SKNbuTMikSlk9U+cTNGBOnqzRC3XcPIel
         5N2kXkj7RYSU5LOgqV557e3hr86dXUOI4V9Hj304q8cvlozW+cdCv/qPEOj5NtUBZNyq
         4sj6Gw4NCvYXEJl7UVxZGji1w2u7RBPtpknFCnTMYhLRaIG0v02qTbqG9RctM/Br552k
         2HQQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yw8hp/elLcjwfJzbydl5PmlgcyZE1vQu5qzZn41VjJPJTNq5Ycm
	ojlPHBYspHJmxc5gN0DPkW8=
X-Google-Smtp-Source: AGHT+IFDFAV+xJ8SHk2625FH6nc2FyCJkcGNVeQKGfKb9mNEWVnJ0tNr9ycT4617eAGok/UBI0Yakg==
X-Received: by 2002:a05:6512:3f6:b0:4fb:89f2:594d with SMTP id n22-20020a05651203f600b004fb89f2594dmr6543915lfq.63.1691498142139;
        Tue, 08 Aug 2023 05:35:42 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a19:8c0e:0:b0:4fa:718c:85b0 with SMTP id o14-20020a198c0e000000b004fa718c85b0ls1461205lfd.2.-pod-prod-06-eu;
 Tue, 08 Aug 2023 05:35:40 -0700 (PDT)
X-Received: by 2002:a05:6512:70e:b0:4fb:9fa7:dcda with SMTP id b14-20020a056512070e00b004fb9fa7dcdamr7401722lfs.26.1691498140151;
        Tue, 08 Aug 2023 05:35:40 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1691498140; cv=none;
        d=google.com; s=arc-20160816;
        b=akt6t8O1cWhgkWvD8/LqbJp9upG1ZWUSEbr0pvfjfXiWlIjaiYa3PhNBV6e4tc5rh/
         Q46JifvdxYDquL0Q4mn0bvC/kE18QcNlUdtLmlKBZXs+fHD4O4rrAQnixHMcP52UAM6t
         FKymWLaW/sptjf5TTKJiZqKQ+lqIJbD5/qH7tu+moGXGDrKJaRsNMxAh1EupkbD3GIET
         zQBk53n2vTqjFleaxKy5BxuaOk54lqILlJDA9413gAVOkgCT539P07rLoZdA/wmE5DdF
         FbyDPB87QggQyDGGu10LKJqM4g6h/zOk3WkU71QsVnQDD+M+rfCBrB05y6oZ2grrziuZ
         wnNg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date;
        bh=xQeRfx/PxCLwYQhk/VjWSA+mNFDuNnUrVLEE343dnnw=;
        fh=OPkJlFMJKH10AVva8ynbVQRaZC9KW3M1lUV94+OTNXA=;
        b=asC4HePq/BPsaEh0+C7R17iBWHar4Cc/NnGSSTusbK0Gk6b4HNONJGTDjybp1tvaL1
         WP0k3pfJiEH1MhaJEjfRQgNfxOEXTetw8n5e4kfezmh8klHFqKY4li/vojZSq1Q8DuWS
         Mt/M4DCcHopcCwhVRhFxP5wcTSDIv1UsUdlJ1qbykn0MBhAN73zPfHyZ0JVyjLt0nabL
         yWzWZhi5veLTgSOJRWrAK0OuDwUK4+u0n86/4YlX7o2+ejBohmZCtMyQdTiR9P+RxVis
         5BixQ//0Yym0rcxi1sx0EFUyZkDIdX5tXFGbts4JwE8PWTf9lcUXc8UQ6B34SqIhrhTo
         wxYQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id v21-20020ac258f5000000b004fe3478235csi676464lfo.7.2023.08.08.05.35.39
        for <kasan-dev@googlegroups.com>;
        Tue, 08 Aug 2023 05:35:40 -0700 (PDT)
Received-SPF: pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 681661576;
	Tue,  8 Aug 2023 05:36:21 -0700 (PDT)
Received: from FVFF77S0Q05N.cambridge.arm.com (FVFF77S0Q05N.cambridge.arm.com [10.1.35.148])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 36E633F59C;
	Tue,  8 Aug 2023 05:35:35 -0700 (PDT)
Date: Tue, 8 Aug 2023 13:35:29 +0100
From: Mark Rutland <mark.rutland@arm.com>
To: Marco Elver <elver@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>,
	Kees Cook <keescook@chromium.org>,
	Guenter Roeck <linux@roeck-us.net>,
	Peter Zijlstra <peterz@infradead.org>,
	Steven Rostedt <rostedt@goodmis.org>, Marc Zyngier <maz@kernel.org>,
	Oliver Upton <oliver.upton@linux.dev>,
	James Morse <james.morse@arm.com>,
	Suzuki K Poulose <suzuki.poulose@arm.com>,
	Zenghui Yu <yuzenghui@huawei.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will@kernel.org>,
	Nathan Chancellor <nathan@kernel.org>,
	Nick Desaulniers <ndesaulniers@google.com>,
	Tom Rix <trix@redhat.com>, Miguel Ojeda <ojeda@kernel.org>,
	Sami Tolvanen <samitolvanen@google.com>,
	linux-arm-kernel@lists.infradead.org, kvmarm@lists.linux.dev,
	linux-kernel@vger.kernel.org, llvm@lists.linux.dev,
	Dmitry Vyukov <dvyukov@google.com>,
	Alexander Potapenko <glider@google.com>, kasan-dev@googlegroups.com,
	linux-toolchains@vger.kernel.org
Subject: Re: [PATCH v3 1/3] compiler_types: Introduce the Clang
 __preserve_most function attribute
Message-ID: <ZNI2kStGIPInDYIK@FVFF77S0Q05N.cambridge.arm.com>
References: <20230808102049.465864-1-elver@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20230808102049.465864-1-elver@google.com>
X-Original-Sender: mark.rutland@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as
 permitted sender) smtp.mailfrom=mark.rutland@arm.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=arm.com
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

On Tue, Aug 08, 2023 at 12:17:25PM +0200, Marco Elver wrote:
> [1]: "On X86-64 and AArch64 targets, this attribute changes the calling
> convention of a function. The preserve_most calling convention attempts
> to make the code in the caller as unintrusive as possible. This
> convention behaves identically to the C calling convention on how
> arguments and return values are passed, but it uses a different set of
> caller/callee-saved registers. This alleviates the burden of saving and
> recovering a large register set before and after the call in the caller.
> If the arguments are passed in callee-saved registers, then they will be
> preserved by the callee across the call. This doesn't apply for values
> returned in callee-saved registers.
> 
>  * On X86-64 the callee preserves all general purpose registers, except
>    for R11. R11 can be used as a scratch register. Floating-point
>    registers (XMMs/YMMs) are not preserved and need to be saved by the
>    caller.
> 
>  * On AArch64 the callee preserve all general purpose registers, except
>    x0-X8 and X16-X18."
> 
> [1] https://clang.llvm.org/docs/AttributeReference.html#preserve-most
> 
> Introduce the attribute to compiler_types.h as __preserve_most.
> 
> Use of this attribute results in better code generation for calls to
> very rarely called functions, such as error-reporting functions, or
> rarely executed slow paths.
> 
> Beware that the attribute conflicts with instrumentation calls inserted
> on function entry which do not use __preserve_most themselves. Notably,
> function tracing which assumes the normal C calling convention for the
> given architecture.  Where the attribute is supported, __preserve_most
> will imply notrace. It is recommended to restrict use of the attribute
> to functions that should or already disable tracing.
> 
> The attribute may be supported by a future GCC version (see
> https://gcc.gnu.org/bugzilla/show_bug.cgi?id=110899).
> 
> Signed-off-by: Marco Elver <elver@google.com>
> Reviewed-by: Miguel Ojeda <ojeda@kernel.org>
> Acked-by: Steven Rostedt (Google) <rostedt@goodmis.org>

So long as this implies notrace I believe it is safe, so:

Acked-by: Mark Rutland <mark.rutland@arm.com>

Mark.

> ---
> v3:
> * Quote more from LLVM documentation about which registers are
>   callee/caller with preserve_most.
> * Code comment to restrict use where tracing is meant to be disabled.
> 
> v2:
> * Imply notrace, to avoid any conflicts with tracing which is inserted
>   on function entry. See added comments.
> ---
>  include/linux/compiler_types.h | 28 ++++++++++++++++++++++++++++
>  1 file changed, 28 insertions(+)
> 
> diff --git a/include/linux/compiler_types.h b/include/linux/compiler_types.h
> index 547ea1ff806e..c88488715a39 100644
> --- a/include/linux/compiler_types.h
> +++ b/include/linux/compiler_types.h
> @@ -106,6 +106,34 @@ static inline void __chk_io_ptr(const volatile void __iomem *ptr) { }
>  #define __cold
>  #endif
>  
> +/*
> + * On x86-64 and arm64 targets, __preserve_most changes the calling convention
> + * of a function to make the code in the caller as unintrusive as possible. This
> + * convention behaves identically to the C calling convention on how arguments
> + * and return values are passed, but uses a different set of caller- and callee-
> + * saved registers.
> + *
> + * The purpose is to alleviates the burden of saving and recovering a large
> + * register set before and after the call in the caller.  This is beneficial for
> + * rarely taken slow paths, such as error-reporting functions that may be called
> + * from hot paths.
> + *
> + * Note: This may conflict with instrumentation inserted on function entry which
> + * does not use __preserve_most or equivalent convention (if in assembly). Since
> + * function tracing assumes the normal C calling convention, where the attribute
> + * is supported, __preserve_most implies notrace.  It is recommended to restrict
> + * use of the attribute to functions that should or already disable tracing.
> + *
> + * Optional: not supported by gcc.
> + *
> + * clang: https://clang.llvm.org/docs/AttributeReference.html#preserve-most
> + */
> +#if __has_attribute(__preserve_most__)
> +# define __preserve_most notrace __attribute__((__preserve_most__))
> +#else
> +# define __preserve_most
> +#endif
> +
>  /* Builtins */
>  
>  /*
> -- 
> 2.41.0.640.ga95def55d0-goog
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ZNI2kStGIPInDYIK%40FVFF77S0Q05N.cambridge.arm.com.
