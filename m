Return-Path: <kasan-dev+bncBD4NDKWHQYDRB54OXL3AKGQEGYP47OI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x638.google.com (mail-pl1-x638.google.com [IPv6:2607:f8b0:4864:20::638])
	by mail.lfdr.de (Postfix) with ESMTPS id 06F061E4752
	for <lists+kasan-dev@lfdr.de>; Wed, 27 May 2020 17:30:01 +0200 (CEST)
Received: by mail-pl1-x638.google.com with SMTP id s9sf18314716plq.18
        for <lists+kasan-dev@lfdr.de>; Wed, 27 May 2020 08:30:00 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1590593399; cv=pass;
        d=google.com; s=arc-20160816;
        b=QapQKjjEDjUVmnVpkSrd8dYZMym0IUP+XpmOMtBYpWz+odFC3OW7eshBci8LuJFU+V
         KrBp879p/RxhU7K8yStXaAAb/JLNYZYE6I99mF02l8Q+uZ0zg/c+t0TPO3Wx2XKL23TT
         lZK5EUPpU33CM1LT8z2i0EC2FBlClXGNJ+mkyya4pTt4xPKz+faLqwWZZyxELLrPuBUP
         8ph6KNZZ8y+UQM15025OjAIsbcb6PyYA7GPcgGdUwOjRYyhYv+BkDl88Nicx8Fa8t78O
         8yQ3e1QV51uYXjBQ2myHzQ09W+Y/aOiTd4SbTjUVitVjQfyDVfbp/e/EuM2bqjrbEJJ2
         YcaA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature:dkim-signature;
        bh=ZYDpc0H5IouSAJ8zHdugaHOKFTZeBzrR6GRtcCF/J2Y=;
        b=sjdoN1AqhC77RHV/uBtCCfN/fTlZqDT9ycjVy4cr13N9Go4+OvnQUP9GJC8PX80qM0
         S0VU2eOzzN9aeyyqsGi2ZedFnsKdwr4twzyZhgTXBpQ4DQt8zGbnUDoSbpfTNOD1kQqP
         ZGxd9l0vmimQlDdojhzq3zB+Xm5DrzRSdm6qn+v451Zb5vpWGfQAG2E9CRbj9K0GaLj+
         IrELxJsCfHhDzpDS3l4WmAKhau601LgO4w4JELggqXo3M4eoWYURdpJWNRHb7UzPHCrB
         bPz/DtgZVTWbwSSuBmUAWNp6jtb51G7xlfPLijctYojwiiotrvnE9UP/Pcs+wYLNdKIu
         /naA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b="C5MB/EUe";
       spf=pass (google.com: domain of natechancellor@gmail.com designates 2607:f8b0:4864:20::542 as permitted sender) smtp.mailfrom=natechancellor@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=ZYDpc0H5IouSAJ8zHdugaHOKFTZeBzrR6GRtcCF/J2Y=;
        b=CrfKFSOsxAVJGc4mqx0+l3ROIo/iuIGan9WxHcGj8WcjnaHDqCjWwxI1K95Uk+pK86
         EoGE2FxKj0NmGax2ytH05abIa7pMhREAFc6DEkEhirk20CYBi1t2WUTBfkub9/lFKF5H
         mTFh1AbOV2OGeg4JlATcrUh3Xd1m2PcFAQ9P+f7+xCLGBzNS69icqL4rROvw0gM2nI1w
         K6DrLo9dULfJxicO+GeIOrdgwGGsyL7t8e+ILFkagTXb1FP6R+ys0MPPkX32jydJSc14
         /8hr56DiU8uUFFJ6Fr8G5vAJiQFvCiiF/8/ZzSrQJnakJxEzmA3BAvoqYYacekFsjuOO
         erGg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=ZYDpc0H5IouSAJ8zHdugaHOKFTZeBzrR6GRtcCF/J2Y=;
        b=Nsuw/1sdP3qnTcS9meT/wwIypq+1BKq1/daLOW4PReJemmZ7cLbOIoRqEQ1V5YDKaU
         BX4EpA5Ro8dlCUHGKsTTGiwabXQ98ncfJrzW7IHpuGGDyw9sdbUzapQuQGqpWUf/Z+Oa
         MDdUuUIzHIxocNWdQ2Iowp08I9ufRtz0rOfQ/C7JbBXApVmD1ygTcSn5rGPKIkIZMFrW
         ptfm640jMG4eAZZIqPWymYbixSwoL9WzQ5JLY5eDwsQeSUwU3FT+8e1OODSdEEo/OLdH
         9g2coKx6bS9dgLRL9i4GTLz+w/zm+rbjgErKLlIW/YbCy6EYma+KMznH/qnLSVVHve1j
         cH1g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=ZYDpc0H5IouSAJ8zHdugaHOKFTZeBzrR6GRtcCF/J2Y=;
        b=BZVtLuxtLYKvwNbErOpc8t6S+r9o9qNPpGIADbhOoro1unN+HAejPxHx66wxjSAg9u
         BHljg9i3RnQA7fKO7XjRSKXa+/j9sjB4sw3IPotSvtjHQJVPG27n8nEpJ1bqP6XLr6pl
         NXvIL8bozdbjabI56ah0WEUZopJNHgJOXMa+QkPnNA1Pr2XMOtySIwD8Bvv7KChNygXg
         lZw2+jYEiCzu0NMTqtWhEuA34ZQmniTnn3t5sWiCyOga/4AL71HHuRDfmHWVk2/SsX9G
         Mq1P0t3Ukum1VzlAi+Jg8yQdM+SXrIMMfVMTiL7Ho/es8I5inraWWGaCr5pcjJSgT31B
         ZGzg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532lq3hAujlD1hBlUi2o2ZMruGgFqV3ch/6Veiqh+hTZVNMCAsWr
	j4kW0fUtCmecXHueqy/eXMY=
X-Google-Smtp-Source: ABdhPJzQvd8wyyA3Nx3lUGJd/sCevMW/OG3slYaeHJnAVcfIuwvTDAFQqPI0yJhZ8wPKBSfG+LnCHQ==
X-Received: by 2002:a63:9319:: with SMTP id b25mr4678212pge.374.1590593399629;
        Wed, 27 May 2020 08:29:59 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:4c84:: with SMTP id my4ls712858pjb.0.gmail; Wed, 27
 May 2020 08:29:59 -0700 (PDT)
X-Received: by 2002:a17:902:6947:: with SMTP id k7mr6512298plt.258.1590593399207;
        Wed, 27 May 2020 08:29:59 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1590593399; cv=none;
        d=google.com; s=arc-20160816;
        b=AC7s5Cz9MOpA1Jiw/eDKt2Pt/hSk8eZVzXadTBdMFbfpaVc5JfoK3munvlTByhca6Y
         OYNafTP5h8U4bADeEtwKcYlyBoIcGasAmxY9dHzGKqXe4fGyLK0PtDQd6RRjiBdYJtyP
         rdUP8MIIClDK1Zh9dhheTGMT7NvmDmWEGNE1xDFdintrew7TTvjOGN7jvPyKpjmjghgP
         3f/o8ioEYV+mQA+/pDmFpCdcsh8LJpUj6mvpk9jJeBa3vNdGfpWYLc15epbx47Lk4V4L
         I26t04BujpK+4Mtys0NX/1N2GPZoytpb7WqRAefIqdE9yXqzd+fko1jpDVQN/OInsTBf
         nDbw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=EP0X4nrq+dBeA9FW2rwRe3EmgkIyPMB88g1VDoRBEaI=;
        b=bOF83juG4d3oRz312cZVDT0l7csyfnlI3ZMpnTe+LJsefilTbRrGKGREYx7DwzF5yO
         HuKkjTzPJ4FDQ+xxqblw5E6rrjmzXHFA35ypcXPDoEliDIfJjuMYTUj8HLJUGg1J1QqH
         LqS/vBxRAhgyHIZdMrFJ+lnRECUx8GScTO9Iqin1oUd45iI61CHWScyWkprm4KJ7+Uet
         RCNp/5TOvwqvrGWn+GZEo02dIn3TLuWeYrV3YSjY3D1TOn2UL81gGrb0lWAKhBlSS+L6
         iPc0Ypz4V4QB12NqSRXC7OLVB95jlGmhJ5LAJimmOUkffgZHfvxR48tXBg1KlhJxu3qf
         U5gw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b="C5MB/EUe";
       spf=pass (google.com: domain of natechancellor@gmail.com designates 2607:f8b0:4864:20::542 as permitted sender) smtp.mailfrom=natechancellor@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pg1-x542.google.com (mail-pg1-x542.google.com. [2607:f8b0:4864:20::542])
        by gmr-mx.google.com with ESMTPS id t132si368695pfc.6.2020.05.27.08.29.59
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 27 May 2020 08:29:59 -0700 (PDT)
Received-SPF: pass (google.com: domain of natechancellor@gmail.com designates 2607:f8b0:4864:20::542 as permitted sender) client-ip=2607:f8b0:4864:20::542;
Received: by mail-pg1-x542.google.com with SMTP id w20so6871405pga.6;
        Wed, 27 May 2020 08:29:59 -0700 (PDT)
X-Received: by 2002:aa7:8c53:: with SMTP id e19mr4487122pfd.264.1590593398712;
        Wed, 27 May 2020 08:29:58 -0700 (PDT)
Received: from ubuntu-s3-xlarge-x86 ([2604:1380:4111:8b00::1])
        by smtp.gmail.com with ESMTPSA id d2sm2409483pfc.7.2020.05.27.08.29.56
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 27 May 2020 08:29:58 -0700 (PDT)
Date: Wed, 27 May 2020 08:29:55 -0700
From: Nathan Chancellor <natechancellor@gmail.com>
To: Marco Elver <elver@google.com>
Cc: will@kernel.org, peterz@infradead.org, bp@alien8.de, tglx@linutronix.de,
	mingo@kernel.org, clang-built-linux@googlegroups.com,
	paulmck@kernel.org, dvyukov@google.com, glider@google.com,
	andreyknvl@google.com, kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org, Arnd Bergmann <arnd@arndb.de>,
	Nick Desaulniers <ndesaulniers@google.com>,
	Stephen Rothwell <sfr@canb.auug.org.au>
Subject: Re: [PATCH -tip] compiler_types.h: Optimize __unqual_scalar_typeof
 compilation time
Message-ID: <20200527152955.GA3681123@ubuntu-s3-xlarge-x86>
References: <20200527103236.148700-1-elver@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20200527103236.148700-1-elver@google.com>
X-Original-Sender: natechancellor@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b="C5MB/EUe";       spf=pass
 (google.com: domain of natechancellor@gmail.com designates
 2607:f8b0:4864:20::542 as permitted sender) smtp.mailfrom=natechancellor@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Wed, May 27, 2020 at 12:32:36PM +0200, 'Marco Elver' via Clang Built Linux wrote:
> If the compiler supports C11's _Generic, use it to speed up compilation
> times of __unqual_scalar_typeof(). GCC version 4.9 or later and
> all supported versions of Clang support the feature (the oldest
> supported compiler that doesn't support _Generic is GCC 4.8, for which
> we use the slower alternative).
> 
> The non-_Generic variant relies on multiple expansions of
> __pick_integer_type -> __pick_scalar_type -> __builtin_choose_expr,
> which increases pre-processed code size, and can cause compile times to
> increase in files with numerous expansions of READ_ONCE(), or other
> users of __unqual_scalar_typeof().
> 
> Summary of compile-time benchmarking done by Arnd Bergmann [1]:
> 
> 	<baseline normalized time>  clang-11   gcc-9
> 	this patch                      0.78    0.91
> 	ideal                           0.76    0.86
> 
> [1] https://lkml.kernel.org/r/CAK8P3a3UYQeXhiufUevz=rwe09WM_vSTCd9W+KvJHJcOeQyWVA@mail.gmail.com
> 
> Further compile-testing done with:
> 	gcc 4.8, 4.9, 5.5, 6.4, 7.5, 8.4;
> 	clang 9, 10.
> 
> Reported-by: Arnd Bergmann <arnd@arndb.de>
> Signed-off-by: Marco Elver <elver@google.com>
> Cc: Borislav Petkov <bp@alien8.de>
> Cc: Ingo Molnar <mingo@kernel.org>
> Cc: Nick Desaulniers <ndesaulniers@google.com>
> Cc: Paul E. McKenney <paulmck@kernel.org>
> Cc: Peter Zijlstra <peterz@infradead.org>
> Cc: Stephen Rothwell <sfr@canb.auug.org.au>
> Cc: Thomas Gleixner <tglx@linutronix.de>
> Cc: Will Deacon <will@kernel.org>
> Link: https://lkml.kernel.org/r/CAK8P3a0RJtbVi1JMsfik=jkHCNFv+DJn_FeDg-YLW+ueQW3tNg@mail.gmail.com
> ---
> Same version as in:
> https://lkml.kernel.org/r/20200526173312.GA30240@google.com
> ---
>  include/linux/compiler_types.h | 22 +++++++++++++++++++++-
>  1 file changed, 21 insertions(+), 1 deletion(-)
> 
> diff --git a/include/linux/compiler_types.h b/include/linux/compiler_types.h
> index 5faf68eae204..a529fa263906 100644
> --- a/include/linux/compiler_types.h
> +++ b/include/linux/compiler_types.h
> @@ -245,7 +245,9 @@ struct ftrace_likely_data {
>  /*
>   * __unqual_scalar_typeof(x) - Declare an unqualified scalar type, leaving
>   *			       non-scalar types unchanged.
> - *
> + */
> +#if defined(CONFIG_CC_IS_GCC) && CONFIG_GCC_VERSION < 40900
> +/*
>   * We build this out of a couple of helper macros in a vain attempt to
>   * help you keep your lunch down while reading it.
>   */
> @@ -267,6 +269,24 @@ struct ftrace_likely_data {
>  			__pick_integer_type(x, int,				\
>  				__pick_integer_type(x, long,			\
>  					__pick_integer_type(x, long long, x))))))
> +#else
> +/*
> + * If supported, prefer C11 _Generic for better compile-times. As above, 'char'
> + * is not type-compatible with 'signed char', and we define a separate case.
> + */
> +#define __scalar_type_to_expr_cases(type)				\
> +		type: (type)0, unsigned type: (unsigned type)0
> +
> +#define __unqual_scalar_typeof(x) typeof(				\
> +		_Generic((x),						\
> +			 __scalar_type_to_expr_cases(char),		\
> +			 signed char: (signed char)0,			\
> +			 __scalar_type_to_expr_cases(short),		\
> +			 __scalar_type_to_expr_cases(int),		\
> +			 __scalar_type_to_expr_cases(long),		\
> +			 __scalar_type_to_expr_cases(long long),	\
> +			 default: (x)))
> +#endif
>  
>  /* Is this type a native word size -- useful for atomic operations */
>  #define __native_word(t) \
> -- 
> 2.27.0.rc0.183.gde8f92d652-goog
> 

Reviewed-by: Nathan Chancellor <natechancellor@gmail.com>
Tested-by: Nathan Chancellor <natechancellor@gmail.com> # build

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200527152955.GA3681123%40ubuntu-s3-xlarge-x86.
