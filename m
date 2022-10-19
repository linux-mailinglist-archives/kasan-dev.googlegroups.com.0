Return-Path: <kasan-dev+bncBCF5XGNWYQBRBY7IYCNAMGQER6EBUNQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33a.google.com (mail-ot1-x33a.google.com [IPv6:2607:f8b0:4864:20::33a])
	by mail.lfdr.de (Postfix) with ESMTPS id 65853604EA5
	for <lists+kasan-dev@lfdr.de>; Wed, 19 Oct 2022 19:31:16 +0200 (CEST)
Received: by mail-ot1-x33a.google.com with SMTP id i3-20020a9d68c3000000b00661a0e6d7fesf8347066oto.0
        for <lists+kasan-dev@lfdr.de>; Wed, 19 Oct 2022 10:31:16 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1666200675; cv=pass;
        d=google.com; s=arc-20160816;
        b=r6DVaUURVxcyHBMBG5SibhLO81Z4voLzx9stz1zLcfoVIp64KLx0m7qc6Qnd1Clz/M
         lenZ7t5tI0BkXEzclQXQRn4/FNb8kO496TLPwXYUAOswny089BA7uSOtlBENE3Ye7a6e
         Cg4ckRDOfjdkcaLvSIVHOb2Xwvu+ZFuLqLwdW6neryR1rRG9I/CxLyQHUdmAJLmV24tv
         uCYlBlTM3uawnJKBdSDtVIdFL2qK6/7hRB91CNDpIqDe6zBujDRFyfIGHuGPACK1FR/G
         aF3SyevPsr9YjrcZIrBfpCUrYX4O6kcSH7BCaKf7GF64g9zLAyVH5Vrn0tS7Ug9yc8xz
         87Wg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=AglcDA0Ww2eObxw4xe94SE8GZXbibznXvQJZNsnalGo=;
        b=nO4YDIvzNh5oj9d1TJR64eu8HQZbHalk6Oc6G6tDA1DXs1CC+v7gEaaIpqdQT/NVJn
         19lpC6DaExYo5X9Mxh8oeXSOYPwDh+P1j8Rg8smtSqJvV6kK0C6lzk0dI7PE7WOpqRAy
         NNxRTvL4I0igFwQ1Obq2xJoI+Njkvs0MKkApBoYn50KI2emaJp7QCUasQM0W0TE/BAZ7
         Nm3GTv8A6RB5gJaDrouy5G4soAy3GeL6ouJRgw4XjEEgj+KYwlqdxMn5UjmjJE8MV4Bj
         RxqmSCK5UrhuvXyh1nrOIeSBWY73GGkBWlxlg6nHlrvhoakWQeUqA6+0HFErzhhQbvVm
         ONVw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=llqmXm0C;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::1029 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=AglcDA0Ww2eObxw4xe94SE8GZXbibznXvQJZNsnalGo=;
        b=Gbczz1pAVZPc02GaQCyCkfEogQDHPFInYgYjzB/AkDgElPFKyZEbW8AuNz+tBUHGf9
         BrQW+70Ej0fPOJMCNh4qnWj/OItQcr5E3/cXc9VbhwAlKXnfcpqlvbK68t7zrzDFhFxp
         pXxB+Gr0p078JbfrV6XqmC6zoObWYK5RZ4vKCg1e5xR6btHkq0cXf7//jMCSR0tmwHqk
         A0ZmvLaY3i436823BxMDqYet+Bmm3Pmy9b1jl0jv//3U+PJsq28sJ/0WGuveiQQiz+oS
         Klb2WPqYLyR4mbDWh6AuR8MqnZ+Q/PJ4fpUEgmeHRZ3SuMtJk9nvDcbjTh7aeDJaTCTs
         9y2g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=AglcDA0Ww2eObxw4xe94SE8GZXbibznXvQJZNsnalGo=;
        b=peX9H4oyf2vtVlyZvwrxlQObaDF4pO9ovQe8dly6I6EnX7vlDjMPG0tAqW1UECycuW
         nF5TmK2OqHqZoKkgMZk4OdP5esA55oi7YmbNPhca7hYoacvjHZlKcAtyqIb5sy30Up5G
         ldjTTRinzTNw0olvGqIJZqTri43d/y6leaZwEczsoK92jAUijg/dJjsugTBcDTqCxefr
         kGMs0yftVrz4HPKD9ANHTc81TlAtkeqEvJE2AgLKwUVjG0A4KRdhnXTsjJtJ0YHn39PN
         WSofxXy0dq7BlE9vfxSQj5KmEXDZpUnbovEzN7SBvthm07X+ORckfGjNg8Lpc4HAKYPJ
         35cg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf3Xf1zhVhJLoqt8aqRENWD7K90Hgl/cwAe1PlX2C5d8l+Hd9ouI
	mJks8nAziuwRl0DNOiLSJ7c=
X-Google-Smtp-Source: AMsMyM4PhmDa6+gZOpGh3/V1hc4b6z/DFQgwdpGN0pf3A7WEmhDttLJMP5m+Y6iiV4WV42SYmJs09g==
X-Received: by 2002:a05:6830:2709:b0:661:e648:2cee with SMTP id j9-20020a056830270900b00661e6482ceemr4520522otu.39.1666200675287;
        Wed, 19 Oct 2022 10:31:15 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:c282:0:b0:354:4a36:cf2d with SMTP id s124-20020acac282000000b003544a36cf2dls586264oif.10.-pod-prod-gmail;
 Wed, 19 Oct 2022 10:31:14 -0700 (PDT)
X-Received: by 2002:a17:90b:692:b0:203:6c21:b4aa with SMTP id m18-20020a17090b069200b002036c21b4aamr45346857pjz.227.1666200584866;
        Wed, 19 Oct 2022 10:29:44 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1666200584; cv=none;
        d=google.com; s=arc-20160816;
        b=IqgpTtDdgSEBZaNhCFmFKLAV4JWmpa9x3WDN6j2R2eBwESg5qd/RJhdqw1UPco1HQ1
         Ja2VqcyD9HfD0e/uonwqIdZMNqS12qlAJd6+A3tPKjFj44TKY9mT1+4qDE3cHx2+MpEx
         zZB9O9eiADpU0Ye5KE+c6ozEqwemfYOXhT6HRBRGacE97125EoacrhEvLIGTaO+HqodG
         8rHxzOcoC+6bzYidQI9bft1XTVeCZa3LypQa4gsVM/bxw9j4yY2cF4IxynWhAuojTl+m
         W1s1XOyvziAoElaXzksJ9gVG++4JgWVbRMreG71JCTceVJjrWtmtcq10hWXJsRtwkDqo
         /Piw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=GKQx/U9Oi8K1uuimUXOQCwOAtdhTQa9BCE+heeFHVSk=;
        b=k6k9EJyZdaAZjSQsiuzWFAsHIvPeNIwsuq8Alx6XUM8cmTjqwVFnpVvrezzXWGsfkP
         UfssGrRpPxxpE56/nMjDIvl/USFlcPpHNXeUo/VE13GlICWKuFru3k2/YogJMdSkWXmQ
         P7Kk0FDbpra36Oj+gDvt/O9coxD8eaO+aFeBrXBcFm0XSiSSfqnvb3rQ7n9RZfM3Itw0
         TAegRNebmaJ49baazekRMxfb5QcfomyJ8UYOU4Risqu7IcSlJyErzD3AgNDr3km93rPK
         teud8wmygEmlUPXRC9rvPqirUqB21oZHozNFtqmKvKJTuavddyC7gEJpIpC07Y5NttrY
         OeUg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=llqmXm0C;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::1029 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Received: from mail-pj1-x1029.google.com (mail-pj1-x1029.google.com. [2607:f8b0:4864:20::1029])
        by gmr-mx.google.com with ESMTPS id 77-20020a621450000000b00562bba09b90si611989pfu.0.2022.10.19.10.29.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 19 Oct 2022 10:29:44 -0700 (PDT)
Received-SPF: pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::1029 as permitted sender) client-ip=2607:f8b0:4864:20::1029;
Received: by mail-pj1-x1029.google.com with SMTP id o9-20020a17090a0a0900b0020ad4e758b3so618721pjo.4
        for <kasan-dev@googlegroups.com>; Wed, 19 Oct 2022 10:29:44 -0700 (PDT)
X-Received: by 2002:a17:903:2312:b0:185:43a2:3d0e with SMTP id d18-20020a170903231200b0018543a23d0emr9702582plh.118.1666200584506;
        Wed, 19 Oct 2022 10:29:44 -0700 (PDT)
Received: from www.outflux.net (smtp.outflux.net. [198.145.64.163])
        by smtp.gmail.com with ESMTPSA id y8-20020a17090a16c800b00205d85cfb30sm234077pje.20.2022.10.19.10.29.43
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 19 Oct 2022 10:29:43 -0700 (PDT)
Date: Wed, 19 Oct 2022 10:29:42 -0700
From: Kees Cook <keescook@chromium.org>
To: Alexander Potapenko <glider@google.com>
Cc: Nathan Chancellor <nathan@kernel.org>,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-hardening@vger.kernel.org, linux-kernel@vger.kernel.org,
	llvm@lists.linux.dev, kasan-dev@googlegroups.com,
	linux-mm@kvack.org
Subject: Re: -Wmacro-redefined in include/linux/fortify-string.h
Message-ID: <202210190930.26BF0CE2@keescook>
References: <Y1AZr01X1wvg5Klu@dev-arch.thelio-3990X>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <Y1AZr01X1wvg5Klu@dev-arch.thelio-3990X>
X-Original-Sender: keescook@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=llqmXm0C;       spf=pass
 (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::1029
 as permitted sender) smtp.mailfrom=keescook@chromium.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=chromium.org
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

On Wed, Oct 19, 2022 at 08:37:19AM -0700, Nathan Chancellor wrote:
> I am seeing the following set of warnings when building an x86_64
> configuration that has CONFIG_FORTIFY_SOURCE=y and CONFIG_KMSAN=y:
> 
>   In file included from scripts/mod/devicetable-offsets.c:3:
>   In file included from ./include/linux/mod_devicetable.h:13:
>   In file included from ./include/linux/uuid.h:12:
>   In file included from ./include/linux/string.h:253:
>   ./include/linux/fortify-string.h:496:9: error: 'memcpy' macro redefined [-Werror,-Wmacro-redefined]
>   #define memcpy(p, q, s)  __fortify_memcpy_chk(p, q, s,                  \
>           ^
>   ./arch/x86/include/asm/string_64.h:17:9: note: previous definition is here
>   #define memcpy __msan_memcpy
>           ^
>   In file included from scripts/mod/devicetable-offsets.c:3:
>   In file included from ./include/linux/mod_devicetable.h:13:
>   In file included from ./include/linux/uuid.h:12:
>   In file included from ./include/linux/string.h:253:
>   ./include/linux/fortify-string.h:500:9: error: 'memmove' macro redefined [-Werror,-Wmacro-redefined]
>   #define memmove(p, q, s)  __fortify_memcpy_chk(p, q, s,                 \
>           ^
>   ./arch/x86/include/asm/string_64.h:73:9: note: previous definition is here
>   #define memmove __msan_memmove
>           ^
>   2 errors generated.
> 
> I can see that commit ff901d80fff6 ("x86: kmsan: use __msan_ string
> functions where possible.") appears to include a fix up for this warning
> with memset() but not memcpy() or memmove(). If I apply a similar fix up
> like so:
> 
> diff --git a/include/linux/fortify-string.h b/include/linux/fortify-string.h
> index 4029fe368a4f..718ee17b31e3 100644
> --- a/include/linux/fortify-string.h
> +++ b/include/linux/fortify-string.h
> @@ -493,6 +493,7 @@ __FORTIFY_INLINE bool fortify_memcpy_chk(__kernel_size_t size,
>   * __struct_size() vs __member_size() must be captured here to avoid
>   * evaluating argument side-effects further into the macro layers.
>   */
> +#ifndef CONFIG_KMSAN
>  #define memcpy(p, q, s)  __fortify_memcpy_chk(p, q, s,			\
>  		__struct_size(p), __struct_size(q),			\
>  		__member_size(p), __member_size(q),			\
> @@ -501,6 +502,7 @@ __FORTIFY_INLINE bool fortify_memcpy_chk(__kernel_size_t size,
>  		__struct_size(p), __struct_size(q),			\
>  		__member_size(p), __member_size(q),			\
>  		memmove)
> +#endif
>  
>  extern void *__real_memscan(void *, int, __kernel_size_t) __RENAME(memscan);
>  __FORTIFY_INLINE void *memscan(void * const POS0 p, int c, __kernel_size_t size)
> 
> Then the instances of -Wmacro-redefined disappear but the fortify tests
> no longer pass for somewhat obvious reasons:
> 
>   warning: unsafe memcpy() usage lacked '__read_overflow2' symbol in lib/test_fortify/read_overflow2-memcpy.c
>   warning: unsafe memmove() usage lacked '__read_overflow2' symbol in lib/test_fortify/read_overflow2-memmove.c
>   warning: unsafe memcpy() usage lacked '__read_overflow2_field' symbol in lib/test_fortify/read_overflow2_field-memcpy.c
>   warning: unsafe memmove() usage lacked '__read_overflow2_field' symbol in lib/test_fortify/read_overflow2_field-memmove.c
>   warning: unsafe memcpy() usage lacked '__write_overflow' symbol in lib/test_fortify/write_overflow-memcpy.c
>   warning: unsafe memmove() usage lacked '__write_overflow' symbol in lib/test_fortify/write_overflow-memmove.c
>   warning: unsafe memset() usage lacked '__write_overflow' symbol in lib/test_fortify/write_overflow-memset.c
>   warning: unsafe memcpy() usage lacked '__write_overflow_field' symbol in lib/test_fortify/write_overflow_field-memcpy.c
>   warning: unsafe memmove() usage lacked '__write_overflow_field' symbol in lib/test_fortify/write_overflow_field-memmove.c
>   warning: unsafe memset() usage lacked '__write_overflow_field' symbol in lib/test_fortify/write_overflow_field-memset.c
> 
> Should CONFIG_KMSAN depend on CONFIG_FORTIFY_SOURCE=n like so? It seems
> like the two features are incompatible if I am reading ff901d80fff6
> correctly.
> 
> diff --git a/lib/Kconfig.kmsan b/lib/Kconfig.kmsan
> index b2489dd6503f..6a681621e3c5 100644
> --- a/lib/Kconfig.kmsan
> +++ b/lib/Kconfig.kmsan
> @@ -11,7 +11,7 @@ config HAVE_KMSAN_COMPILER
>  config KMSAN
>  	bool "KMSAN: detector of uninitialized values use"
>  	depends on HAVE_ARCH_KMSAN && HAVE_KMSAN_COMPILER
> -	depends on SLUB && DEBUG_KERNEL && !KASAN && !KCSAN
> +	depends on SLUB && DEBUG_KERNEL && !KASAN && !KCSAN && !FORTIFY_SOURCE
>  	select STACKDEPOT
>  	select STACKDEPOT_ALWAYS_INIT
>  	help
> 
> or is there a different obvious fix that I am missing?

Hm, why can't KMSAN use the same thing KASAN does, and compose correctly
with FORTIFY? (i.e. redefine the "__underlaying_mem*" macros?)

-- 
Kees Cook

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/202210190930.26BF0CE2%40keescook.
