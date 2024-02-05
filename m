Return-Path: <kasan-dev+bncBCSL7B6LWYHBB25UQOXAMGQE7UDCD2Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33e.google.com (mail-wm1-x33e.google.com [IPv6:2a00:1450:4864:20::33e])
	by mail.lfdr.de (Postfix) with ESMTPS id 5737E849B01
	for <lists+kasan-dev@lfdr.de>; Mon,  5 Feb 2024 13:54:04 +0100 (CET)
Received: by mail-wm1-x33e.google.com with SMTP id 5b1f17b1804b1-40f01cf71cesf25053775e9.1
        for <lists+kasan-dev@lfdr.de>; Mon, 05 Feb 2024 04:54:04 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1707137644; cv=pass;
        d=google.com; s=arc-20160816;
        b=mDl3sGvdBKIc8StoWgbPGGxivUBDdcnQwW6N2WP1r1yfrbNZ6z8l9IXiO+GlUML38O
         5WFolsoVz7suXbKwVVBOSAhiuEHvsSzY/KZTDAB+9ijUFx2SOaLqfoyRHC+ZPHbMlb5o
         lufGYHYUhjy9mPHc7vpYG4eR6IPf9gqDDaaMMaUZK98b+cZzA9t+pmd4khPpH3b6la0t
         AWhm1oqBFClvrc9NcJIkI8uqtsmGsAQhTDd6S3f4mdtB9kiSOLygs81RHVOkCdZlKzdG
         q53FtkFCCdTiIP9W+4S+lcHCXjp1GovKARxXdpkz7bwwydM7h+o54c2TyWdPN6djbYCk
         /w7w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature:dkim-signature;
        bh=d7RCnAM6x2Zj1G5mkqK+Kqyc2RWPkXHBZl+BHDt+5Cs=;
        fh=0WwQo7jFFs+6VTH/7PR5yzKNXPxF5sihxGvvLS9K1Dk=;
        b=jrI6kUBxoJBOAhrABpL/rWZF1Uk91tMjSjGmZ+P2SG96IM+OJkMrTc9PsJ25W6P3Yi
         dRH6UBgnJAMMFiEsG9H86hKRbjcgoPmuCM/MqFu05ti7UmoCVuGkwW3eAacfOscqdmxx
         GOd7DnIM2gPZdm2LK+1jtOfacp4zFJYWi74AhpNoOvqjYySLxZDjQmhxpVPKI31nFHeh
         keZjAfF4B0KvA5yID1KjaMqdHVw1N0giaM9Bfl+tQCdfxpEvLb/nNVOqKmgNEUDpV5wm
         54D6w84UlSHU+cnpmnC+AU2fHuIUX9DOC/zVWLhVD7z4uGXZ4V20T5Gbqa4GDxbRTUyG
         AecQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=llOcwTkx;
       spf=pass (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::135 as permitted sender) smtp.mailfrom=ryabinin.a.a@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1707137644; x=1707742444; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:content-language:references:cc
         :to:subject:user-agent:mime-version:date:message-id:sender:from:to
         :cc:subject:date:message-id:reply-to;
        bh=d7RCnAM6x2Zj1G5mkqK+Kqyc2RWPkXHBZl+BHDt+5Cs=;
        b=usTVNxrxgy74Ydkexs9t2IQ6kKM0h0Bl+MOHoiWAKOAGJ6PJKpUL/WpEuFMtYuyjkh
         Wr615v2ud+q6o8ukPZbSpxs+ScaIAjac586W7o3IKEBOL1zbPdwLBcgW+PS/4ahcJrcs
         +7D3vDmGaa21zACQs76WZXPDiYtnEOoKejjMMtA0t85vH/c1Kxl2LDqdH3QF5TDjImEC
         RaJYWOMZuAulhsWrNNT7mtioEgaqXmWoie90C9vTstX/LxyASnXLc2KVGQOsKslsspuG
         TbYX9Kp56Yd0jxqn+1ColBTpPwdMbrMCOp18xekrPRcz5bdDutDXwvsIYaBHyENRRvaz
         mDSg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1707137644; x=1707742444; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:content-language:references:cc
         :to:subject:user-agent:mime-version:date:message-id:from:to:cc
         :subject:date:message-id:reply-to;
        bh=d7RCnAM6x2Zj1G5mkqK+Kqyc2RWPkXHBZl+BHDt+5Cs=;
        b=fBKzsuHKA2aPuMgi4vPo9S0zHFtroUFwwSbkLLNyvCqOzr5Mqu4qv1dwKpO0Qm2n+l
         YUF04Jyi41ud7pZXUXEsi4tuylt+O7x4EshBPsOH3qHkVCWk1/pZmva/ppdmIh/g9QM/
         TzwO92WpSKvyy9ZCSv2SCyvs89kItY9AST08SpDF8EcyXbMHRuRNzugARhZJYmWxmXku
         2yBnMxKhCsKaudR+qcyH70RDYOECBvjdte4Z8L0GzghP80xbcGr3oILugxDLvTUvoJ9U
         PHUxxMnxo7vzM8xObvMjXYYsF+l6znxvEPDyn/NawMhOpa94xfNswuDKqF6yE6MtGQqj
         3OLw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1707137644; x=1707742444;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:content-language:references:cc:to:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=d7RCnAM6x2Zj1G5mkqK+Kqyc2RWPkXHBZl+BHDt+5Cs=;
        b=lOSo71+DSpdq25ZOVfAihm0fkkWwd9FpkYj5SktGJXDdBTjV+oxJ51PYaf45NxCoSu
         yDhjNjn+Nx6YpSYJrfvvLX5OY9fx0JTeu7MxLJ+8hN4i0WxMGPY8oF+62I9tPlw2pdMm
         UPAStGAsuih+tNTWEs20/wlEjUP3iFmTYoz/krz3XWLHwOUjG+/aQfXUfaR7E2NMqbtJ
         qmRRG8A7S7dKbrqf9cNhh2Zf8vu2xrQPCy6ZhA2Scp5AaCpLL+s82ih57rIzqnjsnuhX
         CDvXnjuHYCvdaGEtc/QfhSBF9uv8TcpCDor5Ym0VjTjD2PrlCpYACMR5Iwwapq/c4mOt
         YSjw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YxKRZZWtc/RhEgYr49a4Wt3a7b0lcWLLOUve+kZU/XFtOxQTAGW
	aQND+emjnE1vYPvHjenDMrEbGY7UovXwCF7mLY7Lxqa6e4Hn9qQ/
X-Google-Smtp-Source: AGHT+IF7KZpRpYmwEzbJ5HOPbC1MgS1cBppT49paOhkJ9nWZqjRBm/BKyxk2gd6q4ArdXB+AyQsywg==
X-Received: by 2002:a05:600c:4f52:b0:40d:3fee:97f6 with SMTP id m18-20020a05600c4f5200b0040d3fee97f6mr4400472wmq.34.1707137643403;
        Mon, 05 Feb 2024 04:54:03 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:511d:b0:40d:6f01:c37e with SMTP id
 o29-20020a05600c511d00b0040d6f01c37els2061375wms.2.-pod-prod-06-eu; Mon, 05
 Feb 2024 04:54:01 -0800 (PST)
X-Received: by 2002:a7b:cd85:0:b0:40e:fa6b:f355 with SMTP id y5-20020a7bcd85000000b0040efa6bf355mr4643691wmj.41.1707137641527;
        Mon, 05 Feb 2024 04:54:01 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1707137641; cv=none;
        d=google.com; s=arc-20160816;
        b=aTji779BWdNehcQR+65D+/jLfboMSmm2QR1McGZZYbo9tw/3uHfyI3O3fZK/ujtY1z
         ceWKDxWPjNuMQPZkxu8y4NeZ38ghr2EJlh5XLeEJZzdjogRbjjiRR23BVZul8IKKo2yU
         DX9y1oKLZLe0IbBllffRPnE7X13OGek4E/z9BXbVn3Vd7oGGrLPNKhs0GIL5ESE6edgA
         uowLM2fAGK/rtxRidpdWwSjTGsDtFpZXCPnI6W4ifhAlYMdhgUR4AMTYu9lUrXlXGdGB
         ze7clmJtgiTdl7e1m4VQ85hG5fO5huHPjx0yHXEYfiTkzSuY+Qql+HoMmbtMlmek/xlY
         HZsA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=14UfJITL0dkLd5SyibepbNnNaR97wsfScRKTGspT4eo=;
        fh=0WwQo7jFFs+6VTH/7PR5yzKNXPxF5sihxGvvLS9K1Dk=;
        b=C4j3D3hf+gJFXCQSCvVeb8SwhbV8GE+zp9YyGIV35ii+7ZwpXQIOswGcz1yvtOy8HY
         RwphO5RI1/t7tAs1tADmtF66K694VpAj250QDlYvJXGBIX5WPS+AkCx/UwDRzINgWnF8
         1LOimLs+nC6lsq5p9M0t6zh4/Rz00F0cII4Iz/9/6mNnrvKmAycnyAm7Y+VZH5hTUjJl
         8jgr3bj2PoPwkFKHz5GYMOAnkScthLhoOHoR3YY7hgySOG8p3nuIRBq5v+nlENZjTj6A
         efO2pmIRtkG0/Xe1DlVR1uaXiHWQ7XxJVSkQQ50+UCpsLqwmHlbbFwzmqNwjGs0vMXnJ
         3qgQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=llOcwTkx;
       spf=pass (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::135 as permitted sender) smtp.mailfrom=ryabinin.a.a@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
X-Forwarded-Encrypted: i=0; AJvYcCVQICSH7nASEHmvE5U5eUX5mC7RPF/NEtaznfHJX2OETBE3WJfesUMIAZZ38nMBhOjjv548MPNSzSkkNz7X+THcAbuuJ0Vi7ESYiA==
Received: from mail-lf1-x135.google.com (mail-lf1-x135.google.com. [2a00:1450:4864:20::135])
        by gmr-mx.google.com with ESMTPS id o25-20020a05600c511900b0040fd31815f3si157688wms.0.2024.02.05.04.54.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 05 Feb 2024 04:54:01 -0800 (PST)
Received-SPF: pass (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::135 as permitted sender) client-ip=2a00:1450:4864:20::135;
Received: by mail-lf1-x135.google.com with SMTP id 2adb3069b0e04-51124d43943so6875390e87.2
        for <kasan-dev@googlegroups.com>; Mon, 05 Feb 2024 04:54:01 -0800 (PST)
X-Received: by 2002:ac2:4837:0:b0:511:53c6:2d with SMTP id 23-20020ac24837000000b0051153c6002dmr820067lft.46.1707137640551;
        Mon, 05 Feb 2024 04:54:00 -0800 (PST)
X-Forwarded-Encrypted: i=0; AJvYcCVUOahf5fd4pgIFmBCGkSP9TbLXOsKXAPzRLRivxXn//rhvweVuzFaDJ69xc7kbw+FUKoSpgmwG4aaUPFlpq7i/w2y3x5XHlAXboKgAe+bCWEuoT1B07kP0HmIZyjQzxaiZsSqdGUHspZlgw/Li0Fwn3HjboC60MEQ6wersRVUa8UlLZbTMP3U820JjCd+Q6+koSANQ3XceUCzFMYnhYbe5KLNRf9tyCUykZal6B0K3E20u+Ii5nWPoeB4Wuf0zIIX7krLC/sokKHCDUz/tChepB5C0U3TssT2luDxlm8lSQRDx2R43noYFIvhibezzRs8F3i235b4cJjKwRr0A6YB2F1Xh1bBOLR88ajJEbiZEJx7kyila69E1SoVMBAg4I251at2/KBtLkRjifszg7gnX8PssSnDKlelEvq+WseDxs3Kbgijx3E58G/TKsogl4DR6p2e16zhQK4FN80ZdpWPnsUQmRZL9RWMOm6QY4ASIbA8J4LvAuEyJTPnAWbws3yY2Az35zeUq8TsurKhu+BbiNeIV2h689CmWyRPVPG0=
Received: from ?IPV6:2a02:6b8:83:1506:8b8c:af7e:d3ba:a153? ([2a02:6b8:83:1506:8b8c:af7e:d3ba:a153])
        by smtp.gmail.com with ESMTPSA id i11-20020a056512318b00b00511525b9d57sm230097lfe.43.2024.02.05.04.53.57
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 05 Feb 2024 04:54:00 -0800 (PST)
Message-ID: <67a842ad-b900-4c63-afcb-63455934f727@gmail.com>
Date: Mon, 5 Feb 2024 13:54:24 +0100
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v3] ubsan: Reintroduce signed overflow sanitizer
To: Kees Cook <keescook@chromium.org>, Justin Stitt <justinstitt@google.com>
Cc: Marco Elver <elver@google.com>, Miguel Ojeda <ojeda@kernel.org>,
 Nathan Chancellor <nathan@kernel.org>, Peter Zijlstra
 <peterz@infradead.org>, Hao Luo <haoluo@google.com>,
 Andrey Konovalov <andreyknvl@gmail.com>,
 Andrew Morton <akpm@linux-foundation.org>,
 Masahiro Yamada <masahiroy@kernel.org>, Nicolas Schier <nicolas@fjasle.eu>,
 Nick Desaulniers <ndesaulniers@google.com>,
 Przemek Kitszel <przemyslaw.kitszel@intel.com>,
 linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com,
 linux-hardening@vger.kernel.org, linux-kbuild@vger.kernel.org
References: <20240205093725.make.582-kees@kernel.org>
Content-Language: en-US
From: Andrey Ryabinin <ryabinin.a.a@gmail.com>
In-Reply-To: <20240205093725.make.582-kees@kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: Ryabinin.A.A@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=llOcwTkx;       spf=pass
 (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::135
 as permitted sender) smtp.mailfrom=ryabinin.a.a@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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



On 2/5/24 10:37, Kees Cook wrote:

> ---
>  include/linux/compiler_types.h |  9 ++++-
>  lib/Kconfig.ubsan              | 14 +++++++
>  lib/test_ubsan.c               | 37 ++++++++++++++++++
>  lib/ubsan.c                    | 68 ++++++++++++++++++++++++++++++++++
>  lib/ubsan.h                    |  4 ++
>  scripts/Makefile.lib           |  3 ++
>  scripts/Makefile.ubsan         |  3 ++
>  7 files changed, 137 insertions(+), 1 deletion(-)
> 
> diff --git a/include/linux/compiler_types.h b/include/linux/compiler_types.h
> index 6f1ca49306d2..ee9d272008a5 100644
> --- a/include/linux/compiler_types.h
> +++ b/include/linux/compiler_types.h
> @@ -282,11 +282,18 @@ struct ftrace_likely_data {
>  #define __no_sanitize_or_inline __always_inline
>  #endif
>  
> +/* Do not trap wrapping arithmetic within an annotated function. */
> +#ifdef CONFIG_UBSAN_SIGNED_WRAP
> +# define __signed_wrap __attribute__((no_sanitize("signed-integer-overflow")))
> +#else
> +# define __signed_wrap
> +#endif
> +
>  /* Section for code which can't be instrumented at all */
>  #define __noinstr_section(section)					\
>  	noinline notrace __attribute((__section__(section)))		\
>  	__no_kcsan __no_sanitize_address __no_profile __no_sanitize_coverage \
> -	__no_sanitize_memory
> +	__no_sanitize_memory __signed_wrap
>  

Given this disables all kinds of code instrumentations,
shouldn't we just add __no_sanitize_undefined here?

I suspect that ubsan's instrumentation usually doesn't cause problems
because it calls __ubsan_* functions with all heavy stuff (printk, locks etc)
only if code has an UB. So the answer to the question above depends on
whether we want to ignore UBs in "noinstr" code or to get some weird side effect,
possibly without proper UBSAN report in dmesg.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/67a842ad-b900-4c63-afcb-63455934f727%40gmail.com.
