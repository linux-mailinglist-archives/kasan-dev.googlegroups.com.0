Return-Path: <kasan-dev+bncBC7OBJGL2MHBBJEOQKQAMGQEHQMXMPI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23a.google.com (mail-oi1-x23a.google.com [IPv6:2607:f8b0:4864:20::23a])
	by mail.lfdr.de (Postfix) with ESMTPS id 428336A80F1
	for <lists+kasan-dev@lfdr.de>; Thu,  2 Mar 2023 12:23:18 +0100 (CET)
Received: by mail-oi1-x23a.google.com with SMTP id bl22-20020a056808309600b00383eaea7c2esf5648194oib.16
        for <lists+kasan-dev@lfdr.de>; Thu, 02 Mar 2023 03:23:18 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1677756196; cv=pass;
        d=google.com; s=arc-20160816;
        b=KI0WhsInqj1e4MGQnuRbQ3Xjr/e5vji3LvpPU4u1b8DGx0Q1/hORGiwp+TUV6mxetm
         Bi9CoUUGFR3yNMp4gDS7hd9aQvmpAwjLebSy3avmWJnf4uZ/eUpz5ycLMupjQwI/lodA
         Wd/PA7gIQEz+i2Lmarp6DxuIs+PJWRrBQL4k8hOgUeCgpsJybgOTdKBCatrmlGJEuP4I
         4M50prjl/w4wMoEmZ/I/c0RN0iNOD6VovM/ePdHu9bh6SVYZ0ltIL0IcUyiG5YYKIxhv
         2BwPdbJliLHZxpfKtciIy5cZXinOrTrdLi3P4JDxdySopHhNumM9RWxOmyzXiUHspBEe
         5PeA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=Hbv3/4R9ZKmJ5Gds/3yZ4tkcVW3ntOs+B/N6WbVNLac=;
        b=TZr1TJ2FxfvwbcRABn5q3GtsF8ULZjdhklfhu0ixnIunlWQgUcvD6AMvIIgKnwsrvu
         NWHjZfTO+rNvzTEMo6DGrrgSH8Zy6fU0CJzoVLdclBVJplrawo8OJ4PFuXOrnkvOdevZ
         GygB7TLjajcLF42STezgpu3fKunNum3Gvhmn5bD5WxWysvTgaHjf8nfGrp5zuWHwAv1s
         KARE22Jd4jqwsAc8/ch0HFYO3WP+CetJz4YFxI+a7u5r/iH0QF8SeiKWxplirnjyjp+2
         O+lYu8U0RT28GfC8S+tROZl0f09xopBC85eCMrHvqbSzuo6F6tf8n2s3puz3K3j/BwPn
         Rdew==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=PIN9Xd0B;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::e31 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=Hbv3/4R9ZKmJ5Gds/3yZ4tkcVW3ntOs+B/N6WbVNLac=;
        b=QmF6PUrnP1Iahfu27B6dbniQmCgyWsD3v+MDIJp4CGVKQSue5nUc8/4onrC44cDlcH
         wWLaeB6JEev0ByWB8cBew/rsAvdLsGwzu6Bhe/vC1vIuIMxfcTFWmlP5bExOT0aE5EBm
         2ZgVhdFnSRG27DYlQGtup6PeJG6PE+3lBA2EEX7K2aU63k85jrTt5mdXjDyRWdFluKiS
         +ZvxMpC/76OueQpxRUceXC3YGLcXXCAO8bGMX3qsx7Cj//zblhilGBs0pa451FuSa/Ir
         CWwVszDeB0xRRHoJv5wtyVWmTW3287CHIAQsTZr+m7PZoha0Ygrxlhmk2mAVY5BFQm1M
         rcwA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=Hbv3/4R9ZKmJ5Gds/3yZ4tkcVW3ntOs+B/N6WbVNLac=;
        b=FbMia5VT4JJo4vnt0vMkO7SOCdGY/McE2CwLvqGAhm856qHryORoqxn9+BEQj9ywvx
         feI3wythcGK3iAenJa1siwz4GiU2ATnPE9yNcS5pmDFWKAZrcUdx0jDSJKpaQtgyrm7k
         nS9WapduPcS6LKdAwZmaplqq7RKQKsfqlAGuvsA5HsXUE4nWPEb8HmKJ5muT48RaRnLL
         g48hoetJWV2/wbDtAU/+RnBIwUJjVRp00PjunzoUhkDhIxJuO1CaZ9zBREMC6RtZGe0h
         8+ZV9XG3JCa4H1fAgeGL+jZWNdQX81ACfD+u21/M2cbllT8VcsC6FeH+ilKWCmA57IIa
         7tGg==
X-Gm-Message-State: AO0yUKUy8lp69Xr8UD5E+2U9KVCMsuGUF9c2pG3Bv8vjm8Tc1EOk4csz
	MxTT0c4kgJhHju8xPbLTZxw=
X-Google-Smtp-Source: AK7set+xRB0Cf4D48TruzfcVIpDLAwtsopYigenL7A5BFjqwFC6I+AHFvxm8YG75Y24TOOtArGdfxQ==
X-Received: by 2002:a05:6808:a98:b0:384:21e7:977c with SMTP id q24-20020a0568080a9800b0038421e7977cmr2862437oij.8.1677756196577;
        Thu, 02 Mar 2023 03:23:16 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:4413:b0:176:30d5:30b9 with SMTP id
 u19-20020a056870441300b0017630d530b9ls1594982oah.9.-pod-prod-gmail; Thu, 02
 Mar 2023 03:23:16 -0800 (PST)
X-Received: by 2002:a05:6870:1603:b0:176:34a4:d908 with SMTP id b3-20020a056870160300b0017634a4d908mr2743662oae.51.1677756196147;
        Thu, 02 Mar 2023 03:23:16 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1677756196; cv=none;
        d=google.com; s=arc-20160816;
        b=ZHIzAAs8NGzN7mwGnEbg7LYToofvFAJy/D1HT2jAZWWp0bR2/ggC+UA5tGwD3c+FD7
         xhyNF3FGwEBaGLZmKsly4EGi+0f5zKznpbA5kSgDwqucgjsG7q8DoJ8cO89RKUokaSz9
         fNUYEzvS6B+ZRST1DXCCiyBCgsJ5go77WsDbdiUgBeMVww9firbMSWfmfYJ2QDsxdV9e
         5s7TD1j9rCfRbOuhWbAlV8LQwfzU6F4yqj6JIpIT/pDLv+74K6DC7CfwoEtibgWq2Lfs
         LMZ+ylg7DHY3U6I9S0yYVP6IimUpThnNZmjhKKW4mrxhkkeaEp7hFowkNrABsgiR9WN+
         Oipg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=ZXJcpekVJsbf05nQkG74Sggw1Qq7M2Hhxe/99xjhW+0=;
        b=Aq6Z29J+y2r/+rX8mPXBC3ofEWi0jxsnUs9T1+oO7fy+QmwDmhfoO/O3yRmcUOMXZD
         Ccz5iBGl13jnclWo6cKARVKc8sd7zN/6t/ciub4bQuRBo3S5H9TKlodM7+BLOvrshHuF
         /7msAXGkYxwC/TTSPqtTSCcJRvjfSQbJMwlVqhd33/JE956GSZr9WgsU3+hOVSforSdQ
         kiQ5ugaHkov0YU53O3J26WIrLS+bPQOgzj8cGrVD0ND7D1dUF4ldwKOmeSaskzZqBx+3
         7QdzFYpHXDsqZLGMcsSEMPGWhXz9Q0gHhySlDolTt5LMEWyr0m75Z4KaG09jSyguSiHk
         u5tQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=PIN9Xd0B;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::e31 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-vs1-xe31.google.com (mail-vs1-xe31.google.com. [2607:f8b0:4864:20::e31])
        by gmr-mx.google.com with ESMTPS id nx12-20020a056870be8c00b001723959e146si933621oab.4.2023.03.02.03.23.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 02 Mar 2023 03:23:16 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::e31 as permitted sender) client-ip=2607:f8b0:4864:20::e31;
Received: by mail-vs1-xe31.google.com with SMTP id by13so4567160vsb.3
        for <kasan-dev@googlegroups.com>; Thu, 02 Mar 2023 03:23:16 -0800 (PST)
X-Received: by 2002:a05:6102:10c5:b0:412:6a3:2276 with SMTP id
 t5-20020a05610210c500b0041206a32276mr6437205vsr.4.1677756195604; Thu, 02 Mar
 2023 03:23:15 -0800 (PST)
MIME-Version: 1.0
References: <20230301143933.2374658-1-glider@google.com> <20230301143933.2374658-4-glider@google.com>
In-Reply-To: <20230301143933.2374658-4-glider@google.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 2 Mar 2023 12:22:39 +0100
Message-ID: <CANpmjNO0GBpfRbT1YnNnoupVG7TOcuBbTHzxNyZwdJaH3W7w5g@mail.gmail.com>
Subject: Re: [PATCH 4/4] kmsan: add memsetXX tests
To: Alexander Potapenko <glider@google.com>
Cc: linux-kernel@vger.kernel.org, linux-mm@kvack.org, tglx@linutronix.de, 
	mingo@redhat.com, bp@alien8.de, x86@kernel.org, dave.hansen@linux.intel.com, 
	hpa@zytor.com, akpm@linux-foundation.org, dvyukov@google.com, 
	nathan@kernel.org, ndesaulniers@google.com, kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=PIN9Xd0B;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::e31 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

On Wed, 1 Mar 2023 at 15:39, Alexander Potapenko <glider@google.com> wrote:
>
> Add tests ensuring that memset16()/memset32()/memset64() are
> instrumented by KMSAN and correctly initialize the memory.
>
> Signed-off-by: Alexander Potapenko <glider@google.com>
> ---
>  mm/kmsan/kmsan_test.c | 22 ++++++++++++++++++++++
>  1 file changed, 22 insertions(+)
>
> diff --git a/mm/kmsan/kmsan_test.c b/mm/kmsan/kmsan_test.c
> index cc98a3f4e0899..e450a000441fb 100644
> --- a/mm/kmsan/kmsan_test.c
> +++ b/mm/kmsan/kmsan_test.c
> @@ -503,6 +503,25 @@ static void test_memcpy_aligned_to_unaligned2(struct kunit *test)
>         KUNIT_EXPECT_TRUE(test, report_matches(&expect));
>  }
>
> +/* Generate test cases for memset16(), memset32(), memset64(). */
> +#define DEFINE_TEST_MEMSETXX(size, var_ty)                                  \
> +       static void test_memset##size(struct kunit *test)                   \
> +       {                                                                   \
> +               EXPECTATION_NO_REPORT(expect);                              \
> +               volatile var_ty uninit;                                     \

This could just be 'uint##size##_t' and you can drop 'var_ty'.

> +                                                                            \
> +               kunit_info(test,                                            \
> +                          "memset" #size "() should initialize memory\n"); \
> +               DO_NOT_OPTIMIZE(uninit);                                    \
> +               memset##size((var_ty *)&uninit, 0, 1);                      \
> +               kmsan_check_memory((void *)&uninit, sizeof(uninit));        \
> +               KUNIT_EXPECT_TRUE(test, report_matches(&expect));           \
> +       }
> +
> +DEFINE_TEST_MEMSETXX(16, uint16_t)
> +DEFINE_TEST_MEMSETXX(32, uint32_t)
> +DEFINE_TEST_MEMSETXX(64, uint64_t)
> +
>  static noinline void fibonacci(int *array, int size, int start)
>  {
>         if (start < 2 || (start == size))
> @@ -549,6 +568,9 @@ static struct kunit_case kmsan_test_cases[] = {
>         KUNIT_CASE(test_memcpy_aligned_to_aligned),
>         KUNIT_CASE(test_memcpy_aligned_to_unaligned),
>         KUNIT_CASE(test_memcpy_aligned_to_unaligned2),
> +       KUNIT_CASE(test_memset16),
> +       KUNIT_CASE(test_memset32),
> +       KUNIT_CASE(test_memset64),
>         KUNIT_CASE(test_long_origin_chain),
>         {},
>  };
> --
> 2.39.2.722.g9855ee24e9-goog
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNO0GBpfRbT1YnNnoupVG7TOcuBbTHzxNyZwdJaH3W7w5g%40mail.gmail.com.
