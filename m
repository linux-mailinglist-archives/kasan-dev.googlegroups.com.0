Return-Path: <kasan-dev+bncBDW2JDUY5AORB7F7XWPQMGQEEAH5ECI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43c.google.com (mail-pf1-x43c.google.com [IPv6:2607:f8b0:4864:20::43c])
	by mail.lfdr.de (Postfix) with ESMTPS id 4084869A9BD
	for <lists+kasan-dev@lfdr.de>; Fri, 17 Feb 2023 12:07:42 +0100 (CET)
Received: by mail-pf1-x43c.google.com with SMTP id h25-20020a62b419000000b005a8da78efedsf391481pfn.2
        for <lists+kasan-dev@lfdr.de>; Fri, 17 Feb 2023 03:07:42 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1676632061; cv=pass;
        d=google.com; s=arc-20160816;
        b=b1s8O5wizwHaoWrCJEspAZEF1W4k/SlHA97ZVR9Fq5Jq07A0VJlPVucM2ffzig7lfv
         hfl8MI9BlG8LhDoMAftmxTsfmUtDtvWzIiN6jsKyvDZ5X1RUfhF5Z205dNOzGyD8P2Vj
         otMyue8JaENWq8pkFffF2QLhU3f8F+Iad4/mwb1tTWkiyAyEbVUctTHWZDHbtA3Pa48P
         ExypiTp7kVGd2gCa7V1PiQrGBpfDYTnhlwJu/ZPXysf9BAy/2bI32NKhisl6INBM2Ogz
         ofKDI+/5AnH1WAGE8nNXAas2jlem1yop1yppFSKZ9ys06RL2rnUlWqNZq1dr3rjw48Xx
         ay4w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=3NBXz1rfjugSlR98tLVKJCKhKMj12ABo+d2li7/omWM=;
        b=Qp/vLwtEBETJPNYgLajOS+N1RWtCmhZwYzy/Q1qOedOYL5o5PlCtZ6xB3RDtTZFg09
         WOp3LNclaEl8nYP3A3cUolHaf+X0rhZOoGU1xPPlKGtx9ODRO9kWyY8kkykDG6tPL3Ew
         QsI6UlCISQhBCLR8GAE9e4421ByjAnbngjpBoYISsdoQxtO/QajUFtFq1uF/Gakxuh+H
         XqYGnOw8ewI2MMlbkwWhe4Bn58zzBMxDljKz/cHer/UctYqzPTX0HUWUSV/fV9nAYF6H
         Z7u849MCH7yft7IkE5LSUQxkz/eRQaKVQr6o7ZukZjRkwgLao7zFnIlDiZGpCHOFcCSL
         SNFA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=G5719LGs;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::433 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:in-reply-to
         :references:mime-version:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=3NBXz1rfjugSlR98tLVKJCKhKMj12ABo+d2li7/omWM=;
        b=MaHKIzxBWeyj3wlMODRvFcI+2oMQd6hK5/sn6qb1TktRGk98k6mgzLX3UPrsj6PXQi
         tdnFIAHw4CHJdCb13oB960Pv0uEENySL/dGbULryIwpXywRv8x1sGY5hz9krvDh+um3c
         oDTCStDcTmWSqVP+bNa9nnmMaeigLPSm+sCUZFzxgcUEZlOmH9KKIsAlIyl1y9p6YzdE
         xo5GDlod1Bb9HNcIpkU1e97tBV5ypgGWVfJFB0UBr3KbZDqAP+fRO58P9dmiA78CPGq0
         l4a5IUDdQ/10ilNZVDM9SkxjKeuN1IlGWPLY/WINmBAEPkVYnTUr8T39VLyztd3jpgi9
         wAUQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:in-reply-to
         :references:mime-version:from:to:cc:subject:date:message-id:reply-to;
        bh=3NBXz1rfjugSlR98tLVKJCKhKMj12ABo+d2li7/omWM=;
        b=MgnFwXtaNorgx+MrLgKK1majv2pmhxtwPFhdaBaCHf0ojpLoLl8hV05n+yvNAP2bQ6
         uP3RN/EUbzUKhqhPkq1TVSY347e84UE8HC2KKO9rCABRJ7HgHgz4bHYnAksCwJItLdan
         pcJ+29RLkFz3hBz2vASfNdJ8hCJDRKy0IHPsySGwI2xvcmx+n52Jw43c61gLnGI6EMw2
         4hniPKAHTiOJwE30TPOEWu2jasNwOCvJbeHen5dkSjaUgU+TIfCthHJnBwqpTmceV5QF
         Pd8pjM3q0Qv4K22Qs35khvwSIsoLcmlzKTOEY/GsBIdDNl8T30U+p/3imGgEO1XO17BT
         Ad6A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=3NBXz1rfjugSlR98tLVKJCKhKMj12ABo+d2li7/omWM=;
        b=L/cf965/sLRzyyz9aBRdS8kEvZwvgO37G4IgjdwyqELKHqH4UQKbC4sdzS4sojdmsY
         6L2LeJfOhW15+hAU8al5xQ8We5jslsV9+7aSKckKUqdVcEu8dEWrn16i/7FMes/JNu86
         prt1DtT5WZLdGx9tN+F2snCKMDxLiVgtzZ8pV9aDefFMPvfdehpyjzi9lgulCVi3mPY0
         hLMHZ1ZYQeEaq8uFngOP1r3PVnoZkcVunVIC5XU7X97F+jeo2DFzNUyKTtE6sZYJQLrh
         KpkDZ4LN/+qt/cYLDKbvLFG0yzqkq0dOVe86c6u0NWeMI/rYH9/jfnF7LO7yBFnoGCgD
         Pb8Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKXiXAtczx2XwsxS6L6K/dXuujgCERraJLzvKqgu/Ee4ztbS/5Cm
	hDJvSMb11WcxmfMthabT87I=
X-Google-Smtp-Source: AK7set+mZbatJ299rD9ERydrjAC8RnMbXAVAVbiyVk5JiMQJLJ3SExQFEgrkKHge1upZpiNQlQOmNg==
X-Received: by 2002:a17:90b:3ecb:b0:230:8de1:2108 with SMTP id rm11-20020a17090b3ecb00b002308de12108mr1341588pjb.110.1676632060767;
        Fri, 17 Feb 2023 03:07:40 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:e84c:b0:198:ddfb:494 with SMTP id
 t12-20020a170902e84c00b00198ddfb0494ls1145769plg.8.-pod-prod-gmail; Fri, 17
 Feb 2023 03:07:40 -0800 (PST)
X-Received: by 2002:a17:90b:4a11:b0:234:41c:74cc with SMTP id kk17-20020a17090b4a1100b00234041c74ccmr10147913pjb.42.1676632060031;
        Fri, 17 Feb 2023 03:07:40 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1676632060; cv=none;
        d=google.com; s=arc-20160816;
        b=Q/ax/ddCYofj4xQ0XU3SkR/RyFvPUyC83ivZGaqExde4Ha46aacEEJVuXdthbLpEbi
         EkQIIhihmTKrSFY0G1kfuHrtvUAos0jzttpy1P8+nrFtMCjueBuHIvLbGlTK2gBKG18O
         7UY0uS+tHxU9Y1YCt9gOe7gF3M6x5g2xlQUI46FUaGHFRWw3wkPUmTsWwzZqAWnm1q0X
         s043j/KbKNBbajumY8E/kQViYUzgEh3if+IDqh3mz8xyWlWm5klr07TmxwCgQATdZmNz
         fxl9PVD88xg/7T2m19Pf/yOeBKgbcet5eTeEF+1PDqRJTqXdoR2b58MbeEoignQSnLBF
         syFQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=F6OARyIkWKx6vJWW66deXzKz0d7MrJOxrFV4HQAbnVY=;
        b=S7e/yJBwo6s+fXdby8B3X3xmswghEzGonnNeXsjQy+tgwGXqcIMYe1JqvXMNi7MCFF
         S0fNiffRIK92+zza03crTMZ94xDbOa6iOwasF/VgjxhSS3IMDem5G6JRma/L58uMqWdn
         qMsyklAXnFY+u7DWPL+udpmWMuw7bfyjkjJSVS8vjYEkfwCBIz2hFRl6zgBAkPtA3rX/
         qYAG/cwKvrOtid5EIZbvqlxmIGSpcNKLGRp08QQetaGFotz/zt7OQBJ2K50OYQcIQ2GK
         3SaiQjbaV/ZSQJrERzIvlod90lL6r7fpen1rG/pFBOJ6LbAogdNVVLCIDaAMoLTdD/If
         Qw5Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=G5719LGs;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::433 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pf1-x433.google.com (mail-pf1-x433.google.com. [2607:f8b0:4864:20::433])
        by gmr-mx.google.com with ESMTPS id t10-20020a63dd0a000000b004a3ed20c3c0si238175pgg.3.2023.02.17.03.07.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 17 Feb 2023 03:07:40 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::433 as permitted sender) client-ip=2607:f8b0:4864:20::433;
Received: by mail-pf1-x433.google.com with SMTP id o5so518139pfw.10
        for <kasan-dev@googlegroups.com>; Fri, 17 Feb 2023 03:07:40 -0800 (PST)
X-Received: by 2002:a62:8282:0:b0:5a9:c954:563e with SMTP id
 w124-20020a628282000000b005a9c954563emr240181pfd.6.1676632059648; Fri, 17 Feb
 2023 03:07:39 -0800 (PST)
MIME-Version: 1.0
References: <20230216234522.3757369-1-elver@google.com> <20230216234522.3757369-3-elver@google.com>
In-Reply-To: <20230216234522.3757369-3-elver@google.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Fri, 17 Feb 2023 12:07:28 +0100
Message-ID: <CA+fCnZdsiWjpp9qjsy16SSuOcaOgnk2h6vC+dq6h8GUrqdF1bw@mail.gmail.com>
Subject: Re: [PATCH -tip v4 3/3] kasan: test: Fix test for new meminstrinsic instrumentation
To: Marco Elver <elver@google.com>
Cc: Peter Zijlstra <peterz@infradead.org>, Ingo Molnar <mingo@kernel.org>, 
	Jakub Jelinek <jakub@redhat.com>, linux-toolchains@vger.kernel.org, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Nathan Chancellor <nathan@kernel.org>, Nick Desaulniers <ndesaulniers@google.com>, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, 
	linux-kbuild@vger.kernel.org, 
	Linux Kernel Functional Testing <lkft@linaro.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=G5719LGs;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::433
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
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

On Fri, Feb 17, 2023 at 12:45 AM Marco Elver <elver@google.com> wrote:
>
> The tests for memset/memmove have been failing since they haven't been
> instrumented in 69d4c0d32186.
>
> Fix the test to recognize when memintrinsics aren't instrumented, and
> skip test cases accordingly. We also need to conditionally pass
> -fno-builtin to the test, otherwise the instrumentation pass won't
> recognize memintrinsics and end up not instrumenting them either.
>
> Fixes: 69d4c0d32186 ("entry, kasan, x86: Disallow overriding mem*() functions")
> Reported-by: Linux Kernel Functional Testing <lkft@linaro.org>
> Signed-off-by: Marco Elver <elver@google.com>
> ---
> v4:
> * New patch.
> ---
>  mm/kasan/Makefile     |  9 ++++++++-
>  mm/kasan/kasan_test.c | 29 +++++++++++++++++++++++++++++
>  2 files changed, 37 insertions(+), 1 deletion(-)
>
> diff --git a/mm/kasan/Makefile b/mm/kasan/Makefile
> index d4837bff3b60..7634dd2a6128 100644
> --- a/mm/kasan/Makefile
> +++ b/mm/kasan/Makefile
> @@ -35,7 +35,14 @@ CFLAGS_shadow.o := $(CC_FLAGS_KASAN_RUNTIME)
>  CFLAGS_hw_tags.o := $(CC_FLAGS_KASAN_RUNTIME)
>  CFLAGS_sw_tags.o := $(CC_FLAGS_KASAN_RUNTIME)
>
> -CFLAGS_KASAN_TEST := $(CFLAGS_KASAN) -fno-builtin $(call cc-disable-warning, vla)
> +CFLAGS_KASAN_TEST := $(CFLAGS_KASAN) $(call cc-disable-warning, vla)
> +ifndef CONFIG_CC_HAS_KASAN_MEMINTRINSIC_PREFIX
> +# If compiler instruments memintrinsics by prefixing them with __asan/__hwasan,
> +# we need to treat them normally (as builtins), otherwise the compiler won't
> +# recognize them as instrumentable. If it doesn't instrument them, we need to
> +# pass -fno-builtin, so the compiler doesn't inline them.
> +CFLAGS_KASAN_TEST += -fno-builtin
> +endif
>
>  CFLAGS_kasan_test.o := $(CFLAGS_KASAN_TEST)
>  CFLAGS_kasan_test_module.o := $(CFLAGS_KASAN_TEST)
> diff --git a/mm/kasan/kasan_test.c b/mm/kasan/kasan_test.c
> index 74cd80c12b25..627eaf1ee1db 100644
> --- a/mm/kasan/kasan_test.c
> +++ b/mm/kasan/kasan_test.c
> @@ -165,6 +165,15 @@ static void kasan_test_exit(struct kunit *test)
>                 kunit_skip((test), "Test requires " #config "=n");      \
>  } while (0)
>
> +#define KASAN_TEST_NEEDS_CHECKED_MEMINTRINSICS(test) do {              \
> +       if (IS_ENABLED(CONFIG_KASAN_HW_TAGS))                           \
> +               break;  /* No compiler instrumentation. */              \
> +       if (IS_ENABLED(CONFIG_CC_HAS_KASAN_MEMINTRINSIC_PREFIX))        \
> +               break;  /* Should always be instrumented! */            \
> +       if (IS_ENABLED(CONFIG_GENERIC_ENTRY))                           \
> +               kunit_skip((test), "Test requires checked mem*()");     \
> +} while (0)
> +
>  static void kmalloc_oob_right(struct kunit *test)
>  {
>         char *ptr;
> @@ -454,6 +463,8 @@ static void kmalloc_oob_16(struct kunit *test)
>                 u64 words[2];
>         } *ptr1, *ptr2;
>
> +       KASAN_TEST_NEEDS_CHECKED_MEMINTRINSICS(test);
> +
>         /* This test is specifically crafted for the generic mode. */
>         KASAN_TEST_NEEDS_CONFIG_ON(test, CONFIG_KASAN_GENERIC);
>
> @@ -476,6 +487,8 @@ static void kmalloc_uaf_16(struct kunit *test)
>                 u64 words[2];
>         } *ptr1, *ptr2;
>
> +       KASAN_TEST_NEEDS_CHECKED_MEMINTRINSICS(test);
> +
>         ptr1 = kmalloc(sizeof(*ptr1), GFP_KERNEL);
>         KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr1);
>
> @@ -498,6 +511,8 @@ static void kmalloc_oob_memset_2(struct kunit *test)
>         char *ptr;
>         size_t size = 128 - KASAN_GRANULE_SIZE;
>
> +       KASAN_TEST_NEEDS_CHECKED_MEMINTRINSICS(test);
> +
>         ptr = kmalloc(size, GFP_KERNEL);
>         KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
>
> @@ -511,6 +526,8 @@ static void kmalloc_oob_memset_4(struct kunit *test)
>         char *ptr;
>         size_t size = 128 - KASAN_GRANULE_SIZE;
>
> +       KASAN_TEST_NEEDS_CHECKED_MEMINTRINSICS(test);
> +
>         ptr = kmalloc(size, GFP_KERNEL);
>         KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
>
> @@ -524,6 +541,8 @@ static void kmalloc_oob_memset_8(struct kunit *test)
>         char *ptr;
>         size_t size = 128 - KASAN_GRANULE_SIZE;
>
> +       KASAN_TEST_NEEDS_CHECKED_MEMINTRINSICS(test);
> +
>         ptr = kmalloc(size, GFP_KERNEL);
>         KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
>
> @@ -537,6 +556,8 @@ static void kmalloc_oob_memset_16(struct kunit *test)
>         char *ptr;
>         size_t size = 128 - KASAN_GRANULE_SIZE;
>
> +       KASAN_TEST_NEEDS_CHECKED_MEMINTRINSICS(test);
> +
>         ptr = kmalloc(size, GFP_KERNEL);
>         KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
>
> @@ -550,6 +571,8 @@ static void kmalloc_oob_in_memset(struct kunit *test)
>         char *ptr;
>         size_t size = 128 - KASAN_GRANULE_SIZE;
>
> +       KASAN_TEST_NEEDS_CHECKED_MEMINTRINSICS(test);
> +
>         ptr = kmalloc(size, GFP_KERNEL);
>         KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
>
> @@ -566,6 +589,8 @@ static void kmalloc_memmove_negative_size(struct kunit *test)
>         size_t size = 64;
>         size_t invalid_size = -2;
>
> +       KASAN_TEST_NEEDS_CHECKED_MEMINTRINSICS(test);
> +
>         /*
>          * Hardware tag-based mode doesn't check memmove for negative size.
>          * As a result, this test introduces a side-effect memory corruption,
> @@ -590,6 +615,8 @@ static void kmalloc_memmove_invalid_size(struct kunit *test)
>         size_t size = 64;
>         size_t invalid_size = size;
>
> +       KASAN_TEST_NEEDS_CHECKED_MEMINTRINSICS(test);
> +
>         ptr = kmalloc(size, GFP_KERNEL);
>         KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
>
> @@ -618,6 +645,8 @@ static void kmalloc_uaf_memset(struct kunit *test)
>         char *ptr;
>         size_t size = 33;
>
> +       KASAN_TEST_NEEDS_CHECKED_MEMINTRINSICS(test);
> +
>         /*
>          * Only generic KASAN uses quarantine, which is required to avoid a
>          * kernel memory corruption this test causes.
> --
> 2.39.2.637.g21b0678d19-goog
>

Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>

Thank you for taking care of all of this, Marco!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZdsiWjpp9qjsy16SSuOcaOgnk2h6vC%2Bdq6h8GUrqdF1bw%40mail.gmail.com.
