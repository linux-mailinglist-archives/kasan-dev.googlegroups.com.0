Return-Path: <kasan-dev+bncBC7OBJGL2MHBBO627STQMGQEUUKCJYQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23d.google.com (mail-lj1-x23d.google.com [IPv6:2a00:1450:4864:20::23d])
	by mail.lfdr.de (Postfix) with ESMTPS id CDF5C79A96C
	for <lists+kasan-dev@lfdr.de>; Mon, 11 Sep 2023 17:07:40 +0200 (CEST)
Received: by mail-lj1-x23d.google.com with SMTP id 38308e7fff4ca-2bcdd6ba578sf51717051fa.3
        for <lists+kasan-dev@lfdr.de>; Mon, 11 Sep 2023 08:07:40 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1694444860; cv=pass;
        d=google.com; s=arc-20160816;
        b=jd3sRWnRFYKmfqnymof0uoypBpgu/MsEu7NJCN9sSEPCh8z8wydGyPvtyX2hqVHSyQ
         V1G1wTzNaBFrIBj5NqkvD4VM7ODcI+uAbpO4011y+y30TX7t9Ev9SSTqG/qN7FeS1vsY
         EHYzYC8O7xkJaqjGRpGgj6gUf55hh5rB/C2y01NkkMDrdtae6JQlsh6sW9IuU1uMqG6V
         od2KmXshWmUL5/Q7Lrj8NLI/OHCKNASTyjzY7XMvMHu1d69TVI8FF2osotEXu/2Oi5WZ
         duVu5JFNwWElYWHQ2XSK2Dc01grPrd99Q31jPva44jl0gbb1zM9PwXdQoroLz5W5R202
         ddxw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=oPCpHKOT/BnYlPDgB9WetB1I0ogf2PKJGdeAgC3d5bc=;
        fh=xOEYjjBxoZTZ/EHX1QhB46LMgR1TviO8E01fK4wIwx0=;
        b=P3sUU44vwM1qpQLGLbhlPYaOBoYnhzzJMitBNoAjSwKp9VAB0ZUh0E0GH0HNTt69pV
         jK7Nkz52cMU7Zj9zEyuRSAls7ey2BfZXsyCMBtIkIsZV6hbmhlw/aPcEKRWXBhsI+iv6
         7UItUYfT/Kqjk+I+1P0vMCQ9qgHTQcWVj9RC2lJglwzM4QH2bKDLiH7Z2JepfGVQFFWr
         haSbhkLEfb5QyF8J7sp3/5k+DKWyfeO+hSZYQ3eAGlienY/e/IzvEUIMVr7lT8DYQyIp
         7HTwFVDa4XQ9rPgC2+TNm1PmTS8iTdZlNHFiJ3z04U2AWC9BavenjAIo6rE0JSBO6Fd3
         D2gw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=ufn2++MR;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::330 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1694444860; x=1695049660; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=oPCpHKOT/BnYlPDgB9WetB1I0ogf2PKJGdeAgC3d5bc=;
        b=fQEmbnaehDMPVddXZ7VwBaB8nQM93NzboYcbyFPHgZeZaZneNcp4mM/pJMySWrDRUG
         mxHFetjgTPVSX/Cen6Vm3xu6X1mOf2uR6eOoM7brfNSaORVQ8jqHXOG1PdpTDxnuFQFP
         3/2ho4W3xSCnTyF+MpWLnxko0eEGOtsXIuuCABOxSZ7Bate2xKZtfdITgI8XDsz/66EV
         QzNDxzTlewhKtWfoIHMuwc6ZnEXIGg2jo2Qr5zZzmGrwDIqrhattpJB9V08piWmKTVQR
         IEP18sY6s8gmNZMfLzxCD8RoDivNOIRhPf+EO+oRMnLuLWOFXIQS4cgRlgn6UB+cKnxV
         mQUA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1694444860; x=1695049660;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=oPCpHKOT/BnYlPDgB9WetB1I0ogf2PKJGdeAgC3d5bc=;
        b=TIocdtSBEVfTifSo83MoQ+ajILbvhwgWqjIvakcbOBBr5RMkakyNbzCaRGrw0OQOj+
         l2fXiIfykKnAVq0LXhk3r1sdmBmQ97QuIurN1W88tfrTi8yUEiOvBVZKddReS8IfpcDa
         x0a2/VR99i/UByU84CjsA6rfxj9sc1ZMuGSHBzvMXU+nbAMKH1sIOMcEJcDt9kQmK+5n
         PnnWfKXKhmcYea/ArwxExYDr9hd+7Gmoe5Xsetb96QNPGYneKcbBiZQ26Z43b0TjoYjM
         81w4CBbjBSUf7qASWp6LoBPVV8ykBirM9PLzJ6+ozctR0opELLkHaT52Vn5LXj1p+phu
         Nzag==
X-Gm-Message-State: AOJu0YxlCJNCe5qBigOdEBBF3zxcKiitM7eld3+2RoJxRUNDDXsK+DWj
	2jK1GaK//+lJ8/45AilZC+g=
X-Google-Smtp-Source: AGHT+IHubq0ndKzq8SGweTaKezv3Xumo9mpa/5p49+PoJFvqb4TdN2wnErE+tNAo+/pnn4gMZDtGCQ==
X-Received: by 2002:a2e:9ed7:0:b0:2bc:d8cb:59fe with SMTP id h23-20020a2e9ed7000000b002bcd8cb59femr8170461ljk.8.1694444859420;
        Mon, 11 Sep 2023 08:07:39 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:150d:b0:2b9:6157:a29a with SMTP id
 e13-20020a05651c150d00b002b96157a29als376633ljf.1.-pod-prod-02-eu; Mon, 11
 Sep 2023 08:07:37 -0700 (PDT)
X-Received: by 2002:a2e:a30a:0:b0:2b9:e53f:e1fd with SMTP id l10-20020a2ea30a000000b002b9e53fe1fdmr8593265lje.34.1694444857379;
        Mon, 11 Sep 2023 08:07:37 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1694444857; cv=none;
        d=google.com; s=arc-20160816;
        b=ob/Qh8zbnUoGTzw3GwFWvG9xyw8bxatkQRsPykRwCv1E3abvXym20VNexEIVDrnJQb
         AzrqlwA5TOq1486B+vzFAhAhGsIKgldYsWRscnf0awF4VCsdCXms+5+v47Kd2b8Uv/Ko
         +XEmTtemhwE0u5pZStU4AmQJwXZLy5hmuEE85r6UoSostkNO+vwiPCPwAlXW7LLapyOe
         r503D//e7Y9utcY02CZGoOGpzzl32uFAMFF6TYslyNxM7u8oAWqJOLFf2VPnJR0cMmnh
         tteRyjx/uK4V/NLuC3/iajfC1k1VZpN58bSn/TNkBSI8DFyUQ663w60U+XcNQTC/AjAw
         pDZg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=FOHcmU4SPBlFSrepvb7+SqS7flL0n1Vuqk9odxNTsOE=;
        fh=xOEYjjBxoZTZ/EHX1QhB46LMgR1TviO8E01fK4wIwx0=;
        b=rLDqIQeKB0cRjuq+qsIsMydGYEmBSeNZbACnceJ5cFw+7JlmjttcFLksCPeT5eiHsu
         auqpUvK7ZEBRhJMS/zHwXWHGsd7UqBRCk6qRSergtkqu0hAJgpgU+yNHLpRKw8Lcz0fV
         BajwuBX+ywDTa8PaREC9R18Bolxv/Lq4vEFRekZzzh/QMh4GlT2AHJhTlWzUu8KBMdms
         dQygVt5MPGrgjOIqkK50E8ZV2BNBGhaBxNohsPgBDmGeu5h9YAdmKHpw/s8ldNEBObf0
         /0zO4/6e43TiEHnAmW1++3zX30Emg8UW+8tkMOh9mpsNZDCek1r5KaGup7hBxxDdMRSH
         wjeg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=ufn2++MR;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::330 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x330.google.com (mail-wm1-x330.google.com. [2a00:1450:4864:20::330])
        by gmr-mx.google.com with ESMTPS id h13-20020a2e9ecd000000b002bf62d01a3bsi540293ljk.5.2023.09.11.08.07.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 11 Sep 2023 08:07:37 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::330 as permitted sender) client-ip=2a00:1450:4864:20::330;
Received: by mail-wm1-x330.google.com with SMTP id 5b1f17b1804b1-40037db2fe7so49116945e9.0
        for <kasan-dev@googlegroups.com>; Mon, 11 Sep 2023 08:07:37 -0700 (PDT)
X-Received: by 2002:a05:600c:452:b0:402:cc5c:c98 with SMTP id
 s18-20020a05600c045200b00402cc5c0c98mr8376028wmb.13.1694444856665; Mon, 11
 Sep 2023 08:07:36 -0700 (PDT)
MIME-Version: 1.0
References: <20230911145702.2663753-1-glider@google.com> <20230911145702.2663753-2-glider@google.com>
In-Reply-To: <20230911145702.2663753-2-glider@google.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 11 Sep 2023 17:07:00 +0200
Message-ID: <CANpmjNNhtYPf82=o+NYB64xkHy-8aRy2w9BZgjERbN_+fuK=DA@mail.gmail.com>
Subject: Re: [PATCH v2 2/4] kmsan: prevent optimizations in memcpy tests
To: Alexander Potapenko <glider@google.com>
Cc: dvyukov@google.com, akpm@linux-foundation.org, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20221208 header.b=ufn2++MR;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::330 as
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

On Mon, 11 Sept 2023 at 16:57, Alexander Potapenko <glider@google.com> wrote:
>
> Clang 18 learned to optimize away memcpy() calls of small uninitialized
> scalar values. To ensure that memcpy tests in kmsan_test.c still perform
> calls to memcpy() (which KMSAN replaces with __msan_memcpy()), declare a
> separate memcpy_noinline() function with volatile parameters, which
> won't be optimized.
>
> Also retire DO_NOT_OPTIMIZE(), as memcpy_noinline() is apparently
> enough.
>
> Signed-off-by: Alexander Potapenko <glider@google.com>

Acked-by: Marco Elver <elver@google.com>

> ---
> v2:
>  - fix W=1 warnings reported by LKP test robot
> ---
>  mm/kmsan/kmsan_test.c | 41 ++++++++++++++++-------------------------
>  1 file changed, 16 insertions(+), 25 deletions(-)
>
> diff --git a/mm/kmsan/kmsan_test.c b/mm/kmsan/kmsan_test.c
> index 312989aa2865c..a8d4ca4a1066d 100644
> --- a/mm/kmsan/kmsan_test.c
> +++ b/mm/kmsan/kmsan_test.c
> @@ -407,33 +407,25 @@ static void test_printk(struct kunit *test)
>         KUNIT_EXPECT_TRUE(test, report_matches(&expect));
>  }
>
> -/*
> - * Prevent the compiler from optimizing @var away. Without this, Clang may
> - * notice that @var is uninitialized and drop memcpy() calls that use it.
> - *
> - * There is OPTIMIZER_HIDE_VAR() in linux/compier.h that we cannot use here,
> - * because it is implemented as inline assembly receiving @var as a parameter
> - * and will enforce a KMSAN check. Same is true for e.g. barrier_data(var).
> - */
> -#define DO_NOT_OPTIMIZE(var) barrier()
> +/* Prevent the compiler from inlining a memcpy() call. */
> +static noinline void *memcpy_noinline(volatile void *dst,
> +                                     const volatile void *src, size_t size)
> +{
> +       return memcpy((void *)dst, (const void *)src, size);
> +}
>
> -/*
> - * Test case: ensure that memcpy() correctly copies initialized values.
> - * Also serves as a regression test to ensure DO_NOT_OPTIMIZE() does not cause
> - * extra checks.
> - */
> +/* Test case: ensure that memcpy() correctly copies initialized values. */
>  static void test_init_memcpy(struct kunit *test)
>  {
>         EXPECTATION_NO_REPORT(expect);
> -       volatile int src;
> -       volatile int dst = 0;
> +       volatile long long src;
> +       volatile long long dst = 0;
>
> -       DO_NOT_OPTIMIZE(src);
>         src = 1;
>         kunit_info(
>                 test,
>                 "memcpy()ing aligned initialized src to aligned dst (no reports)\n");
> -       memcpy((void *)&dst, (void *)&src, sizeof(src));
> +       memcpy_noinline((void *)&dst, (void *)&src, sizeof(src));
>         kmsan_check_memory((void *)&dst, sizeof(dst));
>         KUNIT_EXPECT_TRUE(test, report_matches(&expect));
>  }
> @@ -451,8 +443,7 @@ static void test_memcpy_aligned_to_aligned(struct kunit *test)
>         kunit_info(
>                 test,
>                 "memcpy()ing aligned uninit src to aligned dst (UMR report)\n");
> -       DO_NOT_OPTIMIZE(uninit_src);
> -       memcpy((void *)&dst, (void *)&uninit_src, sizeof(uninit_src));
> +       memcpy_noinline((void *)&dst, (void *)&uninit_src, sizeof(uninit_src));
>         kmsan_check_memory((void *)&dst, sizeof(dst));
>         KUNIT_EXPECT_TRUE(test, report_matches(&expect));
>  }
> @@ -474,8 +465,9 @@ static void test_memcpy_aligned_to_unaligned(struct kunit *test)
>         kunit_info(
>                 test,
>                 "memcpy()ing aligned uninit src to unaligned dst (UMR report)\n");
> -       DO_NOT_OPTIMIZE(uninit_src);
> -       memcpy((void *)&dst[1], (void *)&uninit_src, sizeof(uninit_src));
> +       kmsan_check_memory((void *)&uninit_src, sizeof(uninit_src));
> +       memcpy_noinline((void *)&dst[1], (void *)&uninit_src,
> +                       sizeof(uninit_src));
>         kmsan_check_memory((void *)dst, 4);
>         KUNIT_EXPECT_TRUE(test, report_matches(&expect));
>  }
> @@ -498,8 +490,8 @@ static void test_memcpy_aligned_to_unaligned2(struct kunit *test)
>         kunit_info(
>                 test,
>                 "memcpy()ing aligned uninit src to unaligned dst - part 2 (UMR report)\n");
> -       DO_NOT_OPTIMIZE(uninit_src);
> -       memcpy((void *)&dst[1], (void *)&uninit_src, sizeof(uninit_src));
> +       memcpy_noinline((void *)&dst[1], (void *)&uninit_src,
> +                       sizeof(uninit_src));
>         kmsan_check_memory((void *)&dst[4], sizeof(uninit_src));
>         KUNIT_EXPECT_TRUE(test, report_matches(&expect));
>  }
> @@ -513,7 +505,6 @@ static void test_memcpy_aligned_to_unaligned2(struct kunit *test)
>                                                                              \
>                 kunit_info(test,                                            \
>                            "memset" #size "() should initialize memory\n"); \
> -               DO_NOT_OPTIMIZE(uninit);                                    \
>                 memset##size((uint##size##_t *)&uninit, 0, 1);              \
>                 kmsan_check_memory((void *)&uninit, sizeof(uninit));        \
>                 KUNIT_EXPECT_TRUE(test, report_matches(&expect));           \
> --
> 2.42.0.283.g2d96d420d3-goog
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNNhtYPf82%3Do%2BNYB64xkHy-8aRy2w9BZgjERbN_%2BfuK%3DDA%40mail.gmail.com.
