Return-Path: <kasan-dev+bncBC7OBJGL2MHBBEUXRCQAMGQEU2I5BIA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x338.google.com (mail-ot1-x338.google.com [IPv6:2607:f8b0:4864:20::338])
	by mail.lfdr.de (Postfix) with ESMTPS id 8E8F16A9A12
	for <lists+kasan-dev@lfdr.de>; Fri,  3 Mar 2023 16:00:36 +0100 (CET)
Received: by mail-ot1-x338.google.com with SMTP id o8-20020a9d5c08000000b00693d403480asf1307711otk.3
        for <lists+kasan-dev@lfdr.de>; Fri, 03 Mar 2023 07:00:36 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1677855635; cv=pass;
        d=google.com; s=arc-20160816;
        b=BikZB7A7MnLilUsr6BwSEVx/wIzcL/5bQQDiBh3Lau8VcrtlaS9aam+R3PueRPKdZa
         IoBFmCOfJ6QRT3QZBGZ5My/IyTt8igQizXO+XYHDs6uTv0zO2aGCy+TP/67MZQW5ymam
         NaVpErJdQclpeBWKyoOzR1EEnnbDL2NluJYRJUJYN0LWowPWfGL9CaAo4y+prwoYolR7
         sCw2cd+7Te5TnJdBS8NNrOVVwvfcjjncxAxi1rg87UTk3NIVHcAfCBKEEKOMQiyHu1A2
         cA3hcxdXI4Q0DfAH3svuCWQYq84+58s1u/S4+nRLMUYcd2fdu4SAO8W+BwmFzpo3Gh7Y
         Kymw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=uiigHEuNE1ca5CxiiWTbO4I+de0kcrfqfQG9wLrdxb8=;
        b=vPOlwQBPvSl4747UB4u3njXqeB0VvokQ8t32zPIgqqUbhh6/TYViOd7k5lzpg9b6ln
         AfrZr/YUmCX0ujCpaS3DUdaxteNmBO1WarAg7/+LMhe09v8QJXcIvsYf6f70U4h03b3j
         hpfQY3L+1+BB1vsTh6HjEn7bgpOAlnb7H7IqFCj6PliUEEpizO74epzeZazH6aXsxwJv
         UncF6bykVLWDvyvhIBvyGhvC9sqgbqNu1ehd8Xx9O4hQYsgpHsWzMdrG+Rx6XqzJA9yM
         Ntldk02Yet5E03mdtr1ZAm9ZUBLWnDWlB8Ijn+nYiAoJU2UKhEK9R8QD6GjeVpV27ezY
         C4xQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=jf6Q6kvx;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::936 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112; t=1677855635;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=uiigHEuNE1ca5CxiiWTbO4I+de0kcrfqfQG9wLrdxb8=;
        b=ZsnTfzDXtnOxk6T4hA9CZagYGbCFXfEFCGBHOEzI9Sjc6dTvsRUgOsHSfTLyb9YmDs
         k0pIUrhcNhYr+Or0pl090q+q65gKHtFVhcRcx2taQME6CiO5SyUc6gfZEbGv6oPIWZRH
         T2G19CLNI9brM6IRsrF46BAhRbSYCePO7mZwqVZZwed3dAxzr1pVxiWfoVR9Uye9kHPx
         dBlRTvCrsC3wefyYCd8j/Va4Z2oZMZjzUwV4IIW1WJBOk0QMnDAvf1udPU6LPQoZ6dx2
         bnEyis4h19mWTQ7dw/PL4mX3806pBKPCMbSGhSYV3a7rT+e/QVhEEkpbD9V/9TNMKJGC
         ObzQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112; t=1677855635;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=uiigHEuNE1ca5CxiiWTbO4I+de0kcrfqfQG9wLrdxb8=;
        b=sL+rSh+Wm/mR6SG7wm3W9UYhEYg5KSAmvU86sZ+PX97/EOT8rkTMPAdj4Clca8UNXi
         TMuWOOowiOH0Il+IYUJvr/NICGlJcXto0pBA/wKBtqI/XyRvoJjqW5zosrG3v08J5ive
         WSMnHXm33niO9Zvo1DHSi6IpCFaPQcwet/XgV65moYrTFvcc2Jobk83sHiRY6/65SUEi
         aIYQdW1aDPtUWGWauzE9MdN+BDLIe/a3bHrftB7fbTw0PHEWkontw0zZZgYw+HOH5FEI
         6PRRKqkQdTqPnkiZRY8LFyJQKmxMpz9qN0y81bYYf5dEKHR23dOLY5duvSP14seWvMtr
         PLvQ==
X-Gm-Message-State: AO0yUKUlIUfe09VKIju6MEgoFbg2ZMt6y2Qs2swfntWUgQnlJktWVObu
	uxfHEOMbt321O35Sy6o1h34=
X-Google-Smtp-Source: AK7set9RHgDDius8mVFbUD346alvbVz5bpgZpodaiIZ7EVY4MFhpLDgeO+yds74xx6NPAWczL0yTQg==
X-Received: by 2002:a05:6870:3a07:b0:176:1def:9c31 with SMTP id du7-20020a0568703a0700b001761def9c31mr560841oab.10.1677855634911;
        Fri, 03 Mar 2023 07:00:34 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6830:2a9f:b0:694:3ac6:71e with SMTP id
 s31-20020a0568302a9f00b006943ac6071els677387otu.11.-pod-prod-gmail; Fri, 03
 Mar 2023 07:00:34 -0800 (PST)
X-Received: by 2002:a9d:841:0:b0:68b:bc6c:d955 with SMTP id 59-20020a9d0841000000b0068bbc6cd955mr687671oty.17.1677855634303;
        Fri, 03 Mar 2023 07:00:34 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1677855634; cv=none;
        d=google.com; s=arc-20160816;
        b=j9QnYbaMZEmKElvyPe2dcule2FbdGUo5KZnMr0C315Q5hAjpIqlPIvI3nDRzMRPqBH
         vqjb/N3DlYN3VTuapI5V/xPWf8ObEaqD9vNsj0WPqfueVZfCmzP9hGPqUhzbHrzGr2FA
         R81YXTlLfxE+JD3Fw1zlIdL0OTQcKR4wV37pt2l2qizDp9I0/0vv8Tc7uUPAPAm/pJ/l
         rThcYB3+shQDzBm5rM8ZywUrg+deQT8fXT+Ww/ZCqdI1X1qlYhskvGeMuPA/xR9kfF8b
         UmACRzjMEH8JCf2TAU42ehU0ONQDwasepRWt6+YWdo3Nv4eumnEy4fJttyYW2PiCss4d
         MTjw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=ARdODDyEMP84oqzwuXABwvOYvSOQTabE/Zfw0C3mMnU=;
        b=0KVCZl4SwP46Ba9eq6tiMpvU6tsCEc00G2dzoGn1al5bTbK6c+lH08zLuw8NqLpYE7
         p1HwD8jffDq/lb5PxCW7rT3ySsVHyBC9+GMr1y0280M9/uk4Jv4p8faLmFl38oBFZc2O
         7xgxTTseuBQwayMh9vZIcZG3QWuzOgLJXTXQf4+dYOfBEChSoM3GEpYTQulk5xv5yhUM
         aghKF6AUbZeTJkL6eVfihzu6zjQpZ6Qn6CGSbW9QVUxXRb34ucfWAujpdbqhG4+DgW2R
         UVWjyPnLr5IsjBvF0Houebd98IfSNoraeNgjhoiFMr/bOfVSco/l5gjt8L7lEBr2awB4
         PlHw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=jf6Q6kvx;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::936 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ua1-x936.google.com (mail-ua1-x936.google.com. [2607:f8b0:4864:20::936])
        by gmr-mx.google.com with ESMTPS id oo24-20020a05620a531800b00725bdb9a8acsi118462qkn.5.2023.03.03.07.00.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 03 Mar 2023 07:00:34 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::936 as permitted sender) client-ip=2607:f8b0:4864:20::936;
Received: by mail-ua1-x936.google.com with SMTP id l24so1799298uac.12
        for <kasan-dev@googlegroups.com>; Fri, 03 Mar 2023 07:00:34 -0800 (PST)
X-Received: by 2002:a1f:2dcb:0:b0:401:42e5:6d2e with SMTP id
 t194-20020a1f2dcb000000b0040142e56d2emr1462853vkt.1.1677855633776; Fri, 03
 Mar 2023 07:00:33 -0800 (PST)
MIME-Version: 1.0
References: <20230303141433.3422671-1-glider@google.com> <20230303141433.3422671-2-glider@google.com>
In-Reply-To: <20230303141433.3422671-2-glider@google.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 3 Mar 2023 15:59:57 +0100
Message-ID: <CANpmjNNT29Zyv78-ZieTQg_kexQrkvOJOVikgH0SzCdve5yygw@mail.gmail.com>
Subject: Re: [PATCH 2/4] kmsan: another take at fixing memcpy tests
To: Alexander Potapenko <glider@google.com>
Cc: linux-kernel@vger.kernel.org, linux-mm@kvack.org, tglx@linutronix.de, 
	mingo@redhat.com, bp@alien8.de, x86@kernel.org, dave.hansen@linux.intel.com, 
	hpa@zytor.com, akpm@linux-foundation.org, dvyukov@google.com, 
	nathan@kernel.org, ndesaulniers@google.com, kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=jf6Q6kvx;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::936 as
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

On Fri, 3 Mar 2023 at 15:14, Alexander Potapenko <glider@google.com> wrote:
>
> commit 5478afc55a21 ("kmsan: fix memcpy tests") uses OPTIMIZER_HIDE_VAR()
> to hide the uninitialized var from the compiler optimizations.
>
> However OPTIMIZER_HIDE_VAR(uninit) enforces an immediate check of
> @uninit, so memcpy tests did not actually check the behavior of memcpy(),
> because they always contained a KMSAN report.
>
> Replace OPTIMIZER_HIDE_VAR() with a file-local macro that just clobbers
> the memory with a barrier(), and add a test case for memcpy() that does not
> expect an error report.
>
> Also reflow kmsan_test.c with clang-format.
>
> Signed-off-by: Alexander Potapenko <glider@google.com>
> ---
> v2:
>  - replace inline assembly with a barrier(), update comments

Reviewed-by: Marco Elver <elver@google.com>

> ---
>  mm/kmsan/kmsan_test.c | 44 +++++++++++++++++++++++++++++++++++++------
>  1 file changed, 38 insertions(+), 6 deletions(-)
>
> diff --git a/mm/kmsan/kmsan_test.c b/mm/kmsan/kmsan_test.c
> index 088e21a48dc4b..aeddfdd4f679f 100644
> --- a/mm/kmsan/kmsan_test.c
> +++ b/mm/kmsan/kmsan_test.c
> @@ -407,6 +407,37 @@ static void test_printk(struct kunit *test)
>         KUNIT_EXPECT_TRUE(test, report_matches(&expect));
>  }
>
> +/*
> + * Prevent the compiler from optimizing @var away. Without this, Clang may
> + * notice that @var is uninitialized and drop memcpy() calls that use it.
> + *
> + * There is OPTIMIZER_HIDE_VAR() in linux/compier.h that we cannot use here,
> + * because it is implemented as inline assembly receiving @var as a parameter
> + * and will enforce a KMSAN check. Same is true for e.g. barrier_data(var).
> + */
> +#define DO_NOT_OPTIMIZE(var) barrier()
> +
> +/*
> + * Test case: ensure that memcpy() correctly copies initialized values.
> + * Also serves as a regression test to ensure DO_NOT_OPTIMIZE() does not cause
> + * extra checks.
> + */
> +static void test_init_memcpy(struct kunit *test)
> +{
> +       EXPECTATION_NO_REPORT(expect);
> +       volatile int src;
> +       volatile int dst = 0;
> +
> +       DO_NOT_OPTIMIZE(src);
> +       src = 1;
> +       kunit_info(
> +               test,
> +               "memcpy()ing aligned initialized src to aligned dst (no reports)\n");
> +       memcpy((void *)&dst, (void *)&src, sizeof(src));
> +       kmsan_check_memory((void *)&dst, sizeof(dst));
> +       KUNIT_EXPECT_TRUE(test, report_matches(&expect));
> +}
> +
>  /*
>   * Test case: ensure that memcpy() correctly copies uninitialized values between
>   * aligned `src` and `dst`.
> @@ -420,7 +451,7 @@ static void test_memcpy_aligned_to_aligned(struct kunit *test)
>         kunit_info(
>                 test,
>                 "memcpy()ing aligned uninit src to aligned dst (UMR report)\n");
> -       OPTIMIZER_HIDE_VAR(uninit_src);
> +       DO_NOT_OPTIMIZE(uninit_src);
>         memcpy((void *)&dst, (void *)&uninit_src, sizeof(uninit_src));
>         kmsan_check_memory((void *)&dst, sizeof(dst));
>         KUNIT_EXPECT_TRUE(test, report_matches(&expect));
> @@ -443,7 +474,7 @@ static void test_memcpy_aligned_to_unaligned(struct kunit *test)
>         kunit_info(
>                 test,
>                 "memcpy()ing aligned uninit src to unaligned dst (UMR report)\n");
> -       OPTIMIZER_HIDE_VAR(uninit_src);
> +       DO_NOT_OPTIMIZE(uninit_src);
>         memcpy((void *)&dst[1], (void *)&uninit_src, sizeof(uninit_src));
>         kmsan_check_memory((void *)dst, 4);
>         KUNIT_EXPECT_TRUE(test, report_matches(&expect));
> @@ -467,13 +498,14 @@ static void test_memcpy_aligned_to_unaligned2(struct kunit *test)
>         kunit_info(
>                 test,
>                 "memcpy()ing aligned uninit src to unaligned dst - part 2 (UMR report)\n");
> -       OPTIMIZER_HIDE_VAR(uninit_src);
> +       DO_NOT_OPTIMIZE(uninit_src);
>         memcpy((void *)&dst[1], (void *)&uninit_src, sizeof(uninit_src));
>         kmsan_check_memory((void *)&dst[4], sizeof(uninit_src));
>         KUNIT_EXPECT_TRUE(test, report_matches(&expect));
>  }
>
> -static noinline void fibonacci(int *array, int size, int start) {
> +static noinline void fibonacci(int *array, int size, int start)
> +{
>         if (start < 2 || (start == size))
>                 return;
>         array[start] = array[start - 1] + array[start - 2];
> @@ -482,8 +514,7 @@ static noinline void fibonacci(int *array, int size, int start) {
>
>  static void test_long_origin_chain(struct kunit *test)
>  {
> -       EXPECTATION_UNINIT_VALUE_FN(expect,
> -                                   "test_long_origin_chain");
> +       EXPECTATION_UNINIT_VALUE_FN(expect, "test_long_origin_chain");
>         /* (KMSAN_MAX_ORIGIN_DEPTH * 2) recursive calls to fibonacci(). */
>         volatile int accum[KMSAN_MAX_ORIGIN_DEPTH * 2 + 2];
>         int last = ARRAY_SIZE(accum) - 1;
> @@ -515,6 +546,7 @@ static struct kunit_case kmsan_test_cases[] = {
>         KUNIT_CASE(test_uaf),
>         KUNIT_CASE(test_percpu_propagate),
>         KUNIT_CASE(test_printk),
> +       KUNIT_CASE(test_init_memcpy),
>         KUNIT_CASE(test_memcpy_aligned_to_aligned),
>         KUNIT_CASE(test_memcpy_aligned_to_unaligned),
>         KUNIT_CASE(test_memcpy_aligned_to_unaligned2),
> --
> 2.40.0.rc0.216.gc4246ad0f0-goog
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNNT29Zyv78-ZieTQg_kexQrkvOJOVikgH0SzCdve5yygw%40mail.gmail.com.
