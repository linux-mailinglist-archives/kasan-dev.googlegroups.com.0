Return-Path: <kasan-dev+bncBC7OBJGL2MHBBIUMQKQAMGQELZ5BPMI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-x113d.google.com (mail-yw1-x113d.google.com [IPv6:2607:f8b0:4864:20::113d])
	by mail.lfdr.de (Postfix) with ESMTPS id 32FA86A80EA
	for <lists+kasan-dev@lfdr.de>; Thu,  2 Mar 2023 12:19:00 +0100 (CET)
Received: by mail-yw1-x113d.google.com with SMTP id 00721157ae682-536e8d6d9cesf311636237b3.12
        for <lists+kasan-dev@lfdr.de>; Thu, 02 Mar 2023 03:19:00 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1677755939; cv=pass;
        d=google.com; s=arc-20160816;
        b=G2s9tgeyJuROcrwUCehciSZQYPCvBCiq/Ov6jE+Sy4Rux084zfllDAvvrarvDfL6Ei
         rLSTyJcwQuz/eOUbRT7ELlC2yI3SeJ9+nxyxgeuABcTaO3lrzWWYjXnZCN2J3OM4ZYow
         9vZgdt8X2kCcz/bL/o/N09rbKWM3q/URvYoaXiUKVde/gnPe9WPEr8wmevGXu1XYGdok
         rEyYWFsFMZzmgF0yY3gq1m69kpLzdWQ5D2Fh7C7RYfHhm8uYpy5GBo9cHAdMuF5cKOaX
         tDj+IJxYqNDL2OKt3oCljoKMmmHmBCbCAhKd59BrUKE3vOJ4MGhsOAaLBDpDYg3xGF0q
         vF+A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=ZgdqSJqY8Ig1peuhpw1xem3cjpgahoAulpRJytYV/3w=;
        b=yMY8vTVVrY3UMBxs1pFXuFJH3UD0smFuvePo/ZPIAPhij/rKDIvdJXcUr1k1s4B+vD
         AeLEdhgStO5dfZxiGsrl8iTapkMEjb4fFyXhE9r3EA3+INOqIrbex/Jpp05/C31KWdY+
         dUtPxUlOWUfiQTGggmR0oMKDiSv3uRSlomlu9Fjdu918DfW7iTdfEDUx3HcaoqWVAvqj
         dT2i4xSG/eiazmsetIDMELu+90yCGBu/TdQRpOMTnoTdcTi+e8O12l6U1bUoUo2nJK6+
         L78AfkfYSvIzFImxnH81YImlk2/mXdCG+2nwntc8oGtx4r9OETQkfv0HSPbG6Dx5rPuU
         FhAA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=XSmgGg4V;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::e29 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=ZgdqSJqY8Ig1peuhpw1xem3cjpgahoAulpRJytYV/3w=;
        b=P/oR7qvcVCRS00r/jpMCG7Zkdinags14M932l8pIKZ27Lbipy4DU7GRkv0QIJfxRNG
         5fLRcS+NlDO/n1Wj2imA7OzckYu43MLhBaTfXSqDsTBGsh4hr6hFz+NBpGo8/qz24Hny
         lkhGpBQ1p1hHOR5Ha/1/CO5fgc8p4hgYej0z7TBnBhkLXZzIBQnp34iqYRQ95+LOD1xZ
         iEba0hBYmV5OSEXCeBFiBAbq/hM/m18O7eQOaaEEQPIOX3mrrs/0vMhznLhy4Bs7tsb0
         LpKp4qz+o1DpPb/AketVJbjpsrx/qEM7Sy7La9kuRlqK2sGvklRYr+QhyGn3WroaVrMi
         SRlA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=ZgdqSJqY8Ig1peuhpw1xem3cjpgahoAulpRJytYV/3w=;
        b=eKcPS7cg6jwmXLG9iulcSR221kWKQxUhg0ZqGoj11dmE0XMFXN0GNBACm3cuHTOECp
         i/8vdb6u+rhZbHSrk3g9ssKJqfzoo/32RGoQBafLZ4S7m/S8tuT7S53rhgltXskX9QGI
         nHkLSx1TU78bnvooX2n6Vm2Rsu/cKO8wLb1DRdsZ1o/o9fcIq3EaOarZf2djsnHHEECc
         KjAm+MBBYbjw9xKozw30zuRjbvLVi7Jbr/onTbWJrCs1xSbniqbc5w8kH0tvVADJjUn7
         8eHetMNVjYZ69gwHmA/K9DaVsNNK+OgSpEs2ovipMgmPj2ZlhLH1xI9TTedRQ71b1TQq
         PlSA==
X-Gm-Message-State: AO0yUKUrsS6tdshb9xq49lqdROoS7HqU0zTyBGVdGNKl9TvZlSYSdGJv
	VEKEgiWsHjoHtycB+/hBfts=
X-Google-Smtp-Source: AK7set/2u6kh1r1OplRaU596aoEMErp1mL+j8B+FQj53ciTfBfIZEDITQo26cdF5CfoZ9TbRXEF8xA==
X-Received: by 2002:a81:dc0a:0:b0:52e:fb7a:94b7 with SMTP id h10-20020a81dc0a000000b0052efb7a94b7mr6039215ywj.7.1677755938958;
        Thu, 02 Mar 2023 03:18:58 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:690c:c95:b0:538:597c:fb2b with SMTP id
 cm21-20020a05690c0c9500b00538597cfb2bls13184239ywb.7.-pod-prod-gmail; Thu, 02
 Mar 2023 03:18:58 -0800 (PST)
X-Received: by 2002:a81:6955:0:b0:538:5214:5c14 with SMTP id e82-20020a816955000000b0053852145c14mr9684615ywc.42.1677755938352;
        Thu, 02 Mar 2023 03:18:58 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1677755938; cv=none;
        d=google.com; s=arc-20160816;
        b=xuA8rXJjo/T8iKFj9dlYREJfXqhkHufH9d5roBdxp2bWFPkDnzGqTdFrQkzkODjswx
         me9NThJZzxXzMpeVquzDBfN3RUj4sc2v25/1HlwshHXWOtDEnZ3gl/DENjLbH/ly910U
         1fhoxpWJ0234A7Ca7XGk/qi1hkB7tmYLpgtArlO+9al0pn9xRO//UVNolCjOA16xfZsZ
         IvOO+dZunDADkZJclWzdd8lBdtJo327VDyfjhPB2l8OXBICUnWKF/TjrT0yhcH82USRv
         Ljr2MhNKfVTOJ0z4Mj6lcouglbrmIYQ6sL9TZR2rh7IR8xcCBo/dshmliXxL6T32fN3r
         TYWw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=TQxxCnZY2j28H3XZXEchjSlFpSlW7FKHIgkQwAfvbPo=;
        b=nIihokCSoL0bYkJ0bTyHeyjTaU25qOpVUGUSdIejdVLDSSAOTN6hqKE9kDt+sgn+GI
         3HoB620xNY0aH6whTrhSC36J3NZ8DvFeCGV50w1J3WSK+ioYRJDG49Uxp5XAkKRty/wC
         oEdfSRU8woYfWNF0p4FhnC+9neC4p6ikX9jfRwpyd6y1L6OnUN/z75LkXUz43nd8XnXy
         Ug2FIG8t2Wm1C3O5HHMzrlbfBRhDNhgO4rrQFafdxrI3FPES/IFG6JtFH4FIuQCMLPc9
         fIzsrpbOkhtLCjoDXAc0kzAgPqy19+TXiL0a4NqXuX9IOR8QSmIrKylW6rZBOIAg4H8W
         POpg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=XSmgGg4V;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::e29 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-vs1-xe29.google.com (mail-vs1-xe29.google.com. [2607:f8b0:4864:20::e29])
        by gmr-mx.google.com with ESMTPS id bo5-20020a05690c058500b0053421bb7e79si1520150ywb.1.2023.03.02.03.18.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 02 Mar 2023 03:18:58 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::e29 as permitted sender) client-ip=2607:f8b0:4864:20::e29;
Received: by mail-vs1-xe29.google.com with SMTP id a3so22198311vsi.0
        for <kasan-dev@googlegroups.com>; Thu, 02 Mar 2023 03:18:58 -0800 (PST)
X-Received: by 2002:a67:cb06:0:b0:402:99ce:1d9f with SMTP id
 b6-20020a67cb06000000b0040299ce1d9fmr6216969vsl.4.1677755937832; Thu, 02 Mar
 2023 03:18:57 -0800 (PST)
MIME-Version: 1.0
References: <20230301143933.2374658-1-glider@google.com> <20230301143933.2374658-2-glider@google.com>
In-Reply-To: <20230301143933.2374658-2-glider@google.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 2 Mar 2023 12:18:21 +0100
Message-ID: <CANpmjNOG=T8R=BXO8PUX3FJQnKQfPjNyLGJ0wG5G_4_mHwJ-gA@mail.gmail.com>
Subject: Re: [PATCH 2/4] kmsan: another take at fixing memcpy tests
To: Alexander Potapenko <glider@google.com>
Cc: linux-kernel@vger.kernel.org, linux-mm@kvack.org, tglx@linutronix.de, 
	mingo@redhat.com, bp@alien8.de, x86@kernel.org, dave.hansen@linux.intel.com, 
	hpa@zytor.com, akpm@linux-foundation.org, dvyukov@google.com, 
	nathan@kernel.org, ndesaulniers@google.com, kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=XSmgGg4V;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::e29 as
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

On Wed, 1 Mar 2023 at 15:39, 'Alexander Potapenko' via kasan-dev
<kasan-dev@googlegroups.com> wrote:
>
> 5478afc55a21 ("kmsan: fix memcpy tests") uses OPTIMIZER_HIDE_VAR() to
> hide the uninitialized var from the compiler optimizations.
>
> However OPTIMIZER_HIDE_VAR(uninit) enforces an immediate check of
> @uninit, so memcpy tests did not actually check the behavior of memcpy(),
> because they always contained a KMSAN report.
>
> Replace OPTIMIZER_HIDE_VAR() with a file-local asm macro that just
> clobbers the memory, and add a test case for memcpy() that does not
> expect an error report.
>
> Also reflow kmsan_test.c with clang-format.
>
> Signed-off-by: Alexander Potapenko <glider@google.com>
> ---
>  mm/kmsan/kmsan_test.c | 43 +++++++++++++++++++++++++++++++++++++------
>  1 file changed, 37 insertions(+), 6 deletions(-)
>
> diff --git a/mm/kmsan/kmsan_test.c b/mm/kmsan/kmsan_test.c
> index 088e21a48dc4b..cc98a3f4e0899 100644
> --- a/mm/kmsan/kmsan_test.c
> +++ b/mm/kmsan/kmsan_test.c
> @@ -407,6 +407,36 @@ static void test_printk(struct kunit *test)
>         KUNIT_EXPECT_TRUE(test, report_matches(&expect));
>  }
>
> +/*
> + * Prevent the compiler from optimizing @var away. Without this, Clang may
> + * notice that @var is uninitialized and drop memcpy() calls that use it.
> + *
> + * There is OPTIMIZER_HIDE_VAR() in linux/compier.h that we cannot use here,
> + * because it is implemented as inline assembly receiving @var as a parameter
> + * and will enforce a KMSAN check.
> + */
> +#define DO_NOT_OPTIMIZE(var) asm("" ::: "memory")

That's just a normal "barrier()" - use that instead?

> +/*
> + * Test case: ensure that memcpy() correctly copies initialized values.
> + */
> +static void test_init_memcpy(struct kunit *test)
> +{
> +       EXPECTATION_NO_REPORT(expect);
> +       volatile int src;
> +       volatile int dst = 0;
> +
> +       // Ensure DO_NOT_OPTIMIZE() does not cause extra checks.

^^ this comment seems redundant now, given DO_NOT_OPTIMIZE() has a
comment (it's also using //-style comment).

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
> @@ -420,7 +450,7 @@ static void test_memcpy_aligned_to_aligned(struct kunit *test)
>         kunit_info(
>                 test,
>                 "memcpy()ing aligned uninit src to aligned dst (UMR report)\n");
> -       OPTIMIZER_HIDE_VAR(uninit_src);
> +       DO_NOT_OPTIMIZE(uninit_src);
>         memcpy((void *)&dst, (void *)&uninit_src, sizeof(uninit_src));
>         kmsan_check_memory((void *)&dst, sizeof(dst));
>         KUNIT_EXPECT_TRUE(test, report_matches(&expect));
> @@ -443,7 +473,7 @@ static void test_memcpy_aligned_to_unaligned(struct kunit *test)
>         kunit_info(
>                 test,
>                 "memcpy()ing aligned uninit src to unaligned dst (UMR report)\n");
> -       OPTIMIZER_HIDE_VAR(uninit_src);
> +       DO_NOT_OPTIMIZE(uninit_src);
>         memcpy((void *)&dst[1], (void *)&uninit_src, sizeof(uninit_src));
>         kmsan_check_memory((void *)dst, 4);
>         KUNIT_EXPECT_TRUE(test, report_matches(&expect));
> @@ -467,13 +497,14 @@ static void test_memcpy_aligned_to_unaligned2(struct kunit *test)
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
> @@ -482,8 +513,7 @@ static noinline void fibonacci(int *array, int size, int start) {
>
>  static void test_long_origin_chain(struct kunit *test)
>  {
> -       EXPECTATION_UNINIT_VALUE_FN(expect,
> -                                   "test_long_origin_chain");
> +       EXPECTATION_UNINIT_VALUE_FN(expect, "test_long_origin_chain");
>         /* (KMSAN_MAX_ORIGIN_DEPTH * 2) recursive calls to fibonacci(). */
>         volatile int accum[KMSAN_MAX_ORIGIN_DEPTH * 2 + 2];
>         int last = ARRAY_SIZE(accum) - 1;
> @@ -515,6 +545,7 @@ static struct kunit_case kmsan_test_cases[] = {
>         KUNIT_CASE(test_uaf),
>         KUNIT_CASE(test_percpu_propagate),
>         KUNIT_CASE(test_printk),
> +       KUNIT_CASE(test_init_memcpy),
>         KUNIT_CASE(test_memcpy_aligned_to_aligned),
>         KUNIT_CASE(test_memcpy_aligned_to_unaligned),
>         KUNIT_CASE(test_memcpy_aligned_to_unaligned2),
> --
> 2.39.2.722.g9855ee24e9-goog
>
> --
> You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230301143933.2374658-2-glider%40google.com.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNOG%3DT8R%3DBXO8PUX3FJQnKQfPjNyLGJ0wG5G_4_mHwJ-gA%40mail.gmail.com.
