Return-Path: <kasan-dev+bncBC6OLHHDVUOBBT5Q6HCAMGQEZHNOEEA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3c.google.com (mail-oa1-x3c.google.com [IPv6:2001:4860:4864:20::3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 7A273B2451F
	for <lists+kasan-dev@lfdr.de>; Wed, 13 Aug 2025 11:18:09 +0200 (CEST)
Received: by mail-oa1-x3c.google.com with SMTP id 586e51a60fabf-2d9ea524aa6sf10400793fac.0
        for <lists+kasan-dev@lfdr.de>; Wed, 13 Aug 2025 02:18:09 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755076688; cv=pass;
        d=google.com; s=arc-20240605;
        b=ZwKalm6a5qUROOtIB7BlvdebdnsIUOzW8mcH1bnUDojXbqrN4Oj6Chzh5HFWyjTDwx
         XYH1ynuBBTdKVm0EAKPmvV3xC9mEFDg87yoUyNIiTF6P5L8B/iztQn5beB2fMwXR47DD
         OOxQsnXW4c9g3At64cx/t4QoL483LOvjr3xVTwWDa2iHy6sI8MRnAgedtRImDS2fP+1N
         tfSPbJvFbstPgWPAgcACqvwDew3l4qFIkC0XUn0867wtPZb876gAUByTKJn6b2Y2GCXL
         x+7zzKhwrqBAImc3a/0lKZVxzMg2VQSZHyvW1da1/igqkzTHy56Ucl90UrfS7CZAe3w/
         AzBg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=1sNc22F6rFG0gNEAgRakLcwF2SVXVJs1bQPAOcq5dl0=;
        fh=JFoWAlcWeMgv7L98uB/U3xPGVpZdcwhvMg/Dt0ITh7w=;
        b=iOM82KK+CXLnsdUh//XR7yYXc0rkuoqOmVv4vIelFl6xbHwMFKBzH0Jki1Cl6/ebx6
         KnnazCTBFFPcTDyfLML3yH4XOIGI/Gshl6DGlnkwceGn/tK7Nc59LWgIKMH8jE9grTc0
         xMF5RelOY0J6dHl0speYjih1o07Iq23Hytw4agHxLXSbKKDcCf+PhqgG49mObS/8Nw6x
         lsqkPuJ2zDk/B8bR3soxutRM/lK3qM8r8W77cbLhHvaFpCY1B9WPHARtsLVOi2GNGVB2
         vzLBrZSqapME9U/RvptWTK8cpdpL3vpwf9jo0SItCrqHFuvQh4OhSHzLKMsW8A/eszMo
         VyaQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=M9pxSZcX;
       spf=pass (google.com: domain of davidgow@google.com designates 2607:f8b0:4864:20::f30 as permitted sender) smtp.mailfrom=davidgow@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755076688; x=1755681488; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=1sNc22F6rFG0gNEAgRakLcwF2SVXVJs1bQPAOcq5dl0=;
        b=sbh6e8NumECmnTvIf+sqgse35Zs4preUj9e594P7lka4VuHVkfm4w3QzueKrgaz0g4
         KG6Zft+eGAtSTlS0ZA/SkpFKxQbJtsWdWt4WIEAbYD0gSwpRJrpCrkXhK1zLS6eRqUvB
         fme/wBqDHqYwwoxGhkzNc0Aft4kZp6slzJeg9Az6qGvq9t1EkRqglE2vg5Cj5VS2haD3
         vbJSCeeyvyzL7HrWwvZbps0JlCX/gV7nieHKe4Qsq2G0KqmITqOsMt/Rsb00rq8FrkUZ
         sv3sYdHAcRZaLsTGQGdq+w9NezsXVQ7TUT7ZPr2mbcvePqpKCZ7hRwk5/x6bq0WKmKy5
         2jtw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755076688; x=1755681488;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=1sNc22F6rFG0gNEAgRakLcwF2SVXVJs1bQPAOcq5dl0=;
        b=UwHLoiUk9vG4+QjTUfl1YOTTXsEDMxUd/zC3j/YBdMW44nBiLKh9tbrC+LywDCANGl
         iAK2cw9Nhs7/1ub9A+X0ONMdpfi9TuVlGcJop9tXh33Ae9MyS13W2LTaTHygP6UmO2E2
         8ie2qSHMvE8D8KBdUa736fmC/iiLtFhEXIkElrBCOSsiiX9z48CRhzQHkpq4o3ZkKPBn
         09NTCThI+APcYBPBE7qXz+LX8umOH1vxxDj1g2ig802/7EiHP98S3CxdhyFwqrX8/Kcy
         AGHFFXq6rFHqO69hPND+ivVlzJlvl8p+I1w6myjJiLRIYBpk1JrOYXUGIxVfBfpFOuHp
         SSTA==
X-Forwarded-Encrypted: i=2; AJvYcCWFySHIICwQqkceyHPyLJ0cm1nAT2sJnxj+G1k9xr/GsMJQsTKTNe/6g2MWtxKYNmOi5lKxhA==@lfdr.de
X-Gm-Message-State: AOJu0YyNg6IiXbLG0N0XGuVy62sUayj/Aufp6UZzglNiANKC/8NfRaIE
	pkciYHo8kUoWF//MIVqyf/PmDRW1cEQkFyNlXYQBjznpeUFNAkjqaFkh
X-Google-Smtp-Source: AGHT+IHI/QyWlIQ77ZTLvSwhAzEbRPK7SYmXP6ru9e25CPRDpwFxO3CEytygf0pOggHiIxFpVuagyA==
X-Received: by 2002:a05:6871:ea0c:b0:2cc:4613:76f0 with SMTP id 586e51a60fabf-30cb5a557d2mr1191770fac.17.1755076688006;
        Wed, 13 Aug 2025 02:18:08 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcuaq20jBOnu63Ph7oyaHJ8t9rwZ426mvypQyZYU0F+1Q==
Received: by 2002:a05:6870:1495:b0:306:e7d7:f921 with SMTP id
 586e51a60fabf-30bfe748737ls3344738fac.1.-pod-prod-08-us; Wed, 13 Aug 2025
 02:18:07 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCU1HTnJvu3Nq76HCHF/8I6cBEWMrQLutNXlhzfXISLpprLri3NWJvpigTEwycUQwykTpU/vH7/zSOo=@googlegroups.com
X-Received: by 2002:a05:6808:4e0e:b0:434:e5c:3d7c with SMTP id 5614622812f47-435d54840a4mr987503b6e.9.1755076687029;
        Wed, 13 Aug 2025 02:18:07 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755076687; cv=none;
        d=google.com; s=arc-20240605;
        b=gIYLC6kmgTKhb/3evlHqQuWG6B9Ou03oVfBjmY8XXXY5dgm+YJc3ANq6D/SYDO7JDN
         56pKo0HI4jtPwpFl25vskJZQh6hmgtHptGz0LbGEwy0ctJ1XPyyAsMRxjgyXY35Md5A0
         3on2oFSocwgd18EITqj5BDBELLDWtT/Qiw4MzM4y18eTd+HLEd/Nc7GPzg9pKxE2wNXz
         DltEkAUjd6cDJ4nCwnEV037ej9FLrBNfVnsXIPmLg9F6UCXW+JJOAls7e3XhhTqYoume
         hLAp67vT3QNBoGFy8eZshb4IIoFU3UDp6NFxoXmILGoTSRlYrw7IqiY9gU1578vDQueE
         L43g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=AOCiblN7yz+tXqRCKXeE4oho4Aq4mn8NYcvlEwwM5e8=;
        fh=35D2fRCVwni7nC1b2BQv+agVLSSSZedrPdHGAe7Fidc=;
        b=in14cOnrAqg8V1/ZN1eJAID4lmcoFoOITyNjXb8028CGaZ3n3fXp3xSw4ukorWBCsl
         OwwouQckgY81fUdrUZnaFFZtGM3yxzIt9HNnTE1fjJgS3jHOncP5ScEz5vZjuWTo136T
         VWUAUfU2WI168KfMAm2vOoQeZpEHZ/m0fdUItzvKQKFjj1m2nZWi6omMshu1X4ACzreA
         hEyu9o/aj6SY17ePF8LxXCQtoIMXl8uknM5ho9HjsoITQdAxWD9yWgYxCBFokFDMNRF9
         o/1yYtpjqqxnKfN7feA2JCgxlP6HPmXWFqPKvqniT75F1CENk1saarg9ohj+9jxGGQo4
         wUUg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=M9pxSZcX;
       spf=pass (google.com: domain of davidgow@google.com designates 2607:f8b0:4864:20::f30 as permitted sender) smtp.mailfrom=davidgow@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-qv1-xf30.google.com (mail-qv1-xf30.google.com. [2607:f8b0:4864:20::f30])
        by gmr-mx.google.com with ESMTPS id 46e09a7af769-7436f973a43si123968a34.5.2025.08.13.02.18.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 13 Aug 2025 02:18:07 -0700 (PDT)
Received-SPF: pass (google.com: domain of davidgow@google.com designates 2607:f8b0:4864:20::f30 as permitted sender) client-ip=2607:f8b0:4864:20::f30;
Received: by mail-qv1-xf30.google.com with SMTP id 6a1803df08f44-70736b2ea12so33071746d6.1
        for <kasan-dev@googlegroups.com>; Wed, 13 Aug 2025 02:18:06 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXqCUwJL775YfF3YXHUFPdp3wVqFM1K/LTaa4wv9BgzvEU9lAfmyl3EoC3D61ZSqCoLpC50M2vbpGE=@googlegroups.com
X-Gm-Gg: ASbGncsYeT2D2X6MTzPr3XdKzV0MYm7L7ejPitbGDDNfXlXB3+1yaVSuMs5oyfgt+Ux
	qFQy+HcL8HZlAxbtbOEZU1zPlbC8VkJJCaxP9RXPa0DbvMfrwbdXa5oTz2LL2DfI3KUy2fIF+Mh
	f9KnFHsd+zvtTCwNeOxe2ntRQDaTuPnuW55jeEU347T1qDOzPx22X1sOedFEL9r9QZynWlIA8gv
	nl1vDqVmx66VAd1T2o=
X-Received: by 2002:a05:6214:2b0c:b0:706:aae8:ad48 with SMTP id
 6a1803df08f44-709e89a5a2amr25327886d6.35.1755076685764; Wed, 13 Aug 2025
 02:18:05 -0700 (PDT)
MIME-Version: 1.0
References: <20250811221739.2694336-1-marievic@google.com> <20250811221739.2694336-3-marievic@google.com>
In-Reply-To: <20250811221739.2694336-3-marievic@google.com>
From: "'David Gow' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 13 Aug 2025 17:17:53 +0800
X-Gm-Features: Ac12FXz2-Sx1MIKokqXPRrfeaeu1JViqVWhu-4LdWU5BDmZ2V8sMeaJfMHKLszc
Message-ID: <CABVgOSmViGQRfxEJ_WLjfByCo8tpg3X3rVFjeR7ez+rLnGFRtg@mail.gmail.com>
Subject: Re: [PATCH v2 2/7] kunit: Introduce param_init/exit for parameterized
 test context management
To: Marie Zhussupova <marievic@google.com>
Cc: rmoar@google.com, shuah@kernel.org, brendan.higgins@linux.dev, 
	mark.rutland@arm.com, elver@google.com, dvyukov@google.com, 
	lucas.demarchi@intel.com, thomas.hellstrom@linux.intel.com, 
	rodrigo.vivi@intel.com, linux-kselftest@vger.kernel.org, 
	kunit-dev@googlegroups.com, kasan-dev@googlegroups.com, 
	intel-xe@lists.freedesktop.org, dri-devel@lists.freedesktop.org, 
	linux-kernel@vger.kernel.org
Content-Type: multipart/signed; protocol="application/pkcs7-signature"; micalg=sha-256;
	boundary="00000000000077efa6063c3ba221"
X-Original-Sender: davidgow@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=M9pxSZcX;       spf=pass
 (google.com: domain of davidgow@google.com designates 2607:f8b0:4864:20::f30
 as permitted sender) smtp.mailfrom=davidgow@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
X-Original-From: David Gow <davidgow@google.com>
Reply-To: David Gow <davidgow@google.com>
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

--00000000000077efa6063c3ba221
Content-Type: text/plain; charset="UTF-8"

On Tue, 12 Aug 2025 at 06:17, Marie Zhussupova <marievic@google.com> wrote:
>
> Add (*param_init) and (*param_exit) function pointers to
> `struct kunit_case`. Users will be able to set them
> via the new KUNIT_CASE_PARAM_WITH_INIT() macro.
>
> param_init/exit will be invoked by kunit_run_tests() once before
> and once after the parameterized test, respectively.
> They will receive the `struct kunit` that holds the parameterized
> test context; facilitating init and exit for shared state.
>
> This patch also sets param_init/exit to None in
> rust/kernel/kunit.rs.
>
> Signed-off-by: Marie Zhussupova <marievic@google.com>
> ---

This mostly looks good to me, though there's one issue I've picked up:
we don't try to skip running the test if the param_init function
fails. I think we should do that, ideally in this series, but I'd live
with it in the try-catch support follow-up if you'd strongly prefer
it.

Otherwise, I think there's an argument that param_init/param_exit
should run even before/after non-parameterised tests. The
suite_init/suite_exit functions would run even in an empty suite, for
example. Though given it's useless to actually implement this, I'm
happy with it the way it is.

Further note on the need to skip the tests below.

Cheers,
-- David

>
> Changes in v2:
>
> - param init/exit were set to None
>   in rust/kernel/kunit.rs to fix the Rust breakage.
> - The name of __kunit_init_parent_test was
>   changed to kunit_init_parent_param_test and
>   its call was changed to happen only if the
>   test is parameterized.
> - The param_exit call was also moved inside
>   the check for if the test is parameterized.
> - KUNIT_CASE_PARAM_WITH_INIT() macro logic was changed
>   to not automatically set generate_params() to KUnit's
>   built-in generator function. Instead, the test user
>   will be asked to provide it themselves.
> - The comments and the commit message were changed to
>   reflect the parameterized testing terminology. See
>   the patch series cover letter change log for the
>   definitions.
>
> ---
>  include/kunit/test.h | 25 +++++++++++++++++++++++++
>  lib/kunit/test.c     | 20 ++++++++++++++++++++
>  rust/kernel/kunit.rs |  4 ++++
>  3 files changed, 49 insertions(+)
>
> diff --git a/include/kunit/test.h b/include/kunit/test.h
> index b47b9a3102f3..d2e1b986b161 100644
> --- a/include/kunit/test.h
> +++ b/include/kunit/test.h
> @@ -92,6 +92,8 @@ struct kunit_attributes {
>   * @name:     the name of the test case.
>   * @generate_params: the generator function for parameterized tests.
>   * @attr:     the attributes associated with the test
> + * @param_init: The init function to run before a parameterized test.
> + * @param_exit: The exit function to run after a parameterized test.
>   *
>   * A test case is a function with the signature,
>   * ``void (*)(struct kunit *)``
> @@ -128,6 +130,8 @@ struct kunit_case {
>         const char *name;
>         const void* (*generate_params)(const void *prev, char *desc);
>         struct kunit_attributes attr;
> +       int (*param_init)(struct kunit *test);
> +       void (*param_exit)(struct kunit *test);
>
>         /* private: internal use only. */
>         enum kunit_status status;
> @@ -218,6 +222,27 @@ static inline char *kunit_status_to_ok_not_ok(enum kunit_status status)
>                   .generate_params = gen_params,                                \
>                   .attr = attributes, .module_name = KBUILD_MODNAME}
>
> +/**
> + * KUNIT_CASE_PARAM_WITH_INIT - Define a parameterized KUnit test case with custom
> + * param_init() and param_exit() functions.
> + * @test_name: The function implementing the test case.
> + * @gen_params: The function to generate parameters for the test case.
> + * @init: A reference to the param_init() function to run before a parameterized test.
> + * @exit: A reference to the param_exit() function to run after a parameterized test.
> + *
> + * Provides the option to register param_init() and param_exit() functions.
> + * param_init/exit will be passed the parameterized test context and run once
> + * before and once after the parameterized test. The init function can be used
> + * to add resources to share between parameter runs, and any other setup logic.
> + * The exit function can be used to clean up resources that were not managed by
> + * the parameterized test, and any other teardown logic.
> + */
> +#define KUNIT_CASE_PARAM_WITH_INIT(test_name, gen_params, init, exit)          \
> +               { .run_case = test_name, .name = #test_name,                    \
> +                 .generate_params = gen_params,                                \
> +                 .param_init = init, .param_exit = exit,                       \
> +                 .module_name = KBUILD_MODNAME}
> +
>  /**
>   * struct kunit_suite - describes a related collection of &struct kunit_case
>   *
> diff --git a/lib/kunit/test.c b/lib/kunit/test.c
> index 14a8bd846939..49a5e6c30c86 100644
> --- a/lib/kunit/test.c
> +++ b/lib/kunit/test.c
> @@ -641,6 +641,19 @@ static void kunit_accumulate_stats(struct kunit_result_stats *total,
>         total->total += add.total;
>  }
>
> +static void kunit_init_parent_param_test(struct kunit_case *test_case, struct kunit *test)
> +{
> +       if (test_case->param_init) {
> +               int err = test_case->param_init(test);
> +
> +               if (err) {
> +                       kunit_err(test_case, KUNIT_SUBTEST_INDENT KUNIT_SUBTEST_INDENT
> +                               "# failed to initialize parent parameter test.");
> +                       test_case->status = KUNIT_FAILURE;
> +               }
> +       }
> +}
> +
>  int kunit_run_tests(struct kunit_suite *suite)
>  {
>         char param_desc[KUNIT_PARAM_DESC_SIZE];
> @@ -678,6 +691,7 @@ int kunit_run_tests(struct kunit_suite *suite)
>                         kunit_run_case_catch_errors(suite, test_case, &test);
>                         kunit_update_stats(&param_stats, test.status);
>                 } else {
> +                       kunit_init_parent_param_test(test_case, &test);

Should we skip the rest of the test if this fails? I think ultimately
we should -- that's the behaviour we have for, e.g.,
suite_init/suite_exit, though we don't skip the rest of the test if an
individual parameter fails.

Regardless, it seems likely that generate_params will crash if the
init failed for any test making serious use of it. But then again,
this is already a bit fragile due to the lack of try/catch around the
generate_params, etc.

My preference here would be to skip the rest of the test (and the
param_exit function) if the parent test is marked FAILED immediately
after this line. I could live with pushing that back to the follow-up
which adds the try-catch support, though, if you'd really prefer it.


>                         /* Get initial param. */
>                         param_desc[0] = '\0';
>                         /* TODO: Make generate_params try-catch */
> @@ -714,6 +728,12 @@ int kunit_run_tests(struct kunit_suite *suite)
>                                 param_desc[0] = '\0';
>                                 curr_param = test_case->generate_params(curr_param, param_desc);
>                         }
> +                       /*
> +                        * TODO: Put into a try catch. Since we don't need suite->exit
> +                        * for it we can't reuse kunit_try_run_cleanup for this yet.
> +                        */
> +                       if (test_case->param_exit)
> +                               test_case->param_exit(&test);
>                         /* TODO: Put this kunit_cleanup into a try-catch. */
>                         kunit_cleanup(&test);
>                 }
> diff --git a/rust/kernel/kunit.rs b/rust/kernel/kunit.rs
> index 4b8cdcb21e77..cda64574b44d 100644
> --- a/rust/kernel/kunit.rs
> +++ b/rust/kernel/kunit.rs
> @@ -207,6 +207,8 @@ pub const fn kunit_case(
>          status: kernel::bindings::kunit_status_KUNIT_SUCCESS,
>          module_name: core::ptr::null_mut(),
>          log: core::ptr::null_mut(),
> +        param_init: None,
> +        param_exit: None,
>      }
>  }
>
> @@ -226,6 +228,8 @@ pub const fn kunit_case_null() -> kernel::bindings::kunit_case {
>          status: kernel::bindings::kunit_status_KUNIT_SUCCESS,
>          module_name: core::ptr::null_mut(),
>          log: core::ptr::null_mut(),
> +        param_init: None,
> +        param_exit: None,
>      }
>  }
>
> --
> 2.51.0.rc0.205.g4a044479a3-goog
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CABVgOSmViGQRfxEJ_WLjfByCo8tpg3X3rVFjeR7ez%2BrLnGFRtg%40mail.gmail.com.

--00000000000077efa6063c3ba221
Content-Type: application/pkcs7-signature; name="smime.p7s"
Content-Transfer-Encoding: base64
Content-Disposition: attachment; filename="smime.p7s"
Content-Description: S/MIME Cryptographic Signature

MIIUnQYJKoZIhvcNAQcCoIIUjjCCFIoCAQExDzANBglghkgBZQMEAgEFADALBgkqhkiG9w0BBwGg
ghIEMIIGkTCCBHmgAwIBAgIQfofDAVIq0iZG5Ok+mZCT2TANBgkqhkiG9w0BAQwFADBMMSAwHgYD
VQQLExdHbG9iYWxTaWduIFJvb3QgQ0EgLSBSNjETMBEGA1UEChMKR2xvYmFsU2lnbjETMBEGA1UE
AxMKR2xvYmFsU2lnbjAeFw0yMzA0MTkwMzUzNDdaFw0zMjA0MTkwMDAwMDBaMFQxCzAJBgNVBAYT
AkJFMRkwFwYDVQQKExBHbG9iYWxTaWduIG52LXNhMSowKAYDVQQDEyFHbG9iYWxTaWduIEF0bGFz
IFI2IFNNSU1FIENBIDIwMjMwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDYydcdmKyg
4IBqVjT4XMf6SR2Ix+1ChW2efX6LpapgGIl63csmTdJQw8EcbwU9C691spkltzTASK2Ayi4aeosB
mk63SPrdVjJNNTkSbTowej3xVVGnYwAjZ6/qcrIgRUNtd/mbtG7j9W80JoP6o2Szu6/mdjb/yxRM
KaCDlloE9vID2jSNB5qOGkKKvN0x6I5e/B1Y6tidYDHemkW4Qv9mfE3xtDAoe5ygUvKA4KHQTOIy
VQEFpd/ZAu1yvrEeA/egkcmdJs6o47sxfo9p/fGNsLm/TOOZg5aj5RHJbZlc0zQ3yZt1wh+NEe3x
ewU5ZoFnETCjjTKz16eJ5RE21EmnCtLb3kU1s+t/L0RUU3XUAzMeBVYBEsEmNnbo1UiiuwUZBWiJ
vMBxd9LeIodDzz3ULIN5Q84oYBOeWGI2ILvplRe9Fx/WBjHhl9rJgAXs2h9dAMVeEYIYkvW+9mpt
BIU9cXUiO0bky1lumSRRg11fOgRzIJQsphStaOq5OPTb3pBiNpwWvYpvv5kCG2X58GfdR8SWA+fm
OLXHcb5lRljrS4rT9MROG/QkZgNtoFLBo/r7qANrtlyAwPx5zPsQSwG9r8SFdgMTHnA2eWCZPOmN
1Tt4xU4v9mQIHNqQBuNJLjlxvalUOdTRgw21OJAFt6Ncx5j/20Qw9FECnP+B3EPVmQIDAQABo4IB
ZTCCAWEwDgYDVR0PAQH/BAQDAgGGMDMGA1UdJQQsMCoGCCsGAQUFBwMCBggrBgEFBQcDBAYJKwYB
BAGCNxUGBgkrBgEEAYI3FQUwEgYDVR0TAQH/BAgwBgEB/wIBADAdBgNVHQ4EFgQUM7q+o9Q5TSoZ
18hmkmiB/cHGycYwHwYDVR0jBBgwFoAUrmwFo5MT4qLn4tcc1sfwf8hnU6AwewYIKwYBBQUHAQEE
bzBtMC4GCCsGAQUFBzABhiJodHRwOi8vb2NzcDIuZ2xvYmFsc2lnbi5jb20vcm9vdHI2MDsGCCsG
AQUFBzAChi9odHRwOi8vc2VjdXJlLmdsb2JhbHNpZ24uY29tL2NhY2VydC9yb290LXI2LmNydDA2
BgNVHR8ELzAtMCugKaAnhiVodHRwOi8vY3JsLmdsb2JhbHNpZ24uY29tL3Jvb3QtcjYuY3JsMBEG
A1UdIAQKMAgwBgYEVR0gADANBgkqhkiG9w0BAQwFAAOCAgEAVc4mpSLg9A6QpSq1JNO6tURZ4rBI
MkwhqdLrEsKs8z40RyxMURo+B2ZljZmFLcEVxyNt7zwpZ2IDfk4URESmfDTiy95jf856Hcwzdxfy
jdwx0k7n4/0WK9ElybN4J95sgeGRcqd4pji6171bREVt0UlHrIRkftIMFK1bzU0dgpgLMu+ykJSE
0Bog41D9T6Swl2RTuKYYO4UAl9nSjWN6CVP8rZQotJv8Kl2llpe83n6ULzNfe2QT67IB5sJdsrNk
jIxSwaWjOUNddWvCk/b5qsVUROOuctPyYnAFTU5KY5qhyuiFTvvVlOMArFkStNlVKIufop5EQh6p
jqDGT6rp4ANDoEWbHKd4mwrMtvrh51/8UzaJrLzj3GjdkJ/sPWkDbn+AIt6lrO8hbYSD8L7RQDqK
C28FheVr4ynpkrWkT7Rl6npWhyumaCbjR+8bo9gs7rto9SPDhWhgPSR9R1//WF3mdHt8SKERhvtd
NFkE3zf36V9Vnu0EO1ay2n5imrOfLkOVF3vtAjleJnesM/R7v5tMS0tWoIr39KaQNURwI//WVuR+
zjqIQVx5s7Ta1GgEL56z0C5GJoNE1LvGXnQDyvDO6QeJVThFNgwkossyvmMAaPOJYnYCrYXiXXle
A6TpL63Gu8foNftUO0T83JbV/e6J8iCOnGZwZDrubOtYn1QwggWDMIIDa6ADAgECAg5F5rsDgzPD
hWVI5v9FUTANBgkqhkiG9w0BAQwFADBMMSAwHgYDVQQLExdHbG9iYWxTaWduIFJvb3QgQ0EgLSBS
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
jmkLAgMBAAGjggHgMIIB3DAeBgNVHREEFzAVgRNkYXZpZGdvd0Bnb29nbGUuY29tMA4GA1UdDwEB
/wQEAwIFoDAdBgNVHSUEFjAUBggrBgEFBQcDBAYIKwYBBQUHAwIwHQYDVR0OBBYEFBp5bTxrTm/d
WMmRETO8lNkA4c7fMFgGA1UdIARRME8wCQYHZ4EMAQUBAjBCBgorBgEEAaAyCgMDMDQwMgYIKwYB
BQUHAgEWJmh0dHBzOi8vd3d3Lmdsb2JhbHNpZ24uY29tL3JlcG9zaXRvcnkvMAwGA1UdEwEB/wQC
MAAwgZoGCCsGAQUFBwEBBIGNMIGKMD4GCCsGAQUFBzABhjJodHRwOi8vb2NzcC5nbG9iYWxzaWdu
LmNvbS9jYS9nc2F0bGFzcjZzbWltZWNhMjAyMzBIBggrBgEFBQcwAoY8aHR0cDovL3NlY3VyZS5n
bG9iYWxzaWduLmNvbS9jYWNlcnQvZ3NhdGxhc3I2c21pbWVjYTIwMjMuY3J0MB8GA1UdIwQYMBaA
FDO6vqPUOU0qGdfIZpJogf3BxsnGMEYGA1UdHwQ/MD0wO6A5oDeGNWh0dHA6Ly9jcmwuZ2xvYmFs
c2lnbi5jb20vY2EvZ3NhdGxhc3I2c21pbWVjYTIwMjMuY3JsMA0GCSqGSIb3DQEBCwUAA4ICAQBF
tO3/N2l9hTaij/K0xCpLwIlrqpNo0nMAvvG5LPQQjSeHnTh06tWTgsPCOJ65GX+bqWRDwGTu8WTq
c5ihCNOikBs25j82yeLkfdbeN/tzRGUb2RD+8n9I3CnyMSG49U2s0ZdncsrIVFh47KW2TpHTF7R8
N1dri01wPg8hw4u0+XoczR2TiBrBOISKmAlkAi+P9ivT31gSHdbopoL4x0V2Ow9IOp0chrQQUZtP
KBytLhzUzd9wIsE0QMNDbw6jeG8+a4sd17zpXSbBywIGw7sEvPtnBjMaf5ib3kznlOne6tuDVx4y
QFExTCSrP3OTMUkNbpIdgzg2CHQ2aB8i8YsTZ8Q8Q8ztPJ+xDNsqBUeYxILLjTjxQQovToqipB3f
6IMyk+lWCdDS+iCLYZULV1BTHSdwp1NM3t4jZ8TMlV+JzAyRqz4lzSl8ptkFhKBJ7w2tDrZ3BEXB
8ASUByRxeh+pC1Z5/HhqfiWMVPjaWmlRRJVlRk+ObKIv2CblwxMYlo2Mn8rrbEDyfum1RTMW55Z6
Vumvw5QTHe29TYxSiusovM6OD5y0I+4zaIaYDx/AtF0mMOFXb1MDyynf1CDxhtkgnrBUseHSOU2e
MYs7IqzRap5xsgpJS+t7cp/P8fdlCNvsXss9zZa279tKwaxR0U2IzGxRGsWKGxDysn1HT6pqMDGC
Al0wggJZAgEBMGgwVDELMAkGA1UEBhMCQkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2ExKjAo
BgNVBAMTIUdsb2JhbFNpZ24gQXRsYXMgUjYgU01JTUUgQ0EgMjAyMwIQAUXA7LnOuRz2DvkWTeMc
0TANBglghkgBZQMEAgEFAKCBxzAvBgkqhkiG9w0BCQQxIgQgrZpWgUr4FfrLZltBNDmsxRIiT+08
8c0qi6TtJg3ZyBgwGAYJKoZIhvcNAQkDMQsGCSqGSIb3DQEHATAcBgkqhkiG9w0BCQUxDxcNMjUw
ODEzMDkxODA2WjBcBgkqhkiG9w0BCQ8xTzBNMAsGCWCGSAFlAwQBKjALBglghkgBZQMEARYwCwYJ
YIZIAWUDBAECMAoGCCqGSIb3DQMHMAsGCSqGSIb3DQEBBzALBglghkgBZQMEAgEwDQYJKoZIhvcN
AQEBBQAEggEAbrAnrrTUalgSYjTKqBD203DISqLVJ2AoZvXjq2JsEN8XociY0RUMZRvom4HhfcnU
6GNtpPy7Sl83lNrIJnW7wIJORTfJoBr2mfCQCqkgjfxAGxPxNhdD/+DvZqZfHv1j+97uXNJfKDbs
2bnnGfIh96kMFyVzDZF3YXH0OyNL5EQsFCKO+2Hj8RoxgmEGTrH1eYFWlXAI78QvftiCQG8Wx05H
0Nb79sUDE/rIcPBo23ItZfsBGbICNgCm4e4Z+Ftvv3LezawCA2xlHjhAi0NrImTFEWUcRPXgqdqC
LI9NuI+5C+t7JHuTsSV4dN6AYX7VCXHDdq0FN+QptJvg6YILFw==
--00000000000077efa6063c3ba221--
