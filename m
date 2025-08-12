Return-Path: <kasan-dev+bncBDPPVSUFVUPBBKP553CAMGQEOW2PDZA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf37.google.com (mail-qv1-xf37.google.com [IPv6:2607:f8b0:4864:20::f37])
	by mail.lfdr.de (Postfix) with ESMTPS id 146F6B23BBE
	for <lists+kasan-dev@lfdr.de>; Wed, 13 Aug 2025 00:22:35 +0200 (CEST)
Received: by mail-qv1-xf37.google.com with SMTP id 6a1803df08f44-7073a5f61a6sf109562006d6.0
        for <lists+kasan-dev@lfdr.de>; Tue, 12 Aug 2025 15:22:35 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755037354; cv=pass;
        d=google.com; s=arc-20240605;
        b=R7wORL85EJFL1QVfJ/k4utkgvq6JqFjkkzF4soFsXu0/Coa5ds3QNFIi8+LUVpSZPO
         0u3B0ao31yZrJsLLo+kzEc50471zN2gVh5vp1IcsRm+KWxhtBJQ7jszpTeZAlakYINHV
         D5wDbvcuDJjs1AhIVmBUefC1n2/bziD3kMMJmkamIOYuU/AnJiJxqX9TFuKRNUKY0PLQ
         dqEmqrft7TWoWqCCdQcicmjzqiPRjDz/R0+CX1VipLO3fgIla97sliJE7aH3PwOIALW1
         5uZq5yJrvwFy9nn/7kKLN9b6CLATqXWIlS5XYtLDwaoV28nhOyPFhgtwia/0rKBKRzaY
         9JVw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=HZV9DngrBJ0irQipkm3k/x5hPq/h404lpjjYAO3B/As=;
        fh=cEOUwsmWoUmmmyL8DTrXO6zBN88WKaQnrKW8gotRQ3M=;
        b=N5nUjT89jAIf5G03TEcHN8Lo+Q56BHBSjBVv3N3JNUgT3+jHMOkbhQoIRPNHZ1Hf4o
         nE3rTZewptC7VVsIPuJJIo5dd7ZG1dHa2vwMq+3mrpnGm7j1e0+IHf1KXh/C065f4yMk
         C+HNCCww+Jg9bUXWDcLCsbBLJNd/ahLr0zL4TR66bdvuX8k7IDbPAP45TCnPQ99XzCSr
         +yn7w1YvOHT32iBxgkQ4sSUmRA3obQTGUV+o5nYxh6hzqGbsi2lk7+4JZy1u+BBWEgor
         w4s+xk2dvdggiCApqRT9ZXR12bWbACCCdznpnYk70/9tmjxd02X48GojectoRG1/uD/Y
         nMBg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=FW89uxTN;
       spf=pass (google.com: domain of rmoar@google.com designates 2607:f8b0:4864:20::f2d as permitted sender) smtp.mailfrom=rmoar@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755037354; x=1755642154; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=HZV9DngrBJ0irQipkm3k/x5hPq/h404lpjjYAO3B/As=;
        b=VonXe5yRlaGUwJZSus9c9vaSjXT6gWaxf+dmilkLmUcqanoHFZHxqqoL/HjXWz5BME
         CBIL3JLwXos5dzQgovFnJKgYGtM/uDw0uRdZoY6wGm95BhaqM3642uZhXMKjlgPwsu5Y
         PFOHIlnyjk0BLO5rKZeRuFyMnIy1Yd3fmHHhtVCriPHxgiAwYoTBmJtMIRjOn15FBoo5
         eWP3idGbAR3D6u81e7AYtGsY0I0aCT9HFbufp4Yf/2kPX1hs7IOJicLd+SmqnqteIUNg
         PendKxSuc1luDnJs4i4LfPi778NSy5peFmnAczMWldtpVRcGWrCh1Fs0fP8MO0W3kuHx
         B6ww==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755037354; x=1755642154;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=HZV9DngrBJ0irQipkm3k/x5hPq/h404lpjjYAO3B/As=;
        b=HntIOTYHacQZHRJUqFURC2bk7pMuhPdUZ8vOi82O6whOCP24CBtRqWQ5eRjmmne7Lb
         RBDByrViUOhwzIMi9d8fjDLy504cN/jpA3QLsW9nxDFbgbTMZASDj2EihA42gqE9/GdD
         j/RM3t3d6S15XmHQQf3r9WlaaAhT89rxgmcsThn85bMcFjLLDoIlg+yze4rpdxMCnB9Y
         YOnd+YkAjQK0Y3nnklR/tiXbVUkjTFJE6pOMDahTG6ykyOAQMUhbLcs7zLtVrAnlB1nE
         RnWljzs6jPLq1YPmNOklchdH1vdrKqYaXgJG2ZQ4dc1KHbhHgqu4kGPrQ44WRJ1Zjc+5
         sYtA==
X-Forwarded-Encrypted: i=2; AJvYcCUEH/61GXTQFCpeNmapBmyXSmzelse1sl8jYUVEHUhFyoNyhfueFfx+gVFBc5INGiqOHLdxfg==@lfdr.de
X-Gm-Message-State: AOJu0YwNt/lmp4r6kZwJs+0Ir1b55klfy+1c4QRR4fIJ9mdA7naPW5au
	7mc4yLSSRNK9zI9aXgi6KMODx8EWdYK+xVG3TJkJBblYwmm9QUfngHgS
X-Google-Smtp-Source: AGHT+IEOdPIgb48s7UipV0RHgh5Pnf4ze7Ktt8Kcdd7hCwdqlPJUrPc/HdOst3pZNIqnW735eiJlcg==
X-Received: by 2002:a05:6214:21a8:b0:705:538:65ab with SMTP id 6a1803df08f44-709e89af500mr13000916d6.39.1755037353667;
        Tue, 12 Aug 2025 15:22:33 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcw0Y/Xbzgo85tLOdLv6DV+KkD5VQ2hr/G45r4nC+kAgQ==
Received: by 2002:a05:6214:2425:b0:707:6c93:e847 with SMTP id
 6a1803df08f44-709883a67eels101749356d6.2.-pod-prod-07-us; Tue, 12 Aug 2025
 15:22:33 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVPvu+12vbA2GASGJtMyyVnipLqZuTtxg6IFCCpFhRmJkLVYfx+dyKuGG+vjg9UTnJ5/+FqsCKIC3A=@googlegroups.com
X-Received: by 2002:a05:6102:ccf:b0:4e6:d7af:a7b1 with SMTP id ada2fe7eead31-50e4e8c66b0mr376808137.10.1755037352888;
        Tue, 12 Aug 2025 15:22:32 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755037352; cv=none;
        d=google.com; s=arc-20240605;
        b=dqGvUVc56Wc9dUQEd3/jHZVeP/fHb5bo5MwneBUbwQ7Yl1hifybw9rEPvCROVww1Bg
         elO47x9nSCIjyCPnrohoNJmHi+aYz8hC7jNsimjrIOfSsOSrAT8J0k9h5W+EiP58KXZn
         Tc/4JwPTjGEaqlIXeawFMkaGeaDaUOQhNI9TOKhbTCKcU4hFH2cDpII1PwHEDir6mS4T
         cqbii43RaoBY1aD/4rwMTQrGWSu5kNlzBiuFsVFPT9p10ETLH2U3AKX2TtsBs3pGmz/P
         MBd1KUD1eD6gQTfnlUIcvMzzClxrnl/A3YJ0cCLkjZYpsP1fM9a1MzKWwF+7G9vwufOT
         Te9w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=opcJeE+7tPfMMHi8foMn39Eit1OmyT4Dsk8XguKPJ60=;
        fh=PD2HtGqnxkA/xibkUwLkP8Id/dSlY/k0QcCC2vDAdMA=;
        b=ftgbAyWNUVqCAF07JYYehWPUQVTwgGCqoh60JHwpHWrQRqDxHUfnjK01y37rY4aN9w
         qU7EZ8/QIH3y4D7xfn8adOdoXZ0D67x9tsMTVamfM5UHyohXp41CSUIAH+Er/vZ6vBJu
         jC/KbxPxW1UCJF/unsaDPIX9XxaRavfEJ/T7w+Lp7g0H/FAYjXFu1uGd0D25yd+gfD1X
         HDZBdCCNpt29AUMM/nb9ffKMFYKcUiXAX2cXoj+O4VvcP5MFfxnG6R6FO/rYWYVM0irX
         tDVFfnLdlRIrB7UOpv/lqaV/gAUoM2QSHLNethjZP+Ofsyt/rg7lYHnjq1viaZ43XQdJ
         KL7g==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=FW89uxTN;
       spf=pass (google.com: domain of rmoar@google.com designates 2607:f8b0:4864:20::f2d as permitted sender) smtp.mailfrom=rmoar@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-qv1-xf2d.google.com (mail-qv1-xf2d.google.com. [2607:f8b0:4864:20::f2d])
        by gmr-mx.google.com with ESMTPS id 71dfb90a1353d-539b027ab2asi682259e0c.4.2025.08.12.15.22.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 12 Aug 2025 15:22:32 -0700 (PDT)
Received-SPF: pass (google.com: domain of rmoar@google.com designates 2607:f8b0:4864:20::f2d as permitted sender) client-ip=2607:f8b0:4864:20::f2d;
Received: by mail-qv1-xf2d.google.com with SMTP id 6a1803df08f44-7075ccb168bso49020766d6.0
        for <kasan-dev@googlegroups.com>; Tue, 12 Aug 2025 15:22:32 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUZzjIhfxrOX9qO/67anydxZ4sRuepO4/JnRAiRX0tuWLvLR3HQe2cNZQET3xxyt3q8/f8+h3ypqeo=@googlegroups.com
X-Gm-Gg: ASbGncuAN8khG8Lku9RuzkDarYrLr38ctrAjn37lZNhDcodtcYnMyoZonbmSzdCzQtG
	MwKP6PUuf5m/6ifkjuJMbEUnAyj3Q4HmV/1wDyJomvW6kNxe6ald/whVHlyeP0WEukqj5o/qINl
	wJhwgM5elLH6MRZqlmrewzAnCXa/DWf161sc4T+4DbQm7V37i5AIySfxZ+tpjYlkp1ertdVc46Q
	ONOmQ==
X-Received: by 2002:ad4:4ee4:0:b0:709:995d:d4a8 with SMTP id
 6a1803df08f44-709e89fbe74mr11993096d6.45.1755037352008; Tue, 12 Aug 2025
 15:22:32 -0700 (PDT)
MIME-Version: 1.0
References: <20250811221739.2694336-1-marievic@google.com> <20250811221739.2694336-3-marievic@google.com>
In-Reply-To: <20250811221739.2694336-3-marievic@google.com>
From: "'Rae Moar' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 12 Aug 2025 18:22:20 -0400
X-Gm-Features: Ac12FXwV9IiY0435kgKra-rYAqebBZvna6EsVJ_KwFDNUaF3nei7y9HV2jQMX64
Message-ID: <CA+GJov6zSuMrPU3PLsdZofDw4Gegrqnp=gCxY5AOwZHtqB2cSw@mail.gmail.com>
Subject: Re: [PATCH v2 2/7] kunit: Introduce param_init/exit for parameterized
 test context management
To: Marie Zhussupova <marievic@google.com>
Cc: davidgow@google.com, shuah@kernel.org, brendan.higgins@linux.dev, 
	mark.rutland@arm.com, elver@google.com, dvyukov@google.com, 
	lucas.demarchi@intel.com, thomas.hellstrom@linux.intel.com, 
	rodrigo.vivi@intel.com, linux-kselftest@vger.kernel.org, 
	kunit-dev@googlegroups.com, kasan-dev@googlegroups.com, 
	intel-xe@lists.freedesktop.org, dri-devel@lists.freedesktop.org, 
	linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: rmoar@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=FW89uxTN;       spf=pass
 (google.com: domain of rmoar@google.com designates 2607:f8b0:4864:20::f2d as
 permitted sender) smtp.mailfrom=rmoar@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
X-Original-From: Rae Moar <rmoar@google.com>
Reply-To: Rae Moar <rmoar@google.com>
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

On Mon, Aug 11, 2025 at 6:17=E2=80=AFPM Marie Zhussupova <marievic@google.c=
om> wrote:
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

Hello!

This patch looks good to me. Thank you for fixing the Rust breakage! I
also appreciate the terminology changes here as well.

Reviewed-by: Rae Moar <rmoar@google.com>

Thanks!

-Rae

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
> @@ -218,6 +222,27 @@ static inline char *kunit_status_to_ok_not_ok(enum k=
unit_status status)
>                   .generate_params =3D gen_params,                       =
         \
>                   .attr =3D attributes, .module_name =3D KBUILD_MODNAME}
>
> +/**
> + * KUNIT_CASE_PARAM_WITH_INIT - Define a parameterized KUnit test case w=
ith custom
> + * param_init() and param_exit() functions.
> + * @test_name: The function implementing the test case.
> + * @gen_params: The function to generate parameters for the test case.
> + * @init: A reference to the param_init() function to run before a param=
eterized test.
> + * @exit: A reference to the param_exit() function to run after a parame=
terized test.
> + *
> + * Provides the option to register param_init() and param_exit() functio=
ns.
> + * param_init/exit will be passed the parameterized test context and run=
 once
> + * before and once after the parameterized test. The init function can b=
e used
> + * to add resources to share between parameter runs, and any other setup=
 logic.
> + * The exit function can be used to clean up resources that were not man=
aged by
> + * the parameterized test, and any other teardown logic.
> + */
> +#define KUNIT_CASE_PARAM_WITH_INIT(test_name, gen_params, init, exit)   =
       \
> +               { .run_case =3D test_name, .name =3D #test_name,         =
           \
> +                 .generate_params =3D gen_params,                       =
         \
> +                 .param_init =3D init, .param_exit =3D exit,            =
           \
> +                 .module_name =3D KBUILD_MODNAME}
> +
>  /**
>   * struct kunit_suite - describes a related collection of &struct kunit_=
case
>   *
> diff --git a/lib/kunit/test.c b/lib/kunit/test.c
> index 14a8bd846939..49a5e6c30c86 100644
> --- a/lib/kunit/test.c
> +++ b/lib/kunit/test.c
> @@ -641,6 +641,19 @@ static void kunit_accumulate_stats(struct kunit_resu=
lt_stats *total,
>         total->total +=3D add.total;
>  }
>
> +static void kunit_init_parent_param_test(struct kunit_case *test_case, s=
truct kunit *test)
> +{
> +       if (test_case->param_init) {
> +               int err =3D test_case->param_init(test);
> +
> +               if (err) {
> +                       kunit_err(test_case, KUNIT_SUBTEST_INDENT KUNIT_S=
UBTEST_INDENT
> +                               "# failed to initialize parent parameter =
test.");
> +                       test_case->status =3D KUNIT_FAILURE;
> +               }
> +       }
> +}
> +
>  int kunit_run_tests(struct kunit_suite *suite)
>  {
>         char param_desc[KUNIT_PARAM_DESC_SIZE];
> @@ -678,6 +691,7 @@ int kunit_run_tests(struct kunit_suite *suite)
>                         kunit_run_case_catch_errors(suite, test_case, &te=
st);
>                         kunit_update_stats(&param_stats, test.status);
>                 } else {
> +                       kunit_init_parent_param_test(test_case, &test);
>                         /* Get initial param. */
>                         param_desc[0] =3D '\0';
>                         /* TODO: Make generate_params try-catch */
> @@ -714,6 +728,12 @@ int kunit_run_tests(struct kunit_suite *suite)
>                                 param_desc[0] =3D '\0';
>                                 curr_param =3D test_case->generate_params=
(curr_param, param_desc);
>                         }
> +                       /*
> +                        * TODO: Put into a try catch. Since we don't nee=
d suite->exit
> +                        * for it we can't reuse kunit_try_run_cleanup fo=
r this yet.
> +                        */
> +                       if (test_case->param_exit)
> +                               test_case->param_exit(&test);
>                         /* TODO: Put this kunit_cleanup into a try-catch.=
 */
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
> @@ -226,6 +228,8 @@ pub const fn kunit_case_null() -> kernel::bindings::k=
unit_case {
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

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
A%2BGJov6zSuMrPU3PLsdZofDw4Gegrqnp%3DgCxY5AOwZHtqB2cSw%40mail.gmail.com.
