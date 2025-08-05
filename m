Return-Path: <kasan-dev+bncBDPPVSUFVUPBBMWBZDCAMGQEGDRTHUI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x540.google.com (mail-pg1-x540.google.com [IPv6:2607:f8b0:4864:20::540])
	by mail.lfdr.de (Postfix) with ESMTPS id 791E4B1B73F
	for <lists+kasan-dev@lfdr.de>; Tue,  5 Aug 2025 17:18:12 +0200 (CEST)
Received: by mail-pg1-x540.google.com with SMTP id 41be03b00d2f7-b2fa1a84566sf4498816a12.1
        for <lists+kasan-dev@lfdr.de>; Tue, 05 Aug 2025 08:18:12 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1754407091; cv=pass;
        d=google.com; s=arc-20240605;
        b=gZBOibx8lOqRnQF7bnPmxlpIatajXXk1whYTf7d9SBEWP2/kBOn3xm9P9fmisucpdU
         +ZYSwZM170gOyAfp4W9IV3IHy2mcaha7faQmlj7Vc35ERFXmXTfNkYXpu0Ryc8L7tCqV
         L9S4XeQB5rMl/Ln2rE3ZLWUJtwB1wPSIPOK8pgajIAt2ZjCGRRZtOCNrGBWwr2VSL6+U
         XSNMmeiX106cD/DZfgkt2o6h4JL/yXzPhg4X7nDidL7LLRF6jLekQrc9pSCX9Yi1uLwE
         5Z32HxgJ/P9D97WLFeExQbb28fC6EU/cVfE1CbPs90jstJbT5YmkKeP9H0EwQJlOnlta
         Eo6g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=PdNWn3UMzMUZ+x3Osd67w+V375YfRyppvsKPRFw7L8U=;
        fh=/w4v02kUVJInn9m1kn4t/qHOS65HD09hJ/PgX3xNYmI=;
        b=SCEsV/gN4jUc7w95J8fMJlc0m0NA/t9dOe2fFabuI+leXH4Ck+S2VEtwiVKdzQQA58
         HxAxl5v9hN+rzGc12fzuSRktguVXF/1uwQPWvfSB2msACLkJHsth1nxWatOBFnHL4gud
         4Ub5ciZC5cYEcxWxduuWwd5dMR3f8hrEMF1PZFHyyU3yhP5TcG/ZYjm9zs3nxVjBqNqc
         aI9fZ+Sx6WS0nGNbYQK5IbRBKPa/+8z8hUufSGHfclYlRhq7XUyjUf0EvkUd9+XPmMLN
         QvTb5wK5pbCzmXPfldJm0d+YQ1mITKV0qnAw0ApUgkPPSMwZMadGbwbe8/GJpQmtbzoF
         sC7A==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=rw+ZYlVS;
       spf=pass (google.com: domain of rmoar@google.com designates 2607:f8b0:4864:20::82a as permitted sender) smtp.mailfrom=rmoar@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1754407091; x=1755011891; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=PdNWn3UMzMUZ+x3Osd67w+V375YfRyppvsKPRFw7L8U=;
        b=rbThYSu3nxwoszaxpmpGMVE9KaQEG1ig5PhhcZlNYgiC3X6iVX213Ihtzl2tEqoeFk
         rr24BIiCqZsL6JnNv2+/jWHlWR/lTVnUnEN2t/kFVmYJGYKyJoKZ6xDmgaiEddbUPMJ1
         WEHw2lbViZQ3Fl0nvfsqs7qhEAgoZht/HWKZEk0H3y5KEfK1ZjxQHLsB73J80dtOiZaR
         9IencJgYB42wtAjjBXWbQSxeF5qkaoQF5eSHkIUsJNRBVLWR4XuIOx5BPwPJHqwocHW/
         eqyLDsDTYPJ26BTgRjyWcwvSdsIi+LWX+quSzPWrna9iusiwePkpZWS0lQCx/9RRlq7A
         zXcg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1754407091; x=1755011891;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=PdNWn3UMzMUZ+x3Osd67w+V375YfRyppvsKPRFw7L8U=;
        b=vpqHwI7MPWLvnhpMuMJR8a2ARbB0wGd+PteiPzBDfocDy9CwAzR4cCLjHfraRBFWu6
         VQpJADVaIA4tLxvBW5wQWI9A9dUFzfjjxUe3Ehn1TDlNMnNM5IrDozy38KuXgCbue20f
         /owG2sN6p5Jx290xCbLP9piNIU8Usj6ZagOxy3kQvsMM0X8QLfOXnrmk+laJifoaLcik
         3I9b6pdX8N8HbJIUUu0NcM2GZEl+eI9WR+ospwHyBdNGk4m4GwSzzh3s761FNJSSI2em
         OQ/d2vtLygqvomp4hiVFMvQ/jtsBtD8U5123JRRA4EkK8gDDzy1IEOb7U07YxSatGgRW
         vr7g==
X-Forwarded-Encrypted: i=2; AJvYcCUGoH78cOFcBgOeLZJQ4slHhJEXgzMusSMnHXBdp4/gOS8X6dZsfoKeLtPeAs8zuZAfvQSpZg==@lfdr.de
X-Gm-Message-State: AOJu0YzsoBDXwG9nk00r5eLWNoxCDvYYTNKptFl7jz1xRJ8ohvLQ/FBr
	m2CRfD2MZcD7aYgmz5oJ9iF35VnG7ZSM7MmUx9LZHH//c70Z3oux73/o
X-Google-Smtp-Source: AGHT+IE3jfDYN8AdV/n09M0IWvsXUUc6SVHXo2dgxsbSs16+mSpvcCGsfZcsl/pU87mEA1IwFgNbpw==
X-Received: by 2002:a17:903:3d10:b0:240:72bb:db0b with SMTP id d9443c01a7336-24246f7850emr179185165ad.21.1754407090437;
        Tue, 05 Aug 2025 08:18:10 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZew/vmfIQ7xQi1nYI/gvGnKja3VW25xc82sLUKk0ceHug==
Received: by 2002:a17:902:e8cd:b0:235:f4e3:9c7c with SMTP id
 d9443c01a7336-241e89603bbls46273505ad.1.-pod-prod-05-us; Tue, 05 Aug 2025
 08:18:09 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXph1daLO2dcHONrWw1tnYpc+ZXeEYE/k00XnjdBlAgBslflAUzmLsY1CQG4l2x+Ff1Kh8v41qZLL8=@googlegroups.com
X-Received: by 2002:a17:903:2441:b0:23f:f96d:7581 with SMTP id d9443c01a7336-24246f7882emr159729415ad.20.1754407089054;
        Tue, 05 Aug 2025 08:18:09 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1754407089; cv=none;
        d=google.com; s=arc-20240605;
        b=OJBr9MEMPsAoLSULcVWzbXP3oNuR1c00xiUlOn13qRnSZsfmwU+kXDalrcgOFRF0Q0
         ffakYBKt3TRGfcA4Rp9RPPYBdcjrHk0nZmGVqDiio8tk04L2o2VhRrf39cX49tDjrtbV
         HnV6sLQoegISBQ8NyuvdPU/6Cgm6Aoi3jPHYWGReitf36UCsTxUP/t8TUdp4cGgT4mLi
         2yeE2LNwmZO98Mq1ymbsTdvIcu6nOb+Sn3BosyDyxF4zALmZ6divrktoTkv214YnMkuy
         HODd7TDGS8fVzejaugIppnHIJ1olZQMLdZNm/9BQ93DMEs/wso2t1gA7VD+RpR7b5+Ka
         uqMQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=l5NeMlJwLZpcXV2DV2TdKHI4G5bE2z72dogFrH06R5c=;
        fh=6zTaRmbdqrObG65tdNCA0vuc/sIVsumbCtl+uFPXfG4=;
        b=B0N/z7L5FZvZTwaxoKLgSKgIW7yR3Cg4SnA4YXU5q+zZkk1vU0JacYYjmY1db0Tp8k
         0W42zbwWSGYLX+BrzRD30GmOSGO/1KoLOoRmNXORLvFXs6Z4gIigv5ZVg3mnidAHvKR7
         RLsINTszQmsUU+1OnLBDkNrLmE44N2nGSrxLn1zQaW3uAQqINobTKF0kk35+OwtvUlva
         jpTbGd4J3kYRADz6OZAG52Wwyzd4BSHfo9K+WacU6p9UyzHNjlvgnzxcmtvdw43p910F
         Yma7H0jTnXL9Fj2rmbqHqHEgYFBa6kb8aUb+r9udLusUou7taZCVaUyaCfQJ19apICt7
         d4qA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=rw+ZYlVS;
       spf=pass (google.com: domain of rmoar@google.com designates 2607:f8b0:4864:20::82a as permitted sender) smtp.mailfrom=rmoar@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-qt1-x82a.google.com (mail-qt1-x82a.google.com. [2607:f8b0:4864:20::82a])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-32102a6e7aasi309601a91.1.2025.08.05.08.18.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 05 Aug 2025 08:18:08 -0700 (PDT)
Received-SPF: pass (google.com: domain of rmoar@google.com designates 2607:f8b0:4864:20::82a as permitted sender) client-ip=2607:f8b0:4864:20::82a;
Received: by mail-qt1-x82a.google.com with SMTP id d75a77b69052e-4b07d779287so13079081cf.2
        for <kasan-dev@googlegroups.com>; Tue, 05 Aug 2025 08:18:08 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCU+plPbTHD5H70uUgtfV+GuSSa3ayG+Ui6Wzi5hM79daVf5OiQQ0+yXWewT1Fs/2XY2Mlx2ITmzcT0=@googlegroups.com
X-Gm-Gg: ASbGncvuHl7nYCA6Je9gbY8TSIEMhe0PhanElSiwSSFHx1qWgrrrjsskeqqCRlBMjGN
	DIZE2rdJI2pAkF4oWyy93IW44bz5xdv8ldUUleWJ4z9fDo5dacxmJXr6l6zNQsu4KwEhg3DlaUf
	8eX83Bo6N0RiSHIBhNEm/e8u8KgFE7uQRNY6a7aOf2Lo4fcBQoi03eUUTnr56Pi2miKkdjOFLs+
	es9P1JTpqSoFIR/dC0afCFJt+1OJvxxqIxKzaE2wg==
X-Received: by 2002:ad4:5ca3:0:b0:705:1647:6dfa with SMTP id
 6a1803df08f44-70935f7eda4mr211485656d6.17.1754407087029; Tue, 05 Aug 2025
 08:18:07 -0700 (PDT)
MIME-Version: 1.0
References: <20250729193647.3410634-1-marievic@google.com> <20250729193647.3410634-3-marievic@google.com>
In-Reply-To: <20250729193647.3410634-3-marievic@google.com>
From: "'Rae Moar' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 5 Aug 2025 11:17:55 -0400
X-Gm-Features: Ac12FXyu_BxZIwtuZLWYceoYjDhyP0_a9ARxyqnnkXvZy9hY9vlbesfxKuU3reI
Message-ID: <CA+GJov5R2GnBfxXR=28vS3F4b1E-=WLDXpgdJo0SpKAXb1dpsw@mail.gmail.com>
Subject: Re: [PATCH 2/9] kunit: Introduce param_init/exit for parameterized
 test shared context management
To: Marie Zhussupova <marievic@google.com>
Cc: davidgow@google.com, shuah@kernel.org, brendan.higgins@linux.dev, 
	elver@google.com, dvyukov@google.com, lucas.demarchi@intel.com, 
	thomas.hellstrom@linux.intel.com, rodrigo.vivi@intel.com, 
	linux-kselftest@vger.kernel.org, kunit-dev@googlegroups.com, 
	kasan-dev@googlegroups.com, intel-xe@lists.freedesktop.org, 
	dri-devel@lists.freedesktop.org, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: rmoar@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=rw+ZYlVS;       spf=pass
 (google.com: domain of rmoar@google.com designates 2607:f8b0:4864:20::82a as
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

On Tue, Jul 29, 2025 at 3:37=E2=80=AFPM Marie Zhussupova <marievic@google.c=
om> wrote:
>
> Add `param_init` and `param_exit` function pointers to
> `struct kunit_case`. Users will be able to set them
> via the new `KUNIT_CASE_PARAM_WITH_INIT` macro.

Hello!

Very intrigued by this idea to add an init and exit function for
parameterized tests. In a way, this allows parameterized test series
to act more like suites. Either way I am happy to see more flexibility
being brought to the parameterized test framework.

I have a few comments below that I would like to discuss before a
final review. But this patch is looking good.

Thanks!
-Rae

>
> These functions are invoked by kunit_run_tests() once before
> and once after the entire parameterized test series, respectively.

This is a philosophical question but should we refer to a group of
parameterized tests as a parameterized test series or a parameterized
test suite? In the KTAP, the appearance is identical to a suite but in
the running of the tests it acts distinct to a test case or suite.
Curious on David's opinion here.

> They will receive the parent kunit test instance, allowing users
> to register and manage shared resources. Resources added to this
> parent kunit test will be accessible to all individual parameterized
> tests, facilitating init and exit for shared state.
>
> Signed-off-by: Marie Zhussupova <marievic@google.com>
> ---
>  include/kunit/test.h | 33 ++++++++++++++++++++++++++++++++-
>  lib/kunit/test.c     | 23 ++++++++++++++++++++++-
>  2 files changed, 54 insertions(+), 2 deletions(-)
>
> diff --git a/include/kunit/test.h b/include/kunit/test.h
> index a42d0c8cb985..d8dac7efd745 100644
> --- a/include/kunit/test.h
> +++ b/include/kunit/test.h
> @@ -92,6 +92,8 @@ struct kunit_attributes {
>   * @name:     the name of the test case.
>   * @generate_params: the generator function for parameterized tests.
>   * @attr:     the attributes associated with the test
> + * @param_init: The init function to run before parameterized tests.
> + * @param_exit: The exit function to run after parameterized tests.

If we decide on a terminology for the parameterized test group, it
might be clearer to label these "The init function to run before
parameterized test [suite/series]." and same for the exit function.

>   *
>   * A test case is a function with the signature,
>   * ``void (*)(struct kunit *)``
> @@ -129,6 +131,13 @@ struct kunit_case {
>         const void* (*generate_params)(const void *prev, char *desc);
>         struct kunit_attributes attr;
>
> +       /*
> +        * Optional user-defined functions: one to register shared resour=
ces once
> +        * before the parameterized test series, and another to release t=
hem after.
> +        */
> +       int (*param_init)(struct kunit *test);
> +       void (*param_exit)(struct kunit *test);
> +
>         /* private: internal use only. */
>         enum kunit_status status;
>         char *module_name;
> @@ -218,6 +227,27 @@ static inline char *kunit_status_to_ok_not_ok(enum k=
unit_status status)
>                   .generate_params =3D gen_params,                       =
         \
>                   .attr =3D attributes, .module_name =3D KBUILD_MODNAME}
>
> +/**
> + * KUNIT_CASE_PARAM_WITH_INIT() - Define a parameterized KUnit test case=
 with custom
> + * init and exit functions.
> + * @test_name: The function implementing the test case.
> + * @gen_params: The function to generate parameters for the test case.
> + * @init: The init function to run before parameterized tests.
> + * @exit: The exit function to run after parameterized tests.

If we do change the description above of param_init/param_exit, it
might be nice to change it here too.

> + *
> + * Provides the option to register init and exit functions that take in =
the
> + * parent of the parameterized tests and run once before and once after =
the
> + * parameterized test series. The init function can be used to add any r=
esources
> + * to share between the parameterized tests or to pass parameter arrays.=
 The
> + * exit function can be used to clean up any resources that are not mana=
ged by
> + * the test.
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
> @@ -269,7 +299,8 @@ struct kunit_suite_set {
>   * @priv: for user to store arbitrary data. Commonly used to pass data
>   *       created in the init function (see &struct kunit_suite).
>   * @parent: for user to store data that they want to shared across
> - *         parameterized tests.
> + *         parameterized tests. Typically, the data is provided in
> + *         the param_init function (see &struct kunit_case).
>   *
>   * Used to store information about the current context under which the t=
est
>   * is running. Most of this data is private and should only be accessed
> diff --git a/lib/kunit/test.c b/lib/kunit/test.c
> index 4d6a39eb2c80..d80b5990d85d 100644
> --- a/lib/kunit/test.c
> +++ b/lib/kunit/test.c
> @@ -641,6 +641,19 @@ static void kunit_accumulate_stats(struct kunit_resu=
lt_stats *total,
>         total->total +=3D add.total;
>  }
>
> +static void __kunit_init_parent_test(struct kunit_case *test_case, struc=
t kunit *test)

It would be nice to include "param" in this function name. Currently
it sounds more like you are initializing the @parent field of struct
kunit *test.

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
> @@ -668,6 +681,8 @@ int kunit_run_tests(struct kunit_suite *suite)
>                 struct kunit_result_stats param_stats =3D { 0 };
>
>                 kunit_init_test(&test, test_case->name, test_case->log);
> +               __kunit_init_parent_test(test_case, &test);
> +

Is it possible to move this so this function is only called when it is
a parameterized test? I see the check for KUNIT_FAILURE is useful but
I think I would still prefer this within the section for parameterized
tests.

>                 if (test_case->status =3D=3D KUNIT_SKIPPED) {
>                         /* Test marked as skip */
>                         test.status =3D KUNIT_SKIPPED;
> @@ -677,7 +692,7 @@ int kunit_run_tests(struct kunit_suite *suite)
>                         test_case->status =3D KUNIT_SKIPPED;
>                         kunit_run_case_catch_errors(suite, test_case, &te=
st);
>                         kunit_update_stats(&param_stats, test.status);
> -               } else {
> +               } else if (test_case->status !=3D KUNIT_FAILURE) {
>                         /* Get initial param. */
>                         param_desc[0] =3D '\0';
>                         /* TODO: Make generate_params try-catch */
> @@ -727,6 +742,12 @@ int kunit_run_tests(struct kunit_suite *suite)
>
>                 kunit_update_stats(&suite_stats, test_case->status);
>                 kunit_accumulate_stats(&total_stats, param_stats);
> +               /*
> +                * TODO: Put into a try catch. Since we don't need suite-=
>exit
> +                * for it we can't reuse kunit_try_run_cleanup for this y=
et.
> +                */
> +               if (test_case->param_exit)
> +                       test_case->param_exit(&test);

Also here I am not sure why this is done outside of the check for if
the test is parameterized? Either way this should definitely be done
before the test stats and ok/not ok line are printed because if there
is any log output during the param_exit function it is necessary to
print that before the status line to identify that that log
corresponds with that test.

Also just curious why you chose to implement a function to perform the
param_init but not the param_exit?



>                 /* TODO: Put this kunit_cleanup into a try-catch. */
>                 kunit_cleanup(&test);
>         }
> --
> 2.50.1.552.g942d659e1b-goog
>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
A%2BGJov5R2GnBfxXR%3D28vS3F4b1E-%3DWLDXpgdJo0SpKAXb1dpsw%40mail.gmail.com.
