Return-Path: <kasan-dev+bncBDPPVSUFVUPBBG6BZDCAMGQEDEWICWQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43d.google.com (mail-pf1-x43d.google.com [IPv6:2607:f8b0:4864:20::43d])
	by mail.lfdr.de (Postfix) with ESMTPS id 11156B1B73A
	for <lists+kasan-dev@lfdr.de>; Tue,  5 Aug 2025 17:17:50 +0200 (CEST)
Received: by mail-pf1-x43d.google.com with SMTP id d2e1a72fcca58-76bed3183ecsf3125183b3a.3
        for <lists+kasan-dev@lfdr.de>; Tue, 05 Aug 2025 08:17:49 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1754407068; cv=pass;
        d=google.com; s=arc-20240605;
        b=MiHxzYhV5SXmy4vp1/4MRPFATSpz8eOmgmwzppSJdTWkazmU6A2EC5lfXrFu51Dinh
         EjqFdG5wgI1tLXTGpXs81dzqAcgRovmwOEhdacNXPvXOz22LuIqN9QHrW1eIYFER6h0+
         K4OxiKJtMIMT86NLZYz4RauUyoX/KcKbFmWS2CnkYWTqReSAS2chwCbEquaMKZW1cHbf
         A3Esse30ryYjAnW02dSVjeWB9gsnMNsFis7SQkWZqQZW4PpkKTm4eCr4aHUOjCN1N2Am
         4kwPSNQN5mncIhHDgROKydjHE4CQPkN0tDANnb4m9m34kXKUv2Rwi13tM7ceQyvXTnZa
         YZUQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=5p7zR493eoIBUQaCQD/s533NPfIuWplRxSUOnvlP1Tg=;
        fh=oBUIo6mKBsynjaY4O2lJa/qUBXSXPMF4Y6+0rzFz/SQ=;
        b=fIR8rSLHz5eRkIo+uVElYnUQ9hvFWkpIWCOTyR3uAO9IUv8cLK3WGSQ30JKp7k7laJ
         0OvpFR3NXoTGhlm2yXWZwUMt0H2Q3+nDofZe8gYFi3WyE92344RsU93ueq3prV4KwM+1
         wtnAddADwOo57qII3VQV2s25PPd/G/qYGBANJlBt3G/3C2dBieE+97nyMzs3X63ZVr/J
         sc0ypgJaTePJF9fYl/ug86tEwPTFPUU1s66ADFoBWPVuZtTmspVlS3UwRBwIYrBCYTH8
         sUeGJ3ENELXqiG5Co4eYPOUZ2duBghyCVBGKZZpeLV/B3h6ETc4Yj1SEetqUoFVLBDWe
         Vg5g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=S5PsnYo1;
       spf=pass (google.com: domain of rmoar@google.com designates 2607:f8b0:4864:20::f30 as permitted sender) smtp.mailfrom=rmoar@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1754407068; x=1755011868; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=5p7zR493eoIBUQaCQD/s533NPfIuWplRxSUOnvlP1Tg=;
        b=ckJ8HUNh2mzdrAk1ZpUkGJDrlLsYsMfhURBvFyrFXSa+FZNytER2FyvQpHfqO1yn0f
         nsNzB/NpbTHr+y4oMYjr0g52bicywHWNhPuLyDbzHnfLsD/7tfCh3JZxLvj/wthZ6I9S
         xdsxBmjPnBhp9FdVDNPc3nY1THBydnDfa1jjna2eg2OpuVvUm/F56Ui9iTeo0mkuXIhy
         ncjjnclU9Ygwghk1D6HWGKS08iGvVZkG43hExbcpx/rR5O5mBflSp5Zx8/98I9ILuXuE
         uafQVnoxwjbXBGVm3GRnJHfdpxSXbZSLeuUbqSQK/hyqZudFAe2/P4iM6Tw0eI5Oe5R4
         XQsA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1754407068; x=1755011868;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=5p7zR493eoIBUQaCQD/s533NPfIuWplRxSUOnvlP1Tg=;
        b=gZ6JiMlsO1uVP0HLCfeUosnUHtGTBUKhmKaGorUt+vYcR9a3nsJB6I5ysbBEcMGT1O
         66rCtYMEB0tPmvEFTSHP1OvlE0bqPp/PNHO1Z3Rpa/uMCrJkq9ZXt1fNwWfBFO6vnNoc
         z4u0J2n2BH4P7TjX0vAz6AmVbCeK+cIrD1CAVjZhHqatj7sMNyEYkUI0OCIDBfVfp5aT
         HZv6tsrX+HgW6pqw7jL/IEFU45depZ3V93zRNACVNEHY+yewNpNE3aF58Nfw9iqFyt5o
         oI4dw2CbIXnuT4K1RCb9Kx65EvXjOmyS4vM/mhHB3EW1tut2docxuk2Gnhyyf7qQFFc0
         Cu+g==
X-Forwarded-Encrypted: i=2; AJvYcCUdPA905A+guIo0myf2An5VYrxybhC8gs4QQDTnNxloKaLLKGer00YJd/hBqZ+KlKSVwyC9NQ==@lfdr.de
X-Gm-Message-State: AOJu0YyWd8hxAY+9Zj3fIlcQFogCIVUmmfBqSKuTiunW2L0DB1JLqSXv
	rmkQWJbO+p2tuP7jyssa2bSdKFBpy+umxs6PB0ipHgOCb92nMc70rfMl
X-Google-Smtp-Source: AGHT+IE0hlRlN7jnTPTqiRpL5PJAX4Dzxxh9eBKfKCRt3dN0KJ6cXLFUKuWGorBfIr6caD7s1Id9oA==
X-Received: by 2002:a05:6a00:2e85:b0:74c:3547:7f0c with SMTP id d2e1a72fcca58-76bec310bc5mr19862851b3a.3.1754407067878;
        Tue, 05 Aug 2025 08:17:47 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdcWNH5rpxTSy74QnA8BIuMp3RVOWxS6nSNbMXQA3F5cg==
Received: by 2002:a05:6a00:2e82:b0:769:ebe1:e489 with SMTP id
 d2e1a72fcca58-76bc8cb10f0ls6412775b3a.2.-pod-prod-02-us; Tue, 05 Aug 2025
 08:17:46 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWus7XaScqYldZL2W5NMFm7F+Vw2C/qSfbZXX8Fh/RwtYqIzNpuwJLZ4DmY1jX9KPeWY1Wq3Vm7Tv4=@googlegroups.com
X-Received: by 2002:a05:6a00:3c8e:b0:747:b043:41e5 with SMTP id d2e1a72fcca58-76bec4e92e9mr18435347b3a.16.1754407065850;
        Tue, 05 Aug 2025 08:17:45 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1754407065; cv=none;
        d=google.com; s=arc-20240605;
        b=C5vCP8lMlXsImtRSX3r8AmJMw/D3b1uFmjOjZq0Pm0jvM8c5x4jpwgxsq7jO0e38Sh
         oQjx4WOlvJlPmP+I3V5ssPG6t0y960R2RAdmfcu3D0C25bHZMTFfQzw1oscEixLqJN09
         TE7B3rhr7sG66kWBWj60Up0EzPLKVL67yjUe5bvZcK9+isXvhplxvlAnB3HoPHnx1P+t
         so9EJyJayfAb96ntAOHu3lyzq7ekt62iadex2ka7RBV1iM5UWs0wN+d4zQe2FCDPQBTC
         RKZwkZaJixEmaAHL1uuh9qTzQ/x14LvioY5k/F+2NkQ04M3BwK8g30DBC4NgKAlS0FH5
         a4RA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=7IXs2Kr/JIndnkNpfZSfduZvVHbFnK3EtPg4aqdOsRc=;
        fh=UzwN1mwuz3enVs7+mwGa/8kJKwpYRAPSUIDOpZPVg6M=;
        b=Ke9RkNb3RKuUVq2ul5gURCU9oxjTHk1ZToCV/1TONt11T/tsyxLVvwxADzpPvRJzb7
         3yzT8Rw51iOVR4i4y4nyR9wyAcIlx7WxTsMDFPB1lIh1FxPzCq1VZ2pXMvMvbb0jIeoA
         KJyjBqHhJnG3J06YoGk/9oFOYejQw2Ai5JXImcUqTd+4OjOB5wHN85JOdgT9zzbN3Dhb
         DKI/xxd7fEThiyJDcgtb7wt2lAjkjF8K4KASfwM/aiYv1/i/Gl7NSqK0Owm8dN/9qMls
         KNlRqXO619JLd63xKM9o+RLy4dzxgd3xShez35kDXwhLlDAX8RsqgbOGdj5R9lcCmz/f
         t9gg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=S5PsnYo1;
       spf=pass (google.com: domain of rmoar@google.com designates 2607:f8b0:4864:20::f30 as permitted sender) smtp.mailfrom=rmoar@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-qv1-xf30.google.com (mail-qv1-xf30.google.com. [2607:f8b0:4864:20::f30])
        by gmr-mx.google.com with ESMTPS id d2e1a72fcca58-76bcce5da94si628291b3a.0.2025.08.05.08.17.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 05 Aug 2025 08:17:45 -0700 (PDT)
Received-SPF: pass (google.com: domain of rmoar@google.com designates 2607:f8b0:4864:20::f30 as permitted sender) client-ip=2607:f8b0:4864:20::f30;
Received: by mail-qv1-xf30.google.com with SMTP id 6a1803df08f44-707389a2fe3so55383516d6.2
        for <kasan-dev@googlegroups.com>; Tue, 05 Aug 2025 08:17:45 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCX5q/Z8qUioySbhRn/NCi7ZVNggQxoEX48qzWYEi5ZWvkWsuwvAsYCoqWNAeyPrGAspKoe4G4xON0I=@googlegroups.com
X-Gm-Gg: ASbGncvlfS1QJiFB9jNGS4iBfZc1eBlDJVSuY6PycOgft8OxW/agMqmieVnlWA6pfeq
	wWlMLesHMGOSGiKJu1aPAxNwy/+xxzlraGdu8d7dlx+XCVzu4HqhsI+FsxS7zTdHdP3Nw6yWiOF
	DgBmScdzFHF5VjKlA+zFeyOxVWWzI1XLjSzMas5q6EOmM+0wcSZi1lCZk5V32QUR6CmnRqItmBQ
	w0KGRdCjvmJmLu8nvqkvVRfpPB5iLN64vQm0idK1w==
X-Received: by 2002:ad4:5765:0:b0:706:f753:6b1f with SMTP id
 6a1803df08f44-70935fb3038mr189139186d6.21.1754407064119; Tue, 05 Aug 2025
 08:17:44 -0700 (PDT)
MIME-Version: 1.0
References: <20250729193647.3410634-1-marievic@google.com> <20250729193647.3410634-2-marievic@google.com>
In-Reply-To: <20250729193647.3410634-2-marievic@google.com>
From: "'Rae Moar' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 5 Aug 2025 11:17:33 -0400
X-Gm-Features: Ac12FXze3TaZ1ItJhvvsVg6J8U-v3wToEcNYmNz4bKxujCA6Thw0S4iJb4SdDqU
Message-ID: <CA+GJov4BQ1mRa-JaHoML+gF7rk=XY=hCRL+Shag6Aj6VbUgUeg@mail.gmail.com>
Subject: Re: [PATCH 1/9] kunit: Add parent kunit for parameterized test context
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
 header.i=@google.com header.s=20230601 header.b=S5PsnYo1;       spf=pass
 (google.com: domain of rmoar@google.com designates 2607:f8b0:4864:20::f30 as
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
> Currently, KUnit parameterized tests lack a mechanism
> to share resources across individual test invocations
> because the same `struct kunit` instance is reused for
> each test.
>
> This patch refactors kunit_run_tests() to provide each
> parameterized test with its own `struct kunit` instance.
> A new parent pointer is added to `struct kunit`, allowing
> individual parameterized tests to reference a shared
> parent kunit instance. Resources added to this parent
> will then be accessible to all individual parameter
> test executions.
>
> Signed-off-by: Marie Zhussupova <marievic@google.com>

Hello!

Thank you so much for sending out this series. I have wanted to see an
update of our parameterized test framework for a while. I have a few
comments below for this patch. But otherwise it is looking good.

Reviewed-by: Rae Moar <rmoar@google.com>

Thanks!
-Rae

> ---
>  include/kunit/test.h | 12 ++++++++++--
>  lib/kunit/test.c     | 32 +++++++++++++++++++-------------
>  2 files changed, 29 insertions(+), 15 deletions(-)
>
> diff --git a/include/kunit/test.h b/include/kunit/test.h
> index 39c768f87dc9..a42d0c8cb985 100644
> --- a/include/kunit/test.h
> +++ b/include/kunit/test.h
> @@ -268,14 +268,22 @@ struct kunit_suite_set {
>   *
>   * @priv: for user to store arbitrary data. Commonly used to pass data
>   *       created in the init function (see &struct kunit_suite).
> + * @parent: for user to store data that they want to shared across
> + *         parameterized tests.
>   *

As David mentioned, I would also prefer that this provides a more
general description of the @parent field here. Although this is
currently only used for parameterized tests, it could have other use
cases in the future.

>   * Used to store information about the current context under which the t=
est
>   * is running. Most of this data is private and should only be accessed
> - * indirectly via public functions; the one exception is @priv which can=
 be
> - * used by the test writer to store arbitrary data.
> + * indirectly via public functions; the two exceptions are @priv and @pa=
rent
> + * which can be used by the test writer to store arbitrary data or data =
that is
> + * available to all parameter test executions, respectively.

In addition, I would prefer that the call out to @parent here is also
changed to a more general description of the @parent field. However,
feel free to also include the description of the use case for the
parameterized tests.

>   */
>  struct kunit {
>         void *priv;
> +       /*
> +        * Reference to the parent struct kunit for storing shared resour=
ces
> +        * during parameterized testing.
> +        */

I am more 50/50 on changing this description. Could change it just to:
"Reference to the parent struct kunit for storing shared resources."

> +       struct kunit *parent;
>
>         /* private: internal use only. */
>         const char *name; /* Read only after initialization! */
> diff --git a/lib/kunit/test.c b/lib/kunit/test.c
> index f3c6b11f12b8..4d6a39eb2c80 100644
> --- a/lib/kunit/test.c
> +++ b/lib/kunit/test.c
> @@ -647,6 +647,7 @@ int kunit_run_tests(struct kunit_suite *suite)
>         struct kunit_case *test_case;
>         struct kunit_result_stats suite_stats =3D { 0 };
>         struct kunit_result_stats total_stats =3D { 0 };
> +       const void *curr_param;
>
>         /* Taint the kernel so we know we've run tests. */
>         add_taint(TAINT_TEST, LOCKDEP_STILL_OK);
> @@ -679,36 +680,39 @@ int kunit_run_tests(struct kunit_suite *suite)
>                 } else {
>                         /* Get initial param. */
>                         param_desc[0] =3D '\0';
> -                       test.param_value =3D test_case->generate_params(N=
ULL, param_desc);
> +                       /* TODO: Make generate_params try-catch */
> +                       curr_param =3D test_case->generate_params(NULL, p=
aram_desc);
>                         test_case->status =3D KUNIT_SKIPPED;
>                         kunit_log(KERN_INFO, &test, KUNIT_SUBTEST_INDENT =
KUNIT_SUBTEST_INDENT
>                                   "KTAP version 1\n");
>                         kunit_log(KERN_INFO, &test, KUNIT_SUBTEST_INDENT =
KUNIT_SUBTEST_INDENT
>                                   "# Subtest: %s", test_case->name);
>
> -                       while (test.param_value) {
> -                               kunit_run_case_catch_errors(suite, test_c=
ase, &test);
> +                       while (curr_param) {
> +                               struct kunit param_test =3D {
> +                                       .param_value =3D curr_param,
> +                                       .param_index =3D ++test.param_ind=
ex,
> +                                       .parent =3D &test,
> +                               };
> +                               kunit_init_test(&param_test, test_case->n=
ame, test_case->log);
> +                               kunit_run_case_catch_errors(suite, test_c=
ase, &param_test);
>
>                                 if (param_desc[0] =3D=3D '\0') {
>                                         snprintf(param_desc, sizeof(param=
_desc),
>                                                  "param-%d", test.param_i=
ndex);

This probably doesn't matter too much either way but should this be
param_test.param_index instead? This would cover the case where the
param_index is changed during the test run even though it shouldn't.

>                                 }
>
> -                               kunit_print_ok_not_ok(&test, KUNIT_LEVEL_=
CASE_PARAM,
> -                                                     test.status,
> -                                                     test.param_index + =
1,
> +                               kunit_print_ok_not_ok(&param_test, KUNIT_=
LEVEL_CASE_PARAM,
> +                                                     param_test.status,
> +                                                     param_test.param_in=
dex,
>                                                       param_desc,
> -                                                     test.status_comment=
);
> +                                                     param_test.status_c=
omment);
>
> -                               kunit_update_stats(&param_stats, test.sta=
tus);
> +                               kunit_update_stats(&param_stats, param_te=
st.status);
>
>                                 /* Get next param. */
>                                 param_desc[0] =3D '\0';
> -                               test.param_value =3D test_case->generate_=
params(test.param_value, param_desc);
> -                               test.param_index++;
> -                               test.status =3D KUNIT_SUCCESS;
> -                               test.status_comment[0] =3D '\0';
> -                               test.priv =3D NULL;
> +                               curr_param =3D test_case->generate_params=
(curr_param, param_desc);
>                         }
>                 }
>
> @@ -723,6 +727,8 @@ int kunit_run_tests(struct kunit_suite *suite)
>
>                 kunit_update_stats(&suite_stats, test_case->status);
>                 kunit_accumulate_stats(&total_stats, param_stats);
> +               /* TODO: Put this kunit_cleanup into a try-catch. */
> +               kunit_cleanup(&test);

I might be missing something here but why not do this cleanup before
the printing stage and only if the test was a parent param test?



>         }
>
>         if (suite->suite_exit)
> --
> 2.50.1.552.g942d659e1b-goog
>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
A%2BGJov4BQ1mRa-JaHoML%2BgF7rk%3DXY%3DhCRL%2BShag6Aj6VbUgUeg%40mail.gmail.c=
om.
