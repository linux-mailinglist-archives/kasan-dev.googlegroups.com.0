Return-Path: <kasan-dev+bncBDPPVSUFVUPBBAWCZDCAMGQEW3PR7DY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x639.google.com (mail-pl1-x639.google.com [IPv6:2607:f8b0:4864:20::639])
	by mail.lfdr.de (Postfix) with ESMTPS id A9D6DB1B756
	for <lists+kasan-dev@lfdr.de>; Tue,  5 Aug 2025 17:19:37 +0200 (CEST)
Received: by mail-pl1-x639.google.com with SMTP id d9443c01a7336-23fe98c50dasf51744295ad.3
        for <lists+kasan-dev@lfdr.de>; Tue, 05 Aug 2025 08:19:37 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1754407171; cv=pass;
        d=google.com; s=arc-20240605;
        b=SwjMJTYSv+E/IcdOx+Xq7hbpP/ffd72YDI/j4oVikhpIUGFN46JCwKXPf1FMNEdh4U
         KstS8UYk0KDualxrMf71HVbZmsCxBpCy97PuzqXpaVeuv464rmJ2jmmpuWjLCA1wIOUE
         5oLyiN5Yw8txgamcR2GC0YboJzu0FhegmeygY9x2JB6Qgz3lZjiawv788uBzl9M0Nq0h
         ypWPdL2Qjblmh5sdGS3GWKWkEXUb31Q47VIo6QUsJiBULtrBiXMKP4cA3a5F3ULJF1B0
         YBOCIcI0HWVvgl+OZi4nd3ncB0+fYAWJuHqXPlYgspH2q38pWrX0ze7HBcUAzbmzlHxF
         szHQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=MW5DvtPk//amjeoEycrkydUw2gzBKJGHamkJWkC6O0E=;
        fh=7Avrp4x3GchadNrfGGMFqxh1DS/3WZBDILqy25P4aMM=;
        b=KRualW9opUR55hZ/G1Nvlc++jV3Zmnz5MgcTOeDt9srO0YM4Knslk4nc22B9epfoEd
         P/YajMb8VVaIIrSgl8d3O2WcalCs401K1plZAiuCkcGv+jtvaRMhsiRcHCFgmvz6uIAK
         QZSvjWpiboditL3cjUUt83hJ8fS5UOJA4SAafl+OIpYeLVcvjTDRkYw1O6KfnFLxN7vG
         6KK02SVnHBrWPjpYSG1zTZmPTjkytYPMrR9x0jSWGXcZO2HBSaPfI94GBeBcSKyLDrei
         oUHZDLlHLN9kFEGdxfNRm5Z1KgmKEaZ5I6ZPj3hO1iIbFC28gRrk9xoZeTGQNEMN401k
         Czxw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=HWl9I1tu;
       spf=pass (google.com: domain of rmoar@google.com designates 2607:f8b0:4864:20::936 as permitted sender) smtp.mailfrom=rmoar@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1754407171; x=1755011971; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=MW5DvtPk//amjeoEycrkydUw2gzBKJGHamkJWkC6O0E=;
        b=CPR5lHTa3csGWYr/adSddYhuQ+WdyCZzrMhjby7H7WyMbbvEZJE+UiGYcUdstSB8XR
         9G5yMBE8XZQDKMdTDyNTQiR8pppA/jeHxw7nLew9rdfyqKaBfM5WNxmEm3UEnc0iACar
         VtnGmnKUBwQXCKcjblC0zK6RI2QEC81ajyFjEjYseXxvryRuVX946mkaii8KvRlrF/nl
         qjV3c9O+Qg6oFXe05alyyMiIwccXVoUebnMB9/J4Cl/FPhOA2ejHXMJnbieLZoZDAtYF
         TcVnXN5Rv5bBdj8r38WG1cCyaQT390RR6Y0S6xAMgdMczLpC8QP7/hzfgbcatLiJCTNk
         4rbw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1754407171; x=1755011971;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=MW5DvtPk//amjeoEycrkydUw2gzBKJGHamkJWkC6O0E=;
        b=i37/kjfjd0PxhO4q2FwBgv40txlnjeq0I7y4R39YFNQuWAMxZEO0Sh20wPRvbAobyo
         4UtzhNTT5yyaBs1zXx7pk7DFRLx/SNOirmnRuZLkiYavImO5QvCUUnu/lKeYJx3s60Ue
         m2QbUP6IsuEOHGsFmp9ZIJhU2aTwhT/fpmGHQyoZCDoNGnCmyVK8xLNwLqNhRRrTCoZG
         da5KdYwIIuwpcLkxg48PA2J/OHEGLDGICNBNwo0a85fdHKhfGb0FbDe+W53FS0TBBYG6
         wAFWqOs8xU2T7HQPmCllbMYKYBuEJSchf6cygMme3UlJBoAyoynqYULthXgOWNpDPz4l
         MKcw==
X-Forwarded-Encrypted: i=2; AJvYcCWQXQLSgJCDuJybygUvCIf5FJNLFPNTlHs3ggleNumj4tVCkLzcz0scc6gB4a9LrbJ1RJ4z/g==@lfdr.de
X-Gm-Message-State: AOJu0YzLjV8lCb7KG9DC3NNpA5WUADRvwRsh8hU6CXrZY0j40pVMOk82
	CntOYedfYjRjERjsY6Px6kcUPIR1l88XWdULXawwlzIAcH5TAh/yK9E1
X-Google-Smtp-Source: AGHT+IHqBYgzXogR3HnYIuwYc48Dbo4v4BDKZwaIbrdc2UIxhJztpRavmGO7/4r9FVENdol2nStWgA==
X-Received: by 2002:a17:902:cecc:b0:226:38ff:1d6a with SMTP id d9443c01a7336-24246f2c943mr163822375ad.7.1754407170592;
        Tue, 05 Aug 2025 08:19:30 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcu1Lz6Ydg7iGNC73RbvvyRkLO6zn/GZ8SaE+KYs3u99w==
Received: by 2002:a17:902:db11:b0:234:e655:a617 with SMTP id
 d9443c01a7336-241e89975a9ls59909855ad.2.-pod-prod-02-us; Tue, 05 Aug 2025
 08:19:29 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUN2qOC/hs87wLA/AnvngOElqv/c/dEIv2l5dFe5pe+5B+T4F23OiZkFLrqpaVzb5ftcnztH7ITnfk=@googlegroups.com
X-Received: by 2002:a17:902:f550:b0:23f:f065:f2be with SMTP id d9443c01a7336-24246fe0ec1mr184442415ad.26.1754407169376;
        Tue, 05 Aug 2025 08:19:29 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1754407169; cv=none;
        d=google.com; s=arc-20240605;
        b=e5rFnLwKOU0gfJ33M3ayJjkBCWt5nyYtTDx7U+GgqoSkHutc8ncMUEmGTXY/3Yx68C
         QbPcjNRZXv7NgL28Vcvv0TiJoU8FaakdZkpR8yjzFbA85/ZkuZgEL5uKad6P0RR0RUmG
         DOOiTSzTL8qo8LCNE2H3v7b1lqlrdX3YHk9iKTm2pN9TmsGvj2FmeYekilDE6QiOBFxM
         LzMG0K9ftuccqOVr1ssk5vWkJqIWyIv5uQIumOGeEVJ7aDoMpTj0QwgcIpgYdtllBjov
         4ykB9r7TTANdbRsL/fGzKNQk9fM/FQ+r4Un5+KiNEl5hYz5ABqcFIuDdH0yh79LMIbWf
         TCvQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=V/M4EHqiBN5lPxOAQu9DhSS4CshVThGJ9tZazXfyjBo=;
        fh=+QvjiYGk0CvMaVsqNF4S7uk56LXBXCNgNqxPlVvlNQY=;
        b=W8Eqb6N+vtDGOO0APpxXAlKR6we2Gk4/9Oq3MVERCitAm4hAAhqifAPCNlL3HSSSPW
         vu05M2sG3DLIYeZ2DtXmTTcMnHUtbwR23ahU8aMcnY41dcQ5Xb6Hc5Jwx9YjKf+NWVJK
         yh6NspS8sPGDCtl6FA0TokjbQ5fRxslcD4jl4y1YeiVcQH4s6G0mgyNmP/BSy01pc9La
         W7Aq1/JEKeOuuBJD7+e8JPe7IzQu2ST3pG7A4Vw4mas08Hb5NiG86dxkqU8RKTohM1oa
         cJqVslzCKAxP3Up1HXWH5A/9jdDyiCoN6RIow4TUhwmxIskWxv8MTyESrYgVfd+qskOx
         w51Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=HWl9I1tu;
       spf=pass (google.com: domain of rmoar@google.com designates 2607:f8b0:4864:20::936 as permitted sender) smtp.mailfrom=rmoar@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-ua1-x936.google.com (mail-ua1-x936.google.com. [2607:f8b0:4864:20::936])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-241cecfe034si4834215ad.1.2025.08.05.08.19.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 05 Aug 2025 08:19:29 -0700 (PDT)
Received-SPF: pass (google.com: domain of rmoar@google.com designates 2607:f8b0:4864:20::936 as permitted sender) client-ip=2607:f8b0:4864:20::936;
Received: by mail-ua1-x936.google.com with SMTP id a1e0cc1a2514c-87f04817bf6so3829525241.0
        for <kasan-dev@googlegroups.com>; Tue, 05 Aug 2025 08:19:29 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUP9sGps8Ft+qFNTSCDSg0uKz/yETtRaG8SFW5AX0OsGyVY6coclQV8jNm2TEQpMYd3di1RTgBL5as=@googlegroups.com
X-Gm-Gg: ASbGncuu1H9uxRrFtmGfObi80pOCsaOKJpjHQUjsNdlUKtsPV29FSInu2E2eCfPkxWG
	2a1nTSQSQl1/t/LL3uz+n8BP5tdhHgly1VrmnKO1RXGrq130WmRhaZyxzBCDtQ5rbaYe8fTG1R5
	UonIMO+4B6m5P88S3zoKj6/d8CPQhQCbWibLHCwCgZ9yhIKoa/QhrZOv+pT5Wqh2rvyMwieTmvi
	qwzEzxfvaj1sOYcsAzQN421fWgkwt3aFT7KJim/YA==
X-Received: by 2002:a05:6102:5ccb:b0:4e5:9380:9c20 with SMTP id
 ada2fe7eead31-4fdc1b4ebdbmr6328940137.2.1754407168016; Tue, 05 Aug 2025
 08:19:28 -0700 (PDT)
MIME-Version: 1.0
References: <20250729193647.3410634-1-marievic@google.com> <20250729193647.3410634-9-marievic@google.com>
In-Reply-To: <20250729193647.3410634-9-marievic@google.com>
From: "'Rae Moar' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 5 Aug 2025 11:19:16 -0400
X-Gm-Features: Ac12FXyMmUl4gu7cWRijQYgUuECjdwsoCyIrsthniHfiJ52BVbgwKDdOONRK8UA
Message-ID: <CA+GJov6Xcn_X8iDz9wQhpSo_O+v4DyaqYfW8heQ_+q-DxdOK9Q@mail.gmail.com>
Subject: Re: [PATCH 8/9] kunit: Add example parameterized test with direct
 dynamic parameter array setup
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
 header.i=@google.com header.s=20230601 header.b=HWl9I1tu;       spf=pass
 (google.com: domain of rmoar@google.com designates 2607:f8b0:4864:20::936 as
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
> Introduce `example_params_test_with_init_dynamic_arr`. This new
> KUnit test demonstrates directly assigning a dynamic parameter
> array using the `kunit_register_params_array` macro. It highlights the
> use of `param_init` and `param_exit` for proper initialization and
> cleanup, and their registration to the test with
> `KUNIT_CASE_PARAM_WITH_INIT`.
>
> Signed-off-by: Marie Zhussupova <marievic@google.com>

Hello!

This test is interesting and complex. I am very happy to see this test
accepted. I think it is a good demonstration of the new parameterized
test features.

Reviewed-by: Rae Moar <rmoar@google.com>

Thanks!

-Rae

> ---
>  lib/kunit/kunit-example-test.c | 95 ++++++++++++++++++++++++++++++++++
>  1 file changed, 95 insertions(+)
>
> diff --git a/lib/kunit/kunit-example-test.c b/lib/kunit/kunit-example-tes=
t.c
> index 5bf559e243f6..3ab121d81bf6 100644
> --- a/lib/kunit/kunit-example-test.c
> +++ b/lib/kunit/kunit-example-test.c
> @@ -387,6 +387,98 @@ static void example_params_test_with_init(struct kun=
it *test)
>         kunit_put_resource(res);
>  }
>
> +/*
> + * Helper function to create a parameter array of Fibonacci numbers. Thi=
s example
> + * highlights a parameter generation scenario that is:
> + * 1. Not feasible to fully pre-generate at compile time.
> + * 2. Challenging to implement with a standard 'generate_params' functio=
n,
> + * as it typically only provides the immediately 'prev' parameter, while
> + * Fibonacci requires access to two preceding values for calculation.
> + */
> +static void *make_fibonacci_params(int seq_size)
> +{
> +       int *seq;
> +
> +       if (seq_size <=3D 0)
> +               return NULL;
> +
> +       seq =3D kmalloc_array(seq_size, sizeof(int), GFP_KERNEL);
> +
> +       if (!seq)
> +               return NULL;
> +
> +       if (seq_size >=3D 1)
> +               seq[0] =3D 0;
> +       if (seq_size >=3D 2)
> +               seq[1] =3D 1;
> +       for (int i =3D 2; i < seq_size; i++)
> +               seq[i] =3D seq[i - 1] + seq[i - 2];
> +       return seq;
> +}
> +
> +/*
> + * This is an example of a function that provides a description for each=
 of the
> + * parameters.
> + */
> +static void example_param_dynamic_arr_get_desc(const void *p, char *desc=
)
> +{
> +       const int *fib_num =3D p;
> +
> +       snprintf(desc, KUNIT_PARAM_DESC_SIZE, "fibonacci param: %d", *fib=
_num);
> +}
> +
> +/*
> + * Example of a parameterized test init function that registers a dynami=
c array.
> + */
> +static int example_param_init_dynamic_arr(struct kunit *test)
> +{
> +       int seq_size =3D 6;
> +       int *fibonacci_params =3D make_fibonacci_params(seq_size);
> +
> +       if (!fibonacci_params)
> +               return -ENOMEM;
> +
> +       /*
> +        * Passes the dynamic parameter array information to the parent s=
truct kunit.
> +        * The array and its metadata will be stored in test->parent->par=
ams_data.
> +        * The array itself will be located in params_data.params.
> +        */
> +       kunit_register_params_array(test, fibonacci_params, seq_size,
> +                                   example_param_dynamic_arr_get_desc);
> +       return 0;
> +}
> +
> +/**
> + * Function to clean up the parameterized test's parent kunit struct if
> + * there were custom allocations.
> + */
> +static void example_param_exit_dynamic_arr(struct kunit *test)
> +{
> +       /*
> +        * We allocated this array, so we need to free it.
> +        * Since the parent parameter instance is passed here,
> +        * we can directly access the array via `test->params_data.params=
`
> +        * instead of `test->parent->params_data.params`.
> +        */
> +       kfree(test->params_data.params);
> +}
> +
> +/*
> + * Example of test that uses the registered dynamic array to perform ass=
ertions
> + * and expectations.
> + */
> +static void example_params_test_with_init_dynamic_arr(struct kunit *test=
)
> +{
> +       const int *param =3D test->param_value;
> +       int param_val;
> +
> +       /* By design, param pointer will not be NULL. */
> +       KUNIT_ASSERT_NOT_NULL(test, param);
> +
> +       param_val =3D *param;
> +       KUNIT_EXPECT_EQ(test, param_val - param_val, 0);
> +}
> +
>  /*
>   * Here we make a list of all the test cases we want to add to the test =
suite
>   * below.
> @@ -408,6 +500,9 @@ static struct kunit_case example_test_cases[] =3D {
>         KUNIT_CASE_PARAM(example_params_test, example_gen_params),
>         KUNIT_CASE_PARAM_WITH_INIT(example_params_test_with_init, NULL,
>                                    example_param_init, NULL),
> +       KUNIT_CASE_PARAM_WITH_INIT(example_params_test_with_init_dynamic_=
arr, NULL,
> +                                  example_param_init_dynamic_arr,
> +                                  example_param_exit_dynamic_arr),
>         KUNIT_CASE_SLOW(example_slow_test),
>         {}
>  };
> --
> 2.50.1.552.g942d659e1b-goog
>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
A%2BGJov6Xcn_X8iDz9wQhpSo_O%2Bv4DyaqYfW8heQ_%2Bq-DxdOK9Q%40mail.gmail.com.
