Return-Path: <kasan-dev+bncBDPPVSUFVUPBB5WBZDCAMGQEJFVKF3Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3a.google.com (mail-yb1-xb3a.google.com [IPv6:2607:f8b0:4864:20::b3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 32459B1B74E
	for <lists+kasan-dev@lfdr.de>; Tue,  5 Aug 2025 17:19:20 +0200 (CEST)
Received: by mail-yb1-xb3a.google.com with SMTP id 3f1490d57ef6-e9002c5daa7sf2508668276.2
        for <lists+kasan-dev@lfdr.de>; Tue, 05 Aug 2025 08:19:20 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1754407159; cv=pass;
        d=google.com; s=arc-20240605;
        b=WQes8bHBhfMMq8DsXEJoW8tQ60fj7Q10zynzH8QznujSt4sg964U1+ekbdspJfCTr4
         6rPJI33Ci1fNGaoaJWStfvxWDbaSPrXcxOGS6gXtSq1MUaE1hVYgjGDp4iT+G3ewTuIs
         6xIH3VjiSvumpA2OMR/BR4FlKtP+J7ogvG+hKH+16NnlzQmCGHQQrZT6S/36YspCE3Ra
         T9+Nvbhh/FICycJGdd/xtLKD/byb/I2F/WVDIRmuNDUvLAcAGpYKI7JRi/qauasoWkjL
         9262qAD892hK6w7/Bi/eCA4StjuWF9Nz0Qwp4LRy7e1OGCYA4ltRbpTWL8G4spwch2gw
         ppzQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=NWBPu//1gmCvd940rKAexiBsr4f2ExfbzzYy4BzmZMk=;
        fh=hzgIF8h4wCHXs76fvHfTv+vm60FTImEXJ9M/WJkJKSk=;
        b=igpi4gZvtkkpiybhemK1rhvVOacVt2WoYb0+ecIgR5pDTLNiwMN2/Rm/9GekbNCZR+
         Dr7SjJ53+qQYRjyVHRjffSb9if45HkLmGT3tUHw9Gy/X6Z8PmZmO2BqrCVLQuhaYQ61n
         HME/yQWUSTd1Bp+KGsnSOkS31R8r8Wf/LT1CvPhvxkN6NrQJFuT0kAJDcFIS3rb+wub7
         42m3EJgZErW2v3+dGBpW9LSSk1+pOjx9gg9hWGXkpyK5DqUsnM5rBwmDPTwFTx4vaB9H
         l3w/xD5cshWCvoIxuWYSzQgp+dRibAtPoXT7vv2BlsYPcesI/GRg6JTg2kKGzX+02QKA
         Mo0Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=d62WgcLE;
       spf=pass (google.com: domain of rmoar@google.com designates 2607:f8b0:4864:20::f32 as permitted sender) smtp.mailfrom=rmoar@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1754407159; x=1755011959; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=NWBPu//1gmCvd940rKAexiBsr4f2ExfbzzYy4BzmZMk=;
        b=PEHknj3W/WYWblD4MOPMNml300o0HGFHFKp9EI0ZlCelygPU1oFuHfG0Tq8TZbwdEK
         icnFgSmxIs7Bqiav54dsTcPWJtMceTdXTUXRAuDWGQrLgCaz2RBHPhfX2bHBs+wOUBY/
         PQU7eYwCqusU2c4Fi6tkZ/NbHwL6tNQ0P4pmeK/pzoDw4u5XNt2cQ5o6WtcdIqP5U8b9
         nxgfoRrCD4Cbwbmx1MnYvkfxUQ8lrj1pLbcpEpo++ryINVUfibz5qimnOlevMP8lv3+0
         UPvdInd2ELGz5ZsAHaTavN/vSWCNff9xwxwBGyf2zy+tA8zN2FZFRaUG8z5jJ5MR0sDJ
         5A+g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1754407159; x=1755011959;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=NWBPu//1gmCvd940rKAexiBsr4f2ExfbzzYy4BzmZMk=;
        b=qZu8UopxI3LvC/+IvtN6OSOLaGqHDVByCHewEPnNCH/eJrpUblma3CycD2rIBXviUi
         WTWBM2iWC3Q1wVI5fN5igd6E0xgVIqhezwv+KYHvhyuHtMdfwTqxJJyGXhn8c1nvCROK
         hglLXP2YoZJHXME9jMO+5q9zQ1pFzkydMmYWyMCfc2gLjsD4c9NpQolLHHKRIdpBUfiY
         eeseh5mB/GpNnewetX5MDU6G7WhEDFit1JZZNLvBqv27odeT2FwU48AsbQRa2nuhV5Pq
         Yg+NEFum0XCh7NzJa3n/BXe1nZXl8teGlhLn3wBEgRx8fD02KnTB4jJG80XWqa69LyHc
         Asvg==
X-Forwarded-Encrypted: i=2; AJvYcCVTK5qcWgsO9Uy1rT3IIJizeasZqdvlMhmCzC9N1zCqRKNvw8lDCMeFDgpcJlG7m5NViS47ag==@lfdr.de
X-Gm-Message-State: AOJu0YzqnujCyQ1S43qRQObpk4uDheucS8L6zZJHyQoAn2qoKgXxTde9
	+I3kG9PqVP8aSnpkRLHbperM/JBjEzKYHRna5TWw5NN+v3WGI4euZNXL
X-Google-Smtp-Source: AGHT+IEzTY567a//CiCly0QezTv2UfBeIMNBokKNCrPkgjOMfugSGy93vUmKDds+Im5pgWHa0pyxow==
X-Received: by 2002:a05:6902:6010:b0:e8f:d7ca:aaf3 with SMTP id 3f1490d57ef6-e8fee087119mr14688942276.5.1754407158688;
        Tue, 05 Aug 2025 08:19:18 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZd8wdWA5f3ETSiU6r2h6+ZB35EGbH9rc0NYy6Msjlp27g==
Received: by 2002:a25:7e85:0:b0:e8d:f7a6:9e52 with SMTP id 3f1490d57ef6-e8fd3424ab0ls5809314276.2.-pod-prod-05-us;
 Tue, 05 Aug 2025 08:19:18 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVm8j5HmK+XM8ltIEL3b4/xVuWPYB5yQ+P1UB7SbewQpcxo19+vcPXSEwFsK6UYwj9ULnpA842WWNc=@googlegroups.com
X-Received: by 2002:a05:690c:388:b0:71a:730:12ac with SMTP id 00721157ae682-71b7ed51fecmr152310087b3.15.1754407157825;
        Tue, 05 Aug 2025 08:19:17 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1754407157; cv=none;
        d=google.com; s=arc-20240605;
        b=SAYCDsN1cuUyVFomi7MCx5NR4PyySI7VExJtzkSsFz1l+XD4UUIRbbvE2D9Ip8AXw3
         t5n9kEtpGoaK3kiUnOXkunkT9WfRlY9bFVDYna8InTJZkNeggCG75qJopIqjKulw+vJT
         TI88tzewA8+ra46Q/ZpSt+LqzgY8GQzzun72nZ7FL0VhD8765ZostkA+1/iHINs0k08s
         gt05blYUZ0J+5YSXWrg/UySU7a3/0wzwszhhwNvUEKMovQEIMGakDNYvXAcbA/7qO6I7
         lvinIMAF/9M+JZCdc+yfPg3QBVLjz3rqTxJ5MD0TqD25aqEzB4BMYplGNFipd4mw47d6
         agkQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=il9Pck9IsIM62v468p0OkwRij0VejED4nE+yuVLG5G4=;
        fh=c70s1KKSKD3NEmFsrB3TSl6UHg8OAVQAe3mU11bIF9k=;
        b=DscezaKFJh7uqyRuC3NBf1Mm8Gglicqn66lezqWKycaK0IJtlmmMMWWFY+nSoBiBPl
         xivFktzHTX4TmewNxfEphpbEg1/bWGQyk1hnmEaDUg8UyRC5GHK0mp5CfA187nfJRAHe
         m/cTZ7Ew3W9o2spWsPZwTFN//vFlZVJOQRZXQfmYzZdS9z4LfvZUNz3LNXspqDTWzzCI
         NuVwUK8HULokmRs/dw2vc0Otr53L8dQ4qLmKkLiB8s3mGwT7zT06V0GT115tHbZ7pNq7
         Nmh1A7ThhYSPPF6JHzeAA5ukI/KpqXqMXhmOHv8S0FZWawawet+WXt2i9ZvxFXmLCvmU
         Y21A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=d62WgcLE;
       spf=pass (google.com: domain of rmoar@google.com designates 2607:f8b0:4864:20::f32 as permitted sender) smtp.mailfrom=rmoar@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-qv1-xf32.google.com (mail-qv1-xf32.google.com. [2607:f8b0:4864:20::f32])
        by gmr-mx.google.com with ESMTPS id 00721157ae682-71b5a2dc4f6si5514877b3.0.2025.08.05.08.19.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 05 Aug 2025 08:19:17 -0700 (PDT)
Received-SPF: pass (google.com: domain of rmoar@google.com designates 2607:f8b0:4864:20::f32 as permitted sender) client-ip=2607:f8b0:4864:20::f32;
Received: by mail-qv1-xf32.google.com with SMTP id 6a1803df08f44-704c5464aecso48629996d6.0
        for <kasan-dev@googlegroups.com>; Tue, 05 Aug 2025 08:19:17 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCV+4ZH+dU70LGOklQT6p0vq/QTDRn4OOIOwzB4nmrj2dDTqU2FqXY7sRkp0jEEUDxPx2yD6gQt8phQ=@googlegroups.com
X-Gm-Gg: ASbGncuhvYjczG1fJsfrf9JJUadcQV16+U0bKZfLC3MkbDBo1TH8hDKJiPwxAJVqUQM
	JeQUHcw9vgtMAMsJdTT9DzBm0fVoiAx8L3pAPEIde0/GHG0W5YjYWgY5FKcw9FKa81iQ4QQt3Xv
	N/fhVGGH8P7mxA4b/0lSdhx9GxG74DUswUDOj6+MUa5ke2AnZaDgqGXgwJZ6DN3C1FssJJnGAyy
	vI0Hji7G9bqk0lLs1oUmpuE3W3unwPdDL3w0t2Xeg==
X-Received: by 2002:ad4:5b8f:0:b0:6fa:c81a:6231 with SMTP id
 6a1803df08f44-70935f3f099mr182696396d6.8.1754407156788; Tue, 05 Aug 2025
 08:19:16 -0700 (PDT)
MIME-Version: 1.0
References: <20250729193647.3410634-1-marievic@google.com> <20250729193647.3410634-8-marievic@google.com>
In-Reply-To: <20250729193647.3410634-8-marievic@google.com>
From: "'Rae Moar' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 5 Aug 2025 11:19:05 -0400
X-Gm-Features: Ac12FXwIYISejq5E32R90mOlfU2aOU_svsUKJMC2HWJWPZDH6qlcqSczsSA0db4
Message-ID: <CA+GJov5gBEKDpB=fLwiP5VBjoMJLkDeEcPhfn=SEr+tLoYWHFA@mail.gmail.com>
Subject: Re: [PATCH 7/9] kunit: Add example parameterized test with shared
 resources and direct static parameter array setup
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
 header.i=@google.com header.s=20230601 header.b=d62WgcLE;       spf=pass
 (google.com: domain of rmoar@google.com designates 2607:f8b0:4864:20::f32 as
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
> Add `example_params_test_with_init` to illustrate how to manage
> shared resources across parameterized KUnit tests. This example
> showcases the use of the new `param_init` function and its registration
> to a test using the `KUNIT_CASE_PARAM_WITH_INIT` macro.
>
> Additionally, the test demonstrates:
> - How to directly assign a static parameter array to a test via
>   `kunit_register_params_array`.
> - Leveraging the Resource API for test resource management.
>
> Signed-off-by: Marie Zhussupova <marievic@google.com>

Hello!

I am always happy to see a new example test. I have a few tiny
nitpicky comments below. I would be happy for this to go in as-is or
just include the next test in the series as David suggested.

Reviewed-by: Rae Moar <rmoar@google.com>

Thanks!
-Rae

> ---
>  lib/kunit/kunit-example-test.c | 112 +++++++++++++++++++++++++++++++++
>  1 file changed, 112 insertions(+)
>
> diff --git a/lib/kunit/kunit-example-test.c b/lib/kunit/kunit-example-tes=
t.c
> index 3056d6bc705d..5bf559e243f6 100644
> --- a/lib/kunit/kunit-example-test.c
> +++ b/lib/kunit/kunit-example-test.c
> @@ -277,6 +277,116 @@ static void example_slow_test(struct kunit *test)
>         KUNIT_EXPECT_EQ(test, 1 + 1, 2);
>  }
>
> +/*
> + * This custom function allocates memory for the kunit_resource data fie=
ld.
> + * The function is passed to kunit_alloc_resource() and executed once
> + * by the internal helper __kunit_add_resource().
> + */

I don't think it is necessary to include that this function is
executed by an internal function: __kunit_add_resource(). Especially
since we have other example tests for the resource API.

> +static int example_resource_init(struct kunit_resource *res, void *conte=
xt)
> +{
> +       int *info =3D kmalloc(sizeof(*info), GFP_KERNEL);
> +
> +       if (!info)
> +               return -ENOMEM;
> +       *info =3D *(int *)context;
> +       res->data =3D info;
> +       return 0;
> +}
> +
> +/*
> + * This function deallocates memory for the 'kunit_resource' data field.
> + * The function is passed to kunit_alloc_resource() and automatically
> + * executes within kunit_release_resource() when the resource's referenc=
e
> + * count, via kunit_put_resource(), drops to zero. KUnit uses reference
> + * counting to ensure that resources are not freed prematurely.
> + */

Similarly, I think this is a bit too much information since we have
other tests for the resource API. I would maybe shorten this by
removing the references to kunit_release_resource() and
kunit_put_resource().

> +static void example_resource_free(struct kunit_resource *res)
> +{
> +       kfree(res->data);
> +}
> +
> +/*
> + * This match function is invoked by kunit_find_resource() to locate
> + * a test resource based on defined criteria. The current example
> + * uniquely identifies the resource by its free function; however,
> + * alternative custom criteria can be implemented. Refer to
> + * lib/kunit/platform.c and lib/kunit/static_stub.c for further examples=
.
> + */

Again I would consider shortening this description.



> +static bool example_resource_alloc_match(struct kunit *test,
> +                                        struct kunit_resource *res,
> +                                        void *match_data)
> +{
> +       return res->data && res->free =3D=3D example_resource_free;
> +}
> +
> +/*
> + * This is an example of a function that provides a description for each=
 of the
> + * parameters.
> + */
> +static void example_param_array_get_desc(const void *p, char *desc)
> +{
> +       const struct example_param *param =3D p;
> +
> +       snprintf(desc, KUNIT_PARAM_DESC_SIZE,
> +                "example check if %d is less than or equal to 3", param-=
>value);
> +}
> +
> +/*
> + * Initializes the parent kunit struct for parameterized KUnit tests.
> + * This function enables sharing resources across all parameterized
> + * tests by adding them to the `parent` kunit test struct. It also suppo=
rts
> + * registering either static or dynamic arrays of test parameters.
> + */
> +static int example_param_init(struct kunit *test)
> +{
> +       int ctx =3D 3; /* Data to be stored. */
> +       int arr_size =3D ARRAY_SIZE(example_params_array);
> +
> +       /*
> +        * This allocates a struct kunit_resource, sets its data field to
> +        * ctx, and adds it to the kunit struct's resources list. Note th=
at
> +        * this is test managed so we don't need to have a custom exit fu=
nction
> +        * to free it.
> +        */
> +       void *data =3D kunit_alloc_resource(test, example_resource_init, =
example_resource_free,
> +                                         GFP_KERNEL, &ctx);
> +
> +       if (!data)
> +               return -ENOMEM;
> +       /* Pass the static param array information to the parent struct k=
unit. */
> +       kunit_register_params_array(test, example_params_array, arr_size,
> +                                   example_param_array_get_desc);
> +       return 0;
> +}
> +
> +/*
> + * This is an example of a parameterized test that uses shared resources
> + * available from the struct kunit parent field of the kunit struct.
> + */
> +static void example_params_test_with_init(struct kunit *test)
> +{
> +       int threshold;
> +       struct kunit_resource *res;
> +       const struct example_param *param =3D test->param_value;
> +
> +       /* By design, param pointer will not be NULL. */
> +       KUNIT_ASSERT_NOT_NULL(test, param);
> +
> +       /* Here we access the parent pointer of the test to find the shar=
ed resource. */
> +       res =3D kunit_find_resource(test->parent, example_resource_alloc_=
match, NULL);
> +
> +       KUNIT_ASSERT_NOT_NULL(test, res);
> +
> +       /* Since the data field in kunit_resource is a void pointer we ne=
ed to typecast it. */
> +       threshold =3D *((int *)res->data);
> +
> +       /* Assert that the parameter is less than or equal to a certain t=
hreshold. */
> +       KUNIT_ASSERT_LE(test, param->value, threshold);
> +
> +       /* This decreases the reference count after calling kunit_find_re=
source(). */
> +       kunit_put_resource(res);
> +}
> +
>  /*
>   * Here we make a list of all the test cases we want to add to the test =
suite
>   * below.
> @@ -296,6 +406,8 @@ static struct kunit_case example_test_cases[] =3D {
>         KUNIT_CASE(example_static_stub_using_fn_ptr_test),
>         KUNIT_CASE(example_priv_test),
>         KUNIT_CASE_PARAM(example_params_test, example_gen_params),
> +       KUNIT_CASE_PARAM_WITH_INIT(example_params_test_with_init, NULL,
> +                                  example_param_init, NULL),
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
A%2BGJov5gBEKDpB%3DfLwiP5VBjoMJLkDeEcPhfn%3DSEr%2BtLoYWHFA%40mail.gmail.com=
.
