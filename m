Return-Path: <kasan-dev+bncBDPPVSUFVUPBBX7553CAMGQETWOP7UY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3d.google.com (mail-qv1-xf3d.google.com [IPv6:2607:f8b0:4864:20::f3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 7D542B23BCC
	for <lists+kasan-dev@lfdr.de>; Wed, 13 Aug 2025 00:23:28 +0200 (CEST)
Received: by mail-qv1-xf3d.google.com with SMTP id 6a1803df08f44-709dfc1cdeasf25027066d6.3
        for <lists+kasan-dev@lfdr.de>; Tue, 12 Aug 2025 15:23:28 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755037407; cv=pass;
        d=google.com; s=arc-20240605;
        b=L/uDbfm26+LrXUxIzg604EBiqGe0We1WJO1fITHU8xZ+ZUDO/rbPzSpfvzUkyEnb5i
         ZMZhjBt2RPSpZ4arNAfyfjVeqixOkjzhA0UbzVr+P8EOIluDE8zCFTZyoVk1KHWexvm8
         FIosbHwzdz/to0pcHKl2UDnR+xfY/3wgrp5vDLQ/yX+HNMV2AwU6JoKq8gDRJ3OvJU1i
         hriRg7GW1FcaDaGqRdnAwCsDGFEQP5ucLJdSIBlEKTU372Cu8ozDzW5uAIFf0d4cjCL/
         VHo9hxSsF6YIFWw3FPAMGi4Ct6E6PTO1pQG3SXYPnA5veFtdnFKcHHWahD6nWLtZK9pA
         9o5g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=meGknyHd2AMhdQ3nZSOvrcZECl0pmjq2XiM1W7YRJFk=;
        fh=IGitMvDXr4OMu54PEvgvyiPbEXxlzbOnow8K1R/9Y+w=;
        b=E4xhbfDJCx1gI7Wsdd/77MoMFgPJ/4jt2Q01q1mwqAvTkM6aZVjW3HHuAboNf2mXpt
         MrEBVzBYNh7tG1R/cnGDQGiYsUQTFeY3clOIcOaE5VaxQbk4g4saFceZ0WCUZPajGHZa
         2zeqdxIxwAAwSTw7GX+oDGytCOX7mx3e5z6l84ynoaJBTMzgTv+SAuWoNSCi/n1EPWlU
         pV29KlLVvBumtydj9Q13Uc7HiNAsYPYLtlN+tdXjcqtgHu5M9Vxw2SGio3bsNsjXwzGE
         GDbURBBkUk95CeIMd2iulPqgG5cj+D+DKGK7fhYAbpL1oZ+624bc55fXY1nFjr07CNDQ
         ZJqQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=zQzJ71x+;
       spf=pass (google.com: domain of rmoar@google.com designates 2607:f8b0:4864:20::f29 as permitted sender) smtp.mailfrom=rmoar@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755037407; x=1755642207; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=meGknyHd2AMhdQ3nZSOvrcZECl0pmjq2XiM1W7YRJFk=;
        b=dS7jWzFX1FIOgWPI+uOfXUH6piheUcvNG6Q8tcMALUtecRQ96EQ1NsnZOquRH3RzMo
         XV60wQP4sRWxUxTH7B3cFI46v44tAJB6qBHnF9O0cpq7Vc6353JBq2IEEuhZQWWRWQwq
         ao/upTwi2WfmjQAwtiCK94iu460W+AxX6Q/sr0m/VrWj7b5h5tosSi7cNrlrt9yusAVM
         EFD45Tkb1s1PisJQrrk6OdFi91TRKyyqBMwbfUTmvaDROeCXZut+MtxPS5NeuaZ+sYyQ
         UQn6c5ghTO9IFnO0WZSRRZJrnS4FDsQLpKAXqpIjm3/oZEiGDGE43ZshUvPQF6DxOP6v
         vUAA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755037407; x=1755642207;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=meGknyHd2AMhdQ3nZSOvrcZECl0pmjq2XiM1W7YRJFk=;
        b=Yxu1kJdXoa7Stv93PTxSnSbGOrwoEqK4m5bXxrzENwvivK8sLe+kYo6TOWx6pHt1rp
         Nj55N7cTnPXo6wMSwhA/zb7ghPAwR6y6nr7jl9fj09Xza86ZWQ4vg4/4Nf15E0sKBW3q
         Nox/nSxSheiWsMTo/7gQLWRLwtQtL0QAQqc9t87BAmjzCG1RyshzVsr9lk0UMVkoLQUp
         lqg4cE6QvGu7LF79u3oZTxnSplu/R7tjoe6WpfsGj9v2IoiEQOwXp6tBhHLDbuJ4O2NN
         WjTsj6ms4cW5o0rsnFqIuHiZSSmqEBHu0xS3RyI6FYadI3aMoF+LMXWexvjnbj1swpx0
         pjXA==
X-Forwarded-Encrypted: i=2; AJvYcCXxh/8I7FKZrSZtTad/hrt9FI9WWxeHBBiSyLPLe4lUwO8hzgRqqZGpirpiEXqdqeLgUD7lHw==@lfdr.de
X-Gm-Message-State: AOJu0YyJRYCYRooXGNKBDKfhXuFR6fmyqMy4fKvxu6k860ooFGmXq0JM
	NFxE8DO87RJhzfEPFwQAXSDjBQ+zwyl7G+1+zChcO0KZuH1cIFWvYr+c
X-Google-Smtp-Source: AGHT+IHLwfzf0ujAHgv9cOJu/Sk2uBHazCj8tJScJc4wW/WoN8Yu2pS4Rd5YYPj4ZUqp/KSciD7/pQ==
X-Received: by 2002:a05:6214:c62:b0:709:b6a7:5f16 with SMTP id 6a1803df08f44-709e8968ffbmr12298816d6.28.1755037407253;
        Tue, 12 Aug 2025 15:23:27 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcb505S4xq0ZfiaWl40VmkL409pCKlVBvv8nNbmtALTXw==
Received: by 2002:a05:6214:2425:b0:707:6c93:e847 with SMTP id
 6a1803df08f44-709883a67eels101758546d6.2.-pod-prod-07-us; Tue, 12 Aug 2025
 15:23:26 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUgX4+WUHeRi3W2PJQig9bFeK8N483FIxPLvi0ynuiX3Ldwl/4X0sGYLkaO0JjkZ9vNHEM6X6hq/a4=@googlegroups.com
X-Received: by 2002:ad4:5aa7:0:b0:709:96c8:1c28 with SMTP id 6a1803df08f44-709e89dc4camr9562686d6.41.1755037406400;
        Tue, 12 Aug 2025 15:23:26 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755037406; cv=none;
        d=google.com; s=arc-20240605;
        b=WLRypXS7GDEnFXGsfvWHumfEBAXz9eD2iJLQbyqtv7wNmTbYdpIvmgzhwhhW4jwe0/
         P7u5Bft2NR7vzpFu6oKX/2w3TpH/s6AZG4kH9dF1IXLqbVL/ir7oQuunYowYTX/vFIdk
         tCwmGZgdEFBXhtBIdX3DjBIYoo3tISCUGGXL15fHahLow2JZGCV83k7mB5nabkUJxBDB
         VFFQe5IvtH06CVwYuurRJ3TwRH+fpfZKaCW+axwkIn/yG4G4AXWAUxz5sHd5DS0Upab9
         24DpIZQNGfAr9ReuGId28HExlbdu2I6PET9EzLW2oysweWt3DfO0fvfRGCHarNwr0wYG
         Aemg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=dd43W/9BQYq1dF7t5hnMw3+hXQjYGCxHF8+As7wEnrs=;
        fh=rG9TyP7fQ8kHBAKzMSI7hqDmSycGCS2YvtJugW5csE8=;
        b=Qb/18jnRsVebg9a79rdeba+3gEdDj1Z8qns/trPV0rJJ2IDTiLNiLuoMQ6MB8mY3mT
         Suf3u9iXV5Z1/qwnsmcO20HRUJiQJOP8Sb5Pjz/wRVqxPdJY0oAxjG3K6diAppDFfcKJ
         6iYa/ZO4gx4Bz/r7GUep8zjRHoOomM97LF/GRO839o0zpFu6vpOm99F3lB4hvmioSOzC
         16YAqhpeVHj7/msyI9SUnHop/Kcq3kyJ3Wory6SSYpHei3uN3YcHDYYx/J1UbM70Gmdp
         GVcG5Yo67UZxHPK4p6Tq4Yo5eTkmAZSaqDllBzOS6CXMJFA9Adn0QZk6agIxC1ja/Buy
         OYZg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=zQzJ71x+;
       spf=pass (google.com: domain of rmoar@google.com designates 2607:f8b0:4864:20::f29 as permitted sender) smtp.mailfrom=rmoar@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-qv1-xf29.google.com (mail-qv1-xf29.google.com. [2607:f8b0:4864:20::f29])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-7077c95ddf1si2519786d6.7.2025.08.12.15.23.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 12 Aug 2025 15:23:26 -0700 (PDT)
Received-SPF: pass (google.com: domain of rmoar@google.com designates 2607:f8b0:4864:20::f29 as permitted sender) client-ip=2607:f8b0:4864:20::f29;
Received: by mail-qv1-xf29.google.com with SMTP id 6a1803df08f44-7075ccb168bso49023966d6.0
        for <kasan-dev@googlegroups.com>; Tue, 12 Aug 2025 15:23:26 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCX3lx9GTPJbc7VDXG8unYph65JG/cvLoKHVHMYqKP61AB4cyIWCiBepwtSTh5Casb2kABZBeMLeOtY=@googlegroups.com
X-Gm-Gg: ASbGnctZIoI/TZ0ZKlUD12nB7SqgiaZBG23xJW9fn7v/+sery7QBwcxYvC7DDLTd3OR
	8xIwMTZalPcJhpvdKOAAG/DyESIj6dYc4k3rS0wU+BXI9Xu8V7MciBY6/vEx48KlQCdimAQky5O
	G4zouiOF6k7WOK66CfpNKmLo/uOaOkVzeVH83ndJwk3kO16qD1+hgZjQ4XfVDb/E9Tx4sa0ioNP
	2jOggDWJOxcJwI+9cqO6zlIPjo=
X-Received: by 2002:ad4:5946:0:b0:707:4d3f:c3ae with SMTP id
 6a1803df08f44-709e89af2f6mr10556356d6.36.1755037405616; Tue, 12 Aug 2025
 15:23:25 -0700 (PDT)
MIME-Version: 1.0
References: <20250811221739.2694336-1-marievic@google.com> <20250811221739.2694336-6-marievic@google.com>
In-Reply-To: <20250811221739.2694336-6-marievic@google.com>
From: "'Rae Moar' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 12 Aug 2025 18:23:14 -0400
X-Gm-Features: Ac12FXx4WN7bEpf6eQ3NksoUvds6szYBE3-JX5urqBkn2O7cDov_AcW1Yy1X-70
Message-ID: <CA+GJov4GzpyfEjjBa1j3C6f7bRKGFMmWocMw5CjqY2bJbnH-+A@mail.gmail.com>
Subject: Re: [PATCH v2 5/7] kunit: Add example parameterized test with shared
 resource management using the Resource API
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
 header.i=@google.com header.s=20230601 header.b=zQzJ71x+;       spf=pass
 (google.com: domain of rmoar@google.com designates 2607:f8b0:4864:20::f29 as
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

On Mon, Aug 11, 2025 at 6:18=E2=80=AFPM Marie Zhussupova <marievic@google.c=
om> wrote:
>
> Add example_params_test_with_init() to illustrate how to manage
> shared resources across a parameterized KUnit test. This example
> showcases the use of the new param_init() function and its registration
> to a test using the KUNIT_CASE_PARAM_WITH_INIT() macro.
>
> Additionally, the test demonstrates how to directly pass a parameter arra=
y
> to the parameterized test context via kunit_register_params_array()
> and leveraging the Resource API for shared resource management.
>
> Signed-off-by: Marie Zhussupova <marievic@google.com>
> ---
>
> Changes in v2:
>
> - kunit_array_gen_params() is now explicitly passed to
>   KUNIT_CASE_PARAM_WITH_INIT() to be consistent with
>   a parameterized test being defined by the existence
>   of the generate_params() function.
> - The comments were edited to be more concise.
> - The patch header was changed to reflect that this example
>   test's intent is more aligned with showcasing using the
>   Resource API for shared resource management.
> - The comments and the commit message were changed to
>   reflect the parameterized testing terminology. See
>   the patch series cover letter change log for the
>   definitions.

Hello!

Thank you for adding this example test! As before, this test looks good to =
me:

Reviewed-by: Rae Moar <rmoar@google.com>
Thanks!

-Rae

>
> ---
>
>  lib/kunit/kunit-example-test.c | 118 +++++++++++++++++++++++++++++++++
>  1 file changed, 118 insertions(+)
>
> diff --git a/lib/kunit/kunit-example-test.c b/lib/kunit/kunit-example-tes=
t.c
> index 3056d6bc705d..f2819ee58965 100644
> --- a/lib/kunit/kunit-example-test.c
> +++ b/lib/kunit/kunit-example-test.c
> @@ -277,6 +277,122 @@ static void example_slow_test(struct kunit *test)
>         KUNIT_EXPECT_EQ(test, 1 + 1, 2);
>  }
>
> +/*
> + * This custom function allocates memory and sets the information we wan=
t
> + * stored in the kunit_resource->data field.
> + */
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
> + * This function deallocates memory for the kunit_resource->data field.
> + */
> +static void example_resource_free(struct kunit_resource *res)
> +{
> +       kfree(res->data);
> +}
> +
> +/*
> + * This match function is invoked by kunit_find_resource() to locate
> + * a test resource based on certain criteria.
> + */
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
> + * parameters in a parameterized test.
> + */
> +static void example_param_array_get_desc(struct kunit *test, const void =
*p, char *desc)
> +{
> +       const struct example_param *param =3D p;
> +
> +       snprintf(desc, KUNIT_PARAM_DESC_SIZE,
> +                "example check if %d is less than or equal to 3", param-=
>value);
> +}
> +
> +/*
> + * This function gets passed in the parameterized test context i.e. the
> + * struct kunit belonging to the parameterized test. You can use this fu=
nction
> + * to add resources you want shared across the whole parameterized test =
or
> + * for additional setup.
> + */
> +static int example_param_init(struct kunit *test)
> +{
> +       int ctx =3D 3; /* Data to be stored. */
> +       size_t arr_size =3D ARRAY_SIZE(example_params_array);
> +
> +       /*
> +        * This allocates a struct kunit_resource, sets its data field to
> +        * ctx, and adds it to the struct kunit's resources list. Note th=
at
> +        * this is parameterized test managed. So, it doesn't need to hav=
e
> +        * a custom exit function to deallocation as it will get cleaned =
up at
> +        * the end of the parameterized test.
> +        */
> +       void *data =3D kunit_alloc_resource(test, example_resource_init, =
example_resource_free,
> +                                         GFP_KERNEL, &ctx);
> +
> +       if (!data)
> +               return -ENOMEM;
> +       /*
> +        * Pass the parameter array information to the parameterized test=
 context
> +        * struct kunit. Note that you will need to provide kunit_array_g=
en_params()
> +        * as the generator function to KUNIT_CASE_PARAM_WITH_INIT() when=
 registering
> +        * a parameter array this route.
> +        *
> +        * Alternatively, since this is a static array we can also use
> +        * KUNIT_CASE_PARAM_ARRAY(,DESC) to create  a `*_gen_params()` fu=
nction
> +        * and pass that to  KUNIT_CASE_PARAM_WITH_INIT() instead of regi=
stering
> +        * the parameter array here.
> +        */
> +       kunit_register_params_array(test, example_params_array, arr_size,
> +                                   example_param_array_get_desc);
> +       return 0;
> +}
> +
> +/*
> + * This is an example of a test that uses shared resources available in =
the
> + * parameterized test context.
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
> +       /*
> +        * Here we pass test->parent to search for shared resources in th=
e
> +        * parameterized test context.
> +        */
> +       res =3D kunit_find_resource(test->parent, example_resource_alloc_=
match, NULL);
> +
> +       KUNIT_ASSERT_NOT_NULL(test, res);
> +
> +       /* Since kunit_resource->data is a void pointer we need to typeca=
st it. */
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
> @@ -296,6 +412,8 @@ static struct kunit_case example_test_cases[] =3D {
>         KUNIT_CASE(example_static_stub_using_fn_ptr_test),
>         KUNIT_CASE(example_priv_test),
>         KUNIT_CASE_PARAM(example_params_test, example_gen_params),
> +       KUNIT_CASE_PARAM_WITH_INIT(example_params_test_with_init, kunit_a=
rray_gen_params,
> +                                  example_param_init, NULL),
>         KUNIT_CASE_SLOW(example_slow_test),
>         {}
>  };
> --
> 2.51.0.rc0.205.g4a044479a3-goog
>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
A%2BGJov4GzpyfEjjBa1j3C6f7bRKGFMmWocMw5CjqY2bJbnH-%2BA%40mail.gmail.com.
