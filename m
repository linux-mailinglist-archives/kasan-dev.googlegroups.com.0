Return-Path: <kasan-dev+bncBC6OLHHDVUOBBIN4W7CAMGQE7ZJNCSY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3c.google.com (mail-qv1-xf3c.google.com [IPv6:2607:f8b0:4864:20::f3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 43A28B18D38
	for <lists+kasan-dev@lfdr.de>; Sat,  2 Aug 2025 11:45:07 +0200 (CEST)
Received: by mail-qv1-xf3c.google.com with SMTP id 6a1803df08f44-7075d48a15bsf28681176d6.3
        for <lists+kasan-dev@lfdr.de>; Sat, 02 Aug 2025 02:45:07 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1754127906; cv=pass;
        d=google.com; s=arc-20240605;
        b=TQpnv0BcEoS15V54rDSRGzp478m/xRbFwWAoltYR7OqV4J3colt/RoSfM8iApdrJa7
         ZjVF0Py+MilqTaTV3Qe9X1/P9w1quw55tPFVhG5xt+vBPFf7OrMR6qYk870evT0CVe2d
         XHSwoojqvHIs0X6n7B0s/JyJP2xfbtIptFQUupMbtDRlY9T1eXt6wMH0Oe30m95itkMX
         t/mPJGf+5PTxyUL+Wn5fUUt46/3doc1vAZNENVmr+bobg/j7ppsVgl8/LSOm57Ne17qd
         Hlph7M5Ou0nGHSX+xLJnNvlA9aLlxORMWLZetY13RbkOn3LvjqVfrgx2tsQYjrDxT6Vw
         ISmg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=pzJ7llUcB8Ia+IKF3hVvr6f/wxEQrC2zRZ0vb4qjaqI=;
        fh=kYi3AHT5M/q2XY3tU7OtWBpXPAdmx9x5Ful3IBa7rG4=;
        b=c6RpaQIoJiZ41yOb3PSZMa3MIM2w5YCD5k4KRKKVCZsNmu0B3q1eO4zaVjggRWajRW
         HFsrZttNB/c+8RUpoUPyhv3rxnHx7hev946V50t4lY2i0a2dRGP/2Pibhxrxq9VFqHSc
         qCSnCxbj3raRbYes/oWzKrTwS7sHunXfZokMoU/dVEdTG4VklL/X52gqQ1+7P3oXP0i4
         926OPYTgJlArv17Ec7anS60pO0VySqvImhlf5cCDJqdzkaFU5O+KZmdPJElrQrKWeWWf
         B0Xw6PFPcDMxnqV5fgec1IxwQGe4PXGSbwx5jXkK34GnaCVLCNeiKHzScGT4kJRbog/x
         MVZg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=mEPpAKFJ;
       spf=pass (google.com: domain of davidgow@google.com designates 2607:f8b0:4864:20::733 as permitted sender) smtp.mailfrom=davidgow@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1754127906; x=1754732706; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=pzJ7llUcB8Ia+IKF3hVvr6f/wxEQrC2zRZ0vb4qjaqI=;
        b=FUnD8Bc+jRtGnE2YSmPIFPClNdIevH1DDeOxOAE5MTkq4G4MwNN4AEHb4Sgu+Qzitz
         qjcU+OfkTf0ZcpqFnewtH134bM0MtpkFB4aozFW2jSciOjAy6itpTTHpozrUWv+IaocP
         cASJhxkxmCTeqL9LjcTQsxZomkfInUB+qPho4qn/yoa5kWoTHRNsNipDIqE18giNjy3w
         UoKsBG76anTzG6nF9JskED7goDV0m/YAJ0Vx313ewsH2wyYQLxhBC1jhq0llNLrP5EBV
         WA1EefexCnFdmAoZnM3N7X0F4TpRIVe5DTB+NeqSwMW9qZ3eEegfj0nHqqOpC8zwopjL
         0H9g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1754127906; x=1754732706;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=pzJ7llUcB8Ia+IKF3hVvr6f/wxEQrC2zRZ0vb4qjaqI=;
        b=dGKr6uoyMt/uQdLmwJZ1r4vGJ//TY8D5+ylTC3lkOcySf+JDTeFbeQy2iKYyAEt63s
         vFYB9puv4M82vzpNPErwouLRLTOHT/J5IXE9KO8wZr56C4rVR8O6zX5KgrwXhL/kR3Ty
         osfkssVONRNs/u1TiCr72H6DrFGOUtpLL8gDItijp3t5aDpYoFX2LS/Z4H35wCy5Bgk5
         Nr7V6hrifFgtiO024PkUidy8bsVXcDqvyN7cpVL/YcyeH5VQSj6QxAZjS9TcOe1ttCsb
         jqRV3WEkGg70aMwlzF7p/AFT/bcMvE2G5iXTd3z5KZ5zR4QMhisgArzGoNxHWB6afRyB
         t55A==
X-Forwarded-Encrypted: i=2; AJvYcCXuxD39jNnyOnPlwCRSjeFSSByRLn74GEfKBU2U8IB5xLKXU1d4HSYlbIZ+kXQ03ZBLW0pDGA==@lfdr.de
X-Gm-Message-State: AOJu0Yw6Ttxvjon1v7A/LmSTN/3w85FywkXa429T1/fDuGrqQJ8R+gHt
	MK7I5CvzNBTmvcsyWlKrW1IghB5qpuAIR/+eUoSsdico9aEORedIEkC/
X-Google-Smtp-Source: AGHT+IEYLPYH22ShUZ11nl/to3F46KrKaM/CB54MPwXlLmaLkSH85is3wfeqKnA8GirWDP8JtDcW8w==
X-Received: by 2002:a05:6214:5003:b0:707:6977:aa9f with SMTP id 6a1803df08f44-709362fabc8mr38707106d6.36.1754127905991;
        Sat, 02 Aug 2025 02:45:05 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdABe+thy/IQ+/k8KDb1sKcdE2z23f7iIWYFhz1JRB5sw==
Received: by 2002:a05:6214:5284:b0:707:4335:5f7 with SMTP id
 6a1803df08f44-7077687065bls47207046d6.0.-pod-prod-09-us; Sat, 02 Aug 2025
 02:45:05 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXFw/nuFr+R7ocEdumnc0GfMx2XubqC+3cLxxF0GQNCYiGROBeGEnTWAfM7WnC/u7u5QP1FipQgnyM=@googlegroups.com
X-Received: by 2002:a05:620a:214d:b0:7e6:2de8:7c1 with SMTP id af79cd13be357-7e69637248fmr310880885a.50.1754127905132;
        Sat, 02 Aug 2025 02:45:05 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1754127905; cv=none;
        d=google.com; s=arc-20240605;
        b=UHaWDUpbKB97sySK3Vmv6PJ33kymiNDRf1odVgk7ZQGeRhc3yHsAL1xyykh/Rd/+Bs
         kzoJBVhuB38pei++SoLy53Zg2AyCq3nHyOppf/CTWxmbigPKRS97JC9uic5NOXhABQ+Y
         nJOgEtpFFBU8iGJvGpYizXA2al+sC7yyhUaokp9o9YK6K519JgbvnA3fK20IJFD6Qq1a
         c31kaUBwuMr21bO0L4kkC4v8X5SHwIBHVmkirfb+6Lnii9OIp8Bw57xvsa4FtMcqlKrh
         8HLZ7H4s3zkTRYFdcDlQYuCIJzTDkTSBASe2P052XEDuZ/RfBpSV8J7FPHL4XI/aURsv
         papQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=0A+oXsgHPaE48YzMmMnSQ4SCkYgdZArGjAAzK81nsJM=;
        fh=YnMszGH0QCwURRNPTOUCqukAzQUkEahXtUjgKlzE0X0=;
        b=NiDBWFOW4akreMnj79R4bo8qEAKEWz5f8leW0jLLexv4dfe0buF3lBNWp7gC2gkqCD
         XguaPG/KQloAyPfNJQkMBUPhuOkJaEqUUkmUK1YUXnVcOhoykE4KH7GpSKvHX94P0YuX
         2zcrwOQlUsdtNn0E4s6wnA3M86YW/Goz6fw714SM+pTtbP1IKIW0FztJDpN62U7LrL3G
         gIE2hDy7a92cvFG7JdyCdXUpD9CLZNjFT5ryrRmj4uXPRNmXvsbfwc6XCYNj/QqG9hHf
         4ry/6km2+IiKBvAtHYTQLAxj1w8GkpSuK+cWPxECTIONf4cEljISO1an25Lcpp00IpXE
         SDXA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=mEPpAKFJ;
       spf=pass (google.com: domain of davidgow@google.com designates 2607:f8b0:4864:20::733 as permitted sender) smtp.mailfrom=davidgow@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-qk1-x733.google.com (mail-qk1-x733.google.com. [2607:f8b0:4864:20::733])
        by gmr-mx.google.com with ESMTPS id af79cd13be357-7e67f4c1f4asi20468585a.3.2025.08.02.02.45.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 02 Aug 2025 02:45:05 -0700 (PDT)
Received-SPF: pass (google.com: domain of davidgow@google.com designates 2607:f8b0:4864:20::733 as permitted sender) client-ip=2607:f8b0:4864:20::733;
Received: by mail-qk1-x733.google.com with SMTP id af79cd13be357-7e050bd078cso153656185a.3
        for <kasan-dev@googlegroups.com>; Sat, 02 Aug 2025 02:45:05 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUYxw/0q/1IZtS5f6eNHMKdGZPkNpG0aovAT0GyRJD88jSvdQCPOsBfLwrqwPYap7LvCm1ihK0raEE=@googlegroups.com
X-Gm-Gg: ASbGncvjedG8RwjU7KG+mJjHHrdePF5hPyAAHgeofFPSduGmYhA1j5nBetUOZl4XNv6
	WRKdxzb8NNDc6o54sb2MJHGgwVgnGTjfbTduHMSCIT4CR1SPuxZx445YBdGqfmY5w3Qp5Kq8Irn
	+RrvjqwJSc1FcaZW3ZMz7fFADos3tZwjyWfjmVDWI3FOYGfqxFrjCwx45ajswnO1br8IFezxm+N
	d+mfMOh
X-Received: by 2002:ad4:5fc5:0:b0:707:228e:40b9 with SMTP id
 6a1803df08f44-70936287ad8mr45107586d6.23.1754127904429; Sat, 02 Aug 2025
 02:45:04 -0700 (PDT)
MIME-Version: 1.0
References: <20250729193647.3410634-1-marievic@google.com> <20250729193647.3410634-8-marievic@google.com>
In-Reply-To: <20250729193647.3410634-8-marievic@google.com>
From: "'David Gow' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Sat, 2 Aug 2025 17:44:52 +0800
X-Gm-Features: Ac12FXzokTljgoRE0qgMSt-yhLKe30tCy77nOkh0UcaQ2bdId83zWO9qV660R1w
Message-ID: <CABVgOSmBssmMz3qQi+TdEoaGQJNXaSVBrsO8RSW0MjLUUHPakg@mail.gmail.com>
Subject: Re: [PATCH 7/9] kunit: Add example parameterized test with shared
 resources and direct static parameter array setup
To: Marie Zhussupova <marievic@google.com>
Cc: rmoar@google.com, shuah@kernel.org, brendan.higgins@linux.dev, 
	elver@google.com, dvyukov@google.com, lucas.demarchi@intel.com, 
	thomas.hellstrom@linux.intel.com, rodrigo.vivi@intel.com, 
	linux-kselftest@vger.kernel.org, kunit-dev@googlegroups.com, 
	kasan-dev@googlegroups.com, intel-xe@lists.freedesktop.org, 
	dri-devel@lists.freedesktop.org, linux-kernel@vger.kernel.org
Content-Type: multipart/signed; protocol="application/pkcs7-signature"; micalg=sha-256;
	boundary="000000000000ac3125063b5eba7d"
X-Original-Sender: davidgow@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=mEPpAKFJ;       spf=pass
 (google.com: domain of davidgow@google.com designates 2607:f8b0:4864:20::733
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

--000000000000ac3125063b5eba7d
Content-Type: text/plain; charset="UTF-8"

On Wed, 30 Jul 2025 at 03:37, Marie Zhussupova <marievic@google.com> wrote:
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
> ---

Thanks for writing some examples! This is great, and makes the rest of
the series much easier to understand.

(It also reminds me how much I hate the verbose parts of the resource
API, but it's definitely out of scope to refactor that here. :-))

It does seem like this is a lot of effort to go through for one shared
integer, though. In the real world, I'd suggest using
kunit->parent->priv here. As an example, though, it's fine (though
maybe using a named resource or even kunit_kzalloc() or similar would
give a better example of how convenient this could be.

It's also not entirely clear why we're using
kunit_register_params_array() for a static array, when
KUNIT_ARRAY_PARAM() exists. (This is clearly because the latter
doesn't support init functions; and I see why we don't necessarily
want to make the number of macros explode through adding
KUNIT_ARRAY_PARAM_WITH_INIT() et al, but maybe we should note that in
the commit description, either here or before.)

Actual test looks fine, though:

Reviewed-by: David Gow <davidgow@google.com>

Cheers,
-- David


>  lib/kunit/kunit-example-test.c | 112 +++++++++++++++++++++++++++++++++
>  1 file changed, 112 insertions(+)
>
> diff --git a/lib/kunit/kunit-example-test.c b/lib/kunit/kunit-example-test.c
> index 3056d6bc705d..5bf559e243f6 100644
> --- a/lib/kunit/kunit-example-test.c
> +++ b/lib/kunit/kunit-example-test.c
> @@ -277,6 +277,116 @@ static void example_slow_test(struct kunit *test)
>         KUNIT_EXPECT_EQ(test, 1 + 1, 2);
>  }
>
> +/*
> + * This custom function allocates memory for the kunit_resource data field.
> + * The function is passed to kunit_alloc_resource() and executed once
> + * by the internal helper __kunit_add_resource().
> + */
> +static int example_resource_init(struct kunit_resource *res, void *context)
> +{
> +       int *info = kmalloc(sizeof(*info), GFP_KERNEL);
> +
> +       if (!info)
> +               return -ENOMEM;
> +       *info = *(int *)context;
> +       res->data = info;
> +       return 0;
> +}
> +
> +/*
> + * This function deallocates memory for the 'kunit_resource' data field.
> + * The function is passed to kunit_alloc_resource() and automatically
> + * executes within kunit_release_resource() when the resource's reference
> + * count, via kunit_put_resource(), drops to zero. KUnit uses reference
> + * counting to ensure that resources are not freed prematurely.
> + */
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
> + * lib/kunit/platform.c and lib/kunit/static_stub.c for further examples.
> + */
> +static bool example_resource_alloc_match(struct kunit *test,
> +                                        struct kunit_resource *res,
> +                                        void *match_data)
> +{
> +       return res->data && res->free == example_resource_free;
> +}
> +
> +/*
> + * This is an example of a function that provides a description for each of the
> + * parameters.
> + */
> +static void example_param_array_get_desc(const void *p, char *desc)
> +{
> +       const struct example_param *param = p;
> +
> +       snprintf(desc, KUNIT_PARAM_DESC_SIZE,
> +                "example check if %d is less than or equal to 3", param->value);
> +}
> +
> +/*
> + * Initializes the parent kunit struct for parameterized KUnit tests.
> + * This function enables sharing resources across all parameterized
> + * tests by adding them to the `parent` kunit test struct. It also supports
> + * registering either static or dynamic arrays of test parameters.
> + */
> +static int example_param_init(struct kunit *test)
> +{
> +       int ctx = 3; /* Data to be stored. */
> +       int arr_size = ARRAY_SIZE(example_params_array);
> +
> +       /*
> +        * This allocates a struct kunit_resource, sets its data field to
> +        * ctx, and adds it to the kunit struct's resources list. Note that
> +        * this is test managed so we don't need to have a custom exit function
> +        * to free it.
> +        */
> +       void *data = kunit_alloc_resource(test, example_resource_init, example_resource_free,
> +                                         GFP_KERNEL, &ctx);
> +
> +       if (!data)
> +               return -ENOMEM;
> +       /* Pass the static param array information to the parent struct kunit. */
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
> +       const struct example_param *param = test->param_value;
> +
> +       /* By design, param pointer will not be NULL. */
> +       KUNIT_ASSERT_NOT_NULL(test, param);
> +
> +       /* Here we access the parent pointer of the test to find the shared resource. */
> +       res = kunit_find_resource(test->parent, example_resource_alloc_match, NULL);
> +
> +       KUNIT_ASSERT_NOT_NULL(test, res);
> +
> +       /* Since the data field in kunit_resource is a void pointer we need to typecast it. */
> +       threshold = *((int *)res->data);
> +
> +       /* Assert that the parameter is less than or equal to a certain threshold. */
> +       KUNIT_ASSERT_LE(test, param->value, threshold);
> +
> +       /* This decreases the reference count after calling kunit_find_resource(). */
> +       kunit_put_resource(res);
> +}
> +
>  /*
>   * Here we make a list of all the test cases we want to add to the test suite
>   * below.
> @@ -296,6 +406,8 @@ static struct kunit_case example_test_cases[] = {
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

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CABVgOSmBssmMz3qQi%2BTdEoaGQJNXaSVBrsO8RSW0MjLUUHPakg%40mail.gmail.com.

--000000000000ac3125063b5eba7d
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
0TANBglghkgBZQMEAgEFAKCBxzAvBgkqhkiG9w0BCQQxIgQg0unXhsAh19CYxRmE09urK0VqVIjg
URbRQrf6MUNFcKQwGAYJKoZIhvcNAQkDMQsGCSqGSIb3DQEHATAcBgkqhkiG9w0BCQUxDxcNMjUw
ODAyMDk0NTA1WjBcBgkqhkiG9w0BCQ8xTzBNMAsGCWCGSAFlAwQBKjALBglghkgBZQMEARYwCwYJ
YIZIAWUDBAECMAoGCCqGSIb3DQMHMAsGCSqGSIb3DQEBBzALBglghkgBZQMEAgEwDQYJKoZIhvcN
AQEBBQAEggEAY+/VExwHeYsdpbNF/3HLGuDNQwgKvrGAp8mSqssDtWYwBHpGx/z9yeWeqvi5Ky4L
3TUZup6hFWhsquKAzBuJCwDbXcvWvdbFCX0Z91GUUL4I5/cUi4oGA3o7QaEjSauNWAPJZh9Xs/k9
4teKVoIsnVrLnvW3IO87V52NDIajSY1uLBgVbAJNZeHc9PpgQEsgzorDPFogSMGA6kNL7u0GeZvj
lr1B1kVwkSff5G3XCEdTKZ5Gepr9qZn1v70jMxuNMwMQW9b0Y2DgyvGvogjaiu7dLZ8MctzpomKh
UVHNSvh9frTez0vj3aoivnKZaMI6QK1k8CWWoZwZP5aA5kS+5Q==
--000000000000ac3125063b5eba7d--
