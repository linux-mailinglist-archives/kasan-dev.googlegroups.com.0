Return-Path: <kasan-dev+bncBC6OLHHDVUOBBVVQ6HCAMGQEN7W2FPA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x140.google.com (mail-il1-x140.google.com [IPv6:2607:f8b0:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id C9D8FB24524
	for <lists+kasan-dev@lfdr.de>; Wed, 13 Aug 2025 11:18:16 +0200 (CEST)
Received: by mail-il1-x140.google.com with SMTP id e9e14a558f8ab-3e5263e482dsf64286925ab.3
        for <lists+kasan-dev@lfdr.de>; Wed, 13 Aug 2025 02:18:16 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755076695; cv=pass;
        d=google.com; s=arc-20240605;
        b=iKNwjbyK+gjn9gMHA8FX4uEFl16wEdgZF2TwRVJsN/n8ywRmOg3+IQELw7e7lod9S0
         Thps8nAFa1Y2G0CEtVMLrG/P2AJXCfqIIqdeBayzAlMgUpvm7UyqZ70LfJkqKDvij3fn
         DkZ9ePdYs7gA9qrCQeTY5Kam8WFn8wZ6aMdL7mpsQ/G1v9Ayqp3ZfEBk+hkynXc8MDem
         jKUs5klfEtiIDVvSNYivxjC8WKGUrEd5sFjjtRCuznczYCcusLXeExxhYeGVc+N+Aeln
         aF650UYdLqNzd/5iJW9WoIQIYuM2xrgODyNsTLSaaJW0N4Yj/mAck7ca/BXUlsDvu11y
         /OeA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=pcHEKucRBF5ZtMcVfYQBPFj97E+undS7k1LtX+aRm8U=;
        fh=ioheSGbIHLh1YnD8TL/qFHlAeCDQlrBx4Im7MRquML8=;
        b=gHvt13IB3UHa1EF1/oN7sUM6LjVDMCEeL+JerjmuqzxAyorh9FPRbZGtCSM3P6hV+C
         D4O51LaqqDSiBFN+cxcseKD2vWBSb2P674tkgncS5sUoXKkkN6weZ4LxnyYKPvs1RHWZ
         Z9nOAiYWnIv4VPHxqt+k0exvU7RJ/Kos3zfQ6iygpny8A+awOtqm7naGoFvhTYHI4QAA
         aqs3oBn75ztLaDqWvNjgmz/66pXujXPJ7s/xnAJfz6DKFUzyRbw9pMv2fYwvd2UZSRXz
         pgLqkT23ge/O26vzgEupPWV+jQNrsW6Od8riLggcZy1U0w7h0CZVfEm1+50LiNnz3t2P
         CJVw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=DDmnWi9y;
       spf=pass (google.com: domain of davidgow@google.com designates 2607:f8b0:4864:20::f31 as permitted sender) smtp.mailfrom=davidgow@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755076695; x=1755681495; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=pcHEKucRBF5ZtMcVfYQBPFj97E+undS7k1LtX+aRm8U=;
        b=uyO88hqsrJQXvMBxFjn1/xtHenZZ2QNzDyHjkm6DvFfqObvJkCinjdH+HV8zHJXq2A
         e2W+EWjH5sQCeUl5b1NqUxs2BdbL2Ezm4hX0L3Rgh8Xxrb3qfzhc6BQTY36eWscu7OVz
         mt23By5Sy9gIym9dsQO6cnErMOqOUmEvILlivUlKEFh8urr308lRS97zESRPNyOqykH1
         6p/oNahvxIf0w6jrGbupzc65Arw5G4YOPKb90tW6X8LXM1459pGkCexGnJ/N3sfKuoNS
         GE0ipKW6jqFBBCRxqfpZz3uCkejAXlXe5WL9DxV126jSgAsI4dv0YjidOi/uA2tejKjM
         dqtw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755076695; x=1755681495;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=pcHEKucRBF5ZtMcVfYQBPFj97E+undS7k1LtX+aRm8U=;
        b=caf/a0Ond/8uOm8NKdOA3sLUBFXN+3FTttZcwEjeI08Lv/GaYNaxJDoQNYI9uzpnqY
         9iMcEr72Hej4zha2V8woRScNaWggWtxKOG9yV+OQ+rfLeb2bhhwiG4tRxfqQjJPkCaZ4
         5Bo2LzNtKf+8/roL3LcyGQNoplTf4PVZ4roGlVDZgeHzEP9XOSNABAI91E+5g8/szIxe
         m0Qor15pf02J76iHMb7WigO7z/k8dGHGavpiLJ4ZfEg4OEvR78FNfrds+SPLAD9tSrAc
         9W9fb/y6tqqKPlbC+Rz5WgRfnBlDWpIv5L3Gm0SLrT4fV3/AfTwoBIV7jhswX9E1eL0r
         FdQg==
X-Forwarded-Encrypted: i=2; AJvYcCVZAbpwTjUXluIcM+hV35NceXdKlhNkYwz/uUTfwXfyFr9lYqmrZwiHSRC1ALcpk/cz81B6UA==@lfdr.de
X-Gm-Message-State: AOJu0Yw6wn9pXWKhNpasB3tsuDFqLkeNSlMXtImc3mZphy8pzbLMyi+p
	eD6hGOBwcKSnbpVCtJPaNldHV83LK3C0riPZz20O6zGgt6bZG9064Q/t
X-Google-Smtp-Source: AGHT+IFvcYxNZ7VTjs/89KR5V8dBxbtIlnXKVs2iswY4ceH7KXQ0BZbnjDH9bPukvEzUKObNYEFdDw==
X-Received: by 2002:a05:6e02:1705:b0:3e5:4fee:75e7 with SMTP id e9e14a558f8ab-3e5674a6cb9mr35546465ab.17.1755076694984;
        Wed, 13 Aug 2025 02:18:14 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdrb+a3IjQ+Q6uzcCa5pwoFNKEHca5AWkNeB8K8oQHneQ==
Received: by 2002:a05:6e02:4409:b0:3e3:cbfe:cd96 with SMTP id
 e9e14a558f8ab-3e524b0591bls54660135ab.2.-pod-prod-04-us; Wed, 13 Aug 2025
 02:18:13 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWlbzWW2GKaWMZDELNYxVw39jdStPlc7s9r1NkjKMA7tYbjY8yD3yZelPR76b/9m+AHA+alDW76D+I=@googlegroups.com
X-Received: by 2002:a05:6e02:1fc8:b0:3e3:d8af:3847 with SMTP id e9e14a558f8ab-3e5674a6a32mr33917825ab.16.1755076693336;
        Wed, 13 Aug 2025 02:18:13 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755076693; cv=none;
        d=google.com; s=arc-20240605;
        b=MI/GicQKxxmDfUrx4ZWDHZHeziHRSwUOIi/+vv2kS6m0t/0anik5J/qYk9dJHMTnE4
         53+XrhADBr0b3oh3YSfNkHhClbkzNH4NtYUFM8zaFnAeKuXLUGaZZw6IdqgOcGajYeP1
         hIgSTgf/xFUXEPqKJt1WB6H1T6Wq09YkXnulMxrjmO2G1OAskd2ZAfP7ZvD2gFKiut8x
         vJY925tCuWNuPDmAQLfma35FWfLjV82t/SaeCEt2wO3BZkrTGSTJCxrUf2UOdIFjFSJi
         QIttymOnr1Uw1sTrfvn8vQy+Yds28gYUORxgLegI8Oo+hgcrmKDpckEpwMpll2o5H0Qi
         Arwg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=xu4miy4JsCJSvF/dA9Zp7yLsSO5S5wJhytgtNAxAJ5E=;
        fh=IzyHmp+NZO6gZhi4OxuR9H/iC64nwvDN0jQNW2Uu8PU=;
        b=jEmF5yomYnRnsjOZ7IHlUbnkcRDFD78TygQcAL1yCDeC9XHdtrwbAfETENe//SeFTj
         iGDAHGQnEhqK6mw/LeV2FjhAXd5r3p1fiy9BdBt1Hjk5yBQ7+IOD1yCfjpFMKqM5AU96
         KIgD4WYCi94CC9EI7ttRrw/17gmZ0F3k5TIcOz4YjOTSxN4kwHMeEiYw6ux8h6R+iAkb
         RZly5C3ve0CSpNt9JIn2K2M1S3N88nPPjHZRSwwQ0BD9kfl7VZLWFVgznUkSrR2iZXcp
         zY/h6HE3TBGR9+xtx5zpcxNZigyULrQOMbrSD023I++dzxUEHELKezXfMjrji9zTT29g
         eoqw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=DDmnWi9y;
       spf=pass (google.com: domain of davidgow@google.com designates 2607:f8b0:4864:20::f31 as permitted sender) smtp.mailfrom=davidgow@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-qv1-xf31.google.com (mail-qv1-xf31.google.com. [2607:f8b0:4864:20::f31])
        by gmr-mx.google.com with ESMTPS id 8926c6da1cb9f-50ae9b6cc7bsi470468173.3.2025.08.13.02.18.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 13 Aug 2025 02:18:13 -0700 (PDT)
Received-SPF: pass (google.com: domain of davidgow@google.com designates 2607:f8b0:4864:20::f31 as permitted sender) client-ip=2607:f8b0:4864:20::f31;
Received: by mail-qv1-xf31.google.com with SMTP id 6a1803df08f44-7073075c767so75888426d6.3
        for <kasan-dev@googlegroups.com>; Wed, 13 Aug 2025 02:18:13 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXZZR2ACUgiJwWgfehmOZJ7YWwRYkJXmVbRlyg++irJ7Tm056fOXbW4pMYzCHiIOy9b+A+Grp4lfc0=@googlegroups.com
X-Gm-Gg: ASbGncspgXPIVBMwHaJLOESBAvjmC3ektD1pnTn3ubher82hQm5ELLuF4F+eCoRtF3x
	ZZhaxUNHjAAkLEfSvNwDZD8K2fDx/xDZRowVbTugBEwCuv5s+iYLf4rhKjFqFkKXlUx8hnMMNTo
	W4rcvb75SH4nwNZyXnD8K4YAo0ESFY+6QApNU+pwAZXp2wNW3A1Z5+RrqHn0CgA1k4/Urigswdj
	TVWxao2
X-Received: by 2002:a05:6214:300c:b0:707:5fbf:26ce with SMTP id
 6a1803df08f44-709e891b1a9mr26541896d6.31.1755076692462; Wed, 13 Aug 2025
 02:18:12 -0700 (PDT)
MIME-Version: 1.0
References: <20250811221739.2694336-1-marievic@google.com> <20250811221739.2694336-6-marievic@google.com>
In-Reply-To: <20250811221739.2694336-6-marievic@google.com>
From: "'David Gow' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 13 Aug 2025 17:17:59 +0800
X-Gm-Features: Ac12FXyllklPPmM0S93BAFzCWiarUFJEfRESVl9pmPvzj0UDOJlCFkkkyxvdre4
Message-ID: <CABVgOSkhix4foDmVmLPDNZz8VZ1tJMGHKNeazYgJpgRdbxiVOw@mail.gmail.com>
Subject: Re: [PATCH v2 5/7] kunit: Add example parameterized test with shared
 resource management using the Resource API
To: Marie Zhussupova <marievic@google.com>
Cc: rmoar@google.com, shuah@kernel.org, brendan.higgins@linux.dev, 
	mark.rutland@arm.com, elver@google.com, dvyukov@google.com, 
	lucas.demarchi@intel.com, thomas.hellstrom@linux.intel.com, 
	rodrigo.vivi@intel.com, linux-kselftest@vger.kernel.org, 
	kunit-dev@googlegroups.com, kasan-dev@googlegroups.com, 
	intel-xe@lists.freedesktop.org, dri-devel@lists.freedesktop.org, 
	linux-kernel@vger.kernel.org
Content-Type: multipart/signed; protocol="application/pkcs7-signature"; micalg=sha-256;
	boundary="000000000000dae09b063c3ba290"
X-Original-Sender: davidgow@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=DDmnWi9y;       spf=pass
 (google.com: domain of davidgow@google.com designates 2607:f8b0:4864:20::f31
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

--000000000000dae09b063c3ba290
Content-Type: text/plain; charset="UTF-8"

On Tue, 12 Aug 2025 at 06:18, Marie Zhussupova <marievic@google.com> wrote:
>
> Add example_params_test_with_init() to illustrate how to manage
> shared resources across a parameterized KUnit test. This example
> showcases the use of the new param_init() function and its registration
> to a test using the KUNIT_CASE_PARAM_WITH_INIT() macro.
>
> Additionally, the test demonstrates how to directly pass a parameter array
> to the parameterized test context via kunit_register_params_array()
> and leveraging the Resource API for shared resource management.
>
> Signed-off-by: Marie Zhussupova <marievic@google.com>
> ---

This looks fine to me. One note below about one of the comments.

Otherwise,
Reviewed-by: David Gow <davidgow@google.com>

Cheers,
-- David

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
>
> ---
>
>  lib/kunit/kunit-example-test.c | 118 +++++++++++++++++++++++++++++++++
>  1 file changed, 118 insertions(+)
>
> diff --git a/lib/kunit/kunit-example-test.c b/lib/kunit/kunit-example-test.c
> index 3056d6bc705d..f2819ee58965 100644
> --- a/lib/kunit/kunit-example-test.c
> +++ b/lib/kunit/kunit-example-test.c
> @@ -277,6 +277,122 @@ static void example_slow_test(struct kunit *test)
>         KUNIT_EXPECT_EQ(test, 1 + 1, 2);
>  }
>
> +/*
> + * This custom function allocates memory and sets the information we want
> + * stored in the kunit_resource->data field.
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
> +       return res->data && res->free == example_resource_free;
> +}
> +
> +/*
> + * This is an example of a function that provides a description for each of the
> + * parameters in a parameterized test.
> + */
> +static void example_param_array_get_desc(struct kunit *test, const void *p, char *desc)
> +{
> +       const struct example_param *param = p;
> +
> +       snprintf(desc, KUNIT_PARAM_DESC_SIZE,
> +                "example check if %d is less than or equal to 3", param->value);
> +}
> +
> +/*
> + * This function gets passed in the parameterized test context i.e. the
> + * struct kunit belonging to the parameterized test. You can use this function
> + * to add resources you want shared across the whole parameterized test or
> + * for additional setup.
> + */
> +static int example_param_init(struct kunit *test)
> +{
> +       int ctx = 3; /* Data to be stored. */
> +       size_t arr_size = ARRAY_SIZE(example_params_array);
> +
> +       /*
> +        * This allocates a struct kunit_resource, sets its data field to
> +        * ctx, and adds it to the struct kunit's resources list. Note that
> +        * this is parameterized test managed. So, it doesn't need to have
> +        * a custom exit function to deallocation as it will get cleaned up at
> +        * the end of the parameterized test.
> +        */
> +       void *data = kunit_alloc_resource(test, example_resource_init, example_resource_free,
> +                                         GFP_KERNEL, &ctx);
> +
> +       if (!data)
> +               return -ENOMEM;
> +       /*
> +        * Pass the parameter array information to the parameterized test context
> +        * struct kunit. Note that you will need to provide kunit_array_gen_params()
> +        * as the generator function to KUNIT_CASE_PARAM_WITH_INIT() when registering
> +        * a parameter array this route.
> +        *
> +        * Alternatively, since this is a static array we can also use
> +        * KUNIT_CASE_PARAM_ARRAY(,DESC) to create  a `*_gen_params()` function
> +        * and pass that to  KUNIT_CASE_PARAM_WITH_INIT() instead of registering
> +        * the parameter array here.

Maybe we should note that KUNIT_CASE_PARAM_ARRAY{,_DESC}() doesn't let
us set an init function, so would be less useful here.


> +        */
> +       kunit_register_params_array(test, example_params_array, arr_size,
> +                                   example_param_array_get_desc);
> +       return 0;
> +}
> +
> +/*
> + * This is an example of a test that uses shared resources available in the
> + * parameterized test context.
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
> +       /*
> +        * Here we pass test->parent to search for shared resources in the
> +        * parameterized test context.
> +        */
> +       res = kunit_find_resource(test->parent, example_resource_alloc_match, NULL);
> +
> +       KUNIT_ASSERT_NOT_NULL(test, res);
> +
> +       /* Since kunit_resource->data is a void pointer we need to typecast it. */
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
> @@ -296,6 +412,8 @@ static struct kunit_case example_test_cases[] = {
>         KUNIT_CASE(example_static_stub_using_fn_ptr_test),
>         KUNIT_CASE(example_priv_test),
>         KUNIT_CASE_PARAM(example_params_test, example_gen_params),
> +       KUNIT_CASE_PARAM_WITH_INIT(example_params_test_with_init, kunit_array_gen_params,
> +                                  example_param_init, NULL),
>         KUNIT_CASE_SLOW(example_slow_test),
>         {}
>  };
> --
> 2.51.0.rc0.205.g4a044479a3-goog
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CABVgOSkhix4foDmVmLPDNZz8VZ1tJMGHKNeazYgJpgRdbxiVOw%40mail.gmail.com.

--000000000000dae09b063c3ba290
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
0TANBglghkgBZQMEAgEFAKCBxzAvBgkqhkiG9w0BCQQxIgQgGR54inI8OfkZTsmC/cV0bXyowzKf
DmidwSv/ZQGGmIkwGAYJKoZIhvcNAQkDMQsGCSqGSIb3DQEHATAcBgkqhkiG9w0BCQUxDxcNMjUw
ODEzMDkxODEzWjBcBgkqhkiG9w0BCQ8xTzBNMAsGCWCGSAFlAwQBKjALBglghkgBZQMEARYwCwYJ
YIZIAWUDBAECMAoGCCqGSIb3DQMHMAsGCSqGSIb3DQEBBzALBglghkgBZQMEAgEwDQYJKoZIhvcN
AQEBBQAEggEAgvcVduQTkpKtEkVCPbfGi15AU0gcTXiiMtuKVPEuqbigyfvwn+EkFxvsoMZ3bC1E
G3N0nVMJuFrM/SPYkYYfrNTM1Dsv6YvhNH2HRNVeF54yoUk/7Gi5VE47y/Fy6PKdlfeG/0sI29ce
odKLMNskJhumc1V98+s/SEtjiJL+nHUSeLJlerOJCxDkzOpOe8F3ij9EzPpr1MSQ/v+6mmocHRZm
+QGvLYUp4sZlwAHETt+8Klqn8il+m766ct2gtLri/zvzRGa+wam9ePKue35tm/lv5FQiEv1v3Bi3
WtC+IAZfIr73XkbzLNg0jeRj253qg1q1OZ07DkdmHxl1J9pFuQ==
--000000000000dae09b063c3ba290--
