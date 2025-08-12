Return-Path: <kasan-dev+bncBDPPVSUFVUPBB7P553CAMGQEKJL74MI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103d.google.com (mail-pj1-x103d.google.com [IPv6:2607:f8b0:4864:20::103d])
	by mail.lfdr.de (Postfix) with ESMTPS id 15002B23BD2
	for <lists+kasan-dev@lfdr.de>; Wed, 13 Aug 2025 00:24:00 +0200 (CEST)
Received: by mail-pj1-x103d.google.com with SMTP id 98e67ed59e1d1-31eac278794sf5638095a91.3
        for <lists+kasan-dev@lfdr.de>; Tue, 12 Aug 2025 15:24:00 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755037438; cv=pass;
        d=google.com; s=arc-20240605;
        b=fAXiOM3tPaWmJSPxqWZ/nHuDYuIveVBibNOWWiKIyqq8EFs9ziGBNtu0+xd0Y3izTE
         fuMcrVBfyGwOpA3wI/b8LOdLWVc3LuLNc7bdiDvPt8sEd9YgUyGkenQAxE+pzSCyqVZ9
         3ggitbDhyorzArPxafYtrL+GiXTZYviV97EZ+5C2t1yLOhUq2taN8wX8Q1uIRhT109Zq
         6t+RgORACRUI/XmxJV73SFbCOz3mxBYL0DqJInoGUh8g/tnUIfAqCI8leX4eBjAqaXhm
         xQ2HMNUUgwcIisEWA6hFjXRAHgGpsGXLMIYH/wBAvgbpZEj0Vgcd4b5ZgiAkl4cMAea1
         FO5Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=yp2J+sEj2XhWFy9kgPllmcmdlA20NJv3rZuFnmHhdIw=;
        fh=6I66QoCrZLZoQbNNi8KlrIVbFmUomirBwjngBGRv8/0=;
        b=GLACKRFLo4OEl/edgd0LxH6BpBpkzvW11whySx5psDnb+Q3jHk6JoiYT1n5HjGCiIZ
         YsWnHGxb8hBZkyDeR1RaVdMNBt+3nW5g2CctN0syptEpUEK311ezRsPV9ufXW9wfIoML
         hmwpNYS5gxUIh6ccDxkAiGeCjn6CeWgm0vD9VVtnGoxp1IDVb+CwOFXVAJJQLmBybkVn
         YNU0zRa08jQiBy3sCXdRQMl4LO4etWuyiE/T8K0Aa0A3HnWywcy8s70bN4M1/aZo0fTq
         Nr2mm1gcYCb3cLYreA29oy+/VJuO65lprjQO6lIcCoct7l+EUKbueKJJhdvdY8nUf9pl
         pEVg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=G8vgCTQu;
       spf=pass (google.com: domain of rmoar@google.com designates 2607:f8b0:4864:20::f30 as permitted sender) smtp.mailfrom=rmoar@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755037438; x=1755642238; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=yp2J+sEj2XhWFy9kgPllmcmdlA20NJv3rZuFnmHhdIw=;
        b=hh8AGvzjBEhJV4Rfq6JhzvaqZgWfdU+RiXwxC6Da8tk1eoS1e8qTdVQQl+zmcfjo4/
         rRm44lZ3ZFTl8GbKiOobDtQI4LlkZ/ky7nOea4GbWtcu0nG4EGNclBwt9c6y7hGloGq9
         Kbtehq30tytbj+QopRow/jfG5MYsbI1STTsaP2aJMnteLx6EK3hgoCIfML3jvZ58xvKY
         VI4gw37b2G3xl0lIeW+NbVDnSVWs6eeQF3axTuq56e6CCjFMGGevl2bO5ldLJqzuJbZS
         dWeXYpMzQW2mX7Q61kc+TDWXn9TbJ89Uj+wo6shKFPU4cq5Bv8ojGuGMKhBJxbmAlxT2
         8ltA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755037438; x=1755642238;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=yp2J+sEj2XhWFy9kgPllmcmdlA20NJv3rZuFnmHhdIw=;
        b=n4//f3879+MxNqufcxmxZ75zntAuZ2+hNy3wUL4i0IQI9uOrwEACoV3Tp00e9x61MI
         OB7sk4VwZUfUk8lUACvwLF83lcXXH3TQib9vTLvi+oHw8geHLUQDIwQREtY7e7Yi5JD2
         0tW1jfoxSyEOKipZk3oz0ZhwYyBvjbLtMDCj3CNJ5T7c2YgVPnSM2CInguwaHzC7uUTY
         CEIDq/+HhJp8kzdTQKq7HxwBLZey43YAYK98ZuDI/vCnWTdcEvrpyU46ER59qEubeAm4
         OdhoojDzRptzh4DZsiuS/7KGRhymAMymrYFMX8V5QPWexwn7LsK0dqqiqOK+NfMaDKnu
         J7gw==
X-Forwarded-Encrypted: i=2; AJvYcCXSe3yyLEZsQ89mobVZhxj+rH7sb3exQtvNY4Z6nPo7raP02w2WZ1kTLyBP3wrtpA66mVwzCQ==@lfdr.de
X-Gm-Message-State: AOJu0YyEDjN/CO3jsYiqi9kxoAHEgpzBeqvD1IjdmbY0wh02yhfnOXMQ
	s3Wh6FrRRlfM6t6+GOfaON4YW6YIfuVhw1Gda0jqi504dBs1grMVfbhQ
X-Google-Smtp-Source: AGHT+IG4rvNzlzeUAMkfndGhDbEpP7jFaK0fGtwTNR9jN2lBZffYx1+sggOhdO0gCwxq+401mXBpLA==
X-Received: by 2002:a17:90b:2e04:b0:321:265a:e0c2 with SMTP id 98e67ed59e1d1-321d0ecb6b5mr723779a91.32.1755037438061;
        Tue, 12 Aug 2025 15:23:58 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdnPLUjaKPVj0uw8+OX7Aw/KAD05JC7dNBCFKIrqaCkqA==
Received: by 2002:a17:90b:1d11:b0:31e:f3b4:707e with SMTP id
 98e67ed59e1d1-32174f86489ls5865278a91.0.-pod-prod-02-us; Tue, 12 Aug 2025
 15:23:56 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXqJ/RAGZb7azyHthYINOWoTFAG6SjiwxCYXkDXJc7jNpV7oL0OPRwCa79UyTjt0jjFgwhZpzwHPFY=@googlegroups.com
X-Received: by 2002:a05:6300:218f:b0:22b:8f7f:5cb2 with SMTP id adf61e73a8af0-240a8a8b5f3mr1389108637.8.1755037436597;
        Tue, 12 Aug 2025 15:23:56 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755037436; cv=none;
        d=google.com; s=arc-20240605;
        b=K/tRQG83JE7KRkHGSxL7JV6z2Iyp8cczOp2Vlfw4qCX+t9EyrsLZeEEcpqfzeSIeR+
         dKmNcwK6zKCuEp3sFBSnGFW4jO+faKCWB7qznzOrZD12w8mx4x3XkZteyKBLbo6mOANk
         DszCrJBdYy+eVRq6WoIGacLJ/pvK+iHEO33MK4dgYEX4g4NJq1Icfy+urcglcVuLbwWM
         LRALrPtkEWinvvNOzHuPks+p81v+LBGFPJm09Dsn9z+x34TIpq3W60riy2SWoE1zaLlN
         7uYe9FaBQ66CTWfDVGfumMpTVBOUtJn9XRkiRrmrAh96t6xXu4AShJDWfzvyfaAv0+Mb
         j4oA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=rJnpYXsl8YxSyj1wYhStEbnRqv/Bs6CSw0kV2AlWC5o=;
        fh=a0cm9Zj/fi2F+d2TqRxuUMJjsxG38drWAJTQ+/IqHA0=;
        b=D9MFkctg618vz6wC+hTLpMCuuHbeh9JoS0b9w5r0+RHgsLAYwpY6QeeuTcG/MofRUo
         KxwSfD3Egy9K0JTJOfJQKh7ICMKFM35lMMtuP0KRbh5HvhrCNEHTdPMbut2Z2FUKcjD0
         72tUikxg7P9io1xGF3hY3OmRMiGHLQp46ZIUqGtt2R2QcaysbOBq9pmK364cR4xQTVrF
         yOUZZbzK7EOlFnT2ipoNazFdR6fZUEi2qnEnnF677+f9EWXt5EJ05RGx6TavSrASttUB
         zKi9V89IDyi5D0z+QrTPi1PQg2kQ9mTX9/dl4Ras4h2Nploq1B15YXXhc/QaZvgxYikm
         Og9Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=G8vgCTQu;
       spf=pass (google.com: domain of rmoar@google.com designates 2607:f8b0:4864:20::f30 as permitted sender) smtp.mailfrom=rmoar@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-qv1-xf30.google.com (mail-qv1-xf30.google.com. [2607:f8b0:4864:20::f30])
        by gmr-mx.google.com with ESMTPS id 41be03b00d2f7-b422b8a91c5si1227564a12.4.2025.08.12.15.23.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 12 Aug 2025 15:23:56 -0700 (PDT)
Received-SPF: pass (google.com: domain of rmoar@google.com designates 2607:f8b0:4864:20::f30 as permitted sender) client-ip=2607:f8b0:4864:20::f30;
Received: by mail-qv1-xf30.google.com with SMTP id 6a1803df08f44-7074a74248dso53837756d6.3
        for <kasan-dev@googlegroups.com>; Tue, 12 Aug 2025 15:23:56 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXLi8KhC+Nf9zAkXKbsPr8qdy49e4pmYJLQOFkVNuPqIoKWTkNgkh5Bi8E9fs++65Uj8Pj+P0EnaQo=@googlegroups.com
X-Gm-Gg: ASbGncvd5dlvKfxQAF0vP66DkPyPPkXxMkGfwI1h2LFuREW0Pl1q2579vJTSnK5lM/t
	XsB8fwPlOOif+rQ6PFdmTH3SD1WaNY30fPjP/ZWlzNBVWGYqih2e0lnoDpTDQla2T6EdlnhyvCM
	JHcY9jC/GJu+10yUJi8/UNGeIDNh9eyzFjpSILmjWbq6qi5eCncF5mSpqS1eN53DOn6p975LM2p
	oJNraw7B7Nm4yMx
X-Received: by 2002:ad4:5fc7:0:b0:707:616f:fff4 with SMTP id
 6a1803df08f44-709e87ed0c5mr12374106d6.10.1755037435662; Tue, 12 Aug 2025
 15:23:55 -0700 (PDT)
MIME-Version: 1.0
References: <20250811221739.2694336-1-marievic@google.com> <20250811221739.2694336-7-marievic@google.com>
In-Reply-To: <20250811221739.2694336-7-marievic@google.com>
From: "'Rae Moar' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 12 Aug 2025 18:23:44 -0400
X-Gm-Features: Ac12FXxKNs5XUmU5widgmneS2GgZSAhi_XzG1wZdZRmg99Z9O_yPFEdmMws-MoU
Message-ID: <CA+GJov5uwE43RQwP96i617=dtZ0VAfVtrLu_DV863nhA2+4DmQ@mail.gmail.com>
Subject: Re: [PATCH v2 6/7] kunit: Add example parameterized test with direct
 dynamic parameter array setup
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
 header.i=@google.com header.s=20230601 header.b=G8vgCTQu;       spf=pass
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

On Mon, Aug 11, 2025 at 6:18=E2=80=AFPM Marie Zhussupova <marievic@google.c=
om> wrote:
>
> Introduce example_params_test_with_init_dynamic_arr(). This new
> KUnit test demonstrates directly assigning a dynamic parameter
> array, using the kunit_register_params_array() macro, to a
> parameterized test context.
>
> It highlights the use of param_init() and param_exit() for
> initialization and exit of a parameterized test, and their
> registration to the test case with KUNIT_CASE_PARAM_WITH_INIT().
>
> Signed-off-by: Marie Zhussupova <marievic@google.com>
> ---
>
> Changes in v2:
>
> - kunit_array_gen_params() is now explicitly passed to
>   KUNIT_CASE_PARAM_WITH_INIT() to be consistent with
>   the parameterized test being defined by the existence
>   of the generate_params() function.
> - param_init() was changed to output a log at the start
>   of a parameterized test.
> - The parameter array was changed to be allocated
>   using kunit_kmalloc_array(), a KUnit memory allocation
>   API, as that would be the preferred/easier method. To
>   still demonstrate a use of param_exit(), it now outputs
>   a log at the end of the parameterized test.
> - The comments and the commit message were changed to
>   reflect the parameterized testing terminology. See
>   the patch series cover letter change log for the
>   definitions.
>

Hi!

I am happy with these changes and I really like this test!

Happy to mark this as:
Reviewed-by: Rae Moar <rmoar@google.com>

Thanks!

-Rae

> ---
>  lib/kunit/kunit-example-test.c | 104 +++++++++++++++++++++++++++++++++
>  1 file changed, 104 insertions(+)
>
> diff --git a/lib/kunit/kunit-example-test.c b/lib/kunit/kunit-example-tes=
t.c
> index f2819ee58965..ff21511889a4 100644
> --- a/lib/kunit/kunit-example-test.c
> +++ b/lib/kunit/kunit-example-test.c
> @@ -393,6 +393,107 @@ static void example_params_test_with_init(struct ku=
nit *test)
>         kunit_put_resource(res);
>  }
>
> +/*
> + * Helper function to create a parameter array of Fibonacci numbers. Thi=
s example
> + * highlights a parameter generation scenario that is:
> + * 1. Not feasible to fully pre-generate at compile time.
> + * 2. Challenging to implement with a standard generate_params() functio=
n,
> + * as it only provides the previous parameter, while Fibonacci requires
> + * access to two preceding values for calculation.
> + */
> +static void *make_fibonacci_params(struct kunit *test, size_t seq_size)
> +{
> +       int *seq;
> +
> +       if (seq_size <=3D 0)
> +               return NULL;
> +       /*
> +        * Using kunit_kmalloc_array here ties the lifetime of the array =
to
> +        * the parameterized test i.e. it will get automatically cleaned =
up
> +        * by KUnit after the parameterized test finishes.
> +        */
> +       seq =3D kunit_kmalloc_array(test, seq_size, sizeof(int), GFP_KERN=
EL);
> +
> +       if (!seq)
> +               return NULL;
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
> +static void example_param_dynamic_arr_get_desc(struct kunit *test, const=
 void *p, char *desc)
> +{
> +       const int *fib_num =3D p;
> +
> +       snprintf(desc, KUNIT_PARAM_DESC_SIZE, "fibonacci param: %d", *fib=
_num);
> +}
> +
> +/*
> + * Example of a parameterized test param_init() function that registers =
a dynamic
> + * array of parameters.
> + */
> +static int example_param_init_dynamic_arr(struct kunit *test)
> +{
> +       size_t seq_size;
> +       int *fibonacci_params;
> +
> +       kunit_info(test, "initializing parameterized test\n");
> +
> +       seq_size =3D 6;
> +       fibonacci_params =3D make_fibonacci_params(test, seq_size);
> +
> +       if (!fibonacci_params)
> +               return -ENOMEM;
> +
> +       /*
> +        * Passes the dynamic parameter array information to the paramete=
rized test
> +        * context struct kunit. The array and its metadata will be store=
d in
> +        * test->parent->params_array. The array itself will be located i=
n
> +        * params_data.params.
> +        *
> +        * Note that you will need to pass kunit_array_gen_params() as th=
e
> +        * generator function to KUNIT_CASE_PARAM_WITH_INIT() when regist=
ering
> +        * a parameter array this route.
> +        */
> +       kunit_register_params_array(test, fibonacci_params, seq_size,
> +                                   example_param_dynamic_arr_get_desc);
> +       return 0;
> +}
> +
> +/*
> + * Example of a parameterized test param_exit() function that outputs a =
log
> + * at the end of the parameterized test. It could also be used for any o=
ther
> + * teardown logic.
> + */
> +static void example_param_exit_dynamic_arr(struct kunit *test)
> +{
> +       kunit_info(test, "exiting parameterized test\n");
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
> @@ -414,6 +515,9 @@ static struct kunit_case example_test_cases[] =3D {
>         KUNIT_CASE_PARAM(example_params_test, example_gen_params),
>         KUNIT_CASE_PARAM_WITH_INIT(example_params_test_with_init, kunit_a=
rray_gen_params,
>                                    example_param_init, NULL),
> +       KUNIT_CASE_PARAM_WITH_INIT(example_params_test_with_init_dynamic_=
arr,
> +                                  kunit_array_gen_params, example_param_=
init_dynamic_arr,
> +                                  example_param_exit_dynamic_arr),
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
A%2BGJov5uwE43RQwP96i617%3DdtZ0VAfVtrLu_DV863nhA2%2B4DmQ%40mail.gmail.com.
