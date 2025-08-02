Return-Path: <kasan-dev+bncBC6OLHHDVUOBBJN4W7CAMGQE3R6RUWQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3e.google.com (mail-qv1-xf3e.google.com [IPv6:2607:f8b0:4864:20::f3e])
	by mail.lfdr.de (Postfix) with ESMTPS id D2134B18D3A
	for <lists+kasan-dev@lfdr.de>; Sat,  2 Aug 2025 11:45:10 +0200 (CEST)
Received: by mail-qv1-xf3e.google.com with SMTP id 6a1803df08f44-7073b4fb53esf47284646d6.0
        for <lists+kasan-dev@lfdr.de>; Sat, 02 Aug 2025 02:45:10 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1754127909; cv=pass;
        d=google.com; s=arc-20240605;
        b=XfZJnxts6DbvjbiYqI3vrHXQtmSpIsEuggBRqVoZd/S6HxoYeQqyOWpH8LqjDn6hBg
         3WFq0OWJf9b8V5N+xRoXFRaA1OqSVyWYXZQd2uL245SJEy+0slNMFAOOncbV6V8z1aO1
         qiX7pIvDywSVcq+ZjRYzraMdR2mGyn21XPSOUXroBElVmt1iRk2l7p6ydoqODiV5b7fi
         IaNpxmZS9Qh0uML63K4QzXz1zQUZXLVlcCUv0PC42oo+dX4QNAbSNxDhuz83e0mSvtdm
         CVHOlDcny6owvfJuEan1HFofp3Tn3R8k2Vxz6dAWPAio3uMRnk87P8BxP++Be5yEhFnR
         EKsg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=NK2uTUKECTkIvdV77M/IxGgkWD840nDLCAizRrfezX4=;
        fh=t7OUC8TuOcJD7gHykjie+yPZ+bSDcJ0uDsNRlmSBNuY=;
        b=e9u42nJf/ZEFofndOkU99MX3xLIiN5z/wXhzQNXPhqT1imQt8yoaOPHEx7TabnQ1HE
         tKlHABsHQesjuSserrUnbogJmOvU38ko/hXP8wwe4Hnn95lAZGeTMbwWsaBswkxROFjU
         GGuawbJFxzd8YyYe/ih0qeJrNL4gYG6TVce/ubpz4Z1T/T3w46CuLeySea650YI44yFQ
         nByeP3j4qnbgg2PqmqkEBcGuPCOWvdYqFCth2C+t3/sSPwEd/DUrVGPlbae7FX4AMcNb
         984q4G7kgWxtFW3HrHvTE0KclnQ4WZEGDST9agp05EOo8Es2SN71mYAatXK9uVEqaitf
         A/0A==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=ybgEUyKt;
       spf=pass (google.com: domain of davidgow@google.com designates 2607:f8b0:4864:20::f33 as permitted sender) smtp.mailfrom=davidgow@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1754127909; x=1754732709; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=NK2uTUKECTkIvdV77M/IxGgkWD840nDLCAizRrfezX4=;
        b=sgCZ9e+c566ehM/VKgswTS0m7n0j6wFEDXSZg82ANp4qVWKwXIb5ZSj4rQt+VIYQGg
         FKWDjr2e6XdrNYU2nE6K3z+/KG3qYxJWFaPwj/MKH7Wz0s7P4bywCayyEQBn9i9U02Nf
         wbHOK1MNkVnQWtbh8KzWS/LWGT+tqA2t9eaBzaTl8SK/GCoiqnVeOwbNaJmyw7xCrjED
         6b+eLhj9u9M98BHaSDLuDO2JTyYBPp8zSxWNudZdQKYHkTs7TC3yUoZ5TCbeczDvjYPW
         jptKD4jMN+fWSfRjZC0QlyANfpxuvHf9pGGIE9qZkMGtcSJqA6GIRStuLnA2CmND59uf
         /ZTw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1754127909; x=1754732709;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=NK2uTUKECTkIvdV77M/IxGgkWD840nDLCAizRrfezX4=;
        b=j9vWgIJadHNqb6lbcggQ5TTd9W7xwskaCLJ27nZ08g7fON7SaFXUJZqSfz5RS1EwOr
         bYiFUnW9cKFIlP593KF7L4GRO2jtbHEQ1kJA6321hrHV8ARKEfpDjA1LvLsDn2lxILWb
         IsTcVg/cUrtWNvIsJtQ4cH1i4+W5dUHYpupgG+nM39iCTiwqgv2rPmvGzFcOBUOAOFgR
         kkxdnl6ozMzlhkWBOraKgw642NQLMv/w/DF3GNq3f03raGW0lBQYWcwmwIYXGoDE/HIL
         sCcSVGuSJyy/8Pv3qTdq5/c7ghFxF6U4jQeDLmuuWrB+L3UA6OnYThLdqSDQO86J+iPy
         7pwg==
X-Forwarded-Encrypted: i=2; AJvYcCUBjcFYCH8UlZlVh6IZZ3w3wwl7ukg3KPmkKP+vMxl6D7tmzClEbPCiTtGoaNUj2gQanX3uCQ==@lfdr.de
X-Gm-Message-State: AOJu0Yz37dq47IonkDdfcQLdGYUA9ZBKN/Ds0/Kopd7nKJ5RkGpMWlZC
	JwCoOWFWlFkIFciQ9QBTyCWCbJvbdcOPHzBNKCIL8IkUa0yc1BbYR6ZB
X-Google-Smtp-Source: AGHT+IGWbwdyz1+Z5RWb2xPKrqjqkfUFmtProoxpzarS/A4aQiOLLxTgMPM4FGxDVxsbOSapyiEJ/g==
X-Received: by 2002:a05:6214:1bcf:b0:707:4c0c:5316 with SMTP id 6a1803df08f44-709363656bcmr35094286d6.46.1754127909562;
        Sat, 02 Aug 2025 02:45:09 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZd7AyXnHcshc4T49SjHXT/RdMZysZC+836lYDDxQcBLgQ==
Received: by 2002:a05:6214:b68:b0:6fa:fb65:95dc with SMTP id
 6a1803df08f44-70778d6c838ls57429376d6.1.-pod-prod-01-us; Sat, 02 Aug 2025
 02:45:08 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCX/sms5Yt/pYVy68t4P7r9jytCzX4Fje03ERQ3R3xfWiCFdbUv5uYg6TRyzV7w2ZIUxLHLTC9FZOR4=@googlegroups.com
X-Received: by 2002:a05:6122:3192:b0:539:1dbf:3148 with SMTP id 71dfb90a1353d-5395f1f84aemr1345023e0c.2.1754127908738;
        Sat, 02 Aug 2025 02:45:08 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1754127908; cv=none;
        d=google.com; s=arc-20240605;
        b=ZuzOPQOFYzp+EJ/w/llpFglcm6cxqSyIbtd0yuamvckDETXNKg3hKKlrCcCDcYjO3e
         camqLqBRp5tTZNo09KIW86dsp5Z95KoSVYGqjuSmyQrryby3Xt08ZdZ2kWXwR+0dnLNv
         YbqrbiYp/ddfhxVRXCjtVBZd3W7tRa1YqUpUAb+2tFsAXEvuAU4gEmDsodmln7OKas9V
         ZRLyzT5kJhpZ+YVDl6vh8zUNMpR4JrlhiBeeYaZ0sojxV+ADOQo+efoXg4pNG3S7GIs/
         SLAXinZO1TuJj+XzD5C7Hv1HPFeWcyKMDRQ6k5d7vVak3ZZ+aLrmDFKu5+uNgXOYjpqq
         wyfQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=+RKUQvBT0MdX4TV2KRAFwTnOnf14W6j0n14VfAeUDyU=;
        fh=TuJB/oJ7Yk6dwgK/jBV6KxcgKGtBhl+df5IGC9IbQpU=;
        b=QVkR2Zpn6N865njIdVtJ7f6YRVTbplX1HdfVjhrYjdalIYNY7zxIzblezyZBEu+s4/
         v5NCk/9/nQkDY9lo5h1+6aFBLYMYgdS9bEh11hVzHry7ZRTiRkrBCzjf6MDN9y7LcOks
         B9jFQudQVj+FXDEP7CnZENp5GlgYiave07Fg3hf8j+na57XmJi9l2dpoozJ35xqbsEHD
         m15mkhbPC0qugdcKimEoi4J2pOaFUJNMEtxGpojuDW7nu2c/A+xYiKu9OFchTG+s3cxz
         bZh9I68kO6/pJU7Ik78ml4Zjnuz9OZEcRfHWNrcLEZln5d76u0scxFLSoaSHW6jUyuCw
         04pA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=ybgEUyKt;
       spf=pass (google.com: domain of davidgow@google.com designates 2607:f8b0:4864:20::f33 as permitted sender) smtp.mailfrom=davidgow@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-qv1-xf33.google.com (mail-qv1-xf33.google.com. [2607:f8b0:4864:20::f33])
        by gmr-mx.google.com with ESMTPS id 71dfb90a1353d-53936d1baf1si281786e0c.5.2025.08.02.02.45.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 02 Aug 2025 02:45:08 -0700 (PDT)
Received-SPF: pass (google.com: domain of davidgow@google.com designates 2607:f8b0:4864:20::f33 as permitted sender) client-ip=2607:f8b0:4864:20::f33;
Received: by mail-qv1-xf33.google.com with SMTP id 6a1803df08f44-7077a1563b5so25818996d6.1
        for <kasan-dev@googlegroups.com>; Sat, 02 Aug 2025 02:45:08 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXzSFpWyG/OXmnrrzxrknlZdCpmkQ8z5/5yDTie2PC0ddLrEm3pGkIz2TOpIWHDfXZEKdfHRd32kB0=@googlegroups.com
X-Gm-Gg: ASbGncttXA5nVgP7nwUyHum1MGyEZkHG1E4E68yJKmyaV0pVfkul4aFu3pBZMKYHvOE
	vfjZIcLXo/dJBFqjGaRjIasBAbUxi6MRN705YSDd/Z4FocTyUrf2u8yctYWwvxvrYXebFRIkWfo
	NNcUgChw4XoKWN4uEHmqxvqoYEfiFFnfl0cDQYkLCu/rxwbHvtb2ghRqUaeE4V74uCbQC+G80KG
	Us5zYUZ7iJ5vqJttOE=
X-Received: by 2002:ad4:5b8d:0:b0:705:16d9:16d8 with SMTP id
 6a1803df08f44-70935f1e455mr35480696d6.6.1754127908008; Sat, 02 Aug 2025
 02:45:08 -0700 (PDT)
MIME-Version: 1.0
References: <20250729193647.3410634-1-marievic@google.com> <20250729193647.3410634-9-marievic@google.com>
In-Reply-To: <20250729193647.3410634-9-marievic@google.com>
From: "'David Gow' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Sat, 2 Aug 2025 17:44:55 +0800
X-Gm-Features: Ac12FXzOwppAi0snI7hkP1q9dsV5OcoOySmzNg8J2MRX0xe4fiZt-HGytCbaqbg
Message-ID: <CABVgOS=vsaUjZg1S9VApDFZjHN5d08NswtDNWWsJxUEvg0xGSw@mail.gmail.com>
Subject: Re: [PATCH 8/9] kunit: Add example parameterized test with direct
 dynamic parameter array setup
To: Marie Zhussupova <marievic@google.com>
Cc: rmoar@google.com, shuah@kernel.org, brendan.higgins@linux.dev, 
	elver@google.com, dvyukov@google.com, lucas.demarchi@intel.com, 
	thomas.hellstrom@linux.intel.com, rodrigo.vivi@intel.com, 
	linux-kselftest@vger.kernel.org, kunit-dev@googlegroups.com, 
	kasan-dev@googlegroups.com, intel-xe@lists.freedesktop.org, 
	dri-devel@lists.freedesktop.org, linux-kernel@vger.kernel.org
Content-Type: multipart/signed; protocol="application/pkcs7-signature"; micalg=sha-256;
	boundary="000000000000e27f73063b5ebad6"
X-Original-Sender: davidgow@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=ybgEUyKt;       spf=pass
 (google.com: domain of davidgow@google.com designates 2607:f8b0:4864:20::f33
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

--000000000000e27f73063b5ebad6
Content-Type: text/plain; charset="UTF-8"

On Wed, 30 Jul 2025 at 03:37, Marie Zhussupova <marievic@google.com> wrote:
>
> Introduce `example_params_test_with_init_dynamic_arr`. This new
> KUnit test demonstrates directly assigning a dynamic parameter
> array using the `kunit_register_params_array` macro. It highlights the
> use of `param_init` and `param_exit` for proper initialization and
> cleanup, and their registration to the test with
> `KUNIT_CASE_PARAM_WITH_INIT`.
>
> Signed-off-by: Marie Zhussupova <marievic@google.com>
> ---

This is an excellent example, thanks. (I much prefer it to the
previous one. In fact, if we could use some shared resource in this,
we could probably get rid of the previous one entirely.)

Reviewed-by: David Gow <davidgow@google.com>

Cheers,
-- David

>  lib/kunit/kunit-example-test.c | 95 ++++++++++++++++++++++++++++++++++
>  1 file changed, 95 insertions(+)
>
> diff --git a/lib/kunit/kunit-example-test.c b/lib/kunit/kunit-example-test.c
> index 5bf559e243f6..3ab121d81bf6 100644
> --- a/lib/kunit/kunit-example-test.c
> +++ b/lib/kunit/kunit-example-test.c
> @@ -387,6 +387,98 @@ static void example_params_test_with_init(struct kunit *test)
>         kunit_put_resource(res);
>  }
>
> +/*
> + * Helper function to create a parameter array of Fibonacci numbers. This example
> + * highlights a parameter generation scenario that is:
> + * 1. Not feasible to fully pre-generate at compile time.
> + * 2. Challenging to implement with a standard 'generate_params' function,
> + * as it typically only provides the immediately 'prev' parameter, while
> + * Fibonacci requires access to two preceding values for calculation.
> + */
> +static void *make_fibonacci_params(int seq_size)
> +{
> +       int *seq;
> +
> +       if (seq_size <= 0)
> +               return NULL;
> +
> +       seq = kmalloc_array(seq_size, sizeof(int), GFP_KERNEL);

If we used kunit_kmalloc_array here (we'd need to pass test through
somehow, though), we could have a good example of a shared resource
here.

> +
> +       if (!seq)
> +               return NULL;
> +
> +       if (seq_size >= 1)
> +               seq[0] = 0;
> +       if (seq_size >= 2)
> +               seq[1] = 1;
> +       for (int i = 2; i < seq_size; i++)
> +               seq[i] = seq[i - 1] + seq[i - 2];
> +       return seq;
> +}
> +
> +/*
> + * This is an example of a function that provides a description for each of the
> + * parameters.
> + */
> +static void example_param_dynamic_arr_get_desc(const void *p, char *desc)

Seeing this makes me wonder whether we should pass struct *kunit to
the get_desc function, too.

Thoughts?

> +{
> +       const int *fib_num = p;
> +
> +       snprintf(desc, KUNIT_PARAM_DESC_SIZE, "fibonacci param: %d", *fib_num);
> +}
> +
> +/*
> + * Example of a parameterized test init function that registers a dynamic array.
> + */
> +static int example_param_init_dynamic_arr(struct kunit *test)
> +{
> +       int seq_size = 6;
> +       int *fibonacci_params = make_fibonacci_params(seq_size);
> +
> +       if (!fibonacci_params)
> +               return -ENOMEM;
> +
> +       /*
> +        * Passes the dynamic parameter array information to the parent struct kunit.
> +        * The array and its metadata will be stored in test->parent->params_data.
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
> +        * we can directly access the array via `test->params_data.params`
> +        * instead of `test->parent->params_data.params`.
> +        */
> +       kfree(test->params_data.params);

If we used kunit_kmalloc_array above, though, we'd miss this good
example. So I'm torn...

(I suppose we could use kunit_kfree() anyway, though, and just rely on
the shared resource management for early aborts.)


> +}
> +
> +/*
> + * Example of test that uses the registered dynamic array to perform assertions
> + * and expectations.
> + */
> +static void example_params_test_with_init_dynamic_arr(struct kunit *test)
> +{
> +       const int *param = test->param_value;
> +       int param_val;
> +
> +       /* By design, param pointer will not be NULL. */
> +       KUNIT_ASSERT_NOT_NULL(test, param);
> +
> +       param_val = *param;
> +       KUNIT_EXPECT_EQ(test, param_val - param_val, 0);
> +}
> +
>  /*
>   * Here we make a list of all the test cases we want to add to the test suite
>   * below.
> @@ -408,6 +500,9 @@ static struct kunit_case example_test_cases[] = {
>         KUNIT_CASE_PARAM(example_params_test, example_gen_params),
>         KUNIT_CASE_PARAM_WITH_INIT(example_params_test_with_init, NULL,
>                                    example_param_init, NULL),
> +       KUNIT_CASE_PARAM_WITH_INIT(example_params_test_with_init_dynamic_arr, NULL,
> +                                  example_param_init_dynamic_arr,
> +                                  example_param_exit_dynamic_arr),
>         KUNIT_CASE_SLOW(example_slow_test),
>         {}
>  };
> --
> 2.50.1.552.g942d659e1b-goog
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CABVgOS%3DvsaUjZg1S9VApDFZjHN5d08NswtDNWWsJxUEvg0xGSw%40mail.gmail.com.

--000000000000e27f73063b5ebad6
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
0TANBglghkgBZQMEAgEFAKCBxzAvBgkqhkiG9w0BCQQxIgQga7ci06bb/Pbf8Mpg/ftfpDjGUGYZ
P1279vLvANcTv6cwGAYJKoZIhvcNAQkDMQsGCSqGSIb3DQEHATAcBgkqhkiG9w0BCQUxDxcNMjUw
ODAyMDk0NTA4WjBcBgkqhkiG9w0BCQ8xTzBNMAsGCWCGSAFlAwQBKjALBglghkgBZQMEARYwCwYJ
YIZIAWUDBAECMAoGCCqGSIb3DQMHMAsGCSqGSIb3DQEBBzALBglghkgBZQMEAgEwDQYJKoZIhvcN
AQEBBQAEggEACq8CU7VfBlYl7GKtpo9rt9Y0RW6d+fvAsoyaPHwLqE4iqWlef6oM8by8txRN8Joj
0L2qQB5s8qieLUZzr/AsSiKmCtGqU8T302nXG7eu2AUYSkwVb6m/3u+QKhJs+JUTuOo/tAS5lBFX
Y7GC/8+hOtkOQBZ7MQyEEHf+shz6WUcoCPemE7YMw2y6/Q2Gbfx2RaHADelQOS02SrG8xr00dEWL
W71utvNWpGIPbffVxb/XPMZXVFj8i2fOYcaPXFngPibLorjRMrkdSnKFferhlFkgbAX9b/a4nfsP
uMaXRWmhSwGTY/AnCpDHyMAHo9T6i/v95CfFXG53gV4cxfERWg==
--000000000000e27f73063b5ebad6--
