Return-Path: <kasan-dev+bncBC6OLHHDVUOBBGV4W7CAMGQEMFMAIGY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23e.google.com (mail-oi1-x23e.google.com [IPv6:2607:f8b0:4864:20::23e])
	by mail.lfdr.de (Postfix) with ESMTPS id EF79CB18D2E
	for <lists+kasan-dev@lfdr.de>; Sat,  2 Aug 2025 11:44:59 +0200 (CEST)
Received: by mail-oi1-x23e.google.com with SMTP id 5614622812f47-41c66de9ac8sf971756b6e.0
        for <lists+kasan-dev@lfdr.de>; Sat, 02 Aug 2025 02:44:59 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1754127898; cv=pass;
        d=google.com; s=arc-20240605;
        b=jbxENwcvAsJJrX5Y/rT0IlWt1OIoqcwlVa+7WlcqZSOsoPVCeK7hu1/qB3pLjwLjnr
         +yIwKD9J58R/WoWxXkh1DlGtqVJpWLkLemxqKzl8PYrbaVh7REGmNl0Xl1pQ+GIa2vZ7
         2biieHZGGQQMwAfiQiSJ4sKuIvqYmJtqbWsJbv6hzkatf7N4/vxn8JHGBOBLZ2SWzjw3
         cFwytT5AfWSSRGTgRTyBooPr39VNFkTadBtvvmtegkgAXOl6imsgKx8DH8mIcegUPVqC
         cW8GyVDOWR/DZCOllHqHGUc6r/gzUVMim3sB8I8Qcsu0yQI5J/EAeSinOTBLK+yTev7S
         9uNA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=oB2Mn7Br3csAx/o3xSiqooqaTbCuQ9CQGssq6CQJxcY=;
        fh=01TmURKIn3b3r3NIMM7ADoVEHohaRuPTQL5DMCWq9O8=;
        b=XhoIb70rMF7VibIVpgvsTlZ85vVq7ea9BbZCNz9rcn1kZ0SzJmf9eoWqT9xzXhPnC4
         7GsDC1H9QNQsOzKPpnDtqsxrNdrhBvwtswXirT/ADC94AHTXDf8LD3AtAAgsIvxBbx+a
         bayAVL36Z/yzkj8IAc2XDcwgu4wqgaPJfdTK5pWL33NwEXjOZHIenNtzQODYS/qxFp1b
         /dHtAkeOjdbTsuYw2jUond6KYiL7FruU2QB3ADf7/3DSj67SxfItvNmDfc265ViaVNGg
         FC9+TsWferR1UHqH4JamR3wBiRS4g0wEryHCQVU4D/ArcNQ5cqikc1iDMr+Q7ImyM4Jn
         y9tg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=AVFavAVc;
       spf=pass (google.com: domain of davidgow@google.com designates 2607:f8b0:4864:20::f29 as permitted sender) smtp.mailfrom=davidgow@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1754127898; x=1754732698; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=oB2Mn7Br3csAx/o3xSiqooqaTbCuQ9CQGssq6CQJxcY=;
        b=MewWqjo27tSzwrzCguvYFkdWV9IcP28DxIKysU5lLh1/tncNNOLo8Oakj9MwC0dcMZ
         rA1HRBp8ZJ77JOXNg5TwWdwfhyYlk38rShzOlzR8kLchNUoZcsubYoBaFgvIFBvq+UUT
         qijguP6ayXTttHYo1EhzucO7MhYOAR3/Y7wXTt+1QSgrSXMVaXJLSoKAs8dzc8oPj9jg
         ngnMYAYuxtnv+VhiuxmPoV+JndvnWt7ny6kkCpnoFZ8nlPLRbV02ppcnzpkDuw8U8Gwb
         DkTdpTWe6w6IHiYS3+V/RubhiAA4pl6+xHsmQLMbbAgHMlxjkWoIx1X1gCU9MC7OnbNg
         hiVg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1754127898; x=1754732698;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=oB2Mn7Br3csAx/o3xSiqooqaTbCuQ9CQGssq6CQJxcY=;
        b=dA6Tix9pYDdDy0aXfj7ojsFI9yk3i1J8llTAvdXUP1kYTtfq7g1tRog1yglYTz53+8
         ZYwjLatI6oJ3TeMtDq7FyIlO0og7Ujlew+jqV5LZ9I2pzXhaq+RlkmF83LX+rBgoLWe5
         oaGSJ5X0sXzaJilEKPseOKkgE4a9GzFy2HW/Gv8ryvvOHTKFSsioQMqFUjM3mmDPpQzY
         2j9N8Zpr5/s/pzj8dHrSSExL0XD7GN/R4eni+JBh81MB/98KJS27ZlVdOF6sWaCoXJqN
         oS2EhIzad+0NHfQWgOBGpCEERdZ6bnMzoYGRMgUlsLehDEWVxamfaQrxiWTTb3pjOkic
         9vTQ==
X-Forwarded-Encrypted: i=2; AJvYcCVRXpJqvlsgKwQaK0DPusjUaC7w3c6/+heWXlt2ljUzXUWYDF9gXfKLjSqtXShIfrm7UUhpiA==@lfdr.de
X-Gm-Message-State: AOJu0YzWe7oGRmqhjHJuaeDkYoJyoXn99dmgjhmNhNUu+xwqEZTO5RMY
	OJDUMniEUns9vbHHRZ7orR1VuLpyLJAk8a1i0uaRroXv1vTIc1wXBn1A
X-Google-Smtp-Source: AGHT+IE7kotb0Be1bcXAD48mIE6jQyj38X8DzkVqIUl2xe4D+W7oVabwJV6xmfV1AdDD5s0CjiMaNQ==
X-Received: by 2002:a05:6808:3319:b0:406:5a47:a081 with SMTP id 5614622812f47-433f02391a4mr1934993b6e.13.1754127898280;
        Sat, 02 Aug 2025 02:44:58 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZeYdsgeVAa9M8skIOy3eiKPYsgStuZYSSITtiZESJ2H1g==
Received: by 2002:a05:6820:1511:b0:611:9e19:22fd with SMTP id
 006d021491bc7-6196f89c520ls531624eaf.2.-pod-prod-06-us; Sat, 02 Aug 2025
 02:44:57 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCX7smrsa3b+0GqMzODq/CgjeNCRTbnxlxE+fVSDbE3SwlWgJRo+g20L0HbsuB/NeTR3nJDHCIpXOZM=@googlegroups.com
X-Received: by 2002:a05:6830:920:b0:73e:93a2:3ab1 with SMTP id 46e09a7af769-7419d285b06mr1533095a34.18.1754127897282;
        Sat, 02 Aug 2025 02:44:57 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1754127897; cv=none;
        d=google.com; s=arc-20240605;
        b=L/2fUmOhGMETCQB2XSDP5i+sdzIvdmVSEHSrC7cHLhFXOnB0pAupzflEq8pVIbJaTT
         E+5yBGTjgHiDGPQT3MSFDCu4ml0LrfayI2vXYodH2+nI59/CzDzm2EC+VfwMQ972dBgk
         bfWM63DpIrqET/mTyjgvgKLEk4LmT9LjCHr4vMr0P3Bbcw4RpxakSe2Lf3WxioRS+xY+
         XsSyLeF6o4NbwT3hYI+f9bM65DZQhCaftMv6ZHfcLqLoiMx+553qP3CSDvjJXIWKa/ec
         t2nc/CiFkW/QkyF9gJJb+IwCmyxTFQzc1bn3Vr1J1b8KpIahQ/b448jMozv24BQscDSa
         1q7w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=RwGYYt7lWUsEoYOISVSeiDzkDu64GSIFXI4aAGRPP0Q=;
        fh=BNcPhemX2Yte9USuk+pE1kDp8RlaLWSNRmPyjqu97vY=;
        b=f/gjyXqcvcGBn6fSKFBCqGCGAm+jVWPj3PFq+j8shH9VEwwGcXCbFGtdIgbaRAGLwW
         L1FURYi6D5FKHIPMMKC7dRuFZAku71H3cYIryte/5xbQZRBJmnvD6pw/XFTnEBRMM4MY
         Kv1o6fM9JIePOIS9fD5fz/f0mq8GEoyiTMh/vK9LskC0I7K6yq6vdyGpc4epgExfz4KH
         KomNvtL661LjzGC44XjkX19iZLMwM9ZhUX6q282kWw+/V9A0dPHTeRrD0Tt1HH0U9XVw
         FAdwsWyF3ueEaO7HaJdOTy3wE/OVn3ecgsl9R3PTItjyi/Yv7JDJaP49oNMh1gvJJdvK
         Kkpg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=AVFavAVc;
       spf=pass (google.com: domain of davidgow@google.com designates 2607:f8b0:4864:20::f29 as permitted sender) smtp.mailfrom=davidgow@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-qv1-xf29.google.com (mail-qv1-xf29.google.com. [2607:f8b0:4864:20::f29])
        by gmr-mx.google.com with ESMTPS id 46e09a7af769-74186c99b37si222966a34.1.2025.08.02.02.44.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 02 Aug 2025 02:44:57 -0700 (PDT)
Received-SPF: pass (google.com: domain of davidgow@google.com designates 2607:f8b0:4864:20::f29 as permitted sender) client-ip=2607:f8b0:4864:20::f29;
Received: by mail-qv1-xf29.google.com with SMTP id 6a1803df08f44-707453b031fso26896766d6.1
        for <kasan-dev@googlegroups.com>; Sat, 02 Aug 2025 02:44:57 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWZOncWECDhqpLahBrwUN9lTO8CDK9iLqY36Nne9RQvbNrlk27UHhwDWtxChkFXDWSZ0p+nD2iRlrM=@googlegroups.com
X-Gm-Gg: ASbGncttIcZFaiW5CCn1GDcRoQzRK6jFyN0pZ3Cae7C4Tf+YJbyw7ajkx+fGTA03ZOj
	WBfJitOsSeYOl1Id8xqK+tdbSuG/JOhVPdESR10JGIHz3d6yEO2R4azupCpsihC1KOQGVSN10rn
	nAVlbTesfhpRgQDkDVdttdLG8fGeUnQ+Z1unC5qojV7j5+/LVqSDPuHW1b+MdqPxIm35afctjxy
	HKvvO2S
X-Received: by 2002:a05:6214:dab:b0:709:31e2:465a with SMTP id
 6a1803df08f44-70936522c7dmr49740236d6.7.1754127896464; Sat, 02 Aug 2025
 02:44:56 -0700 (PDT)
MIME-Version: 1.0
References: <20250729193647.3410634-1-marievic@google.com> <20250729193647.3410634-4-marievic@google.com>
In-Reply-To: <20250729193647.3410634-4-marievic@google.com>
From: "'David Gow' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Sat, 2 Aug 2025 17:44:43 +0800
X-Gm-Features: Ac12FXyq85JkWJa7V2n6oMNik7XR4Bcgcea9TMbgv8-h7CIIiTRnRuAYy96PX1w
Message-ID: <CABVgOSkmQHU5ScvgG=i64Rw29yVprJBxoHwhmmrZgR4gJ95srg@mail.gmail.com>
Subject: Re: [PATCH 3/9] kunit: Pass additional context to generate_params for
 parameterized testing
To: Marie Zhussupova <marievic@google.com>
Cc: rmoar@google.com, shuah@kernel.org, brendan.higgins@linux.dev, 
	elver@google.com, dvyukov@google.com, lucas.demarchi@intel.com, 
	thomas.hellstrom@linux.intel.com, rodrigo.vivi@intel.com, 
	linux-kselftest@vger.kernel.org, kunit-dev@googlegroups.com, 
	kasan-dev@googlegroups.com, intel-xe@lists.freedesktop.org, 
	dri-devel@lists.freedesktop.org, linux-kernel@vger.kernel.org
Content-Type: multipart/signed; protocol="application/pkcs7-signature"; micalg=sha-256;
	boundary="000000000000316547063b5ebad3"
X-Original-Sender: davidgow@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=AVFavAVc;       spf=pass
 (google.com: domain of davidgow@google.com designates 2607:f8b0:4864:20::f29
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

--000000000000316547063b5ebad3
Content-Type: text/plain; charset="UTF-8"

On Wed, 30 Jul 2025 at 03:37, Marie Zhussupova <marievic@google.com> wrote:
>
> To enable more complex parameterized test scenarios,
> the `generate_params` function sometimes needs additional
> context beyond just the previously generated parameter.
> This patch modifies the `generate_params` function signature
> to include an extra `struct kunit *test` argument, giving
> users access to the parent kunit test's context when
> generating subsequent parameters.
>
> The `struct kunit *test` argument was added as the first parameter
> to the function signature as it aligns with the convention
> of other KUnit functions that accept `struct kunit *test` first.
> This also mirrors the "this" or "self" reference found
> in object-oriented programming languages.

This matches my prejudices well. :-)

> Signed-off-by: Marie Zhussupova <marievic@google.com>
> ---

At last! This will be very useful as a way of having more complicated
generator functions (or, indeed, any generator function which wants
state without hacking it into an enormously complicated parameter
object).

The only thing worth noting is that this breaks the existing tests
until the next two patches are accepted, which could be a pain for
bisecting. I can live with it, since the breakage is obvious and
confined to the span of a couple of patches in the same series and to
test-only code, but if others prefer, we can squash these together.

Reviewed-by: David Gow <davidgow@google.com>

Cheers,
-- David


>  include/kunit/test.h | 9 ++++++---
>  lib/kunit/test.c     | 5 +++--
>  2 files changed, 9 insertions(+), 5 deletions(-)
>
> diff --git a/include/kunit/test.h b/include/kunit/test.h
> index d8dac7efd745..4ba65dc35710 100644
> --- a/include/kunit/test.h
> +++ b/include/kunit/test.h
> @@ -128,7 +128,8 @@ struct kunit_attributes {
>  struct kunit_case {
>         void (*run_case)(struct kunit *test);
>         const char *name;
> -       const void* (*generate_params)(const void *prev, char *desc);
> +       const void* (*generate_params)(struct kunit *test,
> +                                      const void *prev, char *desc);
>         struct kunit_attributes attr;
>
>         /*
> @@ -1701,7 +1702,8 @@ do {                                                                             \
>   * Define function @name_gen_params which uses @array to generate parameters.
>   */
>  #define KUNIT_ARRAY_PARAM(name, array, get_desc)                                               \
> -       static const void *name##_gen_params(const void *prev, char *desc)                      \
> +       static const void *name##_gen_params(struct kunit *test,                                \
> +                                            const void *prev, char *desc)                      \
>         {                                                                                       \
>                 typeof((array)[0]) *__next = prev ? ((typeof(__next)) prev) + 1 : (array);      \
>                 if (__next - (array) < ARRAY_SIZE((array))) {                                   \
> @@ -1722,7 +1724,8 @@ do {                                                                             \
>   * Define function @name_gen_params which uses @array to generate parameters.
>   */
>  #define KUNIT_ARRAY_PARAM_DESC(name, array, desc_member)                                       \
> -       static const void *name##_gen_params(const void *prev, char *desc)                      \
> +       static const void *name##_gen_params(struct kunit *test,                                \
> +                                            const void *prev, char *desc)                      \
>         {                                                                                       \
>                 typeof((array)[0]) *__next = prev ? ((typeof(__next)) prev) + 1 : (array);      \
>                 if (__next - (array) < ARRAY_SIZE((array))) {                                   \
> diff --git a/lib/kunit/test.c b/lib/kunit/test.c
> index d80b5990d85d..f50ef82179c4 100644
> --- a/lib/kunit/test.c
> +++ b/lib/kunit/test.c
> @@ -696,7 +696,7 @@ int kunit_run_tests(struct kunit_suite *suite)
>                         /* Get initial param. */
>                         param_desc[0] = '\0';
>                         /* TODO: Make generate_params try-catch */
> -                       curr_param = test_case->generate_params(NULL, param_desc);
> +                       curr_param = test_case->generate_params(&test, NULL, param_desc);
>                         test_case->status = KUNIT_SKIPPED;
>                         kunit_log(KERN_INFO, &test, KUNIT_SUBTEST_INDENT KUNIT_SUBTEST_INDENT
>                                   "KTAP version 1\n");
> @@ -727,7 +727,8 @@ int kunit_run_tests(struct kunit_suite *suite)
>
>                                 /* Get next param. */
>                                 param_desc[0] = '\0';
> -                               curr_param = test_case->generate_params(curr_param, param_desc);
> +                               curr_param = test_case->generate_params(&test, curr_param,
> +                                                                       param_desc);
>                         }
>                 }
>
> --
> 2.50.1.552.g942d659e1b-goog
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CABVgOSkmQHU5ScvgG%3Di64Rw29yVprJBxoHwhmmrZgR4gJ95srg%40mail.gmail.com.

--000000000000316547063b5ebad3
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
0TANBglghkgBZQMEAgEFAKCBxzAvBgkqhkiG9w0BCQQxIgQgy96xwUKo/cfvxWdCgEf8Y1F4Twi1
KLJt5QJCgWQhfzEwGAYJKoZIhvcNAQkDMQsGCSqGSIb3DQEHATAcBgkqhkiG9w0BCQUxDxcNMjUw
ODAyMDk0NDU3WjBcBgkqhkiG9w0BCQ8xTzBNMAsGCWCGSAFlAwQBKjALBglghkgBZQMEARYwCwYJ
YIZIAWUDBAECMAoGCCqGSIb3DQMHMAsGCSqGSIb3DQEBBzALBglghkgBZQMEAgEwDQYJKoZIhvcN
AQEBBQAEggEAN8qk3rEX8L8KHyPsiqaKkeL1KfuzCU6oLIjNlYlwiBglQMZlFkKcZGmJklzcMc/5
ozY4wDcnnf4KcaSy7bPJ5ZC4dsU/trQbSV+oLhPmCPscUhhn66oRPO/YQtGMO55DGPH79/nRhT+L
rZxds+dloxM7ypOx+sSReuaIm6rdBTjqcQdKkwMuKpsCYEkCLzQpVm9hBS+AzqduPAqoPCIESSAX
5eSBIJpyjoeI91OCqYr/OcOZhg9CrPzCgs8w2m6FDmPmv+Uavk3XhfzIBYDKEFZiSLjgYzvqzaiG
IEjCs4nuv9zUN0XBlAQN3XGJEOZBwQGXW1hZ2we25Zj2KzbLtw==
--000000000000316547063b5ebad3--
