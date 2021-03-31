Return-Path: <kasan-dev+bncBC7OBJGL2MHBBWOUSKBQMGQEYD4XRCI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe3d.google.com (mail-vs1-xe3d.google.com [IPv6:2607:f8b0:4864:20::e3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 574E8350528
	for <lists+kasan-dev@lfdr.de>; Wed, 31 Mar 2021 18:59:06 +0200 (CEST)
Received: by mail-vs1-xe3d.google.com with SMTP id r185sf336729vsr.0
        for <lists+kasan-dev@lfdr.de>; Wed, 31 Mar 2021 09:59:06 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1617209945; cv=pass;
        d=google.com; s=arc-20160816;
        b=z+aFqAZmYPKaSqWb25HxWFJ0i4XJxYq8WIJxV/TEpbmjgYLFJeej8I852y8azg0xaH
         mdUdvjiXCkATEtpjcyBcXVTWVYrH+4m0asZlqDkFbHp5dxhVCSQCdh19H/vtkZwkHkIC
         +y41hJumOT88tC8scuduoyDBHs6k1Pc7wYoYIgkGJCNPQTvhwwAqKdmw2jwALG9Oi/Ya
         ZmvUXF92smhmgdduj9QbA3SB/glB5/WauytsIZ+PPpa/Bt8OousixNRPum5P2TRqPie4
         x4Kt0onto1rk2t3MRX56YzPUhWYn74wmPv8d2+VDIHFUtIGj6igDEVTy7qaxRIHF5r6Q
         U6zQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=k0PU21Y1LzmVSsOygqdEikyk+iiMOkMA8ggB5EVtZGQ=;
        b=wJj7mxGWypRNWpgn415vemQ3rG+CK5H60z6t4g1C8a2h6/Lcpyaj0CxFMkRx4AKF2g
         dmaynuMa+kMheyTV9noJVEif+1KvprG1W4tNoZZ4RQ0oCMk8gSoplWBH5B6nF13/fjwE
         VbdPPgxFpVjNxv2Te8D0pWvqLd1s5LsVmI5ZCUkOFNR5LjXVFjR5x5YmGAYKxVMmlJ16
         GkeR6SBcTORCN/E6GcFVT0dF4c/icDxmPmi8ch0mhd+3BxqEFuVbyjzDZWFyKlbrwn3G
         Mdj1FtnH0J7VpaK6DU4nuvblKXvKV1rPeqqVLhwcZMfz/nmsffgOSkFq+OlnNFy5KfHA
         DbQA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=lPsNsAfl;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::229 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=k0PU21Y1LzmVSsOygqdEikyk+iiMOkMA8ggB5EVtZGQ=;
        b=UYYKbDMxfWmZkq6qlxyn/TCeWBY2MpqdrAeL53SeiD9sWMOCmp/6Yqyb3pCO39YCj0
         CTQzrBOWbKZKEmt1vJ72wDeM8j1sfQnpmxhIm13neQvc8GSNmVL3pdL9F2LFOKnBv5/q
         SbQaXRMFmXSAUKZ7uccoJKdsi/7t0JktHYirQIBQfvusIEilLfkwYjNQ/pZl+Jyk4u+O
         E64g2mxhrsR0CrG1xAA4uxE7tszRuwE64U2JVoxZDCcN2HopV6ioNXCMKBQF4SgOYt8r
         as9HduoJsEzrDg95E4l4BBziVrZ11FodXQ4WiogVWHKbeFNu5ILLXOYrGBbqofXY97z3
         7w5A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=k0PU21Y1LzmVSsOygqdEikyk+iiMOkMA8ggB5EVtZGQ=;
        b=cHurJP4CJ5IFVbCUT/p075v4K8/m8CapEKHRlhakZ/JN/vvMrQim04gdLZucofpXSz
         TFCKHxGrjp/lrIgIQ27ao/WCevyr9H3Cv2izPzbCReGnBshidsuawHwt4Tl7RG4IMbmo
         q4Fo+sr6t9ayT3t0H6QaQBNEbhjB41/IhUIoe3HnXwCv1HSiK53MiH3uE5JQSMEGCWDL
         DjIpC7JZTmMCLBDsDFVuThAoMHQ/aAJrI2LC0sP6M57TMRVafgEWwtWOPAdeEapEqBSi
         gxFygpHRNLX2DuIq6DxfuO1F1XR+s98TUMN/4EUm+l6SXEcPgAlTVkB6WAA0KU44Y5o3
         lsgA==
X-Gm-Message-State: AOAM532qXgqV704CJta4CAAcwJNY8ys5OSJS/OM0bPwQFmoOb5Ueh3sH
	OYuzGmucQtWe69CXDK2t6ok=
X-Google-Smtp-Source: ABdhPJwORq9cOEWVxOYT2N2EdQrV72iRzrH+IJoFuZd7/y9O3JXfQcqUZuNPANgg89U7mz6T+4MUaw==
X-Received: by 2002:a05:6102:1154:: with SMTP id j20mr2460205vsg.4.1617209945396;
        Wed, 31 Mar 2021 09:59:05 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:2f46:: with SMTP id v67ls335031vsv.5.gmail; Wed, 31 Mar
 2021 09:59:04 -0700 (PDT)
X-Received: by 2002:a67:3243:: with SMTP id y64mr2475562vsy.0.1617209944845;
        Wed, 31 Mar 2021 09:59:04 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1617209944; cv=none;
        d=google.com; s=arc-20160816;
        b=Rsa6h3FjpFYhC6He06cuuxnYckEIyvhA8Ki/KINacroVnUz4EDdoMWrKaLy2ECjaR5
         L0y7WlNSFJEgCr8LyjiojdRFhAc3HdvkHG4KNnHvZ/yyheHU8PPeVtAqTx3u0M8lrJgj
         z3EAS5kPZ/1atDvtGUcosd0ssXFFi4k3uUNoB50TddNZxqQ+v1ZJY5eZ/pln6Qbdar96
         DNkNZtpMIIzYiCfNVZx69pDr9B5MFkwN3cakub66JDioBu6ABNIHVA5Za9m5gzf5iAJd
         5pJeGmSNU1TmxCeOkwy9KFscpRqQ6Gt68btic7cU6QICaN8mx0shPaUk11zilNitVQ1o
         fObg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=FZftGjdCUXY+05ORZ/0TVog0hvFmuHoMzmlE5jZV4Tc=;
        b=oqaGYmQgR6bM4r+qha8py7pptu3F5cJu/dj9ibOAzXuohyZS2vfz+ENQrR/LJ3DbWv
         atj9po02UZDXQdi/xH0nScJY5MGSbIgxb894fUt9BRDGwrACAah36ABaGn6T4jg2OOjK
         1jGGS5oT76FpDlJsgYi7X3UdFRLqjywEHI7jEroGysHJwth9+eU05uLv4r+E3vAIarZ0
         adr452GPkSVhHH87kD0b4Kd7A8vo9sV6gvnOV0eyQnt6f0s5U++vxERF6kZAgvNGamF5
         Zr8H+xj0AJotdFnjUTsL6zRu6evYyAftRcNZHCNlqcoRwfaSsqYkJXE+qLJJ1S7RJVb0
         UIUg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=lPsNsAfl;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::229 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x229.google.com (mail-oi1-x229.google.com. [2607:f8b0:4864:20::229])
        by gmr-mx.google.com with ESMTPS id u22si128569vsn.0.2021.03.31.09.59.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 31 Mar 2021 09:59:04 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::229 as permitted sender) client-ip=2607:f8b0:4864:20::229;
Received: by mail-oi1-x229.google.com with SMTP id x2so20668386oiv.2
        for <kasan-dev@googlegroups.com>; Wed, 31 Mar 2021 09:59:04 -0700 (PDT)
X-Received: by 2002:aca:bb06:: with SMTP id l6mr2893534oif.121.1617209944150;
 Wed, 31 Mar 2021 09:59:04 -0700 (PDT)
MIME-Version: 1.0
References: <48079c52cc329fbc52f4386996598d58022fb872.1617207873.git.andreyknvl@google.com>
In-Reply-To: <48079c52cc329fbc52f4386996598d58022fb872.1617207873.git.andreyknvl@google.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 31 Mar 2021 18:58:52 +0200
Message-ID: <CANpmjNMpT0rYKfywkGvqLy8tk3iP6wAuGxHpHVJA77+EG4c5Gg@mail.gmail.com>
Subject: Re: [PATCH] kasan: detect false-positives in tests
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=lPsNsAfl;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::229 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

On Wed, 31 Mar 2021 at 18:25, Andrey Konovalov <andreyknvl@google.com> wrote:
>
> Currently, KASAN-KUnit tests can check that a particular annotated part
> of code causes a KASAN report. However, they do not check that no unwanted
> reports happen between the annotated parts.
>
> This patch implements these checks.
>
> It is done by setting report_data.report_found to false in
> kasan_test_init() and at the end of KUNIT_EXPECT_KASAN_FAIL() and then
> checking that it remains false at the beginning of
> KUNIT_EXPECT_KASAN_FAIL() and in kasan_test_exit().
>
> kunit_add_named_resource() call is moved to kasan_test_init(), and the
> value of fail_data.report_expected is kept as false in between
> KUNIT_EXPECT_KASAN_FAIL() annotations for consistency.
>
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

Reviewed-by: Marco Elver <elver@google.com>

Thank you!

> ---
>  lib/test_kasan.c | 49 +++++++++++++++++++++++++++---------------------
>  1 file changed, 28 insertions(+), 21 deletions(-)
>
> diff --git a/lib/test_kasan.c b/lib/test_kasan.c
> index d77c45edc7cd..bf9225002a7e 100644
> --- a/lib/test_kasan.c
> +++ b/lib/test_kasan.c
> @@ -54,6 +54,10 @@ static int kasan_test_init(struct kunit *test)
>
>         multishot = kasan_save_enable_multi_shot();
>         kasan_set_tagging_report_once(false);
> +       fail_data.report_found = false;
> +       fail_data.report_expected = false;
> +       kunit_add_named_resource(test, NULL, NULL, &resource,
> +                                       "kasan_data", &fail_data);
>         return 0;
>  }
>
> @@ -61,6 +65,7 @@ static void kasan_test_exit(struct kunit *test)
>  {
>         kasan_set_tagging_report_once(true);
>         kasan_restore_multi_shot(multishot);
> +       KUNIT_EXPECT_FALSE(test, fail_data.report_found);
>  }
>
>  /**
> @@ -78,28 +83,30 @@ static void kasan_test_exit(struct kunit *test)
>   * fields, it can reorder or optimize away the accesses to those fields.
>   * Use READ/WRITE_ONCE() for the accesses and compiler barriers around the
>   * expression to prevent that.
> + *
> + * In between KUNIT_EXPECT_KASAN_FAIL checks, fail_data.report_found is kept as
> + * false. This allows detecting KASAN reports that happen outside of the checks
> + * by asserting !fail_data.report_found at the start of KUNIT_EXPECT_KASAN_FAIL
> + * and in kasan_test_exit.
>   */
> -#define KUNIT_EXPECT_KASAN_FAIL(test, expression) do {         \
> -       if (IS_ENABLED(CONFIG_KASAN_HW_TAGS))                   \
> -               migrate_disable();                              \
> -       WRITE_ONCE(fail_data.report_expected, true);            \
> -       WRITE_ONCE(fail_data.report_found, false);              \
> -       kunit_add_named_resource(test,                          \
> -                               NULL,                           \
> -                               NULL,                           \
> -                               &resource,                      \
> -                               "kasan_data", &fail_data);      \
> -       barrier();                                              \
> -       expression;                                             \
> -       barrier();                                              \
> -       KUNIT_EXPECT_EQ(test,                                   \
> -                       READ_ONCE(fail_data.report_expected),   \
> -                       READ_ONCE(fail_data.report_found));     \
> -       if (IS_ENABLED(CONFIG_KASAN_HW_TAGS)) {                 \
> -               if (READ_ONCE(fail_data.report_found))          \
> -                       kasan_enable_tagging();                 \
> -               migrate_enable();                               \
> -       }                                                       \
> +#define KUNIT_EXPECT_KASAN_FAIL(test, expression) do {                 \
> +       if (IS_ENABLED(CONFIG_KASAN_HW_TAGS))                           \
> +               migrate_disable();                                      \
> +       KUNIT_EXPECT_FALSE(test, READ_ONCE(fail_data.report_found));    \
> +       WRITE_ONCE(fail_data.report_expected, true);                    \
> +       barrier();                                                      \
> +       expression;                                                     \
> +       barrier();                                                      \
> +       KUNIT_EXPECT_EQ(test,                                           \
> +                       READ_ONCE(fail_data.report_expected),           \
> +                       READ_ONCE(fail_data.report_found));             \
> +       if (IS_ENABLED(CONFIG_KASAN_HW_TAGS)) {                         \
> +               if (READ_ONCE(fail_data.report_found))                  \
> +                       kasan_enable_tagging();                         \
> +               migrate_enable();                                       \
> +       }                                                               \
> +       WRITE_ONCE(fail_data.report_found, false);                      \
> +       WRITE_ONCE(fail_data.report_expected, false);                   \
>  } while (0)
>
>  #define KASAN_TEST_NEEDS_CONFIG_ON(test, config) do {                  \
> --
> 2.31.0.291.g576ba9dcdaf-goog
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNMpT0rYKfywkGvqLy8tk3iP6wAuGxHpHVJA77%2BEG4c5Gg%40mail.gmail.com.
