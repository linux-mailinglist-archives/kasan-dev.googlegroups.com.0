Return-Path: <kasan-dev+bncBC7OBJGL2MHBBZWE2OEAMGQEKW4F43I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe38.google.com (mail-vs1-xe38.google.com [IPv6:2607:f8b0:4864:20::e38])
	by mail.lfdr.de (Postfix) with ESMTPS id C0A8D3EA118
	for <lists+kasan-dev@lfdr.de>; Thu, 12 Aug 2021 10:57:11 +0200 (CEST)
Received: by mail-vs1-xe38.google.com with SMTP id e12-20020a67fb4c0000b02902bcb9baa658sf661976vsr.11
        for <lists+kasan-dev@lfdr.de>; Thu, 12 Aug 2021 01:57:11 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1628758631; cv=pass;
        d=google.com; s=arc-20160816;
        b=KwZIGBhWR+Oh/x+T9f/0Lj0PwmDoAhiTYPw89HoEKp1XiUr+3Y08LM8r1lVm8dg/7D
         e6jRVkd/5w96gOptBe/EoIO+bQN8QQNdpZoym94FFyLRgIzA2U/Pcq5WJQgAE9yn/htC
         5orbV8T/ASpCJ/mGst2hsA1ORROtEXqKm/ho3XkicveuXNo7wdG5+UwpGm+eiJ6HrMAr
         PaP9FgiK8HRgr1/oSgXpsecdKeHeQbdedpJ2eju619ZT6/HmNs69e3Oc2qojvvFPO2nZ
         xMgp/LqkrYUYg4nduMB3aaO9qi7AuC71glhJr+c0nqZt/9tSZteMEPyeyZq7xY0sytE4
         7JHA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=01OIvCGfy1iJj7bYMERmeHznxPoUeiUb67euPM3xhAw=;
        b=TphvM+Q/h+maLMaA92zsX/AxaHcYE1AHib0WJtB8an/HjbBZ6RlTqf1J/tOUNStuvk
         ArAgcOxauInJW9ICbkt5IVSM0dEQU43ZMqdscT2f7Y6kDJNRuTA3/lsVUc06U1nkqKR7
         zI4vNE7w0vfQxJiG9N5aO27hz0dGdSAA0HGgAc4vYAlAJQCYv2DGHYkP0wiSmfvwquKY
         WFXuAMAk4Bn2I86y3u4v5rPro1Bk30sJeZkXedZpaszIYYymTbnvcDX9+eMrXIpZNcgs
         59Zz/lzbIdiR37IFpJHH4AXPCvXhvqOvPgzQHWwjDTj4iivoP8nbqSyCZpWyKevnWMQN
         bfmg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=AQQ58CvZ;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::230 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=01OIvCGfy1iJj7bYMERmeHznxPoUeiUb67euPM3xhAw=;
        b=eybsfAzfYmM+NfBhEkyExlopEcKzpVrLk0XrfzJ6LWw0Hj03ow3SGQ1K0QGwNXqYkh
         OdExm/o/dUlGzxsoTuEj6ZpRsx9e/ULX7s8Brfxljy3MXCNypi6/RYKfbXyrnLv4jwD8
         gNSje20CxIZZLX3yUH6QfA1m/zA/RxmcMVLktEBwAl5GUZz8+QRgh8EwcgC0nqvNzZmV
         CA4GT9eGT5HTZ/GCgqnh8Eep5kS9VLTvgSAdW++P6nWFE+VJ4dADrfJP6Zbqv8ZR0Yfa
         CvVO7g2M/sFd++T77kx6xe53gc/IcIRLsEf3p4LIm5TE7oItc7+G2/CQNpMIhqvH7IrP
         luig==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=01OIvCGfy1iJj7bYMERmeHznxPoUeiUb67euPM3xhAw=;
        b=AH9sr8zFaavjELYimHNR2Pc9Yzkr/om78m1KJAxsDxTjRSLC8zHNjdjJ2X44L/V2FN
         58LO4noVxnMIEWz6LYe6/jiii6pjYXIaERgIsWBjw36lQfMYz1PwtcyNtaRIl9GoDEsb
         f60CakbMr0YF562OjNMZNQJLRv40uHTfWFj7v6grVS8GATGM0JQ2D03v2T5miFIoNwxG
         4A++geWiCwPAFd/wHLv+MqmiSP2yReqc7OgZwjOTGKiha3HIjmneTCJ694kmNYBHs2Yp
         RuGrT+bI1ef+bgdJIBl+KCPbh1cbjlTj7mJ4ZnQzYU+dQOT12dnzKSn1+cfXDy4ivL//
         7DNA==
X-Gm-Message-State: AOAM532oEn2xCf3NnHjhnf5AY4/6+PA4thgOT2SRrpcADOx945B8zFyQ
	Xkn1mQjH0VtrqcTifMfCNMQ=
X-Google-Smtp-Source: ABdhPJwDICH3IFFkuW3gKI7d0nMtRb5XSOk7jCL1ozAB11aCEKSKQv8GROv7l53970+qBgFGx0rqnA==
X-Received: by 2002:a05:6122:925:: with SMTP id j37mr2015125vka.21.1628758630829;
        Thu, 12 Aug 2021 01:57:10 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:edd7:: with SMTP id e23ls892008vsp.5.gmail; Thu, 12 Aug
 2021 01:57:10 -0700 (PDT)
X-Received: by 2002:a67:42c2:: with SMTP id p185mr2143820vsa.41.1628758630344;
        Thu, 12 Aug 2021 01:57:10 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1628758630; cv=none;
        d=google.com; s=arc-20160816;
        b=jD5yxtjrkNRSurfLptq6oTHpAwAsGf7F0GmYnXAA0vcwUq20D/ZjNaSQncHRCeYyBT
         oyyQ04PRa7LhNHQnj9eAmQIWygqSq2Ie2wEmNfGQ6SLTwfhvJSKnY0YFzMrUhamI3/EX
         QDxlXUfG3WdhNBa6YTvaMy7J7v6r65ZXW5IavP1TiNKYCULH0nMXo3Cg9DOiC5Ppklsf
         aKV5WAuqiyUgqOKwyrWhgkrBeuAuhJhFgxeVU5+B+Lkrdn/A+yt4wm+5BQzwfytrGmCa
         qYLKAYJSZ3LJiDPCTAL0S5rYzfEWCEcBX0XzYI/coM/7bsDnN/hgmRS5X0+7ohARpKlw
         FFCQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=NvfdMZYMJAya7AOkWdDc2oNND0X7RYexhanHnq6ZuEo=;
        b=K+Y94n0K30lDz7jconIBsZa9dAlApHPOaOvywv6cxvQZtonF7i/k8/AwvQZ08/8iUr
         1OJc8aBd8Qoi2bjg05zR59muXf0plrEuk742wKwesVzfR9Ki9NfByEouXINLT9/yHFxh
         o4jkR0s3WsN5HzxdW0rPA7hCnOyqTdc0FVBmcdwmatOShfWVHbNjFfFAWZpntZYPrHWl
         pcNHvC7LQlFaxOmbxMkenM8Q0YLE3n38+yA8AJ+QnO623LiHZc41pDN3T9F/qRrCyt2g
         Vl8Oaq4sH2yVJycJRTs09OM3TIqbCyNF2fYdMfZJrxrBs6WcqNa4FplLqQDpRieiPFw/
         Vcqg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=AQQ58CvZ;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::230 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x230.google.com (mail-oi1-x230.google.com. [2607:f8b0:4864:20::230])
        by gmr-mx.google.com with ESMTPS id m184si154688vkg.1.2021.08.12.01.57.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 12 Aug 2021 01:57:10 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::230 as permitted sender) client-ip=2607:f8b0:4864:20::230;
Received: by mail-oi1-x230.google.com with SMTP id bj40so9262410oib.6
        for <kasan-dev@googlegroups.com>; Thu, 12 Aug 2021 01:57:10 -0700 (PDT)
X-Received: by 2002:aca:eb8a:: with SMTP id j132mr2510361oih.121.1628758629909;
 Thu, 12 Aug 2021 01:57:09 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1628709663.git.andreyknvl@gmail.com> <e9e2f7180f96e2496f0249ac81887376c6171e8f.1628709663.git.andreyknvl@gmail.com>
In-Reply-To: <e9e2f7180f96e2496f0249ac81887376c6171e8f.1628709663.git.andreyknvl@gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 12 Aug 2021 10:56:58 +0200
Message-ID: <CANpmjNPGsD_nZbcDNVTeL-b9W7X+2_AhzNAiSLdtxuvfyNFMEA@mail.gmail.com>
Subject: Re: [PATCH 3/8] kasan: test: avoid corrupting memory via memset
To: andrey.konovalov@linux.dev
Cc: Andrew Morton <akpm@linux-foundation.org>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, kasan-dev@googlegroups.com, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=AQQ58CvZ;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::230 as
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

On Wed, 11 Aug 2021 at 21:21, <andrey.konovalov@linux.dev> wrote:
> From: Andrey Konovalov <andreyknvl@gmail.com>
>
> kmalloc_oob_memset_*() tests do writes past the allocated objects.
> As the result, they corrupt memory, which might lead to crashes with the
> HW_TAGS mode, as it neither uses quarantine nor redzones.
>
> Adjust the tests to only write memory within the aligned kmalloc objects.
>
> Signed-off-by: Andrey Konovalov <andreyknvl@gmail.com>
> ---
>  lib/test_kasan.c | 22 +++++++++++-----------
>  1 file changed, 11 insertions(+), 11 deletions(-)
>
> diff --git a/lib/test_kasan.c b/lib/test_kasan.c
> index c82a82eb5393..fd00cd35e82c 100644
> --- a/lib/test_kasan.c
> +++ b/lib/test_kasan.c
> @@ -431,61 +431,61 @@ static void kmalloc_uaf_16(struct kunit *test)
>  static void kmalloc_oob_memset_2(struct kunit *test)
>  {
>         char *ptr;
> -       size_t size = 8;
> +       size_t size = 128 - KASAN_GRANULE_SIZE;
>
>         ptr = kmalloc(size, GFP_KERNEL);
>         KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
>
> -       KUNIT_EXPECT_KASAN_FAIL(test, memset(ptr + 7 + OOB_TAG_OFF, 0, 2));
> +       KUNIT_EXPECT_KASAN_FAIL(test, memset(ptr + size, 0, 2));

I think one important aspect of these tests in generic mode is that
the written range touches both valid and invalid memory. I think that
was meant to test any explicit instrumentation isn't just looking at
the starting address, but at the whole range.

It seems that with these changes that is no longer tested. Could we
somehow make it still test that?


>         kfree(ptr);
>  }
>
>  static void kmalloc_oob_memset_4(struct kunit *test)
>  {
>         char *ptr;
> -       size_t size = 8;
> +       size_t size = 128 - KASAN_GRANULE_SIZE;
>
>         ptr = kmalloc(size, GFP_KERNEL);
>         KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
>
> -       KUNIT_EXPECT_KASAN_FAIL(test, memset(ptr + 5 + OOB_TAG_OFF, 0, 4));
> +       KUNIT_EXPECT_KASAN_FAIL(test, memset(ptr + size, 0, 4));
>         kfree(ptr);
>  }
>
> -
>  static void kmalloc_oob_memset_8(struct kunit *test)
>  {
>         char *ptr;
> -       size_t size = 8;
> +       size_t size = 128 - KASAN_GRANULE_SIZE;
>
>         ptr = kmalloc(size, GFP_KERNEL);
>         KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
>
> -       KUNIT_EXPECT_KASAN_FAIL(test, memset(ptr + 1 + OOB_TAG_OFF, 0, 8));
> +       KUNIT_EXPECT_KASAN_FAIL(test, memset(ptr + size, 0, 8));
>         kfree(ptr);
>  }
>
>  static void kmalloc_oob_memset_16(struct kunit *test)
>  {
>         char *ptr;
> -       size_t size = 16;
> +       size_t size = 128 - KASAN_GRANULE_SIZE;
>
>         ptr = kmalloc(size, GFP_KERNEL);
>         KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
>
> -       KUNIT_EXPECT_KASAN_FAIL(test, memset(ptr + 1 + OOB_TAG_OFF, 0, 16));
> +       KUNIT_EXPECT_KASAN_FAIL(test, memset(ptr + size, 0, 16));
>         kfree(ptr);
>  }
>
>  static void kmalloc_oob_in_memset(struct kunit *test)
>  {
>         char *ptr;
> -       size_t size = 666;
> +       size_t size = 128 - KASAN_GRANULE_SIZE;
>
>         ptr = kmalloc(size, GFP_KERNEL);
>         KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
>
> -       KUNIT_EXPECT_KASAN_FAIL(test, memset(ptr, 0, size + 5 + OOB_TAG_OFF));
> +       KUNIT_EXPECT_KASAN_FAIL(test,
> +                               memset(ptr, 0, size + KASAN_GRANULE_SIZE));
>         kfree(ptr);
>  }
>
> --
> 2.25.1
>
> --
> You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/e9e2f7180f96e2496f0249ac81887376c6171e8f.1628709663.git.andreyknvl%40gmail.com.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNPGsD_nZbcDNVTeL-b9W7X%2B2_AhzNAiSLdtxuvfyNFMEA%40mail.gmail.com.
