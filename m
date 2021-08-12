Return-Path: <kasan-dev+bncBC7OBJGL2MHBB6WE2OEAMGQEYSSNX2I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1037.google.com (mail-pj1-x1037.google.com [IPv6:2607:f8b0:4864:20::1037])
	by mail.lfdr.de (Postfix) with ESMTPS id 388583EA11C
	for <lists+kasan-dev@lfdr.de>; Thu, 12 Aug 2021 10:57:32 +0200 (CEST)
Received: by mail-pj1-x1037.google.com with SMTP id me3-20020a17090b17c3b029017835588237sf7616612pjb.0
        for <lists+kasan-dev@lfdr.de>; Thu, 12 Aug 2021 01:57:32 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1628758651; cv=pass;
        d=google.com; s=arc-20160816;
        b=IJQwaZmYucAc/8TWrcSIB1KuPdVGj6zW/fDYMZvmNKuugW3WvfUxGZnZjveon7DRGZ
         SzwWp4X/SVjmc1u8QqgJJ9zuu6GKTNN6kr+aanTU+0engXa0PcAWhU3iduPmA5UbG3kV
         iIYtBaCJ2Y5EmxiG/j9JnjaLQ48RgAJAhZXoIbTGC4fzH0n06kniPN24cD01Ki06W9jv
         GBxgX8sTo8hBf/VROqvWT66aC9/sXlFVjcmta+ZCiDU/SGL09C7I4RwPz8lAlfj8VB36
         0yFGkPYYUefJ5+dunV8YuDtvGlzWWBNxdf1AvCYb7nVjgp2PVxeMlaRssj2RX29N1JX4
         oJTQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=7H0w/EkVISUjA5H3EtRcByTlho19Esn6wSaq3+sm5XY=;
        b=lHFHihonmSsDWsh0AZj1aaL8z1CS87tSe5Hdt0hxixSIAtjPsafiushlc1nfNaNqAD
         QQks/LOqd+6PVp7nwjStHMONuVtlgBMkGTmPzxwcl2cIAStt42bmjRVR7B8zISsHkwVJ
         93Zzf1vangIez8kaTtP+XL3rPzYx0j22jmfoSf6XO+eFYsmXqk70ey1QchDSQc85s+hL
         fvyg45iWsKp6nEoYkfcIk4vDZHX+ffsaG1AlPqY5fbOu19aou9dpctdrmepsl3mk2Hyn
         +zXWl95NoXDralixYljq/zWkVe7qL1B5b2Q5hCt6IZeRp4f+xiWfzl/QL87dsnbKX5xK
         0AQw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Kalpk5uO;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::229 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=7H0w/EkVISUjA5H3EtRcByTlho19Esn6wSaq3+sm5XY=;
        b=Juwl95De/z/xPYIbS2r1RIerxdmHppr90DxOUCHuSd8FlTLiWARFw4LI4yjgP+gGLq
         Ivg0HmMnlmyq3/XmtrdsK5eWSDGAQl5QJ70wTTglp3+1catwQpSpKoaWhj4vdzP5c2Mn
         WSNlCmgjg9le4cjOZnvRHtaiQH68F2cdzsCRv4fLVnR2BB/abWUNn4z4UthnS3wxRXrT
         /tWd48mH9jzbGMctmtFwr9YtHVOzqhPKA/1NOjaKxFy89MwqmhwXoNIyafHhTc54jvDG
         R+Jhm2dk4K+liFvrPFmhta3IMYZ9qiA8ZsFIwCy7CshaE4vjBk4LyXpLO2C4q/478YRW
         XLGA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=7H0w/EkVISUjA5H3EtRcByTlho19Esn6wSaq3+sm5XY=;
        b=HMAK9Jwg/cLfKeWqxSvmQ2POdqkAzvF4A2T6ERosFCjjPbbSOs1AvL2Tu8tCvGvS4N
         ZJ3rVczLkBmefM8LphoHTC/g6cxNvkfoGz13s0mXV3xDHcbYhwzzaebMZmcWi3RN0UdX
         fnzM/46QZYepqRSMVJmrTZTbymqOk1kO/vo31AFuk2gjj+kCt09uH/pGtw8TWvUWXkXw
         8nskO8Aayj4KnxOKcWKq5cEL3o6q3IqN5m9qjn9fm0Kma4WlUqY9SaylMdAv08oP+vQq
         b+Wx2yaLwMzYxLo7FFm3VmX1tLqWDjTlzP1vQxrsbapxoT+Vb45YuGU1Hq8M65weE9au
         hYCw==
X-Gm-Message-State: AOAM530Wwnvqm8cxcVUmblCLCTiboGlJeMNYn+VdfCK7O+kp3gD2FMJI
	JdZ3Xg3Da/cMDuhDS/HPldk=
X-Google-Smtp-Source: ABdhPJyW4Ocw5vwyYa+xKidaiZcfTX7VXOeIqP4+0EnTngyxKQac5IvWR1uk88yuZBph1i3Ge4j7fQ==
X-Received: by 2002:a17:90b:fc5:: with SMTP id gd5mr3388995pjb.193.1628758650988;
        Thu, 12 Aug 2021 01:57:30 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:ed82:: with SMTP id e2ls2290390plj.2.gmail; Thu, 12
 Aug 2021 01:57:30 -0700 (PDT)
X-Received: by 2002:a17:90a:4306:: with SMTP id q6mr15048316pjg.202.1628758650442;
        Thu, 12 Aug 2021 01:57:30 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1628758650; cv=none;
        d=google.com; s=arc-20160816;
        b=mO33KeOBOqPIC11QjSnvCtuvAHObvqxj3mH3m12zWNemhigvmm09J3P63G6pX6LNaV
         4i5JPbpIUfMyK+7wgWiFDb5EcxXbkyB4cKJUr1TGjfr8zzmGnRO9TNWXI7u3P2vQ7wBM
         QX9VxRk0wHHWJpRJh6zpv34OIQbyTev69BWtK3sLM6mrwBXbrMOPApg3q4ndKSOb5SXH
         dQVP/NFTRtZrymQR1FPILFRqqfLvMcAeRt7DAMf5Qe9lrWKPvJz845bsERta8i60O8zr
         9TTNbsJ9ivkdZIRxsJ4M/pqQt1EdT61A0elY9zGwjYvVpmDE2B/oa9+bg7VNSoU2xG2R
         LOrg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=faqrh261ptBS/eNsuw/b4oqk4dw9ADdOP4UjgUKWvsw=;
        b=qGw5jRK71eZMlKGrwQMu5p6ZS65CkOEys21M4VZhmiBxA3PcsG9ONo6ek14HklOXAI
         JjSV+bG8/XN6OJBSotLy8kS48urVHzNvRSm7URwpDNZJj+wvjEnmfbp1Ndo5DfNXDqNr
         DhZkBfiGA3HOhatoRwjovLvTdiarPcpbhetFtCWkKpjxYrFdEra0hu45m4ia0JPdpBum
         u9hoLKJJnh3bI1uE38A9DspsqHJjKwgyjqtRXJ+lwbxvb3Q8or9vCkhaNA/AVMFegSNT
         TxqEGGpuIvmsz6L7upRMVDuA8mM1p+4Wc3v5DC8wEIkxAp+g3Q3UQ3NjpoWlYuTVtnNV
         4oyA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Kalpk5uO;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::229 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x229.google.com (mail-oi1-x229.google.com. [2607:f8b0:4864:20::229])
        by gmr-mx.google.com with ESMTPS id c23si115584pls.5.2021.08.12.01.57.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 12 Aug 2021 01:57:30 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::229 as permitted sender) client-ip=2607:f8b0:4864:20::229;
Received: by mail-oi1-x229.google.com with SMTP id o20so9204872oiw.12
        for <kasan-dev@googlegroups.com>; Thu, 12 Aug 2021 01:57:30 -0700 (PDT)
X-Received: by 2002:aca:2316:: with SMTP id e22mr2504583oie.172.1628758649694;
 Thu, 12 Aug 2021 01:57:29 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1628709663.git.andreyknvl@gmail.com> <474aa8b7b538c6737a4c6d0090350af2e1776bef.1628709663.git.andreyknvl@gmail.com>
In-Reply-To: <474aa8b7b538c6737a4c6d0090350af2e1776bef.1628709663.git.andreyknvl@gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 12 Aug 2021 10:57:18 +0200
Message-ID: <CANpmjNNCV_sioFk0C3mChxCq6-eED+ThV2h-ygPVyaWg3667LQ@mail.gmail.com>
Subject: Re: [PATCH 1/8] kasan: test: rework kmalloc_oob_right
To: andrey.konovalov@linux.dev
Cc: Andrew Morton <akpm@linux-foundation.org>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, kasan-dev@googlegroups.com, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=Kalpk5uO;       spf=pass
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

On Wed, 11 Aug 2021 at 21:21, <andrey.konovalov@linux.dev> wrote:
> From: Andrey Konovalov <andreyknvl@gmail.com>
>
> Rework kmalloc_oob_right() to do these bad access checks:
>
> 1. An unaligned access one byte past the requested kmalloc size
>    (can only be detected by KASAN_GENERIC).
> 2. An aligned access into the first out-of-bounds granule that falls
>    within the aligned kmalloc object.
> 3. Out-of-bounds access past the aligned kmalloc object.
>
> Test #3 deliberately uses a read access to avoid corrupting memory.
> Otherwise, this test might lead to crashes with the HW_TAGS mode, as it
> neither uses quarantine nor redzones.
>
> Signed-off-by: Andrey Konovalov <andreyknvl@gmail.com>

Reviewed-by: Marco Elver <elver@google.com>


> ---
>  lib/test_kasan.c | 20 ++++++++++++++++++--
>  1 file changed, 18 insertions(+), 2 deletions(-)
>
> diff --git a/lib/test_kasan.c b/lib/test_kasan.c
> index 8f7b0b2f6e11..1bc3cdd2957f 100644
> --- a/lib/test_kasan.c
> +++ b/lib/test_kasan.c
> @@ -122,12 +122,28 @@ static void kasan_test_exit(struct kunit *test)
>  static void kmalloc_oob_right(struct kunit *test)
>  {
>         char *ptr;
> -       size_t size = 123;
> +       size_t size = 128 - KASAN_GRANULE_SIZE - 5;
>
>         ptr = kmalloc(size, GFP_KERNEL);
>         KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
>
> -       KUNIT_EXPECT_KASAN_FAIL(test, ptr[size + OOB_TAG_OFF] = 'x');
> +       /*
> +        * An unaligned access past the requested kmalloc size.
> +        * Only generic KASAN can precisely detect these.
> +        */
> +       if (IS_ENABLED(CONFIG_KASAN_GENERIC))
> +               KUNIT_EXPECT_KASAN_FAIL(test, ptr[size] = 'x');
> +
> +       /*
> +        * An aligned access into the first out-of-bounds granule that falls
> +        * within the aligned kmalloc object.
> +        */
> +       KUNIT_EXPECT_KASAN_FAIL(test, ptr[size + 5] = 'y');
> +
> +       /* Out-of-bounds access past the aligned kmalloc object. */
> +       KUNIT_EXPECT_KASAN_FAIL(test, ptr[0] =
> +                                       ptr[size + KASAN_GRANULE_SIZE + 5]);
> +
>         kfree(ptr);
>  }
>
> --
> 2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNNCV_sioFk0C3mChxCq6-eED%2BThV2h-ygPVyaWg3667LQ%40mail.gmail.com.
