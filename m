Return-Path: <kasan-dev+bncBC7OBJGL2MHBBD4XWOIAMGQEO45B2PA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33c.google.com (mail-ot1-x33c.google.com [IPv6:2607:f8b0:4864:20::33c])
	by mail.lfdr.de (Postfix) with ESMTPS id 7916E4B8519
	for <lists+kasan-dev@lfdr.de>; Wed, 16 Feb 2022 11:01:53 +0100 (CET)
Received: by mail-ot1-x33c.google.com with SMTP id v17-20020a9d6051000000b005acf76789e9sf1162483otj.1
        for <lists+kasan-dev@lfdr.de>; Wed, 16 Feb 2022 02:01:53 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1645005711; cv=pass;
        d=google.com; s=arc-20160816;
        b=Rc65Nn8axgW9qZG0k99G6TghxqtR5ELGA82HYVp4JztzHpYY+3P5AONenUan8geZvk
         dZXiV/VlAnaZdSzcwrYkDYhcrld8KrDN1puRAvGgMU73/JIRdHccYHDWyQNhQq4X2j8R
         MD0DGYYpIXVaDw8DpK7GEiNBaraA0x3iHB6TGydaL6tYWtagAIicslo6JqkIyHXJygIr
         07l6nfZgWh6Hhvw+THt8owdvMAkWyqeyIaf/F2gjgspvR71GcKiy0O9r5RL1vq8tpb9U
         z9mlUHuZAV6nJIGAVV3S9Dk/O4/dLMzyy4ztiM6OQwne7hBJlwET/pQWInb8STfq3j0D
         Pxrw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=dEqFQMA2XmVjzOt9KCs+otks7viDWs22Nik7k6F7Rt0=;
        b=UhCVYBVu22dZrcS8iIlvaWfCWGLIek2iNyfuhgPTfR3Tgh1qg+YgeCHMjiJ93aobIg
         qVCLqHlhY5/NdbN/qFoQTO0s2GkX6bopmb6N3n4TRo6coG8jtpZixTs5uQvx7sE2rY35
         yi+hRL2eoiGzxo9PHjmikbbJJ+5xgQF+O5mMezFAZxPUIHLZguZ44UtHxVsJ8OnBLNzQ
         +vtBPyTe7d0gLY+B0gzJuI0aZyAZhANU5CDwikovJJN/ahVxqQLWFTwttRxgO0en16yI
         qg8xhLsM8dcboetXtlbeaFyyUQmV2iq3v9vu5kO+Zjvxf+rqHh/aWNLcHqkHjYRAufX3
         TZXg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=UK52Qlty;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b2e as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=dEqFQMA2XmVjzOt9KCs+otks7viDWs22Nik7k6F7Rt0=;
        b=JgoMfpF5mhdTUWGJvZmkzaf34zjHwrpdqbsCFQUiZY7gjJJg7uRZWBE5JXafWl8r8T
         0f9m6GQaMDvQkmFRxu1jgfhTdx9DEvRbEk5OrAsGpTYCtSRyLfoi5oAF1bNTpvzzZyox
         hSZlrQavie+LNTh4ouX9e+VUPU6KsYMJpP4OI7oPqjeCfXU6QwWkuf5jWYFi1CVOVMBd
         NeB2F5pBX/PjsBGxPq8II1qqbX3lTi2p786rXTw1EvJlQBbsdut7CR7mnkHnKUppKYOS
         A2MfPEHLimsIdIrihvuxQvOhOjeXvwM7KsIzuqNZfoL3u7kKYnJR+dFxILlEcBWdHJWJ
         WY2w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=dEqFQMA2XmVjzOt9KCs+otks7viDWs22Nik7k6F7Rt0=;
        b=FGQZGNddf40i8viJF5MALkkHlwb2v3vrqTGji/6P0z60In40K0qgxgAme9FyfA/STm
         E6hGrlTNLWX1NrZ2h4Iy2W8AuNtuUC/MRP9DO4r/AAzHJ5aITi4j90+n9rO89HwEeLF/
         Nf+Kk8kcoz4ud8ANMoJr7zRthQqYJswcLnjBHXncj48MawbO+gJIKQKvf0jQVsqJURgo
         n9z0NsujFIn2a59jhXCJnehV0jSlWNoj9apoJfGkp5Jz6tIh1zExrASYfAN57e6/VeAQ
         lq8JTpuk2F2O4ZiWZKp5LE5BPIOD1+0F02uOvzKTGCEhoshNGHtpMCgFr2DvyOaHqV2t
         qosQ==
X-Gm-Message-State: AOAM533w/VWLofHC9ldUNJ4wLSnffYGlhpDERplfhka1VwC8LtaSSJzM
	uPQ/tdb+AaY9yqTg5Gd2zp0=
X-Google-Smtp-Source: ABdhPJzjNWAsZPrWNV27H4nhv5hRJadWyup/DFTfGuK3MvrPHvlAqe9zFWMb9sS1MExwzH8XC5/5xw==
X-Received: by 2002:a9d:445:0:b0:5a6:194f:9a7 with SMTP id 63-20020a9d0445000000b005a6194f09a7mr562795otc.212.1645005711223;
        Wed, 16 Feb 2022 02:01:51 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:c793:: with SMTP id dy19ls1385190oab.0.gmail; Wed,
 16 Feb 2022 02:01:50 -0800 (PST)
X-Received: by 2002:a05:6870:438e:b0:c5:9dff:3066 with SMTP id r14-20020a056870438e00b000c59dff3066mr210283oah.87.1645005710829;
        Wed, 16 Feb 2022 02:01:50 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1645005710; cv=none;
        d=google.com; s=arc-20160816;
        b=gZblA/CQ6+ktf7vxOidjYtcQKoBmSLcDxmwmDgEVtpmA67oBRsU6zW4Fpn5FD5xa7B
         kj+2ZJ7ghTdyOYI1bZZCIW9wv+sQkL4x5mB7y6+7NAvDFb7RB/hcPfdbhaRcSP84s0Fw
         Xu/z4nqmkBSGhAZbcloy9fZaG4WL/rtnOhhvJpabkaw0jcr0jxfuz8XTXdCt2fCMlwYl
         5P1GKgl+OmQHdA7EDBKDojiN0PYkBnqw9IFhR2JMuvEQgMWA/QGlPDFMuH8D/bHcB0Or
         yGUDm1EWETUT99krd/YvlYk49sccFgpEe/tqsyzXWnApEiy0N4xcANb0wdRyPxaDy1q5
         JWjg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=S6LWdrzCSVeHr2t82bSdnaI065vYCk5GbX/G1ZKc0RA=;
        b=iSOS1REyWtpjymycX8G+q1DLTXsme2ZvVwettbNiP5wpK15X3ueauW6HyPO0UUCMCK
         Tm4RLumG4oZGc5d9xH/HEkzslUT7hqOgCBg2AphAv6+a725mOnEfacYInjZlweG1D/b5
         L4ajBYttwplJnpwsC+jYuZOjDUsNz57ArtdSW/f+8yOV26gowSFdorwoN57MlhTgyZVm
         aYbv2eG0Qc04rEhWyumiYOFeTAy2kFON+cZ5oP9AdfKS0XhRicv8JyH/6sMVI01+C/4V
         AhhzOmFimWcpmUxlsNz/Fc/exzNkK8+2GZMBH4c5u75sKNH2TTT+H1ysAZVNMdRJuRW+
         TXUg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=UK52Qlty;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b2e as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb2e.google.com (mail-yb1-xb2e.google.com. [2607:f8b0:4864:20::b2e])
        by gmr-mx.google.com with ESMTPS id x31si182667ott.4.2022.02.16.02.01.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 16 Feb 2022 02:01:50 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b2e as permitted sender) client-ip=2607:f8b0:4864:20::b2e;
Received: by mail-yb1-xb2e.google.com with SMTP id j2so4586236ybu.0
        for <kasan-dev@googlegroups.com>; Wed, 16 Feb 2022 02:01:50 -0800 (PST)
X-Received: by 2002:a81:7943:0:b0:2d0:c8bb:a45d with SMTP id
 u64-20020a817943000000b002d0c8bba45dmr1600577ywc.264.1645005710386; Wed, 16
 Feb 2022 02:01:50 -0800 (PST)
MIME-Version: 1.0
References: <865c91ba49b90623ab50c7526b79ccb955f544f0.1644950160.git.andreyknvl@google.com>
In-Reply-To: <865c91ba49b90623ab50c7526b79ccb955f544f0.1644950160.git.andreyknvl@google.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 16 Feb 2022 11:01:39 +0100
Message-ID: <CANpmjNNtE9nYT-NKZpn3k2gwBUY_223mWOKZPgLyDQNzfygBTA@mail.gmail.com>
Subject: Re: [PATCH mm] fix for "kasan: improve vmalloc tests"
To: andrey.konovalov@linux.dev
Cc: Andrew Morton <akpm@linux-foundation.org>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, kasan-dev@googlegroups.com, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=UK52Qlty;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b2e as
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

On Tue, 15 Feb 2022 at 19:39, <andrey.konovalov@linux.dev> wrote:
>
> From: Andrey Konovalov <andreyknvl@google.com>
>
> vmap_tags() and vm_map_ram_tags() pass invalid page array size to
> vm_map_ram() and vm_unmap_ram(). It's supposed to be 1, but it's
> 1 << order == 2 currently.
>
> Remove order variable (it can only be 0 with the current code)
> and hardcode the number of pages in these tests.
>
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

Acked-by: Marco Elver <elver@google.com>


> ---
>  lib/test_kasan.c | 16 +++++++---------
>  1 file changed, 7 insertions(+), 9 deletions(-)
>
> diff --git a/lib/test_kasan.c b/lib/test_kasan.c
> index 491a82006f06..8416161d5177 100644
> --- a/lib/test_kasan.c
> +++ b/lib/test_kasan.c
> @@ -1149,7 +1149,6 @@ static void vmap_tags(struct kunit *test)
>  {
>         char *p_ptr, *v_ptr;
>         struct page *p_page, *v_page;
> -       size_t order = 1;
>
>         /*
>          * This test is specifically crafted for the software tag-based mode,
> @@ -1159,12 +1158,12 @@ static void vmap_tags(struct kunit *test)
>
>         KASAN_TEST_NEEDS_CONFIG_ON(test, CONFIG_KASAN_VMALLOC);
>
> -       p_page = alloc_pages(GFP_KERNEL, order);
> +       p_page = alloc_pages(GFP_KERNEL, 1);
>         KUNIT_ASSERT_NOT_ERR_OR_NULL(test, p_page);
>         p_ptr = page_address(p_page);
>         KUNIT_ASSERT_NOT_ERR_OR_NULL(test, p_ptr);
>
> -       v_ptr = vmap(&p_page, 1 << order, VM_MAP, PAGE_KERNEL);
> +       v_ptr = vmap(&p_page, 1, VM_MAP, PAGE_KERNEL);
>         KUNIT_ASSERT_NOT_ERR_OR_NULL(test, v_ptr);
>
>         /*
> @@ -1186,14 +1185,13 @@ static void vmap_tags(struct kunit *test)
>         KUNIT_EXPECT_PTR_EQ(test, p_page, v_page);
>
>         vunmap(v_ptr);
> -       free_pages((unsigned long)p_ptr, order);
> +       free_pages((unsigned long)p_ptr, 1);
>  }
>
>  static void vm_map_ram_tags(struct kunit *test)
>  {
>         char *p_ptr, *v_ptr;
>         struct page *page;
> -       size_t order = 1;
>
>         /*
>          * This test is specifically crafted for the software tag-based mode,
> @@ -1201,12 +1199,12 @@ static void vm_map_ram_tags(struct kunit *test)
>          */
>         KASAN_TEST_NEEDS_CONFIG_ON(test, CONFIG_KASAN_SW_TAGS);
>
> -       page = alloc_pages(GFP_KERNEL, order);
> +       page = alloc_pages(GFP_KERNEL, 1);
>         KUNIT_ASSERT_NOT_ERR_OR_NULL(test, page);
>         p_ptr = page_address(page);
>         KUNIT_ASSERT_NOT_ERR_OR_NULL(test, p_ptr);
>
> -       v_ptr = vm_map_ram(&page, 1 << order, -1);
> +       v_ptr = vm_map_ram(&page, 1, -1);
>         KUNIT_ASSERT_NOT_ERR_OR_NULL(test, v_ptr);
>
>         KUNIT_EXPECT_GE(test, (u8)get_tag(v_ptr), (u8)KASAN_TAG_MIN);
> @@ -1216,8 +1214,8 @@ static void vm_map_ram_tags(struct kunit *test)
>         *p_ptr = 0;
>         *v_ptr = 0;
>
> -       vm_unmap_ram(v_ptr, 1 << order);
> -       free_pages((unsigned long)p_ptr, order);
> +       vm_unmap_ram(v_ptr, 1);
> +       free_pages((unsigned long)p_ptr, 1);
>  }
>
>  static void vmalloc_percpu(struct kunit *test)
> --
> 2.25.1
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNNtE9nYT-NKZpn3k2gwBUY_223mWOKZPgLyDQNzfygBTA%40mail.gmail.com.
