Return-Path: <kasan-dev+bncBCCMH5WKTMGRBG4CR6UQMGQEEI5PSAA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf37.google.com (mail-qv1-xf37.google.com [IPv6:2607:f8b0:4864:20::f37])
	by mail.lfdr.de (Postfix) with ESMTPS id 59C017BD5FB
	for <lists+kasan-dev@lfdr.de>; Mon,  9 Oct 2023 11:00:12 +0200 (CEST)
Received: by mail-qv1-xf37.google.com with SMTP id 6a1803df08f44-65d3df97d7fsf43784066d6.3
        for <lists+kasan-dev@lfdr.de>; Mon, 09 Oct 2023 02:00:12 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1696842011; cv=pass;
        d=google.com; s=arc-20160816;
        b=bUjv8hkv7zXz3xI/AFBqKycotbKs/sI7Ahg8N0OTlpkHEyuZ218ddkjoB6Uu0HwffO
         b94IvRhUMIrz+0BwYZlBgkT8wc9IWS0biBCPZcCqZp5GwPtUszfNGwcWj7XZB4rav/r9
         1mMFRD9hBBeQtSBvK3CnKLKvvJyzuA8K4uAyky34U5pqut9nK41DpAA7wfyXXTjNt10D
         B5tutYZCcUfpWfJerbnKXuHdRIJB6cqVdAr8o/iPAAwC4leWv8tVr0Y0d/j5+Krnb8+l
         QzcBFym6CGYnaWIDeUJhHpSQa/Y1MwgjCEJiaVU0teP/19iBY5QmeGOhWAHupdmijDQW
         ceSA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=NWbPPFwMA5jfVQDku/mxAgmJnwoPa0lJ8FGI/QqZyOo=;
        fh=D7uhrQnmQG6xf11gbvfi3iQ1A4p/6GZN4OQA8frEvwo=;
        b=HMgj3SkJISwjJww0FlnnHJZlfS+C51kaec+ud6hf+V1haHuS1She0ditaYzH/RINhq
         V6gVpvEZrYoYCMNz841kyYvbytKqz7GmHN7U59Nc4c6Y1U1EBpz+jsZuxCTHp/+n+zvQ
         zwArg39LTuK9c3WDGI+8C/4ikaSZ/3/NHooHA/Swt8eNRJiIDTEYZbngbVBwgObZkMp1
         JbDT1xZDQDsCM/k1oJ7AY3wg/ymbIvrdFtrMb8L9pOTc+p+nFMk4rjQyuiE5JyztJpOv
         bHQ0NubQBdiUnzIJOGEq++LzOChQ7f9JQ4QYzujoWkbr8zhbabZDGWcdzNip++lbrsHA
         9MyQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=gwjo2Q4u;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f32 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1696842011; x=1697446811; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=NWbPPFwMA5jfVQDku/mxAgmJnwoPa0lJ8FGI/QqZyOo=;
        b=QSxhUGq6HlUsnR1OrlA5Ek3goRPue3PaF61LPhjD15XbvLr4xsq36DDU3DuIqfjpks
         ZfmOj+XohzF++A0P8IvP0KfkHxsK8eMYUsBN3UOgjZyqHTOr42OjdrQVT18jy1MItnbJ
         DVRerBjfdStMinlhTb3jiZ56cJlt16GqaQa6/Vg23Tw3/z9SN1CXuPli4+vItd/S7ip/
         /VTHKj5YUql5Fbypo5586oWO4zOPAj9S7FlZiRs6BB0yvrVnCE3iVeHBp8adO3ZnnEij
         UauS0TEDvvIoLk4b7N+w73+fskXljjvIyl/xx2QT3YkD41rR0ApqcjyGsH9Kgvz3BBXx
         UPrA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1696842011; x=1697446811;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=NWbPPFwMA5jfVQDku/mxAgmJnwoPa0lJ8FGI/QqZyOo=;
        b=TH/Qt7Mecyjf0KWayAi2k+SaIL/QFG8ryqO6ePj1TE8HnWJXcl4eA9ZC2WCJIM3srb
         5hG5xT9fv1gQ7ZxS4XD11dL1wsZxoz08W58vgY3hS65uTxcwQWCC9H8aYMibHqnlVUqj
         tCvZIKDM3xHrzhHm/n22mGp0HS3wfHM/sPp9VgfuEbY4EgUYGCJ2WUMVTSasdb6Pv2b1
         w/qVR0qiFUrSQUBlA9zwRIw8bnJ3/y2axFu5bwiXPs4hw1CxuFPP4Ai8VHVoJ8fxPY7n
         Nc1I3WSroJhIQyYhzKLFDP25V1BouCX3ZTOhW86ed3inSbdupbRlrzLgCkKVBAkZRaXe
         pcHw==
X-Gm-Message-State: AOJu0Yz0Gh1+mNg11eL5T5WOCwU5CeO6XSmNWE1GgV3bKsVvcZQGd3TK
	5FHffCKRipXzc2RNSuOWJMQ=
X-Google-Smtp-Source: AGHT+IEm01NpHLRlOELVKoZKbhMMh3Pxd7oWukOuPk1AjMs0xkywwuzETs8Ed0V3uByBv74MmYhWZA==
X-Received: by 2002:ad4:41cf:0:b0:658:1ca4:97f7 with SMTP id a15-20020ad441cf000000b006581ca497f7mr13715203qvq.34.1696842011213;
        Mon, 09 Oct 2023 02:00:11 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0c:f594:0:b0:646:f0a7:568f with SMTP id k20-20020a0cf594000000b00646f0a7568fls2065256qvm.1.-pod-prod-08-us;
 Mon, 09 Oct 2023 02:00:10 -0700 (PDT)
X-Received: by 2002:a67:ec52:0:b0:452:85d6:16fc with SMTP id z18-20020a67ec52000000b0045285d616fcmr10262647vso.26.1696842010550;
        Mon, 09 Oct 2023 02:00:10 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1696842010; cv=none;
        d=google.com; s=arc-20160816;
        b=z+x6MjK4GoBMxJWMBdm66ujioWEp0JMWmBAhO5sKGmPPYQ6UH0C1z66+PWqMSx5fAh
         1pDHVnnpCV6qXNeTlTTeVrF5/UB5zz9dWkVBUA6aKGTxgjaK48sD3QfnQt/Un1qlwadE
         Sn+EASJi6zS1o/InrQ+YteN6JugKsvy5mxNBLRossui/ZWZixtMCzakuqhUAsyLkwVs5
         UXic9IXWfMWdc6OEq2eZygOxEngHyBOlyr9peaKImGUuO6kFbfphZ9re4diptWrcIhHg
         2Bj+YjWGXcZH9J4DB3EikeKviVe3AhEEuwOfub/AO0IeDBZccU6JOU/jjZe3xR/PpbAH
         wvIA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=8StrU8p4Asv0JzFS3HoyE3rwHET/Hez/P+/rBmMaFtk=;
        fh=D7uhrQnmQG6xf11gbvfi3iQ1A4p/6GZN4OQA8frEvwo=;
        b=aT2u6KvN/kTMN/P9TfK7wwOBAxbgm9n2KTrp1Qrh0ZFWfG0fWRqwqMlid3cpFMkIUe
         1viOUrtJcJRtLBT3RP2YfibTXJL5ZzL2EHO4YroUebNbMxMVJ1oQI3tRRuLZD/dPub1J
         nzPHyqlB/w5K9AbOadwy7KdmHeX21SLNQ0ynq2Xa2kxPDy9Y4WyX4SoMTykWdw9fPJwl
         t/YeNgKGpA9sv09mbJ36C8/RwwjYjhqRQg7QeKCEqVXvhZFWsJRGXwMOmG0y/+GN/4Cf
         4Rv4h1mU+gbujoBYHVpTEllvcq9Cm7+JBc2C2qdCJmfKfmMGlJizLB0/ZY3No8O/1jTB
         IYpA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=gwjo2Q4u;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f32 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf32.google.com (mail-qv1-xf32.google.com. [2607:f8b0:4864:20::f32])
        by gmr-mx.google.com with ESMTPS id d17-20020a056102149100b0045258d13d6esi1644604vsv.2.2023.10.09.02.00.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 09 Oct 2023 02:00:10 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f32 as permitted sender) client-ip=2607:f8b0:4864:20::f32;
Received: by mail-qv1-xf32.google.com with SMTP id 6a1803df08f44-65d04a45497so23014306d6.0
        for <kasan-dev@googlegroups.com>; Mon, 09 Oct 2023 02:00:10 -0700 (PDT)
X-Received: by 2002:ad4:4450:0:b0:65d:56c:5177 with SMTP id
 l16-20020ad44450000000b0065d056c5177mr13158908qvt.57.1696842010047; Mon, 09
 Oct 2023 02:00:10 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1694625260.git.andreyknvl@google.com> <bbf482643e882f9f870d80cb35342c61955ea291.1694625260.git.andreyknvl@google.com>
In-Reply-To: <bbf482643e882f9f870d80cb35342c61955ea291.1694625260.git.andreyknvl@google.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 9 Oct 2023 10:59:30 +0200
Message-ID: <CAG_fn=VspORKG5+xdkmnULq3C64mWCb-XGDvnV9htayf5CL-PQ@mail.gmail.com>
Subject: Re: [PATCH v2 07/19] lib/stackdepot: rework helpers for depot_alloc_stack
To: andrey.konovalov@linux.dev
Cc: Marco Elver <elver@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com, 
	Evgenii Stepanov <eugenis@google.com>, Oscar Salvador <osalvador@suse.de>, 
	Andrew Morton <akpm@linux-foundation.org>, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=gwjo2Q4u;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f32 as
 permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

On Wed, Sep 13, 2023 at 7:15=E2=80=AFPM <andrey.konovalov@linux.dev> wrote:
>
> From: Andrey Konovalov <andreyknvl@google.com>
>
> Split code in depot_alloc_stack and depot_init_pool into 3 functions:
>
> 1. depot_keep_next_pool that keeps preallocated memory for the next pool
>    if required.
>
> 2. depot_update_pools that moves on to the next pool if there's no space
>    left in the current pool, uses preallocated memory for the new current
>    pool if required, and calls depot_keep_next_pool otherwise.
>
> 3. depot_alloc_stack that calls depot_update_pools and then allocates
>    a stack record as before.
>
> This makes it somewhat easier to follow the logic of depot_alloc_stack
> and also serves as a preparation for implementing the eviction of stack
> records from the stack depot.
>
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Reviewed-by: Alexander Potapenko <glider@google.com>


> +static void depot_keep_next_pool(void **prealloc)
>  {
>         /*
> -        * If the next pool is already initialized or the maximum number =
of
> +        * If the next pool is already saved or the maximum number of
>          * pools is reached, do not use the preallocated memory.
>          */
>         if (!next_pool_required)
It's not mentioned at the top of the file that next_pool_required is
protected by pool_lock, but it is, correct?
Can you please update the comment to reflect that?


> +
> +       /*
> +        * At this point, either the next pool is kept or the maximum
> +        * number of pools is reached. In either case, take note that
> +        * keeping another pool is not required.
> +        * smp_store_release pairs with smp_load_acquire in stack_depot_s=
ave.

As I wrote in the other patch review, I think we'd better keep
parentheses at the end of the function names in the comments (unless
there's a style guide telling us not to).

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG_fn%3DVspORKG5%2BxdkmnULq3C64mWCb-XGDvnV9htayf5CL-PQ%40mail.gm=
ail.com.
