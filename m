Return-Path: <kasan-dev+bncBC7OBJGL2MHBB7WNWGKQMGQEZHBM5XY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73f.google.com (mail-qk1-x73f.google.com [IPv6:2607:f8b0:4864:20::73f])
	by mail.lfdr.de (Postfix) with ESMTPS id 4559154F6C1
	for <lists+kasan-dev@lfdr.de>; Fri, 17 Jun 2022 13:35:27 +0200 (CEST)
Received: by mail-qk1-x73f.google.com with SMTP id k188-20020a37a1c5000000b006a6c4ce2623sf4711474qke.6
        for <lists+kasan-dev@lfdr.de>; Fri, 17 Jun 2022 04:35:27 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1655465726; cv=pass;
        d=google.com; s=arc-20160816;
        b=qRvZccDpqBy72V4O+YC4tf162DR52/DwRlIxaEXmxTYS6xvJ4Y+6LIVAbDAtGZnTEc
         8TvkpYfG6yMbWnmrBFYy5doxw8V0otGwBdAHJd+/29zfWrGemyFhdc7CUQMBTI+UQjvO
         35UGoTHbH50lz+2scacuTZ9UYu+VbJX0OCO1B7HpytDJiFLoVA3U7ilKmBhycVWQ2nE4
         3dTT++nuiYQttA1TNRp7lCiYL2cJ5ejabwDVj+H2G0YvOk1S1Y3V6JEhKF8DBY4WyDUi
         VCnea29B1eOw1/YkW7fqeRRKvREwnjcW4lj7App3p/cFOiFl08P8AqLLI4Z99vEp+9cU
         ZdVg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=QXrx0aWmucJT4BosZrCY1hIGePnRyGcykwOwXvcWUnA=;
        b=XcXD8n1m3uei89s36/e4I9b9kr81jo24sYKrCuK0qBfJ471D/ak+NxGEY524dPwwxC
         Iur+wxfFPiUGqohGPoXTbNZOXiYrTli0ttVoxzTSvNOz3kj6kreox+d3wR4209pU5EpE
         gBp1CkwPBLfXlmmEn6i1ccMO90XSo7Pq6qTP5w1lg6/dzhkdOS5F8oam/PsZE34+sGyc
         U4rsfY9G+uxOnh43l3FnrIAOZtVGdi86uLVC9WZ90jzYkbp/5DW9E2ipSqUOcsEfruUP
         MldyQely8deoUEO4vlFPqtz5BBOOj7u2Zgvln5tJnTK1jYr9HDKk9Hq33vJc7yiFaivU
         Y6ag==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=PENmBcxu;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1134 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=QXrx0aWmucJT4BosZrCY1hIGePnRyGcykwOwXvcWUnA=;
        b=SbwaxOCGwUa6wS1c0vjEjf1EZ3RXBfp8yf05PWAl4N4WgHSMR7XpmDwRAkisPaCX+E
         HSTjjSH3DZlpGXglAol+UdPNXT5ZgxTgUsSBiBjI8DGIMH1iFFUmIN7+7h/SNSzdhIgR
         pVzn59Fu/NpK/UW6NKtKj6m4wIE0bHpSa4zsFAeo3Y8AMFADFcsRQ/ya1LfndY2zRDND
         qyF7Ga/rqC5oZMJ0j6gesfUDIoqS6UDykIHUtYXUNtt4UESPUyPwlnHgfuLgEjzo/iQK
         11G3kbaYSjCuAaSOSzv9zOb4P7gSdR/pOCkZjEojGJtK+Surd8SXhk7rQBANit4ju/Yw
         idqw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=QXrx0aWmucJT4BosZrCY1hIGePnRyGcykwOwXvcWUnA=;
        b=vc96CpG1NYgzAbDgCt7a1WkE9pSCuxkAM0yFGnfaXao4cI+2LjdH6Nh5ngo5OZovsc
         ndTrI9Ke0zXkjHtGviljKuavnAtOZqYy03cpToqQUl3qRT8NDeuLDt2ysdjF5pxFoolp
         xT5uSWvSYYxy2DLGPTXCW05uaGiSq0XnwSVaLwwnZyE/fIywAfge1HqqAo6bKArzUJ34
         rVH3CsJhVD3CEOB2ns7zk8mUdGJO+4oIeuodNGeFKCIfcUUQ3xSFWmbQHxjSxQi7os3Q
         udB0ZGiHTEHu000l5mUg3J5aijCblGbtOTRQF3p0IDI0Z/AoR587fZI7B7/goUBuQTFX
         YV3Q==
X-Gm-Message-State: AJIora9DtpMaaclHx0ZHZ4gfdkj6qJbszEbaqGWMgZT5vP5WnKVOppor
	nkoMFlpCzIFVayVlUsXHSCA=
X-Google-Smtp-Source: AGRyM1vNeHt5mETp9OzN+5QiEkbItoK+0uAoJN0ZNXQ0hvaotEJ/1TpQbBG9phvwkA9qrxVnc6nY1A==
X-Received: by 2002:a05:620a:4720:b0:6a7:181a:f51f with SMTP id bs32-20020a05620a472000b006a7181af51fmr6527195qkb.357.1655465726290;
        Fri, 17 Jun 2022 04:35:26 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0c:d648:0:b0:46d:80ee:d34c with SMTP id e8-20020a0cd648000000b0046d80eed34cls2111288qvj.8.gmail;
 Fri, 17 Jun 2022 04:35:25 -0700 (PDT)
X-Received: by 2002:a05:6214:508b:b0:467:de79:4f7d with SMTP id kk11-20020a056214508b00b00467de794f7dmr7636595qvb.101.1655465725709;
        Fri, 17 Jun 2022 04:35:25 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1655465725; cv=none;
        d=google.com; s=arc-20160816;
        b=PnC8XPOmNOnjGlqHXs7QlwZaoCoXAPWJt3i5FEoQG1c/4U+xnYoewsxYh7edfauC0Q
         aDmKpUyLb9QzCsW3LV0xeuIaKAuS1C4jjlc88MoRbYYAckhPHUset5JJgfbYUSQqAimo
         3ytMxNkaHbIvFS9I6VwUTQt5mr+iRq+I0B7507RbXTWrZt4qUj9cvMFpLOYCsIih0Qtg
         JFsg+oE6O0j/QzqNAicfNXUqInsreFQx+zAymvpprzkI881ZbBEGKZLYpqw6D9GVxfUj
         2ESe/A/7ws/JqSOrd919q6U7MWEhsrR2qQIO8lN/z2uFkrbXuS+Aw7z/R3qCP99CxpV5
         uVew==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=x5bwvKPWoiAdNfsl0rpPiOJbLUCKa6eFsFkR7Dl/GBw=;
        b=fkAroPgiJA4HDC3ulgp1pCTVOgHdEX8XMCCpINXw1+U4E/eEDr/YLEgpq4o4eNAyL9
         4HumcYukXCdsKTcMj4LPqMxEHe104tDFyOfn52RAlHr6mfD4JPrOPXx2MWNZXYtk+z99
         +jgm9ySYP919CkTr9sTwOZYc71e3ltY7H0RcCr9GmHa3ET34f26JONUmfm7TJzlVe7Ep
         OZ+nkiOhrRvSBNzsl96KP8AdhW0Dhb/bOoYwjLT/MCN56KWNDK/AS5DOD2D6fTVHgcX7
         EjJjwoBOzyRKTmcrtdgU6yXQdzCFDW9htiICFik5HB5M4tiUn4K4kDRdU8FTKnNjnpGI
         +epA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=PENmBcxu;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1134 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x1134.google.com (mail-yw1-x1134.google.com. [2607:f8b0:4864:20::1134])
        by gmr-mx.google.com with ESMTPS id a11-20020ac84d8b000000b00307ca319443si96384qtw.0.2022.06.17.04.35.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 17 Jun 2022 04:35:25 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1134 as permitted sender) client-ip=2607:f8b0:4864:20::1134;
Received: by mail-yw1-x1134.google.com with SMTP id 00721157ae682-3176b6ed923so39349037b3.11
        for <kasan-dev@googlegroups.com>; Fri, 17 Jun 2022 04:35:25 -0700 (PDT)
X-Received: by 2002:a81:18c1:0:b0:317:648e:eec8 with SMTP id
 184-20020a8118c1000000b00317648eeec8mr10552299ywy.327.1655465725193; Fri, 17
 Jun 2022 04:35:25 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1655150842.git.andreyknvl@google.com> <11a7bfb5ed5de141b50db8c08e9c6ad37ef3febc.1655150842.git.andreyknvl@google.com>
In-Reply-To: <11a7bfb5ed5de141b50db8c08e9c6ad37ef3febc.1655150842.git.andreyknvl@google.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 17 Jun 2022 13:34:49 +0200
Message-ID: <CANpmjNMTb4cxizfb5Xzy979jCA2_BMio6W4k1wZivKnu77RKVw@mail.gmail.com>
Subject: Re: [PATCH 06/32] kasan: introduce kasan_print_aux_stacks
To: andrey.konovalov@linux.dev
Cc: Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, kasan-dev@googlegroups.com, 
	Peter Collingbourne <pcc@google.com>, Evgenii Stepanov <eugenis@google.com>, Florian Mayer <fmayer@google.com>, 
	Andrew Morton <akpm@linux-foundation.org>, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=PENmBcxu;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1134 as
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

On Mon, 13 Jun 2022 at 22:16, <andrey.konovalov@linux.dev> wrote:
>
> From: Andrey Konovalov <andreyknvl@google.com>
>
> Add a kasan_print_aux_stacks() helper that prints the auxiliary stack
> traces for the Generic mode.
>
> This change hides references to alloc_meta from the common reporting code.
> This is desired as only the Generic mode will be using per-object metadata
> after this series.
>
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> ---
>  mm/kasan/kasan.h          |  6 ++++++
>  mm/kasan/report.c         | 15 +--------------
>  mm/kasan/report_generic.c | 20 ++++++++++++++++++++
>  3 files changed, 27 insertions(+), 14 deletions(-)
>
> diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
> index aa6b43936f8d..bcea5ed15631 100644
> --- a/mm/kasan/kasan.h
> +++ b/mm/kasan/kasan.h
> @@ -265,6 +265,12 @@ void kasan_print_address_stack_frame(const void *addr);
>  static inline void kasan_print_address_stack_frame(const void *addr) { }
>  #endif
>
> +#ifdef CONFIG_KASAN_GENERIC
> +void kasan_print_aux_stacks(struct kmem_cache *cache, const void *object);
> +#else
> +static inline void kasan_print_aux_stacks(struct kmem_cache *cache, const void *object) { }
> +#endif

Why not put this into one of the existing "#ifdef
CONFIG_KASAN_GENERIC" blocks? There are several; probably the one 10
lines down might be ok?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNMTb4cxizfb5Xzy979jCA2_BMio6W4k1wZivKnu77RKVw%40mail.gmail.com.
