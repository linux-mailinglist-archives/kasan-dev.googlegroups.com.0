Return-Path: <kasan-dev+bncBC7OBJGL2MHBBHNCWWIAMGQEKO4GRLQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x138.google.com (mail-il1-x138.google.com [IPv6:2607:f8b0:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id 55B204B912E
	for <lists+kasan-dev@lfdr.de>; Wed, 16 Feb 2022 20:31:43 +0100 (CET)
Received: by mail-il1-x138.google.com with SMTP id m3-20020a056e02158300b002b6e3d1f97csf468585ilu.19
        for <lists+kasan-dev@lfdr.de>; Wed, 16 Feb 2022 11:31:43 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1645039902; cv=pass;
        d=google.com; s=arc-20160816;
        b=jMX2Wg7JRJpMsv3MQuoM4Z4Fd3wslMa1WgnqImAzrHarSLSkcXg2UWrduj8ptx7Zkl
         JKsmukuWkCEX2lTeU8rk+ikM/BjqcNMFvmXFdGQzmaJjxlYO4ucSqImInhos5wtXdEGA
         hCKdVzQ7ZsQWR8po3Vje010n2ylxAO0dMUaLhCG9phw+cZ9VnZuG+OFxwIMyYDhHQZU0
         lOIqDtLLh95+vy1o/llYJ141FA3H2/8KgChBNf3pAZCCgY762C534bah+U6U/+KR0ctB
         DqE5lcdQ0JHYRPyOe6+ACmuENCWffUSSTrP+a+L/Lk+rV2ayR7L0QXREi/pv0yPGOXpa
         tjzg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=Bv3jn/FwYZN1E8tjrR359f+qXE5n+nU5gKE01nr/q68=;
        b=XcheC0k/XwUL2b5a3TgYxK4Ehn2kRh80IweNFL8NpDGGNIDizmYFkM+VfRDRiESIaC
         eQtFrXirnJntHhTxF2Zz4hcVk7cYsWfdsaDUYKW4I7L94C+iXiZHJ1HabdHJPrGQ+75L
         lR6gPftAxHZb+gfTmK1XT2sVk380u3ygTc+BQQeBPy2Zv5zdZpT6CrhEKAE48n2Kh8AU
         49ASqY7l7yl71ahfdt6tHe6EeYQwrQ04cYs9F6sw1Jg85u1kKFPuTrlf/AoBB226PQep
         hlmv1AR7o6Ium4DEsyYsfHzDuue5+58wRtU/2cEEXKCyRF1I+WnCFyfuhhOBhCQNsJMx
         IVXQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="qJ/yCvpE";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b36 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Bv3jn/FwYZN1E8tjrR359f+qXE5n+nU5gKE01nr/q68=;
        b=GrD8IOLPE0LQKyIILejDOrpRxQL6Yb+YcpskLrvghA/rTdly1eC+AkH9bwVkoi7Jcy
         AmfieyRaJLOjt7bKODO0Ly59sIkZN1eSf5ANAaD4pM26OzGAJNCtODuUdX8p3ZeV4pLJ
         JBHXP0JvZNybRqlc7Pw+IPsw96lg0jEbpFOt24nOK+l1Rf7//wWtovwYbrtpZPtTDUaO
         11PgmfGv4jMBwjp1g/cSzT2k7ikjlknbJe4HinnTO4X4AY9HcPB6NZeyUhUzvNs4Ciu3
         PciLkegvmDTN86WqI9y9YAz1rJiFZMn5t0Ru0rIBFbKovMDzwpZk3cqblPnFXjbbUa5A
         MTsA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Bv3jn/FwYZN1E8tjrR359f+qXE5n+nU5gKE01nr/q68=;
        b=0kq887wkup0oMXrzOOaQDQVNo35K3nmAeeCWr+Ryj7zMP2MS9Ggj448N2ECTRIuwL2
         9DOZiALdpCVfUsd5sbkQAL2o7RA65I07o4TLJvkKO8TBndE1YCIic4werpQCgzsS870A
         ZHJBofE2qTTeBzPOCOZm0K6HZEtzZX8bN8Le1uGKFpgI4UXUWUfJfcZF5cRxY52nioZu
         0UTI6Ej+xEflcgpoBPtl+STV9XqpTMUxr2s/NWFmHEXN1bJGeHy/ySA2fsrbTY0oer/k
         ET8gKcrMnXghcY3pgV31GUXKA397nBV1QjTcQn782lPwSjO9qNsLH16QW1pJzI5GvvfY
         q/fg==
X-Gm-Message-State: AOAM530ZRJ/6c20hXfGU8G6IyS67ezr8/NrNQgpDoii/60fkM+AiZFCC
	bYASKCtT45aByD85/OP0gaY=
X-Google-Smtp-Source: ABdhPJyaBAUzMpXqsjfVkNocpndzo3oxEpsR03ufwQGZF7VMgZEM1CIi4OBWJSk/7htxzZoamZ3sIw==
X-Received: by 2002:a05:6638:2656:b0:30d:23ec:fcbf with SMTP id n22-20020a056638265600b0030d23ecfcbfmr2795028jat.103.1645039901894;
        Wed, 16 Feb 2022 11:31:41 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6602:1581:b0:612:b2f1:ba8 with SMTP id
 e1-20020a056602158100b00612b2f10ba8ls73749iow.0.gmail; Wed, 16 Feb 2022
 11:31:41 -0800 (PST)
X-Received: by 2002:a5d:8d03:0:b0:612:608:9a67 with SMTP id p3-20020a5d8d03000000b0061206089a67mr2816524ioj.19.1645039901477;
        Wed, 16 Feb 2022 11:31:41 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1645039901; cv=none;
        d=google.com; s=arc-20160816;
        b=E644D00+ptg6OptJfIAg7m+m74i/u0P5b9E3+5Xrz8bgkAy9icG1Tf8XNuXwlGJNQo
         N3d9wB+wsyhFa0NzMxmmogYwZ0YEJjmQV0ERpmmhKrnH04AXLsw8L9DgV673FSj8Np2C
         HlKT6aNiRepSYPMANLISoJ4IoZgnhS1czIHl7gsfGeI5N6WlEUmSvLoT0/TfePGDKloo
         JePUhruLgfYZok/SuQfUdEdrKl9EHdhXC+IklYTvYVC1SWuBIXHNBwvHkdewugMrEdst
         EXB9qkMpm9qLPVvePtCJx3ju3vS8QYdiIwhISnj9a1dHcYKwjI2VefbZGCk20FpmSbIF
         7ndg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=dXrDCcliqXFznAwN9UKmpIFnfCTr0AltCrpKcHBOhyI=;
        b=TghSRskfSCVOeD/Ob/H12KMkFtz5qCVcNtuqC0NSpFbMqbFM8ljgz1nhHfdZ2YjC5q
         4zKkMexzWhX/lptiuPa7XylM5gHBWA4boRtWrYo8XYIPinumdhecAlvAM4ImBz9IPMI3
         Sip1U4VKVOzQzt/w1Ec6KVEbxolG8r/gFHNkJPkQMKAz8ZhIdu7mRy8xGtjihj78LBob
         9vftHQPF7iWoklub47JXZNozRZ8WmSiznFwDJd7Do9Hl65WIU7QuNbJXRQhDRPShEImX
         DO8UAoF9dHsRgP/HmaU886HKLg0oEF9AdmmGOUI0UjAixgCUuJeHZg7MPULmmohSJe0Z
         +64A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="qJ/yCvpE";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b36 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb36.google.com (mail-yb1-xb36.google.com. [2607:f8b0:4864:20::b36])
        by gmr-mx.google.com with ESMTPS id x11si3579834jas.5.2022.02.16.11.31.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 16 Feb 2022 11:31:41 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b36 as permitted sender) client-ip=2607:f8b0:4864:20::b36;
Received: by mail-yb1-xb36.google.com with SMTP id bt13so8339768ybb.2
        for <kasan-dev@googlegroups.com>; Wed, 16 Feb 2022 11:31:41 -0800 (PST)
X-Received: by 2002:a25:f441:0:b0:611:4f60:aab1 with SMTP id
 p1-20020a25f441000000b006114f60aab1mr3441157ybe.598.1645039900830; Wed, 16
 Feb 2022 11:31:40 -0800 (PST)
MIME-Version: 1.0
References: <5b120f7cadcc0e0d8d5f41fd0cff35981b3f7f3a.1645038022.git.andreyknvl@google.com>
In-Reply-To: <5b120f7cadcc0e0d8d5f41fd0cff35981b3f7f3a.1645038022.git.andreyknvl@google.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 16 Feb 2022 20:31:29 +0100
Message-ID: <CANpmjNP0QCMhSL+ePf5G8UwbmdjM-qpimAQbuQD+pYK8Gx+2Gw@mail.gmail.com>
Subject: Re: [PATCH mm] kasan: print virtual mapping info in reports
To: andrey.konovalov@linux.dev
Cc: Alexander Potapenko <glider@google.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, kasan-dev@googlegroups.com, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Catalin Marinas <catalin.marinas@arm.com>, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b="qJ/yCvpE";       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b36 as
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

On Wed, 16 Feb 2022 at 20:01, <andrey.konovalov@linux.dev> wrote:
>
> From: Andrey Konovalov <andreyknvl@google.com>
>
> Print virtual mapping range and its creator in reports affecting virtual
> mappings.
>
> Also get physical page pointer for such mappings, so page information
> gets printed as well.
>
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
>
> ---
>
> Note: no need to merge this patch into any of the KASAN vmalloc patches
> that are already in mm, better to keep it separate.
> ---
>  mm/kasan/report.c | 12 +++++++++++-
>  1 file changed, 11 insertions(+), 1 deletion(-)
>
> diff --git a/mm/kasan/report.c b/mm/kasan/report.c
> index 137c2c0b09db..8002fb3c417d 100644
> --- a/mm/kasan/report.c
> +++ b/mm/kasan/report.c
> @@ -260,8 +260,18 @@ static void print_address_description(void *addr, u8 tag)
>                 pr_err(" %pS\n", addr);
>         }
>
> +       if (is_vmalloc_addr(addr)) {
> +               struct vm_struct *va = find_vm_area(addr);
> +
> +               pr_err("The buggy address belongs to the virtual mapping at\n"
> +                      " [%px, %px) created by:\n"
> +                      " %pS\n", va->addr, va->addr + va->size, va->caller);

Can you show an example of what this looks like? It's not showing a
stack trace, so why not continue the line and just say "... created
by: %pS\n"

> +               page = vmalloc_to_page(page);
> +       }
> +
>         if (page) {
> -               pr_err("The buggy address belongs to the page:\n");
> +               pr_err("The buggy address belongs to the physical page:\n");
>                 dump_page(page, "kasan: bad access detected");
>         }
>
> --
> 2.25.1
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNP0QCMhSL%2BePf5G8UwbmdjM-qpimAQbuQD%2BpYK8Gx%2B2Gw%40mail.gmail.com.
