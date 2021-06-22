Return-Path: <kasan-dev+bncBDW2JDUY5AORBMGXY6DAMGQEXVF3S7A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23c.google.com (mail-lj1-x23c.google.com [IPv6:2a00:1450:4864:20::23c])
	by mail.lfdr.de (Postfix) with ESMTPS id 996B63B0640
	for <lists+kasan-dev@lfdr.de>; Tue, 22 Jun 2021 15:54:56 +0200 (CEST)
Received: by mail-lj1-x23c.google.com with SMTP id t1-20020a2e9d010000b02900f5b2b52da7sf10662500lji.8
        for <lists+kasan-dev@lfdr.de>; Tue, 22 Jun 2021 06:54:56 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1624370096; cv=pass;
        d=google.com; s=arc-20160816;
        b=bx89WOOZi56xEaDf/apskdMiRIFRzHZf1gUVDahAiERjTdwu2SXiBHSnRdiezluqM1
         OGb0432TZ3VILDDi/fSzBvKezaImR1wlNwlDnuG7D+TywL7YTAaapifXiJC6vCdQlJGW
         OtyOXxvTRE/kyaPdf+X1QPacwrcYU+7eFALW0HaKp1HkHGNLUbwiouv4yFjZxUX/l77i
         M/6yBaaGbKCIIB8Vzy3vWkahZamiLVwEoGmya+qGmFlNHCBPC9NddhExZB6sxIFYoOJq
         PLIC5GddVCJlddwAvF8FukRNLkP9CLIYvUJ5iuKW7ZPtT/vqhKWvVU6zHupZkhShQ9Lr
         AmzA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=Vg4QEYfASVZyavePOYobClipQoATCYLpEO8O66ZNk7M=;
        b=ZYTJCM7vjxvAEqJLtAqgN5ZXUV7CCGRxZM8g3S7dV8GBeZBIG3o1tFumMx1aogLPNK
         E0RDAlUO1mjlbRTfjdDpbVxXulQFdVV2q05a2UpFcUJe5t1xK4jHvWu2JuzrR2JE6/Dn
         pgUVGEyRSmCOsbFdYkPkNjo/Itlxa7FPAD6/WuX0VeVs2U0bNoZTAn1UyAIyCDlYHNqb
         HoPNalChfncd+YPvL1SaRL5miYNYoRcwaYNnvWH9BH0dtM+2haeU3Qu4HNL2XWL2ZhtH
         2hrWUQxe4lhsCnySEencZgMq05F9RdfMmQTCIvrGSBROKYj+3BQR4xGYtCMKZp6AVkl9
         LXRw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=Do7Q+4WV;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::52c as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Vg4QEYfASVZyavePOYobClipQoATCYLpEO8O66ZNk7M=;
        b=V43UbrYSVXxpmSVHLXQirpdK5Nv67O4bNGyUf3jTIgT2b56WcZOozjGntV+A/we4hP
         yNfxJBhokkbFqlQsRWSM6TWqpR5VnDNRcrRQopiIb+PNPuMPKRFsCU41An3URaMrQGuv
         rbIaxkJmMATfc6/mGcBTfWCAT9nLsp8FsP1GMH0tywcN5bFkLtG/jzLYdk26jBwA7xX3
         06m1Pr00CuLsWf1CcTw0CHfF3gMR5To6gPtxkVCN8ILRUhf3VJVmOB+udrudyKsKAyAk
         xK/GK97eKc5u1H5a3a9D/6MGozE6fUOVrRz/Z0oxr0PcXxfW6xQr35nArz2G2BDZMLyP
         B06w==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Vg4QEYfASVZyavePOYobClipQoATCYLpEO8O66ZNk7M=;
        b=VP2k24ZlsLLpvpPCqvnwd3qeSJjhYmqX8PMQiiADtkHP5I0cMYIGU8AYM0T4IL2cz9
         IB+6ffLX3RNPFYjzhK4RQXqmX1KqwJbbs9eWmgDdLGh0BZk0GtZsYEut4CvytK4h7TWx
         HBzV7CNLrRnBTnnQ9FBotq23VbOB5Srr/HpbWI8RAhUJxIlAhgv59lqp3MK26AH1k6nK
         8nrfVQRziXWud3ZGn/AWUwAKkxxj6DtCS46iQGupyEoPgLswbFAQoYsKQKSz7QYPnpEU
         oYUJEqGi2Y0lc3WCnwuFPwHGeefpbNPA/N7Z7W2a5uAnCA5zvdVbrD2/JeDKqCS3RIzL
         3KrA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Vg4QEYfASVZyavePOYobClipQoATCYLpEO8O66ZNk7M=;
        b=EtLXffRYmkj1qtdqFNWK4WBP3yIL8zBGXcnTHxikMngzwIX4cglLVFzl2cy9AQ1PX/
         oeNghuDuxPn8Jza49I9D+83XYzXBuF56c8FF64qMqO7TMxrLjPYovqsB217Gql0CANnn
         R+EMIvMUx9STFaKm6ZOrmqYmQ8hLhpvJlgNChAR0d8DypKI3082ges91bs/EJD227YzY
         GIIz4yQnYXUYU2lT5Ad/sxUcRjngxjwDkDRltaNuD7zvEZmqDZcxXZRusRVHm8EQb1PR
         nSXr+b7OeBY+/RnEbeEHAfDFBEv7dA3de5OQib3KDJ1glkS7z/hdzwfivIONNqtislER
         S0nA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531PoRVrnrchAUegg7U1l5G4i6sjBYZeD2laNDEP+lw1P3awOUOc
	6qXnBIBhTM5EusNOSJYxxzM=
X-Google-Smtp-Source: ABdhPJyKDa/vXBu3M56P7+b949mZVT/cZGLogMG/G9oWVPQcEZxUGe9JzTqQHf1zEmkYXoowZIuQ4Q==
X-Received: by 2002:a19:dc5e:: with SMTP id f30mr3053509lfj.318.1624370096222;
        Tue, 22 Jun 2021 06:54:56 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:bc1c:: with SMTP id b28ls1037412ljf.4.gmail; Tue, 22 Jun
 2021 06:54:55 -0700 (PDT)
X-Received: by 2002:a2e:7812:: with SMTP id t18mr3467840ljc.108.1624370095265;
        Tue, 22 Jun 2021 06:54:55 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1624370095; cv=none;
        d=google.com; s=arc-20160816;
        b=rWfnYdKw42vp34wXn6HHnKez0yANit4SgFrmnCTFHvoMeVm+hlaTc0KFvPbEIq39+v
         VxcmgAPdHCQ1XbrqV5DBAfG00k4XDkiVXgFw5WZ4W9F8cYvLWSl8NKe7K413qhutnZfQ
         osu/0PFQamOJGpg66OOsmqMV96QdpF3h1+tdAh9qbzNm/IQxYJiakrDyFJR80cLslYr6
         p1J2JA26PHMoOLiq4InMeWYZ+AnQiFsb+2wjw4XQXN3VxZlom1/hrJVtYYFsl6AtbchV
         cRbu8VZRnYC90T934JPbuXIlBa1ApEH+WoyMYeaad+1Rp5tpEMtJbLFi56alzQsQ6HbO
         rwWw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=P7b5G3A0+58gTpXa0/n5lleUJqlnrASAuqzNx+IB8OE=;
        b=Tp0Up9RaHRzM5qW0hWbJVTOeS9ZYSR45YjkU4gmlnbwDfxPaCxGVw5iCS5nVGGrgtQ
         daDhZjHEXOSeXDJzWhRTpz/ssCLK7EVf4hyDyDDrDXGM9Vu7OyX+kC22TO4kAp/8N8Zl
         mWE1kDJ+BmblWKBC2HjALu0KJj2J4IerTvnVsAREDFW2KfqQCYXz0v81mp8CJL+wv1r1
         sbpVY2zbA1uJVTZAasElH3TuxyZHrWuIk8hj5KrVyONNCJvJj3VxEraVWZA64/lxkk5S
         SVLsUvmM+kbN7W76Uroag/LPKXzWzgTaDB1YTvPm1Z2eeGXaY05vjjQuO+WjYi/hxXFF
         08+Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=Do7Q+4WV;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::52c as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-ed1-x52c.google.com (mail-ed1-x52c.google.com. [2a00:1450:4864:20::52c])
        by gmr-mx.google.com with ESMTPS id z16si114107lfq.13.2021.06.22.06.54.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 22 Jun 2021 06:54:55 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::52c as permitted sender) client-ip=2a00:1450:4864:20::52c;
Received: by mail-ed1-x52c.google.com with SMTP id n20so23782679edv.8
        for <kasan-dev@googlegroups.com>; Tue, 22 Jun 2021 06:54:55 -0700 (PDT)
X-Received: by 2002:a05:6402:1014:: with SMTP id c20mr5097086edu.70.1624370094862;
 Tue, 22 Jun 2021 06:54:54 -0700 (PDT)
MIME-Version: 1.0
References: <20210620114756.31304-1-Kuan-Ying.Lee@mediatek.com> <20210620114756.31304-3-Kuan-Ying.Lee@mediatek.com>
In-Reply-To: <20210620114756.31304-3-Kuan-Ying.Lee@mediatek.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Tue, 22 Jun 2021 16:54:34 +0300
Message-ID: <CA+fCnZdGQ-_USQ_dCkmp+=MGS01yRtn1eLpGRLvbq=j-SQDrog@mail.gmail.com>
Subject: Re: [PATCH v3 2/3] kasan: integrate the common part of two KASAN
 tag-based modes
To: Kuan-Ying Lee <Kuan-Ying.Lee@mediatek.com>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Matthias Brugger <matthias.bgg@gmail.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, LKML <linux-kernel@vger.kernel.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	linux-mediatek@lists.infradead.org, wsd_upstream@mediatek.com, 
	chinwen.chang@mediatek.com, nicholas.tang@mediatek.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=Do7Q+4WV;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::52c
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Sun, Jun 20, 2021 at 2:48 PM Kuan-Ying Lee
<Kuan-Ying.Lee@mediatek.com> wrote:
>
> 1. Move kasan_get_free_track() and kasan_set_free_info()
>    into tags.c

Please mention that the patch doesn't only move but also combines
these functions for SW_TAGS and HW_TAGS modes.

> --- /dev/null
> +++ b/mm/kasan/report_tags.h
> @@ -0,0 +1,55 @@
> +/* SPDX-License-Identifier: GPL-2.0 */
> +/*
> + * Copyright (c) 2014 Samsung Electronics Co., Ltd.
> + * Copyright (c) 2020 Google, Inc.
> + */
> +#ifndef __MM_KASAN_REPORT_TAGS_H
> +#define __MM_KASAN_REPORT_TAGS_H
> +
> +#include "kasan.h"
> +#include "../slab.h"
> +
> +const char *kasan_get_bug_type(struct kasan_access_info *info)

As mentioned by Alex, don't put this implementation into a header. Put
it into report_tags.c. The declaration is already in kasan.h.


> +{
> +#ifdef CONFIG_KASAN_TAGS_IDENTIFY
> +       struct kasan_alloc_meta *alloc_meta;
> +       struct kmem_cache *cache;
> +       struct page *page;
> +       const void *addr;
> +       void *object;
> +       u8 tag;
> +       int i;
> +
> +       tag = get_tag(info->access_addr);
> +       addr = kasan_reset_tag(info->access_addr);
> +       page = kasan_addr_to_page(addr);
> +       if (page && PageSlab(page)) {
> +               cache = page->slab_cache;
> +               object = nearest_obj(cache, page, (void *)addr);
> +               alloc_meta = kasan_get_alloc_meta(cache, object);
> +
> +               if (alloc_meta) {
> +                       for (i = 0; i < KASAN_NR_FREE_STACKS; i++) {
> +                               if (alloc_meta->free_pointer_tag[i] == tag)
> +                                       return "use-after-free";
> +                       }
> +               }
> +               return "out-of-bounds";
> +       }
> +#endif
> +
> +       /*
> +        * If access_size is a negative number, then it has reason to be
> +        * defined as out-of-bounds bug type.
> +        *
> +        * Casting negative numbers to size_t would indeed turn up as
> +        * a large size_t and its value will be larger than ULONG_MAX/2,
> +        * so that this can qualify as out-of-bounds.
> +        */
> +       if (info->access_addr + info->access_size < info->access_addr)
> +               return "out-of-bounds";
> +
> +       return "invalid-access";
> +}

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZdGQ-_USQ_dCkmp%2B%3DMGS01yRtn1eLpGRLvbq%3Dj-SQDrog%40mail.gmail.com.
