Return-Path: <kasan-dev+bncBDW2JDUY5AORBHXQRCKQMGQEY5QNZEA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83c.google.com (mail-qt1-x83c.google.com [IPv6:2607:f8b0:4864:20::83c])
	by mail.lfdr.de (Postfix) with ESMTPS id AF7E15453CF
	for <lists+kasan-dev@lfdr.de>; Thu,  9 Jun 2022 20:12:48 +0200 (CEST)
Received: by mail-qt1-x83c.google.com with SMTP id s9-20020a05622a178900b00304e6d79297sf12010569qtk.23
        for <lists+kasan-dev@lfdr.de>; Thu, 09 Jun 2022 11:12:48 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1654798367; cv=pass;
        d=google.com; s=arc-20160816;
        b=Qun8Gv26MnMVJjM+pZaYNMdZS43WYhSN9vje9kJVKXU0RMoUZ1nE+9XBd/tgVXHEaV
         PvF3RI/rg3R0pq+jC70K6YwyFkyy8tKVRTverSBABbvBBbXXmpds2RrtqqewDJlHpU39
         +5XFa2222VbaZxggFCfsbfRErdxLSoYm960AcSHDrNOjg2Gi0yxL1cAGcuuMjB4Kasqu
         ZDxkUVBAoSUL7E4KHxAh1pyIxsYbGQySlTFoFXPuzuoC8D1rTK8hYau0fkzTxHXhq6T8
         oR4bHQax1Vza3J9QR0VCQVJ58/aSYqTkBKURuqZvDIeF3YWe4YnnxdRLsgnZ1rgaQHkB
         VHCg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=y4A31XF5QMl5eN2rK7QSYTgwPl8lVY/uu1CAIjn5LoM=;
        b=SS1t0YH521i2lS6jV2VyKtqzJ6SZuKZWr9doRFR5hd8+r4l9JW1WgcFK5VcuyQEv9b
         eYmxmBzEFtkamjL3UKHpGisin35R5/VlRQ0DMRUnqbmC6qjPUZ2LzdXJgrnABeysC14a
         r2Ukfe2d1nCm7Dk1Wry+EMTaG/+PXsLErE9e8UE4aqavmgAAH2Pwewj88FvX6E4Wi14d
         aouMB+bPpi7mwuLn99poV8+zhwiQERqHlKQZPcMHz1dXu8J1sytj7UAsJgnXYkQ6MMc+
         EMMq5Nu07HEX1YXS1xx4snqvm63AL606XS0sKm7a4XLZXS3PyXenWxiPptGRs1gc69yY
         8BIg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=RWIKj3WM;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::136 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=y4A31XF5QMl5eN2rK7QSYTgwPl8lVY/uu1CAIjn5LoM=;
        b=nwwJr5+xrS0B2vXpxEpeUKUsMMKHcC4dzHQ5EJXeXb9dQ62/V/BqfFdy6I8n14vsEB
         ATexwDKKEOL8W2SpxwKOV8RM1465ehw0fZwhtJmLw66Kz25k8vW8FmudH0tD2IbRk6XR
         F3a6aC5Ll8ubFyoZT2w9+jdEglnu4fgT9AjO8Ql5O6WTfqAcptdNdjfXSv/o7n7F5uHl
         5hL5ZFxF5OXPY0jnjKLHSgS/VcTHjcz0EvnY8BS7ICYtIFJDVxu6kXc7fD1MwLrhY2Ej
         ucxF4aTJ8S2jc/SNH9Ed2vQbe+1a7nRVS2VCweh6qL4BH7tH4uXwy1nJx7oKOkJZzNl3
         nc3g==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=y4A31XF5QMl5eN2rK7QSYTgwPl8lVY/uu1CAIjn5LoM=;
        b=Iqe8kl5XpbBQVcq5Sd99FYGW9+Db1C+pltdF4mvz+T8rJhl+IPyg39Dj631m1X8+Mg
         ih8JCY8cragGosXJvgC3EGdTIrjPVzEbRJtWSmuzzGYbOTiHSt+NavrHsTEbpcVs7O/J
         c5O+5sVtp/M5saOHA07mpnxmqLTBoti60RsVw/Mv3bu/QmShVbg0Bl6vdrR+DOe2FjrK
         5FY8eOqs9oouGbyBqwcgsSd8LYpmvvwrDytqPscJ9DRf0sEodtCBlcwxriA1kTCSZaIK
         aHDioRErTTz7O2eeyL+ykgPJ9sJltRxMEK3Ws+Cpb7kVYXvWKJcmnFHHBI1IfYKZOxhK
         dv8g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=y4A31XF5QMl5eN2rK7QSYTgwPl8lVY/uu1CAIjn5LoM=;
        b=WFn0YsW6vOpPl+WeZhCAqamZsxuAnqfvuylWgmBl1jRPAo3ijmp/LG6sPYOYQLgSIh
         J/QdtJCzybL/1Fsauu1swwXASzTfS1WKM9aM2JEIOXVgm97duVITdo5rYd+nJ+kqBGaB
         m19BlaT9GMEB7QHQD7oQ0Py6ClV5FbByi6I1W5sK5YENbQtbrkFn5P6zyiR3FBYeZ8yl
         2ZoP9+8PuzeoUuCXoNkDuZfZgdwXhAdbsio3igufgIIUDL3/r7Sy0hUS6vtCYkFZp3Ju
         EM5c+el4tkUTqtgcovq3MdSJcSvbR/p7rN4UaXxtYr2hgPD8iZulaIz01IAaUIQKAn2w
         q/ig==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530D9iDyprT1qZRD3X3HxJMnh6YNz6SMADeFCmHzkn9uU0ii8xks
	XaUjOwZWfXXhGWuSdfkYCh0=
X-Google-Smtp-Source: ABdhPJyO9aL2I41/4XHSWxnJnuHvCKzvoABfj7CNTihSZ8B+K2zZ1QY0nt5h2MvHW/fQz6wT6gGG/Q==
X-Received: by 2002:ad4:5d6d:0:b0:467:cb03:965e with SMTP id fn13-20020ad45d6d000000b00467cb03965emr29642278qvb.128.1654798366999;
        Thu, 09 Jun 2022 11:12:46 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:620a:29d3:b0:6a6:b273:4055 with SMTP id
 s19-20020a05620a29d300b006a6b2734055ls7248443qkp.2.gmail; Thu, 09 Jun 2022
 11:12:46 -0700 (PDT)
X-Received: by 2002:a37:58c1:0:b0:6a5:faff:6579 with SMTP id m184-20020a3758c1000000b006a5faff6579mr27554749qkb.28.1654798366428;
        Thu, 09 Jun 2022 11:12:46 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1654798366; cv=none;
        d=google.com; s=arc-20160816;
        b=ypjOfjrJ34NHOkftof0H4aervp0pAq0p+njZal7weSnnDC9uS9b247hgrDkXSybw6s
         Zdj40yEl+Ehi8BmpJAQ5h5wC865Ggu6JjEorMTjNmkm3QFRsdisuE5scfp8oxPIkPywh
         yYod9IQPfR3JqpAoRpbW8W1H/n1XkvgXoeht1mOM+3/AXN/2Js2XgSP3xNQLf/4oQuRD
         VHjbiG49ZNgegZCofaX/AYeg+MrRP1SvAZxpjgmEYtVhUKkrTae43x23dsmiPwLRSUu8
         aPOkiANh12zaFs5RaGPWm+tKwhQQIuTImp1wOJH7bgj0nDfShJPBH0yTQpqwI2ALte9p
         VWaw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=lZmFRyplZFrFLoO+ATeHLa4N7zJRWugh0qo8UpTNm2o=;
        b=HitQr/UvVbxOutvxAfFewxEojAGj2UG1kBD7MBUzPRbLgivNkI9VGVm9HCKgUbbS96
         jtP8x46UkLKIfly/tUgAZYhEN1s01FaEkHU3jurnw1Uelm56jEiIoUEy3TuZA7TbvdXX
         NcE7HaqQZgT68FLJZ6vrWVeR0lckDvBCWrwRKqiamuPc03ofLLfUiXk1WFKhpe1CvLDN
         PT0OEf6+ZmJyc6srM73DOIR48xZ4kZY5bkfPKU2tb2glasw/JifDENuNTAOUQxYaGqAK
         axaklLYh+QPWDocXkNoBDKNnWNmUMPxYZ2L7BwGEd/R7hBir64O8qAFDp41AGiub0R8L
         Ic6g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=RWIKj3WM;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::136 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-il1-x136.google.com (mail-il1-x136.google.com. [2607:f8b0:4864:20::136])
        by gmr-mx.google.com with ESMTPS id l19-20020a05620a211300b006a6c222b5e6si632839qkl.2.2022.06.09.11.12.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 09 Jun 2022 11:12:46 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::136 as permitted sender) client-ip=2607:f8b0:4864:20::136;
Received: by mail-il1-x136.google.com with SMTP id z11so511347ilq.6
        for <kasan-dev@googlegroups.com>; Thu, 09 Jun 2022 11:12:46 -0700 (PDT)
X-Received: by 2002:a92:3609:0:b0:2c6:3595:2a25 with SMTP id
 d9-20020a923609000000b002c635952a25mr23142353ila.233.1654798365958; Thu, 09
 Jun 2022 11:12:45 -0700 (PDT)
MIME-Version: 1.0
References: <4c76a95aff79723de76df146a10888a5a9196faf.1654011120.git.andreyknvl@google.com>
 <bbc30451228f670abeaf1b8aad678b9f6dda4ad3.1654011120.git.andreyknvl@google.com>
 <YpdbgGjjz954Us/y@elver.google.com>
In-Reply-To: <YpdbgGjjz954Us/y@elver.google.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Thu, 9 Jun 2022 20:12:35 +0200
Message-ID: <CA+fCnZf7eyksP7cAVXVPdS9X=qnDTCTBMVJaqmLGUbwnbD6cdA@mail.gmail.com>
Subject: Re: [PATCH 3/3] kasan: fix zeroing vmalloc memory with HW_TAGS
To: Marco Elver <elver@google.com>
Cc: andrey.konovalov@linux.dev, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=RWIKj3WM;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::136
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

On Wed, Jun 1, 2022 at 2:28 PM Marco Elver <elver@google.com> wrote:
>
> On Tue, May 31, 2022 at 05:43PM +0200, andrey.konovalov@linux.dev wrote:
> > From: Andrey Konovalov <andreyknvl@google.com>
> >
> > HW_TAGS KASAN skips zeroing page_alloc allocations backing vmalloc
> > mappings via __GFP_SKIP_ZERO. Instead, these pages are zeroed via
> > kasan_unpoison_vmalloc() by passing the KASAN_VMALLOC_INIT flag.
> >
> > The problem is that __kasan_unpoison_vmalloc() does not zero pages
> > when either kasan_vmalloc_enabled() or is_vmalloc_or_module_addr() fail.
> >
> > Thus:
> >
> > 1. Change __vmalloc_node_range() to only set KASAN_VMALLOC_INIT when
> >    __GFP_SKIP_ZERO is set.
> >
> > 2. Change __kasan_unpoison_vmalloc() to always zero pages when the
> >    KASAN_VMALLOC_INIT flag is set.
> >
> > 3. Add WARN_ON() asserts to check that KASAN_VMALLOC_INIT cannot be set
> >    in other early return paths of __kasan_unpoison_vmalloc().
> >
> > Also clean up the comment in __kasan_unpoison_vmalloc.
> >
> > Fixes: 23689e91fb22 ("kasan, vmalloc: add vmalloc tagging for HW_TAGS")
> > Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> > ---
> >  mm/kasan/hw_tags.c | 30 ++++++++++++++++++++++--------
> >  mm/vmalloc.c       | 10 +++++-----
> >  2 files changed, 27 insertions(+), 13 deletions(-)
> >
> > diff --git a/mm/kasan/hw_tags.c b/mm/kasan/hw_tags.c
> > index 9e1b6544bfa8..c0ec01eadf20 100644
> > --- a/mm/kasan/hw_tags.c
> > +++ b/mm/kasan/hw_tags.c
> > @@ -263,21 +263,31 @@ void *__kasan_unpoison_vmalloc(const void *start, unsigned long size,
> >       u8 tag;
> >       unsigned long redzone_start, redzone_size;
> >
> > -     if (!kasan_vmalloc_enabled())
> > -             return (void *)start;
> > +     if (!kasan_vmalloc_enabled() || !is_vmalloc_or_module_addr(start)) {
> > +             struct page *page;
> > +             const void *addr;
> > +
> > +             /* Initialize memory if required. */
> > +
>
> This whole block of code looks out-of-place in this function, since it's
> not at all related to unpoisoning but a fallback if KASAN-vmalloc is off
> but we still want to initialize the memory.
>
> Maybe to ease readability here I'd change it to look like:

Sounds good, will do in v2! Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZf7eyksP7cAVXVPdS9X%3DqnDTCTBMVJaqmLGUbwnbD6cdA%40mail.gmail.com.
