Return-Path: <kasan-dev+bncBDX4HWEMTEBRBFPITSAAMGQENQM3ZNY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43d.google.com (mail-pf1-x43d.google.com [IPv6:2607:f8b0:4864:20::43d])
	by mail.lfdr.de (Postfix) with ESMTPS id 56E962FC00A
	for <lists+kasan-dev@lfdr.de>; Tue, 19 Jan 2021 20:33:42 +0100 (CET)
Received: by mail-pf1-x43d.google.com with SMTP id w139sf1831731pfc.18
        for <lists+kasan-dev@lfdr.de>; Tue, 19 Jan 2021 11:33:42 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1611084821; cv=pass;
        d=google.com; s=arc-20160816;
        b=GY/n0y1+xXhNLUy2MO2oUG01YZzRAagjClMx0U7QJWhKv/Cyr2PPKAwxnh/KUtZdgA
         WtN0AkIMVEddXzd5b2+JpB9L8QosqoYG2ze0+HmJetrQwXoQwX+B7hmj0H5Z9RNgLnSt
         0o0SxjLRd+CtmrU+Q5PEw/DDUrHRL0quLx/7vqFbijbih1ZYAoMEI64VjpeHcFoBHSJW
         oDhk+YrJ8Vxh7P8SxijgQEyrhnOeP7yM4zaQ8bjONwqRR1EtMZ6EoKYYJJIgAG6nTRkU
         OhqQjUoYa4jwcGTVICHTtAB8kQtCFRHf4oN5U1XfObeywvfm8R/9d53EeK6XkjuHqKoK
         J0Ew==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=f37ol2h14dYZGfPrTvrM1+oezx8GtD4OEOBRmAsXn5g=;
        b=H3s8afiP00Id7+AvBdoiXrAKz2l1w9VlhGGti+PahbKGDNiK0dShYRW3BZK5/LaCxl
         8yM1ZBkS2E8ijQFn8UCHSjwu9R1PqhpDeb6xpovsNGTw/ij92PswwBiqQO87485zLVdg
         Elh7cFapzuRVbtoenL+FAHag70j/Wv1xeAHK0ZPr1F2J3iWHJ2cKuHfG8w1qtI6GgcPr
         huBqbBudqi26Ix97gS4vZhcmlchxpOQZa0hUB4lBzso6An3XU3U63A6GjuWW6qA+fMf2
         bVKnje7QIIe3+0n8GKxz3CSEp0+v+Jxd0Fh1MSfk5VzCLjnozoLcC340HyiN5yhBCKjI
         FC6Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=UXLRrAGf;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::42c as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=f37ol2h14dYZGfPrTvrM1+oezx8GtD4OEOBRmAsXn5g=;
        b=INmQbj9ZfRlH0KYPGrz++oKCbb2TdvgL7LO/M+1wfp/OnVLEeY/6sp6qC7Zr8dyP+9
         ZlI8tKH5R8N4PbFJ4ywCxL8gzMwCzm8l0TxJr+jwzNNtdR8asOLdu22X75c9L9n/6dQe
         0XM7G/BF1+a1pbeOjNMVVj7JPBQUbsOxRqL+acrrZnPr5101uMpeMBalrtMFPQqO/eDG
         AkHcKaYhLvblCiPHCtPXdpBG+KCz223VzmifT8nttKK1JMojy+ST1uxQMz4awtXMklHm
         lkBVrG9drYRSrawcIY29Xj4d86UQmwtB37p/cTwVLSv6oin7Uh/Mka5fUzbI8VexWq81
         euWQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=f37ol2h14dYZGfPrTvrM1+oezx8GtD4OEOBRmAsXn5g=;
        b=U9K7bnuNHupxycae/IogoeMIcUUDMBPzYgI3fb8pCq52HuyJjURmjJMybq7dtNYqmi
         233tzOL88mxW74IOFLI0qVO69EGg6n6Ojem1ytEbUMzZdpHug0/4FvJzvA+JJRGX8vIP
         Db090hxTc/Yhb08/xU0pL9xvZjCvE5Co50SPYXLZf0xGrJwjlEoRTZcKCeSKjUWXxhWm
         uZ4p0dWBuMiC742G/wTwq3AVeghAx7FBMSUYYNxEm2gi/gk0gsiN/wn3wz0kXWVPH1s/
         yMjaHtCl109wqjtgRuFMidM48opDXyWwp7feztEpTvH749FkI60xUm4s3z4HTw2HGIUG
         QIRQ==
X-Gm-Message-State: AOAM533535NDM+42IqUH9SNgncAgHW+wtI39swAB5pzLWr+YA0ljP7yX
	B4L9da931M5z5SzE0RnnYL4=
X-Google-Smtp-Source: ABdhPJx40Su8puEEE3ETbRs+uEIXnudV+V95zfGooffM+lNpEw3AU5Y37x5AEkLOvbQTsaXYDlcmrw==
X-Received: by 2002:a17:902:6b43:b029:db:c7fc:82f3 with SMTP id g3-20020a1709026b43b02900dbc7fc82f3mr6298741plt.74.1611084821076;
        Tue, 19 Jan 2021 11:33:41 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:fb01:: with SMTP id o1ls8036773pgh.7.gmail; Tue, 19 Jan
 2021 11:33:40 -0800 (PST)
X-Received: by 2002:a65:608e:: with SMTP id t14mr5826516pgu.436.1611084820502;
        Tue, 19 Jan 2021 11:33:40 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1611084820; cv=none;
        d=google.com; s=arc-20160816;
        b=h4hZVA4uPmncyyuBJ+3FuMkPFhdIyANnEeLX6SZYTYbAdZu/azCTJ2PhscVY1iEqSG
         g80I4ngeWiferB8jzfHFxNMPCkCxo96+ZqkRBhedpGQD6FaZ5691NMKquwHkjAsVtIaB
         b/ZXl6D65pkPx1AJYT4dnr/PV9Lp/tZCj4WWDvNG8I94bcC9jsOZcz9T/2RBbYSEOz1W
         XLaB1OEW9DRPEmSpbnFSaNqgKCOWYUJhIVWzhGtFh7Huf49SYYkxBGWH4AkaES9Y/3oa
         d7yGjSNr71HIKQxriaPyoTnxRw13XjwS8h9jVZA34Ny3hulWjAQQ7juoPBB4QeXabCDU
         Nh6g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Et5oXk9EBnfayAqZpeLMrHHvh8j8h9yJAXgaYXUhqsI=;
        b=NefaFZuHV7q7s1xPS6P/PFMBniy6hsqGzsLQMrBuyIaJ4enNHTKV0LVPtyuvgQsvSJ
         2OjjKmeJs8s9+Tqqp8kAdyWFUjNrg75JsdvETreUpC8kwDF2uT7SLditnHG16fjuj0w5
         wIvmU7jKUtbhKzEWSoauTPCwmoXzUkCC5SXISf9kPWM0l6XlsZABVYlPLTfNZxPxHned
         GdryEau0fOI9mZNHYudRUy5VgTe5NFWJPzn3lZzSt7FgI7r+Hp3i9/dWqmdfzk+01Oaa
         vHloo+9M3lOje6VGPQvIp8rVdRMBGssGo7UlUjZcBcpOVcPRxutGR7b2qmEURtCf9UIt
         s5Pg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=UXLRrAGf;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::42c as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pf1-x42c.google.com (mail-pf1-x42c.google.com. [2607:f8b0:4864:20::42c])
        by gmr-mx.google.com with ESMTPS id m63si1235726pfb.3.2021.01.19.11.33.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 19 Jan 2021 11:33:40 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::42c as permitted sender) client-ip=2607:f8b0:4864:20::42c;
Received: by mail-pf1-x42c.google.com with SMTP id j12so5748468pfj.12
        for <kasan-dev@googlegroups.com>; Tue, 19 Jan 2021 11:33:40 -0800 (PST)
X-Received: by 2002:aa7:8597:0:b029:1b9:38bd:d0dc with SMTP id
 w23-20020aa785970000b02901b938bdd0dcmr5377887pfn.24.1611084820015; Tue, 19
 Jan 2021 11:33:40 -0800 (PST)
MIME-Version: 1.0
References: <20210119172607.18400-1-vincenzo.frascino@arm.com>
 <CAAeHK+zpB6GZcAbWnmvKu5mk_HuNEaXV2OwRuSNnVjddjBqZMQ@mail.gmail.com>
 <20210119185206.GA26948@gaia> <e3d67672-1825-894a-db68-5709b33b4991@arm.com>
In-Reply-To: <e3d67672-1825-894a-db68-5709b33b4991@arm.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 19 Jan 2021 20:33:28 +0100
Message-ID: <CAAeHK+zKnSdx+=8mA5o1YWR5aV8OSEUaRZiaJiB6wsOo_5kYJQ@mail.gmail.com>
Subject: Re: [PATCH] kasan: Add explicit preconditions to kasan_report()
To: Vincenzo Frascino <vincenzo.frascino@arm.com>
Cc: Catalin Marinas <catalin.marinas@arm.com>, LKML <linux-kernel@vger.kernel.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, Leon Romanovsky <leonro@mellanox.com>, 
	Alexander Potapenko <glider@google.com>, Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Dmitry Vyukov <dvyukov@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=UXLRrAGf;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::42c
 as permitted sender) smtp.mailfrom=andreyknvl@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

On Tue, Jan 19, 2021 at 7:57 PM Vincenzo Frascino
<vincenzo.frascino@arm.com> wrote:
>
>
>
> On 1/19/21 6:52 PM, Catalin Marinas wrote:
> > On Tue, Jan 19, 2021 at 07:27:43PM +0100, Andrey Konovalov wrote:
> >> On Tue, Jan 19, 2021 at 6:26 PM Vincenzo Frascino
> >> <vincenzo.frascino@arm.com> wrote:
> >>>
> >>> With the introduction of KASAN_HW_TAGS, kasan_report() dereferences
> >>> the address passed as a parameter.
> >>>
> >>> Add a comment to make sure that the preconditions to the function are
> >>> explicitly clarified.
> >>>
> >>> Note: An invalid address (e.g. NULL pointer address) passed to the
> >>> function when, KASAN_HW_TAGS is enabled, leads to a kernel panic.
> >>>
> >>> Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
> >>> Cc: Alexander Potapenko <glider@google.com>
> >>> Cc: Dmitry Vyukov <dvyukov@google.com>
> >>> Cc: Leon Romanovsky <leonro@mellanox.com>
> >>> Cc: Andrey Konovalov <andreyknvl@google.com>
> >>> Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
> >>> ---
> >>>  mm/kasan/report.c | 11 +++++++++++
> >>>  1 file changed, 11 insertions(+)
> >>>
> >>> diff --git a/mm/kasan/report.c b/mm/kasan/report.c
> >>> index c0fb21797550..2485b585004d 100644
> >>> --- a/mm/kasan/report.c
> >>> +++ b/mm/kasan/report.c
> >>> @@ -403,6 +403,17 @@ static void __kasan_report(unsigned long addr, size_t size, bool is_write,
> >>>         end_report(&flags);
> >>>  }
> >>>
> >>> +/**
> >>> + * kasan_report - report kasan fault details
> >>> + * @addr: valid address of the allocation where the tag fault was detected
> >>> + * @size: size of the allocation where the tag fault was detected
> >>> + * @is_write: the instruction that caused the fault was a read or write?
> >>> + * @ip: pointer to the instruction that cause the fault
> >>> + *
> >>> + * Note: When CONFIG_KASAN_HW_TAGS is enabled kasan_report() dereferences
> >>> + * the address to access the tags, hence it must be valid at this point in
> >>> + * order to not cause a kernel panic.
> >>> + */
> >>
> >> It doesn't dereference the address, it just checks the tags, right?
> >>
> >> Ideally, kasan_report() should survive that with HW_TAGS like with the
> >> other modes. The reason it doesn't is probably because of a blank
> >> addr_has_metadata() definition for HW_TAGS in mm/kasan/kasan.h. I
> >> guess we should somehow check that the memory comes from page_alloc or
> >> kmalloc. Or otherwise make sure that it has tags. Maybe there's an arm
> >> instruction to check whether the memory has tags?
> >
> > There isn't an architected way to probe whether a memory location has a
> > VA->PA mapping. The tags are addressed by PA but you can't reach them if
> > you get a page fault on the VA. So we either document the kasan_report()
> > preconditions or, as you suggest, update addr_has_metadata() for the
> > HW_TAGS case. Something like:
> >
> >         return is_vmalloc_addr(virt) || virt_addr_valid(virt));
> >
>
> Or we could have both ;)

Sounds good! Please also update the comment to avoid mentioning tag
faults. kasan_report() is used for the generic KASAN mode as well, and
it doesn't use tags.

Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2BzKnSdx%2B%3D8mA5o1YWR5aV8OSEUaRZiaJiB6wsOo_5kYJQ%40mail.gmail.com.
