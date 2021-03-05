Return-Path: <kasan-dev+bncBDX4HWEMTEBRBX4JROBAMGQEGWFJPDY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd38.google.com (mail-io1-xd38.google.com [IPv6:2607:f8b0:4864:20::d38])
	by mail.lfdr.de (Postfix) with ESMTPS id B6DB832F6F8
	for <lists+kasan-dev@lfdr.de>; Sat,  6 Mar 2021 00:55:12 +0100 (CET)
Received: by mail-io1-xd38.google.com with SMTP id j1sf3323268ioo.3
        for <lists+kasan-dev@lfdr.de>; Fri, 05 Mar 2021 15:55:12 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1614988511; cv=pass;
        d=google.com; s=arc-20160816;
        b=B6qi9mDRCNFQ2d0S6vt001Zp2CFVLZR8QVMZQ47r/dymkkheem8Gn9noi6N76TmCrS
         hahvAamt6FKQu5tMtLPnHoZ7f3UcwSYLx0M32b0f2Gk+s59wAKzXKkLEOmK6m5IeR5Kl
         VqteSQFGBeBZdWEXCDtgII05TleJYV40ixiHkQ210RO7sQCLfs4zwjKBz2x7qQTlyhwm
         idgYfY+ltEiJs/0u5r9ex5vJRqcfgnmxSpRfw9O0MhTNIDf3ALX0zWtKHIa7X735gdfZ
         aie/khhAMoIq2fgu5JXn/JU+HjHds7w5yE8tWL2hWPnFbJ9AM/OrXd2g3I7Ak0wmYO5a
         VbMg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=Edo1bVo8lOMJCYtZLfCFoTCZQDgFHEghxLLnFurSpKI=;
        b=YnkW+P9sZocgF7oCDrRZUWFuDA6o3KFXJd4vOL2eZsl2eOGaLyjZjUGNeO6s5bFUOV
         YLSf8LZRt+bISVi2clPSN168OsAPfMAGg31gJgUJCKXtbvuTcJlSBejY9gMu+VdVrdyL
         HGlsFkMXwbz+tTvIzdyC9izrJgTQRAvLtXgXjkdNF/DVcji+27gPxBmz6BeBnOSF5jyH
         r18JRqhUzaPN8SxiLowgEquhMhkdH9K6BcAyh0Zx/uo0q2fkSAkRU6PknJ/oMSfwwWxQ
         7uBehGQTCusnFU9wEbDaTWoOr9uJ5RVUkHIOVahmoFsan4/s9xkJE2xCnsEDIwTIqR0U
         iXRw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=dZN6rzdO;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::1034 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Edo1bVo8lOMJCYtZLfCFoTCZQDgFHEghxLLnFurSpKI=;
        b=dEQUdXFOq9c8WiU+ik3zJFNnbHr/OY6C6JDuRsngYpC8mNH0d+yt/Ua6RKUdzljZT3
         iqO/gMsADEsgrs1rxMV8sTNI0oetp/d8Fu6+KrpCjWkyPFfJZcSYakk5dpL3Z8AsfgeH
         wI+bJXJaGj3hXydgN/5YAVLr3aZyjKHaL0UVFkeSiSLXOmNIh6DkmV2rnfH6rBhtBt3C
         WZ/6nXUHWP96tMGwcn2LCOrViuvj3sRCoB/eH4KbTDSNIif60KQKO1EoUTZGrcdBVgB7
         eEiSrBIUX6namZId8uP6QtIti0uNzBHMu9lWHSkKDYBIsx3bLbLLwU1Yloh24rjtpFYH
         1/+Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Edo1bVo8lOMJCYtZLfCFoTCZQDgFHEghxLLnFurSpKI=;
        b=ELMWsYGOKV6tAbojZyVyv3lxv2uYV+F3ofLVmqr7wZCgVNzBbzeETZLIDiaeeG5MKs
         /Q8GrZjVkoLm4ENpwBXxLv18GnXpgjo1rzbnlpIeCSW3LTBQe8RqjXGHiZRifEg+3dDp
         BdYRvVFIiRQXmp3m4jhV/NQkm0DVKYZ3m1Nnvj4bdpuWeFAqdzMFNmAJnH7/cQ2JJWjW
         8UTKgSGOYP2xaBrLB+k6YdHJH11RzykUjNla7Cez5KFd17vXGTNFVAHuKLQfuGnuso6X
         nGTEDLWuFy/UQjWFTp2V6Y2qdcxwwhmHp/Sa6r//tB/52LJD+YAHGIzWZ80zs7LH66bS
         paYA==
X-Gm-Message-State: AOAM5313XN0LijxU2PrajUbWu8b/cXmDHeVk+bKySok/0D4EunmlJ74+
	W/YSZEHEFjZqR4sC51M4NBg=
X-Google-Smtp-Source: ABdhPJwhJ74vb6a4YP8TyRm8XJsgPS/W8OmJEmna2l1h8ih/Vzn2qTgWaIHXmMHEeBMfcdt4rQ9eIQ==
X-Received: by 2002:a92:c24b:: with SMTP id k11mr10887718ilo.276.1614988511261;
        Fri, 05 Mar 2021 15:55:11 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a6b:b807:: with SMTP id i7ls1857635iof.6.gmail; Fri, 05 Mar
 2021 15:55:10 -0800 (PST)
X-Received: by 2002:a05:6602:26c6:: with SMTP id g6mr10099331ioo.150.1614988510880;
        Fri, 05 Mar 2021 15:55:10 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1614988510; cv=none;
        d=google.com; s=arc-20160816;
        b=w7PlFTGJ1RDGYGBrmNTgcW+8Mu9rwi2qiIFgnxTktGXS9GJr1bFQ2ZbWp6W8A4fItu
         YRaU+zTWkfuOj+SNlsc2zYmuxgLKcPozozwrFAD2+goAu9cOWKoE76G8ygr5LFxYNuY/
         0sHPvTrPgRpWVHb+8Q8m5oZTNBZVNXwZ+GrD2IFEXXUgsoe3rP0H34a8oi84FNOBhoHG
         MmNvOSd6XhOpOTmCK6W+QM+IpL0fA4/PQ0aQ+vDIXjXzAggbtSIL7c2PhSADt+qCeOvy
         V4ktFlJn5CNJk/wqOVydQd0K6Qphf9w6hlXMcwNUl6YiKGlMUvIuizCu+QgYQyiwSB76
         +S0A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=f3poge5+rEFOPBLlgkkWAEUuEZq1vRObX8yBVeHFMs0=;
        b=jZ/xyI6DNHbld7rzMLudA2ayT5lvc4LTkZAq7LOhlJFVSkVIJQ92mb535JrwGAYC5y
         Pe2HUUe6qAnWJAsp35leFqJBhf3BV7hBmZCzyY4oNhRiApGjZfP0+OnM9ap8JzY9XL3A
         xglo1EwlF7GYyqWFD6mEbSv8l2rjsVpI1nbXgwA+5A4KB3dzhNtI+u4R+xYJmDVY32h/
         uT8bjC9E+Co5p0lWKonWYiDvoJCNDUpHTC3HnpOGYutC1jHfcomEPpBZ0leN2luzaa5K
         3LQtmGmHqiBUm/+SyR3Z80drL68NUJvI8Nq3nkVxcrlSlr+jzsDxNrUoS43Jf4jFKo9x
         thMw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=dZN6rzdO;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::1034 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pj1-x1034.google.com (mail-pj1-x1034.google.com. [2607:f8b0:4864:20::1034])
        by gmr-mx.google.com with ESMTPS id o7si177689ilu.0.2021.03.05.15.55.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 05 Mar 2021 15:55:10 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::1034 as permitted sender) client-ip=2607:f8b0:4864:20::1034;
Received: by mail-pj1-x1034.google.com with SMTP id jx13so106364pjb.1
        for <kasan-dev@googlegroups.com>; Fri, 05 Mar 2021 15:55:10 -0800 (PST)
X-Received: by 2002:a17:903:31ca:b029:e6:65f:ca87 with SMTP id
 v10-20020a17090331cab02900e6065fca87mr1091669ple.85.1614988510448; Fri, 05
 Mar 2021 15:55:10 -0800 (PST)
MIME-Version: 1.0
References: <24cd7db274090f0e5bc3adcdc7399243668e3171.1614987311.git.andreyknvl@google.com>
 <20210305154956.3bbfcedab3f549b708d5e2fa@linux-foundation.org> <CAAeHK+yHf7p9H_EiPVfA9qadGU_6x0RrKwX-WjKrHEFz+xFEbg@mail.gmail.com>
In-Reply-To: <CAAeHK+yHf7p9H_EiPVfA9qadGU_6x0RrKwX-WjKrHEFz+xFEbg@mail.gmail.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Sat, 6 Mar 2021 00:54:59 +0100
Message-ID: <CAAeHK+w3Xr8=xLP2og6A54f=wr=BvNj18yKR6ntno1-hbqroFw@mail.gmail.com>
Subject: Re: [PATCH v2] kasan, mm: fix crash with HW_TAGS and DEBUG_PAGEALLOC
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Alexander Potapenko <glider@google.com>, Catalin Marinas <catalin.marinas@arm.com>, 
	Will Deacon <will.deacon@arm.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Marco Elver <elver@google.com>, Peter Collingbourne <pcc@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>, 
	stable <stable@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=dZN6rzdO;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::1034
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

On Sat, Mar 6, 2021 at 12:54 AM Andrey Konovalov <andreyknvl@google.com> wrote:
>
> On Sat, Mar 6, 2021 at 12:50 AM Andrew Morton <akpm@linux-foundation.org> wrote:
> >
> > On Sat,  6 Mar 2021 00:36:33 +0100 Andrey Konovalov <andreyknvl@google.com> wrote:
> >
> > > Currently, kasan_free_nondeferred_pages()->kasan_free_pages() is called
> > > after debug_pagealloc_unmap_pages(). This causes a crash when
> > > debug_pagealloc is enabled, as HW_TAGS KASAN can't set tags on an
> > > unmapped page.
> > >
> > > This patch puts kasan_free_nondeferred_pages() before
> > > debug_pagealloc_unmap_pages() and arch_free_page(), which can also make
> > > the page unavailable.
> > >
> > > ...
> > >
> > > --- a/mm/page_alloc.c
> > > +++ b/mm/page_alloc.c
> > > @@ -1304,6 +1304,12 @@ static __always_inline bool free_pages_prepare(struct page *page,
> > >
> > >       kernel_poison_pages(page, 1 << order);
> > >
> > > +     /*
> > > +      * With hardware tag-based KASAN, memory tags must be set before the
> > > +      * page becomes unavailable via debug_pagealloc or arch_free_page.
> > > +      */
> > > +     kasan_free_nondeferred_pages(page, order, fpi_flags);
> > > +
> > >       /*
> > >        * arch_free_page() can make the page's contents inaccessible.  s390
> > >        * does this.  So nothing which can access the page's contents should
> > > @@ -1313,8 +1319,6 @@ static __always_inline bool free_pages_prepare(struct page *page,
> > >
> > >       debug_pagealloc_unmap_pages(page, 1 << order);
> > >
> > > -     kasan_free_nondeferred_pages(page, order, fpi_flags);
> > > -
> > >       return true;
> > >  }
> >
> > kasan_free_nondeferred_pages() has only two args in current mainline.
>
> Ah, yes, forgot to mention: this goes on top of:
>
> kasan: initialize shadow to TAG_INVALID for SW_TAGS
> mm, kasan: don't poison boot memory with tag-based modes
>
> >
> > I fixed that in the obvious manner...
>
> Thanks!
>
> If you changed this patch, you'll also need to change the other one though.

Nevermind, just realized that this should be a backportable fix :)

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2Bw3Xr8%3DxLP2og6A54f%3Dwr%3DBvNj18yKR6ntno1-hbqroFw%40mail.gmail.com.
