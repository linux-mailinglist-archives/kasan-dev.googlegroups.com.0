Return-Path: <kasan-dev+bncBDX4HWEMTEBRBREJROBAMGQEFOUSGWY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53b.google.com (mail-pg1-x53b.google.com [IPv6:2607:f8b0:4864:20::53b])
	by mail.lfdr.de (Postfix) with ESMTPS id 54FD432F6F7
	for <lists+kasan-dev@lfdr.de>; Sat,  6 Mar 2021 00:54:46 +0100 (CET)
Received: by mail-pg1-x53b.google.com with SMTP id h6sf2305780pgg.13
        for <lists+kasan-dev@lfdr.de>; Fri, 05 Mar 2021 15:54:46 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1614988484; cv=pass;
        d=google.com; s=arc-20160816;
        b=uMPef9fFsMsp2j+GZd7Sf/xweaHS+jf6yfFBZO3vNvwRQ7XNz+QFBEqal/5EVmcJLf
         6810xRZruEYBUg84WbVCddZhSyk/O2FPK7ZEvpNb8VipSswZ5jgz75oEmDX4wduEMRMy
         IJEBZPCcu94ksE9e9o3HHth6Egw4hEsZl4npTjCdHQE+vI7d7gGIWLJ1p1QsSvPs/4bS
         jVt7ypWOLape8QLpDKdeAZHQviJgQ9biX4N5Cu9HT2TXdZ4XGdTrMw1x0k7VVyb1TFyQ
         t3Z/fmFkzs/RQ4jAbOaaxjvpILUYRloDfCzY/XLdjR3paqDm2dMbgp4j0FqA3X+ntCIA
         UsNA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=GTj3ESxAQC9gm4LKCafhrj6fsn2LxwlNY9+7azL+8ns=;
        b=BkWVVfqp+PPl8YhSZXoMgoQYwntZA94zGwmLSUr/Ds9Y2Oqwee9J4HWWMkILIQ9ZM2
         iylOctQsBcd2AlHsTbWs9unL5xtpY5Ec4XIpBBW73e338BHvJZ4hVIQ2Zs0Yg47Zi7d1
         H+0rsZi3uwlIQyGv+h7Ig1RbwyQQityeGQmjW9ouNfpa+UX/AuQ2BWVJLFVngizaIwrH
         zUz4N+wkNDJvxf0KKSle3ZC4jBx6n+lJquzkMRS2xBqrCinlsakvPCbVGZwJBRshWdlS
         sDBMWDhoVMCB5JsSw/CKsKsJxraT6bjy7TxSqYcPlj92QudRafgxVxaFFApoJuRNpDUs
         zLYg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=wOuK4AFF;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::1030 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=GTj3ESxAQC9gm4LKCafhrj6fsn2LxwlNY9+7azL+8ns=;
        b=ra1uN1o3DZyrIeMGEWGa23WoqcDRfBY0ajAhL2buZvmFIrClbGm4L9D9JQW6OL4f10
         kLI6M1Vne6NwJVq/W59t8/52RijC3qmZyHCwxDCWzHejFLWBwO2DcrwC6LjloJGQY0lO
         6H0scgtE9wLvJvhFIYpD5nWDSvm3V7F/fOU/02dB8gO6bIJbh+QqrglzvGv0ePCK/mVT
         EFCIiXXJOkbxAxWjwf+teWlWInolGCp8asMBsq/eQ/N1TrJNUdR4Uc1b7zfVoJ9WWZBJ
         6ED0NXXg8K2op0aYtdu9VHZUhM/XT/cgddoV9pXh7FW7Vtln84kZbIVh7vGm4CIib6kN
         I0jQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=GTj3ESxAQC9gm4LKCafhrj6fsn2LxwlNY9+7azL+8ns=;
        b=RjHgfoEQEBXmc0cwA/bIx4Xbohu2ntYrbSdsWfKrCwQ/AxRW3oXLaTB1vFePDLWK0k
         M1FsrbETYi1ybjGE9dOqWgaWWksj/tY7Opv+hGO0naiGAaP0b0+mb4eyqKxDRUcY+hEh
         ZmCMPNkC5J33kikVgMkJEuxtZOv9YmPsaQ9sFm40FxZiSMvk6dgN7YdeeRCchT9ddqQX
         gzEFyEkGYGNiipV3lE3GUgD828JrYz8TRJinN3YkKsn6CUNn+jwes7s7wnEo1LxpCHwT
         o3UavS3bqXMjHv4iFv7FH0/fshNQy67PVBi2rRC02TFDcn84gJBTMvmGcB8wjeQF9H09
         Ppmw==
X-Gm-Message-State: AOAM532c/2Xsgt/5CPq5i4UkiPUu3Ouc2HMI6wbtxTC0FP7Y2qA2XAPu
	Wt3wd47e4VVmd8JZhZ13lXY=
X-Google-Smtp-Source: ABdhPJzQFXbkF7NuBOSgKRnpaMICpraVshzxcjfjsqtY7cueHsO/9WNxHoXrg42dw62KOEYk0MOs2w==
X-Received: by 2002:a62:1506:0:b029:1ee:ebf9:fbe5 with SMTP id 6-20020a6215060000b02901eeebf9fbe5mr11269331pfv.15.1614988484536;
        Fri, 05 Mar 2021 15:54:44 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:1704:: with SMTP id h4ls4493743pfc.2.gmail; Fri, 05
 Mar 2021 15:54:44 -0800 (PST)
X-Received: by 2002:a63:5525:: with SMTP id j37mr10963948pgb.191.1614988484041;
        Fri, 05 Mar 2021 15:54:44 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1614988484; cv=none;
        d=google.com; s=arc-20160816;
        b=rXZ1t08GE07qY1TYDZ3zzvqsQhmWQTu1FLjLgmcODtOLVkRCoij+/7xHCWXzN6wY3Z
         JolhtcsLLYQBrls4iAHxTT6McoPo71jh3WrNAM45EwmIqf2G9qVXoY1SUhKVQfTJHsaH
         /ElrfP+b0IpR1yufQHvDqUF4l1HWaznaL5vZ6RR4qSao8g650+yL1QQ6mT7r1P+OOF9u
         Xzc/K4YPXoSwX6cR8sBTmy75s0BzRoDfGFbtjaykh3WpliB8t9wr11dUGC/oHVLK0fGg
         KYPvVTqnsT/btQD2F0wJDwM8NH0hEBRgACM/JIcTe1QLOlPT8EcSrgvYtQOZboEJittT
         TRiA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=CNxGCp729OVTS5P6uQ6HNjJN45BugeibGn1RfeYppc4=;
        b=XEMQZqcyNUscyyL0nEnlfH/CpBXP5DkQpQENRwi4oXqdZWCkHqUFsw4WmFpoFfM1dz
         OFuTKEqHvxE4du4bza/IVcujMoC2eGNq8IDIHSUcJr6ng4nmTf9OfOQgMuWDcRZO76Pf
         VJJqpRv3OI1K+dldwY3vYb9rG+hdxVPC5aABdiqRdPADJ5jgOwnOfe/0pIIIZLWPgTpj
         IzGoLTmlPKi7EcpOptfZJfXKSqJZZtL1Y0fZxMiOXZ2Gc0KIcrznSkIyY/58lQsj3287
         UmAR9NLvnwlojmYAfWjB0iuv+Or4zng4XKTBCndNYYaFDAcZrEBk9tquyqqN+pQeaamC
         U+1g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=wOuK4AFF;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::1030 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pj1-x1030.google.com (mail-pj1-x1030.google.com. [2607:f8b0:4864:20::1030])
        by gmr-mx.google.com with ESMTPS id e15si208285pjm.3.2021.03.05.15.54.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 05 Mar 2021 15:54:44 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::1030 as permitted sender) client-ip=2607:f8b0:4864:20::1030;
Received: by mail-pj1-x1030.google.com with SMTP id fu20so103317pjb.2
        for <kasan-dev@googlegroups.com>; Fri, 05 Mar 2021 15:54:44 -0800 (PST)
X-Received: by 2002:a17:90b:350b:: with SMTP id ls11mr12605611pjb.166.1614988483675;
 Fri, 05 Mar 2021 15:54:43 -0800 (PST)
MIME-Version: 1.0
References: <24cd7db274090f0e5bc3adcdc7399243668e3171.1614987311.git.andreyknvl@google.com>
 <20210305154956.3bbfcedab3f549b708d5e2fa@linux-foundation.org>
In-Reply-To: <20210305154956.3bbfcedab3f549b708d5e2fa@linux-foundation.org>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Sat, 6 Mar 2021 00:54:32 +0100
Message-ID: <CAAeHK+yHf7p9H_EiPVfA9qadGU_6x0RrKwX-WjKrHEFz+xFEbg@mail.gmail.com>
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
 header.i=@google.com header.s=20161025 header.b=wOuK4AFF;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::1030
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

On Sat, Mar 6, 2021 at 12:50 AM Andrew Morton <akpm@linux-foundation.org> wrote:
>
> On Sat,  6 Mar 2021 00:36:33 +0100 Andrey Konovalov <andreyknvl@google.com> wrote:
>
> > Currently, kasan_free_nondeferred_pages()->kasan_free_pages() is called
> > after debug_pagealloc_unmap_pages(). This causes a crash when
> > debug_pagealloc is enabled, as HW_TAGS KASAN can't set tags on an
> > unmapped page.
> >
> > This patch puts kasan_free_nondeferred_pages() before
> > debug_pagealloc_unmap_pages() and arch_free_page(), which can also make
> > the page unavailable.
> >
> > ...
> >
> > --- a/mm/page_alloc.c
> > +++ b/mm/page_alloc.c
> > @@ -1304,6 +1304,12 @@ static __always_inline bool free_pages_prepare(struct page *page,
> >
> >       kernel_poison_pages(page, 1 << order);
> >
> > +     /*
> > +      * With hardware tag-based KASAN, memory tags must be set before the
> > +      * page becomes unavailable via debug_pagealloc or arch_free_page.
> > +      */
> > +     kasan_free_nondeferred_pages(page, order, fpi_flags);
> > +
> >       /*
> >        * arch_free_page() can make the page's contents inaccessible.  s390
> >        * does this.  So nothing which can access the page's contents should
> > @@ -1313,8 +1319,6 @@ static __always_inline bool free_pages_prepare(struct page *page,
> >
> >       debug_pagealloc_unmap_pages(page, 1 << order);
> >
> > -     kasan_free_nondeferred_pages(page, order, fpi_flags);
> > -
> >       return true;
> >  }
>
> kasan_free_nondeferred_pages() has only two args in current mainline.

Ah, yes, forgot to mention: this goes on top of:

kasan: initialize shadow to TAG_INVALID for SW_TAGS
mm, kasan: don't poison boot memory with tag-based modes

>
> I fixed that in the obvious manner...

Thanks!

If you changed this patch, you'll also need to change the other one though.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2ByHf7p9H_EiPVfA9qadGU_6x0RrKwX-WjKrHEFz%2BxFEbg%40mail.gmail.com.
