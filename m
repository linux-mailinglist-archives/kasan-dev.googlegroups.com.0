Return-Path: <kasan-dev+bncBDV37XP3XYDRBTUQ5PVAKGQEJHSQSQA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x440.google.com (mail-wr1-x440.google.com [IPv6:2a00:1450:4864:20::440])
	by mail.lfdr.de (Postfix) with ESMTPS id B8EF794956
	for <lists+kasan-dev@lfdr.de>; Mon, 19 Aug 2019 18:03:26 +0200 (CEST)
Received: by mail-wr1-x440.google.com with SMTP id o13sf5438453wrx.20
        for <lists+kasan-dev@lfdr.de>; Mon, 19 Aug 2019 09:03:26 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1566230606; cv=pass;
        d=google.com; s=arc-20160816;
        b=f39o7U3SW4EEvDLtgUEwTgLyfckG4/9hTUeTKMSuNpYx4Ec7s4kLh0sbjwKip6S5aM
         Sl8c6qMbhmaPtwEkjX/pI/OjgLBU859/L9mghZAr3ZYV9jB7GZLtsaLQrL8I2Dzee6Jp
         U0BhQiwXF6TjpBtiCONeeK9lqoON/fN+yN98Jd4Q1azGU7htXh6qLM7TSLCQwwrfEcyz
         s89x5+jsavPz9W01yzDY1pxEEzS2kbn3xgpQSKKeqQtLybi1CfEeHpPL3+XMZG5jzln4
         b1TSY/ceu564ONry7IZSlPHjJjx3C5swEKEqMx7BrwoWJ+iSJIMddoBZ0W+oFK1AYWGD
         Ev/A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=/EhUOHXW/vM77y19Dsr/3Nw/gSP64iCkSmSdicThQz0=;
        b=0SCfh8sAPXGtxRsKhwg7z6U08pxvaks/D44L1ekE8rvPlITsKGQCt9UoL5XmrHeBuQ
         YD58BZ6aGUy8NkPY0xk4VXQ4iHTXGQDFlAgGluuw/gx07vLHWxx0BLDayR44dIhFov4w
         r71ReotecN8VVd6pCq2gTrocfT4nX9kUE0a3crhf44sP+o3n4wAr/RnvGMPQrKRERftv
         vA8HzFbNNpyQvx+h3+d8bP5ehHjLONjL/ar6QKXgYL1Jnegm5WgnJUJSEAkiLltdBC/i
         44Std2FrF65QcU5e2j98b80n+7snUD0UV7zrI3cFsfEFpEaJ9Uxo051+z+dQQ/8f+AJl
         Xyqg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=/EhUOHXW/vM77y19Dsr/3Nw/gSP64iCkSmSdicThQz0=;
        b=M56mC26zMZAIAb5BBZwipb8uThBtnnJikg2h3pjZoHsYzs/hdAvYTEhQJHj0jtwXu1
         XH6d+deCEJTDifotx8HPxFOFNI2EMg5MXuh/cwERaxvdfIaXjQ0ZIUkA4mXFkErmpY0T
         iiGZvt3AmOmzyG+lMfHWi8kQyZaUsQbEq/Rs7cISRl8vWZ9V+CaibNq3PRYOnmiTiplK
         wWRaiVXspUz2+lMukt9i0hXSQ5uTXIdyJjgmtLcQLHYIyTQToB+nMwRVVCcmI4tA3yz/
         Ieow7bsl/uHPsvQxm9qpfWPnbYm87hbGpIVQVYR9wbRMVjNxg/Ha52ZMEJdzAninMysB
         g3Dw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=/EhUOHXW/vM77y19Dsr/3Nw/gSP64iCkSmSdicThQz0=;
        b=W+klRtLMW07611HmggBeodZERdSmzxWoshVZq2ZkuVGkJkHuWAlGwalSTAGuaspMH4
         wEM+wWHAolmwJX7/IlnovBPxE4hHZqCDOYnyh4l/0mpWjCsoGb8FfRPV1/gSEx3Pvwkb
         eLFDdcRn39SA/5Wz2vYpWA/zajFr2KuGaE8PaEgVtoAgCgYJjX4pc0IdhB8OXyF+f0yn
         ntEpnUmbQo8r9QnSgSyk0dZAzJVLvVketREvgm1y9zYlnogvojhJ2TP7XOUbyjUs9Z5F
         lRNhMhOQ25/nMv5Z8ZH/cXyfXC6D2GBcJ3VADnvunPnN2Ebu2NRj1S1mLhs0a86jBdf8
         SbkQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAWhVCovlhJpJDbdEaCLKA4MwruEiGvxTgKJjzZkwvn9VSoz/JzF
	foNWJEucZrlei8xT0hwCEoA=
X-Google-Smtp-Source: APXvYqznqAeQJIDwwpy0t0dPWUZQ76ycnsdO56rBl8YA1davzgYCEUrbntfL+UFr0wNJOWYfmI4KfQ==
X-Received: by 2002:a7b:c5c3:: with SMTP id n3mr21591339wmk.101.1566230606417;
        Mon, 19 Aug 2019 09:03:26 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:283:: with SMTP id 3ls1996wmk.5.canary-gmail; Mon,
 19 Aug 2019 09:03:25 -0700 (PDT)
X-Received: by 2002:a1c:3944:: with SMTP id g65mr22181227wma.68.1566230605684;
        Mon, 19 Aug 2019 09:03:25 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1566230605; cv=none;
        d=google.com; s=arc-20160816;
        b=BTh/+xrXuLEK6u/nNSL3T9xMR/C3E73aUCeWx1Ef63iTfIcgo0npihu15GfHJux01d
         Q3O+B7lgD9Tkwd+/I5SsIgr0fRVbVWON8wUX2iEgjn+U7k8ZfSUXC77IuJAqkc9ep2KP
         bEZ3jlZYOZjEq/yIWFKMGHxved1wdYnUzXmsbtwlx/+4s25w2oRXgdHRBKKuA6UnuHdM
         FkTdtW3IFCdNiweuADIYV22+GkXjjbjaKU6cfwmTVtwQtYaxgyRDohx6ikhU7KKX5Pmh
         Qy4lBFopaazCXxdwchGHlgUXiPDpRmUVqBqyk4vVORBpuj68PpRzp08X3F8GM90TlCZv
         CF2A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=oZ9aSxKnGkQGje9kUXTljfMYyI6a4bIJwIE2oGSudbw=;
        b=rwAA0cjJ5Twd6dgfpCmR97Z7TQSUFD4GBzuAbKYyHGXd3OXW2OSTfALgxfxdxiWB3k
         BHvuCrghcwmF0TTPb7wuziGcJym6CL26aH1ayOlw5ZLnoDN9o56ZXMBTNRazDQLqejk8
         Q63Pj4PBwVqTuqVxiM6I0yr5MT1wXxHJTQ6P9gsLpiDfNrSezLutZZnjgZtTDAPyjSRb
         tCQAr/Sg57lj1ZSHG1zbvuvkIrjU6fPraQZheUVyRGFbS9Pu+mv1KgsZfgoptRG9trgb
         fFJ2cZWalxUsqYWZg3PmbuYGNKpKEUXKrdeC4dC8sxPVCYgjlS+s9+khjYyKYbCfO7c4
         1Nng==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id c4si667808wrw.2.2019.08.19.09.03.25
        for <kasan-dev@googlegroups.com>;
        Mon, 19 Aug 2019 09:03:25 -0700 (PDT)
Received-SPF: pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id C82F4344;
	Mon, 19 Aug 2019 09:03:24 -0700 (PDT)
Received: from lakrids.cambridge.arm.com (usa-sjc-imap-foss1.foss.arm.com [10.121.207.14])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id D1F6B3F718;
	Mon, 19 Aug 2019 09:03:22 -0700 (PDT)
Date: Mon, 19 Aug 2019 17:03:20 +0100
From: Mark Rutland <mark.rutland@arm.com>
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Will Deacon <will@kernel.org>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Walter Wu <walter-zh.wu@mediatek.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will.deacon@arm.com>,
	Matthias Brugger <matthias.bgg@gmail.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	wsd_upstream@mediatek.com, LKML <linux-kernel@vger.kernel.org>,
	kasan-dev <kasan-dev@googlegroups.com>,
	linux-mediatek@lists.infradead.org,
	Linux ARM <linux-arm-kernel@lists.infradead.org>
Subject: Re: [PATCH] arm64: kasan: fix phys_to_virt() false positive on
 tag-based kasan
Message-ID: <20190819160320.GF9927@lakrids.cambridge.arm.com>
References: <20190819114420.2535-1-walter-zh.wu@mediatek.com>
 <20190819125625.bu3nbrldg7te5kwc@willie-the-truck>
 <20190819132347.GB9927@lakrids.cambridge.arm.com>
 <20190819133441.ejomv6cprdcz7hh6@willie-the-truck>
 <CAAeHK+w7cTGN8SgWQs0bPjPOrizqfUoMnJWTvUkCqv17Qt=3oQ@mail.gmail.com>
 <20190819150341.GC9927@lakrids.cambridge.arm.com>
 <CAAeHK+wBNnnKY4wg=34aD8Of6Vea4nzWF-FEnnSpHN0pFyTR3Q@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CAAeHK+wBNnnKY4wg=34aD8Of6Vea4nzWF-FEnnSpHN0pFyTR3Q@mail.gmail.com>
User-Agent: Mutt/1.11.1+11 (2f07cb52) (2018-12-01)
X-Original-Sender: mark.rutland@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as
 permitted sender) smtp.mailfrom=mark.rutland@arm.com
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

On Mon, Aug 19, 2019 at 05:37:36PM +0200, Andrey Konovalov wrote:
> On Mon, Aug 19, 2019 at 5:03 PM Mark Rutland <mark.rutland@arm.com> wrote:
> >
> > On Mon, Aug 19, 2019 at 04:05:22PM +0200, Andrey Konovalov wrote:
> > > On Mon, Aug 19, 2019 at 3:34 PM Will Deacon <will@kernel.org> wrote:
> > > >
> > > > On Mon, Aug 19, 2019 at 02:23:48PM +0100, Mark Rutland wrote:
> > > > > On Mon, Aug 19, 2019 at 01:56:26PM +0100, Will Deacon wrote:
> > > > > > On Mon, Aug 19, 2019 at 07:44:20PM +0800, Walter Wu wrote:
> > > > > > > __arm_v7s_unmap() call iopte_deref() to translate pyh_to_virt address,
> > > > > > > but it will modify pointer tag into 0xff, so there is a false positive.
> > > > > > >
> > > > > > > When enable tag-based kasan, phys_to_virt() function need to rewrite
> > > > > > > its original pointer tag in order to avoid kasan report an incorrect
> > > > > > > memory corruption.
> > > > > >
> > > > > > Hmm. Which tree did you see this on? We've recently queued a load of fixes
> > > > > > in this area, but I /thought/ they were only needed after the support for
> > > > > > 52-bit virtual addressing in the kernel.
> > > > >
> > > > > I'm seeing similar issues in the virtio blk code (splat below), atop of
> > > > > the arm64 for-next/core branch. I think this is a latent issue, and
> > > > > people are only just starting to test with KASAN_SW_TAGS.
> > > > >
> > > > > It looks like the virtio blk code will round-trip a SLUB-allocated pointer from
> > > > > virt->page->virt, losing the per-object tag in the process.
> > > > >
> > > > > Our page_to_virt() seems to get a per-page tag, but this only makes
> > > > > sense if you're dealing with the page allocator, rather than something
> > > > > like SLUB which carves a page into smaller objects giving each object a
> > > > > distinct tag.
> > > > >
> > > > > Any round-trip of a pointer from SLUB is going to lose the per-object
> > > > > tag.
> > > >
> > > > Urgh, I wonder how this is supposed to work?
> > > >
> > > > If we end up having to check the KASAN shadow for *_to_virt(), then why
> > > > do we need to store anything in the page flags at all? Andrey?
> > >
> > > As per 2813b9c0 ("kasan, mm, arm64: tag non slab memory allocated via
> > > pagealloc") we should only save a non-0xff tag in page flags for non
> > > slab pages.
> > >
> > > Could you share your .config so I can reproduce this?
> >
> > I wrote a test (below) to do so. :)
> >
> > It fires with arm64 defconfig, + CONFIG_TEST_KASAN=m.
> >
> > With Andrey Ryabinin's patch it works as expected with no KASAN splats
> > for the two new test cases.
> 
> OK, Andrey's patch makes sense and fixes both Mark's test patch and
> reports from CONFIG_IOMMU_IO_PGTABLE_ARMV7S_SELFTEST.
> 
> Tested-by: Andrey Konovalov <andreyknvl@google.com>
> Reviewed-by: Andrey Konovalov <andreyknvl@google.com>
> 
> on both patches.
> 
> >
> > Thanks,
> > Mark.
> >
> > ---->8----
> > From 7e8569b558fca21ad4e80fddae659591bc84ce1f Mon Sep 17 00:00:00 2001
> > From: Mark Rutland <mark.rutland@arm.com>
> > Date: Mon, 19 Aug 2019 15:39:32 +0100
> > Subject: [PATCH] lib/test_kasan: add roundtrip tests
> >
> > In several places we needs to be able to operate on pointers which have
> 
> "needs" => "need"

Thanks! 

I'll spin a standalone v2 of this with that fixed and your tags folded
in.

Mark.

> 
> > gone via a roundtrip:
> >
> >         virt -> {phys,page} -> virt
> >
> > With KASAN_SW_TAGS, we can't preserve the tag for SLUB objects, and the
> > {phys,page} -> virt conversion will use KASAN_TAG_KERNEL.
> >
> > This patch adds tests to ensure that this works as expected, without
> > false positives.
> >
> > Signed-off-by: Mark Rutland <mark.rutland@arm.com>
> > Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
> > Cc: Andrey Konovalov <andreyknvl@google.com>
> > Cc: Will Deacon <will.deacon@arm.com>
> > ---
> >  lib/test_kasan.c | 40 ++++++++++++++++++++++++++++++++++++++++
> >  1 file changed, 40 insertions(+)
> >
> > diff --git a/lib/test_kasan.c b/lib/test_kasan.c
> > index b63b367a94e8..cf7b93f0d90c 100644
> > --- a/lib/test_kasan.c
> > +++ b/lib/test_kasan.c
> > @@ -19,6 +19,8 @@
> >  #include <linux/string.h>
> >  #include <linux/uaccess.h>
> >
> > +#include <asm/page.h>
> > +
> >  /*
> >   * Note: test functions are marked noinline so that their names appear in
> >   * reports.
> > @@ -337,6 +339,42 @@ static noinline void __init kmalloc_uaf2(void)
> >         kfree(ptr2);
> >  }
> >
> > +static noinline void __init kfree_via_page(void)
> > +{
> > +       char *ptr;
> > +       size_t size = 8;
> > +       struct page *page;
> > +       unsigned long offset;
> > +
> > +       pr_info("invalid-free false positive (via page)\n");
> > +       ptr = kmalloc(size, GFP_KERNEL);
> > +       if (!ptr) {
> > +               pr_err("Allocation failed\n");
> > +               return;
> > +       }
> > +
> > +       page = virt_to_page(ptr);
> > +       offset = offset_in_page(ptr);
> > +       kfree(page_address(page) + offset);
> > +}
> > +
> > +static noinline void __init kfree_via_phys(void)
> > +{
> > +       char *ptr;
> > +       size_t size = 8;
> > +       phys_addr_t phys;
> > +
> > +       pr_info("invalid-free false positive (via phys)\n");
> > +       ptr = kmalloc(size, GFP_KERNEL);
> > +       if (!ptr) {
> > +               pr_err("Allocation failed\n");
> > +               return;
> > +       }
> > +
> > +       phys = virt_to_phys(ptr);
> > +       kfree(phys_to_virt(phys));
> > +}
> > +
> >  static noinline void __init kmem_cache_oob(void)
> >  {
> >         char *p;
> > @@ -737,6 +775,8 @@ static int __init kmalloc_tests_init(void)
> >         kmalloc_uaf();
> >         kmalloc_uaf_memset();
> >         kmalloc_uaf2();
> > +       kfree_via_page();
> > +       kfree_via_phys();
> >         kmem_cache_oob();
> >         memcg_accounted_kmem_cache();
> >         kasan_stack_oob();
> > --
> > 2.11.0
> >

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20190819160320.GF9927%40lakrids.cambridge.arm.com.
