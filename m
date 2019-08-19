Return-Path: <kasan-dev+bncBDX4HWEMTEBRBTEE5PVAKGQECJXZCHI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-xc39.google.com (mail-yw1-xc39.google.com [IPv6:2607:f8b0:4864:20::c39])
	by mail.lfdr.de (Postfix) with ESMTPS id 3145094890
	for <lists+kasan-dev@lfdr.de>; Mon, 19 Aug 2019 17:37:50 +0200 (CEST)
Received: by mail-yw1-xc39.google.com with SMTP id b195sf3484828ywa.16
        for <lists+kasan-dev@lfdr.de>; Mon, 19 Aug 2019 08:37:50 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1566229069; cv=pass;
        d=google.com; s=arc-20160816;
        b=eO6wEnOXnSmdEZr+OieZmCum+K27ix/3C7GbYj+9ssSVweOqX9bvjF6n8WQqJIuqLO
         SFRXAnwAif5DwCZy43xmx9nqNmbh43r4wsmV96ijQ/Bwx6NR0KG+sB6+Cw3KUGGE1JCN
         BzEBHEosnkD88hxwnxe4d6TcUz0SsDHbbd31VuEbGh9dJlG9CIqzJ4xUmYZ4/9HVXuv8
         V9qQJySX5pjccr418MPnXDQH9WWm/MWgskNs5S6nGIayyvPkrQvfzC1ibsUFpXsNUXma
         r47p2OCP3He1MhSQaOwJDv/C0TNMPhD6NAbP3VNLmTFglyCGU6xi43x8w3NcqQdf5liB
         IhEA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=8akMmss/i3Ln+fVZ3WppsDOvVQ9+4c343gI5UVf6W6I=;
        b=DlekRdbE83WUCBXqlTT70WmVC9SjepZZES9ehbFJDcwkiHDftUuGVEyBYL8mo7DbbB
         asUSZWWWUvwX/8M6wDXm2HNAAPJH8ypH96AIWv1nXcGmTqeT0TncYjoPe/jSB1syku8B
         o9gklT233I1kAp25ezJw5ECl2EAdkdArxApjpl+8akg9+IdMzsuuyjdMkrpdjF1rEjHQ
         aDRl01k8v3dWcE/CjEqTBZiOyfTaWSmLuHojNkW02ADLeYa3f47H5+t82YxuhIpROETe
         sT9XHdPCys3HzxsouH84oex8F4RIw7tY18Aj/8czqsALAh2kVl1+a/U652vbnVBM+Nvj
         JbWg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=BASVfhGk;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::542 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=8akMmss/i3Ln+fVZ3WppsDOvVQ9+4c343gI5UVf6W6I=;
        b=hfb9I6SJNUfF05LUyIBoGgg7wH6Cu1CEGWiYXw22YyhZUjhk8vJHp5y3j5xcMlU2qb
         7K33lpvDW2jX9LjqqDg5LLm8FmRIZORdthuVkKeLtSuKITjQl0B1h9rUY3HdCgeSKyva
         y4H2bQ8iN5tiBjuP8C1a/krVxshzRiXS/modW5QBKj3tqc+CHNkHsDC78pEmW8fvvjJD
         vAsxN6nb3wXqzj1vrSrBmc3JYU6FMF5fSxIJokJHcm2jLh89x/hiuJd6c9S1Zl+axwpq
         gRFzhP5hCRFTdCgCbDlrcijaxMwTIIBkoEPmXub1gw0e0Yzd5RZdTvKLq8xj2UZUhVse
         08Pw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=8akMmss/i3Ln+fVZ3WppsDOvVQ9+4c343gI5UVf6W6I=;
        b=Zhf+jXyEUJvY6rn/jvy6IoJZeNN2C8t9KF++TxpzBHMl3nkWJppAaGKojsjCo/bPmp
         9Njx0FEfzJquAkJ3vcKrP45XyHKBPxjaiqAqxjhXu5RoML9R1YaEUOADl57w3T1SbKjc
         twYIYLnbyFQchHJPYC9Zl/kvC3mpDIP9U/b3gZoJk15wkc6Bd6W7J9vs/C55LwRquUn/
         ttXzhBotKouAC6kQmu6GpbXBITrPQ02Y3dWERu/FlmzV1TLIGMQBCp+TuXALzHVLrfRd
         O9gf/tL7R4qGc4cc189J4Kkkzx0KXta/zYFot8hlEQ4w+qvD/lIaWyIY7vYT1OTD9I29
         br7w==
X-Gm-Message-State: APjAAAXDTSskAc6WaSAgvhQH7KrdSt/z5H2oeJ9NEGQvJet6UvKA848D
	kiktCdrTAfx6QHMK+uPlNHU=
X-Google-Smtp-Source: APXvYqyCeNznZN3WHGZQXs1po+F2jzy81hmslkLwRw878by/uNBWJi1lSuIHzll1lFk34FCgdkA6+A==
X-Received: by 2002:a0d:d410:: with SMTP id w16mr16380897ywd.125.1566229068939;
        Mon, 19 Aug 2019 08:37:48 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:be47:: with SMTP id d7ls2084680ybm.14.gmail; Mon, 19 Aug
 2019 08:37:48 -0700 (PDT)
X-Received: by 2002:a05:6902:50a:: with SMTP id x10mr17241826ybs.465.1566229068652;
        Mon, 19 Aug 2019 08:37:48 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1566229068; cv=none;
        d=google.com; s=arc-20160816;
        b=ASSslbXrPvWeanU9SD9bu0OJVc7T35D5mO3qe3EJhQAQibDeR1XVFZ0iiCw7iQe3+U
         oun8i8yQUlmTI4oP+trCK2Ysbeg+fwxOZ9FmUrL9dtdZUzCdVD4S9S6i7HFs773HCPN3
         8dDQypNxcV+cVTVMZku95O6MHf7yQRSGEoLhZsA9OFHYnSKaIPdv50L2JfN/0xz6MRG2
         bT4DBMqz9+/j7LwhSWTSvBCNShPyWC8+kyNaoOfMtQ9u0UeLjY1N2h1u7Ff21Em5CY6U
         0eQgAuNDno1o6fqi+hzbwwDWxmbXa0kNTYY+pvKWuEczAHAZggVfb+aBdw0XHTt40LHr
         nF6g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=1doVjKq3mcViKTNmljRst42DcW8+lOf7Fak48gVUGb8=;
        b=rCTvLkyPFUjIs+4Tqdpxi9x6PjXYkeJABKR5GLCeHcMB9JJuVBvyft507W+rxeg7d2
         hO4/xDHOf251aIRLCIuXOuJ6qiWFshMN5qppYxVEWEfQlN3s4zCPazXQ3Tz0HQXbCvi7
         IYpUAWgtX71R2pmfgG/yLytht/42UOeQ6d/PxFMDE+ou5v2BaN+FHRIPN5h8cJa3kNL1
         CpiwaAnNkgzvyFTTfCvDwhCwvA9O869dyrbtgTMOcd9RGJSJtPh85I72bnErJ5cLBSb4
         8Hi5ycIXySvNSOHfj3xyrtJKBnRA34urwLFhKMwh2zqdqdmhX+x6Lm4saANn0cZx30Zi
         vEBA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=BASVfhGk;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::542 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pg1-x542.google.com (mail-pg1-x542.google.com. [2607:f8b0:4864:20::542])
        by gmr-mx.google.com with ESMTPS id r130si632228ywe.5.2019.08.19.08.37.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 19 Aug 2019 08:37:48 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::542 as permitted sender) client-ip=2607:f8b0:4864:20::542;
Received: by mail-pg1-x542.google.com with SMTP id m3so1415378pgv.13
        for <kasan-dev@googlegroups.com>; Mon, 19 Aug 2019 08:37:48 -0700 (PDT)
X-Received: by 2002:aa7:9e0a:: with SMTP id y10mr24422794pfq.93.1566229067338;
 Mon, 19 Aug 2019 08:37:47 -0700 (PDT)
MIME-Version: 1.0
References: <20190819114420.2535-1-walter-zh.wu@mediatek.com>
 <20190819125625.bu3nbrldg7te5kwc@willie-the-truck> <20190819132347.GB9927@lakrids.cambridge.arm.com>
 <20190819133441.ejomv6cprdcz7hh6@willie-the-truck> <CAAeHK+w7cTGN8SgWQs0bPjPOrizqfUoMnJWTvUkCqv17Qt=3oQ@mail.gmail.com>
 <20190819150341.GC9927@lakrids.cambridge.arm.com>
In-Reply-To: <20190819150341.GC9927@lakrids.cambridge.arm.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 19 Aug 2019 17:37:36 +0200
Message-ID: <CAAeHK+wBNnnKY4wg=34aD8Of6Vea4nzWF-FEnnSpHN0pFyTR3Q@mail.gmail.com>
Subject: Re: [PATCH] arm64: kasan: fix phys_to_virt() false positive on
 tag-based kasan
To: Mark Rutland <mark.rutland@arm.com>, Will Deacon <will@kernel.org>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>, Walter Wu <walter-zh.wu@mediatek.com>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Matthias Brugger <matthias.bgg@gmail.com>, Andrew Morton <akpm@linux-foundation.org>, 
	wsd_upstream@mediatek.com, LKML <linux-kernel@vger.kernel.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, linux-mediatek@lists.infradead.org, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=BASVfhGk;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::542
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

On Mon, Aug 19, 2019 at 5:03 PM Mark Rutland <mark.rutland@arm.com> wrote:
>
> On Mon, Aug 19, 2019 at 04:05:22PM +0200, Andrey Konovalov wrote:
> > On Mon, Aug 19, 2019 at 3:34 PM Will Deacon <will@kernel.org> wrote:
> > >
> > > On Mon, Aug 19, 2019 at 02:23:48PM +0100, Mark Rutland wrote:
> > > > On Mon, Aug 19, 2019 at 01:56:26PM +0100, Will Deacon wrote:
> > > > > On Mon, Aug 19, 2019 at 07:44:20PM +0800, Walter Wu wrote:
> > > > > > __arm_v7s_unmap() call iopte_deref() to translate pyh_to_virt address,
> > > > > > but it will modify pointer tag into 0xff, so there is a false positive.
> > > > > >
> > > > > > When enable tag-based kasan, phys_to_virt() function need to rewrite
> > > > > > its original pointer tag in order to avoid kasan report an incorrect
> > > > > > memory corruption.
> > > > >
> > > > > Hmm. Which tree did you see this on? We've recently queued a load of fixes
> > > > > in this area, but I /thought/ they were only needed after the support for
> > > > > 52-bit virtual addressing in the kernel.
> > > >
> > > > I'm seeing similar issues in the virtio blk code (splat below), atop of
> > > > the arm64 for-next/core branch. I think this is a latent issue, and
> > > > people are only just starting to test with KASAN_SW_TAGS.
> > > >
> > > > It looks like the virtio blk code will round-trip a SLUB-allocated pointer from
> > > > virt->page->virt, losing the per-object tag in the process.
> > > >
> > > > Our page_to_virt() seems to get a per-page tag, but this only makes
> > > > sense if you're dealing with the page allocator, rather than something
> > > > like SLUB which carves a page into smaller objects giving each object a
> > > > distinct tag.
> > > >
> > > > Any round-trip of a pointer from SLUB is going to lose the per-object
> > > > tag.
> > >
> > > Urgh, I wonder how this is supposed to work?
> > >
> > > If we end up having to check the KASAN shadow for *_to_virt(), then why
> > > do we need to store anything in the page flags at all? Andrey?
> >
> > As per 2813b9c0 ("kasan, mm, arm64: tag non slab memory allocated via
> > pagealloc") we should only save a non-0xff tag in page flags for non
> > slab pages.
> >
> > Could you share your .config so I can reproduce this?
>
> I wrote a test (below) to do so. :)
>
> It fires with arm64 defconfig, + CONFIG_TEST_KASAN=m.
>
> With Andrey Ryabinin's patch it works as expected with no KASAN splats
> for the two new test cases.

OK, Andrey's patch makes sense and fixes both Mark's test patch and
reports from CONFIG_IOMMU_IO_PGTABLE_ARMV7S_SELFTEST.

Tested-by: Andrey Konovalov <andreyknvl@google.com>
Reviewed-by: Andrey Konovalov <andreyknvl@google.com>

on both patches.

>
> Thanks,
> Mark.
>
> ---->8----
> From 7e8569b558fca21ad4e80fddae659591bc84ce1f Mon Sep 17 00:00:00 2001
> From: Mark Rutland <mark.rutland@arm.com>
> Date: Mon, 19 Aug 2019 15:39:32 +0100
> Subject: [PATCH] lib/test_kasan: add roundtrip tests
>
> In several places we needs to be able to operate on pointers which have

"needs" => "need"

> gone via a roundtrip:
>
>         virt -> {phys,page} -> virt
>
> With KASAN_SW_TAGS, we can't preserve the tag for SLUB objects, and the
> {phys,page} -> virt conversion will use KASAN_TAG_KERNEL.
>
> This patch adds tests to ensure that this works as expected, without
> false positives.
>
> Signed-off-by: Mark Rutland <mark.rutland@arm.com>
> Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
> Cc: Andrey Konovalov <andreyknvl@google.com>
> Cc: Will Deacon <will.deacon@arm.com>
> ---
>  lib/test_kasan.c | 40 ++++++++++++++++++++++++++++++++++++++++
>  1 file changed, 40 insertions(+)
>
> diff --git a/lib/test_kasan.c b/lib/test_kasan.c
> index b63b367a94e8..cf7b93f0d90c 100644
> --- a/lib/test_kasan.c
> +++ b/lib/test_kasan.c
> @@ -19,6 +19,8 @@
>  #include <linux/string.h>
>  #include <linux/uaccess.h>
>
> +#include <asm/page.h>
> +
>  /*
>   * Note: test functions are marked noinline so that their names appear in
>   * reports.
> @@ -337,6 +339,42 @@ static noinline void __init kmalloc_uaf2(void)
>         kfree(ptr2);
>  }
>
> +static noinline void __init kfree_via_page(void)
> +{
> +       char *ptr;
> +       size_t size = 8;
> +       struct page *page;
> +       unsigned long offset;
> +
> +       pr_info("invalid-free false positive (via page)\n");
> +       ptr = kmalloc(size, GFP_KERNEL);
> +       if (!ptr) {
> +               pr_err("Allocation failed\n");
> +               return;
> +       }
> +
> +       page = virt_to_page(ptr);
> +       offset = offset_in_page(ptr);
> +       kfree(page_address(page) + offset);
> +}
> +
> +static noinline void __init kfree_via_phys(void)
> +{
> +       char *ptr;
> +       size_t size = 8;
> +       phys_addr_t phys;
> +
> +       pr_info("invalid-free false positive (via phys)\n");
> +       ptr = kmalloc(size, GFP_KERNEL);
> +       if (!ptr) {
> +               pr_err("Allocation failed\n");
> +               return;
> +       }
> +
> +       phys = virt_to_phys(ptr);
> +       kfree(phys_to_virt(phys));
> +}
> +
>  static noinline void __init kmem_cache_oob(void)
>  {
>         char *p;
> @@ -737,6 +775,8 @@ static int __init kmalloc_tests_init(void)
>         kmalloc_uaf();
>         kmalloc_uaf_memset();
>         kmalloc_uaf2();
> +       kfree_via_page();
> +       kfree_via_phys();
>         kmem_cache_oob();
>         memcg_accounted_kmem_cache();
>         kasan_stack_oob();
> --
> 2.11.0
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2BwBNnnKY4wg%3D34aD8Of6Vea4nzWF-FEnnSpHN0pFyTR3Q%40mail.gmail.com.
