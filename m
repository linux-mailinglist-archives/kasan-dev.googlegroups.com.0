Return-Path: <kasan-dev+bncBDV37XP3XYDRBVHU5LVAKGQEDMRAC2A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x137.google.com (mail-lf1-x137.google.com [IPv6:2a00:1450:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id E0FB3927D2
	for <lists+kasan-dev@lfdr.de>; Mon, 19 Aug 2019 17:03:48 +0200 (CEST)
Received: by mail-lf1-x137.google.com with SMTP id p9sf596844lfo.16
        for <lists+kasan-dev@lfdr.de>; Mon, 19 Aug 2019 08:03:48 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1566227028; cv=pass;
        d=google.com; s=arc-20160816;
        b=xO16GSgQTmbQlw1504MYhbqoCzhIDVMp1dudBzApZOjnWrXPAQeJXx4XZC2bOh8NRO
         sbbwypZ746mNg14bfdCqwBQQG9PQdc/WodlIIAM7nPa2gu1fIPxS6mgNQP0U+2JWim03
         ZmnSWFPM2iF4ayL++uVUD4UaC8nx5dB+bFg1ca0M2XnWDndQfN3eO4EPSYTVyv7EJN/E
         wycZ8M0MzQG40uEisF8Y/T74Mzg8ZURSkCGQS+Py7tvH7T9IXIeoq1inV/jP/6NGGluB
         dJSpCNODlXpVa4Msx8tPa3wk5dovCkXqH03gc7GtYLHAno+lcgV5/78z5Q3JazZ5laqx
         aJag==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=qk40JHxCN8v8YhicPUKUiAoLtskuJs+u3vYHki62IKo=;
        b=HFcGjzqvOt1uOh7lTSdSZF6boenND0e4dneyVNTtWmPLuXw9kvabtulupJGfVNPZv+
         EhGFhq+TJzcZbMyytMAjurB/TbosYIj/1nKXimobufrK/cMtdhleGHL0+JaQ6xnwZbRq
         axvFWBKHmNHCmf2nBhAJF/LfbkuowJS23jE1LwkBG4E1brgELoLtdWRzyEarpxHuf6AP
         z3yBoa7NiFAfytKxY3C9N3pL2wyCXtrb9i8xZAclyviMGcx7MiYGrwZwwptx0Sxf4nva
         zcjgcbDnLo1N15de9AECbTeVabqeSFQ9PdKw1ifUkGqJOh3uLexLKKNwEqSQ3Fu7JLD7
         dxGQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=qk40JHxCN8v8YhicPUKUiAoLtskuJs+u3vYHki62IKo=;
        b=eGngJ6kX10MA4EVeECfZT6ruoUL+A1WV5CBuea+RW0lypoaJq7slwsB5auiD6Akn30
         C2GtRJINpLSMU9jOxv3EpXkFNbu4KjpCDI9SBvS6foal+agTWdlHD+xsr/HEhs5LNkQk
         hbtmNAlBU+VdMomPHJOuaj6WC6LuIUqMaWmBasoJdVaPl6P6sL6nPNGZzB9WPR3wDBxw
         1MadovAMEJwsY8Sjx4wqhrHaTJFcAmsDWL6R8f7yGeOquZR31hdEXrayNekqPN/sOZDV
         4IhvbczDjbMkgfLftryX95AltY0UB8BfEgbWBxpAbF2idCIuTYEZK4IgKEy7FyPAnNLU
         xW0w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=qk40JHxCN8v8YhicPUKUiAoLtskuJs+u3vYHki62IKo=;
        b=lbX4pH8gPDfcXsMGT30dKXoBFy625j2qt61rzFq/KhdCXx+uRjI6E/tqPsRva/n/j+
         DpY3cE1aQB0TIiJUg8jYSdLNH5vxK1yozMZxMfZ+I0HVuRMK/LlXuwmFLNq2zcFh5Rli
         MS1SIQzKnHFp4SJs81lnhAWB7DEKfeEgx+WlxI0bSvii7ZZFmprV81A3AXJL4mWSNrGf
         eimg5lJn9M7hYT5F7jmq4wFbZMq0eWM/kRVOI0yFQhPLUk57XcOFbLVCvj1STLOKhv84
         v61qYZ9/nqlXikZsD5YB2ygW2yKmZntHuMmKkcKmIVgI1FJxwJPqsdH/csO9fkpWCFDI
         qKkQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAVsgz4TFM/EFbF4KoB2jZGuJJ9IXYiqYaC/PCGcQnxnJzwpaxr5
	YqJiiZ87jGkbx+KbC0q9zW8=
X-Google-Smtp-Source: APXvYqyG9SncfTvnxpyrUbVwBC9Ix6GgpY7R71N6tQfTuyK7P4DdMexAJ5M5TT3dCl4NjDyY0zoLpQ==
X-Received: by 2002:a19:5f0f:: with SMTP id t15mr12967425lfb.67.1566227028497;
        Mon, 19 Aug 2019 08:03:48 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:3018:: with SMTP id w24ls528067ljw.16.gmail; Mon, 19 Aug
 2019 08:03:47 -0700 (PDT)
X-Received: by 2002:a2e:93cc:: with SMTP id p12mr7254011ljh.11.1566227027706;
        Mon, 19 Aug 2019 08:03:47 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1566227027; cv=none;
        d=google.com; s=arc-20160816;
        b=vK9IC3Gb1poHNBxMq8TxBiaXbeCR+WrQ5B6QSjTyxF5jB+6L0UbKT+J0HRI7xg5x67
         fYycTeYg0MoB3evVK+L3URsg1ujsrA0fAgOWbkQ02FXdytJo5+Dqe0jHawRjaYQF7Wg5
         mhQSfdTAnJegW0SL9KaeaG400wM64AuClqk4HmxVllN3XLItWRdB7wByVflV2KeEqQ/Z
         uUwwKqVMp4hKrGFSjiMjzcknGPstdP9ZTADce6cLPnWW7Sc++Qv2vMu6FgcN0AHgZy9V
         p/cfs7Rc9EkPaIjz2/o5hat/D+SlmXcpNLD+Zay6PSgXvShjGzEH6vPVMK6ts9too7Qv
         1kXw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=6gedQF1oAlKbYpLVsje6vjKN/MUaaleEIqdnGFB/nKQ=;
        b=jLPBh6py9kl6vV2RvgQR4B+t0kvqrlVcH0+ClEg058YocAIM2h3WnAN1JqqMm4iHEY
         2sfVyF99xvZumLBimZpXtw0rRJ8Zz6uqVDWSZIB7GMfBOGilsxAHqpEqATCUtv04A2QJ
         EmL/Y6Z/g2Ti7UnOnilljl3rJNd93zEfbOPv8cpgF7s2w7VjRaNPLoY2hlca72gjFk78
         wSFwp30u+jfJYOv7F0xzjYl2srgRqLPtY9BWftLLF1BpFQGaD0e/QZf6mqj+w6OH0TdV
         GwDseXn9UOqGvVELdfpJ2FG6S17obs6IihkEIpRwmRdPxrHqHk1MgALVwsGT2eBHSFzb
         t/KQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id h11si99095lja.2.2019.08.19.08.03.46
        for <kasan-dev@googlegroups.com>;
        Mon, 19 Aug 2019 08:03:47 -0700 (PDT)
Received-SPF: pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id DD2E428;
	Mon, 19 Aug 2019 08:03:45 -0700 (PDT)
Received: from lakrids.cambridge.arm.com (usa-sjc-imap-foss1.foss.arm.com [10.121.207.14])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 009D53F718;
	Mon, 19 Aug 2019 08:03:43 -0700 (PDT)
Date: Mon, 19 Aug 2019 16:03:41 +0100
From: Mark Rutland <mark.rutland@arm.com>
To: Andrey Konovalov <andreyknvl@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Will Deacon <will@kernel.org>
Cc: Walter Wu <walter-zh.wu@mediatek.com>,
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
Message-ID: <20190819150341.GC9927@lakrids.cambridge.arm.com>
References: <20190819114420.2535-1-walter-zh.wu@mediatek.com>
 <20190819125625.bu3nbrldg7te5kwc@willie-the-truck>
 <20190819132347.GB9927@lakrids.cambridge.arm.com>
 <20190819133441.ejomv6cprdcz7hh6@willie-the-truck>
 <CAAeHK+w7cTGN8SgWQs0bPjPOrizqfUoMnJWTvUkCqv17Qt=3oQ@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CAAeHK+w7cTGN8SgWQs0bPjPOrizqfUoMnJWTvUkCqv17Qt=3oQ@mail.gmail.com>
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

On Mon, Aug 19, 2019 at 04:05:22PM +0200, Andrey Konovalov wrote:
> On Mon, Aug 19, 2019 at 3:34 PM Will Deacon <will@kernel.org> wrote:
> >
> > On Mon, Aug 19, 2019 at 02:23:48PM +0100, Mark Rutland wrote:
> > > On Mon, Aug 19, 2019 at 01:56:26PM +0100, Will Deacon wrote:
> > > > On Mon, Aug 19, 2019 at 07:44:20PM +0800, Walter Wu wrote:
> > > > > __arm_v7s_unmap() call iopte_deref() to translate pyh_to_virt address,
> > > > > but it will modify pointer tag into 0xff, so there is a false positive.
> > > > >
> > > > > When enable tag-based kasan, phys_to_virt() function need to rewrite
> > > > > its original pointer tag in order to avoid kasan report an incorrect
> > > > > memory corruption.
> > > >
> > > > Hmm. Which tree did you see this on? We've recently queued a load of fixes
> > > > in this area, but I /thought/ they were only needed after the support for
> > > > 52-bit virtual addressing in the kernel.
> > >
> > > I'm seeing similar issues in the virtio blk code (splat below), atop of
> > > the arm64 for-next/core branch. I think this is a latent issue, and
> > > people are only just starting to test with KASAN_SW_TAGS.
> > >
> > > It looks like the virtio blk code will round-trip a SLUB-allocated pointer from
> > > virt->page->virt, losing the per-object tag in the process.
> > >
> > > Our page_to_virt() seems to get a per-page tag, but this only makes
> > > sense if you're dealing with the page allocator, rather than something
> > > like SLUB which carves a page into smaller objects giving each object a
> > > distinct tag.
> > >
> > > Any round-trip of a pointer from SLUB is going to lose the per-object
> > > tag.
> >
> > Urgh, I wonder how this is supposed to work?
> >
> > If we end up having to check the KASAN shadow for *_to_virt(), then why
> > do we need to store anything in the page flags at all? Andrey?
> 
> As per 2813b9c0 ("kasan, mm, arm64: tag non slab memory allocated via
> pagealloc") we should only save a non-0xff tag in page flags for non
> slab pages.
> 
> Could you share your .config so I can reproduce this?

I wrote a test (below) to do so. :)

It fires with arm64 defconfig, + CONFIG_TEST_KASAN=m.

With Andrey Ryabinin's patch it works as expected with no KASAN splats
for the two new test cases.

Thanks,
Mark.

---->8----
From 7e8569b558fca21ad4e80fddae659591bc84ce1f Mon Sep 17 00:00:00 2001
From: Mark Rutland <mark.rutland@arm.com>
Date: Mon, 19 Aug 2019 15:39:32 +0100
Subject: [PATCH] lib/test_kasan: add roundtrip tests

In several places we needs to be able to operate on pointers which have
gone via a roundtrip:

	virt -> {phys,page} -> virt

With KASAN_SW_TAGS, we can't preserve the tag for SLUB objects, and the
{phys,page} -> virt conversion will use KASAN_TAG_KERNEL.

This patch adds tests to ensure that this works as expected, without
false positives.

Signed-off-by: Mark Rutland <mark.rutland@arm.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
Cc: Andrey Konovalov <andreyknvl@google.com>
Cc: Will Deacon <will.deacon@arm.com>
---
 lib/test_kasan.c | 40 ++++++++++++++++++++++++++++++++++++++++
 1 file changed, 40 insertions(+)

diff --git a/lib/test_kasan.c b/lib/test_kasan.c
index b63b367a94e8..cf7b93f0d90c 100644
--- a/lib/test_kasan.c
+++ b/lib/test_kasan.c
@@ -19,6 +19,8 @@
 #include <linux/string.h>
 #include <linux/uaccess.h>
 
+#include <asm/page.h>
+
 /*
  * Note: test functions are marked noinline so that their names appear in
  * reports.
@@ -337,6 +339,42 @@ static noinline void __init kmalloc_uaf2(void)
 	kfree(ptr2);
 }
 
+static noinline void __init kfree_via_page(void)
+{
+	char *ptr;
+	size_t size = 8;
+	struct page *page;
+	unsigned long offset;
+
+	pr_info("invalid-free false positive (via page)\n");
+	ptr = kmalloc(size, GFP_KERNEL);
+	if (!ptr) {
+		pr_err("Allocation failed\n");
+		return;
+	}
+
+	page = virt_to_page(ptr);
+	offset = offset_in_page(ptr);
+	kfree(page_address(page) + offset);
+}
+
+static noinline void __init kfree_via_phys(void)
+{
+	char *ptr;
+	size_t size = 8;
+	phys_addr_t phys;
+
+	pr_info("invalid-free false positive (via phys)\n");
+	ptr = kmalloc(size, GFP_KERNEL);
+	if (!ptr) {
+		pr_err("Allocation failed\n");
+		return;
+	}
+
+	phys = virt_to_phys(ptr);
+	kfree(phys_to_virt(phys));
+}
+
 static noinline void __init kmem_cache_oob(void)
 {
 	char *p;
@@ -737,6 +775,8 @@ static int __init kmalloc_tests_init(void)
 	kmalloc_uaf();
 	kmalloc_uaf_memset();
 	kmalloc_uaf2();
+	kfree_via_page();
+	kfree_via_phys();
 	kmem_cache_oob();
 	memcg_accounted_kmem_cache();
 	kasan_stack_oob();
-- 
2.11.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20190819150341.GC9927%40lakrids.cambridge.arm.com.
