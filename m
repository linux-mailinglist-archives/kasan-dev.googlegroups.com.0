Return-Path: <kasan-dev+bncBDX4HWEMTEBRBS6M677QKGQEUJPAIDY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x638.google.com (mail-pl1-x638.google.com [IPv6:2607:f8b0:4864:20::638])
	by mail.lfdr.de (Postfix) with ESMTPS id 807262F37F9
	for <lists+kasan-dev@lfdr.de>; Tue, 12 Jan 2021 19:11:24 +0100 (CET)
Received: by mail-pl1-x638.google.com with SMTP id 98sf1971154pla.12
        for <lists+kasan-dev@lfdr.de>; Tue, 12 Jan 2021 10:11:24 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610475083; cv=pass;
        d=google.com; s=arc-20160816;
        b=cr6AFUT0Qk3pHnEAID+WrngNVLeCpemp4C8w7YGprmcOzRSrqt3sOSkOf4e9INhlR7
         rm5qzhUTuMpX2D7Fnfm/LYrVjHtN4WXYSRjJKjAK/Evm3zegh9KiCmV3wN1k8OWs4fKc
         kqy69GAqyc2Zh60+fOX4dWkvZNUOhuCjf8SnZkrHn41fWgjOF4cfQvZw3N1f8XuAMkzi
         lGmwGTGNJTtY+K6GblNKb6/8+1EXBmqWYaUi5paM+orBaKOISftRFdkxKCNyo6mn2Xft
         i1SkQIDLD2uz7sPAg34QJqxCjf1N4dfUC8sBMDNaD5nAwhkj0qOfuKpkty0SZ9I8cG2q
         C4Wg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=oiSeABXZTMlOHUoZ/c1wnma9/XsglEXKhdYgwfwpElM=;
        b=t82FGJLwo7teQmYEQ7x1b9tJet19lGX+gC04i+7Lbzp2WAUwlH48O0Dk9w1BVsDrNO
         qOcBKkaKxaqTZd8p1L5CN1wykJqOswuqFoTzBPBGoINTB4lHg/ay89qFQbFnWjsqvcY2
         TdL+1HeN2Xo7RMo49vf9AIgiT3OQLP2jVKRiK03yE0MTkaE8xRU3aSBIFk3aBd3/pyBd
         bwdMkcOKQ8exHyJLZXZrA5YIb5uoPf2kfZ41RViDiiKYbbigqX4y3b2lfVyb1eLqh9Bu
         re4BHntMIHVvqR+7XRIM8vBZxzBlplaJWVYJCbdUiVekOpbQcjB7ZFexOSUyrDKna3DF
         YSYg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=k2Vk8XGG;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::62b as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=oiSeABXZTMlOHUoZ/c1wnma9/XsglEXKhdYgwfwpElM=;
        b=Dw4kzCK9/yp6QMVzSiprDacp3/+C7z0bsjw1AWDaeyoekA+z+X8fkpD1r44VA5F5b4
         MCveeJLZEi11Su07+Ll3qnU+SFWre38KkMRZx2klVQvkma7/v3VMdJgRYahnVh8Ig8AC
         ZluKpZPw8PRdlIzXBAvjlsq1/CPiPFPuKmN9q0Kp1iz/wCG7povKX4E4RqTBgcU2HubP
         rC9YtsOk8waz0wdoCD2U5uZyJc8+OPMKvsopF9hoGuupax53ps+5zZ9d3G1XFeOPV4Sd
         1u8/nE1rY8d3CfPAjtEZmNHgMlTQ0AWtTMUh/xdmKp4XM4WM/Jsfr3n4uGI1bUtJ/tbg
         lfvQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=oiSeABXZTMlOHUoZ/c1wnma9/XsglEXKhdYgwfwpElM=;
        b=ibkDHNLlQIrBlHzgkm/cnlNY0kwJtgWGsrNyeRH8zsCLwKxIjO+q7o3PxDbSmsSW7J
         PX6NCFGBuXnAEgKsHezH7X3vvp1LObenrWYIGrTPUWL3E8LLxMO9PBKdnKMRcFDnJrd1
         8hRaYvdFQc1ZGlB9/iyJK70fARYICVKCheFifDnCOJpwnNCq6jHx06k90txDmGVRwEmf
         7iam91Ql0f/rNqxOMbJcO+PBu0Mx5Whwm7lLK1LBNMjYqJn+iqPA2v0HiMsAT/Y30yoy
         cg2BUW0izc91yIDEM4EcuyunXf4i5A47mkRuIDyeIx8CP7HnJmRX4tJdMVxJQ+tHmR+H
         nxVQ==
X-Gm-Message-State: AOAM530FK7Ug/IkK/KCBAkJzfwox937k26ytfjOTx7rcEErbc1OKUJgB
	eDwTqi7BRLRGxYv9tXCez3I=
X-Google-Smtp-Source: ABdhPJwflIdEJT4VI4IT52XR9K2y6hAWgtU41wTYDfRDqKPFn2NGPhrm/ymD++gDwgsx5TCHaSN59g==
X-Received: by 2002:a17:90a:fc8e:: with SMTP id ci14mr322700pjb.181.1610475083124;
        Tue, 12 Jan 2021 10:11:23 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:bc47:: with SMTP id t7ls1978016pjv.2.gmail; Tue, 12
 Jan 2021 10:11:22 -0800 (PST)
X-Received: by 2002:a17:90a:ae07:: with SMTP id t7mr320365pjq.115.1610475082592;
        Tue, 12 Jan 2021 10:11:22 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610475082; cv=none;
        d=google.com; s=arc-20160816;
        b=ofCMqJ/NSkU7mcS31xQJdMD4/kWv78Sv4ZbB/IJUW51Y2OClnaSWIccVegcnN/qzd3
         KeWyLrTrbgQeGDt6eSJszahffMRtN3gnpkvjFB1D8k/wa/sEwwtOboM2zYDN6qfkUfX0
         rmMh/NEIujLzY2MR+FxX/k8g9yVpsv2oYHf+/w/eoAusf8PqzXeQl/oiDmpYgbwtTc1m
         vfiFVKgOaUDzrM2kJVCGcpeUHxQfcq9N2V/ejrf7jH9NmdHVp9C5FYtj/vKyDatRqjSz
         O6xDK4LSIEFx+2Avqh1cM+xrHDXFd4I7JTBZeVJvjB/geu4d6gpbE0j7cpZLHFuyVb8K
         Qk8A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=KHIuhecZMVyLx+ijiJ0VpXni4YAkn1lcKgd4j/76ieY=;
        b=UoX2bDGw4YYwS5rnmJKsk3vL+5s7OzBordLI1lKVaftsTlPGX+P34hPbr3IfWX8W4B
         LGEo44DlGLswHLCyzyoflwI2M4vUTK3ZNtLtGReMOSy1yZSW+ED6l7HHDmyjO2oJCLck
         ZGqycgy23Czm/C7hVEyVU4PN17ARIV/S7Qc/U9RTHfNcZydST8W0HwmGyKHIQddhlZqj
         AOOmVb1C6rHltsXmhk2kdFnhe3GZ078zicigTXJe47S9V9dARl/ONOg62q2sw37XLGqJ
         ImF02/pZ/shVNQzjUiibha3dX/AYw4inpuzcpQ7wiJg9nWtAJnWKGBR6Ivb/zt3xZouQ
         Dtyw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=k2Vk8XGG;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::62b as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pl1-x62b.google.com (mail-pl1-x62b.google.com. [2607:f8b0:4864:20::62b])
        by gmr-mx.google.com with ESMTPS id e193si217799pfh.2.2021.01.12.10.11.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 12 Jan 2021 10:11:22 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::62b as permitted sender) client-ip=2607:f8b0:4864:20::62b;
Received: by mail-pl1-x62b.google.com with SMTP id b8so1338268plh.12
        for <kasan-dev@googlegroups.com>; Tue, 12 Jan 2021 10:11:22 -0800 (PST)
X-Received: by 2002:a17:90b:1087:: with SMTP id gj7mr343606pjb.41.1610475082106;
 Tue, 12 Jan 2021 10:11:22 -0800 (PST)
MIME-Version: 1.0
References: <cover.1609871239.git.andreyknvl@google.com> <0f20f867d747b678604a68173a5f20fb8df9b756.1609871239.git.andreyknvl@google.com>
 <X/2hboi2Tp87UZFZ@elver.google.com>
In-Reply-To: <X/2hboi2Tp87UZFZ@elver.google.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 12 Jan 2021 19:11:10 +0100
Message-ID: <CAAeHK+xW+4m140OKa4QG_x1Y-74xnMoxhzpSRszUdm9ZyAkMbA@mail.gmail.com>
Subject: Re: [PATCH 04/11] kasan: add match-all tag tests
To: Marco Elver <elver@google.com>
Cc: Catalin Marinas <catalin.marinas@arm.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Alexander Potapenko <glider@google.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Will Deacon <will.deacon@arm.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Evgenii Stepanov <eugenis@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=k2Vk8XGG;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::62b
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

On Tue, Jan 12, 2021 at 2:17 PM Marco Elver <elver@google.com> wrote:
>
> On Tue, Jan 05, 2021 at 07:27PM +0100, Andrey Konovalov wrote:
> > Add 3 new tests for tag-based KASAN modes:
> >
> > 1. Check that match-all pointer tag is not assigned randomly.
> > 2. Check that 0xff works as a match-all pointer tag.
> > 3. Check that there are no match-all memory tags.
> >
> > Note, that test #3 causes a significant number (255) of KASAN reports
> > to be printed during execution for the SW_TAGS mode.
> >
> > Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> > Link: https://linux-review.googlesource.com/id/I78f1375efafa162b37f3abcb2c5bc2f3955dfd8e
> > ---
> >  lib/test_kasan.c | 93 ++++++++++++++++++++++++++++++++++++++++++++++++
> >  mm/kasan/kasan.h |  6 ++++
> >  2 files changed, 99 insertions(+)
> >
> > diff --git a/lib/test_kasan.c b/lib/test_kasan.c
> > index 46e578c8e842..f1eda0bcc780 100644
> > --- a/lib/test_kasan.c
> > +++ b/lib/test_kasan.c
> > @@ -13,6 +13,7 @@
> >  #include <linux/mman.h>
> >  #include <linux/module.h>
> >  #include <linux/printk.h>
> > +#include <linux/random.h>
> >  #include <linux/slab.h>
> >  #include <linux/string.h>
> >  #include <linux/uaccess.h>
> > @@ -790,6 +791,95 @@ static void vmalloc_oob(struct kunit *test)
> >       vfree(area);
> >  }
> >
> > +/*
> > + * Check that match-all pointer tag is not assigned randomly for
> > + * tag-based modes.
> > + */
> > +static void match_all_not_assigned(struct kunit *test)
> > +{
> > +     char *ptr;
> > +     struct page *pages;
> > +     int i, size, order;
> > +
> > +     for (i = 0; i < 256; i++) {
> > +             size = get_random_int() % KMALLOC_MAX_SIZE;
>
> size appears to be unused?

Indeed, will fix in v2, thanks!

>
> > +             ptr = kmalloc(128, GFP_KERNEL);
> > +             KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
> > +             KUNIT_EXPECT_NE(test, (u8)get_tag(ptr), (u8)KASAN_TAG_KERNEL);
> > +             kfree(ptr);
> > +     }
> > +
> > +     for (i = 0; i < 256; i++) {
> > +             order = get_random_int() % 4;
> > +             pages = alloc_pages(GFP_KERNEL, order);
> > +             ptr = page_address(pages);
> > +             KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
> > +             KUNIT_EXPECT_NE(test, (u8)get_tag(ptr), (u8)KASAN_TAG_KERNEL);
> > +             free_pages((unsigned long)ptr, order);
> > +     }
> > +}
> > +
> > +/* Check that 0xff works as a match-all pointer tag for tag-based modes. */
> > +static void match_all_ptr_tag(struct kunit *test)
> > +{
> > +     char *ptr;
> > +     u8 tag;
> > +
> > +     if (IS_ENABLED(CONFIG_KASAN_GENERIC)) {
> > +             kunit_info(test, "skipping, CONFIG_KASAN_SW/HW_TAGS required");
> > +             return;
> > +     }
> > +
> > +     ptr = kmalloc(128, GFP_KERNEL);
> > +     KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
> > +
> > +     /* Backup the assigned tag. */
> > +     tag = get_tag(ptr);
> > +     KUNIT_EXPECT_NE(test, tag, (u8)KASAN_TAG_KERNEL);
> > +
> > +     /* Reset the tag to 0xff.*/
> > +     ptr = set_tag(ptr, KASAN_TAG_KERNEL);
> > +
> > +     /* This access shouldn't trigger a KASAN report. */
> > +     *ptr = 0;
> > +
> > +     /* Recover the pointer tag and free. */
> > +     ptr = set_tag(ptr, tag);
> > +     kfree(ptr);
> > +}
> > +
> > +/* Check that there are no match-all memory tags for tag-based modes. */
> > +static void match_all_mem_tag(struct kunit *test)
> > +{
> > +     char *ptr;
> > +     int tag;
> > +
> > +     if (IS_ENABLED(CONFIG_KASAN_GENERIC)) {
> > +             kunit_info(test, "skipping, CONFIG_KASAN_SW/HW_TAGS required");
> > +             return;
> > +     }
> > +
> > +     ptr = kmalloc(128, GFP_KERNEL);
> > +     KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
> > +     KUNIT_EXPECT_NE(test, (u8)get_tag(ptr), (u8)KASAN_TAG_KERNEL);
> > +
> > +     /* For each possible tag value not matching the pointer tag. */
> > +     for (tag = KASAN_TAG_MIN; tag <= KASAN_TAG_KERNEL; tag++) {
> > +             if (tag == get_tag(ptr))
> > +                     continue;
> > +
> > +             /* Mark the first memory granule with the chosen memory tag. */
> > +             kasan_poison(ptr, KASAN_GRANULE_SIZE, (u8)tag);
> > +
> > +             /* This access must cause a KASAN report. */
> > +             KUNIT_EXPECT_KASAN_FAIL(test, *ptr = 0);
> > +     }
> > +
> > +     /* Recover the memory tag and free. */
> > +     kasan_poison(ptr, KASAN_GRANULE_SIZE, get_tag(ptr));
> > +     kfree(ptr);
> > +}
> > +
> >  static struct kunit_case kasan_kunit_test_cases[] = {
> >       KUNIT_CASE(kmalloc_oob_right),
> >       KUNIT_CASE(kmalloc_oob_left),
> > @@ -829,6 +919,9 @@ static struct kunit_case kasan_kunit_test_cases[] = {
> >       KUNIT_CASE(kasan_bitops_tags),
> >       KUNIT_CASE(kmalloc_double_kzfree),
> >       KUNIT_CASE(vmalloc_oob),
> > +     KUNIT_CASE(match_all_not_assigned),
> > +     KUNIT_CASE(match_all_ptr_tag),
> > +     KUNIT_CASE(match_all_mem_tag),
> >       {}
> >  };
> >
> > diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
> > index 3b38baddec47..c3fb9bf241d3 100644
> > --- a/mm/kasan/kasan.h
> > +++ b/mm/kasan/kasan.h
> > @@ -36,6 +36,12 @@ extern bool kasan_flag_panic __ro_after_init;
> >  #define KASAN_TAG_INVALID    0xFE /* inaccessible memory tag */
> >  #define KASAN_TAG_MAX                0xFD /* maximum value for random tags */
> >
> > +#ifdef CONFIG_KASAN_HW_TAGS
> > +#define KASAN_TAG_MIN                0xF0 /* mimimum value for random tags */
> > +#else
> > +#define KASAN_TAG_MIN                0x00 /* mimimum value for random tags */
> > +#endif
> > +
> >  #ifdef CONFIG_KASAN_GENERIC
> >  #define KASAN_FREE_PAGE         0xFF  /* page was freed */
> >  #define KASAN_PAGE_REDZONE      0xFE  /* redzone for kmalloc_large allocations */
> > --
> > 2.29.2.729.g45daf8777d-goog
> >

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2BxW%2B4m140OKa4QG_x1Y-74xnMoxhzpSRszUdm9ZyAkMbA%40mail.gmail.com.
