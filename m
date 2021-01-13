Return-Path: <kasan-dev+bncBC7OBJGL2MHBBX567T7QKGQEEEKGPZY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53c.google.com (mail-pg1-x53c.google.com [IPv6:2607:f8b0:4864:20::53c])
	by mail.lfdr.de (Postfix) with ESMTPS id 74C7A2F4FEF
	for <lists+kasan-dev@lfdr.de>; Wed, 13 Jan 2021 17:27:13 +0100 (CET)
Received: by mail-pg1-x53c.google.com with SMTP id n2sf1786817pgj.12
        for <lists+kasan-dev@lfdr.de>; Wed, 13 Jan 2021 08:27:13 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610555232; cv=pass;
        d=google.com; s=arc-20160816;
        b=ta+ogrQyvli95CVtWfAyxolnN/ZOfO6daVMV8/9IaneSZRULCQl2V/ItpMYySv3ho7
         pRvcCCfsYZ7TM+CqcWmGzEasHSUPU8C1UgZOczrmvOkqnNB8VNRh7pNZSoFqBRTyXUXO
         1XXLs4avmzwrDUt/3micufnqSF0fgLlPClx2zvbY4rFEoGfji+fIXoMg5TrurV97p08W
         dlZvt7DDvBJRi//gxaz0q9TKXoTMWzmp4l398kxehed0mQxUyCZ0adilz5qo5A/gR74d
         0sqcUVPuiP1eRBIGgGNKdE2EpE+JJyAVAKGAT+bVzZZLlaebgUE7344mRRStE2IZ93Bf
         QByg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=j0ngxMMN+SYSyakm8SNBpOdvrvD1ROfiLRZMSf7c+j8=;
        b=iOn+2JRXNC9PwWHgR33EFeaSsLm0yI+RcgmhaWEMaffeg6zEELgDP5e9VwIQcnghUc
         cBw35F1BcsJaD+YSlS9/OMdCRuDv185c5QSkWXCIEBYkHQ01Vc2ChSDBOcYDdigqNE1R
         StNFk/2nKoWRJenQSFwHTBoqJkMbRI4b7M8NB2kT9UHCz0PH/J4e+hW8d8SHoiauS9+v
         ROjxr1BqqMIqPV5jh6Jx+qnav5g+GQTKFyIKotZLl9nppffnMF/fIwL6N5v9F9bHJmPN
         dhBuaZu79caUVLYH5eAFuHgdES9/H7TxXFQapgi3bY8PhqbgUkzu1aeDw6Nu9PQZwhVJ
         06Kg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=k902rbsb;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::335 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=j0ngxMMN+SYSyakm8SNBpOdvrvD1ROfiLRZMSf7c+j8=;
        b=Nba3qbRJSFUWpW4zXx0Y7AQVdoSaxLk6SJEk6SfjhZdBF/k7t9yy9CrVTEO1u4ZLzH
         7v0jHwGfs1ImhoscX816s2iYNWKdDbHg4ys1lkAZZ1irZyXvyXI5KQP6Dfdn7K3fqIWy
         njP95sb+PF0daiq45iykPLHpkNPgGMy+ed6ovrhcq2/fGinDmZ/6XRDU2u9a/cIX4pd5
         i6v9A3KZeqPL9PeOF3fIDkr1RuXOG+qJ7ZXLpP71qtjGE7xnLAtrruKx/q2hdo+0KJnD
         sZv+Qw0GDCPPc6KUKocgdgEiFi2J7JOlUX9zp6Co5EW4QqoTkMuiSpuafhGV9ccxJ100
         zzHQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=j0ngxMMN+SYSyakm8SNBpOdvrvD1ROfiLRZMSf7c+j8=;
        b=att4yBgIdvq2R3bK2MYTODZx63YM8p60OAnXl4zGoUOA36HZbcKS+5zeXzppQuay+5
         TBQQpifyAmurAPbhx+yt1iCR9tsJrTf5WJEsvW4lW6dBU9BVs74ch7v1w8F/z1LpLjbV
         IHL1tABBT4MgjDfuT/fSrBVTPB0oeWozHCmocsfHBHd5OuaTggtL+UhGSxD2He/heYo8
         BjMp/ODnGpgIL3sh7DZ9xEToeSyLov3iM2+VIw3Pdeevt2POBVCFulpqBjwzLc3O7Ks9
         FSUG/jo9Dx9VSH6LIaKuoUli2keaOBnrd3qlmFC+VD3//6OBkqvAm1UM2QdDRaZe7SKn
         JLbw==
X-Gm-Message-State: AOAM530d4+tgFSkolHtFsAfELO9Ry2S1P7VwNcyF9OsJHRmcT1jyYjWY
	i2Q2hmex1wviNeJdBezxL6I=
X-Google-Smtp-Source: ABdhPJyYAZhuQzkuwYSzVEODB1TPYnUl1pliaDd++KG1qATWZWcZwqx2WO/l2sZ6rMGYXdZE6q6y5g==
X-Received: by 2002:a63:e049:: with SMTP id n9mr2767104pgj.339.1610555231706;
        Wed, 13 Jan 2021 08:27:11 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:e287:: with SMTP id d7ls1408272pjz.0.gmail; Wed, 13
 Jan 2021 08:27:10 -0800 (PST)
X-Received: by 2002:a17:90a:301:: with SMTP id 1mr32417pje.195.1610555230657;
        Wed, 13 Jan 2021 08:27:10 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610555230; cv=none;
        d=google.com; s=arc-20160816;
        b=rrVJO3tLx+LcT2zfCu0EO828aj5nZE/nYKYqYRMIqN5j/rTUqiNKwFTPUIFOy5BBG0
         Q0lYyp/weEoQbtoue0HMAddZpIIMR7SR+JaTqisPy6+xb/eyIurZpA3xMJxNje7VKIVc
         CiWOGUCd09/wz1NbyRIhYCt/MXwxNuQ1B4Wce25eiMuV1rHju2rNAlmqbl9f3szGN/b5
         ekx42eRp6e7F9IFKhMfNDuSwbpRuMHJxmJRXDYCUaJOhMJQl0P+v0Pdbl/Ghvh62puqN
         T2cL+rUZP1XFBDR3w7dgPYvfk42nXxwyk0bJZYqmPsGrshd9cWqs2P2MLcg1766vEAWf
         GiLA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=ToZseukMUfS4/Mno4fjs/e3BlupSLArbp20G4eoQPpc=;
        b=WxY2+3I+2JBJwAFSp65ZJLKoC3Np+69ro2phtU0lojIqOEQdCoxI5cTThyRxIo9HCD
         H0db+unKmiTrd3AdVFhpJ5LJ1BblybCgKao+K6rHnYcNtWXbhUuRdM8s9tby3emSi4f1
         eD2DCr3b/Qhan6Jr64+ykUUdIRJY7tOG2HW13lSqc00gCh6IrpQb6OLsVv5JeTy8P7cL
         zVFolfXR05WCoh6Loc8nBPfP7D+7ZBmuVvmH5n/LLO3s5pv7VznOf/Dh7c7qV9ZJD+WP
         rWzWhMQfpG0SRL9HAmNPoyITnMXnyFv0ZMVx5/zCQahAXka5rCsAjyHQfbfDGUPOp7W/
         GOvg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=k902rbsb;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::335 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x335.google.com (mail-ot1-x335.google.com. [2607:f8b0:4864:20::335])
        by gmr-mx.google.com with ESMTPS id r142si165725pfr.0.2021.01.13.08.27.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 13 Jan 2021 08:27:10 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::335 as permitted sender) client-ip=2607:f8b0:4864:20::335;
Received: by mail-ot1-x335.google.com with SMTP id d20so2441986otl.3
        for <kasan-dev@googlegroups.com>; Wed, 13 Jan 2021 08:27:10 -0800 (PST)
X-Received: by 2002:a05:6830:2413:: with SMTP id j19mr1826937ots.251.1610555230134;
 Wed, 13 Jan 2021 08:27:10 -0800 (PST)
MIME-Version: 1.0
References: <cover.1610554432.git.andreyknvl@google.com> <351f554b6e4c4c0581d15d7b70cbbacf238c887f.1610554432.git.andreyknvl@google.com>
In-Reply-To: <351f554b6e4c4c0581d15d7b70cbbacf238c887f.1610554432.git.andreyknvl@google.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 13 Jan 2021 17:26:58 +0100
Message-ID: <CANpmjNP-r3CcgCnenJEbHB5_RNfnFDF7x=4uufLVbqRZtqGd7g@mail.gmail.com>
Subject: Re: [PATCH v2 05/14] kasan: add match-all tag tests
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Catalin Marinas <catalin.marinas@arm.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Alexander Potapenko <glider@google.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Will Deacon <will.deacon@arm.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Peter Collingbourne <pcc@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=k902rbsb;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::335 as
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

On Wed, 13 Jan 2021 at 17:21, Andrey Konovalov <andreyknvl@google.com> wrote:
>
> Add 3 new tests for tag-based KASAN modes:
>
> 1. Check that match-all pointer tag is not assigned randomly.
> 2. Check that 0xff works as a match-all pointer tag.
> 3. Check that there are no match-all memory tags.
>
> Note, that test #3 causes a significant number (255) of KASAN reports
> to be printed during execution for the SW_TAGS mode.
>
> Link: https://linux-review.googlesource.com/id/I78f1375efafa162b37f3abcb2c5bc2f3955dfd8e
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

Reviewed-by: Marco Elver <elver@google.com>

> ---
>  lib/test_kasan.c | 92 ++++++++++++++++++++++++++++++++++++++++++++++++
>  mm/kasan/kasan.h |  6 ++++
>  2 files changed, 98 insertions(+)
>
> diff --git a/lib/test_kasan.c b/lib/test_kasan.c
> index 714ea27fcc3e..f5470bed50b6 100644
> --- a/lib/test_kasan.c
> +++ b/lib/test_kasan.c
> @@ -13,6 +13,7 @@
>  #include <linux/mman.h>
>  #include <linux/module.h>
>  #include <linux/printk.h>
> +#include <linux/random.h>
>  #include <linux/slab.h>
>  #include <linux/string.h>
>  #include <linux/uaccess.h>
> @@ -754,6 +755,94 @@ static void vmalloc_oob(struct kunit *test)
>         vfree(area);
>  }
>
> +/*
> + * Check that the assigned pointer tag falls within the [KASAN_TAG_MIN,
> + * KASAN_TAG_KERNEL) range (note: excluding the match-all tag) for tag-based
> + * modes.
> + */
> +static void match_all_not_assigned(struct kunit *test)
> +{
> +       char *ptr;
> +       struct page *pages;
> +       int i, size, order;
> +
> +       KASAN_TEST_NEEDS_CONFIG_OFF(test, CONFIG_KASAN_GENERIC);
> +
> +       for (i = 0; i < 256; i++) {
> +               size = get_random_int() % 1024;
> +               ptr = kmalloc(size, GFP_KERNEL);
> +               KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
> +               KUNIT_EXPECT_GE(test, (u8)get_tag(ptr), (u8)KASAN_TAG_MIN);
> +               KUNIT_EXPECT_LT(test, (u8)get_tag(ptr), (u8)KASAN_TAG_KERNEL);
> +               kfree(ptr);
> +       }
> +
> +       for (i = 0; i < 256; i++) {
> +               order = get_random_int() % 4;
> +               pages = alloc_pages(GFP_KERNEL, order);
> +               ptr = page_address(pages);
> +               KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
> +               KUNIT_EXPECT_GE(test, (u8)get_tag(ptr), (u8)KASAN_TAG_MIN);
> +               KUNIT_EXPECT_LT(test, (u8)get_tag(ptr), (u8)KASAN_TAG_KERNEL);
> +               free_pages((unsigned long)ptr, order);
> +       }
> +}
> +
> +/* Check that 0xff works as a match-all pointer tag for tag-based modes. */
> +static void match_all_ptr_tag(struct kunit *test)
> +{
> +       char *ptr;
> +       u8 tag;
> +
> +       KASAN_TEST_NEEDS_CONFIG_OFF(test, CONFIG_KASAN_GENERIC);
> +
> +       ptr = kmalloc(128, GFP_KERNEL);
> +       KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
> +
> +       /* Backup the assigned tag. */
> +       tag = get_tag(ptr);
> +       KUNIT_EXPECT_NE(test, tag, (u8)KASAN_TAG_KERNEL);
> +
> +       /* Reset the tag to 0xff.*/
> +       ptr = set_tag(ptr, KASAN_TAG_KERNEL);
> +
> +       /* This access shouldn't trigger a KASAN report. */
> +       *ptr = 0;
> +
> +       /* Recover the pointer tag and free. */
> +       ptr = set_tag(ptr, tag);
> +       kfree(ptr);
> +}
> +
> +/* Check that there are no match-all memory tags for tag-based modes. */
> +static void match_all_mem_tag(struct kunit *test)
> +{
> +       char *ptr;
> +       int tag;
> +
> +       KASAN_TEST_NEEDS_CONFIG_OFF(test, CONFIG_KASAN_GENERIC);
> +
> +       ptr = kmalloc(128, GFP_KERNEL);
> +       KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
> +       KUNIT_EXPECT_NE(test, (u8)get_tag(ptr), (u8)KASAN_TAG_KERNEL);
> +
> +       /* For each possible tag value not matching the pointer tag. */
> +       for (tag = KASAN_TAG_MIN; tag <= KASAN_TAG_KERNEL; tag++) {
> +               if (tag == get_tag(ptr))
> +                       continue;
> +
> +               /* Mark the first memory granule with the chosen memory tag. */
> +               kasan_poison(ptr, KASAN_GRANULE_SIZE, (u8)tag);
> +
> +               /* This access must cause a KASAN report. */
> +               KUNIT_EXPECT_KASAN_FAIL(test, *ptr = 0);
> +       }
> +
> +       /* Recover the memory tag and free. */
> +       kasan_poison(ptr, KASAN_GRANULE_SIZE, get_tag(ptr));
> +       kfree(ptr);
> +}
> +
>  static struct kunit_case kasan_kunit_test_cases[] = {
>         KUNIT_CASE(kmalloc_oob_right),
>         KUNIT_CASE(kmalloc_oob_left),
> @@ -793,6 +882,9 @@ static struct kunit_case kasan_kunit_test_cases[] = {
>         KUNIT_CASE(kasan_bitops_tags),
>         KUNIT_CASE(kmalloc_double_kzfree),
>         KUNIT_CASE(vmalloc_oob),
> +       KUNIT_CASE(match_all_not_assigned),
> +       KUNIT_CASE(match_all_ptr_tag),
> +       KUNIT_CASE(match_all_mem_tag),
>         {}
>  };
>
> diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
> index 3b38baddec47..c3fb9bf241d3 100644
> --- a/mm/kasan/kasan.h
> +++ b/mm/kasan/kasan.h
> @@ -36,6 +36,12 @@ extern bool kasan_flag_panic __ro_after_init;
>  #define KASAN_TAG_INVALID      0xFE /* inaccessible memory tag */
>  #define KASAN_TAG_MAX          0xFD /* maximum value for random tags */
>
> +#ifdef CONFIG_KASAN_HW_TAGS
> +#define KASAN_TAG_MIN          0xF0 /* mimimum value for random tags */
> +#else
> +#define KASAN_TAG_MIN          0x00 /* mimimum value for random tags */
> +#endif
> +
>  #ifdef CONFIG_KASAN_GENERIC
>  #define KASAN_FREE_PAGE         0xFF  /* page was freed */
>  #define KASAN_PAGE_REDZONE      0xFE  /* redzone for kmalloc_large allocations */
> --
> 2.30.0.284.gd98b1dd5eaa7-goog
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNP-r3CcgCnenJEbHB5_RNfnFDF7x%3D4uufLVbqRZtqGd7g%40mail.gmail.com.
