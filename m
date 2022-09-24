Return-Path: <kasan-dev+bncBCMIZB7QWENRBI7ZXKMQMGQER4ULORI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x538.google.com (mail-ed1-x538.google.com [IPv6:2a00:1450:4864:20::538])
	by mail.lfdr.de (Postfix) with ESMTPS id C9A145E89ED
	for <lists+kasan-dev@lfdr.de>; Sat, 24 Sep 2022 10:15:31 +0200 (CEST)
Received: by mail-ed1-x538.google.com with SMTP id r11-20020a05640251cb00b004516feb8c09sf1539290edd.10
        for <lists+kasan-dev@lfdr.de>; Sat, 24 Sep 2022 01:15:31 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1664007331; cv=pass;
        d=google.com; s=arc-20160816;
        b=d7qCj8gC8Ma4mqdk6/YCbRSjtGRArkj61BuXFroSrrJ4bKbjLOE0Rqfpjl3HLAx8yw
         A7lnYpIEJc0/XF8th4dVQnBX8A6vrEnuihV+TtpzK6jYwIqp94JWDc2B1PmQ8Duu2O70
         qf+5ynQWwUPi+nCsUQNFviKN2dSTZvcFEOMeGADN5tNDab+r8KhUoh7/hTpuxnbnr4Q4
         hDQ62gF03uWwpywozS5rFEdhj32/stsvbBeeaxkarhxNiX+FJbbVRd3b8vSVBLLx9/FU
         XnaZMo7v4aKCxGas3Uk9Fuf1WOKfm2Y9fnjhneqM4tERD+fI2WAS2n1tLxnX/IBM1SD+
         asLw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=Drf2ZwRed47pjN1mtn69tedeQWLp0jM3CyeEr4FnQ00=;
        b=EFQG3wOEOQxoEIlvas0u2vhYSXO+IDXNrjDTjhYdIlNXKH8yyWiSQGoMzB2MvoyI6b
         ThgLPZpffxLiafLBg3QJGeNQ12dJPsL/ZoCUoYnMcocuK6Ltr8pbc96x0S/9pVHbZIP6
         hJW+zqMlZK1mf7/UYOo29nfWqFtXSwr5HdVzI3Mb02GI22HwvrMBNONwqsT+YeBV8Mx5
         DiZDcua9aPhIqMZs+ewMbPpGAU2/ignSPk3GYP/TSqmbzuREBI6OIvdM2NdwFxVuvT0j
         jUspbx//YAv3oTBAypelDSeSgvGij2WQ6yEpp7GZjmQeR0/8e5LBz7YhWUsec80m4gX4
         uobA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=KI9bvqb1;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::233 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date;
        bh=Drf2ZwRed47pjN1mtn69tedeQWLp0jM3CyeEr4FnQ00=;
        b=rI72NNa5MaFmv5sbtD68L0Vt0stP/1GZTPR6PVpnoa5yhxgqdapmZuM2tOC8tfg/Yr
         WtvwkDM/GBasoV6KD2mwEJ2GZMRyTT1NUdcgP9q1MpA/noRq8rAMQLAtgsQfbUeVyIHQ
         0p2cPOphitZKB9WDqXHruksRMieDkSqbskJgEZsAZ3Q8YrTbXHeKqDZJ7y1uYOxLanpw
         aqvv1rEJ+gVw6f3i5TAkti08NMZcwo0ZmLhK0VDuAMB4XVHuZP91xml5XnS+pwxPGVUC
         QW92+HQ+AzMKPgGRl5RXXA4GwKF9AyqzlGBjfCg1FJkuORLz8d0XC4REZCUZ0dzgCQYy
         a1UQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc:subject:date;
        bh=Drf2ZwRed47pjN1mtn69tedeQWLp0jM3CyeEr4FnQ00=;
        b=hjOf+SGE4GkQh6y3igNH1FowzSFrAgnO+5+3wy9RdujGCqwCQQ/nUE8wq+LTPLgaeU
         zYXvEUU8VaENNKFySA3yjv2XotuI06wtXO8n9QsyG6hGfEkxs2M+66IZuSIeCCigbDLI
         lW8mTiGiXHvM4ZUd/TapVE1jxkh2i2phjwq6Chn/siZpXxXOJL7gO4DFpZjYHMVBPDJh
         a87eZbxOJUyXlsvdCdhnECthSmhh7d9MeA+ONVLLdWHwDLKZUnBaq9gAij8xDZgYxEm3
         //VY+0rOx4y2H0A2UFrwJUuzl0yi5ozKlbuEpad1uE/N9KJSqSwwv8UMdxbYbaH9QzSH
         v2kA==
X-Gm-Message-State: ACrzQf1gMhTXkyREVJfUP/HLrBycvaXGOz+wFHejn1yJ8JXrctZnd9zC
	j42aqZN7Cy8G16VLbAXtTxU=
X-Google-Smtp-Source: AMsMyM5HRy4lH9ndv2Sil+fK3QgnsR4uDigHHZS8a3055/2Z3Y9bLpTsAjsL20kGwMPUdAN/dWIArQ==
X-Received: by 2002:a17:907:2724:b0:779:7545:5df6 with SMTP id d4-20020a170907272400b0077975455df6mr10162213ejl.325.1664007331412;
        Sat, 24 Sep 2022 01:15:31 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:a84f:b0:780:2712:35d2 with SMTP id
 dx15-20020a170906a84f00b00780271235d2ls4692383ejb.4.-pod-prod-gmail; Sat, 24
 Sep 2022 01:15:30 -0700 (PDT)
X-Received: by 2002:a17:907:805:b0:782:1a0d:337f with SMTP id wv5-20020a170907080500b007821a0d337fmr10286720ejb.475.1664007330205;
        Sat, 24 Sep 2022 01:15:30 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1664007330; cv=none;
        d=google.com; s=arc-20160816;
        b=nLfQgdslSRrpGs7Zryo8JKpYiV2gWY1ayYFIh8JhE9czNmP7hhmYteYDH2GOH0AH5n
         IIJiSb+6NmVvWN6RkCvboVmrcCVh6zDDdRAvZG2O3w2iUG/wKByZaayR5YPc3mZUyFxq
         0f2qc7/Kgur/+KkKnABdfovKgDJUktZcFgTw2uysy26LfDlf1DoeTxJ+g1gKbB1ZtmT1
         j6cOZOVzi5KEihs9LaFePrTOaiZtmDLUIYfMBkWOc7AKx2UAwZUPXhDbnCkWq4ppgNIW
         dwpSL233g9TBwoZTAcIKCxNMkItJ6smefcQaJtJIWha17q5iWbZ+Xv7yKkagMPSvsd9k
         DjIQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=nQomz4ut+7sjfQrrU1jIFAnyWatFfjECi53D3yczEIE=;
        b=u3k7sDdTw2O9hbIFeWZiObXlAGvVOHhWonqooOwdNxS5kfEGrdE4cjYJf/TenNZHwn
         jGk40hkfDTLabH3XkMLqzl8Bw21/FToLrpvFmpRLk8eiRz67dR/EtYtoor/C2c6FonGL
         IJQ3tzF7Sjj9CrT6luaojes5sdEPv27b35F2p2RRvTvMyMMQ0cVC7zBuFEV549EWHf8p
         xArCteoGiTFm0BT0gmSZmMKIOhfJwbTUB4PVj7ZqR0/nR+kRSPn2Pt9qVHlF85uCpg/g
         +OO9V7470+YZPOd4p9tHoGhFD/UDDDaTYBaGuN8pAzwa093EUkFW2+oVcfyYOFHeI8QR
         txlw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=KI9bvqb1;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::233 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-lj1-x233.google.com (mail-lj1-x233.google.com. [2a00:1450:4864:20::233])
        by gmr-mx.google.com with ESMTPS id jx23-20020a170907761700b0077e2b420e6esi466797ejc.0.2022.09.24.01.15.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 24 Sep 2022 01:15:30 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::233 as permitted sender) client-ip=2a00:1450:4864:20::233;
Received: by mail-lj1-x233.google.com with SMTP id s10so2332393ljp.5
        for <kasan-dev@googlegroups.com>; Sat, 24 Sep 2022 01:15:30 -0700 (PDT)
X-Received: by 2002:a2e:be8d:0:b0:26c:f4b:47a0 with SMTP id
 a13-20020a2ebe8d000000b0026c0f4b47a0mr4030821ljr.92.1664007329396; Sat, 24
 Sep 2022 01:15:29 -0700 (PDT)
MIME-Version: 1.0
References: <20220923202822.2667581-1-keescook@chromium.org> <20220923202822.2667581-15-keescook@chromium.org>
In-Reply-To: <20220923202822.2667581-15-keescook@chromium.org>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Sat, 24 Sep 2022 10:15:18 +0200
Message-ID: <CACT4Y+bg=j9VdteQwrJTNFF_t4EE5uDTMLj07+uMJ9-NcooXGQ@mail.gmail.com>
Subject: Re: [PATCH v2 14/16] kasan: Remove ksize()-related tests
To: Kees Cook <keescook@chromium.org>
Cc: Vlastimil Babka <vbabka@suse.cz>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	kasan-dev@googlegroups.com, linux-mm@kvack.org, 
	"Ruhl, Michael J" <michael.j.ruhl@intel.com>, Hyeonggon Yoo <42.hyeyoo@gmail.com>, 
	Christoph Lameter <cl@linux.com>, Pekka Enberg <penberg@kernel.org>, David Rientjes <rientjes@google.com>, 
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, "David S. Miller" <davem@davemloft.net>, 
	Eric Dumazet <edumazet@google.com>, Jakub Kicinski <kuba@kernel.org>, Paolo Abeni <pabeni@redhat.com>, 
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>, Nick Desaulniers <ndesaulniers@google.com>, 
	Alex Elder <elder@kernel.org>, Josef Bacik <josef@toxicpanda.com>, David Sterba <dsterba@suse.com>, 
	Sumit Semwal <sumit.semwal@linaro.org>, =?UTF-8?Q?Christian_K=C3=B6nig?= <christian.koenig@amd.com>, 
	Jesse Brandeburg <jesse.brandeburg@intel.com>, Daniel Micay <danielmicay@gmail.com>, 
	Yonghong Song <yhs@fb.com>, Marco Elver <elver@google.com>, Miguel Ojeda <ojeda@kernel.org>, 
	linux-kernel@vger.kernel.org, netdev@vger.kernel.org, 
	linux-btrfs@vger.kernel.org, linux-media@vger.kernel.org, 
	dri-devel@lists.freedesktop.org, linaro-mm-sig@lists.linaro.org, 
	linux-fsdevel@vger.kernel.org, intel-wired-lan@lists.osuosl.org, 
	dev@openvswitch.org, x86@kernel.org, llvm@lists.linux.dev, 
	linux-hardening@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=KI9bvqb1;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::233
 as permitted sender) smtp.mailfrom=dvyukov@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Dmitry Vyukov <dvyukov@google.com>
Reply-To: Dmitry Vyukov <dvyukov@google.com>
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

On Fri, 23 Sept 2022 at 22:28, Kees Cook <keescook@chromium.org> wrote:
>
> In preparation for no longer unpoisoning in ksize(), remove the behavioral
> self-tests for ksize().
>
> Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>
> Cc: Alexander Potapenko <glider@google.com>
> Cc: Andrey Konovalov <andreyknvl@gmail.com>
> Cc: Dmitry Vyukov <dvyukov@google.com>
> Cc: Vincenzo Frascino <vincenzo.frascino@arm.com>
> Cc: Andrew Morton <akpm@linux-foundation.org>
> Cc: kasan-dev@googlegroups.com
> Cc: linux-mm@kvack.org
> Signed-off-by: Kees Cook <keescook@chromium.org>
> ---
>  lib/test_kasan.c  | 42 ------------------------------------------
>  mm/kasan/shadow.c |  4 +---
>  2 files changed, 1 insertion(+), 45 deletions(-)
>
> diff --git a/lib/test_kasan.c b/lib/test_kasan.c
> index 58c1b01ccfe2..bdd0ced8f8d7 100644
> --- a/lib/test_kasan.c
> +++ b/lib/test_kasan.c
> @@ -753,46 +753,6 @@ static void kasan_global_oob_left(struct kunit *test)
>         KUNIT_EXPECT_KASAN_FAIL(test, *(volatile char *)p);
>  }
>
> -/* Check that ksize() makes the whole object accessible. */
> -static void ksize_unpoisons_memory(struct kunit *test)
> -{
> -       char *ptr;
> -       size_t size = 123, real_size;
> -
> -       ptr = kmalloc(size, GFP_KERNEL);
> -       KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
> -       real_size = ksize(ptr);
> -
> -       OPTIMIZER_HIDE_VAR(ptr);
> -
> -       /* This access shouldn't trigger a KASAN report. */
 > -       ptr[size] = 'x';

I would rather keep the tests and update to the new behavior. We had
bugs in ksize, we need test coverage.
I assume ptr[size] access must now produce an error even after ksize.


> -       /* This one must. */
> -       KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)ptr)[real_size]);
> -
> -       kfree(ptr);
> -}
> -
> -/*
> - * Check that a use-after-free is detected by ksize() and via normal accesses
> - * after it.
> - */
> -static void ksize_uaf(struct kunit *test)
> -{
> -       char *ptr;
> -       int size = 128 - KASAN_GRANULE_SIZE;
> -
> -       ptr = kmalloc(size, GFP_KERNEL);
> -       KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
> -       kfree(ptr);
> -
> -       OPTIMIZER_HIDE_VAR(ptr);
> -       KUNIT_EXPECT_KASAN_FAIL(test, ksize(ptr));

This is still a bug that should be detected, right? Calling ksize on a
freed pointer is a bug.

> -       KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)ptr)[0]);
> -       KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)ptr)[size]);
> -}
> -
>  static void kasan_stack_oob(struct kunit *test)
>  {
>         char stack_array[10];
> @@ -1392,8 +1352,6 @@ static struct kunit_case kasan_kunit_test_cases[] = {
>         KUNIT_CASE(kasan_stack_oob),
>         KUNIT_CASE(kasan_alloca_oob_left),
>         KUNIT_CASE(kasan_alloca_oob_right),
> -       KUNIT_CASE(ksize_unpoisons_memory),
> -       KUNIT_CASE(ksize_uaf),
>         KUNIT_CASE(kmem_cache_double_free),
>         KUNIT_CASE(kmem_cache_invalid_free),
>         KUNIT_CASE(kmem_cache_double_destroy),
> diff --git a/mm/kasan/shadow.c b/mm/kasan/shadow.c
> index 0e3648b603a6..0895c73e9b69 100644
> --- a/mm/kasan/shadow.c
> +++ b/mm/kasan/shadow.c
> @@ -124,9 +124,7 @@ void kasan_unpoison(const void *addr, size_t size, bool init)
>         addr = kasan_reset_tag(addr);
>
>         /*
> -        * Skip KFENCE memory if called explicitly outside of sl*b. Also note
> -        * that calls to ksize(), where size is not a multiple of machine-word
> -        * size, would otherwise poison the invalid portion of the word.
> +        * Skip KFENCE memory if called explicitly outside of sl*b.
>          */
>         if (is_kfence_address(addr))
>                 return;
> --
> 2.34.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2Bbg%3Dj9VdteQwrJTNFF_t4EE5uDTMLj07%2BuMJ9-NcooXGQ%40mail.gmail.com.
