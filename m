Return-Path: <kasan-dev+bncBCF5XGNWYQBRBPWJWSIAMGQEL4KKQEY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13e.google.com (mail-il1-x13e.google.com [IPv6:2607:f8b0:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id 478944B8DC1
	for <lists+kasan-dev@lfdr.de>; Wed, 16 Feb 2022 17:22:23 +0100 (CET)
Received: by mail-il1-x13e.google.com with SMTP id y3-20020a920903000000b002be462612d7sf113279ilg.10
        for <lists+kasan-dev@lfdr.de>; Wed, 16 Feb 2022 08:22:23 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1645028542; cv=pass;
        d=google.com; s=arc-20160816;
        b=u/JkYQMgFhoFOA7vcxkkwfSwjCCot4hCdsF+Pt3F4TWIhzeYWCEDHAW8yP/ywmWlmz
         GkZ3WB8jwiWTCW0qpOkZog364PRa0xNJ5ptnDI2fCPeQFLTqpeRp1KFzIXFVlzV0hWX1
         q4m3D/MAGAQj+Z5IvPqi4zCeBgmGxsBiMLFiCcIqDBI8kKHonLt9QwLYGefYJtumZbtD
         BCxBz+UWFvKy13ruyNlJG3iGo2PhROLo6qlVn+QTmyM9bHE7rrZ3j0qhvukHyB6PqoHu
         +FYq932W/eFovvAHneCPCU/8HA8UurFlt4q3vc5cISWxyqh9O0dEUrwHvmm0zOc2P+Ek
         Hx3A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=NZff4Bua3kUFVIjJHyQA3tskXb89zpfOTAE0Qai/fOE=;
        b=R4HFZoNUGoirDbO1/QOKu11kvG5CSxNyrn+n0ekSst2twGvxDw6ledix7VOzntNHMh
         w+hm01EF5vI7/62Iv7V4WT76YucX8dc9FQ3/7CpTdDlaqpLMOpxiwIcvekhht4jawLdy
         ab5H/xyx95TOYf5+aYU8TVZ13Z2rQMCKQoXwJ0WnKGW8KQ599RJAtDmNxC3AliM2zNNP
         U2/um0MvwjCBQbrdxLVuvcr59shRZ/2q9MOll9C75dC9TCM1RyDQs2f3l9ggJ7oWr8h+
         R+0suuU8lbySe+BaiEcSdN+/umLcn4l0G63N8vdAX6XNvaOHaV4vjlRHycv/+CS1agBR
         sFTg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=eSk+1+Gg;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::530 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=NZff4Bua3kUFVIjJHyQA3tskXb89zpfOTAE0Qai/fOE=;
        b=KMF8wfc2raCm5F4asd3Q9rb5KgaT3BIHKDLRGiiwOr64FgXLXlG18WpcfkbxdGFSih
         T7IONt/4B0aF1CaCsKlJr8shGFiuIYuZH8M8QD1WZfDNSYuLGOG1HqdXY9bGUTUqK2W2
         Lh24HlrtOoCVrJ2Oc1HwprkwmXCF5xdt3yKv4aeiSv6EiVzeik1BGnEkAiqcD5u6VoeB
         Ze5Oq8rtXTKgZ2+RLXNSKBpykIV83rqbixlPrfdWadPrqnzxTqZgzII1IWDW7crAbu7+
         5JkhRIT814JcO3ZWRX23qBB9TTqJMK8MeXThAaXt09+EnJizsou5HJz9PcsKNm7ZMNsG
         FkTA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=NZff4Bua3kUFVIjJHyQA3tskXb89zpfOTAE0Qai/fOE=;
        b=rlXwsF/tnmFrC0vp9YngyIGCp+tVAw8v4knPH6ZtPwUrfZDVF70Pa0y63irTVim1sM
         +lyWjF7iaUD2UWxotKEIPDWed64RCVEVIo+0M1MnDLWRZeFjhaaq/TrSFckua90cK2x9
         TbnamR7kCqTovdm1dWdRWXwwmIvixp8TPV7md6HaW3KI9QmA5d7tnwdJG2AG36dsID48
         uNFuMi9Gd4DYY4+Ugw+oQ+Lm0qZOCc6EBu8IXH/sxi1YVmWj8Q0o8Mo8WqgtzJO1v759
         gBeHaBSUsp/NNigyvzRWhPnUQVuTOQD1rfVE1lQvH5QkJhFCGgVHQH6z/crLe6uX3qec
         uZGQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533jDNAx3rIzANR0XgpNrYeY4PlrYZ/QuJrXW92VnqEM0dQNWJuL
	BTUSFIrohZnyLXXotxEWt9Y=
X-Google-Smtp-Source: ABdhPJwvWQsgU2DEue1yxskLaKwC8xKWtkh6Wl6fr//Y3COzotkEnnQTItsCpybvmMXafbUHtyYwGQ==
X-Received: by 2002:a92:ca0f:0:b0:2bf:56d4:3aec with SMTP id j15-20020a92ca0f000000b002bf56d43aecmr2284176ils.220.1645028542295;
        Wed, 16 Feb 2022 08:22:22 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6638:1447:: with SMTP id l7ls1266612jad.8.gmail; Wed, 16
 Feb 2022 08:22:22 -0800 (PST)
X-Received: by 2002:a05:6638:2608:b0:313:f4b2:1106 with SMTP id m8-20020a056638260800b00313f4b21106mr2110345jat.79.1645028541917;
        Wed, 16 Feb 2022 08:22:21 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1645028541; cv=none;
        d=google.com; s=arc-20160816;
        b=XVr+f3hZFmpjLXmVq2o8+gJ/6kEbJHXmorvuyfgmv3e0qnDp1havIxftZ5qfR/kaRm
         VVkKGRSWL8CnE16JQKSBKUsziXMIMdb4CH8qmfrNhNZKFjhXEmEWVti+4AMBIHMhmI7W
         9L//j3ZVuFZhioHXDGjme1Q4N4NsKPP6K4+/ncZ8j15XTrhGMwJIcSkcQKBZr77Ct1tA
         aB3BrUzaTYehV6qaMv/si1kZons96kdaB0s91JwFZ2x5eGahY3q+ShqL7WKHRx06iPHo
         Yoh5Mr2c7zwBkXrvxzQSP2AR+QI9Jg5WvhOOOC97LOq/3nJMm3fUjHROj0BjjfZIaj8O
         JmUw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=iH8izYx1CVz5zaeZ+ywlrsYpOCO6qk+mt4vdLHF4sUs=;
        b=VOkGWB9s4wMyGHrr76l0xqO1+xAWKSdyQqJx3Mz/ohIeZidvoQLYnNIFJRqGeocqgV
         t2L+dXxrnJzmMcL78HiO2CYMtVl30yn5vn4ylWcdBz9+NKflrV1OJ5xiUCJEfFKid79h
         KRKvefLnA4Y/PuETL9YkWkoKSZlDJz8AO7UJFdLTNAog4DVxQeU29hHoZZodMKxX/ulP
         SmtkanVFeMwtp+pjcl0WGtmBMs/QDr0BNhLgNfomwT5MExw9vLI8ESPg3utO7ZoUSfbJ
         YZD5dRHyAoYteRvhOde6dhuTYgZdQ2AKIHA7h0NYfLkioLiWKt/qiGf7KK4oBVnUdm9h
         KkwA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=eSk+1+Gg;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::530 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Received: from mail-pg1-x530.google.com (mail-pg1-x530.google.com. [2607:f8b0:4864:20::530])
        by gmr-mx.google.com with ESMTPS id d15si4899558jak.1.2022.02.16.08.22.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 16 Feb 2022 08:22:21 -0800 (PST)
Received-SPF: pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::530 as permitted sender) client-ip=2607:f8b0:4864:20::530;
Received: by mail-pg1-x530.google.com with SMTP id f8so2563928pgc.8
        for <kasan-dev@googlegroups.com>; Wed, 16 Feb 2022 08:22:21 -0800 (PST)
X-Received: by 2002:a05:6a00:2387:b0:4e0:5414:da5c with SMTP id f7-20020a056a00238700b004e05414da5cmr3976133pfc.85.1645028541563;
        Wed, 16 Feb 2022 08:22:21 -0800 (PST)
Received: from www.outflux.net (smtp.outflux.net. [198.145.64.163])
        by smtp.gmail.com with ESMTPSA id h26sm5903093pgm.72.2022.02.16.08.22.21
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 16 Feb 2022 08:22:21 -0800 (PST)
Date: Wed, 16 Feb 2022 08:22:20 -0800
From: Kees Cook <keescook@chromium.org>
To: Andrey Konovalov <andreyknvl@gmail.com>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	kasan-dev <kasan-dev@googlegroups.com>,
	LKML <linux-kernel@vger.kernel.org>,
	linux-hardening@vger.kernel.org
Subject: Re: [PATCH] kasan: test: Silence allocation warnings from GCC 12
Message-ID: <202202160821.AA9264A71@keescook>
References: <20220213183232.4038718-1-keescook@chromium.org>
 <CA+fCnZfOSD56Uvetqd=ofv-Wxw6LOOZv3sUDcEuX2F3u-MgL9Q@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CA+fCnZfOSD56Uvetqd=ofv-Wxw6LOOZv3sUDcEuX2F3u-MgL9Q@mail.gmail.com>
X-Original-Sender: keescook@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=eSk+1+Gg;       spf=pass
 (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::530
 as permitted sender) smtp.mailfrom=keescook@chromium.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=chromium.org
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

On Wed, Feb 16, 2022 at 04:26:46PM +0100, Andrey Konovalov wrote:
> On Sun, Feb 13, 2022 at 7:32 PM Kees Cook <keescook@chromium.org> wrote:
> >
> > GCC 12 is able to see more problems with allocation sizes at compile
> > time, so these must be silenced so the runtime checks will still be
> > available. Use OPTIMIZER_HIDE_VAR() to silence the new warnings:
> >
> > lib/test_kasan.c: In function 'ksize_uaf':
> 
> Hm, the warning mentions ksize_uaf, but none of the changes touch it.

Excellent point -- let me go re-test this.

-Kees

> 
> > lib/test_kasan.c:781:61: warning: array subscript 120 is outside array bounds of 'void[120]' [-Warray-bounds]
> >   781 |         KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)ptr)[size]);
> >       |                                       ~~~~~~~~~~~~~~~~~~~~~~^~~~~~
> > lib/test_kasan.c:96:9: note: in definition of macro 'KUNIT_EXPECT_KASAN_FAIL'
> >    96 |         expression;                                                     \
> >       |         ^~~~~~~~~~
> > In function 'kmalloc',
> >     inlined from 'ksize_uaf' at lib/test_kasan.c:775:8:
> > ./include/linux/slab.h:581:24: note: at offset 120 into object of size 120 allocated by 'kmem_cache_alloc_trace'
> >   581 |                 return kmem_cache_alloc_trace(
> >       |                        ^~~~~~~~~~~~~~~~~~~~~~~
> >   582 |                                 kmalloc_caches[kmalloc_type(flags)][index],
> >       |                                 ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
> >   583 |                                 flags, size);
> >       |                                 ~~~~~~~~~~~~
> >
> > Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>
> > Cc: Alexander Potapenko <glider@google.com>
> > Cc: Andrey Konovalov <andreyknvl@gmail.com>
> > Cc: Dmitry Vyukov <dvyukov@google.com>
> > Cc: kasan-dev@googlegroups.com
> > Signed-off-by: Kees Cook <keescook@chromium.org>
> > ---
> >  lib/test_kasan.c | 4 ++++
> >  1 file changed, 4 insertions(+)
> >
> > diff --git a/lib/test_kasan.c b/lib/test_kasan.c
> > index 26a5c9007653..a19b3d608e3e 100644
> > --- a/lib/test_kasan.c
> > +++ b/lib/test_kasan.c
> > @@ -124,6 +124,7 @@ static void kmalloc_oob_right(struct kunit *test)
> >
> >         ptr = kmalloc(size, GFP_KERNEL);
> >         KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
> > +       OPTIMIZER_HIDE_VAR(ptr);
> >
> >         /*
> >          * An unaligned access past the requested kmalloc size.
> > @@ -185,6 +186,7 @@ static void kmalloc_pagealloc_oob_right(struct kunit *test)
> >         ptr = kmalloc(size, GFP_KERNEL);
> >         KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
> >
> > +       OPTIMIZER_HIDE_VAR(ptr);
> >         KUNIT_EXPECT_KASAN_FAIL(test, ptr[size + OOB_TAG_OFF] = 0);
> >
> >         kfree(ptr);
> > @@ -265,6 +267,7 @@ static void kmalloc_large_oob_right(struct kunit *test)
> >         ptr = kmalloc(size, GFP_KERNEL);
> >         KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
> >
> > +       OPTIMIZER_HIDE_VAR(ptr);
> >         KUNIT_EXPECT_KASAN_FAIL(test, ptr[size] = 0);
> >         kfree(ptr);
> >  }
> > @@ -748,6 +751,7 @@ static void ksize_unpoisons_memory(struct kunit *test)
> >
> >         ptr = kmalloc(size, GFP_KERNEL);
> >         KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
> > +       OPTIMIZER_HIDE_VAR(ptr);
> >         real_size = ksize(ptr);
> >
> >         /* This access shouldn't trigger a KASAN report. */
> > --
> > 2.30.2
> >

-- 
Kees Cook

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/202202160821.AA9264A71%40keescook.
