Return-Path: <kasan-dev+bncBC7OBJGL2MHBBIGR2KGAMGQEB5CFKDQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103b.google.com (mail-pj1-x103b.google.com [IPv6:2607:f8b0:4864:20::103b])
	by mail.lfdr.de (Postfix) with ESMTPS id 0403F454188
	for <lists+kasan-dev@lfdr.de>; Wed, 17 Nov 2021 08:00:51 +0100 (CET)
Received: by mail-pj1-x103b.google.com with SMTP id n2-20020a17090a2fc200b001a1bafb59bfsf787959pjm.1
        for <lists+kasan-dev@lfdr.de>; Tue, 16 Nov 2021 23:00:50 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1637132448; cv=pass;
        d=google.com; s=arc-20160816;
        b=EMvm/WCEoItmUKz01fhEWBhP1wjxig+lKB7Dqgciv5zP7JPX8+bsKT0rwI+wjEriD8
         hia5uz2mGbXNstNa7n3ooOnT85Mgdo9t/DLTu9ovdcA+QoSEuOe/IspznK9uqqZUHMt8
         CcZGALFN0vKIJyhwXFSxMlE7bha8zjruZa80HszVd8XMCqG6n4JGVVFXBDXFSJwYVXs7
         E2h0tUxtF3LWhi1YX4b93OMFpHnsMzzkfOxgLYUNtpG9Rlo0i1KgDYr04COULE6qXNHy
         smpUgCRT0Ty+YBcCRaqEV3PHX09X4WkYVs0ST4a7GjX/vt7EX8O0xeGAXEgoCWL7XSqb
         VZyA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=BNauOBtGxvXV6e+8LDg/7L0yrhk28GXSqKHRo7eZJAM=;
        b=dRMCUTyYMPpjL02Fv2EyN7wGNGylStgMuXT5jFIvT6+wrpkRCq91NGhGgXxFDmHYCv
         eUDK6b2rYjYCoeKO1HmN3ENSG9CgNuIo8b4R8vCjRK9jcUHwBE9gKUJxZeZCP3220okn
         Tb0RFz22UEaNJEWWtELg82Z2V7hWhGq5lNWJHZRyeztFbesS9dzajb30XCl+uI1Qk7XE
         V8cbzS41SFn8pjMCoozwQN2OTapdXBj4sHwIF8fnKmhTmxwcydT9SZeQ1y89dt1ohoQS
         4YdSLbsgy45mY3Wk+KLjqYQBOG5lYbxteMLYxix5Nk8DxL2q5f/KzaoTYLsvLVYj3uFN
         JnFQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=cFw719NB;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32b as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=BNauOBtGxvXV6e+8LDg/7L0yrhk28GXSqKHRo7eZJAM=;
        b=gV8UO6po2EdDnpxpmzozD7vG5fn5f60RauDATHKsXMNQJ4NQSqDitGWE3htTY8tflW
         aR8u5VrPr7LYJN161NZtMGhZUb6avwv6jiccdA339M0xa3kU+oQ7YjmL4NbfzhxNFk5q
         9QQXjmfJDz+ZdAF6Gov4QcQv30QB12/NeoaeK1LMcEokrv/Pqupr4vNecmiiW9lyf+UB
         WyCjkMtdspwRvtNfK6yKMsiaBDa5t9soQZ3p/EWgz1BLAYuReL+/bdokgRNen2hQGOOe
         lTI3R2IZxdGZ/vA8yYcZtaJy39UaAIP1pKcStAPaw61HMogPN1TdpR0lcQweC2Wd6IgE
         FmAg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=BNauOBtGxvXV6e+8LDg/7L0yrhk28GXSqKHRo7eZJAM=;
        b=J+CvdjHPzaqt6HbCWC+2fFXWQRzAVJJdp21oJ+N9jinsdPAFmtKcqab4qlDmObMFW8
         adM4NxQvE8pB8zzZIU3OAfz9TRIGV9luLCWyE3MC7Shtye+GYX32phIiOmNBzLm0lsxh
         GcPhTwGI1CYFigql82uMy6eMDSVevdSLkTBvH2X2cfLteT2PgoTJkN+G9Wem81VE77xY
         z0VBhELSW0/NSMGBsphinnRmt80wQB0D2oOIU/uCjF8/srBJH+W8A8n+c+vHFhBsYofl
         DFhVxq+ZaMOEG/QsHmrIKgQtg+AIbTVhn0YS1U/9DxeQ8E+x3woxiCHvkfrIVt/Ly5OC
         W7Eg==
X-Gm-Message-State: AOAM530Hsw0RsVDMj2nFesbZRkcIFQ7Tyu98modSstuPpk/1kgDXr+9G
	jxpWanAErmzFy4P9BmJmcP8=
X-Google-Smtp-Source: ABdhPJyPo7Uht5YBv5iIUnc4rRB+fIvldM4J8mwdBqm3Rd9Bv27Wb0ktViZkwjjOq3/yumNph3Wmhg==
X-Received: by 2002:a17:902:ce8c:b0:141:d218:954 with SMTP id f12-20020a170902ce8c00b00141d2180954mr51924399plg.1.1637132448153;
        Tue, 16 Nov 2021 23:00:48 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:f20c:: with SMTP id m12ls4570805plc.3.gmail; Tue, 16
 Nov 2021 23:00:47 -0800 (PST)
X-Received: by 2002:a17:90b:3ec6:: with SMTP id rm6mr6776857pjb.41.1637132447478;
        Tue, 16 Nov 2021 23:00:47 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1637132447; cv=none;
        d=google.com; s=arc-20160816;
        b=u8rfETmbHGkKwM5mDmKVre3RJ7AV4RdmXrmdW9Hyb/AYjZsxVxzhoK5gJeArbJjyY8
         Do8uATDJiDR7FWt9rkULpic/tsTVIFQmSOkvkvY+hH+Bb81qEn6im+ko9ezlp9wvj+vn
         EGnT+ovLNeuscFXPk2ExuhXYuQ7HtWzCzyaHCefHCeaDQNcC1HVtIEAAnseg2c5nfmE9
         XKoJvMoYtsk1u9F8SVhzthutGs8KUSxG6gB+RzWsd/FIm77i+HX+5UtNgklFXRYnNWa7
         Tqx/oLzRs1Lvt8mzHTB9vyID4NOiNPqwHjExV9uLFpc5lC6DJWNLtqsNJAvUZRJEcFLC
         2A+w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=lEisxbhjrG/o/qS2p+yaqlf5bGUGf6XJ32LJqE9ByoA=;
        b=CjB/XDH27NSrMKdKMdYQyDEqsBB2Zq5dyhBUEKBY3WOOe45Qe/MrNs7/vvwxhJpBaC
         DxA46yJztTtkVMOYjXSg8m26RsGH16EaCpawamK2UDjzvIiMZgZi06o6+EfGySxP8C6Y
         dEOsyrfoqBuCih+91yvVm4S+tCtJ8VsiztJBZpqvayeBqaCgE0oPmYAP0MtINxmm121y
         k805J8KLW1bAkN0Ojqj6YqdBc2CDtFu/9jgRSO7Y3NaNqi/hnrMLPEpZV2SLeuD0KaCo
         wf6J3HjveGnqaAQoNUGkkGI8n+OhwMWkgaUmHiM8uH6nyaLYlMkdr9+bhWhp+5lVRtEI
         6svQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=cFw719NB;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32b as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x32b.google.com (mail-ot1-x32b.google.com. [2607:f8b0:4864:20::32b])
        by gmr-mx.google.com with ESMTPS id c3si197165pgv.1.2021.11.16.23.00.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 16 Nov 2021 23:00:47 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32b as permitted sender) client-ip=2607:f8b0:4864:20::32b;
Received: by mail-ot1-x32b.google.com with SMTP id a23-20020a9d4717000000b0056c15d6d0caso2990430otf.12
        for <kasan-dev@googlegroups.com>; Tue, 16 Nov 2021 23:00:47 -0800 (PST)
X-Received: by 2002:a9d:77d1:: with SMTP id w17mr11402677otl.329.1637132445500;
 Tue, 16 Nov 2021 23:00:45 -0800 (PST)
MIME-Version: 1.0
References: <20211116001628.24216-1-vbabka@suse.cz> <20211116001628.24216-26-vbabka@suse.cz>
In-Reply-To: <20211116001628.24216-26-vbabka@suse.cz>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 17 Nov 2021 08:00:00 +0100
Message-ID: <CANpmjNPOWFLEAvTD++NfwiCU4kt=-bAX64PEjUsdjs65EsiGJQ@mail.gmail.com>
Subject: Re: [RFC PATCH 25/32] mm/kfence: Convert kfence_guarded_alloc() to
 struct slab
To: Vlastimil Babka <vbabka@suse.cz>
Cc: Matthew Wilcox <willy@infradead.org>, linux-mm@kvack.org, 
	Christoph Lameter <cl@linux.com>, David Rientjes <rientjes@google.com>, Joonsoo Kim <iamjoonsoo.kim@lge.com>, 
	Pekka Enberg <penberg@kernel.org>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=cFw719NB;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32b as
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

On Tue, 16 Nov 2021 at 01:16, Vlastimil Babka <vbabka@suse.cz> wrote:
> The function sets some fields that are being moved from struct page to struct
> slab so it needs to be converted.
>
> Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
> Cc: Alexander Potapenko <glider@google.com>
> Cc: Marco Elver <elver@google.com>
> Cc: Dmitry Vyukov <dvyukov@google.com>
> Cc: <kasan-dev@googlegroups.com>

It looks sane. I ran kfence_test with both slab and slub, and all passes:

Tested-by: Marco Elver <elver@google.com>

But should there be other major changes, we should re-test.

Thanks,
-- Marco

> ---
>  mm/kfence/core.c        | 12 ++++++------
>  mm/kfence/kfence_test.c |  6 +++---
>  2 files changed, 9 insertions(+), 9 deletions(-)
>
> diff --git a/mm/kfence/core.c b/mm/kfence/core.c
> index 09945784df9e..4eb60cf5ff8b 100644
> --- a/mm/kfence/core.c
> +++ b/mm/kfence/core.c
> @@ -360,7 +360,7 @@ static void *kfence_guarded_alloc(struct kmem_cache *cache, size_t size, gfp_t g
>  {
>         struct kfence_metadata *meta = NULL;
>         unsigned long flags;
> -       struct page *page;
> +       struct slab *slab;
>         void *addr;
>
>         /* Try to obtain a free object. */
> @@ -424,13 +424,13 @@ static void *kfence_guarded_alloc(struct kmem_cache *cache, size_t size, gfp_t g
>
>         alloc_covered_add(alloc_stack_hash, 1);
>
> -       /* Set required struct page fields. */
> -       page = virt_to_page(meta->addr);
> -       page->slab_cache = cache;
> +       /* Set required slab fields. */
> +       slab = virt_to_slab((void *)meta->addr);
> +       slab->slab_cache = cache;
>         if (IS_ENABLED(CONFIG_SLUB))
> -               page->objects = 1;
> +               slab->objects = 1;
>         if (IS_ENABLED(CONFIG_SLAB))
> -               page->s_mem = addr;
> +               slab->s_mem = addr;
>
>         /* Memory initialization. */
>         for_each_canary(meta, set_canary_byte);
> diff --git a/mm/kfence/kfence_test.c b/mm/kfence/kfence_test.c
> index f7276711d7b9..a22b1af85577 100644
> --- a/mm/kfence/kfence_test.c
> +++ b/mm/kfence/kfence_test.c
> @@ -282,7 +282,7 @@ static void *test_alloc(struct kunit *test, size_t size, gfp_t gfp, enum allocat
>                         alloc = kmalloc(size, gfp);
>
>                 if (is_kfence_address(alloc)) {
> -                       struct page *page = virt_to_head_page(alloc);
> +                       struct slab *slab = virt_to_slab(alloc);
>                         struct kmem_cache *s = test_cache ?:
>                                         kmalloc_caches[kmalloc_type(GFP_KERNEL)][__kmalloc_index(size, false)];
>
> @@ -291,8 +291,8 @@ static void *test_alloc(struct kunit *test, size_t size, gfp_t gfp, enum allocat
>                          * even for KFENCE objects; these are required so that
>                          * memcg accounting works correctly.
>                          */
> -                       KUNIT_EXPECT_EQ(test, obj_to_index(s, page_slab(page), alloc), 0U);
> -                       KUNIT_EXPECT_EQ(test, objs_per_slab(s, page_slab(page)), 1);
> +                       KUNIT_EXPECT_EQ(test, obj_to_index(s, slab, alloc), 0U);
> +                       KUNIT_EXPECT_EQ(test, objs_per_slab(s, slab), 1);
>
>                         if (policy == ALLOCATE_ANY)
>                                 return alloc;
> --
> 2.33.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNPOWFLEAvTD%2B%2BNfwiCU4kt%3D-bAX64PEjUsdjs65EsiGJQ%40mail.gmail.com.
