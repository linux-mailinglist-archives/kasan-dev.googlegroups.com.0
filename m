Return-Path: <kasan-dev+bncBC7OBJGL2MHBB2WJROQQMGQEE2YGS6A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb37.google.com (mail-yb1-xb37.google.com [IPv6:2607:f8b0:4864:20::b37])
	by mail.lfdr.de (Postfix) with ESMTPS id DA5CE6CC004
	for <lists+kasan-dev@lfdr.de>; Tue, 28 Mar 2023 15:00:27 +0200 (CEST)
Received: by mail-yb1-xb37.google.com with SMTP id y144-20020a253296000000b00b69ce0e6f2dsf11933978yby.18
        for <lists+kasan-dev@lfdr.de>; Tue, 28 Mar 2023 06:00:27 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1680008426; cv=pass;
        d=google.com; s=arc-20160816;
        b=Qg8mrVkEVcCBZ1TCp2XfnZM8RMVM2U1OfV0lqmoZQnl6AnP3m9raZ7k44Q5CCTp3WA
         X1MjaxVOB8KOGyfE4q3O0da62CY4ADznpH/c5u/whLiCRq2vscJRd8ofpHA3IRhI3GZ8
         XujRlkmh98r8q79EMKqMP57/u5tmz1f/WZPwIUg+JUnFKC5wu3GpKh5iWKEm01G/tQFS
         aBy4xG8ojhpf010yvwd6bkB3UZrGQ3fL/7Zvo8MOEFXdzba3EJI5lmeLDFee+MzQwcIb
         1Qdt0yZY0sSzQ/zwz8/NF4HBVwDBbi+5jJgiPAplAdQynZTFliOvgVF4+KMmmUhDPLA0
         NtpA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=z7GRzFKMrGxH1ssa+PHw557qqmmxNweqp3LlC7Ery4Q=;
        b=gOO/CtevOdJ2h9Co9/4dEgmlrrWuZW2v0hdvu0NwKyiUVEwddlqzPIVXelD8+NaYv6
         5jzJcn1s6Ur86fVtePB0/cXPX0tfzIm6nDhXK7kM1rKEUI5f/SJ0X+BF+CfcJt0sP5AZ
         T4GRJnc71BcrzdbXCARPAs8IQNeP6QseSNmfIV2uX8UY3QFGBu514OQHyFCzWVC6XGgu
         QawnAei4l1mBJwmKbEeFRKPRvNPLvQpCpcr0+EDSiHY4Z7BL4nwVCMJ9xw6FICxf9CHn
         fq8vUOqsRX+XqCqj1Hh+z/xnME8GpzMAts2Q7ynkqLnySMK8ZhNidZ9C+XOPATNUE+2z
         H+lw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=tUw9ivkO;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::112d as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112; t=1680008426;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=z7GRzFKMrGxH1ssa+PHw557qqmmxNweqp3LlC7Ery4Q=;
        b=Muxa4Qb+E95ptoA/oF03FByxxXDWJbtz42VdHdeCpwGJUlHa8nKiI0s1nKev4TtWRD
         D932FcZA612p7r0vAF0uB0smXOU1gifstAoItQUosyxu7l3pBOLPj/g9sK3TQHwWF5nh
         hNFqCiXsNPQZMdry22fFpnprY24hDsJvgrE131kUNTbRakcbBD93V4q+VFlg18NI39wi
         TsX4IdQ/x52rEIw5w8w2i6yKCXeCqBUludm4p49kwVZw6CHIT05VfP/Rkx5h3Jmc+TBx
         NQpomoB2GafbK+2jTQXv2uksb61WPXAnhwsqYnr4zQtPJ3BjsEeTKmMY3qu5uNX3F0gL
         N9+g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112; t=1680008426;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=z7GRzFKMrGxH1ssa+PHw557qqmmxNweqp3LlC7Ery4Q=;
        b=m90k2m1h0SJyBq0q8wK2EU0QqMH3VQ3Wd/xU35Ttut03UYfYxR+2m4rOEAGwUttCqs
         5a2H/CcABYRkFyxPQwshTjk0rrXupZ8JMLRQDTwB+DBmpXe1meahSt/EP6xkww6Otqo+
         aw8WFGuGQKMsJ7+9D7VY2TQj+VYhFBBFaqdrGnGk7kmSzsCCUrxHUU8bp3lMFP7nnzPU
         Xve9lBfYCnt5Lc4t9jbOow9G6e2cxBCY+JtAerTY0bpuHp58WjCoPhprfU9lCRF/kLU5
         x9GORXG7h27OMeo//FrhS78MLNaQMQ7BvXTxsrvPHAefE9HSwDOtvdoiGdE8Ls0alPRv
         hXOA==
X-Gm-Message-State: AAQBX9ddxVRciVxuo4dcSMG79ux1q9PxcMRb8VuoxIz7HcAZtCxer0Hh
	mhvGV5SzBVMfwTCvcrZ0RKo=
X-Google-Smtp-Source: AKy350ZyIEJNRzmBTV0YFAZ9l/qWHVY5gpTLj6fqbuc6cOoybD79HMmg31xD2SfLImasPKkMmse0bA==
X-Received: by 2002:a05:6902:1145:b0:b09:6f3d:ea1f with SMTP id p5-20020a056902114500b00b096f3dea1fmr9684164ybu.4.1680008426540;
        Tue, 28 Mar 2023 06:00:26 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:690c:d86:b0:541:a1f8:430b with SMTP id
 da6-20020a05690c0d8600b00541a1f8430bls7111773ywb.3.-pod-prod-gmail; Tue, 28
 Mar 2023 06:00:25 -0700 (PDT)
X-Received: by 2002:a81:6606:0:b0:544:75c2:d4a1 with SMTP id a6-20020a816606000000b0054475c2d4a1mr15304535ywc.17.1680008425695;
        Tue, 28 Mar 2023 06:00:25 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1680008425; cv=none;
        d=google.com; s=arc-20160816;
        b=G8pFesUd6zKIiL0E1OCuGQ3/XSrbhTfkxrkltsgik+PHT3Fna0lnQ+JoH4k9+0dK5M
         fyYbP7ilp7SG2DLal9HSoypGv/e1RuVz5Kicrbcm6mJDtrUr4G+pmcxaakNAiStFGwmr
         2IAtmfvOPLITAQPUMCiuZRWOIU4JwJ8v2dDZq29rXCDhAdZxJXvKxKyRAtODxUcq4F2c
         Jftb8vlOrurIL/CC0uyid/aoqDynol39Pjxp7pe3fPQp1YiSKafMJ7ctz/5JXT6T5AyN
         YqKZNxep5yay7sgKhKM5Q+ESstOzYcGG1BMGJ+HikwW+UYzqEgk6q+PIZX2wecL2ONO5
         LEVQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=+huGA2Pj+bVMB5ImXYOSsvTzp1LUROSbW9q/pibPfZk=;
        b=Uvib433/J2C0LSi+75okk5ZaxkFrftEZOz3o9eD0xklfBjf4suBlD1pt4VBZtfRhsQ
         NauI/2WT4uYV4ezmSWcyuyFh/D2/F3HTVuoK9EiXkFOcjzxUAW5idbrejq00QKsLPKuV
         HU/xdKzNPXv7Hw+Tyn0yOSlkmjaGa74PGjaQTrs4WLdpbTNGmNGTAuJ6Wmf/nxoxBfxq
         9mbnxhpzdAfSlq79aEKF4SQ5Y4eu61w7YpiZZ+8O9SHGoHmDpzkkNetqN3ho2IgnoJgq
         zyfd+khjEaywvxE8GPkooITsdymzT36QyRkt4JKoDggYmmmA1rgbCYcEQvozYB3xBfGf
         wykg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=tUw9ivkO;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::112d as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x112d.google.com (mail-yw1-x112d.google.com. [2607:f8b0:4864:20::112d])
        by gmr-mx.google.com with ESMTPS id t206-20020a8183d7000000b0054189968a0bsi1689416ywf.4.2023.03.28.06.00.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 28 Mar 2023 06:00:25 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::112d as permitted sender) client-ip=2607:f8b0:4864:20::112d;
Received: by mail-yw1-x112d.google.com with SMTP id 00721157ae682-54184571389so227825157b3.4
        for <kasan-dev@googlegroups.com>; Tue, 28 Mar 2023 06:00:25 -0700 (PDT)
X-Received: by 2002:a0d:c787:0:b0:542:471d:ec62 with SMTP id
 j129-20020a0dc787000000b00542471dec62mr14895469ywd.25.1680008425050; Tue, 28
 Mar 2023 06:00:25 -0700 (PDT)
MIME-Version: 1.0
References: <20230328095807.7014-1-songmuchun@bytedance.com> <20230328095807.7014-6-songmuchun@bytedance.com>
In-Reply-To: <20230328095807.7014-6-songmuchun@bytedance.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 28 Mar 2023 14:59:48 +0200
Message-ID: <CANpmjNPZxDYPYzEjr55ONydwH1FZF_Eh_gu7XKg=4-+HK6vL9Q@mail.gmail.com>
Subject: Re: [PATCH 5/6] mm: kfence: change kfence pool page layout
To: Muchun Song <songmuchun@bytedance.com>
Cc: glider@google.com, dvyukov@google.com, akpm@linux-foundation.org, 
	jannh@google.com, sjpark@amazon.de, muchun.song@linux.dev, 
	kasan-dev@googlegroups.com, linux-mm@kvack.org, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=tUw9ivkO;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::112d as
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

On Tue, 28 Mar 2023 at 11:58, 'Muchun Song' via kasan-dev
<kasan-dev@googlegroups.com> wrote:
>
> The original kfence pool layout (Given a layout with 2 objects):
>
>  +------------+------------+------------+------------+------------+------------+
>  | guard page | guard page |   object   | guard page |   object   | guard page |
>  +------------+------------+------------+------------+------------+------------+
>                            |                         |                         |
>                            +----kfence_metadata[0]---+----kfence_metadata[1]---+
>
> The comment says "the additional page in the beginning gives us an even
> number of pages, which simplifies the mapping of address to metadata index".
>
> However, removing the additional page does not complicate any mapping
> calculations. So changing it to the new layout to save a page. And remmove
> the KFENCE_ERROR_INVALID test since we cannot test this case easily.
>
> The new kfence pool layout (Given a layout with 2 objects):
>
>  +------------+------------+------------+------------+------------+
>  | guard page |   object   | guard page |   object   | guard page |
>  +------------+------------+------------+------------+------------+
>  |                         |                         |
>  +----kfence_metadata[0]---+----kfence_metadata[1]---+
>
> Signed-off-by: Muchun Song <songmuchun@bytedance.com>
> ---
>  include/linux/kfence.h  |  8 ++------
>  mm/kfence/core.c        | 40 ++++++++--------------------------------
>  mm/kfence/kfence.h      |  2 +-
>  mm/kfence/kfence_test.c | 14 --------------
>  4 files changed, 11 insertions(+), 53 deletions(-)
>
> diff --git a/include/linux/kfence.h b/include/linux/kfence.h
> index 726857a4b680..25b13a892717 100644
> --- a/include/linux/kfence.h
> +++ b/include/linux/kfence.h
> @@ -19,12 +19,8 @@
>
>  extern unsigned long kfence_sample_interval;
>
> -/*
> - * We allocate an even number of pages, as it simplifies calculations to map
> - * address to metadata indices; effectively, the very first page serves as an
> - * extended guard page, but otherwise has no special purpose.
> - */
> -#define KFENCE_POOL_SIZE ((CONFIG_KFENCE_NUM_OBJECTS + 1) * 2 * PAGE_SIZE)
> +/* The last page serves as an extended guard page. */

The last page is just a normal guard page? I.e. the last 2 pages are:
<object page> | <guard page>

Or did I misunderstand?

> +#define KFENCE_POOL_SIZE       ((CONFIG_KFENCE_NUM_OBJECTS * 2 + 1) * PAGE_SIZE)
>  extern char *__kfence_pool;
>
>  DECLARE_STATIC_KEY_FALSE(kfence_allocation_key);
> diff --git a/mm/kfence/core.c b/mm/kfence/core.c
> index 41befcb3b069..f205b860f460 100644
> --- a/mm/kfence/core.c
> +++ b/mm/kfence/core.c
> @@ -240,24 +240,7 @@ static inline void kfence_unprotect(unsigned long addr)
>
>  static inline unsigned long metadata_to_pageaddr(const struct kfence_metadata *meta)
>  {
> -       unsigned long offset = (meta - kfence_metadata + 1) * PAGE_SIZE * 2;
> -       unsigned long pageaddr = (unsigned long)&__kfence_pool[offset];
> -
> -       /* The checks do not affect performance; only called from slow-paths. */
> -
> -       /* Only call with a pointer into kfence_metadata. */
> -       if (KFENCE_WARN_ON(meta < kfence_metadata ||
> -                          meta >= kfence_metadata + CONFIG_KFENCE_NUM_OBJECTS))
> -               return 0;

Could we retain this WARN_ON? Or just get rid of
metadata_to_pageaddr() altogether, because there's only 1 use left and
the function would now just be a simple ALIGN_DOWN() anyway.

> -       /*
> -        * This metadata object only ever maps to 1 page; verify that the stored
> -        * address is in the expected range.
> -        */
> -       if (KFENCE_WARN_ON(ALIGN_DOWN(meta->addr, PAGE_SIZE) != pageaddr))
> -               return 0;
> -
> -       return pageaddr;
> +       return ALIGN_DOWN(meta->addr, PAGE_SIZE);
>  }
>
>  /*
> @@ -535,34 +518,27 @@ static void kfence_init_pool(void)
>         unsigned long addr = (unsigned long)__kfence_pool;
>         int i;
>
> -       /*
> -        * Protect the first 2 pages. The first page is mostly unnecessary, and
> -        * merely serves as an extended guard page. However, adding one
> -        * additional page in the beginning gives us an even number of pages,
> -        * which simplifies the mapping of address to metadata index.
> -        */
> -       for (i = 0; i < 2; i++, addr += PAGE_SIZE)
> -               kfence_protect(addr);
> -
>         for (i = 0; i < CONFIG_KFENCE_NUM_OBJECTS; i++, addr += 2 * PAGE_SIZE) {
>                 struct kfence_metadata *meta = &kfence_metadata[i];
> -               struct slab *slab = page_slab(virt_to_page(addr));
> +               struct slab *slab = page_slab(virt_to_page(addr + PAGE_SIZE));
>
>                 /* Initialize metadata. */
>                 INIT_LIST_HEAD(&meta->list);
>                 raw_spin_lock_init(&meta->lock);
>                 meta->state = KFENCE_OBJECT_UNUSED;
> -               meta->addr = addr; /* Initialize for validation in metadata_to_pageaddr(). */
> +               meta->addr = addr + PAGE_SIZE;
>                 list_add_tail(&meta->list, &kfence_freelist);
>
> -               /* Protect the right redzone. */
> -               kfence_protect(addr + PAGE_SIZE);
> +               /* Protect the left redzone. */
> +               kfence_protect(addr);
>
>                 __folio_set_slab(slab_folio(slab));
>  #ifdef CONFIG_MEMCG
>                 slab->memcg_data = (unsigned long)&meta->objcg | MEMCG_DATA_OBJCGS;
>  #endif
>         }
> +
> +       kfence_protect(addr);
>  }
>
>  static bool __init kfence_init_pool_early(void)
> @@ -1043,7 +1019,7 @@ bool kfence_handle_page_fault(unsigned long addr, bool is_write, struct pt_regs
>
>         atomic_long_inc(&counters[KFENCE_COUNTER_BUGS]);
>
> -       if (page_index % 2) {
> +       if (page_index % 2 == 0) {
>                 /* This is a redzone, report a buffer overflow. */
>                 struct kfence_metadata *meta;
>                 int distance = 0;
> diff --git a/mm/kfence/kfence.h b/mm/kfence/kfence.h
> index 600f2e2431d6..249d420100a7 100644
> --- a/mm/kfence/kfence.h
> +++ b/mm/kfence/kfence.h
> @@ -110,7 +110,7 @@ static inline struct kfence_metadata *addr_to_metadata(unsigned long addr)
>          * __kfence_pool, in which case we would report an "invalid access"
>          * error.
>          */
> -       index = (addr - (unsigned long)__kfence_pool) / (PAGE_SIZE * 2) - 1;
> +       index = (addr - (unsigned long)__kfence_pool) / (PAGE_SIZE * 2);
>         if (index < 0 || index >= CONFIG_KFENCE_NUM_OBJECTS)
>                 return NULL;

Assume there is a right OOB that hit the last guard page. In this case

  addr >= __kfence_pool + (NUM_OBJECTS * 2 * PAGE_SIZE) && addr <
__kfence_pool + POOL_SIZE

therefore

  index >= (NUM_OBJECTS * 2 * PAGE_SIZE) / (PAGE_SIZE * 2) && index <
POOL_SIZE / (PAGE_SIZE * 2)
  index == NUM_OBJECTS

And according to the above comparison, this will return NULL and
report KFENCE_ERROR_INVALID, which is wrong.

> diff --git a/mm/kfence/kfence_test.c b/mm/kfence/kfence_test.c
> index b5d66a69200d..d479f9c8afb1 100644
> --- a/mm/kfence/kfence_test.c
> +++ b/mm/kfence/kfence_test.c
> @@ -637,19 +637,6 @@ static void test_gfpzero(struct kunit *test)
>         KUNIT_EXPECT_FALSE(test, report_available());
>  }
>
> -static void test_invalid_access(struct kunit *test)
> -{
> -       const struct expect_report expect = {
> -               .type = KFENCE_ERROR_INVALID,
> -               .fn = test_invalid_access,
> -               .addr = &__kfence_pool[10],
> -               .is_write = false,
> -       };
> -
> -       READ_ONCE(__kfence_pool[10]);
> -       KUNIT_EXPECT_TRUE(test, report_matches(&expect));
> -}
> -
>  /* Test SLAB_TYPESAFE_BY_RCU works. */
>  static void test_memcache_typesafe_by_rcu(struct kunit *test)
>  {
> @@ -787,7 +774,6 @@ static struct kunit_case kfence_test_cases[] = {
>         KUNIT_CASE(test_kmalloc_aligned_oob_write),
>         KUNIT_CASE(test_shrink_memcache),
>         KUNIT_CASE(test_memcache_ctor),
> -       KUNIT_CASE(test_invalid_access),

The test can be retained by doing an access to a guard page in between
2 unallocated objects. But it's probably not that easy to reliably set
that up (could try to allocate 2 objects and see if they're next to
each other, then free them).

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNPZxDYPYzEjr55ONydwH1FZF_Eh_gu7XKg%3D4-%2BHK6vL9Q%40mail.gmail.com.
