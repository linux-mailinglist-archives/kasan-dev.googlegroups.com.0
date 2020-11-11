Return-Path: <kasan-dev+bncBCCMH5WKTMGRBPXAV76QKGQE7CF2COQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53e.google.com (mail-pg1-x53e.google.com [IPv6:2607:f8b0:4864:20::53e])
	by mail.lfdr.de (Postfix) with ESMTPS id CBF4A2AF312
	for <lists+kasan-dev@lfdr.de>; Wed, 11 Nov 2020 15:07:59 +0100 (CET)
Received: by mail-pg1-x53e.google.com with SMTP id 33sf1388242pgt.9
        for <lists+kasan-dev@lfdr.de>; Wed, 11 Nov 2020 06:07:59 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605103678; cv=pass;
        d=google.com; s=arc-20160816;
        b=g5DoHaSYn5f9+w+RkBjv869z70Qy0/FaBn3waiIe9gpoHNP8sQvp1FXoeGHKGRwD7t
         eKixwlfHYq+d2O7cY79E+n+RJvkOOjd/lh3MuOPVHrEzgkgHporDHCKO1CoKaZSScrRU
         wU1AkEFsHiTE6xICvd1Nt7DGpU3Ja27aCFA2xWrpQ+XWmSu1rJh/T9zHjRGXusqRap3K
         Q035m72ays5WCDGqcljWmCBARQ8uC02D8eZ3TePS6KNO/OMeE/LEg3UUTua0GLV96NJ5
         y8hYFNjOhg3Nl1XbvnljvuVPERGYTxdMCQd6zSGfqkXCL8uE2Hl189c1Fl4iqQCmnKFa
         fy6A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=rQlrVab/IzR9jRFVI+M4M8Rac2LbFoK/mbkRKpBg2Ww=;
        b=CQJk8exW3PGA8z3VBaVu18KPPs5xEC7dTEfSM3XH8NvuqqN7y2cXHhvRkMRYCoetEh
         uCKR4p+POQpqtQGFAR8IfaRjmwOsIpZEfEZmQyGUUkF0xZsoskxEk0JDqOfzmFXSqsZn
         Al5bsHsMW/Xq7+HYxJP1cqc+a2HW4+1qj+yjEICwuPft4W2/Z4sgYQjo3WoYlTdJ7YA0
         XY1TvIUmHMcuFN2xyL8DYxdouednifjMh0FDY+AW9BalG0vrvXk50Ac7+HOLWg9xe0GR
         eYskcIv0N5A/jt9SqW5AgOMyD33uSoilZE3CPfM+33tEPagNkztce4KdsuxOKAsnCtyA
         V7CQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=oNeVCz3A;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::843 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=rQlrVab/IzR9jRFVI+M4M8Rac2LbFoK/mbkRKpBg2Ww=;
        b=eu3GHflJ5y2cgZ5zFLL7Cf9ZSUs95JGRhDcgqm760+glVpZVPQJAyqRGVCnasy45fq
         2qWNfwLNIkaNMq0xjSnST+KRoFCbu/xMs+4P0IRXm0BP0LKmFKKPve9v6AbkSp8RXP7a
         WTQkdO5TK4XSCNUUaMu1l6Vz6wGFJV+kCy4gE4AX88r+UY/1pE6PGDCwl7P/9G6UQsS+
         8p5HPOpbbGh0Eh6DuAZ5Ynr7vuUjFznbgUhpbqU8qsjPEvRT8whAh8R5LiX1EtWdszXa
         k4G69SvKIXn0PJfTJua/PRsR5Ypy7oS7b327bC1qpJ2baaDdiNrKOTQz8cnfFQQ6IBAR
         ySzA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=rQlrVab/IzR9jRFVI+M4M8Rac2LbFoK/mbkRKpBg2Ww=;
        b=Y8k2/EFUTS9Tb3n5Yubq9kmprjSTOhuw3sNWgANIKlxar5S10XcKKhRQ+uhXiEtNEV
         YKu2Q7/EFKUJL20SMKiGRv2724+MhqczRxFrLOG6lZ9hk6+jIwIetEb2zl47i5VxT64o
         /1q6+8u7MOdUwE1X4OJjNsvIY9WysQYWp6N7vaK0+2UN0c6QuURm6yao0J7yQWKj77D3
         YZqE9PDuKVj5yK8jy68+FxlnpGPM0v6KvpQGw66pXN5cK6VhGqOq44If8NXOp3S8YoLx
         KaPeVIE1oO/g/1mTNRJwPiBhg7bNOkd9WViFBzLug5NhD+uoxDFc70tK5KxC/KAYRNtx
         PzyQ==
X-Gm-Message-State: AOAM532fniZZEQK0X4+ki4Spgh5IL8xHKwA7AUxx/O8EZ09HfVEzXsz7
	N83eCCHX/CkmrQMYiIWw7Uk=
X-Google-Smtp-Source: ABdhPJx7Kl42rYtBWOJikRAQU5Df9y59tuY9JRFurcsxg581DDNHQJEDQvBe3jLJsLyR9GNrDCLZTQ==
X-Received: by 2002:a63:4d5c:: with SMTP id n28mr21717828pgl.88.1605103678507;
        Wed, 11 Nov 2020 06:07:58 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:6b4a:: with SMTP id g10ls6969290plt.6.gmail; Wed, 11
 Nov 2020 06:07:58 -0800 (PST)
X-Received: by 2002:a17:902:342:b029:d5:ab9e:19ce with SMTP id 60-20020a1709020342b02900d5ab9e19cemr21947820pld.48.1605103677882;
        Wed, 11 Nov 2020 06:07:57 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605103677; cv=none;
        d=google.com; s=arc-20160816;
        b=JJU/qrfXFN1herkza1xYY2sBMfkyrtOyJsQhHdV5K0yAPUfN2AGA813w8HOfhBRIhq
         zHwhgwk1eAczinDy5oZK/NlWZTkll+lGztIDNTrL3ybO7iQBtfh5Gw7v1MCQt9DmKTWG
         PQlxknWqKzjd/mkBk6nccvPDPwcydCwxUdnUWnD+INpno7BF00Y2Lm+MWU1KvzZmez5C
         U/VZ2lGfmDtZ5/rOBqLG0eGgYpqL2EWfspmQN/8xsnz6BYWp2gf0HTV6xsfDBDmu6987
         hBqganrshWl6gSAefEX0jhwP09wbhdvaEU1WnvRSx/27DDIM92irKh5i0Pv4lchV+Yv7
         8dZw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=DdD68Y4Suffqj0ErTJkvwPVVv9KGFkYa0+/VucJpEKw=;
        b=feJ7ptLTl5f1h2PUj8+L2KpM3E8mbusNWOdSi3XZ/JFJ4A10IsMrL5ugPkd0SItCS8
         AGr+HV8oOPERwVyfYSJiBEGlBpROoKksjbhOxCzsTahahVsxQ3MHk+7UgbkBYgY79Oii
         A1DWTldikQs8Jjc4jxQcddZDiwA655Bbb+qkc7BT8VXj6kNMfgS25frkrFeBuGJL1PUN
         5+2P1bgCx78bO0IZFZ2f8s69mC1YaqHLzIhlzgnz+Ggr6c2t0q77MS9XiPmxPIRwkQEA
         A+ooGecnOUKz/72h2Zz8MWs3l+QDq9p/RFghkasK1RuqCEzmlJ9JjBS/bq3Ay7VSnxUK
         ox5A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=oNeVCz3A;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::843 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x843.google.com (mail-qt1-x843.google.com. [2607:f8b0:4864:20::843])
        by gmr-mx.google.com with ESMTPS id 38si145246pgq.3.2020.11.11.06.07.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 11 Nov 2020 06:07:57 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::843 as permitted sender) client-ip=2607:f8b0:4864:20::843;
Received: by mail-qt1-x843.google.com with SMTP id f93so1299390qtb.10
        for <kasan-dev@googlegroups.com>; Wed, 11 Nov 2020 06:07:57 -0800 (PST)
X-Received: by 2002:a05:622a:291:: with SMTP id z17mr23324607qtw.180.1605103676256;
 Wed, 11 Nov 2020 06:07:56 -0800 (PST)
MIME-Version: 1.0
References: <cover.1605046192.git.andreyknvl@google.com> <0a459278f874b4522d7081a96805f2b3bf3d5a91.1605046192.git.andreyknvl@google.com>
In-Reply-To: <0a459278f874b4522d7081a96805f2b3bf3d5a91.1605046192.git.andreyknvl@google.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 11 Nov 2020 15:07:42 +0100
Message-ID: <CAG_fn=V+HeWXU2zLf43P1e854JpZw5h+fAuLL161iHt2Mia9Zg@mail.gmail.com>
Subject: Re: [PATCH v9 09/44] kasan: split out shadow.c from common.c
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Marco Elver <elver@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=oNeVCz3A;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::843 as
 permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

On Tue, Nov 10, 2020 at 11:11 PM Andrey Konovalov <andreyknvl@google.com> w=
rote:
>
> This is a preparatory commit for the upcoming addition of a new hardware
> tag-based (MTE-based) KASAN mode.
>
> The new mode won't be using shadow memory. Move all shadow-related code
> to shadow.c, which is only enabled for software KASAN modes that use
> shadow memory.
>
> No functional changes for software modes.
>
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
> Reviewed-by: Marco Elver <elver@google.com>
Reviewed-by: Alexander Potapenko <glider@google.com>

> ---
> Change-Id: Ic1c32ce72d4649848e9e6a1f2c8dd269c77673f2
> ---
>  mm/kasan/Makefile |   6 +-
>  mm/kasan/common.c | 486 +-------------------------------------------
>  mm/kasan/shadow.c | 505 ++++++++++++++++++++++++++++++++++++++++++++++
>  3 files changed, 510 insertions(+), 487 deletions(-)
>  create mode 100644 mm/kasan/shadow.c
>
> diff --git a/mm/kasan/Makefile b/mm/kasan/Makefile
> index 7cf685bb51bd..7cc1031e1ef8 100644
> --- a/mm/kasan/Makefile
> +++ b/mm/kasan/Makefile
> @@ -10,6 +10,7 @@ CFLAGS_REMOVE_generic_report.o =3D $(CC_FLAGS_FTRACE)
>  CFLAGS_REMOVE_init.o =3D $(CC_FLAGS_FTRACE)
>  CFLAGS_REMOVE_quarantine.o =3D $(CC_FLAGS_FTRACE)
>  CFLAGS_REMOVE_report.o =3D $(CC_FLAGS_FTRACE)
> +CFLAGS_REMOVE_shadow.o =3D $(CC_FLAGS_FTRACE)
>  CFLAGS_REMOVE_tags.o =3D $(CC_FLAGS_FTRACE)
>  CFLAGS_REMOVE_tags_report.o =3D $(CC_FLAGS_FTRACE)
>
> @@ -26,9 +27,10 @@ CFLAGS_generic_report.o :=3D $(CC_FLAGS_KASAN_RUNTIME)
>  CFLAGS_init.o :=3D $(CC_FLAGS_KASAN_RUNTIME)
>  CFLAGS_quarantine.o :=3D $(CC_FLAGS_KASAN_RUNTIME)
>  CFLAGS_report.o :=3D $(CC_FLAGS_KASAN_RUNTIME)
> +CFLAGS_shadow.o :=3D $(CC_FLAGS_KASAN_RUNTIME)
>  CFLAGS_tags.o :=3D $(CC_FLAGS_KASAN_RUNTIME)
>  CFLAGS_tags_report.o :=3D $(CC_FLAGS_KASAN_RUNTIME)
>
>  obj-$(CONFIG_KASAN) :=3D common.o report.o
> -obj-$(CONFIG_KASAN_GENERIC) +=3D init.o generic.o generic_report.o quara=
ntine.o
> -obj-$(CONFIG_KASAN_SW_TAGS) +=3D init.o tags.o tags_report.o
> +obj-$(CONFIG_KASAN_GENERIC) +=3D init.o generic.o generic_report.o shado=
w.o quarantine.o
> +obj-$(CONFIG_KASAN_SW_TAGS) +=3D init.o shadow.o tags.o tags_report.o
> diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> index f65c9f792f8f..123abfb760d4 100644
> --- a/mm/kasan/common.c
> +++ b/mm/kasan/common.c
> @@ -1,6 +1,6 @@
>  // SPDX-License-Identifier: GPL-2.0
>  /*
> - * This file contains common generic and tag-based KASAN code.
> + * This file contains common KASAN code.
>   *
>   * Copyright (c) 2014 Samsung Electronics Co., Ltd.
>   * Author: Andrey Ryabinin <ryabinin.a.a@gmail.com>
> @@ -13,7 +13,6 @@
>  #include <linux/init.h>
>  #include <linux/kasan.h>
>  #include <linux/kernel.h>
> -#include <linux/kmemleak.h>
>  #include <linux/linkage.h>
>  #include <linux/memblock.h>
>  #include <linux/memory.h>
> @@ -26,12 +25,8 @@
>  #include <linux/stacktrace.h>
>  #include <linux/string.h>
>  #include <linux/types.h>
> -#include <linux/vmalloc.h>
>  #include <linux/bug.h>
>
> -#include <asm/cacheflush.h>
> -#include <asm/tlbflush.h>
> -
>  #include "kasan.h"
>  #include "../slab.h"
>
> @@ -61,93 +56,6 @@ void kasan_disable_current(void)
>         current->kasan_depth--;
>  }
>
> -bool __kasan_check_read(const volatile void *p, unsigned int size)
> -{
> -       return check_memory_region((unsigned long)p, size, false, _RET_IP=
_);
> -}
> -EXPORT_SYMBOL(__kasan_check_read);
> -
> -bool __kasan_check_write(const volatile void *p, unsigned int size)
> -{
> -       return check_memory_region((unsigned long)p, size, true, _RET_IP_=
);
> -}
> -EXPORT_SYMBOL(__kasan_check_write);
> -
> -#undef memset
> -void *memset(void *addr, int c, size_t len)
> -{
> -       if (!check_memory_region((unsigned long)addr, len, true, _RET_IP_=
))
> -               return NULL;
> -
> -       return __memset(addr, c, len);
> -}
> -
> -#ifdef __HAVE_ARCH_MEMMOVE
> -#undef memmove
> -void *memmove(void *dest, const void *src, size_t len)
> -{
> -       if (!check_memory_region((unsigned long)src, len, false, _RET_IP_=
) ||
> -           !check_memory_region((unsigned long)dest, len, true, _RET_IP_=
))
> -               return NULL;
> -
> -       return __memmove(dest, src, len);
> -}
> -#endif
> -
> -#undef memcpy
> -void *memcpy(void *dest, const void *src, size_t len)
> -{
> -       if (!check_memory_region((unsigned long)src, len, false, _RET_IP_=
) ||
> -           !check_memory_region((unsigned long)dest, len, true, _RET_IP_=
))
> -               return NULL;
> -
> -       return __memcpy(dest, src, len);
> -}
> -
> -/*
> - * Poisons the shadow memory for 'size' bytes starting from 'addr'.
> - * Memory addresses should be aligned to KASAN_GRANULE_SIZE.
> - */
> -void kasan_poison_memory(const void *address, size_t size, u8 value)
> -{
> -       void *shadow_start, *shadow_end;
> -
> -       /*
> -        * Perform shadow offset calculation based on untagged address, a=
s
> -        * some of the callers (e.g. kasan_poison_object_data) pass tagge=
d
> -        * addresses to this function.
> -        */
> -       address =3D reset_tag(address);
> -
> -       shadow_start =3D kasan_mem_to_shadow(address);
> -       shadow_end =3D kasan_mem_to_shadow(address + size);
> -
> -       __memset(shadow_start, value, shadow_end - shadow_start);
> -}
> -
> -void kasan_unpoison_memory(const void *address, size_t size)
> -{
> -       u8 tag =3D get_tag(address);
> -
> -       /*
> -        * Perform shadow offset calculation based on untagged address, a=
s
> -        * some of the callers (e.g. kasan_unpoison_object_data) pass tag=
ged
> -        * addresses to this function.
> -        */
> -       address =3D reset_tag(address);
> -
> -       kasan_poison_memory(address, size, tag);
> -
> -       if (size & KASAN_GRANULE_MASK) {
> -               u8 *shadow =3D (u8 *)kasan_mem_to_shadow(address + size);
> -
> -               if (IS_ENABLED(CONFIG_KASAN_SW_TAGS))
> -                       *shadow =3D tag;
> -               else
> -                       *shadow =3D size & KASAN_GRANULE_MASK;
> -       }
> -}
> -
>  static void __kasan_unpoison_stack(struct task_struct *task, const void =
*sp)
>  {
>         void *base =3D task_stack_page(task);
> @@ -535,395 +443,3 @@ void kasan_kfree_large(void *ptr, unsigned long ip)
>                 kasan_report_invalid_free(ptr, ip);
>         /* The object will be poisoned by page_alloc. */
>  }
> -
> -#ifdef CONFIG_MEMORY_HOTPLUG
> -static bool shadow_mapped(unsigned long addr)
> -{
> -       pgd_t *pgd =3D pgd_offset_k(addr);
> -       p4d_t *p4d;
> -       pud_t *pud;
> -       pmd_t *pmd;
> -       pte_t *pte;
> -
> -       if (pgd_none(*pgd))
> -               return false;
> -       p4d =3D p4d_offset(pgd, addr);
> -       if (p4d_none(*p4d))
> -               return false;
> -       pud =3D pud_offset(p4d, addr);
> -       if (pud_none(*pud))
> -               return false;
> -
> -       /*
> -        * We can't use pud_large() or pud_huge(), the first one is
> -        * arch-specific, the last one depends on HUGETLB_PAGE.  So let's=
 abuse
> -        * pud_bad(), if pud is bad then it's bad because it's huge.
> -        */
> -       if (pud_bad(*pud))
> -               return true;
> -       pmd =3D pmd_offset(pud, addr);
> -       if (pmd_none(*pmd))
> -               return false;
> -
> -       if (pmd_bad(*pmd))
> -               return true;
> -       pte =3D pte_offset_kernel(pmd, addr);
> -       return !pte_none(*pte);
> -}
> -
> -static int __meminit kasan_mem_notifier(struct notifier_block *nb,
> -                       unsigned long action, void *data)
> -{
> -       struct memory_notify *mem_data =3D data;
> -       unsigned long nr_shadow_pages, start_kaddr, shadow_start;
> -       unsigned long shadow_end, shadow_size;
> -
> -       nr_shadow_pages =3D mem_data->nr_pages >> KASAN_SHADOW_SCALE_SHIF=
T;
> -       start_kaddr =3D (unsigned long)pfn_to_kaddr(mem_data->start_pfn);
> -       shadow_start =3D (unsigned long)kasan_mem_to_shadow((void *)start=
_kaddr);
> -       shadow_size =3D nr_shadow_pages << PAGE_SHIFT;
> -       shadow_end =3D shadow_start + shadow_size;
> -
> -       if (WARN_ON(mem_data->nr_pages % KASAN_GRANULE_SIZE) ||
> -               WARN_ON(start_kaddr % (KASAN_GRANULE_SIZE << PAGE_SHIFT))=
)
> -               return NOTIFY_BAD;
> -
> -       switch (action) {
> -       case MEM_GOING_ONLINE: {
> -               void *ret;
> -
> -               /*
> -                * If shadow is mapped already than it must have been map=
ped
> -                * during the boot. This could happen if we onlining prev=
iously
> -                * offlined memory.
> -                */
> -               if (shadow_mapped(shadow_start))
> -                       return NOTIFY_OK;
> -
> -               ret =3D __vmalloc_node_range(shadow_size, PAGE_SIZE, shad=
ow_start,
> -                                       shadow_end, GFP_KERNEL,
> -                                       PAGE_KERNEL, VM_NO_GUARD,
> -                                       pfn_to_nid(mem_data->start_pfn),
> -                                       __builtin_return_address(0));
> -               if (!ret)
> -                       return NOTIFY_BAD;
> -
> -               kmemleak_ignore(ret);
> -               return NOTIFY_OK;
> -       }
> -       case MEM_CANCEL_ONLINE:
> -       case MEM_OFFLINE: {
> -               struct vm_struct *vm;
> -
> -               /*
> -                * shadow_start was either mapped during boot by kasan_in=
it()
> -                * or during memory online by __vmalloc_node_range().
> -                * In the latter case we can use vfree() to free shadow.
> -                * Non-NULL result of the find_vm_area() will tell us if
> -                * that was the second case.
> -                *
> -                * Currently it's not possible to free shadow mapped
> -                * during boot by kasan_init(). It's because the code
> -                * to do that hasn't been written yet. So we'll just
> -                * leak the memory.
> -                */
> -               vm =3D find_vm_area((void *)shadow_start);
> -               if (vm)
> -                       vfree((void *)shadow_start);
> -       }
> -       }
> -
> -       return NOTIFY_OK;
> -}
> -
> -static int __init kasan_memhotplug_init(void)
> -{
> -       hotplug_memory_notifier(kasan_mem_notifier, 0);
> -
> -       return 0;
> -}
> -
> -core_initcall(kasan_memhotplug_init);
> -#endif
> -
> -#ifdef CONFIG_KASAN_VMALLOC
> -
> -static int kasan_populate_vmalloc_pte(pte_t *ptep, unsigned long addr,
> -                                     void *unused)
> -{
> -       unsigned long page;
> -       pte_t pte;
> -
> -       if (likely(!pte_none(*ptep)))
> -               return 0;
> -
> -       page =3D __get_free_page(GFP_KERNEL);
> -       if (!page)
> -               return -ENOMEM;
> -
> -       memset((void *)page, KASAN_VMALLOC_INVALID, PAGE_SIZE);
> -       pte =3D pfn_pte(PFN_DOWN(__pa(page)), PAGE_KERNEL);
> -
> -       spin_lock(&init_mm.page_table_lock);
> -       if (likely(pte_none(*ptep))) {
> -               set_pte_at(&init_mm, addr, ptep, pte);
> -               page =3D 0;
> -       }
> -       spin_unlock(&init_mm.page_table_lock);
> -       if (page)
> -               free_page(page);
> -       return 0;
> -}
> -
> -int kasan_populate_vmalloc(unsigned long addr, unsigned long size)
> -{
> -       unsigned long shadow_start, shadow_end;
> -       int ret;
> -
> -       if (!is_vmalloc_or_module_addr((void *)addr))
> -               return 0;
> -
> -       shadow_start =3D (unsigned long)kasan_mem_to_shadow((void *)addr)=
;
> -       shadow_start =3D ALIGN_DOWN(shadow_start, PAGE_SIZE);
> -       shadow_end =3D (unsigned long)kasan_mem_to_shadow((void *)addr + =
size);
> -       shadow_end =3D ALIGN(shadow_end, PAGE_SIZE);
> -
> -       ret =3D apply_to_page_range(&init_mm, shadow_start,
> -                                 shadow_end - shadow_start,
> -                                 kasan_populate_vmalloc_pte, NULL);
> -       if (ret)
> -               return ret;
> -
> -       flush_cache_vmap(shadow_start, shadow_end);
> -
> -       /*
> -        * We need to be careful about inter-cpu effects here. Consider:
> -        *
> -        *   CPU#0                                CPU#1
> -        * WRITE_ONCE(p, vmalloc(100));         while (x =3D READ_ONCE(p)=
) ;
> -        *                                      p[99] =3D 1;
> -        *
> -        * With compiler instrumentation, that ends up looking like this:
> -        *
> -        *   CPU#0                                CPU#1
> -        * // vmalloc() allocates memory
> -        * // let a =3D area->addr
> -        * // we reach kasan_populate_vmalloc
> -        * // and call kasan_unpoison_memory:
> -        * STORE shadow(a), unpoison_val
> -        * ...
> -        * STORE shadow(a+99), unpoison_val     x =3D LOAD p
> -        * // rest of vmalloc process           <data dependency>
> -        * STORE p, a                           LOAD shadow(x+99)
> -        *
> -        * If there is no barrier between the end of unpoisioning the sha=
dow
> -        * and the store of the result to p, the stores could be committe=
d
> -        * in a different order by CPU#0, and CPU#1 could erroneously obs=
erve
> -        * poison in the shadow.
> -        *
> -        * We need some sort of barrier between the stores.
> -        *
> -        * In the vmalloc() case, this is provided by a smp_wmb() in
> -        * clear_vm_uninitialized_flag(). In the per-cpu allocator and in
> -        * get_vm_area() and friends, the caller gets shadow allocated bu=
t
> -        * doesn't have any pages mapped into the virtual address space t=
hat
> -        * has been reserved. Mapping those pages in will involve taking =
and
> -        * releasing a page-table lock, which will provide the barrier.
> -        */
> -
> -       return 0;
> -}
> -
> -/*
> - * Poison the shadow for a vmalloc region. Called as part of the
> - * freeing process at the time the region is freed.
> - */
> -void kasan_poison_vmalloc(const void *start, unsigned long size)
> -{
> -       if (!is_vmalloc_or_module_addr(start))
> -               return;
> -
> -       size =3D round_up(size, KASAN_GRANULE_SIZE);
> -       kasan_poison_memory(start, size, KASAN_VMALLOC_INVALID);
> -}
> -
> -void kasan_unpoison_vmalloc(const void *start, unsigned long size)
> -{
> -       if (!is_vmalloc_or_module_addr(start))
> -               return;
> -
> -       kasan_unpoison_memory(start, size);
> -}
> -
> -static int kasan_depopulate_vmalloc_pte(pte_t *ptep, unsigned long addr,
> -                                       void *unused)
> -{
> -       unsigned long page;
> -
> -       page =3D (unsigned long)__va(pte_pfn(*ptep) << PAGE_SHIFT);
> -
> -       spin_lock(&init_mm.page_table_lock);
> -
> -       if (likely(!pte_none(*ptep))) {
> -               pte_clear(&init_mm, addr, ptep);
> -               free_page(page);
> -       }
> -       spin_unlock(&init_mm.page_table_lock);
> -
> -       return 0;
> -}
> -
> -/*
> - * Release the backing for the vmalloc region [start, end), which
> - * lies within the free region [free_region_start, free_region_end).
> - *
> - * This can be run lazily, long after the region was freed. It runs
> - * under vmap_area_lock, so it's not safe to interact with the vmalloc/v=
map
> - * infrastructure.
> - *
> - * How does this work?
> - * -------------------
> - *
> - * We have a region that is page aligned, labelled as A.
> - * That might not map onto the shadow in a way that is page-aligned:
> - *
> - *                    start                     end
> - *                    v                         v
> - * |????????|????????|AAAAAAAA|AA....AA|AAAAAAAA|????????| < vmalloc
> - *  -------- -------- --------          -------- --------
> - *      |        |       |                 |        |
> - *      |        |       |         /-------/        |
> - *      \-------\|/------/         |/---------------/
> - *              |||                ||
> - *             |??AAAAAA|AAAAAAAA|AA??????|                < shadow
> - *                 (1)      (2)      (3)
> - *
> - * First we align the start upwards and the end downwards, so that the
> - * shadow of the region aligns with shadow page boundaries. In the
> - * example, this gives us the shadow page (2). This is the shadow entire=
ly
> - * covered by this allocation.
> - *
> - * Then we have the tricky bits. We want to know if we can free the
> - * partially covered shadow pages - (1) and (3) in the example. For this=
,
> - * we are given the start and end of the free region that contains this
> - * allocation. Extending our previous example, we could have:
> - *
> - *  free_region_start                                    free_region_end
> - *  |                 start                     end      |
> - *  v                 v                         v        v
> - * |FFFFFFFF|FFFFFFFF|AAAAAAAA|AA....AA|AAAAAAAA|FFFFFFFF| < vmalloc
> - *  -------- -------- --------          -------- --------
> - *      |        |       |                 |        |
> - *      |        |       |         /-------/        |
> - *      \-------\|/------/         |/---------------/
> - *              |||                ||
> - *             |FFAAAAAA|AAAAAAAA|AAF?????|                < shadow
> - *                 (1)      (2)      (3)
> - *
> - * Once again, we align the start of the free region up, and the end of
> - * the free region down so that the shadow is page aligned. So we can fr=
ee
> - * page (1) - we know no allocation currently uses anything in that page=
,
> - * because all of it is in the vmalloc free region. But we cannot free
> - * page (3), because we can't be sure that the rest of it is unused.
> - *
> - * We only consider pages that contain part of the original region for
> - * freeing: we don't try to free other pages from the free region or we'=
d
> - * end up trying to free huge chunks of virtual address space.
> - *
> - * Concurrency
> - * -----------
> - *
> - * How do we know that we're not freeing a page that is simultaneously
> - * being used for a fresh allocation in kasan_populate_vmalloc(_pte)?
> - *
> - * We _can_ have kasan_release_vmalloc and kasan_populate_vmalloc runnin=
g
> - * at the same time. While we run under free_vmap_area_lock, the populat=
ion
> - * code does not.
> - *
> - * free_vmap_area_lock instead operates to ensure that the larger range
> - * [free_region_start, free_region_end) is safe: because __alloc_vmap_ar=
ea and
> - * the per-cpu region-finding algorithm both run under free_vmap_area_lo=
ck,
> - * no space identified as free will become used while we are running. Th=
is
> - * means that so long as we are careful with alignment and only free sha=
dow
> - * pages entirely covered by the free region, we will not run in to any
> - * trouble - any simultaneous allocations will be for disjoint regions.
> - */
> -void kasan_release_vmalloc(unsigned long start, unsigned long end,
> -                          unsigned long free_region_start,
> -                          unsigned long free_region_end)
> -{
> -       void *shadow_start, *shadow_end;
> -       unsigned long region_start, region_end;
> -       unsigned long size;
> -
> -       region_start =3D ALIGN(start, PAGE_SIZE * KASAN_GRANULE_SIZE);
> -       region_end =3D ALIGN_DOWN(end, PAGE_SIZE * KASAN_GRANULE_SIZE);
> -
> -       free_region_start =3D ALIGN(free_region_start,
> -                                 PAGE_SIZE * KASAN_GRANULE_SIZE);
> -
> -       if (start !=3D region_start &&
> -           free_region_start < region_start)
> -               region_start -=3D PAGE_SIZE * KASAN_GRANULE_SIZE;
> -
> -       free_region_end =3D ALIGN_DOWN(free_region_end,
> -                                    PAGE_SIZE * KASAN_GRANULE_SIZE);
> -
> -       if (end !=3D region_end &&
> -           free_region_end > region_end)
> -               region_end +=3D PAGE_SIZE * KASAN_GRANULE_SIZE;
> -
> -       shadow_start =3D kasan_mem_to_shadow((void *)region_start);
> -       shadow_end =3D kasan_mem_to_shadow((void *)region_end);
> -
> -       if (shadow_end > shadow_start) {
> -               size =3D shadow_end - shadow_start;
> -               apply_to_existing_page_range(&init_mm,
> -                                            (unsigned long)shadow_start,
> -                                            size, kasan_depopulate_vmall=
oc_pte,
> -                                            NULL);
> -               flush_tlb_kernel_range((unsigned long)shadow_start,
> -                                      (unsigned long)shadow_end);
> -       }
> -}
> -
> -#else /* CONFIG_KASAN_VMALLOC */
> -
> -int kasan_module_alloc(void *addr, size_t size)
> -{
> -       void *ret;
> -       size_t scaled_size;
> -       size_t shadow_size;
> -       unsigned long shadow_start;
> -
> -       shadow_start =3D (unsigned long)kasan_mem_to_shadow(addr);
> -       scaled_size =3D (size + KASAN_GRANULE_SIZE - 1) >>
> -                               KASAN_SHADOW_SCALE_SHIFT;
> -       shadow_size =3D round_up(scaled_size, PAGE_SIZE);
> -
> -       if (WARN_ON(!PAGE_ALIGNED(shadow_start)))
> -               return -EINVAL;
> -
> -       ret =3D __vmalloc_node_range(shadow_size, 1, shadow_start,
> -                       shadow_start + shadow_size,
> -                       GFP_KERNEL,
> -                       PAGE_KERNEL, VM_NO_GUARD, NUMA_NO_NODE,
> -                       __builtin_return_address(0));
> -
> -       if (ret) {
> -               __memset(ret, KASAN_SHADOW_INIT, shadow_size);
> -               find_vm_area(addr)->flags |=3D VM_KASAN;
> -               kmemleak_ignore(ret);
> -               return 0;
> -       }
> -
> -       return -ENOMEM;
> -}
> -
> -void kasan_free_shadow(const struct vm_struct *vm)
> -{
> -       if (vm->flags & VM_KASAN)
> -               vfree(kasan_mem_to_shadow(vm->addr));
> -}
> -
> -#endif
> diff --git a/mm/kasan/shadow.c b/mm/kasan/shadow.c
> new file mode 100644
> index 000000000000..ca0cc4c31454
> --- /dev/null
> +++ b/mm/kasan/shadow.c
> @@ -0,0 +1,505 @@
> +// SPDX-License-Identifier: GPL-2.0
> +/*
> + * This file contains KASAN runtime code that manages shadow memory for
> + * generic and software tag-based KASAN modes.
> + *
> + * Copyright (c) 2014 Samsung Electronics Co., Ltd.
> + * Author: Andrey Ryabinin <ryabinin.a.a@gmail.com>
> + *
> + * Some code borrowed from https://github.com/xairy/kasan-prototype by
> + *        Andrey Konovalov <andreyknvl@gmail.com>
> + */
> +
> +#include <linux/init.h>
> +#include <linux/kasan.h>
> +#include <linux/kernel.h>
> +#include <linux/kmemleak.h>
> +#include <linux/memory.h>
> +#include <linux/mm.h>
> +#include <linux/string.h>
> +#include <linux/types.h>
> +#include <linux/vmalloc.h>
> +
> +#include <asm/cacheflush.h>
> +#include <asm/tlbflush.h>
> +
> +#include "kasan.h"
> +
> +bool __kasan_check_read(const volatile void *p, unsigned int size)
> +{
> +       return check_memory_region((unsigned long)p, size, false, _RET_IP=
_);
> +}
> +EXPORT_SYMBOL(__kasan_check_read);
> +
> +bool __kasan_check_write(const volatile void *p, unsigned int size)
> +{
> +       return check_memory_region((unsigned long)p, size, true, _RET_IP_=
);
> +}
> +EXPORT_SYMBOL(__kasan_check_write);
> +
> +#undef memset
> +void *memset(void *addr, int c, size_t len)
> +{
> +       if (!check_memory_region((unsigned long)addr, len, true, _RET_IP_=
))
> +               return NULL;
> +
> +       return __memset(addr, c, len);
> +}
> +
> +#ifdef __HAVE_ARCH_MEMMOVE
> +#undef memmove
> +void *memmove(void *dest, const void *src, size_t len)
> +{
> +       if (!check_memory_region((unsigned long)src, len, false, _RET_IP_=
) ||
> +           !check_memory_region((unsigned long)dest, len, true, _RET_IP_=
))
> +               return NULL;
> +
> +       return __memmove(dest, src, len);
> +}
> +#endif
> +
> +#undef memcpy
> +void *memcpy(void *dest, const void *src, size_t len)
> +{
> +       if (!check_memory_region((unsigned long)src, len, false, _RET_IP_=
) ||
> +           !check_memory_region((unsigned long)dest, len, true, _RET_IP_=
))
> +               return NULL;
> +
> +       return __memcpy(dest, src, len);
> +}
> +
> +/*
> + * Poisons the shadow memory for 'size' bytes starting from 'addr'.
> + * Memory addresses should be aligned to KASAN_GRANULE_SIZE.
> + */
> +void kasan_poison_memory(const void *address, size_t size, u8 value)
> +{
> +       void *shadow_start, *shadow_end;
> +
> +       /*
> +        * Perform shadow offset calculation based on untagged address, a=
s
> +        * some of the callers (e.g. kasan_poison_object_data) pass tagge=
d
> +        * addresses to this function.
> +        */
> +       address =3D reset_tag(address);
> +
> +       shadow_start =3D kasan_mem_to_shadow(address);
> +       shadow_end =3D kasan_mem_to_shadow(address + size);
> +
> +       __memset(shadow_start, value, shadow_end - shadow_start);
> +}
> +
> +void kasan_unpoison_memory(const void *address, size_t size)
> +{
> +       u8 tag =3D get_tag(address);
> +
> +       /*
> +        * Perform shadow offset calculation based on untagged address, a=
s
> +        * some of the callers (e.g. kasan_unpoison_object_data) pass tag=
ged
> +        * addresses to this function.
> +        */
> +       address =3D reset_tag(address);
> +
> +       kasan_poison_memory(address, size, tag);
> +
> +       if (size & KASAN_GRANULE_MASK) {
> +               u8 *shadow =3D (u8 *)kasan_mem_to_shadow(address + size);
> +
> +               if (IS_ENABLED(CONFIG_KASAN_SW_TAGS))
> +                       *shadow =3D tag;
> +               else
> +                       *shadow =3D size & KASAN_GRANULE_MASK;
> +       }
> +}
> +
> +#ifdef CONFIG_MEMORY_HOTPLUG
> +static bool shadow_mapped(unsigned long addr)
> +{
> +       pgd_t *pgd =3D pgd_offset_k(addr);
> +       p4d_t *p4d;
> +       pud_t *pud;
> +       pmd_t *pmd;
> +       pte_t *pte;
> +
> +       if (pgd_none(*pgd))
> +               return false;
> +       p4d =3D p4d_offset(pgd, addr);
> +       if (p4d_none(*p4d))
> +               return false;
> +       pud =3D pud_offset(p4d, addr);
> +       if (pud_none(*pud))
> +               return false;
> +
> +       /*
> +        * We can't use pud_large() or pud_huge(), the first one is
> +        * arch-specific, the last one depends on HUGETLB_PAGE.  So let's=
 abuse
> +        * pud_bad(), if pud is bad then it's bad because it's huge.
> +        */
> +       if (pud_bad(*pud))
> +               return true;
> +       pmd =3D pmd_offset(pud, addr);
> +       if (pmd_none(*pmd))
> +               return false;
> +
> +       if (pmd_bad(*pmd))
> +               return true;
> +       pte =3D pte_offset_kernel(pmd, addr);
> +       return !pte_none(*pte);
> +}
> +
> +static int __meminit kasan_mem_notifier(struct notifier_block *nb,
> +                       unsigned long action, void *data)
> +{
> +       struct memory_notify *mem_data =3D data;
> +       unsigned long nr_shadow_pages, start_kaddr, shadow_start;
> +       unsigned long shadow_end, shadow_size;
> +
> +       nr_shadow_pages =3D mem_data->nr_pages >> KASAN_SHADOW_SCALE_SHIF=
T;
> +       start_kaddr =3D (unsigned long)pfn_to_kaddr(mem_data->start_pfn);
> +       shadow_start =3D (unsigned long)kasan_mem_to_shadow((void *)start=
_kaddr);
> +       shadow_size =3D nr_shadow_pages << PAGE_SHIFT;
> +       shadow_end =3D shadow_start + shadow_size;
> +
> +       if (WARN_ON(mem_data->nr_pages % KASAN_GRANULE_SIZE) ||
> +               WARN_ON(start_kaddr % (KASAN_GRANULE_SIZE << PAGE_SHIFT))=
)
> +               return NOTIFY_BAD;
> +
> +       switch (action) {
> +       case MEM_GOING_ONLINE: {
> +               void *ret;
> +
> +               /*
> +                * If shadow is mapped already than it must have been map=
ped
> +                * during the boot. This could happen if we onlining prev=
iously
> +                * offlined memory.
> +                */
> +               if (shadow_mapped(shadow_start))
> +                       return NOTIFY_OK;
> +
> +               ret =3D __vmalloc_node_range(shadow_size, PAGE_SIZE, shad=
ow_start,
> +                                       shadow_end, GFP_KERNEL,
> +                                       PAGE_KERNEL, VM_NO_GUARD,
> +                                       pfn_to_nid(mem_data->start_pfn),
> +                                       __builtin_return_address(0));
> +               if (!ret)
> +                       return NOTIFY_BAD;
> +
> +               kmemleak_ignore(ret);
> +               return NOTIFY_OK;
> +       }
> +       case MEM_CANCEL_ONLINE:
> +       case MEM_OFFLINE: {
> +               struct vm_struct *vm;
> +
> +               /*
> +                * shadow_start was either mapped during boot by kasan_in=
it()
> +                * or during memory online by __vmalloc_node_range().
> +                * In the latter case we can use vfree() to free shadow.
> +                * Non-NULL result of the find_vm_area() will tell us if
> +                * that was the second case.
> +                *
> +                * Currently it's not possible to free shadow mapped
> +                * during boot by kasan_init(). It's because the code
> +                * to do that hasn't been written yet. So we'll just
> +                * leak the memory.
> +                */
> +               vm =3D find_vm_area((void *)shadow_start);
> +               if (vm)
> +                       vfree((void *)shadow_start);
> +       }
> +       }
> +
> +       return NOTIFY_OK;
> +}
> +
> +static int __init kasan_memhotplug_init(void)
> +{
> +       hotplug_memory_notifier(kasan_mem_notifier, 0);
> +
> +       return 0;
> +}
> +
> +core_initcall(kasan_memhotplug_init);
> +#endif
> +
> +#ifdef CONFIG_KASAN_VMALLOC
> +
> +static int kasan_populate_vmalloc_pte(pte_t *ptep, unsigned long addr,
> +                                     void *unused)
> +{
> +       unsigned long page;
> +       pte_t pte;
> +
> +       if (likely(!pte_none(*ptep)))
> +               return 0;
> +
> +       page =3D __get_free_page(GFP_KERNEL);
> +       if (!page)
> +               return -ENOMEM;
> +
> +       memset((void *)page, KASAN_VMALLOC_INVALID, PAGE_SIZE);
> +       pte =3D pfn_pte(PFN_DOWN(__pa(page)), PAGE_KERNEL);
> +
> +       spin_lock(&init_mm.page_table_lock);
> +       if (likely(pte_none(*ptep))) {
> +               set_pte_at(&init_mm, addr, ptep, pte);
> +               page =3D 0;
> +       }
> +       spin_unlock(&init_mm.page_table_lock);
> +       if (page)
> +               free_page(page);
> +       return 0;
> +}
> +
> +int kasan_populate_vmalloc(unsigned long addr, unsigned long size)
> +{
> +       unsigned long shadow_start, shadow_end;
> +       int ret;
> +
> +       if (!is_vmalloc_or_module_addr((void *)addr))
> +               return 0;
> +
> +       shadow_start =3D (unsigned long)kasan_mem_to_shadow((void *)addr)=
;
> +       shadow_start =3D ALIGN_DOWN(shadow_start, PAGE_SIZE);
> +       shadow_end =3D (unsigned long)kasan_mem_to_shadow((void *)addr + =
size);
> +       shadow_end =3D ALIGN(shadow_end, PAGE_SIZE);
> +
> +       ret =3D apply_to_page_range(&init_mm, shadow_start,
> +                                 shadow_end - shadow_start,
> +                                 kasan_populate_vmalloc_pte, NULL);
> +       if (ret)
> +               return ret;
> +
> +       flush_cache_vmap(shadow_start, shadow_end);
> +
> +       /*
> +        * We need to be careful about inter-cpu effects here. Consider:
> +        *
> +        *   CPU#0                                CPU#1
> +        * WRITE_ONCE(p, vmalloc(100));         while (x =3D READ_ONCE(p)=
) ;
> +        *                                      p[99] =3D 1;
> +        *
> +        * With compiler instrumentation, that ends up looking like this:
> +        *
> +        *   CPU#0                                CPU#1
> +        * // vmalloc() allocates memory
> +        * // let a =3D area->addr
> +        * // we reach kasan_populate_vmalloc
> +        * // and call kasan_unpoison_memory:
> +        * STORE shadow(a), unpoison_val
> +        * ...
> +        * STORE shadow(a+99), unpoison_val     x =3D LOAD p
> +        * // rest of vmalloc process           <data dependency>
> +        * STORE p, a                           LOAD shadow(x+99)
> +        *
> +        * If there is no barrier between the end of unpoisioning the sha=
dow
> +        * and the store of the result to p, the stores could be committe=
d
> +        * in a different order by CPU#0, and CPU#1 could erroneously obs=
erve
> +        * poison in the shadow.
> +        *
> +        * We need some sort of barrier between the stores.
> +        *
> +        * In the vmalloc() case, this is provided by a smp_wmb() in
> +        * clear_vm_uninitialized_flag(). In the per-cpu allocator and in
> +        * get_vm_area() and friends, the caller gets shadow allocated bu=
t
> +        * doesn't have any pages mapped into the virtual address space t=
hat
> +        * has been reserved. Mapping those pages in will involve taking =
and
> +        * releasing a page-table lock, which will provide the barrier.
> +        */
> +
> +       return 0;
> +}
> +
> +/*
> + * Poison the shadow for a vmalloc region. Called as part of the
> + * freeing process at the time the region is freed.
> + */
> +void kasan_poison_vmalloc(const void *start, unsigned long size)
> +{
> +       if (!is_vmalloc_or_module_addr(start))
> +               return;
> +
> +       size =3D round_up(size, KASAN_GRANULE_SIZE);
> +       kasan_poison_memory(start, size, KASAN_VMALLOC_INVALID);
> +}
> +
> +void kasan_unpoison_vmalloc(const void *start, unsigned long size)
> +{
> +       if (!is_vmalloc_or_module_addr(start))
> +               return;
> +
> +       kasan_unpoison_memory(start, size);
> +}
> +
> +static int kasan_depopulate_vmalloc_pte(pte_t *ptep, unsigned long addr,
> +                                       void *unused)
> +{
> +       unsigned long page;
> +
> +       page =3D (unsigned long)__va(pte_pfn(*ptep) << PAGE_SHIFT);
> +
> +       spin_lock(&init_mm.page_table_lock);
> +
> +       if (likely(!pte_none(*ptep))) {
> +               pte_clear(&init_mm, addr, ptep);
> +               free_page(page);
> +       }
> +       spin_unlock(&init_mm.page_table_lock);
> +
> +       return 0;
> +}
> +
> +/*
> + * Release the backing for the vmalloc region [start, end), which
> + * lies within the free region [free_region_start, free_region_end).
> + *
> + * This can be run lazily, long after the region was freed. It runs
> + * under vmap_area_lock, so it's not safe to interact with the vmalloc/v=
map
> + * infrastructure.
> + *
> + * How does this work?
> + * -------------------
> + *
> + * We have a region that is page aligned, labelled as A.
> + * That might not map onto the shadow in a way that is page-aligned:
> + *
> + *                    start                     end
> + *                    v                         v
> + * |????????|????????|AAAAAAAA|AA....AA|AAAAAAAA|????????| < vmalloc
> + *  -------- -------- --------          -------- --------
> + *      |        |       |                 |        |
> + *      |        |       |         /-------/        |
> + *      \-------\|/------/         |/---------------/
> + *              |||                ||
> + *             |??AAAAAA|AAAAAAAA|AA??????|                < shadow
> + *                 (1)      (2)      (3)
> + *
> + * First we align the start upwards and the end downwards, so that the
> + * shadow of the region aligns with shadow page boundaries. In the
> + * example, this gives us the shadow page (2). This is the shadow entire=
ly
> + * covered by this allocation.
> + *
> + * Then we have the tricky bits. We want to know if we can free the
> + * partially covered shadow pages - (1) and (3) in the example. For this=
,
> + * we are given the start and end of the free region that contains this
> + * allocation. Extending our previous example, we could have:
> + *
> + *  free_region_start                                    free_region_end
> + *  |                 start                     end      |
> + *  v                 v                         v        v
> + * |FFFFFFFF|FFFFFFFF|AAAAAAAA|AA....AA|AAAAAAAA|FFFFFFFF| < vmalloc
> + *  -------- -------- --------          -------- --------
> + *      |        |       |                 |        |
> + *      |        |       |         /-------/        |
> + *      \-------\|/------/         |/---------------/
> + *              |||                ||
> + *             |FFAAAAAA|AAAAAAAA|AAF?????|                < shadow
> + *                 (1)      (2)      (3)
> + *
> + * Once again, we align the start of the free region up, and the end of
> + * the free region down so that the shadow is page aligned. So we can fr=
ee
> + * page (1) - we know no allocation currently uses anything in that page=
,
> + * because all of it is in the vmalloc free region. But we cannot free
> + * page (3), because we can't be sure that the rest of it is unused.
> + *
> + * We only consider pages that contain part of the original region for
> + * freeing: we don't try to free other pages from the free region or we'=
d
> + * end up trying to free huge chunks of virtual address space.
> + *
> + * Concurrency
> + * -----------
> + *
> + * How do we know that we're not freeing a page that is simultaneously
> + * being used for a fresh allocation in kasan_populate_vmalloc(_pte)?
> + *
> + * We _can_ have kasan_release_vmalloc and kasan_populate_vmalloc runnin=
g
> + * at the same time. While we run under free_vmap_area_lock, the populat=
ion
> + * code does not.
> + *
> + * free_vmap_area_lock instead operates to ensure that the larger range
> + * [free_region_start, free_region_end) is safe: because __alloc_vmap_ar=
ea and
> + * the per-cpu region-finding algorithm both run under free_vmap_area_lo=
ck,
> + * no space identified as free will become used while we are running. Th=
is
> + * means that so long as we are careful with alignment and only free sha=
dow
> + * pages entirely covered by the free region, we will not run in to any
> + * trouble - any simultaneous allocations will be for disjoint regions.
> + */
> +void kasan_release_vmalloc(unsigned long start, unsigned long end,
> +                          unsigned long free_region_start,
> +                          unsigned long free_region_end)
> +{
> +       void *shadow_start, *shadow_end;
> +       unsigned long region_start, region_end;
> +       unsigned long size;
> +
> +       region_start =3D ALIGN(start, PAGE_SIZE * KASAN_GRANULE_SIZE);
> +       region_end =3D ALIGN_DOWN(end, PAGE_SIZE * KASAN_GRANULE_SIZE);
> +
> +       free_region_start =3D ALIGN(free_region_start,
> +                                 PAGE_SIZE * KASAN_GRANULE_SIZE);
> +
> +       if (start !=3D region_start &&
> +           free_region_start < region_start)
> +               region_start -=3D PAGE_SIZE * KASAN_GRANULE_SIZE;
> +
> +       free_region_end =3D ALIGN_DOWN(free_region_end,
> +                                    PAGE_SIZE * KASAN_GRANULE_SIZE);
> +
> +       if (end !=3D region_end &&
> +           free_region_end > region_end)
> +               region_end +=3D PAGE_SIZE * KASAN_GRANULE_SIZE;
> +
> +       shadow_start =3D kasan_mem_to_shadow((void *)region_start);
> +       shadow_end =3D kasan_mem_to_shadow((void *)region_end);
> +
> +       if (shadow_end > shadow_start) {
> +               size =3D shadow_end - shadow_start;
> +               apply_to_existing_page_range(&init_mm,
> +                                            (unsigned long)shadow_start,
> +                                            size, kasan_depopulate_vmall=
oc_pte,
> +                                            NULL);
> +               flush_tlb_kernel_range((unsigned long)shadow_start,
> +                                      (unsigned long)shadow_end);
> +       }
> +}
> +
> +#else /* CONFIG_KASAN_VMALLOC */
> +
> +int kasan_module_alloc(void *addr, size_t size)
> +{
> +       void *ret;
> +       size_t scaled_size;
> +       size_t shadow_size;
> +       unsigned long shadow_start;
> +
> +       shadow_start =3D (unsigned long)kasan_mem_to_shadow(addr);
> +       scaled_size =3D (size + KASAN_GRANULE_SIZE - 1) >>
> +                               KASAN_SHADOW_SCALE_SHIFT;
> +       shadow_size =3D round_up(scaled_size, PAGE_SIZE);
> +
> +       if (WARN_ON(!PAGE_ALIGNED(shadow_start)))
> +               return -EINVAL;
> +
> +       ret =3D __vmalloc_node_range(shadow_size, 1, shadow_start,
> +                       shadow_start + shadow_size,
> +                       GFP_KERNEL,
> +                       PAGE_KERNEL, VM_NO_GUARD, NUMA_NO_NODE,
> +                       __builtin_return_address(0));
> +
> +       if (ret) {
> +               __memset(ret, KASAN_SHADOW_INIT, shadow_size);
> +               find_vm_area(addr)->flags |=3D VM_KASAN;
> +               kmemleak_ignore(ret);
> +               return 0;
> +       }
> +
> +       return -ENOMEM;
> +}
> +
> +void kasan_free_shadow(const struct vm_struct *vm)
> +{
> +       if (vm->flags & VM_KASAN)
> +               vfree(kasan_mem_to_shadow(vm->addr));
> +}
> +
> +#endif
> --
> 2.29.2.222.g5d2a92d10f8-goog
>


--=20
Alexander Potapenko
Software Engineer

Google Germany GmbH
Erika-Mann-Stra=C3=9Fe, 33
80636 M=C3=BCnchen

Gesch=C3=A4ftsf=C3=BChrer: Paul Manicle, Halimah DeLaine Prado
Registergericht und -nummer: Hamburg, HRB 86891
Sitz der Gesellschaft: Hamburg

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG_fn%3DV%2BHeWXU2zLf43P1e854JpZw5h%2BfAuLL161iHt2Mia9Zg%40mail.=
gmail.com.
