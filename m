Return-Path: <kasan-dev+bncBDW2JDUY5AORBD4O2SKAMGQEDRUNLRY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103b.google.com (mail-pj1-x103b.google.com [IPv6:2607:f8b0:4864:20::103b])
	by mail.lfdr.de (Postfix) with ESMTPS id 206265386FA
	for <lists+kasan-dev@lfdr.de>; Mon, 30 May 2022 20:04:01 +0200 (CEST)
Received: by mail-pj1-x103b.google.com with SMTP id o8-20020a17090a9f8800b001dc9f554c7fsf6623825pjp.4
        for <lists+kasan-dev@lfdr.de>; Mon, 30 May 2022 11:04:01 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1653933839; cv=pass;
        d=google.com; s=arc-20160816;
        b=FXFw5g/xolo+ekGWzg8i7mDD/NdFeRCQIMDGuXlbIqU1q0o2RZWqMqUEEyBm8Bctez
         mMOg2ztlN9MkOrqTuKo2tqcqKBulVN5DTz92t33i1ewuegIpfES9GMRG85mDFkFVO2S8
         IS8BZyJ544ak6/3n6bhCeSL1BZnANVd6MY++ptRE6C+WM0tu74DPSztU96zK5D03jdeh
         pRQoj2glEkg2d/1zioL638qt/NJHCxb3CzqWfYayQx38dKIuG8YYj+THn8m9ay004SCC
         PCfWOxE/mLRPYA05pmTGMT1VGqZJwSqc7ClaZmswK4r3I6i3Be+dFEdb12F97+UDgvwq
         tZ0w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=5yyLXwmThBqfJejsOslKdTke3L2cidzn/L6MUtXnQH8=;
        b=NOGxyLl/IaUmUOmQjZVk+WQn9auTdJV3h4GTDioN9ZpWhus/aRONT8zubD8lDuW0f1
         kfzT2XBMsl8PqMToTXGeYx5hv64aB7hADpew97oxHJAWmr/M2HHrDlib0OkSyMraU7cJ
         eIB3xk5WM55/vL4O3b7YGYqd3cW1Uo4A7VscfE2Cm7aBg1uNyuIRQuP9hqhEK4hbqqhb
         yijrfGmfFsyGebpClkvo/lchAXaH0sVMu1MlyJSYu8J8JCq7WTR+ScuMuX9Y7EL84dAl
         0JsBiTvbl0PTO265H27sVE7chxzgNF6Y34aOsEuBfugfqrLUwl0QgnskcyE1r0A7owwb
         irAw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=GTWyyPNR;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::12c as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=5yyLXwmThBqfJejsOslKdTke3L2cidzn/L6MUtXnQH8=;
        b=R/A2O498JvBS+ZqJrBoCYZHZdNIzis8FZ0m/q527TpSZRtE4wB9fx/cV4wTgFipHPL
         uSHP19kgOvMXWcp5hsB8F+8zjDIAZZ4D6okHxs8hi/Lc0sokWowH4UT3o6mLC1v7r9g8
         4EB5LUwB7CgTrr78Fm4eFZ4iHceHMfqwQGq1YNsvbIvP32AsroILCY8a2V78HJHDvNXd
         WCjxwmfBovQ6QrvxkrERl3nZDIoLSoh/XzN6P5gApOdEXxS6cqTEaLr6b5dwynBA3w5m
         IkhCTDptYvZ03leX3OD50K5A/adf1cTsjZgd2T5FOxjRD4XOroaOtNKc95nPOLLvTV8O
         up/A==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=5yyLXwmThBqfJejsOslKdTke3L2cidzn/L6MUtXnQH8=;
        b=Y62/SERtkhNeV5pCbJa/QhU3bJ5yP4fIYcOhpOxqd+hxuvuNy7lHfqYCBSiFBf/+pa
         QElWHnnvLtZIalfFVM+nHFiH1ReRD7FXue7QsGs9bpTH51JRnTdjPAhGiK6ypV7h3m2T
         aLkn7eEObcqtuWl80xxFleBBFnGka+PuKtltBk9JQ36OUvFgGmSspk3O2VaTt79wUSnX
         05z3C9bqsxu4yE1VoBxm6HmvDvWx08mVXXwVo9o27i8TsDEkfyQFrtziZgIs0sb8tos0
         +i3r4B6PG1V9+zD8yspoMbVaZIVQHhBOnTc10zKPfpdO522vGcr2jG2RA3BngOew+i7y
         4Mwg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=5yyLXwmThBqfJejsOslKdTke3L2cidzn/L6MUtXnQH8=;
        b=rus+Wdp0F56L/dJJryQ7nWmvjAfxkZF6lfYKUr6HydsyJ9L2AxBV99XfaNbRl3yTEk
         n5zSNmSQjRaWd6yZzzLBIAgUzdpIAboAbKJ4+U5ls9azY8VgJbMC/cyhNHTtIEulG6pF
         LFL1RFqNfaEm+mYzKf9tvrTVDs0uuiGtbgLbD3mn61lWfg293aLlipzv2GyShUDrEo77
         bmP9m1HvYlGMjqWefYXj9hTWC0I2Ks7VFTyO4Yq1pGxFDPhHdjC5Zw8dKi4UK7n43xRj
         oxQ9s7GtgfJAFMBdvVfwXw1Ymgy4L2Y8tYWTgaquiWIlrNPftDBEdCWmv6oNs4LLocnf
         FRXg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532jYDo6VWavebdiWVHKjzVODDFa1/9EXi8VMC4lQ2QmPSJemsMM
	B+u2EuaWG1+ZSH8JfolX23Q=
X-Google-Smtp-Source: ABdhPJwIP43m0iliztoaKoSVP1T07oMzSbevfEZ/n4YOEIl8+3f2M07RoC0/HdAKPeH8M5zYgAOuYQ==
X-Received: by 2002:a17:902:db07:b0:163:5374:6732 with SMTP id m7-20020a170902db0700b0016353746732mr20539715plx.15.1653933839302;
        Mon, 30 May 2022 11:03:59 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:544e:0:b0:3fb:cd6e:c7b2 with SMTP id e14-20020a63544e000000b003fbcd6ec7b2ls2557429pgm.5.gmail;
 Mon, 30 May 2022 11:03:58 -0700 (PDT)
X-Received: by 2002:a63:f158:0:b0:3db:8563:e8f5 with SMTP id o24-20020a63f158000000b003db8563e8f5mr50275842pgk.191.1653933838641;
        Mon, 30 May 2022 11:03:58 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1653933838; cv=none;
        d=google.com; s=arc-20160816;
        b=hsrG1xvziXDbjAXe8UwKA1NxAvg0lZqvtU++L8Kw6G/50Y8OnCMX0r5fOp3pG0NZUV
         BIhhMtVqwYKe1tKRFKuMdwKZbuh4OYxcB3pBEkk2eHh8qbe3SpFoDeX7gq0cRPZDWr0d
         HQhHb7jtUR16mK5qxL7YfJ8t00NVab4k6O/HOBNBFzB/tPuuibByk9BBSWwT/GjbfWQc
         X0fAmNEdPS0ta17S5sjeCPsHyYXTnI6WVYjaZf8Q9c53WqmrFJJRKpzf3IQ+caw9NKJE
         V3D2Pt9kIrAkVFtUc6Z3n4ypAnK/uzQNmY+jOeVfL+D02woe0Nx4d+qLHTbHefVIeL8X
         v7NA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=1ZeR0nN/1eFyuWwXvp0L7EiUsdKyoUpqzB7kyH/D/WM=;
        b=Z1Z8rhUGbKOFsXXX3m1RsqfaX52Kkl1E7IRgUg5tfoQscjHTRgGdFL2crBV84KSQd7
         dWVMAf9/PXE2BVYlM76N6ImXBaK17Z54izVnAeyO6l790kzS9VK8kf3aWtoRx73O3mVV
         IZSgbl9v0WMUA3xc9w19cOAAltIx0AbKH2Rd8nXGIy7s2fPVvrWM51p43yqa7tIL5PY1
         qg9ke8Li+vbz1CbZFzn+eKD7YqhnDgc4GbwVszrqg6VW3ZmIF57niTMKHBAdSR87iUJo
         AwlOpRCcO3tuDdmzdNNEUW6cetSGlfbTfFm9TXU/qqCtcNBarf3A/p//XWQqZGSazXaK
         y4Hw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=GTWyyPNR;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::12c as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-il1-x12c.google.com (mail-il1-x12c.google.com. [2607:f8b0:4864:20::12c])
        by gmr-mx.google.com with ESMTPS id h17-20020a17090aea9100b001e08670c3d9si2368pjz.0.2022.05.30.11.03.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 30 May 2022 11:03:58 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::12c as permitted sender) client-ip=2607:f8b0:4864:20::12c;
Received: by mail-il1-x12c.google.com with SMTP id y17so2871952ilj.11
        for <kasan-dev@googlegroups.com>; Mon, 30 May 2022 11:03:58 -0700 (PDT)
X-Received: by 2002:a92:3609:0:b0:2c6:3595:2a25 with SMTP id
 d9-20020a923609000000b002c635952a25mr29189046ila.233.1653933838071; Mon, 30
 May 2022 11:03:58 -0700 (PDT)
MIME-Version: 1.0
References: <20220527185600.1236769-1-davidgow@google.com> <20220527185600.1236769-2-davidgow@google.com>
In-Reply-To: <20220527185600.1236769-2-davidgow@google.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Mon, 30 May 2022 20:03:47 +0200
Message-ID: <CA+fCnZe63vugPRbD3fVNGnTWbSvjd08g8coG3D71-=NtqpjOvQ@mail.gmail.com>
Subject: Re: [PATCH v2 2/2] UML: add support for KASAN under x86_64
To: David Gow <davidgow@google.com>
Cc: Vincent Whitchurch <vincent.whitchurch@axis.com>, Johannes Berg <johannes@sipsolutions.net>, 
	Patricia Alfonso <trishalfonso@google.com>, Jeff Dike <jdike@addtoit.com>, 
	Richard Weinberger <richard@nod.at>, anton.ivanov@cambridgegreys.com, 
	Dmitry Vyukov <dvyukov@google.com>, Brendan Higgins <brendanhiggins@google.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, linux-um@lists.infradead.org, 
	LKML <linux-kernel@vger.kernel.org>, Daniel Latypov <dlatypov@google.com>, 
	Linux Memory Management List <linux-mm@kvack.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=GTWyyPNR;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::12c
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Fri, May 27, 2022 at 8:56 PM David Gow <davidgow@google.com> wrote:
>
> From: Patricia Alfonso <trishalfonso@google.com>
>
> Make KASAN run on User Mode Linux on x86_64.
>
> The UML-specific KASAN initializer uses mmap to map the roughly 2.25TB
> of shadow memory to the location defined by KASAN_SHADOW_OFFSET.
> kasan_init() utilizes constructors to initialize KASAN before main().
>
> The location of the KASAN shadow memory, starting at
> KASAN_SHADOW_OFFSET, can be configured using the KASAN_SHADOW_OFFSET
> option. UML uses roughly 18TB of address space, and KASAN requires 1/8th
> of this. The default location of this offset is 0x100000000000, which
> keeps it out-of-the-way even on UML setups with more "physical" memory.
>
> For low-memory setups, 0x7fff8000 can be used instead, which fits in an
> immediate and is therefore faster, as suggested by Dmitry Vyukov. There
> is usually enough free space at this location; however, it is a config
> option so that it can be easily changed if needed.
>
> Note that, unlike KASAN on other architectures, vmalloc allocations
> still use the shadow memory allocated upfront, rather than allocating
> and free-ing it per-vmalloc allocation.
>
> Also note that, while UML supports both KASAN in inline mode
> (CONFIG_KASAN_INLINE) and static linking (CONFIG_STATIC_LINK), it does
> not support both at the same time.
>
> Signed-off-by: Patricia Alfonso <trishalfonso@google.com>
> Co-developed-by: Vincent Whitchurch <vincent.whitchurch@axis.com>
> Signed-off-by: Vincent Whitchurch <vincent.whitchurch@axis.com>
> Signed-off-by: David Gow <davidgow@google.com>

Hi David,

Thanks for working on this!

> diff --git a/mm/kasan/shadow.c b/mm/kasan/shadow.c
> index a4f07de21771..c993d99116f2 100644
> --- a/mm/kasan/shadow.c
> +++ b/mm/kasan/shadow.c
> @@ -295,9 +295,29 @@ int kasan_populate_vmalloc(unsigned long addr, unsigned long size)
>                 return 0;
>
>         shadow_start = (unsigned long)kasan_mem_to_shadow((void *)addr);
> -       shadow_start = ALIGN_DOWN(shadow_start, PAGE_SIZE);
>         shadow_end = (unsigned long)kasan_mem_to_shadow((void *)addr + size);
> -       shadow_end = ALIGN(shadow_end, PAGE_SIZE);
> +
> +       /*
> +        * User Mode Linux maps enough shadow memory for all of physical memory
> +        * at boot, so doesn't need to allocate more on vmalloc, just clear it.

Should this say "for all of _virtual_ memory"?

Otherwise, this is confusing. All KASAN-enabled architectures map
shadow for physical memory. And they still need map shadow for
vmalloc() separately. This is what kasan_populate_vmalloc() is for.

> +        *
> +        * If another architecture chooses to go down the same path, we should
> +        * replace this check for CONFIG_UML with something more generic, such
> +        * as:
> +        * - A CONFIG_KASAN_NO_SHADOW_ALLOC option, which architectures could set
> +        * - or, a way of having architecture-specific versions of these vmalloc
> +        *   and module shadow memory allocation options.

I think this part above and the first sentence below belong to the
commit changelog, not to a comment.

> +        *
> +        * For the time being, though, this check works. The remaining CONFIG_UML
> +        * checks in this file exist for the same reason.
> +        */
> +       if (IS_ENABLED(CONFIG_UML)) {
> +               __memset((void *)shadow_start, KASAN_VMALLOC_INVALID, shadow_end - shadow_start);
> +               return 0;
> +       }
> +
> +       shadow_start = PAGE_ALIGN_DOWN(shadow_start);
> +       shadow_end = PAGE_ALIGN(shadow_end);
>
>         ret = apply_to_page_range(&init_mm, shadow_start,
>                                   shadow_end - shadow_start,
> @@ -466,6 +486,10 @@ void kasan_release_vmalloc(unsigned long start, unsigned long end,
>
>         if (shadow_end > shadow_start) {
>                 size = shadow_end - shadow_start;
> +               if (IS_ENABLED(CONFIG_UML)) {
> +                       __memset(shadow_start, KASAN_SHADOW_INIT, shadow_end - shadow_start);
> +                       return;
> +               }
>                 apply_to_existing_page_range(&init_mm,
>                                              (unsigned long)shadow_start,
>                                              size, kasan_depopulate_vmalloc_pte,
> @@ -531,6 +555,11 @@ int kasan_alloc_module_shadow(void *addr, size_t size, gfp_t gfp_mask)
>         if (WARN_ON(!PAGE_ALIGNED(shadow_start)))
>                 return -EINVAL;
>
> +       if (IS_ENABLED(CONFIG_UML)) {
> +               __memset((void *)shadow_start, KASAN_SHADOW_INIT, shadow_size);
> +               return 0;
> +       }
> +
>         ret = __vmalloc_node_range(shadow_size, 1, shadow_start,
>                         shadow_start + shadow_size,
>                         GFP_KERNEL,
> @@ -554,6 +583,9 @@ int kasan_alloc_module_shadow(void *addr, size_t size, gfp_t gfp_mask)
>
>  void kasan_free_module_shadow(const struct vm_struct *vm)
>  {
> +       if (IS_ENABLED(CONFIG_UML))
> +               return;
> +
>         if (vm->flags & VM_KASAN)
>                 vfree(kasan_mem_to_shadow(vm->addr));
>  }
> --
> 2.36.1.124.g0e6072fb45-goog
>

Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZe63vugPRbD3fVNGnTWbSvjd08g8coG3D71-%3DNtqpjOvQ%40mail.gmail.com.
