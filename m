Return-Path: <kasan-dev+bncBC6OLHHDVUOBBT5V6WKQMGQER2BM7KQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x238.google.com (mail-lj1-x238.google.com [IPv6:2a00:1450:4864:20::238])
	by mail.lfdr.de (Postfix) with ESMTPS id 81EC0561460
	for <lists+kasan-dev@lfdr.de>; Thu, 30 Jun 2022 10:12:00 +0200 (CEST)
Received: by mail-lj1-x238.google.com with SMTP id k6-20020a2e9206000000b0025a8ce1a22esf2893756ljg.9
        for <lists+kasan-dev@lfdr.de>; Thu, 30 Jun 2022 01:12:00 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1656576720; cv=pass;
        d=google.com; s=arc-20160816;
        b=lxmRJJ/DkxF4F39FUf6GkoQd86v14lJ8XW/hkm2vYXcmtW1zz4nLA3NH3tRAPDxEm0
         YgnRF6N/GwepFQgCi+7j/gtv/pM6/yaeYB2ztN30v3s5PnrCyayK45WyJQMAi+xCLebG
         dKFFC/3cvGOrdx20iPu2WT14U98qJJ0oZRgP6bJu8Ng2YXgIq+gVPbuNv/6ZMeo7Nv0Y
         kdR+vVxEY5eflTyVapqrHrP1OspUMxpbvkJXdiQx2/XckT0LAzV5V3WPXaRaP8rAY8B7
         AuD45p6xAslcSR/3uJGR1MaLk20s+OyHGIrIRw4p9++trwOrulatmnDrSgL5RKDPQVId
         77AQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=kyVLw2984zqSINHnMSNJLJjOkxfDFxGFW2+D5FYsroM=;
        b=lo4KKZaz9HGeiVvnWz5t9TL4LhxXxy5nPcr2GpHaBtxcD0Z2glmQSbrUnB8LDSuWQj
         e82QZuJ69H7Z0mv6ZPbS4LeFHJNUU4giZK2F+rcNFogEHOl6KAdqn81WDt+pUMH4vAh7
         1kgv0Cua6kEl54LTj3x8HLYbNNcrHW6s2yePkHdmjseU40oXgEzTzCZhVRjn2y4VExuY
         FArqQqqV6tAjiIMCsYJOiEon0lrNHzbF5pYBihIlT0P4kK9j6XnLz2tJtt5ODgQ1nNSz
         ubkiAQ0N1vnz3R0wUSWKZnza6aSdFSGTWEZCEtXe4wG5nbsuYVtUcVEDHkYSeA6swYTF
         Wp+A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="C/t7WScd";
       spf=pass (google.com: domain of davidgow@google.com designates 2a00:1450:4864:20::432 as permitted sender) smtp.mailfrom=davidgow@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=kyVLw2984zqSINHnMSNJLJjOkxfDFxGFW2+D5FYsroM=;
        b=UG710ZgJ2BpMYh6qXIw3NITQJzQiche3aQbfV3t4WSDNPczk92R7+QLi1m4IK8+abN
         NWZAwcGUh/VZFnNBfOTtJdlH4mbQZGrDRsP2VvNrvn5Ek23RmglOAlCSP1y9U3WOUbwS
         zg9GIfkHUUF0MYFpKmtxk0/v78ACculZ3cdCDOqT+9hyPZeqUZf5GyZ8d9TWikYxIqKX
         v+AuiN0i0bBKzlTqR2o+MgRfReSV1IQMboUaBK5k8wH/RWfcTN5D4jAz91EA47ubDfZ4
         vN4u9wThAYc5pLHv2dtHwApJxbpowZV7/yF4x66zV6YAqlXlPm+2kPvOqKelNDwlqQJL
         1HqA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=kyVLw2984zqSINHnMSNJLJjOkxfDFxGFW2+D5FYsroM=;
        b=LQ5Q27bjcHFxWDUuR+6P5zDsc9AnkjKpveAWYhzCDa61JoPWc6PympUMpJqwWODfqV
         W/0iZ9k15DwPtopIsY/IGI3Ggi8XUiZOITXk2e8qWAM1l6lNUkyB+E9VwhpopBPuoe1L
         A9ArG4YVes7ANMgcPRH2A5DDYHFuW/eV/PwToDwkHbvUYgCrMO6ancpkueF4113I7buR
         Rn4liRfzgrAS7xThzu8Et+DN65R7Q2D4sYJgZbcuWrjLX+K9NN4whp9Y4rIFnim7fMlk
         lLQLe84EJHAKb9qkeXQ+elHzzuduWAURC9RTu1OOoKopSqi5j2fe1N567vUpeMqEtEGH
         TP5Q==
X-Gm-Message-State: AJIora8xybWmUiWmjgzmDLUjqKn3I5Z5sQrQhGgN7gfFGF8n+CPemN5y
	j5YWdT8k8bjC3PCv9U47QWM=
X-Google-Smtp-Source: AGRyM1thW2S77HgwzJSSsVwpuR2zg6R7GEUSZ/AT8+rIs45/C2pqh5izOuJx0Ts+zcYdNYHm+BXkjA==
X-Received: by 2002:a05:6512:3583:b0:47f:b381:337b with SMTP id m3-20020a056512358300b0047fb381337bmr4652102lfr.17.1656576719924;
        Thu, 30 Jun 2022 01:11:59 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3b0c:b0:47f:9907:2b50 with SMTP id
 f12-20020a0565123b0c00b0047f99072b50ls171616lfv.3.gmail; Thu, 30 Jun 2022
 01:11:58 -0700 (PDT)
X-Received: by 2002:a05:6512:2a91:b0:47f:6e1d:d22c with SMTP id dt17-20020a0565122a9100b0047f6e1dd22cmr5028455lfb.550.1656576718538;
        Thu, 30 Jun 2022 01:11:58 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1656576718; cv=none;
        d=google.com; s=arc-20160816;
        b=w5H19fQZZFCEp1Szc68exZGoTN1LY4yftjq2tds5tzNq0jZS+4nVlNtDGs92E6fI++
         i0QmlLJlFHWhxWcQLwnhbG4ahGoRlPdXuhJWzYveYm/TScPwgPE7mXsVp1NxVpzQiNYA
         EuNXyVREXW9O2goS/h/K1TZjQptg1yKn0vNRUaZF2Gdql/auN2GZeSIV27FH5akzvAmw
         AOy7FHyweGYGtURr+/yun9RGBKB+8n9MGrWaX4QKL6HVr2mqFp1H/DljPZvylJTbEGfg
         fAX4j2ocPCpcgV2AAEiwU9o/8B5Sm6CNnxI5qi2eR55jzh4i1zK929MLZr/HIaVBYR0p
         /IiA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=OOTtRji8xWxni9yaz7W2gJeXuoycpc5ucnabq09T1bI=;
        b=LBMgNb042fAEpawxEbdBKuBSLxP3oKsAHKSoFZ1HH0i9NYHkP3UrtiytJlK/OM+9eQ
         5/NdRdOxh9YP5jV33YCvhflzk/07Xarh1jg85unDf3N/5k/qMRSF0VjcX+p40/XfTHZX
         gIhixULm1dQy0ZrfvUEngOL4RvR9JAyBxEgBojHhAL18UEc2MKUOGiEG4/UWcctnoYog
         JiKnmDIOfnNrG+AfgIHwu/A98IS0lmGRMpm659RTnpzeNE+N8SJ/NQ9bPjFiPmqNdyXr
         m+D0xVk/l8ZFL52faKDefmNMomE39I64pMMTs/mayxfo9t0S3Dtv7t903EKYbCPvXWo3
         eQqA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="C/t7WScd";
       spf=pass (google.com: domain of davidgow@google.com designates 2a00:1450:4864:20::432 as permitted sender) smtp.mailfrom=davidgow@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x432.google.com (mail-wr1-x432.google.com. [2a00:1450:4864:20::432])
        by gmr-mx.google.com with ESMTPS id k16-20020a0565123d9000b0047c62295117si820139lfv.8.2022.06.30.01.11.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 30 Jun 2022 01:11:58 -0700 (PDT)
Received-SPF: pass (google.com: domain of davidgow@google.com designates 2a00:1450:4864:20::432 as permitted sender) client-ip=2a00:1450:4864:20::432;
Received: by mail-wr1-x432.google.com with SMTP id k7so1562967wrc.12
        for <kasan-dev@googlegroups.com>; Thu, 30 Jun 2022 01:11:58 -0700 (PDT)
X-Received: by 2002:a05:6000:1542:b0:21d:28c0:eb43 with SMTP id
 2-20020a056000154200b0021d28c0eb43mr7083362wry.622.1656576718103; Thu, 30 Jun
 2022 01:11:58 -0700 (PDT)
MIME-Version: 1.0
References: <20220630074757.2739000-1-davidgow@google.com> <20220630074757.2739000-2-davidgow@google.com>
In-Reply-To: <20220630074757.2739000-2-davidgow@google.com>
From: "'David Gow' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 30 Jun 2022 16:11:46 +0800
Message-ID: <CABVgOS=0PmF5k8RcP2Q3JNkMXK4Pd6ZLVGgCT9Ff+t9Dt_wA=w@mail.gmail.com>
Subject: Re: [PATCH v3 2/2] UML: add support for KASAN under x86_64
To: Vincent Whitchurch <vincent.whitchurch@axis.com>, Johannes Berg <johannes@sipsolutions.net>, 
	Patricia Alfonso <trishalfonso@google.com>, Jeff Dike <jdike@addtoit.com>, 
	Richard Weinberger <richard@nod.at>, Anton Ivanov <anton.ivanov@cambridgegreys.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Brendan Higgins <brendanhiggins@google.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>
Cc: kasan-dev <kasan-dev@googlegroups.com>, linux-um <linux-um@lists.infradead.org>, 
	LKML <linux-kernel@vger.kernel.org>, Daniel Latypov <dlatypov@google.com>, 
	Linux Memory Management List <linux-mm@kvack.org>, KUnit Development <kunit-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: davidgow@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b="C/t7WScd";       spf=pass
 (google.com: domain of davidgow@google.com designates 2a00:1450:4864:20::432
 as permitted sender) smtp.mailfrom=davidgow@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: David Gow <davidgow@google.com>
Reply-To: David Gow <davidgow@google.com>
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

On Thu, Jun 30, 2022 at 3:48 PM David Gow <davidgow@google.com> wrote:
>
> From: Patricia Alfonso <trishalfonso@google.com>
>
> Make KASAN run on User Mode Linux on x86_64.
>
> The UML-specific KASAN initializer uses mmap to map the ~16TB of shadow
> memory to the location defined by KASAN_SHADOW_OFFSET.  kasan_init()
> utilizes constructors to initialize KASAN before main().
>
> The location of the KASAN shadow memory, starting at
> KASAN_SHADOW_OFFSET, can be configured using the KASAN_SHADOW_OFFSET
> option. The default location of this offset is 0x100000000000, which
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
> If another architecture chooses to go down the same path, we should
> replace the checks for CONFIG_UML with something more generic, such
> as:
> - A CONFIG_KASAN_NO_SHADOW_ALLOC option, which architectures could set
> - or, a way of having architecture-specific versions of these vmalloc
>   and module shadow memory allocation options.
>
> Also note that, while UML supports both KASAN in inline mode
> (CONFIG_KASAN_INLINE) and static linking (CONFIG_STATIC_LINK), it does
> not support both at the same time.
>
> Signed-off-by: Patricia Alfonso <trishalfonso@google.com>
> Co-developed-by: Vincent Whitchurch <vincent.whitchurch@axis.com>
> Signed-off-by: Vincent Whitchurch <vincent.whitchurch@axis.com>
> Signed-off-by: David Gow <davidgow@google.com>
> Reviewed-by: Johannes Berg <johannes@sipsolutions.net>
> ---
> This is v3 of the KASAN/UML port. It should be ready to go.
>
> Note that this will fail to build if UML is linked statically due to:
> https://lore.kernel.org/all/20220526185402.955870-1-davidgow@google.com/
>
>
> Changes since v2:
> https://lore.kernel.org/lkml/20220527185600.1236769-2-davidgow@google.com/
> - Don't define CONFIG_KASAN in USER_CFLAGS, given we dont' use it.
>   (Thanks Johannes)
> - Update patch descriptions and comments given we allocate shadow memory based
>   on the size of the virtual address space, not the "physical" memory
>   used by UML.
>   - This was changed between the original RFC and v1, with
>     KASAN_SHADOW_SIZE's definition being updated.
>   - References to UML using 18TB of space and the shadow memory taking
>     2.25TB were updated. (Thanks Johannes)
>   - A mention of physical memory in a comment was updated. (Thanks
>     Andrey)
> - Move some discussion of how the vmalloc() handling could be made more
>   generic from a comment to the commit description. (Thanks Andrey)
>
> Changes since RFC v3:
> https://lore.kernel.org/all/20220526010111.755166-1-davidgow@google.com/
> - No longer print "KernelAddressSanitizer initialized" (Johannes)
> - Document the reason for the CONFIG_UML checks in shadow.c (Dmitry)
> - Support static builds via kasan_arch_is_ready() (Dmitry)
> - Get rid of a redundant call to kasam_mem_to_shadow() (Dmitry)
> - Use PAGE_ALIGN and the new PAGE_ALIGN_DOWN macros (Dmitry)
> - Reinstate missing arch/um/include/asm/kasan.h file (Johannes)
>
> Changes since v1:
> https://lore.kernel.org/all/20200226004608.8128-1-trishalfonso@google.com/
> - Include several fixes from Vincent Whitchurch:
> https://lore.kernel.org/all/20220525111756.GA15955@axis.com/
> - Support for KASAN_VMALLOC, by changing the way
>   kasan_{populate,release}_vmalloc work to update existing shadow
>   memory, rather than allocating anything new.
> - A similar fix for modules' shadow memory.
> - Support for KASAN_STACK
>   - This requires the bugfix here:
> https://lore.kernel.org/lkml/20220523140403.2361040-1-vincent.whitchurch@axis.com/
>   - Plus a couple of files excluded from KASAN.
> - Revert the default shadow offset to 0x100000000000
>   - This was breaking when mem=1G for me, at least.
> - A few minor fixes to linker sections and scripts.
>   - I've added one to dyn.lds.S on top of the ones Vincent added.
>
> ---

<... snip ...>

> diff --git a/mm/kasan/shadow.c b/mm/kasan/shadow.c
> index a4f07de21771..7a7fc76e99a8 100644
> --- a/mm/kasan/shadow.c
> +++ b/mm/kasan/shadow.c
> @@ -295,9 +295,22 @@ int kasan_populate_vmalloc(unsigned long addr, unsigned long size)
>                 return 0;
>
>         shadow_start = (unsigned long)kasan_mem_to_shadow((void *)addr);
> -       shadow_start = ALIGN_DOWN(shadow_start, PAGE_SIZE);
>         shadow_end = (unsigned long)kasan_mem_to_shadow((void *)addr + size);
> -       shadow_end = ALIGN(shadow_end, PAGE_SIZE);
> +
> +       /*
> +        * User Mode Linux maps enough shadow memory for all of virtual memory
> +        * at boot, so doesn't need to allocate more on vmalloc, just clear it.
> +        *
> +         * The remaining CONFIG_UML checks in this file exist for the same
> +         * reason.
> +        */

Whoops: these lines had tabs converted to spaces when I reformatted
them. I've sent out v4 which actually passes checkpatch:
https://lore.kernel.org/lkml/20220630080834.2742777-2-davidgow@google.com/

Sorry for the spam!

-- David

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CABVgOS%3D0PmF5k8RcP2Q3JNkMXK4Pd6ZLVGgCT9Ff%2Bt9Dt_wA%3Dw%40mail.gmail.com.
