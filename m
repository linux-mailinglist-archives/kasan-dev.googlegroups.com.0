Return-Path: <kasan-dev+bncBCRKNY4WZECBB4GSTOCAMGQEKTP3AGY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63d.google.com (mail-pl1-x63d.google.com [IPv6:2607:f8b0:4864:20::63d])
	by mail.lfdr.de (Postfix) with ESMTPS id 28C6636B6BC
	for <lists+kasan-dev@lfdr.de>; Mon, 26 Apr 2021 18:25:22 +0200 (CEST)
Received: by mail-pl1-x63d.google.com with SMTP id x7-20020a1709027c07b02900e6489d6231sf24262774pll.6
        for <lists+kasan-dev@lfdr.de>; Mon, 26 Apr 2021 09:25:22 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1619454320; cv=pass;
        d=google.com; s=arc-20160816;
        b=KA5RZ117oLDruWZED6o/kHiMBhUd+7Ep8tssmbgFer6LM0nF/DGk5aAnk/fVEWb1+q
         oUsKnP3DCtheNphmrbEG06SlEV4PqJ4aucaZEEjP3KEHgyIjH2UlImpgDwwVtWipoWvQ
         dsDDRzjgLmiz+DvZGaMSL7q3ie7dwCj8C581DYbOJ4plvzLx1NFwIvuFnYXrXJmkWoae
         6lH0oGU2FG8PUXtI1xKbbZD1k3eusn5RdOq2S1/q61cUTg7aiP6ezqdsBq4X5isP5LoF
         FqexfaXOzlggutlod8QLMhDahKuVtNqhPXzm50i4QoLpxJn1vMMsKk74b40x/M8SWWXs
         +62Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :mime-version:message-id:to:from:cc:in-reply-to:subject:date:sender
         :dkim-signature;
        bh=Gf/OH5s9j4x4gOCQzI2YmelQAsUXqVj9RLvDJ84z59c=;
        b=x+QDkkrAvx6R+XrcKmm030oiJsl0b5LpEO7rNSYoT0wRO8BJvCI611k1Mf6XUZBkbB
         +/DfSfFS/rv2ViAIK7DuUhS+HpVGZDP4T/DlsDVSQnk/tj907JuOMHZe3f3CAm0eKJV9
         xnZT29g1JTbAP51JZ9lEhs4IT2OH822KqLArzmfL6Uv/hHY+K06uYAROlMJBwvIYh2Q2
         tWLqE3DZpPA0G0xk2VSUYXJB0p6buuJu2AHTeIXBc63imi/M52/crhpnZo+ck4pHQZem
         Hna3EN9aHNYYY++Q6XjdbixaoLexfdF29OoFcOEufBfAQZlNoBDa6XiJGcyht5Si2rMt
         tWCg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@dabbelt-com.20150623.gappssmtp.com header.s=20150623 header.b=ZyHP65m0;
       spf=pass (google.com: domain of palmer@dabbelt.com designates 2607:f8b0:4864:20::52f as permitted sender) smtp.mailfrom=palmer@dabbelt.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:subject:in-reply-to:cc:from:to:message-id:mime-version
         :content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=Gf/OH5s9j4x4gOCQzI2YmelQAsUXqVj9RLvDJ84z59c=;
        b=Uyg4NmxsUa0Sxy+TDc3X0utDYbMKqQl1piEl8rB4lG6hx03B7orCzBMP2LSM0MBj2y
         IwGdetUd3XhEBWBFYNpV5fIvtqd3KCxWjDvPyjLXWth1jCcDJ68sdztbwtVj8E/ARXJb
         9CTmPVZ453SbNOfFpm/yisTIv1n8yEP3dZvYfblM2rH1aEXEOlh0zRv79Je7GFHurmoR
         8JQwxlEl5fgDUJsvzV1KosjjM0ci8oVVjF6cHrA0YrQFSLXsOWpcaz/DN2lbgbZ8KdH/
         LF6zVp9/KXq/ryMUmOJR7YaNrfgtkGDGHCYKWiTbBY7rt1fZNyg50d8Nr8m2wR2xumHW
         q4dA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:subject:in-reply-to:cc:from:to
         :message-id:mime-version:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Gf/OH5s9j4x4gOCQzI2YmelQAsUXqVj9RLvDJ84z59c=;
        b=c0KFMKmsMfItONt4PltFwmJblFlPwE6SuvW+swSknb5Vso4M65/FK+HghGhptd+PeM
         nUF8EnpAFCGKpBcX7bTAJ2Wt9t36nEjeDFOPdim35uGHWNoMsGT1Ydq2ZB/YMgDOPfQQ
         R53L7l9cKy3WVlkM3N0euSXKFyPB7bIWoUgbaL1vRDyJfeWa5Uxs7l/L2gjmE2bcSGxc
         ZD2/vokgM73DkLhhmkyQNDgk5U3N5hG5cmEJUUYLNOy9ZcJvv43TDtPdlRVEQDxOYOkj
         t6KamZIUY/zrv3cgdQOBCyo9bCkDyqC1ZusHLpnspkf0EQjjAsqiUiv6XcQO+92bOgm1
         yycw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530mc8GwlAvY8m3SswyoWe6PHeT0syULYCHB4vWEU7b56im41i5X
	i98eE5pJlHX7UrSWM7NyUP0=
X-Google-Smtp-Source: ABdhPJyOe5+i8OaoFh4C5P6M4HfE/tI3fi2S3g94xzwpXR3FQ4M27Ly6kWdHO0ZvhZCyFuKI+vEBdA==
X-Received: by 2002:a63:5fc2:: with SMTP id t185mr18148031pgb.181.1619454320447;
        Mon, 26 Apr 2021 09:25:20 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:903:31cc:: with SMTP id v12ls8525633ple.9.gmail; Mon, 26
 Apr 2021 09:25:20 -0700 (PDT)
X-Received: by 2002:a17:90b:98:: with SMTP id bb24mr9550247pjb.206.1619454319914;
        Mon, 26 Apr 2021 09:25:19 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1619454319; cv=none;
        d=google.com; s=arc-20160816;
        b=ZUVJV02fcrvjU5nz5XutfT2DxYcrqZAuIayvfbicdrtH0s3vGCk/17eXNE8/bvBU3U
         lHGA0w/t+0OfwXQe9qzO8jud64QwhEH4Pl0cSVQdIeuG9d4vH/5V00VkGeU22N1gjl91
         SMh+Ejz237uHUyvUMnoU3mor1OEl0zXOouwlUH2Yfb3+x8WdwM2SdvVLqA9amgzgy2qF
         EJxdp+Lg5jIfUrIZgSmK9vQ2lVI4U5cszAF2N1oDf6MPeJP1N2IJ9RRAJUmwZigNqbwG
         81Lvd2ulvwBVKYX6SrE8tw6JjlUwQNBccWWDrHS0VUK+C1t9Usnwpmb0kSFW0wyrnnvQ
         tPlQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:to:from:cc
         :in-reply-to:subject:date:dkim-signature;
        bh=fSI8/NRCqwzanGzofgGeswpyryhOl5XK8N/2SPExUaM=;
        b=BsRDQpNiLESOXMwGutOkDRitO55ecidJhaP9uu3MtGhRp4SYsJB7BhvZRs70hoE5C9
         T6BDliX8TmP8XdMrdZUlpn/QCTegXYdNMxIpBCi+Ef02HcDpNKf60vrnesDYtdPMu6hB
         C8HWM/Ai92FI+5b3jma1HRAdQfrk6aHgeaHJpiqjbBeJrlvoKVukQ54UV+61Xe/vKWVT
         HmHbOTIAItuRbD7PERAN7IefUb1r2waqp7pgjR1iJN3cM63UscLGXqz52ZV2C/LVXf/Q
         PF6o1LYWzVppF2UX1g7BjaxtU/IUNj4Vc9/65FrTXmE2+HdH8iFCTl1nQ+lR9WSrhyLu
         I4og==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@dabbelt-com.20150623.gappssmtp.com header.s=20150623 header.b=ZyHP65m0;
       spf=pass (google.com: domain of palmer@dabbelt.com designates 2607:f8b0:4864:20::52f as permitted sender) smtp.mailfrom=palmer@dabbelt.com
Received: from mail-pg1-x52f.google.com (mail-pg1-x52f.google.com. [2607:f8b0:4864:20::52f])
        by gmr-mx.google.com with ESMTPS id s20si1469568pfw.6.2021.04.26.09.25.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 26 Apr 2021 09:25:19 -0700 (PDT)
Received-SPF: pass (google.com: domain of palmer@dabbelt.com designates 2607:f8b0:4864:20::52f as permitted sender) client-ip=2607:f8b0:4864:20::52f;
Received: by mail-pg1-x52f.google.com with SMTP id p2so24937547pgh.4
        for <kasan-dev@googlegroups.com>; Mon, 26 Apr 2021 09:25:19 -0700 (PDT)
X-Received: by 2002:a62:4e4c:0:b029:259:b25f:1bf with SMTP id c73-20020a624e4c0000b0290259b25f01bfmr18054066pfb.40.1619454319216;
        Mon, 26 Apr 2021 09:25:19 -0700 (PDT)
Received: from localhost (76-210-143-223.lightspeed.sntcca.sbcglobal.net. [76.210.143.223])
        by smtp.gmail.com with ESMTPSA id z2sm201012pfj.203.2021.04.26.09.25.18
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 26 Apr 2021 09:25:18 -0700 (PDT)
Date: Mon, 26 Apr 2021 09:25:18 -0700 (PDT)
Subject: Re: [PATCH] riscv: Fix 32b kernel caused by 64b kernel mapping moving outside linear mapping
In-Reply-To: <97819559-0af0-0422-5b6c-30872f759daa@ghiti.fr>
CC: anup@brainfault.org, corbet@lwn.net, Paul Walmsley <paul.walmsley@sifive.com>,
  aou@eecs.berkeley.edu, Arnd Bergmann <arnd@arndb.de>, aryabinin@virtuozzo.com, glider@google.com,
  dvyukov@google.com, linux-doc@vger.kernel.org, linux-riscv@lists.infradead.org,
  linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com, linux-arch@vger.kernel.org, linux-mm@kvack.org
From: Palmer Dabbelt <palmer@dabbelt.com>
To: alex@ghiti.fr
Message-ID: <mhng-9ced605b-ce0a-4fbd-b794-d01bc51b900c@palmerdabbelt-glaptop>
Mime-Version: 1.0 (MHng)
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: palmer@dabbelt.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@dabbelt-com.20150623.gappssmtp.com header.s=20150623
 header.b=ZyHP65m0;       spf=pass (google.com: domain of palmer@dabbelt.com
 designates 2607:f8b0:4864:20::52f as permitted sender) smtp.mailfrom=palmer@dabbelt.com
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

On Fri, 23 Apr 2021 13:49:10 PDT (-0700), alex@ghiti.fr wrote:
>
>
> Le 4/23/21 =C3=A0 12:57 PM, Palmer Dabbelt a =C3=A9crit=C2=A0:
>> On Fri, 23 Apr 2021 01:34:02 PDT (-0700), alex@ghiti.fr wrote:
>>> Le 4/20/21 =C3=A0 12:18 AM, Anup Patel a =C3=A9crit=C2=A0:
>>>> On Sat, Apr 17, 2021 at 10:52 PM Alexandre Ghiti <alex@ghiti.fr> wrote=
:
>>>>>
>>>>> Fix multiple leftovers when moving the kernel mapping outside the
>>>>> linear
>>>>> mapping for 64b kernel that left the 32b kernel unusable.
>>>>>
>>>>> Fixes: 4b67f48da707 ("riscv: Move kernel mapping outside of linear
>>>>> mapping")
>>>>> Signed-off-by: Alexandre Ghiti <alex@ghiti.fr>
>>>>
>>>> Quite a few #ifdef but I don't see any better way at the moment.
>>>> Maybe we can
>>>> clean this later. Otherwise looks good to me.
>>
>> Agreed.=C2=A0 I'd recently sent out a patch set that got NACK'd because =
we're
>> supposed to be relying on the compiler to optimize away references that
>> can be staticly determined to not be exercised, which is probably the
>> way forward to getting rid of a lot of of preprocessor stuff.=C2=A0 That=
 all
>> seems very fragile and is a bigger problem than this, though, so it's
>> probably best to do it as its own thing.
>>
>>>> Reviewed-by: Anup Patel <anup@brainfault.org>
>>>
>>> Thanks Anup!
>>>
>>> @Palmer: This is not on for-next yet and then rv32 is broken. This does
>>> not apply immediately on top of for-next though, so if you need a new
>>> version, I can do that. But this squashes nicely with the patch it fixe=
s
>>> if you prefer.
>>
>> Thanks.=C2=A0 I just hadn't gotten to this one yet, but as you pointed o=
ut
>> it's probably best to just squash it.=C2=A0 It's in the version on for-n=
ext
>> now, it caused few conflicts but I think I got everything sorted out.
>>
>> Now that everything is in I'm going to stop rewriting this stuff, as it
>> touches pretty much the whole tree.=C2=A0 I don't have much of a patch b=
ack
>> log as of right now, and as the new stuff will be on top of it that will
>> make everyone's lives easier.
>>
>>>
>>> Let me know, I can do that very quickly.
>>>
>>> Alex
>>>
>>>>
>>>> Regards,
>>>> Anup
>>>>
>>>>> ---
>>>>> =C2=A0 arch/riscv/include/asm/page.h=C2=A0=C2=A0=C2=A0 |=C2=A0 9 ++++=
+++++
>>>>> =C2=A0 arch/riscv/include/asm/pgtable.h | 16 ++++++++++++----
>>>>> =C2=A0 arch/riscv/mm/init.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 25 ++++++++++++++++++++++++-
>>>>> =C2=A0 3 files changed, 45 insertions(+), 5 deletions(-)
>>>>>
>>>>> diff --git a/arch/riscv/include/asm/page.h
>>>>> b/arch/riscv/include/asm/page.h
>>>>> index 22cfb2be60dc..f64b61296c0c 100644
>>>>> --- a/arch/riscv/include/asm/page.h
>>>>> +++ b/arch/riscv/include/asm/page.h
>>>>> @@ -90,15 +90,20 @@ typedef struct page *pgtable_t;
>>>>>
>>>>> =C2=A0 #ifdef CONFIG_MMU
>>>>> =C2=A0 extern unsigned long va_pa_offset;
>>>>> +#ifdef CONFIG_64BIT
>>>>> =C2=A0 extern unsigned long va_kernel_pa_offset;
>>>>> +#endif
>>>>> =C2=A0 extern unsigned long pfn_base;
>>>>> =C2=A0 #define ARCH_PFN_OFFSET=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 (pfn_base)
>>>>> =C2=A0 #else
>>>>> =C2=A0 #define va_pa_offset=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0 0
>>>>> +#ifdef CONFIG_64BIT
>>>>> =C2=A0 #define va_kernel_pa_offset=C2=A0=C2=A0=C2=A0 0
>>>>> +#endif
>>>>> =C2=A0 #define ARCH_PFN_OFFSET=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 (PAGE_OFFSET >> PAGE_SH=
IFT)
>>>>> =C2=A0 #endif /* CONFIG_MMU */
>>>>>
>>>>> +#ifdef CONFIG_64BIT
>
> This one is incorrect as kernel_virt_addr is used also in 32b kernel,
> which causes 32b failure when CONFIG_DEBUG_VIRTUAL is set, the following
> diff fixes it:
>
> diff --git a/arch/riscv/include/asm/page.h b/arch/riscv/include/asm/page.=
h
> index e280ba60cb34..6a7761c86ec2 100644
> --- a/arch/riscv/include/asm/page.h
> +++ b/arch/riscv/include/asm/page.h
> @@ -106,9 +106,9 @@ extern unsigned long pfn_base;
>   #define ARCH_PFN_OFFSET                (PAGE_OFFSET >> PAGE_SHIFT)
>   #endif /* CONFIG_MMU */
>
> -#ifdef CONFIG_64BIT
>   extern unsigned long kernel_virt_addr;
>
> +#ifdef CONFIG_64BIT
>   #define linear_mapping_pa_to_va(x)     ((void *)((unsigned long)(x) +
> va_pa_offset))
>   #ifdef CONFIG_XIP_KERNEL
>   #define kernel_mapping_pa_to_va(y)     ({
>                   \

Can you send a patch for this one?  I'm trying to avoid rebasing any=20
more, as there's more stuff on top of this now.

>
>>>>> =C2=A0 extern unsigned long kernel_virt_addr;
>>>>>
>>>>> =C2=A0 #define linear_mapping_pa_to_va(x)=C2=A0=C2=A0=C2=A0=C2=A0 ((v=
oid *)((unsigned
>>>>> long)(x) + va_pa_offset))
>>>>> @@ -112,6 +117,10 @@ extern unsigned long kernel_virt_addr;
>>>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 (_x < kernel_virt_ad=
dr)
>>>>> ?=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 \
>>>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0 linear_mapping_va_to_pa(_x) :
>>>>> kernel_mapping_va_to_pa(_x);=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 \
>>>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 })
>>>>> +#else
>>>>> +#define __pa_to_va_nodebug(x)=C2=A0 ((void *)((unsigned long) (x) +
>>>>> va_pa_offset))
>>>>> +#define __va_to_pa_nodebug(x)=C2=A0 ((unsigned long)(x) - va_pa_offs=
et)
>>>>> +#endif
>>>>>
>>>>> =C2=A0 #ifdef CONFIG_DEBUG_VIRTUAL
>>>>> =C2=A0 extern phys_addr_t __virt_to_phys(unsigned long x);
>>>>> diff --git a/arch/riscv/include/asm/pgtable.h
>>>>> b/arch/riscv/include/asm/pgtable.h
>>>>> index 80e63a93e903..5afda75cc2c3 100644
>>>>> --- a/arch/riscv/include/asm/pgtable.h
>>>>> +++ b/arch/riscv/include/asm/pgtable.h
>>>>> @@ -16,19 +16,27 @@
>>>>> =C2=A0 #else
>>>>>
>>>>> =C2=A0 #define ADDRESS_SPACE_END=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 (UL(-1=
))
>>>>> -/*
>>>>> - * Leave 2GB for kernel and BPF at the end of the address space
>>>>> - */
>>>>> +
>>>>> +#ifdef CONFIG_64BIT
>>>>> +/* Leave 2GB for kernel and BPF at the end of the address space */
>>>>> =C2=A0 #define KERNEL_LINK_ADDR=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 (=
ADDRESS_SPACE_END - SZ_2G + 1)
>>>>> +#else
>>>>> +#define KERNEL_LINK_ADDR=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 PAGE_OF=
FSET
>>>>> +#endif
>>>>>
>>>>> =C2=A0 #define VMALLOC_SIZE=C2=A0=C2=A0=C2=A0=C2=A0 (KERN_VIRT_SIZE >=
> 1)
>>>>> =C2=A0 #define VMALLOC_END=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 (PAGE_OFFSET=
 - 1)
>>>>> =C2=A0 #define VMALLOC_START=C2=A0=C2=A0=C2=A0 (PAGE_OFFSET - VMALLOC=
_SIZE)
>>>>>
>>>>> -/* KASLR should leave at least 128MB for BPF after the kernel */
>>>>> =C2=A0 #define BPF_JIT_REGION_SIZE=C2=A0=C2=A0=C2=A0 (SZ_128M)
>>>>> +#ifdef CONFIG_64BIT
>>>>> +/* KASLR should leave at least 128MB for BPF after the kernel */
>>>>> =C2=A0 #define BPF_JIT_REGION_START=C2=A0=C2=A0 PFN_ALIGN((unsigned l=
ong)&_end)
>>>>> =C2=A0 #define BPF_JIT_REGION_END=C2=A0=C2=A0=C2=A0=C2=A0 (BPF_JIT_RE=
GION_START +
>>>>> BPF_JIT_REGION_SIZE)
>>>>> +#else
>>>>> +#define BPF_JIT_REGION_START=C2=A0=C2=A0 (PAGE_OFFSET - BPF_JIT_REGI=
ON_SIZE)
>>>>> +#define BPF_JIT_REGION_END=C2=A0=C2=A0=C2=A0=C2=A0 (VMALLOC_END)
>>>>> +#endif
>>>>>
>>>>> =C2=A0 /* Modules always live before the kernel */
>>>>> =C2=A0 #ifdef CONFIG_64BIT
>>>>> diff --git a/arch/riscv/mm/init.c b/arch/riscv/mm/init.c
>>>>> index 093f3a96ecfc..dc9b988e0778 100644
>>>>> --- a/arch/riscv/mm/init.c
>>>>> +++ b/arch/riscv/mm/init.c
>>>>> @@ -91,8 +91,10 @@ static void print_vm_layout(void)
>>>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 (unsigned long)VMALLOC_END);
>>>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 print_mlm("lowmem", =
(unsigned long)PAGE_OFFSET,
>>>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 (unsigned long)high_memory);
>>>>> +#ifdef CONFIG_64BIT
>>>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 print_mlm("kernel", =
(unsigned long)KERNEL_LINK_ADDR,
>>>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 (unsigned long)ADDRESS_SPACE_END);
>>>>> +#endif
>>>>> =C2=A0 }
>>>>> =C2=A0 #else
>>>>> =C2=A0 static void print_vm_layout(void) { }
>>>>> @@ -165,9 +167,11 @@ static struct pt_alloc_ops pt_ops;
>>>>> =C2=A0 /* Offset between linear mapping virtual address and kernel lo=
ad
>>>>> address */
>>>>> =C2=A0 unsigned long va_pa_offset;
>>>>> =C2=A0 EXPORT_SYMBOL(va_pa_offset);
>>>>> +#ifdef CONFIG_64BIT
>>>>> =C2=A0 /* Offset between kernel mapping virtual address and kernel lo=
ad
>>>>> address */
>>>>> =C2=A0 unsigned long va_kernel_pa_offset;
>>>>> =C2=A0 EXPORT_SYMBOL(va_kernel_pa_offset);
>>>>> +#endif
>>>>> =C2=A0 unsigned long pfn_base;
>>>>> =C2=A0 EXPORT_SYMBOL(pfn_base);
>>>>>
>>>>> @@ -410,7 +414,9 @@ asmlinkage void __init setup_vm(uintptr_t dtb_pa)
>>>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 load_sz =3D (uintptr=
_t)(&_end) - load_pa;
>>>>>
>>>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 va_pa_offset =3D PAG=
E_OFFSET - load_pa;
>>>>> +#ifdef CONFIG_64BIT
>>>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 va_kernel_pa_offset =
=3D kernel_virt_addr - load_pa;
>>>>> +#endif
>>>>>
>>>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 pfn_base =3D PFN_DOW=
N(load_pa);
>>>>>
>>>>> @@ -469,12 +475,16 @@ asmlinkage void __init setup_vm(uintptr_t dtb_p=
a)
>>>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0 pa + PMD_SIZE, PMD_SIZE, PAGE_KERNEL);
>>>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 dtb_early_va =3D (vo=
id *)DTB_EARLY_BASE_VA + (dtb_pa &
>>>>> (PMD_SIZE - 1));
>>>>> =C2=A0 #else /* CONFIG_BUILTIN_DTB */
>>>>> +#ifdef CONFIG_64BIT
>>>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 /*
>>>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 * __va can't b=
e used since it would return a linear
>>>>> mapping address
>>>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 * whereas dtb_=
early_va will be used before setup_vm_final
>>>>> installs
>>>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 * the linear m=
apping.
>>>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 */
>>>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 dtb_early_va =3D ker=
nel_mapping_pa_to_va(dtb_pa);
>>>>> +#else
>>>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 dtb_early_va =3D __va(dtb_pa);
>>>>> +#endif /* CONFIG_64BIT */
>>>>> =C2=A0 #endif /* CONFIG_BUILTIN_DTB */
>>>>> =C2=A0 #else
>>>>> =C2=A0 #ifndef CONFIG_BUILTIN_DTB
>>>>> @@ -486,7 +496,11 @@ asmlinkage void __init setup_vm(uintptr_t dtb_pa=
)
>>>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0 pa + PGDIR_SIZE, PGDIR_SIZE, PAGE_KERNEL);
>>>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 dtb_early_va =3D (vo=
id *)DTB_EARLY_BASE_VA + (dtb_pa &
>>>>> (PGDIR_SIZE - 1));
>>>>> =C2=A0 #else /* CONFIG_BUILTIN_DTB */
>>>>> +#ifdef CONFIG_64BIT
>>>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 dtb_early_va =3D ker=
nel_mapping_pa_to_va(dtb_pa);
>>>>> +#else
>>>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 dtb_early_va =3D __va(dtb_pa);
>>>>> +#endif /* CONFIG_64BIT */
>>>>> =C2=A0 #endif /* CONFIG_BUILTIN_DTB */
>>>>> =C2=A0 #endif
>>>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 dtb_early_pa =3D dtb=
_pa;
>>>>> @@ -571,12 +585,21 @@ static void __init setup_vm_final(void)
>>>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0 for (pa =3D start; pa < end; pa +=3D map_size) =
{
>>>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
 va =3D (uintptr_t)__va(pa);
>>>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
 create_pgd_mapping(swapper_pg_dir, va, pa,
>>>>> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 map_size, PAGE_KERNEL);
>>>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 map_size,
>>>>> +#ifdef CONFIG_64BIT
>>>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 PAGE_KERNEL
>>>>> +#else
>>>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 PAGE_KERNEL_EXEC
>>>>> +#endif
>>>>> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0 );
>>>>> +
>>>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0 }
>>>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 }
>>>>>
>>>>> +#ifdef CONFIG_64BIT
>>>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 /* Map the kernel */
>>>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 create_kernel_page_t=
able(swapper_pg_dir, PMD_SIZE);
>>>>> +#endif
>>>>>
>>>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 /* Clear fixmap PTE =
and PMD mappings */
>>>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 clear_fixmap(FIX_PTE=
);
>>>>> --
>>>>> 2.20.1
>>>>>
>
> I agree with you, too much #ifdef, it is hardly readable: I take a look
> at how I can make it simpler.
>
> Sorry for all those fixes,
>
> Alex
>
>>
>> _______________________________________________
>> linux-riscv mailing list
>> linux-riscv@lists.infradead.org
>> http://lists.infradead.org/mailman/listinfo/linux-riscv

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/mhng-9ced605b-ce0a-4fbd-b794-d01bc51b900c%40palmerdabbelt-glaptop=
.
