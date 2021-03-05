Return-Path: <kasan-dev+bncBDX4HWEMTEBRBHOURGBAMGQEIJR2BZY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43a.google.com (mail-pf1-x43a.google.com [IPv6:2607:f8b0:4864:20::43a])
	by mail.lfdr.de (Postfix) with ESMTPS id B66F932F127
	for <lists+kasan-dev@lfdr.de>; Fri,  5 Mar 2021 18:27:58 +0100 (CET)
Received: by mail-pf1-x43a.google.com with SMTP id f17sf1913928pfj.3
        for <lists+kasan-dev@lfdr.de>; Fri, 05 Mar 2021 09:27:58 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1614965277; cv=pass;
        d=google.com; s=arc-20160816;
        b=YuhSXGVlzylB4e66V9DzJZkJTvyPaiuRxox9zeZsIbSxl352TAD+bt+f/RVWoUg4wZ
         XnWTRBLC1YLGYPs37Hvjy+M119Hp/B87LOKsRNaS7LNGzOKD0pZZlge0qERMa3XPlHQu
         xPi8KU3hOmmLxQrfhzl9SjpXDDHvWO8sPgGZdYeaeurgQk4c14R0wlFPs77XNOEi3Q/z
         OUo+lg6Qqqi/z/jzTEL0taoR05se068HIO2AHEIDuajEKHYamls77d36jHLKoEQyTwfN
         TyvLWdusb4JdMnmkcYrIyesQC6SOpSINCIS+La/wqXeSweotCPMAx2Fw4b1bPDs5kUau
         LAVQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=wmW+mBxOc5RoIrfUJSHBoTpNbEDSp4Vcof3RPKd4t6o=;
        b=Lq7SC67S4az0QixSo7s9n6lV5PCeLCIOrJ5V+A0gX+K8yCnF3Lfv65v0xM70B0fSJS
         m+f5PMLFC4Biy/OG6nt8wBpEA3Q+5Mq3ioHwCLr1KY5N+fjHtkdJZhAXdF3rIKIBCIB2
         miIFTZ6Y3pld+OVl/pOFCpQtr7rHxWHUUZ6aCBlxro/Emy57brQHbOHMXVHQbsg+t/RT
         3hBx0oK81VtUmecFsA0mnlEXxktawiLGPWTMNLi2GU7dn80QkvxRy2zxdK4Lz9uHi9c7
         axTjNvjhtiFH3xQur2z8aG6pOt5iDfNV8YqFdadqdDFx4rCxxEd0I8ko2Kd1LJ5nabyP
         /q/g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=eVe0n7v4;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::429 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=wmW+mBxOc5RoIrfUJSHBoTpNbEDSp4Vcof3RPKd4t6o=;
        b=hzaLWd0bUzdaSJVeHbX+2XQLAAa7T35iWZ3hhm4WdWdcdVUFwhUgsyKC9hqJ3Hd1GF
         TlJHTsa6umb0TAjfNL07tCWUMYVtL2TDqb3JGGGNJ+3KzCAmoOV3vdGfom3yzR7ztA8R
         0RRvaJd+i6qxLl3rAd6Ye4uiFRvu3sVX4WmLfxb/lwSNBS9IeQealbgPaklrZAdfSxLp
         LNtJF5pOtgsM49vWobkmN9oTXN33q+4lOuxZfI9j1LGlY37n2O17kJR9YvPfONooecoR
         rLKbqdUDWgoDJ0C/BeLPe+6d3LwZOOtYNpsmRtQqYE7uB7zvljZyZ2J2WTG3KImjj+mh
         A4eA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=wmW+mBxOc5RoIrfUJSHBoTpNbEDSp4Vcof3RPKd4t6o=;
        b=tpqwLRDGAvot71raq3saEHmKB2BQ4OYAyW5SXocsOVSKM0sJkTy6GzGtNwDIk80OrW
         aIHYIi3h5D/6ZXDzkIscISKOvnnWHyC0v0n/ySe3feFmGP9YpPsUviFP9jYxAucbWdwg
         lHEaA+X3od+qrSwgMmXwrgt44ih5VQS6DDLHxiPvb6RWxjk7tXC8jiEehCoX9B1qzbEf
         Anr7S0urj8hnoWFYWWFcRZOLkwKVBVdZewkKvtlfnJf/2NEAHercRw8T4WQQf0SaX2PT
         mt+5McXcuLACviG2AJRfKLK9czAl7afGvMwB2JqtZa2IyGlS2oHtaFbzAdCIWzzc2OnS
         AQeg==
X-Gm-Message-State: AOAM530sMN0DGLKQbFUIudxCBM3uwQm9LMDUUc0GKiBs8vMFF6EEffur
	02AtJavlb45HMuOD0S5OKZ8=
X-Google-Smtp-Source: ABdhPJzA+dwhoWcxlUtIxcfHQEgkNfO42/Qb6zaoPpGTmCI1e8acPFnGuXZsSqOeDLcjAO0rtUOZpw==
X-Received: by 2002:a63:c90a:: with SMTP id o10mr9694778pgg.172.1614965277451;
        Fri, 05 Mar 2021 09:27:57 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:1790:: with SMTP id 138ls4153123pfx.5.gmail; Fri, 05 Mar
 2021 09:27:57 -0800 (PST)
X-Received: by 2002:a63:c80c:: with SMTP id z12mr9410224pgg.376.1614965276940;
        Fri, 05 Mar 2021 09:27:56 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1614965276; cv=none;
        d=google.com; s=arc-20160816;
        b=XBGW1NgkvVvwAqkKeh9UiUDDyXUXpPOATkYsIS+1GbX3j65LDcKC5/fGN7LnIP+r1o
         +OlJfCYgATM629fxUOgMezTeuPR7J2AcpjolHuFroly9EQocY287D9TxeSpMMHKTsl+x
         4kmcyYvotyRz/7TNcwIrq/U6noZprM5QPylll2cCUGK1bCqAvZONhnLnWJxLQX6mU5tO
         sBmXsZ1gn1TW1h5kLS1kf8guPDfJ+pFbcT1pmj9jvFwsnVaCr3yLcChCw/duBcfkdqOc
         k5yzlHXScDQx2HyXjOOcPjlPR3AuEBZhDfHhbXM8aDXsVmTC+WkTlWCZVLENxrcc9mX7
         jBsA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Mns9i0JMQNoxE/XeKE8B1wLj9F9FmeGnmkoG0fLF2Dg=;
        b=cH+bBvpEuTb5aOH7Io3D/lk2Q2V1Rxx0WhFTIxEs/32+OjpvQADfOX8s7r/nTYVBep
         Wj2JVW0caMtg8cfkyh+q/iVRusY904zMqLm8FaoC/nZgQ++NmL2l3jZmMyZc6+Er5/iL
         vBLBsn03O9IUCpedhlzWQgnY3jxj74UIeqnW9U7GcmYT/u0k2mxHdsR+PYrg8onju2w/
         URTFG7T5tFRW0hZwHSIjMq2HWX1+jP8Tf3yUUCNliP7sVarRo3h2CPt+LhiMdXQK/tU+
         U0wpNZC+HnN61tWCCtWi3hZsUGXbj+1dcQ1u6ZewurlJQET4/qORadFLpYsRjxjgVpWL
         +oQg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=eVe0n7v4;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::429 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pf1-x429.google.com (mail-pf1-x429.google.com. [2607:f8b0:4864:20::429])
        by gmr-mx.google.com with ESMTPS id e15si167819pjm.3.2021.03.05.09.27.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 05 Mar 2021 09:27:56 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::429 as permitted sender) client-ip=2607:f8b0:4864:20::429;
Received: by mail-pf1-x429.google.com with SMTP id a188so2633259pfb.4
        for <kasan-dev@googlegroups.com>; Fri, 05 Mar 2021 09:27:56 -0800 (PST)
X-Received: by 2002:a63:4b5e:: with SMTP id k30mr9285055pgl.130.1614965276436;
 Fri, 05 Mar 2021 09:27:56 -0800 (PST)
MIME-Version: 1.0
References: <20210305171108.GD23855@arm.com>
In-Reply-To: <20210305171108.GD23855@arm.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 5 Mar 2021 18:27:45 +0100
Message-ID: <CAAeHK+yuxANLmtO_hyd0Kg4DpHh2TLmyMQEXP58V8mLoj0vtvg@mail.gmail.com>
Subject: Re: arm64 KASAN_HW_TAGS panic on non-MTE hardware on 5.12-rc1
To: Catalin Marinas <catalin.marinas@arm.com>
Cc: Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	Will Deacon <will@kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=eVe0n7v4;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::429
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

On Fri, Mar 5, 2021 at 6:11 PM Catalin Marinas <catalin.marinas@arm.com> wrote:
>
> Hi Andrey,

Hi Catalin,

>
> Enabling CONFIG_KASAN_HW_TAGS and running the resulting kernel on
> non-MTE hardware panics with an undefined STG instruction from
> mte_set_mem_tag_range():
>
> ./scripts/faddr2line vmlinux kasan_unpoison_task_stack+0x18/0x40
> kasan_unpoison_task_stack+0x18/0x40:
> mte_set_mem_tag_range at arch/arm64/include/asm/mte-kasan.h:71
> (inlined by) mte_set_mem_tag_range at arch/arm64/include/asm/mte-kasan.h:56
> (inlined by) kasan_unpoison at mm/kasan/kasan.h:363
> (inlined by) kasan_unpoison_task_stack at mm/kasan/common.c:72

This is weird. kasan_unpoison_task_stack() is only defined when
CONFIG_KASAN_STACK is enabled, which shouldn't be enablable for
HW_TAGS.

Are you using the mainline kernel?

Could you share the kernel config that you use?

>
> The full trace:
>
> ------------[ cut here ]------------
> kernel BUG at arch/arm64/kernel/traps.c:406!
> Internal error: Oops - BUG: 0 [#1] PREEMPT SMP
> Modules linked in:
> CPU: 0 PID: 0 Comm: swapper Not tainted 5.12.0-rc1-00002-ge76afd1d69f3-dirty #2
> pstate: 00000085 (nzcv daIf -PAN -UAO -TCO BTYPE=--)
> pc : do_undefinstr+0x2c8/0x2e8
> lr : do_undefinstr+0x2d4/0x2e8
> sp : ffffc07baeaa3cf0
> x29: ffffc07baeaa3cf0 x28: ffffc07baeab3280
> x27: ffffc07baeaa9a00 x26: ffffc07baeaa7000
> x25: ffffc07baeab3964 x24: ffffc07baeaa9c00
> x23: 0000000040000085 x22: ffffc07baed7f0e0
> x21: 00000000d9200800 x20: ffffc07baeab3280
> x19: ffffc07baeaa3d80 x18: 0000000000000200
> x17: 000000000000000b x16: 0000000000007fff
> x15: 00000000ffffffff x14: 0000000000000000
> x13: 0000000000000048 x12: ffffc07baeab3280
> x11: ffff64d0ffc00294 x10: 0000000000000000
> x9 : 0000000000000000 x8 : 00000000389fd980
> x7 : ffff64d0ffbde5b8 x6 : 0000000000000000
> x5 : ffff64d0ffb99880 x4 : ffffc07baeab5710
> x3 : ffffc07baed7f0f0 x2 : 0000000000000000
> x1 : ffffc07baeab3280 x0 : 0000000040000085
> Call trace:
>  do_undefinstr+0x2c8/0x2e8
>  el1_undef+0x30/0x50
>  el1_sync_handler+0x8c/0xc8
>  el1_sync+0x70/0x100
>  kasan_unpoison_task_stack+0x18/0x40
>  sched_init+0x390/0x3f0
>  start_kernel+0x2cc/0x540
>  0x0
> Code: 17ffff8a f9401bf7 17ffffc8 f9001bf7 (d4210000)
> random: get_random_bytes called from print_oops_end_marker+0x2c/0x68 with crng_init=0
> ---[ end trace c881f708bdfe36c8 ]---
>
> If MTE is not available, I thought we should not end up calling the MTE
> backend but it seems that kasan expects the backend to skip the
> undefined instructions.
>
> Does kasan fall back to sw_tags if hw_tags are not available or it just
> disables kasan altogether?

If the hardware doesn't support HW_TAGS, KASAN should get disabled.

If the compiler doesn't support HW_TAGS, I think KASAN will fall back
to GENERIC through oldconfig.

Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2ByuxANLmtO_hyd0Kg4DpHh2TLmyMQEXP58V8mLoj0vtvg%40mail.gmail.com.
