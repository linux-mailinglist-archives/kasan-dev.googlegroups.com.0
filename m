Return-Path: <kasan-dev+bncBCRKNY4WZECBBJ5LW2DAMGQEPLMWHCI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3d.google.com (mail-qv1-xf3d.google.com [IPv6:2607:f8b0:4864:20::f3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 724503AD84D
	for <lists+kasan-dev@lfdr.de>; Sat, 19 Jun 2021 08:58:48 +0200 (CEST)
Received: by mail-qv1-xf3d.google.com with SMTP id cj11-20020a056214056bb029026a99960c7asf2258790qvb.22
        for <lists+kasan-dev@lfdr.de>; Fri, 18 Jun 2021 23:58:48 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1624085927; cv=pass;
        d=google.com; s=arc-20160816;
        b=BGF7un+bKXghGu1EaKwd4VP1gRDP39igQkMDFMW83WcTSTimJHPFy202FvsaESI522
         xVIJF62jHxqJ6s5Q08Dimv2DTUXdWoePbKZ37HM2Op/BXC2hIicDWXByGpNUd0Y+UHLG
         CrBRZM85crP/u42YHoghHpeUc0F19JsOL5oba0NtJC/ctJmXBiJUPu8tQqqgBf6OK+dy
         eBRgAzmjJXACDoZWECiQYGKGedOnxiqJSUqZAaYmZMj/CnicKpCkAXxJPXmjbr8XJMDa
         AkMWeiSniJ8UULbI3zTrqL7qKKGRtcLYk/rsM+JzTwRuNY5slQhU6g6TohKs0+9hmbOq
         JMow==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:to:from:cc
         :in-reply-to:subject:date:sender:dkim-signature;
        bh=6Ea80nDqGFYID+imN2pzE/ZROSRVAdMRSeLT3cVCGoc=;
        b=rXU5YCB4QYi+uxyom0YfreQ7hMveiHbspPFcwaE5As5nJdIFyokvtzrgW4mrPv7L/n
         FxBeMCiTOg8bToh60Yn78oZ4IZR21gGKrsgDuanNLyWFNBkSIX6SE+LY2Ao+XzpRf4Dc
         6f8d4UrfZbAoh610ibxRR8STRMofLcdf+0S9r0/+xlAfI0YuVCCRZlgXxxxiZeFtdjSN
         GK8Izy+qtscpFkXy+zyVcT+fEcJOlJltR8RV5nuL+e1Hi1IM/+4Q0d5zqDgnqXOME370
         Kv9DXAUWM1eII9hHSpuyBuYz+nAuEvnjllFh2Dj8+Rc5ftXbPRaSsfYsLGN3/s1KECya
         Wfuw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@dabbelt-com.20150623.gappssmtp.com header.s=20150623 header.b=Zmz0Z57z;
       spf=pass (google.com: domain of palmer@dabbelt.com designates 2607:f8b0:4864:20::52e as permitted sender) smtp.mailfrom=palmer@dabbelt.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:subject:in-reply-to:cc:from:to:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=6Ea80nDqGFYID+imN2pzE/ZROSRVAdMRSeLT3cVCGoc=;
        b=TYifCG9/dqnUpzjbCrUb02C3fNjJUU5X7Wt19OecQguq4cg7dzujLx/V3ORgpI4ruz
         ueg+fOjsiJJp4QMaWmYxI0KE3kRJByy/wRdi46Lp+yO+bV8XdcH85pzWoRnhxRTvfwUW
         az9nOTHVh6iJJfQURTEmJrdI+AVKeFvyXZCWYgVJtmrmCSLblL5AJ4aZaP/KFfrg80rt
         1PSs7jwwI0R3hxlZNj08tWtLpJQGeREhTdOVK1e5Vlbp+6Q2Jk/rG6dOGNMOpKLklpdf
         CMBKAyAOhPBFV5IUx18aqoMVKJzIQAkurszeFPSF81lybblCEQjotE9cIuV+Z4PqQbSy
         zslA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:subject:in-reply-to:cc:from:to
         :message-id:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=6Ea80nDqGFYID+imN2pzE/ZROSRVAdMRSeLT3cVCGoc=;
        b=ijmw00MmZ0F01tg+EnD/9C9wvNietPrvFbYhBRTEjD0klA4jeo08Om23RxduBTdaIo
         Vjzoro52/psjaexokpGu5Z6FlS/S/MbHM3AEuvGwJ0/PnnP6nDAnMXPkgyXQUOvAooNP
         RUXu02wkuBk0//SyYR0qK7Z/sc1lyQkpLfqeTavEQnIDscdMFFGlzQtZI1/aNLfhO1iA
         wobZSME5o36Tz/IT6klHQsYXSjImtpkrcGtseuz8uKIya0cf8GT3fLAOEeWgo2NWQSKG
         zkMfRR+g9JBXmjZl8YA6Vr9+lrF2dB9gkYerx2mw8lgSsYUdDnou3QXgPHX+ZhGugliY
         4ZDg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5321ipFWtKqVGIxlw+lwTWsYu7n8RkJ2hWIX+1zquqGYJOStAJCH
	XYUT6AdDUEdyimxebPh6Oxw=
X-Google-Smtp-Source: ABdhPJyvt1QzHP3r/sN0mlzgSo6H2zB3P2pAD6ED864JSWV9z5zcnn2WQGOlMEoEAKFU7LFfuwYKeg==
X-Received: by 2002:a37:4096:: with SMTP id n144mr12741319qka.271.1624085927315;
        Fri, 18 Jun 2021 23:58:47 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:da7:: with SMTP id h7ls4175336qvh.3.gmail; Fri, 18
 Jun 2021 23:58:46 -0700 (PDT)
X-Received: by 2002:a05:6214:1cb:: with SMTP id c11mr9350070qvt.47.1624085926891;
        Fri, 18 Jun 2021 23:58:46 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1624085926; cv=none;
        d=google.com; s=arc-20160816;
        b=cku4FqvHfkocZ8yrJ01wvSolNajQ1rOUwEODmYOBuB5rGNTA1iZLidWVB34bgAlaco
         imBGpYyqCPKcKLW8rayDMuzTJXCOMqV2EwwtqXL/n6xv32BznerU3+j5F7BgxtTkLPIH
         Mhh777ulxH4K2qxMXCUA4bd6cXBMYbbruQlM4uxvMjalR4bnWPtaANc/hnzqy5NBm9JP
         wAV2Z8+SKG6GTEkft7oLZkFVH1ACEGX3LLXavRKoeCUGUsZp19KuXIp1re9I8wFVQCun
         OnIs5POvwJyaRctAwAF3i1fBXokBKW8PP2mVXoyOHmhHWFXmfXmTYuheZSGZj2VYX2EQ
         0zVQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:to:from:cc
         :in-reply-to:subject:date:dkim-signature;
        bh=Y5Tj5VBfCDbHRxlPn8EtoNBakme15m1U4y437Ov6/kw=;
        b=J1Om0eOYREk9TNJ5QkslRz3Bp+hJaxYeQyhYhV6ApmxMAqioaUcR8BedE+IvgDfBaq
         N7GqjwwSyPC+uXKxWgnbtPNuCX2tCJTOalyKcS3aRvrF7bfpIZ76bJhWoUvTkrJnuJNZ
         IdqKSbf/Ej17cyiWIYuXOuoMdng12oW5AiaLZgYdhewWLjh1+ZMWM+HusZJqOqdYpWv8
         E4ZUAUojjZxl1kb5oQoiHHGauvaKYjetjTECbkICD7HNjhqgDTdnJk5cwn0ONlozs7Sr
         5oezTz+4CybS7Smc47PT2HIlmKvzpjfgWBTXKzi8SwnGOQLMmNrloXjY5Rv3xcNRcvCI
         g09A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@dabbelt-com.20150623.gappssmtp.com header.s=20150623 header.b=Zmz0Z57z;
       spf=pass (google.com: domain of palmer@dabbelt.com designates 2607:f8b0:4864:20::52e as permitted sender) smtp.mailfrom=palmer@dabbelt.com
Received: from mail-pg1-x52e.google.com (mail-pg1-x52e.google.com. [2607:f8b0:4864:20::52e])
        by gmr-mx.google.com with ESMTPS id w16si731313qtt.4.2021.06.18.23.58.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 18 Jun 2021 23:58:46 -0700 (PDT)
Received-SPF: pass (google.com: domain of palmer@dabbelt.com designates 2607:f8b0:4864:20::52e as permitted sender) client-ip=2607:f8b0:4864:20::52e;
Received: by mail-pg1-x52e.google.com with SMTP id m2so9706389pgk.7
        for <kasan-dev@googlegroups.com>; Fri, 18 Jun 2021 23:58:46 -0700 (PDT)
X-Received: by 2002:aa7:83c3:0:b029:2e8:f2ba:3979 with SMTP id j3-20020aa783c30000b02902e8f2ba3979mr8852013pfn.8.1624085925610;
        Fri, 18 Jun 2021 23:58:45 -0700 (PDT)
Received: from localhost (76-210-143-223.lightspeed.sntcca.sbcglobal.net. [76.210.143.223])
        by smtp.gmail.com with ESMTPSA id b21sm10769551pgj.74.2021.06.18.23.58.44
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 18 Jun 2021 23:58:45 -0700 (PDT)
Date: Fri, 18 Jun 2021 23:58:45 -0700 (PDT)
Subject: Re: [PATCH v3] riscv: Ensure BPF_JIT_REGION_START aligned with PMD size
In-Reply-To: <20210618220913.6fde1957@xhacker>
CC: corbet@lwn.net, Paul Walmsley <paul.walmsley@sifive.com>, aou@eecs.berkeley.edu,
  ryabinin.a.a@gmail.com, glider@google.com, andreyknvl@gmail.com, dvyukov@google.com, ast@kernel.org,
  daniel@iogearbox.net, andrii@kernel.org, kafai@fb.com, songliubraving@fb.com, yhs@fb.com,
  john.fastabend@gmail.com, kpsingh@kernel.org, alex@ghiti.fr, linux-doc@vger.kernel.org,
  linux-riscv@lists.infradead.org, linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com,
  netdev@vger.kernel.org, bpf@vger.kernel.org
From: Palmer Dabbelt <palmer@dabbelt.com>
To: jszhang3@mail.ustc.edu.cn, schwab@linux-m68k.org
Message-ID: <mhng-3008635e-9a78-413a-8b99-d20a14c5494b@palmerdabbelt-glaptop>
Mime-Version: 1.0 (MHng)
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Original-Sender: palmer@dabbelt.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@dabbelt-com.20150623.gappssmtp.com header.s=20150623
 header.b=Zmz0Z57z;       spf=pass (google.com: domain of palmer@dabbelt.com
 designates 2607:f8b0:4864:20::52e as permitted sender) smtp.mailfrom=palmer@dabbelt.com
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

On Fri, 18 Jun 2021 07:09:13 PDT (-0700), jszhang3@mail.ustc.edu.cn wrote:
> From: Jisheng Zhang <jszhang@kernel.org>
>
> Andreas reported commit fc8504765ec5 ("riscv: bpf: Avoid breaking W^X")
> breaks booting with one kind of defconfig, I reproduced a kernel panic
> with the defconfig:
>
> [    0.138553] Unable to handle kernel paging request at virtual address ffffffff81201220
> [    0.139159] Oops [#1]
> [    0.139303] Modules linked in:
> [    0.139601] CPU: 0 PID: 1 Comm: swapper/0 Not tainted 5.13.0-rc5-default+ #1
> [    0.139934] Hardware name: riscv-virtio,qemu (DT)
> [    0.140193] epc : __memset+0xc4/0xfc
> [    0.140416]  ra : skb_flow_dissector_init+0x1e/0x82
> [    0.140609] epc : ffffffff8029806c ra : ffffffff8033be78 sp : ffffffe001647da0
> [    0.140878]  gp : ffffffff81134b08 tp : ffffffe001654380 t0 : ffffffff81201158
> [    0.141156]  t1 : 0000000000000002 t2 : 0000000000000154 s0 : ffffffe001647dd0
> [    0.141424]  s1 : ffffffff80a43250 a0 : ffffffff81201220 a1 : 0000000000000000
> [    0.141654]  a2 : 000000000000003c a3 : ffffffff81201258 a4 : 0000000000000064
> [    0.141893]  a5 : ffffffff8029806c a6 : 0000000000000040 a7 : ffffffffffffffff
> [    0.142126]  s2 : ffffffff81201220 s3 : 0000000000000009 s4 : ffffffff81135088
> [    0.142353]  s5 : ffffffff81135038 s6 : ffffffff8080ce80 s7 : ffffffff80800438
> [    0.142584]  s8 : ffffffff80bc6578 s9 : 0000000000000008 s10: ffffffff806000ac
> [    0.142810]  s11: 0000000000000000 t3 : fffffffffffffffc t4 : 0000000000000000
> [    0.143042]  t5 : 0000000000000155 t6 : 00000000000003ff
> [    0.143220] status: 0000000000000120 badaddr: ffffffff81201220 cause: 000000000000000f
> [    0.143560] [<ffffffff8029806c>] __memset+0xc4/0xfc
> [    0.143859] [<ffffffff8061e984>] init_default_flow_dissectors+0x22/0x60
> [    0.144092] [<ffffffff800010fc>] do_one_initcall+0x3e/0x168
> [    0.144278] [<ffffffff80600df0>] kernel_init_freeable+0x1c8/0x224
> [    0.144479] [<ffffffff804868a8>] kernel_init+0x12/0x110
> [    0.144658] [<ffffffff800022de>] ret_from_exception+0x0/0xc
> [    0.145124] ---[ end trace f1e9643daa46d591 ]---
>
> After some investigation, I think I found the root cause: commit
> 2bfc6cd81bd ("move kernel mapping outside of linear mapping") moves
> BPF JIT region after the kernel:
>
> | #define BPF_JIT_REGION_START	PFN_ALIGN((unsigned long)&_end)
>
> The &_end is unlikely aligned with PMD size, so the front bpf jit
> region sits with part of kernel .data section in one PMD size mapping.
> But kernel is mapped in PMD SIZE, when bpf_jit_binary_lock_ro() is
> called to make the first bpf jit prog ROX, we will make part of kernel
> .data section RO too, so when we write to, for example memset the
> .data section, MMU will trigger a store page fault.
>
> To fix the issue, we need to ensure the BPF JIT region is PMD size
> aligned. This patch acchieve this goal by restoring the BPF JIT region
> to original position, I.E the 128MB before kernel .text section. The
> modification to kasan_init.c is inspired by Alexandre.
>
> Fixes: fc8504765ec5 ("riscv: bpf: Avoid breaking W^X")
> Reported-by: Andreas Schwab <schwab@linux-m68k.org>
> Signed-off-by: Jisheng Zhang <jszhang@kernel.org>
> ---
> Since v2:
>  - Split the local vars rename modification into another patch per Alexandre
>    suggestion
>  - Add Fixes tag
>
> Since v1:
>  - Fix early boot hang when kasan is enabled
>  - Update Documentation/riscv/vm-layout.rst
>
>  Documentation/riscv/vm-layout.rst | 4 ++--
>  arch/riscv/include/asm/pgtable.h  | 5 ++---
>  arch/riscv/mm/kasan_init.c        | 2 +-
>  3 files changed, 5 insertions(+), 6 deletions(-)
>
> diff --git a/Documentation/riscv/vm-layout.rst b/Documentation/riscv/vm-layout.rst
> index 329d32098af4..b7f98930d38d 100644
> --- a/Documentation/riscv/vm-layout.rst
> +++ b/Documentation/riscv/vm-layout.rst
> @@ -58,6 +58,6 @@ RISC-V Linux Kernel SV39
>                                                                |
>    ____________________________________________________________|____________________________________________________________
>                      |            |                  |         |
> -   ffffffff00000000 |   -4    GB | ffffffff7fffffff |    2 GB | modules
> -   ffffffff80000000 |   -2    GB | ffffffffffffffff |    2 GB | kernel, BPF
> +   ffffffff00000000 |   -4    GB | ffffffff7fffffff |    2 GB | modules, BPF
> +   ffffffff80000000 |   -2    GB | ffffffffffffffff |    2 GB | kernel
>    __________________|____________|__________________|_________|____________________________________________________________
> diff --git a/arch/riscv/include/asm/pgtable.h b/arch/riscv/include/asm/pgtable.h
> index 9469f464e71a..380cd3a7e548 100644
> --- a/arch/riscv/include/asm/pgtable.h
> +++ b/arch/riscv/include/asm/pgtable.h
> @@ -30,9 +30,8 @@
>
>  #define BPF_JIT_REGION_SIZE	(SZ_128M)
>  #ifdef CONFIG_64BIT
> -/* KASLR should leave at least 128MB for BPF after the kernel */
> -#define BPF_JIT_REGION_START	PFN_ALIGN((unsigned long)&_end)
> -#define BPF_JIT_REGION_END	(BPF_JIT_REGION_START + BPF_JIT_REGION_SIZE)
> +#define BPF_JIT_REGION_START	(BPF_JIT_REGION_END - BPF_JIT_REGION_SIZE)
> +#define BPF_JIT_REGION_END	(MODULES_END)
>  #else
>  #define BPF_JIT_REGION_START	(PAGE_OFFSET - BPF_JIT_REGION_SIZE)
>  #define BPF_JIT_REGION_END	(VMALLOC_END)
> diff --git a/arch/riscv/mm/kasan_init.c b/arch/riscv/mm/kasan_init.c
> index 9daacae93e33..55c113345460 100644
> --- a/arch/riscv/mm/kasan_init.c
> +++ b/arch/riscv/mm/kasan_init.c
> @@ -201,7 +201,7 @@ void __init kasan_init(void)
>
>  	/* Populate kernel, BPF, modules mapping */
>  	kasan_populate(kasan_mem_to_shadow((const void *)MODULES_VADDR),
> -		       kasan_mem_to_shadow((const void *)BPF_JIT_REGION_END));
> +		       kasan_mem_to_shadow((const void *)MODULES_VADDR + SZ_2G));
>
>  	for (i = 0; i < PTRS_PER_PTE; i++)
>  		set_pte(&kasan_early_shadow_pte[i],

Thanks, this is on fixes.  With the previous fix also applied it still 
boots for me.

Andreas: I saw you indicate that a subset of this (without the kasan 
chunk, which was breaking for me) fixed your boot issue, but I don't see 
a direct confirmation of that.  LMK if there's still an issue on your 
end, otherwise I'm going to assume this is solved.

Thanks for sorting this out!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/mhng-3008635e-9a78-413a-8b99-d20a14c5494b%40palmerdabbelt-glaptop.
