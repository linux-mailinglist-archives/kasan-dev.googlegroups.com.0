Return-Path: <kasan-dev+bncBDHPTCWTXEHRBX4V7OGAMGQETCR3GQQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13b.google.com (mail-lf1-x13b.google.com [IPv6:2a00:1450:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id 1A6BB45D139
	for <lists+kasan-dev@lfdr.de>; Thu, 25 Nov 2021 00:29:36 +0100 (CET)
Received: by mail-lf1-x13b.google.com with SMTP id k32-20020a0565123da000b0041643c6a467sf2151828lfv.5
        for <lists+kasan-dev@lfdr.de>; Wed, 24 Nov 2021 15:29:36 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1637796575; cv=pass;
        d=google.com; s=arc-20160816;
        b=Z/dQuBzqkdgZSb3UEEAPvNMs90x65M3/p+9uW0stGhZ8Kd39cLIbfzlktky1GOfhG0
         6n/Ns9YdOpiwU1jBAkEOyhyRK4DLAoo8eJzfzhxHI/kqwt9sprDg5P6i/vxxH7v2MwUa
         DY+PLUf/Q5vdCjNYLKRBqBovxpWhsk0XqiXSkGFW7k3Sx4BluFu+bunSgh96npZAqTsQ
         frcU68cEcLUlX6hyHmiHDQ/7vMPKJLck/6XiYOTsMdCaXFtbnou3ZeuqsN9P7DAiBlPE
         Jc2s0XUSp3fXp+qbUm06kXjIDYlAXC3MnUS6pOMyxYy/aIKhvO1JFkrLun3QF8qduzmJ
         4Nyw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=gYSJdtSeufl8IYknZEvEy+eYdoWSafPXgE1+wxG6c1c=;
        b=bbqKJSvTxN7sSESGuuS0K05HcX8Z0ht754Ejb57fmk+VLhmMqtL8QyzIZtlA6iK/vC
         0M0YFvJ/NVfx8cXBpP3ypfpqYkRGSus+r7tuqiam1XuLfJEBxSmgWSukBUKAlbogYERW
         lCl6Bpk7SNm7G4eRiThD8gE+vRNVbGnYB2lU91cKmvFoeDK0Uiq457qgo6YJcGD/G3I2
         lMFtYG990e/UUkyrXic1a5Uco0UsRTiD02/UbvX0IGxUL84LtJF1iusRboXRaBYtSnuN
         P0xTGMZ1hrLdIIKxzcITaWxbuj/FbYULQxrgw6FavQBewXmSxcwK++9eMI5tkImIi6Ae
         KVHA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: best guess record for domain of heiko@sntech.de designates 185.11.138.130 as permitted sender) smtp.mailfrom=heiko@sntech.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=gYSJdtSeufl8IYknZEvEy+eYdoWSafPXgE1+wxG6c1c=;
        b=ko1F9BCB+VV3FEq3EFFjqlJ8H7oXp/63Z4l4SFeQmtVUTeRxDtD+vPXwAO1s0v93PC
         wO2byWkWY/mw3CX94kYQCqnxRUeVtpLq1HWBoafmbAr3vEepzV1TvaOIxJJctsL2sKLm
         WsLlVA1Jfrnt2JMcijxM/1XT4j+is2B24To0EzTzJfIHREp2ZKqX26sqYyYDUuipdD0C
         EiDbjPipBsPnUoetLR4N9LQ0uwd6NDNGEXbnttHpAT18OCwg9cBHt01dTKGirren4Y+f
         0qOK0ROpjwG8IKyEAhVWNGFXpaz57YcB/wRnFdj5Mcp7Sa5hvJ5fjtpv+KigmEYEnYQm
         CW5A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=gYSJdtSeufl8IYknZEvEy+eYdoWSafPXgE1+wxG6c1c=;
        b=35FgS4uqTbEol4fFCdVPIzpGV3QutkditQ7hZ4fYmmVJItWPhXgPZt1Oh1AI8rcNvS
         GNE9+Ot0cUY26RazOxu2xs0APuheM8U+l0nXQZaI8hboiCjpldzz/Qd/EV9tXPjOFvu4
         tweyR/xgXv+pQv4E8tBlMMz0uUmEh30S+1aPrHgDe11Ps49io6/YGWE5A7+Jy5zDMOHS
         /JQsiy5kdXkYRVrI3xnGj4CBuN8dRGJ+BDmYITwf/uyNSwHqqYYAtnnqPXXY+9ixEXUN
         41TmDHkIkxV2edoAyGn8itHfjq5leqKGb+yZt2Lr3TSlU/OLqjdb9AZJhleZzZa7/+k3
         wZHg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530qvy7mbk3t9lC8bdPI5ZRFoMXmxgHpyw7KGDrZ/INpDf3wtESt
	XVCrzr9/2VK/T7fkNVz68FU=
X-Google-Smtp-Source: ABdhPJyiWmJoj08mw8h/KicsyDG8I0OzTsL92yOs5RYx3InC92Hf85M0mnLQCiiQdmrqzLwdjSpLvQ==
X-Received: by 2002:a05:6512:3324:: with SMTP id l4mr18078240lfe.302.1637796575614;
        Wed, 24 Nov 2021 15:29:35 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:8946:: with SMTP id b6ls214922ljk.7.gmail; Wed, 24 Nov
 2021 15:29:34 -0800 (PST)
X-Received: by 2002:a2e:b8d0:: with SMTP id s16mr19995474ljp.496.1637796574656;
        Wed, 24 Nov 2021 15:29:34 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1637796574; cv=none;
        d=google.com; s=arc-20160816;
        b=c39ykFT9/aXxIulhSlQ0yoN4fBsoa8Gc91lpoPSBmHh6u6R89r5ckYxSNcbss8DK0V
         QXHw81nMvO0wuPFhGiyXrNgZ2frmLMtqcZD2h2u2kZHwiJIVrSVzkEk3D2dBxqDuwqrQ
         uUFZNWxQwhe9/Wiwf2RUdboMFKY8cqEy0EKmg52tv+zzSoB6jFgCUNFLK7UUpn6V4Ezj
         dx10bbuFN8rHoYy5i4mxBLd3XWJns0AxpCb6OZOi/sohaCSioU5MAVsOOG3mlA5u5qyc
         JUv36S/pFrIVcF3+AafM+mF5XPAD7dKjEk2JiLQp0J83JNvAtiI1/nnOd4C1bgl5bhtC
         aqFw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=hNFUCosX+/jaAd9PA0q3U2BX0aSGt2Co6EW/vR8a0A4=;
        b=b2ySJnF9pWCPlRjyOlIHceGNTsg2Pf7/Kxq5z2y/UryRpSDKYuQnaJze2uTDxSCBv9
         sWUsx3CH0SCo42fLin3Bv077rNA0UK+wwBWpwWXUK2dvO9xG3MMqE1phLF8BR0ezR7b8
         HiaykN8L6qBUdF0iobJRLRuTSaXpKRxhlTgcMwWmHD3h1BskmD59S6tW8pxrqj3nzCXL
         zoVzAi4JgGLEDkCqY/B8NGQD8VxPNePptNQ85mShzu9NWUwVDLjha4gWvOlQxOcTY5aB
         YJpeVb0VjGH2S4evEila1RyekejSUaZjp6oK2gJjcuSjXKQiKG0CSlwa7l0NQ7niFLBu
         QlUA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: best guess record for domain of heiko@sntech.de designates 185.11.138.130 as permitted sender) smtp.mailfrom=heiko@sntech.de
Received: from gloria.sntech.de (gloria.sntech.de. [185.11.138.130])
        by gmr-mx.google.com with ESMTPS id e19si137944lfr.9.2021.11.24.15.29.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 24 Nov 2021 15:29:34 -0800 (PST)
Received-SPF: pass (google.com: best guess record for domain of heiko@sntech.de designates 185.11.138.130 as permitted sender) client-ip=185.11.138.130;
Received: from ip5f5b2004.dynamic.kabel-deutschland.de ([95.91.32.4] helo=diego.localnet)
	by gloria.sntech.de with esmtpsa (TLS1.3:ECDHE_RSA_AES_256_GCM_SHA384:256)
	(Exim 4.92)
	(envelope-from <heiko@sntech.de>)
	id 1mq1ha-0000eP-BH; Thu, 25 Nov 2021 00:29:22 +0100
From: Heiko =?ISO-8859-1?Q?St=FCbner?= <heiko@sntech.de>
To: Jonathan Corbet <corbet@lwn.net>, Paul Walmsley <paul.walmsley@sifive.com>, Palmer Dabbelt <palmer@dabbelt.com>, Albert Ou <aou@eecs.berkeley.edu>, Zong Li <zong.li@sifive.com>, Anup Patel <anup@brainfault.org>, Atish Patra <Atish.Patra@wdc.com>, Christoph Hellwig <hch@lst.de>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, Ard Biesheuvel <ardb@kernel.org>, Arnd Bergmann <arnd@arndb.de>, Kees Cook <keescook@chromium.org>, Guo Ren <guoren@linux.alibaba.com>, Heinrich Schuchardt <heinrich.schuchardt@canonical.com>, Mayuresh Chitale <mchitale@ventanamicro.com>, linux-doc@vger.kernel.org, linux-riscv@lists.infradead.org, linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com, linux-efi@vger.kernel.org, linux-arch@vger.kernel.org, Alexandre Ghiti <alexandre.ghiti@canonical.com>
Cc: Alexandre Ghiti <alexandre.ghiti@canonical.com>
Subject: Re: [PATCH v2 00/10] Introduce sv48 support without relocatable kernel
Date: Thu, 25 Nov 2021 00:29:20 +0100
Message-ID: <2700575.YIZvDWadBg@diego>
In-Reply-To: <20210929145113.1935778-1-alexandre.ghiti@canonical.com>
References: <20210929145113.1935778-1-alexandre.ghiti@canonical.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: heiko@sntech.de
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: best guess record for domain of heiko@sntech.de designates
 185.11.138.130 as permitted sender) smtp.mailfrom=heiko@sntech.de
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

Am Mittwoch, 29. September 2021, 16:51:03 CET schrieb Alexandre Ghiti:
> This patchset allows to have a single kernel for sv39 and sv48 without           
> being relocatable.                                                               
>                                                                                  
> The idea comes from Arnd Bergmann who suggested to do the same as x86,           
> that is mapping the kernel to the end of the address space, which allows         
> the kernel to be linked at the same address for both sv39 and sv48 and           
> then does not require to be relocated at runtime.                                
>                                                                                  
> This implements sv48 support at runtime. The kernel will try to                  
> boot with 4-level page table and will fallback to 3-level if the HW does not     
> support it. Folding the 4th level into a 3-level page table has almost no        
> cost at runtime.                                                                 
>                                                                                  
> Tested on:                                                                       
>   - qemu rv64 sv39: OK                                                           
>   - qemu rv64 sv48: OK                                                           
>   - qemu rv64 sv39 + kasan: OK                                                   
>   - qemu rv64 sv48 + kasan: OK                                                   
>   - qemu rv32: OK                                                                
>   - Unmatched: OK

On a beagleV (which supports only sv39) I've tested both the limit via
the mmu-type in the devicetree and also that the fallback works when
I disable the mmu-type in the dt, so

Tested-by: Heiko Stuebner <heiko@sntech.de>

>   
>                                                                                  
> Changes in v2:                                                                   
>   - Rebase onto for-next                                                         
>   - Fix KASAN                                                                    
>   - Fix stack canary                                                             
>   - Get completely rid of MAXPHYSMEM configs                                     
>   - Add documentation
> 
> Alexandre Ghiti (10):
>   riscv: Allow to dynamically define VA_BITS
>   riscv: Get rid of MAXPHYSMEM configs
>   asm-generic: Prepare for riscv use of pud_alloc_one and pud_free
>   riscv: Implement sv48 support
>   riscv: Use pgtable_l4_enabled to output mmu_type in cpuinfo
>   riscv: Explicit comment about user virtual address space size
>   riscv: Improve virtual kernel memory layout dump
>   Documentation: riscv: Add sv48 description to VM layout
>   riscv: Initialize thread pointer before calling C functions
>   riscv: Allow user to downgrade to sv39 when hw supports sv48
> 
>  Documentation/riscv/vm-layout.rst             |  36 ++
>  arch/riscv/Kconfig                            |  35 +-
>  arch/riscv/configs/nommu_k210_defconfig       |   1 -
>  .../riscv/configs/nommu_k210_sdcard_defconfig |   1 -
>  arch/riscv/configs/nommu_virt_defconfig       |   1 -
>  arch/riscv/include/asm/csr.h                  |   3 +-
>  arch/riscv/include/asm/fixmap.h               |   1 +
>  arch/riscv/include/asm/kasan.h                |   2 +-
>  arch/riscv/include/asm/page.h                 |  10 +
>  arch/riscv/include/asm/pgalloc.h              |  40 +++
>  arch/riscv/include/asm/pgtable-64.h           | 108 +++++-
>  arch/riscv/include/asm/pgtable.h              |  30 +-
>  arch/riscv/include/asm/sparsemem.h            |   6 +-
>  arch/riscv/kernel/cpu.c                       |  23 +-
>  arch/riscv/kernel/head.S                      |   4 +-
>  arch/riscv/mm/context.c                       |   4 +-
>  arch/riscv/mm/init.c                          | 323 +++++++++++++++---
>  arch/riscv/mm/kasan_init.c                    |  91 +++--
>  drivers/firmware/efi/libstub/efi-stub.c       |   2 +
>  include/asm-generic/pgalloc.h                 |  24 +-
>  include/linux/sizes.h                         |   1 +
>  21 files changed, 615 insertions(+), 131 deletions(-)
> 
> 




-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/2700575.YIZvDWadBg%40diego.
