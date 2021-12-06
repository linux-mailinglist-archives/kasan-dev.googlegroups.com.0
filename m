Return-Path: <kasan-dev+bncBC447XVYUEMRBKW6W6GQMGQEBPMWKII@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43a.google.com (mail-wr1-x43a.google.com [IPv6:2a00:1450:4864:20::43a])
	by mail.lfdr.de (Postfix) with ESMTPS id 2480E4694BF
	for <lists+kasan-dev@lfdr.de>; Mon,  6 Dec 2021 12:08:27 +0100 (CET)
Received: by mail-wr1-x43a.google.com with SMTP id f3-20020a5d50c3000000b00183ce1379fesf1918592wrt.5
        for <lists+kasan-dev@lfdr.de>; Mon, 06 Dec 2021 03:08:27 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1638788907; cv=pass;
        d=google.com; s=arc-20160816;
        b=o2klIu4oA/C4AZHE9CIryLmXGIbfX0HlbHkQJyzGCgNxjEa0IqU5LLNKq5Bd08+2PQ
         yAxpc2jDOnLYjU0PaoT2a50AKHffW1rV19TJ52ODxgJe3DcALeMkKH9f2QiOirdlVWV8
         HfGMKbjjT5OKA7cTyW4Y16pWU3Z9gOklM9pNL92xSEVZJMu4rGk58Odrm/nu/yi5tflN
         7/QBteNmB+fQ7UeMmCIt1TQ4lPZbnPL+iVW3KqHtEiaIkWVRtGNx/8PSUm5XFq/lDJ4x
         vB6XF+uEouZd0aDaY+QyDT2PlkRirDkJ47SoEV2g0fZUar8Mwbo8WnKQFgFKUTewhhaa
         CmUg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:references:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=0K9w6rcY2KkG3qkMgK9CbNQVdZ3EU1/OOrz/or2k4iU=;
        b=WRjCp7cIHusQ+QHjtRTOBS4Fbd5rjfcVgQX3FUTlodT9SyFnFjcKUWXtobNbeWILQg
         j4Ztm8yj39Aa5KGHjruet607SRPM28a+Un1UFLyjORLDPbbcl8RR7H7D94O8pBKbx/L6
         uSeqc8CZPb/cz6FIkf5sUZ5MJjiIvJgIQKQqQQegP6PQDwMC1baW1VLXfIeVlxOXyxv3
         vrLmHnbrdUDwfaYLSF1h/Tmp6b1CJx26wwMeGeHHs5M0O/3d9qfXewaFfWULG6+d7LE6
         j7VddA/vnPcJ+pssWPaZbAHCF8ehFO5ljyINzyei5iEqSMlAd2rVAXwRH/iVFbuC/u+6
         ksSw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=neutral (google.com: 217.70.183.196 is neither permitted nor denied by best guess record for domain of alex@ghiti.fr) smtp.mailfrom=alex@ghiti.fr
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:message-id:date:mime-version:user-agent:subject
         :content-language:to:references:from:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=0K9w6rcY2KkG3qkMgK9CbNQVdZ3EU1/OOrz/or2k4iU=;
        b=IEQDzZNCtKCCLDKt6HoBoynUhmNt1HiAGgdkiIi4lJIedhXPh0xE7VK1jZ6bj+gsLB
         jtTJzfjT6+vwyDKvjv1r0915mnm0GCbp+5uv0vrD+ZFoTvW6stAy9mnW8QEOXSw/eHHC
         AIzBd+1xglce596CHOj3tfJad4uYYdS5qry1QlhjsiGmiBLh0q62K6Hu5ui+sg9XN4FD
         J3FVQnbmxik7gS7Jax767FeRy0ce6jSGlCRb83BMtGYN4T+FNrZYjrl11oRaUy9BYLtp
         waT/gW2RF/fhIWsqQ5QW8CkHWwA8HB6ADpEETzpRM26Xrj84RZF/ByxS+Bdkw0Zaf+AC
         mgng==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:message-id:date:mime-version:user-agent
         :subject:content-language:to:references:from:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=0K9w6rcY2KkG3qkMgK9CbNQVdZ3EU1/OOrz/or2k4iU=;
        b=B71C00ogcEfDs59E3ClUxZxx9BnzrhieAmEdcdLBBV+dkVI0XUnfI7rUk4Cc5s97+o
         Go9+ceEGoakFlPBjGbD2qLSVJQpKowgUKK7n5AlgTsBlZ83wcVR8fLukrltsTZ7Uy4w+
         S1no5m3y8YMPNIlaEMNcsAv+Q1aXAtVGvEW0X4/5cLIQEGRHePxtkXNth0Voaiq/FhLM
         nKWU+TnCYAjdNxlHEMtcUiNSxLEgYnIf99C83iXsXKo5yLpFar/ZD7nysNoVfTY6f93+
         z2f02SfHzzScOL5g/1pV6oMA5l/epEyZf1kvuF6ltG4lc6zeMYMlQXZTNXy6O5nc/vjG
         fxKA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530yyWwrOzNDFZZlLZjfzzJZQJI1YqkJGYi/bqYJdaPbO+Tef6WU
	/lBDv1Gs4ZR5qbTVPNVZyrw=
X-Google-Smtp-Source: ABdhPJw3/M7WsCQXyZAK5Nd2y7yGSQwaRZNT+tXvL89ftO9Aqt8MyT3KG7FnLD8cSgCkA12EUVyFkw==
X-Received: by 2002:a5d:480c:: with SMTP id l12mr42941528wrq.518.1638788906899;
        Mon, 06 Dec 2021 03:08:26 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:fe0b:: with SMTP id n11ls408580wrr.0.gmail; Mon, 06 Dec
 2021 03:08:26 -0800 (PST)
X-Received: by 2002:a5d:68ce:: with SMTP id p14mr41583895wrw.116.1638788906184;
        Mon, 06 Dec 2021 03:08:26 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1638788906; cv=none;
        d=google.com; s=arc-20160816;
        b=QxVDQBWy9zg6nTwAsmK3RdowuVo/9z0yHYelGJz6y6jZEVdvq0lnMOqyCHY4kHGndp
         YFzEmkWvTYHi7VxZjqDwUtaLZpsU2TRl01d5rByZcwIOWucnNNjHV2eNrTg+EwCVIAsW
         CSXPILiF3ktCpI4W7xV0M9msVcaTTY7sVxuOFAuaKc5TBorgOkPvhoJxs+L8SIPiETUF
         2mjRmVhRj7nSmqBCclALHgu8KSfHMDtpr2Ocpx/+BBfwxhbEkjFKuzccjEfkq+vPPgK7
         WxkU7531hUk3iKcJRgYGHgRt/8lypIohU567/VAEd6RBIQjG0KUff9sFjNVp1LUrQNO2
         v5WA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:to
         :content-language:subject:user-agent:mime-version:date:message-id;
        bh=ku02e4xfgpbxvF7h82cgqrZVaVwST2lWtMq7X4D9WZQ=;
        b=v0owNJkzAoO7BO7VuBm9WgRA4MLEfNvz3Hg4YcPOjF1sFEhLctQgSO5rNG4RrH1B4B
         vk7NvhEzUXrGmIOrmkwmLTARnTpzgOivDiYfEGrSqRzscnOcVSsKlK+s0s8V3T9qxbTd
         cvGIMB3FsazHjm0yuYY3Q/YNuErlelqNxP4XzQT2V5DzLSn6beS2wbboUeKYGJ+w56PP
         x0rpjPYaKrpthGp2LCqmI1qfDj1DHBbPZPJZTUO3yNbXfwJ7aogdRSXzV8LGDxgc4Zfw
         S6ozF89XKtF1Kd5psgoVHo3d50sKo3RoYDfiDFnw9K4aaR44snS61dsb4/HK+++jfR7G
         cAYg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=neutral (google.com: 217.70.183.196 is neither permitted nor denied by best guess record for domain of alex@ghiti.fr) smtp.mailfrom=alex@ghiti.fr
Received: from relay4-d.mail.gandi.net (relay4-d.mail.gandi.net. [217.70.183.196])
        by gmr-mx.google.com with ESMTPS id a1si668132wrv.4.2021.12.06.03.08.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 06 Dec 2021 03:08:26 -0800 (PST)
Received-SPF: neutral (google.com: 217.70.183.196 is neither permitted nor denied by best guess record for domain of alex@ghiti.fr) client-ip=217.70.183.196;
Received: (Authenticated sender: alex@ghiti.fr)
	by relay4-d.mail.gandi.net (Postfix) with ESMTPSA id ECAD0E0018;
	Mon,  6 Dec 2021 11:08:19 +0000 (UTC)
Message-ID: <ae3be66c-755a-b068-e224-08cd733c53e1@ghiti.fr>
Date: Mon, 6 Dec 2021 12:08:19 +0100
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101
 Thunderbird/91.3.1
Subject: Re: [PATCH v3 00/13] Introduce sv48 support without relocatable
 kernel
Content-Language: en-US
To: Alexandre Ghiti <alexandre.ghiti@canonical.com>,
 Jonathan Corbet <corbet@lwn.net>, Paul Walmsley <paul.walmsley@sifive.com>,
 Palmer Dabbelt <palmer@dabbelt.com>, Albert Ou <aou@eecs.berkeley.edu>,
 Zong Li <zong.li@sifive.com>, Anup Patel <anup@brainfault.org>,
 Atish Patra <Atish.Patra@rivosinc.com>, Christoph Hellwig <hch@lst.de>,
 Andrey Ryabinin <ryabinin.a.a@gmail.com>,
 Alexander Potapenko <glider@google.com>,
 Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>,
 Ard Biesheuvel <ardb@kernel.org>, Arnd Bergmann <arnd@arndb.de>,
 Kees Cook <keescook@chromium.org>, Guo Ren <guoren@linux.alibaba.com>,
 Heinrich Schuchardt <heinrich.schuchardt@canonical.com>,
 Mayuresh Chitale <mchitale@ventanamicro.com>, panqinglin2020@iscas.ac.cn,
 linux-doc@vger.kernel.org, linux-riscv@lists.infradead.org,
 linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com,
 linux-efi@vger.kernel.org, linux-arch@vger.kernel.org
References: <20211206104657.433304-1-alexandre.ghiti@canonical.com>
From: Alexandre ghiti <alex@ghiti.fr>
In-Reply-To: <20211206104657.433304-1-alexandre.ghiti@canonical.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Original-Sender: alex@ghiti.fr
X-Original-Authentication-Results: gmr-mx.google.com;       spf=neutral
 (google.com: 217.70.183.196 is neither permitted nor denied by best guess
 record for domain of alex@ghiti.fr) smtp.mailfrom=alex@ghiti.fr
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

And I messed Atish address, I was pretty sure I could recall it without 
checking, I guess I'm wrong :)

Sorry for the noise,

Alex

On 12/6/21 11:46, Alexandre Ghiti wrote:
> * Please note notable changes in memory layouts and kasan population *
>
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
> Note that kasan region had to be moved to the end of the address space
> since its location must be known at compile-time and then be valid for
> both sv39 and sv48 (and sv57 that is coming).
>
> Tested on:
>    - qemu rv64 sv39: OK
>    - qemu rv64 sv48: OK
>    - qemu rv64 sv39 + kasan: OK
>    - qemu rv64 sv48 + kasan: OK
>    - qemu rv32: OK
>
> Changes in v3:
>    - Fix SZ_1T, thanks to Atish
>    - Fix warning create_pud_mapping, thanks to Atish
>    - Fix k210 nommu build, thanks to Atish
>    - Fix wrong rebase as noted by Samuel
>    - * Downgrade to sv39 is only possible if !KASAN (see commit changelog) *
>    - * Move KASAN next to the kernel: virtual layouts changed and kasan population *
>
> Changes in v2:
>    - Rebase onto for-next
>    - Fix KASAN
>    - Fix stack canary
>    - Get completely rid of MAXPHYSMEM configs
>    - Add documentation
>
> Alexandre Ghiti (13):
>    riscv: Move KASAN mapping next to the kernel mapping
>    riscv: Split early kasan mapping to prepare sv48 introduction
>    riscv: Introduce functions to switch pt_ops
>    riscv: Allow to dynamically define VA_BITS
>    riscv: Get rid of MAXPHYSMEM configs
>    asm-generic: Prepare for riscv use of pud_alloc_one and pud_free
>    riscv: Implement sv48 support
>    riscv: Use pgtable_l4_enabled to output mmu_type in cpuinfo
>    riscv: Explicit comment about user virtual address space size
>    riscv: Improve virtual kernel memory layout dump
>    Documentation: riscv: Add sv48 description to VM layout
>    riscv: Initialize thread pointer before calling C functions
>    riscv: Allow user to downgrade to sv39 when hw supports sv48 if !KASAN
>
>   Documentation/riscv/vm-layout.rst             |  48 ++-
>   arch/riscv/Kconfig                            |  37 +-
>   arch/riscv/configs/nommu_k210_defconfig       |   1 -
>   .../riscv/configs/nommu_k210_sdcard_defconfig |   1 -
>   arch/riscv/configs/nommu_virt_defconfig       |   1 -
>   arch/riscv/include/asm/csr.h                  |   3 +-
>   arch/riscv/include/asm/fixmap.h               |   1
>   arch/riscv/include/asm/kasan.h                |  11 +-
>   arch/riscv/include/asm/page.h                 |  20 +-
>   arch/riscv/include/asm/pgalloc.h              |  40 ++
>   arch/riscv/include/asm/pgtable-64.h           | 108 ++++-
>   arch/riscv/include/asm/pgtable.h              |  47 +-
>   arch/riscv/include/asm/sparsemem.h            |   6 +-
>   arch/riscv/kernel/cpu.c                       |  23 +-
>   arch/riscv/kernel/head.S                      |   4 +-
>   arch/riscv/mm/context.c                       |   4 +-
>   arch/riscv/mm/init.c                          | 408 ++++++++++++++----
>   arch/riscv/mm/kasan_init.c                    | 250 ++++++++---
>   drivers/firmware/efi/libstub/efi-stub.c       |   2
>   drivers/pci/controller/pci-xgene.c            |   2 +-
>   include/asm-generic/pgalloc.h                 |  24 +-
>   include/linux/sizes.h                         |   1
>   22 files changed, 833 insertions(+), 209 deletions(-)
>
> --
> 2.32.0
>
>
> _______________________________________________
> linux-riscv mailing list
> linux-riscv@lists.infradead.org
> http://lists.infradead.org/mailman/listinfo/linux-riscv

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ae3be66c-755a-b068-e224-08cd733c53e1%40ghiti.fr.
