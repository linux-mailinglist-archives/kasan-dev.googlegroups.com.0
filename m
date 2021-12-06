Return-Path: <kasan-dev+bncBDHPTCWTXEHRBSHCW6GQMGQEQHZOZAA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3f.google.com (mail-io1-xd3f.google.com [IPv6:2607:f8b0:4864:20::d3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 51E2E4694DE
	for <lists+kasan-dev@lfdr.de>; Mon,  6 Dec 2021 12:17:30 +0100 (CET)
Received: by mail-io1-xd3f.google.com with SMTP id s199-20020a6b2cd0000000b005ed3e776ad0sf8076960ios.18
        for <lists+kasan-dev@lfdr.de>; Mon, 06 Dec 2021 03:17:30 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1638789449; cv=pass;
        d=google.com; s=arc-20160816;
        b=tnQyI/66dbcoqJDwEWx/I94sjUf1HnVDZO6yKOqBzLtnrOnSqmET8xi/MEUkYf69/y
         pkTKZMynYv8IVJGBfBAgoseWQ8lwMjxFj40eBA75/d0BtTlERsHGwmStfLHphhLtRCTf
         RtScPBfZZJidRga4jsyD13BcH/FYxYNWrR7jLqoqG1BxtF4D7r+jays06FuyYm//Ouli
         dXqa1pvpBQkiXHkF08PNoqAbpx3x2oC5o3nmVGRG6DtGDC4/Z30WUuhpVMvzLSjEtMUc
         RdzvgfIRyRTTQrVNR808SfV4/zNDNsQOyUEU+uTwVNtfKxkk9M3bQQFVLAjy/2n4Opo9
         aaEQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :mime-version:references:in-reply-to:message-id:date:subject:cc:to
         :from:sender:dkim-signature;
        bh=cnbA4hkG3DjsQUjHG0pIkohl8yJNOh+8w2BKfizAq50=;
        b=uZfayzMB6IFce1kk3uutR77fejpawU3OQkK7d3yc5H+c9sy0mr7/Pgn7Z+wozfDCdx
         kRxl5TQNUX3lCAKUzRIvmJvGrfGTygBQ6j3lXSncy6fqrtfOAttuuv2r0L0hL2ymHH34
         H3K49YIYmxf59F8QJnQdlOiEsXLUOWZ3Wg/uXovvKLUANXATqf3dzULPyUZEeiZunvcg
         kIOuZs9VMnhY/lNVU3iGyvroY/fI+Th6mROP5Rwbw2+4RKvG8kFGK6PxAN3Zk2yONOJH
         0eUy7e290pxnO35bO/pyJ45AU0JXb48El73RZI6YQntpMrqRZo0DO/6ZrAbHzx7P+sZ9
         ZCvg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: best guess record for domain of heiko@sntech.de designates 185.11.138.130 as permitted sender) smtp.mailfrom=heiko@sntech.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=cnbA4hkG3DjsQUjHG0pIkohl8yJNOh+8w2BKfizAq50=;
        b=UP0q6CkjlqEwBWdzsdMZXJ0VkDaQfexUhYLHyVluJzouZT5vfSzr5zRjR+X2OwZO3f
         8hTjyJX9duYdOY0g5cYeT/6FPlDREGpPqmb+vYkAyr/R8rqFDouaAbE/04AXCAYRPcHn
         FSqXo1+lKlHHh8O9aau9nzXDq3RroIWfbHCt/IOqOBhqADKCjWzMqGQSL8gdRrk7WemD
         5sLhJwjgBAhofNwRdvmfkkBUnyOP0O5EcMaHwWvtCM4s+yBscLbRO6M7e7Dg7oa0vQqW
         6iQWaCWLIOOnTVybtsd90EWtuA2Tfv44NYGULsj1e8pQaLvm2XfkrFb0k/5oeUeqUY5F
         VqZQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=cnbA4hkG3DjsQUjHG0pIkohl8yJNOh+8w2BKfizAq50=;
        b=mZdGtrgE79RMoLLSAAyCpi6VWBCpu8pSths+MztLGSCK8dvpTk+dgZzUE/ycDnabT4
         MJJKUuGQN+LtWnoZO+Sad3IA3i00TAXeXQMlaaUOuKSmHd6B5XS1awMF2bi6N0A26o7T
         OrVwjDrKUhbJlcIqDOgsBtx+tZor+fXOiPszrUgBYuCGnY6xWpTIR3itO37FFppjz/Pb
         65VRV5bqgkz+N5VlEjJ4C70sURU2x/9+8SksRcCBT4PaH/4p1+0MGHNRSk0b5WLC0u9O
         5kZ3OrhtW5hgd64axIVhWidUg1DApPpuJjK3iCDlZJFrh/hnGe9p7oQ4DU3TGIKrYwNw
         3uZQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530bcBHLNtYG3lA5XtfJGdyVklnW78XFxAXKg4WAJlyZGmJNFJ8g
	ag1aWBzJjALZgkrF11/4i2k=
X-Google-Smtp-Source: ABdhPJzlfIEmYFllm6Sh4cVAcxr/DQEi0jE2RjQX5seJaesYyEWhwYfSOjxN72n34SqDRc+Q3zl8qg==
X-Received: by 2002:a05:6e02:1be5:: with SMTP id y5mr29358721ilv.8.1638789448958;
        Mon, 06 Dec 2021 03:17:28 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:9358:: with SMTP id i24ls1988839ioo.4.gmail; Mon, 06 Dec
 2021 03:17:28 -0800 (PST)
X-Received: by 2002:a05:6602:2acc:: with SMTP id m12mr31584341iov.107.1638789448672;
        Mon, 06 Dec 2021 03:17:28 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1638789448; cv=none;
        d=google.com; s=arc-20160816;
        b=yzAXh9Q9VU15iWkFMZWMteHSPXmQEXQhcPHsX4VxGMIolEithpw6jyuTWBa6DseI23
         e7C7zKJEiZGEeh3eq8H1zA6dHvM344qABidhoo6pUo15amFXTGfiyqwlAyBwOYQ6AfBa
         W1kjbJt7EyqYst8XdKoxX35VcMNSy7IrMaoDVzdszgfHdwgJ8qjK0XKWsji4BKcWjrRM
         7Lqn0JiN2n9BrIoyTn/s/e491wQIQOD6wOkBAcfVkcyhr5TbY4juGtEORgHhfqy2ndEL
         NcUjrTS1Cnsudmek7snqGQ/ZuQ6uv4aK8G6y1wlnr1XrkvBm+75CCKCyTuxBBeIzEVlW
         XYeA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=yb2qTjxtWUreQ1kbT356c+DT2h0IZ8MA2z19Rj4gdJg=;
        b=M5vueQgZZ6H2FURVWO7IIUlQasEA+AmQC5kDWOn78cnhrND6JOeuwS+SwP6B/15Zs2
         Zqm5gcJinQNuLlq5VPWTk2Kw+lfoOdLmqSJtnPbNi4az5MeDkCciAEhNRJI7FpH6Wa72
         J/X0sRkeYjLVRYfv1u38cKqdd0MogxkQcKmfxGMYwrrZE1ux7PfLxMwk0r313AdArV/U
         gu/mX3cM1vD+gCnXcVbuZo005cDxk76irozsiZPYizc9+kyroJRXvyt59bgCJ+VAkVUj
         pelSt/eFc2HtCEG8002UvwSdeEjIvtDxLW4Bbo5Q+UcUcLUI5nx/YfZfOARqLVyt8MGB
         jOaw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: best guess record for domain of heiko@sntech.de designates 185.11.138.130 as permitted sender) smtp.mailfrom=heiko@sntech.de
Received: from gloria.sntech.de (gloria.sntech.de. [185.11.138.130])
        by gmr-mx.google.com with ESMTPS id a15si2117845ilv.2.2021.12.06.03.17.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 06 Dec 2021 03:17:28 -0800 (PST)
Received-SPF: pass (google.com: best guess record for domain of heiko@sntech.de designates 185.11.138.130 as permitted sender) client-ip=185.11.138.130;
Received: from [77.23.162.171] (helo=diego.localnet)
	by gloria.sntech.de with esmtpsa (TLS1.3:ECDHE_RSA_AES_256_GCM_SHA384:256)
	(Exim 4.92)
	(envelope-from <heiko@sntech.de>)
	id 1muBzU-0003Gp-KA; Mon, 06 Dec 2021 12:17:04 +0100
From: Heiko =?ISO-8859-1?Q?St=FCbner?= <heiko@sntech.de>
To: Jonathan Corbet <corbet@lwn.net>, Paul Walmsley <paul.walmsley@sifive.com>, Palmer Dabbelt <palmer@dabbelt.com>, Albert Ou <aou@eecs.berkeley.edu>, Zong Li <zong.li@sifive.com>, Anup Patel <anup@brainfault.org>, Atish Patra <Atish.Patra@wdc.com>, Christoph Hellwig <hch@lst.de>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, Ard Biesheuvel <ardb@kernel.org>, Arnd Bergmann <arnd@arndb.de>, Kees Cook <keescook@chromium.org>, Guo Ren <guoren@linux.alibaba.com>, Heinrich Schuchardt <heinrich.schuchardt@canonical.com>, Mayuresh Chitale <mchitale@ventanamicro.com>, linux-doc@vger.kernel.org, linux-riscv@lists.infradead.org, linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com, linux-efi@vger.kernel.org, linux-arch@vger.kernel.org, Alexandre Ghiti <alexandre.ghiti@canonical.com>
Cc: Alexandre ghiti <alex@ghiti.fr>
Subject: Re: [PATCH v2 00/10] Introduce sv48 support without relocatable kernel
Date: Mon, 06 Dec 2021 12:17:02 +0100
Message-ID: <16228030.BXmPpbjjvJ@diego>
In-Reply-To: <3283761f-0506-464b-d351-af8ddecafa9b@ghiti.fr>
References: <20210929145113.1935778-1-alexandre.ghiti@canonical.com> <2700575.YIZvDWadBg@diego> <3283761f-0506-464b-d351-af8ddecafa9b@ghiti.fr>
MIME-Version: 1.0
Content-Transfer-Encoding: quoted-printable
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

Am Montag, 6. Dezember 2021, 11:49:55 CET schrieb Alexandre ghiti:
> On 11/25/21 00:29, Heiko St=C3=BCbner wrote:
> > Am Mittwoch, 29. September 2021, 16:51:03 CET schrieb Alexandre Ghiti:
> >> This patchset allows to have a single kernel for sv39 and sv48 without
> >> being relocatable.
> >>                                                                       =
           =20
> >> The idea comes from Arnd Bergmann who suggested to do the same as x86,
> >> that is mapping the kernel to the end of the address space, which allo=
ws
> >> the kernel to be linked at the same address for both sv39 and sv48 and
> >> then does not require to be relocated at runtime.
> >>                                                                       =
           =20
> >> This implements sv48 support at runtime. The kernel will try to
> >> boot with 4-level page table and will fallback to 3-level if the HW do=
es not
> >> support it. Folding the 4th level into a 3-level page table has almost=
 no
> >> cost at runtime.
> >>                                                                       =
           =20
> >> Tested on:
> >>    - qemu rv64 sv39: OK
> >>    - qemu rv64 sv48: OK
> >>    - qemu rv64 sv39 + kasan: OK
> >>    - qemu rv64 sv48 + kasan: OK
> >>    - qemu rv32: OK
> >>    - Unmatched: OK
> > On a beagleV (which supports only sv39) I've tested both the limit via
> > the mmu-type in the devicetree and also that the fallback works when
> > I disable the mmu-type in the dt, so
> >
> > Tested-by: Heiko Stuebner <heiko@sntech.de>
> >
>=20
> Thanks Heiko for testing this, unfortunately I could not add this tag to=
=20
> the latest version as significant changes came up.
>=20
> Thanks again for taking the time to test this,

No worries, I can repeat that with your new version :-)

Heiko


> >>   =20
> >>                                                                       =
           =20
> >> Changes in v2:
> >>    - Rebase onto for-next
> >>    - Fix KASAN
> >>    - Fix stack canary
> >>    - Get completely rid of MAXPHYSMEM configs
> >>    - Add documentation
> >>
> >> Alexandre Ghiti (10):
> >>    riscv: Allow to dynamically define VA_BITS
> >>    riscv: Get rid of MAXPHYSMEM configs
> >>    asm-generic: Prepare for riscv use of pud_alloc_one and pud_free
> >>    riscv: Implement sv48 support
> >>    riscv: Use pgtable_l4_enabled to output mmu_type in cpuinfo
> >>    riscv: Explicit comment about user virtual address space size
> >>    riscv: Improve virtual kernel memory layout dump
> >>    Documentation: riscv: Add sv48 description to VM layout
> >>    riscv: Initialize thread pointer before calling C functions
> >>    riscv: Allow user to downgrade to sv39 when hw supports sv48
> >>
> >>   Documentation/riscv/vm-layout.rst             |  36 ++
> >>   arch/riscv/Kconfig                            |  35 +-
> >>   arch/riscv/configs/nommu_k210_defconfig       |   1 -
> >>   .../riscv/configs/nommu_k210_sdcard_defconfig |   1 -
> >>   arch/riscv/configs/nommu_virt_defconfig       |   1 -
> >>   arch/riscv/include/asm/csr.h                  |   3 +-
> >>   arch/riscv/include/asm/fixmap.h               |   1 +
> >>   arch/riscv/include/asm/kasan.h                |   2 +-
> >>   arch/riscv/include/asm/page.h                 |  10 +
> >>   arch/riscv/include/asm/pgalloc.h              |  40 +++
> >>   arch/riscv/include/asm/pgtable-64.h           | 108 +++++-
> >>   arch/riscv/include/asm/pgtable.h              |  30 +-
> >>   arch/riscv/include/asm/sparsemem.h            |   6 +-
> >>   arch/riscv/kernel/cpu.c                       |  23 +-
> >>   arch/riscv/kernel/head.S                      |   4 +-
> >>   arch/riscv/mm/context.c                       |   4 +-
> >>   arch/riscv/mm/init.c                          | 323 +++++++++++++++-=
--
> >>   arch/riscv/mm/kasan_init.c                    |  91 +++--
> >>   drivers/firmware/efi/libstub/efi-stub.c       |   2 +
> >>   include/asm-generic/pgalloc.h                 |  24 +-
> >>   include/linux/sizes.h                         |   1 +
> >>   21 files changed, 615 insertions(+), 131 deletions(-)
> >>
> >>
> >
> >
> >
>=20
> _______________________________________________
> linux-riscv mailing list
> linux-riscv@lists.infradead.org
> http://lists.infradead.org/mailman/listinfo/linux-riscv
>=20




--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/16228030.BXmPpbjjvJ%40diego.
