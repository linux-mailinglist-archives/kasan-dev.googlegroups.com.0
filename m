Return-Path: <kasan-dev+bncBDQ7NGWH7YJRBN6UW6GQMGQE6VVHAFY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x239.google.com (mail-lj1-x239.google.com [IPv6:2a00:1450:4864:20::239])
	by mail.lfdr.de (Postfix) with ESMTPS id BACB3469423
	for <lists+kasan-dev@lfdr.de>; Mon,  6 Dec 2021 11:47:19 +0100 (CET)
Received: by mail-lj1-x239.google.com with SMTP id 83-20020a2e0556000000b00218db3260bdsf3267850ljf.9
        for <lists+kasan-dev@lfdr.de>; Mon, 06 Dec 2021 02:47:19 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1638787639; cv=pass;
        d=google.com; s=arc-20160816;
        b=B3RWzIvAvSriPuxVSphITPQT2rdwhXFQ+BQ2tP+pM4SCpB6sh/lP0uy1q8iq5lzpix
         iYVbi3c4TcoeTrfqej7zRfNws1mdyh+C76hgVa9fxQGJb+BkwpjZsasBY4lga57jacOB
         zNh3ve67YdTHMUlLgzyly8bGwQg0QFgm7l2mWIBArjUhS3zxBrESprmO9bCSkDZJJOGF
         HKuLZtpQkC/G6cKi03WwB5FjWwXwcc0ll5S9E9/1GoSS9sr0SEGmh4XSRBTpC84TYVZJ
         Tvy0oCVVeYAVWwc4SFYb97F8aI6IfaVGKU+aF0lKzhpoQD9Skqmi4uwKWKzja2DoqO+e
         Q22A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=cncdEtRlqHew9aLYFHW8UMKjEhQqke1O3Mm3+8RGMW8=;
        b=KEQfVzVGQQH15C4alcR/zmm/zFqAT53htEvMF/xC4SLfxCpK+MxNqgt7VHQNVfSSRy
         G3zJtqijD2b55AykAK1ohmt6q2vlf3V5g6Qn3EZWpRjN+KhSqPFisJmDrfvisYx+2WXx
         JFUxhHVXKZe0SzAAz+qiiqLdE9jEk9XDLTDwh8q7AxRpaaCimCN0KUopbIjtEWx/L6er
         PkfCqFvrXU3wvocIU8kQbJbBW22UthRQJjHj5b1wNxzx+w31sO8AUklU7LsVzVaMNgir
         XblnffifliLgN6zVWpZdAG+56B5yF+lc2UYcZOWWVSQ+JDqDoeMfakesqwmkObC1F0LF
         Vkfw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@canonical.com header.s=20210705 header.b=pE7TgXBm;
       spf=pass (google.com: domain of alexandre.ghiti@canonical.com designates 185.125.188.123 as permitted sender) smtp.mailfrom=alexandre.ghiti@canonical.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=canonical.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=cncdEtRlqHew9aLYFHW8UMKjEhQqke1O3Mm3+8RGMW8=;
        b=UZr7sMIHoq7STn518QFuuNHmD6FQ40UFsqkrIS5l4l3IiDMR48igzKtJyDLWuWHXrD
         IHUkgD2TE4AR3l95LcOmilshwCVkfKTULQBpKRWiX9qrvuFNQMI8/X4R2t1TcP9OgKsB
         ez3tiYCeNN9MRChAWfRAw35huahYKPMBYrqABIInBkuFAb8rooYKtOMxAOlpjafYVMPL
         os2f960VZR9FUZexnoWFAW+Km7K8DQG+Z4LIYJOFGmv6jmrdwzYEv3g8PdPEkoUsoP/j
         kO4K+76HjetmwCjTq5Qy7vB84L95yZLz12aKihFl59QEJN7zhBewzaPeY8KytsoViJgY
         Gtdw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=cncdEtRlqHew9aLYFHW8UMKjEhQqke1O3Mm3+8RGMW8=;
        b=kw7rIr2Fpnml0Bm31oObYCqusq7xga/BZ6cIipVdNpWymkFsWHZMkh3GuDRVG1DRkv
         gESueM75SJmU4zYeX3hl6NHy5uQ5a3rn0JFiUyooYD3NX+freUoMrJIAA+xcfQ/rrrU0
         OBQ9AXeBvh7fStbLe4kSXtgelEWZhV6BmZZDTseIH714p5IITO6f3ea/OOSyvM0RBQ1w
         XNWNX6l02KwKIpYpuW25GJldCJ40ygxaqgBJT+oF81I5DAPrLEML1eHnH0my9FKaGOhU
         /+uvhQvxzDJEmmF9bNXJTShMGSrDWZC2uJhjM+1xTcFfgRWMr/70mOyHcWpmF+CfqOCh
         nkTg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532HBpDTzZ/vBCNp2QZu1UOcueXem+reiPyHhAWbDejgA1x7Cxs2
	pSHzuxdRaioac/NFE8E24DE=
X-Google-Smtp-Source: ABdhPJxzIRXUkjYoJ/mm5vV8B2MWYSllK7QfVaQh3Yru21X8mvYu1iYi4NrAzlnLHiEtDxpJs26SYA==
X-Received: by 2002:a05:651c:a04:: with SMTP id k4mr35476910ljq.12.1638787639372;
        Mon, 06 Dec 2021 02:47:19 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3e10:: with SMTP id i16ls690257lfv.3.gmail; Mon, 06
 Dec 2021 02:47:18 -0800 (PST)
X-Received: by 2002:ac2:42c6:: with SMTP id n6mr33970717lfl.553.1638787638381;
        Mon, 06 Dec 2021 02:47:18 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1638787638; cv=none;
        d=google.com; s=arc-20160816;
        b=wXoGlCuZqwDGNK4uUEcs6E4DLJldKmJRQa5c4X7p9hPYXHd/ibKMqOidFaHFQrRFUl
         KUxvKtXo3gXOa/qS5j3NiY4QycRA4LxrqtjRZWEqG1sUtahzEvWFUyTHjBqL3Plfdhr2
         uSogzFe+2u790DtqqAnjqyqFfNejAWBjnvJYUXmBzW9ys+lnRHh/hT5GUcaAb+IVhAY6
         Ss+lIl08dJkpo1P/1UY9UXmrXiT7Kn9DTRsJ3PhtuAmNqJZNYMz6svvcGtMFHuI679xr
         76t0CxgX8B5cKmTyOrDQ7GiJPcfaRx9aPdx0KSTJBl4cmSdvLusk8lgNv/AGrKjsn7Eu
         Q+6w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=b2gB9kgbziNsEGldLluKkZRlwEDdrCHFdkBhlX9f0m4=;
        b=FN5LKHtMBbCA5WlSzGwqwi3Xbyt99OpEmvNNotpMRwOv9lGWAbjx6NakvOd+sTbZ3C
         C/dRy6T5FZoDxUk482rZzZTw+fLTmJw4DqrHWh3O1W1i/0eFrP2eENQfFOSziGTnLEBX
         slUDAopKrBRz8FyDmmwYVED4SrNhBreQSzBP1QpGop5EH6tk12SNwku4sqpHXJJOku5U
         UIC+X3ECK2NBX/W4A2/mWJHb6bTE4JLU6uhF1o9SBRi9T9xaOVv8oNv1CYm3sN041IGY
         BYPcWHx5nUI+i8u1Yblb3b2xkLthK19CgN1ZW9njO23gjfXqGDTnIBrYIuIvM7wAatIR
         1KsQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@canonical.com header.s=20210705 header.b=pE7TgXBm;
       spf=pass (google.com: domain of alexandre.ghiti@canonical.com designates 185.125.188.123 as permitted sender) smtp.mailfrom=alexandre.ghiti@canonical.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=canonical.com
Received: from smtp-relay-internal-1.canonical.com (smtp-relay-internal-1.canonical.com. [185.125.188.123])
        by gmr-mx.google.com with ESMTPS id b9si836463lji.2.2021.12.06.02.47.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 06 Dec 2021 02:47:18 -0800 (PST)
Received-SPF: pass (google.com: domain of alexandre.ghiti@canonical.com designates 185.125.188.123 as permitted sender) client-ip=185.125.188.123;
Received: from mail-wr1-f69.google.com (mail-wr1-f69.google.com [209.85.221.69])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-relay-internal-1.canonical.com (Postfix) with ESMTPS id 478233F1F5
	for <kasan-dev@googlegroups.com>; Mon,  6 Dec 2021 10:47:17 +0000 (UTC)
Received: by mail-wr1-f69.google.com with SMTP id h7-20020adfaa87000000b001885269a937so1892367wrc.17
        for <kasan-dev@googlegroups.com>; Mon, 06 Dec 2021 02:47:17 -0800 (PST)
X-Received: by 2002:a1c:488:: with SMTP id 130mr38244191wme.157.1638787636691;
        Mon, 06 Dec 2021 02:47:16 -0800 (PST)
X-Received: by 2002:a1c:488:: with SMTP id 130mr38244150wme.157.1638787636435;
        Mon, 06 Dec 2021 02:47:16 -0800 (PST)
Received: from localhost.localdomain (lfbn-lyo-1-470-249.w2-7.abo.wanadoo.fr. [2.7.60.249])
        by smtp.gmail.com with ESMTPSA id u23sm11755158wru.21.2021.12.06.02.47.15
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 06 Dec 2021 02:47:16 -0800 (PST)
From: Alexandre Ghiti <alexandre.ghiti@canonical.com>
To: Jonathan Corbet <corbet@lwn.net>,
	Paul Walmsley <paul.walmsley@sifive.com>,
	Palmer Dabbelt <palmer@dabbelt.com>,
	Albert Ou <aou@eecs.berkeley.edu>,
	Zong Li <zong.li@sifive.com>,
	Anup Patel <anup@brainfault.org>,
	Atish Patra <Atish.Patra@rivosinc.com>,
	Christoph Hellwig <hch@lst.de>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Ard Biesheuvel <ardb@kernel.org>,
	Arnd Bergmann <arnd@arndb.de>,
	Kees Cook <keescook@chromium.org>,
	Guo Ren <guoren@linux.alibaba.com>,
	Heinrich Schuchardt <heinrich.schuchardt@canonical.com>,
	Mayuresh Chitale <mchitale@ventanamicro.com>,
	panqinglin2020@iscas.ac.cn,
	linux-doc@vger.kernel.org,
	linux-riscv@lists.infradead.org,
	linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	linux-efi@vger.kernel.org,
	linux-arch@vger.kernel.org
Cc: Alexandre Ghiti <alexandre.ghiti@canonical.com>
Subject: [PATCH v3 00/13] Introduce sv48 support without relocatable kernel
Date: Mon,  6 Dec 2021 11:46:44 +0100
Message-Id: <20211206104657.433304-1-alexandre.ghiti@canonical.com>
X-Mailer: git-send-email 2.32.0
MIME-Version: 1.0
X-Original-Sender: alexandre.ghiti@canonical.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@canonical.com header.s=20210705 header.b=pE7TgXBm;       spf=pass
 (google.com: domain of alexandre.ghiti@canonical.com designates
 185.125.188.123 as permitted sender) smtp.mailfrom=alexandre.ghiti@canonical.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=canonical.com
Content-Type: text/plain; charset="UTF-8"
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

* Please note notable changes in memory layouts and kasan population *

This patchset allows to have a single kernel for sv39 and sv48 without
being relocatable.

The idea comes from Arnd Bergmann who suggested to do the same as x86,
that is mapping the kernel to the end of the address space, which allows
the kernel to be linked at the same address for both sv39 and sv48 and
then does not require to be relocated at runtime.

This implements sv48 support at runtime. The kernel will try to
boot with 4-level page table and will fallback to 3-level if the HW does not
support it. Folding the 4th level into a 3-level page table has almost no
cost at runtime.

Note that kasan region had to be moved to the end of the address space
since its location must be known at compile-time and then be valid for
both sv39 and sv48 (and sv57 that is coming).

Tested on:
  - qemu rv64 sv39: OK
  - qemu rv64 sv48: OK
  - qemu rv64 sv39 + kasan: OK
  - qemu rv64 sv48 + kasan: OK
  - qemu rv32: OK

Changes in v3:
  - Fix SZ_1T, thanks to Atish
  - Fix warning create_pud_mapping, thanks to Atish
  - Fix k210 nommu build, thanks to Atish
  - Fix wrong rebase as noted by Samuel
  - * Downgrade to sv39 is only possible if !KASAN (see commit changelog) *
  - * Move KASAN next to the kernel: virtual layouts changed and kasan population *

Changes in v2:
  - Rebase onto for-next
  - Fix KASAN
  - Fix stack canary
  - Get completely rid of MAXPHYSMEM configs
  - Add documentation

Alexandre Ghiti (13):
  riscv: Move KASAN mapping next to the kernel mapping
  riscv: Split early kasan mapping to prepare sv48 introduction
  riscv: Introduce functions to switch pt_ops
  riscv: Allow to dynamically define VA_BITS
  riscv: Get rid of MAXPHYSMEM configs
  asm-generic: Prepare for riscv use of pud_alloc_one and pud_free
  riscv: Implement sv48 support
  riscv: Use pgtable_l4_enabled to output mmu_type in cpuinfo
  riscv: Explicit comment about user virtual address space size
  riscv: Improve virtual kernel memory layout dump
  Documentation: riscv: Add sv48 description to VM layout
  riscv: Initialize thread pointer before calling C functions
  riscv: Allow user to downgrade to sv39 when hw supports sv48 if !KASAN

 Documentation/riscv/vm-layout.rst             |  48 ++-
 arch/riscv/Kconfig                            |  37 +-
 arch/riscv/configs/nommu_k210_defconfig       |   1 -
 .../riscv/configs/nommu_k210_sdcard_defconfig |   1 -
 arch/riscv/configs/nommu_virt_defconfig       |   1 -
 arch/riscv/include/asm/csr.h                  |   3 +-
 arch/riscv/include/asm/fixmap.h               |   1
 arch/riscv/include/asm/kasan.h                |  11 +-
 arch/riscv/include/asm/page.h                 |  20 +-
 arch/riscv/include/asm/pgalloc.h              |  40 ++
 arch/riscv/include/asm/pgtable-64.h           | 108 ++++-
 arch/riscv/include/asm/pgtable.h              |  47 +-
 arch/riscv/include/asm/sparsemem.h            |   6 +-
 arch/riscv/kernel/cpu.c                       |  23 +-
 arch/riscv/kernel/head.S                      |   4 +-
 arch/riscv/mm/context.c                       |   4 +-
 arch/riscv/mm/init.c                          | 408 ++++++++++++++----
 arch/riscv/mm/kasan_init.c                    | 250 ++++++++---
 drivers/firmware/efi/libstub/efi-stub.c       |   2
 drivers/pci/controller/pci-xgene.c            |   2 +-
 include/asm-generic/pgalloc.h                 |  24 +-
 include/linux/sizes.h                         |   1
 22 files changed, 833 insertions(+), 209 deletions(-)

--
2.32.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211206104657.433304-1-alexandre.ghiti%40canonical.com.
