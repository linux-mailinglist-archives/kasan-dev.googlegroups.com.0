Return-Path: <kasan-dev+bncBDOY5FWKT4KRBA4O3CFAMGQEW7KSBFI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc38.google.com (mail-oo1-xc38.google.com [IPv6:2607:f8b0:4864:20::c38])
	by mail.lfdr.de (Postfix) with ESMTPS id 8BBF841E165
	for <lists+kasan-dev@lfdr.de>; Thu, 30 Sep 2021 20:50:44 +0200 (CEST)
Received: by mail-oo1-xc38.google.com with SMTP id h6-20020a4ae8c6000000b002adb82e3332sf5343458ooe.16
        for <lists+kasan-dev@lfdr.de>; Thu, 30 Sep 2021 11:50:44 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1633027843; cv=pass;
        d=google.com; s=arc-20160816;
        b=HnPul4NE+ycKKci8Y6/z0WvCDnOZ5/BRejb26nGloOXgQ6jxC3uCrYJnIhzHxwyq83
         wPL9VTwwHXngo9nqURVya2uxznDiwtR7YNPt88ZFEjyCXJwncz6VRChlcqpIf2jSAMAP
         GCM55mZM8RpNT7BXeA1AxuGX/3DkKxAYUtdYxQHTJlGLPBdzi5p+86Ki6YYKmNwDRL0L
         ZYSZEkX5BYoDVk4TlzwIY/57Ran4Xn1jnJ31JkLq1qNK+7Z0+/YmB+G8gSaEHgM0Ettp
         RQIZiaHwV34ZfKoJEIs7gsO0WzyqWcCnS90WjeBY8CZhuaBORYOPEdGVnpn+7+UrkK/x
         Oa/Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=32EUs4WKa1rCEUkEuw5xlkKB872250TQYu7mWbNvSoc=;
        b=ci26a8knReKqjdaM9myNbxaUXaR+yYp+jHDea/saUNCBDLtscMAW1yQW2YsJ9hznEs
         Le28C9CuuRhgggedbmWEqrC1SwDZzJcVPWlm32ItSZJXzFyfVWIMYLiRqpHaVbLA0pgL
         /uYA/0GSyB8H7YrDLC5iYL9H9CKGp0ROWO/JXWNSh6bV7aCAqQjUro2dgiiIhKSyxBED
         4J0mdXLxA3qDlzkA985sqfXilwzfZft3BeHG8GUxF7ZRh3ivYZTrmxm6kRPSFFCImXlX
         XLVAPIICpesOt9AaQU6NK+xIRc86xVnLEBonjk8TE2QdMIrQiDX0C4Zxi94VpKkvnk1V
         YJPA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=uHnQO7Kn;
       spf=pass (google.com: domain of rppt@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=rppt@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=32EUs4WKa1rCEUkEuw5xlkKB872250TQYu7mWbNvSoc=;
        b=i7kQK3c5EscJokcD2vuTCKmV5oBacVd7XVOgJ8JIaiwderI0L1tuBTvwjtxPdpzUNs
         4yMsEOB0D7J7VPHMcsQYRCZx68Ziitei4M4f2rS/hy+8jUEVZdE4FjGEYOZJKufnKN3J
         uoQ1JWvNR5lXG+pp8qSN9Wn0oQNCyJKUrZN5CHbdyTmqfMC8CiWHdMpuq+CmjpXPlu2A
         zT22FRBjMAqIXbdXwA1o9CJ2Bw1X71+t2mIIdiHMGwSJ5F+grhWRjUr1OZi9pmTaI2Vd
         6yPGBYVX6rRygDl79y9gAckWGlof4Wugxr5oZ3BHPpzrg1RSR+JqFn1a+bSj8mLVDDgL
         4lIA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=32EUs4WKa1rCEUkEuw5xlkKB872250TQYu7mWbNvSoc=;
        b=HcpqQVrvk6o+zbF23s6+CBhHeUF0GuzFhra+Qg3K1wkUXQMwcGNT7rBfzJX8YkQVZ3
         9KXDDZBZG0e1C/GCLajeufmA6OoAIXUas0UmNKuNWqS8DW2w/sPbp2t7i3TYyXnDmmny
         kL6lMnCzUD4+1P4HNZT4YVq2jXbsNhZ5UG99KrCw1xrBMFn0pTXW+HTIU+UYJTxluGU1
         /tOYppqv9chFSfN8jRRyczc3LLiJJMOvOdSwCr/LbvJVS2Wn7afb3sxx9MfYqEZuBnQ6
         Cs0TORDMbOWHTbMg4nYb5Q1xOyUz++NLNlW8CUdWCaWtKvh77tjfzTfYYl8zlbe47slm
         BISQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5321+nVWcHbbwnSIDINBR5vjEBEBGnMw8F6lkejUbO286hHLMbf9
	u99GDIXKzxUU1JZ1vN+xaVE=
X-Google-Smtp-Source: ABdhPJw2e1xzaWr0LTE2kzryXtxnng+dZnAguc1+tpt2pjhd3UUvgYeD33QURTlC78f0lnurlVXr2g==
X-Received: by 2002:a9d:6092:: with SMTP id m18mr6734039otj.215.1633027843096;
        Thu, 30 Sep 2021 11:50:43 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6808:114:: with SMTP id b20ls2314484oie.10.gmail; Thu,
 30 Sep 2021 11:50:42 -0700 (PDT)
X-Received: by 2002:a05:6808:1151:: with SMTP id u17mr696167oiu.78.1633027842759;
        Thu, 30 Sep 2021 11:50:42 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1633027842; cv=none;
        d=google.com; s=arc-20160816;
        b=GMqc3OPX4JWogkNCQeIQ93j1SQzQrbCPlyH8c4xCu88I5ZeZGWdoHXPxlu6fOxoZGP
         3KXcTmCnmxQA1ZB2SGqwQYf//kYDL8wrw39y8TioTulm4WCW2RZK/bILw5xYrs66eLPv
         tYQH/IHmHm/n8saIHNJa822WcUo8TNpmKc567FGaQZu1r9PjvH5eDVtIhEbfqpyD6AC0
         3q0Fg4TbwImGt/YQKwdhArrs9sgYitfnrzGgYfll4xPJDQRndr/gqbeqM+QU+8VPY0wb
         3rhiZ8LJ1cVCb64cBJdb5wSqVe0+UGUkEEcVTNdrm+0++wdq1gbSnu4edixPR4jnO1/L
         xbGw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=Fjram9k6AWZi/Mo09D9Pgn2LkjacYt0WFr6fSAi63hY=;
        b=PZmpvszbLDzvXEaxx8/ketbqdePsHKcdJyz1jEhscyVWgHHIr02W9FeW5Zy0ufEOV1
         rMOFhqlxgwMKmuJiOykc5B/P6uamNAa7/Br7uZ28C41gFBYlGnEJ4lWZ5YAWpUpnuH87
         0FxpLLjyTMZ/e3/nyPxxLxzIqg8VAgFDFnz6ChyOwph89ZEBycEuFza1LvizJbvpV6re
         JKlc4lP53pC0RcSPYdxfpjra47gW+jRvr7KjcesqDoD50cN9tffyIXEQK4KuUfjiL6+g
         uLbFnAghZK3UO+j1Ad5YQaegkuBx8UebKRj8/sr/dpbBcvAxf5DUXc7JFaxHVRjOtWQB
         eciQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=uHnQO7Kn;
       spf=pass (google.com: domain of rppt@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=rppt@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id bc13si402561oob.2.2021.09.30.11.50.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 30 Sep 2021 11:50:42 -0700 (PDT)
Received-SPF: pass (google.com: domain of rppt@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id 8244C61216;
	Thu, 30 Sep 2021 18:50:35 +0000 (UTC)
From: Mike Rapoport <rppt@kernel.org>
To: linux-kernel@vger.kernel.org
Cc: Andrew Morton <akpm@linux-foundation.org>,
	Christophe Leroy <christophe.leroy@csgroup.eu>,
	Juergen Gross <jgross@suse.com>,
	Linus Torvalds <torvalds@linux-foundation.org>,
	Mike Rapoport <rppt@kernel.org>,
	Mike Rapoport <rppt@linux.ibm.com>,
	Shahab Vahedi <Shahab.Vahedi@synopsys.com>,
	devicetree@vger.kernel.org,
	iommu@lists.linux-foundation.org,
	kasan-dev@googlegroups.com,
	kvm@vger.kernel.org,
	linux-alpha@vger.kernel.org,
	linux-arm-kernel@lists.infradead.org,
	linux-efi@vger.kernel.org,
	linux-mips@vger.kernel.org,
	linux-mm@kvack.org,
	linux-riscv@lists.infradead.org,
	linux-s390@vger.kernel.org,
	linux-sh@vger.kernel.org,
	linux-snps-arc@lists.infradead.org,
	linux-um@lists.infradead.org,
	linux-usb@vger.kernel.org,
	linuxppc-dev@lists.ozlabs.org,
	sparclinux@vger.kernel.org,
	xen-devel@lists.xenproject.org
Subject: [PATCH v2 0/6] memblock: cleanup memblock_free interface
Date: Thu, 30 Sep 2021 21:50:25 +0300
Message-Id: <20210930185031.18648-1-rppt@kernel.org>
X-Mailer: git-send-email 2.28.0
MIME-Version: 1.0
X-Original-Sender: rppt@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=uHnQO7Kn;       spf=pass
 (google.com: domain of rppt@kernel.org designates 198.145.29.99 as permitted
 sender) smtp.mailfrom=rppt@kernel.org;       dmarc=pass (p=NONE sp=NONE
 dis=NONE) header.from=kernel.org
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

From: Mike Rapoport <rppt@linux.ibm.com>

Hi,

Following the discussion on [1] this is the fix for memblock freeing APIs
mismatch. 

The first patch is a cleanup of numa_distance allocation in arch_numa I've
spotted during the conversion.
The second patch is a fix for Xen memory freeing on some of the error
paths.

I agree with Christophe that doing step by step makes the thing easier to
review, so the patches 3-6 do the actual cleanup step by step.

This time I used stricter coccinelle scripts so that only straightforward
uses would get converted.

There still a couple of (void *) castings for the cases when a virtual
address has unsigned long type rather than a pointer type, like e.g
initrd_start.

Since scripts/get_maintainer.pl returned more than 100 addresses I've
trimmed the distribution list only to the relevant lists.

Juergen and Shahab, I didn't keep your Reviewed-by because the patches are
a bit different this time.

v2:
* split changes into several patches
* use stricter coccinelle scripts 

[1] https://lore.kernel.org/all/CAHk-=wj9k4LZTz+svCxLYs5Y1=+yKrbAUArH1+ghyG3OLd8VVg@mail.gmail.com

Mike Rapoport (6):
  arch_numa: simplify numa_distance allocation
  xen/x86: free_p2m_page: use memblock_free_ptr() to free a virtual pointer
  memblock: drop memblock_free_early_nid() and memblock_free_early()
  memblock: stop aliasing __memblock_free_late with memblock_free_late
  memblock: rename memblock_free to memblock_phys_free
  memblock: use memblock_free for freeing virtual pointers

 arch/alpha/kernel/core_irongate.c         |  2 +-
 arch/arc/mm/init.c                        |  2 +-
 arch/arm/mach-hisi/platmcpm.c             |  2 +-
 arch/arm/mm/init.c                        |  2 +-
 arch/arm64/mm/mmu.c                       |  4 ++--
 arch/mips/mm/init.c                       |  2 +-
 arch/mips/sgi-ip30/ip30-setup.c           |  6 +++---
 arch/powerpc/kernel/dt_cpu_ftrs.c         |  4 ++--
 arch/powerpc/kernel/paca.c                |  8 ++++----
 arch/powerpc/kernel/setup-common.c        |  2 +-
 arch/powerpc/kernel/setup_64.c            |  2 +-
 arch/powerpc/platforms/powernv/pci-ioda.c |  2 +-
 arch/powerpc/platforms/pseries/svm.c      |  3 +--
 arch/riscv/kernel/setup.c                 |  4 ++--
 arch/s390/kernel/setup.c                  |  8 ++++----
 arch/s390/kernel/smp.c                    |  4 ++--
 arch/s390/kernel/uv.c                     |  2 +-
 arch/s390/mm/kasan_init.c                 |  2 +-
 arch/sh/boards/mach-ap325rxa/setup.c      |  2 +-
 arch/sh/boards/mach-ecovec24/setup.c      |  4 ++--
 arch/sh/boards/mach-kfr2r09/setup.c       |  2 +-
 arch/sh/boards/mach-migor/setup.c         |  2 +-
 arch/sh/boards/mach-se/7724/setup.c       |  4 ++--
 arch/sparc/kernel/smp_64.c                |  2 +-
 arch/um/kernel/mem.c                      |  2 +-
 arch/x86/kernel/setup.c                   |  4 ++--
 arch/x86/kernel/setup_percpu.c            |  2 +-
 arch/x86/mm/init.c                        |  2 +-
 arch/x86/mm/kasan_init_64.c               |  4 ++--
 arch/x86/mm/numa.c                        |  2 +-
 arch/x86/mm/numa_emulation.c              |  2 +-
 arch/x86/xen/mmu_pv.c                     |  6 +++---
 arch/x86/xen/p2m.c                        |  2 +-
 arch/x86/xen/setup.c                      |  6 +++---
 drivers/base/arch_numa.c                  | 10 ++++------
 drivers/firmware/efi/memmap.c             |  2 +-
 drivers/macintosh/smu.c                   |  2 +-
 drivers/of/kexec.c                        |  3 +--
 drivers/of/of_reserved_mem.c              |  5 +++--
 drivers/s390/char/sclp_early.c            |  2 +-
 drivers/usb/early/xhci-dbc.c              | 10 +++++-----
 drivers/xen/swiotlb-xen.c                 |  2 +-
 include/linux/memblock.h                  | 23 +++--------------------
 init/initramfs.c                          |  2 +-
 init/main.c                               |  2 +-
 kernel/dma/swiotlb.c                      |  2 +-
 kernel/printk/printk.c                    |  4 ++--
 lib/bootconfig.c                          |  2 +-
 lib/cpumask.c                             |  2 +-
 mm/cma.c                                  |  2 +-
 mm/memblock.c                             | 22 +++++++++++-----------
 mm/memory_hotplug.c                       |  2 +-
 mm/percpu.c                               |  8 ++++----
 mm/sparse.c                               |  2 +-
 54 files changed, 99 insertions(+), 119 deletions(-)


base-commit: 5816b3e6577eaa676ceb00a848f0fd65fe2adc29
-- 
2.28.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210930185031.18648-1-rppt%40kernel.org.
