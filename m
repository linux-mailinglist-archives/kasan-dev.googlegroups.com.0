Return-Path: <kasan-dev+bncBDOY5FWKT4KRBMXAWCFAMGQE7FN7NBY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x93b.google.com (mail-ua1-x93b.google.com [IPv6:2607:f8b0:4864:20::93b])
	by mail.lfdr.de (Postfix) with ESMTPS id 100CB41593F
	for <lists+kasan-dev@lfdr.de>; Thu, 23 Sep 2021 09:43:48 +0200 (CEST)
Received: by mail-ua1-x93b.google.com with SMTP id j42-20020ab0186a000000b002b0bf3870desf1929285uag.23
        for <lists+kasan-dev@lfdr.de>; Thu, 23 Sep 2021 00:43:48 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1632383027; cv=pass;
        d=google.com; s=arc-20160816;
        b=ncB+mqhmIUKv4kPB0HUQU8CWrxwiOay1KcB89RZF96IatRtNS17z5Vhktx5fXk9aM/
         MS2la0M0hqWCb26Cd4E/m3QvwTE7ltId9MgmFzt9WP/0bNIiJcIyreTk2QIWfs9lK01a
         Of+sd25Phe5OoAe4odVOT9WCgYgJjjwIJeYuqwZA5N1ksWil0UAxDDkXCb4U7EOBll9k
         bzAMnbQTH3C1KQcu6pha2XE/URJfDJSWvEge3qQTJoHqhXowqxBem1muetQ9abtUosBn
         wErszMF8H2LQUan/MZBOmsVTGztQ1Wb5ebuYFFLjJGLxoV2gTaz58vuqPKsOmWJSx7Cz
         +jSg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=cBtl5zH17/sEwqtStBfoMq8ApEDCpUtrFms82G6fGmM=;
        b=ayjeMRiAaLqNgBnnkXcWK+oXy740ptak0c7O42Q2C28jsuH8jMIwP0iRrHfHXWQmQ/
         +WtjBCg0a28WKDBb3wJ9o4L3bkoqnRPtyEOSMOTCDczqAwFW8VJWAGIU2D5BVKQk7xgh
         EOuo6f5g+aZdRBWdWFrAJgmUYgyTvLD7HHLXa07joTwynDmNeFHHRlzKgC9rSY/r9rzP
         B6OLVe4Z73lXspabOKrUcG3A79U3MfQkd2FeAI3rS8UhppSpTHrYVFb5BnwLLtB448QH
         RHz52z9fvDgZw8lOa7c1kHprsxuGCEy3UniSnrixRJhs3j3aXmoRrX/toefgcqc7vMW9
         SdFw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Vold8Z9h;
       spf=pass (google.com: domain of rppt@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=rppt@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=cBtl5zH17/sEwqtStBfoMq8ApEDCpUtrFms82G6fGmM=;
        b=PSgMhDSHExf9N+pJ85+5OBF5nF6evUUsM4FxeHafhAfIi89RFW9T/JELtrftfGNdnQ
         qRhEHJZLaiYAQWPYfIeCAVNsDy/rEefqWSopVvr3PuYMSE+CnfeGcRQ5zo+YljtBpuAZ
         Ja40+P/rm4zYDqNDE4oCCcKHNGdBANWKjbcowjrsxWzn5S2r7AAaN41v9wilS36m8z61
         ScutfEXK7R0BMwmkWpLc7OQubXlu2MfRCjkNi4aBQu+cEdT/XwkuCs1LHd2Ya4pZY5I9
         cX0aB/vXAyAeEWqo8I7Rpzw5gg1WCVq81ahFI7vx/54Sh6bNPnjEyFsloDHb4xy93Y5X
         VQxQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=cBtl5zH17/sEwqtStBfoMq8ApEDCpUtrFms82G6fGmM=;
        b=vvAKKs68uISUFCh3kFsAAnONJxGYwxYoyGrXTcOh1q8b52QiM8Ni4i2YchsUcpuXQr
         RKMcJg253zd+BpfPsxXLngSEgKIc099L8KcNkV8ggmfo0Rvm0Y1kyatGLstgrSZYEkp9
         MGu0wKqORD/XRhZyzr2ImXLWQ9BcaH8EGJMpiwYUPbCGt2MLLzx36RIgqkDxLNJCZIUi
         tykcJrjj3vQcbnUeYWT6yFB1QG5CkeNUgSAHpNTHzvcb4i5RHw3Pn38fOFb79Fqrfqu5
         l85roA5gmglKkqPfjbaWhP7vVPm6EDnzDqhBmLF65zYCcWg6e80Z4EAMO9uiQ1N+0ovW
         VKLg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530yyMyfQEzr0nO0dRQQ9zUaFrf/REfq8PIRiyZEkM5XBbfeaK1w
	oMM0asLn1UwOroL1gAMC8ZE=
X-Google-Smtp-Source: ABdhPJz9WILWNDyJinJv0Eho1eAV0RxYZ7omh+S/8LOjC2IZj4rfbA1NH/X9FOZz0K+ojjYTaBn5og==
X-Received: by 2002:a05:6122:13af:: with SMTP id n15mr2245740vkp.12.1632383026963;
        Thu, 23 Sep 2021 00:43:46 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ab0:1858:: with SMTP id j24ls636720uag.3.gmail; Thu, 23 Sep
 2021 00:43:46 -0700 (PDT)
X-Received: by 2002:ab0:45a9:: with SMTP id u38mr3017636uau.84.1632383026417;
        Thu, 23 Sep 2021 00:43:46 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1632383026; cv=none;
        d=google.com; s=arc-20160816;
        b=kPByqHkc6LEY4o2Yy0pPpha2tf0++1DuEnU0MR83KK3aeM678nQFjJwfoaakYLEIZS
         PRki/o/E0zkakwFlFIL4sMMJ/tY1jK2k3ISfMEKPCeOjdu2wyM0etV9EE5UELYSQSuUu
         vIHS0SHuPjPwbnkvci/NOjWeMKGusElu/yMLciXje5yim7fD1KLnNAIUCdhxfv2JtAHj
         s01+58FU3ZGu9Nhj5ypcTai0m+sYtfp6SksR9ZgCOFx4qlpcUD7enaP4BTPCxfpJngkj
         OrkiRnrpA1RxFV9vj2lTgTyFEsiwXbN00zZIXT66jGK8pY/M8IEUI1KH2A16sMx8Pht1
         N8ug==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=b0PH7BZc3r7A8AqdQ+BEVz51Mr9JJL5hGCAcNW2gPGQ=;
        b=yUZWKQ4sfY00uwDy6ayMAc2AFoJnOLagNi2hF/kWdA3Jw417KJWtRnL0UvBzupdnIW
         MoIAqavhf9ju0IO1+HHi0/ZS4Hqt9xXIJ1c3iLv7mqIuraQ8/QjnXV7BG1uignVy0K5N
         0d61HElbsIUEHtPh1G4LLpxEc594YtpQGLMoazGScBCRn0a+esw12cjWiwL3/sG4iIMv
         JnE1H0Q3eiEexNEgWhD+r6FKSf5wrPHxoyMymAuv8JqLdL7Hzh+vRiZLv3zRlr932H+/
         9CwQLzewqHneT/M1ZdV0QF7WQIndL9995Cc/4cvLo14Zh8krvdbcH9SDfUrDH6gU9W/q
         7aRg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Vold8Z9h;
       spf=pass (google.com: domain of rppt@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=rppt@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id u64si260540vku.4.2021.09.23.00.43.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 23 Sep 2021 00:43:46 -0700 (PDT)
Received-SPF: pass (google.com: domain of rppt@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id 3D07E60EC0;
	Thu, 23 Sep 2021 07:43:40 +0000 (UTC)
From: Mike Rapoport <rppt@kernel.org>
To: Linus Torvalds <torvalds@linux-foundation.org>
Cc: Andrew Morton <akpm@linux-foundation.org>,
	devicetree@vger.kernel.org,
	iommu@lists.linux-foundation.org,
	kasan-dev@googlegroups.com,
	kvm@vger.kernel.org,
	linux-alpha@vger.kernel.org,
	linux-arm-kernel@lists.infradead.org,
	linux-efi@vger.kernel.org,
	linux-kernel@vger.kernel.org,
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
	xen-devel@lists.xenproject.org,
	Mike Rapoport <rppt@linux.ibm.com>
Subject: [PATCH 0/3] memblock: cleanup memblock_free interface
Date: Thu, 23 Sep 2021 10:43:32 +0300
Message-Id: <20210923074335.12583-1-rppt@kernel.org>
X-Mailer: git-send-email 2.28.0
MIME-Version: 1.0
X-Original-Sender: rppt@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=Vold8Z9h;       spf=pass
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

The core change is in the third patch that makes memblock_free() a
counterpart of memblock_alloc() and adds memblock_phys_alloc() to be a
counterpart of memblock_phys_alloc().

Since scripts/get_maintainer.pl returned more than 100 addresses I've
trimmed the distribution list only to the relevant lists.

[1] https://lore.kernel.org/all/CAHk-=wj9k4LZTz+svCxLYs5Y1=+yKrbAUArH1+ghyG3OLd8VVg@mail.gmail.com

Mike Rapoport (3):
  arch_numa: simplify numa_distance allocation
  xen/x86: free_p2m_page: use memblock_free_ptr() to free a virtual pointer
  memblock: cleanup memblock_free interface

 arch/alpha/kernel/core_irongate.c         |  2 +-
 arch/arc/mm/init.c                        |  2 +-
 arch/arm/mach-hisi/platmcpm.c             |  2 +-
 arch/arm/mm/init.c                        |  2 +-
 arch/arm64/mm/mmu.c                       |  4 ++--
 arch/mips/mm/init.c                       |  2 +-
 arch/mips/sgi-ip30/ip30-setup.c           |  6 +++---
 arch/powerpc/kernel/dt_cpu_ftrs.c         |  2 +-
 arch/powerpc/kernel/paca.c                |  4 ++--
 arch/powerpc/kernel/setup-common.c        |  2 +-
 arch/powerpc/kernel/setup_64.c            |  2 +-
 arch/powerpc/platforms/powernv/pci-ioda.c |  2 +-
 arch/powerpc/platforms/pseries/svm.c      |  4 +---
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
 drivers/of/kexec.c                        |  2 +-
 drivers/of/of_reserved_mem.c              |  4 ++--
 drivers/s390/char/sclp_early.c            |  2 +-
 drivers/usb/early/xhci-dbc.c              | 10 +++++-----
 drivers/xen/swiotlb-xen.c                 |  2 +-
 include/linux/memblock.h                  | 16 ++--------------
 init/initramfs.c                          |  2 +-
 init/main.c                               |  2 +-
 kernel/dma/swiotlb.c                      |  2 +-
 kernel/printk/printk.c                    |  4 ++--
 lib/bootconfig.c                          |  2 +-
 lib/cpumask.c                             |  2 +-
 mm/cma.c                                  |  2 +-
 mm/memblock.c                             | 20 ++++++++++----------
 mm/memory_hotplug.c                       |  2 +-
 mm/percpu.c                               |  8 ++++----
 mm/sparse.c                               |  2 +-
 tools/bootconfig/include/linux/memblock.h |  2 +-
 55 files changed, 94 insertions(+), 110 deletions(-)


base-commit: e4e737bb5c170df6135a127739a9e6148ee3da82
-- 
2.28.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210923074335.12583-1-rppt%40kernel.org.
