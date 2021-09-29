Return-Path: <kasan-dev+bncBDQ7NGWH7YJRB5722GFAMGQEHRGDQIY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53c.google.com (mail-ed1-x53c.google.com [IPv6:2a00:1450:4864:20::53c])
	by mail.lfdr.de (Postfix) with ESMTPS id BFE1B41C740
	for <lists+kasan-dev@lfdr.de>; Wed, 29 Sep 2021 16:51:35 +0200 (CEST)
Received: by mail-ed1-x53c.google.com with SMTP id z62-20020a509e44000000b003da839b9821sf2653836ede.15
        for <lists+kasan-dev@lfdr.de>; Wed, 29 Sep 2021 07:51:35 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1632927095; cv=pass;
        d=google.com; s=arc-20160816;
        b=yMGkkssnHFEBasAAa8D2J35hlA2GJsv5sr79EUO26RL8nSDCCpqFMX4o+3ashwHjoO
         fw2Zvn1GJj3bftDEUMaUVvTsJYmIXOJzQt4Oo+yVbMfuseGv2MN2mLoR2O1qiaGBPdx3
         I4cD10cqjYKo5ZKwL17+aqfYUoq6CN/eeej9ZdoUTAbJMgpZtAAvmVgWS77OoVMvzxBQ
         peV0Rqbpv0WwvXzCWxid6SRkTQxbUej6yaf5cJjeW4Z7f8l32w9rkK08xP1sRA8DlYx5
         5fV6dCFm+rOwu2k7/E/7avTLhV7wGCSRXm9NZ5MGy84QdS6U+E087AT48gKODCxByig3
         ZMjA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=2ubz+eg/Gf/ygP6vqA95a91yeQuDjmZf/6LECBeE9lE=;
        b=tuPkgHT8bKM+t4VCZZRMdJPfSK3At1XXJGPXUYDZDAzyB2HTOhiwVgV9vgnBbfpYaO
         FOWl6lmFdN1R8WQtMOGXxuUm+WHHrA8MbLpDLnn5CsU9YLSRgAXzblqitfV/ouExIC9C
         CUhbttuL5qOMmknowZPY/OVQEDu6hNxwLMrE8CvpvuNiVk7tA0oXJr12XSUBzJSFKkZ9
         PHUjEn0kA5o8aVv/7LSvDaqIBpcEy5sA1IbMqxg4Ql3Wd+LtM4Myng9W5co5C7871Lo8
         6764D/Y+ZprJbH1c92txRZJIGw60iDGISNywzqDsuDpM9IYyJQ0BQf8RnehMkmRBl5yQ
         hDzw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@canonical.com header.s=20210705 header.b=l64xjmVD;
       spf=pass (google.com: domain of alexandre.ghiti@canonical.com designates 185.125.188.123 as permitted sender) smtp.mailfrom=alexandre.ghiti@canonical.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=canonical.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=2ubz+eg/Gf/ygP6vqA95a91yeQuDjmZf/6LECBeE9lE=;
        b=teNiRsixpA4+8Q/27XW1M7PRqm4E+ZazSvVVrmWAtP15s5JTd6SS8I9jECwGsG+AvR
         e7Kzu8RDAu8+BZbRZNi7TVG+2yYvMJaUXb+BDR32vVtU/f4A9FJecHUW2cRoKdxLzXTS
         iHSEE4AgfQ1/NnWaMv8zEDkOtL+ZEuZ8vMwwRdo0FWt8ukSWnks03v4yddV+p9pZpMt5
         G8QXuobOGJLcA4RH3w1aDmozZBGkvHYzq8K3EYZ9kAAdk08W73kV2HI1h6IPGE04oqyD
         VcqDmLL3ky5OMc8lAjzscWxCVoN8ODOl08jmsYqmKy4ATqG5x+CLJkyxtAhpqonyis+Z
         0b6w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=2ubz+eg/Gf/ygP6vqA95a91yeQuDjmZf/6LECBeE9lE=;
        b=muaq0hFVO+BQfWEZnkB73hybyWO+EI1uMmy+JizEoQIc1TlNHhwN2oOhfdjl2dw9S2
         phD6I05y1GBCeTpXMl38/8qgoL3u6/iCAbwhHNPMmKbGtdbxQHmL6c1idSDIEA3dCVJj
         fuZiLuCi5DdhDJjbTIG/phNnRaw9wOn/LKnEWPAy7yKk9OCjz/LZAls+F/vrmCmjqlRr
         LFizgg9ZaOaEbvSjvbA2znVDPx2cyt87woaygM0XQ9/YcqxADVbvSAn5088NZa/qSYIX
         V8TyNuBwzejrLwwSJb6SPc5HJFpj16UMMRgTiwT6kLsYaQ+93Y/Yhm/DJAUoIAZuDnG9
         J6zg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530F6Kg1Eqi1ZZqrLR52VTJIExG/y09+mWbq1sC4E+YjhssciTrH
	H3Q210XE2RqZujwlpLZYuI4=
X-Google-Smtp-Source: ABdhPJzliWNb93Ev8EpMd/s8iKc12Yl9lkwLRzrtoksT8octpu79V5qCjdQJy15cGNauZFRwaY2RrQ==
X-Received: by 2002:a05:6402:484:: with SMTP id k4mr323066edv.303.1632927095560;
        Wed, 29 Sep 2021 07:51:35 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:b34:: with SMTP id bo20ls421630edb.0.gmail; Wed, 29
 Sep 2021 07:51:34 -0700 (PDT)
X-Received: by 2002:a05:6402:5191:: with SMTP id q17mr367822edd.332.1632927094662;
        Wed, 29 Sep 2021 07:51:34 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1632927094; cv=none;
        d=google.com; s=arc-20160816;
        b=Nxpe5TgUTAa/+gIQyckMvIzCnvux169wZc2zRWAxfMT6L+oP4xyPSgD2awUiwAB6XB
         xo5VNJ8JKpUXFTbLzUUS7Nrcp3EGnnpfLVf4KH6rcrYMY4IjxHE0VHENU91pjs+ipdv/
         6uP2gcI6+dCK0i+t2SP/i6OrVI6EnW9TQtin/ByTlDc89EydERja09KjTyj+1Zv5QRjn
         B7Ufmwmoj6GVN/vMVLsDwP0SAiyrENjC34ooF8fTVIz+4cmBRRFhoftOZVPY+MPirWzx
         0pT6sqJhdO3YIwWWxJSC1QFpGrir++bXrrrzBRtZXVS1YPXLttS0j+XytTASwFS50eKT
         EL0Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=/TquUrfUmr5oNmyuO1+Qsp/eD8gniIfYD04SJchk9B4=;
        b=xlwZTP9Hz55ezcJj+SiK2EM8qEeDrrH4clvnUnDwJXLsBLFUUy6TxCrTgCQOc+PnVw
         rENuiCmINt1yG3ayDCE70rZD/b5f57ux2sDA2VR+LLtDdZbraO2MGmZuScrs4BehzGp7
         iUdSDib6ysIZcoQ703VFI0jqglHQiSa66oXJLi8KQz6fC9uDYPegFwcmma+fn5Enak8f
         uz4E53CfoyVA4Pu6Xg69sMHgpXU3JNTRtH6Wd0XJdKU5n3Dp+wE2iEj9zHWRm0aFAD7K
         UP1KsvuId2pdjnSAe3QIgCEdbPoVDHwi0eKrLIWAY5nHLyzh03RVIj+YHpmhyo74O+dR
         GHsQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@canonical.com header.s=20210705 header.b=l64xjmVD;
       spf=pass (google.com: domain of alexandre.ghiti@canonical.com designates 185.125.188.123 as permitted sender) smtp.mailfrom=alexandre.ghiti@canonical.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=canonical.com
Received: from smtp-relay-internal-1.canonical.com (smtp-relay-internal-1.canonical.com. [185.125.188.123])
        by gmr-mx.google.com with ESMTPS id 6si3845edx.5.2021.09.29.07.51.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 29 Sep 2021 07:51:34 -0700 (PDT)
Received-SPF: pass (google.com: domain of alexandre.ghiti@canonical.com designates 185.125.188.123 as permitted sender) client-ip=185.125.188.123;
Received: from mail-wr1-f70.google.com (mail-wr1-f70.google.com [209.85.221.70])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-relay-internal-1.canonical.com (Postfix) with ESMTPS id 37A924019D
	for <kasan-dev@googlegroups.com>; Wed, 29 Sep 2021 14:51:34 +0000 (UTC)
Received: by mail-wr1-f70.google.com with SMTP id x2-20020a5d54c2000000b0015dfd2b4e34so695253wrv.6
        for <kasan-dev@googlegroups.com>; Wed, 29 Sep 2021 07:51:34 -0700 (PDT)
X-Received: by 2002:a05:600c:4e86:: with SMTP id f6mr11084969wmq.52.1632927093813;
        Wed, 29 Sep 2021 07:51:33 -0700 (PDT)
X-Received: by 2002:a05:600c:4e86:: with SMTP id f6mr11084945wmq.52.1632927093654;
        Wed, 29 Sep 2021 07:51:33 -0700 (PDT)
Received: from alex.home (lfbn-lyo-1-470-249.w2-7.abo.wanadoo.fr. [2.7.60.249])
        by smtp.gmail.com with ESMTPSA id q7sm129478wrc.55.2021.09.29.07.51.32
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 29 Sep 2021 07:51:33 -0700 (PDT)
From: Alexandre Ghiti <alexandre.ghiti@canonical.com>
To: Jonathan Corbet <corbet@lwn.net>,
	Paul Walmsley <paul.walmsley@sifive.com>,
	Palmer Dabbelt <palmer@dabbelt.com>,
	Albert Ou <aou@eecs.berkeley.edu>,
	Zong Li <zong.li@sifive.com>,
	Anup Patel <anup@brainfault.org>,
	Atish Patra <Atish.Patra@wdc.com>,
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
	linux-doc@vger.kernel.org,
	linux-riscv@lists.infradead.org,
	linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	linux-efi@vger.kernel.org,
	linux-arch@vger.kernel.org
Cc: Alexandre Ghiti <alexandre.ghiti@canonical.com>
Subject: [PATCH v2 00/10] Introduce sv48 support without relocatable kernel
Date: Wed, 29 Sep 2021 16:51:03 +0200
Message-Id: <20210929145113.1935778-1-alexandre.ghiti@canonical.com>
X-Mailer: git-send-email 2.30.2
MIME-Version: 1.0
X-Original-Sender: alexandre.ghiti@canonical.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@canonical.com header.s=20210705 header.b=l64xjmVD;       spf=pass
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
                                                                                 
Tested on:                                                                       
  - qemu rv64 sv39: OK                                                           
  - qemu rv64 sv48: OK                                                           
  - qemu rv64 sv39 + kasan: OK                                                   
  - qemu rv64 sv48 + kasan: OK                                                   
  - qemu rv32: OK                                                                
  - Unmatched: OK                                                                
                                                                                 
Changes in v2:                                                                   
  - Rebase onto for-next                                                         
  - Fix KASAN                                                                    
  - Fix stack canary                                                             
  - Get completely rid of MAXPHYSMEM configs                                     
  - Add documentation

Alexandre Ghiti (10):
  riscv: Allow to dynamically define VA_BITS
  riscv: Get rid of MAXPHYSMEM configs
  asm-generic: Prepare for riscv use of pud_alloc_one and pud_free
  riscv: Implement sv48 support
  riscv: Use pgtable_l4_enabled to output mmu_type in cpuinfo
  riscv: Explicit comment about user virtual address space size
  riscv: Improve virtual kernel memory layout dump
  Documentation: riscv: Add sv48 description to VM layout
  riscv: Initialize thread pointer before calling C functions
  riscv: Allow user to downgrade to sv39 when hw supports sv48

 Documentation/riscv/vm-layout.rst             |  36 ++
 arch/riscv/Kconfig                            |  35 +-
 arch/riscv/configs/nommu_k210_defconfig       |   1 -
 .../riscv/configs/nommu_k210_sdcard_defconfig |   1 -
 arch/riscv/configs/nommu_virt_defconfig       |   1 -
 arch/riscv/include/asm/csr.h                  |   3 +-
 arch/riscv/include/asm/fixmap.h               |   1 +
 arch/riscv/include/asm/kasan.h                |   2 +-
 arch/riscv/include/asm/page.h                 |  10 +
 arch/riscv/include/asm/pgalloc.h              |  40 +++
 arch/riscv/include/asm/pgtable-64.h           | 108 +++++-
 arch/riscv/include/asm/pgtable.h              |  30 +-
 arch/riscv/include/asm/sparsemem.h            |   6 +-
 arch/riscv/kernel/cpu.c                       |  23 +-
 arch/riscv/kernel/head.S                      |   4 +-
 arch/riscv/mm/context.c                       |   4 +-
 arch/riscv/mm/init.c                          | 323 +++++++++++++++---
 arch/riscv/mm/kasan_init.c                    |  91 +++--
 drivers/firmware/efi/libstub/efi-stub.c       |   2 +
 include/asm-generic/pgalloc.h                 |  24 +-
 include/linux/sizes.h                         |   1 +
 21 files changed, 615 insertions(+), 131 deletions(-)

-- 
2.30.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210929145113.1935778-1-alexandre.ghiti%40canonical.com.
