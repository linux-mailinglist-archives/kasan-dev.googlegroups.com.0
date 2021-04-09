Return-Path: <kasan-dev+bncBC447XVYUEMRB5XBX6BQMGQED43SS2I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23a.google.com (mail-lj1-x23a.google.com [IPv6:2a00:1450:4864:20::23a])
	by mail.lfdr.de (Postfix) with ESMTPS id 55025359538
	for <lists+kasan-dev@lfdr.de>; Fri,  9 Apr 2021 08:15:19 +0200 (CEST)
Received: by mail-lj1-x23a.google.com with SMTP id w13sf804210ljd.2
        for <lists+kasan-dev@lfdr.de>; Thu, 08 Apr 2021 23:15:19 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1617948918; cv=pass;
        d=google.com; s=arc-20160816;
        b=AvUYwrWuEyBC8OrPSnw1KWijbcrOmQD8uOsZV/ulgPsGP54YVUU1eZY78KcV5LUxbM
         oDVOWX9kctglLW16FNeVnZYXqegbqfWPTlT59/RrTRmSpTGmzL3D9KEawiYchMHs+GEx
         47ON7h27rbQ9s1ogBxXWT7d+roAwDyDnJ4yiPxhIS/Yx1gBNVdOInZgOrjNDo0T83TNU
         Xxmciw6enW2zyDJxCXI2zIE/Nu9JTHkAp2AvN5GVj53+eMS+YMroJY1cCLJpRi3i/SpG
         9raXT23kvzE7Sec9xI6NerSD1QJ2fT83nyETBajdera+Xs/0287RxkHRFFVIuyIv9M5v
         KqsA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=YshyOubZC/SdcIRvzc2yy7XzDViANwh1ViSjRkZcIAI=;
        b=rlErONBIcLYtm1E0rREG4I3ibjNOtss9IzboUdvYCSx1P2RyGNCKUTK7PbTGEFT7ge
         TpWL8HCeb5FJtbQ11SssqHwyvuAKHJjU1t0DCy1/fUYJsDuVf+GX0udfoOwS2Zc/3Nko
         eSthZed7jm1aOsqq2EsNKqlzvq+DSpF+ZYAHbqoTBGBdV2XnslafUiDkyBOKeoNkJ3iL
         gJysbzcA9aBDLTm5egVAgEDljs9oS14sPPJDW+xjAQwvzrVCJ4Idkk6BUPc5y0kcrgAE
         NJNHj+uM67p/kVkas4shGbS8TzJCdLPLPUs9/0b6zevwoTMky5pjW5iQPyPJ6J0hsH/D
         E+Fw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=neutral (google.com: 217.70.178.231 is neither permitted nor denied by best guess record for domain of alex@ghiti.fr) smtp.mailfrom=alex@ghiti.fr
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=YshyOubZC/SdcIRvzc2yy7XzDViANwh1ViSjRkZcIAI=;
        b=TuWn6+uqQsHVQMG6ZVqOM501iDAeUqQOL4GOKiyZd5nG76C9BT3hz/mXgrx8rMxP94
         fW2jIipwGqKptvsu4qqognZtthKdrDVH0NypdpiP0miQ+FiP4cTYaDWUx70tDmjbCLjP
         qep2pEEq6CCyp+9VmStpzCP4H/D16FQf14QYlCnyceSh8AQMLgiclPP4qfKgNWOwC1QL
         2MLY4vHLY4MOkq3VW70S0xwAF/2uiLig0ZgqbKs42K2bbUbEGNGnOy6y+E6DFmglh/ci
         U6PYwWmwJH2qqYP3nh+fmQcPYK1qArbHJ7SKhbRe5aZJELbAUsguiVvkXAng31j0UEoD
         x2Cg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=YshyOubZC/SdcIRvzc2yy7XzDViANwh1ViSjRkZcIAI=;
        b=eBNE3IziRmREF2ccmIIm2E+9EVJBE/oMOY921ygas4KX7gogmkO28+TKcFfcqq3th+
         Jf6e3KE7AJ7pza5pCt8d4H8irYd1r+uk2eAXPBSdr060HzvNCn/9OJreryvKRTbpXW+c
         ASHJ2I/NBGNgJonwZEyefBCOauU8iSx2EBZz8JCMgHnwvlQCRi6qEdqllwEpW6zY8b09
         XBkvqlW1sRIVmUtvqMWfp6QVmcPrIu8KPDdDsYQvLwSJmRs4ra63sKvVQencZ8P21qyx
         P+6dtxUIHTZTtYJEL93GpKQ3tHfKoDFNmlJH4ltfN/OPLMXlkxYyfecHicIWJquZLsmO
         m6bg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530y9mSEPdtlQ1z/1+iSDCVkNmawmCk5TsUgLODKfgEhqfhA2RAP
	t7CJ14PbuNNaGNb/EYrmHb8=
X-Google-Smtp-Source: ABdhPJysGBdRBzYSpgTreF4p2dLGFmDzQirD+Prjl0sOydpzkzSm1b0vBkmHOQqjiQTKbne5a1ZYGQ==
X-Received: by 2002:a19:f518:: with SMTP id j24mr1636162lfb.225.1617948918775;
        Thu, 08 Apr 2021 23:15:18 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:8503:: with SMTP id j3ls1861814lji.6.gmail; Thu, 08 Apr
 2021 23:15:17 -0700 (PDT)
X-Received: by 2002:a2e:8591:: with SMTP id b17mr8306821lji.230.1617948917793;
        Thu, 08 Apr 2021 23:15:17 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1617948917; cv=none;
        d=google.com; s=arc-20160816;
        b=y5d/TrNuIi2IMvfkbyY2nd7RoEARWgqXU9ETu6zqkRN47pGaZhOfTI8nibAz4oLq2X
         3jaSLSpEhlrnqckqEOTQI85S+77LMlsXKsOWvisBGz+Hhx731K4+REUJ4cQUjPxW5Uz6
         NMgMQYWPk4cO29rN4r69LA5ZT6EeM8osYPwDczb9gWcTxHdWtGyHycbuo1AY3PlFxMjC
         AP6kO3+Ugg71OyYkCbzflAcxFFmHr0sjdSps7K5HUHo0nDvg7BCL9Yr3ZRBT3X3klctT
         joEFJxVt6sGIWFZGCVJV2IQqBmpmX0rTyGl7N/08ub3N2nOiLHzyKoQHdJ1vhnXPRIQG
         0nnw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from;
        bh=t1XDqrfettaMHMldrJ1+jyYUR3sNWfGpqVm046M5KdA=;
        b=gNG25w5tDhOm1lA+dDlHzTQK3HFoYDTDoy/iZZwWX44CfCkalkfahlkULiWr4yUy7J
         zYn48kyU/dFpCBHbtYYMc2YRpzMNRuAL5Fbb6RvjGqnuxlAwubB7TgvnUDZQgJFIGn1k
         1YX2sxsMksapEOs+xTN04ZMTwybjTiF/HTX3F4C9oWrbo+1jKMaQCKnsrd9IWxc+iAUV
         0kDfvT7mV0CHKfyX3A4oGVybPspaXaB1QTF8B6c0DzHjfKqxc7URZK08djrx5N85JEaH
         ZqSsCLhmf0FJRrp1V1lqYDReGWlNSzcsMrW/i/U47y8FTzcvCw+CUE0AMYdjyNs+JRIx
         66Sw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=neutral (google.com: 217.70.178.231 is neither permitted nor denied by best guess record for domain of alex@ghiti.fr) smtp.mailfrom=alex@ghiti.fr
Received: from relay11.mail.gandi.net (relay11.mail.gandi.net. [217.70.178.231])
        by gmr-mx.google.com with ESMTPS id 63si126243lfd.1.2021.04.08.23.15.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Thu, 08 Apr 2021 23:15:17 -0700 (PDT)
Received-SPF: neutral (google.com: 217.70.178.231 is neither permitted nor denied by best guess record for domain of alex@ghiti.fr) client-ip=217.70.178.231;
Received: from localhost.localdomain (105.169.185.81.rev.sfr.net [81.185.169.105])
	(Authenticated sender: alex@ghiti.fr)
	by relay11.mail.gandi.net (Postfix) with ESMTPSA id 8D27D10000B;
	Fri,  9 Apr 2021 06:15:12 +0000 (UTC)
From: Alexandre Ghiti <alex@ghiti.fr>
To: Jonathan Corbet <corbet@lwn.net>,
	Paul Walmsley <paul.walmsley@sifive.com>,
	Palmer Dabbelt <palmer@dabbelt.com>,
	Albert Ou <aou@eecs.berkeley.edu>,
	Arnd Bergmann <arnd@arndb.de>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	linux-doc@vger.kernel.org,
	linux-riscv@lists.infradead.org,
	linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	linux-arch@vger.kernel.org,
	linux-mm@kvack.org
Cc: Alexandre Ghiti <alex@ghiti.fr>
Subject: [PATCH v4 0/3] Move kernel mapping outside the linear mapping
Date: Fri,  9 Apr 2021 02:14:57 -0400
Message-Id: <20210409061500.14673-1-alex@ghiti.fr>
X-Mailer: git-send-email 2.20.1
MIME-Version: 1.0
X-Original-Sender: alex@ghiti.fr
X-Original-Authentication-Results: gmr-mx.google.com;       spf=neutral
 (google.com: 217.70.178.231 is neither permitted nor denied by best guess
 record for domain of alex@ghiti.fr) smtp.mailfrom=alex@ghiti.fr
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

I decided to split sv48 support in small series to ease the review.

This patchset pushes the kernel mapping (modules and BPF too) to the last
4GB of the 64bit address space, this allows to:
- implement relocatable kernel (that will come later in another
  patchset) that requires to move the kernel mapping out of the linear
  mapping to avoid to copy the kernel at a different physical address.
- have a single kernel that is not relocatable (and then that avoids the
  performance penalty imposed by PIC kernel) for both sv39 and sv48.

The first patch implements this behaviour, the second patch introduces a
documentation that describes the virtual address space layout of the 64bit
kernel and the last patch is taken from my sv48 series where I simply added
the dump of the modules/kernel/BPF mapping.

I removed the Reviewed-by on the first patch since it changed enough from
last time and deserves a second look.

Changes in v4:
- Fix BUILTIN_DTB since we used __va to obtain the virtual address of the
  builtin DTB which returns a linear mapping address, and then we use
  this address before setup_vm_final installs the linear mapping: this
  is not possible anymore since the kernel does not lie inside the
  linear mapping anymore.

Changes in v3:
- Fix broken nommu build as reported by kernel test robot by protecting
  the kernel mapping only in 64BIT and MMU configs, by reverting the
  introduction of load_sz_pmd and by not exporting load_sz/load_pa anymore
  since they were not initialized in nommu config. 

Changes in v2:
- Fix documentation about direct mapping size which is 124GB instead
  of 126GB.
- Fix SPDX missing header in documentation.
- Fix another checkpatch warning about EXPORT_SYMBOL which was not
  directly below variable declaration.

Alexandre Ghiti (3):
  riscv: Move kernel mapping outside of linear mapping
  Documentation: riscv: Add documentation that describes the VM layout
  riscv: Prepare ptdump for vm layout dynamic addresses

Alexandre Ghiti (3):
  riscv: Move kernel mapping outside of linear mapping
  Documentation: riscv: Add documentation that describes the VM layout
  riscv: Prepare ptdump for vm layout dynamic addresses

 Documentation/riscv/index.rst       |  1 +
 Documentation/riscv/vm-layout.rst   | 63 +++++++++++++++++++++
 arch/riscv/boot/loader.lds.S        |  3 +-
 arch/riscv/include/asm/page.h       | 17 +++++-
 arch/riscv/include/asm/pgtable.h    | 37 ++++++++----
 arch/riscv/include/asm/set_memory.h |  1 +
 arch/riscv/kernel/head.S            |  3 +-
 arch/riscv/kernel/module.c          |  6 +-
 arch/riscv/kernel/setup.c           |  5 ++
 arch/riscv/kernel/vmlinux.lds.S     |  3 +-
 arch/riscv/mm/fault.c               | 13 +++++
 arch/riscv/mm/init.c                | 87 ++++++++++++++++++++++-------
 arch/riscv/mm/kasan_init.c          |  9 +++
 arch/riscv/mm/physaddr.c            |  2 +-
 arch/riscv/mm/ptdump.c              | 67 ++++++++++++++++++----
 15 files changed, 265 insertions(+), 52 deletions(-)
 create mode 100644 Documentation/riscv/vm-layout.rst

-- 
2.20.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210409061500.14673-1-alex%40ghiti.fr.
