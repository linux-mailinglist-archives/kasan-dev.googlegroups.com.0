Return-Path: <kasan-dev+bncBDAOJ6534YNBBWVO4LCAMGQE46U2JKY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x339.google.com (mail-wm1-x339.google.com [IPv6:2a00:1450:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id A338DB1FA03
	for <lists+kasan-dev@lfdr.de>; Sun, 10 Aug 2025 14:58:03 +0200 (CEST)
Received: by mail-wm1-x339.google.com with SMTP id 5b1f17b1804b1-4595cfed9f4sf14621145e9.1
        for <lists+kasan-dev@lfdr.de>; Sun, 10 Aug 2025 05:58:03 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1754830683; cv=pass;
        d=google.com; s=arc-20240605;
        b=L5ow5fcyxw0sJk3fL9xb5uv8j4zqjJCMXb/oIkbCbHA00nJJ09u78agkn3PGuWam3a
         tFMUu9+NWUWT8MM3kLrMpo25zBXYbqkSNtmkqJwrP0VrHGGmlWL2WW5O+Mg7v+u1Wu3X
         nFIzW4bk92yK338GyERw7I7L7l7upIP1/dzpyv1gaLx2DvXwHskRfgIq3SEPbfNORPls
         xbh3V3Dy/W97ex/l2EdIOnp71E2lmtk38aRr30oDaXz45BpLn/S//0MrIVP3UO3hXzW8
         lFfHXdxDhayQiTe+CYrIgWNwWPv/8vr9C7EI5dDkbggJVNRmsUEicMQLU4NoczjM2vbV
         PHlA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature:dkim-signature;
        bh=wxAK2l/BgNtyijCFV/V0jFgJf3RG3QAvbWz7VzaOILo=;
        fh=QYM7Nhg31HES+5NeyFLlzsUusSvsINby1nOISGjOR+I=;
        b=Dippfxuh861GHt2cvcNteaeUoWURnkhjANqg0GEur2Sbn5aEv/FspRhwHBV+DZYSVB
         M7O8VsYqL8CfwlILNY7WmLA9Qn+8F6AyIz1pl7M+paR7qdzRmt9Cc9x8EvPV/pzZGWfn
         SSXmM+SNNEoPR1fMytzDWSCIjfS6h/QqxnJJiS8mwwlHlIss99RFehDGabsKA5BN8iXk
         0sCa8cadlRu6tip98GbF2rsdTp5Lp8OaFgVUS6UlIT15Z8paln3vc/+T7ac8ZpjYNVnq
         PfIo8DV4KQ4DPA1fMHWY3W4JSuWZF6hexEbhBxhhhx/QTIK7TLHFqCr2b93BtJR7aVtP
         S1XA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=IFLwTRDq;
       spf=pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::12e as permitted sender) smtp.mailfrom=snovitoll@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1754830683; x=1755435483; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=wxAK2l/BgNtyijCFV/V0jFgJf3RG3QAvbWz7VzaOILo=;
        b=ooGSrG83G3kW9hK3tUZdX2awFzzx99uCFBCJK3QoP7u7dhiOiP+sdAaSWDCWGKl2LJ
         K/6GQk/dQ/eYfbdrOBW9OTOzKKTgky6ZidhMb+tWQ9vYaTwd5aSvuMgdW6ti9XUvOWvN
         YVcQBa/Wo/NrmJROY9IRLbBP6HrbhmlEJeiKXisLmyq+/R74KLX41UkpK5/Je7qkIyZI
         qz5wzC8at++3ujcINQVmQb1Ge6xCmyXs1IF0oVFFdj+W/ZPAlGRK0UpypRq8iZruNLdT
         LiNwHU0bxImSiSVsfl8XXyCvxW6++NPVirLzUbCPrnyr9NG4tZOQsjbrQP1gCqtG2eLS
         Au4A==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1754830683; x=1755435483; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :from:to:cc:subject:date:message-id:reply-to;
        bh=wxAK2l/BgNtyijCFV/V0jFgJf3RG3QAvbWz7VzaOILo=;
        b=VtWgBCsVjJvVAcpvb9pWqxfcS+Xaeb7Cm1XIbRcw57X4+woa5zwhRK5Aw/bfBCvyjO
         flbcakmBTk/ii8nhH064tVWYvAjb1sZO2RueNeZjWW/bF2eU5s/Zp4c/ohvwF56asafe
         zmYBh0YCQcEIvnrVgLtupdbAUqJmpn8Zpaa+Qfa/HsTGNd6avIqXH+qVv7ynP9w8Fq/p
         8uAXTFgf6yzGHJ1v1SFO2ntJnoexLlaNKJl+cKVRc3W3YpdSNVpLD7Sv7pjA00gQ5VII
         IFNUdrRH4/qP3qDKOPeK0Xtt7SSwxDJ7covPe/gLkQhITyHXEj+VoT2TNTnOrvHCVjMd
         gVug==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1754830683; x=1755435483;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=wxAK2l/BgNtyijCFV/V0jFgJf3RG3QAvbWz7VzaOILo=;
        b=wob+RFhHTrYCsMevQKuoXefUMdfTodSYzylzIAsY9gC4E1Wejvsw5wV/iS0L1dRhdV
         67uROx8zmYCRmaSLpQybACKb7+6fQGk6uPtWMLDgMJL9AlED4cI5iyBB2vUN21RvW2rQ
         yv1piB/4v+ql0tdmV973mUOKQIuaIR8z4u8qtcUXfeNET5m04L/+8SoqfvlKlG9sAVMv
         v2G02sXypVIGSezNzvJwcbDvzCX9j4wgAWFFQl9u1w6AZp1Xd+gAkKy0O1hG2VSTNuKI
         F9ecADy9m7PZRSLcpcLWSj8qVaKPfjJ93AX01QAAu1cX7ha9qpA56BKTtnAcqzxZZozl
         E5XA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXQuDzlLshIDN51g14xdjWnab55W1ug2C76hqsKkJINn0a9ypwWwLXXQTO/fhlTBR1Ai2d2fA==@lfdr.de
X-Gm-Message-State: AOJu0YydDRvTpY1o2ziqf5I4yApV+xPGrca0MQc9MVnnCxhx77iXxB2p
	qHBSxu+F8S7y8iz275jV2rPvkkBvcxDnDaZvaN3cNJGGgU6NOFOFcvzT
X-Google-Smtp-Source: AGHT+IEiFkNTYcgc0i9Ov4GT5r8QNcO/q9EaAUEPQ7/3490k7r3eIhR4N8VwOBqk0V59EUCd3g//eQ==
X-Received: by 2002:a05:600c:1c05:b0:456:24aa:9586 with SMTP id 5b1f17b1804b1-459f4f9bd29mr66343655e9.21.1754830682953;
        Sun, 10 Aug 2025 05:58:02 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZc7QMSS4sxa+j5XtIfcuiKOS1B88PyK2LYaKYfvb9BbMA==
Received: by 2002:a05:600c:1551:b0:43c:ec03:5dc5 with SMTP id
 5b1f17b1804b1-459ee3ab03fls21465375e9.2.-pod-prod-01-eu; Sun, 10 Aug 2025
 05:58:00 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXQXTJlESWeEO2sI2Wy/lcQ8XN1B4hmvh1m4S1ZO9zsRKeKFp/7OYffi/uyxHPriDy3lmOjoZH7igM=@googlegroups.com
X-Received: by 2002:a05:600c:b95:b0:459:e025:8c5a with SMTP id 5b1f17b1804b1-45a039a965bmr20833395e9.33.1754830680405;
        Sun, 10 Aug 2025 05:58:00 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1754830680; cv=none;
        d=google.com; s=arc-20240605;
        b=AoTGP2Zu4QtvuQYVlgp1izZksJXAIgM9j3xIiQjZ0XD86gzftfk99DhbS54neHW4kd
         HvQdyIgzpzy5PPT1Ve6hSRMPYYLR6fu3+JKBKLXn6hClmi6NprAi6tNhTkAqWVs64tgB
         IhkL4O7TAtTpWtahyX8s0v2v8jhHpmt44IRuXiFeKzqWD/cS3qZ6CD9izQkPEkgbUqj8
         Zjxavy2FeFmEziR145Kygm0JDQQ9BhxVUfifxKbE/Uc2T4jjwbV4pUua4ZpsFpwQNVX7
         5phWjrSIq0X4UbCD9UPqrT/tyv03qRrFnAUnt61KpGUgeoEEbS6e/nuVS2BWOXyD+HUB
         C27A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=fLpTR6tAuSk7MmdRr1bx3cY7Ji1Fi9DhOlpvPdNYklM=;
        fh=FoxGTgI/kklWq/X1kPUcUs9sqL81ikocUc3ewhXxZEE=;
        b=Nk5vSLbrKPNfu6pvdGuMymTXydzrOfSfX5LVRJ4/Q512bEAwPc9EQCnB5XPmAwRlRg
         +uqY0pH3XwcR/f2Nl6BFGBRDlEH+fpd/KCV2mU/bgHiDyV1ut4mUYJjGR6Ez8LSDUMI/
         ZK6UJ7YSQNyaehHUecb+WaDJn4+gFAIwPvy0/4Un1OnCXRk21/RD0wxVVF4p549iJqrI
         iE8EPyWFJouXds7VkuWQQe+V0QhR3WIlxbEbQgexa8XxzPDh014W7m5Bvta11AHGd2N9
         6NcSOGUc34jWEd4D337gvz5odoLmWwOugeptBYSJL23MIqkdTnph8nnTJMHECNdEb34+
         cR4Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=IFLwTRDq;
       spf=pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::12e as permitted sender) smtp.mailfrom=snovitoll@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-lf1-x12e.google.com (mail-lf1-x12e.google.com. [2a00:1450:4864:20::12e])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-458b75c5450si4188015e9.0.2025.08.10.05.58.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 10 Aug 2025 05:58:00 -0700 (PDT)
Received-SPF: pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::12e as permitted sender) client-ip=2a00:1450:4864:20::12e;
Received: by mail-lf1-x12e.google.com with SMTP id 2adb3069b0e04-55b88369530so3762223e87.0
        for <kasan-dev@googlegroups.com>; Sun, 10 Aug 2025 05:58:00 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUsixsiBvB3mzhI3X4sIqPOrVXWxeMyXc5Oly62GhCfW0UyCLVDALtGfaiOkQ0UEm2Uc5rRnHOqUMI=@googlegroups.com
X-Gm-Gg: ASbGncu+wZ1blTjF3gAqUUnz1Z9LNhncvWwa+FgwOfN8RPrudR7W6TOR/7uCdeM2Lo/
	M+8nXqfOo54XjriI2HgQatKDnD3ciAuzogG++wdeNZ2MRmx1Lj71NCI166rM/chIE7hw8psQ35/
	M+MLW0mIHuJ5yOKGuhx8HCvK5GCuEFLTa6xdrY0M6RC75XoLlJiGtlStPOaL5rbZ5i4dDSM6hjE
	/trcCLGSpC4E7tsrRkTg7IyUa48Fj0YW6O09zY/mts5fFOjcusldSIXisi5cqRAz2wV4S2cGq1P
	O/83wel5GwxXUi7GJc/2nrmFSBCEJYtW8r7LumiAG0ayB4nIwAMbbI6VQsJydbS7zk6X1/EKPGV
	3InB+4MBHMN2DRFx0mYTsNz3uKEksc1dWucRbww==
X-Received: by 2002:a05:6512:2313:b0:55b:8397:cffd with SMTP id 2adb3069b0e04-55cc00ada77mr2589766e87.9.1754830679327;
        Sun, 10 Aug 2025 05:57:59 -0700 (PDT)
Received: from localhost.localdomain ([2a03:32c0:2e:37dd:bfc4:9fdc:ddc6:5962])
        by smtp.gmail.com with ESMTPSA id 2adb3069b0e04-55b88c9908esm3804561e87.76.2025.08.10.05.57.53
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sun, 10 Aug 2025 05:57:58 -0700 (PDT)
From: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
To: ryabinin.a.a@gmail.com,
	christophe.leroy@csgroup.eu,
	bhe@redhat.com,
	hca@linux.ibm.com,
	andreyknvl@gmail.com,
	akpm@linux-foundation.org,
	zhangqing@loongson.cn,
	chenhuacai@loongson.cn,
	davidgow@google.com,
	glider@google.com,
	dvyukov@google.com,
	alexghiti@rivosinc.com
Cc: alex@ghiti.fr,
	agordeev@linux.ibm.com,
	vincenzo.frascino@arm.com,
	elver@google.com,
	kasan-dev@googlegroups.com,
	linux-arm-kernel@lists.infradead.org,
	linux-kernel@vger.kernel.org,
	loongarch@lists.linux.dev,
	linuxppc-dev@lists.ozlabs.org,
	linux-riscv@lists.infradead.org,
	linux-s390@vger.kernel.org,
	linux-um@lists.infradead.org,
	linux-mm@kvack.org,
	snovitoll@gmail.com
Subject: [PATCH v6 0/2] kasan: unify kasan_enabled() and remove arch-specific implementations
Date: Sun, 10 Aug 2025 17:57:44 +0500
Message-Id: <20250810125746.1105476-1-snovitoll@gmail.com>
X-Mailer: git-send-email 2.34.1
MIME-Version: 1.0
X-Original-Sender: snovitoll@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=IFLwTRDq;       spf=pass
 (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::12e
 as permitted sender) smtp.mailfrom=snovitoll@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;       dara=pass header.i=@googlegroups.com
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

This patch series addresses the fragmentation in KASAN initialization
across architectures by introducing a unified approach that eliminates
duplicate static keys and arch-specific kasan_arch_is_ready()
implementations.

The core issue is that different architectures have inconsistent approaches
to KASAN readiness tracking:
- PowerPC, LoongArch, and UML arch, each implement own kasan_arch_is_ready()
- Only HW_TAGS mode had a unified static key (kasan_flag_enabled)
- Generic and SW_TAGS modes relied on arch-specific solutions
  or always-on behavior

Changes in v6:
- Call kasan_init_generic() in arch/riscv _after_ local_flush_tlb_all()
- Added more details in git commit message
- Fixed commenting format per coding style in UML (Christophe Leroy)
- Changed exporting to GPL for kasan_flag_enabled (Christophe Leroy)
- Converted ARCH_DEFER_KASAN to def_bool depending on KASAN to avoid
        arch users to have `if KASAN` condition (Christophe Leroy)
- Forgot to add __init for kasan_init in UML

Changes in v5:
- Unified patches where arch (powerpc, UML, loongarch) selects
  ARCH_DEFER_KASAN in the first patch not to break
  bisectability. So in v5 we have 2 patches now in the series instead of 9.
- Removed kasan_arch_is_ready completely as there is no user
- Removed __wrappers in v4, left only those where it's necessary
  due to different implementations

Tested on:
- powerpc - selects ARCH_DEFER_KASAN
Built ppc64_defconfig (PPC_BOOK3S_64) - OK
Booted via qemu-system-ppc64 - OK

I have not tested in v4 powerpc without KASAN enabled.

In v4 arch/powerpc/Kconfig it was:
	select ARCH_DEFER_KASAN			if PPC_RADIX_MMU

and compiling with ppc64_defconfig caused:
  lib/stackdepot.o:(__jump_table+0x8): undefined reference to `kasan_flag_enabled'

I have fixed it in v5 via adding KASAN condition:
	select ARCH_DEFER_KASAN			if KASAN && PPC_RADIX_MMU

- um - selects ARCH_DEFER_KASAN

KASAN_GENERIC && KASAN_INLINE && STATIC_LINK
	Before:
		In file included from mm/kasan/common.c:32:
		mm/kasan/kasan.h:550:2: error: #error kasan_arch_is_ready only works in KASAN generic outline mode!
		550 | #error kasan_arch_is_ready only works in KASAN generic outline mode

	After (with auto-selected ARCH_DEFER_KASAN):
		./arch/um/include/asm/kasan.h:29:2: error: #error UML does not work in KASAN_INLINE mode with STATIC_LINK enabled!
		29 | #error UML does not work in KASAN_INLINE mode with STATIC_LINK enabled!

KASAN_GENERIC && KASAN_OUTLINE && STATIC_LINK && 
	Before:
		./linux boots.

	After (with auto-selected ARCH_DEFER_KASAN):
		./linux boots.

KASAN_GENERIC && KASAN_OUTLINE && !STATIC_LINK
	Before:
		./linux boots

	After (with auto-disabled !ARCH_DEFER_KASAN):
		./linux boots

- loongarch - selects ARCH_DEFER_KASAN
Built defconfig with KASAN_GENERIC - OK
Haven't tested the boot. Asking Loongarch developers to verify - N/A
But should be good, since Loongarch does not have specific "kasan_init()"
call like UML does. It selects ARCH_DEFER_KASAN and calls kasan_init()
in the end of setup_arch() after jump_label_init().

Previous v5 thread: https://lore.kernel.org/all/20250807194012.631367-1-snovitoll@gmail.com/
Previous v4 thread: https://lore.kernel.org/all/20250805142622.560992-1-snovitoll@gmail.com/
Previous v3 thread: https://lore.kernel.org/all/20250717142732.292822-1-snovitoll@gmail.com/
Previous v2 thread: https://lore.kernel.org/all/20250626153147.145312-1-snovitoll@gmail.com/

Sabyrzhan Tasbolatov (2):
  kasan: introduce ARCH_DEFER_KASAN and unify static key across modes
  kasan: call kasan_init_generic in kasan_init

 arch/arm/mm/kasan_init.c               |  2 +-
 arch/arm64/mm/kasan_init.c             |  4 +---
 arch/loongarch/Kconfig                 |  1 +
 arch/loongarch/include/asm/kasan.h     |  7 ------
 arch/loongarch/mm/kasan_init.c         |  8 +++----
 arch/powerpc/Kconfig                   |  1 +
 arch/powerpc/include/asm/kasan.h       | 12 ----------
 arch/powerpc/mm/kasan/init_32.c        |  2 +-
 arch/powerpc/mm/kasan/init_book3e_64.c |  2 +-
 arch/powerpc/mm/kasan/init_book3s_64.c |  6 +----
 arch/riscv/mm/kasan_init.c             |  1 +
 arch/s390/kernel/early.c               |  3 ++-
 arch/um/Kconfig                        |  1 +
 arch/um/include/asm/kasan.h            |  5 ++--
 arch/um/kernel/mem.c                   | 13 ++++++++---
 arch/x86/mm/kasan_init_64.c            |  2 +-
 arch/xtensa/mm/kasan_init.c            |  2 +-
 include/linux/kasan-enabled.h          | 32 ++++++++++++++++++--------
 include/linux/kasan.h                  |  6 +++++
 lib/Kconfig.kasan                      | 12 ++++++++++
 mm/kasan/common.c                      | 17 ++++++++++----
 mm/kasan/generic.c                     | 19 +++++++++++----
 mm/kasan/hw_tags.c                     |  9 +-------
 mm/kasan/kasan.h                       |  8 ++++++-
 mm/kasan/shadow.c                      | 12 +++++-----
 mm/kasan/sw_tags.c                     |  1 +
 mm/kasan/tags.c                        |  2 +-
 27 files changed, 113 insertions(+), 77 deletions(-)

-- 
2.34.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250810125746.1105476-1-snovitoll%40gmail.com.
