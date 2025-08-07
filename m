Return-Path: <kasan-dev+bncBDAOJ6534YNBBJUC2TCAMGQE5PGNOBY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53e.google.com (mail-ed1-x53e.google.com [IPv6:2a00:1450:4864:20::53e])
	by mail.lfdr.de (Postfix) with ESMTPS id 61818B1DD8A
	for <lists+kasan-dev@lfdr.de>; Thu,  7 Aug 2025 21:40:24 +0200 (CEST)
Received: by mail-ed1-x53e.google.com with SMTP id 4fb4d7f45d1cf-617b497501esf1379990a12.3
        for <lists+kasan-dev@lfdr.de>; Thu, 07 Aug 2025 12:40:24 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1754595624; cv=pass;
        d=google.com; s=arc-20240605;
        b=bjKkcXUd7mF23l7PDPdWYNzoTsDbDoigCivoPl9o8LBKxdXYv4+flNxy94gup/Zs4T
         jnl/zkw+LpRmu52Oqb7lqdh1/G9Y1kDeUT7kxgNQkCUQAfCpUV33aE/pXK0p0Gb8qEGN
         zRcVeYmQbyVcb5qZdo8iGd7vLbEWimRPKGus+WDwIvCUzd1p6KpL5cMkaM6xwRcbRn3V
         l0X0548+NBzxzuafY26FYsC1uBdAvzoMpuzSQHCAvFLkikg6mF313prt3CPos9FOmUoq
         2x0UG5i9thJ2rRCwPtycrojt6Uy8e0baIaawQCm/PAUXG1v2VZeOGQbN2lEXLjb1xs/z
         qemA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature:dkim-signature;
        bh=tee2nW6m/FaC+OYe5nyKKR6saN0KtV65dUv77mINOmg=;
        fh=uAd9Q8R9HxDQaI69Ty9S7bXmgN+61eAOSFT2QXJWBMc=;
        b=YOahVfUzSw5mZ3gAL9lIIrud6pjyV54YISA+fW2arhW8WCv7aYrcchB/fYVqcn4elL
         P1g92/ceeMkZk4rWX4cuPVmvJRHx6c7+OTmDG/uIGspreGq/Z1tVxNFoDL1PEZ8VniFJ
         pXRnLNY5j6dR5JjUtxWTwiFHRYnhgzsokramWt8z/xlu7EhA8IqY9lsQxfNzs9yjlduk
         1ooBkLw9T2rKmz98pQX/A5mbzALrWmPXb4jIZhS66+LWjrcvA+fy4nsuqcZZOH0uAiqe
         NiamPnkc774lucChS5Wotu1jMOGQ42bRfBn9CdLXqL7OxEYsAL8+aAW+nkHyvNMOicKt
         S0sA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=L9Z2Vhj4;
       spf=pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::134 as permitted sender) smtp.mailfrom=snovitoll@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1754595624; x=1755200424; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=tee2nW6m/FaC+OYe5nyKKR6saN0KtV65dUv77mINOmg=;
        b=WCNs7aiFtjyB5YKDa+Hmk+Z15DU2pzn+zh8AgbVxh4og4dPLQtNLR+6jMfQ/OjTcvc
         Oj6OlCK1Fktt8q8yWXIRxgJ777YyQNkOGvcFOCnkpCEgdzosChPWwcYqig1wtZnlnUQG
         iKzq9pGsHba+AecIETKpqNgKmIO3pRrUkepGbd6LJxnOoUVvUOqS1vTCozT/oH2xKzSV
         Pf3UsRhbPkCOofnQusjaFpMQQdvCh2EHE9riFH9cIY3T8G3Gy+ShDEU/bqw7spu5yql2
         3fxQVoqyo6g2j47jGw4vNa4gmeNfAxKlmpmn7xiK1QI777z1WEDuxyM9KkZJfVEyskJt
         o68A==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1754595624; x=1755200424; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :from:to:cc:subject:date:message-id:reply-to;
        bh=tee2nW6m/FaC+OYe5nyKKR6saN0KtV65dUv77mINOmg=;
        b=KhHgUZ48fcp3gVTjtA7uqqssBTBBKjMaqXhMmZSX6arNmq7Hl3euIOM0OvbJdytu4b
         FSNgcDy/hK2M7+Gr1emwMdhQTa0S/17IKmm9jDIsdHcIwPE5S9KM3H7uaAJg75Yxg65V
         F5jUI3LYN59vxFuK/yjsUS2bq/8vxtCU0RJuXrr1AxnCWMFd6LweY9jhcOl/ycp+1U89
         MUWE9BLIk3z4FUmPykyGZwoIIZd49nuWUmiNC1R76xu1BRPEh0ies60z+O1x782BHX6g
         sbMgreWv0z25I0kUNUuhv5kP/JIucFQSw8iSZkbvDwy6E9Tl7zeRRWTSDmJeZormpJoy
         oCHw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1754595624; x=1755200424;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=tee2nW6m/FaC+OYe5nyKKR6saN0KtV65dUv77mINOmg=;
        b=Epyo9CHtDuysaysg/+s4A/R0sRzaUaph/2KW1O1zhifFJAuOKHEOVmWVPc9Dsqy42v
         i2sYFh0mNk1beu1YXxBY5sk1eIqxCZHeAEs7wFgH6+uao1UJBztOGKE+U0/3fczRfPF1
         o6ozgXD4tMnFaPliUDAmvWkG6y6h5u6a+HS3Ijiy8VYSjdQdx5bhjOFTuXVEj3olnIY7
         amYb9OQ5IuOCu9OPQ0EXtSUNiD2qT1ZLGrQuJecFC+Oy79/IXpxK0Ntfemb9le57+kpU
         umQWCLg7nbVvzeGcz6cLS/lFZafJcPCcn7jjnWYirPge2Gbsho0HZCS+r3XoWdE3b7Se
         6YMw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWtHXMd1h23vOaYRgq/lH1ZWsm5jgqUWpFebwCKw+gG8hU212d/NIl4lS7t+wgT/xu2QwUoyw==@lfdr.de
X-Gm-Message-State: AOJu0Yw6D6zizB0qOfMGSsnSaWakl4begV4a7aSjkskAXMSQdZdr98K5
	ZTQUNBqBLMQSfB8FcMtW+wq5E28EXDhbDpey0SuE5C6SDeaoo6Q/cMZN
X-Google-Smtp-Source: AGHT+IEbQi56dPeDqTONppUtWIB6iTqO/HcTs1XwgAV3D+fPGZDTMIPH3zf2glub/t6iLeukpjDhqg==
X-Received: by 2002:a05:6402:2808:b0:615:539b:7acf with SMTP id 4fb4d7f45d1cf-617e2b70974mr89265a12.2.1754595623304;
        Thu, 07 Aug 2025 12:40:23 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdagkXSO9pW2UDSvqkDyM7I4NipXl33f5hoaMjY/81bFw==
Received: by 2002:a05:6402:3488:b0:615:39c7:3951 with SMTP id
 4fb4d7f45d1cf-617b13c5970ls1978729a12.0.-pod-prod-01-eu; Thu, 07 Aug 2025
 12:40:20 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWR1us1sdYUBUq+nebftJApv8/0b3brPfr/OPYlVfoTXTL7cT3bJfM4CK3oXGfaJlOX64eqMwSSYSc=@googlegroups.com
X-Received: by 2002:a05:6402:3550:b0:617:d37c:b561 with SMTP id 4fb4d7f45d1cf-617e2e6c7a6mr75712a12.27.1754595620266;
        Thu, 07 Aug 2025 12:40:20 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1754595620; cv=none;
        d=google.com; s=arc-20240605;
        b=A3/TCv21UsiLlxnkB7pvhHFsdZec/zKUb8Ch++4/6eqswSEHAS2WnEOXKlPHLy4C9r
         pWbAe/GjLHRwcG90FWfIJSZABX285ZPwxLYxkQt+imMyLH6x4vils1MR4L6lGIBy3Kn0
         oiV69PHrDe7v6mDgkMk8mvUGQ4FfXOQ4d74w39KeHKh6lSGpJ0LaFsZhT+TWQHvtMXlY
         XvTxZPdKsS+d38CT4sLH9t2HUeg54v3ZSok8bx75gG07fQsdlvVTQz7goraEv+8k199o
         a9rYVkq8NVMbP4ULWb4kImQdT4nCT/3mZ3t232oIxf27dxsAogRpRZtnw9iLaWj3Z6DP
         Uiuw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=ZxujgbgbPZueP+pnQ5s6H3MUryeO1an975QxEYXuWHk=;
        fh=rmZdAUAXZfmCOtfk90L+fWSuyf1wrNeKPd8l66H3B6Q=;
        b=M33c8oPZ+5JuLlRSm+q1HEVg+Zi6bZkfEjKacEJHf+TSl/ICGr5rHRdxrg/caEHyBf
         TMzts9FT/Eu1QW76fGgmrzQu5c70mEj4rUL5ZbHWxN1D4EsHmLfXWv7kuWHsX5VeYFjU
         0TCqxylr2tmAtPh86S0bkrJT4iBWTuDs9FYT7waEBD7/eRI1uYFTPPpsAC6dakJ7QBgC
         fpRDMA1+aTwNFb7sg5TC2sYZ93iOHcHwtpk4AUJkdhlLJupDTzwiPVmwJ+55V6XkDiX4
         OdSGf89wspugbeFpsMH+FPlED3x1t91lPk3o41HUCdZAajfdxuUM/pQ0CvwQAVrxfL8J
         4y+g==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=L9Z2Vhj4;
       spf=pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::134 as permitted sender) smtp.mailfrom=snovitoll@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-lf1-x134.google.com (mail-lf1-x134.google.com. [2a00:1450:4864:20::134])
        by gmr-mx.google.com with ESMTPS id 4fb4d7f45d1cf-615a8f29032si579885a12.1.2025.08.07.12.40.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 07 Aug 2025 12:40:20 -0700 (PDT)
Received-SPF: pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::134 as permitted sender) client-ip=2a00:1450:4864:20::134;
Received: by mail-lf1-x134.google.com with SMTP id 2adb3069b0e04-55cbf9a78dbso107468e87.2
        for <kasan-dev@googlegroups.com>; Thu, 07 Aug 2025 12:40:20 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXfxPrTjxXOCmRSNXl9+XRtGuPelDvsj6kSft0Sr9a0e9evRZh5mFxWbtjdTBuM3UchOPTMZ6eYQc0=@googlegroups.com
X-Gm-Gg: ASbGncvI1M/X4I5un4Ul+CBEQFXqVXcLMZpm0PVQWGo+DMneS001aD0BoV8y5heL2c0
	9Xd6eHmGbIWDeb4PBYHmqUsTS+LpJ3nP9AG9OJnJ0oNBnVGLcaDDOjD0e4zb1MuupWBh5oiny0s
	q7dDEzt8f4Qe51UK/1xdX6634U61M9d/GQAO9NkDr/W1Yv1b05pX2XeLxSVx0FKsaGDIsUz3tZi
	d+/w9227CKNl2EpweEsoiFZlK1a0gchTURwto3LRRK5ywf6oHviGw6yEsO1rgnfwS7nUKTY0caW
	r5r1OSNkPE3kuwmkf6prg6bmz8klc9oc3ww99sbTRiBrBTIXbtBStH0h/xiTP6qXcsYpvamsGkL
	nfwzW1vVpu2Ii4GUlT4uOWENNEXaxNHoAzfvJZn2pXoxJ/2pu55vDCSoLRIZYIx4BymUEtw==
X-Received: by 2002:a05:6512:3d09:b0:55b:57e8:16c4 with SMTP id 2adb3069b0e04-55cc012c003mr7357e87.30.1754595619107;
        Thu, 07 Aug 2025 12:40:19 -0700 (PDT)
Received: from localhost.localdomain (178.90.89.143.dynamic.telecom.kz. [178.90.89.143])
        by smtp.gmail.com with ESMTPSA id 2adb3069b0e04-55b88c98c2asm2793570e87.77.2025.08.07.12.40.15
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 07 Aug 2025 12:40:18 -0700 (PDT)
From: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
To: ryabinin.a.a@gmail.com,
	bhe@redhat.com,
	hca@linux.ibm.com,
	christophe.leroy@csgroup.eu,
	andreyknvl@gmail.com,
	akpm@linux-foundation.org,
	zhangqing@loongson.cn,
	chenhuacai@loongson.cn,
	davidgow@google.co,
	glider@google.com,
	dvyukov@google.com
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
Subject: [PATCH v5 0/2] kasan: unify kasan_enabled() and remove arch-specific implementations
Date: Fri,  8 Aug 2025 00:40:10 +0500
Message-Id: <20250807194012.631367-1-snovitoll@gmail.com>
X-Mailer: git-send-email 2.34.1
MIME-Version: 1.0
X-Original-Sender: snovitoll@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=L9Z2Vhj4;       spf=pass
 (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::134
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
 arch/um/kernel/mem.c                   | 10 ++++++--
 arch/x86/mm/kasan_init_64.c            |  2 +-
 arch/xtensa/mm/kasan_init.c            |  2 +-
 include/linux/kasan-enabled.h          | 32 ++++++++++++++++++--------
 include/linux/kasan.h                  |  6 +++++
 lib/Kconfig.kasan                      |  8 +++++++
 mm/kasan/common.c                      | 17 ++++++++++----
 mm/kasan/generic.c                     | 19 +++++++++++----
 mm/kasan/hw_tags.c                     |  9 +-------
 mm/kasan/kasan.h                       |  8 ++++++-
 mm/kasan/shadow.c                      | 12 +++++-----
 mm/kasan/sw_tags.c                     |  1 +
 mm/kasan/tags.c                        |  2 +-
 27 files changed, 107 insertions(+), 76 deletions(-)

-- 
2.34.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250807194012.631367-1-snovitoll%40gmail.com.
