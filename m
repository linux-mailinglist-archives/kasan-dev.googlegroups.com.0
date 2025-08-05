Return-Path: <kasan-dev+bncBDAOJ6534YNBBF5JZDCAMGQECGXLQYY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x63f.google.com (mail-ej1-x63f.google.com [IPv6:2a00:1450:4864:20::63f])
	by mail.lfdr.de (Postfix) with ESMTPS id 35BE7B1B658
	for <lists+kasan-dev@lfdr.de>; Tue,  5 Aug 2025 16:26:48 +0200 (CEST)
Received: by mail-ej1-x63f.google.com with SMTP id a640c23a62f3a-af93bb03d76sf352879366b.3
        for <lists+kasan-dev@lfdr.de>; Tue, 05 Aug 2025 07:26:48 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1754403992; cv=pass;
        d=google.com; s=arc-20240605;
        b=GMPMM9gbixwZVnFN72NI1WDlif+h9/StxIeivQjROLcgoJsQflM4HNtmjIHo1qgIk/
         3AGngXNO3QjiUj01tQCnUUONceBnB5coY5lZK1rBnNosbEOa7j0vMm7AdSiCLiAbvxyU
         bYEX7i5w8Vbqe96LkO7aFCTLtM8H096x+DpNZL6MO5n54ALwg+LU3n9nFhRb3LrTs5oV
         dyTeVG4feq77IiXHtbFFp/rhHViN+fOztotnjUGS0P/8aiJr9blXYuUd8mzucwlK/GAq
         9q352+zYK/nOXE3XHpIRF6lnf/FntpGD6VlybTzFS5tJAdc3WEKBy3nU8k0YtbhVTTq8
         F3EQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature:dkim-signature;
        bh=P5YVqsHJ2EnBGDS9ftghWzeZO3Ax9U5jcP4wIOITDA8=;
        fh=W7M0QmgRWHSDuWDOg+S+VZsZJXcavbhRtjYO9FtAfYM=;
        b=ja1E7XbtCOv9KNsCuwcF1yzjiYw2bedcUFrZO6PXkkAQQlns31U5F7ERiO9xZzO6sd
         uh17x7USe7x5cSNFLMTruuUE5rwCefOcA1HiizJ9ARI5TebpnqHcF8ejWe4KwbMosNkp
         YOs+loFQ6G5+1MBWwhxuL/b2vYDxJayPM6UlOiUx74z/sWbt/+xeH5RLpRF7oVsp36ee
         ra4q+w5t5gSSsJ1u+0bB292CTq/1hs3sjvUgYu1Amwo2ykYGO+RDA47+ayZGlxRVY4EA
         B4J5Oa+XVSuZORrkcfkuYI1zC4+mOoBBT2o/hC6l2DWqqmHxdB4Eu38CREkb/XdCDl/Y
         3v6w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=HQHI5bP7;
       spf=pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::134 as permitted sender) smtp.mailfrom=snovitoll@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1754403992; x=1755008792; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=P5YVqsHJ2EnBGDS9ftghWzeZO3Ax9U5jcP4wIOITDA8=;
        b=kqBmFt0HYCr7NzwzoJ3HrXIHSBgJX4JGzO/gyRXju+yGG2MqSxqX/bKUnsBeVIWZt6
         q6uGs/zLiert5B1aX8HsvIiWhkd13uaSG7XcBcqqtz3DqeZqqn0ljTJX0zCqHsdt0vkT
         v6iM/6WmR6Q32JRx4y+PpDrAzCd/M1H5yTptl0WwnyOAtrH5D3HTW1jaxmuDd5jMKJjZ
         avWfMyLDXY5ijOVgq6YLYI1Q64xMgo8AAqmTVTTAmsvWkVzHIExt7pxxVZ45G8VfH6tZ
         PpJPMSMIMmTUzSk/8q3JTpLyfyvmm7VpCMeR8ttpC6sM5jih2wOwqeBTjKZzXb0QWkBx
         CESg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1754403992; x=1755008792; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :from:to:cc:subject:date:message-id:reply-to;
        bh=P5YVqsHJ2EnBGDS9ftghWzeZO3Ax9U5jcP4wIOITDA8=;
        b=Zqu/olnKi2R0Ri0xLILeRQBmwLOXFmblcfVeNuRt072hn6gAfZTt+fscO+SmwdpZZc
         llLhfwRO4SFwKCJSqV/jqfoKG+tWjON4FKcTBeAva5dSrIAXQRgadSZLqvRc5lKyoliQ
         KkVK7fkfpAvXlQi1G6dT0mOjYAhkB416YDW/uy7LIwMc9AfzLnTo9HgzPUNZqJIDxuNj
         dXXkcDX6GE5RuztPLbqflhTmpobTKuRTiyr2paSvQ9JKYpOY8cVtX4Enm0NWeirkpfCD
         i3KQ6AQ9tYgpYMHyj3xeFe1yHw7cf834SGhaIffczLAOzC+fY1PNKJQxWaO+Trc/EttZ
         vXDw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1754403992; x=1755008792;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=P5YVqsHJ2EnBGDS9ftghWzeZO3Ax9U5jcP4wIOITDA8=;
        b=mpxQ4OuhFiEpRukZ/NMlyrYkWft7sKn3ko/0zFixmnbP1uZ4e5B1OhHtV3D4gwdsuR
         Vv70lmzFNXlJFMggmpb7wRvwk9pUcl9+6E5ZUgwMB9YmAy+0kItSU1oqnNGkBmMeR7OU
         ADn2G+x+oaGRADzArjmnKTJRgIeTnVd+d/uO+Gymj32EbY7VgGOmcbEy2Yd0uaFWp8gi
         xJ17hcq2hcGaeuoiNHiryoUHZglEcj5OXk3NFhJutorKXRhcKnJPoZVOpCD3tovpMfHm
         rmEGTEVrCogLF/cAPDdk1ed4IUBtXk0bCeJ/DjNUi9Jhl6v9xNC6iBdShwHG+4WQMtJ9
         7HAw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUc937rAKhsfGp9QFW7psyVHALsGlYvhp9P9IeF5qhkzCD7GzIkhbcbkifDjiW+/Z84NjQlSw==@lfdr.de
X-Gm-Message-State: AOJu0YyyNbMCpQMaXbe8YDykYJ1Ky96UsUAbD0MxI7C12CqCfBtgYhes
	8HabNTouX++xchXz5/PHiNc12Wi33jJjkpOFYW5euyz6sshmwAnit/pY
X-Google-Smtp-Source: AGHT+IFDTuIwTnWIEevNc9YOdNzisCt8AY5uJKsz22Bns2NIAdeWkBiIFXFgMOCZNS0CeOm/88bBLQ==
X-Received: by 2002:a17:906:c10b:b0:af9:32bc:a365 with SMTP id a640c23a62f3a-af94024c1e9mr1661832166b.54.1754403991890;
        Tue, 05 Aug 2025 07:26:31 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdcRZoDgckZjJ/jz9dNIo8b0GajVYvqvVi5pwi5Vpp+aA==
Received: by 2002:a05:6402:2115:b0:615:a4fc:cb7b with SMTP id
 4fb4d7f45d1cf-615a5bf8f68ls6070972a12.2.-pod-prod-02-eu; Tue, 05 Aug 2025
 07:26:29 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCX0B9bvyNe8HBgkJXBgSqFVKn/8r3OufL6ZR3XDAidrypMFZqfLReUcSW5dVanhuAZgiBPepxbcQtY=@googlegroups.com
X-Received: by 2002:a05:6402:1118:b0:615:905a:3d43 with SMTP id 4fb4d7f45d1cf-615e71451c1mr10471030a12.16.1754403988926;
        Tue, 05 Aug 2025 07:26:28 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1754403988; cv=none;
        d=google.com; s=arc-20240605;
        b=XW4QTXc4xR+9Zc52Zzbxctp6fMde7dh2Y6lJ8ZRbq/WvuhVKsLPChAwft8fYtWXs+/
         RrGqRcj6HuxPO6EQ8AuVKiELhKoHXJheV1nLK1I0hjmjJmOmdfg6FDbQXoa7G3IWFJpv
         G5Ssju5S9Wpzilt8Ma3t8k/sHsqPugj76DSqHrjT/m3xZUza9OiL1XuRk6w00HfaqV1x
         cdIhIY1UrIJgoFWetOh1cHXGY/BO5dzBmsTgGyibxkJax38ZAbPeoxwwffC4xr3dsrXe
         /3r/e4lSrBeiBhhuqTOWbyaswmi93eGEVwSqtLUEuwdFsTEmjuwsZ7azOEWF6kan3TJ8
         iG0A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=pksKKRBtO31JVCyUig2REP3M3oI0Y/m5ILEfob1JeTo=;
        fh=2UDWrmwhF2XibFs69C5aU/3xlyMbvyC0BLJaCw4V0MA=;
        b=W/H1AyQJxLs4uoaQVVEodGxhoXCF0MnQsSDRDVobA70NqBiKXPP1XrBulJjYGqQ7Gl
         AnHnBgyXizmsERZeFjwg05JlJvGGihBksxhmrJj05EiHqVoaQc4tScJVour7iZAr2jnP
         4btzbKJj74uS7buEnEmstJPThed8kVqH8CKmZuxUpiXO2HRqCWzgUUk0atU/HSgFYf+m
         f4qm6qsXEUFtvcOyf6403i3ivC6jsCnROg9MIKmEA9c/+2u/gstEGlotwec0XefKX/22
         qYlXhlSaCV8mS1EwNbO+UxYrDye8gJctynkj44pjbLLlI9Em+UD9qcaClTK/YVN3x50E
         Qj0Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=HQHI5bP7;
       spf=pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::134 as permitted sender) smtp.mailfrom=snovitoll@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-lf1-x134.google.com (mail-lf1-x134.google.com. [2a00:1450:4864:20::134])
        by gmr-mx.google.com with ESMTPS id 4fb4d7f45d1cf-615a9135373si280820a12.5.2025.08.05.07.26.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 05 Aug 2025 07:26:28 -0700 (PDT)
Received-SPF: pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::134 as permitted sender) client-ip=2a00:1450:4864:20::134;
Received: by mail-lf1-x134.google.com with SMTP id 2adb3069b0e04-55b8b8e00caso5505667e87.3
        for <kasan-dev@googlegroups.com>; Tue, 05 Aug 2025 07:26:28 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWzzHejI50jpl+cGt7CI0/GJ5JwgMuFIWAH4TvyPya0ilGGRwiNCOHOGSyNlkIvHflcj5zhaw0uhL0=@googlegroups.com
X-Gm-Gg: ASbGncu/ZnowDfB5aM/qleIkihb/iw1ts0bRTHNa0M0QoC4Ebi6ID9q9UICwG6FNUCy
	/i1OYAUTKcAlArkRCtZtvH+Q+Ny+9QzAeVYBfDQbG7lcKwC2tkkfqIMY7sjvB9JmJArpDlVD63y
	pfrwMBaPpIQdBepXEoxJtFh6tiR0dnDQjdcXvPUabZ1/uf7xRwsuXqFKML2J+VJEXxH/vB2Nzu6
	m5a24DLVJXjeO4Xe56x4aIDbyhb3P2hci5RAaojkTQJvrOivik27oBYfBC6fDyKIx8xvgVw19VY
	g+8tbEqcmyLfmmAXjnCICIv0TEyq6ChVXuXSkbtvZ0W1a7Kp7AEG8MFQX/+cOgsb4piqhg348Uw
	yerQjeftR+EEdKQneUHMbe6ATXtperFnfEUGfPueA9h9Ta+krz2BEBbGHbxtwLeGidySxuA==
X-Received: by 2002:a05:6512:39cc:b0:55b:9647:8e7b with SMTP id 2adb3069b0e04-55b97b75a15mr4601956e87.43.1754403988090;
        Tue, 05 Aug 2025 07:26:28 -0700 (PDT)
Received: from localhost.localdomain (178.90.89.143.dynamic.telecom.kz. [178.90.89.143])
        by smtp.gmail.com with ESMTPSA id 2adb3069b0e04-55b889a290fsm1976379e87.54.2025.08.05.07.26.25
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 05 Aug 2025 07:26:27 -0700 (PDT)
From: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
To: ryabinin.a.a@gmail.com,
	hca@linux.ibm.com,
	christophe.leroy@csgroup.eu,
	andreyknvl@gmail.com,
	agordeev@linux.ibm.com,
	akpm@linux-foundation.org,
	zhangqing@loongson.cn,
	chenhuacai@loongson.cn,
	trishalfonso@google.com,
	davidgow@google.com
Cc: glider@google.com,
	dvyukov@google.com,
	kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org,
	loongarch@lists.linux.dev,
	linuxppc-dev@lists.ozlabs.org,
	linux-riscv@lists.infradead.org,
	linux-s390@vger.kernel.org,
	linux-um@lists.infradead.org,
	linux-mm@kvack.org,
	snovitoll@gmail.com
Subject: [PATCH v4 0/9] kasan: unify kasan_arch_is_ready() and remove arch-specific implementations
Date: Tue,  5 Aug 2025 19:26:13 +0500
Message-Id: <20250805142622.560992-1-snovitoll@gmail.com>
X-Mailer: git-send-email 2.34.1
MIME-Version: 1.0
X-Original-Sender: snovitoll@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=HQHI5bP7;       spf=pass
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

This series implements two-level approach:
1. kasan_enabled() - compile-time check for KASAN configuration
2. kasan_shadow_initialized() - runtime check for shadow memory readiness

Changes in v4:
- Unified patches where ARCH_DEFER_KASAN is introduced and used
  in the KASAN code (Andrey Ryabinin)
- Fixed kasan_enable() for HW_TAGS mode (Andrey Ryabinin)
- Replaced !kasan_enabled() with !kasan_shadow_initialized() in
  loongarch which selects ARCH_DEFER_KASAN (Andrey Ryabinin)
- Addressed the issue in UML arch, where kasan_init_generic() is
  called before jump_label_init() (Andrey Ryabinin)

Adding in TO additional recipients who developed KASAN in LoongArch, UML.

Tested on:
- powerpc - selects ARCH_DEFER_KASAN
Built ppc64_defconfig (PPC_BOOK3S_64) - OK
Booted via qemu-system-ppc64 - OK

- um - selects ARCH_DEFER_KASAN
Built defconfig with KASAN_INLINE - OK
Built defconfig with STATIC_LINK && KASAN_OUTLINE - OK
Booted ./linux - OK

- loongarch - selects ARCH_DEFER_KASAN
Built defconfig with KASAN_GENERIC - OK
Haven't tested the boot. Asking Loongarch developers to verify - N/A
But should be good, since Loongarch does not have specific "kasan_init()"
call like UML does. It selects ARCH_DEFER_KASAN and calls kasan_init()
in the end of setup_arch() after jump_label_init().

- arm64
Built defconfig, kvm_guest.config with HW_TAGS, SW_TAGS, GENERIC - OK
KASAN_KUNIT_TEST - OK
Booted via qemu-system-arm64 - OK

- x86_64
Built defconfig, kvm_guest.config with KASAN_GENERIC - OK
KASAN_KUNIT_TEST - OK
Booted via qemu-system-x86 - OK

- s390, riscv, xtensa, arm
Built defconfig with KASAN_GENERIC - OK

Previous v3 thread: https://lore.kernel.org/all/20250717142732.292822-1-snovitoll@gmail.com/
Previous v2 thread: https://lore.kernel.org/all/20250626153147.145312-1-snovitoll@gmail.com/

Closes: https://bugzilla.kernel.org/show_bug.cgi?id=217049

Sabyrzhan Tasbolatov (9):
  kasan: introduce ARCH_DEFER_KASAN and unify static key across modes
  kasan/powerpc: select ARCH_DEFER_KASAN and call kasan_init_generic
  kasan/arm,arm64: call kasan_init_generic in kasan_init
  kasan/xtensa: call kasan_init_generic in kasan_init
  kasan/loongarch: select ARCH_DEFER_KASAN and call kasan_init_generic
  kasan/um: select ARCH_DEFER_KASAN and call kasan_init_generic
  kasan/x86: call kasan_init_generic in kasan_init
  kasan/s390: call kasan_init_generic in kasan_init
  kasan/riscv: call kasan_init_generic in kasan_init

 arch/arm/mm/kasan_init.c               |  2 +-
 arch/arm64/mm/kasan_init.c             |  4 +--
 arch/loongarch/Kconfig                 |  1 +
 arch/loongarch/include/asm/kasan.h     |  7 -----
 arch/loongarch/mm/kasan_init.c         |  8 ++---
 arch/powerpc/Kconfig                   |  1 +
 arch/powerpc/include/asm/kasan.h       | 12 --------
 arch/powerpc/mm/kasan/init_32.c        |  2 +-
 arch/powerpc/mm/kasan/init_book3e_64.c |  2 +-
 arch/powerpc/mm/kasan/init_book3s_64.c |  6 +---
 arch/riscv/mm/kasan_init.c             |  1 +
 arch/s390/kernel/early.c               |  3 +-
 arch/um/Kconfig                        |  1 +
 arch/um/include/asm/kasan.h            |  5 ---
 arch/um/kernel/mem.c                   | 12 ++++++--
 arch/x86/mm/kasan_init_64.c            |  2 +-
 arch/xtensa/mm/kasan_init.c            |  2 +-
 include/linux/kasan-enabled.h          | 36 +++++++++++++++++-----
 include/linux/kasan.h                  | 42 ++++++++++++++++++++------
 lib/Kconfig.kasan                      |  8 +++++
 mm/kasan/common.c                      | 18 +++++++----
 mm/kasan/generic.c                     | 23 ++++++++------
 mm/kasan/hw_tags.c                     |  9 +-----
 mm/kasan/kasan.h                       | 36 ++++++++++++++++------
 mm/kasan/shadow.c                      | 32 +++++---------------
 mm/kasan/sw_tags.c                     |  4 ++-
 mm/kasan/tags.c                        |  2 +-
 27 files changed, 157 insertions(+), 124 deletions(-)

-- 
2.34.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250805142622.560992-1-snovitoll%40gmail.com.
