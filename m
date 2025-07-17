Return-Path: <kasan-dev+bncBDAOJ6534YNBBX4Q4TBQMGQEMTE2POQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x339.google.com (mail-wm1-x339.google.com [IPv6:2a00:1450:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id BE4C3B08F34
	for <lists+kasan-dev@lfdr.de>; Thu, 17 Jul 2025 16:27:45 +0200 (CEST)
Received: by mail-wm1-x339.google.com with SMTP id 5b1f17b1804b1-456175dba68sf7775265e9.2
        for <lists+kasan-dev@lfdr.de>; Thu, 17 Jul 2025 07:27:45 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1752762465; cv=pass;
        d=google.com; s=arc-20240605;
        b=Ntx4v0Xy8rnXkxRvk4Vpy6F1WvHCijuOXDEURccxpOXpCTCqhhk5JpKIQ4uZ1qNIYy
         ycRjaXUrjlAUfwFCV3f97R26FsRcpd+AbhH4MvB2eFncjmuqxbuHgIbtFzXcJu3lvB7o
         J2CynWMZhbZnDoJ+xtDbeWNmUyDLO/JLJPh59PY9jnmIfiCFhuAXZH4dGia4ce0ctJ7h
         HgQyTVMZiSf3k9GAL7sjpaHRG579JgUWY98f6d4xmuSZ9YEtbb54XpySJ24V1fJFGFEa
         SO8Y4AK/P35TSD/ng9hx739pKtpjwOJl0LjPzaSQ+iBsAN4w4ozn5ojvvPLv4KPKegK+
         Fk7Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature:dkim-signature;
        bh=FDGtbnBdB038aFU7Z0fl9JUdDWHsrLsH1MwB9dzfoJY=;
        fh=lrWPXoGFRPB+G7C6kLAcXjUpBVCsPMi2akHsWPD2uGI=;
        b=GqrF/HWWM/86i13d8xZjfVJPVZNpPRlACivY91lRiL8LgRLtBL/EcOme06RvcCEJ1x
         2qBu/+6iB+DTNFSfei7jJZKBnK4D1DPvoKd2TgHSSMPNCvVhfeY9kjFY/4vdGObBSRkB
         NG3rddba48pJ/mYVZ5Y6dJ0ajNUha96HSQ2uWrxfPMIbWCrMQt4OENQ5XVw4WfCY9Kd2
         cDmyat7LVlSJWr3bF8ZDDWNwKK8j4gDzby4u5RYRbS471Gubwi5IdaiD1u1jbUaL5Iiy
         nvDjTAP6t0Ma/PZA0oG3wRcbbRO5n7OeVMJWaRxaZo8HGdhZakYLHol/Iae7K7z+9m1j
         +6CQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=TNPRaYd7;
       spf=pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::134 as permitted sender) smtp.mailfrom=snovitoll@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1752762465; x=1753367265; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=FDGtbnBdB038aFU7Z0fl9JUdDWHsrLsH1MwB9dzfoJY=;
        b=hMANpLhtaeV5IZ1o3JYJdU1ZeZE2Hfn9fAlSVa8j2eEapM97JqQ2LdYoT1E3rpNart
         aIW76XBM+SrMq7cEkAXuVjhPsw+gaqupsQOSgDjyyTsnaV+NDIOSOPtun4e2/mJRKYWI
         C31Z56NCGmfd+rXFBg78DZYkuFAALTmLn1ZjkbjurZtWo8rCjWbpG0rAXhzrZwAOOTMk
         BGRYxxhkfGlCZP5F+/Dyt1jGQBl/ev8gAfQLnDGy+J5d46tTEzIJl1bm3uw9PfY/eHfx
         FTUJ6FFdMzRcYx9KT/TrHyP/4SIMjt2jtmBsccEjZP4ieez5eKxYSGf3EjaiF7VU/yjZ
         mzhw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1752762465; x=1753367265; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :from:to:cc:subject:date:message-id:reply-to;
        bh=FDGtbnBdB038aFU7Z0fl9JUdDWHsrLsH1MwB9dzfoJY=;
        b=D+uaUgJLVdC7NSBS5ninMx7HrBTxY00X/RCUljel3Tjhr/kW1dr22luDR+Khsn0jcU
         6R87Cq3d65Ad9XUOrnhm6H+q+eF2vo7UTo/j49qoDzAciLodWs7sLIM/dk7v0CkQh3fT
         vhVUKPWB8sZblrYNpgePpZ1knRxh5ozTkMNwACq4j3Qu4ulfX5AEiNFycIu4rVbpldlY
         +Hiy6EwfOakHpixaFOsa/ZCUm+ELQ+jKMC0SZdeaFra9c9Z1itgv0+1HVXH2zN27MQs2
         Rrwxou+TDnseNExfCGOT0onOdoHs8Th+9iN3iaFCRkk/at8o8aFV8jsXYQ5OAuR7/yga
         Z6ow==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1752762465; x=1753367265;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=FDGtbnBdB038aFU7Z0fl9JUdDWHsrLsH1MwB9dzfoJY=;
        b=PLwntkFmDjtWC8Mu0lylEa89F4UYzqTnQLks4i1PKqXDhXnTm+yvQ5PIJ1Nh+iwslQ
         4G6SpZSZyGaHsgWLnluRuhJUDUDnShrJmwmyYacXERLw1RG0UVpg5UbY00MrgenRAPUE
         rhcDaToCJUaC9O4doSptyiLxgjjP0pZICDQ0Rbv8WO1aHDuJSGIZr6Cp7cJnrbkoPxqs
         5/VqiYnQ80eEMo8o7OZFIIsNCm6AQoe/cwcDXmoqkD2n0qx1r5gvBgjmRV0pTN2x8ufw
         qQY5Di+2t+Igf7L13avgq7KdY2IwQtbOlsy7ClnEWpHsmHPWSEtyBGQ48nPdyB0JZ6Qn
         VL0Q==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWVKsZrogDmhwQmLYBRI/SC0mqTXsoUZD1Cz9+xRKuyWWcgT86hQWrAHzLo/YHLCvFwRbAQ7g==@lfdr.de
X-Gm-Message-State: AOJu0Yz1go0XCMdC+aSgdWxfB+DGpOyfpXNe+aR5hmt6HHfXfR92JKnv
	l6v+L0Ydded+EWuVdYfx23FITUx+Ee+i3FPmTDCPvHyUFxQOTPxjw5OW
X-Google-Smtp-Source: AGHT+IHBd6UWrTWEsoN5Vi/pZBLsEe53fuRhx9IVKi2THd/YZ1rb9Zdy6Cz83JlY3d1+i+YeFHwLKQ==
X-Received: by 2002:a05:600c:64ce:b0:455:f59e:fd79 with SMTP id 5b1f17b1804b1-4562e33d64emr70779145e9.11.1752762464496;
        Thu, 17 Jul 2025 07:27:44 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZefnk2698MlPTKN4arB6lCDo8nfgFcyILGNKMS4kOFf0A==
Received: by 2002:a05:600c:1c25:b0:456:241d:50d0 with SMTP id
 5b1f17b1804b1-456341b19eels6578125e9.2.-pod-prod-07-eu; Thu, 17 Jul 2025
 07:27:42 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXoPb+qaWbb5hRSrIwEcfwOcpHiDqZhEh/P4BRcE/t6C4HOxZpCXDP1d1Er2EFxZbOpwE9amKZaO1g=@googlegroups.com
X-Received: by 2002:a05:600c:c4a7:b0:456:1a87:a6ba with SMTP id 5b1f17b1804b1-4562e380259mr62994005e9.33.1752762461873;
        Thu, 17 Jul 2025 07:27:41 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1752762461; cv=none;
        d=google.com; s=arc-20240605;
        b=d7bdT9MKhLuxngQFstdyS74oCUti1RLCgqJaT2EbNHKYYE133azfNUE3Ucr0bsbiHy
         DEmD19xjwi1VE3a/IJB5CpKD/oKwuKauJKID2LIa8vpJMGoYjpwX+QIFh83bzUfD52E9
         Evckt59SAF+CIvbKb/0RvKXmbTdlLFgjxRiZUyeu5G+PKlYDumPSO3MZgbZ1WkSb7jDP
         884AWgAiQzVt723a4SE2oDhuno72QTF2IYoQ4lkMzCiuewhqsuhqXAUa/bbqC1NgGQsV
         Oe3DIDn46EM3cr+WdTewIxEYc50QhU84xH5bpmzTNXdVxn3Dqu9VoAs5nVoG6TZPR+Bp
         hz0A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=S1+MAZvM+N/4+avawJ7fodWecsPBgKeK+9BQEGE2Ung=;
        fh=6WoVrW5i5X4lg54y2SDnViXVuaqgqDXg9CZnArn9XLg=;
        b=ImLPlGtH7TdAtIQzStjxz3szvSd6Ff1Iv8h349lSBOVjkvYvkoasu0E+t9NxxuLsVl
         R2siEDZ6TeXqKgShB0iEo8o70l4etBbcWIdbnJFH7oRSRt9iuvyQbkwzBYHIo3VNVyAX
         +Z4NHR3ZwjBDOzkg/8CJ4ZTJ7ITh9kJ2TgsztGyenYpm/MJ7CtrwfXgCOsbjhGa/pb01
         J/MclOPfKCfTbhcp8iSdpIYlA462bYK2Yy5UXN0EqwoX6EX+IY9898+XId36jQRICZ1H
         u7l+FgGCra0vNR98tlxVwlQhVtmp4TAv8qgMTBj4OwjNX/vSEYcLZhzT5apSX9H1HQUs
         NuoQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=TNPRaYd7;
       spf=pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::134 as permitted sender) smtp.mailfrom=snovitoll@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-lf1-x134.google.com (mail-lf1-x134.google.com. [2a00:1450:4864:20::134])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-45627898572si2485605e9.1.2025.07.17.07.27.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 17 Jul 2025 07:27:41 -0700 (PDT)
Received-SPF: pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::134 as permitted sender) client-ip=2a00:1450:4864:20::134;
Received: by mail-lf1-x134.google.com with SMTP id 2adb3069b0e04-5561d41fc96so1208439e87.1
        for <kasan-dev@googlegroups.com>; Thu, 17 Jul 2025 07:27:41 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUAN3vZXxbAAQzbx/Yp1VnxmScDJ3ncJMwHyGBXSqZV2ZTH0CyAc+Yc2O1qtVGoI7BmiD+JDXS3Yt8=@googlegroups.com
X-Gm-Gg: ASbGncsqJjs5mpWq9x1gMPfqKfECH0aEX5/Dz8Hwfw3BszC10/pzFpKx5sOPyBkGFtH
	T2kyEtY2Lf4THaSWqyQ/57g+HHHFvlW/yBsv1kmIbbn9d4qOXxbSIaiA/yZA78yQQimjLD5hNkr
	Br5MLEO47aQHyoXxjeghfta+4ymYjEKeBSyfiUtUPcnYRFew25M42bh8k4EEKYDfYe6Xida4dpZ
	hpdlU5FfXvqaFRNWPL0/zvqNPLJMeWLQY0AfwjuP3+ji3KKVjvwZpAjBZRz0koPHHAJK4zrxYaH
	CjjPItUD4z2ey+xXqqLXEYFd+gAQ9AgFUIBv/jzDtdYabuvbpDT0y3dFP3/kQBtKQOBQ+HjK8Ya
	Q6ZkXNXOtkz6WXHyUMb4ESCsQT1ZWaPDiyjvREZ8bDC9xBalY7IKkhx23D1BIIThWjBcz
X-Received: by 2002:a05:6512:b17:b0:553:ad81:4de1 with SMTP id 2adb3069b0e04-55a23f2d227mr2243765e87.24.1752762460660;
        Thu, 17 Jul 2025 07:27:40 -0700 (PDT)
Received: from localhost.localdomain (178.90.89.143.dynamic.telecom.kz. [178.90.89.143])
        by smtp.gmail.com with ESMTPSA id 2adb3069b0e04-55989825fe3sm3022975e87.223.2025.07.17.07.27.37
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 17 Jul 2025 07:27:39 -0700 (PDT)
From: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
To: hca@linux.ibm.com,
	christophe.leroy@csgroup.eu,
	andreyknvl@gmail.com,
	agordeev@linux.ibm.com,
	akpm@linux-foundation.org
Cc: ryabinin.a.a@gmail.com,
	glider@google.com,
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
Subject: [PATCH v3 00/12] kasan: unify kasan_arch_is_ready() and remove arch-specific implementations
Date: Thu, 17 Jul 2025 19:27:20 +0500
Message-Id: <20250717142732.292822-1-snovitoll@gmail.com>
X-Mailer: git-send-email 2.34.1
MIME-Version: 1.0
X-Original-Sender: snovitoll@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=TNPRaYd7;       spf=pass
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
- PowerPC, LoongArch, and um arch, each implement own kasan_arch_is_ready()
- Only HW_TAGS mode had a unified static key (kasan_flag_enabled)
- Generic and SW_TAGS modes relied on arch-specific solutions
  or always-on behavior

This series implements two-level approach:
1. kasan_enabled() - compile-time check for KASAN configuration
2. kasan_shadow_initialized() - runtime check for shadow memory readiness

Key improvements:
- Unified static key infrastructure across all KASAN modes
- Runtime overhead only for architectures that actually need it
- Compile-time optimization for arch. with early KASAN initialization
- Complete elimination of arch-specific kasan_arch_is_ready()
- Consistent interface and reduced code duplication

Previous v2 thread: https://lore.kernel.org/all/20250626153147.145312-1-snovitoll@gmail.com/

Changes in v3 (sorry for the 3-week gap):

0. Included in TO, CC only KASAN devs and people who commented in v2.

1. Addressed Andrey Konovalov's feedback:
   - Kept separate kasan_enabled() and kasan_shadow_initialized() functions
   - Added proper __wrapper functions with clean separation

2. Addressed Christophe Leroy's performance comments:
   - CONFIG_ARCH_DEFER_KASAN is only selected by architectures that need it
   - No static key overhead for architectures that can enable KASAN early
   - PowerPC 32-bit and book3e get compile-time optimization

3. Addressed Heiko Carstens and Alexander Gordeev s390 comments:
   - s390 doesn't select ARCH_DEFER_KASAN (no unnecessary static key overhead)
   - kasan_enable() is a no-op for architectures with early KASAN setup

4. Improved wrapper architecture:
   - All existing wrapper functions in include/linux/kasan.h now check both
     kasan_enabled() && kasan_shadow_initialized()
   - Internal implementation functions focus purely on core functionality
   - Shadow readiness logic is centralized in headers per Andrey's guidance

Architecture-specific changes:
- PowerPC radix MMU: selects ARCH_DEFER_KASAN for runtime control
- LoongArch: selects ARCH_DEFER_KASAN, removes custom kasan_early_stage
- um: selects ARCH_DEFER_KASAN, removes kasan_um_is_ready
- Other architectures: get compile-time optimization, no runtime overhead

The series maintains full backward compatibility while providing optimal
performance for each architecture's needs.

Closes: https://bugzilla.kernel.org/show_bug.cgi?id=217049

=== Current mainline KUnit status

To see if there is any regression, I've tested via compiling a kernel
with CONFIG_KASAN_KUNIT_TEST and running QEMU VM. There are failing tests
in SW_TAGS and GENERIC modes in arm64:

arm64 CONFIG_KASAN_HW_TAGS:
	# kasan: pass:62 fail:0 skip:13 total:75
	# Totals: pass:62 fail:0 skip:13 total:75
	ok 1 kasan

arm64 CONFIG_KASAN_SW_TAGS=y:
	# kasan: pass:65 fail:1 skip:9 total:75
	# Totals: pass:65 fail:1 skip:9 total:75
	not ok 1 kasan
	# kasan_strings: EXPECTATION FAILED at mm/kasan/kasan_test_c.c:1598
	KASAN failure expected in "strscpy(ptr, src + KASAN_GRANULE_SIZE, KASAN_GRANULE_SIZE)", but none occurred

arm64 CONFIG_KASAN_GENERIC=y, CONFIG_KASAN_OUTLINE=y:
	# kasan: pass:61 fail:1 skip:13 total:75
	# Totals: pass:61 fail:1 skip:13 total:75
	not ok 1 kasan
	# same failure as above

x86_64 CONFIG_KASAN_GENERIC=y:
	# kasan: pass:58 fail:0 skip:17 total:75
	# Totals: pass:58 fail:0 skip:17 total:75
	ok 1 kasan

=== Testing with patches

Testing in v3:

- Compiled every affected arch with no errors:

$ make CC=clang LD=ld.lld AR=llvm-ar NM=llvm-nm STRIP=llvm-strip \
	OBJCOPY=llvm-objcopy OBJDUMP=llvm-objdump READELF=llvm-readelf \
	HOSTCC=clang HOSTCXX=clang++ HOSTAR=llvm-ar HOSTLD=ld.lld \
	ARCH=$ARCH

$ clang --version
ClangBuiltLinux clang version 19.1.4
Target: x86_64-unknown-linux-gnu
Thread model: posix

- make ARCH=um produces the warning during compiling:
	MODPOST Module.symvers
	WARNING: modpost: vmlinux: section mismatch in reference: \
		kasan_init+0x43 (section: .ltext) -> \
		kasan_init_generic (section: .init.text)

AFAIU, it's due to the code in arch/um/kernel/mem.c, where kasan_init()
is placed in own section ".kasan_init", which calls kasan_init_generic()
which is marked with "__init".

- Booting via qemu-system- and running KUnit tests:

* arm64  (GENERIC, HW_TAGS, SW_TAGS): no regression, same above results.
* x86_64 (GENERIC): no regression, no errors

Sabyrzhan Tasbolatov (12):
  lib/kasan: introduce CONFIG_ARCH_DEFER_KASAN option
  kasan: unify static kasan_flag_enabled across modes
  kasan/powerpc: select ARCH_DEFER_KASAN and call kasan_init_generic
  kasan/arm64: call kasan_init_generic in kasan_init
  kasan/arm: call kasan_init_generic in kasan_init
  kasan/xtensa: call kasan_init_generic in kasan_init
  kasan/loongarch: select ARCH_DEFER_KASAN and call kasan_init_generic
  kasan/um: select ARCH_DEFER_KASAN and call kasan_init_generic
  kasan/x86: call kasan_init_generic in kasan_init
  kasan/s390: call kasan_init_generic in kasan_init
  kasan/riscv: call kasan_init_generic in kasan_init
  kasan: add shadow checks to wrappers and rename kasan_arch_is_ready

 arch/arm/mm/kasan_init.c               |  2 +-
 arch/arm64/mm/kasan_init.c             |  4 +--
 arch/loongarch/Kconfig                 |  1 +
 arch/loongarch/include/asm/kasan.h     |  7 -----
 arch/loongarch/mm/kasan_init.c         |  7 ++---
 arch/powerpc/Kconfig                   |  1 +
 arch/powerpc/include/asm/kasan.h       | 12 --------
 arch/powerpc/mm/kasan/init_32.c        |  2 +-
 arch/powerpc/mm/kasan/init_book3e_64.c |  2 +-
 arch/powerpc/mm/kasan/init_book3s_64.c |  6 +---
 arch/riscv/mm/kasan_init.c             |  1 +
 arch/s390/kernel/early.c               |  3 +-
 arch/um/Kconfig                        |  1 +
 arch/um/include/asm/kasan.h            |  5 ---
 arch/um/kernel/mem.c                   |  4 +--
 arch/x86/mm/kasan_init_64.c            |  2 +-
 arch/xtensa/mm/kasan_init.c            |  2 +-
 include/linux/kasan-enabled.h          | 34 ++++++++++++++++-----
 include/linux/kasan.h                  | 42 ++++++++++++++++++++------
 lib/Kconfig.kasan                      |  8 +++++
 mm/kasan/common.c                      | 18 +++++++----
 mm/kasan/generic.c                     | 23 ++++++++------
 mm/kasan/hw_tags.c                     |  9 +-----
 mm/kasan/kasan.h                       | 36 ++++++++++++++++------
 mm/kasan/shadow.c                      | 32 +++++---------------
 mm/kasan/sw_tags.c                     |  2 ++
 26 files changed, 146 insertions(+), 120 deletions(-)

-- 
2.34.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250717142732.292822-1-snovitoll%40gmail.com.
