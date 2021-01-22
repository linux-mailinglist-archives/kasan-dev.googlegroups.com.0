Return-Path: <kasan-dev+bncBCOYZDMZ6UMRBSPLVOAAMGQEUXGIXJY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x539.google.com (mail-pg1-x539.google.com [IPv6:2607:f8b0:4864:20::539])
	by mail.lfdr.de (Postfix) with ESMTPS id 8EFA83007EC
	for <lists+kasan-dev@lfdr.de>; Fri, 22 Jan 2021 16:56:58 +0100 (CET)
Received: by mail-pg1-x539.google.com with SMTP id z20sf3678686pgh.18
        for <lists+kasan-dev@lfdr.de>; Fri, 22 Jan 2021 07:56:58 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1611331017; cv=pass;
        d=google.com; s=arc-20160816;
        b=IWiNF8Gu0rYX/aIJjwXmwBJlJvMrVsZ06qKej8PJVL8oElxZYp9cRu88DqldkQ3Qbd
         A7JfenQDmT7CYReKzJcl9fb798++bEY84RlmE0Em0fKd0knTCVoKSWRg8ZLnnDsdSb3R
         JBl2f7FJ+faObMmUQZ8597PEbmmm1Ri2D9hqzdAyrypf49YAnDhqbZYqYwxslrq1fQO3
         7LWDWHxh8jjh70+jgrwGjSE6Kd2yNBUirURtbO7m0eyXPkQ97Ai5zVALPFA+LX6zo1k1
         ItFiskivWo+PeieskWRp8xJAj5n/UltgY2UwObyqlHBzWHbvQI1mRhRLUyfUNHAMTaBC
         Hnwg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=J3DmJ4KQrr4d7is3wz/t61EsWhQi+Z6Czg7OjvU/5yI=;
        b=Z3AWdIwvi7NJJcCemNjLmGhwGtheVu6yF40OBL71LSWme1qf/ew0GA1QiCi/JL+Fmz
         R/m6b78gks3iHh4+1WltuxA7tJGA9N5OZN1383eOlpuZ+mDgwm0DTpO2ce1zdbpPH3ZN
         lNwom76JrIKxf9reTXy+xtxFRsN2+uIgMZyoTWdz12RV4wHLnqKCOSke+PIIYdZ7cfU6
         WcmaJ2nR6MAJ1T8orDWTFKcQVCfZIwjY5sE1tkmMD4LnH9rQpvq8X6/aWs60/X64X/Kx
         1tJs4e4upuxhGQgJI0MCKs7f+1yq6w/Vc2e/FakwJHJuvH78/7a3XMn8AiIKyrW4rgtv
         2Kwg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=J3DmJ4KQrr4d7is3wz/t61EsWhQi+Z6Czg7OjvU/5yI=;
        b=qoUuW4CQQmEtiBc2bfAYbkpjKq80dNwlAY5KMAc3gQQFxYpCBsApooM6CzlQ0P/tcP
         Ezq5T4D+nsM5gQv/ofcm4vNzDP1bjETKZ5v+b5hRyIfYJW4Q8BsATPV20oi5WbPEOVQY
         xdfs/7KdxAcqTL9IMTM5aqNIQoW9uN3HUOJMcGWKKH6HExhfH2cMkhvZQBRXDXyRBwBO
         bhYq6mmeoriO9b0uxn1nNu7hIE44wtLVGoXj2v+mOT6+C6Uw0lqMFgM/czRFM/iX4JcG
         AQh7WkCw1CBmTv6JwjnbekmZZfOesdBSVmvtjcoKpXPX6zDb8a55aFBaRPBSo7ONYzSI
         V2Lw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=J3DmJ4KQrr4d7is3wz/t61EsWhQi+Z6Czg7OjvU/5yI=;
        b=izxVWQEcT+1UaKJjWgKPKJG45yGIAn0F2v9pfmiKYg6wsp/CdA7FeMlQ5BT4f103tS
         4je36JWo20hdB7m361DrE84HMdumE9AGMqOyaQ/9MqEaAufttSir4X5sshZQaa298l63
         vgW04krqCT0yjW44ZHApB+KrnRoknLwpBpwH9WwI45gLRmhrRoCdPMj51t45Wfnehuu/
         3D6H8wiHiZq7BlrrnVCTl5MgajEWOG7jpAAHHjNeiwXGsxyVxMp+aRkCkCkc5Z/by3aT
         +f91cWIdwzt4gzI90gu2DQNjnxek53RHx4CdhcsN8vs5qCRYQ10rFp3c0wFxAxXGVnaU
         t1cQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533woN+74bkHpbY4qPbnYeJe4CSwID3eNY7S07Tl3ilgJKydyl6L
	PeKKaKl7810pzI92+ZAcTuE=
X-Google-Smtp-Source: ABdhPJxhTromUtrikTqd0y1mbT6LryFC8dzLIqHBITv/6zGq82vM2i7h4ql9HOOYX7S4B0FkLZB5yQ==
X-Received: by 2002:a17:90b:f08:: with SMTP id br8mr6063333pjb.134.1611331017333;
        Fri, 22 Jan 2021 07:56:57 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:4b8f:: with SMTP id lr15ls3383266pjb.3.gmail; Fri,
 22 Jan 2021 07:56:56 -0800 (PST)
X-Received: by 2002:a17:90a:b782:: with SMTP id m2mr6124571pjr.220.1611331016847;
        Fri, 22 Jan 2021 07:56:56 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1611331016; cv=none;
        d=google.com; s=arc-20160816;
        b=uxx0Zi06ZJEKywpWHCEmymXDiVqliCYHDnImRJw57230wF55fZjJtZJHZOBdFukGPA
         HapCIwG2E43gjb+CDlM90RtGfI5U10YUrOG4sC08mr/3BEst9l3fv9DFyW/fv2J+XchQ
         lOjP8308tIZEPAlEdTV8xP9M6qHhYAMT7sgg/YgJZ0aiEV9LQvGhCbM5iY7X4gG57tc7
         0WjpV0HhPMimPE0ccRP5nydhOyFeAPnNIr3y54qHrfvcsnsSnX+SoSndUA6O+jLOLD74
         KTybzbDz3apEAT5wnMpa0pRvz9bNA2Syuj8eEEZUZIGaK3Fm2RHoPSakz/pom61a48y6
         ljGA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from;
        bh=sbCKv7XdShDnZmJZiw6zbuAEbx3BgFI/56gmXr+zGao=;
        b=iyQSTPOXbkB6JZ9phu57NMR7T5sD75HJ4qYupfb8aBbIrks6paQIRM9QptDO6tS/OH
         WYCDyMhJ1mQqmSeDAcxmLvlp0tOGFqn3/Zrx3TUNEri9Ieog2O7uIzGyZmBm9Ez+X/xA
         U3tanFCuLz8TFulUQU8aM9n+96nRRA4JXLaUmirYMzUttP/Lb2tCXppKBFsxNMnP7kEf
         2o1KbGzslhr994dhsHkcn6eawSHTa8gVZzSyveVlZ/drOXXFEZRSq5KRgsEkBzdq1xHN
         0shkYges77vdOwOp+zRnhhuvabuNn1wctaBDedTfB0ydUYdMiDyK3d1Sk8rfvNOVf1Fe
         aEtg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id d2si602822pfr.4.2021.01.22.07.56.56
        for <kasan-dev@googlegroups.com>;
        Fri, 22 Jan 2021 07:56:56 -0800 (PST)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 0B13911D4;
	Fri, 22 Jan 2021 07:56:56 -0800 (PST)
Received: from e119884-lin.cambridge.arm.com (e119884-lin.cambridge.arm.com [10.1.196.72])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 3EDC43F719;
	Fri, 22 Jan 2021 07:56:54 -0800 (PST)
From: Vincenzo Frascino <vincenzo.frascino@arm.com>
To: linux-arm-kernel@lists.infradead.org,
	linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com
Cc: Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Leon Romanovsky <leonro@mellanox.com>,
	Andrey Konovalov <andreyknvl@google.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will@kernel.org>,
	Mark Rutland <mark.rutland@arm.com>,
	"Paul E . McKenney" <paulmck@kernel.org>,
	Naresh Kamboju <naresh.kamboju@linaro.org>
Subject: [PATCH v4 0/3] kasan: Fix metadata detection for KASAN_HW_TAGS
Date: Fri, 22 Jan 2021 15:56:39 +0000
Message-Id: <20210122155642.23187-1-vincenzo.frascino@arm.com>
X-Mailer: git-send-email 2.30.0
MIME-Version: 1.0
X-Original-Sender: vincenzo.frascino@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172
 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
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

With the introduction of KASAN_HW_TAGS, kasan_report() currently assumes
that every location in memory has valid metadata associated. This is due
to the fact that addr_has_metadata() returns always true.

As a consequence of this, an invalid address (e.g. NULL pointer address)
passed to kasan_report() when KASAN_HW_TAGS is enabled, leads to a
kernel panic.

Example below, based on arm64:

 ==================================================================
 BUG: KASAN: invalid-access in 0x0
 Read at addr 0000000000000000 by task swapper/0/1
 Unable to handle kernel NULL pointer dereference at virtual address 0000000000000000
 Mem abort info:
   ESR = 0x96000004
   EC = 0x25: DABT (current EL), IL = 32 bits
   SET = 0, FnV = 0
   EA = 0, S1PTW = 0
 Data abort info:
   ISV = 0, ISS = 0x00000004
   CM = 0, WnR = 0

...

 Call trace:
  mte_get_mem_tag+0x24/0x40
  kasan_report+0x1a4/0x410
  alsa_sound_last_init+0x8c/0xa4
  do_one_initcall+0x50/0x1b0
  kernel_init_freeable+0x1d4/0x23c
  kernel_init+0x14/0x118
  ret_from_fork+0x10/0x34
 Code: d65f03c0 9000f021 f9428021 b6cfff61 (d9600000)
 ---[ end trace 377c8bb45bdd3a1a ]---
 hrtimer: interrupt took 48694256 ns
 note: swapper/0[1] exited with preempt_count 1
 Kernel panic - not syncing: Attempted to kill init! exitcode=0x0000000b
 SMP: stopping secondary CPUs
 Kernel Offset: 0x35abaf140000 from 0xffff800010000000
 PHYS_OFFSET: 0x40000000
 CPU features: 0x0a7e0152,61c0a030
 Memory Limit: none
 ---[ end Kernel panic - not syncing: Attempted to kill init! exitcode=0x0000000b ]---

This series fixes the behavior of addr_has_metadata() that now returns
true only when the address is valid.

Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
Cc: Alexander Potapenko <glider@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>
Cc: Leon Romanovsky <leonro@mellanox.com>
Cc: Andrey Konovalov <andreyknvl@google.com>
Cc: Catalin Marinas <catalin.marinas@arm.com>
Cc: Will Deacon <will@kernel.org>
Cc: Mark Rutland <mark.rutland@arm.com>
Cc: Paul E. McKenney <paulmck@kernel.org>
Cc: Naresh Kamboju <naresh.kamboju@linaro.org>
Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>

Vincenzo Frascino (3):
  arm64: Improve kernel address detection of __is_lm_address()
  kasan: Add explicit preconditions to kasan_report()
  kasan: Make addr_has_metadata() return true for valid addresses

 arch/arm64/include/asm/memory.h | 6 ++++--
 include/linux/kasan.h           | 7 +++++++
 mm/kasan/kasan.h                | 2 +-
 3 files changed, 12 insertions(+), 3 deletions(-)

-- 
2.30.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210122155642.23187-1-vincenzo.frascino%40arm.com.
