Return-Path: <kasan-dev+bncBCOYZDMZ6UMRBNNZYCAAMGQENAFHQZI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3e.google.com (mail-yb1-xb3e.google.com [IPv6:2607:f8b0:4864:20::b3e])
	by mail.lfdr.de (Postfix) with ESMTPS id E3C42303F13
	for <lists+kasan-dev@lfdr.de>; Tue, 26 Jan 2021 14:44:22 +0100 (CET)
Received: by mail-yb1-xb3e.google.com with SMTP id j12sf17868305ybg.4
        for <lists+kasan-dev@lfdr.de>; Tue, 26 Jan 2021 05:44:22 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1611668662; cv=pass;
        d=google.com; s=arc-20160816;
        b=00yKQakFGttYiAYdIm4Bdfbzk9b0iUp4IaJJTva8mXTiVNxNwC+x0xF6HIgSLcbjEo
         yuIQ8WULhohrYFBOEk+CCmUVMM/NhWEDqJoTRSRBFCXTJBkED7xq1TdWH9Eu2/wCunNX
         TkI4Ps5tveSF60it2evoTHZ4HCdgbBb8ZXxSdX0+b1rl1ptVt0VTnYSxAAC68IpRkiSw
         TPb/GQjCEzyCU1kVW4IFbBIZa1WdEYNakPrORBHn+YvqAbYorNWwif5NWTO6tAFoIChw
         Xxk/YYGVYe7W0oD23Sm5/gE8r+3xKePPs2/9SGBEbWEFftl6fT9ooxUim0tG45sg3h8P
         52NQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=6jh2nUCVhfgTl2kruKDtD7ZaIU3HXbnoSCu+4ab0kxU=;
        b=mMqvzZ8QsHShuD9zl4rhbCNkE4QPYlp+Yh0peq2EfVvDMEk8MGBrzHC1uuhuJP+vo/
         i/iZX2h82qudHrjOZ2JmRASfJp5aTbjgMGNcU+tE1JpnqsS/lhFxukhh1q7v6MdQLelG
         8+PcnRULlTLy0EqqEz85g+n3bA1Wr6B9r8xg62e5QR5wa8Wr0mRhG55yQf1t/YdMcsPh
         Nu9SGa48vEtlXvTMqVzGamcmvrEewhZGl1P16nkKiE5pIRhEgPF/sNYotHQMFMTnRGqL
         eR3h548nBdVkBK6nyqSZCZdkfZht0i8Bx6brTdt5U8N/4m5TL38PvxPIY6L13mRrGZx6
         jh7Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=6jh2nUCVhfgTl2kruKDtD7ZaIU3HXbnoSCu+4ab0kxU=;
        b=o5GuN7wE72uqFIPZF87KdHG0bS7XV515PyMtV4ENw+p3/w+EnM8AxqiWsCntEntG8E
         TdQD3FTjVD1MSl4tGGDs6kswNR97lkf7lDqqr1pRAb6gj0xEEQStQ4829V3U5fe8i5aA
         qUrOC8OxBXECpFf5JjFpbjrkIfUVFGAyhHj+WNMnYKlCyXN5WpRyPw7eljOa3N9ajpNy
         JWAIIBNnagxEw2X76hzKPOlIuf/xWvZHg+caj7OY+4OG8gOW3fRszRWsXYGnP3RYl/j1
         v+wjHKnZiKzdAaSwshn8kNoEnRPHq499BB6yJCMLoJvQR7Q4+aCxu7aM04AynLiyippy
         zWgw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=6jh2nUCVhfgTl2kruKDtD7ZaIU3HXbnoSCu+4ab0kxU=;
        b=fw0bJHQ6BlZtcrFPj64pI4tfNtaHz6J/NQ/PEi2BIggtedZETIWLWpfDvP5G0I6EwC
         lc2TxWm2P2x4bTc8NVd0QYxX7E1KPklIXYUWag5EFHMgRPsGVi4HBhbA8xNg4nT3C7FQ
         XoTwrZE9CH40mk5Yvhx3Vd9P+PU1Jj29xmHp2+4Fhw5Z+chDFn5cNUKelrIMsFPg3MOC
         7xwWkejZ6X7b36bnVBck4E+c7C6jA8EH4yrVAHAKnUARH3JXr9E245qao4V3DRNNV5AG
         2Z5l65N9N3uZMKYoW5C33jfrbT/m66VJd4KQe7Cdm+uxVqcQ9UVjni2Ul8Iipg8fcrvM
         oaaQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532mEnvbG096HbFRKWh2+7kM3t3OTkTqxCYB5h/Dp5Od6sqFd+4A
	Y9qUzPsonQ2RwWIwtJYsQdk=
X-Google-Smtp-Source: ABdhPJxjmxHIcs2g06JQBwE8NulF2asHTwAwRWYT5UyDSLWMWw4VugK7TcW7bXTR4ijlmLu9oXpAlw==
X-Received: by 2002:a25:a267:: with SMTP id b94mr8516522ybi.218.1611668661851;
        Tue, 26 Jan 2021 05:44:21 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:8b88:: with SMTP id j8ls181576ybl.3.gmail; Tue, 26 Jan
 2021 05:44:21 -0800 (PST)
X-Received: by 2002:a25:48c8:: with SMTP id v191mr7875967yba.311.1611668661380;
        Tue, 26 Jan 2021 05:44:21 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1611668661; cv=none;
        d=google.com; s=arc-20160816;
        b=cNLlboDtUwYNsC5TgbzzLYtW1PZgComlGIg1ANO5e0Faz7JHxvWLGJEKXlZVtp0NrE
         YCPHAMY9kcL5NEEd45A6weewSNh8hxU4100ws/OnQOdWa0vKUsFydT1HDqsJt522lp9U
         EF5AOOBj0lephhcGbolc9wYulV42cjSf9v+dbIyjwQf+xiR0gCmrYWqNv7tnuK7rO9O5
         bE6XYAK7Qjlyzbbia2EZQVWhOao6ZN/ivron4yRW/WSsCNiZ5IeY5VDcRzjaVLqFs/PM
         RJMBS+rWOli4PWky4qOhuvvg1L0IavxLSfxUNZeLm4CvMQFLUT/SnUAT+0QYzD64Iljy
         9bqQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from;
        bh=52ePbnoeg13VCxLWFe/xJUj0/vBCw+DSYeKK70W5u3g=;
        b=BnVgO1gBJYh5mVnm7FpPJiQ/NbbfPFJ5KRmSC8g1Ir//jLvU1r9v6RUYKY482/uhy2
         RLs0iWJ05I8qfV+FAUrLdX2oigL0vdUO/ZctLk4+dV0zitAGQ33/NOlMprBa/O2IM0cO
         4+Q77lFSvB942LmAuioesUQGeQpBdUyIMX0GiSGJUXqU87F15f9pbRJB/va50zUCrlNC
         +UW6LGfribpg4325WgmMQv/ZzQRQjQzsZ8tFOnQYK2A6dri/M8XKvJhQuONhrclTc0pA
         ++yuA+lDgl7qQQcEtvBF+qf4f7QZOKMXafbxzEztit0cnA7J6hahugaGgu2NfUlrLNgC
         lZTQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id l15si1353195ybf.1.2021.01.26.05.44.21
        for <kasan-dev@googlegroups.com>;
        Tue, 26 Jan 2021 05:44:21 -0800 (PST)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id B481B31B;
	Tue, 26 Jan 2021 05:44:20 -0800 (PST)
Received: from e119884-lin.cambridge.arm.com (e119884-lin.cambridge.arm.com [10.1.196.72])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id CEF043F68F;
	Tue, 26 Jan 2021 05:44:18 -0800 (PST)
From: Vincenzo Frascino <vincenzo.frascino@arm.com>
To: linux-arm-kernel@lists.infradead.org,
	linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com
Cc: Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Andrew Morton <akpm@linux-foundation.org>,
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
Subject: [PATCH v5 0/2] kasan: Fix metadata detection for KASAN_HW_TAGS
Date: Tue, 26 Jan 2021 13:44:07 +0000
Message-Id: <20210126134409.47894-1-vincenzo.frascino@arm.com>
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

Cc: Andrew Morton <akpm@linux-foundation.org>
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

Vincenzo Frascino (2):
  kasan: Add explicit preconditions to kasan_report()
  kasan: Make addr_has_metadata() return true for valid addresses

 include/linux/kasan.h | 7 +++++++
 mm/kasan/kasan.h      | 2 +-
 2 files changed, 8 insertions(+), 1 deletion(-)

-- 
2.30.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210126134409.47894-1-vincenzo.frascino%40arm.com.
