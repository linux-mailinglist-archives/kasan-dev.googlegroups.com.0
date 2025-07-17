Return-Path: <kasan-dev+bncBDAOJ6534YNBB2MQ4TBQMGQERZO6GDY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x138.google.com (mail-lf1-x138.google.com [IPv6:2a00:1450:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id 839C2B08F39
	for <lists+kasan-dev@lfdr.de>; Thu, 17 Jul 2025 16:27:55 +0200 (CEST)
Received: by mail-lf1-x138.google.com with SMTP id 2adb3069b0e04-553d7f16558sf676131e87.3
        for <lists+kasan-dev@lfdr.de>; Thu, 17 Jul 2025 07:27:55 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1752762475; cv=pass;
        d=google.com; s=arc-20240605;
        b=VeqRSCSvKMyKWU/HXEMrxQbWlzMWoSyJAUf6fexrdvwDEl3Ti1L9y5zooZlOxjFwbh
         uT+MMfGsShiJ/upMHCSfDGoQj7DhNFT/CKHIVjnLbf2NzqzjVQmxM0/b3vOQB1UsjV8f
         KZ3j2NmtNcVb6jUpYe3dyHT0on8iAECWJQUKL7CFjxQcrXi19VIlBDRSJBQ7WhkZsrSD
         +VHmzPPtiHysTS6CNmq2j+o9uLkWmUpdLujLnizDVf9YSb1OAAfyeZ+SS+h1C1M3DCkg
         QOqmm7vR1BQ7RTOTt1QILk3FCfWNy9RtU9+74EHlZdjoKc12J/zv7KYbSm7nkL+ji6Sm
         9v6Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=X7PUZRmbCgaFxdnJcEyDMNbxLEFVkGuoSE6QUrCcB8U=;
        fh=UxIFubq4i1zp8L517rvXuwc70hA3qaNFbnV0Nd/9dpg=;
        b=KF4dPI7RpmPRWcGuxqhu0sahhmqQnDTlKsd3nB1NxN+uETq+YBc/7oopiOLdMVaPNX
         HUo6wONRIXbE/z+52qXXoYwE6/C80f/A5/5VUq/du8qXoDfBdwrtqlfSUg8MtynOolm8
         r+k0BU+yLRQ7MP8t3iSCWVZJeLaeRGGailXjThLMcreN85jn9HvkppUsHSYGhBuVBrOO
         TMeXhMiNjm9fi2LAvrJ6fGOc/gxhybwiz2BWAPmxLj0EPi7Gsq+aerdT9mVaDSZNn6KH
         YWthrHcvspxKGhdPSjtHFshykCiR7JFevhecysBYYcXlAnWpXCYa+AGGbJRlVaUQpBiQ
         egEA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=YLvty5zZ;
       spf=pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::129 as permitted sender) smtp.mailfrom=snovitoll@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1752762474; x=1753367274; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=X7PUZRmbCgaFxdnJcEyDMNbxLEFVkGuoSE6QUrCcB8U=;
        b=fj4+DDQUxCdorL7bWMBafrWGcy03+Vt4FukpUBgYSyOfu6hRod8k0Zc+Pt1jCnCX6G
         G2YB0Iq1WA9PYIJLdwkRPMBVUB0QWA7PNpqEzHcghp+0EsLxeolEwcf4InF69FxA/AHu
         QLUhEa+5pFSbN4jUOlckbO7TIxR3auJmSW/3Dks4kd32xuwS2GA40RvROCCnh0Vt+Ltk
         Fk1ilrggoiQmfWHYRMWK5o6131mhwAgP/43V7ppohvh7o/dGkKzdW9JDtKW13ChLoqCu
         8ppqG5jfLVGlG6687mkPqIcCaYEvSYdtY/XW2SexzeCQ3HOpiMqGnfFPVUFQKrxkeUeR
         GJVA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1752762475; x=1753367275; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=X7PUZRmbCgaFxdnJcEyDMNbxLEFVkGuoSE6QUrCcB8U=;
        b=dPyhFGKV4agd5a2L37ALe1gdGmE4tnUcugLCrcCDI2EjcWuZv1NLIyKCfcCFQmJSCa
         iGyzBvjcHpwMFD+Xd9BxNdtPXq+3xDeohCawavPflXMr7muTQjced55BHBKPaY9FSLJj
         bSKaSBqb0s8NCg5rin8AFezlErI4YK6ZXbXapaLwiIk5lGcnRu7qdwgr4Ekjg/30NdsM
         tSZ+oQD1wYhZLXpnZ6gvdwJLCxwjyO94JfXXND9v/kXctjdyjog/7qII3B+nS4PmLI2Y
         wmsF+uM+idsOHGTCquIICFO/HgDZh8909bPkHPkajgBLH7f2wcbGb/Zka+ohiRhkm99X
         0Utw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1752762475; x=1753367275;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=X7PUZRmbCgaFxdnJcEyDMNbxLEFVkGuoSE6QUrCcB8U=;
        b=ZQYhq/X2YU5WptYsAsUQmNaR5evctKVYbrDt5ygtO0JR2C65pij+ujpxg58CAkbfNV
         teQ43IZMuPRolWC4tTod1CCjlU5TFvM6O3/Mn3lEIa0m7crRqzmcTFHN6flYjbmQc1ll
         wTPXZVCsHSjRhIL4uJYdBvscxBMiiYPt6fybaNfFDdyr4f/daG1BOMV0BExiC8u6L4E+
         7kLIWYqnN2L5dG2han/XW5K4vJvC/e7/GG+MmRN6PIoDbdQD5N6aCqPGUr7fh9Z9Z1TJ
         CtnxDpmWh02popPD8rKHsyoZPyU8vNHN3bsKAoQ1oaaLsMdtHp5BCWjXNTGD2FkGep8r
         8z1w==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVuJD+STQI6hPlRtJqSKTqLIAEbR5FW4MOG5hq64bEO8sB1tTsQDP7UrPMvW2fyCTXKeNRPMg==@lfdr.de
X-Gm-Message-State: AOJu0YxDhRvKcGim0w20q3nukySkA1APRV97SpWlL/2gOI0zzUAYzGN6
	i9jNjPg5vBwhgm/7qwKwadf7jUQkhwNlnfuqzSS6aB6lFsKR36g/7XuU
X-Google-Smtp-Source: AGHT+IE0mj0G8V/rpwpnTE4d2//COMKJIKM8IRyaD2znAeknQNjv0VTYENBFq7y9TvW7hBbAaKdjwg==
X-Received: by 2002:a05:6512:22db:b0:553:ccef:e2f4 with SMTP id 2adb3069b0e04-55a2338acfamr2345972e87.35.1752762474444;
        Thu, 17 Jul 2025 07:27:54 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZecChlMtcV9i2iLjUXZJFix8oG9XUYfTQw5eeqw3Vk6GQ==
Received: by 2002:a19:5f4d:0:b0:553:d22f:f92e with SMTP id 2adb3069b0e04-55a288c10d5ls184590e87.2.-pod-prod-01-eu;
 Thu, 17 Jul 2025 07:27:51 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVUiygZWte+uH7DHX0skckE6zE71mx5cTUqOiORhAX/Q/O+prs0VSnucAz/uT2VpkvXzf196reTsi8=@googlegroups.com
X-Received: by 2002:a05:6512:1390:b0:553:2e90:98b4 with SMTP id 2adb3069b0e04-55a2332efb0mr2534438e87.17.1752762471273;
        Thu, 17 Jul 2025 07:27:51 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1752762471; cv=none;
        d=google.com; s=arc-20240605;
        b=CoeZVUiSM834m+0IyuCgkM54n9S5hCSN4gzVoo7o4pvcxXWXDNMY58kRvRJyQt5zvv
         MIDjFIP5h+h1r5SHpA0dewank9/MKSErBFHBrksWqem740Vm2kt/hzD5DwtAJJ/eycsG
         bJJ/HdJ6T34cr/brJbe0MBbr/M0rRz5WV4/6xExZSX6ATX8pwLM1fQyAvlTFCXzBEDwa
         sKZDf+4fQ4IW3eOhL388dLNzkWvFJR5bmS9SDAQSBusv8ZaTD76inFcAmrk6LyMPvwt9
         hKdXyYMl5rVESURWOGsMd+eGp70HMGOydF1bh/1H0jFEVEIQwTNtkmhmE9ils6MEQlOY
         bnPA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=9U6pXPOm17QNJUh3dL0X5SvDfkuBM+kFPXcpz1Z7hWM=;
        fh=Wm6bgVKX4ntO9PIt3R9X/7K74goyUJGtkgDcdJ0ozlU=;
        b=aSEIUxp+39IF7mfqNoVr64awS7Tf5P0IVXhJ9UBoVEzp0zx8EtuP0lwbrNS4MXG/Zy
         P+KAuDYElqUqAN+1T9pDJnXumeWFvFh25V1yDNxAUrZevtFp6GGjtmyXht/Fu1bnfsfg
         +W0t0trbpPyZB+eSYkzQHZ20pdG+T020lJvbr75d2aBt5X1m6kslg1h/JEM8ZHUmbT6U
         uGn+Upy5IB0AArwF/LrGimWIzW7L7BgftUHjO1lsF8qF7PU259AtIBVGexeqgzMikRkX
         bDHbj3nYQpC7jUO+rHa8i1/pbaQgyNs34wPrY7Wbx/Fr180dCFm2guGwzQokCZjDOzlv
         6Blw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=YLvty5zZ;
       spf=pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::129 as permitted sender) smtp.mailfrom=snovitoll@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-lf1-x129.google.com (mail-lf1-x129.google.com. [2a00:1450:4864:20::129])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-5593c9bd011si294373e87.9.2025.07.17.07.27.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 17 Jul 2025 07:27:51 -0700 (PDT)
Received-SPF: pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::129 as permitted sender) client-ip=2a00:1450:4864:20::129;
Received: by mail-lf1-x129.google.com with SMTP id 2adb3069b0e04-558fa0b2c99so852142e87.2
        for <kasan-dev@googlegroups.com>; Thu, 17 Jul 2025 07:27:51 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXroBVvttQMcp7r769DxyWFdq3W18jvr5HzhLxzq4+Dxw9sTBYt7VmpBynbnrkUlqtwzi3wfIIKrwE=@googlegroups.com
X-Gm-Gg: ASbGnctZWux+C+ScpmcvoGCceEZ6bL4Ky/6h+4w0/1KpsI9jAWlRLNjAqoFWG5NFH3n
	+GPXmCaszlYobQfEPRBtB6hTt2QAWnONdBJHPSBuoETTqLXAErayLc2UwJFkv1Z2SCki4jR8K/k
	LLIKKhVxli2jAHO/JxFz/mlVBtFUsMYpnbrSp7TNgRWqIsFzmxO6nr+hjSVmMnn5m+I59Lak/c+
	Xr7Q9nn4y69/Gmw6AgtHLZDZ66JKU2l93GWMNGEAUFGe76Hn/NXcAON3oOn6vgCZs8iIMAHUD2d
	GnVzwRZsyW7nLTL57OOeCwvxKoGG3nKTvBOkSZG0Uum9ZAo3Nf7++0lcnxY9I2cHBhpBmQYEqU3
	cd8skFZ/khKc0XMemu3PueTzPvpEb829M3knQzz5vZTMY4cuvOlhhMHt3gsrf56Ok1Wes
X-Received: by 2002:a05:6512:78a:b0:553:2868:635c with SMTP id 2adb3069b0e04-55a233db5f5mr1804298e87.48.1752762470559;
        Thu, 17 Jul 2025 07:27:50 -0700 (PDT)
Received: from localhost.localdomain (178.90.89.143.dynamic.telecom.kz. [178.90.89.143])
        by smtp.gmail.com with ESMTPSA id 2adb3069b0e04-55989825fe3sm3022975e87.223.2025.07.17.07.27.47
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 17 Jul 2025 07:27:49 -0700 (PDT)
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
Subject: [PATCH v3 03/12] kasan/powerpc: select ARCH_DEFER_KASAN and call kasan_init_generic
Date: Thu, 17 Jul 2025 19:27:23 +0500
Message-Id: <20250717142732.292822-4-snovitoll@gmail.com>
X-Mailer: git-send-email 2.34.1
In-Reply-To: <20250717142732.292822-1-snovitoll@gmail.com>
References: <20250717142732.292822-1-snovitoll@gmail.com>
MIME-Version: 1.0
X-Original-Sender: snovitoll@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=YLvty5zZ;       spf=pass
 (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::129
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

PowerPC with radix MMU is the primary architecture that needs deferred
KASAN initialization, as it requires complex shadow memory setup before
KASAN can be safely enabled.

Select ARCH_DEFER_KASAN for PPC_RADIX_MMU to enable the static key
mechanism for runtime KASAN control. Other PowerPC configurations
(like book3e and 32-bit) can enable KASAN early and will use
compile-time constants instead.

Also call kasan_init_generic() which handles Generic KASAN initialization.
For PowerPC radix MMU (which selects ARCH_DEFER_KASAN), this enables
the static key. For other PowerPC variants, kasan_enable() is a no-op
and kasan_enabled() returns IS_ENABLED(CONFIG_KASAN).

Remove the PowerPC-specific static key and kasan_arch_is_ready()
implementation in favor of the unified interface.

This ensures that:
- PowerPC radix gets the runtime control it needs
- Other PowerPC variants get optimal compile-time behavior
- No unnecessary overhead is added where not needed

Closes: https://bugzilla.kernel.org/show_bug.cgi?id=217049
Fixes: 55d77bae7342 ("kasan: fix Oops due to missing calls to kasan_arch_is_ready()")
Signed-off-by: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
---
Changes in v3:
- Added CONFIG_ARCH_DEFER_KASAN selection for PPC_RADIX_MMU only
- Kept ARCH_DISABLE_KASAN_INLINE selection since it's needed independently
---
 arch/powerpc/Kconfig                   |  1 +
 arch/powerpc/include/asm/kasan.h       | 12 ------------
 arch/powerpc/mm/kasan/init_32.c        |  2 +-
 arch/powerpc/mm/kasan/init_book3e_64.c |  2 +-
 arch/powerpc/mm/kasan/init_book3s_64.c |  6 +-----
 5 files changed, 4 insertions(+), 19 deletions(-)

diff --git a/arch/powerpc/Kconfig b/arch/powerpc/Kconfig
index c3e0cc83f12..e5a6aae6a77 100644
--- a/arch/powerpc/Kconfig
+++ b/arch/powerpc/Kconfig
@@ -123,6 +123,7 @@ config PPC
 	#
 	select ARCH_32BIT_OFF_T if PPC32
 	select ARCH_DISABLE_KASAN_INLINE	if PPC_RADIX_MMU
+	select ARCH_DEFER_KASAN			if PPC_RADIX_MMU
 	select ARCH_DMA_DEFAULT_COHERENT	if !NOT_COHERENT_CACHE
 	select ARCH_ENABLE_MEMORY_HOTPLUG
 	select ARCH_ENABLE_MEMORY_HOTREMOVE
diff --git a/arch/powerpc/include/asm/kasan.h b/arch/powerpc/include/asm/kasan.h
index b5bbb94c51f..957a57c1db5 100644
--- a/arch/powerpc/include/asm/kasan.h
+++ b/arch/powerpc/include/asm/kasan.h
@@ -53,18 +53,6 @@
 #endif
 
 #ifdef CONFIG_KASAN
-#ifdef CONFIG_PPC_BOOK3S_64
-DECLARE_STATIC_KEY_FALSE(powerpc_kasan_enabled_key);
-
-static __always_inline bool kasan_arch_is_ready(void)
-{
-	if (static_branch_likely(&powerpc_kasan_enabled_key))
-		return true;
-	return false;
-}
-
-#define kasan_arch_is_ready kasan_arch_is_ready
-#endif
 
 void kasan_early_init(void);
 void kasan_mmu_init(void);
diff --git a/arch/powerpc/mm/kasan/init_32.c b/arch/powerpc/mm/kasan/init_32.c
index 03666d790a5..1d083597464 100644
--- a/arch/powerpc/mm/kasan/init_32.c
+++ b/arch/powerpc/mm/kasan/init_32.c
@@ -165,7 +165,7 @@ void __init kasan_init(void)
 
 	/* At this point kasan is fully initialized. Enable error messages */
 	init_task.kasan_depth = 0;
-	pr_info("KASAN init done\n");
+	kasan_init_generic();
 }
 
 void __init kasan_late_init(void)
diff --git a/arch/powerpc/mm/kasan/init_book3e_64.c b/arch/powerpc/mm/kasan/init_book3e_64.c
index 60c78aac0f6..0d3a73d6d4b 100644
--- a/arch/powerpc/mm/kasan/init_book3e_64.c
+++ b/arch/powerpc/mm/kasan/init_book3e_64.c
@@ -127,7 +127,7 @@ void __init kasan_init(void)
 
 	/* Enable error messages */
 	init_task.kasan_depth = 0;
-	pr_info("KASAN init done\n");
+	kasan_init_generic();
 }
 
 void __init kasan_late_init(void) { }
diff --git a/arch/powerpc/mm/kasan/init_book3s_64.c b/arch/powerpc/mm/kasan/init_book3s_64.c
index 7d959544c07..dcafa641804 100644
--- a/arch/powerpc/mm/kasan/init_book3s_64.c
+++ b/arch/powerpc/mm/kasan/init_book3s_64.c
@@ -19,8 +19,6 @@
 #include <linux/memblock.h>
 #include <asm/pgalloc.h>
 
-DEFINE_STATIC_KEY_FALSE(powerpc_kasan_enabled_key);
-
 static void __init kasan_init_phys_region(void *start, void *end)
 {
 	unsigned long k_start, k_end, k_cur;
@@ -92,11 +90,9 @@ void __init kasan_init(void)
 	 */
 	memset(kasan_early_shadow_page, 0, PAGE_SIZE);
 
-	static_branch_inc(&powerpc_kasan_enabled_key);
-
 	/* Enable error messages */
 	init_task.kasan_depth = 0;
-	pr_info("KASAN init done\n");
+	kasan_init_generic();
 }
 
 void __init kasan_early_init(void) { }
-- 
2.34.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250717142732.292822-4-snovitoll%40gmail.com.
