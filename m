Return-Path: <kasan-dev+bncBDAOJ6534YNBB6UQ4TBQMGQE3VODYVA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33c.google.com (mail-wm1-x33c.google.com [IPv6:2a00:1450:4864:20::33c])
	by mail.lfdr.de (Postfix) with ESMTPS id BEB88B08F43
	for <lists+kasan-dev@lfdr.de>; Thu, 17 Jul 2025 16:28:11 +0200 (CEST)
Received: by mail-wm1-x33c.google.com with SMTP id 5b1f17b1804b1-453817323afsf6878875e9.1
        for <lists+kasan-dev@lfdr.de>; Thu, 17 Jul 2025 07:28:11 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1752762491; cv=pass;
        d=google.com; s=arc-20240605;
        b=czRRLZYZmeuIUOcFP3+ON1GhYac5XilHrXgPRnmhq+guHhcKj+m21D9gS53jPpI94a
         RoIn2pd90Vc/jZRWR3zNSNtG0JuqTdpaugzugJ930WoeTx6u16Q1CfZuysO2GhuNrc5P
         TgWtwwBLDC6hoeUO03SPUvUbYCGl4dHBhPznQj3YhXAd8/q/UhgkLeJ2qkkqlk5Lqiqe
         9fy6BLuKBDPqLzHE24xGTypo4Cz5+rKW0yfG+b/sx1o2V18WIdLO3oFg0l2ur1yoJKuD
         yx5dQUBnemt/rtfDey/NIwnLvY2f6VFdxFdfrGMXZGZP+P//YnVeP87BR9X+GGHQAHHC
         O+KQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=ruP3CCceBcKB2/K59nmRoNJT3+XZkXPaHWrfWQiEa0w=;
        fh=fRApp/0LjV7jaBcF9UHyFIDEPis5JtZiSoNb+pXckVg=;
        b=Qi6ElWpOVS+f0K1HBqtVycjPPSqHTVXDntW0kP4dN0T3+7EWsSHB/a5imxDNdd4f8N
         J8sDbY8F6bAhb5hpEWMhXGiibn33pFEw2rAoET9ynW40bcYm8vgJpB3ApsJ8aOoIKf44
         gmtPtxKVtqQt62yaUqLRz2qYR/QSBJMYodC3fh/As2U83HBdgnZL+45MTc34LK5ieGON
         LOrWEvlJUDjCa0S+oERWy4gyuawYS863F2I0ieKhNp2CCv5xwijL0wYSzFhckqrAiKz+
         QTpUsFzSeFD+HiX44texB5Fbz26O8yG5OxMSmPBPMCSan2Cxtgkdfq2LTDsHdZHZgZUH
         472w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=mbwoUOdg;
       spf=pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::134 as permitted sender) smtp.mailfrom=snovitoll@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1752762491; x=1753367291; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=ruP3CCceBcKB2/K59nmRoNJT3+XZkXPaHWrfWQiEa0w=;
        b=xvhXnG6LvPLOi4qL/MuxA44plDMO9W4Y1ZkPRTbUXofw8EUOfEEqycuQMTie1LvY/6
         9qBON9SlXM0K/t5OhcrY2ODNjLH+3InKdyUMvK6+85b/V3FA5r07El7Fi7dt1/0419/R
         KY6TaUZ73zKQbLCTvqwqvlowNu/3KZE5Oo7qoJX+NBacev4X5rvru+AYoUk+yxGzzEqm
         cPMLq9I1H/uyKe8NjzzM4u5SqED1LiBrW5i/CRSw495aZc0G/gHwyP2jh6+hYOzZLb0r
         pbk/2K35HzeAzmR+QNT+VJWrXGAZKtbddepoc/2YFucI3XzCa/rWti5SuYui/eGzAqQN
         xIFw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1752762491; x=1753367291; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=ruP3CCceBcKB2/K59nmRoNJT3+XZkXPaHWrfWQiEa0w=;
        b=kzaLdnYF4Ho22OjQyQxgT2MpxojzrKDRDRnVdkqlmtHLpVtOfRcAxeCly/Ukv6AXcM
         6KKiqw1H9HMLWcef1OMVT6zcxQvDG2dOf17oKUPCdtNe5HYUG1hmsAaBdauI8ATssHkg
         //+FDRX8toOu9Ptay2ibkzjXIvepdUI8QkC0AgUERMkfm4icAQvjhiDYvec/dCUG9Fw8
         YSlrNLFXoYPsVcyJtR7eECbZ+7nAC9vnRDTkrzBf97a18Y6Gdjm8Vhn8hiNRXMynSgxA
         yujTpO+9yCWBquEH8cjPUUtN6RU/Lw2nBJs6LUXrOD4escJqlrk/dqbRxv9niHc1vGwu
         pQMg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1752762491; x=1753367291;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=ruP3CCceBcKB2/K59nmRoNJT3+XZkXPaHWrfWQiEa0w=;
        b=jEpjOdJpU4B9Im4ruxpv1MFOvUMb1DArNOszI0HAnnoWwQ3utHzHIRbpKc+/YfwMiF
         eVCNcDObce/VLdgKtmDExHX9jDdc4dBdFreStdFG+RUjfKRDFqZkdgpyYKKoec7Bl4vb
         GwOO0SuoZFoKeOXSCxsA3WYMJ7/Id9O07xaUltlZn1lE+Xl0M63yU4ewZcwkraWESMg2
         5bmvU6FkzTHt4OL28aOL1CjWL4efoENakeCf/jNtfg/ggzcV41EFY4wotWhp0UTNh8Mp
         HwNizon8TMdF17yJMz8Zmxf/oGIm1OzA1BKptMrTZAPk4q4HOanqH4fkCwO/TRs8K4SL
         L/RA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVnogsnbT/UQe8XVfWo8tsqDBidEzKODuVZZTB9XYEuWQo8E0IGofSKA2vnDuzG2P6FMTFprg==@lfdr.de
X-Gm-Message-State: AOJu0YztoS2hvx7c8YPhXGYeOU/4R06SNmhnhBZqdrHxkwTDqQPD/qjf
	/XRsoWCX9zcfNZf7hQgSjvexD5a0+kk9oi5QS6NQLVfrNqA59ynXUSVJ
X-Google-Smtp-Source: AGHT+IE1VdCMbmk8F6NxVSw2zGI9zaP8Su/kVs2pNq5GH/vIMvQNvyAuqQkIdI2jHP6hy15hgq1WSQ==
X-Received: by 2002:a05:600c:4e0f:b0:455:ed0f:e8ec with SMTP id 5b1f17b1804b1-4562e046b2dmr79757535e9.9.1752762491052;
        Thu, 17 Jul 2025 07:28:11 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdmvYsEeL+ck7jUXdhCKsG2ZmrzGTu1XjG0eFoMfcJDvQ==
Received: by 2002:a05:6000:430c:b0:39e:cbca:9220 with SMTP id
 ffacd0b85a97d-3b613771cc9ls532440f8f.1.-pod-prod-04-eu; Thu, 17 Jul 2025
 07:28:08 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXcF3oK9pOrCMKStQEGkd/IoWhkZj6up5n6q3lYeHwv49AIfNnwMH+2RMT1JEG3OXXQ+2R93daOHXM=@googlegroups.com
X-Received: by 2002:a05:600c:1912:b0:456:2020:165d with SMTP id 5b1f17b1804b1-4562e2a5cfcmr82467565e9.31.1752762488268;
        Thu, 17 Jul 2025 07:28:08 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1752762488; cv=none;
        d=google.com; s=arc-20240605;
        b=hNhEh26wRca8da4sy6KZ0M+SKWYzZzPOAkf/potyq5Ic+XMYX8mKe4ohdSfc9JgN9j
         PDgMjZn4pCKMZJpvHGzZUdF2wxMTfhK66aEDfNBqLzvHWZsbgAkMgKEanGMMgExelp/X
         +NtSb0MtwpSwSbn+Gj30XtRUnQbrf55fozxK/ZiCA8nwnwB4biF7PusRnAgW9viqQvsA
         vX+Lg2poooltfeUwL+xsKKGsQP9SragQO/YqsW5DDoCGmCrFXf8630oX3FZ22J1r87Bx
         nJfdwNKU077u6D734YzsS2pfP1jAJqO9w5enMvKE6nadNOowG5eNsnX8cBK4XdXCNjjc
         Hc6g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=FVh/EioNiM2ei5SEPjKOjjcyR398WOKR4A8RtqUhr5I=;
        fh=U1IA67hlA8V/7E+Qq6lTdoXth6XdksQ5XH/pU8DZN1c=;
        b=QJE1JsUflL8PrEcmc1PbskGeDOkq/fOqnqpc6/BDGv7N3/1/U3RmUzm39zaBh1wbhN
         BQGKHKgFmB1nreWTyynICab8VLaqDR/ISLBa/Z9JyE3Kjp90CK9ZOaTxSYy1E9GiG8oP
         bv/lP6IbGXJrPsYoT1/7R7Qiqwq+Izu2jNxZy8u/S9IoKRxziyIPttmHRjdSjZBbHqe7
         /W34drAfWu8wPAsHObLMCWb3eIvedlEGkcFTwRhc8tLjTuoP+PEK+jPkvRDM3LKNcKeG
         oteNoGI+tjbMFxajEgIu2ZXdh9UOteAbwHiybuMJeBmWQV6kyxUG2CwmaHUfVvicEf66
         qHqg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=mbwoUOdg;
       spf=pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::134 as permitted sender) smtp.mailfrom=snovitoll@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-lf1-x134.google.com (mail-lf1-x134.google.com. [2a00:1450:4864:20::134])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-3b5e8e09053si217245f8f.6.2025.07.17.07.28.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 17 Jul 2025 07:28:08 -0700 (PDT)
Received-SPF: pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::134 as permitted sender) client-ip=2a00:1450:4864:20::134;
Received: by mail-lf1-x134.google.com with SMTP id 2adb3069b0e04-5561c20e2d5so1339484e87.0
        for <kasan-dev@googlegroups.com>; Thu, 17 Jul 2025 07:28:08 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWgKjsWFOGlsl7y+ttCyd2qdgDRT6vguBjZIaQPB+SMGqmMuJXW5F978R5aY28ISWe3m/y/OTLu+0s=@googlegroups.com
X-Gm-Gg: ASbGncv225ah7a8JcpSidAs0zf2Q1VOqOcHC902oe6yucQjbHfHGJlFoHocjJKrWnLC
	rhJJRyzo9/yQZPAdBprfTen8a5Nch6ZAhU9QFItb5owtmTPWET+gZmxXxIAiY2F+5hKe6HUgdyj
	ZhKLGE57CgvwdWQPAs4ySxDVr2NtU5BznDpo9G47Z2wi2/tOVyFBY3fS4xJit7BM/DzmjwINbKp
	/GuUCw8XQU60NidOMeTH9YV22yxa3JnrkQFFbX7UDN7vsVBhJC7hV9AEEv5bA2vQTjPb0qpKsYg
	bvt3f0ZrxA1/mMYBUeHHLHO30WLMzMVa7zYMzph+UZAlHLNBYCMj6s4cXNjZNq5rt7IKMha74HB
	RGo/plAtiooipy8n0sWf3B7TZJrfiqpBc3zWEiC8cSUqcv2mj2nnKvyswqCdNIENf8Tsi
X-Received: by 2002:a05:6512:611:10b0:553:2e92:2c98 with SMTP id 2adb3069b0e04-55a2339f4b9mr1702111e87.42.1752762487529;
        Thu, 17 Jul 2025 07:28:07 -0700 (PDT)
Received: from localhost.localdomain (178.90.89.143.dynamic.telecom.kz. [178.90.89.143])
        by smtp.gmail.com with ESMTPSA id 2adb3069b0e04-55989825fe3sm3022975e87.223.2025.07.17.07.28.04
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 17 Jul 2025 07:28:06 -0700 (PDT)
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
Subject: [PATCH v3 08/12] kasan/um: select ARCH_DEFER_KASAN and call kasan_init_generic
Date: Thu, 17 Jul 2025 19:27:28 +0500
Message-Id: <20250717142732.292822-9-snovitoll@gmail.com>
X-Mailer: git-send-email 2.34.1
In-Reply-To: <20250717142732.292822-1-snovitoll@gmail.com>
References: <20250717142732.292822-1-snovitoll@gmail.com>
MIME-Version: 1.0
X-Original-Sender: snovitoll@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=mbwoUOdg;       spf=pass
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

UserMode Linux needs deferred KASAN initialization as it has a custom
kasan_arch_is_ready() implementation that tracks shadow memory readiness
via the kasan_um_is_ready flag.

Select ARCH_DEFER_KASAN to enable the unified static key mechanism
for runtime KASAN control. Call kasan_init_generic() which handles
Generic KASAN initialization and enables the static key.

Delete the key kasan_um_is_ready in favor of the unified kasan_enabled()
interface.

Note that kasan_init_generic has __init macro, which is called by
kasan_init() which is not marked with __init in arch/um code.

Closes: https://bugzilla.kernel.org/show_bug.cgi?id=217049
Signed-off-by: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
---
Changes in v3:
- Added CONFIG_ARCH_DEFER_KASAN selection for proper runtime control
---
 arch/um/Kconfig             | 1 +
 arch/um/include/asm/kasan.h | 5 -----
 arch/um/kernel/mem.c        | 4 ++--
 3 files changed, 3 insertions(+), 7 deletions(-)

diff --git a/arch/um/Kconfig b/arch/um/Kconfig
index f08e8a7fac9..fd6d78bba52 100644
--- a/arch/um/Kconfig
+++ b/arch/um/Kconfig
@@ -8,6 +8,7 @@ config UML
 	select ARCH_WANTS_DYNAMIC_TASK_STRUCT
 	select ARCH_HAS_CPU_FINALIZE_INIT
 	select ARCH_HAS_FORTIFY_SOURCE
+	select ARCH_DEFER_KASAN
 	select ARCH_HAS_GCOV_PROFILE_ALL
 	select ARCH_HAS_KCOV
 	select ARCH_HAS_STRNCPY_FROM_USER
diff --git a/arch/um/include/asm/kasan.h b/arch/um/include/asm/kasan.h
index f97bb1f7b85..81bcdc0f962 100644
--- a/arch/um/include/asm/kasan.h
+++ b/arch/um/include/asm/kasan.h
@@ -24,11 +24,6 @@
 
 #ifdef CONFIG_KASAN
 void kasan_init(void);
-extern int kasan_um_is_ready;
-
-#ifdef CONFIG_STATIC_LINK
-#define kasan_arch_is_ready() (kasan_um_is_ready)
-#endif
 #else
 static inline void kasan_init(void) { }
 #endif /* CONFIG_KASAN */
diff --git a/arch/um/kernel/mem.c b/arch/um/kernel/mem.c
index 76bec7de81b..058cb70e330 100644
--- a/arch/um/kernel/mem.c
+++ b/arch/um/kernel/mem.c
@@ -21,9 +21,9 @@
 #include <os.h>
 #include <um_malloc.h>
 #include <linux/sched/task.h>
+#include <linux/kasan.h>
 
 #ifdef CONFIG_KASAN
-int kasan_um_is_ready;
 void kasan_init(void)
 {
 	/*
@@ -32,7 +32,7 @@ void kasan_init(void)
 	 */
 	kasan_map_memory((void *)KASAN_SHADOW_START, KASAN_SHADOW_SIZE);
 	init_task.kasan_depth = 0;
-	kasan_um_is_ready = true;
+	kasan_init_generic();
 }
 
 static void (*kasan_init_ptr)(void)
-- 
2.34.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250717142732.292822-9-snovitoll%40gmail.com.
