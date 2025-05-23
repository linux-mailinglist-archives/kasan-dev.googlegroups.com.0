Return-Path: <kasan-dev+bncBDCPL7WX3MKBBD7YX7AQMGQEMNHBSJA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53d.google.com (mail-pg1-x53d.google.com [IPv6:2607:f8b0:4864:20::53d])
	by mail.lfdr.de (Postfix) with ESMTPS id 21C2AAC1B0A
	for <lists+kasan-dev@lfdr.de>; Fri, 23 May 2025 06:39:45 +0200 (CEST)
Received: by mail-pg1-x53d.google.com with SMTP id 41be03b00d2f7-b26cdc70befsf5760429a12.1
        for <lists+kasan-dev@lfdr.de>; Thu, 22 May 2025 21:39:45 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1747975183; cv=pass;
        d=google.com; s=arc-20240605;
        b=K/TiUYQClJg79f99XH9FPI/t+FuW1MBPD8OClyWEQxd9BxdZhu4vO4yh7UNegf/TEc
         nCm1bD7QW/Y6jh57xeUYNTPuRLsaPQIRvXGoZqg4IKWE/NHmyLnZyjPsbtWrH9CHlAok
         y7PWkHfVi7bwEb/fDg2GkUYpBGJIkbLOirIMinFjbQVlJk7C9f94LaCtepfw7TjeUElr
         sAkn5MHJCe9jK3mAiaaOTGFJFxQUgYz575kwEM86uxCN4EePoY/82bKa86RtrdTVr+5g
         cbHSRivXhBPY+TxKbNDkEaDu8Ke1S99PdgmYOP+ABpqcJiRWUAb1tdGoaDuCj+vR7dc1
         Mi8Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=cAbn8svgNiZFJyY7jUxmrLz8dZru3bRGet4EHLGx0V4=;
        fh=AW/yUp2aeJb5Ds6SiPX7NaSX43kBAFD6Tq3dgGHbG7w=;
        b=G7E9hVI+T+HgeXJ8rB6ymSfFoy5xxIwt5f4AmM5RrA+vmW0cdeQoNIDCx7/0sQKtwW
         XSseW8qLoZjQIuTpsFOZoFa1KgS4I6qeKo9pvOtAvr2CvF02aq5NIq/oZQ4I0T1y2eTN
         peP/kcfdoe9fOiLw9WDc5jkSEXehplznx1l0/R9NYBhqN4SkMKw4zFT2avdNjc+no75d
         OUxVHFDmlIh6o5dfqDxjauJuyio5WDabrQJthOvxa/HHzSoNqDZuDdtL0qD4cGcI9lE8
         iPoE1sWFJWiGOkMGlKamkx2VzXUJTtd5RVwGB8AWHiJZO0/YClenT4zQkLJPwnEGHKKk
         wVkQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=uUwE0i0m;
       spf=pass (google.com: domain of kees@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1747975183; x=1748579983; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=cAbn8svgNiZFJyY7jUxmrLz8dZru3bRGet4EHLGx0V4=;
        b=SLsu4c8ihhE8KBVv7SQkVRCU/m17HnRoa5AE+iM+HLFOcueQwR82WSpi9XuhgJfRnV
         x4aNyp3Nvw/inlQACUzIPHEROqRwk9ggNT7BlMuD5jVD5ZAmCK9EQuRdfB4EVvp9iJRN
         OI5LSr+PMQaOQaIVTLXYKUFP37Wtv4jAH5TT/UGMindCt1svm8Anuic+CTDubKHq4oi3
         JW3SM5pB2A1+8R9+bVWJmrlBOsQmn0noPOc0BtbAkaOfQrlFnzJ8tCdiWZ8/o4/93no0
         MUhQCNTWX/V+N/6OsaIF1/JHyS0o6xqGzhpkfyDC4gE3PCMUDbhFzD5+oLtmaCIoHvfF
         olKg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1747975183; x=1748579983;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=cAbn8svgNiZFJyY7jUxmrLz8dZru3bRGet4EHLGx0V4=;
        b=vIhT3iUBmZtGPxzlkj4ynyf0tX7FGGEQXyQCBCmxoqyiUcmQ9rhTGHHjhUswuXqIG5
         pEukpiDJJunNUt/gbVSAZgx+b8hJzo4IvXsgpPFb1JIgj9iwwcGqXkgOgkbQUrFuFQPU
         sDnU/L4cQHuna1vp6C+r009atfho7C53pltp/sp3LNBtLcJv1NdhjbuXUgBbCVbKprfv
         nymNW/CkI87f1Sruz9frRbhurweDaU9zwQ1xzSH8RNkfK3o3Gh9+CmDQJsCAjew+oXEf
         QORPf1lMjX4mHN03QGbnmnCSRobZex6U6gQt026b0rFZ3qnJdisQD7Zk5Y251OYCgKzM
         7h1w==
X-Forwarded-Encrypted: i=2; AJvYcCVhpR4H6y1FuTuuYvzEEx2Dyrdx4R3c4GCyTR7O5Z9WFOm0uTsIHZiXIjtw7mqeoUt2VCrLsg==@lfdr.de
X-Gm-Message-State: AOJu0Yxzlwox9H4r2V5GdyIl2tddBfdNj8qC7OzU0g29zJoMCMGfjLhz
	3Ej4V3l3rxC4uVf99u/FFwp+kIUNMhXoVdwS0neTaemPT/DCtdF02dQ1
X-Google-Smtp-Source: AGHT+IE8+2/YmyxLej6ZDhDhkr+/4ncRTaLhufWLy2/J6Aywkoq6xhY1wBH2d5VBH3VtIkO6uaMn3w==
X-Received: by 2002:a17:90b:164f:b0:310:8d73:c54f with SMTP id 98e67ed59e1d1-310e96b6072mr2930152a91.2.1747975183341;
        Thu, 22 May 2025 21:39:43 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AVT/gBGlnHz4Lqu6jSgB9fBKdKxswcxoKV7WLHJxLNNAIFMMtw==
Received: by 2002:a17:90b:4d0b:b0:301:1dae:aee with SMTP id
 98e67ed59e1d1-30e4f16fd9als4685317a91.1.-pod-prod-07-us; Thu, 22 May 2025
 21:39:42 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCV2xYpluLRMMCcw+k//K9Pxqc8KxdDd0K2OeKWyLuxn7dtBB/YTnPInfArMbeK7utH5REvXozCmaJQ=@googlegroups.com
X-Received: by 2002:a17:90b:1645:b0:2ee:94d1:7a89 with SMTP id 98e67ed59e1d1-310e96b6096mr2519845a91.1.1747975181872;
        Thu, 22 May 2025 21:39:41 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1747975181; cv=none;
        d=google.com; s=arc-20240605;
        b=hI2oYzJvBYT8r7JJZ+BUd559QgQiUVoBPV8Oys+FAZY0yQzWdTwv7AbDG/XYIOpE1Y
         X6STNrVP87eOHUoMqxp/1FIgWA+hd8etEdYcFFGDZmlf98pJ/QC6P3Ou9NZQ3hMZwWpo
         AMpVBWxZr9aGB28z44z3xdtCYkvnkNpRXJ9dcVXiqhWwa1D/n+6Gw3Ta1jxBS71WdeJ6
         K9bOxecGDAcHhp4Ji6GWRhF4HshbMHlv3hfkQAOjO9i0zAIStbCKOHiycm1SMvetTrzf
         IGJLLaLO1cew0BAHYeRSwS+hCt1m0IT3Z5dm3lbtBZ0UG5t/6iGNI8Z9RTbG4w3kf6Ko
         j0nA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=pSjMR1x9fxvd3CNHCT9Z5p4pNb/EakIO+LJLpVc6pwE=;
        fh=rhebiVZ6yfpnItgrQtRxXLSNHMVKMLifsGq3vYpVhYo=;
        b=DiuIXVYXxb+mykFOTSNg287WPQpkJZU7yeLYDR7DZq+8IY4Jm4dLyFRTGXYZI89rdd
         WUE7JIbbidisbmMs4EFH3uliyjA4X6XxUn+Wwrr1WfJ5hGHpBxTPEu1fBazbPt6DZPZD
         Rq7kPKI+Yl0lRjv/RwmmANcmAh6grsbrxpLz68GH3o+wDtac6+Y2tOAbpKhgIdAIGd+u
         fikSs9/R6YQVABKdAB+05/8vGe4qETg1Etm7LuS5AOJ3RSSHP09LnOHqYJb3eaQaovm6
         UrxKlbFEbfIK/OfS+I+yQaj6pVTf//v+p1ARoWd27a/YqXude8+QjdIadLbjTIskTq1i
         +Jfw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=uUwE0i0m;
       spf=pass (google.com: domain of kees@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from sea.source.kernel.org (sea.source.kernel.org. [2600:3c0a:e001:78e:0:1991:8:25])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-30e5c14b62dsi1326196a91.0.2025.05.22.21.39.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 22 May 2025 21:39:41 -0700 (PDT)
Received-SPF: pass (google.com: domain of kees@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) client-ip=2600:3c0a:e001:78e:0:1991:8:25;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id 6FE4B4A969;
	Fri, 23 May 2025 04:39:41 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 420A4C4CEF3;
	Fri, 23 May 2025 04:39:41 +0000 (UTC)
From: "'Kees Cook' via kasan-dev" <kasan-dev@googlegroups.com>
To: Arnd Bergmann <arnd@arndb.de>
Cc: Kees Cook <kees@kernel.org>,
	Russell King <linux@armlinux.org.uk>,
	Daniel Lezcano <daniel.lezcano@linaro.org>,
	Thomas Gleixner <tglx@linutronix.de>,
	Nishanth Menon <nm@ti.com>,
	Santosh Shilimkar <ssantosh@kernel.org>,
	Lee Jones <lee@kernel.org>,
	Allison Randal <allison@lohutok.net>,
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
	linux-arm-kernel@lists.infradead.org,
	"Gustavo A. R. Silva" <gustavoars@kernel.org>,
	Christoph Hellwig <hch@lst.de>,
	Marco Elver <elver@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Ard Biesheuvel <ardb@kernel.org>,
	Masahiro Yamada <masahiroy@kernel.org>,
	Nathan Chancellor <nathan@kernel.org>,
	Nicolas Schier <nicolas.schier@linux.dev>,
	Nick Desaulniers <nick.desaulniers+lkml@gmail.com>,
	Bill Wendling <morbo@google.com>,
	Justin Stitt <justinstitt@google.com>,
	linux-kernel@vger.kernel.org,
	x86@kernel.org,
	kasan-dev@googlegroups.com,
	linux-doc@vger.kernel.org,
	kvmarm@lists.linux.dev,
	linux-riscv@lists.infradead.org,
	linux-s390@vger.kernel.org,
	linux-efi@vger.kernel.org,
	linux-hardening@vger.kernel.org,
	linux-kbuild@vger.kernel.org,
	linux-security-module@vger.kernel.org,
	linux-kselftest@vger.kernel.org,
	sparclinux@vger.kernel.org,
	llvm@lists.linux.dev
Subject: [PATCH v2 05/14] arm: Handle KCOV __init vs inline mismatches
Date: Thu, 22 May 2025 21:39:15 -0700
Message-Id: <20250523043935.2009972-5-kees@kernel.org>
X-Mailer: git-send-email 2.34.1
In-Reply-To: <20250523043251.it.550-kees@kernel.org>
References: <20250523043251.it.550-kees@kernel.org>
MIME-Version: 1.0
X-Developer-Signature: v=1; a=openpgp-sha256; l=3494; i=kees@kernel.org; h=from:subject; bh=ukIvmUzCX4cqw7NZIKavKwcJ5OLiJ4po8qig+DsNSjY=; b=owGbwMvMwCVmps19z/KJym7G02pJDBn6v3/+eOy6cc/2RIGpN/7obJr+t2bVlidcXIkfP8xQ1 a3nOnpNqKOUhUGMi0FWTJElyM49zsXjbXu4+1xFmDmsTCBDGLg4BWAiy0QYGTon/Tmgw7nhdvo/ wRdnq6bd8LbuWrrlwoINcV8Xz6/XsQln+KeoVfztP/+eh4En7ucZ6kupZIYzLLs4sX6mv1rXt5y ayWwA
X-Developer-Key: i=kees@kernel.org; a=openpgp; fpr=A5C3F68F229DD60F723E6E138972F4DFDC6DC026
X-Original-Sender: kees@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=uUwE0i0m;       spf=pass
 (google.com: domain of kees@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25
 as permitted sender) smtp.mailfrom=kees@kernel.org;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Kees Cook <kees@kernel.org>
Reply-To: Kees Cook <kees@kernel.org>
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

When KCOV is enabled all functions get instrumented, unless
the __no_sanitize_coverage attribute is used. To prepare for
__no_sanitize_coverage being applied to __init functions, we have to
handle differences in how GCC's inline optimizations get resolved. For
arm this exposed several places where __init annotations were missing
but ended up being "accidentally correct". Fix these cases and force
several functions to be inline with __always_inline.

Signed-off-by: Kees Cook <kees@kernel.org>
---
Cc: Russell King <linux@armlinux.org.uk>
Cc: Daniel Lezcano <daniel.lezcano@linaro.org>
Cc: Thomas Gleixner <tglx@linutronix.de>
Cc: Nishanth Menon <nm@ti.com>
Cc: Santosh Shilimkar <ssantosh@kernel.org>
Cc: Lee Jones <lee@kernel.org>
Cc: Allison Randal <allison@lohutok.net>
Cc: Greg Kroah-Hartman <gregkh@linuxfoundation.org>
Cc: <linux-arm-kernel@lists.infradead.org>
---
 include/linux/mfd/dbx500-prcmu.h  | 2 +-
 arch/arm/mm/cache-feroceon-l2.c   | 2 +-
 arch/arm/mm/cache-tauros2.c       | 2 +-
 drivers/clocksource/timer-orion.c | 2 +-
 drivers/soc/ti/pm33xx.c           | 2 +-
 5 files changed, 5 insertions(+), 5 deletions(-)

diff --git a/include/linux/mfd/dbx500-prcmu.h b/include/linux/mfd/dbx500-prcmu.h
index 98567623c9df..828362b7860c 100644
--- a/include/linux/mfd/dbx500-prcmu.h
+++ b/include/linux/mfd/dbx500-prcmu.h
@@ -213,7 +213,7 @@ struct prcmu_fw_version {
 
 #if defined(CONFIG_UX500_SOC_DB8500)
 
-static inline void prcmu_early_init(void)
+static inline void __init prcmu_early_init(void)
 {
 	db8500_prcmu_early_init();
 }
diff --git a/arch/arm/mm/cache-feroceon-l2.c b/arch/arm/mm/cache-feroceon-l2.c
index 25dbd84a1aaf..2bfefb252ffd 100644
--- a/arch/arm/mm/cache-feroceon-l2.c
+++ b/arch/arm/mm/cache-feroceon-l2.c
@@ -295,7 +295,7 @@ static inline u32 read_extra_features(void)
 	return u;
 }
 
-static inline void write_extra_features(u32 u)
+static inline void __init write_extra_features(u32 u)
 {
 	__asm__("mcr p15, 1, %0, c15, c1, 0" : : "r" (u));
 }
diff --git a/arch/arm/mm/cache-tauros2.c b/arch/arm/mm/cache-tauros2.c
index b1e1aba602f7..bfe166ccace0 100644
--- a/arch/arm/mm/cache-tauros2.c
+++ b/arch/arm/mm/cache-tauros2.c
@@ -177,7 +177,7 @@ static inline void __init write_actlr(u32 actlr)
 	__asm__("mcr p15, 0, %0, c1, c0, 1\n" : : "r" (actlr));
 }
 
-static void enable_extra_feature(unsigned int features)
+static void __init enable_extra_feature(unsigned int features)
 {
 	u32 u;
 
diff --git a/drivers/clocksource/timer-orion.c b/drivers/clocksource/timer-orion.c
index 49e86cb70a7a..61f1e27fc41e 100644
--- a/drivers/clocksource/timer-orion.c
+++ b/drivers/clocksource/timer-orion.c
@@ -43,7 +43,7 @@ static struct delay_timer orion_delay_timer = {
 	.read_current_timer = orion_read_timer,
 };
 
-static void orion_delay_timer_init(unsigned long rate)
+static void __init orion_delay_timer_init(unsigned long rate)
 {
 	orion_delay_timer.freq = rate;
 	register_current_timer_delay(&orion_delay_timer);
diff --git a/drivers/soc/ti/pm33xx.c b/drivers/soc/ti/pm33xx.c
index dfdff186c805..dc52a2197d24 100644
--- a/drivers/soc/ti/pm33xx.c
+++ b/drivers/soc/ti/pm33xx.c
@@ -145,7 +145,7 @@ static int am33xx_do_sram_idle(u32 wfi_flags)
 	return pm_ops->cpu_suspend(am33xx_do_wfi_sram, wfi_flags);
 }
 
-static int __init am43xx_map_gic(void)
+static int am43xx_map_gic(void)
 {
 	gic_dist_base = ioremap(AM43XX_GIC_DIST_BASE, SZ_4K);
 
-- 
2.34.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250523043935.2009972-5-kees%40kernel.org.
