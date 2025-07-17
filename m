Return-Path: <kasan-dev+bncBDCPL7WX3MKBBYUM43BQMGQEXPFHJBQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x440.google.com (mail-pf1-x440.google.com [IPv6:2607:f8b0:4864:20::440])
	by mail.lfdr.de (Postfix) with ESMTPS id 98B6EB09746
	for <lists+kasan-dev@lfdr.de>; Fri, 18 Jul 2025 01:25:35 +0200 (CEST)
Received: by mail-pf1-x440.google.com with SMTP id d2e1a72fcca58-74b537e8d05sf1387059b3a.3
        for <lists+kasan-dev@lfdr.de>; Thu, 17 Jul 2025 16:25:35 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1752794723; cv=pass;
        d=google.com; s=arc-20240605;
        b=ivuK3exaVGKpPOsmzax8+V8hpI6c1sScCwc86IPDl8l6ukPX0jK3QG0zEVDLg4X7fy
         9nMnsUuRNBPcJc+j20oS9t6YBsf6P7fseGePqd6WFzCoXpG78e6jW2+fVmco3O2UESVf
         QCxhZEvAM7nc8A3rqEgYS6V8AidW8AHMjfsrWfLJ2DjsoMsJ70RSkoLXO1mbWhRf8MWT
         L9U/SbpvUXmUHrpYCJoHqCFB9HKR6uNot6qmTw4FaTSoCUOn5CUNXZQR6rtXmGhuzoJz
         es8c59Upou2wspfkUKU2uR/xHpWpvyEBIGGOOJPNV43hOVxnS/1TduavbN+ZrG6IxZ52
         PmVQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=8U/DS0zNgm2C7CsMk3+xDcIZtnLf2orsJjK1pWANTe8=;
        fh=l3b/bGTh67h7sMs6Itx41QXTF07uR68422iRyVDEYsw=;
        b=SnsUG6T9kM05d8NUS0qyyXCtxvNfZGqNXEoMuRM6QKSKXnSpKua23q1SVs4fNm0IeB
         CPpINsAlp/A22gNqTw4+ghk7meL1gnW1MVmuTJwZDzJ3dItGGL+tO0hTiehtei6/KiI7
         zlu7OzUZJ/aPbtgVsEccEavcOCNZHZTyQdViCHUOtP6wCtwjWbFz596utsiiTcC13GUD
         zXsF1oBV3sKw6W7WQfS9AtIdgTPYJzFNh2avw5UvLnhc/En8qMph4r4+uz+mheHk5rWq
         HrfxAqVyfQBgqryYLAjcaPUa+BFMp8n3h0Y3XtauwtpINIWIWm4jKD1UlGM4sdrRTK92
         P4Wg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=rkHtSj4l;
       spf=pass (google.com: domain of kees@kernel.org designates 172.234.252.31 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1752794723; x=1753399523; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=8U/DS0zNgm2C7CsMk3+xDcIZtnLf2orsJjK1pWANTe8=;
        b=XqbKpPLWHY5PAlrumZ/bCImm0Krl7ObFlsIJJr4OYNV+OO/lWsNNlR+KZLF4Xam97T
         Wfeqn6fluuiE8MSznK7gfrDZ5NFHzPwaBFD/TowbJdgJnKCqX9ihdGmf9A2WBMBwJDkN
         KpZtBL4Y93X9QyyuZu4WU9dpXgjDwHo/6WBDw6WZTBrgp56ek3wuyY5/tOizhZCf/an8
         wK5loMsojlYvRR75Goy2QbQJuNV80oiriHhvOCZb/vhO9LegcZN/ooWfwSihH7Hi89Gm
         9mwLS1iKKBEa+xL+Ji4cdgU64OPPW0zycguVl3mJUICSuk/7PcDErPU1pn/6C+nSAfKk
         lmCg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1752794723; x=1753399523;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=8U/DS0zNgm2C7CsMk3+xDcIZtnLf2orsJjK1pWANTe8=;
        b=seYALPm5ZO5c0/rJfVCZ8WHfSTXLhQesHMu8Zcie+4hsisgayzVYE6CwWbnywyXD1S
         T4xmCO7KQlpXK5Mfge+Q4ssURj9NhlKJDIiJxAyUlEg7USCJfjEoNl6V/JFVM6WEwjzT
         w1GlU5CCk6/jZMiaTxEUTVDKBhQoka5LmIK4FKN/PTvg0V2UV3IRJICcId3ONyfCuCOI
         olR1AN8vi5zwj/HyMbUdEqDVVUHabIR4UFF26NnW5xhxMJ9sUtL55VH+yLGyjh9Qyq+R
         LVZiDHx2jEvinYWBZbnbMn6OI1ovvMgpBh1ojWaFUbKp6zDfyQO4W84ozm26gjepVbon
         dLFQ==
X-Forwarded-Encrypted: i=2; AJvYcCW/7WWq5ElfHZZVAZ0H6ft1jiea7rI3qPke0gnC2BQbl1FhrTMw0kXXINVxi2c9F6wb1tp2fA==@lfdr.de
X-Gm-Message-State: AOJu0YxBTG/hs8BKNifhPrHVwilo+qZ4E57NhtImVWWxRb+q7H6ijl+C
	vd14xgV1jmNcROQr77b3/n/UsL2WRuIF/EBkBPzjyBV/ISt9IslKp2oR
X-Google-Smtp-Source: AGHT+IG1fWK+qPczVAg55Jg2SuipIvjazvp4LzqC1tjH4gLXEBamrvsS2qyqpg0d3Uju8fvOxo2lUA==
X-Received: by 2002:a05:6a00:391d:b0:74c:3547:7f0c with SMTP id d2e1a72fcca58-756e819e070mr14535858b3a.3.1752794723123;
        Thu, 17 Jul 2025 16:25:23 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZebE+HymGWWsyoyuQ9mRGIehXrvjz+lEunjVyKLdsBfLA==
Received: by 2002:a05:6a00:3c90:b0:736:a84e:944a with SMTP id
 d2e1a72fcca58-758235f62d6ls1490368b3a.0.-pod-prod-02-us; Thu, 17 Jul 2025
 16:25:22 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXzwHBSm01Ww2Z3CDF5N5BdnVzPcw/QneFgaynkYK5jj+AShznOLGnrDgGTg7XWajQDd1qRwmGb1AI=@googlegroups.com
X-Received: by 2002:a05:6a20:748f:b0:220:9d84:1cf6 with SMTP id adf61e73a8af0-237d7c64606mr15884197637.22.1752794721701;
        Thu, 17 Jul 2025 16:25:21 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1752794721; cv=none;
        d=google.com; s=arc-20240605;
        b=HgpKEyqw0hO0iCMlKtjLsKbOooQ8S8sIleFOQgkfAlxWSsS0I663aUVrHh3TgGwyKS
         V7+aJASGhI5m++r8Bw3BfhlkJgbWLSQVw4Xr9Okgu2kurtg9trpyvO+Ji/U+YG19FgIV
         gUkX283NF0xCVntl1MDTzyeJ4+mosWeO898674Bq/xoy4sQBrVyk2RS1tZev9uMTFNb/
         RkN/2KUlPrL/Yi/zoVjbo1uCAmPTXY2rzqpBqBKPmSD/t6JhlrlCLfmpH2qgKEuEp6Wh
         l7QCalznuzYde99WFkejt+aduPJuzRzb3VpeZhEyPpD9kA9o5pSj/oRp37HUTmLql79X
         5GNw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=ChtZ/qkZniTa98imgF/hybF0gSiormIisVha96eCkyA=;
        fh=H0k6UN04ILvCX/g+1OvdKjuOyhORwCB7imk6QSFcVss=;
        b=SOPxEsKDWFkrCDi44a6NiaEeYjRGr72W18WPLKlBE+bAu5gaismo4UR3lu6RB7YRAM
         QBe0x7p74CM0PqP/kwzT8ZcVxu08Ek8TfWjjClZ2rjcRbFBcCeHQH62x5AXXi/leX2Da
         O8R0XkdZ4FMYzIw0mJ8W8QTn0/T5a/dZ0vF09ah/HKfBoQNp0Ib5EFkMZhCJ6NlsnLij
         nXemy1sxqLErXG/4n+wEMQno6/BBkwJJCCsAgsIx3o7tldMJi2Dez8AYy14NJ/1ZCQ5b
         8MfI1o4i9GUta1WsYLC2raBFdoiSizdL3406Fc/ymhLkf/BGug7N8wHYbx7qgCqJqq1i
         5GVA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=rkHtSj4l;
       spf=pass (google.com: domain of kees@kernel.org designates 172.234.252.31 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from sea.source.kernel.org (sea.source.kernel.org. [172.234.252.31])
        by gmr-mx.google.com with ESMTPS id d2e1a72fcca58-759c4b703e6si11347b3a.0.2025.07.17.16.25.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 17 Jul 2025 16:25:21 -0700 (PDT)
Received-SPF: pass (google.com: domain of kees@kernel.org designates 172.234.252.31 as permitted sender) client-ip=172.234.252.31;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id 2518645D21;
	Thu, 17 Jul 2025 23:25:21 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 71E24C116B1;
	Thu, 17 Jul 2025 23:25:20 +0000 (UTC)
From: "'Kees Cook' via kasan-dev" <kasan-dev@googlegroups.com>
To: Arnd Bergmann <arnd@arndb.de>
Cc: Kees Cook <kees@kernel.org>,
	Nishanth Menon <nm@ti.com>,
	Russell King <linux@armlinux.org.uk>,
	Daniel Lezcano <daniel.lezcano@linaro.org>,
	Thomas Gleixner <tglx@linutronix.de>,
	Santosh Shilimkar <ssantosh@kernel.org>,
	Lee Jones <lee@kernel.org>,
	Allison Randal <allison@lohutok.net>,
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
	linux-arm-kernel@lists.infradead.org,
	Ingo Molnar <mingo@kernel.org>,
	"Gustavo A. R. Silva" <gustavoars@kernel.org>,
	Christoph Hellwig <hch@lst.de>,
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
Subject: [PATCH v3 05/13] arm: Handle KCOV __init vs inline mismatches
Date: Thu, 17 Jul 2025 16:25:10 -0700
Message-Id: <20250717232519.2984886-5-kees@kernel.org>
X-Mailer: git-send-email 2.34.1
In-Reply-To: <20250717231756.make.423-kees@kernel.org>
References: <20250717231756.make.423-kees@kernel.org>
MIME-Version: 1.0
X-Developer-Signature: v=1; a=openpgp-sha256; l=3532; i=kees@kernel.org; h=from:subject; bh=ClXmyf5tYbBw+sj2/5CbB5OIJFvi5W3ekaTQ6nQnftI=; b=owGbwMvMwCVmps19z/KJym7G02pJDBmVbdHzv79/XV1xJstusdnUqKz7Z5dHlrE6aFlJyp1qZ dnzg2NTRykLgxgXg6yYIkuQnXuci8fb9nD3uYowc1iZQIYwcHEKwEReKTD8D5xT9f+GLcsH7/OS +p2zDZ+FrQrRdJgsff/Ac9fi4/Fb0xn+p9lw+6n86zbZmHZD0rOutDS+/8HNzd1tb3IiBPnKK6Y zAwA=
X-Developer-Key: i=kees@kernel.org; a=openpgp; fpr=A5C3F68F229DD60F723E6E138972F4DFDC6DC026
X-Original-Sender: kees@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=rkHtSj4l;       spf=pass
 (google.com: domain of kees@kernel.org designates 172.234.252.31 as permitted
 sender) smtp.mailfrom=kees@kernel.org;       dmarc=pass (p=QUARANTINE
 sp=QUARANTINE dis=NONE) header.from=kernel.org
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

Acked-by: Nishanth Menon <nm@ti.com>
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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250717232519.2984886-5-kees%40kernel.org.
