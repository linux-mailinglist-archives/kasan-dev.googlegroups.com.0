Return-Path: <kasan-dev+bncBCWPLY7W6EARBDH5V2ZQMGQEPZYQBQA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc39.google.com (mail-oo1-xc39.google.com [IPv6:2607:f8b0:4864:20::c39])
	by mail.lfdr.de (Postfix) with ESMTPS id E0C839082BC
	for <lists+kasan-dev@lfdr.de>; Fri, 14 Jun 2024 05:52:45 +0200 (CEST)
Received: by mail-oo1-xc39.google.com with SMTP id 006d021491bc7-5baddaafa8bsf1078169eaf.3
        for <lists+kasan-dev@lfdr.de>; Thu, 13 Jun 2024 20:52:45 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718337165; cv=pass;
        d=google.com; s=arc-20160816;
        b=lFZFxjiehYZvQQ9G2YcVE3/+OgzY5TEbf1/P6uIsB+rnq34HC2s/mceQjSYTRk3Chk
         ABVB9hiaxNbtLqmlJZD05QIGJ7fJ9ZPD3zzlaGZjehtaZ75cA7mGtz1iEeP+kg/slwDm
         pyS5cXsYfvSYoJLnYS75pJpgA+X/OvBDatRDEuN+pvVFy00YtdVwbtxhAPJ3Onz25S1J
         Htgt4Hbm6Cm8E1PrJXhNfeN1jWtBrsYwBnxtplZVP5KN+cYBamjJp96IBep/H4VrVzKX
         vKE/dfhZUoLWCSPuB2bERuok+3WVSvLRvNx3qeWfTM8jJ8QQxMc9VFo0sqQjbZJGRl67
         pjVw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=gQmgl3KJODq8HhZ7kXtWSWesJxeM9pLLCP5fbb+Kl5w=;
        fh=YRgSDltVFZtvieKpokDiK3ygyS9lZkr8KepsjMqgbOg=;
        b=nnSpVG7x76B1+cGTkJGW0O1TYMc6wcNBrCu3qXdUjx6oBMaV7U5RFvyTZQpnwG0rM9
         9vZ4wJ5fTvq1NfXQkR6P6YjxbCghMIXrSdOUBR0TtfHjeGJiXj/7NYmEjkPoi6bQe9Sc
         Gt84FrnDws7v09YiLQDBqCkF7iBRt6ymLx5GJx6wju8kbQI9T21TFqQDMr3NNJQb052o
         5ypKjMTKMlWJCJjyBMmTa9R0xsp57r6rKdOcw2+lFYW6JFl7joB6qQVWSA86VaAnTlSC
         2xa4EzYSa/7b6Qnt7yML54ha7LxhIsyXs5LJRVH85eWRJ/xZbv2pHD+oT7ERpL6jnwaq
         jCRQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of liaochang1@huawei.com designates 45.249.212.189 as permitted sender) smtp.mailfrom=liaochang1@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718337165; x=1718941965; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=gQmgl3KJODq8HhZ7kXtWSWesJxeM9pLLCP5fbb+Kl5w=;
        b=TSrkora/zLsFZm0YbrBhwU9hlUsbH0iXYD10VXkZateDZ2+eW6NHjjIp6Y08ZSEcjf
         /N3RgKh/23evsohnf+2x8uzQxrd2VNlNbsWHjgdIPo/efTafrqxGIhqVeYqMe0ETC4Mz
         4PUUcETWr90rVMH8kxKs5dY8EWskPn3ZKhiAQu0XI/D/B6pIi17BTCaZrNPVKkHme88f
         lZcAHws+MxPW0J464gaNQeo2syNZoFICvS0AsocKDfHWBNXtWaAfkhbA0SlTy/ruhN6A
         ndyuAoUEjvKlPJ34UK1Oh+yc2u6P4kn1J8UvVfb0u49dt/J3YLqZhYross6nBip7fvTW
         4HWg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718337165; x=1718941965;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=gQmgl3KJODq8HhZ7kXtWSWesJxeM9pLLCP5fbb+Kl5w=;
        b=L05aDI6aUnCMo9Cgt34nSNwRClxZUJEngusXl/sJatiwqLSO4U37oeCMJgPkqB1XLT
         a8CCAGR6TSHh7eWHbDqk2OPPYLFNXr6BfN11GEg6GqQKkVwzn5VYbMfh3YfZ99gTdp8J
         2rxOD6kNuzazlVYDfyPsVYZyTEFs9AObxISoJUg8lqViWcAGqUL5fgkOAZosCvqObBaY
         qEJAEjt5968XbxBgnIhDYbUUN09tdB7yxE4/TKKr+hrdQDOZmVTmN86/vfleZbtd4S58
         Egd4dvQW3COTHjAgq6iEd5ejZ+p/3sZruEU/HBQ0ArWfgfBODv6jDKxIfBSVCIjQLFxI
         Pc5Q==
X-Forwarded-Encrypted: i=2; AJvYcCXy1sNaujN64ItNxePp96A2btU2UTp6u2+ipL+9X8cAeKhqWXfwdsIpsK+yw2IM/AdBgWZkcHCM6sTrqQsDKfQE+7wHsZSKUQ==
X-Gm-Message-State: AOJu0YyR0FtHOHITiR8uwr6uRbBBzamX1lS4D7p7guKx+LuGnpINZW9F
	3elFymNUCWXHg5VnGEsaYLNn65WLMdxmloYFv3edszMfpIM6hVDe
X-Google-Smtp-Source: AGHT+IGoNIY3+HSlqnCtB7jbOVEt2WvtFsndI3DqmV9/5oqUmFj122MSy96vKaldInQz1ERAO29uFQ==
X-Received: by 2002:a05:6820:2220:b0:5ba:f5f3:987b with SMTP id 006d021491bc7-5bdadb84d41mr1803916eaf.1.1718337164721;
        Thu, 13 Jun 2024 20:52:44 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:ae0a:0:b0:5af:c4b3:9d4f with SMTP id 006d021491bc7-5bcc3e3e6a0ls1309948eaf.2.-pod-prod-06-us;
 Thu, 13 Jun 2024 20:52:44 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWf2+tk5MFmA7Kd7F0Ms7Qpi46hQNJmujfYUD7jIsub3m/cJdGK0Pft+y7dTnoaONRgMmrF+cL04GRCelhB9pqACULQxjMKaFV4+g==
X-Received: by 2002:a05:6820:2220:b0:5ba:f5f3:987b with SMTP id 006d021491bc7-5bdadb84d41mr1803900eaf.1.1718337163748;
        Thu, 13 Jun 2024 20:52:43 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718337163; cv=none;
        d=google.com; s=arc-20160816;
        b=eWM9mSC+MquS603qQqJQDdO25PyFqYrDNnvbEgTx0sHLFgcmTVKC/TilcS9r0n9tJY
         4HlR1oGTmUvyLpgyasBf9Ewqdhtu3h7yhVGQw/UPZ5dCjvubP1IhtTa0XDoq40n378Ei
         1CP//ytSdKyRPJNfIQqImlCcjs0a/JHWw+nnTmErbDKYdJodPfVbvlEPdBrkyV/T726r
         mVwb+SoJHkWHedCG0p6VqGAhe3GBy45EHp5vF3uOfhBIk3H4LhVBDmQFHLGSuR6XCjqe
         y1ZxpfU7vvl6ZEHkGkoHCt4GLDoFZqzobEnJj+OqSNCfY8Glsq2zsV2oOHAReiLei2lo
         06dA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=VjDI0iH3h5qcjjJxUArrerDXnBHreGba6/7+aYhgwAg=;
        fh=v8nlEsPtC8QOgAMy9+ceT2RXXasdZQBfytgK0uDUtEc=;
        b=Pa1ysouo2AAXkcIcfA+E0GhCpkoxliYE0KmaI1GPyjym73V+S3BUGVBKQPRSUCuaC6
         TSmmXxsxONT0i4sLBd2pJjJE6MZkUBHSV7L/M9BisB7wO+6HYTQ2tq4QbOmhOmFuWQCa
         kp428fksDjLhECV/9OyCwBlU4TYNP4MPEvhXln2vLFVuR2qKDmJ0OiPtzbU1fgE9ThC/
         B1hJp8+ZRhnUD8FGFpTJMSAB1GiMKd2/DePWHSY8fdRVHW29MTYS1lsnIfAJyv0Jti+0
         RP97TSO7Jd3NdV7/ZG+6jkB5sHTFFctDXE5ssOyvvMMiR8Fqv3yXzKw9w8VfybYVytI7
         oICw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of liaochang1@huawei.com designates 45.249.212.189 as permitted sender) smtp.mailfrom=liaochang1@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
Received: from szxga03-in.huawei.com (szxga03-in.huawei.com. [45.249.212.189])
        by gmr-mx.google.com with ESMTPS id 006d021491bc7-5bd59ad0251si165537eaf.0.2024.06.13.20.52.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 13 Jun 2024 20:52:43 -0700 (PDT)
Received-SPF: pass (google.com: domain of liaochang1@huawei.com designates 45.249.212.189 as permitted sender) client-ip=45.249.212.189;
Received: from mail.maildlp.com (unknown [172.19.88.105])
	by szxga03-in.huawei.com (SkyGuard) with ESMTP id 4W0ldQ0jZmzPqhv;
	Fri, 14 Jun 2024 11:49:14 +0800 (CST)
Received: from kwepemd200013.china.huawei.com (unknown [7.221.188.133])
	by mail.maildlp.com (Postfix) with ESMTPS id 08F181402C8;
	Fri, 14 Jun 2024 11:52:41 +0800 (CST)
Received: from huawei.com (10.67.174.28) by kwepemd200013.china.huawei.com
 (7.221.188.133) with Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.2.1258.34; Fri, 14 Jun
 2024 11:52:39 +0800
From: "'Liao Chang' via kasan-dev" <kasan-dev@googlegroups.com>
To: <catalin.marinas@arm.com>, <will@kernel.org>, <ryabinin.a.a@gmail.com>,
	<glider@google.com>, <andreyknvl@gmail.com>, <dvyukov@google.com>,
	<vincenzo.frascino@arm.com>, <maz@kernel.org>, <oliver.upton@linux.dev>,
	<james.morse@arm.com>, <suzuki.poulose@arm.com>, <yuzenghui@huawei.com>,
	<mark.rutland@arm.com>, <lpieralisi@kernel.org>, <tglx@linutronix.de>,
	<ardb@kernel.org>, <broonie@kernel.org>, <liaochang1@huawei.com>,
	<steven.price@arm.com>, <ryan.roberts@arm.com>, <pcc@google.com>,
	<anshuman.khandual@arm.com>, <eric.auger@redhat.com>,
	<miguel.luis@oracle.com>, <shiqiliu@hust.edu.cn>, <quic_jiles@quicinc.com>,
	<rafael@kernel.org>, <sudeep.holla@arm.com>, <dwmw@amazon.co.uk>,
	<joey.gouly@arm.com>, <jeremy.linton@arm.com>, <robh@kernel.org>,
	<scott@os.amperecomputing.com>, <songshuaishuai@tinylab.org>,
	<swboyd@chromium.org>, <dianders@chromium.org>,
	<shijie@os.amperecomputing.com>, <bhe@redhat.com>,
	<akpm@linux-foundation.org>, <rppt@kernel.org>, <mhiramat@kernel.org>,
	<mcgrof@kernel.org>, <rmk+kernel@armlinux.org.uk>,
	<Jonathan.Cameron@huawei.com>, <takakura@valinux.co.jp>,
	<sumit.garg@linaro.org>, <frederic@kernel.org>, <tabba@google.com>,
	<kristina.martsenko@arm.com>, <ruanjinjie@huawei.com>
CC: <linux-arm-kernel@lists.infradead.org>, <linux-kernel@vger.kernel.org>,
	<kasan-dev@googlegroups.com>, <kvmarm@lists.linux.dev>
Subject: [PATCH v4 10/10] arm64: Migrate idle context save/restore to logical interrupt masking
Date: Fri, 14 Jun 2024 03:44:33 +0000
Message-ID: <20240614034433.602622-11-liaochang1@huawei.com>
X-Mailer: git-send-email 2.34.1
In-Reply-To: <20240614034433.602622-1-liaochang1@huawei.com>
References: <20240614034433.602622-1-liaochang1@huawei.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Originating-IP: [10.67.174.28]
X-ClientProxiedBy: dggems704-chm.china.huawei.com (10.3.19.181) To
 kwepemd200013.china.huawei.com (7.221.188.133)
X-Original-Sender: liaochang1@huawei.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of liaochang1@huawei.com designates 45.249.212.189 as
 permitted sender) smtp.mailfrom=liaochang1@huawei.com;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
X-Original-From: Liao Chang <liaochang1@huawei.com>
Reply-To: Liao Chang <liaochang1@huawei.com>
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

This patch is part of migration series, replaces the low-level hardware
interrupt masking operations used during CPU idle context save/restore
with the new helper functions starting from local_allint_, it can ensure
the compatibility with future FEAT_NMI feature.

Signed-off-by: Liao Chang <liaochang1@huawei.com>
---
 arch/arm64/include/asm/cpuidle.h   | 24 +++++-------------------
 arch/arm64/include/asm/daifflags.h | 17 ++++++++++++++---
 arch/arm64/kernel/idle.c           |  2 +-
 arch/arm64/kernel/suspend.c        |  2 +-
 drivers/firmware/psci/psci.c       |  2 +-
 5 files changed, 22 insertions(+), 25 deletions(-)

diff --git a/arch/arm64/include/asm/cpuidle.h b/arch/arm64/include/asm/cpuidle.h
index 2047713e097d..b4e230fc8a7b 100644
--- a/arch/arm64/include/asm/cpuidle.h
+++ b/arch/arm64/include/asm/cpuidle.h
@@ -5,32 +5,18 @@
 #include <asm/proc-fns.h>
 
 #ifdef CONFIG_ARM64_PSEUDO_NMI
-#include <asm/arch_gicv3.h>
-
-struct arm_cpuidle_irq_context {
-	unsigned long pmr;
-	unsigned long daif_bits;
-};
+#include <asm/daifflags.h>
 
 #define arm_cpuidle_save_irq_context(__c)				\
 	do {								\
-		struct arm_cpuidle_irq_context *c = __c;		\
-		if (system_uses_irq_prio_masking()) {			\
-			c->daif_bits = read_sysreg(daif);		\
-			write_sysreg(c->daif_bits | PSR_I_BIT | PSR_F_BIT, \
-				     daif);				\
-			c->pmr = gic_read_pmr();			\
-			gic_write_pmr(GIC_PRIO_IRQON | GIC_PRIO_PSR_I_SET); \
-		}							\
+		arch_irqflags_t *c = __c;				\
+		*c = local_allint_save_notrace();			\
 	} while (0)
 
 #define arm_cpuidle_restore_irq_context(__c)				\
 	do {								\
-		struct arm_cpuidle_irq_context *c = __c;		\
-		if (system_uses_irq_prio_masking()) {			\
-			gic_write_pmr(c->pmr);				\
-			write_sysreg(c->daif_bits, daif);		\
-		}							\
+		arch_irqflags_t *c = __c;				\
+		local_allint_restore_notrace(*c);			\
 	} while (0)
 #else
 struct arm_cpuidle_irq_context { };
diff --git a/arch/arm64/include/asm/daifflags.h b/arch/arm64/include/asm/daifflags.h
index 01c7123d5604..f60f933b88e3 100644
--- a/arch/arm64/include/asm/daifflags.h
+++ b/arch/arm64/include/asm/daifflags.h
@@ -84,9 +84,9 @@ static inline void __local_nmi_mask(void)
 	msr_pstate_allint(1);
 }
 
-static inline void local_allint_mask_notrace(void)
+static inline void local_allint_mask_notrace(unsigned long daif_bits)
 {
-	asm volatile ("msr daifset, #0xf" : : : "memory");
+	write_sysreg(daif_bits, daif);
 
 	if (system_uses_irq_prio_masking())
 		__local_pmr_mask();
@@ -97,7 +97,7 @@ static inline void local_allint_mask_notrace(void)
 /* mask/save/unmask/restore all exceptions, including interrupts. */
 static inline void local_allint_mask(void)
 {
-	local_allint_mask_notrace();
+	local_allint_mask_notrace(DAIF_MASK);
 	trace_hardirqs_off();
 }
 
@@ -172,6 +172,17 @@ static inline arch_irqflags_t local_allint_save(void)
 	return irqflags;
 }
 
+static inline arch_irqflags_t local_allint_save_notrace(void)
+{
+	arch_irqflags_t irqflags;
+
+	irqflags = local_allint_save_flags();
+
+	local_allint_mask_notrace(irqflags.fields.daif | PSR_I_BIT | PSR_F_BIT);
+
+	return irqflags;
+}
+
 static inline void __local_pmr_restore(arch_irqflags_t irqflags)
 {
 	/*
diff --git a/arch/arm64/kernel/idle.c b/arch/arm64/kernel/idle.c
index 05cfb347ec26..69b8aa30273e 100644
--- a/arch/arm64/kernel/idle.c
+++ b/arch/arm64/kernel/idle.c
@@ -22,7 +22,7 @@
  */
 void __cpuidle cpu_do_idle(void)
 {
-	struct arm_cpuidle_irq_context context;
+	arch_irqflags_t context;
 
 	arm_cpuidle_save_irq_context(&context);
 
diff --git a/arch/arm64/kernel/suspend.c b/arch/arm64/kernel/suspend.c
index 559f1eb1ae2e..ff6ac032b377 100644
--- a/arch/arm64/kernel/suspend.c
+++ b/arch/arm64/kernel/suspend.c
@@ -99,7 +99,7 @@ int cpu_suspend(unsigned long arg, int (*fn)(unsigned long))
 	int ret = 0;
 	arch_irqflags_t flags;
 	struct sleep_stack_data state;
-	struct arm_cpuidle_irq_context context;
+	arch_irqflags_t context;
 
 	/*
 	 * Some portions of CPU state (e.g. PSTATE.{PAN,DIT}) are initialized
diff --git a/drivers/firmware/psci/psci.c b/drivers/firmware/psci/psci.c
index d9629ff87861..b5089d4d9478 100644
--- a/drivers/firmware/psci/psci.c
+++ b/drivers/firmware/psci/psci.c
@@ -471,7 +471,7 @@ int psci_cpu_suspend_enter(u32 state)
 	int ret;
 
 	if (!psci_power_state_loses_context(state)) {
-		struct arm_cpuidle_irq_context context;
+		arch_irqflags_t context;
 
 		ct_cpuidle_enter();
 		arm_cpuidle_save_irq_context(&context);
-- 
2.34.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240614034433.602622-11-liaochang1%40huawei.com.
