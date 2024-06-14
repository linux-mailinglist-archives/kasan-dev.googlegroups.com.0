Return-Path: <kasan-dev+bncBCWPLY7W6EARBCX5V2ZQMGQEDYCPKXQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63b.google.com (mail-pl1-x63b.google.com [IPv6:2607:f8b0:4864:20::63b])
	by mail.lfdr.de (Postfix) with ESMTPS id 5F5DE9082BB
	for <lists+kasan-dev@lfdr.de>; Fri, 14 Jun 2024 05:52:44 +0200 (CEST)
Received: by mail-pl1-x63b.google.com with SMTP id d9443c01a7336-1f6efa6a51csf939175ad.0
        for <lists+kasan-dev@lfdr.de>; Thu, 13 Jun 2024 20:52:44 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718337162; cv=pass;
        d=google.com; s=arc-20160816;
        b=W0UG1YVTCtHldRh1ebo2D+fspoU+M3sEVxt9dqUyW+hAhi35K/BhDen9oBhDWNZ8ZF
         wiGPdG6tl0SHqQHBdpi/GU0wpXdIPUGPTopnA1ihqJWu2WBCCxMoaSOnpr8QA6Fw94Wn
         eKMMu7ZuWiGy/TN+oNVuYdALNw/2DPj7t5Tafh657Rn9z8kKN5hDoCPKqBenPlVRW6gh
         CoQMngaFf9fz4qUJ6gKqyEfyGNPmD3/c2w4wJQ0QvD4XhTuBB9JMOIdoEois+DLF4Y1N
         Gx5ab5sOthwuGUsO6arWUgoJ4+GSjHkVHt6K7YO6mQ4v9Jt+JgFiD0Z7k6URmnRf7CF/
         lnCg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=8wYg4wk56L/XqbeC2sE8SL6yJpOazPEf1vQHyVh7wQw=;
        fh=NhSTn23q9LsHsj2lUveqhvmxZkrrd8bG5lxt6n9/tFI=;
        b=zXRwUoh5pR4wup88IBHEzs4QPPQxuadlTEcIIvMjrWsDiYNXuHS5wMwoHmpto3VkP4
         yVTwBfHFLpgwvnlUdtNJutIE8eabFPsnuQexdzQ23tr2OQxPGhhbZ/vMGl8PNsW35cT9
         hydNqudZGhYT7n98xQvfzzLnbtF9GEEVvPWtQp6ayH01XBZXPo4WLhX5JRRp8VH3yC64
         Km2EFPdTl1MQvQF2pQYFK1/YrPzaJKClZpp/YbjdBTAT2TBZbr7qt/S52eY//JYCwEam
         griR+3dAUEZB9bBFGv7J68YIUqvaehqyHQhnC53NkwHVtWGFhhdaxqte3frhyTLXdhvl
         jAnQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of liaochang1@huawei.com designates 45.249.212.255 as permitted sender) smtp.mailfrom=liaochang1@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718337162; x=1718941962; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=8wYg4wk56L/XqbeC2sE8SL6yJpOazPEf1vQHyVh7wQw=;
        b=XgkeWjZvHlWq3YhPSOz2O6SH+bJWiCDjI8g7t+S4EdjkaQdOSzrkSGeW+uodkUZjW9
         0XMXjBiQZwNf+XzU3mZgCZroXwiQaLCh2KfEghh9TKzh2P+ojgcM+JxA460mWWzbcpNi
         2jN6wYpQpDXI3xBO8ZFWV5B73fWBsAWKvK7qjcGGab3AUrGBXfGPbw3EosyuQXyyPTAF
         e64I+ajcMS80k0wWyiDq0H6cX9YAqMsGCoiitmYzMILTLUs4de5iltoeb2JkGrTL0Fn2
         educkADVHEQog/n9ziF2kEWF9phtNRY+1ugMIoflqWSSmVdc3dt14Px+wFwtnXvB4eWH
         N+qw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718337162; x=1718941962;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=8wYg4wk56L/XqbeC2sE8SL6yJpOazPEf1vQHyVh7wQw=;
        b=k3fXLsZ50JL6aE5fziPeBS+7mN2HS+Q5wiNObxtQhA/oaSKfpDW827brpuIlvfzm8m
         4lanz5uGbMUIjh1hbZMhK4Q1ZgCxGO0Wa8WllHXaa33FqRZuRhQPdzswI+1yi/xwJY0r
         DedURtQgKJZHWsLJtwUvx94uKzJqoKyIH2lgSWqtG5yUA7Ie2xbcKdLZwMNHt26GOsud
         d1E8HP6ddsrimk9oA0kMFnp5sQ9QC50ojD3vH93V0SHFKrKqgSOYThbQcpWmsRfb2oWS
         OaVL1yoSL7Y1wDHWW5l7k/3gS+yyIOCTJaUmvdxRUTkIbQPSvpyOKORAN+x3V1yMZOF4
         e6dQ==
X-Forwarded-Encrypted: i=2; AJvYcCXXHuy9yWp10Wu758qQhz1tY+R1u5v5StzHc5biV+kZVrXOOlK8dZQzGNtucebiqsx2VIdhbloYpDue1VjGBvdFGEalIZjrCQ==
X-Gm-Message-State: AOJu0YxhshRm2pN+mzY+zuWeacI99USNyfw9RnMW13VV7ABa935EQq1y
	jKHTNopnXn11q9lJXqJwE1pQPB/0puk4A3WpdJ51RnzZc7Ld0XI4
X-Google-Smtp-Source: AGHT+IG6jNrzBZDxUsPKxpyyI5wFQRUhm5VZK/rYk0ykhzEX+g39p8GDz2jWRyTBpAhCNnBy/iuHkw==
X-Received: by 2002:a17:902:860a:b0:1f6:92be:2c9c with SMTP id d9443c01a7336-1f8642b6e04mr1842105ad.6.1718337162406;
        Thu, 13 Jun 2024 20:52:42 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:903:2282:b0:1f7:1a9:bef5 with SMTP id
 d9443c01a7336-1f84d76783els13486985ad.1.-pod-prod-09-us; Thu, 13 Jun 2024
 20:52:41 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWmDNHsRtJ5wOMFPOlPJToZTC1oGeYJL/M/vlAFlfWLWAlmz8j1Mcf+YxdaK1+7td9NPH5jGVfgPxVCbv8qp1vq6vXnv9VXOyXwLA==
X-Received: by 2002:a17:90a:4b82:b0:2c4:dd4b:b5fd with SMTP id 98e67ed59e1d1-2c4dd4bb718mr1352414a91.7.1718337161110;
        Thu, 13 Jun 2024 20:52:41 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718337161; cv=none;
        d=google.com; s=arc-20160816;
        b=ukSe5u+SGZ8cBu/PqpCuh2jRzxEXzYvIX97JW5G5pXVS7mOtYNenn1GlGvOp9mvXKC
         xvD9VcsUuEaQYjDykyGBwAvznnh2mfGg8mZT/t4n2DPE8K6vMM/Xvbd8dMf1CDeM1Jnl
         8hzDN0+P/FvikZZB0y0sxaF/oJt+Ye24s9SgXchxq8hbT1/CJXlf+Pb5E2RrCigaxUW9
         YWhJKf+0fLm7h4K0REZjKfTsv6TdkifhHirPlGX/tb7mhuJ5DB1ByAc/URfeNsEeuXVP
         PGu4SWsMHeuH+WNWOGsSSoHDVaQzHis6sLOgBvcyd7usqnThoHoIw6JDdjlh0wCZUep6
         WQDg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=1DNmFt2ewZ71A4OOOW4Zmsp4rj377sshzejXpzixIhg=;
        fh=v8nlEsPtC8QOgAMy9+ceT2RXXasdZQBfytgK0uDUtEc=;
        b=hRFXKUHms/S1CBVL8RtfHsLqcCTPTrevVSh99gfo5eGbIQHs4VohpioQGpMFDEnfrE
         T3I0uD055jvn74izEOKKRr0wX4/2PrnryFiEZZp11J9782YPbsPBYlYwzHaZAROZ/2Bd
         Mb9Dsl3kj6v3VXUDX1MxyZ0qF+K6MgyEzN+rxnDXm7vX7EUNae9ntjqleARL5lGTuZXd
         5SiaLV5H7tWMn23uhmssbt/C5JSWSyO9YbGVGOwibJh0vGInEnhGJeOmzf2za75mT0dg
         Jieb1Rve6bmazWisXnBIHjUzxuJeVvU5jld+/JGCYmtNpnu+WTtAwm2xMMFVmh9HjWTb
         a/QQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of liaochang1@huawei.com designates 45.249.212.255 as permitted sender) smtp.mailfrom=liaochang1@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
Received: from szxga08-in.huawei.com (szxga08-in.huawei.com. [45.249.212.255])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-2c4a5fae398si510238a91.0.2024.06.13.20.52.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 13 Jun 2024 20:52:41 -0700 (PDT)
Received-SPF: pass (google.com: domain of liaochang1@huawei.com designates 45.249.212.255 as permitted sender) client-ip=45.249.212.255;
Received: from mail.maildlp.com (unknown [172.19.163.48])
	by szxga08-in.huawei.com (SkyGuard) with ESMTP id 4W0lcb2LsMz1SBcM;
	Fri, 14 Jun 2024 11:48:31 +0800 (CST)
Received: from kwepemd200013.china.huawei.com (unknown [7.221.188.133])
	by mail.maildlp.com (Postfix) with ESMTPS id 36DBD180060;
	Fri, 14 Jun 2024 11:52:39 +0800 (CST)
Received: from huawei.com (10.67.174.28) by kwepemd200013.china.huawei.com
 (7.221.188.133) with Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.2.1258.34; Fri, 14 Jun
 2024 11:52:37 +0800
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
Subject: [PATCH v4 09/10] arm64: irqchip/gic-v3: Simplify NMI handling in IRQs disabled context
Date: Fri, 14 Jun 2024 03:44:32 +0000
Message-ID: <20240614034433.602622-10-liaochang1@huawei.com>
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
 (google.com: domain of liaochang1@huawei.com designates 45.249.212.255 as
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

After the recent refactoring to the exception entry code, the value of
PMR is not set to GIC_PRIO_IRQ_ON | GIC_PRIO_IRQ_I_SET unconditionally.
If kernel traps from IRQs disabled context, the PMR happens to
GIC_PRIO_IRQ_OFF, which allow only PESUDO_NMI could be acknowledged.
This patch leverage this fact to remove the unnecessary dropping of PMR
in NMI handler.

Signed-off-by: Liao Chang <liaochang1@huawei.com>
---
 arch/arm64/kernel/entry-common.c |  4 ++--
 drivers/irqchip/irq-gic-v3.c     | 23 +----------------------
 2 files changed, 3 insertions(+), 24 deletions(-)

diff --git a/arch/arm64/kernel/entry-common.c b/arch/arm64/kernel/entry-common.c
index eabfc80df6fb..fb3f5b772f57 100644
--- a/arch/arm64/kernel/entry-common.c
+++ b/arch/arm64/kernel/entry-common.c
@@ -531,6 +531,8 @@ static __always_inline void __el1_pnmi(struct pt_regs *regs,
 static __always_inline void __el1_irq(struct pt_regs *regs,
 				      void (*handler)(struct pt_regs *))
 {
+	local_nmi_disable();
+
 	enter_from_kernel_mode(regs);
 
 	irq_enter_rcu();
@@ -544,8 +546,6 @@ static __always_inline void __el1_irq(struct pt_regs *regs,
 static void noinstr el1_interrupt(struct pt_regs *regs,
 				  void (*handler)(struct pt_regs *))
 {
-	local_nmi_disable();
-
 	if (IS_ENABLED(CONFIG_ARM64_PSEUDO_NMI) && !interrupts_enabled(regs))
 		__el1_pnmi(regs, handler);
 	else
diff --git a/drivers/irqchip/irq-gic-v3.c b/drivers/irqchip/irq-gic-v3.c
index ed7d8d87768f..de869051039b 100644
--- a/drivers/irqchip/irq-gic-v3.c
+++ b/drivers/irqchip/irq-gic-v3.c
@@ -831,28 +831,7 @@ static void __gic_handle_irq_from_irqson(struct pt_regs *regs)
  */
 static void __gic_handle_irq_from_irqsoff(struct pt_regs *regs)
 {
-	u64 pmr;
-	u32 irqnr;
-
-	/*
-	 * We were in a context with IRQs disabled. However, the
-	 * entry code has set PMR to a value that allows any
-	 * interrupt to be acknowledged, and not just NMIs. This can
-	 * lead to surprising effects if the NMI has been retired in
-	 * the meantime, and that there is an IRQ pending. The IRQ
-	 * would then be taken in NMI context, something that nobody
-	 * wants to debug twice.
-	 *
-	 * Until we sort this, drop PMR again to a level that will
-	 * actually only allow NMIs before reading IAR, and then
-	 * restore it to what it was.
-	 */
-	pmr = gic_read_pmr();
-	gic_pmr_mask_irqs();
-	isb();
-	irqnr = gic_read_iar();
-	gic_write_pmr(pmr);
-
+	u32 irqnr = gic_read_iar();
 	__gic_handle_nmi(irqnr, regs);
 }
 
-- 
2.34.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240614034433.602622-10-liaochang1%40huawei.com.
