Return-Path: <kasan-dev+bncBCWPLY7W6EARBA75V2ZQMGQEBI3RHOI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x40.google.com (mail-oa1-x40.google.com [IPv6:2001:4860:4864:20::40])
	by mail.lfdr.de (Postfix) with ESMTPS id D7A149082B6
	for <lists+kasan-dev@lfdr.de>; Fri, 14 Jun 2024 05:52:36 +0200 (CEST)
Received: by mail-oa1-x40.google.com with SMTP id 586e51a60fabf-25475e2dd2dsf1845194fac.2
        for <lists+kasan-dev@lfdr.de>; Thu, 13 Jun 2024 20:52:36 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718337155; cv=pass;
        d=google.com; s=arc-20160816;
        b=yxnANIITsl4xPdVBdI9HjAu5Bu3AiAyyE70A4kO0FSCzXOFTCC0p32Zw/S9UXhjhiO
         4qEQCeiGcEywPBwjyXhuE1COQkQ8aWkynDiNRmsx7hx/fJsZCyyONJK8oMKY/rq5rFlL
         EbSMlhbO+xBDmNw6Mwe7WUZEmg4OWMjnM+0dGr/CX90Q1tBoOHSNzu7W4q2KLYUMRs1y
         coB0EbZ/dtflN3ygaGWfIoaYOF3LgJPmjG11HXJb7c3Bcw1cLi2Agb8hGCWjo1SNa6UF
         tIkW1GSz/r7oMKbLKB4OB2b9Pp9onPlB5FRpkq6X3+Yqz3qVeej2SRoqXuQtwrkNdyYa
         LBrw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=r48nLde/E/9lw0/CIwAfMezvkXWdaYP2a9foGElPuBQ=;
        fh=PUQFLDVen/gvMBMQz5ijWLt9yhjvdgCG6Zd7Zue6Qzg=;
        b=JiQVy18U56vCTSJaOxH5Dggqj3IL8eDspSe1KfyiNbMt/BAp/jJHk5lPYP7IP9DMLe
         /vCzsT5X/c5vukkE1BpQ1rbOi+rdOGF1FUoi/87+kkDiemS0YgDSndVJko2pzLQsAqY3
         oBntfYxMtLZxDc9deXSIYmvbKrxxjTnkDeizCvH/NWAFVKzSXPfC1EOOevETGY8Pdvet
         5L++wnBAwYMAKSmlMJEr9+wdiemyFaHSer8tCV5Q9vovHKjov+YmcRwNHaCZQArBcT2F
         9HYnbAyOX9folSTZURxRettn9FuKBLAdq9XzVyU6omhetUmcaKyLexBANdcDGwkctpDl
         BZUA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of liaochang1@huawei.com designates 45.249.212.255 as permitted sender) smtp.mailfrom=liaochang1@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718337155; x=1718941955; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=r48nLde/E/9lw0/CIwAfMezvkXWdaYP2a9foGElPuBQ=;
        b=ceXVfIv2IVOsxKwcbFhIvQoXR8vwggis5hHrSagHj4mx3Et/njvgLA4IpQflj9LE90
         I3ydH3m2m+tHhqg/pZmzn0ZSpYGd26d+CxOkCJi2k6gyMohhmOg8iX/uEIvs4eP0qkcl
         c+SRcdq0ovabn3/VGcLYYD/ULYqOftv9RJoQ0oeRjItbX6K4ebSKVJiFIfgP7OybG6om
         GpCwbhZzYVFluhQ4gxLu9H1AThUbsDpi3HTkO+QoMLVmYmOHG0ZT82tZOdICGUvTNOzi
         S4Ub1VnCRCz+EO5xe3PBJlSAnwGSzqmUWZCv0d19hYCroMg38ntmnj5cIZD9HAlbwOTz
         lfyQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718337155; x=1718941955;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=r48nLde/E/9lw0/CIwAfMezvkXWdaYP2a9foGElPuBQ=;
        b=W44XvgWCInPMIf2RauzIfwncXBFKtONq4PpAi8GeMa+ZqCo06sjQlJJqEyHt+amTIm
         YNd2u73lnLzHWiRnOmWR1YncENnyaKZR0T7N33BHua1NlagdiVVXxChqC7yTCsaoozLn
         pV4yAMxYbSWHrNpbn+6hq/Fo9eFhGRn3mk9l4dI/0TFRR9bHknXZoCQ7RzrnmdE2Keyu
         ZQoaQKqhZi4DNrPhDEAjbiZvEY/wZYXmyI0w0HQ0H6aZxt14wnEA/szlbsK2DxKuDqQT
         14HoA4Y74lx/+xR5SPgSWlpnrxAEL6UMFQx+zZ0mbg9I4EwYSMn+L/nmcyBU0EzRYKBg
         1Org==
X-Forwarded-Encrypted: i=2; AJvYcCVlST8nfyroDC5f3WqLVVj/yhpUielNQIXkL/Qcc0nLYf+tFtLJLkzeQafdVRTPXjvnQmKEgBHY4krTCLKLVCBGdwYWp/Qq7Q==
X-Gm-Message-State: AOJu0Yw4HKMs+an8tQ7FuR6n290vkZ6RYq8O5rZMzW0KcMp1aB73gjpJ
	SfAu5zCXioogaO/R+BqJkSXYtoSiZrFwMJk3PvM6fLroFk2+VZc/
X-Google-Smtp-Source: AGHT+IHudOjo6/JT2fIxlutUhIkOrciPlqWshjAWDlSo3etf3ionXg9WXyL5WdqHgk9CK2r0pnTOWg==
X-Received: by 2002:a05:6870:440e:b0:24f:e100:ba2d with SMTP id 586e51a60fabf-25842b9b48fmr1580204fac.54.1718337155218;
        Thu, 13 Jun 2024 20:52:35 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:4f85:b0:704:31f1:89d5 with SMTP id
 d2e1a72fcca58-705c944f0cdls967251b3a.1.-pod-prod-04-us; Thu, 13 Jun 2024
 20:52:34 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWD4zii+aBAQNYwZ4cLnQtl6ep+DSxl1Iz4J6POJQ8VScptNt//d8F7wvQaND8NuCRNzh73L8T0QvN96oBJRSNoM8cS81AMMZWZmw==
X-Received: by 2002:a05:6a20:d50a:b0:1b2:b59c:fdb3 with SMTP id adf61e73a8af0-1bae824d5admr1791117637.32.1718337153922;
        Thu, 13 Jun 2024 20:52:33 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718337153; cv=none;
        d=google.com; s=arc-20160816;
        b=Z5N7pkgAkCE+DMnX5nBIzQsV34swpJEtp0GvN0zGhMT5rkzo2eO9LujK9n9+UoJFip
         PHeOkQBaxtUnrWE31fATozrygcp1gFip5gnQkIYy2fcpx1oE/I1g95eoYVoAmk/bkng6
         x/sgGR/1jnmjxKNkR5cFZwVxgRK/++WnYpo2SRfDPgXuVVA+90vQT0rNquVhfXA1uX/Y
         mzrr79agPlckhkRCA81Cx9Hgnsofg0/Dn0GYOYV+bMAEBUinu+Z2DgTcIBoyqnqYQota
         QeQZPkt0nAewsBfQeaDowwRnyBd6viM2F6QaMSqg9etJlIG8JBdxskDyom5sJ/vS1M1G
         4hPg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=BgIx2NOk2Jq2UlT0AeQFqpew3DQF7alOOZb8TH/g9gA=;
        fh=v8nlEsPtC8QOgAMy9+ceT2RXXasdZQBfytgK0uDUtEc=;
        b=eFIr4tMVHsPGIqnzWU3Hgx+C625885tZY7qvXjaF0Q3PMPs05qP6znV2RW1nyYWIPO
         dZAPzLSQThpaM52bK8M700p529DcTi5cewa/AMp4WHAdl4h6vsfM0nor28flvuSqiZgO
         KfbGg43yXh/ql40stuf/W/ehUDc1ShlBdc7w/OXg36eSa1r8HbMDjBSprxxwPF7tcZr4
         nYGefBjT3q2UB5wzhVMRX9VgIisuJHmuBDi3n9HOk5bwdtKwigP0QzxbsRvHy3vZqRIy
         OafNXTVjmmelwYWzYbD27dgZaPj8akDEsXiDxTlHe0y9sf8OKFtCA5IapVWwiMVerfB/
         GVQg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of liaochang1@huawei.com designates 45.249.212.255 as permitted sender) smtp.mailfrom=liaochang1@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
Received: from szxga08-in.huawei.com (szxga08-in.huawei.com. [45.249.212.255])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-2c4a5fb4166si408288a91.0.2024.06.13.20.52.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 13 Jun 2024 20:52:33 -0700 (PDT)
Received-SPF: pass (google.com: domain of liaochang1@huawei.com designates 45.249.212.255 as permitted sender) client-ip=45.249.212.255;
Received: from mail.maildlp.com (unknown [172.19.163.252])
	by szxga08-in.huawei.com (SkyGuard) with ESMTP id 4W0lcR6mZPz1SBXB;
	Fri, 14 Jun 2024 11:48:23 +0800 (CST)
Received: from kwepemd200013.china.huawei.com (unknown [7.221.188.133])
	by mail.maildlp.com (Postfix) with ESMTPS id CC09818007E;
	Fri, 14 Jun 2024 11:52:31 +0800 (CST)
Received: from huawei.com (10.67.174.28) by kwepemd200013.china.huawei.com
 (7.221.188.133) with Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.2.1258.34; Fri, 14 Jun
 2024 11:52:29 +0800
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
Subject: [PATCH v4 05/10] arm64: Sipmlify exception masking during exception entry and exit
Date: Fri, 14 Jun 2024 03:44:28 +0000
Message-ID: <20240614034433.602622-6-liaochang1@huawei.com>
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

Motivation
----------

The current approach to interrupt masking during exception handling
involves an intermediate step, The kernel writes GIC_PRIO_IRQON |
GIC_PRIO_PSR_I_SET into ICC_PMR unconditionally, followed by a specific
value based on different exception cause. Due to this intermediate step
is unnecessary for platform support FEAT_NMI, this patch propose a
simpler interrupt masking for exception entry.

Implementation
--------------

This patch introduces a series of new helper functions to unify
exception masking at entry and exit points.

- local_nmi_disable(): Masks IRQ, FIQ and NMI interrupts (used at
  IRQ/FIQ entry).

- local_irq_serror_enable(): Unmasks IRQ, FIQ, NMI, Serror and Debug
  exceptions, which restore exception masks to the point exception
  ocurrs (used at regular synchronous exception entyr, e.g., SVC etc).

- local_nmi_serror_disable(): Masks IRQ, FIQ, NMI, Serror and Debug
  exceptions (used at Serror entry for safest requirement).

- local_irq_mark_enabled(): Masks IRQ, FIQ and NMI as enabled, but does
  not directly enable them, PSTATE.I still needs to be cleared for the
  kernel supports PSEUDO_NMI.

Benefits
--------

These functions use descriptive names that convey their purpose (e.g.,
local_nmi_disable()), instead of depicting the details about low-level
hardware operations which can vary depending on kernel NMI configure.
Additionally, removing the unnecessary intermediate step during
exception entry may reduce interrupt handling latency slightly.

Signed-off-by: Liao Chang <liaochang1@huawei.com>
---
 arch/arm64/include/asm/daifflags.h | 80 +++++++++++++++++++--------
 arch/arm64/kernel/entry-common.c   | 88 ++++++++++++++----------------
 arch/arm64/kernel/entry.S          |  2 -
 3 files changed, 98 insertions(+), 72 deletions(-)

diff --git a/arch/arm64/include/asm/daifflags.h b/arch/arm64/include/asm/daifflags.h
index 5d502cc0dac2..90bf0bdde3c9 100644
--- a/arch/arm64/include/asm/daifflags.h
+++ b/arch/arm64/include/asm/daifflags.h
@@ -120,28 +120,6 @@ static inline void local_daif_restore(unsigned long flags)
 		trace_hardirqs_off();
 }
 
-/*
- * Called by synchronous exception handlers to restore the DAIF bits that were
- * modified by taking an exception.
- */
-static inline void local_daif_inherit(struct pt_regs *regs)
-{
-	unsigned long flags = regs->pstate & DAIF_MASK;
-
-	if (interrupts_enabled(regs))
-		trace_hardirqs_on();
-
-	if (system_uses_irq_prio_masking())
-		gic_write_pmr(regs->pmr_save);
-
-	/*
-	 * We can't use local_daif_restore(regs->pstate) here as
-	 * system_has_prio_mask_debugging() won't restore the I bit if it can
-	 * use the pmr instead.
-	 */
-	write_sysreg(flags, daif);
-}
-
 /*
  * For Arm64 processor support Armv8.8 or later, kernel supports three types
  * of irqflags, they used for corresponding configuration depicted as below:
@@ -384,4 +362,62 @@ static inline void local_allint_inherit(struct pt_regs *regs)
 	irqflags.fields.allint = regs->pstate & PSR_ALLINT_BIT;
 	__local_allint_restore(irqflags);
 }
+
+/*
+ * local_nmi_disable - Disable IRQ, FIQ and NMI, with or without superpriority.
+ */
+static inline void local_nmi_disable(void)
+{
+	arch_irqflags_t irqflags;
+
+	irqflags.fields.daif = DAIF_PROCCTX_NOIRQ;
+	irqflags.fields.pmr = GIC_PRIO_IRQON | GIC_PRIO_PSR_I_SET;
+	irqflags.fields.allint = PSR_ALLINT_BIT;
+	__local_allint_restore(irqflags);
+}
+
+/*
+ * local_irq_mark_enabled - When the kernel enables priority masking,
+ * interrupts cannot be handled util ICC_PMR_EL1 is set to GIC_PRIO_IRQON
+ * and PSTATE.IF is cleared. This helper function indicates that interrupts
+ * remains in a semi-masked state, requring further clearing of PSTATE.IF.
+ *
+ * Kernel will give a warning, if some function try to enable semi-masked
+ * interrupt via the arch_local_irq_enable() defined in <asm/irqflags.h>.
+ *
+ * This function is typically used before handling the Debug exception.
+ */
+static inline void local_irq_mark_enabled(void)
+{
+	if (system_uses_irq_prio_masking())
+		gic_write_pmr(GIC_PRIO_IRQON | GIC_PRIO_PSR_I_SET);
+}
+
+/*
+ * local_nmi_serror_disable - Disable all types of interrupt including IRQ,
+ * FIQ, Serror and NMI, with or without superpriority.
+ */
+static inline void local_nmi_serror_disable(void)
+{
+	arch_irqflags_t irqflags;
+
+	irqflags.fields.daif = DAIF_ERRCTX;
+	irqflags.fields.pmr = GIC_PRIO_IRQON | GIC_PRIO_PSR_I_SET;
+	irqflags.fields.allint = PSR_ALLINT_BIT;
+	__local_allint_restore(irqflags);
+}
+
+/*
+ * local_irq_serror_enable - Enable all types of interrupt including IRQ, FIQ,
+ * Serror and NMI, with or without superpriority.
+ */
+static inline void local_irq_serror_enable(void)
+{
+	arch_irqflags_t irqflags;
+
+	irqflags.fields.daif = DAIF_PROCCTX;
+	irqflags.fields.pmr = GIC_PRIO_IRQON;
+	irqflags.fields.allint = 0;
+	__local_allint_restore(irqflags);
+}
 #endif
diff --git a/arch/arm64/kernel/entry-common.c b/arch/arm64/kernel/entry-common.c
index 72c2c9d033a8..eabfc80df6fb 100644
--- a/arch/arm64/kernel/entry-common.c
+++ b/arch/arm64/kernel/entry-common.c
@@ -168,7 +168,7 @@ static __always_inline void exit_to_user_mode_prepare(struct pt_regs *regs)
 	if (unlikely(flags & _TIF_WORK_MASK))
 		do_notify_resume(regs, flags);
 
-	local_daif_mask();
+	local_allint_mask();
 
 	lockdep_sys_exit();
 }
@@ -428,9 +428,9 @@ static void noinstr el1_abort(struct pt_regs *regs, unsigned long esr)
 	unsigned long far = read_sysreg(far_el1);
 
 	enter_from_kernel_mode(regs);
-	local_daif_inherit(regs);
+	local_allint_inherit(regs);
 	do_mem_abort(far, esr, regs);
-	local_daif_mask();
+	local_allint_mask();
 	exit_to_kernel_mode(regs);
 }
 
@@ -439,27 +439,27 @@ static void noinstr el1_pc(struct pt_regs *regs, unsigned long esr)
 	unsigned long far = read_sysreg(far_el1);
 
 	enter_from_kernel_mode(regs);
-	local_daif_inherit(regs);
+	local_allint_inherit(regs);
 	do_sp_pc_abort(far, esr, regs);
-	local_daif_mask();
+	local_allint_mask();
 	exit_to_kernel_mode(regs);
 }
 
 static void noinstr el1_undef(struct pt_regs *regs, unsigned long esr)
 {
 	enter_from_kernel_mode(regs);
-	local_daif_inherit(regs);
+	local_allint_inherit(regs);
 	do_el1_undef(regs, esr);
-	local_daif_mask();
+	local_allint_mask();
 	exit_to_kernel_mode(regs);
 }
 
 static void noinstr el1_bti(struct pt_regs *regs, unsigned long esr)
 {
 	enter_from_kernel_mode(regs);
-	local_daif_inherit(regs);
+	local_allint_inherit(regs);
 	do_el1_bti(regs, esr);
-	local_daif_mask();
+	local_allint_mask();
 	exit_to_kernel_mode(regs);
 }
 
@@ -467,6 +467,7 @@ static void noinstr el1_dbg(struct pt_regs *regs, unsigned long esr)
 {
 	unsigned long far = read_sysreg(far_el1);
 
+	local_irq_mark_enabled();
 	arm64_enter_el1_dbg(regs);
 	if (!cortex_a76_erratum_1463225_debug_handler(regs))
 		do_debug_exception(far, esr, regs);
@@ -476,9 +477,9 @@ static void noinstr el1_dbg(struct pt_regs *regs, unsigned long esr)
 static void noinstr el1_fpac(struct pt_regs *regs, unsigned long esr)
 {
 	enter_from_kernel_mode(regs);
-	local_daif_inherit(regs);
+	local_allint_inherit(regs);
 	do_el1_fpac(regs, esr);
-	local_daif_mask();
+	local_allint_mask();
 	exit_to_kernel_mode(regs);
 }
 
@@ -543,7 +544,7 @@ static __always_inline void __el1_irq(struct pt_regs *regs,
 static void noinstr el1_interrupt(struct pt_regs *regs,
 				  void (*handler)(struct pt_regs *))
 {
-	write_sysreg(DAIF_PROCCTX_NOIRQ, daif);
+	local_nmi_disable();
 
 	if (IS_ENABLED(CONFIG_ARM64_PSEUDO_NMI) && !interrupts_enabled(regs))
 		__el1_pnmi(regs, handler);
@@ -565,7 +566,7 @@ asmlinkage void noinstr el1h_64_error_handler(struct pt_regs *regs)
 {
 	unsigned long esr = read_sysreg(esr_el1);
 
-	local_daif_restore(DAIF_ERRCTX);
+	local_nmi_serror_disable();
 	arm64_enter_nmi(regs);
 	do_serror(regs, esr);
 	arm64_exit_nmi(regs);
@@ -576,7 +577,7 @@ static void noinstr el0_da(struct pt_regs *regs, unsigned long esr)
 	unsigned long far = read_sysreg(far_el1);
 
 	enter_from_user_mode(regs);
-	local_daif_restore(DAIF_PROCCTX);
+	local_irq_serror_enable();
 	do_mem_abort(far, esr, regs);
 	exit_to_user_mode(regs);
 }
@@ -594,7 +595,7 @@ static void noinstr el0_ia(struct pt_regs *regs, unsigned long esr)
 		arm64_apply_bp_hardening();
 
 	enter_from_user_mode(regs);
-	local_daif_restore(DAIF_PROCCTX);
+	local_irq_serror_enable();
 	do_mem_abort(far, esr, regs);
 	exit_to_user_mode(regs);
 }
@@ -602,7 +603,7 @@ static void noinstr el0_ia(struct pt_regs *regs, unsigned long esr)
 static void noinstr el0_fpsimd_acc(struct pt_regs *regs, unsigned long esr)
 {
 	enter_from_user_mode(regs);
-	local_daif_restore(DAIF_PROCCTX);
+	local_irq_serror_enable();
 	do_fpsimd_acc(esr, regs);
 	exit_to_user_mode(regs);
 }
@@ -610,7 +611,7 @@ static void noinstr el0_fpsimd_acc(struct pt_regs *regs, unsigned long esr)
 static void noinstr el0_sve_acc(struct pt_regs *regs, unsigned long esr)
 {
 	enter_from_user_mode(regs);
-	local_daif_restore(DAIF_PROCCTX);
+	local_irq_serror_enable();
 	do_sve_acc(esr, regs);
 	exit_to_user_mode(regs);
 }
@@ -618,7 +619,7 @@ static void noinstr el0_sve_acc(struct pt_regs *regs, unsigned long esr)
 static void noinstr el0_sme_acc(struct pt_regs *regs, unsigned long esr)
 {
 	enter_from_user_mode(regs);
-	local_daif_restore(DAIF_PROCCTX);
+	local_irq_serror_enable();
 	do_sme_acc(esr, regs);
 	exit_to_user_mode(regs);
 }
@@ -626,7 +627,7 @@ static void noinstr el0_sme_acc(struct pt_regs *regs, unsigned long esr)
 static void noinstr el0_fpsimd_exc(struct pt_regs *regs, unsigned long esr)
 {
 	enter_from_user_mode(regs);
-	local_daif_restore(DAIF_PROCCTX);
+	local_irq_serror_enable();
 	do_fpsimd_exc(esr, regs);
 	exit_to_user_mode(regs);
 }
@@ -634,7 +635,7 @@ static void noinstr el0_fpsimd_exc(struct pt_regs *regs, unsigned long esr)
 static void noinstr el0_sys(struct pt_regs *regs, unsigned long esr)
 {
 	enter_from_user_mode(regs);
-	local_daif_restore(DAIF_PROCCTX);
+	local_irq_serror_enable();
 	do_el0_sys(esr, regs);
 	exit_to_user_mode(regs);
 }
@@ -647,7 +648,7 @@ static void noinstr el0_pc(struct pt_regs *regs, unsigned long esr)
 		arm64_apply_bp_hardening();
 
 	enter_from_user_mode(regs);
-	local_daif_restore(DAIF_PROCCTX);
+	local_irq_serror_enable();
 	do_sp_pc_abort(far, esr, regs);
 	exit_to_user_mode(regs);
 }
@@ -655,7 +656,7 @@ static void noinstr el0_pc(struct pt_regs *regs, unsigned long esr)
 static void noinstr el0_sp(struct pt_regs *regs, unsigned long esr)
 {
 	enter_from_user_mode(regs);
-	local_daif_restore(DAIF_PROCCTX);
+	local_irq_serror_enable();
 	do_sp_pc_abort(regs->sp, esr, regs);
 	exit_to_user_mode(regs);
 }
@@ -663,7 +664,7 @@ static void noinstr el0_sp(struct pt_regs *regs, unsigned long esr)
 static void noinstr el0_undef(struct pt_regs *regs, unsigned long esr)
 {
 	enter_from_user_mode(regs);
-	local_daif_restore(DAIF_PROCCTX);
+	local_irq_serror_enable();
 	do_el0_undef(regs, esr);
 	exit_to_user_mode(regs);
 }
@@ -671,7 +672,7 @@ static void noinstr el0_undef(struct pt_regs *regs, unsigned long esr)
 static void noinstr el0_bti(struct pt_regs *regs)
 {
 	enter_from_user_mode(regs);
-	local_daif_restore(DAIF_PROCCTX);
+	local_irq_serror_enable();
 	do_el0_bti(regs);
 	exit_to_user_mode(regs);
 }
@@ -679,7 +680,7 @@ static void noinstr el0_bti(struct pt_regs *regs)
 static void noinstr el0_mops(struct pt_regs *regs, unsigned long esr)
 {
 	enter_from_user_mode(regs);
-	local_daif_restore(DAIF_PROCCTX);
+	local_irq_serror_enable();
 	do_el0_mops(regs, esr);
 	exit_to_user_mode(regs);
 }
@@ -687,7 +688,7 @@ static void noinstr el0_mops(struct pt_regs *regs, unsigned long esr)
 static void noinstr el0_inv(struct pt_regs *regs, unsigned long esr)
 {
 	enter_from_user_mode(regs);
-	local_daif_restore(DAIF_PROCCTX);
+	local_irq_serror_enable();
 	bad_el0_sync(regs, 0, esr);
 	exit_to_user_mode(regs);
 }
@@ -697,9 +698,10 @@ static void noinstr el0_dbg(struct pt_regs *regs, unsigned long esr)
 	/* Only watchpoints write FAR_EL1, otherwise its UNKNOWN */
 	unsigned long far = read_sysreg(far_el1);
 
+	local_irq_mark_enabled();
 	enter_from_user_mode(regs);
 	do_debug_exception(far, esr, regs);
-	local_daif_restore(DAIF_PROCCTX);
+	local_irq_serror_enable();
 	exit_to_user_mode(regs);
 }
 
@@ -708,7 +710,7 @@ static void noinstr el0_svc(struct pt_regs *regs)
 	enter_from_user_mode(regs);
 	cortex_a76_erratum_1463225_svc_handler();
 	fp_user_discard();
-	local_daif_restore(DAIF_PROCCTX);
+	local_irq_serror_enable();
 	do_el0_svc(regs);
 	exit_to_user_mode(regs);
 }
@@ -716,7 +718,7 @@ static void noinstr el0_svc(struct pt_regs *regs)
 static void noinstr el0_fpac(struct pt_regs *regs, unsigned long esr)
 {
 	enter_from_user_mode(regs);
-	local_daif_restore(DAIF_PROCCTX);
+	local_irq_serror_enable();
 	do_el0_fpac(regs, esr);
 	exit_to_user_mode(regs);
 }
@@ -785,7 +787,7 @@ static void noinstr el0_interrupt(struct pt_regs *regs,
 {
 	enter_from_user_mode(regs);
 
-	write_sysreg(DAIF_PROCCTX_NOIRQ, daif);
+	local_nmi_disable();
 
 	if (regs->pc & BIT(55))
 		arm64_apply_bp_hardening();
@@ -797,24 +799,14 @@ static void noinstr el0_interrupt(struct pt_regs *regs,
 	exit_to_user_mode(regs);
 }
 
-static void noinstr __el0_irq_handler_common(struct pt_regs *regs)
-{
-	el0_interrupt(regs, handle_arch_irq);
-}
-
 asmlinkage void noinstr el0t_64_irq_handler(struct pt_regs *regs)
 {
-	__el0_irq_handler_common(regs);
-}
-
-static void noinstr __el0_fiq_handler_common(struct pt_regs *regs)
-{
-	el0_interrupt(regs, handle_arch_fiq);
+	el0_interrupt(regs, handle_arch_irq);
 }
 
 asmlinkage void noinstr el0t_64_fiq_handler(struct pt_regs *regs)
 {
-	__el0_fiq_handler_common(regs);
+	el0_interrupt(regs, handle_arch_fiq);
 }
 
 static void noinstr __el0_error_handler_common(struct pt_regs *regs)
@@ -822,11 +814,11 @@ static void noinstr __el0_error_handler_common(struct pt_regs *regs)
 	unsigned long esr = read_sysreg(esr_el1);
 
 	enter_from_user_mode(regs);
-	local_daif_restore(DAIF_ERRCTX);
+	local_nmi_serror_disable();
 	arm64_enter_nmi(regs);
 	do_serror(regs, esr);
 	arm64_exit_nmi(regs);
-	local_daif_restore(DAIF_PROCCTX);
+	local_irq_serror_enable();
 	exit_to_user_mode(regs);
 }
 
@@ -839,7 +831,7 @@ asmlinkage void noinstr el0t_64_error_handler(struct pt_regs *regs)
 static void noinstr el0_cp15(struct pt_regs *regs, unsigned long esr)
 {
 	enter_from_user_mode(regs);
-	local_daif_restore(DAIF_PROCCTX);
+	local_irq_serror_enable();
 	do_el0_cp15(esr, regs);
 	exit_to_user_mode(regs);
 }
@@ -848,7 +840,7 @@ static void noinstr el0_svc_compat(struct pt_regs *regs)
 {
 	enter_from_user_mode(regs);
 	cortex_a76_erratum_1463225_svc_handler();
-	local_daif_restore(DAIF_PROCCTX);
+	local_irq_serror_enable();
 	do_el0_svc_compat(regs);
 	exit_to_user_mode(regs);
 }
@@ -899,12 +891,12 @@ asmlinkage void noinstr el0t_32_sync_handler(struct pt_regs *regs)
 
 asmlinkage void noinstr el0t_32_irq_handler(struct pt_regs *regs)
 {
-	__el0_irq_handler_common(regs);
+	el0_interrupt(regs, handle_arch_irq);
 }
 
 asmlinkage void noinstr el0t_32_fiq_handler(struct pt_regs *regs)
 {
-	__el0_fiq_handler_common(regs);
+	el0_interrupt(regs, handle_arch_fiq);
 }
 
 asmlinkage void noinstr el0t_32_error_handler(struct pt_regs *regs)
diff --git a/arch/arm64/kernel/entry.S b/arch/arm64/kernel/entry.S
index c568b4ff9e62..e61ecb597905 100644
--- a/arch/arm64/kernel/entry.S
+++ b/arch/arm64/kernel/entry.S
@@ -316,8 +316,6 @@ alternative_else_nop_endif
 
 	mrs_s	x20, SYS_ICC_PMR_EL1
 	str	x20, [sp, #S_PMR_SAVE]
-	mov	x20, #GIC_PRIO_IRQON | GIC_PRIO_PSR_I_SET
-	msr_s	SYS_ICC_PMR_EL1, x20
 
 .Lskip_pmr_save\@:
 #endif
-- 
2.34.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240614034433.602622-6-liaochang1%40huawei.com.
