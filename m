Return-Path: <kasan-dev+bncBCWPLY7W6EARBBX5V2ZQMGQEBP2OPQQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc39.google.com (mail-oo1-xc39.google.com [IPv6:2607:f8b0:4864:20::c39])
	by mail.lfdr.de (Postfix) with ESMTPS id F0E6E9082B8
	for <lists+kasan-dev@lfdr.de>; Fri, 14 Jun 2024 05:52:39 +0200 (CEST)
Received: by mail-oo1-xc39.google.com with SMTP id 006d021491bc7-5bacf94fc7asf1632891eaf.0
        for <lists+kasan-dev@lfdr.de>; Thu, 13 Jun 2024 20:52:39 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718337158; cv=pass;
        d=google.com; s=arc-20160816;
        b=vUS87fqFTQMGvD3UzgBJexwyxPhHqgZfPg5Jc+Id5EqW6BOtKOy+G6rw391lc4/J4P
         TIpT5XGHMoj52poG7lQ6IXlKx76wmtSGgP4W/temfCgrrWgnGCaSeo+SIA1d7DsG9C0Y
         RKskzvhfTDWc9ZqPCmSxzo2x36fThFLWOR5/sTwPVt5H2/fgTeYFnzmG4TlTOuHmHjHg
         HKvMGnGnmzMmmXyZFVOI9xQN5mLzdYD9KDXodDrcLmC2X5cFpy76vAw7aHWKJiXoMaPV
         yQhGjnbmQqmq6d/B8nPmHAUG0W+z59oqd4UUkrLt8F7UO9+m8YXEVgDzTC2Zrtlb/tel
         YYDg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=lG0/6DM8uXZ5fgZ4X0+3EdZI3yu1tZvofqkryD6xaAc=;
        fh=Zx1cur1I//7bWZ4KCvA+k0PEYQFiRC+hCN2I79c5Ws4=;
        b=cdDN/OlV5H7CcOmFc4P+xBqPW2BXXgbrpgdRjOij5bp5CBp2098CsfpVkMlEn4mJ7M
         B6DAMM/O0zIk3AcbOO+j8yTQbQWgjwSn9vDplQSqzaHOybLrYXQ/B8z5CAaG/oo2wHW+
         7CIZbKZ94rTpGxnpcBKf2YL7xPzpFqwrYWhBfUr0bIk6X+AdhPiTXh3ankASe3uKDX2E
         I3yFsVtF8KkX/uTPzgaYCCjtRcreoRGHHfkm2SGFtMZoL3OX5E91XG6c3rDL6Bxw1QkQ
         961vUnmJREZf27/rQIwxCgpCwuBriu468yDM46+s4aqB3MX4iXH9T5UP2cJj9NVYi4IS
         dB4Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of liaochang1@huawei.com designates 45.249.212.187 as permitted sender) smtp.mailfrom=liaochang1@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718337158; x=1718941958; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=lG0/6DM8uXZ5fgZ4X0+3EdZI3yu1tZvofqkryD6xaAc=;
        b=HlimvaM2FMbz1qUAVkxHAa4jGu4UM9bA+Wti5xzpdFwzelzKpIDiQEWTMn1GJP48F3
         mcsvpVt7sJ51D14l8BmVTFZnQD6ZuTCb6dp1iI2/Ki9x6E76106APv2CnGLOdzqwLukS
         vphVLyVAPFAAL6XpSe/M6aC6aCfl+b9+m54frhVhJnAlCWKfq7dzBL4Bx4j0i//tKPIv
         F6UxVDv1Xonmn3yeOHRrfsgdrjTUVdzQ1POW6GUSgpsTYj54m38yUekzmEeYxEo/grBX
         oKc7OKCoQErslAsSQEEkSaum0AMzu4vCxALzUrbiT93ADX3W+4QP5aRHfmBSLYceEtqt
         fYPg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718337158; x=1718941958;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=lG0/6DM8uXZ5fgZ4X0+3EdZI3yu1tZvofqkryD6xaAc=;
        b=o8+t8eM+pmt0mMor34/WpYFgc9bn3E67j3hU/VUqyuKYiwNcvUVvgX5PMt34dco8lV
         /1UfEtfIBkYXbN/PgR87r0VYiTKZlwd37NpJS1YsXFdbkeU2VrDR0X+0x5HDtq6Zzr5y
         +8KhRiH2kIMnyM4lHV+5XtnbOmbsxllMpZkRuYyBglPwD3XS0wdxWIIxutZ+xeLPnSTm
         VNHG66YiN9rcFpoGx/+RDYh4EOw9QfIBbu1VC6lvGNsUEPPqym9ELXqKDpsQMBr0brYK
         DIqHaxhImBZpR1jkmB1qd/b2svgCbocfoOHcCI05D/+MRIsfr3Zn0G7Nz8XC2Z40viON
         yatQ==
X-Forwarded-Encrypted: i=2; AJvYcCVnst+hLZLT86Xma2HEbacPm2CE4eYq/F6jO2cDesk/RyjXn7SJ2UTZ14niUg2JTxZixMM/2e+N0vuX9s/xuPFA8b67qtlqVQ==
X-Gm-Message-State: AOJu0Yy3rAk4gnenIaWSXokkMPB/7XZf1gedZAx0lEQo7uhW0CSoZX1a
	iSqI32GJubEjpUXcArZ9xI8d81+U1Q08xy8LFfDWGemodOLH3yzA
X-Google-Smtp-Source: AGHT+IFirv5OgxogxR5zjFBTET0o41PA0DbABZp7XUNngAcPJKBeq+o+BZhkL1hwV8h5KS0u73I8Ag==
X-Received: by 2002:a05:6820:1b8e:b0:5bb:3326:175a with SMTP id 006d021491bc7-5bdadba74eamr1874294eaf.2.1718337158712;
        Thu, 13 Jun 2024 20:52:38 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:5549:0:b0:5b2:73ec:2f15 with SMTP id 006d021491bc7-5bcbd94d96fls1225088eaf.0.-pod-prod-09-us;
 Thu, 13 Jun 2024 20:52:38 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCX3Ny5DE5dMKBret7SogzUBE612CPegVUOC5OBOKs5GRkcY8Tf28/Q+W/Fn01TyScmtWWqlLkU3zqoode59teYHRMy2n2sX554HTg==
X-Received: by 2002:a05:6830:1d8e:b0:6f9:b348:ddf5 with SMTP id 46e09a7af769-6fb937677d4mr1721999a34.11.1718337157824;
        Thu, 13 Jun 2024 20:52:37 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718337157; cv=none;
        d=google.com; s=arc-20160816;
        b=BvGODpUFwgeFPTn3gCPtGgi0zARdMz4g9JcewLqdeSdIi/4viF1R9aM5MMNpsvXmCT
         19NGvFLuoa5WtImREMF1nHGPAcCdajbkKExBKDqdNgvQEt9pYKQXoyIinHMhaoR6M249
         dGZtXluY4b1tjqFpf3BN8qrnNwf8SSA8AMQLvQYQptxfVrkjRUiluoqKdR+p7XllM14p
         FqyBMgRwLeJsLs5j1ojwocqXkdxK/w9p+LAvVw5fUfmTn653CLdTOTuGFFMZRPsTrzzy
         /mzc5daE5CpKFliFAJzaTo8K1HcmzaYnmu9tNUOn70NJnDwvVWUaxvzSmfz2j62wtdHZ
         i4+g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=ICgIwRf9RBOAAGjMDIWzeHOIZUh+W19TZKdkRRJEfpA=;
        fh=v8nlEsPtC8QOgAMy9+ceT2RXXasdZQBfytgK0uDUtEc=;
        b=uESl8BFJmFLv1vF0za/PCedXhOeqAAIT7ZAYmb/FA8rrTb1CdlwCizhok44lR67/fS
         lhkBWw4rWu2Iercs8bcHAe17q95SiosOgOunpc76ioTssd4D+vaMuTGiN2R5mty0nmLN
         65JGajacsAEEb3hMUeN6RYniI6Aw4xrrSbBql7+WhZNTWqpLAD7nQeBTbA+oBqrOIkk2
         Hw10d4f3XbvI2h9DhIRv8qBCSpkAquvM4c1R5+OwPjJX64AHGHwSVbPAlHSFctAuicEW
         fN2fsTvsW9eRYjRV9+5m2qQkRJeY2nj02WGAG9Pd5xKOQJ3IWbaZ5q3jGZLR0a+/llI/
         iOwQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of liaochang1@huawei.com designates 45.249.212.187 as permitted sender) smtp.mailfrom=liaochang1@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
Received: from szxga01-in.huawei.com (szxga01-in.huawei.com. [45.249.212.187])
        by gmr-mx.google.com with ESMTPS id 46e09a7af769-6fb5ba85bbcsi136686a34.5.2024.06.13.20.52.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 13 Jun 2024 20:52:37 -0700 (PDT)
Received-SPF: pass (google.com: domain of liaochang1@huawei.com designates 45.249.212.187 as permitted sender) client-ip=45.249.212.187;
Received: from mail.maildlp.com (unknown [172.19.88.105])
	by szxga01-in.huawei.com (SkyGuard) with ESMTP id 4W0lcW34nwzwSNG;
	Fri, 14 Jun 2024 11:48:27 +0800 (CST)
Received: from kwepemd200013.china.huawei.com (unknown [7.221.188.133])
	by mail.maildlp.com (Postfix) with ESMTPS id 7C5681402C8;
	Fri, 14 Jun 2024 11:52:35 +0800 (CST)
Received: from huawei.com (10.67.174.28) by kwepemd200013.china.huawei.com
 (7.221.188.133) with Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.2.1258.34; Fri, 14 Jun
 2024 11:52:33 +0800
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
Subject: [PATCH v4 07/10] irqchip/gic-v3: Improve the maintainability of NMI masking in GIC driver
Date: Fri, 14 Jun 2024 03:44:30 +0000
Message-ID: <20240614034433.602622-8-liaochang1@huawei.com>
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
 (google.com: domain of liaochang1@huawei.com designates 45.249.212.187 as
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

It has a better maintainability to use the local_nmi_enable() in GIC
driver to unmask NMI and keep regular IRQ and FIQ maskable, instead of
writing raw value into DAIF, PMR and ALLINT directly.

Signed-off-by: Liao Chang <liaochang1@huawei.com>
---
 arch/arm64/include/asm/daifflags.h | 14 ++++++++++++++
 drivers/irqchip/irq-gic-v3.c       |  6 ++----
 2 files changed, 16 insertions(+), 4 deletions(-)

diff --git a/arch/arm64/include/asm/daifflags.h b/arch/arm64/include/asm/daifflags.h
index b19dfd948704..4eb97241a58f 100644
--- a/arch/arm64/include/asm/daifflags.h
+++ b/arch/arm64/include/asm/daifflags.h
@@ -332,4 +332,18 @@ static inline void local_nmi_serror_enable(void)
 	irqflags.fields.allint = 0;
 	local_allint_restore_notrace(irqflags);
 }
+
+/*
+ * local_nmi_enable - Enable NMI with or without superpriority.
+ */
+static inline void local_nmi_enable(void)
+{
+	if (system_uses_irq_prio_masking()) {
+		gic_pmr_mask_irqs();
+		asm volatile ("msr daifclr, #3" : : : "memory");
+	} else if (system_uses_nmi()) {
+		asm volatile ("msr daifset, #3" : : : "memory");
+		msr_pstate_allint(0);
+	}
+}
 #endif
diff --git a/drivers/irqchip/irq-gic-v3.c b/drivers/irqchip/irq-gic-v3.c
index 6fb276504bcc..ed7d8d87768f 100644
--- a/drivers/irqchip/irq-gic-v3.c
+++ b/drivers/irqchip/irq-gic-v3.c
@@ -33,6 +33,7 @@
 #include <asm/exception.h>
 #include <asm/smp_plat.h>
 #include <asm/virt.h>
+#include <asm/daifflags.h>
 
 #include "irq-gic-common.h"
 
@@ -813,10 +814,7 @@ static void __gic_handle_irq_from_irqson(struct pt_regs *regs)
 		nmi_exit();
 	}
 
-	if (gic_prio_masking_enabled()) {
-		gic_pmr_mask_irqs();
-		gic_arch_enable_irqs();
-	}
+	local_nmi_enable();
 
 	if (!is_nmi)
 		__gic_handle_irq(irqnr, regs);
-- 
2.34.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240614034433.602622-8-liaochang1%40huawei.com.
