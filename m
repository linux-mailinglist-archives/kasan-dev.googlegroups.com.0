Return-Path: <kasan-dev+bncBCWPLY7W6EARB7H4V2ZQMGQE7MERYJQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13d.google.com (mail-il1-x13d.google.com [IPv6:2607:f8b0:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id CAF9B9082B0
	for <lists+kasan-dev@lfdr.de>; Fri, 14 Jun 2024 05:52:29 +0200 (CEST)
Received: by mail-il1-x13d.google.com with SMTP id e9e14a558f8ab-375a26a094dsf16342205ab.0
        for <lists+kasan-dev@lfdr.de>; Thu, 13 Jun 2024 20:52:29 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718337148; cv=pass;
        d=google.com; s=arc-20160816;
        b=R8AcZs73+khs2sktcESbg7SKV79N1W0ZenQUrp5Kv1pGBVCOWGHzVS9x5ic4r9L4Kw
         s+/G8z5CPgFJ12ydKfhSGrUKaA1zG2OfMK1MY1iJXYCITcOYUqW8lt8CCguW0V9gk9Gx
         kZ9vxL+nR7cgeD9LIKkUdNoeQ4zc23R7zaO9D1/g01/8fWe1hhjWGHd+fdpQt4Tp1+8S
         yRG+ZewnJrB/UaM0GyiKuyrqTB5FMl5DCbgr1n/twtiis2AALUBsWu4iI/ZghopIx6lK
         LK0+vaJ7PS0RDCAAYB5egW13stjDmqz0jLKmmNuxnA608TrV+sBum4PZEEGf6YGErhg4
         Ai/A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=8EkzdN6F+hGJhrzvtFiPqeB/yDND3TKLY86obMANTVY=;
        fh=eSZ7jApCiXq0KdJNdQ23yUZpuJDsAkWRZDXxeW0d05Y=;
        b=NIsqHIWYaKhFPB3ShNDM8sPUbaKdlX9AjU1/NZeagqaI4imKBhXwfB3EP2lWTrpx/l
         rBREKnhMo8eVfnaRSMlBW6d9TTPQuggnmdwxv/h0zyiDaVB1Rcwl+2G+3VwdC4dSPY/u
         nprwglO/pUPqpw2CXRBb+SDuyuydkENbGnb5eAPqS0yCRmbFqIYbpb5x5tQCloa3nNAA
         5SyWNjwlA5W48GEvr7TFPTXY7srqAe1ItL+VRNg6woHY+sKNiDMe4Ny/AJhE+JzaISHW
         z0v2ROjazBH/s20vEp7SwhTrXZOsp1Kg7fkAIATb8i5dVlFrE7t32e3DA8balFRdtE4y
         91Vw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of liaochang1@huawei.com designates 45.249.212.188 as permitted sender) smtp.mailfrom=liaochang1@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718337148; x=1718941948; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=8EkzdN6F+hGJhrzvtFiPqeB/yDND3TKLY86obMANTVY=;
        b=cyZ+ukvNdBcyjzgnjiQIL2HftsduU/Rg8Te8+E5aiFfYV5/+J0WvuAm/qLlPCRFdDD
         CWPz0RcAukQnFwOo6igIPRppQS3zYPHE9ds8Bp3leZcnM/94dP02OJQLWHCPk6w0xoZk
         OEK0wnvmWmHIwfjZFt1ftnYUMyzxDpH5GYrPkvDV4AUX3RImhNaik9Vut4lK1eXBkBxy
         Km3sK9fKesEzzkYIYC2Skkx9cJ76bdeDSkFjPJL50Qw0LcI3C0o+3Yv1DyHolqwYqZ3Z
         SayLQW7Citq/7mvhqcRnCAxvYxcczmo3BqOAf0hGxXGaxC6AavRKBVVJD1/YtZ/0uZyx
         2/Zg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718337148; x=1718941948;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=8EkzdN6F+hGJhrzvtFiPqeB/yDND3TKLY86obMANTVY=;
        b=PxEiMDczaUb3bU5t1S6tGeHZo43rf38rUeSo1UBJuHhk5CczhjoCd3Lmbtieq60/Us
         hEGLQIYazjUEPvN8OL0i5uu6VIenhhmyRTamHWH7k3ZDZVYuA4s2WZ6n3jv+u1OKDlzv
         fSKX6INHp1G01KHHW8nmzFoE/+K55zDEDQnfKdQ9Z6uZ7jlFJBBS10Ms8xclLWzglpUr
         EdgNZ4lQbjw4lGaSVZI7uUruVlx6Xp9M/AtmmaD+O/zTKvtf9oWv4jVhMARxHIyDLK92
         ai6mFjScoVhVyOKmUEWe2szwJhLly/4xJPKRXFt1Ll72KRWCpF9iyqRBW2PR3hRw8PNr
         ipqA==
X-Forwarded-Encrypted: i=2; AJvYcCXC3w4lK88RrlAxvQrs1ZxCH96fT2ixkla/G1nEUT9TvLH9173+oHVIUGz0UJP0ka7iHe1yQR3bVEZyzbiobgdvzdwB+bOoGA==
X-Gm-Message-State: AOJu0YyN1xXtg3mZFApCHF+JeU6xZ36Nw4piCIqjRqpDkLybaIEsuTLV
	uGY5VWhGQnIMBHZXGRGv2GzZ9s933MmFEPkChajRyOfmVm0SJ/TU
X-Google-Smtp-Source: AGHT+IFmj93Sk+1rBCifUkk1rt/P9H6mR6uMACTuaBxCiNVWnZD2b7vWCx9jjWP9GXQL9+h6UhhpTw==
X-Received: by 2002:a05:6e02:1846:b0:375:c56b:a0fe with SMTP id e9e14a558f8ab-375e0e2c8f1mr13474085ab.19.1718337148220;
        Thu, 13 Jun 2024 20:52:28 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:1c8d:b0:375:caa7:3b1a with SMTP id
 e9e14a558f8ab-375da5368d9ls9357885ab.0.-pod-prod-09-us; Thu, 13 Jun 2024
 20:52:27 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXXnKla57mJYQEsTp2B3i/9lfg3vs1d0oKKat2MGZQxQyTcSNHnMYkHq6cX8NjeEQdrrn6O1rCEyk2EV3TvL5fLbwLmxDHrBEn1qw==
X-Received: by 2002:a05:6602:2b92:b0:7e1:af90:44ee with SMTP id ca18e2360f4ac-7ebeb4c7167mr174082039f.8.1718337147310;
        Thu, 13 Jun 2024 20:52:27 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718337147; cv=none;
        d=google.com; s=arc-20160816;
        b=LtKQkITjnvLpzkb+kubAkWNG8MkmVttAr3eO39HILwPuYn5aajq7+9GrfdXeIu3gNX
         znEo+5z6+Vw6Tll44cyDXQSK8umLgg4W5BKi3rZ9biWvCmlZLANIiBD0IJAfn0SWQkfR
         ycpXN4InbNKc9mR9I/X6Cq2lCIsTfuZDDHtMqeZMIx7y1c7itGCJnE/VRFYa0WFOFVGi
         qpECOQ9J8gDGwPtrccNF+Tjc0JsmwO0FN/0C89qH/gh07Z6Pp33ieedU4w5WOnjhdNMV
         uAiLo99QHTUlRNWn3QSPcG/O0V4JKpSC2PRkV7EaATHoOvreEliD0SQiNaBmr4QkyoFA
         2dAA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=cujDRB+fhdTwTuL30qfufmZv6Szv4LBOpwx+PD01YKU=;
        fh=v8nlEsPtC8QOgAMy9+ceT2RXXasdZQBfytgK0uDUtEc=;
        b=qVesG7hI+2jgGFRUaJNWikPWNkvaMyG37mPNxhO7zVAalWEw5PEtCjkAgTlL+fLGCl
         A1V6bcErDu/6xGKKC+LSGiLcRftBI+lP8w7Iq6nsdvzikDYcfVEr3er3PRnT81Nz7bwp
         IAyCnysCDA7AsHqIXI6FYUBco/qI4ENR27bhxJNMBdhpxuvRlBxAcVUe/xKcVY2nunMe
         e29a1oj85jfpVIHWEOGGjmq3Y9caPBmKlih7IdMucP0ixgYLyMy7TPOa1TWvsl/BymDb
         nG1u59GpRKue7K74sP3gVbk3jTVaEPq6AUh0vOqP82jT3fJGd58ifH1XTi8eWUYM+CgJ
         BZXg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of liaochang1@huawei.com designates 45.249.212.188 as permitted sender) smtp.mailfrom=liaochang1@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
Received: from szxga02-in.huawei.com (szxga02-in.huawei.com. [45.249.212.188])
        by gmr-mx.google.com with ESMTPS id ca18e2360f4ac-7ebdbba4777si12909139f.4.2024.06.13.20.52.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 13 Jun 2024 20:52:27 -0700 (PDT)
Received-SPF: pass (google.com: domain of liaochang1@huawei.com designates 45.249.212.188 as permitted sender) client-ip=45.249.212.188;
Received: from mail.maildlp.com (unknown [172.19.88.194])
	by szxga02-in.huawei.com (SkyGuard) with ESMTP id 4W0lgN1k9Zzdb9L;
	Fri, 14 Jun 2024 11:50:56 +0800 (CST)
Received: from kwepemd200013.china.huawei.com (unknown [7.221.188.133])
	by mail.maildlp.com (Postfix) with ESMTPS id 5F080140732;
	Fri, 14 Jun 2024 11:52:24 +0800 (CST)
Received: from huawei.com (10.67.174.28) by kwepemd200013.china.huawei.com
 (7.221.188.133) with Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.2.1258.34; Fri, 14 Jun
 2024 11:52:22 +0800
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
Subject: [PATCH v4 01/10] arm64/sysreg: Add definitions for immediate versions of MSR ALLINT
Date: Fri, 14 Jun 2024 03:44:24 +0000
Message-ID: <20240614034433.602622-2-liaochang1@huawei.com>
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
 (google.com: domain of liaochang1@huawei.com designates 45.249.212.188 as
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

Use existing helper in sysregs.h to generate the variant for MSR
instruction used to set the ALLINT field of PSTATE directly using
immediate.

  MSR ALLINT, #Imm1 ;used to set the value of PSTATE.ALLINT

As Mark suggested in [1], the series of PSTATE related helper names in
sysregs.h are lack of self-explanatory nature, which make it difficult
to understand their function and purpose. This patch also rename these
helper from the sytle of SET_XXX to MSR_XXX to make them discoverable.

[1] https://lore.kernel.org/all/ZjpALOdSgu-qhshR@finisterre.sirena.org.uk/

Signed-off-by: Mark Brown <broonie@kernel.org>
Signed-off-by: Liao Chang <liaochang1@huawei.com>
---
 arch/arm64/include/asm/mte-kasan.h |  4 ++--
 arch/arm64/include/asm/mte.h       |  2 +-
 arch/arm64/include/asm/sysreg.h    | 27 +++++++++++++++------------
 arch/arm64/include/asm/uaccess.h   |  4 ++--
 arch/arm64/kernel/cpufeature.c     |  4 ++--
 arch/arm64/kernel/entry-common.c   |  4 ++--
 arch/arm64/kernel/entry.S          |  2 +-
 arch/arm64/kernel/proton-pack.c    |  4 ++--
 arch/arm64/kernel/suspend.c        |  2 +-
 arch/arm64/kvm/hyp/entry.S         |  2 +-
 10 files changed, 29 insertions(+), 26 deletions(-)

diff --git a/arch/arm64/include/asm/mte-kasan.h b/arch/arm64/include/asm/mte-kasan.h
index 2e98028c1965..78e022d462e8 100644
--- a/arch/arm64/include/asm/mte-kasan.h
+++ b/arch/arm64/include/asm/mte-kasan.h
@@ -53,13 +53,13 @@ static inline bool system_uses_mte_async_or_asymm_mode(void)
  */
 static inline void mte_disable_tco(void)
 {
-	asm volatile(ALTERNATIVE("nop", SET_PSTATE_TCO(0),
+	asm volatile(ALTERNATIVE("nop", MSR_PSTATE_TCO(0),
 				 ARM64_MTE, CONFIG_KASAN_HW_TAGS));
 }
 
 static inline void mte_enable_tco(void)
 {
-	asm volatile(ALTERNATIVE("nop", SET_PSTATE_TCO(1),
+	asm volatile(ALTERNATIVE("nop", MSR_PSTATE_TCO(1),
 				 ARM64_MTE, CONFIG_KASAN_HW_TAGS));
 }
 
diff --git a/arch/arm64/include/asm/mte.h b/arch/arm64/include/asm/mte.h
index 91fbd5c8a391..e914ca1c90a0 100644
--- a/arch/arm64/include/asm/mte.h
+++ b/arch/arm64/include/asm/mte.h
@@ -174,7 +174,7 @@ static inline void mte_disable_tco_entry(struct task_struct *task)
 	 */
 	if (kasan_hw_tags_enabled() ||
 	    (task->thread.sctlr_user & (1UL << SCTLR_EL1_TCF0_SHIFT)))
-		asm volatile(SET_PSTATE_TCO(0));
+		asm volatile(MSR_PSTATE_TCO(0));
 }
 
 #ifdef CONFIG_KASAN_HW_TAGS
diff --git a/arch/arm64/include/asm/sysreg.h b/arch/arm64/include/asm/sysreg.h
index af3b206fa423..4f514bdfb1bd 100644
--- a/arch/arm64/include/asm/sysreg.h
+++ b/arch/arm64/include/asm/sysreg.h
@@ -90,24 +90,27 @@
  */
 #define pstate_field(op1, op2)		((op1) << Op1_shift | (op2) << Op2_shift)
 #define PSTATE_Imm_shift		CRm_shift
-#define SET_PSTATE(x, r)		__emit_inst(0xd500401f | PSTATE_ ## r | ((!!x) << PSTATE_Imm_shift))
+#define MSR_PSTATE_ENCODE(x, r)		__emit_inst(0xd500401f | PSTATE_ ## r | ((!!x) << PSTATE_Imm_shift))
 
 #define PSTATE_PAN			pstate_field(0, 4)
 #define PSTATE_UAO			pstate_field(0, 3)
 #define PSTATE_SSBS			pstate_field(3, 1)
 #define PSTATE_DIT			pstate_field(3, 2)
 #define PSTATE_TCO			pstate_field(3, 4)
-
-#define SET_PSTATE_PAN(x)		SET_PSTATE((x), PAN)
-#define SET_PSTATE_UAO(x)		SET_PSTATE((x), UAO)
-#define SET_PSTATE_SSBS(x)		SET_PSTATE((x), SSBS)
-#define SET_PSTATE_DIT(x)		SET_PSTATE((x), DIT)
-#define SET_PSTATE_TCO(x)		SET_PSTATE((x), TCO)
-
-#define set_pstate_pan(x)		asm volatile(SET_PSTATE_PAN(x))
-#define set_pstate_uao(x)		asm volatile(SET_PSTATE_UAO(x))
-#define set_pstate_ssbs(x)		asm volatile(SET_PSTATE_SSBS(x))
-#define set_pstate_dit(x)		asm volatile(SET_PSTATE_DIT(x))
+#define PSTATE_ALLINT			pstate_field(1, 0)
+
+#define MSR_PSTATE_PAN(x)		MSR_PSTATE_ENCODE((x), PAN)
+#define MSR_PSTATE_UAO(x)		MSR_PSTATE_ENCODE((x), UAO)
+#define MSR_PSTATE_SSBS(x)		MSR_PSTATE_ENCODE((x), SSBS)
+#define MSR_PSTATE_DIT(x)		MSR_PSTATE_ENCODE((x), DIT)
+#define MSR_PSTATE_TCO(x)		MSR_PSTATE_ENCODE((x), TCO)
+#define MSR_PSTATE_ALLINT(x)		MSR_PSTATE_ENCODE((x), ALLINT)
+
+#define msr_pstate_pan(x)		asm volatile(MSR_PSTATE_PAN(x))
+#define msr_pstate_uao(x)		asm volatile(MSR_PSTATE_UAO(x))
+#define msr_pstate_ssbs(x)		asm volatile(MSR_PSTATE_SSBS(x))
+#define msr_pstate_dit(x)		asm volatile(MSR_PSTATE_DIT(x))
+#define msr_pstate_allint(x)		asm volatile(MSR_PSTATE_ALLINT(x))
 
 #define __SYS_BARRIER_INSN(CRm, op2, Rt) \
 	__emit_inst(0xd5000000 | sys_insn(0, 3, 3, (CRm), (op2)) | ((Rt) & 0x1f))
diff --git a/arch/arm64/include/asm/uaccess.h b/arch/arm64/include/asm/uaccess.h
index 14be5000c5a0..34890df54e2e 100644
--- a/arch/arm64/include/asm/uaccess.h
+++ b/arch/arm64/include/asm/uaccess.h
@@ -124,13 +124,13 @@ static inline bool uaccess_ttbr0_enable(void)
 
 static inline void __uaccess_disable_hw_pan(void)
 {
-	asm(ALTERNATIVE("nop", SET_PSTATE_PAN(0), ARM64_HAS_PAN,
+	asm(ALTERNATIVE("nop", MSR_PSTATE_PAN(0), ARM64_HAS_PAN,
 			CONFIG_ARM64_PAN));
 }
 
 static inline void __uaccess_enable_hw_pan(void)
 {
-	asm(ALTERNATIVE("nop", SET_PSTATE_PAN(1), ARM64_HAS_PAN,
+	asm(ALTERNATIVE("nop", MSR_PSTATE_PAN(1), ARM64_HAS_PAN,
 			CONFIG_ARM64_PAN));
 }
 
diff --git a/arch/arm64/kernel/cpufeature.c b/arch/arm64/kernel/cpufeature.c
index 48e7029f1054..03a37a21fc99 100644
--- a/arch/arm64/kernel/cpufeature.c
+++ b/arch/arm64/kernel/cpufeature.c
@@ -2151,7 +2151,7 @@ static void cpu_enable_pan(const struct arm64_cpu_capabilities *__unused)
 	WARN_ON_ONCE(in_interrupt());
 
 	sysreg_clear_set(sctlr_el1, SCTLR_EL1_SPAN, 0);
-	set_pstate_pan(1);
+	msr_pstate_pan(1);
 }
 #endif /* CONFIG_ARM64_PAN */
 
@@ -2339,7 +2339,7 @@ static void cpu_trap_el0_impdef(const struct arm64_cpu_capabilities *__unused)
 
 static void cpu_enable_dit(const struct arm64_cpu_capabilities *__unused)
 {
-	set_pstate_dit(1);
+	msr_pstate_dit(1);
 }
 
 static void cpu_enable_mops(const struct arm64_cpu_capabilities *__unused)
diff --git a/arch/arm64/kernel/entry-common.c b/arch/arm64/kernel/entry-common.c
index b77a15955f28..72c2c9d033a8 100644
--- a/arch/arm64/kernel/entry-common.c
+++ b/arch/arm64/kernel/entry-common.c
@@ -953,9 +953,9 @@ __sdei_handler(struct pt_regs *regs, struct sdei_registered_event *arg)
 	 * clearing it when the host isn't using it, in case a VM had it set.
 	 */
 	if (system_uses_hw_pan())
-		set_pstate_pan(1);
+		msr_pstate_pan(1);
 	else if (cpu_has_pan())
-		set_pstate_pan(0);
+		msr_pstate_pan(0);
 
 	arm64_enter_nmi(regs);
 	ret = do_sdei_event(regs, arg);
diff --git a/arch/arm64/kernel/entry.S b/arch/arm64/kernel/entry.S
index 7ef0e127b149..c568b4ff9e62 100644
--- a/arch/arm64/kernel/entry.S
+++ b/arch/arm64/kernel/entry.S
@@ -197,7 +197,7 @@ alternative_cb_end
 
 	.macro	kernel_entry, el, regsize = 64
 	.if	\el == 0
-	alternative_insn nop, SET_PSTATE_DIT(1), ARM64_HAS_DIT
+	alternative_insn nop, MSR_PSTATE_DIT(1), ARM64_HAS_DIT
 	.endif
 	.if	\regsize == 32
 	mov	w0, w0				// zero upper 32 bits of x0
diff --git a/arch/arm64/kernel/proton-pack.c b/arch/arm64/kernel/proton-pack.c
index baca47bd443c..735db447695a 100644
--- a/arch/arm64/kernel/proton-pack.c
+++ b/arch/arm64/kernel/proton-pack.c
@@ -552,12 +552,12 @@ static enum mitigation_state spectre_v4_enable_hw_mitigation(void)
 
 	if (spectre_v4_mitigations_off()) {
 		sysreg_clear_set(sctlr_el1, 0, SCTLR_ELx_DSSBS);
-		set_pstate_ssbs(1);
+		msr_pstate_ssbs(1);
 		return SPECTRE_VULNERABLE;
 	}
 
 	/* SCTLR_EL1.DSSBS was initialised to 0 during boot */
-	set_pstate_ssbs(0);
+	msr_pstate_ssbs(0);
 
 	/*
 	 * SSBS is self-synchronizing and is intended to affect subsequent
diff --git a/arch/arm64/kernel/suspend.c b/arch/arm64/kernel/suspend.c
index eaaff94329cd..0e79af827540 100644
--- a/arch/arm64/kernel/suspend.c
+++ b/arch/arm64/kernel/suspend.c
@@ -63,7 +63,7 @@ void notrace __cpu_suspend_exit(void)
 	 * features that might not have been set correctly.
 	 */
 	if (alternative_has_cap_unlikely(ARM64_HAS_DIT))
-		set_pstate_dit(1);
+		msr_pstate_dit(1);
 	__uaccess_enable_hw_pan();
 
 	/*
diff --git a/arch/arm64/kvm/hyp/entry.S b/arch/arm64/kvm/hyp/entry.S
index f3aa7738b477..e1cb3ea49140 100644
--- a/arch/arm64/kvm/hyp/entry.S
+++ b/arch/arm64/kvm/hyp/entry.S
@@ -113,7 +113,7 @@ SYM_INNER_LABEL(__guest_exit, SYM_L_GLOBAL)
 
 	add	x1, x1, #VCPU_CONTEXT
 
-	ALTERNATIVE(nop, SET_PSTATE_PAN(1), ARM64_HAS_PAN, CONFIG_ARM64_PAN)
+	ALTERNATIVE(nop, MSR_PSTATE_PAN(1), ARM64_HAS_PAN, CONFIG_ARM64_PAN)
 
 	// Store the guest regs x2 and x3
 	stp	x2, x3,   [x1, #CPU_XREG_OFFSET(2)]
-- 
2.34.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240614034433.602622-2-liaochang1%40huawei.com.
