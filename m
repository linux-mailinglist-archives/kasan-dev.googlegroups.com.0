Return-Path: <kasan-dev+bncBDB3VRFH7QKRBKV3ZPDAMGQEYCNASII@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3e.google.com (mail-qv1-xf3e.google.com [IPv6:2607:f8b0:4864:20::f3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 9F25EB9718F
	for <lists+kasan-dev@lfdr.de>; Tue, 23 Sep 2025 19:49:31 +0200 (CEST)
Received: by mail-qv1-xf3e.google.com with SMTP id 6a1803df08f44-7bb414430c2sf2382396d6.0
        for <lists+kasan-dev@lfdr.de>; Tue, 23 Sep 2025 10:49:31 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758649770; cv=pass;
        d=google.com; s=arc-20240605;
        b=a+darksXWC0wm3vZhB0GnSgPo8TCY2JSHtMIvNRhXMLHNxnzkE3omAbWMUvtzODC3f
         V5feXUUfHNU/ZWnbxi3XUTVWHSTqFJXYyhWd/GKuBXBiAOyb+Nx+a74++xFDqyNP2wc0
         dyUVXTq1JMzz8Q/tHKIQM8TReLUoRGVwC4oz17EplHTwoqi+rcXtyZ/JXugDK814LCTX
         B53TryszogirrzUx0YCS1ETeKJkoQD5rczzylEPtzxLfUwiA4WlnBBn1Z+vVaC+qBQX8
         jGbZMBaesXfUKODUnRLdcczhkPPJf4w5Dr5IZyFXP58TKOfG3pl0+JxbwBJIaF2wB0hP
         A2+g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=7NtpSwF7QU4AriSqW6wpD6ps9U1xmq8XJTHUDEXfm9E=;
        fh=NlYGkxfr0H9d0B3NVgMxdhtNAMgPYLhNj+9f+eFbgAU=;
        b=l1zQUgLC10kki5AJp5/hBircnZwWchDI90hCBNFH7oaEB9QVbaijvqwl1gYSSIQGcR
         gq9Sw/ZLGRwGRcT7M6cmzZIhuU5Znnu7A7Eq9+3WyGplN1l8hlOfylHPBzpRao47GZXA
         Vvk0kliqM15aN9R93nR3ED/RHHc2Z4j5zuoz+MIsiS5pNCP9yPsvxbcAldChe0A11Q5x
         XKC1QhM0FWG5c9OU0YktIAAsrvmnIKhPES+7/76e+dkWsg1vOJK7rYVOXcc8l3Ok5p9n
         VzvbOJUFbARDjfskFdNGqPf8UpttCqfkQBwCI7wKq2x1xD8QujaiLNgCy9zd4OvoBojf
         rxyw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of ada.coupriediaz@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=ada.coupriediaz@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758649770; x=1759254570; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=7NtpSwF7QU4AriSqW6wpD6ps9U1xmq8XJTHUDEXfm9E=;
        b=chiVYoz4dPoOAXbTR81KSPCds4PFdHZKI/Qoxu7ZODxBhOSORt3Dna1QaU1SSCkVmY
         6KlcVhNbHlap+B8ifLt91qMlrWV0hHVA6MHrK1g+wFlkjrg7qpCMmdXl3qQOSDQmuQpt
         yi6apy4/FKg8vCIoX/5RcClXsMNqjM6JlVz3KkQ7vSWe4t5oDQGMrYuF8zAuye6lbw4Z
         DcPp1E/sxW3m4HsGJVmAP3MRUhfJSscFiGWiuLZZ2+V6s8qWSndtdiXRvWlw4sCy9EMu
         tZfUIhwfbm0kqkIY0PD7dYLxqSSCwYDwwiracNFrVDuWDzy1h/5zFkZ2Icc1sLDedVbv
         iL0g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758649770; x=1759254570;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=7NtpSwF7QU4AriSqW6wpD6ps9U1xmq8XJTHUDEXfm9E=;
        b=dzzsVga6wuP9QZxs+H41+xMzq2RObr7KKIpRjLXND/ZwUuvVYZGCeDuR+M+E2tH/tI
         oLvthGQ+u0Vb4t4WojC28eII+vOsdauhxspF+sq7Skj0QCepsU/wB8vW9aXxR7uG6++f
         cy3Tas1YuhSkzGbM/MX+26t+uYACL4SVAoBa8g6B6ge8UUD+vxOg7kduqYMrTedHA7mM
         QlTq5kgLKJEbeq63WFpifug0vVeyblmBiTBJqzRKyF42wY+s1uqnAf491R2pqR/PN8er
         vOwAUsSX/QFq8OeTo+eK3natT2SgK/j5DeQli+MDPjtwKW4EDw3avtUWHr7nN5M9NFNf
         WLsg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUNcSpdYynSksZA6xWpxXyECKRNN/PjkzA4loE5XXRMIQK8VPhOtY6SWfXvuurKW0MNFIBbhA==@lfdr.de
X-Gm-Message-State: AOJu0YxE9MhqprofYA3iY8wi5NsnqU7rRCs4dr2KImdVouj9QrngjLo7
	tym7O5DPMdkk7lGTU/dnde4VJcGBshTlQX5Op/zMH6X8JroNwAC2MkH2
X-Google-Smtp-Source: AGHT+IFf7G/2LloR7JO4aMCLyT1TlJGbBv7Q17R9F5nOLlfGaLl+60RgQFDvXUqm76jJV6oClR2bGQ==
X-Received: by 2002:a05:6214:76a:b0:7b0:af41:10f1 with SMTP id 6a1803df08f44-7e7a024baa5mr31865966d6.3.1758649770299;
        Tue, 23 Sep 2025 10:49:30 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd6jFsG0CSitGwar4qXTykjwDokv26dcFVW5Q79tp/ZQ5w==
Received: by 2002:a0c:ea89:0:b0:707:5acb:366c with SMTP id 6a1803df08f44-7effb95007els790626d6.2.-pod-prod-00-us;
 Tue, 23 Sep 2025 10:49:28 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXNW5zFxdg0CRDk0DLLDlwNaem6a+UqihTv7GTQBAVPM9j3pP4BLpl9iQ3zMzKC8JDP9ek0VU8lkPU=@googlegroups.com
X-Received: by 2002:ad4:5c8d:0:b0:796:e048:ee97 with SMTP id 6a1803df08f44-7e7b463fb18mr40314876d6.19.1758649768501;
        Tue, 23 Sep 2025 10:49:28 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1758649768; cv=none;
        d=google.com; s=arc-20240605;
        b=HuRHZfsXQkm0Y+MforJ66KYwMpXcK1y2HNNSYd2mcFX0jnijP1gozTZbIw1sSPhUUR
         9yJ5tUzGs6s4q6FopBW+dE/zMEv3jaJlJs8MgZgtJ3A04NTom0fNlCar/upfUcMp8sYk
         t8IYFroYQyy+puqeCHnO6J15rMsOstkMvyD2SwnxXJ8qslvVJrAM8RgocX4m4D6gcQnc
         0krKhuP8Zhbp66P7Xd+TfFPaKPKKBeNkbsndZLt1Trgr+V51QW3w5+Vxoss0XZY00B+9
         xMPUnKhIsszXfHf/zKdTD/mW7bciRL8ta4P7aOA3M0P6tGPHXpBCZp2fO3iuji6hmRgi
         +I3Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=MF8PkXgUBXn0osNVxu7f/la70PCpV5fAZ4RLQTvzLhw=;
        fh=eoJjfSK6fSSw8URA2i1Ih8m7A3n64cnY04bTfTqxJBk=;
        b=j8fdy/6DQ5cW9MSzUQ0M+EZzh2aQyg01g61gtyGzzAU428kDxMjsX2fYkqfCmL7sdQ
         rwQ1sfWtj2hfp5kSSoP6VaJoe/hsRLZ9cq8tV4COj9QOxUo+n6o3fwSE4jayyi2Duftx
         yVWsrR88VR/wqnk+Q0Lsd2C05U3irFkFHQzgKBE+NktrAHPs8S6AMPHk7jBeoGTpCiGH
         spPTR1MHl6R9dTKnA/3VIhetjLIsJSShADxOgdEcKOqstzBJmYTdpZ7hJZzjcyRAiKSJ
         2gR7fLLyCnqEnCkxpccc5A0WvEwFm8fydLj48WB/uN9Q28QWNIG8ZnDqAhM45W2ZAyvd
         10zg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of ada.coupriediaz@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=ada.coupriediaz@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id 6a1803df08f44-7b0b65e03aesi49416d6.7.2025.09.23.10.49.28
        for <kasan-dev@googlegroups.com>;
        Tue, 23 Sep 2025 10:49:28 -0700 (PDT)
Received-SPF: pass (google.com: domain of ada.coupriediaz@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id D92C0497;
	Tue, 23 Sep 2025 10:49:19 -0700 (PDT)
Received: from e137867.cambridge.arm.com (e137867.arm.com [10.1.30.204])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPA id 6F0BD3F5A1;
	Tue, 23 Sep 2025 10:49:24 -0700 (PDT)
From: Ada Couprie Diaz <ada.coupriediaz@arm.com>
To: linux-arm-kernel@lists.infradead.org
Cc: Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will@kernel.org>,
	Marc Zyngier <maz@kernel.org>,
	Oliver Upton <oliver.upton@linux.dev>,
	Ard Biesheuvel <ardb@kernel.org>,
	Joey Gouly <joey.gouly@arm.com>,
	Suzuki K Poulose <suzuki.poulose@arm.com>,
	Zenghui Yu <yuzenghui@huawei.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	linux-kernel@vger.kernel.org,
	kvmarm@lists.linux.dev,
	kasan-dev@googlegroups.com,
	Mark Rutland <mark.rutland@arm.com>,
	Ada Couprie Diaz <ada.coupriediaz@arm.com>
Subject: [RFC PATCH 03/16] arm64/insn: always inline aarch64_insn_decode_register()
Date: Tue, 23 Sep 2025 18:48:50 +0100
Message-ID: <20250923174903.76283-4-ada.coupriediaz@arm.com>
X-Mailer: git-send-email 2.43.0
In-Reply-To: <20250923174903.76283-1-ada.coupriediaz@arm.com>
References: <20250923174903.76283-1-ada.coupriediaz@arm.com>
MIME-Version: 1.0
X-Original-Sender: ada.coupriediaz@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of ada.coupriediaz@arm.com designates 217.140.110.172 as
 permitted sender) smtp.mailfrom=ada.coupriediaz@arm.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=arm.com
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

As it is always called with an explicit register type, we can
check for its validity at compile time and remove the runtime error print.

This makes `aarch64_insn_decode_register()` self-contained and safe
for inlining and usage from patching callbacks.

Signed-off-by: Ada Couprie Diaz <ada.coupriediaz@arm.com>
---
 arch/arm64/include/asm/insn.h | 32 ++++++++++++++++++++++++++++++--
 arch/arm64/lib/insn.c         | 29 -----------------------------
 2 files changed, 30 insertions(+), 31 deletions(-)

diff --git a/arch/arm64/include/asm/insn.h b/arch/arm64/include/asm/insn.h
index 18c7811774d3..f6bce1a62dda 100644
--- a/arch/arm64/include/asm/insn.h
+++ b/arch/arm64/include/asm/insn.h
@@ -7,6 +7,7 @@
  */
 #ifndef	__ASM_INSN_H
 #define	__ASM_INSN_H
+#include <linux/bits.h>
 #include <linux/build_bug.h>
 #include <linux/types.h>
 
@@ -558,8 +559,35 @@ enum aarch64_insn_encoding_class aarch64_get_insn_class(u32 insn);
 u64 aarch64_insn_decode_immediate(enum aarch64_insn_imm_type type, u32 insn);
 u32 aarch64_insn_encode_immediate(enum aarch64_insn_imm_type type,
 				  u32 insn, u64 imm);
-u32 aarch64_insn_decode_register(enum aarch64_insn_register_type type,
-					 u32 insn);
+static __always_inline u32 aarch64_insn_decode_register(
+				 enum aarch64_insn_register_type type, u32 insn)
+{
+	compiletime_assert(type >= AARCH64_INSN_REGTYPE_RT &&
+		type <= AARCH64_INSN_REGTYPE_RS, "unknown register type encoding");
+	int shift;
+
+	switch (type) {
+	case AARCH64_INSN_REGTYPE_RT:
+	case AARCH64_INSN_REGTYPE_RD:
+		shift = 0;
+		break;
+	case AARCH64_INSN_REGTYPE_RN:
+		shift = 5;
+		break;
+	case AARCH64_INSN_REGTYPE_RT2:
+	case AARCH64_INSN_REGTYPE_RA:
+		shift = 10;
+		break;
+	case AARCH64_INSN_REGTYPE_RM:
+	case AARCH64_INSN_REGTYPE_RS:
+		shift = 16;
+		break;
+	default:
+		return 0;
+	}
+
+	return (insn >> shift) & GENMASK(4, 0);
+}
 u32 aarch64_insn_gen_branch_imm(unsigned long pc, unsigned long addr,
 				enum aarch64_insn_branch_type type);
 u32 aarch64_insn_gen_comp_branch_imm(unsigned long pc, unsigned long addr,
diff --git a/arch/arm64/lib/insn.c b/arch/arm64/lib/insn.c
index 4e298baddc2e..0fac78e542cf 100644
--- a/arch/arm64/lib/insn.c
+++ b/arch/arm64/lib/insn.c
@@ -144,35 +144,6 @@ u32 __kprobes aarch64_insn_encode_immediate(enum aarch64_insn_imm_type type,
 	return insn;
 }
 
-u32 aarch64_insn_decode_register(enum aarch64_insn_register_type type,
-					u32 insn)
-{
-	int shift;
-
-	switch (type) {
-	case AARCH64_INSN_REGTYPE_RT:
-	case AARCH64_INSN_REGTYPE_RD:
-		shift = 0;
-		break;
-	case AARCH64_INSN_REGTYPE_RN:
-		shift = 5;
-		break;
-	case AARCH64_INSN_REGTYPE_RT2:
-	case AARCH64_INSN_REGTYPE_RA:
-		shift = 10;
-		break;
-	case AARCH64_INSN_REGTYPE_RM:
-		shift = 16;
-		break;
-	default:
-		pr_err("%s: unknown register type encoding %d\n", __func__,
-		       type);
-		return 0;
-	}
-
-	return (insn >> shift) & GENMASK(4, 0);
-}
-
 static u32 aarch64_insn_encode_register(enum aarch64_insn_register_type type,
 					u32 insn,
 					enum aarch64_insn_register reg)
-- 
2.43.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250923174903.76283-4-ada.coupriediaz%40arm.com.
