Return-Path: <kasan-dev+bncBDB3VRFH7QKRBXN3ZPDAMGQEBNW5VLI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x839.google.com (mail-qt1-x839.google.com [IPv6:2607:f8b0:4864:20::839])
	by mail.lfdr.de (Postfix) with ESMTPS id 44B51B971C6
	for <lists+kasan-dev@lfdr.de>; Tue, 23 Sep 2025 19:50:33 +0200 (CEST)
Received: by mail-qt1-x839.google.com with SMTP id d75a77b69052e-4b5ee6cd9a3sf120093111cf.2
        for <lists+kasan-dev@lfdr.de>; Tue, 23 Sep 2025 10:50:33 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758649822; cv=pass;
        d=google.com; s=arc-20240605;
        b=POCQBJhNL/p+WYSdrNTHTPNfBFu9FIJog2OJtxOMn9WyK8D5mKxd5rJQyNjRQpAQu0
         5oaR0u0bqP3q25fmeAu5Z7gFqyYGjuoSIIgyfx10thvRE89fEl8OhxgXfu/aHQSDprgs
         hTGzFKD5XSX6a5TsxH/7CyKPZ8LVygHCbTXVVMjcrbbWAZDlt0tWtSm5URCwLgHvGHum
         Rm6viHvQaOqPA4ZYYYaUIKDdWR5xKgSXl9GUYK2B3H4tNiWLBoPxryrCW4B1X2VWEZAd
         HQiJFb5DsZHYeExIaNh3GnFYg4y4GB3+DjYMEJEbcS1wfRnQCpCfn0OKEoXPvLp7dsem
         1qfw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=guIJcGV7r/Ji+bwNZ7jbE0wzNIFLSJrO/8OtCa0Rxhg=;
        fh=DnMuyXtLJkMS8EThZGT4JMe2bp9QIo/ljkhMaTjeROY=;
        b=QtP8cUPYG3OBuA3pMRNtYIrGQwOoaeRnMXux6jUjQgUWWdUFV7U7TDhTeSbkciWHEx
         DKhOU356izs42qXEF3+MA/QGUk5fPA41ArO/TyZ0v2N6OSDdLSF3i494xfajOBcJwSmN
         RLi96zQ+pUusF19W285LFmMPptEFihy+Da1+YN8vbPSPtdR8874roywyB+nHMRd33GG6
         edzIwcGC5sWwLt5uSNYgVQ2fD6SlZAWYpB8eQ/nrwon2DodP1y3j6hbxHnOYtc3QySpU
         8o39yDcO30VMdLx17NnEMJoKi/tKHoIbfAbI86T1ZBajDN0jguHeHID78N0jkdGVsnrz
         IbvQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of ada.coupriediaz@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=ada.coupriediaz@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758649822; x=1759254622; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=guIJcGV7r/Ji+bwNZ7jbE0wzNIFLSJrO/8OtCa0Rxhg=;
        b=Wwa07qpuJdJZkz3BcKlVeJE+7P8ZkeDzDz0Xhx05jAwKbbOtpYfhvyLEUcYmwrVUDB
         WnAZ3wR3Xs4FqeHd36s6nJmAKa/aO9i6GRu3dUmvQZFfzi2ZU13rqScO/pasMstZYu4r
         2wY5jiHPmylaJEIIwDL+CPtwhy6O5hHYTw5BZA3E/fRa0jNNGvBeDxJqCcdKEYBROePo
         XHFwGasKXMF+TkderbsyRO8ER6WVcGPcl8Tk76oqm4W1sd3YuMc4ksfJuu9jdX3+bFKL
         WrUslrdzOjAW6g0k0/AZWSPqxz/Z9R0/ssKfJU8ZaRwFviCXmWdsOduucjrQALhlu4lR
         W1gA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758649822; x=1759254622;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=guIJcGV7r/Ji+bwNZ7jbE0wzNIFLSJrO/8OtCa0Rxhg=;
        b=VwZGl+xAeEzUpgteEszIM+dqM/aEwrA41DHk7XIDKCJD9DYgBtOGwbhzrn/AlGpJGB
         cTU2pAoogjjreYixQJv/vO9w5ZWK0KyLbTZwfFDxzDKaqJA8TZ5G8DHDK8aaeOjFVzit
         dpK9M/SUoIii7iMq5i35/PwqEC9N7rYlbL1z/pddb0v6drLiRYAbh7Hda+KKEc9NIIdW
         +3HCSe1jPAf7hQE6p4sQduM0GgF1OWPJKm1LtGOCtBAEnH6jpLxCnRx6dBh3ckkdVRfh
         O+USIVmX1ui+oUEjtHbGPEM7pJaze9RzRVVTjrnneQjzCcSboQtUO2Z/E7gfMEKcYzFX
         zTug==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWKzupmqqAF/ayzDBkcMqoEWN6akEvy3bJqU30GLRqJrNLjWPzOkrhzrizZguIhjuGCcVAPWQ==@lfdr.de
X-Gm-Message-State: AOJu0YyaJfpqdCbiBzT62t6i4ra9Zi8uAVl12BsITObpIqc4wLvLYuq+
	34q0GLZDiW1iUxvXEAwcOtLeaScB4/e0bR6PPBD4IXxczQGcVvP3WWig
X-Google-Smtp-Source: AGHT+IG8xv6wteo2jzRnH4NwNBQdMJQtjBTjhnfdsKzOsYuqVhW+imp/IuoQ6adZWDG58PRhF5bYRA==
X-Received: by 2002:ac8:7e91:0:b0:4b5:e8e0:4f93 with SMTP id d75a77b69052e-4d36e5de504mr40694841cf.54.1758649822010;
        Tue, 23 Sep 2025 10:50:22 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd4t4RGxuWOOQLBdSVgYS5m6zJqAAgpQwITEPVvPktK3jQ==
Received: by 2002:a05:622a:2a0a:b0:4d5:fa96:92b2 with SMTP id
 d75a77b69052e-4d5fa96c661ls11361731cf.1.-pod-prod-07-us; Tue, 23 Sep 2025
 10:50:20 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUMeo4xw1r7p+RxNdFlKM3HGE835eYqFz3xSLNSZzno55XFtuIQT6Za6jbHwA0Jvy7kivBY5xtQp0c=@googlegroups.com
X-Received: by 2002:a05:620a:7006:b0:82a:930:9cea with SMTP id af79cd13be357-85177763b8fmr348455485a.76.1758649820511;
        Tue, 23 Sep 2025 10:50:20 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1758649820; cv=none;
        d=google.com; s=arc-20240605;
        b=conrTRDCgxw6rnlPLY/nLyavKB1f36Afo2iRnFPjGWecOVyz/vtiVeO1qU709VtQ3T
         4MwmNvKlkvWKqgGSzJw6ElzLR+csSJYLd9DmcbQiddsz5aXG8X4Iq3xP/XYsDxlMMCxS
         a1AB0fvorG6jRhc84CJbGGk5zBv/+pA85q9jkbPm+D8caKzSH6jkDuLHupc64tBeVGNP
         V1dn4rVfEdGB/6KCIxRzfyIrkW1mCrvZh09IONC6p7LcGe86PnTS40CshvOTPt+vZRfX
         Aq9wYET7cJJJ5KAzmAyNfhwDLE1wXiqvfIiKt+ztHq+n3FOXa3MsiEZGk5yU70ZEjlYi
         BZ0A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=n0fsRj8Kbg0YwDCGy1uaBJYcA0zy5gcj8RY7k0/Au4A=;
        fh=eoJjfSK6fSSw8URA2i1Ih8m7A3n64cnY04bTfTqxJBk=;
        b=Y425tFtUmpLeuM18QCX9Jif6NqE4PL7i/hzI3CNQdasKnupBZ5qSzG03D52GiVQAAV
         OmGIgTQ+XadwszjEamCSWYV6vVNatygjdygUyl9AJ39s/E9ip44Sc2FA/x9t8fYg9o71
         yZaAEEXIaiLyab2lwRBD49qRh2qb1z1vJDZkSCtcWXX13QowlfE08kwROjTTrwUaWviw
         qzXfjkjvWJ0M23PxXc8sPhiqcPEi3tIQITUibmBlAFR6+OGYw+BZASeQQvN5nBfaLyXk
         evOK4zdRWhEZo9SQVDyZU3NEBsMSJQCMNDcfMPAnuDuS5GyW4bETxWTJp4e0qhXW67Zv
         XL6g==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of ada.coupriediaz@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=ada.coupriediaz@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id af79cd13be357-8363066c299si30931585a.6.2025.09.23.10.50.20
        for <kasan-dev@googlegroups.com>;
        Tue, 23 Sep 2025 10:50:20 -0700 (PDT)
Received-SPF: pass (google.com: domain of ada.coupriediaz@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id E32FCFEC;
	Tue, 23 Sep 2025 10:50:11 -0700 (PDT)
Received: from e137867.cambridge.arm.com (e137867.arm.com [10.1.30.204])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPA id 0FD563F5A1;
	Tue, 23 Sep 2025 10:50:15 -0700 (PDT)
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
Subject: [RFC PATCH 16/16] arm64/io: rework Cortex-A57 erratum 832075 to use callback
Date: Tue, 23 Sep 2025 18:49:03 +0100
Message-ID: <20250923174903.76283-17-ada.coupriediaz@arm.com>
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

The Cortex-A57 erratum 832075 fix implemented by the kernel
replaces all device memory loads with their load-acquire versions.
By using simple instruction-level alternatives to replace the 13k+
instances of such loads, we add more than 50kB of data
to the `.altinstructions` section, and thus the kernel image.

Implement `alt_cb_patch_ldr_to_ldar()` as the alternative callback
to patch LDRs to device memory into LDARs and use it instead
of the alternative instructions.

This lightens the image by around 50kB as predicted, with the same result.

The new callback is safe to be used for alternatives as it is `noinstr`
and the `aarch64_insn_...` functions it uses have been made safe
in previous commits.

Add `alt_cb_patch_ldr_to_ldar()` to the nVHE namespace as
`__vgic_v2_perform_cpuif_access()` uses one of the patched functions.

Signed-off-by: Ada Couprie Diaz <ada.coupriediaz@arm.com>
---
 arch/arm64/include/asm/io.h    | 27 +++++++++++++++------------
 arch/arm64/kernel/image-vars.h |  1 +
 arch/arm64/kernel/io.c         | 21 +++++++++++++++++++++
 3 files changed, 37 insertions(+), 12 deletions(-)

diff --git a/arch/arm64/include/asm/io.h b/arch/arm64/include/asm/io.h
index 9b96840fb979..ec75bd0a9d76 100644
--- a/arch/arm64/include/asm/io.h
+++ b/arch/arm64/include/asm/io.h
@@ -50,13 +50,16 @@ static __always_inline void __raw_writeq(u64 val, volatile void __iomem *addr)
 	asm volatile("str %x0, %1" : : "rZ" (val), "Qo" (*ptr));
 }
 
+void noinstr alt_cb_patch_ldr_to_ldar(struct alt_instr *alt,
+			       __le32 *origptr, __le32 *updptr, int nr_inst);
+
 #define __raw_readb __raw_readb
 static __always_inline u8 __raw_readb(const volatile void __iomem *addr)
 {
 	u8 val;
-	asm volatile(ALTERNATIVE("ldrb %w0, [%1]",
-				 "ldarb %w0, [%1]",
-				 ARM64_WORKAROUND_DEVICE_LOAD_ACQUIRE)
+	asm volatile(ALTERNATIVE_CB("ldrb %w0, [%1]",
+				 ARM64_WORKAROUND_DEVICE_LOAD_ACQUIRE,
+				 alt_cb_patch_ldr_to_ldar)
 		     : "=r" (val) : "r" (addr));
 	return val;
 }
@@ -66,9 +69,9 @@ static __always_inline u16 __raw_readw(const volatile void __iomem *addr)
 {
 	u16 val;
 
-	asm volatile(ALTERNATIVE("ldrh %w0, [%1]",
-				 "ldarh %w0, [%1]",
-				 ARM64_WORKAROUND_DEVICE_LOAD_ACQUIRE)
+	asm volatile(ALTERNATIVE_CB("ldrh %w0, [%1]",
+				 ARM64_WORKAROUND_DEVICE_LOAD_ACQUIRE,
+				 alt_cb_patch_ldr_to_ldar)
 		     : "=r" (val) : "r" (addr));
 	return val;
 }
@@ -77,9 +80,9 @@ static __always_inline u16 __raw_readw(const volatile void __iomem *addr)
 static __always_inline u32 __raw_readl(const volatile void __iomem *addr)
 {
 	u32 val;
-	asm volatile(ALTERNATIVE("ldr %w0, [%1]",
-				 "ldar %w0, [%1]",
-				 ARM64_WORKAROUND_DEVICE_LOAD_ACQUIRE)
+	asm volatile(ALTERNATIVE_CB("ldr %w0, [%1]",
+				 ARM64_WORKAROUND_DEVICE_LOAD_ACQUIRE,
+				 alt_cb_patch_ldr_to_ldar)
 		     : "=r" (val) : "r" (addr));
 	return val;
 }
@@ -88,9 +91,9 @@ static __always_inline u32 __raw_readl(const volatile void __iomem *addr)
 static __always_inline u64 __raw_readq(const volatile void __iomem *addr)
 {
 	u64 val;
-	asm volatile(ALTERNATIVE("ldr %0, [%1]",
-				 "ldar %0, [%1]",
-				 ARM64_WORKAROUND_DEVICE_LOAD_ACQUIRE)
+	asm volatile(ALTERNATIVE_CB("ldr %0, [%1]",
+				 ARM64_WORKAROUND_DEVICE_LOAD_ACQUIRE,
+				 alt_cb_patch_ldr_to_ldar)
 		     : "=r" (val) : "r" (addr));
 	return val;
 }
diff --git a/arch/arm64/kernel/image-vars.h b/arch/arm64/kernel/image-vars.h
index 714b0b5ec5ac..43ac41f87229 100644
--- a/arch/arm64/kernel/image-vars.h
+++ b/arch/arm64/kernel/image-vars.h
@@ -91,6 +91,7 @@ KVM_NVHE_ALIAS(spectre_bhb_patch_loop_mitigation_enable);
 KVM_NVHE_ALIAS(spectre_bhb_patch_wa3);
 KVM_NVHE_ALIAS(spectre_bhb_patch_clearbhb);
 KVM_NVHE_ALIAS(alt_cb_patch_nops);
+KVM_NVHE_ALIAS(alt_cb_patch_ldr_to_ldar);
 
 /* Global kernel state accessed by nVHE hyp code. */
 KVM_NVHE_ALIAS(kvm_vgic_global_state);
diff --git a/arch/arm64/kernel/io.c b/arch/arm64/kernel/io.c
index fe86ada23c7d..d4dff119f78c 100644
--- a/arch/arm64/kernel/io.c
+++ b/arch/arm64/kernel/io.c
@@ -9,6 +9,27 @@
 #include <linux/types.h>
 #include <linux/io.h>
 
+noinstr void alt_cb_patch_ldr_to_ldar(struct alt_instr *alt,
+			       __le32 *origptr, __le32 *updptr, int nr_inst)
+{
+	u32 rt, rn, size, orinst, altinst;
+
+	BUG_ON(nr_inst != 1);
+
+	orinst = le32_to_cpu(origptr[0]);
+
+	rt = aarch64_insn_decode_register(AARCH64_INSN_REGTYPE_RT, orinst);
+	rn = aarch64_insn_decode_register(AARCH64_INSN_REGTYPE_RN, orinst);
+	/* The size field (31,30) matches the enum used in gen_load_acq below. */
+	size = orinst >> 30;
+
+	altinst = aarch64_insn_gen_load_acq_store_rel(rt, rn, size,
+		AARCH64_INSN_LDST_LOAD_ACQ);
+
+	updptr[0] = cpu_to_le32(altinst);
+}
+EXPORT_SYMBOL(alt_cb_patch_ldr_to_ldar);
+
 /*
  * This generates a memcpy that works on a from/to address which is aligned to
  * bits. Count is in terms of the number of bits sized quantities to copy. It
-- 
2.43.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250923174903.76283-17-ada.coupriediaz%40arm.com.
