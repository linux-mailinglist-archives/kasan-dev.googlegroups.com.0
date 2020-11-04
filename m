Return-Path: <kasan-dev+bncBDX4HWEMTEBRBMPORT6QKGQEZR3U73I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x137.google.com (mail-lf1-x137.google.com [IPv6:2a00:1450:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id 23C352A713C
	for <lists+kasan-dev@lfdr.de>; Thu,  5 Nov 2020 00:20:18 +0100 (CET)
Received: by mail-lf1-x137.google.com with SMTP id 205sf99993lfb.17
        for <lists+kasan-dev@lfdr.de>; Wed, 04 Nov 2020 15:20:18 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1604532017; cv=pass;
        d=google.com; s=arc-20160816;
        b=LpP8Z+UCYNnVraAVHaY6yjZU4vPOwVkoRg6glXINhH9mK/SZPiRPDIipqmwfDk4VCN
         qC0pevqxqSTC1KuFp74ObpgERdBUQ5V0SAR3XP7prWIWo8qkyPRDk1db/OWkCoCXDDBi
         RbFfa7/V6ftmx0Ph75z2Nb8UZiQdSRbLHFxLNx1ls2rdt02uGT3jtVS3Hi0+Q/bxYKDu
         4AkeH7SxNqh5xdof1GHotT9woOMBlCKvLYL6ZZfH0exfLLL8Gkjn3R7vvCBu6VCWtGiw
         FcWeKNfxhvDDSyro6U01sbGLXdGIHMd2RZ+Fl5Bs7ksRdJHQr3e7HXvCpKZUm0chZipj
         aq1w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=c4lHt3CIKMYVQ7/PGCvmTEkG/7Kd8s2QXwoOgFM9lMQ=;
        b=lBkADtM+OmpCTbYHkmDDozalICG+ahNogBkNIqpJS586VP2Da98LXcLHTQStRR5jlg
         a7I3RGvz91aqkt74l9aQ2G4k0IMOwp3nykMJ6AdOWK6z4HKyW44HbIko/lBsBTQCPgOI
         Odo4DJFz3UR2ZC9kare2JWWQvb0Tz72kLSyjj3bbqmPb6cBlhbD+rEXgmEblJH4MSXu4
         LWsuekz694pipzm7fadD4Le7BKG59ph52d8T4ZbYsILPA4yKDvd0rQ+tnV8WRk8WRIHJ
         z+8u/UpHYhn9GZE/mvLSW7TagB/XCdfdabTu6/giNf2AtsMrG5TwFlt9O2WjTC44+GAn
         ZAIQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=dmRgatD+;
       spf=pass (google.com: domain of 3mdejxwokcs8lyocpjvygwrzzrwp.nzxvldly-opgrzzrwprczfad.nzx@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3MDejXwoKCS8LYOcPjVYgWRZZRWP.NZXVLdLY-OPgRZZRWPRcZfad.NZX@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=c4lHt3CIKMYVQ7/PGCvmTEkG/7Kd8s2QXwoOgFM9lMQ=;
        b=nRxCkH4HQ+UzTmqmInPMp3shh0ryn/HAejbMSZBj83zFxG1WAnntlkBX7X9QLY+5sA
         v3NtyqUIQQFjB0xOE/HXYmC3kwZqXxqTBHYBP2HEU2TdMy5QZMgugCZrWNh6lNW5L4N1
         GrjLV3aHRV5Zh0L+frL0BJ+1ubeLGyrbPmub0egPUDy5yF6VzUO7gQLfeYICd7u0Jtz1
         jngB75HlZs7eW1wIf4PxRKlr6Eubuqv0v6sgq9+33cR3mvdsskvBwaCGH9PnJw7n6phg
         GtSKzRaMO5VjCH/EVb9YU+krHQwfXZpElazUVQgvcEyFwdhXL/qA8VKCcC2jsSMGrspq
         UDoQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=c4lHt3CIKMYVQ7/PGCvmTEkG/7Kd8s2QXwoOgFM9lMQ=;
        b=cYipzijeDOeJ+UXjodOHExXqkY6rdlRzCPmk1jaaC1NUqUoP2UBGtYThtS0ykrl7uL
         Lmmw31/N1c3ihP36a3clJR7brPqZP9kenRFvT8WPZQuE50VS6AMBnleibmyhFtzT1jlL
         ZS6STKmYliYTN3TG3DVP9yeSL/06xxX5S8p/RG4qVlOiom2flheKEu0/TS/ORmKhSoo1
         IvErQEBn2gs/LqZyozSTYyJn7dkoQB1Ac/FbyYmH1OIsF7olidDfRLijlTo3d0giYL/1
         vCqr1EyVhl2Ju+B0CFLKkzc1LMrDkrn3vKxUCELd6TZ6ayWOkx3WwqRljDlUFxfa7xXX
         sM5w==
X-Gm-Message-State: AOAM5315q9cn/JUoNvoSGukHJ5iT0dmq2ILx4Fet9XO1ejfb7snN2TJ/
	3Gi7BXlecADw8/rP55OPws0=
X-Google-Smtp-Source: ABdhPJwxX2BlPT7SS5juKSw8gHP6j6QQ8SDuomJPKo7ILy0Dw3X9qhRXLl3IDQQoiOK1N23JtDhoaw==
X-Received: by 2002:ac2:5a0e:: with SMTP id q14mr32212lfn.216.1604532017735;
        Wed, 04 Nov 2020 15:20:17 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a19:586:: with SMTP id 128ls2256152lff.1.gmail; Wed, 04 Nov
 2020 15:20:16 -0800 (PST)
X-Received: by 2002:a05:6512:1c7:: with SMTP id f7mr36831lfp.2.1604532016837;
        Wed, 04 Nov 2020 15:20:16 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1604532016; cv=none;
        d=google.com; s=arc-20160816;
        b=aG/0vSNt5UTXQ+3Knk4YA/N14WRIv5mKFT11HCAXxWk4P+hSSFLMTqJTiT9S8kGf7u
         nmsNL311W9+UqwFiYrY46E52+esy6RLtlXJ6/V3sbS6lajGTKCesCm9h9JQN5v9z3fcM
         /0ozLLW0xLAwGzX7EnMun52YWyop7Jb1QtOqBxpyw2cGcqznucpZamc6ATIrnHdM9ItV
         5BpRUv3L3qEsI6E0WhBbzvCv9qrQmozITqX1tQ8dUUPe1hs8OPgdoKBnFlmv3znwEE91
         8obsVLR1gaZPUsmnGv+he2WNuVl3Hgt5zUlOVQjBkvEFKv1HwkLwi0x4z6ld2EwY14uf
         2Q+A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=SHQTTAC6Hd6Fbj5acE+XjHaNfSSfd6dVM7XrjREAdfI=;
        b=J6siFyInv4Sza2aLcwLj/zAj/sQRkZcyPrZSyKGUGL6D7BLAxwY+E58tNkXyDKaxn9
         g3NZ8FWiCd0gjd5+bVBcjbZt64Yeo2SnYoynubIguio1xnBOxvLxsLGCwYptTmN44ImM
         nvWgR5xwVzFkFUT4/z2CcPHVy0R76KjsqqGtxq3NiYYHaes3E3QeFJbKUWxEAGAvLpZE
         WetOGce65/6dB/jgtby9mki+utBdeEFbjdaoTwhyb1Wf7hb9QusPTOEFkbyIkkZ/pnZU
         eVyMrzHi27LUmR4C0D15gk3MTEBf3satl3DCRPwZijhgVyQMvqUTuRXGhgkXOnm0NCL+
         mg/Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=dmRgatD+;
       spf=pass (google.com: domain of 3mdejxwokcs8lyocpjvygwrzzrwp.nzxvldly-opgrzzrwprczfad.nzx@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3MDejXwoKCS8LYOcPjVYgWRZZRWP.NZXVLdLY-OPgRZZRWPRcZfad.NZX@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x349.google.com (mail-wm1-x349.google.com. [2a00:1450:4864:20::349])
        by gmr-mx.google.com with ESMTPS id v24si116694lfo.5.2020.11.04.15.20.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 04 Nov 2020 15:20:16 -0800 (PST)
Received-SPF: pass (google.com: domain of 3mdejxwokcs8lyocpjvygwrzzrwp.nzxvldly-opgrzzrwprczfad.nzx@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) client-ip=2a00:1450:4864:20::349;
Received: by mail-wm1-x349.google.com with SMTP id u207so24612wmu.4
        for <kasan-dev@googlegroups.com>; Wed, 04 Nov 2020 15:20:16 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:adf:ff82:: with SMTP id
 j2mr329460wrr.401.1604532016330; Wed, 04 Nov 2020 15:20:16 -0800 (PST)
Date: Thu,  5 Nov 2020 00:18:44 +0100
In-Reply-To: <cover.1604531793.git.andreyknvl@google.com>
Message-Id: <a540ab7b9e3b908e0f4cd94c963a0cc6bb4e7d3f.1604531793.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1604531793.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.1.341.ge80a0c044ae-goog
Subject: [PATCH v8 29/43] arm64: mte: Add in-kernel tag fault handler
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Catalin Marinas <catalin.marinas@arm.com>
Cc: Will Deacon <will.deacon@arm.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=dmRgatD+;       spf=pass
 (google.com: domain of 3mdejxwokcs8lyocpjvygwrzzrwp.nzxvldly-opgrzzrwprczfad.nzx@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3MDejXwoKCS8LYOcPjVYgWRZZRWP.NZXVLdLY-OPgRZZRWPRcZfad.NZX@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

From: Vincenzo Frascino <vincenzo.frascino@arm.com>

Add the implementation of the in-kernel fault handler.

When a tag fault happens on a kernel address:
* MTE is disabled on the current CPU,
* the execution continues.

When a tag fault happens on a user address:
* the kernel executes do_bad_area() and panics.

The tag fault handler for kernel addresses is currently empty and will be
filled in by a future commit.

Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
Co-developed-by: Andrey Konovalov <andreyknvl@google.com>
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
Change-Id: I9b8aa79567f7c45f4d6a1290efcf34567e620717
---
 arch/arm64/include/asm/uaccess.h | 23 ++++++++++++++++
 arch/arm64/mm/fault.c            | 45 ++++++++++++++++++++++++++++++++
 2 files changed, 68 insertions(+)

diff --git a/arch/arm64/include/asm/uaccess.h b/arch/arm64/include/asm/uaccess.h
index 991dd5f031e4..c7fff8daf2a7 100644
--- a/arch/arm64/include/asm/uaccess.h
+++ b/arch/arm64/include/asm/uaccess.h
@@ -200,13 +200,36 @@ do {									\
 				CONFIG_ARM64_PAN));			\
 } while (0)
 
+/*
+ * The Tag Check Flag (TCF) mode for MTE is per EL, hence TCF0
+ * affects EL0 and TCF affects EL1 irrespective of which TTBR is
+ * used.
+ * The kernel accesses TTBR0 usually with LDTR/STTR instructions
+ * when UAO is available, so these would act as EL0 accesses using
+ * TCF0.
+ * However futex.h code uses exclusives which would be executed as
+ * EL1, this can potentially cause a tag check fault even if the
+ * user disables TCF0.
+ *
+ * To address the problem we set the PSTATE.TCO bit in uaccess_enable()
+ * and reset it in uaccess_disable().
+ *
+ * The Tag check override (TCO) bit disables temporarily the tag checking
+ * preventing the issue.
+ */
 static inline void uaccess_disable(void)
 {
+	asm volatile(ALTERNATIVE("nop", SET_PSTATE_TCO(0),
+				 ARM64_MTE, CONFIG_KASAN_HW_TAGS));
+
 	__uaccess_disable(ARM64_HAS_PAN);
 }
 
 static inline void uaccess_enable(void)
 {
+	asm volatile(ALTERNATIVE("nop", SET_PSTATE_TCO(1),
+				 ARM64_MTE, CONFIG_KASAN_HW_TAGS));
+
 	__uaccess_enable(ARM64_HAS_PAN);
 }
 
diff --git a/arch/arm64/mm/fault.c b/arch/arm64/mm/fault.c
index 1ee94002801f..fbceb14d93b1 100644
--- a/arch/arm64/mm/fault.c
+++ b/arch/arm64/mm/fault.c
@@ -33,6 +33,7 @@
 #include <asm/debug-monitors.h>
 #include <asm/esr.h>
 #include <asm/kprobes.h>
+#include <asm/mte.h>
 #include <asm/processor.h>
 #include <asm/sysreg.h>
 #include <asm/system_misc.h>
@@ -296,6 +297,44 @@ static void die_kernel_fault(const char *msg, unsigned long addr,
 	do_exit(SIGKILL);
 }
 
+static void report_tag_fault(unsigned long addr, unsigned int esr,
+			     struct pt_regs *regs)
+{
+}
+
+static void do_tag_recovery(unsigned long addr, unsigned int esr,
+			   struct pt_regs *regs)
+{
+	static bool reported = false;
+
+	if (!READ_ONCE(reported)) {
+		report_tag_fault(addr, esr, regs);
+		WRITE_ONCE(reported, true);
+	}
+
+	/*
+	 * Disable MTE Tag Checking on the local CPU for the current EL.
+	 * It will be done lazily on the other CPUs when they will hit a
+	 * tag fault.
+	 */
+	sysreg_clear_set(sctlr_el1, SCTLR_ELx_TCF_MASK, SCTLR_ELx_TCF_NONE);
+	isb();
+}
+
+static bool is_el1_mte_sync_tag_check_fault(unsigned int esr)
+{
+	unsigned int ec = ESR_ELx_EC(esr);
+	unsigned int fsc = esr & ESR_ELx_FSC;
+
+	if (ec != ESR_ELx_EC_DABT_CUR)
+		return false;
+
+	if (fsc == ESR_ELx_FSC_MTE)
+		return true;
+
+	return false;
+}
+
 static void __do_kernel_fault(unsigned long addr, unsigned int esr,
 			      struct pt_regs *regs)
 {
@@ -312,6 +351,12 @@ static void __do_kernel_fault(unsigned long addr, unsigned int esr,
 	    "Ignoring spurious kernel translation fault at virtual address %016lx\n", addr))
 		return;
 
+	if (is_el1_mte_sync_tag_check_fault(esr)) {
+		do_tag_recovery(addr, esr, regs);
+
+		return;
+	}
+
 	if (is_el1_permission_fault(addr, esr, regs)) {
 		if (esr & ESR_ELx_WNR)
 			msg = "write to read-only memory";
-- 
2.29.1.341.ge80a0c044ae-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/a540ab7b9e3b908e0f4cd94c963a0cc6bb4e7d3f.1604531793.git.andreyknvl%40google.com.
