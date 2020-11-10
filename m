Return-Path: <kasan-dev+bncBDX4HWEMTEBRBQNAVT6QKGQEAAIOKSA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x140.google.com (mail-lf1-x140.google.com [IPv6:2a00:1450:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id 5C93A2AE2D3
	for <lists+kasan-dev@lfdr.de>; Tue, 10 Nov 2020 23:12:18 +0100 (CET)
Received: by mail-lf1-x140.google.com with SMTP id b13sf84295lfi.1
        for <lists+kasan-dev@lfdr.de>; Tue, 10 Nov 2020 14:12:18 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605046338; cv=pass;
        d=google.com; s=arc-20160816;
        b=f2v/mgCdnVPwFW56K24HmvUtIaOMXokT90j2e2n+0m0ccXuGMoI6AwXLwrWWVcgfEJ
         tJy1MUL3MNegArr5S5nEg990smdknKnXDm19H3fWIYRCSd/33gUsx/cb0swdyrHN3V5e
         xFNI8RE1d4h+EGtSaMFfzDip002XhHrC5JVSNNvTXodSlUnVGx9UfBYUMrpdRKz4ADaG
         bnpqoU6qLgSu0nfeRJzWOmGDfuzAdVaws21vK7Ig5HdrEemRUsO4CyxxhvuRcUb9k+rn
         ovmFbMVMDMgFue2CiBovFLwMFJmB+zzEmF/h0s3JJvAGE1Dl5RrlE3sSBi33nGgSXDM9
         N0xw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=5Fy7w1JTEuEojl4gOu5efDG/J2ZezUOCTkWCYOATlyA=;
        b=faykgfX2kdNdDv+X3Ai24zHes934P/rnYtobdj0ryPhtKJNPeqXszBeZVMu8+r5hYS
         tNxR+bm6cUjiE3HAlOaQXQA49t6Fa/4+MaQ9TPX2vgAo524w85ocVOwd32g6C7kHKkOC
         UCFA1pD33NSJnpt7PkDvQS1o+cp+fsTb2kcRwXmQhwoe7ht47NSHROeksKgpfXlf9u9p
         7M7Dx7UR6FeS8qQcEUPAuvWa+kinUJBHtpD8pVWRf308G7V1LU0GYC8AoxGrcPqA8oc5
         lzjcGd+g/l/OSP/kd3UQJO31UBqqPmP0P2xBlMoFupB12UaQZeRrBdpwwCEfIjQtknVQ
         r91Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="Oi4sfQV/";
       spf=pass (google.com: domain of 3qbcrxwokcrer4u8vf14c2x55x2v.t531r9r4-uvcx55x2vx85b69.t53@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3QBCrXwoKCREr4u8vF14C2x55x2v.t531r9r4-uvCx55x2vx85B69.t53@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=5Fy7w1JTEuEojl4gOu5efDG/J2ZezUOCTkWCYOATlyA=;
        b=f+4R66HnDWvfr4ZwtrkGWsEkrD4PSCpa+/SSYI38L3AY1LdaUoPIj+JTvxbSRUW2Dc
         7G9GOyQ1tlSRM8jQ2OpvZc27uqVbAInICc6XNaxK//2czx1qiMy9GrMvY7br8LcUUYPr
         b8XqEiNL04QPIfoJj9843WbBLgzoRuT+UETJV/HIa/AUAxUoaw+qzLi6TFRmIkZaPg+G
         qCrwF/rsmeahzmNUl839bXE4b8MIzWP+8GmMCNBFq+BbjGvLejEM79LVEvE5bILnN5go
         RARlq6jCKSW5RnqXRd6YyRzetIGvQZeVaudjfAFsQQloKU3UkDpQ3J6GA44KuIypqIoN
         Zerg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=5Fy7w1JTEuEojl4gOu5efDG/J2ZezUOCTkWCYOATlyA=;
        b=WhfGlnYrtieYYKN/I7nTn8xe7U/ZxGCIlqM2/2bdm/QAH3lme9nVujcCvoOqZsKwmi
         OVRG0E08Ue1IUWKcFue622NaCc+QjNgDsAjCzejskOOPDObmr8szmh8TSyUEm2rCCKNu
         zIKeRNEMHwM10vYhhfmJxVqbkuS99Jf9B2env3dauRR6jv/PlF0LEhYUypyu6arFNG8W
         Y0NXajbD0IEMizf10dsnr3N70vNrrL8HgWHY95Nql6rqZfGlTaWBufHvWD2OA58ebEhW
         GruDbBbI31GvcscwqrNeFCKSMYCEF4sm8cibkxtr8w5NtgNdMECN1umahl8ahxgjU9oD
         nCfg==
X-Gm-Message-State: AOAM532/icV+kg8XRLVPTBH7AhzNEftpvTZCxo8iDZf9Dpwr+RG30asZ
	FhD5mwxHiElTnUfVeWnwB2Q=
X-Google-Smtp-Source: ABdhPJyBUejMFpaMjU/rQn8hRWEyX0MNQ3zyULlgAGOsK9We3EqStcId256RaZwOPdPodbbfON1bkQ==
X-Received: by 2002:a2e:9648:: with SMTP id z8mr6273082ljh.91.1605046337954;
        Tue, 10 Nov 2020 14:12:17 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:9acf:: with SMTP id p15ls1282808ljj.6.gmail; Tue, 10 Nov
 2020 14:12:16 -0800 (PST)
X-Received: by 2002:a2e:9208:: with SMTP id k8mr8725033ljg.369.1605046336722;
        Tue, 10 Nov 2020 14:12:16 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605046336; cv=none;
        d=google.com; s=arc-20160816;
        b=GmW8Orqal+oWWHAvKcJFfoqsG5o2esZb8tTE26tugYQjlArTL4J5emAvjD+MKvHKDP
         9bS9e7k42Obad/HDkhBqouWgsfbL5sWf+vM42lUjs4VdOy7YWtm7fCaZxHSHtq+/XHxM
         gq/Z+mbpHSdngqat+DUhM4UJYuSa87ov/qRnOBRZjX9qMiHryix1t1twP9EOdIlkRMZO
         VO+cxhwCof03dJZkHKGvIpDgljR+1zdu9aXv+khJMSVUEkPDBCcCc+ip8Jz0+mkUOH4H
         j7UdU6hGcazmPGgMyaa9Fsvuz9uwVdyvqahe1wmpsCul1MYROqor39V3obF2fJWG6d+V
         6a8A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=1bYqciy44TQVhE5hxgy8PR0a5xeoaFJ1mc4wbOxDwLU=;
        b=D/1lnkvmcE3B0DvjiinpJmL3HJrOXBpwOj1vhJ/S0xNF29uPtPHVRizFqJQfgvbUQg
         5QoDAUcBx5AawIXlVCSZaiEbNs5c591w+zHEKr5r1fS+J3N/odBe4X1bHSxfFSyXDbSM
         5GVbuWpYBEco2E8sdD2pK5dRUOl/ol2Yc4mS9TOHF4aOYP3doM1VXLkM2K/Y5LBrfCMV
         C0No6zznlOP7BRMmTRffoqA4YCYss7PvBIS7E57sEotwGWlvReSmjI901+PDlfmFyQO0
         Y/LPubRjFH5MiRgCu+DBVbOZDK0RKml8r1U+v7rg3C9fZoCym5nwsr33Ve8R3HWz4o9a
         /jIA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="Oi4sfQV/";
       spf=pass (google.com: domain of 3qbcrxwokcrer4u8vf14c2x55x2v.t531r9r4-uvcx55x2vx85b69.t53@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3QBCrXwoKCREr4u8vF14C2x55x2v.t531r9r4-uvCx55x2vx85B69.t53@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x449.google.com (mail-wr1-x449.google.com. [2a00:1450:4864:20::449])
        by gmr-mx.google.com with ESMTPS id f9si4725lfl.3.2020.11.10.14.12.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 10 Nov 2020 14:12:16 -0800 (PST)
Received-SPF: pass (google.com: domain of 3qbcrxwokcrer4u8vf14c2x55x2v.t531r9r4-uvcx55x2vx85b69.t53@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) client-ip=2a00:1450:4864:20::449;
Received: by mail-wr1-x449.google.com with SMTP id h11so6170728wrq.20
        for <kasan-dev@googlegroups.com>; Tue, 10 Nov 2020 14:12:16 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a7b:cf22:: with SMTP id
 m2mr214895wmg.179.1605046336032; Tue, 10 Nov 2020 14:12:16 -0800 (PST)
Date: Tue, 10 Nov 2020 23:10:26 +0100
In-Reply-To: <cover.1605046192.git.andreyknvl@google.com>
Message-Id: <96694ab6b5b64f4ab2de32cdc4773857966d62f1.1605046192.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1605046192.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.2.222.g5d2a92d10f8-goog
Subject: [PATCH v9 29/44] arm64: mte: Add in-kernel tag fault handler
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
 header.i=@google.com header.s=20161025 header.b="Oi4sfQV/";       spf=pass
 (google.com: domain of 3qbcrxwokcrer4u8vf14c2x55x2v.t531r9r4-uvcx55x2vx85b69.t53@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3QBCrXwoKCREr4u8vF14C2x55x2v.t531r9r4-uvCx55x2vx85B69.t53@flex--andreyknvl.bounces.google.com;
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
Reviewed-by: Catalin Marinas <catalin.marinas@arm.com>
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
2.29.2.222.g5d2a92d10f8-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/96694ab6b5b64f4ab2de32cdc4773857966d62f1.1605046192.git.andreyknvl%40google.com.
