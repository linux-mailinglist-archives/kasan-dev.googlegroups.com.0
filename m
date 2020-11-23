Return-Path: <kasan-dev+bncBDX4HWEMTEBRB65N6D6QKGQEJLR7Q7A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53b.google.com (mail-pg1-x53b.google.com [IPv6:2607:f8b0:4864:20::53b])
	by mail.lfdr.de (Postfix) with ESMTPS id 2A47F2C1554
	for <lists+kasan-dev@lfdr.de>; Mon, 23 Nov 2020 21:09:33 +0100 (CET)
Received: by mail-pg1-x53b.google.com with SMTP id c19sf13304352pgj.14
        for <lists+kasan-dev@lfdr.de>; Mon, 23 Nov 2020 12:09:33 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1606162172; cv=pass;
        d=google.com; s=arc-20160816;
        b=zkSWk2amJl88Uvlz+KP9Qx4PvJZMf8Fa9Q7MmK0zMfyZk193FX6hCa1jE4oS60V/W5
         oKSk69mVQ/RA9y+vTtXrPsXmiyYUQdFrq25Wzn+UaTpWPoLbZLNI+YuMBTWbFeuIIZba
         JwqeNOZcVDz5LRV/VK6bMjs0FDO6OO6jiGWaLy+RMxr2g+aCq59V/RW68oGc+fiz7RG/
         NpNd9nu/sFB7aGpQChK2POZ4uOYR2zrmtOwahUDVZr5gYgZu1E2mbCvxYKzpY9VglCA5
         uHgkmZfqohWFnpIT8ze2n+BZGO2pIjohWUOUbyFKGxk0q8ziFBY/uJtilMxjhro/AKxN
         LhjQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=gf1SPXmlrhYoEmU0QVBDiWy8W1TfxBRCH/V1Dfn7HII=;
        b=jKuZDFzfDKzDEShWt2cvT1T+obM6n03906JJyK5Dth7ho2S3LOhNKs92BDor1imBwv
         Sm4efdlGN5Exx5KSF5Zfc+Q0H5Pj38y/fqBNYhGvmm4GQyf2gHIMO0n3FqA3tFgfiznv
         H/nbCtn+rPm8M/k9clvDVcebQdflNDo+sq6FR5JwAktSWz7AOHPkQL7vtm2Q7g36Y7qf
         S+ijlo3XAcr5PBnjs2+IBvqswwko0iDbUOHwbZVzoMBewRF0sWnA2xm4UJHcqJVH75RH
         HhNrZq3KX7A8cD0Snkf6EML7eOgcJSfbKPq0Z6b2ycw39JfcKSWBmKRBWLo/gSfhoB6H
         TY3Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Bnb8vGsj;
       spf=pass (google.com: domain of 3-ha8xwokcr03g6k7rdgoe9hh9e7.5hfd3l3g-67o9hh9e79khnil.5hf@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3-ha8XwoKCR03G6K7RDGOE9HH9E7.5HFD3L3G-67O9HH9E79KHNIL.5HF@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=gf1SPXmlrhYoEmU0QVBDiWy8W1TfxBRCH/V1Dfn7HII=;
        b=UiCieKR1sKBPJKHrl7Atzx+VgrA+SWr6UBJVstMCLDDqiOx8QjNCJbs/zFvUHd1God
         UrZejFZl0leJramkNWMpAXujabL9h+Us6SGHDXWJkl08p9mYbea49sRlQP0P9rRzVdXG
         J73f5o2ojfcyy8qjjqbYjU13Zz0jmRKWXs+KlYZkiHRr/0ekn4w2G4AsEoATxnKCxG9L
         DBV9zMkAaDiqRd1YWiWJOQBVB8Yd7exlcOkS/5N3vHtRM4JcA/NnF8MSpYpDpxuuUTzs
         pbG7ImWaH3qzlVa6xweS2xop0fkovgd27Cbm1nFqVptkCgqbWr1sjkKeHRoWd82q8fpU
         tUKA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=gf1SPXmlrhYoEmU0QVBDiWy8W1TfxBRCH/V1Dfn7HII=;
        b=fTDhlUmNEjTJava1GciwPCE+hJ2OX1+wt6tY+c9Ixem758v4XiWubVVXgA8uNLl2Py
         JS7yYGnfALPNFHHEdxE7cpMLRa0u4Gtuv8HxMCJsTrgrBx028vOzwyATI1B8QscV7OBv
         IgB95v68kWOrEqt/KsAU7BhxZlYg+5d2sLImaH9YBvv2+jv/iJ3CT+vcCGr1x2aThthc
         qD5V1WI6GJcGZGYuWagUfJVGHTm2xPY2c0ypMWlrMPmNGqzoIR/7ferVZpvhu9m/L1WK
         4QkismBlgrmSNg9Ea92GdV4/HHh+d7/JqoJKzJrCWuBU9HN6JaidC4AhsENv+J2vFi0M
         ZkPg==
X-Gm-Message-State: AOAM533yH7tHWReRpjvRtnheDRFTCVqZU6gh/NG8ylM1bkvpYvDGZn4h
	ZdG/5AmOlBpeCN2yGzEUznU=
X-Google-Smtp-Source: ABdhPJzt5cmxqnlu+uSISWSQND7q/ZonBM5fF2P0rJYfWoV2phI+rXlkozVde/4w+2tMwsLJXeY2Ag==
X-Received: by 2002:a17:902:b60e:b029:da:f96:1b3c with SMTP id b14-20020a170902b60eb02900da0f961b3cmr941297pls.25.1606162171938;
        Mon, 23 Nov 2020 12:09:31 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:e905:: with SMTP id k5ls6658138pld.4.gmail; Mon, 23
 Nov 2020 12:09:31 -0800 (PST)
X-Received: by 2002:a17:90b:3907:: with SMTP id ob7mr717257pjb.70.1606162171367;
        Mon, 23 Nov 2020 12:09:31 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1606162171; cv=none;
        d=google.com; s=arc-20160816;
        b=C02y9EZ8fw2yvJyzsxveFQpRV09CYgA85+GU2+2J59SYDaNjFQnsar4gyN1HQjHmAR
         1QYc54CdmpchEf98tEgj7uzbacFUrlFiRLesNAuiVijiY4YEqx8dZPp7bs/qCxasdW7R
         VQcjSpH1miDS/BKthBj8qTy+34ebAeDxaBVW9uOQRM8R8zh09edRgF5p5M4JoU4m6Hi2
         XfYNcUaCWewKdu1Y73uaUeM/z9IxET/MEzQdeX5fdDiee6xjVX6nBUuDimLkyFYYDToD
         7uj+lnKlwXO87dh6m5bBvE2W7Gc0/eUoPnNkrHw0sAsUD+xh5c0GUoglxTE0bq635Y/D
         6rpA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=vnZk23A1hkByjQlL/Jowfu6pOB5axCxl0nNATXG6I/s=;
        b=TRQI0s12otlvX7fsLVHh0OKoecD8XNkTcCeEYxT7CclmpVqNfaa3qEX/UxnrkNkVIB
         gM4s3QbShXKL/p3Xg91qDOtA83hjjT8giaNYXosPTgQDgDhemQAt78k4meLUL2G3w2T/
         Swx1yObvOgwIP2hhoN/0JFB30OebQToyuWhJHJZtM011HPODkcd7oxOSzCsBkcgD1gfK
         FbuR0DDzI3HlBD7Xdqh2jaOInBZ6UivFS4Wn/yMQb2LqGiIiMX7qsq0GLj3bbIt03eE4
         d39sM/nRM0lGY2o0ozaYhNyHdBINkcOdx14vPof2f4IETFqI1cJmro2Ks7Tz9D0masOf
         m99A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Bnb8vGsj;
       spf=pass (google.com: domain of 3-ha8xwokcr03g6k7rdgoe9hh9e7.5hfd3l3g-67o9hh9e79khnil.5hf@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3-ha8XwoKCR03G6K7RDGOE9HH9E7.5HFD3L3G-67O9HH9E79KHNIL.5HF@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb49.google.com (mail-yb1-xb49.google.com. [2607:f8b0:4864:20::b49])
        by gmr-mx.google.com with ESMTPS id h11si780512plr.1.2020.11.23.12.09.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 23 Nov 2020 12:09:31 -0800 (PST)
Received-SPF: pass (google.com: domain of 3-ha8xwokcr03g6k7rdgoe9hh9e7.5hfd3l3g-67o9hh9e79khnil.5hf@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) client-ip=2607:f8b0:4864:20::b49;
Received: by mail-yb1-xb49.google.com with SMTP id k196so24322721ybf.9
        for <kasan-dev@googlegroups.com>; Mon, 23 Nov 2020 12:09:31 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a25:786:: with SMTP id
 128mr1448326ybh.19.1606162170465; Mon, 23 Nov 2020 12:09:30 -0800 (PST)
Date: Mon, 23 Nov 2020 21:07:51 +0100
In-Reply-To: <cover.1606161801.git.andreyknvl@google.com>
Message-Id: <ad31529b073e22840b7a2246172c2b67747ed7c4.1606161801.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1606161801.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.2.454.gaff20da3a2-goog
Subject: [PATCH mm v11 27/42] arm64: mte: Add in-kernel tag fault handler
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=Bnb8vGsj;       spf=pass
 (google.com: domain of 3-ha8xwokcr03g6k7rdgoe9hh9e7.5hfd3l3g-67o9hh9e79khnil.5hf@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3-ha8XwoKCR03G6K7RDGOE9HH9E7.5HFD3L3G-67O9HH9E79KHNIL.5HF@flex--andreyknvl.bounces.google.com;
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
index 385a189f7d39..d841a560fae7 100644
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
index 183d1e6dd9e0..1e4b9353c68a 100644
--- a/arch/arm64/mm/fault.c
+++ b/arch/arm64/mm/fault.c
@@ -34,6 +34,7 @@
 #include <asm/debug-monitors.h>
 #include <asm/esr.h>
 #include <asm/kprobes.h>
+#include <asm/mte.h>
 #include <asm/processor.h>
 #include <asm/sysreg.h>
 #include <asm/system_misc.h>
@@ -297,6 +298,44 @@ static void die_kernel_fault(const char *msg, unsigned long addr,
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
+	static bool reported;
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
@@ -313,6 +352,12 @@ static void __do_kernel_fault(unsigned long addr, unsigned int esr,
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
2.29.2.454.gaff20da3a2-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ad31529b073e22840b7a2246172c2b67747ed7c4.1606161801.git.andreyknvl%40google.com.
