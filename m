Return-Path: <kasan-dev+bncBDX4HWEMTEBRBUUASP6AKGQERUYBVVI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x438.google.com (mail-pf1-x438.google.com [IPv6:2607:f8b0:4864:20::438])
	by mail.lfdr.de (Postfix) with ESMTPS id AD1E428C2E1
	for <lists+kasan-dev@lfdr.de>; Mon, 12 Oct 2020 22:45:07 +0200 (CEST)
Received: by mail-pf1-x438.google.com with SMTP id j207sf13439960pfd.13
        for <lists+kasan-dev@lfdr.de>; Mon, 12 Oct 2020 13:45:07 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1602535506; cv=pass;
        d=google.com; s=arc-20160816;
        b=WmB0Jj+knLuwkCUfcH7fU6Hwev6cgclLIedTZFT/aQq4AtsyNXm4m6e8vPxpklw/yh
         blrLt7kGxLVwD9Id75nk5Br7yOInsa+O7h1nm7CUX0qYxAbaMlULs6u61m90kFJD+u1m
         m22O6QiFAE89y/1fTvQsqd895eLbLnAV5SzAaH1PrHg2saxGlD4EkI9dgSG8L7X+wvAK
         1ZCwWECQa7Z/wt0+7M2GQKKC4SlCKz83TB1537UR59cyPT0+9mEgxOJ3eory5F2X+XSh
         VfTWytl5misMnPUaj9jBSs2+NaGVIUkx6b7+fsOAMC71Ex9Fx2Q9WIt1dzneZXgWDg9q
         ToTg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=tIO3+GjDvPVD5FVa8J6GtnI5fy44tqGvrHnljfwIW8E=;
        b=ZuFzg4xz9X8hw6Zv2+cDT+XZbwoZasFvhS5Ma58z4SDZLzeEc5nIi7Iwswslx0JwSr
         U6ycjl47e3ucG5sMXxhZyB66rKm6unubXk6BOzFcgflkZRLfLGaowk6HymBAzvy7tJlp
         gAq7X2aO2RNZ+VcKODMI47EBHPqR5HmFLnfh14RrkCVAHuMQsIJPLwe4wXcIIVN8OVAE
         vEli2Ga2P2tDyEHVMcd+pCAznkvioza+zjBBPLWS82d+8oIraiIZgE+XAeq62YQmUtON
         fGwI8Xv+50CYKOFzBp71AUVl/EAIyXCjyzHYfKx2cmdoC9S+3JLuBmY/6k0P6XuUgbxI
         kw4A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=nMVB8I60;
       spf=pass (google.com: domain of 3uccexwokceyivlzmgsvdtowwotm.kwusiaiv-lmdowwotmozwcxa.kwu@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=3UcCEXwoKCeYIVLZMgSVdTOWWOTM.KWUSIaIV-LMdOWWOTMOZWcXa.KWU@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=tIO3+GjDvPVD5FVa8J6GtnI5fy44tqGvrHnljfwIW8E=;
        b=hwsWjfDt9glWiaoYaZnQhG29onBh67cySTTh4N6P2Diop05r1YdWyUHDYSiBZ4E1tv
         A/0TBZ84kBTzHyFtA3sufemLnbWkSztwWIuABjVgb8Y/t5SX1kaXFbjxS1hII0kT+eEY
         KqGJ3I9AlB8hc+iSInqtJ/ApCcQ2PCKuKddSO2J4u1nqOmyInaRPsr56Acumbm8ewZsF
         MMXzk0pf/pcngt4wLTFyXwBeCZrPNCq9yuAg1zsuKBF8EwAlTph1oac74zjGGlM2sU0v
         BFfaRbx8Wn1Xr5uBd3DVe1gwq3rjX8gNQeSH8FZ26UPTTUH1G6lcFqzHwnUjA7p1hmpJ
         5juw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=tIO3+GjDvPVD5FVa8J6GtnI5fy44tqGvrHnljfwIW8E=;
        b=b/60eK9vYkqZLwAr5oQgxIEY39JU77puBugpTJVMdcD9c8PQ0MNbdoIIrf72NdnfUX
         u8NKm+dPs1o4QJKhDDCvsSnnBSq0wmSW9nI/Fr0+FHtQBGNs8kmou5JThn2sKsycbrND
         KrvuhutiTBQ3X2HKvyTqB9mCy+Mg3/xQdQjSO4T3fXntIicF2/ETjqo3AwcIVbt8RGu1
         5mfq16iUCL7YvU5HMe1R+hLbjoqCZyEk7Tvi4B59yuOsqCVR9i54xYU1nePgYH1Ro3wl
         JV1IQUwA7GgMUT6Z56FmDwTZPRmNafntJy802Fu71Be1XLSSSUEowYepLEgoRTw3cK+E
         q/MA==
X-Gm-Message-State: AOAM533lm1b6pDMCHCy7QTFvDbosY2MWJLy70xDRDpTHtyq97pux+xVi
	1l6wodkfnGKZhypHTt01JRk=
X-Google-Smtp-Source: ABdhPJw1ogTArR9YxxX2zO6t7LTroy2XxHlfKQTvz4oBCu/bWUZcHJ3pmvzmiKoWJABGhgL3VYNcfA==
X-Received: by 2002:a17:90a:804a:: with SMTP id e10mr21403726pjw.218.1602535506330;
        Mon, 12 Oct 2020 13:45:06 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:6883:: with SMTP id d125ls6021058pfc.8.gmail; Mon, 12
 Oct 2020 13:45:05 -0700 (PDT)
X-Received: by 2002:aa7:875a:0:b029:155:7c08:f2ed with SMTP id g26-20020aa7875a0000b02901557c08f2edmr18793859pfo.52.1602535505745;
        Mon, 12 Oct 2020 13:45:05 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1602535505; cv=none;
        d=google.com; s=arc-20160816;
        b=xAw+0lYhbrXN31NHI+NqeSX4O9arwL3tRsQJO4K8bvmS1/WhSaN3X5KYsG7k4RShkG
         Aybgh5Owoyovu04C5Ewg5Co57bAW3bGS0a60EUORxYg8UBCLD57esli/pTEIcuWeYNx8
         M4aWzyc2DmSOYaQALHP8Ft3apf1yrhIqm/ADBB7JOFGcIPhQyvZpuKeR/5HDdTkZqqBI
         rJFowqRZMXq9I2YM4SKpdrfesXzCGkbmenSq4uiCXFPUgGYFO2ZDnVhMMwistL5jruIU
         QL1xBTvtx2uDF1pA1aGp+eaw4asSebjhnBSBzN9sN18rUpkCJahWJsikFzPhxYBU2K0f
         IuXg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=bjvHqcBgNm8vzwcqTnhTOa3HGbkQ0h2BrEBfu6OF+W0=;
        b=aGy6KuxBvnFeSsyoKGeXhAONhKY7gxTkmuqR0z5a758DDe6/aYNQvh6PQydKImnXaY
         3ZdmXuOyXm7HPBOWforMTOKh0O1508TrkesBJqrCqnkjZynHQr0Z1kJFh//hqJeJZbQw
         /VmCbK8iFjLzuXrxUy6Zi+i8NNnnYmlZgQFHOYt3qU5cyxIKyA9KCusOszbiiO2UTDkh
         gP+XpzfKXESQ1miFqpj/lqNzEOMYbG1rAK5nNZSfMCNQgMfW+HsCCmBw2J9Zi2zORoVY
         8Vt2TZ2uZXpm2aIB8sUFdUpX8fHCjYMcPsTg2wPDD898RNH1wEb2FplIDdToEOH7uDoI
         qfdQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=nMVB8I60;
       spf=pass (google.com: domain of 3uccexwokceyivlzmgsvdtowwotm.kwusiaiv-lmdowwotmozwcxa.kwu@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=3UcCEXwoKCeYIVLZMgSVdTOWWOTM.KWUSIaIV-LMdOWWOTMOZWcXa.KWU@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x74a.google.com (mail-qk1-x74a.google.com. [2607:f8b0:4864:20::74a])
        by gmr-mx.google.com with ESMTPS id t15si1427891pjq.1.2020.10.12.13.45.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 12 Oct 2020 13:45:05 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3uccexwokceyivlzmgsvdtowwotm.kwusiaiv-lmdowwotmozwcxa.kwu@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) client-ip=2607:f8b0:4864:20::74a;
Received: by mail-qk1-x74a.google.com with SMTP id d124so8404218qke.4
        for <kasan-dev@googlegroups.com>; Mon, 12 Oct 2020 13:45:05 -0700 (PDT)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:ad4:5843:: with SMTP id
 de3mr27589724qvb.12.1602535505094; Mon, 12 Oct 2020 13:45:05 -0700 (PDT)
Date: Mon, 12 Oct 2020 22:44:11 +0200
In-Reply-To: <cover.1602535397.git.andreyknvl@google.com>
Message-Id: <141704aae603604fcc8dec56d57265777d600c21.1602535397.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1602535397.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.28.0.1011.ga647a8990f-goog
Subject: [PATCH v5 05/40] arm64: mte: Add in-kernel tag fault handler
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>
Cc: Vincenzo Frascino <vincenzo.frascino@arm.com>, kasan-dev@googlegroups.com, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Elena Petrova <lenaptr@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=nMVB8I60;       spf=pass
 (google.com: domain of 3uccexwokceyivlzmgsvdtowwotm.kwusiaiv-lmdowwotmozwcxa.kwu@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=3UcCEXwoKCeYIVLZMgSVdTOWWOTM.KWUSIaIV-LMdOWWOTMOZWcXa.KWU@flex--andreyknvl.bounces.google.com;
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
 arch/arm64/include/asm/uaccess.h | 23 +++++++++++++++++++
 arch/arm64/mm/fault.c            | 38 +++++++++++++++++++++++++++++++-
 2 files changed, 60 insertions(+), 1 deletion(-)

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
index a3bd189602df..d110f382dacf 100644
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
@@ -294,6 +295,11 @@ static void die_kernel_fault(const char *msg, unsigned long addr,
 	do_exit(SIGKILL);
 }
 
+static void report_tag_fault(unsigned long addr, unsigned int esr,
+			     struct pt_regs *regs)
+{
+}
+
 static void __do_kernel_fault(unsigned long addr, unsigned int esr,
 			      struct pt_regs *regs)
 {
@@ -641,10 +647,40 @@ static int do_sea(unsigned long addr, unsigned int esr, struct pt_regs *regs)
 	return 0;
 }
 
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
+
 static int do_tag_check_fault(unsigned long addr, unsigned int esr,
 			      struct pt_regs *regs)
 {
-	do_bad_area(addr, esr, regs);
+	/*
+	 * The tag check fault (TCF) is per EL, hence TCF0 affects
+	 * EL0 and TCF affects EL1.
+	 * TTBR0 address belong by convention to EL0 hence to correctly
+	 * discriminate we use the is_ttbr0_addr() macro.
+	 */
+	if (is_ttbr0_addr(addr))
+		do_bad_area(addr, esr, regs);
+	else
+		do_tag_recovery(addr, esr, regs);
+
 	return 0;
 }
 
-- 
2.28.0.1011.ga647a8990f-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/141704aae603604fcc8dec56d57265777d600c21.1602535397.git.andreyknvl%40google.com.
