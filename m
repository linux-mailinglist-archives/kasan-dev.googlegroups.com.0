Return-Path: <kasan-dev+bncBD52JJ7JXILRBFF76CMAMGQEZYHUTAI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3f.google.com (mail-io1-xd3f.google.com [IPv6:2607:f8b0:4864:20::d3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 0CD735B443A
	for <lists+kasan-dev@lfdr.de>; Sat, 10 Sep 2022 07:24:38 +0200 (CEST)
Received: by mail-io1-xd3f.google.com with SMTP id i14-20020a5d934e000000b006892db5bcd4sf2761521ioo.22
        for <lists+kasan-dev@lfdr.de>; Fri, 09 Sep 2022 22:24:37 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1662787476; cv=pass;
        d=google.com; s=arc-20160816;
        b=ltcngyQ6z5U1poGWuwUU1oOjjByklnmDHk8TRsfw/E99QXW8yeIzQk0Bqq6HafZiBF
         vWr7h8qEXwUla9KFc2EoLPIFcwqxaR2FQLxw3DoMQqMgj5mLgE8WeBqgaGqiHTEqnE/j
         srq4m7LFPYD3GtdcoR2zrmNX2AD/tjbn/jEqp3UjXN05gY6JdoufKn8F5UBj+enActI0
         ntYo4uAELFrH1PDhk4+R3Q2u11ahIr8qF7p4BaoJywxPP361XjcPVBM69kCB2au4kT/v
         3Qosb/3Mnw3mXWrPEpoGniKfNBPwR7SJJdWx6fYygTNvjrjYmK8BroyxW+yK6n9EwjGv
         sGDA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=MzLkBICzzqBsyJRE15DJ/E+oQYqX0jckKHL3bltufEw=;
        b=fsY3qT8niIX6aQQ0qFc/2mxtH/5TP2v3KAYcHBBsC38Xr8+cHs0sRfdEng7kfPaUtp
         8Ni34Le9OfGtzOmTWO2zlRDJZMaLvEAhBdcIkmbrq0DA4hpwqK9QOeE5BIaYQPzgmNRO
         iKaqpcwH/I0TP1y+FObiWhlelOd+xEOf9rX8XO+m8RJeJelzrU3QCMR27XYPMbKk8ZFW
         WBTJAOTouHryi8+mHQnalGkXfEQ8fx6dUqCVKfNrJMQ6cSWQutp/HGvBv5dPTMGX17q6
         4ERBAxmGJH71c5OlDCnMgI1NVXC6183IIfjtuPSKMEznQO7XamHnLohqrIEvXqygmS5/
         ECiw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=Ig0ItrD1;
       spf=pass (google.com: domain of 3kx8cywmkcwipccgoogle.comkasan-devgooglegroups.com@flex--pcc.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3kx8cYwMKCWIPCCGOOGLE.COMKASAN-DEVGOOGLEGROUPS.COM@flex--pcc.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:mime-version:message-id:date:from:to:cc:subject:date;
        bh=MzLkBICzzqBsyJRE15DJ/E+oQYqX0jckKHL3bltufEw=;
        b=XWTdMtcEAlQOpUbaaYiCXAsJTpx7752umA7raj/YIDK1dFE0GbK6TSVtwos60DUYlx
         xbMExqY/zAckjgsy2aa+2FHS3FVHNPbryQ6pZzmWUFXMsHp3ynT0JVRMjGuZzb589amt
         1x17ZCXE48CpwrcrqGKkRpqOVUp82Wl7zfhvI37H9DL4fuc3D56f4CGTQJ+waIOcnXCa
         fNLAzd44sASy5OAWc3Xrhfbfw3jc0Wx5Orlf46Y7RMmgwkGbZaZ1EPNGWO9VZzGpoMch
         j5UVyaCt1VGA/4i31xvXbePdwHX8zRlMvolWlKCb5sa3hswoXy7C1bNMrfcSLxk5zRYw
         Dv9w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:mime-version:message-id:date:x-gm-message-state:from:to:cc
         :subject:date;
        bh=MzLkBICzzqBsyJRE15DJ/E+oQYqX0jckKHL3bltufEw=;
        b=sdbBtH/zaLa15BpvqCRKqtS5dCWF9R4a8SSLF53VcJ9WHQ1jjYkhByRt9RJnq8/Dzt
         TI1vKpxaKJ1fNZwTVAHzvpaksUFFtZ5NOus01kNW4bO/Sb5VipgVhlH6StO8r6H4+x7o
         TVrJXwhj04Ub1l/mxLJbxGR75qRUcR028SvsI1XqXWylC/vv+UnUhMAOGdMgPoW37c69
         aRahm0iaH5jnSnkKGGHfqVGPA65OvmAtZiNgJRHCvN1zTZLDo1BIiYLgnpOG+KyvvR1O
         ULBGnQGrs1VqrO27sjVrsCFHbb+g96aBiILEkLdsDtMvpVjmuJJmSZVU3iKGppF/y5Z3
         0XUg==
X-Gm-Message-State: ACgBeo36u2qELxg8mr8DPB9rEaVQrWIdXg3Vw84BRGOtPx6ErfCbwnMj
	oAHqdg+A+Cf37TfbkjLHuBU=
X-Google-Smtp-Source: AA6agR5d7pUlVc99dufmkMgRBvdSnJrHw9jly67R4RCT52rbx/APnrRa+7RS7Pntglz8ZbSR93DL5g==
X-Received: by 2002:a05:6e02:2181:b0:2eb:3770:e3f8 with SMTP id j1-20020a056e02218100b002eb3770e3f8mr6078276ila.79.1662787476544;
        Fri, 09 Sep 2022 22:24:36 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:c7c1:0:b0:2ea:c965:4426 with SMTP id g1-20020a92c7c1000000b002eac9654426ls1689340ilk.1.-pod-prod-gmail;
 Fri, 09 Sep 2022 22:24:36 -0700 (PDT)
X-Received: by 2002:a92:ca91:0:b0:2eb:708:579a with SMTP id t17-20020a92ca91000000b002eb0708579amr5579127ilo.193.1662787476113;
        Fri, 09 Sep 2022 22:24:36 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1662787476; cv=none;
        d=google.com; s=arc-20160816;
        b=MVWOw7IHmdP/MOyBVL0qgvKNy6zZz+qb1ufDw/GoP/pk8l/vjieGaWYlcdWiHE8pMu
         06nTXxmdiivlShbLzhFfwMpEKLE7QjKOwUQyLLVQwxdT4mS2cem917kgtxtlYQkO1IVQ
         aZBInbYnfVKxruVHtluyNXbk7wfqO7X9WofXIEqqtoOsYDmjR8HBKDoWfjqNuPDmftLO
         nDANN0v9U6fAYXM36tPGAb0CFO4NDBjfDAawEutRGlWfuIwIShKNveAXU/zEd4NqjQbA
         4jZRvPXNKF3c2FGjTKqvJwx7ShVRWi+PIXnFzE+4mntVJqzBkQ1tJXbSxb9UkeW/SuGx
         tccQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=JqNTfVNEPEGXKtb8DKwwJsm47BWKuJspxKDX7cLnwDc=;
        b=FWJCtxJ0iNOTeLQnVXgzW/oDph2duP7+XwSUdqzTRcPvs8R9KaLCy+LtChorpjxtra
         HiQWmywrICjFtTQaICyDZU+pzQt6SHoRhn7Kz1iE4l9BEWcpkuXYJYTbu/0QOccD8xix
         TF8hFIvUHN3o3b22eP9b8FTV2/B8QhVtHkuM9VqpyD5o0D16s/bMj/TzwAgIe5GKcu0d
         V3zRJHOwz18HvJ2SBtjXhFFs6K1YGSluw/VQM6YLAwH+9EvR4LBwn52NwsDhbGY069fo
         s1D4J3+Wiv2/RtHVLQycsLAzpKj/y6989/s59JHBDQRVxpfTejEJGdhndZBlgb/H5RiT
         XDWg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=Ig0ItrD1;
       spf=pass (google.com: domain of 3kx8cywmkcwipccgoogle.comkasan-devgooglegroups.com@flex--pcc.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3kx8cYwMKCWIPCCGOOGLE.COMKASAN-DEVGOOGLEGROUPS.COM@flex--pcc.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb4a.google.com (mail-yb1-xb4a.google.com. [2607:f8b0:4864:20::b4a])
        by gmr-mx.google.com with ESMTPS id n21-20020a02cc15000000b00349dba16b8dsi64986jap.6.2022.09.09.22.24.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 09 Sep 2022 22:24:36 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3kx8cywmkcwipccgoogle.comkasan-devgooglegroups.com@flex--pcc.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) client-ip=2607:f8b0:4864:20::b4a;
Received: by mail-yb1-xb4a.google.com with SMTP id l12-20020a25ad4c000000b006a8e04c284dso3317743ybe.11
        for <kasan-dev@googlegroups.com>; Fri, 09 Sep 2022 22:24:36 -0700 (PDT)
X-Received: from pcc-desktop.svl.corp.google.com ([2620:15c:2ce:200:853c:a4e2:939a:fb56])
 (user=pcc job=sendgmr) by 2002:a25:bb82:0:b0:696:4351:8f5f with SMTP id
 y2-20020a25bb82000000b0069643518f5fmr14192400ybg.90.1662787475684; Fri, 09
 Sep 2022 22:24:35 -0700 (PDT)
Date: Fri,  9 Sep 2022 22:24:26 -0700
Message-Id: <20220910052426.943376-1-pcc@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.37.2.789.g6183377224-goog
Subject: [PATCH] kasan: also display registers for reports from HW exceptions
From: "'Peter Collingbourne' via kasan-dev" <kasan-dev@googlegroups.com>
To: Catalin Marinas <catalin.marinas@arm.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Andrey Konovalov <andreyknvl@gmail.com>
Cc: Peter Collingbourne <pcc@google.com>, linux-arm-kernel@lists.infradead.org, 
	kasan-dev@googlegroups.com, linux-mm@kvack.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: pcc@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=Ig0ItrD1;       spf=pass
 (google.com: domain of 3kx8cywmkcwipccgoogle.comkasan-devgooglegroups.com@flex--pcc.bounces.google.com
 designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3kx8cYwMKCWIPCCGOOGLE.COMKASAN-DEVGOOGLEGROUPS.COM@flex--pcc.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Peter Collingbourne <pcc@google.com>
Reply-To: Peter Collingbourne <pcc@google.com>
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

It is sometimes useful to know the values of the registers when a KASAN
report is generated. We can do this easily for reports that resulted from
a hardware exception by passing the struct pt_regs from the exception into
the report function; do so.

Signed-off-by: Peter Collingbourne <pcc@google.com>
---
Applies to -next.

 arch/arm64/kernel/traps.c |  3 +--
 arch/arm64/mm/fault.c     |  2 +-
 include/linux/kasan.h     | 10 ++++++++++
 mm/kasan/kasan.h          |  1 +
 mm/kasan/report.c         | 27 ++++++++++++++++++++++-----
 5 files changed, 35 insertions(+), 8 deletions(-)

diff --git a/arch/arm64/kernel/traps.c b/arch/arm64/kernel/traps.c
index b7fed33981f7..42f05f38c90a 100644
--- a/arch/arm64/kernel/traps.c
+++ b/arch/arm64/kernel/traps.c
@@ -1019,9 +1019,8 @@ static int kasan_handler(struct pt_regs *regs, unsigned long esr)
 	bool write = esr & KASAN_ESR_WRITE;
 	size_t size = KASAN_ESR_SIZE(esr);
 	u64 addr = regs->regs[0];
-	u64 pc = regs->pc;
 
-	kasan_report(addr, size, write, pc);
+	kasan_report_regs(addr, size, write, regs);
 
 	/*
 	 * The instrumentation allows to control whether we can proceed after
diff --git a/arch/arm64/mm/fault.c b/arch/arm64/mm/fault.c
index 5b391490e045..c4b91f5d8cc8 100644
--- a/arch/arm64/mm/fault.c
+++ b/arch/arm64/mm/fault.c
@@ -316,7 +316,7 @@ static void report_tag_fault(unsigned long addr, unsigned long esr,
 	 * find out access size.
 	 */
 	bool is_write = !!(esr & ESR_ELx_WNR);
-	kasan_report(addr, 0, is_write, regs->pc);
+	kasan_report_regs(addr, 0, is_write, regs);
 }
 #else
 /* Tag faults aren't enabled without CONFIG_KASAN_HW_TAGS. */
diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index d811b3d7d2a1..381aea149353 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -353,6 +353,16 @@ static inline void *kasan_reset_tag(const void *addr)
 bool kasan_report(unsigned long addr, size_t size,
 		bool is_write, unsigned long ip);
 
+/**
+ * kasan_report_regs - print a report about a bad memory access detected by KASAN
+ * @addr: address of the bad access
+ * @size: size of the bad access
+ * @is_write: whether the bad access is a write or a read
+ * @regs: register values at the point of the bad memory access
+ */
+bool kasan_report_regs(unsigned long addr, size_t size, bool is_write,
+		       struct pt_regs *regs);
+
 #else /* CONFIG_KASAN_SW_TAGS || CONFIG_KASAN_HW_TAGS */
 
 static inline void *kasan_reset_tag(const void *addr)
diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index abbcc1b0eec5..39772c21a8ae 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -175,6 +175,7 @@ struct kasan_report_info {
 	size_t access_size;
 	bool is_write;
 	unsigned long ip;
+	struct pt_regs *regs;
 
 	/* Filled in by the common reporting code. */
 	void *first_bad_addr;
diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index 39e8e5a80b82..eac9cd45b4a1 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -24,6 +24,7 @@
 #include <linux/types.h>
 #include <linux/kasan.h>
 #include <linux/module.h>
+#include <linux/sched/debug.h>
 #include <linux/sched/task_stack.h>
 #include <linux/uaccess.h>
 #include <trace/events/error_report.h>
@@ -284,7 +285,6 @@ static void print_address_description(void *addr, u8 tag,
 {
 	struct page *page = addr_to_page(addr);
 
-	dump_stack_lvl(KERN_ERR);
 	pr_err("\n");
 
 	if (info->cache && info->object) {
@@ -394,11 +394,14 @@ static void print_report(struct kasan_report_info *info)
 		kasan_print_tags(tag, info->first_bad_addr);
 	pr_err("\n");
 
+	if (info->regs)
+		show_regs(info->regs);
+	else
+		dump_stack_lvl(KERN_ERR);
+
 	if (addr_has_metadata(addr)) {
 		print_address_description(addr, tag, info);
 		print_memory_metadata(info->first_bad_addr);
-	} else {
-		dump_stack_lvl(KERN_ERR);
 	}
 }
 
@@ -458,8 +461,8 @@ void kasan_report_invalid_free(void *ptr, unsigned long ip, enum kasan_report_ty
  * user_access_save/restore(): kasan_report_invalid_free() cannot be called
  * from a UACCESS region, and kasan_report_async() is not used on x86.
  */
-bool kasan_report(unsigned long addr, size_t size, bool is_write,
-			unsigned long ip)
+static bool __kasan_report(unsigned long addr, size_t size, bool is_write,
+			unsigned long ip, struct pt_regs *regs)
 {
 	bool ret = true;
 	void *ptr = (void *)addr;
@@ -480,6 +483,7 @@ bool kasan_report(unsigned long addr, size_t size, bool is_write,
 	info.access_size = size;
 	info.is_write = is_write;
 	info.ip = ip;
+	info.regs = regs;
 
 	complete_report_info(&info);
 
@@ -493,6 +497,19 @@ bool kasan_report(unsigned long addr, size_t size, bool is_write,
 	return ret;
 }
 
+bool kasan_report(unsigned long addr, size_t size, bool is_write,
+			unsigned long ip)
+{
+	return __kasan_report(addr, size, is_write, ip, NULL);
+}
+
+bool kasan_report_regs(unsigned long addr, size_t size, bool is_write,
+		       struct pt_regs *regs)
+{
+	return __kasan_report(addr, size, is_write, instruction_pointer(regs),
+			      regs);
+}
+
 #ifdef CONFIG_KASAN_HW_TAGS
 void kasan_report_async(void)
 {
-- 
2.37.2.789.g6183377224-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220910052426.943376-1-pcc%40google.com.
