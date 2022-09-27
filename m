Return-Path: <kasan-dev+bncBD52JJ7JXILRB6E7ZGMQMGQE5G3JDOI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x93d.google.com (mail-ua1-x93d.google.com [IPv6:2607:f8b0:4864:20::93d])
	by mail.lfdr.de (Postfix) with ESMTPS id 4CB325EB6C1
	for <lists+kasan-dev@lfdr.de>; Tue, 27 Sep 2022 03:20:58 +0200 (CEST)
Received: by mail-ua1-x93d.google.com with SMTP id h11-20020ab0470b000000b003bf1da44886sf1988036uac.17
        for <lists+kasan-dev@lfdr.de>; Mon, 26 Sep 2022 18:20:58 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1664241657; cv=pass;
        d=google.com; s=arc-20160816;
        b=LG3Lg19WXwXTCA73RdTisdHR5ft+MboLUhqvemWZxURh9n3iuwZ6KM28IiKekM4//r
         UxtAfbIDLVR/UCX0n5qBctJ4/DgZNH+yIJmMzMZzMmpnVR7WlObB9AAhNEh9g6y08M5k
         XErU40EkncVj5ykyBiQQE+leuZyVc6tOh1FYL++dhxdzA5AIFA7SxQ+dW+klPoQhblrU
         K7CWgafvVWXS2TKwT+46RFqTmFMjxfiFBPuxGp2YOA/xVgCG2ZBPL1I0Y6MKfJqkxnfW
         MAzRJ/1WCZLCLVHenNpH6aT52ArBpGYdxs/DButjSUBzGBh1WHgvVsE18jpYEiYajao3
         GILQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=YHTxXnHTrw7VUx2KC213D8SV07+RfjSyAmo0oW183Cg=;
        b=qQTpYsM4Q2EusJInkY+4saEyJ6abg8Qg0et8c4pvBOUwv1z7tInMgZX0LynElN8kGf
         P/yHMKZcY31SuPEF7+1xoJz5D1yX4VHqRTZo4LEa3htfOfYSFMNkekZolqlG3y+MRo6C
         5J+DiMawuSmSNZ66zso9IXk9UeBlZNtAvsUh/cBj+tffM+GhPujiVPC08yFURExvRBa3
         6zvGcMhK4aAFmsSXitYfXJgrPw1zJN8FHh9f2LDRJ2GM5tAu8a5vl2CNSYZSjKa4Kfgp
         IGkLgpRKJ3KquJ+VcdIBrvwjbApy634dO2kv7hp7B3P/guLLEHUvfLGdG3zoKI3h6FwI
         q9aw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=tjlHQm36;
       spf=pass (google.com: domain of 3908yywmkcyatggksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--pcc.bounces.google.com designates 2607:f8b0:4864:20::649 as permitted sender) smtp.mailfrom=3908yYwMKCYAtggksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--pcc.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:mime-version:message-id:date:from:to:cc:subject:date;
        bh=YHTxXnHTrw7VUx2KC213D8SV07+RfjSyAmo0oW183Cg=;
        b=SPHWifR+l5aWN6yENM+CXjeoSCJOK6WoqS4LRMZSPS1Ql5r4cYlyreyL3RSAGETyCP
         PNyRe+ZoWpq9TwNoIiu6hHMOoJ78c106g092Txw0vmI2RzNv1o4V6J5bjcjaMT/V+8ON
         0c9qe22hTTXWX8cH4CsnM7vgoKnyXbloLKKB1EVkVEXDQhCAl49uJDv86jlKRVfcAKA2
         Og1NZk8Xs+a+teTTSLuNCDiq80N1m0Cm9b2ZbFAbzLO8DVvgLChaidgaz52kX6My084n
         5Dl6ZzV8J9oCfS/cKXuFCykcMLAOlVvsddjIpaa4+ccfYyDoxCsupk6hl8b+0qO5d5sb
         YiBQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:mime-version:message-id:date:x-gm-message-state:from:to:cc
         :subject:date;
        bh=YHTxXnHTrw7VUx2KC213D8SV07+RfjSyAmo0oW183Cg=;
        b=DR/poXLDMPB/ISm3VWWm/ZtkvkSoEVBdTUlhtkVmhoiKsd/vg7yHvPOkP1CZpxTG/b
         Evp5SfGmV6/khWdAq5D3xJhTK1tH35h/iBKruvPor72ZQ4fO2uIC7ssDE57J7a0UWWrJ
         I7NT9Zu19fxgRCht+bSm/eSI45hXVNw5/ltC3Ief6jIcqOMQ/VSzLtwBOnUNFfz16zzw
         chgFg9tEzpoGtYOEl1Xok2pugcU3k66zBOAG91fiH6GvU8cxWQTt057b7P95QxwJq+bU
         X0lYTAqEEu7TugXwDAdvXp4R1i3n8rj/TvrQsAt61Zay/mjQQR8NA728zJYVhQtUrdSD
         nR4Q==
X-Gm-Message-State: ACrzQf2zeggYRqiYGI/g0iTcYLCJGou124jEEDpK3ZJbu5ot11gx9ZKO
	H/smwTsYOgwpnQMD7kJi0yo=
X-Google-Smtp-Source: AMsMyM4JbGfzoLNWuqo+Rj0BJyOXiSj9fldaqIN+ao9eP6zHGAQ7tPsmXzsitZbk2UcPo9zlfb+oig==
X-Received: by 2002:a05:6102:2826:b0:39b:d63:87bb with SMTP id ba6-20020a056102282600b0039b0d6387bbmr9718535vsb.62.1664241656987;
        Mon, 26 Sep 2022 18:20:56 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9f:3231:0:b0:3ae:855a:9a7f with SMTP id x46-20020a9f3231000000b003ae855a9a7fls84761uad.0.-pod-prod-gmail;
 Mon, 26 Sep 2022 18:20:56 -0700 (PDT)
X-Received: by 2002:ab0:4a54:0:b0:3bf:296c:970d with SMTP id r20-20020ab04a54000000b003bf296c970dmr10362712uae.48.1664241656446;
        Mon, 26 Sep 2022 18:20:56 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1664241656; cv=none;
        d=google.com; s=arc-20160816;
        b=vB6LNO74dxfM2j0gCq6hRZbSKN3KyulpaadjE4yYybhtt4rY9/O449HTwVk+kQRqNM
         2MHiySNl5/nzXv2eKx9pufvns3kr7je2NXh7GFQKhAlrJxW9TN4SF88toX/Ln2iQGrPm
         rCA4hexo4ImgfpdiEbRNGJ4JsHDxgxdrUDSpbBoHtot9dkhO8JCsD0xg/CoBHf4R49uC
         yWU+QpWyJOxklRzyYXhuebDjb8tDYyI26ph/Znrvi/sCqCaRrlF+xDDP8tvlZ7Ir2MMH
         NZxz3JUaediy/owhnbj/zhI1URNULzrP6f9KiZ86gomvRxdo8QCkuG6/FNDjHfzoRnPb
         X0QA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=HOCMPjoy0eVPzOqsFhY6VeQ9OoDjjjrEl2+DddMJ/3E=;
        b=FM9TSQGfBdsAwbez7oduPERZUdts5CXFEtHr5lq3kCAAhgPa0QdFQk4NVxmDSH4kMu
         VCHCYb6WXlg0oWw3lp6dSd9GKUkZCLJvi9GWoLEjXOmVTNp4MrwZ9V+NWpw7VxviuKR1
         XlkRSGcb4LmVAvzRtXUgT+TNXfB7UXh8IAuFBymomMidlFJIXX6g8hdaqvSaW7o0piev
         Tb3cL0VgWcBB16NSs36hd8Upm7PkfzaqtirXR2IeTZ3dUmd6y0htCnucN9CQDvZr4lxW
         HAxWTqnwmA430dJtA3wgrivHQFkpkc4Bg1SsR40GWe1V4PryQqola3pmhBIU1UPAGT+7
         kneQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=tjlHQm36;
       spf=pass (google.com: domain of 3908yywmkcyatggksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--pcc.bounces.google.com designates 2607:f8b0:4864:20::649 as permitted sender) smtp.mailfrom=3908yYwMKCYAtggksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--pcc.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pl1-x649.google.com (mail-pl1-x649.google.com. [2607:f8b0:4864:20::649])
        by gmr-mx.google.com with ESMTPS id w140-20020a1f9492000000b003760f8bf2a0si6319vkd.2.2022.09.26.18.20.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 26 Sep 2022 18:20:56 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3908yywmkcyatggksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--pcc.bounces.google.com designates 2607:f8b0:4864:20::649 as permitted sender) client-ip=2607:f8b0:4864:20::649;
Received: by mail-pl1-x649.google.com with SMTP id u5-20020a170902e80500b00178944c46aaso5389433plg.4
        for <kasan-dev@googlegroups.com>; Mon, 26 Sep 2022 18:20:56 -0700 (PDT)
X-Received: from pcc-desktop.svl.corp.google.com ([2620:15c:2ce:200:feb1:62f4:7ee4:fd92])
 (user=pcc job=sendgmr) by 2002:a05:6a00:1688:b0:53b:4239:7c5c with SMTP id
 k8-20020a056a00168800b0053b42397c5cmr27123207pfc.81.1664241655587; Mon, 26
 Sep 2022 18:20:55 -0700 (PDT)
Date: Mon, 26 Sep 2022 18:20:44 -0700
Message-Id: <20220927012044.2794384-1-pcc@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.37.3.998.g577e59143f-goog
Subject: [PATCH v2] kasan: also display registers for reports from HW exceptions
From: "'Peter Collingbourne' via kasan-dev" <kasan-dev@googlegroups.com>
To: Catalin Marinas <catalin.marinas@arm.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Andrey Konovalov <andreyknvl@gmail.com>
Cc: Peter Collingbourne <pcc@google.com>, linux-arm-kernel@lists.infradead.org, 
	kasan-dev@googlegroups.com, linux-mm@kvack.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: pcc@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=tjlHQm36;       spf=pass
 (google.com: domain of 3908yywmkcyatggksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--pcc.bounces.google.com
 designates 2607:f8b0:4864:20::649 as permitted sender) smtp.mailfrom=3908yYwMKCYAtggksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--pcc.bounces.google.com;
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
the report function; do so, but only in HW tags mode because registers
may have been corrupted during the check in other modes.

Signed-off-by: Peter Collingbourne <pcc@google.com>
---
Applies to -next.

v2:
- only do this in HW tags mode
- move pr_err to caller

 arch/arm64/mm/fault.c |  2 +-
 include/linux/kasan.h | 10 ++++++++++
 mm/kasan/kasan.h      |  1 +
 mm/kasan/report.c     | 30 +++++++++++++++++++++++-------
 4 files changed, 35 insertions(+), 8 deletions(-)

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
index df3602062bfd..be8dd97940c7 100644
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
@@ -281,9 +282,6 @@ static void print_address_description(void *addr, u8 tag,
 {
 	struct page *page = addr_to_page(addr);
 
-	dump_stack_lvl(KERN_ERR);
-	pr_err("\n");
-
 	if (info->cache && info->object) {
 		describe_object(addr, info);
 		pr_err("\n");
@@ -391,11 +389,15 @@ static void print_report(struct kasan_report_info *info)
 		kasan_print_tags(tag, info->first_bad_addr);
 	pr_err("\n");
 
+	if (info->regs)
+		show_regs(info->regs);
+	else
+		dump_stack_lvl(KERN_ERR);
+
 	if (addr_has_metadata(addr)) {
+		pr_err("\n");
 		print_address_description(addr, tag, info);
 		print_memory_metadata(info->first_bad_addr);
-	} else {
-		dump_stack_lvl(KERN_ERR);
 	}
 }
 
@@ -467,8 +469,8 @@ void kasan_report_invalid_free(void *ptr, unsigned long ip, enum kasan_report_ty
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
@@ -489,6 +491,7 @@ bool kasan_report(unsigned long addr, size_t size, bool is_write,
 	info.access_size = size;
 	info.is_write = is_write;
 	info.ip = ip;
+	info.regs = regs;
 
 	complete_report_info(&info);
 
@@ -502,6 +505,19 @@ bool kasan_report(unsigned long addr, size_t size, bool is_write,
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
2.37.3.998.g577e59143f-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220927012044.2794384-1-pcc%40google.com.
