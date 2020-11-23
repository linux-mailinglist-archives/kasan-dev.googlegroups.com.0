Return-Path: <kasan-dev+bncBDX4HWEMTEBRBFVO6D6QKGQEZECV2UQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53d.google.com (mail-ed1-x53d.google.com [IPv6:2a00:1450:4864:20::53d])
	by mail.lfdr.de (Postfix) with ESMTPS id CA24B2C1560
	for <lists+kasan-dev@lfdr.de>; Mon, 23 Nov 2020 21:09:58 +0100 (CET)
Received: by mail-ed1-x53d.google.com with SMTP id l12sf6982558edw.11
        for <lists+kasan-dev@lfdr.de>; Mon, 23 Nov 2020 12:09:58 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1606162198; cv=pass;
        d=google.com; s=arc-20160816;
        b=Atp1o/te1hIlQg8/PEoGahSA+CyKxfWfqJWzWQYRCP31w/ZSlDcUeyWnQ1CpGalrgP
         6HEzV4t56yU/lX4qAD31/tCL2zb6vh1XJXxf2j08hK8v7dg5vYgxxvZEPPYo+F6+5O4A
         ZbPaSVtDpsMKM93QA/JKzlcUx3YYC7qZHN0XoznM3uNoY4pvyvObUgE2WM2IeGi3+ZBG
         kfxqU4OZWyAFHuhE4WlhwwT05SZhc2x+gRqSthZJLO+amP0VcEyIUB0ZAzMQTuemO7M9
         4XK0pHafQw+kXESg9PEneM0bZeZkNP9uwvAkbyHYfkS8EQbEWPJupWfwO2OBh8uQycpF
         nikw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=Bxe6VioWn4ceuX7+x8ZQviTYW95LBhOsAtQJBNKUImM=;
        b=UuFLNQ++nS+xyDXiXwJNxPr5MYG9mjGQMQiz1TxgSLdrntv3urhlLGAaEy9p1QbNh0
         dxVC/78Y8sKUIR+N5iNUh61fYDPCRYxUjPp4T8t8eGsA/0DixnPTiWyQUVDssy8X6VPB
         LMyXhKg5BJgG63E1hKr1WvXZnNgQMzGK/8le1yx326oVP/lhsUYafC4/0wYI+69jetxr
         sbeYkQ4xDzMKlpkziwkV+ZTWFK1C2eh6YFlVV8DYlbTd3s6MbmdcihCGgPm/J+llBTO8
         96smJzPEvuAuauJ9NLEl8wzRUD0pWRq1lhgSGXj+gYGECAzq5k42hhupkTZYYAcvPzTP
         X7Xw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=neCUGBfU;
       spf=pass (google.com: domain of 3fre8xwokctguhxlysehpfaiiafy.wigeumuh-xypaiiafyaliojm.wig@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3FRe8XwoKCTgUhXlYsehpfaiiafY.WigeUmUh-XYpaiiafYaliojm.Wig@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=Bxe6VioWn4ceuX7+x8ZQviTYW95LBhOsAtQJBNKUImM=;
        b=S+uUTFzc4NBHiMcK1KPohl18KeaRew1DEaGr7RqItnwR9IwPTCBuab4o1neuNtTKYK
         vl1FNWMfEyAP2iEcGAf6Bbydv0Vfuaz1+9GBCQjNZg0Lk6ODfKz/5IvMWaeNrM+dIek0
         eJRyVQr+rRKx2DRLf4PtBjgghGsvaj6J/C1fwOkX+ZWSTunidg/cLa7nHX7dze7Cx2ln
         vbvdR54NgO/CBW/okT42f4rszaM0z5oxkgCnEnu+K9VtQLrUmVgBVeof+6/nLm2BIRCR
         pvJxPCtQ5WHzVKnElvpW1Dc8M+d0l77NqFwY30ZPigqIUfqjSohOzvB7dMsX/X1hsiKa
         d/NA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Bxe6VioWn4ceuX7+x8ZQviTYW95LBhOsAtQJBNKUImM=;
        b=X20nyXViq8kKxM1BzG9dgXDF+9xjf8DQvyOikIsCkk7k6uemwMjt2/qPknb4DJY+wi
         SwfAlqxxZ6pxUiSFxDL4BXEIDuHjk8zoK6P2t63deYlgC1pBa0FaPL/z9kyTcT719Wzm
         p0v9qSfxkV+VqXhKoEFswG1d9ctnDTDZuJw43UCTmp/VWYzGdupk+1RorlYC5+rSgl7n
         wdRozy8fr/Zwas4Sq922a2U6f21Q/23yweUj6FOEUS05imLETf/oTjU3JwfXtbK8guFA
         m8UtSoV8eDibFXsqvWs0KxTLnWOGypZX9foAhEiW/GCCdvhGXYZEeKrlSA+8TpzR3pWl
         dyOQ==
X-Gm-Message-State: AOAM530E60mMhxl2vywMlVIjI6uDEJ/h6zQf/Atqn4ubNSf9w4uBOh16
	Emot8CKoAVJYytnpyQtH04I=
X-Google-Smtp-Source: ABdhPJzOKq+PJsExdTp++YPrZGCT+xOj+hTxVnmCsCKmMSof2harar6wkeKQv592QHPnAOjrlTua7Q==
X-Received: by 2002:a50:a410:: with SMTP id u16mr889909edb.274.1606162198602;
        Mon, 23 Nov 2020 12:09:58 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a50:9f27:: with SMTP id b36ls9033618edf.1.gmail; Mon, 23 Nov
 2020 12:09:57 -0800 (PST)
X-Received: by 2002:a50:d5dd:: with SMTP id g29mr845839edj.379.1606162197751;
        Mon, 23 Nov 2020 12:09:57 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1606162197; cv=none;
        d=google.com; s=arc-20160816;
        b=LSUyCIzNKgVTYFFG9tKdHJbZl36UFXhZ3SFmX44OF58iGuv/y4lLjpQ9Sz6R0wPjlV
         z0IxWJa5cbyRpKWqC4/7yWcp4XfVLWBNwYFjkEb8f83lnH+jN3hQpLwQ7msmZm1bYCTL
         Hm2enCWYoYymD9YIL0k8onIpxJdAxbnReOnmCSyeeDGVQM7OmeYs1IZHZtfHrvIewa2B
         nZsxk2sVflIJIPa/kTE3wgTaYeFyLyabrsFy+27y3H3czdqdWaNanyjDuWGvGVVQWzq/
         z8qjVcMOkCrRYZhjmtQLbwajCnHIZb+VXFJuIf60Kd70v9cUy4J7D3B4koHi+5q9k86+
         rxKg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=a641qLXzuR11g6BMkmBPCphI45HnOtEuvC8VFs/i0oY=;
        b=LwZNbO0owY3H2E5rQSpx4H9kC3f2WCpjpSxf5mnTRJGUUg080+5G7JjC+0Mzh2xqEe
         SiCJvAE3oyEIw6jesMif7XyhYP66HSel+oXiXVifD/JQeSkDa959h8U0pIxSRMV1UD9F
         ybXW7oPqiT1gyb2PbEvEs16AJjNpitjoBdwTCWpD9QAQmM6gp8ADcWqqtVZYJo5D5swg
         y3eN5KKBKTevr8qMev/NpGyBevlOPs2gHs3GNW91b88rUZtFkJ2IDiLHDC6bXBfCKt3a
         R7S4VEHR/3lhg5e+n9ry5eaFL8yuZeEkNncE3CwiXM/hqIrTGqV6WmapxUYLFEPEhTf1
         QAOA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=neCUGBfU;
       spf=pass (google.com: domain of 3fre8xwokctguhxlysehpfaiiafy.wigeumuh-xypaiiafyaliojm.wig@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3FRe8XwoKCTgUhXlYsehpfaiiafY.WigeUmUh-XYpaiiafYaliojm.Wig@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x34a.google.com (mail-wm1-x34a.google.com. [2a00:1450:4864:20::34a])
        by gmr-mx.google.com with ESMTPS id w7si425063edl.3.2020.11.23.12.09.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 23 Nov 2020 12:09:57 -0800 (PST)
Received-SPF: pass (google.com: domain of 3fre8xwokctguhxlysehpfaiiafy.wigeumuh-xypaiiafyaliojm.wig@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) client-ip=2a00:1450:4864:20::34a;
Received: by mail-wm1-x34a.google.com with SMTP id u123so103048wmu.5
        for <kasan-dev@googlegroups.com>; Mon, 23 Nov 2020 12:09:57 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a1c:bd0b:: with SMTP id
 n11mr580484wmf.111.1606162197472; Mon, 23 Nov 2020 12:09:57 -0800 (PST)
Date: Mon, 23 Nov 2020 21:08:02 +0100
In-Reply-To: <cover.1606161801.git.andreyknvl@google.com>
Message-Id: <b559c82b6a969afedf53b4694b475f0234067a1a.1606161801.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1606161801.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.2.454.gaff20da3a2-goog
Subject: [PATCH mm v11 38/42] kasan, arm64: print report from tag fault handler
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
 header.i=@google.com header.s=20161025 header.b=neCUGBfU;       spf=pass
 (google.com: domain of 3fre8xwokctguhxlysehpfaiiafy.wigeumuh-xypaiiafyaliojm.wig@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3FRe8XwoKCTgUhXlYsehpfaiiafY.WigeUmUh-XYpaiiafYaliojm.Wig@flex--andreyknvl.bounces.google.com;
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

Add error reporting for hardware tag-based KASAN. When CONFIG_KASAN_HW_TAGS
is enabled, print KASAN report from the arm64 tag fault handler.

SAS bits aren't set in ESR for all faults reported in EL1, so it's
impossible to find out the size of the access the caused the fault.
Adapt KASAN reporting code to handle this case.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Co-developed-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
Reviewed-by: Catalin Marinas <catalin.marinas@arm.com>
Reviewed-by: Alexander Potapenko <glider@google.com>
---
Change-Id: I3780fe7db6e075dff2937d3d8508f55c9322b095
---
 arch/arm64/mm/fault.c | 14 ++++++++++++++
 mm/kasan/report.c     | 11 ++++++++---
 2 files changed, 22 insertions(+), 3 deletions(-)

diff --git a/arch/arm64/mm/fault.c b/arch/arm64/mm/fault.c
index 1e4b9353c68a..3aac2e72f81e 100644
--- a/arch/arm64/mm/fault.c
+++ b/arch/arm64/mm/fault.c
@@ -15,6 +15,7 @@
 #include <linux/mm.h>
 #include <linux/hardirq.h>
 #include <linux/init.h>
+#include <linux/kasan.h>
 #include <linux/kprobes.h>
 #include <linux/uaccess.h>
 #include <linux/page-flags.h>
@@ -298,10 +299,23 @@ static void die_kernel_fault(const char *msg, unsigned long addr,
 	do_exit(SIGKILL);
 }
 
+#ifdef CONFIG_KASAN_HW_TAGS
 static void report_tag_fault(unsigned long addr, unsigned int esr,
 			     struct pt_regs *regs)
 {
+	bool is_write  = ((esr & ESR_ELx_WNR) >> ESR_ELx_WNR_SHIFT) != 0;
+
+	/*
+	 * SAS bits aren't set for all faults reported in EL1, so we can't
+	 * find out access size.
+	 */
+	kasan_report(addr, 0, is_write, regs->pc);
 }
+#else
+/* Tag faults aren't enabled without CONFIG_KASAN_HW_TAGS. */
+static inline void report_tag_fault(unsigned long addr, unsigned int esr,
+				    struct pt_regs *regs) { }
+#endif
 
 static void do_tag_recovery(unsigned long addr, unsigned int esr,
 			   struct pt_regs *regs)
diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index 2c503b667413..a69c2827a125 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -62,9 +62,14 @@ static void print_error_description(struct kasan_access_info *info)
 {
 	pr_err("BUG: KASAN: %s in %pS\n",
 		get_bug_type(info), (void *)info->ip);
-	pr_err("%s of size %zu at addr %px by task %s/%d\n",
-		info->is_write ? "Write" : "Read", info->access_size,
-		info->access_addr, current->comm, task_pid_nr(current));
+	if (info->access_size)
+		pr_err("%s of size %zu at addr %px by task %s/%d\n",
+			info->is_write ? "Write" : "Read", info->access_size,
+			info->access_addr, current->comm, task_pid_nr(current));
+	else
+		pr_err("%s at addr %px by task %s/%d\n",
+			info->is_write ? "Write" : "Read",
+			info->access_addr, current->comm, task_pid_nr(current));
 }
 
 static DEFINE_SPINLOCK(report_lock);
-- 
2.29.2.454.gaff20da3a2-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/b559c82b6a969afedf53b4694b475f0234067a1a.1606161801.git.andreyknvl%40google.com.
