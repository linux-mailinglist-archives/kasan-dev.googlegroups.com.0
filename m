Return-Path: <kasan-dev+bncBDX4HWEMTEBRBG4BSP6AKGQEYHFWZMI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3b.google.com (mail-qv1-xf3b.google.com [IPv6:2607:f8b0:4864:20::f3b])
	by mail.lfdr.de (Postfix) with ESMTPS id AF59028C316
	for <lists+kasan-dev@lfdr.de>; Mon, 12 Oct 2020 22:46:20 +0200 (CEST)
Received: by mail-qv1-xf3b.google.com with SMTP id y45sf11521726qve.15
        for <lists+kasan-dev@lfdr.de>; Mon, 12 Oct 2020 13:46:20 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1602535579; cv=pass;
        d=google.com; s=arc-20160816;
        b=vBzcssQjgBhFDPDWd14AjwwLemHnLeuPY+DddlK3JhmA1WHVzSa8DVtV5XbjmNQSnR
         1bGBYS0lUKGtuWRvfUCfjnGT1JjbYKvat8ztDUje3y0PLiw8ogU83iVO9lIY8GaQrTnK
         SLgg2I+JveQ5qJtekQEWG0gej6IGTaaicDPtxlxJVKGg0ri3wMO/awQ5Gb8jph0q7gNd
         vzIPjunjUTR4amrdr0G3t8SsW2twpicWFmdgJcYAz/xNUdEA99ha7rQjnVo7jU0ZMWhK
         ZqH3eIVgVcMi5VdpmNWfa24OjWVW88vp8c5qyw+WLlU1QQhWQcnFDCvFj+IbJl+zjtC8
         kiGQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=ywAuibWGz9ymY3YEf+tM9BfEqDCgcxTp+Rd9EWg6i5k=;
        b=obNSKIz/Rrw9F5COoD/0zgBh8iLvCwU5E4CHG003CH1zITdlKkytSWirw96azFHkmd
         S6evbVxiq/3Jlk3kyFUmRRnttLNibeuWL3QeYNphH3eTG2IbZPmOJEZFa/3x4BjcNCRZ
         buv1DJiCxTcuFSprFbAIJFrWHwt4DjhdAQ6JaDIsfd3BE2PfDbpzwFjDBrzELydAvpEi
         vLI3nVAu516kwf8M+MzZtuj+BZJ99/KIHE4qoUDGpxiWnCsp284SishJ+AcHvbw/qMyS
         nG/fEc4NFXc4EKoKNqb4Nz593vBhY7WPddqwaExGwfjMKdF2/ZtGvsogRhOcmK6ALZsQ
         pnNw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=tK2nFqlN;
       spf=pass (google.com: domain of 3mscexwokctenaqerlxaiytbbtyr.pbzxnfna-qritbbtyrtebhcf.pbz@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=3msCEXwoKCTENaQeRlXaiYTbbTYR.PbZXNfNa-QRiTbbTYRTebhcf.PbZ@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=ywAuibWGz9ymY3YEf+tM9BfEqDCgcxTp+Rd9EWg6i5k=;
        b=AUSJnayqD74hA7hh+yerrFyPbF2tb6uQZeCDksGeSMEIFZRDNbUQnwb6AcK/ttort1
         U98fGJk3B2+vAH+qWsG2nz/OMLwxNy4+CfeyDJc5u/4zu2UIBU5pAtaRYBxsfzM5MN9j
         WTjqoEHR2qh2LV0273bTxAvkcUK1KvFUurSQNFcQ0/jNa0wDYOZ/sTBxSSDoXC/tEnnY
         flsdUmFcCadwo4hzN8+p7DIA4AH2Dey00WDDz5TxW1bcCaqUL5vzxRQpLW8F2eLBM788
         nkNwwUk4Ik96FszThafSwm3/CtfDDNFAfxxzO87K3U/ge16mCna1hsBal41QZyFIpCxJ
         8uIw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ywAuibWGz9ymY3YEf+tM9BfEqDCgcxTp+Rd9EWg6i5k=;
        b=IS+ySKcPqr2zoN+lOjuWrIfKbvUt1mc3gHaKv8T1mS3yT4w46vwxDpcBfu5z9V+1+W
         CNp/H4P+5BfBTAYarOep8MFqExAmXyPXaccQze+6ZF7CMMykSpcnzgMIX5223W0y0hGH
         r2Md9r7Mq5flfV/9HTzqKyPUROzG09RdNZ/co0WIdeB0oH/bH1cbaQRxfkZkyNSwiQBp
         tWz6808RK79844yuwMn2KhCNcdZto7hBzrfBUx76S3yip44jF1bsEcs972fLU1bXfkNN
         Xx5pdC+1u2HQEsTQW0AFdMZUfnJjCR+BpZ82cC/wNmUXRUTpJl30o56mK8Ul446EP9wI
         4wkg==
X-Gm-Message-State: AOAM530r+3v5xPxzKThcN/jh5aSxMgBf1A58+gn1IMymetLptOe2pm19
	VPDjIOEWYd6Oki/wiDURRRY=
X-Google-Smtp-Source: ABdhPJxQmJ4cNb/wRmXJVfYSjhFGKqoGkC5QW89qpXL8tIib5bnSf5es1lgUA4eK76ooqazIhtsybg==
X-Received: by 2002:a05:620a:9ca:: with SMTP id y10mr12240055qky.144.1602535579465;
        Mon, 12 Oct 2020 13:46:19 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a37:8744:: with SMTP id j65ls3241028qkd.1.gmail; Mon, 12 Oct
 2020 13:46:19 -0700 (PDT)
X-Received: by 2002:a37:9c06:: with SMTP id f6mr12437353qke.161.1602535579047;
        Mon, 12 Oct 2020 13:46:19 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1602535579; cv=none;
        d=google.com; s=arc-20160816;
        b=jZ5yWEyXt0IcCmTPxqaJIBsdPexUEtMdUeRF0BBpNfdqlaSGAnvpx07rzCQj+rRcPy
         p+Zp1CVlUTsVNvnJ06xIO1AqOobrVq13sn+9XCA6ojwaU8QAsFUdqthixYoh1E7WMpI7
         2kw5PyzlMepYfLEEslULIlbBfSSlSwDVLUNa8lk/vc5z6Dk+Facr17umhTkGaapp4rNw
         1KTtaarJDHlABozRTUU5Xvuv9tz4VzcNugOl1YZQv81mXYvpSVQXvnkeLftGd6s4n0bB
         OB1H8sOBmr5NBYBSPoLMPGVF+oMD5sphZTkNRE12u9vEgyhRKkV9H+ueDfWnI3inbPg4
         ou7w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=4P0nIsUWr4hug9uTHV4YbGNkHcxo9uGG3eroRt4rLtQ=;
        b=IujBI0Z3RdCjCor0xpiIZI0IKonGJLdMzlLzT8iYeF0DgwXVWJm+VYpXgvs88dYg1v
         2nq4HfbJ407FobevuNBkPPtvw7jJl6X2+Q1JWY/rL5+zU38dXak8uxVa/OAIUWWXRCeO
         UCJHTWG/S5Ey1PrM6w3T4L1aoh9eji42zlkW/5SsUtwl0yZuLw5trVvHYlhA3JUfGwpJ
         Yhw9szq5mF8PldQIZ/nksZ7QoHbo5We60zk62DMP8gPuyeraiVPm1vvSiHOC8OpqgIKT
         HF6kCNvF0lSRSfAspNT2bvpxT6mGqmb+PbSzhhIygxxghyJqJ6xhJgnIE1BsNy/vQDhS
         CiGQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=tK2nFqlN;
       spf=pass (google.com: domain of 3mscexwokctenaqerlxaiytbbtyr.pbzxnfna-qritbbtyrtebhcf.pbz@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=3msCEXwoKCTENaQeRlXaiYTbbTYR.PbZXNfNa-QRiTbbTYRTebhcf.PbZ@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x74a.google.com (mail-qk1-x74a.google.com. [2607:f8b0:4864:20::74a])
        by gmr-mx.google.com with ESMTPS id m40si1153726qtm.4.2020.10.12.13.46.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 12 Oct 2020 13:46:19 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3mscexwokctenaqerlxaiytbbtyr.pbzxnfna-qritbbtyrtebhcf.pbz@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) client-ip=2607:f8b0:4864:20::74a;
Received: by mail-qk1-x74a.google.com with SMTP id m23so13489421qkh.10
        for <kasan-dev@googlegroups.com>; Mon, 12 Oct 2020 13:46:19 -0700 (PDT)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:ad4:59cf:: with SMTP id
 el15mr27782436qvb.17.1602535578726; Mon, 12 Oct 2020 13:46:18 -0700 (PDT)
Date: Mon, 12 Oct 2020 22:44:42 +0200
In-Reply-To: <cover.1602535397.git.andreyknvl@google.com>
Message-Id: <7c8b0dcdf1cebeb0a596c7aa4be48863cc8b2c9b.1602535397.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1602535397.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.28.0.1011.ga647a8990f-goog
Subject: [PATCH v5 36/40] kasan, arm64: print report from tag fault handler
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
 header.i=@google.com header.s=20161025 header.b=tK2nFqlN;       spf=pass
 (google.com: domain of 3mscexwokctenaqerlxaiytbbtyr.pbzxnfna-qritbbtyrtebhcf.pbz@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=3msCEXwoKCTENaQeRlXaiYTbbTYR.PbZXNfNa-QRiTbbTYRTebhcf.PbZ@flex--andreyknvl.bounces.google.com;
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
---
Change-Id: I3780fe7db6e075dff2937d3d8508f55c9322b095
---
 arch/arm64/mm/fault.c | 14 ++++++++++++++
 mm/kasan/report.c     | 11 ++++++++---
 2 files changed, 22 insertions(+), 3 deletions(-)

diff --git a/arch/arm64/mm/fault.c b/arch/arm64/mm/fault.c
index d110f382dacf..1c314e6f7918 100644
--- a/arch/arm64/mm/fault.c
+++ b/arch/arm64/mm/fault.c
@@ -14,6 +14,7 @@
 #include <linux/mm.h>
 #include <linux/hardirq.h>
 #include <linux/init.h>
+#include <linux/kasan.h>
 #include <linux/kprobes.h>
 #include <linux/uaccess.h>
 #include <linux/page-flags.h>
@@ -295,10 +296,23 @@ static void die_kernel_fault(const char *msg, unsigned long addr,
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
 
 static void __do_kernel_fault(unsigned long addr, unsigned int esr,
 			      struct pt_regs *regs)
diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index 3924127b4786..f8817d5685a7 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -60,9 +60,14 @@ static void print_error_description(struct kasan_access_info *info)
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
2.28.0.1011.ga647a8990f-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/7c8b0dcdf1cebeb0a596c7aa4be48863cc8b2c9b.1602535397.git.andreyknvl%40google.com.
