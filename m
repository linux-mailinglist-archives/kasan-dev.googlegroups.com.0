Return-Path: <kasan-dev+bncBCMPTDOCVYOBBI4LY24AMGQE54JOZ4I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x838.google.com (mail-qt1-x838.google.com [IPv6:2607:f8b0:4864:20::838])
	by mail.lfdr.de (Postfix) with ESMTPS id AADCC9A2FF8
	for <lists+kasan-dev@lfdr.de>; Thu, 17 Oct 2024 23:46:13 +0200 (CEST)
Received: by mail-qt1-x838.google.com with SMTP id d75a77b69052e-460419da355sf32142031cf.0
        for <lists+kasan-dev@lfdr.de>; Thu, 17 Oct 2024 14:46:13 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1729201572; cv=pass;
        d=google.com; s=arc-20240605;
        b=eXFQkfcXk7laf6q1CelVfgSbvXSe4wY7Pt7zeyIXCQObEsqyVa/ZVVoh6HPBQWsNZg
         M2ib6WHIXeTt/nM8vQa1fsCQNE2MYIDIOxl7QPEJUoU1h/ulrfJVmPsBybg7onZGmEkf
         RAr1QUL5zDZF1vb1MYGfiCHSVHYIOEGXtwMbcrF3DPTwh5dGkUcXYoDzFZ7zdPDovKUY
         JI9LMmDUvPdD/7DX7Z+eK9WefnPqWvt48t1sdJpRyerScHBctu2T5Fzf3QmMSQzB0WUK
         l6HdYey3WMSeKLvKN0INiyKXVJbE+gfiogwCh9AdnYtrDhS2PUoiFxf775nLnQnICXud
         LATA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature:dkim-signature;
        bh=UznJjVu+zeGdHA3n92BpzTYYLUwJ1kXs6ihYYyUnoWw=;
        fh=h5eXKKiEPUazlsuoM0HbS2ggCtJKZFsourG6ZuDdnB8=;
        b=XD/i6f9Cx+xEExF/qatOVNq+PrXvRbDpCZdXnXADU5RKJ6Th7MvWBYLZ+nJWP9aSVy
         ufvURucvmzFa3as37EFVAb3pojRBUEcuQNyCOXHFm4zRfShR1hI/14T/WKrwL5JOmF6Y
         61NvOqKcNh7eCwTIH8AAmaYKndPYz1gPiGdBqFMJbUqu2N2a2UoU+alX3WX/GD56jWBR
         pk3HoIAxh6dVPEyCPcVMDMdm+rmCdeSuIlUmix8G6SFthnxn5Wcse4NWEmZSvnr/BwIP
         9yFrxz9oN+pbBVipo1Df/DObMc8uTM6rpV54xrwG9wRliQxvANfaSzCZUhGd/LnMu/hi
         gnNA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=Xo+srcwo;
       spf=pass (google.com: domain of niharchaithanya@gmail.com designates 2607:f8b0:4864:20::52c as permitted sender) smtp.mailfrom=niharchaithanya@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1729201572; x=1729806372; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=UznJjVu+zeGdHA3n92BpzTYYLUwJ1kXs6ihYYyUnoWw=;
        b=L5+dPHBGHbjyMa5BkJevXJIBfYnzfi/+FxxoP229QtV0eG22QarMcd7DIMNLbdHbjO
         9Sojy1wdnLgADu/jJxIckUI1KOo/ZSG2xFLQBOflaOWxvx+91dyc0yGXRZexaTuwNdML
         wy2rF5U2y6bzm/naxfWmBAdCbDjDD/SgJM1c5kKc6oqsUVWbvMdxyg9KLbaA8KT8e6j8
         dVhY4xal1mViGE+Hd0RgRd3MB/UB9ecbwfnVaq31tQxyulkNQ/GVPjmaqVSmYujt3Gt5
         ChkCkz89i6fTghlsGutF+ABER+rLpupWxUA5YTi7OtP8qkP4Mko0agVCwxxhWv8ffH5J
         z6rQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1729201572; x=1729806372; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :from:to:cc:subject:date:message-id:reply-to;
        bh=UznJjVu+zeGdHA3n92BpzTYYLUwJ1kXs6ihYYyUnoWw=;
        b=IcCfZ3RuvxpIS8XVServ+kviJxkx+sG5/pe7FXop3xjOKccmCXYk8wgr1v7/AJX7hN
         Os7CEdMBLKnaYhW0uifZOAUUXC+VrlyGbghUCfpBpSW1M1d873gBpYnY0tY0Pi2ayFUI
         6eHEpcsm8bdIwD1f2QdibIdfalXDOMWlUMG7t1ZEdrQbkinE7KqTt0Dr1wZ9d1JWYNDZ
         LeXpTMknizq52qRLNC4H/Bmlfmi23haQ1ji7mPIRrtbCBwXmpXXB/R4dqI4Ku+WhzT1u
         wh6oCLg/a45vLsd9OgBlmxvK2+vyxr0ZgC9LL9WycZR17VrykvfT+aeLrG0f6PlJTeDI
         fw9Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1729201572; x=1729806372;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=UznJjVu+zeGdHA3n92BpzTYYLUwJ1kXs6ihYYyUnoWw=;
        b=cgzMTR18PIwnIcpCt/BRT0P/dcenhKthdxD51MqqSeULbFe1Ss/LcnOe2ZkTrDKHps
         tCgkQ6t//RN0ZW+5F02bBAZ1fxMXNUR4Zs212l8yKXjVla6SubNWe4adCx2Lzps8V870
         KLgh5O4nUy+tHRquo6ih/KBmUrWfHBb5wKzqS5f8ymMhBfrfORzQyjH5LsA/Lju+8knQ
         44Du7YxLc2+SyPcwEMQEWvJdI6nnvHgLOZP8wdjuW5q+prRFI4DSNYHUZbzN/zRnAV71
         t8vYoJtswNJV9eP+9HbNj7iurZ0wN6jY3lb1T3uOZ5QEkB6v6reYdaCqLb++gPh7gSiw
         YQGg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVg2sszGIxkArViqqqLz1V+QDo5fbrUn3BPenZebKrpIg5WZwRJf/+gk+bgTUUWumgiFc8ybg==@lfdr.de
X-Gm-Message-State: AOJu0Yx322MfWaSiZbem3GOfDAX9pPoKlKAsrfHLmlgESQAECpD35p0F
	zlvL2zYB5IrxQJuiYYCdBIVl/6eizCcQmw9zvwkfO9YiNvYJqGyl
X-Google-Smtp-Source: AGHT+IEYVfNO8RtnKzDjWgyBY1OqjZTpsTAx6cCOxCz2XYMHbicvHkhLtRGh1lR+5hV9G8t3AWhdSw==
X-Received: by 2002:ac8:5a56:0:b0:460:92af:da42 with SMTP id d75a77b69052e-460aed644bamr3004671cf.20.1729201571983;
        Thu, 17 Oct 2024 14:46:11 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:622a:1aa4:b0:458:355c:3632 with SMTP id
 d75a77b69052e-4609b6c6942ls24982671cf.2.-pod-prod-04-us; Thu, 17 Oct 2024
 14:46:11 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWWSEq8LYSenv/0TZt7UIjB0gnySO4u650peSDL5ntNe4qq0INRLmSTOB6EVoUq3pcA4ARZNwlNaUQ=@googlegroups.com
X-Received: by 2002:a05:620a:29d3:b0:7af:c60b:5acf with SMTP id af79cd13be357-7b157b3e581mr17986385a.10.1729201571246;
        Thu, 17 Oct 2024 14:46:11 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1729201571; cv=none;
        d=google.com; s=arc-20240605;
        b=hjhNcofL8pNpO/ea4L6OTEeHJkHQR69GdFKNaWMfsFWOza68LN68gmcR+lk9SSwuCG
         2EM+WpZ09tDog8+pWU/4QO1cZBX1QXgZIetrf6v7E+JJ2K4A8nfX4/4HPrnLM7a6qsQq
         ZrZ9Fgh8I+X1vxlwjjfvugrVd+nseclfZYvaZMN3CVDkQhzJc1fwe7laoYUECo56T3to
         cLgpkuA+f/i0n0YPZDJNpuSt3RsN1s5T2mn2YDgwdpVxWQi3Lg30QRAsBNiid7+YDUMt
         51pvAhTE4RytF7hcYomKJVyJcvBfqik4ghoeaimMCh/D/1rOJHjpDYL1q+Y0UNy4wlSr
         pbxA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=tI1WUEgzzH52RdmMvRjnf4Xl2Jbh0RwAUil8kMyE9bo=;
        fh=hu5LzdNhqIbEhLS4oqklScBe2TPZunzH0zSMgUuaTJA=;
        b=aPaim2tzBvyHKbtJyGoMrIoG7vHykj/Cl/MPxPUazjyL8aY6kENoCPFpczisI4C26b
         mBuF6U0AgTcPF1puXAMDPvqQAnMCfButZqQt8omf929PMjhhcGFHNfRgpuB5VW+UFB+p
         LUc/JKlnTJwffXmDDzy8stOTuc2bMWxzFHvIkfAc088rsYwske71pWrcxr/cXepHZYll
         7VqkyYlidF+n5TM6JdCml6FgVWM/2tRN49q0QCm8o18wdVc/xV4VWk9BAekobwGBgbnl
         8yGp9B6UQTJhODbJGQBCl/Q28lOv/n/degSCEhX8GgphiMlf3IdEZlfUPTzusSPBfFvn
         PqRQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=Xo+srcwo;
       spf=pass (google.com: domain of niharchaithanya@gmail.com designates 2607:f8b0:4864:20::52c as permitted sender) smtp.mailfrom=niharchaithanya@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pg1-x52c.google.com (mail-pg1-x52c.google.com. [2607:f8b0:4864:20::52c])
        by gmr-mx.google.com with ESMTPS id af79cd13be357-7b156ec7cd5si1353485a.0.2024.10.17.14.46.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 17 Oct 2024 14:46:11 -0700 (PDT)
Received-SPF: pass (google.com: domain of niharchaithanya@gmail.com designates 2607:f8b0:4864:20::52c as permitted sender) client-ip=2607:f8b0:4864:20::52c;
Received: by mail-pg1-x52c.google.com with SMTP id 41be03b00d2f7-7eab7600800so192651a12.1
        for <kasan-dev@googlegroups.com>; Thu, 17 Oct 2024 14:46:11 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWFKYh/RyXuU4h4DOCr02tb0E3TBEHGzQkOSR+t0dWz6yEPwp6HXBuv0CnlVX6gkd2+rUWqXrSY4Vk=@googlegroups.com
X-Received: by 2002:a05:6a21:9990:b0:1cf:2be2:6525 with SMTP id adf61e73a8af0-1d92c5872eemr219645637.11.1729201569998;
        Thu, 17 Oct 2024 14:46:09 -0700 (PDT)
Received: from ice.. ([171.76.83.88])
        by smtp.gmail.com with ESMTPSA id 41be03b00d2f7-7eacc20d2desm62817a12.7.2024.10.17.14.46.06
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 17 Oct 2024 14:46:09 -0700 (PDT)
From: Nihar Chaithanya <niharchaithanya@gmail.com>
To: ryabinin.a.a@gmail.com
Cc: andreyknvl@gmail.com,
	dvyukov@google.com,
	skhan@linuxfoundation.org,
	kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org,
	Nihar Chaithanya <niharchaithanya@gmail.com>
Subject: [PATCH] kasan:report: filter out kasan related stack entries
Date: Fri, 18 Oct 2024 03:12:54 +0530
Message-Id: <20241017214251.170602-1-niharchaithanya@gmail.com>
X-Mailer: git-send-email 2.34.1
MIME-Version: 1.0
X-Original-Sender: niharchaithanya@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=Xo+srcwo;       spf=pass
 (google.com: domain of niharchaithanya@gmail.com designates
 2607:f8b0:4864:20::52c as permitted sender) smtp.mailfrom=niharchaithanya@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
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

The reports of KASAN include KASAN related stack frames which are not
the point of interest in the stack-trace. KCSAN report filters out such
internal frames providing relevant stack trace. Currently, KASAN reports
are generated by dump_stack_lvl() which prints the entire stack.

Add functionality to KASAN reports to save the stack entries and filter
out the kasan related stack frames in place of dump_stack_lvl().

Within this new functionality:
	- A function save_stack_lvl_kasan() in place of dump_stack_lvl() is
	  created which contains functionality for saving, filtering and printing
          the stack-trace.
	- The stack-trace is saved to an array using stack_trace_save() similar to
  	  KCSAN reporting which is useful for filtering the stack-trace,
	- The sanitize_stack_entries() function is included to get the number of
          entries to be skipped for filtering similar to KCSAN reporting,
	- The dump_stack_print_info() which prints generic debug info is included
  	  from __dump_stack(),
	- And the function print_stack_trace() to print the stack-trace using the
 	  array containing stack entries as well as the number of entries to be
 	  skipped or filtered out is included.

Signed-off-by: Nihar Chaithanya <niharchaithanya@gmail.com>
Fixes: https://bugzilla.kernel.org/show_bug.cgi?id=215756
---
 mm/kasan/report.c | 92 +++++++++++++++++++++++++++++++++++++++++++++--
 1 file changed, 90 insertions(+), 2 deletions(-)

diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index b48c768acc84..c180cd8b32ae 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -39,6 +39,7 @@ static unsigned long kasan_flags;
 
 #define KASAN_BIT_REPORTED	0
 #define KASAN_BIT_MULTI_SHOT	1
+#define NUM_STACK_ENTRIES 64
 
 enum kasan_arg_fault {
 	KASAN_ARG_FAULT_DEFAULT,
@@ -369,12 +370,99 @@ static inline bool init_task_stack_addr(const void *addr)
 			sizeof(init_thread_union.stack));
 }
 
+/* Helper to skip KASAN-related functions in stack-trace. */
+static int get_stack_skipnr(const unsigned long stack_entries[], int num_entries)
+{
+	char buf[64];
+	int len, skip;
+
+	for (skip = 0; skip < num_entries; ++skip) {
+		len = scnprintf(buf, sizeof(buf), "%ps", (void *)stack_entries[skip]);
+
+		/* Never show  kasan_* functions. */
+		if (strnstr(buf, "kasan_", len) == buf)
+			continue;
+		/*
+		 * No match for runtime functions -- @skip entries to skip to
+		 * get to first frame of interest.
+		 */
+		break;
+	}
+
+	return skip;
+}
+
+static int
+replace_stack_entry(unsigned long stack_entries[], int num_entries, unsigned long ip,
+		    unsigned long *replaced)
+{
+	unsigned long symbolsize, offset;
+	unsigned long target_func;
+	int skip;
+
+	if (kallsyms_lookup_size_offset(ip, &symbolsize, &offset))
+		target_func = ip - offset;
+	else
+		goto fallback;
+
+	for (skip = 0; skip < num_entries; ++skip) {
+		unsigned long func = stack_entries[skip];
+
+		if (!kallsyms_lookup_size_offset(func, &symbolsize, &offset))
+			goto fallback;
+		func -= offset;
+
+		if (func == target_func) {
+			*replaced = stack_entries[skip];
+			stack_entries[skip] = ip;
+			return skip;
+		}
+	}
+
+fallback:
+	/* Should not happen; the resulting stack trace is likely misleading. */
+	WARN_ONCE(1, "Cannot find frame for %pS in stack trace", (void *)ip);
+	return get_stack_skipnr(stack_entries, num_entries);
+}
+
+static void
+print_stack_trace(unsigned long stack_entries[], int num_entries, unsigned long reordered_to)
+{
+	stack_trace_print(stack_entries, num_entries, 0);
+	if (reordered_to)
+		pr_err("  |\n  +-> reordered to: %pS\n", (void *)reordered_to);
+}
+
+static int
+sanitize_stack_entries(unsigned long stack_entries[], int num_entries, unsigned long ip,
+		       unsigned long *replaced)
+{
+	return ip ? replace_stack_entry(stack_entries, num_entries, ip, replaced) :
+			  get_stack_skipnr(stack_entries, num_entries);
+}
+
+static void save_stack_lvl_kasan(const char *log_lvl, struct kasan_report_info *info)
+{
+	unsigned long reordered_to = 0;
+	unsigned long stack_entries[NUM_STACK_ENTRIES] = {0};
+	int num_stack_entries = stack_trace_save(stack_entries, NUM_STACK_ENTRIES, 1);
+	int skipnr = sanitize_stack_entries(stack_entries,
+				 num_stack_entries, info->ip, &reordered_to);
+
+	dump_stack_print_info(log_lvl);
+	pr_err("\n");
+
+	print_stack_trace(stack_entries + skipnr, num_stack_entries - skipnr,
+					 reordered_to);
+	pr_err("\n");
+}
+
 static void print_address_description(void *addr, u8 tag,
 				      struct kasan_report_info *info)
 {
 	struct page *page = addr_to_page(addr);
 
-	dump_stack_lvl(KERN_ERR);
+	save_stack_lvl_kasan(KERN_ERR, info);
 	pr_err("\n");
 
 	if (info->cache && info->object) {
@@ -488,7 +576,7 @@ static void print_report(struct kasan_report_info *info)
 		print_address_description(addr, tag, info);
 		print_memory_metadata(info->first_bad_addr);
 	} else {
-		dump_stack_lvl(KERN_ERR);
+		save_stack_lvl_kasan(KERN_ERR, info);
 	}
 }
 
-- 
2.34.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20241017214251.170602-1-niharchaithanya%40gmail.com.
