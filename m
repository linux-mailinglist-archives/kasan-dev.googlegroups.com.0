Return-Path: <kasan-dev+bncBCMPTDOCVYOBBD5M6S4AMGQEXTKIIMQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1039.google.com (mail-pj1-x1039.google.com [IPv6:2607:f8b0:4864:20::1039])
	by mail.lfdr.de (Postfix) with ESMTPS id 738C89B19B6
	for <lists+kasan-dev@lfdr.de>; Sat, 26 Oct 2024 18:17:22 +0200 (CEST)
Received: by mail-pj1-x1039.google.com with SMTP id 98e67ed59e1d1-2e2fc2b1ce1sf2994639a91.0
        for <lists+kasan-dev@lfdr.de>; Sat, 26 Oct 2024 09:17:22 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1729959440; cv=pass;
        d=google.com; s=arc-20240605;
        b=QWTezRZU/N/CLjq5Wh3kUrllZpMriacCSUNLyLlxgmUX6Ov5NDse96RN/mOsrQDPFm
         Z0LUK3rCjwzOlrh15/n89TGOG0qb7XWBS5Zjh/DtM7CHAfhcxiAyqsD8qGxKqeVluZeA
         ifjGxvc4Jo85p3fSVLZjdjQDJ6ehXeao4mmtuMjRABac/zHSg2tyQPFNt850Er42kHJd
         gDgq7nuEKrwcVYpJiAvmKxNF8tGkxOOBbO0hfGAnaUH1VcO9CGVzpLYT1gMbFRk4NLiu
         tqRAxQcZNCOTgdrELFOsTe/WSBDvwO+TbD7JPeHi1iySbLDNMp8QoJhLrE2lI+kM+Lkp
         FOGQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature:dkim-signature;
        bh=tqfEc+hpc0RnlITrgAbGikiORXk4KjQ+p9EMPF6XxiM=;
        fh=8+EeOAbK476i4n8Py3Nfdu7kKvxgx/3SoXsdMS01fVU=;
        b=LmlqEPE6Oxu+bQXJ2K7dEE48kcadGU5MVh3b1rccVH/PgxYyvF2wVxF7L2Yt7FNrXT
         tIa0A2uIB8jxyPMlqEI8g7NG3g5Mg4Npth4l1nWow+xjfbj0tbcbyZQu4LgWIiXFnEq7
         UWjvpBR2yyIVyqkl6iNxvW7zeM6AFfYJ1g4cho6CXpxO/xx/0ZWeUVVzi5VzYkKlcn5N
         t6Xkei1Rgfm1seq7OeB/HBOOy2BQoRUwlwkLxGDjleh6Equ73VO+/o3ExFkK7BbhCETK
         dKmBEEAX7/zX4UCnEOV72oPnrSZc0gGtVvUFpuY/pqjGk4lVWifmH8XqxrQAL6fL72it
         FBxw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=i5VrvGFS;
       spf=pass (google.com: domain of niharchaithanya@gmail.com designates 2607:f8b0:4864:20::102d as permitted sender) smtp.mailfrom=niharchaithanya@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1729959440; x=1730564240; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=tqfEc+hpc0RnlITrgAbGikiORXk4KjQ+p9EMPF6XxiM=;
        b=FuyMDw2z/qMO0Tb0i7q8Q4l1458/+QR2kLSg+6KNqnUfUy92KM+eMFeG5T/87hzzsT
         umnrtJhsQ8PjfSCJfhxpzpM6/Z1U85OBEsbtTkI3+oHlMsh1Ysgo2yW92XGYBUlDi7dP
         sQ5negba1mlbZmiXTny1fiPLXT5ZnTMb43n1YAJMwr4DAIqhJPpaR3eSPbvtUUZ8WCDL
         6zWALQolLfJJw8upo/2AjK45d+vd03hPEeWqF0gcEsp+hj/7e9cxF5m3M9OkVHT8nxjL
         Z6KMnOut62SUiT5+KkGByOidMmz0hwO+eBoQO/JLuFCFYt1nC06SYnuAv2CpEftfgZWx
         fFdg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1729959440; x=1730564240; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :from:to:cc:subject:date:message-id:reply-to;
        bh=tqfEc+hpc0RnlITrgAbGikiORXk4KjQ+p9EMPF6XxiM=;
        b=OZ1f1zBKiCWXC11CvORtauxrQOPT/L2BJgmyPjb9iR//TsCaLd0DG57w9mohEqFQrW
         AV0lwAjpldCZs+RxV1amPD01XMsB+VnvRbuTK58Z0zb5VNP4pCNMnNAOZ5tH4jfw4SP+
         tF4OE0rvySkNTIXxDwcnj+06PP04MLvakNfoiD7yGzrusavYniz+kGOsysj1KHwA5f9J
         pyhv0wanhTVOFsD+blx7pUqYHMBcBqi4uNg1/aE8ncQaAeJzImtd5hPfk/YoYr7O5r51
         LcwJNWmCLNVASExxfF9x+q/jOE7RA2ViCiefwJT0XUtSUO/8jwqB8x7a/4bgrtDTX9cn
         w8UQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1729959440; x=1730564240;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=tqfEc+hpc0RnlITrgAbGikiORXk4KjQ+p9EMPF6XxiM=;
        b=SC5d7Io3zlw4We7Fzo4a1UO8xsbtovaOSNGH8SAi1yAm3SVz5xTh5I+gJebzp2/+Hc
         sXJhs+/OEJ8x2AgddmuL3LwWcFsVuK9saUM0FBFlYnwHklzz2N7m+oJ4WhJdqhzthEJD
         KpEAQEcvqfxRNCVOVxKC1KYdP2atw7OpbDSTb7M1CMGsuPukLj/CWDEXDNvUbE72KEnU
         Y6kbsyrMJYIR7ROW+/F7iFAx5cHVbs8W2y9frwTXbo7PdA+TMqLYqN7DzLbgB2Y5IajD
         uhUvZ1A61pzPBlojKT8MTdEmlQ7D+uz2lGC8jb48m51jGFuCWr+mlNvqtXmW1LF+hsKX
         vb6g==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVTY0QjuzDq8YNsrROdYSPhDhybbh7mhorv7x0crPcJnF5oZ4KyoE1vWDbfTEqzOwOUvhJVqg==@lfdr.de
X-Gm-Message-State: AOJu0YzWsJ83Tz8fYYuOCPLT4FYIaScQbBN6g+GTk0ZV1I7jl3xChTfS
	MVK3WFcZp/rUj5m+cSUu8k5397RIrXEIRWYXzQYvZowOp8jKBpY5
X-Google-Smtp-Source: AGHT+IF2ALcP7wrKXXpuUe+3qUzYL2dwvC+LoYAkTJH8acn6I6zmA5A+Xt3HRj5YqTw+0UXdiShR4Q==
X-Received: by 2002:a17:90b:510:b0:2e0:853a:af47 with SMTP id 98e67ed59e1d1-2e8f11bddcdmr4183771a91.33.1729959439407;
        Sat, 26 Oct 2024 09:17:19 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:4a45:b0:2e0:79a0:bd97 with SMTP id
 98e67ed59e1d1-2e77a75bac0ls175263a91.0.-pod-prod-01-us; Sat, 26 Oct 2024
 09:17:18 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCV/k4P93AFn2KCMCsFn9GILqFBQ6fNdBdT/jntT+78E4Mb8FT/hp85P67uxUoU4RJ17IouTyP/CbC8=@googlegroups.com
X-Received: by 2002:a17:90a:6c96:b0:2e2:8fb4:502d with SMTP id 98e67ed59e1d1-2e8f106d62dmr3863419a91.16.1729959438148;
        Sat, 26 Oct 2024 09:17:18 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1729959438; cv=none;
        d=google.com; s=arc-20240605;
        b=eNi7pA/OB3vwy787WvFi6XZxz6LXXBfys0tzOfE6AYgf+hLZFxOH04Ihx8Hn4Hv0dE
         ziVkSI9EIZ7fINX+x1qi3djAzRr3bmOq5F5o8tNVpA9Wzr9EqpOsGtcz1hRJdSYKYNEB
         U+UFjpDO2ZfRA7I4tlYg63bnzrMeUxlrSnKGNKLZUFhn3FsqbQB3KGCz1H+/OuQb5hRZ
         MutNSRLh7bWXAZJNARYNi9IvqAU/pScvR1nZB9EsncKSQL1Z6QnPC7ebJgjfVR8hFmEz
         UyAc44Fp6QifEvZTpSapTXOslYuXukql7pwvmJd7RAscTZkaJdaJ4C1qYEZTbAteIzIW
         cDCQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=q0ToQhndnLOEGKHRjsJDV2lxZ3cLs2ivXIHqcO/4O+s=;
        fh=GWdPeC0fZbxAsKPrpGNdJ2gCDHpRVS8pTnEcuSKo/Hw=;
        b=WP0aRuRpggJWLNcB7QnNYwdYISWXefiK6M8oJUf4mcAPtgmAOdNS+K/lVMGrLMiktk
         qpk1g0oXY8fWPY+sOEUVXlh8M243gfVtsskxqYd9iU+3Mx0Cw+g9KszE7C8GLaOuiUtD
         em4jFxE5S7crNSgQFcdWWP2964YrdYpG73V2PdRXoCaYSSvRlyEfj+YNrYkgzUG+Y40P
         j0WDj4vMySmKRSlpQnZjFoBXl3eHVbgUntT0fcLSIhTnZ7AOxqi71ol9R7+uf2/ejYvF
         TUfp60LRzLlPR++9hozLsEftAD/4xgv/XRfH5KYtphn4zkRVeOaSrLaP9eTqM1wMRnvp
         hNPw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=i5VrvGFS;
       spf=pass (google.com: domain of niharchaithanya@gmail.com designates 2607:f8b0:4864:20::102d as permitted sender) smtp.mailfrom=niharchaithanya@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pj1-x102d.google.com (mail-pj1-x102d.google.com. [2607:f8b0:4864:20::102d])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-2e8e34149b9si160856a91.0.2024.10.26.09.17.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 26 Oct 2024 09:17:18 -0700 (PDT)
Received-SPF: pass (google.com: domain of niharchaithanya@gmail.com designates 2607:f8b0:4864:20::102d as permitted sender) client-ip=2607:f8b0:4864:20::102d;
Received: by mail-pj1-x102d.google.com with SMTP id 98e67ed59e1d1-2e31977c653so371395a91.0
        for <kasan-dev@googlegroups.com>; Sat, 26 Oct 2024 09:17:18 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVRQMe5x6JapMbV/3fcSFbwiibeYiK03dEROrEhMw+zCb7u336Uy36uU8AT5XGhl3+6ghGcorrZLiw=@googlegroups.com
X-Received: by 2002:a17:90a:34cb:b0:2e1:682b:361e with SMTP id 98e67ed59e1d1-2e8f11a96dfmr1467042a91.4.1729959437577;
        Sat, 26 Oct 2024 09:17:17 -0700 (PDT)
Received: from ice.. ([171.76.87.243])
        by smtp.gmail.com with ESMTPSA id 98e67ed59e1d1-2e8e3555adesm3661607a91.2.2024.10.26.09.17.13
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sat, 26 Oct 2024 09:17:17 -0700 (PDT)
From: Nihar Chaithanya <niharchaithanya@gmail.com>
To: ryabinin.a.a@gmail.com
Cc: andreyknvl@gmail.com,
	dvyukov@google.com,
	glider@google.com,
	elver@google.com,
	skhan@linuxfoundation.org,
	kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org,
	Nihar Chaithanya <niharchaithanya@gmail.com>
Subject: [PATCH v3] kasan: report: filter out kasan related stack entries
Date: Sat, 26 Oct 2024 21:44:17 +0530
Message-Id: <20241026161413.222898-1-niharchaithanya@gmail.com>
X-Mailer: git-send-email 2.34.1
MIME-Version: 1.0
X-Original-Sender: niharchaithanya@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=i5VrvGFS;       spf=pass
 (google.com: domain of niharchaithanya@gmail.com designates
 2607:f8b0:4864:20::102d as permitted sender) smtp.mailfrom=niharchaithanya@gmail.com;
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
out the kasan related stack frames in place of dump_stack_lvl() and
stack_depot_print().

Within this new functionality:
	- A function kasan_dump_stack_lvl() in place of dump_stack_lvl() is
	  created which contains functionality for saving, filtering and
	  printing the stack-trace.
	- A function kasan_stack_depot_print() in place of
	  stack_depot_print() is created which contains functionality for
	  filtering and printing the stack-trace.
	- The get_stack_skipnr() function which employs pattern based stack
	  filtering is included.
	- The replace_stack_entry() function which uses ip value based
	  stack filtering is included.

Signed-off-by: Nihar Chaithanya <niharchaithanya@gmail.com>
Fixes: https://bugzilla.kernel.org/show_bug.cgi?id=215756
---
Changes in v2:
        - Changed the function name from save_stack_lvl_kasan() to
          kasan_dump_stack_lvl().
        - Added filtering of stack frames for print_track() with
          kasan_stack_depot_print().
        - Removed redundant print_stack_trace(), and instead using
          stack_trace_print() directly.
        - Removed sanitize_stack_entries() and replace_stack_entry()
          functions.
        - Increased the buffer size in get_stack_skipnr to 128.

Changes in v3:
	- Included an additional criteria for pattern based filtering
	  in get_stack_skipnr().
	- Included ip value based stack filtering with the functions
	  sanitize_stack_entries() and replace_stack_entry().
	- Corrected the comments and name of the newly added functions
	  kasan_dump_stack() and kasan_stack_depot_print().

 mm/kasan/report.c | 111 ++++++++++++++++++++++++++++++++++++++++++++--
 1 file changed, 107 insertions(+), 4 deletions(-)

diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index 3e48668c3e40..648a89fea3e7 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -261,6 +261,110 @@ static void print_error_description(struct kasan_report_info *info)
 			info->access_addr, current->comm, task_pid_nr(current));
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
+		/* Never show  kasan_* or __kasan_* functions. */
+		if ((strnstr(buf, "kasan_", len) == buf) ||
+			(strnstr(buf, "__kasan_", len) == buf))
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
+/*
+ * Skips to the first entry that matches the function of @ip, and then replaces
+ * that entry with @ip, returning the entries to skip with @replaced containing
+ * the replaced entry.
+ */
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
+static int
+sanitize_stack_entries(unsigned long stack_entries[], int num_entries, unsigned long ip,
+		       unsigned long *replaced)
+{
+	return ip ? replace_stack_entry(stack_entries, num_entries, ip, replaced) :
+			  get_stack_skipnr(stack_entries, num_entries);
+}
+
+/*
+ * Use in place of dump_stack() to filter out KASAN-related frames in
+ * the stack trace.
+ */
+static void kasan_dump_stack(unsigned long ip)
+{
+	unsigned long reordered_to = 0;
+	unsigned long stack_entries[KASAN_STACK_DEPTH] = { 0 };
+
+	int num_stack_entries = stack_trace_save(stack_entries, KASAN_STACK_DEPTH, 0);
+	int skipnr = sanitize_stack_entries(stack_entries, num_stack_entries,
+										ip, &reordered_to);
+
+	dump_stack_print_info(KERN_ERR);
+	stack_trace_print(stack_entries + skipnr, num_stack_entries - skipnr, 0);
+}
+
+/*
+ * Use in place of stack_depot_print() to filter out KASAN-related frames
+ * in the stack trace.
+ */
+static void kasan_stack_depot_print(depot_stack_handle_t stack)
+{
+	unsigned int nr_entries;
+	unsigned long *entries = NULL;
+	unsigned int skipnr;
+
+	nr_entries = stack_depot_fetch(stack, &entries);
+	if (nr_entries) {
+		skipnr = get_stack_skipnr(entries, nr_entries);
+		stack_trace_print(entries + skipnr, nr_entries - skipnr, 0);
+	} else
+		pr_err("(stack is not available)\n");
+}
+
 static void print_track(struct kasan_track *track, const char *prefix)
 {
 #ifdef CONFIG_KASAN_EXTRA_INFO
@@ -277,7 +381,7 @@ static void print_track(struct kasan_track *track, const char *prefix)
 	pr_err("%s by task %u:\n", prefix, track->pid);
 #endif /* CONFIG_KASAN_EXTRA_INFO */
 	if (track->stack)
-		stack_depot_print(track->stack);
+		kasan_stack_depot_print(track->stack);
 	else
 		pr_err("(stack is not available)\n");
 }
@@ -374,7 +478,6 @@ static void print_address_description(void *addr, u8 tag,
 {
 	struct page *page = addr_to_page(addr);
 
-	dump_stack_lvl(KERN_ERR);
 	pr_err("\n");
 
 	if (info->cache && info->object) {
@@ -484,11 +587,11 @@ static void print_report(struct kasan_report_info *info)
 		kasan_print_tags(tag, info->first_bad_addr);
 	pr_err("\n");
 
+	kasan_dump_stack(info->ip);
+
 	if (addr_has_metadata(addr)) {
 		print_address_description(addr, tag, info);
 		print_memory_metadata(info->first_bad_addr);
-	} else {
-		dump_stack_lvl(KERN_ERR);
 	}
 }
 
-- 
2.34.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20241026161413.222898-1-niharchaithanya%40gmail.com.
