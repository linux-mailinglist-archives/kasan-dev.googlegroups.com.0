Return-Path: <kasan-dev+bncBCMPTDOCVYOBB2PE3K4AMGQEDEHYJYA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1039.google.com (mail-pj1-x1039.google.com [IPv6:2607:f8b0:4864:20::1039])
	by mail.lfdr.de (Postfix) with ESMTPS id C86549A9070
	for <lists+kasan-dev@lfdr.de>; Mon, 21 Oct 2024 21:58:35 +0200 (CEST)
Received: by mail-pj1-x1039.google.com with SMTP id 98e67ed59e1d1-2e3ce03a701sf5241681a91.0
        for <lists+kasan-dev@lfdr.de>; Mon, 21 Oct 2024 12:58:35 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1729540714; cv=pass;
        d=google.com; s=arc-20240605;
        b=MJvU3+dhwK0mrNbtMJJKTmO8m5cYB/bG5dczofmI0Jio59FesTgLRV/IJpGoFY3WD9
         dciQeuLvI9MJEnTZnMeKVU0jd+G7EYNKr32A3NMeaf1Ayhdp0BsDG6IG+z2gfjTIThjH
         w2b+VDcf2xoMRm+cLwX7HLpSbRxCNWW+9b1mjNHR0KPAMd4iuWVa0ec7dMJfjiSn0e7F
         sffksFUS/M4rpi6Tjk7OlRccRk4NYSP2Xk6SXeaSws3VJ/U0ptCNRzCzSvfp5YZaGXWR
         XxzOnZVIIQvQ3ISH1poMNjG09iBL3UTMXd7nfcLsvW6WTV6LC/l8LZGY775EMJKa3cH3
         kPnw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature:dkim-signature;
        bh=RV5HXTG/YQZEXNQCPZ8cTXxQYjptJO3DGpR+xeDo0sw=;
        fh=PqRfbhEBel7zME0/8hQH9uSoTZaVUh5kLAgXpJXcRHA=;
        b=PBuY/BEmaugNakGs6FF3DWTT7kQ4iotuzN7SNlDwX5w34WHbWcPdMpkjf0lHyWRWdD
         7hT6A4KnIJLwW9kIhgzg6PcgbXkH5QiFKFyb2SuujyWa90Ma6jazDqiJToHoBR0ic6Va
         7S5aQGLszzhzvKDXRFyrCShIzGZDXdup+HvTDRsthAHhfJcFLY4KOFa3iX/iHZY7eUmk
         SK2ZR+8kcULyMwJvJPSGVbbHPeKKHSNS7wnOhal7kaGu0cc328+IOpr2rdwsM29Va3Sq
         QpvxYw7fpQ4lkVzMtg1nSaUQsKlZkEWFv40CqnvTGM+Har808ZK9in2cBCVYemZKXRLs
         mqpQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=EDl6LlRq;
       spf=pass (google.com: domain of niharchaithanya@gmail.com designates 2607:f8b0:4864:20::436 as permitted sender) smtp.mailfrom=niharchaithanya@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1729540714; x=1730145514; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=RV5HXTG/YQZEXNQCPZ8cTXxQYjptJO3DGpR+xeDo0sw=;
        b=EWtSTbkJT/LCysonVg+g4cnY8OW3b5p+uGEL1+P0wo4XjKt5VFrkStVJcKTNSzmQ+c
         OakZMYIIC6Gps0n9T+jNfKc+BhcU5O4mxpfkaE3XRvCROVXTKJesBqm4d1B3uAQ/Sr5d
         J6yCPuAjJHdYoXsgBC96PyVOmyfw5yUDInoWaF4wJ4kGE+i8tI5sOH0JV6lqgnbEelni
         FRwTvroBR4ZJwjAEfZ5DFTcOwKoSVNh0jgWBn7x0L6SELqgNsugPg7aCGELWc4mIOnfc
         MaIaF0Oz2RgtwYE2fu9i4a2l7vywVx497Jyd/kb8dO9t/HXKcJn3CMTDHYbqgMcSamXx
         J7VA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1729540714; x=1730145514; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :from:to:cc:subject:date:message-id:reply-to;
        bh=RV5HXTG/YQZEXNQCPZ8cTXxQYjptJO3DGpR+xeDo0sw=;
        b=RJztrgkRLzZHVlXFyuXvPwBLwPfWf/3Y6oKLRtkVhkDP2Ih7xE1Ez7HxtZbY1v22sq
         mRUks6aPYjslkwQ81J2BYd26/fZHjqzwvNltE5zLKjVsi0Sxqxwwww024CM1/SH4Ekvy
         qo70jbv4bBNYsq+T5nIuixengInArodbl1HLbrVmfcwpEWbXrPo85WsSZ8yrvVMyxo22
         D2BhNTrCVruijfG5cVNX4UIekQaImXquT0SsgHKppGPmaT3H8syyV3VvwMWg3JS4/huC
         CyuPCmR9z9uXgVxpHYSGH8uiLdwIgQlx/AlL7zZoIhwwSfzNj82yjv9C/x4xhtRarU2j
         zN9w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1729540714; x=1730145514;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=RV5HXTG/YQZEXNQCPZ8cTXxQYjptJO3DGpR+xeDo0sw=;
        b=ffvqJVMaMkvVV2G6/XWewaJ2m6Tl1CSLEGup5svd3dEy8dpOvpBXww+e2JnArfvuZd
         EmTCE1XMKPx3EDXxxyosm3g4XkGHd/IAoqb0pxjQgYHwAGN3ikXvb+QFlS9ohi7sfUJD
         RFo7iyz7k6EBnWgZ0iyKS+X+2FtnPoQLeDZunBDX5D5d4qpYQgC0vXrtAvOklxvc0gnh
         rhzUptR2ahh8Z56XZRbbYgzVAQQ+mnob9+Cm/iyOh/zMHq3t0ORjZLQpeWuNaUjhbsgh
         +OncIkWAZOvgC/VZz+jpVPFjOMNDpD6Hjwk3uQHG5z2HZZZtnDkS2koshN59fUSxYxDR
         K9Mg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWmwT49NNTDLTHw1Tw8jdyYfzW3zv5qwKrmfMYqfDsYdz784U2lT7NwftKitZKw2bpodAnoXQ==@lfdr.de
X-Gm-Message-State: AOJu0YwV0dya9RzmG0sJlle2hyO+E/dhAyrSAW6GoPpdhS9mVuY61eDg
	Pz2GXROw9EBW7sOyIZXyD3zAvAr+r8bWtdk73GFZxNhB+xTTniIX
X-Google-Smtp-Source: AGHT+IHMHpvZKTxqXD33XwpPUf5s7fbX1wLB8uD6DF7ty+f9N/55y3F3MZXM8/AKF2M4BOoh8x5lVA==
X-Received: by 2002:a17:90a:cf8e:b0:2e2:bd34:f23b with SMTP id 98e67ed59e1d1-2e5618d0f5emr13578123a91.32.1729540713889;
        Mon, 21 Oct 2024 12:58:33 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:f3d8:b0:2e1:9254:6f09 with SMTP id
 98e67ed59e1d1-2e3dbf38b17ls3368763a91.0.-pod-prod-04-us; Mon, 21 Oct 2024
 12:58:33 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCV5PdFg7DP/1fCAVh0ZNEaaWd9dgyC00KPhWXO2jNAfrs6mEYUTnJyBqrAlIOlBtokLLgtE1ARf970=@googlegroups.com
X-Received: by 2002:a17:90a:9c8:b0:2d3:c9bb:9cd7 with SMTP id 98e67ed59e1d1-2e5619f6ca6mr15277794a91.36.1729540712715;
        Mon, 21 Oct 2024 12:58:32 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1729540712; cv=none;
        d=google.com; s=arc-20240605;
        b=dYAOi6Xz0+pNGYslMlPO+QUjT/7o8fKW/bgFife28QRqM+82OIJswX3WkEsPF1pC1t
         xvgEOjdFrw0BwvuAI9aKhKORLcEHZANa/EE0DPX7yAgwwbSla8jJWOl7JeG3x+7lo4QU
         Rz0zzMHTPzsuRaE7x1AKN06JRRTuJGHOks4pjlho18hxatGe4IqR/bTCU8YuRW2+rLUU
         zRHWslgauSQds51z8OwbM8Bo03plIlLRu+TITmx5S7VO5LpzoExCTUF6ezmIh8mhw6PS
         tkjW0391ClNI6lvfIiVQy45Lda4/zDPAspbxChLDJNi0jNJwe5welPf5hc4gxDLK17Ig
         DSaw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=j/FgF0DU7rN81tqNTOqqY5AogDEl5GSNKz8OuW5qCJA=;
        fh=3gHECPXPOvWoWfm6IrAYmoQo9XRy/wDkEIjADmwHYJQ=;
        b=BsO8zXmyqhz5/UOVCmDAgPJu6JVYp1N7sw1edeatqTXNK6TQJm8GB8hyo/C4b9FyhY
         /VySEVClS7xGYZUyF/jrvKKkWIaSdVEeenzHify1SVH6eT2TRYkl/VbcGNJBwLJvG3et
         B/VeI6NoPZsTrOdz3odhmJ8MKQZNuvt7zJumkm+FhSo5YD42xCQvfUx202A/Ence0Yvh
         QPW8vjiXdo7ILNz5S3KCOZtYN0hUcc26nRujTc0H1UtCuuwW/ZHQHs0ThYuUvoHFxBBh
         8oLPF7YhCLWJ9Sre2uTN2PT+AorswMlHrF/NGFkQiRqNI2Kv4cjBSfu5/1lnBNgolX6c
         ltDg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=EDl6LlRq;
       spf=pass (google.com: domain of niharchaithanya@gmail.com designates 2607:f8b0:4864:20::436 as permitted sender) smtp.mailfrom=niharchaithanya@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pf1-x436.google.com (mail-pf1-x436.google.com. [2607:f8b0:4864:20::436])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-2e5df404325si394a91.0.2024.10.21.12.58.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 21 Oct 2024 12:58:32 -0700 (PDT)
Received-SPF: pass (google.com: domain of niharchaithanya@gmail.com designates 2607:f8b0:4864:20::436 as permitted sender) client-ip=2607:f8b0:4864:20::436;
Received: by mail-pf1-x436.google.com with SMTP id d2e1a72fcca58-71e5f526645so273603b3a.2
        for <kasan-dev@googlegroups.com>; Mon, 21 Oct 2024 12:58:32 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXwr0ooJMVe1wKyk39bZGoTMy8LtTAwJq0HpoFcJk1csvjmJEgQ9uoGIJjgOFuFvFH11I455dFK5Sg=@googlegroups.com
X-Received: by 2002:a05:6a00:2e24:b0:71e:66bb:d33b with SMTP id d2e1a72fcca58-71ea3129093mr7659113b3a.1.1729540712152;
        Mon, 21 Oct 2024 12:58:32 -0700 (PDT)
Received: from ice.. ([171.76.87.28])
        by smtp.gmail.com with ESMTPSA id d2e1a72fcca58-71ec1312cd8sm3292796b3a.31.2024.10.21.12.58.28
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 21 Oct 2024 12:58:31 -0700 (PDT)
From: Nihar Chaithanya <niharchaithanya@gmail.com>
To: ryabinin.a.a@gmail.com
Cc: glider@google.com,
	andreyknvl@gmail.com,
	dvyukov@google.com,
	elver@google.com,
	skhan@linuxfoundation.org,
	kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org,
	Nihar Chaithanya <niharchaithanya@gmail.com>
Subject: [PATCH v2] kasan:report: filter out kasan related stack entries
Date: Tue, 22 Oct 2024 01:27:15 +0530
Message-Id: <20241021195714.50473-1-niharchaithanya@gmail.com>
X-Mailer: git-send-email 2.34.1
MIME-Version: 1.0
X-Original-Sender: niharchaithanya@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=EDl6LlRq;       spf=pass
 (google.com: domain of niharchaithanya@gmail.com designates
 2607:f8b0:4864:20::436 as permitted sender) smtp.mailfrom=niharchaithanya@gmail.com;
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
	- The get_stack_skipnr() function is included to get the number of
	  stack entries to be skipped for filtering the stack-trace.

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

Note:
When using sanitize_stack_entries() the output was innacurate for free and
alloc tracks, because of the missing ip value in print_track().
The buffer size in get_stack_skipnr() is increase as it was too small when
testing with some KASAN uaf bugs which included free and alloc tracks.

 mm/kasan/report.c | 62 ++++++++++++++++++++++++++++++++++++++++++-----
 1 file changed, 56 insertions(+), 6 deletions(-)

diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index b48c768acc84..e00cf764693c 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -261,6 +261,59 @@ static void print_error_description(struct kasan_report_info *info)
 			info->access_addr, current->comm, task_pid_nr(current));
 }
 
+/* Helper to skip KASAN-related functions in stack-trace. */
+static int get_stack_skipnr(const unsigned long stack_entries[], int num_entries)
+{
+	char buf[128];
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
+/*
+ * Use in place of stack_dump_lvl to filter KASAN related functions in
+ * stack_trace.
+ */
+static void kasan_dump_stack_lvl(void)
+{
+	unsigned long stack_entries[KASAN_STACK_DEPTH] = { 0 };
+	int num_stack_entries = stack_trace_save(stack_entries, KASAN_STACK_DEPTH, 1);
+	int skipnr = get_stack_skipnr(stack_entries, num_stack_entries);
+
+	dump_stack_print_info(KERN_ERR);
+	stack_trace_print(stack_entries + skipnr, num_stack_entries - skipnr, 0);
+	pr_err("\n");
+}
+
+/*
+ * Use in place of stack_depot_print to filter KASAN related functions in
+ * stack_trace.
+ */
+static void kasan_stack_depot_print(depot_stack_handle_t stack)
+{
+	unsigned long *entries;
+	unsigned int nr_entries;
+
+	nr_entries = stack_depot_fetch(stack, &entries);
+	int skipnr = get_stack_skipnr(entries, nr_entries);
+
+	if (nr_entries > 0)
+		stack_trace_print(entries + skipnr, nr_entries - skipnr, 0);
+}
+
 static void print_track(struct kasan_track *track, const char *prefix)
 {
 #ifdef CONFIG_KASAN_EXTRA_INFO
@@ -277,7 +330,7 @@ static void print_track(struct kasan_track *track, const char *prefix)
 	pr_err("%s by task %u:\n", prefix, track->pid);
 #endif /* CONFIG_KASAN_EXTRA_INFO */
 	if (track->stack)
-		stack_depot_print(track->stack);
+		kasan_stack_depot_print(track->stack);
 	else
 		pr_err("(stack is not available)\n");
 }
@@ -374,9 +427,6 @@ static void print_address_description(void *addr, u8 tag,
 {
 	struct page *page = addr_to_page(addr);
 
-	dump_stack_lvl(KERN_ERR);
-	pr_err("\n");
-
 	if (info->cache && info->object) {
 		describe_object(addr, info);
 		pr_err("\n");
@@ -484,11 +534,11 @@ static void print_report(struct kasan_report_info *info)
 		kasan_print_tags(tag, info->first_bad_addr);
 	pr_err("\n");
 
+	kasan_dump_stack_lvl();
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20241021195714.50473-1-niharchaithanya%40gmail.com.
