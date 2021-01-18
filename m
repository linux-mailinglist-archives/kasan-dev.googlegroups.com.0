Return-Path: <kasan-dev+bncBCOYZDMZ6UMRBX5HS6AAMGQE66SUY6A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x437.google.com (mail-pf1-x437.google.com [IPv6:2607:f8b0:4864:20::437])
	by mail.lfdr.de (Postfix) with ESMTPS id 75AC02FA8D9
	for <lists+kasan-dev@lfdr.de>; Mon, 18 Jan 2021 19:30:56 +0100 (CET)
Received: by mail-pf1-x437.google.com with SMTP id 137sf11424446pfw.4
        for <lists+kasan-dev@lfdr.de>; Mon, 18 Jan 2021 10:30:56 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610994655; cv=pass;
        d=google.com; s=arc-20160816;
        b=qP6MiRwqDnErDbB9NKxUvw/UmneuLhnpOyk8pfRvbykSNwxbed+emniBBk7KUP+6Zc
         7BqS1zRxyOfSVZsnafjgHL+Cqr4VJA1+A3x0UdNdMBGPSZG5Wpk6UhBluUzlzEuqbrM6
         r+OdmL1rmrj/grXvx2nL0XZMiFO2LCly+WJPHB7KvqTzoIaxryShlMROt5br3Id/6S/k
         Cu88UP4kF2cG9wt+6WIM1LuWps5gen7i6Mjtv4u/62qEEPJiZqHoVE+WV8kEzsHqs4jS
         T1msky8OA5Vch671ZvT9jgZv9UW78SgAx0SHZ8Ml5RTPu6RwSpCjU5rSHqPMUqkO2aBY
         3ReQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=CgadMHNHkZgT7gy52FDCQ8FBidHsxlU2u+n7DkbgkKA=;
        b=FCuKtZaPB5lcbmqXOH2ad2aorlF2uKO/kS9PNgMJl+hjHtugdS5cToJrlH/z1RgL1M
         mSiC8bFv8ljsqC0f1dVK9VehwWZvftelHCuQ95rsDQ1CRah1sOHG9O4XjEEBSAok7Yl2
         pDfxpf8rtVk2cRhbI55yGXsLmq1R1aB7cFKSnFNWAolhJ/Ez8Q3PZ+jLk5I8PhCff1Bt
         mw2PPAo4SvVlOkxCFmFbNb3/QUaXlTUKdLvDh7M+YVR9jGe143XNNir2oxRzUI2xdv9w
         OEW0XJV+LUJ6Z3rczzb5bxuqpHUyKSnngZE2Ocly02RpyRJMih7e/fSBS2vaNU/RWQDU
         owBA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=CgadMHNHkZgT7gy52FDCQ8FBidHsxlU2u+n7DkbgkKA=;
        b=nsm9LF5DyszszdfUkGb5YVxo6s6SGS7c9jeKaxVq08OoWxJsT4kEXhsQ1bZzgmwKDr
         YS+O7j7QhrUsV42IrtNY3tn+ylRIfEYq6JQpj91xhW7h0EIqfIAAbFnPRjarHFfsAAxE
         mRqTrfofzRO/uexNjPW/xz+xr3L2AJHfN6aq6b6e7geup+fp/Am4Wq0BCq3R1yaQ5XMv
         lN/ze74uxNfAwhrcm2VfTvlruLeHw9p9yHPW+2+lUi0eagzHYs8top0R4UoGiW6HBvi3
         mYRKYbf2QuWBhK3tHaxLijDhrR9fwQMq6+XFZfuKWKudV5+AXcJeWkNd5lrU74pcYh9N
         8Q9w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=CgadMHNHkZgT7gy52FDCQ8FBidHsxlU2u+n7DkbgkKA=;
        b=ALW60mKs4Y5zQTa3ETNhGoXTLpE0+w/3wjqH1Mrt7zpWh/JqcZ+O6/YNuPSlxnwI/t
         cxEPmaYEuIVfU+BOB405q2pgRemSllHalWJ36wt+EWnZ1ayEpafSRePpPCNhZQN70THb
         /z/lQ8eu3hhTq6nstHzog2etDiX4cyTs+Ig2uBZL01P+Es39yjX1PlVI21ZnNH5l5xvq
         Q1f+N/W3suWEnGZd7uou0w59lsM9lLoL4Ya3P+4+9ZFL9G4c1x2k088xwhBmZAquURCS
         xYlvUQOtlXd/NsY3ENbLeTH4rwfDGgHBNwC/g+TpzTfoFCbscg8zq4ndpNOxeetd3cni
         Vs2Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531P59On/TlC/QxnC9os5tUpDqeVrTNAxP28ehXeO1eZx2b4/3No
	+DPtcpnhm+mbCG6k/7/iVF8=
X-Google-Smtp-Source: ABdhPJyY3ePaKEDYrscS9PEY3AlhAkGz0paplK8cKRNKowzb7/32OTTIX4RUAwlF2D/ii7xQoMEXEg==
X-Received: by 2002:a62:17c3:0:b029:19d:ce3b:d582 with SMTP id 186-20020a6217c30000b029019dce3bd582mr704990pfx.18.1610994655156;
        Mon, 18 Jan 2021 10:30:55 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:6d0e:: with SMTP id i14ls6729648pgc.8.gmail; Mon, 18 Jan
 2021 10:30:54 -0800 (PST)
X-Received: by 2002:a63:174f:: with SMTP id 15mr907135pgx.49.1610994654499;
        Mon, 18 Jan 2021 10:30:54 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610994654; cv=none;
        d=google.com; s=arc-20160816;
        b=yIOIXMIaN6Klwdfsz+Hh6paWw1ZYmys6mvv35Om+3jyD5CwnxL+kcrgxUglm9B/Sxg
         Cr0uaUuTjLZF2vA0p36zsI9NWSF0H23QPA9SJQ241n17OXcKaVTZLg7Ov5zkR76hZlio
         8U8kky2+1Jf0G+FWRj22Tb/vnJu4psLb6bER3aO7s3m8b/Not4bTLqItXoFelm8hoa0X
         T8+DEsgzxqffcBNt/5N/L7IOiKjefVy2yXVDI/DZXq2BDoE37a2JQlaBgWi2UswmEVQB
         8EoO9j9iquMfSlClPpsr0HvIg2rIiWXjX+4pznVbPztAm7+l7pPzefAEAQQypPow4kLA
         358Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=5v6Ic5HvSMngfy9JNOjF0jX1d9tc0QXcpONWYgJUYAk=;
        b=mFzS5G8syCr6CNfKWR7lzA+1lh1Ne88P7andV2QtsiOi3aib5Dpzc1l4SCqd1FCLco
         tCNgQENvtVvPFXtzwyvyoPwkMOaJDsBLU76WDSBWtcoABk3KGC5GJmNu3kmvvQB4OAkF
         Rwvs2awrTgo8ViN3hLAI/dwe0s3fhHMVf5KyodjT95Rt1jSLZEvOGZzJsEnHeho5w4zi
         +AJzgIwZfjVHtTAdcrF+dyZww21WRe/CyrUBFshBlIEuTLYTaq8I1Yer46mOo8GQ4kPr
         M9oW8WBCii2/0lxfXqy90w0rYsyqDhNRPjVvj3emoajNFW/wWIXd6j1XE2ngiIDUFInx
         MlOg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id d1si10860pjo.1.2021.01.18.10.30.54
        for <kasan-dev@googlegroups.com>;
        Mon, 18 Jan 2021 10:30:54 -0800 (PST)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id B3F6C101E;
	Mon, 18 Jan 2021 10:30:53 -0800 (PST)
Received: from e119884-lin.cambridge.arm.com (e119884-lin.cambridge.arm.com [10.1.196.72])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 152DE3F719;
	Mon, 18 Jan 2021 10:30:51 -0800 (PST)
From: Vincenzo Frascino <vincenzo.frascino@arm.com>
To: linux-arm-kernel@lists.infradead.org,
	linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com
Cc: Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will@kernel.org>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Branislav Rankov <Branislav.Rankov@arm.com>,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH v4 3/5] kasan: Add report for async mode
Date: Mon, 18 Jan 2021 18:30:31 +0000
Message-Id: <20210118183033.41764-4-vincenzo.frascino@arm.com>
X-Mailer: git-send-email 2.30.0
In-Reply-To: <20210118183033.41764-1-vincenzo.frascino@arm.com>
References: <20210118183033.41764-1-vincenzo.frascino@arm.com>
MIME-Version: 1.0
X-Original-Sender: vincenzo.frascino@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172
 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
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

KASAN provides an asynchronous mode of execution.

Add reporting functionality for this mode.

Cc: Dmitry Vyukov <dvyukov@google.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
Cc: Alexander Potapenko <glider@google.com>
Cc: Andrey Konovalov <andreyknvl@google.com>
Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
---
 include/linux/kasan.h |  3 +++
 mm/kasan/report.c     | 16 ++++++++++++++--
 2 files changed, 17 insertions(+), 2 deletions(-)

diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index fe1ae73ff8b5..8f43836ccdac 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -336,6 +336,9 @@ static inline void *kasan_reset_tag(const void *addr)
 bool kasan_report(unsigned long addr, size_t size,
 		bool is_write, unsigned long ip);
 
+bool kasan_report_async(unsigned long addr, size_t size,
+			bool is_write, unsigned long ip);
+
 #else /* CONFIG_KASAN_SW_TAGS || CONFIG_KASAN_HW_TAGS */
 
 static inline void *kasan_reset_tag(const void *addr)
diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index c0fb21797550..946016ead6a9 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -388,11 +388,11 @@ static void __kasan_report(unsigned long addr, size_t size, bool is_write,
 	start_report(&flags);
 
 	print_error_description(&info);
-	if (addr_has_metadata(untagged_addr))
+	if (addr_has_metadata(untagged_addr) && (untagged_addr != 0))
 		print_tags(get_tag(tagged_addr), info.first_bad_addr);
 	pr_err("\n");
 
-	if (addr_has_metadata(untagged_addr)) {
+	if (addr_has_metadata(untagged_addr) && (untagged_addr != 0)) {
 		print_address_description(untagged_addr, get_tag(tagged_addr));
 		pr_err("\n");
 		print_memory_metadata(info.first_bad_addr);
@@ -419,6 +419,18 @@ bool kasan_report(unsigned long addr, size_t size, bool is_write,
 	return ret;
 }
 
+bool kasan_report_async(unsigned long addr, size_t size,
+			bool is_write, unsigned long ip)
+{
+	pr_info("==================================================================\n");
+	pr_info("KASAN: set in asynchronous mode\n");
+	pr_info("KASAN: some information might not be accurate\n");
+	pr_info("KASAN: fault address is ignored\n");
+	pr_info("KASAN: write/read distinction is ignored\n");
+
+	return kasan_report(addr, size, is_write, ip);
+}
+
 #ifdef CONFIG_KASAN_INLINE
 /*
  * With CONFIG_KASAN_INLINE, accesses to bogus pointers (outside the high
-- 
2.30.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210118183033.41764-4-vincenzo.frascino%40arm.com.
