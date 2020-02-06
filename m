Return-Path: <kasan-dev+bncBC7OBJGL2MHBBGXM6DYQKGQEWW55QEI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43c.google.com (mail-wr1-x43c.google.com [IPv6:2a00:1450:4864:20::43c])
	by mail.lfdr.de (Postfix) with ESMTPS id BE119154882
	for <lists+kasan-dev@lfdr.de>; Thu,  6 Feb 2020 16:51:54 +0100 (CET)
Received: by mail-wr1-x43c.google.com with SMTP id u8sf3631126wrp.10
        for <lists+kasan-dev@lfdr.de>; Thu, 06 Feb 2020 07:51:54 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1581004314; cv=pass;
        d=google.com; s=arc-20160816;
        b=aivCfZov0dqymNPHoos+cbVU7xTvteevXN3lc1itzLumpcEB3xr06SYrmmZeNnWEsT
         brDY8+P2v+Uliit5DIkrb2J27N2YSZoHSD4FR3gVKL22jRn8g22qojSoXBbuSayRMfbN
         uHG6sTMbn/MOWcHgUIhTP7B40XpO81Ko9jqgc1B8QsT3oZ02g5GJ9EyVQePEQaFn/KX2
         TarJomap8VxPFGC3zHt1XQJOmO3KDn2OgWP3iMHiGGMEVDYk/iKgGPxi6NueJjS1b7k1
         pPPwDDogUbh1DqxMtRUcsP+R7bEOsBv1jBAZfug/RSS6SdphK3i0nWdzTuu/zA2eAZG/
         k2ng==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=7e7HF5sfAOWLldePwdk01Nlpkj+/l88zDi2BuNIKG20=;
        b=WaR8vDbBm+Xx/AE2St3v0K20IzKFvmRppeDZQ8fcgL9cOCEi0EK0yfBSke19yXbKa0
         sakeBekEzO458t3uznTfiqO89P/zGR36nz/sXtIVYNQghgEFl9tntTwNROK2f52bTD09
         WFjxb1AT+Zn32acC5fg0bbQd6Oek1dqz0k0FkEcRGu5tFugMeZgd4qHCmR4TsBJLdfm5
         Sis0IMoBHLUW9/zZy87jgVa/9Arq8mtYqWcD6XVCOFO1A/+EDo++KeAPnO7AE9P0qUZB
         OoAqZmM1+DPIWHoKGYTG4+ep7mlEM54wX6Hs4pOYmhe7BI+BuZr87gebytImxjr7xIXw
         YVLQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=fS6WBSvH;
       spf=pass (google.com: domain of 3gty8xgukcw4qxhqdsaasxq.oaywmemz-pqhsaasxqsdagbe.oay@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3GTY8XgUKCW4QXhQdSaaSXQ.OaYWMeMZ-PQhSaaSXQSdagbe.OaY@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=7e7HF5sfAOWLldePwdk01Nlpkj+/l88zDi2BuNIKG20=;
        b=C+PG0eRzfY8VvrJY9vyFx3nBcyogB1oe8ktlnGye/YvoZPwEs4cWzrFS6D67JqnQuG
         vBXizpQpAzNUVyFDGpxYsV8rxyhvKb5KAMuAShjqtTTAdWVR68BjFhS5QWLwEFiooRxP
         2DO/aTaDi89WBeZmyZuLHacSArdeDWLCkWIHfWq07aO1nOATL3swnGBuOF993U11T5yh
         ViTj2BN5jqNDJRWIgm87mgPwMOyHsLVACC22MsKBFn50ftidVQjBQrAofxunSyQRJ9fR
         KMaaZRWpNr/QIUHX8g2bkR4zW4E1S+Wj/fHTUYM3nyeoUle/gzj1WaGPbF2A5su9ujqa
         ro6Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=7e7HF5sfAOWLldePwdk01Nlpkj+/l88zDi2BuNIKG20=;
        b=ZMHUfsTXPx2aflyd4KLxPRzeQCNh1zA7N0IgKB+koXS/R+HOhEF6S6eDotcqBNrJx+
         pi5xUa0ictqkSAqlfZHVnOlvA1oSVCTpFCsCnZJD4//rql2xmTLxmDh+qbt4cLOnd0+k
         oSDU4SssorOws/yGUVW5UWNPWTPO6qupu77byB2uEzghN90YQDYB+8vJOAFSpHgCgNDR
         0SGMO8wMSgZTwb8ideU/pRnpKnfNvMt3I1JUzcyi4ovUWlMVX14yyW5LZfrP96jJhNZU
         Ol4y5i4dPjo+tahyj3yYeJR2d/cIQVDUv9VxHJcMxP0k4miIIZrf4RVRaVNTF7s3m4VK
         wTxQ==
X-Gm-Message-State: APjAAAVHJ6sP9nuoveZxlGTy8IurbQViYtSki/H+nafLTjcvSisqAbiq
	RGrCbtj9oBRgPPHmPSEiXPs=
X-Google-Smtp-Source: APXvYqzwtdZdcBsl0JdlHBcHbG46VW+opcCr3Pcy4QXSqxpgxCLYyJAxtkFPUtU724/GQcT6mhoAJg==
X-Received: by 2002:a5d:5273:: with SMTP id l19mr4674980wrc.175.1581004314534;
        Thu, 06 Feb 2020 07:51:54 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:65d0:: with SMTP id e16ls4093381wrw.1.gmail; Thu, 06 Feb
 2020 07:51:53 -0800 (PST)
X-Received: by 2002:adf:f802:: with SMTP id s2mr4694431wrp.201.1581004313921;
        Thu, 06 Feb 2020 07:51:53 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1581004313; cv=none;
        d=google.com; s=arc-20160816;
        b=rXtq2b5xfAcJ5N4llrDzh3J5wZivKuuvu+ZRcRyoaLRK2sX3EwdNW+nh635G26VLLD
         KGhUXjMsVc6/gUPl2ysbHNqmks5UuGwny5ytdE8bzAEUopDglZav9QfswpTrFNr+maDs
         lR8TmwOwLfACYMSLQlTuHM5jpe+tHUjF5ymUwccojOzb+1IMZ9YQKnrAXBuR1nVERQD8
         8nIcQ52BBPiBrEzQBnUsFcGroOBTIggKtzF5FVV1pc+Im+w2c7DjtIkOI+wzdpMdb2bd
         b2N1hcSvw2C5y9g9Ywp8D8e/VuQEK1SrblVKJSaI/OYhbR0+EpgSYVctkgUBGqanyDNX
         w54w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=dJMzj3shZa2WtTpFPhLyRyZzYBIlQLsl5gnyIHG8III=;
        b=SpjiZHQTkhogcWOUm5Pw9j5RIrE/cLpH+j0A8qKl9hBqeYLFBDsPm1bbpx4KvkMd3v
         Z2YqTkJO2sxQEM4HLaECKlW5HRnZ78ZSZu3oxyGWmZ7ZyUcj7UIZQy/GuKhC4IrxJtfw
         KmdkttkxX9sHvQuJI3XIukdKvDR362ZoVV7KF7+IdCfnbiwL23p6AlDV0tfUuUElDklz
         VuMcgg1G2qtYgLu6RbTsAaZm35MlM5g6t9HEj/d4PlXklDzdS0qKJwPWYWQIGAXHgcmm
         vuj4wUJg3MwvITnU6CzvOvhf8oHtUtci3E38c/kuh/UoYWyU3jymHvH8txMHdiN0F78y
         4wCg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=fS6WBSvH;
       spf=pass (google.com: domain of 3gty8xgukcw4qxhqdsaasxq.oaywmemz-pqhsaasxqsdagbe.oay@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3GTY8XgUKCW4QXhQdSaaSXQ.OaYWMeMZ-PQhSaaSXQSdagbe.OaY@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x349.google.com (mail-wm1-x349.google.com. [2a00:1450:4864:20::349])
        by gmr-mx.google.com with ESMTPS id e21si606541wme.1.2020.02.06.07.51.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 06 Feb 2020 07:51:53 -0800 (PST)
Received-SPF: pass (google.com: domain of 3gty8xgukcw4qxhqdsaasxq.oaywmemz-pqhsaasxqsdagbe.oay@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) client-ip=2a00:1450:4864:20::349;
Received: by mail-wm1-x349.google.com with SMTP id 205so193638wmc.6
        for <kasan-dev@googlegroups.com>; Thu, 06 Feb 2020 07:51:53 -0800 (PST)
X-Received: by 2002:a5d:4692:: with SMTP id u18mr4511821wrq.206.1581004313452;
 Thu, 06 Feb 2020 07:51:53 -0800 (PST)
Date: Thu,  6 Feb 2020 16:46:26 +0100
In-Reply-To: <20200206154626.243230-1-elver@google.com>
Message-Id: <20200206154626.243230-3-elver@google.com>
Mime-Version: 1.0
References: <20200206154626.243230-1-elver@google.com>
X-Mailer: git-send-email 2.25.0.341.g760bfbb309-goog
Subject: [PATCH v2 3/3] kcsan: Add test to generate conflicts via debugfs
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com
Cc: paulmck@kernel.org, andreyknvl@google.com, glider@google.com, 
	dvyukov@google.com, kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=fS6WBSvH;       spf=pass
 (google.com: domain of 3gty8xgukcw4qxhqdsaasxq.oaywmemz-pqhsaasxqsdagbe.oay@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3GTY8XgUKCW4QXhQdSaaSXQ.OaYWMeMZ-PQhSaaSXQSdagbe.OaY@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

Add 'test=<iters>' option to KCSAN's debugfs interface to invoke KCSAN
checks on a dummy variable. By writing 'test=<iters>' to the debugfs
file from multiple tasks, we can generate real conflicts, and trigger
data race reports.

Signed-off-by: Marco Elver <elver@google.com>
---
 kernel/kcsan/debugfs.c | 51 +++++++++++++++++++++++++++++++++++++-----
 1 file changed, 46 insertions(+), 5 deletions(-)

diff --git a/kernel/kcsan/debugfs.c b/kernel/kcsan/debugfs.c
index a9dad44130e62..9bbba0e57c9b3 100644
--- a/kernel/kcsan/debugfs.c
+++ b/kernel/kcsan/debugfs.c
@@ -6,6 +6,7 @@
 #include <linux/debugfs.h>
 #include <linux/init.h>
 #include <linux/kallsyms.h>
+#include <linux/sched.h>
 #include <linux/seq_file.h>
 #include <linux/slab.h>
 #include <linux/sort.h>
@@ -69,9 +70,9 @@ void kcsan_counter_dec(enum kcsan_counter_id id)
 /*
  * The microbenchmark allows benchmarking KCSAN core runtime only. To run
  * multiple threads, pipe 'microbench=<iters>' from multiple tasks into the
- * debugfs file.
+ * debugfs file. This will not generate any conflicts, and tests fast-path only.
  */
-static void microbenchmark(unsigned long iters)
+static noinline void microbenchmark(unsigned long iters)
 {
 	cycles_t cycles;
 
@@ -81,18 +82,52 @@ static void microbenchmark(unsigned long iters)
 	while (iters--) {
 		/*
 		 * We can run this benchmark from multiple tasks; this address
-		 * calculation increases likelyhood of some accesses overlapping
-		 * (they still won't conflict because all are reads).
+		 * calculation increases likelyhood of some accesses
+		 * overlapping. Make the access type an atomic read, to never
+		 * set up watchpoints and test the fast-path only.
 		 */
 		unsigned long addr =
 			iters % (CONFIG_KCSAN_NUM_WATCHPOINTS * PAGE_SIZE);
-		__kcsan_check_read((void *)addr, sizeof(long));
+		__kcsan_check_access((void *)addr, sizeof(long), KCSAN_ACCESS_ATOMIC);
 	}
 	cycles = get_cycles() - cycles;
 
 	pr_info("KCSAN: %s end   | cycles: %llu\n", __func__, cycles);
 }
 
+/*
+ * Simple test to create conflicting accesses. Write 'test=<iters>' to KCSAN's
+ * debugfs file from multiple tasks to generate real conflicts and show reports.
+ */
+static long test_dummy;
+static noinline void test_thread(unsigned long iters)
+{
+	const struct kcsan_ctx ctx_save = current->kcsan_ctx;
+	cycles_t cycles;
+
+	/* We may have been called from an atomic region; reset context. */
+	memset(&current->kcsan_ctx, 0, sizeof(current->kcsan_ctx));
+
+	pr_info("KCSAN: %s begin | iters: %lu\n", __func__, iters);
+
+	cycles = get_cycles();
+	while (iters--) {
+		__kcsan_check_read(&test_dummy, sizeof(test_dummy));
+		__kcsan_check_write(&test_dummy, sizeof(test_dummy));
+		ASSERT_EXCLUSIVE_WRITER(test_dummy);
+		ASSERT_EXCLUSIVE_ACCESS(test_dummy);
+
+		/* not actually instrumented */
+		WRITE_ONCE(test_dummy, iters);  /* to observe value-change */
+	}
+	cycles = get_cycles() - cycles;
+
+	pr_info("KCSAN: %s end   | cycles: %llu\n", __func__, cycles);
+
+	/* restore context */
+	current->kcsan_ctx = ctx_save;
+}
+
 static int cmp_filterlist_addrs(const void *rhs, const void *lhs)
 {
 	const unsigned long a = *(const unsigned long *)rhs;
@@ -242,6 +277,12 @@ debugfs_write(struct file *file, const char __user *buf, size_t count, loff_t *o
 		if (kstrtoul(&arg[sizeof("microbench=") - 1], 0, &iters))
 			return -EINVAL;
 		microbenchmark(iters);
+	} else if (!strncmp(arg, "test=", sizeof("test=") - 1)) {
+		unsigned long iters;
+
+		if (kstrtoul(&arg[sizeof("test=") - 1], 0, &iters))
+			return -EINVAL;
+		test_thread(iters);
 	} else if (!strcmp(arg, "whitelist")) {
 		set_report_filterlist_whitelist(true);
 	} else if (!strcmp(arg, "blacklist")) {
-- 
2.25.0.341.g760bfbb309-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200206154626.243230-3-elver%40google.com.
