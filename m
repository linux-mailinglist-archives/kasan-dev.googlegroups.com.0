Return-Path: <kasan-dev+bncBCJZRXGY5YJBB5NARKFAMGQEK4LQ5WA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43f.google.com (mail-pf1-x43f.google.com [IPv6:2607:f8b0:4864:20::43f])
	by mail.lfdr.de (Postfix) with ESMTPS id 11AF340D0E5
	for <lists+kasan-dev@lfdr.de>; Thu, 16 Sep 2021 02:31:51 +0200 (CEST)
Received: by mail-pf1-x43f.google.com with SMTP id s22-20020a056a001c5600b0041028eb25a5sf3299925pfw.12
        for <lists+kasan-dev@lfdr.de>; Wed, 15 Sep 2021 17:31:50 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1631752309; cv=pass;
        d=google.com; s=arc-20160816;
        b=So+viuWMDSBK2LmKVZ3TIzd69crEfZlc1zlGq8gxdXrvS1BVusPqq0gVmeyKi/fUdg
         6omxgWpAR48BlwIqutl9VmPvvqd1HpQNaUoWxbeAYwUgh70VNuNm4UgOR2/DFBOsnC8l
         3vM/EYUYLtvW617v43k3lAAYU1+FS42dj6K7E/fWiJgqdWMZoRuFVqvrb0pu1gFH0pSF
         wN9W+7leHHOLidWiFjaApukpMO14humnsweki+wR1eNs11YG5e/j3OZ2xxCE8nkNjPaG
         nKupR7Pkq8Xuj9VGTolgx+GPtWSwHwhcCsx3Ak7fp2Wlx0RIjhPNBBY8ILZgs/Czg+FR
         XzgA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=QZM/pc7X3vZY8I9LkCr6mAOpkuyQ61owX28ouRCg4uM=;
        b=mx1C6GG6PUEPAnxxqFhr4uVNpqEnNJkoZu4t/Z2cc/6YxjeSiQGp/dZVXQC1HJwj88
         T0+Dw8saRm5pkk2J9L7h9GlrkvVRgFclDlUXY31/d9R6+M5MEboRZu+sF1+5VF5tFPA+
         91pPrNxVw4/hXyMRivH5Qb/1HhO2RckEe5+qT9hugH5Bq9MJkTivBKNZfLIrCX7m+BlM
         HXYqEQIPjdDf/1SAWc2zc+JCktwUQJ3/5M7ceEaFViCPS9zt48IV7KRRBR7j47/PebgI
         jiFWXE4/x7xcPI/ygLW56QUa7EVICYDSPMmVbv9HeeYCoAJ6zC1OFMUpe3Zg2XNA34Bt
         L6tg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=eM24mmhI;
       spf=pass (google.com: domain of srs0=j1cw=og=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=J1Cw=OG=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=QZM/pc7X3vZY8I9LkCr6mAOpkuyQ61owX28ouRCg4uM=;
        b=fAdovBFYc0f0s4jV/q/MAha/Ok7YfcXi4UR0XcuMaBY/v0/L6q15OcdOMcvNXPy270
         ir7OwGpOnj8gGr39AHd4FhpT9r62v3Jwd6pO0r65Kn2KHG4iyPL1WXtvB/53S41rEMl+
         EByixGRG+ZOCd9cUbsOJr13G4/Yzlzd0yWS/wklWeVc7IPuN4cqwlm58qiLqc+2LiKMI
         yltVzMcXVTmPA4j/0aWgaxz6H7N6pvV//5KdlkLGCaL5OaGAqFbG9s1Z+6y7a6qnT7e0
         4t5fuUrb0J/Nt2+XCsfDlqFOWnBsY4aIo6lxqEHm/d/4qUX4aU0XQe5P2KF/Tsh7jNaN
         hsig==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=QZM/pc7X3vZY8I9LkCr6mAOpkuyQ61owX28ouRCg4uM=;
        b=u7WzereUNHaY8wTbrL3ZMsHNP0DwtLHw+lAS059JzyAXj1jHYaaoRovDCUL38LuTNo
         wnCxq5T6xQieGv/ck5tM9voR5UmlXK3v8UXpUnqNf0Q35Q88YWlNeMuGx2kmVVYa6sFN
         uyc4/4EjhPlR40DsSMzGtOEoMWIG35PS+AMwfqrrrTjHPTvCAcx0hmcaeJJz05jhG2Pt
         N0x5h2jiWPYqnRKwkQFJhrnejn+VpFE44XkQZXEAa9VTkkfN3WY2+fpuh5Azw+6O61ap
         DS//z8pN5+8/J4518vNX5kT1uyZeXV2l12Q1AU9F+nXrzSlDGSB7z9UYaenUdEwlIaUZ
         6xHA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530J9TYfFEH+OV+XvXGQ3KIG8gassBaOKLPfJyqyDh9o0PDsEPb+
	xTuIwHtic3bMLe6C//2P4MU=
X-Google-Smtp-Source: ABdhPJzYEPgVDopnfmuhZZX0q8JajGf2k7ztccO1e8Gz1/s3kS4bzXZY4D7NPq6mea+NTnLVF76xGQ==
X-Received: by 2002:a17:903:31c2:b0:13c:9de8:d314 with SMTP id v2-20020a17090331c200b0013c9de8d314mr2042177ple.1.1631752309355;
        Wed, 15 Sep 2021 17:31:49 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:4e24:: with SMTP id c36ls714739pgb.5.gmail; Wed, 15 Sep
 2021 17:31:48 -0700 (PDT)
X-Received: by 2002:a63:68e:: with SMTP id 136mr2367389pgg.383.1631752308781;
        Wed, 15 Sep 2021 17:31:48 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1631752308; cv=none;
        d=google.com; s=arc-20160816;
        b=VmvM0XsZTymCSy9V1DdkfgVoViY7m509YCxKCVfNE83qicPdXVj17vPyGmrpbw21EE
         ZOvbQ9VSntxPvJRds9rSfqkON3o/4JPmjnDSgol8NXxWb7eTsoatjSR5Eg70feXRyBXi
         +6Q/sz5aUB7VHCkWe/gO+eRo/b36IJ9QSUVd/KLQUiKzr/rADCyNMTItaYlHmaOcMepB
         n9WmI9fJ4pgoSqpe0twotIlcd79rosc8Nl7ftglOeS7GC0mGzARptqm+g0po+L28zHc+
         UOoFB0mFVMhy6irvHn7xGK+zYuOPLNxqh96Bw8riIIjF1T7Fe2ndm3Dp2Y0ZJvl7B3rF
         O3vw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=QYPhIKEh+pJrnXut14P4C7swVkxAN69J0EF5IonIu00=;
        b=LZJhxsYwXETsLgyY07W7cNtobiotuPXOnCSAEbrMO7B0pdHLs/kvrfypK7S4GTfV95
         UiYmP/1+6kq9sVfTta+N6UtYyDZY77l0c32CkYNAh3WwdLID7JmuH3rOgaUVaEyePraB
         EVgSYJU/nH0xbb/yQ5+6sNkRXnsl1XjBda6cGyKNi/KX75e+yRPdM9Msrr/CZh/18AeW
         Oz8VGC4TEB+xTaJkAvTooObMG0PYLiOW4I0Unf5rjs2upRexpZ/p1LUKE0ka5aASkjhm
         uJkps51KohAayVFrovXV3SJuKP9Tb3wXB3Mr/UNPzKqVt5d2C8w4AkvSsTOBFnV1ahHv
         L/IA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=eM24mmhI;
       spf=pass (google.com: domain of srs0=j1cw=og=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=J1Cw=OG=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id u5si427480pji.0.2021.09.15.17.31.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 15 Sep 2021 17:31:48 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=j1cw=og=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id 0A84861207;
	Thu, 16 Sep 2021 00:31:48 +0000 (UTC)
Received: by paulmck-ThinkPad-P17-Gen-1.home (Postfix, from userid 1000)
	id B62565C0954; Wed, 15 Sep 2021 17:31:47 -0700 (PDT)
From: "Paul E. McKenney" <paulmck@kernel.org>
To: linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	kernel-team@fb.com,
	mingo@kernel.org
Cc: elver@google.com,
	andreyknvl@google.com,
	glider@google.com,
	dvyukov@google.com,
	cai@lca.pw,
	boqun.feng@gmail.com,
	"Paul E . McKenney" <paulmck@kernel.org>
Subject: [PATCH kcsan 6/9] kcsan: Start stack trace with explicit location if provided
Date: Wed, 15 Sep 2021 17:31:43 -0700
Message-Id: <20210916003146.3910358-6-paulmck@kernel.org>
X-Mailer: git-send-email 2.31.1.189.g2e36527f23
In-Reply-To: <20210916003126.GA3910257@paulmck-ThinkPad-P17-Gen-1>
References: <20210916003126.GA3910257@paulmck-ThinkPad-P17-Gen-1>
MIME-Version: 1.0
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=eM24mmhI;       spf=pass
 (google.com: domain of srs0=j1cw=og=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=J1Cw=OG=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
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

From: Marco Elver <elver@google.com>

If an explicit access address is set, as is done for scoped accesses,
always start the stack trace from that location. get_stack_skipnr() is
changed into sanitize_stack_entries(), which if given an address, scans
the stack trace for a matching function and then replaces that entry
with the explicitly provided address.

The previous reports for scoped accesses were all over the place, which
could be quite confusing. We now always point at the start of the scope.

Signed-off-by: Marco Elver <elver@google.com>
Signed-off-by: Paul E. McKenney <paulmck@kernel.org>
---
 kernel/kcsan/kcsan_test.c | 19 ++++++++------
 kernel/kcsan/report.c     | 55 +++++++++++++++++++++++++++++++++++----
 2 files changed, 61 insertions(+), 13 deletions(-)

diff --git a/kernel/kcsan/kcsan_test.c b/kernel/kcsan/kcsan_test.c
index e282c1166373..a3b12429e1d3 100644
--- a/kernel/kcsan/kcsan_test.c
+++ b/kernel/kcsan/kcsan_test.c
@@ -338,7 +338,10 @@ static noinline void test_kernel_assert_bits_nochange(void)
 	ASSERT_EXCLUSIVE_BITS(test_var, ~TEST_CHANGE_BITS);
 }
 
-/* To check that scoped assertions do trigger anywhere in scope. */
+/*
+ * Scoped assertions do trigger anywhere in scope. However, the report should
+ * still only point at the start of the scope.
+ */
 static noinline void test_enter_scope(void)
 {
 	int x = 0;
@@ -845,22 +848,22 @@ static void test_assert_exclusive_writer_scoped(struct kunit *test)
 			{ test_kernel_write_nochange, &test_var, sizeof(test_var), KCSAN_ACCESS_WRITE },
 		},
 	};
-	const struct expect_report expect_anywhere = {
+	const struct expect_report expect_inscope = {
 		.access = {
 			{ test_enter_scope, &test_var, sizeof(test_var), KCSAN_ACCESS_ASSERT | KCSAN_ACCESS_SCOPED },
 			{ test_kernel_write_nochange, &test_var, sizeof(test_var), KCSAN_ACCESS_WRITE },
 		},
 	};
 	bool match_expect_start = false;
-	bool match_expect_anywhere = false;
+	bool match_expect_inscope = false;
 
 	begin_test_checks(test_kernel_assert_writer_scoped, test_kernel_write_nochange);
 	do {
 		match_expect_start |= report_matches(&expect_start);
-		match_expect_anywhere |= report_matches(&expect_anywhere);
-	} while (!end_test_checks(match_expect_start && match_expect_anywhere));
+		match_expect_inscope |= report_matches(&expect_inscope);
+	} while (!end_test_checks(match_expect_inscope));
 	KUNIT_EXPECT_TRUE(test, match_expect_start);
-	KUNIT_EXPECT_TRUE(test, match_expect_anywhere);
+	KUNIT_EXPECT_FALSE(test, match_expect_inscope);
 }
 
 __no_kcsan
@@ -889,9 +892,9 @@ static void test_assert_exclusive_access_scoped(struct kunit *test)
 	do {
 		match_expect_start |= report_matches(&expect_start1) || report_matches(&expect_start2);
 		match_expect_inscope |= report_matches(&expect_inscope);
-	} while (!end_test_checks(match_expect_start && match_expect_inscope));
+	} while (!end_test_checks(match_expect_inscope));
 	KUNIT_EXPECT_TRUE(test, match_expect_start);
-	KUNIT_EXPECT_TRUE(test, match_expect_inscope);
+	KUNIT_EXPECT_FALSE(test, match_expect_inscope);
 }
 
 /*
diff --git a/kernel/kcsan/report.c b/kernel/kcsan/report.c
index 50c4119f5cc0..4849cde9db9b 100644
--- a/kernel/kcsan/report.c
+++ b/kernel/kcsan/report.c
@@ -8,6 +8,7 @@
 #include <linux/debug_locks.h>
 #include <linux/delay.h>
 #include <linux/jiffies.h>
+#include <linux/kallsyms.h>
 #include <linux/kernel.h>
 #include <linux/lockdep.h>
 #include <linux/preempt.h>
@@ -301,6 +302,48 @@ static int get_stack_skipnr(const unsigned long stack_entries[], int num_entries
 	return skip;
 }
 
+/*
+ * Skips to the first entry that matches the function of @ip, and then replaces
+ * that entry with @ip, returning the entries to skip.
+ */
+static int
+replace_stack_entry(unsigned long stack_entries[], int num_entries, unsigned long ip)
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
+sanitize_stack_entries(unsigned long stack_entries[], int num_entries, unsigned long ip)
+{
+	return ip ? replace_stack_entry(stack_entries, num_entries, ip) :
+			  get_stack_skipnr(stack_entries, num_entries);
+}
+
 /* Compares symbolized strings of addr1 and addr2. */
 static int sym_strcmp(void *addr1, void *addr2)
 {
@@ -328,12 +371,12 @@ static void print_verbose_info(struct task_struct *task)
 
 static void print_report(enum kcsan_value_change value_change,
 			 const struct access_info *ai,
-			 const struct other_info *other_info,
+			 struct other_info *other_info,
 			 u64 old, u64 new, u64 mask)
 {
 	unsigned long stack_entries[NUM_STACK_ENTRIES] = { 0 };
 	int num_stack_entries = stack_trace_save(stack_entries, NUM_STACK_ENTRIES, 1);
-	int skipnr = get_stack_skipnr(stack_entries, num_stack_entries);
+	int skipnr = sanitize_stack_entries(stack_entries, num_stack_entries, ai->ip);
 	unsigned long this_frame = stack_entries[skipnr];
 	unsigned long other_frame = 0;
 	int other_skipnr = 0; /* silence uninit warnings */
@@ -345,8 +388,9 @@ static void print_report(enum kcsan_value_change value_change,
 		return;
 
 	if (other_info) {
-		other_skipnr = get_stack_skipnr(other_info->stack_entries,
-						other_info->num_stack_entries);
+		other_skipnr = sanitize_stack_entries(other_info->stack_entries,
+						      other_info->num_stack_entries,
+						      other_info->ai.ip);
 		other_frame = other_info->stack_entries[other_skipnr];
 
 		/* @value_change is only known for the other thread */
@@ -585,7 +629,8 @@ static struct access_info prepare_access_info(const volatile void *ptr, size_t s
 		.access_type	= access_type,
 		.task_pid	= in_task() ? task_pid_nr(current) : -1,
 		.cpu_id		= raw_smp_processor_id(),
-		.ip		= ip,
+		/* Only replace stack entry with @ip if scoped access. */
+		.ip		= (access_type & KCSAN_ACCESS_SCOPED) ? ip : 0,
 	};
 }
 
-- 
2.31.1.189.g2e36527f23

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210916003146.3910358-6-paulmck%40kernel.org.
