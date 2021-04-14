Return-Path: <kasan-dev+bncBC7OBJGL2MHBB55D3OBQMGQE3ZYULYY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x138.google.com (mail-lf1-x138.google.com [IPv6:2a00:1450:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id 6EE7135F26D
	for <lists+kasan-dev@lfdr.de>; Wed, 14 Apr 2021 13:28:56 +0200 (CEST)
Received: by mail-lf1-x138.google.com with SMTP id f11-20020ac2532b0000b02901aa350474f9sf747287lfh.4
        for <lists+kasan-dev@lfdr.de>; Wed, 14 Apr 2021 04:28:56 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1618399736; cv=pass;
        d=google.com; s=arc-20160816;
        b=qUtWFOeNf+qK/zPohCxLqovKo0JhNDaQLknaaeO+HT8h+tMpIDUlFw2Dt6EH9kohqL
         kjwVKqBMoS7w+NAtjlKiBP28nQvWIzN5PMNIYvq2UAu75WH0SUR9CkqSsjDVwgmZolXG
         0vUACPhKllOpUnaeN7TQt+qCftGOspalhD3iSzazGMR3s4EKA5JQN9MK3Na1/ZZqxyCd
         6NE1cNcAe3+1tXoAt9Ico+CCfB3gvsIedKm4rb9cwHlnvYykDKRR65Ut6f0kiftgzBm1
         xS8PG12TS8NNEXVV1KeALectfAubzKZWblzvoMXUX79K1SOG3fMLSQhODi7ezSrrFkmD
         pmVQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=ep74IPfifrEROt/rM5mfhkBPNNvM1R8uDLgZX0mo3ng=;
        b=ZGV6+C86jU+awnyvpeZvMfyzeg+cbKYX6dGswSpmaHGRgGshr2+Jsoj+Nd5niR+lym
         Pra5jK5Zf3GxR0dNdUymb05Mxh0f1Sco32ydZmhe7d9aFbtDaMH3yjMGDqmuYk+vLNdq
         ubj8MPt5U07VbJxy8IGh+QoqbgsKR/CRAU/GbcS8978oen9qudZQGzJoSKjxFbEh4fRN
         Eo6fTuQL+YTGdTiwPBBsRs1oV47RvvW0UWFFOHWF+sMZP2LHHoo+AShTFlBdEePWXxZv
         4AhLf8ChoMw0Z6kliZ/9RMXRdn3XtD/Oyaeh31RNSURqhtbgJa/juIVST4IgKmSFSAlD
         RUwg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Svuo2zs9;
       spf=pass (google.com: domain of 39tf2yaukcx8hoyhujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=39tF2YAUKCX8hoyhujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ep74IPfifrEROt/rM5mfhkBPNNvM1R8uDLgZX0mo3ng=;
        b=HKtHI4HPerEERoGED3nJQKS7Mdh4mx9VKnSXe8yJ5yswt3dbwG8jMBkrtOTGcwhnq6
         0ut/u2hM0Im/gZ6+2BZ+OWwdy78hl5J6hvqvbMqYHVJ/dAhaob645svnFWJydW5Gjnc3
         UkHSyGIut+1IJZq85LJhpDuwAukwPDxO6iKVatHpLpcp0NiL0tjqncw15EaWg/xmzB6z
         yT7lQXz0kNCjhcoszlmFKgp+fU2HsMMk5T57ZmNJRVMGHCH+eNbLNqMZ07WeK4rjsvG5
         cBU5/P/yXqFvb5RnFXCiT0Ct//c3RPOts9sB5XWMb7KM1BcMI5bQjbB8nvnGJRzV8c0Q
         O1Vw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ep74IPfifrEROt/rM5mfhkBPNNvM1R8uDLgZX0mo3ng=;
        b=kDwjememImVpWRLdp4gq6SL2CVnYZkp/bgIu8eGzXLFqMNov8RvI7L8PUnZKkgW+Yu
         4dT2HJWmN3V1QYe9FM+a6RmSu3qd02PtAl2RJ5hjMDbyvGBoOIHToIbbe6RILfZVt5Sp
         ZM9gP3Ehzifk/g252lZkZb8e+XB8JdUHXmj+wOSzpnXds8xg2F/xxAWpnIcWU7CELv5k
         5XFYgTSADlyq6On3CDNK+tAFlbdJ1pFYIcn+owdc4+zqecyPNLJ8Hgw4nPm1hkCPfmnB
         ssQAEJN8aWHJXB8dU9arwAGRRiBOm4HLWSLftSuen8TIt7ISOadfHxkjAZgrXKo5BBTP
         TKSw==
X-Gm-Message-State: AOAM531D5L1SII655knymFBlxKZ+sdO206YEYc9fY0QQOZLqkmneOchT
	qnbYWFNbhobB+kMNXPourUc=
X-Google-Smtp-Source: ABdhPJwoE0LSHFlUxnMUEuVtWd5CyO/qE7fb/123atjdgASQyLUgXSmkfNKn0/NFpNDogJh0MB3NYQ==
X-Received: by 2002:a2e:a41c:: with SMTP id p28mr17981799ljn.228.1618399736042;
        Wed, 14 Apr 2021 04:28:56 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:7408:: with SMTP id p8ls316282ljc.1.gmail; Wed, 14 Apr
 2021 04:28:54 -0700 (PDT)
X-Received: by 2002:a2e:a592:: with SMTP id m18mr18540576ljp.189.1618399734831;
        Wed, 14 Apr 2021 04:28:54 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1618399734; cv=none;
        d=google.com; s=arc-20160816;
        b=P7zrLxaGPhfJEBycbt/uGVpjCHhtRTyvQtMfaG2WTd6XIAlpKHrDvpZ9pr+HgcdZX6
         kIH7xpLixsXwJNAWuHr4NWrikdCS03rkyId7EMOYNTSv+hCev2nRSvKHUIxxDtazdYea
         3vhLeolR+UJov0TdlyJ8PlKbF8ptFZoCo0O+xeXhgffD3lAyU5f7Ge0QSCebXc56FQWM
         YKL0vmSp2h6jH1vkRuhJrByOq+lXml9guMRhoXjgsFixsJ4tyGjpRPySkQe6xa4poLrR
         jyjAx8YW8A9AeEEcHaUSXULXsiWIP1QlXBuHHR16l5ZgSEWT7oEMKOgrQT8D39Y50qOi
         HEvA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=mZuUlNh2PCUT9rxT70cSWAPcOboXAIvYNdGGwPvCpXY=;
        b=C/oRVmOu39kPgL3ab1we8LFJYJkYbL1gVKOIxWLDdxAu8SmbeQbkDnFz1KKH117yCi
         58c0yEJ6JRuH17BhM9cyJZq/JaiwiLT5fL4lQPMyPEjIdNcPreqYth5Hsh9cufV5KvDh
         ZXvwktrRomMRI8eslDNbjtnKsEPZdILzydPZCLNZTmCfH72J5Ypdlc5VYSUgfLZWoUhb
         AH9g800fTTswUnjB0+JJV4Wd0NxjgfNLZWHhDSLhS07oNMsN4Ff3TctUfHskLywfNwdn
         DHz/r+OixhieTiWNUR37mCWt1LlkVFwwfbvJL+t9lnnYJyPwIiDVImsP61C9GPhb3p73
         PooA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Svuo2zs9;
       spf=pass (google.com: domain of 39tf2yaukcx8hoyhujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=39tF2YAUKCX8hoyhujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x349.google.com (mail-wm1-x349.google.com. [2a00:1450:4864:20::349])
        by gmr-mx.google.com with ESMTPS id 81si1000718lfj.2.2021.04.14.04.28.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 14 Apr 2021 04:28:54 -0700 (PDT)
Received-SPF: pass (google.com: domain of 39tf2yaukcx8hoyhujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) client-ip=2a00:1450:4864:20::349;
Received: by mail-wm1-x349.google.com with SMTP id z135-20020a1c7e8d0000b02901297f50f20dso1518268wmc.0
        for <kasan-dev@googlegroups.com>; Wed, 14 Apr 2021 04:28:54 -0700 (PDT)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:4051:8ddb:9de4:c1bb])
 (user=elver job=sendgmr) by 2002:a5d:63c7:: with SMTP id c7mr4575938wrw.238.1618399734275;
 Wed, 14 Apr 2021 04:28:54 -0700 (PDT)
Date: Wed, 14 Apr 2021 13:28:21 +0200
In-Reply-To: <20210414112825.3008667-1-elver@google.com>
Message-Id: <20210414112825.3008667-6-elver@google.com>
Mime-Version: 1.0
References: <20210414112825.3008667-1-elver@google.com>
X-Mailer: git-send-email 2.31.1.295.g9ea45b61b8-goog
Subject: [PATCH 5/9] kcsan: Refactor access_info initialization
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, paulmck@kernel.org
Cc: mark.rutland@arm.com, will@kernel.org, dvyukov@google.com, 
	glider@google.com, boqun.feng@gmail.com, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=Svuo2zs9;       spf=pass
 (google.com: domain of 39tf2yaukcx8hoyhujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=39tF2YAUKCX8hoyhujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--elver.bounces.google.com;
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

From: Mark Rutland <mark.rutland@arm.com>

In subsequent patches we'll want to split kcsan_report() into distinct
handlers for each report type. The largest bit of common work is
initializing the `access_info`, so let's factor this out into a helper,
and have the kcsan_report_*() functions pass the `aaccess_info` as a
parameter to kcsan_report().

There should be no functional change as a result of this patch.

Signed-off-by: Mark Rutland <mark.rutland@arm.com>
Signed-off-by: Marco Elver <elver@google.com>
---
 kernel/kcsan/report.c | 42 +++++++++++++++++++++++++-----------------
 1 file changed, 25 insertions(+), 17 deletions(-)

diff --git a/kernel/kcsan/report.c b/kernel/kcsan/report.c
index 8bfa970965a1..d8441bed065c 100644
--- a/kernel/kcsan/report.c
+++ b/kernel/kcsan/report.c
@@ -596,18 +596,10 @@ static noinline bool prepare_report(unsigned long *flags,
 	}
 }
 
-static void kcsan_report(const volatile void *ptr, size_t size, int access_type,
-			 enum kcsan_value_change value_change,
+static void kcsan_report(const struct access_info *ai, enum kcsan_value_change value_change,
 			 enum kcsan_report_type type, struct other_info *other_info)
 {
 	unsigned long flags = 0;
-	const struct access_info ai = {
-		.ptr		= ptr,
-		.size		= size,
-		.access_type	= access_type,
-		.task_pid	= in_task() ? task_pid_nr(current) : -1,
-		.cpu_id		= raw_smp_processor_id()
-	};
 
 	kcsan_disable_current();
 
@@ -620,14 +612,14 @@ static void kcsan_report(const volatile void *ptr, size_t size, int access_type,
 	 */
 	lockdep_off();
 
-	if (prepare_report(&flags, type, &ai, other_info)) {
+	if (prepare_report(&flags, type, ai, other_info)) {
 		/*
 		 * Never report if value_change is FALSE, only if we it is
 		 * either TRUE or MAYBE. In case of MAYBE, further filtering may
 		 * be done once we know the full stack trace in print_report().
 		 */
 		if (value_change != KCSAN_VALUE_CHANGE_FALSE)
-			print_report(value_change, type, &ai, other_info);
+			print_report(value_change, type, ai, other_info);
 
 		release_report(&flags, other_info);
 	}
@@ -636,22 +628,38 @@ static void kcsan_report(const volatile void *ptr, size_t size, int access_type,
 	kcsan_enable_current();
 }
 
+static struct access_info prepare_access_info(const volatile void *ptr, size_t size,
+					      int access_type)
+{
+	return (struct access_info) {
+		.ptr		= ptr,
+		.size		= size,
+		.access_type	= access_type,
+		.task_pid	= in_task() ? task_pid_nr(current) : -1,
+		.cpu_id		= raw_smp_processor_id()
+	};
+}
+
 void kcsan_report_set_info(const volatile void *ptr, size_t size, int access_type,
 			   int watchpoint_idx)
 {
-	kcsan_report(ptr, size, access_type, KCSAN_VALUE_CHANGE_MAYBE,
-		     KCSAN_REPORT_CONSUMED_WATCHPOINT, &other_infos[watchpoint_idx]);
+	const struct access_info ai = prepare_access_info(ptr, size, access_type);
+
+	kcsan_report(&ai, KCSAN_VALUE_CHANGE_MAYBE, KCSAN_REPORT_CONSUMED_WATCHPOINT,
+		     &other_infos[watchpoint_idx]);
 }
 
 void kcsan_report_known_origin(const volatile void *ptr, size_t size, int access_type,
 			       enum kcsan_value_change value_change, int watchpoint_idx)
 {
-	kcsan_report(ptr, size, access_type, value_change,
-		     KCSAN_REPORT_RACE_SIGNAL, &other_infos[watchpoint_idx]);
+	const struct access_info ai = prepare_access_info(ptr, size, access_type);
+
+	kcsan_report(&ai, value_change, KCSAN_REPORT_RACE_SIGNAL, &other_infos[watchpoint_idx]);
 }
 
 void kcsan_report_unknown_origin(const volatile void *ptr, size_t size, int access_type)
 {
-	kcsan_report(ptr, size, access_type, KCSAN_VALUE_CHANGE_TRUE,
-		     KCSAN_REPORT_RACE_UNKNOWN_ORIGIN, NULL);
+	const struct access_info ai = prepare_access_info(ptr, size, access_type);
+
+	kcsan_report(&ai, KCSAN_VALUE_CHANGE_TRUE, KCSAN_REPORT_RACE_UNKNOWN_ORIGIN, NULL);
 }
-- 
2.31.1.295.g9ea45b61b8-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210414112825.3008667-6-elver%40google.com.
