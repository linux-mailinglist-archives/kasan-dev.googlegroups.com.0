Return-Path: <kasan-dev+bncBAABBOFGTLZQKGQE5Y7FWLY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa3f.google.com (mail-vk1-xa3f.google.com [IPv6:2607:f8b0:4864:20::a3f])
	by mail.lfdr.de (Postfix) with ESMTPS id C09B917E7C9
	for <lists+kasan-dev@lfdr.de>; Mon,  9 Mar 2020 20:04:25 +0100 (CET)
Received: by mail-vk1-xa3f.google.com with SMTP id h197sf4954159vka.5
        for <lists+kasan-dev@lfdr.de>; Mon, 09 Mar 2020 12:04:25 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1583780664; cv=pass;
        d=google.com; s=arc-20160816;
        b=kyDYJvU+x6Gjz1s6ZVBBe1EBbs/ZRXcxyKX6lcH5EbzNZS0VMhxzyKiiypztMCjzl9
         5N62UclozOFuvfEUNi8ZzqEA5w7iviTQNV/U5LZ9d0HN9DRFbl3e5XrKSYrgf6PSdu17
         NpzTW8MOKBeFSN3GN4eHUw1DIpVyrNVyL5Vic/alCzv4ANSMpZ6md/vpiwP4uWlBmFX5
         0fOFxYHfm9cQ5OiwriXMyOFfT766XKRfniOzp6+UqzZNAM7RotFAvn6L2CPhh18ysX8z
         g6s2sZnQ76EN5f/XyGh5lJisgWu919o2rRgwo8l3xfcpEuBN1oz0pdBD/sXZO6PLOMh/
         qH5g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:references:in-reply-to:message-id
         :date:subject:cc:to:from:mime-version:sender:dkim-signature;
        bh=As7RGBs+GHTfvZa00vzTMvRRMNbE1/S76sMq2B243yQ=;
        b=ke1WUxjXxqTKKhxRjc2uAgRpR/mquQ9Xso3NQTgnoVZumBxwzi2ROFjrLAy1arS/L1
         lSn/tSMgmXhO9J8BYF+OEcL4fYTr5JQtDfdFj5QKn1wVK/RbXu+bMRZ1gEWiy2A8TflV
         NgvB72w9bJuUBp5Y9ZHOicGHPg3cL+/QomeLu7Pom6TNjLMPcxAHohRb17iHk3V3Choi
         EYCw/4sbp6XYiBM7zYCDUf9jJHAS5xIE24HbIo/4r8mTPrl8n/aFbTiRnx6LkxvbKW40
         JVE29tm0W8CJQd/1+vuIGJQ9AKOeTfODAJVZVtNnQGsHklFRJz+rKma1ezCEtotg6Zz1
         i2nQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=HeZukTxo;
       spf=pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=paulmck@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:from:to:cc:subject:date:message-id:in-reply-to
         :references:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=As7RGBs+GHTfvZa00vzTMvRRMNbE1/S76sMq2B243yQ=;
        b=gHvXGAf723UCjkZOZ8Yt9V9piE6z+QJ6HD1AxoHaYhRD/0B6HFisgHcIc6VeVKvqA7
         E0M5QpyIQLeZpvfsyKvUAkA3zv9My66gTgj6DUuoSHpFTgeyHFNGS97vfXxyGLYR4KfA
         4GflzAFyKRFy3BaJ4efKsbm1aDRz+etOLSb9x3/eq6GyjI6oBLp6LkjE9jqjwbyQfRxM
         Is0wNC7FEuAmQgT6cqKziz2Wr8FbscrS6rj8dWwfUMBCEcjuk9k44/Xekn+iba1YBzFW
         cTaX3Y0LoDEA5eX8gr4vq0R7FOcFaqftYZISxhoPakI128RoMQtUiO1FldLwzRevnbnQ
         BpGg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:from:to:cc:subject:date
         :message-id:in-reply-to:references:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=As7RGBs+GHTfvZa00vzTMvRRMNbE1/S76sMq2B243yQ=;
        b=npUwOPsl8aFfCPbGJUAk0YB3fE9ObfiOSICHEWTnKpa7fgN2/je07G5gy8vJmPPFVM
         nLWlZRtbONppjo9AnmN9N1S6iw6ISiI3dceFHkD2u5PkMj9VGCWUwM8tHmTIMU64IpOj
         M7PDKexuyfljfzfLSjA+nfB69tuWVFO22V8OtBibrN4lgEAZvYBGzRjcTbjZOHtFGPb5
         dsbOYR95ybBXL8Wu732YEHUE7ImzssI//OvuJeFMTMopFK+VNqfMrg/owMgV1AICvyQU
         KaAKcrWVUii7I1SEjbTtZlbFhaFOKRoBg8Od/bqc28t0HVQkiURlYAlFzXtQitC4gJFQ
         ro3A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ANhLgQ2y5D14fdK5idOiSUrZlFQ+eZBUDoRo9jCPSP8QaOafRuWyg8DD
	L3gsEu+z5DyWVy1zKYJZQFo=
X-Google-Smtp-Source: ADFU+vvixjB0roJb6WMQSp+Ct/t3/k81bTb+/dJ6xY5+oQOaV0DaozwSMK4Fjm2r2o92DfN5jQ2u1w==
X-Received: by 2002:ab0:769:: with SMTP id h96mr9341267uah.20.1583780664731;
        Mon, 09 Mar 2020 12:04:24 -0700 (PDT)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ab0:2005:: with SMTP id v5ls771131uak.3.gmail; Mon, 09 Mar
 2020 12:04:24 -0700 (PDT)
X-Received: by 2002:ab0:2083:: with SMTP id r3mr5057584uak.12.1583780664316;
        Mon, 09 Mar 2020 12:04:24 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1583780664; cv=none;
        d=google.com; s=arc-20160816;
        b=T2fqq1cts+Zu+1LQu9azuRDx4zIaEUUmzHHAPAqbyvhsYcelxbnUnG6dCmWlE73RrI
         RSVReK9k+ovdM7DJj6Tk5n4LA+tgbx/zFrLFEG2ky45Bm4/6gHdiM11tDq6GRsq0xNvC
         oQo4XScE4piY606itVNw1b7BpQ5obHUx/ysNDyOoLJwbdqoPUvT8dTGDTG6+iul7KBRm
         xWa6flrfBbpQXKqwbv9YvSCxKhsO/SWyUlHrUQkvtHp6RJ8eFPGVt//Xlax8BQe1BfLA
         jk3M/BCA6PNzQARkXoDIN0rtiQbrcks0EdYDMceB9auzTHClTmTpgRWv9o5a/OZ6GLpl
         83Ag==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=references:in-reply-to:message-id:date:subject:cc:to:from
         :dkim-signature;
        bh=4wbgPjZurvDPyAs/wx518F3T2nxujGPWNRH/hyBEjkw=;
        b=MbA/zX89w985S/jfbHk5wUOg5R1iJXm1ZwvmiTZurrFoh1jHIjDvgG/SFogpCAj/Rz
         jI+ozySSMebhBVdhfNB+I8ap3WNLYyey5pbbxpUUIYkp8/91cOJ5MrYyb6FHzptJYtxx
         E60iL1qbvP1plKdYXR7RFkchT9lOuP3m07l6aKEp3lac8GjF1jThA/SfXmQ2uPPSIUWp
         eMxmAxEn887g7uPgAWf3EcX02fpgPKxk8y5sxPhKWbeoRq4kBhEGkLA49tBT2Q7aMFBD
         YQzGfNhFKlCoKRK/Q0VhtPvb7D3NGHwMFEgDp2yA15h0yvCygABgXxwyK/nJSOhDFDtn
         uPfQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=HeZukTxo;
       spf=pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=paulmck@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id w4si682114vse.2.2020.03.09.12.04.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 09 Mar 2020 12:04:24 -0700 (PDT)
Received-SPF: pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from paulmck-ThinkPad-P72.home (50-39-105-78.bvtn.or.frontiernet.net [50.39.105.78])
	(using TLSv1.2 with cipher ECDHE-RSA-AES128-GCM-SHA256 (128/128 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 2EDF722B48;
	Mon,  9 Mar 2020 19:04:23 +0000 (UTC)
From: paulmck@kernel.org
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
Subject: [PATCH kcsan 05/32] kcsan: Address missing case with KCSAN_REPORT_VALUE_CHANGE_ONLY
Date: Mon,  9 Mar 2020 12:03:53 -0700
Message-Id: <20200309190420.6100-5-paulmck@kernel.org>
X-Mailer: git-send-email 2.9.5
In-Reply-To: <20200309190359.GA5822@paulmck-ThinkPad-P72>
References: <20200309190359.GA5822@paulmck-ThinkPad-P72>
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=HeZukTxo;       spf=pass
 (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as
 permitted sender) smtp.mailfrom=paulmck@kernel.org;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=kernel.org
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

Even with KCSAN_REPORT_VALUE_CHANGE_ONLY, KCSAN still reports data
races between reads and watchpointed writes, even if the writes wrote
values already present.  This commit causes KCSAN to unconditionally
skip reporting in this case.

Signed-off-by: Marco Elver <elver@google.com>
Signed-off-by: Paul E. McKenney <paulmck@kernel.org>
---
 kernel/kcsan/report.c | 27 ++++++++++++++++++++-------
 1 file changed, 20 insertions(+), 7 deletions(-)

diff --git a/kernel/kcsan/report.c b/kernel/kcsan/report.c
index 33bdf8b..7cd3428 100644
--- a/kernel/kcsan/report.c
+++ b/kernel/kcsan/report.c
@@ -130,12 +130,25 @@ static bool rate_limit_report(unsigned long frame1, unsigned long frame2)
  * Special rules to skip reporting.
  */
 static bool
-skip_report(int access_type, bool value_change, unsigned long top_frame)
+skip_report(bool value_change, unsigned long top_frame)
 {
-	const bool is_write = (access_type & KCSAN_ACCESS_WRITE) != 0;
-
-	if (IS_ENABLED(CONFIG_KCSAN_REPORT_VALUE_CHANGE_ONLY) && is_write &&
-	    !value_change) {
+	/*
+	 * The first call to skip_report always has value_change==true, since we
+	 * cannot know the value written of an instrumented access. For the 2nd
+	 * call there are 6 cases with CONFIG_KCSAN_REPORT_VALUE_CHANGE_ONLY:
+	 *
+	 * 1. read watchpoint, conflicting write (value_change==true): report;
+	 * 2. read watchpoint, conflicting write (value_change==false): skip;
+	 * 3. write watchpoint, conflicting write (value_change==true): report;
+	 * 4. write watchpoint, conflicting write (value_change==false): skip;
+	 * 5. write watchpoint, conflicting read (value_change==false): skip;
+	 * 6. write watchpoint, conflicting read (value_change==true): impossible;
+	 *
+	 * Cases 1-4 are intuitive and expected; case 5 ensures we do not report
+	 * data races where the write may have rewritten the same value; and
+	 * case 6 is simply impossible.
+	 */
+	if (IS_ENABLED(CONFIG_KCSAN_REPORT_VALUE_CHANGE_ONLY) && !value_change) {
 		/*
 		 * The access is a write, but the data value did not change.
 		 *
@@ -228,7 +241,7 @@ static bool print_report(const volatile void *ptr, size_t size, int access_type,
 	/*
 	 * Must check report filter rules before starting to print.
 	 */
-	if (skip_report(access_type, true, stack_entries[skipnr]))
+	if (skip_report(true, stack_entries[skipnr]))
 		return false;
 
 	if (type == KCSAN_REPORT_RACE_SIGNAL) {
@@ -237,7 +250,7 @@ static bool print_report(const volatile void *ptr, size_t size, int access_type,
 		other_frame = other_info.stack_entries[other_skipnr];
 
 		/* @value_change is only known for the other thread */
-		if (skip_report(other_info.access_type, value_change, other_frame))
+		if (skip_report(value_change, other_frame))
 			return false;
 	}
 
-- 
2.9.5

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200309190420.6100-5-paulmck%40kernel.org.
