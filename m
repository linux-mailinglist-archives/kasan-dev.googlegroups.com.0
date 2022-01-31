Return-Path: <kasan-dev+bncBC7OBJGL2MHBBK7W32HQMGQEWI2SU5A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x339.google.com (mail-wm1-x339.google.com [IPv6:2a00:1450:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id D3E5D4A404B
	for <lists+kasan-dev@lfdr.de>; Mon, 31 Jan 2022 11:34:19 +0100 (CET)
Received: by mail-wm1-x339.google.com with SMTP id n7-20020a1c7207000000b0034ec3d8ce0asf5640321wmc.8
        for <lists+kasan-dev@lfdr.de>; Mon, 31 Jan 2022 02:34:19 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1643625259; cv=pass;
        d=google.com; s=arc-20160816;
        b=udMLgAkEaPBQmnp2htX0BDUl+RUk9uf/OE1q2Xsap2M4Qfu0AgADi7TRONKlPh2wlR
         Mapc06yL8BEoflnN1VxyiOgfks4tabc2CpPzc0e24f4YPkCFDE0D4HseJhVtYy0O2ZFI
         DQbwhMYEiu0Zd5tPdxjsjsSOrflP8biiT8Y/2Bg58J5VUjQl11hr34dsPr4cjgQvjqoZ
         2bm6rnaeQ89ly0Si1tCG/J3gcV40au9BZQcVRW8vYdPm/SZG0Zx8GQ11jdg4ElEi2aLP
         lT0RvHEvNBob1frR9evAiqdqzF92h4RFhdwcaEmlg6WKN+mF77iW322/4S93Dciu7sp5
         EcLQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=RdsSl/eMlsVUhpMkzPv9uYqVUA/qsh2raGSd5ACH9xY=;
        b=03aPeYUyn0tC0q7NMwpWOecXJUOsqCO6k52FVroB7ZU2xa0fo1AkB3EuAqsUVSRaTk
         /HPxXjOJZk/EzFO4HADgtjwf0rseQc70eA0j/lGvvJfRHWXh3HfzYyPXfYTyYgdqHFL9
         swQ7uHdgoNjDIqQll3K3kL06uafYcw1TxUDsTcy0lNIOEAQD4WFFtKQEN8P6yfaDUfAq
         PRaTXmHxcot9L9dQM40JhSlm2Gua3DzEVjBjNIkEH38+dJPJ/amUsCsK3D16DfNHegfS
         fNBAzOXghvL2l6W1Iu8JE64g8f2Q64WFSWpgjRDoX+dPuCWcJHXMq/EfcBE0iq79qLWB
         9NTQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=eWt3zv0k;
       spf=pass (google.com: domain of 3krv3yqukczu3ak3g5dd5a3.1db9zhzc-23k5dd5a35gdjeh.1db@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3Krv3YQUKCZU3AK3G5DD5A3.1DB9zHzC-23K5DD5A35GDJEH.1DB@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=RdsSl/eMlsVUhpMkzPv9uYqVUA/qsh2raGSd5ACH9xY=;
        b=ivTORrWuY3R9d5V3Qjdg2BoKa+N1mfT9SmXJYz3dTacThmr0zY0BmXVe6jxkrUJqT0
         5a4UZ5qf/j3ZdzziQXpLFQ3YmnP1BOXOdj7F2nwrb7s2M7TZJ92aX658Ob6WAeuBOkmZ
         V6ztDCkxB2ZQ4s5ecKRqymET9SJDFY06Mkc8yMegGx5+xB0P24q2MgtQ/y6q+9y6t9lj
         g2/xFomEq59CdcuI+gqC+yfly4VpDDp+obxITMwkg/xrb2zuWzAVRXVMRearaFBrIK5W
         b1d7ZPE6o2qm8zXKFuez/XhKi5WNgLBSpKmcr5c7+2OTgrTbHuY5i3W/dyiFTbOT57XL
         aehQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=RdsSl/eMlsVUhpMkzPv9uYqVUA/qsh2raGSd5ACH9xY=;
        b=6mwEQc1xBTmxzPLhax4e5L+jNDAyCDfxqMyrRK3olldpObRHC9JzP8HQSYCr2Ys+f/
         jPv/XWWDzA/MvTbpz+8lMtYCBWSP6a3nwam0PZjlKCCadL9n2047FT1acgkC3Zgb9l5J
         MiSLmCpkZJVHCcS0RSnKj68iJ7hjvOGT9BEFzC4FvfimXNw7LmqTIlVEwOCeLjdZwSh7
         x5Og1phGU1LuDPJhHDCIQMj2ofzBCMm0ZBiugW+YBiIMlK6Id3+1A0IbTov0GQcV7SbS
         /NNFcUzArDKyZxLRmGo2h5TEfWu6SL/y7epQQAo5bbRy3AeI/OLO5PPJ+i8TBhqg/+jQ
         4kVg==
X-Gm-Message-State: AOAM533L3bQmb4W6ssjd/RZJWX9hZxOMAyR6cMp7rEqlLDL57mQ/iWQD
	7MeFdQEiJ6O7PoDbffYD2Lg=
X-Google-Smtp-Source: ABdhPJzHZyyJCjsCkHjpWmEo9bJI69N+IfDiBGuIBNo5T4zI1G/G0liOJdh6uTYMtCHoNiHDToiokg==
X-Received: by 2002:a7b:c923:: with SMTP id h3mr26761785wml.122.1643625259461;
        Mon, 31 Jan 2022 02:34:19 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:ec88:: with SMTP id z8ls291718wrn.2.gmail; Mon, 31 Jan
 2022 02:34:18 -0800 (PST)
X-Received: by 2002:adf:9dd0:: with SMTP id q16mr16284690wre.469.1643625258344;
        Mon, 31 Jan 2022 02:34:18 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1643625258; cv=none;
        d=google.com; s=arc-20160816;
        b=FUSgBMZmdwYoS7DOyq627qpiGpFKiLCT0jeWe2Nm0V7t4x/6/S09eEYLM8PC9vtbW9
         VomT6Lkf/GpI4nZK0ErV2Rzfw75Sza1CtHhiTwJyXYH9LubclNnisSGANUA8VcC9Oq8h
         zYuoDkZk7YwUUl5iUDTaQqaVq33Qg/4j+Jf5LUv3/5fA6MHstOJkexxSapnod1cztjMz
         2sjwmJiFCsQ7Yx9AdLl79TCUnARce68NdOqcqGL+DtXG7j2xWLPgbFScMpc7uTputREf
         /8n0uaXN2gWXZ7IlCjhCcNu10w6rOd5wcyZH9RfuUbc+7qDLMyP2yO66479AEWIPGR6f
         hl7g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=UKwbbY9OvBECTqZsXnc3pFs8yvEOFYua3q+Sg/9PamM=;
        b=eSbGycFICJaLGZ16dVSOsRtdggHBquyLvr9D2sdqyAvEOoQu6Q9O5Qt0uUJjScPfI4
         ZgH2oEpZx6OtbtINn7Y5o7hh4xQOE9LU3jtFf67FdpsF1fqrklDnveh+ThVhxkZbrPm6
         jM3RG2KGXickppHR9iO8TxsyugeX2dMFdKgMDA6KUrkATt0aUkbD8+1KO/u6TLdMSXcy
         lTxr9HWMBYCenVIMBeDVIRzZYCHAurQJAY4yVKLOIRVsmdIQs8dwoM/IeoMcEIWad3oT
         v7YOYT5UD0OgkdKFQH3bTqWB+hX8wy3Sg2wcSwnPCNphQTTfR393d2cf4Eiqa+qCoEDZ
         x9lQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=eWt3zv0k;
       spf=pass (google.com: domain of 3krv3yqukczu3ak3g5dd5a3.1db9zhzc-23k5dd5a35gdjeh.1db@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3Krv3YQUKCZU3AK3G5DD5A3.1DB9zHzC-23K5DD5A35GDJEH.1DB@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x34a.google.com (mail-wm1-x34a.google.com. [2a00:1450:4864:20::34a])
        by gmr-mx.google.com with ESMTPS id p6si1118786wrx.3.2022.01.31.02.34.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 31 Jan 2022 02:34:18 -0800 (PST)
Received-SPF: pass (google.com: domain of 3krv3yqukczu3ak3g5dd5a3.1db9zhzc-23k5dd5a35gdjeh.1db@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) client-ip=2a00:1450:4864:20::34a;
Received: by mail-wm1-x34a.google.com with SMTP id s1-20020a1ca901000000b0034ece94dd8cso10165441wme.5
        for <kasan-dev@googlegroups.com>; Mon, 31 Jan 2022 02:34:18 -0800 (PST)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:76:dcf3:95f9:db8b])
 (user=elver job=sendgmr) by 2002:a05:600c:4f4e:: with SMTP id
 m14mr17527439wmq.155.1643625258015; Mon, 31 Jan 2022 02:34:18 -0800 (PST)
Date: Mon, 31 Jan 2022 11:34:06 +0100
In-Reply-To: <20220131103407.1971678-1-elver@google.com>
Message-Id: <20220131103407.1971678-2-elver@google.com>
Mime-Version: 1.0
References: <20220131103407.1971678-1-elver@google.com>
X-Mailer: git-send-email 2.35.0.rc2.247.g8bbb082509-goog
Subject: [PATCH 2/3] selftests/perf_events: Test modification of perf_event_attr::sig_data
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, Peter Zijlstra <peterz@infradead.org>
Cc: Ingo Molnar <mingo@kernel.org>, Arnaldo Carvalho de Melo <acme@kernel.org>, 
	Mark Rutland <mark.rutland@arm.com>, 
	Alexander Shishkin <alexander.shishkin@linux.intel.com>, Jiri Olsa <jolsa@redhat.com>, 
	Namhyung Kim <namhyung@kernel.org>, Dmitry Vyukov <dvyukov@google.com>, 
	linux-perf-users@vger.kernel.org, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=eWt3zv0k;       spf=pass
 (google.com: domain of 3krv3yqukczu3ak3g5dd5a3.1db9zhzc-23k5dd5a35gdjeh.1db@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3Krv3YQUKCZU3AK3G5DD5A3.1DB9zHzC-23K5DD5A35GDJEH.1DB@flex--elver.bounces.google.com;
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

Test that PERF_EVENT_IOC_MODIFY_ATTRIBUTES correctly modifies
perf_event_attr::sig_data as well.

Signed-off-by: Marco Elver <elver@google.com>
---
 .../selftests/perf_events/sigtrap_threads.c     | 17 +++++++++--------
 1 file changed, 9 insertions(+), 8 deletions(-)

diff --git a/tools/testing/selftests/perf_events/sigtrap_threads.c b/tools/testing/selftests/perf_events/sigtrap_threads.c
index 8e83cf91513a..6d849dc2bee0 100644
--- a/tools/testing/selftests/perf_events/sigtrap_threads.c
+++ b/tools/testing/selftests/perf_events/sigtrap_threads.c
@@ -44,9 +44,10 @@ static struct {
 } ctx;
 
 /* Unique value to check si_perf_data is correctly set from perf_event_attr::sig_data. */
-#define TEST_SIG_DATA(addr) (~(unsigned long)(addr))
+#define TEST_SIG_DATA(addr, id) (~(unsigned long)(addr) + id)
 
-static struct perf_event_attr make_event_attr(bool enabled, volatile void *addr)
+static struct perf_event_attr make_event_attr(bool enabled, volatile void *addr,
+					      unsigned long id)
 {
 	struct perf_event_attr attr = {
 		.type		= PERF_TYPE_BREAKPOINT,
@@ -60,7 +61,7 @@ static struct perf_event_attr make_event_attr(bool enabled, volatile void *addr)
 		.inherit_thread = 1, /* ... but only cloned with CLONE_THREAD. */
 		.remove_on_exec = 1, /* Required by sigtrap. */
 		.sigtrap	= 1, /* Request synchronous SIGTRAP on event. */
-		.sig_data	= TEST_SIG_DATA(addr),
+		.sig_data	= TEST_SIG_DATA(addr, id),
 	};
 	return attr;
 }
@@ -110,7 +111,7 @@ FIXTURE(sigtrap_threads)
 
 FIXTURE_SETUP(sigtrap_threads)
 {
-	struct perf_event_attr attr = make_event_attr(false, &ctx.iterate_on);
+	struct perf_event_attr attr = make_event_attr(false, &ctx.iterate_on, 0);
 	struct sigaction action = {};
 	int i;
 
@@ -165,7 +166,7 @@ TEST_F(sigtrap_threads, enable_event)
 	EXPECT_EQ(ctx.tids_want_signal, 0);
 	EXPECT_EQ(ctx.first_siginfo.si_addr, &ctx.iterate_on);
 	EXPECT_EQ(ctx.first_siginfo.si_perf_type, PERF_TYPE_BREAKPOINT);
-	EXPECT_EQ(ctx.first_siginfo.si_perf_data, TEST_SIG_DATA(&ctx.iterate_on));
+	EXPECT_EQ(ctx.first_siginfo.si_perf_data, TEST_SIG_DATA(&ctx.iterate_on, 0));
 
 	/* Check enabled for parent. */
 	ctx.iterate_on = 0;
@@ -175,7 +176,7 @@ TEST_F(sigtrap_threads, enable_event)
 /* Test that modification propagates to all inherited events. */
 TEST_F(sigtrap_threads, modify_and_enable_event)
 {
-	struct perf_event_attr new_attr = make_event_attr(true, &ctx.iterate_on);
+	struct perf_event_attr new_attr = make_event_attr(true, &ctx.iterate_on, 42);
 
 	EXPECT_EQ(ioctl(self->fd, PERF_EVENT_IOC_MODIFY_ATTRIBUTES, &new_attr), 0);
 	run_test_threads(_metadata, self);
@@ -184,7 +185,7 @@ TEST_F(sigtrap_threads, modify_and_enable_event)
 	EXPECT_EQ(ctx.tids_want_signal, 0);
 	EXPECT_EQ(ctx.first_siginfo.si_addr, &ctx.iterate_on);
 	EXPECT_EQ(ctx.first_siginfo.si_perf_type, PERF_TYPE_BREAKPOINT);
-	EXPECT_EQ(ctx.first_siginfo.si_perf_data, TEST_SIG_DATA(&ctx.iterate_on));
+	EXPECT_EQ(ctx.first_siginfo.si_perf_data, TEST_SIG_DATA(&ctx.iterate_on, 42));
 
 	/* Check enabled for parent. */
 	ctx.iterate_on = 0;
@@ -204,7 +205,7 @@ TEST_F(sigtrap_threads, signal_stress)
 	EXPECT_EQ(ctx.tids_want_signal, 0);
 	EXPECT_EQ(ctx.first_siginfo.si_addr, &ctx.iterate_on);
 	EXPECT_EQ(ctx.first_siginfo.si_perf_type, PERF_TYPE_BREAKPOINT);
-	EXPECT_EQ(ctx.first_siginfo.si_perf_data, TEST_SIG_DATA(&ctx.iterate_on));
+	EXPECT_EQ(ctx.first_siginfo.si_perf_data, TEST_SIG_DATA(&ctx.iterate_on, 0));
 }
 
 TEST_HARNESS_MAIN
-- 
2.35.0.rc2.247.g8bbb082509-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220131103407.1971678-2-elver%40google.com.
