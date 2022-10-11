Return-Path: <kasan-dev+bncBC7OBJGL2MHBBWOLSWNAMGQEQSVVPOY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103b.google.com (mail-pj1-x103b.google.com [IPv6:2607:f8b0:4864:20::103b])
	by mail.lfdr.de (Postfix) with ESMTPS id 6C2365FB2A2
	for <lists+kasan-dev@lfdr.de>; Tue, 11 Oct 2022 14:47:23 +0200 (CEST)
Received: by mail-pj1-x103b.google.com with SMTP id px13-20020a17090b270d00b0020aa188aae8sf6529796pjb.8
        for <lists+kasan-dev@lfdr.de>; Tue, 11 Oct 2022 05:47:23 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1665492442; cv=pass;
        d=google.com; s=arc-20160816;
        b=UEAgvB4UXl8hsQhMk1ZgspZuJX9ypHGR2hEk+7Pr6/A7R9GiNVsScOu0mmKkdtGTbg
         9DBLNh0tI7s4MFjsgVWfItjh9kY/zeBisCNiGi0R5r5H6qTcyTkL5nybTRa7uKhq0oxp
         7HenzNjJvsl2TdyNNpG1E0t3+9Qt8V8c54LvuncXaEVWkNwocnz9myJpKAy0yrxV56eG
         4wsINChWHOfYWEzMSmfURaqNWPwN5ZXr48I+dLgenpueJWLp+SDWEXzyZOPIyvbXI0M9
         C8Vu11w9SaWto9SDV1zeuoufXNcq+z8v/HScgj7nXq7okeoDPbRRdKLbqn5YqxzMs4sh
         /rFQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:mime-version:date:dkim-signature;
        bh=tK+qJRuzwv/eV8zUoMJpkB2LZQtw1RG43EELcnpWsME=;
        b=asR81vP1oY41p1a+82WrIgL+gdYZdnuA57QQSfJ6dM7j1SuxEHZqVlhmFJUY4KnJIy
         4Vo8PghhCI7gLhZqXuHH6+WIccgAQU/rQMx4FPRswQrkbD1U0uZN+ybskXGtaMcLBhZN
         w4KNjw8Whr/CK7+VTwIrXySi8OLwVc6oZ4xZrRm7OhwwW03NDmvRTf5wFDbmWfymfNnC
         Kow2Fnyp0t/BZfbQ/Q3h9gBtoauUFW+DehjTvMGwUiUnFNJJmiev4b7+CJg+vErg1/Cn
         4rgMCqsAqih0kvfB19o9WIAthCp+DsDMgeUgr5tqb+qEma3DPEfTXGjrto0A5JnsSDbj
         N8Mw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=Lhj7yGBg;
       spf=pass (google.com: domain of 32gvfywukcdk9gq9mbjjbg9.7jhf5n5i-89qbjjbg9bmjpkn.7jh@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=32GVFYwUKCdk9GQ9MBJJBG9.7JHF5N5I-89QBJJBG9BMJPKN.7JH@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:mime-version:date:from:to:cc:subject:date
         :message-id:reply-to;
        bh=tK+qJRuzwv/eV8zUoMJpkB2LZQtw1RG43EELcnpWsME=;
        b=pWyApPFl1RbKAJo0tuxRnm2ZBBdTek1unTQuy2U0xmxM4AEZ0c+7dwOrG0AW3m88VM
         jyABzFhBv3wttKxSARqn0qHt9JZ/L0eQjVSTaD/E6BpRJPb6Q/E1o34vhvnTEp3751dT
         4Wjdq/h7Nz1pTekId/HSNa/U4GMmYdJ1n537zSn6cdqjbpSjQtNxDoVoiOE7JCb2OGtE
         hWVu42bA8930j80xQopC1jTigbpdiJeVajLbAd3DeKznFqtw23glrE9T/2mdXJf2hvw7
         ukBPT4HppVqZUOIk/Ll54wPExpCWQM/oeT1eDwVP1p9Heknncdh/VrTmsnRBIvDyqJYg
         WCaw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:mime-version:date:x-gm-message-state:from:to:cc
         :subject:date:message-id:reply-to;
        bh=tK+qJRuzwv/eV8zUoMJpkB2LZQtw1RG43EELcnpWsME=;
        b=4+LRH4bpffj+axDqoJ1/DsqCiedF4MjzMoA3ggGedcrLp4SrJ1pcLdjnEeh6KaxrFe
         a+1n/+fPO2fTrVI8b6VF5DV3GA5Ov+xV63cLrYGVLAbWZfW1mABgzgD4WJ3GCvNNYAwJ
         4fzsY/ENIotWLWm28lrz05iLa6pT3a/cSmZCy8TBnAQ33VnGU2qImJu1x6hn9t49JczQ
         9rZxMS4lOoM0oqfEZn6jHbgTfQq5UuWD51Xol1jfyRkAcRuYZ+/z80cVbWrM06sSoJU3
         ysOkBPIkJ1UBCSnMcsWtAMWkGK4nXj8VVdlfjfBbJlCUB7JlM6i6/s4tfTbmO/HzTSLh
         ukjQ==
X-Gm-Message-State: ACrzQf03cjTf5f0PSRl7daL0MDPjThoIY0ZqqXvps85r9Kv8o6FIWb1j
	JWp1nmzLKDs84Mo/+cgYkd4=
X-Google-Smtp-Source: AMsMyM4lk2Hp92nXwmMI48NJ13/2RgL3trmHtiIfk/Sp7KDgzgzrHe/3pi3j6rEy3/89r31TqSDtvQ==
X-Received: by 2002:aa7:8893:0:b0:563:89e0:2d43 with SMTP id z19-20020aa78893000000b0056389e02d43mr7066849pfe.25.1665492441941;
        Tue, 11 Oct 2022 05:47:21 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:330e:b0:562:1db:a3fb with SMTP id
 cq14-20020a056a00330e00b0056201dba3fbls6706594pfb.2.-pod-prod-gmail; Tue, 11
 Oct 2022 05:47:21 -0700 (PDT)
X-Received: by 2002:a65:6e0f:0:b0:43a:1cd4:4ae6 with SMTP id bd15-20020a656e0f000000b0043a1cd44ae6mr20488379pgb.289.1665492440864;
        Tue, 11 Oct 2022 05:47:20 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1665492440; cv=none;
        d=google.com; s=arc-20160816;
        b=gO+V1/opXBScD4Cn3Hr1X9GRQLJDqouzqNLpGU1XQpqXXoJktL7Yddo3FU6w9AQePM
         0eDMWVVvPvuPjH5RxsVwj1gTrCvakxOKNNVQEOlx5stIcwcMDvlaUtV3RydB1ZPrS9x5
         +jCI6GzHwbdNfRHkvI3x9cHIuS53DrHwWoy+zeICqflEU0ktxbE28nNYQzVRUW5fPVl1
         /Va752+diKd6xMFWnqIDh79IDq8iUIkVNbS/KQINaB4yOTma3q/6J18D8IYRgGA+2/zS
         BhEl/beBJlYq5OjAvkZh8Ktnub1uY4Qp1FK1oeAnUUauCrHSlsKTX6C4nl+oNNJEExwi
         owfg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:mime-version:date:dkim-signature;
        bh=JZgfsSGBJAIpwrM+kN5gILalFFiDKNqq+i+h/f0T+1w=;
        b=UsVAoj7M9bANfi2YC1/q364fUzCryKXk/DnixHeXQYe5sYn/KIYOli6n2JwmrEjDh0
         iqJgkcWPTlu4xfve6/Aks+ut3wrkBJZFCgBNzkynUyIv6Aa3LcI8yrlf+/rtHVdCFSkg
         /JWcCaIZd9FyXvIQp27BJvHZgs+9HWC37J9Cs1Gd/wvKSfXYerf+t1wpzVALPFyAa/yh
         J7lnmvbm/2fKhC923TLDXzvpxgwHwiy0Co6jhI3nEt/PU8oZ+tVwgdRmJUIRVniXvED+
         QosaZS1tPoLxehIFd2GeKTu+oCm/2mm4HfISy7xXfOg436OabknYct4+qxjm4Nc+4guY
         Axyg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=Lhj7yGBg;
       spf=pass (google.com: domain of 32gvfywukcdk9gq9mbjjbg9.7jhf5n5i-89qbjjbg9bmjpkn.7jh@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=32GVFYwUKCdk9GQ9MBJJBG9.7JHF5N5I-89QBJJBG9BMJPKN.7JH@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x1149.google.com (mail-yw1-x1149.google.com. [2607:f8b0:4864:20::1149])
        by gmr-mx.google.com with ESMTPS id k15-20020a170902c40f00b0017f7fffbb13si446189plk.13.2022.10.11.05.47.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 11 Oct 2022 05:47:20 -0700 (PDT)
Received-SPF: pass (google.com: domain of 32gvfywukcdk9gq9mbjjbg9.7jhf5n5i-89qbjjbg9bmjpkn.7jh@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) client-ip=2607:f8b0:4864:20::1149;
Received: by mail-yw1-x1149.google.com with SMTP id 00721157ae682-348608c1cd3so132798877b3.10
        for <kasan-dev@googlegroups.com>; Tue, 11 Oct 2022 05:47:20 -0700 (PDT)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:9c:201:3abd:8519:48e1:da82])
 (user=elver job=sendgmr) by 2002:a25:6dc3:0:b0:6c0:7938:5b3f with SMTP id
 i186-20020a256dc3000000b006c079385b3fmr13344582ybc.625.1665492440186; Tue, 11
 Oct 2022 05:47:20 -0700 (PDT)
Date: Tue, 11 Oct 2022 14:45:35 +0200
Mime-Version: 1.0
X-Mailer: git-send-email 2.38.0.rc1.362.ged0d419d3c-goog
Message-ID: <20221011124534.84907-1-elver@google.com>
Subject: [PATCH] selftests/perf_events: Add a SIGTRAP stress test with disables
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, Peter Zijlstra <peterz@infradead.org>
Cc: Dmitry Vyukov <dvyukov@google.com>, linux-kselftest@vger.kernel.org, 
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com, 
	linux-perf-users@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=Lhj7yGBg;       spf=pass
 (google.com: domain of 32gvfywukcdk9gq9mbjjbg9.7jhf5n5i-89qbjjbg9bmjpkn.7jh@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=32GVFYwUKCdk9GQ9MBJJBG9.7JHF5N5I-89QBJJBG9BMJPKN.7JH@flex--elver.bounces.google.com;
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

Add a SIGTRAP stress test that exercises repeatedly enabling/disabling
an event while it concurrently keeps firing.

Link: https://lore.kernel.org/all/Y0E3uG7jOywn7vy3@elver.google.com/
Signed-off-by: Marco Elver <elver@google.com>
---
 .../selftests/perf_events/sigtrap_threads.c   | 35 +++++++++++++++++--
 1 file changed, 32 insertions(+), 3 deletions(-)

diff --git a/tools/testing/selftests/perf_events/sigtrap_threads.c b/tools/testing/selftests/perf_events/sigtrap_threads.c
index 6d849dc2bee0..d1d8483ac628 100644
--- a/tools/testing/selftests/perf_events/sigtrap_threads.c
+++ b/tools/testing/selftests/perf_events/sigtrap_threads.c
@@ -62,6 +62,8 @@ static struct perf_event_attr make_event_attr(bool enabled, volatile void *addr,
 		.remove_on_exec = 1, /* Required by sigtrap. */
 		.sigtrap	= 1, /* Request synchronous SIGTRAP on event. */
 		.sig_data	= TEST_SIG_DATA(addr, id),
+		.exclude_kernel = 1, /* To allow */
+		.exclude_hv     = 1, /* running as !root */
 	};
 	return attr;
 }
@@ -93,9 +95,13 @@ static void *test_thread(void *arg)
 
 	__atomic_fetch_add(&ctx.tids_want_signal, tid, __ATOMIC_RELAXED);
 	iter = ctx.iterate_on; /* read */
-	for (i = 0; i < iter - 1; i++) {
-		__atomic_fetch_add(&ctx.tids_want_signal, tid, __ATOMIC_RELAXED);
-		ctx.iterate_on = iter; /* idempotent write */
+	if (iter >= 0) {
+		for (i = 0; i < iter - 1; i++) {
+			__atomic_fetch_add(&ctx.tids_want_signal, tid, __ATOMIC_RELAXED);
+			ctx.iterate_on = iter; /* idempotent write */
+		}
+	} else {
+		while (ctx.iterate_on);
 	}
 
 	return NULL;
@@ -208,4 +214,27 @@ TEST_F(sigtrap_threads, signal_stress)
 	EXPECT_EQ(ctx.first_siginfo.si_perf_data, TEST_SIG_DATA(&ctx.iterate_on, 0));
 }
 
+TEST_F(sigtrap_threads, signal_stress_with_disable)
+{
+	const int target_count = NUM_THREADS * 3000;
+	int i;
+
+	ctx.iterate_on = -1;
+
+	EXPECT_EQ(ioctl(self->fd, PERF_EVENT_IOC_ENABLE, 0), 0);
+	pthread_barrier_wait(&self->barrier);
+	while (__atomic_load_n(&ctx.signal_count, __ATOMIC_RELAXED) < target_count) {
+		EXPECT_EQ(ioctl(self->fd, PERF_EVENT_IOC_DISABLE, 0), 0);
+		EXPECT_EQ(ioctl(self->fd, PERF_EVENT_IOC_ENABLE, 0), 0);
+	}
+	ctx.iterate_on = 0;
+	for (i = 0; i < NUM_THREADS; i++)
+		ASSERT_EQ(pthread_join(self->threads[i], NULL), 0);
+	EXPECT_EQ(ioctl(self->fd, PERF_EVENT_IOC_DISABLE, 0), 0);
+
+	EXPECT_EQ(ctx.first_siginfo.si_addr, &ctx.iterate_on);
+	EXPECT_EQ(ctx.first_siginfo.si_perf_type, PERF_TYPE_BREAKPOINT);
+	EXPECT_EQ(ctx.first_siginfo.si_perf_data, TEST_SIG_DATA(&ctx.iterate_on, 0));
+}
+
 TEST_HARNESS_MAIN
-- 
2.38.0.rc1.362.ged0d419d3c-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20221011124534.84907-1-elver%40google.com.
