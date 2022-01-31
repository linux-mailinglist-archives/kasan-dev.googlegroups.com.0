Return-Path: <kasan-dev+bncBC7OBJGL2MHBBKHW32HQMGQEND6J2IY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103b.google.com (mail-pj1-x103b.google.com [IPv6:2607:f8b0:4864:20::103b])
	by mail.lfdr.de (Postfix) with ESMTPS id 9A18A4A4049
	for <lists+kasan-dev@lfdr.de>; Mon, 31 Jan 2022 11:34:18 +0100 (CET)
Received: by mail-pj1-x103b.google.com with SMTP id e7-20020a17090ac20700b001b586e65885sf11311799pjt.1
        for <lists+kasan-dev@lfdr.de>; Mon, 31 Jan 2022 02:34:18 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1643625257; cv=pass;
        d=google.com; s=arc-20160816;
        b=pcwZB0RBdDkDgY3TL32RBgVQvevQi/XQFLdxWP2eQAu+Scv10MxYw1U8CglfBhaNTv
         f2UHrnyjRdPBytkFmNigWwXHaKs4gxQzWwMeY/J00Uc/CzoI7VUq7STYbBYReRyR29TG
         xRK+Ix1an1iv9sAYlmY7LwtPyrTZOmoCX8JR1hPL7L2AnPHyfvYSDrovIlSp19mXmwvI
         PW9dVudxRNXexuY0GOECSUCP5tcHTvG8vZ7a57z9ULap3BZHHSsR38lMm6830uvWvkTx
         6UW5I9a3/yLTwkJxgOULOlhXMAPNF/X8iyUBTNXNKXVWdKlJM7Mvc8R20wiSSJRTdEdD
         h5jA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=Lk+bKt8vrc5S3/FMAOZiwanHx3PqlvO829mebGo63Rc=;
        b=rdgbCFH3vqzD9u/FA2lruoWKQNLEcZzhPk128OQ5iy3NJUMk7OwFqN+9ccGITk0a4L
         ic4a0aW4iJBHmr/tWOnJ9MFAuMm8byGX8IdMzBIiVYW5Pa1EXfwMYARbMmKG/5jwEinJ
         kvzzaFa3MIsgCOZ9yz93KBCzlsetJH7FGL2UiajXESkvwTIO4ylskxT+WT0oxd5NWPL6
         /N+N8ad/8IoKeXoZCherWiz+GoKFazlqf9K0i/HgGbPW5KYzY5EKaE05KskicOK7pAC3
         t0nfZMuq03bVnlX5fX3Kpmz2Q2Pc3CisjaVkIZw/3PjRgH+x0IaLDckuX39gL9P2OIKP
         ntkg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=jBeNywyu;
       spf=pass (google.com: domain of 3jrv3yqukczez6gzc19916z.x975vdv8-yzg19916z1c9fad.x97@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3Jrv3YQUKCZEz6GzC19916z.x975vDv8-yzG19916z1C9FAD.x97@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:message-id:mime-version:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=Lk+bKt8vrc5S3/FMAOZiwanHx3PqlvO829mebGo63Rc=;
        b=fg9qbXtfvX4ryKUNR/YfIcyeZ9ItqxAedy006a+BWYWkEvLGxPv3dL5j04UlDgTb0a
         ICNTOZ5qtaojoY4iNEJrwMohbAIhq6uz7ELPyp0cam+mgxKQ6+hsZ/ZmGsWBIYG6FDjA
         OkBQoUddH3euNWkkKIR9KDCsfZ8Fr/USPJFwDyNwb/1ioYTtB9eiAKPlroWSLM1PckMz
         onvgDaKrZug7IUt5oOaF5op4HcefntPO7/0ZyVPgZyXyTWH4Ugq4n9OiCuaFhg5ny9Cm
         OjtpNQGbyV2nX8UMuBZg01jCOunOVB6VH+TEHrUy6QUYHvAuPIVeWXz4rwBxoYTqLSp7
         XBHQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=Lk+bKt8vrc5S3/FMAOZiwanHx3PqlvO829mebGo63Rc=;
        b=t4gLvwLxBAWH6E8L3L8jQ4SLo/p/qEfr03krxrEIkLXBelrf2qocIHvQSGOVGyL0eK
         N4niZhsnPohcxXMADF0GiRplQLS9u5cty6TEfC6LmVfUVTwtwXjgret4BE4UwHZuJC64
         LX85pQt88ed4bDBaQ8klLXuLnW/zU7R6LiTuwZzs8doa62pbMSWCL26SY79uzy95pvy9
         NGVRi0EkE4rQvZJx02EwRpnxklTymmWhQp2Gfmq1c2ZdTVqFwdVgi4l2m8fWFbcu/1Uj
         KPcMJYX2AVpn3IcaikmLCOG0QckDG3pgpTjvhvYV5rA6OBz6k+McAIo2FqK6Xo2jV7dm
         xPJg==
X-Gm-Message-State: AOAM5316J3HxZBxtDUz229xIQFIXrdDFs42ERbJS/azoTSCeUuQRFbeX
	CawiYqPJphM64qcgc/UhiNU=
X-Google-Smtp-Source: ABdhPJz7b/f2EAITN0FoS0RbhXsqeUVN0WXNzzUFLtC1EJxA+0UG2+kEpuxV/65Nqj2G67N0XN0Syw==
X-Received: by 2002:a63:e1e:: with SMTP id d30mr16672467pgl.352.1643625256949;
        Mon, 31 Jan 2022 02:34:16 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:1011:: with SMTP id gm17ls10991276pjb.2.gmail; Mon,
 31 Jan 2022 02:34:16 -0800 (PST)
X-Received: by 2002:a17:902:c40b:: with SMTP id k11mr19869095plk.94.1643625256219;
        Mon, 31 Jan 2022 02:34:16 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1643625256; cv=none;
        d=google.com; s=arc-20160816;
        b=awR4o1kgeHaE1oIOZSavVlt5PTNSS1Urhb0O5P8D4bqg6joIG8KlpP/82rHTHsWJZA
         aMRx4ccdz8fD5h0H7xYXj3FN70VRMSBVLhT4llzbllVPtjBKKTYi+xMOGj5Ns9rVKIQC
         pvz5jFVaK7uSM5tG6wsNMC9vaI2SSFnA0OPi9Fguo2OFer28K4qKMy417Gpexa1ONXo1
         t0zIIa0QVsqO0Ay5/fLpNDIefIc9zG5fXW8XMrBp40ZqIPokubjDVJ7NnwbDFbfMTZAk
         NFywMy2tKRgr2YlQrIwWu5pmTPuOCT1VFRyWo60Gcus2TIE8jatiePPgKAN/Khop9hIX
         iCsA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=gQiXNhpWeE3w8plSrWyGvN1lrZy07A1L66IKLC7CKbA=;
        b=H71L2gJZRQl56ddN3GfXbry7eKK/3eydpT2r9VD6usvVhyNtuQiSA6jxAaiGEOeL6o
         /Xqiu1B5Rw1lR9/MrkPF/2tH9+owr4IoPm1gQeeDNx5VsCtuHpeCO3sy8Xtiia3RMZ8P
         UhKeeB9Vg5oBBfALScBuJDwXxC/xfEDt+YmdJ86kGujfZVnFHANfunIz1fjJxtSeLx2R
         0ZWgRbmcqLtxRHnTTtZ5RMGYc+8rhrSFYNfnteURyFR8vTw+DwwyDNZaOhGB51yTG2Zc
         ayJDi0FvAtzvn2aF/e5eZ2qrlCWPXGUQ53xs8Vhd7M3PypDi8GCHyRcpjILnP3XXi4Ib
         uG+Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=jBeNywyu;
       spf=pass (google.com: domain of 3jrv3yqukczez6gzc19916z.x975vdv8-yzg19916z1c9fad.x97@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3Jrv3YQUKCZEz6GzC19916z.x975vDv8-yzG19916z1C9FAD.x97@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb4a.google.com (mail-yb1-xb4a.google.com. [2607:f8b0:4864:20::b4a])
        by gmr-mx.google.com with ESMTPS id i8si471096pjv.2.2022.01.31.02.34.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 31 Jan 2022 02:34:16 -0800 (PST)
Received-SPF: pass (google.com: domain of 3jrv3yqukczez6gzc19916z.x975vdv8-yzg19916z1c9fad.x97@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) client-ip=2607:f8b0:4864:20::b4a;
Received: by mail-yb1-xb4a.google.com with SMTP id b2-20020a252e42000000b00619593ff8ddso14620150ybn.6
        for <kasan-dev@googlegroups.com>; Mon, 31 Jan 2022 02:34:16 -0800 (PST)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:76:dcf3:95f9:db8b])
 (user=elver job=sendgmr) by 2002:a81:6fc5:: with SMTP id k188mr1653ywc.507.1643625254572;
 Mon, 31 Jan 2022 02:34:14 -0800 (PST)
Date: Mon, 31 Jan 2022 11:34:05 +0100
Message-Id: <20220131103407.1971678-1-elver@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.35.0.rc2.247.g8bbb082509-goog
Subject: [PATCH 1/3] perf: Copy perf_event_attr::sig_data on modification
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
 header.i=@google.com header.s=20210112 header.b=jBeNywyu;       spf=pass
 (google.com: domain of 3jrv3yqukczez6gzc19916z.x975vdv8-yzg19916z1c9fad.x97@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3Jrv3YQUKCZEz6GzC19916z.x975vDv8-yzG19916z1C9FAD.x97@flex--elver.bounces.google.com;
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

The intent has always been that perf_event_attr::sig_data should also be
modifiable along with PERF_EVENT_IOC_MODIFY_ATTRIBUTES, because it is
observable by user space if SIGTRAP on events is requested.

Currently only PERF_TYPE_BREAKPOINT is modifiable, and explicitly copies
relevant breakpoint-related attributes in hw_breakpoint_copy_attr().
This misses copying perf_event_attr::sig_data.

Since sig_data is not specific to PERF_TYPE_BREAKPOINT, introduce a
helper to copy generic event-type-independent attributes on
modification.

Fixes: 97ba62b27867 ("perf: Add support for SIGTRAP on perf events")
Reported-by: Dmitry Vyukov <dvyukov@google.com>
Signed-off-by: Marco Elver <elver@google.com>
---
 kernel/events/core.c | 16 ++++++++++++++++
 1 file changed, 16 insertions(+)

diff --git a/kernel/events/core.c b/kernel/events/core.c
index fc18664f49b0..db0d85a85f1b 100644
--- a/kernel/events/core.c
+++ b/kernel/events/core.c
@@ -3197,6 +3197,15 @@ static int perf_event_modify_breakpoint(struct perf_event *bp,
 	return err;
 }
 
+/*
+ * Copy event-type-independent attributes that may be modified.
+ */
+static void perf_event_modify_copy_attr(struct perf_event_attr *to,
+					const struct perf_event_attr *from)
+{
+	to->sig_data = from->sig_data;
+}
+
 static int perf_event_modify_attr(struct perf_event *event,
 				  struct perf_event_attr *attr)
 {
@@ -3219,10 +3228,17 @@ static int perf_event_modify_attr(struct perf_event *event,
 	WARN_ON_ONCE(event->ctx->parent_ctx);
 
 	mutex_lock(&event->child_mutex);
+	/*
+	 * Event-type-independent attributes must be copied before event-type
+	 * modification, which will validate that final attributes match the
+	 * source attributes after all relevant attributes have been copied.
+	 */
+	perf_event_modify_copy_attr(&event->attr, attr);
 	err = func(event, attr);
 	if (err)
 		goto out;
 	list_for_each_entry(child, &event->child_list, child_list) {
+		perf_event_modify_copy_attr(&child->attr, attr);
 		err = func(child, attr);
 		if (err)
 			goto out;
-- 
2.35.0.rc2.247.g8bbb082509-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220131103407.1971678-1-elver%40google.com.
