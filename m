Return-Path: <kasan-dev+bncBC7OBJGL2MHBBYW6TPZAKGQEGS2FRIA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe40.google.com (mail-vs1-xe40.google.com [IPv6:2607:f8b0:4864:20::e40])
	by mail.lfdr.de (Postfix) with ESMTPS id 11CF415F657
	for <lists+kasan-dev@lfdr.de>; Fri, 14 Feb 2020 20:05:08 +0100 (CET)
Received: by mail-vs1-xe40.google.com with SMTP id r3sf773175vsl.14
        for <lists+kasan-dev@lfdr.de>; Fri, 14 Feb 2020 11:05:08 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1581707107; cv=pass;
        d=google.com; s=arc-20160816;
        b=YG2L7p6D18kP/g/e90T2GNdJ2lgkutZ3/bczwq2oNuOaioPLzSG/lA49ZRFSMaAAsK
         zdfsadSuFJZaIFYHpsPwnaZkyzEMipzyC+QGJOM/KNPrAiW/EzF0b0x9dRCgdeuOczmR
         KRRQ5M5YhwJdz5vaIrJfM29I355mFkMwTyRFk38NxPJXKeVVw1iHb/QsUeywprMcKyLu
         6qFsX9ZvonBKrcGVs9n8PH+JOww4hDSRK1JRi9m9LVSKF8SX8MmjVhRWkp1HcD001CoZ
         gMKoToS6TPbRd5hmYdppB1EiclHDRLoi0lo0ey1CIoZeSmZWVBkmr62fOR2rmkZgCgqf
         EjPA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=sVbnUcaLw3SpLvKdITO0ns1uRmhhBQNK8P82GFknhXA=;
        b=IhlI8qZY8G/cWldTUNH3F/rEXzBpobOePG/yYCHhay/P0Nr0Dnd1rMs/mjjjxQ12Kg
         LE4O+FrTqcsBZl3/pYrqxG6tMbNHd72sNN8KLpNlKgi54cbIaN1MwGIKMu3fUsuX5y0J
         Oh/71XkQkbGXcKqwPsECa/t6CmgE5nKcCUgOiT2ySTbqoFiGoExtkJXRUBbxWfIp0TCM
         kxWMfozQc97qB0rXeLDJYm6U9vMb+oWc+GXsSht1Cr77nAzg1ipAMHpCKTdE84cC9RY3
         rgpozVgQHTXv0JaX4GQQYDr3JnszD3npa1+k3TsQCNbQ0icIJ1eaEt/0ysHdbKs0bacJ
         La6w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="hrlR0/0d";
       spf=pass (google.com: domain of 3yu9gxgukcvu18i1e3bb381.zb97xfxa-01i3bb3813ebhcf.zb9@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::e4a as permitted sender) smtp.mailfrom=3Yu9GXgUKCVU18I1E3BB381.zB97xFxA-01I3BB3813EBHCF.zB9@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:message-id:mime-version:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=sVbnUcaLw3SpLvKdITO0ns1uRmhhBQNK8P82GFknhXA=;
        b=hsTMP/h0byla+lzARAue+/aLoMHWiclwMH8fOPNGZIpibUg8GZybvrB9xhrcn7ZY+m
         tFt3S3NYlcmXzhWpywHg0tbnAT8857sBSIB8v8Hr1Uz0sNioF4URgPaG0VDQNs6u0/sT
         96Iyi8wofyJYLTsTb/NujvU5P7WK7jJKnVlN+ImISIK0Xhn4y6kIRrBU9ubsnTfQwz7z
         aZ8ZlvEpfTd/XOhACzoLF46e9obigQ5+9DGECGq6VDvyLqKiKpiKHdux8+j3OcWXIeJc
         eKOfWofqAtujrnpf8W/AMO2bAJi7WSTf7obtIjBmUX8w7y1P7frpo+By73KQUWjsBqjD
         zaVA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=sVbnUcaLw3SpLvKdITO0ns1uRmhhBQNK8P82GFknhXA=;
        b=JqAn09sFg7+zEGuFFfk7T+ctGeSeQepOqrznuyVSjr1GEKjLa7mj9ZA/h0D7K605zT
         MlHsc515l3flUQxAmCniyjtzwztXhzCHN1KS/QIW2ty6P0U51LxwjHavxMZdwqzeEO3M
         oBvgzbTjWae/NAJ6h0Pigphn6jr9llXUf9tZ+akn7h46gMb9AINIewSmB1o6tghcZk/S
         OtgbIh1VSdawpdbALkTo3JjEZms9U3tPqRd/kZM3exw0cpCasXlcn3gFO4WzFkmAZFTh
         8e4ohATB/d1WU0GVONCFYbnAgNQEpINZo1tP7Yqe4JoGepJs9P/4e8HKOgQbVnyRRtwh
         Q+xg==
X-Gm-Message-State: APjAAAWshnp2aHxgHpHzTwLhuHWOtX1Loa9kW63R0n+7t7EAsmbBh3bL
	Pd00n0HlXWxe9xx4Y0Cpuy4=
X-Google-Smtp-Source: APXvYqzDDvae3rZsFJswLGTqfWpyjpQS7GCfvI6sDsjTfAuxyY6UDhIWSKX1u0FVUTfRlTRwFbjdnw==
X-Received: by 2002:a05:6102:7d8:: with SMTP id y24mr2376657vsg.78.1581707106991;
        Fri, 14 Feb 2020 11:05:06 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ab0:7807:: with SMTP id x7ls207823uaq.5.gmail; Fri, 14 Feb
 2020 11:05:06 -0800 (PST)
X-Received: by 2002:ab0:64cd:: with SMTP id j13mr2403746uaq.127.1581707106528;
        Fri, 14 Feb 2020 11:05:06 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1581707106; cv=none;
        d=google.com; s=arc-20160816;
        b=kzUmLFsZEPjgwnKxT1z2DsldSL/KOXDGuUePk4vKOpwqwNH42DcZXK+ohDUOsnxabh
         HsmHyHToC7esMVFL+lSAyEz4sOANFVDgDSwg1U+nJfYv+sfHQHUELZcC9vKzZ9ZTt3eh
         M0xisUqDtjF3v3/wKjSbURkKXhr91SoU1DyWSXsjWF0w/xDgG0N/8u2nYxT1KftoTBHb
         XLRF836DHyPCZ3cwRnvAd+ehbuZ7ZMXJZGkksjgajzn8DcXA3fT3LdyzzhUA6sqm7EAm
         n0sRqeIe36ATtNyPfuaLvCKCJoKDhIFNfScJNBU2co03YfH/XRDbX4o+8++cjj6UVw9B
         7dIQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=y0VpLWlLrgreaXGyU2aGKFidKfIZR/ank1/JutXFGq8=;
        b=QvcijQ+RVnJGN506/slzGKc32CBfHS76jLgLWCjqYjLwMp0NSXd1A6ITPcZctHb9J4
         Lbcv9aUUNB0PFv/R/u8U6VDqHfksKYSHnKV/MK8+7G6BDFp8BQWDd7ODuPOS+7XglDTU
         /YU9SbnT7IMCI2eGDMMV28okWzT/SOp8OtntuE0du4J4AglM4RQYNf8atgD//wsBgVcL
         RExlBcaDEPO2DP9BifZBXnuLJal4bDYMHHp91aTKf7fCa6eL9zzQ5e6a/wu9W1YYYPgW
         CmmL8ePn21PH+bjq9pXoKDVYZHfK5gK6VdoDqTvh1uxrN3avp/jrUduHbxErwxZaGvzZ
         6/SA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="hrlR0/0d";
       spf=pass (google.com: domain of 3yu9gxgukcvu18i1e3bb381.zb97xfxa-01i3bb3813ebhcf.zb9@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::e4a as permitted sender) smtp.mailfrom=3Yu9GXgUKCVU18I1E3BB381.zB97xFxA-01I3BB3813EBHCF.zB9@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-vs1-xe4a.google.com (mail-vs1-xe4a.google.com. [2607:f8b0:4864:20::e4a])
        by gmr-mx.google.com with ESMTPS id k26si382246uao.0.2020.02.14.11.05.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 14 Feb 2020 11:05:06 -0800 (PST)
Received-SPF: pass (google.com: domain of 3yu9gxgukcvu18i1e3bb381.zb97xfxa-01i3bb3813ebhcf.zb9@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::e4a as permitted sender) client-ip=2607:f8b0:4864:20::e4a;
Received: by mail-vs1-xe4a.google.com with SMTP id f15so772612vsk.21
        for <kasan-dev@googlegroups.com>; Fri, 14 Feb 2020 11:05:06 -0800 (PST)
X-Received: by 2002:a67:80d3:: with SMTP id b202mr2286028vsd.142.1581707106155;
 Fri, 14 Feb 2020 11:05:06 -0800 (PST)
Date: Fri, 14 Feb 2020 20:05:00 +0100
Message-Id: <20200214190500.126066-1-elver@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.25.0.265.gbab2e86ba0-goog
Subject: [PATCH] kcsan, trace: Make KCSAN compatible with tracing
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com
Cc: paulmck@kernel.org, andreyknvl@google.com, glider@google.com, 
	dvyukov@google.com, kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, 
	rostedt@goodmis.org, mingo@redhat.com, Qian Cai <cai@lca.pw>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="hrlR0/0d";       spf=pass
 (google.com: domain of 3yu9gxgukcvu18i1e3bb381.zb97xfxa-01i3bb3813ebhcf.zb9@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::e4a as permitted sender) smtp.mailfrom=3Yu9GXgUKCVU18I1E3BB381.zB97xFxA-01I3BB3813EBHCF.zB9@flex--elver.bounces.google.com;
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

Previously the system would lock up if ftrace was enabled together with
KCSAN. This is due to recursion on reporting if the tracer code is
instrumented with KCSAN.

To avoid this for all types of tracing, disable KCSAN instrumentation
for all of kernel/trace.

Signed-off-by: Marco Elver <elver@google.com>
Reported-by: Qian Cai <cai@lca.pw>
Cc: Paul E. McKenney <paulmck@kernel.org>
Cc: Steven Rostedt <rostedt@goodmis.org>
---
 kernel/kcsan/Makefile | 2 ++
 kernel/trace/Makefile | 3 +++
 2 files changed, 5 insertions(+)

diff --git a/kernel/kcsan/Makefile b/kernel/kcsan/Makefile
index df6b7799e4927..d4999b38d1be5 100644
--- a/kernel/kcsan/Makefile
+++ b/kernel/kcsan/Makefile
@@ -4,6 +4,8 @@ KCOV_INSTRUMENT := n
 UBSAN_SANITIZE := n
 
 CFLAGS_REMOVE_core.o = $(CC_FLAGS_FTRACE)
+CFLAGS_REMOVE_debugfs.o = $(CC_FLAGS_FTRACE)
+CFLAGS_REMOVE_report.o = $(CC_FLAGS_FTRACE)
 
 CFLAGS_core.o := $(call cc-option,-fno-conserve-stack,) \
 	$(call cc-option,-fno-stack-protector,)
diff --git a/kernel/trace/Makefile b/kernel/trace/Makefile
index f9dcd19165fa2..6b601d88bf71e 100644
--- a/kernel/trace/Makefile
+++ b/kernel/trace/Makefile
@@ -6,6 +6,9 @@ ifdef CONFIG_FUNCTION_TRACER
 ORIG_CFLAGS := $(KBUILD_CFLAGS)
 KBUILD_CFLAGS = $(subst $(CC_FLAGS_FTRACE),,$(ORIG_CFLAGS))
 
+# Avoid recursion due to instrumentation.
+KCSAN_SANITIZE := n
+
 ifdef CONFIG_FTRACE_SELFTEST
 # selftest needs instrumentation
 CFLAGS_trace_selftest_dynamic.o = $(CC_FLAGS_FTRACE)
-- 
2.25.0.265.gbab2e86ba0-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200214190500.126066-1-elver%40google.com.
