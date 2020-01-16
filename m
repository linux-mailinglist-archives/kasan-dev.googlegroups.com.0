Return-Path: <kasan-dev+bncBC4NLWXH4YGBBLULQHYQKGQE63GQ7CA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x240.google.com (mail-lj1-x240.google.com [IPv6:2a00:1450:4864:20::240])
	by mail.lfdr.de (Postfix) with ESMTPS id 07A3B13D8C7
	for <lists+kasan-dev@lfdr.de>; Thu, 16 Jan 2020 12:14:55 +0100 (CET)
Received: by mail-lj1-x240.google.com with SMTP id z17sf5014378ljz.2
        for <lists+kasan-dev@lfdr.de>; Thu, 16 Jan 2020 03:14:55 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1579173294; cv=pass;
        d=google.com; s=arc-20160816;
        b=r/zsGpYIps7y+Audg4ih6yYA00qewYUmyxXFCzM77lpmh/DNFdcHDiaTh+Hpfm9Bzr
         1CiH+MZSlj/t25Pz5MV+zscPxpN2LMe0698xNxtXFjwwW3zRGxGL5G3dBUjyvaiIQMuN
         DmWKXVf5xady18elr0vosk7uketmK8uC+YuNrgikZSJ6t9uSW93wAyD8mt2O4zx6ZKQr
         dLz/W9yjn9bL226IG+lXkpg3w1pDcMhpO4iJgPY5o6lqI16Ym+UyoDov/ec95U16MV5S
         se3OlO7eobyX48dJEKlx/8DicxJAnSKXnEQ4PmMY2WFMLqadJ8hG5BNMoFrf0Xg9sYpr
         NSpg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature:dkim-signature;
        bh=tblgLD3GSUSU4f4oRZrM5p6jZczOOH5G5ciUcwGq0y8=;
        b=K7L9YB9SXZZfldapHhMeVEFry76aXqsAnSjells4/mz4nD+wD+2GfngHAnZg7ot89W
         nVO5oNBh93+V0iN6UoR5BjlC3CU5hsXSxpPbvJe7czOZFYr+AwiLX6r8wRl9k2uiBDnm
         eN5iZwMd400g6+BdxEG2r0cE/0dOPr2z1FTIjH9CHak+86V9EMll6fADpJ8xXhSozyQq
         xacOOoP1aCawnxyHe32cLA4jVVDo+0VZYYl47Ji5HxbMiPxXGO8h2NPCQAYyE8vq+Ka8
         wUmlF0MOKNlCI5rlak2Ru4xAo/4M+zD9SKdONNuaV4y1NnGbmeoYgQEJxC1rKa93wH0E
         0Y4A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=jYfYaY1Y;
       spf=pass (google.com: domain of dvyukov@gmail.com designates 2a00:1450:4864:20::442 as permitted sender) smtp.mailfrom=dvyukov@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=tblgLD3GSUSU4f4oRZrM5p6jZczOOH5G5ciUcwGq0y8=;
        b=H0dhXzkgwXuO4A0m7/8cLr5JYLlU9FA580VlW0ZA2FFXa6UrAWmNl/9ZuQu/PqjSPQ
         xgFD45hOCbVaJrixgbCCsT8nYMicZv4u1sA43vUjhTibGkm3wrgIa4Xfr/oiDiiSOb2Q
         NDUec8942HyUauYXnbxYk3GWtbe0HpuzgK9dPrb+7a/G0DlpFru9Z7FPJfhrP7cpenbC
         ZeWe50yiC/h9gRMuR/6G0cx9+dcHze+dpHAqjv21pHaaV4pdPtQoFQ18m6+jMJISlVVy
         4TZg+5CLgaPXjJEZnlg4yIta1ig0QrioaRiBqTbaCS9Te1d5f0LGVfHKU9PD4JNXcsDc
         8w/w==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=from:to:cc:subject:date:message-id:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=tblgLD3GSUSU4f4oRZrM5p6jZczOOH5G5ciUcwGq0y8=;
        b=seA8sleYVG6S6ioKvYGApEo7dD5m+6sL6Hyiogpqvkkp6pgFuttyGUXDoFfrMYLs4d
         DFJkh4hQ+KzX/QAxaWA5MgkrdktyD38AUy9XHGnhH6cVP315rLgcdPP4swZdL+Wy9ry5
         oCA4XyAXrTjrRgBpnbKqEEE9YFtFESeg8ok00X9bkMn7txoCwsW5rId3hdxJsFJCMcow
         S4YXq//bHs9KxOW1ZCFW1br9PfxtEq5y2nXWQP2/0WM9wwm8JHoyqfTnSpeMNOF6GUFW
         xf8muMfR0C4RDuHmBmKv5prKyp9kg7SeLx+8zd8CC3b3GI4uAyf2Mc2lTY6wIU8Gddjk
         r32g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=tblgLD3GSUSU4f4oRZrM5p6jZczOOH5G5ciUcwGq0y8=;
        b=Xve7FXTlXGaQDwvff6iVBEAiwiH6mDXlUDSnxUKfhGCrXdT44YfS8hiXj0YTZuBhnB
         9J17H9xONbcgcWRdtnaLEsB0zOZB8RuK5y44TyhRtZSOi5ojnqx2tdPVAumIjKi7pAtg
         KZXwDk0uCoIj9569xkzxmxclMk+r1kI4yRA0PCFviJpLOEA/8mwYrJRRkdDHBaj7gGVj
         jFQMxCjD8K5fMyjZ2ZsShVHaqiH2UeiU3ecrA282B9ujjsiEMr4V4Prq4AM+pubxVAQz
         3OrhYwcVZFa7S0FcsvUeMLDduXxj06qAHZfIiXC5/HYozgEiINdVhb4JGBE3cib45LiK
         V5lw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAUAPBtcamK43lqUvCHVyDj6eYO5GvoaZbQ67i+B275lA+5vFOMI
	iiPxUPc6ybgxZA+1ZZc+sDQ=
X-Google-Smtp-Source: APXvYqxuX7JqBLz7T7WlrBCSNmcWhyfAUsN8Tti5OrAOQB6/JnA2+LRXHMso36WjdfF0h5PJZf//Bg==
X-Received: by 2002:a19:7401:: with SMTP id v1mr2190289lfe.129.1579173294606;
        Thu, 16 Jan 2020 03:14:54 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:9c85:: with SMTP id x5ls3049424lji.0.gmail; Thu, 16 Jan
 2020 03:14:54 -0800 (PST)
X-Received: by 2002:a05:651c:2046:: with SMTP id t6mr1951253ljo.180.1579173294039;
        Thu, 16 Jan 2020 03:14:54 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1579173294; cv=none;
        d=google.com; s=arc-20160816;
        b=F30G4PQmLGWpL2G0Re2IXQuNtk8ciANXokkqHHeexWKpJaETPBZCgT2wPArN5rsL5f
         HbJshfQvcj/oAruqvT2YOjFR0OGjCVqU19V8tnwTWAKHZu8eOYGXDtiNBCVI4qKPtGYF
         TxSay04yPSXVwFQdb796nl6IYybXrSPKqITmUTVpr6duYEsaHNBxySowhKA44vg6XNJ8
         nk5MHGFY+sC+Fbqf4/MYT82RlUsUy+e8J96UfJf43q/70OWyMC1VrospxLOiQvOGMLvr
         T3GmMu0Jrp3gkNGpctpxQwoCWSBzsOhrHln0Zr/JQDDqQxonvNjXE/WsuXPaFkwkoFIW
         x2ig==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=R9Q5677Ur8luUcGkjg5jrHlKUFNub/5xyB+iK5Dfa/s=;
        b=uljtkS42+cKQLey09zj3g2qCIulGI6RDco0Pv1/SN9BfF4aeET7qFoYkIKM1J1k60n
         5P6zd5kFc6FCnTK7BEn6qiJqtCs+Tawfdcqsx2gEaMg5n2NkF5acORSHWP7jj2Ke7FfK
         l6vccDG2cxJjABnhTjuKZyGcacKPWzzMFcBRvNa3FkzLY2rkd0gPI9kALh6KoiHJgIyw
         W1+tSqLzpYTaISRQh5fP632SqBBmZjWJiGvJX+tA0sv9BKrEgWbFi5J33uQ+yP5zsEKQ
         9IOBLCIZPK1NsK+/+VuSAPtIjmAgZjG/tBhorqGpd3VmYA7UP5A+s24fWmP660XURjHG
         U/cA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=jYfYaY1Y;
       spf=pass (google.com: domain of dvyukov@gmail.com designates 2a00:1450:4864:20::442 as permitted sender) smtp.mailfrom=dvyukov@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-wr1-x442.google.com (mail-wr1-x442.google.com. [2a00:1450:4864:20::442])
        by gmr-mx.google.com with ESMTPS id z16si822971ljk.0.2020.01.16.03.14.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 16 Jan 2020 03:14:54 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@gmail.com designates 2a00:1450:4864:20::442 as permitted sender) client-ip=2a00:1450:4864:20::442;
Received: by mail-wr1-x442.google.com with SMTP id g17so18716444wro.2
        for <kasan-dev@googlegroups.com>; Thu, 16 Jan 2020 03:14:54 -0800 (PST)
X-Received: by 2002:adf:9c8f:: with SMTP id d15mr2748995wre.390.1579173293323;
        Thu, 16 Jan 2020 03:14:53 -0800 (PST)
Received: from dvyukov-desk.muc.corp.google.com ([2a00:79e0:15:13:aecf:473e:300f:893f])
        by smtp.gmail.com with ESMTPSA id w19sm3573792wmc.22.2020.01.16.03.14.52
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 16 Jan 2020 03:14:52 -0800 (PST)
From: Dmitry Vyukov <dvyukov@gmail.com>
To: akpm@linux-foundation.org
Cc: Dmitry Vyukov <dvyukov@google.com>,
	Andrey Konovalov <andreyknvl@google.com>,
	kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org
Subject: [PATCH] kcov: ignore fault-inject and stacktrace
Date: Thu, 16 Jan 2020 12:14:49 +0100
Message-Id: <20200116111449.217744-1-dvyukov@gmail.com>
X-Mailer: git-send-email 2.25.0.rc1.283.g88dfdc4193-goog
MIME-Version: 1.0
X-Original-Sender: dvyukov@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=jYfYaY1Y;       spf=pass
 (google.com: domain of dvyukov@gmail.com designates 2a00:1450:4864:20::442 as
 permitted sender) smtp.mailfrom=dvyukov@gmail.com;       dmarc=pass (p=NONE
 sp=QUARANTINE dis=NONE) header.from=gmail.com
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

From: Dmitry Vyukov <dvyukov@google.com>

Don't instrument 3 more files that contain debugging facilities and
produce large amounts of uninteresting coverage for every syscall.
The following snippets are sprinkled all over the place in kcov
traces in a debugging kernel. We already try to disable instrumentation
of stack unwinding code and of most debug facilities. I guess we
did not use fault-inject.c at the time, and stacktrace.c was somehow
missed (or something has changed in kernel/configs).
This change both speeds up kcov (kernel doesn't need to store these
PCs, user-space doesn't need to process them) and frees trace buffer
capacity for more useful coverage.

should_fail
lib/fault-inject.c:149
fail_dump
lib/fault-inject.c:45

stack_trace_save
kernel/stacktrace.c:124
stack_trace_consume_entry
kernel/stacktrace.c:86
stack_trace_consume_entry
kernel/stacktrace.c:89
... a hundred frames skipped ...
stack_trace_consume_entry
kernel/stacktrace.c:93
stack_trace_consume_entry
kernel/stacktrace.c:86

Signed-off-by: Dmitry Vyukov <dvyukov@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>
Cc: Andrey Konovalov <andreyknvl@google.com>
Cc: kasan-dev@googlegroups.com
Cc: linux-kernel@vger.kernel.org
---
 kernel/Makefile | 1 +
 lib/Makefile    | 1 +
 mm/Makefile     | 1 +
 3 files changed, 3 insertions(+)

diff --git a/kernel/Makefile b/kernel/Makefile
index e5ffd8c002541..5d935b63f812a 100644
--- a/kernel/Makefile
+++ b/kernel/Makefile
@@ -30,6 +30,7 @@ KCSAN_SANITIZE_softirq.o = n
 # and produce insane amounts of uninteresting coverage.
 KCOV_INSTRUMENT_module.o := n
 KCOV_INSTRUMENT_extable.o := n
+KCOV_INSTRUMENT_stacktrace.o := n
 # Don't self-instrument.
 KCOV_INSTRUMENT_kcov.o := n
 KASAN_SANITIZE_kcov.o := n
diff --git a/lib/Makefile b/lib/Makefile
index 004a4642938af..6cd19bb3085c5 100644
--- a/lib/Makefile
+++ b/lib/Makefile
@@ -16,6 +16,7 @@ KCOV_INSTRUMENT_rbtree.o := n
 KCOV_INSTRUMENT_list_debug.o := n
 KCOV_INSTRUMENT_debugobjects.o := n
 KCOV_INSTRUMENT_dynamic_debug.o := n
+KCOV_INSTRUMENT_fault-inject.o := n
 
 # Early boot use of cmdline, don't instrument it
 ifdef CONFIG_AMD_MEM_ENCRYPT
diff --git a/mm/Makefile b/mm/Makefile
index 3c53198835479..c9696f3ec8408 100644
--- a/mm/Makefile
+++ b/mm/Makefile
@@ -28,6 +28,7 @@ KCOV_INSTRUMENT_kmemleak.o := n
 KCOV_INSTRUMENT_memcontrol.o := n
 KCOV_INSTRUMENT_mmzone.o := n
 KCOV_INSTRUMENT_vmstat.o := n
+KCOV_INSTRUMENT_failslab.o := n
 
 CFLAGS_init-mm.o += $(call cc-disable-warning, override-init)
 CFLAGS_init-mm.o += $(call cc-disable-warning, initializer-overrides)
-- 
2.25.0.rc1.283.g88dfdc4193-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200116111449.217744-1-dvyukov%40gmail.com.
