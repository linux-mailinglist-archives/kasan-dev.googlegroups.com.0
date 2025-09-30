Return-Path: <kasan-dev+bncBD53XBUFWQDBBPMI5XDAMGQE6CUQXDA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x437.google.com (mail-pf1-x437.google.com [IPv6:2607:f8b0:4864:20::437])
	by mail.lfdr.de (Postfix) with ESMTPS id 7A141BAB0D2
	for <lists+kasan-dev@lfdr.de>; Tue, 30 Sep 2025 04:45:19 +0200 (CEST)
Received: by mail-pf1-x437.google.com with SMTP id d2e1a72fcca58-780f9cc532bsf4547802b3a.0
        for <lists+kasan-dev@lfdr.de>; Mon, 29 Sep 2025 19:45:19 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1759200318; cv=pass;
        d=google.com; s=arc-20240605;
        b=T2aA4e5WrIZem/TYEeaowoh9IJA68tkGFn3xH/ADH52K9E29h/akLvjDNrcKHnLBVw
         A2tdhyn4AEFG+Y6X5xSEGk1GWRAxoXPlfMCCneanKyRfa4XZmb0MPoTKHDVw2oPpgHTy
         hyKo/OT95DaNKUxI4dVca16OR604hERnbx7gtkvv4lg0+Etd5EZvfsKBrWYHuo22k6uN
         8DWbXBrB1GTDfXs+o125YrtCb9M5XCG8S767pg7ldKMFCjFwp3F90cWJP5Bi9jf6qF11
         WTWLh2wUN4Ot3KSYKhIdjfBpKcMuYfICJGA1aFHbjzC2wGjPKQ0aXIEWvguHt0Kt/map
         xnNQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=onqyNeSfv0lkk8/5XEyFpd87cJfNRqooSWHDIjAU1fU=;
        fh=fUPuviso72YcuQ6qN5yJZYYE5A4NfR5dCvmWSr+IWTM=;
        b=PWTxUC5Kmg+Res+1PLXe3UwjcZ5noKCXwujl3REGu2NmdLyNvHt49KBFyudGHG6wVa
         NVsC52SyoNOm/nk8nwE0ONazaO6u9Nw55KTT3jFzLX6FNlg2t0IC0t3w6ZM2sd8/B5Uq
         WUjTcVzV41Glkfx9oWk6pmweR4v1KHxE4gNSfO6Njhb3217y+WaqU1zjcU5AnXryGeGK
         nfSSsz8cbZfZEik0iMqWGhpcr4OvN7JrFamcXYnzuBMgg0Ss9M+OQouH0pVGMK9AM64o
         QgOFD6qU6sjyS1vT6uHO+yflXS2qUd4ndhHs7Qx8WtC2pGvgPnvXgC1D1Rf8Qno5isc6
         +Prw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=QxLV1mJD;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::433 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1759200318; x=1759805118; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=onqyNeSfv0lkk8/5XEyFpd87cJfNRqooSWHDIjAU1fU=;
        b=IP26AY6RpJCZV3NKHzNCEYCAnnSqiIgGVM49xCwNonRayzjGRNE+l6ru2oTXR4Ks3o
         WRBhm38QK4xKGPbPeTiedaWvVTI2OoIjxUGuF4kHlNnVKsvi3OsGTXMOiKGbddKVZUFT
         ZlzktfmaNAlDmFIAlC9jARV7H5uPVQvhNrRzDMszSvhxTPneVzT6TtM7sk9MKRib44Nd
         He6IE2IfvJw0r+ayrd2D8NbLaTr0fMT1/3LMkv9tyEs9MQH0SSyTUYsm9PvfM4Y7YmVP
         e3bP61X9hvoCo1YnYOyNyh9PDWJircg/jagoP1uFB5L+x0m/ekucjN1ZtJribonoMrZV
         xFag==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1759200318; x=1759805118; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=onqyNeSfv0lkk8/5XEyFpd87cJfNRqooSWHDIjAU1fU=;
        b=DdcYEUFpn996dVpUG4f5gAMTtvblqeGhkl8gXEMJfa0K3efksQSS6tAk0dRTjzTdzm
         +QYplfjQ/uBoMbwHWsP1zpJJQmcqVBljRZ8PSykl9D9vijXqdZATLgKfUrurrD1m7Ps0
         HBlRv/ulxcWhFcGWDatsz2nhwk4ILdowAgNbOqavv+BIMrsmUvMDn9qHWlhpqBcD1w4M
         iytKN8v3miyZq6eauvdKS878AGgSyWmo2s/zQlstjanJ7dHfkHLeWJTTKbg6E4kqK4am
         qQfuMvhqVg36O6IB65x6cI+MEGoCqfIAubzBe4qxMtiTtvhHRnv+1ySTwVa4zpcewqGQ
         2HTw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1759200318; x=1759805118;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=onqyNeSfv0lkk8/5XEyFpd87cJfNRqooSWHDIjAU1fU=;
        b=BMJxxAyosEYZJ8Br90iBzpWu7i2BzJSRWy6hbInpTW5sKUOOeoDLuGTGHvPjT7mfC3
         431BXJ78oQbam1KZ1l6XUvgx5slPaRvJ2n3bFh6FpF94d9b6WUKDjWtzswGNbKdFCnnA
         xbI4wDqzEgdO1Dzi+u1r+y12vDqxR8Cih8yvD51GWNEv31Ign4+2GX44GouhPUFPHjuO
         HzTQzPhQ4GKQyBLYszl0ZI6HG2oXEp9bkDk5LXqDPSTZmg2m+h+kFje6Yi0rGObcxIyA
         HtYdb0d0kVBXldUzijBlKaetISHRXujmzkM7SkShkqChVQXxM8blPk8GY4VLyJ77FKaa
         NDYA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUDr7dqsCuMLeNSj/b4XBfh2rKHYiqUz2gPjQI6jg48UmJAddK7gyA/YnUbrZa1QSjUvv5zsQ==@lfdr.de
X-Gm-Message-State: AOJu0YzDKnF7+9yRW22wlHXnyrr4vyR0eAxniTYuVtKZBr2heHfvTuLh
	tFb2fjNN9kPvYASpfHBaKdf2KyXeIQc+DYaIa7HMhU+L3ADm75267Ntc
X-Google-Smtp-Source: AGHT+IGIbVs9H84rrpH4pxu5JpDpX7g1UYzJnyeowsr0Oq4J4qgN8s1yUh1CRMetPV0edTMPeJ4ZWw==
X-Received: by 2002:a05:6a00:4fd0:b0:781:1f58:ce6e with SMTP id d2e1a72fcca58-787c7abba8bmr2906731b3a.4.1759200317791;
        Mon, 29 Sep 2025 19:45:17 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="ARHlJd6/xDp3a4sx8eKLnKQGkdQ09p50EuGC1CewKKwRfrNjTw=="
Received: by 2002:a05:6a00:80e1:b0:77f:6183:5d56 with SMTP id
 d2e1a72fcca58-780fee1da84ls2053293b3a.2.-pod-prod-00-us; Mon, 29 Sep 2025
 19:45:16 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWYK6ljxb2B/qJuy2+49PCMULmeHfC+Rk+m7Ow7BeorsXpuGl+suWgScdMurJ63jKhYDkwWzfAe2Rc=@googlegroups.com
X-Received: by 2002:a05:6a20:9f4b:b0:240:1e4a:64cc with SMTP id adf61e73a8af0-317647b7ab5mr3577988637.12.1759200316377;
        Mon, 29 Sep 2025 19:45:16 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1759200316; cv=none;
        d=google.com; s=arc-20240605;
        b=RuV3ZPhdypwvJ5BS8A4b42oEOaa7ZUFUHvs7f3vbYqX0bB/RFKtcNH6tWJs0qqRPBW
         IowaOK+Kg1KiGDco6x+4yF/dBIDmGJekl7KrTDTW2J3BQyp7rITHLn1qfnrttnNjrFEl
         KlQjLjyNCwyfXELD3zXlrGL3ujA5xwrANSz69Lr8vA+tDwffh+E0ggR3oLvITsV8jyMj
         hOvQezjJZHtdCbQ1Bi17wB0ALWlAeWNL8BrURAmJfoQevK+K2tmZ/dP5TdxfmiY9CLZC
         gWpyQb5tTVcpmVxR/sq8RKUy/lqdvlhRe6f2cOl2m2fyGsxTd/Hjaph3njVX9R05oObp
         FROQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=E4BKEfc9ax2ksTKKBAwbjubQHvBiDjA54WMJGQTptLg=;
        fh=dUzdD9E83uH3bRp8X+OSHpPIk8r9oe0whT4sSbdvFDE=;
        b=hsuYEx5RixM0+7YPFvFp0/YyBAWDj+UdDzR/Wa2aPVO1ftkbC2qOPaM8MIhMVnTJRJ
         awtfC3xJwC3vpCdfTES4u8/u5sARe8gs8zpP87I7Th3IIBogOWGntdPbCbN01WvZ5WFU
         b0BVT/dq2rCwJxOhjNQ0otAzFH+x7YKsMzFzp8S78wwQlYzsH/Z9XZgWJyn0zsa2XuqI
         673APmeaLwCCQuz4vw51qfH7jMfNcHu7JigXYpjCZxv18ax6dyDE8B4/Gg9oRSVQ13BA
         w/wsZuEiiDB3EwIRjEgJB7EKFfWyBPzUAUZPue957phunHO3I4Y38VuJEuq+JmzOy/g0
         0RYQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=QxLV1mJD;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::433 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pf1-x433.google.com (mail-pf1-x433.google.com. [2607:f8b0:4864:20::433])
        by gmr-mx.google.com with ESMTPS id 41be03b00d2f7-b57c539db71si634848a12.1.2025.09.29.19.45.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 29 Sep 2025 19:45:16 -0700 (PDT)
Received-SPF: pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::433 as permitted sender) client-ip=2607:f8b0:4864:20::433;
Received: by mail-pf1-x433.google.com with SMTP id d2e1a72fcca58-7811a5ec5b6so2800942b3a.1
        for <kasan-dev@googlegroups.com>; Mon, 29 Sep 2025 19:45:16 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUVnvM+F4YN4QztFMTLa0zFEQoHwmWbe8nRMXY+FCxpPO2wZ59r97SDFBc0e60KPnCfm4y/l42RXPU=@googlegroups.com
X-Gm-Gg: ASbGnctGeZR8rQC7esUCKm2P4WYVqh+6FghRzxcTUvV2MNAYYsDerPh2nwAf7EQ+YfQ
	sqZ+DofZsBob/V91ws2vpRbZLBCH5K2pX99+2ZKJp+kNfjBi7B/t4Fd9JqDOo60vi+REhOcsmab
	XGapekblx85v4j3/ae3TJxY7LnFfHqqTyytJiniIBmTBtwoZBAfd4q2k/sEvB7QpXyCmwyJe6L3
	2aYRUye65SP/dgG7wLVJMYfglj4udVmXhf9t3ti1qAqz/cDmfp72jaw1uaa+TECc6dlBpfrzufi
	sDVMXLQSCEmTnlM32ZPhqIuxgMUnXNFQuy6ZjJ/FjkXC/GwoIw7Q+N2Jh+A5PmLJYdIHhM4Z8+6
	qUOrj1x+n+lNJVO6ZwowjaCFrTv/gdlT/W+X4s+ARuB+5yzaAAI6jGsmULq7awH5x2+V2y4PhA6
	1YTYe+sPGXqSE=
X-Received: by 2002:a05:6a21:3296:b0:2b5:9c2:c584 with SMTP id adf61e73a8af0-31772a179dcmr3208370637.26.1759200315810;
        Mon, 29 Sep 2025 19:45:15 -0700 (PDT)
Received: from localhost ([45.142.167.196])
        by smtp.gmail.com with ESMTPSA id 41be03b00d2f7-b57c557418csm12399859a12.30.2025.09.29.19.45.14
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 29 Sep 2025 19:45:15 -0700 (PDT)
From: Jinchao Wang <wangjinchao600@gmail.com>
To: Andrew Morton <akpm@linux-foundation.org>,
	Masami Hiramatsu <mhiramat@kernel.org>,
	Peter Zijlstra <peterz@infradead.org>,
	Mike Rapoport <rppt@kernel.org>,
	Alexander Potapenko <glider@google.com>,
	Randy Dunlap <rdunlap@infradead.org>,
	Marco Elver <elver@google.com>,
	Jonathan Corbet <corbet@lwn.net>,
	Thomas Gleixner <tglx@linutronix.de>,
	Ingo Molnar <mingo@redhat.com>,
	Borislav Petkov <bp@alien8.de>,
	Dave Hansen <dave.hansen@linux.intel.com>,
	x86@kernel.org,
	"H. Peter Anvin" <hpa@zytor.com>,
	Juri Lelli <juri.lelli@redhat.com>,
	Vincent Guittot <vincent.guittot@linaro.org>,
	Dietmar Eggemann <dietmar.eggemann@arm.com>,
	Steven Rostedt <rostedt@goodmis.org>,
	Ben Segall <bsegall@google.com>,
	Mel Gorman <mgorman@suse.de>,
	Valentin Schneider <vschneid@redhat.com>,
	Arnaldo Carvalho de Melo <acme@kernel.org>,
	Namhyung Kim <namhyung@kernel.org>,
	Mark Rutland <mark.rutland@arm.com>,
	Alexander Shishkin <alexander.shishkin@linux.intel.com>,
	Jiri Olsa <jolsa@kernel.org>,
	Ian Rogers <irogers@google.com>,
	Adrian Hunter <adrian.hunter@intel.com>,
	"Liang, Kan" <kan.liang@linux.intel.com>,
	David Hildenbrand <david@redhat.com>,
	Lorenzo Stoakes <lorenzo.stoakes@oracle.com>,
	"Liam R. Howlett" <Liam.Howlett@oracle.com>,
	Vlastimil Babka <vbabka@suse.cz>,
	Suren Baghdasaryan <surenb@google.com>,
	Michal Hocko <mhocko@suse.com>,
	Nathan Chancellor <nathan@kernel.org>,
	Nick Desaulniers <nick.desaulniers+lkml@gmail.com>,
	Bill Wendling <morbo@google.com>,
	Justin Stitt <justinstitt@google.com>,
	Kees Cook <kees@kernel.org>,
	Alice Ryhl <aliceryhl@google.com>,
	Sami Tolvanen <samitolvanen@google.com>,
	Miguel Ojeda <ojeda@kernel.org>,
	Masahiro Yamada <masahiroy@kernel.org>,
	Rong Xu <xur@google.com>,
	Naveen N Rao <naveen@kernel.org>,
	David Kaplan <david.kaplan@amd.com>,
	Andrii Nakryiko <andrii@kernel.org>,
	Jinjie Ruan <ruanjinjie@huawei.com>,
	Nam Cao <namcao@linutronix.de>,
	workflows@vger.kernel.org,
	linux-doc@vger.kernel.org,
	linux-kernel@vger.kernel.org,
	linux-perf-users@vger.kernel.org,
	linux-mm@kvack.org,
	llvm@lists.linux.dev,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	kasan-dev@googlegroups.com,
	"David S. Miller" <davem@davemloft.net>,
	Mathieu Desnoyers <mathieu.desnoyers@efficios.com>,
	linux-trace-kernel@vger.kernel.org
Cc: Jinchao Wang <wangjinchao600@gmail.com>
Subject: [PATCH v6 11/23] sched: add per-task context
Date: Tue, 30 Sep 2025 10:43:32 +0800
Message-ID: <20250930024402.1043776-12-wangjinchao600@gmail.com>
X-Mailer: git-send-email 2.43.0
In-Reply-To: <20250930024402.1043776-1-wangjinchao600@gmail.com>
References: <20250930024402.1043776-1-wangjinchao600@gmail.com>
MIME-Version: 1.0
X-Original-Sender: wangjinchao600@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=QxLV1mJD;       spf=pass
 (google.com: domain of wangjinchao600@gmail.com designates
 2607:f8b0:4864:20::433 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
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

Introduce struct ksw_ctx to enable lockless per-task state
tracking. This is required because KStackWatch operates in NMI context
(via kprobe handler) where traditional locking is unsafe.

Signed-off-by: Jinchao Wang <wangjinchao600@gmail.com>
---
 include/linux/kstackwatch_types.h | 14 ++++++++++++++
 include/linux/sched.h             |  5 +++++
 2 files changed, 19 insertions(+)
 create mode 100644 include/linux/kstackwatch_types.h

diff --git a/include/linux/kstackwatch_types.h b/include/linux/kstackwatch_types.h
new file mode 100644
index 000000000000..2b515c06a918
--- /dev/null
+++ b/include/linux/kstackwatch_types.h
@@ -0,0 +1,14 @@
+/* SPDX-License-Identifier: GPL-2.0 */
+#ifndef _LINUX_KSTACK_WATCH_TYPES_H
+#define _LINUX_KSTACK_WATCH_TYPES_H
+#include <linux/types.h>
+
+struct ksw_watchpoint;
+struct ksw_ctx {
+	struct ksw_watchpoint *wp;
+	ulong sp;
+	u16 depth;
+	u16 generation;
+};
+
+#endif /* _LINUX_KSTACK_WATCH_TYPES_H */
diff --git a/include/linux/sched.h b/include/linux/sched.h
index f8188b833350..6935ee51f855 100644
--- a/include/linux/sched.h
+++ b/include/linux/sched.h
@@ -22,6 +22,7 @@
 #include <linux/sem_types.h>
 #include <linux/shm.h>
 #include <linux/kmsan_types.h>
+#include <linux/kstackwatch_types.h>
 #include <linux/mutex_types.h>
 #include <linux/plist_types.h>
 #include <linux/hrtimer_types.h>
@@ -1481,6 +1482,10 @@ struct task_struct {
 	struct kmsan_ctx		kmsan_ctx;
 #endif
 
+#if IS_ENABLED(CONFIG_KSTACK_WATCH)
+	struct ksw_ctx		ksw_ctx;
+#endif
+
 #if IS_ENABLED(CONFIG_KUNIT)
 	struct kunit			*kunit_test;
 #endif
-- 
2.43.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250930024402.1043776-12-wangjinchao600%40gmail.com.
