Return-Path: <kasan-dev+bncBD53XBUFWQDBBWFKT3DQMGQE4R4K5KI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf38.google.com (mail-qv1-xf38.google.com [IPv6:2607:f8b0:4864:20::f38])
	by mail.lfdr.de (Postfix) with ESMTPS id AB67BBC8A3B
	for <lists+kasan-dev@lfdr.de>; Thu, 09 Oct 2025 12:58:43 +0200 (CEST)
Received: by mail-qv1-xf38.google.com with SMTP id 6a1803df08f44-87bbee3b92csf731636d6.1
        for <lists+kasan-dev@lfdr.de>; Thu, 09 Oct 2025 03:58:43 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1760007512; cv=pass;
        d=google.com; s=arc-20240605;
        b=MtoA/s9gF+LfNZMOk/wyFLPyVphgTylOoylg/VuDdTDAqwmzmesGeZ5hRbWhaDf2XH
         L6niWlfRSWjCgtKRMItl4xPo0saBQnA/s6H4M8dtJ/6qfnzaZqE+pqWNVxuePmnxtuLF
         z1jYNuwKBi9ELjH/pfPoxmh6c/19ZDMqsOgpFqNXk76hK+v9WaAnKVT3+hVU8RT2WKvW
         CIEZt9iyKZABTbbNLoxnd4bHn5IpjH2lODhwq+dfkwP5H76zCr+oJCsmyG35Ms3PI2Bs
         BVYgFsrOJIfe75VtaLTZWuIFOeXlcMDHdhj5c5Mhvo644FdTAuhxDtWO4kdXd2YdDe5O
         ZXsg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=PSmQxMPEFjY0aHEetBa1iY+Lyo08595DRs9l3IsA+us=;
        fh=lSK/9qZdgvpBcWU2U8GWbRqsOigdG4KPInGBauIsEUE=;
        b=AmgKB/aMcedvvxc7U6JKCN1S0bUgXti5Wu3grFEdIU14gPNKjS/sROj9B3aIJKZUcX
         OozTxuunWc1VnyYIZnrL05SbfptS/PWermeuu4enPBSiwgq7NVTWtMImShreLwO5PQ91
         8nNn4i2CWkPTUct14SdtnsuLqd08HhIJB9uRCvv94RkowRg9F/xCQXP1DLC9bz+qsH+X
         ABR5S54ObkeWo4XEp9f2Nlp5WuhGfvrkHK0XEEX78suzh3+nX5aGVNQyVNYsJZZjPLwU
         +LcJ4yroOS65pEeIXu7U6gIeDhpbHYHFNh8UXuk2fnL6qT4gJZkcGLt3nn+FvhAU7Qrw
         hOyw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=LZyI4sNW;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::1034 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1760007512; x=1760612312; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=PSmQxMPEFjY0aHEetBa1iY+Lyo08595DRs9l3IsA+us=;
        b=sBAvmuJ9IsHPtSMWU2LYRA+ZWFZqFyDV77dm1RUvLKMDkz2kw56ioxfL8JMSCboXBM
         qWZcE2EGL6uPi/ip/vGEv0WmJtZo59uoEz1fPEuNxvrT1Zeocb8LmLq84MQh7iMdrZgt
         SXvIn90R8RWDbZoKoON6/69X+74aVQ3h82PWrKI3Zw0gOnX0wOnJZA1yTC3cptEzEqQk
         kJtRscg20rlNUOeRiql5O47q9FebSJW8vd2r+N+y43ncqY54Mff3pN4aNBBr4X2XgGkv
         hO+2bw0/wCxQGLAeCcA6FeybrFwQfWG9dOiqkliYoKhqc/dfh/iMrJbsscnwwROr9bvK
         wipQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1760007512; x=1760612312; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=PSmQxMPEFjY0aHEetBa1iY+Lyo08595DRs9l3IsA+us=;
        b=VGtrr+L0LJV/GdEznWtWhcZtdCz7l9dGR8LYbOrFAWcRUuqg/3MglqhP+pAG42satB
         p8vfNTT7+v7ZzPwwcvzIwQ/F/h1PpAP9WbrgyNi/ZvV33yuibuo8LyHG1WFAXjmf6D2n
         PdvfD6MmpIFAput3NryJHahTRK9UMM+GAQwoiL1GwrZVfl3bCD1ijvhKN1fCiKFPKake
         037OUy7Us7Zr20Lst4DCzuzOi8iixvMK1KgNGFB2pj3oOLQUbE0sbCfeqfyQ6fJFOPw3
         tAU3M9C7vtjRB8d8MKqk1ap8J4ifFCtiwHPZd8PtbmG6ANs4rvrqWoEKGWqXcXJsPCrV
         pOFg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1760007512; x=1760612312;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=PSmQxMPEFjY0aHEetBa1iY+Lyo08595DRs9l3IsA+us=;
        b=uoVgcU+mIw63Kjholl52+5sUpx29FUzLE8xrU2vt1axNVgqCx2Ke8QxJNgzDLs5UG0
         7dBgLH39BDfv4/LxOySs0mkfvlU70rayKsvsXxn2s+4RZHIeIr0+dS1C9i8tznVeX1WZ
         VQvYm9Z4VDI/wOKZHjGtE9riFKlk+6pp9JTXkHjD4ouq1/ea37gRzoXyAklFjz7HN926
         wHi5JBLlnH9AqfyKWTrOYQ5dZe8Ai4GwQoMSkCR1wzb1x05igMi1pv071yAoOINikFDS
         BhTn0twCHkTBFXXPMsPpncQWhYxEYmYsD1bXAsppCxJz17ZboxObExWM/F6Q3phoIkmz
         iPIA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCV+YHBKVQg0v1d4OfalbvD6bOPOJDHJdBdTMtO7GHoh7ptHF0ClAPdd/+t1JFAC4aZZpnRPMg==@lfdr.de
X-Gm-Message-State: AOJu0Ywy1pF4WH4G1bBn4E7ZSmuyYmDWs49EpwMBWMmVjJsFFbzgY0NK
	MbnJ3SLhsi2HiCZstSdnr1Swg/IuF9NVzHz48+ZNSGxfpaChCNmE5MiG
X-Google-Smtp-Source: AGHT+IGEkUXgT7d7bD41Rzfw3iVDWuMsj2ZoQyE8mKQe097rJCdttCa8fzdceKemPj9xiRR/8UWq+g==
X-Received: by 2002:a05:6214:d61:b0:795:c55c:87de with SMTP id 6a1803df08f44-87b2ef7fa91mr57395046d6.5.1760007512436;
        Thu, 09 Oct 2025 03:58:32 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="ARHlJd5GX3wtzWBBMP5ScCAuNexaTsPkRLFJ3z6f4FdokXSDKA=="
Received: by 2002:ad4:4f2c:0:b0:70d:bc98:89ea with SMTP id 6a1803df08f44-87bb5033611ls14348446d6.2.-pod-prod-09-us;
 Thu, 09 Oct 2025 03:58:31 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXsgbJLnevUDkEFzP0CW7AHpAjMvE9R8XtwPWg49izvZ/b6fSL6oGbCUKJ6AIfUjoUAdjAJyuzdBCA=@googlegroups.com
X-Received: by 2002:a05:6122:c83:b0:520:64ea:c479 with SMTP id 71dfb90a1353d-554b8b941a6mr2910892e0c.10.1760007511749;
        Thu, 09 Oct 2025 03:58:31 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1760007511; cv=none;
        d=google.com; s=arc-20240605;
        b=IaFbUezC8Dq64pfEbBRXzcjMxzvvdaSxsGLJbF5dmTlCIM1wFDV/TgmSyQeQP5escs
         FJ0FLNaEZV62wlUwib6DKlv2bF9rgx6kLKxM4djM5Q7gcNZ85IxVklrASLz+4OUsv4os
         z3tAWhXQJyHv5HzceoXPVnSXEUjBbhBc7eIzUNq3vAbwkLjQGV/aK5ClhSH/Jb9Z7Vhu
         PkWUdDZAnFwhrXUox5nMs+gAbwdziUUGqZaHnXGTUTg+VsWxqV9E9g5OVYIuJiia9nUk
         SArVqJRF1/eh1XYUpCnjYhCkvNJyoS5ohx+cQ5muKBujepY/S630q8tHQ1CfBhE8NLH8
         XdHQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=PODRMG2Z8bUUhx/yC1VRhywhZMIHoJSOmQZCJHqYhJ8=;
        fh=DCZ/oXxwW3qAmN0zkYeL9bfL4eT37Wz9UQYKzgJkevw=;
        b=KTkWYsrcnelZX8Jo7pcG2sNmNYBY67O8bHS7U7euc/MfGx8xrwfTs8gvi8EKu8S+9V
         CL9G+CocBQ32t1TnzLrNpE2820vMoG3VJF3/RSu77/xkeHbYfRhFz2tWzmbx6EBcZifd
         AI0UKgQ21TxlPdpswib55qSt+t5Yare1xq6rD9A5dL5QIYFFOGDkxSGbaDKrAo+lBWoj
         plywkXcdHi+iAKpTHBGu2oM7SrBDHB5/zoUhMpjsBTzYjZW0eu/wFvpe3SI3P1SE6jmI
         mxw4Sa9YY8lnvurJaOUUVGzNprSPBBIhILdU5fyoucmugia4rXQBR0JuMg2jq5zhtVNi
         TPuw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=LZyI4sNW;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::1034 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pj1-x1034.google.com (mail-pj1-x1034.google.com. [2607:f8b0:4864:20::1034])
        by gmr-mx.google.com with ESMTPS id 71dfb90a1353d-5523cf3bbc4si93799e0c.3.2025.10.09.03.58.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 09 Oct 2025 03:58:31 -0700 (PDT)
Received-SPF: pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::1034 as permitted sender) client-ip=2607:f8b0:4864:20::1034;
Received: by mail-pj1-x1034.google.com with SMTP id 98e67ed59e1d1-339d53f4960so903065a91.3
        for <kasan-dev@googlegroups.com>; Thu, 09 Oct 2025 03:58:31 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCX1Os7IMYVk72alqpcMiZVwm3hBXxQTuamIh0t1OLOZJ3oxDVys9C7kLxW7vHiudGq7NnwJwuM6YA4=@googlegroups.com
X-Gm-Gg: ASbGncvo9zQfMtGC+A1MQHYbmWhJT6XFfsV/ygE54HQvHeEZP6JxBZA5pl082ski42P
	MbASwtNhCFSkE/TsDLGdBQTVivFhUkXeBJSf/CAiTIgnPiS84l++jXMhILphNusYK/KqM+0aeDZ
	qK+5jSrqGALooVF2UcCSNp4XsfozdN9diVv4p43MXk9tVEipJdU15aHNW44COPyGDLgFw7rTBVn
	00SluIodBM28mO1NrqlEQVwaIvZtI7GTvYlF4sIfxYuceZGRmrruWcaL0T8pSf2Gom8ji6bWVe5
	ezV0XYE6k8wqwqgv+lsbP3BVj50ZiF63/2OpsCVUAIyj8eRTOHL+doRJf3JfZ8SnBHr+4QYicfw
	wipE/L5f+t76oJmc246wA1mi3yoEZ9fKeo2bDuuqwsuazyq3KFu2rbzn0WVI9
X-Received: by 2002:a17:90b:38cc:b0:329:e2b1:def3 with SMTP id 98e67ed59e1d1-33b51168d95mr9160007a91.10.1760007510612;
        Thu, 09 Oct 2025 03:58:30 -0700 (PDT)
Received: from localhost ([45.142.165.62])
        by smtp.gmail.com with ESMTPSA id 98e67ed59e1d1-33b510e91d4sm6644930a91.1.2025.10.09.03.58.29
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 09 Oct 2025 03:58:30 -0700 (PDT)
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
Subject: [PATCH v7 21/23] tools/ksw: add test script
Date: Thu,  9 Oct 2025 18:55:57 +0800
Message-ID: <20251009105650.168917-22-wangjinchao600@gmail.com>
X-Mailer: git-send-email 2.43.0
In-Reply-To: <20251009105650.168917-1-wangjinchao600@gmail.com>
References: <20251009105650.168917-1-wangjinchao600@gmail.com>
MIME-Version: 1.0
X-Original-Sender: wangjinchao600@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=LZyI4sNW;       spf=pass
 (google.com: domain of wangjinchao600@gmail.com designates
 2607:f8b0:4864:20::1034 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
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

Provide a shell script to trigger test cases.

Signed-off-by: Jinchao Wang <wangjinchao600@gmail.com>
---
 tools/kstackwatch/kstackwatch_test.sh | 52 +++++++++++++++++++++++++++
 1 file changed, 52 insertions(+)
 create mode 100755 tools/kstackwatch/kstackwatch_test.sh

diff --git a/tools/kstackwatch/kstackwatch_test.sh b/tools/kstackwatch/kstackwatch_test.sh
new file mode 100755
index 000000000000..35cad036ecee
--- /dev/null
+++ b/tools/kstackwatch/kstackwatch_test.sh
@@ -0,0 +1,52 @@
+#!/bin/bash
+# SPDX-License-Identifier: GPL-2.0
+
+echo "IMPORTANT: Before running, make sure you have updated the config values!"
+
+usage() {
+	echo "Usage: $0 [0-5]"
+	echo "  0  - test watch fire"
+	echo "  1  - test canary overflow"
+	echo "  2  - test recursive depth"
+	echo "  3  - test silent corruption"
+	echo "  4  - test multi-threaded silent corruption"
+	echo "  5  - test multi-threaded overflow"
+}
+
+run_test() {
+	local test_num=$1
+	case "$test_num" in
+	0) echo fn=test_watch_fire fo=0x29 wl=8 >/sys/kernel/debug/kstackwatch/config
+	   echo test0 > /sys/kernel/debug/kstackwatch/test
+	   ;;
+	1) echo fn=test_canary_overflow fo=0x14 >/sys/kernel/debug/kstackwatch/config
+	   echo test1 >/sys/kernel/debug/kstackwatch/test
+	   ;;
+	2) echo fn=test_recursive_depth fo=0x2f dp=3 wl=8 so=0 >/sys/kernel/debug/kstackwatch/config
+	   echo test2 >/sys/kernel/debug/kstackwatch/test
+	   ;;
+	3) echo fn=test_mthread_victim fo=0x4c so=64 wl=8 >/sys/kernel/debug/kstackwatch/config
+	   echo test3 >/sys/kernel/debug/kstackwatch/test
+	   ;;
+	4) echo fn=test_mthread_victim fo=0x4c so=64 wl=8 >/sys/kernel/debug/kstackwatch/config
+	   echo test4 >/sys/kernel/debug/kstackwatch/test
+	   ;;
+	5) echo fn=test_mthread_buggy fo=0x16 so=0x100 wl=8 >/sys/kernel/debug/kstackwatch/config
+	   echo test5 >/sys/kernel/debug/kstackwatch/test
+	   ;;
+	*) usage
+	   exit 1 ;;
+	esac
+	# Reset watch after test
+	echo >/sys/kernel/debug/kstackwatch/config
+}
+
+# Check root and module
+[ "$EUID" -ne 0 ] && echo "Run as root" && exit 1
+for f in /sys/kernel/debug/kstackwatch/config /sys/kernel/debug/kstackwatch/test; do
+	[ ! -f "$f" ] && echo "$f not found" && exit 1
+done
+
+# Run
+[ -z "$1" ] && { usage; exit 0; }
+run_test "$1"
-- 
2.43.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251009105650.168917-22-wangjinchao600%40gmail.com.
