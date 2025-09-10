Return-Path: <kasan-dev+bncBD53XBUFWQDBBT43QTDAMGQEI42JM5I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3c.google.com (mail-qv1-xf3c.google.com [IPv6:2607:f8b0:4864:20::f3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 27D30B50D6F
	for <lists+kasan-dev@lfdr.de>; Wed, 10 Sep 2025 07:34:09 +0200 (CEST)
Received: by mail-qv1-xf3c.google.com with SMTP id 6a1803df08f44-718cb6230afsf136934646d6.0
        for <lists+kasan-dev@lfdr.de>; Tue, 09 Sep 2025 22:34:09 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757482448; cv=pass;
        d=google.com; s=arc-20240605;
        b=fmW/o4Aw3Mq00zcQWxGOP85GWEZ/mbSd6l0jbe5xJTr/NO1tnc3dCgwHqtbxyLtJVi
         H1d5mlRZNqTvqlwU9fFu8s/jdmMon3uRPN1Ct6tzS/BPuP6sHQeIwBdXNBzwUHHqff2C
         5xmQlllV4SpeJJTWlteKSqR0NxZcfIwsTG6UFBA+e15InqxWMmSJmONllAu3KWgs6Lu3
         d3E1oEZ9P75ktwVLaxn0D+j4aH8/EePgeQrAn37TaLn+kHJJBJLw/bsFIC7JrglmBx+J
         Iskml1qtP2bCeEtNswPVYx96PQJw4PRTGNoHRbaRB//pM/aB4I8g6DcO/oAY0UrF7foo
         3NRA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=Zgjn1TlbP2AQYu/4cd+ZiJdlAXEW2EzNyu0gfEwImzY=;
        fh=1lASyoKk/BXM9/h8ao349a0TMTVocf3ZtsJ9vshmhJc=;
        b=aWee96/0XULbMnOCISVMdYjGTGwPJEgybk4JiOXGojsQle+PCF8xHJPF2A3Sed7XlV
         ybd3Ad7xjc/VinJiF9v/ztojAD3NEpjaWnrU3tUrD1bQpJXOLAEFFKYCZgitYadxgRM6
         CCxCRVDI/11DOCgtlCCYUGG7BScvpkjgvXdies7i/IVXYzAGHfoMthfP65GjCojcYVZv
         xr1K12Kq6ZvFltgoeNCXGHNAvVaLRQZNgXKNVzV3chV3gAP5aIpwYvmaGKPoG98tcxSG
         F/yVVwaTzZ9/BUMw7oeM2hvzAv+1YCe/JvkqBM31XsDv/vaj2e4/8IQN0T2Ii+cU5r7U
         cqyQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=QPHwPHzP;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::42c as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757482448; x=1758087248; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Zgjn1TlbP2AQYu/4cd+ZiJdlAXEW2EzNyu0gfEwImzY=;
        b=Umvsvc8s3nb7V2u+Z5AfoTK0jDWYOa/uwEpHoIku17D13RosiUOzZFL2cx07Vf8huk
         xYFbIGlSAQAEfnp4z/CWKnrutMx+8E9SLppkZI+swIecKz0ACLdp9VJj8D5Il3KxGbKp
         acz8DF9XKfpB6JWtHRNO+bNPjySNBDlu0B5a6d0D6HedCxSDsc1uqRNcOCeCqpEGX6+k
         5c7AgXoGka0nZCHdDZkb9RXZRx1Db0In5UZw6RcY4WdmHNQzW78//AHLVferkTV8QW4O
         1Txxsp7qrUZtMFikel8fBmxowcmpF10JPCisPsDddJqyhrSi0TJ2y4ccHuOcV4PFIaTC
         xh8g==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1757482448; x=1758087248; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=Zgjn1TlbP2AQYu/4cd+ZiJdlAXEW2EzNyu0gfEwImzY=;
        b=IFNuL1s656bQcBWYoOs+53C8aKVGgfQICUAJI4V28ySkNdvfwdTKvsiFxitOKR1Zfp
         Yrw61R4M/6lRBiAg8uC/700BtsxXqjZ0jnv550tkBoLP5SOojrqVOmMrqjjOPEQ8YQcP
         qLA7wba8ABnPrYI+641U8hYkndyRmyhf3B+3YEv+jSL1L8AMLCb5QslF7F5VnRt/QqZ3
         f3qjvPSpMtD9VBV6HuijG3YM++6/0j2XyKzF3UmdM0bJc2zyxYZgLfa4VGO1bXWIVn2P
         w/dhrqo4yoxxFgL7StFEeNb2xk/DiSztzk8MXTecI/xdlCAjx4eOFkv/WORYwX3ut9Aa
         s0Jw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757482448; x=1758087248;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=Zgjn1TlbP2AQYu/4cd+ZiJdlAXEW2EzNyu0gfEwImzY=;
        b=ZSZnzvAjIlI0ky73KLh9JAvcJZPCsLqqMePNE8S/bc+2Rt0Khnp7RIgYjy1+KAnS6j
         18DJ5hDU7qywtmYmEMMB9HT90iLWrjTZ3Z6ofsTb3OKrJ+onidfzy4T2gkEIWk4+VfiI
         QNSzlqHbgeX3vw6PGL4/FUNPnRDtVVVotoqmr2OpEqn9w0u352D7R0HZ67fPqN7G7Bax
         iTjxOWtAC0hJYym/MT7Rr3Ca8I9BWMeteaFMnD5x3x7SQIAAqToVSBIv2c+GZDS0Zout
         UXbVC1LsnMORnb+t5dUeKEz/fk3zaBnTQkfRTpwnxHqLRKhOBZj0h0YrIGfA/Hqeo2cc
         l4Yw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVKC37gnfcBPjCzIMzSgduotiX32PvnGAXC7EdArhMgpbFMTckEc5BrzV/IYgjNobwzsDBvww==@lfdr.de
X-Gm-Message-State: AOJu0Yxww+FkGVORRLu9VTw6NvRSDEMpbiX6ccVNQuAb4Mf/tveudCMF
	pZ0/VqiYDcBzQtyl/3ab5CD8sQwFi6xE6NE92fwcDlXiPqx1Q5JymJOW
X-Google-Smtp-Source: AGHT+IFoldy+NZbv6oHNWxmd0qrPgqF7Lr6TZsXsqMPfuiBO8jIwbiOPEfqtVDaSsfBFE2Ez0mh71A==
X-Received: by 2002:a05:6214:411:b0:70d:daae:c5ff with SMTP id 6a1803df08f44-7393ca9cae4mr174156756d6.39.1757482447895;
        Tue, 09 Sep 2025 22:34:07 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd6FPJ5XImLQICd/gAfdMq5xhEvzW2anS1Dn83tkNIhUdw==
Received: by 2002:a05:6214:2582:b0:70d:9340:2d97 with SMTP id
 6a1803df08f44-72d393497bels82277876d6.1.-pod-prod-03-us; Tue, 09 Sep 2025
 22:34:06 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUF0sMbDylAdqGgKvvMHvyLiCLvvmOFzbO1JOHsAvbkB/zeZpbNrlt3EnpMgIrr+SVBvYJQocyI52M=@googlegroups.com
X-Received: by 2002:ad4:5cea:0:b0:72a:2cf6:76df with SMTP id 6a1803df08f44-73940035018mr176234326d6.45.1757482446587;
        Tue, 09 Sep 2025 22:34:06 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1757482446; cv=none;
        d=google.com; s=arc-20240605;
        b=e0rB+UzSzifuBVXnxrrQPyhWfp9WvYBxiLUIUFcVwz+Xbuo/+aNncLMvDEnNgaCxSd
         VUZGmA5QHRrtZGg26SzM5WLHAhdCp6gxky2COQHKfxUm9JFvY7LJjhl1wzjDR3xb6YlH
         bMidlMPFpUgcglRFjSkiD2jR3gkAG152R0oj2vooLN6InKE3ZcmV4lQsh37zAcVtdv98
         3LwMFEEUK0BgYqpA8u2mys/AX5gBjxI0Ckk9q3srZ4Hom4GJIst7RwVmBAIK8GfvIrUK
         nVyyKt0/W8YL7nH0uzmcyePIbzxjrVK3w0WY/EcCZf6dEGrsVKAYKolZKv0coM6QRYlU
         89/A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=4LZ6B57mC2fepOM/oiVWF88xfTVcoYhpKk3jWWiDDz0=;
        fh=1DWk0hVAJRcgnt3lvmGpaB81WfDkLP4SmwDvc5jyhQw=;
        b=DLRhZ8t3hWAjkUJLSP4axaDA9fsy0kz6YflXi8qk9jgZ39Arr0rOZcZeV2qIMBuF5W
         MQWlNap9mufrmxmDa2+k22o34o2rFXTIzFwjnRrIBiikctq2ei3GiqIwr2IE8Pzx+SJw
         1IJYtg0cajUEkOVOAwig4U28DV9lNajcu2hTWMyBVZYB8Km3cYDkqS4CCYiH9Aoc4Kmb
         BwIde23nG+4FvNCgcgvykQEPZWzje1IUKGe7twUthSo6SJmZ0CvU8LsHmFWFCu6T/LUb
         nHUH9KevHwYx1Q8AgpBJtQ9jq4EsN2KIJ5qvVqiwLbavj3iwGsEL9fFXxw6sJbZFutXX
         otMw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=QPHwPHzP;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::42c as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pf1-x42c.google.com (mail-pf1-x42c.google.com. [2607:f8b0:4864:20::42c])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-720a2dd4bfbsi3282396d6.0.2025.09.09.22.34.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 09 Sep 2025 22:34:06 -0700 (PDT)
Received-SPF: pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::42c as permitted sender) client-ip=2607:f8b0:4864:20::42c;
Received: by mail-pf1-x42c.google.com with SMTP id d2e1a72fcca58-77238cb3cbbso6747700b3a.0
        for <kasan-dev@googlegroups.com>; Tue, 09 Sep 2025 22:34:06 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCV/R4nXcwlPHWFJgORq/8mAVChMEPiHecrIpHgzHcbqMpA2a59G/RP6jo+4cw1GbNrp8bXvdnZLNu8=@googlegroups.com
X-Gm-Gg: ASbGncs6+smq3SILmeNqFGlLcGXthbfLo2DMJwdAHq+oktmcIRo+egySX44P2X+XHFQ
	KxMiyXF/szvTVCd4mEwJoolAShGgy4mFW8GWu06Xs20UzQswymaCuym5fyj+fvz7i75ZZWIjTbG
	3t9dzRZ4Mh2C6W8lHJDoqrTkSnESeWPiZa+lWSvxByxCq3r8SK+Ak3BAA5c7oT14O1UXb+H+7VL
	N5bQKH6jX+2oAmViZCCs+FH8UCpd7glNnCJHfm2sY741KzPI0UO3cuhAbcjGAr+wtVYdWUw4dN7
	UtLuKE7eFFrrvHvG4hchUn8pdnrtHHaSM2thAsLFvGtPhh8Z4mK3DJzh/PuRZFcbkTYDfrBC5Dh
	nAa6hW8EPrkZPjkpdsBY2HTV2UuZMENC11J7VqOD4nVu6H09E/Apg6UOkX/nr
X-Received: by 2002:a05:6a20:3d8b:b0:251:7f83:11cd with SMTP id adf61e73a8af0-2533e5732famr20377356637.11.1757482445592;
        Tue, 09 Sep 2025 22:34:05 -0700 (PDT)
Received: from localhost.localdomain ([45.8.220.62])
        by smtp.gmail.com with ESMTPSA id d2e1a72fcca58-7746628ffbesm3870342b3a.66.2025.09.09.22.33.54
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 09 Sep 2025 22:34:05 -0700 (PDT)
From: Jinchao Wang <wangjinchao600@gmail.com>
To: Andrew Morton <akpm@linux-foundation.org>,
	Masami Hiramatsu <mhiramat@kernel.org>,
	Peter Zijlstra <peterz@infradead.org>,
	Mike Rapoport <rppt@kernel.org>,
	"Naveen N . Rao" <naveen@kernel.org>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	kasan-dev@googlegroups.com,
	"David S. Miller" <davem@davemloft.net>,
	Steven Rostedt <rostedt@goodmis.org>,
	Mathieu Desnoyers <mathieu.desnoyers@efficios.com>,
	Ingo Molnar <mingo@redhat.com>,
	Arnaldo Carvalho de Melo <acme@kernel.org>,
	Namhyung Kim <namhyung@kernel.org>,
	Mark Rutland <mark.rutland@arm.com>,
	Alexander Shishkin <alexander.shishkin@linux.intel.com>,
	Jiri Olsa <jolsa@kernel.org>,
	Ian Rogers <irogers@google.com>,
	Adrian Hunter <adrian.hunter@intel.com>,
	"Liang, Kan" <kan.liang@linux.intel.com>,
	Thomas Gleixner <tglx@linutronix.de>,
	Borislav Petkov <bp@alien8.de>,
	Dave Hansen <dave.hansen@linux.intel.com>,
	x86@kernel.org,
	"H. Peter Anvin" <hpa@zytor.com>,
	linux-mm@kvack.org,
	linux-trace-kernel@vger.kernel.org,
	linux-perf-users@vger.kernel.org
Cc: linux-kernel@vger.kernel.org,
	Jinchao Wang <wangjinchao600@gmail.com>
Subject: [PATCH v3 19/19] docs: add KStackWatch document
Date: Wed, 10 Sep 2025 13:31:17 +0800
Message-ID: <20250910053147.1152253-11-wangjinchao600@gmail.com>
X-Mailer: git-send-email 2.43.0
In-Reply-To: <20250910053147.1152253-1-wangjinchao600@gmail.com>
References: <20250910052335.1151048-1-wangjinchao600@gmail.com>
 <20250910053147.1152253-1-wangjinchao600@gmail.com>
MIME-Version: 1.0
X-Original-Sender: wangjinchao600@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=QPHwPHzP;       spf=pass
 (google.com: domain of wangjinchao600@gmail.com designates
 2607:f8b0:4864:20::42c as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
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

Add a new documentation file for KStackWatch, explaining its
purpose, motivation, key features, configuration format, module parameters,
implementation notes, limitations, and testing instructions.

Update MAINTAINERS to include Jinchao Wang as the maintainer for associated
files.

Signed-off-by: Jinchao Wang <wangjinchao600@gmail.com>
---
 Documentation/dev-tools/kstackwatch.rst | 94 +++++++++++++++++++++++++
 MAINTAINERS                             |  7 ++
 2 files changed, 101 insertions(+)
 create mode 100644 Documentation/dev-tools/kstackwatch.rst

diff --git a/Documentation/dev-tools/kstackwatch.rst b/Documentation/dev-tools/kstackwatch.rst
new file mode 100644
index 000000000000..f741de08ca56
--- /dev/null
+++ b/Documentation/dev-tools/kstackwatch.rst
@@ -0,0 +1,94 @@
+.. SPDX-License-Identifier: GPL-2.0
+
+====================================
+KStackWatch: Kernel Stack Watch
+====================================
+
+Overview
+========
+KStackWatch is a lightweight debugging tool designed to detect
+kernel stack corruption in real time. It helps developers capture the
+moment corruption occurs, rather than only observing a later crash.
+
+Motivation
+==========
+Stack corruption may originate in one function but manifest much later
+with no direct call trace linking the two. This makes such issues
+extremely difficult to diagnose. KStackWatch addresses this by combining
+hardware breakpoints with kprobe and fprobe instrumentation, monitoring
+stack canaries or local variables at the point of corruption.
+
+Key Features
+============
+- Lightweight overhead:
+   Minimal runtime cost, preserving bug reproducibility.
+- Real-time detection:
+  Detect stack corruption immediately.
+- Flexible configuration:
+  Control via a procfs interface.
+- Depth filtering:
+  Optional recursion depth tracking per task.
+
+Configuration
+=============
+The control file is created at::
+
+  /proc/kstackwatch
+
+To configure, write a string in the following format::
+
+  function+ip_offset[+depth] [local_var_offset:local_var_len]
+    - function         : name of the target function
+    - ip_offset        : instruction pointer offset within the function
+    - depth            : recursion depth to watch, starting from 0
+    - local_var_offset : offset from the stack pointer at function+ip_offset
+    - local_var_len    : length of the local variable(1,2,4,8)
+
+Fields
+------
+- ``function``:
+  Name of the target function to watch.
+- ``ip_offset``:
+  Instruction pointer offset within the function.
+- ``depth`` (optional):
+  Maximum recursion depth for the watch.
+- ``local_var_offset:local_var_len`` (optional):
+  A region of a local variable to monitor, relative to the stack pointer.
+  If not given, KStackWatch monitors the stack canary by default.
+
+Examples
+--------
+1. Watch the canary at the entry of ``canary_test_write``::
+
+     echo 'canary_test_write+0x12' > /proc/kstackwatch
+
+2. Watch a local variable of 8 bytes at offset 0 in
+   ``silent_corruption_victim``::
+
+     echo 'silent_corruption_victim+0x7f 0:8' > /proc/kstackwatch
+
+Module Parameters
+=================
+``panic_on_catch`` (bool)
+  - If true, trigger a kernel panic immediately on detecting stack
+    corruption.
+  - Default is false (log a message only).
+
+Implementation Notes
+====================
+- Hardware breakpoints are preallocated at watch start.
+- Function exit is monitored using ``fprobe``.
+- Per-task depth tracking is used to handle recursion across scheduling.
+- The procfs interface allows dynamic reconfiguration at runtime.
+- Active state is cleared before applying new settings.
+
+Limitations
+===========
+- Only one active watch can be configured at a time (singleton).
+- Local variable offset and size must be known in advance.
+
+Testing
+=======
+KStackWatch includes a companion test module (`kstackwatch_test`) and
+a helper script (`kstackwatch_test.sh`) to exercise different stack
+corruption scenarios:
diff --git a/MAINTAINERS b/MAINTAINERS
index cd7ff55b5d32..076512afddcc 100644
--- a/MAINTAINERS
+++ b/MAINTAINERS
@@ -13355,6 +13355,13 @@ T:	git git://git.kernel.org/pub/scm/linux/kernel/git/shuah/linux-kselftest.git
 F:	Documentation/dev-tools/kselftest*
 F:	tools/testing/selftests/
 
+KERNEL STACK WATCH
+M:	Jinchao Wang <wangjinchao600@gmail.com>
+S:	Maintained
+F:	Documentation/dev-tools/kstackwatch.rst
+F:	mm/kstackwatch/
+F:	tools/kstackwatch/
+
 KERNEL SMB3 SERVER (KSMBD)
 M:	Namjae Jeon <linkinjeon@kernel.org>
 M:	Namjae Jeon <linkinjeon@samba.org>
-- 
2.43.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250910053147.1152253-11-wangjinchao600%40gmail.com.
