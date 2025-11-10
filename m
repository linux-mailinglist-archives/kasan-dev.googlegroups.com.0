Return-Path: <kasan-dev+bncBD53XBUFWQDBB4NJZDEAMGQEXHYCEOI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43d.google.com (mail-pf1-x43d.google.com [IPv6:2607:f8b0:4864:20::43d])
	by mail.lfdr.de (Postfix) with ESMTPS id 8651CC47FF5
	for <lists+kasan-dev@lfdr.de>; Mon, 10 Nov 2025 17:38:11 +0100 (CET)
Received: by mail-pf1-x43d.google.com with SMTP id d2e1a72fcca58-7aa440465a1sf6213176b3a.1
        for <lists+kasan-dev@lfdr.de>; Mon, 10 Nov 2025 08:38:11 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1762792690; cv=pass;
        d=google.com; s=arc-20240605;
        b=QITdfvQqXTt9qBguieVRG7EbnSmyZarU7sZm/PB+01AE08Ae76z2cR7XGmAaCbH8lC
         Urpv2raXrdhtmDFC9oqjYKgbNSsCyQQ3MHqI3XfY5DONYneRrVoVLo6C8xk9jg5f6L8P
         XfcwX81xq+GUUWVv2NN4kJXPAa659srKgP5zO+p0FolyyxUDUn9fAWipzJrp8r+J+bqE
         /kBu++GOaDzqKVH5uKTUl4/T+dWA28MzxXDFMhWjSqvyy4JBAHl9sDzcMiT+r2e2HfR+
         HIO8qXpvX9/9f5yWFT4Pnpad6mmixrKMk9pscaXDBaTO5tfSXiivAdMYG4E0/t4pfhUw
         bXVA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:to:from:sender:dkim-signature
         :dkim-signature;
        bh=gYRz/AFB5dWBu2WyNn+WeGESW+7qUgZLN2urNU5Crus=;
        fh=Ox17bGfxEaKpt+5pB6cftXKYCJVPO7b1D/jpV7j1YLI=;
        b=bWRdoo/HcjOkCYYacmqDtX/VoeUTbp/wX8IUNU1s37Kia/CnBauou/BS6/7j3fmYNJ
         vp4vrA9by4UiHhQANwrmwXeasyfRPW8jVeAzzmeP4vBbh4Jx6+Ut11z6lWI/Pwk60Vgi
         hqongQ5+OD4tnksH1SIrk6EPqWTDatArKUvcLyzvOPXF1ZMy0wgfPtlpZCPj90PlXs76
         iZU4l1HM4BsrFBUBAp9meDwcgjPB6GKl8GMocFcYRbsc8Mqw8Z7DcqjPIZbK0q2UxhyX
         c8vi+QJDO7+y2f/Uu9CXuaHTXNO2PbQ63XSozwuKXA4iS2jKp7xzz2dNuO/OVSp3q/Fi
         AFgA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=MLm1+z6A;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::633 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1762792690; x=1763397490; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=gYRz/AFB5dWBu2WyNn+WeGESW+7qUgZLN2urNU5Crus=;
        b=tCOu7AS3YuhVD3NXe+3gO9mcNlfIhAnClhe/bwl3AV4zfVLz3k2X5zcFk1XTx/vIrg
         AJ4XKER4ixRUkVppH7h7fQUrMFws8lmUEnvijD5VYz7C5IqUAKMnD/MAACEAQ9pcyr0d
         wfG/g+ax3YywMsTsLZhNfwTk/47Gw/LZIFngx3Rmuwf8yjc0TW+rjDNXB7KpxGKx+2fc
         UOyH7WUct7yw5PkravKAI1GKVaeN8+b42hcHz1OagG+Y8JvCrod+pUlSjkJJxQJ6vESY
         HuWFMHAb8Y1JLiOn+bISATpHmeUr5HFDcdL7O/b+FiQ2gcbzpHVWZj8DmORlLkc4eA3s
         /2DQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1762792690; x=1763397490; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=gYRz/AFB5dWBu2WyNn+WeGESW+7qUgZLN2urNU5Crus=;
        b=K7f9TQjrXi8Ye2p47WTw5ejEDWniaW72L6yzQTx7lHTRFFCeEWrGTVe0ytWrPzIdt/
         VKEWIi/EnzUbT/M+0ZmeSr7XA8FqIlE02WvRtwC40/i6HVMop2sjIg1uRmWAp1HiuMW/
         rPFn13rLoS0ia7RO23bKC1frbgd8d+RTfkcUCih+otMlcoAVkYwdaaY7ENy6V7l8InQq
         BIF197Ig/G2aawU4bNBuR5BRwzO5wgrgRXuyBPK/VIg4PtePMmF2Mp7GS87pS1D2Abt4
         r016wgGD/ekPZ9udQr9agWIOISN7cJ/FvVBBkkud9LiS+0Z4MSV1eJWlPwldA7rlstHx
         Tfgg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1762792690; x=1763397490;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:to:from:x-gm-gg
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=gYRz/AFB5dWBu2WyNn+WeGESW+7qUgZLN2urNU5Crus=;
        b=sumlmd9wgOIVdrUfWsXgyCCo+htVZBkEBwBJuSWDbEBFxXY/731oYOVOPDs+GhFnTP
         4FkkEevCQN1E5+qhBazCrzucRBfy4kyVxe566z3RgkQ8x2jNBrK0g/F5lYIpyYuUf0v0
         O7OmXlxA8WN/9EBZWr7whQRzVAPw70cpjAK4T5irG5kNQO8YhqRudBhI494TMnebBEJz
         a/RDFe7XO0fYxv713po7Jwx7NdRm0WesGU9Itz0stVNeHutsMS8S26h1bALVlErtpASn
         k5KkGCabAvmdavqi89QcWe4ELtE3/ecOp2ZPDkCwOE77IDIDvHZH8XyUR+usM0/3c0Kd
         YGiA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCX+u5LgGSymGow6BNvGtCM+WCAMsXUprBkEYVvAmkGQZDlEMQ4Yc58thBWJeeFiYI355st9kA==@lfdr.de
X-Gm-Message-State: AOJu0YzsT/rgdpFfr97IOccKRri7Ykl0PXATTBwGnLQ8AWyjCYXV725S
	KIl1dVeQj+1ZP3bGtCCQ0w8ClIDQi9ChfCyXAboZK2T/DRnpF8NJL5PW
X-Google-Smtp-Source: AGHT+IG35TeuUEJb7CXYU2DWjuJeaGzUPqQNxIue/Je1eQY0TK0i9bRLw9pXUHbBr4kSNZaoi+QguQ==
X-Received: by 2002:a05:6a00:985:b0:781:1a65:f230 with SMTP id d2e1a72fcca58-7b2270843aamr12474890b3a.26.1762792690026;
        Mon, 10 Nov 2025 08:38:10 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+a6N4LuoAL/hcytvAQEdGjhivcRg+afgsfwVrms8qcZAw=="
Received: by 2002:a05:6a00:7701:b0:77f:19a2:eb01 with SMTP id
 d2e1a72fcca58-7af7d3e708bls4523606b3a.2.-pod-prod-08-us; Mon, 10 Nov 2025
 08:38:07 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVY7Sd1MX4qvlkC1ApfEXoagHpMxUz1ybrwBexiEG64irhKNU3N32ieyRJIBvn5suRegR7v0LCNqmA=@googlegroups.com
X-Received: by 2002:a05:6a21:6f06:b0:32b:7220:8536 with SMTP id adf61e73a8af0-353a006cedfmr11284572637.16.1762792686861;
        Mon, 10 Nov 2025 08:38:06 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1762792686; cv=none;
        d=google.com; s=arc-20240605;
        b=iN6mDogxu2fKKTKZ+gN/1UW+U5QwIfrvn60FQOTPhhceYuMXY83qTPN69cYPSQFImI
         ZfYJOwFAqbuS3ECCNSvv3uVzrjspFfgTw9ehWP7MlaN17tNCrUHzEElMQK3CXS3AMTuM
         JthZYkhwZR5gXHjodkvRFoCVyLmNqM7mQk9aalmDP5N1yiC99rBt8V5Iu4qYm4tq7K8W
         HIJ0WmCxyAa9ZpliK9kS4o0gXTqZjQxri4+c0MPAWofJfWnbJ49pPGG7rKVZeL2Ep0Dz
         u/lFk++OFkcAlixwdEdeIN8ifZhJKiCZsqIMg1quK/QfOD1ZaM7ItrUvIo8scF0/U2/1
         Yziw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:to:from:dkim-signature;
        bh=BbxG26SeCS0bD0vh784LPkUdC/dr0BSaPzCrIbaXc1o=;
        fh=xX/RhclmF7vQ5/gaSBoSoH0WgX6V9hHrleX239cWqNA=;
        b=KQbP3iEC/1oTOeOVvX99ixQSx0FDZu05ax68lTB5J7Pw/yHUURA3+LBhbFvxJEP7zL
         xENNUAmkauMy+9+lFtqtMKhWiNz/iT+uXngdIPOMfxuRJb8lQ/w7xBRlxa7eHN9lDIvn
         AlxZG9/+uStkN2gJaZly68GyaOju0LKbTS19iLAAUl6PtimqlNRXDflmKYCvyAyiqwGQ
         a6bxvfchaj/A4MmfAvDpHpAfpeqZXg0sSvXyZnwGfidQYvumljD8yUcE5J8PqTx93Sw3
         +wmkFMgwBxcHIpkH4XqwH9FY5BrpFCymC+ueV7pZIBt6tT/so/15sBhoy42gQg5h+9vZ
         9mZA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=MLm1+z6A;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::633 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pl1-x633.google.com (mail-pl1-x633.google.com. [2607:f8b0:4864:20::633])
        by gmr-mx.google.com with ESMTPS id 41be03b00d2f7-ba8f8991a84si378312a12.1.2025.11.10.08.38.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 10 Nov 2025 08:38:06 -0800 (PST)
Received-SPF: pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::633 as permitted sender) client-ip=2607:f8b0:4864:20::633;
Received: by mail-pl1-x633.google.com with SMTP id d9443c01a7336-295247a814bso41664695ad.0
        for <kasan-dev@googlegroups.com>; Mon, 10 Nov 2025 08:38:06 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCUcDgyY+XsiQrKklZm1Qk2S4EpVS0O1RWq7nrmWZNShJmhp8259svlsvaREYLOeN5P+PcEc6njtEbg=@googlegroups.com
X-Gm-Gg: ASbGnculfwUqhFWTrgYR9lZHaIA2Mz1JyeugphoT6ax7/nOxR/LWW1ZgPdyzgP5oHsX
	fZXz+STyHVXTmS+RVYV5D9IOQHS3TVIz+T5sVQC6unRiQ/vrPVOG/4CdvfXjieRh+G9t68nRNvw
	9X596RoC+eX7yUyp9LQnDBnPduqxYW+c4ShrP/CTlfvk3xtteEZLlZpfUJmbKWu+N+eHI5CfYhs
	U4qMl8FXgzMJB915KEc6yXDBZD6OizZ5RG2KgJ5S1COW3j9EmBB17WRHgC+dutP4eEt6p05jjlK
	yYn2tn6AUhdVV8YByndaHthkcetOtmJS4PTqgd0GVXKeFSOD/B5H55cu0IHeytJk8GzXS3Syoh1
	epTvQbDmSZlr1oeyrRDqZg+0DOSOGczkIoSospJnoqxhV8T7gHRif76y/yIOHjT5pOov06SctdA
	w4Rvx63LGqNKc=
X-Received: by 2002:a17:902:ce10:b0:295:596f:8507 with SMTP id d9443c01a7336-297e4bfd91dmr122302855ad.0.1762792686313;
        Mon, 10 Nov 2025 08:38:06 -0800 (PST)
Received: from localhost ([103.88.46.62])
        by smtp.gmail.com with ESMTPSA id d9443c01a7336-29651c7445dsm150531925ad.62.2025.11.10.08.38.05
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 10 Nov 2025 08:38:05 -0800 (PST)
From: Jinchao Wang <wangjinchao600@gmail.com>
To: Andrew Morton <akpm@linux-foundation.org>,
	"Masami Hiramatsu (Google)" <mhiramat@kernel.org>,
	Peter Zijlstra <peterz@infradead.org>,
	Randy Dunlap <rdunlap@infradead.org>,
	Marco Elver <elver@google.com>,
	Mike Rapoport <rppt@kernel.org>,
	Alexander Potapenko <glider@google.com>,
	Adrian Hunter <adrian.hunter@intel.com>,
	Alexander Shishkin <alexander.shishkin@linux.intel.com>,
	Alice Ryhl <aliceryhl@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Andrii Nakryiko <andrii@kernel.org>,
	Ard Biesheuvel <ardb@kernel.org>,
	Arnaldo Carvalho de Melo <acme@kernel.org>,
	Ben Segall <bsegall@google.com>,
	Bill Wendling <morbo@google.com>,
	Borislav Petkov <bp@alien8.de>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Dave Hansen <dave.hansen@linux.intel.com>,
	David Hildenbrand <david@redhat.com>,
	David Kaplan <david.kaplan@amd.com>,
	"David S. Miller" <davem@davemloft.net>,
	Dietmar Eggemann <dietmar.eggemann@arm.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	"H. Peter Anvin" <hpa@zytor.com>,
	Ian Rogers <irogers@google.com>,
	Ingo Molnar <mingo@redhat.com>,
	James Clark <james.clark@linaro.org>,
	Jinchao Wang <wangjinchao600@gmail.com>,
	Jinjie Ruan <ruanjinjie@huawei.com>,
	Jiri Olsa <jolsa@kernel.org>,
	Jonathan Corbet <corbet@lwn.net>,
	Juri Lelli <juri.lelli@redhat.com>,
	Justin Stitt <justinstitt@google.com>,
	kasan-dev@googlegroups.com,
	Kees Cook <kees@kernel.org>,
	"Liam R. Howlett" <Liam.Howlett@oracle.com>,
	"Liang Kan" <kan.liang@linux.intel.com>,
	Linus Walleij <linus.walleij@linaro.org>,
	linux-arm-kernel@lists.infradead.org,
	linux-doc@vger.kernel.org,
	linux-kernel@vger.kernel.org,
	linux-mm@kvack.org,
	linux-perf-users@vger.kernel.org,
	linux-trace-kernel@vger.kernel.org,
	llvm@lists.linux.dev,
	Lorenzo Stoakes <lorenzo.stoakes@oracle.com>,
	Mark Rutland <mark.rutland@arm.com>,
	Masahiro Yamada <masahiroy@kernel.org>,
	Mathieu Desnoyers <mathieu.desnoyers@efficios.com>,
	Mel Gorman <mgorman@suse.de>,
	Michal Hocko <mhocko@suse.com>,
	Miguel Ojeda <ojeda@kernel.org>,
	Nam Cao <namcao@linutronix.de>,
	Namhyung Kim <namhyung@kernel.org>,
	Nathan Chancellor <nathan@kernel.org>,
	Naveen N Rao <naveen@kernel.org>,
	Nick Desaulniers <nick.desaulniers+lkml@gmail.com>,
	Rong Xu <xur@google.com>,
	Sami Tolvanen <samitolvanen@google.com>,
	Steven Rostedt <rostedt@goodmis.org>,
	Suren Baghdasaryan <surenb@google.com>,
	Thomas Gleixner <tglx@linutronix.de>,
	=?UTF-8?q?Thomas=20Wei=C3=9Fschuh?= <thomas.weissschuh@linutronix.de>,
	Valentin Schneider <vschneid@redhat.com>,
	Vincent Guittot <vincent.guittot@linaro.org>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Vlastimil Babka <vbabka@suse.cz>,
	Will Deacon <will@kernel.org>,
	workflows@vger.kernel.org,
	x86@kernel.org
Subject: [PATCH v8 19/27] arm64/hwbp/ksw: integrate KStackWatch handler support
Date: Tue, 11 Nov 2025 00:36:14 +0800
Message-ID: <20251110163634.3686676-20-wangjinchao600@gmail.com>
X-Mailer: git-send-email 2.43.0
In-Reply-To: <20251110163634.3686676-1-wangjinchao600@gmail.com>
References: <20251110163634.3686676-1-wangjinchao600@gmail.com>
MIME-Version: 1.0
X-Original-Sender: wangjinchao600@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=MLm1+z6A;       spf=pass
 (google.com: domain of wangjinchao600@gmail.com designates
 2607:f8b0:4864:20::633 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
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

Add support for identifying KStackWatch watchpoints in the ARM64
hardware breakpoint handler. When a watchpoint belongs to KStackWatch,
the handler bypasses single-step re-arming to allow proper recovery.

Introduce is_ksw_watch_handler() to detect KStackWatch-managed
breakpoints and use it in watchpoint_report() under
CONFIG_KSTACKWATCH.

Signed-off-by: Jinchao Wang <wangjinchao600@gmail.com>
---
 arch/arm64/kernel/hw_breakpoint.c | 7 +++++++
 include/linux/kstackwatch.h       | 2 ++
 mm/kstackwatch/watch.c            | 8 ++++++++
 3 files changed, 17 insertions(+)

diff --git a/arch/arm64/kernel/hw_breakpoint.c b/arch/arm64/kernel/hw_breakpoint.c
index bd7d23d7893d..7abcd988c5c2 100644
--- a/arch/arm64/kernel/hw_breakpoint.c
+++ b/arch/arm64/kernel/hw_breakpoint.c
@@ -14,6 +14,9 @@
 #include <linux/errno.h>
 #include <linux/hw_breakpoint.h>
 #include <linux/kprobes.h>
+#ifdef CONFIG_KSTACKWATCH
+#include <linux/kstackwatch.h>
+#endif
 #include <linux/perf_event.h>
 #include <linux/ptrace.h>
 #include <linux/smp.h>
@@ -738,6 +741,10 @@ static int watchpoint_report(struct perf_event *wp, unsigned long addr,
 			     struct pt_regs *regs)
 {
 	int step = is_default_overflow_handler(wp);
+#ifdef CONFIG_KSTACKWATCH
+	if (is_ksw_watch_handler(wp))
+		step = 1;
+#endif
 	struct arch_hw_breakpoint *info = counter_arch_bp(wp);
 
 	info->trigger = addr;
diff --git a/include/linux/kstackwatch.h b/include/linux/kstackwatch.h
index afedd9823de9..ce3882acc5dc 100644
--- a/include/linux/kstackwatch.h
+++ b/include/linux/kstackwatch.h
@@ -53,6 +53,8 @@ struct ksw_watchpoint {
 	struct llist_node node; // for atomic watch_on and off
 	struct list_head list; // for cpu online and offline
 };
+
+bool is_ksw_watch_handler(struct perf_event *event);
 int ksw_watch_init(void);
 void ksw_watch_exit(void);
 int ksw_watch_get(struct ksw_watchpoint **out_wp);
diff --git a/mm/kstackwatch/watch.c b/mm/kstackwatch/watch.c
index 99184f63d7e3..c2aa912bf4c4 100644
--- a/mm/kstackwatch/watch.c
+++ b/mm/kstackwatch/watch.c
@@ -64,6 +64,14 @@ static void ksw_watch_handler(struct perf_event *bp,
 		panic("Stack corruption detected");
 }
 
+bool is_ksw_watch_handler(struct perf_event *event)
+{
+	perf_overflow_handler_t overflow_handler = event->overflow_handler;
+
+	if (unlikely(overflow_handler == ksw_watch_handler))
+		return true;
+	return false;
+}
 static void ksw_watch_on_local_cpu(void *info)
 {
 	struct ksw_watchpoint *wp = info;
-- 
2.43.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251110163634.3686676-20-wangjinchao600%40gmail.com.
