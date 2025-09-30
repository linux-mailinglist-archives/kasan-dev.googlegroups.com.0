Return-Path: <kasan-dev+bncBD53XBUFWQDBBEMI5XDAMGQEPQGPQHY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83e.google.com (mail-qt1-x83e.google.com [IPv6:2607:f8b0:4864:20::83e])
	by mail.lfdr.de (Postfix) with ESMTPS id 434BDBAB09F
	for <lists+kasan-dev@lfdr.de>; Tue, 30 Sep 2025 04:44:35 +0200 (CEST)
Received: by mail-qt1-x83e.google.com with SMTP id d75a77b69052e-4dc37a99897sf9982151cf.3
        for <lists+kasan-dev@lfdr.de>; Mon, 29 Sep 2025 19:44:35 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1759200274; cv=pass;
        d=google.com; s=arc-20240605;
        b=a706Qp9FfVCr2KixdDeCt5RPpqDCEX9x3GGGfv9QaH9WPyMt9OM/FjvrhBv5KpD6QE
         2XnidTDYbDML4PU9UMRL5dTgKej5WQLqd/pCrwKQy/fK698SSx2Dd7ZQBwE8iM48SMYe
         /3MKG7Ie+uOevouvuuy3SSgrV3ZJLaSpQEr4Oq94JVBbZFb2hF/B+98ZxTt/iu11Ogtx
         QLa813hwIwZZs7C/lIJ14tcp5wb23QNe0LE0aY7UgFUKT50/1S6gx2yJiMqpENG5i39w
         v0yRF1RIKshia7gji4Wik4zqho3OahiGOWOMRO1NGizBpHqUrHaFQj+eXIFBbPmebwE0
         QjGA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=mBRwNuM2KSx6wfPbSAR5meXoovZXq6+GLAXgQLs37ws=;
        fh=CWErIzcSiSv7WlYRJ7t2SGry+YfX5n2bb2ccpOzFsGE=;
        b=Nm/pvz6/JbNYlXegKNFy0V7/3OhZ/RPiJ/1zZxbwyWL0rp9jddJzVmsUe0zGYFk1/e
         6xlVj1O6GWsdlkXhUWO3uvPAHUSlk278pAbjIdbyhD0n4Cl4paoKHzbKN4rgNKE3C/Y7
         J2ouLjUCKIkffHP55Pxy+Gu4HuyavQd8E+6gnvf8JSGt+kmVob8H+KgwgcpzdWCZBZpQ
         g6daskhcPjWQXUAgUyKN+0DQovGmiwMtHa0FXbU8QXCj25LK3ksOe2PZiICzAHk5K7HS
         k33ZlQBSLhRopc10aqFcGApwQNQbaFbjNkeIcOiCWUEWheEcNmGtFxWxTmwwHEjWdDrU
         OiUQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=SwkZDhg5;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::535 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1759200274; x=1759805074; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=mBRwNuM2KSx6wfPbSAR5meXoovZXq6+GLAXgQLs37ws=;
        b=owoG7s/cai8ME15s8Ddzl7pbfRvJ1s1vH+hNttiNvJbSijKnPtSsxkKwfW2q1LC7A3
         EiJHAnz4Lg4eHq6J5q4laFodEgNMrLA/evuVWFvrfc6raXyiG1yQLUYI/ZZczwbrUDHK
         N6tfWrpTalkwf1Akzau8D6hG+TeNxOEJVsghn+1w/cKiHsF4VJnhIIOPi9ouNfMJQGD0
         pp2TNE5z8gAPTiqXdTXaEqOCf3xVhH0uKItHkafdIa3PQLtygZxBAIKKMmKYIbeDt7bZ
         A9XrsKCvqwhN2tE1VhSbTxQA6KirzfxhAFA8jch7Ywjuh4nByrVWrJiUYapefb8BqyvA
         WoFA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1759200274; x=1759805074; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=mBRwNuM2KSx6wfPbSAR5meXoovZXq6+GLAXgQLs37ws=;
        b=APOT9uucq9NuL7pesNk0LK3MUwS+UEhV32JKeLWnpnyOxFqdhRi1GcRYnZ+rZgm7Ve
         GrLnz4IbWrARvatxgNIzqH6jHhX0y2brtTYiAXxc4danwJAjA27kKc6DnZt1KSqDtEE9
         P4ERd0Fye4Zvp1K4tv4NBa9mvp2IClYkj2vVc8ll8qbrhePnlh1Gb4j7RukB+nvJjavX
         X4OztkgVaF8Mq5Azu3gyF08IHoBaSOg2Ks6aboibZTV6SZysNMorYN3XMlEq6gKNr0os
         DQdFQGPCrnLSRft89Y4Oyu6os3/gw0fJsVuw1I7yaJeiXqFbNVqAxU2AFr83OEzLvgh6
         7r9A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1759200274; x=1759805074;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=mBRwNuM2KSx6wfPbSAR5meXoovZXq6+GLAXgQLs37ws=;
        b=O6FEm1asnBgUCLQU0d5wT1iyzMeIAGOtMXSGV9q1QqcLAvpTstXyh3RTGTXpsnE9J9
         w1yhjXj9d10uFLYoSd+EKnm49FzFrnU6ebPjk6qNHhvn4+ZrHtJnvBA6qw0N1VVyY0e6
         +61JtxJcHkMa0LPdRf5NlRNAMvqs6UJNtjhTY3pTio+1ZibJkAkCDEGyoQCQwaMU1t1+
         SDpf+SgXU90/X9V6ovCvCEdDAkxCB4JgCOotDYbURr9GN8oyyfYISV9ZtdtT1qzWbwkZ
         w+3b/xFl0lJXn9rQWiJ1RFkpc9hBGZxMkvcUbkBHlZJrIb43k80L67hC4Zn+T3NTDyqY
         /EZw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCV8m4l7JoH4oHx1500kWwSvwCwFMEkkNT5zNaRbMGHDudPtRGyk0NTq63cVuXzL+hEMDnyGgA==@lfdr.de
X-Gm-Message-State: AOJu0YzIOJdqJAI++mGirVF/5Il5bPhxOtb44EEcOpUyRUSKT+9ORJP6
	4FWLjIxHkezruX1nv7Q3dh+sL7Ht4qGKzJG6H29CBJDzK9467TrLSP2R
X-Google-Smtp-Source: AGHT+IEcYFE95KqHYYg0+Klp2vZCaHZwRnZpvraR+/MeXShUgSKQbfdD1TV1V1w/vnr8Jra8UCDuGw==
X-Received: by 2002:ac8:7545:0:b0:4da:7af7:ca1e with SMTP id d75a77b69052e-4da7b1654d5mr135129171cf.13.1759200273766;
        Mon, 29 Sep 2025 19:44:33 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="ARHlJd45bYHElVvxAKqxcaRUNhIVI58r3SDErFd+SFs1VBwt/w=="
Received: by 2002:ac8:7d8e:0:b0:4b5:dc6e:c1df with SMTP id d75a77b69052e-4da7ef464e8ls135093731cf.2.-pod-prod-07-us;
 Mon, 29 Sep 2025 19:44:32 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCW6103fdDGYRsfjG/Rx+a/J+y2dTpbrvcdt8SmaN9jTazkxw8nCZ/Dy2aapD2GhMtrh4SYRKSRif5s=@googlegroups.com
X-Received: by 2002:a05:620a:298f:b0:858:f75a:c922 with SMTP id af79cd13be357-85adf5d27cbmr2689650685a.6.1759200271798;
        Mon, 29 Sep 2025 19:44:31 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1759200271; cv=none;
        d=google.com; s=arc-20240605;
        b=KrOyKoY5fXUcYSXeswdxNakNOk0EY8cfP9ZlyHDbYNvtLphZ9D+NZ/HUUdMHr+WmWc
         CIuElRD3yNh/i4m4lb6mPZfVNl0AahnAadQITXydd1Cc2TBvOLVaAaaCh2MFk26ijqkD
         C16+LFz0pxytQxRN9EeYv4Ne7LjgL9svdkR8tzVELSxGbbxBqUPdHR/ES5lhbwKgbIJD
         YAuqeD/pQ112VjJAmvbyDdSYqYekd+S4AgTSElONIICU2Kpftu8u5ZTeaI26YuUO8rtR
         Ch6UUVcJvqUecvFoVGtvqINY6b9Zq3ZdSV7UMzIIe72dJ0Tw3WFV5aYs9HCe9S0laryq
         nISQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=l9dguoBkY6LX1N0DOj75LxFoPgkZue82QF3pLTyVov0=;
        fh=j/M9K9ET/4e9+9ccNFwNVjpNWbdRqvqBGgMckL5fSM0=;
        b=TGdXCvGGvfEXIsTH5gp+72EraNiUyfbV7K1NxOAv239WWuPTzVyklCCevNL0vYY2Dd
         lpGDXT3YitqCDtxzMAgHPwsdoGqnE8W7ybRDDSoXhxyf2MARfQ1HJ0DCujZ7AyfFQ6aq
         rs+ficmyVLYybnKY1QnYxfSGlu/4iFgKEQIbakKYB4dyoauSw+mijbymyqjz0UHuN9zK
         b6VDCH7tJu8BdZGHM/0zqvaBXKgoqhkVXvkAJz/vk/ZqiYovTCV0m8w9RP7XsJavg4tt
         +cjNLgdJKdke5Gpxe+/1f3FVCSSlziKqoOZlzRP81MJIInoX/WNDcVqM43+d6qXtTJjP
         HuNg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=SwkZDhg5;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::535 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pg1-x535.google.com (mail-pg1-x535.google.com. [2607:f8b0:4864:20::535])
        by gmr-mx.google.com with ESMTPS id af79cd13be357-85c25b6eeedsi44260285a.2.2025.09.29.19.44.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 29 Sep 2025 19:44:31 -0700 (PDT)
Received-SPF: pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::535 as permitted sender) client-ip=2607:f8b0:4864:20::535;
Received: by mail-pg1-x535.google.com with SMTP id 41be03b00d2f7-b57d93ae3b0so2687803a12.1
        for <kasan-dev@googlegroups.com>; Mon, 29 Sep 2025 19:44:31 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVAyzJmrAjJHvzUNf0uIj9TeKVhmJQoOgtZpvHCywiwBthAqh9e+hGskzU0W7PDLIUsorG90IrKSsk=@googlegroups.com
X-Gm-Gg: ASbGncute4rqdBcpyIG9cjTJPdXdLBdwC5JzDQUShz+LTx9lseY3YZqqMT9/eoislym
	PoZAL4U/o53wHuwkOScR/gA7XYqUyHDBFaOR2kOllZ89vb6AWdk0sIJK5/EuErdXpzWSIYBlHxd
	ynFZsmvhZl4XwV4U/CPpqz+97cBxOZsr9r5wR4hJGJw+ePOq6PXE3yeboygMwQZIoMWTcQDWoC8
	0BIC0Ta7HxrHUr4eRV78XFxh8BQxPC3lQftAzXTR4FJzlCO1W1SuCIRoH6v+tNcOW5nRTgyJJVM
	N2qk7tRL8cDOXQK2kWVhENrd35TiMcKSQIijso6MgzOpxJvioW27RKRRCkYudfes2aDj4cKyqvF
	TAP0GKLGZLa4q4R4m3pRuKy+Eft36Iu/Kouo8kvmXnEM2ggCOx0r4lmTd4+XEYe4ZrDMhO+NGOr
	egrzvtlVINsQA=
X-Received: by 2002:a17:902:f543:b0:24c:b39f:baaa with SMTP id d9443c01a7336-27ed4a98ae9mr223248625ad.49.1759200270921;
        Mon, 29 Sep 2025 19:44:30 -0700 (PDT)
Received: from localhost ([45.142.167.196])
        by smtp.gmail.com with ESMTPSA id d9443c01a7336-27ed69bf9bdsm145712165ad.127.2025.09.29.19.44.30
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 29 Sep 2025 19:44:30 -0700 (PDT)
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
Subject: [PATCH v6 03/23] HWBP: Add modify_wide_hw_breakpoint_local() API
Date: Tue, 30 Sep 2025 10:43:24 +0800
Message-ID: <20250930024402.1043776-4-wangjinchao600@gmail.com>
X-Mailer: git-send-email 2.43.0
In-Reply-To: <20250930024402.1043776-1-wangjinchao600@gmail.com>
References: <20250930024402.1043776-1-wangjinchao600@gmail.com>
MIME-Version: 1.0
X-Original-Sender: wangjinchao600@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=SwkZDhg5;       spf=pass
 (google.com: domain of wangjinchao600@gmail.com designates
 2607:f8b0:4864:20::535 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
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

From: "Masami Hiramatsu (Google)" <mhiramat@kernel.org>

Add modify_wide_hw_breakpoint_local() arch-wide interface which allows
hwbp users to update watch address on-line. This is available if the
arch supports CONFIG_HAVE_REINSTALL_HW_BREAKPOINT.
Note that this allows to change the type only for compatible types,
because it does not release and reserve the hwbp slot based on type.
For instance, you can not change HW_BREAKPOINT_W to HW_BREAKPOINT_X.

Signed-off-by: Masami Hiramatsu (Google) <mhiramat@kernel.org>
---
 arch/Kconfig                  | 10 ++++++++++
 arch/x86/Kconfig              |  1 +
 include/linux/hw_breakpoint.h |  6 ++++++
 kernel/events/hw_breakpoint.c | 37 +++++++++++++++++++++++++++++++++++
 4 files changed, 54 insertions(+)

diff --git a/arch/Kconfig b/arch/Kconfig
index d1b4ffd6e085..e4787fc814df 100644
--- a/arch/Kconfig
+++ b/arch/Kconfig
@@ -418,6 +418,16 @@ config HAVE_MIXED_BREAKPOINTS_REGS
 	  Select this option if your arch implements breakpoints under the
 	  latter fashion.
 
+config HAVE_REINSTALL_HW_BREAKPOINT
+	bool
+	depends on HAVE_HW_BREAKPOINT
+	help
+	  Depending on the arch implementation of hardware breakpoints,
+	  some of them are able to update the breakpoint configuration
+	  without release and reserve the hardware breakpoint register.
+	  What configuration is able to update depends on hardware and
+	  software implementation.
+
 config HAVE_USER_RETURN_NOTIFIER
 	bool
 
diff --git a/arch/x86/Kconfig b/arch/x86/Kconfig
index 52c8910ba2ef..4ea313ef3e82 100644
--- a/arch/x86/Kconfig
+++ b/arch/x86/Kconfig
@@ -247,6 +247,7 @@ config X86
 	select HAVE_FUNCTION_TRACER
 	select HAVE_GCC_PLUGINS
 	select HAVE_HW_BREAKPOINT
+	select HAVE_REINSTALL_HW_BREAKPOINT
 	select HAVE_IOREMAP_PROT
 	select HAVE_IRQ_EXIT_ON_IRQ_STACK	if X86_64
 	select HAVE_IRQ_TIME_ACCOUNTING
diff --git a/include/linux/hw_breakpoint.h b/include/linux/hw_breakpoint.h
index db199d653dd1..ea373f2587f8 100644
--- a/include/linux/hw_breakpoint.h
+++ b/include/linux/hw_breakpoint.h
@@ -81,6 +81,9 @@ register_wide_hw_breakpoint(struct perf_event_attr *attr,
 			    perf_overflow_handler_t triggered,
 			    void *context);
 
+extern int modify_wide_hw_breakpoint_local(struct perf_event *bp,
+					   struct perf_event_attr *attr);
+
 extern int register_perf_hw_breakpoint(struct perf_event *bp);
 extern void unregister_hw_breakpoint(struct perf_event *bp);
 extern void unregister_wide_hw_breakpoint(struct perf_event * __percpu *cpu_events);
@@ -124,6 +127,9 @@ register_wide_hw_breakpoint(struct perf_event_attr *attr,
 			    perf_overflow_handler_t triggered,
 			    void *context)		{ return NULL; }
 static inline int
+modify_wide_hw_breakpoint_local(struct perf_event *bp,
+				struct perf_event_attr *attr) { return -ENOSYS; }
+static inline int
 register_perf_hw_breakpoint(struct perf_event *bp)	{ return -ENOSYS; }
 static inline void unregister_hw_breakpoint(struct perf_event *bp)	{ }
 static inline void
diff --git a/kernel/events/hw_breakpoint.c b/kernel/events/hw_breakpoint.c
index 8ec2cb688903..5ee1522a99c9 100644
--- a/kernel/events/hw_breakpoint.c
+++ b/kernel/events/hw_breakpoint.c
@@ -887,6 +887,43 @@ void unregister_wide_hw_breakpoint(struct perf_event * __percpu *cpu_events)
 }
 EXPORT_SYMBOL_GPL(unregister_wide_hw_breakpoint);
 
+/**
+ * modify_wide_hw_breakpoint_local - update breakpoint config for local CPU
+ * @bp: the hwbp perf event for this CPU
+ * @attr: the new attribute for @bp
+ *
+ * This does not release and reserve the slot of a HWBP; it just reuses the
+ * current slot on local CPU. So the users must update the other CPUs by
+ * themselves.
+ * Also, since this does not release/reserve the slot, this can not change the
+ * type to incompatible type of the HWBP.
+ * Return err if attr is invalid or the CPU fails to update debug register
+ * for new @attr.
+ */
+#ifdef CONFIG_HAVE_REINSTALL_HW_BREAKPOINT
+int modify_wide_hw_breakpoint_local(struct perf_event *bp,
+				    struct perf_event_attr *attr)
+{
+	int ret;
+
+	if (find_slot_idx(bp->attr.bp_type) != find_slot_idx(attr->bp_type))
+		return -EINVAL;
+
+	ret = hw_breakpoint_arch_parse(bp, attr, counter_arch_bp(bp));
+	if (ret)
+		return ret;
+
+	return arch_reinstall_hw_breakpoint(bp);
+}
+#else
+int modify_wide_hw_breakpoint_local(struct perf_event *bp,
+				    struct perf_event_attr *attr)
+{
+	return -EOPNOTSUPP;
+}
+#endif
+EXPORT_SYMBOL_GPL(modify_wide_hw_breakpoint_local);
+
 /**
  * hw_breakpoint_is_used - check if breakpoints are currently used
  *
-- 
2.43.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250930024402.1043776-4-wangjinchao600%40gmail.com.
