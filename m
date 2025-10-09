Return-Path: <kasan-dev+bncBD53XBUFWQDBBNFKT3DQMGQE2V2AMOY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73b.google.com (mail-qk1-x73b.google.com [IPv6:2607:f8b0:4864:20::73b])
	by mail.lfdr.de (Postfix) with ESMTPS id 5EB42BC8A14
	for <lists+kasan-dev@lfdr.de>; Thu, 09 Oct 2025 12:57:58 +0200 (CEST)
Received: by mail-qk1-x73b.google.com with SMTP id af79cd13be357-872d2ad9572sf280192085a.3
        for <lists+kasan-dev@lfdr.de>; Thu, 09 Oct 2025 03:57:58 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1760007477; cv=pass;
        d=google.com; s=arc-20240605;
        b=M4OUSOzvEZJJsYGnaxombOYEPbH2U6WD4Gfk7hmmQnVGMJwuofiAxiCQe60nTb4A6G
         oZHyOQUjDASajt76HBSulsseAG8M0gbeqP5Ym0h2QVRlQVDbLrmVYebVkZ0vFCXNIB7h
         BBLyELU85gg3NrC3/1VAA4tckWNpNJ9Df3DhlZDEJ7QNR/tRvQQCLVIiJTJnzJnIdODO
         UisY6enLemWnFqrdwlHKVDu+YyBA0T8A7nw9RFHXzIX7SwmGCJKeBqbtECpgeVBgRQWB
         ZbuEoaBe4mnLfFzKsvFGxgDIeaa66ntE/TfzpSr2dufWbf6vjvPEgVTjSkvr7yJO05q2
         F8zQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=f6/Yqdixni2jkSa/sSdmzFR+QssaFs10BYAZUoUO1zY=;
        fh=VGDitN9r8mmCcGd1dlmECKBiYEdCIURiHNW9ta2miRM=;
        b=VtVFbsh5VrdkxhXVOv1pvVehEaqTn9ktngxdv50mUsCAMLaPNyUODDXndJ3C4BhwMb
         OMgEIe7FzS8e+wLAAM9FrIeVGnAjI9ieOm9UWPlEEu8+gA1J9EqN4IwJw0TUzRmkk+eJ
         6pE4n0E1YxTposEL+T39pnXD8gOoOBx/0/+vfrCqQVV/3MMSUc4QRFTKO/+XrVjzpNcD
         b41dG3aqYiycxc+KYDSqGkEIRLBi5ufAJiu6UQY9csBMSGAA2kzFQOo5bAvN62O4Kqim
         DEyF1tYYy0cFjkxprQwPHarAwyGiXgaIhofPKp1HAAKiTWZCDH6515jTok57m+yFbrVp
         y2CA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=LcnJE3C7;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::531 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1760007477; x=1760612277; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=f6/Yqdixni2jkSa/sSdmzFR+QssaFs10BYAZUoUO1zY=;
        b=vJ/iFpqC3b4Xfaavnn1qOoEQAeAYroCCFMnUY/jIIArGEhfQUbkwws84DGQjexEuk0
         ucp6Yi5Bw2cuYsybeUUiy+88Yiy5kueS0yL6Na2AiT0WfwhK/tzphCLRsw5p7LwraBLM
         9YQZQtKhZHPPkMOHgEvcx92apWS6nP41O2zRUuGOXurR1EyB+5P1UBF/72qWCOnwALaP
         6TQH4mqWQN367rk/oX52/RIIBrEuVvnKArWvDwm/M0Jjyv5SjRK0FNPOXTOgzOqZEFSr
         ES0lOA7AOmEg5nwI3FvU+ORyG/cx/UlfX3yysxynh8F7bx+Z+XMxFXA0bapREefnpz+h
         AgRA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1760007477; x=1760612277; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=f6/Yqdixni2jkSa/sSdmzFR+QssaFs10BYAZUoUO1zY=;
        b=iBnG2iqcfDqbDf3OKjzwToAb5eU+LSICAxC7Z1KsXjmNAT3mzKp18imrag6OS7zHV8
         hYBEsfn0201cGXsDKmx2UcqG7euZ4xwNNkKkQX2l+IUejaTGpsf795zRwvbXKMXithJf
         SdtgIgZncZ/9vAuxhfqpxV2W2o886/6QXl765Q+GaYjYs1yQcrO01i+ifrBLcPSakhdo
         NibGTccj+7tmSTekIAAD5sNf2sfjShOisLL7IjcqyAyyyzcnDTSLMSl8dyktL5J2Qdzw
         pOSlSev3VY86RORWIvzVmAB/C+J4d0kk03BW2TRy8+N0Mn2pSXpm8JbrrmKI4mVyJDnJ
         o2nw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1760007477; x=1760612277;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=f6/Yqdixni2jkSa/sSdmzFR+QssaFs10BYAZUoUO1zY=;
        b=W4/vr8z7M0lDDTHwFWx8sjQ0ro05bJZ6QpiY3Yqat1CF7g4KZLrEEEmZ8ZUpPFNyO9
         pIJi5OkFKAYYOnmKQq/ZH4vBHJduSf8MdpvYo43QiXGMLhsAeIVIcBoNHMRazma6tiko
         bkKIHpYorTuxGFmMAgvdnjPw14ZbHyy+NMsR2SZdkvuSX50Pz0cII8n+dqNCjYUWQiU6
         hGYAfQSnIkm55xKdjZBPOApo2FI6hEv9rBXtT+JwLmgb/Dvr8dGOk2G4S27cChj4tN4i
         C8uh/aoAPLaYOFRAsz4WV5RYX10rXA5cBm1zeeVCQhhyQMmHN7al6fjtQPPZeAdZiOY1
         oWow==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVLVZ4XLTbo0UvUKGRaGUHW3eJd7Gf1+zbcDMk+I/42gYXGTnz04PX4udCpCF7ataOkyqgMoA==@lfdr.de
X-Gm-Message-State: AOJu0YzWabTkWr+u+6XbO0aVH39NiZZbW5SSRV062yUTXyIXowfopnhm
	o4ejbq+AlH1gmIodvC2KMBiybTCZHyh7X+u22p1n05cjoMndujrPQ7jr
X-Google-Smtp-Source: AGHT+IFjvI1KDZrUf5JkTPA9OZlp76vNIbmcGa4AuihOdb9s4JA+a6tfUI3VUnNOP04Fan5lmoR6aA==
X-Received: by 2002:a05:620a:2985:b0:850:329f:f1ef with SMTP id af79cd13be357-883525c06b3mr849261185a.55.1760007476917;
        Thu, 09 Oct 2025 03:57:56 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="ARHlJd5MUtFz/MCWq5K0Yx9DI6Rru7P5VBRLnFMSR7eUGmefvQ=="
Received: by 2002:a0c:f088:0:20b0:87b:c047:4e44 with SMTP id
 6a1803df08f44-87bc04755a2ls812086d6.0.-pod-prod-02-us; Thu, 09 Oct 2025
 03:57:56 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCV7pzmf3NGScjHQPLkc8N78T5gIs9KenDgcuSCe34spBcsmmKWnuwwfFNtXWHR17eZWMp+mncw98Kc=@googlegroups.com
X-Received: by 2002:a05:6102:6487:20b0:5d5:f3ec:cb57 with SMTP id ada2fe7eead31-5d5f3eccb71mr430439137.22.1760007476140;
        Thu, 09 Oct 2025 03:57:56 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1760007476; cv=none;
        d=google.com; s=arc-20240605;
        b=iJpHXmvYTDpp873tlpLkA5fw4pG1CAeQRl85FQTIVB4nCcorLOusrKL0c3VD00dEy1
         5m8g/r1iEduN/UfJ7KsGsurivBdp1YfL8vOWk7Ow4hdhBcOm+B1t4VsI4T7wzONsTIVy
         mDpYyJccIByPHBKzjbWNFwJSXpsv8D//F7oVsdMtwAWHli/FptqeLfl6YgemdUvjwwyD
         RVAqyChWMdcWSLrkAykFEo7G0h5jSmU6hmD9dgU/nFcQ9+W8K3mUsn0SMsuGfbg/+h6B
         W8VhNMBZcam2kg4OK9jqC5gGWcZiTuprWgT5NOGv/ExOemqumSiLbtrLmJcduF0YEtWK
         kMtg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=Zjvk/jwcgtCF9TRiT6Fv94jzQiYOsdOhmjAblUevyNs=;
        fh=e8NfDG/aXbkpig/d7K53NLkaZLcd2tnSQnpK/7xY5t0=;
        b=SV8xTpQfe13Q4c03Zwfd/1ty70Xqndb6UsvQvSvY9cL62fNdihqM3hmztMQ+ykuyO3
         yq7DG6gLmAbd2hJdG10x0sYqM7Lp+pOP7mUoBejH/RSp4nSbALiCMR+EPnM828P59BEU
         pxNqjRlyzQlBUDyZc/IC0fWpjcG8wo4rzJ+Z3WiGPsOL/o8WjPuv6Hzfa9OMc+YwSU3W
         wD+x6HD2Zxal0ON8UBUivstxECHhBIfxbLl4CMxvjLVrZxJ5EzUkHuhFLH5NkVr6WehF
         b+d8DQRXvtezfy9apYDiktZDyOgVNqGKsUw5h/TlMa3RpsJb60XfJDATDRHUmSJrCf3J
         dJ+A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=LcnJE3C7;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::531 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pg1-x531.google.com (mail-pg1-x531.google.com. [2607:f8b0:4864:20::531])
        by gmr-mx.google.com with ESMTPS id a1e0cc1a2514c-930b1c1b1casi70981241.0.2025.10.09.03.57.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 09 Oct 2025 03:57:56 -0700 (PDT)
Received-SPF: pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::531 as permitted sender) client-ip=2607:f8b0:4864:20::531;
Received: by mail-pg1-x531.google.com with SMTP id 41be03b00d2f7-b55640a2e33so513271a12.2
        for <kasan-dev@googlegroups.com>; Thu, 09 Oct 2025 03:57:56 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCV65zBweseNB+QtH9GDd95hLu47nSmt8kngEGIBP3n4aIkPSrIXdW7PYmNunBbAckq5Wd9xO7YUn60=@googlegroups.com
X-Gm-Gg: ASbGncsbtm9/9qj+SLfQbE0O4ukEuzmq3y7o1Uu+3X22Fy8McHVSueFEnQnq2Zorca6
	+6YujfRSp5V5fPjGKocIyhIBmo1ZZfKk/5cngjnEBZqLJplTzXC3oT2o+1QcuzsdyN/6lqpj23v
	08MfBOaFZGZrv+QLIqU/SaRZSSgXcqOHStA270gJe/7NLT6ZPgGhAKorowK1YAI0F9injZIuuEz
	58ZSguQwgMltKKL4Fu3cf+uOuIdD2iiq+dh+X+hfawAQdnLcz+f6cYDVqrX9c65gZh0eR9tdg7q
	W2dNotHJlWt2oh+wx+u7LF4hmEC3EHUEn7gLjTQt8Wxxq8sYfRwkDLNRwW4Z+qJ0/jgw60t+p39
	wqUTBNCw19OX8dtnHDR3AWhf1MeQssl6wu33pV6ON4GlmPIUObMg4hYE94DKK
X-Received: by 2002:a17:903:acb:b0:24b:270e:56cb with SMTP id d9443c01a7336-2902739b362mr90085425ad.27.1760007475016;
        Thu, 09 Oct 2025 03:57:55 -0700 (PDT)
Received: from localhost ([45.142.165.62])
        by smtp.gmail.com with ESMTPSA id d9443c01a7336-29034e1cc53sm25234015ad.46.2025.10.09.03.57.54
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 09 Oct 2025 03:57:54 -0700 (PDT)
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
Subject: [PATCH v7 12/23] mm/ksw: add entry kprobe and exit fprobe management
Date: Thu,  9 Oct 2025 18:55:48 +0800
Message-ID: <20251009105650.168917-13-wangjinchao600@gmail.com>
X-Mailer: git-send-email 2.43.0
In-Reply-To: <20251009105650.168917-1-wangjinchao600@gmail.com>
References: <20251009105650.168917-1-wangjinchao600@gmail.com>
MIME-Version: 1.0
X-Original-Sender: wangjinchao600@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=LcnJE3C7;       spf=pass
 (google.com: domain of wangjinchao600@gmail.com designates
 2607:f8b0:4864:20::531 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
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

Provide ksw_stack_init() and ksw_stack_exit() to manage entry and exit
probes for the target function from ksw_get_config().

Signed-off-by: Jinchao Wang <wangjinchao600@gmail.com>
---
 mm/kstackwatch/kstackwatch.h |   4 ++
 mm/kstackwatch/stack.c       | 101 +++++++++++++++++++++++++++++++++++
 2 files changed, 105 insertions(+)

diff --git a/mm/kstackwatch/kstackwatch.h b/mm/kstackwatch/kstackwatch.h
index 850fc2b18a9c..4045890e5652 100644
--- a/mm/kstackwatch/kstackwatch.h
+++ b/mm/kstackwatch/kstackwatch.h
@@ -35,6 +35,10 @@ struct ksw_config {
 // singleton, only modified in kernel.c
 const struct ksw_config *ksw_get_config(void);
 
+/* stack management */
+int ksw_stack_init(void);
+void ksw_stack_exit(void);
+
 /* watch management */
 struct ksw_watchpoint {
 	struct perf_event *__percpu *event;
diff --git a/mm/kstackwatch/stack.c b/mm/kstackwatch/stack.c
index cec594032515..9f59f41d954c 100644
--- a/mm/kstackwatch/stack.c
+++ b/mm/kstackwatch/stack.c
@@ -1 +1,102 @@
 // SPDX-License-Identifier: GPL-2.0
+#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
+
+#include <linux/atomic.h>
+#include <linux/fprobe.h>
+#include <linux/kprobes.h>
+#include <linux/kstackwatch_types.h>
+#include <linux/printk.h>
+
+#include "kstackwatch.h"
+
+static struct kprobe entry_probe;
+static struct fprobe exit_probe;
+
+static int ksw_stack_prepare_watch(struct pt_regs *regs,
+				   const struct ksw_config *config,
+				   ulong *watch_addr, u16 *watch_len)
+{
+	/* implement logic will be added in following patches */
+	*watch_addr = 0;
+	*watch_len = 0;
+	return 0;
+}
+
+static void ksw_stack_entry_handler(struct kprobe *p, struct pt_regs *regs,
+				    unsigned long flags)
+{
+	struct ksw_ctx *ctx = &current->ksw_ctx;
+	ulong watch_addr;
+	u16 watch_len;
+	int ret;
+
+	ret = ksw_watch_get(&ctx->wp);
+	if (ret)
+		return;
+
+	ret = ksw_stack_prepare_watch(regs, ksw_get_config(), &watch_addr,
+				      &watch_len);
+	if (ret) {
+		ksw_watch_off(ctx->wp);
+		ctx->wp = NULL;
+		pr_err("failed to prepare watch target: %d\n", ret);
+		return;
+	}
+
+	ret = ksw_watch_on(ctx->wp, watch_addr, watch_len);
+	if (ret) {
+		pr_err("failed to watch on depth:%d addr:0x%lx len:%u %d\n",
+		       ksw_get_config()->depth, watch_addr, watch_len, ret);
+		return;
+	}
+
+}
+
+static void ksw_stack_exit_handler(struct fprobe *fp, unsigned long ip,
+				   unsigned long ret_ip,
+				   struct ftrace_regs *regs, void *data)
+{
+	struct ksw_ctx *ctx = &current->ksw_ctx;
+
+
+	if (ctx->wp) {
+		ksw_watch_off(ctx->wp);
+		ctx->wp = NULL;
+		ctx->sp = 0;
+	}
+}
+
+int ksw_stack_init(void)
+{
+	int ret;
+	char *symbuf = NULL;
+
+	memset(&entry_probe, 0, sizeof(entry_probe));
+	entry_probe.symbol_name = ksw_get_config()->func_name;
+	entry_probe.offset = ksw_get_config()->func_offset;
+	entry_probe.post_handler = ksw_stack_entry_handler;
+	ret = register_kprobe(&entry_probe);
+	if (ret) {
+		pr_err("failed to register kprobe ret %d\n", ret);
+		return ret;
+	}
+
+	memset(&exit_probe, 0, sizeof(exit_probe));
+	exit_probe.exit_handler = ksw_stack_exit_handler;
+	symbuf = (char *)ksw_get_config()->func_name;
+
+	ret = register_fprobe_syms(&exit_probe, (const char **)&symbuf, 1);
+	if (ret < 0) {
+		pr_err("failed to register fprobe ret %d\n", ret);
+		unregister_kprobe(&entry_probe);
+		return ret;
+	}
+
+	return 0;
+}
+
+void ksw_stack_exit(void)
+{
+	unregister_fprobe(&exit_probe);
+	unregister_kprobe(&entry_probe);
+}
-- 
2.43.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251009105650.168917-13-wangjinchao600%40gmail.com.
