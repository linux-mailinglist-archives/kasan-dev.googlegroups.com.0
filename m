Return-Path: <kasan-dev+bncBD53XBUFWQDBBJHER7DAMGQE3IGISOI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x838.google.com (mail-qt1-x838.google.com [IPv6:2607:f8b0:4864:20::838])
	by mail.lfdr.de (Postfix) with ESMTPS id A2C7CB548EB
	for <lists+kasan-dev@lfdr.de>; Fri, 12 Sep 2025 12:13:10 +0200 (CEST)
Received: by mail-qt1-x838.google.com with SMTP id d75a77b69052e-4b5eb7b2c05sf40243261cf.0
        for <lists+kasan-dev@lfdr.de>; Fri, 12 Sep 2025 03:13:10 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757671973; cv=pass;
        d=google.com; s=arc-20240605;
        b=i2hCNgpF+TWy4QBWJv81Bf51aZDfvMDxSbsvhQMpSkbUppIt7NQRNXrxKAqHb5b2zM
         tdwvAYkrx4nHe9E8/5zkKSCQ3E+BZ0aZBdqDvPDmahWR6OxMW/x0TXhhxhu4Lfa2zWK5
         8hPten1CiYwsaHqYPTTn/IOc9VNkj2IqCYBcPMHpuMYMVshlg/o4cqf/mHfiGjjHPG9V
         GdL068BEzm+lQj55DapgFRhwn1XY+E7PW0GmzBR8GMaz6KCAfflQBIOHtOrCetU2liCE
         IRYcHsu7az/oC//ApNpt5VZ/woZOBA/i4tjKSrhvRXvu49Dpi7Zdo7UqLJ9ZqTx+QkO3
         dyxw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=okZhwQgiJQ9kyjeyUnCV/tC6G8G19SfTC8oC9VG7F2s=;
        fh=PJjX95YVuptoibdoi1hwVVHfjro0pnEF1XHxpUrgIVg=;
        b=GWEi5WKD7o2P/lwlIi/bYA+tGaNDN3LMLeNVwK81rtF0UgCXml5f6QbvyQ3a04EDdQ
         nwBiwsUL3ek71uFT+iqZVVvTI45YGIZqvvnhYL7x26ADlqiCn4VI2fxJht69rOgU2w+4
         B1u3gxynisXQCn3Yx4sBG8jxB6E01iKIiU+iOwGjf7h/6vw0X2g9MYKChAzYIf7OmXrg
         ZJWVi1yjijmuG7Njpq31+/2hQzMmIPCne1snqV+hyrdYXFMr2Di6g1c8N7mGzDj//aGa
         iO3JcV4kA2o5cmejFL5Bb7Q+GrC5tL3QsuDLYg6GaIc9yP91M97lP9Hks12qUnSYsZgV
         XAag==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=aOJ8xfWQ;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::529 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757671973; x=1758276773; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=okZhwQgiJQ9kyjeyUnCV/tC6G8G19SfTC8oC9VG7F2s=;
        b=wqzZSOwKiRq2YI/7fyAFtxs0JTX5PshS/HC40aYfeAvtLlerERw1EXHJFC81+Tq55v
         WT+mwVVzSztMEC5BeSycwFzqID9QSjXPKQB85zn2nZAjlq4NuER/Q5r6Tn98qB3NEz7X
         1BifxODcAOcsQCacQB02aAapz9sdlUIWZPdBd0MVSMmbsJ+EmnDmrqRJgN+NAhN4m3qW
         4My+qC+LzdGCn1TXzY5MXxDy0f5Kfsz2UpiTu6B3kzZcCapd8eK4T36JSvSqP16xzqwY
         7ssRMbsGcF4gCO/AnPlT5kZfbwemmJ8CJ2UGwuczAtzpgaR4uLcpvXxjTDpFYuUGeQl2
         HASA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1757671973; x=1758276773; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=okZhwQgiJQ9kyjeyUnCV/tC6G8G19SfTC8oC9VG7F2s=;
        b=JbsI0U5m9DZtZHnzym/33xq8JxbpyW+PJu5bDhBfZFyVTiUpbqWND4jChii3GeH6Xm
         zCHg9TNddmqb04QZ6pp/CC3ZVeCSvFynfH3PrDgR0fnD2YVh81gcuRr7nZi6iqGEvv+K
         xV5TmHPAzbXqhZIeQeXBJOvacjUv/WJLCkllVsWyFNzLh96V1wny4DAfwjOwef2E8xlB
         JC9qc4LlKVpXKkVNhBSmo+1M9QnXZlfGOsfQJc5lRtTVCnAgW3lbPJkPBLlD6jlEc/x5
         ffxP95RJ82iRLywsSVh3l6OcljalZ+E8Zfjsug7d1JMir0NpPimADNYZ48FYy3kl21Fe
         B2Fg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757671973; x=1758276773;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=okZhwQgiJQ9kyjeyUnCV/tC6G8G19SfTC8oC9VG7F2s=;
        b=mQYDTYr58D47q2etrSws9zWt5mG7jNn2RZPjKsxRjQzd3NkcvbSHAgjmvKrmg4hDwY
         aHBuahciXGK7NpV29n1OjBITbsAvoiQA/RQKiYPcIjwDOuDTwotM8oivlcTorr2keHzN
         I1AmOxz6GaPrwA7jfUEYQCWvGN/REC0MO6MmYjt1tm+Yae6oAsYP45DxxFTbtCcWSQ1z
         1DoWGkX/tek695TKuIZnT0MZcIp21VyKPidZ+iCcw1L7qW+3YAvycc1Bx8b3itJlEjP0
         lrIvl9TYjV6BkxszFbyPssnGC8wOCWqZxkuBRlvtL8vDfNOZ3owpbPH9NbKs9v9i8Arb
         948Q==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUwSPO2MMmU3bEBw5QoJ18lGyEhybDzO5iGBJD2D0bka/wBXIpdtMKADE2F8xUwF+DEa6/Blw==@lfdr.de
X-Gm-Message-State: AOJu0YyPZI4eGDQvta2S4jFS0x1wOOlPKTPU4m4n+kEngdCab5oggf/0
	D0r8VcgW8JQAnxbSjcLUSKQpvlaCVGXq1GAubMPr2ujBZzkbaxFXcEfM
X-Google-Smtp-Source: AGHT+IFQLFHxlVgM/FaztInM/Ct/hgvvSZ7YXXqAd8gGVL8tCcFE5KQT4OmtwKOGB82gbGD4/qNT9Q==
X-Received: by 2002:a05:622a:1116:b0:4b6:373c:f81c with SMTP id d75a77b69052e-4b77d096479mr27012221cf.30.1757671972920;
        Fri, 12 Sep 2025 03:12:52 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZe9N93SvJnS1pKpWyYRKDnel/1zNEw3FeWZPCbFdjcpkg==
Received: by 2002:a05:622a:1801:b0:4b0:64ac:9be9 with SMTP id
 d75a77b69052e-4b636cb312els35104721cf.2.-pod-prod-03-us; Fri, 12 Sep 2025
 03:12:52 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXdrGXHhtfSFRCtkufIZG8JAkZ5eqCXFAxamnVJjeSy/aLKscMANlq+pOTv/C5sd+aD1MstOEryKmo=@googlegroups.com
X-Received: by 2002:a05:620a:448c:b0:7f3:62f3:32b1 with SMTP id af79cd13be357-823fbde8dabmr332447485a.1.1757671972011;
        Fri, 12 Sep 2025 03:12:52 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1757671972; cv=none;
        d=google.com; s=arc-20240605;
        b=XTkNtPpz+VHH9ExcAcg+aOaUA5YTbsbndtPURRqrlhLd0xwDBa1xkwq8OGuLjeo8Vp
         o2rG/8mFVuplgAHmuWc7lXErkTZHa6HCm5WpxkQs4E8xsjhotsGnrh9f8qZPDjkUnaWr
         6B7ZwvnVK6enmAj1k8Mmrx5dYIVwrYf93L8OQ6sSPoUBvOAx7EomimOEpVtJ4Yb4ka65
         sdEYYde9uMwdra4IvXy2MB7vzm1uMHtnK/MohJlk6N/QzYKCrwqM/fNcxzfiXr1su9Qn
         CXnOpe6qnhe+qg+V9Lm2Cn1DSspR/feq9HomCjqualUagH31HTyl5RswWHrdWc8hfQKC
         BnrQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=bEzQtMPq9PK+5+yYtP/oNug9OWMsSiZGEa798p9Mz9w=;
        fh=42a2XRUki6t2Ohms8zG0IZxTcj6YbCfqayRLnECwOW8=;
        b=kcxqp2/1n90o5HC91TI8jqIoAAk9b5MG6qm1NnfW8e8f0Ps7H4jm7BaSOx6Ccd+RxI
         sxiiyhZ6ViTnJVzx3HIa6XeLA/HoKPIOTb5oKPFSmvv44FAHj8bidwDzh0kQPEH6YEFm
         rRPNZJhIANtM3lClIY9tWPuT6yZaoxjreAMJSucDrkFcweoXCPGegtGXUSmTo6wwW7mU
         eZgtTXkt8QVMEdItc0LPsOPctmFsA38/H0Cd38L75yQ/jSc6paaC6ixJtwNNMtiyUlg0
         z69iu+H4xA2cFViL1JR8DxN3S7CALeGu8yVWQ/yTDcc94I4CTprzO1z1POySHRmxYAOq
         xbJw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=aOJ8xfWQ;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::529 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pg1-x529.google.com (mail-pg1-x529.google.com. [2607:f8b0:4864:20::529])
        by gmr-mx.google.com with ESMTPS id af79cd13be357-820ccb4e66bsi16628985a.4.2025.09.12.03.12.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 12 Sep 2025 03:12:51 -0700 (PDT)
Received-SPF: pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::529 as permitted sender) client-ip=2607:f8b0:4864:20::529;
Received: by mail-pg1-x529.google.com with SMTP id 41be03b00d2f7-b54abd46747so686274a12.0
        for <kasan-dev@googlegroups.com>; Fri, 12 Sep 2025 03:12:51 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVJMNumkUXzn4xSBFiWDX65FjDiDrh/6/FEMZolD/+RLPOSqZ+Pt9oaj0BJhc1ra8FBhhVZOJ+2t9w=@googlegroups.com
X-Gm-Gg: ASbGncuFlCSFYOWbhhVCLVgrcPBW0PVLcGoumBs5UngoPgM6GMDwwL+hZNWjfW65FX4
	oRWJXosypPHLyDEdoSoujHtLfWNmRGjV4HJ0grGRFWa3ppfVqsm63MU4xbvGB7rBLCPbsFDHfJt
	aMduS3vJ3x++qRLOormIbbhkWkSmqjsUaWQ4Jfn5UIE1XBUD2ECGFHw+RvVEVFAx962A1MM2tcL
	1t71PDGq44gbk53Z+QL9Yw58gD50tSbyxVs5LOEFZYsIsbw3O9mz2+dqN0RxW+bTMgO0sKgKxrk
	kacVR0RHlyTwkWzBLhakhleH/z6/b1to5cyEfl+lxG4op4V2XKdrfASYWEhahIRKHiQapTIXmHi
	ZOhZyTkcIwyfHyCQrimZ48NQI0DcLr15764RbvVieUTThy7/oRq5SiLZg9Syp
X-Received: by 2002:a17:902:d490:b0:25c:18d:893 with SMTP id d9443c01a7336-25d24bb33f9mr25149495ad.22.1757671970918;
        Fri, 12 Sep 2025 03:12:50 -0700 (PDT)
Received: from localhost ([185.49.34.62])
        by smtp.gmail.com with ESMTPSA id d9443c01a7336-25c37293f0asm45159835ad.43.2025.09.12.03.12.49
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 12 Sep 2025 03:12:50 -0700 (PDT)
From: Jinchao Wang <wangjinchao600@gmail.com>
To: Andrew Morton <akpm@linux-foundation.org>,
	Masami Hiramatsu <mhiramat@kernel.org>,
	Peter Zijlstra <peterz@infradead.org>,
	Mike Rapoport <rppt@kernel.org>,
	Alexander Potapenko <glider@google.com>,
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
Subject: [PATCH v4 11/21] mm/ksw: add probe management helpers
Date: Fri, 12 Sep 2025 18:11:21 +0800
Message-ID: <20250912101145.465708-12-wangjinchao600@gmail.com>
X-Mailer: git-send-email 2.43.0
In-Reply-To: <20250912101145.465708-1-wangjinchao600@gmail.com>
References: <20250912101145.465708-1-wangjinchao600@gmail.com>
MIME-Version: 1.0
X-Original-Sender: wangjinchao600@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=aOJ8xfWQ;       spf=pass
 (google.com: domain of wangjinchao600@gmail.com designates
 2607:f8b0:4864:20::529 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
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

Provide ksw_stack_init() and ksw_stack_exit() to manage entry and
exit probes for the target function from ksw_get_config().

The entry/exit probe handlers use atomic ksw_stack_pid to ensure a
singleton watch and current->kstackwatch_ctx.depth to track
recursion depth. A watch is set up only when depth reaches the
configured value.

Signed-off-by: Jinchao Wang <wangjinchao600@gmail.com>
---
 mm/kstackwatch/kstackwatch.h |   4 ++
 mm/kstackwatch/stack.c       | 113 +++++++++++++++++++++++++++++++++++
 2 files changed, 117 insertions(+)

diff --git a/mm/kstackwatch/kstackwatch.h b/mm/kstackwatch/kstackwatch.h
index 0786fa961011..5ea2db76cdfb 100644
--- a/mm/kstackwatch/kstackwatch.h
+++ b/mm/kstackwatch/kstackwatch.h
@@ -38,6 +38,10 @@ struct ksw_config {
 // singleton, only modified in kernel.c
 const struct ksw_config *ksw_get_config(void);
 
+/* stack management */
+int ksw_stack_init(void);
+void ksw_stack_exit(void);
+
 /* watch management */
 int ksw_watch_init(void);
 void ksw_watch_exit(void);
diff --git a/mm/kstackwatch/stack.c b/mm/kstackwatch/stack.c
index cec594032515..ac52a9f81486 100644
--- a/mm/kstackwatch/stack.c
+++ b/mm/kstackwatch/stack.c
@@ -1 +1,114 @@
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
+#define INVALID_PID -1
+static atomic_t ksw_stack_pid = ATOMIC_INIT(INVALID_PID);
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
+	struct kstackwatch_ctx *ctx = &current->kstackwatch_ctx;
+	ulong watch_addr;
+	u16 watch_len;
+	int ret;
+
+	if (ctx->depth++ != ksw_get_config()->depth)
+		return;
+
+	if (atomic_cmpxchg(&ksw_stack_pid, INVALID_PID, current->pid) !=
+	    INVALID_PID)
+		return;
+
+	ret = ksw_stack_prepare_watch(regs, ksw_get_config(), &watch_addr,
+				      &watch_len);
+	if (ret) {
+		atomic_set(&ksw_stack_pid, INVALID_PID);
+		pr_err("failed to prepare watch target: %d\n", ret);
+		return;
+	}
+
+	ret = ksw_watch_on(watch_addr, watch_len);
+	if (ret) {
+		atomic_set(&ksw_stack_pid, INVALID_PID);
+		pr_err("failed to watch on depth:%d addr:0x%lx len:%u %d\n",
+		       ksw_get_config()->depth, watch_addr, watch_len, ret);
+		return;
+	}
+
+	ctx->watch_addr = watch_addr;
+	ctx->watch_len = watch_len;
+	ctx->watch_on = true;
+}
+
+static void ksw_stack_exit_handler(struct fprobe *fp, unsigned long ip,
+				   unsigned long ret_ip,
+				   struct ftrace_regs *regs, void *data)
+{
+	struct kstackwatch_ctx *ctx = &current->kstackwatch_ctx;
+
+	if (--ctx->depth != ksw_get_config()->depth)
+		return;
+
+	if (atomic_read(&ksw_stack_pid) != current->pid)
+		return;
+	WARN_ON_ONCE(!ctx->watch_on);
+	WARN_ON_ONCE(ksw_watch_off(ctx->watch_addr, ctx->watch_len));
+	ctx->watch_on = false;
+
+	atomic_set(&ksw_stack_pid, INVALID_PID);
+}
+
+int ksw_stack_init(void)
+{
+	int ret;
+	char *symbuf = NULL;
+
+	memset(&entry_probe, 0, sizeof(entry_probe));
+	entry_probe.symbol_name = ksw_get_config()->function;
+	entry_probe.offset = ksw_get_config()->ip_offset;
+	entry_probe.post_handler = ksw_stack_entry_handler;
+	ret = register_kprobe(&entry_probe);
+	if (ret) {
+		pr_err("Failed to register kprobe ret %d\n", ret);
+		return ret;
+	}
+
+	memset(&exit_probe, 0, sizeof(exit_probe));
+	exit_probe.exit_handler = ksw_stack_exit_handler;
+	symbuf = (char *)ksw_get_config()->function;
+
+	ret = register_fprobe_syms(&exit_probe, (const char **)&symbuf, 1);
+	if (ret < 0) {
+		pr_err("register_fprobe_syms fail %d\n", ret);
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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250912101145.465708-12-wangjinchao600%40gmail.com.
