Return-Path: <kasan-dev+bncBD53XBUFWQDBBH7ER7DAMGQE46WMLWY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13f.google.com (mail-il1-x13f.google.com [IPv6:2607:f8b0:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id A970BB548EC
	for <lists+kasan-dev@lfdr.de>; Fri, 12 Sep 2025 12:13:10 +0200 (CEST)
Received: by mail-il1-x13f.google.com with SMTP id e9e14a558f8ab-4133da01bdcsf39983905ab.0
        for <lists+kasan-dev@lfdr.de>; Fri, 12 Sep 2025 03:13:10 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757671968; cv=pass;
        d=google.com; s=arc-20240605;
        b=KzODk6olIapPT+APNBAD9XGDfp+D1VkO974Cu6Picb3tg7P3qAhRC9+YB7Qw9Nizyw
         UnINy/+CSxttIIawG9feqRuYKbFFglTdbkwGMWfJZ4MW+MeC93PTxE145Zjl+57SPel/
         VTJbboCN4GHjmhAEoo+G4By3LO+aNGGURshltSSHWVJbWiLuiWbwzXG6D9N6mw5lstyO
         XBlra6hWMTXT5qwfNnGeSi8Wy/hucOU7HAt1ji077wFO5o6XscvigtOil+t/mF7ABfix
         eagl/Cynxtap7i65VuEeL9NCAkAANarTxDY4doM7acoIDJzcqXHO43HqVtCcYffqRlNH
         OoFQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=Oaf0EpzISDaM0qYrtVdR+Q4qGsBV38SIMELmvNLQhzE=;
        fh=pF6Peg9WgMPiTXPx2+GAbOOOsOdrQdA1SbTo485i5hA=;
        b=UdCVt3hyu9Iw0KRJ6YmYOZqLsLG+cGT8aPk2Y2tbT0bFAzrycgVyuAtaXmH3f40bpb
         kLpGMu9jDoGzNUAEyT5RMeamZDaEJnorGKpqhEquOiEAcUeVWuVmwJHgj6A2qTHdWfhh
         JHBlfg5/o/kGPw9C38yIc6cKBQLYkjPmexdOWfuVOFSu1MALpwGPN/TVjaQhu7JXRsDp
         QYxAlxJ2JQMA1Z1b7M/UdNAHeAs0xM7wUInrun3LlSv7z66LwOVFeebnzmVNxRThmg0R
         RYzs/x/5dXRKzACKn4YVEJTehRzfr1HocLIIWYFwV4yuTzTeToGEfMcPbjMWlCVZBX7n
         mwXQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=lobhHoL3;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::536 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757671968; x=1758276768; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Oaf0EpzISDaM0qYrtVdR+Q4qGsBV38SIMELmvNLQhzE=;
        b=Puo+u+dF2ePksmXm2UOUt4lbnKeC5z7rGrKD5KBJhIa21v8n/2Tqefb5bK61UkxKmS
         wBejmlLW5n9mciOaniC+dh6TGBB4Fmtr8s2/MwhHzEzvVe0bJ7poJMn3w46uWG1wJ7qn
         lVORdBc5fjN3UhJmATjOk1jO5UymqSaDdaJoRtukIWce2TT5avJcCBryQYst2e31W6b7
         sGeMQzmI+bWmPXA/LZEPleJ6QehF+PmqIs7X6BQwdeX11u7oCLp1RPCKtytCOoR+WKh5
         8Dvq4HUhwLke0VTH5tcmAIre3KNgqn6o5sDiBRXxT0O+iXQn1UJOFuqBVONuTp0Xb+5w
         kUVg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1757671968; x=1758276768; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=Oaf0EpzISDaM0qYrtVdR+Q4qGsBV38SIMELmvNLQhzE=;
        b=Ss0jFPdm8+NRrd58hQDuWVyO1Q8OBfVGrDHdeyGYQbAFfv7B3HruPX3PIGaZfVD8rF
         8snFx0EBjqDuYmiIM3QQWlVNzj2hjVLuq2INT2J0BzOXPbvpVjgJZmYcf8POFeDUEfw1
         mGWKGSC+Puyj30VU98AG9bcPiQH/3MwDYU6HyS1qzXbeoaqwmiy54A80j0Q/Ver80+Gd
         cuMW3oplDxUC5VbQiMBSD05YcRJsLh8izAyQPIe/cYWiCHZd3qlCCbgIKijiiZCuZEqh
         xi8PdjDpMyzCMyb3QwlSj8vQSY+ss4hoGbhpk8D0NxQTnw8AqfA+hicd9Wl7SncrMBgJ
         Ot8w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757671968; x=1758276768;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=Oaf0EpzISDaM0qYrtVdR+Q4qGsBV38SIMELmvNLQhzE=;
        b=BZ8cAVpE63oU+hBuOGp2jBqIXMOXmNMll5wbFP4xBJZF8aMQiedG/cG6elr5vTMmnU
         wBE1dyd/sIfAI407KoWewL/t6mLXBCJjK+zGXjTzHO3WgC3XpxHzwJmErmbk0A4VeaRx
         lIo7QS6RJKtlEplNYyULDItTQLscA9DmxzLM0C+IIFx8Gkf/R8ZCP8CWv3//KIATzK+U
         Y3LMPlgDitRNfd9/xcDVz7NLHaGxLH4jQ6zITyScN6P7wmOg0Aqtlo/S3Twu5WISw5T9
         fm/YQ4+b5r1rISHqCuCx3wSbTYvACarZA8CZ4FiCZdczYD7u0z96pWysBwkSZmZF5zW+
         cQIA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWphuWQbW5VN3bAQIWKWA0L6NtbXKFfFvplALIsXRLCFiyOvkgjoYo6s1QbLJjcDl4T1w9sWw==@lfdr.de
X-Gm-Message-State: AOJu0YxWZ+xaatWAyC5C/zHR2n6PfLRR3RtVvdj9ng36SNLXYZglD8um
	b6Ca2NvbDYcNdVJpVldcPVxOxvM599SRVy+phekx7/k25KoTFaTw8zhN
X-Google-Smtp-Source: AGHT+IH6+RDiyQb30s02jEz85CYBPODMjkrxYKPkLYT9+dm9vT4JQRfOdHyeV+YKsoGXiY/d0iCBeA==
X-Received: by 2002:a05:6e02:18c9:b0:420:11bf:d5e with SMTP id e9e14a558f8ab-420cabb6b81mr35900135ab.6.1757671967882;
        Fri, 12 Sep 2025 03:12:47 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfWP9W4FMOgRRvrFNldrN2LSO6jRQU4CxIlsMXOL/t3+w==
Received: by 2002:a92:cd8c:0:b0:3ef:b6a3:cccd with SMTP id e9e14a558f8ab-4167f1f0251ls10917485ab.0.-pod-prod-00-us-canary;
 Fri, 12 Sep 2025 03:12:47 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXe41iu1UY+2NU+99egOdqjGFFvyB1GSoeIL9kLYZCgBvzuBYEkC15HMjUmrWbz4cUtbFsWvZj0Xbo=@googlegroups.com
X-Received: by 2002:a05:6602:641b:b0:88d:e490:52b2 with SMTP id ca18e2360f4ac-890293a98admr439560439f.4.1757671966829;
        Fri, 12 Sep 2025 03:12:46 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1757671966; cv=none;
        d=google.com; s=arc-20240605;
        b=WrofhdBuCkWyzkmgCpnX7hU8VxA7S+gmSv6zVi6N7G6r8vFbAAbFe9olyr6Zwy4i4w
         Rk5ZOlcpTTqEuwl+yDplNl2cvWrizIZuF3xxH7fJOfFnpP11G/8Dnvlk5TMzSBGTG3Az
         wVGZnSianwerlmcprimGFNKqubTglhcLkN8BA3+0qTGVoU5gqJEjBj23xNYtU8sdm3xl
         zKqwYwFPMm1wOdItz+ehqFsFTynsr7Iu1t/epsUFvxsdTjcpxyqXBudQFLjMFIulAQpj
         VxGCmuoiUG62/WUNyBuSK7ly+JsTwZD477kbTqIQMS2iiD3nFClueRPLPhFlakluio7h
         Nz4w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=EqhfZKpOZ5vr6/4baQpnpDghHsngjObwVAr7pMjTC1U=;
        fh=vEAj7WE66o6JWhKKM1wz60RK2Tg7TcxquALJj6+zoJg=;
        b=GP9cVP7DfEuPBendtiuNyTCAhF0IQEd5qjgfKmpcZCzRl3peMzL1W+6Y/qb9tGm3wh
         Jh2nQWnNMlJrJ3UgPqQ2gzbZqQs1HtpSfj2Z5TIUEVxU9mTaoP+9t+Hr/EVBrn/HBiwV
         ckDa9AY4fonWGumQkp9lpfGnwmue9ee5NRbq/mHtQIEJGSbhLpNZN3I2AE5jBGfBnEin
         +g872IYO//5M/NPB5L2wSqI1XKezFaaFMwy3LI8oHyDuvIKogxuCGu0MobbQyXh/HIrQ
         OBDxjJrf4XU0OPJTZqAieUSCLJ6hYQ3QJu8SY80tmToA9ZQGNNbUOq0ilLci86qLCfse
         wFag==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=lobhHoL3;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::536 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pg1-x536.google.com (mail-pg1-x536.google.com. [2607:f8b0:4864:20::536])
        by gmr-mx.google.com with ESMTPS id ca18e2360f4ac-88f2f0f9a8csi19794139f.3.2025.09.12.03.12.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 12 Sep 2025 03:12:46 -0700 (PDT)
Received-SPF: pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::536 as permitted sender) client-ip=2607:f8b0:4864:20::536;
Received: by mail-pg1-x536.google.com with SMTP id 41be03b00d2f7-b54a588ad96so1009995a12.1
        for <kasan-dev@googlegroups.com>; Fri, 12 Sep 2025 03:12:46 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWx/9d8QzAl8HBWQnXNBuoXNw3AlKMDcAYsRJT7dFxy54Vrq5FHPUozHIgYz5R/+wP/u/B4W9ZmIQo=@googlegroups.com
X-Gm-Gg: ASbGnctZcTSSIm14JyRuMnIM2TS9lQQbmgNI3Rx3AfBOhhwvo/Mc9z8Un1i1PRH2MET
	JhKfy83zQW09icQMV43YXXjsZ46vf8WXpGha+cejz/phCiQEhssi+Nhoklu558JFrie/+j35ajo
	F8fLn9p5d096KS3rx1xh6w2AcOaIUkeKXtrbnaCS9ciRBDwIDv3KHV0zpmer8gKSnyYtMgLeEAD
	dgfkNTnR1uHbCiAnehbde2nhPyFxgoWvUaOXjxl+r2IJBBdeF8B9K1ey7GpEuPoth0GAj31WWmN
	k/o+7f8hvu18mT3TsJnivWZ87Rs/lu90SOXaohRKG28/UuDfPcvYC1qj2oRl4dn/EjBqKhViqzB
	VprmKYeHZz1rwXoadztKcdN6EIS8uRB8UIvW3kRA=
X-Received: by 2002:a17:902:e5c5:b0:253:65e4:205f with SMTP id d9443c01a7336-25bab92cc8fmr79198095ad.3.1757671965944;
        Fri, 12 Sep 2025 03:12:45 -0700 (PDT)
Received: from localhost ([185.49.34.62])
        by smtp.gmail.com with ESMTPSA id 41be03b00d2f7-b54a3aa1c54sm4273352a12.50.2025.09.12.03.12.44
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 12 Sep 2025 03:12:45 -0700 (PDT)
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
Subject: [PATCH v4 10/21] sched: add per-task KStackWatch context
Date: Fri, 12 Sep 2025 18:11:20 +0800
Message-ID: <20250912101145.465708-11-wangjinchao600@gmail.com>
X-Mailer: git-send-email 2.43.0
In-Reply-To: <20250912101145.465708-1-wangjinchao600@gmail.com>
References: <20250912101145.465708-1-wangjinchao600@gmail.com>
MIME-Version: 1.0
X-Original-Sender: wangjinchao600@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=lobhHoL3;       spf=pass
 (google.com: domain of wangjinchao600@gmail.com designates
 2607:f8b0:4864:20::536 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
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

Introduce struct kstackwatch_ctx to enable lockless per-task state
tracking.  This is required because KStackWatch operates in NMI context
(via kprobe handler) where traditional locking is unsafe.

Signed-off-by: Jinchao Wang <wangjinchao600@gmail.com>
---
 include/linux/kstackwatch_types.h | 13 +++++++++++++
 include/linux/sched.h             |  5 +++++
 2 files changed, 18 insertions(+)
 create mode 100644 include/linux/kstackwatch_types.h

diff --git a/include/linux/kstackwatch_types.h b/include/linux/kstackwatch_types.h
new file mode 100644
index 000000000000..93855fcc7981
--- /dev/null
+++ b/include/linux/kstackwatch_types.h
@@ -0,0 +1,13 @@
+/* SPDX-License-Identifier: GPL-2.0 */
+#ifndef _LINUX_KSTACK_WATCH_TYPES_H
+#define _LINUX_KSTACK_WATCH_TYPES_H
+#include <linux/types.h>
+
+struct kstackwatch_ctx {
+	ulong watch_addr;
+	u16 watch_len;
+	u16 depth;
+	bool watch_on;
+};
+
+#endif /* _LINUX_KSTACK_WATCH_TYPES_H */
diff --git a/include/linux/sched.h b/include/linux/sched.h
index f8188b833350..1b324b458309 100644
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
+	struct kstackwatch_ctx		kstackwatch_ctx;
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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250912101145.465708-11-wangjinchao600%40gmail.com.
