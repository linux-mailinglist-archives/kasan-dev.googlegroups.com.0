Return-Path: <kasan-dev+bncBD53XBUFWQDBBKMI5XDAMGQEGRMBL6A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1038.google.com (mail-pj1-x1038.google.com [IPv6:2607:f8b0:4864:20::1038])
	by mail.lfdr.de (Postfix) with ESMTPS id 1270BBAB0B7
	for <lists+kasan-dev@lfdr.de>; Tue, 30 Sep 2025 04:45:00 +0200 (CEST)
Received: by mail-pj1-x1038.google.com with SMTP id 98e67ed59e1d1-330a4d5c4efsf5011539a91.0
        for <lists+kasan-dev@lfdr.de>; Mon, 29 Sep 2025 19:44:59 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1759200298; cv=pass;
        d=google.com; s=arc-20240605;
        b=bwahB579NCB3PHNbt/nuQGAVROZPpU7mtJj7MT38JtSz+EHSBUC32kFC2bJRWz0buC
         D/uCNCcg0SnzhN2cJUnDVSBtx/MRPbMdARGCQSAWYHk/2Mn2mq3Ik5gNAScnKP8VxWUd
         9QFv6Z9SfGutEQtsR3/P8VyEny4uz8cuOxtN3KWG/3dtrE60Gj3Jcb4tlDmE+btXsi+J
         uLiMMWTAJTOTnDaNmzah3kQWgdhtonxQnXeaAwe4+UFBbokTAgs8GOuUbtEGQ52NZF/7
         AU6Rn3rWQ2KFy6GOFfgjpj7W8iR+dbiwCHkUHSry+RS353M7thcNs61z2LGHQehxb9kn
         272g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=mHKCnK5Z0NOymXYvlFxKQQyYGApffj91VwGCGGsAkQ8=;
        fh=XRM51ARrdts32fXgbQO8TPZKbuI8N54GvSgqnzvq6iM=;
        b=FVg/BGSlmu68SbCx74km1TFSJGTao/aiXOi5DP4xEbhQi3ZHnuJfT0R3o34jrxQ+ET
         AqK3vPwKUoDmrxAfDUGzTIwUO+nAGyPOCZ85YsZWx3wPnRa8FP9W0aTao8gBmC1ConnR
         g8Xk9z0Uu3tdICSR4mV1a00S7c+y72h9O5MK7Ea8vX9nPpqsnoYOXb6xpHdPI/bhy54K
         p417q4irjxdU1lZF2QKowSpgfXjCu9oC265IBxneMIh/XgtKcJQQ2+Sk/x2NX0T0k0i9
         y+Q4OdZiFus9HYPfCI4/Qz6tMvoB6HipEqkmBy3IEw12ki9AATzNIFs+aRIxmsJLtS39
         7PRg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=E4dHQuHi;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::62d as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1759200298; x=1759805098; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=mHKCnK5Z0NOymXYvlFxKQQyYGApffj91VwGCGGsAkQ8=;
        b=aELikgxFSU5BpkxLwpt4G0a5CqfmypZ7MtQ2SmMjxTbf/Ei00HCFZSplRQKyXjxQbR
         zfTSK9iKESvktD+JdYFCyIPtS8kI8qtP/ZUgO2BZTEk01yKZgWDalRcNNKj1CF8X8lz1
         BnMVC0LBFSe3SDUsotcuFi5fo2usKnDvgRBXt6ARTFj/T2rMEHWBIPze3b+EXAYba/Al
         rFoescQw2mPIdNJvITyKnvC2zD9OGr/n1W0jb8QSZMNU+TyduKuyzfF/4Est6pG45MCv
         grwgEQwKKMBmAzF+YddKrIwS39eRW98gvF8tN7XXBZCzhxho5892G99noEhZ/Ae3Wmi0
         +Uwg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1759200298; x=1759805098; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=mHKCnK5Z0NOymXYvlFxKQQyYGApffj91VwGCGGsAkQ8=;
        b=KLTMV0xse7EadYBQJMZ+Mv3AJEiEkcxyrcjzsmRzdlgip7uqNA+ZcFh6pjfTEuU3bZ
         MyGaV8WSVyMfWugpC0seJcn7giSqJ4rCjJ68i1ZpzJvHENHap3a7PTWuQ3GgLfhWvzuM
         yU63Xjy9RoGRCzxQ3RkL5mqjh5bmN/sL+s1EzBes4FdFqVKlm+ZZ6ugY9jFojZdOvjOn
         edjjgSmvg/aB/4pSxcHpm8QOYSmd4EHn6NNfEZz0PBTlSMwp2cVY93QqlWmO6Rx4/HOj
         9fwb7hVHSINKBwk7/tPdKSygBBLiX72y3KTpitanjRK2iRN4Acwuk16gsPB6zh2V7oeo
         VpHA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1759200298; x=1759805098;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=mHKCnK5Z0NOymXYvlFxKQQyYGApffj91VwGCGGsAkQ8=;
        b=EuPXxLGz92DvIRu0r9FuqeMOELnCMXG3flrA7ayd/YW8r0e0gFsOuL9ARDfcf7xZ4Z
         6yFHaIP0lL4iJjCH9Jq3Ens34HdQzdDt/0ovdmiyDQoQL7CZHLxO45ZdKhytoS4YgQf0
         e2NkUNSQT7c+rh3VKuwyObf24eJoZZxvKwsjZihWljU29l22cUF3JE4CBWSVRgGW4w5Q
         cKi9CrskxQNcB7KLybKmrtISbVoVOq4gcEGs4GB5pwir47YNr5lNYi1E7S7xtLERNc9O
         C4wtp204a4+yQz+cUPa1SHmS8Zp3PUjiherM+yBVjmd/AoE3yTCFpn5UO5Ofb1VUF4mi
         T2vQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXXw2sirONWcYSkAfGxS5BA19Ak4J/cPJgTKn4KuWGhOXBipBpJXl/WJ1HExPoLDl88o0oBzA==@lfdr.de
X-Gm-Message-State: AOJu0YxHiemq9AuxU3gYfRpweVAWaGYc43wD3Y9Gufy2GiGBXkMSNsKp
	CiLWZXe8H075bmWbxwqlxZL0j8DmQDODe10Wp0DtCiTo2FdP6S5AZ77s
X-Google-Smtp-Source: AGHT+IH3GEve/7WczcGZsGKtCGIfcyUrao8ftGmOgMrUzIXkwn+LnX1Hz494siKxR2syNZqPg1g2gQ==
X-Received: by 2002:a17:90b:3147:b0:32e:6019:5d19 with SMTP id 98e67ed59e1d1-3342a3004e5mr18709239a91.34.1759200298056;
        Mon, 29 Sep 2025 19:44:58 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="ARHlJd7kJ38PlD7yb7VYTI8905Q4gLR0BjgkXfaXcsqhK/aiCA=="
Received: by 2002:a17:90a:701:b0:327:e760:af15 with SMTP id
 98e67ed59e1d1-3342a4504b5ls3962983a91.0.-pod-prod-04-us; Mon, 29 Sep 2025
 19:44:56 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUdslXXJ4ziUx5EzkRyHZpXtmN3TJplDXbcI3qDqu/kTqg9sy0r5g8TmHMyYpks3bLDrkPpbiccnSI=@googlegroups.com
X-Received: by 2002:a17:90b:3ec9:b0:330:bca5:13d9 with SMTP id 98e67ed59e1d1-3342a2ed8f8mr16387112a91.32.1759200296683;
        Mon, 29 Sep 2025 19:44:56 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1759200296; cv=none;
        d=google.com; s=arc-20240605;
        b=GxlcifjKFVatk5Cr30FMWPmluHp1rlF7b93g98zvmQl4HFXg3/q8YBMcZldN/BTePZ
         OqfrC1dk7vRFUqoTIVOuEU4NzAZgc2JCbGyHOYeovaja9Cb8gy39Zk58DrYNfgEZw460
         ZiiXK+iH3uXs41Ym/vnTeyjPgodWBWQhnb+Z0c7/pG8z94edfaPq6Kq5TFkTZQ7a/SHB
         IhbSi2SBar5emQ7VNDRI6ugEMflyzLiHPHitbY16Y0Of3VetJ48dM+wbNVB+gIJBV3yR
         A7iy4cGySkMR4gMZUK3qSq9db4QTPEjlgP1Ku3CHqIhIs5nhmjXZC4RpHrrjSCm2dfWM
         bVAw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=5NW3rnfkFZjd7Zh69vJKiLybxjQ5f/0P49rVAWgM4UU=;
        fh=+g/JfbmKvTGNkHxBJSfhZnNAV/I8OBuUt90Hn+in0ao=;
        b=WjDXOrqsEw9JAkUOlhXMF/8t1GHU0Zi9utiwR1GE7JYBQeES7VGV/ODDdYF7RoLk8s
         /E6rDWCToukAYbxUb9Wp5iZTWJ+R6W1Gu9oS72OXykKoXf2wvO1vVpd4fdTv/3LB+Hn6
         lWDaNgNNdNfcFH6Ck38xwR/bq0Ue2uC+bluuHDL8Ft51AGptB4VJ8QNq3ASrKX5SXqjO
         10ngSbGWNJoH2UBS9y5Alc8/RG0YNjUWHxUq6Kooqd0PR6I4IcXpA0OKawdNxxLN+XAf
         nNPPug59nkQqeN9R7yti71EgK88YNaEwubypllBKCrnXGD1SQV/K4ouDk7TDqBnwis9O
         fmOg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=E4dHQuHi;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::62d as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pl1-x62d.google.com (mail-pl1-x62d.google.com. [2607:f8b0:4864:20::62d])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-3399cc8452esi11708a91.1.2025.09.29.19.44.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 29 Sep 2025 19:44:56 -0700 (PDT)
Received-SPF: pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::62d as permitted sender) client-ip=2607:f8b0:4864:20::62d;
Received: by mail-pl1-x62d.google.com with SMTP id d9443c01a7336-27d3540a43fso59869765ad.3
        for <kasan-dev@googlegroups.com>; Mon, 29 Sep 2025 19:44:56 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUV00L4+ocjcq2N7YBdyA/RDXw2HoM5HK227EXgXKFeRS7iunM89Sygot51ZeRpSVtK6SP/gET4Wvc=@googlegroups.com
X-Gm-Gg: ASbGnct2i34IHiO7uh2YZHf75W+0Grw7dL74pbCw70CVEnG4zgCq6w6EzHM2QUQ8fNH
	4KTJHVfCvIPiRc4ccDBIpA52Sr/7mjeGDSdrAyI1WdRMh/uJjix06WdKeITNTQkOH9OKEQlL7K1
	tpO+pkskYyrZkR9gngRoIPdC79GerUw51QkRY0yT8x3C6h+WLxHoIYiAmhWDxl301Ush3uLrvUe
	ey9hSW/B01Q1OMWN2RNwtf4VTjQzQAdX4oU2V6Pi8d3fvNoRBPDkrF7z5VdwAFIHcwnvbrQb3Pc
	TobjwCaUKOoZ+e/6+e1bFYxl0QMRg5Ghu326RilIYeAYogWXtX6L/N+AktduEiLhasoxVwgId31
	YvvVd1EflX5uvQcRuIW6egJxjG+uCFaTbpbFziBLP0z//v86AGOEpDPPF9Fn+mpPvyQ==
X-Received: by 2002:a17:902:e54a:b0:270:b6d5:f001 with SMTP id d9443c01a7336-27ed4a0d542mr209110885ad.23.1759200295846;
        Mon, 29 Sep 2025 19:44:55 -0700 (PDT)
Received: from localhost ([45.142.167.196])
        by smtp.gmail.com with ESMTPSA id d9443c01a7336-27ed69952b3sm145098075ad.96.2025.09.29.19.44.55
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 29 Sep 2025 19:44:55 -0700 (PDT)
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
Subject: [PATCH v6 07/23] mm/ksw: add HWBP pre-allocation
Date: Tue, 30 Sep 2025 10:43:28 +0800
Message-ID: <20250930024402.1043776-8-wangjinchao600@gmail.com>
X-Mailer: git-send-email 2.43.0
In-Reply-To: <20250930024402.1043776-1-wangjinchao600@gmail.com>
References: <20250930024402.1043776-1-wangjinchao600@gmail.com>
MIME-Version: 1.0
X-Original-Sender: wangjinchao600@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=E4dHQuHi;       spf=pass
 (google.com: domain of wangjinchao600@gmail.com designates
 2607:f8b0:4864:20::62d as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
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

Pre-allocate per-CPU hardware breakpoints at init with a place holder
address, which will be retargeted dynamically in kprobe handler.
This avoids allocation in atomic context.

At most max_watch breakpoints are allocated (0 means no limit).

Signed-off-by: Jinchao Wang <wangjinchao600@gmail.com>
---
 mm/kstackwatch/kstackwatch.h | 13 +++++
 mm/kstackwatch/watch.c       | 97 ++++++++++++++++++++++++++++++++++++
 2 files changed, 110 insertions(+)

diff --git a/mm/kstackwatch/kstackwatch.h b/mm/kstackwatch/kstackwatch.h
index 983125d5cf18..4eac1be3b325 100644
--- a/mm/kstackwatch/kstackwatch.h
+++ b/mm/kstackwatch/kstackwatch.h
@@ -2,6 +2,9 @@
 #ifndef _KSTACKWATCH_H
 #define _KSTACKWATCH_H
 
+#include <linux/llist.h>
+#include <linux/percpu.h>
+#include <linux/perf_event.h>
 #include <linux/types.h>
 
 #define MAX_CONFIG_STR_LEN 128
@@ -32,4 +35,14 @@ struct ksw_config {
 // singleton, only modified in kernel.c
 const struct ksw_config *ksw_get_config(void);
 
+/* watch management */
+struct ksw_watchpoint {
+	struct perf_event *__percpu *event;
+	struct perf_event_attr attr;
+	struct llist_node node; // for atomic watch_on and off
+	struct list_head list; // for cpu online and offline
+};
+int ksw_watch_init(void);
+void ksw_watch_exit(void);
+
 #endif /* _KSTACKWATCH_H */
diff --git a/mm/kstackwatch/watch.c b/mm/kstackwatch/watch.c
index cec594032515..1d8e24fede54 100644
--- a/mm/kstackwatch/watch.c
+++ b/mm/kstackwatch/watch.c
@@ -1 +1,98 @@
 // SPDX-License-Identifier: GPL-2.0
+#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
+
+#include <linux/cpuhotplug.h>
+#include <linux/hw_breakpoint.h>
+#include <linux/irqflags.h>
+#include <linux/mutex.h>
+#include <linux/printk.h>
+
+#include "kstackwatch.h"
+
+static LLIST_HEAD(free_wp_list);
+static LIST_HEAD(all_wp_list);
+static DEFINE_MUTEX(all_wp_mutex);
+
+static ulong holder;
+bool panic_on_catch;
+module_param(panic_on_catch, bool, 0644);
+MODULE_PARM_DESC(panic_on_catch, "panic immediately on corruption catch");
+
+static void ksw_watch_handler(struct perf_event *bp,
+			      struct perf_sample_data *data,
+			      struct pt_regs *regs)
+{
+	pr_err("========== KStackWatch: Caught stack corruption =======\n");
+	pr_err("config %s\n", ksw_get_config()->user_input);
+	dump_stack();
+	pr_err("=================== KStackWatch End ===================\n");
+
+	if (panic_on_catch)
+		panic("Stack corruption detected");
+}
+
+static int ksw_watch_alloc(void)
+{
+	int max_watch = ksw_get_config()->max_watch;
+	struct ksw_watchpoint *wp;
+	int success = 0;
+	int ret;
+
+	init_llist_head(&free_wp_list);
+
+	//max_watch=0 means at most
+	while (!max_watch || success < max_watch) {
+		wp = kzalloc(sizeof(*wp), GFP_KERNEL);
+		if (!wp)
+			return success > 0 ? success : -EINVAL;
+
+		hw_breakpoint_init(&wp->attr);
+		wp->attr.bp_addr = (ulong)&holder;
+		wp->attr.bp_len = sizeof(ulong);
+		wp->attr.bp_type = HW_BREAKPOINT_W;
+		wp->event = register_wide_hw_breakpoint(&wp->attr,
+							ksw_watch_handler, wp);
+		if (IS_ERR((void *)wp->event)) {
+			ret = PTR_ERR((void *)wp->event);
+			kfree(wp);
+			return success > 0 ? success : ret;
+		}
+		llist_add(&wp->node, &free_wp_list);
+		mutex_lock(&all_wp_mutex);
+		list_add(&wp->list, &all_wp_list);
+		mutex_unlock(&all_wp_mutex);
+		success++;
+	}
+
+	return success;
+}
+
+static void ksw_watch_free(void)
+{
+	struct ksw_watchpoint *wp, *tmp;
+
+	mutex_lock(&all_wp_mutex);
+	list_for_each_entry_safe(wp, tmp, &all_wp_list, list) {
+		list_del(&wp->list);
+		unregister_wide_hw_breakpoint(wp->event);
+		kfree(wp);
+	}
+	mutex_unlock(&all_wp_mutex);
+}
+
+int ksw_watch_init(void)
+{
+	int ret;
+
+	ret = ksw_watch_alloc();
+	if (ret <= 0)
+		return -EBUSY;
+
+
+	return 0;
+}
+
+void ksw_watch_exit(void)
+{
+	ksw_watch_free();
+}
-- 
2.43.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250930024402.1043776-8-wangjinchao600%40gmail.com.
