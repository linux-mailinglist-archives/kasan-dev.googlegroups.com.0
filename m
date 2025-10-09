Return-Path: <kasan-dev+bncBD53XBUFWQDBBIFKT3DQMGQEAQQNYWY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13f.google.com (mail-il1-x13f.google.com [IPv6:2607:f8b0:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id A5F43BC89F9
	for <lists+kasan-dev@lfdr.de>; Thu, 09 Oct 2025 12:57:38 +0200 (CEST)
Received: by mail-il1-x13f.google.com with SMTP id e9e14a558f8ab-42f6e42c844sf34876455ab.2
        for <lists+kasan-dev@lfdr.de>; Thu, 09 Oct 2025 03:57:38 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1760007457; cv=pass;
        d=google.com; s=arc-20240605;
        b=etHEczY50jUiwF5uxyZy2X6uJWm8OhN5d60fgqFI4zTofxUeSdfEyjR0FkyNXJXik7
         B+4IKirf/rEbSnm3eE5u6gQQNdDvMoVXpm0SjB/w/451uANFkj6iSrSBTdCBSJzRm3Gk
         CfBapnAlg+1RNG4E2aLrlrMSVxt46ROTWQF5+uBdnczu5pwrs2q1vZji2oFQGrbglcM2
         gSmat6bBeWwMKN2/TeajKulljT67sQPzRbEtLmsb/n9WLTjim3yoUShO/qKRy566xLeE
         3DkSsmO8V2A04e+uZaO8GCshz3+ouwrSKOYbc3VDVK31xNb1MOGzLwxylo5CYP7s6Htb
         CH0g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=NmXfkTqLfOkIfB/sGSG9H/TG+E3Ku6M5+jVjlDJV5Dg=;
        fh=PpiJ9+JCcskXu/nVRgfmbKxGb4tLrWFLat51Yr+w/TE=;
        b=NwV5BNM/WdUJ2AjRHlPNYfb8SzNpQ/jwVFJs3lNepC5hzH/0vUZBPtU2gQhi1CcC9M
         cwiGpKoOizHJa/pp9ONK9Cg1i+augV5W/JbbCvB4jvYJOWdF7Zbt9qnrAowTVqfFYmFP
         kvdwMSbEGw+NBL0w5nrzxUkxVv6IF7euA6K21wIwm2s/s/oAOlx/hJmFeHRgK2q+DXwv
         aYO2uK1sC7/T3iBqMal07q+JTA8cyJXYUurcw4bRCAHvPr6l5I6n2dRyLzj7ahVLsg7y
         6q0sH/5V7azUHN7obe0LgUw+lS7L5E8CC9M78bl7cWC6O4kuRuSCS5AnFdkAAAd9uB4K
         kQBA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=Wvgrg+r+;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::1036 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1760007457; x=1760612257; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=NmXfkTqLfOkIfB/sGSG9H/TG+E3Ku6M5+jVjlDJV5Dg=;
        b=kyAEoc2ftSB6drMna5YWm5lSwKmplTI8E0X5BT27l2uj5NRIQuOTH6cmY2c9ryegi7
         4uOe64llTRvgABX30FWrqaDlqXICkckX+tT0vxv1tWTrpuuqFB4Nnlg7uPKcjhazgAFj
         3rXE53P4W+xNco4bFPJGOAduIPpNCvxnmX9qmQS7PRElnifuwrcftaXKyyyQKcehojkX
         oUZYgRkWMWYkbe2M02RsKZ5uFApOQ5nP/1NLutK09K8XZCVC1wH9U/rfHpBlsPGw1lMi
         8kF/GG+UCbWK/NKM09UdRaIUJitxcBKqTDkMGduQSKSrO5TVTGcX8kTQ5/Tk5HKr8IsO
         Fs2w==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1760007457; x=1760612257; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=NmXfkTqLfOkIfB/sGSG9H/TG+E3Ku6M5+jVjlDJV5Dg=;
        b=jZnW1soI84Hx+KkCiqEpqf8VrYJLsy84ZVBeRysYtP6zHGCOMzwP7H43BNO+VbH6ks
         QBu++r/c8JT/CDzTOzncqnVpMNdjLQV9MzatVaqAj9ttyKa3rF5w8y/5A2q8/GlU78Pu
         x/iaoOYcMVH3/YaLnhq0NmPshpLY9FC29cmjfo43ZFUkJxJGsSiwTdxHNtOn+v5vB5gL
         TCGaEgnu3ovgsvf5+G6EYtAyZczPRDJ5DtaD43nPc0L8nu8XAPTZ5Yy70xPgScvZ5eeQ
         w+Iy/nrKl9P+PX7JUYQIwSJdA3JY1QRy4cYdK3BHY8ZwMQqjsh1jFugqgZfOxJYmAwXH
         FgFg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1760007457; x=1760612257;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=NmXfkTqLfOkIfB/sGSG9H/TG+E3Ku6M5+jVjlDJV5Dg=;
        b=Vn7ZSNtsE4SFZVhMce63GFz9cwVKE8Sj1kinDarABaxvQSnQJ2ZbYoVmnBspwIKU33
         uhqVuKbQmPa0dGMvemOkMyIHzh/wDfwwuMlrq5BpQdsaXvB89D6czFzNKCbMHQHxfiRV
         m4TKCTZuwtoqWmztXao3bmXqc5ZBmp40CXaymRVSpKYmtMb9qKLtJHabzQXFsdz9quO1
         d8LqUXwIi4bkFbE3ldUpiWj7unG0kCY5xs1xs3O/WBeh1Egy+g7NtCrIV/fzRpUaFs9V
         BZwuSWWySXPOcHiBK15ayw2fxmXCaF9L09a2gObq5PbKkncoIk1DqYRgjZ4B66caD2+S
         KYJQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUg1R50TQDpMa+pslVy6NOBBD5hyt79Mrjuw51o4VrAo0LHf2cc5EABN1tSsLbwMYOAgRqdeQ==@lfdr.de
X-Gm-Message-State: AOJu0YxNeI8WP9VWZX9FrPDrJ/cBtBJdfEh0zZk7+cr/lMXK5pop3rGR
	57WH0VCdCDLSF30Oj03GiRoZ0KCFckLSs0KejcEtnSogzXBI2CBdxXcM
X-Google-Smtp-Source: AGHT+IGqX3ZrwPH/19AcL+E6QF9z3ICGZoAZ9v8ljhzkXBKU+nTXJXLfRDj0E3G8FK/tKzEWL40IQg==
X-Received: by 2002:a05:6e02:1528:b0:42d:84ec:b5e5 with SMTP id e9e14a558f8ab-42f873504a2mr72550085ab.3.1760007457223;
        Thu, 09 Oct 2025 03:57:37 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="ARHlJd65lCTk2vGgFBBhAi4psEzXGRrYnlhOra6HYesFjacE7w=="
Received: by 2002:a92:d6d0:0:b0:42f:2c8d:eb0a with SMTP id e9e14a558f8ab-42f909a98d4ls6096465ab.0.-pod-prod-01-us;
 Thu, 09 Oct 2025 03:57:36 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCV/wfjJV+BKkTyfLJkqPtwpxC/g9QsWEztPmZQYCWLYtOo3bXwV7RXEFX0dA11wOFHbG4mQoWl8mFU=@googlegroups.com
X-Received: by 2002:a05:6e02:440f:10b0:42f:8e51:88e9 with SMTP id e9e14a558f8ab-42f8e518dfcmr37912005ab.2.1760007456083;
        Thu, 09 Oct 2025 03:57:36 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1760007456; cv=none;
        d=google.com; s=arc-20240605;
        b=jfKwB/dtxVC3oBYB6JImRu3rBZKppwZ8JPzvDhyqvej28AMeT97XV7tg32ZxIRVYc7
         4o4ah5cRvFIXjCDH3p4DgS7zOvtAZp3+zAi2qTtq934uuMGHqGvXUJ8mOJNMOB6AXn07
         7K0JkpwAr7LfdCAZA325uJH9PbCtwqqUggIPmls+EPU9UIIxIilTNCTOOKiaIKfNrsZV
         6HGWwN7l1+MDeC0QMZLvSgvyKX2nOxb2m+ezvB7IEVW7a4xNJEdPLzTQLXMhGZVhAecJ
         4Zg+N8F/09m+T5TwoIYgLPk6XUq94zbnDGOEmutYeuM2UfIWk6uVhForqZDfujmGHQ68
         bobQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=5NW3rnfkFZjd7Zh69vJKiLybxjQ5f/0P49rVAWgM4UU=;
        fh=EpiQfp46Y6dxtOqtkc2wqgwDsQwQk+SztJSyAX51fvA=;
        b=ft9vpK9nq+wPjoLbIfvcqlJO3KEYGssbpIbr1qUJ6dscc9WerLM2ltU5Ur99pgeYxe
         NHnAo8vgZhs/f6w4Wm0WdvoUNIRkUoKuePsbLdwnv7bYvBur7Cg/p7vXtot6vseOANKg
         NCpZwhyQDkn7bPDCiTnPYfDihgGnuhbzfyRF8TfG7jR7PodMRujyXkvFQCHY1L3wE0OP
         BfSLmVKMIsAdRtdIhYylZm18qYIbpKylEbmRXqYyg0n97MAUbQcm620RV9tXA8fwzNpp
         zyJz44Y56x5rnqjuIrcmdGqiAiznL0hDE2+gvGB1MEXvCgqTkFWncFRs1WLRkAZvH29E
         6Faw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=Wvgrg+r+;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::1036 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pj1-x1036.google.com (mail-pj1-x1036.google.com. [2607:f8b0:4864:20::1036])
        by gmr-mx.google.com with ESMTPS id 8926c6da1cb9f-57b5e9e6325si854097173.1.2025.10.09.03.57.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 09 Oct 2025 03:57:36 -0700 (PDT)
Received-SPF: pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::1036 as permitted sender) client-ip=2607:f8b0:4864:20::1036;
Received: by mail-pj1-x1036.google.com with SMTP id 98e67ed59e1d1-33082aed31dso923343a91.3
        for <kasan-dev@googlegroups.com>; Thu, 09 Oct 2025 03:57:36 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVyU0YhvxW8LJazOhqnyO/tj6SEFJAQYSl8mNeqio+BPAAd2CIYP7iPcvSKMPAov72aycQ9cPdVUy8=@googlegroups.com
X-Gm-Gg: ASbGncsQLWF8UVLq3BRLAg8KIz2cDZBvwfhT14av4FOoyLfGCtxFfyKbzZ0x77fHAsn
	gWNjXVdReTqnncqIsfExEmcQPcSS0H29ruemE9ZNme0iRmwgnyXRGm1Sy+UlO+zwONMw1i5ntoW
	FxdlQxGEN48GM2GXLOzm4Ye5nf/95BRVucru0kGRKW14Wv9stVreb2FPUQd9vxLk0e7gAdPUSfN
	EvWf2Z3mkPBPI5a2Ajh4C3PbYnB2crAScLsNfvBp2BvRHtoHgM2pA0tH3283FSFeBOpONoc1hdX
	uRWI+JbozemPd0WTFCmTlQYh2hk+HJZm6I60qiG0fVWQAFMdsFnh7j+s/t3DXwBWGbhpepYqTUS
	yMst2vRrlhn1KYyuepRN/biCjIQkUw8XxrJHn/mJWMcvN4JUg/tAq/W2FC1/Q
X-Received: by 2002:a17:90b:2249:b0:32b:cafc:e339 with SMTP id 98e67ed59e1d1-33b5139c4f4mr8493028a91.36.1760007455151;
        Thu, 09 Oct 2025 03:57:35 -0700 (PDT)
Received: from localhost ([45.142.165.62])
        by smtp.gmail.com with ESMTPSA id 98e67ed59e1d1-33b510fc5e6sm6727834a91.6.2025.10.09.03.57.34
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 09 Oct 2025 03:57:34 -0700 (PDT)
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
Subject: [PATCH v7 07/23] mm/ksw: add HWBP pre-allocation
Date: Thu,  9 Oct 2025 18:55:43 +0800
Message-ID: <20251009105650.168917-8-wangjinchao600@gmail.com>
X-Mailer: git-send-email 2.43.0
In-Reply-To: <20251009105650.168917-1-wangjinchao600@gmail.com>
References: <20251009105650.168917-1-wangjinchao600@gmail.com>
MIME-Version: 1.0
X-Original-Sender: wangjinchao600@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=Wvgrg+r+;       spf=pass
 (google.com: domain of wangjinchao600@gmail.com designates
 2607:f8b0:4864:20::1036 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251009105650.168917-8-wangjinchao600%40gmail.com.
