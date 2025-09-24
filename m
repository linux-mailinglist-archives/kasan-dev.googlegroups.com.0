Return-Path: <kasan-dev+bncBD53XBUFWQDBBZNWZ7DAMGQESWTC7NY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103a.google.com (mail-pj1-x103a.google.com [IPv6:2607:f8b0:4864:20::103a])
	by mail.lfdr.de (Postfix) with ESMTPS id 24D69B99A9D
	for <lists+kasan-dev@lfdr.de>; Wed, 24 Sep 2025 13:52:08 +0200 (CEST)
Received: by mail-pj1-x103a.google.com with SMTP id 98e67ed59e1d1-3306543e5absf944075a91.1
        for <lists+kasan-dev@lfdr.de>; Wed, 24 Sep 2025 04:52:08 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758714726; cv=pass;
        d=google.com; s=arc-20240605;
        b=CWx9hmWSZ9LC7Do1jmo/VnDyIAoXK+Y+0d2drAoRwSPHnnbEONjcAGdxbRKmHAlIwL
         Sr9YlMgWU2DqaI2MEnMRAvRm/7riYxQk7r21aCllyyK0jtOYlMmdizoZnovklRHV61Wa
         PfpfR47i5tj7fsfGIUMVUf5AuKJEA6aapwRPre2Cj6c+dnNccTTpt1jWtMN4QZJQ4CNi
         K7fi8QZu+1GNyzj1TuBBm140HyX73vQ0zEHUEy8JrqsMHbHIcziRNI7cA+TJJKeq0KZh
         0+Wm58bZkuOykGQykrtF6LcWltuB1dR84LH1CGhlJ8WUljyMiScStg6A7uy6g42nQ2so
         2JDg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=eeCvujOgSzJNHGtD38K/m4qsdIAqs/JxkSZO0FPDJkM=;
        fh=78/8lmee9HCJ1E4MVIWw/Xr1bCrCOtSCStBM6itocPQ=;
        b=HExywKxSyYvPSo5HNcesMOP4yzaOPaMVHPt6e0mFtPqNdmrHx67wMIWACRZymeZkYi
         cV9HaEE5Ef8QIqaeOIMuoBOp6A1tk6CcWQ3YYFJ5oL9WxsjFojaKfNtZuGTQLXTKWvvI
         2GxX8h/AGtGYXLaA5bOd7TzBF7QuDVY9w24Nf9LG8H2sO1tR7piGL9eOhJWUn1fEXL0l
         YPNu/nh5aLM8D3Qxwi8FmxVitOD0p1KGnbnBcy2GWK3pLTfdP9WvqcTGWYzvRbJmgd8s
         rHbyYaFnMmJk7Bc6VLk6+FLXQAR4b8CgffvTLnxlx8q9mk3EUUV9rXQc2nYEkuD2gZu5
         /47w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=PVmCkXzi;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::430 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758714726; x=1759319526; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=eeCvujOgSzJNHGtD38K/m4qsdIAqs/JxkSZO0FPDJkM=;
        b=Sym3lfr5r8CCGLwnTs0nJ8+Y4ReXmag/bIgUejT/ozp0PaywMlJHl2Vp1yj98Cw/ZY
         l1MBa/Wbj5TekXcZn7/a4m8Ree43eYlWcLIjd2jc0ixRsubp5zq7dHuGa4CuGUfi6xwB
         Kg6lNvMaI3s+xTg84vKgaFk+QnQjCe0ZsR7MDqoZHD6Vz+Cl59Eher4IGGKORLZpzxft
         Y1EnC9ESnZMY0pRLYUb4ly8Un9t+axhejHP04QUFD1mmA6qAmHSs5LMlDRxv8F8gqdko
         3lwTxB12TgkgC5gpJn9iX7pnDBfAvjH9Ux2F6iovtGFIxXWFqihA6OR6regmiYUUypoj
         mCmA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1758714726; x=1759319526; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=eeCvujOgSzJNHGtD38K/m4qsdIAqs/JxkSZO0FPDJkM=;
        b=Lp5p7e+6iDmPnOsbiWHZKWMrEmrSL3igEJXG8bvn3HjMPwkwswLWCkxMWVijBIf73i
         dvyJIT41AkKXq0iiciT2VrReBjUjEPkEIi0AEiIMG1wB0BrztYUWwGD5dSuVkLrnxRKJ
         vUrxEpXxeDI2SUwQwcBQbgu1zYoGUHLqoJhXoNfi3o52xS6s8ook4fWsuSlSu5lCZ5cB
         4f4GoTgtAB25LKNYUrx3nrW8yhFwsIh3qng/Ss27uPHdkLSIWFaukoF/mZjuTk043aao
         aBpl4/hlDHLQ6+037KamD+159txbYFWrSuwxf2vJc9XQB7JP43vVAIa+QlNOn7/IRRpZ
         9a3Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758714726; x=1759319526;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=eeCvujOgSzJNHGtD38K/m4qsdIAqs/JxkSZO0FPDJkM=;
        b=qEbJDbAyL+QlpleRmESQPGErVDapFPPWCfzn6V23RFA6/txPKrau10O/jkyChUtgOo
         wmAXco75rFgOVOjvMjsz6YF1A6tVw/2NkiNxgJqQDhnO0v2BNpE2fz7lTYpi3OsVXcdF
         gzAdbFWFkd0G/F6qKFHZZUEquqFGjbTRcvPgybkg2RrdCTvsiRUzA08jupOMf2WeC8hk
         D5eQ6ds9QfNtDBhawxmAgoSKe8P+dTU6Bs8kEvASApc03zCDY8DtXWtr2bqFgWezaHw9
         TzCQmcN/294stK22cvMouh1Ll8KdiE8PwdeN7cdFhFIpsPsbjGITXYABRufILJSSMrus
         /9SQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXXqY5VJrD7/3f524mKX0EqihJu9+MZM3rcPGyGePc8O74P9xdAooZ1tnT1dpgi5rgM21GqGw==@lfdr.de
X-Gm-Message-State: AOJu0YxNaEckjCKM0Ddhiiw25KGJflfDMqyizy4CJqAWOmsFmsLROjqm
	TmHpGk7wEV+6T29thU4fvpFSonc6lUUbebr5JiLzsstAzqZo/EL5D6NP
X-Google-Smtp-Source: AGHT+IHuHnlhc/qQxXK2DNzNt0C3sgHm1ZLkcill2aPFoHCDjzQChHQzJuYSx39Uq4y4VZSD0yH2wg==
X-Received: by 2002:a17:90b:4c87:b0:32e:3592:581a with SMTP id 98e67ed59e1d1-3341bfeb8femr2651180a91.17.1758714726033;
        Wed, 24 Sep 2025 04:52:06 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd5/MwDJJSNucf9gYb76pYSMwMls8pRJ+6TpTmmf3LawkQ==
Received: by 2002:a17:90b:1b43:b0:327:f95c:7f6a with SMTP id
 98e67ed59e1d1-33419543b1fls453375a91.2.-pod-prod-00-us; Wed, 24 Sep 2025
 04:52:04 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXbjFq8Uvkw9KX7TOcd9YRgVHw3blEGMNKoo7r8wLsobnK0VojNPoxBzCVVOg5KWHZUrRBh/Xkdud8=@googlegroups.com
X-Received: by 2002:a17:90b:4d0e:b0:32d:e309:8d76 with SMTP id 98e67ed59e1d1-3341bfa919fmr2548360a91.10.1758714724530;
        Wed, 24 Sep 2025 04:52:04 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1758714724; cv=none;
        d=google.com; s=arc-20240605;
        b=BEiEIAL6mt1xH4Jzzlrv1T5HY7t/N0KJ63kb+kYZHuUPBQYQGw7XFuwsEt9NSZgCTh
         Jm4BvPryuX8m3Lb5aXr/t+ck889fRGc5UgJCUPl6Qi45WVZMxl2yf/VXFxTxInL37YzU
         IOpgUlS/aPVWCmFc5cpPpqNjvSpgnxcGGaehGM4IMW3DXT+QPq76/eT0SeINnIZ+QN4U
         9UtG+owY40vPW9tK/K3Y5a5mBFfe7qPz/UZtjiboApdRCp7Ck6CJPr3MmLCLuaL4mr6c
         igMH6HnI0hKUEQl7erydLKvclLbB1bRjnYWJl8MOBqIZx/Zq4r6v+50VOtISgBFzOP9I
         KnSQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=EtGUQc6HOhuSXywhIDZ+AUqHUInlRCKup6JfN/4+ZEc=;
        fh=ePvjIssWQ4YTrbix9SZfKCZIH0p+DxywV49Xr8sQacs=;
        b=KV3L1XzbN5WqqTQO+lsNG7G3vMq7ibAS6IAKPY/My303F+NmpTppVPah89k1l8XuCS
         LgRNqUB4pPwxNfB+R2/HFy6qreXK+5eJGxLNK88pCgGV+zaVlgTWF86WOkl98Zm8RXQR
         weOllKtBWyVqUhnH2f+ag3pB/dJocq/Fghfh6wk0Bs1Zpt6FQG0OTkRXc1BfxRdCWEPU
         c0dtUFM6/Wpm6TtzlhUgFqf0wrIO7x+3oUJ2l2gC1/JI4QfhTwJUCefkfVmLrqrJYjUv
         lTcL6IGqeO6wZCRKeLP2cvnxcYnpgP2EWRtN0hBvZZMkYVALwbasKOoG3S4DqQkRSqWH
         uG5A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=PVmCkXzi;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::430 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pf1-x430.google.com (mail-pf1-x430.google.com. [2607:f8b0:4864:20::430])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-3341bd8966dsi71297a91.3.2025.09.24.04.52.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 24 Sep 2025 04:52:04 -0700 (PDT)
Received-SPF: pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::430 as permitted sender) client-ip=2607:f8b0:4864:20::430;
Received: by mail-pf1-x430.google.com with SMTP id d2e1a72fcca58-76e2ea933b7so951756b3a.1
        for <kasan-dev@googlegroups.com>; Wed, 24 Sep 2025 04:52:04 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXRTqkZffbwl4V0vCn5BePBBryyZahywZyCZqluuPOOvi/r+KwIMnspKiiDkf+7KNBPPQ8lfK1LDr8=@googlegroups.com
X-Gm-Gg: ASbGncuTuk+ZyGa3cNOJaqn+CUia+ALckftgaSowt/v1HBlVHVBb3IPF1jHuh/B2DOB
	5LvFh/GLt5hb3S/FnEDbui9pQT4UEofyLFUFXaNRWWXRSaQOaVmo5Bpw5xklk77t1luwvsifY62
	fJKJhUOUoNfO/5sR3rwcYWQRq5omca1DtgX071y32NvtR4WzC9vlJzXjuRoS9UN9yuj6G51PyjD
	fL2sxUHB37P0jJPF4BYgvzYzvTy+aFeabynIsGkg5zySult+YprGAm9PeqNyEkUMEKnKsvyeCmt
	g6Z64OsLpvGzt0pzxvlAZzD0Ub1hsaFj+LqA4kvu79sEoYREC2ebGeQCVFw8wbSrZRpgZd29rAP
	bLdYf0i/vKYjoiMZNPRAeqr1W8A==
X-Received: by 2002:a05:6a20:5d92:b0:243:78a:82d0 with SMTP id adf61e73a8af0-2de961bb503mr1734537637.29.1758714724015;
        Wed, 24 Sep 2025 04:52:04 -0700 (PDT)
Received: from localhost ([23.142.224.65])
        by smtp.gmail.com with ESMTPSA id d2e1a72fcca58-77f4190cc8dsm7514452b3a.2.2025.09.24.04.52.03
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 24 Sep 2025 04:52:03 -0700 (PDT)
From: Jinchao Wang <wangjinchao600@gmail.com>
To: Andrew Morton <akpm@linux-foundation.org>,
	Masami Hiramatsu <mhiramat@kernel.org>,
	Peter Zijlstra <peterz@infradead.org>,
	Mike Rapoport <rppt@kernel.org>,
	Alexander Potapenko <glider@google.com>,
	Randy Dunlap <rdunlap@infradead.org>,
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
Subject: [PATCH v5 08/23] mm/ksw: Add atomic watchpoint management api
Date: Wed, 24 Sep 2025 19:50:51 +0800
Message-ID: <20250924115124.194940-9-wangjinchao600@gmail.com>
X-Mailer: git-send-email 2.43.0
In-Reply-To: <20250924115124.194940-1-wangjinchao600@gmail.com>
References: <20250924115124.194940-1-wangjinchao600@gmail.com>
MIME-Version: 1.0
X-Original-Sender: wangjinchao600@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=PVmCkXzi;       spf=pass
 (google.com: domain of wangjinchao600@gmail.com designates
 2607:f8b0:4864:20::430 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
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

Add three functions for atomic lifecycle management of watchpoints:
- ksw_watch_get(): Acquires a watchpoint from a llist.
- ksw_watch_on(): Enables the watchpoint on all online CPUs.
- ksw_watch_off(): Disables the watchpoint and returns it to the llist.

For cross-CPU synchronization, updates are propagated using direct
modification on the local CPU and asynchronous IPIs for remote CPUs.

Signed-off-by: Jinchao Wang <wangjinchao600@gmail.com>
---
 mm/kstackwatch/kstackwatch.h |  4 ++
 mm/kstackwatch/watch.c       | 85 +++++++++++++++++++++++++++++++++++-
 2 files changed, 88 insertions(+), 1 deletion(-)

diff --git a/mm/kstackwatch/kstackwatch.h b/mm/kstackwatch/kstackwatch.h
index 4eac1be3b325..850fc2b18a9c 100644
--- a/mm/kstackwatch/kstackwatch.h
+++ b/mm/kstackwatch/kstackwatch.h
@@ -38,11 +38,15 @@ const struct ksw_config *ksw_get_config(void);
 /* watch management */
 struct ksw_watchpoint {
 	struct perf_event *__percpu *event;
+	call_single_data_t __percpu *csd;
 	struct perf_event_attr attr;
 	struct llist_node node; // for atomic watch_on and off
 	struct list_head list; // for cpu online and offline
 };
 int ksw_watch_init(void);
 void ksw_watch_exit(void);
+int ksw_watch_get(struct ksw_watchpoint **out_wp);
+int ksw_watch_on(struct ksw_watchpoint *wp, ulong watch_addr, u16 watch_len);
+int ksw_watch_off(struct ksw_watchpoint *wp);
 
 #endif /* _KSTACKWATCH_H */
diff --git a/mm/kstackwatch/watch.c b/mm/kstackwatch/watch.c
index 1d8e24fede54..887cc13292dc 100644
--- a/mm/kstackwatch/watch.c
+++ b/mm/kstackwatch/watch.c
@@ -31,11 +31,83 @@ static void ksw_watch_handler(struct perf_event *bp,
 		panic("Stack corruption detected");
 }
 
+static void ksw_watch_on_local_cpu(void *info)
+{
+	struct ksw_watchpoint *wp = info;
+	struct perf_event *bp;
+	ulong flags;
+	int cpu;
+	int ret;
+
+	local_irq_save(flags);
+	cpu = raw_smp_processor_id();
+	bp = per_cpu(*wp->event, cpu);
+	if (!bp) {
+		local_irq_restore(flags);
+		return;
+	}
+
+	ret = modify_wide_hw_breakpoint_local(bp, &wp->attr);
+	local_irq_restore(flags);
+	WARN(ret, "fail to reinstall HWBP on CPU%d ret %d", cpu, ret);
+}
+
+static void ksw_watch_update(struct ksw_watchpoint *wp, ulong addr, u16 len)
+{
+	call_single_data_t *csd;
+	int cur_cpu;
+	int cpu;
+
+	wp->attr.bp_addr = addr;
+	wp->attr.bp_len = len;
+
+	cur_cpu = raw_smp_processor_id();
+	for_each_online_cpu(cpu) {
+		/* remote cpu first */
+		if (cpu == cur_cpu)
+			continue;
+		csd = per_cpu_ptr(wp->csd, cpu);
+		smp_call_function_single_async(cpu, csd);
+	}
+	ksw_watch_on_local_cpu(wp);
+}
+
+int ksw_watch_get(struct ksw_watchpoint **out_wp)
+{
+	struct ksw_watchpoint *wp;
+	struct llist_node *node;
+
+	node = llist_del_first(&free_wp_list);
+	if (!node)
+		return -EBUSY;
+
+	wp = llist_entry(node, struct ksw_watchpoint, node);
+	WARN_ON_ONCE(wp->attr.bp_addr != (u64)&holder);
+
+	*out_wp = wp;
+	return 0;
+}
+int ksw_watch_on(struct ksw_watchpoint *wp, ulong watch_addr, u16 watch_len)
+{
+	ksw_watch_update(wp, watch_addr, watch_len);
+	return 0;
+}
+
+int ksw_watch_off(struct ksw_watchpoint *wp)
+{
+	WARN_ON_ONCE(wp->attr.bp_addr == (u64)&holder);
+	ksw_watch_update(wp, (ulong)&holder, sizeof(ulong));
+	llist_add(&wp->node, &free_wp_list);
+	return 0;
+}
+
 static int ksw_watch_alloc(void)
 {
 	int max_watch = ksw_get_config()->max_watch;
 	struct ksw_watchpoint *wp;
+	call_single_data_t *csd;
 	int success = 0;
+	int cpu;
 	int ret;
 
 	init_llist_head(&free_wp_list);
@@ -45,6 +117,16 @@ static int ksw_watch_alloc(void)
 		wp = kzalloc(sizeof(*wp), GFP_KERNEL);
 		if (!wp)
 			return success > 0 ? success : -EINVAL;
+		wp->csd = alloc_percpu(call_single_data_t);
+		if (!wp->csd) {
+			kfree(wp);
+			return success > 0 ? success : -EINVAL;
+		}
+
+		for_each_possible_cpu(cpu) {
+			csd = per_cpu_ptr(wp->csd, cpu);
+			INIT_CSD(csd, ksw_watch_on_local_cpu, wp);
+		}
 
 		hw_breakpoint_init(&wp->attr);
 		wp->attr.bp_addr = (ulong)&holder;
@@ -54,6 +136,7 @@ static int ksw_watch_alloc(void)
 							ksw_watch_handler, wp);
 		if (IS_ERR((void *)wp->event)) {
 			ret = PTR_ERR((void *)wp->event);
+			free_percpu(wp->csd);
 			kfree(wp);
 			return success > 0 ? success : ret;
 		}
@@ -75,6 +158,7 @@ static void ksw_watch_free(void)
 	list_for_each_entry_safe(wp, tmp, &all_wp_list, list) {
 		list_del(&wp->list);
 		unregister_wide_hw_breakpoint(wp->event);
+		free_percpu(wp->csd);
 		kfree(wp);
 	}
 	mutex_unlock(&all_wp_mutex);
@@ -88,7 +172,6 @@ int ksw_watch_init(void)
 	if (ret <= 0)
 		return -EBUSY;
 
-
 	return 0;
 }
 
-- 
2.43.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250924115124.194940-9-wangjinchao600%40gmail.com.
