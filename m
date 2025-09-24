Return-Path: <kasan-dev+bncBD53XBUFWQDBBUF2Z7DAMGQEVSVQRXY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13e.google.com (mail-il1-x13e.google.com [IPv6:2607:f8b0:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id B681EB99B61
	for <lists+kasan-dev@lfdr.de>; Wed, 24 Sep 2025 14:00:18 +0200 (CEST)
Received: by mail-il1-x13e.google.com with SMTP id e9e14a558f8ab-4257ba85609sf52720195ab.2
        for <lists+kasan-dev@lfdr.de>; Wed, 24 Sep 2025 05:00:18 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758715217; cv=pass;
        d=google.com; s=arc-20240605;
        b=Mi1/iylwzIIuSR293A/nnEnY7zICAC0l/5SCIgVgUREJq6m4TSNi4XQAnTSvdErsZ/
         BANlMCtN6hMzhDlxNU7Do15466LpR7wBdlaIUG4lExQtdmORBVYAtYxpwK+k7Mlc73ug
         +fe0PVN52lgWGdHKrz2zyI6Q0ItnkY9G363DQRtKHiX1j2Nx/CdQvyqKU6fZkDfnZ7jf
         W+TWlE0MN2mE1nFV7jIN67+OrY5uJO66U7NW40oBURFLpgiK5Aa7SdAI5hL0xLYPfGMC
         rI8p8FTRsb5tQi5BBXLT1e+3jycRkUSA7mJcmT46wAtznFFO4lg5OmUsbgQDR/YuigEU
         arHQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=DNA1n5oQ3sB99PKf6TuFRLCQ9QOkkFwqdwC9DcBCvEo=;
        fh=lRl3lCpkdmIfWp2SW4d1f6Cjk4rVDaWA5XNba6eDFoo=;
        b=VOYEddBc611HEQsVOYk948wKswo/iGPUx9AseoPVo8+gwewJioqM9wZ8egSuMGM8ho
         nRtuOa7Kp/IRwuiBNALDC10FM1avIU8lblsFHABEA7CD3S6i4FsKOEVG+zw3Td9+pid/
         LRRUy+KDR4vU4KZ5idM49llZLwgqHZnzZp59oOjDTwRn6esCBqEuI+3YfAX1vffqBdeM
         F10A7LuomtAMTeUbc5lMNhbNYMFrVj5YqyiFLD3TjiGGWEe7ax5AE3YkCLiaeWXReZhI
         /+ixcUJgYxiU56dIo4CoIVmje/V6+U4lUqutlF/DzYCmnbp7WGQeglROy7mu5boqhuOr
         TP9w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=IXNxlJ+e;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::62b as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758715217; x=1759320017; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=DNA1n5oQ3sB99PKf6TuFRLCQ9QOkkFwqdwC9DcBCvEo=;
        b=UfYA9iBOIQmQ6hQGP7fP22MqTRCPpBoaMy5uIXEIR3ZtxjcXJGLXgsGtg3ip7zdNOD
         1lGkGPvxWHwj8YP0+m19VeVW7baeWZsBN1ijMznRPb5RtYGf/2C7pB4LeC39QU+vogh3
         7P3z1RSt808rL0tCDKqAepm9FfEj13xoQrZ28GCb+5Dlqaqyn81otFwv2xwc6T51BfWP
         1iwmFKWMCR4L73H1NIoYs9TV8K/If22bRSfkuHLyIr3itxe6lOnNjoJM+8kRd4zhnUhY
         zgEpjPPLx0Oo+cKOHRG84r/9muznICojZSyKFSkmiRVh281+jc+8pA+mCVRQZGmQLMn7
         dmwQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1758715217; x=1759320017; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=DNA1n5oQ3sB99PKf6TuFRLCQ9QOkkFwqdwC9DcBCvEo=;
        b=GH928JvrzLzTByaSNZwXZsfBvHFtvzY86hPreb6V6k2fnkqiIwWYopdBd+9uQU3sMB
         TCxbcjv/TdhF7rdflVUjGKm6UeMYx2KYJxqnCOrABgtcw/Vvk9vzWNAm2mossvSfhdlB
         iWGVdpASg0txA+8jwrjg8pe8NmNhwhfsL2XlgNuJgejAlG/lnhxzPAMKJOc0m17Q8qzv
         PghLo0kDluIBo5nDR6Am6k726qy3jvyxSJIvHBqD71nNkQWjpBwFG/Bs9lX5RevtNnzW
         QHuDHuM0PgTcXFGhbwbmw9sNAawdmCKVWZTNfEB4Ut6t3nnCNdBFahmB9Eeu1TMUhb1D
         IEbg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758715217; x=1759320017;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=DNA1n5oQ3sB99PKf6TuFRLCQ9QOkkFwqdwC9DcBCvEo=;
        b=UgIoG2/SGJ18IamUUFvqrPxW4jjRo1LsIhEaJ7hUPaI5llgIEPodyLj/fUH+oOKWSf
         tr/FZAojHC6cyIYlKhdb36pQErld38S0qhgu1x5bmxY1vQW/7wpPwMmMiCFOGcD6LkaZ
         yqeELH4C5cV224UcZn2EykqeSMnfuCoT9D91N7LrUuR9199c1S/z/fI3RWxU17JPf1Hy
         WBNPeCE6CxLHl+5YyJtxco/3y2IoejlxOXgeFQblYfztkQ9a49TI7CjL67ExEw4uceP2
         mMEFLzMhPgRypwPo+ICIARs4FjUdndAyH+vJ3Njk+yynBysg3O7ajpnGYvRDO1cX8eAZ
         lw1w==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWo0o85KaRQ/0A++rFH2XFdxg1dbTcxNYftY4RBA071erLi7XuI3WAAmWcAt6VcyMajxsqBlw==@lfdr.de
X-Gm-Message-State: AOJu0Yw2+VQj4obwBYbvvqbr1gjTesZOpBNFVGEi05dQFY8TWqeKFcqd
	GwnEr4Gi7W3QPYjjJJcVtTBYxyWU5T9vgnXR7p/CRYcz6RzxLqNkFMK2
X-Google-Smtp-Source: AGHT+IEuKAC+CgcQK9Otfobbh6cjMFLSxQKX98m+dFbPbbTF/ScGraFgMHXklk4uMJ3JjgWYFsMjLg==
X-Received: by 2002:a05:6e02:168a:b0:41d:5ef3:e06 with SMTP id e9e14a558f8ab-42581e37017mr100745375ab.12.1758715216842;
        Wed, 24 Sep 2025 05:00:16 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd6t38/P+BhB3z9HnKJBeo4F73DF2eKDSVrhB3QLq1OHmg==
Received: by 2002:a05:6e02:1905:b0:424:1289:9cca with SMTP id
 e9e14a558f8ab-4244d934662ls69811255ab.2.-pod-prod-03-us; Wed, 24 Sep 2025
 05:00:15 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWh0tv1oMVpHKWBhOE7+W2b8vh/QmcoZgn7UYv7ip9u+jCb3aTAfrw5xfjuM8Hrga23pkHy00rJsdk=@googlegroups.com
X-Received: by 2002:a05:6e02:1562:b0:424:6c8e:6185 with SMTP id e9e14a558f8ab-42581e12562mr77212455ab.7.1758715215539;
        Wed, 24 Sep 2025 05:00:15 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1758715215; cv=none;
        d=google.com; s=arc-20240605;
        b=LpynoTRRJlOcPWhzpO8oC0ZsnKsx9PazA22YCWoMlxvO7iwYO05R6JVSKk4G13rpwF
         Zrw9C8LPkBAhE80xWIFiVADIGas58kzzMEx09Xsn834zOtJe4Of6WinzfjAr1RRiB3T9
         MHS8aHMtYfVmQLpEwNS/WPWmvGqxpxPFWIzEMgwgJKn5Ya8R6c3FcJSIVnCtfu8b9Dpb
         0JQT28d3lkxBs08gh6BHy7quuk9zTcYsZKntSGUna6CdoTDQCVWY2kxHkWC0kAQik3CC
         lfFuKpWk27546i8rUMuXkr4OqTpyakHM9IHC0sYd7e4Vizxd5sIVWdVSIw4ryM1/JjfB
         F+GQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=UmaGbmiuxIsK0xKTEWJ/f7gfwC2bw8p0SOLh4b9Z4FY=;
        fh=b/WR0O68wzKPa4c1iw0P8n1NvURquWUJ+wTwh2N64co=;
        b=Xt9J82U26lq5BGzdW9NNBM5gRGrRYxr+rraZWkI4JugYPpiyGT+v84vaiUHi7/MU2K
         cVHGRY0OcZovpImG2ftQERS7KdJn9GSNlEbvDsQMMBHE/bYbqD9RxUhfnwJ9gPkcX9gQ
         1llrryfXsQwLd0VFxmTM7Cj0CPqxDA6M0tV/Fb6q14Ba21EKahTuG0nFPDk1XPOz8r5a
         EWXLRaZ+DrjNEyJFSbmnMI9yBhP6Kx+uxh6w/IIs+lVFj5VLpsoFU6M859Sr1FshY5lF
         vfe6kkKaNpar12Y6fAE3/6Wz4IO2A4zkaPgoCGsHa8r/UKj+DQWggJvKjtMuq88l2f8n
         7Pmg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=IXNxlJ+e;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::62b as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pl1-x62b.google.com (mail-pl1-x62b.google.com. [2607:f8b0:4864:20::62b])
        by gmr-mx.google.com with ESMTPS id e9e14a558f8ab-4244aca860asi7496235ab.3.2025.09.24.05.00.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 24 Sep 2025 05:00:15 -0700 (PDT)
Received-SPF: pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::62b as permitted sender) client-ip=2607:f8b0:4864:20::62b;
Received: by mail-pl1-x62b.google.com with SMTP id d9443c01a7336-27c369f8986so24459745ad.3
        for <kasan-dev@googlegroups.com>; Wed, 24 Sep 2025 05:00:15 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUhJXi6tm76gY3ZP5j62DnBlJy8MqL3GU1k4TJ+F64Qoy+N5ByXRaghAF3ExShrBH7ypD+R2ZSDU/w=@googlegroups.com
X-Gm-Gg: ASbGncuDSeIExw1CoKxkqKui9GebaXucUX6UC2cK9U9/JInKnXfXYQCazElWJbg7RjR
	nqC5mGDtXjSDsx9CPUI/Gd2LYQ+iUkzKlwHb2j63g9dUWvzN2JvmCskwAX7NdZeaP3rdWaDWHUQ
	LuMJUD/cgSi22QkL2gSvGgXp4Ez3kFThSKPcX7AKHU7njVNMKsNIH9kEjC35++3jpJ9g1s8B6Bn
	XQCMmJW21BbxVHPxqTVp53IcfaphF7ZeUByIS6y/oUJofUf5oQA5dumRgN/c272qAEa82zt97DZ
	+BE0Nk7FP9/xryqTtmbdjrLhZqcg5YOZ8anAjS79Yg5loMfpafgOjrPUXgMvrpG9IAVMw6wRhmL
	BmrN8FtPsV7IEo5LhCHUH5WE=
X-Received: by 2002:a17:903:2450:b0:268:f83a:835a with SMTP id d9443c01a7336-27cc9a91248mr60312585ad.60.1758715214591;
        Wed, 24 Sep 2025 05:00:14 -0700 (PDT)
Received: from localhost ([103.88.46.62])
        by smtp.gmail.com with ESMTPSA id d9443c01a7336-269802de5dbsm189402185ad.84.2025.09.24.05.00.12
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 24 Sep 2025 05:00:13 -0700 (PDT)
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
Subject: [PATCH v5 16/23] mm/ksw: add self-debug helpers
Date: Wed, 24 Sep 2025 19:59:22 +0800
Message-ID: <20250924115931.197077-1-wangjinchao600@gmail.com>
X-Mailer: git-send-email 2.43.0
In-Reply-To: <20250924115124.194940-1-wangjinchao600@gmail.com>
References: <20250924115124.194940-1-wangjinchao600@gmail.com>
MIME-Version: 1.0
X-Original-Sender: wangjinchao600@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=IXNxlJ+e;       spf=pass
 (google.com: domain of wangjinchao600@gmail.com designates
 2607:f8b0:4864:20::62b as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
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

Provide two debug helpers:

- ksw_watch_show(): print the current watch target address and length.
- ksw_watch_fire(): intentionally trigger the watchpoint immediately
  by writing to the watched address, useful for testing HWBP behavior.

Signed-off-by: Jinchao Wang <wangjinchao600@gmail.com>
---
 mm/kstackwatch/kstackwatch.h |  2 ++
 mm/kstackwatch/watch.c       | 34 ++++++++++++++++++++++++++++++++++
 2 files changed, 36 insertions(+)

diff --git a/mm/kstackwatch/kstackwatch.h b/mm/kstackwatch/kstackwatch.h
index 4045890e5652..528001534047 100644
--- a/mm/kstackwatch/kstackwatch.h
+++ b/mm/kstackwatch/kstackwatch.h
@@ -52,5 +52,7 @@ void ksw_watch_exit(void);
 int ksw_watch_get(struct ksw_watchpoint **out_wp);
 int ksw_watch_on(struct ksw_watchpoint *wp, ulong watch_addr, u16 watch_len);
 int ksw_watch_off(struct ksw_watchpoint *wp);
+void ksw_watch_show(void);
+void ksw_watch_fire(void);
 
 #endif /* _KSTACKWATCH_H */
diff --git a/mm/kstackwatch/watch.c b/mm/kstackwatch/watch.c
index f32b1e46168c..9837d6873d92 100644
--- a/mm/kstackwatch/watch.c
+++ b/mm/kstackwatch/watch.c
@@ -269,3 +269,37 @@ void ksw_watch_exit(void)
 {
 	ksw_watch_free();
 }
+
+/* self debug function */
+void ksw_watch_show(void)
+{
+	struct ksw_watchpoint *wp = current->ksw_ctx.wp;
+
+	if (!wp) {
+		pr_info("nothing to show\n");
+		return;
+	}
+
+	pr_info("watch target bp_addr: 0x%llx len:%llu\n", wp->attr.bp_addr,
+		wp->attr.bp_len);
+}
+EXPORT_SYMBOL_GPL(ksw_watch_show);
+
+/* self debug function */
+void ksw_watch_fire(void)
+{
+	struct ksw_watchpoint *wp;
+	char *ptr;
+
+	wp = current->ksw_ctx.wp;
+
+	if (!wp) {
+		pr_info("nothing to fire\n");
+		return;
+	}
+
+	ptr = (char *)wp->attr.bp_addr;
+	pr_warn("watch triggered immediately\n");
+	*ptr = 0x42; // This should trigger immediately for any bp_len
+}
+EXPORT_SYMBOL_GPL(ksw_watch_fire);
-- 
2.43.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250924115931.197077-1-wangjinchao600%40gmail.com.
