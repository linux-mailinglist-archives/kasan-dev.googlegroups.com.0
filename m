Return-Path: <kasan-dev+bncBD53XBUFWQDBBJFKT3DQMGQE7MT5YJY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x38.google.com (mail-oa1-x38.google.com [IPv6:2001:4860:4864:20::38])
	by mail.lfdr.de (Postfix) with ESMTPS id ADAF7BC8A02
	for <lists+kasan-dev@lfdr.de>; Thu, 09 Oct 2025 12:57:42 +0200 (CEST)
Received: by mail-oa1-x38.google.com with SMTP id 586e51a60fabf-35d009673e9sf271280fac.3
        for <lists+kasan-dev@lfdr.de>; Thu, 09 Oct 2025 03:57:42 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1760007461; cv=pass;
        d=google.com; s=arc-20240605;
        b=CERGwiwpCHXkWGYn/2yvbZnnDPb+yjM9Sho7ntNg0oWhR8UM0za0Oyj4CBKgkqcvuo
         1mCo1moa3Y44F7u7SI9oHG/lJsGCenIK4SfyIUv/x+vcycdQMtMubV/20pXAeFFMomQj
         Hu7C01BJ10iZp4qOfVbjUsHg+ibB0SGjOr/TRbklWsfJXcDKoLojAI/zk3j3o3y4DaC1
         2i/cLxZouLFoz2fFIyMIlPKYMCP/y74i5zoJVbWk6932DV7RRKd2K1v8tmeGfIn2YjfA
         3RT3bxsTAOP67sJQp8lvVHF6mYnSla1gb+N6BuWiTbtcts+wLKtW7M6CNg6VtKmaUEqj
         TTjw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=NeeQ84ux50kCmTg0QoiLdFrjZZzLnW93Wgw6QQQNc08=;
        fh=xDlHrrxsHDBvd0sTtpObuFM4p4PHvB4MoaPT84HegV8=;
        b=WLVszrhfr8PR+5KdCz9HU2cFZcKLlg0Vv/nWxCyOQkjmkLXDQ+I1rgt2DYeNfqYpOX
         DQLU6Hddz0yF0pbg4OR6yR46jpSA15+HUbnJa352vTrV9/8mS6njL+lN/n5uAZF0zJ09
         70bMtCKyv71OjIkszypAKW1GeIrS02XfiN66lcyQIdtXAJrFUsvP/tVENB57YYxiggnS
         gVQUt54Lm7IiU8n3VpUS4ZwEev8rVYV2FTceFjTComDkY47tkzCktEaZQN/PBr3ufXjz
         Mp2RMStKAMDaiVF4Q3edY5oK+Szi92lJxFcsKxj2BKpdF1eNDk6FcfszkK5PbgjX/YnE
         5p8Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=abkVM172;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::429 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1760007461; x=1760612261; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=NeeQ84ux50kCmTg0QoiLdFrjZZzLnW93Wgw6QQQNc08=;
        b=s62l6MRfZxpIizaWgMiH2BI4F4Pg/r7Gt3o7zKSXN2/fkeBvihyeAQRcWZKKG21nGe
         xu1hdTR3x5R+gIUTVTeuQkgcr7UhS5BRUAuKNJNjBou89oNj9UczfSL6Nt0WgFaGF+N5
         481IBcPzyrd7UEc22njbsshgEn49ukEpoPPLorxXQTtTXq++oXQkRz904Zw8cp150gJz
         mgweQwQBMgHEi1NmueG9YPBFDQ+oeiUUQzqxJjJj3FOK1D48yPQ4TV6inA7HRM7wI8OE
         SPqyEUdU/HvibV2N2DEOC6yoj67qCSn/hrgzRyp2tk9eW7xIn16AN5Go95LncXu1vN5L
         Uj9g==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1760007461; x=1760612261; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=NeeQ84ux50kCmTg0QoiLdFrjZZzLnW93Wgw6QQQNc08=;
        b=EYdk3fyoHn0bsQJU5boTqZNvFvSwoZuhyJt+iLrzVKwehQ1src3XblUD8DwuwmNyEb
         Y11U4Zpmo7pYG4qi2pGwMtr8l//EKrQ/Nf5Avr5Bwl5dQ1QkzdRvbVvkXu/6e5Q3Ubno
         PIk36oLcsDkvfoJ219msjYMJ082nB18mgw1CSximEYQQn4krzTlvlKmpKuuyrQO4YTIR
         rg2bxl8mvpuV7amtTgW8jBfoUaxyixqeMVdKWdr1A9Dl8ZD6q+EcCHmPl7xS00nDzD/3
         j69JXOMDlarvnys39OkFileW6nzet4bLRXd0p+pMO3w4fXBrHvMfDCAZ3eeRRLVZZ01v
         jmYg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1760007461; x=1760612261;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=NeeQ84ux50kCmTg0QoiLdFrjZZzLnW93Wgw6QQQNc08=;
        b=AAZPd/1mDW6WzLTIQYB1IBJlyCUzaGpv+DQ5KZcEOxvCya2l0o/rJWp0nhMBGLWaNg
         9w/FLvN6MGraG/nZ1aGmHr9ZeDP4+kzxdcMxf2sXAYOJozjeU2D8F4IyyPB6ir0ewC4n
         YH4YTYl7lqxIe5QeTO6zXy5HPG5dFKXJosQDSkzCP5c5f510gAIGYKXK1NVhi1loM5I0
         BF7yz/lfkvN0kzxmEewqXvh9UW2VHZ/WwkKHnVVftf2PSv5urfiRigA+DDvK5qYmEEc5
         Sz1pWFWLxs/ijOn2/pardDMDeBGKqpDDqGynrcSO1Ebh/28w0lyG6R21MA8ecKLreyDI
         6wIA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVuztBBGBgwYZ3veeMa108X7tB3QqLDDRRZjdFEwuZsVFUkkrevreuYCpU1Mxl1tQM+IqrLIQ==@lfdr.de
X-Gm-Message-State: AOJu0YzOAuYS31qAcZlydSNbBlQ2CVjdIeGS+S/wrYlTL4pIJaKrJKQK
	BWe9bRzAhMz7iNuk1w8Bo1lsqqBmacJ2xYNnpATknvdcgy6oAgFkuniA
X-Google-Smtp-Source: AGHT+IFRddyLZTMXn40vGfEFLS1l+PTBcUU+o7eKmGLmUFypW5ykT9mB+0pHnCzPZlrC5xp8B2jwQw==
X-Received: by 2002:a05:6870:e307:b0:31d:66fd:298d with SMTP id 586e51a60fabf-3c0f6d1ff02mr3406189fac.23.1760007461120;
        Thu, 09 Oct 2025 03:57:41 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="ARHlJd7z2A8oXeIpPgNZErgUz41kAjy7wsnJLG1gTIzj03Fwug=="
Received: by 2002:a05:6870:3187:b0:393:f276:83f4 with SMTP id
 586e51a60fabf-3c720ce861fls309810fac.0.-pod-prod-02-us; Thu, 09 Oct 2025
 03:57:40 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXxJUbc1AGFFl3griAha5WGzYEDpM5Eoo4xq8SPBa0vtARqQKFKMba4mXxsq6w9ejZ/TChxce3b24g=@googlegroups.com
X-Received: by 2002:a05:6870:46ac:b0:31d:676c:b002 with SMTP id 586e51a60fabf-3c0f6d214b5mr3277263fac.26.1760007460203;
        Thu, 09 Oct 2025 03:57:40 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1760007460; cv=none;
        d=google.com; s=arc-20240605;
        b=UzMsij4ZdlQrI+v4k1uYGPM++E6Z31bX1de3fm1i8oly7CdQNjnrlflXSHV1qt6+7W
         elHvP5hJPYVKzzhbA7TspOY3LymJLQAx/BdQn8YJK9xVYX+v+H0rizWgk51MJWbbGSOW
         fuHkp/9g+7Vuv2fy2asGk6A8yaAeOq6vwo4BPpDQ7BRrYM7bpV03e4GlHAdlB/8OPQfv
         HNn+7OGMiBZK84mkclAa9VVe0nHg9EIP8HxQfK2FvVDiFmpg97ESUB1jDjMk8CWnCawe
         gQZNlaA4wFtUjqu1o498mYkvjSusA12KYLM8aR5O5ayDRqKxwRwXZB1dzFHGwASjX5AA
         4bqQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=EtGUQc6HOhuSXywhIDZ+AUqHUInlRCKup6JfN/4+ZEc=;
        fh=xUTQIK/Gtlqo3XdgGHOHqgntimaqsH7KrF98VZDnFQk=;
        b=EcMVBoHHVWr2/pDv+74EoolkSl/8Kblppn/VVfTNkEKnWf0hZlole/jk0wQr93oEnH
         rC18ZVLwMKhj9F2a2NdbiDTSbv/0fqCFMivqbxIfsfMEtYkgtICNHlvjXHaK+dL5MJ9e
         3+A3H8P8uv6WzOrXJz50x6qTrxl+CrkF/LubDx6mKFX4DAEIA/G1xBZ8RD5B0KVaoVrD
         uCPwq6Pzsbdf/yZ4MqC2Ye7HXyJomWMpEM25lh/GMT17+n96q3tDGlP1SP8NwZV1W0rt
         iMT7SkC23V/XYEvMSOG21iKQHQwQiDdDqJgQdvQu3PVuaDVzoDUoDm3XvervESztrdnG
         N+aw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=abkVM172;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::429 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pf1-x429.google.com (mail-pf1-x429.google.com. [2607:f8b0:4864:20::429])
        by gmr-mx.google.com with ESMTPS id 586e51a60fabf-3c736061333si1472fac.3.2025.10.09.03.57.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 09 Oct 2025 03:57:40 -0700 (PDT)
Received-SPF: pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::429 as permitted sender) client-ip=2607:f8b0:4864:20::429;
Received: by mail-pf1-x429.google.com with SMTP id d2e1a72fcca58-78af743c232so733406b3a.1
        for <kasan-dev@googlegroups.com>; Thu, 09 Oct 2025 03:57:40 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUtiEgk5Brwlbghs6B2JjMqOxFKkyIOJZr8/8aEZ6ovNYEOvLTkLBM4RKPYMzSD8ygq1MD5Hmh3H8U=@googlegroups.com
X-Gm-Gg: ASbGncvZUBERzYiCBvysCWAsUIOw97YiPa2m9H2/c9MD5JQ1J8wSbxbIpx5ZGoSo43y
	x3nDgdpOrzH8uOAkNgimq8qnCv/5VOlvwxn0eghC0j7sly56h+Fzxrk54WoXKDOdIIk6RWDFP+q
	MgRLylVtzqkdlAeYs2UpA7v44hnI3AIMG/LPvWIHHbFqrFZBzY5p6IHfiQKpttWrcESoIL+ZpH+
	K2AhAhGMCE64RcWKH/h33wvw1t9Oa6Ufu0N0kwmtKRAvHkpd8jJTvqvyMZpxVpg30wGVnHSeZeS
	ok3HOggJCebQ15qFlNkfUPayXInIlZ8YZ3WJz//drUpss5my7w/f4Lr23WwnVydyDNKtIO5A0zT
	D/Od6TpFWcotQRKvP6dyk1xKKbswJu0qC1pwfsZNtVzn2t/wOydAuz+L29hVq
X-Received: by 2002:a05:6a20:4305:b0:2cc:692a:3a30 with SMTP id adf61e73a8af0-32da8154253mr8702045637.13.1760007459212;
        Thu, 09 Oct 2025 03:57:39 -0700 (PDT)
Received: from localhost ([45.142.165.62])
        by smtp.gmail.com with ESMTPSA id 41be03b00d2f7-b6099f3b041sm20710766a12.24.2025.10.09.03.57.38
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 09 Oct 2025 03:57:38 -0700 (PDT)
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
Subject: [PATCH v7 08/23] mm/ksw: Add atomic watchpoint management api
Date: Thu,  9 Oct 2025 18:55:44 +0800
Message-ID: <20251009105650.168917-9-wangjinchao600@gmail.com>
X-Mailer: git-send-email 2.43.0
In-Reply-To: <20251009105650.168917-1-wangjinchao600@gmail.com>
References: <20251009105650.168917-1-wangjinchao600@gmail.com>
MIME-Version: 1.0
X-Original-Sender: wangjinchao600@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=abkVM172;       spf=pass
 (google.com: domain of wangjinchao600@gmail.com designates
 2607:f8b0:4864:20::429 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251009105650.168917-9-wangjinchao600%40gmail.com.
