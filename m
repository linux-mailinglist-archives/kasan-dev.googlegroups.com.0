Return-Path: <kasan-dev+bncBD53XBUFWQDBBLUI5XDAMGQERUDLBKA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83b.google.com (mail-qt1-x83b.google.com [IPv6:2607:f8b0:4864:20::83b])
	by mail.lfdr.de (Postfix) with ESMTPS id 8BBAABAB0C3
	for <lists+kasan-dev@lfdr.de>; Tue, 30 Sep 2025 04:45:04 +0200 (CEST)
Received: by mail-qt1-x83b.google.com with SMTP id d75a77b69052e-4e0fcbf8eb0sf50295391cf.1
        for <lists+kasan-dev@lfdr.de>; Mon, 29 Sep 2025 19:45:04 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1759200302; cv=pass;
        d=google.com; s=arc-20240605;
        b=e/jPgAIXxBgrhMtMHLPioqTT6VLCS5hLRruJ937SZQstSDWlZe7VwuJm0x1oistZno
         1BDO63IAi7qv6FowiZEjTYiMCfOv0YzuI772ClOWznnQxxrUNtVDvKGeZ2oh0WJr/3Ij
         lqSpM31KOGUQuyjwrycDui/CKCtb37bxj5mG5KkC0kptTDCne53yjNSJvCnhIKi48hC6
         KLVJ2TrzV79vnusxsEy5+G1+Ir2QL0ovKcuSaZru+dxFwSP2j1I6LLFzRK3VT4Oq2Wso
         /3Ki/lioyVA13qRnr3Y3cw8Dv9rCyYV8k1sh02kl46CC+Fc3Fy+iRn9iYUSSYsS6htZZ
         cE1g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=C3/QNOiLkXr/p2WtoUvVzyA3e8HBjX9KWmjrMwBmcOs=;
        fh=hVwI9sXjafJ+3hY6kadghlkfeKTfOwI/RCdzlBypICg=;
        b=efX73AfhFcnXFy7trhI3j61FiusRt6ytVCnzvx0FurZjMks19p4JRSk2ecLjtk/OcU
         yAyA7/mM5PMnlmv4EqeA/cxZMZ8QdP7f5hXZTfClG8mAHejXsHfSGONoYFD9FxC7sDyW
         z57/KlIr+PaUzmvoQMck+rCNMOko7x+EEGWIu0u7nyesqRhv06H2uCQlLf6hl64LP6HY
         uN2sPpJguvz2sQFlszoRM9Svm45r05kr23VZCyYnPEC4Yt1aEG0KYXHcElwiUP4TfwT+
         /am1SA506FvM6xH2og6dsPwx/VAzA9bd8wHZFP6VtzdgFO5IAtLa5hdrVVl8e1P+AWeI
         S2WA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=OnHiCYAh;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::1029 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1759200302; x=1759805102; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=C3/QNOiLkXr/p2WtoUvVzyA3e8HBjX9KWmjrMwBmcOs=;
        b=peJA4ORRnwOK+kTruq1LMhDSO74gnaeYgcwl/uvrSO2pMBi/EfiBbJ1EWfBsc0/djx
         Bfv8QrSv88ydTFSLnQiGlimj9We+eZ5JoIFSsu+0bfVI9kS6QQW6QN0W5TtTppz1XETu
         fTXh5wSzCfMNJORVX+2/C+ZYO9tH2na2JjudTS/idpCNyseU+PYQu8GxdLKBdpIUm1F7
         z51LIVfi2gMsYdC1mwTyuXtni42C56USC3yJsvuBFveFBs0NWOcHYd5qikxcZZbXH/mm
         Lqhz51T+oNMpxlH4S64Qy0eFpLutJYww3HqsFUKqINvIQs8xdb10L+u/YJAy1c1MupEu
         QreA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1759200302; x=1759805102; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=C3/QNOiLkXr/p2WtoUvVzyA3e8HBjX9KWmjrMwBmcOs=;
        b=m6LxKsYQ7xMdLsLX0W69Qmv7gqnls5Pa/21ZqR25Vr5VxHTScoGdcPpiey+O89N4rN
         3kjS7sZXYH0EFHFoFAWe3tXje/3M36eAe89KpfNxeJoFOpAK4IlQ2OvMk2IyBuCno8Lh
         WEMoiIdh6YFYIuHWEw56PceRWKkcY4rq2YL+KbZ9Dvps8/ROG4TZHkWnq1i2+twF5bXN
         2Dujs/p8hbrYp/adijN7w9bwKaDfzrwZZIpJ5/nf5YQMtMNLRhRmz7n5hnXN2A4rrO8s
         Ps3YpANS8P8L4BsCoAPpIc7VODNsg4bkwk25BeDCvICuIBTEcSYDNTAjZI6KntuQwSoe
         uJxg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1759200302; x=1759805102;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=C3/QNOiLkXr/p2WtoUvVzyA3e8HBjX9KWmjrMwBmcOs=;
        b=ePSk/bE4NWPn+2xgjY9IqbHRxTjh+m0aVzsY0PvWMDDY/AVrBynku6Otbo/N/hEUg3
         y1TgeUJDzAv6c8Q+VwGQzXNOLu/TID7zit2W+IDyfELO+2zEyNfZHaApyBOsxlVP6tOu
         3Qqj4ZgPaqbFhd4Ww77v0w+CArtJyXBYMliMKn3nb0UEvDZfIPanFAPQHCVP1thhI18m
         dYX6pzHp2BbbksRdfOkHJ8azV7Ka/fyJ3+mWhNgeBly2+7+yZYZvcjT6RBn11Kid6Hdp
         qLzIH6yGo1PUCTTl6jLx/JCXzeqmL7uPeJ8pWghOKWdjmdkB753QS+uochCjsZLoHgNo
         8V0A==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUo+D+vGSAVhGsbskPioZ6P7/km2YIjCm/x+tvAAYDOvESJVs0KGvxuPCbFk9KUrjXapbOK5w==@lfdr.de
X-Gm-Message-State: AOJu0YxIQPDhcDCDBoMLqNImYb39E2OYQuBzz8rOC0caviMdMIvaFZpH
	b74MCBASHQqsGRlf+Y6N9uXNODw6lV6cLSuXfrc0X+ofhfcaJAldZ3H1
X-Google-Smtp-Source: AGHT+IGn1y+pKMFvu/QDcfiwMg/WFcZIXXlD5UgY0++6lNaqNJiwoyYeLXlwm9996f9ovYDkkQkF7A==
X-Received: by 2002:a05:622a:2519:b0:4d9:b55c:1fc5 with SMTP id d75a77b69052e-4da4b42ce9fmr271946591cf.44.1759200302319;
        Mon, 29 Sep 2025 19:45:02 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="ARHlJd4c6msHuYRMXTXn3c1MiOIDFpYcLy+OYVOFDMszzgzm9A=="
Received: by 2002:a05:622a:768a:b0:4d6:c3a2:e1bc with SMTP id
 d75a77b69052e-4da7dee65c6ls84785731cf.1.-pod-prod-09-us; Mon, 29 Sep 2025
 19:45:01 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVozqR3N9TRrup+q8R7pkI9LomaVcv/XzHrSWKx3Q9BrhcVBCPbyn0l9rv2XnD8xbHNRaqeIoRcYqo=@googlegroups.com
X-Received: by 2002:a05:622a:480a:b0:4d0:78cf:7f7c with SMTP id d75a77b69052e-4da4924b59emr240780031cf.36.1759200301282;
        Mon, 29 Sep 2025 19:45:01 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1759200301; cv=none;
        d=google.com; s=arc-20240605;
        b=BbFosQdNVNoUWJqZoMhoVqBLnyP9XYHVs1tj+S3mCXzw4oWaqcpanz8mVd74PxgPYd
         VOVsHRefTq5W0ugjiKFjYf/Su2OBJcbydckHnitguSLFTQbJyh8+811iOICZUHNjN38B
         Mo6THZ8JQ7xoDr00BzUwPMVBQRujxjezhh9DysbMaDec8N/+FXRwvtxzrbWUN3xVL1dd
         mHny2PzyqrVYj1ufpeYKk5gx1KjroAbC4mCKIPLQ9MrG0diJLlvvpDlfozHyOeXMPMCF
         zTSUoUenxPoxHKpoSkSYsFDxJEaRSKr+sLaquEFCIhiYrlp4407Lyi7pkb43kxQKkBpg
         67kg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=EtGUQc6HOhuSXywhIDZ+AUqHUInlRCKup6JfN/4+ZEc=;
        fh=ZBx+ihnx2ai8gS5hnJ8RHKbkYKiCu85Wul3eV93eQ4g=;
        b=KNUme1f7QfRE82jXI2y8Fb1BzN9Vwq+hSdL8pJBmYJsX3Lj5KscI+gNx3tybSVqWVo
         T/Hz1bwHFOJwp5jP4ToiGEf2mxn+hl2kVd7UcDXzFbK2jAQodielEDRNUv68BiG1vtDr
         ZPXEdbMI6qH0EG9BrepNRqV0IU/7Pzvd/9skTY/SZEC/BFSBK/j9phKQaysUy84qkztC
         T/SZGrYz1Ber+QJEgLcVeJBME5YkBLUAc1EcOMxJyDohyJrrWL+zCNDG8wXzWafPlBSU
         N0dUg9PzdrAOeNUns3pEPn+yZ7lZa2vNX3SmMIhGDEbaIWR8ezKclM3ecuj3QtOegsun
         tHfQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=OnHiCYAh;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::1029 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pj1-x1029.google.com (mail-pj1-x1029.google.com. [2607:f8b0:4864:20::1029])
        by gmr-mx.google.com with ESMTPS id af79cd13be357-85c2d8898afsi52668785a.5.2025.09.29.19.45.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 29 Sep 2025 19:45:01 -0700 (PDT)
Received-SPF: pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::1029 as permitted sender) client-ip=2607:f8b0:4864:20::1029;
Received: by mail-pj1-x1029.google.com with SMTP id 98e67ed59e1d1-329a41dc2ebso4463257a91.3
        for <kasan-dev@googlegroups.com>; Mon, 29 Sep 2025 19:45:01 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVhw0Nbpom67Gp/5n0hAswxvIxvI9Sai4FwUoyTX8EyhIN04VGQnUUYzdccJYct9DFqzl8+aDkRQuo=@googlegroups.com
X-Gm-Gg: ASbGncubIMpiXF/d/Jj0l50P8MAguVb5JcoJA1JRgf1TkDocxy8AL6aaIdkbjXath++
	eREMTMDuzDXBFCC4GJaaOmA8zZCAqvcB+QGGFMlJCccExh4wGUwatvqjjJL1oQvGZgyZulczjid
	DLHfQTe2urAdlRGUzslTSx/oS9jDmusHyWY1AGK3GLiooS+5WMSpBZTjSGqbAl3j6VnZXe+qhON
	5TBhTtvkCPj2gPXk4mcs4Z2lhAG5GbmekQajnLgzvPDe/C0jxh1zlrER3qb2dJOrZT299g/M++B
	3f8faON+0CUw7OTpN17sDsOGhdPD/vEi2e3uiH0zAKCyUF63zN8chRTKm9L2m7DDCuBJexxcVPZ
	Fvh8rXlODrEIBL/B7zmp7UmGovHso5T2/YsVUYETtnqwOQi+m1C2U0oc+ZgaqlhJCEg==
X-Received: by 2002:a17:90b:1b4d:b0:330:797a:f504 with SMTP id 98e67ed59e1d1-3342a215b70mr18813357a91.3.1759200300239;
        Mon, 29 Sep 2025 19:45:00 -0700 (PDT)
Received: from localhost ([45.142.167.196])
        by smtp.gmail.com with ESMTPSA id 98e67ed59e1d1-338387255adsm2766677a91.19.2025.09.29.19.44.59
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 29 Sep 2025 19:44:59 -0700 (PDT)
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
Subject: [PATCH v6 08/23] mm/ksw: Add atomic watchpoint management api
Date: Tue, 30 Sep 2025 10:43:29 +0800
Message-ID: <20250930024402.1043776-9-wangjinchao600@gmail.com>
X-Mailer: git-send-email 2.43.0
In-Reply-To: <20250930024402.1043776-1-wangjinchao600@gmail.com>
References: <20250930024402.1043776-1-wangjinchao600@gmail.com>
MIME-Version: 1.0
X-Original-Sender: wangjinchao600@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=OnHiCYAh;       spf=pass
 (google.com: domain of wangjinchao600@gmail.com designates
 2607:f8b0:4864:20::1029 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250930024402.1043776-9-wangjinchao600%40gmail.com.
