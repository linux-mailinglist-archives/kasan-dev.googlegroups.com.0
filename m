Return-Path: <kasan-dev+bncBD53XBUFWQDBBOMI5XDAMGQE5EWM2CA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43c.google.com (mail-pf1-x43c.google.com [IPv6:2607:f8b0:4864:20::43c])
	by mail.lfdr.de (Postfix) with ESMTPS id 858D8BAB0CC
	for <lists+kasan-dev@lfdr.de>; Tue, 30 Sep 2025 04:45:15 +0200 (CEST)
Received: by mail-pf1-x43c.google.com with SMTP id d2e1a72fcca58-78105c10afdsf4713733b3a.1
        for <lists+kasan-dev@lfdr.de>; Mon, 29 Sep 2025 19:45:15 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1759200314; cv=pass;
        d=google.com; s=arc-20240605;
        b=iz1vc+ziN7Woj74pt0Nv+2fIsyjh/b8bQxGUvc9wJXU/DIyx5H+KJybLL3Uro2ScMj
         JG1o7gHCKN7czvZQHXTTXDQtD2HMCASbhli0hGP2o0qRfGebWPhqT1/PhJ3Wb/TKE6EE
         VQWeCDsnwGidJ7UtsmjdACssggHqhQgRwxupjvuOiuqyOI/7/+T/9hrUNEHG/KuPzbpq
         zMNMhhQcM6qcRsi1vwnAXbzeUC8HNhR65h8wPMyHeie7lCJ0cjKE6ume8ISFdc8vpN0a
         6k5VUxS9z1BXIqK0EdKyLo2tJZyQC3SnMk0vIgt6DnmniI/OtcBk7eKSp7VB7/ui1jmE
         RlAg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=esuym6wNDW692oPQZOlVSSoagBZryYOoYfqFZWSmXPM=;
        fh=A6nVCbdrPG603jD5jfzI9m7V5apU5Xk/TnRmAVYh3qo=;
        b=Wr6xHnOPLMEE9ix3YteYSX63+wzgWDukKW6EeuV8m6Bn6Xap0L0j6rsi9CBzAJOcWn
         1E624vp5X5OI6z6Tj9BqHi2d5bv3YirviNxXJxLEgom3HmBIaMkZHLjq11WaAVbnllnI
         yGhH8pMSWxSyxO8Zg5Jag8zLTQwxvwSvtwfs6D4VW+cv6bmNr44odQjQk5aKE1ujaAOA
         S3BZbvG06lqoJlhOLmY58pgsRZT4IdMQ09rF9CJUsBmsfHznsHc6mHiTT7kayyiIvNEx
         KEvmf05EBGIDDGt5tsNF3FVCZ8p7BQ3EcIGL5j0N8xBLHWTPKJeDnZytNCUIyLIdiN70
         JZdQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=lSXFQ1dE;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::42f as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1759200314; x=1759805114; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=esuym6wNDW692oPQZOlVSSoagBZryYOoYfqFZWSmXPM=;
        b=tTfcZHFLIiZuRQcEV68ugz5e3dvANdGQd1F/6ZaxgWBiJfD83+IBCEa1NJkJ1z6ewx
         JAoHwkw/P7sDYr/yrKEC039S2mQIPAH+a1l5olSM6qh9kuBpfpWI1c9FUoZnG1JoU5U2
         mExv/3LWkAAHOWrr4pNJagpmJxF6nJSfBUUPtCfuzAjlDtPxvGAalbyiqqHEIxCTivvt
         TJUliTTb36vbCtsuNdg6RjEyCgnw3RaR/+SVD4zth23tDzk/lOdG38mB2hhapiS1v8vL
         EMPiS7deJ+AavVfkr2/H+wRnIkK+bFJia9D5EIKPhv0rgc/rVOaKwiQ84Q53bKdovij3
         0DoA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1759200314; x=1759805114; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=esuym6wNDW692oPQZOlVSSoagBZryYOoYfqFZWSmXPM=;
        b=Ufrt4NxV4GZud0Em1xCu+Eq1X7WcO+WmXje4uTYn5v4+VrKekp7ZuYwOjq654R9yKE
         XF7q4jYaMps/wSkaAi5GZElyUbty4UurB8vNDFax34BHHmQZFYoCqM4OBnDu5Q2LaeDB
         Q5gYh8rqCRpEFF8JIyqKGRA8ANdCRkw4rKXElcXqMgM0IIBesW9//OdirgW5mt/OLnu+
         KEusK2Zm1GuUsgQ4f1uOGYMrBypDukDjjSZWwAPPy4z8QHY08AYJdjc1J9dJ8/DbolMY
         F3wkeX894at/NnbaRErppqDD7a8HAPFyptRdh7Do+MX66OFgwc/tbEdeS2awKZvEPQrL
         I6sw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1759200314; x=1759805114;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=esuym6wNDW692oPQZOlVSSoagBZryYOoYfqFZWSmXPM=;
        b=pySK7FnAcaQxOK/ioP/XPhWVw/Z9RqMRRBwWEv275QjBLQPwnNhjh+Yn2MFpHgykPS
         CFN3hBRF/T22uSK75wDa3sZyw/c8RSbRYpXNs98C5R8b8OXZeMsTTtiiaFSpQd+Zbip4
         YlOAVTXPcIAA17xUBdZYenUfc7Z/lpbsVemxyEVa1avUI5WfDkkw7j3cGF0pkNYb+6qJ
         3aOYmXL2ge4XhFcMPsjGZuH7ceScN0I/oBUXtWwlFdowclWz+K40jTXXqtn+5sxJPE0A
         /44Ew3abIXQBZL4MEe7mkPBIsRMprAt+pQLkAzm4l753EVldBwbv+8hK4Lw9pMIjDJEb
         43qQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCU5iB5J95gbs1fpqrO0vdcQ05oMyiepfUg06eNc4VKk5Wi4OHy1rXzgUZkxhpix15Egug0SDg==@lfdr.de
X-Gm-Message-State: AOJu0YxNEq+uIJHqHO6fDvNVWZBrqPFuDHznuvqVNlkCZwC65aUOKUhn
	P22PSxaRDlH9KE8N5NcLWcJDdeN5MlRnbsHS5L+cxx8MZASRB/Gn565L
X-Google-Smtp-Source: AGHT+IEP7G+fD4ra7ukncZErnj0/E9lcdqZkXM8b4MtiBU8CkcPw0ILsJvxjQ1iKIYRVshelJxaI8w==
X-Received: by 2002:a05:6a21:6f10:b0:2fd:a3b:9348 with SMTP id adf61e73a8af0-2fd0a3b93f6mr15545455637.59.1759200313866;
        Mon, 29 Sep 2025 19:45:13 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="ARHlJd6sqe8HrXn8GBLlreS5UCMFlAQbsiyDY8nYJ2M9b36UGA=="
Received: by 2002:a05:6a00:a469:b0:77f:fd9:9434 with SMTP id
 d2e1a72fcca58-780febe5e1cls4161992b3a.0.-pod-prod-02-us; Mon, 29 Sep 2025
 19:45:10 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXxTSeBpEJux2Q44N3e1CKuYTqk2JICdzUp7rqESgNWml7XKDQHMC1S+lXACeLN/KZs4IFlYa4xv4g=@googlegroups.com
X-Received: by 2002:a05:6a00:2191:b0:782:ec0f:d273 with SMTP id d2e1a72fcca58-782ec0fd83dmr8259436b3a.1.1759200310433;
        Mon, 29 Sep 2025 19:45:10 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1759200310; cv=none;
        d=google.com; s=arc-20240605;
        b=YuYQUdrbYuzgkuNxjenGUp1m2iPIb78gbqYhkcV+FtFXahujLrwsSbcYSzvJhnMp+l
         7tUGgX67dQbCTqH4Wdi1Oa/6C4YWMPXGp69WPFlQcrbNA6kxRVwKLcqOHcPxWXoStFr5
         YhHPYhXQ6cytW3vb5x9VnN6taK9Q2NohDWfKENTpJ4Pon1xeyTN27COgrYxUQP7BaNRL
         A4ozG/aCXo/+/YgMUQJ13Wd+Zp2tom1uIE1OMrbvEbmw8VTU9cRPIqdSsCCFO7veA5Sd
         e0OUvdL/Ytmv2nCQdKABtwFpE9lYW5JBBxASWEsJ1Ia9MBoEoF8dSNdNUKGFJRsW3QVQ
         7Otg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=VplC5p74+BCL3Xjzqw2UL/AL1hevTQUKrGPaYOT40mY=;
        fh=JEiL/w+suq2eeEA3LdO6F/elFFk0gkS2DqY9wj1MKRo=;
        b=fgB+TmSigXG4WzZkke2BgjFY0f2uy01B6z0utuVQsIY301PbLiQpg5pcFL5K/1FoKK
         l1Jr1BT7HQYNSvXLlZKi06BS5G66DAbm+fbrmvOFnT3AajWcz6QPo0jR+OQwCIDBnCYp
         dYbY923PLd4U37C5OnH98nx49GSGn68/557hVY8N4uHFtJ7SV5jaVez0ToRK9JV5BaNf
         GVZ9relmnrkipNQruhpbQZtWBgjb0IWIowFBXTvsOSXBZOWHbOSPatMYNg5K2nttivjo
         GUuzbx5KVf5cbhS3VTE+OALIGySiHB0Sjo4oq4HgoLCTAxTZGAzig4TtkcImmxDw62Se
         TsMg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=lSXFQ1dE;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::42f as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pf1-x42f.google.com (mail-pf1-x42f.google.com. [2607:f8b0:4864:20::42f])
        by gmr-mx.google.com with ESMTPS id d2e1a72fcca58-78102b59212si535668b3a.4.2025.09.29.19.45.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 29 Sep 2025 19:45:10 -0700 (PDT)
Received-SPF: pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::42f as permitted sender) client-ip=2607:f8b0:4864:20::42f;
Received: by mail-pf1-x42f.google.com with SMTP id d2e1a72fcca58-7841da939deso1841459b3a.2
        for <kasan-dev@googlegroups.com>; Mon, 29 Sep 2025 19:45:10 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCX7Gout+xlOPTxeJ0ajK4XkZAXiW0LsnsM8qiPL9AJ+XgPnKx1UgmwSt1ifgHvlFvm8J6W7eTMvQ0E=@googlegroups.com
X-Gm-Gg: ASbGnctqvfPnZJjuD2zdQuztuQ4bJ5HhiYHDPLcJjjZlAPovyv+igoqeXkuDn4HFMuR
	r0MOUDNXyh+ANhHRTKgcUvkTQG+0RTXR6HWW3Up+hUg/1wUd4UoijE7dp1sh4uOSaJTxNDmxcF4
	QGrBSn+pUwFKZpmcXVSKIHF6xwkvXpbQIPXEr4OXwpObZbYVWXXxRtoeg8VU5Gv930l6tN6FCIu
	07rIZanFMhO5VUrAhiyfFnqw8PjiShBJOXXA+ZnY7Qc5wyhmj2TdxKAJFOfNtiI+JN4L8SAyqIV
	aUWzPloGePC3vjKj3iLAEyHzheQD0Tv9XILU/gedlCiC3+b76QiMi4zNONS9BLyB+ofihD8LA2G
	bESGCzfzc9/Pk7hKvBTcALrmxbyiRHOx7lGfp4qZ5scBwDSXGuB9ufGxXNrkZS28N5mFoEE5sTv
	ts
X-Received: by 2002:a05:6a21:e098:b0:250:f80d:b355 with SMTP id adf61e73a8af0-2e7cdd9ffe2mr5395317637.33.1759200309894;
        Mon, 29 Sep 2025 19:45:09 -0700 (PDT)
Received: from localhost ([45.142.167.196])
        by smtp.gmail.com with ESMTPSA id d2e1a72fcca58-78102b23206sm12485889b3a.58.2025.09.29.19.45.09
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 29 Sep 2025 19:45:09 -0700 (PDT)
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
Subject: [PATCH v6 10/23] mm/ksw: support CPU hotplug
Date: Tue, 30 Sep 2025 10:43:31 +0800
Message-ID: <20250930024402.1043776-11-wangjinchao600@gmail.com>
X-Mailer: git-send-email 2.43.0
In-Reply-To: <20250930024402.1043776-1-wangjinchao600@gmail.com>
References: <20250930024402.1043776-1-wangjinchao600@gmail.com>
MIME-Version: 1.0
X-Original-Sender: wangjinchao600@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=lSXFQ1dE;       spf=pass
 (google.com: domain of wangjinchao600@gmail.com designates
 2607:f8b0:4864:20::42f as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
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

Register CPU online/offline callbacks via cpuhp_setup_state_nocalls()
so stack watches are installed/removed dynamically as CPUs come online
or go offline.

When a new CPU comes online, register a hardware breakpoint for the holder,
avoiding races with watch_on()/watch_off() that may run on another CPU. The
watch address will be updated the next time watch_on() is called.

Signed-off-by: Jinchao Wang <wangjinchao600@gmail.com>
---
 mm/kstackwatch/watch.c | 52 ++++++++++++++++++++++++++++++++++++++++++
 1 file changed, 52 insertions(+)

diff --git a/mm/kstackwatch/watch.c b/mm/kstackwatch/watch.c
index 722ffd9fda7c..f32b1e46168c 100644
--- a/mm/kstackwatch/watch.c
+++ b/mm/kstackwatch/watch.c
@@ -89,6 +89,48 @@ static void ksw_watch_on_local_cpu(void *info)
 	WARN(ret, "fail to reinstall HWBP on CPU%d ret %d", cpu, ret);
 }
 
+static int ksw_watch_cpu_online(unsigned int cpu)
+{
+	struct perf_event_attr attr;
+	struct ksw_watchpoint *wp;
+	call_single_data_t *csd;
+	struct perf_event *bp;
+
+	mutex_lock(&all_wp_mutex);
+	list_for_each_entry(wp, &all_wp_list, list) {
+		attr = wp->attr;
+		attr.bp_addr = (u64)&holder;
+		bp = perf_event_create_kernel_counter(&attr, cpu, NULL,
+						      ksw_watch_handler, wp);
+		if (IS_ERR(bp)) {
+			pr_warn("%s failed to create watch on CPU %d: %ld\n",
+				__func__, cpu, PTR_ERR(bp));
+			continue;
+		}
+
+		per_cpu(*wp->event, cpu) = bp;
+		csd = per_cpu_ptr(wp->csd, cpu);
+		INIT_CSD(csd, ksw_watch_on_local_cpu, wp);
+	}
+	mutex_unlock(&all_wp_mutex);
+	return 0;
+}
+
+static int ksw_watch_cpu_offline(unsigned int cpu)
+{
+	struct ksw_watchpoint *wp;
+	struct perf_event *bp;
+
+	mutex_lock(&all_wp_mutex);
+	list_for_each_entry(wp, &all_wp_list, list) {
+		bp = per_cpu(*wp->event, cpu);
+		if (bp)
+			unregister_hw_breakpoint(bp);
+	}
+	mutex_unlock(&all_wp_mutex);
+	return 0;
+}
+
 static void ksw_watch_update(struct ksw_watchpoint *wp, ulong addr, u16 len)
 {
 	call_single_data_t *csd;
@@ -210,6 +252,16 @@ int ksw_watch_init(void)
 	if (ret <= 0)
 		return -EBUSY;
 
+	ret = cpuhp_setup_state_nocalls(CPUHP_AP_ONLINE_DYN,
+					"kstackwatch:online",
+					ksw_watch_cpu_online,
+					ksw_watch_cpu_offline);
+	if (ret < 0) {
+		ksw_watch_free();
+		pr_err("Failed to register CPU hotplug notifier\n");
+		return ret;
+	}
+
 	return 0;
 }
 
-- 
2.43.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250930024402.1043776-11-wangjinchao600%40gmail.com.
