Return-Path: <kasan-dev+bncBD53XBUFWQDBB3EI5XDAMGQECWJ37FI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd39.google.com (mail-io1-xd39.google.com [IPv6:2607:f8b0:4864:20::d39])
	by mail.lfdr.de (Postfix) with ESMTPS id 183B6BAB102
	for <lists+kasan-dev@lfdr.de>; Tue, 30 Sep 2025 04:46:06 +0200 (CEST)
Received: by mail-io1-xd39.google.com with SMTP id ca18e2360f4ac-9265eff5c76sf176997539f.1
        for <lists+kasan-dev@lfdr.de>; Mon, 29 Sep 2025 19:46:06 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1759200365; cv=pass;
        d=google.com; s=arc-20240605;
        b=CEfU2kHXlrT4G/jo1WtgO8+pRWctNXnD99kWt228as/Hy2UT2fjjj0HH3pJnI07BHO
         ajLm8t1qrM3CINSyN02EKrKsZzsEOc6FZRc4NDusjvIMi67pJxsNxBI2eM46wkoPpfUq
         d23Q/kcahxp4IVyMVUzTMD7knFwPUczIReAA0TOulMy5QC5JeVZNkKzE7D3vIHk2yGfy
         xlteJ+8Qlr0960aSwrrRq03zN64l24UJsJHg4abGRbE/QprZZ9pLTQ4S2V/Q0AkpflkF
         2X5Kz3NHJ7uodMcZnE+t8/A4NDVvXz0qkk5v5bd8m3PBDZeihXLwV14zN0BstDfnAyPj
         KPjw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=FGxZoQnirgHsH8vBdif8N3y8v7MCkMMiid5jPtctQ9M=;
        fh=0kZeO9lhE7eYft5+uSPd2jQXovXiPZGod04Fub6vRQo=;
        b=fQb06NM1c7Ka4ZwGjCvwRrBNUQwK722+X7BY4DV6z30m2bgTVfpn+KNZkmHYrKTKlK
         952kFGJUMzJXo6hN8qPErJEAjVkkSBzbh3JTs+VaV0Wfrg/qnrPW9tHUJ3jNgJSlIxCU
         YykachoMjnLIDW/1oL1XJmNe93AtXzBquhecH6nCOrcEEJ/i0FuGYrJyBtbHqM16vwSW
         PysikfFLBvAacJ9Mc7JChj4INejsMLLulgTr0IANJ4tk8eIVtj/SWfBd4CbdcH7Flq9N
         Xx8/Qp4aIQY7uOKSorJyWzuGgaIQJj8l7uOYN+Y9aGJpGgfkNjqtqQLrqYd2mJ0e/sQT
         lZwQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=dNN9tKay;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::1030 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1759200364; x=1759805164; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=FGxZoQnirgHsH8vBdif8N3y8v7MCkMMiid5jPtctQ9M=;
        b=CQlBuHuGcbdEDmxLPoQpMdz2+nH0LvYYXQ/DApPEhsEV0xEI2emUF27utGsTVhW2DS
         nVwjHFRGK+9Smxh8mN1Jx0pPNOl9RSbf/IjKoISib3zOOZMvA88m44x/E/nHXMZZL/nn
         p8rZLV/+yoww2i3bPEuT7ZvUxMYOouKe6vBHIHfHODxXMHY7wJ/emIFj/doVwzTquL1w
         vnAIKuTzIqOOgF3LxDvtEqPq5jvNc5+WPy8QKQ5BNvQ5iQm6IC17Jwj428ZzXf0qqh8J
         1hHchoj6nDxz3BIIiN6hU1kSH5IGbd21P+GBoatCc/wAQbYK3GjcU64gtdlM3Hvojx7O
         1eMw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1759200364; x=1759805164; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=FGxZoQnirgHsH8vBdif8N3y8v7MCkMMiid5jPtctQ9M=;
        b=NGWDRi3f35O81rvpg2Wj7qOEBrHj3N7oAUl3JRV304dRdhpgtyFLmfGt76eThT/7EO
         t52yJc0f1xp/dUJorkNKc9ycH7mmABDVTiMJvd3EWP+cwIWeB3RlcY2Da4LtnNu/ao3G
         8dBAjyofqEL/uL1L0BwELiQuWI2HmQdIhRMMAyxckoY4WWY01BlV4v9ynzqZz100W6kv
         +Uk/HmQOp1AO9OqjAYJy7YcxaZdSVrmaJu9QDt8GcwSUiFauT9x9InWlyORZheTGULeV
         WQmsJlWPmDX24rQ3l+dzocAovY0i5lOhYOx0SIXsQsBCL2LU1KhCdn/fj+NkY5GCVlcO
         39QA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1759200364; x=1759805164;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=FGxZoQnirgHsH8vBdif8N3y8v7MCkMMiid5jPtctQ9M=;
        b=afSIv1W5CZmuUWQCS4XzE/k7qtjC6BlsgJRtleMOcPeTCbmdz6sATxvDqlsztnuHB6
         uOl0Yy7kzFgBgooKpmgmxLm7YyPHEyZvI8mV/9iGF0M8FRjNXfjoUaO1CQ5NzrvVREnj
         NWQg19uTwWHI8MsZZrEsd4iZ1utBatgLUwwXAQpx1bjewo0aq3opmT18oRGmIie1sBNu
         wWWCABUEapayi4Wk5pcrZ8q7L0U+T1yzTft7GajDcBEjKFbcprzzJbW3qh1jIFiCHWet
         DdezugEVSA+cHaJZGP5pUBI7UaqhO9Km/95eVDIkvbvqXxZwi3SWY2ofoJQtW7oB6z8K
         71sg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUQGrWLfQU/9uHis7XNkwfMuEx/4SJ1biAJ0DBXKst0GwroFyR4mOtI/pDR8c56a7/V32TiQQ==@lfdr.de
X-Gm-Message-State: AOJu0YwkxGmz9aXD15KuTBwETugFWdPenbyhT4Sj7Eh/OE2pI5vpOpWr
	z4etH5F9MxzcFEg45KSOmCdk7NLVEkASdGwbJyr/vO9bj1ebgogThlVf
X-Google-Smtp-Source: AGHT+IE/i35PwhDZFQEmtmMvOQKcFy5p1ToW94V38b38OsI/BSCNGsTv97RW5JFLQclN80l55qE17Q==
X-Received: by 2002:a05:6e02:219b:b0:425:849c:52fa with SMTP id e9e14a558f8ab-42d1113ba2bmr37713375ab.15.1759200364666;
        Mon, 29 Sep 2025 19:46:04 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="ARHlJd7ZYqbfHp2tFn6VKAUnFe7qqX83THm9dXlzBK30jptf4g=="
Received: by 2002:a05:6e02:4403:20b0:42a:1be2:88e5 with SMTP id
 e9e14a558f8ab-42a1bf1d04dls7224395ab.2.-pod-prod-00-us; Mon, 29 Sep 2025
 19:46:04 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCX29wutPvBV6lm0tllnLNj36AzNoGsprtYWyC9ixuJPqvAZUMlrC+bM0Kv+j10/qYZ4XIOxF9zGOQM=@googlegroups.com
X-Received: by 2002:a05:6e02:1fe5:b0:425:86d9:91ea with SMTP id e9e14a558f8ab-42d103977b1mr46977745ab.11.1759200363830;
        Mon, 29 Sep 2025 19:46:03 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1759200363; cv=none;
        d=google.com; s=arc-20240605;
        b=gtvvlHWO4QIlnku5p6tYCz6OEYs9pVd2I0UCDsHvyvUGKh0YE3utQDU8O2k6t//FlI
         F+M+ir6qU+L04QyLaZKq9cvKgVMMnqodF37YefASkYwZCttfwZGOSyndOILli8Cy5EKW
         jETfWDjMoFPvwmBtVYjUuy7USj0uUjGRrjNx65NiuYrrdqFBJk3bohWISZfh3wjqUrqs
         totlhRnqPQWrDydXKpat32YURJ6GkZDvVpCnhPdtGQHeKSdyC7VbJMtMSiiq/i+Y+imv
         Xzq3ESmhrSB64YloSqoBhjon4OqbE7qu7XntgnqHyE/wCuMO09aOXKKf/KnUG628tgKZ
         ZHCg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=PODRMG2Z8bUUhx/yC1VRhywhZMIHoJSOmQZCJHqYhJ8=;
        fh=gXPpqnhAZp24u/6wSqVrElVtaFJkSX95nPbG5JAIjHw=;
        b=dP7UOUXaKw9wvsDuQsJ/KKHHzX9F13UtMWTbG+9+JOOB6weizZDR1PNwpJvODjNdH/
         b4BIO3zqu2nG8kxZjpMukqDrbR4bEHsSZK6i3nm3gH3B04rvwbR7N6JCQLCeE+ArTdlL
         onMpQyKXvclscpdvqOdsAoitUlXxOevQmf4xyy5ALJobj4La2vTLDfUYf35KHqdQ46+E
         HYJ1E6MLJf8PSfsZ0YkGE8PYGIssvQE7oqrZEBpUL80Y2MXmWtL1fFH1nFqSRJ+BZVsI
         mXRXTXbw7l/qCPhjbIprxg0aKtDlydHr2iOn8iUfkoDxUQ9YFHXxbhN+Z0AmEl6wHkYK
         86wg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=dNN9tKay;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::1030 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pj1-x1030.google.com (mail-pj1-x1030.google.com. [2607:f8b0:4864:20::1030])
        by gmr-mx.google.com with ESMTPS id 8926c6da1cb9f-56a69ef2da1si354797173.7.2025.09.29.19.46.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 29 Sep 2025 19:46:03 -0700 (PDT)
Received-SPF: pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::1030 as permitted sender) client-ip=2607:f8b0:4864:20::1030;
Received: by mail-pj1-x1030.google.com with SMTP id 98e67ed59e1d1-32ee4817c43so4603293a91.0
        for <kasan-dev@googlegroups.com>; Mon, 29 Sep 2025 19:46:03 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXSWvWlQA5fQ9VKJfcWapxrWjNL6JGMOtZ0ka0gs1eApvGpKpoABatNmxMIbleltWPLZZ4324xzepc=@googlegroups.com
X-Gm-Gg: ASbGncsCApNJ8sWaqeGNkXtJJ5TnyopzzlHJ8oHR2ff+MJgDYwB4LUFOd43HIogcgdK
	fQclMedIqyIP33jUm5Jebb1F5a8qvIfMxTRjXpGRaziYdE8YBFmzD21wKuAfCHJS18FvaxU36Ut
	fPwjwnCZGguEe9Qx6IdUG+iBZChXYQOyaMN4D9fHUWvNK5D/nHarOKAWL4aYkZ3w5HvBoQl5AnY
	O2X7ny9o6iVoQpfsB1Mgaw+xyTlC3EWDEZmSrPa7JVRwtb1Y+KL/umWl6ihOld/BrixGPmD876f
	l+aNGLniCeW49yJsNzYPSM/3/2iMQpG7hzoGdxE3woh6vUNYtvAn9fqJWKBjOHThEwxYw02lJJS
	/sOAubHjE0Oxx9KgCOwu4YgPYi/Qg3o9jEBkJsNIXVL3EULms548wpdSya3VRxeFI2A2byXzh+x
	YL
X-Received: by 2002:a17:90b:264a:b0:32e:64ed:c20a with SMTP id 98e67ed59e1d1-3383aa8b143mr3140082a91.0.1759200362962;
        Mon, 29 Sep 2025 19:46:02 -0700 (PDT)
Received: from localhost ([45.142.167.196])
        by smtp.gmail.com with ESMTPSA id 98e67ed59e1d1-338387099d6sm2786368a91.10.2025.09.29.19.46.02
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 29 Sep 2025 19:46:02 -0700 (PDT)
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
Subject: [PATCH v6 21/23] tools/ksw: add test script
Date: Tue, 30 Sep 2025 10:43:42 +0800
Message-ID: <20250930024402.1043776-22-wangjinchao600@gmail.com>
X-Mailer: git-send-email 2.43.0
In-Reply-To: <20250930024402.1043776-1-wangjinchao600@gmail.com>
References: <20250930024402.1043776-1-wangjinchao600@gmail.com>
MIME-Version: 1.0
X-Original-Sender: wangjinchao600@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=dNN9tKay;       spf=pass
 (google.com: domain of wangjinchao600@gmail.com designates
 2607:f8b0:4864:20::1030 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
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

Provide a shell script to trigger test cases.

Signed-off-by: Jinchao Wang <wangjinchao600@gmail.com>
---
 tools/kstackwatch/kstackwatch_test.sh | 52 +++++++++++++++++++++++++++
 1 file changed, 52 insertions(+)
 create mode 100755 tools/kstackwatch/kstackwatch_test.sh

diff --git a/tools/kstackwatch/kstackwatch_test.sh b/tools/kstackwatch/kstackwatch_test.sh
new file mode 100755
index 000000000000..35cad036ecee
--- /dev/null
+++ b/tools/kstackwatch/kstackwatch_test.sh
@@ -0,0 +1,52 @@
+#!/bin/bash
+# SPDX-License-Identifier: GPL-2.0
+
+echo "IMPORTANT: Before running, make sure you have updated the config values!"
+
+usage() {
+	echo "Usage: $0 [0-5]"
+	echo "  0  - test watch fire"
+	echo "  1  - test canary overflow"
+	echo "  2  - test recursive depth"
+	echo "  3  - test silent corruption"
+	echo "  4  - test multi-threaded silent corruption"
+	echo "  5  - test multi-threaded overflow"
+}
+
+run_test() {
+	local test_num=$1
+	case "$test_num" in
+	0) echo fn=test_watch_fire fo=0x29 wl=8 >/sys/kernel/debug/kstackwatch/config
+	   echo test0 > /sys/kernel/debug/kstackwatch/test
+	   ;;
+	1) echo fn=test_canary_overflow fo=0x14 >/sys/kernel/debug/kstackwatch/config
+	   echo test1 >/sys/kernel/debug/kstackwatch/test
+	   ;;
+	2) echo fn=test_recursive_depth fo=0x2f dp=3 wl=8 so=0 >/sys/kernel/debug/kstackwatch/config
+	   echo test2 >/sys/kernel/debug/kstackwatch/test
+	   ;;
+	3) echo fn=test_mthread_victim fo=0x4c so=64 wl=8 >/sys/kernel/debug/kstackwatch/config
+	   echo test3 >/sys/kernel/debug/kstackwatch/test
+	   ;;
+	4) echo fn=test_mthread_victim fo=0x4c so=64 wl=8 >/sys/kernel/debug/kstackwatch/config
+	   echo test4 >/sys/kernel/debug/kstackwatch/test
+	   ;;
+	5) echo fn=test_mthread_buggy fo=0x16 so=0x100 wl=8 >/sys/kernel/debug/kstackwatch/config
+	   echo test5 >/sys/kernel/debug/kstackwatch/test
+	   ;;
+	*) usage
+	   exit 1 ;;
+	esac
+	# Reset watch after test
+	echo >/sys/kernel/debug/kstackwatch/config
+}
+
+# Check root and module
+[ "$EUID" -ne 0 ] && echo "Run as root" && exit 1
+for f in /sys/kernel/debug/kstackwatch/config /sys/kernel/debug/kstackwatch/test; do
+	[ ! -f "$f" ] && echo "$f not found" && exit 1
+done
+
+# Run
+[ -z "$1" ] && { usage; exit 0; }
+run_test "$1"
-- 
2.43.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250930024402.1043776-22-wangjinchao600%40gmail.com.
