Return-Path: <kasan-dev+bncBD53XBUFWQDBBIOGZ7DAMGQEVPJN6PI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x339.google.com (mail-ot1-x339.google.com [IPv6:2607:f8b0:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id 07AAAB99D2E
	for <lists+kasan-dev@lfdr.de>; Wed, 24 Sep 2025 14:25:09 +0200 (CEST)
Received: by mail-ot1-x339.google.com with SMTP id 46e09a7af769-74381f4c715sf10939054a34.1
        for <lists+kasan-dev@lfdr.de>; Wed, 24 Sep 2025 05:25:08 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758716706; cv=pass;
        d=google.com; s=arc-20240605;
        b=QuHzHK1ETfwpUzgg8S1/tviSPrMW/61iRPccjug2ewqRfwyIqce2QlVAvb9B+axzE0
         vWYTg6I8T0SnTDwYIrNdXws1ItUElCuBzEDwh2urN3JynstvQJ9r+MU9APRNhEqlJKqJ
         tikWGDQ4f2IiJVLWU29Apz5lccZSd4Ct8VWs2YveZu33afn1gjV0BCb5NLrU44kEmN/e
         Xcgq0QqdB0XLGVo2pMbEi7nsE4WhHvIjfGv5G9joB3uo28OkcDl/6ZS5IellHHyx35uB
         +ksYaS1ZbIKh4HxSZSClfUGrEhR9dAaUdSh5ORxSiQApCzHbzgjiNBEWHqseBVn9xK2b
         SdfA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=KeR+DxV1S/zXAaI0KoX15923XY3pXmrHEHb9SsaWAVw=;
        fh=XklgSoWT2qTHnNzd7NwIqZS3RmiUIXEfs7i1cVpBmMI=;
        b=UYC6TYFVqWCEjkOpu72/3sAgkKX+n7eT9H3O+W2u4uyCkCJzEp802YuP1kOuUdmwzL
         uJ1YXkC/PhShPtiMr7udt2eJrIx5ZYPbEl8cHw+NEncbgw9qtnSbGdaOVFKjbzvuZ0br
         svH5ZBHKI/NcqiRHXPPQhJhs/Eh2kGTRfxMt8Why/B4RX1+sI9Dl44XXimHJZvyGOEMu
         iGVz6YiEed/sq6m6HvbPjfPjvljN5mYFrsFL391PrfKlPtXbLgBUegS3XsSSPdotg8Z9
         zsRtfVruk5M3wznGxRMFsrAevk2/S9ChJJhgguo5jDFjE+XeWxeu4DibDnHdkLcSqlST
         5kEA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=no8enjs2;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::1035 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758716706; x=1759321506; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=KeR+DxV1S/zXAaI0KoX15923XY3pXmrHEHb9SsaWAVw=;
        b=hVgfjIwnqmY079hIo7g3dHdnZis/S4gLjYYcaLXCtoJo6tC109mYZ0eEuECYIkdjnR
         /P0qDM2ubdcgxUsMsydC8sBYB7Gafkg7sUwBO4pf9O6FBchU/Lv7KJ773fL3D5FBSBPe
         SXJaMan+p8kjFw5SBdpkfSZ8NAP4jLHypGtdi+BuO27N9+PRH0BwsfQKicipL9Za+SLf
         IokMpFFhG3IwdBCFuYlazZyI58tGnjowLTWekRLFl5lsAp+6iDMg+woKgNgU7LqCQzr0
         bv6E8JwNRyjKv30lRaTVKcULwZLiymktAIZv7n9P2L+tvQp0G4/nVs1blSY4KHHPd/oK
         Uahw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1758716706; x=1759321506; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=KeR+DxV1S/zXAaI0KoX15923XY3pXmrHEHb9SsaWAVw=;
        b=Gyf/GhBQZanlgxZxbl5mK1daXVcmm0wKmGHo61t+WBabhXNjgFtJhPOdaQJlDObWS4
         M8Kr1yMWqjuHmWaagLJbJaGzkGr9nSn6ELxGdicomHeTZYfJlvX7ymWmg4pEyR3xCc7n
         3qecluC/m2PgmE/QJqBvH1UeE9k09tgctDu7DA1pI7SRSuKd4seA5tbyAzMi0HwtGl1x
         qfVA+J3rADglt92SdDq4x70i8gQld2thcMQKdHPvTXQjBxtQWFOC6rTLzQhWCmq17N0y
         5m3M+WavtH5M162nygNV0svmwNdnH9YatMqAM2sDS85LvLdyKV2bvxOo6HtEm9D9OiZw
         2eVQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758716706; x=1759321506;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=KeR+DxV1S/zXAaI0KoX15923XY3pXmrHEHb9SsaWAVw=;
        b=Ua3abSeq2dFqLGLMxECOkpyFrYH4k48BT7eMh1EVxTFefM3aS5qVuU/K+aJUAPH/fL
         BwvmXfE6AbBAQ9wKLrk86nYuoADRpq+pEqLC6/cI7oc1NcS7FJKA+t3CRjFaXTAj3mRk
         WtY75IRu/po6FsxqDkdhGE/w/EJoh0dxBmVeeLtPasvjjEmeLKfeTJJe5FOSEeEBUj6c
         oq86dvc+ajgxgrY9Ty1PFFYrQwOVhkMYPfgVrPbVvGhh9nvQFyk5ENKp791dTQfg9IAM
         wRZsfN1ehxqp8CmWuhkxHznREGhIuAm4vbDUbvmFsfbOcbk5xnQHDrnW+6ZsytC5oReo
         r0sw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXq9xnI02FImdSpkafisl/pi1Whp2C9qIYh0lO21LNvKeeelqle8lRw0qQuvtTyEYqDS9+jYQ==@lfdr.de
X-Gm-Message-State: AOJu0Yyfry7sayrRD/40xC0wXMqXqR+xM4QKsNCtIO3k1raXYYsDen/6
	7jSB2ZG+fsf7kFOn4wS9fOKi6MtPA3s+Eg12QulrNCBlWBPWCSaZQeTV
X-Google-Smtp-Source: AGHT+IExCvHYf58FgCRVg5ZgCOIB6qbSuM16ZA11KxHs/1UFsUIo5UmfwiJo3OsF+Xy6rKlMFnGIUQ==
X-Received: by 2002:a05:6830:2711:b0:788:d698:a0ad with SMTP id 46e09a7af769-7915ae6711fmr3144587a34.24.1758716706220;
        Wed, 24 Sep 2025 05:25:06 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd79zU3iH17qjkpv+2SJ8PgGqbLep/5fcGCfANsT2CD3QQ==
Received: by 2002:a05:6820:4d45:10b0:621:767d:3486 with SMTP id
 006d021491bc7-631cb7d8ab8ls1771692eaf.2.-pod-prod-05-us; Wed, 24 Sep 2025
 05:25:05 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCX5VptBlfIED5PvmkMuYLEDYx9UECXOPLTaMj9zxQY6l+oB2bJiHY6eK28pVoxvDtj1zWgVT+myCAw=@googlegroups.com
X-Received: by 2002:a05:6820:1b8d:b0:625:3106:d3da with SMTP id 006d021491bc7-6330796097cmr3121763eaf.2.1758716705234;
        Wed, 24 Sep 2025 05:25:05 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1758716705; cv=none;
        d=google.com; s=arc-20240605;
        b=hwHjrYBgeKgpG3ayImHm7+k8zVwJ7SmO4G3IIWU1cXrv/KwiL/tYvAHLjgnu6f3lZb
         YJF8Uaut13Nia9vUa8Bd/54vktxfhFnR8VT4oPqG+6J/RG1Djm28o1mpWPvltzGHoCfm
         1y9z3M5C7jIlhEZKDnYLrqwojfuhBHJQj5FqYh8yprsxOnCaqiYYxSWlL1wvA+zC4g3l
         qFkjgXIk/fNhiAwgbuqU+VMpB0d2lgp8L16Qd1Luui7y+rgFSbPRF9mSyteoQfr35spb
         TJwYO+4eDxNAbFnOBGBiLgkS+7uIpLvTLGUS7HKAANxiZEFtNYLSxr/xazZFVoHPNl6X
         EOBw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=5NW3rnfkFZjd7Zh69vJKiLybxjQ5f/0P49rVAWgM4UU=;
        fh=1KCJx+iz+TaMPOaI+PyXm/WMjvBUoUJq7NEWwm8kQAg=;
        b=AJciDrn+X+GCZ+WtMiOshIE0vNy5SfkoTtKFB1WFGce3WH485p/R64rf8qGTUw4lzV
         /sE2iEUz7WybH6qdxz23BgFEpZStsf/ZaOIfuVLiZqVbVSJOb05x3K1Eo7f9T9movlrd
         3ZgRROfQg40DGyh2xk4AQUPAFDiHnLhQePrMX3wMmhgSiGvBPJq5Y71+leo3/vuNZ5A8
         4raqsSquRsuwZgZjRSSSBw6lcsUsa3DCFyZ8HTomfUM7VzpwmbuN2kfEuOvLZ3bKW6bV
         V+8ijnriF02631f2ZUPSqimrUbkZGx348i1QrFIadcRyO44vCAwE/RmhULmxUmFzmanX
         WSrw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=no8enjs2;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::1035 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pj1-x1035.google.com (mail-pj1-x1035.google.com. [2607:f8b0:4864:20::1035])
        by gmr-mx.google.com with ESMTPS id 006d021491bc7-636b59e7e2bsi98373eaf.2.2025.09.24.05.25.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 24 Sep 2025 05:25:05 -0700 (PDT)
Received-SPF: pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::1035 as permitted sender) client-ip=2607:f8b0:4864:20::1035;
Received: by mail-pj1-x1035.google.com with SMTP id 98e67ed59e1d1-32ec291a325so5223749a91.1
        for <kasan-dev@googlegroups.com>; Wed, 24 Sep 2025 05:25:05 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVauEHpg5sS5Ij6NoOdYvTxSpRPcKpcAgdZf1BB75LZLVTVXWihcwLyWvo4OUiP+WDLvWcG83m3z2g=@googlegroups.com
X-Gm-Gg: ASbGncsF/EtVWEAbeghzZV/QWcetBWaksnhzJAgL3oo508uFYTDJxnMFd9K42GUzDkj
	bGea2vxYl4kMVXdJo5ZixYyhPObNj57lQ9bL3vvo5W6BRHQ+eTynx60BydUOVEXe4yDOw0D+8Rp
	ss4CR98ARUOkhM8i9f4x07y1mX7NMwbThq/9UM+mNE6bPutCDgwmgANP/23nHVLTtBS/UqwjzgW
	89otR8wFk4uzkTElSuRb2nL8t9pddMcZevFIPjhnWQcKXEoge/lrP6pJzNwtw56zLniBw32SeB1
	Ej9r47pyPGLqGINtRKp0SUJRtgauCssyDL18t8NNSRZTvVAbrUVJ0CNSwDfK9nKCcTeo2EdN4yL
	siysvz1PyCLEj+nMLpnv+TU0V5WP6cyfKiw==
X-Received: by 2002:a17:90b:380e:b0:32e:d600:4fdb with SMTP id 98e67ed59e1d1-332a95c804cmr7926585a91.18.1758716702994;
        Wed, 24 Sep 2025 05:25:02 -0700 (PDT)
Received: from localhost ([103.88.46.62])
        by smtp.gmail.com with ESMTPSA id 98e67ed59e1d1-3341bdd63c1sm2285996a91.26.2025.09.24.05.25.01
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 24 Sep 2025 05:25:02 -0700 (PDT)
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
Subject: [PATCH v5 07/23] mm/ksw: add HWBP pre-allocation
Date: Wed, 24 Sep 2025 20:24:40 +0800
Message-ID: <20250924122448.9101-1-wangjinchao600@gmail.com>
X-Mailer: git-send-email 2.43.0
In-Reply-To: <20250924115124.194940-1-wangjinchao600@gmail.com>
References: <20250924115124.194940-1-wangjinchao600@gmail.com>
MIME-Version: 1.0
X-Original-Sender: wangjinchao600@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=no8enjs2;       spf=pass
 (google.com: domain of wangjinchao600@gmail.com designates
 2607:f8b0:4864:20::1035 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250924122448.9101-1-wangjinchao600%40gmail.com.
