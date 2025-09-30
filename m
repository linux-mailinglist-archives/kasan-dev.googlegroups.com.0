Return-Path: <kasan-dev+bncBD53XBUFWQDBBJEI5XDAMGQEZJX47LI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3b.google.com (mail-oa1-x3b.google.com [IPv6:2001:4860:4864:20::3b])
	by mail.lfdr.de (Postfix) with ESMTPS id C03CCBAB0B4
	for <lists+kasan-dev@lfdr.de>; Tue, 30 Sep 2025 04:44:53 +0200 (CEST)
Received: by mail-oa1-x3b.google.com with SMTP id 586e51a60fabf-37ff38a39aesf2641800fac.3
        for <lists+kasan-dev@lfdr.de>; Mon, 29 Sep 2025 19:44:53 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1759200292; cv=pass;
        d=google.com; s=arc-20240605;
        b=Pa4xDL2zfY1IsN5/6EIw4iA/NIMddOS3gbGqMXBVAaW/sRzO02Gdn+0yI7l3dENX7S
         VgjhTMk0EmPR/mQCMOzXzTKewVvZ6A8NB0r99dh+7DWEvhLi6mkdQCPyYkN+Yx70E5Jg
         ZYim4GFrYtI2O+cVEmO0IEpIlXYPHPfEucp0l6esShLkJBADOqlBXXLLMN2/OdN2GEo2
         BMZLfwXeF7oGIWAN/RsgurvVGQDh3jM9+YzyYLEMTRtBNGY6+aWrTESxCeugS11v835i
         HXcsWeanhRw04eU8VXhpKBAdnvvSjwWTCSpuYGd0UCdaBuyEoQn13L16pNtksvxYP5Qw
         FX/w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=w3vQu/oaVkWK1myY9r4N966nTHqx/Q/KVEkL4CLvXLs=;
        fh=3TAtutKjBCCk6TdU+GNJxBJ5jXAadB4MaNldh7TYpxs=;
        b=RXRM53KmGlg5niYkPW7sy6/qelXXx5epiNVyQ4XOLYl4bC8ceJZT059tt5gxMtKyGf
         DQHxZcvdNlMfq1+SgOjA5HrabTjP4BeQyu4qoEZdHWf+vXwip3FkoCndeMIzLwqBjFT7
         ij/nfyP+TM1pLaWCkVfc4LHbwJatciTqPtDb7XDIEvqAe4o/MG8IPHjtO2nI3c/FuKnd
         43NwKYddgtaAJOUmhFIiHwwONLFZbO5Dvz3wchi600S+PPxzt2qW9me+5LE9gYXPlR2o
         TqY2f0kFX25DziM/pF6cOqvn4m/2orF3pDfpJqTmWCqxwMcQYRCDb1wIKpXNtFELn3wn
         Ew1A==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=XTStnrXq;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::102f as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1759200292; x=1759805092; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=w3vQu/oaVkWK1myY9r4N966nTHqx/Q/KVEkL4CLvXLs=;
        b=TlVjv24n1rOMoKJSld58ygHr07Tz36s7ONPguagUgr1+3WClN9ztxAyhEFV7JgHQ8m
         FXgGyaWpyzF6u+W7HLg5Ml8T4yyfKrVjHfLcp7oQ1ZIDSDta1fj2UZfeHVxWTnkEx1V6
         HPD86q6aOjTDQwEM4+QW3lhnILl/hl4btXAM3cDvXRVQ20ixKdv0Bef4M1zzPwQ6P6Ms
         NjO5S0+dNIbnsv1MaVkjJXWI0zyaaFR+PrKDMvKgYKQhVtOI4alfL3GjXLpVBWHDe/hX
         84jQjv6HqW1KJpQiXC1QRJeHfvtFUnmm2NuUKVbz1Oo+1/vjHUeLGBLmbg7RHl+lwZqH
         4NAg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1759200292; x=1759805092; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=w3vQu/oaVkWK1myY9r4N966nTHqx/Q/KVEkL4CLvXLs=;
        b=OfTL4QS9UDI07HaQQXwZPLHrFBcAYRFw4pJdNvGywApRqYS0PgOyghrDiyPisuOEbH
         gbo8iJ13dgdAnBRDYQ6vqzRB0S/+M5xObe27VBRcGxlzT3cu5YgxnqOqdv1Yi3K7m6zH
         cLVS86WYzTS+/dGqK7/432SRjP3iMzg5vvDZuVnQxUhh6jMs6269470/wwEYCq/JM0dW
         HcQhH9MorPzwslU5aZzfk8OoTlRzR2gBcUf9Ro8hkHU5hiymM8H7uCZNXvx075EMRJau
         fLY8eIHFTnStxACtBOIgNTmEC3X9Qh1tEykruKkZdthD8seNzMHlpue48zzm0Gxd3fMt
         wV1A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1759200292; x=1759805092;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=w3vQu/oaVkWK1myY9r4N966nTHqx/Q/KVEkL4CLvXLs=;
        b=vzGsneBxsZmBx7F35yS23QigWaEKGZca96PrdXpbBCXhgWbH5p4aFcvPEpeSbzZK1U
         2T67xLbkcxmdHOauzXsH5UVGMHUzd+wIn6ZTOhc63EQAo/5Glq0T0LmRtwvK8Uazxhi9
         5uc7AQf1oowEjl0FS1qhedE209qL2HGtxRonj0RXipnfXelzTbJQ0J80F0n63UAYtcI1
         2B69aUF0rR05bLuWEbmxsMxH6UE4H15PTWxBl/pDhyksz8tkqu3A+kkfFLP/4PtKz9wD
         5aL6dwhjljMaiexSdiBVwvcrknTxVWjhuKkrKpMPD7vd/uRywlmIUBdF3Sh1Qs+q1g0h
         2hSw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWR9xFbGt0SpYImEPY8LOMg2I6hNEp7zKBSSryFVOY6+zPU3KcN44GPVhDpzoXaurMx3+XYhA==@lfdr.de
X-Gm-Message-State: AOJu0YyPj8KUHwGWGg3xmDIzXOpA5UI97UlJoehZel4rxhYOhf9/ai+S
	BwfeUI85vcSXXlORbqso1GgJM8ZsriQrICpd3X9R8+7f0q6Pzod1JEVL
X-Google-Smtp-Source: AGHT+IFA4WV97x2pPUSA+RB5+PxgxADi1x1AzGjMB45wvNNgLgZugrNkQCbS05a1JqV02f5600bs8Q==
X-Received: by 2002:a05:6870:b488:b0:2b8:fab0:33c with SMTP id 586e51a60fabf-35ee74eb47emr9293521fac.23.1759200292481;
        Mon, 29 Sep 2025 19:44:52 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="ARHlJd4NmpdAxE32SqnAAierwTz7OjvyE/DzhbYFh4JsNzdWrw=="
Received: by 2002:a05:6870:3b06:b0:382:f33d:bc12 with SMTP id
 586e51a60fabf-382f34d25dals1867474fac.2.-pod-prod-09-us; Mon, 29 Sep 2025
 19:44:51 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWstjUVW01pEKrCrxPbnvgG4OvXJIJgLr6tnLfqRm+qGYGd2uHZXl1C9yrTGR9S4yPNMerdDoPVW9g=@googlegroups.com
X-Received: by 2002:a05:6870:7604:b0:322:4639:f397 with SMTP id 586e51a60fabf-36b0f21d995mr7801368fac.43.1759200291632;
        Mon, 29 Sep 2025 19:44:51 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1759200291; cv=none;
        d=google.com; s=arc-20240605;
        b=FLfjtBEA4xK2EizIBhaBrdB1+45BSPpd07d3DUG7dzw7AG8vdvcr7UUp2PX0k2bU6x
         duNgIHvcY/UkcExvobxMTNb5nN/wizgvDSwyDYMz0NQOqd91GJzzBUMZiE9qqoDpUHVG
         Fyy5y1RNxa+qp+FHNnEDePMDscbkKtkXKWvelVYmBrBgkGfCMZnXS/gt2G7m06NO9Ofi
         wdJkLzmH8eSe3GorMfVcC0pzTolG3YQV0h30Nzdve3X6jST5Hu7G6BppfWFHnF8UP05Q
         0Qg4o6Ryj0LEBxwyReHWwkrkI5HIcure3JRJ1xNX7AA9X3D007PwJXy/fpwBWXJ2uME/
         yIzA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=tH9NPPXYzjzWmBeV5TNMSRB6I94mkI1pmHDAIM87ayY=;
        fh=Gbgt84xljcl+vMfLTkVHUOXbrFqYFS0qRbTLxvtXqDA=;
        b=Ime6pq6ey0A7LxCVfFCofOPeDXnCOo65EsJonZZYW1gZ5WEmtKMl+3aOBMRDcyigFq
         4FMb9joQHu3ZY2VfBDS860QQwqMIaRFUbtGaZoLfIUcvas9DRcuwPTASH1tQTy5IJyKc
         NJjgE5m1sx+SlAtlCWO+w9ggBpwDD4LWl1U6f5NZSwlOqQT/OnP9V2qh9BR+n7LcS2SU
         LEww0j1AhnTuwqP/q7FPmZBPXBYWTBOaQ1ERAZdXqQfYvVkcxxNj6JhdmPtUJIoEjX6o
         KkWcYyee4JCaPzfok+gmt0RnSU1bPp/V8inZ2LEYIOL2CyqisykdrLwddmzuzCkqOBj6
         WOTA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=XTStnrXq;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::102f as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pj1-x102f.google.com (mail-pj1-x102f.google.com. [2607:f8b0:4864:20::102f])
        by gmr-mx.google.com with ESMTPS id 46e09a7af769-7a23e073b1bsi499281a34.4.2025.09.29.19.44.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 29 Sep 2025 19:44:51 -0700 (PDT)
Received-SPF: pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::102f as permitted sender) client-ip=2607:f8b0:4864:20::102f;
Received: by mail-pj1-x102f.google.com with SMTP id 98e67ed59e1d1-330a4d4359bso4899675a91.2
        for <kasan-dev@googlegroups.com>; Mon, 29 Sep 2025 19:44:51 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWxXsHJUlWPwRvWvj64pN18Z7oTV8AlRHkcuXEhhG+MDeWYJ3bqQ0Xw2ZxwOVYanHuXf0WMYOvfoaU=@googlegroups.com
X-Gm-Gg: ASbGncuvc74SIEESNTzVcT0Ev9l7w1D2sNXaoh+O32hnjZ/rd1oE+gLdh5hNN4TUj/z
	p/5rIapigYAziUaPRvegFfcrHURZ/GxvK+n2umNAku1e6ZfJjLca5COgJthFKFybgjQCQg8AbFI
	wBIZ8+I59CQMrl2dAwcVthRHUAEEiOEcEW0KuFVLGZUQl0z4K3Y7uwWgJ3BU5JeP/etS2xHUppy
	s5mFWiARtDmsa+jBmjUzAceuydh1DPSR1QS/hXO1EJDlcf8N6CFTHgabUVQR3NqzhQbktFSi85V
	gL/SVQnc7RIeq0YH/DF/dTys+NzKdDFlxo5AScyfStGl82pxI2IB2FqD9IoYY/BE4SrwSN9w8wS
	1Na5JlXADyTMdo0LZQv0a+jyk+jD0c9OLSLZVukXFlAfHTME1K8oS+UpqMN35nvKQmqj7PX7vGX
	g1
X-Received: by 2002:a17:90b:3ece:b0:32b:6145:fa63 with SMTP id 98e67ed59e1d1-3342a216f73mr19097573a91.4.1759200290701;
        Mon, 29 Sep 2025 19:44:50 -0700 (PDT)
Received: from localhost ([45.142.167.196])
        by smtp.gmail.com with ESMTPSA id 98e67ed59e1d1-3341be38382sm18526671a91.25.2025.09.29.19.44.49
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 29 Sep 2025 19:44:50 -0700 (PDT)
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
Subject: [PATCH v6 06/23] mm/ksw: add singleton debugfs interface
Date: Tue, 30 Sep 2025 10:43:27 +0800
Message-ID: <20250930024402.1043776-7-wangjinchao600@gmail.com>
X-Mailer: git-send-email 2.43.0
In-Reply-To: <20250930024402.1043776-1-wangjinchao600@gmail.com>
References: <20250930024402.1043776-1-wangjinchao600@gmail.com>
MIME-Version: 1.0
X-Original-Sender: wangjinchao600@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=XTStnrXq;       spf=pass
 (google.com: domain of wangjinchao600@gmail.com designates
 2607:f8b0:4864:20::102f as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
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

Provide the debugfs config file to read or update the configuration.
Only a single process can open this file at a time, enforced using atomic
config_file_busy, to prevent concurrent access.

ksw_get_config() exposes the configuration pointer as const.

Signed-off-by: Jinchao Wang <wangjinchao600@gmail.com>
---
 mm/kstackwatch/kernel.c      | 104 +++++++++++++++++++++++++++++++++--
 mm/kstackwatch/kstackwatch.h |   3 +
 2 files changed, 103 insertions(+), 4 deletions(-)

diff --git a/mm/kstackwatch/kernel.c b/mm/kstackwatch/kernel.c
index 3b7009033dd4..898ebb2966fe 100644
--- a/mm/kstackwatch/kernel.c
+++ b/mm/kstackwatch/kernel.c
@@ -1,13 +1,18 @@
 // SPDX-License-Identifier: GPL-2.0
 #define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
 
+#include <linux/debugfs.h>
 #include <linux/kstrtox.h>
 #include <linux/module.h>
 #include <linux/string.h>
+#include <linux/uaccess.h>
 
 #include "kstackwatch.h"
 
+static atomic_t dbgfs_config_busy = ATOMIC_INIT(0);
 static struct ksw_config *ksw_config;
+static struct dentry *dbgfs_config;
+static struct dentry *dbgfs_dir;
 
 struct param_map {
 	const char *name;       /* long name */
@@ -74,7 +79,7 @@ static int ksw_parse_param(struct ksw_config *config, const char *key,
  * - sp_offset  |so (u16) : offset from stack pointer at func_offset
  * - watch_len  |wl (u16) : watch length (1,2,4,8)
  */
-static int __maybe_unused ksw_parse_config(char *buf, struct ksw_config *config)
+static int ksw_parse_config(char *buf, struct ksw_config *config)
 {
 	char *part, *key, *val;
 	int ret;
@@ -109,20 +114,111 @@ static int __maybe_unused ksw_parse_config(char *buf, struct ksw_config *config)
 	return 0;
 }
 
+static ssize_t ksw_dbgfs_read(struct file *file, char __user *buf, size_t count,
+			      loff_t *ppos)
+{
+	return simple_read_from_buffer(buf, count, ppos, ksw_config->user_input,
+		ksw_config->user_input ? strlen(ksw_config->user_input) : 0);
+}
+
+static ssize_t ksw_dbgfs_write(struct file *file, const char __user *buffer,
+			       size_t count, loff_t *ppos)
+{
+	char input[MAX_CONFIG_STR_LEN];
+	int ret;
+
+	if (count == 0 || count >= sizeof(input))
+		return -EINVAL;
+
+	if (copy_from_user(input, buffer, count))
+		return -EFAULT;
+
+	input[count] = '\0';
+	strim(input);
+
+	if (!strlen(input)) {
+		pr_info("config cleared\n");
+		return count;
+	}
+
+	ret = ksw_parse_config(input, ksw_config);
+	if (ret) {
+		pr_err("Failed to parse config %d\n", ret);
+		return ret;
+	}
+
+	return count;
+}
+
+static int ksw_dbgfs_open(struct inode *inode, struct file *file)
+{
+	if (atomic_cmpxchg(&dbgfs_config_busy, 0, 1))
+		return -EBUSY;
+	return 0;
+}
+
+static int ksw_dbgfs_release(struct inode *inode, struct file *file)
+{
+	atomic_set(&dbgfs_config_busy, 0);
+	return 0;
+}
+
+static const struct file_operations kstackwatch_fops = {
+	.owner = THIS_MODULE,
+	.open = ksw_dbgfs_open,
+	.read = ksw_dbgfs_read,
+	.write = ksw_dbgfs_write,
+	.release = ksw_dbgfs_release,
+	.llseek = default_llseek,
+};
+
+const struct ksw_config *ksw_get_config(void)
+{
+	return ksw_config;
+}
+
 static int __init kstackwatch_init(void)
 {
+	int ret = 0;
+
 	ksw_config = kzalloc(sizeof(*ksw_config), GFP_KERNEL);
-	if (!ksw_config)
-		return -ENOMEM;
+	if (!ksw_config) {
+		ret = -ENOMEM;
+		goto err_alloc;
+	}
+
+	dbgfs_dir = debugfs_create_dir("kstackwatch", NULL);
+	if (!dbgfs_dir) {
+		ret = -ENOMEM;
+		goto err_dir;
+	}
+
+	dbgfs_config = debugfs_create_file("config", 0600, dbgfs_dir, NULL,
+				       &kstackwatch_fops);
+	if (!dbgfs_config) {
+		ret = -ENOMEM;
+		goto err_file;
+	}
 
 	pr_info("module loaded\n");
 	return 0;
+
+err_file:
+	debugfs_remove_recursive(dbgfs_dir);
+	dbgfs_dir = NULL;
+err_dir:
+	kfree(ksw_config);
+	ksw_config = NULL;
+err_alloc:
+	return ret;
 }
 
 static void __exit kstackwatch_exit(void)
 {
+	debugfs_remove_recursive(dbgfs_dir);
+	kfree(ksw_config->func_name);
+	kfree(ksw_config->user_input);
 	kfree(ksw_config);
-
 	pr_info("module unloaded\n");
 }
 
diff --git a/mm/kstackwatch/kstackwatch.h b/mm/kstackwatch/kstackwatch.h
index a7bad207f863..983125d5cf18 100644
--- a/mm/kstackwatch/kstackwatch.h
+++ b/mm/kstackwatch/kstackwatch.h
@@ -29,4 +29,7 @@ struct ksw_config {
 	char *user_input;
 };
 
+// singleton, only modified in kernel.c
+const struct ksw_config *ksw_get_config(void);
+
 #endif /* _KSTACKWATCH_H */
-- 
2.43.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250930024402.1043776-7-wangjinchao600%40gmail.com.
