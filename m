Return-Path: <kasan-dev+bncBD53XBUFWQDBBHUI5XDAMGQEZVNHDBQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23a.google.com (mail-oi1-x23a.google.com [IPv6:2607:f8b0:4864:20::23a])
	by mail.lfdr.de (Postfix) with ESMTPS id B77C9BAB0AE
	for <lists+kasan-dev@lfdr.de>; Tue, 30 Sep 2025 04:44:48 +0200 (CEST)
Received: by mail-oi1-x23a.google.com with SMTP id 5614622812f47-43f697f0315sf819631b6e.1
        for <lists+kasan-dev@lfdr.de>; Mon, 29 Sep 2025 19:44:48 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1759200287; cv=pass;
        d=google.com; s=arc-20240605;
        b=eT1FAC7QjNLSh3OY8ACvjLejuUYZrjzRt/vTR/lIL6EVs2rMhiayZwRMNHJW0BUr+j
         tEJUJUh6GjJSGKYZfWI37JE5zrmMNLOlbUMGLm7cen5BmIYZeyaIgnu2O/nzLLUwquq5
         ABMnnBZ4HrjhkebZ/JUD5hMSWmqLZijV8ffZyrOc8ZHYbH6BHmthTNOFEdbSCeVGpHN+
         juJzm/IZ5ve4uvbQswtVVPxWqvI105qrNUOq2z5KPvpWuUTKLw3iqznaatr4uup+g/i4
         kw6VRHbS/XUWPqIGITt1tX7D86b6rayfrdssWPUOQuLCkoiloFfGqjsTXDQfGfqU+BVj
         8OpQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=M6iL+1pRP6ZLXw7+BG1E9zi0XFRU36eZl8KsdI6hSM4=;
        fh=UoHFiPtCtdwb5cs5AIJoiVJ+OPe9SQ1ne2iIY8gNy6I=;
        b=PZVC6DCEDQgPEQg0/NIquPB69LjcwV3WSbFu6S1RV/Z9ttvsUrIODqFE7Al4AW7jgZ
         pu4fSxjbsVyR+elFmyndjH6Y5ginG9JlD4C0/PESmK+hzLgTOQ1jK4P+ftNq1ESy9lop
         0y/W8JRJMjJZJpeAJcL7lybrA0x+57YTvMx1G1D/ObYTEO9Si7G1IIAZxuYboKrCspqM
         w/HzcLpNM7x3ljgiLhEg+IGad+l8NsjCCpP5HMXIIaCOIx0wLjVAVlszMyeBGSWg0KAk
         EzsSeGwWE0DOoyW1toA4+rvkv24KL725bDlWXBdTqKrHTkXZfGI9/+/E4TEplpmq83V5
         y97g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=BNwwMIHK;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::102c as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1759200287; x=1759805087; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=M6iL+1pRP6ZLXw7+BG1E9zi0XFRU36eZl8KsdI6hSM4=;
        b=xJFz9CGWUM1VDfns2l8rZCtr8/uYjrEfyREvMRvbSdqWWB0qKI6GDiRwwfkOyHPNlH
         JPYA6g2LGjopcUOUnQqfAZqhth9aOsclWtOlVsfJp49sKyqW8yAXueLIjKU0ppZOG3PH
         Dzr9vu07H0JkAcWxuAitm0nt8bem84prwggY4TZyAn05bQus3PJAPkpdzsC9Sm1UVZ4j
         hNQ1cf5wTRy+hjA15XEffmBvDrt8ya+njDRezIVAxmmI2POR200UZJtCHxowDl0Bv636
         nwOOsDj0EJexmrM3QMOwdJgHPbXFgaCnIghNLP6F0/OqwAM77ZlQUl32/4NhiVOs9lNl
         3GjA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1759200287; x=1759805087; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=M6iL+1pRP6ZLXw7+BG1E9zi0XFRU36eZl8KsdI6hSM4=;
        b=UcgpgoWeZog8I+5jbkUwHjfRQ5O7wCQKouO3RQMuexabLC2yea6Q698CgMj0KjQiVL
         oOHN9/7Nf57L9jqwn84gThLpMqTNa8viWQVnnxLdLg+03xb3ruCvmS4iGoRO1qifCcKW
         VwQR4qkTMPWX4jEwzkXtbjvSEO3oWmz7mhF7cBzKiqv7Saz/fTcxn9LxnoTMkAny2Y4p
         P0bd0j/7LKAOn/YyNkDAzkYkJfsfOrNkszGW5MTgt1mHPzAAu+LE5BB3wIjmZN8KOJRl
         Z0+k8nyl257pxESF6yYuR2lsCcpuyk0v2WnTHuFtXlb79BIWdhBJdyRVpTBHeobViMhn
         3x3w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1759200287; x=1759805087;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=M6iL+1pRP6ZLXw7+BG1E9zi0XFRU36eZl8KsdI6hSM4=;
        b=iQt4hBzVMSM11/LRYPbf/2fd8eqGLqGTdp0D1kOztTTpHyeRSlrk8jUH5L2Z5hCXZP
         HumJxST6sDiY+v0xU0BeySa8kuO+AJBCHqKR7ttF1x8HKnqVwDfVn/6V3caR4Mu/NogT
         fkm49Ygre4q+K4tED/uPx35Tk9klt+f8WKxKt/GgTPV7v+OVeiXmAPNZcA77nxzfNtnZ
         qAwrfXy08Oq9r2xV4/F5USCfbB069jlaXGBAt6ndVrWkN+mtz1chuWhx58S3i01oHM1g
         /npgV2WB2AUf2mWjiTgk64iqVM2pAW8WF3w+gBNyFeHpLytmgvCYKKwt4tgBnYhVRIXx
         71wg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVoYSannjb8DKswTSD3oH04WHorCHP3wKT+n9gs+7rnZmx0yY8NPBSMqrJKhOYgdcmJ2jWePw==@lfdr.de
X-Gm-Message-State: AOJu0YxmjZgIsbvGTfPfkibullgMVEzl97hFgKyAF1umjxIkwLcFUcb9
	2OjWEtm93D8H8vmYZRQcY47s/TnZSwNmkdhW7E2jA35CIhw+FDw7z5cp
X-Google-Smtp-Source: AGHT+IGp8AzTg4mQZiYWF+l0T6gNAfrvgqK5Wp6BFuA6kblt3ca30vFwtJfpRticwWMkBjOHaMGNrA==
X-Received: by 2002:a05:6871:3305:b0:31d:7326:c3a7 with SMTP id 586e51a60fabf-35eeb2f2ef9mr10747289fac.41.1759200286932;
        Mon, 29 Sep 2025 19:44:46 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="ARHlJd64iPNGxmmN/2oXWM7s3xxfB87byqcsugmUiFuPjBvGWg=="
Received: by 2002:a05:6871:483:b0:31d:8f7d:c062 with SMTP id
 586e51a60fabf-35ec027b74dls1441388fac.0.-pod-prod-06-us; Mon, 29 Sep 2025
 19:44:46 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXV7WkYqhlqPTyRbM0PJ93j4mZKFt0J5SCYD5zwmvIh+dPf07ZeYjhVLxjJJikS8RcfiJ2MexxgWDA=@googlegroups.com
X-Received: by 2002:a05:6871:891:b0:2ff:8978:6be9 with SMTP id 586e51a60fabf-35ec101a5ccmr11517784fac.16.1759200286092;
        Mon, 29 Sep 2025 19:44:46 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1759200286; cv=none;
        d=google.com; s=arc-20240605;
        b=aqIkATHSUWR8P/x6LFba3/R1cOztj/AI4dYjGd9l3zG2KwJG9picm9tgsGXG6Q8jHy
         hWiy5YE3BhtE7eMU9/12fHyZwyV5+Fhr/n8W9dW4KxR2R4de6qP7wjCqAEE+DihEtXw5
         mIdXOUa9kiDnDSHZiukL5zIRH0E1nsv0f38PEVWa53U4KcK8ja/W8AF3P5vVH1xFmk1t
         YjWD055u5oyATVPN1v/DzLn1miybqYoVw05Uy4iEFN6gchf9oKS7bkZoiPR3uNtr8w3C
         wK/6hXu3L3yyjF6B4fR9en7OT3z0VyFdSgedqeX9gre0w7kNOb5D5hxWwVbESFruJnkK
         9tQQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=eGY4NXn9SYrwp2MIROIAsCXd8mHWC2w3iRZMJXUxzyw=;
        fh=MkEYl/+L+xvfDFUuVOtj9w+3OLeD7X6xes9FEPRgeMw=;
        b=Vh0ce2M4vUOuIJG+tbi4wip9HXVq14rmGB2Obmfa0R7kr4vLhH3ud1FWiFKjrWWPW9
         sE2Mh1v3fTlEzSD/ZHPYke/xywd3jyhGqDIcgCIMAh79x+yHVLd5uabJ3urKfD9FozHK
         MmRwHL8xi9zWJnSRnR8GyeLTgTaP7QoHlLtMBkR/QzezIe/cZB/kb3vmyxlXFQavvDVl
         xZLly0oatzqRNSGngCVBmYvZ2I4L1nYC6WDeow0177Spfsz+DOzUN6DO0XaFA8VjoXG2
         sm4379FfqckEqxPeg+docvpE4KgCIbYOtojM0K32AQ6U9mvJ1kJeARGXu/O5AL6/9v8o
         QbpA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=BNwwMIHK;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::102c as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pj1-x102c.google.com (mail-pj1-x102c.google.com. [2607:f8b0:4864:20::102c])
        by gmr-mx.google.com with ESMTPS id 006d021491bc7-63b208a9b97si432892eaf.2.2025.09.29.19.44.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 29 Sep 2025 19:44:46 -0700 (PDT)
Received-SPF: pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::102c as permitted sender) client-ip=2607:f8b0:4864:20::102c;
Received: by mail-pj1-x102c.google.com with SMTP id 98e67ed59e1d1-32eb76b9039so6285643a91.1
        for <kasan-dev@googlegroups.com>; Mon, 29 Sep 2025 19:44:46 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCViNVWPihj4TBQUM6FO+DHHw+6haaPs60ITGWyNuLFWI2EcawdgbaL/vlg/lrNh0BKFxh5SpstEI5g=@googlegroups.com
X-Gm-Gg: ASbGncuxcESDBZbrJ0HmOvaa2T0tOUULaiWIsMMrZ/qgd2VA6djVqii2uVkEKianS0a
	lH9PJYV6m+UQkDzkVQPUi38UtE+bLT6O+8NrsvygPmySZMB9QNFkIQFbRcA5or9yjCds0BobCv9
	sI6okEfCYPW4rKoy3Txjzgo2iwMBTAkj9t2kBZxtYbrJYki6O5AEymyJT7LYghxHI2W3p7j2HIw
	8GSxEKO1Cx/hI5tNcze6k12lt4aSu6pbEPdFlv+agCX+/m+JM2y0vIWz6HaJFUGGE8B2lFx4QH0
	yIuf5/ZXomZpHq3H8F6c14ZCELNwcyurtkK2LbZSTsGCusV/4Yh4J4Xjg5vrao7HPSPZ/EPadm9
	dc8LWfukYxDqYnW+cp4ENT410UjQzhJGaUI713qi+d1kqpSbdzZ0hyvg4vIvKcVOyoTk17zrKwO
	9+
X-Received: by 2002:a17:90b:1347:b0:330:6edd:9cf with SMTP id 98e67ed59e1d1-3342a2b0f1fmr20209339a91.22.1759200285220;
        Mon, 29 Sep 2025 19:44:45 -0700 (PDT)
Received: from localhost ([45.142.167.196])
        by smtp.gmail.com with ESMTPSA id 98e67ed59e1d1-3341bdac46bsm18593679a91.12.2025.09.29.19.44.44
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 29 Sep 2025 19:44:44 -0700 (PDT)
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
Subject: [PATCH v6 05/23] mm/ksw: add ksw_config struct and parser
Date: Tue, 30 Sep 2025 10:43:26 +0800
Message-ID: <20250930024402.1043776-6-wangjinchao600@gmail.com>
X-Mailer: git-send-email 2.43.0
In-Reply-To: <20250930024402.1043776-1-wangjinchao600@gmail.com>
References: <20250930024402.1043776-1-wangjinchao600@gmail.com>
MIME-Version: 1.0
X-Original-Sender: wangjinchao600@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=BNwwMIHK;       spf=pass
 (google.com: domain of wangjinchao600@gmail.com designates
 2607:f8b0:4864:20::102c as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
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

Add struct ksw_config and ksw_parse_config() to parse user string.

Signed-off-by: Jinchao Wang <wangjinchao600@gmail.com>
---
 mm/kstackwatch/kernel.c      | 112 +++++++++++++++++++++++++++++++++++
 mm/kstackwatch/kstackwatch.h |  27 +++++++++
 2 files changed, 139 insertions(+)

diff --git a/mm/kstackwatch/kernel.c b/mm/kstackwatch/kernel.c
index 78f1d019225f..3b7009033dd4 100644
--- a/mm/kstackwatch/kernel.c
+++ b/mm/kstackwatch/kernel.c
@@ -1,16 +1,128 @@
 // SPDX-License-Identifier: GPL-2.0
 #define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
 
+#include <linux/kstrtox.h>
 #include <linux/module.h>
+#include <linux/string.h>
+
+#include "kstackwatch.h"
+
+static struct ksw_config *ksw_config;
+
+struct param_map {
+	const char *name;       /* long name */
+	const char *short_name; /* short name (2 letters) */
+	size_t offset;          /* offsetof(struct ksw_config, field) */
+	bool is_string;         /* true for string */
+};
+
+/* macro generates both long and short name automatically */
+#define PMAP(field, short, is_str) \
+	{ #field, #short, offsetof(struct ksw_config, field), is_str }
+
+static const struct param_map ksw_params[] = {
+	PMAP(func_name,   fn, true),
+	PMAP(func_offset, fo, false),
+	PMAP(depth,       dp, false),
+	PMAP(max_watch,   mw, false),
+	PMAP(sp_offset,   so, false),
+	PMAP(watch_len,   wl, false),
+};
+
+static int ksw_parse_param(struct ksw_config *config, const char *key,
+			   const char *val)
+{
+	const struct param_map *pm = NULL;
+	int ret;
+
+	for (int i = 0; i < ARRAY_SIZE(ksw_params); i++) {
+		if (strcmp(key, ksw_params[i].name) == 0 ||
+		    strcmp(key, ksw_params[i].short_name) == 0) {
+			pm = &ksw_params[i];
+			break;
+		}
+	}
+
+	if (!pm)
+		return -EINVAL;
+
+	if (pm->is_string) {
+		char **dst = (char **)((char *)config + pm->offset);
+		*dst = kstrdup(val, GFP_KERNEL);
+		if (!*dst)
+			return -ENOMEM;
+	} else {
+		ret = kstrtou16(val, 0, (u16 *)((char *)config + pm->offset));
+		if (ret)
+			return ret;
+	}
+
+	return 0;
+}
+
+/*
+ * Configuration string format:
+ *    param_name=<value> [param_name=<value> ...]
+ *
+ * Required parameters:
+ * - func_name  |fn (str) : target function name
+ * - func_offset|fo (u16) : instruction pointer offset
+ *
+ * Optional parameters:
+ * - depth      |dp (u16) : recursion depth
+ * - max_watch  |mw (u16) : maximum number of watchpoints
+ * - sp_offset  |so (u16) : offset from stack pointer at func_offset
+ * - watch_len  |wl (u16) : watch length (1,2,4,8)
+ */
+static int __maybe_unused ksw_parse_config(char *buf, struct ksw_config *config)
+{
+	char *part, *key, *val;
+	int ret;
+
+	kfree(config->func_name);
+	kfree(config->user_input);
+	memset(ksw_config, 0, sizeof(*ksw_config));
+
+	buf = strim(buf);
+	config->user_input = kstrdup(buf, GFP_KERNEL);
+	if (!config->user_input)
+		return -ENOMEM;
+
+	while ((part = strsep(&buf, " \t\n")) != NULL) {
+		if (*part == '\0')
+			continue;
+
+		key = strsep(&part, "=");
+		val = part;
+		if (!key || !val)
+			continue;
+		ret = ksw_parse_param(config, key, val);
+		if (ret)
+			pr_warn("unsupported param %s=%s", key, val);
+	}
+
+	if (!config->func_name || !config->func_offset) {
+		pr_err("Missing required parameters: function or func_offset\n");
+		return -EINVAL;
+	}
+
+	return 0;
+}
 
 static int __init kstackwatch_init(void)
 {
+	ksw_config = kzalloc(sizeof(*ksw_config), GFP_KERNEL);
+	if (!ksw_config)
+		return -ENOMEM;
+
 	pr_info("module loaded\n");
 	return 0;
 }
 
 static void __exit kstackwatch_exit(void)
 {
+	kfree(ksw_config);
+
 	pr_info("module unloaded\n");
 }
 
diff --git a/mm/kstackwatch/kstackwatch.h b/mm/kstackwatch/kstackwatch.h
index 0273ef478a26..a7bad207f863 100644
--- a/mm/kstackwatch/kstackwatch.h
+++ b/mm/kstackwatch/kstackwatch.h
@@ -2,4 +2,31 @@
 #ifndef _KSTACKWATCH_H
 #define _KSTACKWATCH_H
 
+#include <linux/types.h>
+
+#define MAX_CONFIG_STR_LEN 128
+
+struct ksw_config {
+	char *func_name;
+	u16 depth;
+
+	/*
+	 * watched variable info:
+	 * - func_offset : instruction offset in the function, typically the
+	 *                 assignment of the watched variable, where ksw
+	 *                 registers a kprobe post-handler.
+	 * - sp_offset   : offset from stack pointer at func_offset. Usually 0.
+	 * - watch_len   : size of the watched variable (1, 2, 4, or 8 bytes).
+	 */
+	u16 func_offset;
+	u16 sp_offset;
+	u16 watch_len;
+
+	/* max number of hwbps that can be used */
+	u16 max_watch;
+
+	/* save to show */
+	char *user_input;
+};
+
 #endif /* _KSTACKWATCH_H */
-- 
2.43.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250930024402.1043776-6-wangjinchao600%40gmail.com.
