Return-Path: <kasan-dev+bncBD53XBUFWQDBBGNKT3DQMGQEW3JK4UI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yx1-xb13c.google.com (mail-yx1-xb13c.google.com [IPv6:2607:f8b0:4864:20::b13c])
	by mail.lfdr.de (Postfix) with ESMTPS id B2C77BC89F3
	for <lists+kasan-dev@lfdr.de>; Thu, 09 Oct 2025 12:57:30 +0200 (CEST)
Received: by mail-yx1-xb13c.google.com with SMTP id 956f58d0204a3-6365645cadesf1591751d50.1
        for <lists+kasan-dev@lfdr.de>; Thu, 09 Oct 2025 03:57:30 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1760007449; cv=pass;
        d=google.com; s=arc-20240605;
        b=KkZ00f3Ygffh3EA5pprqOjuqvjePawiYt9ITYgAZh+o+dZC5PZZX3NQCKkMEl7WaaE
         kc4AGUd58/QJDLw071lJgo6OX3cbM5HDFtrs1qNvryL0lnesAy7FEy8Su/oT1KPz7tQP
         DAAR19uCm0hTJZhogPNsrOseT44zQZy9ND8xhMy/7G41/8k3Q0/ZO5s0jfNQ/sxrr36C
         JqlheXGN/qTjzXRvS4wUqPSwRK/oDoVrEQSYKWbmK6oFxVrIA8tFH+XH/lflHe0WKj7d
         SABqZwQK4UFA1QIQyBR5e2rrz3WzgzkU0vb2IBukkWbMcGBMVxKIT4wA7ri3gaIQMBpW
         NEAQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=5grpQrrIeElumG9oC7YSpvkNqn6DwSH3DO57OApK9zA=;
        fh=Umczdu0zU9gNPDn1iTgFCbA3rCzjGBHvmd8uwQmulU4=;
        b=U1UtfBYkCppZ52Rof1HuuHotN/hIXArUw386B37o/zhH2RC6/DGYIhtfXaRXJ3xJYQ
         HrAtH3BilQMB8wbc244hXHaShdmM/rnsprtzUbfGOazfarWTIN58ASEc/7eMkqY+48dX
         4DP27i4Rm0P4/rvpxP5Y6wOygzg89BqrUwP4szwQrty0ajuBaWLXRLmHeaC2l7BLofYk
         i4IMKvdiTXr7q8cca+dCRLqibJ7E78WeP7tXaNPXXZfGanYlpItQneaiZwYNbPi11WyH
         T2W3o4hCWKnrDe4n1BLpeZ8kEWNe6xotai6CP/vXHf11k50Qh/2Szkx3EMLUcQ+m8uy9
         /lbA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b="b3WF/i2b";
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::432 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1760007449; x=1760612249; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=5grpQrrIeElumG9oC7YSpvkNqn6DwSH3DO57OApK9zA=;
        b=cUAuPCA7shm8e6ZbIT6HRCXb/5zMpdszhDIklTrynsxNZayFgFm5VEtTnoEH07Rsfo
         qKXAlWeAEqJUW5kXwArkEb/2DSuy3LEeTFe9hxuIH/q70WhaeHIaW8dzf1e1LRKwQEFH
         s7lRpKxSgSHnlPOidx6WzfuG6M3xeMDMxYWMrVbBUX+GoiNk6UcFBdfE+rRN1z2jJmVj
         o7sqaygUGUNWhw56HsfHmAoKXBNZHNopQ1INFzJHTQpaKKb8pOB3MydH5xEV1YSmap6i
         0C+b6ALDEgfoCqKh/p/93yuDAmiWOu37qSKr9F3LwaZ2a4zTntfudF1O5FMVA8feNMsr
         ROLQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1760007449; x=1760612249; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=5grpQrrIeElumG9oC7YSpvkNqn6DwSH3DO57OApK9zA=;
        b=aNzRlZQWs6BetYyfVSbswNjXt166koqYoQc9caYzDEaqKSeBTSUgWHKcGRnO9qIYfR
         tgpflEr0gCfwFoZ1GHtm485BT0Wd2rka/b3ctBAqmiWJo5RWcXD2YRPrzzuS6Ea7GkpE
         QmwPmcLreJVvwf0aYh98uazFB+Q2MPg/pFf2YagG10O0O7eqsAxJq6Sx6Sgu/pxL2x/V
         DoYehaZbMnXqY1z2xKVgiXowaI9TB0azht5CgRqWY/8KNiQyq8DESh6I9oL+3/E92c8X
         bxZ8fnvUfDto10WVZ6JUmm0pD6krcsMgieA6qwEbF5v2TuPgqU9g451QXCdFylzFkm9p
         GCzw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1760007449; x=1760612249;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=5grpQrrIeElumG9oC7YSpvkNqn6DwSH3DO57OApK9zA=;
        b=UUauSpJbQ5/l7lfravncyt4OTWu28t8gLBm7AWMLctdzSZc6+ZrZA0xt7NhiHs5KHE
         9qu5HKMCEZBhIdtKqGnNAre71zfd1TA5c4zErpEd45o6rRZisCMZrPQNBvFEiaNEqojC
         r6PhSfe12c58Hija3ytiQgx4UPrwhPRHSZyb/RO2V/GGi/0JtgmqLbg8G/Fp4YUx1j4M
         P+nkHP4q9z/xrkgssEaKuk4VsbbxFWEXD7r/cRCDhsy7fVXNvjJr2GUXIMF0nlwhtL9U
         /LCVSM1Ax8lF0+jMQVtHEBSBeDkpYkvZqL+X/AEedfnRN2bjOl1orUEdJpoNd7nXSsIk
         9fKQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWXmMP4DHg3TE8Gdc5Qo1Gpx/A9ZuCXyCJFgegABkUNAWVFwHAc2vSp+yWhaUh1pDTs9F5Mug==@lfdr.de
X-Gm-Message-State: AOJu0YyxyHn7Nz+AYHDARtUNJU9YhQHE/uONDZcBjA+uXSBVjwqJxCNQ
	EftuXKLDfuDlhrCbVREaJDKetxzNsNzxhHRd5pAL92cGnXxQwb+uJdaL
X-Google-Smtp-Source: AGHT+IHkruNXySOSrJR0N720z4LG59ZUvhhW1pcwLErUR7ZeKmq7UkIaeMG8zD9Ya7KQoZuRnMpqtw==
X-Received: by 2002:a53:c056:0:10b0:636:1f2f:da64 with SMTP id 956f58d0204a3-63ccb8ec1d7mr5396736d50.27.1760007449410;
        Thu, 09 Oct 2025 03:57:29 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="ARHlJd6LFyeH4JQ+XEryiukD43/+/eNo7hYdcFjZ+IbE8lZnCQ=="
Received: by 2002:a53:a010:0:b0:5f3:b6f7:98fb with SMTP id 956f58d0204a3-63cd9807ffels869753d50.2.-pod-prod-09-us;
 Thu, 09 Oct 2025 03:57:28 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUY+DlZE5TbwGVnonBH4YKoqaWl4XmjVPvW0rNcSA0qT2vJ+3zJSqTWJt/mPNSjVwzkQwFkylEJh/4=@googlegroups.com
X-Received: by 2002:a05:690c:d93:b0:781:185:c4f8 with SMTP id 00721157ae682-7810185db41mr2282437b3.44.1760007448555;
        Thu, 09 Oct 2025 03:57:28 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1760007448; cv=none;
        d=google.com; s=arc-20240605;
        b=Pnag2LfaK71j45zvBE5kHjFXWovNUxTeJt/vQWpp3skSGmcHOlnl9XHKoxiP8SvINU
         EVHY4J6qyngep8+qleER4lVSnvCuwY8KPK8M36FDE4EmUFViwVpPrt9rZnapzqmfALYO
         3jSX9I1Q6eETftKnCqqoEfVF8H18ADcQPz5b9QkqMp8jWiEHtRMLivZXA4eRum0nxOIv
         lmKS/SDtfjZ53Dl7FekCPgtRePOYGHMppTfyQtjLLeHH/nIC1GzmEDedR8Oe+lVCeIMo
         YcEM5ywvJrCuHqF9ltONoB2T5kjXUF3DXyKVsZtw9am6Zv3VmU6QGzV4iK6vXyH/kytv
         u8Yw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=eGY4NXn9SYrwp2MIROIAsCXd8mHWC2w3iRZMJXUxzyw=;
        fh=fSLkn+F8XHAqmTPeUTe759/EUSe8cePezuMjwpU2spI=;
        b=LxXjthXpBgSppZV4Da0mcd27P9UPXgLFd3cmr8f+sUJxfw7hYlaU321JqwaOOYXNpy
         ZTHvaNQ4fBninsosZcjnsiDZzGj3bNdtvLx8dIKLwekIz/xjid8kF9/hrYEkWAPzRnq9
         m//W85ZxHsfDckf3l6j1xog8hil/s/XD2+ctT+t+lARDondzV/gHo9/wwJ59oKIG1bam
         ynLGGh2pOsowW32kaVBrfqG9upcpSxBw5WHn3hmEi0FhmYodwAFPSOPKFQIe7hiCHuN4
         xpoKGe4vMeNwl5h7dC0cXZLFBbc7q0oTQpQpBbjuhOjgaqN86coD7Iz8ZEuKRfU3Nnxa
         zb8A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b="b3WF/i2b";
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::432 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pf1-x432.google.com (mail-pf1-x432.google.com. [2607:f8b0:4864:20::432])
        by gmr-mx.google.com with ESMTPS id 00721157ae682-780f625cdd4si684527b3.3.2025.10.09.03.57.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 09 Oct 2025 03:57:28 -0700 (PDT)
Received-SPF: pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::432 as permitted sender) client-ip=2607:f8b0:4864:20::432;
Received: by mail-pf1-x432.google.com with SMTP id d2e1a72fcca58-793021f348fso734990b3a.1
        for <kasan-dev@googlegroups.com>; Thu, 09 Oct 2025 03:57:28 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCX6RgxPl/tWuBj+86udig4mUIanvTge6S4eQQwOgBdzSLSbdEZwMFkE5LixCEanfchdF//zSHEm5CA=@googlegroups.com
X-Gm-Gg: ASbGncvUvtIl9oOozjz+5cxK6Q2bi6ITZWUI4uZVZqNj0mdacUK4YNi2648TbQGMdTc
	KpGR5bl1cxQEPXSbpBlBobjejlit32o/Q78SDArer5UQzNVJjmx2JleDHTzldBObSOjuwXEQ1JO
	jEiQkGDyN1P3NW24X1dGD9gAZdjvT8t0pfpc/63uwpOt5ARvm3s2Uhh79Qake9jtDo8k/9xMQlC
	/ixTe+kOYFW74KbWmBeLGjsSkV7LaxBmnUdRr3mNcC5pbvC/TKWI4ngk8ShqeillPaZF5fgxCih
	AvySrFkp/l6R79baudaKcu96EpB/QT801Y3UneVNkQpH+EbTpRxdCHCqXZ/i85k5boAg673oSsB
	sTQ3hVDuyJzZoBaWgBh26MgYHJJO8SREblOQeGexf7ZbyXvc+FpuMymgPeX5F
X-Received: by 2002:a05:6300:40d:b0:32d:b925:74ea with SMTP id adf61e73a8af0-32db9258839mr3446528637.11.1760007447507;
        Thu, 09 Oct 2025 03:57:27 -0700 (PDT)
Received: from localhost ([45.142.165.62])
        by smtp.gmail.com with ESMTPSA id 41be03b00d2f7-b61ac27c74esm18963329a12.33.2025.10.09.03.57.26
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 09 Oct 2025 03:57:27 -0700 (PDT)
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
Subject: [PATCH v7 05/23] mm/ksw: add ksw_config struct and parser
Date: Thu,  9 Oct 2025 18:55:41 +0800
Message-ID: <20251009105650.168917-6-wangjinchao600@gmail.com>
X-Mailer: git-send-email 2.43.0
In-Reply-To: <20251009105650.168917-1-wangjinchao600@gmail.com>
References: <20251009105650.168917-1-wangjinchao600@gmail.com>
MIME-Version: 1.0
X-Original-Sender: wangjinchao600@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b="b3WF/i2b";       spf=pass
 (google.com: domain of wangjinchao600@gmail.com designates
 2607:f8b0:4864:20::432 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251009105650.168917-6-wangjinchao600%40gmail.com.
