Return-Path: <kasan-dev+bncBD53XBUFWQDBBR4I5XDAMGQES7FC3FI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x40.google.com (mail-oa1-x40.google.com [IPv6:2001:4860:4864:20::40])
	by mail.lfdr.de (Postfix) with ESMTPS id 0106FBAB0D8
	for <lists+kasan-dev@lfdr.de>; Tue, 30 Sep 2025 04:45:29 +0200 (CEST)
Received: by mail-oa1-x40.google.com with SMTP id 586e51a60fabf-329207bfba3sf5266586fac.0
        for <lists+kasan-dev@lfdr.de>; Mon, 29 Sep 2025 19:45:28 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1759200327; cv=pass;
        d=google.com; s=arc-20240605;
        b=Aw5xcC0gtBzr7pbAWAmVwN7d2mUXqGYnPz0N4Ir+iq+EkiBVMDSgxT3NMuOKehBvSQ
         tWC3JBhSDdl4H4tFZuSksYbgNrd2wISLSnBJidSUxvygQ7EipVpzYfoansTEHFl6VD3S
         wO8H5HKsNL3kSN6j9S4lLE0Oer4P5KLoAke/U7dk8ASvDJFYTLETD5+wNwNw+OSoFbii
         aFsKSG3p37tUxSw8R5VLlGIRWSqnThw4A/rjoifNTvR3a1kux0y+3+7YyoYO7wlGpzev
         dr/dQ+oePbe7ORcrm3DKe2vBVrG34GKOG/dsA4Bmpmg0ilj+sGN/OKP4MwiJv/nM2xh5
         jBNA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=82rVN9TTrsTewNfCXXhg30vhNo1yWIr0N7lvyubs0RI=;
        fh=0FvWamlxOVZFMPtNzYmXBkvS5poECMBLolcnXp41Do0=;
        b=idDvwziw04AJ6ykinTz4iN+F7knVXXD26qhBJnWU7mzZ42x4I+EWEU3tX2lqRot7fy
         3NTg7f7Lud3ByZN5d4hGvmcv7fyzN6GPz4Hnomn1Eun8+vU+HATYuOO/8wwQ0ncVzK14
         KiWcA1O7D9O1eqF7623Oe+J6MfJshnsYm0RjBWtvySrgselJRe2eXJsaQN8FYUnky7bm
         hDFs3cJl5mRb1G5b4RktVPYMOW9jKjjzL7BGfytt+wjlL3DZCLx8Kn9pXoFn+4YkDKA3
         J6V+9oKN6GsDjoNs0+bApo+WLXsDK3DKLKwbm7QUv36N+3K8q1clG8CKo+KNbqORWhPO
         1Rgw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=eIRCALum;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::52a as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1759200327; x=1759805127; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=82rVN9TTrsTewNfCXXhg30vhNo1yWIr0N7lvyubs0RI=;
        b=TM/kXVDGEG/Ay/ZmYlvMDZbP03BqhMvSGmIRUQ1NScxy2mdQ9bDmZc3XUKz7CuReVO
         /KlbR6TuDQc6paV2st5h8dOdRrse5wuQhi5bwH2XtPf1HMU9NIOiaa0g8MFFWEiCjB9d
         i+EXp0XzpsdqIPK5aX0f662iR6QRKkcNxRpeF4pTfuM2mi4pdUtho2F4PokTtNuWVM93
         5SmUMVwTel1XffhkKn2X3N1T7aqDQnfy6eovbG8kbNAE/ZOGn/OFZEDW+jj9BKgLxCus
         CUTeUKJK7EQ1b5p6No4vrp6Gg0m8RdxydpZDLnTQ+Y/I5QY605WG0uHH4XjD9mdBotf5
         Gc3w==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1759200327; x=1759805127; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=82rVN9TTrsTewNfCXXhg30vhNo1yWIr0N7lvyubs0RI=;
        b=NykfDIXom7ip3+1YQy8qA6O8aDO6Feyi2TJfQgUCL+IvgPuFezIt9970rGN5bLklw7
         GcuA8874tKqEE62vgIhp6FmPJpzXsbXogRs3LrFUey8fRF9I1RJAwZwR7cgDKAk/vR2E
         1MU8gj5aWTRVpJ8szzX94eYioOp3xcx458GkmaxQzT+UZUuk0R089qH9KkTo3yp0JFp9
         CIvq0sfIQ8hirn9TbjRu8oWtVMQxPGTS+m+cVTGbQHmFpxrB3kkkyW/J+MVDIzsMhba7
         cXA9euRzWPZMOg85Chkcn7iwlbTNb24n6tOHHnSKoNUMPxM7nBNImAj1wHdC7bpE9tom
         wYpg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1759200327; x=1759805127;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=82rVN9TTrsTewNfCXXhg30vhNo1yWIr0N7lvyubs0RI=;
        b=givgLJFX7jd6/Bewa1xeP57kyyWsnSNrRfT3DihhJ0pYvc8y2jb1t/BWD2Y4+aEoY+
         F01vK+ShFtLydc892Yhxje/CRvg1jrvMUPbwLNIut3JGwaFU6UdST3hqphq7P7Ybwj2I
         +U5nia22RKbigljtQMwOb0Vj2n0wbLFyRtJPriZSU88ycJXE7/Vf16cCWXYMQtBhwdWR
         h6xy1O4dPeqwLPKqrWn7JqOUM7E8j6N6qcrrp+6B8FL/w0Y+5FmYiZ8m+RP7guMX3XcZ
         ris5i7bKEEXFI8u8hPpIbRTIBDxO5AaXz4L4dF7SL2w/Go21DtHGnAiBgQNW2Ei8Fqje
         CN7Q==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUNOCa3UUJIM1gzoL0m3XD6YRCqX+Sr5cIrHp2sho223LNt92FE98AnVIIdoPjl8yADTYEKgA==@lfdr.de
X-Gm-Message-State: AOJu0YxOxDr3BTJhkxeCWZolwyX0Y9FQlUgZKrll60IovbTojkU602g3
	FT4RbO7OmfucD6IlXG1z9rSO0oxpt092PGZOI78mjC/Vnn5gNe8b7iRP
X-Google-Smtp-Source: AGHT+IHsOBZjJXBwPhgGku0TBPR5rQRrqQ35kBmiF9tBQl52w2ZjLfWKt3L+Nn7pCkcVTwPnfRiznA==
X-Received: by 2002:a05:6870:219e:b0:367:6cdd:8c52 with SMTP id 586e51a60fabf-390f09cac97mr842163fac.14.1759200327588;
        Mon, 29 Sep 2025 19:45:27 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="ARHlJd5qp87tfke6wkCx+Tg330eqGZiwn6pMEzvW9Ft4kL1Dzg=="
Received: by 2002:a05:6871:3a09:b0:319:c62c:c8e0 with SMTP id
 586e51a60fabf-35ec120e0c1ls3113595fac.0.-pod-prod-07-us; Mon, 29 Sep 2025
 19:45:24 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCX2ginBxwQLqgvfeEpdRkDUaeAuTN35K6WsPI303j+dRsr6gsSukBEdJGt/SukIsgrxImItexA5f5M=@googlegroups.com
X-Received: by 2002:a05:6808:f86:b0:43d:33d6:eee0 with SMTP id 5614622812f47-43f9639042bmr812157b6e.5.1759200324820;
        Mon, 29 Sep 2025 19:45:24 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1759200324; cv=none;
        d=google.com; s=arc-20240605;
        b=Lz+o+SJoe+zXjMoQ4Ong0WeT3VGa1T7LZzWvm8IiKzB9wEXhX2aAuiLcH2vNxVqG2q
         lgR5B0Uvn+ieYwi7i9efD0jMdoViM1Xs6Upwt+Jpp1chH5736jDkM9987pQTpTqQBRzp
         nZja6aCKXQfcQ/qmkflnqq65N0oDGihCyTx0Kzgv+ajUmNKFAE+r/mlyYhb1kyjcekQ/
         vRv9maO4HHen2l1x6/xkrH6VLas9RR4aIWkpZBlHyfNgOus8ySBPbvC0Aq0Nis1YB7vk
         skmSedei6BwfzASK/YsDvm9AiqP7OdZrRTl415B49aie7XaO7vqvNFo3dBYVPwFOOwXD
         D8Ug==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=Zjvk/jwcgtCF9TRiT6Fv94jzQiYOsdOhmjAblUevyNs=;
        fh=wYi8tXL4U4R15kF0amcRJDbQVXnV1QQ6dUl0/ntiutU=;
        b=M5N79jqY09pN8lf/Zotta32JL/Pa6a9DrD8jJkJY+VKoocskxlou5G+nuPlFwwLWmJ
         R2B30XYymbMHEKgXDuGjmalxV8K7ypSAWaUMam7V8idj6I1NRDg3JUiMph7RFS/N2Y2D
         7ved9+5x1QSbGuvHAbAEr0ERaWiY64v1N/P9cu0839qLwxwAoJZuWlZuLGmGRZKamydi
         s4etVODWtglFI170r77vui5AhEjIammsqlo9BsLMh2HCpRFF5Ra/pitmPp3ojDRoYfWO
         DND9eSvlcoS/UZkwVYr5uz6DKV0OoJkMDXMyHZL2+YMjXOZFK9sttDJulKBgIDqUULSO
         jWCA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=eIRCALum;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::52a as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pg1-x52a.google.com (mail-pg1-x52a.google.com. [2607:f8b0:4864:20::52a])
        by gmr-mx.google.com with ESMTPS id 5614622812f47-43f511357f5si474744b6e.2.2025.09.29.19.45.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 29 Sep 2025 19:45:24 -0700 (PDT)
Received-SPF: pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::52a as permitted sender) client-ip=2607:f8b0:4864:20::52a;
Received: by mail-pg1-x52a.google.com with SMTP id 41be03b00d2f7-b5526b7c54eso3329377a12.0
        for <kasan-dev@googlegroups.com>; Mon, 29 Sep 2025 19:45:24 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVGm7q0RxdUln1wnU8ettX/952ltWuCUV4O4tv4clkKjx8PQ/Xlja5DAReJ8gPaKgE0IlvmwfGxaX0=@googlegroups.com
X-Gm-Gg: ASbGnct6oQZZLLScwmfk7V2TgBzvq8cENOYLb+61u1FYX95mXEtSZTKWroN+ywl5qQr
	ihYuBdPfWQbjnWmBolIPoBmNlslym5yMcIFsBfF5qLXjHsSrzllaoMEN/iTo1Gu3A8C+hP/42+w
	F2oLJ3tHVNfUk0tDeEGhf7rqhfI1sheqz7t2/ThcqyKC9h2UbIRjmobzCi1ohvfzJU08+1Uo0/t
	C4rYHaUwRegLyw+3BvW/AhUABVG0PyKK5wU4OOQtq9oeX0ih2VIwey7XKbSeZKTJNiThy/Oi+xF
	CRKnmteoow5RlOSd/hfs0LK5CZn0EFuBEB25fYhIN89MyfRMpcY/S3nPb36DPkBAjgo6k5LhVv9
	heDwcb3zpmyQg0yOo0usIHbfXkQpF8omAcPN1Q/n8Otyp7tLigmbW4Ns6KvwNYEHTalsaa0j7eP
	jJ
X-Received: by 2002:a17:903:3bc5:b0:27d:6777:2833 with SMTP id d9443c01a7336-27ed4a986c5mr179688865ad.47.1759200323854;
        Mon, 29 Sep 2025 19:45:23 -0700 (PDT)
Received: from localhost ([45.142.167.196])
        by smtp.gmail.com with ESMTPSA id d9443c01a7336-27ed68821d3sm145446045ad.83.2025.09.29.19.45.21
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 29 Sep 2025 19:45:23 -0700 (PDT)
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
Subject: [PATCH v6 12/23] mm/ksw: add entry kprobe and exit fprobe management
Date: Tue, 30 Sep 2025 10:43:33 +0800
Message-ID: <20250930024402.1043776-13-wangjinchao600@gmail.com>
X-Mailer: git-send-email 2.43.0
In-Reply-To: <20250930024402.1043776-1-wangjinchao600@gmail.com>
References: <20250930024402.1043776-1-wangjinchao600@gmail.com>
MIME-Version: 1.0
X-Original-Sender: wangjinchao600@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=eIRCALum;       spf=pass
 (google.com: domain of wangjinchao600@gmail.com designates
 2607:f8b0:4864:20::52a as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
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

Provide ksw_stack_init() and ksw_stack_exit() to manage entry and exit
probes for the target function from ksw_get_config().

Signed-off-by: Jinchao Wang <wangjinchao600@gmail.com>
---
 mm/kstackwatch/kstackwatch.h |   4 ++
 mm/kstackwatch/stack.c       | 101 +++++++++++++++++++++++++++++++++++
 2 files changed, 105 insertions(+)

diff --git a/mm/kstackwatch/kstackwatch.h b/mm/kstackwatch/kstackwatch.h
index 850fc2b18a9c..4045890e5652 100644
--- a/mm/kstackwatch/kstackwatch.h
+++ b/mm/kstackwatch/kstackwatch.h
@@ -35,6 +35,10 @@ struct ksw_config {
 // singleton, only modified in kernel.c
 const struct ksw_config *ksw_get_config(void);
 
+/* stack management */
+int ksw_stack_init(void);
+void ksw_stack_exit(void);
+
 /* watch management */
 struct ksw_watchpoint {
 	struct perf_event *__percpu *event;
diff --git a/mm/kstackwatch/stack.c b/mm/kstackwatch/stack.c
index cec594032515..9f59f41d954c 100644
--- a/mm/kstackwatch/stack.c
+++ b/mm/kstackwatch/stack.c
@@ -1 +1,102 @@
 // SPDX-License-Identifier: GPL-2.0
+#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
+
+#include <linux/atomic.h>
+#include <linux/fprobe.h>
+#include <linux/kprobes.h>
+#include <linux/kstackwatch_types.h>
+#include <linux/printk.h>
+
+#include "kstackwatch.h"
+
+static struct kprobe entry_probe;
+static struct fprobe exit_probe;
+
+static int ksw_stack_prepare_watch(struct pt_regs *regs,
+				   const struct ksw_config *config,
+				   ulong *watch_addr, u16 *watch_len)
+{
+	/* implement logic will be added in following patches */
+	*watch_addr = 0;
+	*watch_len = 0;
+	return 0;
+}
+
+static void ksw_stack_entry_handler(struct kprobe *p, struct pt_regs *regs,
+				    unsigned long flags)
+{
+	struct ksw_ctx *ctx = &current->ksw_ctx;
+	ulong watch_addr;
+	u16 watch_len;
+	int ret;
+
+	ret = ksw_watch_get(&ctx->wp);
+	if (ret)
+		return;
+
+	ret = ksw_stack_prepare_watch(regs, ksw_get_config(), &watch_addr,
+				      &watch_len);
+	if (ret) {
+		ksw_watch_off(ctx->wp);
+		ctx->wp = NULL;
+		pr_err("failed to prepare watch target: %d\n", ret);
+		return;
+	}
+
+	ret = ksw_watch_on(ctx->wp, watch_addr, watch_len);
+	if (ret) {
+		pr_err("failed to watch on depth:%d addr:0x%lx len:%u %d\n",
+		       ksw_get_config()->depth, watch_addr, watch_len, ret);
+		return;
+	}
+
+}
+
+static void ksw_stack_exit_handler(struct fprobe *fp, unsigned long ip,
+				   unsigned long ret_ip,
+				   struct ftrace_regs *regs, void *data)
+{
+	struct ksw_ctx *ctx = &current->ksw_ctx;
+
+
+	if (ctx->wp) {
+		ksw_watch_off(ctx->wp);
+		ctx->wp = NULL;
+		ctx->sp = 0;
+	}
+}
+
+int ksw_stack_init(void)
+{
+	int ret;
+	char *symbuf = NULL;
+
+	memset(&entry_probe, 0, sizeof(entry_probe));
+	entry_probe.symbol_name = ksw_get_config()->func_name;
+	entry_probe.offset = ksw_get_config()->func_offset;
+	entry_probe.post_handler = ksw_stack_entry_handler;
+	ret = register_kprobe(&entry_probe);
+	if (ret) {
+		pr_err("failed to register kprobe ret %d\n", ret);
+		return ret;
+	}
+
+	memset(&exit_probe, 0, sizeof(exit_probe));
+	exit_probe.exit_handler = ksw_stack_exit_handler;
+	symbuf = (char *)ksw_get_config()->func_name;
+
+	ret = register_fprobe_syms(&exit_probe, (const char **)&symbuf, 1);
+	if (ret < 0) {
+		pr_err("failed to register fprobe ret %d\n", ret);
+		unregister_kprobe(&entry_probe);
+		return ret;
+	}
+
+	return 0;
+}
+
+void ksw_stack_exit(void)
+{
+	unregister_fprobe(&exit_probe);
+	unregister_kprobe(&entry_probe);
+}
-- 
2.43.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250930024402.1043776-13-wangjinchao600%40gmail.com.
