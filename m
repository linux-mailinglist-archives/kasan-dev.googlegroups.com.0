Return-Path: <kasan-dev+bncBD53XBUFWQDBB65WZ7DAMGQEEF2GJQI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x140.google.com (mail-il1-x140.google.com [IPv6:2607:f8b0:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id 05F3CB99AB2
	for <lists+kasan-dev@lfdr.de>; Wed, 24 Sep 2025 13:52:29 +0200 (CEST)
Received: by mail-il1-x140.google.com with SMTP id e9e14a558f8ab-4247661a0c9sf84071725ab.3
        for <lists+kasan-dev@lfdr.de>; Wed, 24 Sep 2025 04:52:28 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758714748; cv=pass;
        d=google.com; s=arc-20240605;
        b=Tfu0Qu+t0hFvo969EpdLU4wZlz0jI8A7a6kG1PEaeATSrgVDZ9YcsYwIWVLvX6ezqi
         rEjWaU7fJU1ir4fOE4wcg7MfdVP6593303Q8FwAyazcoRLwsYuTPzzabkF6IdYDxZLQ1
         RVaNVpwJltvc4E9QjSGgcc85KwUJ9fFfwoX2YzCC3585PGgqeFKfFJEZOzs3sNZom4XQ
         zefclrtcLahEOHFqzqwY7AhYdeNHETRavE0NJju3pNOeBYzyyTjzTVK1CYMEq/Xbih+7
         sSsufiI3o5z/JorBjIIp3bJ2VFijGGPHsFgRLH7pV4GvDQFIQ1pGX90Z8xwpmRcDMsux
         82+g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=Uuh5XYATRMnbDhu+jpGIUDR3h7fJmX+rjNBInPpfvhM=;
        fh=nqGqdmhJdiJyarfDZ3dOM57yD9AbIiVKMm/Z+lhsgzo=;
        b=JYkKEEj381rXhIHM8ddZRDK8rhroBtMnledNNKqMi7QBAC2bb2tu4bub4zw8o3ObaW
         WSGuiEGDT1zsGYV4iWnBDVy1Ksy2d2G2KdicInV1sqjAF11XNORGcFJpasXw53x+S7TT
         JN9L3Z7OmwMgSAM/7I3UOMz7uXO2xRTRxBsq7dYjdybqh+rLjzitgOPQdgl+bBiAkYPB
         5JrxF2bH3vtE9/6GPYmS+lb6CR7mBuS+qcL+L57TwYhUjJQZ3yAKoTSvImBntT0BuZLh
         VdJT6CDLLzGRnKu8INhtkhz2VJC76BWNrSXFnHT0e9VPWnH2afgjUeCRz7IT7lr/z0hm
         Uwzw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=EYzbmoLc;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::42a as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758714748; x=1759319548; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Uuh5XYATRMnbDhu+jpGIUDR3h7fJmX+rjNBInPpfvhM=;
        b=NgGQgCsQv8OlD9x6XZX6TZYB+feNYdYz9KbdiY5kLz3HhYACnxF0NWEN6c5W20BSD8
         khB7SJ7yYODM26Z4yJ9ajIOM9p0IfJUZ8PRFbiXToQ9Szk2ne5gM3KSiUWKgQgT9TlTx
         uxUI9qSBJnAcPzd5bImbT6PE/sb7f01WfcfnBDiIfJr468U+HzuNEU+pJ3QEc+xNtU7w
         pYsU5bQsuvszqSEMg7AuLOe6H+YnPncf93igT+sFEy4jYrL71DPwL8fP5EI/3hvRYyBa
         b7mQUF940OeAHZDTZ68NFiw+JCiys91C/Z2Yi4FYVTxM/+/GX//JKX5Pw/TyRBrDNh4k
         wgsA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1758714748; x=1759319548; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=Uuh5XYATRMnbDhu+jpGIUDR3h7fJmX+rjNBInPpfvhM=;
        b=Dgac5RIYdbB0EdgYMpzTZ4v/aBytxvLkBTRD4JLqJ55iwjAbXpEkTk4LDsJyq0RnV0
         szAeV7IPDaiJdfylc1KvFj48ovYdUenc7FWUwq5fFYBSXLe2A51LSsbDbt1JxpWJ26pl
         hB1b3nKNb4KbU8eAGYTC2iy0SVtSSuasW/rEGou8lrijLNJhONYgDEE8N4IYvlk4EuDk
         rB6fk+3s+3tC3WEG8u9lB8325g/e/8vMF6DgjBcnheJRx6Kv0wHgcDfrXkJaPy6Tz5Ru
         noKY6FlfNVnwlrRwWqJwfkC65CBUaehPMypIS28Vi9FWpYxJrQ/T8h2+QwJp5T1vAwyv
         3f6Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758714748; x=1759319548;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=Uuh5XYATRMnbDhu+jpGIUDR3h7fJmX+rjNBInPpfvhM=;
        b=bpAwbm244e1qa00QciTcW1w7tGigSWpYiOmIZNnEE0hVblLOtCeD+VL3UoyXgj5Vma
         hS9UjUA6kz2IGBIOgAZmHEVKz9juj0rG2WhcKccIoETMgmSZ8Wun25NTrIOA4+kFOhCx
         y+AcXCtQeh3/iUXAkFowBiDGvH5dysV9q3RzRyLh7TCtXCDQlXxRYCzI4Cpk9uZfTdRP
         Kv7rPkPMTd6+tdKfqWok2CWJopfMFv/eO2un5P7GVhjqPYiLJbUadRojTbQ6xJXo/gBB
         ZOxjJFb+YhNizxq8Nn4Frvl2mwNoX+gv/6kFg0cuiFF7r880WUbY4gWl2nrtga9AJA4E
         notA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUjQhDgRbtMUmJgVQ3+PWwe5zEQQIC/uQxqYexMjYKFa1V0Xz17DqL+TMwt0ZBR7q9KoJjLBQ==@lfdr.de
X-Gm-Message-State: AOJu0Yzfna41xNPTHfs6qjlQWsSqa/4LH5Mt6FjxcD1XzYsy5q9FG20c
	FVLXYAHwORCTsKk8IN9uzkV5W9N8JSpUI92dJNwScqw3MKUKo0rQpxDi
X-Google-Smtp-Source: AGHT+IGmzT3P82qJBzyxgnHNOYIJPNra4lxYrNTrjrOJCIRIFmjqVGjGKsc68PkJMLdq2l/YXhRewQ==
X-Received: by 2002:a05:6e02:19c6:b0:424:81fb:9248 with SMTP id e9e14a558f8ab-42581ec9139mr95471965ab.30.1758714747792;
        Wed, 24 Sep 2025 04:52:27 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd6qA/oV7HFUv1cGMBcZyYqEF1nZNqUC5+J4oP5fbXaLfw==
Received: by 2002:a92:cdaa:0:b0:424:19b:1d0c with SMTP id e9e14a558f8ab-4244c80849els59732775ab.0.-pod-prod-07-us;
 Wed, 24 Sep 2025 04:52:27 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWuGYlCjMr2h5jwoM8D+pkz78GEYsORKqKsTIMfHcXOelN7EZwYU6qFt6WLb8qaTw9wRe22QSxMmbc=@googlegroups.com
X-Received: by 2002:a05:6e02:3c82:b0:424:7dff:e4dd with SMTP id e9e14a558f8ab-42581e1eedfmr90794605ab.10.1758714746958;
        Wed, 24 Sep 2025 04:52:26 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1758714746; cv=none;
        d=google.com; s=arc-20240605;
        b=B5aX6DOTnI5FOF7mkYsWBtywjMt1KoaoxISZR50mIpmCjK0zgLMaOhAznKGewB1R3M
         FzBEdLy9qnNoeQKPByUorDkatJBguh6x/ik5U61azXY1h1i4ReFI88SyPE7CV2Rs/1NF
         HCaP1WZp7xU+e6eYh5tfY/7QoiG8tx8Lix4ZBC/Y4dj7XgspwdbRj7NNYQ93K3PSvMQV
         XnRDWSfFdKMlKYdyI65TtZddiT7k6u8UfJN1UIy4ubTynaHijbd1Fq01HrHod9NTW8Yq
         OIq3VsUulVtNfW4cdIoeljIsHv48Ms26ZJMtK63iheIQ0bPvPSgVaVgZY3cyBQ0yy2p3
         CcUQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=1RtyZdLa/V9peD4vyIt7vF3g+yVd+tHG9wNYuCcZNH8=;
        fh=gs6uOpAjffcNM1hC42yc1EVNMUexRARH79TcyRFiWfc=;
        b=goX0EeQSO5Z4I9v8b8IIEODUNJ2SCT8llenx6ZXka7laMRKyyAD+ol47adxpe8EpYz
         900fKl/+/zEjNknaDz0O43vlw++tjmfbs1+SCFKLMMQi+MLSwzNyRN39kDwD+ByxUyCk
         QGGqS/oAE7f/iBGzRfiNdA9jDnNFQtiui+z7w7za/RwydnKqQ/Fk7dg6qqFhpVk1ebnd
         ssJMA2E0tTlWB1BeTalthgeRnfvVSITg9Y31zIBDILZDS4PLXzDjUyNLwUOngStfGcSD
         7x6w8ZsjO9jw9ipVyvKN64w2ChtwrIHOSsQueUWFVSOUplnCGmSycq+sR671ytkTv4ln
         7UUQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=EYzbmoLc;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::42a as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pf1-x42a.google.com (mail-pf1-x42a.google.com. [2607:f8b0:4864:20::42a])
        by gmr-mx.google.com with ESMTPS id e9e14a558f8ab-4244aca860asi7490395ab.3.2025.09.24.04.52.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 24 Sep 2025 04:52:26 -0700 (PDT)
Received-SPF: pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::42a as permitted sender) client-ip=2607:f8b0:4864:20::42a;
Received: by mail-pf1-x42a.google.com with SMTP id d2e1a72fcca58-77f7da24397so518430b3a.2
        for <kasan-dev@googlegroups.com>; Wed, 24 Sep 2025 04:52:26 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXFrO2APfP26aQqNw8CKeRQk9kJSDJnjXaD5WRvJqjdFfq7EqwsVbyBe/RX/PqeAH0Pud1c8f0Q6/k=@googlegroups.com
X-Gm-Gg: ASbGnctAOo+WVImJKO9Jth781pieLajg2ZM9cGOwc31o6mmoA9Atltm6qTOp5R5vVaB
	pCnrWPLk693kGe+CmKzLG2+tR89l7a+V3EnO+NHEFoaF2CM+FQ78jCtRJt9OLIcE0rZfM4e8WIa
	elUcoVnWDbbd7RpwB0OpwDh1WrEKZhzdSPEExEO2QnuHY0UQQuqySwWufcoBG6vu129NsNmA0Qv
	+Drdv+AMcAW/8LKhsnCc62vYBSQx1cLIsEShijaQzH2igUlQ5nYlCtMJ5MM+KJXtca/GauQkgkS
	q/H010v53JWIcZeNB5gRK0PP8ZTGXCMyaiU40Wsa4EkALW0ztMT0qMUvzOVj6TytME8eRF73tda
	0RqfI0De9eaHqlWDSzh0x4Fokbw==
X-Received: by 2002:a05:6a00:c91:b0:77f:3018:c994 with SMTP id d2e1a72fcca58-77f53a13c02mr7705160b3a.17.1758714746084;
        Wed, 24 Sep 2025 04:52:26 -0700 (PDT)
Received: from localhost ([23.142.224.65])
        by smtp.gmail.com with ESMTPSA id d2e1a72fcca58-77f0fc4cfbcsm13824080b3a.61.2025.09.24.04.52.25
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 24 Sep 2025 04:52:25 -0700 (PDT)
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
Subject: [PATCH v5 14/23] mm/ksw: resolve stack watch addr and len
Date: Wed, 24 Sep 2025 19:50:57 +0800
Message-ID: <20250924115124.194940-15-wangjinchao600@gmail.com>
X-Mailer: git-send-email 2.43.0
In-Reply-To: <20250924115124.194940-1-wangjinchao600@gmail.com>
References: <20250924115124.194940-1-wangjinchao600@gmail.com>
MIME-Version: 1.0
X-Original-Sender: wangjinchao600@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=EYzbmoLc;       spf=pass
 (google.com: domain of wangjinchao600@gmail.com designates
 2607:f8b0:4864:20::42a as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
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

Add helpers to find the stack canary or a local variable addr and len
for the probed function based on ksw_get_config(). For canary search,
limits search to a fixed number of steps to avoid scanning the entire
stack. Validates that the computed address and length are within the
kernel stack.

Signed-off-by: Jinchao Wang <wangjinchao600@gmail.com>
---
 mm/kstackwatch/stack.c | 77 ++++++++++++++++++++++++++++++++++++++++--
 1 file changed, 74 insertions(+), 3 deletions(-)

diff --git a/mm/kstackwatch/stack.c b/mm/kstackwatch/stack.c
index e596ef97222d..3c4cb6d5b58a 100644
--- a/mm/kstackwatch/stack.c
+++ b/mm/kstackwatch/stack.c
@@ -9,6 +9,7 @@
 
 #include "kstackwatch.h"
 
+#define MAX_CANARY_SEARCH_STEPS 128
 static struct kprobe entry_probe;
 static struct fprobe exit_probe;
 
@@ -59,13 +60,83 @@ static bool ksw_stack_check_ctx(bool entry)
 		return false;
 }
 
+static unsigned long ksw_find_stack_canary_addr(struct pt_regs *regs)
+{
+	unsigned long *stack_ptr, *stack_end, *stack_base;
+	unsigned long expected_canary;
+	unsigned int i;
+
+	stack_ptr = (unsigned long *)kernel_stack_pointer(regs);
+
+	stack_base = (unsigned long *)(current->stack);
+
+	// TODO: limit it to the current frame
+	stack_end = (unsigned long *)((char *)current->stack + THREAD_SIZE);
+
+	expected_canary = current->stack_canary;
+
+	if (stack_ptr < stack_base || stack_ptr >= stack_end) {
+		pr_err("Stack pointer 0x%lx out of bounds [0x%lx, 0x%lx)\n",
+		       (unsigned long)stack_ptr, (unsigned long)stack_base,
+		       (unsigned long)stack_end);
+		return 0;
+	}
+
+	for (i = 0; i < MAX_CANARY_SEARCH_STEPS; i++) {
+		if (&stack_ptr[i] >= stack_end)
+			break;
+
+		if (stack_ptr[i] == expected_canary) {
+			pr_debug("canary found i:%d 0x%lx\n", i,
+				 (unsigned long)&stack_ptr[i]);
+			return (unsigned long)&stack_ptr[i];
+		}
+	}
+
+	pr_debug("canary not found in first %d steps\n",
+		 MAX_CANARY_SEARCH_STEPS);
+	return 0;
+}
+
+static int ksw_stack_validate_addr(unsigned long addr, size_t size)
+{
+	unsigned long stack_start, stack_end;
+
+	if (!addr || !size)
+		return -EINVAL;
+
+	stack_start = (unsigned long)current->stack;
+	stack_end = stack_start + THREAD_SIZE;
+
+	if (addr < stack_start || (addr + size) > stack_end)
+		return -ERANGE;
+
+	return 0;
+}
+
 static int ksw_stack_prepare_watch(struct pt_regs *regs,
 				   const struct ksw_config *config,
 				   ulong *watch_addr, u16 *watch_len)
 {
-	/* implement logic will be added in following patches */
-	*watch_addr = 0;
-	*watch_len = 0;
+	ulong addr;
+	u16 len;
+
+	// default is to watch the canary
+	if (!ksw_get_config()->watch_len) {
+		addr = ksw_find_stack_canary_addr(regs);
+		len = sizeof(ulong);
+	} else {
+		addr = kernel_stack_pointer(regs) + ksw_get_config()->sp_offset;
+		len = ksw_get_config()->watch_len;
+	}
+
+	if (ksw_stack_validate_addr(addr, len)) {
+		pr_err("invalid stack addr:0x%lx len :%u\n", addr, len);
+		return -EINVAL;
+	}
+
+	*watch_addr = addr;
+	*watch_len = len;
 	return 0;
 }
 
-- 
2.43.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250924115124.194940-15-wangjinchao600%40gmail.com.
