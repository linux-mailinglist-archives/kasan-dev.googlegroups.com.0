Return-Path: <kasan-dev+bncBD53XBUFWQDBBOVJZDEAMGQESOSK32A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf40.google.com (mail-qv1-xf40.google.com [IPv6:2607:f8b0:4864:20::f40])
	by mail.lfdr.de (Postfix) with ESMTPS id 9F3A4C47FBC
	for <lists+kasan-dev@lfdr.de>; Mon, 10 Nov 2025 17:37:15 +0100 (CET)
Received: by mail-qv1-xf40.google.com with SMTP id 6a1803df08f44-88236bcdfc4sf69052406d6.1
        for <lists+kasan-dev@lfdr.de>; Mon, 10 Nov 2025 08:37:15 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1762792634; cv=pass;
        d=google.com; s=arc-20240605;
        b=OYXC7KjFmX0caFHlRRnrg/Esn3kb9pVt6EwAOUGcGtPiKfF7Q1YPRzj7mn+ut+2iWL
         R2BmHX0Dm3TmB8rMLI8mjrchLyzC2/PIJD8/IPjfuX/ULLjAbRcfTaAII89zzvlyC8xd
         HeaY5hvzX8VzoYs6GccKdN79DqR7GjWtGnDstC+sSAvWYTtA6qiAoRDGRkoWkCSMKN1z
         zv6RMJnkB793xRV6FpO1b9Kzmn3nWEzPGuNHNusphMSnum85uyfJj5yA6XIs/meJ09+q
         LLsX0pdDrYUh8mNqFfNuLg6hVI2WKFtsSh7YXjtO+B+YYEsyxNFaJtLXr1zNvnKib7pr
         Y8lA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:to:from:sender:dkim-signature
         :dkim-signature;
        bh=lwfXfy6dsRq3oFMn0BU0WisYpSq1XXqDeFen2VYCyDE=;
        fh=jKpmyImWKCotEemCrxCN7aixCM897kjCKqxyMfph7RQ=;
        b=MR/5x02QbQINF/p9s49PhVjGX++lySw+BVJjBrTFJ4LD8bOnIDcNkN90OOrh3GrmAK
         eXEB03yVyezwLsfBQcn0cSlpNNrEaymwaHKMEKjnzqeETJPhECUM5tKfElwBYM5J7h6I
         Ye0+pc1S9XsXa8Hh7uziAbWu4kZ+goeXEMT1twRlAU0uJBov/6ff5uVXGEMb3GOWu0qu
         OLqksr9cUduhyUXkkdxXrgKkTBcpBy+fqGCkWmvlMLGKJJuzhnLG+ufBUjF2IFXBSclu
         3srBSiX4FlHsfxCgJFNrgra2NkzNo2Wzg7PBE1lEn97tYKImJgngTNhEWNRuxyH+NrUG
         7pvA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=FMhsZze3;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::42e as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1762792634; x=1763397434; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=lwfXfy6dsRq3oFMn0BU0WisYpSq1XXqDeFen2VYCyDE=;
        b=bA5KjEyZG5WIWogRJz9Gkg4z882iNJEgKiMehpDvdjcLeGIFZ1QaBwjWcJabvO5uqn
         +AzQZ8EOq2R33TceHtb46aP+EV2ku1giHF5U0OldBsbLsagbla1E2NxlQS3HrFLRazWz
         kAa5fSCHRueE8j1lCeIHPMNgRXLpaF0oax435cz+jhvnwrDp+qaIEHIGwh3pXS5ZcW78
         9tGnsbM4KteE9JQ1qPps03GchPFy2KE5E1FI1p7e6SKVtTInCE+XUTNOIx8R3kL6cP53
         5hNi98sszWYMh+ktGsRYnO2QBVXn0YBJkWUT0WPPrD6D9/u8X4OrnaT7BDgO1OX6cZKD
         gCPQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1762792634; x=1763397434; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=lwfXfy6dsRq3oFMn0BU0WisYpSq1XXqDeFen2VYCyDE=;
        b=ipjRnHd8RX/syxAN/otc9op5VWdPh9OcnwxSHPlB5faCM9h9dCyFPN74mmG4cZHa3J
         DC1ch09suojzZriKBWrTwhinswE5z79Kv9dy48iq8fFuemlzTRj2s+c5tPsGbsGy7jk3
         CAvp7DQt4YWhJViJpGOrFgpGVm5KKvry5xmA9Xh2+aDMuVBPzJLZk6Kmz6AzcUYivEfg
         FcvJ8wzyGFzKZXvpQYjcbuvIuoc0HIhrY4zV8uAtOGKrQmnWHquss1d3CZUQ6LUrurjI
         6hfEA7/NPQW4unCHngJiqGwg10GfFrVKc762jzSRYmZIAWKeruGXtmupZ115luVJYZxX
         8zuQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1762792634; x=1763397434;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:to:from:x-gm-gg
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=lwfXfy6dsRq3oFMn0BU0WisYpSq1XXqDeFen2VYCyDE=;
        b=K+E8uU2AXs43SQVjAMS9fn9v5792Wp4v6dkHmN7m/D2HmJzLOTnmyYuUPLnZWZy/Bv
         rBkZzPlboaXONvwC0EZcblEc3YJBTpbVLS9p+61U7eCjPWdCft7h/6nMjF05fQsXkPxz
         XgyEG6ecdyDnWjfTorKPScAI9edCJJ8DQhbdL3lZISPBVKGFBV/f/pspBwccYsmr4bVe
         /A2C5hZIaNL532sj0S9TaDsnQRDdisspFl9ndcUilZP9weuICeCxTofXpTglvZ3K3sdO
         xsA5s4JcJu9fPGwujLKikORH4aWCPWwNaiF7aENwYBPKFQuWb1MSfX/NvlNMivQxytXx
         nuSQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXPSygAsQzHfN64RvM7nMxKySvvGfvn4hQzMEG1na8bz4SuvLHMMy35I1iW/PGh+Gcz+xhGhg==@lfdr.de
X-Gm-Message-State: AOJu0YylHkD8ssqtDwHtfbgtxef5qsr6xbcjcn9Kt3Ij8XhTV3uUEpNo
	C8LXjJbz+528UDdGrcHJNuDU2vmwxhYjrBP+35fFZc1bgDeNpLeoG+HP
X-Google-Smtp-Source: AGHT+IHRNe2P3IE5UeapW4UgxIBj7uOJWf7S8R/jbH/Lr95iUtWcDj62mBgtrJUrupE9biKYFUjv7w==
X-Received: by 2002:a05:6214:240d:b0:880:4d78:89ea with SMTP id 6a1803df08f44-88238702c86mr127266616d6.60.1762792634443;
        Mon, 10 Nov 2025 08:37:14 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+bjuoLjNpDgbOsYN63m8N7CFEp0a0Csbu1ThDw3Ag8CuA=="
Received: by 2002:a05:6214:2523:b0:880:31e4:d7e4 with SMTP id
 6a1803df08f44-88082eb7fc5ls81639736d6.1.-pod-prod-07-us; Mon, 10 Nov 2025
 08:37:13 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUbQnyWD4Tvm/W9y0DBrZmwnExCQkIGKDpcU6a48WGN/BFLMcPeNAAZgUy8BZ1/sUFZLNghNylg22Y=@googlegroups.com
X-Received: by 2002:a05:6214:494:b0:87c:1d89:a245 with SMTP id 6a1803df08f44-882386e2f40mr131780596d6.49.1762792633585;
        Mon, 10 Nov 2025 08:37:13 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1762792633; cv=none;
        d=google.com; s=arc-20240605;
        b=ZkbXonTRkGlGt4gVOZKsIvJAkl97TUclxnklfTtOVmc7AK/H3zjKg4SaTr5QnoTDa8
         1txMV6upIBKzOez9WpLNlvXlJAYtL0nvhemGKVEj1clylVxvWG1SHXJlLT0lfVx6hXjY
         uuDDFZrnsYCPtHzpSqixoEajIUdxOGm+Rwy2j3wuu+N1I/t5fr9k01JGG8eI2zfrgqEM
         ePQR3duNSnWkFlsZYZmvmOg81Sz81NXMGFhV9XDfl9vtM2ndHjvD6/2cIa7dqcxz3K/8
         K79SE5y+iYD5s1TM5DAJRzNEigMDF1Nz4wO72LuvpRJ/tR4fQJrMuW/mtUImmbILCB8h
         8/og==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:to:from:dkim-signature;
        bh=OfQWKEWM8M6Sp/kqVVWTo1Q3rJtTZ9aAiY0lp7l1vgw=;
        fh=briA7D9bmqpXcPO3h1/xxFL28cQj3bDoI4C6Iqr0D5o=;
        b=JpiMhQpVQ+N6i4SiIMQ8AINbKdhbZfsIVH2dit11y7QTsH95pvjkWOaBDwLSpGhIkZ
         sLIZIQSSg3VlfHixQ3d8X7Z8ZHC40GZ0vmCYLaqNKMBQq0aLqAwljYQHqpSzMjWfYHpH
         02vpKmxcLO5dooasCSOMr5KS1D3WB5Q7WCM3ZvCug28zbEldAryB4pP+SwrqNenEaAAN
         h721h359vZtR+LkBca4dJm+hbj/rQ+hAkG6D7PDUG/+5oyANJ2vcZ2gDQBampIMexKrH
         b3wiE5Lmc/JK0jw6ubIYOIxeUFe/UDHKS3aBQSkYLJCXsrGBrH/bP0GvfRFAF2DhnDof
         cYQg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=FMhsZze3;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::42e as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pf1-x42e.google.com (mail-pf1-x42e.google.com. [2607:f8b0:4864:20::42e])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-8823881122asi5341156d6.0.2025.11.10.08.37.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 10 Nov 2025 08:37:13 -0800 (PST)
Received-SPF: pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::42e as permitted sender) client-ip=2607:f8b0:4864:20::42e;
Received: by mail-pf1-x42e.google.com with SMTP id d2e1a72fcca58-7ad1cd0db3bso2413033b3a.1
        for <kasan-dev@googlegroups.com>; Mon, 10 Nov 2025 08:37:13 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCVrmbs73wpXLsWFsqbb6qtE3c7w/wcqmm9nOgLq5x5uIyvQnh0qy/3nGdYU//w8asu5/owH7KwLR1I=@googlegroups.com
X-Gm-Gg: ASbGncuL39i5ycYXWeSUIvaG20UCaoMqujTY4//504zEAANLy8R5ywg2D02PnaLUyxe
	hmQgWRKr+POM63h7kelVwKZo2HSJ/UO5VRXjH8+h8aKEv+SVRCkbOT9sizMtimbfaX6BoD8F/P7
	VyinFSIJ6ZdwZlrCR9MNQuQt0j/4BsuJemRUo46xYXPVk0sIJuLdnr3WfRru6bo1iQZ77DhODiX
	9gmzcfSXFOMXUOEWwJsu/ey0LAaYWZh+oOS+Z/4LB0Ia2Esy79qsydMd7Vtqe8ADwi2xSbhhhcS
	grXJe6spfWu94MUHfQW21sSJDncF9CjNTBxcA4B3DrlydrrHyon+vCo+0Q1j4OXQnPg6lfHw+/O
	sX58qS/F+K1U2TPaid0jl5ZWjDuiqGlvtuJzws98MEM7xE8pvkSLHtguPDckjtvxKlOHaqHlFX/
	01dF88iEAOd3nOb6m2HjiAsw==
X-Received: by 2002:a05:6a20:5483:b0:342:873d:7e62 with SMTP id adf61e73a8af0-353a2d42046mr10346355637.29.1762792632699;
        Mon, 10 Nov 2025 08:37:12 -0800 (PST)
Received: from localhost ([103.88.46.62])
        by smtp.gmail.com with ESMTPSA id d2e1a72fcca58-7b0cc17784bsm12559855b3a.47.2025.11.10.08.37.11
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 10 Nov 2025 08:37:12 -0800 (PST)
From: Jinchao Wang <wangjinchao600@gmail.com>
To: Andrew Morton <akpm@linux-foundation.org>,
	"Masami Hiramatsu (Google)" <mhiramat@kernel.org>,
	Peter Zijlstra <peterz@infradead.org>,
	Randy Dunlap <rdunlap@infradead.org>,
	Marco Elver <elver@google.com>,
	Mike Rapoport <rppt@kernel.org>,
	Alexander Potapenko <glider@google.com>,
	Adrian Hunter <adrian.hunter@intel.com>,
	Alexander Shishkin <alexander.shishkin@linux.intel.com>,
	Alice Ryhl <aliceryhl@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Andrii Nakryiko <andrii@kernel.org>,
	Ard Biesheuvel <ardb@kernel.org>,
	Arnaldo Carvalho de Melo <acme@kernel.org>,
	Ben Segall <bsegall@google.com>,
	Bill Wendling <morbo@google.com>,
	Borislav Petkov <bp@alien8.de>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Dave Hansen <dave.hansen@linux.intel.com>,
	David Hildenbrand <david@redhat.com>,
	David Kaplan <david.kaplan@amd.com>,
	"David S. Miller" <davem@davemloft.net>,
	Dietmar Eggemann <dietmar.eggemann@arm.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	"H. Peter Anvin" <hpa@zytor.com>,
	Ian Rogers <irogers@google.com>,
	Ingo Molnar <mingo@redhat.com>,
	James Clark <james.clark@linaro.org>,
	Jinchao Wang <wangjinchao600@gmail.com>,
	Jinjie Ruan <ruanjinjie@huawei.com>,
	Jiri Olsa <jolsa@kernel.org>,
	Jonathan Corbet <corbet@lwn.net>,
	Juri Lelli <juri.lelli@redhat.com>,
	Justin Stitt <justinstitt@google.com>,
	kasan-dev@googlegroups.com,
	Kees Cook <kees@kernel.org>,
	"Liam R. Howlett" <Liam.Howlett@oracle.com>,
	"Liang Kan" <kan.liang@linux.intel.com>,
	Linus Walleij <linus.walleij@linaro.org>,
	linux-arm-kernel@lists.infradead.org,
	linux-doc@vger.kernel.org,
	linux-kernel@vger.kernel.org,
	linux-mm@kvack.org,
	linux-perf-users@vger.kernel.org,
	linux-trace-kernel@vger.kernel.org,
	llvm@lists.linux.dev,
	Lorenzo Stoakes <lorenzo.stoakes@oracle.com>,
	Mark Rutland <mark.rutland@arm.com>,
	Masahiro Yamada <masahiroy@kernel.org>,
	Mathieu Desnoyers <mathieu.desnoyers@efficios.com>,
	Mel Gorman <mgorman@suse.de>,
	Michal Hocko <mhocko@suse.com>,
	Miguel Ojeda <ojeda@kernel.org>,
	Nam Cao <namcao@linutronix.de>,
	Namhyung Kim <namhyung@kernel.org>,
	Nathan Chancellor <nathan@kernel.org>,
	Naveen N Rao <naveen@kernel.org>,
	Nick Desaulniers <nick.desaulniers+lkml@gmail.com>,
	Rong Xu <xur@google.com>,
	Sami Tolvanen <samitolvanen@google.com>,
	Steven Rostedt <rostedt@goodmis.org>,
	Suren Baghdasaryan <surenb@google.com>,
	Thomas Gleixner <tglx@linutronix.de>,
	=?UTF-8?q?Thomas=20Wei=C3=9Fschuh?= <thomas.weissschuh@linutronix.de>,
	Valentin Schneider <vschneid@redhat.com>,
	Vincent Guittot <vincent.guittot@linaro.org>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Vlastimil Babka <vbabka@suse.cz>,
	Will Deacon <will@kernel.org>,
	workflows@vger.kernel.org,
	x86@kernel.org
Subject: [PATCH v8 07/27] mm/ksw: add HWBP pre-allocation
Date: Tue, 11 Nov 2025 00:36:02 +0800
Message-ID: <20251110163634.3686676-8-wangjinchao600@gmail.com>
X-Mailer: git-send-email 2.43.0
In-Reply-To: <20251110163634.3686676-1-wangjinchao600@gmail.com>
References: <20251110163634.3686676-1-wangjinchao600@gmail.com>
MIME-Version: 1.0
X-Original-Sender: wangjinchao600@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=FMhsZze3;       spf=pass
 (google.com: domain of wangjinchao600@gmail.com designates
 2607:f8b0:4864:20::42e as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
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
 include/linux/kstackwatch.h | 13 ++++++
 mm/kstackwatch/watch.c      | 93 +++++++++++++++++++++++++++++++++++++
 2 files changed, 106 insertions(+)

diff --git a/include/linux/kstackwatch.h b/include/linux/kstackwatch.h
index ada5ac64190c..eb9f2b4f2109 100644
--- a/include/linux/kstackwatch.h
+++ b/include/linux/kstackwatch.h
@@ -2,6 +2,9 @@
 #ifndef _KSTACKWATCH_H
 #define _KSTACKWATCH_H
 
+#include <linux/llist.h>
+#include <linux/percpu.h>
+#include <linux/perf_event.h>
 #include <linux/types.h>
 
 #define MAX_CONFIG_STR_LEN 128
@@ -38,4 +41,14 @@ struct ksw_config {
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
index cec594032515..4947eac32c61 100644
--- a/mm/kstackwatch/watch.c
+++ b/mm/kstackwatch/watch.c
@@ -1 +1,94 @@
 // SPDX-License-Identifier: GPL-2.0
+#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
+
+#include <linux/cpuhotplug.h>
+#include <linux/hw_breakpoint.h>
+#include <linux/irqflags.h>
+#include <linux/kstackwatch.h>
+#include <linux/mutex.h>
+#include <linux/printk.h>
+
+static LLIST_HEAD(free_wp_list);
+static LIST_HEAD(all_wp_list);
+static DEFINE_MUTEX(all_wp_mutex);
+
+static ulong holder;
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
+	if (ksw_get_config()->panic_hit)
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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251110163634.3686676-8-wangjinchao600%40gmail.com.
