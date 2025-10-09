Return-Path: <kasan-dev+bncBD53XBUFWQDBBFFKT3DQMGQES643ARQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x140.google.com (mail-il1-x140.google.com [IPv6:2607:f8b0:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id E06F3BC89ED
	for <lists+kasan-dev@lfdr.de>; Thu, 09 Oct 2025 12:57:26 +0200 (CEST)
Received: by mail-il1-x140.google.com with SMTP id e9e14a558f8ab-42f62c67151sf17801885ab.2
        for <lists+kasan-dev@lfdr.de>; Thu, 09 Oct 2025 03:57:26 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1760007445; cv=pass;
        d=google.com; s=arc-20240605;
        b=Wh+TVJNHZauVjOEeSIesaYnSLb51bcU7AX5S78QkpD6FaARGZDJNnWJiy2AcWGfCEM
         iT9PU3kGixwIkCxJ1kyjaq+wFe4cezY7a1w9tB35W9ozPdT6/NNg1TQSNXGI55LaGi7x
         MbtvZ/TWXul25SB8V4YDpdOJufdcDEtki4sSXjPamAV0kV7tqH3VbQFMaWjuonJAubWD
         UX2IKCS5siO60V1tna4/LM5hCRX8uPZ8Dy0AE1LCGyfMRBHToIfmsEtHZR+BsMWzUP3a
         o8Q4klT0AeSGptbEdzjNfLsxV7j8E5ZlhoDLcR/1uRdffG4uzpt5qthnqGd1JFQ2f76u
         YkeA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=7/RufOJc5TXmdukPggy/OQ90OkWREqZCYGAy7P/lD1I=;
        fh=CvHeRgYVJFHGHtpCgFOquXr8li49u0ruuKtiyuJylO0=;
        b=Ijkl6oVKqOilBpEUW2ZqqYhJgr9MtEpBOFnoQ6ugJZaNeMgPd5Fjv4oZ26zuTSqfY1
         XHY1q49NGp0Adg2OUSBmOSmbON6NHxy/3uOMXTC6E0TFoO/lcx/Eu3Y/+QK2StxlnN8U
         H+N9TxBQHM/MIEnaFdnHIOhKpXhcRlUu5chAwuWQAoYRG+Qe7yRJbARfRhY9jumlU3Yw
         bb13VeAViepDSbYMDDaPvrTQvJl4/mhA3A7BId9tUYTaWjKfUbPYg8LW+jp/W3zE7vfg
         HgZC19y2JV/sH1Wr1m4i1fjZfvN4MytUnhzORKQ5nMFHqu8MqGXno7Mb1Rq71V9tNDai
         I37A==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=OnTML6wW;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::531 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1760007445; x=1760612245; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=7/RufOJc5TXmdukPggy/OQ90OkWREqZCYGAy7P/lD1I=;
        b=LTrAagKFRu0OPngs8mykukavPsJ7WVkWZLQiTXhjknu6ZaCs7svazvj4gywjV5Wbwp
         TOV96Bz4EpvrlcXxxKq1oPk16P3jl4FNm0lXPmaOxxxzXKu4p78rqpQDT5U8rsGTmWE+
         63qfkGa+MoVaiP2ppzfR9qeVksgtD4kLn+Wa2ESm9rCN0fsGO5NEuySwLQ9VBJpozkYm
         ftcSMfSgxk5ClexAzIZX0wahdj2BWPyexxZlMvZX/SeqCEJy5yWXLzBZPsBA4roltyeX
         0HVE+NORL9v5bQjHHUpM64ZNCp1N2FIDWgX7X9Gwm9BMzH1m+rImr4+jAEq9LJWjEtSd
         MoIg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1760007445; x=1760612245; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=7/RufOJc5TXmdukPggy/OQ90OkWREqZCYGAy7P/lD1I=;
        b=aqlGB/BQbuOBocBn4jk25p2uAZMK1Tr0bEDoClqLMX2Dn6m0+b+Tkg9MbZYvPynL6B
         xRlyKIGlwhcSiMgw2DL1dbomHOmywS2DgmaN04Cb8BTPAiIertBuVE4m8HATeXjOWeL1
         EMhEYLUj4iRA2AgWghn7KylQU8S9e3R/LN7k8hPMQ2NTxolJ5pP8EDc7m9Lf/HQlGpl1
         BUAl97xI+KhWMd7hPxFdcyc68YR4P+6qi7Roqt7Xup0Cw/d6OyQqEoCvV5GidXmZVNYi
         ud14PXhXa5HDgRC0g+SaCUfW4q5aDJzsMbV8zUjEPLu14jaWJfiQYQ8MSByB4PKZsxi/
         sIzw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1760007445; x=1760612245;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=7/RufOJc5TXmdukPggy/OQ90OkWREqZCYGAy7P/lD1I=;
        b=HcSemRlhmYEd3J3WrXqVd25VIcIeg9kqtxGgTw+gPyKiN3RlGN4Acqn1E5HPFcs8LA
         mq+KqKoiSZl2lUj8m6a7rHDQ6FMValN393Wnckm0PYDVHY7oRe9qEfQK2qYC65AjNKSG
         Sy/EEatCojxrRBVMAoxW+Z+M2UwMFDe1XK94Y6U7C5zDib2JQedR7iZYHNzP3l0TL3ir
         /BoSCR77hL9K57MCf1nD++6WcRi8vc5TwX/API0/OAKhNoLKD/HrGbmx23u1BCaSBR69
         c1fpp+PeImqKYr8OE07mJFUpT75EWOqPy9t2hoje4nte1eO/OB8zfSFUO0vxJYsP9tWg
         e+aQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUu/5ky8DHujE/LWsA4ODLI7BBi4yUsQdk7WBc/JBu6qjQq4GRAOvZ4NZ/9PD73nNTeqHU8cg==@lfdr.de
X-Gm-Message-State: AOJu0YxIagACJkXD4PxhUZMbwgDLmh29w+zU8c6U3fm6Sc/ochPlO9uI
	aGUSGn/UsIqowNjNMjzCSSUBy3/DCaTolr21w0ftXIwKUVkAuPMEFeoo
X-Google-Smtp-Source: AGHT+IHtCRsMj57EWPOMQpYw90N2vD4ucg8t0K5Z/2bA5NkKgw1q7C3MZtRyBqmhaNchLjChr7Uo+A==
X-Received: by 2002:a05:6e02:b24:b0:42e:d74:7252 with SMTP id e9e14a558f8ab-42f8740e748mr61280925ab.31.1760007444943;
        Thu, 09 Oct 2025 03:57:24 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="ARHlJd6JKzU5evjNPExTe5NyyZlcg7DFvXzfH8ZaBYbQoos+Tg=="
Received: by 2002:a92:c52e:0:b0:42f:8af9:6cb0 with SMTP id e9e14a558f8ab-42f90ab0bacls4755465ab.1.-pod-prod-04-us;
 Thu, 09 Oct 2025 03:57:24 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCX5pD8lzmR8QJLgFXBrMEd64cHCQyYq5S14Dsc628JOsybTmNl6xcy8NS/L+oVT2lfVAqw0hQO+jiA=@googlegroups.com
X-Received: by 2002:a05:6602:492:b0:900:1fa2:5919 with SMTP id ca18e2360f4ac-93bd19882e8mr775844939f.9.1760007444001;
        Thu, 09 Oct 2025 03:57:24 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1760007443; cv=none;
        d=google.com; s=arc-20240605;
        b=T9hGCr4X+TvoDjPuzFzTTBUCkVPh9MXdUgTjuG49jxOEAYMimQA7akooaxMn8/dVyO
         HnOyP8equHVePtGFYIv84isjrkek+qVjlK0eSN8UGZG6yTtL0VKJCLZQN6yd8gQnhvQC
         QRxRH3TKLsWMo0ekz/uA2eiug1PwgwdXdSrZDPhLlySDVaM0Dr+odooAsCoZRq7Jzsr6
         9gIi5Nu+7qYuxtZL0azW3ypWfjfJKOFwlfyCwqkSzsxAsdHyPfqWulYb40njcBJqbz/e
         GQENZrEu0mKKBLxxELjVqspM+dPZukwleC8EcJw71Lcy6oHBnFSLSip1f/gyhyH2jDP+
         1e5g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=GIQpLOg8aMQquhlHBEOSk3mXNexjDr9DRSMTRRGj0hA=;
        fh=DAaFaCL/+ZmYVCPDZ03Qo0+5XXN8AVIQL0PuCNEgYTk=;
        b=YZBo23KLfCCu6JWEVJQ49rENFwC5Eq38l48rF0ct3J8qMQL7FZg7sd+9YBy/dZ1I7Q
         ate6/3hxjnJqhGjEXVvI0eyA/q8RNatkVn1BFd3XzIYRKRVW+FTRbVMJDGKgiRMm45Cy
         k4h5VtzEv+wGsgdpEDTTS6s+TJlGQOZkKctc2YNjucD4SkW+pKD7ztQb8ErB2Sp96flS
         2jS5spGKujAVYQztg86AtBRs/t9uA2BDpd3mJFg9VktPBwrsnGWLeo3Dq4hFlV4JW4ZU
         JXtl/QFzhPNZasofZHWVRTp9MZC0tYGUmzzLZ8LqtoiaJj9BUxs1H/nMeZfoSsMzuyt2
         C/KQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=OnTML6wW;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::531 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pg1-x531.google.com (mail-pg1-x531.google.com. [2607:f8b0:4864:20::531])
        by gmr-mx.google.com with ESMTPS id 8926c6da1cb9f-57b5e9e6325si854088173.1.2025.10.09.03.57.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 09 Oct 2025 03:57:23 -0700 (PDT)
Received-SPF: pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::531 as permitted sender) client-ip=2607:f8b0:4864:20::531;
Received: by mail-pg1-x531.google.com with SMTP id 41be03b00d2f7-b62fcddfa21so544785a12.1
        for <kasan-dev@googlegroups.com>; Thu, 09 Oct 2025 03:57:23 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVucqaYrqgTLaCSwgZsLzEggff0LRiV9qYgyZz2q++Jd3LIG5rtbefvy4sFHNFWVhnw2eEl5MlvvVM=@googlegroups.com
X-Gm-Gg: ASbGncsVkX1szfq4F16tZwayWwFUT7USiIXugpfItqtWpyMosE1oxcfgZ6zWlC70nVb
	w6tl13orN8tgDBFDL8NoaBYjm6YYpF/C1y0dlFQBAP8J9uO/TEBGIXPy8HBgz9xKozOpgxmsFGl
	UDoTfqHSOCGXpMytSzJGMshR38HRPnWzxTxec104X+mPg4eSnoKN4m9IOPiIUNe4Tul2hvZayu/
	ZYReoITfUJLzZZT3KzOVpVaSqzi60TUJiwAK/bfOld/gMhN9AQdPD0BW7VGTN2fDqlxqBjUX90c
	Aco802jBBCz6QSLYDjthOrhD+1l5fi7OEENPIlz2ae6dSZM+IIOk1UUwNWEA9Qzs7gxFKSxogAS
	/liOfsczA/x4TMj9saYxuyI4gzwD7yN2w75ppF7MUxGNsHbp5YjeL6iVnD8ho
X-Received: by 2002:a17:903:9cb:b0:267:c984:8d9f with SMTP id d9443c01a7336-29027266982mr95235515ad.24.1760007443143;
        Thu, 09 Oct 2025 03:57:23 -0700 (PDT)
Received: from localhost ([45.142.165.62])
        by smtp.gmail.com with ESMTPSA id 98e67ed59e1d1-33b511135a3sm6722720a91.11.2025.10.09.03.57.22
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 09 Oct 2025 03:57:22 -0700 (PDT)
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
Subject: [PATCH v7 04/23] mm/ksw: add build system support
Date: Thu,  9 Oct 2025 18:55:40 +0800
Message-ID: <20251009105650.168917-5-wangjinchao600@gmail.com>
X-Mailer: git-send-email 2.43.0
In-Reply-To: <20251009105650.168917-1-wangjinchao600@gmail.com>
References: <20251009105650.168917-1-wangjinchao600@gmail.com>
MIME-Version: 1.0
X-Original-Sender: wangjinchao600@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=OnTML6wW;       spf=pass
 (google.com: domain of wangjinchao600@gmail.com designates
 2607:f8b0:4864:20::531 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
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

Add Kconfig and Makefile infrastructure.

The implementation is located under `mm/kstackwatch/`.

Signed-off-by: Jinchao Wang <wangjinchao600@gmail.com>
---
 mm/Kconfig.debug             |  8 ++++++++
 mm/Makefile                  |  1 +
 mm/kstackwatch/Makefile      |  2 ++
 mm/kstackwatch/kernel.c      | 23 +++++++++++++++++++++++
 mm/kstackwatch/kstackwatch.h |  5 +++++
 mm/kstackwatch/stack.c       |  1 +
 mm/kstackwatch/watch.c       |  1 +
 7 files changed, 41 insertions(+)
 create mode 100644 mm/kstackwatch/Makefile
 create mode 100644 mm/kstackwatch/kernel.c
 create mode 100644 mm/kstackwatch/kstackwatch.h
 create mode 100644 mm/kstackwatch/stack.c
 create mode 100644 mm/kstackwatch/watch.c

diff --git a/mm/Kconfig.debug b/mm/Kconfig.debug
index 32b65073d0cc..24f4c4254f01 100644
--- a/mm/Kconfig.debug
+++ b/mm/Kconfig.debug
@@ -309,3 +309,11 @@ config PER_VMA_LOCK_STATS
 	  overhead in the page fault path.
 
 	  If in doubt, say N.
+
+config KSTACK_WATCH
+	bool "Kernel Stack Watch"
+	depends on HAVE_HW_BREAKPOINT && KPROBES && FPROBE && STACKTRACE
+	help
+	  A lightweight real-time debugging tool to detect stack corruption.
+
+	  If unsure, say N.
diff --git a/mm/Makefile b/mm/Makefile
index 21abb3353550..4d45fb69116c 100644
--- a/mm/Makefile
+++ b/mm/Makefile
@@ -92,6 +92,7 @@ obj-$(CONFIG_PAGE_POISONING) += page_poison.o
 obj-$(CONFIG_KASAN)	+= kasan/
 obj-$(CONFIG_KFENCE) += kfence/
 obj-$(CONFIG_KMSAN)	+= kmsan/
+obj-$(CONFIG_KSTACK_WATCH)	+= kstackwatch/
 obj-$(CONFIG_FAILSLAB) += failslab.o
 obj-$(CONFIG_FAIL_PAGE_ALLOC) += fail_page_alloc.o
 obj-$(CONFIG_MEMTEST)		+= memtest.o
diff --git a/mm/kstackwatch/Makefile b/mm/kstackwatch/Makefile
new file mode 100644
index 000000000000..84a46cb9a766
--- /dev/null
+++ b/mm/kstackwatch/Makefile
@@ -0,0 +1,2 @@
+obj-$(CONFIG_KSTACK_WATCH)	+= kstackwatch.o
+kstackwatch-y := kernel.o stack.o watch.o
diff --git a/mm/kstackwatch/kernel.c b/mm/kstackwatch/kernel.c
new file mode 100644
index 000000000000..78f1d019225f
--- /dev/null
+++ b/mm/kstackwatch/kernel.c
@@ -0,0 +1,23 @@
+// SPDX-License-Identifier: GPL-2.0
+#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
+
+#include <linux/module.h>
+
+static int __init kstackwatch_init(void)
+{
+	pr_info("module loaded\n");
+	return 0;
+}
+
+static void __exit kstackwatch_exit(void)
+{
+	pr_info("module unloaded\n");
+}
+
+module_init(kstackwatch_init);
+module_exit(kstackwatch_exit);
+
+MODULE_AUTHOR("Jinchao Wang");
+MODULE_DESCRIPTION("Kernel Stack Watch");
+MODULE_LICENSE("GPL");
+
diff --git a/mm/kstackwatch/kstackwatch.h b/mm/kstackwatch/kstackwatch.h
new file mode 100644
index 000000000000..0273ef478a26
--- /dev/null
+++ b/mm/kstackwatch/kstackwatch.h
@@ -0,0 +1,5 @@
+/* SPDX-License-Identifier: GPL-2.0 */
+#ifndef _KSTACKWATCH_H
+#define _KSTACKWATCH_H
+
+#endif /* _KSTACKWATCH_H */
diff --git a/mm/kstackwatch/stack.c b/mm/kstackwatch/stack.c
new file mode 100644
index 000000000000..cec594032515
--- /dev/null
+++ b/mm/kstackwatch/stack.c
@@ -0,0 +1 @@
+// SPDX-License-Identifier: GPL-2.0
diff --git a/mm/kstackwatch/watch.c b/mm/kstackwatch/watch.c
new file mode 100644
index 000000000000..cec594032515
--- /dev/null
+++ b/mm/kstackwatch/watch.c
@@ -0,0 +1 @@
+// SPDX-License-Identifier: GPL-2.0
-- 
2.43.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251009105650.168917-5-wangjinchao600%40gmail.com.
