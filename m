Return-Path: <kasan-dev+bncBD53XBUFWQDBB6N2Z7DAMGQEXXEWGII@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-x113e.google.com (mail-yw1-x113e.google.com [IPv6:2607:f8b0:4864:20::113e])
	by mail.lfdr.de (Postfix) with ESMTPS id DF49FB99B86
	for <lists+kasan-dev@lfdr.de>; Wed, 24 Sep 2025 14:01:00 +0200 (CEST)
Received: by mail-yw1-x113e.google.com with SMTP id 00721157ae682-73f683808bbsf68213377b3.1
        for <lists+kasan-dev@lfdr.de>; Wed, 24 Sep 2025 05:01:00 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758715260; cv=pass;
        d=google.com; s=arc-20240605;
        b=afEA1Hd/DRjvYDRYjl6sczdIzQFCgYZxnPjxavwPOp9NQYhHIQoRjiLD80wCICkQFy
         sgp6KV5MfOVSNi5dzjTzFRV7GOCubp98YzbLRcqIMC4D+gc0iA65zXwjr0H2pCbA/oI9
         y36gDgmn0JH8cFJJOq+1Od+PV3Mw9zKZ79Yd2JrH1g/InHY17iWiQYmBGtTjhnfdYibu
         jxpu8JH/dbOEwgB/JXZxodiNSbbzcUp339Omlz3rPXggtdBEQlabugvA2FrPZ/WSNBkx
         x1x7S4/+cFKnKwhV1t0XwvnTk+I+jQjRBePQuMDp5Q0JdfbIsUYlJJ+srT1ODN3SYJQ9
         Kb1Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=9JvvBojztqIuYL8Zl2y7uhkflnqRhTLKK5yF7TMs3IA=;
        fh=rYlZmcNRdIbGQw3eUvMYHtipj9oW7RDkj1MUJzXWFr8=;
        b=EFc0PJe376hoY1fBzTGgnNt/7jrGvUmcgWASIfPQmueII+by6og6+6++doX8CD4A6t
         e5pPGWaly+qJZNBlOG2EzmJecx9b/OaupGkDo+mKAw7ikupjZwZ7uVXLONgkUhssUb8T
         uVxbEq9lRiHL8irAIj+KdsyKJ8pQDkekN80rvqL8wOCziAGiXO1U6SvfHPgEwH3FqKyP
         4S8RhCnbhetCk3xSlDDaGWn1TzhZEDUy2ixjJ1r+tl0WfTwMCIjAq9Ol8nZBGeH+Ob9/
         UvRVYVG0AvaHN6HeCDRUTlT1ZOlLmSzQWNWxwOGtgrmhwOOjB+xOLhREJPInUAaC34I6
         9tdg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=bqg6nV52;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::52c as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758715260; x=1759320060; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=9JvvBojztqIuYL8Zl2y7uhkflnqRhTLKK5yF7TMs3IA=;
        b=JOlzuPKrz4PDUpCG+IGAJxhX93CuA87K3tq1OKMky2SD7+FXcSpjqlBqNsVn+oLQLf
         kN6LPrnFD9VIIWKebILLCkeXOMrGAADlQbePDp7JvB5WwnI9BYTQBN5FVoN+gkYdT5G+
         XbfO1QePwV0sVXkDNsIoUVcLAE46Yy2oQGVtL3f0XS3AtOoAXHywLHWjYu4jHlSaa3Uf
         9OJiO8J7frL+gLBm1q7qLJ7pSWxiKw0JJSwml73qu5KXgpIr6UnLgB0hknse9RaUzXNA
         ktfCnOTB+V3IEtoGGAMBFFz/m6EcC17tGiDjeETySRkcPQIQalWOjTVPHyTgk/uJSAxm
         +DcA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1758715260; x=1759320060; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=9JvvBojztqIuYL8Zl2y7uhkflnqRhTLKK5yF7TMs3IA=;
        b=jCuDotb6/pB/9A7rcc+lJp8ptNQ3DEAhIZx7M1BTbmDRMtB5P7p1X5uhH7qJ9z+vcq
         MBPM7xQ5CkjkiVvn/Zc6zE9HSPQXzRpx5bWBRsuvXis3GYbh41dqwTTV61StXVsayXTE
         3LlCmFyxy29JlQQYnBV1d24QK62s2OHSWDXzrpIJl7JfSOaWe89MalwVySbq/C90rLmS
         W9oy+WRJvXQu3Qri+hFy9P2/UVeJwNuPAUcsikkfKFoaQPRPqeW2RVXCzeOgUXoTfKNG
         T8x7OvY1HLPCH2CUth7F3Zjs1yuMZqnKIGSExxLGu7P3bBaBKV5NLs15Q2hlK/AuiNBs
         NbOg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758715260; x=1759320060;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=9JvvBojztqIuYL8Zl2y7uhkflnqRhTLKK5yF7TMs3IA=;
        b=F48tqAHW0nBZTmOHux6VlG9/O6rhKcovw3fZO/3R9LLFHFoc4X/I4EVOYjw2x6N2nm
         1Pb+eoOVh2CkYDKjkvZeiUu96jatiOA69DueoGVDqXEHJS1m7TuZu7otbyJTSKybjBat
         DM0xG+GYDrfR6rhtFq+Fwdcn9LgEr5LBbjuDjREuHrz2G1KRBlSS788c10lY8xuuQ34Z
         I5S6P6RP4kcwUgxVxdrtzpX5sn4F5BLZqKif3X5x5B6FBiEqv4TyhZaZ3oWQd7at+cUF
         G6jQNchGbgUfc6zlkpdMv0nHjWLCCPgjeWvGHCyziMKjNq2pNJyzuruAXR5rl0BQsitR
         0Teg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVXVMAG3Q+XpMejjVDpiM+Jjs5eyDhDPUS+co2iXaVzmZe2fU42aNhkm51d9Bm45SRlPxYNhg==@lfdr.de
X-Gm-Message-State: AOJu0YwaZR02RLvvtnpBa8OXuOjVhdta64/ycv1PpaUFX+LEt2Ypvn3j
	PKZgBWP+Uh6gucjtWK+pWQJn9MfyG4kW/u6te7Kw38o5CMcydvNPsLxK
X-Google-Smtp-Source: AGHT+IGoXfwhSSTYoS5Za9qz090B5n80jZ1BhlRereDGMUHcdKiNTXhH7BXQ/CYWNNKrc2idMAnaJw==
X-Received: by 2002:a05:690e:1a61:b0:62c:204:5dfa with SMTP id 956f58d0204a3-6360463d0c1mr3987424d50.29.1758715258176;
        Wed, 24 Sep 2025 05:00:58 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd7yW+q9JZKv+6qWN226bzRPsikvRFEqY2cLh8bEtbXSfA==
Received: by 2002:a05:690e:4348:b0:630:b196:c4a0 with SMTP id
 956f58d0204a3-633bdfb5004ls2984791d50.1.-pod-prod-01-us; Wed, 24 Sep 2025
 05:00:57 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXQoSPXvNGROQ4OpTHnRazSNsFTHSrxXMMT03KoYFCyjagi+ROo9VuzcOd3ZyzI6OX5ItHdVFLC+L8=@googlegroups.com
X-Received: by 2002:a05:690e:2495:b0:636:1667:28f5 with SMTP id 956f58d0204a3-63616678bfbmr363423d50.13.1758715257018;
        Wed, 24 Sep 2025 05:00:57 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1758715257; cv=none;
        d=google.com; s=arc-20240605;
        b=DPp+JfDRBNek2MdB7Km/7v9x0fV6g9tTrCC83mipun1uos9+MD8f9comXdR1Gh2zVK
         z+wkPokTiAyfPxr/eYxYSbfRkd0FUmgoCZ2Y1mJ7UkF+6RS2KgAUpT7vug1Pj2Fo+EnC
         I1JK/njkaBNLy0F3o4SmzF4oVQjo66JFK33PFDeTHaqyPNBspqoaphyQlTkfYmV8Ceu2
         o3PSDM3bdLRM3+LsCy57tLZqT9cCWrYMeObnXt4DBsCJQG4NKp1sJL5q/svcAMQB+eaW
         Sp1en8WE7rmsPISwP4rIG1Lurq8IANdN8w3xFAYJiybqR5P2KxW5Ovdym/awf6K76695
         271g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=JiYrHsa7aujjpG04RUHlv+tCl0E3sN/Q3IgPp3O0OKQ=;
        fh=Yrj71k/E6rQyRY9CumIowWtrvIRa77SG0VHioKwXJiM=;
        b=lIxZVUb0qIsrMVGNWnY+U6JSL7RioYFTF1rAvfXNDRap5z4TVxqEWWvJ8ihyJeARqd
         +VirxQwdC8KAOU5X5NgRhdlLWwzSCbE1W/crybuGdDh+Oq6COiu0sAgOEw+T5bc4MLGJ
         KAUe047uBKec+Ecp7KCQDaI4X9WctLTbtDRj2u2JnAlUJ09Ok1U8zks6cMv+59g+OuGb
         e0UpsrEkPFjuqouqcBW4TD4NM7iytKyuoGOXTsMu0R9HcE245kZIfybHOl2xXc7mwVdX
         vn6YUgHuv07PYsV1NWXd+yBNqG9qlarrvQUhAbQqZ80uyqxNlakCuqE0WkyTy+43q7ue
         FrLw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=bqg6nV52;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::52c as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pg1-x52c.google.com (mail-pg1-x52c.google.com. [2607:f8b0:4864:20::52c])
        by gmr-mx.google.com with ESMTPS id 00721157ae682-762ff1394efsi62337b3.1.2025.09.24.05.00.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 24 Sep 2025 05:00:57 -0700 (PDT)
Received-SPF: pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::52c as permitted sender) client-ip=2607:f8b0:4864:20::52c;
Received: by mail-pg1-x52c.google.com with SMTP id 41be03b00d2f7-b5579235200so557843a12.3
        for <kasan-dev@googlegroups.com>; Wed, 24 Sep 2025 05:00:56 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWmPvKsWFy3ghbDC7d3aetExFgwlDxKx1FPgOy8bzCCN+XMt95ChEWB97FG8XR5LH3OOQZpMBSN9IY=@googlegroups.com
X-Gm-Gg: ASbGncsTpDBL0Uoa29O9bzdxYQ4DieByXpNH2NRPpq+EUzNPx2LyM8Mdb4g41Ooasd8
	uL/rh8PUr9RdANsOWao+OIjXoFMxvotmZS/vejnQPkrEuEJx5RLxI4/ghdPkkqOYWhcdKy00ZPj
	cI0FcBU8Eripp5JAB+cBAtqqaHwyGJnWjOJEv/UY1Nq61yhhnP3pYnuXQmKfNM659V0W9r70w1U
	IaxU5rjnjAyXfXhCn5Yi/VIKHp12XUBLaFz2aRu8uUeoWILBLB3M15nM+tPKXXHGdwpeQXbVJjK
	acyecysvBbj/j0Rdj0WrYfPBDGQA0Ifeyrq/1tlXNjJCxjgdCp8ZacyhfgX3IfD1uM1PmaezO0B
	fHpN+aL6WQBXV3ASsLY+8QdY=
X-Received: by 2002:a17:903:287:b0:272:1320:121f with SMTP id d9443c01a7336-27cc2d8f1dbmr76992035ad.27.1758715255830;
        Wed, 24 Sep 2025 05:00:55 -0700 (PDT)
Received: from localhost ([103.88.46.62])
        by smtp.gmail.com with ESMTPSA id d9443c01a7336-26980180bdesm188579175ad.56.2025.09.24.05.00.54
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 24 Sep 2025 05:00:55 -0700 (PDT)
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
Subject: [PATCH v5 22/23] docs: add KStackWatch document
Date: Wed, 24 Sep 2025 19:59:28 +0800
Message-ID: <20250924115931.197077-7-wangjinchao600@gmail.com>
X-Mailer: git-send-email 2.43.0
In-Reply-To: <20250924115931.197077-1-wangjinchao600@gmail.com>
References: <20250924115124.194940-1-wangjinchao600@gmail.com>
 <20250924115931.197077-1-wangjinchao600@gmail.com>
MIME-Version: 1.0
X-Original-Sender: wangjinchao600@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=bqg6nV52;       spf=pass
 (google.com: domain of wangjinchao600@gmail.com designates
 2607:f8b0:4864:20::52c as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
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

Add documentation for KStackWatch under Documentation/.

It provides an overview, main features, usage details, configuration
parameters, and example scenarios with test cases. The document also
explains how to locate function offsets and interpret logs.

Signed-off-by: Jinchao Wang <wangjinchao600@gmail.com>
---
 Documentation/dev-tools/index.rst       |   1 +
 Documentation/dev-tools/kstackwatch.rst | 316 ++++++++++++++++++++++++
 2 files changed, 317 insertions(+)
 create mode 100644 Documentation/dev-tools/kstackwatch.rst

diff --git a/Documentation/dev-tools/index.rst b/Documentation/dev-tools/index.rst
index 65c54b27a60b..45eb828d9d65 100644
--- a/Documentation/dev-tools/index.rst
+++ b/Documentation/dev-tools/index.rst
@@ -31,6 +31,7 @@ Documentation/process/debugging/index.rst
    kcsan
    kfence
    kselftest
+   kstackwatch
    kunit/index
    ktap
    checkuapi
diff --git a/Documentation/dev-tools/kstackwatch.rst b/Documentation/dev-tools/kstackwatch.rst
new file mode 100644
index 000000000000..7a9e018ddccb
--- /dev/null
+++ b/Documentation/dev-tools/kstackwatch.rst
@@ -0,0 +1,316 @@
+.. SPDX-License-Identifier: GPL-2.0
+
+=================================
+KStackWatch: Kernel Stack Watch
+=================================
+
+Overview
+========
+
+KStackWatch is a lightweight debugging tool designed to detect kernel stack
+corruption in real time. It installs a hardware breakpoint (watchpoint)
+at a function's specified offset using *kprobe.post_handler* and
+removes it in *fprobe.exit_handler*. This covers the full execution
+window and reports corruption immediately with time, location, and
+call stack.
+
+Main features:
+
+* Immediate and precise detection
+* Supports concurrent calls to the watched function
+* Lockless design, usable in any context
+* Depth filter for recursive calls
+* Minimal impact on reproducibility
+* Flexible procfs configuration with key=val syntax
+
+Usage
+=====
+
+KStackWatch is configured through */proc/kstackwatch* using a key=value
+format. Both long and short forms are supported. Writing an empty string
+disables the watch.
+
+.. code-block:: bash
+
+	# long form
+	echo func_name=? func_offset=? ... > /proc/kstackwatch
+
+	# short form
+	echo fn=? fo=? ... > /proc/kstackwatch
+
+	# disable
+	echo > /proc/kstackwatch
+
+The function name and the instruction offset where the watchpoint should
+be placed must be known. This information can be obtained from
+*objdump* or other tools.
+
+Required parameters
+--------------------
+
++--------------+--------+-----------------------------------------+
+| Parameter    | Short  | Description                             |
++==============+========+=========================================+
+| func_name    | fn     | Name of the target function             |
++--------------+--------+-----------------------------------------+
+| func_offset  | fo     | Instruction pointer offset              |
++--------------+--------+-----------------------------------------+
+
+Optional parameters
+--------------------
+
+Default 0 and can be omitted.
+Both decimal and hexadecimal are supported.
+
++--------------+--------+------------------------------------------------+
+| Parameter    | Short  | Description                                    |
++==============+========+================================================+
+| depth        | dp     | Recursion depth filter                         |
++--------------+--------+------------------------------------------------+
+| max_watch    | mw     | Maximum number of concurrent watchpoints       |
+|              |        | (default 0, capped by available hardware       |
+|              |        | breakpoints)                                   |
++--------------+--------+------------------------------------------------+
+| sp_offset    | so     | Watching addr offset from stack pointer        |
++--------------+--------+------------------------------------------------+
+| watch_len    | wl     | Watch length in bytes (1, 2, 4, 8, or 0),      |
+|              |        | 0 means automatically watch the stack canary   |
+|              |        | and ignore the ``sp_offset`` parameter         |
++--------------+--------+------------------------------------------------+
+
+Workflow Example
+================
+
+Silent corruption
+-----------------
+
+Consider *test3* in *kstackwatch_test.sh*. Run it directly:
+
+.. code-block:: bash
+
+	echo test3 >/proc/kstackwatch_test
+
+Sometimes, *test_mthread_victim()* may report as unhappy:
+
+.. code-block:: bash
+
+	[    7.807082] kstackwatch_test: victim[0][11]: unhappy buf[8]=0xabcdabcd
+
+Its source code is:
+
+.. code-block:: c
+
+	static void test_mthread_victim(int thread_id, int seq_id, u64 start_ns)
+	{
+		ulong buf[BUFFER_SIZE];
+
+		for (int j = 0; j < BUFFER_SIZE; j++)
+			buf[j] = 0xdeadbeef + seq_id;
+
+		if (start_ns)
+			silent_wait_us(start_ns, VICTIM_MINIOR_WAIT_NS);
+
+		for (int j = 0; j < BUFFER_SIZE; j++) {
+			if (buf[j] != (0xdeadbeef + seq_id)) {
+				pr_warn("victim[%d][%d]: unhappy buf[%d]=0x%lx\n",
+					thread_id, seq_id, j, buf[j]);
+				return;
+			}
+		}
+
+		pr_info("victim[%d][%d]: happy\n", thread_id, seq_id);
+	}
+
+From the source code, the report indicates buf[8] was unexpectedly modified,
+a case of silent corruption.
+
+Configuration
+-------------
+
+Since buf[8] is the corrupted variable, the following configuration shows
+how to use KStackWatch to detect its corruption.
+
+func_name
+~~~~~~~~~~~
+
+As seen, buf[8] is initialized and modified in *test_mthread_victim*(),
+which sets *func_name*.
+
+func_offset & sp_offset
+~~~~~~~~~~~~~~~~~~~~~~~~~
+The watchpoint should be set after the assignment and as close as
+possible, which sets *func_offset*.
+
+The watchpoint should be set to watch buf[8], which sets *sp_offset*.
+
+Use the objdump output to disassemble the function:
+
+.. code-block:: bash
+
+	objdump -S --disassemble=test_mthread_victim vmlinux
+
+A shortened output is:
+
+.. code-block:: text
+
+	static void test_mthread_victim(int thread_id, int seq_id, u64 start_ns)
+	{
+	ffffffff815cb4e0:       e8 5b 9b ca ff          call   ffffffff81275040 <__fentry__>
+	ffffffff815cb4e5:       55                      push   %rbp
+	ffffffff815cb4e6:       53                      push   %rbx
+	ffffffff815cb4e7:       48 81 ec 08 01 00 00    sub    $0x108,%rsp
+	ffffffff815cb4ee:       89 fd                   mov    %edi,%ebp
+	ffffffff815cb4f0:       89 f3                   mov    %esi,%ebx
+	ffffffff815cb4f2:       49 89 d0                mov    %rdx,%r8
+	ffffffff815cb4f5:       65 48 8b 05 0b cb 80    mov    %gs:0x280cb0b(%rip),%rax        # ffffffff83dd8008 <__stack_chk_guard>
+	ffffffff815cb4fc:       02
+	ffffffff815cb4fd:       48 89 84 24 00 01 00    mov    %rax,0x100(%rsp)
+	ffffffff815cb504:       00
+	ffffffff815cb505:       31 c0                   xor    %eax,%eax
+		ulong buf[BUFFER_SIZE];
+	ffffffff815cb507:       48 89 e2                mov    %rsp,%rdx
+	ffffffff815cb50a:       b9 20 00 00 00          mov    $0x20,%ecx
+	ffffffff815cb50f:       48 89 d7                mov    %rdx,%rdi
+	ffffffff815cb512:       f3 48 ab                rep stos %rax,%es:(%rdi)
+
+		for (int j = 0; j < BUFFER_SIZE; j++)
+	ffffffff815cb515:       eb 10                   jmp    ffffffff815cb527 <test_mthread_victim+0x47>
+			buf[j] = 0xdeadbeef + seq_id;
+	ffffffff815cb517:       8d 93 ef be ad de       lea    -0x21524111(%rbx),%edx
+	ffffffff815cb51d:       48 63 c8                movslq %eax,%rcx
+	ffffffff815cb520:       48 89 14 cc             mov    %rdx,(%rsp,%rcx,8)
+	ffffffff815cb524:       83 c0 01                add    $0x1,%eax
+	ffffffff815cb527:       83 f8 1f                cmp    $0x1f,%eax
+	ffffffff815cb52a:       7e eb                   jle    ffffffff815cb517 <test_mthread_victim+0x37>
+		if (start_ns)
+	ffffffff815cb52c:       4d 85 c0                test   %r8,%r8
+	ffffffff815cb52f:       75 21                   jne    ffffffff815cb552 <test_mthread_victim+0x72>
+			silent_wait_us(start_ns, VICTIM_MINIOR_WAIT_NS);
+	...
+	ffffffff815cb571:       48 8b 84 24 00 01 00    mov    0x100(%rsp),%rax
+	ffffffff815cb579:       65 48 2b 05 87 ca 80    sub    %gs:0x280ca87(%rip),%rax        # ffffffff83dd8008 <__stack_chk_guard>
+	...
+	ffffffff815cb5a1:       eb ce                   jmp    ffffffff815cb571 <test_mthread_victim+0x91>
+	}
+	ffffffff815cb5a3:       e8 d8 86 f1 00          call   ffffffff824e3c80 <__stack_chk_fail>
+
+
+func_offset
+^^^^^^^^^^^
+
+The function begins at ffffffff815cb4e0. The *buf* array is initialized in a loop.
+The instruction storing values into the array is at ffffffff815cb520, and the
+first instruction after the loop is at ffffffff815cb52c.
+
+Because KStackWatch uses *kprobe.post_handler*, the watchpoint can be
+set right after ffffffff815cb520. However, this may cause false positives
+because the watchpoint is active before buf[8] is fully assigned.
+
+An alternative is to place the watchpoint at ffffffff815cb52c, right
+after the loop. This avoids false positives but leaves a small window
+for false negatives.
+
+In this document, ffffffff815cb52c is chosen for cleaner logs. If false
+negatives are suspected, repeat the test to catch the corruption.
+
+The required offset is calculated from the function start:
+
+*func_offset* is 0x4c (ffffffff815cb52c - ffffffff815cb4e0).
+
+sp_offset
+^^^^^^^^^^^
+
+From the disassembly, the buf array is at the top of the stack,
+meaning buf == rsp. Therefore, buf[8] sits at rsp + 8 * sizeof(ulong) =
+rsp + 64. Thus, *sp_offset* is 64.
+
+Other parameters
+~~~~~~~~~~~~~~~~~~
+
+* *depth* is 0, as test_mthread_victim is not recursive
+* *max_watch* is 0 to use all available hwbps
+* *watch_len* is 8, the size of a ulong on x86_64
+
+Parameters with a value of 0 can be omitted as defaults.
+
+Configure the watch:
+
+.. code-block:: bash
+
+	echo "fn=test_mthread_victim fo=0x4c so=64 wl=8" > /proc/kstackwatch
+
+Now rerun the test:
+
+.. code-block:: bash
+
+	echo test3 >/proc/kstackwatch_test
+
+The dmesg log shows:
+
+.. code-block:: text
+
+	[    7.607074] kstackwatch: ========== KStackWatch: Caught stack corruption =======
+	[    7.607077] kstackwatch: config fn=test_mthread_victim fo=0x4c so=64 wl=8
+	[    7.607080] CPU: 2 UID: 0 PID: 347 Comm: corrupting Not tainted 6.17.0-rc7-00022-g90270f3db80a-dirty #509 PREEMPT(voluntary)
+	[    7.607083] Call Trace:
+	[    7.607084]  <#DB>
+	[    7.607085]  dump_stack_lvl+0x66/0xa0
+	[    7.607091]  ksw_watch_handler.part.0+0x2b/0x60
+	[    7.607094]  ksw_watch_handler+0xba/0xd0
+	[    7.607095]  ? test_mthread_corrupting+0x48/0xd0
+	[    7.607097]  ? kthread+0x10d/0x210
+	[    7.607099]  ? ret_from_fork+0x187/0x1e0
+	[    7.607102]  ? ret_from_fork_asm+0x1a/0x30
+	[    7.607105]  __perf_event_overflow+0x154/0x570
+	[    7.607108]  perf_bp_event+0xb4/0xc0
+	[    7.607112]  ? look_up_lock_class+0x59/0x150
+	[    7.607115]  hw_breakpoint_exceptions_notify+0xf7/0x110
+	[    7.607117]  notifier_call_chain+0x44/0x110
+	[    7.607119]  atomic_notifier_call_chain+0x5f/0x110
+	[    7.607121]  notify_die+0x4c/0xb0
+	[    7.607123]  exc_debug_kernel+0xaf/0x170
+	[    7.607126]  asm_exc_debug+0x1e/0x40
+	[    7.607127] RIP: 0010:test_mthread_corrupting+0x48/0xd0
+	[    7.607129] Code: c7 80 0a 24 83 e8 48 f1 f1 00 48 85 c0 74 dd eb 30 bb 00 00 00 00 eb 59 48 63 c2 48 c1 e0 03 48 03 03 be cd ab cd ab 48 89 30 <83> c2 01 b8 20 00 00 00 29 c8 39 d0 7f e0 48 8d 7b 10 e8 d1 86 d4
+	[    7.607130] RSP: 0018:ffffc90000acfee0 EFLAGS: 00000286
+	[    7.607132] RAX: ffffc90000a13de8 RBX: ffff888102d57580 RCX: 0000000000000008
+	[    7.607132] RDX: 0000000000000008 RSI: 00000000abcdabcd RDI: ffffc90000acfe00
+	[    7.607133] RBP: ffff8881085bc800 R08: 0000000000000001 R09: 0000000000000000
+	[    7.607133] R10: 0000000000000001 R11: 0000000000000000 R12: ffff888105398000
+	[    7.607134] R13: ffff8881085bc800 R14: ffffffff815cb660 R15: 0000000000000000
+	[    7.607134]  ? __pfx_test_mthread_corrupting+0x10/0x10
+	[    7.607137]  </#DB>
+	[    7.607138]  <TASK>
+	[    7.607138]  kthread+0x10d/0x210
+	[    7.607140]  ? __pfx_kthread+0x10/0x10
+	[    7.607141]  ret_from_fork+0x187/0x1e0
+	[    7.607143]  ? __pfx_kthread+0x10/0x10
+	[    7.607144]  ret_from_fork_asm+0x1a/0x30
+	[    7.607147]  </TASK>
+	[    7.607147] kstackwatch: =================== KStackWatch End ===================
+	[    7.807082] kstackwatch_test: victim[0][11]: unhappy buf[8]=0xabcdabcd
+
+The line ``RIP: 0010:test_mthread_corrupting+0x48/0xd0`` shows the exact
+location where the corruption occurred. Now that the ``corrupting()`` function has
+been identified, it is straightforward to trace back to ``buggy()`` and fix the bug.
+
+
+More usage examples and corruption scenarios are provided in
+``kstackwatch_test.sh`` and ``mm/kstackwatch/test.c``.
+
+Limitations
+===========
+
+* Limited by available hardware breakpoints
+* Only one function can be watched at a time
+* Canary search limited to 128 * sizeof(ulong) from the current stack
+  pointer. This is sufficient for most cases, but has three limitations:
+
+  - If the stack frame is larger, the search may fail.
+  - If the function does not have a canary, the search may fail.
+  - If stack memory occasionally contains the same value as the canary,
+    it may be incorrectly matched.
+
+  In these cases, the user can provide the canary location using
+  ``sp_offset``, or treat any memory in the function prologue
+  as the canary.
-- 
2.43.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250924115931.197077-7-wangjinchao600%40gmail.com.
