Return-Path: <kasan-dev+bncBD53XBUFWQDBBEFKT3DQMGQEPGW2UZA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x340.google.com (mail-ot1-x340.google.com [IPv6:2607:f8b0:4864:20::340])
	by mail.lfdr.de (Postfix) with ESMTPS id 5EAC6BC89E7
	for <lists+kasan-dev@lfdr.de>; Thu, 09 Oct 2025 12:57:22 +0200 (CEST)
Received: by mail-ot1-x340.google.com with SMTP id 46e09a7af769-7b0826e4428sf374372a34.3
        for <lists+kasan-dev@lfdr.de>; Thu, 09 Oct 2025 03:57:22 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1760007441; cv=pass;
        d=google.com; s=arc-20240605;
        b=GfxPu0VKFNHp5hy20HxLhyBMbjKQ2wj0LK+PlYFMnhzHa/Rfk/1gaZMuQsKXszsTqM
         oRHE3CRxIDXuVj0/3jnZjQmiwj9qneRBbvz/AzRR2mIPSRoz6G0FAuWTvxfd8mK6tYmp
         LE0kKw7n/lYdg3vYMOuHwsQvhfsLfM9B8zh8hac6R6C12OP22gfsV7UafAi1vqOiLTe2
         36m37han/7ZWK6l7sEurCFA59wWzbh0fCbZQOnhNu6pm/rSXOUeQcWYIonqYKIan5+X6
         oTGTspDQxUdMATSZF4VjbWfDAaUC7ZQIeFeQ8LZOJserQxThXBcJVa9RRpOfjlZVHee5
         l2XA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=o89ppVtCLggA5Wj95PWQF6E6NECdMo4QA1Kcz6KLBaA=;
        fh=aXcGrsUSlEN9O1D3czo26ifTu+/xdBgtLMW6KOi9GBM=;
        b=OHIg0BkPBks1RQ2yA7QPVFy8cQJ6k+LiUOniA/+z/kolpDdxh2grcT/tbJWk2WqpIC
         JdZQbbqDTHyLYUSUdjsFo+Gm8DrjLVGRSQf9kS+Yy394stjwcID5s8ReQUSXjpPXNKqL
         xHQ5oeBwyioJvis0O8AJILvq2+uHSLPClHDxttwkh1QB8pmSnzPHw1nfUzjnhlxGPLzJ
         fch7twX0o0vT734rGB1Tb2WiM8jJoeDptlvRahf4xa/A7a0dLSO7kmqMx4yjsquinE5P
         bPItRznjAXYYLQDlNum+7ivVh6vVY+ISi/IC32JwhiHW/8wTKmDGK8g7965d9evXHlh0
         mvQg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b="X0/lGB7z";
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::1029 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1760007441; x=1760612241; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=o89ppVtCLggA5Wj95PWQF6E6NECdMo4QA1Kcz6KLBaA=;
        b=d4kZwMBFS9LKhTIX92sA1r+T3HdEr+CPIS28hQsiRnmgQgj2KeRwHDXf/mcjgKNYwf
         1Ge4Q/TLhqw7H1cLVLvhN9hE/h884agRuD8LqSeCmabpZ3f6+xXxcQXMUR7F1u8bPk8C
         x7NkCpQ/DuCquYY3v8U+M0nRMlOga88vXoyE4UPJ/4qlEHF8/uMFBKjoeWU9htToUj9O
         Wd1BWulZQqeNrZXSKgtrBAOM3qE4dAef9RNRRLi1679UyEkdampStfKyhF9XKPaW3H3Y
         asJ0rFbmtEzrU06fuTtr5XK991hiIa87r3Hs8tStG061xcm27diQUVl3bNxiVaLuD3Hr
         1AnA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1760007441; x=1760612241; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=o89ppVtCLggA5Wj95PWQF6E6NECdMo4QA1Kcz6KLBaA=;
        b=gHmPxSTcGC4aMAPIcz25cvglss/3037QCisSvYFvOFonyRdAaQeQIf371EisRLfm4I
         AJfhXqiEXX8GUvA45+4UDiEdU+L1Zz7c9/jzbyLb650BTe4wsAaLaLnNBYIPb9izNqdl
         m7ON1ybgttt65Q/un+4wkHRL/B2mVKDPEaMSPMrdQs/YF8c32IdIfKUa1qUpsNAFIWfu
         eEy/I0yCURNPzoqhHDsc2g/W7cEuhrF9M1NMxvZ3KTbSw+4PbgHAVx0i4BGtOKGxoE/z
         1ErNYl0WA92B1+SZqzpqXQnL2CzDRp626kbRaON95jOulUqR+2xVDkBog73QBevoFXO2
         O+KA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1760007441; x=1760612241;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=o89ppVtCLggA5Wj95PWQF6E6NECdMo4QA1Kcz6KLBaA=;
        b=tZ2dUUkRSW+SKk/yQWmPlyGnRba4Kb76czLM9540Ed7EEVRuGkY8sTc8DqnTK7mkgf
         MbQwgmKpiqwI8sG6Jx7IxjlZWvStu8Omn+FSsyRBSMnzzRlkgihfo46g6dHMX6kYGAvN
         +/efS/LhP6nSdp/qzkx+f2L4L93zVbMKdEy2i902UkdfD9xN/VVunq48zfLgeLXVhFrI
         zPtsWlPsh/7rf06YyKgxtn5Snba/4qAHZFDBUViCOU+PFxZS+O8EX5mDUwR6zl7UTRFQ
         H+qwkurLYzGNnemDVSIfL7Eq3R05x4bxfZho1t47PLVia4CzlJzb8Kyei6+33aGTodUi
         fR4Q==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCX32ewvrYIVAk2qGVPOPPGHJB1goCZKLFOeiYWxn6tF+NbUUsMzDR9/ZJ4vnsPc558eVzGOMw==@lfdr.de
X-Gm-Message-State: AOJu0YzdOJqFFtjUp0QwNoP6x19sUAF4uZ8KBKai9VBID9Goex15ArTR
	PmI99e0VBe9l35HFAgI0kBd3lGZbiLLAwRT+0R/VH+yIvBnjKGN8qPrt
X-Google-Smtp-Source: AGHT+IFp9EPLSv87k+XkC0zAwWDx+6LGqzWWdT3lIOmY688xiq7n9oJf/Q81PjGqwbJXEyG5kU5stg==
X-Received: by 2002:a05:6870:d695:b0:34b:cc55:9e85 with SMTP id 586e51a60fabf-3c0f590d804mr2902548fac.13.1760007440687;
        Thu, 09 Oct 2025 03:57:20 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="ARHlJd4mO1WcbbSxx3nrI1ngnu4y8+4yasLJpkjeGKpGsKzVZQ=="
Received: by 2002:a05:687c:2b86:b0:369:1f0e:87ae with SMTP id
 586e51a60fabf-3c725fd6682ls265521fac.1.-pod-prod-04-us; Thu, 09 Oct 2025
 03:57:20 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXAXZeqnY4alV+txCTRRN6G8Gpk5cRvhljNjH9da/RNXbrAscqdcHkWFZ0dyBrdeCozJhRZRQPu0pA=@googlegroups.com
X-Received: by 2002:a05:6808:1a17:b0:43f:bef8:dfa9 with SMTP id 5614622812f47-4417b47a928mr3439026b6e.45.1760007439830;
        Thu, 09 Oct 2025 03:57:19 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1760007439; cv=none;
        d=google.com; s=arc-20240605;
        b=E93pHB3NK6Ay6uTVdUeAOCRrhiwD4xtOL+pKos3bu62/5c1zmHx9J3Om0HE9ZnJ3H7
         n+zShfiojzbPbJ2l9iOxjEaBXhLtU+zX50bQTZT/lPrOh4JkxIzTm5nwhMStVEY7OfHy
         lwVsQCd3EU0I6eqahlQ90rgfI/7mSm4S9yl5Y5Edyktu7CmYfi59iIN0vwfYu49XQEKz
         0XIID0DsmGGW9kY8TWSK2NiZQeVnQ8ePct6soaT8tE9HBWQtgF+ZR3kl1onxrKvKRiKy
         2imsdx05WAKMGoswnRqBHp/TlG1p+M61R05VQgchsZ8AfbNWSpIijphw1+cZkxPMlUm4
         N+qg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=VjBqC5OmraL0dv+F2ewe7IKGLAdUyg9AVVWKAy3m9Vc=;
        fh=A/6ObcqONmbom8G3L6IuzhoJksB9zKJflACy8bjAsoI=;
        b=d34070doobCShSqFOWTpoO9aRo+2aEYyzJnaxjVw1+l3pIK5cIv9yb5Sh/h2WeUYUV
         dVINbjrDZWkIw8jqyEzvC6tP82DmUJ52YCXaStnBUadtheQ7V9+Aoh6uXW++U9nAhAtZ
         4S/PunGvz4jHJn9wEyNkPAvcVfvJ3KZdTNjABC25yXWS6/e2TGvQaGFdJcFyIHG95unW
         byqnKfU6A3Hf70kNne3PYAuTs+dDaqnl3bXF6pU9cBySvaWtScZUF8GhSVYP+98tGURQ
         Wom1KLU1xRIhTLLwEc0Q+/bd7Uxy2ZQuvnoCr74aYpEzcUO2uWdrGIbfnj/+PnolUMyv
         VnIw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b="X0/lGB7z";
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::1029 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pj1-x1029.google.com (mail-pj1-x1029.google.com. [2607:f8b0:4864:20::1029])
        by gmr-mx.google.com with ESMTPS id 5614622812f47-4418977bd08si167588b6e.5.2025.10.09.03.57.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 09 Oct 2025 03:57:19 -0700 (PDT)
Received-SPF: pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::1029 as permitted sender) client-ip=2607:f8b0:4864:20::1029;
Received: by mail-pj1-x1029.google.com with SMTP id 98e67ed59e1d1-3306d3ab2e4so880590a91.3
        for <kasan-dev@googlegroups.com>; Thu, 09 Oct 2025 03:57:19 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUNWLxC3TJ6SFXb6UZAE+QjU1g9oSzUlr00+bXB3emg6hEAcfBZFDRCAPM+gmr9XgBIY3k5O8mwwyg=@googlegroups.com
X-Gm-Gg: ASbGnctg5DroYf/t3Wb2FHt6ZFVaORyz/Z2dwr5tMfxvBBZvmySnzL+5tbghg+L7O9Q
	ia0+1+E2lqRLck/FPHY/J+7EitcuNA8PXlQL004xR62rvSMh2a8yU8ZqdjxdyeeDnLo7sdPyH4A
	qbQGsMopgrSd7YtqJKys9rdfGruMnXVNnArppvE0/AkmX/i/8BM+jFkDYxE4AUpovpUTDcbsplc
	4UtZSY75WhaX8C5sPPwf3hJh4SfRRmnLW1tqXnhb7+RpExUSuqhJZ9LcM5+nuiLg/keQECTA6Qs
	sj3pIg2f1yBCAiSdPJgBgLN0O62E66jDyEXy7RUVLlPWR+BmKmomG/Fuaix2zxHdh1ADtopNU1T
	zk5XjHqEFQtHzX2gsJFy/xZ4UC22AYcrkFnle2PwK6JnhzlWseBfFDR2x79Xy
X-Received: by 2002:a17:90b:1e4b:b0:330:72fb:ac13 with SMTP id 98e67ed59e1d1-33b51125511mr8955062a91.5.1760007438929;
        Thu, 09 Oct 2025 03:57:18 -0700 (PDT)
Received: from localhost ([45.142.165.62])
        by smtp.gmail.com with ESMTPSA id 41be03b00d2f7-b62dd50c879sm17747604a12.17.2025.10.09.03.57.17
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 09 Oct 2025 03:57:18 -0700 (PDT)
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
Subject: [PATCH v7 03/23] HWBP: Add modify_wide_hw_breakpoint_local() API
Date: Thu,  9 Oct 2025 18:55:39 +0800
Message-ID: <20251009105650.168917-4-wangjinchao600@gmail.com>
X-Mailer: git-send-email 2.43.0
In-Reply-To: <20251009105650.168917-1-wangjinchao600@gmail.com>
References: <20251009105650.168917-1-wangjinchao600@gmail.com>
MIME-Version: 1.0
X-Original-Sender: wangjinchao600@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b="X0/lGB7z";       spf=pass
 (google.com: domain of wangjinchao600@gmail.com designates
 2607:f8b0:4864:20::1029 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
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

From: "Masami Hiramatsu (Google)" <mhiramat@kernel.org>

Add modify_wide_hw_breakpoint_local() arch-wide interface which allows
hwbp users to update watch address on-line. This is available if the
arch supports CONFIG_HAVE_REINSTALL_HW_BREAKPOINT.
Note that this allows to change the type only for compatible types,
because it does not release and reserve the hwbp slot based on type.
For instance, you can not change HW_BREAKPOINT_W to HW_BREAKPOINT_X.

Signed-off-by: Masami Hiramatsu (Google) <mhiramat@kernel.org>
---
 arch/Kconfig                  | 10 ++++++++++
 arch/x86/Kconfig              |  1 +
 include/linux/hw_breakpoint.h |  6 ++++++
 kernel/events/hw_breakpoint.c | 37 +++++++++++++++++++++++++++++++++++
 4 files changed, 54 insertions(+)

diff --git a/arch/Kconfig b/arch/Kconfig
index ebe08b9186ad..bb4e4907c95c 100644
--- a/arch/Kconfig
+++ b/arch/Kconfig
@@ -456,6 +456,16 @@ config HAVE_MIXED_BREAKPOINTS_REGS
 	  Select this option if your arch implements breakpoints under the
 	  latter fashion.
 
+config HAVE_REINSTALL_HW_BREAKPOINT
+	bool
+	depends on HAVE_HW_BREAKPOINT
+	help
+	  Depending on the arch implementation of hardware breakpoints,
+	  some of them are able to update the breakpoint configuration
+	  without release and reserve the hardware breakpoint register.
+	  What configuration is able to update depends on hardware and
+	  software implementation.
+
 config HAVE_USER_RETURN_NOTIFIER
 	bool
 
diff --git a/arch/x86/Kconfig b/arch/x86/Kconfig
index 9d034a987c6e..ef5b31158271 100644
--- a/arch/x86/Kconfig
+++ b/arch/x86/Kconfig
@@ -245,6 +245,7 @@ config X86
 	select HAVE_FUNCTION_TRACER
 	select HAVE_GCC_PLUGINS
 	select HAVE_HW_BREAKPOINT
+	select HAVE_REINSTALL_HW_BREAKPOINT
 	select HAVE_IOREMAP_PROT
 	select HAVE_IRQ_EXIT_ON_IRQ_STACK	if X86_64
 	select HAVE_IRQ_TIME_ACCOUNTING
diff --git a/include/linux/hw_breakpoint.h b/include/linux/hw_breakpoint.h
index db199d653dd1..ea373f2587f8 100644
--- a/include/linux/hw_breakpoint.h
+++ b/include/linux/hw_breakpoint.h
@@ -81,6 +81,9 @@ register_wide_hw_breakpoint(struct perf_event_attr *attr,
 			    perf_overflow_handler_t triggered,
 			    void *context);
 
+extern int modify_wide_hw_breakpoint_local(struct perf_event *bp,
+					   struct perf_event_attr *attr);
+
 extern int register_perf_hw_breakpoint(struct perf_event *bp);
 extern void unregister_hw_breakpoint(struct perf_event *bp);
 extern void unregister_wide_hw_breakpoint(struct perf_event * __percpu *cpu_events);
@@ -124,6 +127,9 @@ register_wide_hw_breakpoint(struct perf_event_attr *attr,
 			    perf_overflow_handler_t triggered,
 			    void *context)		{ return NULL; }
 static inline int
+modify_wide_hw_breakpoint_local(struct perf_event *bp,
+				struct perf_event_attr *attr) { return -ENOSYS; }
+static inline int
 register_perf_hw_breakpoint(struct perf_event *bp)	{ return -ENOSYS; }
 static inline void unregister_hw_breakpoint(struct perf_event *bp)	{ }
 static inline void
diff --git a/kernel/events/hw_breakpoint.c b/kernel/events/hw_breakpoint.c
index 8ec2cb688903..5ee1522a99c9 100644
--- a/kernel/events/hw_breakpoint.c
+++ b/kernel/events/hw_breakpoint.c
@@ -887,6 +887,43 @@ void unregister_wide_hw_breakpoint(struct perf_event * __percpu *cpu_events)
 }
 EXPORT_SYMBOL_GPL(unregister_wide_hw_breakpoint);
 
+/**
+ * modify_wide_hw_breakpoint_local - update breakpoint config for local CPU
+ * @bp: the hwbp perf event for this CPU
+ * @attr: the new attribute for @bp
+ *
+ * This does not release and reserve the slot of a HWBP; it just reuses the
+ * current slot on local CPU. So the users must update the other CPUs by
+ * themselves.
+ * Also, since this does not release/reserve the slot, this can not change the
+ * type to incompatible type of the HWBP.
+ * Return err if attr is invalid or the CPU fails to update debug register
+ * for new @attr.
+ */
+#ifdef CONFIG_HAVE_REINSTALL_HW_BREAKPOINT
+int modify_wide_hw_breakpoint_local(struct perf_event *bp,
+				    struct perf_event_attr *attr)
+{
+	int ret;
+
+	if (find_slot_idx(bp->attr.bp_type) != find_slot_idx(attr->bp_type))
+		return -EINVAL;
+
+	ret = hw_breakpoint_arch_parse(bp, attr, counter_arch_bp(bp));
+	if (ret)
+		return ret;
+
+	return arch_reinstall_hw_breakpoint(bp);
+}
+#else
+int modify_wide_hw_breakpoint_local(struct perf_event *bp,
+				    struct perf_event_attr *attr)
+{
+	return -EOPNOTSUPP;
+}
+#endif
+EXPORT_SYMBOL_GPL(modify_wide_hw_breakpoint_local);
+
 /**
  * hw_breakpoint_is_used - check if breakpoints are currently used
  *
-- 
2.43.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251009105650.168917-4-wangjinchao600%40gmail.com.
