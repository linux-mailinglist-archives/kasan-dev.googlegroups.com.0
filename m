Return-Path: <kasan-dev+bncBD53XBUFWQDBB44I5XDAMGQECYPK5EY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x639.google.com (mail-pl1-x639.google.com [IPv6:2607:f8b0:4864:20::639])
	by mail.lfdr.de (Postfix) with ESMTPS id CA941BAB10B
	for <lists+kasan-dev@lfdr.de>; Tue, 30 Sep 2025 04:46:13 +0200 (CEST)
Received: by mail-pl1-x639.google.com with SMTP id d9443c01a7336-277f0ea6ee6sf67560055ad.0
        for <lists+kasan-dev@lfdr.de>; Mon, 29 Sep 2025 19:46:13 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1759200372; cv=pass;
        d=google.com; s=arc-20240605;
        b=bd6oK7EOd6qbwp5NJrW82suFxELNJA9f5aPicabdqIraNSnm3a9GRDR9huIAsZ/hxM
         9W4QseLzBvFZdNL+78sZzMudq8sRNuKPrL56rOjEf+HPkSfySVmpbPF3beX7QI6EVfG4
         9fFxwgWuLydkLZ4ZZrcUeG0kMJtsDl5Wq2y8t8IVLiRaEd7ow2MUfad9YvPKyKLV2VFX
         mOPmIPUBbyirc5zEtSqmbkcsiYeoaWo30FANnRdcRA+7uMa/tg6O8bd1aoZbMgXVS5d+
         VCgYjo/u9g99UBCkV+R3Y0ZJC6QN8mr226APr69oCpSFolh8VbKcRtxbRbjpMOvy2ajM
         Yh0w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=gJlUJ6Pwre45jM2Ch7aepkhk6Rx04SaNipwpKlIJWmU=;
        fh=2AsY6zW8Bk6OyGXI9DHDIk7+bkwP3vlgsg55nQWF06Y=;
        b=Um3014GIkF7tsP/p26U+opD24OHYju5y4xwWlktpRKP0X32uYVx5ok/R2qoo/DI/TZ
         Cq3HXXRtamxXvKbLD+/3ToHhWObfuMqhPrG3rY2Awt4sMl20jbhAjQG4VjEYaE0eZ78s
         7HU0fmDUuntlfeqH5wGRaNeuY3pCg9cAhMmo3jJbcliXLtyXDM7flcMnMkVU0/AV2RO+
         HRDnmQ23j4oZJrhvcEllr1zQnqMe4oK/i5jAPB5o+fMO6E3JQ1mMmDZ2AyJVFXDANPoR
         jj8SM8vVrpOF2piwHXu9C40PdwRFpcONCCvAt3oGKzgQAYTgf2hRc6rH3Dj41x9kjEz3
         r4Ew==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=PoQCbHOE;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::530 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1759200372; x=1759805172; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=gJlUJ6Pwre45jM2Ch7aepkhk6Rx04SaNipwpKlIJWmU=;
        b=YyFhblm7FejBjjp+bT/W88yQZa+vDAO/MKdyeyWrl3LZjDRJGBMyvGXES7j6v54o9l
         75IH48CopicOe7OLX02GbGqQyh0BNUs3KLNJVAZC22ms7ew1M73cYiqsRFfEtOAQIKH5
         u4S37q6Se1yXTK3lCIdJfJF3lzBnQ/qGifXEfaBoRgFs4iAcorPP1d9PxHQsEZlxifnx
         GGv+QZuIXBFpwiGz6A6LQ5B2XFuAs7ua940ClfFTdlM4oHXaUSxzA46W8Jq1qh8HlmrZ
         9fdA//7DwuUpqmhGJ9c8V30TDAhrki4M1Pmv6pjZeKQIKnrx2q2LEZvoN+Z+wvjsh5Gq
         KHQw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1759200372; x=1759805172; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=gJlUJ6Pwre45jM2Ch7aepkhk6Rx04SaNipwpKlIJWmU=;
        b=BViHG5vL5pphGKfbsEBsToCQd5WHqEfO2gGXtVxzQm/BrmTWTdvu97KB01/3cZGboM
         3vsNiQrghkrhcmNLpZaYs81Z6U/7qmRj4rURP9dxGXaTEtgSPPSR/CadrZ29zEDNMC7+
         tKVPFVoQ4XSbwSv2cPoOyPZESM16+a+B8+YBOIkEk5G4OJSm7JaxPNpTYVrug9z4PnBX
         3v/OTbGhRHwzcKme7QyTh2cewHq1K+93OX4MpAvdmHSh9Zav5L+JY+7k48JPeCb17vI6
         ibV1HMdwuk6di6N4DhMjAOl49wWvLB2jiWtE+78CdgqGWBQOEnOlpDuL2OwtFZWQ36u2
         Ce8g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1759200372; x=1759805172;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=gJlUJ6Pwre45jM2Ch7aepkhk6Rx04SaNipwpKlIJWmU=;
        b=HiWLf+uxxW9tG7hD6G84t7GZQTObjD6RBWatiFdR7+CpIG65dumYlCqGJgw+T8ske/
         yBAaLyT4RCGUWYzNK0HVDvRqcJglqGQEdHOUxNHTlR1XrSVR66djLgD3agfhVdgVPdZs
         fcx2YFUH+BzSTfQGsenQX6VT1X9RSHrS1IEI1hfTHzBP6ygPB6NqvJrT9M2nX2IXKrKv
         MEzuvCXzl6QcvjYnaTcJvhAxykX9tBrLULrhjSdjZsj/nippxs+6Cu7jdXCgcGiwJlL8
         rotNTFifEvlvg2B+TX2rdE9YbVb6rvSFf2ZpijH7yTXAaiTJx3Oqce1zXfXNfbegvxHF
         IAFg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUynNbKiQHlGX3tGSgGPH4JDWLHPGkzcOjfpiFKQ5vbUmGfetwFjtGEKWfac4mpw+s/42cKrw==@lfdr.de
X-Gm-Message-State: AOJu0YxAYNIQy7ULdtf/9ED9BeCVyduxlbkwoOc3SCZcILthWmEE8mDx
	/y69DUwIEqxMcjbwbhOwAqDt0QnJKGer9nYFadG1RqG9Sg8133gVCvtw
X-Google-Smtp-Source: AGHT+IHyf+6RJ07nzkReijT+pH4H/b/FMwRyTaneoquRzaeYp2gY3X4oHs9oYukxKFj0RrSnBcAvFA==
X-Received: by 2002:a17:903:32ce:b0:267:c984:8d9f with SMTP id d9443c01a7336-27ed4a0dba3mr218144885ad.24.1759200372081;
        Mon, 29 Sep 2025 19:46:12 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="ARHlJd7UJU9l3F0lWAwfV2Djq//iPHDnwOsDSOq2nMYU3AgLmA=="
Received: by 2002:a17:90a:e7cf:b0:327:6f3a:16ba with SMTP id
 98e67ed59e1d1-3342a5e39eels6025157a91.2.-pod-prod-04-us; Mon, 29 Sep 2025
 19:46:10 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWtBX4FXFSFiaQIKFTSC8eas7Zi9/Vy8dqQJ/KLIWqtOXoh4fqr15q1Hi370wpFgjvTddQtJb/VhtM=@googlegroups.com
X-Received: by 2002:a17:90b:1d92:b0:32e:d282:3672 with SMTP id 98e67ed59e1d1-3342a2c0fcemr19675722a91.23.1759200370673;
        Mon, 29 Sep 2025 19:46:10 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1759200370; cv=none;
        d=google.com; s=arc-20240605;
        b=IBUi/EMwPcaRdL2c7YjS657XtiowSrMZM+8AQTmpCS/tzZX/zGcdin91+dDbkAaH5P
         JnquSDXEo9ZEw7bnd8KnR5F1Gd5KLRHf2zjqoukLnACcMGCMo69pPOyiRqDRxQtTk3h7
         OMyff66xKvgQScTnDtTo5lLfYf+8rjVm4PhritHmv+zb0B35a13th0+jdSs9mwLbz7BQ
         OO8DfqunwklP6RoJ2WYH43jstQZJYpIGuoS0aAGL+74izLsBnYipEEt8zB9iolSijhRt
         fiNcXnQ8Ow6d7wGLglqXjfBeJ3Til0X/KDOF0c80ZngInflZaXGpgDb/A/59zx7T7dP2
         mtLw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=6dXdR7Vr7GvNxroOAYy+aBhMqtIGh2YpUvjEzBf0MIg=;
        fh=D75x+sdEdFlCfx3IlMu5ZY1TLDYzVMmwl9wDANGxI2g=;
        b=e+tIrApiTwaTw/UTXzOyeJ9f/RDbdKoZyxtDq5v2GLG3nNZEIlecfA/bjFR+0lYQEI
         uqdoeNCGAMbH4P1oVzXLECNGHlmRNZNFWtyCqT3W5SnTOKZlHld/Rrc173J20TdtaRza
         PPRrxj0kLr/g4gFbQYCXrUoXN6OFkqxDj628Y3I0AyC3sxEXVB/SdaOchsDpz/O90dVF
         aA+sspaI3+RTFkbAkTv3wrluwLffCV1vEI+H+F8zEk/lgUxSghoBBGPz1l31O+TU8AIe
         FjomyZe4KCjAhSR7WcSKj8GW/JfcjpFaw4tdFRocJQQd5Om0c4dADe+tVwO1YI1EjXDt
         6Rtw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=PoQCbHOE;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::530 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pg1-x530.google.com (mail-pg1-x530.google.com. [2607:f8b0:4864:20::530])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-3399cc87741si18911a91.1.2025.09.29.19.46.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 29 Sep 2025 19:46:10 -0700 (PDT)
Received-SPF: pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::530 as permitted sender) client-ip=2607:f8b0:4864:20::530;
Received: by mail-pg1-x530.google.com with SMTP id 41be03b00d2f7-b550eff972eso3586199a12.3
        for <kasan-dev@googlegroups.com>; Mon, 29 Sep 2025 19:46:10 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUUlLpV0en8DkdHt3Xy3cnBHmPiB+ZfVUMj1wniMr+1xMquzx+I+3ZFfi3uKs0J6rt9lGsOPR28bG0=@googlegroups.com
X-Gm-Gg: ASbGncsG5tzScnJVx0wSd7jAC6Jk+51OoTBBFO38L77p0BBweWBtyR4kxAZ4rQIBXo+
	c8MLozNaMNEUbC4E+330a4tcWa0zusaHytXCE7LIw9ppSJf4VYCon6c6mYEjbB5yFmKxSSrKKrC
	enp2MVeZDQyC/3qvdWD0+Iny059HRIPhdQSlwSxs6HdPoZBFMwkaMgj3lKOa8cF+tHyW+rOkijH
	rCM1GHrdgAQB605qCWlw7l/OxdnpbYbKeXVuEW/N+cEv6QQcErCNJtYFko7dvhZJ9ba8p13L1L+
	LG1WHrN+/tcGREVwsptxjywLDeZTaMSLi4iQiXnrvjkQIWPl5YC0joDD4K34dp1pKbtkz0VDfci
	tS2TZWIHyMwANEiO1kCEwZVNQa7pN/AjykcCrIArbYGCMsaBiBr0b3cYi2r+KB2KJJw==
X-Received: by 2002:a17:902:f9c6:b0:275:2aac:fef8 with SMTP id d9443c01a7336-27ed4a78d81mr138634555ad.38.1759200370200;
        Mon, 29 Sep 2025 19:46:10 -0700 (PDT)
Received: from localhost ([45.142.167.196])
        by smtp.gmail.com with ESMTPSA id d9443c01a7336-27ed6715f0esm144277015ad.52.2025.09.29.19.46.09
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 29 Sep 2025 19:46:09 -0700 (PDT)
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
Subject: [PATCH v6 23/23] MAINTAINERS: add entry for KStackWatch
Date: Tue, 30 Sep 2025 10:43:44 +0800
Message-ID: <20250930024402.1043776-24-wangjinchao600@gmail.com>
X-Mailer: git-send-email 2.43.0
In-Reply-To: <20250930024402.1043776-1-wangjinchao600@gmail.com>
References: <20250930024402.1043776-1-wangjinchao600@gmail.com>
MIME-Version: 1.0
X-Original-Sender: wangjinchao600@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=PoQCbHOE;       spf=pass
 (google.com: domain of wangjinchao600@gmail.com designates
 2607:f8b0:4864:20::530 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
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

Add a maintainer entry for Kernel Stack Watch.

Signed-off-by: Jinchao Wang <wangjinchao600@gmail.com>
---
 MAINTAINERS | 8 ++++++++
 1 file changed, 8 insertions(+)

diff --git a/MAINTAINERS b/MAINTAINERS
index 520fb4e379a3..3d4811ff3631 100644
--- a/MAINTAINERS
+++ b/MAINTAINERS
@@ -13362,6 +13362,14 @@ T:	git git://git.kernel.org/pub/scm/linux/kernel/git/shuah/linux-kselftest.git
 F:	Documentation/dev-tools/kselftest*
 F:	tools/testing/selftests/
 
+KERNEL STACK WATCH
+M:	Jinchao Wang <wangjinchao600@gmail.com>
+S:	Maintained
+F:	Documentation/dev-tools/kstackwatch.rst
+F:	include/linux/kstackwatch_types.h
+F:	mm/kstackwatch/
+F:	tools/kstackwatch/
+
 KERNEL SMB3 SERVER (KSMBD)
 M:	Namjae Jeon <linkinjeon@kernel.org>
 M:	Namjae Jeon <linkinjeon@samba.org>
-- 
2.43.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250930024402.1043776-24-wangjinchao600%40gmail.com.
