Return-Path: <kasan-dev+bncBD53XBUFWQDBBWUI5XDAMGQES2SKJWA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103d.google.com (mail-pj1-x103d.google.com [IPv6:2607:f8b0:4864:20::103d])
	by mail.lfdr.de (Postfix) with ESMTPS id 9D693BAB0ED
	for <lists+kasan-dev@lfdr.de>; Tue, 30 Sep 2025 04:45:48 +0200 (CEST)
Received: by mail-pj1-x103d.google.com with SMTP id 98e67ed59e1d1-33428befc49sf5213665a91.0
        for <lists+kasan-dev@lfdr.de>; Mon, 29 Sep 2025 19:45:48 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1759200347; cv=pass;
        d=google.com; s=arc-20240605;
        b=GdCnWZf6jM5XtFBqAsTVzMli+7F+/74QMW6Y1+mH7K3quEwtqKWs7OkBQN3x3/YCWV
         atuo5YvGhevPZKpouDtpdc2rXW6c5aVCgxMfVfEUJMOYNN2+lt7tk9083arxha60mTn3
         S3+E3GeHyHjq76WUCW+ej2kF0aKyRaYuEzAnRg0FqlyUT1Zjj67gmuaTUb9U2jV8esX8
         MQnee9sjqeN+Kzc0deckodrAtEOn32rReqbl7oaIrpaZiJI2T+8QMnvsrfQ87168DQ3q
         psBxHPl8s52ToRqACcGV1SyJHnPkgXUZ36vqTbPOgsUH9R3YF6l6fG9TGZOqAANlkRoI
         G5gg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=DYRHIvzJ9+X9OojJsEYCeMbM5Es8GJq1vAKHuAwXbVI=;
        fh=MmrQxCw7vghSHJuf7ruKI+lInwKzy3hpQWiDI6gJrFo=;
        b=UjzPAl0qQp+DkQhzdupz/DSnw2wcZzzqnBct/i1zoNpa/FVJMMWjW3AF1mSevvjOwO
         NmY60qEsChNsxlPzoES1YJAP1Jojl1VwUB0OXsI6kh/AZqr3f1/Lx8lmS+dnvn34dtSr
         22Q9CnGriz9NfWGg5IJehwnd0XzcTolCPaXPyTsROlpF2qbZTVeUSlbHUDK2llstnd9T
         ow+yaz5KMNeXchHPB//d7zpVQzrAVV51CfOIiGAGLGP94qcv6YeygLoTxqjUJMhSVVin
         iMtitZVcePUVEZyQKLX42b8yrlKnIHcFZw1IgBf+3nGZHH4hlSjk3/E4s1C2wvke688m
         5vyA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=T5m05MJW;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::62e as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1759200347; x=1759805147; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=DYRHIvzJ9+X9OojJsEYCeMbM5Es8GJq1vAKHuAwXbVI=;
        b=PkhFB2SmymoB3I4DILsqMGq2dK7dZAYxWeGza0nUUkR08uHmRWzOYncmkzZ/eQPHYq
         9KBdWeLbhb5ixX//FdOY0xVXue7/ilbmcGVIi/4QdPfMobEhtOJg1l1XnYbvsFLMlf8M
         kdbU6CxLKvk9a6/jK7K3jB4iVGaLv+I/219/NPOww7nm86ofgz8RAIf42IsJb+3hKB+S
         v7sXQ4P3Dp+UM0g1Vk9P/wKQA6ydq8fGlX2ExBUqu+1olOQAvWmWEtiF0oSYBTakN/d+
         sQb9Q9HCHE1Yi5FB1VaxNMzH1D4x41MlNl7f8oqQcTCKp+npdQtMWLaXSuW/rYJ81z3l
         aS/Q==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1759200347; x=1759805147; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=DYRHIvzJ9+X9OojJsEYCeMbM5Es8GJq1vAKHuAwXbVI=;
        b=kShz5Fep9p5PbIkB7qwZs6EzMmOPwN4ZFWToOFlyEG4dlzyDASDWFsO8bv/fC5UfKz
         Nkcc8Ec1pNj4MECidHueHfn6l+oN2pGgBo/739IcFSdUgMxXMF1mC5TWpatYpnn+ERqV
         0zcH/TtU8hjYhA0Gtk2uHe3opKOhbTXKAI4AwY2LC7MnkLoFCVx1ockcXr7b+IK/oq7D
         kEk7xBvSffPSKhp6WNuQ/GSIBTQevwA0CIvzezGDpbeGClHMWK6BFGVOWkNTkyHb7U9f
         tqIYvVkw/S0nmL1yIjtR5mDbNFhE6wvWdxS5c8zhdFr/HvyM/OAWFbDg5jgI7HtlfxZr
         zSpA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1759200347; x=1759805147;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=DYRHIvzJ9+X9OojJsEYCeMbM5Es8GJq1vAKHuAwXbVI=;
        b=MO7Sj3CEabD5UeVfVR/YvW+2vZdjY8HVQ+JqLflJvClu6wW6l/yc6olk5sm0ZEgfB4
         ppWvvatvJzdxSWpYzdU7usVMSO4CI3SK7UihAAFNhQ4Mg5MaE+xtaoBE8vbygp5cG8Qv
         jmzqQT3j8ctddD2dYKzL+ZAuM9+4DcD3iZkf0cgVOVBvlT8WEDQDHyKeHj2Ma9l37SNu
         sevx2oRHIEl5ICB1SzwFii+kAUSi4kew2VheSnvqIZ0rwA1a0xk36DrSgK5jGm+D7yek
         jWNCAgjBiCgzt4QUaWDVPIctQP9xfC5lLMgyKmBwqyycweuW5vSLLX3/oG8A06M+S5nM
         QuOQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXzfuc6bVUIDx58ycjyKDyl0Rxmym8Qbawf/UqTf0NDkDy3XDtOkSVn3pr0oF8VH7u4OeYzUA==@lfdr.de
X-Gm-Message-State: AOJu0YxkoJvlCP2HA69ZEZPWjCO+EE77tdEb+h1hkvb07ippTpEEp/HR
	/gV/FXECRq9R/Jxn3MhUV1+kOwe/3fdokgQeCP6fm3UQ+pOybpb6cL5S
X-Google-Smtp-Source: AGHT+IEjOoyajvS1fQRHXFJeLocwFwmDirAY6m1+nPkdxICp5NYcsQD9BNRYZKoou9zJoplO20S8vw==
X-Received: by 2002:a17:90b:1a86:b0:32e:23c9:6f41 with SMTP id 98e67ed59e1d1-3383abf713emr2638131a91.5.1759200346957;
        Mon, 29 Sep 2025 19:45:46 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="ARHlJd5m4MmVCliMqCmjGJqxicGms9SwRG1bbLDDNQPd5zt/UA=="
Received: by 2002:a17:90b:4b8b:b0:32e:370a:2fc1 with SMTP id
 98e67ed59e1d1-3342a5b097els3242551a91.1.-pod-prod-00-us; Mon, 29 Sep 2025
 19:45:45 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWWB+p5cyAGmoGXBtjuUgN4C4c18LGrZ97RP7TUNOEqsaALo+JiXtwOob1dQBCnnWvw5zQ5BIChkR0=@googlegroups.com
X-Received: by 2002:a17:90b:4b0b:b0:32e:dcc6:cd33 with SMTP id 98e67ed59e1d1-3383ac093f8mr3016431a91.11.1759200345695;
        Mon, 29 Sep 2025 19:45:45 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1759200345; cv=none;
        d=google.com; s=arc-20240605;
        b=kwGErp6qi1Da7trLwPFP/CbUOP+ejya153o7wubfsyuHNc4BRdiQvX77EZai+4D/68
         7TKhiHFHAt0PMjdP5JeX1etBHBFTAQSs3UiaxSVVPrFFGnUKQqG7e599yrhP6w71hSYD
         wfP3oxiITOnr2KvDg+VTFUs0FK6OIyLqu/S6bJRyWsthQ5zVZvPrFqWwoR37UVRPEavS
         3120/ZqaHLtX5X12zv6D4e5JT83cE1PH9AYOZpz7o5uQtnaRcqxp3+Wl4Nm5ls+Mm/r0
         jnalyKixdgrYHlPdlU/RU2h3Yra21cB8XYDy9nLoETciex5bKyrh9QIByve6iDWwwNOQ
         9aLA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=3Zjn9o91E8eMF6fANpWy8yJadTo2vfyIghwnTsVomDQ=;
        fh=aiHwRSgP3yvZuOahbAwA5wthZDJZ6Z0VZGHOR8RlRMs=;
        b=eILk1u9ZDTRlAqeu0WKdDPJE1q9oMMYJoAU+yhBA+eoV+DGMfe9+7QZ7xMcAsD/A4B
         RxfBVF+DkeIg+gneZBJQJf+LPbfu7Okd+qYLsbLaJh2N4XwYbPgZgLYP89kGBQwLO+h9
         2uH6C+nJPwhzHxjYUB3TYnT0MjhqphSl1M6nfArznMY54EyP9Ngos3e6wAeOry0enL4s
         phm840AhUjrIxym+DOreJMrcdMtBlDS/A3DuJh9hlRG7FhnBfZEEaN670E3n8m0zC5tA
         1n9AMaiLVqOuakeOKujY7Nt/jqIvUidCBCHpa4oM0byCZ0MsswaB3A1CxNAMTqguIFap
         qhtQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=T5m05MJW;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::62e as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pl1-x62e.google.com (mail-pl1-x62e.google.com. [2607:f8b0:4864:20::62e])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-3399bc48235si28877a91.0.2025.09.29.19.45.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 29 Sep 2025 19:45:45 -0700 (PDT)
Received-SPF: pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::62e as permitted sender) client-ip=2607:f8b0:4864:20::62e;
Received: by mail-pl1-x62e.google.com with SMTP id d9443c01a7336-2697899a202so45355235ad.0
        for <kasan-dev@googlegroups.com>; Mon, 29 Sep 2025 19:45:45 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWpRCSFRL/Nmmsjqgg4vwjqGjyr8soe1f0hon+1Kk5fD1qC4ZgvBErt2RbUiGEYsPlXyJc3sH7hgFY=@googlegroups.com
X-Gm-Gg: ASbGncvbqEfiyRER52yPaw8b8iRYjs7L8YGVRciDYcHl0CmzoqQN4qd4cyWZymeWJws
	w0AYEvW0/Ywg9rODxnpSg92hjV8TgOmxoTrPvosUHbuzuCKUZM6Sp0+oHsb4Eyv/z1t4Izka7ub
	5TFe+a13XDaRyjJgtlfKRmJ90im5ZfrxZ3nZvlAoaCYlwxt7PPerS2N3HYqwtscFbhp9+sJCTdV
	XtiZLqbhZ01szL+rEYRCsgx7eyTAz8/z84WwryU4AXS+vjNmJOKuehCC89ydb5KIu67kyFT1Tvc
	vCBLW1grq2Rt00di3quEBpvhaYmf79knrs+Ef0JlsIKrghoLV7Bem5b5OTHkkNyn5NEzxDkV74t
	VFE3onFw9kgES5u1mIpdqDfKHBZoalU2XjlFwHigUUcDPYbO3AfWQ//NL0C352gBQSepOrcjWR+
	QQ
X-Received: by 2002:a17:903:2f4e:b0:25d:510:622c with SMTP id d9443c01a7336-28d1718d306mr31185225ad.28.1759200345170;
        Mon, 29 Sep 2025 19:45:45 -0700 (PDT)
Received: from localhost ([45.142.167.196])
        by smtp.gmail.com with ESMTPSA id d9443c01a7336-27eea801b49sm118165465ad.23.2025.09.29.19.45.44
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 29 Sep 2025 19:45:44 -0700 (PDT)
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
Subject: [PATCH v6 17/23] mm/ksw: add test module
Date: Tue, 30 Sep 2025 10:43:38 +0800
Message-ID: <20250930024402.1043776-18-wangjinchao600@gmail.com>
X-Mailer: git-send-email 2.43.0
In-Reply-To: <20250930024402.1043776-1-wangjinchao600@gmail.com>
References: <20250930024402.1043776-1-wangjinchao600@gmail.com>
MIME-Version: 1.0
X-Original-Sender: wangjinchao600@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=T5m05MJW;       spf=pass
 (google.com: domain of wangjinchao600@gmail.com designates
 2607:f8b0:4864:20::62e as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
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

Add a standalone test module for KStackWatch to validate functionality
in controlled scenarios.

The module exposes a simple interface via debugfs
(/sys/kernel/debug/kstackwatch/test), allowing specific test cases to
be triggered with commands such as:

  echo test0 > /sys/kernel/debug/kstackwatch/test

To ensure predictable behavior during testing, the module is built with
optimizations disabled.

Signed-off-by: Jinchao Wang <wangjinchao600@gmail.com>
---
 mm/Kconfig.debug             |  10 +++
 mm/kstackwatch/Makefile      |   6 ++
 mm/kstackwatch/kernel.c      |   5 ++
 mm/kstackwatch/kstackwatch.h |   2 +
 mm/kstackwatch/test.c        | 121 +++++++++++++++++++++++++++++++++++
 5 files changed, 144 insertions(+)
 create mode 100644 mm/kstackwatch/test.c

diff --git a/mm/Kconfig.debug b/mm/Kconfig.debug
index 24f4c4254f01..224bd561dcbb 100644
--- a/mm/Kconfig.debug
+++ b/mm/Kconfig.debug
@@ -317,3 +317,13 @@ config KSTACK_WATCH
 	  A lightweight real-time debugging tool to detect stack corruption.
 
 	  If unsure, say N.
+
+config KSTACK_WATCH_TEST
+	tristate "KStackWatch Test Module"
+	depends on KSTACK_WATCH
+	help
+	  This module provides controlled stack corruption scenarios to verify
+	  the functionality of KStackWatch. It is useful for development and
+	  validation of KStackWatch mechanism.
+
+	  If unsure, say N.
diff --git a/mm/kstackwatch/Makefile b/mm/kstackwatch/Makefile
index 84a46cb9a766..d007b8dcd1c6 100644
--- a/mm/kstackwatch/Makefile
+++ b/mm/kstackwatch/Makefile
@@ -1,2 +1,8 @@
 obj-$(CONFIG_KSTACK_WATCH)	+= kstackwatch.o
 kstackwatch-y := kernel.o stack.o watch.o
+
+obj-$(CONFIG_KSTACK_WATCH_TEST)	+= kstackwatch_test.o
+kstackwatch_test-y := test.o
+CFLAGS_test.o := -fno-inline \
+		-fno-optimize-sibling-calls \
+		-fno-pic -fno-pie -O0 -Og
diff --git a/mm/kstackwatch/kernel.c b/mm/kstackwatch/kernel.c
index 57628bace365..12b2f5ceb5d4 100644
--- a/mm/kstackwatch/kernel.c
+++ b/mm/kstackwatch/kernel.c
@@ -233,6 +233,11 @@ const struct ksw_config *ksw_get_config(void)
 	return ksw_config;
 }
 
+struct dentry *ksw_get_dbgdir(void)
+{
+	return dbgfs_dir;
+}
+
 static int __init kstackwatch_init(void)
 {
 	int ret = 0;
diff --git a/mm/kstackwatch/kstackwatch.h b/mm/kstackwatch/kstackwatch.h
index 528001534047..b7361d5d071d 100644
--- a/mm/kstackwatch/kstackwatch.h
+++ b/mm/kstackwatch/kstackwatch.h
@@ -34,6 +34,8 @@ struct ksw_config {
 
 // singleton, only modified in kernel.c
 const struct ksw_config *ksw_get_config(void);
+struct dentry *ksw_get_dbgdir(void);
+
 
 /* stack management */
 int ksw_stack_init(void);
diff --git a/mm/kstackwatch/test.c b/mm/kstackwatch/test.c
new file mode 100644
index 000000000000..80fec9cf3243
--- /dev/null
+++ b/mm/kstackwatch/test.c
@@ -0,0 +1,121 @@
+// SPDX-License-Identifier: GPL-2.0
+#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
+
+#include <linux/debugfs.h>
+#include <linux/delay.h>
+#include <linux/kthread.h>
+#include <linux/list.h>
+#include <linux/module.h>
+#include <linux/prandom.h>
+#include <linux/printk.h>
+#include <linux/random.h>
+#include <linux/spinlock.h>
+#include <linux/string.h>
+#include <linux/uaccess.h>
+
+#include "kstackwatch.h"
+
+static struct dentry *test_file;
+
+#define BUFFER_SIZE 32
+
+static void test_watch_fire(void)
+{
+	u64 buffer[BUFFER_SIZE] = { 0 };
+
+	pr_info("entry of %s\n", __func__);
+	ksw_watch_show();
+	ksw_watch_fire();
+	pr_info("buf[0]:%lld\n", buffer[0]);
+
+	barrier_data(buffer);
+	pr_info("exit of %s\n", __func__);
+}
+
+static ssize_t test_dbgfs_write(struct file *file, const char __user *buffer,
+				size_t count, loff_t *pos)
+{
+	char cmd[256];
+	int test_num;
+
+	if (count >= sizeof(cmd))
+		return -EINVAL;
+
+	if (copy_from_user(cmd, buffer, count))
+		return -EFAULT;
+
+	cmd[count] = '\0';
+	strim(cmd);
+
+	pr_info("received command: %s\n", cmd);
+
+	if (sscanf(cmd, "test%d", &test_num) == 1) {
+		switch (test_num) {
+		case 0:
+			test_watch_fire();
+			break;
+		default:
+			pr_err("Unknown test number %d\n", test_num);
+			return -EINVAL;
+		}
+	} else {
+		pr_err("invalid command format. Use 'testN'.\n");
+		return -EINVAL;
+	}
+
+	return count;
+}
+
+static ssize_t test_dbgfs_read(struct file *file, char __user *buffer,
+			       size_t count, loff_t *ppos)
+{
+	static const char usage[] =
+		"KStackWatch Simplified Test Module\n"
+		"============ usage ===============\n"
+		"Usage:\n"
+		"echo test{i} > /sys/kernel/debug/kstackwatch/test\n"
+		" test0 - test watch fire\n";
+
+	return simple_read_from_buffer(buffer, count, ppos, usage,
+				       strlen(usage));
+}
+
+static const struct file_operations test_dbgfs_fops = {
+	.owner = THIS_MODULE,
+	.read = test_dbgfs_read,
+	.write = test_dbgfs_write,
+	.llseek = noop_llseek,
+};
+
+static int __init kstackwatch_test_init(void)
+{
+	struct dentry *ksw_dir = ksw_get_dbgdir();
+
+	if (!ksw_dir) {
+		pr_err("kstackwatch must be loaded first\n");
+		return -ENODEV;
+	}
+
+	test_file = debugfs_create_file("test", 0600, ksw_dir, NULL,
+					&test_dbgfs_fops);
+	if (!test_file) {
+		pr_err("Failed to create debugfs test file\n");
+		return -ENOMEM;
+	}
+
+	pr_info("module loaded\n");
+	return 0;
+}
+
+static void __exit kstackwatch_test_exit(void)
+{
+	debugfs_remove(test_file);
+	pr_info("module unloaded\n");
+}
+
+module_init(kstackwatch_test_init);
+module_exit(kstackwatch_test_exit);
+
+MODULE_AUTHOR("Jinchao Wang");
+MODULE_DESCRIPTION("KStackWatch Test Module");
+MODULE_LICENSE("GPL");
-- 
2.43.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250930024402.1043776-18-wangjinchao600%40gmail.com.
