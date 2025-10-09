Return-Path: <kasan-dev+bncBD53XBUFWQDBBSFKT3DQMGQEL3SFE4Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-x1140.google.com (mail-yw1-x1140.google.com [IPv6:2607:f8b0:4864:20::1140])
	by mail.lfdr.de (Postfix) with ESMTPS id 76398BC8A29
	for <lists+kasan-dev@lfdr.de>; Thu, 09 Oct 2025 12:58:18 +0200 (CEST)
Received: by mail-yw1-x1140.google.com with SMTP id 00721157ae682-76d7efdbac9sf6730047b3.1
        for <lists+kasan-dev@lfdr.de>; Thu, 09 Oct 2025 03:58:18 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1760007497; cv=pass;
        d=google.com; s=arc-20240605;
        b=ZWW+NrcCAkbLmV7v6fkat/iEH1ysZXw04VXmtooTtoyXlPkJ2CkpwQafUDoAq/xKWd
         UOH87aCa/ic4sND5yexYndHpHL4/bBMySAk1JU9KasTxcv2ZFme6PFDzImBZjC6Gu087
         AdFUEWBZDk2aLn3YOh08u3BJcIQkTxNqchPHe6ERoRFKGzJT5g5gzoVi4O0VuuZxhTc7
         ocnLOnfWLx6/j7GNgPhNX9M7vxkNGKzdjXIMMQLnBUxzXH6LyMSXJWECYEtUi4aXiUYj
         pc/JnFfb3QM9oqy8ySB269Fs+Ot8QK49sKs+8e9CK3ozB5tkWd+fYDyZ1AMoD3ZKJClh
         3nqg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=K2PoKNc6WJBOC084y7RPSovQYijlyp1Gzlihi9mSN6M=;
        fh=GtA6gPEteTTGZ0D04eBMAWPrFvnRx8uRP0GNgZH74w8=;
        b=TRqZ7ZczB94dwXU4j1k8VB1j4haETl8vqiUVHCkM+uIodrvfT1oVoFCorjKSQdvDKJ
         VKhLsNkfW1DlqyfTyPBnpwvw1VTGJrVwPl4S/x+a44CvJq1CQ7Pb7CxQZJM8tIzf5ufp
         UbM2BIwsYuo4sAqfea+4gO6NYZoeBfk79TugscSyRsiCjQApB2WrvdERMEK4eMNRMT86
         OYvu1PDwY2e5keLx5jiMZDEUA3Uoo5vEY82+NVoVcrI5N6DSMrHAFaSTgWQX2IW8xdoP
         O8FfXizSj0Z8g50wnSlucsbm48jL+1jJGaUePy7r6tYm+t0qrvi7RDQX6atnpH2bg3LD
         tpig==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=lghT+pua;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::102a as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1760007497; x=1760612297; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=K2PoKNc6WJBOC084y7RPSovQYijlyp1Gzlihi9mSN6M=;
        b=KAwGhtMt7408xBirQKwxrSvyGcp3EOCWriTCSSYsBXsD0FV1NMcUpzP/HXiWUUVScW
         gCDNLYbr2rCjc+CFQYGg3J0iiJgN+QKFmTe3jBrMf+jhPz5ZWiftkiwBwoeykq7yd/l2
         ApgiBTAch/alHkeHZLw+hA0ue6ugef9HmG41BkRjgAiII6q6ilFEpoJizCXe+iWRv7DL
         tDBwj/KdNfQKIGb6yzLC5xJopejUwu6xqqprxjOtkDoSOcVXQCljNsBW/EsClRI4MQPw
         mn7Q8kFAo2TcoGgiobap/hm4+l9u9r+JXTG2KmGMFbnI6LHv0DBaTYdpMtwqQCe4AKGY
         hXRA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1760007497; x=1760612297; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=K2PoKNc6WJBOC084y7RPSovQYijlyp1Gzlihi9mSN6M=;
        b=ksMCnPWE3gsWWMQXepb9jaPTu1koCH6ymjBgQoUDH3Jidb50Jb9RKWu7wzbUfU9f/C
         cWsGRzAAqkuEkdDZrSGGhH8uLPadMcijaFytQKdBjetZOMBBeAwaYsLt1xxVzhnPOGPz
         +ptsKENMJqa584C38/dHcqfdjCf444t9/7XF1eBp0AMtqXZY7IU89g6aPmbFMY61mtLT
         R44ENH9c8Nrm1YJuhkItTlcVsRwrGHCzqZKJ4fQgbxAQ0+rX+df82xqa/SuIcQc3uY1s
         Saq/eg5QWTdEmPpRxn5Pd0eIG94kjgUx10mjfLqRz00dfrGNo3X4YgKFsWGOStmXIING
         lhqQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1760007497; x=1760612297;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=K2PoKNc6WJBOC084y7RPSovQYijlyp1Gzlihi9mSN6M=;
        b=pIN89SxSlNSghPtG9iAaXGd8sSouOK3Dshw95/+8I0oUrL4XmyjtrXVPpCYLYJpU85
         0oV8zQpbEx6T4AWIG8zKPpNbGvuq1dKc17OZxYqJuedc62P6Zxx3fqP+2pti039vXMyp
         6Ack2AMANSixYO1vFpcbdAwzyxwlZIez7YjUmbuaPk0ujpqvM6ni4KwDLCjIhoeXrFgn
         7cshwYyusMuVXkuuH3ur1HVvJeknWVSQWaUkyVTelCZxatYrEWRBU00+TxVgKNcMXqkF
         q/dyDbu5qFV3OPualDAw0xfseE2/NvBIyAMyOAtI+FQ4tZb+PRFOrioUMxUib5Fju2JB
         m1nQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXpoHlq7soqs/aw4E5Y5htIb3i04RY8yNAUbFFZtm98wj+ItFWINwOfMFwq9XQwxan8pLMYRA==@lfdr.de
X-Gm-Message-State: AOJu0YyyVTu05XrumSkg8Z+I6aS1FYFisVMgfRT76/oKCysagldKUV8q
	+H73cXOGdheU1UjPoT054W9VbLKlFMtbPl+6nPt9z4Sc+Jfys8V2csd4
X-Google-Smtp-Source: AGHT+IFBQE1WbzCoi92lSVoyqWKche8bg5b/P9wOxqpMaB7gXIGyF4dVef40OauqCap98Uu0HasGCw==
X-Received: by 2002:a53:c7d2:0:b0:633:102e:93ee with SMTP id 956f58d0204a3-63ccc3e11f3mr5376859d50.1.1760007496967;
        Thu, 09 Oct 2025 03:58:16 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="ARHlJd69PTL3HF0grw29ItwIFZSWPqpTS1742wpycmylRtV8fg=="
Received: by 2002:a53:c051:0:20b0:63b:92ec:fa4c with SMTP id
 956f58d0204a3-63cdec4d90cls227130d50.1.-pod-prod-00-us-canary; Thu, 09 Oct
 2025 03:58:16 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCViTelGZx+2C8HxtaZ99Dkenoll6FzLtaq77iO6RNvqbLqpqT7Xy/LRHbzUUd5ZoZtGGrAQZsU5PVU=@googlegroups.com
X-Received: by 2002:a05:690c:d17:b0:77f:7fd3:944b with SMTP id 00721157ae682-780e23eb504mr75643457b3.0.1760007496152;
        Thu, 09 Oct 2025 03:58:16 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1760007496; cv=none;
        d=google.com; s=arc-20240605;
        b=S1O77uGS6xlaTp3mtpc2HF6atOXG/9VkBIzZGbmfg1x7ZnbtPxoWHrEN2Y2znwm1NB
         Izy3UOp8cuZgO+M206EpiBMU3obMxFtLDMPwBCMeTUu0PYhlRsHa9g64Z7WUn1NQeian
         Hy4ZRe3ftgOk7UlMW7Q8qmeBqvQyCF+Aw2C9Pk/bKiWnwWdD2TV8HJpcFllcZMKw36wT
         opZVZMLV/GE/R5rbkfMX3iVO6OczPH5C/BfExzviGAy2uQOuXVRPKEJGNnK3LiptXKQI
         J+72KTE2DRNgAAefXmYiTwd3lSlLZWG4IdID1dFLceM4sqVFR7IHHwKiu3SHFOCm/hco
         yniw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=3Zjn9o91E8eMF6fANpWy8yJadTo2vfyIghwnTsVomDQ=;
        fh=9R766VWn4kTWQKa9TcoB3qBZZNXOgFRqF3r9dDc/mYY=;
        b=JJ3AMuBwY3OTxmbcNMS7bMnd9jJyHt886i4LHRaaEoff0bSLbBSIVkH6ubLtDbVhxu
         +iesXmTLdOcgLtzoRNKdpWMTxP1KFrAh49Abfnow5In1mzs1B6iANtK3lwmv6PuGYL/3
         GhU9KQmsFvbcv2KmNTC2sNryyw7QgcWbSppbJoJbiNBmwfp2tpvpt1/oDhzvmb4yAeWW
         3tloxL+mDOJ2yXYuD1cPjU1H/Lfp93G5wgs44r5M+HhOT5vWWuZuo4+mV5W10jY8cHM0
         cs37zbQscpr59ZKWOmcvr2xRwcbnlyjsosbOBEQpJrvA6ScPuLWRxgxZrdSHhCl14BrT
         N1tA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=lghT+pua;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::102a as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pj1-x102a.google.com (mail-pj1-x102a.google.com. [2607:f8b0:4864:20::102a])
        by gmr-mx.google.com with ESMTPS id 00721157ae682-780f624c72fsi751757b3.0.2025.10.09.03.58.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 09 Oct 2025 03:58:16 -0700 (PDT)
Received-SPF: pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::102a as permitted sender) client-ip=2607:f8b0:4864:20::102a;
Received: by mail-pj1-x102a.google.com with SMTP id 98e67ed59e1d1-3305c08d9f6so687979a91.1
        for <kasan-dev@googlegroups.com>; Thu, 09 Oct 2025 03:58:16 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWFmHwWRHjMJ7ge+DYXxeyxSIV02azZBfwKzFvZhjOeckPuJn8bo43Vs3xOj2qctVDOilBtU433v7U=@googlegroups.com
X-Gm-Gg: ASbGncv5gUTk317w2ujIx52lnT9SPWD8Oe1cXVZpnanMn6qWFXnp+x0SYBLZKsi6mKM
	R6MfRCW/ioCTQfG8zGlP+bAtaZt3w7JnwHNCPJduJvc1pEttVRfBvtksE3JApAlLbN5n4U1QdGk
	EbR/4ojYw3PpuQHU4u5vtJRy+JdQtIx7N4cL8JxAqA+tWS8BN7+F7zTtXZ3YxSfEBSyfjzRoEYA
	MzAFMKHJiwlxP3vUcKtHzfNDqr04uYmhJXkXqxSUTxiLtGppYujQtSYDByjTmrUezlt9M6F9cIf
	pIAD4pKCm6xfTLhrhCDYU7nYgVnxCE3SLazmkLS5hmEVaI7dArZsHa+CBeBoY3RGLpTYExhE7TB
	K8rdt7P7UYZ9v13RSqqPiQL1lp6IcKR1Y0Zc5Q1dwfXiU9ZamvgoqrzJ6Kni/m7gBkMr8ggM=
X-Received: by 2002:a17:90b:35d1:b0:327:c583:add with SMTP id 98e67ed59e1d1-339eda5cf24mr16255407a91.6.1760007495079;
        Thu, 09 Oct 2025 03:58:15 -0700 (PDT)
Received: from localhost ([45.142.165.62])
        by smtp.gmail.com with ESMTPSA id 98e67ed59e1d1-33b513ad555sm6898776a91.22.2025.10.09.03.58.14
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 09 Oct 2025 03:58:14 -0700 (PDT)
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
Subject: [PATCH v7 17/23] mm/ksw: add test module
Date: Thu,  9 Oct 2025 18:55:53 +0800
Message-ID: <20251009105650.168917-18-wangjinchao600@gmail.com>
X-Mailer: git-send-email 2.43.0
In-Reply-To: <20251009105650.168917-1-wangjinchao600@gmail.com>
References: <20251009105650.168917-1-wangjinchao600@gmail.com>
MIME-Version: 1.0
X-Original-Sender: wangjinchao600@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=lghT+pua;       spf=pass
 (google.com: domain of wangjinchao600@gmail.com designates
 2607:f8b0:4864:20::102a as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251009105650.168917-18-wangjinchao600%40gmail.com.
