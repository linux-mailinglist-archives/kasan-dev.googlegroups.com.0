Return-Path: <kasan-dev+bncBD53XBUFWQDBBWF2Z7DAMGQE3NR5WPI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf40.google.com (mail-qv1-xf40.google.com [IPv6:2607:f8b0:4864:20::f40])
	by mail.lfdr.de (Postfix) with ESMTPS id 2A66AB99B67
	for <lists+kasan-dev@lfdr.de>; Wed, 24 Sep 2025 14:00:27 +0200 (CEST)
Received: by mail-qv1-xf40.google.com with SMTP id 6a1803df08f44-78e30eaca8esf87916306d6.2
        for <lists+kasan-dev@lfdr.de>; Wed, 24 Sep 2025 05:00:27 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758715225; cv=pass;
        d=google.com; s=arc-20240605;
        b=LvRKBV5sTv0UJtYalrdE/3kUxoPO5IN421Bf47aq09h3HquygAWvOhG7YL5mkcHvuV
         21EtwPLYib3AAnF3vtgTLvXkW0GIyP0MbVW/5merueOkQk7qiV6O3yPZEABWCIeI69Ex
         sxcKl2+cfAYPOkKKKA9LN0tY8MBELiYMSM+pvbk2duvm9YKlLSGN3Z9XA1tDW/RfqhCm
         cYA8/ysTA8piWiMQwVaJCtSRw2j0yLed8mBcYfqtlIQTU7bLatZOwJ5SMtk8S3k+zCrx
         6Nqh6h44vAErcnv3BkZfKvzntnCW6odH51IyYd9Rpm5zVKeueUuTuVgw2am/eLx1jB/w
         HVOA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=bKi+qmElC7VAl+ETBhUfDgW+f7CQJ5Z9V3K4p3x/1fY=;
        fh=RxGkc3R13MdeCM7r3V4U/v3FYZtwKzb2dL5c+voarko=;
        b=G1fZ1RFdnorCQu2ovGjTR368MA+rI6/NW5F9G5Dz5d1kPh5AQlgj/I7G790UsZ5Zzk
         g6QbPHRGFUC/7gzTTiOp+qJnEVEM2yuFrDZfK3UHs9zzJqoJH8iw2JYRGtkT95sLpQ/Q
         rVr8H+beAOYeKx4FPevs+p2IERj1021FFputdZKKyOjFDi8w/he60ctHEzFLbbUzOii5
         dO/cCmpMsb17c6DxW60+7HlvLmWWASpfjAFgRlN7nYRci4QwzeA5/G2/8UVz7iLstjMG
         z42FH/EXh4JeWd4foKX0q0vZltAmhJ73uaq6l+xf1bdA6uPzYBAZHlqBrKfHq0dRqZBZ
         uflw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=MADYFh1+;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::434 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758715225; x=1759320025; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=bKi+qmElC7VAl+ETBhUfDgW+f7CQJ5Z9V3K4p3x/1fY=;
        b=lKz03dIxoCI/hHcB0BHOPNeQ8G0OQ8JuuTQqcAX5oay/AMcFOxXSc0174bgI40wLpn
         WkhK8I+tIzdxhGDujSOmQ5T2+zh7is4dfEQsXo1t3oeFn8r+g15hRTPkN4aSLXNtxbnh
         vEYmhQtlIzTeG1K+uUiBsgoCxLuE9cjsuOKrRJWPxAc6D+4oO3v2CPCwpZ7XW1i8Esiv
         /eIJKkAUaNt2QuNut+IyAqzwOrL6UuIu6ZPmzGKVvLpHgj4YFV3vtyffd44N+z+EznIA
         tyghUQCs6ZiL7O6Oseh7iR83LQ3RB7Hgc9fr/muDAMfmlz0IWfQDGQSTiTJElABFj2X/
         80Ug==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1758715225; x=1759320025; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=bKi+qmElC7VAl+ETBhUfDgW+f7CQJ5Z9V3K4p3x/1fY=;
        b=U2QHTCvRLHbiQwErFX/QSBeUH2mcaQXLPf0ff43nB5mGofmFJMhxae4NfBslQW29RC
         tXXSugruMxCTGieoHORa1/cIxWwogV7T4tYjacrUZNqgGgPqEb+JkizsQzBI3cCmiUJ+
         JUMeOMsXFSVGTqF+Sqz3JC4DDGr8lweUBrtqAKJFhpaTI43U+hevHVsNvH1FyB4WodLK
         3Ayzp4LMd9jnEJ+TMVZOwcgp0PHoLSPqTnOl8fSSUnVqPDe0UhRM9VjYPDg4XexXRyz8
         VQluD2NKIKMt5HC5+N3fP4fpnl03cNhM98ajw8iJ/5kw0zTCNWnMSy4P21XqptcFawRm
         Sc7g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758715225; x=1759320025;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=bKi+qmElC7VAl+ETBhUfDgW+f7CQJ5Z9V3K4p3x/1fY=;
        b=Sr2zkwDkoovALSaena71ucWgxeyFOmvY94UI2EkyIdeyDPiFRsZkj4B2LRr5QOwggd
         2oWS5KbTHCVzEfvviSzmEaUctzOW5U5UhXal51P/xrR3p/vSNEF1CSz1BNb2YePWfdWU
         59vkCpRbg83pBzptzY7HhfCmW+Kh8zfpGofQderf0/NLTDMJ7RvfezZUFY5cx/JApbhd
         0YeQh/R9GdN/XOJDNfh22VY7JltStPvZ2sm78+eRM3sxqBfNAWVewINwYs6fJkI/rLlH
         JLpVHQnrKlR6XpkBIUrjjb4TA+FhV2RlKqCIVa2mrP7Jt4kX/m8z8qqKwBuQfcStqPYx
         4+yA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXpU5NOKGnvoBYuox38pJ5k21gH4zVUVBIdegaZIZybrRSNxzH6cWE3+F4t9bMVmH5Iyg57ug==@lfdr.de
X-Gm-Message-State: AOJu0YwF9yQXlFJhnc/I5OBDaOKjfvg1OA4K/ycWFG5g7EBNc4P8RKZu
	r+uHm5JZJVUjqGqDrT6S875Wa51GFJPSK+y9vFMCLDPNyR5n9Y/Ougsm
X-Google-Smtp-Source: AGHT+IFE9oa6zR5V5IWlC+FTg2ZSdWlU3PICQW0fW3Uz/bIv3uyQ+j3P13JDxWajZIxDCxxQ89q7nA==
X-Received: by 2002:a05:6214:1c43:b0:7f9:e0e3:bd92 with SMTP id 6a1803df08f44-7f9e0e3c1b1mr5290586d6.33.1758715224371;
        Wed, 24 Sep 2025 05:00:24 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd7bm2muZx596ZodaQ3V+wswur1j0u7GmJo5RFeSyv6Gcw==
Received: by 2002:a05:6214:240f:b0:70b:acc1:ba52 with SMTP id
 6a1803df08f44-7934d2c0f60ls4732336d6.2.-pod-prod-02-us; Wed, 24 Sep 2025
 05:00:23 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVvAqTFk44/CawuPg24KtEsUZSIMWVl5AxFx5EJ9swzzJDfT2c3K10Ce5sr6nKVEZG1b5PltnrW+FY=@googlegroups.com
X-Received: by 2002:a05:6214:2306:b0:786:6b6:20e7 with SMTP id 6a1803df08f44-7e6fff967f5mr73037086d6.14.1758715223053;
        Wed, 24 Sep 2025 05:00:23 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1758715223; cv=none;
        d=google.com; s=arc-20240605;
        b=Z0z6RtpOqP8/EjKxwP1+TodiBrkAC4sW0ySwkVg+D5AcL2MXfJNb+MistzLYrq2aRz
         Fo+8SfcI3zK2zVvlqajzu6PDP6NjkUhYTWp69apY82BfZnaFioiGvtrWsHqctqlgJma9
         xZgZgPMCMjsLRZz4IbAIaB6V10RF1kMycbqD/7smfhAEjaAlT5bDtFG5Q+6O0VXz8olE
         HJdkqdnU74z+hGwFiVOSdcMi2gqdL+fFYaXhL1zi3j8oty8FwFNmAQQyGcuARYuh+lvk
         IWEWj1RREMJHIGhJkWN0PTuMkVR8YTtxu02aoWQkMtl8Xhnh0UYMBEPMkwC6FB6boYE/
         PPOw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=h46VjKRHdkcMiEZAqaWzAvZEGNArMuVfKDzvSU/d6uw=;
        fh=aFat/GVB08NDATAA1lP0mGxnGeB8NRLB2mwcgrNqrGk=;
        b=gGLlGvI1A/67XpLEE+DqzjguEalqGDPwQwuzuxpup/5p1o9JPuF21LSFl9E5r0Qb4T
         s4oXN/q5s2VCP0CDczVfkdMHKz3AELyi6O2Uo96FUA7F/P/U0aPL8rLoE+NqpQuGADA1
         4KE+LlM96mkV7fDDIFJmKKSF5qpTcIvW+4VFgh+Ja4dPcAfphZp6tVpArdSSfhg9T43v
         kY+r4f3fw+tFprIRLOQ9Q3HnHtnnNRWD5ZMyKguiKEtp/Mk05BZ4/retrxSQfE0bEaai
         arj7ZPpZVz4A8MgYN0nWAct/OmEIUVnmcKklDaJcf4+7W1klXd6vYW5QLUPI/BC5/zK+
         iVVA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=MADYFh1+;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::434 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pf1-x434.google.com (mail-pf1-x434.google.com. [2607:f8b0:4864:20::434])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-7934b5f1629si4183886d6.3.2025.09.24.05.00.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 24 Sep 2025 05:00:23 -0700 (PDT)
Received-SPF: pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::434 as permitted sender) client-ip=2607:f8b0:4864:20::434;
Received: by mail-pf1-x434.google.com with SMTP id d2e1a72fcca58-780f6632e64so169826b3a.2
        for <kasan-dev@googlegroups.com>; Wed, 24 Sep 2025 05:00:23 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCX36VMeKBJ9Ts5ZIVY2IJfU9m6jtQBm8kcjcg/thubJLHs1BYITSC7N01JEgCaoQjCrnm/x4C/mOzw=@googlegroups.com
X-Gm-Gg: ASbGncvEW1PxnFZ5u8xPUJpa5vyUljSmdBOz2Vb+GGP4B5YZdYloramaWVCZwrlB864
	oKvdLEBkfY+nHROgjkUGd5sKXe/J2sW925EB3nD9fDNvI7DIAYAw2RsIylftQ0wB7as9ngeS/Og
	GpTJnn1ybouigtNwB7Le5Bc9VTx/BmbvF0R2YrsmZH1XVcSMg9gxn3pvYcpCOCAZro55h2ivfwz
	3Jt0bwn5FuPP3DAKXDFrEL8goWlvxcFSYcCM9iyUZxnXuFrlf7oFTuZbJ2QDHrmvmt/7t2XZA+T
	Ow8LICsBl6n60HpuX6fGM5IuGgKq/lTKO9IQ4lN91Pv/7oUg0wnCBm0Nmu89PAD4RJIr26NZsXZ
	9wWn86gBTupaL76/jDUsDkBk=
X-Received: by 2002:a05:6a20:12ca:b0:24e:c235:d7ea with SMTP id adf61e73a8af0-2cffdb6b8a3mr8370045637.47.1758715221706;
        Wed, 24 Sep 2025 05:00:21 -0700 (PDT)
Received: from localhost ([103.88.46.62])
        by smtp.gmail.com with ESMTPSA id d2e1a72fcca58-77f335995cbsm9451657b3a.63.2025.09.24.05.00.19
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 24 Sep 2025 05:00:21 -0700 (PDT)
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
Subject: [PATCH v5 17/23] mm/ksw: add test module
Date: Wed, 24 Sep 2025 19:59:23 +0800
Message-ID: <20250924115931.197077-2-wangjinchao600@gmail.com>
X-Mailer: git-send-email 2.43.0
In-Reply-To: <20250924115931.197077-1-wangjinchao600@gmail.com>
References: <20250924115124.194940-1-wangjinchao600@gmail.com>
 <20250924115931.197077-1-wangjinchao600@gmail.com>
MIME-Version: 1.0
X-Original-Sender: wangjinchao600@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=MADYFh1+;       spf=pass
 (google.com: domain of wangjinchao600@gmail.com designates
 2607:f8b0:4864:20::434 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
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

Introduce a separate test module to validate functionality in controlled
scenarios.

The module provides a proc interface (/proc/kstackwatch_test) that allows
triggering specific test cases via simple commands:

  echo test0 > /proc/kstackwatch_test

Test module is built with optimizations disabled to ensure predictable
behavior.

Signed-off-by: Jinchao Wang <wangjinchao600@gmail.com>
---
 mm/Kconfig.debug        |  10 ++++
 mm/kstackwatch/Makefile |   6 ++
 mm/kstackwatch/test.c   | 122 ++++++++++++++++++++++++++++++++++++++++
 3 files changed, 138 insertions(+)
 create mode 100644 mm/kstackwatch/test.c

diff --git a/mm/Kconfig.debug b/mm/Kconfig.debug
index 89be351c0be5..291dd8a78b98 100644
--- a/mm/Kconfig.debug
+++ b/mm/Kconfig.debug
@@ -317,3 +317,13 @@ config KSTACK_WATCH
 	  A lightweight real-time debugging tool to detect stack corrupting.
 
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
diff --git a/mm/kstackwatch/test.c b/mm/kstackwatch/test.c
new file mode 100644
index 000000000000..1ed98931cc51
--- /dev/null
+++ b/mm/kstackwatch/test.c
@@ -0,0 +1,122 @@
+// SPDX-License-Identifier: GPL-2.0
+#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
+
+#include <linux/delay.h>
+#include <linux/kthread.h>
+#include <linux/list.h>
+#include <linux/module.h>
+#include <linux/prandom.h>
+#include <linux/printk.h>
+#include <linux/proc_fs.h>
+#include <linux/random.h>
+#include <linux/spinlock.h>
+#include <linux/string.h>
+#include <linux/uaccess.h>
+
+#include "kstackwatch.h"
+
+static struct proc_dir_entry *test_proc;
+
+#define BUFFER_SIZE 16
+#define MAX_DEPTH 6
+
+struct work_node {
+	ulong *ptr;
+	struct completion done;
+	struct list_head list;
+};
+
+static DECLARE_COMPLETION(work_res);
+static DEFINE_MUTEX(work_mutex);
+static LIST_HEAD(work_list);
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
+
+static ssize_t test_proc_write(struct file *file, const char __user *buffer,
+			       size_t count, loff_t *pos)
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
+static ssize_t test_proc_read(struct file *file, char __user *buffer,
+			      size_t count, loff_t *pos)
+{
+	static const char usage[] = "KStackWatch Simplified Test Module\n"
+				    "============ usage ==============\n"
+				    "Usage:\n"
+				    "echo test{i} > /proc/kstackwatch_test\n"
+				    " test0 - test watch fire\n";
+
+	return simple_read_from_buffer(buffer, count, pos, usage,
+				       strlen(usage));
+}
+
+static const struct proc_ops test_proc_ops = {
+	.proc_read = test_proc_read,
+	.proc_write = test_proc_write,
+};
+
+static int __init kstackwatch_test_init(void)
+{
+	test_proc = proc_create("kstackwatch_test", 0600, NULL, &test_proc_ops);
+	if (!test_proc) {
+		pr_err("Failed to create proc entry\n");
+		return -ENOMEM;
+	}
+	pr_info("module loaded\n");
+	return 0;
+}
+
+static void __exit kstackwatch_test_exit(void)
+{
+	if (test_proc)
+		remove_proc_entry("kstackwatch_test", NULL);
+	pr_info("module unloaded\n");
+}
+
+module_init(kstackwatch_test_init);
+module_exit(kstackwatch_test_exit);
+
+MODULE_AUTHOR("Jinchao Wang");
+MODULE_DESCRIPTION("Simple KStackWatch Test Module");
+MODULE_LICENSE("GPL");
-- 
2.43.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250924115931.197077-2-wangjinchao600%40gmail.com.
