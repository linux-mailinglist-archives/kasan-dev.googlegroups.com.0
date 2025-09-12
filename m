Return-Path: <kasan-dev+bncBD53XBUFWQDBBB7ER7DAMGQE6TW6TAI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd38.google.com (mail-io1-xd38.google.com [IPv6:2607:f8b0:4864:20::d38])
	by mail.lfdr.de (Postfix) with ESMTPS id 77EBCB548E3
	for <lists+kasan-dev@lfdr.de>; Fri, 12 Sep 2025 12:12:25 +0200 (CEST)
Received: by mail-io1-xd38.google.com with SMTP id ca18e2360f4ac-88c4a7fd9f7sf448897139f.2
        for <lists+kasan-dev@lfdr.de>; Fri, 12 Sep 2025 03:12:25 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757671944; cv=pass;
        d=google.com; s=arc-20240605;
        b=AWruIjpi0HndvcD5ZcTkhwk3Pf83rVf5rBleC0H9SPXSdsR073jKuQ7tnE/EGp52f7
         TxDcjk9yOQQgURjjBk48ggrBpt5wRbYQUxmXoRYGJe1ATSVf/I98Gu0ZIVQBE2ui5/D9
         dMoCe9k/ov7DhN5c2+ORD79jkxkdhZT7BkNVclrp2nLl3XfBPpbUy5QveGU3MkjaqaFV
         yu4kEt4J3TPFmWD1Aec05cn99f30ZH5rSsFnv4TOV9lCQhA2Ju5Hin4x3mjbf+buiLEB
         KJUlPyQgZ7sOTPCPrh3cV1yCwKNjL5dK8ggWibK3DO7qe9+uKK1X/0R3TIHQIUvFgGSy
         HyZQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=juiyYpIGt42h1/VLRK1p9PVeexlo9Fuc2XgFZNXatjc=;
        fh=X8IZb7H3tl+HSxxS9UWJx8ayDvX7PaLmbRRYwnJCCYM=;
        b=WldcQYY+yZ9hg12McKzBcWsByyHYXuAWnStYuShM0VAs6dizqfoSDhWi0knqRtuDTF
         tpKxkwKGGDy/DwYVTdmLmahJu7eTWCCHrSj1PYIcxQDZaii1LX5SGjiMP1Wf295Ma26+
         h+89TAg9g7s2Fv2N2uF3otbDB63lRmW8ONBR3+N3zMh1j9OtsDkOOJw6CcSePOiO6aFG
         P8TLOyU+MTaav1n9I33bORfsmoqMqCDH8wyOBpD9uV6Ugs8izWLiT3h6QQEvEkZbTC4w
         0rW1rFK5LZY/fdVadC2k5Bzg8wBSad9aQqz/z3VU8MRg3Hk1/0D4S1VjOv0A9la8yVcj
         qzlg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=W7SEHd0D;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::433 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757671944; x=1758276744; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=juiyYpIGt42h1/VLRK1p9PVeexlo9Fuc2XgFZNXatjc=;
        b=anO1Q3Q7AmBlN5X9oShNX3Rv3sZXmezPaCEZgf2bryNaAT84Bp979nJZwWQJcIHZD1
         elf1ZfvJ4R1/3HAVOSqyfCOvt8nsVz9RhVbq8rjn07cM1bGoH1OBwWBBydE1j7rCrvob
         zGC1nXsjmItkpdUIiIkSZcdbhp5Y0yB0tTOvYFEJbhT5vL2f4GlqzwBhmBtqVQUKs2Py
         L3dWX7F1zBuYspZW5qv5/IEw1KERnne62mZWgIb0N7CJbP6iuBcwWegG5EczBg5H3xl6
         EuxTUESZVr7lEzEig2Z8F4Ko96gLn99mo6QZ6J29oQKBFKRUANC7lzR5A5RIJ9vMIOEi
         kIdA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1757671944; x=1758276744; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=juiyYpIGt42h1/VLRK1p9PVeexlo9Fuc2XgFZNXatjc=;
        b=hBLjgAw6BVCzYFgyvI1ajJfz80515HFL1c99VD446Kcb21QxutRPWc5vjz+PQ8qmd0
         g3+GOdrMVbAxmx/zrKFWlR7N2pUqHKuXp8xwAcbFEwBsgrmFU35Yh0LTI+5D1reNuAw3
         wFY85gYk9P9v2CChQ94QqESdgvN86yaYejhoIK3UCM0Krowa/Two/v62qQ73p4wR8cGU
         mbc6MRnE3Oc9M3JyKC8NJRY3rYD95sV0J4epdmHHKUzZ3bhbVakIdvNqdZPfMKCZ8J/G
         J+8MTice4SbSzYSl4UTUSu6h54QN77iETiaRvgGpgLbxSocXLt7RL+ZPnAno5jaWB912
         tCFg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757671944; x=1758276744;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=juiyYpIGt42h1/VLRK1p9PVeexlo9Fuc2XgFZNXatjc=;
        b=j4VvynNMFVXogh4eTsCchyM1ZFgjLC2GR+qlCkZ7vOL2DOUlJQawh/6YSbVffauCQn
         p4emf+KtgmuxBXOrFharSyv1ZYQwGOBB0GeXr0wC5q9l/WIBSgpUUhTVsG7TTxlR5nHY
         MnbwN4IFNxJ6mjJrGoxa2KMKT4o2nSPVxGhKfvhHQTARnhtBIjE7wyED7uM/5IodSqs1
         TxrkLOUiQb+gFJoW+cPxNjZzyoskWk4Ot0Trv+KuTyHSpx02/0J/yyb/lUMlmqPc0jK1
         IWkN9SIKLfV1nPjyq7dfpuH0m6Ly5szeEZ42oOggqom8aDaM5LuPPIWwhzH0yri+9gp6
         S1vw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXV0dsQ9xXJOOHx8fC1hiJXz+PLp7O8eQuBERiA972KGLn1yOxiLhs7UOFxWOB5E0DnSDToYg==@lfdr.de
X-Gm-Message-State: AOJu0Yxjk20cLu7S7LlQsobsIC26EgeGw2IJo2cWaZRugztYwhQCJsy+
	hjd/I2iIQRlTNgu6EcFjk52e/P7MdgarvM5bkuIr9XoPKW8q9+GXS8P6
X-Google-Smtp-Source: AGHT+IF/HAUGn7EsIF1ZDO8iaaKWnnAh5tTE0ezC80gfIQPCn0ocHUgRLseHDaV00Kz7m6lxUf7o6w==
X-Received: by 2002:a05:6e02:160c:b0:40c:c955:b67d with SMTP id e9e14a558f8ab-420a4dec2f8mr38399445ab.28.1757671943861;
        Fri, 12 Sep 2025 03:12:23 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZeBYy4l1Ke5HvPg4sUtrxK4wDJOdrOYWUjB5AF4veQWgw==
Received: by 2002:a05:6e02:16ca:b0:413:a30b:180d with SMTP id
 e9e14a558f8ab-41cc38b1885ls17685965ab.0.-pod-prod-08-us; Fri, 12 Sep 2025
 03:12:22 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXPJX2PxptEWaFj+secvApfCxzVZ1lkN6VOaDYnvMAf+O1TSTbXL/LCmB7YdAjlrxgZ8O2D70I5v+8=@googlegroups.com
X-Received: by 2002:a05:6e02:1d99:b0:402:dfc1:7ac3 with SMTP id e9e14a558f8ab-4209e64b9eamr44156985ab.12.1757671942760;
        Fri, 12 Sep 2025 03:12:22 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1757671942; cv=none;
        d=google.com; s=arc-20240605;
        b=kqeWfhPV/SQt0aBN5+Kl8u63p4Gg0PsdIRPC9ZjBln3TBw11R9TAyjRvjH0ynLCTWk
         Ygxu64mtOx8UW8jH0ADXo7qSWxcwCoytWKSjjVxxgAbElqsseLWiwfnU8qThyAMhlQHX
         gqTukkNdiYPJRfNloMNBP4OC75skRMvQxOKVBv+r94TORpF20pu6HwRnqPPBXPwQdRWy
         cnKb8BJSWaWeeZQ+WAI+G0X73rVvcB/nRpw4tbnTb5dk49x4gg06IVpRYn2HJbJBEZ+3
         Mapp5aE/XvSxu+BFPWwnMmm91L7b5pTpEun8STWQlne2AUd/3p2QAEF0cWmw2v+rF49H
         SQqw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=JWZ0kuFk/JGga2KckHsx8bbCMGd9rBXEdZWbqFyn8fw=;
        fh=cCyUVDUeSY0xqlCajaKp7tyb7n2UE1YoOL3clz43oqE=;
        b=ikU6x50locZzbrV29XSJz8vtAx/qvOoNUPJFsATPq6HgrD4txx/DOcTTKHkmK8lXHq
         Bsw1v+kR1/3dszIN8AiP7GM8aLLUJKXOdtJwNry3E2kjxjyVpI+gU/ZUr4EhJtmXnDwl
         7667KMS09idsrTWlAAfJiu2p+wSdm+65cB98CTuMlcCqZX937IVOzzm7bw63MHF+1Z8n
         TriqR1kf9E8GgrW5n4S4a4nBnzsmfqj4757Q523297fp/ISAWWxYdJ1jR2zuWgD9zQul
         XUgIIajAybTRDeedkm7QlPePMlvtLp5gc0P5qoBW4Hg0EfRT28igWnUg8X5HG/5fnOJ3
         MopA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=W7SEHd0D;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::433 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pf1-x433.google.com (mail-pf1-x433.google.com. [2607:f8b0:4864:20::433])
        by gmr-mx.google.com with ESMTPS id e9e14a558f8ab-41dee17d767si1573365ab.1.2025.09.12.03.12.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 12 Sep 2025 03:12:22 -0700 (PDT)
Received-SPF: pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::433 as permitted sender) client-ip=2607:f8b0:4864:20::433;
Received: by mail-pf1-x433.google.com with SMTP id d2e1a72fcca58-7725fb32e1bso1780787b3a.1
        for <kasan-dev@googlegroups.com>; Fri, 12 Sep 2025 03:12:22 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVhg2zWMR7F8MwNjxQ4jWpjOF6LJi+Y9jN7KdkkypY1gt9ZpdqZi1EF51bPAT0SodP9mbvtxa4erVc=@googlegroups.com
X-Gm-Gg: ASbGnctKkQvJdxmsKbsAZ6qZ8/qj8oxmRMNwC3REMPdkvbwPFPb3YSjkO/oqdnrD1A9
	zD+seTrFj7P+FhmlKPZmN0T64+nnPj7Ondqdn5fV/e5iryyvqVXpbD0KQnYZ4JMo9b21cCeH8uf
	dzfQ2IzmaXUKyGNM8mRRcO0TeelPsTK3KeJfDd6SWU2oGnGqfBJQSFhdxa6UEWZav7bYkTOOf2I
	5MT0OYHH6VCRbwuKzvojxBaI6a90BJMt76Go37srMglWvt0rOk1J8+MBoTHDefPXMJ4ni+ywOyw
	kqvi7FN28pWQadc0fagpMiANVK+cEx2al+J2jqolmh0bR8VYgWohdzZYfIPIuSq2+68fza25Hho
	iHYG/+o4kENACaA2LqPtyTidjh5thbZ41Ck45X0+eWwlf+J2jjA==
X-Received: by 2002:a05:6a00:812:b0:772:5899:eae8 with SMTP id d2e1a72fcca58-77612189a24mr2770987b3a.27.1757671941982;
        Fri, 12 Sep 2025 03:12:21 -0700 (PDT)
Received: from localhost ([185.49.34.62])
        by smtp.gmail.com with ESMTPSA id d2e1a72fcca58-77607a46eedsm4969144b3a.30.2025.09.12.03.12.21
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 12 Sep 2025 03:12:21 -0700 (PDT)
From: Jinchao Wang <wangjinchao600@gmail.com>
To: Andrew Morton <akpm@linux-foundation.org>,
	Masami Hiramatsu <mhiramat@kernel.org>,
	Peter Zijlstra <peterz@infradead.org>,
	Mike Rapoport <rppt@kernel.org>,
	Alexander Potapenko <glider@google.com>,
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
Subject: [PATCH v4 05/21] mm/ksw: add ksw_config struct and parser
Date: Fri, 12 Sep 2025 18:11:15 +0800
Message-ID: <20250912101145.465708-6-wangjinchao600@gmail.com>
X-Mailer: git-send-email 2.43.0
In-Reply-To: <20250912101145.465708-1-wangjinchao600@gmail.com>
References: <20250912101145.465708-1-wangjinchao600@gmail.com>
MIME-Version: 1.0
X-Original-Sender: wangjinchao600@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=W7SEHd0D;       spf=pass
 (google.com: domain of wangjinchao600@gmail.com designates
 2607:f8b0:4864:20::433 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
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

Add struct ksw_config and ksw_parse_config() to parse user string.

Signed-off-by: Jinchao Wang <wangjinchao600@gmail.com>
---
 mm/kstackwatch/kernel.c      | 91 ++++++++++++++++++++++++++++++++++++
 mm/kstackwatch/kstackwatch.h | 33 +++++++++++++
 2 files changed, 124 insertions(+)

diff --git a/mm/kstackwatch/kernel.c b/mm/kstackwatch/kernel.c
index 40aa7e9ff513..1502795e02af 100644
--- a/mm/kstackwatch/kernel.c
+++ b/mm/kstackwatch/kernel.c
@@ -1,20 +1,111 @@
 // SPDX-License-Identifier: GPL-2.0
 #define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
 
+#include <linux/kstrtox.h>
 #include <linux/module.h>
+#include <linux/string.h>
+
+#include "kstackwatch.h"
 
 MODULE_AUTHOR("Jinchao Wang");
 MODULE_DESCRIPTION("Kernel Stack Watch");
 MODULE_LICENSE("GPL");
 
+static struct ksw_config *ksw_config;
+
+/*
+ * Format of the configuration string:
+ *    function+ip_offset[+depth] [local_var_offset:local_var_len]
+ *
+ * - function         : name of the target function
+ * - ip_offset        : instruction pointer offset within the function
+ * - depth            : recursion depth to watch
+ * - local_var_offset : offset from the stack pointer at function+ip_offset
+ * - local_var_len    : length of the local variable(1,2,4,8)
+ */
+static int __maybe_unused ksw_parse_config(char *buf, struct ksw_config *config)
+{
+	char *func_part, *local_var_part = NULL;
+	char *token;
+	u16 local_var_len;
+
+	memset(ksw_config, 0, sizeof(*ksw_config));
+
+	/* set the watch type to the default canary-based watching */
+	config->type = WATCH_CANARY;
+
+	func_part = strim(buf);
+	strscpy(config->config_str, func_part, MAX_CONFIG_STR_LEN);
+
+	local_var_part = strchr(func_part, ' ');
+	if (local_var_part) {
+		*local_var_part = '\0'; // terminate the function part
+		local_var_part = strim(local_var_part + 1);
+	}
+
+	/* parse the function part: function+ip_offset[+depth] */
+	token = strsep(&func_part, "+");
+	if (!token)
+		goto fail;
+
+	strscpy(config->function, token, MAX_FUNC_NAME_LEN - 1);
+
+	token = strsep(&func_part, "+");
+	if (!token || kstrtou16(token, 0, &config->ip_offset)) {
+		pr_err("failed to parse instruction offset\n");
+		goto fail;
+	}
+
+	token = strsep(&func_part, "+");
+	if (token && kstrtou16(token, 0, &config->depth)) {
+		pr_err("failed to parse depth\n");
+		goto fail;
+	}
+	if (!local_var_part || !(*local_var_part))
+		return 0;
+
+	/* parse the optional local var offset:len */
+	config->type = WATCH_LOCAL_VAR;
+	token = strsep(&local_var_part, ":");
+	if (!token || kstrtou16(token, 0, &config->local_var_offset)) {
+		pr_err("failed to parse local var offset\n");
+		goto fail;
+	}
+
+	if (!local_var_part || kstrtou16(local_var_part, 0, &local_var_len)) {
+		pr_err("failed to parse local var len\n");
+		goto fail;
+	}
+
+	if (local_var_len != 1 && local_var_len != 2 &&
+	    local_var_len != 4 && local_var_len != 8) {
+		pr_err("invalid local var len %u (must be 1,2,4,8)\n",
+		       local_var_len);
+		goto fail;
+	}
+	config->local_var_len = local_var_len;
+
+	return 0;
+fail:
+	pr_err("invalid input: %s\n", config->config_str);
+	config->config_str[0] = '\0';
+	return -EINVAL;
+}
+
 static int __init kstackwatch_init(void)
 {
+	ksw_config = kzalloc(sizeof(*ksw_config), GFP_KERNEL);
+	if (!ksw_config)
+		return -ENOMEM;
+
 	pr_info("module loaded\n");
 	return 0;
 }
 
 static void __exit kstackwatch_exit(void)
 {
+	kfree(ksw_config);
+
 	pr_info("module unloaded\n");
 }
 
diff --git a/mm/kstackwatch/kstackwatch.h b/mm/kstackwatch/kstackwatch.h
index 0273ef478a26..7c595c5c24d1 100644
--- a/mm/kstackwatch/kstackwatch.h
+++ b/mm/kstackwatch/kstackwatch.h
@@ -2,4 +2,37 @@
 #ifndef _KSTACKWATCH_H
 #define _KSTACKWATCH_H
 
+#include <linux/types.h>
+
+#define MAX_FUNC_NAME_LEN 64
+#define MAX_CONFIG_STR_LEN 128
+
+enum watch_type {
+	WATCH_CANARY = 0,
+	WATCH_LOCAL_VAR,
+};
+
+struct ksw_config {
+	/* function part */
+	char function[MAX_FUNC_NAME_LEN];
+	u16 ip_offset;
+	u16 depth;
+
+	/* local var, useless for canary watch */
+	/* offset from rsp at function+ip_offset */
+	u16 local_var_offset;
+
+	/*
+	 * local var size (1,2,4,8 bytes)
+	 * it will be the watching len
+	 */
+	u16 local_var_len;
+
+	/* easy for understand*/
+	enum watch_type type;
+
+	/* save to show */
+	char config_str[MAX_CONFIG_STR_LEN];
+};
+
 #endif /* _KSTACKWATCH_H */
-- 
2.43.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250912101145.465708-6-wangjinchao600%40gmail.com.
