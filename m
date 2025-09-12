Return-Path: <kasan-dev+bncBD53XBUFWQDBBA7ER7DAMGQEKXVRVMY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3a.google.com (mail-qv1-xf3a.google.com [IPv6:2607:f8b0:4864:20::f3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 5F4B0B548E1
	for <lists+kasan-dev@lfdr.de>; Fri, 12 Sep 2025 12:12:21 +0200 (CEST)
Received: by mail-qv1-xf3a.google.com with SMTP id 6a1803df08f44-721094e78e5sf16796036d6.1
        for <lists+kasan-dev@lfdr.de>; Fri, 12 Sep 2025 03:12:21 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757671940; cv=pass;
        d=google.com; s=arc-20240605;
        b=D/eV0TTcCpH6BKXYPOC1geuAtyXdmtWHge309018MT87u8Nxy3tgY15hTjLfa3LkrI
         kQUfO/7xTQQNqKv0/Mke4PmjTwaUmS3iFv/oI1YU9szemErT4gqEDv3eAMxKjjpJqb6n
         l0l+OaTHXMCd+ZwxGfbSGRquyglq0fHBEyrkMYBsk3gjbsC7jUBf2U4+qHhuQOZTleQb
         F5JRDnAruROKDvQ1005Qr2MVmxwCUvdn6QXpdW3Ln8vGWDsq8YWvL4spseueMhVjglqb
         k4lIiGKK9um/secnOaMwhS3kKPbX4DnUeeJkoxwuJkGZjU46lqP9n8ygcr9J2AEgDOMd
         ceJw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=nhbAZqmx9FFHeqEjI69qOr7OsBJBaHppH1ibCB4xmjM=;
        fh=7WrYbx2XG0UMe4i7gnKJMw74DdtAFwr/fzPETw38Upg=;
        b=TRAVz1m9RU/7UlSrK+o2X1ngQU2puMwZnORHcDpNR/OAxNcVEDbRljDBUZnLwRk4re
         9nvpQULyDy58N73wmK8ONakDjUEhkkSmOHhjjxgFHE993r+zt7PkC2ztEjPSZ7eZNLpJ
         zr7/5zANG5yCoys8tlC9l/FEJbPADUmTdIvatK3lIthzAftArPf3+VjEt/bmSkyWLwuH
         pNt1KWs0qBShjSbGSLryTkJqfe8+lAls6f6BfFalEAw8rhR5RyXR4TA0cmZGtjcZcQ/P
         YPmVnDEjTssbN0x+9qtUwkoh96nj8Z4ZV6c5eoLdSo4XfUpVRyaSONPSxSN5EuRnqjek
         ITnQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=GNioVesK;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::532 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757671940; x=1758276740; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=nhbAZqmx9FFHeqEjI69qOr7OsBJBaHppH1ibCB4xmjM=;
        b=F/775AtUvINO0lpTMeeeCpgXeMqJwg24ps7Nni93z2ofwzZR7XOXJfquQ+BtR4wjWR
         8rasrkq9MYqasGKt12VPotoTVxCET3YFMz5m2Ntmg19ssUYtxbva7bydiIfYsr2nercZ
         1159z5n3GhtvO4J8dyrLgYIT9gOUcDaB2RUufgYWEdHLDwa01wiguvVUOykYeegcaRVc
         yPUiiWPLtlaRrSsShvjexoeiz1IFl1kkkFitksbucCq0z5nxkp5aPjWQZWJN4p49/kt7
         Tl4ge655oxvGrR0y72Sj+LNK0T/CAFUo+FVcDb7QeNlLxhGtN86PUbAONvlmegq74K9X
         AXsw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1757671940; x=1758276740; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=nhbAZqmx9FFHeqEjI69qOr7OsBJBaHppH1ibCB4xmjM=;
        b=DiQ1gwi8sw3YdJntahl1VV9uyobPRa1azZmiD2W39YOvaodpSxRMDwSRDdAjahHQ+r
         28844+CwJsd1nIOkoh6xCNmni2/PotnfxGMWo1bleAZWRrwlxsh65M70Es29txL9DEer
         Ecb6W6lJ7xO5x6ITxwVIuZ3Wk1ggtOqyH4WCEcIKpJ0bGUbBKrZWVPWZMjkRWNQte7pw
         J6uzDns9f+u6b/Ecx/TITDrrE7kMoR7j3kBfZ6EJi6vxuhvUwLU606s7Zn3l1XvHLmn4
         bgYKrityOLw4OkwCbuDTVSU9Vt2w9H9yv0zX+hv6u/ZNyJNJslPGqaJs74rminOEXdEB
         A4TQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757671940; x=1758276740;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=nhbAZqmx9FFHeqEjI69qOr7OsBJBaHppH1ibCB4xmjM=;
        b=ERc9mzyFLU2rWzQD/a0egiznuYetVfUe6tky4T4EN2lCFkkzQc2puJ0f87Mi0UTcy0
         pZQhIzkIIu87HKPEJHOuwpCBRgNGWKQg190nXeSjbWEEcLkU8bw1VjAYtBwnHx8YGrw/
         lec8cVzfIfjjll2TAeNKnqoDkfkLfxZoC3KdjpHTJ9s+xb2/Q7kGhJbGxO1ugwMy0l3P
         L9hNpzNISf99p9mrxYwrLnxycFnqyAmCB1rXAvC9aWb0/REe9kFQVWVH8YPLOrRohcWQ
         V0sN2Cq9GJJURd+kJp3sbZAAsSpGPczrGSn7GQETGv+Rd8u5mvrHOAE8iInEDIsmxx4x
         nXaw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCW4A51xbDS1aao3JK6aJfQlT04mRDcxH3oFCJhVYvdZVzOSz22SaeuIu/1KmSo8+W5SzMvjNA==@lfdr.de
X-Gm-Message-State: AOJu0YxnWSocFOqp6RGlV67TPeIoMhZysHq7SasrwFGbfAaVqNlYyf5k
	+5b1VfogfGlqDlX5K6NE9/HSIe67NL9Ba7X5Rb0ZBR42Z3BW1Gzw1XNz
X-Google-Smtp-Source: AGHT+IHGtvh5InX4gKffd1+IgVT1I8vr5xVOIV7Z93GEt3U03ureRyaY9Qe5fM8f91gvp/LpdKd7Fw==
X-Received: by 2002:a05:6214:c4e:b0:764:7115:7543 with SMTP id 6a1803df08f44-767c5621b64mr30071366d6.60.1757671939909;
        Fri, 12 Sep 2025 03:12:19 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd52WvbSDwnHv+a1uOvWD6CylsOGfWuGFzfVY4lQC/VC2A==
Received: by 2002:a05:6214:d0a:b0:72b:800a:845d with SMTP id
 6a1803df08f44-762d6dce735ls21845106d6.0.-pod-prod-08-us; Fri, 12 Sep 2025
 03:12:19 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVpGRVcZqis/FwJMIhV6EIsQj6sTF4q1u/15p7CEfArZb3FR1RUv6zP8tPhxWtJXefnsMvp1fLlZzQ=@googlegroups.com
X-Received: by 2002:a05:6214:c87:b0:744:e250:116c with SMTP id 6a1803df08f44-767c271ddd9mr28009076d6.32.1757671938884;
        Fri, 12 Sep 2025 03:12:18 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1757671938; cv=none;
        d=google.com; s=arc-20240605;
        b=CwtUcWRB++5Ee3k/yAPui0g8y1u9tLgOlR7It3r67CloJc5OSWL9TJUwi/v+2GPZ2a
         rIHKirYZiSEx28ETf4LQx113kTzmpU7kW1l12A/N6xbYHV+Fdp5jQSx46EsMmrZAIdjz
         mlt8NJjcV7tDPgxrlf5cvp14Tu+Heeb5OdJHkPq1KmOlcPwmcQ4qOWTJ5VsdKVD6t4FJ
         aD+Pyoo6QyzogMuNuCtRfgx7CgQiFX1t68ik0fBLGvIXBETqTea3ltYMAO0C7k1FAJzr
         bBZF/pro9nwPa23+qXQy7FwNJySIAxiAXrAxswWiGrOEkKMZwm31uiKHpTx+PkW0Bj0z
         XmGQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=vPBHXhel7rMyKaWRDIHRGBdLv/zGRcLPaVcgqECt6eI=;
        fh=op71AmZJLqA1V+Q/nKxsbtgUy0oabnRhz1njrgnm1+c=;
        b=c4/P4kOWDWw/seJt0aiyuQIm8310ya0kgEBd2zaGUbPYBqjWNtGqUW0b/u1C+rnPwm
         zG7tLjBUI39DZKHESLzwdQH5mw/zxmda3avXwqWegG3Cwhwvuci6NdT2V5DSfUDz/GqU
         aDXMjrV3blf8I2MNVE8M1aRlHv08UWrB732Z/d9DwbY9gGOMD4EqzZ82fDw4sqY4h+Bt
         N+qkSDXcYb/U+WeMpXd3AQWg4dZMHAHc1b43iWE3hRqEWGP1MBpTKLSZvPyvBYMQoCxs
         8XDGssh6Fdn2QBvDriz4A1V6W9fAeSYksVKDQya/a0qElMBmNbDuLs5k1Toq7FrxrF6D
         OMfQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=GNioVesK;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::532 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pg1-x532.google.com (mail-pg1-x532.google.com. [2607:f8b0:4864:20::532])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-763bc5427e5si1251206d6.7.2025.09.12.03.12.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 12 Sep 2025 03:12:18 -0700 (PDT)
Received-SPF: pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::532 as permitted sender) client-ip=2607:f8b0:4864:20::532;
Received: by mail-pg1-x532.google.com with SMTP id 41be03b00d2f7-b54b301d621so225289a12.0
        for <kasan-dev@googlegroups.com>; Fri, 12 Sep 2025 03:12:18 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXSDeF/qR3BCcINwEbDhB7dttEmmkrJ9LGNU8zxeU2ypfhG0NjzIeSHCmT8xPiwvm2OFJyzoe+sgOg=@googlegroups.com
X-Gm-Gg: ASbGncs1pZfdjun4/IPNH6yJKAyKkIX7M1GV+nCQqoL80KLisPe3ui9BSJuxYa82P8z
	fEZMmDNl5AwSW/rnZI57O3CU24n7Eczif6hnVm75O9MEAXMag9bU9BgJjiOWxIwLd7Q+GaTsSlu
	wixnBM3nuGLRliESuM3HbLDuhEFvlJWwFRw5VR0gTmk35jrFX6uaYbfUTXjShXIci1DZeH98Hqp
	S2o8CHuQ7oNF6ah4d320cAypXmYyB/3o0Hvn3m+6DndHxUlF6g+LkJh9LSYvmTFJMho6ezB5+OO
	un8Ib1TmKD7MH+kzR6v5ixYGCzObOmZSAGR1ijnHFi0YfL+2jQWDg9EnZpxywd/K+u4/eISp56h
	VB2HzMUwb/dONwIT3qAc8M6vK/5boKML+OGN/f3k=
X-Received: by 2002:a17:902:f68b:b0:24e:7af7:111a with SMTP id d9443c01a7336-25d281077cdmr34352375ad.49.1757671937679;
        Fri, 12 Sep 2025 03:12:17 -0700 (PDT)
Received: from localhost ([185.49.34.62])
        by smtp.gmail.com with ESMTPSA id d9443c01a7336-25c3b0219f9sm44620085ad.123.2025.09.12.03.12.16
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 12 Sep 2025 03:12:17 -0700 (PDT)
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
Subject: [PATCH v4 04/21] mm/ksw: add build system support
Date: Fri, 12 Sep 2025 18:11:14 +0800
Message-ID: <20250912101145.465708-5-wangjinchao600@gmail.com>
X-Mailer: git-send-email 2.43.0
In-Reply-To: <20250912101145.465708-1-wangjinchao600@gmail.com>
References: <20250912101145.465708-1-wangjinchao600@gmail.com>
MIME-Version: 1.0
X-Original-Sender: wangjinchao600@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=GNioVesK;       spf=pass
 (google.com: domain of wangjinchao600@gmail.com designates
 2607:f8b0:4864:20::532 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
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

The implementation is located under mm/kstackwatch/.

Signed-off-by: Jinchao Wang <wangjinchao600@gmail.com>
---
 mm/Kconfig.debug             | 11 +++++++++++
 mm/Makefile                  |  1 +
 mm/kstackwatch/Makefile      |  2 ++
 mm/kstackwatch/kernel.c      | 22 ++++++++++++++++++++++
 mm/kstackwatch/kstackwatch.h |  5 +++++
 mm/kstackwatch/stack.c       |  1 +
 mm/kstackwatch/watch.c       |  1 +
 7 files changed, 43 insertions(+)
 create mode 100644 mm/kstackwatch/Makefile
 create mode 100644 mm/kstackwatch/kernel.c
 create mode 100644 mm/kstackwatch/kstackwatch.h
 create mode 100644 mm/kstackwatch/stack.c
 create mode 100644 mm/kstackwatch/watch.c

diff --git a/mm/Kconfig.debug b/mm/Kconfig.debug
index 32b65073d0cc..fdfc6e6d0dec 100644
--- a/mm/Kconfig.debug
+++ b/mm/Kconfig.debug
@@ -309,3 +309,14 @@ config PER_VMA_LOCK_STATS
 	  overhead in the page fault path.
 
 	  If in doubt, say N.
+
+config KSTACK_WATCH
+	tristate "Kernel Stack Watch"
+	depends on HAVE_HW_BREAKPOINT && KPROBES && FPROBE
+	select HAVE_REINSTALL_HW_BREAKPOINT
+	help
+	  A lightweight real-time debugging tool to detect stack corruption.
+	  It can watch either the canary or local variable and tracks
+	  the recursive depth of the monitored function.
+
+	  If unsure, say N.
diff --git a/mm/Makefile b/mm/Makefile
index ef54aa615d9d..665c9f2bf987 100644
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
index 000000000000..40aa7e9ff513
--- /dev/null
+++ b/mm/kstackwatch/kernel.c
@@ -0,0 +1,22 @@
+// SPDX-License-Identifier: GPL-2.0
+#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
+
+#include <linux/module.h>
+
+MODULE_AUTHOR("Jinchao Wang");
+MODULE_DESCRIPTION("Kernel Stack Watch");
+MODULE_LICENSE("GPL");
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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250912101145.465708-5-wangjinchao600%40gmail.com.
