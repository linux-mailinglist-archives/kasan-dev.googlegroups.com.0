Return-Path: <kasan-dev+bncBD53XBUFWQDBBVVWZ7DAMGQENSCGT5A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63f.google.com (mail-pl1-x63f.google.com [IPv6:2607:f8b0:4864:20::63f])
	by mail.lfdr.de (Postfix) with ESMTPS id C2394B99A85
	for <lists+kasan-dev@lfdr.de>; Wed, 24 Sep 2025 13:51:52 +0200 (CEST)
Received: by mail-pl1-x63f.google.com with SMTP id d9443c01a7336-269939bfccbsf85337525ad.1
        for <lists+kasan-dev@lfdr.de>; Wed, 24 Sep 2025 04:51:52 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758714711; cv=pass;
        d=google.com; s=arc-20240605;
        b=dgbvcl3UZ+igm0zu6meBrASByut9xgokGUgVMg5S1hsF3rxRjY2+ubtN8nTyH7Fgh7
         Fi6tPRtFDauSHebpuqy8Tx8H4RG6juxOKFFQT7OD2TgNr+tGuXIK6CaigmglBCKfGpo/
         8uohytPiL3x6vWt+PihvOUMUE5vnLPgHQnfgteTfEDZ7qK4OYBZ7718HEGFZcYUanZGv
         MQ+GA5SE9OQIAnTXH2zIBXNpXC5slj7uBxB+iPJAkrxcZ0XuZPbYWtZMqGb6P+zD/QAk
         O+71gGjEAHg+wH/wuSEIIGALpvD45lFlKwZS1mBsPR140kjaCzB7OL9RWmG7BO7T1vkT
         yr3A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=Ri/rKTYwmymv6f3twb22FZcNsMs1i3L4Lt57fj9kcdk=;
        fh=BGeokKND0xNc3+xfCC4dvksH+i5vP5tYfEtHC4y62gA=;
        b=B/6HQDkSC24MaGuyRXJmS067UYJQupISrwkkco5k2JgDEOt4FgtE/sypXAEjSiuT6F
         i7G+6YULatQZeQaGQGUxs9MgmxNnJgUsK3BfXqDs3HgS750DuJIQINlEmZ7C3hgstwgr
         iUkosaug3Hnq6Y7rlvVoOMtCVweMVHMM2X1Q3HZdpd/zrRYOgq+8wKTX7rumbT3fwSiE
         0yj4KtppDZNIlUbezDu4mgM+3PTIP5pxsJgXmoAYdPpXkD3W4tiHs9/Zs9jlrrW4rwFN
         KHDy3QwvjM+c0i/o4KE9Ey92Z2TsGMZWkIGRBSNXAONv/v1q9OnQKbV+HWtYbkWEJcS3
         G7WA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=DNd726q3;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::430 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758714711; x=1759319511; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Ri/rKTYwmymv6f3twb22FZcNsMs1i3L4Lt57fj9kcdk=;
        b=Ub7SVt7JiVTgyds/pfA/Nj0PKtbDCta1Fc56wzVCQDVof5mzZEENuvH2FzkpU4y7lP
         rXTlvPhyvKwm5VA0rlAJi6xcoGv1qcXDvuhPpxzlfAMjB+PeqTznLb1FkiVCDyHB27Lu
         V8RO5pv5IVBWUMpb7ZyypWJPo6QOn8+Ugc4Ke5cTvKQurwKcMzjJCpPDrbo3uH9egYTP
         +lmwUfTGVzrtzMs9esQaIa8BDRZIfC68cdBarRG6YEEdXbmc+cFfUnSGpo47nTdTIZV1
         AR0bbEK0pgN5RhCw1y4nkaFkPEQGikz9W85QfxCI+mu2UemGAP7fP+f7O1GcsmidQPZa
         Jyng==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1758714711; x=1759319511; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=Ri/rKTYwmymv6f3twb22FZcNsMs1i3L4Lt57fj9kcdk=;
        b=X/KQTkbTF1LR3y7AljEElmn8q+3z2HeFwsyG5t4zso3qEu2reJrHLjwYrExPOmkDSU
         0CRGj1kOCx9kyV9SuG8dsTQS7MYDIBg+6Jlc2q+CK2GmVFkM9tO+fcVlZVX8cSi6labx
         HXNTR+Kb3lX6xKP/zRGj7CFRyvTOUv7CJcLapojJ08Lx2noSKuWzlyBktffdJhoX5/Rv
         YOctg/7JAf65UMPIjek4e2Y4iLWOPrYG+CUdS6tOg94GUr7GSz1wusvi+Ywi0hocBDsl
         JSxOE8Jhv0Kq/WE7o7d75YAuhCgral1hB/ulXR9aqH3eecbcX/NXDxLoyg13hH+fhQuE
         Cv/w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758714711; x=1759319511;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=Ri/rKTYwmymv6f3twb22FZcNsMs1i3L4Lt57fj9kcdk=;
        b=mN8lxMwJgSPK5ndy5fFMf4U+Ny3FSwwzXVyOvgOapWcmc/mFcOvbRiR+vyfwvzjE94
         /U6NGPuiFtKRBWM4d4c8xxbGeTkniLiHIk+toy1q9o5AfOO8O32+IsGLezq6m+UTfCXa
         WfSHauVY9jFyrz+SniHCTm5EUS811IbFc7WmuCwqyJltAroLj/CBFaE2fCImJM8plcUW
         yfnWxN9LpUGRGmIJHk2fzConpJQPsE+N19Ysqer2whnVlLclozTGjH5iAQYruN+g+Rkh
         u5TXenAeZDq+9EMn+eaca8B840XldnjaXftBfIdvqIKfxy2pv5AUyGenqeIIt2fo1nS0
         Ki6g==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXfcnGFUOdEMhtGzCl5LLjhy3HGH7rSan9SQcxQ2D/OLS3kODoRiUTXOGeuk70WMoj041W8yw==@lfdr.de
X-Gm-Message-State: AOJu0YzKkfUQHpGj84wfGO2wPVvHwCfcVA5Jb9a0GbTQfnN1zNXQTvHa
	OD/Y3PmIS5VvSYzvlVewl7t1sr4B/r8blpmBl5RvzYcYcQFnM52mLVMR
X-Google-Smtp-Source: AGHT+IH9TJ2KCWnbekuM1ll3ep45YvAoR594QlIncLkZ756AilTuTzf0UeLtB/HrcaYS38BAPzdZxA==
X-Received: by 2002:a17:903:990:b0:267:d0fa:5f75 with SMTP id d9443c01a7336-27cc09e447cmr81804515ad.1.1758714711099;
        Wed, 24 Sep 2025 04:51:51 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd4TB54uHU6u3YovlHknwUyn0aGv1KbbAxmzsrZIg4boqw==
Received: by 2002:a17:90a:ec86:b0:32e:43ae:a453 with SMTP id
 98e67ed59e1d1-330650c9f78ls6869387a91.0.-pod-prod-06-us; Wed, 24 Sep 2025
 04:51:50 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXpmijk3LoUH77B/U30VyESpf9St4mj0Mc0HVHv9zaXdTUCso0gpBtXtfY86ITRPFtlLydC3mfVbxs=@googlegroups.com
X-Received: by 2002:a17:90b:2cc6:b0:32e:37a1:cf65 with SMTP id 98e67ed59e1d1-332a95e0538mr6264212a91.28.1758714709719;
        Wed, 24 Sep 2025 04:51:49 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1758714709; cv=none;
        d=google.com; s=arc-20240605;
        b=ejxLtJ75y3mhEhmB1T+RugHiZa/9PEq/gYLSXi0r/87WlamuuHV7uayrBT8B1YnIT/
         br/NfHSNXjwxFhr+QlRy3Qv/biXeFwFaVE3l3ZeeY57RcvIy1EQgChs/qqn04sypffsG
         uc5w7L1JW7CrenG1uYdZhXfj5rN8GBGFPKW+KlBCPpamd2d3Ulk9ddWB4vr0QpQh0lPp
         nOzAbsx3cbPMY7hZG/wv4UdmMi08EKAuWSpuIMh99ro5U2/eIXWCsmU4tOyGlsl3StzL
         d8HVoT3qpCn2qCmRgC5A9WTjIpiwSBY3Ofucczo2jwU4TlQNdQRVi9PmY2j6wjyqwi+a
         09UA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=R1KSy0afhoo56zSKFToL0Rdd0rZ5LRpSk38GpQKE8pg=;
        fh=UI1v/FMOjOdwOy6+H7kKCK4eyls7jXp8vLPkI5a8Voo=;
        b=V2MJYyyXj0ArcBWyEOt0Alkm8GlRCsu/+lFiIDc+m7gf1qIWcPNu4Fv/UCTC26PFZq
         Z5xIDPJYlPd35ktnn6XlIdswGx6fpPXSCxpYHvwJWA7PuMiVeWWZtR8LBLj4Fk6D30+z
         l6lJCjW7JFocIkxG1PWB8IwbRle7PQd5OGLUkgA4mOqZ1WXbkmJbcF8n8LU0WYF2YMuD
         QAggeBNKe04G9sICT7rOW7ntLdFglgveoaac4VT4NtAJYYqUnpZA4BvL8/OhkmQTduoh
         Av4kidxG+1ZER9QXyNKx8k9PHle1zj4qoc/L+tZifVrdFnpfBzmx+P8aA3g15/U1LpnV
         icPQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=DNd726q3;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::430 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pf1-x430.google.com (mail-pf1-x430.google.com. [2607:f8b0:4864:20::430])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-332a8c894d8si129644a91.1.2025.09.24.04.51.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 24 Sep 2025 04:51:49 -0700 (PDT)
Received-SPF: pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::430 as permitted sender) client-ip=2607:f8b0:4864:20::430;
Received: by mail-pf1-x430.google.com with SMTP id d2e1a72fcca58-77f67ba775aso1026423b3a.3
        for <kasan-dev@googlegroups.com>; Wed, 24 Sep 2025 04:51:49 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWVIXbfVup4UWEV4dtsYTBnYkKkWO1QkJj/H4fOn5zJXqx0Ylav5CW/KokVXmyOIoufGQjrPr6LfHs=@googlegroups.com
X-Gm-Gg: ASbGnctlkj4qMDlhAj9RI4cNs1hysElDf/yt96jFHGRJ1sCADw1Na12KiMsnClJ4jXv
	2+5kqowppnlsp1OQaEBghv3I4ISOqsIQmf9odcskRFZxoQNipG9F+1aVZhV7cD4m+Z7sijkMODm
	Hm2CCludEiTqxaSfDr/BvrW7oFwZlcbcYh6Ju++AaXfMtWF1kIhr2b3lIYh1AI62Gu2qnDBAf12
	gCBSATwDEhVtqcZtPN3QG0qTE8HWqTkzbRNAYEYpscg4us/TZQnFbTCrWYbirdO8KISJbuRJM5w
	2jGBRpVUWXDih+jzuqaY/BLmsIUT8WwFqaOJvGapzyW/11MjqXXHSpc26jMQKCewJ32Stoo4oS0
	i8dd62E/0lA/2fqWNAOk9ePn6CVbtyaI1kAQV
X-Received: by 2002:a05:6a21:3286:b0:2df:8271:f08d with SMTP id adf61e73a8af0-2df8271fb8dmr2764157637.2.1758714708983;
        Wed, 24 Sep 2025 04:51:48 -0700 (PDT)
Received: from localhost ([23.142.224.65])
        by smtp.gmail.com with ESMTPSA id d2e1a72fcca58-77f5f9a45dfsm3248137b3a.7.2025.09.24.04.51.48
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 24 Sep 2025 04:51:48 -0700 (PDT)
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
Subject: [PATCH v5 04/23] mm/ksw: add build system support
Date: Wed, 24 Sep 2025 19:50:47 +0800
Message-ID: <20250924115124.194940-5-wangjinchao600@gmail.com>
X-Mailer: git-send-email 2.43.0
In-Reply-To: <20250924115124.194940-1-wangjinchao600@gmail.com>
References: <20250924115124.194940-1-wangjinchao600@gmail.com>
MIME-Version: 1.0
X-Original-Sender: wangjinchao600@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=DNd726q3;       spf=pass
 (google.com: domain of wangjinchao600@gmail.com designates
 2607:f8b0:4864:20::430 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
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
index 32b65073d0cc..89be351c0be5 100644
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
+	  A lightweight real-time debugging tool to detect stack corrupting.
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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250924115124.194940-5-wangjinchao600%40gmail.com.
