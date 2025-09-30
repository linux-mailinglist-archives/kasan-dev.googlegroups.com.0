Return-Path: <kasan-dev+bncBD53XBUFWQDBBDMI5XDAMGQEU4S4XMQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3d.google.com (mail-io1-xd3d.google.com [IPv6:2607:f8b0:4864:20::d3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 01D69BAB09C
	for <lists+kasan-dev@lfdr.de>; Tue, 30 Sep 2025 04:44:31 +0200 (CEST)
Received: by mail-io1-xd3d.google.com with SMTP id ca18e2360f4ac-90dfda98b4bsf1098428839f.0
        for <lists+kasan-dev@lfdr.de>; Mon, 29 Sep 2025 19:44:30 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1759200269; cv=pass;
        d=google.com; s=arc-20240605;
        b=aBuuVFBpuziJUyYf0xjFK+Mgx6JTbwL/lEnBufiKi8C47K7Cdt4tpD3smaPj8vdNe4
         8g0ef4irsqCRdX1Fevt0YH8StrwS0E8KTyeNjbf2WFne9RbM3ErpxLvm8xilTIYbsXNy
         L5aRpOdk2Wctacsv1N6MzR8OcERLS69MXLEyEKRu7Zj9AzEunA6Y+cBcQyP75Fbroc49
         TguSpEoAMcXYNqT/7WEdCtFHBVgPNUk09Ih+pTukeFjhRfz6kLAGQ/d+0xK+zZp5btxm
         YxTSM/V0Ep6Z3WwprfCGLFOm1KiY3ji5IgGyRUbO5u1q9WVN9yNdQ7MQYuVdv4gWNNzO
         KopA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=elhbBXskcQTCud3K7aq3BZESNUBnqLMSxgw7ivbFa24=;
        fh=z/HBPUdWBdR3fDeSj3JpPCpeF07z1fCJdkp1WRrJhW8=;
        b=dY0FJrOZ0cuygLg50+r9TUmGylQEUm2brsgDRUzig2+HKRYjPtKKoSzS618pQZxdCj
         Iv2RgkWbJbD8fb3Fl4qfvc5PYDGYbbFjs8e2MXPR8RBEOyOXBZwzGlT9uwnOKDa2qemy
         l5RabA1eO3wwlTq19eZ67+jmrVuWrMSl8Rw3zHmEUkklZM47fNRrWsklYd0yjynEUsMS
         riA49/387tdh/hWTl731RAE7kazRB1XYe5aiRAQCrNi2KBIaA6xlG+odXJ0IW/pkKwoB
         zoA2Y8s+8mwvFsJvmk6I4A8yhBjwCXp10FHLxNU3esmEkaKzNWidmYWoiQ8MKWqzeBax
         sABw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=NIvyT57B;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::530 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1759200269; x=1759805069; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=elhbBXskcQTCud3K7aq3BZESNUBnqLMSxgw7ivbFa24=;
        b=RR5QP44+l3uxYfDd2YQJXIQR/4cisTBb1YWDiuEXgzv9fogL3ily9iNFzTJLrv1AfP
         Sh4i4+EvBhV/hOzBbEB5n0SJqVnicHVxBhgmSO0QilKZPWdjlGGq8pg9qT4TLDZWdi2Q
         S+S9B5SphkSkPSREfEAN6cZnGHKMaMdrx93D66m96RzqfRnvowll2hM+xww1tJw14YPn
         Zpye49EW9DFL3yAcqOdvv1PrCHC3TL0l6Xy71EKSndOEN3IHDARpN8ytSquVqu/CCtw7
         2zZZ5/U6IaqgNALqIwjbqLygdDgpTGhR5+RSfvrMdVyJewCtehzKuHgChLJVwYRM3axU
         MkVQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1759200269; x=1759805069; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=elhbBXskcQTCud3K7aq3BZESNUBnqLMSxgw7ivbFa24=;
        b=P1+2U0gBe1Kt/PvJRCVlUL80T8qCZ+U+/hgiCUNCZWi7HurJbxnnGwTL/rREtbn2ct
         H5TDj9L4EEcuDfLvnW23kmG5K8LDL9TEPhx706xoFMjtlexdzdKiPkhi+60hyJZ3M+97
         OSU/r0c9Jg9BKoy6XBM0UNV1o0AGb08a4aEniGlIRDo43TDucklVn+C3DamjLLdYiq1I
         AoGEI7z+XWVbdBJ2KVhTuyeBedmDDLFuXye+P7h7X5EwtgLIVhxL0i4VlPu8pGuAlm0t
         SmFGD9WRDX1/U0bQhcpbsAg4JwyLHi6YVVgJNN79DdA6MdZ6wQkZsFf3gggTiYVjC6LG
         DxyA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1759200269; x=1759805069;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=elhbBXskcQTCud3K7aq3BZESNUBnqLMSxgw7ivbFa24=;
        b=ec/JN5vRy+nfuh0Xmvo5AbbVnyXjVy5ukFJi1S6TtXUrh/eTcEPomNDqrvlhYppb2D
         MhQ4uyJVKi61oq0SdSlkl8r3THznzyHYwQ0/ExkhP9bYxcHZJ+PtmfRUORNRHr6SdjOn
         KoZYoZmdLRdD7J0mztgsiaHeNRMKDkAIxjgP/rZh8jaBszi+1vVVrsl/gLU4KBcA/eWx
         u7UwKs/TgxmdFvs4yT3vBEHs3U4C1yrgsPqkxULTAX6a7gzRFnEojJ6dBwqbV4Ggy8Gy
         RcqasBkO/cneL17EHbG6Aa1NuC0E7219lpy6CSjrXFUGVgCnBInUunbjAaNk7X+u7ZmM
         rKeg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCX/UKHqUIR7PleHaDbo1VWEj10QECpJnEAwISJSOUFmLLsBoA09EnwLKdia7UTPGNg3Tvgbug==@lfdr.de
X-Gm-Message-State: AOJu0YwSzGp/Tp6ynMjcvhGdszrojpeBml/in+gmn6wRLQ1EgeGaRYe0
	9V1Uhay7ov52to9UfrEsLFlqYWfRH5eIX2Tndn8dG+HFlYJCQBqiegUe
X-Google-Smtp-Source: AGHT+IGyuXnKG9OcWXZknW0W9CSgrfucLcYb+o2K9+8Kv0fZz7aiHN+f5qniRN8q6bjXCDJInvz1EA==
X-Received: by 2002:a92:c0c4:0:b0:424:85b0:e1cb with SMTP id e9e14a558f8ab-42595644bb7mr56729505ab.31.1759200269287;
        Mon, 29 Sep 2025 19:44:29 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="ARHlJd6+yZRKwJnjr0GdN0CsvWhFdxo7s04Yg09i1OCYpy4wxg=="
Received: by 2002:a92:c6cc:0:b0:426:c373:25d9 with SMTP id e9e14a558f8ab-426c3732a02ls38991065ab.2.-pod-prod-05-us;
 Mon, 29 Sep 2025 19:44:28 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWW9Q0b32AXn/QBT2mBjqVw4e7v0z8ekv7EtXhQ4yih7kqNoojT3o/3BXn4+mj2308YdJkGlt9lXN4=@googlegroups.com
X-Received: by 2002:a05:6602:6d04:b0:8f9:a50a:ff16 with SMTP id ca18e2360f4ac-929a79332c3mr871636839f.6.1759200268351;
        Mon, 29 Sep 2025 19:44:28 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1759200268; cv=none;
        d=google.com; s=arc-20240605;
        b=MB/xlVkKjLlskKJKB6fxfS2PP8BJGWbihbsAb7F6FhwFT/rdFuvzqFJjil78RPUqxY
         OPgXkxJYcdOtsxlJ4ZAq27vneiRDmxzM5F67W5vt47jEyFqZ2g+jqZ2rCnh+iEce+jO/
         q+/DCvFIgbYjfI37OVNT+8m1C59hyYJcB+zKWtXSZAnYFBMw38RNcBusQ0Fw74l6JCiK
         NNZ+YKMQo5mHNWF+lz+28tcwZv2/+s5LPJltPvj37WCgYDJEcmpM9vUY4pJh2tS3ex3o
         YR6U/1VnSR3QsOLcTSjVPJg/sgSCvwKiY2NUMckuJhxGP9TNJ7cuqiuo/mXPH0ZAODNl
         +31w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=bd/jIJYyk1G6SYf0mNQVLBMDX4oiGoErfqkyMXn4+LQ=;
        fh=w1d7N+myGnoTnqBggO9/xVzx9HjzrbPreXoCuqUv5BM=;
        b=G2p+FPqOKPqxl9ORd/gJRfOQVmjLr/htSdec6AolpHcsvDOkqqKBiPe7KreeMBvrI8
         xmhItuticC8DcUYX1t+PQtxoAPr95/YjOAX9wqcRW72Fw6UhTgaGv/2lQZZxyI79jOZd
         epl6klzCFBMSmUX/iBTlf8fueH1e0DJZFTEenMC5JiEqcyWflmtVC2NDwpYrbCVXSBuI
         e7G7HbkKvlaPC69BPhRrC8SB67I4259s77RlSDkCw6XjsmYzNm3+es91Dp7+c4hcY0d+
         0iwYR29PCXZSIFKD2YVs0hys8aWzSI18qxsRjnhruowvt20sRx7juTP/K6MHqPwmP7SN
         ShUA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=NIvyT57B;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::530 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pg1-x530.google.com (mail-pg1-x530.google.com. [2607:f8b0:4864:20::530])
        by gmr-mx.google.com with ESMTPS id ca18e2360f4ac-9040a31f0d2si60128939f.3.2025.09.29.19.44.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 29 Sep 2025 19:44:28 -0700 (PDT)
Received-SPF: pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::530 as permitted sender) client-ip=2607:f8b0:4864:20::530;
Received: by mail-pg1-x530.google.com with SMTP id 41be03b00d2f7-b57bf560703so4017927a12.2
        for <kasan-dev@googlegroups.com>; Mon, 29 Sep 2025 19:44:28 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUcRGgW5NpjDrEQ6xlPdfwyRvvGlTnWHonRO97b4WhHgezVfNzCXQjk3qMh4ZKRE1nT/xwQ/h64yGk=@googlegroups.com
X-Gm-Gg: ASbGnct/S/Qw7uEHnocLBCG+/XfvGDJUtYvQTksM7Zp8Zwj8nYEcjnpe0mzMwneKNxE
	dZTvwVM7aZ3z1ULlE87zxecWK0ME+0pSJMjeXrnGkkqQt/pcjQstsffPPguF3c8+DIMQv3rXmTF
	Eqm0NwYkBPSba4JequjMw3jBX+5kwaZbFIbZ0aUgf/J09pHBiF3d529izI/KlGEngZmAobpDArw
	Gtshry1aRUci7z+YuN/KqvYEJGs2Y2xZh+e8ZVeV/wQ7CF5zxJpPwXaPvFXDBjJ1ZK1Qc63ZV55
	BPgNc6kb8Zqlpsa0Urhth5qEEH0BNsWe2Z+8I5nEpH2c7T/i1w2l8hBWuGW+HuoEqWfsVr/6ueS
	DF8/L9J39kyUXsYqmrSxYOHpU3QgZgXtmJNrkGDTkXvcBWbw8huyfd6SXLnQfRS5dh+2jadk4Ki
	N9
X-Received: by 2002:a17:903:a8b:b0:27d:339c:4b0 with SMTP id d9443c01a7336-27ed4aa57f1mr154617195ad.35.1759200267317;
        Mon, 29 Sep 2025 19:44:27 -0700 (PDT)
Received: from localhost ([45.142.167.196])
        by smtp.gmail.com with ESMTPSA id d9443c01a7336-27ed66d43b8sm144778285ad.9.2025.09.29.19.44.26
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 29 Sep 2025 19:44:26 -0700 (PDT)
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
Subject: [PATCH v6 02/23] x86/hw_breakpoint: Add arch_reinstall_hw_breakpoint
Date: Tue, 30 Sep 2025 10:43:23 +0800
Message-ID: <20250930024402.1043776-3-wangjinchao600@gmail.com>
X-Mailer: git-send-email 2.43.0
In-Reply-To: <20250930024402.1043776-1-wangjinchao600@gmail.com>
References: <20250930024402.1043776-1-wangjinchao600@gmail.com>
MIME-Version: 1.0
X-Original-Sender: wangjinchao600@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=NIvyT57B;       spf=pass
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

The new arch_reinstall_hw_breakpoint() function can be used in an
atomic context, unlike the more expensive free and re-allocation path.
This allows callers to efficiently re-establish an existing breakpoint.

Signed-off-by: Jinchao Wang <wangjinchao600@gmail.com>
Reviewed-by: Masami Hiramatsu (Google) <mhiramat@kernel.org>
---
 arch/x86/include/asm/hw_breakpoint.h | 2 ++
 arch/x86/kernel/hw_breakpoint.c      | 9 +++++++++
 2 files changed, 11 insertions(+)

diff --git a/arch/x86/include/asm/hw_breakpoint.h b/arch/x86/include/asm/hw_breakpoint.h
index aa6adac6c3a2..c22cc4e87fc5 100644
--- a/arch/x86/include/asm/hw_breakpoint.h
+++ b/arch/x86/include/asm/hw_breakpoint.h
@@ -21,6 +21,7 @@ struct arch_hw_breakpoint {
 
 enum bp_slot_action {
 	BP_SLOT_ACTION_INSTALL,
+	BP_SLOT_ACTION_REINSTALL,
 	BP_SLOT_ACTION_UNINSTALL,
 };
 
@@ -65,6 +66,7 @@ extern int hw_breakpoint_exceptions_notify(struct notifier_block *unused,
 
 
 int arch_install_hw_breakpoint(struct perf_event *bp);
+int arch_reinstall_hw_breakpoint(struct perf_event *bp);
 void arch_uninstall_hw_breakpoint(struct perf_event *bp);
 void hw_breakpoint_pmu_read(struct perf_event *bp);
 void hw_breakpoint_pmu_unthrottle(struct perf_event *bp);
diff --git a/arch/x86/kernel/hw_breakpoint.c b/arch/x86/kernel/hw_breakpoint.c
index 3658ace4bd8d..29c9369264d4 100644
--- a/arch/x86/kernel/hw_breakpoint.c
+++ b/arch/x86/kernel/hw_breakpoint.c
@@ -99,6 +99,10 @@ static int manage_bp_slot(struct perf_event *bp, enum bp_slot_action action)
 		old_bp = NULL;
 		new_bp = bp;
 		break;
+	case BP_SLOT_ACTION_REINSTALL:
+		old_bp = bp;
+		new_bp = bp;
+		break;
 	case BP_SLOT_ACTION_UNINSTALL:
 		old_bp = bp;
 		new_bp = NULL;
@@ -187,6 +191,11 @@ int arch_install_hw_breakpoint(struct perf_event *bp)
 	return arch_manage_bp(bp, BP_SLOT_ACTION_INSTALL);
 }
 
+int arch_reinstall_hw_breakpoint(struct perf_event *bp)
+{
+	return arch_manage_bp(bp, BP_SLOT_ACTION_REINSTALL);
+}
+
 void arch_uninstall_hw_breakpoint(struct perf_event *bp)
 {
 	arch_manage_bp(bp, BP_SLOT_ACTION_UNINSTALL);
-- 
2.43.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250930024402.1043776-3-wangjinchao600%40gmail.com.
