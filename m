Return-Path: <kasan-dev+bncBD53XBUFWQDBBCFKT3DQMGQENDKMVCQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53a.google.com (mail-pg1-x53a.google.com [IPv6:2607:f8b0:4864:20::53a])
	by mail.lfdr.de (Postfix) with ESMTPS id A0033BC89DE
	for <lists+kasan-dev@lfdr.de>; Thu, 09 Oct 2025 12:57:14 +0200 (CEST)
Received: by mail-pg1-x53a.google.com with SMTP id 41be03b00d2f7-b522037281bsf848217a12.3
        for <lists+kasan-dev@lfdr.de>; Thu, 09 Oct 2025 03:57:14 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1760007433; cv=pass;
        d=google.com; s=arc-20240605;
        b=gSu044+eTLX9fDXlPbTSxbRT8mmqUrHS6ZxteMnA6QglXqe4ox7KMdmK/VvR2ebtaS
         BgnSCdfF8hvmAxr958KSUPu7+f5+9rG7gwltfuGbn34wYfJlzB0YePDxJSX4cVmt3DUz
         pS9gvxerzHg608Ds2imwyo7aDbRd3DTTUG0htq7yMopv4t8ddZw6ZVEezQ2KP4B3kEdc
         RC7Qh3IBnaVg8zDqTbTheIagckPdEX5ob5BnxNvKn4qd5bQnAHgTl0Ik3euEFk6+kYRE
         qV4wbxMswyg50NJJKLiHB/QxXaL+CNzvd7eFRvk+MWeO+MHyhtM/jEC3WWHhZ98X+omu
         5aFg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=nd2GIl33acPK4sD1xKZv9MhTUUZ9qSvQIsWWyKbroK4=;
        fh=7rXX4jeJlwEa8W37krT9Ez5RvaQQqlI5Nj2WOhrftrg=;
        b=dfY31qDjBPDbSoIfHBrtSJ9n0hjj/++ThIEhCwGdZLy5eEcOEaDyqJhrLtSD50yfMx
         k7ZtPRAJWNNZXBE9N+YisWYSppsoBgaokqnZHlv5JXM+4ynmS2hvxZSbtixvXrTWI7RE
         TDu4Hc1eqbEWq5jn9+F+fcj9pA8jV1/gP2lz0CfyQuzV7W/77Xj/S8+BcxVzY2qtMiKE
         SfI+ZdiLqg7Y812GUxuEYd86cv1U+jZHxWi6wyHQlD9HKMdoApIjHWDDGtzIKn/KKoOO
         QAipZ612AhMslf0Zy2SPsGsdw08e5rCTfBI3QTmwvaYKmdDiKEj44wjZZLpAWTpgpPxJ
         Ejmw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=dengyI63;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::431 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1760007433; x=1760612233; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=nd2GIl33acPK4sD1xKZv9MhTUUZ9qSvQIsWWyKbroK4=;
        b=NzuMRYKCQkdfM3wz7vUep64zq7UrB3l9sT7gAhSs0q0C9e/MHtQkcqI0AswSLHx6pi
         Dp3KLTmSClT+mGUZX/f37mKSehbfc8CtoabNg+6EjZSf/sttvg4JvCJ/tWTeRMxnxrWg
         bLVSSTc1xHDWI0HMBNw0fNEHS4r+7RSsUrW9/vNUskyJCuEIn37ayZ/4XaLjMP/M2NRT
         HvhGwPkBll2jP9MI+X2hER7avdCDV4xM1depEk+KBJFkTs+Gx9aWcYq6tdYR+sKhoGbg
         oyJqkwEvLWcWp3QN7UV/Jfe6Zsx9VWlxvZkaTTsqOvjkuh4kqNKV3eEL8PIz3VcscNvn
         nuqQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1760007433; x=1760612233; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=nd2GIl33acPK4sD1xKZv9MhTUUZ9qSvQIsWWyKbroK4=;
        b=kGW49WV3LPIa5pjiIffQps4gpoTUG/ar9a6QmPWAl3faIm1HqvEAeCJioQVhb4dF1s
         Qv6PPiAWxlWlFGlJ3k1cmieL+9XrcIjJSWAykKfUO2rwzpReo44XSt0jM8c+LBGpoAq+
         leGg5WSHCvmMQMuGKgGgCTgsQJYQPfXTov0aYuHOm9Tsi8u45pGdGPp7VKft0IMergj6
         JTBBYkFocXp/sdVyIA5qGBQABOHkJ/OSaGb+navu8h4u90wffw2QWoEPoFmFKzZUFb1j
         D9S/TBe+BvwzjAqkHTl5/Ucm3jUcoV7wYbX9diUEV39X7DyrujDKXEMlhxvX1U7adKvW
         vkWQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1760007433; x=1760612233;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=nd2GIl33acPK4sD1xKZv9MhTUUZ9qSvQIsWWyKbroK4=;
        b=Ew7sXoi/H4SwrkrV6Mo6PhuwT0UKYGsmhp5NS3oE6ikE/zdkgFO8f4TL7vjbUklmVO
         nwQrzGMMNvoNjLoDiXWaXAHtJyT0KWxbOJjMuuJnm1VH1iiOpw3+npY9QFff/aLWF1A1
         wGO/jJdj4yW/x3IJH1yoo0/FrJU1CaEnTdivSuNCwtTdEXbzEVRlNfKxPPv35RUkROWA
         be/w8BURJIs9QcSyp6WX2k6Kfn8795BWZWis/ar6ywQoZ6UhIqJlVyQZyqxhKmtIawhl
         i4VgjyBIBFgQaqYRP7t+uWmjc8RZ7BStEIMOvX6CXSXiRwfDZulvBMdQUkyuIyEFBaXn
         KSEg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCX6YU9/52TDKpsNjZjU+NxZRjETsvMXeBWRzw7wnLI0+ur4vFKqI4MKCEd96wp6xlO+dvJqQw==@lfdr.de
X-Gm-Message-State: AOJu0YxQC2HwW8orP0u9TxH3v6Nk5bxdLUIO2ReqectOHM9MZbVcWOtg
	GywRvpMk1i1Ve11WD7ROUzTbiAq1C24dtQAWx18b1WKand5IVV0ZV4EM
X-Google-Smtp-Source: AGHT+IHt/fjokCci6H0p0TDSGuJwO5FDJ6ea4uQUgJH+oDA3BlP2oVSsKdy7wLVAKprSK7r5GjN72Q==
X-Received: by 2002:a17:90b:38d2:b0:335:2eee:19dc with SMTP id 98e67ed59e1d1-33b5138401amr8830425a91.28.1760007432893;
        Thu, 09 Oct 2025 03:57:12 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="ARHlJd5K+U8MkLvYBgJDGTq2l/SXxmhzZ8oNFKVsIWqjjBd3sA=="
Received: by 2002:a17:90a:9a8a:b0:33b:529a:13ed with SMTP id
 98e67ed59e1d1-33b5982beb4ls719729a91.0.-pod-prod-05-us; Thu, 09 Oct 2025
 03:57:11 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVDPD6qLvQymYnr8P96m+jYraSkD5NTdcNbghf7HDo8Wa0jZFWzMLqEDBrSnIcJxWDJ+B5PtEmCQro=@googlegroups.com
X-Received: by 2002:a17:90b:33ce:b0:336:bfcf:c50d with SMTP id 98e67ed59e1d1-33b511150e9mr9472048a91.14.1760007431439;
        Thu, 09 Oct 2025 03:57:11 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1760007431; cv=none;
        d=google.com; s=arc-20240605;
        b=EOeeB9p3PytBmuIqhZcZQSr+HWJhNkDfnIqxJy9kml/2MBVUr+J/RvxGU7KByQUoOG
         AMqSIKezccFbqM+/ZAeVfOtUhax66+bmm2pLNla2Rx1EedrF/9kOv1uIsVXE/FiLzfjk
         iBZr0lXK0rK2QtW35xsfJEgPi4ZFjL2+WsMg6OC4hMRK70s54hY+4LKsHWG6dobvhbvp
         q7MsUL3N0bB0Df3R6TDCwT7lgnialHPAvrDUASAq6DQqwCwwIkMehUBLVAOSBPwvfn/C
         MKWXIUN6VpNvDB6LpigEKUPt85sfZOEgWEtDIgNs3y2qOm8XQkT9Gd0l4scDtlkSxhkH
         6Y6A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=kk8QwiK6ueKhbPm+iybiDp/pMjWX1cNh1XEGnvIxiQI=;
        fh=6qqr+D1ls+d0jqmTdJWf2nL2N5ko8KRDMwoHtWM+vY8=;
        b=Gm7b/72wK0yfRI2mhWMIEewxsowdwn+pehT/+BSf96gqtMsUPPTQz05VhVo5WfEE7a
         KbFYlKY9ADDR7Xrjx17+d5fzfix3JyRE5Z7t3WqBY0/EHvEOPApX6P/01GGPWfjBprw5
         HebCkgGYWMEMnMS0hU88xUuo72R2SOsI0iQqUwEuYnxB0ZuV/MkCanjXZmJZn1IFPWe3
         bGpLFJINE5m/wQC72tqkSOB5sXuDaGnY1v8ar13KKY875Yk5jC+USkkq4pZdhJk8cy2p
         9GKVd92n8+6gG0wCHMD6JeJSARk6M03oButl7S/1Kh8CDWwxAHdXX2UVxXZmqyBeYW/g
         3VjA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=dengyI63;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::431 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pf1-x431.google.com (mail-pf1-x431.google.com. [2607:f8b0:4864:20::431])
        by gmr-mx.google.com with ESMTPS id 41be03b00d2f7-b639612323fsi99414a12.2.2025.10.09.03.57.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 09 Oct 2025 03:57:11 -0700 (PDT)
Received-SPF: pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::431 as permitted sender) client-ip=2607:f8b0:4864:20::431;
Received: by mail-pf1-x431.google.com with SMTP id d2e1a72fcca58-77f605f22easo755872b3a.2
        for <kasan-dev@googlegroups.com>; Thu, 09 Oct 2025 03:57:11 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXTxibAZ1F8j5L74d2G2hTzYm3zUPMFw953v/J0SqRQwKr+1wh4DAx+hG9J0Klmx03yQuoEh/s4uKM=@googlegroups.com
X-Gm-Gg: ASbGncsludR2fPpqGE8WdOZhgEYJxYSpSOtXuz1LlQN3QSBXLi8yPukzXPHUtxemKGR
	rhpJqSfCHNQrn25akDL4kP5v3uJokNhrSbANMD7m5GROUyDiocGTOm+cFG7cFR1dXUSCgC38uyV
	D5juRL89ow9aOforomQxTUNjnLmxzvP6MtLJiukUvhbwxl/Bgn/b6SilHtwfjcyZzmkSKe/SbwY
	aSsyA8sSetJqZmn244WXdiJJLsXzeMRS6gHwSpGb5CP1qQPpMhPBUMLIZWT9nKTVSkrodIZEXQL
	OrbQwLs0OvjcVTKdwsCENDfxWfJ6/nbOXt4Cfg0so5QAZLAWYEe2b/qBKtLV9RS8LhCqeialPPx
	CpvLe534v0ffjZ35CzA7B2JRSwjuMHCDPH3exCJlvLiHBWIGqrcohpMJ5U6HF
X-Received: by 2002:a05:6a20:2584:b0:2e5:655c:7f8f with SMTP id adf61e73a8af0-32da83e6319mr10105263637.46.1760007430823;
        Thu, 09 Oct 2025 03:57:10 -0700 (PDT)
Received: from localhost ([45.142.165.62])
        by smtp.gmail.com with ESMTPSA id 41be03b00d2f7-b6326d3af86sm6576895a12.14.2025.10.09.03.57.09
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 09 Oct 2025 03:57:10 -0700 (PDT)
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
Subject: [PATCH v7 01/23] x86/hw_breakpoint: Unify breakpoint install/uninstall
Date: Thu,  9 Oct 2025 18:55:37 +0800
Message-ID: <20251009105650.168917-2-wangjinchao600@gmail.com>
X-Mailer: git-send-email 2.43.0
In-Reply-To: <20251009105650.168917-1-wangjinchao600@gmail.com>
References: <20251009105650.168917-1-wangjinchao600@gmail.com>
MIME-Version: 1.0
X-Original-Sender: wangjinchao600@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=dengyI63;       spf=pass
 (google.com: domain of wangjinchao600@gmail.com designates
 2607:f8b0:4864:20::431 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
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

Consolidate breakpoint management to reduce code duplication.
The diffstat was misleading, so the stripped code size is compared instead.
After refactoring, it is reduced from 11976 bytes to 11448 bytes on my
x86_64 system built with clang.

This also makes it easier to introduce arch_reinstall_hw_breakpoint().

In addition, including linux/types.h to fix a missing build dependency.

Signed-off-by: Jinchao Wang <wangjinchao600@gmail.com>
Reviewed-by: Masami Hiramatsu (Google) <mhiramat@kernel.org>
---
 arch/x86/include/asm/hw_breakpoint.h |   6 ++
 arch/x86/kernel/hw_breakpoint.c      | 141 +++++++++++++++------------
 2 files changed, 84 insertions(+), 63 deletions(-)

diff --git a/arch/x86/include/asm/hw_breakpoint.h b/arch/x86/include/asm/hw_breakpoint.h
index 0bc931cd0698..aa6adac6c3a2 100644
--- a/arch/x86/include/asm/hw_breakpoint.h
+++ b/arch/x86/include/asm/hw_breakpoint.h
@@ -5,6 +5,7 @@
 #include <uapi/asm/hw_breakpoint.h>
 
 #define	__ARCH_HW_BREAKPOINT_H
+#include <linux/types.h>
 
 /*
  * The name should probably be something dealt in
@@ -18,6 +19,11 @@ struct arch_hw_breakpoint {
 	u8		type;
 };
 
+enum bp_slot_action {
+	BP_SLOT_ACTION_INSTALL,
+	BP_SLOT_ACTION_UNINSTALL,
+};
+
 #include <linux/kdebug.h>
 #include <linux/percpu.h>
 #include <linux/list.h>
diff --git a/arch/x86/kernel/hw_breakpoint.c b/arch/x86/kernel/hw_breakpoint.c
index b01644c949b2..3658ace4bd8d 100644
--- a/arch/x86/kernel/hw_breakpoint.c
+++ b/arch/x86/kernel/hw_breakpoint.c
@@ -48,7 +48,6 @@ static DEFINE_PER_CPU(unsigned long, cpu_debugreg[HBP_NUM]);
  */
 static DEFINE_PER_CPU(struct perf_event *, bp_per_reg[HBP_NUM]);
 
-
 static inline unsigned long
 __encode_dr7(int drnum, unsigned int len, unsigned int type)
 {
@@ -85,96 +84,112 @@ int decode_dr7(unsigned long dr7, int bpnum, unsigned *len, unsigned *type)
 }
 
 /*
- * Install a perf counter breakpoint.
- *
- * We seek a free debug address register and use it for this
- * breakpoint. Eventually we enable it in the debug control register.
- *
- * Atomic: we hold the counter->ctx->lock and we only handle variables
- * and registers local to this cpu.
+ * We seek a slot and change it or keep it based on the action.
+ * Returns slot number on success, negative error on failure.
+ * Must be called with IRQs disabled.
  */
-int arch_install_hw_breakpoint(struct perf_event *bp)
+static int manage_bp_slot(struct perf_event *bp, enum bp_slot_action action)
 {
-	struct arch_hw_breakpoint *info = counter_arch_bp(bp);
-	unsigned long *dr7;
-	int i;
-
-	lockdep_assert_irqs_disabled();
+	struct perf_event *old_bp;
+	struct perf_event *new_bp;
+	int slot;
+
+	switch (action) {
+	case BP_SLOT_ACTION_INSTALL:
+		old_bp = NULL;
+		new_bp = bp;
+		break;
+	case BP_SLOT_ACTION_UNINSTALL:
+		old_bp = bp;
+		new_bp = NULL;
+		break;
+	default:
+		return -EINVAL;
+	}
 
-	for (i = 0; i < HBP_NUM; i++) {
-		struct perf_event **slot = this_cpu_ptr(&bp_per_reg[i]);
+	for (slot = 0; slot < HBP_NUM; slot++) {
+		struct perf_event **curr = this_cpu_ptr(&bp_per_reg[slot]);
 
-		if (!*slot) {
-			*slot = bp;
-			break;
+		if (*curr == old_bp) {
+			*curr = new_bp;
+			return slot;
 		}
 	}
 
-	if (WARN_ONCE(i == HBP_NUM, "Can't find any breakpoint slot"))
-		return -EBUSY;
+	if (old_bp) {
+		WARN_ONCE(1, "Can't find matching breakpoint slot");
+		return -EINVAL;
+	}
+
+	WARN_ONCE(1, "No free breakpoint slots");
+	return -EBUSY;
+}
+
+static void setup_hwbp(struct arch_hw_breakpoint *info, int slot, bool enable)
+{
+	unsigned long dr7;
 
-	set_debugreg(info->address, i);
-	__this_cpu_write(cpu_debugreg[i], info->address);
+	set_debugreg(info->address, slot);
+	__this_cpu_write(cpu_debugreg[slot], info->address);
 
-	dr7 = this_cpu_ptr(&cpu_dr7);
-	*dr7 |= encode_dr7(i, info->len, info->type);
+	dr7 = this_cpu_read(cpu_dr7);
+	if (enable)
+		dr7 |= encode_dr7(slot, info->len, info->type);
+	else
+		dr7 &= ~__encode_dr7(slot, info->len, info->type);
 
 	/*
-	 * Ensure we first write cpu_dr7 before we set the DR7 register.
-	 * This ensures an NMI never see cpu_dr7 0 when DR7 is not.
+	 * Enabling:
+	 *   Ensure we first write cpu_dr7 before we set the DR7 register.
+	 *   This ensures an NMI never see cpu_dr7 0 when DR7 is not.
 	 */
+	if (enable)
+		this_cpu_write(cpu_dr7, dr7);
+
 	barrier();
 
-	set_debugreg(*dr7, 7);
+	set_debugreg(dr7, 7);
+
 	if (info->mask)
-		amd_set_dr_addr_mask(info->mask, i);
+		amd_set_dr_addr_mask(enable ? info->mask : 0, slot);
 
-	return 0;
+	/*
+	 * Disabling:
+	 *   Ensure the write to cpu_dr7 is after we've set the DR7 register.
+	 *   This ensures an NMI never see cpu_dr7 0 when DR7 is not.
+	 */
+	if (!enable)
+		this_cpu_write(cpu_dr7, dr7);
 }
 
 /*
- * Uninstall the breakpoint contained in the given counter.
- *
- * First we search the debug address register it uses and then we disable
- * it.
- *
- * Atomic: we hold the counter->ctx->lock and we only handle variables
- * and registers local to this cpu.
+ * find suitable breakpoint slot and set it up based on the action
  */
-void arch_uninstall_hw_breakpoint(struct perf_event *bp)
+static int arch_manage_bp(struct perf_event *bp, enum bp_slot_action action)
 {
-	struct arch_hw_breakpoint *info = counter_arch_bp(bp);
-	unsigned long dr7;
-	int i;
+	struct arch_hw_breakpoint *info;
+	int slot;
 
 	lockdep_assert_irqs_disabled();
 
-	for (i = 0; i < HBP_NUM; i++) {
-		struct perf_event **slot = this_cpu_ptr(&bp_per_reg[i]);
-
-		if (*slot == bp) {
-			*slot = NULL;
-			break;
-		}
-	}
-
-	if (WARN_ONCE(i == HBP_NUM, "Can't find any breakpoint slot"))
-		return;
+	slot = manage_bp_slot(bp, action);
+	if (slot < 0)
+		return slot;
 
-	dr7 = this_cpu_read(cpu_dr7);
-	dr7 &= ~__encode_dr7(i, info->len, info->type);
+	info = counter_arch_bp(bp);
+	setup_hwbp(info, slot, action != BP_SLOT_ACTION_UNINSTALL);
 
-	set_debugreg(dr7, 7);
-	if (info->mask)
-		amd_set_dr_addr_mask(0, i);
+	return 0;
+}
 
-	/*
-	 * Ensure the write to cpu_dr7 is after we've set the DR7 register.
-	 * This ensures an NMI never see cpu_dr7 0 when DR7 is not.
-	 */
-	barrier();
+int arch_install_hw_breakpoint(struct perf_event *bp)
+{
+	return arch_manage_bp(bp, BP_SLOT_ACTION_INSTALL);
+}
 
-	this_cpu_write(cpu_dr7, dr7);
+void arch_uninstall_hw_breakpoint(struct perf_event *bp)
+{
+	arch_manage_bp(bp, BP_SLOT_ACTION_UNINSTALL);
 }
 
 static int arch_bp_generic_len(int x86_len)
-- 
2.43.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251009105650.168917-2-wangjinchao600%40gmail.com.
