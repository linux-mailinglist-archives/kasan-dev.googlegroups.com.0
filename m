Return-Path: <kasan-dev+bncBD53XBUFWQDBBVFJZDEAMGQEJY7OGCY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x537.google.com (mail-pg1-x537.google.com [IPv6:2607:f8b0:4864:20::537])
	by mail.lfdr.de (Postfix) with ESMTPS id 2541FC47FDD
	for <lists+kasan-dev@lfdr.de>; Mon, 10 Nov 2025 17:37:43 +0100 (CET)
Received: by mail-pg1-x537.google.com with SMTP id 41be03b00d2f7-b6ce1b57b9csf2954890a12.1
        for <lists+kasan-dev@lfdr.de>; Mon, 10 Nov 2025 08:37:43 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1762792661; cv=pass;
        d=google.com; s=arc-20240605;
        b=RMB2VDBmTET1X/GtrR0SrfdB0UmAovV4OPUGDPx0fHeOFSDr3QpFxmDuL+SUmceTjO
         UcLw8oLwG6ErJIt9GbcmLKk7cztMNj+kKtiyQxg8UauwJN8SgvBbFwQrQvb1BJUvj9bM
         OJ7hSZxaAVkdxjJ76vG4mhP8XRYJWgzp4hRAEuWEfPsfwgXBQDemS+yFbyviIz2i8ZWY
         wdtRA4NoGAnJIpslR4MWG67O2Tb0zSpC/9sqImG5B3VWvfisPm3UBCgmwGeF+VSNCb2W
         OASHqanxSr+jUt/1HUNDqiT5hWeuEHiSe/tTz+HPq0abeE/VsIYUSCexyOJDt3icXoLN
         zCgA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:to:from:sender:dkim-signature
         :dkim-signature;
        bh=zvZF/s3HYZDghnEjqpgByxo6DGze19Wu+/hUVfgZHYQ=;
        fh=uWgar/G9o8UcD5CmdSLy/ARiXbveW1ZmTMlOcty0YzM=;
        b=kmO6rDeB1B2g/4tYvQtNrBl2zxtHBxOrqBrX9ow1fVoCV0Rxx+4iIgl4S1MWrJyyBy
         2Lxzj5gUDmjLXUZkOSSBig3OuCtYEX1D3qQlO1WMtXQXE3wtII/FrTKy2+L8injzbZg2
         AmlgzqpDlLj2SqXjEES7aKCyVhdwRoMaIugx58xhF5gfMbftAB1OZ17fNNA3558WdhVr
         61YCLRq1R9oKBGiaOP4W2GHmxPp61aASAFL1OHBOcikhPC8wwuzTGc0ZlUZWVlPnwCGV
         +9G1KYWn7DX0q3LBRBXZrIxz3O6W+9HJ/OHmIk4zU4XvFe87YI7c4spEa1K2mTUP7emw
         xRrA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=NU3VK3oJ;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::429 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1762792661; x=1763397461; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=zvZF/s3HYZDghnEjqpgByxo6DGze19Wu+/hUVfgZHYQ=;
        b=JPDvAq/tZzQqerXSAMH/29W9GbGg0K1zZ52bfDMfDDstrOZDnbVXDBtyrhMQf80cpv
         ENqG2Y3J7AHBXxQsu4p23UVdS2X0xYjhrhe1fqCyK9cEzadSTzUsQZFdOg+NlnnI6lzU
         gK4cUkDjvJxWEPlWoedPhRD33eM+qe4+SsMM7Mgs13ZZz/P5FOkpthLp3IKowlbCPW1S
         Stgew7y/iPsEIScOLp+MuX7OnFkM3nH3/X8O4Myj8kWH/j/mvt+/VMHWYLU3gBfUvfzh
         QIerkUvXj6QDi1sH58qU3sGWjhQhV7gYSA4yteFQCnnHckGRMTTRAMSAE2p3x95i4y4G
         ECqw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1762792661; x=1763397461; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=zvZF/s3HYZDghnEjqpgByxo6DGze19Wu+/hUVfgZHYQ=;
        b=hrRDOBO2WiX+5P/6cfQ2cJTZKEnfqVuJ3nXWPqwNSX1fYSYkM/zAuw/2ssMZKLQBVP
         rOeygmRssZ4LFWZ6x1H01pDiXJvYGeaRIoJFPdWOnVh3qVVQFXYI/FK7Ni5cYZrlW1Hu
         cmyG22NLSrglHEA94gnQh9KlI4HGA/I4qN0pYNBwmp5NKpH65xJMFnHlLHKIPxWwL8pr
         Urr0zW5aQO+XznituxuGXl+R4sA+x86K05AapG5iT4p4c3lPKQxduwKaIkVRwy1HL2Ls
         D1Rd6I8ikxFAZ2VTkqJtiQmkgCTHixPuqNeXOJB0lWFA0UAfYODNa8g8OJROc9hFCjzv
         O7GQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1762792661; x=1763397461;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:to:from:x-gm-gg
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=zvZF/s3HYZDghnEjqpgByxo6DGze19Wu+/hUVfgZHYQ=;
        b=Jj+fezBlHjs0AvgzDZr+6rJ24rVw2003O4u/WLVfY89co9hf3oxpRTfIgaf3a2YdCa
         yLbxfNvk5iEOl3lIaUFW5KeIC79s8tWfmfFS69tyK5/mRtWOCBg+QXeALPul+O+d3kky
         dqjMG4tTdR+n6PUkifrkL0tJhFmiazIM0xlc5QQrt7eCqobc3vPUmMbCJNpg5WIt5cxA
         VPBxLFE2bHQmAoxsRh7iBvdeguXI56c/B4WRie85E/2QOXg7GrNdu67bwr9NOtnArq8D
         DIftMlPZ5LDdr4JIDiFIuRL2gTejTnE/8iK7OpvGcW0EgfjTVC6cZc//W+m3EvBn7C5/
         +khg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUkDmeHwOBjHJgzUj93MsB0QvdDIZhrYSaIC6QKyNj2c7IY2Ol4cwFcm4FY+jk1baqRhO5VyA==@lfdr.de
X-Gm-Message-State: AOJu0YypJ3MXHh2+rA01YJfzLSYC+lnrGp81mueACHCXRHrUT6ck+nRE
	yj1uBBfaE76pOZP9ntIxQG7MFl0/32FWOqFf0rsbPO7AZctZ14CQcMs2
X-Google-Smtp-Source: AGHT+IEzBMJrDxNzL1jRL1g6YgVCX4DLXVakpW+1VbM3Sh8BGiepEC3kVWNFY9kWlU26XU7pJMFz9g==
X-Received: by 2002:a17:90a:da8b:b0:32e:1b1c:f8b8 with SMTP id 98e67ed59e1d1-3436cba9413mr11566356a91.26.1762792661039;
        Mon, 10 Nov 2025 08:37:41 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+aTxAca3K3G8IrYHtoBGomTUE4wxe/AWz2sSLVrpeBKzg=="
Received: by 2002:a17:90a:1049:b0:340:f807:a7b2 with SMTP id
 98e67ed59e1d1-341cd2b6468ls3923688a91.2.-pod-prod-04-us; Mon, 10 Nov 2025
 08:37:39 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUIiBDvmj/rAwrosA5vMcEm3u9IhaXlHH9IKoMzEWjSHXygZ9f49Xpc67uhbMmgMdtN/mQEtfsLUiA=@googlegroups.com
X-Received: by 2002:a17:903:19cf:b0:297:db6a:a82d with SMTP id d9443c01a7336-297e5668a96mr119754535ad.26.1762792659686;
        Mon, 10 Nov 2025 08:37:39 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1762792659; cv=none;
        d=google.com; s=arc-20240605;
        b=dbwYeutxei28UT7Ec3tvzr/JUyg+vFmtKB9zf02pAEUVar+t87vJqtavz1cOHuUDQu
         rw6aKRr5zjj5hBXXfRUEe7S9ryzst7X7ViU3BANMPHuGDJ/fbc4fOl0mRdRC/Y7u/nWB
         nwTnUtBn3bEPWE1Kzs0LGjw9cmUQs6jNVExt8q3oMeNPl5RUr23eK0GWg6kMiELU0RVO
         emqElPlb9Bjic0fAarp6p2OILehZvPsLp4uoTDDkbx0qduB6Q2yuiHokEnGBeL3pYlfS
         d7i0sJNG9zDTXWI8nSB1fgOoBpOcL9SRL5jw3IAMa/330htA7Jc/nMnNZbKQap/yiREQ
         y79w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:to:from:dkim-signature;
        bh=qY+qINpaOz0cBrftmlOPWeh/tDbDV+8hjCudsDUPv3w=;
        fh=vAeVVrXET6hXT5rS4q1QAgthbJ2BetWGgeciM7IQFY0=;
        b=ckYvzTpShRt9ISYHJksABh3mWs2p9BuiI31VK4IDvvkeZF03C3514VY/FoSomDLbbK
         ohwlGqe+OvHKcmd8p8BgihZWcSkcEqw+KJi+mKN9FXEuwcpfxm92j79PlEttqIYSzA3R
         3vzAwqr2xTmojOJutoTshn3p43kY/mYCtWSmY/qj34FERsDcVtmfSJkfMTXA1o+cfZuf
         NhAWXFdhnqUfsGrU/diyqpHplkSmmnYRXmBcfjwHiZIn2NuDvRTsQ7+pCideujM0zpvr
         C/xJQ+FWpoEMk8l5aEdOdKkcdK1XxutB6pu8Owi71WBMc3fwjZ8gmbkzReIM8fpu69G+
         RRpw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=NU3VK3oJ;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::429 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pf1-x429.google.com (mail-pf1-x429.google.com. [2607:f8b0:4864:20::429])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-29651b6b1c1si3803765ad.6.2025.11.10.08.37.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 10 Nov 2025 08:37:39 -0800 (PST)
Received-SPF: pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::429 as permitted sender) client-ip=2607:f8b0:4864:20::429;
Received: by mail-pf1-x429.google.com with SMTP id d2e1a72fcca58-7ade456b6abso2702136b3a.3
        for <kasan-dev@googlegroups.com>; Mon, 10 Nov 2025 08:37:39 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCXmdFQyEWYutrasa8ibSoi0Ip2NVWBW6hUBsEcMLbFOmhjPd/TnffQA668g3y3mM4D5mktvGvyu8O4=@googlegroups.com
X-Gm-Gg: ASbGncsw6Qkt69XHp7LEn9EoDY1lAy/IBorbjkdYsfJI4WLcoSqUpiaJJ+Pd0P40x+/
	HGSi+HlsMm3y28Skc3dnj7ekDcyL8jky9jXG1K0O6mM4Rel3JOw//y0U4fq+VH5x+DT9BMaDOOZ
	Mny7j5SAFrsMT9rTHbjSJBlzRCXlVhZ/OTApBBJoMsKX67QmepSuz8kGIWsMvP5b2yQNx9PskdQ
	+4Io+Z68vZpNn+myUX+CpWLRk0Oh4p1wIWiTV+FG3pwZYqNDQYO521B/81LHUhn+q4xRJQ0qkgC
	BUHkzubdMq/bhrWO/gb+OQGEH3lcpuM26C7NobR5B53vhukRVwSgSmmSsp3rIxI4WOTsFD397U9
	BCvNu8JFPcmPhvA7SlMJYTI+a/gaa8uDoVKfEr0t0RB9pTeTj/0grYFR3y9eYwWf0RhKZ9FjBBB
	L5RRjB0ij/rz/Ng94RNHD0/g==
X-Received: by 2002:a05:6a21:6d97:b0:334:8d0b:6640 with SMTP id adf61e73a8af0-353a13aaf66mr12767757637.8.1762792659125;
        Mon, 10 Nov 2025 08:37:39 -0800 (PST)
Received: from localhost ([103.88.46.62])
        by smtp.gmail.com with ESMTPSA id 41be03b00d2f7-ba8f8e750c1sm13193534a12.1.2025.11.10.08.37.38
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 10 Nov 2025 08:37:38 -0800 (PST)
From: Jinchao Wang <wangjinchao600@gmail.com>
To: Andrew Morton <akpm@linux-foundation.org>,
	"Masami Hiramatsu (Google)" <mhiramat@kernel.org>,
	Peter Zijlstra <peterz@infradead.org>,
	Randy Dunlap <rdunlap@infradead.org>,
	Marco Elver <elver@google.com>,
	Mike Rapoport <rppt@kernel.org>,
	Alexander Potapenko <glider@google.com>,
	Adrian Hunter <adrian.hunter@intel.com>,
	Alexander Shishkin <alexander.shishkin@linux.intel.com>,
	Alice Ryhl <aliceryhl@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Andrii Nakryiko <andrii@kernel.org>,
	Ard Biesheuvel <ardb@kernel.org>,
	Arnaldo Carvalho de Melo <acme@kernel.org>,
	Ben Segall <bsegall@google.com>,
	Bill Wendling <morbo@google.com>,
	Borislav Petkov <bp@alien8.de>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Dave Hansen <dave.hansen@linux.intel.com>,
	David Hildenbrand <david@redhat.com>,
	David Kaplan <david.kaplan@amd.com>,
	"David S. Miller" <davem@davemloft.net>,
	Dietmar Eggemann <dietmar.eggemann@arm.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	"H. Peter Anvin" <hpa@zytor.com>,
	Ian Rogers <irogers@google.com>,
	Ingo Molnar <mingo@redhat.com>,
	James Clark <james.clark@linaro.org>,
	Jinchao Wang <wangjinchao600@gmail.com>,
	Jinjie Ruan <ruanjinjie@huawei.com>,
	Jiri Olsa <jolsa@kernel.org>,
	Jonathan Corbet <corbet@lwn.net>,
	Juri Lelli <juri.lelli@redhat.com>,
	Justin Stitt <justinstitt@google.com>,
	kasan-dev@googlegroups.com,
	Kees Cook <kees@kernel.org>,
	"Liam R. Howlett" <Liam.Howlett@oracle.com>,
	"Liang Kan" <kan.liang@linux.intel.com>,
	Linus Walleij <linus.walleij@linaro.org>,
	linux-arm-kernel@lists.infradead.org,
	linux-doc@vger.kernel.org,
	linux-kernel@vger.kernel.org,
	linux-mm@kvack.org,
	linux-perf-users@vger.kernel.org,
	linux-trace-kernel@vger.kernel.org,
	llvm@lists.linux.dev,
	Lorenzo Stoakes <lorenzo.stoakes@oracle.com>,
	Mark Rutland <mark.rutland@arm.com>,
	Masahiro Yamada <masahiroy@kernel.org>,
	Mathieu Desnoyers <mathieu.desnoyers@efficios.com>,
	Mel Gorman <mgorman@suse.de>,
	Michal Hocko <mhocko@suse.com>,
	Miguel Ojeda <ojeda@kernel.org>,
	Nam Cao <namcao@linutronix.de>,
	Namhyung Kim <namhyung@kernel.org>,
	Nathan Chancellor <nathan@kernel.org>,
	Naveen N Rao <naveen@kernel.org>,
	Nick Desaulniers <nick.desaulniers+lkml@gmail.com>,
	Rong Xu <xur@google.com>,
	Sami Tolvanen <samitolvanen@google.com>,
	Steven Rostedt <rostedt@goodmis.org>,
	Suren Baghdasaryan <surenb@google.com>,
	Thomas Gleixner <tglx@linutronix.de>,
	=?UTF-8?q?Thomas=20Wei=C3=9Fschuh?= <thomas.weissschuh@linutronix.de>,
	Valentin Schneider <vschneid@redhat.com>,
	Vincent Guittot <vincent.guittot@linaro.org>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Vlastimil Babka <vbabka@suse.cz>,
	Will Deacon <will@kernel.org>,
	workflows@vger.kernel.org,
	x86@kernel.org
Subject: [PATCH v8 13/27] mm/ksw: add per-task ctx tracking
Date: Tue, 11 Nov 2025 00:36:08 +0800
Message-ID: <20251110163634.3686676-14-wangjinchao600@gmail.com>
X-Mailer: git-send-email 2.43.0
In-Reply-To: <20251110163634.3686676-1-wangjinchao600@gmail.com>
References: <20251110163634.3686676-1-wangjinchao600@gmail.com>
MIME-Version: 1.0
X-Original-Sender: wangjinchao600@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=NU3VK3oJ;       spf=pass
 (google.com: domain of wangjinchao600@gmail.com designates
 2607:f8b0:4864:20::429 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
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

Each task tracks its depth, stack pointer, and generation. A watchpoint is
enabled only when the configured depth is reached, and disabled on function
exit.

The context is reset when probes are disabled, generation changes, or exit
depth becomes inconsistent.

Duplicate arming on the same frame is skipped.

Signed-off-by: Jinchao Wang <wangjinchao600@gmail.com>
---
 mm/kstackwatch/stack.c | 67 ++++++++++++++++++++++++++++++++++++++++++
 1 file changed, 67 insertions(+)

diff --git a/mm/kstackwatch/stack.c b/mm/kstackwatch/stack.c
index 3aa02f8370af..96014eb4cb12 100644
--- a/mm/kstackwatch/stack.c
+++ b/mm/kstackwatch/stack.c
@@ -11,6 +11,53 @@
 static struct kprobe entry_probe;
 static struct fprobe exit_probe;
 
+static bool probe_enable;
+static u16 probe_generation;
+
+static void ksw_reset_ctx(void)
+{
+	struct ksw_ctx *ctx = &current->ksw_ctx;
+
+	if (ctx->wp)
+		ksw_watch_off(ctx->wp);
+
+	ctx->wp = NULL;
+	ctx->sp = 0;
+	ctx->depth = 0;
+	ctx->generation = READ_ONCE(probe_generation);
+}
+
+static bool ksw_stack_check_ctx(bool entry)
+{
+	struct ksw_ctx *ctx = &current->ksw_ctx;
+	u16 cur_enable = READ_ONCE(probe_enable);
+	u16 cur_generation = READ_ONCE(probe_generation);
+	u16 cur_depth, target_depth = ksw_get_config()->depth;
+
+	if (!cur_enable) {
+		ksw_reset_ctx();
+		return false;
+	}
+
+	if (ctx->generation != cur_generation)
+		ksw_reset_ctx();
+
+	if (!entry && !ctx->depth) {
+		ksw_reset_ctx();
+		return false;
+	}
+
+	if (entry)
+		cur_depth = ctx->depth++;
+	else
+		cur_depth = --ctx->depth;
+
+	if (cur_depth == target_depth)
+		return true;
+	else
+		return false;
+}
+
 static int ksw_stack_prepare_watch(struct pt_regs *regs,
 				   const struct ksw_config *config,
 				   ulong *watch_addr, u16 *watch_len)
@@ -25,10 +72,22 @@ static void ksw_stack_entry_handler(struct kprobe *p, struct pt_regs *regs,
 				    unsigned long flags)
 {
 	struct ksw_ctx *ctx = &current->ksw_ctx;
+	ulong stack_pointer;
 	ulong watch_addr;
 	u16 watch_len;
 	int ret;
 
+	stack_pointer = kernel_stack_pointer(regs);
+
+	/*
+	 * triggered more than once, may be in a loop
+	 */
+	if (ctx->wp && ctx->sp == stack_pointer)
+		return;
+
+	if (!ksw_stack_check_ctx(true))
+		return;
+
 	ret = ksw_watch_get(&ctx->wp);
 	if (ret)
 		return;
@@ -49,6 +108,7 @@ static void ksw_stack_entry_handler(struct kprobe *p, struct pt_regs *regs,
 		return;
 	}
 
+	ctx->sp = stack_pointer;
 }
 
 static void ksw_stack_exit_handler(struct fprobe *fp, unsigned long ip,
@@ -57,6 +117,8 @@ static void ksw_stack_exit_handler(struct fprobe *fp, unsigned long ip,
 {
 	struct ksw_ctx *ctx = &current->ksw_ctx;
 
+	if (!ksw_stack_check_ctx(false))
+		return;
 
 	if (ctx->wp) {
 		ksw_watch_off(ctx->wp);
@@ -91,11 +153,16 @@ int ksw_stack_init(void)
 		return ret;
 	}
 
+	WRITE_ONCE(probe_generation, READ_ONCE(probe_generation) + 1);
+	WRITE_ONCE(probe_enable, true);
+
 	return 0;
 }
 
 void ksw_stack_exit(void)
 {
+	WRITE_ONCE(probe_enable, false);
+	WRITE_ONCE(probe_generation, READ_ONCE(probe_generation) + 1);
 	unregister_fprobe(&exit_probe);
 	unregister_kprobe(&entry_probe);
 }
-- 
2.43.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251110163634.3686676-14-wangjinchao600%40gmail.com.
