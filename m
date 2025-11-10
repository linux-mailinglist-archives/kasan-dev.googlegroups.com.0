Return-Path: <kasan-dev+bncBD53XBUFWQDBBS5JZDEAMGQER7LVIZA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3d.google.com (mail-oo1-xc3d.google.com [IPv6:2607:f8b0:4864:20::c3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 8E165C47FD1
	for <lists+kasan-dev@lfdr.de>; Mon, 10 Nov 2025 17:37:33 +0100 (CET)
Received: by mail-oo1-xc3d.google.com with SMTP id 006d021491bc7-656f0a75a44sf3046954eaf.1
        for <lists+kasan-dev@lfdr.de>; Mon, 10 Nov 2025 08:37:33 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1762792652; cv=pass;
        d=google.com; s=arc-20240605;
        b=WEGdh7Xwr8DPdNYx1IBjE3Sa10pUGcVY0mjzyCu9ioCbOF23qmrSexdakhJ3Gf8Kka
         OBJGz5G7Zpcw2H/H03sUX1BV/dvt0mLxg4xS6R7EfYcDygHt0sF1CyQq83BWb3Y6f7f8
         Nffuh/batncsBLb/ilA0wIQFLfNLPixIqIY8IujUjqhAP3qUymrTMLbyzXb+jvKKoAbb
         xRQjXGlxoLZLhl4F+VzrU5Jc8+p5Hl1AFy9/EFihFgrVVy5CMs8Zz9op4vRUZ4t2Lz4C
         yIUT/LJpWxkugRNaW0VQvwFKR7wtKn+5i2nFt9Nupk07N1TuchRX8934TPdM46v08zcD
         dKPQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:to:from:sender:dkim-signature
         :dkim-signature;
        bh=lxcmO4+FNHhmxXYdP55+4TjDIgUAa4DMB5COSCRbsEc=;
        fh=OEhvubpaOv1OnnEmUnL7FY8/9tUzJQNpAWnejAuStBo=;
        b=flM7/0RB7OfWZazOn6xjNs+twaluu0hCJJeKyYCQk2k0VaAJo8xAymczk6EF2Oa8Yv
         RAkE3SrZs9761OHaKqMon2XKvYbiIuxJrvHJ1INxedc2krCqeNUyECjkNqR9+RarHWZV
         nBm57ZcHZZcM45y8TAMlHJDG+a8XaUDaDclJsR4+gmqZgXgm7TBMOdTlmv27HTFI+0Xx
         LhFp2O123hxcCmzgiNACKHeCTU9iH9+OGkDjn5JxC4XP4U9+mEzjlnZhjwpxm0Chq+yn
         1AWWh0k3jlw6i34bJHpIi1L1u1hrKWNo3p3IKIDNtifa7cwdZkMT5VJdhkBJQtAxpBev
         Bh7w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=euKM0C9z;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::631 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1762792652; x=1763397452; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=lxcmO4+FNHhmxXYdP55+4TjDIgUAa4DMB5COSCRbsEc=;
        b=ZZ7qCkS7/b55dmWWaWCglfpwzhbh0QkeADfzF6ZRLazs1avs9sYnyI4wxxSZfas8e4
         eeXDBvMJ/o1XBQNbsrW+AyOZacZ/jSOhXM6s9DcOm3vfydVLGEJ16iNL8V7ORrF4Vh0g
         KAjsqZjc7USiYA6ow90szteEM+rM1OIRkYUBN5aJQFCD2TOZ3qA61AsnICfTITC5wrkI
         op0C2GRXUdDj+bFIQ4GqJVy3bt4SEp3aEY5w+6mfNL67wuuSIQn3NBl49LnpSOhFXFXi
         D504jiQ8j1YbEt8wFMQEVROzKMAowSHNSN8/Qy/t2DYB3DgAf3rDpyDazVAMSVfjhz6c
         Q4Sw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1762792652; x=1763397452; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=lxcmO4+FNHhmxXYdP55+4TjDIgUAa4DMB5COSCRbsEc=;
        b=VDCswrYPOhNft1dgdlxPEWGkk8YMF2LPGWa2prhwlsUItrQ5U6fS27lxi8LoobaNno
         Q0kMCqXLgE4BDnX97xWqCkMiXRCfkETkR3pRKF0jOmaAmz/bVzrOLWa7hofpY4vm2/Ym
         ixzR51C07K/aA5/k5MVDO2YJqrHM1CUz1OtMbGysqJ1YiblFq+e1via+z9xPirvY+eih
         hvvp01yyQvG6M1eA1xz7HJ1zWeBb+DaeRJSjvLB1qBSJxDGHxifB4lrsdwkBFFMthg8S
         vQOWTVfJe1VMy+nrNxucIpxAJNrhwE4xEwuj12AsNMENHzOmbonahzoU+2IpKcZHH0Mz
         iFEQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1762792652; x=1763397452;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:to:from:x-gm-gg
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=lxcmO4+FNHhmxXYdP55+4TjDIgUAa4DMB5COSCRbsEc=;
        b=gjlORy43s9XyeX35xJrsnLbZ7e+OE44okvU1a1mGpHVUgoBq169lwvh8jE7LvMUkDv
         EWqFpfTyv+qnUQEPHLCg8IWHBErUmFaCm7J1XAg4WbGF8UUGC9BH8KXvPHybK8LIGTeU
         GqjXbaa7c6kBYHDxPBCMDvWxI4F8ZtyqYemyXkcq8UhoFXTfZA7SJuHOpp/nXne7rNia
         BzIQryhOBA8hiKGcxoAvnVwaWGDsjQJucIsfE1CFVBrVlX8sHDjLjCu3yMZsG/nMFuDf
         tq+8uZBbDbKqClt0D8WMjmCrZnY1dptDPpat5ugSVsVzZQzyaFR6QPzk46GqB45GJG8k
         9/3g==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWbgxKqU0B/Cjo4InR92w4791jodMMneGqNUzS1Bk5Wq8zUplzPhoQekUMB5l4N6xU/9jxTAw==@lfdr.de
X-Gm-Message-State: AOJu0Yw1a4wY6I8mkx78tlEDDUHlL1ley07N1W4z7QPq0h1/4rJj+V2P
	6m8P2P6GHZpxlrqkIJAVfRONprcnHM5ndUb6GfoJr5nDivibXOgsAXDr
X-Google-Smtp-Source: AGHT+IH7Z+qTNGX4eZf6B/1/zmtpqXJgTCw6hPLmQyg6J3vXizJPfjgpwsUIv3sq0OxWp0S7yfoetw==
X-Received: by 2002:a05:6820:2216:b0:656:84e7:8fde with SMTP id 006d021491bc7-656d8deb9c2mr4565843eaf.3.1762792651876;
        Mon, 10 Nov 2025 08:37:31 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+YgxVcb0UNq8KmAgOhcvjJVaAbZDCpt8b3rKo4GMWiVEQ=="
Received: by 2002:a05:6820:1954:b0:656:dc35:4828 with SMTP id
 006d021491bc7-656dc354923ls937253eaf.2.-pod-prod-07-us; Mon, 10 Nov 2025
 08:37:31 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXS5XHBl/3JDXPHuobJdKiip4ixGpI+NjQHrJRPAwNxazcF5rPLFGVYC+ghCXuHCitK3WRtn6E1M9k=@googlegroups.com
X-Received: by 2002:a05:6808:3447:b0:450:1f44:da5c with SMTP id 5614622812f47-4502a3bbf8bmr4019618b6e.45.1762792651139;
        Mon, 10 Nov 2025 08:37:31 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1762792651; cv=none;
        d=google.com; s=arc-20240605;
        b=dN+RG/7/G+x8/plW0aMDaDWV05oBW4vOqf4jqcFMfFwIaeokUmaFh/9DmuyQnoDJXp
         M618oG3YEg/94h9JA7Gchq0urBpXs8kRQF+TQtE8P8cQch0UiGSVm1Ozi0N5UGmxTCJu
         Lheb1bUHfHpXh+Yn99ikAjVziy+TiXxOYVx94jBEJp/1cfB/cf+boUu3PM12+3/VmJwy
         q1c2v8s7qiWhorNr6DX7g+4XrKtBC8d6wJUYYzIThYYN0vcOTsjcbD2UF/EDYJahQuRP
         dn7zy5e+rr1ittDK8YPsSZt28lHDSw8B6FJeFUTUh3k/b+hAaq05yDod7QHKMIJIXkiF
         OZDw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:to:from:dkim-signature;
        bh=zmTHCnPEb0OVb2q4c4fHcn++Nk34I0DPY6dUiFoe4Xs=;
        fh=xaw/C1TgHK6dwB+2DnGEwv8LZnNEmZz/wkfa/5YDTD8=;
        b=k38KaNwmcdMVvfsEtXPEocycqBAxWsLlUhXQ9/f7aB6rXD3SfPUK98uL7fiuvjZQ+4
         Ha84RzmvIjol+aGGLuaDWfNv7Lf5i1SbkDRL+9sKOMLUmKKwqXQhFs4A6kuGxOijdRt6
         bzEH+xMiqyof9Pufdw1JHG/DZGrxNHDcLyvMXIOGi4uzgi2mYYXOg9pvVOHZQQB3AZxm
         XTNfXXb/tQDNYVnKDXJXcg2bLf5l/c19e/o8+cvJaYazOmk08ubzQfq381r8gYu0ZOav
         INccyTs52TPhhCFiSGvCkoTr6SNScEfLfWdFXfA1ZMFSiQbHZGq9t5aoYIkA8kHUo9Nk
         1Jzg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=euKM0C9z;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::631 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pl1-x631.google.com (mail-pl1-x631.google.com. [2607:f8b0:4864:20::631])
        by gmr-mx.google.com with ESMTPS id 5614622812f47-45002533084si330195b6e.0.2025.11.10.08.37.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 10 Nov 2025 08:37:31 -0800 (PST)
Received-SPF: pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::631 as permitted sender) client-ip=2607:f8b0:4864:20::631;
Received: by mail-pl1-x631.google.com with SMTP id d9443c01a7336-297dd95ffe4so22999715ad.3
        for <kasan-dev@googlegroups.com>; Mon, 10 Nov 2025 08:37:31 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCUu5FnTKGzal4MT4H5k7YwMWC98YKz95YthvOWjoqvgHvvRJtrqE4akuILE46FQGTMEyD0F5IDOXaY=@googlegroups.com
X-Gm-Gg: ASbGncvFPfhB1UF6+LXVTE/XjX+5FYUIiAZDpsFXACO2tJuj609aMmUKFXSEg18sfSW
	GXuMQmAD6vJ3E1OuhfgA502TjHMIYmIcyNq9Tbubx/xGxzxFeMcts9I9lVsnb7fRz9ZlPlRs0FW
	2vNHgGY1ar3/2P4XxFHwt/ZEq5QbGwHdIxalc4OC8Txz+wrEK3H8saIV3Zcl9qgcHTFfDXpV2cm
	qpA8JYhVgZU7BWcyaQPoVagUaQas2CWc5dcfKsef/VPe7ZAKhiqzRgNJV2PRKsRr6o3Ma30l8+q
	fbC241lqeiaSzHPg4MmzGx2W+HG0/1FlNPcMbyzpW4CRt9+aPzcjP8p4Py9DXXsMwtgmD2ODebD
	nOd0y1AVIYnqeojfppTrvRdrMgjnN4Et0/hj4pxjlqGqWD0d5shJJJAuVmB4meWyBZ6BwpslZNq
	TAMB5ROA6zxJm6p3uyfMkChw==
X-Received: by 2002:a17:903:944:b0:296:3f23:b910 with SMTP id d9443c01a7336-297e5619f92mr100007215ad.9.1762792650184;
        Mon, 10 Nov 2025 08:37:30 -0800 (PST)
Received: from localhost ([103.88.46.62])
        by smtp.gmail.com with ESMTPSA id d9443c01a7336-2965096b801sm154506025ad.7.2025.11.10.08.37.29
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 10 Nov 2025 08:37:29 -0800 (PST)
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
Subject: [PATCH v8 11/27] sched/ksw: add per-task context
Date: Tue, 11 Nov 2025 00:36:06 +0800
Message-ID: <20251110163634.3686676-12-wangjinchao600@gmail.com>
X-Mailer: git-send-email 2.43.0
In-Reply-To: <20251110163634.3686676-1-wangjinchao600@gmail.com>
References: <20251110163634.3686676-1-wangjinchao600@gmail.com>
MIME-Version: 1.0
X-Original-Sender: wangjinchao600@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=euKM0C9z;       spf=pass
 (google.com: domain of wangjinchao600@gmail.com designates
 2607:f8b0:4864:20::631 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
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

Introduce struct ksw_ctx to enable lockless per-task state
tracking. This is required because KStackWatch operates in NMI context
(via kprobe handler) where traditional locking is unsafe.

Signed-off-by: Jinchao Wang <wangjinchao600@gmail.com>
---
 include/linux/kstackwatch_types.h | 14 ++++++++++++++
 include/linux/sched.h             |  5 +++++
 2 files changed, 19 insertions(+)
 create mode 100644 include/linux/kstackwatch_types.h

diff --git a/include/linux/kstackwatch_types.h b/include/linux/kstackwatch_types.h
new file mode 100644
index 000000000000..8c4e9b0f0c6a
--- /dev/null
+++ b/include/linux/kstackwatch_types.h
@@ -0,0 +1,14 @@
+/* SPDX-License-Identifier: GPL-2.0 */
+#ifndef _LINUX_KSTACKWATCH_TYPES_H
+#define _LINUX_KSTACKWATCH_TYPES_H
+#include <linux/types.h>
+
+struct ksw_watchpoint;
+struct ksw_ctx {
+	struct ksw_watchpoint *wp;
+	ulong sp;
+	u16 depth;
+	u16 generation;
+};
+
+#endif /* _LINUX_KSTACKWATCH_TYPES_H */
diff --git a/include/linux/sched.h b/include/linux/sched.h
index b469878de25c..db49325428b3 100644
--- a/include/linux/sched.h
+++ b/include/linux/sched.h
@@ -22,6 +22,7 @@
 #include <linux/sem_types.h>
 #include <linux/shm.h>
 #include <linux/kmsan_types.h>
+#include <linux/kstackwatch_types.h>
 #include <linux/mutex_types.h>
 #include <linux/plist_types.h>
 #include <linux/hrtimer_types.h>
@@ -1487,6 +1488,10 @@ struct task_struct {
 	struct kmsan_ctx		kmsan_ctx;
 #endif
 
+#if IS_ENABLED(CONFIG_KSTACKWATCH)
+	struct ksw_ctx		ksw_ctx;
+#endif
+
 #if IS_ENABLED(CONFIG_KUNIT)
 	struct kunit			*kunit_test;
 #endif
-- 
2.43.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251110163634.3686676-12-wangjinchao600%40gmail.com.
