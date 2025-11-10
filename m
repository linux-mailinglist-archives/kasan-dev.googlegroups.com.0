Return-Path: <kasan-dev+bncBD53XBUFWQDBB25JZDEAMGQERDGEY4Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63b.google.com (mail-pl1-x63b.google.com [IPv6:2607:f8b0:4864:20::63b])
	by mail.lfdr.de (Postfix) with ESMTPS id 5F8ADC47FF2
	for <lists+kasan-dev@lfdr.de>; Mon, 10 Nov 2025 17:38:05 +0100 (CET)
Received: by mail-pl1-x63b.google.com with SMTP id d9443c01a7336-297ddb3c707sf22827745ad.2
        for <lists+kasan-dev@lfdr.de>; Mon, 10 Nov 2025 08:38:05 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1762792684; cv=pass;
        d=google.com; s=arc-20240605;
        b=KzRRTOFkxBAkZuxCy+0i+cBfnjY+77Z7eE59VjE2DDV9LSITdA1DLZMXZG/SoD3r4C
         aAyBWIpd6frnctq4ie1KbDqRWJZm26ForLGuJok3YSWI1L0sVNOCRIxX5cvdJdGmIzzv
         eJBZvjmiWs3v41fwg8p0eJE+qpm0f70bSlxMTI7QsnKFwGFXr3yPJU5qdSX4zdwlOTeH
         ivoLVYeo/DrcPbRle/iF+bLTobdWzneNu14mcLgYO5AngjbdIWdGSxa6MpTAzmu0UFXo
         JwZZ+7CkqX7cZ5cwP/JIoRc7FKWl6BYUEJFc9jl/u2RxZEXsH0JKhXy4UDIWf0dHETLZ
         EIkQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:to:from:sender:dkim-signature
         :dkim-signature;
        bh=qqiUBAMOgpPT3ud5FJ+CTcGLm+5SEP728wSnpPd4qxU=;
        fh=ZiMkhu+RCoStq6QaiypiV1wbdT+lgyEUKGHz7c7NIPk=;
        b=IO2Ehnio4U7P17oZty96n/XvNrvPCyJSeKqDJb/8wGLmvrMAC5xgRAQscixGWB3fLd
         Qrk+RT41RQrM5wus6QKA4gAVoTSCrlGjL+xg3PMOOt2GNbjOizvZ9l0RLpJNq4OtMzbX
         I7wTcupn/adKntpGniYOS2cVw0KmvVeLn04wy2hO9pxmJjZcCvk0PIWdC7Pc5O9dvNzr
         lpnw9+LBKL9npzxqkKArirGltyhNFzVHip1WyXI0UHYYidVHPbvHukovWGtL2FgL/nST
         ekU5pwNU5ZgNWBIQGqefkHVgJuxaPp59dCUFpcwp6B31X2h3LLcuZ3rpfmUtjvwlgxBW
         X1cA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=V7YTE8bq;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::432 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1762792684; x=1763397484; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=qqiUBAMOgpPT3ud5FJ+CTcGLm+5SEP728wSnpPd4qxU=;
        b=HaXjoPZVw9kuSl7o36HWZRGK2amj+RmiAk9XeG5ztkosRY3O7mRwuSOocUwxEwE2Wc
         TK3mLq7YD8gOQBceGGow+pLlHaHEyTxW1kxabPTRmQ3L/X/zahA3O19oHDvzyfJE4HCl
         COrMk8YR8fs1HtuU00meXDw6GEt4dCcR3UqVm/ULLmsTZL4MaZgp3RM8MOZXRbHbmvpz
         RJvurQ9Tjv6nKB5Vnym4mGEl3ENU/r55jYQQmeZJZtv03DgLgGuimPFvYBWsGP3aS8W/
         YvYG87zY9q4cc6CBMK9pl2WQ3dAMwmlEDm0qGGmUSyLgym8ivMYmn/OqxnfQqZkFRMD4
         BBYw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1762792684; x=1763397484; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=qqiUBAMOgpPT3ud5FJ+CTcGLm+5SEP728wSnpPd4qxU=;
        b=km3tiuBjjwVkg1Vx8CoAmK+uWBac+/BNEVezg2QVg1Zl76+bpVhKeoeEbD1H0d17KX
         qOSff3vIxCrt2fxLHHGq1+rT63+bsAqNlPgGpy/REBHpGf2z/fKJi0d/HSBojLEq2tcZ
         hDm8tWs4Py1gO7kAzHQ8a/LRyrzIdIigmGgne0Nh9+M5Hk+hh3lvaogxQoR3Ntb4wUgS
         bp+qTpgfB2go4Y2LzUM2Jyjc/VBA9eipkjv18siee0Pxu18kzsyfQ51Z3e1NPEcOGb9k
         A+h4pJo+Zv0gNRw24AN6NZgd/+fj26eHWZHnf6HGwxUsBQeLrB7yx9dx4M8sxsJY13Bx
         FDqQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1762792684; x=1763397484;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:to:from:x-gm-gg
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=qqiUBAMOgpPT3ud5FJ+CTcGLm+5SEP728wSnpPd4qxU=;
        b=PBvpdnTDUNPpnZk7Ju7NmOueQptOAk8ZRKj0rHZwCFIaezSrvqkx/aYDRRBoi/4i8u
         NAbL/VEIAvAXZvhv+LDKH3POeRWlszeBuLo6Il7z+ct4/vc9a4Ohg6RyMLlf2zfkHbSp
         /DxSt1glIbzqa5rH55tdnT/FOan20+9InKiQ/lchwVC01mW8ZVgDmMmtVUtCb6AcmJwF
         WL7OHjoVcC3Wurjf53WF+x9keHB1IdaBmNc1OFm3zKZgQ1qes4a7tN8euexMIAIvyvuL
         Q0jpZyzR7cgU7efZWUSs+m2qnYts6UCOaCermV/yuyx8oaVYIJeHSkQd/dE+gI9T4AIr
         bdIQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWRVHfAHdkpC9/GH9oU/QOB+YJ0O2uZJaRZbrzW8qiflLkNBw0L+aWqHzLPpu5/NiYOT7+6JQ==@lfdr.de
X-Gm-Message-State: AOJu0YzXXyLRzNT/ebGoqks0jPlcwyrrK5nqDZKPSqSjSQ6IsDcOjbbb
	GRlCwVvekJjfwriDkCSeV8ZhQq3T9tZ/38LlHAZzFGNAFva1tJHEFiyj
X-Google-Smtp-Source: AGHT+IF7/533ZgA29cYS4BpqDm4t6hPMdHfFSOqmFG7hQCs3btjIWgvWS3kgtorQmH5GKvToaJ0LVQ==
X-Received: by 2002:a17:902:da4b:b0:297:dfae:1524 with SMTP id d9443c01a7336-297e56473f1mr131376505ad.16.1762792683682;
        Mon, 10 Nov 2025 08:38:03 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+bWLeeyB3VdkHNdFN/NYmD9Lne4iu2Zz/xYSSntu5D8qQ=="
Received: by 2002:a17:902:6b82:b0:295:119:a71a with SMTP id
 d9443c01a7336-2965244a360ls45131295ad.2.-pod-prod-07-us; Mon, 10 Nov 2025
 08:38:02 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUfI0j2dXu05HH5KhptO9luwbxo6kBfU6HfNXbz++njxo9u+GPFYO5+nAbcLS1NnVtMzT2grhEyLUY=@googlegroups.com
X-Received: by 2002:a17:902:dace:b0:276:d3e:6844 with SMTP id d9443c01a7336-297e56d88bdmr103766965ad.33.1762792682150;
        Mon, 10 Nov 2025 08:38:02 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1762792682; cv=none;
        d=google.com; s=arc-20240605;
        b=MJB2goVM4YqQ7slch1yaJaw+LN+p9IUqHBqLi9jbGmlzoFIGq/QnCWRHJKduaIQ0ne
         P8Ik26hU5vlcfX3SloUSDiD7OU3BQzVu5tsl0KgG6pueZJpLYSmS+/n0HNMXwTY3tW6r
         gi9CUdnAmj+aNBqcjm3ZvhUSC4kfpJoJUCOXgLFF2WeMHNhB1WkxXBpiTj8jDbi0klOq
         7u/+8T++jm5qOLpAqU32+0X5yUvpmVFaERHh95eREiJt+mN+bjyg2ZDE8d4LAq/2Jpqj
         gYxdlBXlW8ZR6KC+7KLq5fNGEHgS9sd1MEH0kytWPD/iu2rSEQyHtMWPHfkAuiUxmtKe
         rhNQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:to:from:dkim-signature;
        bh=UVmErpKw40BYN09ToGb11RVmfMPSvvKFwxlIzoWfVWE=;
        fh=DNNX8hkK9BBOAeu5aTq39ejfrP/HW+YDj2CuX/VXUpI=;
        b=jK83u03Du1pxxHk/uqNSxTvEu1/QSS06XqZEVgm934bjNWmQHcpF+7IbacrtdqScui
         fnmcSicCq06y0RTY+xtC0UZqlkevX6sXZgksmfjSgWXISS6pPE2nu/SIv8dvQ+rRF3Fc
         3+YT++YIBTM4elVxpPPq/qCs12jrGlYLPBTy27SFeaJ60Iom/P89ZHvhk8Fm1tQoluXg
         JAcJpF+y/AUQ3MT+9SC7GHOhhAHwCHIUPjmIelTVla5hwxaolaOVCe5MjxaZWNdCnCsZ
         dSy/Sex76MF5ftqWwT/ha7bR9EoCx5N911/X+7KWknTtLYJxeZA0gdf7CdHKLqX0rFlz
         ma5g==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=V7YTE8bq;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::432 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pf1-x432.google.com (mail-pf1-x432.google.com. [2607:f8b0:4864:20::432])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-2965096d04csi2085525ad.1.2025.11.10.08.38.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 10 Nov 2025 08:38:02 -0800 (PST)
Received-SPF: pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::432 as permitted sender) client-ip=2607:f8b0:4864:20::432;
Received: by mail-pf1-x432.google.com with SMTP id d2e1a72fcca58-78af3fe5b17so2489879b3a.2
        for <kasan-dev@googlegroups.com>; Mon, 10 Nov 2025 08:38:02 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCXGznQHTTFp1+vy/Tfrk930+miOKJMBjwsl94YraVQdnK+agCTVagIvZBd9D4x4RccSsCb9kjUKfGw=@googlegroups.com
X-Gm-Gg: ASbGnctQbCgRdv1n+nt68bvmGGYzatf09mkRVw2AMD0WaLGzAdwgBR/Qc9v7Y82OoXc
	LMwN4Lt53NMmPTb0MAHwNvR+hjpXaVyGuOfNlRTbun5hemqV7cA1U/qImFK4Obcw9VZDPmmI6d0
	nJSxpaYCSPh3U+Ck9TJP3NnDUs4Q+W+xTQpOtPQmgHi9p5dsPMmSpytqIXAuQ9FB/50YFb1YtIW
	wBy6U6GRY/dSeFYGLB0qx6hAsOk3ZyEjBVyPC8D6Q/qVj9dgqV//PyyS0FgcrL2fyhytd9xfM3e
	XI6IjFgX24AMXsP1tJ//do0lXzVtOzcZRfD3Ec4ghoVau11JoKR4Ge7Y13PSBDin5am/zdRiLvq
	JVOyuxCJRgulT9DW117FekfXtOczsquxTNQRd0Fzw9HFtuY3YOejv4tO/KVk4tIMkv6nhEalkYi
	6fu4fQ9MBJw+p3C0r75s0R2mM9Fqb+E8Oz
X-Received: by 2002:a17:902:da4b:b0:297:dfae:1524 with SMTP id d9443c01a7336-297e56473f1mr131374835ad.16.1762792681587;
        Mon, 10 Nov 2025 08:38:01 -0800 (PST)
Received: from localhost ([103.88.46.62])
        by smtp.gmail.com with ESMTPSA id d9443c01a7336-29651c8ef47sm153049485ad.74.2025.11.10.08.38.00
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 10 Nov 2025 08:38:01 -0800 (PST)
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
Subject: [PATCH v8 18/27] arm64/hw_breakpoint: Add arch_reinstall_hw_breakpoint
Date: Tue, 11 Nov 2025 00:36:13 +0800
Message-ID: <20251110163634.3686676-19-wangjinchao600@gmail.com>
X-Mailer: git-send-email 2.43.0
In-Reply-To: <20251110163634.3686676-1-wangjinchao600@gmail.com>
References: <20251110163634.3686676-1-wangjinchao600@gmail.com>
MIME-Version: 1.0
X-Original-Sender: wangjinchao600@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=V7YTE8bq;       spf=pass
 (google.com: domain of wangjinchao600@gmail.com designates
 2607:f8b0:4864:20::432 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
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

Add arch_reinstall_hw_breakpoint() to restore a hardware breakpoint
in an atomic context. Unlike the full uninstall and reallocation
path, this lightweight function re-establishes an existing breakpoint
efficiently and safely.

This aligns ARM64 with x86 support for atomic breakpoint reinstalls.
---
 arch/arm64/Kconfig                     | 1 +
 arch/arm64/include/asm/hw_breakpoint.h | 1 +
 arch/arm64/kernel/hw_breakpoint.c      | 5 +++++
 3 files changed, 7 insertions(+)

diff --git a/arch/arm64/Kconfig b/arch/arm64/Kconfig
index 6663ffd23f25..fa35dfa2f5cc 100644
--- a/arch/arm64/Kconfig
+++ b/arch/arm64/Kconfig
@@ -232,6 +232,7 @@ config ARM64
 	select HAVE_HARDLOCKUP_DETECTOR_PERF if PERF_EVENTS && \
 		HW_PERF_EVENTS && HAVE_PERF_EVENTS_NMI
 	select HAVE_HW_BREAKPOINT if PERF_EVENTS
+	select HAVE_REINSTALL_HW_BREAKPOINT if PERF_EVENTS
 	select HAVE_IOREMAP_PROT
 	select HAVE_IRQ_TIME_ACCOUNTING
 	select HAVE_LIVEPATCH
diff --git a/arch/arm64/include/asm/hw_breakpoint.h b/arch/arm64/include/asm/hw_breakpoint.h
index bd81cf17744a..6c98bbbc6aa6 100644
--- a/arch/arm64/include/asm/hw_breakpoint.h
+++ b/arch/arm64/include/asm/hw_breakpoint.h
@@ -119,6 +119,7 @@ extern int hw_breakpoint_exceptions_notify(struct notifier_block *unused,
 					   unsigned long val, void *data);
 
 extern int arch_install_hw_breakpoint(struct perf_event *bp);
+extern int arch_reinstall_hw_breakpoint(struct perf_event *bp);
 extern void arch_uninstall_hw_breakpoint(struct perf_event *bp);
 extern void hw_breakpoint_pmu_read(struct perf_event *bp);
 extern int hw_breakpoint_slots(int type);
diff --git a/arch/arm64/kernel/hw_breakpoint.c b/arch/arm64/kernel/hw_breakpoint.c
index ab76b36dce82..bd7d23d7893d 100644
--- a/arch/arm64/kernel/hw_breakpoint.c
+++ b/arch/arm64/kernel/hw_breakpoint.c
@@ -292,6 +292,11 @@ int arch_install_hw_breakpoint(struct perf_event *bp)
 	return hw_breakpoint_control(bp, HW_BREAKPOINT_INSTALL);
 }
 
+int arch_reinstall_hw_breakpoint(struct perf_event *bp)
+{
+	return hw_breakpoint_control(bp, HW_BREAKPOINT_RESTORE);
+}
+
 void arch_uninstall_hw_breakpoint(struct perf_event *bp)
 {
 	hw_breakpoint_control(bp, HW_BREAKPOINT_UNINSTALL);
-- 
2.43.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251110163634.3686676-19-wangjinchao600%40gmail.com.
