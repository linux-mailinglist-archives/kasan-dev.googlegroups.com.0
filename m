Return-Path: <kasan-dev+bncBD53XBUFWQDBBB5KZDEAMGQE3GJBO6A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83f.google.com (mail-qt1-x83f.google.com [IPv6:2607:f8b0:4864:20::83f])
	by mail.lfdr.de (Postfix) with ESMTPS id D997DC48016
	for <lists+kasan-dev@lfdr.de>; Mon, 10 Nov 2025 17:38:32 +0100 (CET)
Received: by mail-qt1-x83f.google.com with SMTP id d75a77b69052e-4e89f4a502csf92647571cf.2
        for <lists+kasan-dev@lfdr.de>; Mon, 10 Nov 2025 08:38:32 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1762792711; cv=pass;
        d=google.com; s=arc-20240605;
        b=h+GeU835XA//rkm/NkjP/NCQFSARxQbufSTNvTrjqkj8IWXZ+ApzDrPWEJe3emSESd
         7kGEBDpUd8DWJPlg/oLkUJ7HnYbTEpLA7K2CdSScnCiJzseDu0U7ak6Laaaw1AB13qCG
         0RFoa89vx7vbD70GOocGqufSgM8TZpYHrHQcs6Dtq2dL8Zn9xQILuqkgxYkaG0XCAcCp
         P/s26q/tR/+3eJTPSXQlAk9+xUjnEEM5Po56mtpXYMqhGp3E1TgUCjRW1FNEQ6jQijoQ
         13RqNbDqrEIGo0LBJIKu0ESFLs4t2//F56K3wuEI6YgF2Tz1wL2vyeaWvLOfG8KAcj5p
         fq4A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:to:from:sender:dkim-signature
         :dkim-signature;
        bh=cXyu20fZcJ/zp6IWnEJGyZnsb8WFIz3lI5hzkIauaHY=;
        fh=9y1U2dNqP1qpnQ5oKA6iV927PxD9q3aSlIWZbydNWb8=;
        b=fmpb2bJ0HmwgQfeQpEp0jVAxew9etUg+vfmnNYQDokoWBn7N/G9xMAH6GBO2CwP4cT
         ExnG/q/kSIiUlCeq/qvFaCWQlu9zBCaURDqC/kbcdcL7ijR/t6mGHoGbDtu3oeztBjWb
         6wBXBr04s9DIL2sXTXZSOKeI3ykCVOShp8mcIdImprcB8M1yndHVPPYcLo6ciHF7SsM4
         rb996xEGqeIxKpDwikMVE/Rs4akXLifC395NgfKjRcRDo7yPouCqHanutJVQbD9PhHdH
         XYIUebvs2DzzY+wdxK73pj61RAsAVTGUgwmkIIy8V2zyNwS4BUNdqaloM7GSe3iAzeG+
         yMqA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=N8hJhsbW;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::62e as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1762792711; x=1763397511; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=cXyu20fZcJ/zp6IWnEJGyZnsb8WFIz3lI5hzkIauaHY=;
        b=kVvRbQDnDDgKFz4JjFXNX4ga1Tb3KV4vOk/6M7pll8y9MbRNmL3klREvIK/g5FZ0iJ
         WPACYICjankqdkkMi2rEwylTjNFfwu5yLF2pK+ifGMRvxoduxpHKfoWrbXTqHxgjgerL
         5t0Ihpztv1Rgikb/5O2GKjkKP08ZdSovPIeZ4SXcpdzsd2jibpyec9NMz335iY0t/WY9
         +xihzC7GBA5EqtVW5YXWieoxxvIXarU160DYnIMaZIttEu64V2pJdgLhyDnhL3R16eV7
         m/hpDp5/xPBnlxjVJ4in8vW6Eh6k95ASfYy1ztibIffTXBxEFqeQh1VGuXEzIzu/Jfqy
         RBVg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1762792711; x=1763397511; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=cXyu20fZcJ/zp6IWnEJGyZnsb8WFIz3lI5hzkIauaHY=;
        b=kt9iHMmJZUjrr6f06xyVeIC6G5ZXanSzQ6tzD3DDxJ6SR5BQAJww/38lGXFSBcF3AL
         wPhucg8Vf2WKTjWbiQ4ELLcjEKcxk6wkGaddDepu76sa3T0CbWJbVnccXeSy1iIyA4+q
         UOToKTfu2qiKmksgzoRiP7ALThHJI/dkvckbEOjcN0psAYc8x+xGK0OERM2PtRbZqpC0
         5bUnsWRAlIevVhrGDcxFGVBXbGTX2k6DxGYUpnFuoS00wBmRm2RvFxfYXeUn4M5i30ok
         Vh104utQ0biozECDXzDqWRSuKNTd8kLWrPTt0MvCugtX7CbtL/fgGVIJCJxwgWlL+3Ja
         9b+w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1762792711; x=1763397511;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:to:from:x-gm-gg
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=cXyu20fZcJ/zp6IWnEJGyZnsb8WFIz3lI5hzkIauaHY=;
        b=Svq5k8dTuRi/cYvvc8QJJ1yyl246tvgRi1pLE7It5RtTO6/yPR1T5DnerEQ5WlePiz
         ZetPiP6v2Xw+qEARtWE3Bpv8uXhQcEkUpiTIeNNgqTnfgkFZ90MYaSECTurm4HvUvwSk
         PKGTSj/Wl/XerT31Rw1i7mNQtizicGKpALvD8ftiKE4ddExDXnFFLGnh/hYkL6hGjclp
         dJspAGVe+5CpK4R27LWQIMy88ZDbL6M7s7z/fGuY8ta5dUkCd/4qpebRENUX6zN3w5j5
         NAPQsJ1JdkLRh+2HknI9Xzz7MnX8bcDhRr4GOg9EhEhlC3Vp+LI3HsEA8NmGdyB5xGL9
         hv5Q==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCX/+5PQpNxgHKdRv7aW7DyMZL/FyflKy/zFSQFBQOfMI2iZuGAtxwPMgc6eDnYKulJEHRXFHg==@lfdr.de
X-Gm-Message-State: AOJu0YwKfBEbJ0KCwPzhOeGnrloJJ4LrZLF2LFOACOm5wX4VuqEWL8RZ
	1V9GeZz9xDjqFk+Pk7eXmxRLJ5UZPfub9ufavuSPtZ06vQE1zeor1FTs
X-Google-Smtp-Source: AGHT+IGH5Nfrcaqpt81xx2daxAsJMwROq621We10VVCH5TmMjEl4PvMoIQMxAdkxl1qqsH+b+A6OKw==
X-Received: by 2002:a05:622a:354:b0:4eb:a1a1:7c0b with SMTP id d75a77b69052e-4eda4ffbe62mr116479531cf.78.1762792711402;
        Mon, 10 Nov 2025 08:38:31 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+ZBe+gpA70CyieyImyC8m0k0uBwe/Swsjoj09s6oT9QFg=="
Received: by 2002:a05:6214:b6a:b0:880:803b:bd47 with SMTP id
 6a1803df08f44-8823ace2414ls45479666d6.1.-pod-prod-05-us; Mon, 10 Nov 2025
 08:38:30 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUMNknGFhGcBUa9T9AAFBcFuesNILm6dtEttK4dYh+qMwd2UX06Jv/+vrC3mvSAM/nWJJgturRoEPk=@googlegroups.com
X-Received: by 2002:a05:6214:628:b0:880:5193:10fb with SMTP id 6a1803df08f44-882386eba88mr112657926d6.54.1762792710515;
        Mon, 10 Nov 2025 08:38:30 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1762792710; cv=none;
        d=google.com; s=arc-20240605;
        b=L99vqNIZlyCl1cgMY9GLOiyMt5NzPWNUrbDDPXGxsLl+vohZc83+2ZG/yfv+VMO5oF
         OkgRJX8yB3pnaE6N2i8zIuSTVZCIC4s1R5O0a5sZtG7E9q+HItXNIYOoU8SGG10VzFGo
         2VgQtEvaT7Ss6HkD3zCZR99xF0ftgzXM925i2fwkoImlVCEDAG13i79ApB1u/l8v+oYl
         76vjxN+/9PiWaAdGiaHjuwECEAjScS2jt6+dSl8PoU7cXQ3EyRWf3q2FVGVphOTH3+G0
         UrpHVpgVzCh/Gn6e84yU8AsR1TVAGryKpHV6CJ6p6eRDg0Th7fRSZvRJlsQ6YFdP0Mza
         V0wA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:to:from:dkim-signature;
        bh=/i9Y6D84AcwkcQizXylWnD304yGUpX7AGwmA82BxIzc=;
        fh=adp7g/Cxqo68itWnmJoKez1EiP7rsHYO6fWI/B+43Bs=;
        b=AMr9iCnyzro178z67n6jJc2u79S6V2r6ysTpiPILO/F/LuT87fPbYbRT7iX3u4Ny5k
         P2uEadUrY4BQgrlGukg3AhQxnbvGlqz3hyzJqCUdyyJQLuHWoN6NPBWL3dkGkOzc3UtI
         CBAUNJ1bVtuGPUD7Dbhgq0jUxHF4LbPGIr1zKI8q85Z8NjSjCfuaGgv+QadDNAGhoq9c
         8qZJr+5yNY3de2OMoTN8EKsxln+G13j/ieq3nShDCHdwIh3+l+iHKGymSrxw193z46O5
         d3lh/hkz9zOo7K8mLPogAWfzA++zmf3PofV+q5w8o5IKKWXOUdikemQnyHbRXSnCeuX/
         XsYQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=N8hJhsbW;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::62e as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pl1-x62e.google.com (mail-pl1-x62e.google.com. [2607:f8b0:4864:20::62e])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-88238a16a32si5285386d6.4.2025.11.10.08.38.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 10 Nov 2025 08:38:30 -0800 (PST)
Received-SPF: pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::62e as permitted sender) client-ip=2607:f8b0:4864:20::62e;
Received: by mail-pl1-x62e.google.com with SMTP id d9443c01a7336-297d4a56f97so23190295ad.1
        for <kasan-dev@googlegroups.com>; Mon, 10 Nov 2025 08:38:30 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCUC64dzs399EVxTzPl5b8Ix7mBC13ovPaGBt/fvAZVDnvTzCyrGhFXaRHLWBFuH/OT3urFwg2360r8=@googlegroups.com
X-Gm-Gg: ASbGnctFKdRy4577vPP8IrDqbqm3vUYXxuxKHsXhkObxeXdpoGhuniDpVCVhm+KLoVD
	hKlC2lUGvusxWPYmRhvC04ur9ylhYXTTq2Eh3v2Acf7PlG4bimjMhhKr5SKQ3fNqSYtADLgJg44
	jNjxNI5K+GJLcZGht0IG0Ut8Eo5OpHetPgF+Bwa4g2IdKg+kIjDBWTNHNALUPetIGAd5+T7+Dbc
	ggGO9DYulhxur4N+e5I4nDBrt0oNRgaj0s/7qZ6Zx/UGT4/cdKiPsq57eYtItZYyuEwSE1M4E/2
	TT3FIR47zf0R6W7Zb+E2U27Rxofw0S1nEyul4etkynOhXfVp6mAWNh8Sr0C5DnZUbeyvufgWVes
	n8bnWhlgXG197ufq4qJ8FuMxopNi6lCBDZ2dcypjJyZUuu37O/JF3ZJJKbZPGGH8URBCf0tKKHs
	FcLaGnEkV7+L57l3t0Xazb7w==
X-Received: by 2002:a17:902:da4b:b0:295:512f:5060 with SMTP id d9443c01a7336-297e540dc24mr116769525ad.7.1762792709436;
        Mon, 10 Nov 2025 08:38:29 -0800 (PST)
Received: from localhost ([103.88.46.62])
        by smtp.gmail.com with ESMTPSA id d9443c01a7336-29651ccec04sm151070875ad.102.2025.11.10.08.38.28
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 10 Nov 2025 08:38:28 -0800 (PST)
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
Subject: [PATCH v8 24/27] mm/ksw: add multi-thread corruption test cases
Date: Tue, 11 Nov 2025 00:36:19 +0800
Message-ID: <20251110163634.3686676-25-wangjinchao600@gmail.com>
X-Mailer: git-send-email 2.43.0
In-Reply-To: <20251110163634.3686676-1-wangjinchao600@gmail.com>
References: <20251110163634.3686676-1-wangjinchao600@gmail.com>
MIME-Version: 1.0
X-Original-Sender: wangjinchao600@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=N8hJhsbW;       spf=pass
 (google.com: domain of wangjinchao600@gmail.com designates
 2607:f8b0:4864:20::62e as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
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

These tests share a common structure and are grouped together.

- buggy():
  exposes the stack address to corrupting(); may omit waiting
- corrupting():
  reads the exposed pointer and modifies memory;
  if buggy() omits waiting, victim()'s buffer is corrupted
- victim():
  initializes a local buffer and later verifies it;
  reports an error if the buffer was unexpectedly modified

buggy() and victim() run in worker() thread, with similar stack frame sizes
to simplify testing. By adjusting fence_size in corrupting(), the test can
trigger either silent corruption or overflow across threads.

- Test 3: one worker, 20 loops, silent corruption
- Test 4: 20 workers, one loop each, silent corruption
- Test 5: one worker, one loop, overflow corruption

Test 4 also exercises multiple watchpoint instances.

Signed-off-by: Jinchao Wang <wangjinchao600@gmail.com>

mm/ksw: add KSTACKWATCH_PROFILING to measure probe cost

Introduce CONFIG_KSTACKWATCH_PROFILING to enable optional runtime
profiling in KStackWatch. When enabled, it records entry and exit
probe latencies (in nanoseconds and CPU cycles) and reports averaged
statistics at module exit.

Signed-off-by: Jinchao Wang <wangjinchao600@gmail.com>
---
 mm/kstackwatch/test.c | 186 +++++++++++++++++++++++++++++++++++++++++-
 1 file changed, 185 insertions(+), 1 deletion(-)

diff --git a/mm/kstackwatch/test.c b/mm/kstackwatch/test.c
index 1d196f72faba..4bd0e5026fd9 100644
--- a/mm/kstackwatch/test.c
+++ b/mm/kstackwatch/test.c
@@ -19,6 +19,20 @@ static struct dentry *test_file;
 #define BUFFER_SIZE 32
 #define MAX_DEPTH 6
 
+struct work_node {
+	ulong *ptr;
+	u64 start_ns;
+	struct completion done;
+	struct list_head list;
+};
+
+static DECLARE_COMPLETION(work_res);
+static DEFINE_MUTEX(work_mutex);
+static LIST_HEAD(work_list);
+
+static int global_fence_size;
+static int global_loop_count;
+
 static void test_watch_fire(void)
 {
 	u64 buffer[BUFFER_SIZE] = { 0 };
@@ -64,6 +78,164 @@ static void test_recursive_depth(int depth)
 	pr_info("exit of %s depth:%d\n", __func__, depth);
 }
 
+static struct work_node *test_mthread_buggy(int thread_id, int seq_id)
+{
+	ulong buf[BUFFER_SIZE];
+	struct work_node *node;
+	bool trigger;
+
+	node = kmalloc(sizeof(*node), GFP_KERNEL);
+	if (!node)
+		return NULL;
+
+	init_completion(&node->done);
+	node->ptr = buf;
+	node->start_ns = ktime_get_ns();
+	mutex_lock(&work_mutex);
+	list_add(&node->list, &work_list);
+	mutex_unlock(&work_mutex);
+	complete(&work_res);
+
+	trigger = (get_random_u32() % 100) < 10;
+	if (trigger)
+		return node; /* let the caller handle cleanup */
+
+	wait_for_completion(&node->done);
+	kfree(node);
+	return NULL;
+}
+
+#define CORRUPTING_MINIOR_WAIT_NS (100000)
+#define VICTIM_MINIOR_WAIT_NS (300000)
+
+static inline void silent_wait_us(u64 start_ns, u64 min_wait_us)
+{
+	u64 diff_ns, remain_us;
+
+	diff_ns = ktime_get_ns() - start_ns;
+	if (diff_ns < min_wait_us * 1000ULL) {
+		remain_us = min_wait_us - (diff_ns >> 10);
+		usleep_range(remain_us, remain_us + 200);
+	}
+}
+
+static void test_mthread_victim(int thread_id, int seq_id, u64 start_ns)
+{
+	ulong buf[BUFFER_SIZE];
+
+	for (int j = 0; j < BUFFER_SIZE; j++)
+		buf[j] = 0xdeadbeef + seq_id;
+	if (start_ns)
+		silent_wait_us(start_ns, VICTIM_MINIOR_WAIT_NS);
+
+	for (int j = 0; j < BUFFER_SIZE; j++) {
+		if (buf[j] != (0xdeadbeef + seq_id)) {
+			pr_warn("victim[%d][%d]: unhappy buf[%d]=0x%lx\n",
+				thread_id, seq_id, j, buf[j]);
+			return;
+		}
+	}
+
+	pr_info("victim[%d][%d]: happy\n", thread_id, seq_id);
+}
+
+static int test_mthread_corrupting(void *data)
+{
+	struct work_node *node;
+	int fence_size;
+
+	while (!kthread_should_stop()) {
+		if (!wait_for_completion_timeout(&work_res, HZ))
+			continue;
+		while (true) {
+			mutex_lock(&work_mutex);
+			node = list_first_entry_or_null(&work_list,
+							struct work_node, list);
+			if (node)
+				list_del(&node->list);
+			mutex_unlock(&work_mutex);
+
+			if (!node)
+				break; /* no more nodes, exit inner loop */
+			silent_wait_us(node->start_ns,
+				       CORRUPTING_MINIOR_WAIT_NS);
+
+			fence_size = READ_ONCE(global_fence_size);
+			for (int i = fence_size; i < BUFFER_SIZE - fence_size;
+			     i++)
+				node->ptr[i] = 0xabcdabcd;
+
+			complete(&node->done);
+		}
+	}
+
+	return 0;
+}
+
+static int test_mthread_worker(void *data)
+{
+	int thread_id = (long)data;
+	int loop_count;
+	struct work_node *node;
+
+	loop_count = READ_ONCE(global_loop_count);
+
+	for (int i = 0; i < loop_count; i++) {
+		node = test_mthread_buggy(thread_id, i);
+
+		if (node)
+			test_mthread_victim(thread_id, i, node->start_ns);
+		else
+			test_mthread_victim(thread_id, i, 0);
+		if (node) {
+			wait_for_completion(&node->done);
+			kfree(node);
+		}
+	}
+	return 0;
+}
+
+static void test_mthread_case(int num_workers, int loop_count, int fence_size)
+{
+	static struct task_struct *corrupting;
+	static struct task_struct **workers;
+
+	WRITE_ONCE(global_loop_count, loop_count);
+	WRITE_ONCE(global_fence_size, fence_size);
+
+	init_completion(&work_res);
+	workers = kmalloc_array(num_workers, sizeof(void *), GFP_KERNEL);
+	memset(workers, 0, sizeof(struct task_struct *) * num_workers);
+
+	corrupting = kthread_run(test_mthread_corrupting, NULL, "corrupting");
+	if (IS_ERR(corrupting)) {
+		pr_err("failed to create corrupting thread\n");
+		return;
+	}
+
+	for (ulong i = 0; i < num_workers; i++) {
+		workers[i] = kthread_run(test_mthread_worker, (void *)i,
+					 "worker_%ld", i);
+		if (IS_ERR(workers[i])) {
+			pr_err("failto create worker thread %ld", i);
+			workers[i] = NULL;
+		}
+	}
+
+	for (ulong i = 0; i < num_workers; i++) {
+		if (workers[i] && workers[i]->__state != TASK_DEAD) {
+			usleep_range(1000, 2000);
+			i--;
+		}
+	}
+	kfree(workers);
+
+	if (corrupting && !IS_ERR(corrupting)) {
+		kthread_stop(corrupting);
+		corrupting = NULL;
+	}
+}
+
 static ssize_t test_dbgfs_write(struct file *file, const char __user *buffer,
 				size_t count, loff_t *pos)
 {
@@ -92,6 +264,15 @@ static ssize_t test_dbgfs_write(struct file *file, const char __user *buffer,
 		case 2:
 			test_recursive_depth(0);
 			break;
+		case 3:
+			test_mthread_case(1, 20, BUFFER_SIZE / 4);
+			break;
+		case 4:
+			test_mthread_case(200, 1, BUFFER_SIZE / 4);
+			break;
+		case 5:
+			test_mthread_case(1, 1, -3);
+			break;
 		default:
 			pr_err("Unknown test number %d\n", test_num);
 			return -EINVAL;
@@ -114,7 +295,10 @@ static ssize_t test_dbgfs_read(struct file *file, char __user *buffer,
 		"echo test{i} > /sys/kernel/debug/kstackwatch/test\n"
 		" test0 - test watch fire\n"
 		" test1 - test canary overflow\n"
-		" test2 - test recursive func\n";
+		" test2 - test recursive func\n"
+		" test3 - test silent corruption\n"
+		" test4 - test multiple silent corruption\n"
+		" test5 - test prologue corruption\n";
 
 	return simple_read_from_buffer(buffer, count, ppos, usage,
 				       strlen(usage));
-- 
2.43.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251110163634.3686676-25-wangjinchao600%40gmail.com.
