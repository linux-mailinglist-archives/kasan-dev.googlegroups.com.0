Return-Path: <kasan-dev+bncBD53XBUFWQDBBKPER7DAMGQETMSI2HQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x640.google.com (mail-pl1-x640.google.com [IPv6:2607:f8b0:4864:20::640])
	by mail.lfdr.de (Postfix) with ESMTPS id B8C60B548EE
	for <lists+kasan-dev@lfdr.de>; Fri, 12 Sep 2025 12:13:10 +0200 (CEST)
Received: by mail-pl1-x640.google.com with SMTP id d9443c01a7336-25c1dba8d26sf26482475ad.1
        for <lists+kasan-dev@lfdr.de>; Fri, 12 Sep 2025 03:13:10 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757671978; cv=pass;
        d=google.com; s=arc-20240605;
        b=kBN6de1ME3VS1A5oNzBezrpNfWOoOOF52PMqTMM92VK8Z3YO8VzlLVnwe/NLsRpXH0
         z9WRAHfKY+n2awvrwE7bw4oS1fb+rAzCST2rSJSBRVM+sFcSoVFaUiuiM/x6K4tYLsw5
         PKRyAQfpllUsa7e5ZhZs7ALkckSYpOvgPVRBro30KFYn1e4IKZcr5GcS4f+iJFg7kKwS
         /mw8W9LIu/PvWl7B6O7hoUamAfnJuOAUg2BH4KIsH6oZ7RPPJsGj2H7mWH/YJ3lecMXZ
         z1CIzLJ0KXzNa/C36W5cp91LGRsZqZPKAnOgXEgjanpnh/h0Srw3J7Dx8b/vCBR3Fg2w
         y2MQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=nVtsvQGiT9z2CHqhCCCXGJ0MyDIuuNR5Fx6Yy6jqPjQ=;
        fh=reT2pNsi0a89rZ+JqXuXB2573jqKp+7NqpcoUX1l2F4=;
        b=dfLP7Nr38ZJ9QBxOVPQux5EbqG+oILAcqRwKF15jhlL6FtYFkYwrm1BQ6nkzDkHNne
         Z3rxIt/ZZEyS6Cve6rsfHWF7sv0e5/wuL9finbW1atgY/dj66lHxmur0nR3BmR+TM9W+
         YomAqGtUBVKub1EZOXpW/m5+GAXWFsTFAiA9mxfePon6AK6hhAuZLFxwU8bG0p3pmVe5
         7t/C5J/ub4fCFs3+D9bvL+FP+IL5Mm/pnT+MJ8CTRFESS1Db+EcZsg8H92Xr/OAJTazm
         PhMt6BrGlLI/LsW++BBX0LZDRZ8svNB9aSPwlMkcDCT8msANZymGrxdvO/J3X6RD+jEC
         V5UQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=mKFm+j20;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::633 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757671978; x=1758276778; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=nVtsvQGiT9z2CHqhCCCXGJ0MyDIuuNR5Fx6Yy6jqPjQ=;
        b=Q6tDqL/BwYipiN6zVv4AjuCE0iMkWQ1Y9JjfmXNnXlqLPmjphRWqUSy4g6g6lJ+KDr
         PIJuo461iVBbi8JPuqGgxXw1Avz0WM5jagZ+oYvQssjxKbNzxVVkvB3wpoTEaFcnMxev
         +pGoJPZoN0WWQfXojMg1uE3kpYjpb3tzoriLdTORfzruBj9lHrrkDbc2Z5mZOtDdI+cV
         fnNckC7Uj2pHtLlr9r/Hwy80ThoAvAIckvV5SBrrWYWrv3RtMn5uAy67H8J2o7Lv9+w9
         dR3XZqkmq2jdeW2poK5uAgZYhboqwsHUefu1vr8PF+r5o+2PPrWqyMLqVVv/S/6xp6UJ
         Tn4Q==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1757671978; x=1758276778; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=nVtsvQGiT9z2CHqhCCCXGJ0MyDIuuNR5Fx6Yy6jqPjQ=;
        b=gzvypoVe9Rv/62mJ7QVcgsDYDYmCMZQlhqIM0/gUSuobp87B6xdHpKD4WbgltUbGdP
         YVDFEH7PugLtHwr9O4k31DV6Tzj3Qai0OqD7MYMU7Yc/SsHnSOBiCm6x+MAEvndrj0Yt
         ibQrhSIiYNXjLMxop/GCg88p0N0OtZTTWo6jTQeCxVUclNQAjRVGD4csP4NqxTL/dA7T
         LApGmnhZ/driLejM/A+TW8b8WPyw/UyCSlvCOoUHFfR9hX9QeiKOfm5jsN3DdLwEQDZn
         fIm2Eu+hpe8QPmuQ4ePw5Ms7TQJxO+s+AbwnIlCCE7gVFF7HGDIkK455Sv9pEPcP6RLf
         jpfg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757671978; x=1758276778;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=nVtsvQGiT9z2CHqhCCCXGJ0MyDIuuNR5Fx6Yy6jqPjQ=;
        b=GyHGK/U2o2X7Iba/RoP1GbANssmIaCCZoemkBTfuSiJji3oiJXj0d0Y0bk7Mv7GkDS
         QC0H8C6GCP0dGxVXHOxrwn4jH3qG7ZTGXtlgekRgJ/zACsoicIigEoz37LcAQqjdT1Ax
         e+9z/zLNWA9kXzJ9of1ukaa6mSr4kqc739FD12hx+6PVNF69ykFb7sYhuEZIas1yXmtH
         q4+cA2d6PidDIi1MBUtQlPfKPSc13lk/MhkZnvBP1T0q3YiJwZcCJuJ7iYG6yDHjLoEX
         JSPihMy6ViTNbtD/bUiuc3m3b8JIxRsVMsxISX+eDXCSZ7M3/7qfg/Gc+xBlt4ImCWVs
         82Ag==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVYzc0pvKheYyXlw/T35i+vLnm9+GkBb9agSS+uOLQyfq3Bp1UpE6XcX1D/Lu2Pygy1JA9wuQ==@lfdr.de
X-Gm-Message-State: AOJu0Yzuk5PMlMLD4zsp8ga1+9oTCZNpTlgcrHb2CdyYE6cNoa9EAXIS
	+cyDGN0ke0J/95icKVIoRYJTwHv6QrMDxsPhSNSdqQIVZCuoFoJrxk6v
X-Google-Smtp-Source: AGHT+IFd10tWwk+dUGQUVBjCoVlzebeBjdseaKWgdcxrbDpwg4/Hwo1UVknOW7ha65fGZgKDpCDurQ==
X-Received: by 2002:a17:903:943:b0:24a:9475:3db2 with SMTP id d9443c01a7336-25d26e4384fmr26909045ad.35.1757671978529;
        Fri, 12 Sep 2025 03:12:58 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd5ZfR/VUCyD3Ckj771/7Dvza9x1KtroRHFY/5GkIFOu6w==
Received: by 2002:a17:902:f790:b0:24b:63d:52b0 with SMTP id
 d9443c01a7336-25beca65274ls18950795ad.2.-pod-prod-01-us; Fri, 12 Sep 2025
 03:12:57 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCURYpwm3uxw4ynX5o7Rl8pDHYOUk+ZIUGp/wYBK6LK31EjezqGGvtfDUW+be9/aWPfY9573x1Ix6Wk=@googlegroups.com
X-Received: by 2002:a17:902:ef07:b0:248:79d4:93ba with SMTP id d9443c01a7336-25d26e43ee3mr28168835ad.39.1757671976911;
        Fri, 12 Sep 2025 03:12:56 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1757671976; cv=none;
        d=google.com; s=arc-20240605;
        b=HeMOgO8Y1w7iTboYGedoiQxCJFmpxHVBAJi6lTuXayBD3MyajQPLk9ww+0qaMOohoh
         p+XIJGQQvBAZtkmniIr23OFQ4qU11r+SyfCjAImGjDHPzmr7weEstufshf5S2LShRjhW
         TA8m95iR8K5+z/eaVASspnxlv2QUe8uJBr1Nk58j1cujSOwldzzX/fb0zdK4TOdr8JHB
         jEudtc36V+elrnJIPdw8sYBfDEAY0IX+Rg6AqJwCOuP4HaJKqbBFkuuxa+oS3prDFF65
         MqIfmcQzyxY5TSg4Yja7DGaJcca4oQoL5V1MIKMC2OImnz/42T4tPkcruETp9qLxKUxC
         HwPw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=mwBrRJrnxCqu1u7UrV9e609up8TstQr3mGzjgxeQ/fA=;
        fh=9ERpbi/sYhpFmQoE+4bDEUbZQiRQqJD+/KZoEn6WIzc=;
        b=f7NJy9p+PLi7ZnbkuO5XpoVkWiANXySD+YSYrXPYADxxis/Q3nsur2k5HfSR0p5XzU
         g5myCG9xcVE57RLxmNC8BBuIDIrkR82GwQFNJ1h0iQGKmZCqpisqx9OL+Uf5rpWbT19p
         bO3r2jzRCFo6Jzk0Nf2lJS8gm+s9eKck1G8/cIYa/BQI3mfGBK+cgS+WA64GvvqHQZ6d
         W7I4/9fpb5juFZK/g16gVFbzCH5mppTP7Xh4uCxstceLQeefD8BctRX2os+0el68n1jn
         veXfOQhLcuLKLvmp+etCp7flMdqukzWKw11xK68Nrs/fz1ceFkWvnEzDvOE2LyEBo64p
         bKZg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=mKFm+j20;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::633 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pl1-x633.google.com (mail-pl1-x633.google.com. [2607:f8b0:4864:20::633])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-25c370a502fsi1661515ad.2.2025.09.12.03.12.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 12 Sep 2025 03:12:56 -0700 (PDT)
Received-SPF: pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::633 as permitted sender) client-ip=2607:f8b0:4864:20::633;
Received: by mail-pl1-x633.google.com with SMTP id d9443c01a7336-24cb39fbd90so15148435ad.3
        for <kasan-dev@googlegroups.com>; Fri, 12 Sep 2025 03:12:56 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVl+10oJGbLbjd6EVGVXGZM7/XjLbADGo9hLWBdQFAXC/6Vpqs6SFw3kpLVuPH6/v2JGH1639nkXGs=@googlegroups.com
X-Gm-Gg: ASbGnctph7wHm/aDE/srWcOcUTHxySV0+j8KLtpP84OT+hDb8+u8Ji9y6qtyvKn1D4z
	JunqZC8m7Fn/aawSqWeSUQb4YOUfuDQgEEHnTWRF7Z7I0+fcea+u2Zn6e7y6dqdORVIWKYM3d36
	g4wVZ9QVdMbf9OFVqh9CXqxRU5r5C9qx5H4zk5KevTGBOMabD6HWHabc/CFtnWkgd8PtgbuBWdQ
	u2IozArahYV2z8X2ghwl8Cime3D27oNUDSDf+tRC+FwP24+ov1oydu8vmBo01n6+m3AJlK+dEnO
	5mLhfzh2awSxLL73m2jybbkrsrrFCOWvS69zgMGtVyyShcpUyMGD5s6RvJxu7Pce2xkmuI4WqLb
	nb1w8z8nT4MPER5/sBekDktjS17fT0BznuL2UMnc=
X-Received: by 2002:a17:903:2f0d:b0:248:79d4:93bb with SMTP id d9443c01a7336-25d26e449b9mr26345655ad.31.1757671976359;
        Fri, 12 Sep 2025 03:12:56 -0700 (PDT)
Received: from localhost ([185.49.34.62])
        by smtp.gmail.com with ESMTPSA id d9443c01a7336-25c36cc6af7sm44843015ad.5.2025.09.12.03.12.54
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 12 Sep 2025 03:12:55 -0700 (PDT)
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
Subject: [PATCH v4 12/21] mm/ksw: resolve stack watch addr and len
Date: Fri, 12 Sep 2025 18:11:22 +0800
Message-ID: <20250912101145.465708-13-wangjinchao600@gmail.com>
X-Mailer: git-send-email 2.43.0
In-Reply-To: <20250912101145.465708-1-wangjinchao600@gmail.com>
References: <20250912101145.465708-1-wangjinchao600@gmail.com>
MIME-Version: 1.0
X-Original-Sender: wangjinchao600@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=mKFm+j20;       spf=pass
 (google.com: domain of wangjinchao600@gmail.com designates
 2607:f8b0:4864:20::633 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
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

Add helpers to find the stack canary or a local variable addr and len
for the probed function based on ksw_get_config(). For canary search,
limits search to a fixed number of steps to avoid scanning the entire
stack. Validates that the computed address and length are within the
kernel stack.

Signed-off-by: Jinchao Wang <wangjinchao600@gmail.com>
---
 mm/kstackwatch/stack.c | 88 ++++++++++++++++++++++++++++++++++++++++--
 1 file changed, 84 insertions(+), 4 deletions(-)

diff --git a/mm/kstackwatch/stack.c b/mm/kstackwatch/stack.c
index ac52a9f81486..65a97309e028 100644
--- a/mm/kstackwatch/stack.c
+++ b/mm/kstackwatch/stack.c
@@ -9,18 +9,98 @@
 
 #include "kstackwatch.h"
 
+#define INVALID_PID -1
+#define MAX_CANARY_SEARCH_STEPS 128
 static struct kprobe entry_probe;
 static struct fprobe exit_probe;
-#define INVALID_PID -1
 static atomic_t ksw_stack_pid = ATOMIC_INIT(INVALID_PID);
 
+static unsigned long ksw_find_stack_canary_addr(struct pt_regs *regs)
+{
+	unsigned long *stack_ptr, *stack_end, *stack_base;
+	unsigned long expected_canary;
+	unsigned int i;
+
+	stack_ptr = (unsigned long *)kernel_stack_pointer(regs);
+
+	stack_base = (unsigned long *)(current->stack);
+
+	// TODO: limit it to the current frame
+	stack_end = (unsigned long *)((char *)current->stack + THREAD_SIZE);
+
+	expected_canary = current->stack_canary;
+
+	if (stack_ptr < stack_base || stack_ptr >= stack_end) {
+		pr_err("Stack pointer 0x%lx out of bounds [0x%lx, 0x%lx)\n",
+		       (unsigned long)stack_ptr, (unsigned long)stack_base,
+		       (unsigned long)stack_end);
+		return 0;
+	}
+
+	for (i = 0; i < MAX_CANARY_SEARCH_STEPS; i++) {
+		if (&stack_ptr[i] >= stack_end)
+			break;
+
+		if (stack_ptr[i] == expected_canary) {
+			pr_debug("canary found i:%d 0x%lx\n", i,
+				 (unsigned long)&stack_ptr[i]);
+			return (unsigned long)&stack_ptr[i];
+		}
+	}
+
+	pr_debug("canary not found in first %d steps\n",
+		 MAX_CANARY_SEARCH_STEPS);
+	return 0;
+}
+
+static int ksw_stack_validate_addr(unsigned long addr, size_t size)
+{
+	unsigned long stack_start, stack_end;
+
+	if (!addr || !size)
+		return -EINVAL;
+
+	stack_start = (unsigned long)current->stack;
+	stack_end = stack_start + THREAD_SIZE;
+
+	if (addr < stack_start || (addr + size) > stack_end)
+		return -ERANGE;
+
+	return 0;
+}
+
 static int ksw_stack_prepare_watch(struct pt_regs *regs,
 				   const struct ksw_config *config,
 				   ulong *watch_addr, u16 *watch_len)
 {
-	/* implement logic will be added in following patches */
-	*watch_addr = 0;
-	*watch_len = 0;
+	ulong addr;
+	u16 len;
+
+	/* Resolve addresses for all active watches */
+	switch (ksw_get_config()->type) {
+	case WATCH_CANARY:
+		addr = ksw_find_stack_canary_addr(regs);
+		len = sizeof(unsigned long);
+		break;
+
+	case WATCH_LOCAL_VAR:
+		addr = kernel_stack_pointer(regs) +
+		       ksw_get_config()->local_var_offset;
+		len = ksw_get_config()->local_var_len;
+		break;
+
+	default:
+		pr_err("Unknown watch type %d\n", ksw_get_config()->type);
+		return -EINVAL;
+	}
+
+	if (ksw_stack_validate_addr(addr, len)) {
+		pr_err("invalid stack addr:0x%lx len :%u\n", addr, len);
+		return -EINVAL;
+	}
+
+	*watch_addr = addr;
+	*watch_len = len;
 	return 0;
 }
 
-- 
2.43.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250912101145.465708-13-wangjinchao600%40gmail.com.
