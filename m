Return-Path: <kasan-dev+bncBD53XBUFWQDBBWFJZDEAMGQEHVMMKXY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf37.google.com (mail-qv1-xf37.google.com [IPv6:2607:f8b0:4864:20::f37])
	by mail.lfdr.de (Postfix) with ESMTPS id 4E096C47FE0
	for <lists+kasan-dev@lfdr.de>; Mon, 10 Nov 2025 17:37:46 +0100 (CET)
Received: by mail-qv1-xf37.google.com with SMTP id 6a1803df08f44-88236bcdfc4sf69064266d6.1
        for <lists+kasan-dev@lfdr.de>; Mon, 10 Nov 2025 08:37:46 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1762792665; cv=pass;
        d=google.com; s=arc-20240605;
        b=f36zi+NJ/KFvULYS7xC1xpFMVOhYzsepdi6PjFBvEzbiVGWtFZCfT57Y83C8O/0SCn
         fWc0Twup+jZQxw3yfki5wxckZSqaqKScLesmNK4eLjW0TVG9yZdLdeBW2fITrdKTrjvr
         Ah01glMFF6jtpXaf/WFuRQ5lVg0jmVq7TLih8ru9hQ/YH+et0omUOmfrDUq2kpxgOTNc
         vKsSLIQLEidh4ezXB/t407D1BD+50wVdyAkgQNV0g6S50Fdjr6QJR4RtD+scw/nr9QpL
         KmyFM6DyHgAW1S+KsB04HdaNW0ACqBBxi9QkHR3ypTTbTvmINHDzTTMUwgzaPnT9z1NH
         cWaw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:to:from:sender:dkim-signature
         :dkim-signature;
        bh=wf7jEVWLj3ZjQ5xGK/qQBo0R8ntXVfU9TI5zniZPJSw=;
        fh=sQxN9x5UfhqnbqKxJ5WC9GF07UHTmvdhaVf8AIbYqg8=;
        b=lgRSbeCo00Fs56E6nWs8RWJdAgLuGX798mkJ2hyvpOpro1pXZ0Od8PX0EtEwWBpBFJ
         rtQExOt+1zwYCs5y8nzudgNMv6DZfAAQujN7RcgmXGabfxvgpsD/JkfQgHU7W9GTu41Y
         B3RC4sVlB29GtY7Rda9cW20DXgTYapaXQm9YFbxJzg7bh4oN9o/V63zvreT8PdJ8x+pH
         ro0u22V8y/AL4rXh98UWk063083MbPhQXonSFGSSMLaRD9u82cs1TPBqUNmnNItoJiNx
         fxuxG1a9LruzZHX74gjEEHscuvocKhzcLyVC8WtDFhF26lXq4VzdIX/dKEUdL6wTKsNP
         dMNA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=OMUBnimK;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::42e as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1762792665; x=1763397465; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=wf7jEVWLj3ZjQ5xGK/qQBo0R8ntXVfU9TI5zniZPJSw=;
        b=pUY9CqfoxSZgZLBMOkitsmyTSjffCOr6wpWzh1zpBMY/Avuwm9hvXUg1xO9737Qkax
         QOPy1sJBvDLbLMwhllRQGjSPSlFt5V1uLzhOf+iwNH+07w2ewlzahCyOyNRraUCzk7VV
         NJqiQ9502/s6I+yw+wL8vY2Dnmec9Y0z3ApPT7g64DwLFqoBM2KvKymJwukZ3uLxp0S8
         R1fX5uytjBpV2aqWHRZX4kcr4R+q/WJzfZtsMVn0HReX7PcHLqh52SGJfOabyrNXb2KA
         m4y56jRQAtpNhGdx+cDXaMGtn6IyDQZ8s1KzF9a+041zR8m56hzoiK0ll0UW9IJtowBH
         vZdw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1762792665; x=1763397465; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=wf7jEVWLj3ZjQ5xGK/qQBo0R8ntXVfU9TI5zniZPJSw=;
        b=FIgAJfuzyOKUrkX/6fMTZAdROh4xQ9HhYbTKBZPQJXmmEQbGCkynN9XqT21MuejgC1
         SXgaCj7lAcN4YvA4Fu73bBA+/BFb766boxvp6Ss0pGIIqu4XFCiE4MXPXHECFknWT2qo
         g1+FpTLcSh7O8tFQi4pkikqo/Ih5u/45MYl0yfY8WR/wR+zJ/7+jOB7wCDn54QTOrZUF
         qfy6HsdXN77sOw7eSwIT+X7+ZqiiwD6Cl4ZnXwzDlfruWEytTONba9ZpEWzAHzSZeOj2
         CR42bgaGxi7fA2tVi5ej0V7fUrb5AXeo5eKQDddNUkiD/0MShbj/NX70Py5xihyr+say
         vzMA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1762792665; x=1763397465;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:to:from:x-gm-gg
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=wf7jEVWLj3ZjQ5xGK/qQBo0R8ntXVfU9TI5zniZPJSw=;
        b=PSa3Erwbv3HauqrqPdpoxc9YQPzioQ6ohBoQ+NP4fq5nLv40dduLA4iZkhm3YGl9do
         cpazfgFVtA4D+T6dLT9erEG8r1mTwbSFqsm8W/RppDAnbgwzit+o5tOD7HTCAgWE4MXS
         1tPdQPfTnawzYe4GABVqV4J+ALufW/WdQVgG2fzDdcjQuvRlfVDP2dTJkfJcqBLVULWg
         P6jxARSl1chMn7aUknrhMhpGNgKx8FnG7esXdcS8n2wXiucmhwOroM9bDWm4WX3Czud7
         MIDFHONofMwk+V4nuzfhvfEH0o+gLdumG0gR1N0rfN7mqM7yvtEe6Xx2ahvMOn7eBooJ
         W6gQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXmldKKx1VTaINp7/2VfMiTPVT1rBj3E5X7VZrb/k40drbr1Ygyt27516Yiapa4WaIhpnt9Xw==@lfdr.de
X-Gm-Message-State: AOJu0YxTEAkbFhi0d4lJCOEBEHGKKd3Ya8kUfwcgpeNoBW4KiRhotMZc
	QrjbVvs0yPBf9PBQgotoKTc5cJD2f7gPOgYDQcf1ut4z4Bsn8ZCCs/cC
X-Google-Smtp-Source: AGHT+IHHYUIrXTiUkivEM7bq5V+qT0XlmIA3EwLAexRLra8dp3wk0FA1QFJgnCVW3ivZuNI1bBz0uw==
X-Received: by 2002:a05:6214:c82:b0:880:486d:18dc with SMTP id 6a1803df08f44-88238701ff7mr113016446d6.58.1762792665175;
        Mon, 10 Nov 2025 08:37:45 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+Z56U46Wc5Z2fbSAnwYYL56nrq+wi5zO8x1TrGDRaeipA=="
Received: by 2002:a05:6214:242b:b0:880:4116:d4f5 with SMTP id
 6a1803df08f44-88242ae313dls47671006d6.2.-pod-prod-07-us; Mon, 10 Nov 2025
 08:37:44 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWKS00GW1a8yedOghDk/gUng0UdqNg5FpD3FsFWQpxvwI7chla+uI6UvYrB3vTO+QOcW6XbbjdCGJU=@googlegroups.com
X-Received: by 2002:a0c:f08c:0:b0:882:437d:282d with SMTP id 6a1803df08f44-882437d2e2fmr76268376d6.30.1762792664364;
        Mon, 10 Nov 2025 08:37:44 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1762792664; cv=none;
        d=google.com; s=arc-20240605;
        b=Ghy2gULvg7WqsC3BjVsbOkq2vqaiayojeraRWr/NLz9tVxMGj4ljC86r4IXvHFIgDa
         YL7mu1W5eG5mkIkGTTgRm9F98MDjbp8DiBnMP5X8KMRMOtZHHIme7+fQQlIr3x6w0jO/
         tGNGqJzATnz98Lgzqd8DxVB9sNIr/cX9Z1nObtRa1CkxsfPHLs63ZgbqClZMcXo33ihF
         Reqd08bA9BoDQLg3pgjir618c/xX98XymmX84M/9c+unAxT3URdtrNUXQHAENsIiWFdu
         K24AqV3q6JtesyMj4k16AK5dSdRqdYwqz9I6Y/rDI5nLztY3dre1a8Dq6DST3b/MmRH2
         MXxQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:to:from:dkim-signature;
        bh=rUIy2ZawuG8l7hvlTJp6NnNoOG+7tynb2rchqUDRw1k=;
        fh=RksRyP+kM5pdg3BoTggcwJfFA1jDtcL0tUABZ/2Mf6g=;
        b=ixcHpGU0gPSRzKRoJFq0mcQQWO1Y7/7ZH4Aogv4WfSNPedpEWKnyO2+L1T6MWvUdT9
         UtUcZ0Xs5mfWSjjbI1Db5AgdLYOyd8nTf5Yu5xElfprjnO3iTFVvTCHQZhQSdzZqMITq
         HgT5XALix/+4rIkdEZDv1aYaXtd8DcQ8KWt2uVgw4X7/z92ndEew/w503XdnrubPp+mJ
         8v97TQb6G9Uv+Glh8PcmszJ4JHRhPIL9+71ibv6x0aBeDk2BPIE2XP7Hp9pQurvYhaY7
         fgPPaDJWHZs6bdhHkX/7BBTbwy0mZ7kfzQbhwyg/vQwx26ythw9+TtXmSyDRqrtLyEnU
         h3XQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=OMUBnimK;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::42e as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pf1-x42e.google.com (mail-pf1-x42e.google.com. [2607:f8b0:4864:20::42e])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-8823881122asi5341156d6.0.2025.11.10.08.37.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 10 Nov 2025 08:37:44 -0800 (PST)
Received-SPF: pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::42e as permitted sender) client-ip=2607:f8b0:4864:20::42e;
Received: by mail-pf1-x42e.google.com with SMTP id d2e1a72fcca58-7ad1cd0db3bso2413539b3a.1
        for <kasan-dev@googlegroups.com>; Mon, 10 Nov 2025 08:37:44 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCW/WU3v2e70Eu9Be27o24rIdggsBZ5vZ7WacVgJ6f3Lc+jwq7ihtIDvOaH4RKnXnxGuHYCG2fTmNBU=@googlegroups.com
X-Gm-Gg: ASbGncum+HDq4WTLOJHnAHjgqzVVTcPH/ltlCoJjBUVS+/BiF2uC8fcirZS4T8BEpzz
	d++oebvNK/yioX2+2bO3lZkot6f5PhGhSZ6kPN5NK+jnNxpsX/gX9jKXyuS0U2WKhMtsoIqIFBM
	kQw7LprsKj98EiqQvg8uVssy4UNtORzd5nvbkPhp3Ful8zH8BPDogmobS/beRP4lJ9Zj3rK1Ka7
	egVzUT9WrGvrcX/ZAOmP+oU32TQ1xJe8ifT5V4EmYPf+nz8mZLV6f6NKhjC84woGWjRErKhy40Z
	3S7WkRkOzO9T1gHKRQ2/7CSKy/8YU/bhIGcSUeXPsViZ2x9DOeA7IfvcJjW0meibhFmc7XvsJPr
	ge6neFv6s9rF4NR+segrvM9tKRBEXkje4I6W5MZduCPb0yU+FZPkqqEauEUuD90hv++1L9lQBUE
	jGaOHjMMBZURs=
X-Received: by 2002:a05:6a00:b81:b0:7a9:e786:bdaf with SMTP id d2e1a72fcca58-7b225c9b43amr11411331b3a.14.1762792663661;
        Mon, 10 Nov 2025 08:37:43 -0800 (PST)
Received: from localhost ([103.88.46.62])
        by smtp.gmail.com with ESMTPSA id d2e1a72fcca58-7b0c9635007sm12550190b3a.2.2025.11.10.08.37.42
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 10 Nov 2025 08:37:43 -0800 (PST)
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
Subject: [PATCH v8 14/27] mm/ksw: resolve stack watch addr and len
Date: Tue, 11 Nov 2025 00:36:09 +0800
Message-ID: <20251110163634.3686676-15-wangjinchao600@gmail.com>
X-Mailer: git-send-email 2.43.0
In-Reply-To: <20251110163634.3686676-1-wangjinchao600@gmail.com>
References: <20251110163634.3686676-1-wangjinchao600@gmail.com>
MIME-Version: 1.0
X-Original-Sender: wangjinchao600@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=OMUBnimK;       spf=pass
 (google.com: domain of wangjinchao600@gmail.com designates
 2607:f8b0:4864:20::42e as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
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
 mm/kstackwatch/stack.c | 80 ++++++++++++++++++++++++++++++++++++++++--
 1 file changed, 77 insertions(+), 3 deletions(-)

diff --git a/mm/kstackwatch/stack.c b/mm/kstackwatch/stack.c
index 96014eb4cb12..60371b292915 100644
--- a/mm/kstackwatch/stack.c
+++ b/mm/kstackwatch/stack.c
@@ -8,6 +8,7 @@
 #include <linux/kstackwatch_types.h>
 #include <linux/printk.h>
 
+#define MAX_CANARY_SEARCH_STEPS 128
 static struct kprobe entry_probe;
 static struct fprobe exit_probe;
 
@@ -58,13 +59,86 @@ static bool ksw_stack_check_ctx(bool entry)
 		return false;
 }
 
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
+	if (ksw_get_config()->auto_canary) {
+		addr = ksw_find_stack_canary_addr(regs);
+		if (!addr)
+			return -EINVAL;
+		len = sizeof(ulong);
+	} else {
+		addr = kernel_stack_pointer(regs) + ksw_get_config()->sp_offset;
+		len = ksw_get_config()->watch_len;
+		if (!len)
+			len = sizeof(ulong);
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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251110163634.3686676-15-wangjinchao600%40gmail.com.
