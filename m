Return-Path: <kasan-dev+bncBCCMH5WKTMGRB3XA7W7QMGQEQDQTLOQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43e.google.com (mail-wr1-x43e.google.com [IPv6:2a00:1450:4864:20::43e])
	by mail.lfdr.de (Postfix) with ESMTPS id 8DDB3A8B475
	for <lists+kasan-dev@lfdr.de>; Wed, 16 Apr 2025 10:55:14 +0200 (CEST)
Received: by mail-wr1-x43e.google.com with SMTP id ffacd0b85a97d-39141ffa913sf3737292f8f.2
        for <lists+kasan-dev@lfdr.de>; Wed, 16 Apr 2025 01:55:14 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1744793714; cv=pass;
        d=google.com; s=arc-20240605;
        b=jMhqyT2GCWikbYKx4zo+YTt2b19uqAV/+4CCpP9mJFs4GliTvtUUNiMRoVy2v6jz34
         mT+wuJYCZsmRgelj1493lZIPNtE7d9e0cZYQWxDTNB+7Mugn6jpVdad1L782i8SprdUX
         UAKOTvrodTF7myZryQJjZIN6irS/YUktgHG0qmsjUI2/Mr/J1xXuGli0e729iYjtnTYD
         lYMYw2dwUthpzHvKfkFtIP/CAalkWCoVsPd5tqMJSyF80J3VL5JEqqlVxuPUkYofEulS
         xaWJ2mKj2ciFlKkN8ZjQ0yQ3HMxXMo3foGBazViUHxiGgZTR1yuG7iTisM5rFTNMf6Gg
         uUFg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=DQJnXnzpDCNy1fWVQ6IT4Lhgi+P2cci1Xj+bCiemfjs=;
        fh=Kc5+NZO6hmivRm3jvY7df7m2Lj3FaX95f0m8K5HSPII=;
        b=Q/0NeXcq5WUe+WPyTe15IiRnLppFWr2mwy3LYiFr9a+joFpP4WKw1vrcqL2wsTi24U
         PE2REQ8b/t1tamWMRh0ITIPDrCTY5cSTFHdgazVs0N4Q/VbdkDwAVD7lZhPmUp8oUnfK
         X1thAHK818lOGRBmvZLgLiS7nTTn2XgxVILuU4d4P11kvbUEMTGAT8jJO9hEFuMp4vie
         lfqFVKwt74zQbAcKhsagsoFeE44C91obyNXRkk9Obt36fvPacASw1XrqhQ1VbRZAnal8
         JKK7p81dSB3GSy9YEinTOBffrdTtufcj4ZK0ezyO/RkWhkB4qizYxa4Mq6GzCjjml44F
         lTxQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=HNitlUQb;
       spf=pass (google.com: domain of 3a3d_zwykcza052xyb08805y.w864ucu7-xyf08805y0b8e9c.w86@flex--glider.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=3a3D_ZwYKCZA052xyB08805y.w864uCu7-xyF08805y0B8E9C.w86@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1744793714; x=1745398514; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=DQJnXnzpDCNy1fWVQ6IT4Lhgi+P2cci1Xj+bCiemfjs=;
        b=PYkZ1MDWAw9o+GK2tPonwgCbmj9AgBUigXi9PGrhcVCZVUxVtrdHDnZuSNN3CCILJK
         fZQiWtl5vmWsJNoUrpUpRXxYnoJl5nWtX0nyjKS+r+q++nfcwbyyJkBwf4b7wMmOiUSn
         z1vNaM6pWhgcp6vxJ3ee8FeoLWVj6IR2/OzrzvMYb9TLzhHkBeVTEQgFJQKfFW8V3u4F
         qZy4ghwFz6xBXdm9mZ+LrAsu/X4x+mE6XEm1qOKqXuqG16h1DwfqgL1uaGEbQpAd9VXw
         saVU2zBc9xCGI9lisVQ6fLW6amJi/AKgGjFZlfeFmNnIuivLQs6+Y4ZPCNhjRRw3i7C8
         UXgg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1744793714; x=1745398514;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=DQJnXnzpDCNy1fWVQ6IT4Lhgi+P2cci1Xj+bCiemfjs=;
        b=PDs41uyaNbyOeNxcqtiAdkGrAu0uIq1UHX2M7KPjYY9LgHYjO84o+5L/10jjby158L
         AiZOHcyxaL2eTUe2tLUrLkYAom/J0NT470/k+8YdrvicDb5Q4YWmuNsPLRAvW5E7zZXz
         /Oiu2G+rzV1zdZkCtf+u0/pP8OarG9eH7KNUyaXUT1td0mdKx5enldQdk7SRVKyBu2UW
         6ZQJLPC23tKLvEl+a2xPhAuXuZUZUAdHdWeQmt+nSGGqsXu5LBhYpAEYpIcKeBLEIHfu
         kC2xV8+KICG0FSIrCjF2B36emPjN/9ld9zi0O6kA4GQL9FzngK4koqOattpkdZrey1Mn
         NjHg==
X-Forwarded-Encrypted: i=2; AJvYcCXai/uRlAl+nj1xBmQtpYeEAGcX24t0Q0yX5yrBOWfG1mmEzqHBqZjUD8tvYAWv6IrvycbhLA==@lfdr.de
X-Gm-Message-State: AOJu0Yyy5dB9c12SMvOIi0HT0WbD0Xr8NkZZLGlxtkCypNk0k28DqkU/
	c+JGowsFTDBmve8AvDEY7X2dws2oKJfL601p0l5y7F2OKqiq7BH3
X-Google-Smtp-Source: AGHT+IFXWIGE7IY2QuiBgxMbm+6uRnD1211F+8/vt77ubfCIMcFr8VtZW6wP0DLBIJwHb2nRiBn3CA==
X-Received: by 2002:a05:6000:248a:b0:39c:1ef5:ff8b with SMTP id ffacd0b85a97d-39ee5baf3c9mr813106f8f.48.1744793713003;
        Wed, 16 Apr 2025 01:55:13 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARLLPAKD+fAK+0B1HHMITMm+wMm7VCyWNlVio97de5vkrxdPGQ==
Received: by 2002:a05:6000:2282:b0:39c:1401:6e85 with SMTP id
 ffacd0b85a97d-39d8df196bdls3262021f8f.0.-pod-prod-07-eu; Wed, 16 Apr 2025
 01:55:08 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCW9xv96hywUunDdNmXJus82iisQWi+qTblaa9pMbDunGb2UlkCx7wbqUtkStI+JCRDaev5D0ph1BPc=@googlegroups.com
X-Received: by 2002:a05:6000:4021:b0:39c:223f:2770 with SMTP id ffacd0b85a97d-39ee5b18646mr956449f8f.15.1744793708176;
        Wed, 16 Apr 2025 01:55:08 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1744793708; cv=none;
        d=google.com; s=arc-20240605;
        b=i/6ZV3I1K5su/k7qS3ZqrWTe5NwJzQF0ADJgwjr3CmtMg/eZn6Rr3C2dMBRIe9Oe5x
         DdbiYaFAamLgBIlQ7aI08bugBxncbjWswwEH4DesXyurOqCIyeahnqaACbdaGqbGQZfL
         tsE0B6pM1SclZE2UtZKOMYD32CzAUFsv368LPt7AeS/z4iAIm15Q/cYpNQuceWvBHJWf
         EEgbIAbi5wiU3WMzI0INca3C4tnQ1HtrR3I22KvfaA56wJB5NJbT3LGKLzaXTZFSUpKf
         7dOz6ukOOKoex7koeIo7N/CinVcskmdbzqBfOwwZlqxXi/vuz9ETpdg+fH6SfISAm2VZ
         WSkA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=D7PaNu9SLcaDW6rJLrXYufwflTdOL8oZuD382JbLKOQ=;
        fh=pgnpAZFuzTwEqZbhcPaR6mIprFbaTFNXmTMhGd5IK1s=;
        b=jXcve/JHLPWMlbkZ0+FpSvczb26lKdtJDZtRQAHKO4qnbsXacY1vw4yBLZ4JGfl0oO
         8dLkU5UFILgyj64eWksyA2p3Qg0pZb68Uz03jvPTXjbDqOIKnAHcKobLIReREVZA16zW
         RhEXk8TjhPtFyYxSe8j8gFlERKFV9ehdAVgXdELvOc67IR60t7jZi5PX01/C0VJAtL00
         MwRvEgB5GpozVE2UiiMuEAOBvRbs4yOyYUWSEw0MiqwsB1EAfm+W+sSb/KTZnG0HamNy
         xsCP/Ek58KWEuiTZn+zjyYN9N/9db+x2FdcDwq10PKHHxKrKq14brw2nOzB68i/IRIAF
         rCdw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=HNitlUQb;
       spf=pass (google.com: domain of 3a3d_zwykcza052xyb08805y.w864ucu7-xyf08805y0b8e9c.w86@flex--glider.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=3a3D_ZwYKCZA052xyB08805y.w864uCu7-xyF08805y0B8E9C.w86@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-ej1-x649.google.com (mail-ej1-x649.google.com. [2a00:1450:4864:20::649])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-44034fd82dfsi1693865e9.0.2025.04.16.01.55.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 16 Apr 2025 01:55:08 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3a3d_zwykcza052xyb08805y.w864ucu7-xyf08805y0b8e9c.w86@flex--glider.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) client-ip=2a00:1450:4864:20::649;
Received: by mail-ej1-x649.google.com with SMTP id a640c23a62f3a-ac6ebab17d8so653205666b.1
        for <kasan-dev@googlegroups.com>; Wed, 16 Apr 2025 01:55:08 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVsTwyphitURI7PykgmioE+9Sp8ST36Wj6oxhkTg5VBtzc6umQ85em5bbLfYqQwwmrtvO/XdDDkMgo=@googlegroups.com
X-Received: from ejbgq18.prod.google.com ([2002:a17:906:e252:b0:ac2:8b71:dd54])
 (user=glider job=prod-delivery.src-stubby-dispatcher) by 2002:a17:907:748:b0:ac1:e53c:d13f
 with SMTP id a640c23a62f3a-acb42c13a70mr69983766b.50.1744793707726; Wed, 16
 Apr 2025 01:55:07 -0700 (PDT)
Date: Wed, 16 Apr 2025 10:54:42 +0200
In-Reply-To: <20250416085446.480069-1-glider@google.com>
Mime-Version: 1.0
References: <20250416085446.480069-1-glider@google.com>
X-Mailer: git-send-email 2.49.0.604.gff1f9ca942-goog
Message-ID: <20250416085446.480069-5-glider@google.com>
Subject: [PATCH 4/7] kcov: add `trace` and `trace_size` to `struct kcov_state`
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
To: glider@google.com
Cc: quic_jiangenj@quicinc.com, linux-kernel@vger.kernel.org, 
	kasan-dev@googlegroups.com, Aleksandr Nogikh <nogikh@google.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Borislav Petkov <bp@alien8.de>, 
	Dave Hansen <dave.hansen@linux.intel.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Ingo Molnar <mingo@redhat.com>, Josh Poimboeuf <jpoimboe@kernel.org>, Marco Elver <elver@google.com>, 
	Peter Zijlstra <peterz@infradead.org>, Thomas Gleixner <tglx@linutronix.de>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=HNitlUQb;       spf=pass
 (google.com: domain of 3a3d_zwykcza052xyb08805y.w864ucu7-xyf08805y0b8e9c.w86@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=3a3D_ZwYKCZA052xyB08805y.w864uCu7-xyF08805y0B8E9C.w86@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

Keep kcov_state.area as the pointer to the memory buffer used by
kcov and shared with the userspace. Store the pointer to the trace
(part of the buffer holding sequential events) separately, as we will
be splitting that buffer in multiple parts.
No functional change so far.

Signed-off-by: Alexander Potapenko <glider@google.com>
---
 include/linux/kcov-state.h |  9 ++++++-
 kernel/kcov.c              | 54 ++++++++++++++++++++++----------------
 2 files changed, 39 insertions(+), 24 deletions(-)

diff --git a/include/linux/kcov-state.h b/include/linux/kcov-state.h
index 4c4688d01c616..6e576173fd442 100644
--- a/include/linux/kcov-state.h
+++ b/include/linux/kcov-state.h
@@ -15,9 +15,16 @@ struct kcov_state {
 	struct {
 		/* Size of the area (in long's). */
 		unsigned int size;
+		/*
+		 * Pointer to user-provided memory used by kcov. This memory may
+		 * contain multiple buffers.
+		 */
+		void *area;
 
+		/* Size of the trace (in long's). */
+		unsigned int trace_size;
 		/* Buffer for coverage collection, shared with the userspace. */
-		void *area;
+		unsigned long *trace;
 
 		/*
 		 * KCOV sequence number: incremented each time kcov is
diff --git a/kernel/kcov.c b/kernel/kcov.c
index b97f429d17436..7b726fd761c1b 100644
--- a/kernel/kcov.c
+++ b/kernel/kcov.c
@@ -193,11 +193,11 @@ static notrace unsigned long canonicalize_ip(unsigned long ip)
 	return ip;
 }
 
-static void sanitizer_cov_write_subsequent(unsigned long *area, int size,
+static void sanitizer_cov_write_subsequent(unsigned long *trace, int size,
 					   unsigned long ip)
 {
 	/* The first 64-bit word is the number of subsequent PCs. */
-	unsigned long pos = READ_ONCE(area[0]) + 1;
+	unsigned long pos = READ_ONCE(trace[0]) + 1;
 
 	if (likely(pos < size)) {
 		/*
@@ -207,9 +207,9 @@ static void sanitizer_cov_write_subsequent(unsigned long *area, int size,
 		 * overitten by the recursive __sanitizer_cov_trace_pc().
 		 * Update pos before writing pc to avoid such interleaving.
 		 */
-		WRITE_ONCE(area[0], pos);
+		WRITE_ONCE(trace[0], pos);
 		barrier();
-		area[pos] = ip;
+		trace[pos] = ip;
 	}
 }
 
@@ -223,8 +223,8 @@ void notrace __sanitizer_cov_trace_pc(void)
 	if (!check_kcov_mode(KCOV_MODE_TRACE_PC, current))
 		return;
 
-	sanitizer_cov_write_subsequent(current->kcov_state.s.area,
-				       current->kcov_state.s.size,
+	sanitizer_cov_write_subsequent(current->kcov_state.s.trace,
+				       current->kcov_state.s.trace_size,
 				       canonicalize_ip(_RET_IP_));
 }
 EXPORT_SYMBOL(__sanitizer_cov_trace_pc);
@@ -234,8 +234,8 @@ void notrace __sanitizer_cov_trace_pc_guard(u32 *guard)
 	if (!check_kcov_mode(KCOV_MODE_TRACE_PC, current))
 		return;
 
-	sanitizer_cov_write_subsequent(current->kcov_state.s.area,
-				       current->kcov_state.s.size,
+	sanitizer_cov_write_subsequent(current->kcov_state.s.trace,
+				       current->kcov_state.s.trace_size,
 				       canonicalize_ip(_RET_IP_));
 }
 EXPORT_SYMBOL(__sanitizer_cov_trace_pc_guard);
@@ -250,9 +250,9 @@ EXPORT_SYMBOL(__sanitizer_cov_trace_pc_guard_init);
 #ifdef CONFIG_KCOV_ENABLE_COMPARISONS
 static void notrace write_comp_data(u64 type, u64 arg1, u64 arg2, u64 ip)
 {
-	struct task_struct *t;
-	u64 *area;
 	u64 count, start_index, end_pos, max_pos;
+	struct task_struct *t;
+	u64 *trace;
 
 	t = current;
 	if (!check_kcov_mode(KCOV_MODE_TRACE_CMP, t))
@@ -264,22 +264,22 @@ static void notrace write_comp_data(u64 type, u64 arg1, u64 arg2, u64 ip)
 	 * We write all comparison arguments and types as u64.
 	 * The buffer was allocated for t->kcov_state.size unsigned longs.
 	 */
-	area = (u64 *)t->kcov_state.s.area;
+	trace = (u64 *)t->kcov_state.s.trace;
 	max_pos = t->kcov_state.s.size * sizeof(unsigned long);
 
-	count = READ_ONCE(area[0]);
+	count = READ_ONCE(trace[0]);
 
 	/* Every record is KCOV_WORDS_PER_CMP 64-bit words. */
 	start_index = 1 + count * KCOV_WORDS_PER_CMP;
 	end_pos = (start_index + KCOV_WORDS_PER_CMP) * sizeof(u64);
 	if (likely(end_pos <= max_pos)) {
 		/* See comment in sanitizer_cov_write_subsequent(). */
-		WRITE_ONCE(area[0], count + 1);
+		WRITE_ONCE(trace[0], count + 1);
 		barrier();
-		area[start_index] = type;
-		area[start_index + 1] = arg1;
-		area[start_index + 2] = arg2;
-		area[start_index + 3] = ip;
+		trace[start_index] = type;
+		trace[start_index + 1] = arg1;
+		trace[start_index + 2] = arg2;
+		trace[start_index + 3] = ip;
 	}
 }
 
@@ -380,11 +380,13 @@ static void kcov_start(struct task_struct *t, struct kcov *kcov,
 
 static void kcov_stop(struct task_struct *t)
 {
+	int saved_sequence = t->kcov_state.s.sequence;
+
 	WRITE_ONCE(t->kcov_state.mode, KCOV_MODE_DISABLED);
 	barrier();
 	t->kcov = NULL;
-	t->kcov_state.s.size = 0;
-	t->kcov_state.s.area = NULL;
+	t->kcov_state.s = (typeof(t->kcov_state.s)){ 0 };
+	t->kcov_state.s.sequence = saved_sequence;
 }
 
 static void kcov_task_reset(struct task_struct *t)
@@ -733,6 +735,8 @@ static long kcov_ioctl(struct file *filep, unsigned int cmd, unsigned long arg)
 		}
 		kcov->state.s.area = area;
 		kcov->state.s.size = size;
+		kcov->state.s.trace = area;
+		kcov->state.s.trace_size = size;
 		kcov->state.mode = KCOV_MODE_INIT;
 		spin_unlock_irqrestore(&kcov->lock, flags);
 		return 0;
@@ -924,10 +928,12 @@ void kcov_remote_start(u64 handle)
 		local_lock_irqsave(&kcov_percpu_data.lock, flags);
 	}
 
-	/* Reset coverage size. */
-	*(u64 *)area = 0;
 	state.s.area = area;
 	state.s.size = size;
+	state.s.trace = area;
+	state.s.trace_size = size;
+	/* Reset coverage size. */
+	state.s.trace[0] = 0;
 
 	if (in_serving_softirq()) {
 		kcov_remote_softirq_start(t);
@@ -1000,8 +1006,8 @@ void kcov_remote_stop(void)
 	struct task_struct *t = current;
 	struct kcov *kcov;
 	unsigned int mode;
-	void *area;
-	unsigned int size;
+	void *area, *trace;
+	unsigned int size, trace_size;
 	int sequence;
 	unsigned long flags;
 
@@ -1033,6 +1039,8 @@ void kcov_remote_stop(void)
 	kcov = t->kcov;
 	area = t->kcov_state.s.area;
 	size = t->kcov_state.s.size;
+	trace = t->kcov_state.s.trace;
+	trace_size = t->kcov_state.s.trace_size;
 	sequence = t->kcov_state.s.sequence;
 
 	kcov_stop(t);
-- 
2.49.0.604.gff1f9ca942-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250416085446.480069-5-glider%40google.com.
