Return-Path: <kasan-dev+bncBCCMH5WKTMGRBY5RVXCAMGQEY7EGECQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x137.google.com (mail-lf1-x137.google.com [IPv6:2a00:1450:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id A0D29B170A2
	for <lists+kasan-dev@lfdr.de>; Thu, 31 Jul 2025 13:52:05 +0200 (CEST)
Received: by mail-lf1-x137.google.com with SMTP id 2adb3069b0e04-55b87768966sf299094e87.1
        for <lists+kasan-dev@lfdr.de>; Thu, 31 Jul 2025 04:52:05 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1753962725; cv=pass;
        d=google.com; s=arc-20240605;
        b=c8Y1en6TIhjWlQVPvQnYO14GOfBbsUdugZqk/KkTUnVqjGNVKlTvlPBQXc6zq2hMKW
         UkVgLlOVxxDue6pPldudcexA1Rn0MzWAkLYkJhN3Vae3OZPXOi/HaC3SyaqHoeI1oMS6
         Stg5bYaxVCLyGCfhHpFzhYyCgultoGhvpUREnenrGJqOOKTwl0SDMuG6rrdkfDbZS/uq
         03jvGro5HjLfWnjxk2DfqYnX+qr9G83Br5CqF+ftK8PXkqtmbL9XyGC0Ta9bKkz46K+8
         D1tCxK6Mw/XEc8PFyGmk2/l/cIlk9urfS6nxT+IJECSaxfUy6uZEMBTaSVbhKw8kwSxy
         OQ5A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=Mv60N0/d8sVKmaGBJQLt4ikdBFeMdNUBeADiZA+EUlc=;
        fh=uqT9kkYV5fAQf1wWti/ZJ8zm+Fis1YLBCbrhcIrH/hc=;
        b=TORfs/e21ZRCp8E0tidm+2ZXycoGCMpIxfO5dYWop/GI3JZlyYIMFwgEDAE2QnxAsY
         K6DuQeDeHV7tGpKV3X4yzDCEScKZyKX6z+igphXyHJstXNAK46juWWLlrcbpsAZCuxqm
         xlMqts1CWYyJQ1iaauIXZJwqp8AvvXLuYSiiytngWzUKV0giGGu73Ia2r+I85mUaAaJi
         jk1hdVt3slB7vcYdvUeLGzjZAW9JR34WaOOsa/sJKTUTHR7TU2rWj8mPWT2RQBWPBi+8
         9pN/5uqLcH7o93jSxXvirX8/GHzPjZH+H6B0HNywtmW6G36XIhTFyao64giMUfMcAdaj
         oYPA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=CbZQPqNq;
       spf=pass (google.com: domain of 34filaaykcqsrwtop2rzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--glider.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=34FiLaAYKCQsrwtop2rzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1753962725; x=1754567525; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=Mv60N0/d8sVKmaGBJQLt4ikdBFeMdNUBeADiZA+EUlc=;
        b=T3FfMpjAlmOxnsU5N0AK40o8bd/LjlDOFoTrO/8SPbHW4ClOMbFtQAB4QFzumV5QfW
         uyzc7R6fQReAFeGctFV0XgZ9F6KxXdmjUYpdKHRX8AVyZZ9AIkbilhe9qPXCDuidnWs3
         w8Lj9+ZlyZIWXuVSPE6XrvMHE7JF21keSoONHjeJt42vCYPhZRn9lJ3cxIwzPu66aTIc
         s8TWcJEvqgY/2Q0WkR4TmVtYQTNkiASSFb7gOCegZne4eEwiRUlmI34+K92RRalNWVYK
         Joa7Up6mqsGgNkN2SrwzYz12buY3s/LyXq2Tokc+SXdp8CqsYqK4JLKegr5XPQkEuPEp
         WQXA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1753962725; x=1754567525;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Mv60N0/d8sVKmaGBJQLt4ikdBFeMdNUBeADiZA+EUlc=;
        b=ZfLWyTnLsMaQoFE1CpJctW1s3R1Bk361PVQtJUIfo3HL3siyovi0pK7i1mZVTuaca6
         hr3/FMnQOKND5viA1w/OVVDAfkzwGjnvIQVO6Oe+ngfXdVNcWNCCE7sFjmHa9EGz0oP3
         LqozUBd0TlPlS93RGNVmZi2vDJrbxSHFJ79J77BF225bBRptT4Zou+KU/JSuw7EctDX3
         61OL9MDL9E3lhFeBN/Js5NUQFepFIXvOQZ7v50GrBtDDSPP02SMArWRBbJN+yJAHDfgd
         s6SCW7AYjLWhdbiE9f7iciCchNAFeKgI4PYRFOcSCIfLflTs4HXVAs/YhXTt7JbhoqBX
         yPvg==
X-Forwarded-Encrypted: i=2; AJvYcCXGbjIP1x4+zVcjyObfN1whBgfCHSfcFno88zFWfHrgUiy2CgZGhKjNdNP5Nhajef+8j8RBrg==@lfdr.de
X-Gm-Message-State: AOJu0YwGEJZrVjTSSsLUo8V35eHlmK721I1mr06Op4eAWSj7P+U8n1sP
	jYkZHHHdrMHb93udPi2t6KwxNJTFEZtFj6zexcDYyAPAw+BTRGPTo2cC
X-Google-Smtp-Source: AGHT+IFe9vWUytl6a3YyZngajeNhJ8CLDhTCbnIbX+ZeHVKsCSfvDLHu4w7nUy3AhkToaTPDX1atsw==
X-Received: by 2002:a05:6512:3d0b:b0:55b:2242:a9d7 with SMTP id 2adb3069b0e04-55b7c030bbcmr2131633e87.21.1753962724151;
        Thu, 31 Jul 2025 04:52:04 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZen9OSZJNCJSg5UWVL/lf3/LL8C5qVK/O4l/NSlrm6SdQ==
Received: by 2002:ac2:499d:0:b0:55b:814a:851c with SMTP id 2adb3069b0e04-55b87835eafls143046e87.0.-pod-prod-03-eu;
 Thu, 31 Jul 2025 04:52:01 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVo3iLanypNxyVjC4m0QzCRA3KsjRZN+EBd8I0x8m4yroXei2cXEq5UCUnXCyzY4Rr3jeI1xrwL6Sc=@googlegroups.com
X-Received: by 2002:a05:6512:e92:b0:55b:594b:de9f with SMTP id 2adb3069b0e04-55b7c0264aemr2123289e87.13.1753962721128;
        Thu, 31 Jul 2025 04:52:01 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1753962721; cv=none;
        d=google.com; s=arc-20240605;
        b=gZvM7bH3xDq84JGjubPaSNOPDEsbBEb/zUzmcnlN69aKPuncD8ToerTS2+75R9/qFz
         TIboi5ICz3imEFfjwvtfHnCqQxdKirTZLtSUZVAUsZxiJkmLg2vYEHpikN7NxJIV/B+7
         AbF5IWlz5g3sFuDwBNr4pVUeFvO8Q64BZr9C8Mmoh+lFn3MpgilPeSX9tnlH2/BSVQ8o
         SuhYI6XVxBkaqZcuiaA78Jl8fJHP/10a9icYkEp/LarAu37H6Dzb3L+LsPycTCpw7tNe
         JGv4HuAe99XZ/c3ffDjuduj/FsGy+GPP8q77HIhHU1UFO67v2xeKWXUmEmpUN99SQq9b
         60YQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=PPuLl+jotf/eLqBsrdKJtiuGUESLMuKQyj/jfXbQ+ZY=;
        fh=IxIVRwnQ5DqKawKf4wSHMpaFTSscWEVTYhhM+UQTO9I=;
        b=hmSOAdTLg+ZbLZcYpTE67F5C3PAwsCc8E7bcG/9tGVyJq8+64G9JQbI722WbGNArKV
         GfDor5dq+wzUzG2r9EGSWtc1lb6MUB5+M6OooUFIGIbya9I5aQorRXh2z7UG6OB7r4ye
         ULBQ4sKFuJqeZAtYt26zm5sZneoW9VwcpbSEkJ0vfAnujbz+tp37RukWPGkCOeJkmNz3
         ltqEDjBFbHppvtysTjLRJRZGXuRYBXzk/fYmhQgU8gP/1gXb3Jdr4cxxUF5EHU89JFe9
         Kw2Q/5eduVaswdJMcy44ZFonwGvFpZzqaqIJuZb5GkhsG0MBCDTycDsypGqlwOiw766G
         0fQA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=CbZQPqNq;
       spf=pass (google.com: domain of 34filaaykcqsrwtop2rzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--glider.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=34FiLaAYKCQsrwtop2rzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x449.google.com (mail-wr1-x449.google.com. [2a00:1450:4864:20::449])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-55b887deca0si30423e87.2.2025.07.31.04.52.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 31 Jul 2025 04:52:01 -0700 (PDT)
Received-SPF: pass (google.com: domain of 34filaaykcqsrwtop2rzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--glider.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) client-ip=2a00:1450:4864:20::449;
Received: by mail-wr1-x449.google.com with SMTP id ffacd0b85a97d-3b7931d3d76so654663f8f.1
        for <kasan-dev@googlegroups.com>; Thu, 31 Jul 2025 04:52:01 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCV6igHWBBMogBQOhSPvGg2KdcWtFwQnzkhNYmrI5X9aCBSFFJdTyYt6dpz2+l67lJjP5ZAKwqZ7fB8=@googlegroups.com
X-Received: from wrbfx3.prod.google.com ([2002:a05:6000:2d03:b0:3b7:8216:2015])
 (user=glider job=prod-delivery.src-stubby-dispatcher) by 2002:a05:6000:2c04:b0:3a5:27ba:47c7
 with SMTP id ffacd0b85a97d-3b79500950cmr5811629f8f.48.1753962720502; Thu, 31
 Jul 2025 04:52:00 -0700 (PDT)
Date: Thu, 31 Jul 2025 13:51:35 +0200
In-Reply-To: <20250731115139.3035888-1-glider@google.com>
Mime-Version: 1.0
References: <20250731115139.3035888-1-glider@google.com>
X-Mailer: git-send-email 2.50.1.552.g942d659e1b-goog
Message-ID: <20250731115139.3035888-7-glider@google.com>
Subject: [PATCH v4 06/10] kcov: add trace and trace_size to struct kcov_state
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
To: glider@google.com
Cc: quic_jiangenj@quicinc.com, linux-kernel@vger.kernel.org, 
	kasan-dev@googlegroups.com, Dmitry Vyukov <dvyukov@google.com>, 
	Aleksandr Nogikh <nogikh@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, Borislav Petkov <bp@alien8.de>, 
	Dave Hansen <dave.hansen@linux.intel.com>, Ingo Molnar <mingo@redhat.com>, 
	Josh Poimboeuf <jpoimboe@kernel.org>, Marco Elver <elver@google.com>, 
	Peter Zijlstra <peterz@infradead.org>, Thomas Gleixner <tglx@linutronix.de>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=CbZQPqNq;       spf=pass
 (google.com: domain of 34filaaykcqsrwtop2rzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=34FiLaAYKCQsrwtop2rzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--glider.bounces.google.com;
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
No functional changes so far.

Signed-off-by: Alexander Potapenko <glider@google.com>
Reviewed-by: Dmitry Vyukov <dvyukov@google.com>

---
v4:
 - add Reviewed-by: Dmitry Vyukov

v3:
 - Fix a warning detected by the kernel test robot <lkp@intel.com>
 - Address comments by Dmitry Vyukov:
   - s/kcov/KCOV/
   - fix struct initialization style

v2:
 - Address comments by Dmitry Vyukov:
   - tweak commit description
 - Address comments by Marco Elver:
   - rename sanitizer_cov_write_subsequent() to kcov_append_to_buffer()
 - Update code to match the new description of struct kcov_state

Change-Id: I50b5589ef0e0b6726aa0579334093c648f76790a
---
 include/linux/kcov_types.h |  9 ++++++-
 kernel/kcov.c              | 48 +++++++++++++++++++++-----------------
 2 files changed, 35 insertions(+), 22 deletions(-)

diff --git a/include/linux/kcov_types.h b/include/linux/kcov_types.h
index 53b25b6f0addd..9d38a2020b099 100644
--- a/include/linux/kcov_types.h
+++ b/include/linux/kcov_types.h
@@ -7,9 +7,16 @@
 struct kcov_state {
 	/* Size of the area (in long's). */
 	unsigned int size;
+	/*
+	 * Pointer to user-provided memory used by KCOV. This memory may
+	 * contain multiple buffers.
+	 */
+	void *area;
 
+	/* Size of the trace (in long's). */
+	unsigned int trace_size;
 	/* Buffer for coverage collection, shared with the userspace. */
-	void *area;
+	unsigned long *trace;
 
 	/*
 	 * KCOV sequence number: incremented each time kcov is reenabled, used
diff --git a/kernel/kcov.c b/kernel/kcov.c
index 8154ac1c1622e..2005fc7f578ee 100644
--- a/kernel/kcov.c
+++ b/kernel/kcov.c
@@ -194,11 +194,11 @@ static notrace unsigned long canonicalize_ip(unsigned long ip)
 	return ip;
 }
 
-static notrace void kcov_append_to_buffer(unsigned long *area, int size,
+static notrace void kcov_append_to_buffer(unsigned long *trace, int size,
 					  unsigned long ip)
 {
 	/* The first 64-bit word is the number of subsequent PCs. */
-	unsigned long pos = READ_ONCE(area[0]) + 1;
+	unsigned long pos = READ_ONCE(trace[0]) + 1;
 
 	if (likely(pos < size)) {
 		/*
@@ -208,9 +208,9 @@ static notrace void kcov_append_to_buffer(unsigned long *area, int size,
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
 
@@ -224,8 +224,8 @@ void notrace __sanitizer_cov_trace_pc_guard(u32 *guard)
 	if (!check_kcov_mode(KCOV_MODE_TRACE_PC, current))
 		return;
 
-	kcov_append_to_buffer(current->kcov_state.area,
-			      current->kcov_state.size,
+	kcov_append_to_buffer(current->kcov_state.trace,
+			      current->kcov_state.trace_size,
 			      canonicalize_ip(_RET_IP_));
 }
 EXPORT_SYMBOL(__sanitizer_cov_trace_pc_guard);
@@ -241,8 +241,8 @@ void notrace __sanitizer_cov_trace_pc(void)
 	if (!check_kcov_mode(KCOV_MODE_TRACE_PC, current))
 		return;
 
-	kcov_append_to_buffer(current->kcov_state.area,
-			      current->kcov_state.size,
+	kcov_append_to_buffer(current->kcov_state.trace,
+			      current->kcov_state.trace_size,
 			      canonicalize_ip(_RET_IP_));
 }
 EXPORT_SYMBOL(__sanitizer_cov_trace_pc);
@@ -251,9 +251,9 @@ EXPORT_SYMBOL(__sanitizer_cov_trace_pc);
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
@@ -265,22 +265,22 @@ static void notrace write_comp_data(u64 type, u64 arg1, u64 arg2, u64 ip)
 	 * We write all comparison arguments and types as u64.
 	 * The buffer was allocated for t->kcov_state.size unsigned longs.
 	 */
-	area = (u64 *)t->kcov_state.area;
+	trace = (u64 *)t->kcov_state.trace;
 	max_pos = t->kcov_state.size * sizeof(unsigned long);
 
-	count = READ_ONCE(area[0]);
+	count = READ_ONCE(trace[0]);
 
 	/* Every record is KCOV_WORDS_PER_CMP 64-bit words. */
 	start_index = 1 + count * KCOV_WORDS_PER_CMP;
 	end_pos = (start_index + KCOV_WORDS_PER_CMP) * sizeof(u64);
 	if (likely(end_pos <= max_pos)) {
 		/* See comment in kcov_append_to_buffer(). */
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
 
@@ -381,11 +381,13 @@ static void kcov_start(struct task_struct *t, struct kcov *kcov,
 
 static void kcov_stop(struct task_struct *t)
 {
+	int saved_sequence = t->kcov_state.sequence;
+
 	WRITE_ONCE(t->kcov_mode, KCOV_MODE_DISABLED);
 	barrier();
 	t->kcov = NULL;
-	t->kcov_state.size = 0;
-	t->kcov_state.area = NULL;
+	t->kcov_state = (typeof(t->kcov_state)){};
+	t->kcov_state.sequence = saved_sequence;
 }
 
 static void kcov_task_reset(struct task_struct *t)
@@ -734,6 +736,8 @@ static long kcov_ioctl(struct file *filep, unsigned int cmd, unsigned long arg)
 		}
 		kcov->state.area = area;
 		kcov->state.size = size;
+		kcov->state.trace = area;
+		kcov->state.trace_size = size;
 		kcov->mode = KCOV_MODE_INIT;
 		spin_unlock_irqrestore(&kcov->lock, flags);
 		return 0;
@@ -925,10 +929,12 @@ void kcov_remote_start(u64 handle)
 		local_lock_irqsave(&kcov_percpu_data.lock, flags);
 	}
 
-	/* Reset coverage size. */
-	*(u64 *)area = 0;
 	state.area = area;
 	state.size = size;
+	state.trace = area;
+	state.trace_size = size;
+	/* Reset coverage size. */
+	state.trace[0] = 0;
 
 	if (in_serving_softirq()) {
 		kcov_remote_softirq_start(t);
-- 
2.50.1.552.g942d659e1b-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250731115139.3035888-7-glider%40google.com.
