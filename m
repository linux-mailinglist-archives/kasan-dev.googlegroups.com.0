Return-Path: <kasan-dev+bncBCCMH5WKTMGRBF5NT3CAMGQEU3E7KXQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33b.google.com (mail-wm1-x33b.google.com [IPv6:2a00:1450:4864:20::33b])
	by mail.lfdr.de (Postfix) with ESMTPS id B8CEAB13E3D
	for <lists+kasan-dev@lfdr.de>; Mon, 28 Jul 2025 17:26:16 +0200 (CEST)
Received: by mail-wm1-x33b.google.com with SMTP id 5b1f17b1804b1-45867ac308dsf21956095e9.2
        for <lists+kasan-dev@lfdr.de>; Mon, 28 Jul 2025 08:26:16 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1753716376; cv=pass;
        d=google.com; s=arc-20240605;
        b=dEt6I7zY73w4CzF3mg/UgzYGD6+sJLKAzOvES5vXejrVur0PXFsAbT9edR3MnuIJiM
         BEcrW/DV9qHCzeXjQSSaXOqve3CZSG+MGl8119IqZa2w3ocYh0XUK/j8qqGCCr711O+9
         KN27mL3lsztCeF7rJhFNZYsDJ+f5cj4WO+kcWujWkygQVq63qLx/perWnNGf3zJNfBM3
         QIBW+3yjLg2Z9rMq/L+iNHa0lDLj8hQk0jd6wWL93kLFxKx5rtAvRIOIWDhpjmvECJZK
         TYTd8WkyQYWB88IxlSeCA4vAK6SiYIKK1LzkiJ5NtjiOmuTV/vJj8ItHj/kXZJ1IB05a
         r60w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=odIyxWreDQYCmYaUBnBH32awyWaWIkWlgK9uVQl4Av8=;
        fh=HRMbXI0AQbEO8+bQrKxZSSn2mZWTfkaDN59he4T+Xp8=;
        b=Tl1bJyXN3122KC6Ukd9M0ftXNgx+mfvAW9/MnysxNtC8ArwceUUOe6bhDvF0ysph2T
         1HNfE6SEQ/7nOc95QkIK+mMsu4TkOAsuBj3rGFpRpkHl5zCa5tWK5eFMkQfFjvLHXwX9
         s7A0p4w8zNfUzcBZCHyYPKsMy+hGzHd5qbnAGOskPOP6PeoIfnppUOy1LI8HhHW36r20
         /PRQopiQHpc5BEvXdtROEj5xfkRfxTA9rZyYtM+XRN6HXWHnHrgIq6/zE+mm6s40Q4C9
         N3Uf1QvsZFlbdkWSKFYNSDR1OEAprlJjVWnYIWu1ijL3Nd8tePLBtvJ9vvk88FrLFwPE
         JMtQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=NwQxnvzQ;
       spf=pass (google.com: domain of 3ljahaaykcssnspklynvvnsl.jvtrhzhu-klcnvvnslnyvbwz.jvt@flex--glider.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3lJaHaAYKCSsNSPKLYNVVNSL.JVTRHZHU-KLcNVVNSLNYVbWZ.JVT@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1753716376; x=1754321176; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=odIyxWreDQYCmYaUBnBH32awyWaWIkWlgK9uVQl4Av8=;
        b=o/yb7rTM/qhJ7Jq7ybRVFdEcj1e7b0vHRYz4dq8owrOiWyKf9zw2caU/kYtqo+a2eW
         tuJZr3SgLQarPsbllQW63v4p6cga9oZq5TeR+FdFyaXPV+lxOilSmupWTjdkFIkcbGHv
         T1RxfUhWBnPimiAVzYZigRGeAVDLRZD7KtqGnkdCORt53gmrN5+86ArCNYEf4tZ+ch4I
         f5zdNMdcjFDqbCK2TEB87Y28HA6v/ejAMOAIy0WmltIc5tt0HqVVq4NcwnI3iWhtVk7B
         cqIut0H9JHOhQSZgZ7lnrW6KiQ933N5iEFhnHyCFOuLVMrUYTdWe6TitqgkXMdDF4XFN
         F6kQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1753716376; x=1754321176;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=odIyxWreDQYCmYaUBnBH32awyWaWIkWlgK9uVQl4Av8=;
        b=QTLqmZH7TsH2j2RmY6p9dZbNFIBPKwXNA8qDIDgNjvDPyNal7PTx2P7trmRzNWKcK9
         L+qXuCpMGKuNItdGzSN7xauwDXu5kZQ/ric/tdfvW/wjkvDc26H1T06mEdhFHBMXZ+kV
         kH4+4Q69qV51oA+Heg0WGmw7puyH6ob9ti4Gyp4ZAeS7YIvRsfMajFt8JHTQtFRsFMHU
         X1mSQgnUD2SzMkD8yuhBYwVYBJ8rolfflmwPFQe6FrYUKNfdKUxiJlyJGXcjXBeHcBBu
         U2+iGSG7dYVk0FV25rjjRLQv2iZP7+dC+5S1URvvu4T14Uo5QmbpsdhgoB+XH4K/dqRb
         Am8Q==
X-Forwarded-Encrypted: i=2; AJvYcCXuOeZSLWeElNQwDznVAUByEgz/qG1yL1BHLt/FqrGgMaR9coYtgZre6nzLZmRZDAKwbxbkRA==@lfdr.de
X-Gm-Message-State: AOJu0YyjWXyk2aUUegNYusBeG8L0/YlmiINr+cE9pMRgUOxAA3ZvobfE
	Q/eqV/6pXPULX1b4sMVq9POLtzrA1Wpz5hUC4SK39h1QWnQAy4L/4BQT
X-Google-Smtp-Source: AGHT+IGcopMuOdP+8PQ49D0/6qZgwIf6ocYgFw6RX3XTL1n9v06eDzsA39037of1InQZF9eoG/cAQQ==
X-Received: by 2002:a05:600c:3514:b0:456:27a4:50ad with SMTP id 5b1f17b1804b1-4587667a7b4mr83229295e9.33.1753716375997;
        Mon, 28 Jul 2025 08:26:15 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfw1VfFyOqeC72vXHx18lOLY1biMatX1w+7SjDPT+22+Q==
Received: by 2002:a05:600c:608c:b0:43c:f19c:87b2 with SMTP id
 5b1f17b1804b1-45872d2d54als18996865e9.0.-pod-prod-08-eu; Mon, 28 Jul 2025
 08:26:13 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXRiRRqvxrPN53OBa3+6vrGBqrCCfYCUe1PXJGtcKFLSSKJR+C5cnWHQHKKtMMvDDQrrt2DIqLuLQM=@googlegroups.com
X-Received: by 2002:a05:600c:3514:b0:456:27a4:50ad with SMTP id 5b1f17b1804b1-4587667a7b4mr83228245e9.33.1753716373250;
        Mon, 28 Jul 2025 08:26:13 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1753716373; cv=none;
        d=google.com; s=arc-20240605;
        b=eEJurdfN7RfbzopBWQwvVZSsRRfgROWjEDRE2NlIuQYnChdxoQlaEcwGhk4P5jYfSk
         cx8MeV8SENYDsENaI3wJF0vTjJIb0soZpoYfNmbcwVZpRRFf+AIBmHkCkWMgdWm+YITJ
         QVbqBegeKaTma39awGQTGKfSdUEAXmpxnPhyuhN7v7UGlfsWURwp2Y569p7iTx/huhtF
         Lks7YtKYnz/aqdMUhLV9I7EXtMt44p5GWqeG519w3Ds/lZzhV65tr0rXPkB1GCUWubrS
         LHevDtx68+L/96k+YlgBX96YfFNEeNEvgwfOm1grAKp3pBHVA81NYLM0IBSPtO3cvcXE
         Rhcg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=PWggRk8hyLpW4/M6UT4TQt+tg1m7K6txrnQvGMUPVFM=;
        fh=YVWgLhwFPCuYrkYDySYVT2n/D9894R9njd7DZnckkNo=;
        b=GySraU/s4jOiv78VYd0SurvtI/kWBLk/UeojKy1TsFvt4OBrNts7jdyocjXDUk7EtM
         S46jhjXpTuty2v8S2k+DQymNQwvIPrdFI/XzeeF3rNCQvDeoUBa4wmACndOPedxUybYd
         Yb2nwo1yMbzckdrs5Q6/PpgrtJgtXfhpUb43R54vQ9RExZm1yGLHafC/OsZfJnvOE3rr
         knY5Bv8RDRwPk+edyscNTvA/fvvmMGWYq1ZcPv4Ux+KHzCRpIyKfCAl9G5Eg3HVlP904
         t2eQNF74Mh3dEmmoCxK7MtM80V+7GgKQBKPC13bNu1wTO3v0EAmjXvy/SIv57jpU8Qtm
         i5dw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=NwQxnvzQ;
       spf=pass (google.com: domain of 3ljahaaykcssnspklynvvnsl.jvtrhzhu-klcnvvnslnyvbwz.jvt@flex--glider.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3lJaHaAYKCSsNSPKLYNVVNSL.JVTRHZHU-KLcNVVNSLNYVbWZ.JVT@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x44a.google.com (mail-wr1-x44a.google.com. [2a00:1450:4864:20::44a])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-4586e7d2ec2si3757505e9.0.2025.07.28.08.26.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 28 Jul 2025 08:26:13 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3ljahaaykcssnspklynvvnsl.jvtrhzhu-klcnvvnslnyvbwz.jvt@flex--glider.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) client-ip=2a00:1450:4864:20::44a;
Received: by mail-wr1-x44a.google.com with SMTP id ffacd0b85a97d-3a4eb6fcd88so2774545f8f.1
        for <kasan-dev@googlegroups.com>; Mon, 28 Jul 2025 08:26:13 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWKNxCuZE3VAnxhG2JO3pVjPZZO03LuucTJFZ9nKLrHQo773d/6eG53UHgiS93+Dqs8uwkr90kNxMU=@googlegroups.com
X-Received: from wrod15.prod.google.com ([2002:adf:ef8f:0:b0:3b7:7e20:4466])
 (user=glider job=prod-delivery.src-stubby-dispatcher) by 2002:adf:a11c:0:b0:3b7:76e8:b9f7
 with SMTP id ffacd0b85a97d-3b776e8bcb3mr7141293f8f.10.1753716372699; Mon, 28
 Jul 2025 08:26:12 -0700 (PDT)
Date: Mon, 28 Jul 2025 17:25:44 +0200
In-Reply-To: <20250728152548.3969143-1-glider@google.com>
Mime-Version: 1.0
References: <20250728152548.3969143-1-glider@google.com>
X-Mailer: git-send-email 2.50.1.470.g6ba607880d-goog
Message-ID: <20250728152548.3969143-7-glider@google.com>
Subject: [PATCH v3 06/10] kcov: add trace and trace_size to struct kcov_state
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
 header.i=@google.com header.s=20230601 header.b=NwQxnvzQ;       spf=pass
 (google.com: domain of 3ljahaaykcssnspklynvvnsl.jvtrhzhu-klcnvvnslnyvbwz.jvt@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3lJaHaAYKCSsNSPKLYNVVNSL.JVTRHZHU-KLcNVVNSLNYVbWZ.JVT@flex--glider.bounces.google.com;
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

---
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
2.50.1.470.g6ba607880d-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250728152548.3969143-7-glider%40google.com.
