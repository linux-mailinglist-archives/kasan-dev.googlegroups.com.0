Return-Path: <kasan-dev+bncBCCMH5WKTMGRBQE46XBAMGQELZXPNBQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43c.google.com (mail-wr1-x43c.google.com [IPv6:2a00:1450:4864:20::43c])
	by mail.lfdr.de (Postfix) with ESMTPS id 08FA3AE9F31
	for <lists+kasan-dev@lfdr.de>; Thu, 26 Jun 2025 15:42:26 +0200 (CEST)
Received: by mail-wr1-x43c.google.com with SMTP id ffacd0b85a97d-3a56b3dee17sf1086325f8f.0
        for <lists+kasan-dev@lfdr.de>; Thu, 26 Jun 2025 06:42:26 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1750945345; cv=pass;
        d=google.com; s=arc-20240605;
        b=N/rNka1NcBGyWiTAcXpYiPoTFS0GB1vnQkWRTmLYmI5gMzjycJOWQeZ3oGuKT9u9hV
         sSz7BpyMSh6IQkeQbzHzmJMrvixebfhkumrtv+wRWPkH8LJ0SOAlUexgxO3KskKEdPeS
         qY1XSaKsAQ7A8XOXYwD2T8M+4t4VMrfH1zBjhINl6G1gI0vyw0eSithoCyXbq7cmBL1g
         0CZkCINtTLx2zwpr9A3lE8bxbf9x2PcA4EsbzW+yB0KzHfttHwYnsKAf1YnpKer90L0a
         0H5um7r0FMMdZTOd5bDpVmrH57e5llHeIeGRqY7JQ6aaRcRYwl7lCUOHcJ46Sb6kgxji
         Qkaw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=gle3Yuv4J8nCwRF79ER0BXoPJh6u75cPUdN8e4kRT/U=;
        fh=loqidbNnpP5nsrSEO2KuSW7+5VsmLHkX/0vlxLfP5Ik=;
        b=UGzSgk8A7vKFpmbgFMgXo63BWi+LmfmeBMveiGo8kOOoEbkQY3QwG6WGK8qpsoGnvU
         ahYX/UZ0Al6dcMiBdmGNN9AuHmN1/Ghva41lpKtsz1EKMd1Ftec3BEjE80gtAkNDyN3/
         V/38S8KBhGQpCuXeByPvBcXM5FM4jIEEmsLniAONWlgih2BAk/2q4NVg8SpNoEj3lVpc
         MoC8OoTgrZJtDMcZUtCRBRWukFK8h7CMSKIdlfk+umeRhOhNW8PiFEVv+t+vLnoth5bu
         8x1Z60Tw+3EYoHV4Chxvh6/lmHCxQcU/pqruvp79obPlQvJnPhPZnQ4AiG2OCdaTWoME
         NoMA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=pj3+szrV;
       spf=pass (google.com: domain of 3pk5daaykczk9eb67k9hh9e7.5hfd3l3g-67o9hh9e79khnil.5hf@flex--glider.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3Pk5daAYKCZk9EB67K9HH9E7.5HFD3L3G-67O9HH9E79KHNIL.5HF@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1750945345; x=1751550145; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=gle3Yuv4J8nCwRF79ER0BXoPJh6u75cPUdN8e4kRT/U=;
        b=Xachq+tmZRalj7KRutqC6O+YhE8EgxxI9lYOY+kU0FaIrJES8jFiiT+pmUgJCFgWyl
         /mQVzTPWJl9FDK9+k3+LkG2BS2eymBrNcXHiUTN3TaZismOMqIis3X5QkLiAYp0Kf+4e
         6z1TXEgIAmaMgQzG1Yqe67uytLrOgded8t4ArP7Cnp7H2vO8ugWwqpcm5rnZGPJ6bKH8
         EuzWIGXeZIxo0sU5lqZhGisUwhVr6LOvj7SO01fMHVjsNSWNznHcWBY3reo2Qwm6Fqee
         qV84q8L6j6OTbJusrF/ogg+juDktVkiBGjxyiOK3XKbfdyTB5eJjxHYVvTtfuYn01CcX
         12tQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1750945345; x=1751550145;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=gle3Yuv4J8nCwRF79ER0BXoPJh6u75cPUdN8e4kRT/U=;
        b=BNiUt10vd0cw0+xiZHQ3ZctO+ov8o+1Oqctfw4uKECvIP48ZN8tli+2AqH771R0q0b
         S3EGpAQIFlifvv/4YthB7F3wTflsSOkPPyPKPjLK/DTxVpjKgogIOgfBFAllvH1HTAWh
         bnwRPXNFBBBA8755XbxCo4QjMXHTYgoPsueT1TsRQRCC8IMAmLWz5vmYFvfbxlMWegNC
         sWHbU0EAr5YwxGbfP69/KjvBxXEeOp6A+Ui3LwgyCN9E782I6vnnqXPjeaM+emRh0XHr
         nErj17w/uC7Y4QuTlzFSKLEbRNuH6THHhDY2fmx3T1+FndAASQk9+yLLCCuENOgm2vIL
         2DFg==
X-Forwarded-Encrypted: i=2; AJvYcCXdDij2Sqn9tOe2uEFDsJhxgcS0/XSEEacBSkNcy0M4KHzYJHz8pqGfwvNe1c1lhLTzwlXmBw==@lfdr.de
X-Gm-Message-State: AOJu0YzUFzGGcOCWTWpBcJ78gZeyq13Gl3HX4K4csRMob/CEny65OoWO
	tkrapbQWaaqAu+4hudmNLgx53UtdSB5NXjTRSDUtGbjd5lYjSC5J6cDU
X-Google-Smtp-Source: AGHT+IHejaescJGqoqLZjMAdPOHNM1wLX3MCGMa8SQv4YLctSQuhtDo7P3LEMEe05L1VhUMc6XxaNw==
X-Received: by 2002:a05:6000:40d9:b0:3a4:cec5:b59c with SMTP id ffacd0b85a97d-3a6f3162238mr3504655f8f.25.1750945344843;
        Thu, 26 Jun 2025 06:42:24 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcWZChjdj3FXvkNRGA4YYBY/FswrIad0lrZdozeFe8idQ==
Received: by 2002:a5d:5f83:0:b0:3a3:681e:6505 with SMTP id ffacd0b85a97d-3a6f328d773ls370793f8f.2.-pod-prod-00-eu;
 Thu, 26 Jun 2025 06:42:22 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUPWzGEV6XrCHxZ67TXt7u35yBoGe6MpDfoiQ+mkYgO/HALQdDvSSRyWixFEDxsdDiVXxKu1Hq3YVg=@googlegroups.com
X-Received: by 2002:a05:6000:290f:b0:3a6:d93e:526d with SMTP id ffacd0b85a97d-3a6f3102808mr3385162f8f.10.1750945342553;
        Thu, 26 Jun 2025 06:42:22 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1750945342; cv=none;
        d=google.com; s=arc-20240605;
        b=WK0KgoiwJkM754NS/+w4z4a4aP6Rb+jwAbOe4IMSzF7kJbasttgQuBDwiJ/VLlT4Q1
         FKORWx//Stjj+3NPB/qDcPAtiHtR7Sf3mO6KKEZmYWZ/8U84vHO+/bFfdu4tEZjkgAyK
         aNHYMHYsmmNHHeA0e/joIVTJZQzodmsuTAYN6Zq9FRN4HyMuwS/23SXoTc6a1/8C/AiX
         iMW0qM9QCaP35wMFpQcPpoSOutR171CjmozUSszCCB2x/FeMweKpug3Is7zGsGCYkQP7
         BBk2uJg/xFewLapHXegy3MYU4MIyBv9aMH8WgeVdjTlauG7Vo+Bi9wnwsq36ohxpW//K
         kUYg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=3X/PLO35Kby/7c8Y0k4KR1mlzE+5Joj5D37Kq7kXi8s=;
        fh=A3X4Lczj3cO/Q10Zakym/Kit0X2g/dchQLz0C3RRFao=;
        b=Ry+rnCkGxApDTsBf/OWTDqSHv7t8MSLv0JynGixZGC83BeHgIrNhC6g5r1BknC8ydB
         LZO6YLGwKXV46MbFkcF41XCdL9XhvgaVibSQj4kvdTyd9yRnAINyS5rxyOeWnmuNyQyy
         oD60GSlFKLgJ72EmKeYYc+5XqzZeXTL7h7UJJh0KnMh68n2dlhPCCsxsLDuhpjjbDqra
         fXuUkzziM5fd53qCrGTcXvJeNZyx821iuKdrfdZaAcoSqPGyG7aMrcoCyumGhulrke4y
         3mZ126AYTb9z4cWTBL2N30wpsUJucPWVCo2wolIwhkuLb1ZxBW0Ybk1dBFJKrH6u0nlq
         Jl6g==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=pj3+szrV;
       spf=pass (google.com: domain of 3pk5daaykczk9eb67k9hh9e7.5hfd3l3g-67o9hh9e79khnil.5hf@flex--glider.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3Pk5daAYKCZk9EB67K9HH9E7.5HFD3L3G-67O9HH9E79KHNIL.5HF@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x34a.google.com (mail-wm1-x34a.google.com. [2a00:1450:4864:20::34a])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-4538235f627si1191485e9.1.2025.06.26.06.42.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 26 Jun 2025 06:42:22 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3pk5daaykczk9eb67k9hh9e7.5hfd3l3g-67o9hh9e79khnil.5hf@flex--glider.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) client-ip=2a00:1450:4864:20::34a;
Received: by mail-wm1-x34a.google.com with SMTP id 5b1f17b1804b1-4538a2f4212so4082155e9.2
        for <kasan-dev@googlegroups.com>; Thu, 26 Jun 2025 06:42:22 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUuc1leFSn+g98u0BFjDWGfUHiUQJjbQcS8k5LaGbsKJ8hsPwlK1N5ep79evvOqDHbmbrkzZZdqBzw=@googlegroups.com
X-Received: from wmbet8.prod.google.com ([2002:a05:600c:8188:b0:442:f451:ae05])
 (user=glider job=prod-delivery.src-stubby-dispatcher) by 2002:a05:600c:3590:b0:442:d9f2:ded8
 with SMTP id 5b1f17b1804b1-45381ab8dbemr83015875e9.15.1750945342082; Thu, 26
 Jun 2025 06:42:22 -0700 (PDT)
Date: Thu, 26 Jun 2025 15:41:54 +0200
In-Reply-To: <20250626134158.3385080-1-glider@google.com>
Mime-Version: 1.0
References: <20250626134158.3385080-1-glider@google.com>
X-Mailer: git-send-email 2.50.0.727.gbf7dc18ff4-goog
Message-ID: <20250626134158.3385080-8-glider@google.com>
Subject: [PATCH v2 07/11] kcov: add trace and trace_size to struct kcov_state
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
 header.i=@google.com header.s=20230601 header.b=pj3+szrV;       spf=pass
 (google.com: domain of 3pk5daaykczk9eb67k9hh9e7.5hfd3l3g-67o9hh9e79khnil.5hf@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3Pk5daAYKCZk9EB67K9HH9E7.5HFD3L3G-67O9HH9E79KHNIL.5HF@flex--glider.bounces.google.com;
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
Change-Id: I50b5589ef0e0b6726aa0579334093c648f76790a

v2:
 - Address comments by Dmitry Vyukov:
   - tweak commit description
 - Address comments by Marco Elver:
   - rename sanitizer_cov_write_subsequent() to kcov_append_to_buffer()
 - Update code to match the new description of struct kcov_state
---
 include/linux/kcov_types.h |  9 ++++++-
 kernel/kcov.c              | 54 ++++++++++++++++++++++----------------
 2 files changed, 39 insertions(+), 24 deletions(-)

diff --git a/include/linux/kcov_types.h b/include/linux/kcov_types.h
index 53b25b6f0addd..233e7a682654b 100644
--- a/include/linux/kcov_types.h
+++ b/include/linux/kcov_types.h
@@ -7,9 +7,16 @@
 struct kcov_state {
 	/* Size of the area (in long's). */
 	unsigned int size;
+	/*
+	 * Pointer to user-provided memory used by kcov. This memory may
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
index 8e98ca8d52743..038261145cf93 100644
--- a/kernel/kcov.c
+++ b/kernel/kcov.c
@@ -195,11 +195,11 @@ static notrace unsigned long canonicalize_ip(unsigned long ip)
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
@@ -209,9 +209,9 @@ static notrace void kcov_append_to_buffer(unsigned long *area, int size,
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
 
@@ -225,8 +225,8 @@ void notrace __sanitizer_cov_trace_pc_guard(u32 *guard)
 	if (!check_kcov_mode(KCOV_MODE_TRACE_PC, current))
 		return;
 
-	kcov_append_to_buffer(current->kcov_state.area,
-			      current->kcov_state.size,
+	kcov_append_to_buffer(current->kcov_state.trace,
+			      current->kcov_state.trace_size,
 			      canonicalize_ip(_RET_IP_));
 }
 EXPORT_SYMBOL(__sanitizer_cov_trace_pc_guard);
@@ -242,8 +242,8 @@ void notrace __sanitizer_cov_trace_pc(void)
 	if (!check_kcov_mode(KCOV_MODE_TRACE_PC, current))
 		return;
 
-	kcov_append_to_buffer(current->kcov_state.area,
-			      current->kcov_state.size,
+	kcov_append_to_buffer(current->kcov_state.trace,
+			      current->kcov_state.trace_size,
 			      canonicalize_ip(_RET_IP_));
 }
 EXPORT_SYMBOL(__sanitizer_cov_trace_pc);
@@ -252,9 +252,9 @@ EXPORT_SYMBOL(__sanitizer_cov_trace_pc);
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
@@ -266,22 +266,22 @@ static void notrace write_comp_data(u64 type, u64 arg1, u64 arg2, u64 ip)
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
 
@@ -382,11 +382,13 @@ static void kcov_start(struct task_struct *t, struct kcov *kcov,
 
 static void kcov_stop(struct task_struct *t)
 {
+	int saved_sequence = t->kcov_state.sequence;
+
 	WRITE_ONCE(t->kcov_mode, KCOV_MODE_DISABLED);
 	barrier();
 	t->kcov = NULL;
-	t->kcov_state.size = 0;
-	t->kcov_state.area = NULL;
+	t->kcov_state = (typeof(t->kcov_state)){ 0 };
+	t->kcov_state.sequence = saved_sequence;
 }
 
 static void kcov_task_reset(struct task_struct *t)
@@ -736,6 +738,8 @@ static long kcov_ioctl(struct file *filep, unsigned int cmd, unsigned long arg)
 		}
 		kcov->state.area = area;
 		kcov->state.size = size;
+		kcov->state.trace = area;
+		kcov->state.trace_size = size;
 		kcov->mode = KCOV_MODE_INIT;
 		spin_unlock_irqrestore(&kcov->lock, flags);
 		return 0;
@@ -928,10 +932,12 @@ void kcov_remote_start(u64 handle)
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
@@ -1004,8 +1010,8 @@ void kcov_remote_stop(void)
 	struct task_struct *t = current;
 	struct kcov *kcov;
 	unsigned int mode;
-	void *area;
-	unsigned int size;
+	void *area, *trace;
+	unsigned int size, trace_size;
 	int sequence;
 	unsigned long flags;
 
@@ -1037,6 +1043,8 @@ void kcov_remote_stop(void)
 	kcov = t->kcov;
 	area = t->kcov_state.area;
 	size = t->kcov_state.size;
+	trace = t->kcov_state.trace;
+	trace_size = t->kcov_state.trace_size;
 	sequence = t->kcov_state.sequence;
 
 	kcov_stop(t);
-- 
2.50.0.727.gbf7dc18ff4-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250626134158.3385080-8-glider%40google.com.
