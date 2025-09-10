Return-Path: <kasan-dev+bncBD53XBUFWQDBBFUXQTDAMGQEVXDPFGY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73a.google.com (mail-qk1-x73a.google.com [IPv6:2607:f8b0:4864:20::73a])
	by mail.lfdr.de (Postfix) with ESMTPS id 978E4B50D1D
	for <lists+kasan-dev@lfdr.de>; Wed, 10 Sep 2025 07:25:04 +0200 (CEST)
Received: by mail-qk1-x73a.google.com with SMTP id af79cd13be357-80fcac99fe1sf549920485a.2
        for <lists+kasan-dev@lfdr.de>; Tue, 09 Sep 2025 22:25:04 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757481879; cv=pass;
        d=google.com; s=arc-20240605;
        b=DmnH1WuFVfV8p0e9k0P1IqYpOTuQPTiKNtjzD0/LSMsnlSXkiyQSot7dBfiS+KthUj
         jLeSG3ZNCO4Ugk8q50Bqx8Xa9f5ZlYwatMIqWU/MNy3nUNIVjJoIvlThoQ1HqgvwBugV
         3lD6QTfvaLLoRHEidzmp7nZf/Ud/qZhyofC61InuRt+K/5RprExWBsFxYBUyd/sGERnf
         6xlcW9E3Ww8MwzWpaDzboBZ1RRwoHhEbUSIH6ufTNlTEYPrwKUo/e0r3bVN+h7gN7QBI
         a4nkhKjFj3Lv7vD6Agw3Md4jFrfbYANYjPIDGEmXgNNPBmLHnxq3bEDOdLNaNqYLz3nR
         rdfQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=xl14o3mtRZSl1WAxcLPjuwIJHAlp/jHy8Z9ZLbPK7dk=;
        fh=F5wpbRya/yaE6o2dECG6Jld4D53h970p1/K2dfdrm+Q=;
        b=R81+nBHw0TYJ4L/w0YQzydPmBkf6zrMy9hnJyuH23DO8RjC2em78Jx5w1FHkiWkhaV
         KWKtIlpnANTsIF7FpFq5qg+Zk13CNaOJABQIMVqamHpSYvAAyo1l3LFS+TdyLMZNRoUT
         yguRD2adIMpJuoa2ZIDenUMcscJ6fjB8ylWnehRVaErTSZPB32dlkVA2F/vwFpTPTC89
         SMkD/6z4V1thkTAqZSkeBKXroKCT/FF96APos4F8LjpcQ4WjlbchRBHJp93QO1hA/mD6
         zgYQko6S66zQBpMnZKyASStivHMVhdkgXXNUYCHaYLPwi62O5A+Mxnp3yWnJjOBlQQng
         6rgw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=NIhilPIH;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::52f as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757481879; x=1758086679; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=xl14o3mtRZSl1WAxcLPjuwIJHAlp/jHy8Z9ZLbPK7dk=;
        b=eAHoirtjat8dCrIVYmAlnqOhn5NgvePCiNR5PLiXqFzXcagqdm3IkvWWSn1lmdhlAN
         EJ6S4wK01g4NT29CTsXqFHJaKMsd1kBIlUfF5dpQIekOlGMOVD6/4nusV0NZk2igmIjn
         oRMRYAIE59tLurQLRFj6KcV9nyeBYMW4Kf3prUvrCXmg42qxGwzHcamuEv86cP3ABX42
         m6v1IMb7q3RSVXdxa+SYIfnsFd1YPCWJVLEctI2RhRhEkvZjJqcnohGKCJLe6wchL035
         0yr+zWJkdvzW6cuRZT2ljJJDJUseMqNQwJh66SQRcPX25+rdJvTjB2pK334vrsMTHb5G
         BFOA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1757481879; x=1758086679; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=xl14o3mtRZSl1WAxcLPjuwIJHAlp/jHy8Z9ZLbPK7dk=;
        b=CzHmDJ+1nvcvgLtkgohbLxdEC8IcF8X5ZLW3TCcO37c1IlrGgGK68qu6RwUcElcm5m
         3OGBLaM6o/CWpvY204wmOiv+1Pzy2L6Gb41FReajMTcTHkbxPt4YlgSPfZT4RIQs6xXg
         DZAiu3k8TRa++mVgsOAe88tqelXVpzs1OTFdVzJ+RkmnurPjqkjTEhub+xJ1VLKqe/9g
         nmOwvpqiNs9mlee/jTPuEAemk0DjgJr5cVd6102oOwinpv0IpYVP2SFO5jaCCAAwFJQl
         CEQkUuOWJ+hDqEec55nhHoWsrbDuOLLiPU+QjK7LuvfDo+ZpDeEaBBKxd+X8tLhy0PHC
         GCww==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757481879; x=1758086679;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=xl14o3mtRZSl1WAxcLPjuwIJHAlp/jHy8Z9ZLbPK7dk=;
        b=npLRVotM11lpDKghou3J13eUzq14FAOLchneHbWgsbnn0FcVG/blxRo5su3jfQdH0m
         opT/+RWYZsFtxprcSmEdRsz2RXK7qXWUjJYxBDbDQyd1NTvWwrI+j2uOM5Ko1WKKl9IJ
         BX4D7syO7C8Eers+On+6OmbnxtqijubcXH5JtwgTwMMHSQdzbqmTUOMYJhJJHd9bpTtq
         vG9HjXyHArEVOoWQl6ieNkhLhh+8g7f+Ndun0OlEQfiV1BCXHmMyTqRdycmaj3uP9sbu
         1MDoHzgkLLc3ZFgfEBdkgoKIQriMgUI9wggjL5n6hgQ+NvJkXdIbQUd0MwWhMwMyAAsj
         U2jw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUyrteZtihbP4TDN9lVjlKPK5im31ge5e42UAk+xjxVcLqiRuWLvb8g32bN66uoRoU0R4Dnog==@lfdr.de
X-Gm-Message-State: AOJu0Yx68MbEY/ihEQq5Bls+APzTEXcabT9+2JSvV2RX19YHqVobcVow
	7Pp1i2N6Kgih4QZYMawYb6fWo861I8LzKggFZ4JonyH46GC4knKeQpTS
X-Google-Smtp-Source: AGHT+IEGVPLewLHjbEOb8IZP12IQ27QbrBydvAXC4j55H6nNEgSQIjmV7ztqvv9s7L7oXj0tLNJNkA==
X-Received: by 2002:a05:620a:4556:b0:80b:985d:e95b with SMTP id af79cd13be357-813bf6c15f5mr1677420285a.24.1757481878725;
        Tue, 09 Sep 2025 22:24:38 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd7yH/r4Qwp/0adPs8e1AobfoUPtbr7l6ZOjk0J/v4ii5Q==
Received: by 2002:a05:6214:3008:b0:70b:acc1:ba4f with SMTP id
 6a1803df08f44-72d39347802ls75644116d6.1.-pod-prod-08-us; Tue, 09 Sep 2025
 22:24:37 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVibJMOkBZjaMofosLDYQ7txGQzEb6Qc/JPik+Pg6bkVhNXeUFCelbiX1b1CQNBMyOYVALLM4hovJY=@googlegroups.com
X-Received: by 2002:a05:6102:c08:b0:52a:4268:7618 with SMTP id ada2fe7eead31-53d13a50847mr3845371137.27.1757481877318;
        Tue, 09 Sep 2025 22:24:37 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1757481877; cv=none;
        d=google.com; s=arc-20240605;
        b=V0SY2LvMJ1FE5ERgQTbdmiTu2TcYdJhmgFZW3W2ba7O+hk+0AMRbG7mBG50x7jBpIn
         59XQNJk/NM4H81wwCAM7BvYCD88/ykbVnnqdNbodra9NBrILrkCAAMwbRt1Vltjd412w
         KEU1riTY/ztNNsFufZ0WIdB/88ehjWDJOpoRL8vvRG1JV0LTdOZPlaXA6+poFn9JzQw+
         O7mbNt+qrlr4s43E7MtEvJi4zeZrKhOc6aRWpVQnbvWvx7W5UPATiZMt0vk3mtBM21gk
         jj6CRHzLb4Z7mlMjkKujx9FFuUVfxpCCitl82NyC/ljaoEozYHHuoi+bJg+GdMmZqZRS
         2FPQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=BQYOiNSD0BVFYt8LJn6Fepybq7p8FLHlj9qtf7JwQoI=;
        fh=gJ+cqZOjEFzpgEAJ4upWMwHq8QZVDy0zZhkINh+AEJw=;
        b=ctP2ygrF6c975xey84MM3M0OWSMSScRO6MVTsvW1UCJ1DioLeq9mGHNmo5xZyJWgtA
         WxsO2ltn+4raT6oSkSPYcEgSPb6u3T49AJgUWd61bk6ZINiJWx6Zqjtjfndj3TVdFXCa
         NBigJ6mwF6CObk6yWKKHRa89ywKM+ZdgVGqXmDJAgtPxz6/gKx6bUkZggEsVAsvUusAn
         rR74nHp1s7kNKPVEhddk0fwzHzIHw72PDsoEhRNQ+RWReGuy2J/paAxnwddVTohxuJ8T
         8Ev57iH+VsQjppysNl+hvWnNOxy1MiKEZ1o/om3kYDXQEFFxakbYdhtRtX9nPUA0IgE7
         Ss/Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=NIhilPIH;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::52f as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pg1-x52f.google.com (mail-pg1-x52f.google.com. [2607:f8b0:4864:20::52f])
        by gmr-mx.google.com with ESMTPS id a1e0cc1a2514c-8943b854f03si1136890241.2.2025.09.09.22.24.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 09 Sep 2025 22:24:37 -0700 (PDT)
Received-SPF: pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::52f as permitted sender) client-ip=2607:f8b0:4864:20::52f;
Received: by mail-pg1-x52f.google.com with SMTP id 41be03b00d2f7-b4c53892a56so5742149a12.2
        for <kasan-dev@googlegroups.com>; Tue, 09 Sep 2025 22:24:37 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWSvPINrzYtuBuxkMKGFoEyNqTtcqpGoOvFD+dS0/C5ywwGitrPjJuOBBByCOiocfUqJQLS54CEG6I=@googlegroups.com
X-Gm-Gg: ASbGncvJCINsbJQ/lWxrsupsbiXNBnsm3ckHdYRcqYL/ulrTfCr4QjnbBLm0Ty62HwK
	FOSs6mmr/1wKUV8pxXCCk4398lP19e8qMW/P1HrxT3cMQ6URXRDw+d63aPRchA0Alwz/MD50/7a
	dyLcgsOiuAW68CwwoTbKxc7nx0iufNJYV44VZJH0PDpajbePBdALqBR3o4jcvMDEfVZ74W9sg4e
	KmBvgmMyBIsBYRDhVVASQzyO1joyYjHKdHqkqCnud5hxr5c1qK91w1ofp6xk97aoSTpXhkNwwZf
	ncBLmlCEbEa0C1Q2IZ/I0PvFnJ2rObZC1L4YcW5wn6gGSWfsOJLKP5LdR2fO4hAyQ0rnQ+26RoV
	GtqMxGRwK8vT05rraihmZNd3o2StvYDMBMQ==
X-Received: by 2002:a17:902:d4ce:b0:24c:7bc6:7ad7 with SMTP id d9443c01a7336-2516ef53bb8mr204775165ad.3.1757481876261;
        Tue, 09 Sep 2025 22:24:36 -0700 (PDT)
Received: from localhost.localdomain ([2403:2c80:17::10:4007])
        by smtp.gmail.com with ESMTPSA id d9443c01a7336-25a27422ebcsm14815125ad.29.2025.09.09.22.24.08
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 09 Sep 2025 22:24:35 -0700 (PDT)
From: Jinchao Wang <wangjinchao600@gmail.com>
To: Andrew Morton <akpm@linux-foundation.org>,
	Masami Hiramatsu <mhiramat@kernel.org>,
	Peter Zijlstra <peterz@infradead.org>,
	Mike Rapoport <rppt@kernel.org>,
	"Naveen N . Rao" <naveen@kernel.org>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	kasan-dev@googlegroups.com,
	"David S. Miller" <davem@davemloft.net>,
	Steven Rostedt <rostedt@goodmis.org>,
	Mathieu Desnoyers <mathieu.desnoyers@efficios.com>,
	Ingo Molnar <mingo@redhat.com>,
	Arnaldo Carvalho de Melo <acme@kernel.org>,
	Namhyung Kim <namhyung@kernel.org>,
	Mark Rutland <mark.rutland@arm.com>,
	Alexander Shishkin <alexander.shishkin@linux.intel.com>,
	Jiri Olsa <jolsa@kernel.org>,
	Ian Rogers <irogers@google.com>,
	Adrian Hunter <adrian.hunter@intel.com>,
	"Liang, Kan" <kan.liang@linux.intel.com>,
	Thomas Gleixner <tglx@linutronix.de>,
	Borislav Petkov <bp@alien8.de>,
	Dave Hansen <dave.hansen@linux.intel.com>,
	x86@kernel.org,
	"H. Peter Anvin" <hpa@zytor.com>,
	linux-mm@kvack.org,
	linux-trace-kernel@vger.kernel.org,
	linux-perf-users@vger.kernel.org
Cc: linux-kernel@vger.kernel.org,
	Jinchao Wang <wangjinchao600@gmail.com>
Subject: [PATCH v3 01/19] x86/hw_breakpoint: introduce arch_reinstall_hw_breakpoint() for atomic context
Date: Wed, 10 Sep 2025 13:23:10 +0800
Message-ID: <20250910052335.1151048-2-wangjinchao600@gmail.com>
X-Mailer: git-send-email 2.43.0
In-Reply-To: <20250910052335.1151048-1-wangjinchao600@gmail.com>
References: <20250910052335.1151048-1-wangjinchao600@gmail.com>
MIME-Version: 1.0
X-Original-Sender: wangjinchao600@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=NIhilPIH;       spf=pass
 (google.com: domain of wangjinchao600@gmail.com designates
 2607:f8b0:4864:20::52f as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
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

Introduce arch_reinstall_hw_breakpoint() to update hardware breakpoint
parameters (address, length, type) without freeing and reallocating the
debug register slot.

This allows atomic updates in contexts where memory allocation is not
permitted, such as kprobe handlers.

Signed-off-by: Jinchao Wang <wangjinchao600@gmail.com>
---
 arch/x86/include/asm/hw_breakpoint.h |  1 +
 arch/x86/kernel/hw_breakpoint.c      | 50 ++++++++++++++++++++++++++++
 2 files changed, 51 insertions(+)

diff --git a/arch/x86/include/asm/hw_breakpoint.h b/arch/x86/include/asm/hw_breakpoint.h
index 0bc931cd0698..bb7c70ad22fe 100644
--- a/arch/x86/include/asm/hw_breakpoint.h
+++ b/arch/x86/include/asm/hw_breakpoint.h
@@ -59,6 +59,7 @@ extern int hw_breakpoint_exceptions_notify(struct notifier_block *unused,
 
 
 int arch_install_hw_breakpoint(struct perf_event *bp);
+int arch_reinstall_hw_breakpoint(struct perf_event *bp);
 void arch_uninstall_hw_breakpoint(struct perf_event *bp);
 void hw_breakpoint_pmu_read(struct perf_event *bp);
 void hw_breakpoint_pmu_unthrottle(struct perf_event *bp);
diff --git a/arch/x86/kernel/hw_breakpoint.c b/arch/x86/kernel/hw_breakpoint.c
index b01644c949b2..89135229ed21 100644
--- a/arch/x86/kernel/hw_breakpoint.c
+++ b/arch/x86/kernel/hw_breakpoint.c
@@ -132,6 +132,56 @@ int arch_install_hw_breakpoint(struct perf_event *bp)
 	return 0;
 }
 
+/*
+ * Reinstall a hardware breakpoint on the current CPU.
+ *
+ * This function is used to re-establish a perf counter hardware breakpoint.
+ * It finds the debug address register slot previously allocated for the
+ * breakpoint and re-enables it by writing the address to the debug register
+ * and setting the corresponding bits in the debug control register (DR7).
+ *
+ * It is expected that the breakpoint's event context lock is already held
+ * and interrupts are disabled, ensuring atomicity and safety from other
+ * event handlers.
+ */
+int arch_reinstall_hw_breakpoint(struct perf_event *bp)
+{
+	struct arch_hw_breakpoint *info = counter_arch_bp(bp);
+	unsigned long *dr7;
+	int i;
+
+	lockdep_assert_irqs_disabled();
+
+	for (i = 0; i < HBP_NUM; i++) {
+		struct perf_event **slot = this_cpu_ptr(&bp_per_reg[i]);
+
+		if (*slot == bp)
+			break;
+	}
+
+	if (WARN_ONCE(i == HBP_NUM, "Can't find a matching breakpoint slot"))
+		return -EINVAL;
+
+	set_debugreg(info->address, i);
+	__this_cpu_write(cpu_debugreg[i], info->address);
+
+	dr7 = this_cpu_ptr(&cpu_dr7);
+	*dr7 |= encode_dr7(i, info->len, info->type);
+
+	/*
+	 * Ensure we first write cpu_dr7 before we set the DR7 register.
+	 * This ensures an NMI never see cpu_dr7 0 when DR7 is not.
+	 */
+	barrier();
+
+	set_debugreg(*dr7, 7);
+	if (info->mask)
+		amd_set_dr_addr_mask(info->mask, i);
+
+	return 0;
+}
+EXPORT_SYMBOL_GPL(arch_reinstall_hw_breakpoint);
+
 /*
  * Uninstall the breakpoint contained in the given counter.
  *
-- 
2.43.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250910052335.1151048-2-wangjinchao600%40gmail.com.
