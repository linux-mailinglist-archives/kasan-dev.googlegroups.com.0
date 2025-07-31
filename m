Return-Path: <kasan-dev+bncBCCMH5WKTMGRBZNRVXCAMGQEBAUEROA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53d.google.com (mail-ed1-x53d.google.com [IPv6:2a00:1450:4864:20::53d])
	by mail.lfdr.de (Postfix) with ESMTPS id 55287B170A3
	for <lists+kasan-dev@lfdr.de>; Thu, 31 Jul 2025 13:52:07 +0200 (CEST)
Received: by mail-ed1-x53d.google.com with SMTP id 4fb4d7f45d1cf-61585f22299sf685654a12.0
        for <lists+kasan-dev@lfdr.de>; Thu, 31 Jul 2025 04:52:07 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1753962727; cv=pass;
        d=google.com; s=arc-20240605;
        b=Z83QtIrAhss++hItsESmxzWGlhTuCarIM9UZvQCCy58P00fkg7e1FmA8WJMoSGFJkj
         KIt17lfHklT1HpKqk6ft6/JU2Fk2JJ3bgB1fFO+gVuM82TbFFga9agJArBaqudzFlhgR
         rycqRLucnZByAt0V1UPfL/HO4Q6kbwbjyRZFvcum4BKEI+SH4x2OmpA0pucvsELFm356
         euVZoSw9iIkGWpd4s9OG/nKYqfCNt46GFcNWbTwcMHad2l9QKD+A0yMX+AK2pEMVv1am
         8nEOGTOEQmw6Z479CzBatXNvAs/0PDE8zQEKjLK9jiTuFbBGPgskZIR2PK6vblWB/Fa/
         Hlsg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=zNdEE7xtE6lHR+0jeZx9HS/FeA6RsJoZNZFhiZoTxmg=;
        fh=TQgUVP+oJ/3lr0LyHKgqq0H44jwvSC51w/9dBGcimnU=;
        b=jSOgV8MgchZjS0STBfU8SATT76BwQlTsBAd1qheSmAEPx2i1Vbgh6DrAh4sRpB3wfN
         qzN1AyXr+ok+/Aiu7/c8fRq4RCLRNWfY6w5pIWbWcBLjRt724a7K4v4RzUuB2Dyypf18
         h7U2so9uwib0SpWEaRUd8xYsqtv4b8+XVOMz0q1paaL/Pid5s+r1oAIlqp39QIXeNEBy
         /RTOzTddLHYsh6UV/iT+/kR8HSyHKy+puXLlg4wey0yufFvvpgC7qiKX8Qw43nvgwvZA
         oCMn8d8RzfRG5lII3gRy0rRyoFIr36yxPsyB06K4Vewfg4Ci2zxIExizyxS9O4owJAjO
         X0sA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=d9gq20mt;
       spf=pass (google.com: domain of 341ilaaykcq4uzwrs5u22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--glider.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=341iLaAYKCQ4uzwrs5u22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1753962727; x=1754567527; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=zNdEE7xtE6lHR+0jeZx9HS/FeA6RsJoZNZFhiZoTxmg=;
        b=xVZspVGfaxvUQmwooHNCvS10x/M+/B8xdPf9ADzsl6468IBM84dhPtgdYl0dmLobkD
         D7VGVg3GDIps5Zmqut21QnywdcUHJgu/kG81VoJ/Hf3OzY0sfApW3k+XsjFQp4zUt6Vw
         yUq1OT6qOauUw1SD0Tgnfer4mbkymblorHjWiGtPLGWj3jBXifndMzkrAlRWFWeLGhnS
         ffRgd8sWD4eS06McOrYQp/4wECsfjzeF6g7kkDsoEEe1YbP6BKEgHX+LCiIQTckcm/xB
         PPzLAmmwCeirGfHpC+yUoJce6hPxA78wfvszkbZGvK+xujKtgDBhp3apH6zHIE2hHYbA
         W4HA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1753962727; x=1754567527;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=zNdEE7xtE6lHR+0jeZx9HS/FeA6RsJoZNZFhiZoTxmg=;
        b=eKQ/z2Dop6uE2Ku/LIqSkFDvQhcXxf5OsImx3GrfmBjBuqbh1DZnG8OHnI3h0O5MsW
         tdUzaupIHFUZcyMTbsm8q0Ht/IvBYhh+wyZLJXGHz0usfWM5BjiDObwa8yiPtdLdiGLI
         vCvqa8Q6YNKgVXtiUcdtuC6XJChtB1zxRZ8XvHZ2A25CxrVEnrJu1ssDgmOZjNB0kTLg
         H3WnM3wjtyquv1hdsz9DzP4KbRdbJUi5ETonnN9r2VppjUl1CDJT4ccuK64BSj7ItoX0
         ayjKswSudX0JWuZ5YtR8d72ysl+2lyOG5ieRtDGqBBSoymlkomNYzEhmFQvgJESRYOLb
         z1Eg==
X-Forwarded-Encrypted: i=2; AJvYcCUhHZhMyYmDg7Wmqh8sJGLmBDTUAc6kvMsXV4nRXUsoiJk0tPX1Ysifr878VNpPcriZFthnUA==@lfdr.de
X-Gm-Message-State: AOJu0YyyRUBa7a7hyu1Uurbq5pmPZUriKPCjzsvZdI42YVtf5ANeeybY
	iC9OPBkqwXUHApPiEmRSwqZd+IrDbDFzZhWA0Eb3QFessmOLrU5dp3c8
X-Google-Smtp-Source: AGHT+IHhsoTwMzQnJh4PK1BbAw7wBGoRnKpHkfbeQRZZkBR3Y91yYqFl5Tp3rD751o7TZRw55Wo+RA==
X-Received: by 2002:a05:6402:1e8c:b0:615:69d4:22bd with SMTP id 4fb4d7f45d1cf-61586ba2d59mr7251221a12.0.1753962726442;
        Thu, 31 Jul 2025 04:52:06 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdy19VDVCc07PxhH1UylSr3araKpepzbxR4yqgSub5EyQ==
Received: by 2002:a05:6402:3547:b0:606:3146:5324 with SMTP id
 4fb4d7f45d1cf-615a5d97504ls648437a12.2.-pod-prod-07-eu; Thu, 31 Jul 2025
 04:52:03 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXLrJfTSkOlQys44etyG+5WGo5MVJ6A3X4Ced3eTTGfkh4a+Hl278yIH1iUdMHOD9XvdWoRmX1knyc=@googlegroups.com
X-Received: by 2002:a05:6402:1157:b0:614:fead:3d56 with SMTP id 4fb4d7f45d1cf-61587232e97mr6235448a12.32.1753962723688;
        Thu, 31 Jul 2025 04:52:03 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1753962723; cv=none;
        d=google.com; s=arc-20240605;
        b=iGvHQbQ1HIsEolPJfswMlVJoMoyA6jPZIdxa2KWZZYImZzbfQygDLpF0cMr6WwqYoM
         ouwD2F6YpWLMqR1sf7pZAiyWKb/8P3D54v1e7BH8mQUax8AO1jJEYg1w/kjOVi9ExKKh
         kzvHutFJyCr0z5Fca+RtnW7IwJUVZd9kr3VgsjdAuWQ6Axd3t13WB/NkZY+5t9/BGqUK
         uZf05B8omEmrfSS/Bn/N9TITF6MD+6GKgfFgl9Sq598e25UBWT1IdyCjUZkt4zbrXwof
         e1ME3K0pU8rDP8wqQnizMChP9cN3Ze/46hvCc+iDVanuz+ITN/LXQQVmXpZ+fmtfzFQ3
         6Wxg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=Wxltob97dGGsyXvDSMkg1S6ftRZJNYows0FnYbt40l0=;
        fh=p8ootj9Etu1hI8cWlBk+Hfd1NoU777dKbGZsEX9u7Gs=;
        b=kWo1Itx3vnUnfQtsEVK551YJpvEkvZu4Jy7NuBks7Qn7buzxlyPg2fVqBo1JLae/Je
         icJjaNAc56H1bLWVMFyxx9eZf/rW7YmEo9ZtGJs7fk6U2TWh3Eb7KEA1fyU2qqJoAYla
         gwjs1HDIdsgMcJLpKNTHCGRjIkEm3hAie8Dqf7OxwFlagZGngcIH+6ha6CffOZOMGpil
         FCmqtDgCrBjloDvHmbUM2GVFyiNwxARDNsEQbhCk6fIXiXqKEKhJDkl95o443jBiNPxD
         YN88KYPNYdlkOOkeNEjrmQx6iYvNktVphJV8Q9sTl9Q/sikOwQav1i/pMOECVHbytS3O
         4T2g==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=d9gq20mt;
       spf=pass (google.com: domain of 341ilaaykcq4uzwrs5u22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--glider.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=341iLaAYKCQ4uzwrs5u22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x34a.google.com (mail-wm1-x34a.google.com. [2a00:1450:4864:20::34a])
        by gmr-mx.google.com with ESMTPS id 4fb4d7f45d1cf-615a8673e72si46058a12.0.2025.07.31.04.52.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 31 Jul 2025 04:52:03 -0700 (PDT)
Received-SPF: pass (google.com: domain of 341ilaaykcq4uzwrs5u22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--glider.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) client-ip=2a00:1450:4864:20::34a;
Received: by mail-wm1-x34a.google.com with SMTP id 5b1f17b1804b1-4562985ac6aso5896765e9.3
        for <kasan-dev@googlegroups.com>; Thu, 31 Jul 2025 04:52:03 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVJBfkblTYAnF2jEv5Mf5cvRLo+aF1bv9Endw+IMw1kVcdOCbY2AnSJT20jOzgIJRBCkwkTBmsHxRs=@googlegroups.com
X-Received: from wmbet6.prod.google.com ([2002:a05:600c:8186:b0:454:d702:f3c2])
 (user=glider job=prod-delivery.src-stubby-dispatcher) by 2002:a05:600c:1f92:b0:43c:f44c:72a6
 with SMTP id 5b1f17b1804b1-45892b9341emr73441445e9.2.1753962723337; Thu, 31
 Jul 2025 04:52:03 -0700 (PDT)
Date: Thu, 31 Jul 2025 13:51:36 +0200
In-Reply-To: <20250731115139.3035888-1-glider@google.com>
Mime-Version: 1.0
References: <20250731115139.3035888-1-glider@google.com>
X-Mailer: git-send-email 2.50.1.552.g942d659e1b-goog
Message-ID: <20250731115139.3035888-8-glider@google.com>
Subject: [PATCH v4 07/10] kcov: add ioctl(KCOV_UNIQUE_ENABLE)
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
 header.i=@google.com header.s=20230601 header.b=d9gq20mt;       spf=pass
 (google.com: domain of 341ilaaykcq4uzwrs5u22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=341iLaAYKCQ4uzwrs5u22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--glider.bounces.google.com;
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

ioctl(KCOV_UNIQUE_ENABLE) enables collection of deduplicated coverage
in the presence of CONFIG_KCOV_ENABLE_GUARDS.

The buffer shared with the userspace is divided in two parts, one holding
a bitmap, and the other one being the trace. The single parameter of
ioctl(KCOV_UNIQUE_ENABLE) determines the number of words used for the
bitmap.

Each __sanitizer_cov_trace_pc_guard() instrumentation hook receives a
pointer to a unique guard variable. Upon the first call of each hook,
the guard variable is initialized with a unique integer, which is used to
map those hooks to bits in the bitmap. In the new coverage collection mode,
the kernel first checks whether the bit corresponding to a particular hook
is set, and then, if it is not, the PC is written into the trace buffer,
and the bit is set.

Note: when CONFIG_KCOV_ENABLE_GUARDS is disabled, ioctl(KCOV_UNIQUE_ENABLE)
returns -ENOTSUPP, which is consistent with the existing kcov code.

Measuring the exact performance impact of this mode directly can be
challenging. However, based on fuzzing experiments (50 instances x 24h
with and without deduplication), we observe the following:
 - When normalized by pure fuzzing time, total executions decreased
   by 2.1% (p=0.01).
 - When normalized by fuzzer uptime, the reduction in total executions
   was statistically insignificant (-1.0% with p=0.20).
Despite a potential slight slowdown in execution count, the new mode
positively impacts fuzzing effectiveness:
 - Statistically significant increase in corpus size (+0.6%, p<0.01).
 - Statistically significant increase in coverage (+0.6%, p<0.01).
 - A 99.8% reduction in coverage overflows.

Also update the documentation.

Signed-off-by: Alexander Potapenko <glider@google.com>
Reviewed-by: Dmitry Vyukov <dvyukov@google.com>
---
v4:
 Add Reviewed-by: Dmitry Vyukov

v3:
 - s/check_kcov_mode/get_kcov_mode in objtool

v2:
 - Address comments by Dmitry Vyukov:
   - rename CONFIG_KCOV_ENABLE_GUARDS to CONFIG_KCOV_UNIQUE
   - rename KCOV_MODE_TRACE_UNIQUE_PC to KCOV_MODE_UNIQUE_PC
   - simplify index allocation
   - update documentation and comments
 - Address comments by Marco Elver:
   - change _IOR to _IOW in KCOV_UNIQUE_ENABLE definition
   - rename sanitizer_cov_write_subsequent() to kcov_append_to_buffer()
 - Use __test_and_set_bit() to avoid the lock prefix on the bit operation
 - Update code to match the new description of struct kcov_state
 - Rename kcov_get_mode() to kcov_arg_to_mode() to avoid confusion with
   get_kcov_mode(). Also make it use `enum kcov_mode`.

Change-Id: I9805e7b22619a50e05cc7c7d794dacf6f7de2f03
---
 Documentation/dev-tools/kcov.rst |  43 ++++++++
 include/linux/kcov.h             |   2 +
 include/linux/kcov_types.h       |   8 ++
 include/uapi/linux/kcov.h        |   1 +
 kernel/kcov.c                    | 164 ++++++++++++++++++++++++++-----
 tools/objtool/check.c            |   2 +-
 6 files changed, 193 insertions(+), 27 deletions(-)

diff --git a/Documentation/dev-tools/kcov.rst b/Documentation/dev-tools/kcov.rst
index abf3ad2e784e8..6446887cd1c92 100644
--- a/Documentation/dev-tools/kcov.rst
+++ b/Documentation/dev-tools/kcov.rst
@@ -192,6 +192,49 @@ Normally the shared buffer is used as follows::
     up to the buffer[0] value saved above    |
 
 
+Unique coverage collection
+---------------------------
+
+Instead of collecting a trace of PCs, KCOV can deduplicate them on the fly.
+This mode is enabled by the ``KCOV_UNIQUE_ENABLE`` ioctl (only available if
+``CONFIG_KCOV_UNIQUE`` is on).
+
+.. code-block:: c
+
+	/* Same includes and defines as above. */
+	#define KCOV_UNIQUE_ENABLE		_IOW('c', 103, unsigned long)
+	#define BITMAP_SIZE			(4<<10)
+
+	/* Instead of KCOV_ENABLE, enable unique coverage collection. */
+	if (ioctl(fd, KCOV_UNIQUE_ENABLE, BITMAP_SIZE))
+		perror("ioctl"), exit(1);
+	/* Reset the coverage from the tail of the ioctl() call. */
+	__atomic_store_n(&cover[BITMAP_SIZE], 0, __ATOMIC_RELAXED);
+	memset(cover, 0, BITMAP_SIZE * sizeof(unsigned long));
+
+	/* Call the target syscall call. */
+	/* ... */
+
+	/* Read the number of collected PCs. */
+	n = __atomic_load_n(&cover[BITMAP_SIZE], __ATOMIC_RELAXED);
+	/* Disable the coverage collection. */
+	if (ioctl(fd, KCOV_DISABLE, 0))
+		perror("ioctl"), exit(1);
+
+Calling ``ioctl(fd, KCOV_UNIQUE_ENABLE, bitmap_size)`` carves out ``bitmap_size``
+unsigned long's from those allocated by ``KCOV_INIT_TRACE`` to keep an opaque
+bitmap that prevents the kernel from storing the same PC twice. The remaining
+part of the buffer is used to collect PCs, like in other modes (this part must
+contain at least two unsigned long's, like when collecting non-unique PCs).
+
+The mapping between a PC and its position in the bitmap is persistent during the
+kernel lifetime, so it is possible for the callers to directly use the bitmap
+contents as a coverage signal (like when fuzzing userspace with AFL).
+
+In order to reset the coverage between the runs, the user needs to rewind the
+trace (by writing 0 into the first buffer element past ``bitmap_size``) and zero
+the whole bitmap.
+
 Comparison operands collection
 ------------------------------
 
diff --git a/include/linux/kcov.h b/include/linux/kcov.h
index 2acccfa5ae9af..cea2e62723ef9 100644
--- a/include/linux/kcov.h
+++ b/include/linux/kcov.h
@@ -10,6 +10,7 @@ struct task_struct;
 #ifdef CONFIG_KCOV
 
 enum kcov_mode {
+	KCOV_MODE_INVALID = -1,
 	/* Coverage collection is not enabled yet. */
 	KCOV_MODE_DISABLED = 0,
 	/* KCOV was initialized, but tracing mode hasn't been chosen yet. */
@@ -23,6 +24,7 @@ enum kcov_mode {
 	KCOV_MODE_TRACE_CMP = 3,
 	/* The process owns a KCOV remote reference. */
 	KCOV_MODE_REMOTE = 4,
+	KCOV_MODE_UNIQUE_PC = 5,
 };
 
 #define KCOV_IN_CTXSW	(1 << 30)
diff --git a/include/linux/kcov_types.h b/include/linux/kcov_types.h
index 9d38a2020b099..8be930f47cd78 100644
--- a/include/linux/kcov_types.h
+++ b/include/linux/kcov_types.h
@@ -18,6 +18,14 @@ struct kcov_state {
 	/* Buffer for coverage collection, shared with the userspace. */
 	unsigned long *trace;
 
+	/* Size of the bitmap (in bits). */
+	unsigned int bitmap_size;
+	/*
+	 * Bitmap for coverage deduplication, shared with the
+	 * userspace.
+	 */
+	unsigned long *bitmap;
+
 	/*
 	 * KCOV sequence number: incremented each time kcov is reenabled, used
 	 * by kcov_remote_stop(), see the comment there.
diff --git a/include/uapi/linux/kcov.h b/include/uapi/linux/kcov.h
index ed95dba9fa37e..e743ee011eeca 100644
--- a/include/uapi/linux/kcov.h
+++ b/include/uapi/linux/kcov.h
@@ -22,6 +22,7 @@ struct kcov_remote_arg {
 #define KCOV_ENABLE			_IO('c', 100)
 #define KCOV_DISABLE			_IO('c', 101)
 #define KCOV_REMOTE_ENABLE		_IOW('c', 102, struct kcov_remote_arg)
+#define KCOV_UNIQUE_ENABLE		_IOW('c', 103, unsigned long)
 
 enum {
 	/*
diff --git a/kernel/kcov.c b/kernel/kcov.c
index 2005fc7f578ee..a92c848d17bce 100644
--- a/kernel/kcov.c
+++ b/kernel/kcov.c
@@ -28,6 +28,10 @@
 #include <linux/log2.h>
 #include <asm/setup.h>
 
+#ifdef CONFIG_KCOV_UNIQUE
+atomic_t kcov_guard_max_index = ATOMIC_INIT(0);
+#endif
+
 #define kcov_debug(fmt, ...) pr_debug("%s: " fmt, __func__, ##__VA_ARGS__)
 
 /* Number of 64-bit words written per one comparison: */
@@ -163,9 +167,9 @@ static __always_inline bool in_softirq_really(void)
 	return in_serving_softirq() && !in_hardirq() && !in_nmi();
 }
 
-static notrace bool check_kcov_mode(enum kcov_mode needed_mode, struct task_struct *t)
+static notrace enum kcov_mode get_kcov_mode(struct task_struct *t)
 {
-	unsigned int mode;
+	enum kcov_mode mode;
 
 	/*
 	 * We are interested in code coverage as a function of a syscall inputs,
@@ -173,7 +177,7 @@ static notrace bool check_kcov_mode(enum kcov_mode needed_mode, struct task_stru
 	 * coverage collection section in a softirq.
 	 */
 	if (!in_task() && !(in_softirq_really() && t->kcov_softirq))
-		return false;
+		return KCOV_MODE_INVALID;
 	mode = READ_ONCE(t->kcov_mode);
 	/*
 	 * There is some code that runs in interrupts but for which
@@ -183,7 +187,7 @@ static notrace bool check_kcov_mode(enum kcov_mode needed_mode, struct task_stru
 	 * kcov_start().
 	 */
 	barrier();
-	return mode == needed_mode;
+	return mode;
 }
 
 static notrace unsigned long canonicalize_ip(unsigned long ip)
@@ -202,7 +206,7 @@ static notrace void kcov_append_to_buffer(unsigned long *trace, int size,
 
 	if (likely(pos < size)) {
 		/*
-		 * Some early interrupt code could bypass check_kcov_mode() check
+		 * Some early interrupt code could bypass get_kcov_mode() check
 		 * and invoke __sanitizer_cov_trace_pc(). If such interrupt is
 		 * raised between writing pc and updating pos, the pc could be
 		 * overitten by the recursive __sanitizer_cov_trace_pc().
@@ -219,14 +223,76 @@ static notrace void kcov_append_to_buffer(unsigned long *trace, int size,
  * This is called once per basic-block/edge.
  */
 #ifdef CONFIG_KCOV_UNIQUE
+DEFINE_PER_CPU(u32, saved_index);
+/*
+ * Assign an index to a guard variable that does not have one yet.
+ * For an unlikely case of a race with another task executing the same basic
+ * block for the first time with kcov enabled, we store the unused index in a
+ * per-cpu variable.
+ * In an even less likely case of the current task losing the race and getting
+ * rescheduled onto a CPU that already has a saved index, the index is
+ * discarded. This will result in an unused hole in the bitmap, but such events
+ * should have minor impact on the overall memory consumption.
+ */
+static __always_inline u32 init_pc_guard(u32 *guard)
+{
+	/* If the current CPU has a saved free index, use it. */
+	u32 index = this_cpu_xchg(saved_index, 0);
+	u32 old_guard;
+
+	if (likely(!index))
+		/*
+		 * Allocate a new index. No overflow is possible, because 2**32
+		 * unique basic blocks will take more space than the max size
+		 * of the kernel text segment.
+		 */
+		index = atomic_inc_return(&kcov_guard_max_index);
+
+	/*
+	 * Make sure another task is not initializing the same guard
+	 * concurrently.
+	 */
+	old_guard = cmpxchg(guard, 0, index);
+	if (unlikely(old_guard)) {
+		/* We lost the race, save the index for future use. */
+		this_cpu_write(saved_index, index);
+		return old_guard;
+	}
+	return index;
+}
+
 void notrace __sanitizer_cov_trace_pc_guard(u32 *guard)
 {
-	if (!check_kcov_mode(KCOV_MODE_TRACE_PC, current))
-		return;
+	enum kcov_mode mode = get_kcov_mode(current);
+	u32 pc_index;
 
-	kcov_append_to_buffer(current->kcov_state.trace,
-			      current->kcov_state.trace_size,
-			      canonicalize_ip(_RET_IP_));
+	switch (mode) {
+	case KCOV_MODE_UNIQUE_PC:
+		pc_index = READ_ONCE(*guard);
+		if (unlikely(!pc_index))
+			pc_index = init_pc_guard(guard);
+
+		/*
+		 * Use the bitmap for coverage deduplication. We assume both
+		 * s.bitmap and s.trace are non-NULL.
+		 */
+		if (likely(pc_index < current->kcov_state.bitmap_size))
+			if (__test_and_set_bit(pc_index,
+					       current->kcov_state.bitmap))
+				return;
+		/*
+		 * If the PC is new, or the bitmap is too small, write PC to the
+		 * trace.
+		 */
+		fallthrough;
+	case KCOV_MODE_TRACE_PC:
+		kcov_append_to_buffer(current->kcov_state.trace,
+				      current->kcov_state.trace_size,
+				      canonicalize_ip(_RET_IP_));
+		break;
+	default:
+		return;
+	}
 }
 EXPORT_SYMBOL(__sanitizer_cov_trace_pc_guard);
 
@@ -238,7 +304,7 @@ EXPORT_SYMBOL(__sanitizer_cov_trace_pc_guard_init);
 #else /* !CONFIG_KCOV_UNIQUE */
 void notrace __sanitizer_cov_trace_pc(void)
 {
-	if (!check_kcov_mode(KCOV_MODE_TRACE_PC, current))
+	if (get_kcov_mode(current) != KCOV_MODE_TRACE_PC)
 		return;
 
 	kcov_append_to_buffer(current->kcov_state.trace,
@@ -256,7 +322,7 @@ static void notrace write_comp_data(u64 type, u64 arg1, u64 arg2, u64 ip)
 	u64 *trace;
 
 	t = current;
-	if (!check_kcov_mode(KCOV_MODE_TRACE_CMP, t))
+	if (get_kcov_mode(t) != KCOV_MODE_TRACE_CMP)
 		return;
 
 	ip = canonicalize_ip(ip);
@@ -374,7 +440,7 @@ static void kcov_start(struct task_struct *t, struct kcov *kcov,
 	t->kcov = kcov;
 	/* Cache in task struct for performance. */
 	t->kcov_state = *state;
-	/* See comment in check_kcov_mode(). */
+	/* See comment in get_kcov_mode(). */
 	barrier();
 	WRITE_ONCE(t->kcov_mode, mode);
 }
@@ -409,6 +475,10 @@ static void kcov_reset(struct kcov *kcov)
 	kcov->mode = KCOV_MODE_INIT;
 	kcov->remote = false;
 	kcov->remote_size = 0;
+	kcov->state.trace = kcov->state.area;
+	kcov->state.trace_size = kcov->state.size;
+	kcov->state.bitmap = NULL;
+	kcov->state.bitmap_size = 0;
 	kcov->state.sequence++;
 }
 
@@ -549,18 +619,23 @@ static int kcov_close(struct inode *inode, struct file *filep)
 	return 0;
 }
 
-static int kcov_get_mode(unsigned long arg)
+static enum kcov_mode kcov_arg_to_mode(unsigned long arg, int *error)
 {
-	if (arg == KCOV_TRACE_PC)
+	if (arg == KCOV_TRACE_PC) {
 		return KCOV_MODE_TRACE_PC;
-	else if (arg == KCOV_TRACE_CMP)
+	} else if (arg == KCOV_TRACE_CMP) {
 #ifdef CONFIG_KCOV_ENABLE_COMPARISONS
 		return KCOV_MODE_TRACE_CMP;
 #else
-		return -ENOTSUPP;
+		if (error)
+			*error = -ENOTSUPP;
+		return KCOV_MODE_INVALID;
 #endif
-	else
-		return -EINVAL;
+	} else {
+		if (error)
+			*error = -EINVAL;
+		return KCOV_MODE_INVALID;
+	}
 }
 
 /*
@@ -595,12 +670,47 @@ static inline bool kcov_check_handle(u64 handle, bool common_valid,
 	return false;
 }
 
+static long kcov_handle_unique_enable(struct kcov *kcov,
+				      unsigned long bitmap_words)
+{
+	struct task_struct *t = current;
+
+	if (!IS_ENABLED(CONFIG_KCOV_UNIQUE))
+		return -ENOTSUPP;
+	if (kcov->mode != KCOV_MODE_INIT || !kcov->state.area)
+		return -EINVAL;
+	if (kcov->t != NULL || t->kcov != NULL)
+		return -EBUSY;
+
+	/*
+	 * Cannot use zero-sized bitmap, also the bitmap must leave at least two
+	 * words for the trace.
+	 */
+	if ((!bitmap_words) || (bitmap_words >= (kcov->state.size - 1)))
+		return -EINVAL;
+
+	kcov->state.bitmap_size = bitmap_words * sizeof(unsigned long) * 8;
+	kcov->state.bitmap = kcov->state.area;
+	kcov->state.trace_size = kcov->state.size - bitmap_words;
+	kcov->state.trace = ((unsigned long *)kcov->state.area + bitmap_words);
+
+	kcov_fault_in_area(kcov);
+	kcov->mode = KCOV_MODE_UNIQUE_PC;
+	kcov_start(t, kcov, kcov->mode, &kcov->state);
+	kcov->t = t;
+	/* Put either in kcov_task_exit() or in KCOV_DISABLE. */
+	kcov_get(kcov);
+
+	return 0;
+}
+
 static int kcov_ioctl_locked(struct kcov *kcov, unsigned int cmd,
 			     unsigned long arg)
 {
 	struct task_struct *t;
 	unsigned long flags, unused;
-	int mode, i;
+	enum kcov_mode mode;
+	int error = 0, i;
 	struct kcov_remote_arg *remote_arg;
 	struct kcov_remote *remote;
 
@@ -618,9 +728,9 @@ static int kcov_ioctl_locked(struct kcov *kcov, unsigned int cmd,
 		t = current;
 		if (kcov->t != NULL || t->kcov != NULL)
 			return -EBUSY;
-		mode = kcov_get_mode(arg);
-		if (mode < 0)
-			return mode;
+		mode = kcov_arg_to_mode(arg, &error);
+		if (mode == KCOV_MODE_INVALID)
+			return error;
 		kcov_fault_in_area(kcov);
 		kcov->mode = mode;
 		kcov_start(t, kcov, mode, &kcov->state);
@@ -628,6 +738,8 @@ static int kcov_ioctl_locked(struct kcov *kcov, unsigned int cmd,
 		/* Put either in kcov_task_exit() or in KCOV_DISABLE. */
 		kcov_get(kcov);
 		return 0;
+	case KCOV_UNIQUE_ENABLE:
+		return kcov_handle_unique_enable(kcov, arg);
 	case KCOV_DISABLE:
 		/* Disable coverage for the current task. */
 		unused = arg;
@@ -646,9 +758,9 @@ static int kcov_ioctl_locked(struct kcov *kcov, unsigned int cmd,
 		if (kcov->t != NULL || t->kcov != NULL)
 			return -EBUSY;
 		remote_arg = (struct kcov_remote_arg *)arg;
-		mode = kcov_get_mode(remote_arg->trace_mode);
-		if (mode < 0)
-			return mode;
+		mode = kcov_arg_to_mode(remote_arg->trace_mode, &error);
+		if (mode == KCOV_MODE_INVALID)
+			return error;
 		if ((unsigned long)remote_arg->area_size >
 		    LONG_MAX / sizeof(unsigned long))
 			return -EINVAL;
diff --git a/tools/objtool/check.c b/tools/objtool/check.c
index 60eb5faa27d28..f4ec041de0224 100644
--- a/tools/objtool/check.c
+++ b/tools/objtool/check.c
@@ -1154,7 +1154,7 @@ static const char *uaccess_safe_builtin[] = {
 	"__tsan_unaligned_write16",
 	/* KCOV */
 	"write_comp_data",
-	"check_kcov_mode",
+	"get_kcov_mode",
 	"__sanitizer_cov_trace_pc",
 	"__sanitizer_cov_trace_pc_guard",
 	"__sanitizer_cov_trace_const_cmp1",
-- 
2.50.1.552.g942d659e1b-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250731115139.3035888-8-glider%40google.com.
