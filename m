Return-Path: <kasan-dev+bncBCCMH5WKTMGRBQ446XBAMGQEYNFLLPI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33c.google.com (mail-wm1-x33c.google.com [IPv6:2a00:1450:4864:20::33c])
	by mail.lfdr.de (Postfix) with ESMTPS id 16175AE9F32
	for <lists+kasan-dev@lfdr.de>; Thu, 26 Jun 2025 15:42:31 +0200 (CEST)
Received: by mail-wm1-x33c.google.com with SMTP id 5b1f17b1804b1-451d7de4ae3sf5616545e9.2
        for <lists+kasan-dev@lfdr.de>; Thu, 26 Jun 2025 06:42:31 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1750945348; cv=pass;
        d=google.com; s=arc-20240605;
        b=jlrZjc0X+FNVv3+NmI8iH4K9oSxbXhrFFOzvsEm8BWuZ+Ene9vEHNKKqfTTHA7SHmx
         53ooR6RwU3IhKDeOCp81oAFwfNKMM0E7/r7ArKEPqSI+BF/bzQreIT+btJHk1ONJPdFu
         Lx74skw6Qt0x1Jzbx4zY/aLCgMeeWiXBeVZJd+IPNkBhTCxbg/h8GXKjQQMzVHtUuNNu
         jwSSeoFc/Yi1QsFxdAK97wU2ets9YAI90pSaeePakL/Rof6VJQCFecNORjbFIQegE2gZ
         jWqQkHbXF4+rvuhfi05GBZ278Bt+v4onx/XoniIhRdNW9l9I+0U1U/0KM/zot4jaAeE2
         VmAw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=rcC+3tJbOSZYrhO5rFzie18avkWBLgmZqyVS8UgA2tA=;
        fh=278uyyDy2fNMuA+sr2UIFku8Jstg9gl823v5wgfV+KQ=;
        b=Z7jqLq0R1Pin2V2LVg3SSF/xE6OpFPJtwCvw1gVnk18idN6Nc3aE01Kg0Mn19OPZnB
         tnw6z9VKCHpkew1QB+J4k6enVF+vuS2c3rufw9O3v/oaLh4vPjnI8Nhof8hZNxHYOYBX
         3olIKQLRf1FzGpqUto9klckBjfw8k1EHe6LMwyLc9w9G4/bIlLeB87w7LSfJ6VTDIs+J
         TdpMcOGqGcH5O0R1YK3YTXnAOnw1JkUwEvVSr0+1J31Amfi0z+pw0763svhBXplxl05M
         V0XVk7yP3kVcdkKdwET0IDluLE+M852NZai5JTdgo4+Usu9okPXnx9wRs/mrVRwVy6cP
         PpUQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=qgUXogvY;
       spf=pass (google.com: domain of 3qe5daaykczsbgd89mbjjbg9.7jhf5n5i-89qbjjbg9bmjpkn.7jh@flex--glider.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3QE5daAYKCZsBGD89MBJJBG9.7JHF5N5I-89QBJJBG9BMJPKN.7JH@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1750945348; x=1751550148; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=rcC+3tJbOSZYrhO5rFzie18avkWBLgmZqyVS8UgA2tA=;
        b=qXCfHQ1XOUJ7JfEPpdfk2NhXe/CNkD38NT4TwHuIgFm/xDh7CIIYNO10vPNuS0NzHg
         2hDVtPOHDGbF8uhCYu4V8gORBDu75aWkoXZGaeNCG/mowxuznCEb3DDO+4xk5PhhC+GH
         j63E6YLiRZP9hVQct/ilgEdNHHE78filzB7rwe1hSAHtvt7p4XrEkzuMx4NtfhG47a6b
         elUz+l02Q6NCvF/GB0suTIwL7N9Wk8XAgLn8fAJ7OpvfZKubsNYnJFGUkItqoKwF+2Se
         6F0nSXQoY7WEo+5LhdSTiQtUADKLlfbkHdZZGQNmo44NIdFFCUH1YicoiVpM/Ve8wVKM
         sEow==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1750945348; x=1751550148;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=rcC+3tJbOSZYrhO5rFzie18avkWBLgmZqyVS8UgA2tA=;
        b=KDZuoCRDXL4tLMORH9vhKf76WJjmWfrmco8LIW20XVg7CEXlolmZdxeIxNk/hXrRgI
         ugtKM+fukMG4PKzyNc64hbltKCzja4Pkp/xGGSHhjb7kJgL8Z3qpv0pVq5nmr2e4pD2L
         UG+dkg0husB1Ugv7YRAt8+7GMCo7PJSx7eHu7ylRqaUl/qmNtTErlYFqilNJ8UIpg6kX
         IXyW3/yaYd67dcTCj89Shx6CfXLZDZ4zVQ/vPhr42dBic8Tm4Gwviq+pMP6VPy1x09TT
         IuWc65Jj0bKaNsb4bGhU1Vn/+0HTbe3j9EZanbs4KKFGIj3kBB07HkYaysmwcZCCvNSI
         jc6A==
X-Forwarded-Encrypted: i=2; AJvYcCV4wAa7qdzC9CAjd5PUb0XFj/B5u/0ZN5U7r7nQ33vXuXXYGDo0jmMqmx1svSaWhBzucJdn2A==@lfdr.de
X-Gm-Message-State: AOJu0Yw37viAcQu47nF5hevoi/GCLusri6AFEAYXG6UvcJqsYOXdL+10
	hTT1XXcAvu2eszCPRCZPnRzgAtI2chacv9eaKHEexvMMlFFpnE20BJ1d
X-Google-Smtp-Source: AGHT+IFnqzm3bkbxvPqAFnugoimVMqyjtVGxYuQPVatpUNd4xJLH9DrTUyP3B2plWBPZDHHxG4+v0g==
X-Received: by 2002:a05:600c:c491:b0:450:d37d:7c with SMTP id 5b1f17b1804b1-45389e486f7mr27738845e9.21.1750945348009;
        Thu, 26 Jun 2025 06:42:28 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcLx2Tm4v2sjf1xdqnXbqA35a7r7rWhzyuynwxUcldOxA==
Received: by 2002:a05:600c:37c6:b0:453:dbe:7585 with SMTP id
 5b1f17b1804b1-4538ab3bcfels4553975e9.1.-pod-prod-04-eu; Thu, 26 Jun 2025
 06:42:25 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCV+xUjfjwe0+6UyVHhvchwVJ9u1NMghw0E5j6mu55u70JpqQhfUsqkOCwC2sFd8Hy7UYKkjEbHtexE=@googlegroups.com
X-Received: by 2002:a05:600c:a48:b0:450:d4a6:799e with SMTP id 5b1f17b1804b1-45381af6b04mr64099075e9.20.1750945345357;
        Thu, 26 Jun 2025 06:42:25 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1750945345; cv=none;
        d=google.com; s=arc-20240605;
        b=HGqi2RlALGu8pQBJzzT6RJuy7ic94yhzdF918CEB6XBKs7QOL5FkQPrsVrKBjLbNer
         DUnJHbTQd1d6cZTYgOM1Gb/GZqYrjBF3mpFrvr/AfiN2znZehO3xiTIR5Y0HOlWKNYXS
         xcrz40FpK7v6Uq8N3A1c0Ouj3vtXbPAeVs0vCU2oI/oAvOjIgfuO/ap4uPcHkqhkIchO
         vAvFOsymIhePQaZuWaw7DF6J9qfyi9VCmrdKKQy8FNNKa/EB8BEE5NgRjwBnLyyGW6NS
         RlGiljJjFWO5VVDcWtnoTukNOjUWhwtGg94/35t/EIyijSVtG5rFYJW90uqOJ5SDcuK/
         1/nw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=gRtiAm1l+bCEDwUYq636VEWKycADCHU49+iX/HPvsao=;
        fh=inqigQqAvCyKN3PXT7MwizRGPiIdN8J9u41Vitq3mjA=;
        b=eSZ/WAGyll6GZ15GP5nIURYX90Hq1NFq8uGIh54qT/DjKogxRS9/deZuNuLPMDRnHI
         70pjPPWJwDidBhZSaaRH9UtJJf1REdc+VuXV/kiLn8hUf8cjXjcJAKdNWQ74LVYuS5k0
         xbSrtvwZHqr26nIA3tOjhnwo8EFyyhzQLA4kTxsFnrI7flSiOkT5jXA5pQLP8mVc9BL0
         JBUICERfYemPFz2E7idI4cmB1PtZOusmfd4855hlFD+JLYYF/9LLbF6aIYH27cyh8hZw
         IShLSJvlgLIkbIZhlK2MYE+w5xBvvY+UnrTofO5/r1vVg9E8HfvhPoweInRkKJJqYoJH
         Nrag==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=qgUXogvY;
       spf=pass (google.com: domain of 3qe5daaykczsbgd89mbjjbg9.7jhf5n5i-89qbjjbg9bmjpkn.7jh@flex--glider.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3QE5daAYKCZsBGD89MBJJBG9.7JHF5N5I-89QBJJBG9BMJPKN.7JH@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-ed1-x549.google.com (mail-ed1-x549.google.com. [2a00:1450:4864:20::549])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-45380fced22si1110335e9.0.2025.06.26.06.42.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 26 Jun 2025 06:42:25 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3qe5daaykczsbgd89mbjjbg9.7jhf5n5i-89qbjjbg9bmjpkn.7jh@flex--glider.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) client-ip=2a00:1450:4864:20::549;
Received: by mail-ed1-x549.google.com with SMTP id 4fb4d7f45d1cf-60c4f7964c4so756086a12.1
        for <kasan-dev@googlegroups.com>; Thu, 26 Jun 2025 06:42:25 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXI1HiQHf32OhlrZqrnINpWYxqMw8RGOggcpDO/Iv6N+qIfKB/oVdB+DP+H2LeIvWntGyzh2q+6bIc=@googlegroups.com
X-Received: from edbz3.prod.google.com ([2002:a05:6402:40c3:b0:607:2153:28eb])
 (user=glider job=prod-delivery.src-stubby-dispatcher) by 2002:a05:6402:278a:b0:60c:4a96:423a
 with SMTP id 4fb4d7f45d1cf-60c4dd6eff6mr6768547a12.18.1750945344630; Thu, 26
 Jun 2025 06:42:24 -0700 (PDT)
Date: Thu, 26 Jun 2025 15:41:55 +0200
In-Reply-To: <20250626134158.3385080-1-glider@google.com>
Mime-Version: 1.0
References: <20250626134158.3385080-1-glider@google.com>
X-Mailer: git-send-email 2.50.0.727.gbf7dc18ff4-goog
Message-ID: <20250626134158.3385080-9-glider@google.com>
Subject: [PATCH v2 08/11] kcov: add ioctl(KCOV_UNIQUE_ENABLE)
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
 header.i=@google.com header.s=20230601 header.b=qgUXogvY;       spf=pass
 (google.com: domain of 3qe5daaykczsbgd89mbjjbg9.7jhf5n5i-89qbjjbg9bmjpkn.7jh@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3QE5daAYKCZsBGD89MBJJBG9.7JHF5N5I-89QBJJBG9BMJPKN.7JH@flex--glider.bounces.google.com;
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
---
Change-Id: I9805e7b22619a50e05cc7c7d794dacf6f7de2f03

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
---
 Documentation/dev-tools/kcov.rst |  43 ++++++++
 include/linux/kcov.h             |   2 +
 include/linux/kcov_types.h       |   8 ++
 include/uapi/linux/kcov.h        |   1 +
 kernel/kcov.c                    | 165 ++++++++++++++++++++++++++-----
 5 files changed, 192 insertions(+), 27 deletions(-)

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
index dd8bbee6fe274..13c120a894107 100644
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
 
 #define KCOV_IN_CTXSW (1 << 30)
diff --git a/include/linux/kcov_types.h b/include/linux/kcov_types.h
index 233e7a682654b..5ab6e13a9e725 100644
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
index 038261145cf93..2a4edbaad50d0 100644
--- a/kernel/kcov.c
+++ b/kernel/kcov.c
@@ -29,6 +29,10 @@
 
 #include <asm/setup.h>
 
+#ifdef CONFIG_KCOV_UNIQUE
+atomic_t kcov_guard_max_index = ATOMIC_INIT(0);
+#endif
+
 #define kcov_debug(fmt, ...) pr_debug("%s: " fmt, __func__, ##__VA_ARGS__)
 
 /* Number of 64-bit words written per one comparison: */
@@ -163,10 +167,9 @@ static __always_inline bool in_softirq_really(void)
 	return in_serving_softirq() && !in_hardirq() && !in_nmi();
 }
 
-static notrace bool check_kcov_mode(enum kcov_mode needed_mode,
-				    struct task_struct *t)
+static notrace enum kcov_mode get_kcov_mode(struct task_struct *t)
 {
-	unsigned int mode;
+	enum kcov_mode mode;
 
 	/*
 	 * We are interested in code coverage as a function of a syscall inputs,
@@ -174,7 +177,7 @@ static notrace bool check_kcov_mode(enum kcov_mode needed_mode,
 	 * coverage collection section in a softirq.
 	 */
 	if (!in_task() && !(in_softirq_really() && t->kcov_softirq))
-		return false;
+		return KCOV_MODE_INVALID;
 	mode = READ_ONCE(t->kcov_mode);
 	/*
 	 * There is some code that runs in interrupts but for which
@@ -184,7 +187,7 @@ static notrace bool check_kcov_mode(enum kcov_mode needed_mode,
 	 * kcov_start().
 	 */
 	barrier();
-	return mode == needed_mode;
+	return mode;
 }
 
 static notrace unsigned long canonicalize_ip(unsigned long ip)
@@ -203,7 +206,7 @@ static notrace void kcov_append_to_buffer(unsigned long *trace, int size,
 
 	if (likely(pos < size)) {
 		/*
-		 * Some early interrupt code could bypass check_kcov_mode() check
+		 * Some early interrupt code could bypass get_kcov_mode() check
 		 * and invoke __sanitizer_cov_trace_pc(). If such interrupt is
 		 * raised between writing pc and updating pos, the pc could be
 		 * overitten by the recursive __sanitizer_cov_trace_pc().
@@ -220,14 +223,76 @@ static notrace void kcov_append_to_buffer(unsigned long *trace, int size,
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
 
@@ -239,7 +304,7 @@ EXPORT_SYMBOL(__sanitizer_cov_trace_pc_guard_init);
 #else /* !CONFIG_KCOV_UNIQUE */
 void notrace __sanitizer_cov_trace_pc(void)
 {
-	if (!check_kcov_mode(KCOV_MODE_TRACE_PC, current))
+	if (get_kcov_mode(current) != KCOV_MODE_TRACE_PC)
 		return;
 
 	kcov_append_to_buffer(current->kcov_state.trace,
@@ -257,7 +322,7 @@ static void notrace write_comp_data(u64 type, u64 arg1, u64 arg2, u64 ip)
 	u64 *trace;
 
 	t = current;
-	if (!check_kcov_mode(KCOV_MODE_TRACE_CMP, t))
+	if (get_kcov_mode(t) != KCOV_MODE_TRACE_CMP)
 		return;
 
 	ip = canonicalize_ip(ip);
@@ -376,7 +441,7 @@ static void kcov_start(struct task_struct *t, struct kcov *kcov,
 	/* Cache in task struct for performance. */
 	t->kcov_state = *state;
 	barrier();
-	/* See comment in check_kcov_mode(). */
+	/* See comment in get_kcov_mode(). */
 	WRITE_ONCE(t->kcov_mode, mode);
 }
 
@@ -410,6 +475,10 @@ static void kcov_reset(struct kcov *kcov)
 	kcov->mode = KCOV_MODE_INIT;
 	kcov->remote = false;
 	kcov->remote_size = 0;
+	kcov->state.trace = kcov->state.area;
+	kcov->state.trace_size = kcov->state.size;
+	kcov->state.bitmap = NULL;
+	kcov->state.bitmap_size = 0;
 	kcov->state.sequence++;
 }
 
@@ -550,18 +619,23 @@ static int kcov_close(struct inode *inode, struct file *filep)
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
@@ -596,12 +670,47 @@ static inline bool kcov_check_handle(u64 handle, bool common_valid,
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
 
@@ -619,9 +728,9 @@ static int kcov_ioctl_locked(struct kcov *kcov, unsigned int cmd,
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
@@ -629,6 +738,8 @@ static int kcov_ioctl_locked(struct kcov *kcov, unsigned int cmd,
 		/* Put either in kcov_task_exit() or in KCOV_DISABLE. */
 		kcov_get(kcov);
 		return 0;
+	case KCOV_UNIQUE_ENABLE:
+		return kcov_handle_unique_enable(kcov, arg);
 	case KCOV_DISABLE:
 		/* Disable coverage for the current task. */
 		unused = arg;
@@ -647,9 +758,9 @@ static int kcov_ioctl_locked(struct kcov *kcov, unsigned int cmd,
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
-- 
2.50.0.727.gbf7dc18ff4-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250626134158.3385080-9-glider%40google.com.
