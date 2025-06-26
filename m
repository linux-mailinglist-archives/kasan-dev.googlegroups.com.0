Return-Path: <kasan-dev+bncBCCMH5WKTMGRBRU46XBAMGQEXOBTLJI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43e.google.com (mail-wr1-x43e.google.com [IPv6:2a00:1450:4864:20::43e])
	by mail.lfdr.de (Postfix) with ESMTPS id C38B8AE9F33
	for <lists+kasan-dev@lfdr.de>; Thu, 26 Jun 2025 15:42:31 +0200 (CEST)
Received: by mail-wr1-x43e.google.com with SMTP id ffacd0b85a97d-3a50816ccc6sf654017f8f.1
        for <lists+kasan-dev@lfdr.de>; Thu, 26 Jun 2025 06:42:31 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1750945351; cv=pass;
        d=google.com; s=arc-20240605;
        b=cSZpWVG17MKoOMuRf0MFb3c6qETFHwAVmZtiv8q5KoPWOqQcKxBJzs//Ab2+h099yn
         TNufyL0mGOluLIv2knsvNKvCVpmhm8yimjSVuCcXpQRcMHWYN5wQpdHyz9rEtrGSMLLO
         OT4E8JiZrQSfJ+Y3yqSuxd6D9cqq5R821zZckbpHUGtAgXrquM9HeEuduGFApL0VGcfV
         QFf0KLX2aZV8v1Px/H4TYCr7ZVpgkgf0BqcwNDRK1EKdM7MQ7GjF9PEVFrKcH0S7ZnLn
         kHUQ4u72awepDvmBX2WINW4UP8LQkn5NHkJYjkSCxeF3c8GqyTER7CayO/edxI0aarXF
         r3uQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=2Jz3rVFfkqMIR97qnIlFhdTz/GmKQSqZl0HGs12PkWg=;
        fh=b150oo12NMepBIxmd8fIWdO8HSUtZS/HkkmtWgAGGAk=;
        b=Mj6fidpkN5zQa/ahVnBWZakmsqV359ZGGLm5CmcPENhaFnpyKcZO1ks9qsAJz6oEzk
         iHJvdzO+vNZ2A0+qvMgf/ZJr8GbgZ6hbvo7wHKY9ZWcQT0snxFp8GcIsqJoY3vwKBVvN
         HqHNP6UQgDqBsA3/Q5XbwUpcagVAD7UrHaK513Rl9sy8IVXoHzrcc9LDRVdRa/WFEuBK
         BlviWbjzaDGPBmj1AqqY9iSr5z3XYfOQ3Pg53BcQ7d7gW8Zf6xotCIKIArZ2VANcoSm1
         1OW20mbZG1wpjOWsrbtPDrl6h36p2vNnOoSF3bhkbYRwv9rF1QilfR+qmmbnp+JClhfM
         VW8A==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="kvEjvO/5";
       spf=pass (google.com: domain of 3q05daaykcz4ejgbcpemmejc.amki8q8l-bctemmejcepmsnq.amk@flex--glider.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3Q05daAYKCZ4EJGBCPEMMEJC.AMKI8Q8L-BCTEMMEJCEPMSNQ.AMK@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1750945351; x=1751550151; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=2Jz3rVFfkqMIR97qnIlFhdTz/GmKQSqZl0HGs12PkWg=;
        b=IyxoZOjPVYUcqZyYUXNXdiOR36vZdqvCb6z73AzCTykws5RPMLcU0BwKSf0V/mZKmL
         uO3PQX61vCFpnBo5VjTN6Rgf53lc2XfL5we95forRs8iA5Ss6YTD0ugrpK9x1GUlvBDI
         iy+DAPq0qe/IyjlOUdX1FS1H8y+XboJew/NGkFkGz2toVr29vAFedJpFx1XUcsOchXIE
         zU1Vlp0Zglq7Px9wcR8g8hRm4JP3eSxZ68JlukSmUqlohZ5FIgP/UwoILUENN8MR6qiS
         X7QE0N9KO6TTsayjuxMgPAMKOT87HI2WGeeCz+j2z29qb1xv4NoJ8ah0x83AdsnnInyK
         8ylw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1750945351; x=1751550151;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=2Jz3rVFfkqMIR97qnIlFhdTz/GmKQSqZl0HGs12PkWg=;
        b=P55o9AKFWnZmJZIFZ42zSZUN6U0EVlVGB2oPB9aFnCz+FkbBa8w+gLXee8wjJaBt+6
         eq2mN+nXhpBwgyz2wXi57RG6EoXi40K3PEha/A/LC5EFjri7Y51fTIQv+SSmFDwqvRlN
         2EeIroCineCwS93etuRzInBWT5czyXJPBFBJX7hUtxAoXe23IHUhLwg3bNNOvHXT/oIu
         OJ3wIdsE11aeMtSpsOFve/0u9LasJalu/AYXAWlvIk3x2Wourl6hkVpEYVCJ2yXSrkWx
         XFhpE1Jc2CkZFcn3fhKhedjzly71JGFqi2GyEHz6owdosp2VlN/uelufggpdD13t24GN
         c38g==
X-Forwarded-Encrypted: i=2; AJvYcCWaLQ+DZ7m07PIVCN/vehgf184M1rhx4RuxzPJxJQu4ukqo/wfsHw6Z/Va/Ooj5bg0HZOozIw==@lfdr.de
X-Gm-Message-State: AOJu0Yw3/G5w0AaSV93D54PicUiIVXGJ88+mpH75f5HbRJNdEZjfBh/H
	navj/pgHpBhdtzr5nCtXozPUSwmGJKIzSAQpW+f1cYVuWztMyJky9qzs
X-Google-Smtp-Source: AGHT+IHd5tecNuu2q4XNztSq2giSZj9jAxW54CgGKtPZD9IouTv8SVcHsigjLiz8032P/bGon1qVFw==
X-Received: by 2002:a05:6000:258a:b0:3a3:66cb:d530 with SMTP id ffacd0b85a97d-3a6ed5fd86emr6222765f8f.23.1750945351229;
        Thu, 26 Jun 2025 06:42:31 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZe4ec+5skJOsR0FHx91Mn8YYIsXgJzukrNKshdLLrhnpQ==
Received: by 2002:a05:6000:2382:b0:3a5:89d7:ce0d with SMTP id
 ffacd0b85a97d-3a6f321ba0als471028f8f.0.-pod-prod-09-eu; Thu, 26 Jun 2025
 06:42:27 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVo7LrBwUPu4ZbNu7Bk6HTn8RlOK41KcKfX6WdUpAmDhE0tCRGA9xvZd1zyaK6E7KEC+/GdPXo9pgo=@googlegroups.com
X-Received: by 2002:a5d:4b10:0:b0:3a4:d6ed:8e00 with SMTP id ffacd0b85a97d-3a6ed64251fmr5540026f8f.33.1750945347533;
        Thu, 26 Jun 2025 06:42:27 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1750945347; cv=none;
        d=google.com; s=arc-20240605;
        b=RgTKtcafwXwmJkfwyjYOJG12yESRTXwbarvQyKsQdBqrLerWKo2IfN/1N8o/pw7NX0
         HEid0rFYnRHTq/bnmWI6yj4+u2RgvNTYIDSIlV3JG0sqdwfwPgo0uvcXQ9BeG26mehFV
         LULSTgGkV+E+RoNfSTkReoUs2U66jyfi8rwqR4UkN+s8HsriMVKYVhRS5vVrCZZW9TgE
         CngkREYgrnwVRVPKGoILH99yMJI9rdiARbcR8LUQDsdS6o6R2c9ayMPWyDljXj9pUN18
         Zk2bNk0MagxQcU57y+nPmQgBvjmamIy8IDb5E54B3AyGNGzxQ0sRm1Gyi7/ddNQOoQLt
         qqYw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=aC+obdeMHn5fESAyhGJX79KJV5tcOZyYRgpJyGh+V2A=;
        fh=H4SuQHhsstW9U76MKwFLIYYjNeEW8CUeGmpmbWDprNo=;
        b=kb9EInVuMOrqs0Jc5o8yxNM89fnbEvWhsoDcmE/R5rOOeGgAAPZmFq/j8ypXm0bJG/
         mpp2x6pxO8izMCs5HVkyGsfTE8kbWxCiWkWTOw+9BSup8Akkqe2T/H0IVU4nH5vDXxlJ
         xRfOls0SOs4mWrvT8WZobq8jzHln+QZ83rLCVUdTIfvh6PQD3LueEK7eD4GAApkBqh1R
         B1bu00bqgdb3CbK6DTd/6VaZ0zYczJba7ATQDLnQ+tzSJqUejLOsQwQeNxzorPYzzJBc
         A5gu0ddyi2ZlLeLPqd5MSiHp96BlP9M5pr7UoLA/wyJMIuYMDRTkY7li2X7uNJlWBITR
         RGCg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="kvEjvO/5";
       spf=pass (google.com: domain of 3q05daaykcz4ejgbcpemmejc.amki8q8l-bctemmejcepmsnq.amk@flex--glider.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3Q05daAYKCZ4EJGBCPEMMEJC.AMKI8Q8L-BCTEMMEJCEPMSNQ.AMK@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x34a.google.com (mail-wm1-x34a.google.com. [2a00:1450:4864:20::34a])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-3a6e80d7f22si134965f8f.6.2025.06.26.06.42.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 26 Jun 2025 06:42:27 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3q05daaykcz4ejgbcpemmejc.amki8q8l-bctemmejcepmsnq.amk@flex--glider.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) client-ip=2a00:1450:4864:20::34a;
Received: by mail-wm1-x34a.google.com with SMTP id 5b1f17b1804b1-4530c186394so4466545e9.0
        for <kasan-dev@googlegroups.com>; Thu, 26 Jun 2025 06:42:27 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWLUAAUUSTrVwMeaLuLLhp9FWEOfMACjTlJP+5Vgn8YDluc024jIWQNHTWZE5mFZ521p+inNbgfXoQ=@googlegroups.com
X-Received: from wmbhe15.prod.google.com ([2002:a05:600c:540f:b0:43c:ef7b:ffac])
 (user=glider job=prod-delivery.src-stubby-dispatcher) by 2002:a05:600c:3590:b0:453:6ca:16a6
 with SMTP id 5b1f17b1804b1-45381ab7e02mr85005005e9.10.1750945347145; Thu, 26
 Jun 2025 06:42:27 -0700 (PDT)
Date: Thu, 26 Jun 2025 15:41:56 +0200
In-Reply-To: <20250626134158.3385080-1-glider@google.com>
Mime-Version: 1.0
References: <20250626134158.3385080-1-glider@google.com>
X-Mailer: git-send-email 2.50.0.727.gbf7dc18ff4-goog
Message-ID: <20250626134158.3385080-10-glider@google.com>
Subject: [PATCH v2 09/11] kcov: add ioctl(KCOV_RESET_TRACE)
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
 header.i=@google.com header.s=20230601 header.b="kvEjvO/5";       spf=pass
 (google.com: domain of 3q05daaykcz4ejgbcpemmejc.amki8q8l-bctemmejcepmsnq.amk@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3Q05daAYKCZ4EJGBCPEMMEJC.AMKI8Q8L-BCTEMMEJCEPMSNQ.AMK@flex--glider.bounces.google.com;
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

Provide a mechanism to reset the coverage for the current task
without writing directly to the coverage buffer.
This is slower, but allows the fuzzers to map the coverage buffer
as read-only, making it harder to corrupt.

Signed-off-by: Alexander Potapenko <glider@google.com>

---
v2:
 - Update code to match the new description of struct kcov_state
---
 Documentation/dev-tools/kcov.rst | 26 ++++++++++++++++++++++++++
 include/uapi/linux/kcov.h        |  1 +
 kernel/kcov.c                    | 15 +++++++++++++++
 3 files changed, 42 insertions(+)

diff --git a/Documentation/dev-tools/kcov.rst b/Documentation/dev-tools/kcov.rst
index 6446887cd1c92..e215c0651e16d 100644
--- a/Documentation/dev-tools/kcov.rst
+++ b/Documentation/dev-tools/kcov.rst
@@ -470,3 +470,29 @@ local tasks spawned by the process and the global task that handles USB bus #1:
 		perror("close"), exit(1);
 	return 0;
     }
+
+
+Resetting coverage with an KCOV_RESET_TRACE
+-------------------------------------------
+
+The ``KCOV_RESET_TRACE`` ioctl provides a mechanism to clear collected coverage
+data for the current task. It resets the program counter (PC) trace and, if
+``KCOV_UNIQUE_ENABLE`` mode is active, also zeroes the associated bitmap.
+
+The primary use case for this ioctl is to enhance safety during fuzzing.
+Normally, a user could map the kcov buffer with ``PROT_READ | PROT_WRITE`` and
+reset the trace from the user-space program. However, when fuzzing system calls,
+the kernel itself might inadvertently write to this shared buffer, corrupting
+the coverage data.
+
+To prevent this, a fuzzer can map the buffer with ``PROT_READ`` and use
+``ioctl(fd, KCOV_RESET_TRACE, 0)`` to safely clear the buffer from the kernel
+side before each fuzzing iteration.
+
+Note that:
+
+* This ioctl is safer but slower than directly writing to the shared memory
+  buffer due to the overhead of a system call.
+* ``KCOV_RESET_TRACE`` is itself a system call, and its execution will be traced
+  by kcov. Consequently, immediately after the ioctl returns, cover[0] will be
+  greater than 0.
diff --git a/include/uapi/linux/kcov.h b/include/uapi/linux/kcov.h
index e743ee011eeca..8ab77cc3afa76 100644
--- a/include/uapi/linux/kcov.h
+++ b/include/uapi/linux/kcov.h
@@ -23,6 +23,7 @@ struct kcov_remote_arg {
 #define KCOV_DISABLE			_IO('c', 101)
 #define KCOV_REMOTE_ENABLE		_IOW('c', 102, struct kcov_remote_arg)
 #define KCOV_UNIQUE_ENABLE		_IOW('c', 103, unsigned long)
+#define KCOV_RESET_TRACE		_IO('c', 104)
 
 enum {
 	/*
diff --git a/kernel/kcov.c b/kernel/kcov.c
index 2a4edbaad50d0..1693004d89764 100644
--- a/kernel/kcov.c
+++ b/kernel/kcov.c
@@ -740,6 +740,21 @@ static int kcov_ioctl_locked(struct kcov *kcov, unsigned int cmd,
 		return 0;
 	case KCOV_UNIQUE_ENABLE:
 		return kcov_handle_unique_enable(kcov, arg);
+	case KCOV_RESET_TRACE:
+		unused = arg;
+		if (unused != 0 || current->kcov != kcov)
+			return -EINVAL;
+		t = current;
+		if (WARN_ON(kcov->t != t))
+			return -EINVAL;
+		mode = kcov->mode;
+		if (mode < KCOV_MODE_TRACE_PC)
+			return -EINVAL;
+		if (kcov->state.bitmap)
+			bitmap_zero(kcov->state.bitmap,
+				    kcov->state.bitmap_size);
+		WRITE_ONCE(kcov->state.trace[0], 0);
+		return 0;
 	case KCOV_DISABLE:
 		/* Disable coverage for the current task. */
 		unused = arg;
-- 
2.50.0.727.gbf7dc18ff4-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250626134158.3385080-10-glider%40google.com.
