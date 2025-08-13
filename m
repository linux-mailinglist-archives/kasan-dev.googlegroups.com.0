Return-Path: <kasan-dev+bncBDP53XW3ZQCBBZNK6LCAMGQEGINHKRQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43f.google.com (mail-wr1-x43f.google.com [IPv6:2a00:1450:4864:20::43f])
	by mail.lfdr.de (Postfix) with ESMTPS id C8177B24ABE
	for <lists+kasan-dev@lfdr.de>; Wed, 13 Aug 2025 15:38:46 +0200 (CEST)
Received: by mail-wr1-x43f.google.com with SMTP id ffacd0b85a97d-3b78a034d25sf3444071f8f.0
        for <lists+kasan-dev@lfdr.de>; Wed, 13 Aug 2025 06:38:46 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755092326; cv=pass;
        d=google.com; s=arc-20240605;
        b=IT0m/Wl3ZyYAGqHhnOx5eCZLVBDfThwvtWKYB1Iew/YObv2Oyhmj/INlowbCul4y87
         BMb+CxMx1njOZJwIg/cpOY/19ZbYtj4pzRKkhQs+l8O779IiXjwVwI3C1GZzIiDgvinM
         yJjqyKM3PS0HYnG7wxKLVs0fCQnfcL2dPUfcmck9Wqy+frlf4uvF+5Ahwen4Vcp8DvPb
         /KRB4BsExOJyT3DrwZdqOwjXc8SMiluhgdp30sGSZdamD+SU1BO462MTyltslsSc7OoN
         wyq/vCua3tMTOebsB0XbfEGRu7Pz8rWkR3XhMSKtE+mYzwxNWzLsz3NnuiHr9oZHO7rs
         Ggyg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=f/E8zsMGhfjQYkui2kNsSdi6jrQxnwCkJ5Se4xV+BLk=;
        fh=9Lnvt0TSx0ZfMECXLJZOvxraijkyDaAT0qbPp/1olo8=;
        b=gzJcW0+P8X4GgffZ2ctB/HwOP5W26vcM93jWJsNt5A+oScTO9WBHN3kC8wMakW+vAJ
         mvv7w5iW75o5lT5eL5/6jPO6JmVdG+aZK2sLVEiorQoA9WzekW/ENxdCYFOcS22UUQN0
         A1cTItBfFJag1J5atcpgKRa0DzBxuJ+bt9WVC2wPBZJL4gMotUVZAErIMmJFPcf/M9Tj
         KNe41xXy3gCS0Q3iUZYmxWqGIiRSOiOOhxxHcqwrsCkW2H8g9cw3EsMEbAG7zVhi7By7
         KB+XSltpuwp7Q764fZFODYDZWzPh56C7jePgL3lYGBFr4Z80+VmU6cW1z0w851YJ/nZN
         l0TQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=BasmRz04;
       spf=pass (google.com: domain of ethan.w.s.graham@gmail.com designates 2a00:1450:4864:20::431 as permitted sender) smtp.mailfrom=ethan.w.s.graham@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755092326; x=1755697126; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=f/E8zsMGhfjQYkui2kNsSdi6jrQxnwCkJ5Se4xV+BLk=;
        b=wOkz6VO8JaTgHuTRRf6GeDeS3bgYxopAUyM/mG6iCtGn8AJR6qgONvhT3oKwlQxVoC
         8nrI7fFe/lr/iBWxk/lmh1ELqwSAFSWr6vAXbZbqqZLy+gNw6QSUkd1+IF2f6VaWN1MS
         ExLx0XRxEvjuFj3CO+mQKe+z9lp5q0U2iPNWV02DXJPU8tyxFZuBrOL3Er7ph7rNFlTE
         AQihX8BaSqJqmaDOKXn8Fv3KBsWuSvS7YXGMZ6lyvy5gsEmMRW+a+eAEgU2CmGEPkuq1
         0mLQBPbSI+7sW5SYvOwIchnXU1wQD9hpNv4e0RHX9BBY1HCK6Wx3jmB/SvoXfSl5sE6G
         NYhQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1755092326; x=1755697126; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=f/E8zsMGhfjQYkui2kNsSdi6jrQxnwCkJ5Se4xV+BLk=;
        b=cixx2lCajVdUBtljb4xwMIWIh+rwWq3dERZpONFRUWbJdhc6uEbR9XZvzO8WC4iCp5
         1ZJ3i7pNcucZhZJowraYFCkK/vjVHsEYn2YBCYtJ+DRQcXrxoowqoTq3JaehS/ieDco3
         x8CLmh4So5ZORguebExGJz3Smu7ZKSKjIFyova4EcsLd1J1NIihNypKiOmfuOLD++5it
         mnNLRVXg2bIszTJTgT5SPt3GoHbvSNtYfJ/eJu2jsxdwDZfN+Tkl40LScN9qSirmA/yX
         kramUgHI4f9ZhMnjJg/ycyAKyWs6Z5v6AgQ/k9854XnOC4OE5t7c+7fmWyqBOFxykzMq
         iLtA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755092326; x=1755697126;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=f/E8zsMGhfjQYkui2kNsSdi6jrQxnwCkJ5Se4xV+BLk=;
        b=lRO2depACLtBDHFe4I1E4iU1VnPmhrg4hfuCZspJPY4XdwEBg2zYQLZQ0pxmVa6MuM
         2EuLu5eOgTvYzxa+adSDy3t1XEVCHVmS1nDhHu3ZCCvB25Q44CZekXQO/AYQkfIAMFMb
         ITKTT/ycm2e/AACM6Wt/cEqDtZX4uYMphIzRre0i9JHjMfu04bo7IPjnW7OjJxLsOPev
         AiC86C9C0l05onAsh/D1Cjd+eUiEsqJBscCE9F2TeL43yZu0Gk3j5XJQLQxRUhB6XD8n
         4urgO6HQBLZBc8o6Wh+wKImmTBgsOtwO4Yyv730/NOFRQjFwvbwRwcCcTRktb71L4CO5
         Oqlg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUIHDw9UJ3bfiILRDCokYQuuQ7DquRcmrEScM+BONn23FWk8PGZ1IsnhlY73ivicJ9xpzpSdA==@lfdr.de
X-Gm-Message-State: AOJu0YyqNV0PbZisSgCaHDFRFsZbnR0mez4OHJH81Y2jMWk9HIYRWi6f
	dFYmkFYTfhrbVjAzWXohhYg96ZIPxTVtQLbGhmtqgPaEbz0ptznZnFoK
X-Google-Smtp-Source: AGHT+IEbMQkUdRyPUrYnn8DTQo/2Qu4XSugH2MQyeIqBptX2radqH7yfOO5oL3Z8k7Vgl97+X/zoDA==
X-Received: by 2002:a05:6000:238a:b0:3b7:76e8:ba1e with SMTP id ffacd0b85a97d-3b917d29ae3mr2706198f8f.11.1755092326134;
        Wed, 13 Aug 2025 06:38:46 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZf3IxWElJIXA3wC/A578kioTxCErfZQy9F//PtjMPFhpA==
Received: by 2002:a05:6000:18a9:b0:3b7:89fd:a285 with SMTP id
 ffacd0b85a97d-3b8f946939els3134013f8f.0.-pod-prod-02-eu; Wed, 13 Aug 2025
 06:38:43 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUXfTUIpgE5NxKfn34tu5uFBwPUWjl06sNlyTyKQCLpoZYz0KYB+9ttW0cmz+k5WpYZpKcfUzQWIQk=@googlegroups.com
X-Received: by 2002:a05:6000:2c0c:b0:3b7:95fa:ac4 with SMTP id ffacd0b85a97d-3b917ea21a0mr2504630f8f.32.1755092323023;
        Wed, 13 Aug 2025 06:38:43 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755092323; cv=none;
        d=google.com; s=arc-20240605;
        b=MH8mha/OAJI4gSKdm/AT69Mug82PpHKwKwknlDYnDyS8r88hE4vzBY9l/mvc3gkfco
         JoFCUD5Dxz6A6Ihj7fsxp89fU3Y9pC0EL3aQGKA+6hDhjk4/6sbUchiDlHGLQRMV5hSc
         3byn4+xp1nVVkPm1Rr9uj6Z0D8WqHfEblO3lN1v4ZJacrvSuJLXbDFLBTC3njqx08P7G
         5LxpXw6N4tBCxKtwoq6MN0ptTxzaXiyEV6MGefYR6/n59fvtQEhXg2FeDZzqj16BtoBM
         ZHmWo3V44i+vVQd/j+gYuygSG64aUF1hlQqCkdg+kp0Sd2SHkLFiaxS5OZjt7NEJcFOC
         HXhg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=fT8XtIdCS6vk3GGdGM60wvLV9ckvUvGKm1mza8YtIpw=;
        fh=6mTzkUTMR2f9w+OXAEiTM7tnNn4fdsnEzMjVXUtUB5I=;
        b=G5QWLot8GN1TM/pAJDDFCuGhTAhLXJri5VJQHI0s4qPBZ8sp2CT80KvkMb0Whl3sTL
         f5MkwWzX0Ab10J7F6qC7pBiO5JM/U6iC9ulwxEsf0IS2f7XD8AuFJbNJgsPbzDACdCPy
         MdGYPbopw7oHfZ2n0d1iKNYMqWI7HUoG+DKL9C2ij9H43BTLL2xbZRRt4iXMCm/Cgsh/
         J5x7wbFlI28dAEFJD5KyrbH499IrlX49xYFRI70PngVKI3JT3/rcweU8yt2bBNUb/WCA
         WtkKUbQ2+HeLdSdTtJzNofIW03RIZj61UpKpWZTZ8LW1xWp/c/DuPQg+mFVFnjz3ZwmH
         w4Gw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=BasmRz04;
       spf=pass (google.com: domain of ethan.w.s.graham@gmail.com designates 2a00:1450:4864:20::431 as permitted sender) smtp.mailfrom=ethan.w.s.graham@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x431.google.com (mail-wr1-x431.google.com. [2a00:1450:4864:20::431])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-3b8fa67b1f3si269301f8f.3.2025.08.13.06.38.42
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 13 Aug 2025 06:38:43 -0700 (PDT)
Received-SPF: pass (google.com: domain of ethan.w.s.graham@gmail.com designates 2a00:1450:4864:20::431 as permitted sender) client-ip=2a00:1450:4864:20::431;
Received: by mail-wr1-x431.google.com with SMTP id ffacd0b85a97d-3b7910123a0so5873328f8f.1;
        Wed, 13 Aug 2025 06:38:42 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXQIeMGE6ah1Ys6BWj0IM6mAwzostXuaog4fbMCAs98n0oFJBOpkzrjFxZIVMUMKaoZAUFh+whEy8s=@googlegroups.com, AJvYcCXZsejkCkNyqccEKn126yvNEm04+E8mKIc/+fEHzvIojfD+XFpOFykOiiq/oNqVsbLF/PtZCIZbOXcS@googlegroups.com
X-Gm-Gg: ASbGncttIdfViXpQCBLeuPxWoz+fVUxOD7LTtA1jT9dyDP6aH9dJsgLR5uER52IJZo5
	HLb42+FKI1RX5TLuaoFDiSAV0zzZmdTakzjZBV0u1uu4IIqkgwu3Z9PMatnDTzUY/K7V7xu92Ga
	Zzhe6fb0hwL+n44Akt80S+YkWSIypBWlW5dUijtPw1SE9/P1ulKjBgVE9Xog2fXIGynMc1YPLyg
	+Oq5R/FCwB3IzA8/H3dK+RkX6hAV642V/fIsNNTxRa/+CsG0dMkM0W8DQg5HhQNGG6TKYwILqtY
	JgiOcLKSdsgdhGbVeo7NxCTOXE3kyZKE0e7k3lko8UtSxLwQQgYPRdrsscCcoBToITT/i5MYChj
	H3ygk+L3iu7T1v8YBzkGGRt2C6Xy2t36CRjsdtcDFf4KBFE0LLqt1Ge0XFMwsmje+uK1hTNAD3Z
	yWBUStcuRg0GGo/Og=
X-Received: by 2002:a05:6000:26c9:b0:3b8:d6ae:6705 with SMTP id ffacd0b85a97d-3b917ea1577mr2096491f8f.30.1755092322216;
        Wed, 13 Aug 2025 06:38:42 -0700 (PDT)
Received: from xl-nested.c.googlers.com.com (87.220.76.34.bc.googleusercontent.com. [34.76.220.87])
        by smtp.gmail.com with ESMTPSA id ffacd0b85a97d-3b8f8b1bc81sm25677444f8f.69.2025.08.13.06.38.41
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 13 Aug 2025 06:38:41 -0700 (PDT)
From: Ethan Graham <ethan.w.s.graham@gmail.com>
To: ethangraham@google.com,
	glider@google.com
Cc: andreyknvl@gmail.com,
	brendan.higgins@linux.dev,
	davidgow@google.com,
	dvyukov@google.com,
	jannh@google.com,
	elver@google.com,
	rmoar@google.com,
	shuah@kernel.org,
	tarasmadan@google.com,
	kasan-dev@googlegroups.com,
	kunit-dev@googlegroups.com,
	linux-kernel@vger.kernel.org,
	linux-mm@kvack.org
Subject: [PATCH v1 RFC 4/6] kfuzztest: add ReST documentation
Date: Wed, 13 Aug 2025 13:38:10 +0000
Message-ID: <20250813133812.926145-5-ethan.w.s.graham@gmail.com>
X-Mailer: git-send-email 2.51.0.rc0.205.g4a044479a3-goog
In-Reply-To: <20250813133812.926145-1-ethan.w.s.graham@gmail.com>
References: <20250813133812.926145-1-ethan.w.s.graham@gmail.com>
MIME-Version: 1.0
X-Original-Sender: ethan.w.s.graham@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=BasmRz04;       spf=pass
 (google.com: domain of ethan.w.s.graham@gmail.com designates
 2a00:1450:4864:20::431 as permitted sender) smtp.mailfrom=ethan.w.s.graham@gmail.com;
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

From: Ethan Graham <ethangraham@google.com>

Add Documentation/dev-tools/kfuzztest.rst and reference it in the
dev-tools index.

Signed-off-by: Ethan Graham <ethangraham@google.com>
---
 Documentation/dev-tools/index.rst     |   1 +
 Documentation/dev-tools/kfuzztest.rst | 279 ++++++++++++++++++++++++++
 2 files changed, 280 insertions(+)
 create mode 100644 Documentation/dev-tools/kfuzztest.rst

diff --git a/Documentation/dev-tools/index.rst b/Documentation/dev-tools/index.rst
index 65c54b27a60b..00ccc4da003b 100644
--- a/Documentation/dev-tools/index.rst
+++ b/Documentation/dev-tools/index.rst
@@ -32,6 +32,7 @@ Documentation/process/debugging/index.rst
    kfence
    kselftest
    kunit/index
+   kfuzztest
    ktap
    checkuapi
    gpio-sloppy-logic-analyzer
diff --git a/Documentation/dev-tools/kfuzztest.rst b/Documentation/dev-tools/kfuzztest.rst
new file mode 100644
index 000000000000..7fdc4914b966
--- /dev/null
+++ b/Documentation/dev-tools/kfuzztest.rst
@@ -0,0 +1,279 @@
+.. SPDX-License-Identifier: GPL-2.0
+.. Copyright 2025 Google LLC
+
+=========================================
+Kernel Fuzz Testing Framework (KFuzzTest)
+=========================================
+
+Overview
+========
+
+The Kernel Fuzz Testing Framework (KFuzzTest) is a framework designed to expose
+internal kernel functions to a userspace fuzzing engine.
+
+It is intended for testing stateless or low-state functions that are difficult
+to reach from the system call interface, such as routines involved in file
+format parsing or complex data transformations. This provides a method for
+in-situ fuzzing of kernel code without requiring that it be built as a separate
+userspace library or that its dependencies be stubbed out.
+
+The framework consists of four main components:
+
+1.  An API, based on the ``FUZZ_TEST`` macro, for defining test targets
+    directly in the kernel tree.
+2.  A binary serialization format for passing complex, pointer-rich data
+    structures from userspace to the kernel.
+3.  A ``debugfs`` interface through which a userspace fuzzer submits
+    serialized test inputs.
+4.  Metadata embedded in dedicated ELF sections of the ``vmlinux`` binary to
+    allow for the discovery of available fuzz targets by external tooling.
+
+.. warning::
+   KFuzzTest is a debugging and testing tool. It exposes internal kernel
+   functions to userspace with minimal sanitization and is designed for
+   use in controlled test environments only. It must **NEVER** be enabled
+   in production kernels.
+
+Supported Architectures
+=======================
+
+KFuzzTest is currently only supported for x86_64.
+
+Usage
+=====
+
+To enable KFuzzTest, configure the kernel with::
+
+	CONFIG_KFUZZTEST=y
+
+which depends on ``CONFIG_DEBUGFS`` for receiving userspace inputs, and
+``CONFIG_DEBUG_KERNEL`` as an additional guardrail for preventing KFuzzTest
+from finding its way into a production build accidentally.
+
+The KFuzzTest sample fuzz targets can be built in with
+``CONFIG_SAMPLE_KFUZZTEST``.
+
+KFuzzTest currently only supports code that is built into the kernel, as the
+core module's startup process discovers fuzz targets, constraints, and
+annotations from a dedicated ELF section during startup.
+
+Declaring a KFuzzTest target
+----------------------------
+
+A fuzz target is defined directly in a .c file, typically alongside the function
+being tested. This process involves three main parts: defining an input
+structure, writing the test body using the ``FUZZ_TEST`` macro, and optionally
+adding metadata for the fuzzer.
+
+The following example illustrates how to create a fuzz target for a function
+``int process_data(const char *data, size_t len)``.
+
+.. code-block:: c
+
+	/*
+	 * 1. Define a struct to model the inputs for the function under test.
+	 *    Each field corresponds to an argument needed by the function.
+	 */
+	struct process_data_inputs {
+		const char *data;
+		size_t len;
+	};
+
+	/*
+	 * 2. Define the fuzz target using the FUZZ_TEST macro.
+	 *    The first parameter is a unique name for the target.
+	 *    The second parameter is the input struct defined above.
+	 */
+	FUZZ_TEST(test_process_data, struct process_data_inputs)
+	{
+		/*
+		 * Within this body, the 'arg' variable is a pointer to a
+		 * fully initialized 'struct process_data_inputs'.
+		 */
+
+		/*
+		 * 3. (Optional) Add constraints to define preconditions.
+		 *    This check ensures 'arg->data' is not NULL. If the condition
+		 *    is not met, the test exits early. This also creates metadata
+		 *    to inform the fuzzer.
+		 */
+		KFUZZTEST_EXPECT_NOT_NULL(process_data_inputs, data);
+
+		/*
+		 * 4. (Optional) Add annotations to provide semantic hints.
+		 *    This annotation informs the fuzzer that the 'len' field
+		 *    is the length of the buffer pointed to by 'data'.
+		 *    Annotations do not add any runtime checks.
+		 */
+		KFUZZTEST_ANNOTATE_LEN(process_data_inputs, len, data);
+
+		/*
+		 * 5. Call the kernel function with the provided inputs.
+		 *    Memory errors like out-of-bounds accesses on 'arg->data' will
+		 *    be detected by KASAN or other memory error detection tools.
+		 */
+		process_data(arg->data, arg->len);
+	}
+
+KFuzzTest provides two families of macros to improve the quality of fuzzing:
+
+- ``KFUZZTEST_EXPECT_*``: These macros define constraints, which are
+  preconditions that must be true for the test to proceed. They are enforced
+  with a runtime check in the kernel. If a check fails, the current test run is
+  aborted. This metadata helps the userspace fuzzer avoid generating invalid
+  inputs.
+
+- ``KFUZZTEST_ANNOTATE_*``: These macros define annotations, which are purely
+  semantic hints for the fuzzer. They do not add any runtime checks and exist
+  only to help the fuzzer generate more intelligent and structurally correct
+  inputs. For example, KFUZZTEST_ANNOTATE_LEN links a size field to a pointer
+  field, which is a common pattern in C APIs.
+
+Metadata
+--------
+
+Macros ``FUZZ_TEST``, `KFUZZTEST_EXPECT_*`` and ``KFUZZTEST_ANNOTATE_*`` embed
+metadata into several sections within the main ``.data`` section of the final
+``vmlinux`` binary; ``.kfuzztest_target``, ``.kfuzztest_constraint`` and
+``.kfuzztest_annotation`` respectively.
+
+This serves two purposes:
+
+1. The core module uses the ``.kfuzztest_target`` section at boot to discover
+   every ``FUZZ_TEST`` instance and create its ``debugfs`` directory and
+   ``input`` file.
+2. Userspace fuzzers can read this metadata from the ``vmlinux`` binary to
+   discover targets and learn about their rules and structure in order to
+   generate correct and effective inputs.
+
+The metadata in the ``.kfuzztest_*`` sections consists of arrays of fixed-size C
+structs (e.g., ``struct kfuzztest_target``). Fields within these structs that
+are pointers, such as ``name`` or ``arg_type_name``, contain addresses that
+point to other locations in the ``vmlinux`` binary. A userspace tool that
+parsing the ELF file must resolve these pointers to read the data that they
+reference. For example, to get a target's name, a tool must:
+
+1. Read the ``struct kfuzztest_target`` from the ``.kfuzztest_target`` section.
+2. Read the address in the ``.name`` field.
+3. Use that address to locate and read null-terminated string from its position
+   elsewhere in the binary (e.g., ``.rodata``).
+
+Tooling Dependencies
+--------------------
+
+For userspace tools to parse the ``vmlinux`` binary and make use of emitted
+KFuzzTest metadata, the kernel must be compiled with DWARF debug information.
+This is required for tools to understand the layout of C structs, resolve type
+information, and correctly interpret constraints and annotations.
+
+When using KFuzzTest with automated fuzzing tools, either
+``CONFIG_DEBUG_INFO_DWARF4`` or ``CONFIG_DEBUG_INFO_DWARF5`` should be enabled.
+
+Input Format
+============
+
+KFuzzTest targets receive their inputs from userspace via a write to a dedicated
+debugfs ``/sys/kernel/debug/kfuzztest/<test-name>/input``.
+
+The data written to this file must be a single binary blob that follows a
+specific serialization format. This format is designed to allow complex,
+pointer-rich C structures to be represented in a flat buffer, requiring only a
+single kernel allocation and copy from userspace.
+
+An input is first prefixed by an 8-byte header containing a magic value in the
+first four bytes, defined as ``KFUZZTEST_HEADER_MAGIC`` in
+`<include/linux/kfuzztest.h>``, and a version number in the subsequent four
+bytes.
+
+Version 0
+---------
+
+In version 0 (i.e., when the version number in the 8-byte header is equal to 0),
+the input format consists of three main parts laid out sequentially: a region
+array, a relocation table, and the payload.::
+
+    +----------------+---------------------+-----------+----------------+
+    |  region array  |  relocation table   |  padding  |    payload     |
+    +----------------+---------------------+-----------+----------------+
+
+Region Array
+^^^^^^^^^^^^
+
+This component is a header that describes how the raw data in the Payload is
+partitioned into logical memory regions. It consists of a count of regions
+followed by an array of ``struct reloc_region``, where each entry defines a
+single region with its size and offset from the start of the payload.
+
+.. code-block:: c
+
+	struct reloc_region {
+		uint32_t offset;
+		uint32_t size;
+	};
+
+	struct reloc_region_array {
+		uint32_t num_regions;
+		struct reloc_region regions[];
+	};
+
+By convention, region 0 represents the top-level input struct that is passed
+as the arg variable to the FUZZ_TEST body. Subsequent regions typically
+represent data buffers pointed to by fields within that struct. Region array
+entries must be ordered by offset ascending, and must not overlap with one
+another.
+
+To satisfy C language alignment requirements and prevent potential hardware
+faults, the memory address of each region's data must be correctly aligned for
+the type it represents. The framework allocates a base buffer that is suitably
+aligned for any C type. Therefore, the userspace tool that generates the input
+is responsible for calculating each region's offset within the payload to ensure
+this alignment is maintained.
+
+Relocation Table
+^^^^^^^^^^^^^^^^
+
+The relocation table provides the instructions for the kernel to "hydrate" the
+payload by patching pointer fields. It contains an array of
+``struct reloc_entry`` items. Each entry acts as a linking instruction,
+specifying:
+
+- The location of a pointer that needs to be patched (identified by a region
+  ID and an offset within that region).
+
+- The target region that the pointer should point to (identified by the
+  target's region ID) or ``KFUZZTEST_REGIONID_NULL`` if the pointer is ``NULL``.
+
+This table also specifies the amount of padding between its end and the start
+of the payload, which should be at least 8 bytes.
+
+.. code-block:: c
+
+	struct reloc_entry {
+		uint32_t region_id;
+		uint32_t region_offset;
+		uint32_t value;
+	};
+
+	struct reloc_table {
+		uint32_t num_entries;
+		uint32_t padding_size;
+		struct reloc_entry entries[];
+    };
+
+Payload
+^^^^^^^
+
+The payload contains the raw binary data for all regions, concatenated together
+according to their specified offsets.
+
+- Alignment: The start of the payload must be aligned to the most restrictive
+  alignment requirement of all its constituent regions. The framework ensures
+  that each region within the payload is then placed at an offset that respects
+  its own type's alignment.
+
+- Padding and Poisoning: The space between the end of one region's data and the
+  beginning of the next must be sufficient for padding. In KASAN builds,
+  KFuzzTest poisons this unused padding, allowing for precise detection of
+  out-of-bounds memory accesses between adjacent buffers. This padding should
+  be at least ``KFUZZTEST_POISON_SIZE`` bytes as defined in
+  `include/linux/kfuzztest.h``.
-- 
2.51.0.rc0.205.g4a044479a3-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250813133812.926145-5-ethan.w.s.graham%40gmail.com.
