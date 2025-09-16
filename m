Return-Path: <kasan-dev+bncBDP53XW3ZQCBB3OOUTDAMGQEAGV4KOY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33f.google.com (mail-wm1-x33f.google.com [IPv6:2a00:1450:4864:20::33f])
	by mail.lfdr.de (Postfix) with ESMTPS id 54579B59185
	for <lists+kasan-dev@lfdr.de>; Tue, 16 Sep 2025 11:01:35 +0200 (CEST)
Received: by mail-wm1-x33f.google.com with SMTP id 5b1f17b1804b1-45f29eb22f8sf11641155e9.0
        for <lists+kasan-dev@lfdr.de>; Tue, 16 Sep 2025 02:01:35 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758013294; cv=pass;
        d=google.com; s=arc-20240605;
        b=CeyvhxGhtEYObZ85a5vb9LkldwrhC+Tw97RR2S1Vn6A2KUAaLOntOwozrHBKa0Q+Pz
         LiE/wbxSUsD6XFFz2hrQpiC25btpRAUKxXopREwZ4t0s+jli0L/PVprV3aqRKlg8bC+x
         Bmc/kQsWgBtuZ8frg7QyK7fOTAkjQgUv2cY/2ojmtGm3JXEbh7JpWM2YipQV0krTjHQL
         XVW0EiOTRUv5zH7hypoF/Nfe9/Ph10jmUdNfM5b52lUAzKb9471INfcgRrXkZCKCniyM
         JapBSP7QtJra+43K+dFTGT11X64s4R6XYThfJKfN3HilHP6Dx6JSV+WYh1GaOrQM7M7j
         ve5g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=Xk4z8vfREPHszktKF+YMThoktDPXN1jl4vMbi1kOxiw=;
        fh=/wT7hdHEf7+HddYYJu11sFntyVCYbk48aOBqTtkfeqs=;
        b=ZYIIGYQ+1IRIn/X7QNI8SQwdPqh8XpF5oUskLNgxOB/EHCLSYlatMJ/g5E4aQcY/ev
         3ZTT3FUnKsTs2s5EItmZrFTYxCX5BURVk5mO4fL7rp4EEtHeRlzmslZTJkWWkVk2RNoz
         Ybydwd7owqn+KGP0+iTjaai3GkruO01PdFv9/7EUl9IaFDp6pKH14GI2NQdDDep1dIvF
         kjl0biJisQ8KIouIt8lB0PJ5Mj2NH/CalmwGzfLn9FW3ZPmRhKmJzziWARDre3sPjbMt
         RliYWOEd2o+ovhGubuiILquVccFSWOC8/QEujVtAUi/MWJLipUOcQu4ixh0rTgEZ9R1w
         rLwQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=eD4BpxhV;
       spf=pass (google.com: domain of ethan.w.s.graham@gmail.com designates 2a00:1450:4864:20::332 as permitted sender) smtp.mailfrom=ethan.w.s.graham@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758013294; x=1758618094; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Xk4z8vfREPHszktKF+YMThoktDPXN1jl4vMbi1kOxiw=;
        b=EvZd7rTVX7ldUBw8WBLnUOQlnicQdPAbNmHvoXm044NJG2i+s83reWkHriMDTyrZjp
         IKXCw1a57ccb96vGj3sFq+/O5/riViCQOgTE+Q+R4QNLmycvKHSSodedE9tBrvHLAEgn
         bLTc7Mf4UiDQjlThvQGXAvy/8q6JIc96V9nJscYQTsACbM/XVgCTY++7XZWx2wdysxyX
         IrHthtUptuWEfCMUuCEZqoJholTrGO7kiMdKSv3ZrGPX5yrIP8OpCXzcivhdF8nHbE7c
         r9Q9Vt2lIMzeN+WJCxfFZ3nDU1YHik/JRGxSl5jbpFvrPHcI5+IADwW7ll62JF4+ASek
         FI/g==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1758013294; x=1758618094; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=Xk4z8vfREPHszktKF+YMThoktDPXN1jl4vMbi1kOxiw=;
        b=KUUJjA/gry7hP5PfCscI4s/O8WPeY8qjpiEvTWugH/AZQHsS4fpqcsBKPtIYsgvZHh
         VDJ1l66doA28+swMBtM+KW6VRplRvM7jYtyFWp7G4KfiPjoXMP3YYMQtngfYU0OS2N0d
         KSbU88TidvQ6vamTVF7HyC0xllzs6h8/MLQA88LldnIOj3b+RSFu/lcDQlhJocUy2KWV
         3dkeZ3cFq086NkdfXg0ZxXp3QZZaaBAzEwFKLiXf49qwmc2gQmafTlOZig2lUKMwKu5v
         HTk7sWc5Vpz5SqMcX+j8DfPmB3ZKXhrhvsZTJUT6uK8XjSbJjYKmGL1kVmwotqQwMIaj
         Zzeg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758013294; x=1758618094;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=Xk4z8vfREPHszktKF+YMThoktDPXN1jl4vMbi1kOxiw=;
        b=bbuH20nbgnoYAGwR69qfWaqBZc3MyGUDsnmwEj6wXXaR/q2RJ+eXfN8sidkpHaDXbL
         AWwODHpLOpPLjTA6HM2R78QyqlvYxm0vIDcXkCeE070Z4h8niBNvyfKpoARCeutEyk57
         adHe+vv8s4iw6if1GF0aGjpoe2t1niEWGljIizSAE7rxWgC7h8TcmZifupUEW5CbKNz5
         lS8augO/Gh7gCYcKdBDj9dE1MtnYvy2P9cRKtDRr96zCHZT5uICPW2NoXUN2khR+zEWY
         Bb9eV6MXD/j3p/VHDrbRuKp/YWne8qYjbk3J9NdCy+flCOH0sgUpRZvu9deRSHQnlxcX
         mTKA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCX5BcbpjI3H8amymcUuk2jYuO8hss//fB7D/4m3NzDak4XXI34u6ZAZoVs2X/WKNBd2sle16A==@lfdr.de
X-Gm-Message-State: AOJu0YwS9tBR8FsZcJ9n8MPIbLKCRGJFGyu0UjfGarTSFmF9wWVVtm7K
	KW702+KG51yqbSYAHW5IsDXG5Z8KQ8M6AFdIr510Dgii6j4/4wqBdNw6
X-Google-Smtp-Source: AGHT+IFgllCCem5zpmlzQopfHTHkQHMqq2cCZQ4b0SvA5xGZmgJgZ10/dEWSYuWM9OKTX8aHszF8fw==
X-Received: by 2002:a05:600c:1911:b0:459:d5d1:d602 with SMTP id 5b1f17b1804b1-45f211c8371mr137274405e9.3.1758013294035;
        Tue, 16 Sep 2025 02:01:34 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfQPzIJm4MnvMp6Eq47SUpd2uabEpxuv8N7Cplz88j0IA==
Received: by 2002:a05:600c:46d1:b0:458:bc96:3b4d with SMTP id
 5b1f17b1804b1-45e0618382bls27913965e9.0.-pod-prod-01-eu; Tue, 16 Sep 2025
 02:01:30 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCU/KMbv97qvUzO0os11rzzp2KPRXs5fy5vc2EU9eKHxSUyZ8ywGtfQZvpgkDuPoNTYP0RS8Z1GOGJ0=@googlegroups.com
X-Received: by 2002:a05:6000:1acd:b0:3e7:615a:17de with SMTP id ffacd0b85a97d-3e765a1a4cemr10865638f8f.47.1758013290250;
        Tue, 16 Sep 2025 02:01:30 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1758013290; cv=none;
        d=google.com; s=arc-20240605;
        b=OM4A/4MxEaaJrlRj9fEkRl1o6JJ3vstK4OMZBUVRPXOdMo19tAOaL547DdtBppBUqi
         5n/mcwb8BjrZMVjhkkGGvPeLSWLNEPEWd6l//bN/BuCGT2NX7rDuiv9YTIRjvrpaT3uy
         WoOymNTRHxvVKhSi44/+pjeGDw+c2GIU5PIltNQJTZRE/Mx3GQw3qRmTM/1y/ocvxDi8
         FDSfurS8OLZPcpAkv8qEG0AdD/TeV/O4ujJWcRjNjCpfuAShpn8lPkrIZnlId4X8rsME
         D94BtRRWVH1TGvPdjtYVu3mFAvJztI0ZD34KRL3DRMUd7l86ctZtdio8We+KBPcyK6Bf
         Yfrg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=54a6vrNAUJqXpuCeRFEgTKA2RP5sTalC0x0PuLBwSM4=;
        fh=lPOoWBTYcubGMbFhyXG7Ep8l0OYm3aU2NMDAfptDXIU=;
        b=PSuGkC5UB449m7MFWseyWg+34kHoT/JXU0pSKRY03G4oC1cd3Es62nDEJummX8r8Wv
         hHd5YlzvsvhAQVv78udcyoSAZJm9haUdocRGjp0r28Q4Gfwrt0qLY3hGIzLqgqU0XELI
         3iq6uXhhc8hm3CjKVUg6LsL+MktZepat1kK5h9eB3KlqYLgwzgkgg0wN9Rri2vcSQVOJ
         XVyrn/2Y44anciSp8R8uu9fLK7InsaNrXol5P80XRkyjWzBFBcl0n5s5DzS+JlaANKLe
         vjVorx7Sk5Ab1WY6FZzR37sVg9P7N2Hj3amtLN3RsflqXFsWDQ9Hy8UEjHcqDXBeQ5dI
         BPwA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=eD4BpxhV;
       spf=pass (google.com: domain of ethan.w.s.graham@gmail.com designates 2a00:1450:4864:20::332 as permitted sender) smtp.mailfrom=ethan.w.s.graham@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x332.google.com (mail-wm1-x332.google.com. [2a00:1450:4864:20::332])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-3ec4efa8d18si37337f8f.3.2025.09.16.02.01.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 16 Sep 2025 02:01:30 -0700 (PDT)
Received-SPF: pass (google.com: domain of ethan.w.s.graham@gmail.com designates 2a00:1450:4864:20::332 as permitted sender) client-ip=2a00:1450:4864:20::332;
Received: by mail-wm1-x332.google.com with SMTP id 5b1f17b1804b1-45df7dc1b98so35314125e9.1
        for <kasan-dev@googlegroups.com>; Tue, 16 Sep 2025 02:01:30 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWK8NcNlgV9wFwKQFNavbUmVso2hxo7VgHrOTKRoiiDxChMnHel5MYqCDUYhsnxhUg+QV+hDa0AK4c=@googlegroups.com
X-Gm-Gg: ASbGncuM+sWt2OUN0wiK4ll+Z48u3zA8cJ7OulagQzPUyvNJ3Gg8BlKxmwGKP3ff3HB
	midxU8DKr6WfmZbc5Hu62cR7vVmpCiORNwCcrC58wcbEEn0BHQzLCA1Vf0A9Hv1e/Ah4ux4nnxf
	5BRO12MSngL6tIY4ae6Dv307J1SQvXp8+W+x7lG+wovvcmXGd7mgFfVnTsrnvjMlKnjMInxV8w0
	zc3jsTmGgLp8MFEHi2RIa278mmU4YeTTOKSIpzSsNYu8qfRp1Qju8Ni3k43kaNaCdF3yTZQqet5
	2D3snggNhzvPElBe1YKrJcX9EwZYmrEGLE5ynmSJaS+BYO2AKWcEE4+yzEnkU7PYkif8NmW9UIH
	+2RPRc7/2ucRa9Zi1n0chHDFmijh4AwGnQSbkTcKpeVr0OE6a9x2zNPun2v0XE0JZsMyT1W2uL+
	TxkJa3yt0kIndu
X-Received: by 2002:a05:600c:4446:b0:45d:f7e4:bf61 with SMTP id 5b1f17b1804b1-45f27ceb2f2mr101342565e9.4.1758013289608;
        Tue, 16 Sep 2025 02:01:29 -0700 (PDT)
Received: from xl-nested.c.googlers.com.com (42.16.79.34.bc.googleusercontent.com. [34.79.16.42])
        by smtp.gmail.com with ESMTPSA id 5b1f17b1804b1-45e037186e5sm212975035e9.5.2025.09.16.02.01.28
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 16 Sep 2025 02:01:28 -0700 (PDT)
From: Ethan Graham <ethan.w.s.graham@gmail.com>
To: ethangraham@google.com,
	glider@google.com
Cc: andreyknvl@gmail.com,
	andy@kernel.org,
	brauner@kernel.org,
	brendan.higgins@linux.dev,
	davem@davemloft.net,
	davidgow@google.com,
	dhowells@redhat.com,
	dvyukov@google.com,
	elver@google.com,
	herbert@gondor.apana.org.au,
	ignat@cloudflare.com,
	jack@suse.cz,
	jannh@google.com,
	johannes@sipsolutions.net,
	kasan-dev@googlegroups.com,
	kees@kernel.org,
	kunit-dev@googlegroups.com,
	linux-crypto@vger.kernel.org,
	linux-kernel@vger.kernel.org,
	linux-mm@kvack.org,
	lukas@wunner.de,
	rmoar@google.com,
	shuah@kernel.org,
	tarasmadan@google.com
Subject: [PATCH v1 09/10] fs/binfmt_script: add KFuzzTest target for load_script
Date: Tue, 16 Sep 2025 09:01:08 +0000
Message-ID: <20250916090109.91132-10-ethan.w.s.graham@gmail.com>
X-Mailer: git-send-email 2.51.0.384.g4c02a37b29-goog
In-Reply-To: <20250916090109.91132-1-ethan.w.s.graham@gmail.com>
References: <20250916090109.91132-1-ethan.w.s.graham@gmail.com>
MIME-Version: 1.0
X-Original-Sender: ethan.w.s.graham@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=eD4BpxhV;       spf=pass
 (google.com: domain of ethan.w.s.graham@gmail.com designates
 2a00:1450:4864:20::332 as permitted sender) smtp.mailfrom=ethan.w.s.graham@gmail.com;
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

Add a KFuzzTest target for the load_script function to serve as a
real-world example of the framework's usage.

The load_script function is responsible for parsing the shebang line
(`#!`) of script files. This makes it an excellent candidate for
KFuzzTest, as it involves parsing user-controlled data within the
binary loading path, which is not directly exposed as a system call.

The provided fuzz target in fs/tests/binfmt_script_kfuzz.c illustrates
how to fuzz a function that requires more involved setup - here, we only
let the fuzzer generate input for the `buf` field of struct linux_bprm,
and manually set the other fields with sensible values inside of the
FUZZ_TEST body.

To demonstrate the effectiveness of the fuzz target, a buffer overflow
bug was injected in the load_script function like so:

- buf_end = bprm->buf + sizeof(bprm->buf) - 1;
+ buf_end = bprm->buf + sizeof(bprm->buf) + 1;

Which was caught in around 40 seconds by syzkaller simultaneously
fuzzing four other targets, a realistic use case where targets are
continuously fuzzed. It also requires that the fuzzer be smart enough to
generate an input starting with `#!`.

While this bug is shallow, the fact that the bug is caught quickly and
with minimal additional code can potentially be a source of confidence
when modifying existing implementations or writing new functions.

Signed-off-by: Ethan Graham <ethangraham@google.com>
---
 fs/binfmt_script.c             |  8 ++++++
 fs/tests/binfmt_script_kfuzz.c | 51 ++++++++++++++++++++++++++++++++++
 2 files changed, 59 insertions(+)
 create mode 100644 fs/tests/binfmt_script_kfuzz.c

diff --git a/fs/binfmt_script.c b/fs/binfmt_script.c
index 637daf6e4d45..c09f224d6d7e 100644
--- a/fs/binfmt_script.c
+++ b/fs/binfmt_script.c
@@ -157,3 +157,11 @@ core_initcall(init_script_binfmt);
 module_exit(exit_script_binfmt);
 MODULE_DESCRIPTION("Kernel support for scripts starting with #!");
 MODULE_LICENSE("GPL");
+
+/*
+ * When CONFIG_KFUZZTEST is enabled, we include this _kfuzz.c file to ensure
+ * that KFuzzTest targets are built.
+ */
+#ifdef CONFIG_KFUZZTEST
+#include "tests/binfmt_script_kfuzz.c"
+#endif /* CONFIG_KFUZZTEST */
diff --git a/fs/tests/binfmt_script_kfuzz.c b/fs/tests/binfmt_script_kfuzz.c
new file mode 100644
index 000000000000..9db2fb5a7f66
--- /dev/null
+++ b/fs/tests/binfmt_script_kfuzz.c
@@ -0,0 +1,51 @@
+// SPDX-License-Identifier: GPL-2.0-or-later
+/*
+ * binfmt_script loader KFuzzTest target
+ *
+ * Copyright 2025 Google LLC
+ */
+#include <linux/binfmts.h>
+#include <linux/kfuzztest.h>
+#include <linux/slab.h>
+#include <linux/sched/mm.h>
+
+struct load_script_arg {
+	char buf[BINPRM_BUF_SIZE];
+};
+
+FUZZ_TEST(test_load_script, struct load_script_arg)
+{
+	struct linux_binprm bprm = {};
+	char *arg_page;
+
+	arg_page = (char *)get_zeroed_page(GFP_KERNEL);
+	if (!arg_page)
+		return;
+
+	memcpy(bprm.buf, arg->buf, sizeof(bprm.buf));
+	/*
+	 * `load_script` calls remove_arg_zero, which expects argc != 0. A
+	 * static value of 1 is sufficient for fuzzing.
+	 */
+	bprm.argc = 1;
+	bprm.p = (unsigned long)arg_page + PAGE_SIZE;
+	bprm.filename = "fuzz_script";
+	bprm.interp = bprm.filename;
+
+	bprm.mm = mm_alloc();
+	if (!bprm.mm) {
+		free_page((unsigned long)arg_page);
+		return;
+	}
+
+	/*
+	 * Call the target function. We expect it to fail and return an error
+	 * (e.g., at open_exec), which is fine. The goal is to survive the
+	 * initial parsing logic without crashing.
+	 */
+	load_script(&bprm);
+
+	if (bprm.mm)
+		mmput(bprm.mm);
+	free_page((unsigned long)arg_page);
+}
-- 
2.51.0.384.g4c02a37b29-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250916090109.91132-10-ethan.w.s.graham%40gmail.com.
