Return-Path: <kasan-dev+bncBDP53XW3ZQCBBAO7WXDAMGQE4HXKX5Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23e.google.com (mail-lj1-x23e.google.com [IPv6:2a00:1450:4864:20::23e])
	by mail.lfdr.de (Postfix) with ESMTPS id 32D6DB8A205
	for <lists+kasan-dev@lfdr.de>; Fri, 19 Sep 2025 16:58:11 +0200 (CEST)
Received: by mail-lj1-x23e.google.com with SMTP id 38308e7fff4ca-363ed2cd4c0sf5991071fa.1
        for <lists+kasan-dev@lfdr.de>; Fri, 19 Sep 2025 07:58:11 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758293890; cv=pass;
        d=google.com; s=arc-20240605;
        b=HhbPUxPb68kL1bXlWy6yLdtLZqPpb5ZYIX182RfCCYfajm5m9QJgYYqpj3duhD4gCO
         EeQ+tf5t4ayUMz8bCBdNkzYxo92UU9i0A5ge8bw1RMcivStXqE3tBvSlyxIPKQ/qVXYq
         z30M5mJtIZ30X1mFPt0X5u/uEdnEoUOIRGDVfukc2W12sssseagR15aUqFrrt2rwyBU+
         0j7aA4wVNJiC7QHccVxaV3qFUMKr3AbhTyFFISAdHfbWLlVmFPo2wKHQ9S4FVhwtwyTa
         U6zqht6hOGgyL+zxTMk+ncv1sqTzBJJu7ZmvKYj4lymVsJLvb1tcmT2CARaP8q3fNgHU
         AUXw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=zm8mKoGL5scR7Eb5yeFn0VPR5aeFlFJ7H23SkaeAjGc=;
        fh=7NIdubsCs6QNqD0Y9wgfeFFwixA9V6UdoNgstIt1RiY=;
        b=cnne9HMjDMviJtJELJFnDvcRlpqY9GLcS/l3iQSaJMWGQdHjX124Q7W8HwHGrRX3NG
         fDJwx6wQxX/QFf4OeogozM3Y1x7nwkCCT1qhMwrPiFZ6u28ytGxyhBxWD92rrqSYyWsz
         N/Wtd05nTcT7LuwP2Xidh0RhHcSeyOkkGrGnPvErH8VgrD2LcKrWL12AeqxFWfsJSFR1
         0mEyedm2GDogDyCSwrwhFbMb1l4IigAQrfotWECMrvlT7d3IuguMwd4fq8yGn3sqS4kQ
         e4s90juDFWK7QcOmpZ+SC0NTLeVwgu1O4hqeW3NBPdC620/duQto+h+cyO+WF3BIcFI3
         bCLQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=A5MUxXDh;
       spf=pass (google.com: domain of ethan.w.s.graham@gmail.com designates 2a00:1450:4864:20::430 as permitted sender) smtp.mailfrom=ethan.w.s.graham@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758293890; x=1758898690; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=zm8mKoGL5scR7Eb5yeFn0VPR5aeFlFJ7H23SkaeAjGc=;
        b=h4ltYXhnLclT5VrUFEsgAVPyt7FbHj2MZuz0TEN3cDAv+MxPfHWgps5/wDD+Bc0BdO
         iZ+FDa33LYZJUg/z/gu1FG4KB8p6KIRYctkEbtgn0jWEYjnpYeSS47wm+RfWrt8pDUs7
         RW8V7Ks2Rs9+q1ZrPwCZaVLXlY3Ec+RN/71rJVW70g6gBrHNyXht9YlboFh2T8kdd66S
         tfJlYf51gt22A5lS584osd2SlG6T9TPKkcouMMNLmFsNNyPw8dnqlgL+RA+6SYEAaM1a
         4RSl/eR3kq97lqKbqcnOopa7BitiN477RELJqSmb9bZHXh2R25bSLhGpaivDBmi4ExKL
         MGqw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1758293890; x=1758898690; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=zm8mKoGL5scR7Eb5yeFn0VPR5aeFlFJ7H23SkaeAjGc=;
        b=UmFI9HxdBc586k2aBbyl5fLDl8B/WTVzWGwEha+fRYDblFCQgLx6UmOddM31J9FMZd
         ax7l4vbSlVCsYRZDF52C/iJKU+uGndtt9D+kMHCz68bF8e4IGbPjqwl1Txle7Wg9YbRu
         UGVU1mjEcH2Kj7yAcAAT1/Myl5hkxAAbWbyiQawhctkM5SM40HCM2Fs5WrTkOFbqAKgM
         /J1xnN7pmK71fiSavxxw7kjU87XrlukqiotvlfNA0ZiQ/I0fMqQ1BAAmBbHQLk9w/8fg
         XZEs0bnao9MQ0yt8UioUi+s7oqnrywoCovqBR0fWPx9xmIwZaLJ/Zt1ZMQE1EF5eXCJP
         ocVQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758293890; x=1758898690;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=zm8mKoGL5scR7Eb5yeFn0VPR5aeFlFJ7H23SkaeAjGc=;
        b=ZR/7ommlPl2I0l2EcERuF5swG1cAOrmlrz1nX+F1xvHUhAp3BbFSgh0HmkZ9CQt9tk
         hhv12/6123JgZdZoz0rduNz2ZF4IcWxA/+1Gn3Ckt68oi3J84Qufk4fHQwUebc5Lm0cn
         lmWGb2O72QMHZk2LD/G+CkH3eiCGDDIFQcY0jbaxCgJA+L/3gTDLlYC8cqidB24eg6Xq
         IpcopqZJm23cf6LKx8gMyucFBd/pznotW2lVbM50pj4ow1LhhcS2vyhaXWXNYVYeqBxb
         KyselOGAVoVs7Eh6EreOdxcYsn+HBvzw98qtXYTqeDCZw0rb9GUsW+Uf0Mre4X4KkVIG
         oVrw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXMduWSvRgKpYnzKcS9qft5V8iz17DYjQx+WzYt/AyEF64+tYWmRJRY2/EgMU92q2GGYOAUsg==@lfdr.de
X-Gm-Message-State: AOJu0YxlSDav+zRiUluWllM0uSSSBLtqWmv8oNn7oAk/0f5kVmBr/hx2
	P8dZWpfiYXRWjfVw86tx/HKKmea2aHcyKtg8zqXjTKZNx5etahJpiFdD
X-Google-Smtp-Source: AGHT+IF3NPfYCy8JNHme7jdCm67BheTBwczFRDFBqPg0kNzmF8jxeeHVunVb0Pu5Y6dvmqtlkmI+Tg==
X-Received: by 2002:a05:651c:4413:20b0:336:7a9a:1b16 with SMTP id 38308e7fff4ca-3641709c411mr8259581fa.14.1758293890213;
        Fri, 19 Sep 2025 07:58:10 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd5kW/MXJtFIB2KJhbq4P0dJH46e3fTxR4r8ZSYKZFGI9A==
Received: by 2002:a05:651c:b06:b0:332:2df3:1cb6 with SMTP id
 38308e7fff4ca-361c8bdaa11ls5220981fa.2.-pod-prod-02-eu; Fri, 19 Sep 2025
 07:58:07 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVr2lxrQG+q5evYePpGyM9mmhv1yBK4HiWItMJJMy4g3e9SbGL9AVbg/lges690R70PMkAasNtuEow=@googlegroups.com
X-Received: by 2002:a2e:a9a3:0:b0:338:1286:bca0 with SMTP id 38308e7fff4ca-3641be61508mr11092471fa.44.1758293886793;
        Fri, 19 Sep 2025 07:58:06 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1758293886; cv=none;
        d=google.com; s=arc-20240605;
        b=Okzl22nrgPL1zFCTDjqivc9KSShWDgTlpWsUR8bxwHSj5hmtJmeDwYwOpRRI8zvoUo
         7+6L3r728UZZOQlLriiXCkiCfbhKYflSpATz/VgSbJ9Aj8rFXuE77DL8Up68oTAtkEkI
         eFlqcmwtY60u/67LO/a/foypM1rSBHJz7FI8MXPWKTd+Jj1lmOUZSJIqzFs80k3xcNcW
         OYFAampyVNNiLdL+SZyeA+v7OfW2wKcjWTq9AZXsRTXaMvvrxDNmoncmjNxUUADEM6sT
         CozphODyDb5mvmCfAMQvNu/OelQr6nHKZJTR3bTr8sOjsbQB4ltPXu8SgyT6/55pld99
         HD8Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=LT1ydHgovraiyOIOgetbRaAa0TBzaulhkSUGdqArzzs=;
        fh=z9FD0xmJiqPcT4QvXHxnOFndRmvRH2+nrITk+VzT3Pk=;
        b=C0N4VgK1tNIl3Lt51OyRB20l8NRZJRA33gAqpH7TvE4skTmNqiPW1L1Zr1fhdbXo7q
         iefxkqSWcdMebZwhg0+tReHbKp0JSFQaJJm6qDSQkC/Pvb0v9Jcx8MMckYizzH1akfwT
         PS3+uJjHgP/ttgq5lCSy4P/e4VBfca8xNOypGDOqWGGjXA7YzBCuSgS5Py8hTdEtVpve
         doLLx+P4/X7YTiEN4Fso1y+zwxzPTXux93tfBFDpF7hmmNJfKn8T8Uk1bJgYG9h/q/WS
         d8+6CUJzLBl1B83TfdQuaK6/vLgT2JZnp3mOa+Uew6jflYHlgI7Qk9x0HPjuY27verIl
         8MMA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=A5MUxXDh;
       spf=pass (google.com: domain of ethan.w.s.graham@gmail.com designates 2a00:1450:4864:20::430 as permitted sender) smtp.mailfrom=ethan.w.s.graham@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x430.google.com (mail-wr1-x430.google.com. [2a00:1450:4864:20::430])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-361a6d7ff1bsi953201fa.6.2025.09.19.07.58.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 19 Sep 2025 07:58:06 -0700 (PDT)
Received-SPF: pass (google.com: domain of ethan.w.s.graham@gmail.com designates 2a00:1450:4864:20::430 as permitted sender) client-ip=2a00:1450:4864:20::430;
Received: by mail-wr1-x430.google.com with SMTP id ffacd0b85a97d-3ee64bc6b90so646834f8f.0
        for <kasan-dev@googlegroups.com>; Fri, 19 Sep 2025 07:58:06 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCX4jyM7Z5x5hHssO35ujhicw8G0uzSXLymAiBSDa8A6G8xhtCjxhok0z2YBH5BOFmfOnVT6CtMoksY=@googlegroups.com
X-Gm-Gg: ASbGncvPyrsF1RUD4BIsGd8OQIgFpyxEZ7CNbTfCITNcETY+M51+euTjyS1FAdV/bQq
	WVIFP4qNSqlxF5ftmwv9SwPUrneJmsa3cpHK+YuJEEoT/a4PIwWoQAkUEgcVux8v5pABEzLqTf/
	FhFB9vBHJ9A1HT8U1fDUZOyvsF6ClerdCh0tVzoPZvZR6CVN/EStL7/qurdxrH7+FM4IGWG8lr3
	y5xCdhplRqljtu/yzsbxd0B3CCFO0aZHZv+lvjJsu4GnmPGymFRlx06aQjhFGdCsHHgkcbAu91C
	l283EZSwcUqC0BFRl5XCa1ITVWLci5jIta0fmjyJVRkyhQY6MaYqUSC6dbKMicPBu6hQ8tTjzAf
	hlcDnrGYzQBSJ25xDbzhZ4izvURbrxt94a2siZUIrfFNjj7kbUxbfM+L/mtW27/Eubve46VRDTf
	Y1l+CdrvkGI+ipVHk=
X-Received: by 2002:a05:6000:144f:b0:3ee:1357:e191 with SMTP id ffacd0b85a97d-3ee8407d5ecmr2286466f8f.30.1758293885827;
        Fri, 19 Sep 2025 07:58:05 -0700 (PDT)
Received: from xl-nested.c.googlers.com.com (124.62.78.34.bc.googleusercontent.com. [34.78.62.124])
        by smtp.gmail.com with ESMTPSA id ffacd0b85a97d-3ee0fbc7188sm8551386f8f.37.2025.09.19.07.58.05
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 19 Sep 2025 07:58:05 -0700 (PDT)
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
	sj@kernel.org,
	tarasmadan@google.com
Subject: [PATCH v2 09/10] fs/binfmt_script: add KFuzzTest target for load_script
Date: Fri, 19 Sep 2025 14:57:49 +0000
Message-ID: <20250919145750.3448393-10-ethan.w.s.graham@gmail.com>
X-Mailer: git-send-email 2.51.0.470.ga7dc726c21-goog
In-Reply-To: <20250919145750.3448393-1-ethan.w.s.graham@gmail.com>
References: <20250919145750.3448393-1-ethan.w.s.graham@gmail.com>
MIME-Version: 1.0
X-Original-Sender: ethan.w.s.graham@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=A5MUxXDh;       spf=pass
 (google.com: domain of ethan.w.s.graham@gmail.com designates
 2a00:1450:4864:20::430 as permitted sender) smtp.mailfrom=ethan.w.s.graham@gmail.com;
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
PR v2:
- Introduce cleanup logic in the load_script fuzz target.
---
---
 fs/binfmt_script.c             |  8 +++++
 fs/tests/binfmt_script_kfuzz.c | 58 ++++++++++++++++++++++++++++++++++
 2 files changed, 66 insertions(+)
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
index 000000000000..26397a465270
--- /dev/null
+++ b/fs/tests/binfmt_script_kfuzz.c
@@ -0,0 +1,58 @@
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
+	bprm.filename = kstrdup("fuzz_script", GFP_KERNEL);
+	if (!bprm.filename)
+		goto cleanup;
+	bprm.interp = kstrdup(bprm.filename, GFP_KERNEL);
+	if (!bprm.interp)
+		goto cleanup;
+
+	bprm.mm = mm_alloc();
+	if (!bprm.mm)
+		goto cleanup;
+
+	/*
+	 * Call the target function. We expect it to fail and return an error
+	 * (e.g., at open_exec), which is fine. The goal is to survive the
+	 * initial parsing logic without crashing.
+	 */
+	load_script(&bprm);
+
+cleanup:
+	if (bprm.mm)
+		mmput(bprm.mm);
+	if (bprm.interp)
+		kfree(bprm.interp);
+	if (bprm.filename)
+		kfree(bprm.filename);
+	free_page((unsigned long)arg_page);
+}
-- 
2.51.0.470.ga7dc726c21-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250919145750.3448393-10-ethan.w.s.graham%40gmail.com.
