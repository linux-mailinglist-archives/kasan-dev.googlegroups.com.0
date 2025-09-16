Return-Path: <kasan-dev+bncBDP53XW3ZQCBB26OUTDAMGQEQZ5SV7A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x340.google.com (mail-wm1-x340.google.com [IPv6:2a00:1450:4864:20::340])
	by mail.lfdr.de (Postfix) with ESMTPS id 32298B59182
	for <lists+kasan-dev@lfdr.de>; Tue, 16 Sep 2025 11:01:33 +0200 (CEST)
Received: by mail-wm1-x340.google.com with SMTP id 5b1f17b1804b1-45df9e11fc6sf30076645e9.3
        for <lists+kasan-dev@lfdr.de>; Tue, 16 Sep 2025 02:01:33 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758013292; cv=pass;
        d=google.com; s=arc-20240605;
        b=ducxlo1UUfDsb4+jImrLydSxQq1tys9fuixbabMBTtU/qfp31a8z6k6mdxcq+tzVgO
         X3pcnGsibkzk3S/F1P9OQ4rnyVfuiTT0jozgyNTDeXFqfLVi13LD3QZ8/2JFwn48gju2
         N1WbSvZc6D2P976jIG+eMhFeEhaQFgqQDcv04R63AHhg6U97coP/mkhfFC7lZj+2rY8r
         qo/0LVgCkQ6XBkGWYCleyXTt72Cz700VHCd7NVtsMhkFtvNcCZjHL+VokPeT48y2B6Vc
         JDR1zYt5stL1jt5vZ4KUhe07nrS2YqNyDUwRvHY3t4jzYRRE5zkBjwqeylIiJBqa8nII
         YqVA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=h7vtXf4/rtl0fVpnMwS11wkZWoPWpAjhXY4mzw6Odmk=;
        fh=FJw8xN0pz6KUIxVMAft3OKv5B6JTHY0ejPb4qd/HtKU=;
        b=g+XNwadmxIufieKzndrr/RbbnIx8ko3P5sVaqDwt32mbYvpIgFcxVzvZmqTrekRK1F
         N+TiIf/PuEJTICeDdAI0bc19fqGTNh2dTsj7U30L8v8W91VxFWfdwPQgtPKtxmP4CbM/
         XecX8MF0V7RBSklh78qJo3gq1HSXi9M96ctjrY6GqwfLDYWY1AiRs0cM7g8MfTzOcKQD
         P97rRVKfDzjFd3SOuq9eB9j595WZMNtVmJydtn3GgyLUgaJKJQ9xZB9e/V5VJYalyhBU
         yXYIsMbnMt19x4wrBnEt+hO/kaGqm0xfjkqeJ1BX59jMk0faZYN9NYCJuFrQRJrMZCHi
         0Rww==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b="jca/0X45";
       spf=pass (google.com: domain of ethan.w.s.graham@gmail.com designates 2a00:1450:4864:20::32f as permitted sender) smtp.mailfrom=ethan.w.s.graham@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758013292; x=1758618092; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=h7vtXf4/rtl0fVpnMwS11wkZWoPWpAjhXY4mzw6Odmk=;
        b=dNdVL+W7uO3J5/Bffrl3SyzcHkVcbDsf6JNtxQHfLm8HQxtk1brI2EmDQ21l9kjguH
         3epE1PFALSpN3BIVt0oVUyq2y/85BX0YHDBmTSMw/FkAX5k3S3TxzdxN79YC67M9jCBL
         3ahPxSEchIOh6rzKsma05m/rjv9WJhiv/KQ8pZNTOFuGyFISm1I8gY9d16ItC+hkdiwU
         b295hiXhL2D6Ukjq+va1diOZTJJ8qydyzd8e5Tn4Qro5d/4S7v0vwPJzXg9TlWH7Asdq
         gM0NXiEV/JfqQNqkbMgHIO7HMiEuzyVn308G7+UamFlQ5QKfTf+a7AzbGkOssrTDNFR/
         FtEA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1758013292; x=1758618092; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=h7vtXf4/rtl0fVpnMwS11wkZWoPWpAjhXY4mzw6Odmk=;
        b=boZtFXzAUJGNgkVibmi2xdVS69TUGZKlvcI18haYcATYmOa+IZaLqZOKd/e/CzAdWx
         ibQBSOBk05alRRHNltlavnR7iPRroj4kVJhWqB4EnLUwTN/n6J6cWstzPTj9oYLt70qC
         E3TBRaCUxM/zCpkQmdMreSgGxW1cuFghNRurpNwb4uzqT4XboReZJ/c9q34B9OTxJxa4
         NkhcEySpwAiR0fnF92mY4n+ZuQeSsoBi23tQ10hRSBnAlIKUfer+JmCZH0SE22ZDxeWE
         6PW+2kd4swheuijetwXIj1LwemUutT+myuHU+aSSkDhP9iv3h1hHRAuZlT7ptBuh5NmO
         aNQw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758013292; x=1758618092;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=h7vtXf4/rtl0fVpnMwS11wkZWoPWpAjhXY4mzw6Odmk=;
        b=kyNhMk7Y3i9VJ9ELX6YF9ROHgolhdLxzNJEvV6yiILOI15RqV1TwJ7T8DWbUkdjwM6
         KtZt5RDBeacvPXIr0UtuttZUeT71bnnNwVslelP0JfabFwAqgAsYopWAYtSPJqwfeG4L
         OGCArstiqeZ0uTOA68kMcg5xHocgKqTzsOwpQQBAHdZqRRrm7np8fkq2EgG5hUvpPHA1
         ksVgWoGSWwZAlghnlZDjU0D4JzKI0K1cx2GnwaWoB8QtFCJ8XcTWLKPUSv+FQjo5gAMq
         jaLuesXR1TeYAGlg+8SqAnQRnhC3suevQdc3HXGy64QmCwmqjqZQERC0fweJQVUBr0yl
         Aevw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWEbbpcbvoif2fiNFLmyo0pb4Sc+YdD77Ip0ZyNwOOZ7ZkI50rzWEApZkk+OvZpVzyOAQliSQ==@lfdr.de
X-Gm-Message-State: AOJu0YxUWeYEtN+6Y53UqgG9w1BJTw5l0TjZmSSHl9jkhXIirAZwIgU8
	a/WfDJzcFVVFeFoHOu4WGxIGoYw+dwm411295UOBhXd2j/cXjBDU9ez7
X-Google-Smtp-Source: AGHT+IGzzqKoABof6+cy3Vnky7lKPY4eHdS0WJGDccGvkWBatb54TGd4hH0dPhQqcXEDmJncLnQKBw==
X-Received: by 2002:a05:600c:138a:b0:456:19eb:2e09 with SMTP id 5b1f17b1804b1-45f211e575dmr168599845e9.8.1758013292028;
        Tue, 16 Sep 2025 02:01:32 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd7BY3Sy92Y14n9i2gdUx1q7iSxEAJwB4DTVZO3OmWy/Hw==
Received: by 2002:a05:600c:8409:b0:45b:6fba:90de with SMTP id
 5b1f17b1804b1-45dffc1cf2dls27766035e9.2.-pod-prod-08-eu; Tue, 16 Sep 2025
 02:01:29 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCX6eOS+xLdTAOVJlsYAQ6EgONiHg/dF5rueHHtCrmLM/rRNuqXVUYxdSoHSByJIIcZvhIPC/x0fZV0=@googlegroups.com
X-Received: by 2002:a05:600c:45c5:b0:453:66f:b96e with SMTP id 5b1f17b1804b1-45f211ef88dmr139610255e9.11.1758013288952;
        Tue, 16 Sep 2025 02:01:28 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1758013288; cv=none;
        d=google.com; s=arc-20240605;
        b=D/P/1xwmpC5XZObfKZNojhGzYlq4o6rxRMEzMp+DxlkYERDT5NlDuI3Si+YNLoDRJN
         bOjTcr0HJl5I6V5I85Er6t+6g+UiuG0NFASQ3AI7qerlJkSOJfGQhtHZwZ0Q6/WXpPrJ
         /lDH0zegpyDyMYjKji35jbSr7hrdwbdF+QXqdGgLdHxwHWLCrlJwN9PuiRBOObfoLdO3
         uhhUWdeWNnbwow/8pKcxLczr1TaRcEQpU3OasZCUL0HVRz6z6ZyfNEbwAxJ7IbVe7A9I
         VHMrBw8Gl1PPqqpPHTLVqX4+1rmhO2QLQAXv6JrRjxSYp48/NdE0v4rUost0+UBaa1Cu
         fakg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=DO9AFhAl9ilu83R9AZsAc7oWiIru4g9kqtmWSFQA0xE=;
        fh=5CG6ynoQuwTN7/ufHetQqWo82hz6xXR6EmVoYOkKHLc=;
        b=Nv8GUUrBxXjxPF//vUfM1CM0h1jAo0HDsyiLrJqA1mA+u/fJg9h4apTuux0NuziXys
         ajElsV0DrmYXsYfPM03EL8qVieDtamRWxMC5HETo0hR2G++y9T0xv4GEsibtpuwFcT15
         4twAmwJELhPt7CQe7tXin0Bqgz5cx7iYSBq/pJxzgiKb/8Yk2SThISzhc/DxjKhstCYJ
         hTJIx7bR4YBS3uPEefFeEzvMASU6WOUUN40Prdt1KaaE2HmZ6oHryEKQ8coPtvMPRg8L
         UMxaQWE4N94uSUbkgg1TAU6MIUUNjYe00L3PkHp3wRxMYEn0LRpML3WYy9XHbrheXSw5
         h6ug==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b="jca/0X45";
       spf=pass (google.com: domain of ethan.w.s.graham@gmail.com designates 2a00:1450:4864:20::32f as permitted sender) smtp.mailfrom=ethan.w.s.graham@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x32f.google.com (mail-wm1-x32f.google.com. [2a00:1450:4864:20::32f])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-45f2cfd66bcsi1101725e9.0.2025.09.16.02.01.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 16 Sep 2025 02:01:28 -0700 (PDT)
Received-SPF: pass (google.com: domain of ethan.w.s.graham@gmail.com designates 2a00:1450:4864:20::32f as permitted sender) client-ip=2a00:1450:4864:20::32f;
Received: by mail-wm1-x32f.google.com with SMTP id 5b1f17b1804b1-45b4d89217aso37533345e9.2
        for <kasan-dev@googlegroups.com>; Tue, 16 Sep 2025 02:01:28 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXLrefWNwT3pL1d8fddVBIcY4mRa/O7Kz+EE0GAWS1COo8Mtr5iCQ7eEZhi0REqW+tplrCPAabh2RM=@googlegroups.com
X-Gm-Gg: ASbGnct12pIF+q4ZUkQiJ/7/x71HQ5CGHMWGomKtta03BPFrK3kAkDEQlDwCmgejR/H
	/UIs36H5qyTKy2Mha2ZRKfDcqeDzMO6K5UsjfRF3gQaFI5KSxQre55ZsZsLMs8lUvBUZKiSkEyg
	h22A+zk+yT5WwGO2OtgHaKeuurZvZyGcg4Tk05/vXI2RxRew56wg92zWexjamO2/32jLllA9NoK
	Gz1bp8aG2sgCRdq4/bYO8lBqPQMTQpPFHYJiKdS8u8B6FKGNkq+4yPrV2XckWvYJN62NLH+k1UQ
	3sp/9QVjf5H2dTBdrX+jeZBKkw53sg43E+kw62/NK2kKfK//fSUvxnlKky09Lwdp88WNNUemlyO
	pOGr6xzJKxK3lmXcIqkU+rCQhjXyB4mpGkFPC38zVbBP+3IN5XlXEV/hjCdZ8cXpEBVMZxCxy4h
	Ot+SowQKnp6jrI6xNEPjomvZc=
X-Received: by 2002:a05:600c:3b87:b0:45f:2cd5:5086 with SMTP id 5b1f17b1804b1-45f2d345de3mr59942395e9.3.1758013288120;
        Tue, 16 Sep 2025 02:01:28 -0700 (PDT)
Received: from xl-nested.c.googlers.com.com (42.16.79.34.bc.googleusercontent.com. [34.79.16.42])
        by smtp.gmail.com with ESMTPSA id 5b1f17b1804b1-45e037186e5sm212975035e9.5.2025.09.16.02.01.27
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 16 Sep 2025 02:01:27 -0700 (PDT)
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
Subject: [PATCH v1 08/10] drivers/auxdisplay: add a KFuzzTest for parse_xy()
Date: Tue, 16 Sep 2025 09:01:07 +0000
Message-ID: <20250916090109.91132-9-ethan.w.s.graham@gmail.com>
X-Mailer: git-send-email 2.51.0.384.g4c02a37b29-goog
In-Reply-To: <20250916090109.91132-1-ethan.w.s.graham@gmail.com>
References: <20250916090109.91132-1-ethan.w.s.graham@gmail.com>
MIME-Version: 1.0
X-Original-Sender: ethan.w.s.graham@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b="jca/0X45";       spf=pass
 (google.com: domain of ethan.w.s.graham@gmail.com designates
 2a00:1450:4864:20::32f as permitted sender) smtp.mailfrom=ethan.w.s.graham@gmail.com;
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

Add a KFuzzTest fuzzer for the parse_xy() function, located in a new
file under /drivers/auxdisplay/tests.

To validate the correctness and effectiveness of this KFuzzTest target,
a bug was injected into parse_xy() like so:

drivers/auxdisplay/charlcd.c:179
- s = p;
+ s = p + 1;

Although a simple off-by-one bug, it requires a specific input sequence
in order to trigger it, thus demonstrating the power of pairing
KFuzzTest with a coverage-guided fuzzer like syzkaller.

Signed-off-by: Ethan Graham <ethangraham@google.com>
---
 drivers/auxdisplay/charlcd.c             |  8 ++++++++
 drivers/auxdisplay/tests/charlcd_kfuzz.c | 20 ++++++++++++++++++++
 2 files changed, 28 insertions(+)
 create mode 100644 drivers/auxdisplay/tests/charlcd_kfuzz.c

diff --git a/drivers/auxdisplay/charlcd.c b/drivers/auxdisplay/charlcd.c
index 09020bb8ad15..e079b5a9c93c 100644
--- a/drivers/auxdisplay/charlcd.c
+++ b/drivers/auxdisplay/charlcd.c
@@ -682,3 +682,11 @@ EXPORT_SYMBOL_GPL(charlcd_unregister);
 
 MODULE_DESCRIPTION("Character LCD core support");
 MODULE_LICENSE("GPL");
+
+/*
+ * When CONFIG_KFUZZTEST is enabled, we include this _kfuzz.c file to ensure
+ * that KFuzzTest targets are built.
+ */
+#ifdef CONFIG_KFUZZTEST
+#include "tests/charlcd_kfuzz.c"
+#endif /* CONFIG_KFUZZTEST */
diff --git a/drivers/auxdisplay/tests/charlcd_kfuzz.c b/drivers/auxdisplay/tests/charlcd_kfuzz.c
new file mode 100644
index 000000000000..28ce7069c65c
--- /dev/null
+++ b/drivers/auxdisplay/tests/charlcd_kfuzz.c
@@ -0,0 +1,20 @@
+// SPDX-License-Identifier: GPL-2.0-or-later
+/*
+ * charlcd KFuzzTest target
+ *
+ * Copyright 2025 Google LLC
+ */
+#include <linux/kfuzztest.h>
+
+struct parse_xy_arg {
+	const char *s;
+};
+
+FUZZ_TEST(test_parse_xy, struct parse_xy_arg)
+{
+	unsigned long x, y;
+
+	KFUZZTEST_EXPECT_NOT_NULL(parse_xy_arg, s);
+	KFUZZTEST_ANNOTATE_STRING(parse_xy_arg, s);
+	parse_xy(arg->s, &x, &y);
+}
-- 
2.51.0.384.g4c02a37b29-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250916090109.91132-9-ethan.w.s.graham%40gmail.com.
