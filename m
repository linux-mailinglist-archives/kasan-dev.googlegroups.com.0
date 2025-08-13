Return-Path: <kasan-dev+bncBDP53XW3ZQCBBZNK6LCAMGQEGINHKRQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23e.google.com (mail-lj1-x23e.google.com [IPv6:2a00:1450:4864:20::23e])
	by mail.lfdr.de (Postfix) with ESMTPS id 3BC6FB24AC0
	for <lists+kasan-dev@lfdr.de>; Wed, 13 Aug 2025 15:38:47 +0200 (CEST)
Received: by mail-lj1-x23e.google.com with SMTP id 38308e7fff4ca-3323682d9bbsf34953071fa.0
        for <lists+kasan-dev@lfdr.de>; Wed, 13 Aug 2025 06:38:47 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755092326; cv=pass;
        d=google.com; s=arc-20240605;
        b=UvztjmtAvIeyKE0E1RIXLSwpWVDu8YH6vONLbMAcCi3BdMsP8WmGC9JCbLTJKIIgqv
         bFwNC5cDSYWCALcGvWvVQbpNHzZQcAuhmsBYU8OZa9ZqWLNbZD5KWWtG8JUM92SsN943
         E/x7mrQWDY2KHhxrvoxyDg0/pc3O/hZUO9BcxoZg6olGfw+pnO/MEDj/LFeASqzPPhVa
         gMnHlqgNqWsUj2BCPkolkK6nQXFYgWwxyO2xNtGVxvoCFsWUPZ/JI+k/fE0cYF217Gta
         Kj96vKbEA7RqhlQeh6oQT1vX4lXKT+WwkDz3wmVPGw+TVAQuX7FQ2B/SseQKkJDtyC4f
         ckVw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=hjQMTqrm3EkysOrmDbUD/3DRXtBeOe/h94kbzkHHEZo=;
        fh=Kij08AWNnpoXN/Gt8yH6a7Kjr7WnZINON02PAeMF8is=;
        b=QtJHG8R7giB9rDr8aOoKQMYqJZWOlrg0tEruR7rWtscAIScXajiAPaEtcUPKAsDRL2
         96yxEy0s0K9+UZDV7kiw93sQ+XlR6chpuNaUvO1aHBRcRdqHUzbvaNN+Ct1m5wDJGDZZ
         EXA9tuTBDAqcGtoiDfNtYRPCJH1rPVLkMCTf8Ze0j9gJj3SC9COIrsDCRADDRiwuGsih
         mrnNngmqmgyZ/OFyihiLdRgm/WpHEPNjKNCNx4BUgeR9obT2LdYxnitNHbqoA1mCckTO
         NEPYTLZove/W39GIqBt/1q2f3gGE+dSQLC80W1qzUV8IZef4MyMO7wWC+xpYIHYOqruw
         N/UQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=YGpwe0vH;
       spf=pass (google.com: domain of ethan.w.s.graham@gmail.com designates 2a00:1450:4864:20::433 as permitted sender) smtp.mailfrom=ethan.w.s.graham@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755092326; x=1755697126; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=hjQMTqrm3EkysOrmDbUD/3DRXtBeOe/h94kbzkHHEZo=;
        b=uL+b4G8tmZDYptMI63x/w3c+llCHqs+du0gxfkqJm6kghRHaW8pDdjzAXRri8rfHQW
         gZeLA+MUP7WHPi6pwD+kWWL6mRVohfPEsYGomnILFtgCCtyUkiI00fb9YzLmBo08JebC
         XoGs3BPZpXsWdLJ6BLmylImHBo3TDsL7jhY4dOgVrvfzTQuktgnD9/t72QgRQscoWFN7
         7smaTc7oPmmtD79G1X92M9mRy2IvvvDDsUot5lIUKQCRFb7KcWP3DDCOOSLrJEW3m4Pl
         WXjTFcQfMrQlfrZ+hJvxye5x/RGbcPpeqEr9+yYizHPdWAdCdg6wfQrL/zPEIj3f5nsA
         nMIw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1755092326; x=1755697126; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=hjQMTqrm3EkysOrmDbUD/3DRXtBeOe/h94kbzkHHEZo=;
        b=bVSx1Dfr89gjEroogs+XN4ZiRRWmm5NH2rh4TCtyfRRUDTMGMj+YAMMJakeGg2vRHv
         CwKfKrIYJBas5A3gg6rUy2g8QGH/7b4o3pAMXtJgjh7gPuEwwRyZg9puL80upVDkahCq
         NjyeqmbrmlUYs/+j4EbAL8rowoL3xvVwsqKVehenPjlaoYIIzqNbrVItJZ9M50yzsffw
         O35kFgCsLAt4fh068DM6QgCrm7fAh8iwZ5Q9SDOEuKF4UyRCMm42RtOpA3wGH3O/IK81
         6VY6QBjxM7qy7Yb4+cz6YEW6KamTKI5nqwgVsZYL0O2Uny8618Yn1ZWuJnDlAM4z1zeK
         ERzw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755092326; x=1755697126;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=hjQMTqrm3EkysOrmDbUD/3DRXtBeOe/h94kbzkHHEZo=;
        b=xLRffioHGNj8pYYTM0bqzt1Gfv/ZwNovDk3qq1KYW7YVa7yT1jo1s7Qi5k3YxnGTIy
         9ErO0+7w1msxA6YvI6nmEUziOKgiTL9m0G5N6i49gldOee4/xVicFLDY+AjtnnfqLAXJ
         cboUv8kXjiqOkuN/3a0slKRUZ98zOdUXuyJ7pgSECriWltoRwH+hQ5VbVX0uPl8drvSS
         fco7b38/cuc++QXGPxl+MEtCN/dNQAHisg3wDbl8etnqh+MtI2rmw7p4TJZ5YvosvK7t
         SaIfm46mZPcXdHyhS2Vc4dIVfv3uiJFmY0b+rkNfFPnK017fuT100C5J8b3O59Ve6h5B
         iV3Q==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUapf5G/q3sNf0KYOYnjB1RgatXKrJixahLwq0BHNn2fBkbHpGC50k6ivLoVTOLHH5TghnowQ==@lfdr.de
X-Gm-Message-State: AOJu0YyefG5a2TpjxUoa9N1FpUiptGRCTJ3SumdtxD5DgV4CX484hzXN
	gkc6JZS89yd7EIjhednWROUSQ1rsbAmT5gTEBDHjonb+hkfgfobksxtk
X-Google-Smtp-Source: AGHT+IGeARFZDsEmZspbffmoU7oQq+CTW4KeRTzn34nx1RQbG2QVYe011wnjMILntWiwfwRP1pNtmQ==
X-Received: by 2002:a2e:830c:0:b0:32b:541c:eae1 with SMTP id 38308e7fff4ca-333e9b1e68emr6604411fa.25.1755092325992;
        Wed, 13 Aug 2025 06:38:45 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZf7//jwn1iPqqZJBhLmhrrRxCV20Vi8vQXZpVXIUKMm9A==
Received: by 2002:a2e:b80e:0:b0:32a:5c14:7f1e with SMTP id 38308e7fff4ca-3338c4ca6b1ls14425621fa.2.-pod-prod-01-eu;
 Wed, 13 Aug 2025 06:38:42 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUVgsT97R8hSOaIuywsyzAtWAvMK7N5jAH5a5WyCPtcTUj4+qAT7BVxcWUIIaGLJ3h9E43uZXsLQKE=@googlegroups.com
X-Received: by 2002:a05:651c:150b:b0:332:5171:3114 with SMTP id 38308e7fff4ca-333e966cda1mr7335201fa.10.1755092322523;
        Wed, 13 Aug 2025 06:38:42 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755092322; cv=none;
        d=google.com; s=arc-20240605;
        b=kiQiva/dHBjFXwofws0yPNLSYn3PjFv1DtzA+P4A/wLE8z0hzjAxB8mRIVGfY5IX3Z
         HUIDM93jHkVf9bqK0yOO8SZB8Devh9eG1A1Eh0bhU33uziyjyKChdkY8ngxBo9LctNbR
         yN2K4NYXSExLkzO+RzqzRMog0ObaEYCgXBJO6t4ZuuSgYGlph1XphkShMf6AqE8zM2fQ
         l/CWe61L/OGWrhKmMzeIRikHT0/xfLQwrXu5Q0kzYzzEUpAuhPLHtpK5I2ISs+J8h9ys
         jwX6XUOZxd+URNajwhn1UxLpw5ACMFu8Zjm0Y0EfHI8vot5iXhUEk7Cw3irq5/JibpBp
         MwlQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=NqDz/RTemVf8hk/fnHnI91a5xRvLZSkfIpeLZw9SlZs=;
        fh=EqIhPZTpuR8QmIwVH0/Lmu0ss/hUf7FD8Ly+eRzpxAY=;
        b=H65wLRc97Ruxl6mMatzQheLdfv1daYmNB+wLtED0TigXLeZR3A9V+drWsjWuF2/MBw
         W5N58tPSk5imc76dbRjNOdSYoQG5oXJh5RmPwMQIbiiPAreq+8mrJiJR6UQClqbWg478
         bqDC1pcA/VI2Dk/rMi6Exs3o+duhvccqsVIvif1wt5Vvg6a+WKYvyKQOEiI2BbhOzNGl
         c7M4DROCcsnElLYlSQbDrsUrGjnL6IDdn1AxOGzFA3ygtShYDYIVgYizAMgntft86xuB
         SbrAblM/elaeqBdetRQUP4UPtWt72YhajAAYLhucD+fkiN+FqLLXxDMUUe/BfK+0JhgT
         EgcQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=YGpwe0vH;
       spf=pass (google.com: domain of ethan.w.s.graham@gmail.com designates 2a00:1450:4864:20::433 as permitted sender) smtp.mailfrom=ethan.w.s.graham@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x433.google.com (mail-wr1-x433.google.com. [2a00:1450:4864:20::433])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-3323819ea8asi3052761fa.8.2025.08.13.06.38.42
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 13 Aug 2025 06:38:42 -0700 (PDT)
Received-SPF: pass (google.com: domain of ethan.w.s.graham@gmail.com designates 2a00:1450:4864:20::433 as permitted sender) client-ip=2a00:1450:4864:20::433;
Received: by mail-wr1-x433.google.com with SMTP id ffacd0b85a97d-3b9141866dcso1083908f8f.2;
        Wed, 13 Aug 2025 06:38:42 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVC4TapfBb9l4+rrAc8lk0ZKTTOjrFMAn6uGmk9vz2mT0BA9Pis7lKh2SD0cnKjjI+wHC675LOjsEOu@googlegroups.com, AJvYcCWyLmhyH/Dmw41t5uq8GVAH2pTh9A88pr0I1MrvzaDjubZ2l4dLYGDqiukd6Z4NGqSXuNi6zeB76I8=@googlegroups.com
X-Gm-Gg: ASbGncuxFJYjW52XKqASUk1G3B3ARcUU6RHiYbOXISh8b/41hHhzbrB0EmfC0v0uJlY
	9W3v8EvlIexipoDQjbxPmASFhpSjt4qfG/9rJrIYLf3K9/Y20KW7jd49JqGgTAAMLh1tcdmLdkA
	zQ2XI8aXdlV+LWpDPjLj3FIFd5JVWyOSpe7YL86hVbJvUsMvauUvko/lR0qOI2Dqll8BbZAYAzq
	aEgYHTaEj0qgVakDg4Hgq7AmmTL82S8/gCfpbIKOkQfyBjq6N7T7hJYEOetOvZtIIxRptCh9cSQ
	JHnAD+tJUcZ45Bcqj+oix6R7xYfGXEbzxJdDBX4n1FHQzAHLCmbNV0fLdZLs3dEmBNI/hTp7or/
	YqyBTo3TBQXRFVVC1ZgehPJQ4xpD+c9lJ6u7maqMB5U6/AZFDkAC9IQAfnR8OgiqioW7/v1Mnle
	2exnMgln1Z2pJ3L5g=
X-Received: by 2002:a05:6000:240b:b0:3b8:d08c:cde5 with SMTP id ffacd0b85a97d-3b917eb47ebmr2500162f8f.43.1755092321515;
        Wed, 13 Aug 2025 06:38:41 -0700 (PDT)
Received: from xl-nested.c.googlers.com.com (87.220.76.34.bc.googleusercontent.com. [34.76.220.87])
        by smtp.gmail.com with ESMTPSA id ffacd0b85a97d-3b8f8b1bc81sm25677444f8f.69.2025.08.13.06.38.40
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 13 Aug 2025 06:38:40 -0700 (PDT)
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
Subject: [PATCH v1 RFC 3/6] kfuzztest: implement core module and input processing
Date: Wed, 13 Aug 2025 13:38:09 +0000
Message-ID: <20250813133812.926145-4-ethan.w.s.graham@gmail.com>
X-Mailer: git-send-email 2.51.0.rc0.205.g4a044479a3-goog
In-Reply-To: <20250813133812.926145-1-ethan.w.s.graham@gmail.com>
References: <20250813133812.926145-1-ethan.w.s.graham@gmail.com>
MIME-Version: 1.0
X-Original-Sender: ethan.w.s.graham@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=YGpwe0vH;       spf=pass
 (google.com: domain of ethan.w.s.graham@gmail.com designates
 2a00:1450:4864:20::433 as permitted sender) smtp.mailfrom=ethan.w.s.graham@gmail.com;
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

Add the core runtime implementation for KFuzzTest. This includes the
module initialization, and the logic for receiving and processing
user-provided inputs through debugfs.

On module load, the framework discovers all test targets by iterating
over the .kfuzztest_target section, creating a corresponding debugfs
directory with a write-only 'input' file for each of them.

Writing to an 'input' file triggers the main fuzzing sequence:
1. The serialized input is copied from userspace into a kernel buffer.
2. The buffer is parsed to validate the region array and relocation
   table.
3. Pointers are patched based on the relocation entries, and in KASAN
   builds the inter-region padding is poisoned.
4. The resulting struct is passed to the user-defined test logic.

Signed-off-by: Ethan Graham <ethangraham@google.com>
---
 lib/Makefile           |   2 +
 lib/kfuzztest/Makefile |   4 +
 lib/kfuzztest/main.c   | 161 +++++++++++++++++++++++++++++++
 lib/kfuzztest/parse.c  | 208 +++++++++++++++++++++++++++++++++++++++++
 4 files changed, 375 insertions(+)
 create mode 100644 lib/kfuzztest/Makefile
 create mode 100644 lib/kfuzztest/main.c
 create mode 100644 lib/kfuzztest/parse.c

diff --git a/lib/Makefile b/lib/Makefile
index c38582f187dd..511c44ef4b19 100644
--- a/lib/Makefile
+++ b/lib/Makefile
@@ -354,6 +354,8 @@ obj-$(CONFIG_GENERIC_LIB_CMPDI2) += cmpdi2.o
 obj-$(CONFIG_GENERIC_LIB_UCMPDI2) += ucmpdi2.o
 obj-$(CONFIG_OBJAGG) += objagg.o
 
+obj-$(CONFIG_KFUZZTEST) += kfuzztest/
+
 # pldmfw library
 obj-$(CONFIG_PLDMFW) += pldmfw/
 
diff --git a/lib/kfuzztest/Makefile b/lib/kfuzztest/Makefile
new file mode 100644
index 000000000000..142d16007eea
--- /dev/null
+++ b/lib/kfuzztest/Makefile
@@ -0,0 +1,4 @@
+# SPDX-License-Identifier: GPL-2.0
+
+obj-$(CONFIG_KFUZZTEST) += kfuzztest.o
+kfuzztest-objs := main.o parse.o
diff --git a/lib/kfuzztest/main.c b/lib/kfuzztest/main.c
new file mode 100644
index 000000000000..fccda1319fb0
--- /dev/null
+++ b/lib/kfuzztest/main.c
@@ -0,0 +1,161 @@
+// SPDX-License-Identifier: GPL-2.0
+/*
+ * KFuzzTest core module initialization and debugfs interface.
+ *
+ * Copyright 2025 Google LLC
+ */
+#include <linux/debugfs.h>
+#include <linux/fs.h>
+#include <linux/kfuzztest.h>
+#include <linux/module.h>
+#include <linux/printk.h>
+
+MODULE_LICENSE("GPL");
+MODULE_AUTHOR("Ethan Graham <ethangraham@google.com>");
+MODULE_DESCRIPTION("Kernel Fuzz Testing Framework (KFuzzTest)");
+
+extern const struct kfuzztest_target __kfuzztest_targets_start[];
+extern const struct kfuzztest_target __kfuzztest_targets_end[];
+
+/**
+ * struct kfuzztest_dentry - A container for a debugfs dentry and its fops.
+ * @dentry: Pointer to the created debugfs dentry.
+ * @fops: The file_operations struct associated with this dentry.
+ *
+ * This simplifies state management by keeping a file's dentry and its
+ * operations bundled together.
+ */
+struct kfuzztest_dentry {
+	struct dentry *dentry;
+	struct file_operations fops;
+};
+
+/**
+ * struct kfuzztest_debugfs_state - Per-test-case debugfs state.
+ * @test_dir: The top-level debugfs directory for a single test case, e.g.,
+ * /sys/kernel/debug/kfuzztest/<test-name>/.
+ * @input_dentry: The state for the "input" file, which is write-only.
+ *
+ * Wraps all debugfs components created for a single test case.
+ */
+struct kfuzztest_debugfs_state {
+	struct dentry *target_dir;
+	struct kfuzztest_dentry input_dentry;
+};
+
+/**
+ * struct kfuzztest_simple_fuzzer_state - Global state for the KFTF module.
+ * @kfuzztest_dir: The root debugfs directory, /sys/kernel/debug/kfuzztest/.
+ * @debugfs_state: A statically sized array holding the state for each
+ *	registered test case.
+ */
+struct kfuzztest_state {
+	struct file_operations fops;
+	struct dentry *kfuzztest_dir;
+	struct kfuzztest_debugfs_state *debugfs_state;
+};
+
+/* Global static variable to hold all state for the module. */
+static struct kfuzztest_state state;
+
+const umode_t KFUZZTEST_INPUT_PERMS = 0222;
+
+/**
+ * kfuzztest_init - Initializes the debug filesystem for KFuzzTest.
+ *
+ * Each registered test in the ".kfuzztest" section gets its own subdirectory
+ * under "/sys/kernel/debug/kfuzztest/<test-name>" with one files:
+ *	- input: write-only file to send input to the fuzz driver
+ *
+ * Returns:
+ *	0 on success.
+ *	-ENODEV or other error codes if debugfs creation fails.
+ */
+static int __init kfuzztest_init(void)
+{
+	const struct kfuzztest_target *targ;
+	int ret = 0;
+	int i = 0;
+	size_t num_test_cases;
+
+	num_test_cases = __kfuzztest_targets_end - __kfuzztest_targets_start;
+
+	state.debugfs_state =
+		kzalloc(num_test_cases * sizeof(struct kfuzztest_debugfs_state),
+			GFP_KERNEL);
+	if (!state.debugfs_state)
+		return -ENOMEM;
+
+	/* Create the main "kfuzztest" directory in /sys/kernel/debug. */
+	state.kfuzztest_dir = debugfs_create_dir("kfuzztest", NULL);
+	if (!state.kfuzztest_dir) {
+		pr_warn("KFuzzTest: could not create debugfs");
+		return -ENODEV;
+	}
+
+	if (IS_ERR(state.kfuzztest_dir)) {
+		state.kfuzztest_dir = NULL;
+		return PTR_ERR(state.kfuzztest_dir);
+	}
+
+	for (targ = __kfuzztest_targets_start; targ < __kfuzztest_targets_end;
+	     targ++, i++) {
+		/* Create debugfs directory for the target. */
+		state.debugfs_state[i].target_dir =
+			debugfs_create_dir(targ->name, state.kfuzztest_dir);
+
+		if (!state.debugfs_state[i].target_dir) {
+			ret = -ENOMEM;
+			goto cleanup_failure;
+		} else if (IS_ERR(state.debugfs_state[i].target_dir)) {
+			ret = PTR_ERR(state.debugfs_state[i].target_dir);
+			goto cleanup_failure;
+		}
+
+		/* Create an input file under the target's directory. */
+		state.debugfs_state[i].input_dentry.fops =
+			(struct file_operations){
+				.owner = THIS_MODULE,
+				.write = targ->write_input_cb,
+			};
+		state.debugfs_state[i].input_dentry.dentry =
+			debugfs_create_file(
+				"input", KFUZZTEST_INPUT_PERMS,
+				state.debugfs_state[i].target_dir, NULL,
+				&state.debugfs_state[i].input_dentry.fops);
+		if (!state.debugfs_state[i].input_dentry.dentry) {
+			ret = -ENOMEM;
+			goto cleanup_failure;
+		} else if (IS_ERR(state.debugfs_state[i].input_dentry.dentry)) {
+			ret = PTR_ERR(
+				state.debugfs_state[i].input_dentry.dentry);
+			goto cleanup_failure;
+		}
+
+		pr_info("KFuzzTest: registered target %s", targ->name);
+	}
+
+	return 0;
+
+cleanup_failure:
+	debugfs_remove_recursive(state.kfuzztest_dir);
+	return ret;
+}
+
+static void __exit kfuzztest_exit(void)
+{
+	pr_info("KFuzzTest: exiting");
+	if (!state.kfuzztest_dir)
+		return;
+
+	debugfs_remove_recursive(state.kfuzztest_dir);
+	state.kfuzztest_dir = NULL;
+
+	if (state.debugfs_state) {
+		kfree(state.debugfs_state);
+		state.debugfs_state = NULL;
+	}
+}
+
+module_init(kfuzztest_init);
+module_exit(kfuzztest_exit);
diff --git a/lib/kfuzztest/parse.c b/lib/kfuzztest/parse.c
new file mode 100644
index 000000000000..6010171190ad
--- /dev/null
+++ b/lib/kfuzztest/parse.c
@@ -0,0 +1,208 @@
+/* SPDX-License-Identifier: GPL-2.0 */
+/*
+ * KFuzzTest input parsing and validation.
+ *
+ * Copyright 2025 Google LLC
+ */
+#include <linux/kfuzztest.h>
+#include <linux/kasan.h>
+
+/*
+ * Enforce a fixed struct size to ensure a consistent stride when iterating over
+ * the array of these structs in the dedicated ELF section.
+ */
+static_assert(sizeof(struct kfuzztest_target) == 32, "struct kfuzztest_target should have size 32");
+static_assert(sizeof(struct kfuzztest_constraint) == 64, "struct kfuzztest_constraint should have size 64");
+static_assert(sizeof(struct kfuzztest_annotation) == 32, "struct kfuzztest_annotation should have size 32");
+
+static int kfuzztest_relocate_v0(struct reloc_region_array *regions, struct reloc_table *rt, void *payload_start,
+				 void *payload_end)
+{
+	struct reloc_region reg, src, dst;
+	void *poison_start, *poison_end;
+	uintptr_t *ptr_location;
+	struct reloc_entry re;
+	size_t i;
+
+	/* Patch pointers. */
+	for (i = 0; i < rt->num_entries; i++) {
+		re = rt->entries[i];
+		src = regions->regions[re.region_id];
+		ptr_location = (uintptr_t *)((char *)payload_start + src.offset + re.region_offset);
+		if (re.value == KFUZZTEST_REGIONID_NULL)
+			*ptr_location = (uintptr_t)NULL;
+		else if (re.value < regions->num_regions) {
+			dst = regions->regions[re.value];
+			*ptr_location = (uintptr_t)((char *)payload_start + dst.offset);
+		} else
+			return -EINVAL;
+	}
+
+	/* Poison the padding between regions. */
+	for (i = 0; i < regions->num_regions; i++) {
+		reg = regions->regions[i];
+
+		/* Points to the beginning of the inter-region padding */
+		poison_start = payload_start + reg.offset + reg.size;
+		if (i < regions->num_regions - 1)
+			poison_end = payload_start + regions->regions[i + 1].offset;
+		else
+			poison_end = payload_end;
+
+		if ((char *)poison_end > (char *)payload_end)
+			return -EINVAL;
+
+		kasan_poison_range(poison_start, poison_end - poison_start);
+	}
+
+	/* Poison the padded area preceding the payload. */
+	kasan_poison_range((char *)payload_start - rt->padding_size, rt->padding_size);
+	return 0;
+}
+
+static bool kfuzztest_input_is_valid(struct reloc_region_array *regions, struct reloc_table *rt, void *payload_start,
+				     void *payload_end)
+{
+	size_t payload_size = (char *)payload_end - (char *)payload_start;
+	struct reloc_region reg, next_reg;
+	size_t usable_payload_size;
+	uint32_t region_end_offset;
+	struct reloc_entry reloc;
+	uint32_t i;
+
+	if ((char *)payload_start > (char *)payload_end)
+		return false;
+	if (payload_size < KFUZZTEST_POISON_SIZE)
+		return false;
+	usable_payload_size = payload_size - KFUZZTEST_POISON_SIZE;
+
+	for (i = 0; i < regions->num_regions; i++) {
+		reg = regions->regions[i];
+		if (check_add_overflow(reg.offset, reg.size, &region_end_offset))
+			return false;
+		if ((size_t)region_end_offset > usable_payload_size)
+			return false;
+
+		if (i < regions->num_regions - 1) {
+			next_reg = regions->regions[i + 1];
+			if (reg.offset > next_reg.offset)
+				return false;
+			/*
+			 * Enforce the minimum poisonable gap between
+			 * consecutive regions.
+			 */
+			if (reg.offset + reg.size + KFUZZTEST_POISON_SIZE > next_reg.offset)
+				return false;
+		}
+	}
+
+	if (rt->padding_size < KFUZZTEST_POISON_SIZE) {
+		pr_info("validation failed because rt->padding_size = %u", rt->padding_size);
+		return false;
+	}
+
+	for (i = 0; i < rt->num_entries; i++) {
+		reloc = rt->entries[i];
+		if (reloc.region_id >= regions->num_regions)
+			return false;
+		if (reloc.value != KFUZZTEST_REGIONID_NULL && reloc.value >= regions->num_regions)
+			return false;
+
+		reg = regions->regions[reloc.region_id];
+		if (reloc.region_offset % (sizeof(uintptr_t)) || reloc.region_offset + sizeof(uintptr_t) > reg.size)
+			return false;
+	}
+
+	return true;
+}
+
+static int kfuzztest_parse_input_v0(void *input, size_t input_size, struct reloc_region_array **ret_regions,
+				    struct reloc_table **ret_reloc_table, void **ret_payload_start,
+				    void **ret_payload_end)
+{
+	size_t reloc_entries_size, reloc_regions_size;
+	size_t reloc_table_size, regions_size;
+	struct reloc_region_array *regions;
+	void *payload_end, *payload_start;
+	struct reloc_table *rt;
+	size_t curr_offset = 0;
+
+	if (input_size < sizeof(struct reloc_region_array) + sizeof(struct reloc_table))
+		return -EINVAL;
+
+	regions = input;
+	if (check_mul_overflow(regions->num_regions, sizeof(struct reloc_region), &reloc_regions_size))
+		return -EINVAL;
+	if (check_add_overflow(sizeof(*regions), reloc_regions_size, &regions_size))
+		return -EINVAL;
+
+	curr_offset = regions_size;
+	if (curr_offset > input_size)
+		return -EINVAL;
+	if (input_size - curr_offset < sizeof(struct reloc_table))
+		return -EINVAL;
+
+	rt = (struct reloc_table *)((char *)input + curr_offset);
+
+	if (check_mul_overflow((size_t)rt->num_entries, sizeof(struct reloc_entry), &reloc_entries_size))
+		return -EINVAL;
+	if (check_add_overflow(sizeof(*rt), reloc_entries_size, &reloc_table_size))
+		return -EINVAL;
+	if (check_add_overflow(reloc_table_size, rt->padding_size, &reloc_table_size))
+		return -EINVAL;
+
+	if (check_add_overflow(curr_offset, reloc_table_size, &curr_offset))
+		return -EINVAL;
+	if (curr_offset > input_size)
+		return -EINVAL;
+
+	payload_start = (char *)input + curr_offset;
+	payload_end = (char *)input + input_size;
+
+	if (!kfuzztest_input_is_valid(regions, rt, payload_start, payload_end))
+		return -EINVAL;
+
+	*ret_regions = regions;
+	*ret_reloc_table = rt;
+	*ret_payload_start = payload_start;
+	*ret_payload_end = payload_end;
+	return 0;
+}
+
+static int kfuzztest_parse_and_relocate_v0(void *input, size_t input_size, void **arg_ret)
+{
+	struct reloc_region_array *regions;
+	void *payload_start, *payload_end;
+	struct reloc_table *reloc_table;
+	int ret;
+
+	ret = kfuzztest_parse_input_v0(input, input_size, &regions, &reloc_table, &payload_start, &payload_end);
+	if (ret < 0)
+		return ret;
+
+	ret = kfuzztest_relocate_v0(regions, reloc_table, payload_start, payload_end);
+	if (ret < 0)
+		return ret;
+	*arg_ret = payload_start;
+	return 0;
+}
+
+int kfuzztest_parse_and_relocate(void *input, size_t input_size, void **arg_ret)
+{
+	u32 version, magic;
+
+	if (input_size < sizeof(u32) + sizeof(u32))
+		return -EINVAL;
+
+	magic = *(u32 *)input;
+	if (magic != KFUZZTEST_HEADER_MAGIC)
+		return -EINVAL;
+
+	version = *(u32 *)((char *)input + sizeof(u32));
+	switch (version) {
+	case KFUZZTEST_V0:
+		return kfuzztest_parse_and_relocate_v0(input + sizeof(u64), input_size - sizeof(u64), arg_ret);
+	}
+
+	return -EINVAL;
+}
-- 
2.51.0.rc0.205.g4a044479a3-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250813133812.926145-4-ethan.w.s.graham%40gmail.com.
