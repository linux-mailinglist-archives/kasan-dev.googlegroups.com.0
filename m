Return-Path: <kasan-dev+bncBDP53XW3ZQCBB7NNY3EQMGQE3KRKV5A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53e.google.com (mail-ed1-x53e.google.com [IPv6:2a00:1450:4864:20::53e])
	by mail.lfdr.de (Postfix) with ESMTPS id A4374CA3F5B
	for <lists+kasan-dev@lfdr.de>; Thu, 04 Dec 2025 15:13:18 +0100 (CET)
Received: by mail-ed1-x53e.google.com with SMTP id 4fb4d7f45d1cf-6460725c6a9sf1090414a12.3
        for <lists+kasan-dev@lfdr.de>; Thu, 04 Dec 2025 06:13:18 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1764857598; cv=pass;
        d=google.com; s=arc-20240605;
        b=aQa5mC1MbhDkSS7rKVigNAPKSL1gtEU0/2sqirdbEH2VtmTUqjh5qjEi4xQrD2DtNw
         KzrXADvu2OQKgLCXvEYq0yxUyyFN6NLKNNUskowq6hvqqMuQTTG/rkk57zchnBjvk2Vd
         ZRvYReqy22O1nX2UTNV9iDPGHMWHdNYsRDcdkITTQownyy0VMZoHqpWu3ZDiGY2Ez9Cj
         UBL5YQLMr/I+HRNXhjofdPj0xEfw8R4C1TCDP8J0N9m/2ndrCL+rpP4JWCFvg30eRy0j
         DRtxNT/qZg/HaYYztezNiCUlZw7A8/wfp4rWAfFCnAThU0bXdkmtjuqngaKllOQBYiOn
         owUQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=FoT7rWpvD73SnUiJ97hpZIZgTZ6jj/MhFgGlW2LmUTI=;
        fh=S/54VOPVL222Wq3F8SPjJEjl2iU8qMz4Rn2A4GV4AIY=;
        b=it7/GGBz+HcnSsqeKhX04r1jNKkmVvsmaSIeiGTywWvzZDzKb6pEkp4EWPNJvKYkfQ
         PQF/osXgRmZKIL6XivvtRrtedx6HplS4WkUoaB0l7CHnxyQpvRYm3AnIebjqPlwSWxjm
         F1X7nG192bKQUFNVhQ7sgzjtVPRPk0imKcIuZ6LD3tT9/sUp2rYv+p/t0Y/vU/BsiEcT
         1tH145M/zCevN4u++zUFx0nUae9r/j8X668uveojKIE6Qj4+iLaheY/4gIZD9inxSRBR
         7iPFsqkCp1WK9cmdq+M3NccSUflKLBW9mIosROFnLZIuJaXrNdaAOH+A2vezitN8zo2G
         u3hg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=d+Lv2InM;
       spf=pass (google.com: domain of ethan.w.s.graham@gmail.com designates 2a00:1450:4864:20::42e as permitted sender) smtp.mailfrom=ethan.w.s.graham@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1764857598; x=1765462398; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=FoT7rWpvD73SnUiJ97hpZIZgTZ6jj/MhFgGlW2LmUTI=;
        b=J+jToF6GQYNusTl1hETnobb2Yo2OfLgVFjTgy4tYRrf3YqASH3RTYEEQ7P35UwDVlD
         QDq3UXv6VqTgRBJWVZ6KaSPPhNMy8HJ2sQ9ABjODj2GYETxMBzUqyDvBf/mQWT09LOG+
         KOunkvwXQhUCb+YYjLrQAhkFW+e8cC3Rk7gst830ukwecMbJHKTYZxjOI2/TBt6ut7pS
         u0f9iuk+D4ZOyP5XmS22I85AspCZV7dvlIX6QwzhOEBpCDndEAH7BSItOC3E8LMp9Whs
         Hss+7Yh2YauvweRUCMV6UaAT5plGYWDV6zyftZ9AN0IGF6bkoGjuJiwjSO5cspIGPrbZ
         CSjw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1764857598; x=1765462398; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=FoT7rWpvD73SnUiJ97hpZIZgTZ6jj/MhFgGlW2LmUTI=;
        b=SL0MnKsGfGzwwVjtS6Ov9VLpML6idYOEnoBdgEWd/ixLnT3NaOJlUxEL6oE6We94FX
         LbguNIaoQ7U9yKg9jitN8KuFyWYO528ZKrPh6YU7mHJ1nwVNqeJUM6tEN4AcIXDCVFkj
         l7Y63HG4MIoIRvRF2CrW42j9lSuBfyJ3bNYPZT+VKe4k2fIQo+9hKiWipVOIxHKJLQoB
         QsAO6htDG/sMZsEPanEgeoxQpP1hvpl61iYrIQyWpehmZ+pTO/BIFMbpya33epAJAPV1
         kp/IrzQ2vCuXNhGyTtq1SLIP77e8c02L5XdNfeU3DQBxwSPXNRAs8nsm2b6xw2zAFbbO
         qnLA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1764857598; x=1765462398;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:x-gm-gg
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=FoT7rWpvD73SnUiJ97hpZIZgTZ6jj/MhFgGlW2LmUTI=;
        b=jVkD2/i5SGar73EyokQMrtWVeVy3BpEHVRqt6QnjyCFG6bGv1y7dVtoT7HJAwHA0sb
         gXmuTRCPF58smKEMPKR8bKYUKLKvFm+RC7tSs+E5LKXfaxhJWFe5ndM7nJFe4L0FRbkX
         +DWThwViwWHH/7SBFfAJ5iQsilwTZsYS6HqrCsQF4V1PSkxfu2jwQpbs/3dHFjWZyNCy
         gPup36OIUwIDcApudQWc256uKWX+dKxEngFREmWlLS5klJwbz0xrBrMtp7PuHQwyCWwC
         jBAysgv3W6oW2NSzSy9PhyhRCu6ELnoI3UW7b07we/BlXD6f+dhrJkx1qlVBnVnz1mhp
         +dYw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVIs6rqCsBmdRRJSXXPq0uA6r9AVwTCQWSRob1sC9UhuwgaWMO35XfUNNmlZT9ot84o/qQdXw==@lfdr.de
X-Gm-Message-State: AOJu0YyyKG4kRmJMYa6RaUq65twH4sXEIWngKN1jAiZEeTc7rj/Bo6K+
	UlvQGNthoKL6vpcqDWgq2zclVq1KGdSJI5ztNhcMgIXWTa5C7PbmuvVC
X-Google-Smtp-Source: AGHT+IFdYr978tupgcp7VPsnT799jCIhVCgrJdl+P6bhN+q8DdMBd08BBlyCNm2wMcNm8MZpf4bNog==
X-Received: by 2002:a05:6402:2813:b0:640:b1cf:f800 with SMTP id 4fb4d7f45d1cf-6479c3d6e21mr5525314a12.4.1764857597937;
        Thu, 04 Dec 2025 06:13:17 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+ap0w6ScMHHnwSLLMuWuxOa/VcvPTzxds1XAWgv1dNJDA=="
Received: by 2002:a05:6402:50ca:b0:641:833d:f422 with SMTP id
 4fb4d7f45d1cf-647ad5a9e79ls1075075a12.1.-pod-prod-01-eu; Thu, 04 Dec 2025
 06:13:15 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVEc0f3E7nUvPAQ3YCCYbdcBXH2uNmaMTFerPOBZWQuUhGmYWDZblLX7NU48t//GUv6jq0uhH0uX+Q=@googlegroups.com
X-Received: by 2002:a17:907:7f14:b0:b73:70db:4994 with SMTP id a640c23a62f3a-b79dc51ae9amr621087366b.34.1764857595196;
        Thu, 04 Dec 2025 06:13:15 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1764857595; cv=none;
        d=google.com; s=arc-20240605;
        b=jkI3yXnJVfl4N8POKmz/UZKjc/VmAdMO3+KXkTP6ABh0IfrDjOKHy1fayoYuiqQe2N
         SaulFBKqjciD5EbLOG0+0y3RP+Z9D0as7tppnQtG86B1fz0tMfSVMEXKT0HTSDcogxOM
         lJgdVz+fIVv8ok5qMs3Zt4ZRMmwjwJLBmjWkySf80zgJvUnOrBvW5MwTlkSOOrFjZ7Hu
         EYYmvp5rMDDY9FrVOyVXkLfnWhmObiW+1jkRG+UOmMFLhSDimjK3k8dk4p1zRKCIh8tS
         uPBN5SVPZ/BSx0H1x7zImqc/k2H1ID41EvPgrrwTHindIjbNrQlLBhrrAgc//q0CThxU
         VyXg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=JYb/yPra/VQ92UPtHr69bchv45pj9r5YmHZ7p3XU5gk=;
        fh=QIaMD3yYT3A8zDIEfwfek/cayJymsnw6rIF3/+uTrdU=;
        b=ZtUvm5JGgVcskJhnncOFXIxRFtLputWcidS47QbVAaHwab7+vVBNbMvFGHFiMAiNdE
         grwSJZabC0x1MYGhGJWVBlfANh4HIhaS3vp4SfM/3cUEF0UMICv/XKzP/VeaBLEePy7U
         9SV14NufTXPwv6UtLmL7OXlo0nbsH+WIV43S1Ey/QyH9BeJwoDowMAqBUMfbhgwOUUcv
         z9PYOBp66dPVgdmgPBLkz82ayhe8z05hEuwehIKr1PScuJ7VLHvhxqkVhPNZ61OmV827
         kp/YXs7QhMlFhF0R2pRlwJc3UlE19G0gQCt3DgMW6/Q/f0nMGw974/vVY5UeWREXMYdI
         TbOw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=d+Lv2InM;
       spf=pass (google.com: domain of ethan.w.s.graham@gmail.com designates 2a00:1450:4864:20::42e as permitted sender) smtp.mailfrom=ethan.w.s.graham@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x42e.google.com (mail-wr1-x42e.google.com. [2a00:1450:4864:20::42e])
        by gmr-mx.google.com with ESMTPS id 4fb4d7f45d1cf-647b338c672si25206a12.9.2025.12.04.06.13.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 04 Dec 2025 06:13:15 -0800 (PST)
Received-SPF: pass (google.com: domain of ethan.w.s.graham@gmail.com designates 2a00:1450:4864:20::42e as permitted sender) client-ip=2a00:1450:4864:20::42e;
Received: by mail-wr1-x42e.google.com with SMTP id ffacd0b85a97d-42e2b90ad22so457407f8f.2
        for <kasan-dev@googlegroups.com>; Thu, 04 Dec 2025 06:13:15 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCVaLqX41XxonzfhqU5hT8l2+IYMa8MsQRJ3VIdVEKwt6TX+8PrWfCskXKCXs00EiAxnLMB/AT5PyCc=@googlegroups.com
X-Gm-Gg: ASbGnct5Wm5yebwBrTksn06HdcFmHDGjJO9G7KVO2+Qt2HOwK61maUcS8reLJh8zVr3
	eWAfMScQ31mQpA7IKG2QnUcOjh/owAD4LCvnvJ0430POB+u0om2yhc7ortVNP6dw5oemHh7qcig
	Th9HvBxkkblEAuo5kjrfHnyBb2EwoHaTsrgbYTc5AkATw00kvNATZpwzMIpK5yAe3Nq27Hp6PMG
	h3AUxeKfeXVxp6LzSB3ZAhPN3CWKHwVPgb8VbIj6b8k6YOmf2IqSLxQTOuwMQgB7wCYaP5NaAIy
	yYzG4e9fuF+xfBwrC5qqrKWe1ml2huxJs2ni1KqQKj6Qr7GbPXxg4HUKdacmoYF27kL/Skoetv2
	DC8v13E5NE7Sjm1YGbaAydWMxT5xgepkGqJz94AljvgoCjrRwMVwv5mUXk1QuCvImsRQ7wPXl9c
	uh104HNfVsvlCi3a0Ip+w0wLdkGEFuijjLcFDuZUEez0RysqXJ9oZHu3dXw3sWiwKREO4dOXuT+
	zPx
X-Received: by 2002:a05:6000:290e:b0:42b:411b:e487 with SMTP id ffacd0b85a97d-42f73174091mr6010345f8f.2.1764857594380;
        Thu, 04 Dec 2025 06:13:14 -0800 (PST)
Received: from ethan-tp.d.ethz.ch (2001-67c-10ec-5744-8000--626.net6.ethz.ch. [2001:67c:10ec:5744:8000::626])
        by smtp.gmail.com with ESMTPSA id ffacd0b85a97d-42f7cbfeae9sm3605808f8f.13.2025.12.04.06.13.13
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 04 Dec 2025 06:13:13 -0800 (PST)
From: Ethan Graham <ethan.w.s.graham@gmail.com>
To: ethan.w.s.graham@gmail.com,
	glider@google.com
Cc: andreyknvl@gmail.com,
	andy@kernel.org,
	andy.shevchenko@gmail.com,
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
	tarasmadan@google.com,
	Ethan Graham <ethangraham@google.com>
Subject: [PATCH 07/10] kfuzztest: add KFuzzTest sample fuzz targets
Date: Thu,  4 Dec 2025 15:12:46 +0100
Message-ID: <20251204141250.21114-8-ethan.w.s.graham@gmail.com>
X-Mailer: git-send-email 2.51.0
In-Reply-To: <20251204141250.21114-1-ethan.w.s.graham@gmail.com>
References: <20251204141250.21114-1-ethan.w.s.graham@gmail.com>
MIME-Version: 1.0
X-Original-Sender: ethan.w.s.graham@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=d+Lv2InM;       spf=pass
 (google.com: domain of ethan.w.s.graham@gmail.com designates
 2a00:1450:4864:20::42e as permitted sender) smtp.mailfrom=ethan.w.s.graham@gmail.com;
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

Add two simple fuzz target samples to demonstrate the KFuzzTest API and
provide basic self-tests for the framework.

These examples showcase how a developer can define a fuzz target using
the FUZZ_TEST(), constraint, and annotation macros, and serve as runtime
sanity checks for the core logic. For example, they test that
out-of-bounds memory accesses into poisoned padding regions are
correctly detected in a KASAN build.

These have been tested by writing syzkaller-generated inputs into their
debugfs 'input' files and verifying that the correct KASAN reports were
triggered.

Signed-off-by: Ethan Graham <ethangraham@google.com>
Signed-off-by: Ethan Graham <ethan.w.s.graham@gmail.com>
Acked-by: Alexander Potapenko <glider@google.com>

---
PR v3:
- Use the FUZZ_TEST_SIMPLE macro in the `underflow_on_buffer` sample
  fuzz target instead of FUZZ_TEST.
PR v2:
- Fix build issues pointed out by the kernel test robot <lkp@intel.com>.
---
---
 samples/Kconfig                               |  7 ++
 samples/Makefile                              |  1 +
 samples/kfuzztest/Makefile                    |  3 +
 samples/kfuzztest/overflow_on_nested_buffer.c | 71 +++++++++++++++++++
 samples/kfuzztest/underflow_on_buffer.c       | 51 +++++++++++++
 5 files changed, 133 insertions(+)
 create mode 100644 samples/kfuzztest/Makefile
 create mode 100644 samples/kfuzztest/overflow_on_nested_buffer.c
 create mode 100644 samples/kfuzztest/underflow_on_buffer.c

diff --git a/samples/Kconfig b/samples/Kconfig
index 6e072a5f1ed8..5209dd9d7a5c 100644
--- a/samples/Kconfig
+++ b/samples/Kconfig
@@ -320,6 +320,13 @@ config SAMPLE_HUNG_TASK
 	  Reading these files with multiple processes triggers hung task
 	  detection by holding locks for a long time (256 seconds).
 
+config SAMPLE_KFUZZTEST
+	bool "Build KFuzzTest sample targets"
+	depends on KFUZZTEST
+	help
+	  Build KFuzzTest sample targets that serve as selftests for input
+	  deserialization and inter-region redzone poisoning logic.
+
 source "samples/rust/Kconfig"
 
 source "samples/damon/Kconfig"
diff --git a/samples/Makefile b/samples/Makefile
index 07641e177bd8..3a0e7f744f44 100644
--- a/samples/Makefile
+++ b/samples/Makefile
@@ -44,4 +44,5 @@ obj-$(CONFIG_SAMPLE_DAMON_WSSE)		+= damon/
 obj-$(CONFIG_SAMPLE_DAMON_PRCL)		+= damon/
 obj-$(CONFIG_SAMPLE_DAMON_MTIER)	+= damon/
 obj-$(CONFIG_SAMPLE_HUNG_TASK)		+= hung_task/
+obj-$(CONFIG_SAMPLE_KFUZZTEST)		+= kfuzztest/
 obj-$(CONFIG_SAMPLE_TSM_MR)		+= tsm-mr/
diff --git a/samples/kfuzztest/Makefile b/samples/kfuzztest/Makefile
new file mode 100644
index 000000000000..4f8709876c9e
--- /dev/null
+++ b/samples/kfuzztest/Makefile
@@ -0,0 +1,3 @@
+# SPDX-License-Identifier: GPL-2.0-only
+
+obj-$(CONFIG_SAMPLE_KFUZZTEST) += overflow_on_nested_buffer.o underflow_on_buffer.o
diff --git a/samples/kfuzztest/overflow_on_nested_buffer.c b/samples/kfuzztest/overflow_on_nested_buffer.c
new file mode 100644
index 000000000000..2f1c3ff9f750
--- /dev/null
+++ b/samples/kfuzztest/overflow_on_nested_buffer.c
@@ -0,0 +1,71 @@
+// SPDX-License-Identifier: GPL-2.0
+/*
+ * This file contains a KFuzzTest example target that ensures that a buffer
+ * overflow on a nested region triggers a KASAN OOB access report.
+ *
+ * Copyright 2025 Google LLC
+ */
+
+/**
+ * DOC: test_overflow_on_nested_buffer
+ *
+ * This test uses a struct with two distinct dynamically allocated buffers.
+ * It checks that KFuzzTest's memory layout correctly poisons the memory
+ * regions and that KASAN can detect an overflow when reading one byte past the
+ * end of the first buffer (`a`).
+ *
+ * It can be invoked with kfuzztest-bridge using the following command:
+ *
+ * ./kfuzztest-bridge \
+ *   "nested_buffers { ptr[a] len[a, u64] ptr[b] len[b, u64] }; \
+ *   a { arr[u8, 64] }; b { arr[u8, 64] };" \
+ *   "test_overflow_on_nested_buffer" /dev/urandom
+ *
+ * The first argument describes the C struct `nested_buffers` and specifies that
+ * both `a` and `b` are pointers to arrays of 64 bytes.
+ */
+#include <linux/kfuzztest.h>
+
+static void overflow_on_nested_buffer(const char *a, size_t a_len, const char *b, size_t b_len)
+{
+	size_t i;
+	pr_info("a = [%px, %px)", a, a + a_len);
+	pr_info("b = [%px, %px)", b, b + b_len);
+
+	/* Ensure that all bytes in arg->b are accessible. */
+	for (i = 0; i < b_len; i++)
+		READ_ONCE(b[i]);
+	/*
+	 * Check that all bytes in arg->a are accessible, and provoke an OOB on
+	 * the first byte to the right of the buffer which will trigger a KASAN
+	 * report.
+	 */
+	for (i = 0; i <= a_len; i++)
+		READ_ONCE(a[i]);
+}
+
+struct nested_buffers {
+	const char *a;
+	size_t a_len;
+	const char *b;
+	size_t b_len;
+};
+
+/**
+ * The KFuzzTest input format specifies that struct nested buffers should
+ * be expanded as:
+ *
+ * | a | b | pad[8] | *a | pad[8] | *b |
+ *
+ * where the padded regions are poisoned. We expect to trigger a KASAN report by
+ * overflowing one byte into the `a` buffer.
+ */
+FUZZ_TEST(test_overflow_on_nested_buffer, struct nested_buffers)
+{
+	KFUZZTEST_EXPECT_NOT_NULL(nested_buffers, a);
+	KFUZZTEST_EXPECT_NOT_NULL(nested_buffers, b);
+	KFUZZTEST_ANNOTATE_LEN(nested_buffers, a_len, a);
+	KFUZZTEST_ANNOTATE_LEN(nested_buffers, b_len, b);
+
+	overflow_on_nested_buffer(arg->a, arg->a_len, arg->b, arg->b_len);
+}
diff --git a/samples/kfuzztest/underflow_on_buffer.c b/samples/kfuzztest/underflow_on_buffer.c
new file mode 100644
index 000000000000..b2f5ff467334
--- /dev/null
+++ b/samples/kfuzztest/underflow_on_buffer.c
@@ -0,0 +1,51 @@
+// SPDX-License-Identifier: GPL-2.0
+/*
+ * This file contains a KFuzzTest example target that ensures that a buffer
+ * underflow on a region triggers a KASAN OOB access report.
+ *
+ * Copyright 2025 Google LLC
+ */
+
+/**
+ * DOC: test_underflow_on_buffer
+ *
+ * This test ensures that the region between the metadata struct and the
+ * dynamically allocated buffer is poisoned. It provokes a one-byte underflow
+ * on the buffer, which should be caught by KASAN.
+ *
+ * It can be invoked with kfuzztest-bridge using the following command:
+ *
+ * ./kfuzztest-bridge \
+ *   "some_buffer { ptr[buf] len[buf, u64]}; buf { arr[u8, 128] };" \
+ *   "test_underflow_on_buffer" /dev/urandom
+ *
+ * The first argument describes the C struct `some_buffer` and specifies that
+ * `buf` is a pointer to an array of 128 bytes. The second argument is the test
+ * name, and the third is a seed file.
+ */
+#include <linux/kfuzztest.h>
+
+static void underflow_on_buffer(char *buf, size_t buflen)
+{
+	size_t i;
+
+	pr_info("buf = [%px, %px)", buf, buf + buflen);
+
+	/* First ensure that all bytes in arg->b are accessible. */
+	for (i = 0; i < buflen; i++)
+		READ_ONCE(buf[i]);
+	/*
+	 * Provoke a buffer overflow on the first byte preceding b, triggering
+	 * a KASAN report.
+	 */
+	READ_ONCE(*((char *)buf - 1));
+}
+
+/**
+ * Tests that the region between struct some_buffer and the expanded *buf field
+ * is correctly poisoned by accessing the first byte before *buf.
+ */
+FUZZ_TEST_SIMPLE(test_underflow_on_buffer)
+{
+	underflow_on_buffer(data, datalen);
+}
-- 
2.51.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251204141250.21114-8-ethan.w.s.graham%40gmail.com.
