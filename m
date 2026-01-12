Return-Path: <kasan-dev+bncBDP53XW3ZQCBB4MWSXFQMGQEDXYG62I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33a.google.com (mail-wm1-x33a.google.com [IPv6:2a00:1450:4864:20::33a])
	by mail.lfdr.de (Postfix) with ESMTPS id 9F5A6D15013
	for <lists+kasan-dev@lfdr.de>; Mon, 12 Jan 2026 20:28:50 +0100 (CET)
Received: by mail-wm1-x33a.google.com with SMTP id 5b1f17b1804b1-4775f51ce36sf62725745e9.1
        for <lists+kasan-dev@lfdr.de>; Mon, 12 Jan 2026 11:28:50 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768246130; cv=pass;
        d=google.com; s=arc-20240605;
        b=BJj9sQjVbdHLDicme+biGdEXcQA3WND1QtKKPAsZmhvCGx0g37GKCuX4QN29e8Pjhb
         csAunvf4yzAIsfmYPM3xTJIsSoE9YFKq2xI31t+8D0KToi0IvelySdMX1TfzjpWzxoSV
         fMbZFrXmFOx28ivsdNkQ2OkdC2k9Qu4W0Bxr5Xr6yAjj556OIwzyCnQBwyvGIVvbGI+9
         E+C2MDO4xZua/1hCcVlYsQUgVAaKjD3pW28otSk5x3B240Z+wjrsYEPF3HxtikJY0QZP
         cKiMAEXLMxg0DZ+iRrWD9tqtUYxbVRcmpYv8PD30PG8fI9fzTFIhdBk/kNSSq3tt5UFa
         YLeA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=bYfqGEkzdRSSaElXZ4qHYS1Yl9Ysm79erEP+aG3ePVk=;
        fh=LFjiomwqAOIf9Cols6WOWvtdq6t4kMJcbSiUmAzjtEM=;
        b=B7hGDCwUyd9ze6NepxGSfWu9gDYq80XGrFxNAex+Yl/5euyP1RyIGmYKAHXb6qlSS9
         J0k3zql/nJgC1IpPf/eT44A8SPGIOH/BUjyiGO3jwYSYpsy+yNELO3cC78GvBGiHBbhG
         d1acdW7K2gNeu/k/7LHUgEfIouD+l9l8mLQ8idquCwi0YTpduPCD8vaRDUYJ+rRdpoU/
         aIX/S3q0NJFlJjdvTXSvzYBVf2t9MYY/DJ5ABTapm+z8OoMCAT3Qxlof8b8ZdHO+G39S
         otv8uknPLsO+AtjVulG7uFffhfajCP310Irzd7tVEuce8YRGtHqdvfksPl/2HUvdWp1m
         k37A==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=LAEKtQ4N;
       spf=pass (google.com: domain of ethan.w.s.graham@gmail.com designates 2a00:1450:4864:20::62d as permitted sender) smtp.mailfrom=ethan.w.s.graham@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768246130; x=1768850930; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=bYfqGEkzdRSSaElXZ4qHYS1Yl9Ysm79erEP+aG3ePVk=;
        b=qjmWwsvABHrzgGUERcPBD5baFMOcDb5UXbi84BPsK8iN6rJvIabIqxdhTvauUYe0Bk
         ZilhYNNtecN8qUOTBU6iVhQ+uuxTwTp+19ZHUNzcKKRMbiLFBulxQSp1q7G4FQrKuFY8
         KFW7v+dr2MXWMA+79AoDT4QSNgs9Auj+Jz+NGSZ8Rx4zsU/WQrq3cvJtWrXADFpphgzl
         pXgFSdYugHLrpdDzCxG5KmRoQfmx9p0EHlxpUClZxKSHVvpKmlYA05Y3VR1CGK5ZvRHP
         0nWy5H7OZa+wzTXZf+lBjdFdpXj+i7e4lzOckz7KS0mlbe9O83kc6z71BcysnLcZTLAv
         SdYQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1768246130; x=1768850930; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=bYfqGEkzdRSSaElXZ4qHYS1Yl9Ysm79erEP+aG3ePVk=;
        b=PSZlPlSrkE7t9laYc22klej52vspDt30UP9ga1gvJ2CJqROUADlAhjbLJMqaCgdGF4
         T+ZcsFQkdbLrArLBKdqr0LwRIxRsI1z+qSYFNIUNPcwD3nMtCFk73IQTjVwxXXCPhBuB
         eL5lMZ5wfzqDn24Uw36vqvrYDvhSyQTvpHvgI6pJ7nJFsZiVrDvKI+qyW5DcaZDmJhqT
         9wIBHTBD3iXtbr28l2sGxr0epX81ZsbtjwklAYZP8LWzz7eLSgwtrjKJ+qNba+//3Gd9
         7UF49Fdnbx5Y41t8YmlRa0PehOUNf87MS65SyPLVj0RPxISnG5jTZvGDsE0FF2x77O/p
         9LXg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768246130; x=1768850930;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:x-gm-gg
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=bYfqGEkzdRSSaElXZ4qHYS1Yl9Ysm79erEP+aG3ePVk=;
        b=lkfZIC4LJSCNf8RaVdO3hsdusZ9RjY4jjsm/glLMrKTupXx1/CnERMlCqNRDVfEY22
         8jt8jnInHX0UcEriwGdQxU3eSHrTh1wcTv9lVBT1yMBUhKlYiwrjESfBYEdf4jtYrUQU
         7amBxYhpEgEs00JO/w5ZYxbrEmM+9TKBGugmSjoqk6fEPtxuTZxl8WWYFX8QSixUuITi
         b/C5Aj63X5hnjr1rgZkft3zRas9z+i19Ert2hGaeayNmnFKn/wMRAjnXcOp2rLeacA9a
         KuuFt8fKogOOmM4Yc8BRROGGtJBJyE501rs2bH7SVgCCouvkV9pbdGc/MuvADC9s1bEY
         zcJQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXozmHmW9zo4gfPla78RPcSN0j00nM5CYVtcNJKhy3iL8n/OM30zuB6Dcu7iqB0nBDgBefLBA==@lfdr.de
X-Gm-Message-State: AOJu0YxIb1TVqnCuscG5HrcGBw9ykAqv3cMXKfhVKOXL+m0nkN9LdAOY
	BjR/X64uEbSw85n1xqU5MZFmgUb2Cn17Xh+Fvg2nkUqxazEWLafrjZaT
X-Google-Smtp-Source: AGHT+IHooKZKLL+lk/n+cv3mF2AFU30jAPs/JoS7uMw5ow+wMiDgHqOfpoIxwTFFxzf3jMSsbmPE2A==
X-Received: by 2002:a05:600c:3556:b0:477:7b72:bf9a with SMTP id 5b1f17b1804b1-47d84b3b8c4mr224487775e9.28.1768246129816;
        Mon, 12 Jan 2026 11:28:49 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+GVDZvq+/lSpMHB2TNTV5JnaSoU/tMQ7pBpgMT+pkPX1g=="
Received: by 2002:a05:600c:35cf:b0:47a:74d9:ab with SMTP id
 5b1f17b1804b1-47d7ec1551fls4758445e9.2.-pod-prod-05-eu; Mon, 12 Jan 2026
 11:28:47 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXUx3RV3zzrnHfZ/1ANQqO4Uoqr1vso4Scyyu42EJ4Os3D701ZzW0su2qq/L3xh9W8zmkMnFIhfZaU=@googlegroups.com
X-Received: by 2002:a05:600c:500d:b0:477:9d54:58d7 with SMTP id 5b1f17b1804b1-47d84b3b881mr173325225e9.29.1768246127167;
        Mon, 12 Jan 2026 11:28:47 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1768246127; cv=none;
        d=google.com; s=arc-20240605;
        b=l3GR38d7SQFufRnwiNc+ACWShZbLl8GZZcjw8kklOlaFh3/PxnQ9uiPIVQX3cq5rXM
         rGEvrRYb1hof9aKowx9xEymDBrZRgAFPXBdqWmKCFIQjo74sxpOmjbC5GrfghQqZjyZi
         bp5YIuXdb3efeTnY5H7NuDvaYivnYqIbcCsTKiZ5H1DwFz8woTaZdMSsgKGheuNmnuOL
         dkTgBF1swulgifU9/P7XzoHT7wGXHWz+iZBRXAlZEU2AkPw1MWHt1wIj3VxHNpRN1cTh
         2IZz8zdPxo/W5RLhDJTX9Uw2uWa6fQuv+54Flh0qSpfQxrvNQkTkx1rqiC9Nm7hTuWss
         yKyw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=lYn/cfzIUiLg8O0jmeN0oIUjcH6e7FhIiA9EkVEqfyc=;
        fh=zWbgYExXUw2vhaQFFRLnICOCTDCNtQc40ZhqGohl5VQ=;
        b=Hr2X2b5G3/eaSx1u2rg3AHyzMDY96HPU1nDeR+KbAoVD39Sm40D8CRRyb5nkreRCwD
         60CwIx3ioue+p3UigiEEeVemq0AnEEAliBmIe4eH7SCi3KKYe4NLsmaR4Agpt0wEcXal
         nPigxch8RKgNY1XRnrwVL7t9UE0tTKwlP8NK3EsL2+pX6HiU7JE8DFg/jVDqnnr1a0VH
         5ZuSqPlOvZjVMquj1uzOwblBjBgoQMX5YuRifubSUsA+5FnCyc5Jpdv2yJdkpz9MaMJL
         IImcLZt6KLxu122FbE5arD/uMMr0TdUtl2UkFfn/wtg2h/wad5q6XWN4hJ362/Yflzhk
         JMAA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=LAEKtQ4N;
       spf=pass (google.com: domain of ethan.w.s.graham@gmail.com designates 2a00:1450:4864:20::62d as permitted sender) smtp.mailfrom=ethan.w.s.graham@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-ej1-x62d.google.com (mail-ej1-x62d.google.com. [2a00:1450:4864:20::62d])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-47ed8ae95c7si12625e9.3.2026.01.12.11.28.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 12 Jan 2026 11:28:47 -0800 (PST)
Received-SPF: pass (google.com: domain of ethan.w.s.graham@gmail.com designates 2a00:1450:4864:20::62d as permitted sender) client-ip=2a00:1450:4864:20::62d;
Received: by mail-ej1-x62d.google.com with SMTP id a640c23a62f3a-b8710c9cddbso241239866b.2
        for <kasan-dev@googlegroups.com>; Mon, 12 Jan 2026 11:28:47 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCXBWw25moDXqKNUvTPN38WRQ8h9sT62yJQvZx6ssP4X/PKDP43N0ktbTdhmwZcqDj2c52Eg02Wlm0k=@googlegroups.com
X-Gm-Gg: AY/fxX7FOFt95qK5HIPNeCuhJfa5SQpk/hRhU4CJ00lJalNG+YZJbD+eBnLYNgafyaH
	MSRnxKW3iKoOmRVj7sxW4HiEU6GU7J39SN/Y+b8Z9lM65Ym0LzF17sgoVGyqWCBeCRK08YpowRA
	RSUGmCmiwO2D+g2XUPhbPOW5I8vvvDQeddm0FQVRzLLIQ28yZatmAzFiMtVoNTJU9cvaD7f2KyW
	4mSsdmxDWHWRwJGSx7MWnM57YAULws+cuzW1aCgsWQ2C7NwOPvPAxe6PhbSGiewsk0kGqKnT778
	26GAOtEMm7uc05Qkj6ZY6H0oOI5/6zEXrN+tj+307t+sodFqgLpHk1S9OeC9z24ShFwgj/2R6vk
	ncOI/UkF/DnuQelA/GvsEisZdU0h8OCC6ajkVH/sf97zgDtysp48qffxSczy1vo2hC8HAIKGE+N
	dTjJKLStOmhXqm82bUX2LhiBlzTtXMV+V9iIBFULhLo6fHb4v/MA==
X-Received: by 2002:a17:906:9f87:b0:b73:2b08:ac70 with SMTP id a640c23a62f3a-b844539fc4fmr1937923066b.49.1768246126219;
        Mon, 12 Jan 2026 11:28:46 -0800 (PST)
Received: from ethan-tp (xdsl-31-164-106-179.adslplus.ch. [31.164.106.179])
        by smtp.gmail.com with ESMTPSA id 4fb4d7f45d1cf-6507bf667fcsm18108959a12.29.2026.01.12.11.28.44
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 12 Jan 2026 11:28:45 -0800 (PST)
From: Ethan Graham <ethan.w.s.graham@gmail.com>
To: ethan.w.s.graham@gmail.com,
	glider@google.com
Cc: akpm@linux-foundation.org,
	andreyknvl@gmail.com,
	andy@kernel.org,
	andy.shevchenko@gmail.com,
	brauner@kernel.org,
	brendan.higgins@linux.dev,
	davem@davemloft.net,
	davidgow@google.com,
	dhowells@redhat.com,
	dvyukov@google.com,
	ebiggers@kernel.org,
	elver@google.com,
	gregkh@linuxfoundation.org,
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
	mcgrof@kernel.org,
	rmoar@google.com,
	shuah@kernel.org,
	sj@kernel.org,
	skhan@linuxfoundation.org,
	tarasmadan@google.com,
	wentaoz5@illinois.edu
Subject: [PATCH v4 4/6] kfuzztest: add KFuzzTest sample fuzz targets
Date: Mon, 12 Jan 2026 20:28:25 +0100
Message-ID: <20260112192827.25989-5-ethan.w.s.graham@gmail.com>
X-Mailer: git-send-email 2.51.0
In-Reply-To: <20260112192827.25989-1-ethan.w.s.graham@gmail.com>
References: <20260112192827.25989-1-ethan.w.s.graham@gmail.com>
MIME-Version: 1.0
X-Original-Sender: ethan.w.s.graham@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=LAEKtQ4N;       spf=pass
 (google.com: domain of ethan.w.s.graham@gmail.com designates
 2a00:1450:4864:20::62d as permitted sender) smtp.mailfrom=ethan.w.s.graham@gmail.com;
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

Add two simple fuzz target samples to demonstrate the KFuzzTest API and
provide basic self-tests for the framework.

These examples showcase how a developer can define a fuzz target using
the FUZZ_TEST_SIMPLE() macro. It also serves as a runtime sanity check,
ensuring that the framework correctly passes the input buffer and that
KASAN correctly detects out-of-bounds memory accesses (in this case, a
buffer underflow) on the allocated test data.

This target can be fuzzed naively by writing random data into the
debugfs 'input_simple' file and verifying that the KASAN report is
triggered.

Signed-off-by: Ethan Graham <ethan.w.s.graham@gmail.com>
Acked-by: Alexander Potapenko <glider@google.com>

---
PR v4:
- Remove the `test_underflow_on_nested_buffer` sample target which
  relied on the now removed `FUZZ_TEST` macro.
- Update the sample comment to demonstrate naive fuzzing (using `head`)
  instead of the removed bridge tool.
- Fix stale comments referencing internal layout structures.
PR v3:
- Use the FUZZ_TEST_SIMPLE macro in the `underflow_on_buffer` sample
  fuzz target instead of FUZZ_TEST.
PR v2:
- Fix build issues pointed out by the kernel test robot <lkp@intel.com>.
---
---
 samples/Kconfig                         |  7 ++++
 samples/Makefile                        |  1 +
 samples/kfuzztest/Makefile              |  3 ++
 samples/kfuzztest/underflow_on_buffer.c | 52 +++++++++++++++++++++++++
 4 files changed, 63 insertions(+)
 create mode 100644 samples/kfuzztest/Makefile
 create mode 100644 samples/kfuzztest/underflow_on_buffer.c

diff --git a/samples/Kconfig b/samples/Kconfig
index 6e072a5f1ed8..303a9831d404 100644
--- a/samples/Kconfig
+++ b/samples/Kconfig
@@ -320,6 +320,13 @@ config SAMPLE_HUNG_TASK
 	  Reading these files with multiple processes triggers hung task
 	  detection by holding locks for a long time (256 seconds).
 
+config SAMPLE_KFUZZTEST
+	bool "Build KFuzzTest sample targets"
+	depends on KFUZZTEST
+	help
+	  Build KFuzzTest sample targets that serve as selftests for raw input
+	  delivery and KASAN out-of-bounds detection.
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
index 000000000000..2dc5d424824d
--- /dev/null
+++ b/samples/kfuzztest/Makefile
@@ -0,0 +1,3 @@
+# SPDX-License-Identifier: GPL-2.0-only
+
+obj-$(CONFIG_SAMPLE_KFUZZTEST) += underflow_on_buffer.o
diff --git a/samples/kfuzztest/underflow_on_buffer.c b/samples/kfuzztest/underflow_on_buffer.c
new file mode 100644
index 000000000000..5568c5e6be7a
--- /dev/null
+++ b/samples/kfuzztest/underflow_on_buffer.c
@@ -0,0 +1,52 @@
+// SPDX-License-Identifier: GPL-2.0
+/*
+ * This file contains a KFuzzTest example target that ensures that a buffer
+ * underflow on a region triggers a KASAN OOB access report.
+ *
+ * Copyright 2025 Google LLC
+ */
+
+/**
+ * test_underflow_on_buffer - a sample fuzz target
+ *
+ * This sample fuzz target serves to illustrate the usage of the
+ * FUZZ_TEST_SIMPLE macro, as well as provide a sort of self-test that KFuzzTest
+ * functions correctly for trivial fuzz targets. In KASAN builds, fuzzing this
+ * harness should trigger a report for every input (provided that its length is
+ * greater than 0 and less than KFUZZTEST_MAX_INPUT_SIZE).
+ *
+ * This harness can be invoked (naively) like so:
+ * head -c 128 /dev/urandom > \
+ *	/sys/kernel/debug/kfuzztest/test_underflow_on_buffer/input_simple
+ */
+#include <linux/kfuzztest.h>
+
+static void underflow_on_buffer(char *buf, size_t buflen)
+{
+	size_t i;
+
+	/*
+	 * Print the address range of `buf` to allow correlation with the
+	 * subsequent KASAN report.
+	 */
+	pr_info("buf = [%px, %px)", buf, buf + buflen);
+
+	/* First ensure that all bytes in `buf` are accessible. */
+	for (i = 0; i < buflen; i++)
+		READ_ONCE(buf[i]);
+	/*
+	 * Provoke a buffer underflow on the first byte preceding `buf`,
+	 * triggering a KASAN report.
+	 */
+	READ_ONCE(*((char *)buf - 1));
+}
+
+/**
+ * Define the fuzz target. This wrapper ensures that the `underflow_on_buffer`
+ * function is invoked with the data provided from userspace.
+ */
+FUZZ_TEST_SIMPLE(test_underflow_on_buffer)
+{
+	underflow_on_buffer(data, datalen);
+	return 0;
+}
-- 
2.51.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20260112192827.25989-5-ethan.w.s.graham%40gmail.com.
