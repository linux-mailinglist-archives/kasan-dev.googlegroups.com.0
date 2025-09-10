Return-Path: <kasan-dev+bncBD53XBUFWQDBBFE3QTDAMGQEHXE4VFQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1037.google.com (mail-pj1-x1037.google.com [IPv6:2607:f8b0:4864:20::1037])
	by mail.lfdr.de (Postfix) with ESMTPS id 91F4CB50D5A
	for <lists+kasan-dev@lfdr.de>; Wed, 10 Sep 2025 07:33:10 +0200 (CEST)
Received: by mail-pj1-x1037.google.com with SMTP id 98e67ed59e1d1-329dca88b5asf389419a91.1
        for <lists+kasan-dev@lfdr.de>; Tue, 09 Sep 2025 22:33:10 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757482389; cv=pass;
        d=google.com; s=arc-20240605;
        b=R+WWlDpFesf5i7Pz9hp7oys7yNUQsa8FMEo/j0Kho5ao8+dd8FvAtbL3h1nnXw2IA5
         Bg0uaTrZEjlZJi1GIqbPv2boGCTiYlsbbuh1WzmVxB1RRQl+oK9afUknS0plZoW5XXBd
         s9fu406PB4B3DNMsUPGetY6qZf3IyWQ22HESnIckBupf33C61smwgpnoD3ZH9qE8wzGW
         4jFp+Yt+ClpHdIEbgqyCE2CBkjOO8MtR+za5IYcHlsy75tj0nwzeaj10+phJ1XNobRS8
         p42BlO4+s5fiDeSPgOiaRjnypLNIZNrxLM6eEHzRdgRM4mth04Dqcmb8b7jQCT3g8kUl
         Zx3g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=dpD3WdnvsydfbdplBOHDtX0san8jF07xD3kxSX9QweE=;
        fh=jTtE0GGGXpze5EPWebptGMpWdkKVCqyise6Wd69KFM0=;
        b=Z2dmtO9waFetkubx8NzcpoohO+efdIZgPFbxqdUNdIC1ueYvUUH9wtPCl219/pTbOj
         14UcQjbSjBEIYixLC6GEYfabocaOP3cZ6QTT/vz2JPdA4a3yMKRXw3iLgJIASmCnM6Yk
         oBoSMlEep5wjn2SUdRieRUIgqWREnwvGwN/oVFMB/lPUzHlA5N5aSP44mA1yx0p99jJn
         hbRA9njKRDI0a2y2DNRmFrcHos5xuhuJJQNBuuK0930Dun90I7wzba8FATMMeLShsGgy
         Wk4WpKEb2oSg5x4NUuaM5SxojDA6QGnXq3BqlfVwdCiXuRpx4nki3Y+ZvxL3MevaLP2Z
         gVYg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=PQKNl5Jy;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::1029 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757482389; x=1758087189; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=dpD3WdnvsydfbdplBOHDtX0san8jF07xD3kxSX9QweE=;
        b=l7jm6Dj0YJxU27J/yEgpg4FMpqQxREfNNyUmplSKgSLiPbSTKsLclHbIBwfUzXF51l
         SVMngMT5VqxRRj6LGiTF95hPa90O/0RAO0nnwo40OQINs61087Od43z5n8/gDvxg62fp
         zqOUCJGoikFMIEq16qAM2/3vb07VZ9kpamr9xwTy/PYPdsQ0swlKC6tgpW5ePYRLWyMh
         KCn2ovGxlJq8i8TDUHkDGLx3C5cWOM3OqtCj6fJN6KuUyznPb0nsThmrmXCu9rk8Nm8c
         CgZxbTIo58T+aWB44MI7fkYHvTf9RK5X+Duiu4nJeNZjHdoVH5+D0PaKMy5BFbgWRfJs
         dqSg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1757482389; x=1758087189; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=dpD3WdnvsydfbdplBOHDtX0san8jF07xD3kxSX9QweE=;
        b=DJ5K6eLSaPwY9ZUgiYzMZ8O7wywDMLftv3KVHq4+CHOz+zJDdrSAUVbmZMHDOSIvqF
         2/ii3qaeUo/zuaAMODXvn8MFk2LZ+bnPb6O52at70AMbxeh36Byk6yKdj13XLN9s8koV
         rN5yhBifUvU0IhiUb0zy9pAJ8PcU3iu38xX+a+XXfxGkKp+/TPAxynM/TWQt560tgoE+
         gDyL1P6wzGjAhRzMlAlUzWcRlZ4jpXiiij45hJxsxS4BiucQbCcGcJ0T61bJ/S5y1j0c
         CyqN+BzYMgmR/EpdbrH859aKEpzsBO/pz1pHsXTu9phzAgGU3PnIz4cj9b0MOPWugsZZ
         ITeA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757482389; x=1758087189;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=dpD3WdnvsydfbdplBOHDtX0san8jF07xD3kxSX9QweE=;
        b=EMCc4wS8ELmzmUAiWPqT2xXW8QIuc2B+ZDQ0c2Yk5k6Orysh/1R6IJlWUBwFk8ws/S
         atBfgNCn89trGfHiJMPRBX6EDiD3NMfkbxS3cZEnZ638slc0BWmCP7o7K7/UyCkN4afH
         jbXs6RtMZxY6PiQ+ZRO9IR9QzZFmmQZEnSAelhrSHOCziCSeQGBTv/Y+NwYmILKulsMx
         dd3QTgukL/OvOGyoVL5Fs+qmJoCqysQWrcHp5jPR41K9f8u5lGAAXvq8WqDj9cP0fnqI
         bFqOiEpujKkS3J9PcCFgEXpTJO/7qdWj+bARCzUF0HiT4qq9qP+pa8UUxTxQC30eEcsJ
         6ycg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWZ3EkI96g6UJCODImSfQNgUpSR3r0/slonQR1ew+VQuoYS5R7QBZ1UM/5XT//SRq1BkC/t1A==@lfdr.de
X-Gm-Message-State: AOJu0YxQqmDVHCYOpA1yOUmycW+oaPFlKKHRLMP7o0VcEPkvmNZeXow1
	HLpS2orNma/YI4EJuJCVI9z1cRjgvri3qmpCRNZcoVvK/RfhuD8G5YgI
X-Google-Smtp-Source: AGHT+IFOeBhmVFF0MOZCAJsFFU+VlFvTCeJ+O8pq92hzoPWXdMTJ5BjEMYryGpRy1SBFe9dKeIAdgg==
X-Received: by 2002:a05:6a20:394a:b0:24d:d206:69ac with SMTP id adf61e73a8af0-2537be0f199mr20657035637.14.1757482388835;
        Tue, 09 Sep 2025 22:33:08 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd7dqSCXXxQNITI+SZ71p+qvO2FGv9f05YsG9ad72xZSKg==
Received: by 2002:a17:90b:344d:b0:327:f95c:7f6a with SMTP id
 98e67ed59e1d1-32db9c3f823ls213233a91.2.-pod-prod-00-us; Tue, 09 Sep 2025
 22:33:07 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUTsyqsyBnEkaXklOyRE/dNvdcXSFSPYAKIp4YNSOIGT8DNhn/Cg211ddDuEnMEFNs643BghPqoWI4=@googlegroups.com
X-Received: by 2002:a17:90b:5306:b0:327:c583:add with SMTP id 98e67ed59e1d1-32bbd15a872mr22504393a91.6.1757482387167;
        Tue, 09 Sep 2025 22:33:07 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1757482387; cv=none;
        d=google.com; s=arc-20240605;
        b=dR94Ud0dphYBpbIu4zoDAfkXzyrI20hZtf/HymrEQfJSZyJ04e3i11DCx3x/bI8hmk
         PhA4heC8m17rEN2k0s1x5pyrfL0y91tQ4i4xIAQZtta1D9cUtao+SQ+o45OiKjc3ii8d
         QYXbJi0p4I5snjsopwiW/RY/7zlJlHtwY39qDscZ1w8L7kr/XMzazzEWO9Jsp6FQGX9u
         GhYUaOkw3Vl+xPnJWgsUTueI9MdrDxDGjIR/rqy0at4pd1A7a2RYs//oP7sxFSLzZdg1
         xo0WGOfJQ8G68B5UCpcaGXTGAYIao+OrJSLZIaeDqK0ZtlBqqlu+J1PVzB1cTCXDcKS3
         w4Yw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=Hza3KqRNKGSLYWfBSKXFsxDeH0DXXBXA3429C+Yqz2A=;
        fh=DZqlodiTrZuXjgYCTAqbUnFecIZekNd02HCJAGMLsIc=;
        b=b0c0Rp/isCHmDAAHCC/mZ6O9XqRu/bQKZyzx7ZBaGDSfp6XzbJGK78bPVYgj+IYZXS
         3DTXmgCKnCcv6mylbPfnK/XqMqOccs9v1hKSHoQx74frGkHfD3VEHqMGCDPYvaqxD5F5
         gTHdEoLvARUkSfqOwHosCukzcEhMK0OvAaEesc4fZbUBXaZvUt45AylL2AJkk8ggNUQn
         qffhYzUg0P0e50bW0VlFZyIKZ/K8AswR3x1231fzDOpP+EY6DQwMHndnC8aMfBFfCyzD
         1BM+cz5DAQL2FK83wbtGgGM5eJnSjhHL1eZo82xb1P/N8WatF/KsAGpBGdpSIHlEM3Y6
         9NZA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=PQKNl5Jy;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::1029 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pj1-x1029.google.com (mail-pj1-x1029.google.com. [2607:f8b0:4864:20::1029])
        by gmr-mx.google.com with ESMTPS id 41be03b00d2f7-b4cd28b47easi1314359a12.4.2025.09.09.22.33.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 09 Sep 2025 22:33:07 -0700 (PDT)
Received-SPF: pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::1029 as permitted sender) client-ip=2607:f8b0:4864:20::1029;
Received: by mail-pj1-x1029.google.com with SMTP id 98e67ed59e1d1-32b5d8bea85so223880a91.1
        for <kasan-dev@googlegroups.com>; Tue, 09 Sep 2025 22:33:07 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCViejF74yaTK1O1Ob77vP1biZeTzHIlh5mRS5ntRbC594FoujUq46g6y3xn92LosQUN9mAzoBMrLvE=@googlegroups.com
X-Gm-Gg: ASbGncuT9+XnqQZg13X1FhlDiaPYClhaZJI6klrORzA10R3rJvRHqfPIUL7L8zoWpKU
	yWKMzsaCCMhNv4wSX7gaPBSMs4EB75Ouz743fpF9IS0JqO6S9z+yjNAKVxzDC77GyhEWu6rJ8LN
	KaX5nc0idTRGqNK3tE1/TgGG+QgJIuc7Ycb36bcFIflzvqSC7hpWB4HvQ1ZR2hcseDxnbDeRYx/
	IMgMO/GV0AzxmH9jA62VDrkx2IxtklweeLtZ6kVq2Rz2MXa5TgxbXwl7bOfdZJVQPioA9krgc8I
	dTIgdWaZRIK7W1a6NYSgqjdkFK7kMyAz7DHLFBhoTxodBYryZPSsYsUiSXwbFwH07EED+JNAaa1
	Kz1+TevUmEYNBzfcRv4AzrvZoyviF64vvbM9yc8KBeQG5eA2O5g==
X-Received: by 2002:a17:90b:2396:b0:32b:b514:3936 with SMTP id 98e67ed59e1d1-32bbe214925mr16978278a91.13.1757482386624;
        Tue, 09 Sep 2025 22:33:06 -0700 (PDT)
Received: from localhost.localdomain ([45.8.220.62])
        by smtp.gmail.com with ESMTPSA id d2e1a72fcca58-7746628ffbesm3870342b3a.66.2025.09.09.22.32.54
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 09 Sep 2025 22:33:06 -0700 (PDT)
From: Jinchao Wang <wangjinchao600@gmail.com>
To: Andrew Morton <akpm@linux-foundation.org>,
	Masami Hiramatsu <mhiramat@kernel.org>,
	Peter Zijlstra <peterz@infradead.org>,
	Mike Rapoport <rppt@kernel.org>,
	"Naveen N . Rao" <naveen@kernel.org>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	kasan-dev@googlegroups.com,
	"David S. Miller" <davem@davemloft.net>,
	Steven Rostedt <rostedt@goodmis.org>,
	Mathieu Desnoyers <mathieu.desnoyers@efficios.com>,
	Ingo Molnar <mingo@redhat.com>,
	Arnaldo Carvalho de Melo <acme@kernel.org>,
	Namhyung Kim <namhyung@kernel.org>,
	Mark Rutland <mark.rutland@arm.com>,
	Alexander Shishkin <alexander.shishkin@linux.intel.com>,
	Jiri Olsa <jolsa@kernel.org>,
	Ian Rogers <irogers@google.com>,
	Adrian Hunter <adrian.hunter@intel.com>,
	"Liang, Kan" <kan.liang@linux.intel.com>,
	Thomas Gleixner <tglx@linutronix.de>,
	Borislav Petkov <bp@alien8.de>,
	Dave Hansen <dave.hansen@linux.intel.com>,
	x86@kernel.org,
	"H. Peter Anvin" <hpa@zytor.com>,
	linux-mm@kvack.org,
	linux-trace-kernel@vger.kernel.org,
	linux-perf-users@vger.kernel.org
Cc: linux-kernel@vger.kernel.org,
	Jinchao Wang <wangjinchao600@gmail.com>
Subject: [PATCH v3 14/19] mm/ksw: add test module
Date: Wed, 10 Sep 2025 13:31:12 +0800
Message-ID: <20250910053147.1152253-6-wangjinchao600@gmail.com>
X-Mailer: git-send-email 2.43.0
In-Reply-To: <20250910053147.1152253-1-wangjinchao600@gmail.com>
References: <20250910052335.1151048-1-wangjinchao600@gmail.com>
 <20250910053147.1152253-1-wangjinchao600@gmail.com>
MIME-Version: 1.0
X-Original-Sender: wangjinchao600@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=PQKNl5Jy;       spf=pass
 (google.com: domain of wangjinchao600@gmail.com designates
 2607:f8b0:4864:20::1029 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
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

Introduce a separate test module to validate functionality in controlled
scenarios, such as stack canary writes and simulated corruption.

The module provides a proc interface (/proc/kstackwatch_test) that allows
triggering specific test cases via simple commands:

 - test0: directly corrupt the canary to verify watch/fire behavior

Test module is built with optimizations disabled to ensure predictable
behavior.

Signed-off-by: Jinchao Wang <wangjinchao600@gmail.com>
---
 mm/Kconfig.debug        |  10 ++++
 mm/kstackwatch/Makefile |   6 +++
 mm/kstackwatch/test.c   | 115 ++++++++++++++++++++++++++++++++++++++++
 3 files changed, 131 insertions(+)
 create mode 100644 mm/kstackwatch/test.c

diff --git a/mm/Kconfig.debug b/mm/Kconfig.debug
index fdfc6e6d0dec..46c280280980 100644
--- a/mm/Kconfig.debug
+++ b/mm/Kconfig.debug
@@ -320,3 +320,13 @@ config KSTACK_WATCH
 	  the recursive depth of the monitored function.
 
 	  If unsure, say N.
+
+config KSTACK_WATCH_TEST
+	tristate "KStackWatch Test Module"
+	depends on KSTACK_WATCH
+	help
+	  This module provides controlled stack exhaustion and overflow scenarios
+	  to verify the functionality of KStackWatch. It is particularly useful
+	  for development and validation of the KStachWatch mechanism.
+
+	  If unsure, say N.
diff --git a/mm/kstackwatch/Makefile b/mm/kstackwatch/Makefile
index 84a46cb9a766..d007b8dcd1c6 100644
--- a/mm/kstackwatch/Makefile
+++ b/mm/kstackwatch/Makefile
@@ -1,2 +1,8 @@
 obj-$(CONFIG_KSTACK_WATCH)	+= kstackwatch.o
 kstackwatch-y := kernel.o stack.o watch.o
+
+obj-$(CONFIG_KSTACK_WATCH_TEST)	+= kstackwatch_test.o
+kstackwatch_test-y := test.o
+CFLAGS_test.o := -fno-inline \
+		-fno-optimize-sibling-calls \
+		-fno-pic -fno-pie -O0 -Og
diff --git a/mm/kstackwatch/test.c b/mm/kstackwatch/test.c
new file mode 100644
index 000000000000..76dbfb042067
--- /dev/null
+++ b/mm/kstackwatch/test.c
@@ -0,0 +1,115 @@
+// SPDX-License-Identifier: GPL-2.0
+#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
+
+#include <linux/delay.h>
+#include <linux/kthread.h>
+#include <linux/module.h>
+#include <linux/prandom.h>
+#include <linux/printk.h>
+#include <linux/proc_fs.h>
+#include <linux/string.h>
+#include <linux/uaccess.h>
+
+#include "kstackwatch.h"
+
+MODULE_AUTHOR("Jinchao Wang");
+MODULE_DESCRIPTION("Simple KStackWatch Test Module");
+MODULE_LICENSE("GPL");
+
+static struct proc_dir_entry *test_proc;
+#define BUFFER_SIZE 4
+#define MAX_DEPTH 6
+
+/*
+ * Test Case 0: Write to the canary position directly (Canary Test)
+ * use a u64 buffer array to ensure the canary will be placed
+ * corrupt the stack canary using the debug function
+ */
+static void canary_test_write(void)
+{
+	u64 buffer[BUFFER_SIZE];
+
+	pr_info("starting %s\n", __func__);
+	ksw_watch_show();
+	ksw_watch_fire();
+
+	buffer[0] = 0;
+
+	/* make sure the compiler do not drop assign action */
+	barrier_data(buffer);
+	pr_info("canary write test completed\n");
+}
+
+static ssize_t test_proc_write(struct file *file, const char __user *buffer,
+			       size_t count, loff_t *pos)
+{
+	char cmd[256];
+	int test_num;
+
+	if (count >= sizeof(cmd))
+		return -EINVAL;
+
+	if (copy_from_user(cmd, buffer, count))
+		return -EFAULT;
+
+	cmd[count] = '\0';
+	strim(cmd);
+
+	pr_info("received command: %s\n", cmd);
+
+	if (sscanf(cmd, "test%d", &test_num) == 1) {
+		switch (test_num) {
+		case 0:
+			pr_info("triggering canary write test\n");
+			canary_test_write();
+			break;
+		default:
+			pr_err("Unknown test number %d\n", test_num);
+			return -EINVAL;
+		}
+	} else {
+		pr_err("invalid command format. Use 'test1', 'test2', or 'test3'.\n");
+		return -EINVAL;
+	}
+
+	return count;
+}
+
+static ssize_t test_proc_read(struct file *file, char __user *buffer,
+			      size_t count, loff_t *pos)
+{
+	static const char usage[] =
+		"KStackWatch Simplified Test Module\n"
+		"==================================\n"
+		"Usage:\n"
+		"  echo 'test0' > /proc/kstackwatch_test  - Canary write test\n";
+
+	return simple_read_from_buffer(buffer, count, pos, usage,
+				       strlen(usage));
+}
+
+static const struct proc_ops test_proc_ops = {
+	.proc_read = test_proc_read,
+	.proc_write = test_proc_write,
+};
+
+static int __init kstackwatch_test_init(void)
+{
+	test_proc = proc_create("kstackwatch_test", 0600, NULL, &test_proc_ops);
+	if (!test_proc) {
+		pr_err("Failed to create proc entry\n");
+		return -ENOMEM;
+	}
+	pr_info("module loaded\n");
+	return 0;
+}
+
+static void __exit kstackwatch_test_exit(void)
+{
+	if (test_proc)
+		remove_proc_entry("kstackwatch_test", NULL);
+	pr_info("module unloaded\n");
+}
+
+module_init(kstackwatch_test_init);
+module_exit(kstackwatch_test_exit);
-- 
2.43.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250910053147.1152253-6-wangjinchao600%40gmail.com.
