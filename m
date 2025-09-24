Return-Path: <kasan-dev+bncBD53XBUFWQDBBXVWZ7DAMGQEKZG3EVI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-x113d.google.com (mail-yw1-x113d.google.com [IPv6:2607:f8b0:4864:20::113d])
	by mail.lfdr.de (Postfix) with ESMTPS id D00BCB99A94
	for <lists+kasan-dev@lfdr.de>; Wed, 24 Sep 2025 13:51:59 +0200 (CEST)
Received: by mail-yw1-x113d.google.com with SMTP id 00721157ae682-74887ca0b1csf13022967b3.0
        for <lists+kasan-dev@lfdr.de>; Wed, 24 Sep 2025 04:51:59 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758714718; cv=pass;
        d=google.com; s=arc-20240605;
        b=FL7UiGXoUP/oV+n3c3Tr9UbhAebX0K6iKHpCbaET+a7aTPEkTkDFC7uj8rEEXKTodm
         jDqNtu6lSK2nY2DQGtrBuIteyywJe6/sYhY731MgQPIWSZjL9g8HCBua3iodiWFjn+8/
         qInbCU5YojXs8Ta5uQYRuyhwS5uG6vanoTnEczztWZW1iLy9DIjn+5OW0c6NXvGAvjkU
         MCdDjk2ukXfnf9g3Pu4aUCHt4lNGKy9xPXtQyp4NNzMHQAnG78Rbw0KbU/y/ddI4zvb5
         GwT3vhCDQO4IPQ8cW3JuYjQr1XgcnDTwu6o5K02tfJRhOuIRlyTxBrPe2NHw1JkqFZui
         SbXQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=rbFCSYhyRrlrfby98rlcsNhBg5bU53l/IbL1tPYcKME=;
        fh=xVlvW1JbV94xnl03glkAHJ7SAK6V/40cXkTX1F/5xR4=;
        b=AHRUrjJDOmTsjrtGCOLc9NUK0EF+GTKplKG9EnuUgnHTGSdkvgx392Se/6RKn5cVmN
         f50JRyE5qOqksNddmixvNXhKKf3C/G33ESMF5+Kn0anbTZo6VGROQnKLrP23wOzEzfqe
         sWVk5lLWtUIlOW2vh/XDfEj5jQr8dwzeKn7BFCFQ3oCklDvJ6s2vqCqCt6AwhjA7EXmq
         +I/KkBWl6QtS3fRUes1xTh/imMQ9zu3GXVoUx0wfasxQiHVYhzVEV7Q0gIk8KzwMxemI
         SHR/HNnX4kq9nB+Mhn+R8rEfh5PY5VFHXDO7npblzwVJhF47z4yzirDZJTNgIyF0jc18
         zkMw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=aTu0FDHc;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::52c as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758714718; x=1759319518; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=rbFCSYhyRrlrfby98rlcsNhBg5bU53l/IbL1tPYcKME=;
        b=PvCP94F4zp210YINNYG4x52SgEJLY8l1X92kW7939eDZpyAhdQFUUcAlNVeHDGfjT+
         UGBJ+gqY5n5kH9PlpyckxGxogjaG+MJNmr15rHiXwXrPJ0SS6IFwA/UZRcwoiDc03/j3
         Dhg0qLTVpdmJwr0J94hca8CrukJVKDE/68GnMw4nacrGXtDKa1x2h0Tk+ti19SSb4F2L
         RmHS/qU9YP8t3jFv141S2ihRnKoDMr8Ca6ZG7w6mJNsJKTtOKAo98tFKIiOHDoMkahT2
         L4/meHwod2OSiXAB2r3JHWyfxkPmyjMaf0BOTiF4jmMuz3be1hJPyQ4GYW3USYkszjNq
         6mig==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1758714718; x=1759319518; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=rbFCSYhyRrlrfby98rlcsNhBg5bU53l/IbL1tPYcKME=;
        b=X93R7Zj8mcZTTcQstJuLyCQ576BYuebcM4wQsqS/yOCP8LVHO/uC4JUvpIcvT6rGbc
         /dA9EcLUbln1cDdT8+qfiwcIKpHWkRJtXV9FYH4VtQI8hLZt5UQoN+4xZEJgPn79Lesf
         5vQEujjDO5DHYdj8/ZTyUhxLduMsTWmN2JSU2DKGv295SChwhbQLYN/t7YU3iO1Pot3m
         083s/ylOLSksG+QAPi0yxjiHJYj+UrlSjZmHpXcJuwkmL4/eY+/m+zVM/QqYVsKomyiS
         TeQTSkDTYpUkTQyKsRUaDxgTZOzEc8X2hpSb4KYbO6sFnWkyuii6fdBYLgujWO76v1J1
         RAbg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758714718; x=1759319518;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=rbFCSYhyRrlrfby98rlcsNhBg5bU53l/IbL1tPYcKME=;
        b=IKPEvxb2H4wQvaB6cxwsP87l/hajqpm5zw2ICrO4sghJkoTYx15KRAiMjyFy/QSVBh
         IUYNMaTl9nMPgsShVXeTSZf5cKQAbcbit3fupFjOZjuDSJLhTTim7N66GRgeQgzd+mSO
         DRXk+wDS6Y+O9z5O3MK1JlyuUZ1BKCiRe+8SY9L9LKJFC4wXXnBWK+O8e/vnQJoR6lBW
         SuDFn+DnWqfmHlesS5alDLw2Rwv/guPnuW8qY5xMQ+7UM6wjJzbU9hDmTndO89I7Z4mh
         2ZVSGnwOTfZBA7Mk+5mHESSwAUu0YHSywb7iXx8jRtQ4RRG11xiW/azDlWN0/SY4aFWH
         o8Ng==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUFJANc0y3KDccEiADwBnSH8QfTj1cNMVomlRL8m45PlLdZlYinDir47KFHjlMTS/bfx+gvww==@lfdr.de
X-Gm-Message-State: AOJu0YwJ/8t3dj6koqMU6dQdshEfZPbTtq1FGU6VdmxIDrSic2vNRdJ3
	qC2QO3Atp5khcjACtRbzDX5Eeuy/+8TkW8gxMLtWK/GUw1XUzWlA1cnM
X-Google-Smtp-Source: AGHT+IEadjM6RAW8gq2ObzNMvqRcwL4YF30DUGBDQ0LCEHdyomHkEwUdgSjya30SVyPFS5s1dl7JGA==
X-Received: by 2002:a05:690c:10d:b0:72d:479f:5af8 with SMTP id 00721157ae682-75f65bebb95mr15021507b3.20.1758714718454;
        Wed, 24 Sep 2025 04:51:58 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="ARHlJd6H6wbFxrQRBTAhlapy8bKZ1ubUOl1LI6r5Pa9+FCRuow=="
Received: by 2002:a05:690e:245c:b0:5f3:ae22:ddc0 with SMTP id
 956f58d0204a3-6360dcc0100ls106804d50.0.-pod-prod-00-us-canary; Wed, 24 Sep
 2025 04:51:57 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWQUX9uSThLmFcEV3qQiX44vQvF8faSWgfTwWC8RJPnF7TSP+tMTxHsLEdmsBpxU+B4C3fWGGppHR4=@googlegroups.com
X-Received: by 2002:a05:690c:a5c7:b0:742:7bcc:5d58 with SMTP id 00721157ae682-75f67f8a989mr9462267b3.27.1758714717396;
        Wed, 24 Sep 2025 04:51:57 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1758714717; cv=none;
        d=google.com; s=arc-20240605;
        b=Ge+/3a+1z0zoZBEFZpzs0LGLdy+qpiAamOymbS7Tx+A42DgVCmpQ+gzoaITUeduBsX
         hA7sZ0QfV3/EOT69lpw/yy0hQFUpCwGLX+/lCY0PKxW+b9o8Y1hi064U4e3UWX/7+OK0
         ctTEDYdWUjRv6kQpM92/f5zwbehYZsGRFdxrVx0XJTF/prfRyPnCepT55o7bgUirs5mp
         HIrwpRBRElL8OFFgfV0C8R98MnjCn/jb9c4Yhf8vufxpJQ7tBOjrSBfzx2o1dE6fP56F
         QWldCMF2/XwRRfgute5j8UeDmll3tDLAZHGBcY0JdwMWruCSRzoPGMhE2smVaBd5XV9g
         SgnQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=chAO9GOTMxCV8ZHg6BsIF9VuSBV9TkSRS16Il152ztM=;
        fh=KBgHcO6a9YGW7odE4ZOS/5CzN7HRDeU6jNRRCuUr2VY=;
        b=MGmT/6acjcELqj+nK+edEG2N6c4ux28klWyQAUd3lemyu2cSWyDvvZRnG6o+9wL0CZ
         gHWefhqS7M0CudxaAoI3gu6m3VBzw9MT9pUxHvf/7eyPIPFeeS7Yw/L4LVTq8c8mZfSc
         LrVrCirSCPAVLCrQzrQanFDeGMgC5TiFPxDNKatPqedXsyq9sJSrmb4ppV9jmOw+pDj+
         xluEpx6zuBlJDfQ2FzeAugG8Kb3qFvtMolj2+xEsvJ5TE+WGY8bYp2I1uFO7ddMGQu8S
         x8Z/3f3cGKKf2dtpCl7X6u1pvXFOn3v6x2bxJqgsQ5FE2H3w/IHEc4Fimjufdr8Oiu+7
         5J/g==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=aTu0FDHc;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::52c as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pg1-x52c.google.com (mail-pg1-x52c.google.com. [2607:f8b0:4864:20::52c])
        by gmr-mx.google.com with ESMTPS id 00721157ae682-7397146ea02si6034557b3.0.2025.09.24.04.51.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 24 Sep 2025 04:51:57 -0700 (PDT)
Received-SPF: pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::52c as permitted sender) client-ip=2607:f8b0:4864:20::52c;
Received: by mail-pg1-x52c.google.com with SMTP id 41be03b00d2f7-b54a588ad96so768766a12.1
        for <kasan-dev@googlegroups.com>; Wed, 24 Sep 2025 04:51:57 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWfu6JnXf/hu4GZHyQYLq5a9F1tt+9T7KWubdEWK5CcOyxb8H/8Ch9x5hOwg1y54W6O7y8texWrE8U=@googlegroups.com
X-Gm-Gg: ASbGncvUztGuKc6mzZpDB5QIKXQQpXIojllF2o/Kzp0fvgL9oZ/6m3Pfh3YoPym/HBk
	UQcOEnjVKfrRmuVDnUBI/Qu/RF/UKRum1eBBYVcCdklXYBEH+7eqm2mUKKNhRUOPTOSaglmo6aJ
	JR+K+GhlbZeUz4NAIlto/UNpJaRZ30fTgGhpy417gPtVnlMXwQjWGBmX//PfnHQRTNlW8mj0Jdu
	LwguP/+B8M8pnfN0Drb3Md7ZIpsxRwa9QW6SymdDGQN3waYwVHjx/SVQdEKffWyn6reUCa1NlUP
	BSBlwOT2U9MhgoVE+ylp4m7alS9NaRdeVmFzjAEwCOCaKDGz2qJubcz81dqjTk7ot8HG7PKVE0Z
	ZlQ6W7uuad0hTXXzgg0Wq5IZPtg==
X-Received: by 2002:a17:903:19ef:b0:27d:6cb6:f7c2 with SMTP id d9443c01a7336-27ec11ff7d5mr23462095ad.17.1758714716359;
        Wed, 24 Sep 2025 04:51:56 -0700 (PDT)
Received: from localhost ([23.142.224.65])
        by smtp.gmail.com with ESMTPSA id d9443c01a7336-26980179981sm188216855ad.54.2025.09.24.04.51.55
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 24 Sep 2025 04:51:55 -0700 (PDT)
From: Jinchao Wang <wangjinchao600@gmail.com>
To: Andrew Morton <akpm@linux-foundation.org>,
	Masami Hiramatsu <mhiramat@kernel.org>,
	Peter Zijlstra <peterz@infradead.org>,
	Mike Rapoport <rppt@kernel.org>,
	Alexander Potapenko <glider@google.com>,
	Randy Dunlap <rdunlap@infradead.org>,
	Jonathan Corbet <corbet@lwn.net>,
	Thomas Gleixner <tglx@linutronix.de>,
	Ingo Molnar <mingo@redhat.com>,
	Borislav Petkov <bp@alien8.de>,
	Dave Hansen <dave.hansen@linux.intel.com>,
	x86@kernel.org,
	"H. Peter Anvin" <hpa@zytor.com>,
	Juri Lelli <juri.lelli@redhat.com>,
	Vincent Guittot <vincent.guittot@linaro.org>,
	Dietmar Eggemann <dietmar.eggemann@arm.com>,
	Steven Rostedt <rostedt@goodmis.org>,
	Ben Segall <bsegall@google.com>,
	Mel Gorman <mgorman@suse.de>,
	Valentin Schneider <vschneid@redhat.com>,
	Arnaldo Carvalho de Melo <acme@kernel.org>,
	Namhyung Kim <namhyung@kernel.org>,
	Mark Rutland <mark.rutland@arm.com>,
	Alexander Shishkin <alexander.shishkin@linux.intel.com>,
	Jiri Olsa <jolsa@kernel.org>,
	Ian Rogers <irogers@google.com>,
	Adrian Hunter <adrian.hunter@intel.com>,
	"Liang, Kan" <kan.liang@linux.intel.com>,
	David Hildenbrand <david@redhat.com>,
	Lorenzo Stoakes <lorenzo.stoakes@oracle.com>,
	"Liam R. Howlett" <Liam.Howlett@oracle.com>,
	Vlastimil Babka <vbabka@suse.cz>,
	Suren Baghdasaryan <surenb@google.com>,
	Michal Hocko <mhocko@suse.com>,
	Nathan Chancellor <nathan@kernel.org>,
	Nick Desaulniers <nick.desaulniers+lkml@gmail.com>,
	Bill Wendling <morbo@google.com>,
	Justin Stitt <justinstitt@google.com>,
	Kees Cook <kees@kernel.org>,
	Alice Ryhl <aliceryhl@google.com>,
	Sami Tolvanen <samitolvanen@google.com>,
	Miguel Ojeda <ojeda@kernel.org>,
	Masahiro Yamada <masahiroy@kernel.org>,
	Rong Xu <xur@google.com>,
	Naveen N Rao <naveen@kernel.org>,
	David Kaplan <david.kaplan@amd.com>,
	Andrii Nakryiko <andrii@kernel.org>,
	Jinjie Ruan <ruanjinjie@huawei.com>,
	Nam Cao <namcao@linutronix.de>,
	workflows@vger.kernel.org,
	linux-doc@vger.kernel.org,
	linux-kernel@vger.kernel.org,
	linux-perf-users@vger.kernel.org,
	linux-mm@kvack.org,
	llvm@lists.linux.dev,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	kasan-dev@googlegroups.com,
	"David S. Miller" <davem@davemloft.net>,
	Mathieu Desnoyers <mathieu.desnoyers@efficios.com>,
	linux-trace-kernel@vger.kernel.org
Cc: Jinchao Wang <wangjinchao600@gmail.com>
Subject: [PATCH v5 06/23] mm/ksw: add singleton /proc/kstackwatch interface
Date: Wed, 24 Sep 2025 19:50:49 +0800
Message-ID: <20250924115124.194940-7-wangjinchao600@gmail.com>
X-Mailer: git-send-email 2.43.0
In-Reply-To: <20250924115124.194940-1-wangjinchao600@gmail.com>
References: <20250924115124.194940-1-wangjinchao600@gmail.com>
MIME-Version: 1.0
X-Original-Sender: wangjinchao600@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=aTu0FDHc;       spf=pass
 (google.com: domain of wangjinchao600@gmail.com designates
 2607:f8b0:4864:20::52c as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
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

Provide the /proc/kstackwatch file to read or update the configuration.
Only a single process can open this file at a time, enforced using atomic
config_file_busy, to prevent concurrent access.

ksw_get_config() exposes the configuration pointer as const.

Signed-off-by: Jinchao Wang <wangjinchao600@gmail.com>
---
 mm/kstackwatch/kernel.c      | 77 +++++++++++++++++++++++++++++++++++-
 mm/kstackwatch/kstackwatch.h |  3 ++
 2 files changed, 79 insertions(+), 1 deletion(-)

diff --git a/mm/kstackwatch/kernel.c b/mm/kstackwatch/kernel.c
index 3b7009033dd4..4a06ddadd9c7 100644
--- a/mm/kstackwatch/kernel.c
+++ b/mm/kstackwatch/kernel.c
@@ -3,11 +3,15 @@
 
 #include <linux/kstrtox.h>
 #include <linux/module.h>
+#include <linux/proc_fs.h>
+#include <linux/seq_file.h>
 #include <linux/string.h>
+#include <linux/uaccess.h>
 
 #include "kstackwatch.h"
 
 static struct ksw_config *ksw_config;
+static atomic_t config_file_busy = ATOMIC_INIT(0);
 
 struct param_map {
 	const char *name;       /* long name */
@@ -74,7 +78,7 @@ static int ksw_parse_param(struct ksw_config *config, const char *key,
  * - sp_offset  |so (u16) : offset from stack pointer at func_offset
  * - watch_len  |wl (u16) : watch length (1,2,4,8)
  */
-static int __maybe_unused ksw_parse_config(char *buf, struct ksw_config *config)
+static int ksw_parse_config(char *buf, struct ksw_config *config)
 {
 	char *part, *key, *val;
 	int ret;
@@ -109,18 +113,89 @@ static int __maybe_unused ksw_parse_config(char *buf, struct ksw_config *config)
 	return 0;
 }
 
+static ssize_t kstackwatch_proc_write(struct file *file,
+				      const char __user *buffer, size_t count,
+				      loff_t *pos)
+{
+	char input[MAX_CONFIG_STR_LEN];
+	int ret;
+
+	if (count == 0 || count >= sizeof(input))
+		return -EINVAL;
+
+	if (copy_from_user(input, buffer, count))
+		return -EFAULT;
+
+	input[count] = '\0';
+	strim(input);
+
+	if (!strlen(input)) {
+		pr_info("config cleared\n");
+		return count;
+	}
+
+	ret = ksw_parse_config(input, ksw_config);
+	if (ret) {
+		pr_err("Failed to parse config %d\n", ret);
+		return ret;
+	}
+
+	return count;
+}
+
+static int kstackwatch_proc_show(struct seq_file *m, void *v)
+{
+	seq_printf(m, "%s\n", ksw_config->user_input);
+	return 0;
+}
+
+static int kstackwatch_proc_open(struct inode *inode, struct file *file)
+{
+	if (atomic_cmpxchg(&config_file_busy, 0, 1))
+		return -EBUSY;
+
+	return single_open(file, kstackwatch_proc_show, NULL);
+}
+
+static int kstackwatch_proc_release(struct inode *inode, struct file *file)
+{
+	atomic_set(&config_file_busy, 0);
+	return single_release(inode, file);
+}
+
+static const struct proc_ops kstackwatch_proc_ops = {
+	.proc_open = kstackwatch_proc_open,
+	.proc_read = seq_read,
+	.proc_write = kstackwatch_proc_write,
+	.proc_lseek = seq_lseek,
+	.proc_release = kstackwatch_proc_release,
+};
+
+const struct ksw_config *ksw_get_config(void)
+{
+	return ksw_config;
+}
 static int __init kstackwatch_init(void)
 {
 	ksw_config = kzalloc(sizeof(*ksw_config), GFP_KERNEL);
 	if (!ksw_config)
 		return -ENOMEM;
 
+	if (!proc_create("kstackwatch", 0600, NULL, &kstackwatch_proc_ops)) {
+		pr_err("create proc kstackwatch fail");
+		kfree(ksw_config);
+		return -ENOMEM;
+	}
+
 	pr_info("module loaded\n");
 	return 0;
 }
 
 static void __exit kstackwatch_exit(void)
 {
+	remove_proc_entry("kstackwatch", NULL);
+	kfree(ksw_config->func_name);
+	kfree(ksw_config->user_input);
 	kfree(ksw_config);
 
 	pr_info("module unloaded\n");
diff --git a/mm/kstackwatch/kstackwatch.h b/mm/kstackwatch/kstackwatch.h
index a7bad207f863..983125d5cf18 100644
--- a/mm/kstackwatch/kstackwatch.h
+++ b/mm/kstackwatch/kstackwatch.h
@@ -29,4 +29,7 @@ struct ksw_config {
 	char *user_input;
 };
 
+// singleton, only modified in kernel.c
+const struct ksw_config *ksw_get_config(void);
+
 #endif /* _KSTACKWATCH_H */
-- 
2.43.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250924115124.194940-7-wangjinchao600%40gmail.com.
