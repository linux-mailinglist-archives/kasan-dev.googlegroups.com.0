Return-Path: <kasan-dev+bncBD53XBUFWQDBBC7ER7DAMGQECBDKR2Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13e.google.com (mail-il1-x13e.google.com [IPv6:2607:f8b0:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id BE44DB548E4
	for <lists+kasan-dev@lfdr.de>; Fri, 12 Sep 2025 12:12:29 +0200 (CEST)
Received: by mail-il1-x13e.google.com with SMTP id e9e14a558f8ab-411db730dcasf55523965ab.0
        for <lists+kasan-dev@lfdr.de>; Fri, 12 Sep 2025 03:12:29 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757671948; cv=pass;
        d=google.com; s=arc-20240605;
        b=l0GH6NWPylZ7kSfgm2igayhpODVYj5KJYwcZI+s4gu2U+l88ToIoa0+EwKOVULJC3s
         shRy8wieih+MrARHkR5H3T3WzzrSSZMe3w9yx8LC8icvSN/VQ79WaYKbxlI6dkDOLrVl
         d9LMgfqp1PgR157ZzxgUA5eo3r9G584Avlut4Adp4tSmmdddvzSe6m6r6D0ptaHhMOxf
         1JUFUporHX7lp7ZVZT0vXM7cLBd+4CfteVDd1IPFfMtmPub1+Dg8ArQEDUCdDcG0rTB9
         hPXuf/8QAaZ1gWD5rgl8wPuvmvwqvmJ8zBDzLMs7Tb10lM1A3Z1mtfLLDqqb8xNNzv7h
         /vZQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=OXleT4ITHgtoWRW1xR4hTqm9X+XXPCuPhJbvHH8RmmA=;
        fh=XYdYQv64r9J8WdkI66DwaQH8IpnLDUj7CV2hunxpujk=;
        b=AfMG6U8IBnCLgFjqvFWls2Dk5LxhlSHDbAIUi6qMmO7Xv9tOK4s6G1p0dPCRIBWuIP
         QfDoB7ZCV5+xxgd+QzhyOBYs1+fOY/qeWKbSssOBTVk6OeoDnkSD7gsbl0ZF7aLURygg
         vMW9z53yyYFZoJqOy5e8h7yiNLgM7FdJdCALqw0CAyfdiFOo+DnHl6zqpeS1KN9CtDSn
         lK9lhDSo2eg9ednJ7o65h863p7it4kBKUTAzMb77nXbmZA9y1AGRkeUI1QQosBzSHA36
         UsdhNcjWGzLdK9q3Aljn4guLxA+wUpv/tM7EyAJ5dLF2vQjk8KMlbFYDCGTriQETvOkR
         Tj9g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=m1yb7Z+Q;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::102d as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757671948; x=1758276748; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=OXleT4ITHgtoWRW1xR4hTqm9X+XXPCuPhJbvHH8RmmA=;
        b=vLFR5usyIYSLcMXbUV8YFmjazi5L7CC3qs2Qkm+3ewbZjbLqRNBALgeqGH97RML5ep
         FobXReIz4e604eNGBxVNeHwJIWv+ynG56hcoa778gKPSqpO1wlk4GjsDSHOrciio6ThM
         zpMmtk7Sj30WdTZjiHjmBbTiP9G8lTFANEnA3d8G/Uax5XO3015kMOR/qN7WAnbT9uwt
         4BaNy6H37JUaI4HIZKhVk9Gfax2vRPf9FZ3Ony/3yLUvCncakhyKZgb0aVjUACxdhaj9
         lyX5SDsjItBjI+J06z4hpidOVIs/WnEAmZWc1Ji/aBfWfunkU9UtsskjR9/3tKnW3rBX
         Mj6w==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1757671948; x=1758276748; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=OXleT4ITHgtoWRW1xR4hTqm9X+XXPCuPhJbvHH8RmmA=;
        b=LCJA3e/tEqZUiXEk3c4B8pADP83tTdDRaKJXIniYg54sy1+6JRHwINyQu46IYQOX2x
         xSHT9644MM+lINNKktVKHWp0UYFeYGecIRapVvWqOy5V3OJZ73v5SQaQU+RAsNSovnfb
         /guvgPOhosK7XeiDRtTkMv8M8By55v/vR3pDo5jTKXBvvYIeoWgDbOnY4TeR+ZFsiDf0
         /GgIka7+oT+eAaf26f0jTsA0BxBJQLqKsSipFbS6g1bFNS4F9SEJqfZTbEl8Fap/cHjx
         /+i61AL/DAakB6npMsXBLRLP4zmPcfCuG6Axu/+mVeNrZWIKYijT9bsLBKi16Ru56z1J
         jz9w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757671948; x=1758276748;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=OXleT4ITHgtoWRW1xR4hTqm9X+XXPCuPhJbvHH8RmmA=;
        b=qyaYEIxxSRLfl2qN/voadZd5G+aQu9xIo0dvPR2r+DmU24vJWZXUrjumoQmK3lxiJb
         w9gqGDjyCcfcDjD93TeTGjZC2vShH+igZoy/3SrE5toLNoaIFk+xH1pk4ehIEe858fWJ
         WTRFg7N6oKb8x65jNmQ7fXgYOa/m33RYk0guxJs2FE7ouKsAV3RFhSe1U0+gG9+1ZAbE
         1R7RlA3+bGodSXb2o9UaU4fZeiYAib47sMSLSIl5dKuSUDtqA3NIe/aQErOk48pcFtEq
         +LxXCKgAFBXCWH1drBPfLXakBJO+pMn3e3kpkwiMBMhRVzbe+lzqVAHihBTBCVCyhMOp
         +Xcg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCX8qiCmA4jFT4UDBrVLKfhJd9a6+CzsinKBapXapBnDQvyBg8gKdYf/++Q+TfUgYmDFXXnomw==@lfdr.de
X-Gm-Message-State: AOJu0YyS3JZnQASRY8s+PKucFqPHjD4GZ5eob0Zgf2nVus/ohP35p3bS
	96CKyG3uB+g1botClufC+wFSd8HZ+6sP+49DNXGy+4a2OV5vZiEV3cg3
X-Google-Smtp-Source: AGHT+IFzStyRXEjGv7z1Bn6afkcYAUYrR4oK9t/9lBzP10ilJRQKpDedCpNzMDo07jBZAj2akpA3Vw==
X-Received: by 2002:a92:c26a:0:b0:404:47c7:fe82 with SMTP id e9e14a558f8ab-420a53af2d3mr45400875ab.29.1757671948365;
        Fri, 12 Sep 2025 03:12:28 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcaDLTg+2byvSEkQidT010XNWzCNsYAF5LrmVSQ8SQoFg==
Received: by 2002:a05:6e02:12ef:b0:41c:ba93:bf62 with SMTP id
 e9e14a558f8ab-41cc1545605ls18161905ab.0.-pod-prod-01-us; Fri, 12 Sep 2025
 03:12:27 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCV8sfMTWawHFY7qg+aQzpEzft3YDDcAsR65hOP63Z+uKa25lGx3bNAbBHp1UPun2mTREzIEcWAbPwY=@googlegroups.com
X-Received: by 2002:a05:6e02:178b:b0:41a:b66f:4e5b with SMTP id e9e14a558f8ab-4209e833e95mr40216755ab.10.1757671947272;
        Fri, 12 Sep 2025 03:12:27 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1757671947; cv=none;
        d=google.com; s=arc-20240605;
        b=iZXfGJsHr4mzTtNTsZqVpmAP74pF390NsoA+3bscw6WrHGcLdtue+y1H3nZiNtId6v
         KSjEc2edZ5JUaRhMxfHiSCAUbkdSCniW/pF+FycXbKE3p69Ifr0Ix5p+4ZhzK/scDQ5o
         gNOgr8xrYGZnPvoMEK2kEdTKejbMi02gTmA3wsXwu77rKps82+3SmgNFQR037uslPof4
         +iRrcNbKmwCDeAsM8q0vM4R+tCCXOubrbe8+pkV/4x4vA/J7LwfzXtoGsf58E8qVCMmH
         GK0Z/uPYpyq8JqvX/wOaL01Um//r3Lb8JxTkNE2z0zOQd1nR73mhCZA+cdEvH+U+SXO6
         Umwg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=Btw7JeEHjCHi0fmk72XeSdeksiIjhqX1c6woWjS/nBg=;
        fh=icKcl3K+/j6e3Wk+L4RrxPws8GeIpMFSN3xjQchaAC8=;
        b=ECLIqws1cc+uJBHqXzvV6P6RJc3R1rOMIrYnCEJ85cIS+eX9hoqlwm6wtDke46PHvo
         wTFvEj8z8wcj/rDrVg2+EKu7LozWXW1qgi9k6gIXb871voEzH9gKZiZdqnKw+ZfW2APY
         1reHgSFYC0Pb8uqQ80b5m7jxLIfnc4eMPnXj+wsxTv/+4fUZ1mnkM8d8BVWZPG8fnlxE
         l4Z/ifAy52dAlfrG6CxPu+oGR/W5nhFLETpcmKb7MVnPDmAjNHORV+KXtmWhA4lMfhfz
         DuinKAYC9bX5Fwe5fDt/UT51p9PY4XS1HPAAKNfJwXRXsD0dP1l2ksFPlg+7AyD0Xzpn
         QYhA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=m1yb7Z+Q;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::102d as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pj1-x102d.google.com (mail-pj1-x102d.google.com. [2607:f8b0:4864:20::102d])
        by gmr-mx.google.com with ESMTPS id e9e14a558f8ab-41df02f52c9si1640025ab.2.2025.09.12.03.12.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 12 Sep 2025 03:12:27 -0700 (PDT)
Received-SPF: pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::102d as permitted sender) client-ip=2607:f8b0:4864:20::102d;
Received: by mail-pj1-x102d.google.com with SMTP id 98e67ed59e1d1-329b760080fso1804640a91.1
        for <kasan-dev@googlegroups.com>; Fri, 12 Sep 2025 03:12:27 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVIJVCmJns62l1fhhQn2O7nbUj+JNU5lOQ3qxgM8cvuJMU4VTAUnkDkd3i/zjJZaqTZjXXKfrFfCl8=@googlegroups.com
X-Gm-Gg: ASbGncsvfccQCrVgETVKcP7LSGkJWr9Mdm6LT7wQ9nXW0FrABJ5nzrVc8Tm5qUOPcuf
	hH3myThzbajtfEmRag2dxxRmrPQY8DzZ5SUMi6v/mrkmoTEODWkX6TV4XSsHv/GBQQs5P/Hinmo
	PA+psXbUcDKR3zgK1xYBkOgi92mOO9DbY9BTdyr2fmX28Mg2yZBAR+2qxk0ahvsKdyrSdH0vmuh
	Bdfne5cEz3mLJwj0thDVQ+fNPTSfJWrs8Rsv4j4t7xtwhKvnhrdqGZB7VnrCJQ/1cns+ZeetE5A
	2rcA3v3fCnPxeJXH1dRcjnGX/Rkll8RJHVeQ4XUfthmSD/w/e6yTaCgnjKBu6hIFMvYaOY5ofuu
	gu3BdjVsPg1W+iMLI2pd9xkMzpOXqTvIVLyS/31YlIVY1UFXerg==
X-Received: by 2002:a17:90b:534e:b0:32b:df0e:928f with SMTP id 98e67ed59e1d1-32de4fb9a28mr2940174a91.37.1757671946347;
        Fri, 12 Sep 2025 03:12:26 -0700 (PDT)
Received: from localhost ([185.49.34.62])
        by smtp.gmail.com with ESMTPSA id d2e1a72fcca58-77607a48c19sm4972892b3a.36.2025.09.12.03.12.25
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 12 Sep 2025 03:12:25 -0700 (PDT)
From: Jinchao Wang <wangjinchao600@gmail.com>
To: Andrew Morton <akpm@linux-foundation.org>,
	Masami Hiramatsu <mhiramat@kernel.org>,
	Peter Zijlstra <peterz@infradead.org>,
	Mike Rapoport <rppt@kernel.org>,
	Alexander Potapenko <glider@google.com>,
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
Subject: [PATCH v4 06/21] mm/ksw: add singleton /proc/kstackwatch interface
Date: Fri, 12 Sep 2025 18:11:16 +0800
Message-ID: <20250912101145.465708-7-wangjinchao600@gmail.com>
X-Mailer: git-send-email 2.43.0
In-Reply-To: <20250912101145.465708-1-wangjinchao600@gmail.com>
References: <20250912101145.465708-1-wangjinchao600@gmail.com>
MIME-Version: 1.0
X-Original-Sender: wangjinchao600@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=m1yb7Z+Q;       spf=pass
 (google.com: domain of wangjinchao600@gmail.com designates
 2607:f8b0:4864:20::102d as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
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
 mm/kstackwatch/kernel.c      | 75 +++++++++++++++++++++++++++++++++++-
 mm/kstackwatch/kstackwatch.h |  3 ++
 2 files changed, 77 insertions(+), 1 deletion(-)

diff --git a/mm/kstackwatch/kernel.c b/mm/kstackwatch/kernel.c
index 1502795e02af..8e1dca45003e 100644
--- a/mm/kstackwatch/kernel.c
+++ b/mm/kstackwatch/kernel.c
@@ -3,7 +3,10 @@
 
 #include <linux/kstrtox.h>
 #include <linux/module.h>
+#include <linux/proc_fs.h>
+#include <linux/seq_file.h>
 #include <linux/string.h>
+#include <linux/uaccess.h>
 
 #include "kstackwatch.h"
 
@@ -12,6 +15,7 @@ MODULE_DESCRIPTION("Kernel Stack Watch");
 MODULE_LICENSE("GPL");
 
 static struct ksw_config *ksw_config;
+static atomic_t config_file_busy = ATOMIC_INIT(0);
 
 /*
  * Format of the configuration string:
@@ -23,7 +27,7 @@ static struct ksw_config *ksw_config;
  * - local_var_offset : offset from the stack pointer at function+ip_offset
  * - local_var_len    : length of the local variable(1,2,4,8)
  */
-static int __maybe_unused ksw_parse_config(char *buf, struct ksw_config *config)
+static int ksw_parse_config(char *buf, struct ksw_config *config)
 {
 	char *func_part, *local_var_part = NULL;
 	char *token;
@@ -92,18 +96,87 @@ static int __maybe_unused ksw_parse_config(char *buf, struct ksw_config *config)
 	return -EINVAL;
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
+	seq_printf(m, "%s\n", ksw_config->config_str);
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
 	kfree(ksw_config);
 
 	pr_info("module unloaded\n");
diff --git a/mm/kstackwatch/kstackwatch.h b/mm/kstackwatch/kstackwatch.h
index 7c595c5c24d1..277b192f80fa 100644
--- a/mm/kstackwatch/kstackwatch.h
+++ b/mm/kstackwatch/kstackwatch.h
@@ -35,4 +35,7 @@ struct ksw_config {
 	char config_str[MAX_CONFIG_STR_LEN];
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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250912101145.465708-7-wangjinchao600%40gmail.com.
