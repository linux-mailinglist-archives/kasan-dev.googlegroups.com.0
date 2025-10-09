Return-Path: <kasan-dev+bncBD53XBUFWQDBBHFKT3DQMGQE2JRWTVQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x638.google.com (mail-pl1-x638.google.com [IPv6:2607:f8b0:4864:20::638])
	by mail.lfdr.de (Postfix) with ESMTPS id A7A12BC89F6
	for <lists+kasan-dev@lfdr.de>; Thu, 09 Oct 2025 12:57:34 +0200 (CEST)
Received: by mail-pl1-x638.google.com with SMTP id d9443c01a7336-286a252bfbfsf33471915ad.3
        for <lists+kasan-dev@lfdr.de>; Thu, 09 Oct 2025 03:57:34 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1760007453; cv=pass;
        d=google.com; s=arc-20240605;
        b=JQsYIAeJ8JaezDF9JM+H4H/XK7hxihk8LDTaybs7ueR1ngVmBOeVDpl8BSq9hF9kTf
         wTSxTObMXObapdVuyFZgiaDeIXEqUsK3zch5YQlpuodyrQwWVKAWe4aPcFsu6/1p+ssl
         azANP4IEXVhJmL3Lsi+krp8UOS+aW4mYo+11ZbDJKZwupobijoJhR3/X3GAJpftT7L1u
         UqhXREOAMFHCCy7KOhCInWTZm2BJ1VH6PZjShcMXLDM4M4Xxq8WRRmgy51ZbwSQ7LdiN
         Mo/3er68qh8/rBZ5huh9r2zOnbEqQwCyvcJ2OHqP3jYmvVyFrxly4LnZGLqKxSQ6+nwi
         mmOQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=IuNlONc/pMsORSPUIanWDXgqdrzij2pmo/uG2eX+hIc=;
        fh=wkk0JvowT+Jzvg8CqbmdWwMWTfI5v53dByolm/u0AIo=;
        b=fdOZxr4nMYaUldFDwe7VEzASjAQqX+aqsMH5sVZXzl5lyu5Uay/bnvTJdgUYVD3QpU
         K3YqIKRzPL70ljsTzoh5eQBeg9Mz80Foq0GPuc6TrLBThiLJ90/Q6qEaMGI/LMOLQd0k
         LR4GOcU5sDxM9tx5DXPAHFI8fs+ymAZtOiiMrijCz2LhUrJruTO67A+oi6NgvsATUdUh
         xZzF/1THUPGxHek2f23AFYHCDiDe4CIIlvvjJneATOuJ62gbhAPVnq/Rt2DfuNNwJ+ET
         yJF5nMXxJClmyJD7+ccCS34cWrdIm4agkALZUO5ju1nKQJoKovC2UzgL6qEtLwnCPdHt
         UKmg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=PI2SFazA;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::431 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1760007453; x=1760612253; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=IuNlONc/pMsORSPUIanWDXgqdrzij2pmo/uG2eX+hIc=;
        b=tPScF0j7oh3YIffQOfQ0sw3nbithrBFt4wqdgnoV4jQt7rFNCiRc+qsGPytnfvRsiZ
         Izk1Kd2nxMXwK7JahHgGbwwhGRyYtEjo4llMQYTqmBzPHVBqyQ6rxWOLHmbzoduhHqUe
         BJv3mgEl/41Btilzkvqa3tFNpen9dCmg2QnH35NVEUjx4JdC9WSxzF3pGE1lyT2uIRPq
         71KtWNw5Luhw8YXmDGGm2KOD9FLH4lRyIh1+Z+e4Fi/ZVvtoWhjMx2dMSC1T2cyKgo9P
         45vQyPxIspObpEZcaRV81/AfJhJjeRtkLbk9dtUAf+Oexo1tkCm9AlMlzl1P7glMZEm/
         11vg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1760007453; x=1760612253; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=IuNlONc/pMsORSPUIanWDXgqdrzij2pmo/uG2eX+hIc=;
        b=S7PztUvRTYZDXkkB/CFfLWNBn1PM2f6i3qMvZfDyEk2LgrFJpIDQSV/9V+tJRkkD6s
         2w17adLBMFn6BAAZzv/Jxp6DiKWtUgZqKcPgpn/Fc0Ig+INNlZ5c5rZ8Mb7ak4OlfDY5
         GT9mo+ROSijZ0DPq3/2J5K16Hlm4h+aJoEKvDf1aAih81/TNhBBkoTsXuzNYyEFaLqb5
         /KGvLSKWo32KA2GAHn7QMDG3Ht0vRvuOM8LyOGQCXWavC84zccl5Gy6dYOmYhU+//TQn
         yMvK766CvfEajAkEbJOjL52o/GrMi0sq93AhggRW64CCWDa99lPSD0oXYzNmDBiSvFcE
         gXNQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1760007453; x=1760612253;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=IuNlONc/pMsORSPUIanWDXgqdrzij2pmo/uG2eX+hIc=;
        b=rsWoTwjLiYG5d40WB5vlSJ0AZcdvjpSPvZruLoa8Nz8xCf/cU+d1Af61PoPpF/7zYG
         VWYtBQYCkYBGpKC+EZ/18DofLMiZKVVyUCrKhAUVORZazV4XG02wHDKV8pWl46kC5k9G
         D8ppgn/0KKmKhk67aTkVIwph48eg1nI8wreWuzrOjPU34Eh5Ru6Ps3iaoGfQvQ8hHMES
         jSZQHTp23cwJw9CrYn+tL7wV6j6Jl+IxBQNNh3TMH14K/KJHnfNpyc/NnDRf/S67q8NS
         SKciDDv1X3aA5sM2w/C5sZyAV/wo1/FnvWjHLHf56twiUYu9Op5nWbcaG+ybl9qpNJtr
         fVoQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWEBk4da/VFFCLgBGwAFPwKZ9GMU24wkhwVCk7UGJN7kthEgIUQ8kaMDtwIWSYCyi/ErKhndA==@lfdr.de
X-Gm-Message-State: AOJu0YwWqrzNBmMAa/1S6mGS/t1PAl8gVw3vLfBeWXINPEURAQqfjfAi
	ZRB7V4ye6P1K7oHvtl/MvCRWxnGltj1L7c3hXHUUwSMaTTCGljkMVuMa
X-Google-Smtp-Source: AGHT+IEKQA5JntGzGTRHyjPFmS8KExUOB7K/GunlQINGuEGNhCNuTm4DwiTpPsR+/eccKVqndxtPgA==
X-Received: by 2002:a17:903:1a2b:b0:26c:4fa9:64d with SMTP id d9443c01a7336-290272152dfmr93224765ad.5.1760007453065;
        Thu, 09 Oct 2025 03:57:33 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="ARHlJd5L3UG40HMnmH/o9mXtkmCu+fCcEzvWW5MmDaDwGR/KFg=="
Received: by 2002:a17:902:d512:b0:242:434e:6d22 with SMTP id
 d9443c01a7336-290356a48b4ls18065525ad.1.-pod-prod-08-us; Thu, 09 Oct 2025
 03:57:31 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXRAzRlQNVd4HV6w/nhsyVnnaBfSAFM+KH5AIvqIyCxv4H3L7xJL1CGBZNc2r6yk0/toyXA8Gyl2fk=@googlegroups.com
X-Received: by 2002:a17:903:3c2c:b0:267:a55a:8684 with SMTP id d9443c01a7336-290272159dcmr91738095ad.2.1760007451690;
        Thu, 09 Oct 2025 03:57:31 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1760007451; cv=none;
        d=google.com; s=arc-20240605;
        b=ZKy/ti0Xw8CDuQMEDGnyEhF4v/6J55U5msoNuJg7cOdYHYYYpMLFTi0ti1byC/X8Rv
         OecDdz7QiXC+UvevXLkB6EygQFBtXi2gv9RSzE8RoTerKAOykrkJMumnpLygugcDX/AY
         XOKRF9Rcomn989uiUzRhDGX/i4WJCY/hGURsiHoVUYUUOz+l/swzRtm6Y/m2facB2+Wp
         GQabMk5mU+doDAecX+bXAwG1ep+Zs+i1o76csEhUozpG6hYRGRLRDDr5xIRlDUsRBeAg
         rSD46jqqB35+0CdmCi37sN00wK0ZAQJgRZ//qMlpn8LUa9syYNFwF1CEU+NJzzxnx7Wd
         0RIA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=tH9NPPXYzjzWmBeV5TNMSRB6I94mkI1pmHDAIM87ayY=;
        fh=B8LlYgXSomL6zzsPiU+4Xgma2tHeQswqZWSCQzD2mc0=;
        b=c8Mzr9uS25ZBm7L6a2718nSJ4/nMcVrXi9Ui0OEEUChOuQdv1TUOX3WtbCacx+Lav3
         Gpk4j7wJU3o8ldKAsv/aJFLEajoHvSg59loNgDk4u8+L+ftQ72Vm1nXZvEOkWvpEUYaU
         QbftpKB0X9iM+SgI/phj0Sa1/qbyOPIS8FWZwxtpbY9GKCK3Aw++Jp0VSXTgg9ckoCIW
         uQq0fsPKbojRZG4vbrHCR/w0Lbb5Or5w8iSUucm21kwTC4iSk7aqxvzDxZ4zW4+oQrLI
         4vXJ9uZ5Juodi0t9bFz3QBf8fPe82DB3NcHaicKk28zlb+GrEOcs3iN932Ys2UdCauXm
         MRvw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=PI2SFazA;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::431 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pf1-x431.google.com (mail-pf1-x431.google.com. [2607:f8b0:4864:20::431])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-33b510d3d92si95793a91.1.2025.10.09.03.57.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 09 Oct 2025 03:57:31 -0700 (PDT)
Received-SPF: pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::431 as permitted sender) client-ip=2607:f8b0:4864:20::431;
Received: by mail-pf1-x431.google.com with SMTP id d2e1a72fcca58-7810289cd4bso802980b3a.2
        for <kasan-dev@googlegroups.com>; Thu, 09 Oct 2025 03:57:31 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWKlQney7dEEKHqCK+EKwDmIW5Ix/aSvCKzRpRKSqEp8pyOYWtBse85ph3+iCQuH9Uu3DoN04vW2s4=@googlegroups.com
X-Gm-Gg: ASbGncu4XrT/OJUwFQ6XWn0hIUdOiGTNlQysUydKWq58yr6n1WQcG6kdlGoGDTMmz15
	ccj63OeIxFR6F5Nk8b52y5tA6ngnNrLqR9M/oYZgzNnVrLcaMwc2qqG2/m95IpbuIjBBcnYaVZc
	WU1pVsA6f0LjcfgegmaE1fVHOFn42rCQaNgZgHi7+m62YUVEtRdOpS4j+vghI9inSJX24U9z+4X
	JlekDo2J0qRE70yEnNBEBCO0rKeKhQ8MZG7QuxADkE8QhbXmMpQNnnZ9KZ7lbzTRicmZ2Scre02
	EenzL6oqIbfnB2LujU0PQ4BiKDKK9E72Um5DPoVWvV5q0I+ta+kSA0nWqhJbO0lz4KmkVjAWXEq
	iZ2/O34bCXjBUlj2PbKz6t2YZRmRVmBkrIbuHTBXOZdJ3jpdFEgiGt2KwSrym
X-Received: by 2002:a05:6a00:4fd0:b0:783:7de9:d3ca with SMTP id d2e1a72fcca58-79387c1a74bmr8499688b3a.31.1760007451210;
        Thu, 09 Oct 2025 03:57:31 -0700 (PDT)
Received: from localhost ([45.142.165.62])
        by smtp.gmail.com with ESMTPSA id d2e1a72fcca58-794d4b3d866sm2531315b3a.11.2025.10.09.03.57.30
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 09 Oct 2025 03:57:30 -0700 (PDT)
From: Jinchao Wang <wangjinchao600@gmail.com>
To: Andrew Morton <akpm@linux-foundation.org>,
	Masami Hiramatsu <mhiramat@kernel.org>,
	Peter Zijlstra <peterz@infradead.org>,
	Mike Rapoport <rppt@kernel.org>,
	Alexander Potapenko <glider@google.com>,
	Randy Dunlap <rdunlap@infradead.org>,
	Marco Elver <elver@google.com>,
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
Subject: [PATCH v7 06/23] mm/ksw: add singleton debugfs interface
Date: Thu,  9 Oct 2025 18:55:42 +0800
Message-ID: <20251009105650.168917-7-wangjinchao600@gmail.com>
X-Mailer: git-send-email 2.43.0
In-Reply-To: <20251009105650.168917-1-wangjinchao600@gmail.com>
References: <20251009105650.168917-1-wangjinchao600@gmail.com>
MIME-Version: 1.0
X-Original-Sender: wangjinchao600@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=PI2SFazA;       spf=pass
 (google.com: domain of wangjinchao600@gmail.com designates
 2607:f8b0:4864:20::431 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
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

Provide the debugfs config file to read or update the configuration.
Only a single process can open this file at a time, enforced using atomic
config_file_busy, to prevent concurrent access.

ksw_get_config() exposes the configuration pointer as const.

Signed-off-by: Jinchao Wang <wangjinchao600@gmail.com>
---
 mm/kstackwatch/kernel.c      | 104 +++++++++++++++++++++++++++++++++--
 mm/kstackwatch/kstackwatch.h |   3 +
 2 files changed, 103 insertions(+), 4 deletions(-)

diff --git a/mm/kstackwatch/kernel.c b/mm/kstackwatch/kernel.c
index 3b7009033dd4..898ebb2966fe 100644
--- a/mm/kstackwatch/kernel.c
+++ b/mm/kstackwatch/kernel.c
@@ -1,13 +1,18 @@
 // SPDX-License-Identifier: GPL-2.0
 #define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
 
+#include <linux/debugfs.h>
 #include <linux/kstrtox.h>
 #include <linux/module.h>
 #include <linux/string.h>
+#include <linux/uaccess.h>
 
 #include "kstackwatch.h"
 
+static atomic_t dbgfs_config_busy = ATOMIC_INIT(0);
 static struct ksw_config *ksw_config;
+static struct dentry *dbgfs_config;
+static struct dentry *dbgfs_dir;
 
 struct param_map {
 	const char *name;       /* long name */
@@ -74,7 +79,7 @@ static int ksw_parse_param(struct ksw_config *config, const char *key,
  * - sp_offset  |so (u16) : offset from stack pointer at func_offset
  * - watch_len  |wl (u16) : watch length (1,2,4,8)
  */
-static int __maybe_unused ksw_parse_config(char *buf, struct ksw_config *config)
+static int ksw_parse_config(char *buf, struct ksw_config *config)
 {
 	char *part, *key, *val;
 	int ret;
@@ -109,20 +114,111 @@ static int __maybe_unused ksw_parse_config(char *buf, struct ksw_config *config)
 	return 0;
 }
 
+static ssize_t ksw_dbgfs_read(struct file *file, char __user *buf, size_t count,
+			      loff_t *ppos)
+{
+	return simple_read_from_buffer(buf, count, ppos, ksw_config->user_input,
+		ksw_config->user_input ? strlen(ksw_config->user_input) : 0);
+}
+
+static ssize_t ksw_dbgfs_write(struct file *file, const char __user *buffer,
+			       size_t count, loff_t *ppos)
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
+static int ksw_dbgfs_open(struct inode *inode, struct file *file)
+{
+	if (atomic_cmpxchg(&dbgfs_config_busy, 0, 1))
+		return -EBUSY;
+	return 0;
+}
+
+static int ksw_dbgfs_release(struct inode *inode, struct file *file)
+{
+	atomic_set(&dbgfs_config_busy, 0);
+	return 0;
+}
+
+static const struct file_operations kstackwatch_fops = {
+	.owner = THIS_MODULE,
+	.open = ksw_dbgfs_open,
+	.read = ksw_dbgfs_read,
+	.write = ksw_dbgfs_write,
+	.release = ksw_dbgfs_release,
+	.llseek = default_llseek,
+};
+
+const struct ksw_config *ksw_get_config(void)
+{
+	return ksw_config;
+}
+
 static int __init kstackwatch_init(void)
 {
+	int ret = 0;
+
 	ksw_config = kzalloc(sizeof(*ksw_config), GFP_KERNEL);
-	if (!ksw_config)
-		return -ENOMEM;
+	if (!ksw_config) {
+		ret = -ENOMEM;
+		goto err_alloc;
+	}
+
+	dbgfs_dir = debugfs_create_dir("kstackwatch", NULL);
+	if (!dbgfs_dir) {
+		ret = -ENOMEM;
+		goto err_dir;
+	}
+
+	dbgfs_config = debugfs_create_file("config", 0600, dbgfs_dir, NULL,
+				       &kstackwatch_fops);
+	if (!dbgfs_config) {
+		ret = -ENOMEM;
+		goto err_file;
+	}
 
 	pr_info("module loaded\n");
 	return 0;
+
+err_file:
+	debugfs_remove_recursive(dbgfs_dir);
+	dbgfs_dir = NULL;
+err_dir:
+	kfree(ksw_config);
+	ksw_config = NULL;
+err_alloc:
+	return ret;
 }
 
 static void __exit kstackwatch_exit(void)
 {
+	debugfs_remove_recursive(dbgfs_dir);
+	kfree(ksw_config->func_name);
+	kfree(ksw_config->user_input);
 	kfree(ksw_config);
-
 	pr_info("module unloaded\n");
 }
 
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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251009105650.168917-7-wangjinchao600%40gmail.com.
