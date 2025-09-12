Return-Path: <kasan-dev+bncBD53XBUFWQDBBSPER7DAMGQER3BLCNA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3f.google.com (mail-qv1-xf3f.google.com [IPv6:2607:f8b0:4864:20::f3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 16329B54900
	for <lists+kasan-dev@lfdr.de>; Fri, 12 Sep 2025 12:13:31 +0200 (CEST)
Received: by mail-qv1-xf3f.google.com with SMTP id 6a1803df08f44-72e83eb8cafsf33032336d6.2
        for <lists+kasan-dev@lfdr.de>; Fri, 12 Sep 2025 03:13:31 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757672010; cv=pass;
        d=google.com; s=arc-20240605;
        b=IzYOaKhoyWdOgQhen4DhtFmnheibQ9NrqpfZf77kRQpZf+i0j2f9O/l5ap8neZk911
         Zm/cuEI7MaSfePOmfjA/YErS9KLSAvXtUNeV+9kMXDzKPbfHAqKSpl0X9PTlSgKPgcO1
         wyTJ27mNTm48AwnTvbEoj6w6Re21Gxz/jkl13iE7cLPUXr7EVdGHHCUltnzViXFFo084
         La3R4T7jVOu+0795v353o9FB89QQsrm4Zoy+YFCiGr+6qIQk1FC02d5nJl7F2BG2oXFW
         ou4AUQ+4FOkMLrP4VZ1xWR80GUO5/m1K/UKbvnDvRzyV26Z+VhhCm+ilJJu1jbaJ9Lns
         lJrg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=44QI+sKDtzZwuBuCl/nxvalgtfffANInlca2f5LWLF8=;
        fh=LkjxwkdBgJ5dGtkqpzgmZVdYKKjdoTiLVD3FsHRkzpg=;
        b=RChP3bfSVUFciLiNTSx+5BSP7FkLnvuoRuFTa2wUVsO1J+Ne5/GuslTeS8HzJXyf+N
         t2vkLTZwPSzkOno4W4cRgmazBVfBqdKP0g3Zb+oXWTDz835IBf2Q5k1/Asq1Wv7V89Oj
         ojlbMzut2BGuYBYle0zlCH9OcRGl1OS2mCDHu8lOJXXK3u8ItEVHXy2QcBjD76iOOayp
         AQ0VfKqReIRlThbmv9GvkwQ5/L0Tuyri5VhHvYysKyZM/4j9u6LOLfMG4MxBIPRCCyMh
         W7Hkb6TdFwWIATiiqDvUq068G49pZt5xyIZEyaJbXRFKs5BMcu+wIczwr2DSZ++WyeJM
         6z2g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=jCoOsI9C;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::635 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757672010; x=1758276810; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=44QI+sKDtzZwuBuCl/nxvalgtfffANInlca2f5LWLF8=;
        b=UbRAMpDQlVb6pmv6eK4ltQwbWNaohd+O54h3Ygr+iHchfN9fnh1Dn6SkhI4XZkQ/fP
         tijnU3VloioyrHdZvS9NF8yZQ0m9mH9wX1tLLdOoJ6Db1fUsOebx2RPYDOtwTG78HO5q
         9CXV0/SfXyZrYg2Bihzk2pUm8O+Fcin1YIAfncPug0npIYeGc2HzXVEUtTvK12m4stgl
         jjRa/2/X9R3/6yRMkLLyDIVI2rcEVBL8TyEqh5/okwqGQi4V0wmXSwzaQst4DN9g7xLa
         a6XnSDxMhHh/AhcNs+/txwC8A/H57L3AkTvJ7g589aJewO+nt6n//DggJOplOYgmJWa3
         XjOA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1757672010; x=1758276810; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=44QI+sKDtzZwuBuCl/nxvalgtfffANInlca2f5LWLF8=;
        b=FhcaASZj0IyBvEQQ96z2Eiu/5N18rGPRGewEq3dt345XCYbVZ4YcBjI3vrR9y1h4gH
         iuME3NzBbt3fJDUV0Sl0g6rSmap7EJFZ7PCecYoKXyZ2Af5KOa5wHjUFfI5KfwCUYRoD
         tj3oJpzziBfscGSGWKnewiGTXbp0Hl8uXmHBlGv0ue0qMl83ZDy4Lw7pRrfN5Fr+9SHG
         WtXwAQDYz0I1jo3JY8l5MNp3GVknLSVCctzm0gsevDUrcK3T0+nohbPA/thTf+ikIo4o
         ++2qgjNQqMjHDmJ9S946SIrKoSx4mE8OzV6q2U0XdKx88NL+dAFGbR5W3a0Vb/XLwjf9
         sxzw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757672010; x=1758276810;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=44QI+sKDtzZwuBuCl/nxvalgtfffANInlca2f5LWLF8=;
        b=B3hwp26XA3E2FcHyl1FO1Y3/A9VBlRTOVqmHJuAE7vFE7d/KUa9EJtFWn14jsQ6YFA
         deW2Dxs0ZHS/gczS9iAe+9/edR+lhpyqse4Ct1cWRDIjbtPnb7gxs0PQr8x8xVW7PayU
         TFXxvcSllLtYfukiETVzvdc2K87c4KyTna97PhyEe7g/ETyzEx2wyXUTaVK8bC6nk2fO
         9yRKlAO1b3oxEl+52ymgv0mz6sOBbN5GOV0lkBQd816WbVrSEqKq1vcYD4seI+hJWOp0
         jHeG7SgCT7Rp3nVKwTZd6ErSy6h70OLydE1zcx5LhCLYFbamEDy0Sk3gAyX9TAnP7vcv
         PlmA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWQRSVkA9tM4Pu6tQrCgT8f/PSwp8NNFoL+2acJ9EQvQ8gu3Q5RWpfZX2F46JnR0vZch7UlrQ==@lfdr.de
X-Gm-Message-State: AOJu0Yz2q3CGhVdf3QqpnZRjWozzAoo9jhwxtHCmCWivA38dySB2QA4O
	JNh654h36rzwBEp4Sd0aQKTCImd941n8OTgaaB3+mo4BnDeYcW4nnTgg
X-Google-Smtp-Source: AGHT+IFXC1xSz6ycBHhrLww1b19m7cDWl3na4rqJJIdLEWce92pTnVBH57DlDz3N4SZ5Uidk1QS2gA==
X-Received: by 2002:a05:6214:d83:b0:747:b0b8:307 with SMTP id 6a1803df08f44-767bb97718cmr25427386d6.26.1757672009725;
        Fri, 12 Sep 2025 03:13:29 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd657GUGpL0quy1v9DoeLvsZ6NaEEqeqswPHH/SmAg7QWg==
Received: by 2002:a05:6214:4104:b0:725:7cef:3097 with SMTP id
 6a1803df08f44-762d82e7cacls24038966d6.0.-pod-prod-03-us; Fri, 12 Sep 2025
 03:13:28 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVmdZGMyNifyG9klh3tsiQaJ43FZXsdy4MBzNHlTek/UZJQLfxFE/TdBO+5UWe/QeGBKwzyl4VZHmI=@googlegroups.com
X-Received: by 2002:a05:6214:d4f:b0:721:cbee:3a5c with SMTP id 6a1803df08f44-767c3582b4dmr30293706d6.48.1757672008790;
        Fri, 12 Sep 2025 03:13:28 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1757672008; cv=none;
        d=google.com; s=arc-20240605;
        b=brxS2aVBKUK9EBgp50y3zBUEq0wZ1+sUGLAl+mODoaWT12MWp9FiCBqyj/+c11Qj4h
         KSYonhhLzdF++2KvvGumQj7ONkihfvEaxCgITeYmxXRD3HquTFsOBQ7YQd4F1RluYPdc
         fBcXUFX/FCwT5OVFtiKJXWJqYwmeHh9sPYRUPiZ7FdUa/kqUE50DL+RVZRz8FIhxe2Ln
         cUHIJGN3cnrWon1z8He/8/yUtWOVQF9v1ZXyqZpxh1n+S2cZ7wz8M0TUP0jX11RLLqP+
         aSKGHKY+12TAl1VPRzK2dSHLm0YIGgHR3NkOA9/hXr8M5yYtsPya9+RNj3ZKL0DRkkiT
         G4jA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=C5u/a2s8j5yqiSFbkPas+Re9l+zCPojPRf0oLtuMcdk=;
        fh=ZzjuDv1D6X+vwMweYfZart771e6z8A9Nua6RNyR7Fyo=;
        b=A0mifCH7O0sjvpJ3QY4K7GNQ2OyvJAHXqnhB+4ArHpJSuiWNU7dqBPBCwKz+GmWoDq
         fim3NrxmmCESCLGc9wRabCkeb4u6usV+tpdMcV37iSvXnYiCw3C+NARnXkJcYZmCcHXg
         F9fgkCN7v5fL+RZ6bvCL0jxDLXO4wTlcecskw0D/XwPfRMTbeR9VNfLuNtSTStqSTxf0
         Nkj4R/jqi8ELPEhl0bCeO3LcGDp2+S2Xuh4cyHDIQC6wd+r4wU4cPjWQ+M70vKZ+ORZ+
         nH/k7t0Dq3V+r753GjRYmC9qqflpj3LIyfa2mTRGbE16trq88TKmMa4mWqUxH1SVWe3G
         UNhg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=jCoOsI9C;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::635 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pl1-x635.google.com (mail-pl1-x635.google.com. [2607:f8b0:4864:20::635])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-763b97136c0si1772116d6.3.2025.09.12.03.13.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 12 Sep 2025 03:13:28 -0700 (PDT)
Received-SPF: pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::635 as permitted sender) client-ip=2607:f8b0:4864:20::635;
Received: by mail-pl1-x635.google.com with SMTP id d9443c01a7336-2570bf6058aso23127235ad.0
        for <kasan-dev@googlegroups.com>; Fri, 12 Sep 2025 03:13:28 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVq3rrCpyjbY/i4Md+YQcCmPr1gvmyxOpQN58akWOTUuUHN3SWIk0+jlm5sAymoveITRiJ/YcDfeMs=@googlegroups.com
X-Gm-Gg: ASbGncs01KFlLEGMjaIJZeN5gzLzmpuWK4ArIaLLV1RQTHaP0Ppw/BwqKZ9oSB/G73q
	NuBURFxxnF9A8T5a7wMjqWMtnBrAojQPvG6f0mZQ1V4Y+urNWT70Hv/W48dUnioIB87P0jvHOoo
	uv86qfYfHCEijPGz4WX+iokQY1Ex2IRcmXIe3TAceW5yTiPWhjGc4gB1avhBO7byJ+7cPiW9thL
	GBCgmXKNREULQCXqfjzkYWk/3z5xlqd1LdQaM2Kil0uc2/AQKS+T67GKcPTuGE0tmopOrFaNNFU
	5r2+ECNlwUx/LYpW+oEX4eHMRTzNs81kfSGv3Uw4nfspr4rGSZrQVVuegsxVLTV/qY2T80Rf1t7
	7mk+w7McqLcur3WbX2EyClbk79nG3OHv9pbk=
X-Received: by 2002:a17:902:ebc2:b0:24a:ceea:b96f with SMTP id d9443c01a7336-25d24e9dc1dmr34403925ad.24.1757672007735;
        Fri, 12 Sep 2025 03:13:27 -0700 (PDT)
Received: from localhost ([185.49.34.62])
        by smtp.gmail.com with ESMTPSA id 98e67ed59e1d1-32dd9509002sm5179465a91.0.2025.09.12.03.13.26
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 12 Sep 2025 03:13:27 -0700 (PDT)
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
Subject: [PATCH v4 18/21] mm/ksw: add recursive stack corruption test
Date: Fri, 12 Sep 2025 18:11:28 +0800
Message-ID: <20250912101145.465708-19-wangjinchao600@gmail.com>
X-Mailer: git-send-email 2.43.0
In-Reply-To: <20250912101145.465708-1-wangjinchao600@gmail.com>
References: <20250912101145.465708-1-wangjinchao600@gmail.com>
MIME-Version: 1.0
X-Original-Sender: wangjinchao600@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=jCoOsI9C;       spf=pass
 (google.com: domain of wangjinchao600@gmail.com designates
 2607:f8b0:4864:20::635 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
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

Add a test that triggers stack writes across recursive calls,verifying
detection at specific recursion depths.

Signed-off-by: Jinchao Wang <wangjinchao600@gmail.com>
---
 mm/kstackwatch/test.c | 29 ++++++++++++++++++++++++++++-
 1 file changed, 28 insertions(+), 1 deletion(-)

diff --git a/mm/kstackwatch/test.c b/mm/kstackwatch/test.c
index 2b196f72ffd7..3e867d778e91 100644
--- a/mm/kstackwatch/test.c
+++ b/mm/kstackwatch/test.c
@@ -150,6 +150,27 @@ static void silent_corruption_test(void)
 		silent_corruption_victim(i);
 }
 
+/*
+ * Test Case 3: Recursive Call Corruption
+ * Test corruption detection at specified recursion depth
+ */
+static void recursive_corruption_test(int depth)
+{
+	u64 buffer[BUFFER_SIZE];
+
+	pr_info("recursive call at depth %d\n", depth);
+	pr_info("buffer 0x%lx\n", (unsigned long)buffer);
+	if (depth <= MAX_DEPTH)
+		recursive_corruption_test(depth + 1);
+
+	buffer[0] = depth;
+
+	/* make sure the compiler do not drop assign action */
+	barrier_data(buffer);
+
+	pr_info("returning from depth %d\n", depth);
+}
+
 static ssize_t test_proc_write(struct file *file, const char __user *buffer,
 			       size_t count, loff_t *pos)
 {
@@ -181,6 +202,11 @@ static ssize_t test_proc_write(struct file *file, const char __user *buffer,
 			pr_info("triggering silent corruption test\n");
 			silent_corruption_test();
 			break;
+		case 3:
+			pr_info("triggering recursive corruption test\n");
+			/* depth start with 0 */
+			recursive_corruption_test(0);
+			break;
 		default:
 			pr_err("Unknown test number %d\n", test_num);
 			return -EINVAL;
@@ -202,7 +228,8 @@ static ssize_t test_proc_read(struct file *file, char __user *buffer,
 		"Usage:\n"
 		"  echo 'test0' > /proc/kstackwatch_test  - Canary write test\n"
 		"  echo 'test1' > /proc/kstackwatch_test  - Canary overflow test\n"
-		"  echo 'test2' > /proc/kstackwatch_test  - Silent corruption test\n";
+		"  echo 'test2' > /proc/kstackwatch_test  - Silent corruption test\n"
+		"  echo 'test3' > /proc/kstackwatch_test  - Recursive corruption test\n";
 
 	return simple_read_from_buffer(buffer, count, pos, usage,
 				       strlen(usage));
-- 
2.43.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250912101145.465708-19-wangjinchao600%40gmail.com.
