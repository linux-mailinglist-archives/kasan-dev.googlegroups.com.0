Return-Path: <kasan-dev+bncBD53XBUFWQDBBUFKT3DQMGQEXM2NGFQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103c.google.com (mail-pj1-x103c.google.com [IPv6:2607:f8b0:4864:20::103c])
	by mail.lfdr.de (Postfix) with ESMTPS id DD684BC8A44
	for <lists+kasan-dev@lfdr.de>; Thu, 09 Oct 2025 12:58:43 +0200 (CEST)
Received: by mail-pj1-x103c.google.com with SMTP id 98e67ed59e1d1-32eb2b284e4sf2607966a91.1
        for <lists+kasan-dev@lfdr.de>; Thu, 09 Oct 2025 03:58:43 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1760007505; cv=pass;
        d=google.com; s=arc-20240605;
        b=HG0TWzZb+SGXR6+qTTANLLEBO4VoIHUPMuZh99qu1oCNHcbeEsKmwr9lk1D0V9H9q0
         wZUoHoE/Mqjv0xZH0uioS/IHB0gy4OP3tDO7Mu5VnJv6rwsZgfn4aa+sEEwlc0ZedohD
         jgQ5+l5+PXKldv7jcE+ZnlO2885oDkKE5TYTuodAV5eGheeoOZKzGLBqvrdg2ObZ+IHo
         LGugPBsOh3XsJZpM8zNwrVSeuncZrlaYn4+MSZpgN6KFNLKoOPTXzj+gsvt6Hmn1jAT1
         m3vJeNSMU71oKgvgmXZtgGNIjEwB9jfWr6mpAUw8hMX+SEzGw8UnaK1/xKmusISUTsiL
         OZhw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=RoI3894HRf3egA0Bbt0Yhyi1l5I6JnNqRS4OPUmH8o4=;
        fh=owEUk53Q2vyPXzPBQeb4qf/cWZkOqhcdEm9zZgH8cOM=;
        b=XrW70Qp/aHavgKNx2UGeltOfn578YMai4aBxMozrt2ab4rqWSrmeLgUGXwfC6inVXu
         b5xW9OmlXEdN8PuvQMJVuOFsk9J8x6glmlhQPhbekW6zmBzBxeRBuiUlvopfKvevcc10
         BYShNsdzBpMgaoK66Yns5joXXOf00ZNSB8g5vALAkgXBjeobKCll9exMf9jEZc2vTHsG
         GjsC05vyot4HRZG9EUo6AM4qp+6iTH9CJfjY7d6PNSVZltrfA3CbFb1h/3ZobcsRiv76
         G0cR9HSz3BM3H1v8W/ieMc10IpWwSD0BX/n1ctdDnMn6o3bLmin+pMlZOsez26PZApRu
         +/+g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=jxkTcpXd;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::432 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1760007504; x=1760612304; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=RoI3894HRf3egA0Bbt0Yhyi1l5I6JnNqRS4OPUmH8o4=;
        b=KUn9yDcIJdTPZ3CC3bzMS8gbm8Ycq3bSWarJMFF4sFdPavrb9MKTF/HIgp/45UTWGd
         JOjn9/4RkP9jeV+Ee/+w3fbMg68bfBWemaips8q/y7pYvMj4YojuWwrmLRcjUsjYAktz
         dU0ZKmnVxw+YHgySJ6GGmPDM6uvWdEAMJn+9cOphW477CRODCeO2P+jBWGysarjRLT8E
         hP4ZN6jTv24MTGsR13GOmUAj/sJSalXUG9gm9HO2mCNwgVUY39a07GDoMNPem8Di/1bU
         fqDpYW2yImI8j7wZ/2hJH5uTtAoGqrYlOElPy5A/D+DSXwSfQhCeq4cMmPcJCyTMCM8w
         j/yA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1760007504; x=1760612304; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=RoI3894HRf3egA0Bbt0Yhyi1l5I6JnNqRS4OPUmH8o4=;
        b=HDuCl/UDmYhQA7wNEci1RxXOD49B/TX8i/PStPW/vcEQEmzIxctu3o+vJWVU9WrhU8
         pE19cDEKIFVLDG0+IlTGXYwwCh1fjbselPHqi1NSC0RQszydQ5vVf9tGR7ufoalD3Amy
         MBJMXL9bPnRkBqUBPGoStHmPd0hK463nbkxq29Nsj+NkpPjqagZX17p/1hd4f1PoRHE9
         tGwkBlvSaXBfkvs+8hWbivF3iytocHr8NhQ2MM6nml+LvcGJQSgriyioV1aOujyNk9kr
         3bg+DEeMM1Jd9bN+NVeU0MHUYd6y25HbprqUChBiCeSLzPyiiZGQid1RMEbrPOBnhuEX
         Wq7w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1760007505; x=1760612305;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=RoI3894HRf3egA0Bbt0Yhyi1l5I6JnNqRS4OPUmH8o4=;
        b=srpQ/NBkTfYN7JahWL/sUhpopber5lYt6ymjIGSJmdHwIXk24Q86PngkVP9Yxv2v38
         gN6M36r5l3zkmA6HC9aN2YVNb2/FbcmOhAmfTngIo/cO7SOGLZL5LEIq6zU4dj4Ke6Gw
         G8psX5lLtIvotCe0TjHOTeKfa3cQt68/isHi++DRjy16pmwdfIj/zKlFXq9P3swyX/dy
         k9pXP/baDg+G3AVEhkMg5PQ4UmckSsTMLuyv2eCuTJsCYc0uFvvvBWOt/zqpSdZImrQJ
         ZaD5HoGr5Uz05La8pGR0+A9/R47JdtVCxv1XDkam60GX7RdMxNe8wtq7mhclAOnu3je1
         tFxQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVyewOXI5csAHEnPFkhMiGH6lMrLj7GNKs/r+OU7vfF4kg9+ZOj+YfOxdN1NZ9SrzOmdPZhAg==@lfdr.de
X-Gm-Message-State: AOJu0YxMcAScAGaI71iIqqSzK4CjfbLuxGN6zRQvzQ+Rpo9rv3X0G+01
	X0cpq+Sx1ra4r4Vtq1qYJSFa+/CUX+Ue+K7eOdA2FYySfNdkeWxvON1S
X-Google-Smtp-Source: AGHT+IEiCOJNcuhXFZGib43OkZ9kp0DiYbBGD0/bSTlINrRLNXTkkg3WpOtX4TnksOdU3M//a5xzmw==
X-Received: by 2002:a17:90b:1806:b0:32d:db5b:7636 with SMTP id 98e67ed59e1d1-33b513cdaf5mr9124076a91.27.1760007504481;
        Thu, 09 Oct 2025 03:58:24 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="ARHlJd5R0J23Kk5CPXP3IqQlmEk5FFUq2XCAmN5hGPgI6QvGTw=="
Received: by 2002:a17:90b:112:b0:332:8779:a3d4 with SMTP id
 98e67ed59e1d1-33b5990368els833570a91.2.-pod-prod-03-us; Thu, 09 Oct 2025
 03:58:23 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCV0f4YA8ohicsCIQVk6zbcRwgixGediNSuU7lWLjCzsS5jY6DupDQPKCwho7Y7I0VGXnDSuw83myyo=@googlegroups.com
X-Received: by 2002:a17:903:94f:b0:290:26fb:2b91 with SMTP id d9443c01a7336-2902724dc96mr90895405ad.0.1760007503028;
        Thu, 09 Oct 2025 03:58:23 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1760007503; cv=none;
        d=google.com; s=arc-20240605;
        b=HaP401Ep8P1ibgMR89KgzrL6zRgAza0iRDaWKo4ObiRzKhVZYzL1ZDQZoP4UnUt03M
         NrjHvAvhSv8eMlkrx5m7YT6Exp/qWShIyP39B1C6+C5mqi7Y7I1OfHxyr7dUbMMi35ug
         BiudNim3OUjnwkcsUjBjGvvjngqlEmJu1EVao2ib15WVpORAO6v5c/KplWUeTq65TSrJ
         uXH79Ujssfc7nvhkd1BRq1gnvqEwElaYEjOIHroNGMrKcXmvP6fLNwvlivIA9azoCbSt
         LgnG+nAqI+1glY/CTseYCTdtJgCw8dpD8oFTE++s6oAzXbKyl1JaV0fFJ6i29dSVIwTa
         37Hg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=ANupiyfNlS++I01zMHP5Qbsc6Wgfn8wZLgNnwRsiWjA=;
        fh=XWJrIG4Vk0KSGFgb17O84Em+G2peB6WiRGN3NlEHGhw=;
        b=O74mS/7yyvSu+LESVrRPcmoEazq6WN5T0O8AVHh6yw2iPrXhdgdoof2fCRdsuXujsr
         2LHGoAoKkpTDyqd7DbjihAVs9omXbDpZIVPvuZKhheXuy/bTJBUf13rUAgOFIS2CHCko
         UWTutAabqJEv0/8mqrj4P/KQWn6rTdK2nrL41rXPW31I3pveOfFncWcMW3f+Bf5mOrB7
         Ourosm9Qw3VWKOPPeLXi/kORFi4Kg7n0ylPW7s+VwgWkGhua9mjW88Gc9aX0kBLeJCEd
         JSYVKo1GKoshzhqmCdBd/pgD5nW9UTKFsStRgwBlzA9hK1bB8yoVjimNm/rv2JlrEn/c
         KrAQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=jxkTcpXd;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::432 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pf1-x432.google.com (mail-pf1-x432.google.com. [2607:f8b0:4864:20::432])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-29034ec2ef7si1134915ad.5.2025.10.09.03.58.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 09 Oct 2025 03:58:23 -0700 (PDT)
Received-SPF: pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::432 as permitted sender) client-ip=2607:f8b0:4864:20::432;
Received: by mail-pf1-x432.google.com with SMTP id d2e1a72fcca58-7930132f59aso1153307b3a.0
        for <kasan-dev@googlegroups.com>; Thu, 09 Oct 2025 03:58:23 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXIoCmOfOIIapP6CNVLOyM282Mj3XwjGLFecD35JdTR9gWSOdIG15f/4UVU5nnTSLkJdF2EVj0cFVE=@googlegroups.com
X-Gm-Gg: ASbGncv8mU0VEmgocMFFgw69PhWllNzzUPojiTM4JOn+GZxQTKNvc9Mj3xNE27qLJz/
	SJPXSDqkJ9HhLmOMF6mm6J3hnwaNBSOXKbktB1O+QyOu8/ru1T9HozODqoiApgw0zesXHkotS6W
	iuYD1leBKf+GwWhJysnhNgTdiTHSaAjr6PkgHYypMqm3zGtOJTQ/TSVbO/JJrlgZJoC0/20uE0k
	dMLp1aIXKX8O1MX3YagSigITSEN0SRImbtYkmXVLNBf2CGZjOpvgFBlXHA2s/BHM4MFr9B0eAv7
	wBZWyl0mJNgjx1kP1pek0RDFBmzv/uO73+PqM4TwnKEp+mSDWC4F06dWBmejhekzvfWtRlaT1+A
	S7couxQZzLQeDrZzJOrd9reZ6/KV/t0OOxsmGwbfJi3nkHRusNwEmmxGjBkG9aiwdIA9cg30=
X-Received: by 2002:a05:6a00:2d96:b0:77f:1d7a:b97f with SMTP id d2e1a72fcca58-7938782ac68mr8582957b3a.28.1760007502437;
        Thu, 09 Oct 2025 03:58:22 -0700 (PDT)
Received: from localhost ([45.142.165.62])
        by smtp.gmail.com with ESMTPSA id d2e1a72fcca58-794e33f0cb3sm2487606b3a.78.2025.10.09.03.58.21
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 09 Oct 2025 03:58:21 -0700 (PDT)
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
Subject: [PATCH v7 19/23] mm/ksw: add recursive depth test
Date: Thu,  9 Oct 2025 18:55:55 +0800
Message-ID: <20251009105650.168917-20-wangjinchao600@gmail.com>
X-Mailer: git-send-email 2.43.0
In-Reply-To: <20251009105650.168917-1-wangjinchao600@gmail.com>
References: <20251009105650.168917-1-wangjinchao600@gmail.com>
MIME-Version: 1.0
X-Original-Sender: wangjinchao600@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=jxkTcpXd;       spf=pass
 (google.com: domain of wangjinchao600@gmail.com designates
 2607:f8b0:4864:20::432 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
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

Introduce a test that performs stack writes in recursive calls to exercise
stack watch at a specific recursion depth.

Signed-off-by: Jinchao Wang <wangjinchao600@gmail.com>
---
 mm/kstackwatch/test.c | 22 +++++++++++++++++++++-
 1 file changed, 21 insertions(+), 1 deletion(-)

diff --git a/mm/kstackwatch/test.c b/mm/kstackwatch/test.c
index 012692c97a50..203fff4bec92 100644
--- a/mm/kstackwatch/test.c
+++ b/mm/kstackwatch/test.c
@@ -18,6 +18,7 @@
 static struct dentry *test_file;
 
 #define BUFFER_SIZE 32
+#define MAX_DEPTH 6
 
 static void test_watch_fire(void)
 {
@@ -46,6 +47,21 @@ static void test_canary_overflow(void)
 	pr_info("exit of %s\n", __func__);
 }
 
+static void test_recursive_depth(int depth)
+{
+	u64 buffer[BUFFER_SIZE];
+
+	pr_info("entry of %s depth:%d\n", __func__, depth);
+
+	if (depth < MAX_DEPTH)
+		test_recursive_depth(depth + 1);
+
+	buffer[0] = depth;
+	barrier_data(buffer);
+
+	pr_info("exit of %s depth:%d\n", __func__, depth);
+}
+
 static ssize_t test_dbgfs_write(struct file *file, const char __user *buffer,
 				size_t count, loff_t *pos)
 {
@@ -71,6 +87,9 @@ static ssize_t test_dbgfs_write(struct file *file, const char __user *buffer,
 		case 1:
 			test_canary_overflow();
 			break;
+		case 2:
+			test_recursive_depth(0);
+			break;
 		default:
 			pr_err("Unknown test number %d\n", test_num);
 			return -EINVAL;
@@ -92,7 +111,8 @@ static ssize_t test_dbgfs_read(struct file *file, char __user *buffer,
 		"Usage:\n"
 		"echo test{i} > /sys/kernel/debug/kstackwatch/test\n"
 		" test0 - test watch fire\n"
-		" test1 - test canary overflow\n";
+		" test1 - test canary overflow\n"
+		" test2 - test recursive func\n";
 
 	return simple_read_from_buffer(buffer, count, ppos, usage,
 				       strlen(usage));
-- 
2.43.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251009105650.168917-20-wangjinchao600%40gmail.com.
