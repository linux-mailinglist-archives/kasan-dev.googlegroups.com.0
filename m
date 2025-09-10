Return-Path: <kasan-dev+bncBD53XBUFWQDBBH43QTDAMGQEA3UUSNY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb39.google.com (mail-yb1-xb39.google.com [IPv6:2607:f8b0:4864:20::b39])
	by mail.lfdr.de (Postfix) with ESMTPS id 9222AB50D5F
	for <lists+kasan-dev@lfdr.de>; Wed, 10 Sep 2025 07:33:21 +0200 (CEST)
Received: by mail-yb1-xb39.google.com with SMTP id 3f1490d57ef6-e98b7088229sf8349726276.0
        for <lists+kasan-dev@lfdr.de>; Tue, 09 Sep 2025 22:33:21 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757482400; cv=pass;
        d=google.com; s=arc-20240605;
        b=QkG3sbMm62c+UGjUwTLg01lVR0leaR6ZT0Fb83s2Hh3AN32CaAy9JWTouDOKsGU8JY
         MdMHzWxaso6g++DnNaXw0CP9sd82hpvx24M0Zw/oHXS/hf6DVjPgKWlyN7+/PVq4Txsc
         DCAg+mzqoyZ9d7FIUinZMbKwxpxv5iAunDFTs2bOGMPTKldGgTQH8QU/OMYsrbtUUm3I
         EEaqT6IDtxYU3P5K17JFoW+QOArBf8s5k1kQBaaTzR9ig7w+VqFTMmmH1yF7MjRO5QoJ
         dh66zc5jA9uhBgq2+VOThRa8tiIUxaeY1ufxhKN+ZUStfgT99U0aYCzjsY2lRPlEpjbU
         6sQA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=y6UPnCIYQThU3scY5xtBDiEQA5SRiXLM+dyNVtgGMFs=;
        fh=SJPfvFGYJL+VMji9mp75/6XRmyDPCUci7lj3C+VnSQE=;
        b=iDYF43XmTd35LNcJTQBjQZo/eOU270M0atsF0NzXOvR/BUZNxpAI+OfdEx/TUzwxqI
         l8S9dyT7R2wgV0lloxT469+3u0ZG1CaLIKoLW6Jol4nSKcyrkxgB7MLJ3nPqmZde17Gv
         yhdeQ9yPVzYoFLPvbv2EqkDoG+1dqtCJ9p19l+q4tA1j3YLi3Ypcd9L2+1kt9+/+RRRL
         5INKNIU8R6zFk57OAXCmpAp4f7ZFsdfLwOJcsZKjUUsJ1gk65qYEugWFaZHLE1E+TPCX
         HVyTLCrF7k7gCOTDReogS4eJA0TNkLYvGZ8pBFb86/eFLtSIfZshtZ0jpOWfEJ7eaoDa
         s1KA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=FkU2ICAp;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::42e as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757482400; x=1758087200; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=y6UPnCIYQThU3scY5xtBDiEQA5SRiXLM+dyNVtgGMFs=;
        b=SLO+w48MIUxDckK31YJNY32qno0sH1SdXW7CK8ThMIYgjR5zS8rHXCFQ/O1w1YAAxT
         g7JNeLv4bz3Zk7SbL7J3JJBVNxNEtooiCCaOrjwyIVvGWhG8vKje4rb47zuq8wsjQWSS
         RMb9sefY5ofWP3A6SIA2mxGAJDUMu+tu0Q2RC7YXl7Oux8Z52QNRPIi7dQIvH77VawLl
         DDhoBXoRHqXkNWJ0ULFt3GwPYItJFTmXkWZzTOJbnlykCiBD2jtVwvc+egUl0HSCjMZb
         TGgCOnQIs/UCG8mRAW8Z/Es7PaLX2fpfTHtBinqkKbyi4POcDUV9LMFzuXc8/vyvK+eS
         iTmA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1757482400; x=1758087200; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=y6UPnCIYQThU3scY5xtBDiEQA5SRiXLM+dyNVtgGMFs=;
        b=MXpXMOlddpsmzhL8htM3yXkxpEguYTguNCPXBvxF1EGSoySrHa2BM2lCApsOss3bm0
         mGETpSt3XINyIajg0Azk0voQJecBYYUKCGKZjTrj46EArnkyo/Zh3+jBmELVsK5tdSOh
         dqAEOaOGid5gvQNgyEacj/BJo86mDhIlsr4a7AmpxYXkhFQXUhGF4ycsvFRuI89Ef3oV
         d/MN97CnMVrTuzRgfpVSOAKNWaVa3f5OFmQOWNNGG93HFu3/KrYEkhE1d/jybSEAYg4g
         GTp6oE6l43m9Jqt1t7pdZ1pjPWC561XswAxj5ZY04VRrth9spKyjhEjsSu4ef7nL0VbH
         Hr3w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757482400; x=1758087200;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=y6UPnCIYQThU3scY5xtBDiEQA5SRiXLM+dyNVtgGMFs=;
        b=p4kdGOMG5xChW/izV7ejVr2XftPGJ4vBHbeqkbHBiPwQvj0QM081Q8zhVA5U58+fMC
         2QXg0ZBhjOOQg7lkgizdFLfXnD6rPPdf28MaM1gt1FtxeYoq7K2vPlXWzipJrkH8tuXn
         YIu0/yjmNnfYAKU7rCEcd57wtiz4NWtJJXoi34WZNKR6InAq88Lhc9JAdzqoqQrc4WIx
         69MK7mQpvSDBgKW3WcsqiaYkOzQO0sUm/iuhlWbxw96uGm4Eh9Wio3IYdwFhOqMYdY9N
         3Kpn6c9OLf4M+6vLE31snImVRQce0KUP/rzjG5XRxSgvr4VkfSszCNoAn8ikLXxb+Oli
         p3Ew==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUzYFNJCfjBaMDnFnri79o6VWYhXoquAsA6VEeVOF+jZSlClZyyF3j4KuS24Y+ok3PcMAwvZA==@lfdr.de
X-Gm-Message-State: AOJu0YxBLhjqyjA7ZNEZ+fDsSXwp3caO/RxvmL5O4YVtUz6IiaOGNG/6
	tydSOVUKyVwMVOPf3DD/7JQHH/yT/OrO1HNR/89hASn1EpzZUnJsvAm3
X-Google-Smtp-Source: AGHT+IErNL0N68VMMESt4cGXASb7MKx/zTCyMDJCHEF7WMRl6Cty5r2f4B+h1hrqAYD08xeltSqMMw==
X-Received: by 2002:a05:6902:6109:b0:e9f:3be2:db36 with SMTP id 3f1490d57ef6-e9f688af025mr12914350276.39.1757482400243;
        Tue, 09 Sep 2025 22:33:20 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd6PJfWvUvkbm76i0eirBRedrd9YBzjQmSyNemyExO5R6Q==
Received: by 2002:a05:6902:6b04:b0:e96:db47:50f8 with SMTP id
 3f1490d57ef6-e9e06ec00bcls1560645276.0.-pod-prod-05-us; Tue, 09 Sep 2025
 22:33:19 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXmd4gx1fYzMw6FQ6IArzMCggAGA+TUV+gim+TMShGgjhhgCg+blLRMrv8P06QAmrHgqNAvWAjPbpk=@googlegroups.com
X-Received: by 2002:a05:6902:5410:b0:e97:7f7:434c with SMTP id 3f1490d57ef6-e9f68a9a23amr11835345276.44.1757482399178;
        Tue, 09 Sep 2025 22:33:19 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1757482399; cv=none;
        d=google.com; s=arc-20240605;
        b=MG9xHrKcZB5FfjQdBFXevH4pEhueTZyJhz1MMDnEyCJ9FE4xu8SvcbwyfAspvV4cFQ
         xO0iBKd/UbruvZkNVFGywVrDpspsvnGGGV/2OJsrhrPHs/4qLW7crfZkmjgiGCtCncyQ
         3KvIQT8c+tfE0xGd5GsvfZOoztiZ5cpXNNdA/dhoRlkV/IMzkeKaEUs2rj/r20DoaL8e
         GpUE7Mr4uEsRpyHDUHqyyK/MJEpYSi6Wz44jfuh30HTuQckejolUB1k2bNgzO4a/XdsZ
         Ldwmhpdw294u+UaY22OO8FccYOEDS+luX2ylu6K+XJwXzIaEpy/G9524JR9owV4fLJ4+
         vuhA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=C6BBsZfnmfgl1Jgn+pU00vd6g5c1DTmTteWqGp/Sk64=;
        fh=2afZRAoccO5u03mYBwHGJhLrEHM9eZzVj9GZxv9OX0g=;
        b=IwNEvOQ2nWNdqedPifvNdbIGAqdXfLNh/5DxDcsAmYYyHFpOGl/dnuQfAqPhVAXvRt
         SVCHy307OAvbfDotA20G15Kt0gRTHh1iqPb4Js5U5FSd0r8+WjnWXcgDkkykjjNFinSU
         vziO0vJXUcZXdHIg2hPrZ/ST3MnHNlserH3doQC9tbPhdHzn2MczvuaOUdAiuLIlyNmS
         buwYsrQ1O/41qDcBGl0beakzjp/mTyEAOrspoHly0WkI8P3WyjJq1Zhe2Tinf/qlA9H7
         mKQ5jZQpkoIVsvpAPas4EaQTyeOtEvMSp5Xo9xf8rjMSJXE15vov+I5LhjSn9f/raUuf
         MDmw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=FkU2ICAp;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::42e as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pf1-x42e.google.com (mail-pf1-x42e.google.com. [2607:f8b0:4864:20::42e])
        by gmr-mx.google.com with ESMTPS id 3f1490d57ef6-e9bd7e717f7si792939276.0.2025.09.09.22.33.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 09 Sep 2025 22:33:19 -0700 (PDT)
Received-SPF: pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::42e as permitted sender) client-ip=2607:f8b0:4864:20::42e;
Received: by mail-pf1-x42e.google.com with SMTP id d2e1a72fcca58-76e4fc419a9so5279660b3a.0
        for <kasan-dev@googlegroups.com>; Tue, 09 Sep 2025 22:33:19 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCW5VYBYlOEtIx+quyN5XCS9lfLuxIkjRjFB8vdS9A9aCM3ZP4nx1gPi8hpgidI+FrxUdSRGhzksHFw=@googlegroups.com
X-Gm-Gg: ASbGncvbOgE+ROIrFpsJRwoiC/Wrl1X7T3QG//KXJmPXQMLBJ0Egikf4uwBrD9WEoIH
	eLJYX4hHayq0rkFv6Aa8CEKYFJNykj3SVaaRtIIDzIoUQR8tqF8e5PkeRwXK4Ay3I2An6sUlgab
	LCFBSiZO6MuNspAV/L5ZYGBhqLA9LOdZLIRoZEOEKLWkRG4VMOSb1voFNwdM8qII6cMiibWwd+u
	Oevlfat0J3c1TEVoKYrNtde/uhvAveGVZiIj85NEvdxQTamSiC7WxIW2RNMtwghnzGsk3RwxFWE
	Q389PQVTKvH+tt8+L2umXa1kk7Nuxk5fm/YaqMVjxXlOBd3+WeGz3fnvwyeNoal25gmerBX9+Fm
	aLVK77XYmfsusXubc6wlwPJYq+U+jYBnJF16Be1JAp64hoegAvQ==
X-Received: by 2002:a05:6300:2189:b0:24e:3b70:978c with SMTP id adf61e73a8af0-2534756f62cmr20233577637.59.1757482398166;
        Tue, 09 Sep 2025 22:33:18 -0700 (PDT)
Received: from localhost.localdomain ([45.8.220.62])
        by smtp.gmail.com with ESMTPSA id d2e1a72fcca58-7746628ffbesm3870342b3a.66.2025.09.09.22.33.07
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 09 Sep 2025 22:33:17 -0700 (PDT)
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
Subject: [PATCH v3 15/19] mm/ksw: add stack overflow test
Date: Wed, 10 Sep 2025 13:31:13 +0800
Message-ID: <20250910053147.1152253-7-wangjinchao600@gmail.com>
X-Mailer: git-send-email 2.43.0
In-Reply-To: <20250910053147.1152253-1-wangjinchao600@gmail.com>
References: <20250910052335.1151048-1-wangjinchao600@gmail.com>
 <20250910053147.1152253-1-wangjinchao600@gmail.com>
MIME-Version: 1.0
X-Original-Sender: wangjinchao600@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=FkU2ICAp;       spf=pass
 (google.com: domain of wangjinchao600@gmail.com designates
 2607:f8b0:4864:20::42e as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
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

Extend the test module with a new test case (test1) that intentionally
overflows a local u64 buffer to corrupt the stack canary. This helps
validate detection of stack corruption under overflow conditions.

The proc interface is updated to document the new test:

 - test1: stack canary overflow test

Signed-off-by: Jinchao Wang <wangjinchao600@gmail.com>
---
 mm/kstackwatch/test.c | 28 +++++++++++++++++++++++++++-
 1 file changed, 27 insertions(+), 1 deletion(-)

diff --git a/mm/kstackwatch/test.c b/mm/kstackwatch/test.c
index 76dbfb042067..ab1a3f92b5e8 100644
--- a/mm/kstackwatch/test.c
+++ b/mm/kstackwatch/test.c
@@ -40,6 +40,27 @@ static void canary_test_write(void)
 	pr_info("canary write test completed\n");
 }
 
+/*
+ * Test Case 1: Stack Overflow (Canary Test)
+ * This function uses a u64 buffer 64-bit write
+ * to corrupt the stack canary with a single operation
+ */
+static void canary_test_overflow(void)
+{
+	u64 buffer[BUFFER_SIZE];
+
+	pr_info("starting %s\n", __func__);
+	pr_info("buffer 0x%lx\n", (unsigned long)buffer);
+
+	/* intentionally overflow the u64 buffer. */
+	((u64 *)buffer + BUFFER_SIZE)[0] = 0xdeadbeefdeadbeef;
+
+	/* make sure the compiler do not drop assign action */
+	barrier_data(buffer);
+
+	pr_info("canary overflow test completed\n");
+}
+
 static ssize_t test_proc_write(struct file *file, const char __user *buffer,
 			       size_t count, loff_t *pos)
 {
@@ -63,6 +84,10 @@ static ssize_t test_proc_write(struct file *file, const char __user *buffer,
 			pr_info("triggering canary write test\n");
 			canary_test_write();
 			break;
+		case 1:
+			pr_info("triggering canary overflow test\n");
+			canary_test_overflow();
+			break;
 		default:
 			pr_err("Unknown test number %d\n", test_num);
 			return -EINVAL;
@@ -82,7 +107,8 @@ static ssize_t test_proc_read(struct file *file, char __user *buffer,
 		"KStackWatch Simplified Test Module\n"
 		"==================================\n"
 		"Usage:\n"
-		"  echo 'test0' > /proc/kstackwatch_test  - Canary write test\n";
+		"  echo 'test0' > /proc/kstackwatch_test  - Canary write test\n"
+		"  echo 'test1' > /proc/kstackwatch_test  - Canary overflow test\n";
 
 	return simple_read_from_buffer(buffer, count, pos, usage,
 				       strlen(usage));
-- 
2.43.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250910053147.1152253-7-wangjinchao600%40gmail.com.
