Return-Path: <kasan-dev+bncBD53XBUFWQDBBNU3QTDAMGQEIX62USI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23c.google.com (mail-oi1-x23c.google.com [IPv6:2607:f8b0:4864:20::23c])
	by mail.lfdr.de (Postfix) with ESMTPS id 72A62B50D67
	for <lists+kasan-dev@lfdr.de>; Wed, 10 Sep 2025 07:33:47 +0200 (CEST)
Received: by mail-oi1-x23c.google.com with SMTP id 5614622812f47-435de8296d5sf7984711b6e.3
        for <lists+kasan-dev@lfdr.de>; Tue, 09 Sep 2025 22:33:47 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757482423; cv=pass;
        d=google.com; s=arc-20240605;
        b=XMTNqcGCBufLILC5UKAJW4dQTnpce/tjjgsateywjUgYQIPYUYWZJZHDK+L/mC1XJR
         /OCMncEh4S3Tgj9zyoc+Fv/6XuY+hfOFkJWuxBFe5ipI0GHMzS2fw9RCmUlfN+Fqjcwk
         FgVajOkQczmkRpTZFqPhcvKPHMff0qJO/MPDXAUHFBPs9/ijUamyFsSepGg8IDiRuM3l
         rVKwkGa4Yf38HhoQSRQg8mJbiX/I0IKIaQpTwUWxzWZ6rqBSocwRhGf/fc8JHVRy4qcv
         3/uq2BbpLgDca8FKxLr4tsTR+WjtVOQarOI4Zkjzz1Ygk4fX+vfxeV7lO9Ot38+3/CFA
         pLnQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=ACWrAzzxOAUXHlUpJik1cJ5JQjdPAd0mR5OeMsqw9Qg=;
        fh=OC2z4hAc1JmxERkrN8FwSnmHMEFFssT1Cjb6Q9G82kg=;
        b=UmqZOftI+q01ITsd8974gCtgBC8U8hiKjnbv2wCWdsZmaz5p+k3kV94raTvxSF+lqt
         oDIYN7FDDF/rezp/8xPcWePbXYC3Ho0G7Yfc7VKezw67zmZH4o10TIFEBSIIvBJAy3FN
         b6H/ENs85sDaqEPiraciBi+qsAnkPvmFVcvP3ZFDiHnzEm8Kp8I/J8N3b7nNIaMDOboy
         lE5Z6TGfcxjU3Fyq4BGXTR7od8S3ClEw1/2LYNBEpb4GAN+nQ8yvF1fXyF/ATLPTXyrB
         aPCKhXxrB8Zioe6ZUKoM1Lb41hCk0bE6aHjXozuUMaKGdNb9IWpPPpCRUSrYm6s3aTks
         EMlA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=P97G4L3r;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::433 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757482423; x=1758087223; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=ACWrAzzxOAUXHlUpJik1cJ5JQjdPAd0mR5OeMsqw9Qg=;
        b=FUhq/6/xgGKkAIjKXuFT2hZ+JKDEB8F97LYMI/9poe6GowiaqZ1ItCgM6NLZ2sQsrF
         TnNOVlXyM/dPZKvmB1SWgM+UkFe4/CWfmYGoLczUIEA0ROGJoBtghtX5pXrQe23GT1yz
         w0bzaoTx9T60NnVz6uQsYdYwvFhSx5nYBlmpiwTA9CiCocOo3nV0Os+GuHleGB+ATfu6
         MSa9gokcVjDTOKtnndOHhD5gRk2FHN6sp/y6fK32lJFY005Jir5DJwUkMQyQLBtRQ2+p
         MDURhpkvs9N/9lIjawywE5BMGsxZeKfc+DLWpv1piOZGhDESHvXOyKa5Ztlrt3TjOFUv
         OkFQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1757482423; x=1758087223; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=ACWrAzzxOAUXHlUpJik1cJ5JQjdPAd0mR5OeMsqw9Qg=;
        b=mizREDMi0wrxuJXqZl+0K9ICeRTQxRUZog/6IB5IXN5M3FbEJADKoYA1Y7+maQj4yS
         yiI6Vn4Aki/iDe8FfqNNfGwASR41ZP/udASBZSs3KgwOycHiCMKf0RgW1HToyEYCGbt9
         WIMB2+a97DSWE4f/j6dC/nrYfgXbDQGwzKNP7BHHia2jN/uiS+kBHyDW2mbKEY5UGqCQ
         nktSMKqZpzf4eyWSx+mwVp5/pxdruAe5UtrxFvPugU1VrVeTPcGr66s5p5Cg7LnXmetB
         C5lDylP6Ql6OtvfQuNND8WHk68exgWrQvAkpQM146whMvyN0pN/6/5RbqMRq8FO5lBTF
         MoXQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757482423; x=1758087223;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=ACWrAzzxOAUXHlUpJik1cJ5JQjdPAd0mR5OeMsqw9Qg=;
        b=mLKcWtxIi9/5SzZqse8cW3uDA0gtU28mK9C/rv+es+Pde2y2MQ7RVc1NMRkmeCaoqK
         B5qofMH3ToqmeWOxoeNipFA8KwKUNlNR0j4OvLLWCUQgiTTdKu2npLSjV0xy9jW4a3Kq
         Q3GlJm9w07LcLuimxy+1PLTEzOz52taTeXJQa3zg7i/PqBYp11NxE6IdxqWDyxp6VbK5
         UGeklEVElO4B7HNTFlq1eELASQtSlpirluEZTNO+9uLZp+qxeUTnKkTPvEDz4AzYW9F0
         T8qU5KNXSfR7OyN1BJ91sUHWryxmm0SLR8YD/2VOfmvTGa2e3vbuK5RCxv/xuVo6fr5O
         SW1A==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXlVC8S+0b9b1Yo5vqU4cxXj2jfp5aqY3FriGNm1bBo6gfKbw2+avKocD9NTx6VlK1BLnwJ0Q==@lfdr.de
X-Gm-Message-State: AOJu0YywzrLa5Ew/8pnTh5egmqDQmfdFu+9Ky+bmlA8gbKD1+p4S0eI6
	vR4QrsVE2O/bJWDn7fFfP+JRSUbqXlMl3f9G9cvwp4ogjRO+w9Lafk91
X-Google-Smtp-Source: AGHT+IFkH4jYY45qzxtU0YX9yYk3wpL4fE9p9nNkoOobA4zeGznRP8MbUYchEps632uu9pf0hDeI0Q==
X-Received: by 2002:a05:6808:1481:b0:438:1ca3:11f7 with SMTP id 5614622812f47-43b29a2c391mr7546013b6e.17.1757482423155;
        Tue, 09 Sep 2025 22:33:43 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd46V2oTqSJdVivVMKDUPWGtm72+BoXK/LA+YHZ1K8fLkg==
Received: by 2002:a05:6871:503:b0:31d:8e96:6f5e with SMTP id
 586e51a60fabf-321272207bals2114280fac.2.-pod-prod-08-us; Tue, 09 Sep 2025
 22:33:42 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVaALtng7qJCt3HGXknhHvS3Il7xj49k/BUmF2s/ilxkYSxADFZG3olhZJcllzP4RUv7QJcyS9MjPE=@googlegroups.com
X-Received: by 2002:a05:6830:6b03:b0:745:4823:df18 with SMTP id 46e09a7af769-74c77a6a78bmr8592617a34.28.1757482421946;
        Tue, 09 Sep 2025 22:33:41 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1757482421; cv=none;
        d=google.com; s=arc-20240605;
        b=NLzPm9buzGHHQtZXnOKO/474XpXp3ilKnk8ubjbo782Ki0t6e2Ck+iCtqN+kHhdWJ3
         4gZzt1rrakcjbdv3xAdHRgpVemNS29yW7G2bBzL4Gtg3eAl56XQEmTT3fhL1xDFV/LCk
         TdKzaW/r/799yf9Uqf32Wlw6p53rpV9YCCbfCFypDF67MEuBA6Qbo2prXqkRKjdEj51J
         /fNg+gtVkoT6YdI7ySVn1Nm9/skQoWpw7pxX+30ATmOGpJQpMjyS9O0EbX26jra9/GqH
         RlGR50Z5f5pWW0qpKKOcI8Ag2Sm5NxlKGtlND9j56eDo5vFAyuHJum8Ni3zO5d0e6fSR
         Kltw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=xjx9GLpO3aNSMJAiegkOcLHgHnGs8uYVGx2kXqhm4j4=;
        fh=Az73WP8MLsdkKMKQa7eEp2YZXcn/7bAchxkztQaVPbE=;
        b=Ay22zwNxzicMBl0pxpSuhmicjPLvn4EDIddyknlBR3MRhbRyB220kwWbheumgPeMYx
         MkOrOrefivZV5YI+kpl9AxG7Uwb3tFKg1PShVp1wUcQ9MMRWiHLP93WLKpIKisRJIWpZ
         sXLVW6gRS7QFsfk58yDd/GFMCa6zXB1wK3cPfZKJbNNKaAV5UwT4QoU8iFMoUHiojII4
         +bH3GUhwzNqrZytua6kgf8ViZ38WTE9jAlqRTMgjZXO7AQnRtavTF9PdvsYCLSDhjgf2
         6U6dWquWHYZBXZGPHEygxCkLmxnGXKMzooAWpA18a8GFG5XPFit20jqAUvYWMaMZHOvc
         NMew==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=P97G4L3r;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::433 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pf1-x433.google.com (mail-pf1-x433.google.com. [2607:f8b0:4864:20::433])
        by gmr-mx.google.com with ESMTPS id 46e09a7af769-74ed6219080si373290a34.2.2025.09.09.22.33.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 09 Sep 2025 22:33:41 -0700 (PDT)
Received-SPF: pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::433 as permitted sender) client-ip=2607:f8b0:4864:20::433;
Received: by mail-pf1-x433.google.com with SMTP id d2e1a72fcca58-7741991159bso5978798b3a.0
        for <kasan-dev@googlegroups.com>; Tue, 09 Sep 2025 22:33:41 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWAYYzxEJn9do3s4nTJSspqLbLm93FQcqXIPxQ9HwBVjPC0rh/Au3mnX4+Bc/2DYWrvQC4YNJb1EIQ=@googlegroups.com
X-Gm-Gg: ASbGncsvGcaRV38BaZlgToC8x7fl68ZWVbPFMEcJoAnJCDuXLs5H/lpWsvsJG+2s2YO
	rViEfzTxLbTF1K5X7hHy/X1ZLvDDOa1uyHRxNpDayZW+hc0JHRrNtL+iERbtIYrSfPUwxgkH4vV
	/pu2ntP33Zk37L4B+kqOrVySSIKh6bcdI9zMAcVZUMjar5KNaCcfe4e58qEKVhMDtOAmCerqCVW
	CAQolZL8spayhyt/MYeJIU6/KKbRpxfi2B88bHAEt/9at4XrjkeSgOMYzkHbVfoMtubqS8HDoao
	sxihU1tOmyp61+j13LwRjjGTRfLoqMbirtGk/v358x6iUB2XMpOD/nQdSPJtgZkZLmUdgMBKK/w
	Z51ibLzWtR+g2ODRmjsH/otkeNMVhxkhB3IuQRmPAe+m20NMePZghuJjvFnXO
X-Received: by 2002:aa7:8882:0:b0:771:e179:343a with SMTP id d2e1a72fcca58-7742dea0275mr22122301b3a.17.1757482421165;
        Tue, 09 Sep 2025 22:33:41 -0700 (PDT)
Received: from localhost.localdomain ([45.8.220.62])
        by smtp.gmail.com with ESMTPSA id d2e1a72fcca58-7746628ffbesm3870342b3a.66.2025.09.09.22.33.29
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 09 Sep 2025 22:33:40 -0700 (PDT)
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
Subject: [PATCH v3 17/19] mm/ksw: add recursive stack corruption test
Date: Wed, 10 Sep 2025 13:31:15 +0800
Message-ID: <20250910053147.1152253-9-wangjinchao600@gmail.com>
X-Mailer: git-send-email 2.43.0
In-Reply-To: <20250910053147.1152253-1-wangjinchao600@gmail.com>
References: <20250910052335.1151048-1-wangjinchao600@gmail.com>
 <20250910053147.1152253-1-wangjinchao600@gmail.com>
MIME-Version: 1.0
X-Original-Sender: wangjinchao600@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=P97G4L3r;       spf=pass
 (google.com: domain of wangjinchao600@gmail.com designates
 2607:f8b0:4864:20::433 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
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
index b10465381089..6a75cd3e313d 100644
--- a/mm/kstackwatch/test.c
+++ b/mm/kstackwatch/test.c
@@ -147,6 +147,27 @@ static void silent_corruption_test(void)
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
@@ -178,6 +199,11 @@ static ssize_t test_proc_write(struct file *file, const char __user *buffer,
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
@@ -199,7 +225,8 @@ static ssize_t test_proc_read(struct file *file, char __user *buffer,
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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250910053147.1152253-9-wangjinchao600%40gmail.com.
