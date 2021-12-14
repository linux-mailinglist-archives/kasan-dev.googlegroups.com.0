Return-Path: <kasan-dev+bncBCS4VDMYRUNBB7VJ4SGQMGQEPKJXLKI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13c.google.com (mail-lf1-x13c.google.com [IPv6:2a00:1450:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id B099A474D8F
	for <lists+kasan-dev@lfdr.de>; Tue, 14 Dec 2021 23:04:47 +0100 (CET)
Received: by mail-lf1-x13c.google.com with SMTP id u20-20020ac24c34000000b0041fcb2ca86esf6977594lfq.0
        for <lists+kasan-dev@lfdr.de>; Tue, 14 Dec 2021 14:04:47 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1639519487; cv=pass;
        d=google.com; s=arc-20160816;
        b=ChL62wo1paZVuBiGA0zp1VzKubeRkWzr9b3M9WIvONQyE6srvlIndrNzbjFqt2KFi8
         /yfq0TpKo/wTsA8CQVbVmWj7a0ZnqwbT1vRQVz/pOmzGs50kz+6vHha/22jwjNlGUrRh
         kDzIWrufeRojgrkozV7h7HYb0UZWH4/h1ZIkltSPVmls0d/qul34UIV/Y12Gaw+1oSXX
         g/Oej9kqUoeyJczufG0qE0GnyyS1vdCUKHK8BPgxlggDzO3HmlLKi/RpMIhUWQu18rCt
         TuskPxxImScC0Of1wb58kceZF1iTVEa0f51d0pf34fylHAZWNYfvw5P1aDCkQFk2k2CR
         lyUw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=1jPiDzrhVUJYwJkkum94PL6wRHKi3RmnsqbZaSDX3y8=;
        b=WatHnacCTtuMTRukqs4FKj8krYSDOtT1BLwEb234mX+UAp3peB8qF25bk5zX8aflSg
         VIqqS7ATX6RzHzlfImDLOS5MimzLG5k962Au/STEFZeH8WFTD1e1iDtTotPbk4wlzULn
         YLWRf5B1yY9LXdFp7LHKfUwghDrKP9D1MxSISn5XTH+Whg/yeCcths5lkunB5gcTYCCf
         aC25yNp3MvUOn6P7MLXENB05QZ9+oLjL+WIyytdBUWFractl7vJVMCJCXyoUtKYWGsYX
         4kQkT0mMTQjV5fMsyPT4xDGAzSXEcIMzfqQDQBSoNgxKuYnYREuPe4eB9goR0tthikDn
         WmJw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=IdvPLAJf;
       spf=pass (google.com: domain of srs0=oav4=q7=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom="SRS0=oav4=Q7=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=1jPiDzrhVUJYwJkkum94PL6wRHKi3RmnsqbZaSDX3y8=;
        b=MmnwjaPY6W6EQcJ6fzw/TrI2yT9R40L06xer5+/iReWqDstm+vQgKTB4hfnWe53wJd
         vRtecpKYEGU6X38baNnwar/fiKaak8JVj5+jyUB9qVlbJ3WDFRpLYVj+h1rtQbUAyJCK
         VogdMYclRRLkM6c5DQVj7c96FaTvvpCgKaU0IG6myhaQS01CMvxF+lkJRtXBmROGe3PN
         bNb7M882XLBDM4FhFWIgVJBQQvK1+N/PJ8Wtq2BajGZgFpkwtDmtbiMM6BzOuDnKah0V
         YncE+4f81OCTB/qAdafU0njC0WzZPIyvD6dJ6sVIo10A/XCNah6kbXKktGGxnG5NYZVN
         LkAQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=1jPiDzrhVUJYwJkkum94PL6wRHKi3RmnsqbZaSDX3y8=;
        b=5yAmVgHrbZpvku5CwiIOUkOBqlLDH59zxLoMGZlilGmvT3tsqRng1CC3qzkGY0Knyo
         0K+uQ2mJ4hXw1kFOLYxK9tg8kb69XzNRAgVANpcX69YvwK+1Q7poWNzO2uoAN7tgLuc0
         JUeXfDlP6NNFYR9xpR1CP41GtoSLx7vCc6MsVByXdMvsAKPmmBV7MqhNxRUyZMSjn23v
         hnXL23lAWt6yxzY1vhCzlugQD9YGcu0wByPXUf3B/yle8PgS2KmtECbwOCcozvStIEnB
         Sk5cmBDK1LF2b+NLAYyaxTx09Ih507SQ/hjEDEo6P7PdqMtlKrjXGcIMcHMbWPCGLb3x
         et0w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530vN95fg+mX+oqzJA47h//zalvIif6pxI0hkGFpTAkyxYxmC6Zx
	EeXNsyjwErQ22utnbMhibtM=
X-Google-Smtp-Source: ABdhPJxpdxcLmf3RGLdkgGg2q9MJwoSQqqygeylULc9d2WIu3UfAKCWH9oM92XlIFgn9T54SLusDlg==
X-Received: by 2002:a05:6512:10d3:: with SMTP id k19mr7007982lfg.448.1639519487097;
        Tue, 14 Dec 2021 14:04:47 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:a378:: with SMTP id i24ls32876ljn.3.gmail; Tue, 14 Dec
 2021 14:04:46 -0800 (PST)
X-Received: by 2002:a2e:83cc:: with SMTP id s12mr7233433ljh.508.1639519486014;
        Tue, 14 Dec 2021 14:04:46 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1639519486; cv=none;
        d=google.com; s=arc-20160816;
        b=nCnJeaN9eZ5nSkAe6mu7gHGzY33VnTzn+G8hjurf8t9WS+AjixDbZCQwkaxK4xMkr3
         tvLX70QSBLOOAUyNvcoY03yS9djJm/yQRF97eyoOaMRUAJeTh6oMLBVDF5Z8LHCQ4Q9a
         HugCmQyn2r+a/6ocQP8wHxnx6YwHobvmZ+L6cLZpcYSRs+hnHNtPZpLkkCeMm6ahIyMR
         Wv3slKXYqTO4T5Ps7g5d/W8i/gsa4Kbj8XOLenBkkoTbqvnSBCFo2EilPgZH83uiTWWh
         Cg5/dccSLg1K6e7Vckcth2TFkdVqq7zM8ux2XeEGJh+NDCoCiVRU1A8d18XwzhUD+/KX
         Pzyw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=vlqBh3/MPyc96SohyjyBEUeSQoRiY9353YHf3zDmXvY=;
        b=g4N5UY9gbaVwlrbxqFCF0NFMi4l/+Vn953TyMe9g6Hw4DNUXqYC7GBeuVwdzh63z29
         asP4YRrNCLLRHIcfxtqeGgcwTRIzdwu7ePk9y24mq4sY4ufHFMeccMTfVFZoULfpWyP8
         qhkvCRv7LE+7RmuO5M+ValUQBSwjvkZmAuPcf9mQMOi3PVPV1gFGT2YJeKrH6sT3xlcL
         JdaW7UKUQPYxqmUqIP7myeNqkYVJvLle+B/S2xqljTaexvuEj2BnZsR+X0d5JKFKIogx
         zvMg/0hhS0ZNaBELQi2/75dscYI0jRaB2IkQfISmt+D/Hu5V6FpSkl9/GJWuxCbSXN7G
         DFkg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=IdvPLAJf;
       spf=pass (google.com: domain of srs0=oav4=q7=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom="SRS0=oav4=Q7=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id b29si2850ljf.6.2021.12.14.14.04.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 14 Dec 2021 14:04:46 -0800 (PST)
Received-SPF: pass (google.com: domain of srs0=oav4=q7=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id E85A561747;
	Tue, 14 Dec 2021 22:04:43 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 26EDBC34632;
	Tue, 14 Dec 2021 22:04:42 +0000 (UTC)
Received: by paulmck-ThinkPad-P17-Gen-1.home (Postfix, from userid 1000)
	id 7CF985C1D0D; Tue, 14 Dec 2021 14:04:41 -0800 (PST)
From: "Paul E. McKenney" <paulmck@kernel.org>
To: linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	kernel-team@fb.com,
	mingo@kernel.org
Cc: elver@google.com,
	andreyknvl@google.com,
	glider@google.com,
	dvyukov@google.com,
	cai@lca.pw,
	boqun.feng@gmail.com,
	"Paul E . McKenney" <paulmck@kernel.org>
Subject: [PATCH kcsan 18/29] x86/barriers, kcsan: Use generic instrumentation for non-smp barriers
Date: Tue, 14 Dec 2021 14:04:28 -0800
Message-Id: <20211214220439.2236564-18-paulmck@kernel.org>
X-Mailer: git-send-email 2.31.1.189.g2e36527f23
In-Reply-To: <20211214220356.GA2236323@paulmck-ThinkPad-P17-Gen-1>
References: <20211214220356.GA2236323@paulmck-ThinkPad-P17-Gen-1>
MIME-Version: 1.0
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=IdvPLAJf;       spf=pass
 (google.com: domain of srs0=oav4=q7=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org
 designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom="SRS0=oav4=Q7=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
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

From: Marco Elver <elver@google.com>

Prefix all barriers with __, now that asm-generic/barriers.h supports
defining the final instrumented version of these barriers. The change is
limited to barriers used by x86-64.

Signed-off-by: Marco Elver <elver@google.com>
Signed-off-by: Paul E. McKenney <paulmck@kernel.org>
---
 arch/x86/include/asm/barrier.h | 10 +++++-----
 1 file changed, 5 insertions(+), 5 deletions(-)

diff --git a/arch/x86/include/asm/barrier.h b/arch/x86/include/asm/barrier.h
index 3ba772a69cc8b..35389b2af88ee 100644
--- a/arch/x86/include/asm/barrier.h
+++ b/arch/x86/include/asm/barrier.h
@@ -19,9 +19,9 @@
 #define wmb() asm volatile(ALTERNATIVE("lock; addl $0,-4(%%esp)", "sfence", \
 				       X86_FEATURE_XMM2) ::: "memory", "cc")
 #else
-#define mb() 	asm volatile("mfence":::"memory")
-#define rmb()	asm volatile("lfence":::"memory")
-#define wmb()	asm volatile("sfence" ::: "memory")
+#define __mb()	asm volatile("mfence":::"memory")
+#define __rmb()	asm volatile("lfence":::"memory")
+#define __wmb()	asm volatile("sfence" ::: "memory")
 #endif
 
 /**
@@ -51,8 +51,8 @@ static inline unsigned long array_index_mask_nospec(unsigned long index,
 /* Prevent speculative execution past this barrier. */
 #define barrier_nospec() alternative("", "lfence", X86_FEATURE_LFENCE_RDTSC)
 
-#define dma_rmb()	barrier()
-#define dma_wmb()	barrier()
+#define __dma_rmb()	barrier()
+#define __dma_wmb()	barrier()
 
 #define __smp_mb()	asm volatile("lock; addl $0,-4(%%" _ASM_SP ")" ::: "memory", "cc")
 
-- 
2.31.1.189.g2e36527f23

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211214220439.2236564-18-paulmck%40kernel.org.
