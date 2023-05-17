Return-Path: <kasan-dev+bncBCXO5E6EQQFBB4E2SORQMGQELONVL3Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x440.google.com (mail-pf1-x440.google.com [IPv6:2607:f8b0:4864:20::440])
	by mail.lfdr.de (Postfix) with ESMTPS id 5B98C70689B
	for <lists+kasan-dev@lfdr.de>; Wed, 17 May 2023 14:49:54 +0200 (CEST)
Received: by mail-pf1-x440.google.com with SMTP id d2e1a72fcca58-643fdfb437asf11137507b3a.0
        for <lists+kasan-dev@lfdr.de>; Wed, 17 May 2023 05:49:54 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1684327793; cv=pass;
        d=google.com; s=arc-20160816;
        b=dwTThY0Kwmztn+QgKOsC+Lzk3FJeeVZGSuCdyMapc0jgG1O8e4F5tDvNcBNQdUO5Pc
         dPtPRkE/wBtVd+ssMs0i+nN4oi3S/ggbQt8/9cPMRQxUqLaihXRdIHNXANrh1c7ESXtO
         IC3L+2xMxbO81ktu74wtW1Q2c1GzVgWJskDvjGNoyFJVfmduxiT2acPAH1btiwi7kW81
         qzak7ijUnNlBtBpoMvqlCWAl3/sAnWAZvbbf9X6gH/dc1HUTV/wt+tnPEBLmJGpinMgK
         /ToSlBlAfOfT1/2gqkL6AvZsP29rAh9Jt3Ml0sbu7V9fwC2AzMBlJj3qyXApzABD9cME
         3Tpw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=vjgeJn48CbYYu+0alia7SAps7KcmSVShnZtGZnOE/S8=;
        b=MXeNq/PhDemnS3vYmZoPpKooh/fTyH6gzkcu9+h5UvcH+yLBt+xs+TAqcPCakz2KKu
         E+Mra0cao4eUYnUUhk4uPxZI292hWCYw/llNfGMKde0NoHCwh5ybVYeGGfmw3Exm49qR
         RZmAZiB4gTNGI4FmxOzUGHjTxCZTG3Bh7vuqhXoBJDOkW5h7N8FSNb6O/ogxUECKBtsX
         k038q4cma9eYpeSpHkWAkSl2STuWxZvuTcNj4z60ZmxMtEOCxZWt0KEfmz5tqY+AqViA
         T4uGwU8rljMOG5lILpwDzUqDyBNvVQSEKMBni4xsANecoaBVSm3rI/lqjmEngkBWRq5L
         1aJA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=dUCYVuTn;
       spf=pass (google.com: domain of arnd@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=arnd@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1684327793; x=1686919793;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=vjgeJn48CbYYu+0alia7SAps7KcmSVShnZtGZnOE/S8=;
        b=OUJGBLUIlaeiiq8lfdLjSmk5oloikr/n6z9HMbbnSEzVOfxT7SmMg030f6Mr5XYYdB
         P9TL0X0qzwPimTtuOyMxSy+waVaFmEjrdxn4myHz7zgIOLOet55TUVqRyhXnUkD17bPQ
         g5sqHze+HPFk2Z+fgHpqoQtrsxDNJvO8DHXBrrXCzizzWdQmjKGOof37pCLq+wrkuELU
         pUowyLBM8Rgk086EY7OUgboHjdl0+VSYkJdb8yEtBjxv9fuXGOgfQ9aYOoFpP1PmDAAC
         Rise+A+OL+RZ4TguFLsYBYpAaGFVoPolFiFuNyzZKnwN4AYVmuK6lcWj2GKHFr3Hchzf
         hcow==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1684327793; x=1686919793;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=vjgeJn48CbYYu+0alia7SAps7KcmSVShnZtGZnOE/S8=;
        b=kJ/k7al8XUKPmAbZ6EuTeiOIRNC4vbSxkmNhyEjoJ9qdZ4M/KkkYWsx8NAmiGw/Owr
         /y1eokoEEx7QI5LdZ7Qu/ojlQmaJNrC0FegRQUnieTxhX72+u3lwZ3wiS5f9lpINMVFF
         zpMMvzyTldwHY73RA+bFgQdGwGQpf+lANRzvfAKOVfPVVX4TSjhvpwce3ZrsDVJWomGQ
         sQNL6kQ+sM3W3WZRoyCR54WJ97p3IDUavoflpKw2vpV3gJ7KW9NYEbnCYZ/oW7lwCa9L
         zp+cNWjnfPJsEJvt/qyMYfp+/pXqUzMA9XW1Fe9U3o366WTlhnYUPaAajhCvkbVuKhjh
         3mFg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AC+VfDz5bIqM6rJkWSxISPLaPD+LqVG9e4b35arOki3eFxUhkzYcxA6B
	vOHtBTemUE73wlWUkk0pupQ=
X-Google-Smtp-Source: ACHHUZ4Iaefw1uNRW/zTVZIDLIotcvhbH+D1kNFcdxzKicPL9S3AhmpHYUN3cJhdlQ06gWGuqIRtAQ==
X-Received: by 2002:a17:90b:18a:b0:253:43af:b75f with SMTP id t10-20020a17090b018a00b0025343afb75fmr652816pjs.4.1684327792436;
        Wed, 17 May 2023 05:49:52 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:df16:b0:23c:1f9b:df20 with SMTP id
 gp22-20020a17090adf1600b0023c1f9bdf20ls18919985pjb.1.-pod-control-gmail; Wed,
 17 May 2023 05:49:51 -0700 (PDT)
X-Received: by 2002:a17:90b:46cd:b0:250:6119:6c1f with SMTP id jx13-20020a17090b46cd00b0025061196c1fmr34694581pjb.19.1684327791654;
        Wed, 17 May 2023 05:49:51 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1684327791; cv=none;
        d=google.com; s=arc-20160816;
        b=wMHD9f+dYOCmagBfA5F94pdUQcg3mwTe+CZVUIa3OVy5kRN/ZAvzhFZwvq3oZlhAj8
         izlqxHvhfA8fnjuOmb8uZQOJDYoFFaqqpf4TEo6Vo3a8VQLDduaFuLM5Kw99j80Ojf5D
         cz2PViwNunT2Bddas5fwBB47YbTpwmRdYG4yIhRK257N1C3nl7My57MJsKPx3EF4d8fw
         C/sUh3+zZXxd7qgoHHW7bkOHhtdf48wroQVI5bAtStD7G1VLlK4nC5ou9eM0b1Igzmpq
         KswJtBU1tSMKTIOghZcGUrU4GvUQuCcxD9ooLbur2Z+aeh6lFW0CnaSDINuL6l5iIgBw
         vU8A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=eaGAW5hFZoQd57dM1YBZwV9p9UPGMHofcmC8mrNVh0o=;
        b=fd+EYI1am0qI8DBohzPxQlhJAdhNqfkfDlIrTWARb7XwgUgeIiy9XsfcLCCPpZ43uk
         ZPRyMJFss6D9aWnH7mJiehBWOJzUMgLZUpr6pupjlybrRFMnMyJDniiXsyPCNPYWU/cH
         031r+qLEmLmlnNI8q8MJQdFb1IgsFZIVImdgyoW1pIaSwvNLkiS7h3cWWPbryjKUQ9B3
         dHSGgySe9l6TAGIoOJSQh2kRRbhYDIXl592yYaY83XEhbWXETrIxHXzWJjBmT5q4HQgF
         uWMSTa/+qhXc0zdeLOTFCq2U8nkPOFoBHqEXb8VoF6vpkoY6Na4QqHoPCo69z0TcBRkJ
         Hvjw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=dUCYVuTn;
       spf=pass (google.com: domain of arnd@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=arnd@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id s15-20020a17090aad8f00b0024e59d95b82si67053pjq.1.2023.05.17.05.49.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 17 May 2023 05:49:51 -0700 (PDT)
Received-SPF: pass (google.com: domain of arnd@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id 0396663B83;
	Wed, 17 May 2023 12:49:51 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id C545AC433D2;
	Wed, 17 May 2023 12:49:48 +0000 (UTC)
From: Arnd Bergmann <arnd@kernel.org>
To: kasan-dev@googlegroups.com
Cc: Arnd Bergmann <arnd@arndb.de>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Rong Tao <rongtao@cestc.cn>,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-kernel@vger.kernel.org
Subject: [PATCH] kcov: add prototypes for helper functions
Date: Wed, 17 May 2023 14:49:25 +0200
Message-Id: <20230517124944.929997-1-arnd@kernel.org>
X-Mailer: git-send-email 2.39.2
MIME-Version: 1.0
X-Original-Sender: arnd@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=dUCYVuTn;       spf=pass
 (google.com: domain of arnd@kernel.org designates 139.178.84.217 as permitted
 sender) smtp.mailfrom=arnd@kernel.org;       dmarc=pass (p=NONE sp=NONE
 dis=NONE) header.from=kernel.org
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

From: Arnd Bergmann <arnd@arndb.de>

A number of internal functions in kcov are only called from
generated code and don't technically need a declaration, but
'make W=1' warns about global symbols without a prototype:

kernel/kcov.c:199:14: error: no previous prototype for '__sanitizer_cov_trace_pc' [-Werror=missing-prototypes]
kernel/kcov.c:264:14: error: no previous prototype for '__sanitizer_cov_trace_cmp1' [-Werror=missing-prototypes]
kernel/kcov.c:270:14: error: no previous prototype for '__sanitizer_cov_trace_cmp2' [-Werror=missing-prototypes]
kernel/kcov.c:276:14: error: no previous prototype for '__sanitizer_cov_trace_cmp4' [-Werror=missing-prototypes]
kernel/kcov.c:282:14: error: no previous prototype for '__sanitizer_cov_trace_cmp8' [-Werror=missing-prototypes]
kernel/kcov.c:288:14: error: no previous prototype for '__sanitizer_cov_trace_const_cmp1' [-Werror=missing-prototypes]
kernel/kcov.c:295:14: error: no previous prototype for '__sanitizer_cov_trace_const_cmp2' [-Werror=missing-prototypes]
kernel/kcov.c:302:14: error: no previous prototype for '__sanitizer_cov_trace_const_cmp4' [-Werror=missing-prototypes]
kernel/kcov.c:309:14: error: no previous prototype for '__sanitizer_cov_trace_const_cmp8' [-Werror=missing-prototypes]
kernel/kcov.c:316:14: error: no previous prototype for '__sanitizer_cov_trace_switch' [-Werror=missing-prototypes]

Adding prototypes for these in a header solves that problem, but now
there is a mismatch between the built-in type and the prototype on
64-bit architectures because they expect some functions to take
a 64-bit 'unsigned long' argument rather than an 'unsigned long long'
u64 type:

include/linux/kcov.h:84:6: error: conflicting types for built-in function '__sanitizer_cov_trace_switch'; expected 'void(long long unsigned int,  void *)' [-Werror=builtin-declaration-mismatch]
   84 | void __sanitizer_cov_trace_switch(u64 val, u64 *cases);
      |      ^~~~~~~~~~~~~~~~~~~~~~~~~~~~

Avoid this as well with a custom type definition.

Signed-off-by: Arnd Bergmann <arnd@arndb.de>
---
 include/linux/kcov.h | 17 +++++++++++++++++
 kernel/kcov.c        |  7 ++++---
 2 files changed, 21 insertions(+), 3 deletions(-)

diff --git a/include/linux/kcov.h b/include/linux/kcov.h
index ee04256f28af..b851ba415e03 100644
--- a/include/linux/kcov.h
+++ b/include/linux/kcov.h
@@ -72,6 +72,23 @@ static inline void kcov_remote_stop_softirq(void)
 		kcov_remote_stop();
 }
 
+#ifdef CONFIG_64BIT
+typedef unsigned long kcov_u64;
+#else
+typedef unsigned long long kcov_u64;
+#endif
+
+void __sanitizer_cov_trace_pc(void);
+void __sanitizer_cov_trace_cmp1(u8 arg1, u8 arg2);
+void __sanitizer_cov_trace_cmp2(u16 arg1, u16 arg2);
+void __sanitizer_cov_trace_cmp4(u32 arg1, u32 arg2);
+void __sanitizer_cov_trace_cmp8(kcov_u64 arg1, kcov_u64 arg2);
+void __sanitizer_cov_trace_const_cmp1(u8 arg1, u8 arg2);
+void __sanitizer_cov_trace_const_cmp2(u16 arg1, u16 arg2);
+void __sanitizer_cov_trace_const_cmp4(u32 arg1, u32 arg2);
+void __sanitizer_cov_trace_const_cmp8(kcov_u64 arg1, kcov_u64 arg2);
+void __sanitizer_cov_trace_switch(kcov_u64 val, void *cases);
+
 #else
 
 static inline void kcov_task_init(struct task_struct *t) {}
diff --git a/kernel/kcov.c b/kernel/kcov.c
index ddcf4f3ca9c9..c3124f6d5536 100644
--- a/kernel/kcov.c
+++ b/kernel/kcov.c
@@ -279,7 +279,7 @@ void notrace __sanitizer_cov_trace_cmp4(u32 arg1, u32 arg2)
 }
 EXPORT_SYMBOL(__sanitizer_cov_trace_cmp4);
 
-void notrace __sanitizer_cov_trace_cmp8(u64 arg1, u64 arg2)
+void notrace __sanitizer_cov_trace_cmp8(kcov_u64 arg1, kcov_u64 arg2)
 {
 	write_comp_data(KCOV_CMP_SIZE(3), arg1, arg2, _RET_IP_);
 }
@@ -306,16 +306,17 @@ void notrace __sanitizer_cov_trace_const_cmp4(u32 arg1, u32 arg2)
 }
 EXPORT_SYMBOL(__sanitizer_cov_trace_const_cmp4);
 
-void notrace __sanitizer_cov_trace_const_cmp8(u64 arg1, u64 arg2)
+void notrace __sanitizer_cov_trace_const_cmp8(kcov_u64 arg1, kcov_u64 arg2)
 {
 	write_comp_data(KCOV_CMP_SIZE(3) | KCOV_CMP_CONST, arg1, arg2,
 			_RET_IP_);
 }
 EXPORT_SYMBOL(__sanitizer_cov_trace_const_cmp8);
 
-void notrace __sanitizer_cov_trace_switch(u64 val, u64 *cases)
+void notrace __sanitizer_cov_trace_switch(kcov_u64 val, void *arg)
 {
 	u64 i;
+	u64 *cases = arg;
 	u64 count = cases[0];
 	u64 size = cases[1];
 	u64 type = KCOV_CMP_CONST;
-- 
2.39.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230517124944.929997-1-arnd%40kernel.org.
