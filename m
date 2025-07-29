Return-Path: <kasan-dev+bncBDQ67ZGAXYCBB46FUTCAMGQEYFHEQVA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x837.google.com (mail-qt1-x837.google.com [IPv6:2607:f8b0:4864:20::837])
	by mail.lfdr.de (Postfix) with ESMTPS id 0C250B1538B
	for <lists+kasan-dev@lfdr.de>; Tue, 29 Jul 2025 21:37:25 +0200 (CEST)
Received: by mail-qt1-x837.google.com with SMTP id d75a77b69052e-4aeda8bf2c1sf6763021cf.2
        for <lists+kasan-dev@lfdr.de>; Tue, 29 Jul 2025 12:37:24 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1753817843; cv=pass;
        d=google.com; s=arc-20240605;
        b=GUATb41/r0+/sTq3V1bIzpyLNpU7UOabOCaTXzmuieS2x0hTzKz5Fcv9ytSOHXP2O2
         ZwTLUix5+pKICGsEdoHwyWFvFgOzzNVHcybABkNH7rrEIZShjIzuMSFR5xDnp1o+KSOF
         RiVxV0hzVXSv0GljI4otdcyn3KeC+N6l+FjiFshNk1KkbAggfv30iNZmUajbDgj5gppq
         GubKEiuxGr4uayAXWxlSDRxF7PbaYweIvxkSFEyCtKjvxCsJtDMLlHMzH5v+jaQ3hJur
         5ENI13fDN9QEPY943qrf+u3sbhvMc4Obz4M/SSeC0LYIZrPocPGO0HlMGJ5IiAbsB8nK
         9ERg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=F2m5D9wSpie//Q2vy+twLOck9/l7l2HYZ2SNUmsZoU8=;
        fh=upWKwMCpyBJbxOFLHDnfNCk8vPERJbO6NvXT5xYqgcU=;
        b=MFCo4MuodEzYZGujiz5dsubuDk8v6yOnKQUaDguc0DN63stS7eDimbGh7eLPHX/Le5
         LwR/87h1AQKLb5W2NBzM4R7MnGXfGDgOZmJj82X9nVvRsNEWjCj/Ma5Rp6MafMBBiaeS
         WA5oEs8w0KZScHPhpu0FhpOPTZMqTwj+Lnr7UFXj+3Jr/W9Bvj9P8zPJDR4j4l9BAHtw
         v5FWaK+yOPtigVo8A3mVfjij2Xaji1S2HjVAnGYaakhnPBftrinX9tnunlMeD/6EZm99
         aR+taPc/1jEvTdRQ64w8XL+gdTdZQ0vvhTtfHicVFkfRM9jNX/OevrAHZlluDDC9JNwH
         2x7A==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=DNq7ZT63;
       spf=pass (google.com: domain of 38ikjaagkcacthyplcpjnvvnsl.jvtrhzhu-klcnvvnslnyvbwz.jvt@flex--marievic.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=38iKJaAgKCacTHYPLcPJNVVNSL.JVTRHZHU-KLcNVVNSLNYVbWZ.JVT@flex--marievic.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1753817843; x=1754422643; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=F2m5D9wSpie//Q2vy+twLOck9/l7l2HYZ2SNUmsZoU8=;
        b=ig8eOu5YCsjPWeimpM+1Xn+7ww2YRiJwYGDCzNzZmcwue0zJJi3NtNgdoX8fYzGc/x
         Gu69PGp7MeQpPcr75hJ6N964VTaF9GSmb+89ljt1cUR/lDZw/5uMtrkF+YYFf3nU4fmE
         YTLs6ORBB/r8TKMOvP9RcfG7xuFUe4ZRYVkR8Q+5IBEr6b1N6FDF4CXjRkxbhy2XFKex
         BzgoTNhNcHxl7XmMLcvz41usAOLKG034VggFw4avg3stCz3s8B+VfQe7mgiJz0r42ca8
         59BxbQy3xH42SVx993nrwUiLwed/lAyJ5ul764crj3NahpTceLjq4QtTWYrH1ypZVRCO
         jC0w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1753817843; x=1754422643;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=F2m5D9wSpie//Q2vy+twLOck9/l7l2HYZ2SNUmsZoU8=;
        b=g45kvDdzS4mxxcYIDw5KwcT8XLc1MvAM4Vh6HIWO2eWlCj3YIVkZujlauC1iV1z/Cn
         Ck5p9yxZJ8ysroO4wWGYXhS8yy00D7agSD7Q63fZoYZhLvGCFehKLl5WKf+ySoeUgPhj
         0wGAT1aRIsXge6Geo21m3GZLKNGOBJwxBNMDtcB2x/05R1Pj+luyMGBf0frrFxIdifDW
         z1FF6vyPSRnHJZzM0COLj+MYWTjyQisV9HsXg9i4NSBoic+xTwGl/gdMnTfLqXINFMpt
         BKenscRs9nsqJQrjCCZ0oGN4N/VjECRAUIzTcHknA37O4LhrifsXtMSmScA1h0JEFqAe
         bAeg==
X-Forwarded-Encrypted: i=2; AJvYcCX9RvP5a8/1D4xmBAUF5NWKlPAjF67ujLRuA0rCJrmBhb54e8q15OTSnlyVlKr7khhGMGcT3w==@lfdr.de
X-Gm-Message-State: AOJu0Yz7LbMBqPI6s4zEgc4zEZpBM/BHHs2tah8HOWBe/mnfJHZ0AUZ5
	t2XHDzHNXPKP64uVQq3WGIzEoKegSPDMIHuB0OhmWpM0OVVwR78rlrOi
X-Google-Smtp-Source: AGHT+IF0qX7u/ubdZJHWoevT+RR/I4HQPkmXopWRvHW0UnFmxcE2Juw2OaHDvMjgtccQhhSqto+lqw==
X-Received: by 2002:a05:622a:1803:b0:4ab:6c5a:1fe7 with SMTP id d75a77b69052e-4aedbc88d46mr14263271cf.52.1753817843435;
        Tue, 29 Jul 2025 12:37:23 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcykQOeZyNHwEh2yUIxZec5+w4xjDCVGr9onoj+PNKq7w==
Received: by 2002:a05:622a:552:b0:4a5:a87e:51cf with SMTP id
 d75a77b69052e-4ae7bd2f607ls114593771cf.1.-pod-prod-07-us; Tue, 29 Jul 2025
 12:37:22 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUM3v/DksByVuxTj90BobIMl/jGXgc/xi9CK2GRHDolaJWKJ2n7QrhUTMYD4mab31tbtW1nRfgSAb8=@googlegroups.com
X-Received: by 2002:a05:622a:1103:b0:4a9:91b7:6b88 with SMTP id d75a77b69052e-4aedb97a76emr16342841cf.11.1753817842467;
        Tue, 29 Jul 2025 12:37:22 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1753817842; cv=none;
        d=google.com; s=arc-20240605;
        b=eZ0yntR1Nc8IHP9Of0KA37g5gz/xG2nCkzT2A+0VS+koe2ilwkjEvooE3gLoehfsFt
         hpJnrKxiCtaJ9rh5n6RHF0LSfXqok1GtA/emqtyRTtkLPQ2oN16UZbeOja5CjS93W4k7
         OmdHa8aOpW1TBd/zx+6ZfN9bVoxsHiqXpnn3APGm6jDTMCY85XaZkH3Jjj6/KxNeDepr
         9YI1t1FwOvzjQAKswpveKUcA1KCSDmZ2VXDG8n/Xm3SXa17z84bwV23N656o/7o4UhsF
         E7hm0Bnmf3CQPbdMgB+AIKj8WS140HTaCWC55wz1mXoxzAC1hrH2DalO4XTJoUqtQ1lU
         kZNQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=LOeFclXy3T+mxjPs2r95qUwInGd9f34oaUC//E5T6EQ=;
        fh=n2LqVZOU79EI+EIaN1Fa16RozX5aJjskQd58u8r8004=;
        b=IiTwdidbXf0sLu7l6Gtsl3DuQOBNayUcFSxm8l7QsqoNYcGFwJxFOQIz5vg2gisg01
         NXA11bauh1B/b/PqXe03Tgh553vJC+HlxtYxCIyseqoqm4/WZrLkYV4f4QdhgvGdo29p
         xFpI9w8bA+W5UTvpkpcI1t4TR5sgLStYxJMHcck1PNdLgo6MlUHSMBjWCODwbLGgx1qy
         wmb9vId2kBNqjI4Qw+bRNqM2GluRVM/8qCS1UWtouaGmR25B6gFMs+hW7LruP2JyRYpn
         BRAq+nM6GFcPSOfPS3Qj2buRfBho9Ku/9sOEcwhP+OtDgxQIhT3/HMfMrckb0XfZyrHS
         jCBg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=DNq7ZT63;
       spf=pass (google.com: domain of 38ikjaagkcacthyplcpjnvvnsl.jvtrhzhu-klcnvvnslnyvbwz.jvt@flex--marievic.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=38iKJaAgKCacTHYPLcPJNVVNSL.JVTRHZHU-KLcNVVNSLNYVbWZ.JVT@flex--marievic.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-qt1-x84a.google.com (mail-qt1-x84a.google.com. [2607:f8b0:4864:20::84a])
        by gmr-mx.google.com with ESMTPS id d75a77b69052e-4ae994e1312si4985161cf.3.2025.07.29.12.37.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 29 Jul 2025 12:37:22 -0700 (PDT)
Received-SPF: pass (google.com: domain of 38ikjaagkcacthyplcpjnvvnsl.jvtrhzhu-klcnvvnslnyvbwz.jvt@flex--marievic.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) client-ip=2607:f8b0:4864:20::84a;
Received: by mail-qt1-x84a.google.com with SMTP id d75a77b69052e-4ab856c0efeso199357051cf.3
        for <kasan-dev@googlegroups.com>; Tue, 29 Jul 2025 12:37:22 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXyFRVVSmJOifHOt9/X8sJCksp/pp3XM0c5IWEWO2fPbc7xmsYY4Bmqfz5FKgTgCRaHGl5tOfMPi1k=@googlegroups.com
X-Received: from qtbfh7.prod.google.com ([2002:a05:622a:5887:b0:4ab:b3a4:9650])
 (user=marievic job=prod-delivery.src-stubby-dispatcher) by
 2002:a05:622a:1906:b0:4ab:6a4c:83a2 with SMTP id d75a77b69052e-4aedbc5d048mr14740211cf.39.1753817842099;
 Tue, 29 Jul 2025 12:37:22 -0700 (PDT)
Date: Tue, 29 Jul 2025 19:36:41 +0000
In-Reply-To: <20250729193647.3410634-1-marievic@google.com>
Mime-Version: 1.0
References: <20250729193647.3410634-1-marievic@google.com>
X-Mailer: git-send-email 2.50.1.552.g942d659e1b-goog
Message-ID: <20250729193647.3410634-4-marievic@google.com>
Subject: [PATCH 3/9] kunit: Pass additional context to generate_params for
 parameterized testing
From: "'Marie Zhussupova' via kasan-dev" <kasan-dev@googlegroups.com>
To: rmoar@google.com, davidgow@google.com, shuah@kernel.org, 
	brendan.higgins@linux.dev
Cc: elver@google.com, dvyukov@google.com, lucas.demarchi@intel.com, 
	thomas.hellstrom@linux.intel.com, rodrigo.vivi@intel.com, 
	linux-kselftest@vger.kernel.org, kunit-dev@googlegroups.com, 
	kasan-dev@googlegroups.com, intel-xe@lists.freedesktop.org, 
	dri-devel@lists.freedesktop.org, linux-kernel@vger.kernel.org, 
	Marie Zhussupova <marievic@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: marievic@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=DNq7ZT63;       spf=pass
 (google.com: domain of 38ikjaagkcacthyplcpjnvvnsl.jvtrhzhu-klcnvvnslnyvbwz.jvt@flex--marievic.bounces.google.com
 designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=38iKJaAgKCacTHYPLcPJNVVNSL.JVTRHZHU-KLcNVVNSLNYVbWZ.JVT@flex--marievic.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
X-Original-From: Marie Zhussupova <marievic@google.com>
Reply-To: Marie Zhussupova <marievic@google.com>
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

To enable more complex parameterized test scenarios,
the `generate_params` function sometimes needs additional
context beyond just the previously generated parameter.
This patch modifies the `generate_params` function signature
to include an extra `struct kunit *test` argument, giving
users access to the parent kunit test's context when
generating subsequent parameters.

The `struct kunit *test` argument was added as the first parameter
to the function signature as it aligns with the convention
of other KUnit functions that accept `struct kunit *test` first.
This also mirrors the "this" or "self" reference found
in object-oriented programming languages.

Signed-off-by: Marie Zhussupova <marievic@google.com>
---
 include/kunit/test.h | 9 ++++++---
 lib/kunit/test.c     | 5 +++--
 2 files changed, 9 insertions(+), 5 deletions(-)

diff --git a/include/kunit/test.h b/include/kunit/test.h
index d8dac7efd745..4ba65dc35710 100644
--- a/include/kunit/test.h
+++ b/include/kunit/test.h
@@ -128,7 +128,8 @@ struct kunit_attributes {
 struct kunit_case {
 	void (*run_case)(struct kunit *test);
 	const char *name;
-	const void* (*generate_params)(const void *prev, char *desc);
+	const void* (*generate_params)(struct kunit *test,
+				       const void *prev, char *desc);
 	struct kunit_attributes attr;
 
 	/*
@@ -1701,7 +1702,8 @@ do {									       \
  * Define function @name_gen_params which uses @array to generate parameters.
  */
 #define KUNIT_ARRAY_PARAM(name, array, get_desc)						\
-	static const void *name##_gen_params(const void *prev, char *desc)			\
+	static const void *name##_gen_params(struct kunit *test,				\
+					     const void *prev, char *desc)			\
 	{											\
 		typeof((array)[0]) *__next = prev ? ((typeof(__next)) prev) + 1 : (array);	\
 		if (__next - (array) < ARRAY_SIZE((array))) {					\
@@ -1722,7 +1724,8 @@ do {									       \
  * Define function @name_gen_params which uses @array to generate parameters.
  */
 #define KUNIT_ARRAY_PARAM_DESC(name, array, desc_member)					\
-	static const void *name##_gen_params(const void *prev, char *desc)			\
+	static const void *name##_gen_params(struct kunit *test,				\
+					     const void *prev, char *desc)			\
 	{											\
 		typeof((array)[0]) *__next = prev ? ((typeof(__next)) prev) + 1 : (array);	\
 		if (__next - (array) < ARRAY_SIZE((array))) {					\
diff --git a/lib/kunit/test.c b/lib/kunit/test.c
index d80b5990d85d..f50ef82179c4 100644
--- a/lib/kunit/test.c
+++ b/lib/kunit/test.c
@@ -696,7 +696,7 @@ int kunit_run_tests(struct kunit_suite *suite)
 			/* Get initial param. */
 			param_desc[0] = '\0';
 			/* TODO: Make generate_params try-catch */
-			curr_param = test_case->generate_params(NULL, param_desc);
+			curr_param = test_case->generate_params(&test, NULL, param_desc);
 			test_case->status = KUNIT_SKIPPED;
 			kunit_log(KERN_INFO, &test, KUNIT_SUBTEST_INDENT KUNIT_SUBTEST_INDENT
 				  "KTAP version 1\n");
@@ -727,7 +727,8 @@ int kunit_run_tests(struct kunit_suite *suite)
 
 				/* Get next param. */
 				param_desc[0] = '\0';
-				curr_param = test_case->generate_params(curr_param, param_desc);
+				curr_param = test_case->generate_params(&test, curr_param,
+									param_desc);
 			}
 		}
 
-- 
2.50.1.552.g942d659e1b-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250729193647.3410634-4-marievic%40google.com.
