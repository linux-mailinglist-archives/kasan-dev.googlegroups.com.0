Return-Path: <kasan-dev+bncBDQ67ZGAXYCBBJE37TCAMGQEZ7DKBJY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x637.google.com (mail-pl1-x637.google.com [IPv6:2607:f8b0:4864:20::637])
	by mail.lfdr.de (Postfix) with ESMTPS id 0A110B27E5B
	for <lists+kasan-dev@lfdr.de>; Fri, 15 Aug 2025 12:36:22 +0200 (CEST)
Received: by mail-pl1-x637.google.com with SMTP id d9443c01a7336-2445812598bsf42089415ad.2
        for <lists+kasan-dev@lfdr.de>; Fri, 15 Aug 2025 03:36:21 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755254180; cv=pass;
        d=google.com; s=arc-20240605;
        b=Pgz0y8HkQlg4kXMbAepmBX+Y9FUBRB8TKSuPALl/511G+oLanYpVs80ai72EPIw0Nz
         Iy80lwTgoPjDLh/OjPQEBknO+Y1qQGokmRLfTpQeQQn0ZDrGL6yoVomHt9FT1lse5onf
         zNir8348v9gnIaIzNQI4qwVGQDgPJSgPBg09lxM0i94eR1kKCqmSKjGLDqxl9JDglCB/
         E/EuZmoblXKjydjzGBrWNhlTnZjevg8Uc6ZhkaXY0OCx79+RmUfbYz3IKo15Wc1ZCx6s
         GRh944U9pI9i6c6py+AF8jrGqGs58ycuTpUQvVjB2Pj9+4juxDtVRfIUWUylJBfCT4gS
         6x3g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=GIuaKChE80dfY5gtOIUCkGG2tKJ9xw+yJpbc5R2bzfg=;
        fh=VKcENfHGdRWqoQU9kPfbCxB823drIABh4xKvIe+4jdA=;
        b=YwZNx4TIEuTDzcHRBYA1J2Qz5W6TBFELimWWJrEbbnxGAySJp5P7cXDFAsHnizc0WU
         lP+Grk9M6LMdzKjemC9KxD5WEgNSMdmhCfsZjfOXEQ6TiTnFNW6tOClaYyZdVyueSfYA
         HcEKut9DeynCf3LnlOSooGwGe0gk8l+LCJii9oH7HqQTGvFFLzR7t12Oi67RLIsBwDs+
         0r9Ipvln2BPhN4CsW3Yt1VlxoS/fbg7wceoPEfsmD0kuB+Fr6FAyo1jlV01m0mbsfeuZ
         G5/h8O0iV1xej5eiw0ql3UbLuckQ9b6q35nVLXFHSSWWAs62f8q50/xoeQs8M6t9if7u
         xsAA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="d6wVQ1/o";
       spf=pass (google.com: domain of 3og2faagkcyuvj0rn4rlpxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--marievic.bounces.google.com designates 2607:f8b0:4864:20::e4a as permitted sender) smtp.mailfrom=3og2faAgKCYUvj0rn4rlpxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--marievic.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755254180; x=1755858980; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=GIuaKChE80dfY5gtOIUCkGG2tKJ9xw+yJpbc5R2bzfg=;
        b=FmLTBI9BITrzMfWHEdksx6ecOVwND4+SKCwf2M93Nm/Fl4Geod9rizajuw7QcMtMV/
         dfzHApumBLL7gkgEWMAOKF3aCZ7Ad/HcymxiQzFpBZ7eUnv88YeNVZVApeoNDITnqA+N
         GW6XE4sHL/4Ba840N+WaOfuC6zspEVews3ZkZC1TnpZsNejUJn6K5IC04YVhOKDUUgmE
         EUuZutzJPSwCdPJowyQrhajcmDDnppXzRYgZbBU72hwt+KWsK8+84Njmgu6sGNODHG7i
         mSWrSMZ5hV9bk0nf4WmbXoay94uHbTnlc1Wz/iDZx88xbm1fxYzKnO2Yws4OkOKOBHdX
         tZhw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755254180; x=1755858980;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=GIuaKChE80dfY5gtOIUCkGG2tKJ9xw+yJpbc5R2bzfg=;
        b=aBsACL7oIq1e+WUA19gTmu/ZLIw5RX6tBLhJNKZ0WOSpkrs9N1SPhH6porZfKtd+Rj
         bh8JQxA1PW2B8NVYgaW1JVWO0ATlt9oWDR7s0kUrmBa0/zgoh4UIN4fd9n6cqxbNJPMy
         OOMANUj/CLz+MZu2pTKfWuC74BDidh4xqNn47RSTLqvtYe1JzLzzKSUYyt9QPeNgk2tX
         QOfOfIZ/iIf7QC1PdbZtEIEpbfS3o5zP2J5WEFrwAmb/hWur0jv1RqlW+B6j/+xtQIN5
         VQn40mOG+vbKBAF2lJVRU042hEJY602eUA5WAD/hNh9L1WWGXU+kvLDKc+Xqap0mxP1L
         fh+A==
X-Forwarded-Encrypted: i=2; AJvYcCVy41x7+cb5yNGX5ozyejR9sjthsYlwbTd7mChXOJ7mWFzJfWQIjjbPL5l/iXZpmJls86gkiA==@lfdr.de
X-Gm-Message-State: AOJu0YzLn5jZXsYT6+DGeAzfkU12m8OH7nhIJ7iW6aY85tfiWGfrnc9K
	9/iydCGqj0FuTBclm/YvQCuMI1sW8JJ+a7T6gb7JVuo+mptLCjqY0nyz
X-Google-Smtp-Source: AGHT+IEMxTuj1hhXJ/XZPI04BN+5hq4ZxlkRxhY10QRu+MVYDt0oDmY0reUWM8HLyKTxL0eskGK6Iw==
X-Received: by 2002:a17:902:f641:b0:240:8262:1a46 with SMTP id d9443c01a7336-2446d725e08mr20189815ad.25.1755254180389;
        Fri, 15 Aug 2025 03:36:20 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZeXeRajrhkadPMuBscfiWf7/kOvRQzgFC78tMdAOL7VnQ==
Received: by 2002:a17:902:e0c3:b0:240:38f1:5c80 with SMTP id
 d9443c01a7336-2445760b12bls14827425ad.2.-pod-prod-06-us; Fri, 15 Aug 2025
 03:36:19 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUye9MiJMWn+nep1fnRzsFK5eZSzlS1TGvD0Io4ahgfj6zHhrftEzA79H3iPTVlOB4jci0G21cmGQU=@googlegroups.com
X-Received: by 2002:a17:903:2a8f:b0:234:d292:be95 with SMTP id d9443c01a7336-2446d8e4a18mr20474865ad.42.1755254179110;
        Fri, 15 Aug 2025 03:36:19 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755254179; cv=none;
        d=google.com; s=arc-20240605;
        b=WcJhpjwG916HWM3j6axW17sbU70Se/Lkg0DAL1bJJJK9i0KtbvnfrlSliBI5pEOe3t
         kAn5N4wmfu7Tliteo/PA5QhVupMmlMrSCKo28B1xMJMX/iPXuQBr+D+Xb+DRuthUXbDA
         htNecuxQ3GqBYKUo7/C/4YfwShpQCRagJfJn2buc00PyYV1+F+aZ8dLS/kPVhIhjIJrp
         RYWbF3FjrChNeTNBKG3y+D85s//5qgZ6KVcjeyUway6lSwsWKCQh39YCk9+F5D/tbubM
         Ki7TQEZDPGU260OInJE72qsL5VOL/JIKPw7qkfy/t0BVZeO3pYTLo0DEfWcTevbK/OIq
         l2rw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=EbtD+Xjrb63N9PWKLbZO8o0el647SMdtXD5thCMFX0c=;
        fh=9MeXifk6so/NhJwctxURkIm89ey6KvX5lSqplgkPEmI=;
        b=Or11idaurSKPmlJoD+7XRPDz+sIUwcttm4C2QdIMSXgUe0JPR7H65HMdzODc5IVFro
         UATmDN0da73Gn1HzIkjHz59N+kDyhhGK3InszCjKEMzWWYefH1SxorjGBQt20KC9hf+N
         2tEmWYR74puYqg8K5Flva+3q17R5gmyvqgmUS0PpNcs+ybG+4m1CXH9RxfTYCF5oBaKO
         LFAg9lScCOV9ExYMjdn9soBAGWbqUrailfXjpWTeKbMaYZy/OxHKTFWZfFwf/agqjZWH
         +E5uyVCmw3T3e8qMJyfO1AYhN6hQPXxNOy/9CYjtoG8+xuRHmM71y+gKcnTG4SYQSxf9
         7mkw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="d6wVQ1/o";
       spf=pass (google.com: domain of 3og2faagkcyuvj0rn4rlpxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--marievic.bounces.google.com designates 2607:f8b0:4864:20::e4a as permitted sender) smtp.mailfrom=3og2faAgKCYUvj0rn4rlpxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--marievic.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-vs1-xe4a.google.com (mail-vs1-xe4a.google.com. [2607:f8b0:4864:20::e4a])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-2446cb74d04si357235ad.1.2025.08.15.03.36.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 15 Aug 2025 03:36:19 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3og2faagkcyuvj0rn4rlpxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--marievic.bounces.google.com designates 2607:f8b0:4864:20::e4a as permitted sender) client-ip=2607:f8b0:4864:20::e4a;
Received: by mail-vs1-xe4a.google.com with SMTP id ada2fe7eead31-50f85ea631bso3288636137.0
        for <kasan-dev@googlegroups.com>; Fri, 15 Aug 2025 03:36:19 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVcm1tvrzeC/OD6oISNPhFnaVRtudyz998bLFh2zKYpWlufuNLSrrq0tuJRm1ihzoGgM2nJ951YRwI=@googlegroups.com
X-Received: from vsp19-n2.prod.google.com ([2002:a05:6102:40d3:20b0:512:29bc:e5ed])
 (user=marievic job=prod-delivery.src-stubby-dispatcher) by
 2002:a05:6102:6cc:b0:4e5:f673:7da4 with SMTP id ada2fe7eead31-5126b10f139mr343801137.8.1755254178131;
 Fri, 15 Aug 2025 03:36:18 -0700 (PDT)
Date: Fri, 15 Aug 2025 10:36:01 +0000
In-Reply-To: <20250815103604.3857930-1-marievic@google.com>
Mime-Version: 1.0
References: <20250815103604.3857930-1-marievic@google.com>
X-Mailer: git-send-email 2.51.0.rc1.167.g924127e9c0-goog
Message-ID: <20250815103604.3857930-5-marievic@google.com>
Subject: [PATCH v3 4/7] kunit: Enable direct registration of parameter arrays
 to a KUnit test
From: "'Marie Zhussupova' via kasan-dev" <kasan-dev@googlegroups.com>
To: rmoar@google.com, davidgow@google.com, shuah@kernel.org, 
	brendan.higgins@linux.dev
Cc: mark.rutland@arm.com, elver@google.com, dvyukov@google.com, 
	lucas.demarchi@intel.com, thomas.hellstrom@linux.intel.com, 
	rodrigo.vivi@intel.com, linux-kselftest@vger.kernel.org, 
	kunit-dev@googlegroups.com, kasan-dev@googlegroups.com, 
	intel-xe@lists.freedesktop.org, dri-devel@lists.freedesktop.org, 
	linux-kernel@vger.kernel.org, Marie Zhussupova <marievic@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: marievic@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b="d6wVQ1/o";       spf=pass
 (google.com: domain of 3og2faagkcyuvj0rn4rlpxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--marievic.bounces.google.com
 designates 2607:f8b0:4864:20::e4a as permitted sender) smtp.mailfrom=3og2faAgKCYUvj0rn4rlpxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--marievic.bounces.google.com;
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

KUnit parameterized tests currently support two primary methods f
or getting parameters:
1.  Defining custom logic within a generate_params() function.
2.  Using the KUNIT_ARRAY_PARAM() and KUNIT_ARRAY_PARAM_DESC()
    macros with a pre-defined static array and passing
    the created *_gen_params() to KUNIT_CASE_PARAM().

These methods present limitations when dealing with dynamically
generated parameter arrays, or in scenarios where populating parameters
sequentially via generate_params() is inefficient or overly complex.

This patch addresses these limitations by adding a new `params_array`
field to `struct kunit`, of the type `kunit_params`. The
`struct kunit_params` is designed to store the parameter array itself,
along with essential metadata including the parameter count, parameter
size, and a get_description() function for providing custom descriptions
for individual parameters.

The `params_array` field can be populated by calling the new
kunit_register_params_array() macro from within a param_init() function.
This will register the array as part of the parameterized test context.
The user will then need to pass kunit_array_gen_params() to the
KUNIT_CASE_PARAM_WITH_INIT() macro as the generator function, if not
providing their own. kunit_array_gen_params() is a KUnit helper that will
use the registered array to generate parameters.

The arrays passed to KUNIT_ARRAY_PARAM(,DESC) will also be registered to
the parameterized test context for consistency as well as for higher
availability of the parameter count that will be used for outputting a KTAP
test plan for a parameterized test.

This modification provides greater flexibility to the KUnit framework,
allowing  testers to easily register and utilize both dynamic and static
parameter arrays.

Reviewed-by: David Gow <davidgow@google.com>
Signed-off-by: Marie Zhussupova <marievic@google.com>
---

Changes in v3:
v2: https://lore.kernel.org/all/20250811221739.2694336-5-marievic@google.com/
- Commit message formatting.

Changes in v2:
v1: https://lore.kernel.org/all/20250729193647.3410634-7-marievic@google.com/
- If the parameter count is available for a parameterized test, the
  kunit_run_tests() function will now output the KTAP test plan for it.
- The name of the struct kunit_params field in struct kunit was changed
  from params_data to params_array. This name change better reflects its
  purpose, which is to encapsulate both the parameter array and its
  associated metadata.
- The name of `kunit_get_next_param_and_desc` was changed to
  `kunit_array_gen_params` to make it simpler and to better fit its purpose
  of being KUnit's built-in generator function that uses arrays to generate
  parameters.
- The signature of get_description() in `struct params_array` was changed to
  accept the parameterized test context, as well. This way test users can
  potentially use information available in the parameterized test context,
  such as the parameterized test name for setting the parameter descriptions.
- The type of `num_params` in `struct params_array` was changed from int to
  size_t for better handling of the array size.
- The name of __kunit_init_params() was changed to be kunit_init_params().
  Logic that sets the get_description() function pointer to NULL was also
  added in there.
- `kunit_array_gen_params` is now exported to make it available to use
  with modules.
- Instead of allowing NULL to be passed in as the parameter generator
  function in the KUNIT_CASE_PARAM_WITH_INIT macro, users will now be asked
  to provide `kunit_array_gen_params` as the generator function. This will
  ensure that a parameterized test remains defined by the existence of a
  parameter generation function.
- KUNIT_ARRAY_PARAM(,DESC) will now additionally register the passed in array
  in struct kunit_params. This will make things more consistent i.e. if a
  parameter array is available then the struct kunit_params field in parent
  struct kunit is populated. Additionally, this will increase the
  availability of the KTAP test plan.
- The comments and the commit message were changed to reflect the
  parameterized testing terminology. See the patch series cover letter
  change log for the definitions.

---
 include/kunit/test.h | 65 ++++++++++++++++++++++++++++++++++++++++----
 lib/kunit/test.c     | 30 ++++++++++++++++++++
 2 files changed, 89 insertions(+), 6 deletions(-)

diff --git a/include/kunit/test.h b/include/kunit/test.h
index b527189d2d1c..8cc9614a88d5 100644
--- a/include/kunit/test.h
+++ b/include/kunit/test.h
@@ -234,9 +234,13 @@ static inline char *kunit_status_to_ok_not_ok(enum kunit_status status)
  * Provides the option to register param_init() and param_exit() functions.
  * param_init/exit will be passed the parameterized test context and run once
  * before and once after the parameterized test. The init function can be used
- * to add resources to share between parameter runs, and any other setup logic.
- * The exit function can be used to clean up resources that were not managed by
- * the parameterized test, and any other teardown logic.
+ * to add resources to share between parameter runs, pass parameter arrays,
+ * and any other setup logic. The exit function can be used to clean up resources
+ * that were not managed by the parameterized test, and any other teardown logic.
+ *
+ * Note: If you are registering a parameter array in param_init() with
+ * kunit_register_param_array() then you need to pass kunit_array_gen_params()
+ * to this as the generator function.
  */
 #define KUNIT_CASE_PARAM_WITH_INIT(test_name, gen_params, init, exit)		\
 		{ .run_case = test_name, .name = #test_name,			\
@@ -289,6 +293,20 @@ struct kunit_suite_set {
 	struct kunit_suite * const *end;
 };
 
+/* Stores the pointer to the parameter array and its metadata. */
+struct kunit_params {
+	/*
+	 * Reference to the parameter array for a parameterized test. This
+	 * is NULL if a parameter array wasn't directly passed to the
+	 * parameterized test context struct kunit via kunit_register_params_array().
+	 */
+	const void *params;
+	/* Reference to a function that gets the description of a parameter. */
+	void (*get_description)(struct kunit *test, const void *param, char *desc);
+	size_t num_params;
+	size_t elem_size;
+};
+
 /**
  * struct kunit - represents a running instance of a test.
  *
@@ -296,16 +314,18 @@ struct kunit_suite_set {
  *	  created in the init function (see &struct kunit_suite).
  * @parent: reference to the parent context of type struct kunit that can
  *	    be used for storing shared resources.
+ * @params_array: for storing the parameter array.
  *
  * Used to store information about the current context under which the test
  * is running. Most of this data is private and should only be accessed
- * indirectly via public functions; the two exceptions are @priv and @parent
- * which can be used by the test writer to store arbitrary data and access the
- * parent context, respectively.
+ * indirectly via public functions; the exceptions are @priv, @parent and
+ * @params_array which can be used by the test writer to store arbitrary data,
+ * access the parent context, and to store the parameter array, respectively.
  */
 struct kunit {
 	void *priv;
 	struct kunit *parent;
+	struct kunit_params params_array;
 
 	/* private: internal use only. */
 	const char *name; /* Read only after initialization! */
@@ -376,6 +396,8 @@ void kunit_exec_list_tests(struct kunit_suite_set *suite_set, bool include_attr)
 struct kunit_suite_set kunit_merge_suite_sets(struct kunit_suite_set init_suite_set,
 		struct kunit_suite_set suite_set);
 
+const void *kunit_array_gen_params(struct kunit *test, const void *prev, char *desc);
+
 #if IS_BUILTIN(CONFIG_KUNIT)
 int kunit_run_all_tests(void);
 #else
@@ -1696,6 +1718,8 @@ do {									       \
 					     const void *prev, char *desc)			\
 	{											\
 		typeof((array)[0]) *__next = prev ? ((typeof(__next)) prev) + 1 : (array);	\
+		if (!prev)									\
+			kunit_register_params_array(test, array, ARRAY_SIZE(array), NULL);	\
 		if (__next - (array) < ARRAY_SIZE((array))) {					\
 			void (*__get_desc)(typeof(__next), char *) = get_desc;			\
 			if (__get_desc)								\
@@ -1718,6 +1742,8 @@ do {									       \
 					     const void *prev, char *desc)			\
 	{											\
 		typeof((array)[0]) *__next = prev ? ((typeof(__next)) prev) + 1 : (array);	\
+		if (!prev)									\
+			kunit_register_params_array(test, array, ARRAY_SIZE(array), NULL);	\
 		if (__next - (array) < ARRAY_SIZE((array))) {					\
 			strscpy(desc, __next->desc_member, KUNIT_PARAM_DESC_SIZE);		\
 			return __next;								\
@@ -1725,6 +1751,33 @@ do {									       \
 		return NULL;									\
 	}
 
+/**
+ * kunit_register_params_array() - Register parameter array for a KUnit test.
+ * @test: The KUnit test structure to which parameters will be added.
+ * @array: An array of test parameters.
+ * @param_count: Number of parameters.
+ * @get_desc: Function that generates a string description for a given parameter
+ * element.
+ *
+ * This macro initializes the @test's parameter array data, storing information
+ * including the parameter array, its count, the element size, and the parameter
+ * description function within `test->params_array`.
+ *
+ * Note: If using this macro in param_init(), kunit_array_gen_params()
+ * will then need to be manually provided as the parameter generator function to
+ * KUNIT_CASE_PARAM_WITH_INIT(). kunit_array_gen_params() is a KUnit
+ * function that uses the registered array to generate parameters
+ */
+#define kunit_register_params_array(test, array, param_count, get_desc)				\
+	do {											\
+		struct kunit *_test = (test);							\
+		const typeof((array)[0]) * _params_ptr = &(array)[0];				\
+		_test->params_array.params = _params_ptr;					\
+		_test->params_array.num_params = (param_count);					\
+		_test->params_array.elem_size = sizeof(*_params_ptr);				\
+		_test->params_array.get_description = (get_desc);				\
+	} while (0)
+
 // TODO(dlatypov@google.com): consider eventually migrating users to explicitly
 // include resource.h themselves if they need it.
 #include <kunit/resource.h>
diff --git a/lib/kunit/test.c b/lib/kunit/test.c
index ac8fa8941a6a..ce4bb93f09f4 100644
--- a/lib/kunit/test.c
+++ b/lib/kunit/test.c
@@ -337,6 +337,14 @@ void __kunit_do_failed_assertion(struct kunit *test,
 }
 EXPORT_SYMBOL_GPL(__kunit_do_failed_assertion);
 
+static void kunit_init_params(struct kunit *test)
+{
+	test->params_array.params = NULL;
+	test->params_array.get_description = NULL;
+	test->params_array.num_params = 0;
+	test->params_array.elem_size = 0;
+}
+
 void kunit_init_test(struct kunit *test, const char *name, struct string_stream *log)
 {
 	spin_lock_init(&test->lock);
@@ -347,6 +355,7 @@ void kunit_init_test(struct kunit *test, const char *name, struct string_stream
 		string_stream_clear(log);
 	test->status = KUNIT_SUCCESS;
 	test->status_comment[0] = '\0';
+	kunit_init_params(test);
 }
 EXPORT_SYMBOL_GPL(kunit_init_test);
 
@@ -641,6 +650,23 @@ static void kunit_accumulate_stats(struct kunit_result_stats *total,
 	total->total += add.total;
 }
 
+const void *kunit_array_gen_params(struct kunit *test, const void *prev, char *desc)
+{
+	struct kunit_params *params_arr = &test->params_array;
+	const void *param;
+
+	if (test->param_index < params_arr->num_params) {
+		param = (char *)params_arr->params
+			+ test->param_index * params_arr->elem_size;
+
+		if (params_arr->get_description)
+			params_arr->get_description(test, param, desc);
+		return param;
+	}
+	return NULL;
+}
+EXPORT_SYMBOL_GPL(kunit_array_gen_params);
+
 static void kunit_init_parent_param_test(struct kunit_case *test_case, struct kunit *test)
 {
 	if (test_case->param_init) {
@@ -706,6 +732,10 @@ int kunit_run_tests(struct kunit_suite *suite)
 				  "KTAP version 1\n");
 			kunit_log(KERN_INFO, &test, KUNIT_SUBTEST_INDENT KUNIT_SUBTEST_INDENT
 				  "# Subtest: %s", test_case->name);
+			if (test.params_array.params)
+				kunit_log(KERN_INFO, &test, KUNIT_SUBTEST_INDENT
+					  KUNIT_SUBTEST_INDENT "1..%zd\n",
+					  test.params_array.num_params);
 
 			while (curr_param) {
 				struct kunit param_test = {
-- 
2.51.0.rc1.167.g924127e9c0-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250815103604.3857930-5-marievic%40google.com.
