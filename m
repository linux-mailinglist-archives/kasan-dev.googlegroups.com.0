Return-Path: <kasan-dev+bncBC6OLHHDVUOBBUPVWXCQMGQEDWJTVBI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x440.google.com (mail-pf1-x440.google.com [IPv6:2607:f8b0:4864:20::440])
	by mail.lfdr.de (Postfix) with ESMTPS id 764C2B3585B
	for <lists+kasan-dev@lfdr.de>; Tue, 26 Aug 2025 11:13:55 +0200 (CEST)
Received: by mail-pf1-x440.google.com with SMTP id d2e1a72fcca58-771b23c098dsf1760157b3a.2
        for <lists+kasan-dev@lfdr.de>; Tue, 26 Aug 2025 02:13:55 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756199634; cv=pass;
        d=google.com; s=arc-20240605;
        b=Qvc9HVYiGP6uNKeV+65BNX2wS7d0DS3zYYG8cKU+zanEzPtJl/0q7T4WQMKMCMQYV5
         mEEySHXcmaNTnE2AuoBBTRROL/hOeukXWAMbti+FY0lRbVjpGlMSjOLmhx44DhWtWqRX
         0uqtm/NUfrJNERWlet8xDsfBL8r3HuaoLznJPLC5ZVUJydzSJBI41IbYeaor5lm/8LKZ
         woMh+EMkNhJUPR5PsLVMIJOJeqYIKOaQ6WhiQ2l6q4V4zQ4IYzKXStKBtLjRzKyt4qxk
         3OYG7GYWbDSM7MtWAeqW2/bm02g2gGVi4QI2RQLOjIz4qQtRq6OKgfVFPvHO55Tm35KI
         Qu7g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=2tPkfA7vQNUYTRMisbdDA3rva/ko3BDaQb3mBBCDEtA=;
        fh=H9idVYbR/FNn3mxBqZoKaTt2QDhOEl3NOwaIWx+7lTo=;
        b=W1Wp0lx2WP09MiDRK/BkMn4IoupFygrWyzao3BBJAlTj0c9vXA0B033IPC0RYkWa8z
         pvPdcDuNbQ+fXHSpLN0PzWcPvnFBEhlz4CkdWGke0JkLC7E5FiCL5MYTiSICImGap7T4
         Sag6sg4QyLkGmbB0wlm9VrD3bj7FA9MbuIwYpMM8kr70Rp2Taud9nN+vGPYqF9Ut+Xgb
         92AECpltx/9A6q8pI87ElaqkHeoNhrC70okpcSnhG7sMbj+ERtil6AEC1iuKN7cWIfFw
         HWwOOd8PeNVrEp6JAB3nPDpPP/etD5P2GzcMCpqddkdlkXrXy8DpzXNJrJ3t1Rfa6Lye
         ao8g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=Kvhypoqm;
       spf=pass (google.com: domain of 3znqtaagkccuol6torz7rzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--davidgow.bounces.google.com designates 2607:f8b0:4864:20::44a as permitted sender) smtp.mailfrom=3znqtaAgKCcUol6torz7rzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--davidgow.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756199634; x=1756804434; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=2tPkfA7vQNUYTRMisbdDA3rva/ko3BDaQb3mBBCDEtA=;
        b=a+Tojr6QGVZO+KIAuQUUVPNqjMHqYyluDe/oMl3PxWucWpLgCuHeWykWd+hBReZQ5C
         Pv83WlbiopSCO/yt2bSZf2tgl7ZJIbjOZXpezFqWQSeCXuGsaIohDqWsP/x/d6LUPe4V
         B3HiIy16ftww47kXTnyUv3pYB2PFeeeyk9NnKbiaVbVF/eFrd5die0Lqp9JQUid6ceVC
         r/jiTTU87I0y5cs9TlbXBb8+S44HMM8b2FsrGY14LGAdOhTC9z97HNGi9qPoKSRqwxQb
         LGI3ayN70L35cF7u7S4nP0DSmD7x1h/70tpvfBDKovxB9xEXjKJYvpqt/Z+UPYOBL7nq
         n9sQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756199634; x=1756804434;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=2tPkfA7vQNUYTRMisbdDA3rva/ko3BDaQb3mBBCDEtA=;
        b=mpaBOZmrB2cy5UfTwJ7wCYgCp8TObFnQ7nNLSTlOm7kUFQD2XEQ3jLP2ZAIjdU+95w
         INEDLmDipzAy9QaiU2/flZAk2TzZtaqqiHsYUEk694rowEWh9ri1RZl/VFMzyP5LL5kQ
         LwBfJRcBlzUxcG0vyPcJrAtb0RHoYTotcXVmmPxgKVua10e0g+EIqVPX0Cenf6cJaUIb
         I5mOa4FvC3FtD89EBsFPBLkpI5Q/dHDHSzFaJbBqo7yOPP7cA7i0fDTEwm+ybhJzeTFC
         tifZNOmeOw9+zEg10JT3hAb+DAXr5pWocr3e3/AkZM1iYfMwchgViYaKw1etJ5kmG1bO
         QA6g==
X-Forwarded-Encrypted: i=2; AJvYcCVtGD0KXEd1l+Y62cVN+SdQEcaWVzN7tJA/7LhZ/7CIDeSd+YSOv2ILZckjPFEFZw04OsCsYQ==@lfdr.de
X-Gm-Message-State: AOJu0YzZ5K/qFzTaFVFOl7B0go14hbZlR99wDF39ZBOKiCBS0mG09sky
	231m2dqdeDnre9VrsAFpsBRBiabLpZBoNwXR/Fvz+i9e59T59n547v+Z
X-Google-Smtp-Source: AGHT+IGcU19Nd3mVn+MPPnie7gIP422cJUThigK+bN7ZfIbYDvR9lmgTctMcgs4fE0UpXdDF2ZSHSQ==
X-Received: by 2002:a05:6a00:3e01:b0:76e:885a:c33a with SMTP id d2e1a72fcca58-7702fc28b0cmr21053787b3a.32.1756199633691;
        Tue, 26 Aug 2025 02:13:53 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcJHnuNkrqgmEFj7Sk2Wbdj4ZEVEw9/1iKOYQ5DcwRFcA==
Received: by 2002:a05:6a00:600e:b0:771:e960:9564 with SMTP id
 d2e1a72fcca58-771e96095f4ls1943795b3a.2.-pod-prod-05-us; Tue, 26 Aug 2025
 02:13:51 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWlwPjn35ZAeemvkFCjhbQZgsAqPPD7o8hj2Imp2sC9Y4f4q4vJsfnOMw7sMKirn+zswzEi9vyL8Z8=@googlegroups.com
X-Received: by 2002:a05:6a20:7fa4:b0:243:25b0:2321 with SMTP id adf61e73a8af0-24340e443cdmr22758653637.52.1756199631607;
        Tue, 26 Aug 2025 02:13:51 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756199631; cv=none;
        d=google.com; s=arc-20240605;
        b=aTmOxG0eF8MXZFolNqAlqoKbWGrX+y6EJr9TWZ3HoVIt6O8kv1XvX7gyeBxPkxuEPy
         iBpOmzsqZY5g109XPYW3kMvPqptMjEyqYaFUA+bWhcGcvy4NCmJ78NarHRSZpKjTi5hR
         8s5yJMohKc+Vz8wOD8NLA6zoui8dZaCt4ChFdNx200NM//10gtKIYewlYYWZnJ99m9TF
         DBj8JRIrecNOFedaYzL2UpL8SVHVhKJDAP3+Ye2VRa01Mh46A3N4KJv2grFFXjGc3Qpq
         pug+T0gR04vaaRJl2VhB/hsqvuoLEB9Epm9rrTeVJdBoF6X8hfqjxbPxkRFQR0xczP70
         /WCA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=SS4RWWsYR8rt67WX12qateLzVdeeE0BdCVVhb7GW4rE=;
        fh=VCoYC+l9tmo2sGi+Pj1BVjFHpkg51CTai29CiUDZw6s=;
        b=iE3xptNlC343Yg34xO0cAF254KwhBY11cErpoBbHLD4lSVwfgKNrKi2d69u6TyifF3
         p6FRIOFUPcxAT4/oz36zkJ4PoWkLKLnjzYVW7upR+xL0x2QiWnL4xpfeqdvll4UesHcB
         ciyCoycnqzxW6v1R9vsbP0bOWBTsnlDHGfYC+iq+RracwU30vMCTpM1S9Q/dxA4YUuGf
         AkZnfy3FAo30WL8x9Us4Di3ve9s7Q3kCKbQWVqALhPXlMj2MkcIZ7EXvoxkadBXj5uzL
         cklcibqG6IlJCaz3U/o6kyRtOwFqTyi8vXNd8NO0fLr9Gz5a1+BU4mnmNmiHCQLdG9tP
         2ymw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=Kvhypoqm;
       spf=pass (google.com: domain of 3znqtaagkccuol6torz7rzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--davidgow.bounces.google.com designates 2607:f8b0:4864:20::44a as permitted sender) smtp.mailfrom=3znqtaAgKCcUol6torz7rzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--davidgow.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pf1-x44a.google.com (mail-pf1-x44a.google.com. [2607:f8b0:4864:20::44a])
        by gmr-mx.google.com with ESMTPS id d2e1a72fcca58-77040191ec4si158623b3a.3.2025.08.26.02.13.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 26 Aug 2025 02:13:51 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3znqtaagkccuol6torz7rzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--davidgow.bounces.google.com designates 2607:f8b0:4864:20::44a as permitted sender) client-ip=2607:f8b0:4864:20::44a;
Received: by mail-pf1-x44a.google.com with SMTP id d2e1a72fcca58-76e2e5c4734so5387336b3a.0
        for <kasan-dev@googlegroups.com>; Tue, 26 Aug 2025 02:13:51 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWF7eRrh7scX0+Z8MzBPAIChlDWGNOx5jZjzVug2bLE/bofn7SMA7DOYgn2zptCbloZDOffsHGOWik=@googlegroups.com
X-Received: from pfz14.prod.google.com ([2002:a05:6a00:bb8e:b0:748:e22c:600c])
 (user=davidgow job=prod-delivery.src-stubby-dispatcher) by
 2002:a05:6a00:3c91:b0:771:ebf1:5e4b with SMTP id d2e1a72fcca58-771ebf16677mr4678781b3a.26.1756199630989;
 Tue, 26 Aug 2025 02:13:50 -0700 (PDT)
Date: Tue, 26 Aug 2025 17:13:34 +0800
In-Reply-To: <20250826091341.1427123-1-davidgow@google.com>
Mime-Version: 1.0
References: <20250826091341.1427123-1-davidgow@google.com>
X-Mailer: git-send-email 2.51.0.261.g7ce5a0a67e-goog
Message-ID: <20250826091341.1427123-5-davidgow@google.com>
Subject: [PATCH v4 4/7] kunit: Enable direct registration of parameter arrays
 to a KUnit test
From: "'David Gow' via kasan-dev" <kasan-dev@googlegroups.com>
To: Marie Zhussupova <marievic@google.com>, marievictoria875@gmail.com, rmoar@google.com, 
	shuah@kernel.org, brendan.higgins@linux.dev
Cc: mark.rutland@arm.com, elver@google.com, dvyukov@google.com, 
	lucas.demarchi@intel.com, thomas.hellstrom@linux.intel.com, 
	rodrigo.vivi@intel.com, linux-kselftest@vger.kernel.org, 
	kunit-dev@googlegroups.com, kasan-dev@googlegroups.com, 
	intel-xe@lists.freedesktop.org, dri-devel@lists.freedesktop.org, 
	linux-kernel@vger.kernel.org, Stephen Rothwell <sfr@canb.auug.org.au>, 
	David Gow <davidgow@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: davidgow@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=Kvhypoqm;       spf=pass
 (google.com: domain of 3znqtaagkccuol6torz7rzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--davidgow.bounces.google.com
 designates 2607:f8b0:4864:20::44a as permitted sender) smtp.mailfrom=3znqtaAgKCcUol6torz7rzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--davidgow.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
X-Original-From: David Gow <davidgow@google.com>
Reply-To: David Gow <davidgow@google.com>
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

From: Marie Zhussupova <marievic@google.com>

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
Reviewed-by: Rae Moar <rmoar@google.com>
Signed-off-by: Marie Zhussupova <marievic@google.com>
[Only output the test plan if using kunit_array_gen_params --David]
Signed-off-by: David Gow <davidgow@google.com>
---

Changes in v4:
v3: https://lore.kernel.org/linux-kselftest/20250815103604.3857930-5-marievic@google.com/
- Only output a KTAP test plan if the generate_params function is
  kunit_array_gen_params.
- This fixes an issue with generate_params functions which use an array,
  but skip some elements.
- This change is also available as a separate patch here:
  https://lore.kernel.org/linux-kselftest/20250821135447.1618942-2-davidgow@google.com/

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
 lib/kunit/test.c     | 32 ++++++++++++++++++++++
 2 files changed, 91 insertions(+), 6 deletions(-)

diff --git a/include/kunit/test.h b/include/kunit/test.h
index 8eba1b03c3e3..5ec5182b5e57 100644
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
@@ -1708,6 +1730,8 @@ do {									       \
 					     const void *prev, char *desc)			\
 	{											\
 		typeof((array)[0]) *__next = prev ? ((typeof(__next)) prev) + 1 : (array);	\
+		if (!prev)									\
+			kunit_register_params_array(test, array, ARRAY_SIZE(array), NULL);	\
 		if (__next - (array) < ARRAY_SIZE((array))) {					\
 			void (*__get_desc)(typeof(__next), char *) = get_desc;			\
 			if (__get_desc)								\
@@ -1730,6 +1754,8 @@ do {									       \
 					     const void *prev, char *desc)			\
 	{											\
 		typeof((array)[0]) *__next = prev ? ((typeof(__next)) prev) + 1 : (array);	\
+		if (!prev)									\
+			kunit_register_params_array(test, array, ARRAY_SIZE(array), NULL);	\
 		if (__next - (array) < ARRAY_SIZE((array))) {					\
 			strscpy(desc, __next->desc_member, KUNIT_PARAM_DESC_SIZE);		\
 			return __next;								\
@@ -1737,6 +1763,33 @@ do {									       \
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
index 50705248abad..bb66ea1a3eac 100644
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
@@ -706,6 +732,12 @@ int kunit_run_tests(struct kunit_suite *suite)
 				  "KTAP version 1\n");
 			kunit_log(KERN_INFO, &test, KUNIT_SUBTEST_INDENT KUNIT_SUBTEST_INDENT
 				  "# Subtest: %s", test_case->name);
+			if (test.params_array.params &&
+			    test_case->generate_params == kunit_array_gen_params) {
+				kunit_log(KERN_INFO, &test, KUNIT_SUBTEST_INDENT
+					  KUNIT_SUBTEST_INDENT "1..%zd\n",
+					  test.params_array.num_params);
+			}
 
 			while (curr_param) {
 				struct kunit param_test = {
-- 
2.51.0.261.g7ce5a0a67e-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250826091341.1427123-5-davidgow%40google.com.
