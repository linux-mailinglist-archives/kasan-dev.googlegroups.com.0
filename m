Return-Path: <kasan-dev+bncBDQ67ZGAXYCBB66FUTCAMGQEZVFBH2I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3c.google.com (mail-oa1-x3c.google.com [IPv6:2001:4860:4864:20::3c])
	by mail.lfdr.de (Postfix) with ESMTPS id AC29EB15390
	for <lists+kasan-dev@lfdr.de>; Tue, 29 Jul 2025 21:37:32 +0200 (CEST)
Received: by mail-oa1-x3c.google.com with SMTP id 586e51a60fabf-2e933923303sf6628701fac.1
        for <lists+kasan-dev@lfdr.de>; Tue, 29 Jul 2025 12:37:32 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1753817851; cv=pass;
        d=google.com; s=arc-20240605;
        b=ccOaJ2SCeWeq12rwkRB1GT/b7faVQgg3TdLSPJs+Z6r2baaM7f1cWyhWnsADylsXvJ
         gxmJr0zh9B0z/g6Ph3WDDGqXMYYv1L5MRsw+PlV2FNUL8CYVyMvNWvk9/zEzHoRkDB05
         BvzVGm0BGDeMVLMRZcITwY1ewsJkaR76p/hNZVO8PnNtEWxRl/gVOE1bc6FZIePWzaqP
         OxjmjxaOIpERAGBgOjCKs/XxMW4+VLGOug3itsxKYC0/6g5VaiSiBkSRubiVJLtSnFol
         acZYDPYACPu7mvfrT3NM2X1dxGuK8io+fgZJMq0Ay4SeX0Dd8XWa653J6qzkIev9WALB
         2q4g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=InhDc/MWz0xMEu1JYRiZZttZV4GBbfHFZJRbJ9XuH7M=;
        fh=jnuPa01gf26LupbVWffXQEZmcaA8n4j3/IbBclqkyKs=;
        b=DdR8mvmM9BGKEJHaWnhGN/IZC/bO/XOzv3mPs5MlHWR320JPc3pqaT+xJy3TZrsSUE
         wxPLLEN1nfKrN/ecaAX6tcq0rkvCSvZH6WNOGOUFYZ7dazP7Ny5UhWnRwuwhLSdC1XQb
         WBdAUsyrqkm/9h+7b3LUOvWYaz5T61bGq77C7rcB9sxP1Gnj1DSNQWSHdl5S9r95WZSP
         d8r8AJFhHFWjSG+Tivds0UZayeZq0SuleTJi86etRzLWWMp7bqN77cE/4IUJXJnogYoy
         twy8AT4JESrhzXsgMTmr5RVqhR0inPsGZFv8FsEMQp7ymJGOd009fZcrOfv7Zozgl/X4
         AfWQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=Su+eCKH3;
       spf=pass (google.com: domain of 3-ikjaagkca8bpgxtkxrvddvat.rdbzphpc-stkvddvatvgdjeh.rdb@flex--marievic.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=3-iKJaAgKCa8bPgXTkXRVddVaT.RdbZPhPc-STkVddVaTVgdjeh.Rdb@flex--marievic.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1753817851; x=1754422651; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=InhDc/MWz0xMEu1JYRiZZttZV4GBbfHFZJRbJ9XuH7M=;
        b=TiAPRHUCiA0Uay25YiAe53pNlaKMIF3yiibVrRLDZMSIxKR8IirTh2UGANRvimtfqI
         f7ujOwNz/tTTFPyDuaKmPyUDchprFlTQzlGiyca5XDEtDo5jgWZjQq+odsB+XFPN/cGW
         h+1x+oGtPjVvWOnf5xu29LKz2hG8ry92MKzPAUs2r//VLsJfVJG+UrG7ySk6dbZKVhuh
         edRtSFiIc5cZ0TCWJEnjow87GR38SFE5EXsCwiEPQADaM7Q/4b9eyP5oLu1KcP6PtCuK
         8uOjPp8jHaPh8cF8Au/tvKs49kctl1HwUnW65ltLCWWC+dtaouWds+nn/7X8EusQ5rPX
         9fgw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1753817851; x=1754422651;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=InhDc/MWz0xMEu1JYRiZZttZV4GBbfHFZJRbJ9XuH7M=;
        b=RXPWLbreLjJKmEvPSaX6dvpeIxEAMm272GPIJ52zauzv/c6z1l+TW5MbGEOha7F84b
         dNLsoERWvMpxnBRMF/QFeSY6NKRzsTlwRm37htgPCj+SSH0xKkRrTIWdq+YyzXPqzW4l
         JbCshzY/S0JWKDOFB69BCTg6jDZ8yUqlCCM8Mzd86hsNOe6IwDdQhVuBPY/OiVuWHbmX
         lQ8a6FNkD4XTxxJnZviPDXJLp7RXljpg619dQSnI0T2ix6GuWqMjyd0fWIKmopaQ+IJ9
         bTDVdd3pHXJbCFXmeIjjCRKjKpEODkpj2kTtrsaX/PrbM+IM1VHG//qIflWrnMOeOFLS
         hbBA==
X-Forwarded-Encrypted: i=2; AJvYcCVEWLTIAZTJxwHaEsnk5FR05Wz9U+IGdnOJ2BFf+mDrYA4SvKA73U6PYSIO2QGBLJ1YEsslbg==@lfdr.de
X-Gm-Message-State: AOJu0YwJW+ttc9dq+bm4H7swO/3iXwQJuh631sE82lQvPoyxlZ1Ds93W
	YSz8XoFixxOUNqjfpK8hxRvnymQ6v8UOKhG+gDDkJE4CICX3HGqf/KSh
X-Google-Smtp-Source: AGHT+IEopPRYSjjIOHC7TRmlpmaHFrBqqwqo8kY2LNhkRypi1740oxwN/3SJ907mbTlXB9KzHySO8g==
X-Received: by 2002:a05:6870:591:b0:2ff:8f57:9168 with SMTP id 586e51a60fabf-30785cb08a9mr358161fac.28.1753817851381;
        Tue, 29 Jul 2025 12:37:31 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdd/71AXL6tHc2X0om72KPC3mj7UVKAHxSqYF33Zaka6g==
Received: by 2002:a05:6871:900a:b0:306:e7d7:f921 with SMTP id
 586e51a60fabf-306e7d808aals1727881fac.1.-pod-prod-08-us; Tue, 29 Jul 2025
 12:37:30 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWEcmYrDnjWdYSaF1LlxHJh2t1HItwMJd+W9SsGRQajetlEjF9A2sqf5Yqo/b4T9TThXJrPfWioEeo=@googlegroups.com
X-Received: by 2002:a05:6870:2104:b0:2bc:918c:ee04 with SMTP id 586e51a60fabf-30785aaedc5mr388138fac.14.1753817850565;
        Tue, 29 Jul 2025 12:37:30 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1753817850; cv=none;
        d=google.com; s=arc-20240605;
        b=aoQ+fAW+eka21ifcbkyOLzBivZc5cU8EBN4d4sJYTWO96AWkO+9Rt99qQMbOIj75WQ
         Glr/QVr6yi/NFoMjk/ala30f8QvzCxOEfYICitBa5EyH2wo4HzR0Qfp9M8Qi41TIUX3r
         iHyIByTFtrZMBJc2cMeqCKhEq6dwwSR2BHhUCQRJPMxoTEKqU29AAZX0TX2Y1YjtHKRw
         WPSYODBMZm4Lx6nnsl6/2KaK98U395SfE87aDz2g+7W+lnSYqZz9v1Q7GqDnYkVdHTGg
         x8J1EH8IxbNRR1koL7nbChm+n196+SCPPY8zkxzIJuHhXeF7VoIBMh4U1MXozwa4lxuG
         houQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=78rzCs5wryrNYhO305P66/dWltNV0BBuUlP5VrjuElY=;
        fh=wj3F4A6jeuQMIHd7PtzH57I5ty0thDVy62NhS9z+uzU=;
        b=Wjt0n02zH5jidxKxsCnmQbndWaNZ71lkjY2+sEF5hEF2lyKJ1RsT/nHJOeJiow5XfZ
         sxCAin4fhN7jxQX2o20axMYV+Hn5PrC31rTxIUrZHH5tO7MNickzfE/gSMQ0Kr6HugKP
         Uz0oIExxfibmp14ncmJinmicEdVRvRa98FIPAPvOZ3glFo+dqxT9h2DN7as5B8uyw5Kk
         lqrA1/bfH3wm6YfAnqAyYxg05LaKwNZx3ROi72U/oYhWKTbOX4Jsrda8Sl6S9qe2N02c
         /xt+YBK0dANW3JaL5biKhwh+Jg4Y605HwUDMEYY+IY6+pkCQn3f3d4s8CBrfyLfxqAaR
         cLIQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=Su+eCKH3;
       spf=pass (google.com: domain of 3-ikjaagkca8bpgxtkxrvddvat.rdbzphpc-stkvddvatvgdjeh.rdb@flex--marievic.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=3-iKJaAgKCa8bPgXTkXRVddVaT.RdbZPhPc-STkVddVaTVgdjeh.Rdb@flex--marievic.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-qk1-x749.google.com (mail-qk1-x749.google.com. [2607:f8b0:4864:20::749])
        by gmr-mx.google.com with ESMTPS id 586e51a60fabf-30712fff7e5si453286fac.1.2025.07.29.12.37.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 29 Jul 2025 12:37:30 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3-ikjaagkca8bpgxtkxrvddvat.rdbzphpc-stkvddvatvgdjeh.rdb@flex--marievic.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) client-ip=2607:f8b0:4864:20::749;
Received: by mail-qk1-x749.google.com with SMTP id af79cd13be357-7e651d8b5e0so369220685a.0
        for <kasan-dev@googlegroups.com>; Tue, 29 Jul 2025 12:37:30 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCV1bbp+F4PpNPjcvsr5xPVSPcM/VcpCDID7Jjb5woYVSRLNI1eioT9V8QUGXB2BjU3pYnHa0RadR68=@googlegroups.com
X-Received: from qtbbc7.prod.google.com ([2002:a05:622a:1cc7:b0:4ab:a3a0:c3dc])
 (user=marievic job=prod-delivery.src-stubby-dispatcher) by
 2002:a05:620a:8b15:b0:7d4:4c48:d5b4 with SMTP id af79cd13be357-7e66f3b9ea4mr75650485a.56.1753817850191;
 Tue, 29 Jul 2025 12:37:30 -0700 (PDT)
Date: Tue, 29 Jul 2025 19:36:44 +0000
In-Reply-To: <20250729193647.3410634-1-marievic@google.com>
Mime-Version: 1.0
References: <20250729193647.3410634-1-marievic@google.com>
X-Mailer: git-send-email 2.50.1.552.g942d659e1b-goog
Message-ID: <20250729193647.3410634-7-marievic@google.com>
Subject: [PATCH 6/9] kunit: Enable direct registration of parameter arrays to
 a KUnit test
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
 header.i=@google.com header.s=20230601 header.b=Su+eCKH3;       spf=pass
 (google.com: domain of 3-ikjaagkca8bpgxtkxrvddvat.rdbzphpc-stkvddvatvgdjeh.rdb@flex--marievic.bounces.google.com
 designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=3-iKJaAgKCa8bPgXTkXRVddVaT.RdbZPhPc-STkVddVaTVgdjeh.Rdb@flex--marievic.bounces.google.com;
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

KUnit parameterized tests currently support two
primary methods for getting parameters:
1.  Defining custom logic within a `generate_params`
    function.
2.  Using the KUNIT_ARRAY_PARAM and KUNIT_ARRAY_PARAM_DESC
    macros with pre-defined static arrays.

These methods present limitations when dealing with
dynamically generated parameter arrays, or in scenarios
where populating parameters sequentially via
`generate_params` is inefficient or overly complex.

This patch addresses these limitations by adding a new
`params_data` field to `struct kunit`, of the type
`kunit_params`. The struct `kunit_params` is designed to
store the parameter array itself, along with essential metadata
including the parameter count, parameter size, and a
`get_description` function for providing custom descriptions
for individual parameters.

The `params_data` field can be populated by calling the new
`kunit_register_params_array` macro from within a
`param_init` function. By attaching the parameter array
directly to the parent kunit test instance, these parameters
can be iterated over in kunit_run_tests() behind the scenes.

This modification provides greater flexibility to the
KUnit framework, allowing testers to easily register and
utilize both dynamic and static parameter arrays.

Signed-off-by: Marie Zhussupova <marievic@google.com>
---
 include/kunit/test.h | 54 ++++++++++++++++++++++++++++++++++++++++----
 lib/kunit/test.c     | 26 ++++++++++++++++++++-
 2 files changed, 75 insertions(+), 5 deletions(-)

diff --git a/include/kunit/test.h b/include/kunit/test.h
index 4ba65dc35710..9143f0e22323 100644
--- a/include/kunit/test.h
+++ b/include/kunit/test.h
@@ -245,7 +245,8 @@ static inline char *kunit_status_to_ok_not_ok(enum kunit_status status)
  */
 #define KUNIT_CASE_PARAM_WITH_INIT(test_name, gen_params, init, exit)		\
 		{ .run_case = test_name, .name = #test_name,			\
-		  .generate_params = gen_params,				\
+		  .generate_params = (gen_params)				\
+		   ?: kunit_get_next_param_and_desc,				\
 		  .param_init = init, .param_exit = exit,			\
 		  .module_name = KBUILD_MODNAME}
 
@@ -294,6 +295,21 @@ struct kunit_suite_set {
 	struct kunit_suite * const *end;
 };
 
+/* Stores the pointer to the parameter array and its metadata. */
+struct kunit_params {
+	/*
+	 * Reference to the parameter array for the parameterized tests. This
+	 * is NULL if a parameter array wasn't directly passed to the
+	 * parent kunit struct via the kunit_register_params_array macro.
+	 */
+	const void *params;
+	/* Reference to a function that gets the description of a parameter. */
+	void (*get_description)(const void *param, char *desc);
+
+	int num_params;
+	size_t elem_size;
+};
+
 /**
  * struct kunit - represents a running instance of a test.
  *
@@ -302,12 +318,14 @@ struct kunit_suite_set {
  * @parent: for user to store data that they want to shared across
  *	    parameterized tests. Typically, the data is provided in
  *	    the param_init function (see &struct kunit_case).
+ * @params_data: for users to directly store the parameter array.
  *
  * Used to store information about the current context under which the test
  * is running. Most of this data is private and should only be accessed
- * indirectly via public functions; the two exceptions are @priv and @parent
- * which can be used by the test writer to store arbitrary data or data that is
- * available to all parameter test executions, respectively.
+ * indirectly via public functions. There are three exceptions to this: @priv,
+ * @parent, and @params_data. These members can be used by the test writer to
+ * store arbitrary data, data available to all parameter test executions, and
+ * the parameter array, respectively.
  */
 struct kunit {
 	void *priv;
@@ -316,6 +334,8 @@ struct kunit {
 	 * during parameterized testing.
 	 */
 	struct kunit *parent;
+	/* Stores the params array and all data related to it. */
+	struct kunit_params params_data;
 
 	/* private: internal use only. */
 	const char *name; /* Read only after initialization! */
@@ -386,6 +406,8 @@ void kunit_exec_list_tests(struct kunit_suite_set *suite_set, bool include_attr)
 struct kunit_suite_set kunit_merge_suite_sets(struct kunit_suite_set init_suite_set,
 		struct kunit_suite_set suite_set);
 
+const void *kunit_get_next_param_and_desc(struct kunit *test, const void *prev, char *desc);
+
 #if IS_BUILTIN(CONFIG_KUNIT)
 int kunit_run_all_tests(void);
 #else
@@ -1735,6 +1757,30 @@ do {									       \
 		return NULL;									\
 	}
 
+/**
+ * kunit_register_params_array() - Register parameters for a KUnit test.
+ * @test: The KUnit test structure to which parameters will be added.
+ * @params_arr: An array of test parameters.
+ * @param_cnt: Number of parameters.
+ * @get_desc: A pointer to a function that generates a string description for
+ * a given parameter element.
+ *
+ * This macro initializes the @test's parameter array data, storing information
+ * including the parameter array, its count, the element size, and the parameter
+ * description function within `test->params_data`. KUnit's built-in
+ * `kunit_get_next_param_and_desc` function will automatically read this
+ * data when a custom `generate_params` function isn't provided.
+ */
+#define kunit_register_params_array(test, params_arr, param_cnt, get_desc)			\
+	do {											\
+		struct kunit *_test = (test);						\
+		const typeof((params_arr)[0]) * _params_ptr = &(params_arr)[0];			\
+		_test->params_data.params = _params_ptr;					\
+		_test->params_data.num_params = (param_cnt);					\
+		_test->params_data.elem_size = sizeof(*_params_ptr);				\
+		_test->params_data.get_description = (get_desc);				\
+	} while (0)
+
 // TODO(dlatypov@google.com): consider eventually migrating users to explicitly
 // include resource.h themselves if they need it.
 #include <kunit/resource.h>
diff --git a/lib/kunit/test.c b/lib/kunit/test.c
index f50ef82179c4..2f4b7087db3f 100644
--- a/lib/kunit/test.c
+++ b/lib/kunit/test.c
@@ -337,6 +337,13 @@ void __kunit_do_failed_assertion(struct kunit *test,
 }
 EXPORT_SYMBOL_GPL(__kunit_do_failed_assertion);
 
+static void __kunit_init_params(struct kunit *test)
+{
+	test->params_data.params = NULL;
+	test->params_data.num_params = 0;
+	test->params_data.elem_size = 0;
+}
+
 void kunit_init_test(struct kunit *test, const char *name, struct string_stream *log)
 {
 	spin_lock_init(&test->lock);
@@ -347,6 +354,7 @@ void kunit_init_test(struct kunit *test, const char *name, struct string_stream
 		string_stream_clear(log);
 	test->status = KUNIT_SUCCESS;
 	test->status_comment[0] = '\0';
+	__kunit_init_params(test);
 }
 EXPORT_SYMBOL_GPL(kunit_init_test);
 
@@ -641,6 +649,22 @@ static void kunit_accumulate_stats(struct kunit_result_stats *total,
 	total->total += add.total;
 }
 
+const void *kunit_get_next_param_and_desc(struct kunit *test, const void *prev, char *desc)
+{
+	struct kunit_params *params_arr = &test->params_data;
+	const void *param;
+
+	if (test->param_index < params_arr->num_params) {
+		param = (char *)params_arr->params
+			+ test->param_index * params_arr->elem_size;
+
+		if (params_arr->get_description)
+			params_arr->get_description(param, desc);
+		return param;
+	}
+	return NULL;
+}
+
 static void __kunit_init_parent_test(struct kunit_case *test_case, struct kunit *test)
 {
 	if (test_case->param_init) {
@@ -687,7 +711,7 @@ int kunit_run_tests(struct kunit_suite *suite)
 			/* Test marked as skip */
 			test.status = KUNIT_SKIPPED;
 			kunit_update_stats(&param_stats, test.status);
-		} else if (!test_case->generate_params) {
+		} else if (!test_case->generate_params && !test.params_data.params) {
 			/* Non-parameterised test. */
 			test_case->status = KUNIT_SKIPPED;
 			kunit_run_case_catch_errors(suite, test_case, &test);
-- 
2.50.1.552.g942d659e1b-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250729193647.3410634-7-marievic%40google.com.
