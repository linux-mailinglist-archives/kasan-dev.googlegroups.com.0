Return-Path: <kasan-dev+bncBDQ67ZGAXYCBBFWY5HCAMGQE7OEBREI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33b.google.com (mail-ot1-x33b.google.com [IPv6:2607:f8b0:4864:20::33b])
	by mail.lfdr.de (Postfix) with ESMTPS id 8403EB2181B
	for <lists+kasan-dev@lfdr.de>; Tue, 12 Aug 2025 00:18:00 +0200 (CEST)
Received: by mail-ot1-x33b.google.com with SMTP id 46e09a7af769-743021bdd01sf2336178a34.0
        for <lists+kasan-dev@lfdr.de>; Mon, 11 Aug 2025 15:18:00 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1754950679; cv=pass;
        d=google.com; s=arc-20240605;
        b=ktKIapQY4DXzDR2KSV5uUTgp6Sno4W5KG2KJwjGMaJKT8s7mFYezZeH7zCSZs0Frb8
         i0UItvljFYJtuhYwiUkjYWiZrA8/dyxe/ewKGP8xFkygZsWUcSU0uJ38rOkzihYdy7hr
         A5ibkTx2Zp/xTKNlMcq9jjLJgwgymn23pYGg0uw0Ha82TupAfdmdUq+4i6dj0zf8RjDu
         GjLuQs6qx+QnFrEqe8320lKp1GA1eZX199Kpfvlq6/yEk8s4cCtpwLzczm9SNYrfU5k5
         J8BAwCP0jmEW5oiaim8ZN6AD2D0EdbyYyN24rlMK/EPuFUmSRwAfgfZYlibAGacsOb51
         NFDQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=ADiYxqhSITayC/HlS7zEG14iUYomLCLdF6Ue7o0vB7o=;
        fh=0QlThkCeivkt9Mb8w6EeEPuB1YSQ9jy7AH5MBHHmdsQ=;
        b=JHmWtToD+E1fUqdjZJ1fhBEf7JLrgqU+ZgFtypYomL47bzmM2WIAM4LS1O5gxdO9C9
         yxvZClDTWVYRU1hnx8QGxqfZBhQW0KjFxSMZrUvSNpQM0DwyJdvFQ47bcuBYBn6OPucb
         mzlntOUJdUBIQz6eL6Ntf9ah4mYjmyoKg3CrhWrLiVdxr2q3w+SrKpY+jnjAriPwM2i+
         2bwfq+IpgAefSnWkJxS+HXEeQqdWvFH+klkSJZpdUX1yAoqHXr3XYeqlHSU53I41/kHU
         sE3IBjLI85emPK/L05zknT8ZPZQBuC5uhrQ0xa8vbVVnX+UAtX28TyJMCUujmq5+Ypfx
         h7Qw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=Odu4rTcZ;
       spf=pass (google.com: domain of 3fwyaaagkcaioctkgxkeiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--marievic.bounces.google.com designates 2607:f8b0:4864:20::f4a as permitted sender) smtp.mailfrom=3FWyaaAgKCaIOCTKGXKEIQQING.EQOMCUCP-FGXIQQINGITQWRU.EQO@flex--marievic.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1754950679; x=1755555479; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=ADiYxqhSITayC/HlS7zEG14iUYomLCLdF6Ue7o0vB7o=;
        b=aP03yiS/hiAevUFj4QEoJLrq6spYMU71+YN22vCrB0LG/ZYet6hsJvt77bi9n5oTBx
         5+MD6cCNLvidfAuF5kMHjYiD40QEErmC5s9QGl51183hNsxh6JbWetQIVEXKwekGqJdC
         a40K38lkgIgxEfshFC+DGrP45ZakPUpb8Gd346cahF2/wy66vXHbS+eGpVw6dBCx+xJF
         tspIlieGnxA6LYOcsmAbrczNJXi7cBkyY0hpkeVSuhqvaP2aMN+rM3rNyya7exWyEeip
         idLGf9psZcNeUL+bRIxxseRyE7TWKzC7LYMlYwixs/wnGvbyU1gHr3W+v2Niw5/SmwZh
         11KQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1754950679; x=1755555479;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=ADiYxqhSITayC/HlS7zEG14iUYomLCLdF6Ue7o0vB7o=;
        b=QpvhzC5aUubsDwmm8gkT+AAHFXGhYhgZQK+1Jt0e/zEw98ee8/2eI0MurLobHYU2Kn
         4NrFoiMhMfHKzmiqb43bkTO5SyOjo5pTCLHWgjSOLu0622gYv9DdPyAjze782daAq3dL
         hOC7EUN/yX+6q7vpwdLNc5hcundBBBjTe8tGWo6RxKqItXUZdO0ZkbIJgA70ASrGbO2z
         oAXtcPBtSAmUcSW83ZMLp2BFbRF5xJ4cPzw9NhsZ9G0RHYNf9E8G6QCJ0ukBEwUFv5lg
         cP+QNAxOkG9dANsdqVLSfgMcxOOjc+0twgpZJma52Eb/TleVJvflPO6W0bYkwi+9d/on
         yejg==
X-Forwarded-Encrypted: i=2; AJvYcCUMpEzNPf7oM+SJ1hr6snA9rrq6sucU2baN3RWLRtBJ0YFI8uvco7d2SSpwGqU1la2ZTxdw3w==@lfdr.de
X-Gm-Message-State: AOJu0YxX2VwzG4msBgM0RsOANMXxltx5caHOjgkfShIycrte3CietvEn
	y0W7/Bmyu5A9bRyVGJScqoWucuLVnhLNsyzKjmgzu3geIVrYtki9z9FO
X-Google-Smtp-Source: AGHT+IEBqsG0R/eHxi9Ooet/CBR0Xqpffpz9TdTWmkvKeG6HbS3vK25lzFkqs6UqHsN9HpqUVDF1jg==
X-Received: by 2002:a05:6830:7182:b0:741:84f0:5461 with SMTP id 46e09a7af769-743668b8223mr1050295a34.6.1754950679131;
        Mon, 11 Aug 2025 15:17:59 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdEvcaBnEDXDpdxxRznCeYgnWGuAl8EbAY1C5byGdCEYQ==
Received: by 2002:a05:6820:761b:b0:61b:9d92:d9b9 with SMTP id
 006d021491bc7-61b9d92e05als295187eaf.0.-pod-prod-04-us; Mon, 11 Aug 2025
 15:17:58 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXBeD3gQf6E77lJ4ie/8BFNt3FbEtwSprOmv7mJUYu4DXRUgCleMNfwNsWu5diFHa3ogYNcVd3RP7I=@googlegroups.com
X-Received: by 2002:a05:6830:660d:b0:73e:996d:ccd8 with SMTP id 46e09a7af769-74366c62afcmr1343987a34.21.1754950678261;
        Mon, 11 Aug 2025 15:17:58 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1754950678; cv=none;
        d=google.com; s=arc-20240605;
        b=FnDgiMjxxBm18wOtXukHMPNC4uumuP7bUJC8wtCHhFReTsVAk9o6T16UT252XHBx74
         dZZxZ3E4Y0zmI7w8kd9bMzMggJgjz0wVbvX5yRSGYgXypPFQ9+1dmx7+ZA3arFQBgl6m
         WPileKgUhdrIZmsXepOUs1pX5CuwdFzUjTEZRJ9XOi4g1AIz5lHp8BZGUDuckcSo/yfO
         /062ofM8dwyCRBlspM9UNRzOzhZosbUEDmf0ba1t0jWfy0qB/v1/uMacfpeenIHUEaP8
         p5gCctOWQBrDxC1KDG1jqH9HscmQCq4zYDKs7S3wgN0H9Wvqe6ZxyaVrjvwHo+slmqjF
         qDvg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=TwTIktrqk3ooBYnJ9ISRYmPJ92svBOzIIuaqj7Vn+Ao=;
        fh=IUwOX83xsmc6tuZAT65vvZs7FLIwjRS39xDmFKhoqhU=;
        b=KcdZKMHfmSJc7rOlTQikBoXsbyinHs6pGXD47dcwT3e3OlF78qnsc0G9BmS7aQPHhj
         FiDBfyvkjAz0Aon0JvYAs6xgKY2P0m1sYJy7VKQ3n2QkqHjlED7UkMjW+efkZUH7q2uw
         eUOlhQIG4fksw4+l0HRW/oRCIb+uZOwDTqPOZ9I+0CVyJpwKjjo0E09lBNujOx4l6Or2
         3MkJ6WPVzvwQUZWFdQAJaBwv2r5SGZEiyiIj659q9jiEyNIEpxGjIHYqoDSD6uk/9v0+
         pp6lTqkU+uUrnrk679TpyP/tt5xsHOKOmbL1BR1fEo60jCBiFEY2F4TSO57WyNHkO9Yb
         rh8A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=Odu4rTcZ;
       spf=pass (google.com: domain of 3fwyaaagkcaioctkgxkeiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--marievic.bounces.google.com designates 2607:f8b0:4864:20::f4a as permitted sender) smtp.mailfrom=3FWyaaAgKCaIOCTKGXKEIQQING.EQOMCUCP-FGXIQQINGITQWRU.EQO@flex--marievic.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-qv1-xf4a.google.com (mail-qv1-xf4a.google.com. [2607:f8b0:4864:20::f4a])
        by gmr-mx.google.com with ESMTPS id 46e09a7af769-741a1ff1a32si887974a34.3.2025.08.11.15.17.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 11 Aug 2025 15:17:58 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3fwyaaagkcaioctkgxkeiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--marievic.bounces.google.com designates 2607:f8b0:4864:20::f4a as permitted sender) client-ip=2607:f8b0:4864:20::f4a;
Received: by mail-qv1-xf4a.google.com with SMTP id 6a1803df08f44-7073f12d546so143136616d6.1
        for <kasan-dev@googlegroups.com>; Mon, 11 Aug 2025 15:17:58 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVNr0BCObmcPdqzFBqP93IzdD+Wd/9Bms76mwYbHKrmKkLyGAiOHinF7f6QKl1WHBDCxo0uTRCh9uc=@googlegroups.com
X-Received: from qvbda12.prod.google.com ([2002:a05:6214:8cc:b0:704:909c:3f3b])
 (user=marievic job=prod-delivery.src-stubby-dispatcher) by
 2002:ad4:5ce5:0:b0:707:5759:848b with SMTP id 6a1803df08f44-709d5c9ef08mr24231676d6.12.1754950677619;
 Mon, 11 Aug 2025 15:17:57 -0700 (PDT)
Date: Mon, 11 Aug 2025 22:17:36 +0000
In-Reply-To: <20250811221739.2694336-1-marievic@google.com>
Mime-Version: 1.0
References: <20250811221739.2694336-1-marievic@google.com>
X-Mailer: git-send-email 2.51.0.rc0.205.g4a044479a3-goog
Message-ID: <20250811221739.2694336-5-marievic@google.com>
Subject: [PATCH v2 4/7] kunit: Enable direct registration of parameter arrays
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
 header.i=@google.com header.s=20230601 header.b=Odu4rTcZ;       spf=pass
 (google.com: domain of 3fwyaaagkcaioctkgxkeiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--marievic.bounces.google.com
 designates 2607:f8b0:4864:20::f4a as permitted sender) smtp.mailfrom=3FWyaaAgKCaIOCTKGXKEIQQING.EQOMCUCP-FGXIQQINGITQWRU.EQO@flex--marievic.bounces.google.com;
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
1.  Defining custom logic within a generate_params()
    function.
2.  Using the KUNIT_ARRAY_PARAM() and KUNIT_ARRAY_PARAM_DESC()
    macros with a pre-defined static array and passing
    the created *_gen_params() to KUNIT_CASE_PARAM().

These methods present limitations when dealing with
dynamically generated parameter arrays, or in scenarios
where populating parameters sequentially via
generate_params() is inefficient or overly complex.

This patch addresses these limitations by adding a new
`params_array` field to `struct kunit`, of the type
`kunit_params`. The `struct kunit_params` is designed to
store the parameter array itself, along with essential metadata
including the parameter count, parameter size, and a
get_description() function for providing custom descriptions
for individual parameters.

The `params_array` field can be populated by calling the new
kunit_register_params_array() macro from within a
param_init() function. This will register the array as part of the
parameterized test context. The user will then need to pass
kunit_array_gen_params() to the KUNIT_CASE_PARAM_WITH_INIT()
macro as the generator function, if not providing their own.
kunit_array_gen_params() is a KUnit helper that will use
the registered array to generate parameters.

The arrays passed to KUNIT_ARRAY_PARAM(,DESC) will also
be registered to the parameterized test context for consistency
as well as for higher availability of the parameter count that
will be used for outputting a KTAP test plan for
a parameterized test.

This modification provides greater flexibility to the
KUnit framework, allowing testers to easily register and
utilize both dynamic and static parameter arrays.

Signed-off-by: Marie Zhussupova <marievic@google.com>
---

Changes in v2:

- If the parameter count is available for a parameterized
  test, the kunit_run_tests() function will now output
  the KTAP test plan for it.
- The name of the struct kunit_params field in struct
  kunit was changed from params_data to params_array.
  This name change better reflects its purpose, which
  is to encapsulate both the parameter array and its
  associated metadata.
- The name of `kunit_get_next_param_and_desc` was changed
  to `kunit_array_gen_params` to make it simpler and to
  better fit its purpose of being KUnit's built-in generator
  function that uses arrays to generate parameters.
- The signature of get_description() in `struct params_array`
  was changed to accept the parameterized test context,
  as well. This way test users can potentially use information
  available in the parameterized test context, such as
  the parameterized test name for setting the parameter
  descriptions.
- The type of `num_params` in `struct params_array` was
  changed from int to size_t for better handling of the
  array size.
- The name of __kunit_init_params() was changed to be
  kunit_init_params(). Logic that sets the get_description()
  function pointer to NULL was also added in there.
- `kunit_array_gen_params` is now exported to make
  it available to use with modules.
- Instead of allowing NULL to be passed in as the
  parameter generator function in the KUNIT_CASE_PARAM_WITH_INIT
  macro, users will now be asked to provide
  `kunit_array_gen_params` as the generator function.
  This will ensure that a parameterized test remains
  defined by the existence of a parameter generation
  function.
- KUNIT_ARRAY_PARAM(,DESC) will now additionally
  register the passed in array in struct kunit_params.
  This will make things more consistent i.e. if a
  parameter array is available then the struct kunit_params
  field in parent struct kunit is populated. Additionally,
  this will increase the availability of the KTAP test plan.
- The comments and the commit message were changed to
  reflect the parameterized testing terminology. See
  the patch series cover letter change log for the
  definitions.

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
index 01b20702a5a2..cbde238ff334 100644
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
@@ -701,6 +727,10 @@ int kunit_run_tests(struct kunit_suite *suite)
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
2.51.0.rc0.205.g4a044479a3-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250811221739.2694336-5-marievic%40google.com.
