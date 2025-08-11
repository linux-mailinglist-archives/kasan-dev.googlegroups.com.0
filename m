Return-Path: <kasan-dev+bncBDQ67ZGAXYCBBLWY5HCAMGQEZQ74ZHI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb40.google.com (mail-yb1-xb40.google.com [IPv6:2607:f8b0:4864:20::b40])
	by mail.lfdr.de (Postfix) with ESMTPS id 70F05B2182B
	for <lists+kasan-dev@lfdr.de>; Tue, 12 Aug 2025 00:18:24 +0200 (CEST)
Received: by mail-yb1-xb40.google.com with SMTP id 3f1490d57ef6-e8d90697a77sf5780806276.0
        for <lists+kasan-dev@lfdr.de>; Mon, 11 Aug 2025 15:18:24 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1754950703; cv=pass;
        d=google.com; s=arc-20240605;
        b=jsdP19de5sNgJacS58On0wmGQMlW3bVTB1xXw6MCf0M9NolyTIPsEiliNiLY0zRtFy
         W2lWcjLjiMIY2CbtmwVcH3pxkaDb3apgFJANbYkO7rcDvku6HIIqP0A0vyonAquaxZTt
         pBSDFax0jp88uIHACC52y/ZwhH92bgVtyp4FEpSsF4CYODIvVRMHwS0FoH35wfEyJzpR
         Di5kAQaZrZQNHqQKyom+7f2LnUksMEIlFmEatVZ6VNTaqn9cLOR6/n/U5KLBo6f3LjEl
         2rYmCPyLbzKz73b7Jg3INEhassPYg5+zUOxabpkrEErKp665rhmBlMnZwbIDRlB9DIce
         2sWw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=I1ySyu7HYcGu9ERXBtKJ3fMB2ztw3Y1+uVjTcwEns/w=;
        fh=dsTIXeYjGtmlut+YjESBk9T+tXOqQZ2W24+0KthyY+I=;
        b=G17nevGh8V3u2EkWHe6GLKdo8nuVa8IM/2SzG+29wee0EHHyzDRZ8JaD+Ek68GWJqO
         ONr2BP2VxXeYFTETwg5d31q1UBhUa571PuZPWHAt7DCTXPmzVbGgynbRQrYMJk6hD+eG
         sd5NkxyoAAEcNoiqQF4nYZP2WJs4NLkZS2tfJRU/2B4AiRiLW+IC1xvFIp8f/D708ytM
         hG8Hbk6Y6uI1OEK7BUf+8U3KzLSjsd3bNYc8/OaURSIE8g5bYq4gJPLSYK/0Z3oqLiMS
         qDTn5a2J/b2fyxVfn2EZC35d4BspgDHOXG37Zo4Y4zSf7O6nbdGHlAHYMsWh1tUMfH4Z
         234g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=UBCcMjvY;
       spf=pass (google.com: domain of 3lgyaaagkcbklzqhduhbfnnfkd.bnljzrzm-cdufnnfkdfqntor.bnl@flex--marievic.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=3LGyaaAgKCbklZqhduhbfnnfkd.bnljZrZm-cdufnnfkdfqntor.bnl@flex--marievic.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1754950703; x=1755555503; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=I1ySyu7HYcGu9ERXBtKJ3fMB2ztw3Y1+uVjTcwEns/w=;
        b=WSBTR5k9T03U3wC4R8WC9SND3wHpCZT00W7MiFppiILtc1CnOhMCRg0JtlqMkBDlDX
         +OZLMqFzCZtOvzjO2TfElwaDQ5PtCgtBJLLQob1jaTFxsTJlYrxjB9KzJQLuE7Z7IitU
         SKKVo7WOucj/7uBUanxq5iGlmmWkuu5StbvMqi2aMoN1Cp2zCa4oci1ZfRpVWxR/DyCp
         1nLd/36ZnO0Z2LCfj4XmD6ApIdmtqq1YFYSsjbH6YUAwEt3Y6cpaEVs1tPYDtZU9Io/E
         +acO5roGTwYWF0RNCejOWQArLodxnmD7Lm15LBJmC0JU93Tb0OZjpiSgR5ZOOvLSvmI6
         V4Fw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1754950703; x=1755555503;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=I1ySyu7HYcGu9ERXBtKJ3fMB2ztw3Y1+uVjTcwEns/w=;
        b=Ildoup6VLVN9HGH36bOEXFWIYRF+aOMMJ/02IJD8Vdro5AvPzdojFupEWL/tkKK4od
         trbqeWrRpwQZxVhYlOdei9FkTeGH9jdyRJzcSdzdjW+hXAP66Q8DfDWuXBfk+y6KBf8k
         CIDIrttnFmuUz1I3Y7pP3E+ZelCCj7JvWVKr4f9Bqcws+oxANQRUN86wfo/4PVVXdYHJ
         5l6IMNgry2PpX2Qfj+VRkcucD6BQoUAnj/ifYUi0SgQzDZGJG7qrSjm918gfveL0UKqS
         IcGgzQbB5HFN3DT1OmPXzqSNpEnXDTPlHEUzgbOTXLbnuN9mgJ7PQaWSNyOfuzyKLADE
         m8QA==
X-Forwarded-Encrypted: i=2; AJvYcCU41Awi7ctdPNGjnlNKpRi5BNdpJ9Uym96PyXd8w/U6WbTb22eyOUGAJ0GHPZWHgKHFqknu/A==@lfdr.de
X-Gm-Message-State: AOJu0YzkgSW6Q3cIvXDeQfOwv+1i8Pzx5xDoXjUOZidFrifiUOd4oMxc
	SnNyd23azAFmW5yKgi5MOzl1ygXQPHDYscPOquQzg3yvpD0BE7DdJ0j1
X-Google-Smtp-Source: AGHT+IE2jv6G4VZ9ch15+abwpI3KKGFc7MSGrUEAcEmrpZMohmSeXQFUwSHrCoQ1qRuMgzUFOGClsw==
X-Received: by 2002:a05:6902:6c14:b0:e8e:d61:a66a with SMTP id 3f1490d57ef6-e904b668394mr15999292276.37.1754950702795;
        Mon, 11 Aug 2025 15:18:22 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZd3BiROHks49YVxf44QgENzj6jcg7ZqAhV5cqPJlDMuUQ==
Received: by 2002:a25:13c3:0:b0:e8f:e27f:b189 with SMTP id 3f1490d57ef6-e917cf9134cls65975276.2.-pod-prod-07-us;
 Mon, 11 Aug 2025 15:18:21 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVAdOuKgZE8/c8KDS2oEpDRsAELAaUJ+doQbZ8GLEWKHFXSiKsn0GfofHkAiFYa+JOv6Ej2kmtSp8U=@googlegroups.com
X-Received: by 2002:a05:690c:4b81:b0:71c:1a46:48ee with SMTP id 00721157ae682-71c1a4652edmr82502017b3.19.1754950701593;
        Mon, 11 Aug 2025 15:18:21 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1754950701; cv=none;
        d=google.com; s=arc-20240605;
        b=TEH5XeV7+GLUjLv/IqZWMI2iXQdYFFL8NfO/R8GlJa2Nf/ZtQ0LEZx0n87eLEql477
         5a5gdpMWg6st0oPfxKLCYmQUubT1K28VtkTYGXFAHnU1vfDq9Yih2LcB6hvMdDZS+EwZ
         PrONOlePRhBjeN7oul7dTx+qpPb3PuBO2zOuQA/u0IO566ubFFnQJQcxeRtb7wcGD3LI
         tELp4mvUaiPenvFGAppeFph22uAV7wSKf/siiLgKXu+5t4KzLPjUhy0oAlZMaxCTgf3k
         XKYuSmV+TMMDBDE4PFQzqGO+8TEjC81YfIhOoirtpNFrvZLLwSDcFkmNwOzlUa9wcqsL
         B7kg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=KJu5ZG1zVtZbmrIPBHBPazK1MeR8D4jv5grkHoZ9tz4=;
        fh=4xktjdaVQhuwdz7W8WXv3jbIebGSGSBg1yAgIEwcilo=;
        b=ImDh4yVQKRsATgRMcpn+/cNLIdcMzK1rKb0FrANsM3dVNrmE9yZMC7Yh2zhu2tBZ5+
         ulxjH6iEC8xAV32cLtIKMWlOrCkzVKwhBu3MwqAT0xvLqtBVKrUKJNQ9cUi3FK5FXadQ
         Y6Kfbkqum/ckP3+WbX/xDLfLJyOBqCNhZQ30l3Kuglw65hzJ5Y2mFc3Il8VHeMqlGmog
         UCV+nZaTXxTesz5fDj9Mtc9Ognh/iGNY/qov38xQ8P8FgaOoWBCP55Exu58j2xTajuO4
         zJehqoY0LWHc+JGI231MKlyu6O8M0siXJrwu3LJ9FmDn+8OMeti+Has0sJX1tYj2u65j
         BVRQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=UBCcMjvY;
       spf=pass (google.com: domain of 3lgyaaagkcbklzqhduhbfnnfkd.bnljzrzm-cdufnnfkdfqntor.bnl@flex--marievic.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=3LGyaaAgKCbklZqhduhbfnnfkd.bnljZrZm-cdufnnfkdfqntor.bnl@flex--marievic.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-qk1-x74a.google.com (mail-qk1-x74a.google.com. [2607:f8b0:4864:20::74a])
        by gmr-mx.google.com with ESMTPS id 00721157ae682-71c0a1cc669si2425037b3.1.2025.08.11.15.18.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 11 Aug 2025 15:18:21 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3lgyaaagkcbklzqhduhbfnnfkd.bnljzrzm-cdufnnfkdfqntor.bnl@flex--marievic.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) client-ip=2607:f8b0:4864:20::74a;
Received: by mail-qk1-x74a.google.com with SMTP id af79cd13be357-7e82a101470so905035185a.0
        for <kasan-dev@googlegroups.com>; Mon, 11 Aug 2025 15:18:21 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVe1W7u0K4SKQo0Wb3vWQe5tJY3oH1+k9x3Psb8i0fNZ2X8IgdKGgNPTI6RHkryKkwC1G2+AHBdbF0=@googlegroups.com
X-Received: from qkhp17.prod.google.com ([2002:a05:620a:22b1:b0:7e8:5a80:9ec9])
 (user=marievic job=prod-delivery.src-stubby-dispatcher) by
 2002:a05:620a:126e:b0:7d4:5db0:5b95 with SMTP id af79cd13be357-7e8588d41ecmr186321185a.58.1754950700946;
 Mon, 11 Aug 2025 15:18:20 -0700 (PDT)
Date: Mon, 11 Aug 2025 22:17:39 +0000
In-Reply-To: <20250811221739.2694336-1-marievic@google.com>
Mime-Version: 1.0
References: <20250811221739.2694336-1-marievic@google.com>
X-Mailer: git-send-email 2.51.0.rc0.205.g4a044479a3-goog
Message-ID: <20250811221739.2694336-8-marievic@google.com>
Subject: [PATCH v2 7/7] Documentation: kunit: Document new parameterized test features
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
 header.i=@google.com header.s=20230601 header.b=UBCcMjvY;       spf=pass
 (google.com: domain of 3lgyaaagkcbklzqhduhbfnnfkd.bnljzrzm-cdufnnfkdfqntor.bnl@flex--marievic.bounces.google.com
 designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=3LGyaaAgKCbklZqhduhbfnnfkd.bnljZrZm-cdufnnfkdfqntor.bnl@flex--marievic.bounces.google.com;
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

This patch updates the KUnit docs to show how to use the new
parameterized test context to share resources
between parameter runs. It documents and show examples
of different ways the test user can pass parameter
arrays to a parameterized test. Finally, it specifies the
parameterized testing terminology.

Signed-off-by: Marie Zhussupova <marievic@google.com>
---

Changes in v2:

- The documentation was updated to establish the parameterized
  testing terminology and reflect all the patch series changes.
- The references to other parts of the KUnit Documentation were
  not changed from being "Documentation/dev-tools/kunit/api/test.rst"
  to ":ref:`kunit-resource`" links as originally planned. This is
  because the existing way shows up as a link to a webpage and it
  would be hard for people reading the documentation as an .rst
  file to find the referred section without having the file path.
- The code examples were made more concise.
- Minor edits to titles and formatting.

---
 Documentation/dev-tools/kunit/usage.rst | 342 +++++++++++++++++++++++-
 1 file changed, 336 insertions(+), 6 deletions(-)

diff --git a/Documentation/dev-tools/kunit/usage.rst b/Documentation/dev-tools/kunit/usage.rst
index 066ecda1dd98..b236bb07aaca 100644
--- a/Documentation/dev-tools/kunit/usage.rst
+++ b/Documentation/dev-tools/kunit/usage.rst
@@ -542,11 +542,29 @@ There is more boilerplate code involved, but it can:
 Parameterized Testing
 ~~~~~~~~~~~~~~~~~~~~~
 
-The table-driven testing pattern is common enough that KUnit has special
-support for it.
-
-By reusing the same ``cases`` array from above, we can write the test as a
-"parameterized test" with the following.
+To run a test case against multiple inputs, KUnit provides a parameterized
+testing framework. This feature formalizes and extends the concept of
+table-driven tests discussed previously. A KUnit test is determined to be
+parameterized if a parameter generator function is provided when registering
+the test case.
+
+To establish the terminology, "parameterized test" refers to the group of all
+runs of a single test function with different parameters. "Parameter run" refers
+to the execution of the test case function with a single parameter.
+"Parameterized test context" is the ``struct kunit`` that holds the
+context for the entire parameterized test. Finally, "parameter run context" is
+the ``struct kunit`` that holds the context of the individual parameter run.
+
+Passing Parameters to a Test
+^^^^^^^^^^^^^^^^^^^^^^^^^^^^
+There are three ways to provide the parameters to a test:
+
+Array Parameter Macros:
+
+   KUnit provides special support for the common table-driven testing pattern.
+   By applying either ``KUNIT_ARRAY_PARAM`` or ``KUNIT_ARRAY_PARAM_DESC`` to the
+   ``cases`` array from the previous section, we can create a parameterized test
+   as shown below:
 
 .. code-block:: c
 
@@ -555,7 +573,7 @@ By reusing the same ``cases`` array from above, we can write the test as a
 		const char *str;
 		const char *sha1;
 	};
-	const struct sha1_test_case cases[] = {
+	static const struct sha1_test_case cases[] = {
 		{
 			.str = "hello world",
 			.sha1 = "2aae6c35c94fcfb415dbe95f408b9ce91ee846ed",
@@ -590,6 +608,318 @@ By reusing the same ``cases`` array from above, we can write the test as a
 		{}
 	};
 
+Custom Parameter Generator Function:
+
+   The generator function is responsible for generating parameters one-by-one
+   and has the following signature:
+   ``const void* (*)(struct kunit *test, const void *prev, char *desc)``.
+   You can pass the generator function to the ``KUNIT_CASE_PARAM``
+   or ``KUNIT_CASE_PARAM_WITH_INIT`` macros.
+
+   The function receives the previously generated parameter as the ``prev`` argument
+   (which is ``NULL`` on the first call) and can also access the parameterized
+   test context passed as the ``test`` argument. KUnit calls this function
+   repeatedly until it returns ``NULL``, which signifies that a parameterized
+   test ended.
+
+   Below is an example of how it works:
+
+.. code-block:: c
+
+	#define MAX_TEST_BUFFER_SIZE 8
+
+	// Example generator function. It produces a sequence of buffer sizes that
+	// are powers of two, starting at 1 (e.g., 1, 2, 4, 8).
+	static const void *buffer_size_gen_params(struct kunit *test, const void *prev, char *desc)
+	{
+		long prev_buffer_size = (long)prev;
+		long next_buffer_size = 1; // Start with an initial size of 1.
+
+		// Stop generating parameters if the limit is reached or exceeded.
+		if (prev_buffer_size >= MAX_TEST_BUFFER_SIZE)
+			return NULL;
+
+		// For subsequent calls, calculate the next size by doubling the previous one.
+		if (prev)
+			next_buffer_size = prev_buffer_size << 1;
+
+		return (void *)next_buffer_size;
+	}
+
+	// Simple test to validate that kunit_kzalloc provides zeroed memory.
+	static void buffer_zero_test(struct kunit *test)
+	{
+		long buffer_size = (long)test->param_value;
+		// Use kunit_kzalloc to allocate a zero-initialized buffer. This makes the
+		// memory "parameter run managed," meaning it's automatically cleaned up at
+		// the end of each parameter run.
+		int *buf = kunit_kzalloc(test, buffer_size * sizeof(int), GFP_KERNEL);
+
+		// Ensure the allocation was successful.
+		KUNIT_ASSERT_NOT_NULL(test, buf);
+
+		// Loop through the buffer and confirm every element is zero.
+		for (int i = 0; i < buffer_size; i++)
+			KUNIT_EXPECT_EQ(test, buf[i], 0);
+	}
+
+	static struct kunit_case buffer_test_cases[] = {
+		KUNIT_CASE_PARAM(buffer_zero_test, buffer_size_gen_params),
+		{}
+	};
+
+Runtime Parameter Array Registration in the Init Function:
+
+   For more complex scenarios, you can directly register a parameter array
+   to the parameterized test context.
+
+   To do this, you must pass the parameterized test context, the array itself,
+   the array size, and a ``get_description()`` function to the
+   ``kunit_register_params_array()`` macro. This macro populates
+   ``struct kunit_params`` within the parameterized test context, effectively
+   storing a parameter array object. The ``get_description()`` function will
+   be used for populating parameter descriptions and has the following signature:
+   ``void (*)(struct kunit *test, const void *param, char *desc)``. Note that it
+   also has access to the parameterized test context.
+
+      .. important::
+         When using this way to register a parameter array, you will need to
+         manually pass ``kunit_array_gen_params()`` as the generator function to
+         ``KUNIT_CASE_PARAM_WITH_INIT``. ``kunit_array_gen_params()`` is a KUnit
+         helper that will use the registered array to generate the parameters.
+
+	 If needed, instead of passing the KUnit helper, you can also pass your
+	 own custom generator function that utilizes the parameter array. To
+	 access the parameter array from within the parameter generator
+	 function use ``test->params_array.params``.
+
+   The ``kunit_register_params_array()`` macro should be called within a
+   ``param_init()`` function that initializes the parameterized test and has
+   the following signature ``int (*)(struct kunit *test)``. For a detailed
+   explanation of this mechanism please refer to the "Adding Shared Resources"
+   section that is after this one. This method supports registering both
+   dynamically built and static parameter arrays.
+
+   The code snippet below shows the ``example_param_init_dynamic_arr`` test that
+   utilizes ``make_fibonacci_params()`` to create a dynamic array, which is then
+   registered using ``kunit_register_params_array()``. To see the full code
+   please refer to lib/kunit/kunit-example-test.c starting at line 396.
+
+.. code-block:: c
+
+	/*
+	* Example of a parameterized test param_init() function that registers a dynamic
+	* array of parameters.
+	*/
+	static int example_param_init_dynamic_arr(struct kunit *test)
+	{
+		size_t seq_size;
+		int *fibonacci_params;
+
+		kunit_info(test, "initializing parameterized test\n");
+
+		seq_size = 6;
+		fibonacci_params = make_fibonacci_params(test, seq_size);
+		if (!fibonacci_params)
+			return -ENOMEM;
+		/*
+		* Passes the dynamic parameter array information to the parameterized test
+		* context struct kunit. The array and its metadata will be stored in
+		* test->parent->params_array. The array itself will be located in
+		* params_data.params.
+		*/
+		kunit_register_params_array(test, fibonacci_params, seq_size,
+					example_param_dynamic_arr_get_desc);
+		return 0;
+	}
+
+	static struct kunit_case example_test_cases[] = {
+		/*
+		 * Note how we pass kunit_array_gen_params() to use the array we
+		 * registered in example_param_init_dynamic_arr() to generate
+		 * parameters.
+		 */
+		KUNIT_CASE_PARAM_WITH_INIT(example_params_test_with_init_dynamic_arr,
+					   kunit_array_gen_params,
+					   example_param_init_dynamic_arr,
+					   example_param_exit_dynamic_arr),
+		{}
+	};
+
+Adding Shared Resources
+^^^^^^^^^^^^^^^^^^^^^^^
+All parameter runs in this framework hold a reference to the parameterized test
+context, which can be accessed using the parent ``struct kunit`` pointer. The
+parameterized test context is not used to execute any test logic itself; instead,
+it serves as a container for shared resources.
+
+It's possible to add resources to share between parameter runs within a
+parameterized test by using ``KUNIT_CASE_PARAM_WITH_INIT``, to which you pass
+custom ``param_init()`` and ``param_exit()`` functions. These functions run once
+before and once after the parameterized test, respectively.
+
+The ``param_init()`` function, with the signature ``int (*)(struct kunit *test)``,
+can be used for adding resources to the ``resources`` or ``priv`` fields of
+the parameterized test context, registering the parameter array, and any other
+initialization logic.
+
+The ``param_exit()`` function, with the signature ``void (*)(struct kunit *test)``,
+can be used to release any resources that were not parameterized test managed (i.e.
+not automatically cleaned up after the parameterized test ends) and for any other
+exit logic.
+
+Both ``param_init()`` and ``param_exit()`` are passed the parameterized test
+context behind the scenes. However, the test case function receives the parameter
+run context. Therefore, to manage and access shared resources from within a test
+case function, you must use ``test->parent``.
+
+For instance, finding a shared resource allocated by the Resource API requires
+passing ``test->parent`` to ``kunit_find_resource()``. This principle extends to
+all other APIs that might be used in the test case function, including
+``kunit_kzalloc()``, ``kunit_kmalloc_array()``, and others (see
+Documentation/dev-tools/kunit/api/test.rst and the
+Documentation/dev-tools/kunit/api/resource.rst).
+
+.. note::
+   The ``suite->init()`` function, which executes before each parameter run,
+   receives the parameter run context. Therefore, any resources set up in
+   ``suite->init()`` are cleaned up after each parameter run.
+
+The code below shows how you can add the shared resources. Note that this code
+utilizes the Resource API, which you can read more about here:
+Documentation/dev-tools/kunit/api/resource.rst. To see the full version of this
+code please refer to lib/kunit/kunit-example-test.c starting at line 280.
+
+.. code-block:: c
+
+	static int example_resource_init(struct kunit_resource *res, void *context)
+	{
+		... /* Code that allocates memory and stores context in res->data. */
+	}
+
+	/* This function deallocates memory for the kunit_resource->data field. */
+	static void example_resource_free(struct kunit_resource *res)
+	{
+		kfree(res->data);
+	}
+
+	/* This match function locates a test resource based on defined criteria. */
+	static bool example_resource_alloc_match(struct kunit *test, struct kunit_resource *res,
+						 void *match_data)
+	{
+		return res->data && res->free == example_resource_free;
+	}
+
+	/* Function to initialize the parameterized test. */
+	static int example_param_init(struct kunit *test)
+	{
+		int ctx = 3; /* Data to be stored. */
+		void *data = kunit_alloc_resource(test, example_resource_init,
+						  example_resource_free,
+						  GFP_KERNEL, &ctx);
+		if (!data)
+			return -ENOMEM;
+		kunit_register_params_array(test, example_params_array,
+					    ARRAY_SIZE(example_params_array));
+		return 0;
+	}
+
+	/* Example test that uses shared resources in test->resources. */
+	static void example_params_test_with_init(struct kunit *test)
+	{
+		int threshold;
+		const struct example_param *param = test->param_value;
+		/*  Here we pass test->parent to access the parameterized test context. */
+		struct kunit_resource *res = kunit_find_resource(test->parent,
+								 example_resource_alloc_match,
+								 NULL);
+
+		threshold = *((int *)res->data);
+		KUNIT_ASSERT_LE(test, param->value, threshold);
+		kunit_put_resource(res);
+	}
+
+	static struct kunit_case example_test_cases[] = {
+		KUNIT_CASE_PARAM_WITH_INIT(example_params_test_with_init, kunit_array_gen_params,
+					   example_param_init, NULL),
+		{}
+	};
+
+As an alternative to using the KUnit Resource API for sharing resources, you can
+place them in ``test->parent->priv``. This serves as a more lightweight method
+for resource storage, best for scenarios where complex resource management is
+not required.
+
+As stated previously ``param_init()`` and ``param_exit()`` get the parameterized
+test context. So, you can directly use ``test->priv`` within ``param_init/exit``
+to manage shared resources. However, from within the test case function, you must
+navigate up to the parent ``struct kunit`` i.e. the parameterized test context.
+Therefore, you need to use ``test->parent->priv`` to access those same
+resources.
+
+The resources placed in ``test->parent->priv`` will need to be allocated in
+memory to persist across the parameter runs. If memory is allocated using the
+KUnit memory allocation APIs (described more in the "Allocating Memory" section
+below), you won't need to worry about deallocation. The APIs will make the memory
+parameterized test 'managed', ensuring that it will automatically get cleaned up
+after the parameterized test concludes.
+
+The code below demonstrates example usage of the ``priv`` field for shared
+resources:
+
+.. code-block:: c
+
+	static const struct example_param {
+		int value;
+	} example_params_array[] = {
+		{ .value = 3, },
+		{ .value = 2, },
+		{ .value = 1, },
+		{ .value = 0, },
+	};
+
+	/* Initialize the parameterized test context. */
+	static int example_param_init_priv(struct kunit *test)
+	{
+		int ctx = 3; /* Data to be stored. */
+		int arr_size = ARRAY_SIZE(example_params_array);
+
+		/*
+		 * Allocate memory using kunit_kzalloc(). Since the `param_init`
+		 * function receives the parameterized test context, this memory
+		 * allocation will be scoped to the lifetime of the parameterized test.
+		 */
+		test->priv = kunit_kzalloc(test, sizeof(int), GFP_KERNEL);
+
+		/* Assign the context value to test->priv.*/
+		*((int *)test->priv) = ctx;
+
+		/* Register the parameter array. */
+		kunit_register_params_array(test, example_params_array, arr_size, NULL);
+		return 0;
+	}
+
+	static void example_params_test_with_init_priv(struct kunit *test)
+	{
+		int threshold;
+		const struct example_param *param = test->param_value;
+
+		/* By design, test->parent will not be NULL. */
+		KUNIT_ASSERT_NOT_NULL(test, test->parent);
+
+		/* Here we use test->parent->priv to access the shared resource. */
+		threshold = *(int *)test->parent->priv;
+
+		KUNIT_ASSERT_LE(test, param->value, threshold);
+	}
+
+	static struct kunit_case example_tests[] = {
+		KUNIT_CASE_PARAM_WITH_INIT(example_params_test_with_init_priv,
+					   kunit_array_gen_params,
+					   example_param_init_priv, NULL),
+		{}
+	};
+
 Allocating Memory
 -----------------
 
-- 
2.51.0.rc0.205.g4a044479a3-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250811221739.2694336-8-marievic%40google.com.
