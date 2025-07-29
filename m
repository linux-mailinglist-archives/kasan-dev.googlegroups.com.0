Return-Path: <kasan-dev+bncBDQ67ZGAXYCBBAWGUTCAMGQESBNCIYA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13e.google.com (mail-il1-x13e.google.com [IPv6:2607:f8b0:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id 260C0B15398
	for <lists+kasan-dev@lfdr.de>; Tue, 29 Jul 2025 21:37:40 +0200 (CEST)
Received: by mail-il1-x13e.google.com with SMTP id e9e14a558f8ab-3e3ed8b5d05sf2795805ab.0
        for <lists+kasan-dev@lfdr.de>; Tue, 29 Jul 2025 12:37:40 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1753817859; cv=pass;
        d=google.com; s=arc-20240605;
        b=b3i649Xyz5A8TTvIPvq2Fgo17lJ1VnZGgfmjLsv+SCTnwMDAjPUbAj7VgGyOwGuKJW
         J5bdq1VaGHCFORpZ+/3tjfujgbXtsoNrU/ClYjo04dqnbTUyrZ7TXmMa0ohqa5JPMzU2
         S/jy34QRtguFwG3F+34gQMj/KkgtexeT37s+F+mfRLhXl6bckkIRDYtLjXdVKg21L2rW
         W6cb6t642imOBLKOp6luP+YX6mYOW/Ac42QHEF0QOJJrDPgrZjFsk4EIeiM6IpsWyI5Y
         EfuYiG443Id/XQyhka5EuhvJeTUvnBO7vxZkTlMwhYrAB9lk/EiXTUnHlyXkAifNhpLd
         PShg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=a5EyPOPUHLmxIWaZdC0Q9zcukJqu54BIjSo0+QUIRWY=;
        fh=y3hsgE4HVNsRcjPiMSUiUi4+yzxnueVoniTr67xmX4g=;
        b=DH1KdxSPxeozI0pEPCFqAsHw2aY/LdPu/f1jVtrL0IEM+gq7YppW2A4nAyocB6mpNv
         FyhfcxWqyA8Df+DwatA+m1U31z20+NeSWFYjvc72L1MHTDD92NqQl6gJ9jy8eqgV8uf6
         fDcQ7UtV891DjZOgUX/A0lb/FaovyIZPDEDJBSLfcdSFRHJtANzcQ+1WVHJ3xn8XdkuV
         WOLPIsgdOliXCoWpMqV76oIqVdTXcmKuvasPVMAiOA6jQ8R4tYOhA/HmU1ma5gJNvYwz
         UWuCRMa3cFp39oLlUNBpvkdFLAHgfGFxhY14u3crPRFrY9KIepG7+4LuEUPJeKDgGR6u
         z2OQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="e/spIZTK";
       spf=pass (google.com: domain of 3asojaagkcbyiwneareyckkcha.ykigwowj-zarckkchacnkqlo.yki@flex--marievic.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=3ASOJaAgKCbYiWneareYckkcha.YkigWoWj-Zarckkchacnkqlo.Yki@flex--marievic.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1753817859; x=1754422659; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=a5EyPOPUHLmxIWaZdC0Q9zcukJqu54BIjSo0+QUIRWY=;
        b=Z8kW6KReV8TDWbwlzkCn03iZJeL+YfGEkS62X7JFm7vJqR8LoE+eoekFr+L5DSd2yc
         YSM0lINpsUTHoe1owipvdvyYNUWMurYE9kQPcdnDlbT1Z8jkWNmhbDXaKo3ppcAyrGqF
         i7sjpM92bzHkVSPBmm4q3sTt0ABKFIRuN+6BAHA8bhwpX9qT38an09BnIwBTWlUXnUZg
         KRWcqUCpJzOiOI0vqn/Su8kCFpnyyMvwDc0vTnGrHyYwI8qYb/fyRjVht1oG1SUAyjmb
         liaB7xf5NGmJiv/E9maSuBFoOIlL8Ey7F3vowdcwgPkU+M17dPLJHQ53tDGaFc8Dae+6
         5FyQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1753817859; x=1754422659;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=a5EyPOPUHLmxIWaZdC0Q9zcukJqu54BIjSo0+QUIRWY=;
        b=orj6GPK7pi8KsLsDKi6JlItxna+pZQsAPtckFcG4LeyhgcaetpWnQSYFM1+ZC287Xd
         KDaJs+a0HpPP0odPNNtr50rAjYQQ53+cBUrgqnKbX32esNZoQO+K2xPaLjBsb2mWFc32
         TbMSJxT3i99UYRcRymHJI/XUCPRtTiBEwTpduKh4emnasDaA43zxuXM0v40S/xOxtfrm
         NQRBPZxNIDEBtAD8LHuWBpsUmmSheH/0zByk5wEq7fmKjB5Xis5oBfWq7K8IiFohQGlv
         2aLZBYX9kT6oXDOMmEQj9yppd4PwTIIimAUXJ/gmta1zIPinkXV9y4y1sAAFrK6Fzclr
         Oarw==
X-Forwarded-Encrypted: i=2; AJvYcCVo3IBd+O8Yyy27rdAfgRkiI7VjnQqjnMwj5tosaTmF6vZoV7eKn/cKdp+QBZZuwobLVxrR1w==@lfdr.de
X-Gm-Message-State: AOJu0Yz/L0+jD53XIwJJIwQIxrGQ8aIQ9svn5ExdxO6kNv/T/6fC1eGW
	CSvJ7OO7UD/NrAuXuSlej+8Bx4T95Lkfd4IHRv3DkDC4iq9LIXUTw8ET
X-Google-Smtp-Source: AGHT+IH17gWYYRH2iujLdKvT/XvtijVp16LDblDk8KUqE60McEzGZUmyRrUiavRGnp4l6yrGYiB6/w==
X-Received: by 2002:a05:6e02:338f:b0:3e3:f47e:815e with SMTP id e9e14a558f8ab-3e3f62a412cmr9854255ab.6.1753817858823;
        Tue, 29 Jul 2025 12:37:38 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdx+OzMqzs+C5W8OsKski1PoTABeVcMBkZmBMgMBH9NcQ==
Received: by 2002:a05:6e02:10d3:b0:3dd:a103:6762 with SMTP id
 e9e14a558f8ab-3e3f67ab6a3ls678465ab.2.-pod-prod-00-us; Tue, 29 Jul 2025
 12:37:38 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXtg4R4QwI+vo4BwP+yrho6fNDJ5L2Pm1YYU12f1arplTqfJtt8CJEr038Phi2Y5xf3iQNcjUCBI5c=@googlegroups.com
X-Received: by 2002:a05:6e02:19ce:b0:3e3:ed80:843f with SMTP id e9e14a558f8ab-3e3f62bdc32mr10658045ab.9.1753817857951;
        Tue, 29 Jul 2025 12:37:37 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1753817857; cv=none;
        d=google.com; s=arc-20240605;
        b=azkJup7kep24OmHucQPNSlVjxRIBdMKsi81PzDzy7RuxK5Ni+vVD3+Dyz+jd4h+bCk
         ivplJ0W1Mq7+T+k7JGCraRnqCru2tys0ibCAE3cOnpW8m+NsSDwuLQUwtO/KMRWOxOla
         NoE+gVRLiWzm3P5dbyEmf5SwBs/xTVAnqYQqNziLx6qFhDM3vK6sWhKG4ltxzbR6+ag5
         E+L6Vcv9PmfuF23ARm2FhQUU+sbLjQZueLP5QqzLWMEetWc9g4JMbuycj0UUJDCNxtMW
         xkBIVQ0wfjoARYoDHhJIV5SNTk1XN5OjeODooT9+PZBUcFkb21kPe2UTdlw3W3O6r0zX
         QxoA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=FE6RrLniApVoy+rkPyhu2vo0lMS/eDyyytX43V/mIbA=;
        fh=SMJai19gQF7HIHMdfmyg6/+P8gh8cCsCL+xUCVQz1OY=;
        b=J1w2AS6lgz+Dwubu9B07vc4gkdwqhPpCcu3zEP7rFgcGTgzw0NXfdMapgbQ9D9Mgs+
         LcxaE0t2bpwMgIyDoCll5vgEI6/XnUID1wIxgClHjnutGPvs04cMP3emY7j9WiadX62G
         GZw/C3dtFz4Av6spNA3AFWhOTjMZgol8HZ7MS3wJJwjznlgE7oy7w8yIGt5pcOulX3WE
         +2f9xqTyI4u4jIuGVhKuhash/5alPXPl/NclGH23fAO4r17mkAoKMOxzraGjgcxVHItv
         ddv+5MkmONWC89QaU/Nd0wRvrTMPYNrUFEtVx959vkjTAC/BQo43qSUq99ECnwO9NSS8
         PhQg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="e/spIZTK";
       spf=pass (google.com: domain of 3asojaagkcbyiwneareyckkcha.ykigwowj-zarckkchacnkqlo.yki@flex--marievic.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=3ASOJaAgKCbYiWneareYckkcha.YkigWoWj-Zarckkchacnkqlo.Yki@flex--marievic.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-qk1-x749.google.com (mail-qk1-x749.google.com. [2607:f8b0:4864:20::749])
        by gmr-mx.google.com with ESMTPS id e9e14a558f8ab-3e3ca84dc9asi6620415ab.2.2025.07.29.12.37.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 29 Jul 2025 12:37:37 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3asojaagkcbyiwneareyckkcha.ykigwowj-zarckkchacnkqlo.yki@flex--marievic.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) client-ip=2607:f8b0:4864:20::749;
Received: by mail-qk1-x749.google.com with SMTP id af79cd13be357-7e33d32c501so1505823985a.3
        for <kasan-dev@googlegroups.com>; Tue, 29 Jul 2025 12:37:37 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXil9HnZ6R647yBrMdWnFWJtpf+oFR0QzCOvwu634enesRGTBshVX5aQg8CC2QH8YFqyWIf0VG0Uaw=@googlegroups.com
X-Received: from qktt8.prod.google.com ([2002:a05:620a:48:b0:7e3:512b:f2b4])
 (user=marievic job=prod-delivery.src-stubby-dispatcher) by
 2002:a05:620a:3951:b0:7e0:c0a0:c68b with SMTP id af79cd13be357-7e66ef716bamr109499885a.10.1753817857244;
 Tue, 29 Jul 2025 12:37:37 -0700 (PDT)
Date: Tue, 29 Jul 2025 19:36:47 +0000
In-Reply-To: <20250729193647.3410634-1-marievic@google.com>
Mime-Version: 1.0
References: <20250729193647.3410634-1-marievic@google.com>
X-Mailer: git-send-email 2.50.1.552.g942d659e1b-goog
Message-ID: <20250729193647.3410634-10-marievic@google.com>
Subject: [PATCH 9/9] Documentation: kunit: Document new parameterized test features
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
 header.i=@google.com header.s=20230601 header.b="e/spIZTK";       spf=pass
 (google.com: domain of 3asojaagkcbyiwneareyckkcha.ykigwowj-zarckkchacnkqlo.yki@flex--marievic.bounces.google.com
 designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=3ASOJaAgKCbYiWneareYckkcha.YkigWoWj-Zarckkchacnkqlo.Yki@flex--marievic.bounces.google.com;
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

-Update the KUnit documentation to explain the concept
of a parent parameterized test.
-Add examples demonstrating different ways of passing
parameters to parameterized tests and how to manage
shared resources between them.

Signed-off-by: Marie Zhussupova <marievic@google.com>
---
 Documentation/dev-tools/kunit/usage.rst | 455 +++++++++++++++++++++++-
 1 file changed, 449 insertions(+), 6 deletions(-)

diff --git a/Documentation/dev-tools/kunit/usage.rst b/Documentation/dev-tools/kunit/usage.rst
index 066ecda1dd98..be1d656053cf 100644
--- a/Documentation/dev-tools/kunit/usage.rst
+++ b/Documentation/dev-tools/kunit/usage.rst
@@ -542,11 +542,21 @@ There is more boilerplate code involved, but it can:
 Parameterized Testing
 ~~~~~~~~~~~~~~~~~~~~~
 
-The table-driven testing pattern is common enough that KUnit has special
-support for it.
-
-By reusing the same ``cases`` array from above, we can write the test as a
-"parameterized test" with the following.
+To efficiently and elegantly validate a test case against a variety of inputs,
+KUnit also provides a parameterized testing framework. This feature formalizes
+and extends the concept of table-driven tests discussed previously, offering
+a more integrated and flexible way to handle multiple test scenarios with
+minimal code duplication.
+
+Passing Parameters to the Test Cases
+^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
+There are three main ways to provide the parameters to a test case:
+
+Array Parameter Macros (``KUNIT_ARRAY_PARAM`` or ``KUNIT_ARRAY_PARAM_DESC``):
+   KUnit provides special support for the common table-driven testing pattern.
+   By applying either ``KUNIT_ARRAY_PARAM`` or ``KUNIT_ARRAY_PARAM_DESC`` to the
+   ``cases`` array from the previous section, we can create a parameterized test
+   as shown below:
 
 .. code-block:: c
 
@@ -555,7 +565,7 @@ By reusing the same ``cases`` array from above, we can write the test as a
 		const char *str;
 		const char *sha1;
 	};
-	const struct sha1_test_case cases[] = {
+	static const struct sha1_test_case cases[] = {
 		{
 			.str = "hello world",
 			.sha1 = "2aae6c35c94fcfb415dbe95f408b9ce91ee846ed",
@@ -590,6 +600,439 @@ By reusing the same ``cases`` array from above, we can write the test as a
 		{}
 	};
 
+Custom Parameter Generator (``generate_params``):
+   You can pass your own ``generate_params`` function to the ``KUNIT_CASE_PARAM``
+   or ``KUNIT_CASE_PARAM_WITH_INIT`` macros. This function is responsible for
+   generating parameters one by one. It receives the previously generated parameter
+   as the ``prev`` argument (which is ``NULL`` on the first call) and can also
+   access any context available from the parent ``struct kunit`` passed as the
+   ``test`` argument. KUnit calls this function repeatedly until it returns
+   ``NULL``. Below is an example of how it works:
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
+		// memory "parameter managed," meaning it's automatically cleaned up at
+		// the end of each parameter execution.
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
+Direct Registration in Parameter Init Function (using ``kunit_register_params_array``):
+   For more complex scenarios, you can directly register a parameter array with
+   a test case instead of using a ``generate_params`` function. This is done by
+   passing the array to the ``kunit_register_params_array`` macro within an
+   initialization function for the parameterized test series
+   (i.e., a function named ``param_init``). To better understand this mechanism
+   please refer to the "Adding Shared Resources" section below.
+
+   This method supports both dynamically built and static arrays.
+
+   As the following code shows, the ``example_param_init_dynamic_arr`` function
+   utilizes ``make_fibonacci_params`` to create a dynamic array, which is then
+   registered using ``kunit_register_params_array``. The corresponding exit
+   function, ``example_param_exit``, is responsible for freeing this dynamically
+   allocated params array after the parameterized test series ends.
+
+.. code-block:: c
+
+	/*
+	 * Helper function to create a parameter array of Fibonacci numbers. This example
+	 * highlights a parameter generation scenario that is:
+	 * 1. Not feasible to fully pre-generate at compile time.
+	 * 2. Challenging to implement with a standard 'generate_params' function,
+	 * as it typically only provides the immediately 'prev' parameter, while
+	 * Fibonacci requires access to two preceding values for calculation.
+	 */
+	static void *make_fibonacci_params(int seq_size)
+	{
+		int *seq;
+
+		if (seq_size <= 0)
+			return NULL;
+
+		seq = kmalloc_array(seq_size, sizeof(int), GFP_KERNEL);
+
+		if (!seq)
+			return NULL;
+
+		if (seq_size >= 1)
+			seq[0] = 0;
+		if (seq_size >= 2)
+			seq[1] = 1;
+		for (int i = 2; i < seq_size; i++)
+			seq[i] = seq[i - 1] + seq[i - 2];
+		return seq;
+	}
+
+	// This is an example of a function that provides a description for each of the
+	// parameters.
+	static void example_param_dynamic_arr_get_desc(const void *p, char *desc)
+	{
+		const int *fib_num = p;
+
+		snprintf(desc, KUNIT_PARAM_DESC_SIZE, "fibonacci param: %d", *fib_num);
+	}
+
+	// Example of a parameterized test init function that registers a dynamic array.
+	static int example_param_init_dynamic_arr(struct kunit *test)
+	{
+		int seq_size = 6;
+		int *fibonacci_params = make_fibonacci_params(seq_size);
+
+		if (!fibonacci_params)
+			return -ENOMEM;
+
+		/*
+		 * Passes the dynamic parameter array information to the parent struct kunit.
+		 * The array and its metadata will be stored in test->parent->params_data.
+		 * The array itself will be located in params_data.params.
+		 */
+		kunit_register_params_array(test, fibonacci_params, seq_size,
+					    example_param_dynamic_arr_get_desc);
+		return 0;
+	}
+
+	// Function to clean up the parameterized test's parent kunit struct if
+	// there were custom allocations.
+	static void example_param_exit_dynamic_arr(struct kunit *test)
+	{
+		/*
+		 * We allocated this array, so we need to free it.
+		 * Since the parent parameter instance is passed here,
+		 * we can directly access the array via `test->params_data.params`
+		 * instead of `test->parent->params_data.params`.
+		 */
+		kfree(test->params_data.params);
+	}
+
+	/*
+	 * Example of test that uses the registered dynamic array to perform assertions
+	 * and expectations.
+	 */
+	static void example_params_test_with_init_dynamic_arr(struct kunit *test)
+	{
+		const int *param = test->param_value;
+		int param_val;
+
+		/* By design, param pointer will not be NULL. */
+		KUNIT_ASSERT_NOT_NULL(test, param);
+
+		param_val = *param;
+		KUNIT_EXPECT_EQ(test, param_val - param_val, 0);
+	}
+
+	static struct kunit_case example_tests[] = {
+		// The NULL here stands in for the generate_params function
+		KUNIT_CASE_PARAM_WITH_INIT(example_params_test_with_init_dynamic_arr, NULL,
+					   example_param_init_dynamic_arr,
+					   example_param_exit_dynamic_arr),
+		{}
+	};
+
+
+Adding Shared Resources
+^^^^^^^^^^^^^^^^^^^^^^^
+All parameterized test executions in this framework have a parent test of type
+``struct kunit``. This parent is not used to execute any test logic itself;
+instead, it serves as a container for shared context that can be accessed by
+all its individual test executions (or parameters). Therefore, each individual
+test execution holds a pointer to this parent, accessible via a field named
+``parent``.
+
+It's possible to add resources to share between the individual test executions
+within a parameterized test series by using the ``KUNIT_CASE_PARAM_WITH_INIT``
+macro, to which you pass custom ``param_init`` and ``param_exit`` functions.
+These functions run once before and once after the entire parameterized test
+series, respectively. The ``param_init`` function can be used for adding any
+resources to the resources field of a parent test and also provide an additional
+way of setting the parameter array. The ``param_exit`` function can be used
+release any resources that were not test managed i.e. not automatically cleaned
+up after the test ends.
+
+.. note::
+   If both a ``generate_params`` function is passed to ``KUNIT_CASE_PARAM_WITH_INIT``
+   and an array is registered via ``kunit_register_params_array`` in
+   ``param_init``, the ``generate_params`` function will be used to get
+   the parameters.
+
+Both ``param_init`` and ``param_exit`` are passed the parent instance of a test
+(parent ``struct kunit``) behind the scenes. However, the test case function
+receives the individual instance of a test for each parameter. Therefore, to
+manage and access shared resources from within a test case function, you must use
+``test->parent``.
+
+.. note::
+   The ``suite->init()`` function, which runs before each parameter execution,
+   receives the individual instance of a test for each parameter. Therefore,
+   resources set up in ``suite->init()`` are reset for each individual
+   parameterized test execution and are only visible within that specific test.
+
+For instance, finding a shared resource allocated by the Resource API requires
+passing ``test->parent`` to ``kunit_find_resource()``. This principle extends to
+all other APIs that might be used in the test case function, including
+``kunit_kzalloc()``, ``kunit_kmalloc_array()``, and others (see
+Documentation/dev-tools/kunit/api/test.rst and the
+Documentation/dev-tools/kunit/api/resource.rst).
+
+The code below shows how you can add the shared resources. Note that this code
+utilizes the Resource API, which you can read more about here:
+Documentation/dev-tools/kunit/api/resource.rst.
+
+.. code-block:: c
+
+	/* An example parameter array. */
+	static const struct example_param {
+		int value;
+	} example_params_array[] = {
+		{ .value = 3, },
+		{ .value = 2, },
+		{ .value = 1, },
+		{ .value = 0, },
+	};
+
+	/*
+	 * This custom function allocates memory for the kunit_resource data field.
+	 * The function is passed to kunit_alloc_resource() and executed once
+	 * by the internal helper __kunit_add_resource().
+	 */
+	static int example_resource_init(struct kunit_resource *res, void *context)
+	{
+		int *info = kmalloc(sizeof(*info), GFP_KERNEL);
+
+		if (!info)
+			return -ENOMEM;
+		*info = *(int *)context;
+		res->data = info;
+		return 0;
+	}
+
+	/*
+	 * This function deallocates memory for the 'kunit_resource' data field.
+	 * The function is passed to kunit_alloc_resource() and automatically
+	 * executes within kunit_release_resource() when the resource's reference
+	 * count, via kunit_put_resource(), drops to zero. KUnit uses reference
+	 * counting to ensure that resources are not freed prematurely.
+	 */
+	static void example_resource_free(struct kunit_resource *res)
+	{
+		kfree(res->data);
+	}
+
+	/*
+	 * This match function is invoked by kunit_find_resource() to locate
+	 * a test resource based on defined criteria. The current example
+	 * uniquely identifies the resource by its free function; however,
+	 * alternative custom criteria can be implemented. Refer to
+	 * lib/kunit/platform.c and lib/kunit/static_stub.c for further examples.
+	 */
+	static bool example_resource_alloc_match(struct kunit *test,
+						 struct kunit_resource *res,
+						 void *match_data)
+	{
+		return res->data && res->free == example_resource_free;
+	}
+
+	/*
+	 * This is an example of a function that provides a description for each of the
+	 * parameters.
+	*/
+	static void example_param_array_get_desc(const void *p, char *desc)
+	{
+		const struct example_param *param = p;
+
+		snprintf(desc, KUNIT_PARAM_DESC_SIZE,
+			"example check if %d is less than or equal to 3", param->value);
+	}
+
+	/*
+	 * Initializes the parent kunit struct for parameterized KUnit tests.
+	 * This function enables sharing resources across all parameterized
+	 * tests by adding them to the `parent` kunit test struct. It also supports
+	 * registering either static or dynamic arrays of test parameters.
+	 */
+	static int example_param_init(struct kunit *test)
+	{
+		int ctx = 3; /* Data to be stored. */
+		int arr_size = ARRAY_SIZE(example_params_array);
+
+		/*
+		 * This allocates a struct kunit_resource, sets its data field to
+		 * ctx, and adds it to the kunit struct's resources list. Note that
+		 * this is test managed so we don't need to have a custom exit function
+		 * to free it.
+		 */
+		void *data = kunit_alloc_resource(test, example_resource_init, example_resource_free,
+						  GFP_KERNEL, &ctx);
+
+		if (!data)
+			return -ENOMEM;
+		/* Pass the static param array information to the parent struct kunit. */
+		kunit_register_params_array(test, example_params_array, arr_size,
+					    example_param_array_get_desc);
+		return 0;
+	}
+
+	/*
+	* This is an example of a parameterized test that uses shared resources
+	* available from the struct kunit parent field of the kunit struct.
+	*/
+	static void example_params_test_with_init(struct kunit *test)
+	{
+		int threshold;
+		struct kunit_resource *res;
+		const struct example_param *param = test->param_value;
+
+		/* By design, param pointer will not be NULL. */
+		KUNIT_ASSERT_NOT_NULL(test, param);
+
+		/* Here we need to access the parent pointer of the test to find the shared resource. */
+		res = kunit_find_resource(test->parent, example_resource_alloc_match, NULL);
+
+		KUNIT_ASSERT_NOT_NULL(test, res);
+
+		/* Since the data field in kunit_resource is a void pointer we need to typecast it. */
+		threshold = *((int *)res->data);
+
+		/* Assert that the parameter is less than or equal to a certain threshold. */
+		KUNIT_ASSERT_LE(test, param->value, threshold);
+
+		/* This decreases the reference count after calling kunit_find_resource(). */
+		kunit_put_resource(res);
+	}
+
+
+	static struct kunit_case example_tests[] = {
+		KUNIT_CASE_PARAM_WITH_INIT(example_params_test_with_init, NULL,
+					   example_param_init, NULL),
+		{}
+	};
+
+As an alternative to using the KUnit Resource API for shared resources, you can
+place them in ``test->parent->priv``. It can store data that needs to persist
+and be accessible across all executions within a parameterized test series.
+
+As stated previously ``param_init`` and ``param_exit`` receive the parent
+``struct kunit`` instance. So, you can directly use ``test->priv`` within them
+to manage shared resources. However, from within the test case function, you must
+navigate up to the parent i.e. use ``test->parent->priv`` to access those same
+resources.
+
+The resources placed in ``test->parent-priv`` will also need to be allocated in
+memory to persist across the parameterized tests executions. If memory is
+allocated using the memory allocation APIs provided by KUnit (described more in
+the section below), you will not need to worry about deallocating them as they
+will be managed by the parent parameterized test that gets automatically cleaned
+up upon the end of the parameterized test series.
+
+The code below demonstrates example usage of the ``priv`` field for shared
+resources:
+
+.. code-block:: c
+
+	/* An example parameter array. */
+	static const struct example_param {
+		int value;
+	} example_params_array[] = {
+		{ .value = 3, },
+		{ .value = 2, },
+		{ .value = 1, },
+		{ .value = 0, },
+	};
+
+	/*
+	 * Initializes the parent kunit struct for parameterized KUnit tests.
+	 * This function enables sharing resources across all parameterized
+	 * tests.
+	 */
+	static int example_param_init_priv(struct kunit *test)
+	{
+		int ctx = 3; /* Data to be stored. */
+		int arr_size = ARRAY_SIZE(example_params_array);
+
+		/*
+		 * Allocate memory using kunit_kzalloc(). Since the `param_init`
+		 * function receives the parent instance of test, this memory
+		 * allocation will be scoped to the lifetime of the whole
+		 * parameterized test series.
+		 */
+		test->priv = kunit_kzalloc(test, sizeof(int), GFP_KERNEL);
+
+		/* Assign the context value to test->priv.*/
+		*((int *)test->priv) = ctx;
+
+		/* Pass the static param array information to the parent struct kunit. */
+		kunit_register_params_array(test, example_params_array, arr_size, NULL);
+		return 0;
+	}
+
+	/*
+	* This is an example of a parameterized test that uses shared resources
+	* available from the struct kunit parent field of the kunit struct.
+	*/
+	static void example_params_test_with_init_priv(struct kunit *test)
+	{
+		int threshold;
+		const struct example_param *param = test->param_value;
+
+		/* By design, param pointer will not be NULL. */
+		KUNIT_ASSERT_NOT_NULL(test, param);
+
+		/* By design, test->parent will also not be NULL. */
+		KUNIT_ASSERT_NOT_NULL(test, test->parent);
+
+		/* Assert that test->parent->priv has data. */
+		KUNIT_ASSERT_NOT_NULL(test, test->parent->priv);
+
+		/* Here we need to use test->parent->priv to access the shared resource. */
+		threshold = *(int *)test->parent->priv;
+
+		/* Assert that the parameter is less than or equal to a certain threshold. */
+		KUNIT_ASSERT_LE(test, param->value, threshold);
+	}
+
+
+	static struct kunit_case example_tests[] = {
+		KUNIT_CASE_PARAM_WITH_INIT(example_params_test_with_init_priv, NULL,
+					   example_param_init_priv, NULL),
+		{}
+	};
+
 Allocating Memory
 -----------------
 
-- 
2.50.1.552.g942d659e1b-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250729193647.3410634-10-marievic%40google.com.
