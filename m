Return-Path: <kasan-dev+bncBDQ67ZGAXYCBBK437TCAMGQE4VW66WA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3b.google.com (mail-io1-xd3b.google.com [IPv6:2607:f8b0:4864:20::d3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 33759B27E63
	for <lists+kasan-dev@lfdr.de>; Fri, 15 Aug 2025 12:36:29 +0200 (CEST)
Received: by mail-io1-xd3b.google.com with SMTP id ca18e2360f4ac-88432e1c782sf223843439f.2
        for <lists+kasan-dev@lfdr.de>; Fri, 15 Aug 2025 03:36:29 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755254187; cv=pass;
        d=google.com; s=arc-20240605;
        b=hfL8pNkfzup8j0WUFrkgkGwuFS62OHiDsrBL48P8ss33/NZ8r7uPCBoeodKhmPcsF9
         g1vAO3k6Ov43Bk4fczxjdpnbQDsOS0kDPWPaEyMIis7MGftXxz/boazdKeqTHeAL9GKj
         xvHXZYy15HL84ttONxLAOcZCrpTg567vfIoHOJftNRQYHGSASwnQ0flj5sq2u0tEd2z6
         EXDPd+GvP6WJdSuLm0+4XZrjOO3TRgEUsGCbRmk9Oylv5nm7NTBSqRW4yG/S8b/xT1KX
         NJOlC/9yUh6G1ADKqcFnXVilU0rL4qtyy/xVADEuf6fSqb0VhuuBboR8sIZMndMhuR6Y
         53cQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=ZxcfqJzkiObpE7VFotvSFAHHX1G9vmcYuipLrr+vjXs=;
        fh=OnO5dK1SQAZmoxmZY05Iwvvd9nWDYzour9mShL8ya9k=;
        b=DBqShIYsAz1p5GGLIry3oWVybzV0gg6BsGjDXzEqofi6VO8KTWVsc9N06xhP7vcTiK
         /z4/4rTfhrsqlMnvVfsMro4fv7PYi6432GD2FndBEEoUEym7m0wWFFCaME26GiZ275qJ
         BTu1M27ZkZ0KwoeBMnzhu0uUNjeGqv277/mh/+jFbTTBki3hTTAMf7VLfXo+vCzImaPB
         G9428nO11fLKqjXjWPH/fQlrdnbdFcE94cqAloqQu5z38WP6mjAOuBUkKM24F38qPxaY
         /2fREajmKT3p3ShDyNzQV/hMkOFvEawlrHFgyaItJyTYjeq6LD3fk8D/luSVYVvv6Q7e
         OAcQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=O2PPZpxk;
       spf=pass (google.com: domain of 3qg2faagkcy03r8zvcztx55x2v.t531r9r4-uvcx55x2vx85b69.t53@flex--marievic.bounces.google.com designates 2607:f8b0:4864:20::849 as permitted sender) smtp.mailfrom=3qg2faAgKCY03r8zvCztx55x2v.t531r9r4-uvCx55x2vx85B69.t53@flex--marievic.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755254187; x=1755858987; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=ZxcfqJzkiObpE7VFotvSFAHHX1G9vmcYuipLrr+vjXs=;
        b=VfNu/fPWssM7175LPfAl53K00OZ8acnbLUHmJmCVXpEy1XOzj2RcmxqnFSozcVg6PY
         wYzpKBjJGue81Cs3EaKFjqV6F+AAP1L48ew10N/KU2qttBxNdptB2AE5zOgGcWUm2/bK
         EDOlWPvhtLleySS/ABLpI4jS7OKfWBSFxv7JW5VPikau83oOjEpVu6S0zrvA8gGKYjpn
         0gD50l1PKwcBHtwcAaWhA62VM0rPvSJx2V8mG/QfKSNuOs4eL2E5Av5jhr+jwK2yBC5V
         uoGMCPRp//5VZ+qJb/VSch4DmsHjTt9gFdYM+UXZrBD9swbnXBh74CgHLT2uoN2fhUcv
         nmYg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755254187; x=1755858987;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=ZxcfqJzkiObpE7VFotvSFAHHX1G9vmcYuipLrr+vjXs=;
        b=tlCb4fy7eZjbJdgYh8NEJAws+vDzjCbj6gd34zoAvHeHD5opxrAKeG77yxN5gcS46A
         AVWSl14o1Iu34M4sKKRgdmmUO5VaLOEIXn2AsxiI3MWxBdX7fKpPz60gVce9b6c91U4/
         bchmE7Dm2ONQrdlqjV6qucUu5+1lwBGlhQSDL9opteNzo6MlC0rev6cY5Exrp2cesiFG
         wuVzaoRnHK2dZeq+fVEcGmUWsVuG6cNIOft7P972yZkhZqvpUVGNFAlH1VWtm46vqy93
         ZVcbWhRppKmEz6a6CTRxCArVPUc0BW9TurVgOikSwEaDyrnyOw4+L5iHZp8PqTFxrHDU
         PP5Q==
X-Forwarded-Encrypted: i=2; AJvYcCX5Ed8L+D8xUKGC81+9d2V243GhjV1aUfM+WG3z6f67B9n6HZtoHxM7vy3GPrKvh/yNUPRl+Q==@lfdr.de
X-Gm-Message-State: AOJu0YzaFfuvODEwwKdwBF74vbJg69p+nrYGHw/KlNaP7zzZsyYgPtYd
	vS8lT1erGoTVNGJCVQOnGqXL2/OUKxLakMFb0PzM329vLWz0ABO+ve2F
X-Google-Smtp-Source: AGHT+IGScTIEvx4ZliXAtcYKtRgyTcFcC9PImot5nOl9qR7QschaiPfHePsZZ8MRWj9EjY7aQ1OjdQ==
X-Received: by 2002:a05:6e02:2182:b0:3e5:58d7:98f5 with SMTP id e9e14a558f8ab-3e57e9d1a3dmr28359545ab.19.1755254187529;
        Fri, 15 Aug 2025 03:36:27 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZewpE/8XncUUht8Go7FqBK5fc5/OouGY3L6LJJrqEXPRg==
Received: by 2002:a92:cdad:0:b0:3dd:be50:e1f8 with SMTP id e9e14a558f8ab-3e56fb97861ls16712255ab.1.-pod-prod-07-us;
 Fri, 15 Aug 2025 03:36:26 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVJQ2UZTrEQix7CnuREYjNDLYVin1ebqAMKGS0oQK5RH7HVuyrKK5DRW54UimD1k73ZEGpUFBNUBGo=@googlegroups.com
X-Received: by 2002:a05:6e02:18c5:b0:3e5:5c80:2cf3 with SMTP id e9e14a558f8ab-3e57e9c605cmr24038165ab.13.1755254186672;
        Fri, 15 Aug 2025 03:36:26 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755254186; cv=none;
        d=google.com; s=arc-20240605;
        b=DbfgmlLMtbbGx/zVw/6cwqSTPrWb6y88XTdykVxCwUbyfVCqqAZPLIGTbpwgxPFtCe
         PQ1KieKzBSvkTB1hb+97eUo/M7mP8poKS7Jchi+FvtbNUXlZKuds5Fy5YPfrWvEc9D3z
         Riu+zYu/oEeQzaPUd2Rqr8yQGEUyBMvKbctzChjlurjvjeZ53QcPdeZ1lFIT8zXHIuBY
         nuDdEQ/e08zXRBemsLHXS5sNmXBucTpzDabJ0pq1WGmo7hFZPLDKFOf7zIFDKOaVC2Tc
         6L/sDQOXiO277OQwnDch190kteh4iEYjefVSijntIyipF0GccuaOx57maLQKXBcW5hfw
         LTbw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=z5VWtmN7wXdBM8xUp2T3Z+kcllw5mJ+rBSS+cDWhsio=;
        fh=pLIsWj6as+N93RmEVJOtzfbGOlNF+FLIAzyhAPVfp7c=;
        b=BXT/6oTfYuc0tOPEeqkuh5j93koYNiNOzu3NYw1JxcFM6Tqh9kRTUYW0IDIlEKOtIo
         uoZHnSuuqfBwyAsfM67K/2mhufWiR0wJL6Z+KqHGtuKtwTYLpu6ITDUEeyJXIcqtTQKb
         LNvMZeN1rSj2JzzS5Q/zRRGQD22nkQMf6cBxYMWEd9LKpWxEhjiKtfeRUQv1HzedE8i1
         Vj9N58GADRVz9cI73MeN8qg8LwTr6XQVHoHHsPys/BY/t7rbjEmeuZxF7+1tAw6+QJch
         l9BG99uMNvFOfLiMHy4XO6aLJNOQVN4Silupkrpl9foAwpS4iAWPJiQHxXWvl7OZEvi1
         kOvg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=O2PPZpxk;
       spf=pass (google.com: domain of 3qg2faagkcy03r8zvcztx55x2v.t531r9r4-uvcx55x2vx85b69.t53@flex--marievic.bounces.google.com designates 2607:f8b0:4864:20::849 as permitted sender) smtp.mailfrom=3qg2faAgKCY03r8zvCztx55x2v.t531r9r4-uvCx55x2vx85B69.t53@flex--marievic.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-qt1-x849.google.com (mail-qt1-x849.google.com. [2607:f8b0:4864:20::849])
        by gmr-mx.google.com with ESMTPS id e9e14a558f8ab-3e57e3c7026si496505ab.0.2025.08.15.03.36.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 15 Aug 2025 03:36:26 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3qg2faagkcy03r8zvcztx55x2v.t531r9r4-uvcx55x2vx85b69.t53@flex--marievic.bounces.google.com designates 2607:f8b0:4864:20::849 as permitted sender) client-ip=2607:f8b0:4864:20::849;
Received: by mail-qt1-x849.google.com with SMTP id d75a77b69052e-4b109919a51so75863301cf.0
        for <kasan-dev@googlegroups.com>; Fri, 15 Aug 2025 03:36:26 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVJVAJJatdF/1ka6KlfOVsmAxaSUiuhDuhjmCwXGgMsf3C4qaUFIxuGQl45R2Eeyw/+mp1FCJK4dLc=@googlegroups.com
X-Received: from qtny22.prod.google.com ([2002:ac8:5256:0:b0:4b0:77f6:dd7f])
 (user=marievic job=prod-delivery.src-stubby-dispatcher) by
 2002:ac8:7dcc:0:b0:4af:1837:778e with SMTP id d75a77b69052e-4b11e2a24demr15608461cf.31.1755254186232;
 Fri, 15 Aug 2025 03:36:26 -0700 (PDT)
Date: Fri, 15 Aug 2025 10:36:04 +0000
In-Reply-To: <20250815103604.3857930-1-marievic@google.com>
Mime-Version: 1.0
References: <20250815103604.3857930-1-marievic@google.com>
X-Mailer: git-send-email 2.51.0.rc1.167.g924127e9c0-goog
Message-ID: <20250815103604.3857930-8-marievic@google.com>
Subject: [PATCH v3 7/7] Documentation: kunit: Document new parameterized test features
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
 header.i=@google.com header.s=20230601 header.b=O2PPZpxk;       spf=pass
 (google.com: domain of 3qg2faagkcy03r8zvcztx55x2v.t531r9r4-uvcx55x2vx85b69.t53@flex--marievic.bounces.google.com
 designates 2607:f8b0:4864:20::849 as permitted sender) smtp.mailfrom=3qg2faAgKCY03r8zvCztx55x2v.t531r9r4-uvCx55x2vx85B69.t53@flex--marievic.bounces.google.com;
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
parameterized test context to share resources between parameter runs.
It documents and show examples of different ways the test user can
pass parameter arrays to a parameterized test. Finally, it specifies the
parameterized testing terminology.

Reviewed-by: Rae Moar <rmoar@google.com>
Reviewed-by: David Gow <davidgow@google.com>
Signed-off-by: Marie Zhussupova <marievic@google.com>
---

Changes in v3:
v2: https://lore.kernel.org/all/20250811221739.2694336-8-marievic@google.com/
- Parameterized test terminology was made more concise.
- Introduction now includes more background information on the
  generate_params() function.
- Minor wording edits for conciseness.
- Code line number references were removed as they could quickly go
  out of date.

Changes in v2:
v1: https://lore.kernel.org/all/20250729193647.3410634-10-marievic@google.com/
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
 1 file changed, 337 insertions(+), 5 deletions(-)

diff --git a/Documentation/dev-tools/kunit/usage.rst b/Documentation/dev-tools/kunit/usage.rst
index 066ecda1dd98..ebd06f5ea455 100644
--- a/Documentation/dev-tools/kunit/usage.rst
+++ b/Documentation/dev-tools/kunit/usage.rst
@@ -542,11 +542,31 @@ There is more boilerplate code involved, but it can:
 Parameterized Testing
 ~~~~~~~~~~~~~~~~~~~~~
 
-The table-driven testing pattern is common enough that KUnit has special
-support for it.
+To run a test case against multiple inputs, KUnit provides a parameterized
+testing framework. This feature formalizes and extends the concept of
+table-driven tests discussed previously.
 
-By reusing the same ``cases`` array from above, we can write the test as a
-"parameterized test" with the following.
+A KUnit test is determined to be parameterized if a parameter generator function
+is provided when registering the test case. A test user can either write their
+own generator function or use one that is provided by KUnit. The generator
+function is stored in  ``kunit_case->generate_params`` and can be set using the
+macros described in the section below.
+
+To establish the terminology, a "parameterized test" is a test which is run
+multiple times (once per "parameter" or "parameter run"). Each parameter run has
+both its own independent ``struct kunit`` (the "parameter run context") and
+access to a shared parent ``struct kunit`` (the "parameterized test context").
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
 
@@ -555,7 +575,7 @@ By reusing the same ``cases`` array from above, we can write the test as a
 		const char *str;
 		const char *sha1;
 	};
-	const struct sha1_test_case cases[] = {
+	static const struct sha1_test_case cases[] = {
 		{
 			.str = "hello world",
 			.sha1 = "2aae6c35c94fcfb415dbe95f408b9ce91ee846ed",
@@ -590,6 +610,318 @@ By reusing the same ``cases`` array from above, we can write the test as a
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
+   For scenarios where you might need to initialize a parameterized test, you
+   can directly register a parameter array to the parameterized test context.
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
+   please refer to lib/kunit/kunit-example-test.c.
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
+code please refer to lib/kunit/kunit-example-test.c.
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
2.51.0.rc1.167.g924127e9c0-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250815103604.3857930-8-marievic%40google.com.
