Return-Path: <kasan-dev+bncBC6OLHHDVUOBBVPVWXCQMGQEETH55XI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3b.google.com (mail-oa1-x3b.google.com [IPv6:2001:4860:4864:20::3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 05037B35860
	for <lists+kasan-dev@lfdr.de>; Tue, 26 Aug 2025 11:13:59 +0200 (CEST)
Received: by mail-oa1-x3b.google.com with SMTP id 586e51a60fabf-30ccebfdef3sf9031420fac.2
        for <lists+kasan-dev@lfdr.de>; Tue, 26 Aug 2025 02:13:58 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756199637; cv=pass;
        d=google.com; s=arc-20240605;
        b=U3m98mhGe0zyw8FjLdSzTOn6dD5EOiiIOMRxRcHIF11TYB3+jLmE4u6cMoZ6XD/zwG
         GNev0S6byuTQm5FFaO/qwkqoS+XRql1sCV146klVXQY/jPzIRkRI6voxb9MPr3lnopf+
         ahnZWHOlIHqn1xs45BFzQE2UTAAOmYXSi2D1/xe+Xzt0LFh+RrsG56/GDdyEjtu7gkTH
         NWncKMk82ypuqMMVGMMRiCH5a9uHbWffPgco9tAOwdsUSoU6A+CC/homq4W69sx6RSDG
         hnYCT5GtvHTsuYgKY0thfowMJXijyF33r34/QY3r5HT7ZKKYTfIFxE2yCeUpJJVbJ+hh
         klDA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=S/pkDbeYD5YiJe918VcInUNs2L2OE2Blj0kGbLpEWRc=;
        fh=QyC6lWxPWCZYGNtcDzMiWK1cBvGFep3txZ1o9SAsQCM=;
        b=H58ctvF0q4FQFgKLhwNknGZi3Em6AEbvGOM4e8moBVdLmAK8PGXP02ig/p2XSGzE48
         Z0zzkbanYY0vLh8tugEhxqQJvkw1wUj/GXOaGrZ/oZoQ5c/2OiX8v8tGRGnjDwOtB/kK
         Eka9Gu4Sf6wAf5iM1NBUZmivF6aIgpF4KLIgvtTliQ9xcqowlP6tFpptE5c0qtXPeV5n
         rrUruBuFWURa0dzAxTSZ5RaNMsj/FRQg64hjsbedbePURZ4Q6v6Us4zEbItzSwxdlBrb
         W+UWbdUsam7pksRLGIWQiaJOvnN2EX5fcI74beIIv0fTgutPYJiTeK5E9/4/PStUi3f3
         jGBg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=UHqbVsLI;
       spf=pass (google.com: domain of 303qtaagkccotqbytw4cw44w1u.s420q8q3-tubw44w1uw74a58.s42@flex--davidgow.bounces.google.com designates 2607:f8b0:4864:20::44a as permitted sender) smtp.mailfrom=303qtaAgKCcotqBytw4Cw44w1u.s420q8q3-tuBw44w1uw74A58.s42@flex--davidgow.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756199637; x=1756804437; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=S/pkDbeYD5YiJe918VcInUNs2L2OE2Blj0kGbLpEWRc=;
        b=VdOWRGrUehPgto4SzipzfCmxoodhmh4bhnyeiA0ItZiw9I9oR9Lj7UGV1CAtLc6Jd+
         tkPAtvS8+kZPngaAmEvSRJDwtCCIqI9OdXEoKtwE2HcLU0vVBWjH4rLPTCW6NeW+8FeN
         90JVvOtrfTzdHcNM3D1AYDwKSJeP5q0qKoriD/j0o/GVhbYFmsvqKJVBiwHwS7XvVoFK
         Tu0Atd7BTYMScodph0mjEt8k/jrKlCfGS8wFo1dlLw+u0HZQJpeA2OjoUfdQBQiNPbok
         +38RpIKOPdByrkdG4SYbZIKmnISDalKY7FMSmN3X4Y3/5Smk/CartXzNJJ6y445+r6Jd
         Ubew==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756199637; x=1756804437;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=S/pkDbeYD5YiJe918VcInUNs2L2OE2Blj0kGbLpEWRc=;
        b=MsjP+2XTqHL7plE3OxLQd3ozKXpB54Dee77Fg3RGofCpri4fFuSMF+rqhFGvaiJjor
         ISA+IHRWYgT+icphGeLq37Z36JtDDZZ+ohH8Kl/DwoGqofmkIFi87464E7Ru0OONKbhl
         m0EXp0Yk1q0es0E30H6rh0C129WMmTNi2hNBy+w6tReFh4ACNdtlhlSYPQr1EZtUHUrT
         syHmYsnbqS/qlD4nGmD2B1niiifTGPUy93rw51D08B3tzeIeXMfEaG+t9FXwjvOqiOks
         vL/k/yZHvZ9aT1xoCAxeMOwF8ki2pUDkrUq2ZmOU56NsHd3g0zh4QGr1vLdCcmKntaMo
         96ig==
X-Forwarded-Encrypted: i=2; AJvYcCVMuDwkt6xShCTFzcpKKiceavKftjasbkLQpS6VHMhyDNYLU1ly0JspqF4FFj03p7352Zp1pQ==@lfdr.de
X-Gm-Message-State: AOJu0YyoVNWKI2U2fVumTInuS5Jcs5eEjmnB1KDHCXoSib8C7Udf+aHo
	HYSaj5Nx/GJwNNw14DUwki+AwDgT/fJWnjYF1PvIt4ArBlSE7QvdnObE
X-Google-Smtp-Source: AGHT+IHP+RzrIGVqBKnUnxa1xV4h/EMUNKRnmJk56DJoTUj0/kDcJzMLpw5PINhGtojjSH/VK9yt0w==
X-Received: by 2002:a05:6871:e786:b0:2ff:9224:b1c8 with SMTP id 586e51a60fabf-314dcdb031cmr7821240fac.36.1756199637564;
        Tue, 26 Aug 2025 02:13:57 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZf2EamPOWYcia2tMS3J/8X9D34dPP9G/UKBa9jg09x1Vw==
Received: by 2002:a05:687c:2707:b0:315:2c96:21e8 with SMTP id
 586e51a60fabf-3152c962a15ls487717fac.1.-pod-prod-01-us; Tue, 26 Aug 2025
 02:13:56 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVfcAOWtjxpUJQHDFWdP9TBVxK7JvE92oSazMVP095/8gPtm7Q8RB5Wqkm9RYb1hifThxY2zX8hcLA=@googlegroups.com
X-Received: by 2002:a05:6808:2189:b0:437:7577:d458 with SMTP id 5614622812f47-437852880d1mr8584924b6e.44.1756199636789;
        Tue, 26 Aug 2025 02:13:56 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756199636; cv=none;
        d=google.com; s=arc-20240605;
        b=e7YKM7WW5wZcWYMOyI5KSpeQ85qwqjMA2DMry2PJ/TD8IK1MrPcXsawebZLXbQ2eRm
         l6FMngtoYxdNNI41HRjCB6ltTu+E2IVV7qOUW/5blX8bl7XIkv+zU0A2PBpF1MCQVxWf
         cKngJZH8tJrQ2IAzc4eULH57eWGNLiA7MbH5n4bNKJCNmGH56wJ2eVyxhYVNOIGK6fk3
         Kpk06Hm7U2yCi3OtfCMkCHL4Ti2/oXc/qRglrbemhJ7aN2BkHjXQiFt4HLt6EVnCRfGO
         13fim1rkBOcdEXcWFo1nFpzGb1v6tic66rwGRekQOxA4TssoNqtO9t1X5XPL96cc9Jw8
         sf7g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=bNb+tbEq0O34V9vRUZVDatMKWz5EoksX488NOcATxpQ=;
        fh=KhLuUe8lXilPwpvRkYzLey9I2gGpkO6BcXmgEHpIqpQ=;
        b=d2lEnofaIQPhk54A4bBY/lDUQ6cSA3r3vC79n+qomgJB4Ol6N5gUGGnKG6yQ3yZhPF
         3nG5r2PNYGDinrr9/6Rn8ZNSBq9Zc37VJD7W358OmTTOLDCB9w7RXVsd2EihXeM5QKWX
         9f/WvuzWXpVgZTnr5tcyl5Jk0Es9bYlVWiu0rODt9mE/0T8Yw9g7hcRBnFOdHbScw0+x
         lk1JXjCFJIAieeCllAKzlYkRw5jtBcE+OX41iR4nWJgzMN+HHIkrOi8t0Jz2rAE1JWIM
         3CrYjdPavdNDHKTt/45EgKjhA/9iVHyKSyQhg0VJ/U8jT4dPvAE4q7N7JiL8eITQNMsm
         GwmA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=UHqbVsLI;
       spf=pass (google.com: domain of 303qtaagkccotqbytw4cw44w1u.s420q8q3-tubw44w1uw74a58.s42@flex--davidgow.bounces.google.com designates 2607:f8b0:4864:20::44a as permitted sender) smtp.mailfrom=303qtaAgKCcotqBytw4Cw44w1u.s420q8q3-tuBw44w1uw74A58.s42@flex--davidgow.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pf1-x44a.google.com (mail-pf1-x44a.google.com. [2607:f8b0:4864:20::44a])
        by gmr-mx.google.com with ESMTPS id 5614622812f47-437968d1c38si374982b6e.3.2025.08.26.02.13.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 26 Aug 2025 02:13:56 -0700 (PDT)
Received-SPF: pass (google.com: domain of 303qtaagkccotqbytw4cw44w1u.s420q8q3-tubw44w1uw74a58.s42@flex--davidgow.bounces.google.com designates 2607:f8b0:4864:20::44a as permitted sender) client-ip=2607:f8b0:4864:20::44a;
Received: by mail-pf1-x44a.google.com with SMTP id d2e1a72fcca58-771b23c098dso1760223b3a.2
        for <kasan-dev@googlegroups.com>; Tue, 26 Aug 2025 02:13:56 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUsF662HP86D/D4ITeDW7Xtx6W45VJ8HvOpo0y9KPoZaV/mVSS5X6TaZmqEJzMyuLjwGq9vn9vyO1o=@googlegroups.com
X-Received: from pfbbx23.prod.google.com ([2002:a05:6a00:4297:b0:770:4ea0:3960])
 (user=davidgow job=prod-delivery.src-stubby-dispatcher) by
 2002:a05:6a00:3e01:b0:76e:885a:c33a with SMTP id d2e1a72fcca58-7702fc28b0cmr21053996b3a.32.1756199635827;
 Tue, 26 Aug 2025 02:13:55 -0700 (PDT)
Date: Tue, 26 Aug 2025 17:13:37 +0800
In-Reply-To: <20250826091341.1427123-1-davidgow@google.com>
Mime-Version: 1.0
References: <20250826091341.1427123-1-davidgow@google.com>
X-Mailer: git-send-email 2.51.0.261.g7ce5a0a67e-goog
Message-ID: <20250826091341.1427123-8-davidgow@google.com>
Subject: [PATCH v4 7/7] Documentation: kunit: Document new parameterized test features
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
 header.i=@google.com header.s=20230601 header.b=UHqbVsLI;       spf=pass
 (google.com: domain of 303qtaagkccotqbytw4cw44w1u.s420q8q3-tubw44w1uw74a58.s42@flex--davidgow.bounces.google.com
 designates 2607:f8b0:4864:20::44a as permitted sender) smtp.mailfrom=303qtaAgKCcotqBytw4Cw44w1u.s420q8q3-tuBw44w1uw74A58.s42@flex--davidgow.bounces.google.com;
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

This patch updates the KUnit docs to show how to use the new
parameterized test context to share resources between parameter runs.
It documents and show examples of different ways the test user can
pass parameter arrays to a parameterized test. Finally, it specifies the
parameterized testing terminology.

Reviewed-by: Rae Moar <rmoar@google.com>
Reviewed-by: David Gow <davidgow@google.com>
Signed-off-by: Marie Zhussupova <marievic@google.com>
Signed-off-by: David Gow <davidgow@google.com>
---

Changes in v4:
v3: https://lore.kernel.org/linux-kselftest/20250815103604.3857930-8-marievic@google.com/
- No changes.

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
2.51.0.261.g7ce5a0a67e-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250826091341.1427123-8-davidgow%40google.com.
