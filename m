Return-Path: <kasan-dev+bncBDQ67ZGAXYCBB76FUTCAMGQEII6WUIY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13c.google.com (mail-il1-x13c.google.com [IPv6:2607:f8b0:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id 9518DB15397
	for <lists+kasan-dev@lfdr.de>; Tue, 29 Jul 2025 21:37:37 +0200 (CEST)
Received: by mail-il1-x13c.google.com with SMTP id e9e14a558f8ab-3e3f0a3f62asf16091205ab.2
        for <lists+kasan-dev@lfdr.de>; Tue, 29 Jul 2025 12:37:37 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1753817856; cv=pass;
        d=google.com; s=arc-20240605;
        b=ODVEUUSrzBwKR3LDdqh1oeGUhAEy0k77WyMP16nnsgVINohdOkp4GiUuL+f2uNuf+Z
         uQYqSvkv1iRNV+l+QbHxBK0FaC4BgSPYRPkEcW+JwFqzCRH6zdJ85vH1oy4yEvDc8Gf2
         yUMpZhEko1GXJ/rXZbxc77X1N0/HjhafBNO5aLffcbZDK0P9RnuHX/eHVrrisUmwSyIJ
         dCj7M88JZKqop+8qvXLtTLZ9pKAcsFqf8EYtY1z2TEwAYibswTV69dohC4UO/YiLj7HL
         Uuy7M9A0ylNi2MIIqtjm1Ip7I0O5+K2Tn4NR1FYA4/Y7JuAjukz3tJG0FxOa52fXsQmO
         VX1w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=gtDdSns5/97zc5xp6+0I9cQSSuxoOXvZJfuAaa4bv4I=;
        fh=cZx5c8tvhMmMCMsVsDrMehnI8iTd3ftVvd9dEdUEEzI=;
        b=N1w4BRaG/tKyj3JwLShZZnHg7rkRi5cdrbrJhG0GIpqb2VEPoFdcwQ47JfCS7Vf87V
         zyEi/wM37oYcDh4syIuxVBuW3h36aSXn6/YrdlYFBi/H8bV9Ypa2v1h4Uq+8fx0aPKmo
         i6u0XUJzSZcSzOMlc+ZnTWQ5s9gvLlqlO2tQnz/tc9CyuH4DiqNrxtAigFzcSed6tx0a
         T47rbd3uvEZXdcenx3o9/BZf4eu0FB0aAcNQgx6GbKD7S4FI0BSSEVhNCM/wGtq7liJa
         47DPRMkbu7giI6yB9OHRxYGRvm0zCeKKh/+GjeGffCUrrOeiN0WiNwE6p5T2JrrqQzHl
         T92g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=ebyqi+Cc;
       spf=pass (google.com: domain of 3_ikjaagkcbmftkbxobvzhhzex.vhfdtltg-wxozhhzexzkhnil.vhf@flex--marievic.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3_iKJaAgKCbMfTkbXobVZhhZeX.VhfdTlTg-WXoZhhZeXZkhnil.Vhf@flex--marievic.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1753817856; x=1754422656; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=gtDdSns5/97zc5xp6+0I9cQSSuxoOXvZJfuAaa4bv4I=;
        b=WNKr9QK/KoMgEJhO0h67qZn0bnSradwD8ZX7I/grgjgFLMe2nBISorHNi3TTMfGIe3
         Sya/9QzqLnqyeJe+9pUZUd/DthldMJcz/JCAQ8g7Eo2ql+emBFmeW4oH1lNu8aotdpZ0
         Gq4S04tsVeYg3G2gxrVERDbn/wvkosaEIWXtK+BJkJjdB8bb2R2LLXcpRS4CfP6a8nVq
         8URiuVggLd/v5eOA8x3obS7E/H9oa5cTRVKul+9DSSo0+ESVmF/TCAluq7J1A/E06qe1
         iz+4zStvsL/D33FMO8e8iiZv/LT/hRq8loRjAKRwQNn4FH85tvNEEHck0JF/frLhTtqf
         kzug==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1753817856; x=1754422656;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=gtDdSns5/97zc5xp6+0I9cQSSuxoOXvZJfuAaa4bv4I=;
        b=SDQ+aPAK+K0Lp6U+pJQ6M/MwvbYf3OHGdys5y/z/FuTwn6jRN3nKTmCZAqKlSO0GhG
         F/pl+LzSYyL4ezx7Ix6uwOu0wBxN2Hoo0+RE/crwGbMJaeanfSPR2MquTsazVwxB2a6H
         9WmVl9c4LgkI12h6EBrzPEgVjSUK/X2KVm8Thl2zewNh4uEDcS2pNZRdPkuzrFDkuxxr
         EErphrBUI1vqWrqbw2vCh7N36Fr/dSCSQgeCIxZdHLiSLk0Lv1/e1plZe0NGtqC9PcHV
         YC9le0Mvt9BhqH4xGzSl6G0jwfPpNHvtyH5RmQrpnP2qH9EtrWG6VynjKjPtE/MxQJFQ
         wlVQ==
X-Forwarded-Encrypted: i=2; AJvYcCXc72gbUQGR7f7+9Zeh5vl9qjFF5in39pjFaGHKaVNtc2T453wpxhQSM3juA0Aw7oGgBcQOeA==@lfdr.de
X-Gm-Message-State: AOJu0YxVs7Stv8rpACCz34ymVAD1btsWqpIFwvH3ybpbRtdc8se6CZAS
	zDNHvkYrEZojUM/4J2j1EXwYVOw9A+a9EiwsOISwTArk/WejjqwFyUUn
X-Google-Smtp-Source: AGHT+IHB6l2dWlW4MNi5+JiAjc9TQHJDa5DEXBipUxo6YnBRniNj3kXblBITT9RuEUohqa/SlKzC2g==
X-Received: by 2002:a05:6e02:338f:b0:3e2:c6e1:7713 with SMTP id e9e14a558f8ab-3e3f6250c25mr14895315ab.18.1753817856149;
        Tue, 29 Jul 2025 12:37:36 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdNcr13ozC36S7/oiepFReLfXBJQw6FbdfxPqNaf6JQ3Q==
Received: by 2002:a05:6e02:9a:b0:3dd:b6c9:5f59 with SMTP id
 e9e14a558f8ab-3e3b5192f75ls49355515ab.1.-pod-prod-05-us; Tue, 29 Jul 2025
 12:37:35 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXqb6Q3I/JgNkOjHE4iGQNvE5S3emKjRpRKiChD1b67nCu0bp+Uoq+isU3Ul2aIdyi6+iw0Qol2E4Y=@googlegroups.com
X-Received: by 2002:a05:6602:29d2:b0:87c:4412:dad1 with SMTP id ca18e2360f4ac-88138140d6emr112403739f.9.1753817855381;
        Tue, 29 Jul 2025 12:37:35 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1753817855; cv=none;
        d=google.com; s=arc-20240605;
        b=g8moY/2SMdw2RP7ChICGWwAaybvXgL/3/xjjCADERVzhmkbRzfx2l/eAcCR9tWRckd
         slQtWO7DlSiL1MAUcd4BAT2qVSCUQTFPhThjU0fId39DyizahZzVoWmfhUsc7yOgN6Wk
         PnZ6/W5kIItVeBDo3ezMuS+N9vI+rfPz2PkhXYTpkwoQdX8L7OO6vqknrPiV6/dlFD5T
         1XLsroHmjTfxVRINfYsFYLUlekTW2Ur46YUX+biB222wDBocw+XLJ7/BqzjY+lO7pFnP
         tZUpUKKA2Jch6is2VvkpEbIQq3C8mnllTt8gIJVDiQcCapqhrjLR+rTgKxL8L4+gt3LV
         JM3g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=mqlb+4Olh1TwsUKHNBaNVmipEQokIfwNy2zQhwsaeKw=;
        fh=QkhVsIhP+nH14rXzxAgOw6GDrOkwC9VXE+CiFXC9oig=;
        b=hxLKtHeXbz6kXUaD5mqFkEMCWFnQQEMonGxYAPcOWNFKDFJMqO+2cbtj0HnX5XZhkh
         W/rkoJttVG+CnM5Yh6rg6HcCldyiY+UKgv9g6AWmrtbLoiQteLzZZFKYt1FpU0ByDpUP
         U5TrvJey2qIRPWF1OVqmFWhr6Zl80+pWcZJ2x2pXQK0PV4KL246IAgk5sgCLtELJ8g3m
         I0QkA+H7/lSDt6EWsDZcpKmpBdH1WviDYP6Va3/OBsFAssbxz6vEwBQr3UfAQPOsTLAn
         xrQezZ5nCVbSGYx5Kx+3oyYKM/iwdX3kTm/zA55NnAB5RNbjtEVpjZC7WVEaYz6nLOZM
         BXJg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=ebyqi+Cc;
       spf=pass (google.com: domain of 3_ikjaagkcbmftkbxobvzhhzex.vhfdtltg-wxozhhzexzkhnil.vhf@flex--marievic.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3_iKJaAgKCbMfTkbXobVZhhZeX.VhfdTlTg-WXoZhhZeXZkhnil.Vhf@flex--marievic.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-qt1-x84a.google.com (mail-qt1-x84a.google.com. [2607:f8b0:4864:20::84a])
        by gmr-mx.google.com with ESMTPS id ca18e2360f4ac-880f79a397esi22045839f.1.2025.07.29.12.37.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 29 Jul 2025 12:37:35 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3_ikjaagkcbmftkbxobvzhhzex.vhfdtltg-wxozhhzexzkhnil.vhf@flex--marievic.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) client-ip=2607:f8b0:4864:20::84a;
Received: by mail-qt1-x84a.google.com with SMTP id d75a77b69052e-4ab6d31e2dbso189227201cf.3
        for <kasan-dev@googlegroups.com>; Tue, 29 Jul 2025 12:37:35 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUqabAFPqencefchQ/NYMDkG8Rz99RohY4ai12u75YwcQ2HISr3cCmhQ5FROCC9RCIcKinSoJDujWE=@googlegroups.com
X-Received: from qtbcm22.prod.google.com ([2002:a05:622a:2516:b0:4ab:3fb5:ddd8])
 (user=marievic job=prod-delivery.src-stubby-dispatcher) by
 2002:ac8:5fd3:0:b0:4ab:63b9:9bf4 with SMTP id d75a77b69052e-4aedb98b2bfmr15053941cf.1.1753817854822;
 Tue, 29 Jul 2025 12:37:34 -0700 (PDT)
Date: Tue, 29 Jul 2025 19:36:46 +0000
In-Reply-To: <20250729193647.3410634-1-marievic@google.com>
Mime-Version: 1.0
References: <20250729193647.3410634-1-marievic@google.com>
X-Mailer: git-send-email 2.50.1.552.g942d659e1b-goog
Message-ID: <20250729193647.3410634-9-marievic@google.com>
Subject: [PATCH 8/9] kunit: Add example parameterized test with direct dynamic
 parameter array setup
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
 header.i=@google.com header.s=20230601 header.b=ebyqi+Cc;       spf=pass
 (google.com: domain of 3_ikjaagkcbmftkbxobvzhhzex.vhfdtltg-wxozhhzexzkhnil.vhf@flex--marievic.bounces.google.com
 designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3_iKJaAgKCbMfTkbXobVZhhZeX.VhfdTlTg-WXoZhhZeXZkhnil.Vhf@flex--marievic.bounces.google.com;
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

Introduce `example_params_test_with_init_dynamic_arr`. This new
KUnit test demonstrates directly assigning a dynamic parameter
array using the `kunit_register_params_array` macro. It highlights the
use of `param_init` and `param_exit` for proper initialization and
cleanup, and their registration to the test with
`KUNIT_CASE_PARAM_WITH_INIT`.

Signed-off-by: Marie Zhussupova <marievic@google.com>
---
 lib/kunit/kunit-example-test.c | 95 ++++++++++++++++++++++++++++++++++
 1 file changed, 95 insertions(+)

diff --git a/lib/kunit/kunit-example-test.c b/lib/kunit/kunit-example-test.c
index 5bf559e243f6..3ab121d81bf6 100644
--- a/lib/kunit/kunit-example-test.c
+++ b/lib/kunit/kunit-example-test.c
@@ -387,6 +387,98 @@ static void example_params_test_with_init(struct kunit *test)
 	kunit_put_resource(res);
 }
 
+/*
+ * Helper function to create a parameter array of Fibonacci numbers. This example
+ * highlights a parameter generation scenario that is:
+ * 1. Not feasible to fully pre-generate at compile time.
+ * 2. Challenging to implement with a standard 'generate_params' function,
+ * as it typically only provides the immediately 'prev' parameter, while
+ * Fibonacci requires access to two preceding values for calculation.
+ */
+static void *make_fibonacci_params(int seq_size)
+{
+	int *seq;
+
+	if (seq_size <= 0)
+		return NULL;
+
+	seq = kmalloc_array(seq_size, sizeof(int), GFP_KERNEL);
+
+	if (!seq)
+		return NULL;
+
+	if (seq_size >= 1)
+		seq[0] = 0;
+	if (seq_size >= 2)
+		seq[1] = 1;
+	for (int i = 2; i < seq_size; i++)
+		seq[i] = seq[i - 1] + seq[i - 2];
+	return seq;
+}
+
+/*
+ * This is an example of a function that provides a description for each of the
+ * parameters.
+ */
+static void example_param_dynamic_arr_get_desc(const void *p, char *desc)
+{
+	const int *fib_num = p;
+
+	snprintf(desc, KUNIT_PARAM_DESC_SIZE, "fibonacci param: %d", *fib_num);
+}
+
+/*
+ * Example of a parameterized test init function that registers a dynamic array.
+ */
+static int example_param_init_dynamic_arr(struct kunit *test)
+{
+	int seq_size = 6;
+	int *fibonacci_params = make_fibonacci_params(seq_size);
+
+	if (!fibonacci_params)
+		return -ENOMEM;
+
+	/*
+	 * Passes the dynamic parameter array information to the parent struct kunit.
+	 * The array and its metadata will be stored in test->parent->params_data.
+	 * The array itself will be located in params_data.params.
+	 */
+	kunit_register_params_array(test, fibonacci_params, seq_size,
+				    example_param_dynamic_arr_get_desc);
+	return 0;
+}
+
+/**
+ * Function to clean up the parameterized test's parent kunit struct if
+ * there were custom allocations.
+ */
+static void example_param_exit_dynamic_arr(struct kunit *test)
+{
+	/*
+	 * We allocated this array, so we need to free it.
+	 * Since the parent parameter instance is passed here,
+	 * we can directly access the array via `test->params_data.params`
+	 * instead of `test->parent->params_data.params`.
+	 */
+	kfree(test->params_data.params);
+}
+
+/*
+ * Example of test that uses the registered dynamic array to perform assertions
+ * and expectations.
+ */
+static void example_params_test_with_init_dynamic_arr(struct kunit *test)
+{
+	const int *param = test->param_value;
+	int param_val;
+
+	/* By design, param pointer will not be NULL. */
+	KUNIT_ASSERT_NOT_NULL(test, param);
+
+	param_val = *param;
+	KUNIT_EXPECT_EQ(test, param_val - param_val, 0);
+}
+
 /*
  * Here we make a list of all the test cases we want to add to the test suite
  * below.
@@ -408,6 +500,9 @@ static struct kunit_case example_test_cases[] = {
 	KUNIT_CASE_PARAM(example_params_test, example_gen_params),
 	KUNIT_CASE_PARAM_WITH_INIT(example_params_test_with_init, NULL,
 				   example_param_init, NULL),
+	KUNIT_CASE_PARAM_WITH_INIT(example_params_test_with_init_dynamic_arr, NULL,
+				   example_param_init_dynamic_arr,
+				   example_param_exit_dynamic_arr),
 	KUNIT_CASE_SLOW(example_slow_test),
 	{}
 };
-- 
2.50.1.552.g942d659e1b-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250729193647.3410634-9-marievic%40google.com.
