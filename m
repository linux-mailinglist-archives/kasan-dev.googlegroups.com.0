Return-Path: <kasan-dev+bncBC6OLHHDVUOBBX6W2T2AKGQE4X4T2GY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43e.google.com (mail-pf1-x43e.google.com [IPv6:2607:f8b0:4864:20::43e])
	by mail.lfdr.de (Postfix) with ESMTPS id 7016D1A719D
	for <lists+kasan-dev@lfdr.de>; Tue, 14 Apr 2020 05:17:53 +0200 (CEST)
Received: by mail-pf1-x43e.google.com with SMTP id f11sf10594445pfq.2
        for <lists+kasan-dev@lfdr.de>; Mon, 13 Apr 2020 20:17:53 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1586834272; cv=pass;
        d=google.com; s=arc-20160816;
        b=uKEolQG5SQ4dcQ7ThU9iMEqDE7OwfC3111ylTKxKPqvIbQfYACDKFlTa/OsMxAinU2
         CJUXAYPaAQ130OKC55EB59hjZ0gSvqOj+HBpbAiZb1rveR90ZfEnARnJikUBWqAwt7Zg
         ahaTktFaHgM6VVJtiqJf85Tkx7RZqjzE+lPiEZU3rD7TH16iCoUOpCNjc83WXZch6rw6
         gPmrRVB1tvcWVr5JOPRsQAkel/QbUKLOGMNcvTIolXqsKLCSXBwlHlmha0K3yk0xeTE0
         dUf2Ekwvs8Cc1BGjm5xWDVU+sH4NSi4Tl6gjmNlqrqqDdpn5f5XmWJSdsMYpmLS4iXU8
         5jQg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=OI7hnHunFV8/2I++Idtq2A/yWAygtVFXvUHG4mKj4tY=;
        b=LDHMXYqB6R60KVxqWGebpFidki1SG5LCRbioaGMo5GSNpHhBUydRPK+j4+xnS5+pHQ
         STtVFuWovgvLaIL18Tbv6//79LlHRRyVQVU+iZMbxGNSYQtn1n3RARORczxphd6KcIUm
         x92umBGdW5Dy6mq3Lo2HnIRn4EqnS+0EJwqLrKCVHHhx04enhQXkPcJexya4ofJd3/b/
         b+Rs6zhkj/Eh9HcWZ8sUiX0abwLtpDx7VWgIUeEEqT/Tl9HcLyKXAM3oRBGWIsVNhY/t
         JFq1CvZyOTVBarCA2zVszVK2cU6MWVxZ+JqH/jeu9oDDSkHMGAxMVrQRk/qU6ELVLlOO
         o9/A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=CWNeHW1R;
       spf=pass (google.com: domain of 3xyuvxggkcqyjg1ojmu2muumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--davidgow.bounces.google.com designates 2607:f8b0:4864:20::549 as permitted sender) smtp.mailfrom=3XyuVXggKCQYjg1ojmu2muumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--davidgow.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=OI7hnHunFV8/2I++Idtq2A/yWAygtVFXvUHG4mKj4tY=;
        b=avdyfvQ1Ey59IlR40T4gJqjkKqmvuk++KgHmiDcRg154hM1DtpPf7C+YqDcN79SNqW
         5kMGxlCRcrkUHEYOI6zMt+6iF5f+CKuIPC3zMVliYP6pJbCLpGk3hCao5AfbtURmEsj4
         pU0g9/+GWhzG6e1ffCSGZNjCCEu+kGh+H9Q6ClEoscDt1f+DKLDczHWb0QuM0ZzMv3XX
         0+0iclXPlOE/bJQnOGAdv3+5qU4hNQNJxHBMHwnltdPZHi76uoBVNWHQvX1ACOgtQ7st
         dd0s8fSSuSpHpJ1CbpXu6egRm0+jtgS7npORVxwGDKXjQ/7gHtsgAPAPwHSPCqZ8iDda
         0Zhw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=OI7hnHunFV8/2I++Idtq2A/yWAygtVFXvUHG4mKj4tY=;
        b=ju27ufTd0wj/FH4eoTL3L+cWPp9LIGvFGXyEgbXD6ccgpYnEkoBdrc8ZYNxxueG6+d
         Yn/gAoMgpM8l64Pp3dhyCde/f3MXH1zbsVXA6R0paWMVVrWSLFBTVt8jOZ5i6Z0idUxv
         Pve9a9Z+lTeutQUhTq/XUy7SXbhq2aMrGX4Jpl2/hYSSAg/+7fleuHSFkrDRng1DDCuN
         P9ZR2wRkcFOy/0quH+AsTjzuXS/bAh1K9Mr6XdjVJHndbK40ED2xRWdKgNJMCd1Nr/az
         rUBCD0GAOo9Y+Kb3MnUDS0EP7UgoXSt6JrEzy2VMZYTBdOMg7XIM86XfATXgvUFfKXYw
         t1/A==
X-Gm-Message-State: AGi0PuZtD+vHeXmnERm8VKDB19Rycel1/URiuOyaMdzwG4sLBopDgr1F
	DcRTgJM97LTfh3DHn5UqBA0=
X-Google-Smtp-Source: APiQypLa9fFgDRNP68Sw11ROqIhtD4R4fMWuEXIS2zBMikro1MC8RwhS0/Emx9VvFOpZSN4B1GK5CA==
X-Received: by 2002:a63:561c:: with SMTP id k28mr18898142pgb.390.1586834271949;
        Mon, 13 Apr 2020 20:17:51 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:d34a:: with SMTP id u10ls2243805pgi.8.gmail; Mon, 13 Apr
 2020 20:17:51 -0700 (PDT)
X-Received: by 2002:a63:7f5d:: with SMTP id p29mr14378058pgn.96.1586834271482;
        Mon, 13 Apr 2020 20:17:51 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1586834271; cv=none;
        d=google.com; s=arc-20160816;
        b=XdEoRdOn6SfIRDRw0MykIxfj04TG+Y/2V5X4+yUUranoCrt7w+I+eikaniopxfRZLN
         BuvnkACcWZK6j7hLtJjPSAWgETcJd6YrnhjmOVClu0/JmYAy9A5TZ96S08jt7QX2J4kl
         JWO43A6qk7IOZ+WTSIfe99lMpqvO/WGhD0E6FFYwfUm42q7ZTs1bIYrm0IdN+skvilUi
         ULS06H9ZogJGUAw5C16s55oJSaOR/c8CPU5fBpLUGcmoXwEe5WYC8aSpkz/n5kwl+RM2
         HoC7/XlRgLye6dDvOZM7e+BBEG4Vs5KsaPiBvKxJNtBLqe2i2YZptzhOibiip4j5VO1q
         6g/w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=lyafSFvaDeRHLhmsBZNecjQ1f+rw68vrQlYD5+Y3w5w=;
        b=jbom9os86AvWnqYoRrGY3d73oEtXZcKzBYF+9/eClmRt4YhKeLG6rBdCj1KY7NnfL7
         /Lky6aAPGT6RgwfUFj3FPekhtb+G1EWDhaZXuLVs/2IVHUIUUwzugbYpJ1XvpjEjR4Is
         oV7uiKo5OVBL9FF6hrHQG1Mz9pTf0VbY3L2+K/ZVrChO3tN9OVYl4f0zsVm0g5JNW046
         QhrxQbkD8TzZl27WFsMzExRLJN2jq+OywR3qspiR5K5wKFHKnE3+2YSJ1OT3ZnwppNO6
         Z+iIivqqD/8Ik8B38P854tyoulxeXQNnJHGpqKhTQ0zi+U74u18pfjCdWZT9u++CULgq
         G8NQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=CWNeHW1R;
       spf=pass (google.com: domain of 3xyuvxggkcqyjg1ojmu2muumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--davidgow.bounces.google.com designates 2607:f8b0:4864:20::549 as permitted sender) smtp.mailfrom=3XyuVXggKCQYjg1ojmu2muumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--davidgow.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pg1-x549.google.com (mail-pg1-x549.google.com. [2607:f8b0:4864:20::549])
        by gmr-mx.google.com with ESMTPS id 194si769836pgd.0.2020.04.13.20.17.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 13 Apr 2020 20:17:51 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3xyuvxggkcqyjg1ojmu2muumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--davidgow.bounces.google.com designates 2607:f8b0:4864:20::549 as permitted sender) client-ip=2607:f8b0:4864:20::549;
Received: by mail-pg1-x549.google.com with SMTP id x16so10372167pgi.0
        for <kasan-dev@googlegroups.com>; Mon, 13 Apr 2020 20:17:51 -0700 (PDT)
X-Received: by 2002:a17:90a:d101:: with SMTP id l1mr25196004pju.1.1586834271190;
 Mon, 13 Apr 2020 20:17:51 -0700 (PDT)
Date: Mon, 13 Apr 2020 20:16:48 -0700
In-Reply-To: <20200414031647.124664-1-davidgow@google.com>
Message-Id: <20200414031647.124664-5-davidgow@google.com>
Mime-Version: 1.0
References: <20200414031647.124664-1-davidgow@google.com>
X-Mailer: git-send-email 2.26.0.110.g2183baf09c-goog
Subject: [PATCH v5 4/4] KASAN: Testing Documentation
From: "'David Gow' via kasan-dev" <kasan-dev@googlegroups.com>
To: trishalfonso@google.com, brendanhiggins@google.com, 
	aryabinin@virtuozzo.com, dvyukov@google.com, mingo@redhat.com, 
	peterz@infradead.org, juri.lelli@redhat.com, vincent.guittot@linaro.org
Cc: linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com, 
	kunit-dev@googlegroups.com, linux-kselftest@vger.kernel.org, 
	David Gow <davidgow@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: davidgow@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=CWNeHW1R;       spf=pass
 (google.com: domain of 3xyuvxggkcqyjg1ojmu2muumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--davidgow.bounces.google.com
 designates 2607:f8b0:4864:20::549 as permitted sender) smtp.mailfrom=3XyuVXggKCQYjg1ojmu2muumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--davidgow.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
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

From: Patricia Alfonso <trishalfonso@google.com>

Include documentation on how to test KASAN using CONFIG_TEST_KASAN and
CONFIG_TEST_KASAN_USER.

Signed-off-by: Patricia Alfonso <trishalfonso@google.com>
Reviewed-by: Dmitry Vyukov <dvyukov@google.com>
Signed-off-by: David Gow <davidgow@google.com>
---
 Documentation/dev-tools/kasan.rst | 70 +++++++++++++++++++++++++++++++
 1 file changed, 70 insertions(+)

diff --git a/Documentation/dev-tools/kasan.rst b/Documentation/dev-tools/kasan.rst
index c652d740735d..287ba063d9f6 100644
--- a/Documentation/dev-tools/kasan.rst
+++ b/Documentation/dev-tools/kasan.rst
@@ -281,3 +281,73 @@ unmapped. This will require changes in arch-specific code.
 
 This allows ``VMAP_STACK`` support on x86, and can simplify support of
 architectures that do not have a fixed module region.
+
+CONFIG_TEST_KASAN & CONFIG_TEST_KASAN_USER
+-------------------------------------------
+
+``CONFIG_TEST_KASAN`` utilizes the KUnit Test Framework for testing.
+This means each test focuses on a small unit of functionality and
+there are a few ways these tests can be run.
+
+Each test will print the KASAN report if an error is detected and then
+print the number of the test and the status of the test:
+
+pass::
+
+        ok 28 - kmalloc_double_kzfree
+or, if kmalloc failed::
+
+        # kmalloc_large_oob_right: ASSERTION FAILED at lib/test_kasan.c:163
+        Expected ptr is not null, but is
+        not ok 4 - kmalloc_large_oob_right
+or, if a KASAN report was expected, but not found::
+
+        # kmalloc_double_kzfree: EXPECTATION FAILED at lib/test_kasan.c:629
+        Expected kasan_data->report_expected == kasan_data->report_found, but
+        kasan_data->report_expected == 1
+        kasan_data->report_found == 0
+        not ok 28 - kmalloc_double_kzfree
+
+All test statuses are tracked as they run and an overall status will
+be printed at the end::
+
+        ok 1 - kasan_kunit_test
+
+or::
+
+        not ok 1 - kasan_kunit_test
+
+(1) Loadable Module
+~~~~~~~~~~~~~~~~~~~~
+
+With ``CONFIG_KUNIT`` built-in, ``CONFIG_TEST_KASAN`` can be built as
+a loadable module and run on any architecture that supports KASAN
+using something like insmod or modprobe.
+
+(2) Built-In
+~~~~~~~~~~~~~
+
+With ``CONFIG_KUNIT`` built-in, ``CONFIG_TEST_KASAN`` can be built-in
+on any architecure that supports KASAN. These and any other KUnit
+tests enabled will run and print the results at boot as a late-init
+call.
+
+(3) Using kunit_tool
+~~~~~~~~~~~~~~~~~~~~~
+
+With ``CONFIG_KUNIT`` and ``CONFIG_TEST_KASAN`` built-in, we can also
+use kunit_tool to see the results of these along with other KUnit
+tests in a more readable way. This will not print the KASAN reports
+of tests that passed. Use `KUnit documentation <https://www.kernel.org/doc/html/latest/dev-tools/kunit/index.html>`_ for more up-to-date
+information on kunit_tool.
+
+.. _KUnit: https://www.kernel.org/doc/html/latest/dev-tools/kunit/index.html
+
+``CONFIG_TEST_KASAN_USER`` is a set of KASAN tests that could not be
+converted to KUnit. These tests can be run only as a module with
+``CONFIG_TEST_KASAN_USER`` built as a loadable module and
+``CONFIG_KASAN`` built-in. The type of error expected and the
+function being run is printed before the expression expected to give
+an error. Then the error is printed, if found, and that test
+should be interpretted to pass only if the error was the one expected
+by the test.
-- 
2.26.0.110.g2183baf09c-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200414031647.124664-5-davidgow%40google.com.
