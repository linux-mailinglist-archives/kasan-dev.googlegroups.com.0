Return-Path: <kasan-dev+bncBC6OLHHDVUOBBIO6ZD4QKGQEFZ4VWBQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa38.google.com (mail-vk1-xa38.google.com [IPv6:2607:f8b0:4864:20::a38])
	by mail.lfdr.de (Postfix) with ESMTPS id 5E9CC241609
	for <lists+kasan-dev@lfdr.de>; Tue, 11 Aug 2020 07:39:46 +0200 (CEST)
Received: by mail-vk1-xa38.google.com with SMTP id q206sf3844158vkb.14
        for <lists+kasan-dev@lfdr.de>; Mon, 10 Aug 2020 22:39:46 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1597124385; cv=pass;
        d=google.com; s=arc-20160816;
        b=WCRaF34Y7Q2XBaiLQjOuKYgvnqPEtUFa+5BQgDKL6YTRP/D/A1oINRd9NP6HqbIAAr
         qbrO93WCqzfYyhXLZTMvTTPlolO2X2Ur3XLozuUZIiz26+dfUu1fuEiAhB3FZMzfw8sx
         WcFZe5FuO4E+AsnDpUtlrP2InqeCi8vIGdwZrrPPouxbh8OaUDbFYqUz0QRDxt32s8Vx
         ni8VaFXOQNVGyN7CD7CPea/wPfCmINmq/xEzroAeeh+3VwZeoGh81VpiE3SfCBUEQ2Ir
         JgLrenT2WLbXXYaG9COFj0WgpeXkvccKpf245BUDh5o5nDk/kFIkAaZj5OHo93B9/ClS
         mqWA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=y6fSGU23TSEDNptgdR519Pr6SfjPSzxGb4Obc0EYaZw=;
        b=Bj8i0A9m3ethsvcFlo0QBkhbpqmdS0+S5tCAFwqJalbZ38CTVh3enDrGGkCj5A7B6J
         lpjmYksjYKuyW2blk94inadAuTJGX1DU8uvUtxXdaFsOFjVXUEt8VTlLGX3s0PjnDpbq
         O0N7pKBowhnHs3SZWVRJI/aitxHecJLdSfT6oTBYbn7wDzrFOMkreJmJjpQqooONtgNw
         SmR+NaHwUhJgGzwnwdEPTGfRUidbojTgFokcU0iOfi5rLipdO7ShojRdexb2X3VbyFyp
         aXyqt7nv+vr8UpUKzEiJTcdbsVbFUiBIQM0KCQZ9qJQFAKLC9tfhQcWmoTR3NZNAgkZM
         dmaw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=FV8uMO3a;
       spf=pass (google.com: domain of 3ic8yxwgkcucmj4rmpx5pxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--davidgow.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3IC8yXwgKCUcmj4rmpx5pxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--davidgow.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=y6fSGU23TSEDNptgdR519Pr6SfjPSzxGb4Obc0EYaZw=;
        b=PhW0kR44OQEKXmrgj4T5IGkHMpB9P+SlAn1kwWj42h3ZZt4jH1zGZlL+UoXJ1dABFk
         OAr+BrUtn+duxh2WwIe9C7BaCvQ8SVPpPVQ3IXLt8v4XSDx2ee21vIuExu7eGfRXoEre
         JfWqXODEIU8Dr1wWdr5ozA5JenY2NwHCNfLHI+L8uzXyBZBwUk+38Zzn7itJxCqYMrDE
         1TJbX83aYvFNQqC/Kr8k/5VGaRpoB5kL09G95rVVIxM2VLyvjbqYxqv/9zSP3sDBl+s7
         8GbA7u6k3Tb6tdQ6jjxzzaJd9A37RyC76Ko5QWVozuncZhltLwS1HOCot38hCEKLwSfV
         IDnw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=y6fSGU23TSEDNptgdR519Pr6SfjPSzxGb4Obc0EYaZw=;
        b=Gr7JzGm8D6jZ+OHsaWl8qfTQPWVZ+YqK6hT8IiN34CtNU0eCcua5TIIYJnHuCfRSWA
         seWU8eYS6RAwz5nBMwTXHVH1K0LEMNgVdogBw1qE0EIp0ueBexFvbZvyKP9ZddK544Fg
         nnz6h/yyX+fh21uuO4sMeOcp3FV8bdmIKIZbhi7JQ7yYK6xJ/oEHR2G9OzOjOMcV2F1M
         s0/9AhON6mnbE4o8MtSnn3Yru9+CRcYHpQ4UikqGFYq0uafokKarAAZdGAp8Hs6v4Or6
         hr2cHRTIZswR8kIe6N1WBg9VoT+DYd9bIP4nozENgbP4RyPw7+TfojhneVI4RD2QBoWZ
         yBIA==
X-Gm-Message-State: AOAM532lgSVQD7w5dU0FHSM6rmjijUdLx5sWX+mjmT6ei2+zzGzS+GXT
	hFdrgYw6qhE4oW9b8AEHo7g=
X-Google-Smtp-Source: ABdhPJyXni9kYzkLx6Op+v0TnthZB1hcQt+D326Lo69XFeDtH7xRRh88s1MIjhv0eLtTnzWieiAf8w==
X-Received: by 2002:ab0:70af:: with SMTP id q15mr22237893ual.84.1597124385146;
        Mon, 10 Aug 2020 22:39:45 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ab0:211a:: with SMTP id d26ls1025365ual.3.gmail; Mon, 10 Aug
 2020 22:39:44 -0700 (PDT)
X-Received: by 2002:ab0:1ecc:: with SMTP id p12mr21775378uak.58.1597124384712;
        Mon, 10 Aug 2020 22:39:44 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1597124384; cv=none;
        d=google.com; s=arc-20160816;
        b=Jq+3ovK7pPfvZc11abYDYtJeO4i/GJuAlCoJLJTTWmCg7kcKl+tr95JbdM1zNqzR1+
         J4zcHUH5wcmGfc+elqK2LkCw0BAWo2m3TIwvBknCA6OHKMWP8IqyhvmUX4E2ZwEd+3/z
         wyVxSZWa0BX+hLc6HatzJQcaegZ+NibjoC6wCcZ8S2NQWrzoFbAiwj70ZqNDD6Vs1tJs
         P26+kZrnWRR5vZoZOY9Em3OrCk6fj2wDcQO7UCkW5H1FXlWeDs5x9XtSP3Xjfc9W8Ajm
         C+FGnCq+XQitye8CqA8/YLvDw9JgfXdDA2DXvr6IKRXzhife3aYYmmJ8m2BIPbROO302
         /U2w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=45vX/OukMjmRJbYoiR0tKiPizR257EeVnpqPnjVNEcE=;
        b=IuJM2u4/MMdQRol5T0ChlZ/j3e0pvFHrbwNeDFdfiyZtbqpsV34L9bIJMRoE0iI0JW
         mgKu7nXRFSfuDQ7QnHnIWeEBt/DQc54LMbLrf/z8F8zL73MNVSplmSKQO3FtGKnEIiLg
         GfFeVWTTw963hqkf1j+vzR9D3hNqOcCpXTZcOPQtHL20BDuBpoJ9KyQl8dev494WoRCq
         MCsmgQpDt1nGfNaW2qM4RuOYs1W7uF+iQ2ZyU1XI5TSiYvzmJnuC0+sZsoYaLxKIUaf7
         MZzqzZKKwkdAhBQhp+Itv/EbZjYxBxp1KKJgK05UqXPiR+P0L43HQC1X3x0kBoMlupPm
         6tsQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=FV8uMO3a;
       spf=pass (google.com: domain of 3ic8yxwgkcucmj4rmpx5pxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--davidgow.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3IC8yXwgKCUcmj4rmpx5pxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--davidgow.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf49.google.com (mail-qv1-xf49.google.com. [2607:f8b0:4864:20::f49])
        by gmr-mx.google.com with ESMTPS id u18si143515vsq.0.2020.08.10.22.39.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 10 Aug 2020 22:39:44 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3ic8yxwgkcucmj4rmpx5pxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--davidgow.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) client-ip=2607:f8b0:4864:20::f49;
Received: by mail-qv1-xf49.google.com with SMTP id q12so8858021qvm.19
        for <kasan-dev@googlegroups.com>; Mon, 10 Aug 2020 22:39:44 -0700 (PDT)
X-Received: by 2002:a0c:fdeb:: with SMTP id m11mr32366961qvu.103.1597124384218;
 Mon, 10 Aug 2020 22:39:44 -0700 (PDT)
Date: Mon, 10 Aug 2020 22:39:14 -0700
In-Reply-To: <20200811053914.652710-1-davidgow@google.com>
Message-Id: <20200811053914.652710-6-davidgow@google.com>
Mime-Version: 1.0
References: <20200811053914.652710-1-davidgow@google.com>
X-Mailer: git-send-email 2.28.0.236.gb10cc79966-goog
Subject: [PATCH v12 5/6] KASAN: Testing Documentation
From: "'David Gow' via kasan-dev" <kasan-dev@googlegroups.com>
To: trishalfonso@google.com, brendanhiggins@google.com, 
	aryabinin@virtuozzo.com, dvyukov@google.com, mingo@redhat.com, 
	peterz@infradead.org, juri.lelli@redhat.com, vincent.guittot@linaro.org, 
	andreyknvl@google.com, shuah@kernel.org, akpm@linux-foundation.org
Cc: linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com, 
	kunit-dev@googlegroups.com, linux-kselftest@vger.kernel.org, 
	linux-mm@kvack.org, David Gow <davidgow@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: davidgow@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=FV8uMO3a;       spf=pass
 (google.com: domain of 3ic8yxwgkcucmj4rmpx5pxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--davidgow.bounces.google.com
 designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3IC8yXwgKCUcmj4rmpx5pxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--davidgow.bounces.google.com;
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

Include documentation on how to test KASAN using CONFIG_TEST_KASAN_KUNIT
and CONFIG_TEST_KASAN_MODULE.

Signed-off-by: Patricia Alfonso <trishalfonso@google.com>
Signed-off-by: David Gow <davidgow@google.com>
Reviewed-by: Andrey Konovalov <andreyknvl@google.com>
Reviewed-by: Dmitry Vyukov <dvyukov@google.com>
Acked-by: Brendan Higgins <brendanhiggins@google.com>
Tested-by: Andrey Konovalov <andreyknvl@google.com>
---
 Documentation/dev-tools/kasan.rst | 70 +++++++++++++++++++++++++++++++
 1 file changed, 70 insertions(+)

diff --git a/Documentation/dev-tools/kasan.rst b/Documentation/dev-tools/kasan.rst
index 38fd5681fade..42991e40cbe1 100644
--- a/Documentation/dev-tools/kasan.rst
+++ b/Documentation/dev-tools/kasan.rst
@@ -281,3 +281,73 @@ unmapped. This will require changes in arch-specific code.
 
 This allows ``VMAP_STACK`` support on x86, and can simplify support of
 architectures that do not have a fixed module region.
+
+CONFIG_KASAN_KUNIT_TEST & CONFIG_TEST_KASAN_MODULE
+--------------------------------------------------
+
+``CONFIG_KASAN_KUNIT_TEST`` utilizes the KUnit Test Framework for testing.
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
+With ``CONFIG_KUNIT`` enabled, ``CONFIG_KASAN_KUNIT_TEST`` can be built as
+a loadable module and run on any architecture that supports KASAN
+using something like insmod or modprobe.
+
+(2) Built-In
+~~~~~~~~~~~~~
+
+With ``CONFIG_KUNIT`` built-in, ``CONFIG_KASAN_KUNIT_TEST`` can be built-in
+on any architecure that supports KASAN. These and any other KUnit
+tests enabled will run and print the results at boot as a late-init
+call.
+
+(3) Using kunit_tool
+~~~~~~~~~~~~~~~~~~~~~
+
+With ``CONFIG_KUNIT`` and ``CONFIG_KASAN_KUNIT_TEST`` built-in, we can also
+use kunit_tool to see the results of these along with other KUnit
+tests in a more readable way. This will not print the KASAN reports
+of tests that passed. Use `KUnit documentation <https://www.kernel.org/doc/html/latest/dev-tools/kunit/index.html>`_ for more up-to-date
+information on kunit_tool.
+
+.. _KUnit: https://www.kernel.org/doc/html/latest/dev-tools/kunit/index.html
+
+``CONFIG_TEST_KASAN_MODULE`` is a set of KASAN tests that could not be
+converted to KUnit. These tests can be run only as a module with
+``CONFIG_TEST_KASAN_MODULE`` built as a loadable module and
+``CONFIG_KASAN`` built-in. The type of error expected and the
+function being run is printed before the expression expected to give
+an error. Then the error is printed, if found, and that test
+should be interpretted to pass only if the error was the one expected
+by the test.
-- 
2.28.0.236.gb10cc79966-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200811053914.652710-6-davidgow%40google.com.
