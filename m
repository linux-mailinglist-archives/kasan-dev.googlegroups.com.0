Return-Path: <kasan-dev+bncBC6OLHHDVUOBBVM7475AKGQEKTJS4NQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3c.google.com (mail-qv1-xf3c.google.com [IPv6:2607:f8b0:4864:20::f3c])
	by mail.lfdr.de (Postfix) with ESMTPS id CB64F263DE8
	for <lists+kasan-dev@lfdr.de>; Thu, 10 Sep 2020 09:03:50 +0200 (CEST)
Received: by mail-qv1-xf3c.google.com with SMTP id l29sf2783039qve.18
        for <lists+kasan-dev@lfdr.de>; Thu, 10 Sep 2020 00:03:50 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1599721429; cv=pass;
        d=google.com; s=arc-20160816;
        b=iADB6ELoBO10vzpkpWJJ28vP6RB47ur58NTHaYdEBm1D/6LO9ZmWvp/zA5mp//TNty
         ftb/rddBMcaK7X73jWYhFZ35zmcOTuJ5m0U/5ld64ASso2gQq96pRoY/c2/+4DH98GKc
         FmB0iIdaAIkZXC+CeB8K+QEzw3PC7J/ckMrH1iNy2m3u+29XANoa73OEsribssRcm8Lo
         VRHu6gChC86SCNf0Af5tOP/Lz7mk2lds4cECwL/avYzSf13ihJ4gmncz7H4AGl+/rroT
         G2K3v1w8lIZry2uZNYxnC8JoK3hxoDJ9WfNgZQeYsUe8Ka6uC0FwLRAg2sNs71spGKC8
         C74g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=swgLSgOalSGaprhBLhCFBdesCAf+IyYM4eN/icQqQ7A=;
        b=c/d5TgFJ42Odq9hgkAcO1S1eprzetnoAXdZYTUtM4JuJtFrrDaWrwqWYGsfraXA33T
         UGXMtN+TbzqX6kRWTCKhzHAiTIFk6Z/9qBMF7Nq8sHBrbz3wobdMf/jBZwAYRCOE/Kha
         4mFA2QXuhTndR5Ul6PiUWrcjUC0n3GAaw9s82bDpGYAXAUXaw7R0jeKgYLOc38B7Cwp3
         1CoqPVtvt5LXhsNgk2xBLiaXjF+ldTYXAXgZrWWzMTd4q9IfLuf0FQorjq7msEb/Q50h
         8rM9sWXOivN3mZejNmKfdM5L45ubdvRr7f0d4vXOqlqRyDDksMQ1Bi2PgSXzMEvR298q
         u/Yw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=AvAqHkXs;
       spf=pass (google.com: domain of 31m9zxwgkcdsa7sfadltdlldib.9ljh7p7k-absdlldibdolrmp.9lj@flex--davidgow.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=31M9ZXwgKCdsA7SFADLTDLLDIB.9LJH7P7K-ABSDLLDIBDOLRMP.9LJ@flex--davidgow.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=swgLSgOalSGaprhBLhCFBdesCAf+IyYM4eN/icQqQ7A=;
        b=ijpXIS5f9dkGzS8CJcHxHaRyaunj+1suakmIulmXeAsn4FN785CilRThWmxzisp//L
         +APEc/ave9jB4g9jkbZSayyFZTGeJlhXiVVL8HZ3mil8RK0kqKwJpkkpx3KAYWX/stMs
         5Wim4gstc2mXwnIkBtpUCHJ6srBpLEldVgKW3ZIZ9oCCAmj6R92zqjMYxG+WhJczKZUp
         txGb63DdpYnY2qUcsv5THKIIff/dK96Ajy3Dzq0H7v18RuvXCWa532VVzNJd/BNFK1wv
         MbcKfbGhhjjsWNEw5Vd9S+bx1RwavdldCfnjmA+7BNlEA8VPI1JD4SfaEz8M1RXyYkbM
         zxWQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=swgLSgOalSGaprhBLhCFBdesCAf+IyYM4eN/icQqQ7A=;
        b=axzpCWqpyyt9E0zJ8w2/Wh9qBCjsYKJ2kBK8LDaRyxIOMPuRmwK2f1oOo68YIrsd0O
         JMo8Aq4X3aKsxTVOCpfY28YfoWuuEcJhVlys4qNOgKS+LMZjS6YQza9v5pUuo62uGYgL
         ZyHeiPol8ZhYvuu6fnk00waWIxz/HlkjgYOIw4h+w7oBEPGuWZthmscF8sB0tra+b4Ef
         SFKTnWx8dAYZ+aL7t3zWEZ8888KJC8Lk5BXdPOsrkii9cirT9ToMtD1HO1JoB7mdLEtQ
         nxnmHkrl/U2Xyud5sJfcVWNJj0f05bqVpJhKuSf6M/PpWc3xT+mYeAalgPPXtJG5N2km
         zrWA==
X-Gm-Message-State: AOAM531ONR90MvWAFDSGnqRr4NIjsV23WIgA9TV9418T5qekA6gYqJ/2
	JKzkosXgGwLtGzzZzoD47tI=
X-Google-Smtp-Source: ABdhPJzMtBxX8qC8ZRNLNIgfYDD6OJ+V46Tw0AaimkWf2tI00MTqKYs4DKuOfCAMsuIMKm8R41GW3g==
X-Received: by 2002:a05:6214:60d:: with SMTP id z13mr7700886qvw.76.1599721429775;
        Thu, 10 Sep 2020 00:03:49 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:1abd:: with SMTP id x58ls1813882qtj.10.gmail; Thu, 10
 Sep 2020 00:03:49 -0700 (PDT)
X-Received: by 2002:ac8:614b:: with SMTP id d11mr6673275qtm.271.1599721429313;
        Thu, 10 Sep 2020 00:03:49 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1599721429; cv=none;
        d=google.com; s=arc-20160816;
        b=o1opgQRLhMmdeoUQ+9Meuq/V9TUFeRzSWDRW7LNgfRprGtaElYNmAo0nniY+yZixFk
         MYFfpiyrrbZb8pskyniucwtVGppY9QR2O8nZ+iMnYcUM2TKQuk2aMMWiKj0vcEeefI+2
         SUh8soiu/wHPgGaslSnS7MYYBfNYgMOsqGnxG8IZVQndvJTiH32MZMKFjinyqIaRazwS
         YMtKrpr9AMpcKAwX/l3f9ByIbT8klmKRi/fbAHj9spsw5w5rM8XeP4Edsn57tNDNfwFh
         PjbK18xwhWJzTB67sKkNxpJptqwvIpKFbZUwGsx8N7kYc4k8923htxnkqPx2MfpL8U+1
         aUYA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=+BKi9csz5osX4KTPzoBomTKB3kjtuT5jT2WVtCJDrmk=;
        b=iRLfKggMqSDWNA/Mi8d1HyydABPpZ4LQmFuEsJHUoiUKgvDQtZpCF0HyIiIYOCsJsU
         /Y9t/UdaBuQlTDeZAe91v/KsRrBuFiUzQV4j8FjoBoWWqfOPNLq7oqWEk5/8vrpkJzBQ
         useK8/eRlAbUEWNjPBZZO+sJm/tUHCfx6LBMyg5Tjf/hol7CoWFPLCusK1zObbJVuDw4
         mta+yyy/mGA5mesT2CMWDXk0UX0qy9VV89cHtHlutv7UY3A1M7mm5RwAtfAvAf+fQSNT
         D+zsepTKkM4JNHM1gvZOtLPTyegri+ZslzvYFtiA2EsIIbTraEmxtNr3uf8e6RX7FGU+
         um2A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=AvAqHkXs;
       spf=pass (google.com: domain of 31m9zxwgkcdsa7sfadltdlldib.9ljh7p7k-absdlldibdolrmp.9lj@flex--davidgow.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=31M9ZXwgKCdsA7SFADLTDLLDIB.9LJH7P7K-ABSDLLDIBDOLRMP.9LJ@flex--davidgow.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb49.google.com (mail-yb1-xb49.google.com. [2607:f8b0:4864:20::b49])
        by gmr-mx.google.com with ESMTPS id q5si276778qkc.2.2020.09.10.00.03.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 10 Sep 2020 00:03:49 -0700 (PDT)
Received-SPF: pass (google.com: domain of 31m9zxwgkcdsa7sfadltdlldib.9ljh7p7k-absdlldibdolrmp.9lj@flex--davidgow.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) client-ip=2607:f8b0:4864:20::b49;
Received: by mail-yb1-xb49.google.com with SMTP id j20so4575561ybt.10
        for <kasan-dev@googlegroups.com>; Thu, 10 Sep 2020 00:03:49 -0700 (PDT)
Sender: "davidgow via sendgmr" <davidgow@spirogrip.svl.corp.google.com>
X-Received: from spirogrip.svl.corp.google.com ([2620:15c:2cb:201:42a8:f0ff:fe4d:3548])
 (user=davidgow job=sendgmr) by 2002:a25:6849:: with SMTP id
 d70mr11302635ybc.117.1599721428940; Thu, 10 Sep 2020 00:03:48 -0700 (PDT)
Date: Thu, 10 Sep 2020 00:03:29 -0700
In-Reply-To: <20200910070331.3358048-1-davidgow@google.com>
Message-Id: <20200910070331.3358048-5-davidgow@google.com>
Mime-Version: 1.0
References: <20200910070331.3358048-1-davidgow@google.com>
X-Mailer: git-send-email 2.28.0.526.ge36021eeef-goog
Subject: [PATCH v13 4/5] KASAN: Testing Documentation
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
 header.i=@google.com header.s=20161025 header.b=AvAqHkXs;       spf=pass
 (google.com: domain of 31m9zxwgkcdsa7sfadltdlldib.9ljh7p7k-absdlldibdolrmp.9lj@flex--davidgow.bounces.google.com
 designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=31M9ZXwgKCdsA7SFADLTDLLDIB.9LJH7P7K-ABSDLLDIBDOLRMP.9LJ@flex--davidgow.bounces.google.com;
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
index 38fd5681fade..072ecdadba07 100644
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
+        ok 1 - kasan
+
+or::
+
+        not ok 1 - kasan
+
+(1) Loadable Module
+~~~~~~~~~~~~~~~~~~~~
+
+With ``CONFIG_KUNIT`` enabled, ``CONFIG_KASAN_KUNIT_TEST`` can be built as
+a loadable module and run on any architecture that supports KASAN
+using something like insmod or modprobe. The module is called ``test_kasan``.
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
2.28.0.526.ge36021eeef-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200910070331.3358048-5-davidgow%40google.com.
