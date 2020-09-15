Return-Path: <kasan-dev+bncBC6OLHHDVUOBB5XXQD5QKGQEM5CSRRA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3b.google.com (mail-io1-xd3b.google.com [IPv6:2607:f8b0:4864:20::d3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 620D6269CBD
	for <lists+kasan-dev@lfdr.de>; Tue, 15 Sep 2020 05:58:47 +0200 (CEST)
Received: by mail-io1-xd3b.google.com with SMTP id e21sf1342035iod.5
        for <lists+kasan-dev@lfdr.de>; Mon, 14 Sep 2020 20:58:47 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1600142326; cv=pass;
        d=google.com; s=arc-20160816;
        b=xIVdzud+a1V0ZcZUHeEibiGdCQ/h63pY1g8oG5dGEOeLGcYT0ITksdDr+rtUUEJ3Hj
         DgeiEz2qRkdRB/DC8istiBLSXiqI2G1CRQ2KkCkMJrr4djkmMgXxgKUArFGh65ALa2jg
         Qw8aqXR5AunTjcV/rs50u2LhB8sITLb5aunccqKDOwgT7ApmyEPNOjuWPm3Nx2oVWm05
         CfLPOH9GEK2aAxlDp1gHVwmnsVBArloYlyFrJWHM5tat6swQABRtfgRxseMXPsCPuLZu
         Pd0/oqyx/pnZlnP8M26+mF1ty0DVKbdA6RWnOup3ITTD6P6L/qByucJ4mJ2JFVqB3qcL
         BiDw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=zxMxJ5Lchs4WPY0ThtK1Kad8w5P7/E7I0eEkzr/z/jM=;
        b=FT/T+3J/+oFJKXJxnjPQow5UfxghoKFW/LTOoUI5zMDqW4si1fOgUSCcRMUdld+YvV
         Dhz668bn8Vj4PLPX3ReZySH30VTMOYWH92zSFOi2mFlGPXTys3rS6AnUin6vbBn2MMnK
         CBan4WBcpONg5D/z9TFbrxf8ka3N7BW2fggJXy2iVisgfG0i7imwk4ixJe1rMyDz36qg
         SSea7DOJydir3C0WlGdjCW0u5VmqFYjH7WZCz0zGofB8u6pCd1jXPwe1RSEDcii9w+uO
         vT9TbIi7qsGQ+Rg5lnVkgXqp3bRGrWkRhYBDCBo5psykhnFmo1D0ESjFiswmukSojr/F
         4TLQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=HPKahaLV;
       spf=pass (google.com: domain of 39ttgxwgkce4tqlytwemweewbu.secaqiqd-tulweewbuwhekfi.sec@flex--davidgow.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=39TtgXwgKCe4TQlYTWemWeeWbU.SecaQiQd-TUlWeeWbUWhekfi.Sec@flex--davidgow.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=zxMxJ5Lchs4WPY0ThtK1Kad8w5P7/E7I0eEkzr/z/jM=;
        b=r25fpt23lOrijzgsUj9yTOuJvrVyx8et7upmOnA81S32LNU/OSxAceLvJw7pRsmpPg
         2kpXDVtdhmJEuD+SjlCR5A74rzOmUr3ITemdmeWSSvENcxi9AZvfjhx3vbHywKdqAMYo
         e3rBsk8vA2GCVMnQR31zZbG3CRcDuRoGlm9LMZGZu03LlS0OjbFJikNTFRs5EZ3/BigP
         BCcs6fkacEsdZD/systDBW+BUXeDJ75tJPoJx6m51pjgYubUmKhQsF/06wfu/VLFl9FX
         tKjMFVxLBM6EMdCi74mQywYUY6pCnPBFXKlpE642iXAn+ltqfeqIX/Jtme3/iptdQ8zW
         kwkA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=zxMxJ5Lchs4WPY0ThtK1Kad8w5P7/E7I0eEkzr/z/jM=;
        b=Mh0q+WKreuovNy5dSQhzHvhBeu3OuVnYTEnTWtT3UuQquFXKnusni1wGvVM1sVh1p6
         OpuG13r0OvGGO6FgPyJzVo3nyvtqOEzi8RtshNyhZV9AE6xpqL8Tge1fpivjRNly7OsM
         +fSCEu6NUz+0NN1SzTeoebXvwIBwDvkcmxAwnDHVyl6Zc7aPIKkiq7ooyrH45mFvd0gM
         6yuC3FWD/l3ydQdfbRGe7/Myayypa1v6u4x4q0vRdGr+WVkXXyh54caPnaZRNumLPRrj
         iyxPQ6jJ3NrEQTH2GcbpgyvNcG5C1SGglwc/tN9BUxdnCWNXh8EULruwHV21wZfUpnzP
         +/Gg==
X-Gm-Message-State: AOAM530XzGpZ6TlhjtY3SHj8sgeYT6WIpiOQziuoQBKmqxEEpWKXbG3R
	igNJ4aeSAx7ekPDA8IrMn/c=
X-Google-Smtp-Source: ABdhPJxOEAeQGDzfkJbG+K1hpcBC6qreNlCvv8PHQ/Ptd0iF4q1i+gjKB0jTamiTqxTuP0NKKHJwwQ==
X-Received: by 2002:a05:6602:1d0:: with SMTP id w16mr14104281iot.102.1600142326372;
        Mon, 14 Sep 2020 20:58:46 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6638:12d0:: with SMTP id v16ls1605817jas.8.gmail; Mon,
 14 Sep 2020 20:58:45 -0700 (PDT)
X-Received: by 2002:a02:9086:: with SMTP id x6mr16706595jaf.126.1600142325909;
        Mon, 14 Sep 2020 20:58:45 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1600142325; cv=none;
        d=google.com; s=arc-20160816;
        b=ldeWlnTHtHt2HJdPZH8e2pVVU4Yl8iSRDRt1ZQybNZRU+GNbGJCII5XzeajlNdvKRq
         kyd4lWRMbffjRT+pETPsf68ulJcrZXmtdK/rOkciJ2q2564sz752RVzbbtH/z7nfanFf
         NFH8DztKu/21y5sUSvftMt+qGTYU138toaO0R4vF7iyCb0pXsW6el5IkT2tqo25XdNXh
         6zYiAcHM4ng3x4aApPc6BCCBjbWyuXn9RS+HzBzNmezQHJJa5y4mF6/gvMH2xv9HBIcX
         82rR58bZWLcG9Y/S7QiTUjBdpIlCTy/kWmL68asJYK4VlfV1nHjmG0uHFlVoa4rSs8UA
         eZXA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=uCglP5LX985FGF4m2PQOWOUblsVZfIf8g+EYcPDK67c=;
        b=g0ssbLGTbygtSSniY8Vz5OOc6QjB74WxjPJY/H5WZIwh+L9wxudtAbKdNNAsbamBKr
         3vEeMbx48LkyaIbxlB+aov08eRT4VoeJSe0CQqZMTuEpEmAYqFhUt471K0SpaOAcvl+l
         FZgIeDoEqbzWlQ2K+IKk1LHfrA1ru1sNZbDGLeQdgZRO3/ySdrO87m45e+3/PVVq+57+
         /twh1FJICVHgFXLdr+LXhhml1wa+1cpJ5gwhEOs9+biBRhB6bxsW2qsnXO+cdozkJ4Ql
         6L+KSHeiND2MIfk0aYxB2RLap1wJIa90J9bb7w4XOcVNMZc5BYnRQlwSLKHfUKzvxH+e
         8exw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=HPKahaLV;
       spf=pass (google.com: domain of 39ttgxwgkce4tqlytwemweewbu.secaqiqd-tulweewbuwhekfi.sec@flex--davidgow.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=39TtgXwgKCe4TQlYTWemWeeWbU.SecaQiQd-TUlWeeWbUWhekfi.Sec@flex--davidgow.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x749.google.com (mail-qk1-x749.google.com. [2607:f8b0:4864:20::749])
        by gmr-mx.google.com with ESMTPS id q22si637172iob.1.2020.09.14.20.58.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 14 Sep 2020 20:58:45 -0700 (PDT)
Received-SPF: pass (google.com: domain of 39ttgxwgkce4tqlytwemweewbu.secaqiqd-tulweewbuwhekfi.sec@flex--davidgow.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) client-ip=2607:f8b0:4864:20::749;
Received: by mail-qk1-x749.google.com with SMTP id q131so1970361qke.22
        for <kasan-dev@googlegroups.com>; Mon, 14 Sep 2020 20:58:45 -0700 (PDT)
Sender: "davidgow via sendgmr" <davidgow@spirogrip.svl.corp.google.com>
X-Received: from spirogrip.svl.corp.google.com ([2620:15c:2cb:201:42a8:f0ff:fe4d:3548])
 (user=davidgow job=sendgmr) by 2002:a0c:f48e:: with SMTP id
 i14mr16532536qvm.9.1600142325247; Mon, 14 Sep 2020 20:58:45 -0700 (PDT)
Date: Mon, 14 Sep 2020 20:58:27 -0700
In-Reply-To: <20200915035828.570483-1-davidgow@google.com>
Message-Id: <20200915035828.570483-5-davidgow@google.com>
Mime-Version: 1.0
References: <20200915035828.570483-1-davidgow@google.com>
X-Mailer: git-send-email 2.28.0.618.gf4bc123cb7-goog
Subject: [PATCH v14 4/5] KASAN: Testing Documentation
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
 header.i=@google.com header.s=20161025 header.b=HPKahaLV;       spf=pass
 (google.com: domain of 39ttgxwgkce4tqlytwemweewbu.secaqiqd-tulweewbuwhekfi.sec@flex--davidgow.bounces.google.com
 designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=39TtgXwgKCe4TQlYTWemWeeWbU.SecaQiQd-TUlWeeWbUWhekfi.Sec@flex--davidgow.bounces.google.com;
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
2.28.0.618.gf4bc123cb7-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200915035828.570483-5-davidgow%40google.com.
