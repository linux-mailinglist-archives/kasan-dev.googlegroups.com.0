Return-Path: <kasan-dev+bncBDK3TPOVRULBBTFRSP2AKGQEMAIJLFQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x437.google.com (mail-pf1-x437.google.com [IPv6:2607:f8b0:4864:20::437])
	by mail.lfdr.de (Postfix) with ESMTPS id 030FF19B520
	for <lists+kasan-dev@lfdr.de>; Wed,  1 Apr 2020 20:09:18 +0200 (CEST)
Received: by mail-pf1-x437.google.com with SMTP id i1sf307727pfo.19
        for <lists+kasan-dev@lfdr.de>; Wed, 01 Apr 2020 11:09:17 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1585764556; cv=pass;
        d=google.com; s=arc-20160816;
        b=bHY+yUR6+sN168CQsavMT7CMkYrZKDoLvQ9RBaNwaVZO6PwdTTHlSCZnYHVBNmv5az
         DDqovGldzwUPd5V8nWm5eSxEH+na4zPtUY6FsPETkEGLS7YS9GXruwHcH1YLEhCS+pa8
         JdNkHoWBb1f704Jz3hRMAsMqrmNwNubZlZNTzDqABiDFhZqqX2dVoe6bpU3e1HdSyV/B
         34VeNnAVER+ZOLTJ8tU3YHi3/3AJyRt0s2KtZMt5Z4qYFmEqKlCvjUOIaUkqecAfFgrY
         tqp3n9rXJbuTgUvPwPCqlXTvkLpBMyMofsxOrW7dVnzKU8OIIV2rgeySswSlTj2/MVy1
         wFRA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=NYbVlk+StjEO7Ady7Zcg9tQApjJzFWwHagPmh/RmfwI=;
        b=iAucB7s0swGa60YPxDsc8ve0MjsIkxDlAm4Kcl9Q1JV2l860pwrH9etAOHGSdVfJTx
         s3NJuM1jiAOrmRS7NGwdI1e14RBo8IfdJn+zPIayNaQIKEvfUmzTOYbCsSbHTRI7YWI8
         uKWuzCQTSGBuPR4T53snaO0lLUl/E5jmFQLyJIHiHj1u3tvwxIkCKOmvr4i4rGayM+QO
         klnIQX+x4R6CHlQOFBb3pMno3RuGeDEsX/tB7FOT75SAA8twhdrGbN4gPylbqmowZuHj
         D5MT8ajfDjm30COwWbzJDy4Ekem05OJyi6bq2rKaELVrkMUdSOUpg1kNGJapf7dWSXwZ
         Wqpg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=HYgbJZF8;
       spf=pass (google.com: domain of 3y9iexgwkcyo75w6vozt2162u22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--trishalfonso.bounces.google.com designates 2607:f8b0:4864:20::1049 as permitted sender) smtp.mailfrom=3y9iEXgwKCYo75w6vozt2162u22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--trishalfonso.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=NYbVlk+StjEO7Ady7Zcg9tQApjJzFWwHagPmh/RmfwI=;
        b=dGzCWFA1nqVPhx2pbMHX06lrTn1sXU289qdQtgVDWhayfXNfbwlM0murg4G90fu0JU
         uAUHbbj6cxFOj7HC69iNQnOSbd4iaesJ6uqa099nBKCINheIKbznwJCLZ0TzHfINECAi
         U23xSyCx5oUqIGsAHfw92cEfzvDS0ORLXHg/DG0G8yDOZ/M4R80AAauJPQAVSSR6QJSu
         xu2MFr2WCLWNg+sP7t6wr0ZGrXA3kx5gD/YGlkM9ssOICNgukEGqgrxGQqxxedNh5Z6W
         OU0eStg5k7ViuzVvtjfepa1flp8oxxIwLE0AqeQinr7wlmANufEzunbT20OsD2rUNISB
         Byiw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=NYbVlk+StjEO7Ady7Zcg9tQApjJzFWwHagPmh/RmfwI=;
        b=m1sTpasFlQZhsX3YB23cJ9xmgb52+TGDgp1TljYTQ1UgKMf4ByeGtJxDkraeeNGddB
         SEZmgu14lm4F4cMmEpV3LYmpCf+haV9JIxZCfaH4F6o7CVj188GyrNjhWL2eGlnxBYxi
         okZFw2VXnJhtCp2lDU8bn+KAqWn3N36PZiyk3LM1TWiE/rGr4HggdQLBgW+vcMbRpEOR
         jKr3gkw7hZKfy2IjN0Vnzs5Jd9Allf/Y8I3tTbv+1xnPep09II/HDAcEaAMk0wFMy81K
         xeA49db3ug2f2R+nU70wvF/AfeNvPO2Ic/81mMM2CZmFOIFPV7ckTCvG3cQSwpLw8kma
         yRTg==
X-Gm-Message-State: AGi0Puawm46QLAYf8+XfDHym5HGt7vTgp7BG4edj40A0ZikwJ3pZ+Khv
	wdTpAchaQs3rhZ9d7kyIi78=
X-Google-Smtp-Source: APiQypJntLOjrNRAVyCmaLp3qhaR9MkljWyIVR8gYNPPdZf8MljHNYU53YH6I/oucBL3JDIySGAuSw==
X-Received: by 2002:a17:902:be12:: with SMTP id r18mr15714872pls.303.1585764556624;
        Wed, 01 Apr 2020 11:09:16 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:a418:: with SMTP id p24ls316788plq.1.gmail; Wed, 01
 Apr 2020 11:09:16 -0700 (PDT)
X-Received: by 2002:a17:902:8509:: with SMTP id bj9mr10522372plb.64.1585764556157;
        Wed, 01 Apr 2020 11:09:16 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1585764556; cv=none;
        d=google.com; s=arc-20160816;
        b=WjBTg/sZ1PSNs/ddc3vo+5LMLR3kWwhs3L3OrFuLzmT3/9hUObFyPxlc6i616FZyFi
         GbB8Jkc24woie4jtiC+8bFrE2y8mvj2sPyLXoj9UmSEVHQT42EZKXJNM4Jf5ZRZQ/o93
         OzKioLBSw8vM2jMkIDpCaUDOxlkx6oQMQzIaGcUWLmbHoOKzykFKp3z+gWJkTIq03xrq
         PkPY9dxEQW6+FzT0b9V6cJJtIhtznS8O9cerCRxO+tKezWyaYNGyxvIQ6KpZAKO5brlk
         d58MNpaVtyE7Z9aTrtXNdjP57WWvqAN9Bx/mILnR5pwlhIrfxs6OQ/b9ou+LebEyFrt6
         C17w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=sl7H9I59bpRm4U1wnt7pV7FscJTzqhyyGtH4qFo0cnw=;
        b=IKJRhByq2pGpwkruFP0Ry7BwpibJe2elPabDJRWsTzstCvH1dMcCAQh7SXPldoQTw2
         FdJAF7BgXI0jDVNEp/6PfiVJuDPNcZsi0PE6XA5mJdBiE8V7pm5RQ58vXW482AwtlIJv
         C93gLMjDc8N8UOo7CRoOtxFUTuIHM8hGrfkRSJnftTQeThtanwI8Q8f8B/OFDNiMcgc4
         i4lb3DE3YLVwag9EkKgIGrN/+pPFYzK7ALSN7stpmenkjuOUfzjNC+AkYS8CHbruiXVU
         fxaLSG8gaGid6TN7dF8JlVFAN2e0gXx7IC+L+/2u4jfmMvY6tr9TXMKI6k7/CyXZDSfH
         r7WA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=HYgbJZF8;
       spf=pass (google.com: domain of 3y9iexgwkcyo75w6vozt2162u22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--trishalfonso.bounces.google.com designates 2607:f8b0:4864:20::1049 as permitted sender) smtp.mailfrom=3y9iEXgwKCYo75w6vozt2162u22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--trishalfonso.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pj1-x1049.google.com (mail-pj1-x1049.google.com. [2607:f8b0:4864:20::1049])
        by gmr-mx.google.com with ESMTPS id 62si206699pgf.0.2020.04.01.11.09.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 01 Apr 2020 11:09:16 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3y9iexgwkcyo75w6vozt2162u22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--trishalfonso.bounces.google.com designates 2607:f8b0:4864:20::1049 as permitted sender) client-ip=2607:f8b0:4864:20::1049;
Received: by mail-pj1-x1049.google.com with SMTP id np18so839673pjb.1
        for <kasan-dev@googlegroups.com>; Wed, 01 Apr 2020 11:09:16 -0700 (PDT)
X-Received: by 2002:a17:90b:3610:: with SMTP id ml16mr6405214pjb.106.1585764555886;
 Wed, 01 Apr 2020 11:09:15 -0700 (PDT)
Date: Wed,  1 Apr 2020 11:09:05 -0700
In-Reply-To: <20200401180907.202604-1-trishalfonso@google.com>
Message-Id: <20200401180907.202604-3-trishalfonso@google.com>
Mime-Version: 1.0
References: <20200401180907.202604-1-trishalfonso@google.com>
X-Mailer: git-send-email 2.26.0.rc2.310.g2932bb562d-goog
Subject: [PATCH v3 4/4] KASAN: Testing Documentation
From: "'Patricia Alfonso' via kasan-dev" <kasan-dev@googlegroups.com>
To: davidgow@google.com, brendanhiggins@google.com, aryabinin@virtuozzo.com, 
	dvyukov@google.com, mingo@redhat.com, peterz@infradead.org, 
	juri.lelli@redhat.com, vincent.guittot@linaro.org
Cc: linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com, 
	kunit-dev@googlegroups.com, linux-kselftest@vger.kernel.org, 
	Patricia Alfonso <trishalfonso@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: trishalfonso@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=HYgbJZF8;       spf=pass
 (google.com: domain of 3y9iexgwkcyo75w6vozt2162u22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--trishalfonso.bounces.google.com
 designates 2607:f8b0:4864:20::1049 as permitted sender) smtp.mailfrom=3y9iEXgwKCYo75w6vozt2162u22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--trishalfonso.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Patricia Alfonso <trishalfonso@google.com>
Reply-To: Patricia Alfonso <trishalfonso@google.com>
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

Include documentation on how to test KASAN using CONFIG_TEST_KASAN and
CONFIG_TEST_KASAN_USER.

Signed-off-by: Patricia Alfonso <trishalfonso@google.com>
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
2.26.0.rc2.310.g2932bb562d-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200401180907.202604-3-trishalfonso%40google.com.
