Return-Path: <kasan-dev+bncBC6OLHHDVUOBBZ774SNAMGQECMPIXHQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3c.google.com (mail-oa1-x3c.google.com [IPv6:2001:4860:4864:20::3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 20DA560E2E3
	for <lists+kasan-dev@lfdr.de>; Wed, 26 Oct 2022 16:10:49 +0200 (CEST)
Received: by mail-oa1-x3c.google.com with SMTP id 586e51a60fabf-131caeb598bsf8696798fac.12
        for <lists+kasan-dev@lfdr.de>; Wed, 26 Oct 2022 07:10:49 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1666793447; cv=pass;
        d=google.com; s=arc-20160816;
        b=jPOgo21eX3MQVr+oEzRNQ5YJvcPgtx6umZBo4kavaBgqKjArji/6GGJcUoz+n+Fv89
         oxJxCAh2uYa6WepLCFBBEUES54E4oWMz1kms7BfivIE3kOB2vTWtIhjokFsHqQa1kLem
         GU0o0dXx93SJPaZlKGUslltr6QeXvp8hoPAx5q3jSmc0oxIGaAQ3H2gw9hsSk7hq1l6S
         IhZdqWdI6tfb6kvayMSaqZkAXG9hJKrs6u4YMu5Rv6oimk0Ue07591iWwAP4WXFngoC0
         1gbH3jGkcTyinguhLv9TkM13d497ecEAhD0UBPaNoMrWxdbpItUXhPzUxuDNbh+DYUT8
         FQpg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:mime-version:date:dkim-signature;
        bh=oYPfnhz+dD2bxhXWtHfWeNDDKuS8yUxo8Z3y37gbJs0=;
        b=EAiR7J341qxQvHrEn/pIepoZ0uLAtHQI6zMSV4ZZzXTeyfwFQcRLX9wn2RpnZDABhv
         DHNhe/4FV8+XuHsK7CUib4rqQR6V+IK407uCsvz6YRoI3UZGfeXdDXPiZN+A01YoqoJd
         BbV96zlwVuhgny0d8ULgQN5rAJjDyO1xIbAn9DpwKrzIlxvevlwtvL7xj/7YGg5xkTUf
         XCnTWUmmG0MrWqmmfm43p3ndqMgNgeDMirO577t62U/o0EeB+oWY8IVBtagaA2OpB2Uc
         r1pJ/Lk/zBCdjQQkiJwTqUBmWZcD26s6Z9VrpE7H7vR4yDB82P3v8c8dYcD90A+EdjUQ
         rpzA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=MpZihCZI;
       spf=pass (google.com: domain of 35j9zywgkcesqnivqtbjtbbtyr.pbzxnfna-qritbbtyrtebhcf.pbz@flex--davidgow.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=35j9ZYwgKCesQNiVQTbjTbbTYR.PbZXNfNa-QRiTbbTYRTebhcf.PbZ@flex--davidgow.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:mime-version:date:from:to:cc:subject:date
         :message-id:reply-to;
        bh=oYPfnhz+dD2bxhXWtHfWeNDDKuS8yUxo8Z3y37gbJs0=;
        b=csF257oFSJ7iS4kZGzHRSi1FYc0Lu/XHpfO9cbfRsGaQzeM50wdA23bUtgjxqRTnSB
         hTNTxcI9eFlvlAO+DdEeRjCAw0FAMzQmWLKBBdWXs+Bh9i8oio/LxwSXoZajRWnchMby
         7GhnKFW8wqyAWCeU0zslFmw3dRaANHP+DbR1j5whsjEh9lbnhl/JqDbnb9oumRM7ypOQ
         /NDJCr+2krNXp/Zkf03/+rBRmY+++QLgU7VKhDNa65AYF1WMDlwOu/dT9CflnBdSVJPH
         DYcoqmdyzr6tuzJhYA/apIRYhidwmCA+/cTxPnUTtXsSvNanMHMaKpvSVMhn/JA7DnqB
         19Tw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:mime-version:date:x-gm-message-state:from:to:cc
         :subject:date:message-id:reply-to;
        bh=oYPfnhz+dD2bxhXWtHfWeNDDKuS8yUxo8Z3y37gbJs0=;
        b=IAzoOrDq+EayltAt6Qa9IZUwz02hxlAWXFGRbn2TIJ0zQnGiWCQfdkB0tOcVnR1hJH
         DaU3uG1GTY04Zvc4i60DKlXJV5rKoQIcq+p4Y+1plHabVW9elUbQtJEVxBm5G6HikO5f
         t9sP2FgBJF68N7XiaEK72jcGK1kw8tooKxSgAf2kXifxhI2LHbfwbNTC0zUvv3TNbYOK
         v0w4GK/E5YQx3ooWxpsux9cBh2y5Vj9RjqVEroxdgoV3+BqspQdLP1a2rgHBqiHQMv2b
         7flt6YBMXZqUr0k5aa5gpVaBESZy7T+RshD1FO3YICETjl+rSVa3cFZ0t8FNYFFc7ffp
         qMqg==
X-Gm-Message-State: ACrzQf3rKs4maoOSXNJ+4C5+4xcqdQaYf9JYjx2dwXySAfQsjJHsLeVy
	f13eSL35+tCL4Gg2BY5p3Sg=
X-Google-Smtp-Source: AMsMyM5gPlcIk7hexMp3jpCK+08OMc5bSG0GsNzJt94UgWs4LYosezu+Wv5LbvqWADMhmoNiLhdsdA==
X-Received: by 2002:a05:6871:71f:b0:13b:7f4d:1eae with SMTP id f31-20020a056871071f00b0013b7f4d1eaemr2283343oap.201.1666793447371;
        Wed, 26 Oct 2022 07:10:47 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:502:0:b0:357:5ddf:b56e with SMTP id 2-20020aca0502000000b003575ddfb56els2762411oif.7.-pod-prod-gmail;
 Wed, 26 Oct 2022 07:10:46 -0700 (PDT)
X-Received: by 2002:a05:6808:219a:b0:354:daec:53cb with SMTP id be26-20020a056808219a00b00354daec53cbmr1892089oib.2.1666793446787;
        Wed, 26 Oct 2022 07:10:46 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1666793446; cv=none;
        d=google.com; s=arc-20160816;
        b=N89b89OSxVAWEvHoCILGgmAgPtmWOEC84Y5xhizbc44tcfMLDd65vJNtwuToa+YdMj
         9zU0kGeo5vhqVsrI5K1Xr0VxtIekbG0gSTDDPfW0r3mlEQkJ9O0K8kz4txmZRWLXSD3n
         0CzVIBbfSff8vxBEgsV8rBXfvKMUrMKngGMhXH3B5khqJJ0k7l+SwHN2+JkD08+noCNA
         fX1UbhI0+2/NVl6KSLFUuu6BhCLA85Q3U4jPBLp0e5+gh1SUkCd3H0vkTVqrmwS/yZyb
         90ejwp0WkF2jglHRqRytAD4RgG5Wv5OXJ45GEJlcxjE0f/hrN/I/g1/2EnQJZxt46rXg
         PaCQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:mime-version:date:dkim-signature;
        bh=oVCnLyxMsU2FaLl3D+PS+uuU9HLGod0PTLLsMzXQBPI=;
        b=GtO7NjF+4AzdBDFUDy58VUKAP2rNeLLVQgda6P8dPvLNKqIrm65wKBSLhqq5cne6jt
         NA2naHOHqRdWjK2/1yNt0gJxmihxzBDNz3Ch3t18SA1/sTz9+cNp1bB14AoUeMxHFGeh
         IBkdmei+M4aAuN0DSnZ3hSBgn1UReibb+AVMtS3iQpWj3dbkAnk+Oy9sEd02sIWDdVXX
         an0syl0348Bzhu6r8I2W4KgXGO8Pv05a9s+IHciHCKkFxBdrleYYwMNPD+cvbyk0om0w
         Ndfv0cj8PxqKSB2vNBsKnJRVQaY7EBZitBy/txZ9SwNlMEo3EUNjtiJkDHpiCnJ1aNrm
         cTLg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=MpZihCZI;
       spf=pass (google.com: domain of 35j9zywgkcesqnivqtbjtbbtyr.pbzxnfna-qritbbtyrtebhcf.pbz@flex--davidgow.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=35j9ZYwgKCesQNiVQTbjTbbTYR.PbZXNfNa-QRiTbbTYRTebhcf.PbZ@flex--davidgow.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x114a.google.com (mail-yw1-x114a.google.com. [2607:f8b0:4864:20::114a])
        by gmr-mx.google.com with ESMTPS id 65-20020aca0744000000b00353e4e7f335si216050oih.4.2022.10.26.07.10.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 26 Oct 2022 07:10:46 -0700 (PDT)
Received-SPF: pass (google.com: domain of 35j9zywgkcesqnivqtbjtbbtyr.pbzxnfna-qritbbtyrtebhcf.pbz@flex--davidgow.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) client-ip=2607:f8b0:4864:20::114a;
Received: by mail-yw1-x114a.google.com with SMTP id 00721157ae682-36b1a68bfa6so107860177b3.22
        for <kasan-dev@googlegroups.com>; Wed, 26 Oct 2022 07:10:46 -0700 (PDT)
X-Received: from slicestar.c.googlers.com ([fda3:e722:ac3:cc00:4f:4b78:c0a8:20a1])
 (user=davidgow job=sendgmr) by 2002:a0d:d857:0:b0:36f:c0f7:f0ec with SMTP id
 a84-20020a0dd857000000b0036fc0f7f0ecmr7838435ywe.82.1666793446446; Wed, 26
 Oct 2022 07:10:46 -0700 (PDT)
Date: Wed, 26 Oct 2022 22:10:40 +0800
Mime-Version: 1.0
X-Mailer: git-send-email 2.38.0.135.g90850a2211-goog
Message-ID: <20221026141040.1609203-1-davidgow@google.com>
Subject: [PATCH] perf/hw_breakpoint: test: Skip the test if dependencies unmet
From: "'David Gow' via kasan-dev" <kasan-dev@googlegroups.com>
To: Marco Elver <elver@google.com>, Peter Zijlstra <peterz@infradead.org>, 
	Ingo Molnar <mingo@redhat.com>, Dmitry Vyukov <dvyukov@google.com>
Cc: David Gow <davidgow@google.com>, linux-perf-users@vger.kernel.org, 
	linux-kernel@vger.kernel.org, kunit-dev@googlegroups.com, 
	Brendan Higgins <brendanhiggins@google.com>, Daniel Latypov <dlatypov@google.com>, 
	kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: davidgow@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=MpZihCZI;       spf=pass
 (google.com: domain of 35j9zywgkcesqnivqtbjtbbtyr.pbzxnfna-qritbbtyrtebhcf.pbz@flex--davidgow.bounces.google.com
 designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=35j9ZYwgKCesQNiVQTbjTbbTYR.PbZXNfNa-QRiTbbTYRTebhcf.PbZ@flex--davidgow.bounces.google.com;
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

Running the test currently fails on non-SMP systems, despite being
enabled by default. This means that running the test with:

 ./tools/testing/kunit/kunit.py run --arch x86_64 hw_breakpoint

results in every hw_breakpoint test failing with:

 # test_one_cpu: failed to initialize: -22
 not ok 1 - test_one_cpu

Instead, use kunit_skip(), which will mark the test as skipped, and give
a more comprehensible message:

 ok 1 - test_one_cpu # SKIP not enough cpus

This makes it more obvious that the test is not suited to the test
environment, and so wasn't run, rather than having run and failed.

Signed-off-by: David Gow <davidgow@google.com>
---
 kernel/events/hw_breakpoint_test.c | 4 ++--
 1 file changed, 2 insertions(+), 2 deletions(-)

diff --git a/kernel/events/hw_breakpoint_test.c b/kernel/events/hw_breakpoint_test.c
index 5ced822df788..c57610f52bb4 100644
--- a/kernel/events/hw_breakpoint_test.c
+++ b/kernel/events/hw_breakpoint_test.c
@@ -295,11 +295,11 @@ static int test_init(struct kunit *test)
 {
 	/* Most test cases want 2 distinct CPUs. */
 	if (num_online_cpus() < 2)
-		return -EINVAL;
+		kunit_skip(test, "not enough cpus");
 
 	/* Want the system to not use breakpoints elsewhere. */
 	if (hw_breakpoint_is_used())
-		return -EBUSY;
+		kunit_skip(test, "hw breakpoint already in use");
 
 	return 0;
 }
-- 
2.38.0.135.g90850a2211-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20221026141040.1609203-1-davidgow%40google.com.
