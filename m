Return-Path: <kasan-dev+bncBAABBS63QCCAMGQEYWDDEWA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73a.google.com (mail-qk1-x73a.google.com [IPv6:2607:f8b0:4864:20::73a])
	by mail.lfdr.de (Postfix) with ESMTPS id 69546366D33
	for <lists+kasan-dev@lfdr.de>; Wed, 21 Apr 2021 15:51:08 +0200 (CEST)
Received: by mail-qk1-x73a.google.com with SMTP id g76-20020a379d4f0000b02902e40532d832sf3293018qke.20
        for <lists+kasan-dev@lfdr.de>; Wed, 21 Apr 2021 06:51:08 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1619013067; cv=pass;
        d=google.com; s=arc-20160816;
        b=DkMidFJL4MtPcvqDMq51mhEpEbJmyK5YYW4/07XvlNadPPsUddMsu2FJkbd+FtmWkM
         2OL3x7sv8SE6hJEN8o9JIxnuj/ZfDyx7d5x/PIsxltIgfUy+x6PzLBJxxiNjlyvYoYNa
         ngJPRtVZlmRcYy8T2787Pb5AeW4kPAfVruqDoeq6FQZXhRLkvdfLdN9FdnbMvqyZw+Ga
         MGrLE3UN6JHmmCTqW/Cu7hI2gkrIFDYyQnMxjSkmrT/P+lzU0MV4AyGKUyEcm5E2tYtz
         AtSqNSLhaJ/3BaiXznudc2ndyddpz+g1sXxlvaTEPOlsDoOHFNA7oScRBs3+JLS1IC04
         HNkw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=Ubmu65lBTlaFuaC8lujPOjmIQFTQ+P/QoSpwVkBSpiI=;
        b=eokhKfM5CmBbxEmkQSGa+QvDo834FtSSuBQHYf0Aw85udOJB8IMOMTYrEfugXR2HHV
         Me6nriiaub45euIQw+kmgnLc4/8god+5WJvVSLSxazY4OW7NLgzLYeFT4J0gOqGeXaPZ
         EfAOeC8gT8e/9kD8EVMe5PwHl201vwgB4PjBRUkdJCjq0bWgDv5NASBpqALGhe1JGw49
         lQeeVZUOEYp8CdzJfamP+ktzTErdhHtL2+hoMX0+6BAv/gBgoySLFeASsBMcdJCMOLFD
         Z19A5AaU4rGhNkkLhpVia69Ht6R1khwl5DiI2v9rQ7PCgioIXVALhwwE6c7sbiYRAMJ7
         WGjw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=OouB3r7b;
       spf=pass (google.com: domain of arnd@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=arnd@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Ubmu65lBTlaFuaC8lujPOjmIQFTQ+P/QoSpwVkBSpiI=;
        b=rCBu3pHbpY3ALcdkf+zpRIL4o84wWnvErjzr5ZqH5vND/jVbp7tp/5G8xpvEUUlMA8
         miZp9p7X2lK8syS77eqngBYJyExBx0mSIy2qFOnDeGkN+yu8jRjvTEg5CWVq54MuwTIZ
         I0SZ6Tb4RpBp/Rm79Q4ve4/2iJBLjweB2Q/4rewaixEA9CSrTfTuW2XujE8w+TyHWrMS
         rY+p7VuBjRngWQq/360QyKIRF3/nDwHYc8ctRN2GjR0sof/Q7P/GrbQ0n9StEOX0/cfz
         Q2xFGyb25Z0UxTIl7Nm0H9nhb1dc8Vyev3IM7DOjdr5qU7INM5q8mlbvCBGU30zgCAWE
         PB1A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=Ubmu65lBTlaFuaC8lujPOjmIQFTQ+P/QoSpwVkBSpiI=;
        b=O9lKH8imYEm7udtZkgWB9XHwG56ihmd8LZQvwhWLsvuaNJtoPhWEqfXBIyk0MmExUu
         2lWZAJ1U7M/HJbFiX+MgzkHKlzJQl9au3C+6BN3CYKgTaT0ME4cOaaJOB/ZZEbChlmvV
         YFlSHGZ21WlvEtiqQEXboDGCnWt3+SAozQQg3n+wpJzkzOfx3yt66CS0BcLsJvJYWD7y
         FTbfgNJcsSOeHMFwOfpkwD+De+5w5pud/m0KE4uHqp8bY+DD7ABk1ETHNSCROlaJG8zq
         20v10nEwe8Ep6SztH3zlCPPVvnrUAqLQjJwkTWOKXjxQJN/OgURW1RoiHrrjiWwetRJU
         RUFg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531CvPlS2rZp+c9HofAqiwC9hOvaqCMIXHrmRfk3SA/jyEKkki8j
	ySKc6/zGxr1pHY0VAkT682c=
X-Google-Smtp-Source: ABdhPJwnNa48WR4YuWJrk6JIuCYDOabxUqLr49kvW5YA1hb5wPEc6WDjh5nQC6+VwpSUu7sHhOZXAw==
X-Received: by 2002:a05:620a:1350:: with SMTP id c16mr22937305qkl.105.1619013067458;
        Wed, 21 Apr 2021 06:51:07 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ae9:f20e:: with SMTP id m14ls1275370qkg.8.gmail; Wed, 21 Apr
 2021 06:51:07 -0700 (PDT)
X-Received: by 2002:a37:e94:: with SMTP id 142mr11289341qko.49.1619013066950;
        Wed, 21 Apr 2021 06:51:06 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1619013066; cv=none;
        d=google.com; s=arc-20160816;
        b=ZfC7H/yGuxORXl9mpG3/YD7mKhhGCtuISDWiFcK2B/rXA4Pzc6E2Lj/MzpN7zuMRlW
         EIlyH/fE76B6R6h8fq0EKrk5J/g93HrLvc6GuH2k1dqG7Is5IzF2Bork8xldxgNGRXWg
         fN3ANo0ldxrnJzmWujRGvH6olSxhExel+1mnHRQxyo0x0wHpT2EexbFvTmh3IhOL8gId
         0K6Ylc0KsUA+FmDqtQdIrmhlV4mChDYG+L6hIbiCwQK9gq06ipBrqKDdmxGPuP7st6yz
         HPZGc2wLyIqUWLhYR6dI+49pVMsWmzUlTIcStblNryljYQMRfUWikqG29oSSOH5YDAoh
         RJ7A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=osB5LpgKGLS+kSq3i1bASA/MA9ohNI/eftepaa5DlG8=;
        b=W6aOvFn1+sylfLIPqHD/J2r7YGcqdI1M38eiByBk9SZm3rardKQOoQgm3gji9z6PrD
         zA6ZFX76eK48DHtYLGmEIeJlf8dxGVd+C1uOT4lekiQKc6jQfOZxghE3hwjOiuLQqfsU
         XTLsmbPbKYYqGBM/SOK6csNgs/AfrnDmS6L1PP+mbneiujZhJRQsO58SaSuRpN0uj05j
         7EG7RysDfKSFdHVRdJP4htNrvmIRLeS3Qp0K2i7zqvwGG1UunvigJ7YjrGFlV1VKB9Z1
         xgoVAGX9DUq4jVhYHHWi8zqIlLM6iAjWkQv6rdvoEIt7mbtiFKxVbXtHrShDkMyKSVQT
         7gww==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=OouB3r7b;
       spf=pass (google.com: domain of arnd@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=arnd@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id n63si270021qkn.7.2021.04.21.06.51.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 21 Apr 2021 06:51:06 -0700 (PDT)
Received-SPF: pass (google.com: domain of arnd@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id 288C46144D;
	Wed, 21 Apr 2021 13:51:03 +0000 (UTC)
From: Arnd Bergmann <arnd@kernel.org>
To: Marco Elver <elver@google.com>,
	"Paul E. McKenney" <paulmck@kernel.org>,
	David Gow <davidgow@google.com>
Cc: Arnd Bergmann <arnd@arndb.de>,
	Dmitry Vyukov <dvyukov@google.com>,
	"Peter Zijlstra (Intel)" <peterz@infradead.org>,
	kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org
Subject: [PATCH] kcsan: fix printk format string
Date: Wed, 21 Apr 2021 15:50:38 +0200
Message-Id: <20210421135059.3371701-1-arnd@kernel.org>
X-Mailer: git-send-email 2.29.2
MIME-Version: 1.0
X-Original-Sender: arnd@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=OouB3r7b;       spf=pass
 (google.com: domain of arnd@kernel.org designates 198.145.29.99 as permitted
 sender) smtp.mailfrom=arnd@kernel.org;       dmarc=pass (p=NONE sp=NONE
 dis=NONE) header.from=kernel.org
Content-Type: text/plain; charset="UTF-8"
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

From: Arnd Bergmann <arnd@arndb.de>

Printing a 'long' variable using the '%d' format string is wrong
and causes a warning from gcc:

kernel/kcsan/kcsan_test.c: In function 'nthreads_gen_params':
include/linux/kern_levels.h:5:25: error: format '%d' expects argument of type 'int', but argument 3 has type 'long int' [-Werror=format=]

Use the appropriate format modifier.

Fixes: f6a149140321 ("kcsan: Switch to KUNIT_CASE_PARAM for parameterized tests")
Signed-off-by: Arnd Bergmann <arnd@arndb.de>
---
 kernel/kcsan/kcsan_test.c | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/kernel/kcsan/kcsan_test.c b/kernel/kcsan/kcsan_test.c
index 9247009295b5..a29e9b1a30c8 100644
--- a/kernel/kcsan/kcsan_test.c
+++ b/kernel/kcsan/kcsan_test.c
@@ -981,7 +981,7 @@ static const void *nthreads_gen_params(const void *prev, char *desc)
 		const long min_required_cpus = 2 + min_unused_cpus;
 
 		if (num_online_cpus() < min_required_cpus) {
-			pr_err_once("Too few online CPUs (%u < %d) for test\n",
+			pr_err_once("Too few online CPUs (%u < %ld) for test\n",
 				    num_online_cpus(), min_required_cpus);
 			nthreads = 0;
 		} else if (nthreads >= num_online_cpus() - min_unused_cpus) {
-- 
2.29.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210421135059.3371701-1-arnd%40kernel.org.
