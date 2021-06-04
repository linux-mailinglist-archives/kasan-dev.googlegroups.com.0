Return-Path: <kasan-dev+bncBC6OLHHDVUOBB2XS42CQMGQE5C7BDWY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73a.google.com (mail-qk1-x73a.google.com [IPv6:2607:f8b0:4864:20::73a])
	by mail.lfdr.de (Postfix) with ESMTPS id BA9CA39B1FF
	for <lists+kasan-dev@lfdr.de>; Fri,  4 Jun 2021 07:26:03 +0200 (CEST)
Received: by mail-qk1-x73a.google.com with SMTP id b19-20020a05620a0893b02902e956b29f5dsf5837321qka.16
        for <lists+kasan-dev@lfdr.de>; Thu, 03 Jun 2021 22:26:03 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1622784362; cv=pass;
        d=google.com; s=arc-20160816;
        b=EFN17iRkFBDawW0jpOLpTwR2y/DRRZAga/kc0LTGKYQO59bF2FpqYqtNanCez0ghha
         LuYWL/ifVM1fYHPndIvLVxFmpzelgWWDGK1/BOaPpCik+s76owpuv9nBBTQ1GXaxa3XT
         x1PfMW4H8vJb5zCJdlTgV5PAN7sIUew0IaMzIeSJFYSAzKfF6cBuUm7V3gazykRja4S7
         g0C3I7ZKVgCi2KYVJp8CuzUabbWxF+dfFvV8+w+r7kS4ryH6Zc4gxJWHmVEPzeViytSJ
         krg1z53sXEn2o2qtUC2XfDfag/v3YluVb5+sPGod/3r902q17U7oiXC38Xaxef0xkY5j
         xz+Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=OC8lrY2idDrNKimZEHZz+o8Xvcd+li8Zff56+4eTwDY=;
        b=HHP8EYpmgRTypR3v8S0GmQJzQ8Wt8Nojy5cHOO7AelsAd3sBQLAPGdHfEdnSoc7feH
         WEDJe0Er+1nIHLUBvol9m1f1MIKYttXmy2jgY12H64HafX6H2+5RDkd+6yG3Jwzba9+w
         Gjc5TTeWEQRTjvDYe1sa2lvaBaN1eFrZ5Fp5nspVH15i3RwFDqS5TWgkoZqmvFj0iuD0
         YiZ5GuZgBYE2f+xYleOYsdAttVZSfyqx7r4wTEHRA0gG+WiarZWLpo94ELrt2IRwcMGi
         BZEW9HN6TvXXE5pt3nldYfwBxhTscKCd9DLrsxEuZLxcuKrLMd2Rm3y7iBERZbwDElx7
         k7Bw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=ZqKBGRs5;
       spf=pass (google.com: domain of 3abm5yagkcc4xuf2x08g08805y.w864ucu7-xyf08805y0b8e9c.w86@flex--davidgow.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3abm5YAgKCc4xuF2x08G08805y.w864uCu7-xyF08805y0B8E9C.w86@flex--davidgow.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:message-id:mime-version:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=OC8lrY2idDrNKimZEHZz+o8Xvcd+li8Zff56+4eTwDY=;
        b=q1lhAHn0cZ3LqAIn9fAVkf20hGvfbUybZaUt17tBvE6SBEzHnQs7Qn4UGKQlxCGrrG
         wRLctaxR3QWS2wk5x0+xX8BIqvsVB3WtKhAKrETNsZaSS/YTwvANDSrSnDhUz50MkpQW
         lgspie4ophRoGvd8ojVG79eOsYc0d6hudZk+wa9Yyr1ft5Quvs3kZpi+n9om160voC9b
         A6/NwzU8WyzjpxhAdLX2uObePp6JMVOzLltYGWrh4ne7ujWCzX+ksmEAFEm+Avqk64Ze
         1+M9WlW0b+fdYypUGSZCVoSU7UyvE6c330GyprFO0kaErBCehMyPrA44AfXfCT4Im/NB
         nSag==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=OC8lrY2idDrNKimZEHZz+o8Xvcd+li8Zff56+4eTwDY=;
        b=GVR9EwYCrUHRN0kFahQyMkhIv2I8J1vQ16FEQTqsSVexyIT1WIqEUsHPZC5ztg0l4k
         X0bSJoh7ZyQJUQx9CcuNZNRA0Qo9JsFCPa4dnYYpbAL+k65Os3j5JUbA85TNw92TfJFG
         IdXJEyqmHF3Co7+YNcu6kM34wcVyD0kUIBJeDI2lJhy+0t8RxHFOtNqaKfBg7fqej15u
         G19NPA0K28rRHl6zqtyuChTkTvnWOhCPaFX04gyb+bHLXOQskUIpMxzwi5TalPoOhcll
         +maZpwhZpBBeV/hVfeVE1zJpbHR68tE9Jn03nL8mUdFVgvt7if1k165IchUXFZJL8Y2C
         mBNQ==
X-Gm-Message-State: AOAM532WU/WYBtYI0yIXnXpcuKjWHkgupXY/YSoX/f2Cid6qOZBgBYT6
	jSTG4xZ45hU377lwx1dNN4Q=
X-Google-Smtp-Source: ABdhPJxvVZo4y8dYUz/trDZ2s/zdkWkW8HqH3S3KyztBJZT2JytgdQHj0vhKu+yjKxRuOS6qE+xlfg==
X-Received: by 2002:a0c:8e49:: with SMTP id w9mr3141170qvb.35.1622784362485;
        Thu, 03 Jun 2021 22:26:02 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:622a:1313:: with SMTP id v19ls2501347qtk.11.gmail; Thu,
 03 Jun 2021 22:26:02 -0700 (PDT)
X-Received: by 2002:ac8:108e:: with SMTP id a14mr3067240qtj.28.1622784361982;
        Thu, 03 Jun 2021 22:26:01 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1622784361; cv=none;
        d=google.com; s=arc-20160816;
        b=wwunb7heFEdvFJzSzIB2ZpBvikBkppQSUaXUHCg9fo/fk8jacCzasQ2WEM3Ioz3UKf
         E1Dwn6BLO+kk/K7UnJaOWbNnYvaZ0NwgHjW/3FTpMKOKL/Blr5CI+xEFbZkd1hGWaZde
         UPpMk0KlGXNRfMn82AR038IVtbQ89tE43J5PHlv/9QzoAaIZKrn5etJ3k7DHQVo9JLES
         CqPeuQDr2u37VPPF2PUupb3hQu/oMg2EXnojiMTdirsYsLW7i094s4JCUdC/j4dXkQfo
         13+yoeuGTpiPK3CXwumfHZbyDFZrsi5jhf9bUF0CT2SlL3T8ur8R9IXAuEwf2QkcL6fV
         jy2w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=BmX2qAurH2kKXteL0ga3zN+hRpRwUJBvctVU87eAUVg=;
        b=GeqfNsEfzCQFMugXEQZcPEq22g0gIXyLB9LkxaNUJT+jxNpdueW1c6xECa6vTcVeFI
         7/AeUhH0K1dWHkqYd1HbHtB0PvxuuLmKWIVyPdfOpbn/C7tuuR3krKYUr11BhBKEr7ht
         zoKpUnBp0QBz3wjly/YeTPXMbdqdcfyc2jhCptNAfCPOoJ9doy+Goc3MqWXnDld6jG3y
         IBnAJ4XP0s49BmwsiUaaKPREmogXRueMHVtNQ7yVqwwyQ/5b0zkF8nTlQqsywdJxh1rF
         5hXxcCno2/pK7IRXWNBrlxdbvJfSyVEWiQF5RH727HfvmoiKYa7N7Wju3YpZVA4fl85s
         oHMA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=ZqKBGRs5;
       spf=pass (google.com: domain of 3abm5yagkcc4xuf2x08g08805y.w864ucu7-xyf08805y0b8e9c.w86@flex--davidgow.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3abm5YAgKCc4xuF2x08G08805y.w864uCu7-xyF08805y0B8E9C.w86@flex--davidgow.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb49.google.com (mail-yb1-xb49.google.com. [2607:f8b0:4864:20::b49])
        by gmr-mx.google.com with ESMTPS id y5si630793qtn.4.2021.06.03.22.26.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 03 Jun 2021 22:26:01 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3abm5yagkcc4xuf2x08g08805y.w864ucu7-xyf08805y0b8e9c.w86@flex--davidgow.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) client-ip=2607:f8b0:4864:20::b49;
Received: by mail-yb1-xb49.google.com with SMTP id w130-20020a25df880000b02905327e5d7f43so10224174ybg.3
        for <kasan-dev@googlegroups.com>; Thu, 03 Jun 2021 22:26:01 -0700 (PDT)
X-Received: from spirogrip.svl.corp.google.com ([2620:15c:2cb:201:66ad:9d8a:27f0:46ba])
 (user=davidgow job=sendgmr) by 2002:a25:ac9d:: with SMTP id
 x29mr2692093ybi.369.1622784361599; Thu, 03 Jun 2021 22:26:01 -0700 (PDT)
Date: Thu,  3 Jun 2021 22:25:48 -0700
Message-Id: <20210604052548.1889909-1-davidgow@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.32.0.rc1.229.g3e70b5a671-goog
Subject: [PATCH] kasan: test: Improve failure message in KUNIT_EXPECT_KASAN_FAIL()
From: "'David Gow' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Daniel Axtens <dja@axtens.net>, Brendan Higgins <brendanhiggins@google.com>
Cc: David Gow <davidgow@google.com>, kasan-dev@googlegroups.com, 
	kunit-dev@googlegroups.com, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: davidgow@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=ZqKBGRs5;       spf=pass
 (google.com: domain of 3abm5yagkcc4xuf2x08g08805y.w864ucu7-xyf08805y0b8e9c.w86@flex--davidgow.bounces.google.com
 designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3abm5YAgKCc4xuF2x08G08805y.w864uCu7-xyF08805y0B8E9C.w86@flex--davidgow.bounces.google.com;
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

The KUNIT_EXPECT_KASAN_FAIL() macro currently uses KUNIT_EXPECT_EQ() to
compare fail_data.report_expected and fail_data.report_found. This
always gave a somewhat useless error message on failure, but the
addition of extra compile-time checking with READ_ONCE() has caused it
to get much longer, and be truncated before anything useful is displayed.

Instead, just check fail_data.report_found by hand (we've just test
report_expected to 'true'), and print a better failure message with
KUNIT_FAIL()

Beforehand, a failure in:
KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)area)[3100]);
would looked like:
[22:00:34] [FAILED] vmalloc_oob
[22:00:34]     # vmalloc_oob: EXPECTATION FAILED at lib/test_kasan.c:991
[22:00:34]     Expected ({ do { extern void __compiletime_assert_705(void) __attribute__((__error__("Unsupported access size for {READ,WRITE}_ONCE()."))); if (!((sizeof(fail_data.report_expected) == sizeof(char) || sizeof(fail_data.repp
[22:00:34]     not ok 45 - vmalloc_oob

With this change, it instead looks like:
[22:04:04] [FAILED] vmalloc_oob
[22:04:04]     # vmalloc_oob: EXPECTATION FAILED at lib/test_kasan.c:993
[22:04:04]     KASAN failure expected in "((volatile char *)area)[3100]", but none occurred
[22:04:04]     not ok 45 - vmalloc_oob

Signed-off-by: David Gow <davidgow@google.com>
---

Stumbled across this because the vmalloc_oob test is failing (i.e.,
KASAN isn't picking up an error) under qemu on my system, and the
message above was horrifying. (I'll file a Bugzilla bug for the test
failure today.)

Cheers,
-- David

 lib/test_kasan.c | 8 +++++---
 1 file changed, 5 insertions(+), 3 deletions(-)

diff --git a/lib/test_kasan.c b/lib/test_kasan.c
index cacbbbdef768..deda13c9d9ff 100644
--- a/lib/test_kasan.c
+++ b/lib/test_kasan.c
@@ -98,9 +98,11 @@ static void kasan_test_exit(struct kunit *test)
 	barrier();							\
 	expression;							\
 	barrier();							\
-	KUNIT_EXPECT_EQ(test,						\
-			READ_ONCE(fail_data.report_expected),		\
-			READ_ONCE(fail_data.report_found));		\
+	if (READ_ONCE(fail_data.report_found) == false) {		\
+		KUNIT_FAIL(test, KUNIT_SUBTEST_INDENT "KASAN failure "	\
+				"expected in \"" #expression		\
+				 "\", but none occurred");		\
+	}								\
 	if (IS_ENABLED(CONFIG_KASAN_HW_TAGS)) {				\
 		if (READ_ONCE(fail_data.report_found))			\
 			kasan_enable_tagging_sync();			\
-- 
2.32.0.rc1.229.g3e70b5a671-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210604052548.1889909-1-davidgow%40google.com.
