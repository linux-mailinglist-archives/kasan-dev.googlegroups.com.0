Return-Path: <kasan-dev+bncBDX4HWEMTEBRBX6ESKBQMGQEKW23PUI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3f.google.com (mail-oo1-xc3f.google.com [IPv6:2607:f8b0:4864:20::c3f])
	by mail.lfdr.de (Postfix) with ESMTPS id A550B35046D
	for <lists+kasan-dev@lfdr.de>; Wed, 31 Mar 2021 18:25:04 +0200 (CEST)
Received: by mail-oo1-xc3f.google.com with SMTP id h18sf1337579oot.8
        for <lists+kasan-dev@lfdr.de>; Wed, 31 Mar 2021 09:25:04 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1617207903; cv=pass;
        d=google.com; s=arc-20160816;
        b=RAVTBRLp/IlDgNPlwRzclggC7w3VsliKofwA3kOF2WptOd3K/dZuMtV7gcxhsbcSH9
         0qk0QGIjiVTFCwbc7hTNkVU6ZJf4klY0i/BJPOHUe2jqcgtZI/k8No6qdVfRVfUJAgUR
         gP5rr+3zWrbpFhM5rN3varHym1h6eIgyDGb4tIjbpw9Ei7XtNgJ7p1xlTWSR/PvnI4OP
         KN+KnOePldvL20MqnpsshkRvevFTvj6uquz560cGmFo0qFYdiy4q3/VJScUDVjGvLNLz
         SSE+0CqQwmJRFeNOU88tz9omr90IEs/sEihDa6FKx8R3fEg3xVAANBqJp/3BNv9TLpDj
         Zarg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=DgzLGtgEujgrtxZ9WcnTVslTvwIn0hHmSCx6N8J8cok=;
        b=Apifzd6fu5dEUQNEpQoBRmQc4FFW0AHEM8aorS463HXIl4L7fwhwtT890GvT9hGFGM
         ormF4Nt1dKsCYsJudkixgpcmU5CycdpVnzSDtCcN3iDnftRzxTwrziTS0ryZHdPP+d9I
         fPajJxUfe3sxOckppeB92fAaECgy4zvCBUu+miTLgh9UI3oeNswNVKbHaNN7y3SAF3BR
         N0glzKx+pGW3sxB6dZxe4vfZJthhVnY15jCKdu3t/GtzWtwb9CsAXSMAGcaUj198jkiU
         xpyscP0slXnNKG7HNnkzM46H0DYbBgH3VbGYBvNg4xeRhkYUHvhpsebJvjxnefzZu9tx
         Gtzw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=E0qHaj7G;
       spf=pass (google.com: domain of 3xqjkyaokct8boesfzlowmhpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3XqJkYAoKCT8boesfzlowmhpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:message-id:mime-version:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=DgzLGtgEujgrtxZ9WcnTVslTvwIn0hHmSCx6N8J8cok=;
        b=dz/LHg27RHqCKzEdve+FCT36F35GtKYrd8Q8Q61vAzl0nrHI4fkdKfHjEylCqyO7UG
         CXQh8vvJ44VRNa3IP5BxvN2J0SE9VI82ViI/Ygd2h8mAIUbksdGcxdEkE9ENGYLfwUrb
         bAwLv9KsVcwwirtigjlpw3qX8YcxzJkDPWWMuVi9xLLfAUezQ7BpwgJoH33GLbXfxCvi
         oXd1QeNA6gfqmC6b2oYde+dOF4JR8XZZpxgDV8/cNGoaUaoYWJTp7lCOmFxiUizb69K3
         8hFa5IRKi/4oUbrGsfLvmrkDZjodoWKXijkLLA2yt9shTW00bid2uDZm7+Q/519oXlN/
         dnFQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=DgzLGtgEujgrtxZ9WcnTVslTvwIn0hHmSCx6N8J8cok=;
        b=n2sC1pFia9+zUT8UUl7eWtM1yAbfqSEyRz5aTsPn6Rx9q/hchg/gj1H6jtda4fQPIQ
         eAJK0AZ7D56l2u/ExbwUfLtDSC37HUe/Cef0tH9jQBzvI0WLK7kMv/gcIZ7E0gAmp1HN
         ECV64tdM7LckNo0GVYAylO8mARr7cqBmDEJr8r8fM0tk43xIO7I8e4aZNf8MQfMN+Qfa
         gJPS6X35mnp0EOF3ToqElijG5NbO2i8FiIFwllF+jFfOiMhvEld0NoI0r8HFc4t0qgxV
         CA6LUW9NP+0iimNrjrBmJzK/e4wlg3z3/VXM7S0yyRED6Gvt1+OwrO95G4/8C4k3XVWY
         8RGA==
X-Gm-Message-State: AOAM533owowVZDkenUybfVa92xuJ3rN/vwNQJL/3LHl2uDG1J+UaJnKz
	boCUgtdiRi9+jIryQ/I4Z3M=
X-Google-Smtp-Source: ABdhPJwE9NRn+P5lL5FAJwGAP1VWwjPLo5s9CXaxTvYOaTn4Fg8Krqt5tWDl5vTbHVKnYatzWEaG/g==
X-Received: by 2002:aca:5d82:: with SMTP id r124mr2768209oib.59.1617207903643;
        Wed, 31 Mar 2021 09:25:03 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:5c5:: with SMTP id 188ls613955oif.6.gmail; Wed, 31 Mar
 2021 09:25:03 -0700 (PDT)
X-Received: by 2002:aca:4487:: with SMTP id r129mr2882941oia.106.1617207903271;
        Wed, 31 Mar 2021 09:25:03 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1617207903; cv=none;
        d=google.com; s=arc-20160816;
        b=vuxmKy//W+1+74RCe3YrCaXA11Rv6aa34cOMJMoidXc8dcyEytjC0NvYQ03B1iWhDe
         dNdO5QH4/78WnKLaQ1+LzFJliMM5uwZ4TJYlp+OffPvANPXC0g5oxjmsW4rYbYt1LFaR
         B52KSNehXrj/ujgurrqMmWTG0wgcg1C8W7qogIXgFL2RlIUBFEOtnK2aZ2s3z1rIVIs/
         Z2tz2FI9l7fxDkH1uMbjcbwg1Bk1UPvA8qtiBDwnpusZvbZ5u4VNKtIiBwEnHsVtifXj
         RrEDPH2PYICKpHO8k6vYTR1mE87Ce9wCibZoQlzMOSod1Xv2yYsGGJFD1SIXMuwy/yBY
         7B4A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=fCRp+f9oEZRwz2tLs+x5UFPxXT2k+8MTEajLiG543iE=;
        b=ybJLY1JWxE6NUVyHx6y8aoOzGQoV379EtaKj1189x/iSBT+39pd5swWKdzafmi1vuP
         wA0dzqeU3nF+93FsIKkr7QXwvrcpkFOFmD6r18ZxxZ5fRmvmvp1fWZIR7IhpRpyNA1zo
         UZV/kD7EzVVMxBQlN9ymWFIkMVtr/BdK1jaYG9DCxw0khFrPUvzPJx4HBNW7IaUnmf3Y
         e6gaxlKO9xaVRnVCqydwPiLYwCCyxEzBIB2+hl4jLY5upwO0C08uxtW7CwkKBetnq+3J
         sAtNaMpIxZQQ7NfVfl5TvlnyXqEhBgGS6tpW8DvpucLAKIeEsg4Te2wv24/rn1LUxFqo
         YxKA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=E0qHaj7G;
       spf=pass (google.com: domain of 3xqjkyaokct8boesfzlowmhpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3XqJkYAoKCT8boesfzlowmhpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x84a.google.com (mail-qt1-x84a.google.com. [2607:f8b0:4864:20::84a])
        by gmr-mx.google.com with ESMTPS id v12si188273otj.0.2021.03.31.09.25.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 31 Mar 2021 09:25:03 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3xqjkyaokct8boesfzlowmhpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) client-ip=2607:f8b0:4864:20::84a;
Received: by mail-qt1-x84a.google.com with SMTP id w8so1455769qtk.3
        for <kasan-dev@googlegroups.com>; Wed, 31 Mar 2021 09:25:03 -0700 (PDT)
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:f189:6e8f:457f:e245])
 (user=andreyknvl job=sendgmr) by 2002:a05:6214:16c1:: with SMTP id
 d1mr3810787qvz.29.1617207902660; Wed, 31 Mar 2021 09:25:02 -0700 (PDT)
Date: Wed, 31 Mar 2021 18:24:59 +0200
Message-Id: <48079c52cc329fbc52f4386996598d58022fb872.1617207873.git.andreyknvl@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.31.0.291.g576ba9dcdaf-goog
Subject: [PATCH] kasan: detect false-positives in tests
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, kasan-dev@googlegroups.com, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=E0qHaj7G;       spf=pass
 (google.com: domain of 3xqjkyaokct8boesfzlowmhpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3XqJkYAoKCT8boesfzlowmhpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

Currently, KASAN-KUnit tests can check that a particular annotated part
of code causes a KASAN report. However, they do not check that no unwanted
reports happen between the annotated parts.

This patch implements these checks.

It is done by setting report_data.report_found to false in
kasan_test_init() and at the end of KUNIT_EXPECT_KASAN_FAIL() and then
checking that it remains false at the beginning of
KUNIT_EXPECT_KASAN_FAIL() and in kasan_test_exit().

kunit_add_named_resource() call is moved to kasan_test_init(), and the
value of fail_data.report_expected is kept as false in between
KUNIT_EXPECT_KASAN_FAIL() annotations for consistency.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 lib/test_kasan.c | 49 +++++++++++++++++++++++++++---------------------
 1 file changed, 28 insertions(+), 21 deletions(-)

diff --git a/lib/test_kasan.c b/lib/test_kasan.c
index d77c45edc7cd..bf9225002a7e 100644
--- a/lib/test_kasan.c
+++ b/lib/test_kasan.c
@@ -54,6 +54,10 @@ static int kasan_test_init(struct kunit *test)
 
 	multishot = kasan_save_enable_multi_shot();
 	kasan_set_tagging_report_once(false);
+	fail_data.report_found = false;
+	fail_data.report_expected = false;
+	kunit_add_named_resource(test, NULL, NULL, &resource,
+					"kasan_data", &fail_data);
 	return 0;
 }
 
@@ -61,6 +65,7 @@ static void kasan_test_exit(struct kunit *test)
 {
 	kasan_set_tagging_report_once(true);
 	kasan_restore_multi_shot(multishot);
+	KUNIT_EXPECT_FALSE(test, fail_data.report_found);
 }
 
 /**
@@ -78,28 +83,30 @@ static void kasan_test_exit(struct kunit *test)
  * fields, it can reorder or optimize away the accesses to those fields.
  * Use READ/WRITE_ONCE() for the accesses and compiler barriers around the
  * expression to prevent that.
+ *
+ * In between KUNIT_EXPECT_KASAN_FAIL checks, fail_data.report_found is kept as
+ * false. This allows detecting KASAN reports that happen outside of the checks
+ * by asserting !fail_data.report_found at the start of KUNIT_EXPECT_KASAN_FAIL
+ * and in kasan_test_exit.
  */
-#define KUNIT_EXPECT_KASAN_FAIL(test, expression) do {		\
-	if (IS_ENABLED(CONFIG_KASAN_HW_TAGS))			\
-		migrate_disable();				\
-	WRITE_ONCE(fail_data.report_expected, true);		\
-	WRITE_ONCE(fail_data.report_found, false);		\
-	kunit_add_named_resource(test,				\
-				NULL,				\
-				NULL,				\
-				&resource,			\
-				"kasan_data", &fail_data);	\
-	barrier();						\
-	expression;						\
-	barrier();						\
-	KUNIT_EXPECT_EQ(test,					\
-			READ_ONCE(fail_data.report_expected),	\
-			READ_ONCE(fail_data.report_found));	\
-	if (IS_ENABLED(CONFIG_KASAN_HW_TAGS)) {			\
-		if (READ_ONCE(fail_data.report_found))		\
-			kasan_enable_tagging();			\
-		migrate_enable();				\
-	}							\
+#define KUNIT_EXPECT_KASAN_FAIL(test, expression) do {			\
+	if (IS_ENABLED(CONFIG_KASAN_HW_TAGS))				\
+		migrate_disable();					\
+	KUNIT_EXPECT_FALSE(test, READ_ONCE(fail_data.report_found));	\
+	WRITE_ONCE(fail_data.report_expected, true);			\
+	barrier();							\
+	expression;							\
+	barrier();							\
+	KUNIT_EXPECT_EQ(test,						\
+			READ_ONCE(fail_data.report_expected),		\
+			READ_ONCE(fail_data.report_found));		\
+	if (IS_ENABLED(CONFIG_KASAN_HW_TAGS)) {				\
+		if (READ_ONCE(fail_data.report_found))			\
+			kasan_enable_tagging();				\
+		migrate_enable();					\
+	}								\
+	WRITE_ONCE(fail_data.report_found, false);			\
+	WRITE_ONCE(fail_data.report_expected, false);			\
 } while (0)
 
 #define KASAN_TEST_NEEDS_CONFIG_ON(test, config) do {			\
-- 
2.31.0.291.g576ba9dcdaf-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/48079c52cc329fbc52f4386996598d58022fb872.1617207873.git.andreyknvl%40google.com.
