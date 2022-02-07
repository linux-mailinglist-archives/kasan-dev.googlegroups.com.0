Return-Path: <kasan-dev+bncBDHK3V5WYIERBE4WQ2IAMGQEXZMNROQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43d.google.com (mail-wr1-x43d.google.com [IPv6:2a00:1450:4864:20::43d])
	by mail.lfdr.de (Postfix) with ESMTPS id 2943A4ACAF2
	for <lists+kasan-dev@lfdr.de>; Mon,  7 Feb 2022 22:11:48 +0100 (CET)
Received: by mail-wr1-x43d.google.com with SMTP id t14-20020adfa2ce000000b001e1ad2deb3dsf5016278wra.0
        for <lists+kasan-dev@lfdr.de>; Mon, 07 Feb 2022 13:11:48 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1644268308; cv=pass;
        d=google.com; s=arc-20160816;
        b=NdhmhAZKfWvHHd6RemiK43vIcSZV86JxJUngQCAWyrr5ELTozfuMvTjLYDKMngL6WF
         +BYBFFgbgp8OjaeLM01ogVGof6lZpDOSQL/qvyMImExOUTe5TN7j7MO7RMkrzi43rGD/
         CVPj7WRWfxH0XZkNDb23YU3fRZe8PDIpp7Yn8gqkl3olN3uPKsueYW+tGrmHiuYuzFUq
         XNepEZCVa7EpZet2hCOgWavDlw9NbD9S6NP2Dvw6CbWCRx4HNpxkSaGN70/NoImqSytP
         jjKXWsdesJ5XY18Tjaedu2BxxxWO466TsAcDXHrwjyB6f+x6LSY8c0QY+Xp7VgEmpZjC
         OIxw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=Ok2x0mhz2Ouj8ZZ4YIl8Xlo1QZoJK5PteZ4s7CcZ0bo=;
        b=Be77LgrI106mappb/sbkl0w/zY2+7FfVg0OdrOz3I6E3lEyFAjoRIFMJmPCuPYuBIK
         +rqbfJJYVRCiPw7vlVei2xccMLVAABPudkSA9cCKBQ7t7PPsv+HU63Q+PNkxqPq3sKbI
         TMpghwH8G6YqK9xH44ya3UCPCqsLu42Wv8y5jJPyn7m4/rQql0DnlRCvyh4W5u1KGd0O
         dJO/yigA60UuO1s9/T/uTgvfC8I8jJ5KnDwJVIZXktemLjrIOVSwiISq1hpXeOLvbgWF
         m+PY6kAOvTHwaafi6Fd8bfNBwhV+6SCCBYUDVYE1sxfogGTCeWpAzuvooVz8HUf9B473
         t2eQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=itHXjjA4;
       spf=pass (google.com: domain of ribalda@chromium.org designates 2a00:1450:4864:20::529 as permitted sender) smtp.mailfrom=ribalda@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Ok2x0mhz2Ouj8ZZ4YIl8Xlo1QZoJK5PteZ4s7CcZ0bo=;
        b=NyIpJnuS+GLDa9Ar8dlzo35k6EnMrBa57qX0DE/qq8tdAZoVKy5Byr5/m0LR/qKoct
         VpWbcsqEMWQalTqkBIcxF8v9GblwqhZwcSuZ7gWzKF/QzqvH/drAye/2HILw9LASmLTn
         957Za7j24yNRz1Wo51HAT5WKxNhblw6sqZPLyY9KT+ScLu4fz6Z7IfgDXm2YvbXJgACW
         DCzT3++ExSMpEZo+OJMEjQBpBwoLif3N4kzwY1yXKyMGgbhP4TjggttUv8KU2ck18GMB
         ljKg0U/6MjI/SgtbLHxUspgVfbh3WUMIKzN/K7AdHvJTq/7NeNXXickfzWH5FibbLRQn
         FwWQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=Ok2x0mhz2Ouj8ZZ4YIl8Xlo1QZoJK5PteZ4s7CcZ0bo=;
        b=TBK0tEbMzVGzao9wEjGvSxXxzcMvb+tGezL1Qq16qyksKb9IUoT6CwioWBqeSWzoUQ
         t/dvuwbowxzyvUuKuJSfMPEH6LaxaqPkmYRgUvqzbMZcOYs7iE0U5Q0UJM+f4zq151eU
         LIJN97Dh3H3mNkBjvU9H+AGDUtjjf3EI62HoF21vZDvBaZ9Mz9r+ZHmx6ul6Tj5j4Glr
         p2L4SRCPeMwc1Ql2jUj2HMdvGQH/jIOiZeZtLKjXavTaq00bd3npD0Xzeifv+LJfauHV
         OADXGafon3qxwLJ5/YoeRWERA4/C0HvDKw/3NEAeLcM3KgQ5U40mNSveSOaiyaMkh7sy
         AuPg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533CXx9M5AyG2tFz5Xl9zjO6W7Gpsbfo/JnaY4h6o74imwn/TNuF
	xKZaYbeLm2vB16kmKKtn5Jo=
X-Google-Smtp-Source: ABdhPJyXlo9nytGOneNa5jUtqXePkH636wMgIZnVxHp1CI+MDMcdStjIPfDvth+Hel1Gpt40ZI9M0Q==
X-Received: by 2002:a05:600c:3641:: with SMTP id y1mr584846wmq.53.1644268307937;
        Mon, 07 Feb 2022 13:11:47 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:3487:: with SMTP id a7ls200849wmq.2.canary-gmail;
 Mon, 07 Feb 2022 13:11:47 -0800 (PST)
X-Received: by 2002:a05:600c:290a:: with SMTP id i10mr584889wmd.43.1644268307221;
        Mon, 07 Feb 2022 13:11:47 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1644268307; cv=none;
        d=google.com; s=arc-20160816;
        b=i1FezwkYgpMM3re6hBQUWJQ7ngSr7EhT0VqcYi7sFDYsG8KHQatxg0wiK9l0ceBGB8
         e+TCTvDNgZMKSEY5bg2R69MStSNnYx0kAhNzs1jtjGqk3dVbjveZkiDoT4dEW+DDK8Ba
         Fn55waAQL51tzoxbbti3i8QQy1kIAnKiLk8u7R7hoL88SGA9ZeS9e0cve16xm5sQ2W8g
         S9UoPYmFZLLkzuStIHBqn9LqfqNfx/ZM472LAiMr1HhT0g5uycwAykrOu1Zb0AGlSE0x
         vCdlIJcuSGLKf8yrlfX0crm0Ws0ZjcOzXUSveg3XkDXl8Ij3EMEVA9hJt1vngxnvJRpM
         fCdg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=mO0nS1vlfvTw04UTXUIpbtNuC8tb/IOjCirvjFq+c0Q=;
        b=lvDBfKD02k4kMdMaO3BLCR2E3E8vzxYSOSjKD0bFsnuFPJlhfiWaDPWQbMx+HBPvTs
         0c9JK85qWNUeZGMoUxM/gi8nN8cnahFvugBw3iUjv07dQpOYN9XqY6Wm3Qm+cW72vcju
         ihzhRqC8kbaRjqQ1dgHcExmIibErGs57+u+bayf8SddRTfafQ3I2W06KXYtnDCjPwK9Z
         yLcxbN6kQqjoNPQqSa425wF7K0deRx6aNMNG9TuyiV4+ayKEfETitvQN2cGlgOZxtqjY
         rmWZLt81w2xfPQWLBrznRr5F6VCH7bxo41/87bhcMv4wZTi2g9Fwsby52npyDPFmpqVi
         pt7A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=itHXjjA4;
       spf=pass (google.com: domain of ribalda@chromium.org designates 2a00:1450:4864:20::529 as permitted sender) smtp.mailfrom=ribalda@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Received: from mail-ed1-x529.google.com (mail-ed1-x529.google.com. [2a00:1450:4864:20::529])
        by gmr-mx.google.com with ESMTPS id ay37si22372wmb.2.2022.02.07.13.11.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 07 Feb 2022 13:11:47 -0800 (PST)
Received-SPF: pass (google.com: domain of ribalda@chromium.org designates 2a00:1450:4864:20::529 as permitted sender) client-ip=2a00:1450:4864:20::529;
Received: by mail-ed1-x529.google.com with SMTP id bx2so16624127edb.11
        for <kasan-dev@googlegroups.com>; Mon, 07 Feb 2022 13:11:47 -0800 (PST)
X-Received: by 2002:a05:6402:40c1:: with SMTP id z1mr1325109edb.23.1644268306955;
        Mon, 07 Feb 2022 13:11:46 -0800 (PST)
Received: from alco.lan (80.71.134.83.ipv4.parknet.dk. [80.71.134.83])
        by smtp.gmail.com with ESMTPSA id z4sm4047239ejd.39.2022.02.07.13.11.46
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 07 Feb 2022 13:11:46 -0800 (PST)
From: Ricardo Ribalda <ribalda@chromium.org>
To: kunit-dev@googlegroups.com,
	kasan-dev@googlegroups.com,
	linux-kselftest@vger.kernel.org,
	Brendan Higgins <brendanhiggins@google.com>,
	Mika Westerberg <mika.westerberg@linux.intel.com>,
	Daniel Latypov <dlatypov@google.com>
Cc: Ricardo Ribalda <ribalda@chromium.org>
Subject: [PATCH v3 1/6] kunit: Introduce _NULL and _NOT_NULL macros
Date: Mon,  7 Feb 2022 22:11:39 +0100
Message-Id: <20220207211144.1948690-1-ribalda@chromium.org>
X-Mailer: git-send-email 2.35.0.263.gb82422642f-goog
MIME-Version: 1.0
X-Original-Sender: ribalda@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=itHXjjA4;       spf=pass
 (google.com: domain of ribalda@chromium.org designates 2a00:1450:4864:20::529
 as permitted sender) smtp.mailfrom=ribalda@chromium.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=chromium.org
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

Today, when we want to check if a pointer is NULL and not ERR we have
two options:

KUNIT_EXPECT_TRUE(test, ptr == NULL);

or

KUNIT_EXPECT_PTR_NE(test, ptr, (struct mystruct *)NULL);

Create a new set of macros that take care of NULL checks.

Reviewed-by: Daniel Latypov <dlatypov@google.com>
Signed-off-by: Ricardo Ribalda <ribalda@chromium.org>
---
 include/kunit/test.h | 88 ++++++++++++++++++++++++++++++++++++++++++++
 1 file changed, 88 insertions(+)

diff --git a/include/kunit/test.h b/include/kunit/test.h
index 00b9ff7783ab..340169723669 100644
--- a/include/kunit/test.h
+++ b/include/kunit/test.h
@@ -1218,6 +1218,50 @@ do {									       \
 				   fmt,					       \
 				   ##__VA_ARGS__)
 
+/**
+ * KUNIT_EXPECT_NULL() - Expects that @ptr is null.
+ * @test: The test context object.
+ * @ptr: an arbitrary pointer.
+ *
+ * Sets an expectation that the value that @ptr evaluates to is null. This is
+ * semantically equivalent to KUNIT_EXPECT_PTR_EQ(@test, ptr, NULL).
+ * See KUNIT_EXPECT_TRUE() for more information.
+ */
+#define KUNIT_EXPECT_NULL(test, ptr)				               \
+	KUNIT_EXPECT_PTR_EQ_MSG(test,					       \
+				ptr,					       \
+				NULL,				       \
+				NULL)
+
+#define KUNIT_EXPECT_NULL_MSG(test, ptr, fmt, ...)	                       \
+	KUNIT_BINARY_PTR_ASSERTION(test,				       \
+				   KUNIT_EXPECTATION,			       \
+				   ptr, ==, NULL,			       \
+				   fmt,					       \
+				   ##__VA_ARGS__)
+
+/**
+ * KUNIT_EXPECT_NOT_NULL() - Expects that @ptr is not null.
+ * @test: The test context object.
+ * @ptr: an arbitrary pointer.
+ *
+ * Sets an expectation that the value that @ptr evaluates to is not null. This
+ * is semantically equivalent to KUNIT_EXPECT_PTR_NE(@test, ptr, NULL).
+ * See KUNIT_EXPECT_TRUE() for more information.
+ */
+#define KUNIT_EXPECT_NOT_NULL(test, ptr)			               \
+	KUNIT_EXPECT_PTR_NE_MSG(test,					       \
+				ptr,					       \
+				NULL,					       \
+				NULL)
+
+#define KUNIT_EXPECT_NOT_NULL_MSG(test, ptr, fmt, ...)	                       \
+	KUNIT_BINARY_PTR_ASSERTION(test,				       \
+				   KUNIT_EXPECTATION,			       \
+				   ptr, !=, NULL,			       \
+				   fmt,					       \
+				   ##__VA_ARGS__)
+
 /**
  * KUNIT_EXPECT_NOT_ERR_OR_NULL() - Expects that @ptr is not null and not err.
  * @test: The test context object.
@@ -1485,6 +1529,50 @@ do {									       \
 				   fmt,					       \
 				   ##__VA_ARGS__)
 
+/**
+ * KUNIT_ASSERT_NULL() - Asserts that pointers @ptr is null.
+ * @test: The test context object.
+ * @ptr: an arbitrary pointer.
+ *
+ * Sets an assertion that the values that @ptr evaluates to is null. This is
+ * the same as KUNIT_EXPECT_NULL(), except it causes an assertion
+ * failure (see KUNIT_ASSERT_TRUE()) when the assertion is not met.
+ */
+#define KUNIT_ASSERT_NULL(test, ptr) \
+	KUNIT_ASSERT_PTR_EQ_MSG(test,					       \
+				ptr,					       \
+				NULL,					       \
+				NULL)
+
+#define KUNIT_ASSERT_NULL_MSG(test, ptr, fmt, ...) \
+	KUNIT_BINARY_PTR_ASSERTION(test,				       \
+				   KUNIT_ASSERTION,			       \
+				   ptr, ==, NULL,			       \
+				   fmt,					       \
+				   ##__VA_ARGS__)
+
+/**
+ * KUNIT_ASSERT_NOT_NULL() - Asserts that pointers @ptr is not null.
+ * @test: The test context object.
+ * @ptr: an arbitrary pointer.
+ *
+ * Sets an assertion that the values that @ptr evaluates to is not null. This
+ * is the same as KUNIT_EXPECT_NOT_NULL(), except it causes an assertion
+ * failure (see KUNIT_ASSERT_TRUE()) when the assertion is not met.
+ */
+#define KUNIT_ASSERT_NOT_NULL(test, ptr) \
+	KUNIT_ASSERT_PTR_NE_MSG(test,					       \
+				ptr,					       \
+				NULL,					       \
+				NULL)
+
+#define KUNIT_ASSERT_NOT_NULL_MSG(test, ptr, fmt, ...) \
+	KUNIT_BINARY_PTR_ASSERTION(test,				       \
+				   KUNIT_ASSERTION,			       \
+				   ptr, !=, NULL,			       \
+				   fmt,					       \
+				   ##__VA_ARGS__)
+
 /**
  * KUNIT_ASSERT_NOT_ERR_OR_NULL() - Assertion that @ptr is not null and not err.
  * @test: The test context object.
-- 
2.35.0.263.gb82422642f-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220207211144.1948690-1-ribalda%40chromium.org.
