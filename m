Return-Path: <kasan-dev+bncBDHK3V5WYIERB2GLQWIAMGQE2J4KLTA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23a.google.com (mail-lj1-x23a.google.com [IPv6:2a00:1450:4864:20::23a])
	by mail.lfdr.de (Postfix) with ESMTPS id 4B5CC4AC89A
	for <lists+kasan-dev@lfdr.de>; Mon,  7 Feb 2022 19:33:13 +0100 (CET)
Received: by mail-lj1-x23a.google.com with SMTP id q17-20020a2e7511000000b0023c95987502sf4814522ljc.16
        for <lists+kasan-dev@lfdr.de>; Mon, 07 Feb 2022 10:33:13 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1644258792; cv=pass;
        d=google.com; s=arc-20160816;
        b=0mo09/DHBiIqfIBF5nYyjVW3MvFdkunRi7vpsb0ME5IlJSB0GFMGaelOx74+4PMl6A
         FVQkdpBEF2jS5N1fvul1vole8IbYh0WqFxZkYgrcm+jGWKGOvOEMPNXrKbRmBjLW5rnW
         2uPeL5oiMizsSpCsTaHzEVZAyBVziQcM7RATtBWf9IgjXKDJlXqueY6/ufgsNfxtBPAq
         K03akNNkv9J6rQ+hCFEUevTbhQuyzt9oLrO6vPcqSXD/t5AylfDP8L8utapDV6bC8OW4
         /up3H834m69d9vXkWY4bIqBS8vIr26tU3fPJXUlUp/txAHkiz1BIXmAIunS+pdYmxa9M
         9h3g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=eojq12zAMs6V+5xYVhcQR+rgrJXzwkKTjE/qBB01UCY=;
        b=V6OJ5+C0g+WQeANEL77GTRezNSVsfc3fSOD/BLYHPLqg7ERkRAcgM4Ph4lglbH4fBP
         s2RAecuIwusOPNJfBurIBJ7b1DuZiNPlPp4IrgYcWtDQxlC9pxOukau4ERZ13FRgjEWN
         3ULRsKIW+pbwILlAy4OckxlKV87ioShYDIAPRwsK+qnixkjk4SNg7935s4MQAq8ZuG5p
         ezusIKqFgCpA+8OC8GgJyzvt2knt+xS26OTOAm0wADpQGjJ80rOAADJ8iAIVBqxtOzxY
         Kdw1KluKb8H2a86ojLmY5zIygE88PxGk53vmcO80Yt70u4XoXoiDGCAWk7iOTmKPyb6F
         IcCA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=JyS9GZHn;
       spf=pass (google.com: domain of ribalda@chromium.org designates 2a00:1450:4864:20::634 as permitted sender) smtp.mailfrom=ribalda@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=eojq12zAMs6V+5xYVhcQR+rgrJXzwkKTjE/qBB01UCY=;
        b=cndYAKAoSbWfruJMnwrK/WkyGixkei6HsnzKAj095CcTqrL7MADx9ofKGCUyv8EPkG
         95EPfydm6udIIQDFZUCXnHzfsLH9ZiR+K3KXR7vta03Ayw9tTyzZ+DA9Q0Ri2afb7G0n
         rDmspNhShX/4IruWFa2YbSb3d3meBdzYR+yjn1jGHPEth8CYGys2L/9k/2kGZhPSrwvB
         9rjRIJWoq9xiEJW3h8GAE8X5pIOPCf3kAUvsLHLccZo8SPpzgF3MbP7o7hhg1RgX7027
         QBEWCot7tznjKGtti87r/240xbQbw3QJ6f+cJ8bhWsG+Ova/0/nY/Qg+gcs1bZ5FGDyJ
         R9fA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=eojq12zAMs6V+5xYVhcQR+rgrJXzwkKTjE/qBB01UCY=;
        b=Qkl8c0sxQf31v3yv13IVCEEAyR8V3/Lr0K3d3M7Y/w+5iQHjL0FamAQrS6qlurhlSU
         4Z8zoG4EjE4JsvZnG1mb4F0IgLKwAzXJJrsy0qsKf59gy84LCaro8kCGXz+5DeMVOp+A
         c5lBbLKSJf3/mU1tCJD3jMsHDh2ZMeMtcYR49suCMJktppF2cEhDaiEamgAF5FY34XwG
         /P7wAieFPy0Sanl6XteMQhR3Zt5nBCTWu0GGdIYSpDlRt5aN7IG3KgxynZH6jfrbua/O
         I+UhhsGcXMaS3w0S3qqiYdHnwvFx09Bu4AUIRt9rROTrrohGWHovTz6ib0yTpJLNH6fD
         5KNA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533y/AGA21FRI08r+WET07uFA4OgTOlbjbPnte00sdwQO5SJcc01
	/8T14gQLG1vjGu57rrBGsM0=
X-Google-Smtp-Source: ABdhPJy8gZtCcqTtS9tsZceMn4Yoep6HTBEaR7U3zk1ZVSR/wMmLBxhiUIG2OfuW4dHTl7vUD5jmww==
X-Received: by 2002:a2e:8746:: with SMTP id q6mr483869ljj.308.1644258792616;
        Mon, 07 Feb 2022 10:33:12 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3ba6:: with SMTP id g38ls6217571lfv.3.gmail; Mon,
 07 Feb 2022 10:33:11 -0800 (PST)
X-Received: by 2002:ac2:4183:: with SMTP id z3mr524708lfh.577.1644258791689;
        Mon, 07 Feb 2022 10:33:11 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1644258791; cv=none;
        d=google.com; s=arc-20160816;
        b=pH/WxJ/7ch61fDvZMqzh6KMn/FJNyzTu3QASavcDhW9bsshHB99zHx5+e5bQzy2Nxm
         cwEZkB55mbIOLWV4KkRCL06tJZZ6mGY1wJmGsEvkPYZvQY+Y4eWF9dGwyxJgV8sgZzbk
         4U0o7Ap+uSoV3/0C6uIZqhrCDTwJYmnkZdEJ3idGVnYWB0IXkVji2Aj2DGcaLGwl8JJh
         EozMdxktttfMTvRit5/Wa3zYmw7dCOFUZ3WsziHJzp+74PRbd7p7K2ZO8xA6Pj3vNvjc
         pZneEFIbqIJqNWSOjQ6OxjVyNbC6anG3gc3JaY4Niofh6Iwv1yqvshdkI9L52XgJccvs
         ULFA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=760cUhZxPNwETk5wV5EY2nvw4jOkyadVdKCIRfo19SI=;
        b=ThAY+pJWduqn2yzrIt9QaByKtl9uJvNgDWxGCEB7R5kzNGjwz9XUkAggkHRig/xQXD
         B+n/xuc12ubo8xZqrGB5GGrCTsys3Jc0SbHUNt2ryZ2yxcxW6rahKRLwQl70jtttrkTq
         +ElMf1EMi+lY8AmW0grm7ExX749buXCk5374MiN/9gksKHwEIO+Pac1a2IqptAq8mwNP
         Ax5H9WTkEOLQvlK0DY7nKuy/8bxvBykokDQ1quSMmP+iCHdCFEUJ63P7R1krBlpfT+h4
         jVRO3vxCL7yZ+35YdE4Y9jH2GsNE7gvSkDLrzJcbFgEtamPzz/JlLTfN9BTwvhjncmaH
         opIg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=JyS9GZHn;
       spf=pass (google.com: domain of ribalda@chromium.org designates 2a00:1450:4864:20::634 as permitted sender) smtp.mailfrom=ribalda@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Received: from mail-ej1-x634.google.com (mail-ej1-x634.google.com. [2a00:1450:4864:20::634])
        by gmr-mx.google.com with ESMTPS id a6si547681lji.0.2022.02.07.10.33.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 07 Feb 2022 10:33:11 -0800 (PST)
Received-SPF: pass (google.com: domain of ribalda@chromium.org designates 2a00:1450:4864:20::634 as permitted sender) client-ip=2a00:1450:4864:20::634;
Received: by mail-ej1-x634.google.com with SMTP id ka4so44589758ejc.11
        for <kasan-dev@googlegroups.com>; Mon, 07 Feb 2022 10:33:11 -0800 (PST)
X-Received: by 2002:a17:907:1627:: with SMTP id hb39mr784326ejc.407.1644258791316;
        Mon, 07 Feb 2022 10:33:11 -0800 (PST)
Received: from alco.lan (80.71.134.83.ipv4.parknet.dk. [80.71.134.83])
        by smtp.gmail.com with ESMTPSA id k15sm3045173eji.64.2022.02.07.10.33.10
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 07 Feb 2022 10:33:10 -0800 (PST)
From: Ricardo Ribalda <ribalda@chromium.org>
To: kunit-dev@googlegroups.com,
	kasan-dev@googlegroups.com,
	linux-kselftest@vger.kernel.org,
	Brendan Higgins <brendanhiggins@google.com>,
	Mika Westerberg <mika.westerberg@linux.intel.com>
Cc: Ricardo Ribalda <ribalda@chromium.org>
Subject: [PATCH 1/6] kunit: Introduce _NULL and _NOT_NULL macros
Date: Mon,  7 Feb 2022 19:33:03 +0100
Message-Id: <20220207183308.1829495-1-ribalda@chromium.org>
X-Mailer: git-send-email 2.35.0.263.gb82422642f-goog
MIME-Version: 1.0
X-Original-Sender: ribalda@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=JyS9GZHn;       spf=pass
 (google.com: domain of ribalda@chromium.org designates 2a00:1450:4864:20::634
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

EXPECT_TRUE(test, ptr == NULL);

or

EXPECT_PTR_NE(test, ptr, (struct mystruct *)NULL);

Create a new set of macros that take care of NULL checks.

Signed-off-by: Ricardo Ribalda <ribalda@chromium.org>
---
 include/kunit/test.h | 91 ++++++++++++++++++++++++++++++++++++++++++++
 1 file changed, 91 insertions(+)

diff --git a/include/kunit/test.h b/include/kunit/test.h
index b26400731c02..a84bf065e64b 100644
--- a/include/kunit/test.h
+++ b/include/kunit/test.h
@@ -1395,6 +1395,51 @@ do {									       \
 					  ##__VA_ARGS__)
 
 /**
+ * KUNIT_EXPECT_NULL() - Expects that @ptr is null.
+ * @test: The test context object.
+ * @ptr: an arbitrary pointer.
+ *
+ * Sets an expectation that the value that @ptr evaluates to is null. This is
+ * semantically equivalent to KUNIT_EXPECT_PTR_EQ(@test, NULL, ptr).
+ * See KUNIT_EXPECT_TRUE() for more information.
+ */
+#define KUNIT_EXPECT_NULL(test, ptr)				               \
+	KUNIT_BINARY_PTR_EQ_ASSERTION(test,				       \
+				      KUNIT_EXPECTATION,		       \
+				      (typeof(ptr))NULL,		       \
+				      ptr)
+
+#define KUNIT_EXPECT_NULL_MSG(test, ptr, fmt, ...)	                       \
+	KUNIT_BINARY_PTR_EQ_MSG_ASSERTION(test,				       \
+					  KUNIT_EXPECTATION,		       \
+					  (typeof(ptr))NULL,		       \
+					  ptr,				       \
+					  fmt,				       \
+					  ##__VA_ARGS__)
+/**
+ * KUNIT_EXPECT_NOT_NULL() - Expects that @ptr is not null.
+ * @test: The test context object.
+ * @ptr: an arbitrary pointer.
+ *
+ * Sets an expectation that the value that @ptr evaluates to is not null. This
+ * is semantically equivalent to KUNIT_EXPECT_PTR_NE(@test, NULL, ptr).
+ * See KUNIT_EXPECT_TRUE() for more information.
+ */
+#define KUNIT_EXPECT_NOT_NULL(test, ptr)			               \
+	KUNIT_BINARY_PTR_NE_ASSERTION(test,				       \
+				      KUNIT_EXPECTATION,		       \
+				      (typeof(ptr))NULL,		       \
+				      ptr)
+
+#define KUNIT_EXPECT_NOT_NULL_MSG(test, ptr, fmt, ...)	                       \
+	KUNIT_BINARY_PTR_NE_MSG_ASSERTION(test,				       \
+					  KUNIT_EXPECTATION,		       \
+					  (typeof(ptr))NULL,		       \
+					  ptr,				       \
+					  fmt,				       \
+					  ##__VA_ARGS__)
+
+			   /**
  * KUNIT_EXPECT_NE() - An expectation that @left and @right are not equal.
  * @test: The test context object.
  * @left: an arbitrary expression that evaluates to a primitive C type.
@@ -1678,6 +1723,52 @@ do {									       \
 					  fmt,				       \
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
+	KUNIT_BINARY_PTR_EQ_ASSERTION(test,				       \
+				      KUNIT_ASSERTION,			       \
+				      (typeof(ptr))NULL,		       \
+				      ptr)
+
+#define KUNIT_ASSERT_NULL_MSG(test, ptr, fmt, ...) \
+	KUNIT_BINARY_PTR_EQ_MSG_ASSERTION(test,				       \
+					  KUNIT_ASSERTION,		       \
+					  (typeof(ptr))NULL,                   \
+					  ptr,			               \
+					  fmt,				       \
+					  ##__VA_ARGS__)
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
+	KUNIT_BINARY_PTR_NE_ASSERTION(test,                                    \
+				      KUNIT_ASSERTION,                         \
+				      (typeof(ptr))NULL,                       \
+				      ptr)
+
+#define KUNIT_ASSERT_NOT_NULL_MSG(test, ptr, fmt, ...)		               \
+	KUNIT_BINARY_PTR_NE_MSG_ASSERTION(test,				       \
+					  KUNIT_ASSERTION,		       \
+					  (typeof(ptr))NULL,                   \
+					  ptr,			               \
+					  fmt,				       \
+					  ##__VA_ARGS__)
+
 /**
  * KUNIT_ASSERT_NE() - An assertion that @left and @right are not equal.
  * @test: The test context object.
-- 
2.35.0.263.gb82422642f-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220207183308.1829495-1-ribalda%40chromium.org.
