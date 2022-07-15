Return-Path: <kasan-dev+bncBC6OLHHDVUOBB7UXYSLAMGQEKANIKWI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1037.google.com (mail-pj1-x1037.google.com [IPv6:2607:f8b0:4864:20::1037])
	by mail.lfdr.de (Postfix) with ESMTPS id B0DE0575BB4
	for <lists+kasan-dev@lfdr.de>; Fri, 15 Jul 2022 08:41:04 +0200 (CEST)
Received: by mail-pj1-x1037.google.com with SMTP id 1-20020a17090a190100b001f05565f004sf2048904pjg.0
        for <lists+kasan-dev@lfdr.de>; Thu, 14 Jul 2022 23:41:04 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1657867263; cv=pass;
        d=google.com; s=arc-20160816;
        b=0DZENza/wLMV963EqQhFj+s0dFjK4ZfJ586gBcwypk8mwn+br8X21GSfIoe3isq8b6
         dgevziqOzx8qRlTU4OCWM1QS2ELGa3tq+FrbxA8J47WCWFfSXLDl4kwITljZNVDmskUp
         5IVZYebNLD3ib3TJzOdgU65iI+9VuhC+SnIOnjbE0DBeA8t88RyimrcPURsm7IgQpwlg
         nhPIoFWoXHGOD2f7xN0rOpy4jCIFt+EvWwnLOT0H2ZSAWo3dDzZt07LQh120ghAtVCN3
         seya0ShOJTZHnz2hJFjhM0dlbiPuJsr+uGJq/MDSXLXd85aOXfKRs9oS1bgzQPU2h6lh
         UM3Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=/p3+6B/TfWYhZhmoF9CMVPHDTi0KKEqJEA0HsinQwmQ=;
        b=YjtesQyo0o5PHn3OwsjzM6i+uEYTYBh8ph3CMhJYVK9RZCObxnxORdqT1aRtW7RrxA
         0woRL99MZrgwTTgUyNZKzpcMUcohhAxHOAVTX/MhGLalI6FCha4hXyLlYJQEG7FCrOiG
         3IDu8cAGFMqmMQRxlpFvA3FgCrRhAcdTrrxbB2VqoBWt+UKnF2fqPib0tqNetwSGHdMP
         y9PyZX+PF2DTSY9zID79j8r5EJkhYFn2F+cZDvrGIyK/iLdB1P6mBcwnyrCc11LmUKNN
         1OS9zyfjM5zm3kIkdnMdMPSo85Wlpv5iQ68zh+Jr+2FbEKCWeDkNvjl30A5efUkxH7xV
         dZUQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=I3+mcTQj;
       spf=pass (google.com: domain of 3_qvryggkcxyxupcxaiqaiiafy.wigeumuh-xypaiiafyaliojm.wig@flex--davidgow.bounces.google.com designates 2607:f8b0:4864:20::649 as permitted sender) smtp.mailfrom=3_QvRYggKCXYXUpcXaiqaiiafY.WigeUmUh-XYpaiiafYaliojm.Wig@flex--davidgow.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:message-id:mime-version:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=/p3+6B/TfWYhZhmoF9CMVPHDTi0KKEqJEA0HsinQwmQ=;
        b=RoBkASli27JV8x1MuI2Gv0A+Jur3yBRqeb8Pz6B/I7Q+bl86cZK3+Sr/3o2aG8XMuV
         UaO+ulzBZdB2/YHPazyUiL/IEho6h/Hi4iJvlUuPVaeFvX/IPCSxA4GNqHXnXqcc7mr/
         Otp+m70eFlWUT7TrDoUJEFBeRMDNXGql/vLw/BemUCGl9DAoJFtW8vXTn16y1IpMYbNv
         R6AhNiSoFvssqbE+D4zfKVlmfOBA8zkrsGq/kU1N1coGAnpJbhfvS6CAFTBR42yU8RlL
         5bR3qiHkFOP5NZQHsEZrpqTDqiJR8r0prMD/SkyXU3zFQsg9sIdfxeUC9wblRdoYk7OF
         0lng==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=/p3+6B/TfWYhZhmoF9CMVPHDTi0KKEqJEA0HsinQwmQ=;
        b=akW+LP5DrB0SMxEV0noktQlEGMXPVZAGvLpjue0HiJlcGvtXw27TACD45dQnpzgbmG
         LpZrdZxIf3LfEodA6ni4s6YQeZalFSqW70o1uNRFVK0sOS+gn5J9Sb6AkPL9ukCkSUid
         QjAQ50m7+dkRmSLACplqUfeoGEnZpxlbFmlxaweYz7xbPHp8MJB5UU9SF08QFC4A6fU3
         5LwTdwM4vAY6c/j+KzE7Lx6xF+kogs0qadaGcvlRFKV1LFaj5YcBZgUbqyUh/7dt9oYt
         aUeKJGXRvyY4V9J0GUvkfphXgjykTx3f1jVzekwq0s4blh3iC1ZrYVhZfcZ9Ay4V14yd
         sWkQ==
X-Gm-Message-State: AJIora9im+YL0n+ecEKu+wEO77hTcLZr3Omw0bH9dCX9XhfmT4L5iaIY
	re2WlJkJC0ABAsOnNfBg+6M=
X-Google-Smtp-Source: AGRyM1tHTMyGZbJr5tmGt5+8cjdX0WS5w5lvuzvsgOze0VZDTCGPq4fOe/iGesc5HqzPtL0mheX+IQ==
X-Received: by 2002:a05:6a00:1249:b0:52b:3343:3dc7 with SMTP id u9-20020a056a00124900b0052b33433dc7mr3354059pfi.72.1657867262863;
        Thu, 14 Jul 2022 23:41:02 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:67c1:b0:1ef:26af:287b with SMTP id
 g1-20020a17090a67c100b001ef26af287bls582670pjm.2.-pod-canary-gmail; Thu, 14
 Jul 2022 23:41:02 -0700 (PDT)
X-Received: by 2002:a17:90a:4e05:b0:1ec:8de4:1dd5 with SMTP id n5-20020a17090a4e0500b001ec8de41dd5mr13851917pjh.242.1657867262047;
        Thu, 14 Jul 2022 23:41:02 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1657867262; cv=none;
        d=google.com; s=arc-20160816;
        b=WQeMuWwXJQykIAAgubIpmZE8Elzhe3wESyy9toy0YYwkHKSucHdDTMQSvPSqTMx8ne
         Jo9jg4z0JBryWW4nPhE0bNv6x3t/AHGdlI9AwGKh9mSKyY13O0ggMgnBknLUz0dMCbgO
         UXwH7TelF3LyOV7hA/XTFAheRxuTPCSxrQ7PeQMlGT2mCdQ7jIPvZ2HLuxaE3kAHkvao
         oIyiS+ozXwgr5dGGGxfPtCBODJdP5y7317ed4AgcPsZPqlrH2R/0qpjwtRH5mXj0DbHk
         BG3bbAFSv4SuwOOLtY9ILpBrjTXGnTlLKo8mPoMw5I4NJqs40AtV33DMOogp08Amy/MU
         Oyrw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=q8Lc0RHx8l1tneFtOMp4vYatrYpRnfAN4z26Z90CGPY=;
        b=ExYjTxsSASdsq8iGC37jRR2QtElYlJ1CuAk0/NtV8Bl7ZeBX5uR0ipaKT5gBu9uEaR
         m9hZkKJOyEY/qsH2M+9TXdVKbHsjqCccxY2zznQGJM6QKG4q9hi6/awHQbmAj3GMwI4Y
         KNePxOEssvfMQlEiXyKHCd+Rl8DZkEga8MOXQhKKZbGBdSO8ueAKeY1BHRiAoAG2f2fC
         6wuV5Gz89xLFhSm6xQ6XCW6dwkKWTFgvjmQ8JqYPg6ZANXa357IbJo6YyjAFfY0AJ3jz
         sQKTAAk5tF+Sxn+YO8bBVCUWzEp7qr+IwkCMQCNQHiWUOFWXaHS7nQKH7I0DYqgB2up4
         9x8Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=I3+mcTQj;
       spf=pass (google.com: domain of 3_qvryggkcxyxupcxaiqaiiafy.wigeumuh-xypaiiafyaliojm.wig@flex--davidgow.bounces.google.com designates 2607:f8b0:4864:20::649 as permitted sender) smtp.mailfrom=3_QvRYggKCXYXUpcXaiqaiiafY.WigeUmUh-XYpaiiafYaliojm.Wig@flex--davidgow.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pl1-x649.google.com (mail-pl1-x649.google.com. [2607:f8b0:4864:20::649])
        by gmr-mx.google.com with ESMTPS id mm15-20020a17090b358f00b001efc9eed180si271571pjb.0.2022.07.14.23.41.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 14 Jul 2022 23:41:02 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3_qvryggkcxyxupcxaiqaiiafy.wigeumuh-xypaiiafyaliojm.wig@flex--davidgow.bounces.google.com designates 2607:f8b0:4864:20::649 as permitted sender) client-ip=2607:f8b0:4864:20::649;
Received: by mail-pl1-x649.google.com with SMTP id b10-20020a170902d50a00b0016c56d1f90fso1564454plg.21
        for <kasan-dev@googlegroups.com>; Thu, 14 Jul 2022 23:41:02 -0700 (PDT)
X-Received: from slicestar.c.googlers.com ([fda3:e722:ac3:cc00:4f:4b78:c0a8:20a1])
 (user=davidgow job=sendgmr) by 2002:a17:902:f606:b0:168:ecca:44e with SMTP id
 n6-20020a170902f60600b00168ecca044emr11864579plg.144.1657867261813; Thu, 14
 Jul 2022 23:41:01 -0700 (PDT)
Date: Fri, 15 Jul 2022 14:40:52 +0800
Message-Id: <20220715064052.2673958-1-davidgow@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.37.0.170.g444d1eabd0-goog
Subject: [PATCH v2] kcsan: test: Add a .kunitconfig to run KCSAN tests
From: "'David Gow' via kasan-dev" <kasan-dev@googlegroups.com>
To: Brendan Higgins <brendanhiggins@google.com>, Daniel Latypov <dlatypov@google.com>, 
	Marco Elver <elver@google.com>, Shuah Khan <skhan@linuxfoundation.org>
Cc: David Gow <davidgow@google.com>, Dmitry Vyukov <dvyukov@google.com>, kunit-dev@googlegroups.com, 
	linux-kselftest@vger.kernel.org, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: davidgow@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=I3+mcTQj;       spf=pass
 (google.com: domain of 3_qvryggkcxyxupcxaiqaiiafy.wigeumuh-xypaiiafyaliojm.wig@flex--davidgow.bounces.google.com
 designates 2607:f8b0:4864:20::649 as permitted sender) smtp.mailfrom=3_QvRYggKCXYXUpcXaiqaiiafY.WigeUmUh-XYpaiiafYaliojm.Wig@flex--davidgow.bounces.google.com;
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

Add a .kunitconfig file, which provides a default, working config for
running the KCSAN tests. Note that it needs to run on an SMP machine, so
to run under kunit_tool, the --qemu_args option should be used (on a
supported architecture, like x86_64). For example:
./tools/testing/kunit/kunit.py run --arch=x86_64 --qemu_args='-smp 8'
					--kunitconfig=kernel/kcsan

Signed-off-by: David Gow <davidgow@google.com>
Reviewed-by: Marco Elver <elver@google.com>
Acked-by: Brendan Higgins <brendanhiggins@google.com>
---
 kernel/kcsan/.kunitconfig | 24 ++++++++++++++++++++++++
 1 file changed, 24 insertions(+)
 create mode 100644 kernel/kcsan/.kunitconfig

diff --git a/kernel/kcsan/.kunitconfig b/kernel/kcsan/.kunitconfig
new file mode 100644
index 000000000000..e82f0f52ab0a
--- /dev/null
+++ b/kernel/kcsan/.kunitconfig
@@ -0,0 +1,24 @@
+# Note that the KCSAN tests need to run on an SMP setup.
+# Under kunit_tool, this can be done by using the --qemu_args
+# option to configure a machine with several cores. For example:
+# ./tools/testing/kunit/kunit.py run --kunitconfig=kernel/kcsan \
+# 				 --arch=x86_64 --qemu_args="-smp 8"
+
+CONFIG_KUNIT=y
+
+CONFIG_DEBUG_KERNEL=y
+
+# Need some level of concurrency to test a concurrency sanitizer.
+CONFIG_SMP=y
+
+CONFIG_KCSAN=y
+CONFIG_KCSAN_KUNIT_TEST=y
+
+# Set these if you want to run test_barrier_nothreads
+#CONFIG_KCSAN_STRICT=y
+#CONFIG_KCSAN_WEAK_MEMORY=y
+
+# This prevents the test from timing out on many setups. Feel free to remove
+# (or alter) this, in conjunction with setting a different test timeout with,
+# for example, the --timeout kunit_tool option.
+CONFIG_KCSAN_REPORT_ONCE_IN_MS=100
-- 
2.37.0.170.g444d1eabd0-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220715064052.2673958-1-davidgow%40google.com.
