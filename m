Return-Path: <kasan-dev+bncBC6OLHHDVUOBBJ6CSKKAMGQE4PAA7YA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x139.google.com (mail-il1-x139.google.com [IPv6:2607:f8b0:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id E00D052B372
	for <lists+kasan-dev@lfdr.de>; Wed, 18 May 2022 09:32:56 +0200 (CEST)
Received: by mail-il1-x139.google.com with SMTP id q6-20020a056e0215c600b002c2c4091914sf801699ilu.14
        for <lists+kasan-dev@lfdr.de>; Wed, 18 May 2022 00:32:56 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1652859175; cv=pass;
        d=google.com; s=arc-20160816;
        b=s0w6fudfC9ts5rCp5bIpNyRISUMyFq3VTB3WIj4V0/UBbFMXs7fXdkwHF9C0DkjUwj
         nw4cfPen8lpKjRfOPN/07Dr8U2+F3gA7KCUn1xC1RiCel08TqXhTYR1B5CliGWiLxLYE
         3BUdD1AQzRi49CDD7XNARyPrjKhhcZfNGpSSPnX737+Oc6qfpd+QXbAB7pqlE78gfOLJ
         fJhkWfrjP9PUIL2gF3bLActRMPRSBVnJSapcdHEAHJXM9V6OCtom188+mPnCYZwdAb86
         i2z+J5Lz7xFfBCiqymjOvSTKTeXAovs7Ibzwvei57YoqmdKP/sjfKGae0ZtnWFJsNbNr
         yFLg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=J3hjr+E5mxBTy5YORpY9Ia/vs2JluBIn+Ho5g0zW7Rw=;
        b=Pd1IsI5gsf6chOCmSZDvK36RjizGurePlJIK60PxpsLaWOxWwqRKJvKq20yQxG8GC7
         ZfJqh46BDQkwWAdD7+9aptBWIGTRgxrqtb97t6bgWiZ+uH7RTwnjJWYUNEpw71f6gPpd
         7IqtFvgiCw7jP9olFaK/Vf/xMsD7BNus3TXtdsLi+AKTAPBsqP0vBHG0EVRy0NTG8G5N
         hTtfkxKncBFKRCM8ubrMbcDG1DqcCcDE+Z95k05ZM5mHElkx92Rot9or+bV96pE7NGIS
         nhm1zUv2ZQVP6LMBAuLcGGOmzhjok3LZni/KyRUNfINwx2GqOQzlYoVvA+ujUMPAKu+w
         82Bg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=Pitbkuos;
       spf=pass (google.com: domain of 3jqgeyggkczu2zk725dl5dd5a3.1db9zhzc-23k5dd5a35gdjeh.1db@flex--davidgow.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3JqGEYggKCZU2zK725DL5DD5A3.1DB9zHzC-23K5DD5A35GDJEH.1DB@flex--davidgow.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=J3hjr+E5mxBTy5YORpY9Ia/vs2JluBIn+Ho5g0zW7Rw=;
        b=rQTelSM9DCELqgUkLqVSrNzkWHRjKcBGqVYQrd61/odxw/cL5K/RdEFnnJ8LkYGWzE
         ZmO+GSLGb6Y83LXzyMITuG1za6xF6iqOpG26UJ0WPQuhAscHsjRK88OoapSk7j1J89jy
         6+Q7sXKT6hfiocZYyMluN5jH8aX9NDzi1UAScjEHOJBFzdVEuSQbxIPDjfUiyKSd6Axi
         Fn7eod7XDNraCgNLCcZXQ8kj7g/GyWubtzNzYIicdlJ66k3YppyhiLabMLg0uMXf+oa0
         OTEmiK2KCaBJ9Nmoy/ysmqOeTamtgu2WDj3nCrU0bwalSSjzpoXgxY0h+DheQi2psL4D
         68kg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=J3hjr+E5mxBTy5YORpY9Ia/vs2JluBIn+Ho5g0zW7Rw=;
        b=FF+XJVCTd173TxhkmwRD8G3+UJW2JX9ygTtOiWgWVdKRNLBTfzSmX53OCeCsBgn/cY
         n4b5HcEmopp3RCUMz2Iw6/vd2JYkN2V+AtBsg9LfLagrfGhDoKveMq4xouWWClCTSC5V
         ANtDEsM3HmHQodZf2RdalMjTivLjtQdGv01413ZfH+sLaILDA6JenN0SOvdIIC4kE371
         l4RBJSQ3HKOMcuo7Xs48CA4ECMe4bzOL4IE20QFJDBn5SFVrSSk0KqKIT/jBrtvICDpe
         JsHv2B9y64WD/B9rWzm1A5hQwaE5I4Aq5TY6IYC6sxemzfZ9sDa5f7DC5hwMUHk1cxqq
         iRyg==
X-Gm-Message-State: AOAM533829er8F7lDuJ44+3/q4VF10E9HybVDdmA86pRY71+HmXi45Jg
	g31hrF/iHGqDE1vqUBA1Phc=
X-Google-Smtp-Source: ABdhPJzeCxpsLU+1lPzXa6SGzkuOpHCvgGp/kud/QxYqxYTXSmja9XCFHnw+FHmu0E9SWRQUsAzhkQ==
X-Received: by 2002:a92:d805:0:b0:2d0:ea4f:5dcb with SMTP id y5-20020a92d805000000b002d0ea4f5dcbmr13277298ilm.78.1652859175728;
        Wed, 18 May 2022 00:32:55 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6638:3010:b0:319:c97e:f47d with SMTP id
 r16-20020a056638301000b00319c97ef47dls3629625jak.1.gmail; Wed, 18 May 2022
 00:32:55 -0700 (PDT)
X-Received: by 2002:a05:6638:1c14:b0:32b:5d85:f8e6 with SMTP id ca20-20020a0566381c1400b0032b5d85f8e6mr13837036jab.110.1652859175194;
        Wed, 18 May 2022 00:32:55 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1652859175; cv=none;
        d=google.com; s=arc-20160816;
        b=tX4TVHeum+l/u8cjbXD0tm9onU0oJ4HR7MkmdfdInw00L6Xl0NqGjy/sezpdXl1leQ
         3iF7Mx6z/XEHTCKBtqMP848yVYKCr133BHOfEUb/L5nHEwetOoi8zSkY0CAWk6aYwvqH
         Bg+nUauxXM4hVTnwjfRwOwuJaHaJzOWk9d2T+DrB3suu6uNrDjHg4w1sI/X9t5FkW21Q
         4i/J7EmH3qWrWu4Azic05aSD+XN2KN7j77OTQG7m85BV27YkuZAjpO+3NaWQ7XyxXyMf
         49kQyndjCqhpDo51KqNq+Rvv4gE3nyyINdr6CkTeQdBdvHSrqZ6aabnwG7CBzJO/hPbZ
         rjSw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=GtAQDy8qrMQs7mWCa7GmbHUrKXDNUra1mtOtVoTKAPY=;
        b=0YTXHDgIi3nW5FwslFL3Da97457mUwNk1/t23p+eeJEW8RWpaFXwHberd1gSgRubxt
         F3S+Gb5TH2Y6uTOEiCUjNPgngbx0jf2QpAn6tP/1I2tZ7ck3Fu6z/gsMLso5Rv4ZWFZR
         jj9Pvx14uprxOGwC29g02eiHreNJnj1P6JUru/8QVTI5iXOb1II4yuwv7rJIAmXxiIrB
         QliDHxN7xcYFAp2bctjDnLC8RQzf7SW6aoN2qkViSguQYfV4/YJUNPMwcuAn71vIUsWU
         BcykjElQGMiJ7RMYA88uRIhMRzcl2XwS3LTPH6KFwpMuhwJ+afN0uvL1az77CUZoKQ75
         2Npw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=Pitbkuos;
       spf=pass (google.com: domain of 3jqgeyggkczu2zk725dl5dd5a3.1db9zhzc-23k5dd5a35gdjeh.1db@flex--davidgow.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3JqGEYggKCZU2zK725DL5DD5A3.1DB9zHzC-23K5DD5A35GDJEH.1DB@flex--davidgow.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb49.google.com (mail-yb1-xb49.google.com. [2607:f8b0:4864:20::b49])
        by gmr-mx.google.com with ESMTPS id m11-20020a056e02158b00b002cc062dcde7si120801ilu.0.2022.05.18.00.32.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 18 May 2022 00:32:55 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3jqgeyggkczu2zk725dl5dd5a3.1db9zhzc-23k5dd5a35gdjeh.1db@flex--davidgow.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) client-ip=2607:f8b0:4864:20::b49;
Received: by mail-yb1-xb49.google.com with SMTP id z39-20020a25a12a000000b0064dbcd526ffso1162948ybh.15
        for <kasan-dev@googlegroups.com>; Wed, 18 May 2022 00:32:55 -0700 (PDT)
X-Received: from slicestar.c.googlers.com ([fda3:e722:ac3:cc00:4f:4b78:c0a8:20a1])
 (user=davidgow job=sendgmr) by 2002:a81:2643:0:b0:2f4:c975:b7ca with SMTP id
 m64-20020a812643000000b002f4c975b7camr28529608ywm.494.1652859174736; Wed, 18
 May 2022 00:32:54 -0700 (PDT)
Date: Wed, 18 May 2022 15:32:32 +0800
In-Reply-To: <20220518073232.526443-1-davidgow@google.com>
Message-Id: <20220518073232.526443-2-davidgow@google.com>
Mime-Version: 1.0
References: <20220518073232.526443-1-davidgow@google.com>
X-Mailer: git-send-email 2.36.0.550.gb090851708-goog
Subject: [PATCH 2/2] kcsan: test: Add a .kunitconfig to run KCSAN tests
From: "'David Gow' via kasan-dev" <kasan-dev@googlegroups.com>
To: Brendan Higgins <brendanhiggins@google.com>, Daniel Latypov <dlatypov@google.com>, 
	Marco Elver <elver@google.com>, Shuah Khan <skhan@linuxfoundation.org>
Cc: David Gow <davidgow@google.com>, Dmitry Vyukov <dvyukov@google.com>, kunit-dev@googlegroups.com, 
	kasan-dev@googlegroups.com, linux-kselftest@vger.kernel.org, 
	linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: davidgow@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=Pitbkuos;       spf=pass
 (google.com: domain of 3jqgeyggkczu2zk725dl5dd5a3.1db9zhzc-23k5dd5a35gdjeh.1db@flex--davidgow.bounces.google.com
 designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3JqGEYggKCZU2zK725DL5DD5A3.1DB9zHzC-23K5DD5A35GDJEH.1DB@flex--davidgow.bounces.google.com;
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
to run under kunit_tool, the x86_64-smp qemu-based setup should be used:
./tools/testing/kunit/kunit.py run --arch=x86_64-smp --kunitconfig=kernel/kcsan

Signed-off-by: David Gow <davidgow@google.com>
---
 kernel/kcsan/.kunitconfig | 20 ++++++++++++++++++++
 1 file changed, 20 insertions(+)
 create mode 100644 kernel/kcsan/.kunitconfig

diff --git a/kernel/kcsan/.kunitconfig b/kernel/kcsan/.kunitconfig
new file mode 100644
index 000000000000..a8a815b1eb73
--- /dev/null
+++ b/kernel/kcsan/.kunitconfig
@@ -0,0 +1,20 @@
+# Note that the KCSAN tests need to run on an SMP setup.
+# Under kunit_tool, this can be done by using the x86_64-smp
+# qemu-based architecture:
+# ./tools/testing/kunit/kunit.py run --kunitconfig=kernel/kcsan --arch=x86_64-smp
+
+CONFIG_KUNIT=y
+
+CONFIG_DEBUG_KERNEL=y
+
+CONFIG_KCSAN=y
+CONFIG_KCSAN_KUNIT_TEST=y
+
+# Needed for test_barrier_nothreads
+CONFIG_KCSAN_STRICT=y
+CONFIG_KCSAN_WEAK_MEMORY=y
+
+# This prevents the test from timing out on many setups. Feel free to remove
+# (or alter) this, in conjunction with setting a different test timeout with,
+# for example, the --timeout kunit_tool option.
+CONFIG_KCSAN_REPORT_ONCE_IN_MS=100
-- 
2.36.0.550.gb090851708-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220518073232.526443-2-davidgow%40google.com.
