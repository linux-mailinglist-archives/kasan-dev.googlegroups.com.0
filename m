Return-Path: <kasan-dev+bncBD2OFJ5QSEDRB4GMSSKAMGQEO7GCOSI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x38.google.com (mail-oa1-x38.google.com [IPv6:2001:4860:4864:20::38])
	by mail.lfdr.de (Postfix) with ESMTPS id 9B97B52BFD6
	for <lists+kasan-dev@lfdr.de>; Wed, 18 May 2022 19:01:38 +0200 (CEST)
Received: by mail-oa1-x38.google.com with SMTP id 586e51a60fabf-e653506dd0sf1399261fac.14
        for <lists+kasan-dev@lfdr.de>; Wed, 18 May 2022 10:01:38 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1652893297; cv=pass;
        d=google.com; s=arc-20160816;
        b=raoAez2Mj4c6dipALn6lqR8rrs4N1Qr4hfZSmutRuHq5JM3BzzAP7R5jSNCYOJ8XJ9
         oYiPCHxazLxfgRJ7pjz49MaX5H8b7+rpbEwRbP2Ko4sOhyw55ZhOV8KLM3+keQpPZoXD
         Xi7Ke/Awa2YMHPX93u1VJ+HMtt48NIKaBuB/U+EVxy9xPNX7hY/yR0D7XY7FahD14M9p
         yGnbujduGAAYuDimN8QLfoQIkA2WCYxRiZFASQHWj968DPAlLMLCe9m+NQU4Sm5L5X6V
         peqrT5xdrM+Vo5WD5t8yASCp+Nu16R0wcq9XCWq4DtyNH2jk14Q92H1nQqUvFwATQbro
         Pzbg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=GGaAVZF+ZHZsZc6hUjZF4lK2FB2JSeoLEjzugJUtxLg=;
        b=HMAws/btZCEm0ZBKaG3wj7QOm6jWXTx+JzLga4Fwr95zB+GVTrxfmCgY7kr7cCT/AC
         oCBrRTkU4B/PIZWF7i/KhEWLGxWElU48vaWlbrIDDTBAVeLvSvOkURDR/kwGA34k+wdR
         N1eumVWZTKRFzqH2YpZY8ZfkElG67Mf9LJ0ebWnl5x7dsI9RVGiYLM3gpKhHCYoDndBJ
         8aJnhyiPumraCUtI1X2qQC/ZHphT6j0SBJS75VDX3heypL9TZMv2ag/I3kwraq1GIcRc
         4YwlTNCjS/FXnPF8AGIUqRjchBRVavY3c40fiSxD6FHc8o4SsRVeOemkwQ5AIW/1os3K
         zyKA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=dunm2cE6;
       spf=pass (google.com: domain of 3ccafyggkcesqynglcbitbbtyr.pbzxnfna-qritbbtyrtebhcf.pbz@flex--dlatypov.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=3cCaFYggKCesQYNglcbiTbbTYR.PbZXNfNa-QRiTbbTYRTebhcf.PbZ@flex--dlatypov.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:message-id:mime-version:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=GGaAVZF+ZHZsZc6hUjZF4lK2FB2JSeoLEjzugJUtxLg=;
        b=AVJirPfDsVL8ooztEyvy8UeaE1smwyOYCWgdRCpSfuL23SYVYzyHj3uQWzGmMJiqN0
         4rgiMBj6g+cYaeusuDHJgLC7okl0eEewZgeKSUaS8ScFGdhbQqKAl6bM+dBuA6VLFaf0
         ICr+/NzAHr4XLnFl+kcX6MXpYtIjViy8pBPg+0sqttK/AFfhEi3R5igt+ZeTEl1R7Vdd
         v14YvkGj79nYgUw7JWhpP2Tq3jldPReuPNJzqsxQnb6OAt+4VIOcmIqUBazDS9C4H5CF
         tUeRLrpo8odrMLcYcUVE65O69jcVq3xwPoMOnbKTb/wsPOb0uGCqSJNAIFMmX2rAMhwQ
         fpLg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=GGaAVZF+ZHZsZc6hUjZF4lK2FB2JSeoLEjzugJUtxLg=;
        b=aUU3FEK/8J9anglvBJcaPLRM5TCuFBRIYxiMlylZRyQODXO6Kk1H1l0oLyAneomdiZ
         9/9YsLbOavzB4XBolu9+YeNLY69oEDIVQVsSyNv7sB8rFRSOWVnQwxg3Tp+ePdpH9PVB
         VogZztSQ0n43IvuoyCNVo5iszmhTFGwwbmHPTtSC/vycFVe1F6HbHg+kDPKtZBNR3OTs
         jhIhSftGJGO7+XAbFuvu9h8zHZS76TE/8nSTJDJ3fF8ltXb6NWBDHEFcGEcMXhzk7c5W
         SMKqMIACfTDZspwmSv/RZ8GQUVaNgdG+a0pSUd92qCmgHTzmSiZWBvCcUAq82hIqgV0B
         MssA==
X-Gm-Message-State: AOAM53231RDgO/Vis55Fz3aFc9B42tyw8RkXslZdpMmq+vMNqKnNaZkK
	GIpLWmJbcu9bXim/WQH4NFQ=
X-Google-Smtp-Source: ABdhPJwfsieZZKGh6/lSNUAsEqwF3O5v2q4YlaGiwM+P3HcK+t9swHn+SLOm+nK59hlW3WEyXAu24A==
X-Received: by 2002:aca:b782:0:b0:325:7a29:352d with SMTP id h124-20020acab782000000b003257a29352dmr501862oif.217.1652893297091;
        Wed, 18 May 2022 10:01:37 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6830:1299:b0:60a:c4d4:f038 with SMTP id
 z25-20020a056830129900b0060ac4d4f038ls96684otp.2.gmail; Wed, 18 May 2022
 10:01:36 -0700 (PDT)
X-Received: by 2002:a05:6830:1290:b0:606:1ae6:7089 with SMTP id z16-20020a056830129000b006061ae67089mr255941otp.3.1652893296560;
        Wed, 18 May 2022 10:01:36 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1652893296; cv=none;
        d=google.com; s=arc-20160816;
        b=E2pSFGAaMTl4vfEF5Z4hXYTuvr1JrIoWOHSkEAbMfaqgHUaH35UBZ1qwf8zfkyGbSK
         UwpTW3q9FLp61J0vrom6hjxpJl5d3ByoEyPRIr6MMLXbpWU5Zzhopt8wdNWkUCnuis3W
         tZyK9iSU4Pyy0C6k5CrC9NxY8feu3yJUvmXir7+Zity6S5TRwIzPq+AdZpizuESJxajP
         /4MRoTuklTwokQq1m++ctSrPIoxV2ctsL2GzEKXTJ5QB+lVmoPNdv+5BZ9Co2869XZz8
         ANy/ifYJN2iDWY2II1yfM7bYpCzyDfj1hYkNfejmVZ3dkBVa6GAv4DiF1Rr5y6tODeEx
         6rsA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=6lIh3KMhywLkny9k1R++mLvsFHwuvhtDKbmD+YqVcZ8=;
        b=hwl5b6q9dijbiarAwochL5nHhjGpF9TW6fcXh3FnLe/uUElohs+jFkcAG/KI3ZsKfj
         GuqhFIm1v30mIrvH1PmrjM3WOtHogvzlSWsJLtfuyvgYjNeqSMBeVjofA8+gD/Hnz79+
         PM2nAnCR5myC1lcDlfb2Q2ruDG2Lu9jYwVUVIcHrrk08+nq0zPjXsNjZqn+cpahNAapY
         T/1P9b4JxDv+mR+X691gzBvEtOnnkM8cA7McMSF8aQxDVPZ5YGMmE7xHPyYQO+Z4AFPY
         MUnT90Y9P7lydeMpdoXUHuQZdjzgrKGQPJzyXJRq9elaY+x1Auh+YW5RgMad1y0KugFr
         kEMQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=dunm2cE6;
       spf=pass (google.com: domain of 3ccafyggkcesqynglcbitbbtyr.pbzxnfna-qritbbtyrtebhcf.pbz@flex--dlatypov.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=3cCaFYggKCesQYNglcbiTbbTYR.PbZXNfNa-QRiTbbTYRTebhcf.PbZ@flex--dlatypov.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x114a.google.com (mail-yw1-x114a.google.com. [2607:f8b0:4864:20::114a])
        by gmr-mx.google.com with ESMTPS id el40-20020a056870f6a800b000e2f2a83479si338206oab.1.2022.05.18.10.01.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 18 May 2022 10:01:36 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3ccafyggkcesqynglcbitbbtyr.pbzxnfna-qritbbtyrtebhcf.pbz@flex--dlatypov.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) client-ip=2607:f8b0:4864:20::114a;
Received: by mail-yw1-x114a.google.com with SMTP id 00721157ae682-2fb7bf98f1aso24408757b3.5
        for <kasan-dev@googlegroups.com>; Wed, 18 May 2022 10:01:36 -0700 (PDT)
X-Received: from dlatypov.svl.corp.google.com ([2620:15c:2cd:202:a94f:2cb3:f298:ec1b])
 (user=dlatypov job=sendgmr) by 2002:a25:c60e:0:b0:64e:a4a3:bd76 with SMTP id
 k14-20020a25c60e000000b0064ea4a3bd76mr645342ybf.372.1652893296118; Wed, 18
 May 2022 10:01:36 -0700 (PDT)
Date: Wed, 18 May 2022 10:01:21 -0700
Message-Id: <20220518170124.2849497-1-dlatypov@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.36.1.124.g0e6072fb45-goog
Subject: [PATCH 0/3] kunit: add support in kunit.py for --qemu_args
From: "'Daniel Latypov' via kasan-dev" <kasan-dev@googlegroups.com>
To: brendanhiggins@google.com, davidgow@google.com
Cc: elver@google.com, linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com, 
	kunit-dev@googlegroups.com, linux-kselftest@vger.kernel.org, 
	skhan@linuxfoundation.org, Daniel Latypov <dlatypov@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dlatypov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=dunm2cE6;       spf=pass
 (google.com: domain of 3ccafyggkcesqynglcbitbbtyr.pbzxnfna-qritbbtyrtebhcf.pbz@flex--dlatypov.bounces.google.com
 designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=3cCaFYggKCesQYNglcbiTbbTYR.PbZXNfNa-QRiTbbTYRTebhcf.PbZ@flex--dlatypov.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Daniel Latypov <dlatypov@google.com>
Reply-To: Daniel Latypov <dlatypov@google.com>
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

Note: this series applies on top of
https://lore.kernel.org/linux-kselftest/20220516194730.1546328-2-dlatypov@google.com/.
That patch greatly simplified the process of adding new flags.

This flag would let users pass additional arguments to QEMU when using a
non-UML arch to run their tests.
E.g. for kcsan's tests, they require SMP and with this patch, you can do
$ ./tools/testing/kunit/kunit.py run --kconfig_add=CONFIG_SMP --qemu_args='-smp 8'

This is proposed as an alternative to users manually creating new
qemu_config python files and also to [1], where we discussed checking in
a new x86_64 variant w/ `-smp 8` hard-coded into it.

This patch also contains a fix to the example `run_kunit` bash function
since it didn't quote properly and would parse the example above as
  --qemu_args='-smp' '8'
no matter how you tried to quote your arguments.

[1] https://lore.kernel.org/linux-kselftest/20220518073232.526443-1-davidgow@google.com/

Daniel Latypov (3):
  Documentation: kunit: fix example run_kunit func to allow spaces in
    args
  kunit: tool: simplify creating LinuxSourceTreeOperations
  kunit: tool: introduce --qemu_args

 .../dev-tools/kunit/running_tips.rst          |  2 +-
 tools/testing/kunit/kunit.py                  | 14 +++++++++-
 tools/testing/kunit/kunit_kernel.py           | 26 +++++++++++--------
 tools/testing/kunit/kunit_tool_test.py        | 20 +++++++++++---
 4 files changed, 46 insertions(+), 16 deletions(-)

-- 
2.36.1.124.g0e6072fb45-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220518170124.2849497-1-dlatypov%40google.com.
