Return-Path: <kasan-dev+bncBC7OBJGL2MHBBM5BYSEAMGQEBZIIK2Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x238.google.com (mail-oi1-x238.google.com [IPv6:2607:f8b0:4864:20::238])
	by mail.lfdr.de (Postfix) with ESMTPS id 32CAD3E44BA
	for <lists+kasan-dev@lfdr.de>; Mon,  9 Aug 2021 13:25:40 +0200 (CEST)
Received: by mail-oi1-x238.google.com with SMTP id v128-20020aca61860000b029025c02a6228csf7002919oib.21
        for <lists+kasan-dev@lfdr.de>; Mon, 09 Aug 2021 04:25:40 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1628508339; cv=pass;
        d=google.com; s=arc-20160816;
        b=kxF9a3K7cqCa7VEFjhNDyj4JLmrayVzGyj6sPCgYzFFpyUuXKHwcpl6v1YtywwI1HS
         RRbL/2h8WRpnCehjgr9ygN1mMIvtMkocP45lz8H+Fwg2r8y7Y5LHk5KCvaNH7D4N7vXF
         sZgoRvA8Wu0sK8nMpIisz7Ei11CzJ8yfBmU98eAHS0giAnMPvOybhJfZjV2Sb+24vt3e
         xEnKZI5okW6tJBetXKfaHJkV73mJ6gxeWQ3O40CXW2W5dcRfEg1GdldUN/rZhdqfrdNn
         h+BXugW3f+2YYxYHBF4QyAKPjXqgxKugCHg7w1vj7BQZ3w06PH8qi0Khl1FIqk1w3d9a
         Rm2A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=U2iukyTxFm+XpJosdhCVaJ1jOvAYrcBn1ZGsh2cI+PE=;
        b=slgpmOCcH7+EdaETAAz4WxdJ0p3w0tT/ir0Zfnub4uImGKRoMmPRSVrciwkqcNcHEy
         PQe4Yu0cmWWqvoxq06qranXtCgfxA3AsYf0VsqDZghhZVvQ/iStttIeM2lMO4JVygrnd
         ZrHQ2pMHQN0BVp7s+G0mlxu5/SdAma8T9NyqVTIOrZ76yQ6Qz5TYAPt4N78NfNSeCHG3
         vfo7hvqSvG2bot41CTen5ghERkBthajG8NaAFcga1wNwlwFn56w4UpPcz0kNP1RkmvTZ
         xpX9bASmlHfACLvkAq962R0LSVrnliJXn5o9h2Gb1B3na/IQoYVizS7E/fcK3iWJcQSA
         AKaw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=eY1798Oe;
       spf=pass (google.com: domain of 3sharyqukcschoyhujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::f4a as permitted sender) smtp.mailfrom=3shARYQUKCScHOYHUJRRJOH.FRPNDVDQ-GHYJRRJOHJURXSV.FRP@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=U2iukyTxFm+XpJosdhCVaJ1jOvAYrcBn1ZGsh2cI+PE=;
        b=jcRPoEP7PEgl2r49OXHL0bOxvAmt8LySSMhz/eTqS5joNz7aWXrL9UX7IclDNMiaRb
         qOGBaly51KMeWHr0vxkvXXIbaPQkowcYqCheedphHXq9vXajTuDGF1umKWkAdtQ1ptcX
         iSkNYu3ktpQ5z0ejdkZJ/uuNXU19hxR/AlSf9sbVasgBPg5l7EcQ/chn6fE4rMMxuuhl
         VJb7vWipNCH92RiCqYAE4qIKs//ebqTToMPXRf9yly3aRI/Js2Nr3GO2XhrPghwJuAI5
         FKRBXawQYu3K2EqkmcJZRary3/10gHtn73xl+BWSfvl0IVn8Ek1ye3hyFyidLWDn1qvS
         yQIw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=U2iukyTxFm+XpJosdhCVaJ1jOvAYrcBn1ZGsh2cI+PE=;
        b=icYMVE5i5wGR6fTIOv0xwXLqLdOk7uPY0ylE6QeA52UffPsVqOc3GblIKe5Iw2Z1mW
         /IqmdW2GaZAmvfD88wr2hrep+I4ibPM2dNkyMEenQbpIt6rwDnRx4QRkwxSVFGgBk9oj
         OT6Ielj18LKGXQZhS2HahXgNXLCYub2k+6u9L8iG6ipm5B0UHGDhl46VYfXJ+LYJ8mgO
         9BRyMz/tTeEXcEPuBm5kVJwanLeT2kULFTbsBTzJ1+VKzezQH8m4bIdvXr+xWOxMveiU
         HvCymZhcLJ2K2JpeUi+3xm6Qv0hvEpTFtL8m3TNGrlJ+VPtnvRa0/GOC8hCv8VnFJsf2
         MHqQ==
X-Gm-Message-State: AOAM531McPaxzVr7dl0aiccUKurvptofebnZj7SPEBP0PKPvP8mD3f1t
	3NSrpIBl+VK6uRr1KsZtzrc=
X-Google-Smtp-Source: ABdhPJx/a8AdQANX9rG/7/a0DeXFmowNBX9S5Dpthxo4hhWZ7h8iPZO4WgP5ovS3geeS0+ZQjYPhLg==
X-Received: by 2002:a05:6830:4407:: with SMTP id q7mr16053596otv.246.1628508339247;
        Mon, 09 Aug 2021 04:25:39 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6808:198e:: with SMTP id bj14ls259244oib.3.gmail; Mon,
 09 Aug 2021 04:25:38 -0700 (PDT)
X-Received: by 2002:aca:b309:: with SMTP id c9mr23788699oif.135.1628508338834;
        Mon, 09 Aug 2021 04:25:38 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1628508338; cv=none;
        d=google.com; s=arc-20160816;
        b=HIAYCKY9Cvf6aOXch8wjDyCc9dGCaBCTzIGclboArL/6URvpLNXgAVrqAKLvHbEfFU
         ntKBaiToHo9U9pJLedpHjYBB5qAG8rJjQbuJSkMuH9L7GIoZPhv+eseUF+Wd4mVgrorY
         oQcsnf6c+cieeYVgKom8NrOVT8sQA8V9A1uwOMKvVzfyW5afzZHV1LVlnSfocq39/Hct
         p7q50FDpc6VZy4FPonATCBTCLTM4qSHTsOvq5IbGyz4JP8ttutWf9NJDJ4U0EjOBeaAr
         0PdQnEAzPg8RiqR1oRmBUzD5Daxvi3KzihSfGPLG/36PoTuAdCNVOJeQf3BzE1wxc6f9
         Dgkw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=8ypZsLoKbz6m1Ndv9rBXLhnIYaRjGdKDRIRf2rW5PW4=;
        b=OcxzS5PgZL4ukqUbpfVPuKJa7OGBblqvMe6MFE1x3M+0en36budUBhAFjXcUgxk8n/
         ZsoBnJ464gz6MixnTl0brHDtRAe4/lJSfnvP+jV3p9JbyOfXDqCL/ElmPfT275PPIQQu
         EAcwK4XkOYbHfhcpOMhsRyWORx6+DXNtY/S3Vw5t6trXlw1zHv0q/vTdCEeTW3xCaj+d
         N0anVvhI1f0xVYrrVzHM5rHObA+nBIJlO3Aq3+DdtXZjl+sr9BqvVlOdxxCV6r5x8Qho
         4YHse3c2iIoTIgbZVRd09d14gH27o6ogixIWeE4gWPfdgi9E8lLMhK+vuje6lFOhFAES
         YsWw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=eY1798Oe;
       spf=pass (google.com: domain of 3sharyqukcschoyhujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::f4a as permitted sender) smtp.mailfrom=3shARYQUKCScHOYHUJRRJOH.FRPNDVDQ-GHYJRRJOHJURXSV.FRP@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf4a.google.com (mail-qv1-xf4a.google.com. [2607:f8b0:4864:20::f4a])
        by gmr-mx.google.com with ESMTPS id q1si1020872oij.1.2021.08.09.04.25.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 09 Aug 2021 04:25:38 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3sharyqukcschoyhujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::f4a as permitted sender) client-ip=2607:f8b0:4864:20::f4a;
Received: by mail-qv1-xf4a.google.com with SMTP id v15-20020a0ccd8f0000b0290335f005a486so12009995qvm.22
        for <kasan-dev@googlegroups.com>; Mon, 09 Aug 2021 04:25:38 -0700 (PDT)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:e5a3:e652:2b8b:ef12])
 (user=elver job=sendgmr) by 2002:a0c:c78f:: with SMTP id k15mr11904588qvj.20.1628508338344;
 Mon, 09 Aug 2021 04:25:38 -0700 (PDT)
Date: Mon,  9 Aug 2021 13:25:09 +0200
In-Reply-To: <20210809112516.682816-1-elver@google.com>
Message-Id: <20210809112516.682816-2-elver@google.com>
Mime-Version: 1.0
References: <20210809112516.682816-1-elver@google.com>
X-Mailer: git-send-email 2.32.0.605.g8dce9f2422-goog
Subject: [PATCH 1/8] kcsan: test: Defer kcsan_test_init() after kunit initialization
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, paulmck@kernel.org
Cc: mark.rutland@arm.com, dvyukov@google.com, glider@google.com, 
	boqun.feng@gmail.com, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=eY1798Oe;       spf=pass
 (google.com: domain of 3sharyqukcschoyhujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::f4a as permitted sender) smtp.mailfrom=3shARYQUKCScHOYHUJRRJOH.FRPNDVDQ-GHYJRRJOHJURXSV.FRP@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

When the test is built into the kernel (not a module), kcsan_test_init()
and kunit_init() both use late_initcall(), which means kcsan_test_init()
might see a NULL debugfs_rootdir as parent dentry, resulting in
kcsan_test_init() and kcsan_debugfs_init() both trying to create a
debugfs node named "kcsan" in debugfs root. One of them will show an
error and be unsuccessful.

Defer kcsan_test_init() until we're sure kunit was initialized.

Signed-off-by: Marco Elver <elver@google.com>
---
 kernel/kcsan/kcsan_test.c | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/kernel/kcsan/kcsan_test.c b/kernel/kcsan/kcsan_test.c
index dc55fd5a36fc..df041bdb6088 100644
--- a/kernel/kcsan/kcsan_test.c
+++ b/kernel/kcsan/kcsan_test.c
@@ -1224,7 +1224,7 @@ static void kcsan_test_exit(void)
 	tracepoint_synchronize_unregister();
 }
 
-late_initcall(kcsan_test_init);
+late_initcall_sync(kcsan_test_init);
 module_exit(kcsan_test_exit);
 
 MODULE_LICENSE("GPL v2");
-- 
2.32.0.605.g8dce9f2422-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210809112516.682816-2-elver%40google.com.
