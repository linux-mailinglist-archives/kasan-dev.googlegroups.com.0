Return-Path: <kasan-dev+bncBC24VNFHTMIBBBFDZ33QKGQEUL7UHUY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33e.google.com (mail-ot1-x33e.google.com [IPv6:2607:f8b0:4864:20::33e])
	by mail.lfdr.de (Postfix) with ESMTPS id 0D62D207A94
	for <lists+kasan-dev@lfdr.de>; Wed, 24 Jun 2020 19:46:46 +0200 (CEST)
Received: by mail-ot1-x33e.google.com with SMTP id o21sf1892676ote.4
        for <lists+kasan-dev@lfdr.de>; Wed, 24 Jun 2020 10:46:45 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1593020805; cv=pass;
        d=google.com; s=arc-20160816;
        b=Oj1fb/7MFv5bjGy/RcZBO4XTzf8Ep8BnMOBGv/hvghpdzuNCYNd+ujVK3np6gn7dpZ
         v95nP/e4hBednFprhJQFVSIBuCyHSDpi9pHEmhVeep6An+7lGoYTs0xW5DxRhxTC6yoI
         hz4UXhcR+cfZRgOYk/HNjN9QICPbM7RMCzoqcfzwmsfVM7u/xdVRP6S/syU7YqBSs+PM
         x2iUROzXfTqvJb2VOyoUQqg0Z69lD7/ueCNVCltzarr8hLw602euV637jk3sQ2OWUkiW
         kaNkIUn5WI87EDU0g/ZlZb3PYID3dyML2hpY6C22Kk7yr2nqDuzqLydWRQZQojxbuTnA
         +Cqw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=cQanJXPbydvQNzajguVonKuSPUvE83R3QwWvixE/pac=;
        b=j0FioHnTobKzpTRD8ezPZ+Phs/rM+UFg8VGVazsN+QklZ72l3WPF1ogk64Q8H/BouE
         a85pAWT9MOLOGRLcEgKCXIRKdPRpCOJR/M5vpzSDlSSrD4kWorUbFtNa+DRlp98AOQGT
         zKXvyhTS5HqdYsWKalMYioJS89sqwUqjjpbYtOK6ba9w5pAO2NmZBVR8p9c/Lcq8K2dZ
         d6K8ifJdBU1gxdM3i+2MD/R1qGjKopuvL5imzXo7yRxPoL6tlXQPFJcdHacuy5vmG5dw
         3XHWdoAuRuEEgDJ+mQMtmqaH7mCJL1Nk3kLioYwpRqCGitUJup7JUuzclvmO1PXQpjav
         9+3A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=7ptk=af=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=7pTk=AF=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:date:message-id:in-reply-to:references
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=cQanJXPbydvQNzajguVonKuSPUvE83R3QwWvixE/pac=;
        b=caZtKLcyjJuBe0Xj8678hyr6enbk+JZ4OiXcVZTjRB43jWUCj3ctUxGvfg1ZlJTW2W
         b3WsymfGeoPbamEUNYP210vQNJyatGG1WaPsodO0yh5ky4nZQMzySMGZ1PoNiKHwBEdr
         xctvKurarYEVd9ZzSTQL86NA+vburGXd2yd9qbJ4jNMSFVIngwJUHoPdexinGkGu/Yk6
         kHz8G0TChz9VafDz8IWC/zWzVBG3555VzD375bO8A/sSWT7v6/Uxoo1TsOU5KXgzokk8
         GCXiRNEpn7J5svrIkNveMa+DHgCXFKzNiXWBRobObOpjrxqp45xwUmlvpIE3AvDEynx+
         u33g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :in-reply-to:references:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=cQanJXPbydvQNzajguVonKuSPUvE83R3QwWvixE/pac=;
        b=WnPbBXp1vxmPboZawR2UgDFc6J5ELb8rzxfUuDJNGnH9EdBsT38uNXvv+H3xtI+3NP
         hLZxxwKSGPV8apqTqhT/gl+2xx5lCfZ+WPF0U7HLm56H0GuoZTQ5gTjmpP/G+Ui78pr9
         NX8u4aHsG3f+p1gIsFeh0xnS8oElm4z0NPvRRu+7w5q4ywRifqyfYf0wOA7jktCJcy+O
         hTO2i2DYDi+j9hgeimuAkWLVDG5o9obY28Lm6IowDWhmUbdLCg1Wm4mZxXn68WnxJ1fJ
         n3Oc94aqyNAjy60DC5RJuw+CTnzccWq0gJGSZp5G4/FP0gvEJEXsDwEkngHR8+ROjwjX
         65ag==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532JFL6Y5Xkdy20xWLi/Brsp2GtFOxfueGpySGJFUU9vWNNgzXlw
	c+amdaDKz8nG7+YxPwD9id0=
X-Google-Smtp-Source: ABdhPJzQ3GnsMg17GqESci0O1DlJH3G9qRJvFg3pHO0WWQHTC98Yri6am885on2+V2DVwzS43uJyzQ==
X-Received: by 2002:a4a:9210:: with SMTP id f16mr8724190ooh.13.1593020804951;
        Wed, 24 Jun 2020 10:46:44 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:520f:: with SMTP id g15ls562726oib.7.gmail; Wed, 24 Jun
 2020 10:46:44 -0700 (PDT)
X-Received: by 2002:a05:6808:496:: with SMTP id z22mr21207186oid.176.1593020804679;
        Wed, 24 Jun 2020 10:46:44 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1593020804; cv=none;
        d=google.com; s=arc-20160816;
        b=P7g8C6C+Hpm/yJDAJ7Ppt8y/ZreWpcz8fCX1CdUBQ04G7abbvj1gei8+y7eQ7+QgDg
         TgpmA+1ImuUSXR5IG+TSjZGi7NQ6Y2rZRBVytnUKGXw1LT9HQ0pBWOarWN28sv4F5HUb
         Be01ULCG8f43MS7b4PvPazNkOltlNDQhJR2VlPBFq9pD5OyqkirLlN73bnUnAa5xPjcL
         cpuN9LtAb2iJmh1EjVWk8OOL13rdjQA0iaPLEiKzf3cwTRliq3yi0jV4Xb9LuUBnMggZ
         +YDxjMCufI9bCoiLZD+Iezlm+VMjU/Qxchv7B3U/H9mLJJ1jZDQ19ITA7KquiHrkrpIN
         eKww==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from;
        bh=eLx+NEPB8HzONShpkleml37uStgjGAx++ZfA4d9OQqM=;
        b=BWNAFMW4vwPG916Rc4D16S1frsE2pbdKDQtzE5eiDsdpy1BjQx5bRo+GTL5mj3R6oX
         tVqwnjMd4pw6GhbU8pJq3zLvFGeclPRUXs4qgkXiSo2RRg1zyAjyYsUW9IwxAqdHiDdT
         3U1bW9amSBZRUL0bSuI3QwAFd4gXLdUi6A6ICDJ4WdzfSjBMDUtp8pR+G35NDRZLFnGc
         TlgYMVKABmwlYNwxtse6hdolSyoh8Zn0M+6/J6PxDFYPMvOZuA5YDwzwE/bXr8Ad06pp
         U3TqnNIHdojC3ED8TFVgVlwu7I22jmNKLFxbMI30TFouDw9xSJpsXfKC7nxLd1uJwfE+
         DxGA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=7ptk=af=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=7pTk=AF=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id l9si1140146oig.0.2020.06.24.10.46.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 24 Jun 2020 10:46:44 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=7ptk=af=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 203497] KASAN (tags): support stack instrumentation
Date: Wed, 24 Jun 2020 17:46:43 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: changed
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Memory Management
X-Bugzilla-Component: Sanitizers
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: normal
X-Bugzilla-Who: andreyknvl@gmail.com
X-Bugzilla-Status: NEW
X-Bugzilla-Resolution: 
X-Bugzilla-Priority: P1
X-Bugzilla-Assigned-To: mm_sanitizers@kernel-bugs.kernel.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: 
Message-ID: <bug-203497-199747-wx0jNj7mV4@https.bugzilla.kernel.org/>
In-Reply-To: <bug-203497-199747@https.bugzilla.kernel.org/>
References: <bug-203497-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@bugzilla.kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of srs0=7ptk=af=bugzilla.kernel.org=bugzilla-daemon@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=7pTk=AF=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
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

https://bugzilla.kernel.org/show_bug.cgi?id=203497

--- Comment #11 from Andrey Konovalov (andreyknvl@gmail.com) ---
This won't work, as there's a number of functions that are inlined into
start_kernel(), and we'll need to mark those with __no_sanitize_address too. We
could disable instrumentation of kernel/init.c, but it seems quite harsh.

-- 
You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-203497-199747-wx0jNj7mV4%40https.bugzilla.kernel.org/.
