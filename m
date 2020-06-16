Return-Path: <kasan-dev+bncBC24VNFHTMIBBYWZUD3QKGQEOCFNF3Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43b.google.com (mail-pf1-x43b.google.com [IPv6:2607:f8b0:4864:20::43b])
	by mail.lfdr.de (Postfix) with ESMTPS id 9E0961FA665
	for <lists+kasan-dev@lfdr.de>; Tue, 16 Jun 2020 04:22:27 +0200 (CEST)
Received: by mail-pf1-x43b.google.com with SMTP id r198sf10130572pfc.19
        for <lists+kasan-dev@lfdr.de>; Mon, 15 Jun 2020 19:22:27 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1592274146; cv=pass;
        d=google.com; s=arc-20160816;
        b=wnScOJdFazQ1T3piankG1ErwOHH+xAZmodTmj/p9fCJZG3gILR54z6PE/7nBtBiJFz
         WEIzmVej/GWGKznCP2bb4D2FjymdCJXQeji/8peDBV81N3d/IqfRZ/2IBJWXviviOB9F
         qnxCOoHd4WamjCUxjalutZcPgEn9qUgQhS8xT0BRMJHkKR7K0XUpzEa/cm3/+t9tOor8
         qYL/rSdjx297uOIx+ninJoHtQB/BJFt3GFxSFr014Xbi2GdKh09A/kjBe8ORIm1ZWyfg
         Hkw7wCenJim/ardxJy15OrV0TAsYEff7YZ5m8SkuANDwmGku1XqlSREs+T86yPSqhHYd
         rvxg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=tvAoxwzQVjitxa8ZVephUhlxEo+n6g+VqdO+aSVyDmc=;
        b=rXNHXuM51xNwDi60KCXku1Pl0622wjiEUCvkKxAQY1cTmNX5cjIYSB09lHZ7TVOGdi
         glghm7rcZG4xKIGLOj00cRCDZjc26u4jB9fJRytLmcPECLvBtzbV1TAX4YYI8GJpqa6F
         0FdliCPdp8Udx5XxzPMpb5S2hp91ObFJiA/+t1snjIqZreidhrcHEUnMJkt8ILQRO/su
         IUCxspoMfrZ3pWcBySFpytqkzs4r4NCvMnLpuSI5R2A+cS9X+UymgColzAV84gTwlUy1
         MGS0WzHgpsQtRp5ndRZN8JsKy78wYthUxqXd1v9iZSAyBug94iujmtVCGmXtN7O3j23Q
         WriA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=qzwx=75=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=QZwX=75=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:date:message-id:in-reply-to:references
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=tvAoxwzQVjitxa8ZVephUhlxEo+n6g+VqdO+aSVyDmc=;
        b=YJtbiWyI1xWZoOxI8MpD8+e4X8RANeh2X65aKyHC9/Utr83qV0jsKyE7nmKBbf5Bdg
         3QbJrDoTC+W9+qYM7AbMP6TFyc7HkRqpvkWlCwlEOMTavBeRAuUoaajzMgqyMpCAmXEE
         prX6UJHzjADIwKdJEG0/T/2OM/bHN4fBFewNvC6JikslKeWJI/g/N9T8wFClvqp8UXSy
         T8VJAM6V6iW5zlgUiKPVMfFP9ehecK6zNweFfaBC6vTUBXwu6qN/3323PaYdShfpvLOh
         z2HGOqX4dDEeWdL1Ly69WhTSBim6s9GSD2L8eMqp3IPIviXaKNFFh60zg0u/2xfD+tUt
         KJ8Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :in-reply-to:references:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=tvAoxwzQVjitxa8ZVephUhlxEo+n6g+VqdO+aSVyDmc=;
        b=RZaxvsn0jGJ88dw7mltUtSzGqPfuZzdKw9r6524YobdpvfAoz5eAj8/EN+ktcQzncQ
         Oo3JEl/i0wnzw+Nff9ZsA+oXoECBia9+0xyzm4z2KD6DNG2F145gfDcbs5WLzwhwzHxl
         CnGiQJzKqnp8Li/ATdhI2qjCCDqpW1IWqUiD65v5r9pJtm3H45Cp5UzcNWpSxFR124ov
         2vXaIt5z+oeILgsivYE+Q1y2BXKwJNurdBltaOVZwgIn35n465RBXqc5ddQ+SdE2rKLd
         S/S3nfcfRotn+a/BE6UOvuxx+xhRlwxsVctAbIq3iaFaodGyp9b//iroLZDzTYAMhUoH
         HIKA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530Sv9CWtSjCGMBa9EqI1GVsPOy1eduFDncZ2CA0G5TsFVHyoA2y
	D6VmEJNFJFfAaA0uwyvzLYQ=
X-Google-Smtp-Source: ABdhPJwLeE/LKNT4oWC7O6IO4teWyi6TKY6FBD9QV6169IQTQbPpV0hVghGI3w9jIdACYCAX8eI/OQ==
X-Received: by 2002:a62:4e91:: with SMTP id c139mr118325pfb.18.1592274146339;
        Mon, 15 Jun 2020 19:22:26 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:9007:: with SMTP id a7ls3498988plp.3.gmail; Mon, 15
 Jun 2020 19:22:25 -0700 (PDT)
X-Received: by 2002:a17:90b:3746:: with SMTP id ne6mr613461pjb.166.1592274145881;
        Mon, 15 Jun 2020 19:22:25 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1592274145; cv=none;
        d=google.com; s=arc-20160816;
        b=R/UAkxwwiZsGdj7d32UdHViZsLohYAIw9jVd/vPqGcnI4kmG6iXThesYC90rZKZnBA
         25gcE9YXYadmhl/Flj/yyf+0pYmVj2rIoP2NJlzYUKebrXOUVHieo+oZ6DlXqEB7JakR
         eC0LvKLFha8IpxaBUENp9FmT90d+LyFNA38UdMh+38bLNdyd2btLxXpvcE+r1eRURWuD
         hZ3FCq9r/4QPALxM2kgmLy81tMYfIyWE6/OjOeN6Aj7ZjzMoEIKc5nI1UV90NGY+yhcs
         /YIGUSbIOAGZMAl5Ri2+YB+bqJBAKWaCjpXRHShcvlrimEPUTc8xnqUAt+scj4kFQpR1
         be2Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from;
        bh=Yg5X6IGGcYmJXnGJKKTK8kh1XPLe8XAzwNCxWFgJ6/Y=;
        b=wsFCY1qpvtq9Fe2kUcwTuYs+BZWCWfb3Apqml3J83kKp42LBQk4GbHagyjICoAWvAh
         wsaySeGBuC5Q/ykPMwTC/PfgjAjfBxZ00w7P72c/a7Lt3qem/OCUUulyIo2fhJ4MMnfS
         Sp92TImWq90d/4v+otEBgCAANxn+AuOzZcz1CvR8WHSytfVYsVuZjfPzct3quaQ4ZkK5
         +Ayr04RWBpp5oPerhM3dtBgnIxQF9mWq06ieKi56Dx9neKSe0sh/L8yZaGW/o0r3RKvr
         Trqw2SX2Pfd6/peWHHeuO2YzJRQK83ymfxN7xoQXAkuR3XbMLtekNHkIndwM7q+mGgf3
         /Xlg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=qzwx=75=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=QZwX=75=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id v197si1091810pfc.0.2020.06.15.19.22.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 15 Jun 2020 19:22:25 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=qzwx=75=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 203497] KASAN (tags): support stack instrumentation
Date: Tue, 16 Jun 2020 02:22:25 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: changed
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Memory Management
X-Bugzilla-Component: Sanitizers
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: normal
X-Bugzilla-Who: walter-zh.wu@mediatek.com
X-Bugzilla-Status: NEW
X-Bugzilla-Resolution: 
X-Bugzilla-Priority: P1
X-Bugzilla-Assigned-To: mm_sanitizers@kernel-bugs.kernel.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: 
Message-ID: <bug-203497-199747-NiqdsJu9tC@https.bugzilla.kernel.org/>
In-Reply-To: <bug-203497-199747@https.bugzilla.kernel.org/>
References: <bug-203497-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@bugzilla.kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of srs0=qzwx=75=bugzilla.kernel.org=bugzilla-daemon@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=QZwX=75=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
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

--- Comment #3 from Walter Wu (walter-zh.wu@mediatek.com) ---
If I understand correctly, I originally think this issue can fixed by adding an
additional instruction "bfi x20, x1, #56, #8" after this instruction "and x20,
x10, x9". After this modification, x20[56:63] can get the x1[0:7].  Its purpose
is shown below:

1) x20[56:63] is pointer tag. It will needed by 3).
2) x1[0:7] is random tag, it generate from "eor x1, x29, x29, lsr #20". This
tag will store in shadow memory. It will needed by 3).
3) __hwasan_load1_noabort() will check whether x20[56:63] and x1[0:7] are the
same.

---
assemble code:

ffff9000104a331c <kasan_stack_oob>:
ffff9000104a331c:       d10203ff        sub     sp, sp, #0x80
ffff9000104a3320:       a9067bfd        stp     x29, x30, [sp, #96]
ffff9000104a3324:       a9074ff4        stp     x20, x19, [sp, #112]
ffff9000104a3328:       910183fd        add     x29, sp, #0x60
ffff9000104a332c:       d000eec8        adrp    x8, ffff90001227d000
<page_wait_table+0x14c0>
ffff9000104a3330:       f944a508        ldr     x8, [x8, #2376]
ffff9000104a3334:       ca5d53a1        eor     x1, x29, x29, lsr #20
ffff9000104a3338:       92ffe009        mov     x9, #0xffffffffffffff          
// #72057594037927935
ffff9000104a333c:       910003ea        mov     x10, sp
ffff9000104a3340:       b3481c29        bfi     x9, x1, #56, #8
ffff9000104a3344:       910003e0        mov     x0, sp
ffff9000104a3348:       52800a02        mov     w2, #0x50                      
// #80
ffff9000104a334c:       f81f83a8        stur    x8, [x29, #-8]
ffff9000104a3350:       8a090154        and     x20, x10, x9
ffff9000104a3354:       97fb24c7        bl      ffff90001036c670
<__hwasan_tag_memory>
ffff9000104a3358:       91004693        add     x19, x20, #0x11
ffff9000104a335c:       aa1303e0        mov     x0, x19
ffff9000104a3360:       97fb2466        bl      ffff90001036c4f8
<__hwasan_load1_noabort>

-- 
You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-203497-199747-NiqdsJu9tC%40https.bugzilla.kernel.org/.
