Return-Path: <kasan-dev+bncBC24VNFHTMIBBWGHWHTAKGQELN665BA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x838.google.com (mail-qt1-x838.google.com [IPv6:2607:f8b0:4864:20::838])
	by mail.lfdr.de (Postfix) with ESMTPS id 3C1A71317C
	for <lists+kasan-dev@lfdr.de>; Fri,  3 May 2019 17:52:57 +0200 (CEST)
Received: by mail-qt1-x838.google.com with SMTP id o17sf6416179qtf.4
        for <lists+kasan-dev@lfdr.de>; Fri, 03 May 2019 08:52:57 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1556898776; cv=pass;
        d=google.com; s=arc-20160816;
        b=L7BkSeEW2LNkfMTAmef4c9eocL8bscy6yd7TRqIET72BCrQCTdFI0a8sn86mFNA80Z
         hx8znaE0cFQdWJGOLsujhDtBkOjDk9lLfB35yLOxapeWnoGNgzVlQiGeIA6Z2b0xP5jh
         nPb2GTC1dfVboyphJ05J5ngC9JEb4Yw5AtScUSrtobMO/e3Ada5NZ2XJj3Sn2Yk9QPBt
         +4YBrB1F+Javite2f8tjngy9Svzn65vRB+g5sRyfwLo5S31q1ohtQVEVNEXmpWA1kl7k
         QJ4IdWhRDF3FSual10ADtRvfQHmaH5/t7hQFf/0RXjYJjYUHD1ty022s8Rjv3P/SPEb2
         Jccg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=wRZ3XaeFSeaqy1gPTrtl1DuJ0odjAp0Q6FCcjm/toTc=;
        b=L/I1n2zVQTvHKoSlTvcNiKzcKD7uZ7FwFr8OH4hH3uno064+SKrxeg6JRHsxv7ZsxA
         W/WQdsCGXMJsClZGSR9Ro94TvO7NwJmmrlOrXOwhkQvVqfCWic0BopYkUxNyanBA7arn
         2Gmh0G8r3G5j300LCtrHI/PpFustojkoYZYvNiowwhuglkhrX+y6evTYP7+kXKqqtvC+
         KVyxG9NAASFtDrR4YxARi+xdp/gLiiOXW2FF88fasa2+2zHtrfCSEn/DB4WesLMGIdrf
         sVKJ4J0rCrKmpTat1RG1SmL566c5YRwwOzgheyVa0ybZYZYA+ATAKdPl6Y2G7ZYjChYy
         xPjA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.98 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:date:message-id:in-reply-to:references
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=wRZ3XaeFSeaqy1gPTrtl1DuJ0odjAp0Q6FCcjm/toTc=;
        b=It21iMWczSBRXIdPnyLWu6+JocBg0mgEzAcfJ+EhpiXpl1/LM6x2ev5Ypu7gVzIX0x
         X0wAckP+ghw4fHU1FC+UA2k2+RmhwaXCPIsVLBfcooV6BGmKs7sjYJ325vTHnvZt2yRE
         9OERew9pQEPH0fyAFILm5GWB9KGfFlZDMHOrIk6ubR+CQx4nCJHuDe8vuY659xXPN4K6
         Imk18mX+tswCt3yQsXfquqIJYkNSXkoPjsjGUv92yguv5kOgNYIvxpELbHUDpQa2SAmc
         S4MoIG8O2Mpjdv33f5A8HCYYl69e1mscOXzgYnlDagyyFJHd3Im40RAaruaYIXdTIiZG
         zLqw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :in-reply-to:references:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=wRZ3XaeFSeaqy1gPTrtl1DuJ0odjAp0Q6FCcjm/toTc=;
        b=NPLi5ntWLoWZBA+fDiVdI8DKRxbd1ESUvJzjMC+0ZsiSp2O82GhsH+RgMAXeATN037
         4S9gku/1IAs9mhfw8J8qWIEl6LcoRHQu8xHQ/K57wtIFFLtc6gHUdy/cpcWNyV1k85aE
         aJJoXVnR+mVCHdf93MdtOKTu7gJ4TKAEHSVXsYrJbcL6GbG1iMT25deNVIbBYtxpFBFC
         rbFaV9EE7yzOWtSo0UOj2Z9sleQu0F5oe5BPV1qG0ZydXYVOfrYKsfmjK+4Gb86HtS4e
         HW5z301tsExh3lB0COQWBILVGeiGfyh5yV4/MAjpYP4UudhPKH4zdSn1S/goPFMs9S9q
         NFRA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAUj/M9oA6LTsqG7lFEGm0BhoGECtUCJh3dWLMM0/ksFM0xyIw1s
	IW2geIAfZ4idpU3Vn4nVqsw=
X-Google-Smtp-Source: APXvYqxD0xhoXUWVdsXUpDUm5Gpw8/fNI9gQqwJMqKl0TCYk82+gHNLoEfwa8fNOD8vfHh8vY8XAoQ==
X-Received: by 2002:ac8:22f3:: with SMTP id g48mr9054026qta.333.1556898776125;
        Fri, 03 May 2019 08:52:56 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:2952:: with SMTP id z18ls1407862qtz.6.gmail; Fri, 03 May
 2019 08:52:55 -0700 (PDT)
X-Received: by 2002:ac8:1c82:: with SMTP id f2mr9169477qtl.68.1556898775924;
        Fri, 03 May 2019 08:52:55 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1556898775; cv=none;
        d=google.com; s=arc-20160816;
        b=m3PesiN/eGvhdwsy0x0oizjtyrutxq1KNSFwI/fJLnyP6DrAM3bZpI8h/gxYAwTJ1k
         k5xpiiRq3Y0yj/ZgY4URJO7CBCo3dw3EOzJFUAT3eb0RutiOVxwAIKrMfirnMxq5TqDn
         IN6gUUEKznOolpISAgG2F79nHreh5ORnyAxVPDLn0cSewmZ6Q/67nlkucZF3sNlS/p2C
         JRYPf2IQ5ZCfvempN5C5Ycd2v1TkgpoGWMotsXGUBDsswhwnh0ZliuDAN5sY1LGE3Qkl
         VTYsLixefTpZ8yCdrkBxqS3ahCjmN/zJ1B12HdoQFz1Bu1QQxOq0DUFbELCwKL2+VA1M
         ey6A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from;
        bh=qAJPszRQiseyWj9GY0KUFiQzsQs8JlTgo6G+lquRznk=;
        b=KkN4s4vL0Uj0yXPwGKr0Ai8/ZKXEPKtcBcoklz4iIAlkCjYFv8Ew4gWmwruoE0WAEx
         +zXA7ZBlS+JXtQUaq1GYuhTfeO3fLKEKo27kbTVWeDTos0HaxXM531R+CWZTs28mgNeP
         xkp3Bc/jvlufLZohILw2EELV6xpbYEcflJwbM2pczxpmV6phOTGefJ742flswVkkFCK6
         U6tjOf8S4OJt2K53nUqiBIUyNcROZYKfZFvbYKWyZsW5smWRss21LawjL4uXc+uhY2iN
         DhXFhsWIWfNgjDc+BQqVEROGl5g1d/GgwYHrHybsID1Esx7GKiz2HCukYQN0w9pkxetY
         CyAQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.98 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.wl.linuxfoundation.org (mail.wl.linuxfoundation.org. [198.145.29.98])
        by gmr-mx.google.com with ESMTPS id x11si99307qka.5.2019.05.03.08.52.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 03 May 2019 08:52:55 -0700 (PDT)
Received-SPF: pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.98 as permitted sender) client-ip=198.145.29.98;
Received: from mail.wl.linuxfoundation.org (localhost [127.0.0.1])
	by mail.wl.linuxfoundation.org (Postfix) with ESMTP id CBDF828610
	for <kasan-dev@googlegroups.com>; Fri,  3 May 2019 15:52:54 +0000 (UTC)
Received: by mail.wl.linuxfoundation.org (Postfix, from userid 486)
	id C044A2861C; Fri,  3 May 2019 15:52:54 +0000 (UTC)
X-Spam-Checker-Version: SpamAssassin 3.3.1 (2010-03-16) on
	pdx-wl-mail.web.codeaurora.org
X-Spam-Level: 
X-Spam-Status: No, score=-1.9 required=2.0 tests=BAYES_00,NO_RECEIVED,
	NO_RELAYS autolearn=ham version=3.3.1
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 203491] KASAN: ouble unpoisoning in kmalloc()
Date: Fri, 03 May 2019 15:52:53 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: changed
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Memory Management
X-Bugzilla-Component: Sanitizers
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: normal
X-Bugzilla-Who: andreyknvl@google.com
X-Bugzilla-Status: NEW
X-Bugzilla-Resolution: 
X-Bugzilla-Priority: P1
X-Bugzilla-Assigned-To: mm_sanitizers@kernel-bugs.kernel.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: short_desc
Message-ID: <bug-203491-199747-WWdkpUHeKZ@https.bugzilla.kernel.org/>
In-Reply-To: <bug-203491-199747@https.bugzilla.kernel.org/>
References: <bug-203491-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Virus-Scanned: ClamAV using ClamSMTP
X-Original-Sender: bugzilla-daemon@bugzilla.kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates
 198.145.29.98 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
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

https://bugzilla.kernel.org/show_bug.cgi?id=203491

Andrey Konovalov (andreyknvl@google.com) changed:

           What    |Removed                     |Added
----------------------------------------------------------------------------
            Summary|Double unpoisoning in       |KASAN: ouble unpoisoning in
                   |kmalloc()                   |kmalloc()

-- 
You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To post to this group, send email to kasan-dev@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-203491-199747-WWdkpUHeKZ%40https.bugzilla.kernel.org/.
For more options, visit https://groups.google.com/d/optout.
