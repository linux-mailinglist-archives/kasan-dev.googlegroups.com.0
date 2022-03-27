Return-Path: <kasan-dev+bncBAABBA7BQGJAMGQENCGWPCI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x237.google.com (mail-lj1-x237.google.com [IPv6:2a00:1450:4864:20::237])
	by mail.lfdr.de (Postfix) with ESMTPS id 060C54E87F6
	for <lists+kasan-dev@lfdr.de>; Sun, 27 Mar 2022 16:11:16 +0200 (CEST)
Received: by mail-lj1-x237.google.com with SMTP id v6-20020a2e9246000000b002497a227e15sf4691133ljg.4
        for <lists+kasan-dev@lfdr.de>; Sun, 27 Mar 2022 07:11:15 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1648390275; cv=pass;
        d=google.com; s=arc-20160816;
        b=iRLLmAD64nf44Pa21RFzPEmsZijdZHpPz69/F3qwXPGx6h3gq7QtRnmzAzx1b3daEq
         4vIARhz2689uZEWAAwDdVxxz/ETqPPztUhrQr2lSNe2QXM2cY3cJrxdEFhXGD5xf2cDu
         JGn9umJG07TsdYxhcDcWdLXS02z/wviYq4IOKjwwaU1h0+Do+46UHEIFXc/4SeGNU4Qf
         Orehuni5OIf4ydR4OiaBiDIvATvTDnwbtTn4AgtTc6UMe9IWwGZa1+xZV6yjf2/ilyq9
         1JQFu4ysi1rr5IEKL1ORwqxvGevAVbdBbzFmsFBzpiOdeaRsh0NKZR3XpqcSRIywQicj
         twwg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=Bxb24LBQjznTowOQqsj0Ba2UR0oca/c7mvS3Ip2anYA=;
        b=xlFen7bhEKV0V/FgP0yngF2rTXwAzQSLJHYGX55RptwXxHHJ0cyOYtM+uDRHnJT1PQ
         ttO2pXWfJrbiqn2+m60bXqM8nXytuvtFpltzWTN6olIpWQHTu3bZAAnK9heI73XhP617
         gEH+v3AzzTsseod2j+CT5QyLzRxycQyshx7zEzuuCLp3RcrpAqM9oY6VjwD+wTYI359P
         RMaVdUKv3pX5QmEM3WJRslPFoUx50ESmHEcFYXSo1/o3hNNtpG4fUP87KPJ+BZklVQ9f
         x0CqhSDzOreow0/j7jFzaTofQ9g+cT7n6WJta0/DmYhxqz9DMAEgkwFxG2PdqrtfWDE9
         JneA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=hL0k5S1E;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:subject:date:message-id:in-reply-to:references
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=Bxb24LBQjznTowOQqsj0Ba2UR0oca/c7mvS3Ip2anYA=;
        b=nLW5ZY23DwTfmidPWHXGqJrC2X+BOCFyAQvIb3YSUXpNrGn/WVUGkDe6T5JzfW8ucj
         R2FmEVeguG9TW8AYOMrG1f++sJSgh4OcQUABZ6GCIsJBpGz4IIkP3fofNFC1FwgSCR9x
         k/MXEpnqrSM387B0nT9kdUZ0qfZ6dum54LMrm8lO4SsZ0wvwuXAv6l8bYmChNaFqkiAZ
         hl3I+CUteMw0QfOcg4GyitBpiy3mB1jm+IlRw2Ra8IBshEEG6095L84G+O+VAeJlQiwQ
         EtMT8bn2zlXszKV7sNEAZt33r3cd2ohN1YX/pVwqiwEczp9lnNnxK5JdIeAGMFmXCFG0
         iEwg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :in-reply-to:references:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=Bxb24LBQjznTowOQqsj0Ba2UR0oca/c7mvS3Ip2anYA=;
        b=hWpujAgvGwKz4Tpbfb3sqK7tparyhShnz4NPIljBy2J+Y18J4hvG9l1tJ0QbidG9Af
         P1m9rNFl8F5erA3VWIRJotEgTwB3WpsxULWVe69QNmtfLDvkvZmksmf97s5w4E1vogFR
         c8Wr5Uj4DscDuNl6MzgcM1PY8wB3odU124MoL2P+JCW6kYxCxvR8ls5TI+ViomqbIHY9
         U20xXfWTQR2mCl2z8YRGwg9DEgLC0PPEfP+lXasmigFyCYeQkTX8wIHhHwmeN6eJcEtg
         qrWSfWcRfUlX3vLTxNNS4oPWsrhPb2EsBlkEDrHPAdQlPrUsa/hUtJaesioINUPxnaDT
         h+Zg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533ILdgfZnwgS5jDlrrKsDZ6SBMHjIfo4013DHvm8nBQK9zbceDz
	oyRJlaJteCM5d1THiLXx/98=
X-Google-Smtp-Source: ABdhPJw4Z9T7wLcg1+B6RvS7RVr2VBgbT1vGDs+wfvw410EYAbfrjSXu/YYEJzJvgBQvNLoOI1dXTw==
X-Received: by 2002:a05:651c:515:b0:249:8d1c:5af6 with SMTP id o21-20020a05651c051500b002498d1c5af6mr15834286ljp.51.1648390275363;
        Sun, 27 Mar 2022 07:11:15 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:90ce:0:b0:249:7e33:4f9b with SMTP id o14-20020a2e90ce000000b002497e334f9bls699209ljg.0.gmail;
 Sun, 27 Mar 2022 07:11:14 -0700 (PDT)
X-Received: by 2002:a2e:a58c:0:b0:249:b1ce:ba97 with SMTP id m12-20020a2ea58c000000b00249b1ceba97mr13571954ljp.78.1648390274518;
        Sun, 27 Mar 2022 07:11:14 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1648390274; cv=none;
        d=google.com; s=arc-20160816;
        b=mIJtUIdHsvr09VwtNyTULxpObOAhP/Myvp65QnJMngKRFgsIDvvI26kXGxxijUFls0
         8/KuGQHvTGeaLCMqORX4P7dbNDsk/8e4KHEvra8H3ShyGOA7rSQ/w9XNYBYUK6dF1HkZ
         9H2l3l8LBygIM7hNsAwTVrulTDIBP3onrqAK/bAj4nGPoRDWmP8/ESHRYzDLXK4m/0YO
         M8k5PyFknPRikT0vJ0onTIZyyC+/7jXdr4PuYPjxgrCZfhx5rl7sNOJcbOvPEmBGNOWR
         xH3UpM3euofPBcsuD7qFjVrXVsOq1IF7yu5wy2gNhqdddRyrNifKB7XkGPb5XX+ikFNa
         SqLQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from:dkim-signature;
        bh=FhLOH5tr5xB6p7KWTxQ/bohPJsR+ySjE/SYKODTUBgE=;
        b=bAlqTU+tZyqm8+PUrHfuex7h/rCbmlQSa+A9YNlWHkEnKifo9rcGZCdUOVWpM72s8l
         ExCBLURd87/G23sPNO7jDJQdD8X8/a31zbZ/BMZYlCAaL5ul0SU+Al0f6M4/4/e7t2TJ
         kqnbi+B7bjQkbOVXFaoPJySnSo5/XxPphv13HYFgWHgSfYVMRtsaqZ/QGnzRSjNzLtp0
         rOJpufaV+8dKH/v1B/m49aZ3e0zciCr3pVmoE3bBIOvjvr29NjzBtAHov/cRqm7Q/glO
         gP3B0og1ryB+imUl30GF97I/kIB8w6CEy4QDxL0HJ617GIi4R78xYWuA2BuAKtrHDPMA
         Ukvw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=hL0k5S1E;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from ams.source.kernel.org (ams.source.kernel.org. [2604:1380:4601:e00::1])
        by gmr-mx.google.com with ESMTPS id b19-20020a2ebc13000000b00249b9662730si288448ljf.3.2022.03.27.07.11.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sun, 27 Mar 2022 07:11:14 -0700 (PDT)
Received-SPF: pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) client-ip=2604:1380:4601:e00::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by ams.source.kernel.org (Postfix) with ESMTPS id E63FDB80D0C
	for <kasan-dev@googlegroups.com>; Sun, 27 Mar 2022 14:11:13 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id 83827C340EE
	for <kasan-dev@googlegroups.com>; Sun, 27 Mar 2022 14:11:12 +0000 (UTC)
Received: by aws-us-west-2-korg-bugzilla-1.web.codeaurora.org (Postfix, from userid 48)
	id 68ED5C05FCE; Sun, 27 Mar 2022 14:11:12 +0000 (UTC)
From: bugzilla-daemon@kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 211775] KASAN (sw-tags): support CONFIG_KASAN_VMALLOC
Date: Sun, 27 Mar 2022 14:11:12 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: changed
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Memory Management
X-Bugzilla-Component: Sanitizers
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: normal
X-Bugzilla-Who: andreyknvl@gmail.com
X-Bugzilla-Status: RESOLVED
X-Bugzilla-Resolution: CODE_FIX
X-Bugzilla-Priority: P1
X-Bugzilla-Assigned-To: mm_sanitizers@kernel-bugs.kernel.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: bug_status resolution
Message-ID: <bug-211775-199747-LEiP1AuqnQ@https.bugzilla.kernel.org/>
In-Reply-To: <bug-211775-199747@https.bugzilla.kernel.org/>
References: <bug-211775-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=hL0k5S1E;       spf=pass
 (google.com: domain of bugzilla-daemon@kernel.org designates
 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
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

https://bugzilla.kernel.org/show_bug.cgi?id=211775

Andrey Konovalov (andreyknvl@gmail.com) changed:

           What    |Removed                     |Added
----------------------------------------------------------------------------
             Status|NEW                         |RESOLVED
         Resolution|---                         |CODE_FIX

--- Comment #1 from Andrey Konovalov (andreyknvl@gmail.com) ---
Resolved with [1].

[1]
https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=f6f37d9320a11e9059f11a99fc59dfb8e307c07f

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-211775-199747-LEiP1AuqnQ%40https.bugzilla.kernel.org/.
