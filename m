Return-Path: <kasan-dev+bncBAABBUESRWJAMGQE2JV5I7I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3b.google.com (mail-oo1-xc3b.google.com [IPv6:2607:f8b0:4864:20::c3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 3FB434EB30A
	for <lists+kasan-dev@lfdr.de>; Tue, 29 Mar 2022 20:00:50 +0200 (CEST)
Received: by mail-oo1-xc3b.google.com with SMTP id q1-20020a4a7d41000000b0032404f48373sf11511646ooe.11
        for <lists+kasan-dev@lfdr.de>; Tue, 29 Mar 2022 11:00:50 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1648576849; cv=pass;
        d=google.com; s=arc-20160816;
        b=RVa6IQ0r6q6Z+Ojs2Rm6zJLpo5+eIRC7QGE4CHhES5YYg78lwWrHnfgjZ3NPfSxBPj
         pIatr1ABfIAqfW8Sl6vPxCDmAbvbkBisso/3+vFOXzCivXkhNOAfELGtjb82kD3LOoRO
         /2eqQZ5VVq4aFvdj8RhPN3v869TQXYD4b+zKHsp2WTVUt7PMZQhgw67voRr9N7DnipYa
         4a7Ljq3mBGb2lKxpKs0l7cFgRZXbGhiBBTGu/diOK5b+Gli0goUaQrMxoU0Uh6O/BGhr
         3i43VKueKSc/WAIkN0nWxOzZekBta+ET9CW8lKOt7xnLFlo/vBMAcSYMQ6lt0B5vQgCn
         So7w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=3tU1WBoWLaEQS5cJPKcVXe9LHdiLCtWXWh0AqBZyUY4=;
        b=rv8XRPnEe9EGUOIgsI7AUeworGWFs3FXNwL8PbP7aC+9B+DM8U/MMfukyeUu7JG+ze
         xBPnJJKeKQyWHhknHcFpQmdqc8bImGm0O9pYXKaMCo8CUuprPRJtc7+VNRCSY/KJq3oQ
         tDJ7mKdr+sP6SLxkroys1ZcVirwvv787XFV5AOTYiZGeWAurkAozXGrBAW75BEbocBC4
         kXGDhbmRbrntgAGJZ98sCjucBHHUiKwrLY5w3uH5adSXLSuIJVlfmjfAnw+aTk0P9s/w
         DE/VO+wmjNVMi3v4xgcfYWN6QYh2Wu23X4RTz2itDqWsipgqvp7DGbyIW/KF6wqn6tqw
         +iFw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=SjSc1Bqv;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:subject:date:message-id:in-reply-to:references
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=3tU1WBoWLaEQS5cJPKcVXe9LHdiLCtWXWh0AqBZyUY4=;
        b=DbqAmqLfSLJh2zcgHohzTIxUt6pwc0hJ/RFxtuqv5Y2Wry8biUQsV6uJRi8gjM4Osk
         ecYuIjh5v1/jkHJRuLEkWaVTN1lwmRXg25TyD8FPKa90q+UlMcabl9IDlvW7oudl7IGZ
         BdX00Mn+NmJn07mFdJuf6d449MUdLJE4uKQ7rcYOoavlIIeTsIcHJ+no8FKkQSidqo39
         FP9mvDL6zxALg9g5iE5OEHoH7I49f2c5SNhDXUFGo7Y1hbOEm3nnuQk2ujli/JhtLF6L
         KU1w9CWHlF7DpAZ9XJsEiujVhUbBmQmg3yWmrkHwhOVJHnF4XM7Q4Fs8xAyV0bPV0nFP
         vrhA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :in-reply-to:references:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=3tU1WBoWLaEQS5cJPKcVXe9LHdiLCtWXWh0AqBZyUY4=;
        b=D2wRPn3iKg8W/1jGdGpaPXp9Ic3Q79DGq79OpIZOfCs6zjMb85WhNJ9H3axtYV80wF
         l0xVWhmrVV8Xlm+6Km/fCoRsEDasz3m9Yc93Uy4y/o7GrHV7Ep55NjABM2KBr9wQcX2j
         2YJ7m/oN5cjZIvrckT2CcL9sd8w1jsuCD99lRSIkVImhDQx3uxB1dhCYfFZdNPGo8sxZ
         2yScooIuyPj2WQQkvtqiCiQBXT1Zr1YdrDpHlziH7bvxNpmkDKnpQceURXohLEO0G8l1
         FxjZQ3PX0TVAkuwWWBIf66yI9JvPm0wMqWHPres4DeKfUqGMh9DD51rGmeLUiZ57c3yI
         FcuQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533BXiOw3icQs4irULIMhCqi/IJnzG1bKNqRRlV+akcT7gMKYRlO
	aBRs8CApIbVG0M4C22ov4KM=
X-Google-Smtp-Source: ABdhPJwk0NZ/dYrG/9s5z0ZZTDhRNaAeQqMdNRXNzhk7teaw0xiTSagTUobWNkQweLK+v4xL8UiGXw==
X-Received: by 2002:a9d:136:0:b0:5cd:9e9b:4872 with SMTP id 51-20020a9d0136000000b005cd9e9b4872mr1664334otu.192.1648576848758;
        Tue, 29 Mar 2022 11:00:48 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:b387:b0:da:ea30:ee8d with SMTP id
 w7-20020a056870b38700b000daea30ee8dls6521511oap.0.gmail; Tue, 29 Mar 2022
 11:00:48 -0700 (PDT)
X-Received: by 2002:a05:6870:17a5:b0:d4:164a:a1b0 with SMTP id r37-20020a05687017a500b000d4164aa1b0mr221165oae.74.1648576848413;
        Tue, 29 Mar 2022 11:00:48 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1648576848; cv=none;
        d=google.com; s=arc-20160816;
        b=IEQr1SwBOOMLnEkaz337+CQUeTJ/zXR+q7Xuckf4keSWUU6M/tlsnqx5gSq3Dv1vIO
         7toFIberQrcDP6lDyz9awYg7lQmjvRhO7rLrncbBIGDHHZ2RLu8fcCVN/UCmTJ9cSJrW
         lMC/izXpSForamK2VgIJMVx9ryoApxO7U+5yT29BS1k/WQZGRsCYPXP5hz6MWZWtwBb1
         Qo8KhaiLbnh9vK9xCsmie/syw2F5vSr46NtO33nL+8zBt79fjsvMPaCsYc/f03Q7Zw/F
         uEPplRQqNJWD/6+E7CG/8TZzyL1j14w8mNFDTpVa+1FxIhdaVwbB2mNKXp+oZhgJCyjE
         j8UA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from:dkim-signature;
        bh=lbqQE679BW1MTFdYrvegH5AxiPlo/Wb7YYltD6UOS1o=;
        b=T39HjwKvxNqi1rs0X3WO2veWzoHbi/38Z6dsQBtcStlJCIgwVrKCz7ie6HXjfarboC
         dtXZ6lprMEDE+3rn/lVuG4eD8d4rtU1yaHO272MJS5waO5pSKQ2x83nHTVGULfWtXw3z
         zZjbIowX8HpaJEUuRWGvfO24h4pJAdz9fxYRZA+CF6oZg6YXKGVvqHdCwnx6E2CfQwJF
         gpkvIPebE60PqCJ96LYnOIfrnJ2u83tXrTb16bez84AfqvjEyuvy8Yw9zNYJvHv4BtDg
         PyH2DCugXL6fNBDFVxMu7JiwK1s+d2tEk7loZqzhMhw37rIdYVYInvbP7+vrCj31+z10
         gCsg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=SjSc1Bqv;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id y19-20020a4ae713000000b003215b384eb1si1135218oou.2.2022.03.29.11.00.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 29 Mar 2022 11:00:48 -0700 (PDT)
Received-SPF: pass (google.com: domain of bugzilla-daemon@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id 2D8CB615B0
	for <kasan-dev@googlegroups.com>; Tue, 29 Mar 2022 18:00:48 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id 92B0CC340ED
	for <kasan-dev@googlegroups.com>; Tue, 29 Mar 2022 18:00:47 +0000 (UTC)
Received: by aws-us-west-2-korg-bugzilla-1.web.codeaurora.org (Postfix, from userid 48)
	id 73D0FC05FD2; Tue, 29 Mar 2022 18:00:47 +0000 (UTC)
From: bugzilla-daemon@kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 211877] Make "unregister_netdevice: waiting for dev to become
 free" diagnostic useful
Date: Tue, 29 Mar 2022 18:00:47 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: changed
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Memory Management
X-Bugzilla-Component: Sanitizers
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: enhancement
X-Bugzilla-Who: andreyknvl@gmail.com
X-Bugzilla-Status: NEW
X-Bugzilla-Resolution: 
X-Bugzilla-Priority: P1
X-Bugzilla-Assigned-To: mm_sanitizers@kernel-bugs.kernel.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: cc
Message-ID: <bug-211877-199747-FOrvuhPuQ2@https.bugzilla.kernel.org/>
In-Reply-To: <bug-211877-199747@https.bugzilla.kernel.org/>
References: <bug-211877-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=SjSc1Bqv;       spf=pass
 (google.com: domain of bugzilla-daemon@kernel.org designates 139.178.84.217
 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
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

https://bugzilla.kernel.org/show_bug.cgi?id=211877

Andrey Konovalov (andreyknvl@gmail.com) changed:

           What    |Removed                     |Added
----------------------------------------------------------------------------
                 CC|                            |andreyknvl@gmail.com

--- Comment #2 from Andrey Konovalov (andreyknvl@gmail.com) ---
The patch was merged [1], this issue is resolved, right? 

[1]
https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=5aa3afe107d9099fc0dea2acf82c3e3c8f0f20e2

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-211877-199747-FOrvuhPuQ2%40https.bugzilla.kernel.org/.
