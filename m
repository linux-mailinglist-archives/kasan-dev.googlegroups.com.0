Return-Path: <kasan-dev+bncBC24VNFHTMIBBRU2Y3VAKGQEKFKPMII@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33d.google.com (mail-ot1-x33d.google.com [IPv6:2607:f8b0:4864:20::33d])
	by mail.lfdr.de (Postfix) with ESMTPS id 430488A2CB
	for <lists+kasan-dev@lfdr.de>; Mon, 12 Aug 2019 18:01:12 +0200 (CEST)
Received: by mail-ot1-x33d.google.com with SMTP id a26sf11104203otl.1
        for <lists+kasan-dev@lfdr.de>; Mon, 12 Aug 2019 09:01:12 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1565625671; cv=pass;
        d=google.com; s=arc-20160816;
        b=UVl90rQLO04c9FCLxOH/VsAUz4D6+qzkqCgcQrP2+siHV6irTWbtcpuwKCyFwHqtia
         wueIUPwPhWmUZ4CnUviZRHMClpEsDKbTTRrHfkZnBh7RUsFDH4j7iMQdypJkyKIwzaR0
         D/b9wCw+b9mjh/FUF20+j0Sv+kBG0OdfIPMuYpbHE/aTfRQkqzOK39850m98sKLJtNre
         jQYzRSL2wCtkxPzvlGCQgPSt64q9gNdyrQp1PTHhihq/REKg2TG55ogxLa3T7HAWLK9Z
         pjxoY5Ra7qelqgboi2fQMHPhWqwj/CsnMrZz2h7LaTcqPKo3DxHtbgB7tCzxiosOVDun
         ix5Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=Qmav5ZX4emrefrGqQDfeVR9cG+lPM18u0rqIMgQXDyA=;
        b=PF+vUarehVouSg6wt7v0UEgsrcC3NGonScgYoBAk9Ros/YZi7k2d+LegiuJ89XJIZa
         GBmdxqI9S7Kgo2o/B0HECNlgqJiWoSHQ3IeYiwFMZqmRFokxFGON2lxPV/Ys6V8T4XqO
         8fH2fsW7Rpg6FdB2NwZfh+cdgt9JGOT1YZUOIyngWONqr1vcEgIYmILif5zI0BJB7LvD
         uYsYzO9d2U9GxQB2Fbev1jCYyU68VdmXcUmkeaVjtsfch2SlBnRo/UFgi7vPgqUTR3QZ
         bu7v6YicMXjyqugVC9xgN6e0hdG7PUNCOnTDQj6C1VFHyp3cop3vJPPQyNqmftbmHlqL
         3wng==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.98 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:date:message-id:in-reply-to:references
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=Qmav5ZX4emrefrGqQDfeVR9cG+lPM18u0rqIMgQXDyA=;
        b=CSMXuQFLwBqRQ1vDXLrVBKpbxGaIrIr6Z2K/pGPSGvUFRraU9Xih9acsaGgCtq/DqX
         7W09+xUP2tr5IipIR/0kwMlMBSZ9Axyl9tqq32BtQn62x2DoK09DcE0F2HekiTJ4V7km
         w1qmvwjQybkLPv2dfOulrIem1A8O0tY6BjT51AfmJCrY0EltRTZHXtnteZfTLmbQUxGE
         fyQWkSyPru7SZOQ+rvv99YyOLPmS+1QeMrP/ZipwExhzxO+IKMGXYM2xZQKsP5j3PoA8
         ybXcbf+shQUk6tHFORGbiTkNaCLwNZTYZYa8e0gsasf43RuEfzScnA0QUuZ1hUFPghA+
         3UKw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :in-reply-to:references:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=Qmav5ZX4emrefrGqQDfeVR9cG+lPM18u0rqIMgQXDyA=;
        b=TOhGQE0bXXYODU2alUqYqM10yiKOOpxpbVqvBmiBLVlHncCo+aDX2Jrzp3Gjo2FAKD
         RCGI9XCTwtPlX7o8I0/QjSjfqs+YpmQUbVrsKvRr4TdTS12Uljrm8eAWnN+8kM+Wna0R
         Zy6VZtZxbjwEeJHjiiHx3RTUS5tDtstjeb0jUngBTDc+Xgvk7gkuYs3B3+fWsCtPyeJ4
         kf07plLcJzxLdKTHDH7NjA7D5avtxfop8OlYyAd7rt713BuqdJYKYfEFI6BTmgpwyGp6
         igya/SJWijK4mG09pr0AIhe2wPon8qTNtaT6hTvm3NHSdpGnN27As8mKT54WDHzzt64r
         p+Fg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAVAijeNC4p8l43d6BuIl/1abql5kpSaFxSl74hR4p3dwEkLOPOI
	TURxlQ0zSLOioV8MV7n3ujA=
X-Google-Smtp-Source: APXvYqxgP0W81wLu8szTM5H8x4ei+NdhPvk+6KeVHNjO+yDdyqYq3mt4I0F+jy5f1X6bGI8ci8bKew==
X-Received: by 2002:a9d:6256:: with SMTP id i22mr845593otk.139.1565625670961;
        Mon, 12 Aug 2019 09:01:10 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:71d0:: with SMTP id z16ls1247832otj.2.gmail; Mon, 12 Aug
 2019 09:01:10 -0700 (PDT)
X-Received: by 2002:a9d:7e83:: with SMTP id m3mr6868610otp.356.1565625670612;
        Mon, 12 Aug 2019 09:01:10 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1565625670; cv=none;
        d=google.com; s=arc-20160816;
        b=sp+ia9n1KrXDmhRk3rIeQPhK36zs3vpmf1H8DXVMVFtrayeqwKLHV1X+t3+M8kGzSG
         hawP0JTdLehq1eek/+XUlHg0NZbg0FE8I60n8ArX29kJIz7jX5vvWYP15pT8nLgpN2Ac
         2PRMIlnseoipFrb3aa2ISw3RGLG5gk19sx+aZy6soV3XHNuSXq2yLDHQSsP+CxdwItze
         JzicLim2IOq7LRLCzdmo6CT0knmj0OltIbW/DqLhKvYP+4kx9Kmr7wQ0OZhOXaFx7yMd
         e/BJLKQ7HCvmp3Kg95XAf6YqHqzGnLZriHu3SO1jRVYAup7viRJ8F0bfv2fNDHtVtTJs
         nSEA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from;
        bh=oCEW0CR605HFD9Qhv7zjDD2lFgVZBYJ9hLx9k6V5gE8=;
        b=ZVHYRgmifpSIwLlj8vE/iAj3yyG39iJmfBpaDtNCa93qCkRgIn7+uWakj5ki5Eaf+3
         tNbvUjpVVJzPhSYUaGR9B3EMSs8TLUf7HPIk3j8YgNPF2NgoieT4CydrmYIbpVyI1e9C
         3lV9nNko4dthNUxp4ZEiRiVHvOisoVJgj8LjkHNwHjRch+q6u97n/wsRLpRpkWUikqKT
         MSp/7qNi6j1fOMy8D02sM5YX2ATKuD8TT3hBisYH1g9igaxW55DJWhr5qiw/i5uzPi5S
         fC8dC9LXN+WDvHAxMpkRTy0LjEBxCC0ovEasMRz/gcuFIkHK492oN+PkTthB+YYqB2u+
         etEw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.98 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.wl.linuxfoundation.org (mail.wl.linuxfoundation.org. [198.145.29.98])
        by gmr-mx.google.com with ESMTPS id n27si5111032otj.1.2019.08.12.09.01.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 12 Aug 2019 09:01:10 -0700 (PDT)
Received-SPF: pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.98 as permitted sender) client-ip=198.145.29.98;
Received: from mail.wl.linuxfoundation.org (localhost [127.0.0.1])
	by mail.wl.linuxfoundation.org (Postfix) with ESMTP id B161A26E55
	for <kasan-dev@googlegroups.com>; Mon, 12 Aug 2019 16:01:08 +0000 (UTC)
Received: by mail.wl.linuxfoundation.org (Postfix, from userid 486)
	id A5BB42832B; Mon, 12 Aug 2019 16:01:08 +0000 (UTC)
X-Spam-Checker-Version: SpamAssassin 3.3.1 (2010-03-16) on
	pdx-wl-mail.web.codeaurora.org
X-Spam-Level: 
X-Spam-Status: No, score=-1.9 required=2.0 tests=BAYES_00,NO_RECEIVED,
	NO_RELAYS autolearn=unavailable version=3.3.1
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 204479] KASAN hit at modprobe zram
Date: Mon, 12 Aug 2019 16:01:05 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: changed
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Drivers
X-Bugzilla-Component: Flash/Memory Technology Devices
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: normal
X-Bugzilla-Who: christophe.leroy@c-s.fr
X-Bugzilla-Status: NEW
X-Bugzilla-Resolution: 
X-Bugzilla-Priority: P1
X-Bugzilla-Assigned-To: dwmw2@infradead.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: attachments.created
Message-ID: <bug-204479-199747-NeUhmuVadF@https.bugzilla.kernel.org/>
In-Reply-To: <bug-204479-199747@https.bugzilla.kernel.org/>
References: <bug-204479-199747@https.bugzilla.kernel.org/>
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

https://bugzilla.kernel.org/show_bug.cgi?id=204479

--- Comment #17 from Christophe Leroy (christophe.leroy@c-s.fr) ---
Created attachment 284343
  --> https://bugzilla.kernel.org/attachment.cgi?id=284343&action=edit
Disassembly of lib/raid6/altivec8.o

-- 
You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-204479-199747-NeUhmuVadF%40https.bugzilla.kernel.org/.
