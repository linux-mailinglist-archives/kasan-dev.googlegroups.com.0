Return-Path: <kasan-dev+bncBAABBXXCQGJAMGQEUSWKBBQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x240.google.com (mail-lj1-x240.google.com [IPv6:2a00:1450:4864:20::240])
	by mail.lfdr.de (Postfix) with ESMTPS id E4DD04E8802
	for <lists+kasan-dev@lfdr.de>; Sun, 27 Mar 2022 16:14:54 +0200 (CEST)
Received: by mail-lj1-x240.google.com with SMTP id 21-20020a2e1455000000b0024ace13ce62sf398670lju.3
        for <lists+kasan-dev@lfdr.de>; Sun, 27 Mar 2022 07:14:54 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1648390494; cv=pass;
        d=google.com; s=arc-20160816;
        b=JYSREHgvPKU1d66rdmwGWMdlLrOU0Q8FhaeipAANJ6XDOD+Exy9ncKXfsqepC5qCRZ
         c6d/+TKQKnIYmtYrsJxyEc0LCSPD35ggVPC54Q4Kt37hrxn2u1ME3LQOZ76aVyYs6Tku
         j7n2Q0NBXcptkv8w8qhLjSWlHLmX4g8AszDxiORAImIuf0J0hhCvkkzrwV+lNCMlEjlN
         fQb62MPvihCR3uhm609QHuAjRDBS+H1LmGqhP+teoIIQ7HV8kqALO5pu+tL315BuSzJ8
         4IWWaAJb1AWbuPpwzZPJ6UKpZ/ql1aXvYsgaZe27EGn1QRhhDFwZkf2cCnb1/+oCdL/e
         Z6Rw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=/8ocTJZi6oCqLlUOJqwUBWQdYVV3zeVErcU+szQYl6M=;
        b=QCIs7HPPOEG56ZX8EbuZKrc+deXEDibg85DYR5vcspocNP/ZUuildVxqOorfobTKMl
         9F44qcqpyUemiR7kxDyAbGbTip7aGQyoRbqm6Z5gRe62dpmNmIWqZrrUN+Ie7nIVB+K+
         Wmo0spXPKiyW1b6jEQotK9YaH/VKiXzo1G+kzHxxsMi1Bk5K/kWqFPAOCrOQRF11rSvA
         EXsUkQIpYCmowM9ZTu3Ul8fZmoC317BzezksTqPfwRcKJwaJbFFNj2F2NfIgud63QncU
         lLoSr7rwC/sYqJRw5HsJPHSXc9Xm+EGGyNTP/JqdktMbsjYJVPv8vuqFT6JUMLttDzb/
         ANFQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=XqLrn4Ke;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:subject:date:message-id:in-reply-to:references
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=/8ocTJZi6oCqLlUOJqwUBWQdYVV3zeVErcU+szQYl6M=;
        b=EhedA6FgoAkR5uh2cL9F3Rv63eShVxJh82t8IC5q/sElr5PfqZ5WSW677OOahKLTSh
         QVyEHB+u3dvrCJK6K94gVg48M79TBvbTi0kXP9m8KR/O6jlKMk2g4orRJ89siMMTx9YN
         DoI3BqNAJaBweiefATr/z6kZDZJeokESUqkSVQhVMxxWqrk/RlVcOtQnIdQA1LDtICwE
         FE2hk5Up3Bs3h0V4eZQdKaJwBRlI5Gp26n9O/otC7W4tqK3ctn2RixOjqRAP6UAsBNzb
         LTy8CrL+U6UArQten0Y5We0UkS50putub1CCRIwIZkuxuUFmSBEO6uUASJ1rEnPMQitw
         vSSQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :in-reply-to:references:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=/8ocTJZi6oCqLlUOJqwUBWQdYVV3zeVErcU+szQYl6M=;
        b=Up0C92sx8pm73psFTIiaKbHSGl0dILgjHX+a8Z13giTHXewjG0HFAJdV9cVW62TeIL
         TSsTwdXh8RyURB5HMs4xAUrlUH6PxnxGjOAq4XkRgdHbvl2P6fZKo4FfTPdxC2TFQWAP
         +SjJAJo96+Fc3pmDg369htPDIt5OlG2et7ND9IBolF6hKqRSIt94ouq606vSGoSfKA+v
         iADKnB1VR2bg9eW90G722yUjKKQ99aIohTZ2xJBEViRjZafF5eGwfenBvQ+bsE25lM3m
         KamEpkkLWKzQuSCUiXstBUhvY+bx+BP0of1RzUik5lsxoRfRjU7bIQUs/l0zhv7QxLvt
         bLiA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532CKDFi8uq0n8fOb/a/8eY9idYaxuJZxNOQBgIMo2SebfipLgvv
	jusHlp3x5vJUuzu08ip+5UU=
X-Google-Smtp-Source: ABdhPJw94I/wPFHfhmBESf+HcsezTzdozYYw9vMPd0av6pUh0nefgqWUeU/zw3QOtvjaBK91kVMVWA==
X-Received: by 2002:a05:651c:14a:b0:24a:c1ba:b65e with SMTP id c10-20020a05651c014a00b0024ac1bab65emr7420072ljd.18.1648390494216;
        Sun, 27 Mar 2022 07:14:54 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3f16:b0:449:f5bf:6f6a with SMTP id
 y22-20020a0565123f1600b00449f5bf6f6als2008887lfa.2.gmail; Sun, 27 Mar 2022
 07:14:53 -0700 (PDT)
X-Received: by 2002:a05:6512:1529:b0:432:2c53:f9e7 with SMTP id bq41-20020a056512152900b004322c53f9e7mr15500504lfb.139.1648390493388;
        Sun, 27 Mar 2022 07:14:53 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1648390493; cv=none;
        d=google.com; s=arc-20160816;
        b=0PbL8a0msAWYQ7z+QtZyKKcGeH3rfW2dIGFnCa0SEmndZucttJNrZOa/YramGSV3PA
         uH0arjP/qa76h04Y1OjgC2W2lhBKmAQ+1D2MBavUzc3BdFf1uG2E4oaFTffq8QwVHWQH
         ysO+hvx4iElIVHOT9NHXr7dhP/8eB2y87BfngAFPiYaSmZ7PSMO6XIY0OzKs46Iq+d/Y
         xX3yg5sT9A5wUecUgiMl5RKdrpZNbCWADZ2yV0cOd51kdKfG3Oy+lcxJNBXbVugh7Dfm
         WJgIS1Aj9Jx3Zya1qPOqdAwp9MuQwGvcncUr2Ayf0RyDnK7nJjDiz3/UsMsAJVKfTUlU
         TVNQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from:dkim-signature;
        bh=vspsTSeW+rW6VSZo+F524JtcgiXCH2f0Y0JIjxVnemY=;
        b=PZGyG59W/i/X6AEk2f7cRFrUzfpEy0YIHnAetciNTsCubK7Q0eU2ZCoLM3pBF0Ljw/
         mhTryEfjmKeu67JKnzDT28UAAbzvLk2ga1yxGeLoa//T+tb0FHEh3rRVQsB4ucaQb2Dl
         GFQ5ScgI5NhYWNb67ZU+LODjrPwq/wzWjke2ZL26anuTpGUPPxVM9ZiT5OBOKHrFFEDn
         uvxDjsAXr4V15fbaheX8ybwtp2JrdOSdhgQf8RiaedmM3+P3vp/E2JCkJz4OkeW9+Do1
         MFaonhpOI8ipgY2U/ko8nkRmk/AjK8pVSj4BEfiFTtzGQJ1mh8e65PwxVeumOlvxH+vI
         6Rug==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=XqLrn4Ke;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from ams.source.kernel.org (ams.source.kernel.org. [2604:1380:4601:e00::1])
        by gmr-mx.google.com with ESMTPS id bn35-20020a05651c17a300b002462e02f542si668708ljb.2.2022.03.27.07.14.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sun, 27 Mar 2022 07:14:52 -0700 (PDT)
Received-SPF: pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) client-ip=2604:1380:4601:e00::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by ams.source.kernel.org (Postfix) with ESMTPS id DEFDBB80D0C
	for <kasan-dev@googlegroups.com>; Sun, 27 Mar 2022 14:14:51 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id 8A60DC34110
	for <kasan-dev@googlegroups.com>; Sun, 27 Mar 2022 14:14:50 +0000 (UTC)
Received: by aws-us-west-2-korg-bugzilla-1.web.codeaurora.org (Postfix, from userid 48)
	id 75E8CC05FCE; Sun, 27 Mar 2022 14:14:50 +0000 (UTC)
From: bugzilla-daemon@kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 202115] KASAN: disable LOCKDEP on reports?
Date: Sun, 27 Mar 2022 14:14:50 +0000
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
X-Bugzilla-Priority: P2
X-Bugzilla-Assigned-To: dvyukov@google.com
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: cc
Message-ID: <bug-202115-199747-A5HlKvcrx8@https.bugzilla.kernel.org/>
In-Reply-To: <bug-202115-199747@https.bugzilla.kernel.org/>
References: <bug-202115-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=XqLrn4Ke;       spf=pass
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

https://bugzilla.kernel.org/show_bug.cgi?id=202115

Andrey Konovalov (andreyknvl@gmail.com) changed:

           What    |Removed                     |Added
----------------------------------------------------------------------------
                 CC|                            |andreyknvl@gmail.com

--- Comment #1 from Andrey Konovalov (andreyknvl@gmail.com) ---
Resolved with [1].

Dmitry, could you close? I don't have the permissions for this bug.

[1]
https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=c32caa267b927b744610f4214bfde7ce7d55df1c

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-202115-199747-A5HlKvcrx8%40https.bugzilla.kernel.org/.
