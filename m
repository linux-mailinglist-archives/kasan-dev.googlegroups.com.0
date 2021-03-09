Return-Path: <kasan-dev+bncBC24VNFHTMIBB3P6TWBAMGQEJMDFKHY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3c.google.com (mail-io1-xd3c.google.com [IPv6:2607:f8b0:4864:20::d3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 26A803327F9
	for <lists+kasan-dev@lfdr.de>; Tue,  9 Mar 2021 15:00:15 +0100 (CET)
Received: by mail-io1-xd3c.google.com with SMTP id d8sf10225421ion.10
        for <lists+kasan-dev@lfdr.de>; Tue, 09 Mar 2021 06:00:15 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1615298413; cv=pass;
        d=google.com; s=arc-20160816;
        b=QnsSC49fWHS7aJQ+atYeJwSwPG9Zqoc/p+z592QNbgk/99wxq6J2BcQcvXu3uiwkge
         vUcDu/qSJx9P28tlxd/950kEeC7EtJKoYrFOL5du6HW106Rx9UAjca1+4lzRpwkLwJtY
         dxxQfX+zGatLWI0F9v4sC4U0BGH6RilBfKbxi1L99U3J3jBitM7eAxgphZJsYyOtGXQ8
         KWuPIVZk5hrLZD6OGayIEEzWiKI0Cn8crTG0jcAGBi9A+oavE7qyWgR2PfyHaOzTMRBx
         epgFbvFoyHz0iqmyC9DK2Hzxc58Kf2PX2zZxLj+/FosQZzCBe/9PU7W0qfkulNQfcqgl
         0Clg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=g5S6X5sk9TmCblUN3noV2fsO+ANTPatoP6efXTgyhsQ=;
        b=NERqaoPGwrpV6lPUa+dQgsX/O3XFwc8Yd42ONzfanREJhT21PTR+Y79wDU+2sk1/PX
         Ny8Jpj2AEdtUrtvofeJDOC5wxRZ0RdK3pMqh3CXGu6W+k1kOUnz1i+EW2ppGZd12/WEY
         vP4V9AKvhZ8F6jQ0JLjh37Q8jq4Qc7v4aaBDKYur0/+2HXC3WCvZ0h2F7dWSPk//tBYb
         HdpHcx4Dku89JtT0x5RmGVyR8XAK3eGwfl7PGoZbn5pmleYkAblgfB8aJp766gPhg+zB
         1Cx1HpvLgYzv0R3LCE2+bWCj7LC0FBdzIdthzPUvQBOOMN4k6xqO7+MjNcpWTST5Ub30
         ubgA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=MReaTvSi;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:date:message-id:in-reply-to:references
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=g5S6X5sk9TmCblUN3noV2fsO+ANTPatoP6efXTgyhsQ=;
        b=Xzd4ymOfHvJ1vrc2JnQ9LIfqqk8U8kcZaiaxHsU/dktvOWYaoHc7lIpD0kix3CGJsU
         gYLXWjc5sTa/4rMrIimbqyx9ysUKFdVkWEcN4I6lxVReZ/TzFmqpZy+QXXP/ud+JMTfC
         vSwjGbYl6C6msD1r5o2PZAHKBd/XRsvvBJGOqqBEMoOaH5B8koahvfgjrX/JHAWW3M17
         KJPuW/QjMMq1spSOzvGuNuSvozi1ZDQ4fCXt//CWABZq41bqHfM7Fv2Oug2pREitlWUU
         nMoPt7P/3rLp1BWOAFI+EFBLZntD+L5PamYsd50KjNsYotHs6BBUPtVHGMLiqeTyYq6K
         OP8g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :in-reply-to:references:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=g5S6X5sk9TmCblUN3noV2fsO+ANTPatoP6efXTgyhsQ=;
        b=TrXcfj6YpobJ9ehXnW7wHeSh8be9DFeVGQdf1Hcvvg9MOJcFBMT4G4tlJh/M7SInpJ
         SjRxkF6whuzKlh4bhCtGXzn0t6sbYjRSIY4FlixB7aRsWYDRAjYnfi5/+tb8Z7lOJT2P
         I7wijifqpNtmFGI6N9i2v4t5hJzaVG3FhOahBEuvoT7ZUy3o8kuRLJE5r6Jk7ATmhKMf
         z7N38WwszHiX5Yijahqwnqgjp7XR3rB8npVERXD9HPceCPVPaIaCt0icA9Xy3LyNYVFs
         jT9Yh0CCf0iSvpX2MPnqlSSYr6Cpei85gWkLHHiJpD70kl6VLwwpImPo7qkwh18T4sh9
         se7g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531RKYJPTaa5wsCK5onQd71PAT+1YUsiPoAHeIMpoV6eNWbnOB9v
	PADNDYTiLwC0NMxKfHc7aWY=
X-Google-Smtp-Source: ABdhPJx113K5sxCGnYxyNpe1JvtwLL1OKa1VSprsj7lFa0DkWlIslCQem22drxmyAXLehpW/k+2Q5A==
X-Received: by 2002:a92:dd82:: with SMTP id g2mr24719659iln.194.1615298413885;
        Tue, 09 Mar 2021 06:00:13 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:1a85:: with SMTP id k5ls5226621ilv.6.gmail; Tue, 09
 Mar 2021 06:00:13 -0800 (PST)
X-Received: by 2002:a92:b00d:: with SMTP id x13mr24701932ilh.128.1615298413559;
        Tue, 09 Mar 2021 06:00:13 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1615298413; cv=none;
        d=google.com; s=arc-20160816;
        b=oX2PL1UOqKh3JdY4wp4ssw/t8HZQU9Z5WqVlAf728goz6+/OdDSgYBps5N6bS2iKqk
         v+47fH4sZaoBjh9mBviGHcq489fFXg8thTEdQP82/Zf65rYO0kza00yPHXEhi9qU3cJN
         rFm5h5g5g6Kin8SoZqoNcN8bAgq/HX0ZkJ+xFXEhs0+QihTe7Cj5DbGSs25qFpTanEAB
         6Lu+TVyR+1FJiJ+TywQ0659bVwhEL9goL6rS9dbRdTs3GoN/ddLaoOsKuLUiqrYEJdEC
         LJ1F+QpQALAzIVVUcFRi3w4ZLlcrogyKxDsBRsCgrrX1m/UbE8xkcMMfwp5abxiaPDQX
         bUzg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from:dkim-signature;
        bh=GhEsHtZFHHjFsZBo4wKTL7m4bhHecKqR7V21YBIx924=;
        b=tX+NJdxatmXcaLE/CJhzVBLwKVAan/zECG2NdDWVH4hU8NFq3I+imcRPhkcOzB6GQR
         vsnhbrt4JkDFCyqBcL2d2iqDqav1RVIZiKsPuf/BjtFMIiXvwZu4d4qCEjtY/GokbHxt
         9b1oxx6yJhGJuL6pihjMPSTbw+85ZrFZp6+ysf7Tpl3Yt11EVq8D1mmm9JZJ/kvkE9/N
         PwhC2mvsNX3gEnRVktXbX54WEgF78a6B72EKOkI2jhYcK4d52ttsI8+YcLcpmhRiksGR
         Ats7HuNiFFPNoLCEan7zNmkD86ONvjZ0FUu9+Um/UorxYFSsbFoXQkYx591BTppUzeOp
         YdVg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=MReaTvSi;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id r19si829896iov.3.2021.03.09.06.00.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 09 Mar 2021 06:00:13 -0800 (PST)
Received-SPF: pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPS id 9D4E6651A8
	for <kasan-dev@googlegroups.com>; Tue,  9 Mar 2021 14:00:12 +0000 (UTC)
Received: by pdx-korg-bugzilla-2.web.codeaurora.org (Postfix, from userid 48)
	id 97AAE65368; Tue,  9 Mar 2021 14:00:12 +0000 (UTC)
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 203505] KASAN (tags): guaranteed detection of linear buffer
 overflow
Date: Tue, 09 Mar 2021 14:00:12 +0000
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
Message-ID: <bug-203505-199747-awO3fmdnLz@https.bugzilla.kernel.org/>
In-Reply-To: <bug-203505-199747@https.bugzilla.kernel.org/>
References: <bug-203505-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@bugzilla.kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=MReaTvSi;       spf=pass
 (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates
 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
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

https://bugzilla.kernel.org/show_bug.cgi?id=203505

--- Comment #1 from Andrey Konovalov (andreyknvl@gmail.com) ---
Related bug: https://bugzilla.kernel.org/show_bug.cgi?id=212177

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-203505-199747-awO3fmdnLz%40https.bugzilla.kernel.org/.
