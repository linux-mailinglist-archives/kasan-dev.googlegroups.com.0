Return-Path: <kasan-dev+bncBC24VNFHTMIBBLMB7L6QKGQEC64M4LQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23c.google.com (mail-oi1-x23c.google.com [IPv6:2607:f8b0:4864:20::23c])
	by mail.lfdr.de (Postfix) with ESMTPS id 582082C449D
	for <lists+kasan-dev@lfdr.de>; Wed, 25 Nov 2020 17:05:02 +0100 (CET)
Received: by mail-oi1-x23c.google.com with SMTP id w67sf1418914oia.13
        for <lists+kasan-dev@lfdr.de>; Wed, 25 Nov 2020 08:05:02 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1606320301; cv=pass;
        d=google.com; s=arc-20160816;
        b=nWWHgCX718x7aqCGmMUWoXv/9GxH8jnrpoT/rH9EFh5OT3pzw2XXVrO6SbodhN4dEM
         MBJyvpZTgjHEZzGgq81EBUXpUiGSsbFx37U/UfKpQLEM9jNDNb9hWAn38ZtTbCqfAo9R
         7gBVBF4szJx9nkZSWJioCEZ997Sli0UDZsEDgH3rgH1GXrhgKToNeJGOABrF556HXJTn
         IFID0f+cxY4AY/1ANeV92JXgmJWgw2jTohg+7FHsrZwmWM3Erb3gYub0le6VfiMP92J3
         hDj4Eorxl0AdlEaGAOeSs5p/EJFlaltsiXbGfFaG1kdUQJlwURFtuSL6o4KtMi24zhBx
         Vb8A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=IwvmLaMYFT0M6wCyRXu/hdEuPvHGB6n/eOEM1bljBpo=;
        b=y/W1FSG6CFXxjjhNr6DaEmlYDIRuI1sfpFYsDu4lCopI08XiQF3YRc/sbvlNnwf4D0
         ob2z3kEJZGVjMBudhHXFskBVDCz9xtTZ+a9fzqHJtgYLSed4Ldc+ONB1d32nklUV3gbq
         KVg8WxzaqneFJnjZH9yVA2AkKAPy/mSXv7GFEjfr2mpWs7dVDnLAqN7wlNpmTlh9VKFV
         N9BOaFmwRzhFu5a19ynuEX9UHrQnkttzNtOSPZAJTCgZuYJ39KEbWOuB6IXMZtP2/PvT
         PR/WvcYdes2eT9b+DLUblUY2haiFKOts8Yl2M1lGEgd+Pg2ksJ0rNpwMUrb2nbq4MoJ8
         ardw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:date:message-id:in-reply-to:references
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=IwvmLaMYFT0M6wCyRXu/hdEuPvHGB6n/eOEM1bljBpo=;
        b=PAyy5yBCad3EqVvnaMVOP8UgqxoFyH7mlQyZshhRNoy/Ma3zoQaAc8GeDPYbmmiKoB
         0PQUisMmKH6+IPj5H+v4yY0EBx7X4/Rkk1hsTL0ZZtWmoiRpXbg7g7AcWlHMcvS+/FCs
         r2v3mVbr9SS0vDX/Q3zbDbvz1KoRFOv3NiCWkApHMCdmvaM6BoOCEI/q6Pdt0AUwaiFE
         00uHuPFMQIh8AoIMwNyQfhXdEmu+t/piL4Y920c0D0+s8ffP7bePcQWyF7WOfJwxk/H6
         om4OohJoeaVqVNOlY9pYb8tw7RxXQB95dXtWC7mI7heyqjO2giuBpfycWhmbA84r7Ut7
         Tw7g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :in-reply-to:references:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=IwvmLaMYFT0M6wCyRXu/hdEuPvHGB6n/eOEM1bljBpo=;
        b=n2eBbZQvIKFHocCeqf6r36b5t+CjhPNpwUmVtIch7HpiONXxBDlfDJMmmjOEbpJ+p9
         KcGNJJEFfb+gCTwCCa6FzyGFz2ld5prxpQtCOgb5TM6DjYYjAcmYY8C9KcQBR1kshgPH
         iPDxINA+jaxtQG24kIZ9ULx0t+arLY+i+oEWTmGjDa2HAAERzKoxiAjS20uGb8k3Ny+F
         q9KXqGPcT4KHTdf2Mj0lj+DvMl1hooH2kioqQV3Lo9tSpI/N3OpRUGlfBg6UbH8QnePH
         xobYP3ggF44nQczIbkjSU2CSu1AizDxcJt9UW+awxE0lr86zCpxCYnReLZpZL+AlqptM
         ibEg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531GCV3+ROo+kWIGEX4OwE7nDy54yq19j1dDB2GOo8LARUrJZpcM
	nlzYf6bMadEO3mw8UMt263s=
X-Google-Smtp-Source: ABdhPJx/cF/5QQYW3l4rdlxinM/TvjaDhS+a+G/PnK1q3vs04hvavwjIAwQcM6FPt6ZmXKw2MKfsRg==
X-Received: by 2002:a9d:d4f:: with SMTP id 73mr3327208oti.170.1606320301200;
        Wed, 25 Nov 2020 08:05:01 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:230d:: with SMTP id e13ls687539oie.1.gmail; Wed, 25 Nov
 2020 08:05:00 -0800 (PST)
X-Received: by 2002:a05:6808:11a:: with SMTP id b26mr2640202oie.59.1606320300888;
        Wed, 25 Nov 2020 08:05:00 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1606320300; cv=none;
        d=google.com; s=arc-20160816;
        b=kOFU6xQDGkri07MomKYalSn3nWtJIfXZuxlWZevxLIOnUrIVaNgSDV66NhR4ehFU2Y
         sd+uV6FOWV3Ie0dzJ5XVCt4jtwt6tyDIm7IcsYu8XJW5gFF6aJaXz9efXTANTyqBHfOj
         50h0Ti370HHJmwvzWjv3WkmRUTk/EmcedH8UXf0d/uX9LqUXfM1BSzinrBEu7H5kZu4F
         3+YPnNBiGdCoxG/MxYYJ54zKpA2N65JPRfa4nOyaY35jx4eLms8mgI9FtGx4AqdIgFJO
         YD0Q1KGY5xlCFqeR7n5OeoBSjMvoDPGX7nblFzcmm4OBiwjzDAfesbeoBxQzifINBloR
         Qq7Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from;
        bh=SpqJkHNTr5wPHAr+7ElLHKPJ/xpixMkHqA7YKBWpCXk=;
        b=Zst8NuUYttoz1d+TTw4RKSewjT60BUv836YiviKFSXjAj50M1+xfhlFv8HjfzM/L01
         hesG7Ar1S3u03vve3CkQuxDoOPUVsJDFk8wZURs1ds+09Aj3L5nl2unlmDjcPMk5xjPP
         /4e0Fw2pRFa4lqmDjXxgLfK9Af1iFet27nPBRvlasK2s4AhJhb3fYz593/6JTAcrGf+B
         MDsmjROQ976wWxFnZyXtr5mMoeS/m5rPVrRaufBBWylRoiq9iDXGf45ejc1WKMWVuC09
         LY5NouaQmhp+k0dZ9rs9kTgMpq94bdg3xLZGPBvwSD85JK/eMlQXYZToUeisUwviAF40
         CnNQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id i23si167152oto.5.2020.11.25.08.05.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 25 Nov 2020 08:05:00 -0800 (PST)
Received-SPF: pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 210293] potential kernel memory leaks
Date: Wed, 25 Nov 2020 16:04:59 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: changed
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Memory Management
X-Bugzilla-Component: Slab Allocator
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: normal
X-Bugzilla-Who: vtolkm@googlemail.com
X-Bugzilla-Status: NEW
X-Bugzilla-Resolution: 
X-Bugzilla-Priority: P1
X-Bugzilla-Assigned-To: drivers_network@kernel-bugs.osdl.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: 
Message-ID: <bug-210293-199747-AYyiPcWt2X@https.bugzilla.kernel.org/>
In-Reply-To: <bug-210293-199747@https.bugzilla.kernel.org/>
References: <bug-210293-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@bugzilla.kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
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

https://bugzilla.kernel.org/show_bug.cgi?id=210293

--- Comment #10 from vtolkm@googlemail.com ---
> based on the fact it's WiFi related

How so? It is netdev a/o network stack related:

* chronyd = ntp server
* netifd  = OpenWrt's network manager for Wan, Lan, Switch connectivity
* hostapd = WLan connectivity
___

> It might help if you get line numbers with your stacktraces, otherwise it's
> hard to say what's really going on

could you advise how to achieve that?

-- 
You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-210293-199747-AYyiPcWt2X%40https.bugzilla.kernel.org/.
