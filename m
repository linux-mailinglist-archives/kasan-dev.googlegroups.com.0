Return-Path: <kasan-dev+bncBC24VNFHTMIBB4VJT2BAMGQEBHQN2YQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe37.google.com (mail-vs1-xe37.google.com [IPv6:2607:f8b0:4864:20::e37])
	by mail.lfdr.de (Postfix) with ESMTPS id 6388F332A7A
	for <lists+kasan-dev@lfdr.de>; Tue,  9 Mar 2021 16:32:03 +0100 (CET)
Received: by mail-vs1-xe37.google.com with SMTP id v15sf4666895vso.17
        for <lists+kasan-dev@lfdr.de>; Tue, 09 Mar 2021 07:32:03 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1615303922; cv=pass;
        d=google.com; s=arc-20160816;
        b=Tw/WsNFHWuhpomWT82MWxqT5y9TgIAEDWoeiCRyPWPlhvGEWKWKT9O+5csBLixQeuw
         QtrniwB0oEz1hZgjZ7EZG8t2zIfxSGlV8JP3r7b/0aAMNAqIPizV83KcMIngPhOQpaOB
         +frr9SzOgCzfv8TnQxFlM6F8Mi8oOEgkgqGUiYlnthMF8mcSoXL9uurVMSI7UdVnL+/4
         jV4wPwJ02kLiv2LfCLfxi1XcvpXccVUqkp3PMud9eCpDJDLWMDjazGXGGPXKMAhTZDFw
         uCnCWF+UuhF+BamNAmh9Io09/YtW2Isn4y5/l1ZuWrkPjLBl6VcbX6lp+PKc192RiDZ4
         TcKg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :message-id:date:subject:to:from:sender:dkim-signature;
        bh=7jP5Nc5fDBwq17NEZdJjs1eBZlI1KwzZ1RfPgN3kpQQ=;
        b=xgKWSWplT74bDqmDvKAWmsVFEmeA6jKJmoy0PVh34Ql8D0JIiZ5c0mJc9UdhwEoxsi
         UPpeEZO4YG/R2oupa3jaxouqWeP8zluTxMYTzC7B3PFi5hhEBPr8QguCotR4/iR5pzQC
         c+HVDKhxcVzUbrrzcufhH5kOfDSVvrDM5gXKr+9TwsFchcKSrtCn8yifzecccoNNubYs
         O/PSoOdM9x+j0HXCDagRuj5+TdRE8aI6FImsP8bEdmtOY2MYK8ZZ/I8L8r570kQ1Pr9G
         JKHSsp04NuKXGcKCnF6wfGjVZL4pJIZ6qxc3HNq7QYhPXFjOUD+d1f0K+OL2Gdg9Gi0J
         xLaw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=rNRBTWt2;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:date:message-id:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=7jP5Nc5fDBwq17NEZdJjs1eBZlI1KwzZ1RfPgN3kpQQ=;
        b=LXq12pURTFS5OYC2tDR0bIh3UkRoY13o2pqiRCd5D0oyT0G923i4p0TV64jZKByKQI
         4O7LIKRu2i4MgaX6v3MEqH9adaD3wx9pruexk88J0Avte8kbzKxftLwvMuutfPuxQxCs
         uF7mF6eZrOEbaEeYQAEW0h92WZ79xEbYhSkYZgXLwn8ceafRIstbKK9saWCY2v2YOXfo
         Wlw2NBX22g+nIx2Q8svGg2L4eiXK7575qCBh+sSd8xgXGF1Uo1MsbNJkLccaAYgXNvKp
         xav5YKSjzIqk4hGqJ0A68uxexFYhHD8eZJIRAmiXmmc3gz3G2wfhLJxcyszn24Qz9ChH
         paOA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=7jP5Nc5fDBwq17NEZdJjs1eBZlI1KwzZ1RfPgN3kpQQ=;
        b=DxPPJkHz1xbavXaeln+tfvq3uLS4APj56wCCzVCB/vKd+dmZ1idx2lLpi0avXBYtaL
         fabxcS7G+zKOYTeGu3UOEYB0dmxKm8VhgI6IPCQyDu/6Ed8aqpESa3wmhu7xlH8oVkeD
         xOIHVm4qxBTlVJcYEUrthBRjbV13l6HGc2YOYnqbCVRfbS0zsOVkaOF5fpd4/A0Me6bD
         XzDz86k69CduEyNPTMCnsq5LCs1nxAV2TApMjuY8xcG68kJz2JZSOgHCH1VXug4TLZjo
         QmyoeP08HQ7GDpsn0F5+rKx8pFc4YRGjK1g9CRvMDF+coZLgxBIjalebylLu7Ydibxm0
         m1bQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531OqQMqC/dKtjFcg1/SR3JuqmVPqsrNw8JgwUNYzjYmr3Ijrt7W
	AR+0sOHGpK9avCxb80UPhVo=
X-Google-Smtp-Source: ABdhPJxWdvPfNIZNArJpZzjlre9S87t3t4BgTgIivFPLEKpf2A/1SP1jz8ispJAjLbZTjgZjx8ruEg==
X-Received: by 2002:ab0:4911:: with SMTP id z17mr16539912uac.81.1615303922247;
        Tue, 09 Mar 2021 07:32:02 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6102:21c4:: with SMTP id r4ls875990vsg.5.gmail; Tue, 09
 Mar 2021 07:32:01 -0800 (PST)
X-Received: by 2002:a67:945:: with SMTP id 66mr6338317vsj.47.1615303921773;
        Tue, 09 Mar 2021 07:32:01 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1615303921; cv=none;
        d=google.com; s=arc-20160816;
        b=l4zTL3foSFkcUXDAQhOjd0lhD6kN5X6b58al5uGgyClPGHx8MrpXfbRDhK1kXdKGOp
         AyBmDaRvN4JuR/hYirPCHaIoCSPfgQ5MUbUM+WEZWvGQWTXbF7tkgBCtXTi7NTvDvSZc
         RfC7DtPZpVySMwFAPMIPZH2U42lwy8bNNpMXG4ZyR8R20HFpOgLduhEnqNOoEDSHmAXf
         B96rBRrmRElT1BfW03zA8sHqNiAI87DJcs02KfuiW6WU06/b4gYr/TLzDX3XazJDlzKw
         eje51LW4BAKdysyklWck3+rP5OFoVJnt+enqiizfWqIebIaW9I9XqMFfilj6iyz1+ABL
         FPKQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:message-id
         :date:subject:to:from:dkim-signature;
        bh=xVNy0yWpi89ZSuO/IlIRnBMk/Qidp+HU9f2pUrPVRtc=;
        b=K0okgu3TLtcYFVpP7SxLJDZigFJmpXCeAtyw2h/0ssjroKH5xnbWPz84vhlcFNYW++
         r3RQGqmuxtSXKH8M6p5p0NcKRT8jOTHGdIdM1vVVXlow0vwVDNw0yiWZGfr/SGIH+tGD
         Ecb4KtBc2bV4JpgPjlPjtSKhN9dmHgBtI2mK4LO9wPCAKnPOMcJD9UB9jbEFcC3u4/6q
         sctm8e9cdj61CDgoA9re2eVIn1C6Mm6gEEjsJQhQnEy0EWtYFobkAXsBajzL0UWnxTsd
         GCW4RXmQ7aSvKlCH/eiTiYLR8GEqrvc0TBaMoqO1TniyIWMwIum3ovU1D38kWQyAY8T7
         Y4cg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=rNRBTWt2;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id l11si541314vkr.5.2021.03.09.07.32.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 09 Mar 2021 07:32:01 -0800 (PST)
Received-SPF: pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPS id 826CC6525F
	for <kasan-dev@googlegroups.com>; Tue,  9 Mar 2021 15:32:00 +0000 (UTC)
Received: by pdx-korg-bugzilla-2.web.codeaurora.org (Postfix, from userid 48)
	id 6BAB465368; Tue,  9 Mar 2021 15:32:00 +0000 (UTC)
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 212189] New: KASAN (tags): consider not tagging on alloc
Date: Tue, 09 Mar 2021 15:32:00 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: new
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
X-Bugzilla-Changed-Fields: bug_id short_desc product version
 cf_kernel_version rep_platform op_sys cf_tree bug_status bug_severity
 priority component assigned_to reporter cc cf_regression
Message-ID: <bug-212189-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@bugzilla.kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=rNRBTWt2;       spf=pass
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

https://bugzilla.kernel.org/show_bug.cgi?id=212189

            Bug ID: 212189
           Summary: KASAN (tags): consider not tagging on alloc
           Product: Memory Management
           Version: 2.5
    Kernel Version: upstream
          Hardware: All
                OS: Linux
              Tree: Mainline
            Status: NEW
          Severity: normal
          Priority: P1
         Component: Sanitizers
          Assignee: mm_sanitizers@kernel-bugs.kernel.org
          Reporter: andreyknvl@gmail.com
                CC: kasan-dev@googlegroups.com
        Regression: No

Currently, tag-based KASAN modes assign a random tag on alloc and assign the
invalid (0xfe) tag on free. What KASAN could do is assign a random tag on free
and keep the tag on alloc (but still poisoning the tail for kmalloc). This
reduces the performance impact giving similar bug-detection capabilities.

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-212189-199747%40https.bugzilla.kernel.org/.
