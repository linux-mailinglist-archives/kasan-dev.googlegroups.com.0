Return-Path: <kasan-dev+bncBC24VNFHTMIBBFGJ7L2AKGQEJNXRLPI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa3b.google.com (mail-vk1-xa3b.google.com [IPv6:2607:f8b0:4864:20::a3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 263DF1B202A
	for <lists+kasan-dev@lfdr.de>; Tue, 21 Apr 2020 09:45:25 +0200 (CEST)
Received: by mail-vk1-xa3b.google.com with SMTP id e69sf4969886vke.11
        for <lists+kasan-dev@lfdr.de>; Tue, 21 Apr 2020 00:45:25 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1587455124; cv=pass;
        d=google.com; s=arc-20160816;
        b=xU+G9UQriTyomsqqLFvh2FNOjcg1pZmPnjsV7BpBEoSQnm0GDwEkvxAa8bgW7/j5++
         xWoKYzAWv9fFtPkXNYLBaj7sZe/ZIRfELcl32TuVe18X0JwZFvnooVr0v1onObWoF5l8
         uUyrYiqKMrh+noLkEUgJbK3ljvWpchQs5TQln+g+Jk8hrk3AF/IjJsWDGyI3QKgASNm/
         tacZYgAGo79jlsmxxRoqpdm/NAm337iU80kCaOv5eaUoloL26NDMlNfFSmYjo/18+Vau
         tok8VlG5sbd54/pK5eChX7tLriq+sw6FaGFa2xkUGlpIzQxHIKaOmLYYKuuNGncfDKQl
         qHWg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=Ig2tXOuthnXi8YiDmwXXIMYHZXDsFb06sHO54kEVw7E=;
        b=v7ylQhboCRzchx21LY1HTLJ8gR8nR7Hf8hCMw87lBlzZwHydrBBYywoi6anWOfobzS
         acJ0Bx1ZKLV0+EWr/kmKifWmwY/rflv9i3CX4H+p3aouzDIe7IGodUcIfiCiYRM366sD
         Od66KEJEE71WecMNpuaa3S9pP2BsBMNK5shITL7pqRaJu1NJ1nIAvv48Cp3skWV92GGP
         wme/sK4w4ZrRNJAGPx93gWlOmp6PqFJ/lUiup8barcHImza4DGzSjQVtgCsSTUPcoAyB
         XVkuvQAaeM//QXi2xFJdc0kKPlz8PL74YIYgwg50PTELEGx1mXObcLk2A/eg9pLx/813
         moew==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=06v3=6f=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=06v3=6F=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:date:message-id:in-reply-to:references
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=Ig2tXOuthnXi8YiDmwXXIMYHZXDsFb06sHO54kEVw7E=;
        b=cvIJ7sWRq2Uw0w+LnFXfmyz/jz1lLKhun1mSxmO6UmzpnNXQgSuxUxsoBhyluTgOVO
         2yET9rPlHsvjGvqq8uHoapPI+26MDgYXk6/nME1owrQPFn/VMCcAC1aPyUT5OA56fBd4
         SwiKCGZqaxvyzR+9HtaTFYOO/FRVi4LsejEGr75VoEHJK6FrGPVEcuRJr9vszen8uXA1
         lQyVCKgCrUdmV9yKGkrUrnv2sNJhfoJUmZV0Hba+e1+Yg9p3r6IzKPEm2X/IIlmeRi6I
         IWSog6SmYHPwCCL353f2QD0EcLDMJWxMvkttlYTRqcJoFHN+u2VxQ+9oRf85Mbw1gwP4
         XjHg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :in-reply-to:references:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=Ig2tXOuthnXi8YiDmwXXIMYHZXDsFb06sHO54kEVw7E=;
        b=RlfbUotACP/5v+UswvtLnkYvXhcnF49r0is4NNkPL/f5Ja4G9DebxSis+qGDMeMiYI
         FBZJ2p480woSmQxaaAzDpondFRGu7Ar3vxqXLzEzNLBxiAa9+J0EGTpfR8VVGw2yqgm2
         uiXJAxwFx1cGb/2qTZgx2bPVHDSGs3Sty084JGgmjxKXdxzQujPSYsCMF4ZSQZSfFLpn
         wV85Na0k8yNX81W6cP20usFJtIEKtdZcjhKXTaa7nFyUOTyUvlD7lEPnKI97I+ESnDtL
         s3PUdU8DgTOuykEjmXGicrJ4mpp89z0yXQ5Kw3oiN5xnBU3UQHkhbP14XITeW+a8GGvN
         Q6DA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AGi0PuaEuc2yG4ZrOTfpgLAyyJHXI1tlL+tibQ0tIVpxT2cHr0ZNYZOu
	gsAgfh6q/IzMucJIo8m2yTw=
X-Google-Smtp-Source: APiQypJowXR6YWQVmA0f+sZVEWx5Lq/ZU1apS6Ovzg65BCfIkpT3AGjCeT5LC18JeiQILnhdhrzWyQ==
X-Received: by 2002:a9f:22e5:: with SMTP id 92mr10704791uan.114.1587455124184;
        Tue, 21 Apr 2020 00:45:24 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:f1c8:: with SMTP id v8ls1433238vsm.7.gmail; Tue, 21 Apr
 2020 00:45:23 -0700 (PDT)
X-Received: by 2002:a67:7c50:: with SMTP id x77mr15201087vsc.187.1587455123786;
        Tue, 21 Apr 2020 00:45:23 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1587455123; cv=none;
        d=google.com; s=arc-20160816;
        b=0oDY5bNpxSe8qOXVZtSiViHlI05gYGTyShfIzgw2m7oGoy7dypb0En2ImmVgJQqnfR
         CiU9BYS4PT/1Fxf14mNERPQsaNzQhx2fEkOHgFh7osS08JXA0XZgrJRwzGx/yef8ovit
         jijALLgOJcj6cfpS2dLWv63E6GrCwC9m073LbTGJJo9JWjnfHv2urrhygM3QpFEsAlZn
         QnLFIID8H9jRH+l+4rBS96CUiCnsL/C5lwocmjDS8i5YiCGV17sOcfLSHnEB5l+Cv5mx
         ljfHY761q5O+qePhy1KdVt9GzpXYM1yKeEI2HxTwVARkKur50Dt290vvInpsQIqYYrEm
         tz9g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from;
        bh=IEWMGe0NjPTX+cvTQnBC2B9egoI6IBCeb9pc2H6Z2PA=;
        b=pXxW6M/PB24sMkIGR+injMDgAnLoxSBXxnyxt+EwnBlrErZpH/EEwpznr8/KqPRmF+
         sn+latyj/+bQDfNrRs2T8sBxFjC2epp3XnohJeyA2pqujkUYvlaq+Dp4KZXDIVwtMAnq
         GSlVIsK5QbV8qBAdu1EZ9ykDOe6XxBuWZLUp8ZtjLO1DOOD0yBWDW12ERGPN4L4r7UK8
         D729yMFxbf5nnO8vkSdjGHL87uE2iqGEutlxslKzzcE559AP4B7ol44BLeaDImZCQbQx
         b/PyBBTg7uhrfJwvIkLixuSCDaC5ZLss2R9Z73T2uBeunCfXLKVszcCE5GXieDahHiAX
         d3MA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=06v3=6f=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=06v3=6F=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id v22si66706vsl.1.2020.04.21.00.45.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 21 Apr 2020 00:45:23 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=06v3=6f=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 203493] KASAN: add global variables support for clang
Date: Tue, 21 Apr 2020 07:45:22 +0000
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
Message-ID: <bug-203493-199747-a8JTdWCBb6@https.bugzilla.kernel.org/>
In-Reply-To: <bug-203493-199747@https.bugzilla.kernel.org/>
References: <bug-203493-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@bugzilla.kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of srs0=06v3=6f=bugzilla.kernel.org=bugzilla-daemon@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=06v3=6F=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
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

https://bugzilla.kernel.org/show_bug.cgi?id=203493

--- Comment #3 from Walter Wu (walter-zh.wu@mediatek.com) ---
Hi Andrey,

Sorry to lately respond to you.
We recently use tag-based KASAN, it looks like STACK and GLOBAL variable
checking are invalid. Because I saw the config has -mllvm
-hwasan-instrument-stack=0.

We think tag-based KASAN's advantage is exciting, so we want to use KASAN from
generic KASAN to tag-based KASAN. Unfortunately, we are not familiar with
Clang. Do you know whether any Clang experts have a plan to support it?

Walter

-- 
You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-203493-199747-a8JTdWCBb6%40https.bugzilla.kernel.org/.
