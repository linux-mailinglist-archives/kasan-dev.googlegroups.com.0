Return-Path: <kasan-dev+bncBAABBWPPY24AMGQEQ7DNRLY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63d.google.com (mail-pl1-x63d.google.com [IPv6:2607:f8b0:4864:20::63d])
	by mail.lfdr.de (Postfix) with ESMTPS id 02FE49A31EC
	for <lists+kasan-dev@lfdr.de>; Fri, 18 Oct 2024 03:20:28 +0200 (CEST)
Received: by mail-pl1-x63d.google.com with SMTP id d9443c01a7336-204e310e050sf17486025ad.0
        for <lists+kasan-dev@lfdr.de>; Thu, 17 Oct 2024 18:20:27 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1729214426; cv=pass;
        d=google.com; s=arc-20240605;
        b=JEppk3j2rRb+S2nZ+6OgBvFiKuN496LX9VxlIOnvks3jP5/GBzIOE9unXaa1P87xAf
         I+BC8JL1LSEPeekmbdFzfpO1zvvBf82DbKhqAMHBX5huNS2KHImzMZ2f4THNnC4+E7ks
         5aO1LBWcebPPgcetAsg7w6ln6YJTbdZ4oS89xLd03afB8ESvfCn8xnxzriHquAOH1unU
         tIhtk1bHJPLToS0XtJZaby7DSXQO9hNONlIcpX/R65y5rykD0DaI51NC1vl9fqE2SW/5
         yeozM7vjD1Gp2KyD0BPdrjTKa9RPScG3otoSldXt5rEOfIAMA7HhiVzJeP1WYMuFdKeA
         jZ9Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:dkim-signature;
        bh=XSJ9KiUeo372/mAw5ONr6HAr+i3PvR08coYmFNWNsNc=;
        fh=WiQngXHpGz1WCX/XN7ppccOC/BM3wvHtUoST5qzJMsE=;
        b=ICya2YAr507fcoK9Gjmx+MdXG3OTg5T+XjCI0dcRArTmSD4EbJfdnh0OoFCdv0XUaA
         8huS4Pmt5BeNBpXe/X4nmx7E+S30J//2s0PU/glGAITx3IoO590yWhNOyYEv5p+p6z5I
         fnAT2/mhZyiMsIKxdafX+/rvWEQX1G0E/WeMSveXHxrZiFgUSx2o3JqRKUHSZp+Aze2a
         lTdh9B65Obzc/51eyZ31aLgE2q73Av7otdFiFVYn9fsZh0L13UeDvDsFJbeze9bjQkEx
         MjGLwV2zakPmRSsZD3LlG/7FqibF3DI+J30JdWbsEqZzSEnl9Ry6EZUC8PMlIILZ/Vuc
         uZMw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=PySw1K18;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1729214426; x=1729819226; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:from:to:cc:subject:date:message-id:reply-to;
        bh=XSJ9KiUeo372/mAw5ONr6HAr+i3PvR08coYmFNWNsNc=;
        b=ZwgDG//BrwHZOCX/pfmOdWES4ag71Ovqhllnjrgk8aYGLJmD7DUn6W/hftx8vWHMau
         WbVTfngqjstOKaWu+ic1Ji05o7TNB6SK4zeNf3icH+rHEGmlZNKihGanOdF2ZsYZAqOo
         Z3yNaznrf+wQ/aCzO4xpH1Qd6O6ZO9+/smbnwJvJx83fggtRhb6idiIfFb4q5LXlCRRy
         83Fx0JJVhXZq97lbIIXd9Q/iNmSBNX2bV5GEKyQWJsY0eJZs79sqWL6HejjC6N2LXUSL
         w2Kir4U9MEH+o9RwK2TkYnlldoxcWlD/Qp4/7myC84EYTktnU8kkwWqDkTihvjXBwzwO
         U2ew==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1729214426; x=1729819226;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=XSJ9KiUeo372/mAw5ONr6HAr+i3PvR08coYmFNWNsNc=;
        b=GiiohkNsKCMWTIzdJSKjbl2aI1TNOsIBoxOG05AiEH/QjAlM6fTe5csiVPsGHx8WKE
         2h/jkZe6PCCDmJ1REqpvBSzzpor4NIGHkK5yeZaixBXI9+W+WHKAuI/ONLuTW/B2IWpo
         SqndepS2c0VTufAItIiGs5A0S/W+mWuSM2DEiYMe5JX3Z2w+p1zjUiaPV1A5v7ia2z7P
         8E1JyyEAgCtPsQ/156Rw3UaCgSXgwPlwPgqhDidhTnRXkQD3SsLv4bZzIWdJ2RR/1NhR
         y6YCsOERPsazVHLj59lfCglP30w+4jqyZ5wyAKaSHzK1qj71D5AlQ7WGOcJCH5nGcZBn
         1y7g==
X-Forwarded-Encrypted: i=2; AJvYcCUlLvfafWV/mVhQViA3XEBE5TqIGaUHfvRl72wIig+mBqGCdeHPDmcHkRt5nvk23pYqKxXI2A==@lfdr.de
X-Gm-Message-State: AOJu0YwTxhxeRHNpEqz7LJZlUupZIapg+nP6Ryk+3743huCp+Sm/eyoF
	FSuE14IEBaw0qMlIaFN5oEjpcAC6RpAx+URj/q04Iw5QIHBQal3V
X-Google-Smtp-Source: AGHT+IHWhP36lV1qtnNNt86cPavPFATIJD9/Fn1stWgz0bjnITrRBODDG8EIjtVVlxIbNkR4+2fPHA==
X-Received: by 2002:a17:902:ec88:b0:20c:95d9:25e6 with SMTP id d9443c01a7336-20e5a8a2685mr10888935ad.34.1729214425909;
        Thu, 17 Oct 2024 18:20:25 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:903:228f:b0:20c:5fda:7b55 with SMTP id
 d9443c01a7336-20d47b3672els15092785ad.2.-pod-prod-08-us; Thu, 17 Oct 2024
 18:20:25 -0700 (PDT)
X-Received: by 2002:a17:90a:1f43:b0:2e2:c40c:6e8e with SMTP id 98e67ed59e1d1-2e561a31bc3mr1098938a91.34.1729214424849;
        Thu, 17 Oct 2024 18:20:24 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1729214424; cv=none;
        d=google.com; s=arc-20240605;
        b=iyeCFm6cggyNF4D9uI/hr9yiHOHlLYkNOITG411rAl2sJbkeWbCgF3BJxuxrSkrub3
         ej/2skrwViD8ec+gUZPmW1Ws2R58VwaigD8ZyMtLPa4IvkGsxswvsFNNrK6Tjc2JRkkd
         RNmOITaU/FjVEQeZRhSWrRPwkivyN/cZFHUFzppo+/P6z1k0P2GzROYOSad3EWsmUN0F
         iWUlKaUULZOO1K1tqrQtyjiLrIMt+1oKUqSN1V49wNyEKdw9Qn4oqJTuwYCgaOFfM8cT
         G4FkcB43nZKLm2UKsLvJbCHSWRF3q0UUihGOSgCQP+PNqep0rXIRJNOcJ8y/SBoCaWvL
         OYUw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from:dkim-signature;
        bh=DfJphSyv1wXmEZ6FK8u1ZsrbRKxuT0jYaSUiiAgOwOA=;
        fh=uQCsmYQr+KJEcG63Y45gsyDulzJl/B4EdEfpx8XrGGo=;
        b=LxfULDAtq+azF3R8y1TTwNayYdro1p5cx8ZlCtl/hl0nC3AESE2DTiYh53prJrN8s0
         9mffCyr4GGQ2ScoksLzaN7UsrWrI2djyFZm/fF3GyMZsWDnN/L3Kt146Ok4s8D7KikOg
         g+GOlQqdvvI91w8XE4L8X8N++mb9VenWTyJOB92FISb7Coy9PFUDTnZfID50Ya1XWtpA
         yQ31OR7dEavM/2xi3rhqoAzPwlcfYpTslrhRJsAEwMHGyFygQN8zjiPfXbjtc2d4ZgvL
         fyhSruqXGs0SN+/R0tRrpCL8RbC0Yy5MZLsTmuXnK7vFP4Q9JIElGdZY0lYNCVOK8AUr
         WQXg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=PySw1K18;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-2e56129dbcdsi26748a91.3.2024.10.17.18.20.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 17 Oct 2024 18:20:24 -0700 (PDT)
Received-SPF: pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id ACAF55C5BDF
	for <kasan-dev@googlegroups.com>; Fri, 18 Oct 2024 01:20:19 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id D42E3C4CEC7
	for <kasan-dev@googlegroups.com>; Fri, 18 Oct 2024 01:20:23 +0000 (UTC)
Received: by aws-us-west-2-korg-bugzilla-1.web.codeaurora.org (Postfix, from userid 48)
	id CBA91C53BC2; Fri, 18 Oct 2024 01:20:23 +0000 (UTC)
From: bugzilla-daemon via kasan-dev <kasan-dev@googlegroups.com>
To: kasan-dev@googlegroups.com
Subject: [Bug 218854] KASAN (sw-tags): multiple issues with GCC 13
Date: Fri, 18 Oct 2024 01:20:23 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: changed
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Memory Management
X-Bugzilla-Component: Sanitizers
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: normal
X-Bugzilla-Who: pinskia@gcc.gnu.org
X-Bugzilla-Status: NEW
X-Bugzilla-Resolution: 
X-Bugzilla-Priority: P3
X-Bugzilla-Assigned-To: mm_sanitizers@kernel-bugs.kernel.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: cc
Message-ID: <bug-218854-199747-w8kV3WX8p3@https.bugzilla.kernel.org/>
In-Reply-To: <bug-218854-199747@https.bugzilla.kernel.org/>
References: <bug-218854-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=PySw1K18;       spf=pass
 (google.com: domain of bugzilla-daemon@kernel.org designates
 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: bugzilla-daemon@kernel.org
Reply-To: bugzilla-daemon@kernel.org
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

https://bugzilla.kernel.org/show_bug.cgi?id=218854

Andrew Thomas Pinski (pinskia@gcc.gnu.org) changed:

           What    |Removed                     |Added
----------------------------------------------------------------------------
                 CC|                            |pinskia@gcc.gnu.org

--- Comment #2 from Andrew Thomas Pinski (pinskia@gcc.gnu.org) ---
"    I believe this is a compiler bug, as there doesn't seem to be a
    separate attribute to prevent instrumentation in this mode.
"
At least the above is not true.
`__attribute__((no_sanitize("hwaddress")))` and
`__attribute__((no_sanitize("kernel-hwaddress")))`

Turns off hwasan for the function for GCC.

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-218854-199747-w8kV3WX8p3%40https.bugzilla.kernel.org/.
