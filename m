Return-Path: <kasan-dev+bncBAABBSHGX23QMGQE6FSVJMY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-x113c.google.com (mail-yw1-x113c.google.com [IPv6:2607:f8b0:4864:20::113c])
	by mail.lfdr.de (Postfix) with ESMTPS id 5E83497E038
	for <lists+kasan-dev@lfdr.de>; Sun, 22 Sep 2024 08:03:54 +0200 (CEST)
Received: by mail-yw1-x113c.google.com with SMTP id 00721157ae682-6db7a8c6831sf52512757b3.3
        for <lists+kasan-dev@lfdr.de>; Sat, 21 Sep 2024 23:03:54 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1726985033; cv=pass;
        d=google.com; s=arc-20240605;
        b=ZOu8CbXlKcHksVju4KYnYppNsPAJ8xR65tOuVfyI3a8o1W0L4otfIG4/Iopqo4TYo2
         hSND8+UBdlkjx+vUPQ9XjkqC+ixF/T6qTHNCzB65hTHHI36rd5OpxXMUplNt1GTIk3mt
         KXhLU95ynQeaLq+mXAcfHQXTbk6LmReA6G1VclejfuHDFLNptNE/EkCnpz2vuwpO+7Jt
         sDIxhYS9I91vQq75eFEm8Is6ziV1I32xI70wJ6uMmzZOcBaWMHoGe1RS/8Mmkfl3Ze8e
         d/JXSgjCO8yBxZ43PXRFBWkKt0Aoon7FANM6hN685YRWjMyvsWdcJ14E3xHemaug8MpX
         GcKg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:dkim-signature;
        bh=hnW7irX1h0WBVwyjQ1QNbV4hK+yKCdAIlArvq3hn+iY=;
        fh=vNk6be0Hmzlx9XVNgsADFJOzGVuCDHSdX8dtM88Ejck=;
        b=NGs38fXxS9jnxlVyT2MHxyXSrATz0t/Ym4Dl02TfzT6yteiCFhoHtCfUi+oUUrFEhp
         +bg8i8kEI1OJOPxglnrGejJy8iKZHDXPCXapS1jRK1IN8jaMMWLj0b6C4wItZeUs+TxJ
         CMk9sIK1d//aL2iEAAOjuFgYGmoCkd/KH3Lqd5u8laXBfx8YGqRdF2DmpT4cDMeZvDED
         BKioiENkhO7AX63zdkL5aYOLaNunycYcPflBnHZFSr3Pf3zAYKBcD80HWt+hfguF4HiW
         iZGxskp7U78C1IuMDpf4iTNkOXr1vclSDoLtD/I8KqZNCvDuQBVO/MboLywaHacJYDD7
         v+cQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=sadb2t81;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 147.75.193.91 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1726985033; x=1727589833; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:from:to:cc:subject:date:message-id:reply-to;
        bh=hnW7irX1h0WBVwyjQ1QNbV4hK+yKCdAIlArvq3hn+iY=;
        b=rRB853vWHxj6dkKsKgYqMbssGlbsiSwLAw4bp/Z4scBoR7HFkO/UEf7SLSQGvcTGer
         x8fv41pcUwn+eSUwtHUGcEEVnGYmf9DhvB2+xLfSVHUdUY2g/+Sa35OGiqX5qCf7f2bE
         hvPA3+o75YNvDsHhHEeHtAsXgpk36n2htN5Y7zch8EQbOUu7SDOaO+pe6CX42bbV7WuP
         uWfiD+MO2pvMW+m+OOBcVbJpTpE1rFSah+Ka8sfYRcJ5/Sa5OcdFdLYTvyN1zDz9Kh3B
         HH7WjuiN4CBuk7CPb42EsWF9JlhYzlBOyT4UxTfwgbWZ2uMMwuRWgMc4iAQm6q+RqAJS
         krcg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1726985033; x=1727589833;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=hnW7irX1h0WBVwyjQ1QNbV4hK+yKCdAIlArvq3hn+iY=;
        b=hNLZVR97O3ceiqrEpii1TW2sQC2ExYTUXvcmHGb8ZpyZ6RmbZxHpL5kwsLeHQTqQ6M
         DZJ3DBuPf4eqo8mFSocywquM2rvCcL6gQfiQ/xAL9m5Q/58FEvjNBQ4XUxjhXssFh6nQ
         edsn22oDf35mG2maj2S/TebM0BV9YBRnmCpX7AIVV4WxQrFHc+4XFTGfoBJygash0r7C
         5T9cD4hM+FW6BFJqu79X6MZbRkG3x/Te073E8ze4YcrLbYWfSUv1QPJIoBsFJmqyS3UH
         kWnr9JgDHeF7uv/aG1pTAaZVblJhpbxWSSDFKsCKu4vvYkK2EEvSE43yioURSkk/y6xr
         CBCA==
X-Forwarded-Encrypted: i=2; AJvYcCUaHkTNCrPtO7J/lRhkkjB9Z7EQqdjF4PjCmzMzENYP6b/M23MrPqOv5AUlSDl41htBXqaKFA==@lfdr.de
X-Gm-Message-State: AOJu0Yzp/WQfjyI4FwsZTnSvhkoAzIexDcsDkil5Mo6jhu3cRKq8kZcT
	5Dz6YE5HWcBg2guDoOI944IlyCMoqXcfxyTijWj5kWVqQ0rc1icE
X-Google-Smtp-Source: AGHT+IH+WEsM7YIWPAbGr9fSLcSPOVo4ZxSo05cXBwi+I6KPPuSIIkxtZglWDtZi6VQJCCjb9esfVA==
X-Received: by 2002:a05:6902:2e0a:b0:e21:9746:2642 with SMTP id 3f1490d57ef6-e2252fb722amr4722107276.50.1726985032667;
        Sat, 21 Sep 2024 23:03:52 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:84c8:0:b0:e22:5721:cd30 with SMTP id 3f1490d57ef6-e225721cee4ls714103276.0.-pod-prod-07-us;
 Sat, 21 Sep 2024 23:03:52 -0700 (PDT)
X-Received: by 2002:a05:690c:f8f:b0:6dd:d2c5:b2d with SMTP id 00721157ae682-6dff2710c72mr61716077b3.4.1726985032046;
        Sat, 21 Sep 2024 23:03:52 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1726985032; cv=none;
        d=google.com; s=arc-20240605;
        b=MlWQ0jHAW6FJzdbJFjbRsTVyK3VtWzlcEqQeKPP58BXuf9yfRA2bz4y+/pul6WKPhs
         8QHxsT6MSRKL/TapLiaTIintGNze353DBRs38eH7cnIxaPLaEE2Tq+RHYeFnyFQD2Cpk
         EghM8N1ivVJaNHFDJQtdyoISz4B7YzwYdfH5AcLVb8C9NTAstm97SmTZb3hYiMOEkZL4
         nIB5AKTjt+Rqo2W/IYZZ3DCtq3YH5RJCyAmblToW8rYuNsCcSPI2STpjAbWLa0++SSQ5
         DMul0ZKGP/z04sicY78dfBTJUVlr4huFDDQaCtlQA5k9Rorbz+XduxDpXL1BJDRfIlvn
         K9VQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from:dkim-signature;
        bh=bbfJ5iGV0AqTu4UU6mjzqClJUH0IalBUfk5XANWBu0E=;
        fh=uQCsmYQr+KJEcG63Y45gsyDulzJl/B4EdEfpx8XrGGo=;
        b=JPfl2CdJ/A9MiZ1CqtmxCHGWbAe7QUTETlJIFU6uV1o48tTwNT2xWLBX3RLuhD7y3i
         btbzCuvZb/7AgbAz+4h4yWVg4MfHwltXCIJjrIBDm00MFu2zt8nNIo77PXDFfmQDArcc
         fUsPvObZyB9Itlb1HnDMO3SPz4cC1yEw2HdUYZXfD0nWqyNbtbaJzuQyEtKxXYMJbQcr
         O0PRShco4v68XgqutmejzN5CDF59AH/JoauRGzSKk7R9PZOOvcqJn6voHy8bjrhaCqFV
         fnF2btKyml2D0WhM3Fz5xZxSghMFYe6QoYqXexZHzOOPi3m/wo3Mq0XbwA3CiXtJeUfU
         Cg7w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=sadb2t81;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 147.75.193.91 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from nyc.source.kernel.org (nyc.source.kernel.org. [147.75.193.91])
        by gmr-mx.google.com with ESMTPS id 00721157ae682-6dbe2ab5736si10413667b3.0.2024.09.21.23.03.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sat, 21 Sep 2024 23:03:51 -0700 (PDT)
Received-SPF: pass (google.com: domain of bugzilla-daemon@kernel.org designates 147.75.193.91 as permitted sender) client-ip=147.75.193.91;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by nyc.source.kernel.org (Postfix) with ESMTP id 5E3AEA40B57
	for <kasan-dev@googlegroups.com>; Sun, 22 Sep 2024 06:03:43 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id A230FC4CECF
	for <kasan-dev@googlegroups.com>; Sun, 22 Sep 2024 06:03:50 +0000 (UTC)
Received: by aws-us-west-2-korg-bugzilla-1.web.codeaurora.org (Postfix, from userid 48)
	id 9255BC53BBF; Sun, 22 Sep 2024 06:03:50 +0000 (UTC)
From: bugzilla-daemon via kasan-dev <kasan-dev@googlegroups.com>
To: kasan-dev@googlegroups.com
Subject: [Bug 198661] KASAN: add checks to DMA transfers
Date: Sun, 22 Sep 2024 06:03:50 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: changed
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Memory Management
X-Bugzilla-Component: Sanitizers
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: enhancement
X-Bugzilla-Who: dvyukov@google.com
X-Bugzilla-Status: NEW
X-Bugzilla-Resolution: 
X-Bugzilla-Priority: P1
X-Bugzilla-Assigned-To: dvyukov@google.com
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: cc
Message-ID: <bug-198661-199747-eUje9pzlYQ@https.bugzilla.kernel.org/>
In-Reply-To: <bug-198661-199747@https.bugzilla.kernel.org/>
References: <bug-198661-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=sadb2t81;       spf=pass
 (google.com: domain of bugzilla-daemon@kernel.org designates 147.75.193.91 as
 permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
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

https://bugzilla.kernel.org/show_bug.cgi?id=198661

Dmitry Vyukov (dvyukov@google.com) changed:

           What    |Removed                     |Added
----------------------------------------------------------------------------
                 CC|                            |arnd@arndb.de,
                   |                            |dvyukov@google.com

--- Comment #2 from Dmitry Vyukov (dvyukov@google.com) ---
+Arnd, do you know where exactly DMA memory needs to be poisoned and unpoisoned
for KASAN? Or do you know who may know?

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-198661-199747-eUje9pzlYQ%40https.bugzilla.kernel.org/.
