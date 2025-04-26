Return-Path: <kasan-dev+bncBAABBXVVWTAAMGQERORUISI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3c.google.com (mail-qv1-xf3c.google.com [IPv6:2607:f8b0:4864:20::f3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 55857A9DC9E
	for <lists+kasan-dev@lfdr.de>; Sat, 26 Apr 2025 19:41:52 +0200 (CEST)
Received: by mail-qv1-xf3c.google.com with SMTP id 6a1803df08f44-6e9083404b7sf60461576d6.1
        for <lists+kasan-dev@lfdr.de>; Sat, 26 Apr 2025 10:41:52 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1745689311; cv=pass;
        d=google.com; s=arc-20240605;
        b=gCs+PPgaJONJDRnB/UcflmpPV0fckgcLtq/kfuaUXkgJV9b3OlsZTWvO4ANfkHiHQ8
         l5SuS9USMqMSk1Ofaa3v1DXYmAow0eg5SiXPyHGDFevdTudEgGv1WqAfe6tIPruAwwt8
         tEAcb1v9mXpGBGym1ucA+n6Snn71PgmircFb+3ZgP+flhSQlUJpaWrKuM9uwq1kF9KaD
         Wd2fwLpl//SiY6wFToYwOOEElw3b9NQQFS7dQtFmgkeDPtmoPf9cBnWuS6KbZAkbvIOw
         faKjO9dwK5PFXop+oG/SPyVjrFRSgg9pThzeIcT5MnGngWSpDPKMHOqHHUut8l6P+HuR
         N4bQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:dkim-signature;
        bh=I1hLsluJneDcVcyYzGfWxIl8Kqd7QkM2zIaTEe6sS/M=;
        fh=2bgx4gg74R9sAgArmAKxOqDTizV9Ju+u6mzh+sx/De8=;
        b=c4E/n1t+EJHXoH5rylkVgQWSrppTKqpwRnYN2v7fHtmYpc7vU3vYZ3E3xhUuSN8jXE
         VRDbiwB2ezSkJON62ZX809S3ZhonEBCNcsqOedG1k1XYbWqy2iRyQZQBbEvUZHkCVNd7
         j6jpR1a0vY2MQtzJ2q6FIygvKH7ArpNmaGrVfGiVY0cnEyZCx8S3TR2q/tiAstOKFwNc
         5JwUCWx6KrsdzCKsS6wBelgLbAsTNd4/t5o/NV5eHRgLrcVtcPiUgWM9E5sm6G0LkQuD
         sOxQEIdrTna4JAH/iL4bmq45iX1f1J2cFVZoBwGHJPHJDe8CY9d7UV5WR3Usk54eqkek
         QOLQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=fg4XDpxM;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 147.75.193.91 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1745689311; x=1746294111; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:from:to:cc:subject:date:message-id:reply-to;
        bh=I1hLsluJneDcVcyYzGfWxIl8Kqd7QkM2zIaTEe6sS/M=;
        b=SLxZ6+S39G7wOnfg8vqlKyGrCRyzeIkeT8nO+aMLWBL/YO0Y/wvA9/8u8JwLfOyLQX
         M4MRnvxeT9AH3vLhxpzojVyfoapMHBpKLTYENW7Ja0QYiuN67CHh642A/PbIwNNl7JTD
         n4tsF54rTKXPmUUdidyV/yVZCpjF+kQxd+VOaE6gu4N333j5kXHPP9UUzPT+QJ1O+mtH
         B56/LHGg6+jmS2OeKdEWDVMqvBgf/SCYtR/zUiWvjbqkNGfDwA3IM/evZVaKGHSKbNaG
         2DJdSU+BalmcH2ESPIC0FluLgpRo5n8EH8Dey7sl2mWICLcrzONn/4gLmaWOFxSLr3Zf
         u28A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1745689311; x=1746294111;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=I1hLsluJneDcVcyYzGfWxIl8Kqd7QkM2zIaTEe6sS/M=;
        b=O0CNb5VGTw55DgrpfDRovSrKaGDjt18mQp7TpyQ1OYAs42ksfZGay3xTcdQXWGqMgQ
         z37LMFJZZpVYV2Shtw+7kjzoq9wlIEbMOONSyWECgkqE/4LHPPpwd/jsKtEcODpX3GuL
         ZTfledW6AP+Y8RDQzScylCaOsE3GfMdkMMUsUY2t2IEZVntlUqmhz2XBycDkKyvcCU2I
         FacGvFSyM6ODgS3AN5Hute8sc6Px2YlSUlGwUKHZfqSxwGERFAndaDtdLf4BSRXjtk86
         LVipHQEM74GWgsS19rvOu6Y3wMQTPzFMp2Uf4kvQXwb9284Qqz7oOdJN8PjPxMkS3ul8
         IE/g==
X-Forwarded-Encrypted: i=2; AJvYcCUxp/+ftPPyccpwn6/1DRpxI1op0kwm3sOofKaNYpx/Eok3qVDSpZq5l47jnwbZ+ja2Ik0pew==@lfdr.de
X-Gm-Message-State: AOJu0Ywetd66Eogb17Z/Nwczr766a0S+vRwR7tk6KaOgqswfyZon5T9+
	qv+eCclqQDIlH88tCLfYmzgr4U/VpfKwlCAjmKwrvaMH7POBiZoU
X-Google-Smtp-Source: AGHT+IHgGwTfRc4M9uqzJjJaRlTxXl6JHVhe1rU5OwfRCbL/SBt2Q7gZ3R932ISL9/AFSu8kM8Fydg==
X-Received: by 2002:a05:6214:500c:b0:6e8:f4d3:e8a5 with SMTP id 6a1803df08f44-6f4cb9d2cebmr112671216d6.15.1745689310899;
        Sat, 26 Apr 2025 10:41:50 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AVT/gBFV+mZqXPDEtXcy/HqOGK1li8vUiCVCXmUYZ1SyM9t5iA==
Received: by 2002:a05:6214:110d:b0:6ec:ed67:455d with SMTP id
 6a1803df08f44-6f4be390ee1ls26509786d6.1.-pod-prod-07-us; Sat, 26 Apr 2025
 10:41:50 -0700 (PDT)
X-Received: by 2002:a05:620a:d89:b0:7c5:3df0:48cf with SMTP id af79cd13be357-7c9606a18d1mr891803185a.3.1745689309989;
        Sat, 26 Apr 2025 10:41:49 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1745689309; cv=none;
        d=google.com; s=arc-20240605;
        b=BZzmnEDj1iTXbyoCfT5Y6bt9NVFJBz0CaRTqove7wl9thm1KSdlqH47+JaxNnC3D00
         veHbW+VKYdPYRucJt5Aa2XFKUeCjRVMQ5a9NKKoa16V4LCXWX6nRHMchwCJb86+nvBzN
         le+BQAkRje8GS6TKRlS6qbK5Fm7ROkM633wPoGBx5L6iXf7nCtltwgyqli0v7swrc4ix
         jNJQdzraiwJ/D2AiVDNInkLdAr+iMOKMExj8ByjOpd1bQQ/gJj0o/739gpoI/tC7M7SA
         NhhLrn+r3c96IrqfJ4J63ZcJpi/4O0QLm8hnzacxnlC+495j4UCbtQVm39rZU6o82HmU
         kdIA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from:dkim-signature;
        bh=BUxtVM9dzJSvIHHXQ5VRAJygxXmQOHPK7jrR5RwYp60=;
        fh=uQCsmYQr+KJEcG63Y45gsyDulzJl/B4EdEfpx8XrGGo=;
        b=M+i6mdG4/8OFLH1fJOIsPBBgI7mcorlduLqWCNHzuQUCtlBQ8pDnmfFHrxvZb7/7DZ
         ga/vfwCzANPnHSwE9AZjXNfP1sAdH1Vh6dWlwgJupVhRukk1xw0d/l/qh3sWOKBfXDbp
         1ld9w2mHe9vOmu1JLQXVyEvAjAIns3Mn7w0sXGaoNm94KT+2ATgXg5tqvfFfz3eVLbLk
         YVZZIbpHSSd+lh1lV7nrOyrP3u4Xx9j1mAZ+KUwC4aEO88yVDB6cmN2okWoX/ty+XK9N
         6XckdBJ9dtBYeyfvwkKyTWeh7nw/FRP6q3VYGnKKpg952CHmGYGkGDQ73acWmQ/WUoRG
         aOWQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=fg4XDpxM;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 147.75.193.91 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from nyc.source.kernel.org (nyc.source.kernel.org. [147.75.193.91])
        by gmr-mx.google.com with ESMTPS id af79cd13be357-7c958d4869csi26217085a.3.2025.04.26.10.41.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sat, 26 Apr 2025 10:41:49 -0700 (PDT)
Received-SPF: pass (google.com: domain of bugzilla-daemon@kernel.org designates 147.75.193.91 as permitted sender) client-ip=147.75.193.91;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by nyc.source.kernel.org (Postfix) with ESMTP id 7F290A4D33C
	for <kasan-dev@googlegroups.com>; Sat, 26 Apr 2025 17:36:21 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id 1627FC4CEEC
	for <kasan-dev@googlegroups.com>; Sat, 26 Apr 2025 17:41:49 +0000 (UTC)
Received: by aws-us-west-2-korg-bugzilla-1.web.codeaurora.org (Postfix, from userid 48)
	id 0B092C41614; Sat, 26 Apr 2025 17:41:49 +0000 (UTC)
From: bugzilla-daemon via kasan-dev <kasan-dev@googlegroups.com>
To: kasan-dev@googlegroups.com
Subject: [Bug 219800] KASAN (hw-tags): set KASAN_TAG_WIDTH to 4
Date: Sat, 26 Apr 2025 17:41:48 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: changed
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Memory Management
X-Bugzilla-Component: Sanitizers
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: normal
X-Bugzilla-Who: trintaeoitogc@gmail.com
X-Bugzilla-Status: NEW
X-Bugzilla-Resolution: 
X-Bugzilla-Priority: P3
X-Bugzilla-Assigned-To: mm_sanitizers@kernel-bugs.kernel.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: attachments.created
Message-ID: <bug-219800-199747-oEZ3EAR8YB@https.bugzilla.kernel.org/>
In-Reply-To: <bug-219800-199747@https.bugzilla.kernel.org/>
References: <bug-219800-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=fg4XDpxM;       spf=pass
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

https://bugzilla.kernel.org/show_bug.cgi?id=219800

--- Comment #4 from Guilherme (trintaeoitogc@gmail.com) ---
Created attachment 308023
  --> https://bugzilla.kernel.org/attachment.cgi?id=308023&action=edit
Patch for submit on mailing list

I will attach my patch here

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/bug-219800-199747-oEZ3EAR8YB%40https.bugzilla.kernel.org/.
