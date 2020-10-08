Return-Path: <kasan-dev+bncBC24VNFHTMIBB57T7P5QKGQEZIZSVTI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x539.google.com (mail-pg1-x539.google.com [IPv6:2607:f8b0:4864:20::539])
	by mail.lfdr.de (Postfix) with ESMTPS id 16DB3287374
	for <lists+kasan-dev@lfdr.de>; Thu,  8 Oct 2020 13:37:29 +0200 (CEST)
Received: by mail-pg1-x539.google.com with SMTP id c3sf3597118pgj.5
        for <lists+kasan-dev@lfdr.de>; Thu, 08 Oct 2020 04:37:29 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1602157047; cv=pass;
        d=google.com; s=arc-20160816;
        b=V6zDVEvO+5HS41xQxe5JZLj15mhoG0Zq5RPkrW0t3DuR2hO+P3XJE3d9kDEMWubsu9
         1HAuBiPCfaRC48cT3JJ0tEkb+Uu12+rBR/t2+8ua6a79nujmOZbdEYrdnJoPA5voU9Fh
         PnbgYnfyLCAmDwG9bPiqe0UTyvUoZTVpeuW+UhGa/ZLVXaejLxrvlcs5Q8fo75rI22Ox
         Qh4QLgsocDtqnQ4kcE2HCKLhwIHm/cxyBJGMP8kz0HQsa6EswK0wR0Npb9ffE7sRdQCm
         KzcchP8a10y3rK4/LvUJ5/77AmlAssP0ugmCJVhfpMb7TSsvlcECLdfsB7YYtqyUDitL
         oYCg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=9+KIGt/RRUpwwuCzGwJ6PXxy2JDQ5Z84vM8iH68PUAQ=;
        b=00yvH+UgivMxkXQCIYXWHPYZWb3o9BD2V4E6L929/m6Yh7IKeizlqDW32PKR8ULDlV
         lJzKaFT93Yt8jhRuZLMTC5PU0wfe8mYAiTvOqGQuy73KZ/mMgLZVDHja2cyzMRiOfVTU
         uD7xCDUHAOAbQ6mVWGE3JZqFxkM7Wr4hBNhFVVc8die1CPQe7nP3xGyBvyqFxoLKP2EF
         rBLOyw3GO6gmif9o1pkZGG7rlf8ihgnk86/AO/E9l2zzEyUvZg3J7dHIlTYIAKtOuaXo
         p9VDfPyXmnzUhYfHAzNztNeS2YyvqFrKjkZnbIf+013keOJRMqy6bzQzGVkX9RtyPYqf
         tlZw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=mmdr=dp=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=MmDR=DP=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:date:message-id:in-reply-to:references
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=9+KIGt/RRUpwwuCzGwJ6PXxy2JDQ5Z84vM8iH68PUAQ=;
        b=GRFeZSuAbEl9D/mTgqSoyC7fQXiGV9E2GfPpA5u3XvFnZfHr4hK1gwD/PSivrxTFfh
         VEULpwrTraBcOx487xzMEPILudJWgBTPRfJcwmCoKLLVIDyirWIxT/R4IKU0cGwnVVle
         RiXDpAL6gmm96RBlibWsH0PljtciTrEdB5dd0ZY/apVxgz01IoXe79j0E7JsFhJG8OyW
         6Hyx63Ndano9FkxsyoiZ+tgp0lljQrqMy71e0SUNZwcJXFiaLBTnsy6bLS/DSGouvWbp
         budQ4grhSxEn74tzJlOv6YCUMIw/thhMbyKoNBWEjAUni2haPIZroKvxhvukdm8CA+IB
         B/Yg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :in-reply-to:references:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=9+KIGt/RRUpwwuCzGwJ6PXxy2JDQ5Z84vM8iH68PUAQ=;
        b=QBwerYHQS5+L4NIndsNCuWDsA5mcrJzDYPezqphxto2QwPozS8IZhIOXqiKRWd6m1e
         kSubV5nEoMSbN4J0UjYAJITOJqMvopR59hNvRDbBCZNgml7nK/YrsrHkv7crWKWw35dP
         IwYp55HlExStB5Qn51XeGV+JkSqCGv9H3sQjvDhdms1yUoZp1xIMl5HJOnrvXG7hzJPb
         tTBI6LCeRDpeUWE7vWPx9ljun5pe5SqUTVmGMDoFwFoYf004w05DiF2n3uY9m4AU3Sa3
         EG96YczW/1zSWwXP5I8/aO6lql229ATnTa8KiQxZp5BPVxZxBQrT8iQjLPs5NxFAxRNk
         FKyQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5327v89q3P4/Y1mJyJb7PN9BtDnlfHPt8aLnoeVtBaRUCIBXrFDn
	2jRx7CiCGG1fK1AFeBQPBiY=
X-Google-Smtp-Source: ABdhPJxOwNQcGXwkGLKWO2aRDF4ug0SjDAdCqOUcXa5vKJVFVTfmG5CvNOqYIh5n1YvW+xJKdJ9Heg==
X-Received: by 2002:a17:90a:1bc3:: with SMTP id r3mr4458493pjr.196.1602157047586;
        Thu, 08 Oct 2020 04:37:27 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a65:4547:: with SMTP id x7ls2119369pgr.2.gmail; Thu, 08 Oct
 2020 04:37:27 -0700 (PDT)
X-Received: by 2002:a62:1a95:0:b029:151:d47e:119b with SMTP id a143-20020a621a950000b0290151d47e119bmr7165437pfa.46.1602157046881;
        Thu, 08 Oct 2020 04:37:26 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1602157046; cv=none;
        d=google.com; s=arc-20160816;
        b=QbVxLxBFGmuUAE5ivh1XqdzvXeZY6qG/Xa5rjMQsw5q3XccZUMXf6M6XggXITFFt4+
         E/2W8qUay2UB3OcCgsAAMDXgR4+SiUCgo2fCUIl+qto79wOEgCvabON210CEZjFFq8Ch
         JFEzV4WrRn/4jhCaJn3LQlOzMr7we0pS1iU7sOHAqmfLPwKYlFWAGHnz3KCGtmvqRDbD
         G5iYF5Ac0OkYIAWaKRLHAz68/2EA9Em6T1Jk8cczOsWS7g8tMSKWLxepnRjqmA2AOa8n
         ua/4xzrKU5dLOjyhdm1pWfBrEUtNiRxF9fJKZwFlAAT1x3CqJhpjziLbp7vteef/Lo2E
         WTeQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from;
        bh=WYecEjIj82/H+nyh/ITAQ+NY3vXnWO0e14b/oU/M6y0=;
        b=AZodXxsL1tlEJtyQ0yeHNnFo2rixN8xwkwd8SCvQG4J4aRWYQT7kAh8jbh78Zf4AOl
         KrjWJrpGT7GOEpPL/00UnNpjtk6slDX0te8kNVUcMqVG1KX7vtQbmSkwQT0H2rmDawhP
         b7SSHG7pQlLppOVu+NakaD03rzhOxstFrqf2tUgOmePsNJWfQKWqkeMOZy+P4e/7JuMJ
         tz8rNbKDLBx3AF5ZUrh8Y8JBr/rYQT6gfQ5Hksa6uePW/vBawqp5Ga+q+JBXwDEqy2K3
         XEYCJ7cgdhp4H5wXY2qShEm/pUOrPhPr3towMhnI7G3SzS9qt1c4I2BIfkJXoz04vErk
         7hTQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=mmdr=dp=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=MmDR=DP=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id h10si336570pgm.4.2020.10.08.04.37.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 08 Oct 2020 04:37:26 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=mmdr=dp=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 206267] KASAN: missed checks in copy_to/from_user
Date: Thu, 08 Oct 2020 11:37:26 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: changed
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Memory Management
X-Bugzilla-Component: Sanitizers
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: enhancement
X-Bugzilla-Who: a.nogikh@gmail.com
X-Bugzilla-Status: NEW
X-Bugzilla-Resolution: 
X-Bugzilla-Priority: P1
X-Bugzilla-Assigned-To: mm_sanitizers@kernel-bugs.kernel.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: cc
Message-ID: <bug-206267-199747-0tld5MPqeM@https.bugzilla.kernel.org/>
In-Reply-To: <bug-206267-199747@https.bugzilla.kernel.org/>
References: <bug-206267-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@bugzilla.kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of srs0=mmdr=dp=bugzilla.kernel.org=bugzilla-daemon@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=MmDR=DP=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
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

https://bugzilla.kernel.org/show_bug.cgi?id=206267

Aleksandr Nogikh (a.nogikh@gmail.com) changed:

           What    |Removed                     |Added
----------------------------------------------------------------------------
                 CC|                            |a.nogikh@gmail.com

--- Comment #1 from Aleksandr Nogikh (a.nogikh@gmail.com) ---
copy_to_user verifies the target memory address by calling access_ok, same for
cope_from_user. Doesn't it eliminate the possibility of accessing kernel memory
space?

-- 
You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-206267-199747-0tld5MPqeM%40https.bugzilla.kernel.org/.
