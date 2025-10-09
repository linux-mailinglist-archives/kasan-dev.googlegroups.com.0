Return-Path: <kasan-dev+bncBAABB6N3T7DQMGQEAUF3H2I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3c.google.com (mail-oa1-x3c.google.com [IPv6:2001:4860:4864:20::3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 02CEEBC9FA8
	for <lists+kasan-dev@lfdr.de>; Thu, 09 Oct 2025 18:08:27 +0200 (CEST)
Received: by mail-oa1-x3c.google.com with SMTP id 586e51a60fabf-34c14f3b822sf6279559fac.1
        for <lists+kasan-dev@lfdr.de>; Thu, 09 Oct 2025 09:08:26 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1760026105; cv=pass;
        d=google.com; s=arc-20240605;
        b=DpZylsUrTVMGdo5MdF+FlfCpa0n8lrR+fUuxICxB0Z2IB32NWWKhXzDp71IC2j+vWl
         najJDnBre/DLAtg6NEHE2vIwh+A7Pz39j0Su/ZraqAs3i4fGoMChndj92m77BhAtkC1C
         gj6yu/1d0JUAyxJjhDD2Hs4jF/R4bOfBUJzFPxh8SYQFU+uT3CQDrCBV6JpfPuivuuxp
         UTlNmiTMyUGSqSuBG9OgGyIKAnQqJyvhqGbGx1EBSNcco1XKykduQRA1FDS/9TOlEpmD
         Nbs/+2m5LcVm2fEbp5pxQgtri+doax1hi/pYMudns5jQE2X+mO2ratFkz3CPDZGOmV7C
         uAeg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:dkim-signature;
        bh=49lLbnq+ahL0FnH4Xq5KLMRacxC2zSIazilfeAzk6Lw=;
        fh=tLcW8HZSCK+wgk18aQlgEDNppuLjelDr+C8Lr2Dwyvo=;
        b=PoLU33RT3GjqurJSIeAy8U59H1utQfuWx04bWsKxN8zqRgzh9vk58nQxbTetnT37io
         4ilXiYAC4v1YIC+7wWliwBIOxYCug3N6EKw6ki1+36HxWeiTqaRr6veIr8YWBa8O4w5B
         slZkKp48mfs0zf9DYnuo7t/m6xvHxwdqQYapW33sAvKcrSqBpB8RHnnUPFIPIDHSNDTR
         fyp1DrrYq94QjAxAVJy0QvDztPweM0qLnchbzhEyK7WubDS7x2GhBsFDJinoKa9eVJ24
         rbqrpkOfnwakzQD+3mLevwkOxGrH/YEhRvO0LrTRRLSzNso1nJiW/dLp9KTk582aLVlt
         J4Hg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=tEaaNzlR;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1760026105; x=1760630905; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:from:to:cc:subject:date:message-id:reply-to;
        bh=49lLbnq+ahL0FnH4Xq5KLMRacxC2zSIazilfeAzk6Lw=;
        b=MTCOHxPVon7KABsZzutSUniCuFaqIicfwKHj3mGvykslSuYOrfftRwj3du3cS6ZAH/
         dPuUBZ0fSodeZZ0qfbljAb8dSBwmttMZOJbLRRaPN35ATRZzW0W1XuoE7U33gs//+GFK
         Y+r0oOj9rOX+RDF2JYBAt4uaiA72DgI5lXCn/5Y+lUqITEoD9LU/vWeap0WaqHDVDnSf
         SXmwP5OC6EFYkz8hvhcQFO8DBPSY/dqvBcDPEFgg7lD1Qugf0zKM6/2IA0VZZif37zDc
         8yqADAbZ+08mM6UC1z+4QPeLqh0sPG7UAmqnC68OcpPQ8zVRZjjU9i5zOpm540rIFbI1
         x7Ww==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1760026105; x=1760630905;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=49lLbnq+ahL0FnH4Xq5KLMRacxC2zSIazilfeAzk6Lw=;
        b=sUoIrLzvH1xSIa8yoGv7epQKhMscZ/eA+e8UhaHkgkcMI5JWQ/cLiyYKgtLRZmZSyp
         4fd6Z2WzSXmiro5b5+JUwjRn+mbxYOEL4RB8Yu0P82FXbQJk0JfwQf5gfvfVy87wwnML
         nH/niRH12ae57s8ByFSw2ffls46cVinh7Lk7jX0BXV6TrjANsRTDnGojMwDDGEPm3yD6
         DiudZP9ixbY2YqumPChcTvhpzWrUDuaZDPuLama9BxOhf6p6zZDLvhu/IK3ehKE36qBu
         89S7DN0UmW+TWfQX26UVm624joGHViq46Orbji3PEqxVkMQNRfTfS4ZzuYHfmPGs47SB
         yoAQ==
X-Forwarded-Encrypted: i=2; AJvYcCWLBpZJJyx2On9fgU8ggKO1QHpQtsjX/ACzvRfvNQxX1tof/glIwmDAKUq0Y4FhYfoTSwgqow==@lfdr.de
X-Gm-Message-State: AOJu0YyU2P6M6jj4d4JixExsqeQsiovrOv8oisd97AhA7LfStaPpuK0X
	HB6DJVVHH5ksz2LLoRt81qMiWn4pg7/x+AmXhcu20FE4JfhLEhQoPh5U
X-Google-Smtp-Source: AGHT+IEs/CsZPMMQ+R+MQE3hrodokAy6ruCF2s1ffK5dtLBw9NUK1DAHEwnXUIyrVhObFK2fvIEAhQ==
X-Received: by 2002:a05:6870:6493:b0:38a:9333:9688 with SMTP id 586e51a60fabf-3c0f590ff59mr3872908fac.18.1760026105465;
        Thu, 09 Oct 2025 09:08:25 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="ARHlJd7fDmgUFC6bEgi7zOBWoSLgYFvbZqMSVHM78peIU9WJ9A=="
Received: by 2002:a05:6870:c08e:b0:35a:ce0a:d0a3 with SMTP id
 586e51a60fabf-3c720409c1als974278fac.0.-pod-prod-08-us; Thu, 09 Oct 2025
 09:08:24 -0700 (PDT)
X-Received: by 2002:a05:6808:1907:b0:441:8f74:fca with SMTP id 5614622812f47-4418f741ef5mr1156650b6e.55.1760026104548;
        Thu, 09 Oct 2025 09:08:24 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1760026104; cv=none;
        d=google.com; s=arc-20240605;
        b=GnkJ57vKu0c80LDxltW0oiB4D5h58kjA4vMJ2MlwaaYgGTPcruRzUlYFlWCz8vmU7V
         unCFvMRcEXQjuo3hqJFWk3vyFbH/RtFvKugp3zBb0jXUzclh5HczB/Vpk0o946O+Mi5F
         7itddo3FGGwmoIYPgpK9FBWgBV1hY4st35We9jRneEtMdxgQ57VY8CFNLlKXGIDPHHIz
         LzdQ+xQvF4sekgPFK57QBMMrSxSy82OJfpTwxeHrYVWviC9AmPRzaymLWLXmoOxM8iji
         /pSFYFpdFpc1tTJFdocYYgaOJuHRjWLox0Gfvz8S7PbQhNO+GP3tcgIzy0O9SLlTZOD4
         wumw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from:dkim-signature;
        bh=1ASAKy/uQNl0MrecYe0zYoi9r4LqoiFmMOyD948EIzY=;
        fh=uQCsmYQr+KJEcG63Y45gsyDulzJl/B4EdEfpx8XrGGo=;
        b=jIHx2wP32ErCwbCIAuLuvs46ewhU8I5xHIOwwMbQGH72LpgpP/2s22xKh5osT8mE5a
         c78tKh2FAv1XIEOJNBN92B6JO9JxXJPOVE8iOUfzPQZSsbZYvQ+YmmkRlyvJeGRhj3+I
         lvXUC+TP4LrWtFLYo6XNWnWW/K8eg2hlFe+RwRM4aZ1rM/+3k0wTz2gIlzIcNWXOhkeX
         rCr1NT7pZzl86dcMbjDI+kiSW+9I/k63oYj6nJAllvUpwyNs0L/xxLp1R1A4SgtQL0v8
         56N8k5A9Ws1W/IA5Pqx00K8LwB3yctvuFFQkjUWLcgpcAzBxy98+P1wXUy3PiRuNJd4t
         NhUQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=tEaaNzlR;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from tor.source.kernel.org (tor.source.kernel.org. [2600:3c04:e001:324:0:1991:8:25])
        by gmr-mx.google.com with ESMTPS id 5614622812f47-4418977bd09si3449b6e.5.2025.10.09.09.08.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 09 Oct 2025 09:08:24 -0700 (PDT)
Received-SPF: pass (google.com: domain of bugzilla-daemon@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) client-ip=2600:3c04:e001:324:0:1991:8:25;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by tor.source.kernel.org (Postfix) with ESMTP id D32026239B
	for <kasan-dev@googlegroups.com>; Thu,  9 Oct 2025 16:08:23 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id 85BC0C4CEF7
	for <kasan-dev@googlegroups.com>; Thu,  9 Oct 2025 16:08:23 +0000 (UTC)
Received: by aws-us-west-2-korg-bugzilla-1.web.codeaurora.org (Postfix, from userid 48)
	id 78C59C53BC5; Thu,  9 Oct 2025 16:08:23 +0000 (UTC)
From: bugzilla-daemon via kasan-dev <kasan-dev@googlegroups.com>
To: kasan-dev@googlegroups.com
Subject: [Bug 217049] KASAN: unify kasan_arch_is_ready with kasan_enabled
Date: Thu, 09 Oct 2025 16:08:23 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: changed
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Memory Management
X-Bugzilla-Component: Sanitizers
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: normal
X-Bugzilla-Who: snovitoll@gmail.com
X-Bugzilla-Status: NEW
X-Bugzilla-Resolution: 
X-Bugzilla-Priority: P1
X-Bugzilla-Assigned-To: mm_sanitizers@kernel-bugs.kernel.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: 
Message-ID: <bug-217049-199747-nT1v5uEiHR@https.bugzilla.kernel.org/>
In-Reply-To: <bug-217049-199747@https.bugzilla.kernel.org/>
References: <bug-217049-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=tEaaNzlR;       spf=pass
 (google.com: domain of bugzilla-daemon@kernel.org designates
 2600:3c04:e001:324:0:1991:8:25 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
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

https://bugzilla.kernel.org/show_bug.cgi?id=217049

--- Comment #4 from Sabyrzhan Tasbolatov (snovitoll@gmail.com) ---
Hello,

This can be closed. Related commits in the mainline are:

https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=1e338f4d99e6814ede16bad1db1cc463aad8032c
https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=e45085f2673b165687a3874d8e868437683fa8e4

Thanks!

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/bug-217049-199747-nT1v5uEiHR%40https.bugzilla.kernel.org/.
