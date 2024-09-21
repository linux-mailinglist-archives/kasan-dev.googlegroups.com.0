Return-Path: <kasan-dev+bncBAABBVHWXS3QMGQE6KAIELI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x440.google.com (mail-pf1-x440.google.com [IPv6:2607:f8b0:4864:20::440])
	by mail.lfdr.de (Postfix) with ESMTPS id 8CE8197DF16
	for <lists+kasan-dev@lfdr.de>; Sat, 21 Sep 2024 23:32:06 +0200 (CEST)
Received: by mail-pf1-x440.google.com with SMTP id d2e1a72fcca58-718db8e61bfsf5024236b3a.0
        for <lists+kasan-dev@lfdr.de>; Sat, 21 Sep 2024 14:32:06 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1726954325; cv=pass;
        d=google.com; s=arc-20240605;
        b=OhN52DdNGsKp5REdr7vwP6trgoINKO2Yt/kmwkvoLOLNDQOboRvxlPyEbtp9VIiWBo
         nsLxM7EIF+J1787idbon9ClvM6NnPTBUjslasokwGc5oPnXOgIejbhjq7gPYwuRZxPRo
         iZU7wcMm3vGQdYmcIkb+r9O61VECcYp2p1Wl/jfCPZlaz20BGVeNGqR0uqQEd+4IakZh
         KZ3ytWSWk0fjXR4WPIY2p5vxlw/AICH47PoqIWLfIheGRz/lZLBl9mU7tR7+uF+m6ZGS
         EoRlz8DwF34CCf+lXrYjLW9MBrE8vD95ReHvRwE/4f2D4Q+hwiS0WwOTDXHhD3XY6x5w
         6HpA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:dkim-signature;
        bh=Zs+YsZb9DOTeRq6Yuprq8HKFHYukIvIXLHXvlyM8XRU=;
        fh=mEV8tUuJUaI3kCCsJmiIFTC8WV86s8Lj3T/rVmdGKF8=;
        b=EPVDPBM+z0NoxeHryHYbZdJ3e3DwvFHJ86AEVhqllhgwxXZQOqv6hwxrd4NrRBOVNq
         Nl9TyK0xnAjZye+BVLOQXpnptOzQ2Mhye+V9z/q8mjXtobY2LQfBNG9+T+Xne9UDOsKP
         ktM4uLYoN0rwSgEoDZMllBJ6ky1/RtI+gpyQD3eg+E4F/6MvKbhV67IXjBpmjjhz3aL/
         E+Az5PZGQdZJA0/LA2wQgeTUvKMbrhSYtqoIiWGH4wNcEAfryqVivC9uNN/QFytTbtpw
         ehiaU8o/uOPeOrtznZkKVP8pPyYdVyeZuP+aCvSltmyPzCECV/55mVFOsIlG6u4xD7O4
         PQVw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=iQonRcZs;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1726954325; x=1727559125; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:from:to:cc:subject:date:message-id:reply-to;
        bh=Zs+YsZb9DOTeRq6Yuprq8HKFHYukIvIXLHXvlyM8XRU=;
        b=IJXyZJsbkyAagU36CWPbdeqcVIHAUYW8uex0U+YEQZ2J0O7leqAF3rnVeu+5/CiPhn
         /WlDaHC5TmV3STen2ycNdIE6IqBCleZj1dZhcLWDVBr1vHG3qogZdY+XeDcj8Z9pZ6J2
         R0pfvdNf6tK8nX83QgoFu/T6xXotDHUWkiyyI2hS/dE4P55gdsZquN9l2X/WMbJA8jVN
         Ez8Ddd67l8CJbcoCthKPsyF9yfR/U+J/cg6sgkNSLrQXDU/ci3NJf/LFaCjQNmg2L/TX
         1yj3BwqjKzyFNbVEl/0qPBA85CEZu8ZzygtuUaV83hqu5XEMNt2JDnGBO9Kc7zgf0E2l
         0lUw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1726954325; x=1727559125;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=Zs+YsZb9DOTeRq6Yuprq8HKFHYukIvIXLHXvlyM8XRU=;
        b=TC/QD0NsVqQSjviVzm8HCX9rL6Ixr9XwhGrAjtVjJRujPjUDWzM2OzHw3uSHn5ZSvm
         caJpnZpLUeeuQT1Y89GnEMhPyRliSlyh/meFw1tPQAuJUcffWsatnz8964/B6vYoTdW+
         XjpsHGIXz3Ks/z6+LwQX92C4zx+UfSOpa+wfYFoQPJcKZunPkL/xO/lNN9RP6jSCJayp
         9ziXDfIgLooE/VGwk15Yv2tYlVSNqSSy+tUfsf6II3Bdfe27P0ABA2Og6zmp6T6tDrLk
         qJIcpuAcmJ11cibDyLkJ4Pw5OCgdj5zMDuNtl2OTlPM2buyt4LliWgDGLZjfD0EwgEUz
         hQ3g==
X-Forwarded-Encrypted: i=2; AJvYcCX3iTCDAOJTclOTaXPt6Boq51lzvfDGBjnStdBH9rjkWaHuA4trkpDFiszGebeigQb3HrvmYQ==@lfdr.de
X-Gm-Message-State: AOJu0YwTObipLyGBMOBHmA1aUyNSC+uDtszuPMYu42iFeisuPtm7vwqR
	fdRn0cD/hEbbKy4ZrScyb7mun1oKZZRhuFcuaf596cikq9ZqY2Jd
X-Google-Smtp-Source: AGHT+IFDTBRQKqvDXT1Ep1N+Bj5rzDLF7slTAd1/6iQMvGih0EkYt312VmtJ3NIKbQ3/oUHXm7MfTA==
X-Received: by 2002:a05:6a21:e8f:b0:1cf:4336:5a9d with SMTP id adf61e73a8af0-1d30cb682d1mr8997441637.48.1726954324559;
        Sat, 21 Sep 2024 14:32:04 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:851:b0:714:2401:4428 with SMTP id
 d2e1a72fcca58-7198e690841ls3854836b3a.2.-pod-prod-08-us; Sat, 21 Sep 2024
 14:32:03 -0700 (PDT)
X-Received: by 2002:a05:6a00:3e18:b0:717:8ee0:4ea1 with SMTP id d2e1a72fcca58-7199cace840mr12505678b3a.0.1726954323323;
        Sat, 21 Sep 2024 14:32:03 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1726954323; cv=none;
        d=google.com; s=arc-20240605;
        b=hOCcS6YAXGreZBmPs3GO0I1/QrOt7eQoYvi8bMahDcjCqmLMTKv8k0B796pAiGESV1
         SOhMNVysI2HDMm7XE5SStfUDbMlWxxa/O/Gh8/eIh4nReFaSDOqY7TWCQjvzyYJJSy1V
         MxgPdtFlOTperF6G3oJ2TZUqymFzoS+MXOfUWA4QFY7HXjBkKXGBIJUwPBsEphrjvKmn
         k9PPihIIqRWIGchl7iVzTQqupv5rG+phSKPDRydMr53x7WL5u8Kx++GrorFHox7g01p1
         P96dbqtvI4asR6mh8CbAidDQ3sVDBkP0ZIacQDoKPQlXUHVY9X9puPYUnknXMgNpXrdX
         YRvw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from:dkim-signature;
        bh=qb5VZzbkcF3/HDd0WKcuhu5KOFvj/rYeV691e8hpHdU=;
        fh=uQCsmYQr+KJEcG63Y45gsyDulzJl/B4EdEfpx8XrGGo=;
        b=HiA+Rfu4Q1cXu+IfC0B4+5kFT7VJTpACJ3UFa2+Nk5NKP9knVJG+02agoz7p05UsFP
         uOY2BzzAlNI3BOZnPmRJzmRQ5gT8GkdMoU8Y6rULX7HUr22OlCJHsTmM4oCByuIgGqG/
         o8nWRQCOKsYIYXa4j3YYcocZbM3WV+qwuyaQhiv0i6Xm6DNvEnmP8Wm0y4DR4qQAAifM
         cjw7Y8+wyfaJhdjfLP3aF+M1QePWtFmvIZwW2/ngurpHU8c7JRz6A0teze1Qt5pYTkn2
         MpBo2fJnbtOWqFV8hE/wU42UktCwYKC0OCNxaA6a1Y9eNTMU60K78I18vwG/4k8JnHJF
         NxEA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=iQonRcZs;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id d2e1a72fcca58-719449b29f9si669232b3a.0.2024.09.21.14.32.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sat, 21 Sep 2024 14:32:03 -0700 (PDT)
Received-SPF: pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id BF7255C0548
	for <kasan-dev@googlegroups.com>; Sat, 21 Sep 2024 21:31:58 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id F2837C4CEC4
	for <kasan-dev@googlegroups.com>; Sat, 21 Sep 2024 21:32:01 +0000 (UTC)
Received: by aws-us-west-2-korg-bugzilla-1.web.codeaurora.org (Postfix, from userid 48)
	id E3122C53BC4; Sat, 21 Sep 2024 21:32:01 +0000 (UTC)
From: bugzilla-daemon via kasan-dev <kasan-dev@googlegroups.com>
To: kasan-dev@googlegroups.com
Subject: [Bug 198661] KASAN: add checks to DMA transfers
Date: Sat, 21 Sep 2024 21:32:01 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: changed
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Memory Management
X-Bugzilla-Component: Sanitizers
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: enhancement
X-Bugzilla-Who: andreyknvl@gmail.com
X-Bugzilla-Status: NEW
X-Bugzilla-Resolution: 
X-Bugzilla-Priority: P1
X-Bugzilla-Assigned-To: dvyukov@google.com
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: cc
Message-ID: <bug-198661-199747-TBA4AzGfIr@https.bugzilla.kernel.org/>
In-Reply-To: <bug-198661-199747@https.bugzilla.kernel.org/>
References: <bug-198661-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=iQonRcZs;       spf=pass
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

https://bugzilla.kernel.org/show_bug.cgi?id=198661

Andrey Konovalov (andreyknvl@gmail.com) changed:

           What    |Removed                     |Added
----------------------------------------------------------------------------
                 CC|                            |andreyknvl@gmail.com

--- Comment #1 from Andrey Konovalov (andreyknvl@gmail.com) ---
There was also a related request from kernel people during LPC: allow
temporarily marking certain ranges of memory to be inaccessible by the kernel,
as only the device is supposed to access those ranges via DMA.

This can technically be already done via kasan_un/poison_pages or other related
functions, but we might want to provide some DMA-specific wrappers. We also
need to document this interface usage use case.

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-198661-199747-TBA4AzGfIr%40https.bugzilla.kernel.org/.
