Return-Path: <kasan-dev+bncBAABBLPDXS3QMGQEX6GO3HY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc39.google.com (mail-oo1-xc39.google.com [IPv6:2607:f8b0:4864:20::c39])
	by mail.lfdr.de (Postfix) with ESMTPS id E5C6B97DEE2
	for <lists+kasan-dev@lfdr.de>; Sat, 21 Sep 2024 22:50:55 +0200 (CEST)
Received: by mail-oo1-xc39.google.com with SMTP id 006d021491bc7-5e3ad854e02sf2028792eaf.1
        for <lists+kasan-dev@lfdr.de>; Sat, 21 Sep 2024 13:50:55 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1726951854; cv=pass;
        d=google.com; s=arc-20240605;
        b=br0lu313B69UcpF41HDf+U768SP7ZE02pp+c6ber20TBwCaoQbsLC0cYtqQo5cSPq8
         xlQymGyxICcGZjFRDXD4YG0gHtMMVOSkB6gyxjXn9rNIUj568sx3+6TM+y1oPARBXNl8
         ezYHbDvmstE57+yWTxf2XYZgNJdr4ueIO0Fx7uFQI1oFNIWY7LiBWVlYq5XJdPPUGlxe
         vLRWrcvF6RMys++uGOqnVhQD38YWSI6TxYPFiqWVYP4N+g1n1vmss1ntXZBKZ1qhX4is
         60kXStOfPDVrG5otraVbWo1UtEvWnBDwRXMt4clp/KjVShkbGlUGgsD6CXm4Ax0rF8kB
         /nSw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:dkim-signature;
        bh=zjFiqIubQs9GkcFzuY3jt9Wr77fLd5cEptoe9GDuAHM=;
        fh=TA7HcceytA1pDEfT8ecV0F+21grn5xeVEZcOR/lFyfI=;
        b=EI+thQ3fH1NoWa9ROf4PbfYeJpeOqRiGE/cNWPDTrxIsQ9fSGrBbWe1sGEc//fLcLN
         lknIu83RaHjDFM8r/0Qr6DGWf1O0d0EjrrgUDSumg0Pf3am9guUhRYI3Eh8ISR9mX6r0
         DS/hRS/3LJOYXPCnvvPGolRS+WSoRH7SXX+jwG3tljKMb2lMsoAIlyEmG9SNX9ZdkxVx
         WaWP2x0O4BZYbRzKC48/BNnxb8H+qByspxDqY/1GHugDNcItgo5PvJjPa/NEULzdlzNy
         rvgRmK7la3GNny1XQslA5iAZWB8fpHF0WMDQBGBokS4SD1KXcM//ZUcTT1CM22C5XVVa
         kxVQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=DTv1HqZ3;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 147.75.193.91 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1726951854; x=1727556654; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:from:to:cc:subject:date:message-id:reply-to;
        bh=zjFiqIubQs9GkcFzuY3jt9Wr77fLd5cEptoe9GDuAHM=;
        b=Pxas5Gj7erCNlHXdWU9ImQOjRjRasUF4XfZGNtGpVz5+QgBJxIeYMhmS9dxU33TAtQ
         Z+6aF6en6ErIrDZEO+0mkHccuItP1wR03WBDTQh2hi5MivjijrBiBPXX7HvWm1J56em9
         NiAMm1lxcU6LUhTK19REaTEkzyaIPqMnBJpYA/KOTs4bIDLoljiAiqiftTgvy6tZ8ZIH
         uI4q+NCON/fslah1479w4TDIYTOTwB7EoBzkru9kWjMd3/U1tKIXqesQwljzrAeWnzQG
         H0t5gS3IyJCW1/RfzjqNZkS0maK6cULxFMcf8YNKyLBkmUozlXQscrkCzEYvMH4kV8Ed
         CY6g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1726951854; x=1727556654;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=zjFiqIubQs9GkcFzuY3jt9Wr77fLd5cEptoe9GDuAHM=;
        b=t7laCQQdFkKaH9ORUVeqZ3OzcSpl1RwGLVTAg8+n7IvuBEGnBTuQOSygigeOaumTjT
         YyrtJPHP2uvA6HNg4cwKWX4SW73qJAgnDHE250sIzpnWm/emthVklkKCPq7OM2YE88Zc
         vfNbHXr+4APVnbYCTj4EN20KKFkhEn8DXFAyfaKfC6R+1aEb2K2AiMQCvmQnGfi7SMoN
         byaelrT+gX1kVWiqQ74ylfrU5E2G4sOlyk5qryWxDFDpIGZTh8LT1+kae7ysSv5hAVgJ
         TCY5Rk/rsV8pzmXYRl4XvY3VMdbzUWhR8lqqWkWR887RS6w5qHIwNGfCF3a1GTGZ/twG
         bNWQ==
X-Forwarded-Encrypted: i=2; AJvYcCVd10bS4ts4MvC13bN9ksB8bAIErgzxfxcJ/7P2kiyn5WI8PPxHxE1AscslIbT9vjAFPMYnuQ==@lfdr.de
X-Gm-Message-State: AOJu0YySdvBfewx88mKeK91aCjqll4np2Aap4UrMAG0aF29+xbLpZo5H
	6iPGxEj9hzvVLIDg2t2M6MKMcz3Hp3hE5aqIcX4pNAqtD+fylaJH
X-Google-Smtp-Source: AGHT+IF70tDPIBEl7Qifhguiokv4kP5ofR93c+zqE/DGCnL3Hwi6CX622hF8BgA5s/H1eKGL79GstQ==
X-Received: by 2002:a05:6808:2e97:b0:3e0:6864:52d5 with SMTP id 5614622812f47-3e272951ae9mr4882711b6e.27.1726951853834;
        Sat, 21 Sep 2024 13:50:53 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:9d94:b0:25e:160c:c90 with SMTP id
 586e51a60fabf-27d09345568ls2315559fac.2.-pod-prod-08-us; Sat, 21 Sep 2024
 13:50:53 -0700 (PDT)
X-Received: by 2002:a05:6870:3124:b0:269:2708:afed with SMTP id 586e51a60fabf-2803d0e89f5mr4137117fac.30.1726951853062;
        Sat, 21 Sep 2024 13:50:53 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1726951853; cv=none;
        d=google.com; s=arc-20240605;
        b=cgy19bqqBwxGBHOuyCHabQAVqRM50bjk19/w1vK7s+ZUkRYYEjY07o471aJ0TWpVkx
         1hX+2Cgg7C5tFeymo23pbcImaGFdEv4N/ZSfwDC0FP3c1LZlf3573pbvpjOMpROWmh5f
         HFlX9d41kkQA4SonS4XePiXFOTczgAz0r1vkBJjKQX1zvAaNQUkdqmJIoicyyVAl7GBz
         zQymIY6heNC/cczxr+1EdP1L/XSd7fP6fStW9r1Dm5EPg63+KYQ7EnNBAoQTvgT3X4xi
         z8O+kQ8xhn4OAHi60DbJ61tz2tN0KXld5bUq46QDl/1m4HU7QK3rMZDCm5RtyptMlznk
         rQ8A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from:dkim-signature;
        bh=tJF00AYv+ML3W/AbahSSBK6yQSglLpqkwP3YcTJlk1U=;
        fh=uQCsmYQr+KJEcG63Y45gsyDulzJl/B4EdEfpx8XrGGo=;
        b=OaJWXg+w87qAsV+N/yHtstnxcOuGPFAkzSx40zwAOdQQud353qYdFTYkQxn1s+Hc/u
         xYSQwS3Tv3eqDbi6DR/HX8RIsDtRc/HfpyN1A2amCDrUAPmK7xirCJj/8Gsc95oQn7AJ
         u3ufCp9+Sz0HsLYkX+gnypHSMY5C7JhIuLneIw0KH48T8ciwWvc3JJcDMu8j+YwypXY2
         peHfG5qgdQnJSr1KE3RKVQa8iRlHtXbnel1CYjcAJWkiX3BHUDRhgrszzVPWydXB8UMr
         xtud7x1SYQYfcGr91e60MQWsH3nqeJikmGRHAKnAlrWhRzmxtzX7QoYSbNAWSEDGRREm
         8XEg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=DTv1HqZ3;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 147.75.193.91 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from nyc.source.kernel.org (nyc.source.kernel.org. [147.75.193.91])
        by gmr-mx.google.com with ESMTPS id 46e09a7af769-71389bf0cf4si279701a34.4.2024.09.21.13.50.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sat, 21 Sep 2024 13:50:53 -0700 (PDT)
Received-SPF: pass (google.com: domain of bugzilla-daemon@kernel.org designates 147.75.193.91 as permitted sender) client-ip=147.75.193.91;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by nyc.source.kernel.org (Postfix) with ESMTP id 51D52A4011F
	for <kasan-dev@googlegroups.com>; Sat, 21 Sep 2024 20:50:44 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id 0CE18C4CECD
	for <kasan-dev@googlegroups.com>; Sat, 21 Sep 2024 20:50:52 +0000 (UTC)
Received: by aws-us-west-2-korg-bugzilla-1.web.codeaurora.org (Postfix, from userid 48)
	id F021BC53BC1; Sat, 21 Sep 2024 20:50:51 +0000 (UTC)
From: bugzilla-daemon via kasan-dev <kasan-dev@googlegroups.com>
To: kasan-dev@googlegroups.com
Subject: [Bug 212205] KASAN: port all tests to KUnit
Date: Sat, 21 Sep 2024 20:50:51 +0000
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
Message-ID: <bug-212205-199747-7afBl5gFAH@https.bugzilla.kernel.org/>
In-Reply-To: <bug-212205-199747@https.bugzilla.kernel.org/>
References: <bug-212205-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=DTv1HqZ3;       spf=pass
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

https://bugzilla.kernel.org/show_bug.cgi?id=212205

--- Comment #5 from Andrey Konovalov (andreyknvl@gmail.com) ---
KUnit now supports creating mock userspace memory mappings via kunit_vm_mmap,
so we should be able to port all tests to KUnit. See lib/usercopy_kunit.c as a
reference.

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-212205-199747-7afBl5gFAH%40https.bugzilla.kernel.org/.
