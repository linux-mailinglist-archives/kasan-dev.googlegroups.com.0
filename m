Return-Path: <kasan-dev+bncBAABBYN6S3FQMGQE63GXEEI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x840.google.com (mail-qt1-x840.google.com [IPv6:2607:f8b0:4864:20::840])
	by mail.lfdr.de (Postfix) with ESMTPS id 11D9CD16292
	for <lists+kasan-dev@lfdr.de>; Tue, 13 Jan 2026 02:26:59 +0100 (CET)
Received: by mail-qt1-x840.google.com with SMTP id d75a77b69052e-4f4a5dba954sf200980061cf.0
        for <lists+kasan-dev@lfdr.de>; Mon, 12 Jan 2026 17:26:59 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768267618; cv=pass;
        d=google.com; s=arc-20240605;
        b=MWk3AWr0rx5/usBOG1DRfH1lQQKxMXWnbVsauImpETpC3senrp2VQSE93TRqASXl8W
         V1g3Xm6QZ0SatHBLbWvuDgXUvY1IEnmKYJrZRXokVuu6Fz2gpMAHrMQg+pMKhuTLy4x/
         D+ddMRQJjTviWDdlgaYa5rem2Hl7vXTJnLWvCewh+ynAcYZC4g0jYZvXBVF1WNN94mw2
         CVSiO0kp0swp3fM9K4AhfB88HxGmT2WrqKz/j1QU3R+I4A8bAO/GTCPgZMm2TZ82QT54
         DvnC2PoeeDX2SpTIVKWu0tcc1JTzAOwow36wvNZlI0DIcnfe88xtBYKqoon+A1yVH3O5
         xpyw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:dkim-signature;
        bh=CpMa7XjYjb32Nk3p3q3Maf2C+vPwgOsV1lIs9Egehkw=;
        fh=ENYOxRkbMDwYKhgPhkIz9CVlU35a0ULD8r033/KdWVM=;
        b=SoB8wSR2fXLFwxDzQAwwLAmsR68fga+lQ7EkOny4rGh5sn47pwjxa5oqD0DZCLvQsJ
         XJtg/E+RgAnLgHBuOXEXVJv4GUUhhm5ozqlj1oYDSEsBDU2CnB9uLeH3gIF84GZnWaPN
         fPaG3vKRhxOgLwSTPhWkWCyqADju6RxIjCfxH8WghKsEm0H+Rhsubi/jnN++HZvyjmAe
         fsutWA3RKFpL+4WktzicJmPRdnpAR0OHUWflnTlkooZyK5Nwnp3Cp4vedaWNCh1S9paI
         EzvhBTYBmOijHCu9bsfhQnghSy0YORshehvDLbfgK7EWoCf7a57gig+WZjoKtphxzkJB
         YT/A==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="jPFM/Mhz";
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768267618; x=1768872418; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:from:to:cc:subject:date:message-id:reply-to;
        bh=CpMa7XjYjb32Nk3p3q3Maf2C+vPwgOsV1lIs9Egehkw=;
        b=rIrfsI+WK3LXA4CJisASbMd1a8xX2bV0KV0I/GZJY0+TtxOXYf8VH96Mij9teYyApL
         4ni2NlvA78Nah+MEjzwKLpcy9mIfsptLXYmvYEk70+E/nS9f2ocw1kmeN1lVRSMUxVrf
         P2DHLbrkPYmHriGHpu4uTkj3cO0YOnaoifvnRsKEBJ1Yna+3x8HrbKLJ1casE8nW+qzP
         h25O2HZJor3K/yArcuirdPvVl8Bhegdb9Q3yXEdWi0L8yZHqMLwddj924uML3k6opV4V
         EwO9nzHqfurZ2RZ1TlcWlkaJGqvVrpAaU5yRViOjsNx7Em7cezcMhSMe6IA5Bd6H4sFG
         d1kg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768267618; x=1768872418;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=CpMa7XjYjb32Nk3p3q3Maf2C+vPwgOsV1lIs9Egehkw=;
        b=ZTkXyxZM7K0rx56C31zxvEGhiknGK26hoI9BMP4oMlJZloTc6vvpEGWfK003l4u7l0
         ay13kM9N4MR+V1FC7GZpP9zm5evWA84Absfp2j0QTHuTWFoxgWzr5q2QElKGl6WddIhT
         vEant2lDenxfpmOpoZ9Hz8/Qwwgzq+fWN2L7bWRtkWMWbWPH6aUsuLG0wpM6IWLUlgLf
         +tQ60CnTa0Q0M5esgSXH2jXoRuyJHD7eTFlcRGbHa8lFFXZR155dWI4aLDZwMIBdb+Vo
         rcTB0GpSHXaC1B/AF+L6qgi++9KgT68Bb67Jaae7zQJz835+cl8gTmnUnGGcPIwPS6Dm
         nfhw==
X-Forwarded-Encrypted: i=2; AJvYcCUXlD4LbvQAiFOBBp7Qog35CalIkLak5evmQ3pFozT/klS3C/fIjnJ7Tyqv9pO23Eb2ZPjWOg==@lfdr.de
X-Gm-Message-State: AOJu0Yzlmb2PZXhNhHadyl3AqSGxMG6VuT0V14ClQ9HP6GquPOmvbI31
	KydmfjJHWoktd1sum1Ssnl9EV3X3UsoRuZhVFdn6su51XJQSGGD28+EM
X-Google-Smtp-Source: AGHT+IG0Hw0A4CnPARv6H1AfLbaJvCSURgBlffP6k3sdsJ8alc+rZW+aY2CXZ0p8F2yWkeZqSGgciA==
X-Received: by 2002:a05:622a:283:b0:4f1:b712:364a with SMTP id d75a77b69052e-4ffb49e63f8mr249221061cf.56.1768267617784;
        Mon, 12 Jan 2026 17:26:57 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+EyHZqec3/pNm1dunWydQO8Hiqd2uJYIRNKW0htmEz7Mg=="
Received: by 2002:a05:622a:546:b0:4ee:1f69:fde2 with SMTP id
 d75a77b69052e-4ffa72a281cls153507221cf.2.-pod-prod-02-us; Mon, 12 Jan 2026
 17:26:57 -0800 (PST)
X-Received: by 2002:a05:620a:172b:b0:8a4:107a:6772 with SMTP id af79cd13be357-8c389432833mr2585386085a.76.1768267616988;
        Mon, 12 Jan 2026 17:26:56 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1768267616; cv=none;
        d=google.com; s=arc-20240605;
        b=iMIpAklnd/djLu2cj786ps/joQfk0DKfLBYBS3vT61bn69VPCGDvHfMoaYHGgmbI6g
         wfXrGXCnCmuPIowcXq3g/g2PJ7KimfQS+yEKhGPQ2Axp+RrH1z23ykSDxwKL8J093V/1
         QzM9S+fiKlKxYgDc6uY9gpEojOvOS9g+ee55cEXQc95OJOmKOExANvb4/sg/P+EkuyFz
         2h6RnNZybD7OmMz3Kf+ifmmFvaWhYii5BSooKZU6lWA4wQQgoth/hCZpHL3p/hVsotE1
         0yt4U7pnNgUB78Onttw8E52Z6ihyTxTYopFJQehL0yeexvversaa0ekcahT29+PHDMym
         6C4A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from:dkim-signature;
        bh=WIDcUdYY6Q6rq0X87dh8gEVmrypQTp73cB0WaErTQq0=;
        fh=uQCsmYQr+KJEcG63Y45gsyDulzJl/B4EdEfpx8XrGGo=;
        b=T07m3TrlknK+k74ZviYmVVSyHEzvM0zE0PdFwr3G+FxFkS/KH1PMpgFg8CVpLHsqa/
         Ckk5HTh4cLXV4Q4UddUxP+sVd45IzBR3uTzGsRCGr43Mn07OSkaszJ75jWd5VjiHOo9U
         Zc9LtSViqYdZF/2k/4LcfiCsS/vcBA4XEZ+qv4BkB+EYHrlQK3xzn8e8NrM1zYhq1EI8
         PY7ZR6XCaZ1zTpJSEIQnb9kJLlmm4bqLasKMPksbQ4gRmvIlmQN8dcyOlWXk3qCL/T7+
         fhkSbUMzDHLsBWWTSQjnatwiYxLkI6cVskYhr24ie18DqHiwTMfCy/uJ3dAb2zikLh/W
         lR8w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="jPFM/Mhz";
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from tor.source.kernel.org (tor.source.kernel.org. [2600:3c04:e001:324:0:1991:8:25])
        by gmr-mx.google.com with ESMTPS id af79cd13be357-8c387cc0980si55980085a.4.2026.01.12.17.26.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 12 Jan 2026 17:26:56 -0800 (PST)
Received-SPF: pass (google.com: domain of bugzilla-daemon@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) client-ip=2600:3c04:e001:324:0:1991:8:25;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by tor.source.kernel.org (Postfix) with ESMTP id 6E4FE60017
	for <kasan-dev@googlegroups.com>; Tue, 13 Jan 2026 01:26:56 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id 25B93C19423
	for <kasan-dev@googlegroups.com>; Tue, 13 Jan 2026 01:26:56 +0000 (UTC)
Received: by aws-us-west-2-korg-bugzilla-1.web.codeaurora.org (Postfix, from userid 48)
	id 13B3AC53BBF; Tue, 13 Jan 2026 01:26:56 +0000 (UTC)
From: bugzilla-daemon via kasan-dev <kasan-dev@googlegroups.com>
To: kasan-dev@googlegroups.com
Subject: [Bug 218043] KASAN (sw-tags): Clang incorrectly calculates shadow
 memory address
Date: Tue, 13 Jan 2026 01:26:55 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: changed
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Memory Management
X-Bugzilla-Component: Sanitizers
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: normal
X-Bugzilla-Who: andreyknvl@gmail.com
X-Bugzilla-Status: RESOLVED
X-Bugzilla-Resolution: CODE_FIX
X-Bugzilla-Priority: P3
X-Bugzilla-Assigned-To: mm_sanitizers@kernel-bugs.kernel.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: bug_status resolution
Message-ID: <bug-218043-199747-WxcalNaWOY@https.bugzilla.kernel.org/>
In-Reply-To: <bug-218043-199747@https.bugzilla.kernel.org/>
References: <bug-218043-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b="jPFM/Mhz";       spf=pass
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

https://bugzilla.kernel.org/show_bug.cgi?id=218043

Andrey Konovalov (andreyknvl@gmail.com) changed:

           What    |Removed                     |Added
----------------------------------------------------------------------------
             Status|NEW                         |RESOLVED
         Resolution|---                         |CODE_FIX

--- Comment #3 from Andrey Konovalov (andreyknvl@gmail.com) ---
Looks like this Clang behavior can be considered a feature and not a bug. The
outline instrumentation mode is being changed to use the arithmetic shift as
well [1].

kasan_non_canonical_hook is getting adjusted accordingly.

[1]
https://lore.kernel.org/linux-mm/9d78f71b-cbf1-4936-bc72-befa6d6bfe35@intel.com/T/#m0ca3a60c3842176476e7752885b2bc43bd627793

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/bug-218043-199747-WxcalNaWOY%40https.bugzilla.kernel.org/.
