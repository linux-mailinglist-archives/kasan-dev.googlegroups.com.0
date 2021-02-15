Return-Path: <kasan-dev+bncBC24VNFHTMIBBBVDVOAQMGQE5P4PODI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13d.google.com (mail-il1-x13d.google.com [IPv6:2607:f8b0:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id D2F5B31C2AB
	for <lists+kasan-dev@lfdr.de>; Mon, 15 Feb 2021 20:54:47 +0100 (CET)
Received: by mail-il1-x13d.google.com with SMTP id j7sf6150611ilu.7
        for <lists+kasan-dev@lfdr.de>; Mon, 15 Feb 2021 11:54:47 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1613418886; cv=pass;
        d=google.com; s=arc-20160816;
        b=D9rt9yRfM5DYrU18QZJedLM8f4pQIoFSXudENp/I9A/R1k5Gf/C0ayp2jd2PoR+5p0
         IArWLGzEclfmuLmFO/By2z4Id0D5eVJPJXdVDyB3McFQxnYxlYGr5hvMmQqm/anBBT0O
         dhWOMR6SH5WFgTFeWjBuvZi12lsyMdhwndvrQx2WqeDz7QnDGpxsdb0blGaRqguBkdvx
         EfopKgFA8v01T6qHnhV67q1qjvrvSXf0ml8iIg6i6CuhHLw0z0XyIrM3/jdS1eaZ18YS
         7BCYiNIfAt5kY3pYXBzOzofVxlA7DGC0kLM13UEHpTy5Nj3do8aEvPAwkomcp24rG9VE
         RLDQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=ev62s6811lZpXokSlkrYVIHoelKkHmsYmx554XgOpSo=;
        b=iAaZ4Xo+y5NTdnQ4vjJse9yuPZKrKfyauMTISO9HWNRpcpLK91c5GMR9BBVjKoBcru
         hm8MBlsuFOU1IMIkBIqMsp9dDiE4Zsq3Um52txLD1ISLQk6v1+ntD4QhKv3rSJ0IC1ZX
         AYW+P6+dJcshVLY7M7qlqfwMsk0g4ehuO+jDB0B07830Jd5K2YNKUD8Ls1USdJ+vnoUT
         8u2NqxPtX9+MJOPIaH0bqiU9wsivUg3dk6vDjH0tciP7LiGQMtO/qZqgJevnau/JOEiF
         QjpMkS0HApBjdbc0gBKcFOxM/AfBRK3qlHIVrSgOGnIldGrxIFvbCpnJ04ZzzMexPYoS
         vOpA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=lcWUxsTm;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:date:message-id:in-reply-to:references
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=ev62s6811lZpXokSlkrYVIHoelKkHmsYmx554XgOpSo=;
        b=EADmEPTajTicWpKM/bnsA1jBOz6x86daDmyGN6NkFtweYBlwclZDwRVzhUKvrS63PY
         B0MLh8l6X+cM4Xe8WQSLe09/S7YlU+Uw8cd0vJ0Q//ZWuRRlCxZfAbKiTm608c7sG7gi
         YBewO+htlsIHMMPDeOEBZypWUtP3Wx6HPUWM1AEEEYRJJMnkhmTMIrf5PDMUheH3lFY3
         ETtOhiz+7KuhSoH8Sm0SJQ0Vg/wuODlMddj5FpKjJKp19Oc9XVmUa/cSBoHlRTneQ60H
         ZUIA3IsO+tN9/8+dTEoz+88yBtMCVDKohRxj6jHOyc23ABYdhCP800InG9qIzrLec3Cn
         hxYQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :in-reply-to:references:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=ev62s6811lZpXokSlkrYVIHoelKkHmsYmx554XgOpSo=;
        b=CQjoy4mt+p9CqNmab3Xg4ktIQBlpzjm/nliIt9QrFIpe//7SWvGTm2FHNDLG3k51Ez
         M+zjgwOGIVHih1Il+mC02OjnMNHgziHaFevY4eenjTnkwTmvw9EpvWNCTe5pcjQ6qpHr
         A8G6gyCl6x4Zn2K+QljZ9BtMvRM+QlkA5ss18pb4RCfIB2qCDrpLl+zM0JXXHCi3Btr3
         FUKJqN1UsI+J+2PpaOtH+Kn5DHKkj4nhMUA1Myj4lTK6i2XPCxpPyQzlNN85XWK7vGzB
         Gm7NqnwCeD6X5yggvJJHm27TYL/R3kYWCao/yvlgqI8B2M91imLalRTcmBCoaaG6UJtH
         JOBg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533QCYesu6IUB8yJVHZxNowR0oFde/EprLEOW91KOv2Rc5qtHCF9
	LL7ltzK+N/jG1mehEsv+9iI=
X-Google-Smtp-Source: ABdhPJxM8fHVVnXjE33r0rakbe7lVlxc358DSQGd5hCQhyQqAPGcIfHQQn1kQTTg1GTdj4RRdn508g==
X-Received: by 2002:a92:de4b:: with SMTP id e11mr13289145ilr.123.1613418886633;
        Mon, 15 Feb 2021 11:54:46 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:c549:: with SMTP id a9ls4353396ilj.10.gmail; Mon, 15 Feb
 2021 11:54:46 -0800 (PST)
X-Received: by 2002:a05:6e02:ee3:: with SMTP id j3mr63559ilk.199.1613418886281;
        Mon, 15 Feb 2021 11:54:46 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1613418886; cv=none;
        d=google.com; s=arc-20160816;
        b=hRXJ3iRGwnhFloCKACwQDiF2mAGaLaGnfzEr2is/qH4cpZZIaFwW5AqJxHVMUp6rtG
         ptOZS2sJT8mcVRzI7uLSeve7vPXcx+ENMih1sV0+nxbQd+kNVWpBWJhGisar4qHGwaMN
         kgRkw7zHr7M5+aB3loPYGOCXcjO/84g+VfrgE0szo5UOHCqZkZPKdIoQfahYxwEXT74L
         /Z/v+J93+aDMOZvT5D4YgrL3Hn6MU9mZPHgbZ/ugJQYAONsrcnWqhqsvHjMhtNZmncH+
         N9QhRgy2oNZxqqmmLieJcWJ347WmshzPg81Qq6gVQ1kGoUSi45XbrXkCQFr9CE6pvb3e
         B4Ug==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from:dkim-signature;
        bh=W2Z0e3uUNk/0mLewEtKQEKP88QgIne5RnDLv/BaPt/Q=;
        b=y1l8kpLwTQbG/Bo3nE+nFzajvENULZeHhJH8cLegtzU81KthGKUeqIZAGtdHwuXsEz
         0vSOJJr8RJAHmDtUi23lNI0KoyMs+v+dLyv8uSRcSUxK1lkp8MpRSe92lpUvQFtL4qP/
         dLDJfylpXmIDqOuu3RTKeqmm1w1S7wpXXiwhcFrHB93rNKMCGeD2BfNI0SGZM32Cfzzi
         y94HlX+jz15/8ztFAPF7et5sl1QTA55qEbVJGoHdfkrGp/q+ujtV1FatlQT2qBsZ/Dz2
         mARiCUerpXag6oRByL7utHyGXYWkPYg97VuomxJIDrs8V2mMlVD+C5UtY2CKa5EWVpCd
         /4Ag==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=lcWUxsTm;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id u12si483649ilm.4.2021.02.15.11.54.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 15 Feb 2021 11:54:46 -0800 (PST)
Received-SPF: pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPS id 77C0F64DF4
	for <kasan-dev@googlegroups.com>; Mon, 15 Feb 2021 19:54:45 +0000 (UTC)
Received: by pdx-korg-bugzilla-2.web.codeaurora.org (Postfix, from userid 48)
	id 5C163653BA; Mon, 15 Feb 2021 19:54:45 +0000 (UTC)
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 211783] KASAN (hw-tags): integrate with init_on_alloc/free
Date: Mon, 15 Feb 2021 19:54:45 +0000
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
Message-ID: <bug-211783-199747-0rgmfkBb50@https.bugzilla.kernel.org/>
In-Reply-To: <bug-211783-199747@https.bugzilla.kernel.org/>
References: <bug-211783-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@bugzilla.kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=lcWUxsTm;       spf=pass
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

https://bugzilla.kernel.org/show_bug.cgi?id=211783

--- Comment #1 from Andrey Konovalov (andreyknvl@gmail.com) ---
The implementation needs to make sure that with either KASAN enabled or
disabled, the same memory gets initialized.

Likely, we'll need to:

1. Move KASAN and init_on_alloc/free annotations so they come together in
mm/sl*b code.
2. Nop init_on_alloc/free annotations when KASAN is enabled.
3. Duplicate init_on_alloc/free functionality inside of KASAN runtime
(combining initialization with setting the tags).

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-211783-199747-0rgmfkBb50%40https.bugzilla.kernel.org/.
