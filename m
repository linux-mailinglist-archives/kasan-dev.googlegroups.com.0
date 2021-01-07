Return-Path: <kasan-dev+bncBC24VNFHTMIBBI6R3L7QKGQEZWLSQPQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73f.google.com (mail-qk1-x73f.google.com [IPv6:2607:f8b0:4864:20::73f])
	by mail.lfdr.de (Postfix) with ESMTPS id 7CD182ECA71
	for <lists+kasan-dev@lfdr.de>; Thu,  7 Jan 2021 07:22:28 +0100 (CET)
Received: by mail-qk1-x73f.google.com with SMTP id f27sf4943604qkh.0
        for <lists+kasan-dev@lfdr.de>; Wed, 06 Jan 2021 22:22:28 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610000547; cv=pass;
        d=google.com; s=arc-20160816;
        b=oSy0rX5/xlTnDmXsb+t9ICjfHb2YgA46RSfOWvGHvLAVMcQuHklvspwmKVwTgJP69T
         B3qM/jOYNZNt/sG/YysFUspM8RfiBKKr3U7Fr+thVXRyfZtMcKx5qmxO7L7dmOaJQbZJ
         YHMlefEFSqA3VQ6toYn/lOcKCzJDXBasNZz4FuzeiB03hCIM6lmkcxk5pee+jtf/LrXs
         GC6HiZeisOqlPts7moumsAmXQTJkjROIAJvXGp0Yh/j5xAwwwETvzyWUvaliBQ7smnPC
         b+g7R+8IcaFhSHocv3ep0C0vi+jRtqsEz5M0l+urIPeIOMhZMzWJl20jSrny1W6xxPkD
         a99A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=KArwiPn1VPClYSllK79DWzLmO89mqdiW2aqZI9rJjWo=;
        b=Wt5qma4B7pwtqfuoz/J3Rig+vAx/SDx8c4ez2cH6Xs1FPHy/3DdnlwOYgRn486+qGC
         10u2OkqTfexYnw5BKXd5qrCoE7GDnL09Vkxd2H1F2pQdOCFjTVV2E92ZTNgybWBoxNRQ
         B2ol5Eb//lR/H7EZItYzMvz9xuegvlrZ5OlSxCbuOU4K9E4J2Bh3/7cM+fOCtCsvSUEz
         Y9Pg+HMPu0fE7Do8T0KHVlG5HxCb+Yujq73Li+TCC2qFPj0inmChYyZE3Hh7/Xd1hvMC
         r8HSzxeVURkxTxvRYXXGELblrwKFqGIdPcd72K92Kp0zJvDAJ65xuWki9zyC4nMEkkr4
         cYNQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:date:message-id:in-reply-to:references
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=KArwiPn1VPClYSllK79DWzLmO89mqdiW2aqZI9rJjWo=;
        b=Mkd3mLFGbQ/imEaCy7Nfsxw50cwwFPBfkdjwdR9r1cvWFr7loeLWsUumgpiLiKRugS
         cWzA4nm2ZhSxcmrflhGKra9zsJnhYEZT0WjBKQX2Nf6Q0/HTTgcb5+6LXwW8kEYZ6iIK
         bLv1HCznnrTC0iqOy340rq40PEb9JFUAc4zMBZxA0qFV9eIcrupnjiWdH1kWtcFO9tMe
         /d8lF6Ae31hMHt4PFAOUrQL9ErPrDbU8XU8+/49Elpd918DJIphvhDXxC3Vuq9zlbW0x
         aNuf5mFsYWV0KkJstxH9PA15MaKu2XjKglIqw1OKSF43M++ToKT4mK7dGs9CzY0N5oGi
         0d7A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :in-reply-to:references:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=KArwiPn1VPClYSllK79DWzLmO89mqdiW2aqZI9rJjWo=;
        b=Y/93oVsUf1zWolx4U/2XEqdXyBqJTDHCetYomux69NRcm+ji/tEqW5TKhwvNIVzrHZ
         y8vUyReVRtSx/VfkLC3x6vQsNZoH5IRVEO29UxxEC8wr3CBuccHuSKBVWXedznUl1SVr
         Ie6bzrfd9l7eyd12/xDIrLYm9bUSvZ35VL8Rn0NfpXhk2xF9M5D+alALhwgYszUZpWK0
         Ge3Gs1Yi9O2G1CmVAxkFumsfAms2rpgtABtjLoR4IugJVF6w+79x9mv+W0UJtknFXPYB
         BpN58atGM4MEfnNkChQ9P+U4/4VYjUN3XtbEpK+hZSm73kw1pi3ZD4sgmGDYkIw3mgsH
         41Tg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531VgXS1dsSBp4JDYfd59IwtFQQkVxdMrFxSMSHrN9DpUec4E7jt
	FNJVc7wC7jelqXvmGVad6L4=
X-Google-Smtp-Source: ABdhPJzMplHhsE6eZ/FAiBND6a7wARJ3M91aApF3jHYxiFXX7ZNDgHkT/fVK309aGbjL8TElzj+Sfw==
X-Received: by 2002:a05:620a:144b:: with SMTP id i11mr7741048qkl.178.1610000547449;
        Wed, 06 Jan 2021 22:22:27 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a37:bec6:: with SMTP id o189ls3139997qkf.4.gmail; Wed, 06
 Jan 2021 22:22:27 -0800 (PST)
X-Received: by 2002:a37:63d1:: with SMTP id x200mr7721207qkb.164.1610000547102;
        Wed, 06 Jan 2021 22:22:27 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610000547; cv=none;
        d=google.com; s=arc-20160816;
        b=d+GQckmnLqkNA+oztM3uEq8gqITFhfIsk+qRfOvG+uHY1qXaJmb9VMzWPsZvhV8O7w
         vSKVhizTJ9FZQJp2IAFlZVoz8wiLsKdszTWZX2aJFkhv9Bv+wjOnDaWJB7b1CUEdo9Td
         euvOVC6FIYom/su9bHeQNCYCsK7W9DZO9lQz5cKUzXGFCmzidTbV68HFZcmQ+4Rlhzhg
         ++S3vNeZG8Trxq0lhKiQbKtDBm99yw6iMgWGTTUudL0EHf1hArAE39I0jAPTeKM++2g/
         kwmp5RtAvhdwU7RFpb3ZfV5viSsZR5ca7jgdAYFNpYIz95ic4otIaYtEle+pUPBetCnZ
         CGXQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from;
        bh=gNH2BMxv2KqQ6IwbtZTKQaLqp+H6RLqquSsx36sjILk=;
        b=yXj8NgUbKG/Qrla15AC1rlLgkwBby1aIydqdSEHZOmwE5DGZ1AcSn9JvfGtpw0y3Gk
         +S1/9uP39RigFkmhfikhtt9XwnU8vNEDx3NmGfrAHaqNpnUsPbGmiVDg23HSLeBXWEbP
         GNW1VlCiyRCb6I4/4VtolPRa1ctrhuZJk2uhn7qRLwacQel6vMMJQi5TFi9b1n+c94Dm
         HhI1N4L4H3zQEaZfGjL6+fGxsExUcyfcSaZAogusXNhauKCazshjaLPrGZASird7aybX
         YBNi8C2vn0FdJnxjCLnlrMoq55Wmn/2y0esRYS9sd70SpJ3j3UQAh41WjImP3U+v3nGg
         AqiQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id p55si423408qtc.2.2021.01.06.22.22.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 06 Jan 2021 22:22:27 -0800 (PST)
Received-SPF: pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPS id 08B4D230F9
	for <kasan-dev@googlegroups.com>; Thu,  7 Jan 2021 06:22:26 +0000 (UTC)
Received: by pdx-korg-bugzilla-1.web.codeaurora.org (Postfix, from userid 48)
	id EDCDC86731; Thu,  7 Jan 2021 06:22:25 +0000 (UTC)
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 210221] KASAN: turn CONFIG_KASAN_STACK into bool
Date: Thu, 07 Jan 2021 06:22:25 +0000
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
X-Bugzilla-Changed-Fields: cc
Message-ID: <bug-210221-199747-mSBBfOUyx3@https.bugzilla.kernel.org/>
In-Reply-To: <bug-210221-199747@https.bugzilla.kernel.org/>
References: <bug-210221-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@bugzilla.kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
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

https://bugzilla.kernel.org/show_bug.cgi?id=210221

Walter Wu (walter-zh.wu@mediatek.com) changed:

           What    |Removed                     |Added
----------------------------------------------------------------------------
                 CC|                            |walter-zh.wu@mediatek.com

--- Comment #2 from Walter Wu (walter-zh.wu@mediatek.com) ---
Hi Dmitry/Andrey,

I already sent one patch(kasan: remove redundant config option) to fix it.
Thank you for your suggestion.

Walter

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-210221-199747-mSBBfOUyx3%40https.bugzilla.kernel.org/.
