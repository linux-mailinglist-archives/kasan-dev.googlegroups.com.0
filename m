Return-Path: <kasan-dev+bncBC24VNFHTMIBBM4BY2GAMGQEGGUACTQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x93a.google.com (mail-ua1-x93a.google.com [IPv6:2607:f8b0:4864:20::93a])
	by mail.lfdr.de (Postfix) with ESMTPS id D0AAC44FBD6
	for <lists+kasan-dev@lfdr.de>; Sun, 14 Nov 2021 22:33:40 +0100 (CET)
Received: by mail-ua1-x93a.google.com with SMTP id 43-20020a9f25ae000000b002cf28d7afd2sf8356764uaf.3
        for <lists+kasan-dev@lfdr.de>; Sun, 14 Nov 2021 13:33:40 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1636925619; cv=pass;
        d=google.com; s=arc-20160816;
        b=NB8KJYwiTXQUhOSYHlFmuQa2XgOzvfX5xQHWOdkdZ5iAIdvw7q+cOLPth/2LgWy7TG
         ZZFo3o6SQp7PHsz86xB9IadOTt6dCqMvrHk5y7jlWWa2TtNDKR8V753ygUbAMkScm4oT
         HpGWZ5PLHgLYxe2t04+yHugDfZ6Vhjmn7jqQgP5OAm199a0VqXH6ShLV+5a3lxh6NlDt
         /b+c4ibWQPJkb/QF3Ugj7hbpeISCzEAKmRA6bXX1lcHyaAnzWAjF2Ga5CQUZRpQyaLfK
         0RIF/aPk0cBq+p+1U0eKTcH8/caggXlAu66EK7t1lxESA6BpmF5v5Z8fmWOYFe8tDQAo
         s4nA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=Ia8oWmLOqSQj3cPne+nbv33lrxVZJFiB0kczVb/MiVA=;
        b=goZSfER2jquEcXPCcBQEKHMPWiFu7dsyWIxG8HylY+ms0LJp0x6Mr0m9+ctZGObIC+
         L3zWTKLN/qhR4msSBg3v7I2BckJ9cFrbGLTitSyQPbUjElceSkahDZt11JUO5RjkFgPc
         e3ALYZSacImnIoemiwIGBSo0RvgDpQjRAlWiQCjkya/Ft9SAna2VXpAcveS/aCFjhNfA
         HGYQtEalCmI6w9ORIm19Prmp7pjTTrs2DC1g51DP0Uu/XhXAp7+CGz7x9n3/B73IX1lB
         o9wStYXKpdZtn26Yb/+Of/jUkqNIEFErP8kYrVlJ/nNdNbCfEmbxpT+a2DHu2QkDZwFv
         Gqvw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="YhLDqhy/";
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:subject:date:message-id:in-reply-to:references
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=Ia8oWmLOqSQj3cPne+nbv33lrxVZJFiB0kczVb/MiVA=;
        b=Vr/jSWLYEK+NatcUMTSQqT8oVj8euQksYs8Fc0eowt7ZmqKq0uvYwJDZAETFS9fd1a
         u3AlWQLCSCR1YTB7de4DLAAQk2+FpVT3xT0YTRCUoAwdTQttORyPO5AakzT6x6oX7JHM
         Gc+od+/YCzHfTdPPAnr+gPebUT52hwnEJkm+QS0KrigMkV01EfUL11t1kxV6a5KBNj1b
         IJ4G9bW2/cHFHR9/Zl8Zl41ZOBxff2SednkrnLWdfPDBSmY4r3GWpwvsTYa54Q3wK/sh
         4LQCk/hVwMcWLK2Y0jeEZ6u+yK2TV7z+MJQmXwfqDtIHJpaOGd9yHD47hZt2tda3WZmr
         eE+w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :in-reply-to:references:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=Ia8oWmLOqSQj3cPne+nbv33lrxVZJFiB0kczVb/MiVA=;
        b=Omt48URf1avv1depGLUZrx8ZluOyVUz37lTlDhqs1C9D+Qyn+szYurFc3sVThQ4wwJ
         LSBSOf7cgHplBAzlzGL6GOagOSy+Dbh3PKZD6CLlXTrksmw2R92a7NSIIag876YizSmC
         G9XM1DMgTMw9MoDEpICElgRWfysPN90oVEYcpEErp3yFTkF3jNvFHpynWMNdYglrK9IG
         R4PIEUScJD0u8i/wVazwx0Z3Yjq2uoGS8GK2uGAAo6zKtRX8YEuaf1yLSeElrXUIQECr
         EhevzvHzm3nm0dZHR04DalMp+jsia38vWYhI5UqzX2OpwsN/cKNXlCyiunBCtuarhRcD
         HCvg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532AGrxMCn9B751qKkTeKCVSkczKNqdniamJerf51XF0i1bnB3v6
	jL+bAVwtL9QdwI5rV1ZYuJ8=
X-Google-Smtp-Source: ABdhPJzN4M1WvtP78hBw+64O4I4SzDiJqWv1DvSikXdYRDeP/E8brVObJkutYu8EqX6/RoB1F1j8yg==
X-Received: by 2002:a05:6102:36c:: with SMTP id f12mr35468726vsa.46.1636925619605;
        Sun, 14 Nov 2021 13:33:39 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ab0:284c:: with SMTP id c12ls2553783uaq.3.gmail; Sun, 14 Nov
 2021 13:33:39 -0800 (PST)
X-Received: by 2002:ab0:20d4:: with SMTP id z20mr50799701ual.23.1636925619220;
        Sun, 14 Nov 2021 13:33:39 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1636925619; cv=none;
        d=google.com; s=arc-20160816;
        b=NSpaI5oBJbNLCX0rm/+wv7wKWVAk8lWIz4sd2U08Ub6R+C15nnJMmoxEgLE/u0aYZ/
         K6/YGJ2e61aGYoKLpAq8dn4XToQuN5iIDzlSm/qPMslq6kCgrYJU4C9isO4JPCHhILjT
         BblqsPGztdItk4Y6u7+IKlNEJaCsv/HO+XP26C6TYke7z0fTWnn3p3SCu0gD+o2hxLit
         uF+O7EmdAt/Y9XcjIcrI5ZRV8CjOp3xe+9zocOHexCnfWnOAL2z/GSWB2jrilH2wbXO/
         3adHtzCkEXgdEJnw4qgBA/6jzdiSU99NmN81UNkPB9vJ+UBBLQaqEFomuuDw4Bq9WDel
         Ju/g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from:dkim-signature;
        bh=7ROAr2U8wtojLHZX6GmvYgtN6ydVSmZrbU5R5MZ1GoE=;
        b=rxxEk/5+L9ZIfSwBhHwKT/Iuy8/7icmGUKMgOwpvzRE28eAd3aLzaTTHW4nwVprGm9
         k2kXZN8A3S/U4Bf/DFMJbMgh9+dgbOpJFLwc7Iu9+NYYAKG1oy+cE16K8hehe2ybsHsf
         0xnSmjQhuddyTX40Vl/n6TB31ZxjZV1pqu6QvpEZO4S3OWdBuVsRz3qfh29XWgYaxEwR
         Ot1IsxgayCr9NHhD/BSxfDp+gpdyX8Cae9KdSIV6iBtag3f2G6Z5Gvdpv+ioAVRl5+Sa
         avLVj/b1D7+JYA3nidurS0VZypkqBzCvTM6ZiL/svM7kP1i4UEbMCwg62Hlwhea/PaiH
         ZlXQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="YhLDqhy/";
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id q25si939856vko.0.2021.11.14.13.33.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sun, 14 Nov 2021 13:33:39 -0800 (PST)
Received-SPF: pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPS id 362006044F
	for <kasan-dev@googlegroups.com>; Sun, 14 Nov 2021 21:33:38 +0000 (UTC)
Received: by pdx-korg-bugzilla-2.web.codeaurora.org (Postfix, from userid 48)
	id 2E99560F5B; Sun, 14 Nov 2021 21:33:38 +0000 (UTC)
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 203267] KASAN: zero heap objects to prevent uninit pointers
Date: Sun, 14 Nov 2021 21:33:37 +0000
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
X-Bugzilla-Assigned-To: mm_sanitizers@kernel-bugs.kernel.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: cc
Message-ID: <bug-203267-199747-YD5ppZXGCj@https.bugzilla.kernel.org/>
In-Reply-To: <bug-203267-199747@https.bugzilla.kernel.org/>
References: <bug-203267-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@bugzilla.kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b="YhLDqhy/";       spf=pass
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

https://bugzilla.kernel.org/show_bug.cgi?id=203267

Andrey Konovalov (andreyknvl@gmail.com) changed:

           What    |Removed                     |Added
----------------------------------------------------------------------------
                 CC|                            |andreyknvl@gmail.com

--- Comment #2 from Andrey Konovalov (andreyknvl@gmail.com) ---
Dmitry, this can be closed, right?

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-203267-199747-YD5ppZXGCj%40https.bugzilla.kernel.org/.
