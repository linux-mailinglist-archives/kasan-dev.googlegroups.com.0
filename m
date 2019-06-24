Return-Path: <kasan-dev+bncBC24VNFHTMIBB7U4YLUAKGQE44QRLCY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23e.google.com (mail-oi1-x23e.google.com [IPv6:2607:f8b0:4864:20::23e])
	by mail.lfdr.de (Postfix) with ESMTPS id B65C8504D6
	for <lists+kasan-dev@lfdr.de>; Mon, 24 Jun 2019 10:49:03 +0200 (CEST)
Received: by mail-oi1-x23e.google.com with SMTP id t198sf5029941oih.20
        for <lists+kasan-dev@lfdr.de>; Mon, 24 Jun 2019 01:49:03 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1561366142; cv=pass;
        d=google.com; s=arc-20160816;
        b=fjC91bwQo6xXEtd5oYpW5sU5kKPS2UKnXw3nbWKOADRqOMTTBo8p63V/RFbxRC6ffP
         lmn/RD3QfySXmpkO8IqNCtgINHRN6egoFHAPwlOcpzvdVeluyR4R0H3F3W5uhkgkv4Wv
         uOhWBq4p5e+xU76q2gZnkflqY1sNfobGGtL+wj9c+QqwhgUMxWOdrOB0QBegwg2jF9t9
         ULV+hrDyJfMN4V8mZE5nwhptkCQL5hm13mzbb43+y4CZLPHhDrt0ym4cbnf7J3BBuVPw
         Yob70T8f9RNa9MNJ5ZLzF7rbiCW1c0j+6+zOAjYyEwMNln8kkLNjY3oaogQ+DjmsC4mH
         tk9Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=qCamxGNMgAJmYkYTjtYLVhNYFtZZW+xm7UTgrMv+irk=;
        b=sVTsh7AoBzyuNisSTc99yTOimuoGnuz46VY8B1aG51k7h/sp9uQzXiUB726uDicdea
         u9CShovRKH8LA+VrsbdmviXej/nEbqTd8AtrCsPQgZdtNGMpcmZnvWcS+pL+lR8tgitI
         KQXU0sF5PANdzHffm31TEuYKOsVQ7BprN7FaHERlgos5dH3mS/wCK0pDgL07k2dTUtPM
         WX0nPaTGsN20DwKqQTw2mTx1OkTYRcbL4sEesGQZIlH4tXPSIcKzwJLvogJIuJIbO/pR
         qDA49kLsP5G26557aaZONcnniVyVJqCbgtcUQjh4ALfG0bkE4Yl5kWw/Pqy2a15FuCnT
         a58A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.98 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:date:message-id:in-reply-to:references
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=qCamxGNMgAJmYkYTjtYLVhNYFtZZW+xm7UTgrMv+irk=;
        b=VVZJRUh7wZr4jPkgQtnoDE2HyxDd5sj4E35v4Yz7zpbKAYJp+LAW8Tc3EDshwmRsP7
         qrvUrFGeLv/hrl5aJQtMZvIQhHzTRO43WmTCJgOokqyfc64zzDcThJG5F/zSFPbudO9A
         6P3xXMbcEmbKNRq6yfbjShDW433vzKde+x3NzNTzw3sxpZcVTOSGJjDCc9LqzbiLEvPJ
         70PayHmDWk4ht2wWwChVvHCUg/TfnAeFc1q6OngElYjDqVeiC5mmlCpNSTK1SQxbz5yx
         ixmYNHUjm+WBcSveX1DSXo4MNuCO3CBZFqJTQyyiBIPmYZdIZT1slVe+MmzyalLTzq8y
         Usqg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :in-reply-to:references:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=qCamxGNMgAJmYkYTjtYLVhNYFtZZW+xm7UTgrMv+irk=;
        b=F2bnsFmxn1vhA/ezOhRIkA32p3Hw1jQ9VXd0KFF+/ineVjS63sQ9ZvyxHM9+WOm2Qs
         dyOa7UeajAkFw0r9Di+8aS2OLQBm/To/W68AgUSgqriOoW9YGLm28GViAGx4tXLUxZmL
         501/t66X4BAcktDZ+gfsSK8/GSimqQGgk6172Wbh/cXj31MGHIu2HaVgXKYRf9cDZcuK
         zKSXcpxMh3jNJ/0b9F8w+Cv3/FAG+grFJ8Vc623XjDbdQkSY5MXeys7hnzyXy8UMD6vj
         H2JU649CmDyxY6C9B39EOnY0m+j4AbkbtJCYmSEi5nULG1dFdsiJGj09Yp0Zz4gmxE4a
         Joug==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAWBdK6TKcKgHckjV02yW+hqmO33yNWHbHoj3qfO70lq/MsUnDd/
	0POu/kZLXq6wRITUCgHJ/Sw=
X-Google-Smtp-Source: APXvYqwPySxo+8yAqYbw899llf3WlM27fCMVJSb7PCMn1jVcpoxizdVMiEYK8SrC0DL5sQY9abzVcA==
X-Received: by 2002:aca:410:: with SMTP id 16mr9642270oie.94.1561366142618;
        Mon, 24 Jun 2019 01:49:02 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:3e45:: with SMTP id h5ls929693otg.11.gmail; Mon, 24 Jun
 2019 01:49:02 -0700 (PDT)
X-Received: by 2002:a05:6830:108d:: with SMTP id y13mr18594194oto.255.1561366142376;
        Mon, 24 Jun 2019 01:49:02 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1561366142; cv=none;
        d=google.com; s=arc-20160816;
        b=ouSsVK7dTtlh03II0dE9XcgfiyJzacWWZV1xdJfA0LDS+PHiVMRru1JW23KNdeTpkC
         cLcIJ1edNbaR4dNOkud4Dg7eRFXOxsezpV+WOAEUUPi2cXLI5SW0NR6SmXdpHXvb5uXW
         cTCKktuzraUR9ZK1TCe0BsQab8AUykphx0U7Qzj5AP83QQyZjv/l4NK4oaqpRwSuPmWK
         +B0uX/E1TnwbtQJhimpTOlfRk9LLtc5DebsOn0IbF4Z2PMJgHenSHDEAydrgqCFft8Q0
         8pT9OPyedjMJHHoMhi87ZAB2PsAx5CNEXL+fBSgpG+V8rFGoaMHNT2fORXgWy/9lEwXF
         vmKQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from;
        bh=0I1OiGmr8dgEm5ZXfMNI6KFatlL5tWC0TBnrMa0ErWE=;
        b=d+pDuG/v0/lDu1ZQd6N8dqdTORmwaBX98c6uCLwwksECQBG6FY8cndYmoge/fmllAO
         uQgnPOyR5Dbofrm6n1ENsfOOL++xbpIZ5frO1cQu1q1Ex9YNprkX3uWF+kgmxNkBRb0N
         TTIiqBvgk2LsZfTTNE0E8xpEqrA68g6lwmqNU2at3oMZ4Fc+RNfOmERApxwvqcpvzsz6
         G4JYbC2EaRO3BjwuklI07VGCS2JhB2PyxhvQywARtSOEEsQ0FChoV05Zyg5sqCKT0PrI
         cv6MIBzS3bAOnv3CDTrJQl4fg5oXIS56YEZOl/n7ZT08SJAcUKZPk505yiVvPVYqPCc0
         4FRw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.98 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.wl.linuxfoundation.org (mail.wl.linuxfoundation.org. [198.145.29.98])
        by gmr-mx.google.com with ESMTPS id n67si669537oih.1.2019.06.24.01.49.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 24 Jun 2019 01:49:02 -0700 (PDT)
Received-SPF: pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.98 as permitted sender) client-ip=198.145.29.98;
Received: from mail.wl.linuxfoundation.org (localhost [127.0.0.1])
	by mail.wl.linuxfoundation.org (Postfix) with ESMTP id 98D6F28B85
	for <kasan-dev@googlegroups.com>; Mon, 24 Jun 2019 08:49:01 +0000 (UTC)
Received: by mail.wl.linuxfoundation.org (Postfix, from userid 486)
	id 8B1CC28B8B; Mon, 24 Jun 2019 08:49:01 +0000 (UTC)
X-Spam-Checker-Version: SpamAssassin 3.3.1 (2010-03-16) on
	pdx-wl-mail.web.codeaurora.org
X-Spam-Level: 
X-Spam-Status: No, score=-1.9 required=2.0 tests=BAYES_00,NO_RECEIVED,
	NO_RELAYS autolearn=unavailable version=3.3.1
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 203967] KASAN: incorrect alloc/free stacks for alloc_pages
 memory
Date: Mon, 24 Jun 2019 08:49:01 +0000
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
X-Bugzilla-Changed-Fields: assigned_to
Message-ID: <bug-203967-199747-urKdC7ln3X@https.bugzilla.kernel.org/>
In-Reply-To: <bug-203967-199747@https.bugzilla.kernel.org/>
References: <bug-203967-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Virus-Scanned: ClamAV using ClamSMTP
X-Original-Sender: bugzilla-daemon@bugzilla.kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates
 198.145.29.98 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
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

https://bugzilla.kernel.org/show_bug.cgi?id=203967

Dmitry Vyukov (dvyukov@google.com) changed:

           What    |Removed                     |Added
----------------------------------------------------------------------------
           Assignee|mm_sanitizers@kernel-bugs.k |dvyukov@google.com
                   |ernel.org                   |

-- 
You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To post to this group, send email to kasan-dev@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-203967-199747-urKdC7ln3X%40https.bugzilla.kernel.org/.
For more options, visit https://groups.google.com/d/optout.
