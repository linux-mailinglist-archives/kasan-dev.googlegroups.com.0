Return-Path: <kasan-dev+bncBC24VNFHTMIBB4H7VKAQMGQEBW3WLPQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x239.google.com (mail-oi1-x239.google.com [IPv6:2607:f8b0:4864:20::239])
	by mail.lfdr.de (Postfix) with ESMTPS id A9DD731C1A3
	for <lists+kasan-dev@lfdr.de>; Mon, 15 Feb 2021 19:39:45 +0100 (CET)
Received: by mail-oi1-x239.google.com with SMTP id 20sf4468899ois.23
        for <lists+kasan-dev@lfdr.de>; Mon, 15 Feb 2021 10:39:45 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1613414384; cv=pass;
        d=google.com; s=arc-20160816;
        b=VSv1Mh/NnJSgzW1SDCNj+VNLs3C2wImY7lFpfk+xVXuchslKEfW+M3nV70sXe/jxf4
         43HBWRcv5h+x2GmC6QhcGjXKAICZQ2lDMJkpDKajt4BrcQJQDJyu2QHRtPVrg42kQwJS
         849ZCEHHhTE3qXF5JWcp7qZs+IKi/x97rKHgKNm7G62T5d2nSrMFRYmzdGb4CxmVjrrw
         Z72mih8Csh7hYRsJ0vjFjDI5vyEQd4F/bDJDG6zXXsv/bBsp+0Vx9jKvYVkptLfoTFNM
         /ATZkFZvONeNbXbcc0ZEt6wzmMJsuHJbhiLjddkxuNI7VpsGKOwhT1mtOdGYwkCkCMia
         ykJQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=+66qVUVxln3D96oln6QtuJQuS+4j+wuRSPpqlslr2PQ=;
        b=Etyh0lHUM3095rEkhG0utMhW/cox6fvauqMqkC1AUzaQcEhgdjrEOAdJvB8fm14wjh
         o4SiKvuLMGVZAB7UdZ7GBVXP9juGyDpwcZZYyc7Cp2ddQ6qrrhMszPyLrAXWQxzbh57j
         q5Hm40GHX/02v67mH0E9gLGFeVaTdiGsidvtpG1gsq5012ogoqtVjL+cz0ZdZbRbqB7p
         hjmfXCMp3aYWd4LI9tU1/+UCdKKQoR/xQcUe60amGOjA3fGrWXD5JujSaMH2aeehF8Bi
         YCcsJK9bQ26UlpA7oNmx9dOy55Q1pDmZIjINwn+TDBVuzxEgb2pRCCnPW7JCKcaDIWjr
         82zw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Y2Dh1FEX;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:date:message-id:in-reply-to:references
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=+66qVUVxln3D96oln6QtuJQuS+4j+wuRSPpqlslr2PQ=;
        b=KC7dsOrnQpW7Pr04718pxN6qiBZJAmbv0nxbI3+TgyfQwoobLpwdHgF19+YsqRj4UR
         W3O6erw2EKX4co4Tw8BVgLwnh4CsE7nrkT4r34uXCfFcQuPmIaZCboXch1awGKQ/EpwS
         rkSB6KrAU6TZrPiOe6LnM06AyKqgTnMNH11PusraiCqZuA5ESKMFhL8Arq7VJuWKMs0M
         FybZSKammewbKXVOT3kO11lkjQeI0uYlwwO47YC0AwxyWRGdPk2ofeAz6wwGgN7/DNhe
         8wfRYBe0QhtKcx7DlnJyuzEokvNbVkEwC2WhR550SAtgJZpDwvBITq/iFo5Hp8RDpY1G
         eBZg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :in-reply-to:references:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=+66qVUVxln3D96oln6QtuJQuS+4j+wuRSPpqlslr2PQ=;
        b=VYuz/lzwj+3pCb04v4YNGJZIkz+WDUVKVUTd3WM1My+qxGHP9AHK7BWkmIzooVL2nI
         du+b89f1QR6V5gMgcBOJsWSNMK3LhTShXTL6LkG6b8cyi/2mODB7fLh8Bq0FGxA3jWlP
         XL0ZZ5v/GmwixJ9TmUOE6dNHWPZ4Ctw5dhpwTw/IH+fsrGk16/iP3NpTeE1wPPc1vVq+
         vOt9nlXS/Td57xNk01t8ckMYmlW5msF3iJTTkYjkCuhuh1PU0pf616Ev7Zg2uDRpOwdL
         QloODZhDw50vCGuX32m4+Y7vb5kdZXtOkZqG2WRXcURbWEH7yDCwu+sPX87gEvBPTJki
         kd2w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533KaoH4IcvtYSknhA7LSR6H5yHH2RfRwwrisJOYs6j5okKj2BWN
	kqJj9jZVIDmadb3g0vm3Qwc=
X-Google-Smtp-Source: ABdhPJzqRILmK1dbvwmujVVbzCNyBySncqTbQytqEtKqZ9K0EPYTFYxluWzwg6rLghLu0rzv3wwe1A==
X-Received: by 2002:a05:6830:56e:: with SMTP id f14mr12078294otc.85.1613414384738;
        Mon, 15 Feb 2021 10:39:44 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:7d19:: with SMTP id v25ls3997145otn.4.gmail; Mon, 15 Feb
 2021 10:39:44 -0800 (PST)
X-Received: by 2002:a9d:d34:: with SMTP id 49mr12281650oti.337.1613414384430;
        Mon, 15 Feb 2021 10:39:44 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1613414384; cv=none;
        d=google.com; s=arc-20160816;
        b=bnAahMm0EzUivyifOsF1Vx70o8/hWRjSY2ge9QpNc1ivTsSV9Fzs55KPyjE8/9lzqE
         Qzjk8Ay4dYpa1TJF8QCqU2kByETzJX2AHBwEwO/iH3qDVcsDNY5HrKyN+pwxwmQLE9nf
         Ui0BOs6MNGMFyymdhAuS/ym+zhBTlqDGY3f5ftYenbfKI/iUno0YaYWGdovFC4/8v+dx
         ncz7/+QA2UFidWKdu1BmIX6FJKaUYo/nh2Wz0aeVdIe87D/g5tYYq/JO0IUWwZRFKCas
         4v8JYyqmsmDLOXTod2mL3RUronL8ipHKd8exzYIm+n6JUllL1GZe5KS8g/LqRjtKePnk
         5Ruw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from:dkim-signature;
        bh=RdO3U9TTIQjQikFoKjhQyD3ohcqMNQaWyInFP7IbS+o=;
        b=MUSdThveE+KtF0+CAndsuTz4XzH+tWfCnd9OUacRmqJI53r7TeSgHQA2tJs182EXDK
         7K0Lj7o3/FUlzsRJudfWt3uX7oVCZDoeJT3a1RT+rE/G8Ssg4+HgzzmTl4m7eCroxDF0
         hT5hA6y/gRKul+l8zKB8eCOt0sqiVgq3P2OiVxAtuI2CWhA25XTzIk6r0NzL+pt8bol9
         kJAGKJGconZPpsEH9hZtHrk+o8YzVNiaqA5Uhlk7JM8g5b+orUwQz38/9oniLtbCnRKt
         Ij5WO2egcemotbJ7rurr4GtM0jqgCbdMPug2DBwZJeQgNHM6OZG+wtUWYPnCfs/ZRll/
         yvQQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Y2Dh1FEX;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id e206si1520788oib.3.2021.02.15.10.39.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 15 Feb 2021 10:39:44 -0800 (PST)
Received-SPF: pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPS id 9407960C40
	for <kasan-dev@googlegroups.com>; Mon, 15 Feb 2021 18:39:43 +0000 (UTC)
Received: by pdx-korg-bugzilla-2.web.codeaurora.org (Postfix, from userid 48)
	id 81B89653BB; Mon, 15 Feb 2021 18:39:43 +0000 (UTC)
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 203491] KASAN: double unpoisoning in kmalloc()
Date: Mon, 15 Feb 2021 18:39:43 +0000
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
X-Bugzilla-Priority: P1
X-Bugzilla-Assigned-To: mm_sanitizers@kernel-bugs.kernel.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: bug_status resolution
Message-ID: <bug-203491-199747-RtcYiWFkVo@https.bugzilla.kernel.org/>
In-Reply-To: <bug-203491-199747@https.bugzilla.kernel.org/>
References: <bug-203491-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@bugzilla.kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=Y2Dh1FEX;       spf=pass
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

https://bugzilla.kernel.org/show_bug.cgi?id=203491

Andrey Konovalov (andreyknvl@gmail.com) changed:

           What    |Removed                     |Added
----------------------------------------------------------------------------
             Status|REOPENED                    |RESOLVED
         Resolution|---                         |CODE_FIX

--- Comment #5 from Andrey Konovalov (andreyknvl@gmail.com) ---
This is fixed by:

https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/commit/?h=akpm&id=1a5083113ceb13e41b90ca73972d6e71f23d959d
https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/commit/?h=akpm&id=a12790ebf6a97c453f5ca53048ac46229b88182a

which are in mm and should be merged into 5.12 soon.

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-203491-199747-RtcYiWFkVo%40https.bugzilla.kernel.org/.
