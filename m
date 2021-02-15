Return-Path: <kasan-dev+bncBC24VNFHTMIBBEMCVOAQMGQEONRX5JY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x640.google.com (mail-pl1-x640.google.com [IPv6:2607:f8b0:4864:20::640])
	by mail.lfdr.de (Postfix) with ESMTPS id BF78731C1D9
	for <lists+kasan-dev@lfdr.de>; Mon, 15 Feb 2021 19:44:34 +0100 (CET)
Received: by mail-pl1-x640.google.com with SMTP id f3sf7180083plg.21
        for <lists+kasan-dev@lfdr.de>; Mon, 15 Feb 2021 10:44:34 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1613414673; cv=pass;
        d=google.com; s=arc-20160816;
        b=JRuoktK143d6LmVwNW8EEKekgU8coEzQSS2NO4WRmQP7dPj1NMF5Q3WjJ3mtJWvMlf
         hipD92ARtjXDMshvabGUxdwXnaPHF/9qxPLs+BKa1w+Ka4BaximMxLchef+yusILCtFW
         Pa3zao56QZSQoqouks4QykI1WIEXPIaIBRMqCRZ6LHoQkohThFgDZxVnaxoApX8HbLme
         bNEKLTg25lQUv195+D4Wx2svzO4Tz0NBzyzhoqsVik7V6BGOkmS8hIikLQyZORBnxsCk
         3b1QIVckltR+Tfi+aS5kBtdc4935w7ykw8mNLZbFzh+yMQD7uVvsw8XH477M30kNyKbJ
         xY+g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=a3bE224x9fv6rBkzfc+QPuQSfZbKVrAsZRDy6fHHUjM=;
        b=kAzdJ8c+XJUwvYflHo+Vd8HpLgOZGlWRxzzD4mN8+bX73pgGcvKlBpjOT9SGBorYdj
         Ts+9zdbn52u0T9m8ihV2KaVQYEOG7uoPzsmVv9xwnhPZDR9MqpLeShsxTvoDA/gLAAAD
         zBZfl215zJMn3vegeIlfb6e0k5D7M9SKixg/Vzm1Xk5qEU25GhbD1i0DOtnYKLiZI6jG
         kgI+aTo3r1paN/Obhc0yVdQMPnuqtB66gh3QZpD7rmi8iE/SScajMhQexR/0OB9s3V8t
         04t/m0KyrQj2Ryrb4QAqlrOm0Ov0SU2lBggehSF8lyv/F4M2leCQeM2u1YjVJDKnoXEe
         IeRw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=mu3H6Dyx;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:date:message-id:in-reply-to:references
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=a3bE224x9fv6rBkzfc+QPuQSfZbKVrAsZRDy6fHHUjM=;
        b=jh6dbJR7V6pAHwiw2nhsciQrATS61jnkrIeqzY4B7WfR4GYKks08qKnhSZOriFi2bN
         2pwy4N8YlucDMCPLribez8YWEZxoF5aEiKlsH9Zw6Scn0Pr9WikApyXoYh6wXwFPxIkO
         /7nDzE8xslJu4Xa7d5/2dbjv/vEhtxfdi9GuosfU15ntfCpERnMJcme/A2YgmCeNKWND
         9zps10QfSbLv/JKEwj6sWIB4m7NR5nguZkTZ6QjuS3jnmeD0aUpYt8mRrRfoKpmR3fHc
         caLPs+QEDJTeNMhHxNa7VlzzwEKFz7QONU0dssbs7vNxLNnPqGnHq/5SHH6nRFOXPjnP
         4mSQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :in-reply-to:references:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=a3bE224x9fv6rBkzfc+QPuQSfZbKVrAsZRDy6fHHUjM=;
        b=YX8/86vidXKUf1tI52fGXRw9Ywkfu0P4DI8XwkvoZGKlAiBP1iqXoh8fkEm+mO6Ccs
         aqjw4hz1AUT0PjXy6w1kxTIeW+h0eR3AySRjEVM0COqhcdBOpi0aaqf6PbOr0QcgeLL9
         tVcmJieim7fofhZwsq6r3RG7F44pbwCWYBBHSpg2fKtkxzEHhfMOtHhbpZbh4weZeLFh
         q2hjGHOHlVtKL0EI4nA4xNTVXdhtYCBs25BmMdsefbvfH/UupTXIL8JQ3X3DkLMlNz4U
         CrglKhehWi1m4o1u7UELQLvk0kGuW8vOnPMt8mxRDBAtpFT8Lg1bNjQRL0cDSon4ocRh
         F8bg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530+wQMS5sAp5y6XyJPkJ2NCN/69ueSgTwM7P1aA+Pengc/3qD+D
	4BV0tqSJsTKd+R9Fo3xeljA=
X-Google-Smtp-Source: ABdhPJxCWlA0wxGt0KXz/7+8lTLfd53g+VUyLcbwVkzhUIRGfSAdp47UHdtovLAy6CLOO6EiJGDmxA==
X-Received: by 2002:aa7:9356:0:b029:1dd:644a:d904 with SMTP id 22-20020aa793560000b02901dd644ad904mr16183963pfn.18.1613414673539;
        Mon, 15 Feb 2021 10:44:33 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:e281:: with SMTP id d1ls91432pjz.0.gmail; Mon, 15
 Feb 2021 10:44:33 -0800 (PST)
X-Received: by 2002:a17:902:7d96:b029:e2:d7f7:6aa with SMTP id a22-20020a1709027d96b02900e2d7f706aamr16509218plm.15.1613414672968;
        Mon, 15 Feb 2021 10:44:32 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1613414672; cv=none;
        d=google.com; s=arc-20160816;
        b=aIXSaw+pNh3lQ9JoD272bCcmTxF3uxi9yDweWzt2vYz2KK+pJuMtLQ/KoWvFJE8qRI
         csEpM/vbECCY9EsFNL77q8ROxX6FSIuSW4zKieuBSdVmF2J6YfUjCJhnWtSgpTq4ODGN
         W2RMIdaL5X9RBf7cYSePD5DPVBWVEohh2GNHFnnuVyEo1DCzpDb6itx5FQ6+Gv6oGj7F
         +N0b4Ru0sMEaHnWWutMU+PyxHK/yCYjFKZmUlPAjuehxXj70PcQR/UPc8T30NHAGNOPc
         vgxigIGszfHKCfa3d5Qhhg94BL54t76w6+urRDPiqrvjXJKXXziDgSMCOGDC4dBGBEcJ
         oqYA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from:dkim-signature;
        bh=/tD4Mob4H1cjCcoANl2IFpDFPJWon0wVFXwOk5SFfzQ=;
        b=ica7nV4fWfqa9qG9wlgZIk+JoktezRV0vX6B5jiCglJZ+a6sxwI5++U93JNwHoHniv
         CtMXESWFjqQePw3P90HHUbDK3nPi0SiYUj9sYqc5M31NVgGzZ+lkYfPQXgYcoJGM9cMa
         QqYu6w0Csg/c30Qsn22hJeRzWyoBHsubGzhWD51wp7rZL47NSa3xKq3d6VjEEi00qv8h
         aa/QT7Qtzz3Meg60MHx1vAsDg3fMR3EtS7k1AdVJxqU7mQu8gqEqWwqVFr+GKZnHJ0G5
         CQ1pT299+i+20+5lUgHcuQFVMoFOZy3FMHwQpXtZGQbU7Od9XjChYO0VLYjDdEtmNqwG
         w0PQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=mu3H6Dyx;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id y16si989683pfb.3.2021.02.15.10.44.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 15 Feb 2021 10:44:32 -0800 (PST)
Received-SPF: pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPS id 8823C64E13
	for <kasan-dev@googlegroups.com>; Mon, 15 Feb 2021 18:44:32 +0000 (UTC)
Received: by pdx-korg-bugzilla-2.web.codeaurora.org (Postfix, from userid 48)
	id 68E50653BA; Mon, 15 Feb 2021 18:44:32 +0000 (UTC)
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 208515] KASAN: support CONFIG_KASAN_VMALLOC for arm64
Date: Mon, 15 Feb 2021 18:44:32 +0000
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
Message-ID: <bug-208515-199747-OnBK7mfDHu@https.bugzilla.kernel.org/>
In-Reply-To: <bug-208515-199747@https.bugzilla.kernel.org/>
References: <bug-208515-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@bugzilla.kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=mu3H6Dyx;       spf=pass
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

https://bugzilla.kernel.org/show_bug.cgi?id=208515

--- Comment #1 from Andrey Konovalov (andreyknvl@gmail.com) ---
Lecopzer Chen is working on this:

https://lore.kernel.org/linux-arm-kernel/20210206083552.24394-1-lecopzer.chen@mediatek.com/

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-208515-199747-OnBK7mfDHu%40https.bugzilla.kernel.org/.
