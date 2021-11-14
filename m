Return-Path: <kasan-dev+bncBC24VNFHTMIBBUX4YWGAMGQEDSS3REY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3c.google.com (mail-io1-xd3c.google.com [IPv6:2607:f8b0:4864:20::d3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 6470744FBCB
	for <lists+kasan-dev@lfdr.de>; Sun, 14 Nov 2021 22:23:32 +0100 (CET)
Received: by mail-io1-xd3c.google.com with SMTP id m6-20020a0566022e8600b005ec18906edasf479657iow.6
        for <lists+kasan-dev@lfdr.de>; Sun, 14 Nov 2021 13:23:32 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1636925011; cv=pass;
        d=google.com; s=arc-20160816;
        b=oSadL7462qc+LWXgiHX5pYvQ/zeUIe+3Ba+tXlTwt8m4B4b2p5cSDfeUoj0LJHtnen
         khiNHh33Qjl1uP2su/1hNZW0bcNEnjovcL5swMwQtRvHDLU71oB7KLKG4SiBhnJQYuD2
         gMustCJsRxx1W8QtbZnF0gP4CVGVJJW3YcrJogi3QQAFwip1PF9LE9jGzK3CEMsWk7pa
         JvxIXFhUS7aXyFFErxWIuPgIB5jcAuEL0SFgh9z8sQu20wD0+diRNtXJGoe7unt35jUH
         RW4GHj4J7Ka2eQ6VCLkPzrssrQfgFvknaRvvZTp/0sPKkk8iHi+Q/ILkwcUxyo8R8+Cm
         9KCA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=8Hw0grwkkLyU+Rvc53HF9uw226nVS/n+e7Q10/hf38A=;
        b=RVcZPMXBwkAjA0q5tC+Fa3W+0zCZHDbJmd0jyvXRnC+Tn3R9zY8miY25L9COEehyiV
         ++vaC1zMhKjQOaDSsQY2PRPhlKK3saGd+5sMkSEcasIPgyUNqNpcGr96a87nyE7XZJME
         xJmHMNHiYWtjwFrc7+JpJ52dtvW0PVpdIbA20+nvCL8DQ06yTeKhXRkA3Io7KTLKrRsM
         N/SzaZlR7+fstA/TB/o4Rep/S69r33EEAY5Isx/6V/Pmv785xL3UST1949ieZ2xwkSQ2
         G59kMDA2tGUeU0PfUdCU6NW+ERKjkdA3Mkd9KVeBLf8qGdspBLwwLbxPgNN2fMGps+pQ
         UMFg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Ylaa5JfQ;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:subject:date:message-id:in-reply-to:references
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=8Hw0grwkkLyU+Rvc53HF9uw226nVS/n+e7Q10/hf38A=;
        b=oEzEav2fm1zreNIYY+ZfzUEQJqTq5X24zwTwuPSGqyU4pIScXpndmZb/dkexogDCtW
         XU/41tCf0jQsaTSAZxzbDrGclswTiU1KEyfXUeLwnARYCTR3CL9kQyCh3VvMbjKwhLEN
         HTsOd4qR+ASE8/8Xd7/5eHTvYd1ko/nUS/xFU5/4QRIEymCyHuJS8PMasBv2drHj96AI
         2a2uJBPJgaAxMbuZwZ+fQ9HxNUKK0PPVF7WwWiBkgIlQMU5pSOrswRJ4SrFEJiY5gCZN
         SAslA7RmN3c7UOhcyD0lLW4rESMneE39xt6RAMgkiQnHsR14p1S+95r7ReCMD11+4ae2
         9Psw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :in-reply-to:references:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=8Hw0grwkkLyU+Rvc53HF9uw226nVS/n+e7Q10/hf38A=;
        b=zP/uxvE8DcwWq2hAlEwkFe8cJOH1V0wZCYLFnPuZEtW8L6892vP9HEOA9GY6k3OeNv
         oKQlucHTjd9JYaXFTjmIeHEcJeFBg+GLatifU/oFuh4SsqUAnrE6v/6B7golBQH1Q6TX
         I7euqVenvjjc5I6YmGfa2IHzHL2eRfBK2PcBnJ8vIZBp8X32mioN3+LMMtIGzoF7Fo/a
         gYKoDFckOL6M2yCvyrz0qRKFj4dilwOtUNYf747foSkwvE2ucIwN605gRIiKvFqlw0aR
         /bELKMWrpN9cB4yXdKtZZOjEV8Oxlhti0dlUE7iDh47RO8KEMaoXSXX5WxGtATzqPUKn
         o2Cw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5314Jl8IMMqhEnXtIsfh03br/WUltPY+swlcpfndsRbpzBFGlw9+
	GzSlFrSPW2wsT5QE8G25OSA=
X-Google-Smtp-Source: ABdhPJxEuj4xwzC2iV53kIyczXs2o1hpHWz3QMG4I8XalI6ucKVD2ZLLg0pU/H8EZgNkKRnbeteVRw==
X-Received: by 2002:a02:954d:: with SMTP id y71mr24988664jah.83.1636925010869;
        Sun, 14 Nov 2021 13:23:30 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6602:2c0a:: with SMTP id w10ls1596950iov.0.gmail; Sun,
 14 Nov 2021 13:23:30 -0800 (PST)
X-Received: by 2002:a6b:c881:: with SMTP id y123mr21933394iof.53.1636925010491;
        Sun, 14 Nov 2021 13:23:30 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1636925010; cv=none;
        d=google.com; s=arc-20160816;
        b=DHKVrYu9xBSJeexe+AjOg95c85JbpjEc77efmA+ahGBwhdqF3XUGDjK2jgx65BEtbA
         hfKnwjAh6m3CHJOvC4k4fXdMk3ha3ym5+O3fqhwrQb//TFisdGWWz0+CIk/LelGE4DR5
         UxyufuG22Q1+m8Ff1x2D5hSCrh/ryT1ysPmC/dtsOLoS3yrJ800uPpn4e8In8xlz8Bxm
         ohdPNBX0Zyxv1mcu9BzCWJy0QDk/Z2RJKmyal4/JKV3NPx5wUeJJPjs8FidwKtTqJbeC
         An6npmMLyzzzoUYDV70ANM31/roPL7Bx96gGjp3GTRsXH4TttB5HIS2+d0NjWHTt2PmR
         JMkQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from:dkim-signature;
        bh=CbxGI7aRqzJ1S5cbuhaoG5QgHL/OENDAcQY+ca9pnr0=;
        b=M6kzkREoaxtwdsh8/YINXjABDrtVT6H2yrjzrBcFVFskGv+Dgx2lL3nKLlH0+iQWEN
         XHkYSnzfBN3+Vps3kHYtsZfbkqbXL/5SQ8mZ1Qpc9yrbpnT9vxM8jbH9cLQCtL3fuZRu
         mW1Wzy/C0Wmk3uy7gAhPbAeBa/toZYFunrzzOsR+w3dej/TYbb3ckog1BsyCquRZ3ft5
         yanjkG9VlE/OGvX3x0CYpJ7UDHkRjbD471k92u2jzbXkpTKCGwZEUFtTgonM/mGAWoZS
         ijVm98Cs5Z9sO0N/l5ZJtZNglTuUfCaQ5x8GTfcFxSF3tnBD/Grwc3mY0BshMxF0QbHO
         8M5A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Ylaa5JfQ;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id o6si792894ill.3.2021.11.14.13.23.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sun, 14 Nov 2021 13:23:30 -0800 (PST)
Received-SPF: pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPS id 935CF61073
	for <kasan-dev@googlegroups.com>; Sun, 14 Nov 2021 21:23:29 +0000 (UTC)
Received: by pdx-korg-bugzilla-2.web.codeaurora.org (Postfix, from userid 48)
	id 8EF1A60F51; Sun, 14 Nov 2021 21:23:29 +0000 (UTC)
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 213719] KASAN: don't corrupt memory in tests
Date: Sun, 14 Nov 2021 21:23:29 +0000
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
Message-ID: <bug-213719-199747-hXbSOd8gDq@https.bugzilla.kernel.org/>
In-Reply-To: <bug-213719-199747@https.bugzilla.kernel.org/>
References: <bug-213719-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@bugzilla.kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=Ylaa5JfQ;       spf=pass
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

https://bugzilla.kernel.org/show_bug.cgi?id=213719

Andrey Konovalov (andreyknvl@gmail.com) changed:

           What    |Removed                     |Added
----------------------------------------------------------------------------
             Status|NEW                         |RESOLVED
         Resolution|---                         |CODE_FIX

--- Comment #2 from Andrey Konovalov (andreyknvl@gmail.com) ---
This is resolved.

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-213719-199747-hXbSOd8gDq%40https.bugzilla.kernel.org/.
