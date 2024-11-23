Return-Path: <kasan-dev+bncBAABBCX4RC5AMGQEFOERHTA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83e.google.com (mail-qt1-x83e.google.com [IPv6:2607:f8b0:4864:20::83e])
	by mail.lfdr.de (Postfix) with ESMTPS id 0C4C99D6B7D
	for <lists+kasan-dev@lfdr.de>; Sat, 23 Nov 2024 21:41:48 +0100 (CET)
Received: by mail-qt1-x83e.google.com with SMTP id d75a77b69052e-460b8f4bab8sf56861201cf.2
        for <lists+kasan-dev@lfdr.de>; Sat, 23 Nov 2024 12:41:47 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1732394507; cv=pass;
        d=google.com; s=arc-20240605;
        b=Yvt5ekka4CUt9wfytvSBdc4XjDCKQi+lRfF7gqL2Cqvq8p5YZm/L9qPrLkpHgwlhJI
         qwGIBTXGvj+LDv8A60S9lwGW5ps5zJPHa63h1Y5fdZAgYrBVWwkdXokK0+ZHxdJOoOyL
         wO3pl8dgcIuWEJkZoKdF1r53zAkhBk3EAKF1cjUdFuuMumPgSzM0DtrYcqippzyjkyLK
         Hhq5zlVdlQcONjEwZlEvboNJ5tuyk+iDeiUK9oLOELHxvXAcrXqcK1mzmQ5VPdJP+per
         tlZ5Jfqin/JKXWG+d2QAt5rb9p9iZnaOpfx3ymYLprtGwAho0CGdWriLSJwRDddyJYPV
         gLHA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:dkim-signature;
        bh=nvI6J6QTo3qmbwip5M+vgaFZRxTRlw6cVFpd8o13xkM=;
        fh=8e8fGI3TnOWdyTUsdnHxPUv2cuxZEcW0dwdUlIPX4Yk=;
        b=OZS4sKgPIdUcx6Cw5Fa167WjU2rUB/HJV2WioQ/HYYXPc8W+y3LugpmqEJI6An/K7H
         zlGwCO7McHOoPOcMoM4AaFVpKXPlkqsqPlHOC44IpNZ3Pcuu/fMuJpvlhjKBeees8kXZ
         DpyogW3t0qpVaei4UZpkkwYjGeKTWNHnb2NJPM7nXrHo9+9dGyPxBmOVDpf0XgaRGQro
         D7uFgYdy20/991+F3FjPMuTE7OAkbOajBwCt9uuO0OpApsjvjD1erAwomZiQS0ZJW9MA
         OWttIW8N+OlyZ7ElB8m3sAZVu3tssaLO4u+0Od18gryVkFpoVGJSxVfEQICkq8Gw6diB
         XSLA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=PWxHg2bP;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1732394507; x=1732999307; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:from:to:cc:subject:date:message-id:reply-to;
        bh=nvI6J6QTo3qmbwip5M+vgaFZRxTRlw6cVFpd8o13xkM=;
        b=GPYySAX6FQ9ppBxKCkNZz5rlv4PPHnGHOF5IrD3AgsRiFDuN+h5VcGOQpBhLXWOoHw
         oB09w5CSTZ08Mg4AKZoqF5zQcCD4Lc0478wZ2Kx3QxbYGEsOVkzNjbDeBa6iXHJTkd8A
         Gc4cN+/EzXZqBOvriyh6wENmf7g3NSnNTyWfihVz//kBRxN70Ls4G5GoO8+zlV55Ruxy
         RAIG4BGdcwgjTbvCUVUKTtZzqdWkEN32dGgT7JS7ThI/tj6NHIrajP66zMNYkguKN3gh
         fn3ZmPeZfAgHKn4VmKB9j/l3P0v5brJ67f70khCc2rkrLg146undKEsWQ57f1dg/yDeJ
         0lZQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1732394507; x=1732999307;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=nvI6J6QTo3qmbwip5M+vgaFZRxTRlw6cVFpd8o13xkM=;
        b=RT6x7G/iI/5mO8cvKom+Ff5mLG/LJtWsK1XiyXnKTdQEFdeI8IlVAdc7I00OuWtXWl
         gEHTvhWmYwchRfN3Q0OGUktJzBozO2GuGVHKTw+ICsBH+Gkuyd421lheVZxiGMLkv2wc
         ghEnSuWoJ7m/Y0zobusmbB76nA3E2GoH+hz+VY49rUHclhG70Y5tOAvsp0453BAE0iFm
         BPBVpAGWy6pk1b1uZIzFP5VxZrocHUMlCiBg9oglyfKJyJ/yTC47G2do8YONLv2VCsjU
         TXuMZloLpvMFOlkO0x/WjFUP+Yra+xcQl0a9xESjgZJIkX7UeudN52uYy0OoobShF1Rp
         v4ZA==
X-Forwarded-Encrypted: i=2; AJvYcCVCjBlDwZGookmkSqvGN/0bm52+q50jURT9i1ySr2TA78EC+P7O/grMadFZp6bCn+y1PsoOLw==@lfdr.de
X-Gm-Message-State: AOJu0YyBR5cTGwBE4g3gKH7KENfNhczEYATc5wkBmxxB18TwXRHriyBN
	g3367eYJtGBuJ7MuebSuvQOD2+/dKk5vw6QR/3BE/n4YkkShlpEy
X-Google-Smtp-Source: AGHT+IFEu0MuDlEY8JcMK9JOXOv+dg9Unol+RgvVa331csj9+jjbb65/+EKQCDPofkoJQrVYhxgwOw==
X-Received: by 2002:a05:622a:4a08:b0:461:148b:1888 with SMTP id d75a77b69052e-4653d5388e9mr135975601cf.4.1732394506451;
        Sat, 23 Nov 2024 12:41:46 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:622a:1f88:b0:465:2fdd:88a5 with SMTP id
 d75a77b69052e-46679ae867bls680891cf.0.-pod-prod-09-us; Sat, 23 Nov 2024
 12:41:45 -0800 (PST)
X-Received: by 2002:a05:620a:1722:b0:7b2:fa17:f7d4 with SMTP id af79cd13be357-7b5144f7bf1mr941246685a.20.1732394505710;
        Sat, 23 Nov 2024 12:41:45 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1732394505; cv=none;
        d=google.com; s=arc-20240605;
        b=NKX2Ztvm7kBjthi+b/67dIeN/CeivPKS0Nrq4m5GlWrWOAH22g/pUAYfeh9yqlhWi2
         BwkAc2j7hw2nA+fuWnn+aWcAH5Yc9bmaCQIDAEfXCo47mSEM+xY9y0kbXxbWJg2ULxVF
         RVAT2IxziTCjKzFai6QKm7zLe5tB6IWS3JLJVXPYOdMws0LO9BVGAYluY+j711hbxhs+
         zHyGszcsJ1Ilc5GfYY1iMULav7Ak9N5dzArd8uQCN8EbKQMEWHlU6dhdQWNlUOAvorC0
         yM/1f60PzeX6K8evYOAjmjD02Rbv/pF2qB4Uapk/MG2HOvwun5pfF3unOAJR0HNGi5B4
         O/GQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from:dkim-signature;
        bh=oDnKTCDOfzql1TrMzEPdgc/G9SU7k5mCzoS+1Iws/+g=;
        fh=uQCsmYQr+KJEcG63Y45gsyDulzJl/B4EdEfpx8XrGGo=;
        b=SEqBLwvlV4G3Pok5XfmQ7UZTYgXWPj76WrYhmdfApGF/0m6y3w+5jYAs6pbsRurwJn
         wDajIkjZ6p2fpc+xl0hGdKqBHZR8/JWiRjFhba8NHiLaqA5GyXoayATq8OLqPLHpk8IM
         CJoPKbZ7gDxW8Sz9Yw5j8mUQXM7/7k7krvjp7KkYT1L9hpw/RDYG0lyPSWNfnjwSojC3
         QX6zC7F22gUndpOb8pkrgSqOuSGErG/XspE64VxU/ck2V59ukJsx+MY6OMvEiH9Ip0q+
         41o2OBthUaXsrunqh0vIImrEwNs1Zs/64iP6VkvMY7vzs2liN0VytYbFRGEAw8bUGsWc
         eX3Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=PWxHg2bP;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id af79cd13be357-7b514167c95si18679485a.5.2024.11.23.12.41.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sat, 23 Nov 2024 12:41:45 -0800 (PST)
Received-SPF: pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id 8DE735C48E9
	for <kasan-dev@googlegroups.com>; Sat, 23 Nov 2024 20:41:01 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id DBCCCC4CED2
	for <kasan-dev@googlegroups.com>; Sat, 23 Nov 2024 20:41:44 +0000 (UTC)
Received: by aws-us-west-2-korg-bugzilla-1.web.codeaurora.org (Postfix, from userid 48)
	id CDA43C53BC2; Sat, 23 Nov 2024 20:41:44 +0000 (UTC)
From: bugzilla-daemon via kasan-dev <kasan-dev@googlegroups.com>
To: kasan-dev@googlegroups.com
Subject: [Bug 218315] KASAN: use EXPORT_SYMBOL_NS to export symbols for tests
Date: Sat, 23 Nov 2024 20:41:44 +0000
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
Message-ID: <bug-218315-199747-E8E3ZWP0PF@https.bugzilla.kernel.org/>
In-Reply-To: <bug-218315-199747@https.bugzilla.kernel.org/>
References: <bug-218315-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=PWxHg2bP;       spf=pass
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

https://bugzilla.kernel.org/show_bug.cgi?id=218315

Andrey Konovalov (andreyknvl@gmail.com) changed:

           What    |Removed                     |Added
----------------------------------------------------------------------------
             Status|NEW                         |RESOLVED
         Resolution|---                         |CODE_FIX

--- Comment #3 from Andrey Konovalov (andreyknvl@gmail.com) ---
Resolved by Sabyrzhan in [1].

[1]
https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=c28432acf61751c2be8b36cb831dd490d2aed465

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/bug-218315-199747-E8E3ZWP0PF%40https.bugzilla.kernel.org/.
