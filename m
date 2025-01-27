Return-Path: <kasan-dev+bncBAABBQ65366AMGQEEBLGUHI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103c.google.com (mail-pj1-x103c.google.com [IPv6:2607:f8b0:4864:20::103c])
	by mail.lfdr.de (Postfix) with ESMTPS id 82ECBA1DD78
	for <lists+kasan-dev@lfdr.de>; Mon, 27 Jan 2025 21:38:30 +0100 (CET)
Received: by mail-pj1-x103c.google.com with SMTP id 98e67ed59e1d1-2ef79403c5esf14416521a91.0
        for <lists+kasan-dev@lfdr.de>; Mon, 27 Jan 2025 12:38:30 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1738010308; cv=pass;
        d=google.com; s=arc-20240605;
        b=HI9rR6XEv/WBfNbma7Cz717lmRspDBlTi41jry+pqP/oK7q0/qy9N+IuLmmP7PLtW/
         YDND47xDgL457C+4qouUHkqxxOzVhLbZ07eYSt1nTFoi+ikIEjgAtNZsLDtmR/qtFseV
         UtZdC/HRQulEnM+VEV7dG03hrjGNyxseUm87+UbJhU1kHB2WdsznM2s4F0Ywn3tdO0W4
         pUpu2SU/MCicWoQcnurHfZTd9W1QKUiCvDEhICv/LQwwBCKSVR/o1iqqKB0nBeOXI5Yq
         N3nEFRaSzVTIN+Eio+HSgfBelaSe4vTcMTV5yOb2vOGKN3LTkj0L2grzZreCpgb91tlo
         g5gg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:dkim-signature;
        bh=FENOHwIYMdyqb0/0F40quheZ5wyJfpyMj+ViYvVjxto=;
        fh=MUXbZxVjqu2Al8g5Da1vmHjKJ4v/9R75a2t8z7FtqV8=;
        b=Z7XWDVGcJlfNR3VP9yE0BR7q2wWbvmBz0jkROf3MbwMk9b06w+rNLCyMTls/JGpOIU
         rT4jH9YB6UoVNHMDE/yBVrRb4Pb2BBKvevyxvmqUB9o3y4xlHx18WeOqpp3IpCTR57Ea
         wdQEBobwVfV8TDLevIhoFgEcWgoMChRFJN5qFbcHGieYNw3viY0CJruC5hXch7nHpyRR
         UN2b0uFXEKOjXxmsbfiHETQUo0fN6JYbfDHXWlOCXPI2BZJxl+T2e+6tKnSDLsnF7REy
         NyPimafKTYnxTDJrKOsxCs2f3epUyU5WHnN7eqvWSjMHJGB3+vCMcId7umKXtoTqtibW
         +A8A==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="m/+jOd/u";
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1738010308; x=1738615108; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:from:to:cc:subject:date:message-id:reply-to;
        bh=FENOHwIYMdyqb0/0F40quheZ5wyJfpyMj+ViYvVjxto=;
        b=iw/ks7bq7GLx0f7MkG2rdtyhjWir/R5chDFx+PU1+VOzVjsv3CXyuvwUewsQL/WMME
         bMV+927gF15K6SE/L6jarR7BrpEFePZVOVKLhNVD6h7MCXOsEyQldC2rHbwfGrEb1Og0
         raoUJKirIaRPK+G6jFU6VJei+bJpHs10PQ5kwqHceJmztSbh/YBW9G7exo687X9VLs0P
         WtjtSy+CTBi+B+UbymOMl+vfb3qpW5RnytaiOT1jMegECc4XqurtZeGXk4CBuzgcfM/I
         vzRoxHOqGw8d9Xe8lHTCp5kwf3q6siCi31O+s3FwJuS9UFlUl+IEcxAEHD7H6YtKz0BF
         yVaQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1738010308; x=1738615108;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=FENOHwIYMdyqb0/0F40quheZ5wyJfpyMj+ViYvVjxto=;
        b=YRNodRjNg8mUeN2da5YTg45SC8KgnbuY2opdBVAxKq/WyuAlNduCUKMbByUoZZSVJS
         u8lpl68s4RrUUZutw4Dxgln1kvZMhhVGHNFSJTDX6xhBJ4jH546r4JbNahJF6yeHpMFg
         /ph9Jsk34SFz2gor2Hmr17BK3DC2Q5ND3dJSAuRZIC43xWm8jxiKwqFcjMERsOcXPe+a
         azuDgu0giTUNp1aiTbrkEagLGmXEuZTHDaTeghoGLPG+wiCCiqaxcEF5LdEUx8YdvhGK
         XOVwz9LkmBM+rquo0eeYQ8qltq7WWxD2qn8xn/aa+hbaMvuYhapMUOPSc4HRYv6ydkMl
         U8cA==
X-Forwarded-Encrypted: i=2; AJvYcCWeeyszJDNkqGXgl668ByxMtfSGTCoZ55/xGejiZGeMUerhS3LkQzidIvFkio0ZI20CIY4z2g==@lfdr.de
X-Gm-Message-State: AOJu0YxHEEl0szSlb6djZqBmoGKlnAs1r9XHbwU5AbDvmuWlSzD5YIJF
	g08AxmDm4D/abSG8+xo8BXAXg/g7qdhzu9Xa+AC8HfA0fuSXn8d5
X-Google-Smtp-Source: AGHT+IEUKLZ7MVieMEXHIdg0DtASnwAp2vcgoqJHjfyRthcKbCvAnxdPKFTeSkQyirwxXw7rE2b65g==
X-Received: by 2002:a17:90b:1f8f:b0:2ea:bf1c:1e3a with SMTP id 98e67ed59e1d1-2f782c71e64mr70146444a91.12.1738010308127;
        Mon, 27 Jan 2025 12:38:28 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:d388:b0:2ea:4633:7a29 with SMTP id
 98e67ed59e1d1-2f7f13efbe8ls4813882a91.0.-pod-prod-03-us; Mon, 27 Jan 2025
 12:38:27 -0800 (PST)
X-Received: by 2002:a17:90b:4d05:b0:2ee:5958:828 with SMTP id 98e67ed59e1d1-2f782c70176mr63845582a91.9.1738010306924;
        Mon, 27 Jan 2025 12:38:26 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1738010306; cv=none;
        d=google.com; s=arc-20240605;
        b=EB10o/3sS82t4AdbfG1GYOu5U5HkvwAeb+uODNCmhIgcAGrmEH/JWPi87PFsRCEqOX
         wrqBkBti2pu1eE1i3ymItJpu4SQbqtQrdegrIBfOdxk96RE3kVWY3VhMXiTG/M0INfRd
         ZZX8y0RDeDhlcte67Fg6RbPb5BiIM+e7Tb5OZE8D6uwbFovyonU5oJ1WPueQgw7tjlH/
         Gm1oz0nLw9NM7ER2vJFnFZTF49itAMtF5PGZCgAJcwzSvBozH8kI0Js8jiFeablHHEjQ
         O52eSN/clSyAQ0K7JJZeGgZ2DuZpKY8lfcTSpM8Tqhvq44bCtcBBo8GA436v9vNd6wz7
         cVfQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from:dkim-signature;
        bh=/3fDNYICWO23OtsHwXaZv2PtwAsIvSpjrn8R9luT1G0=;
        fh=uQCsmYQr+KJEcG63Y45gsyDulzJl/B4EdEfpx8XrGGo=;
        b=XPGGoojEegDAnyUYeRcOQlJzxgdEEjtNZhorD7ealiWc3VeGYnJM8oUXu3a0qOxZwr
         HKW2TlthwzsXYtNN8h6rZ0Q9f9TpzWMkZX36c5qEWM1b3Ns333cdSN1kb3cMYDx/rQYg
         3+GYr4O4HlTMyj3nHG00zNX/fJhwl/8Rq1geDM+pj0WopLpy2aCjxByP9LCYu1A/DNvk
         9NM0RTbh2iNOWyV7b7ARNs4uewXRF3C6BoRtoz37a2b4RLKntYU7IwEnBH/t4IQPZpvQ
         Q3cU0A/zJtXkh2QVRKtpdy2qQX9fkBIsesx2R1OXCvQXFEAFaATW3oJZLn8H2zx5aXGm
         lDFQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="m/+jOd/u";
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-2f7e46407aasi916506a91.1.2025.01.27.12.38.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 27 Jan 2025 12:38:26 -0800 (PST)
Received-SPF: pass (google.com: domain of bugzilla-daemon@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id 1D1485C1178
	for <kasan-dev@googlegroups.com>; Mon, 27 Jan 2025 20:37:46 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id E73F0C4CED2
	for <kasan-dev@googlegroups.com>; Mon, 27 Jan 2025 20:38:25 +0000 (UTC)
Received: by aws-us-west-2-korg-bugzilla-1.web.codeaurora.org (Postfix, from userid 48)
	id DC3E7C41612; Mon, 27 Jan 2025 20:38:25 +0000 (UTC)
From: bugzilla-daemon via kasan-dev <kasan-dev@googlegroups.com>
To: kasan-dev@googlegroups.com
Subject: [Bug 216743] KASAN: fix sparse warnings in tests
Date: Mon, 27 Jan 2025 20:38:25 +0000
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
Message-ID: <bug-216743-199747-SrVhlML1GN@https.bugzilla.kernel.org/>
In-Reply-To: <bug-216743-199747@https.bugzilla.kernel.org/>
References: <bug-216743-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b="m/+jOd/u";       spf=pass
 (google.com: domain of bugzilla-daemon@kernel.org designates 139.178.84.217
 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
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

https://bugzilla.kernel.org/show_bug.cgi?id=216743

Andrey Konovalov (andreyknvl@gmail.com) changed:

           What    |Removed                     |Added
----------------------------------------------------------------------------
             Status|NEW                         |RESOLVED
         Resolution|---                         |CODE_FIX

--- Comment #1 from Andrey Konovalov (andreyknvl@gmail.com) ---
Fixed in [1].

[1]
https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=5f1c8108e7ad510456733d143b8ffc4e2408b1a1

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/bug-216743-199747-SrVhlML1GN%40https.bugzilla.kernel.org/.
