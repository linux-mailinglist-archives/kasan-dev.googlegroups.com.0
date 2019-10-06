Return-Path: <kasan-dev+bncBC24VNFHTMIBBC5I5HWAKGQEDX7LIZA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3f.google.com (mail-io1-xd3f.google.com [IPv6:2607:f8b0:4864:20::d3f])
	by mail.lfdr.de (Postfix) with ESMTPS id C434BCD942
	for <lists+kasan-dev@lfdr.de>; Sun,  6 Oct 2019 22:52:28 +0200 (CEST)
Received: by mail-io1-xd3f.google.com with SMTP id g15sf23742476ioc.0
        for <lists+kasan-dev@lfdr.de>; Sun, 06 Oct 2019 13:52:28 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1570395147; cv=pass;
        d=google.com; s=arc-20160816;
        b=CKWiAK6CLazNvaF7w8qHKOHBQKc5Z/LubjwBvuQwJ0SESQ4Ft8RAr5gWnl5ooZzKfK
         2zgTmfqlwFPSem8uzeGRV3wo0MlV6B6oc8MlWYj3UGqvg0esYWyTa+hK2swB9BI9FVKl
         20ubrwZN69mAgB3a9GVdZ/0OIqlkEJLfK+liPidoMGo7upU1N+nhwsHj9brH7kDeF0rh
         MS/TCiUtlyzt/QNtvjnA90/wUzNHC55KQb18aA+DCp6FbTSPxhTqXl3B3x1mwiQKsUAl
         3sXF3X8uvB9gqLvp8WwbYCeJYRa9UQ5pnIfB8CnWoUkU01rUACaSVhfhWyGCdwk4py5f
         6AZg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=AHRaBzNz4Gx7Q2nfd9c3iPOoN/vc+tGjIHndNtax16w=;
        b=kHjqT71LovEptVyTK7mMckyF7WW666fztllLpKrkYRsr0HqQOQNFeZGl7zwQSrCvqZ
         Up/hZrXG/V2laJRWQPROQBu/P3i5ywY4tqYm4Zrq7UfEZ3yEnRVGTJ9fI7gvaz0FKnss
         2g5A8JYioG1QpSby9i4/5qqSoA1W1MTQwRtitiR9SNc3SjdByPNHtiIFxvl3rGM7iPVz
         xtMnnkLwm/SzkZkFmmG11DHRoS85RSzSesgpzuQUPYhzPUfjqm9+Xvye2Dc1N/7K0beN
         3Cx3Z+HUJ1HwhPbTcDfskp6i1jyQmKmDkCd7gpOrb4DUcsThVkZDoxHSE7af1qQygB5z
         10NA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=26xn=x7=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=26xN=X7=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:date:message-id:in-reply-to:references
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=AHRaBzNz4Gx7Q2nfd9c3iPOoN/vc+tGjIHndNtax16w=;
        b=AeCDcmIoISXzngP6JeFsK73opyAbEfww1fLcyvXEXQQAeq8Nvz9svLCx/OH1MVOkdc
         gmCZKGc2ujK7zu5WjxVx+FRsXudrmpzcdbz6Tsi61MYoOY2iOKshVYzpwwknTzyJfi2c
         06Tx9dZRZW4opLSK+2iUxvhgWXWsGRYZeFTa1nSWpF4n+Mx/wprkbObi2u127X54XqzV
         wTJedooz18Q5yGS4ixJLFuip0egbiCpyhsitso6UzyeZVq4D9mE5tphyTJ0FOk9pA7ca
         4u2kMby+lyqtDQZdYTO+EtcJtEu3nhqJ2Cng7hDpue1Q3DmQjcvTTfrOIEQYJhFm7NLQ
         sGjg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :in-reply-to:references:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=AHRaBzNz4Gx7Q2nfd9c3iPOoN/vc+tGjIHndNtax16w=;
        b=SQe82jbcYqXIu0A1Yh7TGwk6LiLfMBlRQZ6q4b1bsj+fetoyQZ8c7ikkAKM+4Vc33c
         dLhmNlkQL1bzHHancqdDLZd51pR2cnalVmvJH6lcEDhZHeI02cZJxVHzFj1eNQT8u7gI
         zYevfdICkuB0gLSq4rmzv3z8G3FlG2SMFzvtEZTf9PTEolsCiqJNPYOkL2IKYv4A1GMg
         jDaOBEmuWrbKZx2YgH0KH7zS/oa1kmniR9TCyidaWhJ6L6jDWeLm7Z+BqwmY6Sx/stNe
         yvTS03PPvCojrtrCWIB4cQDRe4/1SLFMH3nc1JQsfJTPPmJ51FQ6srQqrcv3fVY8ZFLj
         x5Dw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAWAsWeB9LtaROrA03ONSYW4iWO1z/uWYsmUb7wsH6QjCQMY/wAu
	+5Lgv2PF0oGycJ9eTaSebGQ=
X-Google-Smtp-Source: APXvYqyybXJfOtI/jjcwIlwX/qHcBCEte19HbCBnmDJAkAlrFV0NPL02GlHBaiBHyLY01WKYj187sQ==
X-Received: by 2002:a92:ba90:: with SMTP id t16mr27681648ill.19.1570395147783;
        Sun, 06 Oct 2019 13:52:27 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:9145:: with SMTP id y5ls3074488ioq.11.gmail; Sun, 06 Oct
 2019 13:52:27 -0700 (PDT)
X-Received: by 2002:a5e:de01:: with SMTP id e1mr21588360iok.195.1570395147470;
        Sun, 06 Oct 2019 13:52:27 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1570395147; cv=none;
        d=google.com; s=arc-20160816;
        b=X4/8D/8IiOicnTx4l2oYXDaz45cZRgfhFxZO5GmLa5oitwGlrb9G8luCfUBx6lz2Sy
         k9AkDCaHJNt/rUjzDnrKzE5WP+DA6a6XLp6y3wJPfbVn7GLf2LTEJWpyqWjLg3lnf2Ws
         YGffxqzf8M2H2uuo7iSz4IcfByBPm+5kkiTvwNF9pLDdEMtnjj82nfWf8nx237EYFuaL
         Yp40Y5KWVxtJRY5iR5TQ8EBAoai0L63G98l/N897AAoTNo+H3XYx39w0eIns/7maZpf4
         YWT7EXjaxCohEL55grl3wWDmnuc2MUBOH2LbZhtHDInKBe+sCk0tUBodmfYsGhyK77A6
         o8Yg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from;
        bh=OpV2jCCn9+9EXsK0yjc9mXTtbYzvOEnzvXELPJVokgU=;
        b=qQu0yIsArNREagws+5o115Oha4lzw71V2DKs1pmJm6uNA90BlNEbXeqKPf7O4kxW/8
         Cuv/QhIbKxzh0WyqzTThXEZv4bqzxwoL/VfL3tT5GZwmKAoP6X/s9+lUYYlb7ra1Lstq
         dcqEjrJP5filr51tOPUjMmKrJ1mDcye9nKeVdEBmjNt+W61FneW2Zbk81UO9JkLyizKM
         qHfdLCWEgt8qRUUcMN5CnwNAzr4Scx0gGmRni3mv2LxTuFm3MWIpvNEFRzqbxoCTWXI6
         yb2633TGosHiTWPtxKlTmmSBV6eJPDPGzAFlxUzF+NzDwqkuKqblkfDiMtC26SJmtDCz
         D4SQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=26xn=x7=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=26xN=X7=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id b2si844797ilf.5.2019.10.06.13.52.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Sun, 06 Oct 2019 13:52:27 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=26xn=x7=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 204479] KASAN hit at modprobe zram
Date: Sun, 06 Oct 2019 20:52:26 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: changed
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Drivers
X-Bugzilla-Component: Flash/Memory Technology Devices
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: normal
X-Bugzilla-Who: erhard_f@mailbox.org
X-Bugzilla-Status: RESOLVED
X-Bugzilla-Resolution: CODE_FIX
X-Bugzilla-Priority: P1
X-Bugzilla-Assigned-To: dwmw2@infradead.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: bug_status resolution
Message-ID: <bug-204479-199747-rm8vY4C547@https.bugzilla.kernel.org/>
In-Reply-To: <bug-204479-199747@https.bugzilla.kernel.org/>
References: <bug-204479-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@bugzilla.kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of srs0=26xn=x7=bugzilla.kernel.org=bugzilla-daemon@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=26xN=X7=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
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

https://bugzilla.kernel.org/show_bug.cgi?id=204479

Erhard F. (erhard_f@mailbox.org) changed:

           What    |Removed                     |Added
----------------------------------------------------------------------------
             Status|NEW                         |RESOLVED
         Resolution|---                         |CODE_FIX

--- Comment #22 from Erhard F. (erhard_f@mailbox.org) ---
On kernel 5.4-rc1 zram loads & runs fine without KASAN complaining.

As the original issue is fixed now I will close this bug. For any other issues
KASAN was complaining about here, I will open new bugs if they still happen
(like bug #205099).

-- 
You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-204479-199747-rm8vY4C547%40https.bugzilla.kernel.org/.
