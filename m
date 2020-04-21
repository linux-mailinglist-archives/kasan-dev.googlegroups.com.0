Return-Path: <kasan-dev+bncBC24VNFHTMIBBQ7F7P2AKGQEXXWHTWQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x539.google.com (mail-pg1-x539.google.com [IPv6:2607:f8b0:4864:20::539])
	by mail.lfdr.de (Postfix) with ESMTPS id 3DA001B2773
	for <lists+kasan-dev@lfdr.de>; Tue, 21 Apr 2020 15:19:01 +0200 (CEST)
Received: by mail-pg1-x539.google.com with SMTP id 62sf13014640pgh.5
        for <lists+kasan-dev@lfdr.de>; Tue, 21 Apr 2020 06:19:01 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1587475140; cv=pass;
        d=google.com; s=arc-20160816;
        b=YezeDz9bJapqw1RFH6fkRNlwPd1CSG0kZX0OqepAI/ro0AOWgIDVtGXKDYI9LP8YsD
         XYh8ZctASmpeCAU13U9z4Ar+tP6WvmOJmphlOpR00sWwiliGFlyE/3Xpe93wKTf1T0Ww
         /wD6klxo3bp1p4PimPxNMkBTJ34c+/jc75ntWd5uNgWoZx3wYo5ovdCJ4AXsIRNU1KDR
         F6E6ctxUiW4K6/FhpsOs6mgvFiVFO2zizojjvjSuNugePE/qvZ40aVN1NPuez5HdyErx
         fuEaxReFZhxsZWUwm7dnOqaEBDGmy829PNmjF0PAiBigGY4+CWYVVI6fqTp1ohDvq6HS
         3C8w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=4AeQf6hVKTkokXXFsSPey4jqXOJg7PKNDv0xiJjPBuc=;
        b=h9FMQGOYiH7vv2B33PEXlkB5AxK/amoqC31VeYfeA/YWk4uuHC3uVSc+r7nuriKCTZ
         2rJ0YJoRBYFHSFC5NnXOXT13PqkvWtvs/nRhJ1dqh3ELDTlVrKOq+XBXpN0Hx1oVJy3Y
         0MM+omFQOufkijG4rSglaKBS3I3ZE3SwLnfmfTXjab54EwsTSeZI+J8mtuj2ld3UFWS5
         PZh6T0eY+iU1mtoBwj0crfa2ZpPmPjCbqerFiJfjMVGGoJy/tSVxBmQmqQ6sluYhDHpQ
         yAAzI9QVVeNkZtp0iYmw8WahNbI13l/89vSDjePrx+EQiwCIZ7h0YdSBe0varaOdsXXG
         9oAA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=06v3=6f=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=06v3=6F=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:date:message-id:in-reply-to:references
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=4AeQf6hVKTkokXXFsSPey4jqXOJg7PKNDv0xiJjPBuc=;
        b=QGcGK2JdPcbY1aMC6mLvFHBxRLrMmz6CydNZueclgp1oOsLeGNoxXzQTwdxViTkj5g
         WgVQcIVQM0eC5qTVDes3H1eNEChGivsVmSvJv4A+VzF0NhTM6/TQZ6oChiS5OLO7u/sG
         NAuDM6jHmNQQfSIXxn9V7e3vfRTgDzyLGqVG+xwJCFp0+Yej/3xavo78qn9F2wmZcEVf
         vAreY49+MvC3zZNgHyGukdKR3l3HxM4S1fmlRcoa2lGfPdMqz3M7Gs/AgSbxbyabDMOy
         Y3p0xdGp+pBQZucorpC7Qg4FJSLpB3Kzqy0XJini2n+g9JCFvJSs+op7crK23tl0VcxJ
         Ju/Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :in-reply-to:references:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=4AeQf6hVKTkokXXFsSPey4jqXOJg7PKNDv0xiJjPBuc=;
        b=dRAAv7gQBq232hr8fiq0Xuiz7VanUMUoeDUKYhRy6xkVBNDC+Kr3R1JFDIiVDe469v
         x5a5/pxsBr3pCwrEKjpj+q/bxX2/y1cPM8wCV+45tiS4L4xHawBPnneF1B2sjXHA6N/i
         pG3FlG9UNTgCwITNMDM57krtkS+hBVFll5IZ+M0ZNBNFC//l0qu5thHnViQ69M+iCGEv
         syMR0jXnvAa5rc2zVpJ870dsN/4TwlI4P7U2nkigrNAZNBoZTGus7Gzd86u4/sB8rUqs
         aAtWMWECySNtT/0Or9WwIQlTNoLssbAAqjokOelWXpzd/kUfhUCvQ+12YGhCdvG0KLX9
         7JRQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AGi0PuYYsw1QafomXkd9EvpQeTr8EGL02Yjsjdz/qufaf3kGpKhkqnMz
	7PImtVIAb5ZrzSA6nWVPHgA=
X-Google-Smtp-Source: APiQypIvTu9X6Sn7Y+S0oIIx5ZZrc6/iVYOf1uqV8eyL4FCoyKeSqlz7+jsUjVmacfgonGLxjyIb3g==
X-Received: by 2002:a17:902:aa84:: with SMTP id d4mr22113868plr.158.1587475139949;
        Tue, 21 Apr 2020 06:18:59 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:9117:: with SMTP id 23ls2971404pfh.0.gmail; Tue, 21 Apr
 2020 06:18:59 -0700 (PDT)
X-Received: by 2002:a62:2783:: with SMTP id n125mr22903107pfn.133.1587475139564;
        Tue, 21 Apr 2020 06:18:59 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1587475139; cv=none;
        d=google.com; s=arc-20160816;
        b=aRtJ/jEJedJoPulJYH4YmlrD+688Wenm1n9MR8v7u31CAufh4W9RN5eoQUKIISXad2
         mzTLxT0CDfS0s4isF8M2cn5fwiyyHl7nWF9WStX6h/StHbJHvAF1VsUfFalYKZQUrVEL
         EQ69d0iuuE4tZHv1d2BSbDvSRA9fyFcWth20u9bFOW8kz28VKRDlCuR8P97mtEsoKOdf
         Lmw7jsuue4SIkUriMNpY36Ko2CS2VSx1cDfHQq8YYdNcdImZP/51ZEb9QrnKztDLaTeO
         POsJlBwCKYHfzWf6I5/wrKSLe0807WB5LFlkCq+GQWh7MxCPtGtza+qouV//5g1gOANv
         v/Vw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from;
        bh=c26JiIJSJB6TGkALZLOrHDA2IKqSrShKc9DKZwerQxM=;
        b=sscyEAl3PBLQTLaz1ZwJ7nB6MbQZwKy4rKUEZlawseyqnnm6K/ng+eP92YKgH9yeyk
         0Fnxu7RUtEEaLX8BfopQJ77aZoqRTi6aRiesdG7qigpMw3tGjdTQ20IYR5sWxDngk2Gh
         Ym/FRzHgNooIt4Y5t53u15DcG8Up/uzpQ6Gs29uWGg/F6wTEcudeYVX68lBh6Wbri8PX
         itu8IQ6iZMW0F3nl/JlJNnbmEVd2HsCoi4jECSe1YNQq4l+iUWgk5LWCTfA62+eh8wev
         3Y+sobFbp4qbf5MRZ0Lke82l4TxzH0Ipgm8Ld0+KevNdJ2cBkJ9mWfybZREQoyU6W6pa
         pUxg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=06v3=6f=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=06v3=6F=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id gn24si452280pjb.2.2020.04.21.06.18.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 21 Apr 2020 06:18:59 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=06v3=6f=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 203493] KASAN: add global variables support for clang
Date: Tue, 21 Apr 2020 13:18:59 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: changed
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Memory Management
X-Bugzilla-Component: Sanitizers
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: normal
X-Bugzilla-Who: dvyukov@google.com
X-Bugzilla-Status: NEW
X-Bugzilla-Resolution: 
X-Bugzilla-Priority: P1
X-Bugzilla-Assigned-To: mm_sanitizers@kernel-bugs.kernel.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: cc
Message-ID: <bug-203493-199747-785QD9v5BT@https.bugzilla.kernel.org/>
In-Reply-To: <bug-203493-199747@https.bugzilla.kernel.org/>
References: <bug-203493-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@bugzilla.kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of srs0=06v3=6f=bugzilla.kernel.org=bugzilla-daemon@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=06v3=6F=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
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

https://bugzilla.kernel.org/show_bug.cgi?id=203493

Dmitry Vyukov (dvyukov@google.com) changed:

           What    |Removed                     |Added
----------------------------------------------------------------------------
                 CC|                            |dvyukov@google.com

--- Comment #4 from Dmitry Vyukov (dvyukov@google.com) ---
First we need to remember what's the actual problem with global variables and
clang. The root problem is not captured in the report.

Potentially the problem is with kernel than clang, because I would assume
global variables work in user-space with clang.

-hwasan-instrument-stack=0 it related to stack instrumentation, not global
variables.

-- 
You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-203493-199747-785QD9v5BT%40https.bugzilla.kernel.org/.
