Return-Path: <kasan-dev+bncBC24VNFHTMIBBGPRU76AKGQEBLB2GOY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x837.google.com (mail-qt1-x837.google.com [IPv6:2607:f8b0:4864:20::837])
	by mail.lfdr.de (Postfix) with ESMTPS id EB652290C69
	for <lists+kasan-dev@lfdr.de>; Fri, 16 Oct 2020 21:46:34 +0200 (CEST)
Received: by mail-qt1-x837.google.com with SMTP id z22sf2063981qtn.15
        for <lists+kasan-dev@lfdr.de>; Fri, 16 Oct 2020 12:46:34 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1602877593; cv=pass;
        d=google.com; s=arc-20160816;
        b=kT/cdoxAX08Q81VCfCxQtnXqe0rRGU/cBvd3/jAm489Rc0DOWIj/CZ+6bS8tBrbLU0
         kbiGDxsLCW2YV5C9E1Aqub3i+DQwjyXGHLgOr6zoVE6KNLSWuOWMSOtj+PmGAA0+B77B
         u5KdyPyhbI8+PBO39Ntls4yM/M0sptqb3MXCNYWww9OcmimobXMW4md6znlyc+WhHPYw
         qLm4Apf8WjIUIp7aI6vrPjq7BCv7Hjp6rIA06ktp4ZWcfcRJb8L6+6tRdEi7SA2oT8gK
         e84SWt4XXz/GJ6/0yh1ZQfA/7kNI7thlt8hVJcVrJbI5ouFyceQleobJ6rHw6osGKLLX
         l/cA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=Qw6EB1gjuQ3gnqhnb2A3Gxhmy23whrvpbN4Sw3w8qfY=;
        b=bx/4/6OMjFInBVPJUjPMVRZZNMAckE+zMFe/KqsC13T6imePfPm2CztmTR99hp/pMV
         1Y6JavfryCVbfCW+u2Dh0iNzhQFuAgdtZ2a6MQL3vywg+ySoLoDbfXTc0fbwB25Lc0kt
         P/0lrDrsvnR/6HXNIqtLkdQ+TZEd1g5PldazExYQUu3eqmMBcHwwEhIBObMTu+rf6Vtg
         urFii2MlvQourXJAESXhobPAnY4+Ro90JNzy3zfBYKfIR2Kfyj+AYGNXcOa9plJsL0ug
         qXxMuoTakNxHNErXfJjUeLrTMACYYBruGyaJGg6z42pBSkG6///2/BMeupPtPuEboUmk
         wFOQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=zkmu=dx=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=zKmU=DX=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:date:message-id:in-reply-to:references
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=Qw6EB1gjuQ3gnqhnb2A3Gxhmy23whrvpbN4Sw3w8qfY=;
        b=H+0UTG3AUHNNZKUXfiaDPs9ggpG+RZYcveBtstkuaJX4qlxVhaUnr0Jv/SVcMpVdIx
         +Terewtq73ZeP3YfStB2+TdO6eeiQ1ycTLEoL4zTAEdV3SMFJlighz/P3xHzT6fgvKBK
         Li12B5NsmkvS0GHO+hNRv0QS/qjRBzXa0/jISu+/69RvXMZ1VVsPmnJJ1DerzSvVFD6i
         bKE58g4tUm5ocpAt31VYrXGzZvgqAc3nwpkaUqMacTsQl34K7wJVqM2Of0PSOsfVAHDn
         uE+YcMflqUbnSSvTdklWOSJqQ9HINOd0UTrIlSeYevfN3uRWdiLqG6Kl6oRxGtiQchIC
         Ll0g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :in-reply-to:references:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=Qw6EB1gjuQ3gnqhnb2A3Gxhmy23whrvpbN4Sw3w8qfY=;
        b=kCrEqXEIY0tRTUUVKtTtuDelbG8zNnfRy4vOaIYzTiRQQQUQ3+WEINblX/KR5Th2iP
         F/26MEUR49X0eoVA0fZdu7VWDlvGzHaZOZqA9Xl/Hk4lt0Ws3dt7DWIHISYTgBD1PFzd
         4msQxswil+fEnH2b1zfdYdi3BfSuXxONo6VYKdHDdPtNwACF9biwwBWf8rpABSoSYxWq
         S6CH8xSgsI5kvexB/xb1RCzZprSmb1uUilmAmnaiZIgpBttKjL2L/08wVefpGDTn9D2K
         dlgBarOW66KcnumzgRDCcPxsCrT7wDq/l6WweZaVQPLUX15Eg86x6UzJRB1azCZ1z5ES
         WYrA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5317frUiPT21pW2OhYqOubs/VVHz9u4Pb8jABZYdedD1dcKVjXGr
	WCwHKypP2c1+91UU1OF2HK8=
X-Google-Smtp-Source: ABdhPJybzl0F7LXJQ6E5i64ViaPDHwvXA/zmVqrLDMAKHR6Sc3yxxQIYPfrvxETl28yzfG02R0TPSw==
X-Received: by 2002:a0c:e78d:: with SMTP id x13mr5728643qvn.20.1602877593290;
        Fri, 16 Oct 2020 12:46:33 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a37:ad0f:: with SMTP id f15ls1709797qkm.8.gmail; Fri, 16 Oct
 2020 12:46:32 -0700 (PDT)
X-Received: by 2002:a05:620a:1221:: with SMTP id v1mr5362663qkj.98.1602877592768;
        Fri, 16 Oct 2020 12:46:32 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1602877592; cv=none;
        d=google.com; s=arc-20160816;
        b=IIhYO1qozDBruTx+OjZ8ry3gbNaCiJEz+wUFWjmGL4cw3PCGd7HMqL7kD/U4TsXUDL
         0iD20QQ3S7tV8Mb0/xg/e+WzQ2UIGMnzQ0lPJ1eeKGL0m7IkxyNssabR5grc//nUYKKd
         HMZXpQIBMEsBsT7KJ7uGzwHtghTajWhHzkkjLBHvyAAhuZQmc1kyzhZXa0Gy9ZRVoxZg
         mqsbxYLp7t2LjWOrB4V3vDky9Ua8ou4wzvXrflsIhAXi5+EZeurdSj7oD8g0Wn03kvfZ
         DB51CgOn/r4KChdDtiNiYe+ZtjvI28s7RqV08oD9Y/0ov98Nbovi/UW+obHyuMxs3l+C
         ERJw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from;
        bh=niRqIcuhHIziBEVQSQESev7YnHHYofdqcW3/Y8xnYVI=;
        b=DN/R1mgCyAXn0PpuKpeeLKHsK5XVErVeSr0xMYx/GMbXCb8Kgqj+uAZwsIXY/RCwj4
         /Y7Wjjp36iSxPBbr0oscxLR7T1XMVHAjL3jlonG4k0u7490dBFZbq08lIoXG9bb+xh3I
         LBf2VHiDgScEywMm4b9UwKYzZCtDZozSxnNkT6Zu7A8wmBhzzP+PBe588a+9astQXk/v
         ED4IL1KxfR8LOX8m6d3EePewlUzuwkFn7ZN3BaULuE0JEfSi4tPOpld6LitBSTgnaN1F
         L2DDCj63ba9jvJ/OX4MLG03yzcJ9dvcN313iB28tykBKTqXiVXfGpXIsSadXOXvYNDxQ
         rqWQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=zkmu=dx=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=zKmU=DX=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id j14si143359qko.4.2020.10.16.12.46.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 16 Oct 2020 12:46:32 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=zkmu=dx=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 199359] KASAN: double-free is not detected on kzfree
Date: Fri, 16 Oct 2020 19:46:31 +0000
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
X-Bugzilla-Assigned-To: dvyukov@google.com
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: cc
Message-ID: <bug-199359-199747-F6edj8ntBd@https.bugzilla.kernel.org/>
In-Reply-To: <bug-199359-199747@https.bugzilla.kernel.org/>
References: <bug-199359-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@bugzilla.kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of srs0=zkmu=dx=bugzilla.kernel.org=bugzilla-daemon@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=zKmU=DX=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
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

https://bugzilla.kernel.org/show_bug.cgi?id=199359

Andrey Konovalov (andreyknvl@gmail.com) changed:

           What    |Removed                     |Added
----------------------------------------------------------------------------
                 CC|                            |andreyknvl@gmail.com

--- Comment #1 from Andrey Konovalov (andreyknvl@gmail.com) ---
This is fixed by the "mm/kasan: Add object validation in ksize()" series,
right?

-- 
You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-199359-199747-F6edj8ntBd%40https.bugzilla.kernel.org/.
