Return-Path: <kasan-dev+bncBC24VNFHTMIBB5M4Y3VAKGQEE7ULGEQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73d.google.com (mail-qk1-x73d.google.com [IPv6:2607:f8b0:4864:20::73d])
	by mail.lfdr.de (Postfix) with ESMTPS id 743A48A2E5
	for <lists+kasan-dev@lfdr.de>; Mon, 12 Aug 2019 18:06:14 +0200 (CEST)
Received: by mail-qk1-x73d.google.com with SMTP id s23sf9619331qkg.1
        for <lists+kasan-dev@lfdr.de>; Mon, 12 Aug 2019 09:06:14 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1565625973; cv=pass;
        d=google.com; s=arc-20160816;
        b=ua6Y1Meqyv8z3JS3HAwBHmjhlqa1UmzbiQ5U8o8Dxpvx/NTxuEanPrMf4zO4LJpobw
         fwkAZ1iN39Zf1/Oku962Oa2/kqn9MIyJB69/Bv5mmn/WyPtsIkh6s8ihhags0CJ6MRaM
         7YbafvYrUa3L+e8YflfLb+1P8wr5kg7OSHuFWG2tKxBBObpmhMFifkCPJBHo+K9zJBnu
         YUZ2QM7tkQltVQxQAJmCAK8MbkWYZnCLJwCMYeYQPu50N5RLGy3BAZYflbw4eyBfatX+
         0l5Mea9ziM/qxKxHM84PfYptPSL4k/j5nG0Jcwio+inQmx/m48obE+vAnwmpLFybLgmN
         JWFw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=EyFwsqRC6DhPrJh/6gRnpUEuxxl1h0GPMEBRhN8NId0=;
        b=IByOgNBaKKK38N1tBbvRB0uXzdz/0RRI0+xSkh2wrKPouA6QydgogaziDMJ56NKoa5
         9r7WA96ciN+/KWMOe9bI0gzE1LTo80kNXhhu/gtwjntA8Qlx38qgTeJNNX+3Bxzm63eO
         aQxF+dVnLQtq9vvJseJTGSK6/96CnlyDdGlw3zc3+9sAK4kGUHF72EiLSzJHVyzdV9A9
         z1Bmqg6SrAYzWKpubM+uuOOXzZScASt2CUZHTuVFY6hAZK1JMQkCzh8kkNUb8BuiPBu1
         weHTPKJt1rAhJcOCB4JRcFB+Ds4EH0PmDCX4vR9t/LqODutoQYI0EMVo6vrBYqyaAeJ7
         9zlQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.98 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:date:message-id:in-reply-to:references
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=EyFwsqRC6DhPrJh/6gRnpUEuxxl1h0GPMEBRhN8NId0=;
        b=WPi79RUIaVInBwLzSJVEzItWMSYVgmALYsHqfGEyZmyiGQ+JMOMd0XeH8Vz8mwkMW4
         NYycbZf8jyimtpe1iLiAOBoPeKTUvfuPX1azgUGtqQYwLCevVqhKknFRrvCqkzXOfGrp
         idshVWcOxv1tZEVl4jR4bFqTpEJU8cclBprNfUvXL0qAGGJnN7Gt7f/nA4BE+GOKTYzI
         7n6edFSvQ9rODQpea38A9RTAVbI+p7dTeyREaHONpX3zNxVQXWNtXeIEpSNhe7K6cRp0
         3EAZdpjb336rIlpz7zZnj1SDtF88xyv58X84O1UrDvkvjJsH/3M57lL8NxAUQQYDb/xw
         1KiQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :in-reply-to:references:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=EyFwsqRC6DhPrJh/6gRnpUEuxxl1h0GPMEBRhN8NId0=;
        b=TBp24bVnY73rU8BS3rGBVZqHwwzZrHOUziteOQEljLubB8oPemvir6u0yzo7hEnsP4
         kbm6jdv+pjZI1Fz2D53PDWR8og/7gs8enmZXkYCvJNbshLv759zSojFNRZkW3kMU5Ycx
         MAgUTEjpE2TrPvPpj61hf3Lf4pTjVhW2OzvwiK6ZBIlr5D95mIu3RXawDRMGLurlkulJ
         280Gr5eJNNuMQm39i8RxIXhOTeyWAjkvTR9OYNWXJ6+7hErWuKEL3XxXNjE5/p9my7s1
         49xJs0Al1yfgBkcQ56h4BrV1NEJj2QYvytlY+28edyRRNJ9LiKSpnPSzR1Glvb3FBtTr
         mCIQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAUYm9iC1G9z3Yk9hA2lH6Ph5NR/Mt57h+F8v0K1Y3TcDjJSEvtU
	MC3E0IxjRRCFvRUqAf5ieFQ=
X-Google-Smtp-Source: APXvYqxUa18bOelzKShLuS3ZxH9em9J1xIFCxdiXClEhas5bcFIRxGclCwuR1rJ+tRaUk2jcW5k3aw==
X-Received: by 2002:ac8:42c4:: with SMTP id g4mr14965926qtm.228.1565625973321;
        Mon, 12 Aug 2019 09:06:13 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0c:d081:: with SMTP id z1ls142511qvg.7.gmail; Mon, 12 Aug
 2019 09:06:13 -0700 (PDT)
X-Received: by 2002:a05:6214:110c:: with SMTP id e12mr27703675qvs.126.1565625973075;
        Mon, 12 Aug 2019 09:06:13 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1565625973; cv=none;
        d=google.com; s=arc-20160816;
        b=ULMPQeWTi0NlitdpFcpPnSALX9maAAKKFjnVEM1usxNThtBQggql+krwnVYcHpSzXB
         pxPuzaOSARhrhXFIdw4Zd11eeX4UiWioMICeGGavuQZLtaReYov1frYEVTu36KuQUCc8
         nQ9Hbt+NzP9qJTcWN/Pa4fQ8ZU7ZH9SX2QbrdJs07DjCBQvsK9mnuvPD+/FA8L6TNfmj
         Ce8cFMp8a6M4ybPTZ8vU3r9N3iA7VsDUXohMZEZe8SMfvH0+Yt+gzYzfNBxGzxvofYIu
         m/NCYlg8YfXVN/t9Mm5t8tZeeUu3ZpiHSNcpG3Ka6oGQharGrndSGl3d672yfQtGqnSi
         ztqQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from;
        bh=/EMc2cfupXLhdoQws8pCwJP8dMkhipDbilyjvAXJl8c=;
        b=XHivKtrTMNXrSmSi0qyuCoWudVYeap3beOZbIP6OulU5Lpb7YgIgEkoPdlJnuplwIu
         +wvz1BDoFSSofgFJa9VBlf/8ADRZEQ70BZgSyYdTPIR1kGxIPSz4MVbL91T/2JlPQ8sc
         FQ4Uycskh3MVpdYGXZfs5cv7aslOnvMkWc/yQvFBop4/yajK4xrxQXTRQAPoOzEKWqqF
         SaY/+PLzkMrSIcey/KkvkbTw5mgBL4nq33se31r5S7gy6MxiVT6hekF6srwrj9t2Ul0U
         Iph1MKPmxW0ohpKIsDGD3gwTcJLzE8cfePpMA7lZv4kkXrPlKZtYIz/kXbPN2vWcWiFp
         SS3g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.98 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.wl.linuxfoundation.org (mail.wl.linuxfoundation.org. [198.145.29.98])
        by gmr-mx.google.com with ESMTPS id g2si239996qkl.0.2019.08.12.09.06.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 12 Aug 2019 09:06:13 -0700 (PDT)
Received-SPF: pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.98 as permitted sender) client-ip=198.145.29.98;
Received: from mail.wl.linuxfoundation.org (localhost [127.0.0.1])
	by mail.wl.linuxfoundation.org (Postfix) with ESMTP id F25EE2850F
	for <kasan-dev@googlegroups.com>; Mon, 12 Aug 2019 16:06:11 +0000 (UTC)
Received: by mail.wl.linuxfoundation.org (Postfix, from userid 486)
	id DEFAF28514; Mon, 12 Aug 2019 16:06:11 +0000 (UTC)
X-Spam-Checker-Version: SpamAssassin 3.3.1 (2010-03-16) on
	pdx-wl-mail.web.codeaurora.org
X-Spam-Level: 
X-Spam-Status: No, score=-1.9 required=2.0 tests=BAYES_00,NO_RECEIVED,
	NO_RELAYS autolearn=unavailable version=3.3.1
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 204479] KASAN hit at modprobe zram
Date: Mon, 12 Aug 2019 16:06:11 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: changed
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Drivers
X-Bugzilla-Component: Flash/Memory Technology Devices
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: normal
X-Bugzilla-Who: christophe.leroy@c-s.fr
X-Bugzilla-Status: NEW
X-Bugzilla-Resolution: 
X-Bugzilla-Priority: P1
X-Bugzilla-Assigned-To: dwmw2@infradead.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: 
Message-ID: <bug-204479-199747-47Ii0mNnci@https.bugzilla.kernel.org/>
In-Reply-To: <bug-204479-199747@https.bugzilla.kernel.org/>
References: <bug-204479-199747@https.bugzilla.kernel.org/>
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

https://bugzilla.kernel.org/show_bug.cgi?id=204479

--- Comment #18 from Christophe Leroy (christophe.leroy@c-s.fr) ---
The Oops occurs at 0x3c8:

 3b0:   81 21 00 88     lwz     r9,136(r1)
 3b4:   13 67 dc c4     vxor    v27,v7,v27
 3b8:   7d 11 a8 ce     lvx     v8,r17,r21
 3bc:   11 5f 5b 06     vcmpgtsb v10,v31,v11
 3c0:   11 6b 58 00     vaddubm v11,v11,v11
 3c4:   81 41 00 8c     lwz     r10,140(r1)
>3c8:   7c 00 48 ce     lvx     v0,0,r9

This is because the value in r9 is most likely wrong.

r9 is loaded from the stack at 0x3b0

r9 was calculated and stored in the stack by the below code.

  70:   3d 20 00 00     lis     r9,0
                        72: R_PPC_ADDR16_HA     .rodata.cst16
  74:   3b b3 00 10     addi    r29,r19,16
  78:   39 29 00 00     addi    r9,r9,0
                        7a: R_PPC_ADDR16_LO     .rodata.cst16
  7c:   91 21 00 88     stw     r9,136(r1)

The value comes from .rodata.cst16

Two possibilities, either the value in .rodata.cst16 is wrong or the stack gets
corrupted.

Maybe you could try disabling KASAN in lib/raid6/Makefile for altivec8.o ? Or
maybe for the entire lib/raid6/ directory, just to see what happens ?

-- 
You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-204479-199747-47Ii0mNnci%40https.bugzilla.kernel.org/.
