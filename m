Return-Path: <kasan-dev+bncBC24VNFHTMIBBGVBRT4QKGQEXKIHEDI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x637.google.com (mail-pl1-x637.google.com [IPv6:2607:f8b0:4864:20::637])
	by mail.lfdr.de (Postfix) with ESMTPS id 97D75233857
	for <lists+kasan-dev@lfdr.de>; Thu, 30 Jul 2020 20:25:32 +0200 (CEST)
Received: by mail-pl1-x637.google.com with SMTP id k4sf18448917pll.6
        for <lists+kasan-dev@lfdr.de>; Thu, 30 Jul 2020 11:25:32 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1596133531; cv=pass;
        d=google.com; s=arc-20160816;
        b=FfrSCcxUVW76BeNMGPUyZGKw9uyEe/K1STUzvve29x1jxTwxljdq8Tt+ZjHT+RYQKO
         cU4ypnxVctChw0GVA5t6dmm/ad+Dl1wtIHw9rWtUo7Tkwmh1h0QXmfM50AfaU9RMw8Il
         0USqb5zU6Cybd4cmqvtyTr5qMkRquBxhtf+d4b7Pq+CKYK8D4fVP7NBHutFvqw/f/JWJ
         6GBW+6r/gWDIu4+93QV8Vm+RB4dFzevI6O81/Kw97a0x+QzLX2DyyMKM2Uv7jkPPRulj
         4g5yNWSSo5x9a6n+HTtlNwvo6KAnWyBupB2ZkMP9GYa+96LHJzY2fPWUzq+taKS1gvFK
         /NgQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=aFq4oVSuh86/l3whLskDgMJkJis0pXUsSR/BTTC5K+g=;
        b=Xn66ddHhY1sZJFVllpOfe04nEtEpFQjmuIc8i2XMAoVn9mOfzsBhZ2q1W3Yg05xi6Q
         vG80yLQ4cuPtAyEjPMlhZKhjW88EPxRNryrkKT5LPy4Yh0s1+tXBug6KhQU+0ESEvtPd
         9UyLLu5vR0b9dwVlFgsLDXIVFavBDc98xjQcZIncRBKG0Qmthk0qlHbRb71EWmQJjeqs
         WPpP8IxeKV9P5H/zKe7Om9ykFDm+/NmQKRqY6vo5+4Tj2TVbBLXXaZpvLezckGxv625C
         DZ0n2Tj/D7T18xu1guTvfjem8zMCOZWE0hO9La7kgloT0+oukiSd2fEmRnnpdANP000/
         +/Zw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=giuf=bj=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=gIuF=BJ=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:date:message-id:in-reply-to:references
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=aFq4oVSuh86/l3whLskDgMJkJis0pXUsSR/BTTC5K+g=;
        b=eFU55pxTLMmZDpaKg1hz70n2N8XCur4MxklSlA9xguKUAHRZF2Q9RXBv3FEInThp75
         ojSQrfCUv6b30AFE8mM7LhCzrMKtUAf2x7mQY26Q+AOBkJxTUB8MsGMQ+5oLXjo5Do9y
         P1VVhbnBbV5S9LAjddbO99EOpqdcGHeA/qo4bn5WuMEqhrEm650t+2AN0NvUxFasNVYE
         taMG5JY2XtDTtc4jWma8LHwur/7ecFIP3G7/Ta2XPGm6eFqBdN5BJ0VGwgqFGTlYF5co
         PiGKLwWizILAGeKpSlkP0zpp2dsXc9nwM9DdhkUo6swRFepQaU6aaovNYFi3BUpzfrct
         N23A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :in-reply-to:references:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=aFq4oVSuh86/l3whLskDgMJkJis0pXUsSR/BTTC5K+g=;
        b=iO+GV4RvQA/9m5WBW33prU01vxnBw35GCbZf51kSABJwQ+otC1vuObbAuZoplVqLGj
         bP1kGnyHoo4XpA+zCZ6bVyMhAN7uK2v+inzD+2ZSsck2cfHjdi0kQmUiUXgRCgibGIyX
         R2LJIl89Uvqem4yDk7kgCimB0zuCP/vDdERhQT9drmrSTYN+HHniKmY5cT1IypOfyldB
         34dr5y/HFCrV74R3aUH4a8mwOEzI3aMsT3f76SmHRqPZogKv8AuKkgi4j5DLu06xNVqt
         +fmt66d75BT3qS6MBUGL5pSqS22a+I3SD6jtZajZLMDpztZ3ltwQb0HvOQMRez0LKH1x
         BUpg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532DNj4JwMxz98sli6sqQqtBs9DL7zTcqCFOB0YNj8zzkin5vzq3
	NprU6YoxKaVHF3EX+Eqhklc=
X-Google-Smtp-Source: ABdhPJyIbDGEuMn+ZUa+MzAhAiuuzumWDkcI/x2IWKgAlu7iCgxBOp5+/5jbpQRCTr4d551WZBXzMw==
X-Received: by 2002:aa7:8d02:: with SMTP id j2mr293448pfe.90.1596133530958;
        Thu, 30 Jul 2020 11:25:30 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:4ec4:: with SMTP id c187ls2165804pfb.7.gmail; Thu, 30
 Jul 2020 11:25:30 -0700 (PDT)
X-Received: by 2002:a62:2546:: with SMTP id l67mr294338pfl.154.1596133530544;
        Thu, 30 Jul 2020 11:25:30 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1596133530; cv=none;
        d=google.com; s=arc-20160816;
        b=xi9Z2cyRGk5YFvVseFfLk4EiD+3hFhkJQPZ2fW7FaxN0bDfwutDQ1IhYOHAyym9WpZ
         ygjnECd7E+PjGsgBoqnVYS1VKFIA6N1RtI8SwgYHDH9rYpd5zPN2hgGOE3DkEoOHk0U4
         D3gBB+CJl21o+E9uGsHBZzkGO33E8gJUmUt1JNc4nx+1MxLCjnYumYJbu6tG77UnAO2W
         LeV0MA1yc8yDWlCeH+kKr+A+AubsD0kD3HRYRGwIS6swbz66qp24MQS4JDORHIQHcsSl
         Bf2oPuNid3LKJBBogGxueg2uQDGJyEibgO0x/EB3FpnpoGaTa4dYCdIcDxNaB2yTuVBp
         tl1g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from;
        bh=/Y2VWHEp/j1RLxNRkWoK9DfDlxGtSaTuxGXpWVlnaMk=;
        b=bqQGe/NjbnwnlKP5FAtCbbBOGoJd4pEI74VeN26WN6jDKj3EcEmFv+p+i9A/kWzALv
         7/hadF6SDEMltKBUeSCdKV5VOmJSe7RQeaJKYm8W00tKS6uOpfAYa6e8rHjuWAwnxvho
         tHAhLf61l7n9p/dz1AsdujqEH6CtLBnb4tw5I3HxoDln1V9BdQH00mHx7/y+/UqkXFR/
         Wxq+MT8vZSRBy1wJ4DVstrTT4AuQGG64/SNGpCFZ8A95CKgX09oorPqKUez0BcjczFg6
         DZ+ftk33zIVVJLvpQ0wt1IhOgXmkbFnKB63hkoGk0w0ahMdlQs/6x5jM768cjImbJVX/
         2hbw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=giuf=bj=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=gIuF=BJ=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id w2si263628plq.3.2020.07.30.11.25.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 30 Jul 2020 11:25:30 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=giuf=bj=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 203497] KASAN (sw-tags): support stack instrumentation
Date: Thu, 30 Jul 2020 18:25:29 +0000
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
Message-ID: <bug-203497-199747-yRMEhuqAyz@https.bugzilla.kernel.org/>
In-Reply-To: <bug-203497-199747@https.bugzilla.kernel.org/>
References: <bug-203497-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@bugzilla.kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of srs0=giuf=bj=bugzilla.kernel.org=bugzilla-daemon@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=gIuF=BJ=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
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

https://bugzilla.kernel.org/show_bug.cgi?id=203497

--- Comment #21 from Andrey Konovalov (andreyknvl@gmail.com) ---
Hi Walter,

I've updated the series with fixes here:
https://github.com/xairy/linux/commits/up-kasan-stack-tags

Could you try them and see if they fix the false positive with inline
instrumentation for you?

Thanks!

-- 
You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-203497-199747-yRMEhuqAyz%40https.bugzilla.kernel.org/.
