Return-Path: <kasan-dev+bncBC24VNFHTMIBBK4SYHYQKGQEC77N3DY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x238.google.com (mail-oi1-x238.google.com [IPv6:2607:f8b0:4864:20::238])
	by mail.lfdr.de (Postfix) with ESMTPS id A572A14BB46
	for <lists+kasan-dev@lfdr.de>; Tue, 28 Jan 2020 15:46:04 +0100 (CET)
Received: by mail-oi1-x238.google.com with SMTP id k3sf3396786oig.17
        for <lists+kasan-dev@lfdr.de>; Tue, 28 Jan 2020 06:46:04 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1580222763; cv=pass;
        d=google.com; s=arc-20160816;
        b=IquX39EJsCrpqugvT+X30z6ufKwIzgiMnWrUNu7P5Hj7EkG3+Rd4v4r7HaRdtP6Yce
         QifpeekV8nVhgoRa2PcYO1oyjKOn2t50fXa3IAuBLu6guO9sE58HboRfBingHBwYW75R
         g4xzg8hiCFPfKv6OPKK6J6OyFzQUHrrfXF5HEro00Iep0vvKazRWZ3XqcUtAQNPYXWt9
         wkqxbsoEXOW4gWv/GI4JbO6Tdumz9LR1Jwl/vbZIR1u9W1MnvYth58zraeWX23O41KyS
         f+IuaPFQ5CmDWsJ094O7q4G/bK2+8JI9iaSJjtgVSGyXc4lhVm8D2/Mnkasbp2GL9CnR
         Sx4w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=qz2fNW4VY7rU3uu09JJSpkm+iTOTDfpioAMVXQuDLuc=;
        b=R5r1hnmjt7atQG8w5D/HuqBhQKOQYAQgVGM76GQhmAg+1sOPcT/B1RZSIH2wjgCCKa
         dXTtQ+t/GTbTyheZ8fpq81WFASi+VKLsT/t1GAmFjOj5uBaHj3Biv85JzjpNgGniQz2L
         xddkVRRd6bs5wAe7I4ijV/sVFD8lP83tdK8fASQ0HBMHT9EITv7tUFYndu2c5WEhiUJc
         ymfCHNkTOoA7m3cN4qofAkJmTMuDW9c+kTGnbkssuGh0J8niE9zboom5W4c+GMiP1b81
         7p/JS0Tth22SSTnBvy2EHFJDVGZM5FM78umb3lKQFakFyzVxRZXQX5xG4aw5VFeDElJl
         9OeA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=vppz=3r=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=VPpz=3R=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:date:message-id:in-reply-to:references
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=qz2fNW4VY7rU3uu09JJSpkm+iTOTDfpioAMVXQuDLuc=;
        b=JRPgjaOlPWW4Wgb6qgucdA6kcx7QXTr/Mhr3zOC0nkJKtJ8WBao2nWvpQRQgFFg90V
         QwlO4t/SgFwNKYxSpQNhrE2V0zqizeGCiKSBbuWh8aBXbfvolnEwbhMZVjp8a555++g0
         KdxzGsPsvHpNnqLYrDPxOpLyWfIBUV39NXGQzTw532y4I2RkpVON0dixlkoQy/ziuQ3g
         5OhOGG+oeHUkVVgkWAeQX9E0pqXs7kxgNT0/s26kjDRyBk3BelAWoOE8LsJ4dhWRq4BV
         GadHdkAH62ujpSr4TvpnHWdW9oSFfOuEzDlxCuKpITe3Z3kt7CQiTx/ngm91qN46gtQ+
         hpbA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :in-reply-to:references:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=qz2fNW4VY7rU3uu09JJSpkm+iTOTDfpioAMVXQuDLuc=;
        b=A4iK/HKwq0nPvN9P1r0EIhUpZmX/ZypWSSa9iWiS9kOZJsQOXzCAnLvASHb9h7kA0M
         0F95A/AhFVhUYQvPYeMMKnBvSuNQCRbuRNpCJrK3DRv+qpUCb5XPOurO2XZkDY5STrVX
         mcL8z0cyi8sdYjiZbbLks6UAZp+achwCCRwGCbSw+DCja6MyEgGzyg3udjqwcAUiXxG8
         nelNvf2xEiPXZ0pd++RC+/XYYpplcenhP9AUZboGVMB+QF01x3A9kNCETuCVXiAQpjS/
         T2+AJavq/jyDPlaoavePlgPHJclMWYYDQxWkVcWg5Zoit0ODcZiAAr5zpndjy3jOVljO
         OgFQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAXv1oHpAeG3oOca0cNhVf1fFO80unDGY1beGgWUtLODYmBsFaUs
	v+2kSLp6+K/jtfeFL6ZTgSQ=
X-Google-Smtp-Source: APXvYqwHyaly8Gte8vr+4HndhpdG464FmXLrcUFZIDv8/9N1fMk/l312uAqpvvjUY9bbF6E06jv0iQ==
X-Received: by 2002:a54:468b:: with SMTP id k11mr2907858oic.134.1580222763649;
        Tue, 28 Jan 2020 06:46:03 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:534e:: with SMTP id h75ls2236971oib.9.gmail; Tue, 28 Jan
 2020 06:46:03 -0800 (PST)
X-Received: by 2002:a54:4418:: with SMTP id k24mr3146680oiw.46.1580222763277;
        Tue, 28 Jan 2020 06:46:03 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1580222763; cv=none;
        d=google.com; s=arc-20160816;
        b=TOneV84HHhkH8SwPCMGHdFiB10p+Xvn1KaTZZ8ijGrEUp6JmMWc1Q1TmP3tWj2i0mo
         4BO7S6PZzwZAdCak7CPUBDDLRPyltgQXxg4UStMomyweyqlmbAc2pHfD2sDHP2sL3EAT
         Tyr9gdkmdqC4NJ1hFdOsCtbY/9upjslc/DQfkBBaz47c45VF+mkAifqLpaQ6u8kLXGJ8
         HKpjYNn7m/tNpfxq4QOSPJ9rj6q0I0bF6bVxr7eIN/LS2njvk1a8YeMOPls7nnEAWKtw
         sm4SgzgkU4YBf+T/XL0ErJiRlJlVj0wKc1vLnSNp5QUpHo6kYcqOPFoyK2r8I10lthvp
         XTZQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from;
        bh=+HHr8j7AVSkg4Mqh8/PDPwW11TLXAJoYW02/i6USLD8=;
        b=IyztGuYirrjjo1Bqa2jS2AzJhvEoubpIFpTXGeN24XIBHWZC9QT1Ivn2O4AhanCa8B
         JN6GACm6641rjXnEf6XdSYVCnmcz3Dj0NHe7IaUoYpICV0W1/jBZDFcCS6Ieiw7TJYvI
         /++io0ATNdO4erjXxTaXGMgpkjMKO+G9T0irm9xFvh32HCZFnduCgkzqL5F6Z8t/Y34C
         NY1qxGPfjMCH+TGYheYMWexuqN7r4ALpOAclTyHZ9giWtMKY2OEwQSm2pgfPpt7BcOMF
         Iu0hiV7EsC8jUk7Apc70okInKPALgfDUVg2eHtDuRpL3aE2fMLKKn7OAETPp29zEAUDs
         JdmA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=vppz=3r=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=VPpz=3R=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id a17si531103otr.1.2020.01.28.06.46.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 28 Jan 2020 06:46:03 -0800 (PST)
Received-SPF: pass (google.com: domain of srs0=vppz=3r=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 206337] KASAN: str* functions are not instrumented with
 CONFIG_AMD_MEM_ENCRYPT
Date: Tue, 28 Jan 2020 14:46:02 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: changed
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Memory Management
X-Bugzilla-Component: Sanitizers
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: normal
X-Bugzilla-Who: bp@alien8.de
X-Bugzilla-Status: NEW
X-Bugzilla-Resolution: 
X-Bugzilla-Priority: P1
X-Bugzilla-Assigned-To: mm_sanitizers@kernel-bugs.kernel.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: 
Message-ID: <bug-206337-199747-CW1mOX8w8H@https.bugzilla.kernel.org/>
In-Reply-To: <bug-206337-199747@https.bugzilla.kernel.org/>
References: <bug-206337-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@bugzilla.kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of srs0=vppz=3r=bugzilla.kernel.org=bugzilla-daemon@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=VPpz=3R=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
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

https://bugzilla.kernel.org/show_bug.cgi?id=206337

--- Comment #5 from Borislav Petkov (bp@alien8.de) ---
The only data I see controlled from the outside is boot_command_line and that
by whoever is able to change it. But if one can change boot_command_line, the
setup has much bigger problems AFAICT.

-- 
You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-206337-199747-CW1mOX8w8H%40https.bugzilla.kernel.org/.
