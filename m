Return-Path: <kasan-dev+bncBC24VNFHTMIBBNMOYHYQKGQE4GW5O7I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa3d.google.com (mail-vk1-xa3d.google.com [IPv6:2607:f8b0:4864:20::a3d])
	by mail.lfdr.de (Postfix) with ESMTPS id A272014BA12
	for <lists+kasan-dev@lfdr.de>; Tue, 28 Jan 2020 15:37:42 +0100 (CET)
Received: by mail-vk1-xa3d.google.com with SMTP id m72sf5799461vka.20
        for <lists+kasan-dev@lfdr.de>; Tue, 28 Jan 2020 06:37:42 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1580222261; cv=pass;
        d=google.com; s=arc-20160816;
        b=tUQvakojpLtaeFeWPil/RdqqspvvUoyBQW1c/OPaNBAFfbKtdts3+xA2TooGz/d1GH
         3tEQ/u7tPhF2rmrXEAYO68/ny3qihcRV76NnirDocRBm5VyWbmTDViCQ0BCAIBPng1uH
         OkAXKuKh+y4n00dWtFFVXY47GhhK7zewmfr/xnB0T05kq2u7dBkn7O7tqzs7G3QnS6OD
         /hitmbEME9yFNwPw86FpXPGkIwx8fWjRvXKgpiK9A03vYMjLerjiAfyt9+VuhusIgXXR
         7n80ayWLnCdoo2stMVo0aQitq7Kbm2TNoh5tFXjyxgk63k2XJ61GieF9msPpnkgUjqP9
         fNyg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=UIp0kYQ6ZVJ775yy20kGN/DCz6+TwXOpw69BWkPIlVs=;
        b=lcYN4hFtkbpLntPJRCbbhFnCaRbUt/FI9Hw3fnH7uLC9GKNaXRLeY5+xz5heqtwxoj
         5ZTP3diiCeT1YYEXTBjvFQGC3NOLyyn7Ge3VkXeZrxK5rUhCVKTbwx6tJ+Qw0Ygy5A5b
         Nqmqo9tbIf64NSrl7HnhcReZ+MnyEzL2W/Zb+jdf0oCTFzqPt7bCEwMgFNBEfNAEwjFY
         MnKh7d1sIALxkRzme2QnBlKZzIjdt+ApDWa/xI9xzX67agMEKU65QFjtPtdn3TjPb+I/
         dc6oGJr0RQdsUFsupu/CP4rFIZk98RO5dY2PyULVTyo5U9O3BN/O4WdXIJrPhmlo1A1Q
         +xuw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=vppz=3r=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=VPpz=3R=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:date:message-id:in-reply-to:references
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=UIp0kYQ6ZVJ775yy20kGN/DCz6+TwXOpw69BWkPIlVs=;
        b=VQjQmCnO0laK9ogJph87TuUkGPKXO3F66wOF3sUbquWVrtKTPIr312NZ1IEUajrs5P
         fGtiFJNKHp/liXCT2s14TUfoTZnze9wrUqSvVCSguZ0+uNtoFCGk56d13w3FtQnw7j/Z
         ALjNlWt/stQ9eBtTKEIwIwTAz5IJ7rW1OunXiBUjrHGHfSDEDgcXy3riVmb7hEMxlfaD
         6fQ5K0JPhVm+HCIu0IB/K67osoC65e7ZqYriCY3qjSOL0RsD2t717j53AFc9vX6/rT3s
         9RV/Hpq70DWveJp9I+Xx4/c4/5k8g4vK2ffEHrCBj0TGW7M3+PsyxxYRV3VXHapmsBaF
         XmgA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :in-reply-to:references:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=UIp0kYQ6ZVJ775yy20kGN/DCz6+TwXOpw69BWkPIlVs=;
        b=clJmNmTt1LC/llYpqKc/m2hJmUEmMfKY435nor150XXIjHmQRZAEvD/BvAmNKYSQBP
         gyBJpKyeIFBIqxDbLTHh2xyurJlZYGdhH5t6tygeuI48rp+OL5kzu6N2vFsHeHL344ow
         P3djEkappM/rxmyV8DROWtI0QCmTsF7hG8Nk6zZTBjFtIf4iAUluS8w72uNf6CuX+VJs
         1G9DeHKbpn4V9s8pyBeyTwMZHE71HXTrs+PbCBx9TgdZqp7CSlemsj+TU7fO6PmzpCap
         tzF21wit/X+nnS2LmRxnpynYLIiCcDBBoTAmGWpLDS1e/miQImlIMwCLtYuFQYsfdLCP
         ejFw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAXwyaBPrFdyJkLLZgunerKzslvTR/phUaxIqXgf6iKLIv43Q1bm
	lO2hbtIBpph77UWPQNaoE/k=
X-Google-Smtp-Source: APXvYqzL09DV8dUnsB29DB3DtJCxmyjnVZSU5Nne9Oht9D5yavO9ONJYPoYt2491TjMp7P3x3wNAlA==
X-Received: by 2002:ab0:1051:: with SMTP id g17mr13876998uab.52.1580222261393;
        Tue, 28 Jan 2020 06:37:41 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1f:4196:: with SMTP id o144ls668938vka.0.gmail; Tue, 28 Jan
 2020 06:37:41 -0800 (PST)
X-Received: by 2002:a1f:bf86:: with SMTP id p128mr13713254vkf.3.1580222261028;
        Tue, 28 Jan 2020 06:37:41 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1580222261; cv=none;
        d=google.com; s=arc-20160816;
        b=N/KuedrM0a7lDHvjkS9SlomwknWQ7DDeQb1+JYTSqU6/wxRhigErznSe1ZYavflDXA
         E1jpdOZDJJvvBbOUnx+TV/VGxvtDnpLkquEaMmazlu0ns7f9cmBCqzz+OmO606HcyWIK
         qJHRHZ4/8LBtwbh45e9FGb1mGLH5GzmuXQE2x0UNIUyXPgSPE49Ok5uThawpiPC07QSi
         iMtAQGisoXI5kTn3EVhANJzN7hPSE7JD7pXLXP459oLVQt5YxIJXIT6X2pGc7xpgRTJw
         06yFtxelhT1tNMQ1O87cGSERXb8ZsoPrbAp39jmAHBJTMBwPs4k7mUNDxyqe0zP4LelO
         ZXzg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from;
        bh=CyId4ejzIW4paS1/HZ8aUH882bXr/fVrl2v5thq/C94=;
        b=thG0HGcKRjeGqboYzYHbEgfbTTxu1gDNlrLalT778+FYDUpiG7tgER5e3t6/xwMeY5
         814eDhFloECBdNqzpmHxcpzlSOgvxQlkBBNlRLxw8+T94Be0dCgSj2znJmBroO8uvIPM
         u7y4xdd1G/fEH+dRXkuwbvoM1WlbnVFVKjWkSZ1tNqLobIkNQQV9a1GAQ9CdhhLkD8Ka
         UEDSi9Nn2mMvwry2j3R9R866CS84NLivwWM0b8MHEwGt4YYotEjTmJ27AheZh/aNkIUK
         TKnTrpYUWjXjISXcy0o2jt0M2sRhUmMO5Csxngauz29iymo3XFDfKetcgvXlqTZA7Hz9
         AThg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=vppz=3r=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=VPpz=3R=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id o19si973314vka.4.2020.01.28.06.37.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 28 Jan 2020 06:37:40 -0800 (PST)
Received-SPF: pass (google.com: domain of srs0=vppz=3r=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 206337] KASAN: str* functions are not instrumented with
 CONFIG_AMD_MEM_ENCRYPT
Date: Tue, 28 Jan 2020 14:37:39 +0000
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
Message-ID: <bug-206337-199747-xcEVoN2FGf@https.bugzilla.kernel.org/>
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

--- Comment #3 from Borislav Petkov (bp@alien8.de) ---
We could revert back to the first version of this:

https://marc.info/?l=linux-kernel&m=155440967805174&w=2

which excluded arch/x86/lib/cmdline.c only from instrumentation.

-- 
You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-206337-199747-xcEVoN2FGf%40https.bugzilla.kernel.org/.
