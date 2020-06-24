Return-Path: <kasan-dev+bncBC24VNFHTMIBBXNIZ33QKGQEG763DJI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63b.google.com (mail-pl1-x63b.google.com [IPv6:2607:f8b0:4864:20::63b])
	by mail.lfdr.de (Postfix) with ESMTPS id 7E056207B0D
	for <lists+kasan-dev@lfdr.de>; Wed, 24 Jun 2020 19:58:54 +0200 (CEST)
Received: by mail-pl1-x63b.google.com with SMTP id g14sf2015678plj.15
        for <lists+kasan-dev@lfdr.de>; Wed, 24 Jun 2020 10:58:54 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1593021533; cv=pass;
        d=google.com; s=arc-20160816;
        b=kvWNATo3vWoQ+3FZpfoPiT7q2htBZ4X6RQ2LhJcZJ0W65Jo/4rA0LYaiDsOTAkvq45
         9jQyKfUglIMFHWbg9izhJDFedP6v8o36nMlPTmio0UPlxoGD3clkdAUBZsLqSzn3IIrU
         AGPX29INipmRp7vsTpmSwJjzjCh2iQD9MKuAF+VT+9q+t2QVAure3Ow92Tyl8kb73eRp
         ps3rGsAB3ILhVdrKUku5cY+72xHjSrNcW9ZBuzpEa5S8Bw9oiHe5Yft6LF8nvBUIkqfF
         X38eeOTPFnLEw+2SjhL10vhr1z+HiVQw+d44Q2MCaXevGZWzk/ddq1Pj91n7Rr+3I4Hv
         kgpg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=ehLydY+S90TnaGzIwpJ3PWUU1Y3vlZoFNdtKYZzCEO0=;
        b=MNNGSvGMicgwLk8XtsVdtg+r3DWPlQurMwGe6Ex83zxHM4+HSFBz6pvp90Bh5NIaRm
         B6EZy+V/hUcMYrE0bN2Sd5XVxBVgL9rohadciT3fFFfMopEFOFgyjU555qYXM0hYS17C
         TguUVR/asCLL+w/njVI9Wsn/FZlB5ztCyK2QBk43N9sgbqaCSTiwnu9mJ+NBCJiYlydi
         4AQNuf3U5frNIMSQFzRwrSNS1Ftn30NNnnXSS1hJ712d+aox4fK3ejesZTPyQxKg9Dn5
         kxUpZRpm3J7dcjr5lTL+n/NZ6TyLMVcdLbmM+fsTVGi1qfz6aI32NdAuJmfXNOTKtfzS
         ZA8A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=7ptk=af=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=7pTk=AF=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:date:message-id:in-reply-to:references
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=ehLydY+S90TnaGzIwpJ3PWUU1Y3vlZoFNdtKYZzCEO0=;
        b=WXmMA+FyKDAGF14JPraCTtoa/9j20E46n1tR3ob43uMioVAaoci0770EcIZxBLaEyI
         wjhcnQt2mBZOcFaRZcuKefuu2PkSE5lPwff3/Nh1gjH2pSxsa7tCaoMeKIHuay42Xe26
         PxGG/2M1bfRiraJwd0wFK5sSlc8XRrq+H815CXx5G3I7//JANNlVMxrJ6Nsd4c51V9TO
         j4szoKGm5ydm4rLX/4VKT3qWlTVZ2C4+cDl0vp1A3PYXUMZo0K8OAzPd4/4S9HkRX+JS
         NmItqUyhf03OocgZShxAmIPuPEQgB2bOKyto6ja5YgAP+zVRX9Vhy3urFXCjueTMYqZj
         OEiw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :in-reply-to:references:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=ehLydY+S90TnaGzIwpJ3PWUU1Y3vlZoFNdtKYZzCEO0=;
        b=bbAk+fcYdf/g0tzhrT0x8w0Wuyw7+ugsygHFqe1Kv+w66f8bAUlkFR5d7/L33oNvIv
         kiNQAfGikoPt2Kfuk5NpWfZHJfe07/Nn29Hvx+/Ui78UyZTVEL50e1s3/GRWOphWnsCi
         EWoaS3toEzmj2jgWnOhxTHojCN4xw3dnhQ9rhZtqYOVGtqa7e4a96Benb2Rb1GwunZ2O
         186K9T8xh0RCMqzGij7kaFwwuS96DJs493F0BGR9c17FQ9Roh40qrRvJgifNGmiyW/pN
         A0hkaq4mkvctwFefEg32hWi8nuLCrZaiQqliunuKvE88e5UWaShcgMEjlphpmf9Ra0k4
         snKg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532CfFZ53VzVJvpiLPcKW7RNYNOSJnxQO6S3tV2eZL+taYTMkU32
	U62W07ZQu8k4EpdylIjtUbA=
X-Google-Smtp-Source: ABdhPJxUsR6b/BrULd0L+eb5/8beF2bm5nOA16lwj2E/NJZijCog18qI28qhVM02p2M7EeijjAHYfA==
X-Received: by 2002:a63:541c:: with SMTP id i28mr23960371pgb.344.1593021533270;
        Wed, 24 Jun 2020 10:58:53 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:7143:: with SMTP id g3ls1284673pjs.1.gmail; Wed, 24
 Jun 2020 10:58:52 -0700 (PDT)
X-Received: by 2002:a17:90b:23c8:: with SMTP id md8mr30940580pjb.72.1593021532854;
        Wed, 24 Jun 2020 10:58:52 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1593021532; cv=none;
        d=google.com; s=arc-20160816;
        b=EfSzb8etUmG6RPnU9Qblyd7EBpydZPaxvfT+yJq+5Ozbgn8UpRq7WdQyp467GLcajm
         heo0pmGCBerJpKoCQPM0xk73RejCjGHSPV6+zo9uWrruo8FnLDq4w9gud3YDiSJaZzDv
         8IDwu2rvYsPH2tT1sYEWPv5g0uYNHm2Uh+TdQB0g8pvzX9iYda0sUPxy8eRLQDCtgqIh
         c7QVzOyG7Cz5ho5+nLnvncfYcpcljOAgj2sS03H/l8l/gltC3NWygzE3At/tMCXmNiuK
         F57Sj/GSCl+HEvGFOK0aShSttJtU8l/eLjcKy+rzXlMF98zzG3XfaqBUtgOp/16d3zkX
         6HBA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from;
        bh=tfQQC11XP7ndxX+P5aB73lDnDM9I3byJqUwRb2vUO+M=;
        b=Q3Y+TCckcekLiqsUPw/OO9fd6MGaa0TJ0dfonQdDjTO/gW+5bB62OZOCY2drpCZNWc
         5tJu0ksgPaNvCT5HhFGBN+6a+eHOUoR5gE5td/4AlYoCRd07bDDWpVAKErxIv9AsAgML
         1kCNoQs87e13NgcdbJl0XwUpQXx+gjVYcyue1pQNnSUVTqYq37fMYWigvVoTtTGp/4WW
         +nuXfUCeHG0z4aC5nDuvnKQ6vahL+Q/36KaW3fglO6jG0oYI9WWjLaDRnWHak/sjG+ur
         flwws5tMoyIuVkdKCTijE4KAczWOeI3I/HFpv4RoeqjdAnE9fj6+Dd8QqicxBnryJuAA
         NyyQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=7ptk=af=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=7pTk=AF=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id l9si275678pjw.2.2020.06.24.10.58.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 24 Jun 2020 10:58:52 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=7ptk=af=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 203497] KASAN (tags): support stack instrumentation
Date: Wed, 24 Jun 2020 17:58:52 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: changed
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Memory Management
X-Bugzilla-Component: Sanitizers
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: normal
X-Bugzilla-Who: elver@google.com
X-Bugzilla-Status: NEW
X-Bugzilla-Resolution: 
X-Bugzilla-Priority: P1
X-Bugzilla-Assigned-To: mm_sanitizers@kernel-bugs.kernel.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: cc
Message-ID: <bug-203497-199747-MRpbkkp5iv@https.bugzilla.kernel.org/>
In-Reply-To: <bug-203497-199747@https.bugzilla.kernel.org/>
References: <bug-203497-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@bugzilla.kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of srs0=7ptk=af=bugzilla.kernel.org=bugzilla-daemon@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=7pTk=AF=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
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

Marco Elver (elver@google.com) changed:

           What    |Removed                     |Added
----------------------------------------------------------------------------
                 CC|                            |elver@google.com

--- Comment #13 from Marco Elver (elver@google.com) ---
(In reply to Andrey Konovalov from comment #11)
> This won't work, as there's a number of functions that are inlined into
> start_kernel(), and we'll need to mark those with __no_sanitize_address too.
> We could disable instrumentation of kernel/init.c, but it seems quite harsh.

Does tagged ASAN's inlining behaviour differ to ASAN? AFAIK, they don't, and
inlined functions still "inherit" whether or not they're instrumented from the
parent function. Same for __always_inline functions. So there is, AFAIK, no
need to explicitly mark the inlined functions __no_sanitize.

-- 
You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-203497-199747-MRpbkkp5iv%40https.bugzilla.kernel.org/.
