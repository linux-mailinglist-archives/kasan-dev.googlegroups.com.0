Return-Path: <kasan-dev+bncBAABBXGRXWMQMGQEKHECYOA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x838.google.com (mail-qt1-x838.google.com [IPv6:2607:f8b0:4864:20::838])
	by mail.lfdr.de (Postfix) with ESMTPS id 289DC5E8FAD
	for <lists+kasan-dev@lfdr.de>; Sat, 24 Sep 2022 22:30:22 +0200 (CEST)
Received: by mail-qt1-x838.google.com with SMTP id cb22-20020a05622a1f9600b0035bb51792d2sf2095870qtb.5
        for <lists+kasan-dev@lfdr.de>; Sat, 24 Sep 2022 13:30:22 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1664051421; cv=pass;
        d=google.com; s=arc-20160816;
        b=tji1wRBqYvdzAEO/Qfi58ALOdTIYpNTV7iaviaKOSE9Abb5CjjyMlMeveFC445LPMg
         4Z9nfe6wsiRip5yvIaynXinOZM0sdhsWefoqq6WF1akEp97dgQTa8CrN4xqrsQ4P8OxE
         e1PnTPl6f5wj/IG1tdV97e64V8ePPu5rXKeNnPA1m0fFCkczSG5Uc52edk32lcJo1jMq
         sf4WMjL/A/KOBtWZHUArEwg5bxzfY7osqumean0MIGLyJtEX9KoMF++n1M4F72/DNxmZ
         F5GSa3ryhkCcgud3mVhV61P71PTZKcdUe6XRhdgOcnPCmF9XFBOOyO2uoEZc/p1s1PZQ
         WieQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=WSHrTmXXnt+3Cj2b5pqJ3RxjCkT8LrMS0sD5S/j6UU0=;
        b=lYE7d9gWc9LJdDyiqlxaey6aq6K9Q/IllSQttCx9vN+cMSrcRCbJPxa3GW2bDk1BgY
         sb3GC8kFtJdpUHq+JV6Cbbwfq3LoEpKuhl9NaUjalQBaV0lPshKyqsciaLCXCdbi0T5u
         wx2OHv/cNeLoKM2/Et3pRp1JqsNhA7gfGp5WmBpi/YGkpRDQRPVSjWzCBty+jctLCCUf
         E0+JPu9uriDoy9cxH5O4u+lYkYf+WwSulxIObpk9SQZKcvqsuP6yGHL2a2EGjpCye+ws
         uK2iEYEnTwtYZaP8D8i0zpq2YbESRvAWkUf9OcqTj7k4o6G6Yqun/Mmqcy+0mpJGk8zs
         9MAg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="i/mlt3TH";
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 145.40.73.55 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:auto-submitted:references
         :in-reply-to:message-id:date:subject:to:from:sender:from:to:cc
         :subject:date;
        bh=WSHrTmXXnt+3Cj2b5pqJ3RxjCkT8LrMS0sD5S/j6UU0=;
        b=JpDR/WNffqKgD/lDbeduOapVhqHhpGq57hEay+auPUX2ddE6BjYlH1+yvh2dcUp+SO
         LNBz4psnNk1M/6aR6bxLSc2f9cAP50WZ+4VZubrrxPJYhh5bQe/8IuUBRsCMDxGaI/RE
         QIocZqyq0xJNOJ6Bqa2Z4FF/ZvlgwLiK0AK3T03ggMxZ9cR/yWpGRCe48AJD7uJoqN0l
         koAtKJBdiKyCWcJSrOODEKWMEtfcA0lehXSzIZMd7M2DA5WKSRpXIkLc6Bh+bIEblR+8
         9lSJr6WEhr9gLKSg2aSHFa6tTTWCs9Y7AEYvzdhzM/BwPV3CoLCO+0hjwB4/wbAQ/2w4
         3XMQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:x-gm-message-state:sender:from:to:cc:subject:date;
        bh=WSHrTmXXnt+3Cj2b5pqJ3RxjCkT8LrMS0sD5S/j6UU0=;
        b=b/O1CqkZS1mnsRky1lpdjBWdvku4k5nXWt0cIcrEaGxJW08ic49hT+smLv8zATFQz+
         o0bb+iwDDdqB44/UtCJ/NR3yYNulX3olhXL108fxjidUzksN0m2ZdaeFji795w8rjPMv
         +CtT0ZGsuq4jSkaRKFppkW9AqaJZHHsr2Q46bNQZ7IKNZnFsvw4RDLTpCwY0Z15we8Lg
         3ZwCgALt8KXlwjvHAr5EfMJ2bEzJJRLpNBGCQIom6Zq1tvpl749cyw1CKFM5lKAixAY5
         Bhu4rKcpkVTfzy1uS+BtZ/TwnWGlGDtk9vYBgVFqKPNRUMPZ9YzLpHU/1dUKhEiR1iSY
         sRLg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf04XdP1mOdGc5ofEqGxc0D2mJ0s34yO3q3+kcQCrxUw3I9sg+Z0
	OcYjRCBmpakzhkRIXB/BcBE=
X-Google-Smtp-Source: AMsMyM5Qj16RYB2dd0gbU5Twb2uPIxSbrYf60mzYAFUQBE+uapSeP06tS2vWAbyQpgE0jrpCw1w/sg==
X-Received: by 2002:ac8:5884:0:b0:35c:d949:30cc with SMTP id t4-20020ac85884000000b0035cd94930ccmr12176770qta.528.1664051420885;
        Sat, 24 Sep 2022 13:30:20 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:622a:6096:b0:35b:b0fa:af8b with SMTP id
 hf22-20020a05622a609600b0035bb0faaf8bls13654376qtb.8.-pod-prod-gmail; Sat, 24
 Sep 2022 13:30:20 -0700 (PDT)
X-Received: by 2002:a05:622a:4e:b0:35d:159:3d95 with SMTP id y14-20020a05622a004e00b0035d01593d95mr12482669qtw.362.1664051420360;
        Sat, 24 Sep 2022 13:30:20 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1664051420; cv=none;
        d=google.com; s=arc-20160816;
        b=U2UeMBFl3Z516GskZcEXhUmXksgPNSdEYn5pd1ityAseyBQ5M3rnIBGkTIf1yQpFfw
         8YCAuicVeFhrdfURncenR5pvKyHo4aBOtiZDWcZk0Xx0ucEXpSL+KzdsjEH4GZZc8EpR
         J2fyIRB49QgZfT4BN+5i3SYjjWxz4OQNaWLW4VTKur8glCFWXw5RcZvRI0AKG1VXMZjJ
         OiucNxKaHwjyONaHjlzG3NfiUYqXZH5Ll7yofgAGHUVDWGjGj85lfZXWpNJkCQo3dVpJ
         3aAxjlaVKnJB+tKNZmW5Xw+pkacpdtkD1c39uf5qfTeBb0e7mFh92B3Q3V87vPaG2aBW
         utvQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from:dkim-signature;
        bh=pBZPz/DCN7cUyZe7tI6/qKa1g9E/72JvO2zjPOSY9VU=;
        b=hb+CNo1sNwbB7ZXa4ceSM5/EPgrwN/DWq33hZF3tv22TLGhxG9RnF2JZbjsCW++vwo
         GTDBPI3wwGGRasIJR64MWOw6Rr6npcO5lHYSwvq60wX4iY/K0xBDL6uen6Mc0BKGa0TJ
         vEpLVYa7AJoXKYhl/qW/Xx33JRuY6CnN/L4wjC3txvOjBgj81RPVdW6hXg2bzob6Y3u0
         rJTNbq8GkNSZvRPTejfpZM4h9z8ixEeKUtY2TRZYpqjax07JNP1OrcWYSDAOkhUv/J3R
         jQoRyWtSeb99zbLpIDZCOdDrGdJkfvcxS2o8pEmk3au0x5PnTMG7BDMtr/G4SuPL477M
         BNMA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="i/mlt3TH";
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 145.40.73.55 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from sin.source.kernel.org (sin.source.kernel.org. [145.40.73.55])
        by gmr-mx.google.com with ESMTPS id j1-20020a37c241000000b006cef2726141si482955qkm.6.2022.09.24.13.30.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sat, 24 Sep 2022 13:30:20 -0700 (PDT)
Received-SPF: pass (google.com: domain of bugzilla-daemon@kernel.org designates 145.40.73.55 as permitted sender) client-ip=145.40.73.55;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by sin.source.kernel.org (Postfix) with ESMTPS id 63274CE0AAD
	for <kasan-dev@googlegroups.com>; Sat, 24 Sep 2022 20:30:17 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id B01C8C433D6
	for <kasan-dev@googlegroups.com>; Sat, 24 Sep 2022 20:30:15 +0000 (UTC)
Received: by aws-us-west-2-korg-bugzilla-1.web.codeaurora.org (Postfix, from userid 48)
	id 843D1C433E7; Sat, 24 Sep 2022 20:30:15 +0000 (UTC)
From: bugzilla-daemon@kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 215759] KASAN: more OPTIMIZER_HIDE_VAR annotations in tests
Date: Sat, 24 Sep 2022 20:30:14 +0000
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
Message-ID: <bug-215759-199747-ffsIPOCNav@https.bugzilla.kernel.org/>
In-Reply-To: <bug-215759-199747@https.bugzilla.kernel.org/>
References: <bug-215759-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b="i/mlt3TH";       spf=pass
 (google.com: domain of bugzilla-daemon@kernel.org designates 145.40.73.55 as
 permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=kernel.org
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

https://bugzilla.kernel.org/show_bug.cgi?id=215759

--- Comment #1 from Andrey Konovalov (andreyknvl@gmail.com) ---
All of the mentioned warnings has been already fixed.

I just mailed a patch to fix the remaining warnings produced by -Warray-bounds
[1].

[1]
https://lore.kernel.org/linux-mm/9c0210393a8da6fb6887a111a986eb50dfc1b895.1664050880.git.andreyknvl@google.com/

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-215759-199747-ffsIPOCNav%40https.bugzilla.kernel.org/.
