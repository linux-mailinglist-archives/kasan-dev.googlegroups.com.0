Return-Path: <kasan-dev+bncBC24VNFHTMIBBO76VKAQMGQEOEEYAKI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43c.google.com (mail-pf1-x43c.google.com [IPv6:2607:f8b0:4864:20::43c])
	by mail.lfdr.de (Postfix) with ESMTPS id 7C64931C195
	for <lists+kasan-dev@lfdr.de>; Mon, 15 Feb 2021 19:36:45 +0100 (CET)
Received: by mail-pf1-x43c.google.com with SMTP id w200sf816926pfc.18
        for <lists+kasan-dev@lfdr.de>; Mon, 15 Feb 2021 10:36:45 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1613414204; cv=pass;
        d=google.com; s=arc-20160816;
        b=fajzkrK2DMI21tqv86VIufRJ73/wx6Mgox0XH/VSTZtRX2pBydswZ7eRFxCnHxaLd/
         bePD4PcQQdgtSL3IahcVvTWnqiBq6xd32/Id6Yr876LRslJ1KHrwY21Pi4JhBt4MGC7K
         BcOMSd+7psekVRMptkmFp0AQ9m2d9GEma5qJSps/y8dqirWTPIW2XQll7vr+WBcMYdR9
         z5sVemPGp4NsJDZDifNvnoADtlYRAKnAThNPQ4ycIVNg7V/DubAkegiDLphdzsHMDs6W
         adQBIJ/7RiBx4OfaJe4j5KtjIlCrPUGQNAn8GRrl55jKh5tGPwqYEoeRZh9GNonsqWpJ
         CQHw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=6fBIn2AWuzlVnhIrcsp2Z6XlOqQddWVZ5E4gygMIGt0=;
        b=nBp0RZAZNQtBuzMXpel5e6LObj3/dWKNKfK9tbNH5dKR1aOQ/OK9rt2ENDKakf1hZ0
         KowfXJ06hvz05prYYBGsUayw4jDL1QiqBdpVGtd6gbr5Chl2Q2Ex2OvB+mkrmzoIrWRJ
         gmYEnvL/o9Dfh9yaYZdqppE+7TxQA9YMxEhlDDiRHp33ydGKTNDCcWbpHCq8Z/G2Jjeb
         VTPQ4CdziWDL3PfSEEnc5QrFCdWp9XP8n63HL20J1MgeULBgC6j+eWOuUpHkF+O7HsXs
         dNXGx75labdwqSSNNbi1Y11HpuD/uTmo4BfjL+jcO3e7kQtoqflO3w96gN0Pol41nm0B
         BVsw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=uVlVEKKN;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:date:message-id:in-reply-to:references
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=6fBIn2AWuzlVnhIrcsp2Z6XlOqQddWVZ5E4gygMIGt0=;
        b=h3iJ2vpU1xzF5GEZIQ+3GPXH0wYaXtzoIktXW2UX9SDa724tKhxgf7nNQ2BepFQAXt
         ntqf2KazU11gf6CZXVVxxadjkIUAMenW1nU4Tpf2EoOTUQWLY9LMNglI9hrnN53EP75D
         ZvxA5mhCyNq+NN/klaFa/DRfksu4bDDD20pKINVojifkVmdhAuwrLcHoXuG942Pm0YY7
         CeUuDHA6YXmZ3e1Yw/wwzeg8GxSn0PVnERTFC3pw5uDguJRCUv7igfcTuESAbbz0M2EY
         W1IeLck/kcmNZk6o9vbsEMkTAW7OGbxH+yUiQcDjLHMkXDBdMqj2swIKQUTaCaYaCfX+
         gebw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :in-reply-to:references:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=6fBIn2AWuzlVnhIrcsp2Z6XlOqQddWVZ5E4gygMIGt0=;
        b=o4U5onxt0WwikfPq0M/ydBwSl6JMuF5eXFe/gqHxfhLwfRfwVpg+TnWm4twzftdBhM
         R9dWyVs7nFbTK9mD/5Gmi/n97scf6h1OH+a2VW1lSAbR+sHwaUlw+gl+J/EI0t1zYYOM
         uatrDnH6iTKJcCouuV+uFD+OMcO6f+HmHZrcRUVqIaxii3Fad7m+rb+Lk/qopKQlmKBh
         eQ6EWwxy7Txbfl06GiRBonq0ix9aK4L3rL9Ii63nm4J/quOmfguYVmfSMr5E4a+2vjBN
         JT5eAEMy36sMkWTyS0TKmLiwDU43dg1iAXmYBOmT+M6SdfeuUHIM3oNshG04OkRpEsDc
         LqTA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531Sq4ThJXmMt5SwfTHxx3T09O+rjjqz8gnYsPGTfG45RohHOQwu
	qKNmaUuDBicT2bZNRRLQv6I=
X-Google-Smtp-Source: ABdhPJwVDdSsNfS1Qd9380+LaYUW8HLv2BKNd6snEvnR6UrEBVQtaBBchincolanyxvMWZj2myT1HQ==
X-Received: by 2002:aa7:8b59:0:b029:1e9:8229:c100 with SMTP id i25-20020aa78b590000b02901e98229c100mr15236685pfd.19.1613414204090;
        Mon, 15 Feb 2021 10:36:44 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:903:31c7:: with SMTP id v7ls7828312ple.2.gmail; Mon, 15
 Feb 2021 10:36:43 -0800 (PST)
X-Received: by 2002:a17:90a:9288:: with SMTP id n8mr186665pjo.91.1613414203458;
        Mon, 15 Feb 2021 10:36:43 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1613414203; cv=none;
        d=google.com; s=arc-20160816;
        b=bGkAkNkF+M7gyPIIPYbiYdwqxqptGeUh4KkimFk3pCAi8qA2+4Ck/5ngRl4olHjkfC
         a0CeU/qkoPd9S2QMX19ULXUppWIN5xfxHJ4X1D5oYsYfu0pB68Q1omK3F/Cur4mTmxPr
         MbnerI1lEL52yTaV1/wWf8WflHyyLF2QVIyZqHSwYfst42RS7ZHOqsE+lvD76/Ibv7hM
         cgMXjpKc655ggqxbTWj1U9PPswYg4BB2C8SPdCglTPzotHzWpe5CfJFJfv0F5/eM+RtR
         hzaElZE8zMLWtvRrnLLFryfNWeJEa53p22Q2rJSfU/rUNZ/a9gQxBn1ryPP+J6m2tsUc
         Eh3w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from:dkim-signature;
        bh=zu1ax+w2e+0U7apq6lU55VaPDFBHl9QQsjjzTJxh8rA=;
        b=vCDYcVobMkZNHGmlKFa+nojAiON2CCAgbblCTAWgO+2kQWo3m6/iM3OyKHd4WR579+
         CkBJn/OzGplkeV7sy3FeyVX/r8ror8qmKTGo3ZxssrwV+9oC/0C5Rz7ID/MPQzN56MlK
         c+6ARtAEmCO0vDsn2+LgLI1OWhmIF4pVLqcsA5rTf+nZDYUjV1t+sSZEj3D2Xfq7BdyJ
         iKopxWfiZ98/0PW7VnqPrj1X4iXZN01jJo2W3dTATWXK6SFvIFj1LmlwRZT6554erLo3
         KcJ3Am6amX4F5ID/QtWasKqs2mn9h3XYpu4T6oyBaUGqsd7Cd4d4mYqjQnk85TF3bn4b
         e7+A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=uVlVEKKN;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id q10si7698pjp.0.2021.02.15.10.36.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 15 Feb 2021 10:36:43 -0800 (PST)
Received-SPF: pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPS id 249CE64DEE
	for <kasan-dev@googlegroups.com>; Mon, 15 Feb 2021 18:36:43 +0000 (UTC)
Received: by pdx-korg-bugzilla-2.web.codeaurora.org (Postfix, from userid 48)
	id 12B83653BA; Mon, 15 Feb 2021 18:36:43 +0000 (UTC)
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 203503] KASAN (tags): add 16-byte aligned tests
Date: Mon, 15 Feb 2021 18:36:42 +0000
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
Message-ID: <bug-203503-199747-tbYJj73VzU@https.bugzilla.kernel.org/>
In-Reply-To: <bug-203503-199747@https.bugzilla.kernel.org/>
References: <bug-203503-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@bugzilla.kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=uVlVEKKN;       spf=pass
 (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates
 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
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

https://bugzilla.kernel.org/show_bug.cgi?id=203503

Andrey Konovalov (andreyknvl@gmail.com) changed:

           What    |Removed                     |Added
----------------------------------------------------------------------------
             Status|NEW                         |RESOLVED
         Resolution|---                         |CODE_FIX

--- Comment #3 from Andrey Konovalov (andreyknvl@gmail.com) ---
The last batch of fixes for this is in mm and should be merged into 5.12 soon.
KASAN tests now work and pass with the SW/HW_TAGS modes.

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-203503-199747-tbYJj73VzU%40https.bugzilla.kernel.org/.
