Return-Path: <kasan-dev+bncBC24VNFHTMIBB376YWGAMGQEWTQ3HAI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53a.google.com (mail-pg1-x53a.google.com [IPv6:2607:f8b0:4864:20::53a])
	by mail.lfdr.de (Postfix) with ESMTPS id 57D2B44FBD3
	for <lists+kasan-dev@lfdr.de>; Sun, 14 Nov 2021 22:28:17 +0100 (CET)
Received: by mail-pg1-x53a.google.com with SMTP id t75-20020a63784e000000b002993a9284b0sf8113582pgc.11
        for <lists+kasan-dev@lfdr.de>; Sun, 14 Nov 2021 13:28:17 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1636925296; cv=pass;
        d=google.com; s=arc-20160816;
        b=FGSdSn4nXCy0u8tpOXmCEDwpwZDHWDyREEHAtwaybm9SviKHzcq9WisRD3BrpREv1Q
         M3Ys7fmMtU/ixQahPllqnnf9nZaZxGp1+umTsW3yHMjVxFthPZkpc+EU4a57lwpT3etG
         1iK68c1jk4uXrCmJ46wTFuKx2YadfRH4EnQaQeFy2rAopyNPvynhheAPNIBsiYEPnJOj
         eHUAUfNlmlUL7zsWwCrbmHTRDobBKLBDMo3TCwP/dfhMx42b92lPb19b05EgBPV1OE+7
         Hkj1Lk5a/7HagoWs8+hopYayBCpkqNokPKIcHM1ETbHIAU6ngS7XcVeOestM5JjQlp5+
         8hVw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=tYEtML7mIDDDockCR6WCX+YbhDe1mVStmCdb1l56iVU=;
        b=ckuz2ub5AVEHF4yQ56IvDLVadyW4bxKTq8ygvdJ67cIy2IIEbk+3fjGO3FeCmUiNoS
         lnSBrpNBIMVr8NRR7mqgHyIEZ3rjO0sDBriYtU9xPgfIEJo55NvGA+J9hoh7xKsV3qvi
         CmTuJ/Ug3q475on8zqryFg9u4W4WCr7uqlos4+jShS3HFnNQUZV8PRIejKFxE0OjbLqr
         l+IMPvmrI+S4t4gHVtT1105KdO9Udfpr3fIcTdl8u1P6aIChJ4sCF9lKvq7T81bd/v1u
         mM3jim49jZj/Db4z9Crtr+A7iWhXXSOJPew6TP3vXiHnZjyTGGkLjUIPGhFZmmRdS+/m
         rylQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=sTB4n8Gs;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:subject:date:message-id:in-reply-to:references
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=tYEtML7mIDDDockCR6WCX+YbhDe1mVStmCdb1l56iVU=;
        b=IZE3rLsI8ZDMcxYAzHWF++BR+6Fc47bZdWacchgc+VOWRuXxz4FaLqMKAQMUQUI/Hi
         mLaUvq+B1g8VbembCvp8xji11yjgEre7OHVbRTOORuxbLAVJdv+sJQXRVcvpXuYWMna8
         Of5huhxSGQW4zLhpqAcEB/7PTeWBGEhsfHjli9e1qcqyWsCOi0JqoWjMtNVTxVtVJnG9
         wE6fEvwpKx14C+4QFXbmIiU6+ZQU1g1fGgonm6/g0tj2QLipJVcLTn8XKaOpzA3fO4w4
         xjATLzPhudv756RkEymEXpFrAN9+mgRdXNBnTtxVI2gCsUyKYA56jYR4MbvkDYVqbrqb
         cQ0w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :in-reply-to:references:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=tYEtML7mIDDDockCR6WCX+YbhDe1mVStmCdb1l56iVU=;
        b=LgvJ2l2wVH2YqvHVVfzWtI1U1tvtHuJaoaan5VYY0NEMLlxLD7QshuB7lA1eVlJWk1
         MNhVtP9J8lPb18E6klZd2hLD8uKyz4MdaU2Lana5YqvYaXv1J8Q/v4FN5CovZiX1SWKw
         67LK1lz05GkDC07HVwSSHwtRuxUIygknPn3VTjCMUMpGtuVGUEIuTWkNmfc/urzatoEL
         7USKrTDQz6cBHDvd9DeznZ7j5KBhb2kDnkRLlnymHrFeknIkj2VwU33wZ4SK1K3a9+oT
         8QfNC6RK35ASyqhUwE0erjT6LrwapYj+3ehHD6dPTuYUQdiQH2vmgto0RlHxOIeJTWoS
         8W2Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533ru2Jo9LoN1UthH0lRBa4TxWcRAUmaBL4ZlFUcTdvNBPU4l7MO
	pktj1dXdEDQmJbilI4TmmGc=
X-Google-Smtp-Source: ABdhPJzmByjLlEHZxxNVZ0PpgtsrOrPtTV1TtC7ifVybBaK04De44KJcZlEMthpr5iZh2eWn+rHqJw==
X-Received: by 2002:a17:902:e0ca:b0:143:c213:ffa1 with SMTP id e10-20020a170902e0ca00b00143c213ffa1mr6739113pla.73.1636925296092;
        Sun, 14 Nov 2021 13:28:16 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:73c2:: with SMTP id n2ls1516260pjk.0.gmail; Sun, 14
 Nov 2021 13:28:15 -0800 (PST)
X-Received: by 2002:a17:90b:4ace:: with SMTP id mh14mr57610444pjb.164.1636925295576;
        Sun, 14 Nov 2021 13:28:15 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1636925295; cv=none;
        d=google.com; s=arc-20160816;
        b=GAbXIA77oQUzLY9/lP0XFG3/6EPxHHyBRpVssIgPmChBEjxhDMi9SQc5etz3R6Fadx
         k7EVxYivnOshxI2/LHwHFzImYofPTn9K4py3dViSxEyRbuspFXQQPpsRCql1IYZaniYJ
         4V3tzrEKPqObyzi1vCfY2HnVqQl0w9BiHcLL5SLoA6oKN77t4R5Svbzn1M1/yxhQv7FI
         kqbajdT2vMH98tSAjZBHWPtpnDARXbAmNDHYZ7BYNkpIU7dwZCKjrJA2g3LZwFoamO68
         jfRqYzfldGO1jHiuTxW334k1TNFXWLxtMgSS/Mhz22jhHkubfZLQ35wKggyTooI85qzW
         UbUA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from:dkim-signature;
        bh=5pRzRlrcNKcGa+rZ1uIY4khFWo8rGVPstkO2TM4KMMQ=;
        b=YXGNYhFXqvUEVd+eIyhp6tPvnlN7314QjVSCXRXhwfhnZQSEdUzmiblJ7hMuVEkBk5
         qV/vPMBcIwYZUTtEMblAN6hGeilnebp5gtCzBGrZosK904TvHvi7x4RVbvzCTZfLB8BM
         b4YieWU+WZmwq4kjYAQJJjBRpUkN93x4B1m8nKVXLsgA6w35ZNCIJgOkNHMm2Hr8FWjK
         p/LeT7bVnyWFkZLEcYu3EygoeaTlHRAz5NR2/7fQ1JUYhFIq3H8L9UTu/w1j8LNL0sjU
         Q9UDRGWso63Z+xgLGWqT7QT/+D9J8TPusXPQ2UwvcnedND6L0o+GyFaC35Jdk7x9dDoZ
         rztA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=sTB4n8Gs;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id lr18si2846296pjb.3.2021.11.14.13.28.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sun, 14 Nov 2021 13:28:15 -0800 (PST)
Received-SPF: pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPS id 3B7FE61104
	for <kasan-dev@googlegroups.com>; Sun, 14 Nov 2021 21:28:15 +0000 (UTC)
Received: by pdx-korg-bugzilla-2.web.codeaurora.org (Postfix, from userid 48)
	id 33C2060F51; Sun, 14 Nov 2021 21:28:15 +0000 (UTC)
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 213719] KASAN: don't corrupt memory in tests
Date: Sun, 14 Nov 2021 21:28:15 +0000
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
X-Bugzilla-Changed-Fields: 
Message-ID: <bug-213719-199747-1z148RAmQA@https.bugzilla.kernel.org/>
In-Reply-To: <bug-213719-199747@https.bugzilla.kernel.org/>
References: <bug-213719-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@bugzilla.kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=sTB4n8Gs;       spf=pass
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

https://bugzilla.kernel.org/show_bug.cgi?id=213719

--- Comment #3 from Andrey Konovalov (andreyknvl@gmail.com) ---
https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=ab512805710fa0e4ec6b61fee8a52d044a060009

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-213719-199747-1z148RAmQA%40https.bugzilla.kernel.org/.
