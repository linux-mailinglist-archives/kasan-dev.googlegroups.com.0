Return-Path: <kasan-dev+bncBAABB2FP6CIAMGQE2GRWC5Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23c.google.com (mail-lj1-x23c.google.com [IPv6:2a00:1450:4864:20::23c])
	by mail.lfdr.de (Postfix) with ESMTPS id 542554C6020
	for <lists+kasan-dev@lfdr.de>; Mon, 28 Feb 2022 01:31:37 +0100 (CET)
Received: by mail-lj1-x23c.google.com with SMTP id r27-20020a2e575b000000b002463f43ca0asf4883916ljd.7
        for <lists+kasan-dev@lfdr.de>; Sun, 27 Feb 2022 16:31:37 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1646008297; cv=pass;
        d=google.com; s=arc-20160816;
        b=uIlX0/ElpaLXtsx+oDjmlbjpWwQNrhLGFvoAYLwXGpBmnt/Tw6J3oc7A26DYnYd2fV
         fxrj2zzpnjc7/IAjp7YenaKseFLGofYilipoGD0s/sl2/M13jWXHk4f2Hd4/nStv8DMk
         Tp5+5Tod5UMfldHflpe85Vcm++OLw3M7SdwBWmRuFoB7UYZa3siPTuBWpNBRGUG6Vza6
         2rWhuel0Z2yDf1fylmAZk6xtfYe2gfhz0s6UILXZ+mmJJ++7aQvJYMsAKV7cmizkloUy
         p5CIis0eGCQ9ygfWzEKFzcVdn97AXrZBMhQVDpGrI9K1xTe7Q5xGu4WvZvko3DbacUBJ
         4+wQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=5akw3AxxbboCl3SLE24j35Y4DMEwypdvSYUNoC7pqMw=;
        b=b4+CYv2V9dhw3zAgHZXQLrtq5vcFF+33/ktn4vUVfdft68NVmhp26FGUKow52ROrO8
         pv01/06SUbGdS12m+H6cJlD8DLP/R2cFwLqgfW/aT+Lm5YaMPE/4/uThTMk5k/xa092g
         2rCCbtN6UXxrZfD6+1UOelTa85HyOoOCHd3tM07ZuuFtaVIYNUXyCUDUiCOXBTHnE58Z
         Wgzvf2qA6GblKpQE7inoheBgxxoLGwQbffwmAm/U8s8j2fvMzTMIg1X2f6GkMb0IIVkC
         PXXMku7p0zGGZ6eaG59N/d24SEv6aLQlfI8NgAoO2Ypw3kNYoATCHu5TkDsgaNIc2dWT
         rAEg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=J1cBM0ss;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:subject:date:message-id:in-reply-to:references
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=5akw3AxxbboCl3SLE24j35Y4DMEwypdvSYUNoC7pqMw=;
        b=rs1mDfK6jy5d8U2u2p6Gf0v3TF87KS9lYBoio51rbrwKvWugm1r/rYvi6pv68H7g2O
         AVjTnd+extY88/+fBW85e1uPlVBwVMTK4wJo4VTjyu/8xfnYeFMgXIY63msT8uksnHQ1
         gPkiveQAFvCOX/q+P49J16kN+zPcnzX2Yx4feoUzaYkQVq3P3xfpDyRSAJPVRlmYJv76
         a8NhuVsbf7cFCQgc2kn3ywQhDM4l6sD+DWLf0mZVgefiBmkX7sWDAmnDMaUQmvIOzctE
         dPR2XaTkJ1Hslkop+3L77aE5F33h3oItQCyTq9fmfqeikT4+Qb15wJySXhz8vn48oAKQ
         mNWg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :in-reply-to:references:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=5akw3AxxbboCl3SLE24j35Y4DMEwypdvSYUNoC7pqMw=;
        b=10XeELtFZEJBXmSI4IrtEv3r+7ARADxZNHfBQ/GZHpA11xnAE2Hdd8iWHlGqcXuHjU
         lu6uLF+aX9TDrPaof0KmRZ+NHEo0Wb4cwBp/85M/GCu4sUvv8/gaOGwH3jCO2HBjz6xq
         hEiVGiLCpGe7BH6JziX8GFJZpw6KK/OuhsSKZeBtZBqanCmglGKNpVeCP3LOHF06m+GF
         VhNTVRaEHwXdpx8UlKyYzKIXIpFxFKAEUODMwYm7LzFO4K2kBVkJ7rLYE35mXJ/I4CE4
         9UZysL8AFj2HVDyPBDU/vq9/PECw7kHzup6Oa2F9B0t2G8MAtTB3SAAATxXxewqKng5t
         m7ug==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533xgpnNnl6GULK/Y92B21qbrkXOoMT/5JVbqv2MVRQTzaRjNr2Q
	7gO+6AYpOJz55GwYa5T1LrM=
X-Google-Smtp-Source: ABdhPJyZe4uSN6ydIGv3BlXkSlpLUViaP3TrvsvHhrAGjJsmeS7D4ms7NbUdSfJt/mOWqHGPGjZ62A==
X-Received: by 2002:a2e:9202:0:b0:244:c698:e0eb with SMTP id k2-20020a2e9202000000b00244c698e0ebmr12723896ljg.444.1646008296727;
        Sun, 27 Feb 2022 16:31:36 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3b8e:b0:443:9610:6a0c with SMTP id
 g14-20020a0565123b8e00b0044396106a0cls331575lfv.1.gmail; Sun, 27 Feb 2022
 16:31:35 -0800 (PST)
X-Received: by 2002:a19:5212:0:b0:443:5b82:b6b with SMTP id m18-20020a195212000000b004435b820b6bmr11708028lfb.232.1646008295903;
        Sun, 27 Feb 2022 16:31:35 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1646008295; cv=none;
        d=google.com; s=arc-20160816;
        b=hsJsgbEV3DwyjKwgeXTqmd9nFWfyPjzliJjR61Xl7zhM+NrXSzFIiTyVZw26cH5dUG
         jP6/kSQOV4WREqdPD7TIqmvqPt/XgCyYCvwv4HA68l3SczG7M//apc2dK6OhJb1APELh
         sGyP45O2BZAzhJPkYWGE9he4ipiNn+ADrRUrtBeo4aQ0gHwRscdWZJ9Qs0lRp79xL7KC
         uPilYTUiwzfKK79AYQh1ewZmrEsyStX75FVbsBT0Q3sQbvISTdgNNwMlM2NlB3kDGqkL
         mjMfN0pAlUIovtDIEurSi+f13idXaYzzeKFlCsH1knPBnVVGYsPVJ24hfIjgn7+r23Zv
         ou3A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from:dkim-signature;
        bh=xUBceC65BEQ9lNaYqUjkMjDoX7ZCkJvS7JFXBERCeuQ=;
        b=vsDVa+/ED94Apqfo+L1jNomYD2orc6JqNx3cXa24FpNmTgU5xziNVop17SQUbq381w
         VcXccWI/RVH7dnqZIwZRVK3ayhjo4+BwPuGebk5lN4haqcU0max/Rc1OljtdBW01TXil
         BjUAR8/qkJMHyLssJDhYEMrfvellNIcXg60RRKhb589cNbV4MpjtmIwo9kyt75mwAqo5
         6TQcNI/2IkwN091HfmdkIw5PX2oM+q00yv2/r5uexd2VTgkU9FyYL6y1MekxmVvbmZ8M
         2IFt03/Qz0pEOMKIn8VwUlklVw00UTJYnpjUeMAZXVYpE1jIzibZ2se6mJ/DSqDSDnBD
         MiaQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=J1cBM0ss;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from ams.source.kernel.org (ams.source.kernel.org. [2604:1380:4601:e00::1])
        by gmr-mx.google.com with ESMTPS id v12-20020a2e9f4c000000b002463b896be4si444523ljk.7.2022.02.27.16.31.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sun, 27 Feb 2022 16:31:35 -0800 (PST)
Received-SPF: pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) client-ip=2604:1380:4601:e00::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by ams.source.kernel.org (Postfix) with ESMTPS id 20A97B80B78
	for <kasan-dev@googlegroups.com>; Mon, 28 Feb 2022 00:31:35 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id B83BBC340F2
	for <kasan-dev@googlegroups.com>; Mon, 28 Feb 2022 00:31:33 +0000 (UTC)
Received: by aws-us-west-2-korg-bugzilla-1.web.codeaurora.org (Postfix, from userid 48)
	id 9D624CAC6E2; Mon, 28 Feb 2022 00:31:33 +0000 (UTC)
From: bugzilla-daemon@kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 198437] KASAN: memorize and print call_rcu stack
Date: Mon, 28 Feb 2022 00:31:33 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: changed
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Memory Management
X-Bugzilla-Component: Sanitizers
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: normal
X-Bugzilla-Who: andreyknvl@gmail.com
X-Bugzilla-Status: REOPENED
X-Bugzilla-Resolution: 
X-Bugzilla-Priority: P1
X-Bugzilla-Assigned-To: dvyukov@google.com
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: cc
Message-ID: <bug-198437-199747-j3dSahycm6@https.bugzilla.kernel.org/>
In-Reply-To: <bug-198437-199747@https.bugzilla.kernel.org/>
References: <bug-198437-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=J1cBM0ss;       spf=pass
 (google.com: domain of bugzilla-daemon@kernel.org designates
 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
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

https://bugzilla.kernel.org/show_bug.cgi?id=198437

Andrey Konovalov (andreyknvl@gmail.com) changed:

           What    |Removed                     |Added
----------------------------------------------------------------------------
                 CC|                            |andreyknvl@gmail.com

--- Comment #12 from Andrey Konovalov (andreyknvl@gmail.com) ---
This seems resolved: task_work_add() has kasan_record_aux_stack() as of [1].

[1]
https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=23f61f0fe106da8c9f6a883965439ecc2838f116

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-198437-199747-j3dSahycm6%40https.bugzilla.kernel.org/.
