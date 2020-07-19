Return-Path: <kasan-dev+bncBC24VNFHTMIBBH6Q2D4AKGQEOK4XDKI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x538.google.com (mail-pg1-x538.google.com [IPv6:2607:f8b0:4864:20::538])
	by mail.lfdr.de (Postfix) with ESMTPS id CD2EF225174
	for <lists+kasan-dev@lfdr.de>; Sun, 19 Jul 2020 13:01:52 +0200 (CEST)
Received: by mail-pg1-x538.google.com with SMTP id 75sf11588079pga.20
        for <lists+kasan-dev@lfdr.de>; Sun, 19 Jul 2020 04:01:52 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1595156511; cv=pass;
        d=google.com; s=arc-20160816;
        b=CdTuvRx1LxfsPkznZr1x8gK6fCY5JQvrnDp4v5EnfSacd8bUMm40aeM+Z5fW2CnS9W
         lqX8fkIqbRRw9CrgDdOVVDrF0H5teZOVN/mgyFNq6onHJSp+TFUNmQj+8jPAaBlkMNQJ
         DRikBADS1FLx+wGFk1zxUc/0LwlCwl1jqceShgpd1/22rrszpWDbH696aapV9w7yJ/7N
         +FlRmJysdvoIliKm1woi3+as6xVaNW1iiCaHhbzqc3SRBilFdlWDqDyV9+3+fz8tZIaT
         5boxlG8jQVvkQGz388MykmWhdp84cKlcv2yxQx6cS/0WkmvEODay9RpGYpmS+eWct36k
         e0EQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=sbKPdFAh+WJ7X2B1SMJwu5W3fH/ttGukUyBW1jm8dp0=;
        b=qN8o28Q5+jFABIRBAVRuo+iO7ywn2AgK9KuM2ciQg9IEWatUKQM0tUMhBC70V6EwLY
         Nx2G+C69xFXOWBsfN+5LHZ/y1oLr4d/Qdo63uOCl0o+a1Q1T2vuD+mcc/tB0EoNVP//u
         UMAf2YuHCt284+NTGYyFDdMltA+gGAPUodQpGas0bQivkOVLqrXtS//zGdIsFfBziZR5
         dr+hpoHzk+qTKtPvPqMniF94tNqBuKqDoZT++2kiQL+BMNTFaq1uoZFmLx7xiSfeFnHQ
         4YMiF3NPyHPMdDZpJPlCRmCYo7oYkXAbrDaMvCGiKJEOB2mzPQROA6h75ZTB/q8TphhT
         /n/Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=d/lx=a6=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=d/lX=A6=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:date:message-id:in-reply-to:references
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=sbKPdFAh+WJ7X2B1SMJwu5W3fH/ttGukUyBW1jm8dp0=;
        b=F++iWl8rp9HV0b0+caHQ2Tj7WNQzq0cLCbU6tRoA89Abmp7bHFtgCNLtmvnZBNQH2J
         bGrUrxMPxqRBnO6gpH1TWgqLzWGX8RlDbuuc1m/EROVZqt2azv6F0zMjaTb8LGy9TXrS
         /LATrOi8FWHzrwXiC041sjoG0wf2pDdhk3Uw7agpulrjuyc0eZr9kgfi8EGkQOaDVK6a
         d8vXwTXqbYGnODzx5d6JSXGO2aHOES5h9o1Zdd4lzIvt7FOvcu2xbciFHXqgTt2SzHtD
         YMYcWroALPubjsytkVoQLqiNaSwwRExwDKN3W6Y5YgV6qBIILJT3XbTzz+Zj2hkNwT4a
         SilQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :in-reply-to:references:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=sbKPdFAh+WJ7X2B1SMJwu5W3fH/ttGukUyBW1jm8dp0=;
        b=k9ltVCmm588Skbc7RXk//EKojuYLFOoooMhuKpvykXSK68un1C3H6fRhP27crd/wbZ
         /IayQhbU6tlKxRHYMtJeP8WxqhwBsj1tCUCfGJ5E8xLDIdtDBmkMuouxT64nGCcjfLsm
         dyRxnxpRqc9uCcCP/Kntsms0IqXTIZ1PLSq3Yce9nsc87PIB+xbUgaQ/+4/QFVCgN/oy
         lGth/VmXHvab9qqQvhL4wOe1IAalDfNX5ai2sxfm4bcyxSS20FGMJbweheo7BNQxI/Bs
         uQixKZmxwNSdyMWnVp2lfS5XcTUw2btf59JF69/c3GSy7Awb/MaskZOs0Yd3IfQ76OIU
         eFjg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533tanPYtodnGNNEJp/SmKIUK4JV4wT83IX5+rFsLutqIWfwT5tI
	iNJBzXEYWuUOjom6WzVfGrw=
X-Google-Smtp-Source: ABdhPJzimpmWLLnHQ2gIDHeZvEk/Zk5zn8UzsMVFfzuuK6+xaM7c8cGVwvVnUKn8MQyq5xK2Ueb2uQ==
X-Received: by 2002:a17:902:8349:: with SMTP id z9mr12178100pln.46.1595156511225;
        Sun, 19 Jul 2020 04:01:51 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:9798:: with SMTP id o24ls3584479pfp.0.gmail; Sun, 19 Jul
 2020 04:01:50 -0700 (PDT)
X-Received: by 2002:a65:6089:: with SMTP id t9mr15458353pgu.236.1595156510754;
        Sun, 19 Jul 2020 04:01:50 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1595156510; cv=none;
        d=google.com; s=arc-20160816;
        b=TE2cfhFDsTQW2EQinb/0fqbnZPPaPTvVcA5PzZyPkz2+Z343pj7U3x2vlfOGv5O+WE
         ljEEbDbiQCIEu3vY/IFuNg59fPE5qniv/i51X9GptWfpLvAOWadlhCRvkkVbh9LgUrnh
         T97Q0dX9zpWsci1vzUmNLlqMs8Ha3wIZ48Voi4xb6zd0F69iZItzasv2vI5mr6tq0sYp
         6CCRKIQ5d9q1fqYxtpJ/XGEWzSL8qc3zZmz29b+TlTAXM9LOHyb8JXotARy+bgAMP7Y0
         +YnEfppvsz2jhk+75jW2ypwXvgjuBmcbDWLeCOfXM6oPE4a7spm5BR1ak/Khjl0UGE3t
         mMpw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from;
        bh=AOZkERnU8eKxsW0BpUZWjsFkGVPia0S36RGDeEcgSm4=;
        b=an5XpvlKMl8BEIYxlVb5eJcVoi0MIx8YEvDx+HpJSIXIHq9HxYCESDHbVuVPuKrjkz
         jlacTjhzrEEKAdYpca3m0o/Z+wM6TMAVlu3hO+3ZEDQUjvI1fAiKtzgiignlVdWvw/qV
         KDrILuE5fl+ucTSN6hDCTGzjJzWNyXseJJwhwGTWPAzA+4dnnwp9R1H91l+6iy7l7SzB
         Y9b08Al9TkpjuLH5OdvDdKdkvnj92gNzm2uD8djk01Pp3CalfDKSanPJMm9Q2asA8mEE
         4Y1NLWTuc/YhrrfIv+jKVdZTPaxmvYA289izN2k9k5hjI3qEXBLVtM1U8e5f8+lw9WoD
         W+Qg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=d/lx=a6=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=d/lX=A6=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id cp21si356764pjb.3.2020.07.19.04.01.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sun, 19 Jul 2020 04:01:50 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=d/lx=a6=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 208461] FAULT_INJECTION: fail copy_to/from_user
Date: Sun, 19 Jul 2020 11:01:50 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: changed
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Memory Management
X-Bugzilla-Component: Sanitizers
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: normal
X-Bugzilla-Who: dvyukov@google.com
X-Bugzilla-Status: NEW
X-Bugzilla-Resolution: 
X-Bugzilla-Priority: P1
X-Bugzilla-Assigned-To: mm_sanitizers@kernel-bugs.kernel.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: 
Message-ID: <bug-208461-199747-QnOa6biQk6@https.bugzilla.kernel.org/>
In-Reply-To: <bug-208461-199747@https.bugzilla.kernel.org/>
References: <bug-208461-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@bugzilla.kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of srs0=d/lx=a6=bugzilla.kernel.org=bugzilla-daemon@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=d/lX=A6=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
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

https://bugzilla.kernel.org/show_bug.cgi?id=208461

--- Comment #2 from Dmitry Vyukov (dvyukov@google.com) ---
Also see related:
FAULT_INJECTION: fail LSM hooks
https://bugzilla.kernel.org/show_bug.cgi?id=208607

-- 
You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-208461-199747-QnOa6biQk6%40https.bugzilla.kernel.org/.
