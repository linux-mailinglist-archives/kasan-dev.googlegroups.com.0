Return-Path: <kasan-dev+bncBAABBMEFWW3QMGQEBOKUZGQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3d.google.com (mail-yb1-xb3d.google.com [IPv6:2607:f8b0:4864:20::b3d])
	by mail.lfdr.de (Postfix) with ESMTPS id DFBFD97D3C6
	for <lists+kasan-dev@lfdr.de>; Fri, 20 Sep 2024 11:38:57 +0200 (CEST)
Received: by mail-yb1-xb3d.google.com with SMTP id 3f1490d57ef6-e1a8de19944sf3229809276.1
        for <lists+kasan-dev@lfdr.de>; Fri, 20 Sep 2024 02:38:57 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1726825137; cv=pass;
        d=google.com; s=arc-20240605;
        b=TMr4MTPqDJ8vH95LeKYL1ROIyF8vyjC0QjF1z12p0A8XM0zbii6nnY1gksR7PN9vhx
         YaCWve22eO4/GBprRPuosaNbrlWsodD5fCMtITyunW/jF6ulm+VG0pr0iufaP71NlzJi
         sSidPtKeCK3gm+IzW82WgjGqh2LLlCPg7GRF9ZhvEA7Vq8hIPKMg4cpqjGSsCsTpnn9K
         XMwfztIDT5e/k5oiqYcgaAt/vi5T8ChYSKAa4USvX68VCTY2Orfcweq3AIpY3cogSqSK
         Ie/JgmO5UWX7qbqs+dRim5+EtNcA8IyTe7wQ0KdegFpJ/egvrtK64T8luHIFAjYvLYhK
         /CcQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:dkim-signature;
        bh=3iy70JVIjuec6EAgSX3UDzw+vBlX0MVP6gDnh5MBYhw=;
        fh=z5fRmFP88aqBeI839vf5vLqNJ8rMLB55EN3IJOmyGCM=;
        b=SpngbvOe1i+scaAaCoz1vuMC559jINHRriG9crEB8acKcUVc3X+47i/N4bmb6T3ecC
         k+MGNLiKPfdkh8rT/JO86DHYrgxNwVMycQFbV6atmZ/VqP3Kq9jCul0Ag8btdiN0MWP3
         zj//pwdHbAuDS4CE7K+QiwKvfrJ4Epw/AhkBmoPBfitxWKYk2UoUBhBH9SeHco2cX2pW
         aUJS5ztPnzUtqJ2LYEi/IjRWeR/yeW38TgzAZxm0OJaQETvIIUFudw5u011Om9cUqoje
         Mgg+KM7kbbdxeULZnKeRjnkVxAPNE1bBKIFwAjxJvvyPoiNmaiTrmoVQ3nhUeheKfRmW
         qeyg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=QzunUkmV;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 147.75.193.91 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1726825137; x=1727429937; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:from:to:cc:subject:date:message-id:reply-to;
        bh=3iy70JVIjuec6EAgSX3UDzw+vBlX0MVP6gDnh5MBYhw=;
        b=Nh2V//MYdhFaRwwtDRP0q3sa+G5MEC/eLTE3Oe6KBdhMPWS+MPH71FElzco42n39jT
         H/GzLvapslEkb5XqbXvS0oBJuFza3nEYuZDNOaMljIFRO0a20I70spJQm2aIlcgC70xN
         EytnfGJACyDJmSVpPtrEcDqmovBl184ome+XOTAyxrUjdtBh/bKkwHiRlUnH6RyIFJNZ
         IkcgXsF8+ZTR15CLse7zEynH+iunoHXXSYmrqHv3S1UtKn7rtiGq5Iwn6HgdgYkStcZd
         bDBUiTDc1t9YMOkmzmz4ucpeZrvYG8dNsODdGQA0e7Gt0rREC3pY70sjAsamIGEQ3M5d
         mzYg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1726825137; x=1727429937;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=3iy70JVIjuec6EAgSX3UDzw+vBlX0MVP6gDnh5MBYhw=;
        b=U12OjAyEbPf9b2LSeudcuSh9f6NGCg4mVmh+9/K5wq442eNZXFwQZleP8JrTdEGaJ8
         rLQOFkp9ZGxiGkwAx+Jw1cuSg4MI5F05YtzrsaVEZ7ymBEBPo/LK3QZ6932a4cVosa4j
         eL70EneRqMBLwKRhYee3/UZQpcXZH6KBNyuLzwS67CQbd8KFGmC//mEfzcCpfws18uep
         G3G67jQX1ISC8ZBcPnMkxSYvX5hOP5UT5olxxo4sT6y7hQL+SO2pWX1eltUUjsBvrAlz
         /lOYMaedvL+JKYXlg/1fNu3ABBG0ZDrctjlwntVDovQaFM8rweNIl1u/8bW9sZMzMgr6
         L0zw==
X-Forwarded-Encrypted: i=2; AJvYcCU9bybx2KLheVyIfOJtSKBBZ78jP4MR3zhIYEjAP0f38Hx7bTLpZe0TY7wRXiCv5KO8f5/WKg==@lfdr.de
X-Gm-Message-State: AOJu0Ywxf78E1UU97hv2MX23boYS03sDWd1nZxgHpa3ANKBnUhqpeCCi
	K+jQEAW0uPSP9N38QpsH0zdl6c40LkcQt2oqsVPNci3k2BnIvJFk
X-Google-Smtp-Source: AGHT+IFQEvokXAdnD6i/1tddXh6vVzsMJKJt9Vo418RoYABOyWLzr1ZK2ezhH6MDpzOcqA9M+ogJ9A==
X-Received: by 2002:a05:6902:2004:b0:e0e:4923:55f4 with SMTP id 3f1490d57ef6-e2250c29079mr1920970276.5.1726825136601;
        Fri, 20 Sep 2024 02:38:56 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6902:1883:b0:e1d:d1b:d4fb with SMTP id
 3f1490d57ef6-e2027e91959ls203584276.2.-pod-prod-04-us; Fri, 20 Sep 2024
 02:38:56 -0700 (PDT)
X-Received: by 2002:a05:690c:3610:b0:699:7b60:d349 with SMTP id 00721157ae682-6dfeed2dcc2mr23415267b3.11.1726825135935;
        Fri, 20 Sep 2024 02:38:55 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1726825135; cv=none;
        d=google.com; s=arc-20240605;
        b=FTusS5AxNyHMSulNp+Ge/1tO+Jun53PcJeN8VXbPtCVe1iA7QIP1c/93AZ1rgRTg9v
         PLC094EPArNZ2k45Ed7+OJF5lrdjRwlyOlQFlpZpEHmbSqnSQmomF7urVpk+m09NHukw
         JUiYAaSGG3kfkHo7tdqXQ+Zi0F8G6bJGvWeRzYGcyWzrIUyVa1Z3mF6bVSgqZDtjQRcG
         dxMGb01Pehb8UcIKJaIvyzrbxs6otg/LyJX1zY6WqCxxclj5BEaVTwEyYuOPOvThbJaY
         cWCjZZTWI+gUhlE/kmBoyT8mLs01wt8xfmP4AZRN+97coqCOt4sGDofqkfEe+K9j1Xzq
         w+xQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from:dkim-signature;
        bh=Sg+XbH/tdHs+sIuqiF5Z5UIVhjtfCye65UqzbLkK6u8=;
        fh=uQCsmYQr+KJEcG63Y45gsyDulzJl/B4EdEfpx8XrGGo=;
        b=gvX3o1PHDR4Fs1oeCia6iQJd6KgDGzLK6U79MqYTmiPgWtsxJKRJeGTMWr8OMy+LIZ
         l7rDiWbzhnxLXhTfXfa8tpjUwpHbs/FNFxU2/A167rgVm4UC2s6x1d7baDTHCoHvA1Y/
         lQjUFCKp8lnmRFITpLRD6GX08tI9ct7cYquDPXmKlG5/4MHH4+ALxKz1x2hu6Lq66Zap
         3RhGYrhmVtjM6XvKvhBWvjh+kFc/5A0iuRCwhJG1XnXUxFXWHzSk+W2fW0Gs96glRaI0
         MLerUA1YfcDtct+dxtcTJgJ/Iozg2TwD5NYDf90KSVD4mWDLmf/oQyUzpYLAfkibOsrN
         Bwqw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=QzunUkmV;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 147.75.193.91 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from nyc.source.kernel.org (nyc.source.kernel.org. [147.75.193.91])
        by gmr-mx.google.com with ESMTPS id 00721157ae682-6dbe2f3c0b5si8048717b3.4.2024.09.20.02.38.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 20 Sep 2024 02:38:55 -0700 (PDT)
Received-SPF: pass (google.com: domain of bugzilla-daemon@kernel.org designates 147.75.193.91 as permitted sender) client-ip=147.75.193.91;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by nyc.source.kernel.org (Postfix) with ESMTP id 7C703A407AE
	for <kasan-dev@googlegroups.com>; Fri, 20 Sep 2024 09:38:47 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id 28DFEC4CEC3
	for <kasan-dev@googlegroups.com>; Fri, 20 Sep 2024 09:38:55 +0000 (UTC)
Received: by aws-us-west-2-korg-bugzilla-1.web.codeaurora.org (Postfix, from userid 48)
	id 1DE7EC53BC3; Fri, 20 Sep 2024 09:38:55 +0000 (UTC)
From: bugzilla-daemon via kasan-dev <kasan-dev@googlegroups.com>
To: kasan-dev@googlegroups.com
Subject: [Bug 206285] KASAN: instrument pv_queued_spin_unlock
Date: Fri, 20 Sep 2024 09:38:54 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: changed
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Memory Management
X-Bugzilla-Component: Sanitizers
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: enhancement
X-Bugzilla-Who: snovitoll@gmail.com
X-Bugzilla-Status: NEW
X-Bugzilla-Resolution: 
X-Bugzilla-Priority: P1
X-Bugzilla-Assigned-To: mm_sanitizers@kernel-bugs.kernel.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: cc
Message-ID: <bug-206285-199747-15d0jNMmmr@https.bugzilla.kernel.org/>
In-Reply-To: <bug-206285-199747@https.bugzilla.kernel.org/>
References: <bug-206285-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=QzunUkmV;       spf=pass
 (google.com: domain of bugzilla-daemon@kernel.org designates 147.75.193.91 as
 permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: bugzilla-daemon@kernel.org
Reply-To: bugzilla-daemon@kernel.org
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

https://bugzilla.kernel.org/show_bug.cgi?id=206285

Sabyrzhan Tasbolatov (snovitoll@gmail.com) changed:

           What    |Removed                     |Added
----------------------------------------------------------------------------
                 CC|                            |snovitoll@gmail.com

--- Comment #3 from Sabyrzhan Tasbolatov (snovitoll@gmail.com) ---
I've checked pv_queued_spin_unlock in v6.11-rc7, AFAIU,
the missing check is `cmpxchg` instruction.

https://elixir.bootlin.com/linux/v6.11-rc7/source/arch/x86/include/asm/qspinlock_paravirt.h#L45

, which, I believe, can be replaced with  atomic, instrumented `try_cmpxchg`:

https://elixir.bootlin.com/linux/v6.11-rc7/source/include/linux/atomic/atomic-instrumented.h#L4873

I'll research if I can reproduce it via kunit test to verify.
If there is a 4-year old tweet from grsecurity,
that would be helpful :)

Thanks

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-206285-199747-15d0jNMmmr%40https.bugzilla.kernel.org/.
