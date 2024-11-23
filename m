Return-Path: <kasan-dev+bncBAABB4H2RC5AMGQEDHTUGVY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb37.google.com (mail-yb1-xb37.google.com [IPv6:2607:f8b0:4864:20::b37])
	by mail.lfdr.de (Postfix) with ESMTPS id 676FB9D6B7A
	for <lists+kasan-dev@lfdr.de>; Sat, 23 Nov 2024 21:39:14 +0100 (CET)
Received: by mail-yb1-xb37.google.com with SMTP id 3f1490d57ef6-e388f173db4sf6142538276.3
        for <lists+kasan-dev@lfdr.de>; Sat, 23 Nov 2024 12:39:14 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1732394353; cv=pass;
        d=google.com; s=arc-20240605;
        b=YAJKxoVx1qGPQfVVuFryFD0aFbTzRaj2O8QlMw15fMZX749BD51s987wLUGHwY9Id6
         pYMbbHt4dg3RzFddwo8qxGXiw/lGoL7ZbkEvNpCrFZsIjbKhE/1wBM3fPXYNa/PLWCwM
         iExpXRJh82j2B11ogurFwwezODCzbmqdC3ySdt0CHWJkK+8HzInYNYQ/jgJxaAdR3Djq
         rGEF6CewtBKlF7mQgDo7Ez7o9rS/j4sSLRss0I+mi7VWeBZdMgp+5EMLy9lg5JpmFbRz
         jfB8iRJp2nRiDqeGmzWdxmm3ZISnl1G/hSFwXxr/Yupc3ERCsnY3bAxXIUXXE11PogfY
         V0Dg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:dkim-signature;
        bh=oi1dmlr2Ybq7yOrWiiQd3FE7T76bfjbHh+iKeXuFkKk=;
        fh=VX4C/cB7WBNSSLHqicaNolnWtVB69C+Y12g91ZbVC/U=;
        b=YyiM9XlCXGo6nYEyeHFD8//Fxd0rlYqNvPij/QxGZeWxCf3rnS71F7uP/Ad+K0PKa6
         6IO76UPyMPq7HY0g0stB8ros2VAgF8rRTRyenVtcDC17os+n2bdoz8PTMU4X3h8ZG2xa
         jFiWeqiaa0iFUDlpR+Pa0H6E7VsyZ1g1voldeUepZ+tm2DYBLm+B/y4NGgJS56QeQvig
         iqTEswJ2Hhz3KoQU2ZSoswVhGyVec02987b8PUcrRKbYMWX3nnsKL2m7ULbQHXlROLQx
         odQu+Z3zeg9cFBdf0vt+NUWOwP7bnVlyj1U6+F0MF8CXwgNb4bkCCCOoVzWkc0UQ4fHA
         z1xw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=uKX8fSLm;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:45d1:ec00::3 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1732394353; x=1732999153; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:from:to:cc:subject:date:message-id:reply-to;
        bh=oi1dmlr2Ybq7yOrWiiQd3FE7T76bfjbHh+iKeXuFkKk=;
        b=niVOEp2uFLurWPQvjamDqBu+aj394IiZwIvGmD5dhbh2U2C60O+NPzEbLAh0SOYQAi
         +rSJEVUFvetZ3uiI0fUblAvhX8/rd0UtZOOmS7w4joNwcFlx/SuEqJBGSOsOV5S4CWjw
         gotVBRrO14lsttcnc5spv1x9iOu86Z3VQaNmS+sQfbrHfj+O/8WtBAAA05ObUQ85IbAR
         XiQafvG/G4JlKOKbkuJD0F1jZeC+YHl/cisFiCGUZjQ76Zh7lzTKK5iD7+wyFWPXMo7A
         24WmEM5A0NkdNDRMQIIqKA3CVFkpHGolCj5WiC44qiPxsmV5sU8STiLejrsjU7DXXYf3
         rvVg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1732394353; x=1732999153;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=oi1dmlr2Ybq7yOrWiiQd3FE7T76bfjbHh+iKeXuFkKk=;
        b=MSRIP2r2LDTEQkJMnE6dwJ+NvEnk0fktP4SWIDt7HwR0yiCFOlTxzlG6iytzHNc6Vd
         vxOC1hL3edcy0slhDCrudlJerc82sOZ7s8xiYxwEuKDry58sopEtu3MuMCuF/1324U1r
         Lt2sC/pH90PwYlRPS7nAkh/IREPTXExMP9pwDMPYAUvcRYP4efpPQj3qDqJp6JJ7nwIL
         6wN/L8qwDXZBtKSj5ywIfcdvQDW2RceuopGX4ztNxSjizKF37vvVBBUmNMufx0GcxVqy
         t4tD78saN/l9n7hbedUmkY74dvieqUZdwNu6nJqOq1DV4nrkCXTuXWKPNxnPlfAVb5dV
         Dt3g==
X-Forwarded-Encrypted: i=2; AJvYcCX0P4DmOcbqrLQnxB71CAWVwH+PoSeKtdbnoHIQhcGgzsnhH8QJqqPTPNYhC4KqIlL/ydyCeg==@lfdr.de
X-Gm-Message-State: AOJu0YzySeggUoKgpzNUCB4XNjvJS3GXaznRR9Nv8gpTHxIh8Sr3Au+H
	EJ687V70K4MhNGk2yUrvIs2UnFmUL8RJuoAHEcJA2cNxYyyq+wHh
X-Google-Smtp-Source: AGHT+IFccoiLwhaAXlUX3wAwvLBn6ZcRcKCk4Tsk9Gj0d4CdH5cw7l8tw9u8DOq3mTUd4SWO89x1CQ==
X-Received: by 2002:a05:6902:72e:b0:e35:d8b1:571e with SMTP id 3f1490d57ef6-e38f8b0a979mr6625059276.10.1732394353052;
        Sat, 23 Nov 2024 12:39:13 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:7155:0:b0:e30:e1d9:fe2c with SMTP id 3f1490d57ef6-e38e197fffdls2247281276.1.-pod-prod-03-us;
 Sat, 23 Nov 2024 12:39:12 -0800 (PST)
X-Received: by 2002:a05:690c:998a:b0:6e5:a431:af41 with SMTP id 00721157ae682-6eee0a4a7d0mr83362967b3.38.1732394352305;
        Sat, 23 Nov 2024 12:39:12 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1732394352; cv=none;
        d=google.com; s=arc-20240605;
        b=axFdnSSA1aWWWemlLaZObgLgqcd4iJ7nAlbit0sfKrhIjDsn0Hyn/v+gHHkk/3tzu4
         C6NfCRaDzTvBorFDctDcK3/ZCigwsYOsscO3IJrcuk3maUmYKynp8uBESKE1FYyuM+lP
         /w5p1GMg3vu30Qv87VrXzhoCoUkTzvcFEKu/q73n4Iw/ZhFUESQAdtTLwoooVEPCEPgv
         KXXgqUu8G7+1wJIISXH7kajZJJfV1RJIG4GzGfQ3KtIPJUz5veG7s4v9Sbl+5rCzlZeX
         lUC/j5g1pUWMQYPxUthDIpinMQIhi6YCl20ebhs7LSDlxjTEQbg4frhh/bFyBixVLs3x
         C4hg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from:dkim-signature;
        bh=GCpl/ATn3by2tFxVC+s4Wy2rlXL9bC02PtFRYaMRVE0=;
        fh=uQCsmYQr+KJEcG63Y45gsyDulzJl/B4EdEfpx8XrGGo=;
        b=NDFQzrc+mWIaA+pveqXf6JUyRgAclWY4qmxwkKLPXuiCWYOJZgrn+bXjfpXl36SaW4
         OV5BscPbk7f3aBO0GPl98nqXB8BAckhySWk1CKkd4ffurBqKu1CM4i0nsrCC9EKaMom4
         mDfDVjdcyyt0Hkl03qAijBhIW8N5mDI0o8r//SMyAd+Bxb0Ign0aOlwXLEMAWEnmR8NI
         J6n/2Se+ZIG1gI5NDyn6PbL4l0oZsPPDjii8r90XH9WR6wl25JLIisDli7qGFHq6q0EB
         NZjoaSykqQMhdVADeLryyTAWSJt4vuhUp1ecqRA1N0PZQHitIQ9N7lSME6sJpWe1HCCp
         uEjQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=uKX8fSLm;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:45d1:ec00::3 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from nyc.source.kernel.org (nyc.source.kernel.org. [2604:1380:45d1:ec00::3])
        by gmr-mx.google.com with ESMTPS id 00721157ae682-6eedfc6e0f1si2676667b3.0.2024.11.23.12.39.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sat, 23 Nov 2024 12:39:12 -0800 (PST)
Received-SPF: pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:45d1:ec00::3 as permitted sender) client-ip=2604:1380:45d1:ec00::3;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by nyc.source.kernel.org (Postfix) with ESMTP id B0D6CA4070B
	for <kasan-dev@googlegroups.com>; Sat, 23 Nov 2024 20:37:18 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id 7D77AC4CED2
	for <kasan-dev@googlegroups.com>; Sat, 23 Nov 2024 20:39:11 +0000 (UTC)
Received: by aws-us-west-2-korg-bugzilla-1.web.codeaurora.org (Postfix, from userid 48)
	id 6EFE8C53BC2; Sat, 23 Nov 2024 20:39:11 +0000 (UTC)
From: bugzilla-daemon via kasan-dev <kasan-dev@googlegroups.com>
To: kasan-dev@googlegroups.com
Subject: [Bug 210505] KASAN: handle copy_from/to_kernel_nofault
Date: Sat, 23 Nov 2024 20:39:11 +0000
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
Message-ID: <bug-210505-199747-Cy4i048LVF@https.bugzilla.kernel.org/>
In-Reply-To: <bug-210505-199747@https.bugzilla.kernel.org/>
References: <bug-210505-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=uKX8fSLm;       spf=pass
 (google.com: domain of bugzilla-daemon@kernel.org designates
 2604:1380:45d1:ec00::3 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
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

https://bugzilla.kernel.org/show_bug.cgi?id=210505

--- Comment #9 from Andrey Konovalov (andreyknvl@gmail.com) ---
Filed [1] to track the issue with HW_TAGS.

[1] https://bugzilla.kernel.org/show_bug.cgi?id=219523

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/bug-210505-199747-Cy4i048LVF%40https.bugzilla.kernel.org/.
