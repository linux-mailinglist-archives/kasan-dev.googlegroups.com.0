Return-Path: <kasan-dev+bncBAABBVU2SO4AMGQEA6GZYIA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103d.google.com (mail-pj1-x103d.google.com [IPv6:2607:f8b0:4864:20::103d])
	by mail.lfdr.de (Postfix) with ESMTPS id 52AFA993E9F
	for <lists+kasan-dev@lfdr.de>; Tue,  8 Oct 2024 08:12:40 +0200 (CEST)
Received: by mail-pj1-x103d.google.com with SMTP id 98e67ed59e1d1-2e2898549e0sf225240a91.0
        for <lists+kasan-dev@lfdr.de>; Mon, 07 Oct 2024 23:12:40 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1728367958; cv=pass;
        d=google.com; s=arc-20240605;
        b=Qdkf4fjIe/xU6sDmovwO5gqrWtAh+tzl1HXxKQrZtGWMKYGQY2UbOE5AnblVV/KJpt
         ZVyonwyZ/3JBTjSsuvWq+PxXUOhRoujQzpvqeaAw/kyJjuV2hSfVSPq9iD7PIJw4cdUb
         nuVCuzhoI6nnv+kPr70u7lHZO69cUzsFnvVzMbmtdlMY/ry6PUaI8lI8//v+ZFe8pcJt
         YeTjchOQBpNV4BeN2+zw9nM6ADUL3sv6TDNCArL3OPl38h0hwOwSA+LH9ryS0dA0xLLH
         OX6oVCeG8dscRpk15uvnCyOW0esk/M7XzFNkm7Kpz0PCL2+wWcz1jJwAapIjyhrQPPgo
         sFag==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:dkim-signature;
        bh=nQ0ZsMedxBJMcMM4L5zW2HJMuEz3vaGTpu545tQSsNE=;
        fh=73eGActRxEiOx9ZXPjK49GnXmGzIQJCu0YFV/2yA3MQ=;
        b=N4lMxpaPXf2hkTy5MSNkrTF3zVLOayEgWIqMibJMT3o7KHz932eq8ulFvg+7iJc5lI
         m9RhZ17tzSwjBrSwlnFjGb0D310EJGTNjpLwrtfcctVba+2BNGqC1D3y5wN1ELIB/Fgk
         B2jJgpz8DxwcvNiWsO29PS3Sktk82H2rL+BN9XGJXbY4xyUCcPeuu1ImPeMSCQrQmmwf
         mB9v4bEvIERrP+C2RMtilTvwX57C8X110xtm8LntbktC49Nk8s5zQVCSfM84Uex+jcwv
         kHMu2wns78cfuEYJGjH/unVVamoDsMDMIYR76ylw+ed98EOLxIcUt4fjd+0Wo8TeZCz7
         IN5A==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=JOV0nkh6;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1728367958; x=1728972758; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:from:to:cc:subject:date:message-id:reply-to;
        bh=nQ0ZsMedxBJMcMM4L5zW2HJMuEz3vaGTpu545tQSsNE=;
        b=vc5QpjcXBI5ba2mMmLMCJuo/qNpKRpVcojs+g4B8KQcE5/L6xKFUWzV/wORmvnoTPn
         qjErcaEo81XnBq5V8DRcqtPrvhN4rngxQ+lYJQP5lsPOjj4/glSpLnmPrC+jKgTa6l4P
         dAbjqbYaPPfAf/rMyMLa4x1D6rhbjjemEtmhMskdBP088tfOhR8BUJS+kkDn+fhCbDr8
         vuN6ao31J0EQ6s9HGAiBHpAIx7rC2Gsc1j38dY2LKM75qAYPiPrk4VDGIZr3S3dkPDdk
         cKwHGmyv/4csocwNtFx+ozqoAx1LrXYBaXvbQ/KkUl1ote0PvxMkELiL1oeSsd1OwWBI
         xFjw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1728367958; x=1728972758;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=nQ0ZsMedxBJMcMM4L5zW2HJMuEz3vaGTpu545tQSsNE=;
        b=T5jsQkUD9wkVh0bOfmKjyA5A3Yjcalw0c//dkhcHwcpw+G9O25iJR+L/4T1foeaCA/
         GBdL9RNYibXbmlzo5Zr3QrgmmuCui7v4nmNr1EBdghy8yPNbDuPVLqzwntlzCj6SeUJR
         U3Eyr6sPuPIMaRbc+NoJ7pYf+m/5GBNm6vulSMkWVfzGqoyCnDRWkFJdXUNRwZk1OgrQ
         dVV9LWBG76aoLqSqzv/PMixgDKqXbZiXml7PqzVqLRkiLC3yAL1C3GrSP0+nTxLQ8KMn
         3sc+YMvTlHPleKggcHw0RAdBxHv1QIADhwQNpMZp3lo9vl0wQrOGxnmLqSadDXWe9rUf
         D8Lw==
X-Forwarded-Encrypted: i=2; AJvYcCVvhTfmj5o1jdx4FBt6FJ//hLupd+EtphQZxw7/sz4y7B4lq8MxfFPyEYOcQeYVtma8zUzQlA==@lfdr.de
X-Gm-Message-State: AOJu0YwjktGMFZnpmXM6RPcDs1cH0Y9AYDTGKbiwfj6jfUW34HnUn/Oe
	2O1NMnxr8ospUurb1aNac5O+YdSX6ZqbvlE/mAAFHGDBecMif7Zg
X-Google-Smtp-Source: AGHT+IEh7Tx3rQyIoW5jGFrhG3SZIS5mkQ2eE2d6UTgL0xDQ3++fgc2TTFCSXj8WRShZgPgsyiFdMw==
X-Received: by 2002:a17:90b:3c87:b0:2da:905a:d893 with SMTP id 98e67ed59e1d1-2e1e636c83dmr17267782a91.31.1728367958446;
        Mon, 07 Oct 2024 23:12:38 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:4b0e:b0:2e2:865b:5559 with SMTP id
 98e67ed59e1d1-2e2865b5684ls261604a91.0.-pod-prod-07-us; Mon, 07 Oct 2024
 23:12:37 -0700 (PDT)
X-Received: by 2002:a05:6a20:6f07:b0:1d0:45c2:8140 with SMTP id adf61e73a8af0-1d6dfa33c28mr20431396637.18.1728367957196;
        Mon, 07 Oct 2024 23:12:37 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1728367957; cv=none;
        d=google.com; s=arc-20240605;
        b=RuFGsnMkEjN3F5+WfR/xKCmYQ7UkaSsPWperSZS6FBrVykm+ypv4tnJd5Wlzt0H7XR
         0mYMcSsqBT2VywfBnAFnSaiqvJbvPnEHABkSDffUpFsIxC3qFzwQgbdzu8CwWm/bxHD0
         MMIvhV1K2880+wO8y9/DPUruLMV+ljwcS7+7ZaAPSl1JYRTIB3uWCbgEMdPFlxCh9OMD
         FQ6ZLi+M1iYI9UIVnhttDM/1N6eGijBMGrSaGOAdpnBCIJqaUzzIxOq2en7tANr1sPGK
         tPWPVkbJQu4X5EN5FcGkolawucYb7d1fAONjdqNwrMcq2YS83/2onMV4aQ/EVgD5UadS
         7nmw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from:dkim-signature;
        bh=pkGU8h7+0tMGbk0/gL0OMypU/nqTBTxN4swESrp15N8=;
        fh=uQCsmYQr+KJEcG63Y45gsyDulzJl/B4EdEfpx8XrGGo=;
        b=cO8GiGUEk3Je9vscZ90MMZFB9VFM/M/X8ftxM5bHv333/F+A7VhHCyUaV3GifcmGYS
         LAZAcTsCKL4Dijzse6HpzoDF8jw8Nxu6TMZj4fdXeL6fdfyI4q1Y3NG5gXPLz/vphnQy
         fEGHz73cAbrKZZokUYpdgTTTDGTOo5WxW13jnfuoxgGOhkPfuqmUWiqTVK6TnEIWq+pd
         IgBL+XQt/ovdrTI9gtjsNZ7qyHfJ6Qve9zThA6AVKe7xMA7s8CrZejIvm0uRDPP5dG9i
         SOdK6xepU5byLjX2xr52byYRRl8RE7bIGNvjN2LS4Puhfa8ZJ85hC6uqrVyD5uoMIgTW
         OK7Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=JOV0nkh6;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id 41be03b00d2f7-7e9f6e75541si330898a12.5.2024.10.07.23.12.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 07 Oct 2024 23:12:37 -0700 (PDT)
Received-SPF: pass (google.com: domain of bugzilla-daemon@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id 50FDD5C5E3A
	for <kasan-dev@googlegroups.com>; Tue,  8 Oct 2024 06:12:32 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id 45362C4CECC
	for <kasan-dev@googlegroups.com>; Tue,  8 Oct 2024 06:12:36 +0000 (UTC)
Received: by aws-us-west-2-korg-bugzilla-1.web.codeaurora.org (Postfix, from userid 48)
	id 3D6D9C53BC1; Tue,  8 Oct 2024 06:12:36 +0000 (UTC)
From: bugzilla-daemon via kasan-dev <kasan-dev@googlegroups.com>
To: kasan-dev@googlegroups.com
Subject: [Bug 210505] KASAN: handle copy_from/to_kernel_nofault
Date: Tue, 08 Oct 2024 06:12:35 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: changed
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Memory Management
X-Bugzilla-Component: Sanitizers
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: normal
X-Bugzilla-Who: snovitoll@gmail.com
X-Bugzilla-Status: NEW
X-Bugzilla-Resolution: 
X-Bugzilla-Priority: P1
X-Bugzilla-Assigned-To: mm_sanitizers@kernel-bugs.kernel.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: 
Message-ID: <bug-210505-199747-t484TrClp4@https.bugzilla.kernel.org/>
In-Reply-To: <bug-210505-199747@https.bugzilla.kernel.org/>
References: <bug-210505-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=JOV0nkh6;       spf=pass
 (google.com: domain of bugzilla-daemon@kernel.org designates 139.178.84.217
 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
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

--- Comment #7 from Sabyrzhan Tasbolatov (snovitoll@gmail.com) ---
PATCH with Marco's comments has been merged to -mm tree
as the squashed commit dropping prev. patches.

https://lore.kernel.org/all/20241005164813.2475778-2-snovitoll@gmail.com/T/#m314b7f19ded0915d925cff29361291cd5c479617

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-210505-199747-t484TrClp4%40https.bugzilla.kernel.org/.
