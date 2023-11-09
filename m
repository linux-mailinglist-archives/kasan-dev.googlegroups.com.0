Return-Path: <kasan-dev+bncBAABBZWIWOVAMGQEUIZU3HI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3e.google.com (mail-qv1-xf3e.google.com [IPv6:2607:f8b0:4864:20::f3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 778227E6BAF
	for <lists+kasan-dev@lfdr.de>; Thu,  9 Nov 2023 14:53:44 +0100 (CET)
Received: by mail-qv1-xf3e.google.com with SMTP id 6a1803df08f44-6757f3d7911sf11356416d6.1
        for <lists+kasan-dev@lfdr.de>; Thu, 09 Nov 2023 05:53:44 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1699538023; cv=pass;
        d=google.com; s=arc-20160816;
        b=UwFXuSR1FUSPFs0UJBEpkmU/7k2+xlcSVn+gDgDJsK5sfktuik2lDGB4F0RyV/3viw
         vJber8X/XJBYKKPkHMabDzt833psyQbY/XMSuZvqNqiaRVdHHgPwaiE7vbEnhmz8R7ho
         L1nmPoMPghPkhgnqaeIOvWeB9wjRlslRE8n9LFSNkyrocxRawckAf+D41Zg0vU8tr5jS
         MKsEW421QIJmodNGYorErrXDHD08XcXKtbWn7awVlVD5Aw7CUaZaxkWPQhnL3oX8c22m
         25xMk0sh/VCNM0tSaAAWSAZvx/AlIcqkn/Q7myb3vCuLrT/kZBLoSPGAmffoP+8XuBIC
         IY7A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :content-transfer-encoding:references:in-reply-to:message-id:date
         :subject:to:from:sender:dkim-signature;
        bh=Va/Yhkgqd97U0cdzhAS7dPuW0H6iM3ZX8ZvtxvyWyXw=;
        fh=uQCsmYQr+KJEcG63Y45gsyDulzJl/B4EdEfpx8XrGGo=;
        b=JGuOBI4yHg1mD8xGanOl4v/DfBnfJSP+RPwANmuIVjzpwbAnJ4300A3V9qNePRpFux
         djIwJ5C/Vc90/G27dL6s9rZFgE5/8f8xE/V94sb2k2nY7FcmoiWO2jVj9bDoFI5Rq/MW
         L4ArhX9nVvp0UjTp9d+yO3B3FipvBcfWm5sOZmkGMKN+yjrk0H+mqNy4Rmx0+isYsSgV
         tbwDdWdcpI3I71fHKCqolOQNhwB/fzGBmKRpC3Y3tXkMOUDXnpW+OtSc7xf3WIMyyvhn
         VZ2ngYMERvH5pMUMw+ijtfU5c2NIX+atvoGXlw4xzTFDypENkrppAXVr4UcDX5RVBpyR
         vmRQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=GUSROcM3;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1699538023; x=1700142823; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:auto-submitted
         :content-transfer-encoding:references:in-reply-to:message-id:date
         :subject:to:from:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=Va/Yhkgqd97U0cdzhAS7dPuW0H6iM3ZX8ZvtxvyWyXw=;
        b=wkM1em/hos4Yk0AFVflPM0UvFPTd6MLc9jBBBEX2roUdq7mrXGn2L8WITFmeOofqJL
         tCOfVR8jHmXVFKbdNBPZU2btp4zihrj5nxyG5riZMv6arz+2ZmkWo01Sg1g7ntDJF3/U
         SNFomMrNx+exiAFYKaQ7LX45gGM7gZQHpL9qBh/4uEkT98JuxLfYJM+VGZkso9/62hUq
         4biAEVMtE28plHIDoq0th+nulQa2SldTGfba4r5FbJdRjXgPL+ybrBqAU0xw+v1VU6SU
         FsltwwlcAaliK3qUMucXHyOFmy8N5a6vgPmO96o05IA9Rfi2Jt60KZ2RXLT+4LDBxYr0
         su4A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1699538023; x=1700142823;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:content-transfer-encoding:references:in-reply-to
         :message-id:date:subject:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=Va/Yhkgqd97U0cdzhAS7dPuW0H6iM3ZX8ZvtxvyWyXw=;
        b=aULTlY6G8PaLDhy0cROlx0yoJRFjXH9Ws9uHQNrfMzMGuv85XdIHQKhPUtj5E38gxz
         WKYS0DA9bHRP0GDDqjSclA2pFfIziSfZdL4sqCxpqqEORw35xvxr6bP4FAWQ3al+ywR9
         oIXYu8ieKvbGfDECrG9BgbJVed1PDXwJI36WEqBileVjriBZx3sW/Y/t+1QpQr/w8yeJ
         ebzxoBYNXHnURA3dvqkC6+pUvDxvGnotEJUccyZa0VR1ctwk9NPn2yorww2sqnSbXTHy
         F+QKfPilNrV1JlX4ie16W6mIT9zbotxYfjQhhw3Ihv7oSeAIsXp6vnYa3tPWsrOGfWZB
         CauQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YxOPUhFAV7dAIosKrhjfGAT45OEOGyERMTTKMBhF/BP/pEixNtX
	ENpqPWovTW5cRZT5OdX/nZo=
X-Google-Smtp-Source: AGHT+IGSrqGrogh5CapDceODLcjKb2ubGstuk9zgu0qNw3r/F7uLPqgI31pTjr9Jod9Wse/xK51izw==
X-Received: by 2002:a05:6214:20a7:b0:66d:2543:b356 with SMTP id 7-20020a05621420a700b0066d2543b356mr5103803qvd.41.1699538022917;
        Thu, 09 Nov 2023 05:53:42 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:14b0:b0:66d:871:cd95 with SMTP id
 bo16-20020a05621414b000b0066d0871cd95ls817896qvb.0.-pod-prod-08-us; Thu, 09
 Nov 2023 05:53:42 -0800 (PST)
X-Received: by 2002:a05:6122:2517:b0:4a8:fcf8:9c77 with SMTP id cl23-20020a056122251700b004a8fcf89c77mr1478180vkb.6.1699538022149;
        Thu, 09 Nov 2023 05:53:42 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1699538022; cv=none;
        d=google.com; s=arc-20160816;
        b=NBafTOeXq4gFf5HgyuB2yHc1O6o0zkg+sC7cR/rYpCbby86NaFiDu1isWuJG1hkxxy
         qs1v1qDYwrqulVwfVXDDraMf+kixUfQwW02NJD2YTp4mgG4sMzF/opr/dY3s2Ck6qr2k
         a0oTt7GdvGURsglogX7ilTixqZ50yzmRYomrwiApbvhiFSBF4n+1Atgw38wWN4PTlYRd
         ChR59f3T7lC5d8/JaFXtzHhPJE6SmIq5NVR3nU/VZO372bPL6bfit343bqAVu6EYFjWS
         Zt3NZenOsHs3Lwa6bN/GPibx05WJKMTeSFggRWdvnp4q+aqDYXrbbl4JiTJBs4GKqObo
         rRKA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from:dkim-signature;
        bh=PIQXsMJi8S3VEymD0LPLr+v1Iwe1Q0cmGROrRr9t86Y=;
        fh=uQCsmYQr+KJEcG63Y45gsyDulzJl/B4EdEfpx8XrGGo=;
        b=V8opaz3Wt22MqGf5wKlmty9GxZquJAXZz8DmKuuwv7bBSil1uQ4XhJFE/QnznJbNgC
         fue+3TtU3AwfR7eAV85B6U/vGawQ6aOmSdbfo+2byynE2jwcTXY5eiLgJHS0nOU4pdDE
         6/hcFBEwmjRuIn3WeCrUBoO72X5Q9Kx1+K487LeOAfkw1E/gQDbe28pPd5a6QCaG/7DG
         MuTXFeFRscHZuZ5FzB0c/cELaI/zRh7adCIXDPDmFcjBQJEg2iPniZQxDuwITq3ot425
         nlunsY2u61hU++RSf/piU7Rhduj8XwZ4N/jjQV9TtK9jwUsdrtq1pJDvlQXL97gZLcUx
         jYkg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=GUSROcM3;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id p20-20020a056122115400b004937daab34esi507795vko.4.2023.11.09.05.53.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 09 Nov 2023 05:53:42 -0800 (PST)
Received-SPF: pass (google.com: domain of bugzilla-daemon@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id A02A76187E
	for <kasan-dev@googlegroups.com>; Thu,  9 Nov 2023 13:53:41 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id 4B2BEC433CD
	for <kasan-dev@googlegroups.com>; Thu,  9 Nov 2023 13:53:41 +0000 (UTC)
Received: by aws-us-west-2-korg-bugzilla-1.web.codeaurora.org (Postfix, from userid 48)
	id 345DCC53BD2; Thu,  9 Nov 2023 13:53:41 +0000 (UTC)
From: bugzilla-daemon@kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 203495] KASAN: make inline instrumentation the default mode
Date: Thu, 09 Nov 2023 13:53:40 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: changed
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Memory Management
X-Bugzilla-Component: Sanitizers
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: normal
X-Bugzilla-Who: paul.heidekrueger@tum.de
X-Bugzilla-Status: NEW
X-Bugzilla-Resolution: 
X-Bugzilla-Priority: P1
X-Bugzilla-Assigned-To: mm_sanitizers@kernel-bugs.kernel.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: 
Message-ID: <bug-203495-199747-SvQsjNctRq@https.bugzilla.kernel.org/>
In-Reply-To: <bug-203495-199747@https.bugzilla.kernel.org/>
References: <bug-203495-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=GUSROcM3;       spf=pass
 (google.com: domain of bugzilla-daemon@kernel.org designates 139.178.84.217
 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
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

https://bugzilla.kernel.org/show_bug.cgi?id=3D203495

--- Comment #3 from Paul Heidekr=C3=BCger (paul.heidekrueger@tum.de) ---
On PowerPC, inline instrumentation will be disabled if PPC_RADIX_MMU is set=
.
But Kconfig will already take care of disabling inline instrumentation in t=
hat
case. That's the only arch I could find where this is relevant.=20

I'll be submitting a patch then. Thanks!

--=20
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/bug-203495-199747-SvQsjNctRq%40https.bugzilla.kernel.org/.
