Return-Path: <kasan-dev+bncBAABB2WBSS4QMGQEMV57U7A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53e.google.com (mail-pg1-x53e.google.com [IPv6:2607:f8b0:4864:20::53e])
	by mail.lfdr.de (Postfix) with ESMTPS id 0145A9B97CE
	for <lists+kasan-dev@lfdr.de>; Fri,  1 Nov 2024 19:42:10 +0100 (CET)
Received: by mail-pg1-x53e.google.com with SMTP id 41be03b00d2f7-7ea8baba60dsf2369784a12.3
        for <lists+kasan-dev@lfdr.de>; Fri, 01 Nov 2024 11:42:09 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1730486507; cv=pass;
        d=google.com; s=arc-20240605;
        b=L5kFByRhkfJtfDkgNoKr/870W52wWGjlUZfvODtFE7w9XB5D7gBnwNlGNVhH+VOZ2j
         tVoDpDhdYL1d5xJayIufnsniiE/jnD1Gz/6ke6guuy7aehLoGiM3/J2wXFWMUvCkxkgm
         jEluvpX6c2uFktHOvH1QLtPt7/xzweUPjYYF0ElBWa/AefWqqaqe6lDKeVWAAS7t1NR0
         aubahnHJP6y7xKtoi7GjgYbYcNLDvung4bdAsqTTizwLCe2v9YpXEMPwV3P6eB2wyqhY
         w+J+rkxdAdx2JWzsdFDgWa1qgtsC9znlAWfFmOggx30xPWYf1k9FanTGW/j8k/EYRZIY
         yNhg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:dkim-signature;
        bh=0/debkBk4v6J111PEpFCM81OSE4uUImQzrTo71zzztU=;
        fh=+x+5v7CvedTgeo2m8X0d6L+HtBY0DqkeMvhu3qHQsRY=;
        b=HiTuif1vGm9vGzItlcQ8dh6KUTV+7646fH7GupJQz5aYfBFwEw1erOMcZ6KfOzhdQb
         X+RFh+YCNboGLMR9V+XSuC4oKR9r+YaFQqVjFksy78gDR6tMutLIaC5msHemr9kdiA2u
         kEpStTaqTaGvguSoNe1wanHHKRKyGR+BqL/rxnD0VRdBu6PDl5GAu5OoM+yqzzc/OOqX
         0zi+ZAa2IqVVEt95mroCP8TOAj2S+brHzrPO6cMR3UzsFlvvVty5I+vLO6YM9K0BZsCA
         ux2PPVMUeQ7RAFr+ErB6E2yaTojkbg7anBeMdlr9ZoRNkKyYCCMf0jAXRMAAAdZ88lwI
         8Iqw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=JrZXzStq;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1730486507; x=1731091307; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:from:to:cc:subject:date:message-id:reply-to;
        bh=0/debkBk4v6J111PEpFCM81OSE4uUImQzrTo71zzztU=;
        b=Ax5pXYfJCLXZ6IDAgYTByb/Gw2DTktXCni0T1EO3arDt3pLvFiy0PmhPiRirJN3FZF
         hmOhuhWN7kpKAPdz54oQQFWfUWiSKW6SZKFfnDTcJfDJmxi6mnyXvsolWoRlwnV++CVf
         GlsKo87QmmSHYNDDJKo9zERzEBwzvoLKxllPznkproqZ2dgmsyPyOHR6A25RBnqzGydU
         yMPRxrKo9kfloBAStXt+wgbnn4LZmpPJHzy3mY+euBAV1NKpLNAHpw+WdXohoM3AKe/v
         qJSY8BZfzNcEXnnEUCzoXJUZliqHjAuIGFJ9R5rQJS/Bt8uRfiEpZtv117IMilu+QOks
         Rb4Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1730486507; x=1731091307;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=0/debkBk4v6J111PEpFCM81OSE4uUImQzrTo71zzztU=;
        b=Kffzhb+vMMHPCc0uFd/bUKiaLp+N4O2fy9SQi021PEQdw7OSXgyV2tNMlejJokKfEr
         Kl2gnIeJnit4kzbKh+1fA8xV+QChzUbHrFGdwmb/Zit0bAU8CcANHdBV8G8AOgfDsSZq
         bG1W+GRf7smVe/o0jOk952cJIvl2z7pwTZvOvPTXYubN4eDb+Pz/R1FdbgP5yuqSrxH8
         9fVlB+9l6tr4VqFmfxL07LTIVXWq+hEDSTHffreATyTnwl3X5X0qM4slPAc+Ly3IV7Zs
         Srgf/ofonZiPFV1znH7GMfK5AiCDb6CSntLvecrgtqaUni69TK4qKaHZZbiKwaxRE2YY
         hvBA==
X-Forwarded-Encrypted: i=2; AJvYcCU70w/9jVsDP9scsL6foFV/5hQBs3jUy2SB7s3585EmRF08JzSCHeOKn7NAP9OVn+YxGqH76Q==@lfdr.de
X-Gm-Message-State: AOJu0YzpgpG6xYBAgUsojrBLj3CatUk9pV3OmzcIIB+uGn62+c80LOvW
	GSWCa9abMBdfpdwD2gQRgoFnpK6tNfPEfu0iYqWMDR4R4ydIsAz5
X-Google-Smtp-Source: AGHT+IGHKgXHCTgwxvo9TZkOaUDkwmi4pWBxRJhtvZvOL9G6UINI/mFMI2FRpbcddvgDIyNA2aLcSg==
X-Received: by 2002:a17:90b:4d0f:b0:2e2:a3aa:6509 with SMTP id 98e67ed59e1d1-2e93c18616amr10045108a91.14.1730486506849;
        Fri, 01 Nov 2024 11:41:46 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:a683:b0:2e2:a2ab:516c with SMTP id
 98e67ed59e1d1-2e93b10a174ls2031520a91.1.-pod-prod-02-us; Fri, 01 Nov 2024
 11:41:46 -0700 (PDT)
X-Received: by 2002:a17:90b:1c0a:b0:2d8:7561:db71 with SMTP id 98e67ed59e1d1-2e93c1e626emr10074131a91.25.1730486505841;
        Fri, 01 Nov 2024 11:41:45 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1730486505; cv=none;
        d=google.com; s=arc-20240605;
        b=KTjdFmeLNH9YIvz5Tj6j7ZkTtz4er2K3Y0inrV0eIwWjmq0hhp9CjSGq1DLzkJrGSs
         gH6XRJE/G9EksTaLLkWPJg+Yh+o66syG6EllVRpHob9c7+reyUiGHcfG1/pD4us+4mCa
         thRBzOpnu+2idwKWgXw69Kr3gALrGgVWeM0C5rwf6CI/EI8aNZJ77Q2z2shqkDCZXU//
         0OiEQO3uQWzoxeZmjJvbbOYAZOum3iraYUlhIHdXbfyMT09LURkGVF0/unbfO+WlGFnC
         2qQn+/P5Ch/covc1Bue3/Y5sx8Hl9idq6EzIvZlcFRg/UCd21qS8MKcBumOW75W90U2B
         eV6w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from:dkim-signature;
        bh=C/s/IJaOBD5gqgQl8PW/hj3cTEXY80nbRSqMjRuWuiE=;
        fh=uQCsmYQr+KJEcG63Y45gsyDulzJl/B4EdEfpx8XrGGo=;
        b=WuKORMTvEbDgZLTz4t5IXwlMAk/jAUKuciPnG+NrAdrWaZssBSflnvnJttZu5y+O0h
         BDzJbLsuy4rxkhC7y7JsjDqd9jjZtb4q5//cDBAAmi4rYBRdr9vzuTyw+Gi5Sh+Luu4m
         rezp9vK+L6t1juXmcAYnr4TshChYcpleJRn1qdRhyrOKXQj3xeeMJU33koT1eBxfWQKy
         QSE05/p3rWmOmgL+GNPtvKqoKQoqgH9xchVVMsvHYtYdsBsb1pOLWHqWadezUl+GwOOk
         b6HapuRoFEa7WwIs3dTOMZRdg3MIjOTacuxZTHZk0hUuG+jYfszEf7w0Z9GdFAnza65l
         OZxw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=JrZXzStq;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-2e93db16505si154301a91.3.2024.11.01.11.41.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 01 Nov 2024 11:41:45 -0700 (PDT)
Received-SPF: pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id 3484A5C4336
	for <kasan-dev@googlegroups.com>; Fri,  1 Nov 2024 18:41:00 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id C483BC4CED3
	for <kasan-dev@googlegroups.com>; Fri,  1 Nov 2024 18:41:44 +0000 (UTC)
Received: by aws-us-west-2-korg-bugzilla-1.web.codeaurora.org (Postfix, from userid 48)
	id B47ABC53BC9; Fri,  1 Nov 2024 18:41:44 +0000 (UTC)
From: bugzilla-daemon via kasan-dev <kasan-dev@googlegroups.com>
To: kasan-dev@googlegroups.com
Subject: [Bug 218315] KASAN: use EXPORT_SYMBOL_NS to export symbols for tests
Date: Fri, 01 Nov 2024 18:41:44 +0000
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
X-Bugzilla-Priority: P3
X-Bugzilla-Assigned-To: mm_sanitizers@kernel-bugs.kernel.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: cc
Message-ID: <bug-218315-199747-Mp1EQu7Rol@https.bugzilla.kernel.org/>
In-Reply-To: <bug-218315-199747@https.bugzilla.kernel.org/>
References: <bug-218315-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=JrZXzStq;       spf=pass
 (google.com: domain of bugzilla-daemon@kernel.org designates
 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
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

https://bugzilla.kernel.org/show_bug.cgi?id=218315

Sabyrzhan Tasbolatov (snovitoll@gmail.com) changed:

           What    |Removed                     |Added
----------------------------------------------------------------------------
                 CC|                            |snovitoll@gmail.com

--- Comment #2 from Sabyrzhan Tasbolatov (snovitoll@gmail.com) ---
Hello,

Create a patch for this issue:
https://lore.kernel.org/all/20241101184011.3369247-2-snovitoll@gmail.com/T/#u

Thanks

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/bug-218315-199747-Mp1EQu7Rol%40https.bugzilla.kernel.org/.
