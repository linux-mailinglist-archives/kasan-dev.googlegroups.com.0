Return-Path: <kasan-dev+bncBAABBOONYPAAMGQED7FYU7Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1040.google.com (mail-pj1-x1040.google.com [IPv6:2607:f8b0:4864:20::1040])
	by mail.lfdr.de (Postfix) with ESMTPS id A032EAA0F71
	for <lists+kasan-dev@lfdr.de>; Tue, 29 Apr 2025 16:48:27 +0200 (CEST)
Received: by mail-pj1-x1040.google.com with SMTP id 98e67ed59e1d1-306b590faaesf4562111a91.3
        for <lists+kasan-dev@lfdr.de>; Tue, 29 Apr 2025 07:48:27 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1745938106; cv=pass;
        d=google.com; s=arc-20240605;
        b=GwTrGERwFU5kpOvcdJUQ4CwMG4+Gfo1TimN4fSU+ss0wIYM8t/119ajByF6dCtkym+
         tXo8EE6nIt8RZvbmZZYhjgN+ULsR6NgTs4WeSdpgWGSCYnYfTRZVQkHEfNHAyg4UBC07
         /5kCUgdafXcETWIa0a5pe9Im3WTrzMbp1sjMVSFTAQnZ3Ifstc8AMlZmEvoKNCn7Jy7Q
         RxZRFkbNDGN7tkCuz85GLm02eVTOyELvulDQRRYcJ8d0n99rsgWr4jCz4rpk9GZ48c5E
         VJjGnGIk/hbXzDd3Ok5iH2oAbqNkLvAOw0XUCcc6n1oTjbjw/LilaNu0uOZug82do090
         8hVg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:dkim-signature;
        bh=+Z1E6vme8srJSAHBnCCOcQBFkpXEaKrXfl/vkaII2JE=;
        fh=h7zqxUQ/EWugRa4C7qHJsCwpFrjoDQ2VzhnOlpaGUuc=;
        b=Ge2r7dIGHIEG5I0pL9aFMa/QD/ApC3ebk9u6FJjWHfri8zxxz+w3DvJzF6cGZpTnFe
         VPylXycstKmEc4sUs+owBB2lkuOb8JW+SUYU443/nLmoRktakfzSe0aq/AJz4+gr8L/K
         yGygtjkoO4Pa4HH/CCbEWcvutqcwwfj7ibMojseFuGhhjtnsAG3iF7CTCpK3vDecdsUZ
         8x9zN0feEy1NYUfSsCWfnfVnt0JssPRXaani5RvLLIo5i1yFYHJ75c8+ps6wn6fq86Wl
         ATv4Wf2/T5u8YW4TjokNmFOaCDyWgIPRJYfZCaaN4rwxDgfJVU8Xud/ZDzsfa4VPLJ2j
         U4nA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=sMXYFb1V;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 172.234.252.31 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1745938106; x=1746542906; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:from:to:cc:subject:date:message-id:reply-to;
        bh=+Z1E6vme8srJSAHBnCCOcQBFkpXEaKrXfl/vkaII2JE=;
        b=RiTfTcMV9c2tayoNY8nofukHzeA19hxMC9TdPi78cYtKqPUdWymOg7sHn6HZi40dTG
         pxAivELr/VEgPKtmnRFF2/768aGPN1/uKLBG2XI5RNItG8Dqt69+NdgsxkNQaUwEs8pM
         9CwCO+IX3NOXQI8OCrb3a0jclfVM/ibm0cXBgvRRtAOhgRP3nqvjiCrNQe1tjpwFenoA
         dgHitx7mcyR5g8Yea777oa22qVCxomJSy/JOcy2sIcucFi5u0UdIPSUxCBGF5dnv+k4B
         gvudsesL7Qg3kgcTXFAyc+maXljyjswTApTJL9AeMQWUTqX1u8MjpkicHV6KZWhrWwkQ
         1SeA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1745938106; x=1746542906;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=+Z1E6vme8srJSAHBnCCOcQBFkpXEaKrXfl/vkaII2JE=;
        b=nxPIao4YXBj9H33awSt3eOvRl6sFHD5qsqPUcCUG8gJJbI+9Nb0c3Osn5TXNOa86jT
         KafRlsOReTuFTDllrtOCPPZ3jwwnpDa4xUatLuPgjZS2xViBcJhCas77a2kU3Enp3h9w
         tZRE5gC2LE6jIAX137jHPXvYN/LTls2E5VH7LDz9cIA5Cx73t54AOYbBLeI7Ka66F7LG
         LldtrjjvwLAC2TlqVVArdO6uGtvJsTN6+qtEfxj/kD9l47dOqULglKHy8rDkk5RRiXWr
         30b7smrFysJAnn+I7XyhxBc9HKoWwtRlfX5qNKZFu+Kb1BZwavmCCiXrSRyKpvpjqMAQ
         hqjA==
X-Forwarded-Encrypted: i=2; AJvYcCW9GVfvqZZcpIacyGuTFaYoJS2u6fReF6gGjHuakwU6XzxRNBV7fmp6JwAnnoPPM+xX3vinlw==@lfdr.de
X-Gm-Message-State: AOJu0Yy9xrm/PIPKldYg+xk2XlLVO9g8ps6OZtC8r7jYkFqT9+ir9sHz
	RQ/Z0c0lJJUl22fiVwpeDcaX23ST55Wpl9KnuisnlDBMQx6/aoAA
X-Google-Smtp-Source: AGHT+IF9KUUwnS4nVchMSlNov9IsxtUC7i12ZJZQo2dLNT3MzL5I+sWKwTIyISUj56NqtG+Ul58m4Q==
X-Received: by 2002:a17:90b:1f92:b0:2f1:2fa5:1924 with SMTP id 98e67ed59e1d1-30a21593a7fmr4821779a91.26.1745938105865;
        Tue, 29 Apr 2025 07:48:25 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AVT/gBFIMqLsJZbamZ72+rg8KgmMrCAFqysaH6hQ1Ofux6X4mQ==
Received: by 2002:a17:90b:5884:b0:2f9:acfc:8eaa with SMTP id
 98e67ed59e1d1-309ebe3102dls4746246a91.2.-pod-prod-07-us; Tue, 29 Apr 2025
 07:48:25 -0700 (PDT)
X-Received: by 2002:a17:90b:384b:b0:2ff:5ec1:6c6a with SMTP id 98e67ed59e1d1-30a2155cfd5mr6814029a91.18.1745938104879;
        Tue, 29 Apr 2025 07:48:24 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1745938104; cv=none;
        d=google.com; s=arc-20240605;
        b=XB0KfMwD4cg6lq6dBpdJZDqU/kJY54pMXP3UUCNKTEg/PVLqNH5AexckZxgNMOxDEE
         6UVqIhpl7ldT6wlBFR+dqLY1iVGWMV7/ymzRCrs9EJySidIII+RCuP6EBLLC2Xv1RM1g
         woCqXB0i6c7nuSmFmm5txbDUKWftefOx2zKL/7ObFbqY3vaH04BpQoU3h2pp5dB/MGlB
         mOvgQyZ1KpEAobvZ/zB03RIiBrsivaT2L68hr10v8aIj1kGJ89lg7wiHb5FaMpnP/oi7
         bnZOtFEjE7auq+EskvjTYOBfVB3npW7obufWMm3p7tdB40x64IbAURDt8b8LdbEdMbUb
         79Bw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from:dkim-signature;
        bh=KYwqlVRd9nTWdTmLXR+jW/WWxL9my4OT6Yca60x+XRI=;
        fh=uQCsmYQr+KJEcG63Y45gsyDulzJl/B4EdEfpx8XrGGo=;
        b=XKKS6BCdjM4tyYxqzH/jCrBTVCJoUdcEnrvzyWkEQIKv93Bb1YsUvs87gW8Xid/+f/
         9z19541X/1vrsF6eEx6l+h01zxQLIiJfbYfynH3WzYg3KsGd0G+K1TAhphgNM6FGrkyU
         u/KOm/gNG54iQC6LTQO7AdgrbHUQgmwtGe56G5XqgPeSQOrj0mDkVPNXCxjl6rCzUCEB
         BXY8mp68r9OPY5gNdbzji+9gKJ6ztwDkRk1cp/IQdN/CLKuBlJLaQ4g9aQE58uhMKAiw
         CxttJgodzsgdeGuH5pmlapXtW0IOtlNNB4+tqJ3D2FuFQQq4WoeiZqAOs2u9HPC3ScbW
         JXNA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=sMXYFb1V;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 172.234.252.31 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from sea.source.kernel.org (sea.source.kernel.org. [172.234.252.31])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-309f77d7162si62005a91.3.2025.04.29.07.48.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 29 Apr 2025 07:48:24 -0700 (PDT)
Received-SPF: pass (google.com: domain of bugzilla-daemon@kernel.org designates 172.234.252.31 as permitted sender) client-ip=172.234.252.31;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id 61FF64A8D9
	for <kasan-dev@googlegroups.com>; Tue, 29 Apr 2025 14:48:22 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id 6E167C4CEF3
	for <kasan-dev@googlegroups.com>; Tue, 29 Apr 2025 14:48:24 +0000 (UTC)
Received: by aws-us-west-2-korg-bugzilla-1.web.codeaurora.org (Postfix, from userid 48)
	id 6755BC41614; Tue, 29 Apr 2025 14:48:24 +0000 (UTC)
From: bugzilla-daemon via kasan-dev <kasan-dev@googlegroups.com>
To: kasan-dev@googlegroups.com
Subject: [Bug 199055] KASAN: poison skb linear data tail
Date: Tue, 29 Apr 2025 14:48:23 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: changed
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Memory Management
X-Bugzilla-Component: Sanitizers
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: enhancement
X-Bugzilla-Who: stephen@networkplumber.org
X-Bugzilla-Status: RESOLVED
X-Bugzilla-Resolution: INVALID
X-Bugzilla-Priority: P1
X-Bugzilla-Assigned-To: dvyukov@google.com
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: bug_status resolution
Message-ID: <bug-199055-199747-ZoKlUXCI7F@https.bugzilla.kernel.org/>
In-Reply-To: <bug-199055-199747@https.bugzilla.kernel.org/>
References: <bug-199055-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=sMXYFb1V;       spf=pass
 (google.com: domain of bugzilla-daemon@kernel.org designates 172.234.252.31
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

https://bugzilla.kernel.org/show_bug.cgi?id=199055

Stephen Hemminger (stephen@networkplumber.org) changed:

           What    |Removed                     |Added
----------------------------------------------------------------------------
             Status|REOPENED                    |RESOLVED
         Resolution|---                         |INVALID

--- Comment #6 from Stephen Hemminger (stephen@networkplumber.org) ---
Almost no kernel developers read bugzilla directly.
I am the gatekeeper and filter some bugs to netdev@vger.kernel.org

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/bug-199055-199747-ZoKlUXCI7F%40https.bugzilla.kernel.org/.
