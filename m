Return-Path: <kasan-dev+bncBAABBGX362OQMGQEXAUA5CY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3f.google.com (mail-oo1-xc3f.google.com [IPv6:2607:f8b0:4864:20::c3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 72270664C89
	for <lists+kasan-dev@lfdr.de>; Tue, 10 Jan 2023 20:33:48 +0100 (CET)
Received: by mail-oo1-xc3f.google.com with SMTP id z18-20020a4a6552000000b004ce83a068c0sf4557513oog.8
        for <lists+kasan-dev@lfdr.de>; Tue, 10 Jan 2023 11:33:48 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1673379227; cv=pass;
        d=google.com; s=arc-20160816;
        b=rJVZxNaHZbKfkBfNZpO3mUYnkRNPVJi/5ilwbMprYksXE5OJda43VxOkf/mhaJz1Sd
         T9KiRQnM1/2qOd4AMbBpV/RgoP383rqOj4tNGKv6if34LFLlj44cPy9Lf7bbvt68wuIa
         MMXGsacoGpRe+cmqkMqqrhgKnqW7gkF6h39Ah190WNnePURR1mu+1kilRV1jdtFxdrRW
         fJBFvs9hqHNq/9wzA5zzSwulE2Zx+SBHFJ43wa5xcSCUIfAYoA+ut3Tf/PsInh4GUQTw
         9TC18+XxNPqkrno61b9mVxlTB1vPtTBltelmz4Pc8+ywzMeiwUjVlMPlraBQ3HVKaMPc
         ChWA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :content-transfer-encoding:references:in-reply-to:message-id:date
         :subject:to:from:sender:dkim-signature;
        bh=0qVUxAzsDqv2A/4bnYJU7hsl0m5s9+K8sxP3oDP3v0c=;
        b=Upt8Rps7yHR/gFQuQe340bNwIUIVO8ueW8+7clhjVcQ/4qxLQRM42u0pIs2XYfltol
         aJ6ENRIty2vSumU636/UMcBU687VS2gNq9Dzq80vGdRl5rjEPb4cCYsysoRVYfLeivw5
         Mb8bdSTZRs73+YJ+0H3K90z15WfZSPEkFdOEYnY55rpwhvi55C8kA9XPvybX1NQPNLoJ
         11L26kYQIUHd62tT3J7q6hVndfAqSnm4wETRfM14oSdYEJn8R3Ga9evMgjR//5Vtv2G/
         AcmDfjaf8X1louZeO/OMJzkoxKpcHBZglsBp7JDqgf+54ThsTXljMRvHFUhZL69tjfGV
         J8Og==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=NmHC028i;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:auto-submitted
         :content-transfer-encoding:references:in-reply-to:message-id:date
         :subject:to:from:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=0qVUxAzsDqv2A/4bnYJU7hsl0m5s9+K8sxP3oDP3v0c=;
        b=g+lquk+tfIHPYZGgJdZ6hsk+3SoYdnpB6MllWTV0M2VIq6jB02Q7fLdQ94DdJDdxsv
         cfuMreFNAqb8zyyVfjeFvXnezu+BaNDKVv/hahVBEChgLePgzKNePXgZFl9PSzplujF6
         BJbZehQgaqv7FllNtBp/mBz8A5j371FNa0ZgJj4JOKy6d5N2hvZedm2VNt0nqc7OJ9f1
         czc936CkqspH7hmxTyfGmsCXTn7CZyQ+vOvO5NZ5z6OI9nllAd2aOZKGuDugHcT5ci9D
         aWsTRvtYfcYYBKN1hwBVXWL2Tq61aBCoiBv1QSYNbMjao49KGcawXY9KdMmpPf85/wMT
         4mbA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:content-transfer-encoding:references:in-reply-to
         :message-id:date:subject:to:from:x-gm-message-state:sender:from:to
         :cc:subject:date:message-id:reply-to;
        bh=0qVUxAzsDqv2A/4bnYJU7hsl0m5s9+K8sxP3oDP3v0c=;
        b=A09Iu8HTnks1U8kI+aVdqOrfqBRyJXc9wEXDUN1aEA/PmWtLaV8pU/oPiKXLiFxZle
         MCOZ88SVSC5QSWKoyQdNEQdTSlqpPUs1ufAzOtUmGbCDVmQy38DG4uNjfo6djEPxZZos
         nCUMggxv+3GfH34/LSnY0lscMAVeZGyM70goqOgoYk3Sz6uHhxcjrSbaLC0PRgcXt4kg
         ZNgLOMyxhPbdKYLuELVXtS2jQjoZGl9HUE+XINQtsKiXMRu871qfqC7lkNyWTvxumiKM
         kLPULYs+RDmbZG3oik32KOsUXuhD4VssKB2FSgEiCOc3bSM2TBfOCuSqJCqkbM3a21TS
         OSKw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AFqh2kp0ZtUNMniEApxociZGsKmy3e3f78Xx83PqndqMdJ2zXsBF6GxB
	Orhkm+j2mtCCpLYC4s0ALoc=
X-Google-Smtp-Source: AMrXdXv321Eepvd+dBe/sYF9p254HjoW8HCMoa0JRa5FvTwMP+kYdttt0O6bD4xpXswfKOAPACBL1Q==
X-Received: by 2002:aca:2309:0:b0:363:bef1:30c0 with SMTP id e9-20020aca2309000000b00363bef130c0mr2922995oie.129.1673379226893;
        Tue, 10 Jan 2023 11:33:46 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a54:4f87:0:b0:363:19d3:70f7 with SMTP id g7-20020a544f87000000b0036319d370f7ls3744183oiy.9.-pod-prod-gmail;
 Tue, 10 Jan 2023 11:33:46 -0800 (PST)
X-Received: by 2002:a05:6808:1491:b0:360:d477:41d9 with SMTP id e17-20020a056808149100b00360d47741d9mr44946492oiw.5.1673379226537;
        Tue, 10 Jan 2023 11:33:46 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1673379226; cv=none;
        d=google.com; s=arc-20160816;
        b=hbgzndoYvcAY4fYse7TyQJ2/Ar0VBlutB4aU6NMv0AWHZcMHxB2DYij/nS1Iloh/vb
         zncMJBsSnUorSKaVN5NUx2/l0qm78wqtXw2fxifC9hqN7cL1kmR/W78qEk6SD5+n6xco
         cvsDvSPavThX+mx6Bl07oN1ErxAGFhvZ7n75yPzMt9jgAqSMCc7qLsbJOCYMrD9oQVUG
         8+YDttpYLnb6eOUs0rPuW00nmfhfDh3xh6aC1OQ6ig9UAtmalhL32K7r3+SwZbc80r7u
         m4iGcuyQ2gLeipZqbFeS7QtelCOq7/K6ivVhwAlz6WP4hM4umegr4G3qhgDuh9Qt6/k5
         swOQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from:dkim-signature;
        bh=mtQo5785gpJajBN+9ZthtAt4WNK27phW/PLy4M1RHJU=;
        b=k5oRZ8tzEh7cWWyCZabuZssEFgFFks0RrqS5PYpY8jWectYKtsCMYCoqgCYgfYB5+B
         a1jXP+XYWMl8PZiKXn/qPpXxDKCVCUDTs6KJ5XLsPlIsoZ2HQUaRgCeLUJNLQlk1R8eI
         SnOTkf4z2blfk3ctoPvcLngl7/hinLlRwmQtf2obDPZWy5tGH9IP6VWLR+HXF+Uky+wF
         KwnbL7A8imbzUL4XA4BJ28mcPYtewLZJT1hKd8JYMaW2qKSPmG6hPhnd1AdC5wFwa4xC
         3ZakZqXVmxNqkUpORXgTDNZFlHzl5L9MgHOAQhr/w7OA9u43Ik599GaT+E2HZWbmzEg7
         CL3A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=NmHC028i;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id g37-20020a9d12a8000000b0066c427f94ecsi1193943otg.3.2023.01.10.11.33.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 10 Jan 2023 11:33:46 -0800 (PST)
Received-SPF: pass (google.com: domain of bugzilla-daemon@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id 4E6BB618E1
	for <kasan-dev@googlegroups.com>; Tue, 10 Jan 2023 19:33:46 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id B3DC8C433D2
	for <kasan-dev@googlegroups.com>; Tue, 10 Jan 2023 19:33:45 +0000 (UTC)
Received: by aws-us-west-2-korg-bugzilla-1.web.codeaurora.org (Postfix, from userid 48)
	id 9D26DC43145; Tue, 10 Jan 2023 19:33:45 +0000 (UTC)
From: bugzilla-daemon@kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 216905] Kernel won't compile with KASAN
Date: Tue, 10 Jan 2023 19:33:45 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: changed
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Memory Management
X-Bugzilla-Component: Sanitizers
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: normal
X-Bugzilla-Who: tytso@mit.edu
X-Bugzilla-Status: NEW
X-Bugzilla-Resolution: 
X-Bugzilla-Priority: P1
X-Bugzilla-Assigned-To: mm_sanitizers@kernel-bugs.kernel.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: 
Message-ID: <bug-216905-199747-9hrEM0Wqlp@https.bugzilla.kernel.org/>
In-Reply-To: <bug-216905-199747@https.bugzilla.kernel.org/>
References: <bug-216905-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=NmHC028i;       spf=pass
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

https://bugzilla.kernel.org/show_bug.cgi?id=3D216905

--- Comment #6 from Theodore Tso (tytso@mit.edu) ---
On Mon, Jan 09, 2023 at 08:58:41PM -0800, Robert Dinse wrote:
>=20
>  Increasing to 2048 did allow kernels to compile with KASAN enabled. I
> am curious why e-mail only? It would seem bugzilla, a public forum would
> make this fix available to others who may be experiencing the same or
> related problems.

Not all kernel developers pay attention to bugzilla.  (In fact, most
kernel developers do not.)

>=C2=A0 Interestingly, I could not locate the symbol with
> xconfig, had to hand edit the .config file in deference to the fact that =
it
> tells you not to.

If you search for FRAME_WARN in menuconfig ('/', followed by
"FRAME_WARN", followed by return), it will report:

Symbol: FRAME_WARN [=3D2048]
 Type  : integer
 Range : [0 8192]
 Defined at lib/Kconfig.debug:395
   Prompt: Warn for stack frames larger than
   Locationf
     -> Kernel hacking
       -> Compile-time checks and compiler options
 (1)     -> Warn for stack frames larger than (FRAME_WARN [=3D2048])


That being said, you can edit the .config file if you know what you
are doing.  But if it breaks, you get to keep both pieces, since there
aren't the safety checks and guardrails of the supported paths.  For
novices, I recommend saving a copy of .config before editing the
.config, and then afterwards, run "make oldconfig", and then diff the
resulting .config with the saved copy to make sure there aren't any
unexpected changes.

Cheers,

                                                        - Ted

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
kasan-dev/bug-216905-199747-9hrEM0Wqlp%40https.bugzilla.kernel.org/.
