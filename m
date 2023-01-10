Return-Path: <kasan-dev+bncBAABBFOL6SOQMGQEX2PP55A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3e.google.com (mail-oo1-xc3e.google.com [IPv6:2607:f8b0:4864:20::c3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 4FB7D663B8B
	for <lists+kasan-dev@lfdr.de>; Tue, 10 Jan 2023 09:45:11 +0100 (CET)
Received: by mail-oo1-xc3e.google.com with SMTP id q28-20020a056820029c00b004d2bbed17b6sf3964065ood.23
        for <lists+kasan-dev@lfdr.de>; Tue, 10 Jan 2023 00:45:11 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1673340309; cv=pass;
        d=google.com; s=arc-20160816;
        b=SYsJjujJToXzOSaGNk/FAIRp58+Qo0i5SfKyqLddMSVaADoxh9HAXUk+uBh/5vj+Bi
         Bgb3sxRRzVbfdHrBOyTtU6NIZ/vrWkgiLyGy8FiME6LhqLP9yrG8dr03vZTb0slaEM0G
         i0uJsQP7oYFImvl+tG+Xp3I89jytSfniPga4giA8uja/ZY4dr9ipNofsVMZTqiBGTcZP
         GoNNG4CPV3SBNLJ6Dl+5HhwMAuhGDeKdKmzGW7wiy4+Z11SrH5yhVpsbQ3MNEZaZve/d
         LtzlixfbF0rardxkmlIKZlWutbN4u3vEvAqOko9hl6nGHQAtTdn4rux6JP3+sGN1ZKKs
         51dA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=MxteaktxnkK/TDkvctNTKZwfPmqbT43efoDqfXw/gpc=;
        b=Ag0OPxMW+5bPHV+ABd6YebmGK7IObU7nkJKhEoO89y8j24n7IYzowGER16D8SSNUpz
         4TUZe6qV+LOefUJtLNvPofggG+lOR6ILrnWXgNM8xKuFx4udNcSULEZ90Iwuh6vcmPXC
         0m5+xG+7tRvgly23cZ7JJ3JvHz6qDuNR7YLDWFo6+KsrmAh4/UyuIylmbf0BTBOYKm6D
         dSPXVPf5y3J6zgdnwbp/Xz1WL3qX+MAJUTd+BWbt/ror3z1Xd2qC4Tv9gG+jY8jBFLgh
         GHhd6bpFw5yd1AllTpxeKFN04xMiK5NMcyw9IU9fcJaGg/OnQ9lDizB7DcnI02ekm0LL
         stjg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=tHGpLoxT;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:auto-submitted:references
         :in-reply-to:message-id:date:subject:to:from:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=MxteaktxnkK/TDkvctNTKZwfPmqbT43efoDqfXw/gpc=;
        b=i8JVyLWGPwIZpXurt3FDx9TjFEktCfsvTa+Nk9FGqfAGQcvpUIYJeJedOH9hxsMylM
         jl8Rmv/vkgmvt2tXAoroA+7Zbi685b4y1k4J23ibrXU1gmNFFtnrbA3RVKox7CnQeokx
         d7+NnVwzT6/kiD88fzCKaIoU4stzquOqQFoaNN7qR5jpDGnrDfvdLzdBcxqVG8x8IqJT
         ibRjgWV43WRTjggmnRMZBLJTj4HwIJv7BizW2p3F3RJU3i2yZFvrwCOiBmqYv+6e9IOi
         KtSZoJHGadOaoqEff2nUPqBYArFVXWT1iSoaiKEnr3bvyWLzbjY8py3BL06Zw2UKatgD
         lmPQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=MxteaktxnkK/TDkvctNTKZwfPmqbT43efoDqfXw/gpc=;
        b=OsBJGiYa1+O8KglsB5D7pD6qeN04gs7dzKiMbsC2Aw89WCFpqPF/mn+ZMslKouiGS/
         ZUueJLlCvjFeGETgADMMDkDVqUMoUaYR8Wz1BRkEnvvGzC2W3Bk4DKsqa0ESsBiKkwFD
         KAnT9135o9qESCcfG3LcSDNY3s+KhAecomHqiX2jpu5gYL8mTdax1A+JWtdLuo3WQ3tR
         c+SP8nvdWeEj7lVf5oXt1KYyWyFUG+uoxBn8Gi0FQ2hTPPXgRYBMOsD8eTCWSatbTc5K
         SHsMPdjFtdmdlLXwNloBcvlrkQYhSp/T1asaxKxxkYZ/jIl8bxfSAm1LOG6fWhjvnEI/
         Mc5g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AFqh2ko3NzeM7P9kJPG/nVA6lD43d78zf4YyDD7+ihIOdnPAvPnjBeXZ
	Puo15fXODP6K4TXibfsFMwQ=
X-Google-Smtp-Source: AMrXdXt6OsczC+ELS1c5/GsbkrbVTKMqitae+fQ9DZ0xoWgBFR3XVzp/HF7VroodEu8c7lGPr8aU8A==
X-Received: by 2002:a05:6808:8f2:b0:35c:25a0:291b with SMTP id d18-20020a05680808f200b0035c25a0291bmr2956405oic.135.1673340309625;
        Tue, 10 Jan 2023 00:45:09 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:a896:b0:152:e7d4:7359 with SMTP id
 eb22-20020a056870a89600b00152e7d47359ls3573757oab.2.-pod-prod-gmail; Tue, 10
 Jan 2023 00:45:09 -0800 (PST)
X-Received: by 2002:a05:6870:3d8a:b0:159:f750:ddc3 with SMTP id lm10-20020a0568703d8a00b00159f750ddc3mr4316519oab.44.1673340309252;
        Tue, 10 Jan 2023 00:45:09 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1673340309; cv=none;
        d=google.com; s=arc-20160816;
        b=RTCQTwpj7dHpGuwsTkBc7zG210gnd34sN//90nwpwTLxSeLxq/Is5rIU4Hr2RXoH4k
         Ph6odig9y7a08rQn1aoChXpokg85JFEr6XbHLxgpmrGFQ6sbWLqYfC8T0b0CrLzIlaem
         rAu1mGIuXwI0HjBelHS4PoINgRiB1QFnwi8MxLrNBbiR+esBpoDtdbRb1Iyxw+ASODNG
         qcHjp5jmYGWbEONUEX7NQIfbD0P8l7b4lKS9pSXP7LG9ROj0++1NpoV8zjPECSMCiLkx
         4ebimwTQnkarvVIDW92HpgqTBHQ85ZSBzha8VNUunhELvTmOKkvyuhgocR59txJqBIOo
         RYBw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from:dkim-signature;
        bh=fMPCpOLR0UJf7rGJxnKZJhBfFzPySf70hcOxVtLN/lY=;
        b=Lxsb8yKqHijz/mlb9Y/P36O5SKDb7yfYa3qO/IYbf12Os1eB8cMib9SeUocuOhYdPG
         P77PN9hUL8RqTf9twHCVIbvRDVJLlBxtvsvAbEN1cvUCbGzXftND5nGb0U3titr/6ZVb
         spZOJIeZ8DYPyctL4wkvgTwcjIxxOFeymUHWGOkm23XWGP/1F7B95XfO46vt8c3HAX1D
         gb28iAjES9BSllqYb0zRM9wAxSZL1oo0+9cbGwBkmErJZ1/222vKSJByEI6SLunTtg0Q
         GAJEIueuN1NTtTKf8uU/x26+73xqKTN8i0YFni4fIwPpp8otq5mGgQLNeAWfK+dzlLIj
         X6cA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=tHGpLoxT;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id a20-20020a056870d61400b00144a469b41dsi1136217oaq.4.2023.01.10.00.45.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 10 Jan 2023 00:45:09 -0800 (PST)
Received-SPF: pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id 0615F6153C
	for <kasan-dev@googlegroups.com>; Tue, 10 Jan 2023 08:45:09 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id 376D9C433AA
	for <kasan-dev@googlegroups.com>; Tue, 10 Jan 2023 08:45:08 +0000 (UTC)
Received: by aws-us-west-2-korg-bugzilla-1.web.codeaurora.org (Postfix, from userid 48)
	id 266C8C43141; Tue, 10 Jan 2023 08:45:08 +0000 (UTC)
From: bugzilla-daemon@kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 216905] Kernel won't compile with KASAN
Date: Tue, 10 Jan 2023 08:45:07 +0000
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
X-Bugzilla-Changed-Fields: cc component assigned_to
Message-ID: <bug-216905-199747-itnXkEjHh8@https.bugzilla.kernel.org/>
In-Reply-To: <bug-216905-199747@https.bugzilla.kernel.org/>
References: <bug-216905-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=tHGpLoxT;       spf=pass
 (google.com: domain of bugzilla-daemon@kernel.org designates
 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
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

https://bugzilla.kernel.org/show_bug.cgi?id=216905

Dmitry Vyukov (dvyukov@google.com) changed:

           What    |Removed                     |Added
----------------------------------------------------------------------------
                 CC|                            |dvyukov@google.com,
                   |                            |kasan-dev@googlegroups.com
          Component|Other                       |Sanitizers
           Assignee|akpm@linux-foundation.org   |mm_sanitizers@kernel-bugs.k
                   |                            |ernel.org

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-216905-199747-itnXkEjHh8%40https.bugzilla.kernel.org/.
