Return-Path: <kasan-dev+bncBAABBDOHXKWQMGQEJ7DEW6A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x237.google.com (mail-lj1-x237.google.com [IPv6:2a00:1450:4864:20::237])
	by mail.lfdr.de (Postfix) with ESMTPS id E5C46836CDA
	for <lists+kasan-dev@lfdr.de>; Mon, 22 Jan 2024 18:19:10 +0100 (CET)
Received: by mail-lj1-x237.google.com with SMTP id 38308e7fff4ca-2cd2f4600f6sf30344911fa.1
        for <lists+kasan-dev@lfdr.de>; Mon, 22 Jan 2024 09:19:10 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1705943950; cv=pass;
        d=google.com; s=arc-20160816;
        b=Rg8PisPKdYhDfhmTFTLGSw9NZ0dIPPIM4LJ0Ypta6F5JP+PhJBNnwhVHImxPtpCG6u
         4sTKwyhmARgLU5aPXyFhVeD4AgzI1kOMbE9vN/4BgmtpnRdypS+BJ4AzqvYduDEzmdbZ
         9ZFMyepOZB19j1EcejoWG3yGBN9rjxYvsYgGP446erIiXkCuQIO5+5UFD74qAVuWcE4j
         L5l0RqOM+LVpQow/xfXpFlA+G9dO+feZKwnVJXNVUVTBk1wV6mnFC6orHIi8rnOq7C4o
         4n42KnaNjCY+g5SIXU661c8XaDS1uQFvqGlYOsOzGuKhSCHxWrQsID+gf/Ie4RYIjKxp
         GD+Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=fU5tN5Z5stSgIzBmHsR1J6kLmoPnl5h9tieOVASnwVU=;
        fh=uQCsmYQr+KJEcG63Y45gsyDulzJl/B4EdEfpx8XrGGo=;
        b=Z5UNV8UUO9Hg0/QOFOkT9O6wC8yLnWwg4ToY26iep5ReiVqK0Ns+oXBISVblvwvuGG
         HVnDk/1FhCgVX43aEaXWDTkb+LJIc++H087YlNAw7a4xag10fFfDBSPowxLGZvMQL6b8
         cI3mP/t+isTcl3dExds7mBV4VFoOvx61JGgNT6bCpTkbD9Lrox9QFlDqSzHEunUDPjBl
         WKuvvA/1coIY2cIGrMjTuizP4+9hVXzGz42gvOkzOxIAKVxV25dO1xZKLoSBVLvkqYH5
         oQzXOC3/R+6H/H7PK81T4D7atufQTrMHfDU2j9Fn8dAG6D8wWIOR+L6GhTsaNXhBRSvM
         jbyg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=GpnSoAfn;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 145.40.68.75 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1705943950; x=1706548750; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:auto-submitted:references
         :in-reply-to:message-id:date:subject:to:from:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=fU5tN5Z5stSgIzBmHsR1J6kLmoPnl5h9tieOVASnwVU=;
        b=Oq+jKJqqdwp0sV7lufrRyaM77OBE4VlDM269RsA4xf0vKgHl/uvMBSGg9RqJIZUGFe
         RADvlE7Lduk2SnhOD8z9B6FlZDQmUUIAU25+OiPsThwnfMkMaV4KYZjEgTAshadpGaH6
         4MEgspwlOs33sutC9Y0Rm6t9pe0QH8QAAs9sjAznrJEbQaigqzAawYnsWnl4M81GArp1
         eFf7nqm9K7GKsXcwQuRldvDXpYmdHy66JCZOFq1Q9D9XV8t2U7DV4acJBl8WJmX2Eicg
         Fwl9FXvkrbgc/NDy84dK/ihoAOvxDDk3nN2KkiPlSOWtiOIPUKFGHvSI0oBPI09Q8pT4
         lZdQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1705943950; x=1706548750;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=fU5tN5Z5stSgIzBmHsR1J6kLmoPnl5h9tieOVASnwVU=;
        b=w9u3o/i35mQVUF1+fICcUR2kq2mp5p939bzuudlfivDi0NuGXr4d9zjOVzQypBbA4E
         7P6E9/YCM8QtmS0Z2Cw6QR86AVYb00L4WVjMprXxRBeHt5r2SZIvE2H2u16/CJp5UHvD
         Cl8/FGNHscTDhrEirNDbhhbkiMYXY1hlQJVhoFoDBax7x4xQMzLxD6hCh3pJrYw+fJXA
         wSHKtwq2/1lCO3RdnbgOII2x9sX/Y3DeYdmIiZCFMAta3iOVWMAulYNiyQIc3p6+iYQn
         8UMyyzvfAccnd0RqmTEJntMIKGX/7hZNP+QivdaZipqKoh1wzVXsgK9X9yTzExVCtljr
         MBCw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YybSyEAP6DXiZblaDhIk1eUzl7nFxU9nLDVbl6JyjUvGj4afs0Y
	ABHmjioiJb7jFXpwNksBA4t3sevVqRDDjoAv6xOChqnCCZ05YAI0
X-Google-Smtp-Source: AGHT+IFk2AxJ2pvhKSCC4rvtErUnh9SiU4RVYIwuXDm/bIdFtvOBle7US3zMJQhaqiMl0vq4VuvtxQ==
X-Received: by 2002:a2e:7311:0:b0:2cc:7b19:1b05 with SMTP id o17-20020a2e7311000000b002cc7b191b05mr1925697ljc.48.1705943949593;
        Mon, 22 Jan 2024 09:19:09 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:9bd0:0:b0:2cf:390:eb68 with SMTP id w16-20020a2e9bd0000000b002cf0390eb68ls203014ljj.2.-pod-prod-09-eu;
 Mon, 22 Jan 2024 09:19:08 -0800 (PST)
X-Received: by 2002:ac2:4da7:0:b0:50e:ebd3:3517 with SMTP id h7-20020ac24da7000000b0050eebd33517mr2187450lfe.39.1705943947862;
        Mon, 22 Jan 2024 09:19:07 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1705943947; cv=none;
        d=google.com; s=arc-20160816;
        b=b3gX28cS/dgLLfHmPBoBWx42ck80Ct5o43StRYWeFTZ80dy73YgJLbhnFE0vmJO/Ne
         Ex+HL1HVaWM4Bl9q5m741Ptummcy5vhda6lvCeuS5DjrJgwg1oRVIhpEUQcCcIjweKxK
         zK53K97FupjF6nYMxEe94pNGgwXMCDFlmwCKL2lTM9IZZzeGZsIk9Javun5poI9B1ecp
         46y7iXbpJzMEeKvNV+JwNQb7J0UJzzJC87PJGxBhQG4eJcnQ4cKSJ7qTGTp0xTY2gDDq
         xo+/EzEkAWR8KIrcEpcCS6P7efBUh9UGD2ETEJZjx6kxw57K+GGo+eA6LusAYe8XMxnX
         Xhlw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from:dkim-signature;
        bh=rPXrUtGMpQez4asocOACE+QGNzm76KAEKjbdOHpS1s0=;
        fh=uQCsmYQr+KJEcG63Y45gsyDulzJl/B4EdEfpx8XrGGo=;
        b=YTR5WeQr8vUVHAFMQfyl+PsmpfYsVh4AZ+hlgl+wplsejFQ2p1rPGXaB8e0UqU0KUe
         /hYspoxRKOAtBGuBzYs+Ia95Zi8EMrcP6BFp69/NP3b2Jkx+lireKPHNTDOFj8jriko4
         jm38fbrek1nqrMq7MQRjzwpN57hqkxFWvIl/PuNHhVf5ujPSUMQhCPVNq6+EVJYRV/QZ
         kr6to4Z0kMTCsw0knjGmgiWlfPopO9Vy69Q/87CMIC4s0PPdVgVGMbSYR9Vi83Kq4CCX
         nVpHHo/5kCLCfq7DeSqGKgsdiSSRxf/XNgyyADOcKxL5tVV2GeXyUmjKxATMdSI9JfT0
         wp0Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=GpnSoAfn;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 145.40.68.75 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from ams.source.kernel.org (ams.source.kernel.org. [145.40.68.75])
        by gmr-mx.google.com with ESMTPS id c6-20020a05600c0a4600b0040e657c8b72si727094wmq.2.2024.01.22.09.19.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 22 Jan 2024 09:19:07 -0800 (PST)
Received-SPF: pass (google.com: domain of bugzilla-daemon@kernel.org designates 145.40.68.75 as permitted sender) client-ip=145.40.68.75;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by ams.source.kernel.org (Postfix) with ESMTP id 6F893B80F9E
	for <kasan-dev@googlegroups.com>; Mon, 22 Jan 2024 17:19:07 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id B44A9C43399
	for <kasan-dev@googlegroups.com>; Mon, 22 Jan 2024 17:19:05 +0000 (UTC)
Received: by aws-us-west-2-korg-bugzilla-1.web.codeaurora.org (Postfix, from userid 48)
	id 9E728C53BCD; Mon, 22 Jan 2024 17:19:05 +0000 (UTC)
From: bugzilla-daemon@kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 218313] stackdepot: reduce memory usage for storing stack
 traces
Date: Mon, 22 Jan 2024 17:19:05 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: changed
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Memory Management
X-Bugzilla-Component: Sanitizers
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: normal
X-Bugzilla-Who: melver@kernel.org
X-Bugzilla-Status: NEW
X-Bugzilla-Resolution: 
X-Bugzilla-Priority: P3
X-Bugzilla-Assigned-To: mm_sanitizers@kernel-bugs.kernel.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: 
Message-ID: <bug-218313-199747-Unc28z1bnG@https.bugzilla.kernel.org/>
In-Reply-To: <bug-218313-199747@https.bugzilla.kernel.org/>
References: <bug-218313-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=GpnSoAfn;       spf=pass
 (google.com: domain of bugzilla-daemon@kernel.org designates 145.40.68.75 as
 permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=kernel.org
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

https://bugzilla.kernel.org/show_bug.cgi?id=218313

--- Comment #3 from Marco Elver (melver@kernel.org) ---
We can keep the evictions feature, and just remove
STACK_DEPOT_FLAG_GET/stack_depot_put() where it doesn't make much sense - and
this should get previous memory usage again:
https://lore.kernel.org/all/20240122171215.319440-2-elver@google.com/T/#u

Is it only KASAN generic where we should remove evictions again?

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-218313-199747-Unc28z1bnG%40https.bugzilla.kernel.org/.
