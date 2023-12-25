Return-Path: <kasan-dev+bncBAABBEX7U2WAMGQEQDZVOSY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x138.google.com (mail-il1-x138.google.com [IPv6:2607:f8b0:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id 708DE81E1DD
	for <lists+kasan-dev@lfdr.de>; Mon, 25 Dec 2023 18:44:51 +0100 (CET)
Received: by mail-il1-x138.google.com with SMTP id e9e14a558f8ab-35ff23275b8sf18742135ab.2
        for <lists+kasan-dev@lfdr.de>; Mon, 25 Dec 2023 09:44:51 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1703526290; cv=pass;
        d=google.com; s=arc-20160816;
        b=UBjmOCTsfblsNNq/JaO+BPvrvxz0iGKDfZCeXKBXj2jCWaONpFD7Es8fla9KZWR0S9
         paQ6qhvRFEUPQAuVKgWWMBn+/V+GAIKGCPShFalN+s0bGIdDNYlhbGEY7vqhseD6j7d0
         Pk+ObvEi3JKRG4OAnK5fPUo8Q83fR09zm1xagZO8cVhxaVj2TWTeemE5LQtQ2P7aj/jg
         gMBYr5OSzmyhR1becLpWEZdStqn8QwAOFJQ4xStAY2+vLxAUNYMM39alOgbJC0GyAI0j
         aJB8pmsjObrAJzK/xy17YE4RTlx6c7ZoChQdPALamQNj2NzCYGTl+svLmZC54nYECPbW
         Jjsw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :message-id:date:subject:to:from:sender:dkim-signature;
        bh=Is0z40NPu8joUnAnbu8ntgIy5CCa6ACyygGeBXKF/CY=;
        fh=uQCsmYQr+KJEcG63Y45gsyDulzJl/B4EdEfpx8XrGGo=;
        b=Z2EeeD1rYbeccejrDuy/dvHm+IGVL5Gmn85WLR5PCjj+xp6TkWhNLutUVPJQ6SVtei
         cuoMAJsF8I0jDY+Bk15lEkHyTrA+MJ8Vt4Q2qNa/yqj7wHIiW/k48X0SNXTzp7totBl8
         bdKTDsb5YIA4K4fBjnNYn2m7wvDIZwTw6TpNMsQhemD5/45HgrTvydlbi4U6BoL0/c8l
         gfenoGR6AKwXtLByh5tSYgX6yF9SUiGbahvAoRlKwzwUcHOKHYbak3RJ/xPOqbY+2Tbu
         Np52CCOPiKwtCo47ZdCZwhTRa3XFSGrkENBxBbHvFc/XK9l7xMCzoOa45eM/i73Ve77F
         VK1A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=jxv9v5zx;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1703526290; x=1704131090; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:auto-submitted:message-id:date
         :subject:to:from:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=Is0z40NPu8joUnAnbu8ntgIy5CCa6ACyygGeBXKF/CY=;
        b=W85B8DY3xN6uP/0eW9xWgbA60BVjjdb28KTI/XgsOtPkvEK8MkCHizF6+N2kzAOYBl
         m1BsU9f6SS0LspgT6rIwdoV47/iXj3Hup6J0OKgI31sqxIb7xxBaMBONByl3pjN8HcHo
         HmNLF+bfEqKpxmzG3if7HDgWavOQLr6zlyt0srI1+z1eRXMGVZmxHARbh/81YL+S2D1F
         WU9XbkfuYVbdZvh/gBNn48B1qUxMVBh4nfgmS888cbE7+DysuIcncBAOQ3wLBHc8+9Js
         unkVJqqokVBM9c2ZUNVqG6d45Qtc61LsU7U+UENkszJ/nmZUcqnTWOf1AUk/Ib+pCikV
         p3zg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1703526290; x=1704131090;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:message-id:date:subject:to:from:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Is0z40NPu8joUnAnbu8ntgIy5CCa6ACyygGeBXKF/CY=;
        b=bJCKnQ4062/95E0GfcI8lOFHX8YOOQjiPlSGo0sOXRdZkofBozNBSUgFNxO2L6yQe6
         HFF+vTz+2iR+bIhGQHZFVvef0YzQjevkIcw3+JXAE0e7CmwZCo1T32NCtzXCY0CK5Yrj
         IBhZNK/8brhIEhHBNuV0pBSexbUbzV8/w9thflo2tpT5rJMx+ehlTIwuG0Xio4B/LLXi
         wwJe8NbPVR7fWvt66O+Gc0W+BYC/xVoMrQ0uUnF8uKsICPNZLlhL5DTJA/pVmQReF9I3
         uBilZb4E+HbrF28X/FMLtgoDcEdye1F+uiK92hMIf4ZpqBx7u3tgi65CpVEeHQ4vCuHJ
         DQ8A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YzK9Nmx8StVUy/wXfS/Hv0LtvpSfnQmZqcZKnOC0St8+SV4cBUf
	2bpBvx9vjVmpLwkMKGAj+/Y=
X-Google-Smtp-Source: AGHT+IH5a8YacHA5j9frzYMFyQTXuW3GqTY5Dv6w430iJqTf+BqcCzzDHJNsVo0vbe87dGQmxuSOwg==
X-Received: by 2002:a05:6e02:1a0a:b0:35f:eb58:7c88 with SMTP id s10-20020a056e021a0a00b0035feb587c88mr7464891ild.8.1703526290207;
        Mon, 25 Dec 2023 09:44:50 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:1c04:b0:360:69b:4399 with SMTP id
 l4-20020a056e021c0400b00360069b4399ls360182ilh.1.-pod-prod-04-us; Mon, 25 Dec
 2023 09:44:49 -0800 (PST)
X-Received: by 2002:a05:6602:3145:b0:7ba:a4c2:faf with SMTP id m5-20020a056602314500b007baa4c20fafmr7392443ioy.20.1703526289644;
        Mon, 25 Dec 2023 09:44:49 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1703526289; cv=none;
        d=google.com; s=arc-20160816;
        b=lw7FP5T0JVu0DgrrRzF4WZt2gbrd87Uq0HFKD6qZ4J3SqnTG67GQk9JGK6hbYWqJNy
         TpeJ2ndzL3nd2GYI3lbk48K89uB8NspGuTRtgk+Se25hGFW43WfaDr2HCKs5mhbBKmao
         kKEC/TgW6QRjW3vbREgwXGmL1/ov/CUVduBk9MvqnMPYsNziSIEtNqD6kYtJ0ADFr6lH
         psFzjFG7xZ6dmGYWm8CmstL0rW6dvsc7L7yry4l4hmS1an+q/nAxNzreczqRQae857Fo
         fGbiXX0hB6RT+hNhmiA5iOqcp82YKPzyLkO18hTVROwo7ZRaP1ImS31D/aKdv/2kqqUH
         IswQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:message-id
         :date:subject:to:from:dkim-signature;
        bh=+DONjuMeToQIGkF4W1B1y7kc/D4ILc6C+y/bgt8Yp8E=;
        fh=uQCsmYQr+KJEcG63Y45gsyDulzJl/B4EdEfpx8XrGGo=;
        b=nOw21nEFzyz9sGLLAb6apqlMGa5uMmJbPWEF0Fqrj/V6v0IhbL3FYbMwAC+FFdDJ+i
         vesAz9Q+95bdHDtCccSyeKPvM9hfYDgUCpBRZd/YbH2OtdAtYVJ8LoCYaLDaDHss+63B
         Iq4f2ieM2Wzd5qvn4MqaNCPoAqUcdcvR0BRS9lWH3GV15r1mKcqOentmiklJlJpSIqIx
         QN2oaYZDoV6jOuYw0tLV0SXHjHjYG2WHf/1TGr8c8kx2HH4iFXTXMp8ieSDDGwdbre4c
         QJfI4oW7koI6cpnJpVmQw3+IdpGXv/GDdAkiMrDwtctGTjM7Fv/L998uD4/d4IuScZiN
         8fpA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=jxv9v5zx;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id p4-20020a634204000000b005bd70dedbc3si399543pga.1.2023.12.25.09.44.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 25 Dec 2023 09:44:49 -0800 (PST)
Received-SPF: pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id 1873160C81
	for <kasan-dev@googlegroups.com>; Mon, 25 Dec 2023 17:44:49 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id BDEF3C433C9
	for <kasan-dev@googlegroups.com>; Mon, 25 Dec 2023 17:44:48 +0000 (UTC)
Received: by aws-us-west-2-korg-bugzilla-1.web.codeaurora.org (Postfix, from userid 48)
	id A71E7C53BC6; Mon, 25 Dec 2023 17:44:48 +0000 (UTC)
From: bugzilla-daemon@kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 218315] New: KASAN: use EXPORT_SYMBOL_NS to export symbols for
 tests
Date: Mon, 25 Dec 2023 17:44:48 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: new
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Memory Management
X-Bugzilla-Component: Sanitizers
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: normal
X-Bugzilla-Who: andreyknvl@gmail.com
X-Bugzilla-Status: NEW
X-Bugzilla-Resolution: 
X-Bugzilla-Priority: P3
X-Bugzilla-Assigned-To: mm_sanitizers@kernel-bugs.kernel.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: bug_id short_desc product version rep_platform
 op_sys bug_status bug_severity priority component assigned_to reporter cc
 cf_regression
Message-ID: <bug-218315-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=jxv9v5zx;       spf=pass
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

https://bugzilla.kernel.org/show_bug.cgi?id=218315

            Bug ID: 218315
           Summary: KASAN: use EXPORT_SYMBOL_NS to export symbols for
                    tests
           Product: Memory Management
           Version: 2.5
          Hardware: All
                OS: Linux
            Status: NEW
          Severity: normal
          Priority: P3
         Component: Sanitizers
          Assignee: mm_sanitizers@kernel-bugs.kernel.org
          Reporter: andreyknvl@gmail.com
                CC: kasan-dev@googlegroups.com
        Regression: No

Currently, KASAN uses EXPORT_SYMBOL_GPL to mark the symbols that are only
exported to allow building KASAN tests as a module.

We can instead create a separate namespace for these symbols and use
EXPORT_SYMBOL_NS.

This would work as a guard against external code accidentally using
KASAN-internal symbols.

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-218315-199747%40https.bugzilla.kernel.org/.
