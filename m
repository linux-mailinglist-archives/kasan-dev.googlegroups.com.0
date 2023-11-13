Return-Path: <kasan-dev+bncBAABBVGUZGVAMGQESHXTQQA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13b.google.com (mail-il1-x13b.google.com [IPv6:2607:f8b0:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id CA3567EA2CB
	for <lists+kasan-dev@lfdr.de>; Mon, 13 Nov 2023 19:26:29 +0100 (CET)
Received: by mail-il1-x13b.google.com with SMTP id e9e14a558f8ab-357c8d93b1bsf48048925ab.0
        for <lists+kasan-dev@lfdr.de>; Mon, 13 Nov 2023 10:26:29 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1699899988; cv=pass;
        d=google.com; s=arc-20160816;
        b=xwzwseXwXFBwnUm1747M0pR7b3upItl9YNhXvIu5MH+EeBUgTosGvP4ynguzMCvA6l
         GEzxia8mve/hVeOD5S0wow8BhlISVTKrZxGLgqfAPiGhEMZj/LnLPKXpf6aoOTiAlViL
         f7zfNgh44EMi5l2RPuYAggz716lAuLDQ/kSNi0lXVb9Y6qvf0k5jGZisHtynXtWvWAZ9
         CTxjp2Dxkn+CJg17yFH6UuXk0a3pymafceGrE90R4gEfDGZQ83295RuLF5gCSdyhEozh
         6g6YlLipuOALOf5yTchPvnwWOhT9XLdXB8TfvpSPBJKIBXZJWjKjH5ZEz2R4YqS4m0qK
         wKsw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :content-transfer-encoding:references:in-reply-to:message-id:date
         :subject:to:from:sender:dkim-signature;
        bh=AIhxxNzdHdV4vXIBeiRatbt4m/xFP/Yj5yYEw0Utlpw=;
        fh=uQCsmYQr+KJEcG63Y45gsyDulzJl/B4EdEfpx8XrGGo=;
        b=KWso7EE2gbvi62HkB0QIgSjG+mkFh40VIMlV2T06mS61/LWpo0CqKvMrpFM2MjC+f1
         5VslEqYIT4phA/y0uRYVvua7nfWmv6lLh2gwUletZ2vVs+JNOY7haS+NpM85dnSAPiTu
         TMeA56RMdWC5y2j3vlZBGp6UV51h7EWCAeFR+DtF/q7pe1jC4FegVrQp5FO6McnyHZ/J
         C1AIJw48dRQ8ggQ5gge3Fxnw0mTPOpcEfimTstBe42hPlZV40EsCBlndGlfHSgH9jtCn
         SkHeIlAOj8EBBUtkLg0eM9gXKAQzNctxrzG8zNCBRtHOdKf5Ogi6+zF7uZf1H+xSnDHc
         zZDg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=ZYFmLPqh;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1699899988; x=1700504788; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:auto-submitted
         :content-transfer-encoding:references:in-reply-to:message-id:date
         :subject:to:from:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=AIhxxNzdHdV4vXIBeiRatbt4m/xFP/Yj5yYEw0Utlpw=;
        b=JdMTbUKrEQ7ZLa+6GuFmw7w3/vFOVATkCksKTErvz/HyUH0qMEymAOsZxuhVokndDb
         1NI3+eXxMgScZLpehO0ANFgYschddvGQd07GwbY3EQZF/Tsh/KpeVCMpCbavT6P5hH5n
         jN7q4IlCxeGjq0nwBu2kOimlU+n+GocwnKxjI6JiEih2ohUcXraBLwmmKQjH81BXYc75
         NRYExR8fSI+1qSGjxUs31inqeL7gVnh0YRu0XzhvzZkDRolEOXwPCgoqGbzDP7yyZQXV
         MBtBDsznfLPFxM1DMKj442Gb5fRbeDkChFwsR+uCwR6IS8Qci5h1CJ7RJE1YpmlzWCX/
         tYDA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1699899988; x=1700504788;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:content-transfer-encoding:references:in-reply-to
         :message-id:date:subject:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=AIhxxNzdHdV4vXIBeiRatbt4m/xFP/Yj5yYEw0Utlpw=;
        b=RZkBX8mFkuHkhAIPFnHNXujYM4tlcz0xzRUmba45NhapnWrp78YAyo28JxhU+Etd3A
         ZrlP4WP31H0zgUGACo+LoLMzIyjRRwgcxdxK25GjniWzNe1WVDhl0Yn1YOo8Vm4Wah6d
         g32TcQygCkimY9qCfqjG7JQUelwxvUJyPzmNDSzuqUJa+7RdfSDI1xXXMwQ4+/xmjQx0
         Gp69lykBiWW5fJ6XPCsEtwUB1JS8fhwQcdnOnnRv35ve180AVyFKE0pPz6ijFaQCinsP
         61S8+T7fB9xdImBhG93faUHA36PLtkQqmh5MI3IAo2ED7sBrOJ5FzoPdNDdDX0XmN+H7
         zf8w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yxekie0xfNju0zdBDqq7fY0SLj36aZaLqejLlkfjfpD+KScAV23
	xm5DMcKRG8TMGwcGTmdtFpI=
X-Google-Smtp-Source: AGHT+IFh4EWEURNOQfp53ZyL9KbifvN9iyFOVY6cRoJfDNst77/nnUPOhJtv7bxDf/qKMBKiwP/pNg==
X-Received: by 2002:a05:6e02:1949:b0:359:6116:4d9a with SMTP id x9-20020a056e02194900b0035961164d9amr11562063ilu.7.1699899988140;
        Mon, 13 Nov 2023 10:26:28 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:3702:b0:35a:a617:5f3f with SMTP id
 ck2-20020a056e02370200b0035aa6175f3fls2144659ilb.0.-pod-prod-09-us; Mon, 13
 Nov 2023 10:26:27 -0800 (PST)
X-Received: by 2002:a05:6602:4185:b0:792:8d16:91ef with SMTP id bx5-20020a056602418500b007928d1691efmr10904014iob.18.1699899987221;
        Mon, 13 Nov 2023 10:26:27 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1699899987; cv=none;
        d=google.com; s=arc-20160816;
        b=FHYtEOzXFo7YwZtonNqfExE3Eep9fljovNVS0bzJRimB7nkODI+NF+bQacYHY4q/dt
         SsbotWq7Y3DmbK2KhUGM8spYdILGxI504kx+/cV52drqpy460ZyDENQiI7SS5OIyd2mF
         LEKxCoI8cYQ5c+Bmlfi8/54t9g2f6hpXcO89VnyIyebGLG7TDSksHPp5S0E3JlNLhG6t
         OF0NjhydWrfvzYDhbqCiaFgHcnPUHfMo2pa4wfM7EL9UIpxliVCAYRTD4sZl7eY3LWNq
         QQHzxlu2p0COzAlNpCwVONim7ubE17ey9qP8WbnL00IZa4ynIQIc8Upqw7hiBoTnsFQy
         kU8A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from:dkim-signature;
        bh=qafGQKEM7JrKj1wK9gsKb5CyBz2DQfHWn3YcQo8wP/k=;
        fh=uQCsmYQr+KJEcG63Y45gsyDulzJl/B4EdEfpx8XrGGo=;
        b=ZkFQDrv89SSyWWfMDyzCo3xfe0+jfu8muG0wnFccDoaEzw485v69bYltlS3WvkpVhp
         7GZMhB8KLd2Ule4vmFsJXP76M8cS5eLR2J4ou7ZJbaa3+aT8MH/KQZgHt0v8iN6r3zcp
         +0PYfXMosx8iTt+Io77fGhdVpAu9jhv6z5mXkc0LGB0C3raCiQC5puVMoah5kHHe2b+9
         wYyoLcg2ZaEZPHkq3HLfJI1JE3inKf0ZXoiDnrx6UC+dtxcoKCS7IPxs6mHdLdx4n8RX
         ZUEOKnl6EwJk8x2ry1opCteKkzA/wM6iKZSyKx+oj/SwunY+ADIZ9UsigIWlFzE8tU4Z
         DLKw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=ZYFmLPqh;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id 197-20020a6b14ce000000b007a692b26f2bsi550317iou.3.2023.11.13.10.26.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 13 Nov 2023 10:26:27 -0800 (PST)
Received-SPF: pass (google.com: domain of bugzilla-daemon@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id 997EF60E95
	for <kasan-dev@googlegroups.com>; Mon, 13 Nov 2023 18:26:24 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id 47168C433CA
	for <kasan-dev@googlegroups.com>; Mon, 13 Nov 2023 18:26:24 +0000 (UTC)
Received: by aws-us-west-2-korg-bugzilla-1.web.codeaurora.org (Postfix, from userid 48)
	id 1E509C53BD3; Mon, 13 Nov 2023 18:26:24 +0000 (UTC)
From: bugzilla-daemon@kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 214055] KASAN: add atomic tests
Date: Mon, 13 Nov 2023 18:26:23 +0000
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
X-Bugzilla-Changed-Fields: cc
Message-ID: <bug-214055-199747-UAgp2kRgLd@https.bugzilla.kernel.org/>
In-Reply-To: <bug-214055-199747@https.bugzilla.kernel.org/>
References: <bug-214055-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=ZYFmLPqh;       spf=pass
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

https://bugzilla.kernel.org/show_bug.cgi?id=3D214055

Paul Heidekr=C3=BCger (paul.heidekrueger@tum.de) changed:

           What    |Removed                     |Added
---------------------------------------------------------------------------=
-
                 CC|                            |paul.heidekrueger@tum.de

--- Comment #1 from Paul Heidekr=C3=BCger (paul.heidekrueger@tum.de) ---
FYI, I'm looking into this.

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
kasan-dev/bug-214055-199747-UAgp2kRgLd%40https.bugzilla.kernel.org/.
