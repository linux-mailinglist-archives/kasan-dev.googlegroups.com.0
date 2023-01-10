Return-Path: <kasan-dev+bncBAABBY6O6SOQMGQEN3SUKWQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23e.google.com (mail-lj1-x23e.google.com [IPv6:2a00:1450:4864:20::23e])
	by mail.lfdr.de (Postfix) with ESMTPS id 7DAB2663BD3
	for <lists+kasan-dev@lfdr.de>; Tue, 10 Jan 2023 09:52:52 +0100 (CET)
Received: by mail-lj1-x23e.google.com with SMTP id r10-20020a2eb60a000000b00281ccc0c718sf2532508ljn.0
        for <lists+kasan-dev@lfdr.de>; Tue, 10 Jan 2023 00:52:52 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1673340772; cv=pass;
        d=google.com; s=arc-20160816;
        b=TukILDnw07BYKyyjT0DefjYkDwNjJoL4CuL6oXZK44WUWkVjO3cXRt9inHhgBROnHL
         2WMhl/kZ7+Uo4Y5MJtxzvkLLBDHTu+Ci4gyeWoXFEHJc9blLAPWj58ck4JKyUv5Yb9BE
         Fl4Gfg6sdVXAJzzxuICoO9mtxsiYBeN0jl8mXfGOzp4BCRi0kHYcbW6OEhcUNPkKAz0V
         by0g9qio4sTDnCXR+p0fCRDtBwMuOuxp/1wO0+iDeuP/oUGB4uqxpJIy1uTzY2y7Yr5A
         LPKIxFuUs6E6H/jyN0bhkizXmOiDXlt8yHUyETgLkwcMjo2JFBitclmTn39+caWpoAhA
         ucFw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=N6K1HHXlqmG2qMUA6ESdMI9nLD2eSYwTwsNaDJSrm4w=;
        b=Bss79zZqqjExiE2wrR2eeUGIl2AyGd+NUnErPW0YdzYACNE7HGaR4ZWbzL8zJH9RaX
         F1jRF2PUw+ouDCtL+/ukMPWGg/w9kXlRzbvULots/EwJjh9yTfFf6jL6BF5Iok7UjDoD
         0E0eEYQpY4YBl7Lf9rRI/STRPuUHWHmKqnMwXknyEhkAMnt+h5IZ8K6Ktl+y7L2Qe/Vs
         S0vzt8nV8yukSpKu8DSdKZWz0+6xtJrCXakfgF+Bh4XIEcNe5TE0TcrwC2NlLWx0SB87
         YxaxysNO/AheGbAiVgKJSVMRp29/vu1WrX+o/2bmRWeA5GtjDf/RPxk7B1YwUB+/JSFO
         U05g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="i/g4xIES";
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:auto-submitted:references
         :in-reply-to:message-id:date:subject:to:from:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=N6K1HHXlqmG2qMUA6ESdMI9nLD2eSYwTwsNaDJSrm4w=;
        b=E95ef7qKO6I/8/dWdiy6tnn2YU0RcGla1ABMwp2braOTvIUOLV6HNK7uxR+3b0Jlng
         bx/4M1MmNuOy+i0veqrFcnzT25+4QRGSF0jtGGMjULlX7fTJfrlx0qQMfRrmQjOHbD8j
         E8XnLwA9UzYHzsef6lS2Wzt1xuHUgFRh3JHGr3p5Md9hbkXHgGQ5MHuo0iC0ATNBTAPl
         7SrsQw8fqmTLYnevYtCV/ZS+OvJa0S/syNWZdms2rPo+8vvsTlM3Cy7vTy0ZA/HBPSiz
         czP3azGFhzAkwWlixbkxgw5GEEVUaIDMbEIXmwTdBdlmw6Co+IHZrR0ycfMgm3dDsQbw
         XYnw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=N6K1HHXlqmG2qMUA6ESdMI9nLD2eSYwTwsNaDJSrm4w=;
        b=iBHo2d0XfnGuMN/5BpQoiPTAXO04LYNduFYbB9V+phytoDtW0zP7dFMkI3hxvAZu+0
         HjaN0vSxkDJPCwYGnrS4PcoJwjB8+cIdIaBzRR4txZMElzfeBxaSVanfgrAFWxHl+BUN
         EBgICT2FKrtEyOpzdTKCjfL9jSxts3cmx9M6V0m9Q53BcqKeLq/5+Abc76H3VOPri6bX
         AtBHs6K8JUahVAGvqWNoxb/c+l8tbSQ8t7oTcw2TA7GWbCemoTavZtTmOsdH+FUDu59g
         8HSfdqT70I4uP+Qh9dda/tFNB0Aql72+nZD5eNBJDve1yxDGsLXe5YhQ5JKO7t9/Xy4L
         0avQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AFqh2kqAcTTZ95qQYcdr0E9Cg1JcLtkDz4l/zusby1btSbjPBlOF+vHd
	5sSzlODaQs6RqY8HnHgIYFA=
X-Google-Smtp-Source: AMrXdXs6Wnoqbb/Fyk8gqVVALAfEPDzH1WFAkU7tYyilab45+gftoXbfRHWPsvb+aIsk60AzP3Ohmg==
X-Received: by 2002:a2e:a90d:0:b0:281:1110:9b69 with SMTP id j13-20020a2ea90d000000b0028111109b69mr1292145ljq.329.1673340771808;
        Tue, 10 Jan 2023 00:52:51 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:58f3:0:b0:49a:b814:856d with SMTP id v19-20020ac258f3000000b0049ab814856dls2593754lfo.1.-pod-prod-gmail;
 Tue, 10 Jan 2023 00:52:50 -0800 (PST)
X-Received: by 2002:a05:6512:6d0:b0:4b5:d:efb2 with SMTP id u16-20020a05651206d000b004b5000defb2mr21272761lff.14.1673340770908;
        Tue, 10 Jan 2023 00:52:50 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1673340770; cv=none;
        d=google.com; s=arc-20160816;
        b=dUBooKaI+xCwlh+SvcfxX1EnbAFPKTCyAND6qV2DEdG0Mry3HxYV1s2CfKqB++qAqy
         phXYUWeDkZrB53hDT5yH+vy/vSr7Vt6Zk5pjuQp7brxPIV+EvEd7Qk6OGzxNby2d/92P
         Mbn2Ry3a+YN7vijkMtLgc661q9m2XEDaG6A2Y9+xgV/5WrirKAMJ2ErbAynLnyArqRr+
         a35VwV1hwYvlzeuAoAojGG3LN5HLrcQW5QNuK6DgWfcddS8JwT9VOFJjL4xENHAlyOfl
         62jJCL2o9ja+Smacw3GFjnbR8qHnEVIiykX017//ap1Jhal6IAlaVYRbSTuwv0FLCoVO
         QF0Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from:dkim-signature;
        bh=kIxMVpfihlYKrrpPUPAY+M4skedJorgKZY8jaFdTzr0=;
        b=s0/IaJ3YKWkD5RBbH2RPPFrK/HChC/uVZj7lRM0g6QDjp+fTyQUpXJkM246scdd7Ju
         GTR3D1DJvAJVFthd6ZnpdsJZgfaCGUpnIraGSoojLmLs7e+rdnCv1rG+oIh+0dt+8hR9
         chdpGvHTQFBQx2c9dDZTFnR9Haoyh09umwnCo7cpCw48Dh26IxZff9H76v+E9jQ3avG0
         HEBEfv1kcsAkldI4nRxozp9l5yIVeHY0LxEsmTnsS0hwTyMI8PyZ6HZb+2UuJKUUtzuc
         zmnXBk3KaQnwNER+oZu5+bl5imrTS1VRQuOi+s40iGv2sjyfWh/E7v/sAQmZSQ8igyWb
         h6Fw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="i/g4xIES";
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from ams.source.kernel.org (ams.source.kernel.org. [2604:1380:4601:e00::1])
        by gmr-mx.google.com with ESMTPS id c5-20020a056512324500b004b069b33a43si446440lfr.3.2023.01.10.00.52.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 10 Jan 2023 00:52:50 -0800 (PST)
Received-SPF: pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) client-ip=2604:1380:4601:e00::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by ams.source.kernel.org (Postfix) with ESMTPS id 3BDD8B8117E
	for <kasan-dev@googlegroups.com>; Tue, 10 Jan 2023 08:52:50 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id 5FBB1C43392
	for <kasan-dev@googlegroups.com>; Tue, 10 Jan 2023 08:52:49 +0000 (UTC)
Received: by aws-us-west-2-korg-bugzilla-1.web.codeaurora.org (Postfix, from userid 48)
	id 5003DC43143; Tue, 10 Jan 2023 08:52:49 +0000 (UTC)
From: bugzilla-daemon@kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 216905] Kernel won't compile with KASAN
Date: Tue, 10 Jan 2023 08:52:49 +0000
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
X-Bugzilla-Changed-Fields: 
Message-ID: <bug-216905-199747-XQ9e7Didtm@https.bugzilla.kernel.org/>
In-Reply-To: <bug-216905-199747@https.bugzilla.kernel.org/>
References: <bug-216905-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b="i/g4xIES";       spf=pass
 (google.com: domain of bugzilla-daemon@kernel.org designates
 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
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

--- Comment #5 from Dmitry Vyukov (dvyukov@google.com) ---
Maybe we should add noinline_for_stack to ecc_point_double_jacobian() function
declaration:
https://elixir.bootlin.com/linux/v6.2-rc3/source/include/linux/compiler_types.h#L192

it's called from ecc_point_mult_shamir():
https://elixir.bootlin.com/linux/v6.2-rc3/source/crypto/ecc.c#L1396

Though I am not sure about performance impact in non-KASAN build.

Meanwhile you may try gcc 10.2. syzbot uses it with KASAN and builds seem to be
fine.

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-216905-199747-XQ9e7Didtm%40https.bugzilla.kernel.org/.
