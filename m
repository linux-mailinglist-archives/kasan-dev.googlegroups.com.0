Return-Path: <kasan-dev+bncBAABBUOIUSVAMGQE6TKWQZI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x40.google.com (mail-oa1-x40.google.com [IPv6:2001:4860:4864:20::40])
	by mail.lfdr.de (Postfix) with ESMTPS id B6B767E2B08
	for <lists+kasan-dev@lfdr.de>; Mon,  6 Nov 2023 18:37:22 +0100 (CET)
Received: by mail-oa1-x40.google.com with SMTP id 586e51a60fabf-1ef4f8d26d2sf6330294fac.3
        for <lists+kasan-dev@lfdr.de>; Mon, 06 Nov 2023 09:37:22 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1699292241; cv=pass;
        d=google.com; s=arc-20160816;
        b=NPd2Y4Ssqn9s2VpGhS9CtZK3mWooKbGnP4L2FuneLWh21cU9kE3POT/F6TRj25gI0h
         f4MmoCNqUvg2XxBz49ZNz8rqORNr17vVenbsjNH3qy/xEdxDL7gdRMYTrMW+WSzxG7eQ
         INFEP/2eyQVXAb93GZ4MYf4Ks4ySMttSUTNeRTyfYdtxTlJpBPXnYFpt0wLctzmYTabX
         kKqlvGPEB7wJdMf3KWczMwmJjyY8Ev0CY9lg7WnQqgGvOd7/FI6p8lta6/AXanIggI83
         /4tSyumvAh3FJWjt/3g/K3DG0i129i+XBvjWSRNdHdpaIIaphSdtrFQosHYdQGU25FN4
         v9pg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=i/U66ipbgMARMI3dtRmZJfxdFwbXSn9AHUkBAFQl1Cs=;
        fh=uQCsmYQr+KJEcG63Y45gsyDulzJl/B4EdEfpx8XrGGo=;
        b=XjdMYRTZGEye1c9Tw5Hk91cPwhnh4rO4Sp6pzSLV4d6OhAr6OCLtBb+7higWNQbFkY
         4bKP8Yw2K8BLC2JX8d/7PIuUUpPmfyEsX7QvRYOyo8N7bMEwT1uc77uRY90yzSm5a3sc
         OFhsuCuyeZF2V3ujuc2obRNM/DhW1zvlfLrvhtCFyRQVVnimynYxxnFnGij//sfkGQ3f
         7u62TgzeJunV9A8WNN0yHqa1sJILMfNOkk9aT20D228cPDRBKGbTT1QmtzH35q+X+3jO
         /op2E4pmtVdc3qEAZbbAWefaaUbZovdbObNOQuv5vsf707pT6bCW4S7JAxMth3nskCbl
         vD3w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=gD4O5cTh;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:40e1:4800::1 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1699292241; x=1699897041; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:auto-submitted:references
         :in-reply-to:message-id:date:subject:to:from:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=i/U66ipbgMARMI3dtRmZJfxdFwbXSn9AHUkBAFQl1Cs=;
        b=S46RCiRgj/tZaRfzSyxCseGc6yurO1ARWrOiKBLB8yEHpa+IHPRsJtvhy02qtWaRAU
         Jdt4RrqpqrE56Hmj3WprTazuVqnhsN7XLBPch4OIwWKhk2ghzXT/vdk/1bJmRSCso/G6
         PvGi5vEcZ8s5hF31FFoh68mfZdWRLHBnPT2FdsBWSfiiFlQ6JeAEamnVnGnnpidbWEpk
         rrTVSUtBQcx2xSFqrxXs+LjQa9HM56ZRWUEst1OkmpmI71sprCL6oGPUDjUjdOZt5KZR
         1B39KPbU5PEeH3tUFD2O0N8T1fJQiWF9o96nbHcueWTtMKlsTRzT2QL7GF7JGKmCYaOb
         zxXA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1699292241; x=1699897041;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=i/U66ipbgMARMI3dtRmZJfxdFwbXSn9AHUkBAFQl1Cs=;
        b=hfdMwpyHQlD1RimQdYmIfd4HhoJKaGE2U4r9rfIYG6egyLjiecciuXqWzPObBs2VBs
         jRd7nBbMlfo49uAlrK8n/2Ea972PYWySgnBNIKlh1HB3JXn5W8d1rtc44/QsYkJiNJDD
         r2p1YUcKYysTCF1NiMdhygRACLmsG0oEBJdMekkQUse7aj3/uUxe5tQZvbXC4Uc8KGlG
         EKzNVUKd/2eFmwdLRu56WH16rWS0wV1Ci8iUSxQny3laH1VtbRfCa4XxTkpFKp4ICYOv
         7s5UMsnGG7HdYJnoGWwbXtELoGSCqbxpiQQOCKTzhSj05ZGvCHrgG4OyH5L5ANiH+0XC
         aQKg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yy7lLhtLKHOnBm/BONVIZzevv4QOUkJebu4f1uJUHskraYr38mx
	STkkEFq24tXYGF5wMq5RTK0=
X-Google-Smtp-Source: AGHT+IHfuwLTt+xXUkbidHcWKcelZXfY+XOy5rnKM3SgCbnZKHTOjcBPD30SqIo27qXvYaJMA8h6yg==
X-Received: by 2002:a05:6870:44c8:b0:1d5:8d8b:dcc with SMTP id t8-20020a05687044c800b001d58d8b0dccmr529722oai.18.1699292241118;
        Mon, 06 Nov 2023 09:37:21 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:6c14:b0:1e1:5989:cb9f with SMTP id
 na20-20020a0568706c1400b001e15989cb9fls532889oab.2.-pod-prod-04-us; Mon, 06
 Nov 2023 09:37:20 -0800 (PST)
X-Received: by 2002:a4a:d038:0:b0:587:873d:7e2c with SMTP id w24-20020a4ad038000000b00587873d7e2cmr7693958oor.1.1699292240337;
        Mon, 06 Nov 2023 09:37:20 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1699292240; cv=none;
        d=google.com; s=arc-20160816;
        b=ua/vv6AAp/q/YUoR2LHoAqrdDD7hQI96V4UX/tqr0JkN0UF28ObaE8E9j86Fe0shU8
         rqesJ11YkMUjU8mMTIMrTkII6RTlvWaxOKDQnsIhfutzfaFSJRlRN2/BTTNSBp9mIxL9
         uhcWt+u4Cn9x3iZDfhKaZURCDWdxgbAtotzAUP/9y1Ujr75bo11+4OrtpK2Rr/fKgYaV
         kROULbIRKK0iSkIWrAxzTGbqBBO/Ij2TApyES3qRdzdo4GUZEAe7lfJRAgUSJ91UVubD
         YhjJiQ/u9gCQ8uJazlyz0l0IG7AxHpYmir5mz1k3ayi2pHpLFNTey8vWcRu9xOxKzLK6
         eA9w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from:dkim-signature;
        bh=KMSx3EdzxKgVX5DPiSczMq6XKL+CNGhvxSAJKAFsY6Y=;
        fh=uQCsmYQr+KJEcG63Y45gsyDulzJl/B4EdEfpx8XrGGo=;
        b=qIIcFiZH0X1kN6fL68cxd3AFZeaOHTfmZX1prhBI9aOeGQxnbGiD0V6STNFgLqJDnG
         y+zzsiQISrQ4+RTB/iyWQTE/A5JRPjKjA7P8yIcjcbeOPjQlH5Zh+nd6hws6GwlvZfhu
         cvS1uEMRZC6cYiJGcKJAx5qMt8pa/FiRHnUYvjn8wXsGHcZoPoeS+DFMYdqCDd3DtmTr
         vI+Wftw3C/tGCATkSTGV/Xhs+Q3h3Ho4yeNIM5K2fzOZgIhC2ERb1CrS+buo+VCUG0Us
         VyIpB1bY2iEE+VikUk19gIiE5Bm5jacAiBpsiiIXjAj1DJ4OqnrKdBpbVEyf/EHoCRn5
         ypmQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=gD4O5cTh;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:40e1:4800::1 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from sin.source.kernel.org (sin.source.kernel.org. [2604:1380:40e1:4800::1])
        by gmr-mx.google.com with ESMTPS id b11-20020a4ae20b000000b00587abe0a6dfsi296844oot.0.2023.11.06.09.37.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 06 Nov 2023 09:37:20 -0800 (PST)
Received-SPF: pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:40e1:4800::1 as permitted sender) client-ip=2604:1380:40e1:4800::1;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sin.source.kernel.org (Postfix) with ESMTP id D0BC7CE0DFD
	for <kasan-dev@googlegroups.com>; Mon,  6 Nov 2023 17:37:17 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id 1968EC433CA
	for <kasan-dev@googlegroups.com>; Mon,  6 Nov 2023 17:37:17 +0000 (UTC)
Received: by aws-us-west-2-korg-bugzilla-1.web.codeaurora.org (Postfix, from userid 48)
	id 04974C53BD1; Mon,  6 Nov 2023 17:37:17 +0000 (UTC)
From: bugzilla-daemon@kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 203967] KASAN: incorrect alloc/free stacks for alloc_pages
 memory
Date: Mon, 06 Nov 2023 17:37:16 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: changed
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Memory Management
X-Bugzilla-Component: Sanitizers
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: enhancement
X-Bugzilla-Who: andreyknvl@gmail.com
X-Bugzilla-Status: NEW
X-Bugzilla-Resolution: 
X-Bugzilla-Priority: P2
X-Bugzilla-Assigned-To: dvyukov@google.com
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: 
Message-ID: <bug-203967-199747-vfxKuSYjsr@https.bugzilla.kernel.org/>
In-Reply-To: <bug-203967-199747@https.bugzilla.kernel.org/>
References: <bug-203967-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=gD4O5cTh;       spf=pass
 (google.com: domain of bugzilla-daemon@kernel.org designates
 2604:1380:40e1:4800::1 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
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

https://bugzilla.kernel.org/show_bug.cgi?id=203967

--- Comment #3 from Andrey Konovalov (andreyknvl@gmail.com) ---
Also see https://bugzilla.kernel.org/show_bug.cgi?id=216762 wrt detecting
page_alloc OOB.

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-203967-199747-vfxKuSYjsr%40https.bugzilla.kernel.org/.
