Return-Path: <kasan-dev+bncBAABBFELUG4AMGQE3YTB7GI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73d.google.com (mail-qk1-x73d.google.com [IPv6:2607:f8b0:4864:20::73d])
	by mail.lfdr.de (Postfix) with ESMTPS id 7243D999458
	for <lists+kasan-dev@lfdr.de>; Thu, 10 Oct 2024 23:22:30 +0200 (CEST)
Received: by mail-qk1-x73d.google.com with SMTP id af79cd13be357-7a7fa073718sf186611785a.3
        for <lists+kasan-dev@lfdr.de>; Thu, 10 Oct 2024 14:22:30 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1728595349; cv=pass;
        d=google.com; s=arc-20240605;
        b=CoddX2yEHbaVF8rqqgqjpPlqa/SHpBeNqBT6MWNygIbZ9I4480IOis41S41lsZkL+4
         lMu/XqWUQaAABrO7rDySe2OinSXs6rrrwAc8yitkM97yMCKS2uyfyf1aSQOIWmdg1zkA
         h7UwMksnJLCCOcwGOxy97zyreY63vN6LQiW4AQLmtxvD3mw3nUqGlkfa1xcabp5GdDop
         LD2ZlRBxexi/OaKE3eg6m+NN++wdZYedSkBBmg8++WqWbErXRoKGkKuLlTrHGn26dUyj
         dnTYeTbi4/G00EvsqDK2sw+k3alYByKj3CECZn5Hft/3MVboA6aLsqdjyGlDx9UjnnBc
         O5Hg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:dkim-signature;
        bh=Q7p4iQJNDTw+cAB5qkA8PobuCKptQRMTOf5e5KxH/k0=;
        fh=uqxb87YxMirpNcnbGCQUX1mL0HH5IQqwzCU7wrfkBVc=;
        b=C3f6uOBNdhY/SFGnukwA+ImWp72BxjdduygHi1U64C2/buwvp0hPse5eTAzDWu01B+
         SOMBYSTKOF4riPywUduAtFG3/mDSZ3O6UGt6r06vKGWTdRsFK0WUgKu+I3K5ReGPxzWs
         deJPrd+8lR9kBfZ7qcYr+TuwyhWyA8UgnzeP85+YyROd67O4rgwrEmSpNCax65dPlGhN
         wSTvVSzgW7Il82K/KYQlharoloM9iAdDGBOeh+gL3oOJH+BpauzV6Gi+imdrdwbFdpsg
         DNDOvu6gk3HCrT5q7I0I0RJrXT4Ru5HHe8rNZ7FCPz3rEv5sT3302J3T/nB9hpXWMEjs
         DDRg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Ic87rNHE;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1728595349; x=1729200149; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:from:to:cc:subject:date:message-id:reply-to;
        bh=Q7p4iQJNDTw+cAB5qkA8PobuCKptQRMTOf5e5KxH/k0=;
        b=HrjpYDX6O+QOcKjB/l0VjxKS3IJEeUQmCgw7Sqf+s9B3w2IbfDg6OA0qnfBb2ZOs4I
         MrniktHSCnTeWmqdcKLoTqDF2k4uzCNZTg2Lawrs2qxX2d/p5EbjwJZTSkC+hevc/BG+
         GDZg4Fsopyf3ntiYaO4s83U0NBPfCa6LyHnktrJgmotRi4rBCc2oZWOppwvPZY0saf6t
         /9BYvYvx/ipApbyWqQIL2bhSExhjHOoVXa+GtvBF/jRgzV8ldINm3NX0mb03kwVI0/Up
         Pkbm4UeqoVn3AWgigVlB7Gij1pMRPq8dEWWZ+HXaV72ZyGN/HQP6uB7yLL22RdVJ0Z7S
         pRrQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1728595349; x=1729200149;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=Q7p4iQJNDTw+cAB5qkA8PobuCKptQRMTOf5e5KxH/k0=;
        b=al8mkzmXOb0e0vB6c0isQHKVlqKe9YMgtY52jOA/yzF8qoyFKoo1aMKVetGWa3HkRu
         4VTInfSqU3fJr1lP3Hv1w/ezYQJ0RY9qL9oE7af5v3+JTtOOgDHF0DILtLdzpJT6PoUS
         nrAjr82Gy7+Wg673IxD69bbeIAS59WAc6bAOAE3PAsmF7/STHBKJBQMcT52alEkUCTDC
         b6FElNhfo2vWpBHvsbklE0AJfkSU+jsXqapIED9X9tXJy7UJtGx++8TwH7PERH5ExVE9
         NZWiU7+Nr9/roxJjCbE2+Bq+C34Os6rBW+19BEorQvK8FkqJf2kQawATlmZgKlzneEMa
         ir5A==
X-Forwarded-Encrypted: i=2; AJvYcCVA6tndw48mlzeh1kfq4bTn03qBAUQ82oh3yieViLsWwG9CjLO8Akr7j8NmLmTr1V+Ndy6t2A==@lfdr.de
X-Gm-Message-State: AOJu0Yyd0Hc1gHcPz/OLcuGN+KdZLkol5GPXWjgwOwfirnciZ45CWTUb
	qHQ83DIOJPQZXaluan8sDcPptuz5UERVcXsh5SHRLjJqypVvmpVo
X-Google-Smtp-Source: AGHT+IGoJ6XGKssJqCUVPMZsPjXixIUpq6sUKqG4rTwY9s29ZNTACUc2j0oIlLoviV8yPqku0eR94w==
X-Received: by 2002:a05:620a:1724:b0:7ac:c348:6a55 with SMTP id af79cd13be357-7b11a37929emr58277385a.38.1728595348960;
        Thu, 10 Oct 2024 14:22:28 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:622a:114:b0:45f:a10:6c04 with SMTP id
 d75a77b69052e-4603fd57071ls21424401cf.1.-pod-prod-02-us; Thu, 10 Oct 2024
 14:22:28 -0700 (PDT)
X-Received: by 2002:a05:622a:291:b0:458:23e5:1342 with SMTP id d75a77b69052e-4604bca885bmr3956271cf.56.1728595348456;
        Thu, 10 Oct 2024 14:22:28 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1728595348; cv=none;
        d=google.com; s=arc-20240605;
        b=WcZQ4fd1QxsqfwfVKDfltWwR1b7cxIFqRvuuxxGZf4LMs6VgVIA6JZ3hlwpdU0y/gm
         u/KAWkAplWIDe0+RgwKyd/Iu6MrdQJZDC2heBRkSJ1/p0xn8JQiTzI6jgpGqIzonAJUz
         Joqhj0MAspmvAN+mJGokfs9xAAUOvu/kqGG1SdAUF2F7EcsepzBMEUGBqKfRJQXxK4K8
         G3QdAT2UgoA9aXkmHtc2X1iMBw1CGv/9TxUii4Yg+zHwte48Q3A6LUEQ+PJgZJFw1jrr
         LyZBIKpqzqwq5AB61bavt1I6Jr4METkjG4Kx+uUCAMPbTtEvNePVGjxU9vq84WDMce+D
         K4rQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from:dkim-signature;
        bh=0CNVN5TFk9eh6fjpUl+Wi6b1LtITTyv2lNCqmS/UVtE=;
        fh=uQCsmYQr+KJEcG63Y45gsyDulzJl/B4EdEfpx8XrGGo=;
        b=j3CP7yGkeCZXPPieJyFfKb0jfS5WfA0drGwStrvdx42m0mgQMDuIqjz6A+v4tW44Ft
         rsu/7HTX3vRfEScCGuGqMSFLvEDrNONTnBRoCu2z0GYP3wlbLuhnn3Ws0nUE3cMsvllv
         CmbSVHoIrLfTCVRN8PhW7CAwV6svpr2omjUNM0qxIGhB+uWLH1KGbI4VWKuWf51psBbb
         b804viijYKQff2SHKOdbIbx5DvhVX0HAeitVDcRkT2507ash0rziP+bEC7bgwK8LsEuN
         +WXFF7wBAe3u5jUojgSn5Z7Ec2MiDBeS0q6gOAKttoq0JIh8qi5ejuX6720knLJnko80
         NhCQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Ic87rNHE;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id d75a77b69052e-4604807bc45si762711cf.5.2024.10.10.14.22.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 10 Oct 2024 14:22:28 -0700 (PDT)
Received-SPF: pass (google.com: domain of bugzilla-daemon@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id A2BAC5C55D7
	for <kasan-dev@googlegroups.com>; Thu, 10 Oct 2024 21:22:23 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id A4FA7C4CEC5
	for <kasan-dev@googlegroups.com>; Thu, 10 Oct 2024 21:22:27 +0000 (UTC)
Received: by aws-us-west-2-korg-bugzilla-1.web.codeaurora.org (Postfix, from userid 48)
	id 981DAC53BC7; Thu, 10 Oct 2024 21:22:27 +0000 (UTC)
From: bugzilla-daemon via kasan-dev <kasan-dev@googlegroups.com>
To: kasan-dev@googlegroups.com
Subject: [Bug 218319] KASAN: fix UML build warning
Date: Thu, 10 Oct 2024 21:22:27 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: changed
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Memory Management
X-Bugzilla-Component: Sanitizers
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: normal
X-Bugzilla-Who: andreyknvl@gmail.com
X-Bugzilla-Status: RESOLVED
X-Bugzilla-Resolution: CODE_FIX
X-Bugzilla-Priority: P3
X-Bugzilla-Assigned-To: mm_sanitizers@kernel-bugs.kernel.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: bug_status resolution
Message-ID: <bug-218319-199747-QWh0d79CGk@https.bugzilla.kernel.org/>
In-Reply-To: <bug-218319-199747@https.bugzilla.kernel.org/>
References: <bug-218319-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=Ic87rNHE;       spf=pass
 (google.com: domain of bugzilla-daemon@kernel.org designates 139.178.84.217
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

https://bugzilla.kernel.org/show_bug.cgi?id=218319

Andrey Konovalov (andreyknvl@gmail.com) changed:

           What    |Removed                     |Added
----------------------------------------------------------------------------
             Status|NEW                         |RESOLVED
         Resolution|---                         |CODE_FIX

--- Comment #1 from Andrey Konovalov (andreyknvl@gmail.com) ---
Fixed with [1].

[1]
https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=6a85e34c4d07d2ec0c153067baff338ac0db55ca

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-218319-199747-QWh0d79CGk%40https.bugzilla.kernel.org/.
