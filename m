Return-Path: <kasan-dev+bncBAABB35M3GYAMGQEVG5UPCI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3b.google.com (mail-oo1-xc3b.google.com [IPv6:2607:f8b0:4864:20::c3b])
	by mail.lfdr.de (Postfix) with ESMTPS id EAF0A89EE25
	for <lists+kasan-dev@lfdr.de>; Wed, 10 Apr 2024 11:05:52 +0200 (CEST)
Received: by mail-oo1-xc3b.google.com with SMTP id 006d021491bc7-5a4873596e8sf6805154eaf.1
        for <lists+kasan-dev@lfdr.de>; Wed, 10 Apr 2024 02:05:52 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1712739951; cv=pass;
        d=google.com; s=arc-20160816;
        b=u62V1ChmAEetaYpy9Kr+ov+jzYcQqvOkTFDl84hIcN6f8E9IBS/n0J5d0W9EeVtHgV
         h68DCZoWJn2O9W2/EwTjmiwyNcluDFMaMl3bFrIWzf3Z94GIHdq0m1JRQi2HGzKv2XDJ
         /AA8oQAfwYICFBH5m39EiG9ntZ+C9hglMwVxwuqoejGan2L7oS858h8WkudjvHdHtXcF
         6f/qxeIPoJxNH1N3PjB0EadhOUoXzArHW51QPSnXDHfLlblyKYihpBaDwzIeDYG5GXDJ
         Wqw1ltbzjQWKOHA2D69TpxeiWHW99jghK+lTP0hXah3nTZo1ID2A9YOI7W2zqopP8y/3
         HXpA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=cdYiNkOVL8Ur2JP3RWrDQZEMgngoKFMOE6w5KFox/gk=;
        fh=0FegTbxVChHMTwC7tn3zx9OOkHkGUnxSyOPZA2YHzUE=;
        b=qCHoRQ2EtdY1BYfAt81iZk5TSmjEp0eo040NZl1xCW4KAonw/KWkU8FdQ9HfpNt0+4
         Mxp7hmkSGdzJpTi3FiE4G+OdIKRy90UdGq17t8LkcVcHiUfZ3d/oIQzY7w1Yh3lDfODm
         LKymd5DHRvpvVkCaaECNHOsOLtNXVDSHX5gyiZBNie3pJjLBmb1R8tmRwFEBzm9b5K/k
         F+qsYxUvA/BFT2TWxPedqKJPXbsMMVtzHY15u0WtGzjT/38K8qVz9AgUJm/c2FjzJGur
         ag8UrD0vEQ68Ujl2zdiSzEtxdsRvSXAeRAIzFdYhf+41cC0bjT4NkyGEjC4mgIj2dHNq
         4wIA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=GjkUuJfA;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:40e1:4800::1 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1712739951; x=1713344751; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:auto-submitted:references
         :in-reply-to:message-id:date:subject:to:from:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=cdYiNkOVL8Ur2JP3RWrDQZEMgngoKFMOE6w5KFox/gk=;
        b=P0k3Bg3Bp41QpSkXDgGjgwBd0/dji6r2eaz4bTmkuWr9ZHRwT2cm+UtqfZjGeEe4l4
         U2mFYuNjOVanoeurIfRbRqxBL39nD0bV5YBAgkLkHgKCH/Oev2n9B1UM+McAhaEmRedI
         SKDD/t0KNXzXM8kqOKJIrOxJ3vgTWDyVQ2X8XiESyk3BB3bqu/u8oJmPlQpJ84Z3qJo+
         UUQM2Vvxy0CWOWY7JILPdrPnel0PVWzYIpH2bdaJEkDzYtZmQdlaDtKOp2vJbxU+A/QL
         cQnnoj41mDDMybn2SV8gGA2jxLFdGo02bEqYrj530dZUhNQlN3QCBaUnbDSC0n1hUUUw
         pzSw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1712739951; x=1713344751;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=cdYiNkOVL8Ur2JP3RWrDQZEMgngoKFMOE6w5KFox/gk=;
        b=noeLGgF9mrYBpB+grCGRhSjNnnt/a3UH5PJb1ALJkx1Cny0bO3oTfCkk4UxK0EIHix
         wC5PxVFGm0gdV2OVaLE9PZeD4apm5p0vXw0sv5FF/PjmYgiLiAlEw3mQvI05hYmH0rPv
         MyREH7PIrgJIKEzaXnmFBvVneSXDtUTKULN8v6BpXlphhJXZNxuElBS8Sy1E2BAvrDQx
         ZIuWWvelETVmXnO7c0TtgErAAZBckAjVQc2Crh/guw+bdyWmOLTvS2K1Q3dwufgRkzFu
         I+b08dOskEulzwKxp8ogcKzNkruFI6fO7EOYkYlYXP7pqBHLWnNTQzBIt63Ta2RJIKMh
         33Zw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWoHlaFtm7tPyH6QABCPmAutKEh9YIbwg7lKI7nzxHoT6SK6aAMoSHK/BvzNNTxDJEbrEHI9sJwvrOmJ8Ou2nwh16UnAdnLDg==
X-Gm-Message-State: AOJu0Yw563Xuv0qW2YRhGzAOzwLTlGd68RW9rZxLq1KESB9Li+BHmnPs
	X7yGJnT+r3df6q56duEU7VmJ/gMnUSvj6sEM/PiFjs0W0aNLOFJS
X-Google-Smtp-Source: AGHT+IFu1bcKwSJ8WLLXoQ5VMwKo6xG01a8MWQ9WKcvdovoCH3BsCbqxYmh+dMqV8dqDH+iDfCDrjQ==
X-Received: by 2002:a05:6820:1e0e:b0:5aa:6462:dab5 with SMTP id dh14-20020a0568201e0e00b005aa6462dab5mr2147475oob.0.1712739951569;
        Wed, 10 Apr 2024 02:05:51 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:8c0d:0:b0:5a5:68e3:9cc9 with SMTP id u13-20020a4a8c0d000000b005a568e39cc9ls1540425ooj.2.-pod-prod-01-us;
 Wed, 10 Apr 2024 02:05:51 -0700 (PDT)
X-Received: by 2002:a9d:6a5a:0:b0:6ea:1001:f077 with SMTP id h26-20020a9d6a5a000000b006ea1001f077mr1949540otn.9.1712739950999;
        Wed, 10 Apr 2024 02:05:50 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1712739950; cv=none;
        d=google.com; s=arc-20160816;
        b=eCGHoAe7v9k3GM2YZ/zzu4VUmoh2DrfVesisti51K5CrLZ8RuTn2i8yfUE4srDHRiy
         4nFkBKTgEixI9Enaj/XJlvFH+I+q1DJRUNrpEL/K4ydxoWJ3jJL9nLN7/ag+ng8dqCFI
         jhNpyscO9kWN6ogP5xQoqqa0nybS7gW8BGlZSeoHweoK/Yq23axT78yeL0zu4OCcrYwK
         KhF0PnQ6JDG/GOzOhaIP96LPpXfvX7y1tvFT9eVOuWIpbx72c1WmQLK9B/s3tDBk8k/l
         txzA4yIPY/9vEq2KtcDYMyyOxK02k1ZhtsAr1Xk3OW5vZVdZ7ZowjYVNI9IPaf+nlx4/
         RrjA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from:dkim-signature;
        bh=BSX9uRB2NngiKcOwGp4I273nCSHXUvP7wSKuWrazbHo=;
        fh=uQCsmYQr+KJEcG63Y45gsyDulzJl/B4EdEfpx8XrGGo=;
        b=X8JjR0mDXZgM+OHqNS2eN+31oEBOLJUEID9WJ+XS/3807l/uab/vqHEhqHTkKxYnjV
         UAEqjIuysZDpshyaD2q8CZIMP5cf7xSYmiU+QKxLalyTEUckvYdkH6fs7a8eCHtAPNAP
         8JMJSO0DtDecQJITLPddPg2uWlSfGatU3zKVRH5WHcYQDIpC9Si2yWOKP5gh419Gq94+
         0JdHXZN2azJmaDedGWT7xHDltx+RJSCiGYiRLJ1ygVBW8NsJaLlYc+tiXvG37UNL29nJ
         Atxle2vrcyYB6Dh75TgURlfpix/CfSoDfugOwoPjuwpixnstmIkp2wffUz3vSKkBO0b3
         TgqA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=GjkUuJfA;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:40e1:4800::1 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from sin.source.kernel.org (sin.source.kernel.org. [2604:1380:40e1:4800::1])
        by gmr-mx.google.com with ESMTPS id bf13-20020a056830354d00b006ea0b56baf7si563782otb.2.2024.04.10.02.05.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 10 Apr 2024 02:05:50 -0700 (PDT)
Received-SPF: pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:40e1:4800::1 as permitted sender) client-ip=2604:1380:40e1:4800::1;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sin.source.kernel.org (Postfix) with ESMTP id 8F57FCE25B6
	for <kasan-dev@googlegroups.com>; Wed, 10 Apr 2024 09:05:48 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id CE2BDC43390
	for <kasan-dev@googlegroups.com>; Wed, 10 Apr 2024 09:05:47 +0000 (UTC)
Received: by aws-us-west-2-korg-bugzilla-1.web.codeaurora.org (Postfix, from userid 48)
	id A83CFC53BDA; Wed, 10 Apr 2024 09:05:47 +0000 (UTC)
From: bugzilla-daemon@kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 218313] stackdepot: reduce memory usage for storing stack
 traces
Date: Wed, 10 Apr 2024 09:05:46 +0000
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
Message-ID: <bug-218313-199747-H7NCEbCKBQ@https.bugzilla.kernel.org/>
In-Reply-To: <bug-218313-199747@https.bugzilla.kernel.org/>
References: <bug-218313-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=GjkUuJfA;       spf=pass
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

https://bugzilla.kernel.org/show_bug.cgi?id=218313

Andrey Konovalov (andreyknvl@gmail.com) changed:

           What    |Removed                     |Added
----------------------------------------------------------------------------
             Status|NEW                         |RESOLVED
         Resolution|---                         |CODE_FIX

--- Comment #6 from Andrey Konovalov (andreyknvl@gmail.com) ---
Marco reintroduced compact stack records for users that don't rely on eviction
in [1].

I think we can close this.

[1]
https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=31639fd6cebd4fc3687cceda14814f140c9fd95b

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-218313-199747-H7NCEbCKBQ%40https.bugzilla.kernel.org/.
