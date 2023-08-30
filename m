Return-Path: <kasan-dev+bncBAABBB55XWTQMGQEJARVJ4A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43b.google.com (mail-pf1-x43b.google.com [IPv6:2607:f8b0:4864:20::43b])
	by mail.lfdr.de (Postfix) with ESMTPS id 629FA78D6ED
	for <lists+kasan-dev@lfdr.de>; Wed, 30 Aug 2023 17:21:45 +0200 (CEST)
Received: by mail-pf1-x43b.google.com with SMTP id d2e1a72fcca58-68a3f3f1e56sf6246190b3a.3
        for <lists+kasan-dev@lfdr.de>; Wed, 30 Aug 2023 08:21:45 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1693408904; cv=pass;
        d=google.com; s=arc-20160816;
        b=ToiC3rFVuvZFr14pCWfkhDgLp6kQazZ7pkxX7P6k/GNe00g29KsUWDqY+iW/RNE4Yt
         uBgrxugc4YQ0+csLxSolwBnSWoeeJ0PnjM9ksm0ggB2rsDO8rkKMG6CcUzEt5YU9hi4A
         BYW6TurH1RNhsjZINnp9vyijzyqhdcVPntr7jzbn/T/QugALpMa9hmTNGDhbuq/r4Z8/
         SDuMPGQQ/ywIlEC7VJ9jiW/9qikXpo66BLBK2i67HKd2/36LG2RbW9BT/VlDCyDgbwIv
         UrjillE2B2G7Wbmf7tMW2wkvhB1pdoM76Repjylxl2ZopF4yenPqfdM9XQPXtADX1t+p
         2Peg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=R6RxqsLGjtfDjfSaD++aKrxnk+LHPOXnqSfV8sHtv8Q=;
        fh=uQCsmYQr+KJEcG63Y45gsyDulzJl/B4EdEfpx8XrGGo=;
        b=niuqUObbivQ01WxI67P5QGGLEsOEiY8t2ltkT45bZFhkdaplPUQYPUZ7ZQRdxDYaGy
         bAOxjLLQs2D3xXzBTj0JsXMIP0dYuJZS/Er/vw7Qn+N/r3CdFOLP/xSVKToTvaXWj5VQ
         MXs+/sN8usBK6F11+PJq2iB8/FsXH7J9HFjLyuQUt5VNh2e1gc7Irxw7Wg48sxBAXVi2
         jGPEiz+gjv0vKkEC4olb0nr6BtaUCtu0iBKI+s3p77Qx8WoGM0DtLy38JusQDsfHsqdd
         RjiIRg00lb6Aj0ItixDePP0vrfqgx0RDOAtjnnAbrHkf4bmx4DkgLta1VuVLQPeO9t1P
         k7Kg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=bCUsYqOg;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1693408904; x=1694013704; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:auto-submitted:references
         :in-reply-to:message-id:date:subject:to:from:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=R6RxqsLGjtfDjfSaD++aKrxnk+LHPOXnqSfV8sHtv8Q=;
        b=HCGojtCtsT7cXLgib1BFbJyItQrGDCsSXc9r08FXluU3EW6jcOS6VCFmMgTcZJsHUD
         LnBsApPLymTnhONpGeJhYX16dCgfxknKxQ8z6NeZSl3nJK3DMvl3VW5MYqMzA/PxSqX1
         kPgzfJIwmoq8P++1K7yKwqgWp3n1n5ZTtIBMWz0xe28mUDCeidi1omUYxcFFQDJAHTDW
         0jzz2/L8b/yRKsGC6x9AMjNl6h0Lccf3FwfR0PSm3O2eKcNGae1UBSDTx/frZfFmZ/SY
         GRXPX1A7meJqaxcGXhzf3FOcZD2rmzk3EpX2e0CTvX42rJ/nKD2DC2RFaRAH6jkX7SUb
         ziag==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1693408904; x=1694013704;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=R6RxqsLGjtfDjfSaD++aKrxnk+LHPOXnqSfV8sHtv8Q=;
        b=h6pv3sESd8jbVYHn0qD+k51Jb1j7q21pVzd45+3CKjHvgZ1Q+3yCmn0Ba1tJUuSXqP
         BWlwQkwRf9p/VrfkkTjwQYcQAegsD3hlyaCSs3JogHHIlsQjkwJHaKIhOyKoUFT+1NEF
         asoWrHjhVYzL/xAerZMzzcJEm+sEYWxHS2VGUJdXsj125n7MC67XwJNqKZoaDz5nf3WU
         1vrszeNf6YRx8yQntGBl2xKMeEYs3Wcq17ktQdtibWo+Hm9PL7wspUEAqfM3PjVhcYck
         pfYYyUpmcJkWYFarcRqnzXaaSA/lYc6VdIpKuiVflGyCUZWxoMsAiK5LPUIsLICW7PwZ
         S4uA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YyPJ9625SGMPUBk8QaUfyVCZMMGJgWGCDuBKrj0/V6Lj/3KZdSx
	LxMRx0T43Nqe7kKIW3Pk2maUSA==
X-Google-Smtp-Source: AGHT+IGa7u/bWz/SnnainDB8+b+xyZN02Uu4Jpd+mX977T0unNLCiznn+2YDDK4d6dxr+bR/YNdFYA==
X-Received: by 2002:a05:6a00:1949:b0:68b:e578:6645 with SMTP id s9-20020a056a00194900b0068be5786645mr2948985pfk.27.1693408903726;
        Wed, 30 Aug 2023 08:21:43 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:96ef:0:b0:687:aeb9:7e85 with SMTP id i15-20020aa796ef000000b00687aeb97e85ls4159286pfq.0.-pod-prod-01-us;
 Wed, 30 Aug 2023 08:21:43 -0700 (PDT)
X-Received: by 2002:a05:6a20:914d:b0:13a:43e8:3fb8 with SMTP id x13-20020a056a20914d00b0013a43e83fb8mr2908010pzc.54.1693408902853;
        Wed, 30 Aug 2023 08:21:42 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1693408902; cv=none;
        d=google.com; s=arc-20160816;
        b=K2igzJxRa3ftfQrv41vlgMs5KCoL6c5CL6uEzGCJHZeYunbPZxVMUBfa8VBEfVYzN6
         K3AsR9hDz01m09MgvCJNAP3O7LTgScJztL90a/fuGixZIG3qXFGh6wKhlGh8sL/TwKFH
         6K2M/MfU5DQOmtOyyx68+1Sqgd7ch7Yq8zUVsVgqoRBXPU6z2eafMYWFXT7tqgZH34Ld
         BGcCZ4rSbPn0eiA++J9Q39mCc92lGxbkRIwlDIrLb4aSVTXZ4n9qxTXj7aPd3XKhOr36
         SFy4qHjka6vw34eCHQB4jHLWWvjkqxh7oWKRI2pS4SExNTVdlaAIU6+rnbmP/dWFWdB5
         WcuQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from:dkim-signature;
        bh=i6KofKd9ysFh31suHyab7go4BuRkA01dO/A/4ToARv8=;
        fh=uQCsmYQr+KJEcG63Y45gsyDulzJl/B4EdEfpx8XrGGo=;
        b=rcinj3hT0TBZ2ye6ozaEBxQP/pmiZgQnb3w8NZGztuL0Lbr2TjcPMcrDmNz2jKY6Dy
         zMwofn+qmEitYcRT7IvzQ51YCt5dzWbqAT4n992Ki3PDgp+974dFF/JHeGAS6kfeIzzw
         Fz1++S9CsmcXVas26/y5b3s2Q6DSVhQqWffjSKa7+NB/8djLzISgSffXhex58QzA/Skw
         Ff9ZJ3V885Zokqy7KzDBc2MpiYDxKXOhDjqAeN5/dgJxXgFVrN/a16T5WJoP7YcCwtNR
         pVCdeHtbD1ocdDDdp09f33eeK1wNpagZykoIlyqrftqdnVfaA4s17nVj8yH+QtQeMIJg
         cwXA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=bCUsYqOg;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id 27-20020a63165b000000b0056bcd716015si1193867pgw.3.2023.08.30.08.21.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 30 Aug 2023 08:21:42 -0700 (PDT)
Received-SPF: pass (google.com: domain of bugzilla-daemon@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id 3D81C6108C
	for <kasan-dev@googlegroups.com>; Wed, 30 Aug 2023 15:21:42 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id A5659C433C7
	for <kasan-dev@googlegroups.com>; Wed, 30 Aug 2023 15:21:41 +0000 (UTC)
Received: by aws-us-west-2-korg-bugzilla-1.web.codeaurora.org (Postfix, from userid 48)
	id 8CA9AC53BC6; Wed, 30 Aug 2023 15:21:41 +0000 (UTC)
From: bugzilla-daemon@kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 212161] KASAN (hw-tags): support SLAB allocator
Date: Wed, 30 Aug 2023 15:21:41 +0000
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
X-Bugzilla-Resolution: OBSOLETE
X-Bugzilla-Priority: P1
X-Bugzilla-Assigned-To: mm_sanitizers@kernel-bugs.kernel.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: bug_status resolution
Message-ID: <bug-212161-199747-6aDLlQsxVr@https.bugzilla.kernel.org/>
In-Reply-To: <bug-212161-199747@https.bugzilla.kernel.org/>
References: <bug-212161-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=bCUsYqOg;       spf=pass
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

https://bugzilla.kernel.org/show_bug.cgi?id=212161

Andrey Konovalov (andreyknvl@gmail.com) changed:

           What    |Removed                     |Added
----------------------------------------------------------------------------
             Status|NEW                         |RESOLVED
         Resolution|---                         |OBSOLETE

--- Comment #1 from Andrey Konovalov (andreyknvl@gmail.com) ---
Closing, as SLAB is now deprecated is scheduled to be removed [1].

[1]
https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=eb07c4f39c3e858a7d0cc4bb15b8a304f83f0497

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-212161-199747-6aDLlQsxVr%40https.bugzilla.kernel.org/.
