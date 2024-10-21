Return-Path: <kasan-dev+bncBAABBSVA3K4AMGQECY3RAFA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x139.google.com (mail-il1-x139.google.com [IPv6:2607:f8b0:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id CA7EE9A7115
	for <lists+kasan-dev@lfdr.de>; Mon, 21 Oct 2024 19:33:01 +0200 (CEST)
Received: by mail-il1-x139.google.com with SMTP id e9e14a558f8ab-3a3c90919a2sf47220905ab.0
        for <lists+kasan-dev@lfdr.de>; Mon, 21 Oct 2024 10:33:01 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1729531980; cv=pass;
        d=google.com; s=arc-20240605;
        b=JrTimsY574SixacNje3GnDNU2eCZkHeEkON4U3//CZPJp5mlgmmC9p+aI7HxZLpaG4
         yEu1AZOq2Eop+8JUgh3gXFvN9gDScK+HoP16HWCcHTVRyYPbRLTHLyCNR4LwHptclWcO
         t6h/vPY//7noVMeLnD+B9Rgk+WSLa9HRvpYHebxebgMwrOZodzYHs2f6OqVxOqSaZ3Xb
         JQ7Emqor5pSZR4Vglu82ZqsbPds51r85bKPNzv+70YuWvVrMrCvZsmp6l8dKqYUeIvyQ
         kOwUl2WB4zQWHPteqZX8+V0YYZbL0jth5xlrs5u5FRo9B2MYIU9JVNXEs/5nYsygp/jA
         D80g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:dkim-signature;
        bh=8vVAU+wsm1hWcW/mDlX6IxDlnb/c2yUf/X4cs9ZAygw=;
        fh=2ycYMKIte6F2I84RRlnJ69pQ/Br+EI5yUeLWVhIdinw=;
        b=QTNN09VkmLgLhzwuBNFRuK8Dc0euTfxfyaYwsFjv4Bw4l7mkTfttdFLs0ulMo6rHsI
         RCY3/f5uB+b02e3aIHix2XfPfPonAlSp+l9CaDESdvW0FyVATE8ijf26UuP/3LWy2oA5
         9Muxq5M+7XAcyX1itdz3MwdpQ42cChFET1LleSi0aOu7fHDZcIqZF765GaueQoMKiBXz
         GqGg/8khW4tueepJbxW46m0x7ReB+1aWICI95wrPZ6BFMvn+v3/1pvzgjfWzA1QsHzLQ
         ieplN/fhngyFSinOiLoss3S3np2DucfjrePsvFMf5O9s07XGtC00GGcThrHaRrv4beuO
         qjsA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=m1gufDIB;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1729531980; x=1730136780; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:from:to:cc:subject:date:message-id:reply-to;
        bh=8vVAU+wsm1hWcW/mDlX6IxDlnb/c2yUf/X4cs9ZAygw=;
        b=smYu/6SsRld6eMjBRKMEwhs8Oh3PAbvU5YUZJEoSgPvew7saeUXiV42J4fie7otH8U
         g8Fq9V2PghrTN9KD4Ig7K6erslqqGp3kb+QFzKl759+FX4jpOrY/bBiJ1lNLczvRQrX7
         QjmWthrjQ310kgGZRMVqq3v9aHnQtP7eAc6pSuQrTlPl+bMx1NykDJmnmXe5LKIIlwkK
         LTlV2TwLF8rmdz86rSIL9iApjD/XcXBtaOR4oABXktkAsPlOWiuQ+n2M1o7NfuJGqXZ5
         JiPcdmCSP2HTKiTfzgGpGBa4v5gow+VVDy87mnhfEEIpR3CvD/CmzKwEOnllJSKQHh6k
         i1wQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1729531980; x=1730136780;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=8vVAU+wsm1hWcW/mDlX6IxDlnb/c2yUf/X4cs9ZAygw=;
        b=ZOsYIKWQrrVCueEpuMuZ2FGmnTB/GWKVxvJ1DkxqkndHJRC1pEtZZyC5/ayXe5OFFA
         r2XxeTeCxLoe0wPSiG5xarv3fRhugfpSyfsXQwGtapGjh4wFcbU+VFt3m8qYI6D2lS2o
         dIDKAtGIltjw14z1J7SHbQoj517f+AtaOrthVz3VH35yBXGratFtGfOuAXa6gfmI16uz
         j4Bfh79kCJNUAnG9LrB7czUVP93lwiKdBjrkmONI3QBs6j+BvWwLJQ3NPukHCEG7TyaJ
         iK3NhWDitI6i6nR+mgiqjSM/L31eLfC9OGRMQ7xYtEJKN6RA434nHUswakB3MnoacH0i
         kgHA==
X-Forwarded-Encrypted: i=2; AJvYcCXKA7l36nj9YVqIqbe1h5j7sWt2eB1ffZ7BTow+Dt9ir/sH26h5knfY8FocJGLReWBGA3FWQA==@lfdr.de
X-Gm-Message-State: AOJu0YyNTOuOUlRfvIngaWVuAYweNmIcsHClX/T0XDJ4o9lfP8JUddaS
	ttzWEguYzLUzfj1ZsEaly/iM8hGKXB19/uFOw4caGOh49y8qztCX
X-Google-Smtp-Source: AGHT+IHqr3LYf2HjsGMJSnlULkYE8YF+in+XvVp6IKzSxiVBfc9r06hSxcqRtaB5qdafTVEcZk1x0g==
X-Received: by 2002:a05:6e02:138b:b0:3a3:da4f:79f4 with SMTP id e9e14a558f8ab-3a3f40457c6mr104390925ab.2.1729531978975;
        Mon, 21 Oct 2024 10:32:58 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:1b01:b0:3a2:6eaf:d929 with SMTP id
 e9e14a558f8ab-3a3e4b0383cls24383545ab.2.-pod-prod-08-us; Mon, 21 Oct 2024
 10:32:58 -0700 (PDT)
X-Received: by 2002:a05:6602:2dcb:b0:835:3ffe:fe31 with SMTP id ca18e2360f4ac-83aba612b82mr1435527639f.8.1729531978321;
        Mon, 21 Oct 2024 10:32:58 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1729531978; cv=none;
        d=google.com; s=arc-20240605;
        b=Ajm/FkzgsYRBiK8OaWup6V8TYTgtZQFp/V0PhwZIYO4sdSgFZzA3CJEzNzIS5HHoPW
         6Z0NoWlF4sLoVzVnkzrRP7Mude5UEla7ubb4B/QZPmDgkD8h23C4oSl+rhku7fsMiEgY
         +Yi5yogLQ6lyaOlL5046j/ofboD+IfLuGYUPPPmrjS99TJK+ax4YakVRp9S+bJwV3Ecy
         27/2PxBpoqMIogSpSbn73796er9PFa5pbP8Rd7+bNsxrT5ELFHeCwWTY1HkMKMHgky+K
         hvXfPZTVTsDaZeuI7NvQzms/r6Cqc0PBccI5jbTFRxZHldTprDU+bavKfDrXZLGFkzrb
         H8+g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from:dkim-signature;
        bh=+2g4Qyy3Tv/egh8W+tw1X6NZn7Mrr+viWfNsOdHBvnI=;
        fh=uQCsmYQr+KJEcG63Y45gsyDulzJl/B4EdEfpx8XrGGo=;
        b=Az6r1hSKhoLL9zulrmG7okALmRUrn1iFbwNcNQBVFbyBWpjxbbi8KTFX5ajNdgvie5
         oeT89uEoSQysHrdny24+bENZzJ9l9IqchU/nfRzG+kht+tqApqqzrfkLFS6HG0jQZff2
         JooDcH3Qm4XMNNwhC/jIhGzpYcSmvFOuyDsf87ad03S+l+rta2+XvfA25OkiBY8U3O4L
         ljn5R9GFqi7qJrVMZfB+h3aV8+uXAMEAnYlLb22aIlXZc347Ayc0BKRY5WYxVo1MLz+2
         VcLiOIl7/WYAyn+0Kg6d8SxPMDYXdFCTPIbzBgcM2ObxISlOY/FbaAXJBrRBWRO238lb
         5bfw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=m1gufDIB;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id 8926c6da1cb9f-4dc2a4a358fsi134022173.1.2024.10.21.10.32.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 21 Oct 2024 10:32:58 -0700 (PDT)
Received-SPF: pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id 55B385C48AC
	for <kasan-dev@googlegroups.com>; Mon, 21 Oct 2024 17:32:53 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id 80670C4CEC3
	for <kasan-dev@googlegroups.com>; Mon, 21 Oct 2024 17:32:57 +0000 (UTC)
Received: by aws-us-west-2-korg-bugzilla-1.web.codeaurora.org (Postfix, from userid 48)
	id 72302C53BCA; Mon, 21 Oct 2024 17:32:57 +0000 (UTC)
From: bugzilla-daemon via kasan-dev <kasan-dev@googlegroups.com>
To: kasan-dev@googlegroups.com
Subject: [Bug 212173] KASAN (tags): explore possibility of not using a
 match-all pointer tag
Date: Mon, 21 Oct 2024 17:32:57 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: changed
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Memory Management
X-Bugzilla-Component: Sanitizers
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: normal
X-Bugzilla-Who: andreyknvl@gmail.com
X-Bugzilla-Status: NEW
X-Bugzilla-Resolution: 
X-Bugzilla-Priority: P1
X-Bugzilla-Assigned-To: mm_sanitizers@kernel-bugs.kernel.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: 
Message-ID: <bug-212173-199747-B6XyjD8hRM@https.bugzilla.kernel.org/>
In-Reply-To: <bug-212173-199747@https.bugzilla.kernel.org/>
References: <bug-212173-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=m1gufDIB;       spf=pass
 (google.com: domain of bugzilla-daemon@kernel.org designates
 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
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

https://bugzilla.kernel.org/show_bug.cgi?id=212173

--- Comment #1 from Andrey Konovalov (andreyknvl@gmail.com) ---
If we manage to get rid of the match-all tag, we can also rethink the strategy
of marking freed memory with a reserved tag (0xFE). This would prevent
attackers from being able to reliably access metadata stored within freed
memory via crafted pointers. As long as the match-all tag is there, getting rid
of the reserved free tag likely makes little impact against attacks via crafted
pointers.

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-212173-199747-B6XyjD8hRM%40https.bugzilla.kernel.org/.
