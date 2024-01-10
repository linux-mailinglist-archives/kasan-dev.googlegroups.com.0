Return-Path: <kasan-dev+bncBAABBH4S7CWAMGQEKS2XOLQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd37.google.com (mail-io1-xd37.google.com [IPv6:2607:f8b0:4864:20::d37])
	by mail.lfdr.de (Postfix) with ESMTPS id 6711E82929D
	for <lists+kasan-dev@lfdr.de>; Wed, 10 Jan 2024 04:04:01 +0100 (CET)
Received: by mail-io1-xd37.google.com with SMTP id ca18e2360f4ac-7bc32b2226asf290915039f.2
        for <lists+kasan-dev@lfdr.de>; Tue, 09 Jan 2024 19:04:01 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1704855839; cv=pass;
        d=google.com; s=arc-20160816;
        b=zyKaR8cyjdN+k/QrT5tp9F6NEVgtdE3PU17V4vJMUvY/YLzPY16UzO9hyor03ZetAX
         t+jXKxUaxDAHn+6UCvOgfAQDTIuuyFbiQyLdUOMZysNxStkPBV2n7arsosjTRyzLkv29
         /FcUSn2MUqAbnyE8yNQ79CvgLFhlR5Z00FvJay6Aybbc8H/OivFAdQFeL5E8izX60Ir+
         nYLAS3dscNlh4R+6p9EcrUlQaogr6c3YlyeCrofpjzZivmTMak2w+g+YPuMJ2fL24VoK
         4U0v+MOEmmx8KZhP3/I39DTV2hETBxjTUBcuueNfmQo9ammLJ9PiMbfFoB4v+HwjrBIZ
         6SNQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=TSgNCB4vkA1mdAsyv8HRqWGahGoyYMe0klfA79lDdKs=;
        fh=uQCsmYQr+KJEcG63Y45gsyDulzJl/B4EdEfpx8XrGGo=;
        b=oS4GOz6JU+NSJhnw9F0Uu2pxFSjqEzBSSotjz4hwBwIa1x0M2Gon3EYmRlEnnjhDxT
         9mVxPk9U/ejgDR8AigG2Sli532QQIkDbE+6jcZg320fAlvr/VD7XFhR8aU8H4SqKwKPR
         ALPc1mteM4O4CiZZR+ED5hI4J333dp1mYV6HMEVAEIiNlz+fWbkunq3RyKjPzeN6pwbX
         QhgL4eIdYO1hTommptX/QYXpLhT7EU8DFxSbgYvA3rENJDr8b7+p36vV1Ym9ltn48yBC
         VS8NKgxLCj7fm4dK/CeADbjCMXT2/T7Z5inqIAlwF3zsPd+xHKzkjNheIRGo/gKEPn0l
         Pvqg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=kLC5Hyvl;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:40e1:4800::1 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1704855839; x=1705460639; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:auto-submitted:references
         :in-reply-to:message-id:date:subject:to:from:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=TSgNCB4vkA1mdAsyv8HRqWGahGoyYMe0klfA79lDdKs=;
        b=rNEJvQMDKCSaggR0k780rZBtIm29Od3TMS1dbYVrSuaOqoJ5hUtWPFckYPF285G9Ih
         i5dbBw5Tjv3md2pOTyF3h6LtFKZUSBhkt5Mx2stCDcaxrDrImEv3dnHuNVXDnSXQnDTR
         uEhii1dHVvPGajNQPVOK4Qnd66Sy+COXSF/tDZuAy435nWTmFByFuKRUfIu+Nf3BTntb
         KCpVHjE1rvLvaM9OTgeJfSeQVTFOLm2R2xYIz4oxDOEVTBm9/IKjaFy8xxO/8ytwooKm
         rsGYOaGxCm3c+XmD4Qo5PPaHkO9hT8eHG6GZeCNLINYFGntnPtjDYvT5sZUpLsTSHyrL
         a3wA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1704855839; x=1705460639;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=TSgNCB4vkA1mdAsyv8HRqWGahGoyYMe0klfA79lDdKs=;
        b=ZhqqBmxUyq8I0nryH/PyAQQ3MG7L+c9Si+u43sBSuHUvwoLeQ3bJStYLUFuml6Fd/V
         0CLef12RVBk5DOnikFt5OQTSBU1ndbDzqUAZ4Aho57m5K62KxrQ/IPVggclVe6xm7yd1
         xoxeEPaOuSiyGgmpVLuGjr8fx8jr2C1SoXSQzCfP6ntzhjtFVHe7nnGwdub2OR/Tttqz
         tpp3xbjm3xo+z2siEQ55HAJeQ89WsRUknIMlUYiJrEcwNW84NIyDSEZkge5P1WX1NpTZ
         xa3StcbJD4a5zIBxqai0N0yx+6sqLbEoT2pmLMf0od3p+Rpd+AT1cHyR0bSq5BEMSD4H
         v7lg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YwaqM8o7geTLsk0LxsG2gwXJ+UpGbiElXfkoZ0ezV4xnJ/lnzXK
	vPRKK2RRAYCXm8tF72DX3lU=
X-Google-Smtp-Source: AGHT+IHbNpVhT2dEofBIDwhvWsA/WuMFnTPLsyLeOA3FGYNFZ7oirC4mQGnIQYehk4GWl0W4DZAQxQ==
X-Received: by 2002:a05:6e02:1c2a:b0:360:6bd2:ddc0 with SMTP id m10-20020a056e021c2a00b003606bd2ddc0mr489397ilh.28.1704855839772;
        Tue, 09 Jan 2024 19:03:59 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:c6c9:0:b0:35f:7653:fcc9 with SMTP id v9-20020a92c6c9000000b0035f7653fcc9ls1614957ilm.0.-pod-prod-09-us;
 Tue, 09 Jan 2024 19:03:59 -0800 (PST)
X-Received: by 2002:a6b:c810:0:b0:7be:e36f:c84c with SMTP id y16-20020a6bc810000000b007bee36fc84cmr79498iof.6.1704855839154;
        Tue, 09 Jan 2024 19:03:59 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1704855839; cv=none;
        d=google.com; s=arc-20160816;
        b=mVJboTRYQyg3m0YAD/AjvAq9R+mKNcCCf8Ejq7L6Lf5RmawytqKkCBSLKHL8/a4WvS
         QwTTfZDNIgl+jcGGBuigXgGDAFxGn6FI0Mr1kh047goIwDj458IWxU0JefZ6+sAooZ9n
         e1c2tShuHUgBNtpi8BjDu1Pt6B97GRmt5DCBtmjGPNRQUQH9MeabHf1TYxysJrernDLA
         67pB4IB95VU7+lmtYD07TJ0Z+bDKcfuZyNkbcAV99sfSG03zpJ8hrZtCy4L3WK2qI2Jx
         J2R07GNrJHcnFH53gZzORwwlFH5sVSYBBaQZVMjTnrEABJ1q7wd0pjWpwVVPcqp1FDII
         mQag==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from:dkim-signature;
        bh=/t59/hOtR9X1WnDIqtrZr3qbIgXMgDS5fOc6FYuE5Dc=;
        fh=uQCsmYQr+KJEcG63Y45gsyDulzJl/B4EdEfpx8XrGGo=;
        b=C+6m0p0CYsRE1pRuE6leoANIxrm8+BRY0qp6qL39N9LIxpWgzsUNidu8aIKC9Sp1ck
         FpdmBBJmbV9QWDbok+i3YAVLDiQTAuVYqo77mSwHeLRnEOPiAS02VzZ6l3IcGLvp1nqO
         XylrSnjIoNAqnzStT+yPd+G0aDSH54S7TPhV/JX+SGVoQaUgKiDEXl+kjLTJWCD0g5SF
         Q4KyJ6Sr96mK1HDE7dKN/dQqMFM4O8hjisQ/AtOyOngjxpcN/PhYTm6UOpFt8rFRSJVz
         SLs26TEt66pFVytaV0DEskslf6r84xi6XkLObI2AAm4aa2FxVwjSXH890EdTiRlD/Yig
         2ZiQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=kLC5Hyvl;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:40e1:4800::1 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from sin.source.kernel.org (sin.source.kernel.org. [2604:1380:40e1:4800::1])
        by gmr-mx.google.com with ESMTPS id g15-20020a0566380bcf00b0046d6ccc53dasi209397jad.6.2024.01.09.19.03.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 09 Jan 2024 19:03:59 -0800 (PST)
Received-SPF: pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:40e1:4800::1 as permitted sender) client-ip=2604:1380:40e1:4800::1;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sin.source.kernel.org (Postfix) with ESMTP id 68C38CE1AC8
	for <kasan-dev@googlegroups.com>; Wed, 10 Jan 2024 03:03:56 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id A57E6C43390
	for <kasan-dev@googlegroups.com>; Wed, 10 Jan 2024 03:03:55 +0000 (UTC)
Received: by aws-us-west-2-korg-bugzilla-1.web.codeaurora.org (Postfix, from userid 48)
	id 965D1C53BCD; Wed, 10 Jan 2024 03:03:55 +0000 (UTC)
From: bugzilla-daemon@kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 218322] KASAN (hw-tags): skip page_alloc (un)poisoning of large
 kmalloc allocations
Date: Wed, 10 Jan 2024 03:03:55 +0000
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
X-Bugzilla-Priority: P3
X-Bugzilla-Assigned-To: mm_sanitizers@kernel-bugs.kernel.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: 
Message-ID: <bug-218322-199747-tdrc1ZOuJW@https.bugzilla.kernel.org/>
In-Reply-To: <bug-218322-199747@https.bugzilla.kernel.org/>
References: <bug-218322-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=kLC5Hyvl;       spf=pass
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

https://bugzilla.kernel.org/show_bug.cgi?id=218322

--- Comment #1 from Andrey Konovalov (andreyknvl@gmail.com) ---
If skipping is implemented, https://bugzilla.kernel.org/show_bug.cgi?id=218358
becomes obsolete.

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-218322-199747-tdrc1ZOuJW%40https.bugzilla.kernel.org/.
