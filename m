Return-Path: <kasan-dev+bncBAABB27VXONAMGQET3M3YUY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc38.google.com (mail-oo1-xc38.google.com [IPv6:2607:f8b0:4864:20::c38])
	by mail.lfdr.de (Postfix) with ESMTPS id EAC73603323
	for <lists+kasan-dev@lfdr.de>; Tue, 18 Oct 2022 21:13:48 +0200 (CEST)
Received: by mail-oo1-xc38.google.com with SMTP id n27-20020a4a611b000000b0048067b2a6f7sf6333784ooc.6
        for <lists+kasan-dev@lfdr.de>; Tue, 18 Oct 2022 12:13:48 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1666120427; cv=pass;
        d=google.com; s=arc-20160816;
        b=fHKR63hoMhSvcTcf63LpMv+KQxnTKkEA6kPpDvxgqaA9cGHaRxTRP5zEHE40UZUodn
         hLdk26tTsaG9fsAUBoiTh3Y4QtfttGZ0xfeTDM5vAb2kMfiI7Lg1OC7XWoOGIlK775/J
         6ThCcWrBDoV5zIw/cyuMxc8LaVUHNFA7Zn+FrtePpMw1KqzEBjvBhDbwcbVu3EkLqpam
         caIQjCmi7LTN8pjo6IfKNVaGy9M0HjZYTlPkVeINEEQdOLbVnOZ0b0cD87m/jf/QRq01
         8mW6MB5TjT0KBsKAJy2OxojPF8sK6bYZhRowc40vp0ZEtHXB/qSNlNFFW1qJ2hjlxlCG
         gvHA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=xVbI9QNAGwao82mqnsVTv/atg4rKQGteG6b+w4vZp7c=;
        b=yzg3YwVB1mzbMPLhH46ELFJVanNDG241m+Gc3c90vN6/Fw70O9qs5dmjzebFCJn2jj
         CKkRMRFs7HO1UWdW+/CF8kbVw72DC1qghpiedDnPtH7GcpRh6i3iVS8jxfMhZKonzl+k
         AjiCCPPcHJOTEZYA6FTrI+LfV3kmu3EokD7OcJpn32VbSGIEu5qdVH46+sh55ESJGbzT
         YTem8xoF5dZbTuYO2P8byvygKVm/WGohX5r/vRHu58wMhJhMizIWp6XDZa8GNshgasY/
         QVgaPFeAIqd3BLjnMXgK/LSK1XbNa1Y64o+1EvbO3c9BJ96px6ScLlRRTCDqVRFYtx4U
         HE+A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=rQOabIFN;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:auto-submitted:references
         :in-reply-to:message-id:date:subject:to:from:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=xVbI9QNAGwao82mqnsVTv/atg4rKQGteG6b+w4vZp7c=;
        b=Snvmupla4IEmJJOfFVQuTfZ463eDpW3ArIPK+n+GdTOdo85dHMlcHxobz/qMO9lFb2
         yb3OVnRgJdbSHNeQWJs3vdJyvtz1qQZVBFAR+GOrfth6XLUNY8uCjn48neRKRSxpeCb8
         aaYIcxDapuQ/fZoHmw/RbE9EwSxuBNs/9zVfc5oEfoEAMlA/Zz6ahblt5tgeVX9OLNGB
         SDiB+OGneMgHn8VsfB7Clab9W09i2IjdwDbiZO/OyaKPE2OJ0CtijFofzH6JSC3D3f8O
         ULOTnmXg1hj1fxla9t8x4QeVDwJM5b/l9zDNu5SXbp+sSNsnn0uih/gvUV2BZXa2moIo
         smFA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=xVbI9QNAGwao82mqnsVTv/atg4rKQGteG6b+w4vZp7c=;
        b=3WxrNhNdnFqtcInNiNLMTMdohHTEgcffPWrYKKF2wCqWUVUck695U09YzmjzZfQsl3
         s7ru/v/3WntJpxKRAfXEHjK4tKMAJ3JrENVVDak1AAl6uD42TZdcaVXg8TH8NoKdQ81T
         LuNpJoVbKwdwTkEuc0/qPMMh4yaRUAQk48R+tmj4Oh6db4uPvNnA5vUhvuM+zr7QZFr4
         Pezx+WegxULJpoWJ/yq/38/R4qGmX+aj87Pz+4UuhyYCNG79Jt5EyMqu+M2JTRFzcCsD
         jS8UWI2M+59qi1AkiH4oAJ5LwO3Z9L3qG0wDgn5GY1u/cMvNiI0zi6CARrerOSF1MO9I
         93ew==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf0oBaM0akKdude3iv32rTxn/IbjSImZLJVXGj0ZT3U/Oz50QnoU
	6GO6etOorY6xCSmzoNLJubg=
X-Google-Smtp-Source: AMsMyM5s6Bh9uB69uJxJuUib3FrnmsTug6DJI9fDCtwZ6Ml3/+wEUn4v9ibCNhC1/1tXoLnyJW2XHQ==
X-Received: by 2002:a05:6830:1189:b0:661:ad5e:7306 with SMTP id u9-20020a056830118900b00661ad5e7306mr2090791otq.17.1666120427464;
        Tue, 18 Oct 2022 12:13:47 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6808:546:b0:354:6639:a1f with SMTP id
 i6-20020a056808054600b0035466390a1fls4457604oig.0.-pod-prod-gmail; Tue, 18
 Oct 2022 12:13:47 -0700 (PDT)
X-Received: by 2002:a17:90a:b903:b0:20d:a36b:6791 with SMTP id p3-20020a17090ab90300b0020da36b6791mr33287615pjr.26.1666120416589;
        Tue, 18 Oct 2022 12:13:36 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1666120416; cv=none;
        d=google.com; s=arc-20160816;
        b=S47HeWQAZl3AJ4xXY5jhqTlmAT/j8dSIFXvk187tMEA1RBXJ6udahRNgVNmnACS9jX
         q/Y+bcBW8VasRZ9C3+PrMimcGotZQAzPJqx1V+Cy0pzAlH6N0Dv7mIA24vZAlYIBxvZW
         MCXoyCxh6l3JKde9cpniQ1Lp9vEmx0A68OKTfSCM1ke6vf6vihGg5yTwzmgULF3sP0uf
         AYnOpCl3A54Nl0uGZuZohV9jpu3jOhcMgcLzJt1G2p5cjoKqLrRYTrgZqs20jtTQMjPM
         dCtWoj8lgQ+WC94R22ZOFtpHaLAMnzNIDe5uvibbgFhsYaK5efPUR8D9e7DPtIaunn+o
         JGAA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from:dkim-signature;
        bh=jefAtfXB1ayz56iWSp/sfWGLrWGWShXwNNeF7ofmhPo=;
        b=f0aeBUkpuKtMlsj9iD7OrhyCsDiBa+/UOQV4Apgcwverhj1/bO+4YrMrENZow0v3pz
         gjDtzHaVhPL/ClnPU0e+RCx64x7zm2Q5GLyhjiwmDo11lhLwbNX+9JS7X3vKjuaeMXIZ
         +6EqP+m/H73OGAqOXBfL4pGV4mIdyYtyT1+7Rag09Wed8449Tgs6sEIF+/Vonv4souJ6
         QcaS32ICh+LM6Gj9CG3xPudyloephYnEuTvWNYXHK8UBVuRYCXo5HRwbl8mHC6ShpcGq
         hsHUSQux1Y3Wib/tc4WTpNM4XWlNWQ4aGJfbYMoHQuNW0K23hEBmofACpKTOlmqikPVM
         p3ag==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=rQOabIFN;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id o19-20020aa79793000000b00562230e14d8si565646pfp.2.2022.10.18.12.13.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 18 Oct 2022 12:13:36 -0700 (PDT)
Received-SPF: pass (google.com: domain of bugzilla-daemon@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id 0A35A616D7
	for <kasan-dev@googlegroups.com>; Tue, 18 Oct 2022 19:13:36 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id 6A2BDC433D7
	for <kasan-dev@googlegroups.com>; Tue, 18 Oct 2022 19:13:35 +0000 (UTC)
Received: by aws-us-west-2-korg-bugzilla-1.web.codeaurora.org (Postfix, from userid 48)
	id 52338C433E7; Tue, 18 Oct 2022 19:13:35 +0000 (UTC)
From: bugzilla-daemon@kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 212191] KASAN (tags): better use-after-free report header
Date: Tue, 18 Oct 2022 19:13:35 +0000
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
Message-ID: <bug-212191-199747-1J35LCUdKH@https.bugzilla.kernel.org/>
In-Reply-To: <bug-212191-199747@https.bugzilla.kernel.org/>
References: <bug-212191-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=rQOabIFN;       spf=pass
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

https://bugzilla.kernel.org/show_bug.cgi?id=212191

--- Comment #1 from Andrey Konovalov (andreyknvl@gmail.com) ---
This has been improved with the addition of the stack ring [1].

[1]
https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=1f538e1f2d294cf8a9486fb1a7d4d4f0d16e2b01

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-212191-199747-1J35LCUdKH%40https.bugzilla.kernel.org/.
