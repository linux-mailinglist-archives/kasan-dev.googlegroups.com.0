Return-Path: <kasan-dev+bncBAABBN7CQGJAMGQEPLEEILQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa37.google.com (mail-vk1-xa37.google.com [IPv6:2607:f8b0:4864:20::a37])
	by mail.lfdr.de (Postfix) with ESMTPS id 4CC144E8801
	for <lists+kasan-dev@lfdr.de>; Sun, 27 Mar 2022 16:14:17 +0200 (CEST)
Received: by mail-vk1-xa37.google.com with SMTP id a188-20020a1f66c5000000b0033e52f60923sf2245293vkc.7
        for <lists+kasan-dev@lfdr.de>; Sun, 27 Mar 2022 07:14:17 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1648390456; cv=pass;
        d=google.com; s=arc-20160816;
        b=FpOFDFC8txPIXSGk0K3QSp4igNSIO2jAasW15eJZYtXNhI1alVN1RZ2fQL/YNLpT6w
         kpNDCF7DP6SmhrErPBxW8RqhDu/a5h7pjQqHDxckv+vxaAUvN/ViqIya2yrPE/+diIQw
         1z8poLQb2o9biUC079BMoeBWUQNVfw23S5FWHXxF+z8ShSx4uFKPKzJtdmHTRrufsWlR
         aMr5gMX/j5cq9N6cUXDZtVyAu64Q+VRDjw4EmFxTuNthOxBwHWOeym2pi6Kp3owXSDfD
         X+RsEXP3LRMaBjV5Sil/tvQ7XuGg1vMf0/RIdESCf4s1jeVqpZZnwrd3DmpnAJHgWonR
         WUqA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=/AFU1Yq4deObcKHc4G2X65uIk1Qph629+FvgmO8ucXY=;
        b=PYp7WKgwPGt02G0Oskq8LeQ4PHM/jyJwXDqZTaH5O2gQmjtQXpuxmMzVhTIrD8Ijp2
         zLy1y0+ZTQoDhl3oRLEYtMGeZl/g6qMMvO4Fc/IilpDQ8NJNXYZj1H6P7IzlFSDpGUYv
         QkKTalZ4LvHdee9pHHOV0GrPNXSj2YRqEX5NV2zDiy0K+OUDTTNMbhf8JARN3VpRD7C6
         exU6pTlw1bi3Mzk2gWi1dzSLPAA938HjB8o+/RR+DPFeY76JBheBUWzY403xZbvWIjNZ
         cOhNMVsOllNVCCNWjwNbDQxElVrkrBmgyWDG/YCtq3Am1VJ0FINfkSCJGZwOMwyx9me8
         1f9A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Xd+7fZ6i;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:subject:date:message-id:in-reply-to:references
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=/AFU1Yq4deObcKHc4G2X65uIk1Qph629+FvgmO8ucXY=;
        b=nj57hCoZYv6SoH+zPrJe+aZFX6gjpdnp2i81Y76StaimXp+mGrZ/iDYSSlCaVy1Ff1
         E4TKYkby7VDX8zIOwS55g92X5qvyfK1C4EnAc2tuL31fINK/gtR22j5m5IhxPbrpGcVx
         3da+OIbeaH02yQoaP4a+US54dFKu1/XQ7CQf9bRCobmPD3aYxeqda2aRxx9GjvCSnHhx
         vKNZacqVMcSyophUaRlnkhadP1FB5+2OjqjnlIHFCLb5yW7MGYTIFYKu3E8mB8fDbV/U
         XHrzYJYA3BbBKEZRKS5Z5fb7UjqUYa1KojFAxhDXfm0IpoD/keIpBZqVJc10y52rx/jn
         RP4g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :in-reply-to:references:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=/AFU1Yq4deObcKHc4G2X65uIk1Qph629+FvgmO8ucXY=;
        b=6cXYqGH8QOuyZN9TCgD0HE0q5NBMYyLut8zjFurbPYjp5xz6Wkx8eC8RonYye2+MmK
         M4iAEM1N1jvDocWVgrkloKcr8dKBLJlgQ6sUofeL9B1C8u4W8HlhJrksX0Tf79p6f8uy
         g8OTRRgmble8aC/HS5xAzoFDzrk4UtSj4m/Zrl1ZCZqUJUH49682oolrTB5Gf8hTN7K8
         twHGxdBM3JXwG0YJuNoM5OvY/Cbkl5aiqWN28E+MBsyKam9slV2x3hcqbC3jIXEBv9yi
         Nu24jJG9yv971H1F9OG5Ax3NRm9Uod54cdTIfnWXFtIS/a2shLyGAHXxzHSrcZ1Xq3c1
         rEwA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533QMq6xWnDnEjEJiTL67pFy6Jjw2J9bO8FsS077JDWtYLH/RQBW
	OxrvjxcP+fY1FUofFGtkBko=
X-Google-Smtp-Source: ABdhPJzXJyJo42vQYody3akUuM3aRMDmVAd36fwvyf9PJQ8Lmt9AI4I4x9ujtnlw5Fa6cuDnn7LvIg==
X-Received: by 2002:a05:6102:8:b0:325:6b5c:1332 with SMTP id j8-20020a056102000800b003256b5c1332mr5844282vsp.16.1648390456085;
        Sun, 27 Mar 2022 07:14:16 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1f:b602:0:b0:33e:93f4:8a1b with SMTP id g2-20020a1fb602000000b0033e93f48a1bls1067366vkf.5.gmail;
 Sun, 27 Mar 2022 07:14:15 -0700 (PDT)
X-Received: by 2002:a1f:2e0f:0:b0:33f:18a6:49f1 with SMTP id u15-20020a1f2e0f000000b0033f18a649f1mr8706669vku.8.1648390455657;
        Sun, 27 Mar 2022 07:14:15 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1648390455; cv=none;
        d=google.com; s=arc-20160816;
        b=BFfOfYYKzEMr4Dv/q0T2gPECdhZkLV3FfR9X4n5yFREBQEmYYPOF+nAvOIhYpbz9LA
         e5YFeyT/3qkbFHcWbLd3QYnFkus87OKa6LtsHITW/XgXcJlpegJX2/a1/s59QC+4DwA2
         E0Tmkyk+Hvhp/+RWr+sdZNk85KS7x/pQvZ4ZDxwJ7tTyOC9Iol8HUkWsn9uh5qJNeOiA
         iclsH1uGuc/Izx7snrwfbRsOR0pPGy0BDDu0ru9kusAGzhEtOHFYOsqLb7JJ+sGHj/Yp
         /97dZYSeuWAN81k7rCWIc+fVyJ1o4NuHXz2I2MHwCGMg+yFHff/+GteW1znPLf4XbTVv
         t3BA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from:dkim-signature;
        bh=FrTBNsqByrAV/4DLgkEQI0S9fQwK8d4P9mUNGNVIkNQ=;
        b=t4YgRaGKscyQym4ma0bQThO6TAX3PnTHmPfedOYRqYRhTQm5qj2cuMAzVnC4plDZd2
         PyhRKFXC0h9qr8ecZ0ZX1LVFGzbcP9nuJ/bolUCfFpsPzo6FhcCSi/SyiAufNV+i9p2b
         1yu7Av8jDiJQmU7KLm0QmgHt0EB1bSjde3/aXKYwwsGJMUHALk4PDJTDnNXWBB2Vs4AM
         Di1iz5cY3tfY7cUY0mZf7SQeysye10oC4izflJRgycek9f4UEVktA/jVp4YXUSBDXLhT
         mUrUywvTIFgXsInM3atr+qhI+i1uoTX67I4XucZi2p5oJ1UgFTA2hgRpX5Owcr9+BDWJ
         flFA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Xd+7fZ6i;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id h129-20020a1f2187000000b0033fb725e3e3si674509vkh.2.2022.03.27.07.14.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sun, 27 Mar 2022 07:14:15 -0700 (PDT)
Received-SPF: pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id 3D2656101C
	for <kasan-dev@googlegroups.com>; Sun, 27 Mar 2022 14:14:15 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id A3C75C34100
	for <kasan-dev@googlegroups.com>; Sun, 27 Mar 2022 14:14:14 +0000 (UTC)
Received: by aws-us-west-2-korg-bugzilla-1.web.codeaurora.org (Postfix, from userid 48)
	id 8D052C05FD4; Sun, 27 Mar 2022 14:14:14 +0000 (UTC)
From: bugzilla-daemon@kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 212211] KASAN: check report_enabled() for invalid-free
Date: Sun, 27 Mar 2022 14:14:14 +0000
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
X-Bugzilla-Priority: P1
X-Bugzilla-Assigned-To: mm_sanitizers@kernel-bugs.kernel.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: bug_status resolution
Message-ID: <bug-212211-199747-broohJo2np@https.bugzilla.kernel.org/>
In-Reply-To: <bug-212211-199747@https.bugzilla.kernel.org/>
References: <bug-212211-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=Xd+7fZ6i;       spf=pass
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

https://bugzilla.kernel.org/show_bug.cgi?id=212211

Andrey Konovalov (andreyknvl@gmail.com) changed:

           What    |Removed                     |Added
----------------------------------------------------------------------------
             Status|NEW                         |RESOLVED
         Resolution|---                         |CODE_FIX

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-212211-199747-broohJo2np%40https.bugzilla.kernel.org/.
