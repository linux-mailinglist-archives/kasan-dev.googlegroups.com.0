Return-Path: <kasan-dev+bncBC24VNFHTMIBBHMGZSEAMGQE37BSRLQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x339.google.com (mail-ot1-x339.google.com [IPv6:2607:f8b0:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id 33D9B3E863B
	for <lists+kasan-dev@lfdr.de>; Wed, 11 Aug 2021 00:52:16 +0200 (CEST)
Received: by mail-ot1-x339.google.com with SMTP id h38-20020a9d14290000b02904ceed859e6esf280947oth.21
        for <lists+kasan-dev@lfdr.de>; Tue, 10 Aug 2021 15:52:16 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1628635935; cv=pass;
        d=google.com; s=arc-20160816;
        b=zMRw6wjoSPAFnm8o2zHLMtQFBUrJhqcMWNSbaS4M5UQ0BQZe2kfBjNNstP4kncB9g4
         lSIxEs3d5HOYMU4oUV2rBqsJGESdEHataf/rWu6YdhQn7McRpUSSSo76dAQQ7/js+jNL
         w06ETfeVrioZjq/IDVYIkAbH5J8gziLMHlqB0ArLjuNNQHRz4sbChEwfC0Zg8X5qraJB
         J+uNp8mzWM9tFqwl8ftVxGoRdMS4STbuk4vTEl8vm9mjrzoFktsecBMqvqjaYzAmy27G
         4k0juasbaq2DoyjRemXQ6RWjvo7teukwIcNiwUXRLiw8bJ/IfQrsE7SMxn97DbinC2kB
         baNQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=SM2Qi2cf8fcpBfZzWt1VqaIOyLeJRPv2T/Hzbj4NL/M=;
        b=lr/df3OOazCI72Zk7L5gKmzYWMfB2mzcZceBUYXPl/EurFOE3aW9zYRA2jntWFXL01
         RibdYuvjfjpWtT78aAckYOxZi9hFpYc+6zM8cnkDeu/BVFW+xe+cRonBbbOwD1NzOUwK
         +3zdL6k2YjNZGkgHukvhT1ZmD8C98ZzpHLiKNyW2cuxlDtg7aiunkgcz5/fUTWYjRdMB
         TYWOSjbzmA3zDnovyTyphvjq0e41GKAFNn6bxZNHqIlDF0HGTTKpkD14JhrbNoJijP0p
         Q1HbrZ7vUPjOC96EItcgnD233Whc5x/Hw7tRFFueD54rWF/+PZbcLklu9LxKCV/zi5K8
         2FVQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="G9Q6vek/";
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:date:message-id:in-reply-to:references
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=SM2Qi2cf8fcpBfZzWt1VqaIOyLeJRPv2T/Hzbj4NL/M=;
        b=V5Y5QVrSdx5bEBCySrzm71l4Jk2DCzrZAUoExbjNE80aPz+J0HLXI2VKVVTKv/ydFi
         I0gVR8okIYDZyMD3ELMFIp3nfM5ppaaytlF7qZ1xuaGUfuc3quVfOFIw3USD8vwg6tn5
         8gM0LlQg4ylUGN7pkO2cst4n8drVMKnUPfhEuk9rwxz5sS9aqYgdW/u3D2OYqSP8o4zA
         MegTpcZ3x2vn/cQEr/LFxpfyAw6j3IHUF4fgC9GN3fwFHts3khfmDkgt4Rp4+8GfWPoa
         w/WKljmCuYjZfwmhHemAfi3g4R5J7jWCgqzE+koKptvQ7FbLN0UdSvSYpHq2JsD0O8UM
         Lk/w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :in-reply-to:references:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=SM2Qi2cf8fcpBfZzWt1VqaIOyLeJRPv2T/Hzbj4NL/M=;
        b=l2ZGobKe5OS2g6DNLRtVf6ybn8w/ZXXUt8eyiuPajn2/rc5YZHoHsxOdqHu8sA+bFm
         OYvhg79boYSz9DNeQhCC5qBOcVuvndFfCM18y9xCEi+QD+s65U5XL9ju3PoRKIYS0qu8
         HhCQC2ptTj5WgKn+jO3igSiiNvcby2BgwfcCkA0j0R9xsSwQsZh6tC9uhnIaxBZiRVp7
         NXV2dNST3TcQwvK8VtWmhs/tmcbi/oIHfq5GBh/AVLfzc71X4OXlZlBGA0UNzBrl0bmy
         VqqTu1V2aWg/nKW2oG1/syFY2v9RaU5GJ4NzRzfRGsKjOu94fxgjxQcukYrSGvqdrnf3
         kdnQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531MryN7a/3umdSCPom1LXZskPhLPiLROZT06ffnmJaGGgQPl989
	DjH5p/uPSkuifzsQbRTv9xI=
X-Google-Smtp-Source: ABdhPJw2/QpgrhGTDh3QxS1LQMx4ciKn9dkb3g+wxQ3KEavosKYsCtnNQElwFXNe7qVcKSnInyK30Q==
X-Received: by 2002:aca:4e06:: with SMTP id c6mr5371748oib.161.1628635934059;
        Tue, 10 Aug 2021 15:52:14 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:6c16:: with SMTP id f22ls24144otq.5.gmail; Tue, 10 Aug
 2021 15:52:13 -0700 (PDT)
X-Received: by 2002:a9d:448:: with SMTP id 66mr22392730otc.345.1628635933744;
        Tue, 10 Aug 2021 15:52:13 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1628635933; cv=none;
        d=google.com; s=arc-20160816;
        b=t3ZGtgb2JMVQaJF6BIVt5HGToZWUL5SjuHrlzHFu5zhjOB93kD5PRqEnijPFVfgjx9
         3czYARe9TXreHxU05QcX7VzVxRP6mQnnOpgwigKuBiG9KnnckmKaZ8Zzo8wFVFmoA8W5
         SgVaaW4xZE9R7M8hqD/Xgt0FX1GkcqCYDxK7pzC443k7j/yPQFKeDnfa7yawbJUbFQnv
         ezihXeGdGYM/X7m22LcaBd8DJM/yi1Ug2aJRaUCujp7e/C8NouATsa3o4QvhEttb6w1q
         qP+bdHg3OF3xvQRjQbP0ZNFdhLzTI6gmToefD86Rn9L6tYdTCpJzu2mRspk9qbZzOafb
         hl4w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from:dkim-signature;
        bh=0Pa+ce8pypATRE1L8iv1w+mGiHFb8IfIrmMjmAmz+LU=;
        b=Fa5ALp9jl0kf6EoF4GRQgXgDLPE8I9VrjLAgfBDW8w3nAUruevbIpl7nPH7vx3m2Q2
         9XqrnWB4FCFMb7eaoBp/2G6g9CgSdOr1sAKaC/3t4thmM/NHckY/NJ7O0TUl4KqgC4SX
         M2PX1yOPKGDsqsTS4e6JsdW+KJLvYHLWvdqpcX3qrtx65l8KOdiEpCfBtN/g3nDOKv8H
         cDAsAwWBY9VHNfEcs4gAlZhpMFn7p2fRWQC2INqrDFBxl/Uk2+81CXLFMfbKmYlDXlok
         hkrofvTWIseiUHiUtu1bdSQSmn/ioNpKvukQVweyu2a3U0i4+9zm749UnPyTuR4bh7A+
         AoRA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="G9Q6vek/";
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id bi32si179803oib.0.2021.08.10.15.52.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 10 Aug 2021 15:52:13 -0700 (PDT)
Received-SPF: pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPS id F091A60EBD
	for <kasan-dev@googlegroups.com>; Tue, 10 Aug 2021 22:52:11 +0000 (UTC)
Received: by pdx-korg-bugzilla-2.web.codeaurora.org (Postfix, from userid 48)
	id E405A60E4B; Tue, 10 Aug 2021 22:52:11 +0000 (UTC)
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 212163] KASAN (hw-tags): support KMEMLEAK
Date: Tue, 10 Aug 2021 22:52:11 +0000
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
Message-ID: <bug-212163-199747-WbbwF47UwH@https.bugzilla.kernel.org/>
In-Reply-To: <bug-212163-199747@https.bugzilla.kernel.org/>
References: <bug-212163-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@bugzilla.kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b="G9Q6vek/";       spf=pass
 (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates
 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
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

https://bugzilla.kernel.org/show_bug.cgi?id=212163

--- Comment #1 from Andrey Konovalov (andreyknvl@gmail.com) ---
Patch is on the list:
https://patchwork.kernel.org/project/linux-mm/patch/20210804090957.12393-2-Kuan-Ying.Lee@mediatek.com/

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-212163-199747-WbbwF47UwH%40https.bugzilla.kernel.org/.
