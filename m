Return-Path: <kasan-dev+bncBC24VNFHTMIBBU6JT2BAMGQEOH4DGOY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x837.google.com (mail-qt1-x837.google.com [IPv6:2607:f8b0:4864:20::837])
	by mail.lfdr.de (Postfix) with ESMTPS id 53CCB332C4E
	for <lists+kasan-dev@lfdr.de>; Tue,  9 Mar 2021 17:39:53 +0100 (CET)
Received: by mail-qt1-x837.google.com with SMTP id 16sf10868850qtw.1
        for <lists+kasan-dev@lfdr.de>; Tue, 09 Mar 2021 08:39:53 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1615307987; cv=pass;
        d=google.com; s=arc-20160816;
        b=B9SlAGDS9i+XeggpNsvHLt/K39dj01aBMY+P2StVUf+nNL06MCi6/DFTVwNcxp0Qfb
         oncHkpg+W0iU+GIva3lk1OhM6gLCkwl64/5yBkD2h618bnJuWdCYVCY//w1kxM0LQdVB
         t7+iM97x9IZ6SRe8B8fW/95diuBC2txrOexrr3csPkBdfjPTV/kNdrhfC+1MrP8n6kHI
         t2uOWOlyvCT/Gq9YbZZ/zPs+rqEkGVPeZijEWQ+tu3atbaoglAUzVi+Lr/Dyd4s+S3S5
         unb4vYKtM+yIjTAVgslPVnl08rGrtl9/kALCF9zsrQYQVo96JSgt87MWZ6sLQM5djhG8
         EXeQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=+SSE5ebJHR60RCSrebDJTsxHv+Vw+Zk5LbaWfCvBGvk=;
        b=arwnQkr2DsjfmeyizzoTdN5zexQqt2qRbI7b0KCIBsuK0AKevU+/lcCXKiM3cF36F+
         JWnGHQjbQRWk7QaOrFx8rAP1WUL8fKgNfALEXbzeRNju71W8LPKhJDDubDFZIHvu2ehL
         X4wt8cX9mpbVuGyjwAMtJsU85mSGkp28muO1/Uv3nJ1+kzZAKhZumosed5eFt/y1jYrd
         s1FSC1rCuqiG6wh7N986BhKgp4N0Rexl1UOkxT85qbgIB7JQ+878Rym3QkamoTKS6zn+
         FCIbNYqa13UTm0Wqo2rwbAlR6Y3TWHgrGQFAn/fi1PxfO3ub+zueOAr+pKthXU+twA07
         Drqg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Rtln3RQE;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:date:message-id:in-reply-to:references
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=+SSE5ebJHR60RCSrebDJTsxHv+Vw+Zk5LbaWfCvBGvk=;
        b=ixYlOFIkTFTUL+Jq7IChqvSG2Htdx3sZN1GmJ2Nk8PR8BAD16USvAb10FH4aMQHE3X
         GT4WffG8pt4qQRJouVQvahHhoxfq9N/V+lNH0nlfRIU7iyMBzWGqeMwRpWjW8yI5q9d5
         bdU2xLJq9Z+9p0dBCtcJ3mj61q5GsiHAtD7DOKalMH+7DH7Bx9p5i2yVbdi35taEkGkD
         /p7dGrW3NEcKZFZN4eLunefFkJTCW94h56n1LKag0IIIsp+zd0L8S2tgFKFB4xlcZPaV
         8qtvfKZ6qWSugK9Yr+bzmfDZKcneOd3igSyHXNGifvAXbc7tNUr3tfMAmCMjAz1YK3gb
         VRZg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :in-reply-to:references:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=+SSE5ebJHR60RCSrebDJTsxHv+Vw+Zk5LbaWfCvBGvk=;
        b=gMDuNxgv9vTgZW5tMBcsbB8RAdZe1so0ynpvP4Dt1lwRHfDx87i+Z5IgMozPgWtj1D
         k8nsplooRFVZD65zyK+tVYn0Y6Mp+i6HVOZedW5EuqSjDYFL6LmXCaleeHrTxiTNmN9P
         LvmaMP+yVpnnkRxqlZ84kz9SKngLmcLCG3GgAoX1DWbHGm1HYy7PDALdGQKHy/CYEEQq
         wFvKx+sp61MrTTta9KQ5t431/wa8lrieoYIAQ/dDI6Pl2ewUycs/d+5fGPYUAa/JhHB8
         wpSjdDIPhgYLzoayAT4Tq6Sj5gFl2BG0qG6RiOOcNdJSofheZrYFHQQMjaTsXufK00LS
         0zxw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533I1Y50N4OTcnSAieKPXvg40t9KEU/rJnuOvKe+asgp2rw81zW3
	8gbHyRmU9TVag6LOm/wQr8E=
X-Google-Smtp-Source: ABdhPJxA+QDCXdKynmElCYxPCM4Bev+eatiuFV6eJ73lKSkRK50bv5MekbhJ8jtBdHqNCsGcLNbfQA==
X-Received: by 2002:a05:620a:4143:: with SMTP id k3mr26939204qko.93.1615307987283;
        Tue, 09 Mar 2021 08:39:47 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ad4:5501:: with SMTP id az1ls5401702qvb.11.gmail; Tue, 09
 Mar 2021 08:39:46 -0800 (PST)
X-Received: by 2002:a0c:bf12:: with SMTP id m18mr26432062qvi.40.1615307986932;
        Tue, 09 Mar 2021 08:39:46 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1615307986; cv=none;
        d=google.com; s=arc-20160816;
        b=HXpdzOe5TZ6sfNqGJhxiw2VXIA1oftng3ETk1OeUFjGKCCJ8/YHJWx6PJHf4M7VhOc
         QzbmjQZf7xmbsnxRFpuooo7XLhMDklbR2L7QiCKyaDXSoiIVuptsEFgQ/RFh3M/WXsSP
         dL/TyV5HFYvEsFb6GSidQlagknLBnmVAzpDf9RcwjGCG+dWSkzJqrJHUicU7/UGbs9kn
         jXx15cIoSnFgNCbFoU+lhRAXIDaMxtrhUfij+fnl5aEijWwbR9DiGbzrwZOCipIGRJxv
         DdtZKktqqexT/0V9YazC9HZ0G+CcIxT6pRaZA5eAG/pPKHxGwT+VZD7yhFkUhuhFgcz2
         6/Iw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from:dkim-signature;
        bh=yFIZae2x/d+GhRXSMroZ7VTdAHR1ut40BDbo8G8WQnY=;
        b=bO68CCP70GmUWHoHAKCGgPJzIzGMQAKmKhkmpNJRrOpPbGCNAkrW67oZVN7X/UdlPC
         oymTwc61ZqSJSs8PtN5gpib3H6fLHwM2NiImmtPqTRuvf99T9LKDe4yd4VGasIv/Kq0v
         jFFprP1ljV3iyLneegb9FG27ZZMXy7GaEznCVlXWDLAsvsiibfP3tEPasCFfTWmvzdYg
         UpQ9iibkED7VEyPBbfqDziLoQ51DnRcHC0REJwqgpSay/KXjvPIyktGHBcTzBpCoMKPv
         acs7mhKiOTkL4jvPw6i3iUiuC24wzs4FBQT94oixyjkoO43xZJcoIhv2CCd6vpV17gkb
         y2Aw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Rtln3RQE;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id w19si1089718qto.4.2021.03.09.08.39.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 09 Mar 2021 08:39:46 -0800 (PST)
Received-SPF: pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPS id F187564FF3
	for <kasan-dev@googlegroups.com>; Tue,  9 Mar 2021 16:39:45 +0000 (UTC)
Received: by pdx-korg-bugzilla-2.web.codeaurora.org (Postfix, from userid 48)
	id E47D665368; Tue,  9 Mar 2021 16:39:45 +0000 (UTC)
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 212205] KASAN: port all tests to KUnit
Date: Tue, 09 Mar 2021 16:39:45 +0000
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
Message-ID: <bug-212205-199747-NWsNg4jvi7@https.bugzilla.kernel.org/>
In-Reply-To: <bug-212205-199747@https.bugzilla.kernel.org/>
References: <bug-212205-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@bugzilla.kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=Rtln3RQE;       spf=pass
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

https://bugzilla.kernel.org/show_bug.cgi?id=212205

--- Comment #1 from Andrey Konovalov (andreyknvl@gmail.com) ---
Some options for #3:

- Spawning a user task from the kernel.
- Creating fake mm structs.
- Using kernel memory as arguments to copy_to/from_user. (It might make sense
to add tests for this in either case.)

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-212205-199747-NWsNg4jvi7%40https.bugzilla.kernel.org/.
