Return-Path: <kasan-dev+bncBC24VNFHTMIBBHUMV3WAKGQE7DVE42A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x338.google.com (mail-ot1-x338.google.com [IPv6:2607:f8b0:4864:20::338])
	by mail.lfdr.de (Postfix) with ESMTPS id 449C6BE128
	for <lists+kasan-dev@lfdr.de>; Wed, 25 Sep 2019 17:22:07 +0200 (CEST)
Received: by mail-ot1-x338.google.com with SMTP id l7sf3426785otf.1
        for <lists+kasan-dev@lfdr.de>; Wed, 25 Sep 2019 08:22:07 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1569424926; cv=pass;
        d=google.com; s=arc-20160816;
        b=xx4Fgm5g7wHSj97gbHGsmAV/u75v43NsDR83dXVg28hFOsYIhG5CopNidHk36Evo0y
         BBy88M3HG560+4LaBOo8nz8hFCeiI8VGh5skHm8ikfJQ2RkMoQAqdkC4WrUx1EMblGAT
         gvAJ/4Y4K5Sjps5ef91Uok4slWAMUlStbjVDgrN+IOL521W7HBcAygJx/hCSyiLV8ypF
         Xi0BGtwJLCN9lo0xLd+o/en7E1b52wEExHuhRd0nHCyfvmIowPE/jcnedM9ihyG93wsg
         6qdr6fPBaMcVq6tI93Og1vX3/irLLEQerfEBP7tdcqudH9veQdvd2WSqMdKM1TfTIgVz
         9veg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=ErZEANDQs8MXTUCZYZHUcH7O4ojfWnqQBY0Myp/tHeg=;
        b=OwZe6roBNrgxbGoXdgJ/vt63BKbPhxhYXFz9u/x/9zZh8SCNkWf0PyZl0SkruhLfio
         zzqhs/liLn0TKDgjNk3z43Sqm4oHgT/ezldISvZw6kaFFDIYP+HS+T3EzOsTDHthQBZM
         arSagp97bt68n8MKaMTvIJlrePf2UeloZ6WCo35ESAvjNicNXQvN3R/4PP6uCfvPE10w
         g6+p3xpW5OTaYDIWTEyGHrBI+Cr5L+Vz3pclTqL/yf42UYbE2lmcQqtkY1Wizyk1WKQ0
         f9MGc6C4QjoEhTZXbQuTN0XRux2DGLY6q5b0B/cOtz17CpBm3o5RHkXloKm3BydUVhac
         VnoQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=rois=xu=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=Rois=XU=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:date:message-id:in-reply-to:references
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=ErZEANDQs8MXTUCZYZHUcH7O4ojfWnqQBY0Myp/tHeg=;
        b=PdhWt+R/bsDZDlXYG67BxWe2SWb7492eHueYj8QPMvLkUNEE8wSTopiCZbuHpusPlE
         HU5TbdI0pfO3YrgHxfkW2OH5rgHp73/vuzRclSsIpQQTk0n8AopfXzr6cgGJVIRkKibl
         SWB0BwdbTOyEviiRq78kPlRbDoU4hURnkct6eR0MsZa1rdhzO71EyFS8jcKU4i1Tv5c5
         Dd7Uvi1aKoB6ETURNqumjt37W7+wpM5mC+9iwhLDoTBJqYAxs43Rdgn5a5PAan0OGY4c
         E5QUt1I+RvvouRwbbbRtTmmoXSSDFvtl6ApRZhKs5lwfQm+NybHa20OkOjvYccKJ12iF
         v+sA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :in-reply-to:references:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=ErZEANDQs8MXTUCZYZHUcH7O4ojfWnqQBY0Myp/tHeg=;
        b=X8uBMc70yjgFa3K/n5gyuVEXlqbiOLu0ro0Ku4NOUU8NTmeaB+ZPJIR7pDh30jYHS+
         HuYC96g/HIVlw4/YAaTwrvCRJCPMk2w2SrhnpIowZtUbdefwhkgMmbOtIR+MCn/s0Le2
         OewBV7f7e16GmQ4mYMAOZQvrjPaLZqUF9XE01yh0GUHk7hrIoVhlII+LKqNfyPid7aeH
         wBdAoKrd7+hXnnu7lvLHaw4zqf9gMBJ2zPDcv58poWn3wxGGUrqag+ziPAVLeF67l/Z4
         2PoiFtyW856P4Ef6r9Ub1fhmg1NOabx5qgQ5vHfSHHI+FzXEZbDuNO8eL0PmmIyQogGe
         0lag==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAVVJ2RUJZ5pHW4kdeyz3nHsJ77RNMm8VfT9YPBlEt6VH81pBXOw
	5GyH/K6YSRl1lOrQO+OO01c=
X-Google-Smtp-Source: APXvYqwHwnewnXRJt62h7P0Z9lrUTQg4LnhwD3EJkl84cNr5wm1pRbARwZutG9ebkF1vxkrAGFTn9Q==
X-Received: by 2002:a9d:3476:: with SMTP id v109mr6786937otb.179.1569424926134;
        Wed, 25 Sep 2019 08:22:06 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:2963:: with SMTP id d90ls567535otb.12.gmail; Wed, 25 Sep
 2019 08:22:05 -0700 (PDT)
X-Received: by 2002:a05:6830:16da:: with SMTP id l26mr6691003otr.339.1569424925880;
        Wed, 25 Sep 2019 08:22:05 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1569424925; cv=none;
        d=google.com; s=arc-20160816;
        b=u61vRefxAXC/yRPdLRFQIIWUOmTV4yUnERpiI8pVOTx0N8cM4014b8aezJgeaSYdF9
         Lqlzt4qyURAsXQtpgDWqHrMXVGfvwpG+dWf/fENC1dlQbCQQUoC/Al9gRso5j4fhy/WZ
         sGtKvvGR3Jy/L0slJQ6MVI2sQEzvsaGf4UeQ1d4eIAKoODBigNwCAuq7aaNqoBMmltqk
         0Frq4wndn/0eWeWp/FTkDBRX52AmQVxPZ0UwIjziwikDl5qsXqpNhe9iMQT/BxsuJYo7
         progdq6oU/2qv4nei62e/ZjHppGqgHIOOVdX5bLjmnmCe4Q6ZqIK1ieHAbQJ/VGntWVv
         9q/g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from;
        bh=fNbpvLPw4zWnlyJKU8PfbCHDaOkE9cRL4oXYyIBtqto=;
        b=yQarqKr5nwWJX6w0rCRsrAxi7hE+v3S143Np1RD0C9ymH5dOum9+Vue5rUqUTbHFs/
         m/1PjZT56Dv4wigZ7rjz5fVtDDyuUOuXnRIQCeKDj5aihdATUHE2EbNxeNN3qrbwx9+5
         wcL4M137gdIFoD8PgkH2uR1bnqqcAUtHYkEpgMbzOIwV+o3fdPUcXNCF2rOzIDSzSwtN
         G9KLG4KGt6BjpEEb5cr6DTZ3Gvnnou5MERvVmQZULGFICIULGwQfoCspR5rBzFF2xhp3
         gJJmwmG9yeHVfRu3NDIRL6clnFpai3+Oyy0Sg5TBg4Q9z4w+C0qIrJe7nZkhGipXvsrU
         +5SA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=rois=xu=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=Rois=XU=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id w8si428188otl.2.2019.09.25.08.22.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 25 Sep 2019 08:22:05 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=rois=xu=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 199341] KASAN: misses underflow in memmove
Date: Wed, 25 Sep 2019 15:22:04 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: changed
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Memory Management
X-Bugzilla-Component: Sanitizers
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: normal
X-Bugzilla-Who: walter-zh.wu@mediatek.com
X-Bugzilla-Status: NEW
X-Bugzilla-Resolution: 
X-Bugzilla-Priority: P1
X-Bugzilla-Assigned-To: dvyukov@google.com
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: cc
Message-ID: <bug-199341-199747-ve95GPaXPh@https.bugzilla.kernel.org/>
In-Reply-To: <bug-199341-199747@https.bugzilla.kernel.org/>
References: <bug-199341-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@bugzilla.kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of srs0=rois=xu=bugzilla.kernel.org=bugzilla-daemon@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=Rois=XU=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
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

https://bugzilla.kernel.org/show_bug.cgi?id=199341

Walter Wu (walter-zh.wu@mediatek.com) changed:

           What    |Removed                     |Added
----------------------------------------------------------------------------
                 CC|                            |walter-zh.wu@mediatek.com

--- Comment #1 from Walter Wu (walter-zh.wu@mediatek.com) ---
Hi,

It still has the issue at kernel 5.3-rc1. Maybe We should try to fix the
missing underflow issue.
I first try to see why the shadow start is equal to shadow end and send the
patch to fix it.

Thanks.
Walter

-- 
You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-199341-199747-ve95GPaXPh%40https.bugzilla.kernel.org/.
