Return-Path: <kasan-dev+bncBAABBBXQYKMQMGQEVEF5JZY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x340.google.com (mail-wm1-x340.google.com [IPv6:2a00:1450:4864:20::340])
	by mail.lfdr.de (Postfix) with ESMTPS id 2821D5E95D6
	for <lists+kasan-dev@lfdr.de>; Sun, 25 Sep 2022 22:20:23 +0200 (CEST)
Received: by mail-wm1-x340.google.com with SMTP id l15-20020a05600c4f0f00b003b4bec80edbsf3131732wmq.9
        for <lists+kasan-dev@lfdr.de>; Sun, 25 Sep 2022 13:20:23 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1664137222; cv=pass;
        d=google.com; s=arc-20160816;
        b=Op0yS7ujE4ANbWmxBHkcAc5B/JRRZJ27HxRYLdZEIUYyhzc4oH4YARcx/hW6aftArO
         1HwbUoHL0uYvpynNi88i0Iweh+pe/s847r4v+5KyWZiTX7tO+NtB7fSB5sl3F/RjQ/Sj
         eg0eQAZN3XS/fzzNaSNFJvvnPo8rxndSpMuN4yPPKMWQ/rmZ6CBOWu2XZPM0qMTrWNEe
         URaDJp+Ghrj1zUF1clV6vxcKOLAWzknynv3h3C8OcCAtKb0JVIfp1eHjFmszShEmxlaa
         MU9XUQBhaX+1SwkDwBFw2RPFzd/k2roCqBmyVG7x3h16oZXetQpBm5F7p+hHrSGv2Hl1
         K97Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=LwGl9ZP7Rav8NEdJ3E4f5Sy3mlQ7A7RmA0aqbJMPkU0=;
        b=AM20bCZ0W2hjogGpeO/pp13CrL/+h35XYdsd44Wv1DR5+BH0wrivrUVTdXxkIwBNYv
         WLLyJcC3wjZQJSHwWVekOksHZxyXkbXBoEGaUIZykEYm7sPdC8bcBpIld4X7Ho+V5iRu
         wxQW6SjBez6ksqRBEcdsl/oU+KnVgdPQopdrfmrOXQqpINigyVMALNrjwteiJ54XSUQo
         GrYr387CbgyiI2TZ7jdfxLuVNpGydjO2L+dOWqAWMiewaaUWqXgebnQMy8NA4dSpQoEq
         4/xfqa9Ystf6kODs3YO5ZAhZbNEthdepaT63PilHRGp1VVTaXkvH1tRP9ZjnyXuOT/WO
         XeGA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=OlIdFxJv;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:auto-submitted:references
         :in-reply-to:message-id:date:subject:to:from:sender:from:to:cc
         :subject:date;
        bh=LwGl9ZP7Rav8NEdJ3E4f5Sy3mlQ7A7RmA0aqbJMPkU0=;
        b=JzxAZEvau0Va4rsjEjM+mz8SLojuGJfMVV/Nxetu1S9KCY+HEdX0W3M7Sg0GSFCCfo
         716QMKBL96EicUIjUba5DP/pBZjBVITCUWp4m7A6xKmyE63tRYTUsXVDrwj1Dfs1+t7C
         hXOg1Lk03tF+vQ6BsRvpi2R8S6IlfCRQNcZUlPdp2QeLI5J9XHhpb870lA5vxaig/Stx
         aI3i7Y0qeo0e9iuPelIF+PNcCV+xwEftx5b9ufO6+er6UerrvFFr8jg/C/ddO8tMUEMo
         AvcqbI/rzV5AzUkz4rA57haCVmqEp9ALj7M226v/Ogv74qoKSF0qvJs7U6miBo+G42u2
         1UGg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:x-gm-message-state:sender:from:to:cc:subject:date;
        bh=LwGl9ZP7Rav8NEdJ3E4f5Sy3mlQ7A7RmA0aqbJMPkU0=;
        b=BdiJpxwuLaLKYzJZzf2vogiDa/ZyfOWk1tzdXlbKnCWOQ/+fV6Hv8ns1ECEWQrIeUS
         HKxUQggvghFwjlR758OZXyTHAFdP/E8yzBV1RXGUBl4Wj+un699TTNGlelld4qgfAQyU
         6rRBMxNRajhYwzgNdFYJQVOVLFVOjrAlR27Ij1OJFjwx/RxNeDzuL0B0PiLVeKBWD67c
         rjQIexXzvC8kvTPwo/0ReZUUPyidXMmFDM2ZVy6QfU+z8TcNNG094zVq0n/ictBAVjQD
         0GCknGHnzZGeZ6aKv8KuA679ajlI0RVy6jqp5l6q/O8cxAEFphIfVpDo/03qHr3s1cXY
         A1Hw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf1Lt41N0ClTqG+v0BX+HbogshRPmatLaeJiqr+VFLN+B4kIpoR2
	sxDqmFolMf/lhX49tLi5G08=
X-Google-Smtp-Source: AMsMyM4n7C/4WsF2Q5oLJv/55J5/0gdjp7vMe2eT6mpWJUhp+fiPM3yxOGHPJxZF3eWFwvGKTDgWlQ==
X-Received: by 2002:a05:600c:474c:b0:3b4:cbca:5677 with SMTP id w12-20020a05600c474c00b003b4cbca5677mr12512333wmo.76.1664137222558;
        Sun, 25 Sep 2022 13:20:22 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a7b:c395:0:b0:3b4:9792:b16c with SMTP id s21-20020a7bc395000000b003b49792b16cls7361867wmj.2.-pod-prod-gmail;
 Sun, 25 Sep 2022 13:20:21 -0700 (PDT)
X-Received: by 2002:a05:600c:548b:b0:3b5:95b:57d3 with SMTP id iv11-20020a05600c548b00b003b5095b57d3mr10820750wmb.153.1664137221611;
        Sun, 25 Sep 2022 13:20:21 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1664137221; cv=none;
        d=google.com; s=arc-20160816;
        b=suiHGpdof3XrR9wXKeZ1UtMbCfI80pes4LEpVKZu0E84Oo/ZOJVz8Vvmtm83f4dsQG
         pDrYvj05KeWMzsF1GSLrrXyO/dO2d4uMw/GTphLjuZq5y+Bh8g8Kq5GppTanqtsBUZZl
         3QmC+E1UwKl5SZLFaBrmQyupGT1ur0vnV65Vmlb6i7O/RKzymZJLXjVeOJzZfJDdcXke
         /a7M5gni5xZorqRkFODG35AnZBIFB/Danq3xxz8aGHeC3khBiOQvKuIM90xrhJCxKx/i
         oLJSsDrWfz9E6LzRtPOPg544qXuQRK9y84TWaHcGnhXp11ZcBhN/10bfUtzp5y9kGdio
         VNfA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from:dkim-signature;
        bh=ogRACx0g5E1o9jaWBDZgusdK3oPm5cqMN8lo33+Agj0=;
        b=yFZMOlXw0AHdTRx1XUSoWx2H5jrjJKJSgtQxpQn56VLUGDp78LabyBjGEe3tuTGuc9
         dSzzlFstUcjncemieSf9HQ+UCU2lG86fZYxkwXmQS+ybhpYbFhbUuKJWc1uP/c7h7K17
         unUQBfrWQTqQFZ2fHfnpLbLFNH216Ofd+VEXEqmtT4jPIs0Z8144cMePcq0ZPBzRNlcH
         tkrjp65GAwyZO5pBdwhr76L7Gi1faCfaYVFVSynE7fOD/SeCNxuP8Z42V1B9lcjI5Pm1
         5R6n/54PAr4+8qBYE90Dx5TMBtBQfhUHStOPVvwmWAm0gtQ4wKmpKpuyl0vzKY1mbqAm
         +KNA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=OlIdFxJv;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from ams.source.kernel.org (ams.source.kernel.org. [2604:1380:4601:e00::1])
        by gmr-mx.google.com with ESMTPS id f62-20020a1c3841000000b003b211d11291si715639wma.1.2022.09.25.13.20.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sun, 25 Sep 2022 13:20:21 -0700 (PDT)
Received-SPF: pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) client-ip=2604:1380:4601:e00::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by ams.source.kernel.org (Postfix) with ESMTPS id 408A8B80D67
	for <kasan-dev@googlegroups.com>; Sun, 25 Sep 2022 20:20:21 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id F1051C433C1
	for <kasan-dev@googlegroups.com>; Sun, 25 Sep 2022 20:20:19 +0000 (UTC)
Received: by aws-us-west-2-korg-bugzilla-1.web.codeaurora.org (Postfix, from userid 48)
	id C50EAC433E7; Sun, 25 Sep 2022 20:20:19 +0000 (UTC)
From: bugzilla-daemon@kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 212205] KASAN: port all tests to KUnit
Date: Sun, 25 Sep 2022 20:20:19 +0000
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
Message-ID: <bug-212205-199747-5zfQIaxq7P@https.bugzilla.kernel.org/>
In-Reply-To: <bug-212205-199747@https.bugzilla.kernel.org/>
References: <bug-212205-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=OlIdFxJv;       spf=pass
 (google.com: domain of bugzilla-daemon@kernel.org designates
 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
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

--- Comment #3 from Andrey Konovalov (andreyknvl@gmail.com) ---
Posted patches porting #1 and #2 to KUnit [1].

For #3, another potential approach is to hijack a userspace process via
tracepoints, and execute the test there. However, this can only be done when
userspace processes are launched (=> when KUnit tests are loaded as a module)
and also requires the faultable tracepoints patchset [2].

[1]
https://lore.kernel.org/linux-mm/653d43e9a6d9aad2ae148a941dab048cb8e765a8.1664044241.git.andreyknvl@google.com/T/
[2] https://lore.kernel.org/bpf/20210218222125.46565-5-mjeanson@efficios.com/T/

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-212205-199747-5zfQIaxq7P%40https.bugzilla.kernel.org/.
