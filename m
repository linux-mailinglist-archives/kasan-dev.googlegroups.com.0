Return-Path: <kasan-dev+bncBAABBKMTRWJAMGQE3VN5CTA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53b.google.com (mail-pg1-x53b.google.com [IPv6:2607:f8b0:4864:20::53b])
	by mail.lfdr.de (Postfix) with ESMTPS id 28F3F4EB30B
	for <lists+kasan-dev@lfdr.de>; Tue, 29 Mar 2022 20:02:19 +0200 (CEST)
Received: by mail-pg1-x53b.google.com with SMTP id r28-20020a63205c000000b00398344a2582sf3690555pgm.20
        for <lists+kasan-dev@lfdr.de>; Tue, 29 Mar 2022 11:02:19 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1648576937; cv=pass;
        d=google.com; s=arc-20160816;
        b=jDwmLXzLxy/WysvD9y1pRIb8lPIdHvHDy37HJl+Rxq/n/r/ANjD+6wWCM2ECZRn+kG
         2m6mPFBzZL6d4326KD9/g66uygOSe4O0LFuS+mGs3ZeK6hxyk5MWVrnT/KvwJrqqYm6X
         55cYvFkrOqpRKm6U2sruCfi42Th5xVtBq14OQKtth65gDk5svfF5X67I2w3HIyUW9ObF
         pvPJ5f7cKDRo65sJCuvHxWFoyRlwlY2RvtZmyEY4N38u2cgH62yEp1iYI9hOtozJT8lu
         aMsQWfetJJSJX07wAB5hV7vcIUZk7hG6rSe9AkrP1urltXbDOFzc+mg7D9c8ZdWyOZOE
         TAjQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=5QZuWlu8EtkNnSIrrcPWWwkgReyVfgn9z4d+Lc6gcGs=;
        b=WnIGcey3govlKQkxmb3jyQSoCBPi6BbaiOZ2WSnTSlCExa5u/0CQXO18Wr/Mb3dhPQ
         hb5Zuym8pED7gtQaVjuRTu3m+KBznkOJXzgoKL0AgsC8m3Q5esA6UEdd3WmHOsNhD5BD
         fkUm6M+rz8q4RMeW1RJMp/4K21yzkpYeoLiOHwhuszZEMA/hVzZBcr1uUubN/xZpQ9UV
         LNO+9CfuRWPVrsvsicWgxb6B2qLjBkynZV1VVw5QjeDAmCnXlaYdkHE0ETJrT/nzXLJp
         LzF7n3mMx2S6dt+zpra05yPozhPqnRL33f0XEktlicxaP5U63JWaW+6S0s7roIcG7EQ8
         DHIA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="FI/Za/O1";
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:subject:date:message-id:in-reply-to:references
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=5QZuWlu8EtkNnSIrrcPWWwkgReyVfgn9z4d+Lc6gcGs=;
        b=czrg4wNJ6HXF260eN55r0nn5eyV7hVahV3Xpz+OmnDgfbaJ0JwohKqN1mZEQ4xwgox
         XWs87dJEWYF3E09nGlZ2pcC42GzWGT9+Fmf0n4JC6fZ4urSzQbftZ7vBv//H8QBRF6Uu
         gplEPNbzfnzAMETJUtflJN80X+1HgQYI/Cm9JSELNurYlj1yjaWrJBREfkNkm+AvjkYo
         R81EY5G/hZVoqoRgJVq9dZCroVancsujUelrg29VnWSymDgQEIPsPUDC+4xXpzz+Y3pj
         Uu81Xrv0ghdtfRdkObZ+2p1Q0Z25qlIf3tlBd8qYLS9IwF0ynHAbjA9BgJ9XgXdspgbX
         6Qog==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :in-reply-to:references:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=5QZuWlu8EtkNnSIrrcPWWwkgReyVfgn9z4d+Lc6gcGs=;
        b=oN1xsyV6pMe1/NWzlqhBx7o79NE9KHZaXN2FszP67k73MfDgdmpt8tS/Q5u60MxN9e
         ahyFI7VlILkO6/rSzu31OaAS0s5HlPRzdQ9S95GHzF04AgvDMksabjtkQJHetWvi7EtF
         2nyP0lIFdC7YlONJbwL3OuT5bXy7Izya0nRxkifqsp0nbiNW+gkz4LLpEfUpO5I8h7Jw
         81PA53UttRUJjghWlyJCdG5ySzkpZnUJNluoSDpW3EVaxi3M1KLuPwrzHdMbaMTVh3/6
         2MJOtofdBNFG7GSa2noL8YfSL8gtc8Zbj2eMzQbDEBH5uONz9TwchXxvY37uNSBvAdG9
         xOpA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532f2hzfDAW5rgEfzdQrFgyFJjnidIdYo6b+pflqEW6KmOfpj9i1
	Ix6SjrqePS2sUX9K7U2vxXM=
X-Google-Smtp-Source: ABdhPJwRMY5sQc+0zhUxssu1IV/xyFVICdgF+8D0vTIM0Jhl5Z588MGf+uorL1Ip8lI99z6f/xkmug==
X-Received: by 2002:a17:90b:4a06:b0:1c7:2020:b5b9 with SMTP id kk6-20020a17090b4a0600b001c72020b5b9mr374527pjb.58.1648576937152;
        Tue, 29 Mar 2022 11:02:17 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:7981:0:b0:382:742:7fd3 with SMTP id u123-20020a637981000000b0038207427fd3ls6190924pgc.10.gmail;
 Tue, 29 Mar 2022 11:02:16 -0700 (PDT)
X-Received: by 2002:a05:6a00:1a42:b0:4f7:e158:152e with SMTP id h2-20020a056a001a4200b004f7e158152emr28941938pfv.50.1648576936445;
        Tue, 29 Mar 2022 11:02:16 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1648576936; cv=none;
        d=google.com; s=arc-20160816;
        b=LN4ToFLkxdIHTTT14OW3JKjBveJHWqzoQpAXQl4jW8Wmq/qdNjOzsp8L0Nzvo1Dpwo
         wRhcD24NyUXf1PbzLEow3v19EGi2DJyU4YmHA5jTkgY74cOkPEfCRxIvpg2Yk9+kf9KR
         ksvdYnT/4hHUr/5cNEnI5LKDNK7zuwXLzM+QoBweNqALiCg5Nn+joQ5WPN+m/cCFkXym
         ZL0q6U48NYyhSYpMF5/lAWQB9JS3oo38Ekji42IM8d4bXxIf3P0YOa7pxSz3x8W1O/ly
         xScbryZ6xkkM8lJPdQw3GN1u/xOL4z4IFxxJ2ZRFKHWjH/VuoUujaT8BsUQqX1iAFQTi
         a5Dg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from:dkim-signature;
        bh=DCTs18qJECBx5bacJ/9fNdpBzu/Rl7HSE/67D8raCYw=;
        b=kF1OA86kxYcdpOXZMRgX4VzzPWrYlOYtok13/qbHlKMhWfhIedBeHpIcAOHvsJMbvg
         eMza80id+PdkJoAOqzkdfGTxmskwRgcOT1nbiM6mQ+rMD9cArdtvDYnTN4/U8BPZIWQd
         6ygYNa6I+dYJdIBFzy1i+l8q6AptpO7NHhrl16A6tl3v02M1bwkGHBBncW6ukzb/qXwa
         yBqkZLcH3pJyubA2XIH+4ZvJjWM/sNwD54vhXSIFuqqz7Km5spZwDtWD7lrUAy8cbqrX
         rm4mkJWeu1fNHq1VhWQ68+SWj4BoaNbKyOGM0rq5Z7vMD6PbzSvmydjsVrSSsncCxRmr
         +iow==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="FI/Za/O1";
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id k5-20020a170902e90500b001517cf05af9si1077946pld.8.2022.03.29.11.02.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 29 Mar 2022 11:02:16 -0700 (PDT)
Received-SPF: pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id EBAA26159B
	for <kasan-dev@googlegroups.com>; Tue, 29 Mar 2022 18:02:15 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id 5CB16C34100
	for <kasan-dev@googlegroups.com>; Tue, 29 Mar 2022 18:02:15 +0000 (UTC)
Received: by aws-us-west-2-korg-bugzilla-1.web.codeaurora.org (Postfix, from userid 48)
	id 4A055C05FD5; Tue, 29 Mar 2022 18:02:15 +0000 (UTC)
From: bugzilla-daemon@kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 215758] KASAN (hw-tags): tag vmalloced per-cpu areas
Date: Tue, 29 Mar 2022 18:02:15 +0000
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
Message-ID: <bug-215758-199747-fsKTjS2Jpd@https.bugzilla.kernel.org/>
In-Reply-To: <bug-215758-199747@https.bugzilla.kernel.org/>
References: <bug-215758-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b="FI/Za/O1";       spf=pass
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

https://bugzilla.kernel.org/show_bug.cgi?id=215758

--- Comment #1 from Andrey Konovalov (andreyknvl@gmail.com) ---
Related bug: https://bugzilla.kernel.org/show_bug.cgi?id=215019

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-215758-199747-fsKTjS2Jpd%40https.bugzilla.kernel.org/.
