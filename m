Return-Path: <kasan-dev+bncBAABBGXVX2IAMGQEUB5Q2JY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43b.google.com (mail-wr1-x43b.google.com [IPv6:2a00:1450:4864:20::43b])
	by mail.lfdr.de (Postfix) with ESMTPS id 0BA724BBC1D
	for <lists+kasan-dev@lfdr.de>; Fri, 18 Feb 2022 16:26:19 +0100 (CET)
Received: by mail-wr1-x43b.google.com with SMTP id s22-20020adf9796000000b001e7e75ab581sf3644862wrb.23
        for <lists+kasan-dev@lfdr.de>; Fri, 18 Feb 2022 07:26:19 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1645197978; cv=pass;
        d=google.com; s=arc-20160816;
        b=t++kLm1S/VUQC1g622+TI+2Xn5ofnuc0BNJowyJdGdetK0edfFKoLkPs1dIc1955Lq
         W1egn8yxADFNwG+3nUMjhiLwhNfFjpBtgvw9tbaFmOKsAJ/Y/HaVUZb7qgXoq+oXuL+M
         B9ghj0MJNYBD2Al3NG/4zFIO7RrpqU9Kme4e6XDUR65Z4Zxp7iTKZ/2iX20CUdfPyypk
         aw8GojJLbvMisUyyHK9e/3tbezirGarsqnwQBAI/bDUd5xgVP0WiwNTZV5adLdR7p6rp
         CLxsmOM6Vk5Qh2YkNg1p8FbTNV0/b0oyqPRNfr0q2P0RLC6letMGvVVsFsTiBiC1jnmf
         9bJw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=UYYrjG4gpv8Ph8Q39vgiSRxh7JrwhlKqQ6Prz03dAek=;
        b=GprcuFiYs49G9bGmKxdlTvP2N55+f8/FR4icJCbGoZM4HE99Du/SIoibMiDOB0I2Oh
         C3aCuqvGYiMDZOsrYJV3lP2gD3AvezByhP2nEjCdNpfLvz7c4IEefh5FIqMri2+R901D
         YBrw34sW556YtYb7mj6pvoCNskM05T/sQwblqmtX5V+VShgN94EJsida1B9sMCxh0LO2
         fEeHZ5XsIfJMhjYkd1TmvnaJjM2bTEgF8ctyDJbl9lqPN8pixmSFKCBFP3ytSGy3FJuf
         fnh/UiL0BTQcbJSPfnnxDtgYu1yWvvIIhc4hJlUh8zs4dRXPtcCb+UiXwlkT86snJxbX
         itpQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=NM2k5Jc8;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 145.40.68.75 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:subject:date:message-id:in-reply-to:references
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=UYYrjG4gpv8Ph8Q39vgiSRxh7JrwhlKqQ6Prz03dAek=;
        b=tPrbWlL9VHM+g1tzxo6q0AnSgRFbKewE3EoLF8JV51zHn7PFyDodk5CjxmMmlwYfWh
         A1nq/On/TwjnNt8TSsHfDeZyKGDGGld/CTX60oHQSNlArFPdl5kBBsHPsCz2Ny42q6QN
         LjUKVRZpf6m5rw3+ouMf50HUBnlfmsCrFr5kJI/7Fkzn/yYZxmrZ24Zu3IdDqQP0XWWC
         2EaoYuV0yRGBI0cOW3nE2+ZnynL6+jinYp0XfFe5ohQ09r6+khO/l4EU7Jl7rZjVb1oE
         93Ww/73jRR2qGNdz49oG2Lgiy/YG/Gu6k4b9aIaltIXKj0SneilMLaCsKba9zKByUC2D
         6QVg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :in-reply-to:references:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=UYYrjG4gpv8Ph8Q39vgiSRxh7JrwhlKqQ6Prz03dAek=;
        b=ptdngW5EsNDw3grkZN77oCwBiqTrbDH7pgBX0OYlCbBndbuc92bmczU+AZF3k++2JD
         46Lj8AzDlMMz2dZsvSOgxychDCz7DgIEVn+bVm4zbWTi3+N0G6IX/aV3wPuvTNO74c/3
         IcNYl3uD27nOwsOwla9pKH5FBbMTgfxroZ46UDttrnKe07Ht09Ylz93O1IIgi+ZWJXty
         si9aiY4Z8MiXhPJTsAJSro6m4J0lu8RqXpBdTQD13njUPFz+sjQXKFFVBZxCBIwQMxUt
         pnQgtV6slIYiLV7VI5IIH5JvRgGSazw/d/1minR1HUsgVcqtCdx4wmKMr+dVG6e4n4oj
         +d9Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532aBA9NpBb+cX5YxjynJdSxqAKkKSYTQYUBC90HoOTpeuOPQ90G
	QIvnpPtDdfwEYxcg0u1SaCs=
X-Google-Smtp-Source: ABdhPJz2GZRXd628t8TeLyIes7mmPxPqud6kroUz2Fm4FQFrZ2CCmEQTdqUGyhxrNDKX/8NbsiwMhA==
X-Received: by 2002:a05:600c:3505:b0:37b:bf81:97d8 with SMTP id h5-20020a05600c350500b0037bbf8197d8mr7843357wmq.30.1645197978606;
        Fri, 18 Feb 2022 07:26:18 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:fec3:0:b0:1e3:3e51:b38d with SMTP id q3-20020adffec3000000b001e33e51b38dls95009wrs.1.gmail;
 Fri, 18 Feb 2022 07:26:17 -0800 (PST)
X-Received: by 2002:adf:e10a:0:b0:1e3:3188:79c7 with SMTP id t10-20020adfe10a000000b001e3318879c7mr6423369wrz.329.1645197977788;
        Fri, 18 Feb 2022 07:26:17 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1645197977; cv=none;
        d=google.com; s=arc-20160816;
        b=QvtGi83g1piWbyGxzkoLMwWE+lRDZMqxc4mHEFWQE2hg77muBL8S3PmHASweW2DJgk
         3aaivsXxK8uQxpekYzznFzjl9XEmxJNX1brq8tJWYLHi2PRFQGHkvqb9Pc+Z8tUkN0XN
         KRLRrO2vqKCFMnrWFUpBXkbuHVCurowq886jn75GttZAVa83UHbHb7zAp/5uwu43qBYL
         GMomOJy+R7lEBVf+CZKZLhd5PpzsuwO3DWZYKcRfq9MLAcS6gnHJh+lzwMvNhtYYUXAW
         FsQwGMi2SLdkNtEeMHAROmapy6/H/VbbiZJLA52L9HTsHZGuTcyxwam/mCHluz2ceZn4
         C/xg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from:dkim-signature;
        bh=jjgLtPjoAV23tLzUuTSbaVwGCKgmId642+RGfYdpRUw=;
        b=JVOXaoHpDjpS7l/zS0vV1w/huTEUxZzYdjfebAeTZ4+zochmHUfTAoR8SnOanOm3Z5
         JDfsfCQYUX5S9yYT3c6lgYYHB7mPiB3I/ogptr8P9XNxM104W4uzBVXfWJsJhDD8sY1f
         /EfUKwCY4DBCjrCiAlFYt3QvklQPPmgyQksCtWMbZYJDkBpk2eBezq9kWFuZUz5q0Zu0
         On+J7i2WBGa9iH5Yh6r7G4nS0Q1y0doG6mer75MXJOlOO2ugM4Q3y6R+HLB6FcbMCKQe
         /HGFfVAh+VUD9dhUxRhyhrORCtUGXu1Ohx6Gc4sXyb9uDKqjMAUsvU9ujDJarWc1W+4G
         GM8A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=NM2k5Jc8;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 145.40.68.75 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from ams.source.kernel.org (ams.source.kernel.org. [145.40.68.75])
        by gmr-mx.google.com with ESMTPS id j13si1432323wrp.6.2022.02.18.07.26.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 18 Feb 2022 07:26:17 -0800 (PST)
Received-SPF: pass (google.com: domain of bugzilla-daemon@kernel.org designates 145.40.68.75 as permitted sender) client-ip=145.40.68.75;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by ams.source.kernel.org (Postfix) with ESMTPS id 869FBB82671
	for <kasan-dev@googlegroups.com>; Fri, 18 Feb 2022 15:26:17 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id 3B28BC340E9
	for <kasan-dev@googlegroups.com>; Fri, 18 Feb 2022 15:26:16 +0000 (UTC)
Received: by aws-us-west-2-korg-bugzilla-1.web.codeaurora.org (Postfix, from userid 48)
	id 1F734C05FD4; Fri, 18 Feb 2022 15:26:16 +0000 (UTC)
From: bugzilla-daemon@kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 212189] KASAN (tags): consider not tagging on alloc
Date: Fri, 18 Feb 2022 15:26:15 +0000
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
Message-ID: <bug-212189-199747-cjQt6wBgWx@https.bugzilla.kernel.org/>
In-Reply-To: <bug-212189-199747@https.bugzilla.kernel.org/>
References: <bug-212189-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=NM2k5Jc8;       spf=pass
 (google.com: domain of bugzilla-daemon@kernel.org designates 145.40.68.75 as
 permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=kernel.org
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

https://bugzilla.kernel.org/show_bug.cgi?id=212189

--- Comment #1 from Andrey Konovalov (andreyknvl@gmail.com) ---
Another potential reason to consider this. However, it assumes that the
match-all tag is not used (https://bugzilla.kernel.org/show_bug.cgi?id=212173).

If the attacker is able to craft pointers with an arbitrary tag, they can do
use-after-free-before-realloc accesses, as freed memory is always marked with
the same known tag.

With a random tag being used for freed memory instead of the invalid one, the
attacker would also need to leak that tag before they can do such accesses.

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-212189-199747-cjQt6wBgWx%40https.bugzilla.kernel.org/.
