Return-Path: <kasan-dev+bncBC24VNFHTMIBBWEFY2GAMGQEQ3EORLY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3b.google.com (mail-yb1-xb3b.google.com [IPv6:2607:f8b0:4864:20::b3b])
	by mail.lfdr.de (Postfix) with ESMTPS id D759D44FBDB
	for <lists+kasan-dev@lfdr.de>; Sun, 14 Nov 2021 22:42:49 +0100 (CET)
Received: by mail-yb1-xb3b.google.com with SMTP id w5-20020a25ac05000000b005c55592df4dsf23697070ybi.12
        for <lists+kasan-dev@lfdr.de>; Sun, 14 Nov 2021 13:42:49 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1636926168; cv=pass;
        d=google.com; s=arc-20160816;
        b=weqoZsjou0GkxV8UAdPO5DrgKwgEf0ecsJDmHFavRkOXbYRU0B/qjhYmLJP2Bb9Q/s
         il2jw80QkZ2qACtTbAp6EgY9Kmc98RLXKS2LOnyMGnc22APHS8rYeYb/T8/jSm4Gjw9g
         KmMXtMDTpPMtDjFia7jfKFYzEox4ImLSibFNSviXdRZok4lHGmTwRc3Yq+PNH17NJ7So
         6X4J8JKwpvvHaarK9Ene250taid4JBLV63Q0plL0FS337bCq0EvzhZm+TZ+5m2gSyTYt
         pooYwD0qbdC6vCn6RZSsKSQZcyW/Pa1RkFaf34wuNuTtOVk7MNj5g5OGkDD5SqyC8w0K
         ugUw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=8Eu0BHgDuHNQT8s1N140MONeG1z3p80Abvj7l2D4y5U=;
        b=ZUDoca5P/mlihMf+MqbZR8/18Y7Ys0smaOKmVuJXR/3pMViXm4DtPNK5wWxGChoxrd
         4nXjvmeQYkdsTKtrxJiHac2fSfTp+LDvlj8Jvl1iIjy7wWIpDEarpbW0e47vPOq0uUy8
         Z3fUm7YbJ92Rk3+tX6uPdFPQxIM+nrlIVcArMfxqdYuAdcrjMw36m6VcL9QXpZBfr5Ig
         SUUQw9nMYqdJHMCd4vgX7GtRgZHSRp1A+KHj8MrPhPo5hdmKK5Dazo3tLQfILZNpg6e9
         EgpyIJWAifBt6Af4l2AvnBmjAfQABPp76kluO5qXt8NWEbQziTGHYXCJNL+tNCZnLbfX
         2jVg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=DTJIS8uE;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:subject:date:message-id:in-reply-to:references
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=8Eu0BHgDuHNQT8s1N140MONeG1z3p80Abvj7l2D4y5U=;
        b=YQ2JCO2QdrXna1WCLl9c6nsaAGxF9qKBUKJBULItw4Q6ml74+C4xfI7M2nCw0IZpr9
         nHboL+LmBtPGLCNQ+iOevfgxi5ddbUt83r/HY9agrF0rRgmLZ2gtEMpoAZLDfmN5n9Xi
         sWHD6jUzexcczcuNMBqxvhpM0q2SaN+tDYq7rvZY6mR+3hCZNJo4vEKUCD1WV5Wu/rw2
         ilwLfL/ZiwAV3V9BKGtiF+KemucUQ9NaC81pLQqjnqzVRj5A2x1Qqg4gPkLm4qg+/OqI
         qkmUJUXI/PcZbruAFlNzeoGofuHwcrFTY10L3vsvJHULq/lsoxpHJiGhdWJ8IrONEy3d
         LLNQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :in-reply-to:references:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=8Eu0BHgDuHNQT8s1N140MONeG1z3p80Abvj7l2D4y5U=;
        b=m2+HG9Wc8GlsGqfRx0bLZ6uuc93MvpBimDltywUd5d+VSpX5JDa7F3eniEEiWJHB5U
         wBkhVno3xYdWXf6l+ydr6jYImaG06bq67RUl520aZxB0psqvnWmlWSUlIHS4AQfzZL3m
         LBQW+XVKySED4pJQE0eWx45tMk2cl2MMBCIbo+HTvmMIU8qlYdaCEMSn0uIYuiTbvwXt
         VR6L/Fe7LPqMVzaGrvCassdXoQPtmkdlTDaCEAXRnxNmHVU5ljnQxcArCUCaXprAJ9aC
         OpjU+f8Zue5Rj/6CqEUK1NsmnXxOr/3XVek0cHNl6ELL5ju40axzsNXqvIHYlodAaQBn
         BBww==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531ms8aDewV1r/2FjLc/kxq1ARmwgekX6TDFKIhFZNcTmhRVv8q9
	VUyfOX2nmWAGeYbYGQwN5FA=
X-Google-Smtp-Source: ABdhPJzl/Ohq/FTLWxYtSYvwAn8TG1pX/nCLdUJyksQAF6f5KCENUazsyw9v7i6bAuf4+mfQ5Re+qg==
X-Received: by 2002:a25:50d7:: with SMTP id e206mr35727380ybb.496.1636926168737;
        Sun, 14 Nov 2021 13:42:48 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:3fc2:: with SMTP id m185ls7716064yba.9.gmail; Sun, 14
 Nov 2021 13:42:48 -0800 (PST)
X-Received: by 2002:a25:ab4c:: with SMTP id u70mr33208726ybi.82.1636926168252;
        Sun, 14 Nov 2021 13:42:48 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1636926168; cv=none;
        d=google.com; s=arc-20160816;
        b=kAAL9nuA3SxdXgNkIndxzHdstKyi2oDzrMHbC43PW1jYiZCHpp1dy4wGapHgU+KK9Q
         Bss92VXo7rlNOk7S7cul5hbaa6DgvpP4EuYc0ixuLgY7gDm4VF2nkeNXRuvojdLI3W6v
         aTxT+Xy/QniphBgLU2cozs/W+PhoAZqoZHcs5qnxLtXwbM+HO97A+FFQV5qy/Gg36nBu
         5bTV3rrNCLBwcE6712sYldcFiIveBCUISkHOSvX/jtM6V9ku0iZXht5l3fPxF+U3Qc/O
         w0Yt9qEH64moIuHR9js1kfQg0dsuK74WoyambDIz7FeSm0LuNjJznKFfB0wEpIS4CgCp
         e4yQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from:dkim-signature;
        bh=qu00ZkYtNSgtaFzibGzmzQuTULV3z47ycRyxwqSafTc=;
        b=MKSVJnx1BmdAnq5KYA+k2oYfuCkBrJ4yJLM32ElcCun+GF625sSFik0mEd8Bk+Tf4x
         4/nrjYFFqymDfYYjCvJwinV5Is+p+CR7uqSSk8/ZIg9z6XxHiLxHcmMI5zyF1D5WpdHp
         CDGIa0Lhy2ZVRKLJK2rShGIYUx52U8+4JUPAdc1LYbzaEAWu9rRzITURVzEvDHJJkUsb
         pNkFlmvCP/wVdRwFm4TXOqBM3OczAR8OdRnoYstB8CcgSBQzf2MLkz3bN0WQOvCzZCLb
         +XiSoyOcOZ+Ags8nFoTAEN+xHdiiL4trEath/lEiV797tgBPLOYKydH6B4mTdyttp14Q
         6QFQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=DTJIS8uE;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id g35si1370596ybi.2.2021.11.14.13.42.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sun, 14 Nov 2021 13:42:48 -0800 (PST)
Received-SPF: pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPS id 3E20D60F01
	for <kasan-dev@googlegroups.com>; Sun, 14 Nov 2021 21:42:47 +0000 (UTC)
Received: by pdx-korg-bugzilla-2.web.codeaurora.org (Postfix, from userid 48)
	id 322FA60F5B; Sun, 14 Nov 2021 21:42:47 +0000 (UTC)
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 199341] KASAN: misses underflow in memmove
Date: Sun, 14 Nov 2021 21:42:46 +0000
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
X-Bugzilla-Assigned-To: dvyukov@google.com
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: cc
Message-ID: <bug-199341-199747-KaOvqAeHb6@https.bugzilla.kernel.org/>
In-Reply-To: <bug-199341-199747@https.bugzilla.kernel.org/>
References: <bug-199341-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@bugzilla.kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=DTJIS8uE;       spf=pass
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

https://bugzilla.kernel.org/show_bug.cgi?id=199341

Andrey Konovalov (andreyknvl@gmail.com) changed:

           What    |Removed                     |Added
----------------------------------------------------------------------------
                 CC|                            |andreyknvl@gmail.com

--- Comment #2 from Andrey Konovalov (andreyknvl@gmail.com) ---
Resolved with [1].

I don't have the permissions to close this bug though.

[1]
https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=8cceeff48f23eede76de995df08cf665182ec8fb

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-199341-199747-KaOvqAeHb6%40https.bugzilla.kernel.org/.
