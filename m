Return-Path: <kasan-dev+bncBDH43ZGQR4ARBV4I2COAMGQEBTTAKHQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-x1140.google.com (mail-yw1-x1140.google.com [IPv6:2607:f8b0:4864:20::1140])
	by mail.lfdr.de (Postfix) with ESMTPS id 6CC64648D09
	for <lists+kasan-dev@lfdr.de>; Sat, 10 Dec 2022 05:00:25 +0100 (CET)
Received: by mail-yw1-x1140.google.com with SMTP id 00721157ae682-3b5da1b3130sf71797567b3.5
        for <lists+kasan-dev@lfdr.de>; Fri, 09 Dec 2022 20:00:25 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1670644824; cv=pass;
        d=google.com; s=arc-20160816;
        b=QMCsC4Htkz9czvrqjSEgI7DjLP8znAvIHaq7iMDQgEyUHikKwBPD5mjOZ+f5dRKIaO
         WjR69RqWaSwl5vJvD147vdcCx2YSrSmvWSi65Vn031NTqYfDvN9sXcQOYTguswRN3qId
         P5aDawLIU8OdpWLclWLcOVnN6W18uBmmDEgXjoV7xssi8vE9+BPaZV/HDmlB3qBgdew6
         T9vm5n92GKKlQn7f+ARbHlRtID6JXSiMx0+J7BKAxWJGea2gxQhYOcWZ/h976WNbEECw
         hxC8nM1H4dMlq1TclsuCT0onte1dLDXJWpnudfQB5mAf6hR9TNHNvtzqmmCUTmRon5S0
         TVyQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:in-reply-to:references:date
         :message-id:from:subject:mime-version:sender:dkim-signature;
        bh=wez8/+qcr2kJIbje1JY67reZQmW6c1cGo0ufbD7cIXs=;
        b=EhEeKgW5xF4FqUchxsXjtKuTbUi32VNXVA6kN2rvzM9phU3UO7KqevQntCwS/KGGrL
         Q4Ngsg0IM/PsRd4vN4J+LTpojfQpFOKqgA2YD0r9ZARLp9gMHhTL2rNhcVaw7FigIoJm
         CYx1LdFLK1nbZMXkLC6iEzxU7Hn6C/PquvoXRfpMOH7eVFQo0OQNXHkOWDVfHMcBKM5b
         CdVpnbUy8nMK8+ld2VcElYrDd0oZicBMIjPFN5yXaNJlvrEneWMbKGsxkPCXM8ltPn8/
         BNgYBZIa/79S3QDFTof5ooHM5vXcztmpDgONPw4Y5sxcAHE/4cqncqGbHHUcxPTf/Zpr
         P0rQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=mVRc8GNE;
       spf=pass (google.com: domain of patchwork-bot+netdevbpf@kernel.org designates 2604:1380:40e1:4800::1 as permitted sender) smtp.mailfrom=patchwork-bot+netdevbpf@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:in-reply-to:references:date:message-id:from
         :subject:mime-version:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=wez8/+qcr2kJIbje1JY67reZQmW6c1cGo0ufbD7cIXs=;
        b=DBh0i+cnDDvQqTsnKffI7oHnEduJZ/8Gmka+mckfYKADQn7d/T7QYQjh3PRmBn2TjP
         knV39C7lH2Nuc6FMy1z+R3CO2jLuTZv2gRTLYEuO4OrJRjFxkT3bPsXr72MopTOPY4Qt
         +Kpz+iB3OBJC4A6pGLpG0EQJhDq48kO2A/x4B6o2HuT1TdDX74UgYqlbDA8kX6HcNj8q
         WHgm9cLnVT60yha4qgzi2B0o/3W8C+Z+VX9kZdyq1YEzOBNl1x8xgXHu9+1K9tLDp4xr
         Dj93FO/XYTluosvKYfhz3u+iyj6U87qGeVRnk6GWwd51B38yryGlwjD0Ie0zzWoUShCB
         1Msw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to
         :in-reply-to:references:date:message-id:from:subject:mime-version
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=wez8/+qcr2kJIbje1JY67reZQmW6c1cGo0ufbD7cIXs=;
        b=Gt6KmGzrGvfg0iObvq1eTb1AKpiwuJTpJUwRZ1fuhA/MyeWwVuiXPrq595M+Wfx7nD
         E0tJZz6W1MYm20/JyeYcJErvAdk+exlT1zyMZBnsNGdLHjsSUhfmZxXX9DQVueKphwFN
         7cuEtXqoZpVt/t9ZlPpx+W+kXnkrwFr8+jXY3/2xxEZPNGBC/lI+coftiY9TUduhStrK
         EgM0goSWiomp3KASTHvA4loqYjqFc0Pg5gN4tUs5E7eAsTuPoBgIoZmvjNLhfl7mNZfl
         EacracHK4uz8JxHwfGiVggQFVFrY8ptYM2xo7l5DfEpdyxIHNv5iLlsFO4W2Pv6bY7FK
         AioA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ANoB5pkPrPQT3Eg2+c4vTp+3hJeVG3i5YTuF3gfhZNVsHDWstCbK58qi
	u8Uo4zOegCieBLUL1fUdsDY=
X-Google-Smtp-Source: AA0mqf7f995QVUMkZqLlgAUMBajfTWhHTn7k4Dgv3ivOsXeWr6aVPZHs/DqN3V0UKBFyAcr4bUF1CQ==
X-Received: by 2002:a25:c694:0:b0:703:5949:3b2a with SMTP id k142-20020a25c694000000b0070359493b2amr10039265ybf.525.1670644823962;
        Fri, 09 Dec 2022 20:00:23 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a81:8350:0:b0:3da:3e43:9e3c with SMTP id t77-20020a818350000000b003da3e439e3cls5986201ywf.9.-pod-prod-gmail;
 Fri, 09 Dec 2022 20:00:23 -0800 (PST)
X-Received: by 2002:a05:690c:884:b0:3ed:aa4:2a72 with SMTP id cd4-20020a05690c088400b003ed0aa42a72mr8140523ywb.39.1670644823391;
        Fri, 09 Dec 2022 20:00:23 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1670644823; cv=none;
        d=google.com; s=arc-20160816;
        b=HdjT6vT5Yn0RZE9ViurUKMXO5DZ2PYqIrVbCwkoUPtyU1hKNtvN1EZpdelzRBR4Cqe
         fyaH/kGMl7oXSj2AfjqhtCDS3nqTZSfy3FW0QRXOHWAxxTvhE2FFqTm3+sMYTNgxxrGY
         +ZRouB/QKnRCs8UHLxpc1ygiz4qt9GMM2srP7tQhK+B7Ho2lnFEQlWilTbXxQyczlb95
         m4bJjD7qUFS5ZYyvjvMwmLrPSxaIWCEw6ul10P7UNXPb42gTbRL3bjIL+zKxcNulS86V
         w9UBUlR3t37vipqJfDJWt2xKTD612Tx0SrGweKYzFfFE/fHQUoR9mBvCshqa2+IxidSy
         /T0A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:in-reply-to:references:date:message-id:from:subject
         :content-transfer-encoding:mime-version:dkim-signature;
        bh=i+zeAtKEKib0CFwY3er5qfIMMp7kCmM/mQ9ZF0W28Ys=;
        b=mWOVp65REeZzw6EI4LHZZ1v+LUQroENHY6CZU+VBSEbWLt3KF/3bQQgKrg+vDxS8Ax
         DjGdIqPQnzoVJ169wYbsKzIX8krfLTbyP/SxzBGa77yhfSaJAS9RQok+D49u+R5hzkFs
         HTePymBoxAybqaM5XP1NvBjjP8jTNU/w8YlXIN6/XJSTVFC8FzRpYtuxrnJ3jShKYIPP
         FuT3TQNXO6+COKAX+MLOeOydeSClsH//kvPaHiG2ejiTWGkIQCHotYwVu3nxHNcUzWU5
         XdOR20uYr/XjNqsF4cBEibFUlsrvxyY6a9s+tZu//NLVCCeQbxv5xinZX31z52IZgMUr
         4IXw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=mVRc8GNE;
       spf=pass (google.com: domain of patchwork-bot+netdevbpf@kernel.org designates 2604:1380:40e1:4800::1 as permitted sender) smtp.mailfrom=patchwork-bot+netdevbpf@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from sin.source.kernel.org (sin.source.kernel.org. [2604:1380:40e1:4800::1])
        by gmr-mx.google.com with ESMTPS id y194-20020a0dd6cb000000b003e0d1cdbb77si354610ywd.3.2022.12.09.20.00.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 09 Dec 2022 20:00:23 -0800 (PST)
Received-SPF: pass (google.com: domain of patchwork-bot+netdevbpf@kernel.org designates 2604:1380:40e1:4800::1 as permitted sender) client-ip=2604:1380:40e1:4800::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by sin.source.kernel.org (Postfix) with ESMTPS id 5D522CE2B9F;
	Sat, 10 Dec 2022 04:00:20 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id 78931C433EF;
	Sat, 10 Dec 2022 04:00:18 +0000 (UTC)
Received: from aws-us-west-2-korg-oddjob-1.ci.codeaurora.org (localhost.localdomain [127.0.0.1])
	by aws-us-west-2-korg-oddjob-1.ci.codeaurora.org (Postfix) with ESMTP id 41E41C41606;
	Sat, 10 Dec 2022 04:00:18 +0000 (UTC)
Content-Type: text/plain; charset="UTF-8"
MIME-Version: 1.0
Subject: Re: [PATCH net-next v3] skbuff: Introduce slab_build_skb()
From: patchwork-bot+netdevbpf@kernel.org
Message-Id: <167064481825.12189.4717731779203655380.git-patchwork-notify@kernel.org>
Date: Sat, 10 Dec 2022 04:00:18 +0000
References: <20221208060256.give.994-kees@kernel.org>
In-Reply-To: <20221208060256.give.994-kees@kernel.org>
To: Kees Cook <keescook@chromium.org>
Cc: kuba@kernel.org, syzbot+fda18eaa8c12534ccb3b@syzkaller.appspotmail.com,
 edumazet@google.com, davem@davemloft.net, pabeni@redhat.com,
 asml.silence@gmail.com, soopthegoop@gmail.com, vbabka@suse.cz,
 kasan-dev@googlegroups.com, andrii@kernel.org, ast@kernel.org,
 bpf@vger.kernel.org, daniel@iogearbox.net, haoluo@google.com,
 hawk@kernel.org, john.fastabend@gmail.com, jolsa@kernel.org,
 kpsingh@kernel.org, martin.lau@linux.dev, sdf@google.com, song@kernel.org,
 yhs@fb.com, netdev@vger.kernel.org, linux-kernel@vger.kernel.org,
 rmody@marvell.com, aelior@marvell.com, manishc@marvell.com,
 imagedong@tencent.com, dsahern@kernel.org, richardbgobert@gmail.com,
 andreyknvl@gmail.com, rientjes@google.com, GR-Linux-NIC-Dev@marvell.com,
 linux-hardening@vger.kernel.org
X-Original-Sender: patchwork-bot+netdevbpf@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=mVRc8GNE;       spf=pass
 (google.com: domain of patchwork-bot+netdevbpf@kernel.org designates
 2604:1380:40e1:4800::1 as permitted sender) smtp.mailfrom=patchwork-bot+netdevbpf@kernel.org;
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

Hello:

This patch was applied to netdev/net-next.git (master)
by Jakub Kicinski <kuba@kernel.org>:

On Wed,  7 Dec 2022 22:02:59 -0800 you wrote:
> syzkaller reported:
> 
>   BUG: KASAN: slab-out-of-bounds in __build_skb_around+0x235/0x340 net/core/skbuff.c:294
>   Write of size 32 at addr ffff88802aa172c0 by task syz-executor413/5295
> 
> For bpf_prog_test_run_skb(), which uses a kmalloc()ed buffer passed to
> build_skb().
> 
> [...]

Here is the summary with links:
  - [net-next,v3] skbuff: Introduce slab_build_skb()
    https://git.kernel.org/netdev/net-next/c/ce098da1497c

You are awesome, thank you!
-- 
Deet-doot-dot, I am a bot.
https://korg.docs.kernel.org/patchwork/pwbot.html


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/167064481825.12189.4717731779203655380.git-patchwork-notify%40kernel.org.
