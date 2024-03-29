Return-Path: <kasan-dev+bncBDH43ZGQR4ARB2N3TSYAMGQE3NE2SXI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3a.google.com (mail-oa1-x3a.google.com [IPv6:2001:4860:4864:20::3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 1F6A88924B7
	for <lists+kasan-dev@lfdr.de>; Fri, 29 Mar 2024 21:00:43 +0100 (CET)
Received: by mail-oa1-x3a.google.com with SMTP id 586e51a60fabf-2299abdcb65sf3065879fac.1
        for <lists+kasan-dev@lfdr.de>; Fri, 29 Mar 2024 13:00:43 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1711742442; cv=pass;
        d=google.com; s=arc-20160816;
        b=mXtzHZ3+ChZS2gina2wlprxmvcBhb3puLLSY1lskkRyEyAQQjo7Uu16zas6DtiZg87
         TZsSLRv7IiHhAmDsaJamHQk+NTSvK12+Sc5RrBk4wubebM3YtwDOPSyDJZzQMcGFZT6s
         mwkGN0plqdviq9hkrWy5h5v2J4Uft/khc1qr76WBBugNXN1ghseNK3HG4CzN0N2BGVAl
         1YPlWTKMJYuQ78J5TtT2bYRPTz/JPoZyDeW6+yVJv9UbXAkUFfVV1MWC0yVJQnJCAflq
         9jBbhDXsmJXWOOgijFtD6wqkCvJQkqmKQOn8wtbMFmL9t4C4lPM4YqpAiTpS9CGQYicX
         QOyg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:in-reply-to:references:date
         :message-id:from:subject:mime-version:sender:dkim-signature;
        bh=nyZZx1UO3KoI6zcBiRYbf6koYhyakNtNBR/7k7y7bHg=;
        fh=zm9zN2bxkkXk2J0rPl8h6N6jb2jtYfPx2zBbLz8xqqc=;
        b=fdS5wGryaXxIgNb6AJI8rC4LmKtLQwXei8SH7/EUSIf3cdgc7YUmemg3+EwbUSRRNd
         gCLlmOOqD5JBjTlW3mGi0MIccVs9skF/CbzuKRPJuUes6+rZ2mVZGuPO5a+ENPYbePt+
         jarsu8tq2lSSdLnbkV1O0b0HWmCSrPFsx+sqZpFQLD6qMymvQzpdHH8tdwKeW30jzlpn
         LOXWHu2rFvPWZ7zL1aYeArHMbz5dGHlMmaScaigJifG3ie+FT9e8YqdnJksVHIWAUiA6
         Nk4RR/aU3MlBGsrtFNiyJH/Q/91ij1i6aBDVYRJRJ0FtEt1QfYIQdxvpPBeH67qayMAT
         xw6g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="ibdChtO/";
       spf=pass (google.com: domain of patchwork-bot+netdevbpf@kernel.org designates 2604:1380:40e1:4800::1 as permitted sender) smtp.mailfrom=patchwork-bot+netdevbpf@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1711742442; x=1712347242; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:in-reply-to:references:date:message-id:from
         :subject:mime-version:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=nyZZx1UO3KoI6zcBiRYbf6koYhyakNtNBR/7k7y7bHg=;
        b=Zi7THMdQl60w8ZyTe4ja4up2dOBiyrqFVtYhg8RzNG3+CKpniGkfQllXvKvJs811cB
         fax/2fDrIucjMF7BLFttDfDA5R5caa9wcu6AKgMELsWwP+Up4hXO6nvN0jWt2oJYEhqI
         LbtH2K3xWaVNDCh/W8jNCc0tPTCH6oVcxDtGtw6aBYD9xzeUQ6JucjG20WITNRD8FOui
         gbKRnnPyZveHJzU4ZTpo+A8EtpsOSXMRp90+zq50wkYbAl15PIQ4Y42Sg2jSY/2ie/1S
         Ymns11v2rl4W7hPqHDwEkMl3vUj95nFHIe2lMY3otam5rbVY1sRSohV6qYhfCtAzbRzY
         xLkQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1711742442; x=1712347242;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to
         :in-reply-to:references:date:message-id:from:subject:mime-version
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=nyZZx1UO3KoI6zcBiRYbf6koYhyakNtNBR/7k7y7bHg=;
        b=sB7Gh7UJ8QpIctbY+2WqYXVEVSDgZTS0fHg+YXf8OyZtOTwshAiJljmowjaxW+7nNy
         8vtGkwNj2doZgIbkR6/4DRXxIMFmnqFVtmEdqVu38Jm807G7NkBL4QNnUWRHLdyUb+QD
         TuDsM53ua9mCkoqDfulier3Woxw8eluPL7w0RACKMfsrqDWOfnRr7AkXif6FPJvi3TiJ
         P/oMpV6cMieakIAg3hmqfhlMDOLthIuJT0PXs3qaJf5PsYKZi2ACq+K3S7Ib3AIHpFxs
         NDT47vAW/+Ha/lo76hNDmGY4jXsrRqRHBiUytEJDEsUlg687S//vNhkMi09O5OYFRQU3
         oUOw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXtxI78goC6RUiYPUVsm+yodmJx2RpWf03H9KPo0Fq2Yk/P31Xkd8otk7qv5gbx52u8/unHiXPUWfMJiSLtReGe3CeTA3Vuxg==
X-Gm-Message-State: AOJu0Yx+4Afxa1O0AqYjVNMwzq+B6gczspmRnJv7NYT3+t5sQcFQOpEE
	2lTB6jWn980TCniZhRh2ikJj+Rt3u52IXAX3XqxQ9aAKc8YZQqX4
X-Google-Smtp-Source: AGHT+IFdAuWAGeVrLifxrhg6gzkh059MFuDSKRsuFaOuXVrm+N+vvT7M79xrWAuR5+2Dct7g0BkQpA==
X-Received: by 2002:a05:6870:95a4:b0:22b:5bc1:66f5 with SMTP id k36-20020a05687095a400b0022b5bc166f5mr3083542oao.16.1711742441748;
        Fri, 29 Mar 2024 13:00:41 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:5d92:0:b0:431:3419:79d3 with SMTP id d18-20020ac85d92000000b00431341979d3ls2860691qtx.0.-pod-prod-01-us;
 Fri, 29 Mar 2024 13:00:40 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUfBxs8zvFfhCmdaTCOzTPw417f95CP7TJG4ZjrGDvOfY+NLxkIpSwk0r7bYNlLzR/1woFSs3PfsbT1wkhQMAYU0TNFD38jLhK7mQ==
X-Received: by 2002:a05:622a:178f:b0:432:b41e:ceca with SMTP id s15-20020a05622a178f00b00432b41ececamr3520666qtk.47.1711742440410;
        Fri, 29 Mar 2024 13:00:40 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1711742440; cv=none;
        d=google.com; s=arc-20160816;
        b=zAYmQFAEPllvUu3EPecqmFQZRR19EXb8AN5t/TOPCfK+QBQhzjHyiQxJDJPV6tpzpE
         K8ueKOqjVyQ3JXoh6rAwhZzNrlW9k1GLUeaTXMTw8BI0rvnWa+Fx/mGagJkSljQJcFGM
         XK46k5aDXkEuk5TBEm/OK8n4bCRGgGUfP870XoZ3mAtbCUIsBC2zgKUDVrr142wgL5Zn
         lWaP+nOQ7kGN/gL0tYo4pobl2G2io6Z4FxxctcSZoopTt6oMB2ykH/kF0uKYqh/XjgS2
         1nywwKCVfKpGnBOWr7knkZdEHTYiOU+Xg2kwq1DMslwPKkeRUWSVIbao2nqAna1YCs57
         7/HQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:in-reply-to:references:date:message-id:from:subject
         :content-transfer-encoding:mime-version:dkim-signature;
        bh=Pta+dDYgijsDuj7Osl37dGVEuFxQxB8an1ymZUUwZkE=;
        fh=ls6PQjMtjEanOoBMn0Loz3G7DzGuEq2uK5RjgDIQVD0=;
        b=rrVsxizeBcaWap/9mwlF+8KM69h/FDyvm74w0FERaaMRgf42STWNdjsojATp+Z6Isf
         hCWpIJUYhwEE19uImX8sZ3ZaP1sQN+2bFbXHvhYSHCLtEstfsQjBxNK8jo591Qk9rWUR
         IgIJexMJX54YBcZgc7+oyfvJkwdnyCTwmaZXUVTBNGH9Rlkxb8AcHewxQ9l2xe17c0gT
         /cbcTYdAZlMc/3IqzBQ6bh+aGKgTcn/hki2QAVdSN/T6isfHe7GVUzaM16etppGo5lBw
         /Pu4PDMlIEMD5PIbvaKfagslHnVpVIYXYXSvhOqiRQGROGNhN0uyvciI16I81b6WkjbT
         3qIg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="ibdChtO/";
       spf=pass (google.com: domain of patchwork-bot+netdevbpf@kernel.org designates 2604:1380:40e1:4800::1 as permitted sender) smtp.mailfrom=patchwork-bot+netdevbpf@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from sin.source.kernel.org (sin.source.kernel.org. [2604:1380:40e1:4800::1])
        by gmr-mx.google.com with ESMTPS id hc5-20020a05622a2a0500b00431710760fdsi410292qtb.2.2024.03.29.13.00.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 29 Mar 2024 13:00:40 -0700 (PDT)
Received-SPF: pass (google.com: domain of patchwork-bot+netdevbpf@kernel.org designates 2604:1380:40e1:4800::1 as permitted sender) client-ip=2604:1380:40e1:4800::1;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sin.source.kernel.org (Postfix) with ESMTP id 61330CE30E9;
	Fri, 29 Mar 2024 20:00:37 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id 88958C43399;
	Fri, 29 Mar 2024 20:00:36 +0000 (UTC)
Received: from aws-us-west-2-korg-oddjob-1.ci.codeaurora.org (localhost.localdomain [127.0.0.1])
	by aws-us-west-2-korg-oddjob-1.ci.codeaurora.org (Postfix) with ESMTP id 7B142D84BAF;
	Fri, 29 Mar 2024 20:00:36 +0000 (UTC)
Content-Type: text/plain; charset="UTF-8"
MIME-Version: 1.0
Subject: Re: [PATCH 0/9] address remaining
 -Wtautological-constant-out-of-range-compare
From: patchwork-bot+netdevbpf@kernel.org
Message-Id: <171174243650.4906.1760676317968487901.git-patchwork-notify@kernel.org>
Date: Fri, 29 Mar 2024 20:00:36 +0000
References: <20240328143051.1069575-1-arnd@kernel.org>
In-Reply-To: <20240328143051.1069575-1-arnd@kernel.org>
To: Arnd Bergmann <arnd@kernel.org>
Cc: linux-kernel@vger.kernel.org, arnd@arndb.de, idryomov@gmail.com,
 dongsheng.yang@easystack.cn, axboe@kernel.dk, jgg@ziepe.ca, leon@kernel.org,
 agk@redhat.com, snitzer@kernel.org, mpatocka@redhat.com,
 dm-devel@lists.linux.dev, saeedm@nvidia.com, davem@davemloft.net,
 edumazet@google.com, kuba@kernel.org, pabeni@redhat.com, xiubli@redhat.com,
 jlayton@kernel.org, konishi.ryusuke@gmail.com, dvyukov@google.com,
 andreyknvl@gmail.com, dsahern@kernel.org, masahiroy@kernel.org,
 nathan@kernel.org, nicolas@fjasle.eu, ndesaulniers@google.com,
 morbo@google.com, justinstitt@google.com, keescook@chromium.org,
 gustavoars@kernel.org, tariqt@nvidia.com, ceph-devel@vger.kernel.org,
 linux-block@vger.kernel.org, linux-rdma@vger.kernel.org,
 netdev@vger.kernel.org, linux-nilfs@vger.kernel.org,
 kasan-dev@googlegroups.com, linux-kbuild@vger.kernel.org,
 llvm@lists.linux.dev
X-Original-Sender: patchwork-bot+netdevbpf@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b="ibdChtO/";       spf=pass
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

This series was applied to netdev/net-next.git (main)
by Jakub Kicinski <kuba@kernel.org>:

On Thu, 28 Mar 2024 15:30:38 +0100 you wrote:
> From: Arnd Bergmann <arnd@arndb.de>
> 
> The warning option was introduced a few years ago but left disabled
> by default. All of the actual bugs that this has found have been
> fixed in the meantime, and this series should address the remaining
> false-positives, as tested on arm/arm64/x86 randconfigs as well as
> allmodconfig builds for all architectures supported by clang.
> 
> [...]

Here is the summary with links:
  - [2/9] libceph: avoid clang out-of-range warning
    (no matching commit)
  - [5/9] ipv4: tcp_output: avoid warning about NET_ADD_STATS
    (no matching commit)
  - [8/9] mlx5: stop warning for 64KB pages
    https://git.kernel.org/netdev/net-next/c/a5535e533694

You are awesome, thank you!
-- 
Deet-doot-dot, I am a bot.
https://korg.docs.kernel.org/patchwork/pwbot.html


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/171174243650.4906.1760676317968487901.git-patchwork-notify%40kernel.org.
