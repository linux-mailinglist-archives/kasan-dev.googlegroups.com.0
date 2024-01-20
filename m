Return-Path: <kasan-dev+bncBAABBH7NWCWQMGQEO3EGOMI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3b.google.com (mail-qv1-xf3b.google.com [IPv6:2607:f8b0:4864:20::f3b])
	by mail.lfdr.de (Postfix) with ESMTPS id BEC37833629
	for <lists+kasan-dev@lfdr.de>; Sat, 20 Jan 2024 22:09:52 +0100 (CET)
Received: by mail-qv1-xf3b.google.com with SMTP id 6a1803df08f44-680139b198asf46835316d6.3
        for <lists+kasan-dev@lfdr.de>; Sat, 20 Jan 2024 13:09:52 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1705784991; cv=pass;
        d=google.com; s=arc-20160816;
        b=t1hNEne2JzWSgHblhW9DYG4yzTZFR+zv+7MDARtv0uw1+Dfj7wBqgc4xzuGnpsUk6N
         zxOkvV3tyMSNiJlFuJDnXjf/NWMi8Rw6RoYLYVaeMNFBcwRAxXenQp2E73KQWR1h0L4X
         KNnT+HAFxMU0pSFvoKhciuQrMzutEpIveayPQ+oaVukUt2lfP2jFBcBTA4EKRONG4iFn
         CXbjGm/ms7MnCaMjwxkyQ0FkAlHHnBkcAt7QuqI+sEOkkux4xK9GgHezybvHJ0FQ3Q+4
         uKL0wJM3PSj1lohrWWAJsOo291WoJIazdqcUdblJtGoTNzp6NIQb3zqyF10ViR3WDw0q
         musw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:in-reply-to:references:date
         :message-id:from:subject:mime-version:sender:dkim-signature;
        bh=+hCgEWz3yVsT3pACK8iqh3xOzxHOP2uSGyc5Tk6aVxM=;
        fh=LfeFBdvWjHJGXCOo2ChWX/sK8lRt/rsOHjbPLl0nihU=;
        b=Uctiboi8Ji/5Yk7X7XaMnqIx0Uop9k579enm0o74u7rD/jPccX/dlGKNli5RSg/aMC
         q8vY5dzrrO7W28zz1t1uxlyDDYYw5VlRacJhdhL0RYIsHAL2SpTp1dFpza5OYzl+3Rvo
         8ERcEHniRugZZqTQuHyLoMBeEkrkbRiG/gFCmTdCKEZqHqiij7jI7v8TIRNYkeFI5STx
         XQCK/53PBr+eBiGxU850/TqMs1CV9++Y7qFiI69Rzf5xYE5xnTiGhTGxyILvlVZrwVWu
         je2iSROdEOVlceJTttFUdgt11rLdi8icZWKOoYjsqvVHMRR1Hwr3uoe2S5VRTbgUnAZQ
         05HA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Q3JVAx1d;
       spf=pass (google.com: domain of patchwork-bot+linux-riscv@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=patchwork-bot+linux-riscv@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1705784991; x=1706389791; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:in-reply-to:references:date:message-id:from
         :subject:mime-version:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=+hCgEWz3yVsT3pACK8iqh3xOzxHOP2uSGyc5Tk6aVxM=;
        b=xovLXWn1n1Xheb6yCdSGd1TMOrYeux8soO1BaCmXuhAGzjNCLMzybNBtAiWMH99sjz
         YAoCfdQYIKTF0TpO34Fu7ZMtQVE44i5lt23FdOtnrcVDbm1PSAm8C41pmzpqTo5sp9+u
         yHnhGnMy+gG9iE4CinEX/+K9xYYhS8zUcTE2JgA+LJSwE9GdFGX3ZTEKD1+FqOPLCCrY
         iy6vkOXkF3yX7eylszQ57E4gHo51yxiT7cei6qKBtN+lLgyCqZdrn6SB6t4GWeZgd1D0
         iIWvuHQzP3btgBg10V2Q5NCJANHKqjbRKU92e70HscIlrc5UnOoJdn9pXBXk9PI2NGoV
         2NgA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1705784991; x=1706389791;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to
         :in-reply-to:references:date:message-id:from:subject:mime-version
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=+hCgEWz3yVsT3pACK8iqh3xOzxHOP2uSGyc5Tk6aVxM=;
        b=f9yH/rUV8S2ejEADvmgd58vvPG+eF3kfNfPeisW7ui9CywgWrqnbJb+xq2/i6y1tkI
         Ax0xlBu1++z7kVDv902D1zPo+xKeAsnkU/ClSXJ/04uFaOhzUUmeaaQif1cJcZGNfbUY
         8/rWjnlEyN9wbe8O+0nFyyUsfNKl9MLYa0/TiqS7nIToMibZcx5MEPM1x5rPgSC7xW+Q
         STqa95Tw9YoIZRaR4i1zoT+qvANnDyrfJGmWAd6KwrwV63zvp/SGQg/rhJLbKFnbeuyn
         VWkTBM4pWxA+J4UN115tVSs60wxeq/rZ+pfVhQ2ayc8VLKZg3AzULBDej6Qeq+LG6nZj
         VzQw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YxwNC8lA5H0uGPYtFyOTMMGN7YZBdw/pMeOxuPuJiyEz7Db7hjf
	PyiCmEUeyBNiYikKuRv2dQqOZ9RyjTHN67NezabXh3Gp/DrFcwW0
X-Google-Smtp-Source: AGHT+IF1129faCSBusm67V1ALy2kgqwKcw27HPEoK2i3li0hpwp5cMvrEn5KO4CQ3GjnCu6Ut5jLUA==
X-Received: by 2002:a05:6214:1941:b0:681:555b:d44 with SMTP id q1-20020a056214194100b00681555b0d44mr2776234qvk.61.1705784991625;
        Sat, 20 Jan 2024 13:09:51 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0c:b3d9:0:b0:681:6cda:84f6 with SMTP id b25-20020a0cb3d9000000b006816cda84f6ls543645qvf.0.-pod-prod-07-us;
 Sat, 20 Jan 2024 13:09:51 -0800 (PST)
X-Received: by 2002:a0c:9a44:0:b0:67f:e136:7de2 with SMTP id q4-20020a0c9a44000000b0067fe1367de2mr2100904qvd.122.1705784990863;
        Sat, 20 Jan 2024 13:09:50 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1705784990; cv=none;
        d=google.com; s=arc-20160816;
        b=NqvSLtAUkC1s81PP2Ru2tJk13E7fbtQvtEuTDAA8V511R+RJ/WofsxrOkN6q/AiB2b
         Je5cTYBlekfydWv+g6D5eLExhp9f5VmGVgDRcaorRr6DXDcN8T+kglrhxdBZ39ohrMfa
         k7xpXLiWtFKXUdya9mSKBQePlBmWIRC7mUcpEXqLpPOvkVf8+0CUbhbF5Qs2uZZolOdN
         PQ68aTfCT9Tna1ZT6OoporDhPY+/6ftRCyK0tKrdcWS6Ws/4diw+IAry8vr6tlFZGABI
         aND2AlJlT8Fh6GG/VaY7Lik8d5z8RIN33NBi7hQKdxEspS4PhWybJGnw7jKTpgw59lYv
         iQuw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:in-reply-to:references:date:message-id:from:subject
         :content-transfer-encoding:mime-version:dkim-signature;
        bh=FTS0ws9QqTV98/ROpBZhJSS2oPV/DtYXS3ql2E/wOvA=;
        fh=LfeFBdvWjHJGXCOo2ChWX/sK8lRt/rsOHjbPLl0nihU=;
        b=w+eXMZBywlWSuxBLfFdg2swFm2AtcN9bbA/Lgt15KeLobU185d4TIEhC6J46v09GAu
         Opr+lSb33mEYaGQ4sze6pPW1MQvBmkWcJcQ626uWTfC+QjwExe/2vCx9SsDdZjXXv16i
         AuufP4PFCp2K+OuI7mhyLcw8+8NFTGL5bMF35ggPonbVLNBAHfnFnA6j8NWC3SGQuhzt
         OSIzzFZJ/B7o1b5wJJzpj2/2QS7QY9UtDoljKXHsu3k1uJ9egk2ywe1OOu/J29ktx45g
         5xuP0rzi3TSP+nJgb57N61qkrcc5nEU+sw5j9qDUjYmzA5cg5Ek3VR4GWGxTmCZVFntd
         f56w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Q3JVAx1d;
       spf=pass (google.com: domain of patchwork-bot+linux-riscv@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=patchwork-bot+linux-riscv@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id jh9-20020a0562141fc900b006834973abd0si114684qvb.6.2024.01.20.13.09.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sat, 20 Jan 2024 13:09:50 -0800 (PST)
Received-SPF: pass (google.com: domain of patchwork-bot+linux-riscv@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id 4F4FE60C35;
	Sat, 20 Jan 2024 21:09:50 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id 1C3EAC43390;
	Sat, 20 Jan 2024 21:09:50 +0000 (UTC)
Received: from aws-us-west-2-korg-oddjob-1.ci.codeaurora.org (localhost.localdomain [127.0.0.1])
	by aws-us-west-2-korg-oddjob-1.ci.codeaurora.org (Postfix) with ESMTP id 09F97D8C970;
	Sat, 20 Jan 2024 21:09:50 +0000 (UTC)
Content-Type: text/plain; charset="UTF-8"
MIME-Version: 1.0
Subject: Re: [PATCH v2 0/2] riscv: Enable percpu page first chunk allocator
From: patchwork-bot+linux-riscv@kernel.org
Message-Id: <170578499003.24348.2691177844867923598.git-patchwork-notify@kernel.org>
Date: Sat, 20 Jan 2024 21:09:50 +0000
References: <20231212213457.132605-1-alexghiti@rivosinc.com>
In-Reply-To: <20231212213457.132605-1-alexghiti@rivosinc.com>
To: Alexandre Ghiti <alexghiti@rivosinc.com>
Cc: linux-riscv@lists.infradead.org, paul.walmsley@sifive.com,
 palmer@dabbelt.com, aou@eecs.berkeley.edu, ryabinin.a.a@gmail.com,
 glider@google.com, andreyknvl@gmail.com, dvyukov@google.com,
 vincenzo.frascino@arm.com, arnd@arndb.de, dennis@kernel.org, tj@kernel.org,
 cl@linux.com, akpm@linux-foundation.org, linux-kernel@vger.kernel.org,
 kasan-dev@googlegroups.com, linux-arch@vger.kernel.org, linux-mm@kvack.org
X-Original-Sender: patchwork-bot+linux-riscv@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=Q3JVAx1d;       spf=pass
 (google.com: domain of patchwork-bot+linux-riscv@kernel.org designates
 139.178.84.217 as permitted sender) smtp.mailfrom=patchwork-bot+linux-riscv@kernel.org;
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

This series was applied to riscv/linux.git (fixes)
by Dennis Zhou <dennis@kernel.org>:

On Tue, 12 Dec 2023 22:34:55 +0100 you wrote:
> While working with pcpu variables, I noticed that riscv did not support
> first chunk allocation in the vmalloc area which may be needed as a fallback
> in case of a sparse NUMA configuration.
> 
> patch 1 starts by introducing a new function flush_cache_vmap_early() which
> is needed since a new vmalloc mapping is established and directly accessed:
> on riscv, this would likely fail in case of a reordered access or if the
> uarch caches invalid entries in TLB.
> Note that most architectures do not include asm-generic/cacheflush.h so to
> avoid build failures, this patch implements the new function on each of
> those architectures. For all architectures except riscv, this new function
> is implemented as a no-op to keep the existing behaviour but it likely
> needs another implementation.
> 
> [...]

Here is the summary with links:
  - [v2,1/2] mm: Introduce flush_cache_vmap_early()
    https://git.kernel.org/riscv/c/7a92fc8b4d20
  - [v2,2/2] riscv: Enable pcpu page first chunk allocator
    https://git.kernel.org/riscv/c/6b9f29b81b15

You are awesome, thank you!
-- 
Deet-doot-dot, I am a bot.
https://korg.docs.kernel.org/patchwork/pwbot.html


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/170578499003.24348.2691177844867923598.git-patchwork-notify%40kernel.org.
