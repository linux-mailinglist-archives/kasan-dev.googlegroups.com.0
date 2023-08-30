Return-Path: <kasan-dev+bncBAABBJEEXWTQMGQE2W4TPPA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x139.google.com (mail-il1-x139.google.com [IPv6:2607:f8b0:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id E4E2E78D615
	for <lists+kasan-dev@lfdr.de>; Wed, 30 Aug 2023 15:20:38 +0200 (CEST)
Received: by mail-il1-x139.google.com with SMTP id e9e14a558f8ab-34ce0fc6a4fsf467225ab.0
        for <lists+kasan-dev@lfdr.de>; Wed, 30 Aug 2023 06:20:38 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1693401637; cv=pass;
        d=google.com; s=arc-20160816;
        b=enV2gIgxpRFDa3f7HY0J/8SmpUcIRCAo4mLNQkDHqTaL4ywZAdWci6sP+LZxqftOhh
         HJ9R72j785sBVd3u0IxZw0+XEKtTA2kcqJaBugu4eJZPefr2C/m7vDrkNw2hNHX4aurY
         U75hNW9l9X0Bva+tr1H3y9TIfr+aD/6t0MbF6daBr99ZcNrGVqDK5+VApIM7wN5GZuQI
         pD3f4MrCHFJtq3TjFW1nSC9b/lloArk990gr9npDP9NM2h1Qx0Z0Y4k03c92eoU4IDcr
         o2pMgP88n57I4VilgamBJxDYfT/t1r3gBQM1XZeSUeD1NQT2klglb6XA8R44sNTQA5km
         4iFg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:in-reply-to:references:date
         :message-id:from:subject:mime-version:sender:dkim-signature;
        bh=Ww+Rp4AR13xVDIVJIOMsGTULQ9o27gWgnGEpBWjYBII=;
        fh=0Ty61Yx08/9LJOiBmJ60qyJKKS4uPVm6W95JaRXejTM=;
        b=0O4NnZKDyHTl2qUmGnkFp6SZl82RBpWZ6WfEsA6kmdbUpoo2KTZvWjvT6DMJUDMHI8
         t3iOMyA0jTiorOfxDauP5NlyGrr5d2fzG26pS4eqLBOjmrJSth53Yph+5uTmbnNgrmEL
         anAw6WDiMglsqGwvT1+bGWo3bFrPGWj2ceQWpJ7n3JMjeqOzUXKG9mMSaFzKnXBwaf0K
         dYRmc9P7dUWI22ajnAKaSzghgq5ZVNb+cwLzkkrvj1NfuDzwkgdizKEQT7aW0SuEFtJH
         raihACI0AUe2eKmN8xByWzoG2sL6c3g9j1WFZBG4Yavnfpyq+w8j/a8QtxSfC40dncNP
         CXkw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=F32oMYF7;
       spf=pass (google.com: domain of patchwork-bot+linux-riscv@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=patchwork-bot+linux-riscv@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1693401637; x=1694006437; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:in-reply-to:references:date:message-id:from
         :subject:mime-version:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Ww+Rp4AR13xVDIVJIOMsGTULQ9o27gWgnGEpBWjYBII=;
        b=A9zGkk3DnDh1yuQTQvjbGqOmLsESM0wsz8x6nNM4LzYSdLBVbVEdCriyTQlgWdos5k
         mKS7Np6SDCh6EMRv0ultdLfb/muxOEwCcQzx5cemqVhY+T8IYysxjFM2mHZWJZPE4rRe
         eT9zeAlY8ltVYiyWo9f7X+y7W4fnoNTCqCLGoevTM5755VK9miowRmg7NmpyGDW6GR14
         9Q0F9OJbEubq+lWAoFYTde3+4W4tN93J2ZOcpfNSwbNm6+d1U7Nbj98+gt3dLfvxkfCl
         Wfky+4B0+HfhxZRdnijleaIN6V7UHdjfrbucLjGSe0edRdev0zkxrBYfoyze115JKJnq
         CNTA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1693401637; x=1694006437;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to
         :in-reply-to:references:date:message-id:from:subject:mime-version
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=Ww+Rp4AR13xVDIVJIOMsGTULQ9o27gWgnGEpBWjYBII=;
        b=akejerfYp3ztp+gOASG2BS85NIWjDj0OZm3xG57RrnpJKw8Xmu07T0JhbJ/Gf0XR/V
         I1yDVR6lesxqX3zYauQhUq8X23T4UNzjyAYhZZHOXDnORZOP6XBa5Xxuz62iWiVo+2rr
         vA1UORrIqZ9UINaJdZqD2cQB7MoKYaCl59jHyPZSSbovk7xvv+ZHLv4ch65UADrnVTZB
         o+NzZpe+dlEsnPKRd5aEa6YIXPEto3MnB8d0kqTfbcfhL4HNGGdnyCg5o3bGLBV7yYI0
         lXUewfgg7JK74kCUa1TF0jDFvv083VeY4uucPjep6wXMYZmn3qHgkxWzHNa6LlyNhHR0
         A9YA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YyanMaqwR347dgKCtaH7Y9tixTJISqTrKji+IkYQZrj6v83L+G4
	3UkOwC5cJZJhuTzSSV+EeCQ=
X-Google-Smtp-Source: AGHT+IEaUtv2XLPwEqJkaShd7+SD5bqSwlblEwhzKrz4waIw9JmW80bnCKhfL7djN6gged9IOSSaeA==
X-Received: by 2002:a92:ca4a:0:b0:349:59a2:2427 with SMTP id q10-20020a92ca4a000000b0034959a22427mr500282ilo.18.1693401636913;
        Wed, 30 Aug 2023 06:20:36 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:49d5:0:b0:571:18b0:e60e with SMTP id z204-20020a4a49d5000000b0057118b0e60els4832175ooa.0.-pod-prod-08-us;
 Wed, 30 Aug 2023 06:20:36 -0700 (PDT)
X-Received: by 2002:a54:4119:0:b0:3a7:9837:7148 with SMTP id l25-20020a544119000000b003a798377148mr1656095oic.58.1693401636296;
        Wed, 30 Aug 2023 06:20:36 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1693401636; cv=none;
        d=google.com; s=arc-20160816;
        b=ypSanOICQGDFxn+q+Dtu4nTk4HC2pRqDNYmJkgwnGa+jmn5nLWPatXYeqYuXFkvHGj
         OCTXNMEQTBGOsucbQthSet38ckAntboxlfRGN127iq5PmCB++Bw24cUZNuJrhrfwnwA0
         mfqWpn2phAYtybsnfJEGfb3WrR/u4RsbCMHUrti1VTuvZ7zA3F3LoVgF5sP5fJ91m49A
         ybhC8ijtF0wfGDNJFou3wdkQey8UHxzI5O2CvQ+nCHx6dJOEpOKLs6y74fwcaaZll63V
         3/FUY75M3aYvfH/6mdBYoLf9Lhb0SMsjfjCv72tJFgy7ubD7+tB1aVE4uxgxJdw/Te2r
         s6VQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:in-reply-to:references:date:message-id:from:subject
         :content-transfer-encoding:mime-version:dkim-signature;
        bh=TWBCiJcZyXnqDkHTh6iHubJa3P/ml1LXQyO7odvmV8E=;
        fh=0Ty61Yx08/9LJOiBmJ60qyJKKS4uPVm6W95JaRXejTM=;
        b=JqK6hOmTQ2aSynCsYylZeI4mGL0OlPQOSAsSp95pmSGx9EwUhECMHMm6m+scJElkTG
         ioZTRZwYpCckMuGbMYpMcqjuGDbJ0dasy7RKXq24vONcjuzw2HQ/KjFPT9QTmsEIGMYh
         vTlgVqPDhOJ7WMl4ykTgbs5QQzgNhsIa2RSPDcgdhs6NcP7P25xMmTtSYRh0wAKk4puA
         Qycds5NMOq8sPxdrSYzH4SnaT5ttEvLB75ch6LSnC1zcck0dAb+9QaMHrnYuhheGNR+3
         fRsXmyURAleFD+tjyOZpZhmpeCLDW4MSAi1hSCsunaiYkiFzUCjXjsI4UXJeFep2aTPa
         0BXg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=F32oMYF7;
       spf=pass (google.com: domain of patchwork-bot+linux-riscv@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=patchwork-bot+linux-riscv@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id bk1-20020a0568081a0100b003a7cc78b4c8si1681947oib.2.2023.08.30.06.20.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 30 Aug 2023 06:20:36 -0700 (PDT)
Received-SPF: pass (google.com: domain of patchwork-bot+linux-riscv@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id D876B62094;
	Wed, 30 Aug 2023 13:20:35 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id C087DC433B7;
	Wed, 30 Aug 2023 13:20:34 +0000 (UTC)
Received: from aws-us-west-2-korg-oddjob-1.ci.codeaurora.org (localhost.localdomain [127.0.0.1])
	by aws-us-west-2-korg-oddjob-1.ci.codeaurora.org (Postfix) with ESMTP id A76EBE26D49;
	Wed, 30 Aug 2023 13:20:34 +0000 (UTC)
Content-Type: text/plain; charset="UTF-8"
MIME-Version: 1.0
Subject: Re: [PATCH 1/2] riscv: Mark KASAN tmp* page tables variables as static
From: patchwork-bot+linux-riscv@kernel.org
Message-Id: <169340163468.19859.6513000378615706534.git-patchwork-notify@kernel.org>
Date: Wed, 30 Aug 2023 13:20:34 +0000
References: <20230704074357.233982-1-alexghiti@rivosinc.com>
In-Reply-To: <20230704074357.233982-1-alexghiti@rivosinc.com>
To: Alexandre Ghiti <alexghiti@rivosinc.com>
Cc: linux-riscv@lists.infradead.org, ryabinin.a.a@gmail.com,
 glider@google.com, andreyknvl@gmail.com, dvyukov@google.com,
 vincenzo.frascino@arm.com, paul.walmsley@sifive.com, palmer@dabbelt.com,
 aou@eecs.berkeley.edu, bjorn@rivosinc.com, kasan-dev@googlegroups.com,
 linux-kernel@vger.kernel.org, lkp@intel.com
X-Original-Sender: patchwork-bot+linux-riscv@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=F32oMYF7;       spf=pass
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

This series was applied to riscv/linux.git (for-next)
by Palmer Dabbelt <palmer@rivosinc.com>:

On Tue,  4 Jul 2023 09:43:56 +0200 you wrote:
> tmp_pg_dir, tmp_p4d and tmp_pud are only used in kasan_init.c so they
> should be declared as static.
> 
> Reported-by: kernel test robot <lkp@intel.com>
> Closes: https://lore.kernel.org/oe-kbuild-all/202306282202.bODptiGE-lkp@intel.com/
> Fixes: 96f9d4daf745 ("riscv: Rework kasan population functions")
> Signed-off-by: Alexandre Ghiti <alexghiti@rivosinc.com>
> 
> [...]

Here is the summary with links:
  - [1/2] riscv: Mark KASAN tmp* page tables variables as static
    https://git.kernel.org/riscv/c/56e1803d9de0
  - [2/2] riscv: Move create_tmp_mapping() to init sections
    https://git.kernel.org/riscv/c/d616fce3f100

You are awesome, thank you!
-- 
Deet-doot-dot, I am a bot.
https://korg.docs.kernel.org/patchwork/pwbot.html


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/169340163468.19859.6513000378615706534.git-patchwork-notify%40kernel.org.
