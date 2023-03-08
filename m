Return-Path: <kasan-dev+bncBAABBT4CUCQAMGQEEPDSOVY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23c.google.com (mail-lj1-x23c.google.com [IPv6:2a00:1450:4864:20::23c])
	by mail.lfdr.de (Postfix) with ESMTPS id 07A806AFD63
	for <lists+kasan-dev@lfdr.de>; Wed,  8 Mar 2023 04:30:25 +0100 (CET)
Received: by mail-lj1-x23c.google.com with SMTP id y23-20020a05651c021700b002984904d871sf3117957ljn.6
        for <lists+kasan-dev@lfdr.de>; Tue, 07 Mar 2023 19:30:24 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1678246224; cv=pass;
        d=google.com; s=arc-20160816;
        b=GcujJFB6FMXXrWeBzbEUyp5Tuf0slR/uOk2NZTR8TaAC6N0KYuWpgJ4+UbQcozA5qN
         +IVdK5Pbm59hc/PGQ/10qOCUtKcj7wmv85RNfK3vbQD00pLTyh13TsgMf8qWoW3pFVCS
         FnJ8/yyzpkVprSUpj3kS2bOGMXcqvdzRkjZll3DDpcNBCuOMbNlUb5IAdH5y2u243zOB
         xyfg8ErOogaEjajisp5hzphjkoFvrTu2yLvRAtE679IhZf+3+w8ZiQ95JKdxc3yxVlT1
         BPWCVJOIpFECy4SinDLR75r0uJns0ni5iNDkKfARo0PMbnyhEObqS5sZt9wkCFUTmbV1
         Aeiw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:in-reply-to:references:date
         :message-id:from:subject:mime-version:sender:dkim-signature;
        bh=7lH/H1tcHdVbRKSol74lUC0slFgknozUJ6uoGc30XWA=;
        b=oJHqEnqOKAncZzrtbTPXD68yCKIh2Y7zeWfzau8hCob+zy0+ZLRpafN9cbI+/6RApP
         QDzXvahwEBdy7Vh9+T2sGpackPfMC3QdNL4Qe+7Rn5g6zih9E1WpF/UTDf6Vb3d3W4DV
         nD4H3gweNeVNVBvGnZZqgAER7MxYBhPPaLwRm6pxVIXKoJegoRXLvhmMVWL8OqOsKm90
         vPCmNHMIVlqAZfpSH4b7JCRe3oPBpjZCECYVa4oSs0ycJQrMkQfRKqHVU8AEcxRUSJtI
         UQM1brHRpDhJZZxSD6hF235O/j256vvBwT1IHHDaNbd7bWWq3HNj8p1Eou/i89ItgHyM
         TKYw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=P0OewE6K;
       spf=pass (google.com: domain of patchwork-bot+linux-riscv@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom=patchwork-bot+linux-riscv@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112; t=1678246224;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:in-reply-to:references:date:message-id:from
         :subject:mime-version:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=7lH/H1tcHdVbRKSol74lUC0slFgknozUJ6uoGc30XWA=;
        b=dQ3SLNCzqpp+2nJc6IzMnTu56Ja7eLG6oiios2cg+zH1VhrngR24EkqH8lGwDyC5dM
         rOrvxvKeqpdVl8G2RSE039XcpC1hygPto3cwoKAb/9s/hxI9QtSdvmLlo2FYzPMZqyf3
         JysEFq1yaHN72Tziv9p4DaenaySl4W3sMM/StahfBjc6C6cWjyejRCV7SN4AGzzXOVNz
         Aaq8QvJNtrFEHKP9BgPKUb81ofwKcQqT+sQesztkl8KGUNrwzaTN2iLC9Q9TM0lEQqqB
         8vz0bI8FjyYdxz8QdC5oVLnnkIVXnpQLC0kUn4EajE6i+JO1JDuMNBYQ1JiwHy1nESd8
         cqOg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112; t=1678246224;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to
         :in-reply-to:references:date:message-id:from:subject:mime-version
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=7lH/H1tcHdVbRKSol74lUC0slFgknozUJ6uoGc30XWA=;
        b=wwaXfH7y5RQ3uMSMzFY+rzBIhVHRpebCQbt/DvYEHpnYeW9rFA32GC1d61uOynt4+c
         u97x7GJN9rMsjgsOSdTVy/JpWyOfxa8O/p7Buxw5uP+S/bS5zCZEM/FuNhH01DW7tro4
         pdCSKU9N56yiKPVubOjE752Siq2w+STZpzQlZsWam8vRCw3q6O5PGOAePu3lXVuMxHQH
         CTUNNTp2i9CBLPSozAylLgAaiZh68JhViIZlord3EFrQKvfpqr688CMsrvU9aKfVnAyY
         p8azvZg5ciExYlr0me+c7oynK674fIUdockZRC6cz/3fYkWM/dYPTLI9sSOUtgDGtEje
         UKEQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKWEvzK7gUQ0Zk+xeg9cvHIGo1sHkk39yLeFb8DDm3d1lJ+oKgqL
	SuUgUWbKyd/e3sXREtwNEl4=
X-Google-Smtp-Source: AK7set8EXFyNYlhtx47fQK23KekI+8NfcE6McPbPJ/okguuhnaPfyOydnmCFfrIBjnShv4PqrHC9Uw==
X-Received: by 2002:a2e:595:0:b0:298:6d17:eaa7 with SMTP id 143-20020a2e0595000000b002986d17eaa7mr324220ljf.2.1678246224011;
        Tue, 07 Mar 2023 19:30:24 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:1610:b0:293:12a9:1ca5 with SMTP id
 f16-20020a05651c161000b0029312a91ca5ls2538848ljq.6.-pod-prod-gmail; Tue, 07
 Mar 2023 19:30:22 -0800 (PST)
X-Received: by 2002:a2e:be94:0:b0:298:6a97:25b1 with SMTP id a20-20020a2ebe94000000b002986a9725b1mr378779ljr.16.1678246222750;
        Tue, 07 Mar 2023 19:30:22 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1678246222; cv=none;
        d=google.com; s=arc-20160816;
        b=wSjqD0tXivz5dL63Xiq8RqEcOlW0acD6yxjvVtcXeJnE95Vf+HjAZkiw55w/c9soQe
         MMolmPqdfSQtwzwAKfSPKzwQ75XibKDQJRXt2LvPO1nxiNao+4elAm+m7lGNPclQfg0h
         z/FH+eVnz0wGEARdNRwolIUgXePsjf19lXfxbwSnEHuyflSH1WMLEJOSB88VEknW555K
         SZPPDVfPjIcUk9l6TBF53/yhczJNPvOQTv0ix/sBZExxxXUOSb2sU6tmaZucY3anArd1
         Sl+ShHwyzebTUejkKQk0YCRhs+dEGD084kbRhy0LWCso3f9Z7uFTetCmJPolp/CQcASI
         u40Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:in-reply-to:references:date:message-id:from:subject
         :content-transfer-encoding:mime-version:dkim-signature;
        bh=5gGQAXQVxahP1kUqGlRw6/vpfkbgnFxTCsyEbWOJYE0=;
        b=rvWODc+1eq5lz+QzBIjjFgpDGtdQDDhHRHPAQS7r+sVwf2ngf9Sf4laxn+nLrV6bd4
         9w2pKlycGzH80gHtpzCcFfraXuHHiJmKWxHxkvHnTv7WRz2GoUbjBtcBHsZYh9BOg3Es
         h6RR6LbEkxAJD/R1BdPgjbfD7c4Liak1Klxu6h1EN9+h8H29cyN6LpH/GgoaA4z+DIf5
         g38aIDl7Td7/trzF1OnBS1yg393TCg5XERJN7nr1eLbCXDi05IN+2staW30FvZtAeduU
         K0xGTbYlEFBDIIqTX/0jsQGRkzLRc4tMEeitC262xmQpN8t8k86+xuyY2Bz8Ja8CdOim
         hp/Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=P0OewE6K;
       spf=pass (google.com: domain of patchwork-bot+linux-riscv@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom=patchwork-bot+linux-riscv@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from ams.source.kernel.org (ams.source.kernel.org. [2604:1380:4601:e00::1])
        by gmr-mx.google.com with ESMTPS id y14-20020a05651c154e00b00295a255ee26si717345ljp.6.2023.03.07.19.30.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 07 Mar 2023 19:30:22 -0800 (PST)
Received-SPF: pass (google.com: domain of patchwork-bot+linux-riscv@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) client-ip=2604:1380:4601:e00::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by ams.source.kernel.org (Postfix) with ESMTPS id EFB1DB81BA3;
	Wed,  8 Mar 2023 03:30:21 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id A45A2C4339B;
	Wed,  8 Mar 2023 03:30:20 +0000 (UTC)
Received: from aws-us-west-2-korg-oddjob-1.ci.codeaurora.org (localhost.localdomain [127.0.0.1])
	by aws-us-west-2-korg-oddjob-1.ci.codeaurora.org (Postfix) with ESMTP id 862FDC39563;
	Wed,  8 Mar 2023 03:30:20 +0000 (UTC)
Content-Type: text/plain; charset="UTF-8"
MIME-Version: 1.0
Subject: Re: [PATCH v4 0/6] RISC-V kasan rework
From: patchwork-bot+linux-riscv@kernel.org
Message-Id: <167824622054.6983.17538269821612408608.git-patchwork-notify@kernel.org>
Date: Wed, 08 Mar 2023 03:30:20 +0000
References: <20230203075232.274282-1-alexghiti@rivosinc.com>
In-Reply-To: <20230203075232.274282-1-alexghiti@rivosinc.com>
To: Alexandre Ghiti <alexghiti@rivosinc.com>
Cc: linux-riscv@lists.infradead.org, paul.walmsley@sifive.com,
 palmer@dabbelt.com, aou@eecs.berkeley.edu, ryabinin.a.a@gmail.com,
 glider@google.com, andreyknvl@gmail.com, dvyukov@google.com,
 vincenzo.frascino@arm.com, ardb@kernel.org, conor@kernel.org,
 linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com,
 linux-efi@vger.kernel.org
X-Original-Sender: patchwork-bot+linux-riscv@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=P0OewE6K;       spf=pass
 (google.com: domain of patchwork-bot+linux-riscv@kernel.org designates
 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom=patchwork-bot+linux-riscv@kernel.org;
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

On Fri,  3 Feb 2023 08:52:26 +0100 you wrote:
> As described in patch 2, our current kasan implementation is intricate,
> so I tried to simplify the implementation and mimic what arm64/x86 are
> doing.
> 
> In addition it fixes UEFI bootflow with a kasan kernel and kasan inline
> instrumentation: all kasan configurations were tested on a large ubuntu
> kernel with success with KASAN_KUNIT_TEST and KASAN_MODULE_TEST.
> 
> [...]

Here is the summary with links:
  - [v4,1/6] riscv: Split early and final KASAN population functions
    https://git.kernel.org/riscv/c/70a3bb1e1fd9
  - [v4,2/6] riscv: Rework kasan population functions
    https://git.kernel.org/riscv/c/fec8e4f66e4d
  - [v4,3/6] riscv: Move DTB_EARLY_BASE_VA to the kernel address space
    https://git.kernel.org/riscv/c/1cdf594686a3
  - [v4,4/6] riscv: Fix EFI stub usage of KASAN instrumented strcmp function
    https://git.kernel.org/riscv/c/415e9a115124
  - [v4,5/6] riscv: Fix ptdump when KASAN is enabled
    https://git.kernel.org/riscv/c/fe0c8624d20d
  - [v4,6/6] riscv: Unconditionnally select KASAN_VMALLOC if KASAN
    https://git.kernel.org/riscv/c/4cdc06c5c741

You are awesome, thank you!
-- 
Deet-doot-dot, I am a bot.
https://korg.docs.kernel.org/patchwork/pwbot.html


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/167824622054.6983.17538269821612408608.git-patchwork-notify%40kernel.org.
