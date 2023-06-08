Return-Path: <kasan-dev+bncBAABBT6CQ6SAMGQEUQTY3QA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3a.google.com (mail-oa1-x3a.google.com [IPv6:2001:4860:4864:20::3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 85C3472825E
	for <lists+kasan-dev@lfdr.de>; Thu,  8 Jun 2023 16:10:24 +0200 (CEST)
Received: by mail-oa1-x3a.google.com with SMTP id 586e51a60fabf-1a2ac646438sf119412fac.1
        for <lists+kasan-dev@lfdr.de>; Thu, 08 Jun 2023 07:10:24 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1686233423; cv=pass;
        d=google.com; s=arc-20160816;
        b=iaIwxtpPYp+IuVydyIjnXJfZC6yvIQkgrnPv73CfuLOHhW2U6rNvi/Ccn1s7vPxKMX
         Rs/BYvzrVRHrEQOs64mZY+qnJNOwRoBTkogF67L8QA6ZfAQL2uq2iAC1jxWLnT2D5OsD
         ubIKCu1lHNRKuPpu9crhY22oRfm71662LCuxxxSfaq14g+eUltCmJjOVt4xoRkiVeuzT
         Mf/OEqLfsU24hNgeErW+tJYsVojyqr7cG8hyNYvtLUcAZTD1w8ZcXxD2kSfwwAl/xSsN
         tpRxJQMWPKLyUhPv8nzcNDl4huzc6tNFMa2TbiRYNgG6eWGUcb88Ov+gqsdyggXc/EAf
         gqyw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:in-reply-to:references:date
         :message-id:from:subject:mime-version:sender:dkim-signature;
        bh=RLCj6sDLLk+bp7nXvz62DsAPoVdHi1djeIP+GNS/imA=;
        b=tcuOrsiOifzVewxUctMlpDdmahO87NrqL5bchcpzcSRBuDBbaoqwklBO45HnkdQKJ3
         LbWwkVpU7SX5Nj7js79+C93FfYK5haMPldnTzBRLE0svNkbyNJtAm5y0kSiuENEqw9TR
         y1wqROtmwWDL6vmwys8vqBVsYinBYgOgq+EKsXF9Jwp1d6Z8cR2SO09/ZNr1TaNZXlCq
         klvA1u0RYIJpcp+LCRBU18UfPEaokxp5Bq7CtV7aZSF4zIfAG/q2BT0URIIZVRxrcfqx
         8P5E9P8opl/IXV8kmJm8khcCspXTfjEjOW7oGCL9R2Rk04oLbQs6kvs2Oht31XodTn+8
         FxPA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=eFxcodm+;
       spf=pass (google.com: domain of patchwork-bot+linux-riscv@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=patchwork-bot+linux-riscv@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1686233423; x=1688825423;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:in-reply-to:references:date:message-id:from
         :subject:mime-version:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=RLCj6sDLLk+bp7nXvz62DsAPoVdHi1djeIP+GNS/imA=;
        b=GkHLWYut3aYvsJ6RVUMjwZHiiF9NiMe+8DyYnTgBQHhEED6dU2j71JXH31kJ5QNk6E
         oonUMwmmWSSkZQyCGSUiThSjiMlRkUcQZ+oeLKDAUXfbrqS5Mn9TvSHEf7nFr+62lJWL
         kF9xRF19LktHOzA29k803zc9LL7T6YLpIKW76eA5zW6z5poQcYP7IK6XbEpdz0RGOwdU
         gMYIW2PdsdZKSBhBE73ABajqPCkL+WhdPYGPr4jYQgV1QfurPPTlARnHaSWVF1OirV93
         6/xM+yDh7KzJcHf4SF2LynRkAmJW1d8ponpZvZTVge6EZkZXoAeNCayBv+doprC2Knqd
         /FrA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1686233423; x=1688825423;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to
         :in-reply-to:references:date:message-id:from:subject:mime-version
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=RLCj6sDLLk+bp7nXvz62DsAPoVdHi1djeIP+GNS/imA=;
        b=IKGFIQY5kzTz8WkNiedQUtZsJOXZobpOf6eZOkMHjiYK/9HwteMNcoLv3Avp3HzyKP
         Kce35Nizq3onGD00tGOAGrVCD8IolYo+QVCMFQ3+qRTg1sqdCevYTGKFEnFOZ0z7z2Jm
         qZPsBHOsjGAgNplAig7CK6WQf1J73N8jBw/DD6HhaMKgTLEyoq+OPlIfIysj9R2v/HYN
         vank1C+Nqze2Ucp2lloYvNqzgjG6oPFejUOM7nJGNtJQkYWZwKWzf8uQmf89ydfNXZdE
         eUgpx3vhXgsj+K+yekJJvVRXyT5fqtr+WulCcjyDaJINFd0ZRzbGhLIJSY9rpc3PWb8A
         ltVg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AC+VfDyzL3/YU9gU9BCKigWPlhFb5yrU2e7SfqD35iSfWQFdqzsviG13
	3b56KDldlu1cepY+oDQyGDw=
X-Google-Smtp-Source: ACHHUZ5i0lNNvwbedO/novLeMElC8+7AWQ/vlapFnhiOhVSJruj2Pi8G66bjCdS8Ew3vghZRFpqMYA==
X-Received: by 2002:a05:6870:5611:b0:1a0:78d4:ab6 with SMTP id m17-20020a056870561100b001a078d40ab6mr3685315oao.3.1686233423084;
        Thu, 08 Jun 2023 07:10:23 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6871:8906:b0:19f:a424:5e74 with SMTP id
 ti6-20020a056871890600b0019fa4245e74ls1126766oab.0.-pod-prod-09-us; Thu, 08
 Jun 2023 07:10:22 -0700 (PDT)
X-Received: by 2002:a05:6870:716:b0:1a1:2939:3ece with SMTP id ea22-20020a056870071600b001a129393ecemr7355686oab.36.1686233422357;
        Thu, 08 Jun 2023 07:10:22 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1686233422; cv=none;
        d=google.com; s=arc-20160816;
        b=USeyhBDXJ5etsOjus8MwWwwb+wTVFOAuf6ippnd5P+B9ewH4GkaPGvMIRlYmh13j9P
         7jKc+etiLiiXlI390zDDZQIqnsbv3VIITI5fszr7G5nd4WjID0CQ8bqqcJugwgo0JKFy
         Hhht/lL9uF83sQ3JuYGTXiHqRMp1S7i3/3nQ6Tn7nRrSoKds6MtjnfZnWFQaJuxM+lSp
         lCfg7lVR4S1UMaDhs++exk04MaeaR4trlALCPadv6NHTk2JA2jVPQ9u6+W7YEcCsgdzl
         Qoq7Ti0tOJLRCywkGn56vBA9JzNcDSQSTfP+0lhx7bvbaL2VTB5NrbMxmMy9aQHjm7tO
         aLFQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:in-reply-to:references:date:message-id:from:subject
         :content-transfer-encoding:mime-version:dkim-signature;
        bh=HXpPH3ea8uPZMETLaKvlMwvgRIHgw8zggBqHoIQwCQc=;
        b=yjSKCcIs80o+qq/tSXnywbP7pJgdcLQC5X3U5l4ANxNZ2/0cm7hdoKiFSVKdXb/kb2
         Pg/gQ0XjTaRqEaLnOsuXTNS2fKyypRjxEgBVMyZOoyaTe1GALD4Pvj8k/UVonjfsSEv9
         +otpj3gvXSP4vAxnvJXtjJtHm3jwzpldacYJPQrHubdtZuChn/AMVSzFsVMchHCvbt78
         GcOi2c+NdN2jsAiWyaIgoSYPQxjRiQwdOz0KZD42rqS7OEt8E2TeHTwn/Kldlq6KlReo
         AM6ZAFi309h6tIeGP0RbjX1EK78KlStEl6pIV7vdlr6O4V/fyDCGbggMoaiA/lm7W02b
         yayg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=eFxcodm+;
       spf=pass (google.com: domain of patchwork-bot+linux-riscv@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=patchwork-bot+linux-riscv@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id mv7-20020a0568706a8700b001a34e64b281si161117oab.5.2023.06.08.07.10.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 08 Jun 2023 07:10:22 -0700 (PDT)
Received-SPF: pass (google.com: domain of patchwork-bot+linux-riscv@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id 26AC560B10;
	Thu,  8 Jun 2023 14:10:22 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id 7CB23C433D2;
	Thu,  8 Jun 2023 14:10:21 +0000 (UTC)
Received: from aws-us-west-2-korg-oddjob-1.ci.codeaurora.org (localhost.localdomain [127.0.0.1])
	by aws-us-west-2-korg-oddjob-1.ci.codeaurora.org (Postfix) with ESMTP id 5AACFE451B4;
	Thu,  8 Jun 2023 14:10:21 +0000 (UTC)
Content-Type: text/plain; charset="UTF-8"
MIME-Version: 1.0
Subject: Re: [PATCH] riscv: Fix kfence now that the linear mapping can be backed
 by PUD/P4D/PGD
From: patchwork-bot+linux-riscv@kernel.org
Message-Id: <168623342136.30670.5165804559719545344.git-patchwork-notify@kernel.org>
Date: Thu, 08 Jun 2023 14:10:21 +0000
References: <20230606130444.25090-1-alexghiti@rivosinc.com>
In-Reply-To: <20230606130444.25090-1-alexghiti@rivosinc.com>
To: Alexandre Ghiti <alexghiti@rivosinc.com>
Cc: linux-riscv@lists.infradead.org, glider@google.com, elver@google.com,
 dvyukov@google.com, paul.walmsley@sifive.com, palmer@dabbelt.com,
 aou@eecs.berkeley.edu, robh@kernel.org, anup@brainfault.org,
 ajones@ventanamicro.com, kasan-dev@googlegroups.com,
 linux-kernel@vger.kernel.org,
 syzbot+a74d57bddabbedd75135@syzkaller.appspotmail.com
X-Original-Sender: patchwork-bot+linux-riscv@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=eFxcodm+;       spf=pass
 (google.com: domain of patchwork-bot+linux-riscv@kernel.org designates
 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=patchwork-bot+linux-riscv@kernel.org;
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

This patch was applied to riscv/linux.git (fixes)
by Palmer Dabbelt <palmer@rivosinc.com>:

On Tue,  6 Jun 2023 15:04:44 +0200 you wrote:
> RISC-V Kfence implementation used to rely on the fact the linear mapping
> was backed by at most PMD hugepages, which is not true anymore since
> commit 3335068f8721 ("riscv: Use PUD/P4D/PGD pages for the linear
> mapping").
> 
> Instead of splitting PUD/P4D/PGD mappings afterwards, directly map the
> kfence pool region using PTE mappings by allocating this region before
> setup_vm_final().
> 
> [...]

Here is the summary with links:
  - riscv: Fix kfence now that the linear mapping can be backed by PUD/P4D/PGD
    https://git.kernel.org/riscv/c/25abe0db9243

You are awesome, thank you!
-- 
Deet-doot-dot, I am a bot.
https://korg.docs.kernel.org/patchwork/pwbot.html


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/168623342136.30670.5165804559719545344.git-patchwork-notify%40kernel.org.
