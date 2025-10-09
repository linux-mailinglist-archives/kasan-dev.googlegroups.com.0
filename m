Return-Path: <kasan-dev+bncBAABBSMVTTDQMGQEY7MO5NY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63e.google.com (mail-pl1-x63e.google.com [IPv6:2607:f8b0:4864:20::63e])
	by mail.lfdr.de (Postfix) with ESMTPS id 357A8BC70EE
	for <lists+kasan-dev@lfdr.de>; Thu, 09 Oct 2025 03:07:27 +0200 (CEST)
Received: by mail-pl1-x63e.google.com with SMTP id d9443c01a7336-28eb07797f9sf1736345ad.3
        for <lists+kasan-dev@lfdr.de>; Wed, 08 Oct 2025 18:07:27 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1759972045; cv=pass;
        d=google.com; s=arc-20240605;
        b=JkDxgXiwbk9SB0Kj/8zm4QBp+b9Bk3RTmTBDuBhir2kyLZ0bdLIf/l/Cfqo6c2jfd5
         W+1UZCobEexWOCRpzlImSn9VKecEy+MJGqFlNO62Hp29mo7kxnt8FOY64qk2tEtQZygk
         tlOlzJHlWEqxgTvzFkBU1rxAkOdYPqf1yPzwi7fW/QIrcoEbfjVsoFihOGa4WPEOrZ+k
         Ptm3D3PS56SfGeaEeNPCVKe+Yf/rQIPy7nBmK+u08Diqet4zBOr9cLPQPsZwDrLcd0+4
         4rkvWwBVNypItM1sxAbgv0ZqK0xC8eUhaS0EpZiuBy6i3L4rC24qsgSg6eiYPxrOAXDN
         aZ6g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:in-reply-to
         :references:date:message-id:from:subject:mime-version:dkim-signature;
        bh=6eXxy1u/SoyFk5ErnI6mo52doNXyggB3KUr92sqtooQ=;
        fh=HKsLweb8gQ00Rmka0cI/53aTLwe9Pj0uvQsTPHw0SwQ=;
        b=NO8N9HmLMj7bOqjD0cuRn17uPhMYanSQENGjGXmg/OCbQCQfGq/4oR3nZjMCXOI7l3
         TEj9K3eRzwolPleUbbf8k34pL5CzBlBCWSDoDvXs+CUvbV0nWhgNVsDRNaPpVCkJzTmd
         CcdVKH00mgysbEEYfadvSmOas7ty4XnDqQ0qU1NjrTeagJdfotiKPnpm6T5wGTxF5Zxz
         yYQcbb8KJTNtwb3zsVP/q//h0at8S0oHA6SSDuqXSrcN/Cvgf63xshQVf96Dtp57DrA+
         FNaafLc1mYrWN27mr3syxv06lZyUA5a6CLHd/2g83tG7nIRTVQg69j+ftMEXWsH5mbFC
         75KQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=hjYsA57W;
       spf=pass (google.com: domain of patchwork-bot+linux-riscv@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=patchwork-bot+linux-riscv@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1759972045; x=1760576845; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to
         :in-reply-to:references:date:message-id:from:subject:mime-version
         :from:to:cc:subject:date:message-id:reply-to;
        bh=6eXxy1u/SoyFk5ErnI6mo52doNXyggB3KUr92sqtooQ=;
        b=XV0MMk/UkWdb8sL0XIH8TGVXMa+km1U8uBKKc6vxCcYVeIdOzjV+Kig1BrPoxVD0lG
         zSI0g5EFTL4/B5n/6nyYqTP+digUVwELZ9DDvXqT3ULN2cJzd6KeYLnf2Jd2nw41QuMB
         DBN9gkTRJAE81rGX5aGd6ErdYMAIkHTsA2faHTGeEd2Ts1gpLJll61UILv+E9lvD4vnM
         jk2kNc7CrswnPn9TdwzNNVL19rAKj0yxzQ78oN9l2ySNu7RrBrVUFH50qjAefXWyZYtb
         bI47GTe5tVYje9QzCPBADad1ojnOsTSoOdtrvh+F/qxKJekRk3JKjSlLNT0fJoAlrOaj
         g8iw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1759972045; x=1760576845;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to
         :in-reply-to:references:date:message-id:from:subject:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=6eXxy1u/SoyFk5ErnI6mo52doNXyggB3KUr92sqtooQ=;
        b=C8QDdvDE1o/BYdQE5x+YvkBGOn4go8ZASJKPadKBNxZIcqPreJHq1hOmsnKrrCLf4k
         CnROz0oIZQQTVT0JMe3582EkG8nWVsjcVpMMGEHDx17BO44Th6AcHl/OqSxFL7kJOXbn
         5i+rV4AmLTocYzzzU3IZ9PYJ1VLNNLuRmx9Aj3LCRS7gFTqZxnalLOrFFXYEA8s8vVEj
         6p/lojliJxrAutuw57K8G9kKsoVzJuSxiRUTpY90+H+g0rHxXsl3k9Y/Z1kcMUmoVbuX
         ZcemchhBw6Xl04hP8X8Qava5Wq4pRUFwkF7l+dPNAJ2vn2FI7pK4cXEB2VONPsWcRotK
         TRHA==
X-Forwarded-Encrypted: i=2; AJvYcCVqHov0oRsb9JNzD5RVDTu6wYLS6x2QnmxLFI8GLofraDa+8B2KbkaaHTLyQvSn0TY/WUUB6A==@lfdr.de
X-Gm-Message-State: AOJu0YzHach8/5l+RXUYXY+RHLn4aKaB3UPUPCMWPavkhAhx4QXyvmLg
	v44N/MZZnqVrmaBelKCXJxiU3BKfLjdzKSZhitlDswQkcStK3/01Xkei
X-Google-Smtp-Source: AGHT+IHdOyiyR+a297H+yWQPMv6ByzmGuHm3JB5XCP1LHIjCL/lnmuw05b78uITkmQoqQ3kewL1uSQ==
X-Received: by 2002:a17:902:c94c:b0:28e:aacb:e6f7 with SMTP id d9443c01a7336-2902723ca5dmr39316615ad.3.1759972045378;
        Wed, 08 Oct 2025 18:07:25 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="ARHlJd45WG/83/1K/MYs2sC4nMVhPlEnmLn0f2A7VXNi3yhyfg=="
Received: by 2002:a17:902:cccc:b0:248:96db:5c48 with SMTP id
 d9443c01a7336-290358d2292ls3711925ad.2.-pod-prod-06-us; Wed, 08 Oct 2025
 18:07:20 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVRNtKdEqSOJyki1nyrcXrYecWvRYOXALvA8mnS2gSm/SgUz0XrXmRN2mqJQeKShSKRQW0tjlIJuFc=@googlegroups.com
X-Received: by 2002:a17:903:1a87:b0:26c:2e56:ec27 with SMTP id d9443c01a7336-2902737495amr80347375ad.19.1759972039817;
        Wed, 08 Oct 2025 18:07:19 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1759972039; cv=none;
        d=google.com; s=arc-20240605;
        b=e5jAsj2mHOTVV2QFJ/P7dlIn/N5THMjE8Sa7k5WfunRznCO1TCXjh2eQTegfoE3FKz
         IASN7c1/TTBnLpHrPZwl4L+9rHzebImRFm+OjaabMXwiroxUSVMVwAQolUXW9DIQ6sT/
         mavu6oMOAik5Xx9LMBmnnRuedq+sYrhrj1qC5+zr4GCvnrH/DW0G7KG44jKWvbNYUHlP
         fNRJsbJed3YdPEI5qWLG4SGcC6IcV6zcC9bBNjHZWPKILbvK3/8Rcg+kXSfakTNJLIBk
         D3D0abYnKwoAq/mjis722X6eUxvuOLDWg2Jx/xTPOSsrcLUi/F3xCZIpKAK8SssO+S6/
         WOYA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:in-reply-to:references:date:message-id:from:subject
         :content-transfer-encoding:mime-version:dkim-signature;
        bh=Pf7jqXbWOnWfySIA6lQmKNb481iT1x0PI2Co78K1Es0=;
        fh=21BeCPiS6I3AwF76Sfivd01Lm2oNQRecNtvSlAYe87U=;
        b=N5TqkVdaR6WGGnom6Gr4jY6hfTtTOWVUK4yw3wY/ZK/jw06W1tyUy6mPOQ1ilJfe+H
         B21eQHknc47Ttt/tnBetvFfJfmkhgU+98w03KTlupwHhiBPmT/NxYwvHtlS8Sn4nbIgE
         cbtPKQZSX/92gsotWmO4M1IIKS70YFBpebMFW6VOMf8nl4sKNmOvUHWLicowQpY2LgT8
         LDmiLkzBB4ksOgSt0Cpr9djohk6oKKposWKnNkXNmHfb1xjnOlZC6xKsf+ZdOBjjQMVy
         rHTEKZTDLrOcP+HY8GFhDhssMWXk0MDy09h+aoNHkqU6UwWFjmLJnE1bpxvn981ZEaCp
         eluQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=hjYsA57W;
       spf=pass (google.com: domain of patchwork-bot+linux-riscv@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=patchwork-bot+linux-riscv@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from sea.source.kernel.org (sea.source.kernel.org. [2600:3c0a:e001:78e:0:1991:8:25])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-29034eebe81si510725ad.7.2025.10.08.18.07.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 08 Oct 2025 18:07:19 -0700 (PDT)
Received-SPF: pass (google.com: domain of patchwork-bot+linux-riscv@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) client-ip=2600:3c0a:e001:78e:0:1991:8:25;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id A8F9748840;
	Thu,  9 Oct 2025 01:07:19 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 8A1B5C4CEF5;
	Thu,  9 Oct 2025 01:07:19 +0000 (UTC)
Received: from [10.30.226.235] (localhost [IPv6:::1])
	by aws-us-west-2-korg-oddjob-rhel9-1.codeaurora.org (Postfix) with ESMTP id 33C163A41017;
	Thu,  9 Oct 2025 01:07:09 +0000 (UTC)
Content-Type: text/plain; charset="UTF-8"
MIME-Version: 1.0
Subject: Re: [PATCH v2 00/12] Bump minimum supported version of LLVM for
 building the kernel to 15.0.0
From: "patchwork-bot+linux-riscv via kasan-dev" <kasan-dev@googlegroups.com>
Message-Id: <175997202775.3661959.1535236572113247824.git-patchwork-notify@kernel.org>
Date: Thu, 09 Oct 2025 01:07:07 +0000
References: <20250821-bump-min-llvm-ver-15-v2-0-635f3294e5f0@kernel.org>
In-Reply-To: <20250821-bump-min-llvm-ver-15-v2-0-635f3294e5f0@kernel.org>
To: Nathan Chancellor <nathan@kernel.org>
Cc: linux-riscv@lists.infradead.org, linux-kernel@vger.kernel.org,
 arnd@arndb.de, kees@kernel.org, nick.desaulniers+lkml@gmail.com,
 morbo@google.com, justinstitt@google.com, llvm@lists.linux.dev,
 patches@lists.linux.dev, nsc@kernel.org, linux-kbuild@vger.kernel.org,
 linux-hardening@vger.kernel.org, linux@armlinux.org.uk, ardb@kernel.org,
 linux-arm-kernel@lists.infradead.org, will@kernel.org,
 tsbogend@alpha.franken.de, linux-mips@vger.kernel.org, maddy@linux.ibm.com,
 mpe@ellerman.id.au, npiggin@gmail.com, christophe.leroy@csgroup.eu,
 linuxppc-dev@lists.ozlabs.org, palmer@dabbelt.com, alex@ghiti.fr,
 elver@google.com, peterz@infraded.org, kasan-dev@googlegroups.com
X-Original-Sender: patchwork-bot+linux-riscv@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=hjYsA57W;       spf=pass
 (google.com: domain of patchwork-bot+linux-riscv@kernel.org designates
 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=patchwork-bot+linux-riscv@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: patchwork-bot+linux-riscv@kernel.org
Reply-To: patchwork-bot+linux-riscv@kernel.org
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
by Nathan Chancellor <nathan@kernel.org>:

On Thu, 21 Aug 2025 14:15:37 -0700 you wrote:
> s390 and x86 have required LLVM 15 since
> 
>   30d17fac6aae ("scripts/min-tool-version.sh: raise minimum clang version to 15.0.0 for s390")
>   7861640aac52 ("x86/build: Raise the minimum LLVM version to 15.0.0")
> 
> respectively. This series bumps the rest of the kernel to 15.0.0 to
> match, which allows for a decent number of clean ups.
> 
> [...]

Here is the summary with links:
  - [v2,07/12] riscv: Remove version check for LTO_CLANG selects
    https://git.kernel.org/riscv/c/6578a1ff6aa4
  - [v2,08/12] riscv: Unconditionally use linker relaxation
    https://git.kernel.org/riscv/c/7ccbe91796d7
  - [v2,09/12] riscv: Remove ld.lld version checks from many TOOLCHAIN_HAS configs
    https://git.kernel.org/riscv/c/87b28d71396b

You are awesome, thank you!
-- 
Deet-doot-dot, I am a bot.
https://korg.docs.kernel.org/patchwork/pwbot.html


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/175997202775.3661959.1535236572113247824.git-patchwork-notify%40kernel.org.
