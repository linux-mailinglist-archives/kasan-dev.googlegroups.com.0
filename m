Return-Path: <kasan-dev+bncBAABBK4W4TCAMGQE7IANB5A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x737.google.com (mail-qk1-x737.google.com [IPv6:2607:f8b0:4864:20::737])
	by mail.lfdr.de (Postfix) with ESMTPS id 572F8B1FC1F
	for <lists+kasan-dev@lfdr.de>; Sun, 10 Aug 2025 23:12:13 +0200 (CEST)
Received: by mail-qk1-x737.google.com with SMTP id af79cd13be357-7e69a0a8bcbsf899477085a.0
        for <lists+kasan-dev@lfdr.de>; Sun, 10 Aug 2025 14:12:13 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1754860332; cv=pass;
        d=google.com; s=arc-20240605;
        b=UW0JkLS4w3aZFaoU6kv9Db4fVk6GfkzyYcOsJgTBW2mXwhRNARutRUaWe6FWXnuF3q
         qKnpq+c/iNxzVKMkU5g/K/hoTpGGPHZyazCzUYzDeC3kcfIK84lKDIzcGNxD+T95bwb3
         1/NW+aj57ll4esYUgr3UivJVF5bb471AGjGokElqxY9cnAvYp/lGMy3seGelVgedO2xM
         utf/TWULj+SmzFWLOCj76CzxqWR1HTKpboVrs10lJQYY2Pl8VUhkqqh63+JGJtfEmT1h
         Ot45/YAbxKZkbNguqWxentgW1U8MFaAsTFUxAz2gybZSlqm6Ifnn3LuyRNw81ZvtWxrg
         d+7A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:in-reply-to
         :references:date:message-id:from:subject:mime-version:dkim-signature;
        bh=pipcHJfDfZ93DnpEAUeyymMGsBizv/sixplEevqNkOw=;
        fh=VeopVern/nfueFdegUTvn9JyO9bTH2UMUiq7bVlERyI=;
        b=PUV4Y8eZFN3NAmsXafnSNS6KK+2PYNr8CApjKfWSTs9pkwcAkwicNlZlCmTrjkQGtJ
         n8+pfMzucU52WR/OzoFbLWyvNwSaM2JpGh+4fSwkIDTNFFD4ZGsj/DUKbZZBtWJR98Hn
         wkQioGcpAkdWG9OJMd+vxJOAzvZZI4nQj8valrQ+gDO8/SvWFMGZbmdyHrsmbwueu1pf
         uPLCEkgXY0oKcOMj4brk7N2GApB3fcVwWDrx2UwHHKU8qB29irBdRfakzm59puLoilqO
         Nbo3UbrLNv1o9TDwPUEKkHQq3Hz1oO+DIpEovf4BBCh1iz84CV1jyo6kwuDiYBdkuNLt
         nhSw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=HCOBV3tU;
       spf=pass (google.com: domain of patchwork-bot+linux-riscv@kernel.org designates 172.234.252.31 as permitted sender) smtp.mailfrom=patchwork-bot+linux-riscv@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1754860332; x=1755465132; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to
         :in-reply-to:references:date:message-id:from:subject:mime-version
         :from:to:cc:subject:date:message-id:reply-to;
        bh=pipcHJfDfZ93DnpEAUeyymMGsBizv/sixplEevqNkOw=;
        b=bmr/WMowYbmmBKQQLzUI0ln+L9WtnQ3ckAZaz+aeTmFlbadppIMeyWYX8GwepT+LkM
         q6xuGCtLTpuIKDe4LnShBaZCtbiW5zxd3vYPmiFJznSPo4gpFEBA3gqpyDeHBDAew1Zq
         OCyoGjVDpRPkWaqPaDMTK9r/SF3sB9ZsTNs+OvVq+SujOYHnQuIBNiqQzc0gBWB4mIbl
         +TtiN+PZskiWUeHuaKlWofVVkRrWv10fRbo1x6VqqwAcVJukch3fDLF0pkXM0pvnqhdM
         8BP2NBXMf0WY7aZ9k68xjA5mLdNVM8dI2AcT0GzoU2NJ1KBBjPIOLe3JY3ZQmQsyCKtr
         bxKA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1754860332; x=1755465132;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to
         :in-reply-to:references:date:message-id:from:subject:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=pipcHJfDfZ93DnpEAUeyymMGsBizv/sixplEevqNkOw=;
        b=q0F2Zg3jWREZQgAOuPNrm+wT7SjewbdnqZYDE1Bqeotrq41vX3+FAVi3kTlNZUuHXA
         hrdy7RYwiXjPXMN4l2RjEeYvwsFPHaRZx+r78jVxEqh0atwMOsusa1Pj10aAXdygmEgK
         7ljToFjjLQoE9xStZKM3QdOKotEH1kEyAgTJweKKGQ3umwwMBFfnyMtoUZr2b1TZgXF8
         sW4gE2qSsH1JgingXupBjjfVQqI09sauGvRvCLq99I+KYSt4SYMMM7SRNcyCi/XZbxSp
         0YnjpBdJbIGHJqj5aHOIUy+2kGbht55U7aXwHZl9cSxIHpSAa3/W3/4tyAjx+ROVEI72
         wo5Q==
X-Forwarded-Encrypted: i=2; AJvYcCWKAsBMAXQc+XKsBd7kkEkmslaS1gWMt8brgQ5ny/anuHZnbstFPtpk5gMUerqhkuNkZ58STg==@lfdr.de
X-Gm-Message-State: AOJu0YwoFKx1oCChBPNdvjCNoHIiTvK5QuWko6kHunZUI7CsPgr/usE5
	W0GLk815HWISmihDTiAN4u+gcp6cuVK7Yw9bRpbXDQ8oABOJlqtf2l5X
X-Google-Smtp-Source: AGHT+IFPGJzpeyiufwxqE16eOQipZ/hFCJ9H/4dBM/IIplhC2F398xoUSl8tgG59s68HeBr5v7PUnA==
X-Received: by 2002:a05:6214:212e:b0:707:808:edea with SMTP id 6a1803df08f44-7099a19a222mr158197396d6.1.1754860331801;
        Sun, 10 Aug 2025 14:12:11 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdGy5NjIQViYbsj/A3wFf6EKCpabnTid++Y0pYMHpMrDg==
Received: by 2002:a05:6214:410f:b0:6ff:16c9:4229 with SMTP id
 6a1803df08f44-709882e09a8ls58848416d6.1.-pod-prod-05-us; Sun, 10 Aug 2025
 14:12:11 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXirno87VwPL7k1P8W2NnjdJtRKecPiXwH/gv33XdVeBDFlQu663lDXZUiqXvnLsVYl8zmZYoOLOJ8=@googlegroups.com
X-Received: by 2002:a05:6102:330e:b0:4f9:69a9:4ec5 with SMTP id ada2fe7eead31-5060f6ab441mr3562760137.27.1754860330973;
        Sun, 10 Aug 2025 14:12:10 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1754860330; cv=none;
        d=google.com; s=arc-20240605;
        b=JACOA1nWx4c5sLI66qnkSAPBYqfbqbCEv67k1H9AJrXGxCGWpZFivTX6Kozm5iBK+p
         vQWOt7LBrZ1MpGVBAVKlvSIVUwFOpFg5R0D98mW6PfUnW7iQ4YhGxa+VDnn4x1qb/ngA
         XSbkwV5vtgtitYO1aYOFEPwlTgkxn2mO059QivosBL84iC7usxU5X+8D0pnCgYftLYyG
         rDczanIU8jouNFK4sRrDN/li2LwFAxBTX8Frzr8f8Q7y1J6gTpo30eSnkmwvm+Z+9YfZ
         qOueLDus/UdmPGFJcxf9YL96HVE1QIvC0qP5QCn7uo0DQLQlSdDX8ZG3jEv1JI/6+BwT
         dnhQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:in-reply-to:references:date:message-id:from:subject
         :content-transfer-encoding:mime-version:dkim-signature;
        bh=MHGi9waLbc/LXqI7q6196IqO0koRV2UuvFn61AeiCls=;
        fh=tR1Y0T04rz5/Im94Cq7ymdZGvgJwH8HsXVDz6nCj+es=;
        b=BWPtj3Cf/rKGgK7Nj0jxI0e9jZNpRus6KwuEj5eXXSADkWixRlD4a3JNQqGNg4kL/1
         fOqkZXR4nCpdSbYX9R1XrWw4oljSZ+VeyMCoW8QpzYarsgDeVbS3JVXKfO7k9RZ9291o
         pGZ6jvwIw7rxZt7pM386vO28xuW13/9nDZlv60zqi3LM+j5r3dbfFEppTNUKE+6HuLOS
         SblXs9AuhEx4Y4AutV8KN12MK6oqBS7qJbdJ27f/SUazAFXlfXLIwmvixHPyREwCXRxj
         Tb65OyQd6moYrMZudZvP3bf/TXueZVpYk2wO2n7Ws+mlVU4jcK2qJ8rKAoSkvZaBbEk3
         /dwA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=HCOBV3tU;
       spf=pass (google.com: domain of patchwork-bot+linux-riscv@kernel.org designates 172.234.252.31 as permitted sender) smtp.mailfrom=patchwork-bot+linux-riscv@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from sea.source.kernel.org (sea.source.kernel.org. [172.234.252.31])
        by gmr-mx.google.com with ESMTPS id a1e0cc1a2514c-88e1ff5ef6esi181342241.2.2025.08.10.14.12.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sun, 10 Aug 2025 14:12:10 -0700 (PDT)
Received-SPF: pass (google.com: domain of patchwork-bot+linux-riscv@kernel.org designates 172.234.252.31 as permitted sender) client-ip=172.234.252.31;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id F149F45AF0;
	Sun, 10 Aug 2025 21:12:09 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id CF676C4CEEB;
	Sun, 10 Aug 2025 21:12:09 +0000 (UTC)
Received: from [10.30.226.235] (localhost [IPv6:::1])
	by aws-us-west-2-korg-oddjob-rhel9-1.codeaurora.org (Postfix) with ESMTP id ADD1539D0C2B;
	Sun, 10 Aug 2025 21:12:23 +0000 (UTC)
Content-Type: text/plain; charset="UTF-8"
MIME-Version: 1.0
Subject: Re: [PATCH v3 00/13] stackleak: Support Clang stack depth tracking
From: "patchwork-bot+linux-riscv via kasan-dev" <kasan-dev@googlegroups.com>
Message-Id: <175486034248.1221929.3658503475425874388.git-patchwork-notify@kernel.org>
Date: Sun, 10 Aug 2025 21:12:22 +0000
References: <20250717231756.make.423-kees@kernel.org>
In-Reply-To: <20250717231756.make.423-kees@kernel.org>
To: Kees Cook <kees@kernel.org>
Cc: linux-riscv@lists.infradead.org, arnd@arndb.de, mingo@kernel.org,
 gustavoars@kernel.org, hch@lst.de, andreyknvl@gmail.com,
 ryabinin.a.a@gmail.com, ardb@kernel.org, masahiroy@kernel.org,
 nathan@kernel.org, nicolas.schier@linux.dev, nick.desaulniers+lkml@gmail.com,
 morbo@google.com, justinstitt@google.com, linux-kernel@vger.kernel.org,
 x86@kernel.org, kasan-dev@googlegroups.com, linux-doc@vger.kernel.org,
 linux-arm-kernel@lists.infradead.org, kvmarm@lists.linux.dev,
 linux-s390@vger.kernel.org, linux-efi@vger.kernel.org,
 linux-hardening@vger.kernel.org, linux-kbuild@vger.kernel.org,
 linux-security-module@vger.kernel.org, linux-kselftest@vger.kernel.org,
 sparclinux@vger.kernel.org, llvm@lists.linux.dev
X-Original-Sender: patchwork-bot+linux-riscv@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=HCOBV3tU;       spf=pass
 (google.com: domain of patchwork-bot+linux-riscv@kernel.org designates
 172.234.252.31 as permitted sender) smtp.mailfrom=patchwork-bot+linux-riscv@kernel.org;
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

This series was applied to riscv/linux.git (fixes)
by Kees Cook <kees@kernel.org>:

On Thu, 17 Jul 2025 16:25:05 -0700 you wrote:
> v3:
>   - split up and drop __init vs inline patches that went via arch trees
>   - apply feedback about preferring __init to __always_inline
>   - incorporate Ritesh Harjani's patch for __init cleanups in powerpc
>   - wider build testing on older compilers
>  v2: https://lore.kernel.org/lkml/20250523043251.it.550-kees@kernel.org/
>  v1: https://lore.kernel.org/lkml/20250507180852.work.231-kees@kernel.org/
> 
> [...]

Here is the summary with links:
  - [v3,01/13] stackleak: Rename STACKLEAK to KSTACK_ERASE
    (no matching commit)
  - [v3,02/13] stackleak: Rename stackleak_track_stack to __sanitizer_cov_stack_depth
    (no matching commit)
  - [v3,03/13] stackleak: Split KSTACK_ERASE_CFLAGS from GCC_PLUGINS_CFLAGS
    (no matching commit)
  - [v3,04/13] x86: Handle KCOV __init vs inline mismatches
    (no matching commit)
  - [v3,05/13] arm: Handle KCOV __init vs inline mismatches
    (no matching commit)
  - [v3,06/13] arm64: Handle KCOV __init vs inline mismatches
    https://git.kernel.org/riscv/c/65c430906eff
  - [v3,07/13] s390: Handle KCOV __init vs inline mismatches
    https://git.kernel.org/riscv/c/c64d6be1a6f8
  - [v3,08/13] powerpc/mm/book3s64: Move kfence and debug_pagealloc related calls to __init section
    https://git.kernel.org/riscv/c/645d1b666498
  - [v3,09/13] mips: Handle KCOV __init vs inline mismatch
    https://git.kernel.org/riscv/c/d01daf9d95c9
  - [v3,10/13] init.h: Disable sanitizer coverage for __init and __head
    https://git.kernel.org/riscv/c/381a38ea53d2
  - [v3,11/13] kstack_erase: Support Clang stack depth tracking
    (no matching commit)
  - [v3,12/13] configs/hardening: Enable CONFIG_KSTACK_ERASE
    https://git.kernel.org/riscv/c/4c56d9f7e75e
  - [v3,13/13] configs/hardening: Enable CONFIG_INIT_ON_FREE_DEFAULT_ON
    https://git.kernel.org/riscv/c/437641a72d0a

You are awesome, thank you!
-- 
Deet-doot-dot, I am a bot.
https://korg.docs.kernel.org/patchwork/pwbot.html


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/175486034248.1221929.3658503475425874388.git-patchwork-notify%40kernel.org.
