Return-Path: <kasan-dev+bncBAABB24R5K4AMGQEVQE345Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x638.google.com (mail-pl1-x638.google.com [IPv6:2607:f8b0:4864:20::638])
	by mail.lfdr.de (Postfix) with ESMTPS id 1724F9AEE9C
	for <lists+kasan-dev@lfdr.de>; Thu, 24 Oct 2024 19:50:38 +0200 (CEST)
Received: by mail-pl1-x638.google.com with SMTP id d9443c01a7336-20c748ad236sf12843395ad.3
        for <lists+kasan-dev@lfdr.de>; Thu, 24 Oct 2024 10:50:37 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1729792236; cv=pass;
        d=google.com; s=arc-20240605;
        b=feHrAwWUCo+uIawrhIbIxfkM5NVVN+MoPbAEuA/dsr4geKVuqOeGByOxXcPJTcw7ED
         0TPdvKhzro5PrDQ9RnJOfOi5pniYp+3etWEpdLH6vHEt/iWNzGBP87S8UMjMNbH3ieEL
         pzy8s0dNgmlFNv6ERRmVwYMg+kb7hYXwL/Ud/xqgGawXO5+3WlrAVelfVDjm7AjpraGB
         sqpwXpzmjyxy6tbNXOAhqoPQPNaDh1D+UEZUofoKGtK+W3oMJxRyAXLka0hI00QrBgr+
         dPoK2fKP69yfNTEzYn9aZxvpmgZzYEr389ta24cDuP6M/xHLhNjhs69zp6AL+X0qD8G6
         tFZg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:in-reply-to
         :references:date:message-id:from:subject:mime-version:dkim-signature;
        bh=ZznyeOau+E7Ym/yNQ/EKSRSsfKWulPx29MkheEtWfeI=;
        fh=mdQ4rEtbKJsqdTmaI5k9T+/cp8fRs/05O71tXk3udQY=;
        b=XxzWzngtr04KYNu2RpCg0BCTXomvzLJam0eHnIvthyjcEvLguX+KdPMlU3dpGR2t8o
         VXYsBexlTkEcUZ836ZoJT0uCoMnj81+UJKbS7pEMKq7BeO+WsO9QstXApUGaYBmbkjoE
         aT0mboDJoTN5AHz4mWKpX8LcNpi+dwaKKpRh10MlIMfIidbQ2tV5lGwricxm3xJ2KoQK
         SC9dOcu9Ryic/GA0L2Hni747yimDJWj1mDT6nDJKeYk6GVTSUUPO4sQr5ERWdfTSQdZn
         xjfR8u3pjk9roiLGB95lzhRnVg8SAA1f0XD5ZTv48d9d+sqvqsDZE4Ks5AmLyOl8H75W
         9pmA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=jFqqJqdI;
       spf=pass (google.com: domain of patchwork-bot+linux-riscv@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=patchwork-bot+linux-riscv@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1729792236; x=1730397036; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to
         :in-reply-to:references:date:message-id:from:subject:mime-version
         :from:to:cc:subject:date:message-id:reply-to;
        bh=ZznyeOau+E7Ym/yNQ/EKSRSsfKWulPx29MkheEtWfeI=;
        b=ZK1ZvMsSO8FVI/SO9tiTG3IH3kdJAAgJDnhdTGRatX2NexPrrpAP9ceSo6gNym33TE
         WfzRNcoDV66P+jmddmRqJE3vV/Ik9pqg1FWUFMFBHiLSNdGUNtd9dgyE3pS7/JXxu9O6
         poZNI9jNrlQYSfIJEOzx74J1OP5ViTDjn5B3DRCYhPaDJEwKlu9uts2XB850V8swnLfw
         HmnYZ5UxDmhMqNc5rB9h3UvE0egg6WwfwmhHWsbjlPIQrhIwH/agvtBKZFp8clF8JxR9
         bLx6iyPyGQuESBr9dXdLjhkLW9PnJfLfBzYWTcMgAYr3OT5F1VksEiOJzYwTWPyN1cKZ
         64hA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1729792236; x=1730397036;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to
         :in-reply-to:references:date:message-id:from:subject:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=ZznyeOau+E7Ym/yNQ/EKSRSsfKWulPx29MkheEtWfeI=;
        b=l1XI1XHMF1N4aJy+EHbGF91eF3eQCaJM2Rp0LdYVtIiOgI+ybv8J7oInVLi70CIamB
         FWi+4/nuxOKfPhzrcanfiuX3C39nOs9c2EYvJJXK9U7BthIZUQ94jvjhWwtyNW3WexOC
         xXINJrJdK7Iv43ZO9FTUWQ9D51gFlGeNwC6uLn3Da5kyElBn85HJYLI2Rb5JnOf6Toxe
         NtcWa8/cqEVR6T6jgNjzoNBeMHLAtODn2kbfRjK23vHDKa2S7js5BU8ZIB9FQ1/nvYQQ
         jhMM82TXjpAhT7/5xKsVnH4sMaX8YuwPKqZqz6sHXWNXHuk6jLVP6JslTkKZ9N+T6FW3
         TYQA==
X-Forwarded-Encrypted: i=2; AJvYcCX/I44TUnrwCP+fYZ0RJEXLXQ5DVBhBWy8GnDVbixC/uTVXFIgFS1MoxzRXX9XmOZd5an9KOg==@lfdr.de
X-Gm-Message-State: AOJu0YyHctUyUlmS/hxukaNXCYNU/4mtDPCOyrJg5ahuX9y13U00gTWL
	GPZZGv6uDTL87Dqe7R2S6CusLD2v9FAYExKorIDBW6I+PuO03rOI
X-Google-Smtp-Source: AGHT+IGZDkuDSmRJMQchAOfxKZCFrckaLMaIhVMhqpMyvqtsjzxwm7hP8OvixBholW2/4LFM2y0Oyw==
X-Received: by 2002:a17:902:dac6:b0:20c:f9ec:cd9e with SMTP id d9443c01a7336-20fa9eb948amr85989325ad.41.1729792235650;
        Thu, 24 Oct 2024 10:50:35 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:903:41cb:b0:206:9347:a4f with SMTP id
 d9443c01a7336-20fb5312f8cls8588955ad.1.-pod-prod-02-us; Thu, 24 Oct 2024
 10:50:34 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCX79rx5kJQbboYaCRAM32o61ENWu7RXB7oH1cwZ5p/eFBIuINW7t8lFSYcBE56hOyiGRV9hjitEV0A=@googlegroups.com
X-Received: by 2002:a17:902:e741:b0:20c:ea04:a186 with SMTP id d9443c01a7336-20fab2db8c1mr80998775ad.48.1729792234173;
        Thu, 24 Oct 2024 10:50:34 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1729792234; cv=none;
        d=google.com; s=arc-20240605;
        b=VRhEeH9w6MY8sdH8f9bEXEb8a+idXj7mY+DhKciRBDErR0gSTZbeVMnMYVk1au/moB
         pPNSiqdFKeYki5BJrw+mvWqNDpCn2U2eJE6XI1766LTKVfyzfnnF+CAS2JTJmqJ/lH4e
         lCl76tnN75md0x4Kkutp9+c4gd7F0OuQwBJoEqLZesPSMzXIv8rQ/SxuZNgpuzkj4zd7
         QW7NlvF0Zf68+gIs50u2Icutbo0MGd1EkmHzsb1a3Bg6oKsRe7TaPD8rdvfXQZYVdhmU
         TXmzZ6EUayjW6v8m5bIOTByXkF1Eft292Prdjhi32EwHCI1PLDlr+yVSrVwM99M2OuZI
         coxQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:in-reply-to:references:date:message-id:from:subject
         :content-transfer-encoding:mime-version:dkim-signature;
        bh=kKFNtARqjxJUJG79PlC168zfN+E0AzxlJ6w5/d5Cw+U=;
        fh=pP225OjecbCw2t/4YhEJreP/kAwO0SFmti4MEw4e4ws=;
        b=MHt8RTrnM4I7Bc7ceTWXotI8V3O5h8+XfbMt6x+5/JHPpoAInixVy6+R3tKYaXIUCf
         Y/9rSM1RQXHSf8V4dcMBRJTVY0mDiVuj5w42rGeEnu6aa0bHgvgWtDPeCQeV+V1LYyvW
         CBiwYdvRNvRaKVZ5hm5jdO6+/z2XhNkt1Fb901K2EIr9Tbyr9mg6c4WoUxvEjUDDqXdy
         KXXpB0+48cPFP3clMd5V2qM7c6qR7BbNzQE7XFZZ/ctTsqxgnRTf0PRgPo7Oic0A1MuQ
         CrdiyJ4kgidVbz2LRNuSR38KEptE6tVdGtyMupIhVIPWCuerp3hknRFjpwZHWvddpdza
         7HgA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=jFqqJqdI;
       spf=pass (google.com: domain of patchwork-bot+linux-riscv@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=patchwork-bot+linux-riscv@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-20e7ef4484esi4010735ad.4.2024.10.24.10.50.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 24 Oct 2024 10:50:34 -0700 (PDT)
Received-SPF: pass (google.com: domain of patchwork-bot+linux-riscv@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id B42785C54E6;
	Thu, 24 Oct 2024 17:50:28 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 17B83C4CEE4;
	Thu, 24 Oct 2024 17:50:33 +0000 (UTC)
Received: from [10.30.226.235] (localhost [IPv6:::1])
	by aws-us-west-2-korg-oddjob-rhel9-1.codeaurora.org (Postfix) with ESMTP id EAF38380DBDC;
	Thu, 24 Oct 2024 17:50:40 +0000 (UTC)
Content-Type: text/plain; charset="UTF-8"
MIME-Version: 1.0
Subject: Re: [PATCH v5 00/10] riscv: Userspace pointer masking and tagged address
 ABI
From: "patchwork-bot+linux-riscv via kasan-dev" <kasan-dev@googlegroups.com>
Message-Id: <172979223949.2327357.12698642185375267636.git-patchwork-notify@kernel.org>
Date: Thu, 24 Oct 2024 17:50:39 +0000
References: <20241016202814.4061541-1-samuel.holland@sifive.com>
In-Reply-To: <20241016202814.4061541-1-samuel.holland@sifive.com>
To: Samuel Holland <samuel.holland@sifive.com>
Cc: linux-riscv@lists.infradead.org, palmer@dabbelt.com,
 catalin.marinas@arm.com, atishp@atishpatra.org,
 linux-kselftest@vger.kernel.org, robh+dt@kernel.org,
 kirill.shutemov@linux.intel.com, shuah@kernel.org,
 devicetree@vger.kernel.org, anup@brainfault.org,
 linux-kernel@vger.kernel.org, corbet@lwn.net, kvm-riscv@lists.infradead.org,
 conor@kernel.org, kasan-dev@googlegroups.com, linux-doc@vger.kernel.org,
 eugenis@google.com, charlie@rivosinc.com, krzysztof.kozlowski+dt@linaro.org
X-Original-Sender: patchwork-bot+linux-riscv@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=jFqqJqdI;       spf=pass
 (google.com: domain of patchwork-bot+linux-riscv@kernel.org designates
 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=patchwork-bot+linux-riscv@kernel.org;
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
by Palmer Dabbelt <palmer@rivosinc.com>:

On Wed, 16 Oct 2024 13:27:41 -0700 you wrote:
> RISC-V defines three extensions for pointer masking[1]:
>  - Smmpm: configured in M-mode, affects M-mode
>  - Smnpm: configured in M-mode, affects the next lower mode (S or U-mode)
>  - Ssnpm: configured in S-mode, affects the next lower mode (VS, VU, or U-mode)
> 
> This series adds support for configuring Smnpm or Ssnpm (depending on
> which privilege mode the kernel is running in) to allow pointer masking
> in userspace (VU or U-mode), extending the PR_SET_TAGGED_ADDR_CTRL API
> from arm64. Unlike arm64 TBI, userspace pointer masking is not enabled
> by default on RISC-V. Additionally, the tag width (referred to as PMLEN)
> is variable, so userspace needs to ask the kernel for a specific tag
> width, which is interpreted as a lower bound on the number of tag bits.
> 
> [...]

Here is the summary with links:
  - [v5,01/10] dt-bindings: riscv: Add pointer masking ISA extensions
    https://git.kernel.org/riscv/c/8946ad26c0e2
  - [v5,02/10] riscv: Add ISA extension parsing for pointer masking
    https://git.kernel.org/riscv/c/12749546293e
  - [v5,03/10] riscv: Add CSR definitions for pointer masking
    https://git.kernel.org/riscv/c/1edd6226877b
  - [v5,04/10] riscv: Add support for userspace pointer masking
    https://git.kernel.org/riscv/c/871aba681a0d
  - [v5,05/10] riscv: Add support for the tagged address ABI
    https://git.kernel.org/riscv/c/c4d16116bd11
  - [v5,06/10] riscv: Allow ptrace control of the tagged address ABI
    https://git.kernel.org/riscv/c/cebce87fb04e
  - [v5,07/10] riscv: selftests: Add a pointer masking test
    https://git.kernel.org/riscv/c/5e9f1ee1c523
  - [v5,08/10] riscv: hwprobe: Export the Supm ISA extension
    https://git.kernel.org/riscv/c/d250050aae4f
  - [v5,09/10] RISC-V: KVM: Allow Smnpm and Ssnpm extensions for guests
    https://git.kernel.org/riscv/c/e27f468bcf14
  - [v5,10/10] KVM: riscv: selftests: Add Smnpm and Ssnpm to get-reg-list test
    https://git.kernel.org/riscv/c/814779461d84

You are awesome, thank you!
-- 
Deet-doot-dot, I am a bot.
https://korg.docs.kernel.org/patchwork/pwbot.html


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/172979223949.2327357.12698642185375267636.git-patchwork-notify%40kernel.org.
