Return-Path: <kasan-dev+bncBAABBJXT4GWAMGQEP7ZT5LY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43f.google.com (mail-wr1-x43f.google.com [IPv6:2a00:1450:4864:20::43f])
	by mail.lfdr.de (Postfix) with ESMTPS id A84C8825C3A
	for <lists+kasan-dev@lfdr.de>; Fri,  5 Jan 2024 22:50:31 +0100 (CET)
Received: by mail-wr1-x43f.google.com with SMTP id ffacd0b85a97d-336a56ff1e5sf445773f8f.1
        for <lists+kasan-dev@lfdr.de>; Fri, 05 Jan 2024 13:50:31 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1704491431; cv=pass;
        d=google.com; s=arc-20160816;
        b=L+gatFl1rapZ2/RYpYw8wTMcd6SDuA1gt/5FjuKqgYe+xGOudW+qev6eEY3lBQ1fYA
         sfuPbZoLPhjkrtUbgfsvN9TRHNu85NnTXTcQ87p08D18kRYZAnlLTjLbx6roptHpQdtw
         VW+/5bYZ9G8uj+23ATqGav3eqPPuSSXGa5VkB2DK4AHgZ0R2l3eG77ZJmimkom4qkFbA
         KGyTOD+UTXutgfTDysyfd+Ouoxq7w+HdW5i//cLwmibiwv6EYH4vGwSdmqY+RWe6PboD
         ywp95qwjVQ9Kyn8vPBDBfqbhMYYBvX3X+3wCvoUi0KA5pBRpqnOw0dV/BmwypJQaUXi2
         WHyg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:in-reply-to:references:date
         :message-id:from:subject:mime-version:sender:dkim-signature;
        bh=iPVc5J/nyXg4hBoCKVQ8lAvvZhxdjGgY0SNYgUAWxyg=;
        fh=DULSmvQJ10ynEPq8FTbjDtggRZt8LuaC8ESAD7cK3CU=;
        b=ay3Dertwe3XmBfksKE1w7qm7CGoFRzmN5vMQy3nv1cGEOQyPv5gKF0KtjH7FCC1z9X
         KxQHn8mMbZG1mvGAv80mn+IQ2QT74kR35xTmIXfdSwSXEqY9LmDZsRelbQO+mC5MKNa2
         5EITHHXITcF2UoZ1qpK2MllrquaujvnS7l9LIdyKPtHzDn+HgHzTBXRFayE8mUohPrV8
         k9tB43T1lrL5B6erOG78+bqj6miqSxoGug0rO5Jqbfx9qKvK8jKZhMRPy5sLZbh+dhHE
         K7Y1LWWgL38yibjn7nEm14EpotSqzyoTEIY7w7Ey7IXL2YtbSzrNtETg78cjg8IgcuJw
         S/IQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=eqKFe3dT;
       spf=pass (google.com: domain of patchwork-bot+linux-riscv@kernel.org designates 145.40.68.75 as permitted sender) smtp.mailfrom=patchwork-bot+linux-riscv@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1704491431; x=1705096231; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:in-reply-to:references:date:message-id:from
         :subject:mime-version:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=iPVc5J/nyXg4hBoCKVQ8lAvvZhxdjGgY0SNYgUAWxyg=;
        b=Gy6l5b+IYlgg+SbX4l3R0u/NYll3/oR3p4oB3aWhM2gBzXx8WvJdH1e3cEebRhRuqO
         fHvC6VOg4TbkhW80TeB94Bwr+gAajuN3eGb0HfTtDJ4ypUg5UgBFIS4GYEUHbak94UA9
         h4aszFXmesq8J03e+sc//6sH217NPcRMtb82yOOQip3/yNTvKOjC4kY8gfOig8eQBg4q
         uBQIxeA0SZH/0iKBTlz+rT+P1SVvWjvOPdkxtH5uJDaHJ0E0hLb1V8tyyX5yzEVuCEHV
         scUoWLKROL6oAnH9EJ16krKkB5YcEqMKr4pJTCx4oCHEdTVhE5BF3vzV6F6+hb43ErT3
         Ijww==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1704491431; x=1705096231;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to
         :in-reply-to:references:date:message-id:from:subject:mime-version
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=iPVc5J/nyXg4hBoCKVQ8lAvvZhxdjGgY0SNYgUAWxyg=;
        b=sKH99H8UP+yrSYjTEEiT6Xz4ChPDuY+KMvMNHe7a6oTICOnL96gijj5euV4hWHPIzz
         1OlypIotdEmf+GwG7LWL3m/6bj4IYnFz8hLS0yiWluQ2W2DCx+/iJruzcBRVjV+UZyHk
         opaqpufD3tDAA99+z/TwB+uF0TNVisnAVKN3dd6kGJxQ9DRnVSz+aj4FicceOxIT/A7S
         mCG1A7SexJLPqyFx+t9q+g5E1FN2AGcWY1MMJ6dD8j/o8Nh61J9LVADF1e6bMe0XI8ez
         tQgEmxIay+SkTkVWkInJRngQpOJHX3c6lrwRHPUQVIBLs2SbTpQbDwCTmezIhV/ywVtP
         odKw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yz9Hk2+/u7lHrjBujCTPGBxDJd7z3ws0O2PjgFwkMzX/kDKYccE
	2A5t1myp+p1/TH1N3CJ/7Bk=
X-Google-Smtp-Source: AGHT+IFeumy4QRAxX/JRmFt8ywO+ycBrwui/bdDiUuj0cG1H83JGpEAkTmr32n+gxBs6qwVijniPFg==
X-Received: by 2002:a05:600c:1f95:b0:40d:5d0d:e131 with SMTP id je21-20020a05600c1f9500b0040d5d0de131mr1650014wmb.0.1704491430846;
        Fri, 05 Jan 2024 13:50:30 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:fc08:0:b0:336:dfa1:60dd with SMTP id i8-20020adffc08000000b00336dfa160ddls276876wrr.1.-pod-prod-00-eu;
 Fri, 05 Jan 2024 13:50:29 -0800 (PST)
X-Received: by 2002:adf:e88f:0:b0:337:4fa5:f378 with SMTP id d15-20020adfe88f000000b003374fa5f378mr48991wrm.52.1704491429324;
        Fri, 05 Jan 2024 13:50:29 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1704491429; cv=none;
        d=google.com; s=arc-20160816;
        b=qCweLIGsbSZroJb6HYu39KSJ149rdtI6O0O7iGlLQTqthEnvReI9uDKXNNijBDV4A1
         es9gJvxhD4cSQgvr0LwO7JLvqgnLSBKAkg1Klcenb9kpXM4tXtPeJO0PpF29dt2cqqIw
         neU7iO0eTL8KmZle9N5Sh7D51eyMbOjssBXSPsNNOU0boKwGL7QhKiwNvutFkpZT2X10
         pO+xO5fomy4zLJXARobvTBk+kl8pe5XlonCr8OIUdccZwCqAdxvixiTOjC/iIrlTk+zS
         iIqgo/WFzp9Jx6oooD+qHZlJtUXiTYT7APRa0tqzZL3UC1D4nOTeKhG+1RY1GTj2dKBk
         egMQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:in-reply-to:references:date:message-id:from:subject
         :content-transfer-encoding:mime-version:dkim-signature;
        bh=GHTLgGAfjvMs4KnH8HIXfolXQeoIl0vDCriiAW9s+7U=;
        fh=DULSmvQJ10ynEPq8FTbjDtggRZt8LuaC8ESAD7cK3CU=;
        b=N9UKCvNdbimP1VNr1jqkVe29QxxFMaj2UJzCasGwg/kU4YeEc36MraN/HUWPzo9/bt
         z5wE44XnoVd/5vkOXbVTIAkpHPDMyoPQQ/Gydmwt0Rd/8yVJsDgDnSaEWSDyuL+ivbAg
         bavBiFwvrkkiA2GTwa/Ozf6LO9kd+IjYQzVXbI9ZL5DGyk5gYgTqAMifRBUDflj1GtQR
         eRrGZMroTOWTn6U12ymn+vAgPMyfqztPqqyqDem7DgpZ6+dKih1c+SE/t15ZopDjpuxX
         6XLxJ35gmUpM9kFefG2vUwN796fVNYb6PdE30BE5iPISRutL/wSdjiUfLfIqSwXraB1e
         0RKA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=eqKFe3dT;
       spf=pass (google.com: domain of patchwork-bot+linux-riscv@kernel.org designates 145.40.68.75 as permitted sender) smtp.mailfrom=patchwork-bot+linux-riscv@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from ams.source.kernel.org (ams.source.kernel.org. [145.40.68.75])
        by gmr-mx.google.com with ESMTPS id u3-20020a5d5143000000b003372dfaad0csi110482wrt.7.2024.01.05.13.50.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 05 Jan 2024 13:50:29 -0800 (PST)
Received-SPF: pass (google.com: domain of patchwork-bot+linux-riscv@kernel.org designates 145.40.68.75 as permitted sender) client-ip=145.40.68.75;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by ams.source.kernel.org (Postfix) with ESMTP id C5483B81D88;
	Fri,  5 Jan 2024 21:50:28 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id D8506C433CB;
	Fri,  5 Jan 2024 21:50:27 +0000 (UTC)
Received: from aws-us-west-2-korg-oddjob-1.ci.codeaurora.org (localhost.localdomain [127.0.0.1])
	by aws-us-west-2-korg-oddjob-1.ci.codeaurora.org (Postfix) with ESMTP id C002DDCB6FD;
	Fri,  5 Jan 2024 21:50:27 +0000 (UTC)
Content-Type: text/plain; charset="UTF-8"
MIME-Version: 1.0
Subject: Re: [PATCH v2 0/4] riscv: Use READ_ONCE()/WRITE_ONCE() for pte accesses
From: patchwork-bot+linux-riscv@kernel.org
Message-Id: <170449142778.26226.7492189738418488414.git-patchwork-notify@kernel.org>
Date: Fri, 05 Jan 2024 21:50:27 +0000
References: <20231213203001.179237-1-alexghiti@rivosinc.com>
In-Reply-To: <20231213203001.179237-1-alexghiti@rivosinc.com>
To: Alexandre Ghiti <alexghiti@rivosinc.com>
Cc: linux-riscv@lists.infradead.org, linux@armlinux.org.uk,
 ryan.roberts@arm.com, glider@google.com, elver@google.com,
 dvyukov@google.com, paul.walmsley@sifive.com, palmer@dabbelt.com,
 aou@eecs.berkeley.edu, anup@brainfault.org, atishp@atishpatra.org,
 ardb@kernel.org, ryabinin.a.a@gmail.com, andreyknvl@gmail.com,
 vincenzo.frascino@arm.com, kasan-dev@googlegroups.com,
 linux-kernel@vger.kernel.org, kvm@vger.kernel.org,
 kvm-riscv@lists.infradead.org, linux-efi@vger.kernel.org, linux-mm@kvack.org
X-Original-Sender: patchwork-bot+linux-riscv@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=eqKFe3dT;       spf=pass
 (google.com: domain of patchwork-bot+linux-riscv@kernel.org designates
 145.40.68.75 as permitted sender) smtp.mailfrom=patchwork-bot+linux-riscv@kernel.org;
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

On Wed, 13 Dec 2023 21:29:57 +0100 you wrote:
> This series is a follow-up for riscv of a recent series from Ryan [1] which
> converts all direct dereferences of pte_t into a ptet_get() access.
> 
> The goal here for riscv is to use READ_ONCE()/WRITE_ONCE() for all page
> table entries accesses to avoid any compiler transformation when the
> hardware can concurrently modify the page tables entries (A/D bits for
> example).
> 
> [...]

Here is the summary with links:
  - [v2,1/4] riscv: Use WRITE_ONCE() when setting page table entries
    https://git.kernel.org/riscv/c/c30fa83b4989
  - [v2,2/4] mm: Introduce pudp/p4dp/pgdp_get() functions
    https://git.kernel.org/riscv/c/eba2591d99d1
  - [v2,3/4] riscv: mm: Only compile pgtable.c if MMU
    https://git.kernel.org/riscv/c/d6508999d188
  - [v2,4/4] riscv: Use accessors to page table entries instead of direct dereference
    https://git.kernel.org/riscv/c/edf955647269

You are awesome, thank you!
-- 
Deet-doot-dot, I am a bot.
https://korg.docs.kernel.org/patchwork/pwbot.html


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/170449142778.26226.7492189738418488414.git-patchwork-notify%40kernel.org.
