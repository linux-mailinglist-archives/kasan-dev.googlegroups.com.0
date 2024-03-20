Return-Path: <kasan-dev+bncBC76RJVVRQPRBU7B5WXQMGQE2FHJGAY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd40.google.com (mail-io1-xd40.google.com [IPv6:2607:f8b0:4864:20::d40])
	by mail.lfdr.de (Postfix) with ESMTPS id 9DFAE881A26
	for <lists+kasan-dev@lfdr.de>; Thu, 21 Mar 2024 00:27:17 +0100 (CET)
Received: by mail-io1-xd40.google.com with SMTP id ca18e2360f4ac-7cbfd4781fcsf31221939f.3
        for <lists+kasan-dev@lfdr.de>; Wed, 20 Mar 2024 16:27:17 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1710977236; cv=pass;
        d=google.com; s=arc-20160816;
        b=erxMwLrTn4hK1AA5LxKU+5xxfyURq30ucaKpoTAlbwgx9jMFfQCokjLNm3QYDIbDU+
         GEDJ0jIXSDd22U5wWIVLQHjSanaPqb09a4XPSvw9XMctG6pkZ3o9gRWa98oZv0+ZIdj1
         CYOjUIYR72cg7aP1eLy5LOAT+RnygLJeso0rL4nhvwFoJSj6PCIi3/hffCQ6DoNC8gh1
         g962PdM6dOBP8KviHzT8izYrI5oxy/LGgtjh+QOGdI8Ww5ZNbsZ171UCVKI2vO7IH63/
         s8zi3K4AkeQgTv0WnRDZ3sfqcoqR4slTupv4XsHU+KUzCMFnckVbMiE9hYnTwDNSklXF
         yIDA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=sPZgtkKUNnMLZTZQ51rOdcahT/0Ce+aYAnGJPNyno6Y=;
        fh=rdMpA7KmuA2T1NJUIoE0BBTgyX9Gr6FfWcsF0Y/Wedk=;
        b=q515PsUutunY2gXAYEVFTLZJ3EBh6M++x7YSozNpp7ED9pUqcFMLgdGLo/QesP/j+8
         7w4ia1AjnrUEhBCcUsxCLuM3hWkaUbObRllB3gY/Klqt1grzmsayl0wXHA1LljwuV962
         Lg3Ul7ZOB+sdgS1TQVX1tDDFqOGz/np6lapSvqEdh70DX3C5d2KNQRLYyfF1QtISCyCE
         jHGcbUReOQZ3MRME7V80WitYGZaj8m3ric2VlI28+61XVbiUjyuoSuWOBdLl/AYVQ424
         5ul2d9D1D2cy2Vm0UYA/HAHAonnZrTCVpefAoSQvPcC2yeXwdPTi3RETPmuVxsysju/n
         2qWw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@rivosinc-com.20230601.gappssmtp.com header.s=20230601 header.b=qvzmqyfO;
       spf=pass (google.com: domain of debug@rivosinc.com designates 2607:f8b0:4864:20::1133 as permitted sender) smtp.mailfrom=debug@rivosinc.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1710977236; x=1711582036; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:in-reply-to
         :references:mime-version:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=sPZgtkKUNnMLZTZQ51rOdcahT/0Ce+aYAnGJPNyno6Y=;
        b=hQ/k/r3dQl3fYkf35/MpSOihz9T5MmIGHUhejOfiIO5vuiVGr7e6Sjc7HmhofuC92D
         zA1nrqxw+fa3ueXw4ci4ryACtP7CN8Uq9fuLSAn63avFn9fbvAse4LNtWS2t3B31rs/G
         kA5ACaYpGdz5Sz9k1rrhmgIxnLl8JIism6LrRpJandmQF92hdU+OZ9MzHv1PZXZRwYQ7
         8qO2cwSBkL+aTIB/SVEenU/f2PmzG8oUFhec2KMckgykN24tSG7omHE5+B7rJQUYcBpc
         sRldZAAQkprapfSNW6ALrXFN5sPbj0bSlzcnEx3SscFTGbgR/TaeQMeIcf/WzW00LSP4
         0z8g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1710977236; x=1711582036;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=sPZgtkKUNnMLZTZQ51rOdcahT/0Ce+aYAnGJPNyno6Y=;
        b=DhhtCuTF3QS5F3687lTczw7JamoNtTBNurnYxSVUQWr0fD3mIamoN5kVR1q7ASrY5Z
         NjRCSIu12xngIRD2MpAcEBosocPk0wZnRvtdFmRyBiYyA92Y7owJJFqSrhdR0OE3vQFj
         BHfsfto0a6zQcOiggPtBe9q/gCrJE9XR/zBi1/OTSVxL4GU7leTh+YPOE0cRoFi9gaRH
         43aYbUAdOKf9DJs7OlgtZZDb7AptzOAUEqos7lII/vvKjFm5bhsWVqIKGS7GUZG35l4n
         xYra/3De4his38AdgH6muw6ug1SsDWVvQZ83Dc9AfVu2BMS6abkdgFGcRPIM8tGJpXEw
         tlOw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXsnjC38IRMwM1qSqDVC5JJzLF3kYzAv2uniAwsIL8xZx2nLDF8dp3V+u6HYc7FBYlekv2oT1ZK4nrl3bxcBwdn64xqn1PotA==
X-Gm-Message-State: AOJu0YyiF6xjDHeB6t+LPJvfAm93+XzEsfLkGdjtF+c/3zc+xpXNI00V
	yjtVShK4fz/Upj64M+/UhOjwWJAJDeFP1/BlaCuA1DxQjfUce+qE
X-Google-Smtp-Source: AGHT+IHCj8fFDH/ZNRGT2VEjmR/kTeFgSNChS2YaDnF94Zgsa4WsQew9Hql2V3sSg0RDK+5RqoLIXg==
X-Received: by 2002:a05:6e02:2164:b0:366:d124:cbe7 with SMTP id s4-20020a056e02216400b00366d124cbe7mr4340626ilv.31.1710977235930;
        Wed, 20 Mar 2024 16:27:15 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:1e09:b0:366:c618:133 with SMTP id
 g9-20020a056e021e0900b00366c6180133ls323357ila.2.-pod-prod-07-us; Wed, 20 Mar
 2024 16:27:15 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCU4IC5+4kp2PwBfOW93SqBHS9eaZZqAdrYt3Ve3FbojF/hoRURT4hFxN/IhCIUSvVEJjpgE4Tsi5WeG9qbA2OL1Ysu63U8TNPN4Qg==
X-Received: by 2002:a6b:e012:0:b0:7cc:ce24:795b with SMTP id z18-20020a6be012000000b007ccce24795bmr3403152iog.8.1710977235113;
        Wed, 20 Mar 2024 16:27:15 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1710977235; cv=none;
        d=google.com; s=arc-20160816;
        b=mviSrgdeQ7PbIiCnDhWxkj3oBvrV2TcgBcji16zdhuRsnBUm0rK9l15UZEjyyucaWO
         1PLGhCqo/jZkuqx5P/fHmrJXlVFCC8Vii78xUy3ThOeAvpNEdBhCnf17IxhvWE30OeKt
         x2xz9yH5c0+SCk70CUNNXMNiAWP1cO6bTFZV42DHdSlXX3tUGbM4UwA83V64dKqW55lu
         /1FVx4SYtDhEB+7tpXd6XF/ChQmHp6WjkHJm38LfAB1XbzJQGv5ImGkWx2g/lP+/eQSH
         3v3mnSYAc7lFH4+wX7g4yCfbouAbr8BPmo/PhJwoj6oY5FZT1A2aHo7r76Ykis/ugbjV
         N0Ig==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=q6wHVvQOpEVBe9GN/RDfS0/7UHobpz6yHjFxam80y4A=;
        fh=Qw58T0j2EoJr6GftT3I6uEdd1gDMRhNwCblchoqhp4I=;
        b=lFW8ECWK2vNrEkTp021pViwMS+nErYYY99ys7Eq4hbS72VsJ33FeifrhBelyyV1ulD
         ct4EihpHRVK7j5wViBZrLovB+f1Ow3BMyd4pCsRnj+Yqi4FGIqiP8rzAM1o3S8pZ4wQN
         Tb3jy6xQoti9xRoZe/qTi0M1zgTvB1FQjbd0v7NSx0McDgAZ011QV4CT5rbfeBDzUY5i
         4JL5r35mBi11iehL3qU2XYl8TTuglRetLDHp4zmxvB+dc99LnwrO1E09ZRl9VVSPjQJJ
         T4u7Rfu8qmjXAp18jOjMA4iU9mcVGH4drI8zmvmj+pNvY6mugka7rJ2dnVSEucp8Vaur
         17Ww==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@rivosinc-com.20230601.gappssmtp.com header.s=20230601 header.b=qvzmqyfO;
       spf=pass (google.com: domain of debug@rivosinc.com designates 2607:f8b0:4864:20::1133 as permitted sender) smtp.mailfrom=debug@rivosinc.com
Received: from mail-yw1-x1133.google.com (mail-yw1-x1133.google.com. [2607:f8b0:4864:20::1133])
        by gmr-mx.google.com with ESMTPS id d63-20020a6bcd42000000b007cc83e09d3asi672956iog.2.2024.03.20.16.27.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 20 Mar 2024 16:27:15 -0700 (PDT)
Received-SPF: pass (google.com: domain of debug@rivosinc.com designates 2607:f8b0:4864:20::1133 as permitted sender) client-ip=2607:f8b0:4864:20::1133;
Received: by mail-yw1-x1133.google.com with SMTP id 00721157ae682-609fb0450d8so3840187b3.0
        for <kasan-dev@googlegroups.com>; Wed, 20 Mar 2024 16:27:15 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWHwTJcjgRB16GzUQkOvdjtSED6KWOYC0jYf45WE4eb3GVwH+TfIDA8LdsZvRFzbx1giHQBEx/tMAet0b4ALSR16LKeZqXvlpBZFA==
X-Received: by 2002:a25:b847:0:b0:dc6:da83:88e6 with SMTP id
 b7-20020a25b847000000b00dc6da8388e6mr3262598ybm.32.1710977234540; Wed, 20 Mar
 2024 16:27:14 -0700 (PDT)
MIME-Version: 1.0
References: <20240319215915.832127-1-samuel.holland@sifive.com>
 <20240319215915.832127-6-samuel.holland@sifive.com> <CAKC1njSg9-hJo6hibcM9a-=FUmMWyR39QUYqQ1uwiWhpBZQb9A@mail.gmail.com>
 <40ab1ce5-8700-4a63-b182-1e864f6c9225@sifive.com> <17BE5F38AFE245E5.29196@lists.riscv.org>
In-Reply-To: <17BE5F38AFE245E5.29196@lists.riscv.org>
From: Deepak Gupta <debug@rivosinc.com>
Date: Wed, 20 Mar 2024 16:27:03 -0700
Message-ID: <CAKC1njTnheUHs44qUE2sTdr4N=pwUiOc2H1VEMYzYM84JMwe9w@mail.gmail.com>
Subject: Re: [RISC-V] [tech-j-ext] [RFC PATCH 5/9] riscv: Split per-CPU and
 per-thread envcfg bits
To: debug@rivosinc.com
Cc: Samuel Holland <samuel.holland@sifive.com>, Palmer Dabbelt <palmer@dabbelt.com>, 
	linux-riscv@lists.infradead.org, devicetree@vger.kernel.org, 
	Catalin Marinas <catalin.marinas@arm.com>, linux-kernel@vger.kernel.org, 
	tech-j-ext@lists.risc-v.org, Conor Dooley <conor@kernel.org>, kasan-dev@googlegroups.com, 
	Evgenii Stepanov <eugenis@google.com>, 
	Krzysztof Kozlowski <krzysztof.kozlowski+dt@linaro.org>, Rob Herring <robh+dt@kernel.org>, 
	Andrew Jones <ajones@ventanamicro.com>, Guo Ren <guoren@kernel.org>, 
	Heiko Stuebner <heiko@sntech.de>, Paul Walmsley <paul.walmsley@sifive.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: debug@rivosinc.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@rivosinc-com.20230601.gappssmtp.com header.s=20230601
 header.b=qvzmqyfO;       spf=pass (google.com: domain of debug@rivosinc.com
 designates 2607:f8b0:4864:20::1133 as permitted sender) smtp.mailfrom=debug@rivosinc.com
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

> > >
> > > And instead of context switching in `_switch_to`,
> > > In `entry.S` pick up `envcfg` from `thread_info` and write it into CSR.
> >
> > The immediate reason is that writing envcfg in ret_from_exception() adds cycles
> > to every IRQ and system call exit, even though most of them will not change the
> > envcfg value. This is especially the case when returning from an IRQ/exception
> > back to S-mode, since envcfg has zero effect there.
> >
> > The CSRs that are read/written in entry.S are generally those where the value
> > can be updated by hardware, as part of taking an exception. But envcfg never
> > changes on its own. The kernel knows exactly when its value will change, and
> > those places are:
> >
> >  1) Task switch, i.e. switch_to()
> >  2) execve(), i.e. start_thread() or flush_thread()
> >  3) A system call that specifically affects a feature controlled by envcfg
>
> Yeah I was optimizing for a single place to write instead of
> sprinkling at multiple places.
> But I see your argument. That's fine.
>

Because this is RFC and we are discussing it. I thought a little bit
more about this.

If we were to go with the above approach that essentially requires
whenever a envcfg bit changes, `sync_envcfg`
has to be called to reflect the correct value.

What if some of these features enable/disable are exposed to `ptrace`
(gdb, etc use cases) for enable/disable.
How will syncing work then ?

I can see the reasoning behind saving some cycles during trap return.
But `senvcfg` is not actually a user state, it
controls the execution environment configuration for user mode. I
think the best place for this CSR to be written is
trap return and writing at a single place from a single image on stack
reduces chances of bugs and errors. And allows
`senvcfg` features to be exposed to other kernel flows (like `ptrace`)

We can figure out ways on how to optimize in trap return path to avoid
writing it if we entered and exiting on the same
task.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAKC1njTnheUHs44qUE2sTdr4N%3DpwUiOc2H1VEMYzYM84JMwe9w%40mail.gmail.com.
