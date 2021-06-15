Return-Path: <kasan-dev+bncBDEZDPVRZMARB34AUSDAMGQECUKMN4I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3f.google.com (mail-yb1-xb3f.google.com [IPv6:2607:f8b0:4864:20::b3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 64F173A898F
	for <lists+kasan-dev@lfdr.de>; Tue, 15 Jun 2021 21:33:05 +0200 (CEST)
Received: by mail-yb1-xb3f.google.com with SMTP id m205-20020a25d4d60000b029052a8de1fe41sf21361716ybf.23
        for <lists+kasan-dev@lfdr.de>; Tue, 15 Jun 2021 12:33:05 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1623785584; cv=pass;
        d=google.com; s=arc-20160816;
        b=GkQcXOq4qugGCHL76aqWK8itjuqLBOuOVHaqOH3LHKQnMGf57mQVK0XwXvgFNzbzUl
         P3w7UUWp1SDtks6vAm2m1YfNlg5HqQB8UbLRxiy5iN42kqJUpOF5gF8EQBfpYOe9/Sxx
         DFBQ7osM6pjNdLlDd3eDsbVpUJp4aqH2+TMdoNLgqYU5AE3MZgXPysviTQ5NyymOehbd
         8JIy5cjOzpfwhAPfaEP1M3kVGN884UsSFN0CnUlVxskiWhCuBEz+Bellx2VC0oedQKQc
         2WVG6MkwgXvq2zAk5AFqXdKhE3QMmI/fuUY1E2LPoHM8WDjDVCYYyHysxys4XYX2MMBc
         rx7A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=zaNxO2SkS/3HjViVpb9W93NnKDSVZPxYbzsIrku6Tps=;
        b=DyNYP+0rMz1uhelVjCy8y04OPtCl7S9QHlTjRkkhXbap9/Clpr19RL4EdAmQi3mT3n
         Zh9R4uZLWQYPuaXb/nuNkrSYLBng0g5WoGKUAvfrLmTaPxIkA6r0sO63fZUtLDsDCerQ
         8Ffeqpqs87RN8VTBy6+MO6fkIkAd29PiR+MhyESmulf441YhrV3zGMlqTihY6mzz1a66
         jJ20DOOTWIjCj2ya4rrLevRiU5LVMi3MwmSLF2rFpbagSS6GKQhqOrWUCh1jfmPglrTq
         iz5gMpnnNFssQ1GDvn4v5QqA05YszTNuA0jml2moi1Z7hkT9P1c+wZz1KDgYUjwenQtq
         l8rw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=s+556g9O;
       spf=pass (google.com: domain of ebiggers@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=ebiggers@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=zaNxO2SkS/3HjViVpb9W93NnKDSVZPxYbzsIrku6Tps=;
        b=JVu9XjugAYfy/IbMCg4qpFb/8HyXrbcLaVbiVPNQiKynmuKBHWWjZOTqJacjkjNl52
         AaCXxmXtlsTvdWwN77OoX/DQuhMzyJo/sDNgOYUSbZ5K35IXjJKtYRsdoq/r67JuZRCt
         hrKdCYjleUG+34zDY5MraEPPTZwN9IKquCVhLox8TZb8PAgatsdgLwLyLht2avqzLtsM
         lHq3Ci0PlDAZMPLIJebZU0RU+HbN1CZdPabMlaGJNUwj7bTMa/PBLhtoVYMe/khRWK+X
         o5OWskK93IGWBOijGSZjhjOGo/N/CsdEWgf7/CJwN5AdfnGSqMQDbgj4+kPqsyuNacBi
         My2w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=zaNxO2SkS/3HjViVpb9W93NnKDSVZPxYbzsIrku6Tps=;
        b=eQ6vmKPcJer0LqsSdFcdf5QDVrZrAQQBajq2DuA/EtBrDVIUaqRHlru/H3Y9Xrzrhp
         d2JVoT+9xtmhpzvG/M7kLT5fLkyGb5NaUC0J5+OfWfby10OkE71PViXPJW/x1ZPDG18G
         vG3+9fIpqGG5bkemetKbCDUqM9ViuV29N9k60sagsKsyLhAiEdNnxUMIyluEVcvd2C4U
         K+fA3q/ijacrcWm1VDewRjEMm80TSNv5Vs9IcovNJiAniUNJm3YQiUskJt+/XBIIGULH
         7UQmGq73ETVmfyuZKik1AYtjDUQPmQU39F5SRBQJDbig2FB1pX0gymcKVa1d63J26K5Z
         irzQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530oFvbllmf19yVE9LBpQnuf4MI1KG+rFN7x43tlXV7baPMWdZZZ
	9E9BUZZgD57cdzIqoRFUMB8=
X-Google-Smtp-Source: ABdhPJxs5IRq2xr+8LjZr9jW00TWr5/fCd4Bl6fS0MtH/ObxVo6qe4GE8JgswjaOrE3b4KjGG39cbQ==
X-Received: by 2002:a25:d290:: with SMTP id j138mr1083915ybg.468.1623785583443;
        Tue, 15 Jun 2021 12:33:03 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6902:544:: with SMTP id z4ls16954ybs.3.gmail; Tue, 15
 Jun 2021 12:33:03 -0700 (PDT)
X-Received: by 2002:a25:764c:: with SMTP id r73mr1121759ybc.271.1623785582995;
        Tue, 15 Jun 2021 12:33:02 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1623785582; cv=none;
        d=google.com; s=arc-20160816;
        b=hAT7YcTUqqZjaw7Va3ODf2zHS5YaM8+33PIKc7nPMiNyHkOQpXdNMNJLlwmLD4U25Z
         lX5xtFhheQKQYSPFuIBp/8ANTXx96Pd/NiwQ8E86MU/dyaedPIynJUUd+LdXHQVJXv0e
         8MH7h05ZAIW7VS534DhTteCVEF8HXoeceBvM89Q+TCiS5nAR1l5xfhVRIUwrncV2C6h5
         BK14h/gPNDZIRTbaz3khWsvydCa2yPhUH5b5CkwdxnobcYh8lRq0WCCNA/U14XpcRpXV
         X2U/R9UboMKwi/vTXEuy5Mv8mKLwTY7S1/R31mMnSsXJDnDxFQTimEsLUIv0Qza7Qifs
         8Shw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=9o9cYCs0zHNio05ImrzjlAnZH3CFqgtE2kOdF5LazHs=;
        b=Yht0B5ik6VpoC/R4/tvWrvpwnsCJDvQXuuw5UhjDubLUswXjVfihze0Eua1ydwpHSO
         f9dsqx6zDHlfC+pW5RpLSuNo9d60pFy0ESrPqVM5eU5wMtPLj+lJY573YC/XV4mTIAjl
         IqpFLfEZI1EV3NDcYMf4+kAlhk0dfugVZe/rVGQRmEBnYBvG/t0cJCmcLQC5dtQPPMqQ
         KPlA0y1Pa96atRnv7hsqc6YMOD8sc0lFBtjTiB4ZZKHXbzDCSCIMGyPfYnxnHr8iBGQy
         xAltQff/S55XD+D4C1hRyf1EmPO2KRlNYulVr6iKJ7c3j23ArCziCrvXoq6QGtdQoo8d
         8bxQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=s+556g9O;
       spf=pass (google.com: domain of ebiggers@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=ebiggers@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id c8si389860ybl.3.2021.06.15.12.33.02
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 15 Jun 2021 12:33:02 -0700 (PDT)
Received-SPF: pass (google.com: domain of ebiggers@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id 9A28D60E0C;
	Tue, 15 Jun 2021 19:33:01 +0000 (UTC)
Date: Tue, 15 Jun 2021 12:33:00 -0700
From: Eric Biggers <ebiggers@kernel.org>
To: Edward Cree <ecree.xilinx@gmail.com>
Cc: Kurt Manucredo <fuzzybritches0@gmail.com>,
	syzbot+bed360704c521841c85d@syzkaller.appspotmail.com,
	keescook@chromium.org, yhs@fb.com, dvyukov@google.com,
	andrii@kernel.org, ast@kernel.org, bpf@vger.kernel.org,
	daniel@iogearbox.net, davem@davemloft.net, hawk@kernel.org,
	john.fastabend@gmail.com, kafai@fb.com, kpsingh@kernel.org,
	kuba@kernel.org, linux-kernel@vger.kernel.org,
	netdev@vger.kernel.org, songliubraving@fb.com,
	syzkaller-bugs@googlegroups.com, nathan@kernel.org,
	ndesaulniers@google.com, clang-built-linux@googlegroups.com,
	kernel-hardening@lists.openwall.com, kasan-dev@googlegroups.com
Subject: Re: [PATCH v5] bpf: core: fix shift-out-of-bounds in ___bpf_prog_run
Message-ID: <YMkAbNQiIBbhD7+P@gmail.com>
References: <CAADnVQKexxZQw0yK_7rmFOdaYabaFpi2EmF6RGs5bXvFHtUQaA@mail.gmail.com>
 <CACT4Y+b=si6NCx=nRHKm_pziXnVMmLo-eSuRajsxmx5+Hy_ycg@mail.gmail.com>
 <202106091119.84A88B6FE7@keescook>
 <752cb1ad-a0b1-92b7-4c49-bbb42fdecdbe@fb.com>
 <CACT4Y+a592rxFmNgJgk2zwqBE8EqW1ey9SjF_-U3z6gt3Yc=oA@mail.gmail.com>
 <1aaa2408-94b9-a1e6-beff-7523b66fe73d@fb.com>
 <202106101002.DF8C7EF@keescook>
 <CAADnVQKMwKYgthoQV4RmGpZm9Hm-=wH3DoaNqs=UZRmJKefwGw@mail.gmail.com>
 <85536-177443-curtm@phaethon>
 <bac16d8d-c174-bdc4-91bd-bfa62b410190@gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <bac16d8d-c174-bdc4-91bd-bfa62b410190@gmail.com>
X-Original-Sender: ebiggers@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=s+556g9O;       spf=pass
 (google.com: domain of ebiggers@kernel.org designates 198.145.29.99 as
 permitted sender) smtp.mailfrom=ebiggers@kernel.org;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=kernel.org
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

On Tue, Jun 15, 2021 at 07:51:07PM +0100, Edward Cree wrote:
> 
> As I understand it, the UBSAN report is coming from the eBPF interpreter,
>  which is the *slow path* and indeed on many production systems is
>  compiled out for hardening reasons (CONFIG_BPF_JIT_ALWAYS_ON).
> Perhaps a better approach to the fix would be to change the interpreter
>  to compute "DST = DST << (SRC & 63);" (and similar for other shifts and
>  bitnesses), thus matching the behaviour of most chips' shift opcodes.
> This would shut up UBSAN, without affecting JIT code generation.
> 

Yes, I suggested that last week
(https://lkml.kernel.org/netdev/YMJvbGEz0xu9JU9D@gmail.com).  The AND will even
get optimized out when compiling for most CPUs.

- Eric

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YMkAbNQiIBbhD7%2BP%40gmail.com.
