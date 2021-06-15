Return-Path: <kasan-dev+bncBCOLPU5Q4MDBBHXNUODAMGQENDM4L7Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33a.google.com (mail-wm1-x33a.google.com [IPv6:2a00:1450:4864:20::33a])
	by mail.lfdr.de (Postfix) with ESMTPS id EB12B3A88DD
	for <lists+kasan-dev@lfdr.de>; Tue, 15 Jun 2021 20:51:10 +0200 (CEST)
Received: by mail-wm1-x33a.google.com with SMTP id u17-20020a05600c19d1b02901af4c4deac5sf136886wmq.7
        for <lists+kasan-dev@lfdr.de>; Tue, 15 Jun 2021 11:51:10 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1623783070; cv=pass;
        d=google.com; s=arc-20160816;
        b=GPNhCjQS9Kc1csBk916roPb74aP4qbNN2mSO/NlcDmFlEsgnBKSTV1cJlvp0nmKq6M
         KAWzdu4pSwRAmykvbClz/J0AbplaI17RNjGM+9MAyLKM5qOOufXsq/TTc1vd+o206pN7
         jImAvAlVHCXmTxC2oYy+sBIS5ff9CKZZDEs9zGsG5VhO8BxzBXRN6C3ROQ5KP3bzIXpW
         lLK/AHS8cGN5OiKGQ/Bkc/f7FAIg+NdmOjV+RG+TiZayuoHOkccN6c3zhH74ytz5IrzY
         MxUwmSYD2efOZ2xixp+wYvtPaC13cq2k0S91mUL8aWLMg9C39CSSGfnnvBj9KlO4cl93
         qawQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature:dkim-signature;
        bh=Si4mNZvRO956+P6DUwMefc1RV5PHI9F9ZXYWF3RePoA=;
        b=tSI4bQTn06qpqdM5OZZgP9zLc82EVzjNvw+5dLKXvsDPDdIeLLnBdV16f4mpQCvQvd
         vFHdofJOX62G2g4L/1ktXJifSMw1cfyMVwdcqF3njVNnX99LeH7i545ut6fVL8E3zcdg
         7LBtz/moLtMdkXjKE5yIz3WgLUveK/9abHgqzxFJUe1IqlxYLmVJd8YGH1DFA5jkcjyi
         e2Dfa1Bky0v8elXXAmxmHhPZuCFDX6XuJ/4di5PfJ3BpLXXAzfa+AefIK18317wFiYw8
         LePep6htPLeDDKgLbBlNhq8pk7sQobhaRfH2d5VohURzpPmvMrCgAxujw1pNmbO+tLZ9
         4UeQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=keYPy5Ik;
       spf=pass (google.com: domain of ecree.xilinx@gmail.com designates 2a00:1450:4864:20::42d as permitted sender) smtp.mailfrom=ecree.xilinx@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=Si4mNZvRO956+P6DUwMefc1RV5PHI9F9ZXYWF3RePoA=;
        b=e7NmRkPi6WKjoocVJEzEmlT2OfQJ6ICiUTJN28cKinW//W13hOv1UhYjbJXDV/nhJv
         KfMPUwBD+lTAvusyMyjkD0QUyHxe3F2lHga7vic+pS+BB4c04AwTJiOTe5qdrRHT09Rd
         yuC4dmlMqJLl5dGsGsAUhQL1PwkDHhId4K+gWVF786y+79TAaCz/2ldLpEQYYtQ7Gmh7
         n4O9IMpIIwEuDMD46+96pBYD1jSeeEBCkZUYPdOGGybfdzueNHq0FhdJ172uphCB0Cij
         RY2VESOTtbbDEVKavTtf3GS2/e5GUD5qWBciGJ/xKESc8LO3VCOl0pCrZO9+WpxHYTXT
         4MTA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=Si4mNZvRO956+P6DUwMefc1RV5PHI9F9ZXYWF3RePoA=;
        b=elRVrOr1BIrZdbUPUkcrZqFsQwzS4iQaki6c+OJsI0h/6FT9SAARYmrjnFL2ysD72A
         UynIA+kAbf9dPGU1PM1luGV/s/1/HJke8qi5F7RDMfX5P1makzGHTWpdH4xRF6eVZmY9
         hBGwX8giNM1s259TEZ2p6BZWyDi+JewA+vca7eohboGiV3pNhThXwoWdFzxhfMn7G9tA
         HciOyV9LRt9sKNECf0DYhSG3JmLbqKodHvhwySUzPxcQVqzdO16QAczEdQMh2BHQ6ey+
         rl766iRasGqvnijSkk+iSTIav8oPc7Z05vPzOKCSlsSJ5P8GDOlzkBMoabWYikzdIaH/
         97Xg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=Si4mNZvRO956+P6DUwMefc1RV5PHI9F9ZXYWF3RePoA=;
        b=Dr0C2fd3KK5htwT6TqnQ9pdP5WcQ6xe+l3v5IEig7O2k1Z92qXZY1OHy2P1fPuNJmK
         4A9xXOh/mh4CA2yqb+ioV9FNuBPv1f2XTGZZ1SPzA/8UyP+/1ZeN9sMAie/Dx8L1DShv
         qWqsqyKSJ1VAKUMbdBLvVc2Do6R1xBPRDmNXtmSPDTBZ8jq8FKUTOmx270QX6ERLv5s2
         vPW1UyhAuhnY6KgiESk+k62gFTRHZIfeJmTw9XDy+eJYz1BAEsb7Su/IlvD7hWyjTNmp
         AKRHghg6plyIz9e9ge2BqAwCPv/j+UekfWKD0314wSFiaOT6aT0hW91NeBJetFmmeplD
         mRyw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5328HZ0iGB+6yRHkRE/2i2Z5ZkwuK4e4vkhO5if54mY1dQS3zXuG
	PyIdusk3uEw3pePhCrJZekk=
X-Google-Smtp-Source: ABdhPJzzyDuUqfhTh9m3a/NX94h4SdL3x93+1DTfLABWggkrlvdRFm8hVm5gRJ1uzF97SAw4r9GiJQ==
X-Received: by 2002:a05:600c:190f:: with SMTP id j15mr766292wmq.37.1623783070688;
        Tue, 15 Jun 2021 11:51:10 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:45c9:: with SMTP id b9ls1418430wrs.1.gmail; Tue, 15 Jun
 2021 11:51:09 -0700 (PDT)
X-Received: by 2002:a5d:6584:: with SMTP id q4mr620018wru.230.1623783069747;
        Tue, 15 Jun 2021 11:51:09 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1623783069; cv=none;
        d=google.com; s=arc-20160816;
        b=Pl8SeJp2GyYPrsGZcebIfwi3Km88EVKafLG14GdvsvO0/gGamBhlMJV6UxYvSx+ZtS
         N8jBq0loCFDv6xwwH0K0CwopW7RSx+heQghNLj3ykrhokqbJRE2GiNu99YhtMC+4jDKH
         qzWC8IfJZkIqxDblPfTuF3Kf5CayjRNtirqSBuaCPktAH4HnuuEfRwwU4w3n6l9MPc0I
         XxwKH3EvEnzpQyIzOu3nGTUqDoX6VH+X7Bj8GZWISxkxxvqfUZQ0Nnk6fxa6qJkUH94o
         NQ09xvLI2LQYAftjTbzJLeCZpIK9ikYOM5MhP1+HzCMPBo56xpYISOgtcvKl4gjJFz0l
         ZHzA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject
         :dkim-signature;
        bh=QojazdBWoM3SyAlRdVHgqcAEHJPhAD/lO190hYA/8jw=;
        b=cDZ813/chUSGF8OvVc0fc8mOw3qa/zj0k/65XL090BMtkQyb3hSNz4Sn2H054/mI7u
         sd7cEUK+nGlG1n6DoMXPm9GwTBhHTkl/89kUaIdfVOdrDHWasn3xKMKtosZKsHXRseKi
         fg0Dljw5o61T0vhf+O19VwL61JefzHPrzYzd4oNclOBaBcu+c+xRoYDjgScedumOaIAB
         T/Z5wvmFAJ+gCgMUPyMak6xx6q9a8f7RNn9CsH6V7bKGbzNMgbjta57DZPuMaGtUm7w9
         u//UupzENjNHva/vObqiRiEgZEW1pkxg3N2JJdTwFyzpNuUSJIKTRcasTh3BLgHQlZsN
         WphA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=keYPy5Ik;
       spf=pass (google.com: domain of ecree.xilinx@gmail.com designates 2a00:1450:4864:20::42d as permitted sender) smtp.mailfrom=ecree.xilinx@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-wr1-x42d.google.com (mail-wr1-x42d.google.com. [2a00:1450:4864:20::42d])
        by gmr-mx.google.com with ESMTPS id j15si125120wrb.3.2021.06.15.11.51.09
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 15 Jun 2021 11:51:09 -0700 (PDT)
Received-SPF: pass (google.com: domain of ecree.xilinx@gmail.com designates 2a00:1450:4864:20::42d as permitted sender) client-ip=2a00:1450:4864:20::42d;
Received: by mail-wr1-x42d.google.com with SMTP id m18so19406337wrv.2;
        Tue, 15 Jun 2021 11:51:09 -0700 (PDT)
X-Received: by 2002:a5d:658a:: with SMTP id q10mr618994wru.258.1623783069593;
        Tue, 15 Jun 2021 11:51:09 -0700 (PDT)
Received: from [192.168.1.122] (cpc159425-cmbg20-2-0-cust403.5-4.cable.virginm.net. [86.7.189.148])
        by smtp.gmail.com with ESMTPSA id v15sm2900252wmj.39.2021.06.15.11.51.08
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 15 Jun 2021 11:51:09 -0700 (PDT)
Subject: Re: [PATCH v5] bpf: core: fix shift-out-of-bounds in ___bpf_prog_run
To: Kurt Manucredo <fuzzybritches0@gmail.com>, ebiggers@kernel.org,
 syzbot+bed360704c521841c85d@syzkaller.appspotmail.com
Cc: keescook@chromium.org, yhs@fb.com, dvyukov@google.com, andrii@kernel.org,
 ast@kernel.org, bpf@vger.kernel.org, daniel@iogearbox.net,
 davem@davemloft.net, hawk@kernel.org, john.fastabend@gmail.com,
 kafai@fb.com, kpsingh@kernel.org, kuba@kernel.org,
 linux-kernel@vger.kernel.org, netdev@vger.kernel.org, songliubraving@fb.com,
 syzkaller-bugs@googlegroups.com, nathan@kernel.org, ndesaulniers@google.com,
 clang-built-linux@googlegroups.com, kernel-hardening@lists.openwall.com,
 kasan-dev@googlegroups.com
References: <87609-531187-curtm@phaethon>
 <6a392b66-6f26-4532-d25f-6b09770ce366@fb.com>
 <CAADnVQKexxZQw0yK_7rmFOdaYabaFpi2EmF6RGs5bXvFHtUQaA@mail.gmail.com>
 <CACT4Y+b=si6NCx=nRHKm_pziXnVMmLo-eSuRajsxmx5+Hy_ycg@mail.gmail.com>
 <202106091119.84A88B6FE7@keescook>
 <752cb1ad-a0b1-92b7-4c49-bbb42fdecdbe@fb.com>
 <CACT4Y+a592rxFmNgJgk2zwqBE8EqW1ey9SjF_-U3z6gt3Yc=oA@mail.gmail.com>
 <1aaa2408-94b9-a1e6-beff-7523b66fe73d@fb.com> <202106101002.DF8C7EF@keescook>
 <CAADnVQKMwKYgthoQV4RmGpZm9Hm-=wH3DoaNqs=UZRmJKefwGw@mail.gmail.com>
 <85536-177443-curtm@phaethon>
From: Edward Cree <ecree.xilinx@gmail.com>
Message-ID: <bac16d8d-c174-bdc4-91bd-bfa62b410190@gmail.com>
Date: Tue, 15 Jun 2021 19:51:07 +0100
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101
 Thunderbird/78.5.0
MIME-Version: 1.0
In-Reply-To: <85536-177443-curtm@phaethon>
Content-Type: text/plain; charset="UTF-8"
Content-Language: en-GB
X-Original-Sender: ecree.xilinx@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=keYPy5Ik;       spf=pass
 (google.com: domain of ecree.xilinx@gmail.com designates 2a00:1450:4864:20::42d
 as permitted sender) smtp.mailfrom=ecree.xilinx@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On 15/06/2021 17:42, Kurt Manucredo wrote:
> Syzbot detects a shift-out-of-bounds in ___bpf_prog_run()
> kernel/bpf/core.c:1414:2.
> 
> The shift-out-of-bounds happens when we have BPF_X. This means we have
> to go the same way we go when we want to avoid a divide-by-zero. We do
> it in do_misc_fixups().

Shifts by more than insn_bitness are legal in the eBPF ISA; they are
 implementation-defined behaviour, rather than UB, and have been made
 legal for performance reasons.  Each of the JIT backends compiles the
 eBPF shift operations to machine instructions which produce
 implementation-defined results in such a case; the resulting contents
 of the register may be arbitrary but program behaviour as a whole
 remains defined.
Guard checks in the fast path (i.e. affecting JITted code) will thus
 not be accepted.
The case of division by zero is not truly analogous, as division
 instructions on many of the JIT-targeted architectures will raise a
 machine exception / fault on division by zero, whereas (to the best of
 my knowledge) none will do so on an out-of-bounds shift.
(That said, it would be possible to record from the verifier division
 instructions in the program which are known never to be passed zero as
 divisor, and eliding the fixup patch in those cases.  However, the
 extra complexity may not be worthwhile.)

As I understand it, the UBSAN report is coming from the eBPF interpreter,
 which is the *slow path* and indeed on many production systems is
 compiled out for hardening reasons (CONFIG_BPF_JIT_ALWAYS_ON).
Perhaps a better approach to the fix would be to change the interpreter
 to compute "DST = DST << (SRC & 63);" (and similar for other shifts and
 bitnesses), thus matching the behaviour of most chips' shift opcodes.
This would shut up UBSAN, without affecting JIT code generation.

-ed

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bac16d8d-c174-bdc4-91bd-bfa62b410190%40gmail.com.
