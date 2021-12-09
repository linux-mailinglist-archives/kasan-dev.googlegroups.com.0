Return-Path: <kasan-dev+bncBCQ2XPNX7EOBBPHEZGGQMGQE4WU3EYA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43f.google.com (mail-wr1-x43f.google.com [IPv6:2a00:1450:4864:20::43f])
	by mail.lfdr.de (Postfix) with ESMTPS id EEE0B46F5CA
	for <lists+kasan-dev@lfdr.de>; Thu,  9 Dec 2021 22:16:44 +0100 (CET)
Received: by mail-wr1-x43f.google.com with SMTP id x17-20020a5d6511000000b0019838caab88sf1832082wru.6
        for <lists+kasan-dev@lfdr.de>; Thu, 09 Dec 2021 13:16:44 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1639084604; cv=pass;
        d=google.com; s=arc-20160816;
        b=kMolkA4ZvHc3zIdT14Z0oPLQPiRAECk6K8CcBZA0hMc8GVlti1sTnLEf95eqKKUIFp
         5FSpXnmmInoFmjwWqlXoKA5qYzeTN8EVEQwz4pzxnfCLKe92mxoPga8q47LWri0Lts0h
         A0RgsqRY1ih3MFIjWc7soJ3t8Co5m4XdIuuEAy1IYAKuYQiywW+B8U3pBz3lv9yQOuBE
         hv+WwOn1Y4zchiKrRCgRGs+aqLCyG4PK/K5+Vb/w/TZkxy6yKAzHhuxbBL+SIR/xMEMl
         jh+E0nqPf9+T+q8ecMOxaYiKmsMMP/R3Zs+rKWehf8Qz+ckWoDZoTUXXAWmMswgvFeYe
         Kgdg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=WZ7sY1tRChbinLfR45Yw71boay5i02akVutS1q2leSU=;
        b=fEF9e9DGQxY6Ue58U29KTf+mUPIMHccFykDj9p67Xl77dEdG+ax2HSN3Kd9R4qid8M
         eov2UMc6WJb5vm3PpOckg9Y2jX78o5ekF2Pi8cLVjbSCspUpAvm649xYHhwdgntgqTVV
         X2Vd6wmjTUs6MVaD2oUzxvlwc/bB73zeVPcNG6Qcm3PU+iqy0YpgIz6OZ0x9gjJvI/Xd
         k4Is6UHzqUNg4Bo91Toc+MOW+EWyjDzW8GKqx63RDbi1IHY0MWqfvxhHz6JbFvm5UWGY
         v+e1GAdEHuC6MCBX/VP18GhKJCX10iWlN+h/gfmm0ug4cn3p5y+mP7x+6o+DCLLin6MF
         aV8w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=g4y37LIT;
       spf=pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::12b as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=WZ7sY1tRChbinLfR45Yw71boay5i02akVutS1q2leSU=;
        b=t3HARXYRSVYmYD/56+iSkp8kqIT2pLY4BiTWOai6Sx6Uu3MngM2T6uimQAHM0VYmMo
         gwk2P4v3pktFXV7Qu+ebh9Dckl11A3HMfyZo7xdLn+V77VUv7vPcywT4VBC2l3vKqcEM
         1jCtrgAnAR2to6ddG/9j1Wri66+s2as/vpxjwpUmI1ybwH6GCMGg0OmODKssQ+gExm0g
         VKjTQv//y1OxHZtpWjevRVJFS1QoAowF4v/30QiAWFlHjG21jJHtYICK/S9YRxvV//rP
         s95s6/2Rd1CkA7S0iN9Hw3FbfujS9uOg28qPEoZ15XTpEsSI8B1ZyJ4nep4hcuGtISjB
         84IA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=WZ7sY1tRChbinLfR45Yw71boay5i02akVutS1q2leSU=;
        b=zevFU+otwtcNtUKZf5s1rImjm/n95FmABNw43eRHP8dVvcFO9OecTL3dZBXUh8htB8
         42/FZEGSk3wvhxLE/co5RLSNl+I3VCEqLovUk2NtnKExEEf24dlBwXjeW+kKhYVRUHXf
         wenRWenNPVu/c0zMbArcOuzfIApf1hz7yICaNkk+fvZlHsdhBQ93ZUcb9HfiTib3IhZk
         l0I2xjbHZPrLEsngRjmOdDVnj2wptWpWb3C6bW2e1MAsy//FPpGPu7fkLKxiWYtWlLL8
         M/1X9HLo9ihwy2gStNo/9ReDmS8gojr5Mw8ssU0NcqUW4wVL/NNYLjqv48r8QFFbFCF1
         gAjg==
X-Gm-Message-State: AOAM531uBSYnijMUHsonjrcbNOVg/isXzkCuaIaEiPooBbyoxjbYwSP6
	rs8sNbcWce2LhU+B7LuZ3UQ=
X-Google-Smtp-Source: ABdhPJz2qPEokdkoKennjeGJO5Dh3mOYqRNAK+LTcQv8k5p00tTXB4FYd/XQRB0/nLI0Yu+Snkeljg==
X-Received: by 2002:a1c:7517:: with SMTP id o23mr10359277wmc.172.1639084604608;
        Thu, 09 Dec 2021 13:16:44 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:4092:: with SMTP id o18ls10080wrp.1.gmail; Thu, 09 Dec
 2021 13:16:43 -0800 (PST)
X-Received: by 2002:adf:edc1:: with SMTP id v1mr9480705wro.170.1639084603670;
        Thu, 09 Dec 2021 13:16:43 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1639084603; cv=none;
        d=google.com; s=arc-20160816;
        b=M3cQw9iLxQhCEfw9szZe+B1dIGPBMwGbvWN1FiKw/fNZsRWx59BuAvXS/74w3j+YRL
         FEIhvlmMzumw48lAAPEkWlLHy5nEFTK+crFXLSfsyqMdNa4bhIlrHh0laOZCZP6hnXyN
         b3/bK+eoegP8Wjv49L9b9Dum8DRowC/zp4WFduwAe2/bShH3mjbCBnSQb7ZGP6967F09
         bn+EScUdi1iR5HQGnzJFiMEqXN/CZrPzLBME9Mu7zQkj8tsRAEDTFKCK5ioY40ORyZ13
         9MI7JXgDzKshFINGgzrd2EQ7Nbr8ScSHpdr76bK5UuoGsqmdGwnkCm+yCdE46dh3radc
         CWPQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=n/PRQqohZJZoWPfeAL4/gTv4y1kA/vUHTgUSzu+kjUk=;
        b=cqpgazEUSvxXOAglPBB52KXMcizueoIVWbhUAcXd5xEUeftfnykG+JBdDFoe6cFEqs
         kwPAx/wWG8AGeSYn/mhto1lGPGzNbq0vqJjz+W/LKYOAf1wl7RVvgMZEsojbzgdOz6/a
         tnXxS6neuSlcaVjGWZI2VC0vIYbul5HBaPP4Stkt91tHAsmO8ApndCzxzeuwh7Vzn/7U
         hDNELjj8NxKmnEY2h1jth/U7Vd/98lKHnh6PsWQgS56yejjiVTj7ThrOiTk7sI8gLmw8
         8PqeoQbk6COIpCFy/t5rdvoKzcI0cUUYNuK9n/gDglshYgLIvtHt1d6NLMxhPGdg5713
         JE+Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=g4y37LIT;
       spf=pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::12b as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-lf1-x12b.google.com (mail-lf1-x12b.google.com. [2a00:1450:4864:20::12b])
        by gmr-mx.google.com with ESMTPS id q74si786522wme.0.2021.12.09.13.16.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 09 Dec 2021 13:16:43 -0800 (PST)
Received-SPF: pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::12b as permitted sender) client-ip=2a00:1450:4864:20::12b;
Received: by mail-lf1-x12b.google.com with SMTP id m6so2657627lfu.1
        for <kasan-dev@googlegroups.com>; Thu, 09 Dec 2021 13:16:43 -0800 (PST)
X-Received: by 2002:ac2:418f:: with SMTP id z15mr7863545lfh.213.1639084602937;
 Thu, 09 Dec 2021 13:16:42 -0800 (PST)
MIME-Version: 1.0
References: <YbHTKUjEejZCLyhX@elver.google.com>
In-Reply-To: <YbHTKUjEejZCLyhX@elver.google.com>
From: "'Jann Horn' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 9 Dec 2021 22:16:16 +0100
Message-ID: <CAG48ez0dZwigkLHVWvNS6Cg-7bL4GoCMULyQzWteUv4zZ=OnWQ@mail.gmail.com>
Subject: Re: randomize_kstack: To init or not to init?
To: Marco Elver <elver@google.com>, Peter Zijlstra <peterz@infradead.org>, 
	Alexander Potapenko <glider@google.com>
Cc: Kees Cook <keescook@chromium.org>, Thomas Gleixner <tglx@linutronix.de>, 
	Nathan Chancellor <nathan@kernel.org>, Nick Desaulniers <ndesaulniers@google.com>, 
	Elena Reshetova <elena.reshetova@intel.com>, Mark Rutland <mark.rutland@arm.com>, 
	Peter Collingbourne <pcc@google.com>, kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, 
	llvm@lists.linux.dev, linux-toolchains@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: jannh@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=g4y37LIT;       spf=pass
 (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::12b as
 permitted sender) smtp.mailfrom=jannh@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Jann Horn <jannh@google.com>
Reply-To: Jann Horn <jannh@google.com>
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

On Thu, Dec 9, 2021 at 10:58 AM Marco Elver <elver@google.com> wrote:
> Clang supports CONFIG_INIT_STACK_ALL_ZERO, which appears to be the
> default since dcb7c0b9461c2, which is why this came on my radar. And
> Clang also performs auto-init of allocas when auto-init is on
> (https://reviews.llvm.org/D60548), with no way to skip. As far as I'm
> aware, GCC 12's upcoming -ftrivial-auto-var-init= doesn't yet auto-init
> allocas.
>
> add_random_kstack_offset() uses __builtin_alloca() to add a stack
> offset. This means, when CONFIG_INIT_STACK_ALL_{ZERO,PATTERN} is
> enabled, add_random_kstack_offset() will auto-init that unused portion
> of the stack used to add an offset.
>
> There are several problems with this:
>
>         1. These offsets can be as large as 1023 bytes. Performing
>            memset() on them isn't exactly cheap, and this is done on
>            every syscall entry.
>
>         2. Architectures adding add_random_kstack_offset() to syscall
>            entry implemented in C require them to be 'noinstr' (e.g. see
>            x86 and s390). The potential problem here is that a call to
>            memset may occur, which is not noinstr.

This doesn't just affect alloca(), right? According to godbolt.org
(https://godbolt.org/z/jYrWEx7o8):

void bar(char *p);
void foo() {
  char arr[512];
  bar(arr);
}

when compiled with "-ftrivial-auto-var-init=pattern -O2 -mno-sse"
gives this result:

foo:                                    # @foo
        push    rbx
        sub     rsp, 512
        mov     rbx, rsp
        mov     edx, 512
        mov     rdi, rbx
        mov     esi, 170
        call    memset@PLT
        mov     rdi, rbx
        call    bar
        add     rsp, 512
        pop     rbx
        ret

So I think to fix this properly in a way that doesn't conflict with
noinstr validation, I think you'll have to add a compiler flag that
lets you specify a noinstr-safe replacement for memset() that should
be used here?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAG48ez0dZwigkLHVWvNS6Cg-7bL4GoCMULyQzWteUv4zZ%3DOnWQ%40mail.gmail.com.
