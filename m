Return-Path: <kasan-dev+bncBC7OBJGL2MHBBZ4DSCPQMGQEFFOP7DA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x240.google.com (mail-oi1-x240.google.com [IPv6:2607:f8b0:4864:20::240])
	by mail.lfdr.de (Postfix) with ESMTPS id 47E9768F89B
	for <lists+kasan-dev@lfdr.de>; Wed,  8 Feb 2023 21:11:21 +0100 (CET)
Received: by mail-oi1-x240.google.com with SMTP id o206-20020acad7d7000000b00375c9d6b919sf3990251oig.4
        for <lists+kasan-dev@lfdr.de>; Wed, 08 Feb 2023 12:11:21 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1675887079; cv=pass;
        d=google.com; s=arc-20160816;
        b=Sy7sDxhKtGjVTZxfBmuVLCXBTVYaGcBZ3CKBWIVUw8pYHx+FqkgmqGTC77QldJTEc8
         g+UIl9i48Nop04nMiEdS7QP1QD/bM0GPavn2YWpVMGhfRfAxiVLf+OHVNv16APeav50l
         GUtmnSIBCikYlhzKHRBVWZaoL9hIyxOrWH2CthU6jxt+Gtrd3CapL8AuAPXhNFm9lxjA
         rws0OwphQd65JiIEgbVda8iulPUIeqR4aHsMJwb/NgP0lHeF+jgZWXG0xjssBvfGsH7Q
         LxXcy1n7+8F+xFuwVX7qMpNODhUBd4G2frCVH6jsrj4SHIOT6e1rCjCK8K2cgnIBPqkM
         cE8A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=Y323ezPYrZSS/BZSZsEXRdBdf+qE8AVxq7GqQXRfyXQ=;
        b=KMYKh3OSY8DLJnQLY0sr7IcZDze7KEbWaFWz7GnjZGx/2yvF0fOojFhzMYCEErmakt
         zO5mMKv0e/qG96WVvpT63nN72KhAY+KOSCiC3rV1KVcJHr0EIIe7T/bGnYh1AWyu5nnE
         oXNMPK+mJbU6BuM3I+6rCj8lonYmnw38eQFvEkZ9ppRpp28jzpUZm0yEIUzbD93J2yTZ
         Sn1hPc6ZMRoKQ9NoWOOYWF6L9AkpUOTVUgBMFB0xhOUgc6sRlVUCu5QtYqTmEWGk67IZ
         ZyRwSel7uLUrm3kJEDYNPt9F952YLVAwdgwx+EsOuyOT+XweVMgj7LkEGcWJsz3pVlnH
         0uGw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=YRhnWSY5;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1131 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=Y323ezPYrZSS/BZSZsEXRdBdf+qE8AVxq7GqQXRfyXQ=;
        b=tTuBSOW3UvX8mDy49/mTy53XJ+01/s79R+vQyukhBX/K+smtd6qGJiy0WZT087j8R8
         n9ZRHVv/l/KmxjpAqa6cZrmxK/l0SXBkbkLYwQ8jOgy/TB2dFi7qDabPDCsvdf7hXC4w
         gwwYdozzAPdfLzNhEiqSVnuLI9HfOAFroSk3ECE8v76iVKj/55BTT/zEKDNLIHoaoG62
         puYlUF/Wk5k6skZJTsEzHYSNC6zTCw83CyCVxRSv6PD+HK9505CH0MUvwTRiJiFR147O
         uceaqUVZ26v/UipLvhRPwAdgSxtA2GTnSq4i5Ja/70PcUZx01otQkTOvlqReKvfRaNAU
         ghAw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=Y323ezPYrZSS/BZSZsEXRdBdf+qE8AVxq7GqQXRfyXQ=;
        b=O5lRW4IVa9VhStmgq3LFbirwOKFqR+l+cO/W4so2O80B9PIqWN1XRNBv9ArECe/ORy
         C5Bip1U5bk264UxhjSAfSRjuZ2oty61ORtnR62n6ekepsbMSbtWZiHDj4MFjqb5WtUIj
         /FN3/O6XXmnU+6Dm/G83i4dLbHLlm0erKoBkNJBgzF6cE8gHH6ZO1G4+akRSlb9fpwV4
         vhFekacQ97Scxhz2EGmFc5lEY85sKETK9DqbLls4pdWz2P82KrZ8G5wW7+H4JlyDiHys
         fwcWdVAII+ASBvQNc8qgapTPD5dcCP+qKRbmflLrc+zpNsrnvqfou49drtARvUKA+uQz
         TC5Q==
X-Gm-Message-State: AO0yUKXXK7C8BkOzzj7RnJQrqttr/AcLzcylW0Cj3QvE2PNMUVn5fP1i
	Gkes73noaOH00V59xetG65E=
X-Google-Smtp-Source: AK7set8zSZcGOOwl74dJ/+6g2MsY0WEi50I1Vv1Uoqzv+ZERUwY04Bcy+wFgT5jCkfrez955a8qOeA==
X-Received: by 2002:a05:6870:73d4:b0:15f:e289:9b7e with SMTP id a20-20020a05687073d400b0015fe2899b7emr773368oan.109.1675887079615;
        Wed, 08 Feb 2023 12:11:19 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:a687:0:b0:498:10f0:1c with SMTP id f7-20020a4aa687000000b0049810f0001cls1819oom.7.-pod-prod-gmail;
 Wed, 08 Feb 2023 12:11:17 -0800 (PST)
X-Received: by 2002:a4a:41c5:0:b0:51a:35de:d4c1 with SMTP id x188-20020a4a41c5000000b0051a35ded4c1mr4241546ooa.5.1675887077534;
        Wed, 08 Feb 2023 12:11:17 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1675887077; cv=none;
        d=google.com; s=arc-20160816;
        b=Nc1ge4LHIqUiRWiPlfm6C6c/X13sRbn7Q2t6uW0sWJo4XTsSC0TjU0eTZ6H9Lp78xB
         lutV25VOebFBToA9ZDy2v/llWYPN1/VSPK4ri4w+IOfBrgQf3wPqSm45RlnPRo3oRqm3
         lhcAjxppGU4gAK+j/kudgw5ybtmzhAk2pRhz4RQeUccq58sNyXjJpJ+BsfuTYD4DQM/q
         vqA3OAxaAL93tenfrd6rp5aHI8BbOEEVXHg0GhVsDzdDhnNFXLd3xpBz2yp24oMOgPrz
         q0GpXZriOPLAxvIA584A0ywd9HTO1NW7GCHXgtmnc70l/3KXsTn1Qv+K9aWA1HlgDjYS
         qcbw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=3ppZKTlZsbVsBTD7XLFZBK3GUbz0ywmkpoflVXVXaA8=;
        b=gNIv/gPvXQsvKpUGtXF38Ok2U//zygl3MPS5MnpcsSNgHW0CwzsNYXYPh0vhMb5yDN
         XZy4f5gtMh+HzANMExV4MTaysXciitFbLlmQgssnFU5CwANNQIRM7iG4DBDWtpkUM0Y7
         dKvkFFrdQBpmV6GR+zQkV4KvWhQ0Yyo1AJHmWMEkhrlpYaAM7C7z9INoDOZiQeZV6lZf
         gDSY6UvkxWOCp3QIdxzzjHyse6r7kOLcPlV80r7CdW8b40BTrO/D0YtiysKTTb3A/lSU
         39ZhkK3s9CRltJgHQIzGZLLC8Hc8LCrET8OuU7DuBd2GfLspMBEDKnaocV3z2emF5uiK
         KP0A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=YRhnWSY5;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1131 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x1131.google.com (mail-yw1-x1131.google.com. [2607:f8b0:4864:20::1131])
        by gmr-mx.google.com with ESMTPS id u17-20020a4ad0d1000000b004a399d01471si1384386oor.1.2023.02.08.12.11.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 08 Feb 2023 12:11:17 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1131 as permitted sender) client-ip=2607:f8b0:4864:20::1131;
Received: by mail-yw1-x1131.google.com with SMTP id 00721157ae682-52bee6d3380so29650097b3.2
        for <kasan-dev@googlegroups.com>; Wed, 08 Feb 2023 12:11:17 -0800 (PST)
X-Received: by 2002:a81:600a:0:b0:527:acf6:e0bf with SMTP id
 u10-20020a81600a000000b00527acf6e0bfmr1087733ywb.109.1675887076968; Wed, 08
 Feb 2023 12:11:16 -0800 (PST)
MIME-Version: 1.0
References: <20230208164011.2287122-1-arnd@kernel.org> <20230208164011.2287122-4-arnd@kernel.org>
 <CANpmjNN1nmjavBhj=xMMqAD1VScPySkdZbm2sTpWnKN1ZvmJcQ@mail.gmail.com> <c3da32e0-bfa9-415c-9970-e5506abb1a71@app.fastmail.com>
In-Reply-To: <c3da32e0-bfa9-415c-9970-e5506abb1a71@app.fastmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 8 Feb 2023 21:10:39 +0100
Message-ID: <CANpmjNNTUOfdjK_e5xWheqJgGBkD5e9_F15Vn0DECwtCwppDkw@mail.gmail.com>
Subject: Re: [PATCH 4/4] objtool: add UACCESS exceptions for __tsan_volatile_read/write
To: Arnd Bergmann <arnd@arndb.de>
Cc: Arnd Bergmann <arnd@kernel.org>, Josh Poimboeuf <jpoimboe@kernel.org>, 
	Peter Zijlstra <peterz@infradead.org>, Borislav Petkov <bp@suse.de>, Will Deacon <will@kernel.org>, 
	Thomas Gleixner <tglx@linutronix.de>, kasan-dev@googlegroups.com, 
	Dmitry Vyukov <dvyukov@google.com>, Alexander Potapenko <glider@google.com>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Miroslav Benes <mbenes@suse.cz>, 
	"Naveen N. Rao" <naveen.n.rao@linux.vnet.ibm.com>, Sathvika Vasireddy <sv@linux.ibm.com>, 
	linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=YRhnWSY5;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1131 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

On Wed, 8 Feb 2023 at 20:53, Arnd Bergmann <arnd@arndb.de> wrote:
>
> On Wed, Feb 8, 2023, at 17:59, Marco Elver wrote:
> > On Wed, 8 Feb 2023 at 17:40, Arnd Bergmann <arnd@kernel.org> wrote:
> >>
> >> From: Arnd Bergmann <arnd@arndb.de>
> >>
> >> A lot of the tsan helpers are already excempt from the UACCESS warnings,
> >> but some more functions were added that need the same thing:
> >>
> >> kernel/kcsan/core.o: warning: objtool: __tsan_volatile_read16+0x0: call to __tsan_unaligned_read16() with UACCESS enabled
> >> kernel/kcsan/core.o: warning: objtool: __tsan_volatile_write16+0x0: call to __tsan_unaligned_write16() with UACCESS enabled
> >> vmlinux.o: warning: objtool: __tsan_unaligned_volatile_read16+0x4: call to __tsan_unaligned_read16() with UACCESS enabled
> >> vmlinux.o: warning: objtool: __tsan_unaligned_volatile_write16+0x4: call to __tsan_unaligned_write16() with UACCESS enabled
> >
> > That's odd - this has never been needed, because all __tsan_unaligned
> > are aliases for the non-unaligned functions. And all those are in the
> > uaccess_safe_builtin list already.
> >
> > So if suddenly the alias name becomes the symbol that objtool sees, we
> > might need to add all the other functions as well.
> >
> > Is this a special build with a new compiler?
>
> I see this with gcc-12 and gcc-13 but not with clang-{14,15,16}, have
> not tried any older versions recently.
>
> What I see in the .s file for one of the affected configs is
>
>         .globl  __tsan_unaligned_read16
>         .set    __tsan_unaligned_read16,__tsan_read16
>         .p2align 6
>         .globl  __tsan_volatile_read16
>         .type   __tsan_volatile_read16, @function
> __tsan_volatile_read16:
>         endbr64
>         jmp     __tsan_read16   #
>         .size   __tsan_volatile_read16, .-__tsan_volatile_read16
>         .globl  __tsan_unaligned_volatile_read16
>         .set    __tsan_unaligned_volatile_read16,__tsan_volatile_read16
> ...
>         .set    __tsan_unaligned_write16,__tsan_write16
>         .p2align 6
>         .globl  __tsan_volatile_write16
>         .type   __tsan_volatile_write16, @function
> __tsan_volatile_write16:
>         endbr64
>         jmp     __tsan_write16  #
>         .size   __tsan_volatile_write16, .-__tsan_volatile_write16
>         .globl  __tsan_unaligned_volatile_write16
>         .set    __tsan_unaligned_volatile_write16,__tsan_volatile_write16
>
>
> In the object file that turns into:
>
> 0000000000004e80 <__tsan_unaligned_volatile_read16>:
>     4e80:       f3 0f 1e fa             endbr64
>     4e84:       e9 b7 fe ff ff          jmp    4d40 <__tsan_read16>
> ...
> 0000000000005000 <__tsan_unaligned_volatile_write16>:
>     5000:       f3 0f 1e fa             endbr64
>     5004:       e9 b7 fe ff ff          jmp    4ec0 <__tsan_unaligned_write16>
>
>
> It appears like it picks randomly between the original name
> and the alias here, no idea why. Using the clang integrated assembler
> to build the .o file from the gcc generated .s file shows the same
> code as
>
> 0000000000004e80 <__tsan_unaligned_volatile_read16>:
>     4e80:       f3 0f 1e fa             endbr64
>     4e84:       e9 00 00 00 00          jmp    4e89 <__tsan_unaligned_volatile_read16+0x9>
>                         4e85: R_X86_64_PLT32    __tsan_read16-0x4
> ...
> 0000000000005000 <__tsan_unaligned_volatile_write16>:
>     5000:       f3 0f 1e fa             endbr64
>     5004:       e9 00 00 00 00          jmp    5009 <__tsan_unaligned_volatile_write16+0x9>
>                         5005: R_X86_64_PLT32    __tsan_write16-0x4

Interesting - also note that in kernel/kcsan/core.c, these functions
don't even call each other explicitly. Although because sizeof(long) <
16 everywhere, the code for the volatile and non-volatile 16-byte
variants ends up the same. So the optimizer seems to think it's ok to
just "call" the other equivalent function, even though we didn't tell
it to do so - check_access() is __always_inline.

Whatever happens here isn't completely wrong, so if you just want to
silence the warning:

  Acked-by: Marco Elver <elver@google.com>

But I have a feeling the compiler is being a bit too clever here.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNNTUOfdjK_e5xWheqJgGBkD5e9_F15Vn0DECwtCwppDkw%40mail.gmail.com.
