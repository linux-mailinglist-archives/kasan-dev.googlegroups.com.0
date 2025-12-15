Return-Path: <kasan-dev+bncBC7OBJGL2MHBB3PX77EQMGQEV2UEGGQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83b.google.com (mail-qt1-x83b.google.com [IPv6:2607:f8b0:4864:20::83b])
	by mail.lfdr.de (Postfix) with ESMTPS id 0EF3BCBDBD6
	for <lists+kasan-dev@lfdr.de>; Mon, 15 Dec 2025 13:15:43 +0100 (CET)
Received: by mail-qt1-x83b.google.com with SMTP id d75a77b69052e-4ee0193a239sf35251221cf.0
        for <lists+kasan-dev@lfdr.de>; Mon, 15 Dec 2025 04:15:43 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1765800942; cv=pass;
        d=google.com; s=arc-20240605;
        b=HFmB3m0GO7cgauqy8gVun3dHXkACgBi7i67F6VADRIIUoMKYukfPxK7ER7aIqIu9PB
         MoUZSD73I7YKkauhXCJaYNXuoOaLf2WbufdNuEK2MQnGmzWEnLEgc4yEY4R2xi0J1aQH
         ygaWJ/aGBVNAOAEtNilvFHdT+uZ5iZa6kdoJD6TbpqHnKT4JQ+ioaDp9LpQ1a0kA5HEj
         zyPnDF6AE2hIcGFKa9jgL5DBAKi050BXylQmKy0wWaFGR8OTrIdnZYRGNsio4SZ1VFo9
         BXSQFMsd+HVI3uGNDduvbHWm0vBt6f5mikPR3aU1tnBivCUT1V+EIQtvAtkkZDbje3qa
         J+/g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=gMV9tj8ORwO73FN3uGH4JexWaG9tM+dc+NhaCYjuILQ=;
        fh=BLlfd9DLnMMz6bTPg8xSJoWbnhTVvet5VBerAv1FN7k=;
        b=GfYdU9Vt/xtxH/5wYeMTF1OLcWydyLuPO9t2lQylcjPLuUB6AB5IzNmtapVdTM7ifF
         ctqwoQOK4uFU4K6cdBHge00DbpVt8vabfgZYa1caJzbr0L3UHnVWa6dWPdIRYFRT8dqe
         i+Vb5jhHvepkWdcxWvxETPqtHXZf5bL25WNecKFlx/uiIr4L+eFGe1YQOlv52EW1JodB
         8cTsJOko91o+0RuBzPJO1+CgczUoJ8vTEoHP2Lh8h4Nzl7PTj/Tzxr1IUkt3GI0iIrgB
         NTaeT01G9Mqwk/RcFnlyP1ltU5btlooC7t5+BJYHIEpIi6SzeaPi/JO85KQQFVyiWAb5
         oXkw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=GRCm2PL4;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1033 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1765800942; x=1766405742; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=gMV9tj8ORwO73FN3uGH4JexWaG9tM+dc+NhaCYjuILQ=;
        b=tE0NeSEtt8uztje7P98rUcDWU5vii4Mtvi6PAHMny3wEXybGB3mH9tKEDNPECIsS8t
         StmK/+nLdPZdaRFc/AIoUZkbXXnwXSd9x2htd4unFnN0dcHDrJeh2/SWPheWB1WrTU9w
         8SQZHWaHYhUm0FP7H4iPPKY5C/SnI67WSE9NmtG8fzS+Tg8JcOxIHgSX9bU6F5ziba3t
         pz/1xPCTKu1ftwWyBNqkIUyRRnAH2fdilRHBp+nztZK2IzmjhoigVVV9r+l5ER98BSmT
         2DgWJWJtk97UisPZQOpjCbKyfD8nB+sOfcB+qQ36q7NOBPH8Mp4w1PWO92xWwleJ0UWT
         jWaA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1765800942; x=1766405742;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-gm-gg:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=gMV9tj8ORwO73FN3uGH4JexWaG9tM+dc+NhaCYjuILQ=;
        b=d2YCDeJAtcZgX9SQl7w8iJAHhAFzTwlm4psIXXXLlnqjHn1FcPXuhfwPffyqU5VihS
         TwiSFe850uHjwjaV5Nb9EOZffo4QXx7jXbymgDx/r5H4Iilk/afkeARWFvYXOP4yyMAM
         IPr6Jsti0X+1uxobK7eNtvYMl8AORGI2djk2s6K0AFX/1NOnrxafx11JO1A+r8rsXNeS
         j560rqU4S5NPquh5FsgLbUhgg6ilRRmtUM5rco3/+odvPhbAWr1qXJkCnIyp4XKmgag4
         7fiq8VJiLS/7kJGvyQ/A/iWlZaiWs8qTTswRQInYkGwR+LKy50UENuxhYdWY99PrfeXI
         llhQ==
X-Forwarded-Encrypted: i=2; AJvYcCVNqLRa0+tdnIKaPsg1C5YbSHLxpJc7FRRrywTSZ0Sm+NkKQz2PfS0N8eNqdgTedca1et/HtQ==@lfdr.de
X-Gm-Message-State: AOJu0YwGhWm8aoUPTI3VT7QfpigsOuTzi2eICQ6pRLQSWFdAUPPDDRm2
	XKKpI3VLPjqLKbs+vnEXNdQAWjoI0H7J+IB8nJk7dxXb/cVvBMH9eKAf
X-Google-Smtp-Source: AGHT+IHAupo5z4Xr2DVHwuTP9jOHiRG5Dz6r3kwJ0Ax/M5rJZefrItP0u2MazPXNHapr+iBifWI9sw==
X-Received: by 2002:a05:622a:106:b0:4ee:4a3a:bd08 with SMTP id d75a77b69052e-4f1d066fe70mr143586901cf.80.1765800941558;
        Mon, 15 Dec 2025 04:15:41 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWZK2DRma9uQJeCWyV2XZzL3cUdOu3XZichx2ehDEonuzQ=="
Received: by 2002:a05:622a:1391:b0:4ee:1b36:aec4 with SMTP id
 d75a77b69052e-4f1ce9673ddls62253701cf.0.-pod-prod-08-us; Mon, 15 Dec 2025
 04:15:40 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXKHAzf768wXJpIA3ODs+glfHwx9jGD2bQvcOoSbUrgQXhwaQEiAoKIZGZYr7Yr7zsNBdmGcIrg6Fg=@googlegroups.com
X-Received: by 2002:a05:620a:4488:b0:8b1:ac18:acc8 with SMTP id af79cd13be357-8bb39bd6d5dmr1439427985a.26.1765800940413;
        Mon, 15 Dec 2025 04:15:40 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1765800940; cv=none;
        d=google.com; s=arc-20240605;
        b=Uib86bl9KuDyxWOiaXib2DVhCBYe2xXogB1WQv/Kc5MD7aLM0JHTqD6U82AEtD5xia
         BRet4GGOjbEWqbT0M3o20m05hStnJLFiuBtQntJEXSBStddehcPRgWpyndKSK5gBPAs7
         PXqfHTeYmmypZlVmlYtzno9h5fwL7G/YMSX8PQM/XpgnQROyUaChx4ebYdmvX+b874zG
         SdnYn84cnS/XDWPgH8zaH7YYqWi2lRzQILlJEX9lOMz/W5vg4u6HVZ0HukZGlJL1vOeu
         Zz1CODHh+6Qa2k6Kpsc4xZw+M/o5TsLk3OK4woTEdC6wMLwlY65GgjsolqLIOYoL943a
         Ez2g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=MljZZ8zldo/4ypaBESWWww7WxyG+/hcwicEAXthybXA=;
        fh=0f3wLqjlaWEafL8nCYMsQQD7U3wrQ0wfOarB9uPRLk0=;
        b=Jsfr4UB9EwWEPIRg2+83xaz/nCCfjEz2ujFbI+zSyhYEXJgObMWi5eKKKcCMEbiSFD
         PeLJD/6bTeQNTDi3oOxb+0bWjZ1zTcpBsKuncR2SfCrgmd6WQdkTNpduQCA8RVjGd8+w
         8SoJrQIV0YFF9l/USfxLVoHd4/p3cHtoIwwUYrJDyvq8ajfmEWEgXItnM3W+1yiJSx3c
         +WBy+SeVn2asLU2wURz1mmrr6flmHt9AunFn0hZZ6DUQvjHXkMrAeJR+PYoECe7yHMdq
         FNb/FCye7zy0OM68ndPBW1jolrP9rYXua1KtqH9xaBefHY6AMS1CSyFZNXAxV1vWg46Q
         UOGQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=GRCm2PL4;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1033 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pj1-x1033.google.com (mail-pj1-x1033.google.com. [2607:f8b0:4864:20::1033])
        by gmr-mx.google.com with ESMTPS id af79cd13be357-8bab47ff743si60959285a.0.2025.12.15.04.15.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 15 Dec 2025 04:15:40 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1033 as permitted sender) client-ip=2607:f8b0:4864:20::1033;
Received: by mail-pj1-x1033.google.com with SMTP id 98e67ed59e1d1-34aa62f9e74so4121230a91.1
        for <kasan-dev@googlegroups.com>; Mon, 15 Dec 2025 04:15:40 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCWZWDUBsswj/b7lbwSuMP6zA2TigS7LQOHAAHJ/hKf5+1snJewgx9Cu1FzmTn6oUfHFF6i3dw5SqUE=@googlegroups.com
X-Gm-Gg: AY/fxX6J798YWAfRvTB9McYayda/clRAJ0M5SAlwnDLlWRwl7Zumosf5WCtZpiBEZ6C
	JRRvLIuYzstGn68ZWPgp1dGO0Mfmqb4YbDliS6Npj1/pvNBe1Qdj7oNYTlI2u2zPp7jmS+cOakG
	xmcDUQZNOqTIZd+uUODRlzy10rlY+5/I3HXWYwhGCPlC17HACT9Xx9SBXFf6Fz34pNnH9PcXL/a
	KNAOI6vQaXGmfGDs8Q0HMh3yXbaqbkjdo8h2UtpWA9sCcwXb0x7fpiOEO1PLPuSllBigh2WeI0n
	WXHlkTkNFd62Snhx5AuLmtVtKw==
X-Received: by 2002:a05:7022:6086:b0:11b:3742:1257 with SMTP id
 a92af1059eb24-11f34c4247bmr10220605c88.34.1765800938974; Mon, 15 Dec 2025
 04:15:38 -0800 (PST)
MIME-Version: 1.0
References: <20251215-gcov-inline-noinstr-v2-0-6f100b94fa99@google.com>
In-Reply-To: <20251215-gcov-inline-noinstr-v2-0-6f100b94fa99@google.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 15 Dec 2025 13:15:01 +0100
X-Gm-Features: AQt7F2pLHtT-aX9GbIMKKNXEbj3I4-5xFOj7BZTsusSyU80WPdK3FI7EBOWAt4Y
Message-ID: <CANpmjNMqJVzXrMhCCHjLF5+nvLk33+wuUG_EQ6jd=nF4W-+uMQ@mail.gmail.com>
Subject: Re: [PATCH v2 0/3] Noinstr fixes for K[CA]SAN with GCOV
To: Brendan Jackman <jackmanb@google.com>, Andrew Morton <akpm@linux-foundation.org>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Ard Biesheuvel <ardb@kernel.org>, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=GRCm2PL4;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1033 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
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

On Mon, 15 Dec 2025 at 11:12, Brendan Jackman <jackmanb@google.com> wrote:
>
> Details:
>
>  - =E2=9D=AF=E2=9D=AF  clang --version
>    Debian clang version 19.1.7 (3+build5)
>    Target: x86_64-pc-linux-gnu
>    Thread model: posix
>    InstalledDir: /usr/lib/llvm-19/bin
>
>  - Kernel config:
>
>    https://gist.githubusercontent.com/bjackman/bbfdf4ec2e1dfd0e18657174f0=
537e2c/raw/a88dcc6567d14c69445e7928a7d5dfc23ca9f619/gistfile0.txt
>
> Note I also get this error:
>
> vmlinux.o: warning: objtool: set_ftrace_ops_ro+0x3b: relocation to !ENDBR=
: machine_kexec_prepare+0x810
>
> That one's a total mystery to me. I guess it's better to "fix" the SEV
> one independently rather than waiting until I know how to fix them both.
>
> Note I also mentioned other similar errors in [0]. Those errors don't
> exist in Linus' master and I didn't note down where I saw them. Either
> they have since been fixed, or I observed them in Google's internal
> codebase where they were instroduced downstream.
>
> As discussed in [2], the GCOV+*SAN issue is attacked from two angles:
> both adding __always_inline to the instrumentation helpers AND disabling
> GCOV for noinstr.c. Only one or the other of these things is needed to
> make the build error go away, but they both make sense in their own
> right and both may serve to prevent other similar errors from cropping
> up in future.
>
> Signed-off-by: Brendan Jackman <jackmanb@google.com>
> ---
> Changes in v2:
> - Also disable GCOV for noinstr.c (i.e. squash in [0]).
> - Link to v1: [2]
>
> [0] https://lore.kernel.org/all/DERNCQGNRITE.139O331ACPKZ9@google.com/
> [1] https://lore.kernel.org/all/20251117-b4-sev-gcov-objtool-v1-1-54f7790=
d54df@google.com/
> [2] https://lore.kernel.org/r/20251208-gcov-inline-noinstr-v1-0-623c48ca5=
714@google.com
>
> ---
> Brendan Jackman (3):
>       kasan: mark !__SANITIZE_ADDRESS__ stubs __always_inline
>       kcsan: mark !__SANITIZE_THREAD__ stub __always_inline
>       x86/sev: Disable GCOV on noinstr object

Acked-by: Marco Elver <elver@google.com>

But please double check if you missed any __always_inline on stubs
(see my comment in "kcsan: mark !__SANITIZE_THREAD__ stub
__always_inline").

I don't know which tree this should go through, but since it deals
with KASAN and GCOV, perhaps -mm would be appropriate (also for the
KCSAN patch this time). There shouldn't be any conflicts with other
patches AFAIK.

Thanks,
  -- Marco

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
ANpmjNMqJVzXrMhCCHjLF5%2BnvLk33%2BwuUG_EQ6jd%3DnF4W-%2BuMQ%40mail.gmail.com=
.
