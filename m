Return-Path: <kasan-dev+bncBDA5JVXUX4ERBEER33EQMGQEL7BG3EI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x63d.google.com (mail-ej1-x63d.google.com [IPv6:2a00:1450:4864:20::63d])
	by mail.lfdr.de (Postfix) with ESMTPS id 43BA5CAEB7A
	for <lists+kasan-dev@lfdr.de>; Tue, 09 Dec 2025 03:25:22 +0100 (CET)
Received: by mail-ej1-x63d.google.com with SMTP id a640c23a62f3a-b7270cab7eesf388868466b.1
        for <lists+kasan-dev@lfdr.de>; Mon, 08 Dec 2025 18:25:22 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1765247122; cv=pass;
        d=google.com; s=arc-20240605;
        b=LPEiHpjSXdOEAr77NZX/MqzuSnFntM1i3LPZbdJf7NALY+1THgGuxPTTEGJFpxb2c+
         s5rwyBaqeWFPPAnni3msT9bwqVoAxFtQAb4Bmljpm5pzxuMrDJNc3LcLPNQuIo3do9Jp
         Dd1l8uIBqCdSAH9DMI15+pu0G9INFVjaDsE/LMgYbSrtIFnImw7hIFgm/8L1YEbXY77F
         TI0DfJT4jIEu4CqpUOJ/ESyOS/xAeRkMGlm+kFflCd+UZJ2LtSbfDr2T7J79Ae6ZTOPG
         BFPpLaeR5SlpqF30PoHMHUULEJuzLkr8UfY+Uvcz7c2ZgQPtu4i2uMf0YY+4UKONPq2a
         ZNHw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=chD0tYC0g/3RRzPwUpwECqmN/wt6og76sGTgMzg/Pqo=;
        fh=HmFyd5MhWGiX0bCUnFQmoQi4Ga1fuWWTzozH7oPEXws=;
        b=JPee8NJmu3LVmWfoVwdfjxR9qRMJc8iB/J4RV3m8Njp1iLLuobprWRCoyXq04vQz8r
         bJacgGyzGxik2e3MPoTrTOSCEm2OD7ulUzrgVK6+VAGhGPZX8svkcdhA+pjoqtt8Wo4E
         FPOOLioTnrVT6BnZlyCQJeJRXN+ygnTi3K2beezC9RvTUA+c0zWiG3Pu/kb5b4ZScPvX
         P2HXXWgyq8VW6d15x4UrjRWromN4kkLgi8ShTvpT610/6qJW60WvKxCGnuEACYYc1Rfq
         OXRMmegUDaN2vABHSj/VRfBj9qz8K3NmD/aEuzOrlmI3tPsB9+JwkXqEdRnOAUIOU6BN
         9rPw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=VkZiV4dr;
       spf=pass (google.com: domain of 3jog3aqgkcc02tv35t6uz77z4x.v753tbt6-wxez77z4xza7d8b.v75@flex--jackmanb.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3jog3aQgKCc02tv35t6uz77z4x.v753tBt6-wxEz77z4xzA7D8B.v75@flex--jackmanb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1765247122; x=1765851922; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:from:subject:message-id:references
         :mime-version:in-reply-to:date:from:to:cc:subject:date:message-id
         :reply-to;
        bh=chD0tYC0g/3RRzPwUpwECqmN/wt6og76sGTgMzg/Pqo=;
        b=mqGLdVovdyqRVqXvJ+HH+r8p4otSKxUuMhAvjLcNgKDHKfV/X9KeK/eb7MTByJZWn3
         WhA9FJ/N33b56GFehkjn9mzifOV5cLl75y3Ks4HVpyd0h7jV10tBrWEBl+x0BcQ0m/ar
         8L1VJkg9Lk2xnrDB233NQReOKfYWtdLdyYUrqko9/Av3tUwiIMRJaKM5SqziRrwcjcus
         88b2UgyoIgXTHfkmsSjy3iuIREbFLxmY76IbJRQJKkp/QKpQFnUeRu9H2Iq73xwA4hoT
         LXW+9fMsKtCUt2eboX50EfLIMTHr8/Ht1h+XFCVsoCjjXy4T9Ke6bOClBcrHCDPWhzIj
         w9mA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1765247122; x=1765851922;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:from:subject:message-id:references
         :mime-version:in-reply-to:date:x-beenthere:x-gm-message-state:from
         :to:cc:subject:date:message-id:reply-to;
        bh=chD0tYC0g/3RRzPwUpwECqmN/wt6og76sGTgMzg/Pqo=;
        b=hIvsaunATe9in92Cw5Xezj3pQCO1cj4QNLMLHhmQRWnnIQaOHj4ihcUCV+EjsD8jq0
         KIoFPrcG2DOLMPzYhCEQthzjeOdVp3KBNa8SOS8bK8NoHkypHaqER16bacAzB4qP2m0s
         otVemfRPL9tQMMk8n/HKdoa75XrSHA4gBJ+sZpMOUqboxNcDgtKKMg5M1TJp1i8baJ6t
         0qmjYU1eQN3v5Fvl34ecSB5ggMKJHuiExRFyA4zCkMTYOAn3WQJRAAhVmNHuSw0hUnYI
         9UA9Adf1D6sVSnKONgzbXP2xVgN3hk6q0Y58+A002BXopg/0gsEoZ65nPAWLjSpakAMU
         YiBg==
X-Forwarded-Encrypted: i=2; AJvYcCVUFRfZ5HAHBSRlLpjAJLECVRB3rXRhUBp2z6HaDfFHpXF1YjSGbiH4SU05dUXyaqEvU+eJKg==@lfdr.de
X-Gm-Message-State: AOJu0YxoVakVNqXFizuSMrLKuliaeE6SN3HwJMzBUpkQwPHuCFwStldz
	8pj+YZD1+wT1RmW/jvvZUGt4MwcnLeb8yoIaU0reCv6LFzC2tnuul95/
X-Google-Smtp-Source: AGHT+IEMGlWOx5RrHQmms+ZOwtVW77tc710CwQCg/M23Ar8dm3GXMAi8kzb0uGqnsH57CCuty8zfng==
X-Received: by 2002:a17:907:2d8e:b0:b72:134a:48c8 with SMTP id a640c23a62f3a-b7a242b0af3mr959845466b.14.1765247121368;
        Mon, 08 Dec 2025 18:25:21 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWbULlrTW+F7RQLxerwHPyGQkW4Qr/DlcX4VFQiXPJJBQg=="
Received: by 2002:a05:6402:5206:b0:643:8196:951 with SMTP id
 4fb4d7f45d1cf-647ad2f52a2ls4132582a12.0.-pod-prod-07-eu; Mon, 08 Dec 2025
 18:25:18 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCX7Y0uKXs988MPACKgb88JsDtoXFFvZ7cEOM6Am8zw7TEfvtjN0/xb4m9XFabuLJtrC4HOr9UvYfCM=@googlegroups.com
X-Received: by 2002:a05:6402:1941:b0:640:a356:e797 with SMTP id 4fb4d7f45d1cf-6491a3e85d2mr8569044a12.13.1765247118665;
        Mon, 08 Dec 2025 18:25:18 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1765247118; cv=none;
        d=google.com; s=arc-20240605;
        b=M64TklSCjMtdX4TqqysP4D53ebF2cAN/QffYCT5wObPrpw3GO/4iumJe5fHD6TAzaa
         euXC7CINewmSkYkQ8wjssGBegcL2MYLiAahoVvpO8yAMOZoAljs6BBVRODETck2MHw3R
         ke+ktSCJZqsDyE5Qb+rprXPCFtCwNUxRIqdUCM6S76rrxOwYXvQAYSqwaoVOiA3pD2Cr
         HTEV5cLsM2SMXqbEjsA2BPDatk8+H7XCRzxopSnuczeV7w/c4NDsGAKrhBNBQJLlyhzY
         oSL74F/fW4xumbkItSEFJULycRlcwsryAkYClYKpcyfzIbJo87CMaVY3E8t82lJ2p611
         UOKQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:from:subject:message-id:references
         :mime-version:in-reply-to:date:dkim-signature;
        bh=fhuWLS5fTL+DTVMTjxhbeF8m7ga3oboOLspu3QuJmuA=;
        fh=OO+P5mIFoWBWLs3Et7rNu1X+n0MJ0n62N/Me/tu9Ka8=;
        b=MO7E5+h1xJ8olCMq/mEHmRhV4z7FFwsR+2x3mY3Mp5SmNoyJM9ngMZ+mqcnAUiMgAQ
         Pa72eHCEJcVhVnFyzqCAwgJM/LjJ8ZGR+tniN+u/0ORx44exBl6H7iUGspKe1+vxv0V3
         n13PyYwTjJ64YwnTsQl2QAEH09WwFYCC1pJ4QAQc6YptY9jQrGpDHb9u1iUc5M58OrrP
         F+qnv/r1rWAYGBxm4RykxVUFcO7ci3ZOJJgT9/h8ktSMGfhhcKTNhJUwVfvwc7ut/qZR
         zpD+ywX0Cwr5DlUHgqYHRnyTarAUjBm3j3AE2i8CLRe+4GBQM0V8WanqzwgvQgTIro/k
         bE/w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=VkZiV4dr;
       spf=pass (google.com: domain of 3jog3aqgkcc02tv35t6uz77z4x.v753tbt6-wxez77z4xza7d8b.v75@flex--jackmanb.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3jog3aQgKCc02tv35t6uz77z4x.v753tBt6-wxEz77z4xzA7D8B.v75@flex--jackmanb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x449.google.com (mail-wr1-x449.google.com. [2a00:1450:4864:20::449])
        by gmr-mx.google.com with ESMTPS id 4fb4d7f45d1cf-647b33844d4si188334a12.8.2025.12.08.18.25.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 08 Dec 2025 18:25:18 -0800 (PST)
Received-SPF: pass (google.com: domain of 3jog3aqgkcc02tv35t6uz77z4x.v753tbt6-wxez77z4xza7d8b.v75@flex--jackmanb.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) client-ip=2a00:1450:4864:20::449;
Received: by mail-wr1-x449.google.com with SMTP id ffacd0b85a97d-42e2d105358so3457145f8f.3
        for <kasan-dev@googlegroups.com>; Mon, 08 Dec 2025 18:25:18 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCUpKBhMz5f2Bt6lHAPd2Za2ov1FZ9xd/092mV/pHR1qX0HbixHakTVbW+/ja9mt8NZMo+VBEjcb23Y=@googlegroups.com
X-Received: from wruh13.prod.google.com ([2002:a5d:688d:0:b0:42b:4c63:868a])
 (user=jackmanb job=prod-delivery.src-stubby-dispatcher) by
 2002:a05:6000:4028:b0:427:454:43b4 with SMTP id ffacd0b85a97d-42f89f56dcdmr9816619f8f.48.1765247118114;
 Mon, 08 Dec 2025 18:25:18 -0800 (PST)
Date: Tue, 09 Dec 2025 02:25:17 +0000
In-Reply-To: <CANpmjNOpC2kGhfM8k=Y8VfLL0wSTkiOdkfU05tt1xTr+FuMjOQ@mail.gmail.com>
Mime-Version: 1.0
References: <20251208-gcov-inline-noinstr-v1-0-623c48ca5714@google.com>
 <CANpmjNNK6vRsyQ6SiD3Uy7fNim-wV+KWgbEokOaxbbd02Wa=ew@mail.gmail.com>
 <CANpmjNPizath=-ZUVTDFAdO_RZL1xqnx_o24nHA+3tJ4-FOg+Q@mail.gmail.com>
 <DET8WJDWPV86.MHVBO6ET98LT@google.com> <CANpmjNOpC2kGhfM8k=Y8VfLL0wSTkiOdkfU05tt1xTr+FuMjOQ@mail.gmail.com>
X-Mailer: aerc 0.21.0
Message-ID: <DETBVMG30SW8.WBM5TRGF59YZ@google.com>
Subject: Re: [PATCH 0/2] Noinstr fixes for K[CA]SAN with GCOV
From: "'Brendan Jackman' via kasan-dev" <kasan-dev@googlegroups.com>
To: Marco Elver <elver@google.com>, Brendan Jackman <jackmanb@google.com>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Ard Biesheuvel <ardb@kernel.org>, 
	<kasan-dev@googlegroups.com>, <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: jackmanb@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=VkZiV4dr;       spf=pass
 (google.com: domain of 3jog3aqgkcc02tv35t6uz77z4x.v753tbt6-wxez77z4xza7d8b.v75@flex--jackmanb.bounces.google.com
 designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3jog3aQgKCc02tv35t6uz77z4x.v753tBt6-wxEz77z4xzA7D8B.v75@flex--jackmanb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
X-Original-From: Brendan Jackman <jackmanb@google.com>
Reply-To: Brendan Jackman <jackmanb@google.com>
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

On Tue Dec 9, 2025 at 12:52 AM UTC, Marco Elver wrote:
> On Tue, 9 Dec 2025 at 01:05, Brendan Jackman <jackmanb@google.com> wrote:
>>
>> On Mon Dec 8, 2025 at 11:12 AM UTC, Marco Elver wrote:
>> > On Mon, 8 Dec 2025 at 10:37, Marco Elver <elver@google.com> wrote:
>> >>
>> >> On Mon, 8 Dec 2025 at 02:35, Brendan Jackman <jackmanb@google.com> wr=
ote:
>> >> >
>> >> > Details:
>> >> >
>> >> >  - =E2=9D=AF=E2=9D=AF  clang --version
>> >> >    Debian clang version 19.1.7 (3+build5)
>> >> >    Target: x86_64-pc-linux-gnu
>> >> >    Thread model: posix
>> >> >    InstalledDir: /usr/lib/llvm-19/bin
>> >> >
>> >> >  - Kernel config:
>> >> >
>> >> >    https://gist.githubusercontent.com/bjackman/bbfdf4ec2e1dfd0e1865=
7174f0537e2c/raw/a88dcc6567d14c69445e7928a7d5dfc23ca9f619/gistfile0.txt
>> >> >
>> >> > Note I also get this error:
>> >> >
>> >> > vmlinux.o: warning: objtool: set_ftrace_ops_ro+0x3b: relocation to =
!ENDBR: machine_kexec_prepare+0x810
>> >> >
>> >> > That one's a total mystery to me. I guess it's better to "fix" the =
SEV
>> >> > one independently rather than waiting until I know how to fix them =
both.
>> >> >
>> >> > Note I also mentioned other similar errors in [0]. Those errors don=
't
>> >> > exist in Linus' master and I didn't note down where I saw them. Eit=
her
>> >> > they have since been fixed, or I observed them in Google's internal
>> >> > codebase where they were instroduced downstream.
>> >> >
>> >> > This is a successor to [1] but I haven't called it a v2 because it'=
s a
>> >> > totally different solution. Thanks to Ard for the guidance and
>> >> > corrections.
>> >> >
>> >> > [0] https://lore.kernel.org/all/DERNCQGNRITE.139O331ACPKZ9@google.c=
om/
>> >> >
>> >> > [1] https://lore.kernel.org/all/20251117-b4-sev-gcov-objtool-v1-1-5=
4f7790d54df@google.com/
>> >>
>> >> Why is [1] not the right solution?
>> >> The problem is we have lots of "inline" functions, and any one of the=
m
>> >> could cause problems in future.
>> >
>> > Perhaps I should qualify: lots of *small* inline functions, including
>> > those stubs.
>> >
>> >> I don't mind turning "inline" into "__always_inline", but it seems
>> >> we're playing whack-a-mole here, and just disabling GCOV entirely
>> >> would make this noinstr.c file more robust.
>> >
>> > To elaborate: `UBSAN_SANITIZE_noinstr.o :=3D n` and
>> > `K{A,C}SAN_SANITIZE_noinstr.o :=3D n` is already set on this file.
>> > Perhaps adding __always_inline to the stub functions here will be
>> > enough today, but might no longer be in future.
>>
>> Well you can also see it the other way around: disabling GCOV_PROFILE
>> might be enough today, but as soon as some other noinstr disables
>> __SANITIZE_ADDRESS__ and expects to be able to call instrumented
>> helpers, that code will be broken too.
>
> This itself is a contradiction: a `noinstr` function should not call
> instrumented helpers. Normally this all works due to the compiler's
> function attributes working as intended for the compiler-inserted
> instrumentation, but for explicitly inserted instrumentation it's
> obviously not. In otherwise instrumented files with few (not all)
> `noinstr` functions, making the stub functions `__always_inline` will
> not work, because the preprocessor is applied globally not per
> function. In the past, I recall the underlying implementation being
> used of e.g. the bitops (arch_foo... or __foo) in `noinstr` functions
> to solve that.

Sorry I dropped an important word here, I meant to say other noinstr
_files_. I.e. anything else similar to SEV's noinstr.c that is doing
noinstr at the file level.

>> Still, despite my long-winded arguments I'm not gonna die on this hill,
>> I would be OK with both ways.
>
> To some extent I think doing both to reduce the chance of issues in
> future might be what you want. On the other hand, avoiding the
> Makefile-level opt-out will help catch more corner cases in future,
> which may or may not be helpful outside this noinstr.c file.

Cool, then yeah I think I will do both unless anyone shows up to object
to that. Both things ultimately make sense on their own merit and even
if you only need one or the other to make the error go away, I don't
think that actually makes them "redundant".

>> > The alternative is to audit the various sanitizer stub functions, and
>> > mark all these "inline" stub functions as "__always_inline". The
>> > changes made in this series are sufficient for the noinstr.c case, but
>> > not complete.
>>
>> Oh, yeah I should have  done __kcsan_{en,di}able_current() too I think.
>>
>> Are there other stubs you are thinking of? I think we only care about th=
e
>> !__SANITIZE_*__ stubs - we don't need this for !CONFIG_* stubs, right?
>> Anything else I'm forgetting?
>
> Initially, I think !__SANITIZE_* stubs are enough. Well, basically
> anything that appears in <linux/instrumented.h>, because all those are
> __always_inline, we should make the called functions also
> __always_inline.

Ack, thanks for all the input here! I'll probably wait until after LPC
to do a v2.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/D=
ETBVMG30SW8.WBM5TRGF59YZ%40google.com.
