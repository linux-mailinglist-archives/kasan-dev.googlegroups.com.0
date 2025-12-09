Return-Path: <kasan-dev+bncBDA5JVXUX4ERBSOP3XEQMGQEOQ4XTFY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13e.google.com (mail-lf1-x13e.google.com [IPv6:2a00:1450:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id AE0A9CAE719
	for <lists+kasan-dev@lfdr.de>; Tue, 09 Dec 2025 01:05:51 +0100 (CET)
Received: by mail-lf1-x13e.google.com with SMTP id 2adb3069b0e04-596af6ada80sf3146246e87.1
        for <lists+kasan-dev@lfdr.de>; Mon, 08 Dec 2025 16:05:51 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1765238730; cv=pass;
        d=google.com; s=arc-20240605;
        b=dvUgtKkn7Dsizl54MfJ2lDFQufyU3IL/fTPHarzBNFy584zmIJBbovKLBuoSed3Sc3
         JfhtQafxK9UDs39m/OBSw+VGeS8H97cvFZk76sSnmcZv/FTXQ7SHMp3ZPq8DQCeMVkfi
         7ijA1/fh3ETqpY/QcpZBeK23Q4HsekvkEFbtf40QwEsLCKXaghj9x4q2ySfjMU/imVkb
         8F4sNBL9yAyUBTpPho1Z8HLuAgktXDULHSp3L49ahNaddBBkX9xvqQDQRQi9fdGP7FcA
         tw3vMSiSLpMWAxmdfYPIkqPovH53erJ3PM0qDyp4SbsXMYiHybpEAA7BPJwtdXNtkI6D
         AVBw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=aKuiAuvnIhOyMjz7ylDO8FwanK7qT6GhOJ9rcZn6bAE=;
        fh=KNCJifdWZbSlhvXN36zNP84+jkNUOGTtmryMvhM2TTA=;
        b=IhKS2Kyu+3sEwaVNmgdyx9durHT2Vvizjb0RNtPFJptPA4W7rlB8X0gT2TigVccZN0
         rf7M5hRf4g0DL7E5YMMnT1XaaPxUUj9AFN3ijnKTVLL1i9OYKgr0aamCPh49TQsi3mdU
         47ybaCnUzC/s4duggdNMar5JYbQ+NVMHhI9CxdKzImZQijxP+BnuWNTr9fFbgO7vW6VO
         9MUmK2CG04b39U0D88CM5Nf/WIAVRBzGxyUs3WilsPEuNBch73F2fJ1KNbY9vN2ekVAH
         IR+klMwIzNP1LOvOBO4kitze9mSmLG46gvr6Fxin61RTdJBu4N2SLH2qo8nzi9mUV8bS
         ns1g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=TssuIq8C;
       spf=pass (google.com: domain of 3xmc3aqgkccmsjltvjwkpxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--jackmanb.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3xmc3aQgKCcMsjltvjwkpxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--jackmanb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1765238730; x=1765843530; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:from:subject:message-id:references
         :mime-version:in-reply-to:date:from:to:cc:subject:date:message-id
         :reply-to;
        bh=aKuiAuvnIhOyMjz7ylDO8FwanK7qT6GhOJ9rcZn6bAE=;
        b=R6emIakc7WIGub0LA1z8H9CejbFcmbAovxFQX79hvL2A5eLvs2zExCDt4yTLUGKKBm
         kyfygFWXvynGyQZMH2rW1zdmb4Vvxrl/1XdtRV3atpKTfFDrrRcent1Rh13RuzFD9KCC
         92G97xRASawOJliYkyODBrPWkOKtNuS0Z5amVQLVYYhLPjZXkZsxA8hN0NGa4iB6g9Jy
         pxaag976RoZTzXrpdgMQESqmaYiFdvHwf4YLg1vYFaY66CqEw6p+nDuVmwhzudHMMlsO
         /bxlTtT7nI/OiAuY9Q437+edU1C0BERRVtmNqUxYcMB2I+ULH4aTAO4ZmaePVdPcXjOL
         gBfQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1765238730; x=1765843530;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:from:subject:message-id:references
         :mime-version:in-reply-to:date:x-beenthere:x-gm-message-state:from
         :to:cc:subject:date:message-id:reply-to;
        bh=aKuiAuvnIhOyMjz7ylDO8FwanK7qT6GhOJ9rcZn6bAE=;
        b=R7rI0gU2VR6psx+V/vtAIsYdIQILbAltZXi2mutytkKBUW8L9rBwRyWh3uing7MLzg
         q8b0L81k4ydsWLfTHzOvmmf1QoGxnvS5h1ZYr4Q51Xql9PcwGAmQGTutKNABcBOf0XgI
         tBoSrsQ5N/e25dqXLnPzqDX6s5TaZt5tMHAIQxhuUFAD+bvrb6t2mtO3CVXDEZd+zy84
         fgjqE2qJ1aewdJl1xDqPafH4uCe/oIlVlvYz6bum1jt9JwCEV1nzq82rUGpiBHebDimA
         AErzCCTTNJOFjOcjJLxUvV42xjNNUYlWS+wr13DOu5F+Tg15bYRUOLuOVSOtVonnJdWN
         wVzQ==
X-Forwarded-Encrypted: i=2; AJvYcCUfC8fCe+tzvQwCITSv5AimvNmb9JEBVAdNfKiBYx0fM3l+EQ1JNSkExrFmwwI8VhXg7pqzYQ==@lfdr.de
X-Gm-Message-State: AOJu0YwWp9LHpMaiMRcr+tj47pR5LZdaYXGvPExksOTDWTuj2UCGsAWU
	zepIf1UyURMdqvPnTK1D1TW9nCsCjGdlCqIXLvjYwbIb+rvDJvW3BDXy
X-Google-Smtp-Source: AGHT+IFZCSN0SfRJR5nUEfsksXiENBnBs165iY+LUJEUnewE8bFUL5vwbB2c2s7MRKBDxHyn9HbKIg==
X-Received: by 2002:a05:6512:2314:b0:594:2d53:545 with SMTP id 2adb3069b0e04-598853bd087mr2969236e87.46.1765238729832;
        Mon, 08 Dec 2025 16:05:29 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWYwivKkeggfamgMVX7k2q8DYluz81eH2Jzblt3Je2VCcA=="
Received: by 2002:ac2:4bd3:0:b0:598:e6e5:51fc with SMTP id 2adb3069b0e04-598e6e552f2ls127660e87.1.-pod-prod-07-eu;
 Mon, 08 Dec 2025 16:05:27 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXSjt1NiFTEA1bqUb7IXuRDnzIQxQmAY6MiM/rAj3HYc6hGjrVgJdv68hIZrgY6oRovXz0Jh73PCRc=@googlegroups.com
X-Received: by 2002:a05:6512:1195:b0:598:de13:6096 with SMTP id 2adb3069b0e04-598de136156mr2812101e87.31.1765238727053;
        Mon, 08 Dec 2025 16:05:27 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1765238727; cv=none;
        d=google.com; s=arc-20240605;
        b=E7j+OK52b8PxAjGgcTzzwq8uVSfHAdTVZHdRKn6VJ7JMCKJuF3km0JgfnOu5Nis8mZ
         /8AdDj3Zhxazwt1KXwlECy4loWrWCXHQnvD8L+uDKr8BkrwbpP1jaMNYArtMLUj2aj6q
         gwCsokkcqejBUr7KFtmKIj6Z3IzbhpwH+Jw+5TL9ukEQYillxDA5R84zr78TT5cGEHAt
         +nM5n+Jrw9sFfFSRtK0ATWTIuEVDVcWVvZxjyILNJLYeRX8l9xZiJCiEWoiHSG+6TM1v
         XMLvzvN/g55fMt/HxfVp9/ZBoA2PBcB/LTp9hLZpoP+QheCY6dkTASsmBhiA/l3pS1nk
         Yu3g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:from:subject:message-id:references
         :mime-version:in-reply-to:date:dkim-signature;
        bh=aamW1NV6H/hkABqRJX47BwzLA3vkBm1Xi/NkYiS8C9Q=;
        fh=qiOAKRVcUfJjiGUDAKNJFWHekvQ3JaMD3w8xdvjr030=;
        b=CxuEEa4zrqNp0xwDpg5LirBprt2FvGRUnKMtOu9J70QyLSiZROn9gtzrMyD5cBVnoA
         Js+/sJEDMvuf5hsoIq4hiQFCI8PbsENZW2uXSIMgINwwG8KSsYBVypMiDaz8pvRbsRhL
         FD5rI3YDxfJ5xGaX92xgK4jWrps4/f5t3fBowRlg3xjKAOrLeDVy0rJPQZn1OdbkJI/l
         29Dd66CRsGR2/6PpW+jrS7dIcd0KK4fNEMVDBy7lDYoPWSZYa15L/ygoUGw4V1lPtmWt
         9aMQUUF6gZE+WvFvdSp06mKddx6Gr9pptZL21RyM8ExXpgU5fosVX6NC87YfvvMkOknp
         60Kg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=TssuIq8C;
       spf=pass (google.com: domain of 3xmc3aqgkccmsjltvjwkpxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--jackmanb.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3xmc3aQgKCcMsjltvjwkpxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--jackmanb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x44a.google.com (mail-wr1-x44a.google.com. [2a00:1450:4864:20::44a])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-37e700c2581si2056191fa.5.2025.12.08.16.05.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 08 Dec 2025 16:05:27 -0800 (PST)
Received-SPF: pass (google.com: domain of 3xmc3aqgkccmsjltvjwkpxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--jackmanb.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) client-ip=2a00:1450:4864:20::44a;
Received: by mail-wr1-x44a.google.com with SMTP id ffacd0b85a97d-42b3c965ce5so4165141f8f.2
        for <kasan-dev@googlegroups.com>; Mon, 08 Dec 2025 16:05:27 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCW3tauN4vCQt58Pfs4a2Hp9YOIaPn24xag4zutq0MqPGE+ZgWM/H5AlmuQZwthgbCTUQIw5kLIV3t4=@googlegroups.com
X-Received: from wmqi18.prod.google.com ([2002:a05:600c:3552:b0:477:76e1:9b4e])
 (user=jackmanb job=prod-delivery.src-stubby-dispatcher) by
 2002:a05:600c:1e28:b0:477:7a53:f493 with SMTP id 5b1f17b1804b1-47939e38284mr98433785e9.23.1765238726444;
 Mon, 08 Dec 2025 16:05:26 -0800 (PST)
Date: Tue, 09 Dec 2025 00:05:25 +0000
In-Reply-To: <CANpmjNPizath=-ZUVTDFAdO_RZL1xqnx_o24nHA+3tJ4-FOg+Q@mail.gmail.com>
Mime-Version: 1.0
References: <20251208-gcov-inline-noinstr-v1-0-623c48ca5714@google.com>
 <CANpmjNNK6vRsyQ6SiD3Uy7fNim-wV+KWgbEokOaxbbd02Wa=ew@mail.gmail.com> <CANpmjNPizath=-ZUVTDFAdO_RZL1xqnx_o24nHA+3tJ4-FOg+Q@mail.gmail.com>
X-Mailer: aerc 0.21.0
Message-ID: <DET8WJDWPV86.MHVBO6ET98LT@google.com>
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
 header.i=@google.com header.s=20230601 header.b=TssuIq8C;       spf=pass
 (google.com: domain of 3xmc3aqgkccmsjltvjwkpxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--jackmanb.bounces.google.com
 designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3xmc3aQgKCcMsjltvjwkpxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--jackmanb.bounces.google.com;
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

On Mon Dec 8, 2025 at 11:12 AM UTC, Marco Elver wrote:
> On Mon, 8 Dec 2025 at 10:37, Marco Elver <elver@google.com> wrote:
>>
>> On Mon, 8 Dec 2025 at 02:35, Brendan Jackman <jackmanb@google.com> wrote=
:
>> >
>> > Details:
>> >
>> >  - =E2=9D=AF=E2=9D=AF  clang --version
>> >    Debian clang version 19.1.7 (3+build5)
>> >    Target: x86_64-pc-linux-gnu
>> >    Thread model: posix
>> >    InstalledDir: /usr/lib/llvm-19/bin
>> >
>> >  - Kernel config:
>> >
>> >    https://gist.githubusercontent.com/bjackman/bbfdf4ec2e1dfd0e1865717=
4f0537e2c/raw/a88dcc6567d14c69445e7928a7d5dfc23ca9f619/gistfile0.txt
>> >
>> > Note I also get this error:
>> >
>> > vmlinux.o: warning: objtool: set_ftrace_ops_ro+0x3b: relocation to !EN=
DBR: machine_kexec_prepare+0x810
>> >
>> > That one's a total mystery to me. I guess it's better to "fix" the SEV
>> > one independently rather than waiting until I know how to fix them bot=
h.
>> >
>> > Note I also mentioned other similar errors in [0]. Those errors don't
>> > exist in Linus' master and I didn't note down where I saw them. Either
>> > they have since been fixed, or I observed them in Google's internal
>> > codebase where they were instroduced downstream.
>> >
>> > This is a successor to [1] but I haven't called it a v2 because it's a
>> > totally different solution. Thanks to Ard for the guidance and
>> > corrections.
>> >
>> > [0] https://lore.kernel.org/all/DERNCQGNRITE.139O331ACPKZ9@google.com/
>> >
>> > [1] https://lore.kernel.org/all/20251117-b4-sev-gcov-objtool-v1-1-54f7=
790d54df@google.com/
>>
>> Why is [1] not the right solution?
>> The problem is we have lots of "inline" functions, and any one of them
>> could cause problems in future.
>
> Perhaps I should qualify: lots of *small* inline functions, including
> those stubs.
>
>> I don't mind turning "inline" into "__always_inline", but it seems
>> we're playing whack-a-mole here, and just disabling GCOV entirely
>> would make this noinstr.c file more robust.
>
> To elaborate: `UBSAN_SANITIZE_noinstr.o :=3D n` and
> `K{A,C}SAN_SANITIZE_noinstr.o :=3D n` is already set on this file.
> Perhaps adding __always_inline to the stub functions here will be
> enough today, but might no longer be in future.=20

Well you can also see it the other way around: disabling GCOV_PROFILE
might be enough today, but as soon as some other noinstr disables=20
__SANITIZE_ADDRESS__ and expects to be able to call instrumented
helpers, that code will be broken too.=20

I don't think we can avoid whack-a-mole here. In fact I think the whole
noinstr thing is an inevitable game of whack-a-mole unless we can get a
static anlyzer to find violations at the source level. I suspect there
are loads of violations in the tree that only show up in objtool if you
build in weird configs on a full moon.

One argument in favour of `GCOV_PROFILE_noinstr.o :=3D n` would be: "this
is non-instrumentable code, the issue here is that it is getting
instrumented, so the fix is surely to stop instrumenting it". But, I
don't think that's really true, the issue is not with the
instrumentation but with the out-of-lining. Which highlights another
point: a sufficiently annoying compiler could out-of-line these
stub functions even without GCOV, right?

Still, despite my long-winded arguments I'm not gonna die on this hill,
I would be OK with both ways.

> If you look at
> <linux/instrumented.h>, we also have KMSAN. The KMSAN explicit
> instrumentation doesn't appear to be invoked on that file today, but
> given it shouldn't, we might consider:
>
> KMSAN_SANITIZE_noinstr.o :=3D n
> GCOV_PROFILE_noinstr.o :=3D n

This would make sense to me, although as I hinted above I think it's
sorta orthogonal and we should __always_inline the k[ca]san stubs
regardless.

> The alternative is to audit the various sanitizer stub functions, and
> mark all these "inline" stub functions as "__always_inline". The
> changes made in this series are sufficient for the noinstr.c case, but
> not complete.

Oh, yeah I should have  done __kcsan_{en,di}able_current() too I think.

Are there other stubs you are thinking of? I think we only care about the
!__SANITIZE_*__ stubs - we don't need this for !CONFIG_* stubs, right?
Anything else I'm forgetting?

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/D=
ET8WJDWPV86.MHVBO6ET98LT%40google.com.
