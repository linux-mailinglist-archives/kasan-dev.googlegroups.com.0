Return-Path: <kasan-dev+bncBC3ZPIWN3EFBBG735CEQMGQEMEL6L6I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x63d.google.com (mail-ej1-x63d.google.com [IPv6:2a00:1450:4864:20::63d])
	by mail.lfdr.de (Postfix) with ESMTPS id 78085405BA2
	for <lists+kasan-dev@lfdr.de>; Thu,  9 Sep 2021 19:00:11 +0200 (CEST)
Received: by mail-ej1-x63d.google.com with SMTP id ne21-20020a1709077b95b029057eb61c6fdfsf1099009ejc.22
        for <lists+kasan-dev@lfdr.de>; Thu, 09 Sep 2021 10:00:11 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1631206811; cv=pass;
        d=google.com; s=arc-20160816;
        b=gcKYj1nACvG1LTQBpS+MwUB820X684VIc00I4sWpbFv9OUzVvWvQYQf4qnPMYHwhqC
         DjcsTCbyEKrDJ3BLG/pvgi3DSpthK4Da7mubkI2XCsB1VQ2amEnZ+djGIkk6trtpFN6F
         n/2Se8oLqEH5Ltt1KIBxbqtoWgHXjS8zIW2GFHphQ5Af0zFaZztsgZVZm0pFbUh6I+gr
         VIOJpRNNqp/xL+/c0rKDzcADod5tovDW+ejbTaqtWNJdTxrBGyi+B9ffDl+1vRt2aCwy
         m3MoQmZmfxngWCOkw2Af8tqzK6fHRIbRuWaPkRd4eE4K7fZFjGu3RvOoc3q4r8J4nqOs
         Nhsg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=4rVrDH6MQrzeJtbyVlq+0cuU+JWPo/JS8IMSlT7kJKo=;
        b=T9JgGKFYMExfUns6lUX/+5Rp2wIjq/HYHxeMW8G8shOSsRnuQYDjD5ePpe7pYdj3Dm
         WuPFwg1JrLZafhjmJ437MnhoFgUo8lAguThTS5MoTB2FuF+DFG6RNeOZOFjB/wX7WggF
         UwJFhciXanuzbBZOTaVnMy28R2EBIJdduucfRwFXmTLVLgr5DOUzfeQdF79LyoGbr9UH
         u2OlvmvQhFKvahlsUimZ+6widsSCZguEcWW5ooe839IwXgRQXVVbteJy+cckNDJApKIH
         E5lamDqOl60o4WU5ItAY0iBt0luV6gvj7rzFzw/73MbNDV9yDpRoTcFCEM/qSkUsOlcS
         q6JA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=google header.b=OWJMz8LL;
       spf=pass (google.com: domain of torvalds@linuxfoundation.org designates 2a00:1450:4864:20::529 as permitted sender) smtp.mailfrom=torvalds@linuxfoundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=4rVrDH6MQrzeJtbyVlq+0cuU+JWPo/JS8IMSlT7kJKo=;
        b=JrCG5CGozQ2FW1u41oP4+pf8OQtZC0Oys17tE7ajCv2VNKaz+aIbhjBHYhe6A6r+Qh
         OPFOpsoFfg7u2c+cvHP1aVjkvOFxlOjN4iAfkfu0jc8jFjTXo9l+M7HZ/Hy/lgv++6BF
         gxFBsqONJdNv3N7RT76gX0GjeCXFkl8tmJuOubBRBIn/c4CBeQY5uPa4PJRxJ2gfcrMS
         ccXcQdNeF9VaGIkuPgnM8zSFtuhsE5q537yy1HmXBPDbIQIO66rXfA8x4kdD5clB1ou0
         Jw+H5GrOyV342ni1Lma1lJrGXMghajEcN+X39OhTj8CyJ/uhWB0SKt4vWyZhV64EO7/w
         s7TQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=4rVrDH6MQrzeJtbyVlq+0cuU+JWPo/JS8IMSlT7kJKo=;
        b=GsmmaKA0DixQEZgJ9stYUHpL3x5ZjrdxuOFHEnLifAjzHt1BCjpEPOaWxb25jksHqI
         /8Al91XA09syZusm9gx7d8OVNyRo/obxYlRMRi83gpd46Y1eyk8pig+ktHoxq5S4oYWX
         fLOg7sCfXx+EhuBWOlImIZGfw9VFXki0Xg23VNM0Gf5HBuwpvClGk8WHPAgu1Bx8jJiG
         5s0z+2mK3HdH9c8wVXMEtWq/okc0lR5XYa35m6EdbfSHVmevZRbRs/pSBCkZWbS9NhAj
         cwpLr7cMEJpIN59n9p6JAa3zMSmiCAan1RVLhCCuB69IPQcJQZNCYf3X4dQyVyvrx2sP
         VduQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530WqJvEDVnUZCAh35MQYDHOt5+maG4PprOf4xqKTvL+X6O9ugoZ
	lAb1k3s0HiSQLqSzqp2+ius=
X-Google-Smtp-Source: ABdhPJzwpY71X3evSKYUWlkCIqA/31LbZ9uglHdpPZe1aBALtOKcNLxiTElzlPpRAJkcecdwIV3+Ew==
X-Received: by 2002:a50:f145:: with SMTP id z5mr3097789edl.4.1631206811255;
        Thu, 09 Sep 2021 10:00:11 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:5941:: with SMTP id g1ls1349009ejr.10.gmail; Thu, 09
 Sep 2021 10:00:10 -0700 (PDT)
X-Received: by 2002:a17:906:1d07:: with SMTP id n7mr4545335ejh.53.1631206808175;
        Thu, 09 Sep 2021 10:00:08 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1631206808; cv=none;
        d=google.com; s=arc-20160816;
        b=X5HNUQf9YJfqDVgoZbyhsgTupxDWmSPV0M6Blq46t08A8w1ukHiT4waCPdsBo1k0oZ
         utR5Wi9IpeXnTJqFJz1NkWpYsu7G4GTkE00dg1JhWaDKu7unDHKOonJUIijNlBxvgaR0
         KpZorzMJfksAcqc3+Pz8spJMtEaDHrgAtGgA3KkZU5G6f6NB1ZBoIAso4qiSu3ukJj4z
         NXSfZW/v1BaKxLZhZdWkKIVwiEjLNdSwNjrzOvyXcbr32kMwRpeDdobu588VSnVAoL/z
         mv4GVQhhU4PkIL/Acz2auTFwPJm8CNEfxo5EF0l1ykk2QmRLxiSgvXxGpI507CU2I+ly
         93lg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=dZAGO3iBrhQAq7cxABN7v0YxXWtGf0YiblsBwMfWyrc=;
        b=TfI2HN83gBI4hMTulSs38fMLt7+Aia61SZJvAQnvNkRxxlK6n4SNa6u1HKXsn41egx
         cRKB1v8DTUiUS6j5jzVzy4vh5sgUjztc4xBrT3iAqhwwQ1ceDMUgnHp2U8YsQ23lxExZ
         uo9hvlbrGFl0I+3OEQd25q9NTbn7iSjR95QqlyXti5DFFiH9HBQ0TbmcoQscbSp+W4VY
         BehrF8X6aMwWQs0F/oANbd+FCvFjE1yobsvT3Kel7SXnivE4KClrLKfkR3myhNSxJGM0
         agIaAf7HwccJcACm3funbnRY8vSjYvYstYAHpPokTOw29We9acgYnoMr1V2K81YNU5ZE
         vTsw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=google header.b=OWJMz8LL;
       spf=pass (google.com: domain of torvalds@linuxfoundation.org designates 2a00:1450:4864:20::529 as permitted sender) smtp.mailfrom=torvalds@linuxfoundation.org
Received: from mail-ed1-x529.google.com (mail-ed1-x529.google.com. [2a00:1450:4864:20::529])
        by gmr-mx.google.com with ESMTPS id n10si113167eje.0.2021.09.09.10.00.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 09 Sep 2021 10:00:08 -0700 (PDT)
Received-SPF: pass (google.com: domain of torvalds@linuxfoundation.org designates 2a00:1450:4864:20::529 as permitted sender) client-ip=2a00:1450:4864:20::529;
Received: by mail-ed1-x529.google.com with SMTP id z19so3559108edi.9
        for <kasan-dev@googlegroups.com>; Thu, 09 Sep 2021 10:00:08 -0700 (PDT)
X-Received: by 2002:aa7:c952:: with SMTP id h18mr4237046edt.18.1631206806936;
        Thu, 09 Sep 2021 10:00:06 -0700 (PDT)
Received: from mail-ej1-f51.google.com (mail-ej1-f51.google.com. [209.85.218.51])
        by smtp.gmail.com with ESMTPSA id s3sm762608edw.38.2021.09.09.10.00.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 09 Sep 2021 10:00:06 -0700 (PDT)
Received: by mail-ej1-f51.google.com with SMTP id kt8so4937900ejb.13
        for <kasan-dev@googlegroups.com>; Thu, 09 Sep 2021 10:00:06 -0700 (PDT)
X-Received: by 2002:a05:6512:3da5:: with SMTP id k37mr583246lfv.655.1631206431030;
 Thu, 09 Sep 2021 09:53:51 -0700 (PDT)
MIME-Version: 1.0
References: <20210906142615.GA1917503@roeck-us.net> <CAHk-=wgjTePY1v_D-jszz4NrpTso0CdvB9PcdroPS=TNU1oZMQ@mail.gmail.com>
 <YTbOs13waorzamZ6@Ryzen-9-3900X.localdomain> <CAK8P3a3_Tdc-XVPXrJ69j3S9048uzmVJGrNcvi0T6yr6OrHkPw@mail.gmail.com>
 <YTkjJPCdR1VGaaVm@archlinux-ax161> <75a10e8b-9f11-64c4-460b-9f3ac09965e2@roeck-us.net>
 <YTkyIAevt7XOd+8j@elver.google.com> <YTmidYBdchAv/vpS@infradead.org>
 <CANpmjNNCVu8uyn=8=5_8rLeKM5t3h7-KzVg1aCJASxF8u_6tEQ@mail.gmail.com>
 <CAK8P3a1W-13f-qCykaaAiXAr+P_F+VhjsU-9Uu=kTPUeB4b26Q@mail.gmail.com> <CANpmjNPBdx4b7bp=reNJPMzSNetdyrk+503_1LLoxNMYwUhSHg@mail.gmail.com>
In-Reply-To: <CANpmjNPBdx4b7bp=reNJPMzSNetdyrk+503_1LLoxNMYwUhSHg@mail.gmail.com>
From: Linus Torvalds <torvalds@linux-foundation.org>
Date: Thu, 9 Sep 2021 09:53:35 -0700
X-Gmail-Original-Message-ID: <CAHk-=wiZqRFx6Oh8ZBer2THTMcjdbwZb5X3fCLBHmyuC9jPDhA@mail.gmail.com>
Message-ID: <CAHk-=wiZqRFx6Oh8ZBer2THTMcjdbwZb5X3fCLBHmyuC9jPDhA@mail.gmail.com>
Subject: Re: [PATCH] Enable '-Werror' by default for all kernel builds
To: Marco Elver <elver@google.com>
Cc: Arnd Bergmann <arnd@kernel.org>, Christoph Hellwig <hch@infradead.org>, 
	Guenter Roeck <linux@roeck-us.net>, Nathan Chancellor <nathan@kernel.org>, 
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>, llvm@lists.linux.dev, 
	Nick Desaulniers <ndesaulniers@google.com>, Paul Walmsley <paul.walmsley@sifive.com>, 
	Palmer Dabbelt <palmer@dabbelt.com>, Albert Ou <aou@eecs.berkeley.edu>, 
	linux-riscv <linux-riscv@lists.infradead.org>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	=?UTF-8?Q?Christian_K=C3=B6nig?= <christian.koenig@amd.com>, 
	"Pan, Xinhui" <Xinhui.Pan@amd.com>, amd-gfx list <amd-gfx@lists.freedesktop.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: torvalds@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=google header.b=OWJMz8LL;
       spf=pass (google.com: domain of torvalds@linuxfoundation.org designates
 2a00:1450:4864:20::529 as permitted sender) smtp.mailfrom=torvalds@linuxfoundation.org
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

On Thu, Sep 9, 2021 at 4:43 AM Marco Elver <elver@google.com> wrote:
>
> Sure, but the reality is that the real stack size is already doubled
> for KASAN. And that should be reflected in Wframe-larger-than.

I don't think that's true.

Quite the reverse, in fact.

Yes, the *dynamic* stack size is doubled due to KASAN, because it will
cause much deeper callchains.

But the individual frames don't grow that much apart from compilers
doing stupid things (ie apparently clang and KASAN_STACK), and if
anything, the deeper dynamic call chains means that the individual
frame size being small is even *more* important, but we do compensate
for the deeper stacks by making THREAD_SIZE_ORDER bigger at least on
x86.

Honestly, I am not even happy with the current "2048 bytes for
64-bit". The excuse has been that 64-bit needs more stack, but all it
ever did was clearly to just allow people to just do bad things.

Because a 1kB stack frame is horrendous even in 64-bit. That's not
"spill some registers" kind of stack frame. That's "put a big
structure on the stack" kind of stack frame regardless of any other
issues.

And no, "but we have 16kB of stack and we'll switch stacks on
interrupts" is not an excuse for one single level to use up 1kB, much
less 2kB.  Does anybody seriously believe that we don't quite normally
have stacks that are easily tens of frames deep?

Without having some true "this is the full callchain" information, the
best we can do is just limit individual stack frames. And 2kB is
*excessive*.

                     Linus

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAHk-%3DwiZqRFx6Oh8ZBer2THTMcjdbwZb5X3fCLBHmyuC9jPDhA%40mail.gmail.com.
