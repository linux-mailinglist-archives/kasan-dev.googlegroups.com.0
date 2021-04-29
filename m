Return-Path: <kasan-dev+bncBDEKVJM7XAHRBTVXVSCAMGQE7VZFX5I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23a.google.com (mail-lj1-x23a.google.com [IPv6:2a00:1450:4864:20::23a])
	by mail.lfdr.de (Postfix) with ESMTPS id 89C4836F146
	for <lists+kasan-dev@lfdr.de>; Thu, 29 Apr 2021 22:49:19 +0200 (CEST)
Received: by mail-lj1-x23a.google.com with SMTP id e15-20020a05651c038fb02900ba7bf7d589sf18209067ljp.20
        for <lists+kasan-dev@lfdr.de>; Thu, 29 Apr 2021 13:49:19 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1619729359; cv=pass;
        d=google.com; s=arc-20160816;
        b=usqDrl8TN4YZ6jXbZF+QTjh05ZEwBrHRCr1JX1rV7LOTd8o1Hc0VaSt9K3rgtor0IW
         9qgq27U7Gfw1olBmrONkaTwxAdVjkzSxx/VEn9Bx83j9v3gfW25jWDv1Bq3ScGE/zG+L
         ysX53i3Z0NOzCAKQVokfkesLrawPS7QSx0Oix/eTphNuycOfwf6IWZ9maqwvbpsFu34T
         8a2ilsmHdZK8TZEEhcuuLbNG85RsGarcbw9BlZ6x0dm9m36DwN/zibq3V6vfOWbaNyrF
         RmA4Fn93m3R2/xBuikpInvqrH40dJLtyaPeuah4L9UCjr0JeXnN+v8kxWsdp6m1DhTMu
         EDFQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=TG8qHB+GNZLICBT2xTlqCSM1h0f3YEjGVoq5JZ2d/6c=;
        b=NOo+pVQNnc3PcPTgc9nYeo+nrpbbTaMnoewYshXN5OLOT20Fc7sL9tlHkH1u0An5iL
         XBfApkhXr7QHaGz8QkVawzgvMyxMulehnh/hy46xai9vFY/wM/aJvZuwujx1NphjycCE
         Nq4VcWbg1RfXkzK0+46Q60EiOgvPzBHZo7FgUsYRm4k040vzyKWwcWxNaAsemYEKAr5y
         9it29CbPop9p23aFTJ7IpzC1VA8cetJu7L1/2+LEp41p8NKRxsSFoIXd2+mAI1TqOPoJ
         qCwGIOQg9Y+KG5L9Tjye8w8R3Qy4eCE3RCq2U78NG1S2JszxsxbOwwpi9yrq+jI6VlHg
         wxdg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=neutral (google.com: 212.227.126.131 is neither permitted nor denied by best guess record for domain of arnd@arndb.de) smtp.mailfrom=arnd@arndb.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=TG8qHB+GNZLICBT2xTlqCSM1h0f3YEjGVoq5JZ2d/6c=;
        b=phSr5O/4kws5PXPjIR73ZVN0bLpoEJm4I7EN54z0ns/HuXyHHvYxvZRkgFiq9IPEhl
         0OCstmkndYIdEbkbjsqYIJ4vMZL7heVEsLgpd8DLnZt8OgxAPd00bM7I7HDXPPfUGOGq
         EzIL/p4AINlFawhYB+FqdXbTLHOkfbaRtgVdQDFGtUn2LKinnGiP6rEuq5OBG1QZ9O+C
         xnStdUsyuziXqbyAa+B1wa+RzQeF93s15xAzvIN5zRnx2IQG4vpv7O1hTTgU18xYP85I
         canak0+11uYzOQaOdh6RJUIKDUT1SNWmrsiJqZFqbMfyE23m2v8AAgrbQqncfwHSnhMC
         yYYg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=TG8qHB+GNZLICBT2xTlqCSM1h0f3YEjGVoq5JZ2d/6c=;
        b=XBJQ2ivsYgS3jqHbvicVXlDl25+8CLTw0pMr/Wy3FzrkV5+/RO/j/lCa6e6gVQv+O5
         8jsJcMpy8taDbVzuHjwckEkAPQ/ZEfwxOedsytSMg9kiq6bV6cF/o5O4jnacHepwkSge
         KL4tpThCs5XrJms8okblc87G79EsgZusF9iC3KnP7J6FWaTvCHFlrcNfk1XtDjlfSloh
         yrKZLodREcy4032wpBdT+ZwqoqHzJiqQ2E2glLs9GOaSuQ/U8r79ToO+Ye/tP4AFnNPZ
         7Nnnao8gk1VZ6FIJMG554SUjjlW2JfhOdVlXGiz+0uA+gAdDrl/FO1yDU7+imAgOhCM2
         H8BQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532+tYQfsiLmCJeDdOuT6wLDBIcUswjaeNgnJW8XTwSUEJTWDWkJ
	dezSgST+fDtFJDwjsxm9tXg=
X-Google-Smtp-Source: ABdhPJyTZRqc6UQGnrl4csdZjuy8VGsUjcOTeJ4b0PowKzJuARwczKA6wB3LY2jX00ZKc/fRTrUnfA==
X-Received: by 2002:a05:6512:3ce:: with SMTP id w14mr986113lfp.90.1619729359120;
        Thu, 29 Apr 2021 13:49:19 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:bc14:: with SMTP id b20ls354686ljf.10.gmail; Thu, 29 Apr
 2021 13:49:18 -0700 (PDT)
X-Received: by 2002:a2e:921a:: with SMTP id k26mr1152010ljg.149.1619729358048;
        Thu, 29 Apr 2021 13:49:18 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1619729358; cv=none;
        d=google.com; s=arc-20160816;
        b=wtZFbGdQeyE9fnD7HPj/5t8zSxQIX4NQUGs+1mOkUzvx/4NAnJdZrgYQCcfxvW1hBZ
         LJlsrB/AigvYuLbkTAVTI6kFQYF0kzwiIjK0dh+UioCxjO2W6U67FoiabFEXomEcZ4Dc
         rKQamr7P9EdmENNdOlqalRIdtYLmhRPer+Eo0+bz/2nn0DZ6sin5He6xdNKf89a7LFP7
         bWj8fh+F773FsxwTGMnlxqDpcy0t88MSwnvWNe5C7MiNJCNkR/EUt0Ggctr47fJhaskU
         0orsUG64bYIdUMDL5dDEY7T68Ph0Cw+2kKERLod63NEWckG81G6uj+FVMvkub1j0SctU
         3Rdg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version;
        bh=XPKr2OzxzEqAz4j8KYhUwNIVrgXX0dgHlgZCIhSjrP4=;
        b=n+NbaaVmKCWNAPhwceKYvYAoa0OoNZW7PhpH/jXBF8obuN/fiBdjcxtlSieX9iYnyE
         TTGqp8LHXtQQp3HCsa3ClTIVqoeU+3XbpD3U4VSPXdTf/uXxn3N4LIojtoTtpcoI/6ca
         SaKT9SAEHpb0rxW8vi1W4y/pIITahUHNK8+aWLabsgxQ47ruxLwwCJw6yXhrkpiIa4x0
         mFp3oaOQ70pSQaFUlOx+33rWKUV7daVyRyXFLav3qCDDF3Kf2+wn7RiXmnziHqxfiiuk
         BbaOo0CUULpvDG2JcAZzZ/P40PVyijHe5xPLpnyeKbt1S51mxUn+/ysJOcd1hOgrY53d
         GsDQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=neutral (google.com: 212.227.126.131 is neither permitted nor denied by best guess record for domain of arnd@arndb.de) smtp.mailfrom=arnd@arndb.de
Received: from mout.kundenserver.de (mout.kundenserver.de. [212.227.126.131])
        by gmr-mx.google.com with ESMTPS id z33si57023lfu.12.2021.04.29.13.49.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 29 Apr 2021 13:49:17 -0700 (PDT)
Received-SPF: neutral (google.com: 212.227.126.131 is neither permitted nor denied by best guess record for domain of arnd@arndb.de) client-ip=212.227.126.131;
Received: from mail-wm1-f44.google.com ([209.85.128.44]) by
 mrelayeu.kundenserver.de (mreue010 [213.165.67.97]) with ESMTPSA (Nemesis) id
 1MXGak-1m5Rhb18pC-00YfoJ for <kasan-dev@googlegroups.com>; Thu, 29 Apr 2021
 22:49:17 +0200
Received: by mail-wm1-f44.google.com with SMTP id o26-20020a1c4d1a0000b0290146e1feccdaso809068wmh.0
        for <kasan-dev@googlegroups.com>; Thu, 29 Apr 2021 13:49:17 -0700 (PDT)
X-Received: by 2002:a7b:c4da:: with SMTP id g26mr2183043wmk.43.1619729356972;
 Thu, 29 Apr 2021 13:49:16 -0700 (PDT)
MIME-Version: 1.0
References: <YIpkvGrBFGlB5vNj@elver.google.com> <m11rat9f85.fsf@fess.ebiederm.org>
In-Reply-To: <m11rat9f85.fsf@fess.ebiederm.org>
From: Arnd Bergmann <arnd@arndb.de>
Date: Thu, 29 Apr 2021 22:48:40 +0200
X-Gmail-Original-Message-ID: <CAK8P3a0+uKYwL1NhY6Hvtieghba2hKYGD6hcKx5n8=4Gtt+pHA@mail.gmail.com>
Message-ID: <CAK8P3a0+uKYwL1NhY6Hvtieghba2hKYGD6hcKx5n8=4Gtt+pHA@mail.gmail.com>
Subject: Re: siginfo_t ABI break on sparc64 from si_addr_lsb move 3y ago
To: "Eric W. Biederman" <ebiederm@xmission.com>
Cc: Marco Elver <elver@google.com>, Florian Weimer <fweimer@redhat.com>, 
	"David S. Miller" <davem@davemloft.net>, Peter Zijlstra <peterz@infradead.org>, 
	Ingo Molnar <mingo@kernel.org>, Thomas Gleixner <tglx@linutronix.de>, 
	Peter Collingbourne <pcc@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, sparclinux <sparclinux@vger.kernel.org>, 
	linux-arch <linux-arch@vger.kernel.org>, 
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>, Linux API <linux-api@vger.kernel.org>, 
	kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Provags-ID: V03:K1:nhwgJwoQis991zuj1ZzDgJoABx2FGq+WUbHzY2d3dYZtp655e8Y
 V8UVmAUyIxqh37fq8tvQc5gfQapGdDW9biSy9cimslGTLUbTDKa6ihOkzmcf3Dfh4go/g3Q
 QZkTD6s548kHzNnvgEr+mz4SKuwNmk+uUiZ1xEy7g3thXGBlQQVOpcEwPFm5wl/w6P407ma
 lM7g4aigFXDHp8dw4Sd7g==
X-Spam-Flag: NO
X-UI-Out-Filterresults: notjunk:1;V03:K0:qsbVtB6y8lM=:BGI0Gqezxnuk9GGezPOE5G
 B4yhHSTC/FfY8mN8oHJQzySXC5sXo+7ku0yIXlynW+XGr/46XoKGZdZ0ou8EOtH1IHukBV3fn
 lhcuGkqa9NG/79/CZOrSSUuQsi0YOOpe1lRuS+0uNs+br1n9V58u1snuSkto08GQSd4q1H8+O
 csBSt1VFM7KvQlpzgqKcFUd3UgT8hdcOh/9ACSfRuhqnTFC9EQfCxTmaDvIar830L0FCv7BdZ
 JRJmNk+Pc8YQT1adaxYxDSeiqYUns16EjFXRxUe/iZIsN+74CWGtkJpthl33eJxssqLyFbTvg
 tEBqHhnPGYET+rA3UA5CPTjKOjKjIsFnF2fK4p819tCvnyO6Y6uLLuWsbzrCJvdiauRFNpQIm
 WEGVoZ+AQyu/ES9Gnzv823v/R3SoiaGw0L/aYsuK+cVzPuyEOXXZymH8aMYqY0olhDUy7f/Jh
 GhvuV2Psi0Lg6V4rkVOoeV6Ebm7HQm2/v649DBVaVsA4xsX8JuCKPGfYbr4xN6Ou+PQXFgF61
 iZ8IKpswkT8kG0h7/5GFs0=
X-Original-Sender: arnd@arndb.de
X-Original-Authentication-Results: gmr-mx.google.com;       spf=neutral
 (google.com: 212.227.126.131 is neither permitted nor denied by best guess
 record for domain of arnd@arndb.de) smtp.mailfrom=arnd@arndb.de
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

On Thu, Apr 29, 2021 at 7:23 PM Eric W. Biederman <ebiederm@xmission.com> wrote:

> > Which option do you prefer? Are there better options?
>
> Personally the most important thing to have is a single definition
> shared by all architectures so that we consolidate testing.
>
> A little piece of me cries a little whenever I see how badly we
> implemented the POSIX design.  As specified by POSIX the fields can be
> place in siginfo such that 32bit and 64bit share a common definition.
> Unfortunately we did not addpadding after si_addr on 32bit to
> accommodate a 64bit si_addr.
>
> I find it unfortunate that we are adding yet another definition that
> requires translation between 32bit and 64bit, but I am glad
> that at least the translation is not architecture specific.  That common
> definition is what has allowed this potential issue to be caught
> and that makes me very happy to see.
>
> Let's go with Option 3.
>
> Confirm BUS_MCEERR_AR, BUS_MCEERR_AO, SEGV_BNDERR, SEGV_PKUERR are not
> in use on any architecture that defines __ARCH_SI_TRAPNO, and then fixup
> the userspace definitions of these fields.
>
> To the kernel I would add some BUILD_BUG_ON's to whatever the best
> maintained architecture (sparc64?) that implements __ARCH_SI_TRAPNO just
> to confirm we don't create future regressions by accident.
>
> I did a quick search and the architectures that define __ARCH_SI_TRAPNO
> are sparc, mips, and alpha.  All have 64bit implementations.

I think you (slightly) misread: mips has "#undef __ARCH_SI_TRAPNO", not
"#define __ARCH_SI_TRAPNO". This means it's only sparc and
alpha.

I can see that the alpha instance was added to the kernel during linux-2.5,
but never made it into the glibc or uclibc copy of the struct definition, and
musl doesn't support alpha or sparc. Debian codesearch only turns up
sparc (and BSD) references to si_trapno.

> I did a quick search and the architectures that define __ARCH_SI_TRAPNO
> are sparc, mips, and alpha.  All have 64bit implementations.  A further
> quick search shows that none of those architectures have faults that
> use BUS_MCEERR_AR, BUS_MCEERR_AO, SEGV_BNDERR, SEGV_PKUERR, nor do
> they appear to use mm/memory-failure.c
>
> So it doesn't look like we have an ABI regression to fix.

Even better!

So if sparc is the only user of _trapno and it uses none of the later
fields in _sigfault, I wonder if we could take even more liberty at
trying to have a slightly saner definition. Can you think of anything that
might break if we put _trapno inside of the union along with _perf
and _addr_lsb?

I suppose in theory sparc64 or alpha might start using the other
fields in the future, and an application might be compiled against
mismatched headers, but that is unlikely and is already broken
with the current headers.

       Arnd

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAK8P3a0%2BuKYwL1NhY6Hvtieghba2hKYGD6hcKx5n8%3D4Gtt%2BpHA%40mail.gmail.com.
