Return-Path: <kasan-dev+bncBCXO5E6EQQFBBWX2U6FAMGQENSC5AEA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83b.google.com (mail-qt1-x83b.google.com [IPv6:2607:f8b0:4864:20::83b])
	by mail.lfdr.de (Postfix) with ESMTPS id 92425413661
	for <lists+kasan-dev@lfdr.de>; Tue, 21 Sep 2021 17:42:21 +0200 (CEST)
Received: by mail-qt1-x83b.google.com with SMTP id f34-20020a05622a1a2200b0029c338949c1sf217230241qtb.8
        for <lists+kasan-dev@lfdr.de>; Tue, 21 Sep 2021 08:42:21 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1632238940; cv=pass;
        d=google.com; s=arc-20160816;
        b=WCqjtpI7XNCEa9bRepp9aBS1h+exvTKE+XyA8KRkE3EqKcswjKkxhvLNPMJDqI4/vQ
         bLNV02HqiV3zSmHUZManPEl1UYWHVgCfi38u+BIm0haClovsXk56GdZYnAENMCh/nIUr
         zHIqhxDuGAqPTGbvBQnHPESl3YG2dG6ehshSyO/+Inkvy0pJJgWm+9ig3SjRCT/WubNH
         2PcYnSBpFSCKUb8KIQtlT1nHRaH0qsw8bz49kyDkVo/ZK8iZlai2SdRtz5QpNq+E7wiY
         2jS60Y8DxrvqvsZxVUZwvbDu8HmqkBfUvbbEw+FtWxGoDCCx881nVfhKi1dLLSYsPxEh
         Rp/Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=DCfQMnR6js3YIb1nV9ggc7usZc7/UD196moYMdEu8aw=;
        b=KQYAtANErhd558ywijyvEpZEZq4AL0/1tqyQke8ICA2II+g0sTXqz1UhvEgF2NI9af
         o2Wl95IqnCv1X3YBJNNM72ExV4+jI80hfGxYqThtGWQehjDKW5tSt20NB1zUhDE+OFew
         0SK8/jHQel/Vl/HDhbmeW7hcwC8cfLEXz/e9uT0lW1Pck0odFbsxyfrUFDWxWAn3xf6Y
         BLVxll2jj8V6R3d0Wdt9OYTv9AjOg3r7v+zirN8IT/i7N1Ueo76ZuuqOEviHs5oeKusQ
         PlE2GNDqlKRsFIT7oCh4v0MmAVw3ft3Xp6kSCWshDHl7y/sk2mtE9QDPjuTBh60nkhH8
         hDUQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=T8Dele6U;
       spf=pass (google.com: domain of arnd@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=arnd@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=DCfQMnR6js3YIb1nV9ggc7usZc7/UD196moYMdEu8aw=;
        b=Wvc0NFxoTwUgw2wVsvZyZNU4IICpsziwVNILOVgpgKOwtwg3bH35tzlz7XrbjppWBX
         CYXQaqTb9tkLMiiGM+WXmIURWRPfyBuQ0XsrbNggwoI+mcc0FCtzTH9BRV5EOb/UySbO
         JKC0TaqGUXMkZcX2ChUL85UhNK3wDgvqSht1DfstWZlz8XSzcqg3liC6WsqydpatHEdF
         +fhUdoBpyx+LhBEWXZHZz7aAXvBhDE8VyLHVlKU+9yUNWadKCdNDI1Glb1gwUL+o0vM3
         aAIkC3Y6D+0Zij+sl55Z77Vel533pchBrZhjlmn/a+X3eSl6rTGzYSx9z48O/zzZ0n1a
         vSNQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=DCfQMnR6js3YIb1nV9ggc7usZc7/UD196moYMdEu8aw=;
        b=rJFe+rUWcA3U0FHfQhF7jzJiTgaCWDg/G+HCf4EjIfGUJWgGGLw9VLxDLsJDI0K0ni
         gy+WN6m/J46TvbVezL0eXMliFksEyJiJGHAQu0Kn26V4Ik0lKfMeJY0xVXMZmz8w+5pF
         2v5Hj7ObT61Bg9sJD7NQLIzBkv3SS9fsVmp+Yk8LG2WlZMbFtk8Bn8GvOJK+TOeUetC/
         EilK6mktjjqgUUj4KHlsaSvoDzvfc9TcdT4ivFUXp8IvG52lHnCBNGaTY84PkS/Oas36
         XhzQos/vy4h3uliiQC0187MKcvk5BwHEKCuhGjuswzui8E2QZl6Gvum5VzeD61UkLEht
         XeZQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533nqYQWCOYyuJMPfjVAIcRl7NXvBSgh351n8agc7jfcqWdT8JnA
	IgOPhGNsU7N+DqVQYdNt6qs=
X-Google-Smtp-Source: ABdhPJxdHJ8RJx0JHFAk6aIjLjFcwwZAFkx4FPQQJrLjA2KI6oXj38pc0FG3mKruzktJqbPXT0q67A==
X-Received: by 2002:a05:6214:1372:: with SMTP id c18mr29299814qvw.28.1632238938333;
        Tue, 21 Sep 2021 08:42:18 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a37:f608:: with SMTP id y8ls2572417qkj.7.gmail; Tue, 21 Sep
 2021 08:42:17 -0700 (PDT)
X-Received: by 2002:ae9:dd43:: with SMTP id r64mr29822709qkf.225.1632238937894;
        Tue, 21 Sep 2021 08:42:17 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1632238937; cv=none;
        d=google.com; s=arc-20160816;
        b=uXtEoZxhn/ZiMJkE0TQHAaC3FsNOSf5NYyV4q2zYXzZMC+ptMUOPCVWy2v9IekFJh/
         NVUTu6oyhEVi467vtW5khDhYsBQwaieR84744Ce/FQJqnX3NoMscGNMpHMKeWoZR+fjl
         YlhubDVL4dXZBkLbVgnjB5G+xoLIxOxJ0dQzoT/PYRYNN4cQZw/Xsn/ZNLOxqw7A70DR
         GQ4l+QW6DY49zP9eqpiORw/y0XWeL9yIe33VZIf5kCxqkzemKzlkmZCxgoO+P9Y9Lsid
         Vb61xRFgxw4EoMM3RXuOb5VU3fhc46RaV4BF/u5Cd6vG2Vp5318NnPPNzW/rQlDZADUd
         PotQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=mPc1NpD6ms3O/7Nec4dB64rWmPPEIqLSABxVWNM/eRE=;
        b=MvrpeeFmnu5UpkFOqFftIm0CEsPPiIJCIRFN4RYTgDJJVMQ39xsKLDIYGMW9s0nC00
         dNW7gdA/CsIJ+jlXPqYNc0ZXsPzmGxXivgdIDpmd+gSsgW4NoylNFX+u6naBULTDCyaU
         7rWNgbW/KTt14LFw3a1GrF7PdCIG+gTpTPhIBkT/mtRET+Wt/QbnvviENUaJmE6tzorn
         6S1WpWhbwLlmE4SGowCLSyoFWA3ROUbgW1mztfOTJw+CzLY1TvwYClfm8l2dR3XTS/W0
         DTSoftpFejyEvEDucW5znUrAWNWFN7qk1dxdprL3KKy8XwvAMkIkV9QJa7C/FptYkseH
         ScXQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=T8Dele6U;
       spf=pass (google.com: domain of arnd@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=arnd@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id 126si494911qko.4.2021.09.21.08.42.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 21 Sep 2021 08:42:17 -0700 (PDT)
Received-SPF: pass (google.com: domain of arnd@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id DAC6861168
	for <kasan-dev@googlegroups.com>; Tue, 21 Sep 2021 15:42:16 +0000 (UTC)
Received: by mail-wr1-f51.google.com with SMTP id u18so38771049wrg.5
        for <kasan-dev@googlegroups.com>; Tue, 21 Sep 2021 08:42:16 -0700 (PDT)
X-Received: by 2002:a05:600c:3209:: with SMTP id r9mr5344103wmp.35.1632238935395;
 Tue, 21 Sep 2021 08:42:15 -0700 (PDT)
MIME-Version: 1.0
References: <20210906142615.GA1917503@roeck-us.net> <CAHk-=wgjTePY1v_D-jszz4NrpTso0CdvB9PcdroPS=TNU1oZMQ@mail.gmail.com>
 <YTbOs13waorzamZ6@Ryzen-9-3900X.localdomain> <CAK8P3a3_Tdc-XVPXrJ69j3S9048uzmVJGrNcvi0T6yr6OrHkPw@mail.gmail.com>
 <YTkjJPCdR1VGaaVm@archlinux-ax161>
In-Reply-To: <YTkjJPCdR1VGaaVm@archlinux-ax161>
From: Arnd Bergmann <arnd@kernel.org>
Date: Tue, 21 Sep 2021 17:41:58 +0200
X-Gmail-Original-Message-ID: <CAK8P3a0tswcc1icb99cmdX7w0nBc4CAXjaAKJMuYSdJC1MS8YQ@mail.gmail.com>
Message-ID: <CAK8P3a0tswcc1icb99cmdX7w0nBc4CAXjaAKJMuYSdJC1MS8YQ@mail.gmail.com>
Subject: Re: [PATCH] Enable '-Werror' by default for all kernel builds
To: Nathan Chancellor <nathan@kernel.org>
Cc: Linus Torvalds <torvalds@linux-foundation.org>, Guenter Roeck <linux@roeck-us.net>, 
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>, llvm@lists.linux.dev, 
	Nick Desaulniers <ndesaulniers@google.com>, Paul Walmsley <paul.walmsley@sifive.com>, 
	Palmer Dabbelt <palmer@dabbelt.com>, Albert Ou <aou@eecs.berkeley.edu>, 
	linux-riscv <linux-riscv@lists.infradead.org>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	Harry Wentland <harry.wentland@amd.com>, Alex Deucher <alexander.deucher@amd.com>, 
	=?UTF-8?Q?Christian_K=C3=B6nig?= <christian.koenig@amd.com>, 
	xinhui pan <Xinhui.Pan@amd.com>, amd-gfx list <amd-gfx@lists.freedesktop.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: arnd@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=T8Dele6U;       spf=pass
 (google.com: domain of arnd@kernel.org designates 198.145.29.99 as permitted
 sender) smtp.mailfrom=arnd@kernel.org;       dmarc=pass (p=NONE sp=NONE
 dis=NONE) header.from=kernel.org
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

On Wed, Sep 8, 2021 at 10:55 PM Nathan Chancellor <nathan@kernel.org> wrote:
> On Tue, Sep 07, 2021 at 11:11:17AM +0200, Arnd Bergmann wrote:
> > On Tue, Sep 7, 2021 at 4:32 AM Nathan Chancellor <nathan@kernel.org> wrote:
function 'rtw_aes_decrypt' [-Werror,-Wframe-larger-than]
> > > arm32-fedora.log: drivers/gpu/drm/amd/amdgpu/../display/dc/calcs/dce_calcs.c:3043:6: error: stack frame size (1376) exceeds limit (1024) in function 'bw_calcs' [-Werror,-Wframe-larger-than]
> > > arm32-fedora.log: drivers/gpu/drm/amd/amdgpu/../display/dc/calcs/dce_calcs.c:77:13: error: stack frame size (5384) exceeds limit (1024) in function 'calculate_bandwidth' [-Werror,-Wframe-larger-than]
> > >
> > > Aside from the dce_calcs.c warnings, these do not seem too bad. I
> > > believe allmodconfig turns on UBSAN but it could also be aggressive
> > > inlining by clang. I intend to look at all -Wframe-large-than warnings
> > > closely later.
> >
> > I've had them close to zero in the past, but a couple of new ones came in.
> >
> > The amdgpu ones are probably not fixable unless they stop using 64-bit
> > floats in the kernel for
> > random calculations. The crypto/* ones tend to be compiler bugs, but hard to fix
>
> I have started taking a look at these. Most of the allmodconfig ones
> appear to be related to CONFIG_KASAN, which is now supported for
> CONFIG_ARM.
>
> The two in bpmp-debugfs.c appear regardless of CONFIG_KASAN and it turns
> out that you actually submitted a patch for these:
>
> https://lore.kernel.org/r/20201204193714.3134651-1-arnd@kernel.org/
>
> Is it worth resending or pinging that?

I'm now restarting from a clean tree for my randconfig patches to see which
ones are actually needed, will hopefully get to that.

> The dce_calcs.c ones also appear without CONFIG_KASAN, which you noted
> is probably unavoidable.

(adding amdgpu folks to Cc here)

Harry Wentland did a nice rework for dcn_calcs.c that should also be
portable to dce_calcs.c, I hope that he will be able to get to that as well.

Looking at my older patches now, I found that I had only suppressed that one
and given up fixing it, but I did put my analysis into
https://bugs.llvm.org/show_bug.cgi?id=42551, which should be helpful
for addressing it in either the kernel or the compiler.

        Arnd

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAK8P3a0tswcc1icb99cmdX7w0nBc4CAXjaAKJMuYSdJC1MS8YQ%40mail.gmail.com.
