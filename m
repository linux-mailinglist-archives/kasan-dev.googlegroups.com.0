Return-Path: <kasan-dev+bncBD4NDKWHQYDRBK6G4SEQMGQELPBL3QQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x140.google.com (mail-il1-x140.google.com [IPv6:2607:f8b0:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id 7542740405B
	for <lists+kasan-dev@lfdr.de>; Wed,  8 Sep 2021 22:55:08 +0200 (CEST)
Received: by mail-il1-x140.google.com with SMTP id y8-20020a92c748000000b00224811cb945sf2762627ilp.6
        for <lists+kasan-dev@lfdr.de>; Wed, 08 Sep 2021 13:55:08 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1631134507; cv=pass;
        d=google.com; s=arc-20160816;
        b=oxWOouGhq+jXIDt1TB1+phFwFnN9iINTD9sJ5Ys/d1Ux4hUKjt9WgPsxnvCCLA85w8
         NmmHiT8G+xVPXY+uacG6QhdrcR7bA6FaSzHJy+cQfZoQp++Y386F2rYw/0e8NzrpdQre
         0sOlH7DWQyQ2jRNjBPSi4yqy/8aAwXBk4bmhnhK7wYuV9wGHvs9EniS23RHvgFZg6nW3
         2VrGAwA0Swb9090QTBy7m18T2EBxPFJrcL7okIWR37DcWhOPigg0Ii+NUqUOmJKcslei
         cXVdb0zQSLoosrSrnWJdCDTUF8zec2Uo3KByg0S9IT+55gkn4KEWaDQw7jDhK7+llu8P
         Db1w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=ZZ9ZNN9oZ5bdUbp6NztPMoar4htkAdvQvAgzfH++usw=;
        b=zuGEiUcsdYSWHe6aEl0kJIgb0IBgd8k3oCIQ5jkrmbY+fPbTa0gUulznZxFNpB9GmI
         g9QpthZrmzu7P4NEMdPG0lasYoT+HA16xAp4TwsWeJuc4zD1CKxyySz3sBhYYlHsfwdq
         NQlcg4OHwxZlbds84+4/uyFeCzN0JJ+bGSN73HngKAKxXiRui+n4ML1AkRbjUthl8U3/
         WID9EGRWReXIJVdp+8crzEcrs7z2iWxOp6nQD9UbRoWXCO/BxF4L0k/XEu/HSH7JG5Y0
         lM2c19jOHDkjnytMYN0YSG7ymnr60sKXPv9X2xXIoiSccaMUGKOhIZFgVBbqUndpVRM3
         xmAw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=GxBnw5yj;
       spf=pass (google.com: domain of nathan@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=nathan@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=ZZ9ZNN9oZ5bdUbp6NztPMoar4htkAdvQvAgzfH++usw=;
        b=eo4JNpx8NGencwXr0at8zBIzdVLMtTy4AicYYoKiUIkVdxAT83nsdiPH3Vwa92dYuu
         iDJiiDrZrqkxsF2w0KE7qlKxDsW6UixJLkQ+GBheFOjYSUfvsvfjR5T2ksfFc1c6/oI+
         jv9CcyBO03ectj2lGQ+zDBk0TrwH1bnvFTzrB2obRbZp3SCjni+z4BSyT5rp/9XqPaAA
         MoE8t/Poo12ljXmWG91empK0pfa13L8P9QTajx1LlsJmEJSAAIm0JswWlvwKiYxMHteF
         W14dtjm+Ky04pXjEIokEf4RgnMcJqcmHGaxJ7apU2HGvxu4+SVUv2TqQEgFlrZyQdCJy
         5pMQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=ZZ9ZNN9oZ5bdUbp6NztPMoar4htkAdvQvAgzfH++usw=;
        b=vRK+Gwz5fihh282zDuqVGTUlEOxPTOVbSPMPBKxOZVYFxm3zGQjaaNiLS1TLDIS6p/
         oukl/zXRHzv2FtVZjckUL+vseqppbFYvuGoEdLeKnujrsJM4smiJh5RAoMf+8doVhIlY
         J8XOJPkj9/yFO53R+tJP+Zs7fJIfDFpbKndnlZeqUy40DnCj0nPWwX2lckQMnRsuq7cY
         Oi1m9ksCD0REr2aWuGOSquSSf4yLSEEfEMfbYWDaJ2Ran3wc32JVdthjOYTja9DlJOy0
         bJq5d05c3w57X90iXPvPsDGdKc/tuw1aVnI59//AdY8Pn7cc/eJRbPaqAqNPaZ3x7SQj
         Q0Gw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532ZYZiZwraj/DdhmkJ/kdx1NEqxW+ab0kdAWhEXB/93GSTcHDdi
	i/ByOLlfDTGkPalRZngBSWs=
X-Google-Smtp-Source: ABdhPJzvaIwaAV//pe5/eiS6wqBMMS5cy99EY3Jo+33P+R4ZsscVRzKrlUW3zQ7YxIbK5yEW4PZVEQ==
X-Received: by 2002:a6b:e712:: with SMTP id b18mr173269ioh.186.1631134507365;
        Wed, 08 Sep 2021 13:55:07 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:87d6:: with SMTP id q22ls604953ios.7.gmail; Wed, 08 Sep
 2021 13:55:07 -0700 (PDT)
X-Received: by 2002:a05:6602:2c0f:: with SMTP id w15mr186953iov.106.1631134506946;
        Wed, 08 Sep 2021 13:55:06 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1631134506; cv=none;
        d=google.com; s=arc-20160816;
        b=XRqlle4UhiYGRpkH/fQhX+as1ZrX9rxf+34rOXZrgVVK49U9LUjnTLYdvB9KehFXlD
         ViKwLI9SilKXHeoldidnzBYlKI0oaJ6D2GWIqa1W1upTWS9wzWaaN3q8B/MxUHl3W3b/
         PDK2S4tkYlml12Y8DYGDYrzIDHAui56V30MRiBHeOaxOPi286lwqdfezJCbm/5Cmxnev
         L7g1GyA/dOkyRP0mabinRCbtC1QvCvfusJcskqcaL+mebOOc6q5WkiI+Tq+ILSel57mB
         bObELdcrBIPsU9AdKuPR+A9jBRXKzFp3ejpY1J7CGIF97yieQWIhgK/+8J2OHZeN/uvS
         5dKQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=yPxbcfUn4l1k//PKLn0GwIl9m7YTwdQ/EP9R2PXeQNM=;
        b=Bmjuf7BIDURYJ2FqpsjuhxAHCut4JbUS7XRXlE0IcV/G9Whl3dNHIIEjXnHw5otAOW
         UA3lRnz/yIniFYFpdDUqdoq4BIYFP8D86VNVr7KFVTj7cKziYZUsfpSX+Ix5aFl6roww
         +ZcVIF5d23DTlSWbnnLGzi9JreBYmlKIOEgLWr27QiCyXbxG6/WLIxJkFV2B0qFlEuPT
         SOXQ6mfvU8BBSPwyeivDpp0sLisztofy3+S8UKlSgTt5YU0FS7UqUWbZ76wa/GJynIft
         hl7fgM1G5rkB0VMJYnx83U3QFxhRgJ2JrsDASI2USFPIHxi2e7zCxVy/Y7cOaB1Ben0M
         +fPg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=GxBnw5yj;
       spf=pass (google.com: domain of nathan@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=nathan@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id y16si6480ilc.5.2021.09.08.13.55.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 08 Sep 2021 13:55:06 -0700 (PDT)
Received-SPF: pass (google.com: domain of nathan@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id 9036F61158;
	Wed,  8 Sep 2021 20:55:03 +0000 (UTC)
Date: Wed, 8 Sep 2021 13:55:00 -0700
From: Nathan Chancellor <nathan@kernel.org>
To: Arnd Bergmann <arnd@kernel.org>
Cc: Linus Torvalds <torvalds@linux-foundation.org>,
	Guenter Roeck <linux@roeck-us.net>,
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>,
	llvm@lists.linux.dev, Nick Desaulniers <ndesaulniers@google.com>,
	Paul Walmsley <paul.walmsley@sifive.com>,
	Palmer Dabbelt <palmer@dabbelt.com>,
	Albert Ou <aou@eecs.berkeley.edu>, linux-riscv@lists.infradead.org,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>, kasan-dev@googlegroups.com
Subject: Re: [PATCH] Enable '-Werror' by default for all kernel builds
Message-ID: <YTkjJPCdR1VGaaVm@archlinux-ax161>
References: <20210906142615.GA1917503@roeck-us.net>
 <CAHk-=wgjTePY1v_D-jszz4NrpTso0CdvB9PcdroPS=TNU1oZMQ@mail.gmail.com>
 <YTbOs13waorzamZ6@Ryzen-9-3900X.localdomain>
 <CAK8P3a3_Tdc-XVPXrJ69j3S9048uzmVJGrNcvi0T6yr6OrHkPw@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CAK8P3a3_Tdc-XVPXrJ69j3S9048uzmVJGrNcvi0T6yr6OrHkPw@mail.gmail.com>
X-Original-Sender: nathan@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=GxBnw5yj;       spf=pass
 (google.com: domain of nathan@kernel.org designates 198.145.29.99 as
 permitted sender) smtp.mailfrom=nathan@kernel.org;       dmarc=pass (p=NONE
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

Hi Arnd,

On Tue, Sep 07, 2021 at 11:11:17AM +0200, Arnd Bergmann wrote:
> On Tue, Sep 7, 2021 at 4:32 AM Nathan Chancellor <nathan@kernel.org> wrote:
> >
> > arm32-allmodconfig.log: crypto/wp512.c:782:13: error: stack frame size (1176) exceeds limit (1024) in function 'wp512_process_buffer' [-Werror,-Wframe-larger-than]
> > arm32-allmodconfig.log: drivers/firmware/tegra/bpmp-debugfs.c:294:12: error: stack frame size (1256) exceeds limit (1024) in function 'bpmp_debug_show' [-Werror,-Wframe-larger-than]
> > arm32-allmodconfig.log: drivers/firmware/tegra/bpmp-debugfs.c:357:16: error: stack frame size (1264) exceeds limit (1024) in function 'bpmp_debug_store' [-Werror,-Wframe-larger-than]
> > arm32-allmodconfig.log: drivers/gpu/drm/amd/amdgpu/../display/dc/calcs/dce_calcs.c:3043:6: error: stack frame size (1384) exceeds limit (1024) in function 'bw_calcs' [-Werror,-Wframe-larger-than]
> > arm32-allmodconfig.log: drivers/gpu/drm/amd/amdgpu/../display/dc/calcs/dce_calcs.c:77:13: error: stack frame size (5560) exceeds limit (1024) in function 'calculate_bandwidth' [-Werror,-Wframe-larger-than]
> > arm32-allmodconfig.log: drivers/mtd/chips/cfi_cmdset_0001.c:1872:12: error: stack frame size (1064) exceeds limit (1024) in function 'cfi_intelext_writev' [-Werror,-Wframe-larger-than]
> > arm32-allmodconfig.log: drivers/ntb/hw/idt/ntb_hw_idt.c:1041:27: error: stack frame size (1032) exceeds limit (1024) in function 'idt_scan_mws' [-Werror,-Wframe-larger-than]
> > arm32-allmodconfig.log: drivers/staging/fbtft/fbtft-core.c:902:12: error: stack frame size (1072) exceeds limit (1024) in function 'fbtft_init_display_from_property' [-Werror,-Wframe-larger-than]
> > arm32-allmodconfig.log: drivers/staging/fbtft/fbtft-core.c:992:5: error: stack frame size (1064) exceeds limit (1024) in function 'fbtft_init_display' [-Werror,-Wframe-larger-than]
> > arm32-allmodconfig.log: drivers/staging/rtl8723bs/core/rtw_security.c:1288:5: error: stack frame size (1040) exceeds limit (1024) in function 'rtw_aes_decrypt' [-Werror,-Wframe-larger-than]
> > arm32-fedora.log: drivers/gpu/drm/amd/amdgpu/../display/dc/calcs/dce_calcs.c:3043:6: error: stack frame size (1376) exceeds limit (1024) in function 'bw_calcs' [-Werror,-Wframe-larger-than]
> > arm32-fedora.log: drivers/gpu/drm/amd/amdgpu/../display/dc/calcs/dce_calcs.c:77:13: error: stack frame size (5384) exceeds limit (1024) in function 'calculate_bandwidth' [-Werror,-Wframe-larger-than]
> >
> > Aside from the dce_calcs.c warnings, these do not seem too bad. I
> > believe allmodconfig turns on UBSAN but it could also be aggressive
> > inlining by clang. I intend to look at all -Wframe-large-than warnings
> > closely later.
> 
> I've had them close to zero in the past, but a couple of new ones came in.
> 
> The amdgpu ones are probably not fixable unless they stop using 64-bit
> floats in the kernel for
> random calculations. The crypto/* ones tend to be compiler bugs, but hard to fix

I have started taking a look at these. Most of the allmodconfig ones
appear to be related to CONFIG_KASAN, which is now supported for
CONFIG_ARM.

The two in bpmp-debugfs.c appear regardless of CONFIG_KASAN and it turns
out that you actually submitted a patch for these:

https://lore.kernel.org/r/20201204193714.3134651-1-arnd@kernel.org/

Is it worth resending or pinging that?

The dce_calcs.c ones also appear without CONFIG_KASAN, which you noted
is probably unavoidable.

The other ones only appear with CONFIG_KASAN. I have not investigated
each instance to see exactly how much KASAN makes the stack blow up.
Perhaps it is worth setting the default of CONFIG_FRAME_WARN to a higher
value with clang+COMPILE_TEST+KASAN?

> > It appears that both Arch Linux and Fedora define CONFIG_FRAME_WARN
> > as 1024, below its default of 2048. I am not sure these look particurly
> > scary (although there are some that are rather large that need to be
> > looked at).
> 
> For 64-bit, you usually need 1280 bytes stack space to get a
> reasonably clean build,
> anything that uses more than that tends to be a bug in the code but we
> never warned
> about those by default as the default warning limit in defconfig is 2048.
> 
> I think the distros using 1024 did that because they use a common base config
> for 32-bit and 64-bit targets.

That is a fair explanation.

> > I suspect this is a backend problem because these do not really appear
> > in any other configurations (might also be something with a sanitizer?)
> 
> Agreed. Someone needs to bisect the .config or the compiler flags to see what
> triggers them.

For other people following along, there were a lot of
-Wframe-larger-than instances from RISC-V allmodconfig.

Turns out this is because CONFIG_KASAN_STACK is not respected with
RISC-V. They do not set CONFIG_KASAN_SHADOW_OFFSET so following along in
scripts/Makefile.kasan, CFLAGS_KASAN_SHADOW does not get set to
anything, which means that only '-fsanitize=kernel-address' gets added
to the command line, with none of the other parameters.

I guess there are a couple of ways to tackle this:

1. RISC-V could implement CONFIG_KASAN_SHADOW_OFFSET. They mention that
   the logic of KASAN_SHADOW_OFFSET was taken from arm64 but they did
   not borrow the Kconfig logic it seems.

2. asan-stack could be hoisted out of the else branch so that it is
   always enabled/disabled regardless of KASAN_SHADOW_OFFSET being
   defined, which resolved all of these warnings for me in my testing.

I am adding the KASAN and RISC-V folks to CC for this reason.

Cheers,
Nathan

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YTkjJPCdR1VGaaVm%40archlinux-ax161.
