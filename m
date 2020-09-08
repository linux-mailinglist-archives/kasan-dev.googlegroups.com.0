Return-Path: <kasan-dev+bncBDTJXNWA5IDBB7N4375AKGQEGQ4SSCI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x439.google.com (mail-pf1-x439.google.com [IPv6:2607:f8b0:4864:20::439])
	by mail.lfdr.de (Postfix) with ESMTPS id 23A48261DBF
	for <lists+kasan-dev@lfdr.de>; Tue,  8 Sep 2020 21:41:51 +0200 (CEST)
Received: by mail-pf1-x439.google.com with SMTP id e12sf219786pfm.0
        for <lists+kasan-dev@lfdr.de>; Tue, 08 Sep 2020 12:41:51 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1599594109; cv=pass;
        d=google.com; s=arc-20160816;
        b=M+JzF4szZ9VcQNK4WIz6Eg0mjjGYFmNAD4sdN9tAD6q3hWMMQbKyc1BBGEqSNLtA0e
         m6Hz8s2OmZVe75qskHfY80V/NGHODXmnLGib9xmwR7SuqlKGwlpERRn5Ar7q5ZAA6iZ6
         0Jb4+bbKZvle5MCyo4gFeUOjEwoGCnUlP4zlfJPoSOPeLpjVmu/9yhA9HJPR8SrAWMN0
         ThUMy0q9bKufF2foUOu+sOez9hfwczhLgC5okSPTCJH4K0Gp9b8lIl+1YwF8jclMbswS
         UvUtILeHyLLgFjve9nDIZH+3XeF/SHF+Bw9K2F+fYZTNPIOHO1XpeMTLg9W0uX2iFWgg
         XvmQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=iy0iPxMFa5u2Ed0EpXtW0UI4W94ayTaUNsbfyFNXijM=;
        b=NF38m+rln/EGPdbMUM7Dgx7BSYBykLNGMuYloV4mVPjHMEHe8+xveixrH9zF+E5m4L
         txNiRv7SdsKdxmaVxSkTYNuILSpKhiqYqRzbDhjxeryPkC27G/QwETVEeNpxu0XNzzaY
         5ksKSkiA0v95SuuwgegChRmOa6pVRPjFbQ6PTCFzNgpqcVwKPU1rsOuRzUhJsljZU4rh
         f8gSygQjodjN8JnSmkwlZ68uK5MMkts8qLCHbqDonyJsMeN7kfBT4PeDLksOPzekuWsr
         s7elGgBoCQTHZeHUWw0grBQLslDdXspZYeM91bCO6cDivaZBlVdow+3cwLn+J352zsde
         gvUA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=RwAuRwk7;
       spf=pass (google.com: domain of derrick.mckee@gmail.com designates 2607:f8b0:4864:20::f44 as permitted sender) smtp.mailfrom=derrick.mckee@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=iy0iPxMFa5u2Ed0EpXtW0UI4W94ayTaUNsbfyFNXijM=;
        b=qs7dN0jhZzzz7nhM0kIawgbdx8qaLuB4YhXl2IxLL78/rykZTCdVUogDT9joyZNt7E
         5Z/jXb4TPNd2Q9mREBjLGKKKEJDjdsYaBZfs92c+cvybKUuEv8vOh1zwR8rxEvtJGmTu
         e/3f/3DVT1IdhpCkLqzD+5n+zWAFrM0c+f9AHnbAM6FoUh1dOQIb8MRFum1KMRXtgJ4S
         0NhRL9LLQm229N4ulA4U3HhOyumVrYAdvROak9Zkq9bI2u11LNAvpYxs5Q69rF9HSL1/
         G5rEVgsp0fo6uFp7o87+MoX6FlCrmtpxN47VXiMDnanndJeF4/Viq0v/+cbPFwQ0THS/
         MO8Q==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=iy0iPxMFa5u2Ed0EpXtW0UI4W94ayTaUNsbfyFNXijM=;
        b=n3x4Zh4sPK2kseeQkw+9jQiFPVTK3dR5V2Qm5rpT27S3oTizCz5GGXrWgyz4d+0peG
         kP5RMU6oEQJxUQJ5VpKpzxUGaat6PcfAyO1h5p3NZIM2zv6vltu0TI86Wmo/Z2sLgNpA
         Be0ObRW9MLuuXut08TcL7evjd1Cibw5Y09a8q2OvY0gBHA4A3u5dmVrAOqKr+Op0lpwH
         IQ/FCDZUBWvdzSIaZaXIqH1QZ8ds7BgAMuE4i18PogBnd4a2qkIhoEFEdOCyBEsyPm9F
         2gppsh8CwWqfh0JO1eOI8H8OMuoXFP8aUxhMCDoKgqc+mbaOLuRbm/C7H1CLo41CFxBu
         +A/Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=iy0iPxMFa5u2Ed0EpXtW0UI4W94ayTaUNsbfyFNXijM=;
        b=PQBrFihBPUToysxgmKau8PvsdsOYB3ybcJAWauc1V/2lhjf2uN7EiTCGTeypltqZTT
         zh8nDxnl9U8mG37s8rq+NZbeO+cEUUfuFrU9ZAUgaayXBdi8uYzfCnGlxdYwO5qEqwGI
         M0CtMSz1/t6WzH3H62ic75bkOPsKiCdW1L9mUA5iDX7nUe1IH0PXe4rQ4u/szN4Uf+UH
         XymNAmj5MDuTK3PyKPQ9QmFsBBh1dRqKpm6DfJDAPiP/uE2T9LW9zc/uS7f45akbOCSw
         v1jjki1w4nIwJ0xHsVOSraRTe9Zc2X1F8nHiRsd7NJQwVni54AU9mDH7RYCNw41kmQfL
         /+GA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533Hy8gPJZH+Db9hOkzu3wH1mH/7JQ2pgmge4/Uz2k0J08XO7OLY
	+6mumrB8pgiK3cNcpM4hD+k=
X-Google-Smtp-Source: ABdhPJzjlSoOKVGfsGlelrzuwmoE8wPxPG+jhp2hTn4aH8NT5MNtbqgSF2A8Se9+u9AKhHye1OxaUA==
X-Received: by 2002:a63:c40d:: with SMTP id h13mr230608pgd.185.1599594109395;
        Tue, 08 Sep 2020 12:41:49 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:8d89:: with SMTP id v9ls198836plo.4.gmail; Tue, 08
 Sep 2020 12:41:48 -0700 (PDT)
X-Received: by 2002:a17:90b:357:: with SMTP id fh23mr339908pjb.221.1599594108730;
        Tue, 08 Sep 2020 12:41:48 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1599594108; cv=none;
        d=google.com; s=arc-20160816;
        b=G3fu3xZWxpBeAdXPmlpVV5oqZu972uy5093Z/YZ8cJFd6Yo8/gIv78YXrZsklAq9lE
         mWEPo8BP/HBC+XjvtLFl3E7UW6ITD3hjLSR06tAqpeDglRjlWKEBzUwZi8+PzQWDM4EC
         tLig0WNW8UJiZMAqDrsGTzbU24XNcLdB8DCQ2R4+dX9eC/PzAtaKRnHwRhwWMOuO+6yI
         f+b7awxlcy58Fx1kaa+hNr0QvUtBlxfsXWN7VNMygPiSkp+PpDRZMtRWAtNgZp8lYXpO
         8IS5e5UB2nb427pi4qtzHeYpJeohCxJ+zCaEodMaG2LfTALdxk+5ZnO5uvB3m+aUTuvc
         6/kA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=B/dG9jEncAs6+nkD7fnq9LTKRpUa08FrYgm5ZlkQNI8=;
        b=S00FzP4x3tLff1v2nmhWT9cczrwZ0HZ9Zyw4J+if9yluFfO6Mb6pxsCZyWpHbrjtH0
         92XII7HDp6Vs137ey+zDmCcGukg7gaND+UWF1q+VRtRlLUP/6TMn5Xn30KPX9sOYqSge
         9lx95YutESFzfX0gInmMC580mjD3qPXYtg3xpm69CAOoTT21un+9f86GsH4TEjWc0DEG
         nO649G6gEiWRwJBRm43utaUo8HXmXxrB5Py9QJXSJL0DiG4OtrBoZVbrMWLmSxgJ+Qy9
         bEEvxgxspaUBCGDfTUJ6STd4IKPwjshw8PVhMyyU0DNqT9guCqypCZZnulcXruzbyHlZ
         Q6Qw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=RwAuRwk7;
       spf=pass (google.com: domain of derrick.mckee@gmail.com designates 2607:f8b0:4864:20::f44 as permitted sender) smtp.mailfrom=derrick.mckee@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-qv1-xf44.google.com (mail-qv1-xf44.google.com. [2607:f8b0:4864:20::f44])
        by gmr-mx.google.com with ESMTPS id iq17si22766pjb.3.2020.09.08.12.41.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 08 Sep 2020 12:41:48 -0700 (PDT)
Received-SPF: pass (google.com: domain of derrick.mckee@gmail.com designates 2607:f8b0:4864:20::f44 as permitted sender) client-ip=2607:f8b0:4864:20::f44;
Received: by mail-qv1-xf44.google.com with SMTP id cv8so300828qvb.12
        for <kasan-dev@googlegroups.com>; Tue, 08 Sep 2020 12:41:48 -0700 (PDT)
X-Received: by 2002:a05:6214:bcf:: with SMTP id ff15mr784046qvb.39.1599594108271;
 Tue, 08 Sep 2020 12:41:48 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1597425745.git.andreyknvl@google.com> <ec314a9589ef8db18494d533b6eaf1fd678dc010.1597425745.git.andreyknvl@google.com>
 <20200827103819.GE29264@gaia> <8affcfbe-b8b4-0914-1651-368f669ddf85@arm.com>
 <20200827121604.GL29264@gaia> <CAAeHK+yYEFHAQMxhL=uwfgaejo3Ld0gp5=ss38CjW6wyYCaZFw@mail.gmail.com>
 <20200908153910.GK25591@gaia>
In-Reply-To: <20200908153910.GK25591@gaia>
From: Derrick McKee <derrick.mckee@gmail.com>
Date: Tue, 8 Sep 2020 15:41:37 -0400
Message-ID: <CAJoBWHy9=hJ-GCCYjUm2=HKOiHbue2cXO1TBNx0LsCQKAqO02A@mail.gmail.com>
Subject: Re: [PATCH 24/35] arm64: mte: Switch GCR_EL1 in kernel entry and exit
To: Catalin Marinas <catalin.marinas@arm.com>
Cc: Andrey Konovalov <andreyknvl@google.com>, Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Marco Elver <elver@google.com>, Elena Petrova <lenaptr@google.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	LKML <linux-kernel@vger.kernel.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, Alexander Potapenko <glider@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Dmitry Vyukov <dvyukov@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: derrick.mckee@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=RwAuRwk7;       spf=pass
 (google.com: domain of derrick.mckee@gmail.com designates 2607:f8b0:4864:20::f44
 as permitted sender) smtp.mailfrom=derrick.mckee@gmail.com;       dmarc=pass
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

Hello,

Is the branch where the MTE patches currently are being applied
for-net/mte?  It looks like that's the place, but I want to confirm.

On Tue, Sep 8, 2020 at 11:42 AM Catalin Marinas <catalin.marinas@arm.com> wrote:
>
> On Tue, Sep 08, 2020 at 04:02:06PM +0200, Andrey Konovalov wrote:
> > On Thu, Aug 27, 2020 at 2:16 PM Catalin Marinas <catalin.marinas@arm.com> wrote:
> > > On Thu, Aug 27, 2020 at 11:56:49AM +0100, Vincenzo Frascino wrote:
> > > > On 8/27/20 11:38 AM, Catalin Marinas wrote:
> > > > > On Fri, Aug 14, 2020 at 07:27:06PM +0200, Andrey Konovalov wrote:
> > > > >> diff --git a/arch/arm64/kernel/mte.c b/arch/arm64/kernel/mte.c
> > > > >> index 7717ea9bc2a7..cfac7d02f032 100644
> > > > >> --- a/arch/arm64/kernel/mte.c
> > > > >> +++ b/arch/arm64/kernel/mte.c
> > > > >> @@ -18,10 +18,14 @@
> > > > >>
> > > > >>  #include <asm/barrier.h>
> > > > >>  #include <asm/cpufeature.h>
> > > > >> +#include <asm/kasan.h>
> > > > >> +#include <asm/kprobes.h>
> > > > >>  #include <asm/mte.h>
> > > > >>  #include <asm/ptrace.h>
> > > > >>  #include <asm/sysreg.h>
> > > > >>
> > > > >> +u64 gcr_kernel_excl __read_mostly;
> > > > >
> > > > > Could we make this __ro_after_init?
> > > >
> > > > Yes, it makes sense, it should be updated only once through mte_init_tags().
> > > >
> > > > Something to consider though here is that this might not be the right approach
> > > > if in future we want to add stack tagging. In such a case we need to know the
> > > > kernel exclude mask before any C code is executed. Initializing the mask via
> > > > mte_init_tags() it is too late.
> > >
> > > It depends on how stack tagging ends up in the kernel, whether it uses
> > > ADDG/SUBG or not. If it's only IRG, I think it can cope with changing
> > > the GCR_EL1.Excl in the middle of a function.
> > >
> > > > I was thinking to add a compilation define instead of having gcr_kernel_excl in
> > > > place. This might not work if the kernel excl mask is meant to change during the
> > > > execution.
> > >
> > > A macro with the default value works for me. That's what it basically is
> > > currently, only that it ends up in a variable.
> >
> > Some thoughts on the topic: gcr_kernel_excl is currently initialized
> > in mte_init_tags() and depends on the max_tag value dynamically
> > provided to it, so it's not something that can be expressed with a
> > define. In the case of KASAN the max_tag value is static, but if we
> > rely on that we make core MTE code depend on KASAN, which doesn't seem
> > right from the design perspective.
>
> The design is debatable. If we want MTE to run on production devices, we
> either (1) optimise out some bits of KASAN (configurable) or (2) we
> decouple MTE and KASAN completely and add new callbacks in the core code
> (slab allocator etc.) specific to MTE.
>
> My first choice is (1), unless there is a strong technical argument why
> it is not possible.
>
> --
> Catalin
>
> _______________________________________________
> linux-arm-kernel mailing list
> linux-arm-kernel@lists.infradead.org
> http://lists.infradead.org/mailman/listinfo/linux-arm-kernel



-- 
Derrick McKee
Phone: (703) 957-9362
Email: derrick.mckee@gmail.com

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAJoBWHy9%3DhJ-GCCYjUm2%3DHKOiHbue2cXO1TBNx0LsCQKAqO02A%40mail.gmail.com.
