Return-Path: <kasan-dev+bncBDE6RCFOWIARBLMQ5T3QKGQENCY2SQQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13f.google.com (mail-lf1-x13f.google.com [IPv6:2a00:1450:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id 6496620F1C3
	for <lists+kasan-dev@lfdr.de>; Tue, 30 Jun 2020 11:38:54 +0200 (CEST)
Received: by mail-lf1-x13f.google.com with SMTP id m24sf11555710lfh.2
        for <lists+kasan-dev@lfdr.de>; Tue, 30 Jun 2020 02:38:54 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1593509934; cv=pass;
        d=google.com; s=arc-20160816;
        b=kWHcvEq/wO+nB9jlcU/bQu4ZYMDCD3wp47K2x7wz3ajMK61D2J7deghY9VeDiKOMsI
         WmVr4KykVPejtrn+Wsv7EeqSlUvB9UpTcrykrosq5l0p15fhMWwMm7GpESD00cQUvfuO
         BWsBezVBweUtGJM+Fm0JTMck+TQO4yNvR74tvtUo9IFMfzvVs0YpXzIQHQ/P6dfZLsk4
         /93Ya4YCU92FvL7AtnR8PvIprJ423a/mIp0b4nHBkQAzb+30zJvDVv5s+hqqNYz5uQVv
         00B51oMAGUMiJrEDnU3nFVQNk4mz8x7535TO6YFiAFi+D82O+rZHx4IXZEYI7sWkZP4k
         ySRA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=J7RrCzPy032M0Q24rUep+BC9ZQ5c6poT2OduiB+J6Og=;
        b=Vd+Bvm76Qd51MCPG55EXeIchzesCRdyspAXJr1H1q8SJHtdLMzcgJ3f6ULkWbbYLzi
         jOdTW9G2MolOh55REj+/r6LmEwDjR736EG5T7eJibgueNnRAtfhRpUev5OKt75rqjUuv
         gCgZkPpnRXWi0Ujylv00ABnhZnMmWBc5eCPBPOy5Bq7uR8EmWEZUPoJ/uV3Sxt7z9DNs
         Z9vBP3tO7OCmrVzPouYVqdPp5HGW5iXkm3VglEJ4C6+0MQ6GkEdwaV35iwxLGSCn7MKp
         hC7pvQFborHXwbPjnrSyajJkMWqfVGng+XOnBwSbB/OwyIp6RhBKnLO9RiYVWfjZ//kS
         cruQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b="fqd4DR/Z";
       spf=pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::642 as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=J7RrCzPy032M0Q24rUep+BC9ZQ5c6poT2OduiB+J6Og=;
        b=m5X07cjO121U2Xyx/949292Bmn0jrBYTjMKBicEX6VD2Ycg4hoPkJNO1mJ7atL/95P
         IwAZ1FvWbojxWi49BT1SLEF6Nh8wDJ/GWhEbgJxOnMLZ+ShfVQjIkYZuNxLyhTYDWIUJ
         hBBmeUBhffcOgg5VJFWsamstII+EIM9dDprk1bVBCVQa3SxVV3a7OJOR7DB5F08CIbxE
         Qgcogi4VPd/W8KpIEZybWv8JrvuFrPIKo/+6Z/hZNMT3137aC/M0CFu1xrfORIEb0q2w
         wyOJJEzrO/zztt7YB1Poh+Jose+zMJMhojJ8snU0JtmCdo+KsOoGPe8CjUqaF9kDGraZ
         wmHQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=J7RrCzPy032M0Q24rUep+BC9ZQ5c6poT2OduiB+J6Og=;
        b=qagVdkOKhdTAxeWHy54z36SrUeRpuWTb2cyAQnLJ/ozjxw4zf7yUa34O7nt8Y8fNo1
         GTSKCLZ2ZbemwYtApFn0DH7vy5zWGRW62S66/hDtJE5G91JbxKRaGIWiqMddvikQNeHE
         fnWNeuFIUBLBBZKPhGrTwqLMWHj5KmuwZCnLL+u9WeaCchVKA852ZNeyb16ZuYABAgNz
         JtONz05DG0OfPmQY5DybMbfQreboLOWO0rXD9PU2osQnxPyKpYfNkC5iDx7AmeRdQpjq
         yRAXdEuVFlL40bR3Rhc4/WFAz+yQc/cFwTDSihe/g67+fsCWeELEY344irBwfQxPmMxT
         Xcow==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5323denE0F3CVIaaLdDeb/rmB3oo+ZEb7eh271R24Q5vGsE87tPc
	UR9fIzTMFoTB3NazzHGq/JE=
X-Google-Smtp-Source: ABdhPJzCppZhkkgbdJFjPerXgH371u1PaDXV0nW6NVimRxjQXwgQno/kcpv4zonZSlFWOFRlAUSVKQ==
X-Received: by 2002:a2e:810a:: with SMTP id d10mr4526750ljg.144.1593509933925;
        Tue, 30 Jun 2020 02:38:53 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:9190:: with SMTP id f16ls1489832ljg.11.gmail; Tue, 30
 Jun 2020 02:38:53 -0700 (PDT)
X-Received: by 2002:a2e:a54a:: with SMTP id e10mr10357247ljn.198.1593509933258;
        Tue, 30 Jun 2020 02:38:53 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1593509933; cv=none;
        d=google.com; s=arc-20160816;
        b=NzBlBQoffvAXQLEilKyW2ztZG42QqZgjqI+r5rsUcFjn4As5GNoU6vPJj7pIoJMCLa
         JGjt5Gk6hWQHsSmq6hYgT5zPPQEaeFYtd/FlP5vL+GjXMAAl4T/GrNtuKfM4vUgFRy3Y
         21MBfSi3ePOGnH9u3/XIGJvfHdzkxYtUVJmsC3dgWKxGjVN3OaasDsMwjaiNWkRWYTkW
         r5kR/Gwi7rCvq8s/nNivbFmAcGYSV6Mle/WQnrCNtogUHzdo2uBgrUJrwcNnqIwimYxX
         wm4A8JR304lfStgD2mwwiEF431WYQbjvGLbejEhCOXEljzblTEr1m7ULqxHycKWdzrSC
         iNvQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=fmaWewzOpMepreT+cZhaZQ/NoiEUDZB/QrMGwxTrguE=;
        b=C9PU1Ba/M068x6eRt/I4aleI0fJlZw6KYuBp9tpuwVK0LnnLOA1qAVONXlOtN445SM
         Ic6jf8SNYDMtkQIfUT+pbyOuaJhRXyJbq0uuw/wnixdtHJkgBiIwgKG6cHh73+tvKPWH
         fjpPGLjQZrq2tvqiWSTk0Up91ZsNAScS4DE6y00WsJvC4Lp9adAsnSOZY3RGsaOodNRs
         H9c/BDD8+UlDnMXWgFl/ZhaT6KEsIO2tOrxZDfM+Xk59W0SDzU3nXu0knYXyHVMtvhDr
         QFENKl6ZjH2qfv4o6th86FFw9axW/qZnCXQhmAFixyijIu+7vw+Wx5fs+JNquGb+NJ8Q
         5EMg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b="fqd4DR/Z";
       spf=pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::642 as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
Received: from mail-ej1-x642.google.com (mail-ej1-x642.google.com. [2a00:1450:4864:20::642])
        by gmr-mx.google.com with ESMTPS id a15si158991lfb.3.2020.06.30.02.38.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 30 Jun 2020 02:38:53 -0700 (PDT)
Received-SPF: pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::642 as permitted sender) client-ip=2a00:1450:4864:20::642;
Received: by mail-ej1-x642.google.com with SMTP id y10so19858287eje.1
        for <kasan-dev@googlegroups.com>; Tue, 30 Jun 2020 02:38:53 -0700 (PDT)
X-Received: by 2002:a17:906:c943:: with SMTP id fw3mr17214298ejb.55.1593509932782;
 Tue, 30 Jun 2020 02:38:52 -0700 (PDT)
MIME-Version: 1.0
References: <20200615090247.5218-1-linus.walleij@linaro.org>
 <20200615090247.5218-5-linus.walleij@linaro.org> <CACRpkdbuRCXvnaKvAcqQPCWBWmJYQ9orVhWNrOdhUVJUD2Zbbw@mail.gmail.com>
 <20200629143751.GV1551@shell.armlinux.org.uk>
In-Reply-To: <20200629143751.GV1551@shell.armlinux.org.uk>
From: Linus Walleij <linus.walleij@linaro.org>
Date: Tue, 30 Jun 2020 11:38:41 +0200
Message-ID: <CACRpkdb-sHJDRhP-WT+1z3wsVXEvO6_imQvzoosgwLLzNUS60Q@mail.gmail.com>
Subject: Re: [PATCH 4/5 v10] ARM: Initialize the mapping of KASan shadow memory
To: Russell King - ARM Linux admin <linux@armlinux.org.uk>
Cc: Florian Fainelli <f.fainelli@gmail.com>, Abbott Liu <liuwenliang@huawei.com>, 
	Ard Biesheuvel <ardb@kernel.org>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Mike Rapoport <rppt@linux.ibm.com>, Will Deacon <will@kernel.org>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, Arnd Bergmann <arnd@arndb.de>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: linus.walleij@linaro.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linaro.org header.s=google header.b="fqd4DR/Z";       spf=pass
 (google.com: domain of linus.walleij@linaro.org designates
 2a00:1450:4864:20::642 as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
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

On Mon, Jun 29, 2020 at 4:37 PM Russell King - ARM Linux admin
<linux@armlinux.org.uk> wrote:
> On Mon, Jun 29, 2020 at 04:07:06PM +0200, Linus Walleij wrote:
> > Asking for help here!
> >
> > I have a problem with populating PTEs for the LPAE usecase using
> > Versatile Express Cortex A15 (TC1) in QEMU.
> >
> > In this loop of the patch:
> >
> > On Mon, Jun 15, 2020 at 11:05 AM Linus Walleij <linus.walleij@linaro.org> wrote:
> >
> > > +static void __init kasan_pte_populate(pmd_t *pmdp, unsigned long addr,
> > > +                                     unsigned long end, int node, bool early)
> > > +{
> > > +       unsigned long next;
> > > +       pte_t *ptep = pte_offset_kernel(pmdp, addr);
> >
> > (...)
> >
> > > +       do {
> > > +               next = pmd_addr_end(addr, end);
> > > +               kasan_pte_populate(pmdp, addr, next, node, early);
> > > +       } while (pmdp++, addr = next, addr != end && pmd_none(READ_ONCE(*pmdp)));
> >
> > I first populate the PMD for 0x6ee00000 .. 0x6f000000
> > and this works fine, and the PTEs are all initialized.
> > pte_offset_kernel() returns something reasonable.
> > (0x815F5000).
> >
> > Next the kernel processes the PMD for
> > 0x6f000000 .. 0x6f200000 and now I run into trouble,
> > because pte_offset_kernel() suddenly returns a NULL
> > pointer 0x00000000.
>
> That means there is no PTE table allocated which covers 0x6f000000.
>
> "pmdp" points at the previous level's table entry that points at the
> pte, and all pte_offset*() does is load that entry, convert it to a
> pte_t pointer type, and point it to the appropriate entry for the
> address.  So, pte_offset*() is an accessor that takes a pointer to
> the preceding level's entry for "addr", and returns a pointer to
> the pte_t entry in the last level of page table for "addr".
>
> It is the responsibility of the caller to pte_offset*() to ensure
> either by explicit tests, or prior knowledge, that pmd_val(*pmdp)
> is a valid PTE table entry.
>
> Since generic kernel code can't use "prior knowledge", it has to do
> the full checks (see, mm/vmalloc.c vunmap_pte_range() and higher
> levels etc using pmd_none_or_clear_bad() for example - whether you
> can use _clear_bad() depends whether you intend to clear "bad" entries.
> Beware that the 1MB sections on non-LPAE will appear as "bad" entries
> since we can't "walk" them to PTE level, and they're certainly not
> "none" entries.)

Spot on! I figured it out quickly with this hint.

Essentially I have some loops like this:

pmd_t *pmdp = pmd_offset(pudp, addr);

if (pmd_none(*pmdp)) {
    void *p = early ? kasan_early_shadow_pte :
kasan_alloc_block(PAGE_SIZE, node);
    ....
}

do {
    pmd_populate_kernel(&init_mm, pmdp, p);
    flush_pmd_entry(pmdp);
    next = pmd_addr_end(addr, end);
    kasan_pte_populate(pmdp, addr, next, node, early);
} while (pmdp++, addr = next, addr != end && pmd_none(READ_ONCE(*pmdp)));

I just had to move the i (pmd_node(*pmdp)) inside the loop and it all
starts working
fine.

What confuses me is that arm64 does it this way (checking pmdp outside the loop)
for all levels of the cache and it works (I suppose?) for them, but I
suspect it is
formally wrong.

I'll rewrite with the check inside the loop at all levels and retest
and resend, then
I hope this starts to work and look reasonable, finally.

Yours,
Linus Walleij

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACRpkdb-sHJDRhP-WT%2B1z3wsVXEvO6_imQvzoosgwLLzNUS60Q%40mail.gmail.com.
