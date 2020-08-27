Return-Path: <kasan-dev+bncBDX4HWEMTEBRBXOBT35AKGQEBFX2DYA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x438.google.com (mail-pf1-x438.google.com [IPv6:2607:f8b0:4864:20::438])
	by mail.lfdr.de (Postfix) with ESMTPS id 515292544B2
	for <lists+kasan-dev@lfdr.de>; Thu, 27 Aug 2020 14:02:39 +0200 (CEST)
Received: by mail-pf1-x438.google.com with SMTP id f10sf4075801pfd.18
        for <lists+kasan-dev@lfdr.de>; Thu, 27 Aug 2020 05:02:39 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1598529758; cv=pass;
        d=google.com; s=arc-20160816;
        b=zVJj1QXEIfVIu0sZ2fp4silV8puhzCPV8urU50XW8h2rai9tzpVRa2/brURDnvoPT0
         FFpQ9PzJDt+SuT8V4YpB1G98dr4wpzynsus3hbIpy+LrH7bdOePtTGM5Tr/njHh9xPYJ
         k0RTCE98fQMJg9PoDTfxoM9rxt9b1KIL1a5japu2W6SU4BUmMXWA6oTwgITuFjR1gQVJ
         b1djx1t5U9Dcjo05ED8z+N9KC1jDHEENCampGwV/lgVX4PLlsZKQIReUB+rhVPXMsYEn
         v5Lj5mQ1mpkrknVhKc+GbbrgoS/mtFFzewWBYIPPbtnJG5ZP9RYL4WC5FRBb/TMF52Zr
         GY1Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=OkP4KkU35G5XFrBNE4EgGBdgiwCLkw8n5O0kZ/voZgA=;
        b=udZReFVoiM1j1NyxmygwRVmVWpENAu5nBqvm4vqYn5GlD+JevBDaMtJDmRMj/jH6O4
         3aqzMGcpScFBzwrJIo/llYF7KGeitUJOjzV0cjw/ANhOjtk1VSA5LGy7eGq1md5UKuGa
         6M//EVgwcucyJAdbVSaipRK9HcdIcER6BWx1t8+A2o906+4wYWoA3HkT31IogoVmbfh4
         VMvDLxnxn5KI8tvqxFKgWapwHUuoowSNvmFEtvK7XOgU76aXj4roQWeYoMx8HDrAZSkR
         O89aMPXwYKwdPYxrCI9wp0/O9VOD4EydjH3BPgt578vGKxhxjP00CqxQhftk8RcDnzzj
         a/eA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=CKVMeJcB;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::443 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=OkP4KkU35G5XFrBNE4EgGBdgiwCLkw8n5O0kZ/voZgA=;
        b=IRbS/oHJYdvVlyG3BjaJ3jK/ZS7F+6balqO9LuUCj3Qizf9Enqt43JBiuZr2oiPqnO
         Mr6hJvcUZUd7puN+A2HlwhYupaVETJFkHR5/Ov/rMMbV9DRCFHnjAAbQz8CKq+pfeC0p
         ZaZOj0wAaQqHhkcGetFtT+KGctOvTnYbFlJJnQQ5R07rz4FSgKWyNJJcHa+sJGBHDNk/
         qXcvA2JDbVt71vWTYUxq0WiVFZDTxospka4OkRpS0AaYFACfJ+cmXy9QJBx21aQbutmb
         Vmtn820iD9c/NwJXTgoX48EH0AOMAM/nCUrqxZb4rYLyQZh6P+g+h2FxahsKgtUnETtd
         ZGug==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=OkP4KkU35G5XFrBNE4EgGBdgiwCLkw8n5O0kZ/voZgA=;
        b=YEPTYWCPzAIvD5oXqJUtYdvv0qbp1K1CqTluKNMhk/oS6HvHLJE4QUoJuiKTDbPy8S
         l5UIsvcn3AFne5raBPDojm5N651UMIhTK9Lw9uE+/L+kXl3YVJJLHCorE5fn/uIzqfv1
         oYhrtiLaef7048s1VhB5wDYS8TAoBnEQ8fWeJULCbMLhHZVp8O9inHXvBldIiVb1gbJd
         ab6R35VKB8KJf+D6it1jqUHD383tFpeCLtBhn+ITOE/4l+qarCYuSh9C1gek/F0whale
         Ne4NgKjKOOV214LJyIT6Us6la/tNVV/aMmifCaOyC5Np77q28aL4a7QJFK0t7E0Axy4+
         BPQw==
X-Gm-Message-State: AOAM530Gj2f1TGLvZ7A2Ko8INMSGhhcG8Ijae25efocRsYBj/uYXiq3k
	0D/LDILNh7ECgkqD0u0d6ow=
X-Google-Smtp-Source: ABdhPJzN0QruYHdLc8L1SSJhivg3cHzov/50dNZBQCnnAH8kvFoozaH5gWeGl3R68osaZuFpbd3w/g==
X-Received: by 2002:a63:4859:: with SMTP id x25mr14383989pgk.422.1598529758015;
        Thu, 27 Aug 2020 05:02:38 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:f158:: with SMTP id o24ls795355pgk.4.gmail; Thu, 27 Aug
 2020 05:02:37 -0700 (PDT)
X-Received: by 2002:a62:6847:: with SMTP id d68mr16359204pfc.110.1598529757456;
        Thu, 27 Aug 2020 05:02:37 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1598529757; cv=none;
        d=google.com; s=arc-20160816;
        b=btUwun5RlJa2ow5Ew/NeKeCghH/8BK/waHZF68my4eV7OSaviLc5/rw8GLcKPQGkNH
         +D4agu3/el2QX+P8jcyBrvZXQb9tr/XsHzj+34BeUdmj5troovbRU27oPg+K9wC5oTdF
         KkwKxvHaPbEJmJBeMq1VgQUnqITMyIZJZJvVbaRiasQLsiq3eaDkEw+Mj0wTsn1cSXBJ
         H6kmKo6mBuih+B7qe41qUw8Dt84XzNJCkXbK7lMqr6qtU/2WrdRsk94YzSdz/az3BNH1
         6IZOa/K19YBzzWk6d7O9o9LBFQPrXUK2lrInsi0WTEdicdQet6jYPudEEzUUXw+YUK55
         Rv8w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=7wwPhOxGIRjLkN/opTRViTv7LvuoBwuvf4nfx6OU/cE=;
        b=COlN3Vb7KcmpI/wdxYO02UntTNZVVpLS5h/iiQZkw6on3un3t/4Z9Wd1Npwun4gro1
         jHjiMGEyHxViBO6Za/tFNIvKGoNFxReTK9vw3BxdByfAUMEO9rkZN5jCyJFDU0EYt/Nl
         EqwAwnIWsvcwFpxbYD+/BKZ+HXs8OHfEyQxPxSf9TEU86CRpuJsEntUXRiu0xx8Cq4Mj
         uE3I/d4n9XEKrlQfYIDv07LYDrJT+XqmcptuuXLmgeoV+vWb3vpG723Jr+KHq2EFSAP5
         RRGUDvJ6rCLxc5jBrMJaE5QquX/nd6FUfCK2th68ubYAHGgh6eV6AM/Tyg2hm8ktvN/h
         fVdA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=CKVMeJcB;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::443 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pf1-x443.google.com (mail-pf1-x443.google.com. [2607:f8b0:4864:20::443])
        by gmr-mx.google.com with ESMTPS id s2si102210pgh.4.2020.08.27.05.02.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 27 Aug 2020 05:02:37 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::443 as permitted sender) client-ip=2607:f8b0:4864:20::443;
Received: by mail-pf1-x443.google.com with SMTP id t185so3305690pfd.13
        for <kasan-dev@googlegroups.com>; Thu, 27 Aug 2020 05:02:37 -0700 (PDT)
X-Received: by 2002:a17:902:8d89:: with SMTP id v9mr15849073plo.289.1598529756898;
 Thu, 27 Aug 2020 05:02:36 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1597425745.git.andreyknvl@google.com> <5185661d553238884613a432cf1d71b1480a23ba.1597425745.git.andreyknvl@google.com>
 <20200827080442.GA29264@gaia> <56ba1b14-36af-31ea-116b-23300525398d@arm.com>
In-Reply-To: <56ba1b14-36af-31ea-116b-23300525398d@arm.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 27 Aug 2020 14:02:25 +0200
Message-ID: <CAAeHK+yYeYJqkxiQD7F_VBzUmJ3Tx4W6huUUJ4Sk7auiA=UkoQ@mail.gmail.com>
Subject: Re: [PATCH 19/35] kasan: don't allow SW_TAGS with ARM64_MTE
To: Vincenzo Frascino <vincenzo.frascino@arm.com>
Cc: Catalin Marinas <catalin.marinas@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Elena Petrova <lenaptr@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	Will Deacon <will.deacon@arm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=CKVMeJcB;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::443
 as permitted sender) smtp.mailfrom=andreyknvl@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

On Thu, Aug 27, 2020 at 11:52 AM Vincenzo Frascino
<vincenzo.frascino@arm.com> wrote:
>
> Hi Andrey,
>
> On 8/27/20 9:04 AM, Catalin Marinas wrote:
> > On Fri, Aug 14, 2020 at 07:27:01PM +0200, Andrey Konovalov wrote:
> >> Software tag-based KASAN provides its own tag checking machinery that
> >> can conflict with MTE. Don't allow enabling software tag-based KASAN
> >> when MTE is enabled.
> >>
> >> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> >> ---
> >>  lib/Kconfig.kasan | 1 +
> >>  1 file changed, 1 insertion(+)
> >>
> >> diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
> >> index b4cf6c519d71..e500c18cbe79 100644
> >> --- a/lib/Kconfig.kasan
> >> +++ b/lib/Kconfig.kasan
> >> @@ -69,6 +69,7 @@ config KASAN_GENERIC
> >>  config KASAN_SW_TAGS
> >>      bool "Software tag-based mode"
> >>      depends on HAVE_ARCH_KASAN_SW_TAGS && CC_HAS_KASAN_SW_TAGS
> >> +    depends on !ARM64_MTE
> >
> > I think that's better as:
> >
> > diff --git a/arch/arm64/Kconfig b/arch/arm64/Kconfig
> > index 10cf81d70657..736c32bd8905 100644
> > --- a/arch/arm64/Kconfig
> > +++ b/arch/arm64/Kconfig
> > @@ -131,7 +131,7 @@ config ARM64
> >       select HAVE_ARCH_JUMP_LABEL
> >       select HAVE_ARCH_JUMP_LABEL_RELATIVE
> >       select HAVE_ARCH_KASAN if !(ARM64_16K_PAGES && ARM64_VA_BITS_48)
> > -     select HAVE_ARCH_KASAN_SW_TAGS if HAVE_ARCH_KASAN
> > +     select HAVE_ARCH_KASAN_SW_TAGS if HAVE_ARCH_KASAN && !ARM64_MTE
> >       select HAVE_ARCH_KGDB
> >       select HAVE_ARCH_MMAP_RND_BITS
> >       select HAVE_ARCH_MMAP_RND_COMPAT_BITS if COMPAT
> >
>
> I agree with Catalin here, "select HAVE_ARCH_KASAN_SW_TAGS if HAVE_ARCH_KASAN &&
> !ARM64_MTE" should be sufficient.

Sounds good, will do in v2, thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2ByYeYJqkxiQD7F_VBzUmJ3Tx4W6huUUJ4Sk7auiA%3DUkoQ%40mail.gmail.com.
