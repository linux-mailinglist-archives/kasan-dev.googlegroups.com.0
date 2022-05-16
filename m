Return-Path: <kasan-dev+bncBAABBQ4VRKKAMGQEVQ5XKXQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3e.google.com (mail-yb1-xb3e.google.com [IPv6:2607:f8b0:4864:20::b3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 55D50528C04
	for <lists+kasan-dev@lfdr.de>; Mon, 16 May 2022 19:32:56 +0200 (CEST)
Received: by mail-yb1-xb3e.google.com with SMTP id j2-20020a2597c2000000b0064b3e54191asf12798302ybo.20
        for <lists+kasan-dev@lfdr.de>; Mon, 16 May 2022 10:32:56 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1652722372; cv=pass;
        d=google.com; s=arc-20160816;
        b=sF8xMbbd1dCym9/jFnuT+qj5sLlviQZ9t617SF5BrWZ8JoGhY05cmt/9Xxdw+r2kHI
         wBvP7m5oY4XLE+XxzRZEpykqTvZJM+m6kGJBrajDTz49ZXA+0FWdhIOErUcXk5xbbl14
         ntlplDYKgUVU3OThzi7UjX6RuG0pHo5/Lrmw34ADr4bQtCsNsz6k4JcwQFGy+XsBNOWm
         82VwiZxJFL2HHRr5AlsyT/ZsOSFO272h7T9XAeDXgMaOXNRDZ4oUG34Ad+pkjd0Bfffh
         EpwkBR7H5V79qgE//neJG9TgeZsLs0fBCGOjyQV5KMFusEbMJTG+1VxIL06obEjg9bOl
         yW8A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=dN9k0u5fpBqF/RC28/NpIaGRrdpKTpw3o9B0u5EPsUQ=;
        b=Z5TZb3IfdE8x4dVbZstSLd0QJfDnaUDvFET53YfANDXBdUapzDwuUt+YhwLwWVQlDb
         AFDgitvJpHqF8nDzfvFONxGjY8PVLcfJcWu/mgbzKJrosywfetedhbHmcJsPAcNc7tb4
         PKCaxSV6T6dD2bhpRNlDxR3Xspau+PQPeJn1gP6n5oM8Hj+RFXwCQqlhvp8maku+OXV1
         oVuwOPcq/aaRNIFVszzO249WFH8gKvFzPETKerO7vzqph75QWj3qBsApu3Zh5gny1YKY
         TPZx86sICJvNxUAaxQsfJ09582+4KgIM62L/feotCjAW5A8LBAs8OacChk8q7nvtOyzY
         1cJg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=jMNnoHdH;
       spf=pass (google.com: domain of jszhang@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=jszhang@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=dN9k0u5fpBqF/RC28/NpIaGRrdpKTpw3o9B0u5EPsUQ=;
        b=CZKLEQXIsRuRwyFz2UlcVhInt41JnShXRAt04GfrlzKX9HMq71+oGOq1INBDk7S8FT
         wZvwaL12dXWg9k+IN0hdzI2EI3i07bwuQtvCIidZzB1Zg5wWd53YpTkIZ2rK3ljfHbuV
         gZHIrhim/HaMBKlBzaBi1YxpOMZypRxMLM6M3oXXcoFCxHjJHF1f8A7YxvPVdeu/us48
         7zQL0T0bHqEKide4sZpHE31BIlNZQKj4IuXLwiaqdBy3Jh61bzXjN1dPeu1Kpqp72DDH
         x8u8TySu5u/XUnn3tErmPHJVM8gzU3JrOhuOcZjxo24wJFlo2YojkaowRt8wFLfdqmxL
         1i0w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=dN9k0u5fpBqF/RC28/NpIaGRrdpKTpw3o9B0u5EPsUQ=;
        b=B20VH57Qqibi9m8hQXW6RFW/RFNtfiHrN44/wIm/N6XgSrkL4178ukI4/6n9se6SvS
         +ZmcBs8NZto+qeA5ai7W40LJeG6SBK9Ua5xfAZri5ZVjtC2Gsa0x2vhRzdd60/luShOI
         kDRMN91lcqQHrpakJbU99VZwEhsREcfJz/ZOO6busDl3zgDhrRGE7bUmAkLydnXuSWky
         89CmmpWRD+SxYOPq6AgT2+Dpr1xlfBsI0pLEQxWQeSaz9Y9bQDH13kzMANViqFfTXWx3
         aXrnAOy0jF2sNqexCdBJ4asM+Rvo4nMhvv50Mu8jmJGDfMX0Gv6qAJyhcjy8sgOt3juM
         ZGXQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531ZJwVGsMuIlXjQqvCFDpAhf9bU/pr/LslYTHmWzVd2QhFNcjg+
	ZoI9uJm83VtixTA3z17sjNk=
X-Google-Smtp-Source: ABdhPJysk5Is57BfvXPVV1qAAyJmgPStybK5ibCzkfNnWbUgOrbdzIZEwsLC3+FVHXvsVKBhE4u/Mw==
X-Received: by 2002:a81:1357:0:b0:2ff:150d:c11a with SMTP id 84-20020a811357000000b002ff150dc11amr2677476ywt.272.1652722372090;
        Mon, 16 May 2022 10:32:52 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a81:6502:0:b0:2f8:7c91:43fc with SMTP id z2-20020a816502000000b002f87c9143fcls8709804ywb.1.gmail;
 Mon, 16 May 2022 10:32:51 -0700 (PDT)
X-Received: by 2002:a81:70f:0:b0:2fb:79b3:27a8 with SMTP id 15-20020a81070f000000b002fb79b327a8mr21021478ywh.335.1652722371730;
        Mon, 16 May 2022 10:32:51 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1652722371; cv=none;
        d=google.com; s=arc-20160816;
        b=FY1Dmvw4EFC0AraNbFM5AskW8L4Wm+RZGe4DaSsrNlSen+wf3msRZ+uaPn0psk5sFy
         DnAs+2XhYrQFBM1DGNoC+CcIrLXo3Nxo9lTCW2MZjH+jcVIIScWPVwUZp7PSh7EAxNPH
         GfSEFg569nRXvaX/TNVqZz2xs+8Kln5eBtC5qfarjkNLojnN8O1O401Wk2JBO8/4b7IS
         PRGQrDghdXDYtmRCboIVrkwQgac35aeT4BBVzwS2aZTzR2xt3nob9YIvayiGXuFMSfra
         8ABCIdg43ZPnQdJ67tSHYa4YyEwtUf4uDGVJd4XQcmoIxUkfO27LBAYpQsTnqHYva+uk
         gMNQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=skD8rXhu50/na63Ei/dcx0jhsh+ODFpaVS33VSM7HAk=;
        b=vOPkIB0xnl0XumyhqdnWKp/3Fe5MTyd0lXVkrZoIvRMVKiHf+PrsG/u2MzjjKHpHgW
         ICh2wdVSYfWcnBlrzE2Fwj6Yb1pw+czAVxdGSCFC1swrxJ/fQEVNdrTIKqbDlEtZib/Z
         MXBFYxiUG7jKbH9fr1cKh0iUmljseslNb/Gl2Jxmmq+2f+Mskw6MltZV52QoArMvCnu7
         5Kzmd5pZNNn9ZlRynxlHyyA/zHyGvkkgRtWCHglo7y4HU7+Ld/vFvHenmZzjCVS8EUBu
         aZK3Pcn5V6T4FxUu5ULIBPuqfpGLlvo4463SjJLWQB4dbKKwvNjZexHXDKPf3WW6Hnn2
         f6/w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=jMNnoHdH;
       spf=pass (google.com: domain of jszhang@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=jszhang@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id bc27-20020a05690c001b00b002f8fd405eb6si1027952ywb.1.2022.05.16.10.32.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 16 May 2022 10:32:51 -0700 (PDT)
Received-SPF: pass (google.com: domain of jszhang@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id 4CAEA612C6;
	Mon, 16 May 2022 17:32:51 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id D093FC385AA;
	Mon, 16 May 2022 17:32:46 +0000 (UTC)
Date: Tue, 17 May 2022 01:24:15 +0800
From: Jisheng Zhang <jszhang@kernel.org>
To: Anup Patel <anup@brainfault.org>
Cc: Atish Patra <atishp@atishpatra.org>,
	Anup Patel <apatel@ventanamicro.com>,
	Paul Walmsley <paul.walmsley@sifive.com>,
	Palmer Dabbelt <palmer@dabbelt.com>,
	Albert Ou <aou@eecs.berkeley.edu>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Alexandre Ghiti <alexandre.ghiti@canonical.com>,
	linux-riscv <linux-riscv@lists.infradead.org>,
	"linux-kernel@vger.kernel.org List" <linux-kernel@vger.kernel.org>,
	kasan-dev@googlegroups.com
Subject: Re: [PATCH v2 2/4] riscv: introduce unified static key mechanism for
 CPU features
Message-ID: <YoKIv2ATRdQfYbBf@xhacker>
References: <20220508160749.984-1-jszhang@kernel.org>
 <20220508160749.984-3-jszhang@kernel.org>
 <CAK9=C2Xinc6Y9ue+3ZOvKOOgru7wvJNcEPLvO4aZGuQqETXi2w@mail.gmail.com>
 <YnkoKxaPbrTnZPQv@xhacker>
 <CAOnJCU+XR5mtqKBQLMj3JgsTPgvAQdO_jj2FWqcu7f9MezNCKA@mail.gmail.com>
 <YoCollqhS93NJZjL@xhacker>
 <CAAhSdy3_av5H-V_d5ynwgfeZYsCnCSd5pFSEKCzDSDBbD+pGLA@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CAAhSdy3_av5H-V_d5ynwgfeZYsCnCSd5pFSEKCzDSDBbD+pGLA@mail.gmail.com>
X-Original-Sender: jszhang@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=jMNnoHdH;       spf=pass
 (google.com: domain of jszhang@kernel.org designates 2604:1380:4641:c500::1
 as permitted sender) smtp.mailfrom=jszhang@kernel.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=kernel.org
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

On Sun, May 15, 2022 at 08:19:37PM +0530, Anup Patel wrote:
> On Sun, May 15, 2022 at 12:54 PM Jisheng Zhang <jszhang@kernel.org> wrote:
> >
> > On Wed, May 11, 2022 at 11:29:32PM -0700, Atish Patra wrote:
> > > On Mon, May 9, 2022 at 7:50 AM Jisheng Zhang <jszhang@kernel.org> wrote:
> > > >
> > > > On Mon, May 09, 2022 at 09:17:10AM +0530, Anup Patel wrote:
> > > > > On Sun, May 8, 2022 at 9:47 PM Jisheng Zhang <jszhang@kernel.org> wrote:
> > > > > >
> > > > > > Currently, riscv has several features why may not be supported on all
> > > > > > riscv platforms, for example, FPU, SV48 and so on. To support unified
> > > > > > kernel Image style, we need to check whether the feature is suportted
> > > > > > or not. If the check sits at hot code path, then performance will be
> > > > > > impacted a lot. static key can be used to solve the issue. In the past
> > > > > > FPU support has been converted to use static key mechanism. I believe
> > > > > > we will have similar cases in the future.
> > > > >
> > > > > It's not just FPU and Sv48. There are several others such as Svinval,
> > > > > Vector, Svnapot, Svpbmt, and many many others.
> > > > >
> > > > > Overall, I agree with the approach of using static key array but I
> > > > > disagree with the semantics and the duplicate stuff being added.
> > > > >
> > > > > Please see more comments below ..
> > > > >
> > > > > >
> > > > > > Similar as arm64 does(in fact, some code is borrowed from arm64), this
> > > > > > patch tries to add an unified mechanism to use static keys for all
> > > > > > the cpu features by implementing an array of default-false static keys
> > > > > > and enabling them when detected. The cpus_have_*_cap() check uses the
> > > > > > static keys if riscv_const_caps_ready is finalized, otherwise the
> > > > > > compiler generates the bitmap test.
> > > > >
> > > > > First of all, we should stop calling this a feature (like ARM does). Rather,
> > > > > we should call these as isa extensions ("isaext") to align with the RISC-V
> > > > > priv spec and RISC-V profiles spec. For all the ISA optionalities which do
> > > > > not have distinct extension name, the RISC-V profiles spec is assigning
> > > > > names to all such optionalities.
> > > >
> > > > Same as the reply a few minutes ago, the key problem here is do all
> > > > CPU features belong to *ISA* extensions? For example, SV48, SV57 etc.
> > > > I agree with Atish's comments here:
> > > >
> > > > "I think the cpu feature is a superset of the ISA extension.
> > > > cpu feature != ISA extension"
> > > >
> > >
> > > It seems to be accurate at that point in time. However, the latest
> > > profile spec seems to
> > > define everything as an extension including sv48.
> > >
> > > https://github.com/riscv/riscv-profiles/blob/main/profiles.adoc#623-rva22s64-supported-optional-extensions
> > >
> > > It may be a redundant effort and confusing to create two sets i.e.
> > > feature and extension in this case.
> > > But this specification is not frozen yet and may change in the future.
> > > We at least know that that is the current intention.
> > >
> > > Array of static keys is definitely useful and should be used for all
> > > well defined ISA extensions by the ratified priv spec.
> > > This will simplify this patch as well. For any feature/extensions
> > > (i.e. sv48/sv57) which was never defined as an extension
> > > in the priv spec but profile seems to define it now, I would leave it
> > > alone for the time being. Converting the existing code
> > > to static key probably has value but please do not include it in the
> > > static key array setup.
> > >
> > > Once the profile spec is frozen, we can decide which direction the
> > > Linux kernel should go.
> > >
> >
> > Hi Atish, Anup,
> >
> > I see your points and thanks for the information of the profile
> > spec. Now, I have other two points about isa VS features:
> >
> > 1. Not all isa extenstions need static key mechanism, so if we
> > make a static key array with 1:1 riscv_isa <-> static key relationship
> > there may be waste.
> >
> > For example, the 'a', 'c', 'i', 'm' and so on don't have static
> > key usage.
> 
> Not all isa extensions but a large number of them will need a static
> key. It's better to always have one static key per ISA extension
> defined in cpufeatures.c

Currently, RISCV_ISA_EXT_MAX equals to 64 while the base ID is 26.
In those 26 base IDs, only F/D and V need static key, it means
we waste at least 24 static keys.

> 
> For example, F, D, V, Sstc, Svinval, Ssofpmt, Zb*, AIA, etc.
> 
> >
> > 2.We may need riscv architecture static keys for non-isa, this is
> > usually related with the linux os itself, for example
> > a static key for "unmap kernelspace at userspace".
> > static keys for "spectre CVE mitigations"
> > etc.
> 
> These things look more like errata or workarounds so better
> to use that framework instead of ISA extensions (or features).

Currently, the errata workarounds are implemented with ALTERNATIVEs
but I believe sometime we may need static key to implement the
workarounds. However this can be checked later. Now I worried about
the static key waste above.

Thanks

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YoKIv2ATRdQfYbBf%40xhacker.
