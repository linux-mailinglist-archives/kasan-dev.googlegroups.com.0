Return-Path: <kasan-dev+bncBDX4HWEMTEBRB2U5335AKGQEVAE2TSI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43e.google.com (mail-pf1-x43e.google.com [IPv6:2607:f8b0:4864:20::43e])
	by mail.lfdr.de (Postfix) with ESMTPS id 43DF6261248
	for <lists+kasan-dev@lfdr.de>; Tue,  8 Sep 2020 16:02:20 +0200 (CEST)
Received: by mail-pf1-x43e.google.com with SMTP id h15sf10717049pfr.3
        for <lists+kasan-dev@lfdr.de>; Tue, 08 Sep 2020 07:02:20 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1599573739; cv=pass;
        d=google.com; s=arc-20160816;
        b=uiL5vrDZ1egJmHVm0wuY1sUHdh/6Wj4lvA0G8B1b5tK3hPnxWle9MTUKxXulHua0Wx
         Irn5mx7J0bNMuM7w1gq/B0v0VHy8TnMC8POGQmeGG3ycqF75//BDf6dXttCUaWO0mo85
         9gAKsNCjFEsPKHs0u4zAwQNeWHW1owpH8oOcWB62E9RQffKcc2lmnSI/0NwHAptWIBVa
         uC1ZYXtRefOYdtuOuw+M7kypLVpbGP6xpOGc7PRTg3d1qIhj5fdfc7kr0GNCM8KliBTO
         tQ81QAQO6PqGK+gQFhfueLJPcVuKuhTGHfuru8CSudt/iTtyAGM105q5RnggsvIL6PqV
         Hj1w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=jVUPQuSJ13agA78SYIXh0Q9T0lkyC7W35bVjEvORxxg=;
        b=mB5A4XAqbsyYgNuNp4ulCGz8N5Yxlgn4L+4BqkIkTlse6gQDNji9sJEZ785aGDr7qd
         qIOsvhzyLcaPwQgObRpgg0x5Ss5F8mpGfYLW0+AsOUDsBZIw6WyMk6ueDN+zFZlBfLkS
         utO57FsGc3MGNYwGY5mtMFZGiMMzTTq7xSrtsFc1rWWP4yFbI66p3+6GSqQH/fQYiqjY
         gNwsEYorhhN0KevH7rRi8Zcg6wiLN/Rr3RkbR44YPbytOw2sxx7r90AmemdHVpdmdUzj
         OdHPwbQb50cS9sQ0PloOrW5mBsBBXsL9xW58NltQYEd2QV8HNJICcZrO03rd/hWoA0V/
         Rz5Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=p9feilB1;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::1043 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=jVUPQuSJ13agA78SYIXh0Q9T0lkyC7W35bVjEvORxxg=;
        b=LM09EOtvc6ZsXBiX9WAZa+1VHMV7YSB+TUFP5CG63oycumXuSEGmdNal4TCDoO6ek5
         IoVw1wJ6US4Z2h1LpaJUhj/cbpDyYXr5rEBYgaqCi2EsRcPj5wzBTchOjhR7yYnt6ETd
         h18KP5XGyeqkItGOhK9xl7MQ6XP/dGvnfm3BQXwFii2OVi+wWXj23Gk0ds+VIOd86fDx
         5psqreFnMzNYQ9xsomWzvAk18uzT2Q9dCz4Jabm6SZdZOviuOV7sDOnOFYLW0c9DiNjj
         86dO06vFWo+m07wcbf4rCnHke5xQ2JB39XeRRGfolMJVxxaqC8rUl6HKPRcybulR064f
         iDkQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=jVUPQuSJ13agA78SYIXh0Q9T0lkyC7W35bVjEvORxxg=;
        b=bUNzVYtpIWxMMEp99y6lS/fcJHFqWstpCNMK5gWoIjqQTW0sGciCo7H0Z44BE0+dr9
         rLEqgtPMdes7ksRLJkHmkPsHWEepnXnAlLZgjS4ZiHw8VM3c0PG2WPhNaYrMwM1Zi3/s
         ACYYcKE6sQ2k4WpgwJ5Lql44DdFH4jQ4FKQDxVP2xMDyOgKSUOX4Yl5pXOI5N91rlss3
         RHLlqH8a0bdoiqUT/K19SO+9FhxsuZz21l4rZtdOWalUaS+lERG+cJrKbSbinzdMkIR0
         2PdGUyfEwOXrv6YyDkHCmI5H7Mi3URSlxvFlV3NlWKRn3iBG3Q5mDdhtsEqo2hJoZLW5
         aOxQ==
X-Gm-Message-State: AOAM533dPqZ6VucpQs2hD+90XwSjRRKLPW/pJ5xnA5kVqAjLfy1bmNLr
	EZUk+R6fp2O2JUlYRC4sj9U=
X-Google-Smtp-Source: ABdhPJwhOshZBhTwzBj+6/yWSDEea/E276PgP88KirM80EgxMIxc+XPFVzxBIZKjG0PNWrKnqWWbuQ==
X-Received: by 2002:a62:3146:0:b029:13e:d13d:a08e with SMTP id x67-20020a6231460000b029013ed13da08emr1251934pfx.37.1599573738933;
        Tue, 08 Sep 2020 07:02:18 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:9d01:: with SMTP id i1ls5686975pgd.5.gmail; Tue, 08 Sep
 2020 07:02:18 -0700 (PDT)
X-Received: by 2002:a63:1b65:: with SMTP id b37mr21055965pgm.453.1599573738406;
        Tue, 08 Sep 2020 07:02:18 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1599573738; cv=none;
        d=google.com; s=arc-20160816;
        b=MSPRRPw0qTbXO3k4a3tRTU/oCqzuRVyHMtrWQTIf25B6ISKHRWbFNGmO+IGvqMtjfX
         vTWSuPshyqaRyE0CjaY+bIZ+0uewHpRweVpvdsyLI7bNzNIDj0tClr2tTNwhsiARNCLv
         OAwbUE2twMH2MO1R24MydNruMy2MFyW4MXgLLHmCli6cCEd7jCeAe+EyAe6hqSMORJR7
         AYzA6WMqPHgUrBGA8reMxpEXkIOUrWdly4Bu5gn0QHtX3ZIENdeuKqMiYUzONK3aHJnS
         4GxNXzzjuOUCdsJs13rsiUoJcWhm9BTrYz1R3SlY97MhizglIZjZOQKWQ2TtUqGm2Tk4
         P3jA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=tB5vJBBCtNhXMgKB2GrADyceasBad1luqBoSGuNUjz8=;
        b=kY5l/031i7duJtut6m/7q14Vl0g+AoFXF043kWHF8JFlBHaD1UxkzNSjTVBJpDahzf
         mcOsXBnzmyjf4NyqTpzA6QILeGxHW4ydEhvIipHCxNiZhC6Kxxj0deryxwG1HhCb6k40
         WBpUR/ojBiuMUnQVVLJFkA0ej7mtnPb/Xay0ubFxZFwivUg4XHWlohLZk7hlhhzI4pEe
         yW4Knchz5siEOTtHA2W8Qlk+jfM7S/BUvJ7AuivEJRALfVIGC2e+vqidQvp4+otOv3Ud
         1+BI/EKTs6TBPvi3fvCjLvWvS9OUF02nrEnFahW5kj9ReQiwPoACYYSTV/ynFJDFIdQr
         sE8g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=p9feilB1;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::1043 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pj1-x1043.google.com (mail-pj1-x1043.google.com. [2607:f8b0:4864:20::1043])
        by gmr-mx.google.com with ESMTPS id lj12si1174270pjb.0.2020.09.08.07.02.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 08 Sep 2020 07:02:18 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::1043 as permitted sender) client-ip=2607:f8b0:4864:20::1043;
Received: by mail-pj1-x1043.google.com with SMTP id o16so8348473pjr.2
        for <kasan-dev@googlegroups.com>; Tue, 08 Sep 2020 07:02:18 -0700 (PDT)
X-Received: by 2002:a17:90a:81:: with SMTP id a1mr3986021pja.136.1599573737858;
 Tue, 08 Sep 2020 07:02:17 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1597425745.git.andreyknvl@google.com> <ec314a9589ef8db18494d533b6eaf1fd678dc010.1597425745.git.andreyknvl@google.com>
 <20200827103819.GE29264@gaia> <8affcfbe-b8b4-0914-1651-368f669ddf85@arm.com> <20200827121604.GL29264@gaia>
In-Reply-To: <20200827121604.GL29264@gaia>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 8 Sep 2020 16:02:06 +0200
Message-ID: <CAAeHK+yYEFHAQMxhL=uwfgaejo3Ld0gp5=ss38CjW6wyYCaZFw@mail.gmail.com>
Subject: Re: [PATCH 24/35] arm64: mte: Switch GCR_EL1 in kernel entry and exit
To: Catalin Marinas <catalin.marinas@arm.com>
Cc: Vincenzo Frascino <vincenzo.frascino@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
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
 header.i=@google.com header.s=20161025 header.b=p9feilB1;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::1043
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

On Thu, Aug 27, 2020 at 2:16 PM Catalin Marinas <catalin.marinas@arm.com> wrote:
>
> On Thu, Aug 27, 2020 at 11:56:49AM +0100, Vincenzo Frascino wrote:
> > On 8/27/20 11:38 AM, Catalin Marinas wrote:
> > > On Fri, Aug 14, 2020 at 07:27:06PM +0200, Andrey Konovalov wrote:
> > >> diff --git a/arch/arm64/kernel/mte.c b/arch/arm64/kernel/mte.c
> > >> index 7717ea9bc2a7..cfac7d02f032 100644
> > >> --- a/arch/arm64/kernel/mte.c
> > >> +++ b/arch/arm64/kernel/mte.c
> > >> @@ -18,10 +18,14 @@
> > >>
> > >>  #include <asm/barrier.h>
> > >>  #include <asm/cpufeature.h>
> > >> +#include <asm/kasan.h>
> > >> +#include <asm/kprobes.h>
> > >>  #include <asm/mte.h>
> > >>  #include <asm/ptrace.h>
> > >>  #include <asm/sysreg.h>
> > >>
> > >> +u64 gcr_kernel_excl __read_mostly;
> > >
> > > Could we make this __ro_after_init?
> >
> > Yes, it makes sense, it should be updated only once through mte_init_tags().
> >
> > Something to consider though here is that this might not be the right approach
> > if in future we want to add stack tagging. In such a case we need to know the
> > kernel exclude mask before any C code is executed. Initializing the mask via
> > mte_init_tags() it is too late.
>
> It depends on how stack tagging ends up in the kernel, whether it uses
> ADDG/SUBG or not. If it's only IRG, I think it can cope with changing
> the GCR_EL1.Excl in the middle of a function.
>
> > I was thinking to add a compilation define instead of having gcr_kernel_excl in
> > place. This might not work if the kernel excl mask is meant to change during the
> > execution.
>
> A macro with the default value works for me. That's what it basically is
> currently, only that it ends up in a variable.

Some thoughts on the topic: gcr_kernel_excl is currently initialized
in mte_init_tags() and depends on the max_tag value dynamically
provided to it, so it's not something that can be expressed with a
define. In the case of KASAN the max_tag value is static, but if we
rely on that we make core MTE code depend on KASAN, which doesn't seem
right from the design perspective.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2ByYEFHAQMxhL%3Duwfgaejo3Ld0gp5%3Dss38CjW6wyYCaZFw%40mail.gmail.com.
