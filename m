Return-Path: <kasan-dev+bncBDX4HWEMTEBRBD6PSL5QKGQED2GRMIY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33a.google.com (mail-ot1-x33a.google.com [IPv6:2607:f8b0:4864:20::33a])
	by mail.lfdr.de (Postfix) with ESMTPS id E31F326FC70
	for <lists+kasan-dev@lfdr.de>; Fri, 18 Sep 2020 14:26:56 +0200 (CEST)
Received: by mail-ot1-x33a.google.com with SMTP id a63sf1535382otb.0
        for <lists+kasan-dev@lfdr.de>; Fri, 18 Sep 2020 05:26:56 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1600432015; cv=pass;
        d=google.com; s=arc-20160816;
        b=JFrYW0YZNBq4Edl40MkyTvBMvDUGtudI8UvWmjL5DqVFkoJp8V4C0W5g/RCx3U0mrF
         0BZr+GsExCX0VVBd4OGy52ALR1bMSjw6X0oXoTKdtN0NiqdEbI3fiYbWljP048uQIo52
         nUX5embsQpbpZqOfFQRZ93Of1hwQOBRaThRnHfFQez/jxq56BTDHxSDP12RVXX37/fKD
         kcNaRkH+rJJwwPg2Q38MPtpHUh5NlLI016xR9e9EO37LfhibcLvYJZuXBpKCae2b1ICc
         RmMJYg0YsTYdSsIaF9Pzvz3zB+CBKfTctASVFH6KYKjPzmnZKaM9TLg0rU+TyOde9Wz6
         Yq8g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=oJbhdfBNibwBEY2tTdHWaslh/2Yb8DS3eK0NH+ChJUA=;
        b=kkW4qsaDLU98cfhwuXP4PKi69HrG+n+RZIdOn6oIJNSt7jX0BtVSmdhwSNhYIqKbtz
         9H+pa4Fi85VjEed/NruvMpVIlOPLU3gHUHwsB1ZBMSf0jVoLR2UAwTjyiv9m5S82J5bb
         haABzq+Sh1JXZ7wPxV9CpPFob6JWIp4LlWYoOyDo6nBQFdMfbEG/DJUWHwgFoPg2ELLA
         n5A4bV8EVyzjkL0xrMbmALZfM9HOI32OCU0WLFQzbdVNO7rP9jnaXsYf+QnuQvg2bMIl
         Krj2hfIy8RiR9ys74aAG6Llu7Lv9gf+O83m8oOKXImevPmFQroTRjgi4GqdOJcCuc0ei
         KiEg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=AJCCnnw6;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::1044 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=oJbhdfBNibwBEY2tTdHWaslh/2Yb8DS3eK0NH+ChJUA=;
        b=NA1tIZV0MqeZopWFX9Xk5Y+O82Mr3mAMau5xBNwZeaGUlqjLlQtlt5NeoCzzE4Cm+f
         EqY0qDDqWG1vn/9Tugeg2wBaNMtTnhPQyU1L7aut4uDhVpNqvqYE4TYtQDUeKn75tx+3
         xNzvL3x/LABPjoviSBMHcNJ+cnPUEVjlVlrdsTs82zNaK889xTCAakB68Ss+U/IoT4uP
         PFAisj+YvLY8g50VwOYxenLZuEDs+BN2cusgaV92dOuoQgGBVHTS3FDwzT1StSA/N5KX
         Tyg8UPvsNcyiHLGwYVE3KtN6HsrcE4f+ryK94c1Qaa93sOsKUeGC2tdoM4qJaom76Bza
         taXw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=oJbhdfBNibwBEY2tTdHWaslh/2Yb8DS3eK0NH+ChJUA=;
        b=UuB286lSFpQNAOdFJSBDZjAO2QgAy2+F8jiKiMDiSNxaRUB56lZXYkIlZ6YiAWOmHa
         UFXedXISqMz88kfYav6V0uf0ytYi87X+IXpmBR+uDkihkbyK1iAy0aoIN718MZqbmmrA
         7XfReqd+hWdsN+gROyVDa7bRjSMZy/mxpzzvN6CXLGpU8et8zUBz1F/vCqinH3g2wkoh
         jXvvZNAVU+FqgNJDWXS4TiRn4mRjVAGsIeXwxnQ+QAMHdsrW70NDCRrxVd9NwgXDMjk5
         C0Tvi/8IM9kkDlJBpqP4lfRw0b85hXm5FKlWi7Z2p0ovfNpuQ4xWgkuvi8u9RuMj2fpe
         jGXA==
X-Gm-Message-State: AOAM533O2rY9D7oiUsfk9PQ488rKUGM4FmlRcBizkiGMxtY/ESDDmAC2
	fi6tSXGDcrnyJXq2vp/OmDo=
X-Google-Smtp-Source: ABdhPJyhBuF7fuJr5PbeRVRfud/zSm0RfBxAqF8GM9LlJJtUylfr8GQBsnlyEdJEidxbEdOgXt8Cbw==
X-Received: by 2002:aca:58c3:: with SMTP id m186mr8429295oib.139.1600432015697;
        Fri, 18 Sep 2020 05:26:55 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:2208:: with SMTP id b8ls1252280oic.9.gmail; Fri, 18 Sep
 2020 05:26:55 -0700 (PDT)
X-Received: by 2002:aca:f5cc:: with SMTP id t195mr9567738oih.10.1600432015390;
        Fri, 18 Sep 2020 05:26:55 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1600432015; cv=none;
        d=google.com; s=arc-20160816;
        b=twDDDeiW9jfx0HTOX/mEw2xrKVhnMVTIKrNNsHCnN+CHLiOX2DHQgF1gmjEwUMRvpu
         EtU9BDVTKHyWrI8Hht8ZL7B+gpR1/ETQLt9D6gPWpD8OQTF7p1itJs3ZJaUM8JNAx37X
         btf/S1+uyhqq1cM+kMVl5Al192BJXtEpgIhUk951hCHLAK0vIrKgLJP9mqG0NNpWsIN8
         tOKzXWRuRJ2ULiEmsxLg6hJR33fEioqYSAG3usA7DRySH7qWydFxA/uApAQqjfT75NpF
         SflCeKG0jjhg7wLOaAenaunGU2Adz25p04gDshytvZantmKbsBaNut4yvD80MpCDT5n8
         tcZA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=VtDuINtc2G9zXnT6yMkHKsVlqkwJ9oqFqRt0wDdeL5k=;
        b=xInWB9OgPElRdMkeRuLm+UXgsxCsoNTKtIuKKPpgrhTXlv5Uaau53PxKNDNPs2M0bj
         XzKu6+fWNk+HusEpO04kuDOw96cSxkLxP+p7FL9TXrDvkfTJOUk1jYPwUFoZpKzdABCg
         9OfKCNJOzn7oLWRMlFPlojdsZIrEnW/GNSGE9cDkTeo6D9JtF4CB1o/Hz84c2pMZ4psO
         ifIHdLEsIaS6phyrBIzj0ZFNqFc1JG1Hlr7PYzCLVBsoHAW2iS2Qiq+8AcGYvkawDvV9
         K2SThGHh8ZyTpImaQtcDVW1ydvGv6U7fzb4tXJZjpqs6CW1h/FEXA6WYN4wOUeioUD7P
         SnIQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=AJCCnnw6;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::1044 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pj1-x1044.google.com (mail-pj1-x1044.google.com. [2607:f8b0:4864:20::1044])
        by gmr-mx.google.com with ESMTPS id i15si195165oig.1.2020.09.18.05.26.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 18 Sep 2020 05:26:55 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::1044 as permitted sender) client-ip=2607:f8b0:4864:20::1044;
Received: by mail-pj1-x1044.google.com with SMTP id fa1so3094267pjb.0
        for <kasan-dev@googlegroups.com>; Fri, 18 Sep 2020 05:26:55 -0700 (PDT)
X-Received: by 2002:a17:902:d888:b029:d0:cb2d:f274 with SMTP id
 b8-20020a170902d888b02900d0cb2df274mr32829839plz.13.1600432014609; Fri, 18
 Sep 2020 05:26:54 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1600204505.git.andreyknvl@google.com> <fb70dc86ccb3f0e062c25c81d948171d8534ee63.1600204505.git.andreyknvl@google.com>
 <20200917170418.GI10662@gaia>
In-Reply-To: <20200917170418.GI10662@gaia>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 18 Sep 2020 14:26:43 +0200
Message-ID: <CAAeHK+zLzajA8-TTJ4OjoMtgPB=hyJRxzz7WwG4gc=tHTuB3Yw@mail.gmail.com>
Subject: Re: [PATCH v2 34/37] kasan, arm64: print report from tag fault handler
To: Catalin Marinas <catalin.marinas@arm.com>
Cc: Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
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
 header.i=@google.com header.s=20161025 header.b=AJCCnnw6;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::1044
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

On Thu, Sep 17, 2020 at 7:04 PM Catalin Marinas <catalin.marinas@arm.com> wrote:
>
> On Tue, Sep 15, 2020 at 11:16:16PM +0200, Andrey Konovalov wrote:
> > diff --git a/arch/arm64/mm/fault.c b/arch/arm64/mm/fault.c
> > index cdc23662691c..ac79819317f2 100644
> > --- a/arch/arm64/mm/fault.c
> > +++ b/arch/arm64/mm/fault.c
> > @@ -14,6 +14,7 @@
> >  #include <linux/mm.h>
> >  #include <linux/hardirq.h>
> >  #include <linux/init.h>
> > +#include <linux/kasan.h>
> >  #include <linux/kprobes.h>
> >  #include <linux/uaccess.h>
> >  #include <linux/page-flags.h>
> > @@ -295,17 +296,23 @@ static void die_kernel_fault(const char *msg, unsigned long addr,
> >       do_exit(SIGKILL);
> >  }
> >
> > +#ifdef CONFIG_KASAN_HW_TAGS
> >  static void report_tag_fault(unsigned long addr, unsigned int esr,
> >                            struct pt_regs *regs)
> >  {
> > -     bool is_write = ((esr & ESR_ELx_WNR) >> ESR_ELx_WNR_SHIFT) != 0;
> > +     bool is_write  = ((esr & ESR_ELx_WNR) >> ESR_ELx_WNR_SHIFT) != 0;
> >
> > -     pr_alert("Memory Tagging Extension Fault in %pS\n", (void *)regs->pc);
> > -     pr_alert("  %s at address %lx\n", is_write ? "Write" : "Read", addr);
> > -     pr_alert("  Pointer tag: [%02x], memory tag: [%02x]\n",
> > -                     mte_get_ptr_tag(addr),
> > -                     mte_get_mem_tag((void *)addr));
> > +     /*
> > +      * SAS bits aren't set for all faults reported in EL1, so we can't
> > +      * find out access size.
> > +      */
> > +     kasan_report(addr, 0, is_write, regs->pc);
> >  }
> > +#else
> > +/* Tag faults aren't enabled without CONFIG_KASAN_HW_TAGS. */
> > +static inline void report_tag_fault(unsigned long addr, unsigned int esr,
> > +                                 struct pt_regs *regs) { }
> > +#endif
>
> So is there a point in introducing this function in an earlier patch,
> just to remove its content here?

I added it to make the first patch somewhat self-consistent. But we
can drop it in v3 if you think it's not needed.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2BzLzajA8-TTJ4OjoMtgPB%3DhyJRxzz7WwG4gc%3DtHTuB3Yw%40mail.gmail.com.
