Return-Path: <kasan-dev+bncBCP4ZTXNRIFBBBXI2TXAKGQEE5NIVLY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13f.google.com (mail-lf1-x13f.google.com [IPv6:2a00:1450:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id DFDFD103A2E
	for <lists+kasan-dev@lfdr.de>; Wed, 20 Nov 2019 13:39:34 +0100 (CET)
Received: by mail-lf1-x13f.google.com with SMTP id j16sf2233233lfk.2
        for <lists+kasan-dev@lfdr.de>; Wed, 20 Nov 2019 04:39:34 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1574253574; cv=pass;
        d=google.com; s=arc-20160816;
        b=jXJEY+aFZY6K9Xe1ijiR77TLq/sNi1TLdJU3BAlwztm4/kB+Ct6i48lFWnqXOfrmMn
         eR0To3kbfgVOCqJbOn/IQ3SV78FjuAFvEB+hb5oiUfq9+jJqgB9vQA0/UUrSHOAOZAdH
         77xBi3TKoLU6Ul7sstcmVrAD0c+motNRGmI7+KDVH15KAYGCvvU6zdAvbvebwZnt7GR8
         jGJmxxXFbZHW/EWXfJSTO0kGUrfwsENXQnKoM35KIWB+vNcy7WdTYkYI6QT4tTPcE3by
         KiS5H3VP1AN8P+ZMowgsrGcRZvQGi9VOFt4gRk4vMQ3YFHvKyHPPFZGzQ+MddenPxU/j
         /MYA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=AZuGir3b1KN6D314gbhsnjYzv/jfHJH2iSyH2j4coXU=;
        b=tkUdNJhbyLUHPwA+j0+SCoHzbLbm/7cv4Tqxqu0WwJG/ExK39op2n/ht5wM6rpt0Fc
         HQT/39dQRzLvEMQb38hfwryVuAwFpeWoyyi25PXQ9RhoaFhKiJa+0F4y4gyySrQGtOoL
         NEtQ7XsxDAid0gCHenyAwLTURY/+nHTD4ZXuZ5Kyl+VxCcnj47ZxBJSicwbf0fxhSq9M
         EZbs+jyfxEDokGKbNF/VWutOYktCKkqgN3ynN4zMnjzEYQP9p+RsxWOmEMgsuE/0+sn0
         LKuIVxceI6Zc4H2XtZ61DEpu4k4AaPW2na/ZW8LNVhVk9+ba4jnRIt5OTUpAHM3alI7I
         rT7w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@alien8.de header.s=dkim header.b=OjXmSLn6;
       spf=pass (google.com: domain of bp@alien8.de designates 2a01:4f8:190:11c2::b:1457 as permitted sender) smtp.mailfrom=bp@alien8.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=alien8.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=AZuGir3b1KN6D314gbhsnjYzv/jfHJH2iSyH2j4coXU=;
        b=lGqPSy+QPM+HWa9QHnHsr0ui7K0Il6wV/SQwIjHOpYWsnsfjwY8d05By+WbXINHHcv
         eAUaBv8ZhHrS3tjyP8nP4OEtPe7z9f7W4ypAYcb0oGtrkm6QpS2rkTLpBuhoym0mAEIq
         fXCKOngxgmBEkeB2CCWKP8wMl8l954Jxf32ybVrZ+xyeOfYv58O4MLnG4eo3pLykTE/M
         aEfbl5+H2vjrJx3ifAxwSymYvChExrNR9eZfXhlPX1xEbgSOMBhjMuipHilWwiUt4aBa
         rneJEHAvdiyEvH9FfwDTgZz9of50+SkJZzbngpKZXC3EGqXRpr6OvX2W1XmYmt9yJNtp
         SqDw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=AZuGir3b1KN6D314gbhsnjYzv/jfHJH2iSyH2j4coXU=;
        b=AB9TSx7l4ajK1MPK0x+EYmXXEIPkUuxad7LhYu/bwju4Fn8MdyeyAyB51vELhn+BFN
         6yyVmw0cn10udoEwRhWzwCKikW9TwmUodBv+AJo1eALFR5O79c0sN5Cm5W9544Z36uU0
         GiXs3S3xff9azr2crkUw7UOVhWhnPoJpqkoCjci5qEBNKrSdgcHK+59Xi2goHuwZc58S
         eX+CTZN8BLEsBk+VTVMcEfju/j538ikWIQEkFvNZERYEN9M2lfdQcFm7HWGyWZNkvSrQ
         BqOVYwqg1IGZ2g5eACtErHYt0qgCntvOL7YYkDnJgbV6BM/603j0QUl4jXpl0TV8S1oj
         SQ5Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAU+sMK4zFaFQ3p2gYZAwBs2bO1OYNFeQ8QfAfh+3X6nLHLxN/tu
	6tEfHzzcAgPQdfYpm/aKgmw=
X-Google-Smtp-Source: APXvYqz6reuzp/cMlH2KoBzpNGqVzedvxclY1oSJyggXpS7heOkt8PxaaozXTNIUkSOWCkoVMmjArw==
X-Received: by 2002:a2e:7013:: with SMTP id l19mr2579601ljc.201.1574253574358;
        Wed, 20 Nov 2019 04:39:34 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:289:: with SMTP id b9ls273507ljo.10.gmail; Wed, 20
 Nov 2019 04:39:33 -0800 (PST)
X-Received: by 2002:a2e:8508:: with SMTP id j8mr2548360lji.136.1574253573568;
        Wed, 20 Nov 2019 04:39:33 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1574253573; cv=none;
        d=google.com; s=arc-20160816;
        b=hcUHzQryGXpTX/4ihTF5/Yb8btqrY5OXEB+NngrLkkzbHnrOecUtpaq1xI5diRMQup
         U6HC5PKy7ey4QVqhx0cDeyU8zu/Ch4lD+twXRQvolU3ou4N5ea4uSUfrMbcOlOcG6MJE
         Ab4n2laH6r48aQziKSS4EKo+ZCXqTY02E1pHVyjmr4fLs7QX5RvcOu4srd2KuAdhRMTo
         +0WRmm5XwHyt2e8EYs2kAsN4ODptcpP5QRdWpDDtwTRI2cIEklndMJXnxBcLbuxBpA8C
         wXw6FXFShHSLmgGgEPd4PceTGxvs/fFlEwEPOdgYP3xYm/EzJhhl3N7bWNDKOfk7xiZm
         0CIw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=zp+1xALzK6MVb4JuJSTpKsxknVwYBFmIQv2YEQLs+rY=;
        b=0dCrzOVwv2u3WyWsiPInoUXlSlcC6A0eDlP9FGJfvhaPFq6pFCbdr4VIT3CtmCLa1n
         DnSE66SDirtZEZRxH0DjuYqOWnNrSOe92Pu+Ob++NUEV2LKKn320J0h3eKjPF+y8KLzZ
         gGFAsTTqKdVH6oCvD7ESOXVj2ylekfxd9ePtxi6T5o9WPn+NSzPRL58I5CZYjdt/8O9I
         3KsQJoN1bSRlw/atvZfGPLKcaXMhFkDIvwGkQwoXVd7LCCRACYOU1AHlkbWaGiPCWeyg
         5nhbM8/TlzdMHeGkYx1g5hBFL1M6kpZBU1bmB8wJVGljPYpmkCSwrbFSKaO+fkGijtSk
         i00g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@alien8.de header.s=dkim header.b=OjXmSLn6;
       spf=pass (google.com: domain of bp@alien8.de designates 2a01:4f8:190:11c2::b:1457 as permitted sender) smtp.mailfrom=bp@alien8.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=alien8.de
Received: from mail.skyhub.de (mail.skyhub.de. [2a01:4f8:190:11c2::b:1457])
        by gmr-mx.google.com with ESMTPS id b13si1326363ljk.4.2019.11.20.04.39.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 20 Nov 2019 04:39:33 -0800 (PST)
Received-SPF: pass (google.com: domain of bp@alien8.de designates 2a01:4f8:190:11c2::b:1457 as permitted sender) client-ip=2a01:4f8:190:11c2::b:1457;
Received: from zn.tnic (p200300EC2F0D8C00B1B17C12861BCCA4.dip0.t-ipconnect.de [IPv6:2003:ec:2f0d:8c00:b1b1:7c12:861b:cca4])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.skyhub.de (SuperMail on ZX Spectrum 128k) with ESMTPSA id 8C9BE1EC0CE3;
	Wed, 20 Nov 2019 13:39:32 +0100 (CET)
Date: Wed, 20 Nov 2019 13:39:26 +0100
From: Borislav Petkov <bp@alien8.de>
To: Ingo Molnar <mingo@kernel.org>
Cc: Jann Horn <jannh@google.com>, Thomas Gleixner <tglx@linutronix.de>,
	Ingo Molnar <mingo@redhat.com>, "H. Peter Anvin" <hpa@zytor.com>,
	the arch/x86 maintainers <x86@kernel.org>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	kasan-dev <kasan-dev@googlegroups.com>,
	kernel list <linux-kernel@vger.kernel.org>,
	Andrey Konovalov <andreyknvl@google.com>,
	Andy Lutomirski <luto@kernel.org>,
	Sean Christopherson <sean.j.christopherson@intel.com>,
	Andi Kleen <ak@linux.intel.com>
Subject: Re: [PATCH v3 2/4] x86/traps: Print non-canonical address on #GP
Message-ID: <20191120123926.GE2634@zn.tnic>
References: <20191120103613.63563-1-jannh@google.com>
 <20191120103613.63563-2-jannh@google.com>
 <20191120111859.GA115930@gmail.com>
 <CAG48ez0Frp4-+xHZ=UhbHh0hC_h-1VtJfwHw=kDo6NahyMv1ig@mail.gmail.com>
 <20191120123058.GA17296@gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20191120123058.GA17296@gmail.com>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: bp@alien8.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@alien8.de header.s=dkim header.b=OjXmSLn6;       spf=pass
 (google.com: domain of bp@alien8.de designates 2a01:4f8:190:11c2::b:1457 as
 permitted sender) smtp.mailfrom=bp@alien8.de;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=alien8.de
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

On Wed, Nov 20, 2019 at 01:30:58PM +0100, Ingo Molnar wrote:
> 
> * Jann Horn <jannh@google.com> wrote:
> 
> > You mean something like this?
> > 
> > ========================
> > diff --git a/arch/x86/kernel/traps.c b/arch/x86/kernel/traps.c
> > index 9b23c4bda243..16a6bdaccb51 100644
> > --- a/arch/x86/kernel/traps.c
> > +++ b/arch/x86/kernel/traps.c
> > @@ -516,32 +516,36 @@ dotraplinkage void do_bounds(struct pt_regs
> > *regs, long error_code)
> >   * On 64-bit, if an uncaught #GP occurs while dereferencing a non-canonical
> >   * address, return that address.
> >   */
> > -static unsigned long get_kernel_gp_address(struct pt_regs *regs)
> > +static bool get_kernel_gp_address(struct pt_regs *regs, unsigned long *addr,
> > +                                          bool *non_canonical)
> 
> Yeah, that's pretty much the perfect end result!

Why do we need the bool thing? Can't we rely on the assumption that an
address of 0 is the error case and use that to determine whether the
resolving succeeded or not?

-- 
Regards/Gruss,
    Boris.

https://people.kernel.org/tglx/notes-about-netiquette

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191120123926.GE2634%40zn.tnic.
