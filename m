Return-Path: <kasan-dev+bncBD7LZ45K3ECBBBXE2TXAKGQE6OCPG7A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x337.google.com (mail-wm1-x337.google.com [IPv6:2a00:1450:4864:20::337])
	by mail.lfdr.de (Postfix) with ESMTPS id DD854103A13
	for <lists+kasan-dev@lfdr.de>; Wed, 20 Nov 2019 13:31:02 +0100 (CET)
Received: by mail-wm1-x337.google.com with SMTP id x16sf5045389wmk.2
        for <lists+kasan-dev@lfdr.de>; Wed, 20 Nov 2019 04:31:02 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1574253062; cv=pass;
        d=google.com; s=arc-20160816;
        b=hrb4ft3y+yekJCheZaG/RRgtPcDi/UuipRPHrf7/CkHJpWEMRv8dgRn0ScOweJUtwH
         aiaLUtPttPdHKd5EEIT6bkD/+5zsNVqh6Mi0kyQQ4dEGqi0SvF0rodluLpjAL0Kgbq4c
         0RKkvHQTffU/L9cGe2wwO3Mhm9nd1QNalvw/UjoAh0qSnnzD7SkVyGAAhKI4t0FFiIHW
         PdPBb9ioyamXroOhSZMWygVlxs1Ng59YsILiosxtZS11A26Bm0stCP8EpOQ6M/lVP9wz
         P4MHj2mEBazMBCLiToZ5hZ7N4V/3P7VPCwIJzaf7NpOLmqMJrNXG7lWxboFtccezs3tY
         O0oQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=4eOtM60OUwFs7gGlYJ29N+7jX3cpdOq0Iy2LO/0gX7M=;
        b=C4hadJcpCBEjei5e4wy27LUgoDkAwb26PpCUrZLvhC5ofinAoCZQJji9UonGT/iL04
         +fhB7BCYczgLhEsYXPktiv0RQBPxeZjM26PY3PwvxR7Z0vJmx6Pdw/mTBcLSx33c+VWT
         4QbISo9o7UR4m+rCtX609diSUtV4gS1BDoPhZN0Y9pLaIOpxakjfUcZrrEcVcNB/l6Xn
         8IE8cnhkdrbNBrTbv+5JDFWrskqM9S7iH7CNFzqu/53IsjN3XfeWMpQYIVOcFaZL/FRe
         Q2cKlKeTnyq//vBkD1psBpsvpFPUMTA7OK+DS75yi3FQovy3Hsqq6nJHq2YC2RvMLlNS
         pj/g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=kMbThVja;
       spf=pass (google.com: domain of mingo.kernel.org@gmail.com designates 2a00:1450:4864:20::441 as permitted sender) smtp.mailfrom=mingo.kernel.org@gmail.com;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=4eOtM60OUwFs7gGlYJ29N+7jX3cpdOq0Iy2LO/0gX7M=;
        b=mYd7K/ZcB31wG5FUnWkynfbSjABsqvYggdZQNAkFX5ZWERzrKMoQxXcpkUP+xfS5kg
         GJKt9dmr4lu6KnumSOe1vL3l+y3Uqyy4asklJ+uda+cQqB/fOMhlJn46GvH+ZS2B1pim
         JYznj7GofVYsNr4bSMGAQvELx8xfNAaq+uhZ23v83DFuA3wGXkPktipRjCpANFvFHJPc
         R2/Sep4b4WNOGroYNC9GG63yhLq+Ve5uT1pJ1NfNdvyEcp6wT5UPb53QEBALrUmQlsmN
         qOrrzJ2HuiPNykraJJ2Q+SCy28rICREXno++YC7yehsSfEHxd9DpFyvMtqLZCoDB5I8o
         d1Ng==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=4eOtM60OUwFs7gGlYJ29N+7jX3cpdOq0Iy2LO/0gX7M=;
        b=Cp0vYh2HiHn7t7BvUvIzPwn/20H0I0+KMvzjh+Nfz5slumAaiaGsFM7fS4VpHHj1RT
         rLZJuJezloUG0TNlbJ6lmjP8Jfj/x970bSIPdwaZjGJFsXYKd+VoS+J3ML2FKAQZ3NgA
         u5HASF4z1vVwECpt6A2SWuuBYQJAsP5jd0LR5sM4k9MPYdeb9/fvcrJITQymDV5WsRg3
         w1tdfRS4+Lba8Fg7uPM2OKv52zauC/Lh7QYIDI8wUWp/XL3MAkpJu5maD5ucFEOD4fy3
         j6EvhIesSu4aN/WR1l/DAtaKgBEiRMe3eRQddm1zoe651XN5sOAFFEKb6q2fcM12HsbB
         viVw==
X-Gm-Message-State: APjAAAWHXGomANea+0i0v6cus77J+vnvY4fK3TkKLjuron/bY16UVxeY
	hATTnSHOKyAhDtDABhelSRQ=
X-Google-Smtp-Source: APXvYqzJaEBGeaiVx1WTXudCTkPFb0HRVQSpMwyVDg6MQAkYb/f2ElOVuxd4qA2o0Dj5DntvZzyOWQ==
X-Received: by 2002:a7b:c959:: with SMTP id i25mr2955307wml.100.1574253062562;
        Wed, 20 Nov 2019 04:31:02 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:5512:: with SMTP id b18ls724759wrv.16.gmail; Wed, 20 Nov
 2019 04:31:01 -0800 (PST)
X-Received: by 2002:adf:fe0e:: with SMTP id n14mr3139901wrr.72.1574253061858;
        Wed, 20 Nov 2019 04:31:01 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1574253061; cv=none;
        d=google.com; s=arc-20160816;
        b=J8j+qCAWl3MwRRYPOmd4+FGHCCBEpxDLfEdbK88A9ZY6yQlIPTQ+xGEb+XQH3HeBfy
         6FZAJnOHzUo2cmkRuCAd0rcKe1La+tQBqXHwctb2Ni6f4fJ+XozBq8L5tPLY5s0ADzgS
         HOLrxyBTqEKqp/rG07T81c+SrDuROwpVQpace+qHgvCtbpj5O+hw+UEoeoAd71F1jtR7
         s/U0TEvLIJYlFDiz1DV+sH45VIRrrLuMFe0V/26GuUH1UZuyXhUDE/LjlOD/h7t+7KYl
         EGOQSC72YrnyEq2Rl2dgGs7h2LQ+dLlIIaJIWsJi8wuen1r5x1Sd+vlBNYakHbc8VUWc
         NlMQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=oF272YdvOBPcMekRUMKZ+4luBT6maFPugIEMdZDUVZw=;
        b=ZqPibUbq/Ov8Bx3rnSXNiJvEeoL3r/PMxaTbW1iDV+8adQXol+cMdgx2TsiS2sv2Dz
         4+x04ePSXXICJ1TDw6xqFbVVlBnifMwIuq6JjnnnnnIF6fHkYtzN/GS5m9/gYIORX5yK
         xkFyM5JSCVFYSU9rd6a+/l8BQp8HRVy8+55zcz8XtKWHztCU2qf+5pJJ2L2iXNYHkO4h
         /WgFl5WSTP2jKzEjO19dzuCYOzPkOofdXhdk9pxsE5NDpEue2PfcAQA4GqA8624QVles
         +4BB8docyMJnLvFlYoUrqA+x8x1p1bS784VrqxLErzCfuTJibaugAsVcmlpusAfio+Tq
         8vaw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=kMbThVja;
       spf=pass (google.com: domain of mingo.kernel.org@gmail.com designates 2a00:1450:4864:20::441 as permitted sender) smtp.mailfrom=mingo.kernel.org@gmail.com;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail-wr1-x441.google.com (mail-wr1-x441.google.com. [2a00:1450:4864:20::441])
        by gmr-mx.google.com with ESMTPS id d5si1355871wrm.5.2019.11.20.04.31.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 20 Nov 2019 04:31:01 -0800 (PST)
Received-SPF: pass (google.com: domain of mingo.kernel.org@gmail.com designates 2a00:1450:4864:20::441 as permitted sender) client-ip=2a00:1450:4864:20::441;
Received: by mail-wr1-x441.google.com with SMTP id t1so27930810wrv.4
        for <kasan-dev@googlegroups.com>; Wed, 20 Nov 2019 04:31:01 -0800 (PST)
X-Received: by 2002:a5d:4c8c:: with SMTP id z12mr2966064wrs.347.1574253061550;
        Wed, 20 Nov 2019 04:31:01 -0800 (PST)
Received: from gmail.com (54033286.catv.pool.telekom.hu. [84.3.50.134])
        by smtp.gmail.com with ESMTPSA id w12sm6421851wmi.17.2019.11.20.04.31.00
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 20 Nov 2019 04:31:00 -0800 (PST)
Sender: Ingo Molnar <mingo.kernel.org@gmail.com>
Date: Wed, 20 Nov 2019 13:30:58 +0100
From: Ingo Molnar <mingo@kernel.org>
To: Jann Horn <jannh@google.com>
Cc: Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@redhat.com>,
	Borislav Petkov <bp@alien8.de>, "H. Peter Anvin" <hpa@zytor.com>,
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
Message-ID: <20191120123058.GA17296@gmail.com>
References: <20191120103613.63563-1-jannh@google.com>
 <20191120103613.63563-2-jannh@google.com>
 <20191120111859.GA115930@gmail.com>
 <CAG48ez0Frp4-+xHZ=UhbHh0hC_h-1VtJfwHw=kDo6NahyMv1ig@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CAG48ez0Frp4-+xHZ=UhbHh0hC_h-1VtJfwHw=kDo6NahyMv1ig@mail.gmail.com>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: mingo@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=kMbThVja;       spf=pass
 (google.com: domain of mingo.kernel.org@gmail.com designates
 2a00:1450:4864:20::441 as permitted sender) smtp.mailfrom=mingo.kernel.org@gmail.com;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=kernel.org
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


* Jann Horn <jannh@google.com> wrote:

> You mean something like this?
> 
> ========================
> diff --git a/arch/x86/kernel/traps.c b/arch/x86/kernel/traps.c
> index 9b23c4bda243..16a6bdaccb51 100644
> --- a/arch/x86/kernel/traps.c
> +++ b/arch/x86/kernel/traps.c
> @@ -516,32 +516,36 @@ dotraplinkage void do_bounds(struct pt_regs
> *regs, long error_code)
>   * On 64-bit, if an uncaught #GP occurs while dereferencing a non-canonical
>   * address, return that address.
>   */
> -static unsigned long get_kernel_gp_address(struct pt_regs *regs)
> +static bool get_kernel_gp_address(struct pt_regs *regs, unsigned long *addr,
> +                                          bool *non_canonical)

Yeah, that's pretty much the perfect end result!

> I guess that could potentially be useful if a #GP is triggered by
> something like an SSE alignment error? I'll add it in unless someone
> else complains.

Yeah - also it's correct information about the context of the fault, so 
it probably cannot *hurt*, and will allow us to debug/validate everything 
in this area faster.

> > > +#define GPFSTR "general protection fault"
> > >  dotraplinkage void
> >
> > Please separate macro and function definitions by an additional newline.
> 
> Will change it.

Thanks!

	Ingo

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191120123058.GA17296%40gmail.com.
