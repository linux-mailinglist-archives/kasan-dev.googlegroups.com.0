Return-Path: <kasan-dev+bncBDX4HWEMTEBRBAUASH6QKGQE5V2XGQA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x240.google.com (mail-oi1-x240.google.com [IPv6:2607:f8b0:4864:20::240])
	by mail.lfdr.de (Postfix) with ESMTPS id 0FB452A85B9
	for <lists+kasan-dev@lfdr.de>; Thu,  5 Nov 2020 19:10:12 +0100 (CET)
Received: by mail-oi1-x240.google.com with SMTP id 204sf1006952oid.21
        for <lists+kasan-dev@lfdr.de>; Thu, 05 Nov 2020 10:10:12 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1604599811; cv=pass;
        d=google.com; s=arc-20160816;
        b=rIp9VwqLNVpeDV+WC15Qm0QcN/u/Z/+wgxB1I2KJ+u17t2wFpoaoLSbQ/xfq9tmonH
         NI+sfPgJGqYcDQrNzCuHK9v0aCCo+2Ki+5GMWLwWvDHVoHrnQxFrkELrRsobcXs0kJR0
         +d9QATdF+9xy5IizBNyv4RJO2rIjps6ggnv9qCAc/jnHtOok8q0zaMv5hZewKdLNABQM
         aw3xab9rqDvsQJZbLKtDDjsqMqcGpHgGEjEahKtxneV2/i5CJjGSCQoy9qTq6v6NPLe8
         SlVxBhbH31QmFde4rW/RGT1SmU7xbg7g+dSUbRiRnOBl9UKo7hfeC1H+CadkQRyMZjB5
         qvIw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=cDI6kG4IxYw/IwcM5/ueDmx7GPoftwydHp60H99FhDI=;
        b=kzInlp43cEOs56zYnye97/fSO9S/2X5AbkFTMiMM2NL5urwN9qRIMMFBi8Eu/qgMd+
         qzwD9xsJ1aaBLeOiHD5KOSazRilSKapqsS7cd6nOkA1ivsnnVzGJYTznaGWAq58b5QP3
         vePshJ4VPTpeun+Ip6I95WtQEK0vaMhRI44xQ4HylaiDoTwgUV0z1e0V+TrzcqzJvXUI
         ttiDZzbnQQGXFSoeigWD4z+PyPe25hrCpoRXq6ix9WQwebGk2xojvYlRCRQLLvo0It+a
         JX0vu5I6QiPtdByCZAt++HVsdZoZw+fWt3bRL3JAnPjx7v+XAl0JhNNbC8crUhiwbi3c
         t1sA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="F491/pGR";
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::541 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=cDI6kG4IxYw/IwcM5/ueDmx7GPoftwydHp60H99FhDI=;
        b=bxMn1timlaJsKCSYdk0nhOOHaa0AgLdh5iWoHFYcq7j1BZ3vv6U4KlyLZgDVZHbSdU
         BAyzEJuEEXEZ911t9GGAg8nrS/vO7vaRaMYXYRty2Zwh0FJs6a4UAB360OI95WBDhsWg
         j1pip8pDxde6x1X8NzmjMD9ErYcN2hYkcT3Tmdx6N3pPQPS5h6czB8y+UUvYG/fKtvnR
         FqxMrAzxg7aOj4OY47xgUThXPgja7pc+QqIFG9zTl0sLwazg3mmos9o+MEKv3kMSV8OH
         93A8kN3SX7yw5K53hB7xkIHtkIfYLymY+tMSHznsUGvBxgcAvg5uheipWdfdkF+SvaIO
         9hAw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=cDI6kG4IxYw/IwcM5/ueDmx7GPoftwydHp60H99FhDI=;
        b=fDyA//9PQGMdfBXAoedMrg0FYHKVHiBm+ekeUtuvk4AuQMfMoILmWyu7O5IfU7k0Ag
         9U8Qt/8Rs2zjw3PdotEqib6xRjyftxHn/L2weLzELEQohHYAU/a9VEpmj3XANsKj4L84
         klWAtdOVwyr/vh3qtvxIHOa4/ofEWIf8iKemRYnGfCZISfXxjYMO6TCHRPc/VMj1N1hG
         PQ3e6K5MNOSPIkm2dBQ5CH1bgXs2z1t5BKDPm/h4fDwAHeTYu2W+toZhSIfz42E/5XTa
         CdPcDW4mcyAyPj1iOlmh5SXVFw2U1OPeTF1eFLAGLwbC7RqH/ee4Ws20yH0L/yqBKeA5
         Tk6g==
X-Gm-Message-State: AOAM532ycVc/4KA7WlgrOuOv8I3ZuZA5RLt/b9/YkTm/UVERZPq33/Rm
	rQlaCfwG+/8nGX13oTZLYg0=
X-Google-Smtp-Source: ABdhPJxckajXvpkXbDrpMFa0kNJnPjsGtDldGDIRghW1L4YFV5Kg9RV9mmG41uCCizyPeGKlHgASWw==
X-Received: by 2002:aca:75c4:: with SMTP id q187mr411266oic.132.1604599810875;
        Thu, 05 Nov 2020 10:10:10 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:53cc:: with SMTP id i12ls648694oth.7.gmail; Thu, 05 Nov
 2020 10:10:10 -0800 (PST)
X-Received: by 2002:a05:6830:2397:: with SMTP id l23mr1035543ots.308.1604599810506;
        Thu, 05 Nov 2020 10:10:10 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1604599810; cv=none;
        d=google.com; s=arc-20160816;
        b=zlFAdpOT20IBbxZcaMw5Hei7n8x5/GEkVV23EMJ9K7Lt9pISqS70jzHmbT1FwcJ1dC
         XUZlnqSXGUAbB1OWrPwIp+qoICcrfYmby6OuYPlGdLcQkiTM3im567PugwGcLMwUUeIU
         KajBiniEe7nUv1gQYxgOSNVw/hAfMFCH42ikWWC81uhuzh957As/ha21cRixwgoRudbp
         hcEGVz0gJgSTQ1fNQpzLBuDsKBG7IYYjvRp1T7YiRTNWuC3EhRoL9Z0jRko8zMueHqwT
         tpOopLHG4etFDTJl4i4S2Z0Qxb3Yo1569IumKbr3u8gdThQobJCQ46S50jgGEpkuEU6y
         Q8gw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=mAoNSuBVW5u3fxEUjvf+bvrAfgyMkB897WinOBxVK3w=;
        b=P7muNFCfZZM825ZA6jj5nr25DohdlhIj/V06F9xDGErYy+KnU9sALd7F6azruUWfjy
         KRoNWgoBdCyrYiSar+qMrb+ub8cZHimpP3cBMFA2kjKx0eWB1MD4fX+0GvpnMo5TbBud
         nj4C9h8NH4WD/8CmbFVJaz8PRC3kHDqmaCMRWrCY+4bcNfDnKPm6uAjKyOz1cE7pvQ1O
         mvB41HKBbbab0zAeagawsWwCkQPZ1KT1iUjFImbZZrsHWHTegmIFXuExdyrSjz5ILABF
         3RhqJxhWH2jZXSgXj1iVhngvp6laZp9VGgoFqICNLJMMxpUZ6wTDmKH5nwoXBa1ojPOo
         ZndA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="F491/pGR";
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::541 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pg1-x541.google.com (mail-pg1-x541.google.com. [2607:f8b0:4864:20::541])
        by gmr-mx.google.com with ESMTPS id h8si114489oih.2.2020.11.05.10.10.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 05 Nov 2020 10:10:10 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::541 as permitted sender) client-ip=2607:f8b0:4864:20::541;
Received: by mail-pg1-x541.google.com with SMTP id r186so1908214pgr.0
        for <kasan-dev@googlegroups.com>; Thu, 05 Nov 2020 10:10:10 -0800 (PST)
X-Received: by 2002:a05:6a00:16c4:b029:162:bf9f:6458 with SMTP id
 l4-20020a056a0016c4b0290162bf9f6458mr3576815pfc.55.1604599809690; Thu, 05 Nov
 2020 10:10:09 -0800 (PST)
MIME-Version: 1.0
References: <cover.1604531793.git.andreyknvl@google.com> <5e3c76cac4b161fe39e3fc8ace614400bc2fb5b1.1604531793.git.andreyknvl@google.com>
 <20201105172549.GE30030@gaia> <CAAeHK+x0pQyQFG9e9HRxW5p8AYamPFmP-mKpHDWTwL_XUq7msA@mail.gmail.com>
 <20201105173901.GH30030@gaia>
In-Reply-To: <20201105173901.GH30030@gaia>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 5 Nov 2020 19:09:58 +0100
Message-ID: <CAAeHK+wOyPYP=BkhratZwR=NKyzLWzwTTbyGtqQ75tJyM1D=rg@mail.gmail.com>
Subject: Re: [PATCH v8 30/43] arm64: kasan: Allow enabling in-kernel MTE
To: Catalin Marinas <catalin.marinas@arm.com>
Cc: Will Deacon <will.deacon@arm.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="F491/pGR";       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::541
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

On Thu, Nov 5, 2020 at 6:39 PM Catalin Marinas <catalin.marinas@arm.com> wrote:
>
> On Thu, Nov 05, 2020 at 06:29:17PM +0100, Andrey Konovalov wrote:
> > On Thu, Nov 5, 2020 at 6:26 PM Catalin Marinas <catalin.marinas@arm.com> wrote:
> > >
> > > On Thu, Nov 05, 2020 at 12:18:45AM +0100, Andrey Konovalov wrote:
> > > > diff --git a/arch/arm64/kernel/mte.c b/arch/arm64/kernel/mte.c
> > > > index 06ba6c923ab7..fcfbefcc3174 100644
> > > > --- a/arch/arm64/kernel/mte.c
> > > > +++ b/arch/arm64/kernel/mte.c
> > > > @@ -121,6 +121,13 @@ void *mte_set_mem_tag_range(void *addr, size_t size, u8 tag)
> > > >       return ptr;
> > > >  }
> > > >
> > > > +void __init mte_init_tags(u64 max_tag)
> > > > +{
> > > > +     /* Enable MTE Sync Mode for EL1. */
> > > > +     sysreg_clear_set(sctlr_el1, SCTLR_ELx_TCF_MASK, SCTLR_ELx_TCF_SYNC);
> > > > +     isb();
> > > > +}
> > >
> > > Is this going to be called on each CPU? I quickly went through the rest
> > > of the patches and couldn't see how.
> >
> > Yes, on each CPU. This is done via kasan_init_hw_tags() that is called
> > from cpu_enable_mte(). This change is added in the "kasan, arm64:
> > implement HW_TAGS runtime".
>
> Ah, I got there eventually in patch 38. Too many indirections ;) (I'm
> sure we could have trimmed them down a bit, hw_init_tags ==
> arch_init_tags == mte_init_tags).

The idea with these indirections was to make hw_tags.c to not directly
call MTE stuff and abstract away the underlying memory tagging
implementation. We won't know for sure how fitting these abstractions
are before we add another memory tagging implementation though :)

> > Would it make sense to put it into a separate patch?
>
> I think that's fine. I had the impression that kasan_init_hw_tags()
> should only be called once.

This was the case before, but not anymore. I've also added a comment
before the kasan_init_hw_tags() definition.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2BwOyPYP%3DBkhratZwR%3DNKyzLWzwTTbyGtqQ75tJyM1D%3Drg%40mail.gmail.com.
