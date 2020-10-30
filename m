Return-Path: <kasan-dev+bncBC7OBJGL2MHBBE666D6AKGQEHT3UVQQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43f.google.com (mail-pf1-x43f.google.com [IPv6:2607:f8b0:4864:20::43f])
	by mail.lfdr.de (Postfix) with ESMTPS id 1E06F2A096E
	for <lists+kasan-dev@lfdr.de>; Fri, 30 Oct 2020 16:19:49 +0100 (CET)
Received: by mail-pf1-x43f.google.com with SMTP id t10sf5130194pfh.19
        for <lists+kasan-dev@lfdr.de>; Fri, 30 Oct 2020 08:19:49 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1604071187; cv=pass;
        d=google.com; s=arc-20160816;
        b=kI5TygrfMKb2APtRrRJk848PCSq4PBkIDDxfgwekCNOpEVhSukEHw+hRDKG5+tq8Vf
         kuiT5g+5OcovTnST6Gflj2Ud247mRCuNghoH2rRypkG8jwI2WoOTjvkJzzXiaG/6CiGv
         VLhVN5RwlcyVXwK8Pi29T772j1mGFgy2KlupR2eKoO8dVbLvYsh5tv9NTud5z5A7BTy8
         pdeZ92mm5x11FI2X66D33+3c4ejxOFIQPJySvivzG0fJHMxymo+A+08DWcijocZSzjuU
         tHEQ1s3m4APuHtcO05j/d7/1YipOxXehej+ZbU0A1rqTFsMlF5UyWsnmJHtJ1hVOJEGD
         nMsg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=1yzqpUtTN+uRAgbpZcsK3qX03ZdOhBxedmZBOXDiPp4=;
        b=rk484ceNjtgV2Xz0Lt5E0RehA5byQZtsVikLnkQId32ENU6GTNpGN4tbn+1WQUF9GD
         OV3E2FO6LYUCoGXokLFzKx5SyAekbHJkfWNC9B1ohjrgN3n24O3TlObytYuQO6/pTVhr
         FwgXqk+ueaLbNRAMZqIchLxc5g21xY0PRqyqRQolrnEdVr6a8PELvr4+b+T9kiJGYpjY
         eZKaT79URXtAxbhTpkzSesTiBXuscEZU2y2BMZsMxdCG1AywmYvgcSwLELVePCw+slGW
         xdMiSBD1ypfQabgPZmJzHAEecBmY4RJffrusRn+bCHbkov1NvXre2CvAIGodHakXfPhO
         YLGA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="Msw/AdRy";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::242 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=1yzqpUtTN+uRAgbpZcsK3qX03ZdOhBxedmZBOXDiPp4=;
        b=HPGtTO06JKGMxTw9BoTDsPmW2+bD5LqYPvYQbccTu3XCEbMTzzjeatWiwvMcr/muiT
         Ep77/BeSv440zIDdYq43nfhz9ylWWyKVws1WI5p6z6uXp1y1pT8NZddSuTSUW1UB45Cc
         +L3WmadOa1koLHcgrmIyTPfVy9aCJXtr+hocgKWZlT5/Eua+YNKCNM5IhgIKKI6ZLwTn
         WqFmh7/vCverSkCwRWM1655y7LeXxBMgxyLhGMnZYUrF9BfiWEGy1tbNftwGxtzpIOUj
         RudohrX1KQyBFmcClS0cnotQd5cngr9KbtDlGCq1d3AVXpARLNsovwIyRFj/5M8Ac6nm
         NKGA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=1yzqpUtTN+uRAgbpZcsK3qX03ZdOhBxedmZBOXDiPp4=;
        b=TCqfiZdfrbwgwm724879wjXfR3BVQIV8zMJ42OIMJczPzPg/ASuqy5I3H/KcS6uRH5
         uUFE1jVVlc6HehwlXlf7O0y7Hm8psra05Crj1QTu2GmC2pANFYEHolKv3pSg+wJ1mMpT
         xi6T+130aZo3JjPy5DKYHM87qEHt//hiEaXb8BnsuWb62RL4GHuwunU5e5yrM3c+8z3P
         eb9g6igVm9XAyPp6x8sRTkvKXPqYq3ubqZhbwXs7epkT3pbSL9aEcpAzw8Qx6wg5YHR6
         zhRKmcXC5fxWLHwHpcPKtU82tdwREcEBOE6cyml17BE6nALgYSoea5iXOicdNCAXX6oP
         0jMA==
X-Gm-Message-State: AOAM530rWK6LYEeFIWu0xDmSfcxaxT8sooKZHK+KMqkazwAQXG9MedOQ
	Od6bLCYsDC8HjhFqBoL8zc4=
X-Google-Smtp-Source: ABdhPJxr2eftSV28oW0idwM5MUNx+hvELAX70VLzTDsGzPvYItTx4IWvgyjoI2dqGuMrDlmOOTwcKA==
X-Received: by 2002:a63:c749:: with SMTP id v9mr2576347pgg.451.1604071187501;
        Fri, 30 Oct 2020 08:19:47 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:ec06:: with SMTP id l6ls1863273pld.8.gmail; Fri, 30
 Oct 2020 08:19:46 -0700 (PDT)
X-Received: by 2002:a17:90a:b63:: with SMTP id 90mr3683858pjq.154.1604071186777;
        Fri, 30 Oct 2020 08:19:46 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1604071186; cv=none;
        d=google.com; s=arc-20160816;
        b=Toace03VIqPv9YxfV7QBqusgCLNj11ApnmkIoVkWhm2b+Xhtd94GuW+j0RLjFXqbHx
         mB98RapvWWMkSbvM7D0tTiTW07LX0+RWJUzN0hlwKyBz2g+EsFaYJqB6Ot/lyLV6orfs
         is8J6HFJiwauRy/Guh7lo3Yku6b4iCWrQdlw6SHt6dSGA1IsTIPEPWv+Tq8QFRxWV5HI
         3ueFtF/w3ZlF4J1AQK4mhYYExcqQm9eKTIMFgFpyvOSmGI+kRSAMJc0M9e1vwyhM+/6p
         ZjLVRx8AOpMLBvP2JQgdP88sCOC8CDb01F3sCOlLjarWuUZNz3pmIVhUJq2Dso/J4KjI
         88Eg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Od+UUSBMiEqFH2KlwfDgZow7v7NLfac8lHnjw8U4wHg=;
        b=DLA0efCs6jC04qHCHkXADwsUEPgvkGlDP8hkjatmEpYHx0yGkjYN9Z5wml6OCniIPO
         JgKdTUuTN7VnWAOo0BCErMu8UMaX3bpM/57IotuLa3LT9PPEdQLR1f+iC78IK8iLvU94
         /bjzChdEGEewB4eSoLq3YNoOBapE6NFquzD5iU7vuZn7eYJDR/I1oobQGl+4V6JZAn9B
         ksq77EfDhtO2bJxHoUDVUB3I/1Jg9JyKUr2f3nPamrs9ozdG5QsX3NdxyoznSxS+RK3t
         AVEtETVeKmnkg8zgQSsmEZk5qQhoCOMxL3dy9lO43JNPeWv0IoJ0UHT5gt+BjgUah4CL
         MKbA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="Msw/AdRy";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::242 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x242.google.com (mail-oi1-x242.google.com. [2607:f8b0:4864:20::242])
        by gmr-mx.google.com with ESMTPS id t13si413066ply.2.2020.10.30.08.19.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 30 Oct 2020 08:19:46 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::242 as permitted sender) client-ip=2607:f8b0:4864:20::242;
Received: by mail-oi1-x242.google.com with SMTP id s21so7036735oij.0
        for <kasan-dev@googlegroups.com>; Fri, 30 Oct 2020 08:19:46 -0700 (PDT)
X-Received: by 2002:aca:4f55:: with SMTP id d82mr1984254oib.172.1604071185897;
 Fri, 30 Oct 2020 08:19:45 -0700 (PDT)
MIME-Version: 1.0
References: <20201029131649.182037-1-elver@google.com> <20201029131649.182037-7-elver@google.com>
 <CAG48ez0N5iKCmg-JEwZ2oKw3zUA=5EdsL0CMi6biwLbtqFXqCA@mail.gmail.com>
 <CANpmjNONPovgW6d4srQNQ-S-tiYCSxot7fmh=HDOdcRwO32z6A@mail.gmail.com> <CAG48ez30tzadrtJm_ShY8oGjnYpf3GDfcajm7S0xX6UxfTCQZw@mail.gmail.com>
In-Reply-To: <CAG48ez30tzadrtJm_ShY8oGjnYpf3GDfcajm7S0xX6UxfTCQZw@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 30 Oct 2020 16:19:34 +0100
Message-ID: <CANpmjNPoQkWuV0q3atamrAzyOxR9ZTpY43Ndg5+ko0KJhYt9sA@mail.gmail.com>
Subject: Re: [PATCH v6 6/9] kfence, kasan: make KFENCE compatible with KASAN
To: Jann Horn <jannh@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Alexander Potapenko <glider@google.com>, 
	"H . Peter Anvin" <hpa@zytor.com>, "Paul E . McKenney" <paulmck@kernel.org>, 
	Andrey Konovalov <andreyknvl@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Andy Lutomirski <luto@kernel.org>, Borislav Petkov <bp@alien8.de>, 
	Catalin Marinas <catalin.marinas@arm.com>, Christoph Lameter <cl@linux.com>, 
	Dave Hansen <dave.hansen@linux.intel.com>, David Rientjes <rientjes@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Eric Dumazet <edumazet@google.com>, 
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>, Hillf Danton <hdanton@sina.com>, 
	Ingo Molnar <mingo@redhat.com>, Jonathan Cameron <Jonathan.Cameron@huawei.com>, 
	Jonathan Corbet <corbet@lwn.net>, Joonsoo Kim <iamjoonsoo.kim@lge.com>, 
	=?UTF-8?Q?J=C3=B6rn_Engel?= <joern@purestorage.com>, 
	Kees Cook <keescook@chromium.org>, Mark Rutland <mark.rutland@arm.com>, 
	Pekka Enberg <penberg@kernel.org>, Peter Zijlstra <peterz@infradead.org>, 
	SeongJae Park <sjpark@amazon.com>, Thomas Gleixner <tglx@linutronix.de>, Vlastimil Babka <vbabka@suse.cz>, 
	Will Deacon <will@kernel.org>, "the arch/x86 maintainers" <x86@kernel.org>, 
	"open list:DOCUMENTATION" <linux-doc@vger.kernel.org>, kernel list <linux-kernel@vger.kernel.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, Linux-MM <linux-mm@kvack.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="Msw/AdRy";       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::242 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

On Fri, 30 Oct 2020 at 16:09, Jann Horn <jannh@google.com> wrote:
>
> On Fri, Oct 30, 2020 at 2:46 PM Marco Elver <elver@google.com> wrote:
> > On Fri, 30 Oct 2020 at 03:50, Jann Horn <jannh@google.com> wrote:
> > > On Thu, Oct 29, 2020 at 2:17 PM Marco Elver <elver@google.com> wrote:
> > > > We make KFENCE compatible with KASAN for testing KFENCE itself. In
> > > > particular, KASAN helps to catch any potential corruptions to KFENCE
> > > > state, or other corruptions that may be a result of freepointer
> > > > corruptions in the main allocators.
> > > >
> > > > To indicate that the combination of the two is generally discouraged,
> > > > CONFIG_EXPERT=y should be set. It also gives us the nice property that
> > > > KFENCE will be build-tested by allyesconfig builds.
> > > >
> > > > Reviewed-by: Dmitry Vyukov <dvyukov@google.com>
> > > > Co-developed-by: Marco Elver <elver@google.com>
> > > > Signed-off-by: Marco Elver <elver@google.com>
> > > > Signed-off-by: Alexander Potapenko <glider@google.com>
> > >
> > > Reviewed-by: Jann Horn <jannh@google.com>
> >
> > Thanks!
> >
> > > with one nit:
> > >
> > > [...]
> > > > diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> > > [...]
> > > > @@ -141,6 +142,14 @@ void kasan_unpoison_shadow(const void *address, size_t size)
> > > >          */
> > > >         address = reset_tag(address);
> > > >
> > > > +       /*
> > > > +        * We may be called from SL*B internals, such as ksize(): with a size
> > > > +        * not a multiple of machine-word size, avoid poisoning the invalid
> > > > +        * portion of the word for KFENCE memory.
> > > > +        */
> > > > +       if (is_kfence_address(address))
> > > > +               return;
> > >
> > > It might be helpful if you could add a comment that explains that
> > > kasan_poison_object_data() does not need a similar guard because
> > > kasan_poison_object_data() is always paired with
> > > kasan_unpoison_object_data() - that threw me off a bit at first.
> >
> > Well, KFENCE objects should never be poisoned/unpoisoned because the
> > kasan_alloc and free hooks have a kfence guard, and none of the code
> > in sl*b.c that does kasan_{poison,unpoison}_object_data() should be
> > executed for KFENCE objects.
> >
> > But I just noticed that kernel/scs.c seems to kasan_poison and
> > unpoison objects, and keeps them poisoned for most of the object
> > lifetime.
>
> FWIW, I wouldn't be surprised if other parts of the kernel also ended
> up wanting to have in-object redzones eventually - e.g. inside skb
> buffers, which have a struct skb_shared_info at the end. AFAIU at the
> moment, KASAN can't catch small OOB accesses from these buffers
> because of the following structure.

Sure, and it might also become more interesting with MTE-based KASAN.

But, currently we recommend not to enable generic KASAN+KFENCE,
because it'd be redundant if the instrumentation price for generic (or
SW-tag) KASAN is already paid. The changes here are also mostly for
testing KFENCE itself.

That may change with MTE-based KASAN, however, which may have modes
where stack traces aren't collected and having KFENCE to get
actionable debug-info across a fleet of machines may still be wanted.
But that story is still evolving. The code here is only for the
generic and SW-tag based KASAN modes, and MTE will have its own
kasan_{un,}poison_shadow (afaik it's being renamed to
kasan_{un,}poison_memory) which works just fine with KFENCE AFAIK.

> > I think we better add a kfence guard to
> > kasan_poison_shadow() as well.
>
> Sounds good.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNPoQkWuV0q3atamrAzyOxR9ZTpY43Ndg5%2Bko0KJhYt9sA%40mail.gmail.com.
