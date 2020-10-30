Return-Path: <kasan-dev+bncBCQ2XPNX7EOBBJGZ6D6AKGQEK3FMHFI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x538.google.com (mail-ed1-x538.google.com [IPv6:2a00:1450:4864:20::538])
	by mail.lfdr.de (Postfix) with ESMTPS id 70CE52A0948
	for <lists+kasan-dev@lfdr.de>; Fri, 30 Oct 2020 16:09:25 +0100 (CET)
Received: by mail-ed1-x538.google.com with SMTP id a73sf2744257edf.16
        for <lists+kasan-dev@lfdr.de>; Fri, 30 Oct 2020 08:09:25 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1604070565; cv=pass;
        d=google.com; s=arc-20160816;
        b=OkSW5IRSgu7vQz/jnDhr8yjwem8PpiKkVokXmw4H4iWzjEnUE+bNMmCRZM8d4X9S4T
         3bA12A7/2X1trHBrI78Dbw1NW6/Od8DLR45zzMTFEmJfbYpEgDie70+WCDgORfhLL1C+
         je2KNHaUysYD1Di9OkY/eGRLgXigZL//K1sNmhDhAI/m3H/B7KVYoJpaiipFXWXrM0XO
         Q7yhouuDdHvQceguyQLBpfS3S5bZFzNXC4tr9zSPU1pXl1kzWzqfINAf/6iaOxg/pWup
         M2qeK+Lu+eIc0zILRjE74WuG746wutMX/99Xa3y504GRaMS8SeAA9trKc/7x4j6W4Hbr
         sw3g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=+mZ2FTZuIXOTPLoi7Ly/QykxoTsMq0beIfAAfBbGQ2E=;
        b=Rs3+BVdgwqnolK8aO1RqTIr/KkicCj2njmtDnFp/Sv4ojQHGmA7P8aYLf+9y/eC09M
         Jb+ZLxLMC2hn1DVJBQ7sv5hbW+I2YpBR01Ee0bxXftg0LYu94v0+CC3yqokry1VGjJMn
         BjUU3yXd4Xb7WSnXukby7JFLlNxpNl2xKZG3tSf0oUwgAJbFu0KJ1ZweIykyrmXBe4nC
         5ipYyMIaU9BoFkPPB0ILQKLgXqKOwe4YBzbof2Akw/EdrDinfzZrTDCBIdSX3DpENVw0
         6pBJOD2tYZPciswWPLH96DJh+ZnIZqil9uVLJzg+P9N1udqjuViJCeH+WK6ngX/m9oNp
         yj4w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=GJxiwN9x;
       spf=pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::141 as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=+mZ2FTZuIXOTPLoi7Ly/QykxoTsMq0beIfAAfBbGQ2E=;
        b=RUWW6pvFd+V5LB70ZTsBcm83kxbLPY+jyrdcvlWz7Ql885K3j0CFKuS1Xz1tk2pIvT
         /MWfTX1v5RNCfJZGJdUaFizAbJ+lZ1meD3IlI2yDH3VudFiip47fO95ffqu2dmS7aI8o
         HCQZ+X680dHNjcz2EiI0GdeE65jNeninu2FvTLxkj5jQ8mhOXQKGxPMAHPwF9TsubYq8
         Nhu6klqnC4l1bIPvdlJy1I4JeDnHTejqCy5XqPAVx5sE1Xvrcezen74+L14p7Z81pzsC
         pixYVZ7Q6Pvc6pchtqR87CCP6dLolUUJdA4h4gqAnV/f8GsX4SLCzjLIc4ubqdO+BJ7H
         7OSQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=+mZ2FTZuIXOTPLoi7Ly/QykxoTsMq0beIfAAfBbGQ2E=;
        b=eyCGtVgljYycntETOAE8lYaKWOi78sy1sWC0b4ly2fPfm25PSAYsUUEoAkUXFGdwPG
         lz8Oq1E4+L33tknCqLXIdFKgBgUtg36DEz12VZ9DcqHlXUa+eB/BzeTBBvylGbL0kXwY
         HuFBCQCzcuVyeSE3SSs0rvUSPnIbabN7OzmtEtwqJkvl/i2ozFDjQsaBrjMKJTdNb0ic
         r7DQqLbYn1I6Xbyx5iO/zg2AFMnW0kQ9Du9jZwl8NzqTu+yF3YvEVsxOGjkYv2Z7pN9r
         hM5czVfXp8bXMpAoFJUj0u5SmIoqs/YDlRLjqWgU1ePVHEbmKbenRmRYtRVl9iv5aPcW
         OOrg==
X-Gm-Message-State: AOAM533EnK5d367qEOh6jbnFA0hYGWgoArMr5bWyx6DNs32mu+83aX80
	WD0TihegfJPtvbDDJLUVvoA=
X-Google-Smtp-Source: ABdhPJxvpzq4kP36gotblT+6NgcNEqIZi2uandc+9BwSzWYOF6aih5SluPX4SHl5/65R8c6Czf4E9Q==
X-Received: by 2002:a50:c38e:: with SMTP id h14mr2983238edf.174.1604070565176;
        Fri, 30 Oct 2020 08:09:25 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:1351:: with SMTP id x17ls84ejb.4.gmail; Fri, 30 Oct
 2020 08:09:24 -0700 (PDT)
X-Received: by 2002:a17:906:5509:: with SMTP id r9mr3017825ejp.12.1604070564012;
        Fri, 30 Oct 2020 08:09:24 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1604070564; cv=none;
        d=google.com; s=arc-20160816;
        b=nsa0smPsdA49OpI0i2qHHxUVozqT+akdhWOIg6OF/clVdnyk74nECivbEA6C1mJnw0
         Oha+nnxbx4ruL0LsdVxt7cYlcOsjaJJjjYKSJuA0gtENqW8FeuVAAhN2JwGeFpH+KFee
         oVdphPUgn3sMEMNPwS8vclqX1A+69rBcpewSJSOpE1cytvugkD6ZoiEoGH54PN5KseCf
         u9Yhr9Vgv+0y6KtOETMv2hmk2PnoPqp0ksyIW1WZEiIKidcRUDz7DWxoICpNeIqmnd9v
         qrzqb94QjLcBwBMsFtKJeZdh0Dk5SMdAGVFA9A0SHt/FXrXvSTr8VNzVXmIAkh1aXg9I
         rAfg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Mk8TOBtLAUSh5UUmmftefVTpJAKNzTPUbZbR4xmTmm4=;
        b=wITV3RSPo6q2u9suh+sTsxFBX9TNv1ghUAT3AS3wnvw0RwcpaO5rGGZBDcyiTWL/Hp
         sPz0xKHb2F2xbAZ8GOfBd1h8YC8zlzMKli63y+YQU2+35BbO//7gLPNJ80L8WPCKhznl
         WdNlk8nArlVBLh8K0bYlg75o54ScKEVOWqikKz7wyLfO+lgEKqHHfGWY0clmcT0Wr1T9
         ftXz9N8rDjmuHfVkVyuDwV6VGjVFwvUMLrvtmJeq1WE0T+pTwCffncthNnpMEkhUgJh1
         ZMNclcbVUjnClWZAY3H9kM3/GPTvTOAQN9NNgm2KP0Ig64cPWwLwOdcjNTfqNOnIifRF
         CG8Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=GJxiwN9x;
       spf=pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::141 as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-lf1-x141.google.com (mail-lf1-x141.google.com. [2a00:1450:4864:20::141])
        by gmr-mx.google.com with ESMTPS id n7si155405edy.3.2020.10.30.08.09.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 30 Oct 2020 08:09:24 -0700 (PDT)
Received-SPF: pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::141 as permitted sender) client-ip=2a00:1450:4864:20::141;
Received: by mail-lf1-x141.google.com with SMTP id 126so8292778lfi.8
        for <kasan-dev@googlegroups.com>; Fri, 30 Oct 2020 08:09:23 -0700 (PDT)
X-Received: by 2002:a05:6512:1182:: with SMTP id g2mr1077748lfr.198.1604070563207;
 Fri, 30 Oct 2020 08:09:23 -0700 (PDT)
MIME-Version: 1.0
References: <20201029131649.182037-1-elver@google.com> <20201029131649.182037-7-elver@google.com>
 <CAG48ez0N5iKCmg-JEwZ2oKw3zUA=5EdsL0CMi6biwLbtqFXqCA@mail.gmail.com> <CANpmjNONPovgW6d4srQNQ-S-tiYCSxot7fmh=HDOdcRwO32z6A@mail.gmail.com>
In-Reply-To: <CANpmjNONPovgW6d4srQNQ-S-tiYCSxot7fmh=HDOdcRwO32z6A@mail.gmail.com>
From: "'Jann Horn' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 30 Oct 2020 16:08:56 +0100
Message-ID: <CAG48ez30tzadrtJm_ShY8oGjnYpf3GDfcajm7S0xX6UxfTCQZw@mail.gmail.com>
Subject: Re: [PATCH v6 6/9] kfence, kasan: make KFENCE compatible with KASAN
To: Marco Elver <elver@google.com>
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
X-Original-Sender: jannh@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=GJxiwN9x;       spf=pass
 (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::141 as
 permitted sender) smtp.mailfrom=jannh@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Jann Horn <jannh@google.com>
Reply-To: Jann Horn <jannh@google.com>
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

On Fri, Oct 30, 2020 at 2:46 PM Marco Elver <elver@google.com> wrote:
> On Fri, 30 Oct 2020 at 03:50, Jann Horn <jannh@google.com> wrote:
> > On Thu, Oct 29, 2020 at 2:17 PM Marco Elver <elver@google.com> wrote:
> > > We make KFENCE compatible with KASAN for testing KFENCE itself. In
> > > particular, KASAN helps to catch any potential corruptions to KFENCE
> > > state, or other corruptions that may be a result of freepointer
> > > corruptions in the main allocators.
> > >
> > > To indicate that the combination of the two is generally discouraged,
> > > CONFIG_EXPERT=y should be set. It also gives us the nice property that
> > > KFENCE will be build-tested by allyesconfig builds.
> > >
> > > Reviewed-by: Dmitry Vyukov <dvyukov@google.com>
> > > Co-developed-by: Marco Elver <elver@google.com>
> > > Signed-off-by: Marco Elver <elver@google.com>
> > > Signed-off-by: Alexander Potapenko <glider@google.com>
> >
> > Reviewed-by: Jann Horn <jannh@google.com>
>
> Thanks!
>
> > with one nit:
> >
> > [...]
> > > diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> > [...]
> > > @@ -141,6 +142,14 @@ void kasan_unpoison_shadow(const void *address, size_t size)
> > >          */
> > >         address = reset_tag(address);
> > >
> > > +       /*
> > > +        * We may be called from SL*B internals, such as ksize(): with a size
> > > +        * not a multiple of machine-word size, avoid poisoning the invalid
> > > +        * portion of the word for KFENCE memory.
> > > +        */
> > > +       if (is_kfence_address(address))
> > > +               return;
> >
> > It might be helpful if you could add a comment that explains that
> > kasan_poison_object_data() does not need a similar guard because
> > kasan_poison_object_data() is always paired with
> > kasan_unpoison_object_data() - that threw me off a bit at first.
>
> Well, KFENCE objects should never be poisoned/unpoisoned because the
> kasan_alloc and free hooks have a kfence guard, and none of the code
> in sl*b.c that does kasan_{poison,unpoison}_object_data() should be
> executed for KFENCE objects.
>
> But I just noticed that kernel/scs.c seems to kasan_poison and
> unpoison objects, and keeps them poisoned for most of the object
> lifetime.

FWIW, I wouldn't be surprised if other parts of the kernel also ended
up wanting to have in-object redzones eventually - e.g. inside skb
buffers, which have a struct skb_shared_info at the end. AFAIU at the
moment, KASAN can't catch small OOB accesses from these buffers
because of the following structure.

> I think we better add a kfence guard to
> kasan_poison_shadow() as well.

Sounds good.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAG48ez30tzadrtJm_ShY8oGjnYpf3GDfcajm7S0xX6UxfTCQZw%40mail.gmail.com.
