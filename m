Return-Path: <kasan-dev+bncBC7OBJGL2MHBBTNS6D6AKGQEJYVSKLQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x839.google.com (mail-qt1-x839.google.com [IPv6:2607:f8b0:4864:20::839])
	by mail.lfdr.de (Postfix) with ESMTPS id 496462A06B3
	for <lists+kasan-dev@lfdr.de>; Fri, 30 Oct 2020 14:46:54 +0100 (CET)
Received: by mail-qt1-x839.google.com with SMTP id y14sf3976990qtw.19
        for <lists+kasan-dev@lfdr.de>; Fri, 30 Oct 2020 06:46:54 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1604065613; cv=pass;
        d=google.com; s=arc-20160816;
        b=i0XarEXUFEKl0ZHHRKGyZdogG5FMP1FQCSQ2zbcOdTeWqpdQCkmtOrs1HZrdE9BXhV
         OrjufBM6L4vApD3EhgatgSTvU7dhlcKeOKWq8FYskhCvD9jSlYyTY2/g01+tf3+yu35A
         AP1Um1QGLnuQmP6tDi00C/edmZRx84TEJ88CBiej41BBpVgKxczFNY39DYhAlZOFuJZM
         2wfdnquc934IHsxuW83z9A/hkYxCMUVy89qY45dGyjnc0NUxerU4SFGUvlhZT6zr+Nk2
         SeG3sXLvPUQvIJr7X5APZDIDgUXSGa2+MDwdHvmg/Ug7zoH8RPAnLj+tQVk/FonXVEhR
         sebw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=k9jbDqwUj0VkVdyOpNGCRyFKAiyOS+JqE4CNZ1uy83U=;
        b=fF7+8QCoPZ7zE7KAvCdjH5CAY6AS/luS3QnbDch8KjAnOXpYHNjXJ9XJT2kQ+tJ1vV
         KS2NWHxP+53Xtx6nQadD3CPh4I2A7OslHHVz4OQNLzUkFGC+Lx9hS2xzz/CYkiGeMXGW
         8wapxHOuYtTZoPZkfC9YMGOCD/TdE1NQ77xKKwLQWbTe3RbLMUQemgTpfPljnZvUMmHD
         BH6Bn6V3n1/Op4SgTUUBOj2fnNcl4qw0UfAoSKgbWoETYKmCw27EjyYGT+/Hv5z50n+E
         DzQGXVN2eFrRclNEMvFnseLvVBR/KP5HROv8+pXxDLbsGDx5tCbuQ8UqUTXzE3yvmvzv
         If7g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=ADogkMye;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::244 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=k9jbDqwUj0VkVdyOpNGCRyFKAiyOS+JqE4CNZ1uy83U=;
        b=EW3DxwnS/u04jiSiZkkNwJhlC/7ZOdeYmCoPWTgucnOGAhFx2a4Va33CiXOp6O7D5g
         mcipOgpKCKGatQlAH3Qwv1kMB3LEdC0tCcuYAnsKlTDg7kUt7fEI74RhjI1uOb7j/6ET
         o9hzsrP4SPmL3plL3gO8IIFXThgWzAaD4tEstJz1tGB1h854VOs5QzxlodKXgY9r9tC8
         dXtZg7kDQGPpQsPB4aatvGd46aus5VHt7uzLz1GQidGceafQKZGuYu83BnDfCBAxW901
         KItX6uS6HkCatk/ubKPaaFnH3Cg9GW234SfoC2qb2BvHefaki5REWIFfyTM6SGDuckQ2
         GWMQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=k9jbDqwUj0VkVdyOpNGCRyFKAiyOS+JqE4CNZ1uy83U=;
        b=WxCO+O75abvrHmPJEt/Ko6bF3F3NygxLHWLX0X5YPzOoKYuumTvUzapVjrlQ5YcWFq
         C+t9ZQ58MZ8NrPDMzWzCGaWo7GjSmUBp6zWo/gzaEJ/WrVucfqGFiVlvQofQ5Hq/u93b
         jdiu+YJD2HbDaSpBlHEYeURWxxDbkcnPtEm9sijDW2+3mtemqMkI3VMvchAa70u5AR8B
         hQg8erMl9ktwtlTOe01bMcAEhor5F66FW6PAi7xnhjmnpYO+eJXfF+EYVtkRg4IiHoee
         jKCZFi/9xJWvB/8TxCfXrpqTa9jZlGdOus23TTBM0NMhgXSnGygX0MVXapDeQU2PwvPR
         NX6Q==
X-Gm-Message-State: AOAM532XEHEzaCxTjllhJ1zdNxrmAEq8lvhHpTGbU0gHAvmQ1hkuq7f7
	V6EQQ7yYHdymrlGtQ+CR6NQ=
X-Google-Smtp-Source: ABdhPJyZzidVzMAT8/P9jQmf5Gdc0Vtu6e4rucXqtw5SJ1t6zPlJkGJJmrlLpTSY4uVSQURSSq7puA==
X-Received: by 2002:ac8:5a8c:: with SMTP id c12mr2057810qtc.310.1604065613378;
        Fri, 30 Oct 2020 06:46:53 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ad4:4a21:: with SMTP id n1ls1613064qvz.11.gmail; Fri, 30 Oct
 2020 06:46:52 -0700 (PDT)
X-Received: by 2002:ad4:4f22:: with SMTP id fc2mr9761769qvb.28.1604065612916;
        Fri, 30 Oct 2020 06:46:52 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1604065612; cv=none;
        d=google.com; s=arc-20160816;
        b=qrBOuC6iLp3W1IzsIIT9C4W0Tscq6o+MCrNonDym5WjGyHwzL499D6d9zoMGr2TT0v
         lHHs6I50Vdqdgj21qEeaVBH1iqwcUWEH6VtcFXv4mUEhRBqXiR2mu9OUwwTKhdS5weyQ
         3MYfxiaPFYF1IJmdZZkS7HrwHriwVWYGrbsuf2Y39oTW5k4AUF9BlsH+svTZfiUKYfRE
         pGb4TvDzrnF8NeyhEswwkWv3oSC1YeQnWO51pa7794bdjw3jvC1JRBi9CYPB5xV59UGO
         oALBUbUFyYEjPelsMWE1bkYea1PTUaaM0CAywABYAsYJk1O76EhlZio0LeL8asDJ7/tW
         hMNQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=L9KsQ649Ydk+F62S7OnKir8xMXm76fswU9q4GRYaxwA=;
        b=lsyslztRdYkXX+ZRXZ0vcyBRyjys3bNUn4E2ONZY36i3R0ALgeoW4S55h75PzzWve1
         nmSCbw1CudqaZ6WLRa6onTTnpRGoW1liW8CDSSgzdUXAHtdbZyhwPcuotg4bCPGd4NZM
         hGwzEs9k/dJ3kux8qhNDjBnhaV0nGUvm3N4oYasnGg/GPEvjGyI7mh81edsMIwbmalty
         711vNXB4J55dQSUsfrzurY4UFX1mp26jzHEztgB5Baa+5ngNaVRSdm0lkABBaQUDDSFI
         A6e5737T6pG6XmNqirr3bBZYdizxntYrnKVRBLeUEIOSBg76pE4TO8d5NvH1Sp1Yb6p4
         zFKQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=ADogkMye;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::244 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x244.google.com (mail-oi1-x244.google.com. [2607:f8b0:4864:20::244])
        by gmr-mx.google.com with ESMTPS id x21si386129qtx.1.2020.10.30.06.46.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 30 Oct 2020 06:46:52 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::244 as permitted sender) client-ip=2607:f8b0:4864:20::244;
Received: by mail-oi1-x244.google.com with SMTP id 9so6689651oir.5
        for <kasan-dev@googlegroups.com>; Fri, 30 Oct 2020 06:46:52 -0700 (PDT)
X-Received: by 2002:a54:4812:: with SMTP id j18mr1740133oij.70.1604065612340;
 Fri, 30 Oct 2020 06:46:52 -0700 (PDT)
MIME-Version: 1.0
References: <20201029131649.182037-1-elver@google.com> <20201029131649.182037-7-elver@google.com>
 <CAG48ez0N5iKCmg-JEwZ2oKw3zUA=5EdsL0CMi6biwLbtqFXqCA@mail.gmail.com>
In-Reply-To: <CAG48ez0N5iKCmg-JEwZ2oKw3zUA=5EdsL0CMi6biwLbtqFXqCA@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 30 Oct 2020 14:46:40 +0100
Message-ID: <CANpmjNONPovgW6d4srQNQ-S-tiYCSxot7fmh=HDOdcRwO32z6A@mail.gmail.com>
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
 header.i=@google.com header.s=20161025 header.b=ADogkMye;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::244 as
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

On Fri, 30 Oct 2020 at 03:50, Jann Horn <jannh@google.com> wrote:
>
> On Thu, Oct 29, 2020 at 2:17 PM Marco Elver <elver@google.com> wrote:
> > We make KFENCE compatible with KASAN for testing KFENCE itself. In
> > particular, KASAN helps to catch any potential corruptions to KFENCE
> > state, or other corruptions that may be a result of freepointer
> > corruptions in the main allocators.
> >
> > To indicate that the combination of the two is generally discouraged,
> > CONFIG_EXPERT=y should be set. It also gives us the nice property that
> > KFENCE will be build-tested by allyesconfig builds.
> >
> > Reviewed-by: Dmitry Vyukov <dvyukov@google.com>
> > Co-developed-by: Marco Elver <elver@google.com>
> > Signed-off-by: Marco Elver <elver@google.com>
> > Signed-off-by: Alexander Potapenko <glider@google.com>
>
> Reviewed-by: Jann Horn <jannh@google.com>

Thanks!

> with one nit:
>
> [...]
> > diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> [...]
> > @@ -141,6 +142,14 @@ void kasan_unpoison_shadow(const void *address, size_t size)
> >          */
> >         address = reset_tag(address);
> >
> > +       /*
> > +        * We may be called from SL*B internals, such as ksize(): with a size
> > +        * not a multiple of machine-word size, avoid poisoning the invalid
> > +        * portion of the word for KFENCE memory.
> > +        */
> > +       if (is_kfence_address(address))
> > +               return;
>
> It might be helpful if you could add a comment that explains that
> kasan_poison_object_data() does not need a similar guard because
> kasan_poison_object_data() is always paired with
> kasan_unpoison_object_data() - that threw me off a bit at first.

Well, KFENCE objects should never be poisoned/unpoisoned because the
kasan_alloc and free hooks have a kfence guard, and none of the code
in sl*b.c that does kasan_{poison,unpoison}_object_data() should be
executed for KFENCE objects.

But I just noticed that kernel/scs.c seems to kasan_poison and
unpoison objects, and keeps them poisoned for most of the object
lifetime. I think we better add a kfence guard to
kasan_poison_shadow() as well.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNONPovgW6d4srQNQ-S-tiYCSxot7fmh%3DHDOdcRwO32z6A%40mail.gmail.com.
