Return-Path: <kasan-dev+bncBC7OBJGL2MHBBWEUU75QKGQEV7H3ZYI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3f.google.com (mail-yb1-xb3f.google.com [IPv6:2607:f8b0:4864:20::b3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 38656273F00
	for <lists+kasan-dev@lfdr.de>; Tue, 22 Sep 2020 11:56:41 +0200 (CEST)
Received: by mail-yb1-xb3f.google.com with SMTP id b8sf11339403yba.10
        for <lists+kasan-dev@lfdr.de>; Tue, 22 Sep 2020 02:56:41 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1600768600; cv=pass;
        d=google.com; s=arc-20160816;
        b=nEZKaOFSi15yyB5P8kcFylBwO93uSfGAcXP+/P8KLWqTbfgA4xet6uigRVNZgIpmQ/
         D1sBxvUum1dtz0Z1DnnKCX+GvkSdKpwbZN5x3G9QH3hk/cfB6v9voMMeemJN0LDr1zAq
         nPbM3B2oXIYye6bgjTPKvTLFubziAqy7zP2ERKog9S8WzjfknsfwTM7Ad9IpGKZRECmO
         6Re9Q7goaFmlTcveHK1bjaoy2MXXB5EaCgj6uWKU3HEyoKmBi8V2MEf5JGYBYgY8UBqj
         Ac5ItKkVcABem9eZN2jLFmhkcfLMOXbwODEcCRBV/McRrS59RGg/lYF7G3/UFxW7ucxn
         F32g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=+G4q880+FieagZXabikaP157g+p9ZVPXKzVYNWtBajc=;
        b=gmmKFV5xfikl9or8FUg6dgaSaCauPEc1MIx2mNOVwULJst6VuIekel9Cq72pNzygn9
         1ALhnNOhwdCvevKEVTj+wfaaxK3zH6+gpXChsTClsLktUA+eCjAsOjUYfyYo3FJ2Jbz4
         8ztZXk0LRB7RoD9O/Dk32ilohEQeumlvrNkk2K0uiPrKvRG7zu3rUDeucsZgOXxRz6om
         o+GJkgirMw4ePh0z1owi3FdU8mkKR1rM5Gw2jUSzLvcJDnveml3rr/4kgzAS4x0Fe3Wr
         X+Up2kd2/6XD6Plt/3mGgkNxu9zldWEBG+jFZ0Z5c0AqtfyhzAsCmid+33vKrV1f/2R0
         +4Uw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Js+n82cx;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c44 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=+G4q880+FieagZXabikaP157g+p9ZVPXKzVYNWtBajc=;
        b=LEvlIFJ3ZkKsX4EqrIpZTS3ZFhQdjnD1Q9ZEUiAsHG4JVsl8QTJ51nJmDcAt+4K02G
         M8FKFl8Y2SE2mj6EDGK0PPLkEvAHPuKm9M7JuAzwexKR/XZ8/AAfNMoKw/SmdNGK1Afc
         TGwcTM0kkObhQx0wh+bJBqfu7tY4XNotNYDUbIr9gNMFnU6V/m6v2qEZ6OD3SKWK1ukG
         jnJPkrtOADG9sa5xPBb4z+vxgQQkN8UB325CysAXe3rlOFq9NcCplTnIQ4qZFhZXjWtW
         OUS58FrJpdQi/CU7FfM6UbrGDZdFGyVFja1TwOFi6/ORx78+m+32qVR5TEQJAX9Zw5Yx
         O/kw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=+G4q880+FieagZXabikaP157g+p9ZVPXKzVYNWtBajc=;
        b=mTSnkCMf+imLSCYlvB0Y8F4zb1XJwBDVzIapGAFDjt+Sd0hubwtJufBA7xQC5PUnyc
         AtrTid8sprueM+8Uc4qTf3AcbvISjMqXKZf+oDrar9szMsNVfpIO8T9bYW5OOSwiFiu1
         P/3yslff9W4Ta066IJvZk4rnUya2KVXAPfRsLnIHkeudEftV7g3Rj8tyUSd1PBHWY39R
         OkqRliJRESvUPdBme+Gi5dYjLMgT65TGhBeRoLCAiITjtpP3oENPCVWDEgwJJfDK8Wu0
         RWh2vdGRKKCDBTGMbVkI7uX5Cq2CH/DmWYGIsCWWjSloGcleRJH+Lhcix5trkLW+PoMs
         ZTsw==
X-Gm-Message-State: AOAM532f3AfivUNwITm5SxgzcNJdsCmG9PfPMdQWg3x/VaEiRTos2fOe
	+8X6YOLdp+EKlP0O5r7QX3E=
X-Google-Smtp-Source: ABdhPJzzIXTSAZEJexJWCPBIMj54PZlizL/NWhIO7W+r8KRAwFBjfxKy67XVVm3IaUbIpRVfKby7CQ==
X-Received: by 2002:a25:8812:: with SMTP id c18mr6074622ybl.330.1600768600112;
        Tue, 22 Sep 2020 02:56:40 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:5755:: with SMTP id l82ls6932729ybb.5.gmail; Tue, 22 Sep
 2020 02:56:39 -0700 (PDT)
X-Received: by 2002:a25:d8b:: with SMTP id 133mr5506059ybn.294.1600768599683;
        Tue, 22 Sep 2020 02:56:39 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1600768599; cv=none;
        d=google.com; s=arc-20160816;
        b=wN1gPPCJqNXLll7DnRJvNYzC0XqaQKop42f9Cn8iD7eXmoR+LUX6Hw0dgyLAxBMw/1
         pJh/twNhcJ3qyIh3klPX8KTrvBGMo7qiC6F6JzTf5DPpu2Wc0lgWoVY9gmj6qN6RPeZ8
         6qydplqcPbEcIrlM++z7TXz9dlo65+h4VEzGad7PJ+3DRxYbxDALsH0zanMMixC+CCex
         7i6OGMZaUSY0JNeL2WqrFJ+LFAYKgluq2hRiSS/DIbo5Rus2jAgP5I8DQgk5xXwIIKKe
         gvXJRVb3sXpSLJ3AseJcr+Cnm1TvinW61vQ4wTE1uPbAAYUN27/zP9TZ0q4iWy9TGzrC
         2FxQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=eVKPH13bJ8Pw64uEwVW7kgXl7zM95RCC9p4HQ/Nmkxc=;
        b=nwSX4Kj30d8ykoLuBgYjcJsEWHuIK8Hg/PTSx/0duKvEiretzDFbc0v1A7lDb2WBJC
         ggvyhc+8k1DHITp3s2w7rxPR0xoKvLJWkva7vdUPCnj2Td2gsDL3pgtZlMoFqqY7H686
         bHO/JB+XydfEoMy9bu0z+QHC8Edf7nEyqFG8zMBBSVMkQOWJ1b+5iNlM9BsosQyud6bf
         NE1q56f6wdnONcScHSP5EVbXyEc85eVl47DOqbebpMxpyT6bAUTl0txb3QfK3Zr0xgSX
         dDqDR5/ejRxESXOc2Hm6i40GP9UY+ICHbs2C0sKk/kJA/wKqEMNaegPUrilWC9PRN7xC
         rBdw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Js+n82cx;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c44 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oo1-xc44.google.com (mail-oo1-xc44.google.com. [2607:f8b0:4864:20::c44])
        by gmr-mx.google.com with ESMTPS id e17si1151257ybp.1.2020.09.22.02.56.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 22 Sep 2020 02:56:39 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c44 as permitted sender) client-ip=2607:f8b0:4864:20::c44;
Received: by mail-oo1-xc44.google.com with SMTP id 4so3982028ooh.11
        for <kasan-dev@googlegroups.com>; Tue, 22 Sep 2020 02:56:39 -0700 (PDT)
X-Received: by 2002:a4a:751a:: with SMTP id j26mr2423028ooc.14.1600768599083;
 Tue, 22 Sep 2020 02:56:39 -0700 (PDT)
MIME-Version: 1.0
References: <20200921132611.1700350-1-elver@google.com> <20200921132611.1700350-4-elver@google.com>
 <20200921143059.GO2139@willie-the-truck> <CAG_fn=WKaY9MVmbpkgoN4vaJYD_T_A3z2Lgqn+2o8-irmCKywg@mail.gmail.com>
 <CAG_fn=XV7JfJDK+t1X6bnV6gRoiogNXsHfww0jvcEtJ2WZpR7Q@mail.gmail.com> <20200921174357.GB3141@willie-the-truck>
In-Reply-To: <20200921174357.GB3141@willie-the-truck>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 22 Sep 2020 11:56:26 +0200
Message-ID: <CANpmjNNdGWoY_FcqUDUZ2vXy840H2+LGzN3WWrK8iERTKntSTw@mail.gmail.com>
Subject: Re: [PATCH v3 03/10] arm64, kfence: enable KFENCE for ARM64
To: Will Deacon <will@kernel.org>
Cc: Alexander Potapenko <glider@google.com>, Andrew Morton <akpm@linux-foundation.org>, 
	"H. Peter Anvin" <hpa@zytor.com>, "Paul E. McKenney" <paulmck@kernel.org>, 
	Andrey Konovalov <andreyknvl@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Andy Lutomirski <luto@kernel.org>, Borislav Petkov <bp@alien8.de>, 
	Catalin Marinas <catalin.marinas@arm.com>, Christoph Lameter <cl@linux.com>, 
	Dave Hansen <dave.hansen@linux.intel.com>, David Rientjes <rientjes@google.com>, 
	Dmitriy Vyukov <dvyukov@google.com>, Eric Dumazet <edumazet@google.com>, 
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>, Hillf Danton <hdanton@sina.com>, 
	Ingo Molnar <mingo@redhat.com>, Jann Horn <jannh@google.com>, 
	Jonathan Cameron <Jonathan.Cameron@huawei.com>, Jonathan Corbet <corbet@lwn.net>, 
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, Kees Cook <keescook@chromium.org>, 
	Mark Rutland <mark.rutland@arm.com>, Pekka Enberg <penberg@kernel.org>, 
	Peter Zijlstra <peterz@infradead.org>, SeongJae Park <sjpark@amazon.com>, 
	Thomas Gleixner <tglx@linutronix.de>, Vlastimil Babka <vbabka@suse.cz>, 
	"the arch/x86 maintainers" <x86@kernel.org>, "open list:DOCUMENTATION" <linux-doc@vger.kernel.org>, 
	LKML <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linux Memory Management List <linux-mm@kvack.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=Js+n82cx;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c44 as
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

On Mon, 21 Sep 2020 at 19:44, Will Deacon <will@kernel.org> wrote:
[...]
> > > > > For ARM64, we would like to solicit feedback on what the best option is
> > > > > to obtain a constant address for __kfence_pool. One option is to declare
> > > > > a memory range in the memory layout to be dedicated to KFENCE (like is
> > > > > done for KASAN), however, it is unclear if this is the best available
> > > > > option. We would like to avoid touching the memory layout.
> > > >
> > > > Sorry for the delay on this.
> > >
> > > NP, thanks for looking!
> > >
> > > > Given that the pool is relatively small (i.e. when compared with our virtual
> > > > address space), dedicating an area of virtual space sounds like it makes
> > > > the most sense here. How early do you need it to be available?
> > >
> > > Yes, having a dedicated address sounds good.
> > > We're inserting kfence_init() into start_kernel() after timekeeping_init().
> > > So way after mm_init(), if that matters.
> >
> > The question is though, how big should that dedicated area be?
> > Right now KFENCE_NUM_OBJECTS can be up to 16383 (which makes the pool
> > size 64MB), but this number actually comes from the limitation on
> > static objects, so we might want to increase that number on arm64.
>
> What happens on x86 and why would we do something different?

On x86 we just do `char __kfence_pool[KFENCE_POOL_SIZE] ...;` to
statically allocate the pool. On arm64 this doesn't seem to work
because static memory doesn't have struct pages?

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNNdGWoY_FcqUDUZ2vXy840H2%2BLGzN3WWrK8iERTKntSTw%40mail.gmail.com.
