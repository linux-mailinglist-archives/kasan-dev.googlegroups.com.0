Return-Path: <kasan-dev+bncBC7OBJGL2MHBBV6MSH6AKGQEOFI2J6Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x340.google.com (mail-ot1-x340.google.com [IPv6:2607:f8b0:4864:20::340])
	by mail.lfdr.de (Postfix) with ESMTPS id 4E35828BAB0
	for <lists+kasan-dev@lfdr.de>; Mon, 12 Oct 2020 16:21:13 +0200 (CEST)
Received: by mail-ot1-x340.google.com with SMTP id q8sf6406073otk.6
        for <lists+kasan-dev@lfdr.de>; Mon, 12 Oct 2020 07:21:13 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1602512472; cv=pass;
        d=google.com; s=arc-20160816;
        b=db6IW0inBzdYQxy6Soq3J7ZmwLPy7DtkuDOIRO9uEI1mq+Ydi68+Pw74KE9PO+ejL7
         RE63zpdyiBAKkYD2PB17bjqeVYS68UInC+ZvMdM2c5MxEWlbtwV64kyIWHT8+oE3WDP4
         nIhRDubMm9VhJy6I8fMkX7aXVuxU3UqrHwwxcojhCDZXBJJ1n9Y5/wks2HISzh+bye2q
         CfKgSrBUWL+JRSw8p5eDkkHice61qdFTROCvFKZh790DKu0U8QNvJ8AO/l184qlAi0Fj
         5ZjsniMJJ4EEPbgN/8XmIfUE8lteBpDXxTban8DPV2y6lWsFW3hN+pvLnis/mUP+z4EJ
         wjow==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=BNeEyKpCvIt9HqOhjg+yU/znK2lPTClZMUg09Q2h03s=;
        b=YsTevOFlDkS80DwdVc8xOEtket+IctRw98goYXws0jQnyzK0r1Xk/D5UBFTJ5+CJTN
         WRUH5qVB3eEX3lTTOUBY58b8yvOY4ZELuqNQSlz3t9FtMMgP/LqaRnnefw0rG0Fyg5NN
         UD3dIZbl4enRr8TrfLYF69rCA81VIjMId4InSjmHB5YqwIfxDcVFhVbEp5VmpKb/cgFk
         ynjDyNwtR4FSycFSVD9D4U5W0/6NuxBvlAq9aAIznrDhwACsKt52PJS2//fhEk1tjFib
         doOg8YxzuBqjpaMy/VrYgtG3DlXRJLhKAFQUpVBBn0freNOv5lCBPDXVfB2sAunVVsvo
         DaVA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=W5D1O2Lh;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::242 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=BNeEyKpCvIt9HqOhjg+yU/znK2lPTClZMUg09Q2h03s=;
        b=Ad0a3d1Y4zcPWT56LDd2IxL0FvK5iOqWVF3Tf2myq+si2Uod0Eupy6QS2FNtk3RDXe
         f7B52WGaKo32XEg0K/KC9ZyhesbF2w0Uj+GNpht/+ZUGaX0aWGXt5xqjWks1cWk+PRu6
         mLmmV9Gh5XsjCV1/fP/mO10Z0hrLH5e9aEcuNHCzXTfSOn6X8nhWkF1/4QuzU2J4Q16o
         fffc0ZyhQox1J2JhhV33QdU/8RYoaOfqORxQPMq9GNK21MHsq61Jrytq1Sp65covp5y+
         X+j4Mmi+offqgsKzjyYIKjaZGdIzdOgxCwweoWv3qD265aEMtHNyUA9wIL9j22HwVYB8
         4IXw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=BNeEyKpCvIt9HqOhjg+yU/znK2lPTClZMUg09Q2h03s=;
        b=l0E2FfXSjDqFeenjtfC/SiwRCTXCuniFiBVd4D7eUnHxF6dbZA1WmRmnZCbqAS5JEW
         67DbF8XZREULsY0ghDgLP7fyLEaiHS77H4tHb72H4H9OSwGyWNcRlUfU81Zjxktn9Z6t
         fj+aKe2Dk4oYY5tjf8PHWjKDTRhAd2Okx2NpGjg6xKtLHs+HU51Tu1feY+WcNteivUgv
         V3M9TMIvdN+rttYQrzEDttC+B/DnCIBN6BeHvhEWw9gWF1pcVTpkKLZ9xRvwoaUllHsz
         Cx2Y5F8xa4f3OTLVba8xwSgNtyHRf/k7YUFVSkRtI2FdZbwMvvJGtresE6125RBKOm5C
         fo/w==
X-Gm-Message-State: AOAM532kAfTFjfCvoGKyVeM0UQujmWOOeDmI40dluYT46YzNmC6itwf3
	XJzTKXTTZ8z3+uFAAq80jLQ=
X-Google-Smtp-Source: ABdhPJzWkSHdhxrkQ0qZ6qGvNdU2yF+AEErttUa0kpyyFFLhDmoml9XExPfUlKrGIuo3/aU0GElnOA==
X-Received: by 2002:a4a:5182:: with SMTP id s124mr6323191ooa.88.1602512471942;
        Mon, 12 Oct 2020 07:21:11 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6830:310b:: with SMTP id b11ls1125523ots.10.gmail; Mon,
 12 Oct 2020 07:21:11 -0700 (PDT)
X-Received: by 2002:a9d:708f:: with SMTP id l15mr18265779otj.5.1602512471599;
        Mon, 12 Oct 2020 07:21:11 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1602512471; cv=none;
        d=google.com; s=arc-20160816;
        b=eDww1QtUIk0dpJoocw6bpQShNW2qfYlCgZrahkzuasKRzyHzsNDuhmvPthMcVgcyS0
         zvkSc5kWJniN3qGPk7I13PC4v0ecUNlOH5WullMw5cEaHA96A5DuMvYm+qP0jfmU2mnz
         39/e44H/V2K7/4nlBnTs1HEruI0NsVS8FOejvNH4DELwHi+rgej12W0kv0OLcixnl8tf
         Xdd7C/BzkpjvpHuS9w4AjUo0rTXUfSI7V4aUJCU9m1us1A7k8lkOQlNLZmBJ4a58CDUS
         RWDRnPLIYsaAL8qxBt7uyBBUpY2CJznJi7xptetI644G+6pNy+TM5Z1LnZBtMuGiIzeR
         /ELA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=qgmtNie/zntd1O8Xi3/aeMkTtA9q5iGd/FaFCpPsSPs=;
        b=p52N0u9f3wip3PXoSEkryQeAWHEinhOUoGX4+9+ar19z2PHZDRltQRMN0Z7O83fhn3
         Gico0fLgHlqqE44mnPdoIovdsCUEIENduH0aFI1y8zSz1gGLLIKzPQFwFZ7MsbAWgGMj
         RAodXjaJBIzH5p0Yb/CKsQdc1oKRGcJ9jynbrFh295fyjuwWsyz+ZoC1VI7gjpHpnv8b
         aBVtrn2aXQoYjmcpD+p2QY3KDMYFAYAQV1CGBFyTaSvmH0SF5J5JjlEQmql6Uy9W2vvs
         yE+h/hxhr+mxaCmMA2NAAqmZ2AdbZYrlW9TzxeDOZAiwVungnzWX1cOVcvLODAPJDwsH
         U8TA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=W5D1O2Lh;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::242 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x242.google.com (mail-oi1-x242.google.com. [2607:f8b0:4864:20::242])
        by gmr-mx.google.com with ESMTPS id r6si2612013oth.4.2020.10.12.07.21.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 12 Oct 2020 07:21:11 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::242 as permitted sender) client-ip=2607:f8b0:4864:20::242;
Received: by mail-oi1-x242.google.com with SMTP id w141so18919248oia.2
        for <kasan-dev@googlegroups.com>; Mon, 12 Oct 2020 07:21:11 -0700 (PDT)
X-Received: by 2002:a54:468f:: with SMTP id k15mr11407914oic.121.1602512471058;
 Mon, 12 Oct 2020 07:21:11 -0700 (PDT)
MIME-Version: 1.0
References: <20200929133814.2834621-1-elver@google.com> <20200929133814.2834621-2-elver@google.com>
 <CAG48ez3+_K6YXoXgKBkB8AMeSQj++Mxi5u2OT--B+mJgE7Cyfg@mail.gmail.com>
 <20201002171959.GA986344@elver.google.com> <CAG48ez0D1+hStZaDOigwbqNqFHJAJtXK+8Nadeuiu1Byv+xp5A@mail.gmail.com>
 <CANpmjNN7s3o4DYbP64iLYo0MeDWciQnKd61njJKLsiZv+ZLQdA@mail.gmail.com> <CAG48ez0az-Mv1f6EpnQwO6cYQANwx4qCDLa+yda_i15AzciS1Q@mail.gmail.com>
In-Reply-To: <CAG48ez0az-Mv1f6EpnQwO6cYQANwx4qCDLa+yda_i15AzciS1Q@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 12 Oct 2020 16:20:59 +0200
Message-ID: <CANpmjNPb2JW6vjRODOzpbjh2HauAN2==NAs9tfpbxYiv53r_Zg@mail.gmail.com>
Subject: Re: [PATCH v4 01/11] mm: add Kernel Electric-Fence infrastructure
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
	Kees Cook <keescook@chromium.org>, Mark Rutland <mark.rutland@arm.com>, 
	Pekka Enberg <penberg@kernel.org>, Peter Zijlstra <peterz@infradead.org>, 
	SeongJae Park <sjpark@amazon.com>, Thomas Gleixner <tglx@linutronix.de>, Vlastimil Babka <vbabka@suse.cz>, 
	Will Deacon <will@kernel.org>, "the arch/x86 maintainers" <x86@kernel.org>, 
	"open list:DOCUMENTATION" <linux-doc@vger.kernel.org>, kernel list <linux-kernel@vger.kernel.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, Linux-MM <linux-mm@kvack.org>, 
	SeongJae Park <sjpark@amazon.de>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=W5D1O2Lh;       spf=pass
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

[ Sorry for delay, just noticed this one doesn't have a reply yet. ]

On Sat, 3 Oct 2020 at 00:27, Jann Horn <jannh@google.com> wrote:
> On Fri, Oct 2, 2020 at 11:28 PM Marco Elver <elver@google.com> wrote:
> > On Fri, 2 Oct 2020 at 21:32, Jann Horn <jannh@google.com> wrote:
> > > > That's another check; we don't want to make this more expensive.
> > >
> > > Ah, right, I missed that this is the one piece of KFENCE that is
> > > actually really hot code until Dmitry pointed that out.
> > >
> > > But actually, can't you reduce how hot this is for SLUB by moving
> > > is_kfence_address() down into the freeing slowpath? At the moment you
> > > use it in slab_free_freelist_hook(), which is in the super-hot
> > > fastpath, but you should be able to at least move it down into
> > > __slab_free()...
> > >
> > > Actually, you already have hooked into __slab_free(), so can't you
> > > just get rid of the check in the slab_free_freelist_hook()?
> >
> > I missed this bit: the loop that follows wants the free pointer, so I
> > currently see how this might work. :-/
>
> reverse call graph:
> __slab_free
>   do_slab_free
>     slab_free
>       kmem_cache_free (frees a single non-kmalloc allocation)
>       kmem_cache_free_bulk (frees multiple)
>       kfree (frees a single kmalloc allocation)
>     ___cache_free (frees a single allocation for KASAN)
>
> So the only path for which we can actually loop in __slab_free() is
> kmem_cache_free_bulk(); and you've already changed
> build_detached_freelist() (which is used by kmem_cache_free_bulk() to
> group objects from the same page) to consume KFENCE allocations before
> they can ever reach __slab_free(). So we know that if we've reached
> __slab_free(), then we are being called with either a single object
> (which may be a KFENCE object) or with a list of objects that all
> belong to the same page and don't contain any KFENCE allocations.

Yes, while that is true, we still cannot execute the code in
slab_free_freelist_hook(). There are several problems:

- getting the freepointer which accesses object + s->offset, may
result in KFENCE OOB errors.

- similarly for setting the freepointer.

- slab_want_init_on_free zeroing object according to memcache
object_size, because it'll corrupt KFENCE's redzone if memcache
object_size > actual allocation size.

Leaving this here is fine, since we have determined that recent
optimizations make the check in slab_free_freelist_hook() negligible.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNPb2JW6vjRODOzpbjh2HauAN2%3D%3DNAs9tfpbxYiv53r_Zg%40mail.gmail.com.
