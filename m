Return-Path: <kasan-dev+bncBC7OBJGL2MHBBUPI6D6AKGQEYMCIAQA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc39.google.com (mail-oo1-xc39.google.com [IPv6:2607:f8b0:4864:20::c39])
	by mail.lfdr.de (Postfix) with ESMTPS id 79C8B2A0A13
	for <lists+kasan-dev@lfdr.de>; Fri, 30 Oct 2020 16:42:10 +0100 (CET)
Received: by mail-oo1-xc39.google.com with SMTP id t19sf2971689ook.18
        for <lists+kasan-dev@lfdr.de>; Fri, 30 Oct 2020 08:42:10 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1604072529; cv=pass;
        d=google.com; s=arc-20160816;
        b=L2AP2fepaR/8frPrX3xI+4lbDi24hPS6CWNnk1/E2+7GypX1dsKISDsE2uBAIhsg7W
         kxoALidQkxbE62n0yb3rx58YoyCdrqrfLgzclrXW8uxoR5ceDHovrIfpR/gnUaw1zwNY
         0IRTqZTTo7ryUt2mxv1b9BWkHTIFVY7ZkyFdo5pcs71hSU1Ck1kZBfLQxM2rKc4r3iUV
         gLxbwu4OC8XUtPydySbz0HSg6ViFX49q6sG8rn7EVr1XEdJIETX+eZlJsJAtatKpBcc9
         ZKP36Ac6eYnq1hnFYUdOQxhFckK87UM2S8px5cx08GVFUX5MCTpzXFsS+Bu+KKdkdMVS
         jEXA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=H2GIWuHYIJkZnQVxLUPNj7HUE7YY6/3rfCppf9Te9b4=;
        b=ETDRpnQNWqE0W43EokaqCrLyhFrTxqABRzLjZ4glNAKQdxKHf9h73+rFq8QSiDm8Bp
         eZy4QDifMWAELg7TtWOjWRtjTtx+Iu0yEm4WEvcEk2Zba1ubB51gsReJZ52t+zP1xJmG
         Vh5TIhnYklJsocjuadzBVEWSM2aAU6WueO53uDcOmtT01Ix0VizjGkvcKuzJqLqSdYHe
         Pu5JxcoUUnOWxxdPlVrYJQA6VKLE0Sf3fqBNLjYJNJg4IDHSs3abMpOHx/nXSkvcEI8G
         PG7fsnKkgSOMQf1/XvpVzAtv5JuN9V+etqkKptu1GApD77IngfSRgHR9mVAyP6+Dq8pP
         CthQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=DTRV++Wj;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::241 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=H2GIWuHYIJkZnQVxLUPNj7HUE7YY6/3rfCppf9Te9b4=;
        b=ngkFbItWuYI6zinDwke/sOscqyMjOLuY8LMOKS22gZtNFxyZCI1EtDi58cJcKkOC2D
         AmVpx+lglsYzFLbO8HTbjsAUrWKfJwcsimm3NiwcSevks/CHf0fQ/t+L8chgxjci969Y
         xhS0sXX+D/GQyGJbJ63gwhlHIIHMpLmqHWipGhXw10eo6i9D3mAnZS/NMiSu+z60u7xF
         jikToJz8oKzgBE/mksVkiC2+QTEl2OUCNYKPXBAIoqZU1fEdCAFDgwo5XL6l8g5lKCTE
         ZsVAghTkGbMx5AhAZxnHepnIBvKjlWZKzxvqWS1ApKqB6g3rxTc2payRU7lIIYKzg7Zr
         NTWA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=H2GIWuHYIJkZnQVxLUPNj7HUE7YY6/3rfCppf9Te9b4=;
        b=gcgtwL5Jif6sRKvVAu0NxGHjtn0eWbHGQuPSoyyCb0yBgQtWaidwVhEm9bAp6mq+gM
         4XNUJ6bTZGXk//f6zfvX5dIieCpZyXnj5TjaUvIaQIGrK2/VlIRedJqRJgnoASD8pvJu
         7777Bk6zjfAiLcLO3S+51XZGmkiOHLYmuJC9thadtNvjoAP8uAJJ8aaGljfpYaqhlB/X
         5qoLPdCeza6hcFREgwFmhxewFCYrJUxCBhKAZ3mZq7GsiZdjZZ8yle2VFSxsB9bH6zt2
         j1aZ/wGJl+6u89uyBWcfWV0tef9QZIdgW5p8MHBZsvThJjDTqSuuwevZfkKuriiLHbwI
         O/cg==
X-Gm-Message-State: AOAM531UrddzU8tv4qLWE874K1MeLbCa/9nEPMdeIJ2TCMvfKdzAKSHf
	+ooXoqXrxxdS8nz89Rc4w/Y=
X-Google-Smtp-Source: ABdhPJwlX7DduTQ7wDuIZAULLcW5uoaM0NURh7k/NyRGnmWe3h9OLlFJf9xZidBzIDlFO5UDiQ2YCQ==
X-Received: by 2002:aca:be56:: with SMTP id o83mr2149192oif.1.1604072529174;
        Fri, 30 Oct 2020 08:42:09 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:750d:: with SMTP id r13ls1733154otk.0.gmail; Fri, 30 Oct
 2020 08:42:08 -0700 (PDT)
X-Received: by 2002:a05:6830:400d:: with SMTP id h13mr2203751ots.371.1604072528757;
        Fri, 30 Oct 2020 08:42:08 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1604072528; cv=none;
        d=google.com; s=arc-20160816;
        b=0GVsi4biGlvI3wFAme/+WZO9G0iQh9f2G68cLBLMYOs+eqs0v0b4aL/WSIvsb3ISRW
         AaNG8HL3iuft7LnE9mBp2pFMfP+TMgaudCC3mK4y0G5F9Av/1BvaK9aVuRaO8Frn9EmV
         68wtEDqjQFSIYaBv31oZSGqd5+gs0yjZ6ji6323fzCZ1ETv5be/6pdYS/3kYHYacx68C
         WcaPfLnhRPdKfqQHiFK5qUOA6x4ipJ/VTvGtUbMbD6kKLQaLUZ9vKzSjqM5vVVIjudZK
         VPWVp5uFSU29V5WyorDwdvqxwVsLZ7g7fVk40UY1Q7PeWtJlDHWSt91hKFDbgcBBlxJz
         0lDA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=jliMwvFbMuf3FmeyCOZHebsGYCHgE565UHogT5/5F4c=;
        b=F2mkeaMqjOXShzTEzRp4aagVWHqJDKsPIGBUustymH1IuOAPJzqEvjXOhNvKMmLzUs
         uddEL2JbJWjAiwpLhlL2ifbtHjdPG+o1hYzS5aYn1HnDUokxdgStCTQY2feI4J5nbzEM
         +YtZx0kMZy3Z+c8DiDmAZO3/u6oMGdHznrsCDlLStcYyBRA7yfHOeBHuoQtnv20IIydx
         WafBFM/A6gLfCgA/lKCmDE2nA4ro8Vn+4vrFbFPpO4MBzoHE/F0tlLuoThewj59EihQN
         8xbo3mN1dI7mkl4W1fgU6HYxhbVcoikdcVGAocBs6OUo/8m7Ad3YU0xakpMz0Rnb1wWm
         CjqQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=DTRV++Wj;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::241 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x241.google.com (mail-oi1-x241.google.com. [2607:f8b0:4864:20::241])
        by gmr-mx.google.com with ESMTPS id w26si419921oih.1.2020.10.30.08.42.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 30 Oct 2020 08:42:08 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::241 as permitted sender) client-ip=2607:f8b0:4864:20::241;
Received: by mail-oi1-x241.google.com with SMTP id x203so7029112oia.10
        for <kasan-dev@googlegroups.com>; Fri, 30 Oct 2020 08:42:08 -0700 (PDT)
X-Received: by 2002:aca:6206:: with SMTP id w6mr2138653oib.121.1604072528251;
 Fri, 30 Oct 2020 08:42:08 -0700 (PDT)
MIME-Version: 1.0
References: <20201029131649.182037-1-elver@google.com> <20201029131649.182037-5-elver@google.com>
 <CAG48ez1DxttDs6vj61c0jSGSbhoUmAW9_OSBSENrC-=hz-d+HA@mail.gmail.com>
In-Reply-To: <CAG48ez1DxttDs6vj61c0jSGSbhoUmAW9_OSBSENrC-=hz-d+HA@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 30 Oct 2020 16:41:56 +0100
Message-ID: <CANpmjNOPmgeVLb5COyE734F-1NNSU4vfok-8AQuDoAcLnQ=PbQ@mail.gmail.com>
Subject: Re: [PATCH v6 4/9] mm, kfence: insert KFENCE hooks for SLAB
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
 header.i=@google.com header.s=20161025 header.b=DTRV++Wj;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::241 as
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

On Fri, 30 Oct 2020 at 03:49, Jann Horn <jannh@google.com> wrote:
> On Thu, Oct 29, 2020 at 2:17 PM Marco Elver <elver@google.com> wrote:
> > Inserts KFENCE hooks into the SLAB allocator.
> [...]
> > diff --git a/mm/slab.c b/mm/slab.c
> [...]
> > @@ -3416,6 +3427,11 @@ static void cache_flusharray(struct kmem_cache *cachep, struct array_cache *ac)
> >  static __always_inline void __cache_free(struct kmem_cache *cachep, void *objp,
> >                                          unsigned long caller)
> >  {
> > +       if (kfence_free(objp)) {
> > +               kmemleak_free_recursive(objp, cachep->flags);
> > +               return;
> > +       }
>
> This looks dodgy. Normally kmemleak is told that an object is being
> freed *before* the object is actually released. I think that if this
> races really badly, we'll make kmemleak stumble over this bit in
> create_object():
>
> kmemleak_stop("Cannot insert 0x%lx into the object search tree
> (overlaps existing)\n",
>       ptr);

Good catch. Although extremely unlikely, let's just avoid it by moving
the freeing after.

>
> > +
> >         /* Put the object into the quarantine, don't touch it for now. */
> >         if (kasan_slab_free(cachep, objp, _RET_IP_))
> >                 return;

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNOPmgeVLb5COyE734F-1NNSU4vfok-8AQuDoAcLnQ%3DPbQ%40mail.gmail.com.
