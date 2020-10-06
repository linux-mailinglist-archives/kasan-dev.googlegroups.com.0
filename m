Return-Path: <kasan-dev+bncBCQ2XPNX7EOBBCFH575QKGQEDSQCRFI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x237.google.com (mail-lj1-x237.google.com [IPv6:2a00:1450:4864:20::237])
	by mail.lfdr.de (Postfix) with ESMTPS id DAE762843FF
	for <lists+kasan-dev@lfdr.de>; Tue,  6 Oct 2020 04:16:40 +0200 (CEST)
Received: by mail-lj1-x237.google.com with SMTP id n24sf2305062ljc.9
        for <lists+kasan-dev@lfdr.de>; Mon, 05 Oct 2020 19:16:40 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1601950600; cv=pass;
        d=google.com; s=arc-20160816;
        b=ZNfGj+AcS78+4bd0LMGXsRTmgLDIUqnplU+hqI6A1EvO0LBVr2NeHAURvIHwOVh+n2
         FeA0l+2pg4pRyyciYz9HsS9eHOJ1I9tm6AwDgNenLI5Pe8s5U2v59HTCaOFYJ4JS0ctd
         a9t6PrnvfgkNOhFZYvua6KVsVm4Nbs/Uaq4MYJbgAQWU8BbC/jpIq8pOQSDL3GzxgWQX
         nyIMS9xEu5Q0XThbof6HR0kggmW23pD4y3lby4tj5WYhBs9qfWiXiKnyL8SGy41dvSdk
         w2xcs5uunNDx6FSDZzWOQFWMjVBlYbbWkSCMZDcd0LoqQpgU4dQwIHGZzRANJLZAKHl5
         H+og==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=rE1Z+POEOjgmMpj0BbTgwWqC/bAJup7fZlID08nZXYc=;
        b=qNotJFHHVfJBJ9BleYWCFWbb/65S6iQOllF3sQjhGbEBM2LFsTitnpq5451zBZONxR
         5wXrM6K+fMtowsg/+WBqCb0OBGj7lnRK4yqGFRGjV5laJAQI21yRnOPVR+FdzPUVkJYh
         Vv1nu5gWGBQnkQQyt89+sZkUM2bP8j6i4LY1dS9zJF3XKBPNO/uCg7TTQawa4bYSyWlB
         9xIg1yzYNTN6KPaDDu5NaXzU92ZhB+w/REXn911/g/sLcbexbwVkapkBCHI0gX7lk65v
         olWNI0eAeYcbNPivX8+o4nkLmrdzPsWneC5wrLmhRZL6XVnIJMrFk4UjaN7fQ3wUXxyn
         sR0g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=VSSaWD0W;
       spf=pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::644 as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=rE1Z+POEOjgmMpj0BbTgwWqC/bAJup7fZlID08nZXYc=;
        b=U7CCYmMUjE7Ub/p0b2/3D/ZxFC2xn9+CpfNHj+39h5xdpFNO3XCpUlGV59e7RETxIO
         J60InQrs4UiJhrYEW+PqixlHK1pwSDN2Ca1OuDdRBuyd67YWVNrbFZXAMwWs0BFcE+dA
         JjzI5GCEBZzvDasH3wIqLjOxF0efPe+pgP2R0AVwrdw5NCUlCf6iYvTVdfxbPxc61u9n
         zL9MMH5MmSUOhxsunlUV4l1/xw/gZPxDBCcEulFUcCZEXk34LD2kIqdMy4Xc97+Vm8Xp
         CWFkrIjncbEqFhxAeS/Tbi4zUeIdciVJYU8l1jKgx4rRmjVdaBURgqbbIrxl1PErptis
         rb4Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=rE1Z+POEOjgmMpj0BbTgwWqC/bAJup7fZlID08nZXYc=;
        b=fScj0LZGqphfRg0BbL1WbMfzrQj/Iu3rjYcJcPS0miz8ldCliFlgehmxpHJcpJSmcF
         tyyIRjAugfBXOBUbitBm2BC2omT/tieqjVy6XfT342/M6ouDHu07s3PajsW9JMQx0dga
         DwjSLY3ETjqxCeIi9zklalNiy54E8Jaf70DavGlrpS9QJHMzajLJOHysEqXcPt8geUt/
         3S/tuUPcfNe5YSF5o/LebEEYrXJx9aERCmCm9W+6zPrBD12++lNAnZLPTW1jOS3Ex3YF
         5hMfrkSP92z2ufHVJMCW1CW96YAOwWw3Za+010YSmlwPlEr6SqJ93dV70Fpfq138S4NO
         FJtQ==
X-Gm-Message-State: AOAM533nBRWxGO9KK7tj1z8VmqnogqVvsIFHOZ0hvJvgRccYZhtWAB59
	pQhVuo97eCFBfUeDEMKd26M=
X-Google-Smtp-Source: ABdhPJzwqTpxCJntqlfh8jyTDP4lI7FsQE6jVxqV236njIFimpOJINBK2Ra9EUPez7DRL9XZ1ku2kA==
X-Received: by 2002:ac2:52ab:: with SMTP id r11mr797521lfm.118.1601950600394;
        Mon, 05 Oct 2020 19:16:40 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:9bc6:: with SMTP id w6ls1406929ljj.0.gmail; Mon, 05 Oct
 2020 19:16:39 -0700 (PDT)
X-Received: by 2002:a05:651c:554:: with SMTP id q20mr892664ljp.348.1601950599363;
        Mon, 05 Oct 2020 19:16:39 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1601950599; cv=none;
        d=google.com; s=arc-20160816;
        b=LznfxQdIypkIgqZkRSfE/BkJjaATy9SPhdzCy7BJnWpweAzyFdKvL3/AhPPDOzufGB
         FB2AFKUWg73peHfL8gzvz4UN+JM/n5dEP0dWzQHUjykA6TpPsLprS9xjXp9JjzuGYSo0
         w/w7DpFDplB42tStngJASJNpa+2tP1ob8Pf+rSd3+tLNpdP4NFhwkoDfqqBRVJbchrPS
         +Q2So60lSDBL8Pnq77ALPD9YVJ7IBNnN8au+kqt43/ProNA9v/tcI1w0saawqCzN/6FG
         q4OoSWUOaQcsDu2JjDcKGCtZXeIYHvsq58ctEtx76dlZRcCzmNN5ceGJTcAaaerYRRIY
         aXfQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=ifD/jW+MjbtS2EijgQAS4OITv0Z9zRA4cL1N04HQHu4=;
        b=LB1wxmZ7SWsi//HXKKoK8yR74Xdr8B0VGJUZc7LdK2/0q8JyBGuf/K6h4tfjFMrtS1
         4RzpezYNR1YLP2oEEkQOb0rb7cW7CSsdhVZOyqeekud3WmLwUWBnxpzEZxusR/pkPmtM
         kI8iULRLMtJfAi0BD0ciXMvf5OwgIfkageVMssHO5FLfOlHcXr1StenYHkXTv54Vkp5E
         pbLDoQj8M7LlQMU8kceiipMWtPuwNIu8l7Uc1YgaopNxd7DMN7B9glLpjgTYbZTuDkyQ
         c056yy2jyA+NdA5Vv805SxbFb3Lf9vpffcG4hEUPgVEhZKXqqmLWwyp4DUZvxJvCW53t
         cCng==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=VSSaWD0W;
       spf=pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::644 as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ej1-x644.google.com (mail-ej1-x644.google.com. [2a00:1450:4864:20::644])
        by gmr-mx.google.com with ESMTPS id j75si62432lfj.5.2020.10.05.19.16.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 05 Oct 2020 19:16:39 -0700 (PDT)
Received-SPF: pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::644 as permitted sender) client-ip=2a00:1450:4864:20::644;
Received: by mail-ej1-x644.google.com with SMTP id qp15so15200241ejb.3
        for <kasan-dev@googlegroups.com>; Mon, 05 Oct 2020 19:16:39 -0700 (PDT)
X-Received: by 2002:a17:906:fcae:: with SMTP id qw14mr2849150ejb.537.1601950598646;
 Mon, 05 Oct 2020 19:16:38 -0700 (PDT)
MIME-Version: 1.0
References: <20200929183513.380760-1-alex.popov@linux.com> <91d564a6-9000-b4c5-15fd-8774b06f5ab0@linux.com>
 <CAG48ez1tNU_7n8qtnxTYZ5qt-upJ81Fcb0P2rZe38ARK=iyBkA@mail.gmail.com>
 <20201006004414.GP20115@casper.infradead.org> <202010051905.62D79560@keescook>
In-Reply-To: <202010051905.62D79560@keescook>
From: "'Jann Horn' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 6 Oct 2020 04:16:12 +0200
Message-ID: <CAG48ez19ecXyqz+GZVsqqM73WZo7tNL4F7Q1vTTP6QG75NaWKw@mail.gmail.com>
Subject: Re: [PATCH RFC v2 0/6] Break heap spraying needed for exploiting use-after-free
To: Kees Cook <keescook@chromium.org>
Cc: Matthew Wilcox <willy@infradead.org>, Alexander Popov <alex.popov@linux.com>, 
	Will Deacon <will@kernel.org>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, Christoph Lameter <cl@linux.com>, 
	Pekka Enberg <penberg@kernel.org>, David Rientjes <rientjes@google.com>, 
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Masahiro Yamada <masahiroy@kernel.org>, Masami Hiramatsu <mhiramat@kernel.org>, 
	Steven Rostedt <rostedt@goodmis.org>, Peter Zijlstra <peterz@infradead.org>, 
	Krzysztof Kozlowski <krzk@kernel.org>, Patrick Bellasi <patrick.bellasi@arm.com>, 
	David Howells <dhowells@redhat.com>, Eric Biederman <ebiederm@xmission.com>, 
	Johannes Weiner <hannes@cmpxchg.org>, Laura Abbott <labbott@redhat.com>, Arnd Bergmann <arnd@arndb.de>, 
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>, Daniel Micay <danielmicay@gmail.com>, 
	Andrey Konovalov <andreyknvl@google.com>, Pavel Machek <pavel@denx.de>, 
	Valentin Schneider <valentin.schneider@arm.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux-MM <linux-mm@kvack.org>, Kernel Hardening <kernel-hardening@lists.openwall.com>, 
	kernel list <linux-kernel@vger.kernel.org>, notify@kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: jannh@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=VSSaWD0W;       spf=pass
 (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::644 as
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

On Tue, Oct 6, 2020 at 4:09 AM Kees Cook <keescook@chromium.org> wrote:
> On Tue, Oct 06, 2020 at 01:44:14AM +0100, Matthew Wilcox wrote:
> > On Tue, Oct 06, 2020 at 12:56:33AM +0200, Jann Horn wrote:
> > > It seems to me like, if you want to make UAF exploitation harder at
> > > the heap allocator layer, you could do somewhat more effective things
> > > with a probably much smaller performance budget. Things like
> > > preventing the reallocation of virtual kernel addresses with different
> > > types, such that an attacker can only replace a UAF object with
> > > another object of the same type. (That is not an idea I like very much
> > > either, but I would like it more than this proposal.) (E.g. some
> > > browsers implement things along those lines, I believe.)
> >
> > The slab allocator already has that functionality.  We call it
> > TYPESAFE_BY_RCU, but if forcing that on by default would enhance security
> > by a measurable amount, it wouldn't be a terribly hard sell ...
>
> Isn't the "easy" version of this already controlled by slab_merge? (i.e.
> do not share same-sized/flagged kmem_caches between different caches)

Yes, but slab_merge still normally frees slab pages to the page allocator.

> The large trouble are the kmalloc caches, which don't have types
> associated with them. Having implicit kmem caches based on the type
> being allocated there would need some pretty extensive plumbing, I
> think?

Well, a bit of plumbing, at least. You'd need to teach the compiler
frontend to grab type names from sizeof() and stuff that type
information somewhere, e.g. by generating an extra function argument
referring to the type, or something like that. Could be as simple as a
reference to a bss section variable that encodes the type in the name,
and the linker already has the logic to automatically deduplicate
those across compilation units - that way, on the compiler side, a
pure frontend plugin might do the job?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAG48ez19ecXyqz%2BGZVsqqM73WZo7tNL4F7Q1vTTP6QG75NaWKw%40mail.gmail.com.
