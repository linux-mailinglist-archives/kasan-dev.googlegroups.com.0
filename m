Return-Path: <kasan-dev+bncBD63HSEZTUIBBAFBV36QKGQEXWGWIWY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa3d.google.com (mail-vk1-xa3d.google.com [IPv6:2607:f8b0:4864:20::a3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 51AA22AE98A
	for <lists+kasan-dev@lfdr.de>; Wed, 11 Nov 2020 08:19:29 +0100 (CET)
Received: by mail-vk1-xa3d.google.com with SMTP id t127sf338915vkf.20
        for <lists+kasan-dev@lfdr.de>; Tue, 10 Nov 2020 23:19:29 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605079168; cv=pass;
        d=google.com; s=arc-20160816;
        b=pDmEYklq8/IDKtmOvFRU+eQG8fmDtIutSuOo6GKBf3jrQhDTA1XtGeV/pAhf64BN1I
         6smWF9bTav7U5gDwbt3oPCG18OQavgNsk1EyoBUkOHTKvxDPc5L7y5kyziRrdfsZfnOm
         HDl/TDwEDZd9iZuSAxAnu1BlY68Tw1lgiN02hF4NFapAkaZEgi2CsIWJcmtknU1uv+yu
         qzvaHvdOxPecl8B8+6YPI34+poy/TB0xehS03EBvB7t+0vHogWpWSeZjo/py+jdXqGQ7
         MbVLbVqZyJbPoelq0wjLJI3UNZaKSlD6dkCyEntcFkXojojz+ppTmP8yn3JbggJ0gQjz
         7H7g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=VErnrrTSAubhz156D8b1njOxJ4c4W8L4750mMLiLJ5M=;
        b=A1gidbl1bap/z1bokdfOe0HQUumGKrRt9M0ud3RGXb3MKqoP0JlOti3Om4YiJ2xTFp
         gO4tjaOTMXF3ks+dodg9esUiEE8otTjPUPC2QE3o3TBbKmCX0xxqpUpm9RcjTwuH+9tp
         +y3KDhDDw1OArbVdgayCsIwFlbB8KwKY774ZBKs3pZ6hwwsdXjAJFeN1hXW1lPWICkfu
         tL0VkIfD0wOmHFrV790R7nb3ckI1SJZN93BgbJLnKDhiLUV5wUE79ez+ZvJqad8Noj+v
         7dybMBXiP/pV0LuoPSaMEmDPeqkJHxOk8qrt5BTFIQEMWFgqDGfbainZDn5jD9Rjkvac
         wnjg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=guq6CmAi;
       spf=pass (google.com: domain of ardb@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=ardb@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=VErnrrTSAubhz156D8b1njOxJ4c4W8L4750mMLiLJ5M=;
        b=h2EpQ+mBB0Q/siQzvy6/ULYCyx/fJLLqPcvDLJNNPKJ7x+sZIpMQbq15iqNlPIb5bd
         wpZG1fX8qPn7Ak0O3Vyq0WxGhgo9kpcsmOtHCROXOpoMTcHM85vzs7O2Sz7poSAcEFNl
         TG3mqMhu8bzae0pv6WEejOKQ+BrlU8ieraCc5o/3hJVMzop7R+KFLmYitBahYkzbD60M
         QYS+3Xl5VqtogNl3KP8HvqY8LqbsQjsX63tMWpaHtMDOHsPSdfYVYJvBvhvLysAnr6uO
         Tuv/EdfdMZNT89DitpmpiuMZrTyj836bqa9+V44OpKqAIPLe7zQ/7tzHN/IfRAFiUWPH
         4oIA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=VErnrrTSAubhz156D8b1njOxJ4c4W8L4750mMLiLJ5M=;
        b=bFh3pZZYL9vysWhPK/RUlDhhFEnczxywNsJUkJKQVFOp1J1y8MxQBU7JZK7qc9IygC
         /7Gfy0Xujw2NbOKhyUNZrInARDx+0p8DT5MF4oDIfJs3ONomkwYDn2LEpni21kM6uEgJ
         OMf7qNXXUbflR+mrc2EwYwLLwSPp6f7S3U/qW4kK7F8rHVfK4lCnPLeWSjuuKOWf7AmN
         dz+AnNTC8PyCQl6Bda8KV62jgRglVpeOmlNPvQWbRHILB9MrgnycNRL1Oe133LVlhku6
         mZAGo1bKUIP+9DfkbthCZtfbedH3byOocNOP7oQ7w2HQFur65phUtdfdpRwKioi8dVjO
         dV+A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5321DYqFdHyurNvnqpIwi8iCBx2PWBXjHTtA2W6lweU/npcBAf8w
	LQ7wl6eW6K0YuIjA01ROKbc=
X-Google-Smtp-Source: ABdhPJwm2JDBtTlI6COCw2e0TNF45Dzl1kMFt7EgUWAEIUjtKBcBT9Gi2To1v7X0FSClj1DtmweT5Q==
X-Received: by 2002:a67:f142:: with SMTP id t2mr14287824vsm.34.1605079168407;
        Tue, 10 Nov 2020 23:19:28 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1f:fe43:: with SMTP id l64ls689735vki.6.gmail; Tue, 10 Nov
 2020 23:19:27 -0800 (PST)
X-Received: by 2002:a1f:2817:: with SMTP id o23mr13191015vko.2.1605079167844;
        Tue, 10 Nov 2020 23:19:27 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605079167; cv=none;
        d=google.com; s=arc-20160816;
        b=k+RAh0c9Bb7dgvoQYNy0z6RU9ofULiL6nE5nP/VDwEGhTj1uKKzEBnQHuiyaecv7nl
         hmnvNUeQbpzTGqgLlmFFowZJRdha2BrpvVHRAFuDuJrjeXUxpe99HEPPPxemiwRtIkKv
         3N5mV+CnHspXbH7pKBwDa9aemt7hP8dVkqVRIdxRDE/9GNBFZLhauw4X14hIEtw0wQ3g
         6qG00q/p8jHoAUDeTm++dH4jZOZ8rD9UEzxaFm9398PSArZWnmSvdF7C+fRxXcG9/V3v
         rw9Y+aB5P+nl4n3l8I2L5Q26IFnVKidBVSRlbjMVkthkhtdeLK/BiFDJRA2xlycG/nGG
         G/Ag==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=CAQVZqtxtSOwUyW8EqmnyD/K8yMmd2zuMQylnTG3pAg=;
        b=0UWVKnYGrRDQwtE8tjkIACTLH4l0Wng48rp4cPwBCA03L4/qR9XiVVTNzxt/Dlz4lI
         W0e1R2nEclZUYzn30IoeDyWwEoWztHwqEVy2rPbBcpZFeBSsi+u5AHoBxchXekA8aBiw
         9wLK5AhjjSEGXv0NNHV0E64TNWbOskEBdiP7U1S3QwAaupB13qkJOOncusfeTGzstQ67
         a7ZN/0+F6SCT0POarKAe1i7roQm1unOWWnxuv7y0E5POsz/5LUkiz4ph7OzKpZ3N8J9n
         /ReliC+oheDJyzgKokW1Pq90kwziO8c92xPtYnJWhkrFh2GxJZGoYAUUTSEBvAO20Nek
         vMiA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=guq6CmAi;
       spf=pass (google.com: domain of ardb@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=ardb@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id t26si65231uaq.1.2020.11.10.23.19.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 10 Nov 2020 23:19:27 -0800 (PST)
Received-SPF: pass (google.com: domain of ardb@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from mail-ot1-f51.google.com (mail-ot1-f51.google.com [209.85.210.51])
	(using TLSv1.2 with cipher ECDHE-RSA-AES128-GCM-SHA256 (128/128 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 4C93B207BB
	for <kasan-dev@googlegroups.com>; Wed, 11 Nov 2020 07:19:26 +0000 (UTC)
Received: by mail-ot1-f51.google.com with SMTP id j14so1290645ots.1
        for <kasan-dev@googlegroups.com>; Tue, 10 Nov 2020 23:19:26 -0800 (PST)
X-Received: by 2002:a05:6830:214c:: with SMTP id r12mr7308063otd.90.1605079165545;
 Tue, 10 Nov 2020 23:19:25 -0800 (PST)
MIME-Version: 1.0
References: <e9b1ba517f06b81bd24e54c84f5e44d81c27c566.camel@perches.com>
 <20201022073307.GP2628@hirez.programming.kicks-ass.net> <133aa0c8c5e2cbc862df109200b982e89046dbc0.camel@perches.com>
In-Reply-To: <133aa0c8c5e2cbc862df109200b982e89046dbc0.camel@perches.com>
From: Ard Biesheuvel <ardb@kernel.org>
Date: Wed, 11 Nov 2020 08:19:13 +0100
X-Gmail-Original-Message-ID: <CAMj1kXF_0_bu0nbJyUU-yBDCOAirRvGkX-V8kQPVh_GHO2WM-g@mail.gmail.com>
Message-ID: <CAMj1kXF_0_bu0nbJyUU-yBDCOAirRvGkX-V8kQPVh_GHO2WM-g@mail.gmail.com>
Subject: Re: [PATCH -next] treewide: Remove stringification from __alias macro definition
To: Joe Perches <joe@perches.com>, Russell King <linux@armlinux.org.uk>
Cc: Peter Zijlstra <peterz@infradead.org>, Thomas Gleixner <tglx@linutronix.de>, 
	Borislav Petkov <bp@alien8.de>, X86 ML <x86@kernel.org>, "H. Peter Anvin" <hpa@zytor.com>, 
	Miguel Ojeda <miguel.ojeda.sandonis@gmail.com>, Marco Elver <elver@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Herbert Xu <herbert@gondor.apana.org.au>, 
	"David S. Miller" <davem@davemloft.net>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Alexander Potapenko <glider@google.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Nick Desaulniers <ndesaulniers@google.com>, 
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>, linux-efi <linux-efi@vger.kernel.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux Crypto Mailing List <linux-crypto@vger.kernel.org>, linux-mm <linux-mm@kvack.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: ardb@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=guq6CmAi;       spf=pass
 (google.com: domain of ardb@kernel.org designates 198.145.29.99 as permitted
 sender) smtp.mailfrom=ardb@kernel.org;       dmarc=pass (p=NONE sp=NONE
 dis=NONE) header.from=kernel.org
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

(+ Russell)

On Thu, 22 Oct 2020 at 18:20, Joe Perches <joe@perches.com> wrote:
>
> On Thu, 2020-10-22 at 09:33 +0200, Peter Zijlstra wrote:
> > On Wed, Oct 21, 2020 at 11:58:25AM -0700, Joe Perches wrote:
> > > Like the __section macro, the __alias macro uses
> > > macro # stringification to create quotes around
> > > the section name used in the __attribute__.
> > >
> > > Remove the stringification and add quotes or a
> > > stringification to the uses instead.
> >
> > There's a complete lack of rationale for this change.
>
> I'll eventually post V2.
> I'm waiting to see if there are more comments.
>
> As I wrote in reply to Ard:
>
> https://lore.kernel.org/lkml/1cecfbfc853b2e71a96ab58661037c28a2f9280e.camel@perches.com/
>
> Using quotes in __section caused/causes differences
> between clang and gcc.
>
> https://lkml.org/lkml/2020/9/29/2187
>
> Using common styles for details like this is good.
>

This patch is now causing problems in the ARM tree, because some new
uses of __alias() have been queued (for KASAN), and since this is a
non-backwards compatible change, we have to choose between breaking
the maintainer's tree or breaking -next (given that the change has
been pulled in there now)

I am still not convinced we need this change, as I don't see how the
concerns regarding __section apply to __alias. But if we do, can we
please use the same approach, i.e., revert the current patch, and
queue it again after v5.11-rc1 with all new occurrences covered as
well?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAMj1kXF_0_bu0nbJyUU-yBDCOAirRvGkX-V8kQPVh_GHO2WM-g%40mail.gmail.com.
