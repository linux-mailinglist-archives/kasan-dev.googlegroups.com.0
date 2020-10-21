Return-Path: <kasan-dev+bncBD63HSEZTUIBBB4PYL6AKGQECG3UN6A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63f.google.com (mail-pl1-x63f.google.com [IPv6:2607:f8b0:4864:20::63f])
	by mail.lfdr.de (Postfix) with ESMTPS id 4F3D12952C0
	for <lists+kasan-dev@lfdr.de>; Wed, 21 Oct 2020 21:10:01 +0200 (CEST)
Received: by mail-pl1-x63f.google.com with SMTP id q4sf1743428plr.11
        for <lists+kasan-dev@lfdr.de>; Wed, 21 Oct 2020 12:10:01 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1603307400; cv=pass;
        d=google.com; s=arc-20160816;
        b=IaCmmFWH5yOwsWlWi1rqlAnDWJDfUPpaDx7ecGDxikjqJJU+q0vDZM5hIWXv2ycVe+
         3GUa2K3OgWaR2ZHMBFjwQoNaxCHko01k6SB4WnflYPJ3vQ9IIKdwigbIWCdemYYu0FqC
         OkDNyAMkCOWVmnybbWxZDKjC10tSNctyGHECQ9xL0hpD9LFuM5N/I7AZvSwYRPxzVOaa
         bNjZBz5NTEXordOeA1u6PTI3YQPdm/MPM7rHlWE2/IxXCY1IDEx+s+qWVocC8YduZoyi
         GznWgK3mxEt4i57zoBIGP30gAv8unK8HbjU+U/16dYASJxD1PubfWFidIB516siCKrvB
         ft9Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=WwiRQ7DuSb9aGW4YjsOOhR2zdl/I2dGq1MQrsNWBJDw=;
        b=Ibr/vmsua8ekjoW1woEaw0TVP1XfxNsVNzcEHDAXk7qEwua3uMKxB1Mz3S13ZF8ZrM
         YtSS2S/CjRJhOFM957RrZ0orJ49mmX5OCYUFgj3BgsN2J8AI4wjmb6AK+F/ekQkY35tr
         1/j4349RafvwDqodOsWzHMy59N1rZDEuABdiuYXzq8oE/tQwjtLd1ncciO8s5vMXC7mc
         nC7DlbaMaQIzF3waVZn4PV2TjsG2ZpWxZQ4VDaK3tYqRgkcEBzF+K01YTHFfQ7Ppp4Yx
         c4aS/O74d9dGSYjDHcGKhZsGGHgc+kvdjXjGpaUx3Oxdo1bOP29P1LpYeCEa+mujPwxq
         QViA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=gLg2ILm+;
       spf=pass (google.com: domain of ardb@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=ardb@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=WwiRQ7DuSb9aGW4YjsOOhR2zdl/I2dGq1MQrsNWBJDw=;
        b=HSoTw3qg3zQLkjCaNdvo3xgt5L2evhbN6QP69RiIdXZXIH77axRQrtx2pgl3jqrcNp
         eFDH8gbetBl0U7OpVc7eujau7/4q2oN6o4qMtESrVYdU1zjiqPk8Vo4VH+B01t2sibpp
         rM7VqwjAm5JW5ziztWIPwm2ZbivmGZcd/+YQxKTuFIFglTs0SxhJZgQmDxIuTkeAbdiK
         qk1dVPMO51K1wqAMX7mobc67aFC4Re56+UxddUeAtQGysoo69u75/7EQIoge0eftie7t
         24gGKZNWYwCzyrtMmnJT0/bCQMrwwqOPxlgKHF7lbvGPyQVJIS0dRs+Bk0xZ8+qmju2K
         ON/w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=WwiRQ7DuSb9aGW4YjsOOhR2zdl/I2dGq1MQrsNWBJDw=;
        b=GeqkKo133LjwER3ZuV+i41ap5SxYLX+dB6YrNM2W9bw0n8CuESQKcauIcvgHQEDfP+
         VOtIFe710J+OgSJloRVTG5G62eWviqgceTFSRjNq/5aQm1hCExv5piE/iJoNff+A2bjI
         pKsOlRY8d4mHhrLoWYZowikrwDusM1FH8HA7bWqvjvp+Z+Vf20h63zHve9SMgTmxInqa
         isJ+8OmJLqiIAdRN0TmrsCBkyQeaHs6jNhrGGaymJCOwVHGZLqJp1YW8TgL8frT/GMnv
         sl85Xv9hgfrj24ubx+DYkhNomNy3TFAIRrgWjd6w9FCKj4j0F0RCzfLRXjOvASXGpL9e
         2pDw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533HqNOwJwbffH8K0ib/8JrRZxPieYh5GoMpGWYAx/BuSQue8FqJ
	NR/06Oy/DN3kz1Szrlw/A1M=
X-Google-Smtp-Source: ABdhPJzIRXBMQS/2S+MdyaYr0Hv1R1eAAkeVSSdGUIN2nb8+adL7H4FdbivCjw6CIwOQEIlsILaO9A==
X-Received: by 2002:a63:4d45:: with SMTP id n5mr4482101pgl.389.1603307399767;
        Wed, 21 Oct 2020 12:09:59 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:8edc:: with SMTP id b28ls294694pfr.9.gmail; Wed, 21 Oct
 2020 12:09:59 -0700 (PDT)
X-Received: by 2002:a62:2ac2:0:b029:15d:a09e:7a0c with SMTP id q185-20020a622ac20000b029015da09e7a0cmr5011388pfq.21.1603307399238;
        Wed, 21 Oct 2020 12:09:59 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1603307399; cv=none;
        d=google.com; s=arc-20160816;
        b=i/Ynbgg4moOZ/UijpQoS0kAKk+hVpbs1N4DWiNqWqu+IDF6sT2miQWitHPTv4y1/Jq
         JgOH+43+keiPwGgV8cxKJdSbOoNFp4z+OtEcz5I5RtjnPWDa7rRXgnBrgTrdZB5KRF7n
         PE6BLXKOE5FhwGiKXXnRI7PYrSOoscMasfwCIu7v4rU1KXEjexD3DYhTSPU2zsVUpHiD
         mKHtf5rue4IjtlXLZJ0XY3L+OkqZp9o1W2iK7RSns9PcKvGeAzYgSD9xZTJiuvwTPpSs
         1uLq0qoXau3Y65R4MFSheJFifpEZpoO3Sht6b1x/GnWMi1MNdf9qVhzFev73rDAtsOdM
         XUKw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=3mlDknj7gWWP20636gbskByHmbYqyI43SuULks1EPec=;
        b=f+OnCd7XfS4hZLuawXu6vCmKEZrNQKUYWO1hg+MeBsUXYbmaUN60ykhG9XyPaDhF8T
         4tJrNnu9+OttCohWULoWTe7/RW774EbRvZCAslwR6fBMEDfGZYdg+aTm3xNZNdhW2JY5
         aj9b2lWwIn3snmirWgLI3uVr1+gSas78HDwLLR/u5owdwYWTi4kbEGmy6yFDc0GzVsAq
         rPRYmYLno46jauDLcJmoUGz4yIkinysjmPOD4Y02GbJCRnKnMtULZblBfN8hpkQtfKMI
         SgdzKNPpZM2Vbvw9NciHlT0NhbgewBie3t4jnnVP/7DkQZdbD/EDNjLZiU64LS2MCZWq
         Xs5g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=gLg2ILm+;
       spf=pass (google.com: domain of ardb@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=ardb@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id l7si176708plt.3.2020.10.21.12.09.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 21 Oct 2020 12:09:59 -0700 (PDT)
Received-SPF: pass (google.com: domain of ardb@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from mail-oi1-f176.google.com (mail-oi1-f176.google.com [209.85.167.176])
	(using TLSv1.2 with cipher ECDHE-RSA-AES128-GCM-SHA256 (128/128 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 904A52416E
	for <kasan-dev@googlegroups.com>; Wed, 21 Oct 2020 19:09:58 +0000 (UTC)
Received: by mail-oi1-f176.google.com with SMTP id u127so3244789oib.6
        for <kasan-dev@googlegroups.com>; Wed, 21 Oct 2020 12:09:58 -0700 (PDT)
X-Received: by 2002:aca:5a56:: with SMTP id o83mr3085292oib.47.1603307397782;
 Wed, 21 Oct 2020 12:09:57 -0700 (PDT)
MIME-Version: 1.0
References: <e9b1ba517f06b81bd24e54c84f5e44d81c27c566.camel@perches.com>
 <CAMj1kXHe0hEDiGNMM_fg3_RYjM6B6mbKJ+1R7tsnA66ZzsiBgw@mail.gmail.com> <1cecfbfc853b2e71a96ab58661037c28a2f9280e.camel@perches.com>
In-Reply-To: <1cecfbfc853b2e71a96ab58661037c28a2f9280e.camel@perches.com>
From: Ard Biesheuvel <ardb@kernel.org>
Date: Wed, 21 Oct 2020 21:09:46 +0200
X-Gmail-Original-Message-ID: <CAMj1kXFZteNourygxm1zEmW_sBgenpNZno0VefXd0W8GgWEPTQ@mail.gmail.com>
Message-ID: <CAMj1kXFZteNourygxm1zEmW_sBgenpNZno0VefXd0W8GgWEPTQ@mail.gmail.com>
Subject: Re: [PATCH -next] treewide: Remove stringification from __alias macro definition
To: Joe Perches <joe@perches.com>
Cc: Thomas Gleixner <tglx@linutronix.de>, Borislav Petkov <bp@alien8.de>, X86 ML <x86@kernel.org>, 
	"H. Peter Anvin" <hpa@zytor.com>, Miguel Ojeda <miguel.ojeda.sandonis@gmail.com>, 
	Marco Elver <elver@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Herbert Xu <herbert@gondor.apana.org.au>, "David S. Miller" <davem@davemloft.net>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Nick Desaulniers <ndesaulniers@google.com>, 
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>, linux-efi <linux-efi@vger.kernel.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux Crypto Mailing List <linux-crypto@vger.kernel.org>, linux-mm <linux-mm@kvack.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: ardb@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=gLg2ILm+;       spf=pass
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

On Wed, 21 Oct 2020 at 21:07, Joe Perches <joe@perches.com> wrote:
>
> On Wed, 2020-10-21 at 21:02 +0200, Ard Biesheuvel wrote:
> > On Wed, 21 Oct 2020 at 20:58, Joe Perches <joe@perches.com> wrote:
> > > Like the __section macro, the __alias macro uses
> > > macro # stringification to create quotes around
> > > the section name used in the __attribute__.
> > >
> > > Remove the stringification and add quotes or a
> > > stringification to the uses instead.
> > >
> >
> > Why?
>
> Using quotes in __section caused/causes differences
> between clang and gcc.
>
> https://lkml.org/lkml/2020/9/29/2187
>
> Using common styles for details like this is good.
>
>

Ah, fair enough.

With this rationale added to the commit log:

Acked-by: Ard Biesheuvel <ardb@kernel.org>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAMj1kXFZteNourygxm1zEmW_sBgenpNZno0VefXd0W8GgWEPTQ%40mail.gmail.com.
