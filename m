Return-Path: <kasan-dev+bncBDEPT3NHSUCBBOWV3PVAKGQEW3DL5HA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x440.google.com (mail-pf1-x440.google.com [IPv6:2607:f8b0:4864:20::440])
	by mail.lfdr.de (Postfix) with ESMTPS id 5C4219071A
	for <lists+kasan-dev@lfdr.de>; Fri, 16 Aug 2019 19:41:16 +0200 (CEST)
Received: by mail-pf1-x440.google.com with SMTP id e25sf4239663pfn.5
        for <lists+kasan-dev@lfdr.de>; Fri, 16 Aug 2019 10:41:16 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1565977274; cv=pass;
        d=google.com; s=arc-20160816;
        b=SxFykkSjtkuq+g4eblXa1O/NmL2N00y6zEDRYBXmyHYBaxu/O/1B7QoXvmashGB7C8
         e91f44yHiDAla9jDCV99eU73F5QPPtm8A0iMYKK8nafuZD6NdjIFs8PxSLRHicP6CL8f
         fia9/dfnruFT9MZ5JgbOzjdH4g68XyNiidiS+4sqt0d9Al1q1MawVDLbuo17ZAC3Otnq
         Sq4i6/6zNXsyHAJbmXmJMXCZb79Zr1QTMrHGCOvBQMiWRlhpD7DnLlwV0T9my1pV7/O2
         aFo7aCzaW4wR4XLOmqdEqWcmYambW4CoIdG13OEOXjOGQ6FX4qDxK+EOTTmVVRrs4dBN
         Dkcg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature;
        bh=ugV8epyJ+gSdgXjpN1R6MLKi36ylpmQcIoIha2dw+0c=;
        b=BmG7gUIdd3JYQsWUmoDmETYhDN/7TJtstcOIpddEd2HICWjpu8+j5r8yBE+IlX9PJQ
         RUbwV6bTX7ElBtlT4VSKfrkM7/WObtjZ/whD+b+pRf9WZDjF8ZlRtatBBZP4sViM6jvX
         8rr8kfF9oW9qs6HjszXYB4E+zQiHyWiPdcK15BG/fdWbUy0eRY39aDia9yGw89uz+Ii0
         dpXOVkIZx8ghWFJJhXqNGRnlj1cUcDQsAY+wTmJU0LV5+1aQWYMBXk9/YAUEHC4Lu9hg
         m9Mg/nkPeviSiXIyZ7xxwiVoHnGN2ptceJvFEeDTQOYGg1FPpK85SaCnV1UYNHDOQhLO
         jz9g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=0gBjg2V1;
       spf=pass (google.com: domain of luto@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=luto@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=ugV8epyJ+gSdgXjpN1R6MLKi36ylpmQcIoIha2dw+0c=;
        b=FJr2t4Z1yMleQnd9x8ABYSrRGh9Vh0SgjZruV62vQLzdiOhLwryLnn9oLW78jzekZP
         Op8eansM2QdtPbpYsi1tzdVhVAZ6XT2iNvBPqa+pSgMViyrOQ1E4sBOddhpSqJORAA2a
         lPT++diXmyVSpb6n2v6vwm0PwM6oyP/fnaJsF47GKY+kcZ8Rp1ye0pfuZXKt6/xp0ucF
         17b8tYw/PPucztPXeYBXHJ6murwqqDhl/dPp0XIVp8RT/ntwbDARCtRA+PquwWm1uI62
         SMzgjKWXnlZeKO5Dek6MhcI1Y6cNdGNRDR+ekhR8eGCybngowAcn4NNmYHGsNZApoWgE
         ldzQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=ugV8epyJ+gSdgXjpN1R6MLKi36ylpmQcIoIha2dw+0c=;
        b=C12N5JFneqj2LjSx+DSA7amu9if1bowo8L+vOZm28ezisbR/MYb1uHLJl8MXIM5r/E
         x66uWWhdAMcXZg/nowGSbhtfwCV8HAU23ziEbWOUOlubhB2AI9omwI4F3zXB/Wioi7cp
         Io5fEftRjtoOv9KVDCWctiHsdZjwQ7IZFI2cUdU2GPEtsFT3dZn4shoHubsGV436T4dp
         r/0+OiHtOVXIhoDwVUFXusyHSCFDTPuL+TU7b9DBaKmdXjAYdiqD0XAh4lYp6jCtMDM9
         eRQ72QKBgZobb1ARCKgpNYMFU8CzK8kQSGNSw6EHnX0pWDe4bkRzrKQExm85nVJBj1Pg
         OQPA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAVo/zZRWYCHcSLj6jnVNOunYrRkMYz3as92QJg1PjlItTQ7OA5d
	y6nrEJWjOcfYWgefd2CnLFU=
X-Google-Smtp-Source: APXvYqzO9akGvN3LVJ1zdw3CWcr/M1psUwxXeSTY16QLyHt3rEeAMVMtsCat7rFRFHqBdbeSZKCV6Q==
X-Received: by 2002:a17:902:54d:: with SMTP id 71mr10189355plf.140.1565977274818;
        Fri, 16 Aug 2019 10:41:14 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:800d:: with SMTP id j13ls2256591pfi.12.gmail; Fri, 16
 Aug 2019 10:41:14 -0700 (PDT)
X-Received: by 2002:a63:6f41:: with SMTP id k62mr8835412pgc.32.1565977274479;
        Fri, 16 Aug 2019 10:41:14 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1565977274; cv=none;
        d=google.com; s=arc-20160816;
        b=rz5Kpgu/s+VhUheWfZSRFRsuG/b7x7LeRhoWLwLWFkOWGgcjuyJ7FXDHdFWKEfIVsR
         A+bo5xNgiT80X4KW8MXt0BcFX0mi/gsNTKXWngc9WtIElCnvcPsSIEVBL3DFcwT81iM8
         zpXR4Y5YCoEgu2CKhvmmL6BLEG9yg+3CttTbVJgpLODh1R/JWnqJl/qoTVBCfftXQG0F
         22TfltSShnXdIaF/BopxQfQngJWntOT22tjPg31Z9joAp5zjQNJ+yvVD3pHM1q+y25IE
         w+6cn4/ZXF7vkbf/Nro4qgg5WlK4JdpKfYdtRXeA8KTNWQAYeifrLdQI7Yuw39WFW+kZ
         cXmA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=aFI8TAvCX3mGqmCyOrNiViRTHQlXirAglLGjqpHruWA=;
        b=xPLPzn7G9PGiCvr03UIpFtSfkLyXCn9u0YPontVVnqQ/U+Qk8+73i3bJE6/jUlQklC
         FMagg9B3FoODKWCR/cRhfGU7S0siIjMmHn5QEaOU+VwNCqEgmCMdQjhSCEdVQeAd12M7
         VNBn1S2YF0rPyzUsmh1T4FmIESPKuiF50Md0+tbydAGQyZGiXM+CAPa0ohhT6inj1xvM
         3WdmHKElo5ang4ag6389SZLLEDrDOBNzLNttHjXjUCuIRlF0RyAf3c+0hex3M8lXShNs
         TnsK/R9LkMJz9PHD9TfVnkjCaC92Yz+PxkjwPgYrTBD04r866x4WOxzInPDjnGFdxGWA
         ODYQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=0gBjg2V1;
       spf=pass (google.com: domain of luto@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=luto@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id i11si185121pju.1.2019.08.16.10.41.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 16 Aug 2019 10:41:14 -0700 (PDT)
Received-SPF: pass (google.com: domain of luto@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from mail-wr1-f54.google.com (mail-wr1-f54.google.com [209.85.221.54])
	(using TLSv1.2 with cipher ECDHE-RSA-AES128-GCM-SHA256 (128/128 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id BED4B2173E
	for <kasan-dev@googlegroups.com>; Fri, 16 Aug 2019 17:41:13 +0000 (UTC)
Received: by mail-wr1-f54.google.com with SMTP id p17so2279321wrf.11
        for <kasan-dev@googlegroups.com>; Fri, 16 Aug 2019 10:41:13 -0700 (PDT)
X-Received: by 2002:a05:6000:4f:: with SMTP id k15mr11973553wrx.221.1565977272223;
 Fri, 16 Aug 2019 10:41:12 -0700 (PDT)
MIME-Version: 1.0
References: <20190815001636.12235-1-dja@axtens.net> <20190815001636.12235-2-dja@axtens.net>
 <15c6110a-9e6e-495c-122e-acbde6e698d9@c-s.fr> <20190816170813.GA7417@lakrids.cambridge.arm.com>
In-Reply-To: <20190816170813.GA7417@lakrids.cambridge.arm.com>
From: Andy Lutomirski <luto@kernel.org>
Date: Fri, 16 Aug 2019 10:41:00 -0700
X-Gmail-Original-Message-ID: <CALCETrUn4FNjvRoJW77DNi5vdwO+EURUC_46tysjPQD0MM3THQ@mail.gmail.com>
Message-ID: <CALCETrUn4FNjvRoJW77DNi5vdwO+EURUC_46tysjPQD0MM3THQ@mail.gmail.com>
Subject: Re: [PATCH v4 1/3] kasan: support backing vmalloc space with real
 shadow memory
To: Mark Rutland <mark.rutland@arm.com>
Cc: Christophe Leroy <christophe.leroy@c-s.fr>, Daniel Axtens <dja@axtens.net>, 
	kasan-dev <kasan-dev@googlegroups.com>, Linux-MM <linux-mm@kvack.org>, X86 ML <x86@kernel.org>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Andrew Lutomirski <luto@kernel.org>, LKML <linux-kernel@vger.kernel.org>, 
	Dmitry Vyukov <dvyukov@google.com>, linuxppc-dev <linuxppc-dev@lists.ozlabs.org>, 
	Vasily Gorbik <gor@linux.ibm.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: luto@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=0gBjg2V1;       spf=pass
 (google.com: domain of luto@kernel.org designates 198.145.29.99 as permitted
 sender) smtp.mailfrom=luto@kernel.org;       dmarc=pass (p=NONE sp=NONE
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

On Fri, Aug 16, 2019 at 10:08 AM Mark Rutland <mark.rutland@arm.com> wrote:
>
> Hi Christophe,
>
> On Fri, Aug 16, 2019 at 09:47:00AM +0200, Christophe Leroy wrote:
> > Le 15/08/2019 =C3=A0 02:16, Daniel Axtens a =C3=A9crit :
> > > Hook into vmalloc and vmap, and dynamically allocate real shadow
> > > memory to back the mappings.
> > >
> > > Most mappings in vmalloc space are small, requiring less than a full
> > > page of shadow space. Allocating a full shadow page per mapping would
> > > therefore be wasteful. Furthermore, to ensure that different mappings
> > > use different shadow pages, mappings would have to be aligned to
> > > KASAN_SHADOW_SCALE_SIZE * PAGE_SIZE.
> > >
> > > Instead, share backing space across multiple mappings. Allocate
> > > a backing page the first time a mapping in vmalloc space uses a
> > > particular page of the shadow region. Keep this page around
> > > regardless of whether the mapping is later freed - in the mean time
> > > the page could have become shared by another vmalloc mapping.
> > >
> > > This can in theory lead to unbounded memory growth, but the vmalloc
> > > allocator is pretty good at reusing addresses, so the practical memor=
y
> > > usage grows at first but then stays fairly stable.
> >
> > I guess people having gigabytes of memory don't mind, but I'm concerned
> > about tiny targets with very little amount of memory. I have boards wit=
h as
> > little as 32Mbytes of RAM. The shadow region for the linear space alrea=
dy
> > takes one eighth of the RAM. I'd rather avoid keeping unused shadow pag=
es
> > busy.
>
> I think this depends on how much shadow would be in constant use vs what
> would get left unused. If the amount in constant use is sufficiently
> large (or the residue is sufficiently small), then it may not be
> worthwhile to support KASAN_VMALLOC on such small systems.
>
> > Each page of shadow memory represent 8 pages of real memory. Could we u=
se
> > page_ref to count how many pieces of a shadow page are used so that we =
can
> > free it when the ref count decreases to 0.
> >
> > > This requires architecture support to actually use: arches must stop
> > > mapping the read-only zero page over portion of the shadow region tha=
t
> > > covers the vmalloc space and instead leave it unmapped.
> >
> > Why 'must' ? Couldn't we switch back and forth from the zero page to re=
al
> > page on demand ?
> >
> > If the zero page is not mapped for unused vmalloc space, bad memory acc=
esses
> > will Oops on the shadow memory access instead of Oopsing on the real ba=
d
> > access, making it more difficult to locate and identify the issue.
>
> I agree this isn't nice, though FWIW this can already happen today for
> bad addresses that fall outside of the usual kernel address space. We
> could make the !KASAN_INLINE checks resilient to this by using
> probe_kernel_read() to check the shadow, and treating unmapped shadow as
> poison.

Could we instead modify the page fault handlers to detect this case
and print a useful message?

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CALCETrUn4FNjvRoJW77DNi5vdwO%2BEURUC_46tysjPQD0MM3THQ%40mail.gmai=
l.com.
