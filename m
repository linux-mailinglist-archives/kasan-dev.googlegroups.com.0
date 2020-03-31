Return-Path: <kasan-dev+bncBCS4V27AVMBBBOHLRX2AKGQERSY3WFY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53a.google.com (mail-ed1-x53a.google.com [IPv6:2a00:1450:4864:20::53a])
	by mail.lfdr.de (Postfix) with ESMTPS id 8759E199C31
	for <lists+kasan-dev@lfdr.de>; Tue, 31 Mar 2020 18:54:16 +0200 (CEST)
Received: by mail-ed1-x53a.google.com with SMTP id bm25sf539690edb.18
        for <lists+kasan-dev@lfdr.de>; Tue, 31 Mar 2020 09:54:16 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1585673656; cv=pass;
        d=google.com; s=arc-20160816;
        b=XsAyVBQYxKliUigej9qVmbPlPJwG1zSp7MJOOyblgEhcrR1m/6Qp49vcL7Em2IuIRE
         uyLDHCcc+tS3k9Mg01W0AeDcERj3cxx3JAGCH3mN9+g3ntH+zggzNyZlfqcow4HII5BC
         R92MLM1O0TT2DS3owQ4JF/ul3/9+FMr6419JKHxi0825NnObAl7VtiOZCPRgJTktLhfH
         39Fp9tTFW3WVyihhlpmAzDsCIP/ZYBzT6k27jAJzXWoRDFDeIIVGqu+WhbIwb9JU2RqP
         mUgaJ4ZYHq9+0tiSbLlrbdJl8s79VQV6FjI6XMPmi5YEXAt5oNL3DISmnIdYj2Ca/i0I
         Px4A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:thread-index:thread-topic
         :content-transfer-encoding:mime-version:subject:references
         :in-reply-to:message-id:cc:to:from:date:sender:dkim-signature;
        bh=4bH6MBzzW8BdtaZuzuMAqa0QnWDpyBLJql07/cW9dB0=;
        b=ptPAhbXavmhyHQshRq28GEguvGkAY570Wh1OdEDN/HB1sU+rgvf0RHkPWBhtmdiUtV
         Nl0usLAoC7eaoL/A64fgbm4amixoCZWSP7N4IUFkWmspJ8U7dD20I9Jp7LgW5daK3F5x
         yxVEJx2FV5Fr+VH85oxSvWlq2PIveZPQ7AmiSpA+Y6VL4ds5Cdhlc+z+FWC5dBv6mvmU
         hn06UUA/+5yXBO4ltsxadJcyA2FpynQQqXXSXmsPoRNfVTPWlUPr4nDrvQnXHsm/ZZWn
         0cTAbDHOQl4tXFa9CeQ5984VjST1Rh/H+NhHAnglf2CGptOo1USjZal1IieQyjoC82D9
         iFtQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of richard@nod.at designates 195.201.40.130 as permitted sender) smtp.mailfrom=richard@nod.at
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:message-id:in-reply-to:references:subject
         :mime-version:content-transfer-encoding:thread-topic:thread-index
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=4bH6MBzzW8BdtaZuzuMAqa0QnWDpyBLJql07/cW9dB0=;
        b=nzkajE2xots7NqivXyO74LhBa5INnyRjpkpFZ+OQzYDNXL45QxXNvPRE2bNXP6Z9zn
         c8fiaYmTmzlKS8WyzpTgksa4vpALsJ96wMQNuqudOYaNKefq8wdkLUyQIxHUGnxDYTJ/
         SRGe+KgovW7wePMP5KAD4yZ9tKRrLx1oaSpiAH8nwc3bVIc6/GES+pG5yoEzoeudv+pC
         Uhk8Lmsfi+TYjh2UgxpziFLv++5WF4r6azFTsZkEpzLsvk5zAjFxvDG6CzS2bUcmkSqd
         5ke7RrWtEqkZ7h8EIawRJNSvyKaN/oakd57VBvoYoMjbY/6kxSkhaNjoF5HzhG88ABq4
         +o9A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:message-id:in-reply-to
         :references:subject:mime-version:content-transfer-encoding
         :thread-topic:thread-index:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=4bH6MBzzW8BdtaZuzuMAqa0QnWDpyBLJql07/cW9dB0=;
        b=EFUYORoHxVnuD40QSJLAzW2jKNZAeUl0pg0szuDWFoDTppO6OKEBQ1BXutYy5UZGY4
         zeqEO3F9OYLodpkbjU0jldxKZi4OJzJAyr6Exv/PdqKd9nf38cOb9vKpndRdW1G8nQCu
         PubnjLQkU9d6Cu3g03O217HKTNX55JSn2RRLHOeKCgNFdwB0ytipbkrkRj0oiqc39J+I
         fIJY2t9qS40cYOVgephyJ31RYG9EyWY/I+ZYHarIpuI0QwhEnLhOcoFs5E8UCbIWhtME
         7rLlmf1zNjKCK0wn7zdWdt26M8tE8stQgX0Ct4vQXNp6ogPuh3rEt3krceMJTnRqKUgN
         A9FQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ANhLgQ2vi8WrgPDItxr8ij6GNB8DeMchx8Q8Ld3ufIAtgRqzFIQkwTaz
	mv0kBSIvqi8Zs8/cWtk6AoI=
X-Google-Smtp-Source: ADFU+vtlCI8bwH4k7KZoHMhI/iOB3hNdXe6JNI7LQ50qJOYgmml09fnOO3QzPi5w8g09RcfFSbpjAw==
X-Received: by 2002:a17:906:5c43:: with SMTP id c3mr15957162ejr.3.1585673656195;
        Tue, 31 Mar 2020 09:54:16 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:907:6f5:: with SMTP id yh21ls13780419ejb.11.gmail; Tue,
 31 Mar 2020 09:54:15 -0700 (PDT)
X-Received: by 2002:a17:906:261a:: with SMTP id h26mr16477060ejc.321.1585673655553;
        Tue, 31 Mar 2020 09:54:15 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1585673655; cv=none;
        d=google.com; s=arc-20160816;
        b=ggDilzEYvxgtmDoDKnemOEmRVWkbUVgOkV6w8kw3gvMup8z2YsvjN9nDeRLR7MTyOV
         VFCotNgmO23VmhxZyLNBmpGmfKJgtgzwYDYLNWHZzRBm5idxE0ebpNiK8lg+PX6epzQB
         OqZvvb/J57PiEn9rXRLV+Oe2B1mEc6y1vwkKuojefzA0yTk86zTs3hDC6p0MW831bfaS
         +8fg1kUFp3ndokZgOLdp8aVvpZodm0UW6Jjnn6PPJ4T/+gZhTBqBpeZl7kY8AKQAiPzU
         naE4S2WyaaDQHC1UV78WLsZ/NvhYA7XnJoOJScfBOnbaImLij/iW3dGBmRFh5kanriDt
         JFOA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=thread-index:thread-topic:content-transfer-encoding:mime-version
         :subject:references:in-reply-to:message-id:cc:to:from:date;
        bh=rZmXXUEpmnRibLUWf30rAZ61aSKOO34Z1veVFNnc6+w=;
        b=tyLVcqcONEm3hWMH0V40pO9RZPJmbjwZyso5bYwsAPAmFBUheFeWbh3W12oz+Lmgtw
         F1SEzcRLgvYbU4RO+DHXihBUCFlc9qEnSiX3TMj6rhNb+OdeMApSNhJz5vKVIUll2BIe
         eNiva8RTBhdMC7xsYCcn/4wbii+iU2UxRphUlyVxPhJ5W47T5gzFICEW6Gwu0iL6BpUH
         VCIsPVXHMa7HOMlIIvNd+lfl6iFKWQPRBit1RA7E9M6W2X94F0f0Mka7TDyRZmChC7FR
         nQryDk42G3ku6UAJ+ewYxn5tdXaqzUJynBpuGJn1WHCkgmXM4RbFmUWm6XXl0pQAWsrV
         muyw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of richard@nod.at designates 195.201.40.130 as permitted sender) smtp.mailfrom=richard@nod.at
Received: from lithops.sigma-star.at (lithops.sigma-star.at. [195.201.40.130])
        by gmr-mx.google.com with ESMTPS id k14si775747ejb.1.2020.03.31.09.54.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 31 Mar 2020 09:54:15 -0700 (PDT)
Received-SPF: pass (google.com: domain of richard@nod.at designates 195.201.40.130 as permitted sender) client-ip=195.201.40.130;
Received: from localhost (localhost [127.0.0.1])
	by lithops.sigma-star.at (Postfix) with ESMTP id 1FE5E60A073D;
	Tue, 31 Mar 2020 18:54:15 +0200 (CEST)
Received: from lithops.sigma-star.at ([127.0.0.1])
	by localhost (lithops.sigma-star.at [127.0.0.1]) (amavisd-new, port 10032)
	with ESMTP id bCAazVMZJRqh; Tue, 31 Mar 2020 18:54:13 +0200 (CEST)
Received: from localhost (localhost [127.0.0.1])
	by lithops.sigma-star.at (Postfix) with ESMTP id 0280B609D2F6;
	Tue, 31 Mar 2020 18:54:13 +0200 (CEST)
Received: from lithops.sigma-star.at ([127.0.0.1])
	by localhost (lithops.sigma-star.at [127.0.0.1]) (amavisd-new, port 10026)
	with ESMTP id 82ywUB7fjkiv; Tue, 31 Mar 2020 18:54:12 +0200 (CEST)
Received: from lithops.sigma-star.at (lithops.sigma-star.at [195.201.40.130])
	by lithops.sigma-star.at (Postfix) with ESMTP id D47F7609D2E2;
	Tue, 31 Mar 2020 18:54:12 +0200 (CEST)
Date: Tue, 31 Mar 2020 18:54:12 +0200 (CEST)
From: Richard Weinberger <richard@nod.at>
To: Patricia Alfonso <trishalfonso@google.com>
Cc: Johannes Berg <johannes@sipsolutions.net>, 
	Dmitry Vyukov <dvyukov@google.com>, Jeff Dike <jdike@addtoit.com>, 
	anton ivanov <anton.ivanov@cambridgegreys.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Brendan Higgins <brendanhiggins@google.com>, 
	davidgow <davidgow@google.com>, 
	linux-um <linux-um@lists.infradead.org>, 
	linux-kernel <linux-kernel@vger.kernel.org>, 
	kasan-dev <kasan-dev@googlegroups.com>
Message-ID: <418158403.63080.1585673652800.JavaMail.zimbra@nod.at>
In-Reply-To: <CAKFsvULjkQ7T6QhspHg87nnDpo-VW1qg2M3jJGB+NcwTQNeXGQ@mail.gmail.com>
References: <20200226004608.8128-1-trishalfonso@google.com> <CACT4Y+bdxmRmr57JO_k0whhnT2BqcSA=Jwa5M6=9wdyOryv6Ug@mail.gmail.com> <ded22d68e623d2663c96a0e1c81d660b9da747bc.camel@sipsolutions.net> <CACT4Y+YzM5bwvJ=yryrz1_y=uh=NX+2PNu4pLFaqQ2BMS39Fdg@mail.gmail.com> <2cee72779294550a3ad143146283745b5cccb5fc.camel@sipsolutions.net> <CACT4Y+YhwJK+F7Y7NaNpAwwWR-yZMfNevNp_gcBoZ+uMJRgsSA@mail.gmail.com> <a51643dbff58e16cc91f33273dbc95dded57d3e6.camel@sipsolutions.net> <CAKFsvULjkQ7T6QhspHg87nnDpo-VW1qg2M3jJGB+NcwTQNeXGQ@mail.gmail.com>
Subject: Re: [PATCH] UML: add support for KASAN under x86_64
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Originating-IP: [195.201.40.130]
X-Mailer: Zimbra 8.8.12_GA_3807 (ZimbraWebClient - FF68 (Linux)/8.8.12_GA_3809)
Thread-Topic: add support for KASAN under x86_64
Thread-Index: PKJWQW+CVN2ItfoQyPENtJL8H3bmwg==
X-Original-Sender: richard@nod.at
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of richard@nod.at designates 195.201.40.130 as permitted
 sender) smtp.mailfrom=richard@nod.at
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

Patricia,

----- Urspr=C3=BCngliche Mail -----
> Von: "Patricia Alfonso" <trishalfonso@google.com>
> An: "Johannes Berg" <johannes@sipsolutions.net>
> CC: "Dmitry Vyukov" <dvyukov@google.com>, "Jeff Dike" <jdike@addtoit.com>=
, "richard" <richard@nod.at>, "anton ivanov"
> <anton.ivanov@cambridgegreys.com>, "Andrey Ryabinin" <aryabinin@virtuozzo=
.com>, "Brendan Higgins"
> <brendanhiggins@google.com>, "davidgow" <davidgow@google.com>, "linux-um"=
 <linux-um@lists.infradead.org>,
> "linux-kernel" <linux-kernel@vger.kernel.org>, "kasan-dev" <kasan-dev@goo=
glegroups.com>
> Gesendet: Dienstag, 31. M=C3=A4rz 2020 18:39:21
> Betreff: Re: [PATCH] UML: add support for KASAN under x86_64

> On Mon, Mar 30, 2020 at 1:41 AM Johannes Berg <johannes@sipsolutions.net>=
 wrote:
>>
>> On Mon, 2020-03-30 at 10:38 +0200, Dmitry Vyukov wrote:
>> > On Mon, Mar 30, 2020 at 9:44 AM Johannes Berg <johannes@sipsolutions.n=
et> wrote:
>> > > On Fri, 2020-03-20 at 16:18 +0100, Dmitry Vyukov wrote:
>> > > > > Wait ... Now you say 0x7fbfffc000, but that is almost fine? I th=
ink you
>> > > > > confused the values - because I see, on userspace, the following=
:
>> > > >
>> > > > Oh, sorry, I copy-pasted wrong number. I meant 0x7fff8000.
>> > >
>> > > Right, ok.
>> > >
>> > > > Then I would expect 0x1000 0000 0000 to work, but you say it doesn=
't...
>> > >
>> > > So it just occurred to me - as I was mentioning this whole thing to
>> > > Richard - that there's probably somewhere some check about whether s=
ome
>> > > space is userspace or not.
>> > >
>=20
> Yeah, it seems the "Kernel panic - not syncing: Segfault with no mm",
> "Kernel mode fault at addr...", and "Kernel tried to access user
> memory at addr..." errors all come from segv() in
> arch/um/kernel/trap.c due to what I think is this type of check
> whether the address is
> in userspace or not.

Segfault with no mm means that a (not fixable) pagefault happened while
kernel code ran.

>> > > I'm beginning to think that we shouldn't just map this outside of th=
e
>> > > kernel memory system, but properly treat it as part of the memory th=
at's
>> > > inside. And also use KASAN_VMALLOC.
>> > >
>> > > We can probably still have it at 0x7fff8000, just need to make sure =
we
>> > > actually map it? I tried with vm_area_add_early() but it didn't real=
ly
>> > > work once you have vmalloc() stuff...
>> >
>=20
> What x86 does when KASAN_VMALLOC is disabled is make all vmalloc
> region accesses succeed by default
> by using the early shadow memory to have completely unpoisoned and
> unpoisonable read-only pages for all of vmalloc (which includes
> modules). When KASAN_VMALLOC is enabled in x86, the shadow memory is not
> allocated for the vmalloc region at startup. New chunks of shadow
> memory are allocated and unpoisoned every time there's a vmalloc()
> call. A similar thing might have to be done here by mprotect()ing
> the vmalloc space as read only, unpoisoned without KASAN_VMALLOC. This
> issue here is that
> kasan_init runs so early in the process that the vmalloc region for
> uml is not setup yet.
>=20
>=20
>> > But we do mmap it, no? See kasan_init() -> kasan_map_memory() -> mmap.
>>
>> Of course. But I meant inside the UML PTE system. We end up *unmapping*
>> it when loading modules, because it overlaps vmalloc space, and then we
>> vfree() something again, and unmap it ... because of the overlap.
>>
>> And if it's *not* in the vmalloc area, then the kernel doesn't consider
>> it valid, and we seem to often just fault when trying to determine
>> whether it's valid kernel memory or not ... Though I'm not really sure I
>> understand the failure part of this case well yet.
>>
>=20
> I have been testing this issue in a multitude of ways and have only
> been getting more confused. It's still very unclear where exactly the
> problem occurs, mostly because the errors I found most frequently were
> reported in segv(), but the stack traces never contained segv.
>=20
> Does anyone know if/how UML determines if memory being accessed is
> kernel or user memory?

In contrast to classic x86, without KPTI and SMAP/SMEP, UML has a strong
separation between user- and kernel-memory. This is also why copy_from/to_u=
ser()
is so expensive.

In arch/um/kernel/trap.c segv() you can see the logic.
Also see UPT_IS_USER().

Thanks,
//richard

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/418158403.63080.1585673652800.JavaMail.zimbra%40nod.at.
