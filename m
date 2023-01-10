Return-Path: <kasan-dev+bncBDN3ZEGJT4NBBKGP6SOQMGQEGTYXDAQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa40.google.com (mail-vk1-xa40.google.com [IPv6:2607:f8b0:4864:20::a40])
	by mail.lfdr.de (Postfix) with ESMTPS id 5A195663BDA
	for <lists+kasan-dev@lfdr.de>; Tue, 10 Jan 2023 09:54:02 +0100 (CET)
Received: by mail-vk1-xa40.google.com with SMTP id x75-20020a1f7c4e000000b003d591e8cac6sf3524339vkc.5
        for <lists+kasan-dev@lfdr.de>; Tue, 10 Jan 2023 00:54:02 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1673340841; cv=pass;
        d=google.com; s=arc-20160816;
        b=lpEG0328YahyGEfwmegpya3FMNeIjjYms0YbK6c0j4qc9L+IFRTm0dBVqBrDjJDzhS
         6qU2Bj2vrlQpWwejHCs3Lg/1ZoSolUZH5utzlHUVhJkYxNlUK54dPbptLz2Ps30tO7QV
         ZO1gig6wgq6Qx8cioTcRZaHpcTTM+CskUlAAN9cJmR1HrUIxf+N66xvKEH646az5bnpS
         1NJ8ob6fRSeLQLujUpQQOtK11lBE2cV7BM+LqUy17jjvk3n7afrgkPBaxbPibuGtiZzd
         IVOIBVJXpIKynZzci/SmqQt1OPntvnz6dTkMt2mppAxmPIKt2fVzkH7oxck4/p8A+JuP
         Mv+w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=cIknT0or3MFA4CVsQTaiOfoMhg/ZGGL1xbCM4dA41Xg=;
        b=HnnckATYePE5ORpm1Zr1+YTQWjXldeXrRV5NJnHWtPK0naRaLW/zNF+X7qgpeeoWtC
         QFU9mXs9WkFPYKjLG7sVVp3y8X6fl2LIpdUpRs2GrfDwcDaMCZFuzK7F2KfEAdktpJ4O
         Sy3HXXP0soBXWPDDZvoIm2OShvJkGPCxcDsttEPSuK/axUbVxwne2RSQxssXEjDOoGkZ
         YZz1Lspreeg3kOEkPaXXvKehEGX8al5r/kvXsnTUJWOVdQfvnv4sgt1uaCYHBHSAVSzZ
         cNJQg6NFtidEMelddMrbRYXBTYGPIZiHEjqhx9R2rJdeER2t86QsvAHJzpCGj5TBGImZ
         sujw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="k/TJCMVa";
       spf=pass (google.com: domain of edumazet@google.com designates 2607:f8b0:4864:20::b31 as permitted sender) smtp.mailfrom=edumazet@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=cIknT0or3MFA4CVsQTaiOfoMhg/ZGGL1xbCM4dA41Xg=;
        b=QVSL82eO4ioSgoBx4HbPLeVKH8JSrTd4Gsxsnn7+Ne+KHE1bHBefwkWvLfOOH889sg
         r6BPEsZkvub8EpkRWqPTlLqvlL/GNkxAU1wxcsHej5eeEBQqmg1vneVxIyjYIn6yyZE9
         n+tePh+LAiX0NApcRTkkY1VIF5SmY1aRVA/zn/6UXE14ZIDvh+uEEmAyJpUTZOftL8z2
         jYIZLCdE2Q9tpn7ph/R6x3vN5y4wS7fiXR7g3InbBhFfmPzel3Ms6GLWgI2RoojipFNm
         cKhZYMh5f+HQulxjqSQ5DwjXzOrCUHu8t3X1HO26vPfFzp7gQoEyXik0Agi6KH783C9L
         s7xQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-gm-message-state:from:to:cc
         :subject:date:message-id:reply-to;
        bh=cIknT0or3MFA4CVsQTaiOfoMhg/ZGGL1xbCM4dA41Xg=;
        b=Rjx4z/u3AuG56GpUuZ0SgbgWCC7SqtceiJfELwTGttNM6CbN+Kzd73dlJPscbgdhv6
         M5N1b5PaYE+to29UjDc/Be2/hTvTlf2w2sWOD2iuk5mbWeTQQFQxerfM7rR/1G1D83Mr
         wOG6cujg04xviB32cvfhziBcO5sjnWjSzCT+ZHL29Bcvd5FU1E03HfcuiBb4K8cGnWwX
         +NtY5Q0GspE/uHoyF0qRYYqCIJAwUw0UXnky3Q6dcSAr7olNGAgtUyCwjX2L3TiFKXBR
         tIOsyy9wJCtPwBk8Von2pq8g/MI2IFkbz/fK9VacAN9MrYXatLdwUUrZ1N52uylk0EwQ
         8Waw==
X-Gm-Message-State: AFqh2koiyMD57BMnes+0eN6h1Hs3b3D2YhFUGANw3tJeECclOp93Y3rL
	rJwt58wKEjzFWAe44GJQkjA=
X-Google-Smtp-Source: AMrXdXvNZBUTYgpEARbLXTsAtllEHNzXtfG9NTRXSxZRbEkEySBE45/8kD0JMJ0d7/Jm49BptnTdTA==
X-Received: by 2002:a67:db06:0:b0:3ce:b074:b597 with SMTP id z6-20020a67db06000000b003ceb074b597mr5164698vsj.36.1673340841146;
        Tue, 10 Jan 2023 00:54:01 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:d488:0:b0:3b1:1703:92cb with SMTP id g8-20020a67d488000000b003b1170392cbls2268066vsj.1.-pod-prod-gmail;
 Tue, 10 Jan 2023 00:54:00 -0800 (PST)
X-Received: by 2002:a67:de83:0:b0:3ca:a9ef:43ee with SMTP id r3-20020a67de83000000b003caa9ef43eemr24840927vsk.5.1673340840491;
        Tue, 10 Jan 2023 00:54:00 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1673340840; cv=none;
        d=google.com; s=arc-20160816;
        b=Zb/mIQFsKveJZL82VxMTLW0fpj1N0xoqHfx3n8FHtH2mLGSBkiOhdA8ewSUnMLgJdD
         1BGE5ghJRy3LFied1oWVdnkhVZy+Ddt+R+USP4n0tt+08A2DDEPhRnGak2W2th6AL+Er
         p4gyc0wD0lqMlsDFKzE53wxoP2mjH4ddcJ7IuueTDePIRBhwXntLAQHlZE6oXHZFpowu
         cqkRe5rJzLvuqYMraPl6iLl1ngT3Rq2epI+gCuNgabpRql7ZDmBY9MgmuiI0U3bTZi2l
         t3iE8u7SdqiUvefb42FgBjLlnB+boEQ/ucRL6i7ywgTGOa2QnzK4CL4evCku9RkzMcH0
         YpLQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=9C0wBQv8YQpv5VyQcb9pxfBorQ6HWujhHG8utDOoc3g=;
        b=VtZFy3VA1gj5JAlCLFEPhAEIuH8UCMSbEWe7s6cNg+yiAH/lDfOWfRfpOau7NuVtl+
         JonUHYDl93qc13SGntHU0V9AOLlWT5x8yeK0BoMcNPuVDZ69PdyZZQkXW9C1xLeY02mN
         wGqgwD1+pBcR9NHqE2nwNqRLwQcSFLOQUqidv7R/NDh0AcjgqsDWfcFAXELLky7+yVL+
         c4czqot9CMnbYAuTcF5PeBKNIw/e1mAnfh+Qi8Pig89Fawb8nswpLzV3u7cCHIJIW9Pq
         yfPB0YESWajE1Lsdkuvix9lZAF+PM7wIEq2nVACUrmBSSXkIy4+6N25piyu2+Xb6zrWf
         m1Vg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="k/TJCMVa";
       spf=pass (google.com: domain of edumazet@google.com designates 2607:f8b0:4864:20::b31 as permitted sender) smtp.mailfrom=edumazet@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb31.google.com (mail-yb1-xb31.google.com. [2607:f8b0:4864:20::b31])
        by gmr-mx.google.com with ESMTPS id ay9-20020a056130030900b005e2cbd30052si160369uab.1.2023.01.10.00.54.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 10 Jan 2023 00:54:00 -0800 (PST)
Received-SPF: pass (google.com: domain of edumazet@google.com designates 2607:f8b0:4864:20::b31 as permitted sender) client-ip=2607:f8b0:4864:20::b31;
Received: by mail-yb1-xb31.google.com with SMTP id v19so5229993ybv.1
        for <kasan-dev@googlegroups.com>; Tue, 10 Jan 2023 00:54:00 -0800 (PST)
X-Received: by 2002:a25:3f06:0:b0:769:e5aa:4ac9 with SMTP id
 m6-20020a253f06000000b00769e5aa4ac9mr6208999yba.598.1673340839748; Tue, 10
 Jan 2023 00:53:59 -0800 (PST)
MIME-Version: 1.0
References: <20220701142310.2188015-1-glider@google.com> <20220701142310.2188015-11-glider@google.com>
 <CANpmjNOYqXSw5+Sxt0+=oOUQ1iQKVtEYHv20=sh_9nywxXUyWw@mail.gmail.com>
 <CAG_fn=W2EUjS8AX1Odunq1==dV178s_-w3hQpyrFBr=Auo-Q-A@mail.gmail.com>
 <63b74a6e6a909_c81f0294a5@dwillia2-xfh.jf.intel.com.notmuch>
 <CAG_fn=WjrzaHLfgw7ByFvguHA8z0MA-ZB3Kd0d6CYwmZWVEgjA@mail.gmail.com>
 <63bc8fec4744a_5178e29467@dwillia2-xfh.jf.intel.com.notmuch>
 <Y7z99mf1M5edxV4A@kroah.com> <63bd0be8945a0_5178e29414@dwillia2-xfh.jf.intel.com.notmuch>
 <CAG_fn=X9jBwAvz9gph-02WcLhv3MQkBpvkZAsZRMwEYyT8zVeQ@mail.gmail.com>
In-Reply-To: <CAG_fn=X9jBwAvz9gph-02WcLhv3MQkBpvkZAsZRMwEYyT8zVeQ@mail.gmail.com>
From: "'Eric Dumazet' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 10 Jan 2023 09:53:48 +0100
Message-ID: <CANn89iJRXSb-xK_VxkHqm8NLGhfH1Q_HW_p=ygAH7QocyVh+DQ@mail.gmail.com>
Subject: Re: [PATCH v4 10/45] libnvdimm/pfn_dev: increase MAX_STRUCT_PAGE_SIZE
To: Alexander Potapenko <glider@google.com>
Cc: Dan Williams <dan.j.williams@intel.com>, 
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>, Marco Elver <elver@google.com>, 
	Alexander Viro <viro@zeniv.linux.org.uk>, Alexei Starovoitov <ast@kernel.org>, 
	Andrew Morton <akpm@linux-foundation.org>, Andrey Konovalov <andreyknvl@google.com>, 
	Andy Lutomirski <luto@kernel.org>, Arnd Bergmann <arnd@arndb.de>, Borislav Petkov <bp@alien8.de>, 
	Christoph Hellwig <hch@lst.de>, Christoph Lameter <cl@linux.com>, David Rientjes <rientjes@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Herbert Xu <herbert@gondor.apana.org.au>, 
	Ilya Leoshkevich <iii@linux.ibm.com>, Ingo Molnar <mingo@redhat.com>, Jens Axboe <axboe@kernel.dk>, 
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, Kees Cook <keescook@chromium.org>, 
	Mark Rutland <mark.rutland@arm.com>, Matthew Wilcox <willy@infradead.org>, 
	"Michael S. Tsirkin" <mst@redhat.com>, Pekka Enberg <penberg@kernel.org>, 
	Peter Zijlstra <peterz@infradead.org>, Petr Mladek <pmladek@suse.com>, 
	Steven Rostedt <rostedt@goodmis.org>, Thomas Gleixner <tglx@linutronix.de>, 
	Vasily Gorbik <gor@linux.ibm.com>, Vegard Nossum <vegard.nossum@oracle.com>, 
	Vlastimil Babka <vbabka@suse.cz>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux Memory Management List <linux-mm@kvack.org>, Linux-Arch <linux-arch@vger.kernel.org>, 
	LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: edumazet@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b="k/TJCMVa";       spf=pass
 (google.com: domain of edumazet@google.com designates 2607:f8b0:4864:20::b31
 as permitted sender) smtp.mailfrom=edumazet@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Eric Dumazet <edumazet@google.com>
Reply-To: Eric Dumazet <edumazet@google.com>
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

On Tue, Jan 10, 2023 at 9:49 AM Alexander Potapenko <glider@google.com> wro=
te:
>
> On Tue, Jan 10, 2023 at 7:55 AM Dan Williams <dan.j.williams@intel.com> w=
rote:
> >
> > Greg Kroah-Hartman wrote:
> > > On Mon, Jan 09, 2023 at 02:06:36PM -0800, Dan Williams wrote:
> > > > Alexander Potapenko wrote:
> > > > > On Thu, Jan 5, 2023 at 11:09 PM Dan Williams <dan.j.williams@inte=
l.com> wrote:
> > > > > >
> > > > > > Alexander Potapenko wrote:
> > > > > > > (+ Dan Williams)
> > > > > > > (resending with patch context included)
> > > > > > >
> > > > > > > On Mon, Jul 11, 2022 at 6:27 PM Marco Elver <elver@google.com=
> wrote:
> > > > > > > >
> > > > > > > > On Fri, 1 Jul 2022 at 16:23, Alexander Potapenko <glider@go=
ogle.com> wrote:
> > > > > > > > >
> > > > > > > > > KMSAN adds extra metadata fields to struct page, so it do=
es not fit into
> > > > > > > > > 64 bytes anymore.
> > > > > > > >
> > > > > > > > Does this somehow cause extra space being used in all kerne=
l configs?
> > > > > > > > If not, it would be good to note this in the commit message=
.
> > > > > > > >
> > > > > > > I actually couldn't verify this on QEMU, because the driver n=
ever got loaded.
> > > > > > > Looks like this increases the amount of memory used by the nv=
dimm
> > > > > > > driver in all kernel configs that enable it (including those =
that
> > > > > > > don't use KMSAN), but I am not sure how much is that.
> > > > > > >
> > > > > > > Dan, do you know how bad increasing MAX_STRUCT_PAGE_SIZE can =
be?
> > > > > >
> > > > > > Apologies I missed this several months ago. The answer is that =
this
> > > > > > causes everyone creating PMEM namespaces on v6.1+ to lose doubl=
e the
> > > > > > capacity of their namespace even when not using KMSAN which is =
too
> > > > > > wasteful to tolerate. So, I think "6e9f05dc66f9 libnvdimm/pfn_d=
ev:
> > > > > > increase MAX_STRUCT_PAGE_SIZE" needs to be reverted and replace=
d with
> > > > > > something like:
> > > > > >
> > > > > > diff --git a/drivers/nvdimm/Kconfig b/drivers/nvdimm/Kconfig
> > > > > > index 79d93126453d..5693869b720b 100644
> > > > > > --- a/drivers/nvdimm/Kconfig
> > > > > > +++ b/drivers/nvdimm/Kconfig
> > > > > > @@ -63,6 +63,7 @@ config NVDIMM_PFN
> > > > > >         bool "PFN: Map persistent (device) memory"
> > > > > >         default LIBNVDIMM
> > > > > >         depends on ZONE_DEVICE
> > > > > > +       depends on !KMSAN
> > > > > >         select ND_CLAIM
> > > > > >         help
> > > > > >           Map persistent memory, i.e. advertise it to the memor=
y
> > > > > >
> > > > > >
> > > > > > ...otherwise, what was the rationale for increasing this value?=
 Were you
> > > > > > actually trying to use KMSAN for DAX pages?
> > > > >
> > > > > I was just building the kernel with nvdimm driver and KMSAN enabl=
ed.
> > > > > Because KMSAN adds extra data to every struct page, it immediatel=
y hit
> > > > > the following assert:
> > > > >
> > > > > drivers/nvdimm/pfn_devs.c:796:3: error: call to
> > > > > __compiletime_assert_330 declared with 'error' attribute: BUILD_B=
UG_ON
> > > > > fE
> > > > >                 BUILD_BUG_ON(sizeof(struct page) > MAX_STRUCT_PAG=
E_SIZE);
> > > > >
> > > > > The comment before MAX_STRUCT_PAGE_SIZE declaration says "max str=
uct
> > > > > page size independent of kernel config", but maybe we can afford
> > > > > making it dependent on CONFIG_KMSAN (and possibly other config op=
tions
> > > > > that increase struct page size)?
> > > > >
> > > > > I don't mind disabling the driver under KMSAN, but having an extr=
a
> > > > > ifdef to keep KMSAN support sounds reasonable, WDYT?
> > > >
> > > > How about a module parameter to opt-in to the increased permanent
> > > > capacity loss?
> > >
> > > Please no, this isn't the 1990's, we should never force users to keep
> > > track of new module parameters that you then have to support for
> > > forever.
> >
> > Fair enough, premature enabling. If someone really wants this they can
> > find this thread in the archives and ask for another solution like
> > compile time override.
> >
> > >
> > >
> > > >
> > > > -- >8 --
> > > > >From 693563817dea3fd8f293f9b69ec78066ab1d96d2 Mon Sep 17 00:00:00 =
2001
> > > > From: Dan Williams <dan.j.williams@intel.com>
> > > > Date: Thu, 5 Jan 2023 13:27:34 -0800
> > > > Subject: [PATCH] nvdimm: Support sizeof(struct page) > MAX_STRUCT_P=
AGE_SIZE
> > > >
> > > > Commit 6e9f05dc66f9 ("libnvdimm/pfn_dev: increase MAX_STRUCT_PAGE_S=
IZE")
> > > >
> > > > ...updated MAX_STRUCT_PAGE_SIZE to account for sizeof(struct page)
> > > > potentially doubling in the case of CONFIG_KMSAN=3Dy. Unfortunately=
 this
> > > > doubles the amount of capacity stolen from user addressable capacit=
y for
> > > > everyone, regardless of whether they are using the debug option. Re=
vert
> > > > that change, mandate that MAX_STRUCT_PAGE_SIZE never exceed 64, but
> > > > allow for debug scenarios to proceed with creating debug sized page=
 maps
> > > > with a new 'libnvdimm.page_struct_override' module parameter.
> > > >
> > > > Note that this only applies to cases where the page map is permanen=
t,
> > > > i.e. stored in a reservation of the pmem itself ("--map=3Ddev" in "=
ndctl
> > > > create-namespace" terms). For the "--map=3Dmem" case, since the all=
ocation
> > > > is ephemeral for the lifespan of the namespace, there are no explic=
it
> > > > restriction. However, the implicit restriction, of having enough
> > > > available "System RAM" to store the page map for the typically larg=
e
> > > > pmem, still applies.
> > > >
> > > > Fixes: 6e9f05dc66f9 ("libnvdimm/pfn_dev: increase MAX_STRUCT_PAGE_S=
IZE")
> > > > Cc: <stable@vger.kernel.org>
> > > > Cc: Alexander Potapenko <glider@google.com>
> > > > Cc: Marco Elver <elver@google.com>
> > > > Reported-by: Jeff Moyer <jmoyer@redhat.com>
> > > > ---
> > > >  drivers/nvdimm/nd.h       |  2 +-
> > > >  drivers/nvdimm/pfn_devs.c | 45 ++++++++++++++++++++++++++---------=
----
> > > >  2 files changed, 31 insertions(+), 16 deletions(-)
> > > >
> > > > diff --git a/drivers/nvdimm/nd.h b/drivers/nvdimm/nd.h
> > > > index 85ca5b4da3cf..ec5219680092 100644
> > > > --- a/drivers/nvdimm/nd.h
> > > > +++ b/drivers/nvdimm/nd.h
> > > > @@ -652,7 +652,7 @@ void devm_namespace_disable(struct device *dev,
> > > >             struct nd_namespace_common *ndns);
> > > >  #if IS_ENABLED(CONFIG_ND_CLAIM)
> > > >  /* max struct page size independent of kernel config */
> > > > -#define MAX_STRUCT_PAGE_SIZE 128
> > > > +#define MAX_STRUCT_PAGE_SIZE 64
> > > >  int nvdimm_setup_pfn(struct nd_pfn *nd_pfn, struct dev_pagemap *pg=
map);
> > > >  #else
> > > >  static inline int nvdimm_setup_pfn(struct nd_pfn *nd_pfn,
> > > > diff --git a/drivers/nvdimm/pfn_devs.c b/drivers/nvdimm/pfn_devs.c
> > > > index 61af072ac98f..978d63559c0e 100644
> > > > --- a/drivers/nvdimm/pfn_devs.c
> > > > +++ b/drivers/nvdimm/pfn_devs.c
> > > > @@ -13,6 +13,11 @@
> > > >  #include "pfn.h"
> > > >  #include "nd.h"
> > > >
> > > > +static bool page_struct_override;
> > > > +module_param(page_struct_override, bool, 0644);
> > > > +MODULE_PARM_DESC(page_struct_override,
> > > > +            "Force namespace creation in the presence of mm-debug.=
");
> > >
> > > I can't figure out from this description what this is for so perhaps =
it
> > > should be either removed and made dynamic (if you know you want to de=
bug
> > > the mm core, why not turn it on then?) or made more obvious what is
> > > happening?
> >
> > I'll kill it and update the KMSAN Documentation that KMSAN has
> > interactions with the NVDIMM subsystem that may cause some namespaces t=
o
> > fail to enable. That Documentation needs to be a part of this patch
> > regardless as that would be the default behavior of this module
> > parameter.
> >
> > Unfortunately, it can not be dynamically enabled because the size of
> > 'struct page' is unfortunately recorded in the metadata of the device.
> > Recall this is for supporting platform configurations where the capacit=
y
> > of the persistent memory exceeds or consumes too much of System RAM.
> > Consider 4TB of PMEM consumes 64GB of space just for 'struct page'. So,
> > NVDIMM subsystem has a mode to store that page array in a reservation o=
n
> > the PMEM device itself.
>
> Sorry, I might be missing something, but why cannot we have
>
> #ifdef CONFIG_KMSAN
> #define MAX_STRUCT_PAGE_SIZE 128
> #else
> #define MAX_STRUCT_PAGE_SIZE 64
> #endif
>

Possibly because this needs to be a fixed size on permanent storage
(like an inode on a disk file system)



> ?
>
> KMSAN is a debug-only tool, it already consumes more than two thirds
> of the system memory, so you don't want to enable it in any production
> environment anyway.
>
> > KMSAN mandates either that all namespaces all the time reserve the extr=
a
> > capacity, or that those namespace cannot be mapped while KMSAN is
> > enabled.
>
> Struct page depends on a couple of config options that affect its
> size, and has already been approaching the 64 byte boundary.
> It is unfortunate that the introduction of KMSAN was the last straw,
> but it could've been any other debug config that needs to store data
> in the struct page.
> Keeping the struct within cacheline size sounds reasonable for the
> default configuration, but having a build-time assert that prevents us
> from building debug configs sounds excessive.
>
> > --
> > You received this message because you are subscribed to the Google Grou=
ps "kasan-dev" group.
> > To unsubscribe from this group and stop receiving emails from it, send =
an email to kasan-dev+unsubscribe@googlegroups.com.
> > To view this discussion on the web visit https://groups.google.com/d/ms=
gid/kasan-dev/63bd0be8945a0_5178e29414%40dwillia2-xfh.jf.intel.com.notmuch.
>
>
>
> --
> Alexander Potapenko
> Software Engineer
>
> Google Germany GmbH
> Erika-Mann-Stra=C3=9Fe, 33
> 80636 M=C3=BCnchen
>
> Gesch=C3=A4ftsf=C3=BChrer: Paul Manicle, Liana Sebastian
> Registergericht und -nummer: Hamburg, HRB 86891
> Sitz der Gesellschaft: Hamburg

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CANn89iJRXSb-xK_VxkHqm8NLGhfH1Q_HW_p%3DygAH7QocyVh%2BDQ%40mail.gm=
ail.com.
