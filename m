Return-Path: <kasan-dev+bncBDEK37P2TEBRBBNOYKWQMGQEJHQERNA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63f.google.com (mail-pl1-x63f.google.com [IPv6:2607:f8b0:4864:20::63f])
	by mail.lfdr.de (Postfix) with ESMTPS id 8B62D83A0BA
	for <lists+kasan-dev@lfdr.de>; Wed, 24 Jan 2024 05:50:15 +0100 (CET)
Received: by mail-pl1-x63f.google.com with SMTP id d9443c01a7336-1d75dbaa9fdsf432295ad.1
        for <lists+kasan-dev@lfdr.de>; Tue, 23 Jan 2024 20:50:15 -0800 (PST)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1706071814; x=1706676614; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-sender:mime-version
         :subject:references:in-reply-to:message-id:to:from:date:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=zOc5zeN8rlTELc+e9R+04kpk99UaNMgEUFaCQWaMaGM=;
        b=Q+4h9DgP4IGLGAojXOmN3YlsHSAktHSkvmohMSItnXQ8wp0oMvYkij5GthAvo6rpbN
         acX1Wk0DKT09I8LdZRIZYFJHj7gIiBh50KdnNcaM0KvFyqRyy5fMuMA0ziRvxWW3UB/V
         NfwcfZSIelZLAIWmGDpkuL+QdHhI0GXB1OBCLowChOUD1BG+A9yKvKv5rQg0svRNUovO
         pzroYoW4BF+b1MF/KMEycmiv0AzU3/Y3HmlTUFWyffn9btxC+tvzmK5kzpP2mPD8VS9R
         LUJwObzhr7IQnClg7JLiNOY9Qpj+CCuOzL7n6kS1Eu+vaIHDkRE3hkiWww//3xOlK0vf
         4Ixw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1706071814; x=1706676614; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-sender:mime-version
         :subject:references:in-reply-to:message-id:to:from:date:from:to:cc
         :subject:date:message-id:reply-to;
        bh=zOc5zeN8rlTELc+e9R+04kpk99UaNMgEUFaCQWaMaGM=;
        b=FCIn+sq+I64zHNAOUu43AFRMUDCSJCdbNQVAtI1tvNubWU94qPzCROaU2H+UWn96I5
         5qlQE5ieNeNEOoWrY4hCgyybT4AOcyb0N2/s8A3vlCIMZqeOY01+RbAve6czeAPUEmVX
         tCR+Rr4OsOBQilcWAUsjc7ZIH9ehqkSgCw79ave1M/alIeG4GgwMYcwFiDR6GJ7OGoOw
         d3V6NrMMNQzfUgeRP9HxyjJ7Eka+uRa2DubcP12ANakjKSomuSNTRT1vQJqwiE0TBevT
         f5Gv0lbQgR5bNQs1AhoiQaYz8U6Napgi38mA3Wd52SU1fznFm85aLPkOVXqfUvDnoZ10
         5K2A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1706071814; x=1706676614;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-sender:mime-version:subject:references:in-reply-to
         :message-id:to:from:date:x-beenthere:x-gm-message-state:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=zOc5zeN8rlTELc+e9R+04kpk99UaNMgEUFaCQWaMaGM=;
        b=CV3T4G3aNiM97N3JQKM+DbJr9N2UKD50HcybCm3xZjlZfZNKVg3NyMwbAM92UUsw3O
         +P8rHcKTMIUBVmNSCoK4s2rXSPFIoVmFopli8BR6P8EuCEij+6uatzuQeshSNpBkXE6L
         F0USp+RVwQmAV+4TRL12ocih83vI4vegl7V2iAReIInvPuxHzEv4LoCs74zW49Q1Mz8x
         nIiuYi9cQpsi/W9XgrgWpzC2Hbqfr6qOv8Zl7lZUv0wYGjU7I3o9wzB3ptLZ4Uj2tS3W
         949z5wEK1gizE5C2l+8QMkTwaz9uvt/Vrtz9VhdKVkSi4LWaCQS1MeI2mFiugzSV1Yzj
         DMZQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YwnzlHhaRA9q5f2nDkU2pmWC2kzQ1Gmr/ZeWiInDeIHmS/XN6qv
	c4Bw4bQtMq6jj45qMPnixLOpCAdHnbNe5Em3DLtTZsDd7TRYOjgg
X-Google-Smtp-Source: AGHT+IEg5yqKlY8Z6gJNAKxGVyQ3HxgwbQOr58EWbf9u2XjPnqVC2CTH0gfCvuWhRjYblyAMvny3AA==
X-Received: by 2002:a17:902:d185:b0:1d7:7a5a:61ab with SMTP id m5-20020a170902d18500b001d77a5a61abmr26651plb.3.1706071813776;
        Tue, 23 Jan 2024 20:50:13 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:8c61:0:b0:599:25d8:29af with SMTP id v30-20020a4a8c61000000b0059925d829afls3178152ooj.2.-pod-prod-09-us;
 Tue, 23 Jan 2024 20:50:13 -0800 (PST)
X-Received: by 2002:a05:6820:1c97:b0:599:c441:446b with SMTP id ct23-20020a0568201c9700b00599c441446bmr22929oob.1.1706071812915;
        Tue, 23 Jan 2024 20:50:12 -0800 (PST)
Date: Tue, 23 Jan 2024 20:50:12 -0800 (PST)
From: Reusable Scraps <reusablescraps@gmail.com>
To: kasan-dev <kasan-dev@googlegroups.com>
Message-Id: <a9639593-c438-4cdb-b571-dfb0d2008aacn@googlegroups.com>
In-Reply-To: <CANpmjNOaeKRZKtJusQu9Ag2=ifwPS+L9-ZGL77dRzDFPGu_DOQ@mail.gmail.com>
References: <cover.1703024586.git.andreyknvl@google.com>
 <CANpmjNOaeKRZKtJusQu9Ag2=ifwPS+L9-ZGL77dRzDFPGu_DOQ@mail.gmail.com>
Subject: Re: [PATCH mm 00/21] kasan: save mempool stack traces
MIME-Version: 1.0
Content-Type: multipart/mixed; 
	boundary="----=_Part_38242_161557240.1706071812321"
X-Original-Sender: reusablescraps@gmail.com
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

------=_Part_38242_161557240.1706071812321
Content-Type: multipart/alternative; 
	boundary="----=_Part_38243_2066470211.1706071812321"

------=_Part_38243_2066470211.1706071812321
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

Buy Hayward Pod Kit AXV417WHP Navigator and Pool Vac White
 https://reusablescraps.com/product/buy-hayward-pod-kit/

Features

WARNING: The following product(s) can expose you to chemicals which are=20
known to the State of California to cause cancer and birth defects or other=
=20
reproductive harm. For more information go to=20
https://reusablescraps.com/product/buy-trek-container-pools/
https://reusablescraps.com/product/buy-hayward-pod-kit/
Hayward AXV417WHP White Pod Kit
https://t.me/RecoveredLostFunds
Hayward Pod Kit AXV417WHP Navigator and Pool Vac Factory replacement parts=
=20
from Hayward. (Wings not included).

https://reusablescraps.com/product/buy-trek-container-pools/
https://reusablescraps.com/product/buy-hayward-pod-kit/

At Hayward=C2=AE, we=E2=80=99re more than just equipment. Our objective is =
to make your=20
pool experience worry and hassle-free. That=E2=80=99s why our equipment is=
=20
engineered to last and work smart at keeping your pool sparkling clean and=
=20
trouble-free. For over 80-years, we=E2=80=99ve been helping pool owners enj=
oy the=20
pleasures of pool ownership by manufacturing cutting-edge, technologically=
=20
advanced pool equipment worldwide. We strive to ensure that your Totally=20
Hayward=E2=84=A2 System operates at maximum efficiency all season long. Whe=
ther you=20
are trying to create the perfect backyard environment, reduce operating and=
=20
maintenance costs through the ease of wireless controls, Hayward is your=20
single source solution. Our products include a complete line of=20
technologically advanced pumps, filters, heaters, heat pumps, automatic=20
pool cleaners, lighting, controls, and salt chlorine=20
generators=E2=80=94high-quality components engineered to work together to k=
eep your=20
pool at its best. Hayward aims to take the worry out of pool ownership by=
=20
developing products that are efficient, require little maintenance, and add=
=20
value to your investment. For more than 40 years Hayward Flow Control has=
=20
remained committed to producing the highest quality products while=20
providing outstanding service that exceeds customer expectations. Hayward=
=20
has earned an unsurpassed reputation for product design, manufacturing=20
precision, quality assurance, experience and know-how, and a total=20
commitment to customer satisfaction and support. For more than 40 years=20
Hayward Flow Control has remained committed to producing the highest=20
quality products while providing outstanding service that exceeds customer=
=20
expectations. Hayward has earned an unsurpassed reputation for product=20
design, manufacturing precision, quality assurance, experience and=20
know-how, and a total commitment to customer satisfaction and support.

 https://reusablescraps.com/product/buy-trek-container-pools/

https://reusablescraps.com/product/buy-hayward-pod-kit/

https://t.me/RecoveredLostFunds

On Tuesday, January 2, 2024 at 1:54:47=E2=80=AFPM UTC+1 Marco Elver wrote:

> On Tue, 19 Dec 2023 at 23:29, <andrey.k...@linux.dev> wrote:
> >
> > From: Andrey Konovalov <andre...@google.com>
> >
> > This series updates KASAN to save alloc and free stack traces for
> > secondary-level allocators that cache and reuse allocations internally
> > instead of giving them back to the underlying allocator (e.g. mempool).
> >
> > As a part of this change, introduce and document a set of KASAN hooks:
> >
> > bool kasan_mempool_poison_pages(struct page *page, unsigned int order);
> > void kasan_mempool_unpoison_pages(struct page *page, unsigned int order=
);
> > bool kasan_mempool_poison_object(void *ptr);
> > void kasan_mempool_unpoison_object(void *ptr, size_t size);
> >
> > and use them in the mempool code.
> >
> > Besides mempool, skbuff and io_uring also cache allocations and already
> > use KASAN hooks to poison those. Their code is updated to use the new
> > mempool hooks.
> >
> > The new hooks save alloc and free stack traces (for normal kmalloc and
> > slab objects; stack traces for large kmalloc objects and page_alloc are
> > not supported by KASAN yet), improve the readability of the users' code=
,
> > and also allow the users to prevent double-free and invalid-free bugs;
> > see the patches for the details.
> >
> > There doesn't appear to be any conflicts with the KASAN patches that ar=
e
> > currently in mm, but I rebased the patchset on top just in case.
> >
> > Changes RFC->v1:
> > - New patch "mempool: skip slub_debug poisoning when KASAN is enabled".
> > - Replace mempool_use_prealloc_only API with mempool_alloc_preallocated=
.
> > - Avoid triggering slub_debug-detected corruptions in mempool tests.
> >
> > Andrey Konovalov (21):
> > kasan: rename kasan_slab_free_mempool to kasan_mempool_poison_object
> > kasan: move kasan_mempool_poison_object
> > kasan: document kasan_mempool_poison_object
> > kasan: add return value for kasan_mempool_poison_object
> > kasan: introduce kasan_mempool_unpoison_object
> > kasan: introduce kasan_mempool_poison_pages
> > kasan: introduce kasan_mempool_unpoison_pages
> > kasan: clean up __kasan_mempool_poison_object
> > kasan: save free stack traces for slab mempools
> > kasan: clean up and rename ____kasan_kmalloc
> > kasan: introduce poison_kmalloc_large_redzone
> > kasan: save alloc stack traces for mempool
> > mempool: skip slub_debug poisoning when KASAN is enabled
> > mempool: use new mempool KASAN hooks
> > mempool: introduce mempool_use_prealloc_only
> > kasan: add mempool tests
> > kasan: rename pagealloc tests
> > kasan: reorder tests
> > kasan: rename and document kasan_(un)poison_object_data
> > skbuff: use mempool KASAN hooks
> > io_uring: use mempool KASAN hook
> >
> > include/linux/kasan.h | 161 +++++++-
> > include/linux/mempool.h | 1 +
> > io_uring/alloc_cache.h | 5 +-
> > mm/kasan/common.c | 221 ++++++----
> > mm/kasan/kasan_test.c | 870 +++++++++++++++++++++++++++-------------
> > mm/mempool.c | 67 +++-
> > mm/slab.c | 10 +-
> > mm/slub.c | 4 +-
> > net/core/skbuff.c | 10 +-
> > 9 files changed, 954 insertions(+), 395 deletions(-)
>
> Acked-by: Marco Elver <el...@google.com>
>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/a9639593-c438-4cdb-b571-dfb0d2008aacn%40googlegroups.com.

------=_Part_38243_2066470211.1706071812321
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

Buy Hayward Pod Kit AXV417WHP Navigator and Pool Vac White<br />=C2=A0https=
://reusablescraps.com/product/buy-hayward-pod-kit/<br /><br />Features<br /=
><br />WARNING: The following product(s) can expose you to chemicals which =
are known to the State of California to cause cancer and birth defects or o=
ther reproductive harm. For more information go to https://reusablescraps.c=
om/product/buy-trek-container-pools/<br />https://reusablescraps.com/produc=
t/buy-hayward-pod-kit/<br />Hayward AXV417WHP White Pod Kit<br />https://t.=
me/RecoveredLostFunds<br />Hayward Pod Kit AXV417WHP Navigator and Pool Vac=
 Factory replacement parts from Hayward. (Wings not included).<br /><br />h=
ttps://reusablescraps.com/product/buy-trek-container-pools/<br />https://re=
usablescraps.com/product/buy-hayward-pod-kit/<br /><br />At Hayward=C2=AE, =
we=E2=80=99re more than just equipment. Our objective is to make your pool =
experience worry and hassle-free. That=E2=80=99s why our equipment is engin=
eered to last and work smart at keeping your pool sparkling clean and troub=
le-free. For over 80-years, we=E2=80=99ve been helping pool owners enjoy th=
e pleasures of pool ownership by manufacturing cutting-edge, technologicall=
y advanced pool equipment worldwide. We strive to ensure that your Totally =
Hayward=E2=84=A2 System operates at maximum efficiency all season long. Whe=
ther you are trying to create the perfect backyard environment, reduce oper=
ating and maintenance costs through the ease of wireless controls, Hayward =
is your single source solution. Our products include a complete line of tec=
hnologically advanced pumps, filters, heaters, heat pumps, automatic pool c=
leaners, lighting, controls, and salt chlorine generators=E2=80=94high-qual=
ity components engineered to work together to keep your pool at its best. H=
ayward aims to take the worry out of pool ownership by developing products =
that are efficient, require little maintenance, and add value to your inves=
tment. For more than 40 years Hayward Flow Control has remained committed t=
o producing the highest quality products while providing outstanding servic=
e that exceeds customer expectations. Hayward has earned an unsurpassed rep=
utation for product design, manufacturing precision, quality assurance, exp=
erience and know-how, and a total commitment to customer satisfaction and s=
upport. For more than 40 years Hayward Flow Control has remained committed =
to producing the highest quality products while providing outstanding servi=
ce that exceeds customer expectations. Hayward has earned an unsurpassed re=
putation for product design, manufacturing precision, quality assurance, ex=
perience and know-how, and a total commitment to customer satisfaction and =
support.<br /><br />=C2=A0https://reusablescraps.com/product/buy-trek-conta=
iner-pools/<br /><br />https://reusablescraps.com/product/buy-hayward-pod-k=
it/<br /><br />https://t.me/RecoveredLostFunds<br /><br /><div class=3D"gma=
il_quote"><div dir=3D"auto" class=3D"gmail_attr">On Tuesday, January 2, 202=
4 at 1:54:47=E2=80=AFPM UTC+1 Marco Elver wrote:<br/></div><blockquote clas=
s=3D"gmail_quote" style=3D"margin: 0 0 0 0.8ex; border-left: 1px solid rgb(=
204, 204, 204); padding-left: 1ex;">On Tue, 19 Dec 2023 at 23:29, &lt;<a hr=
ef data-email-masked rel=3D"nofollow">andrey.k...@linux.dev</a>&gt; wrote:
<br>&gt;
<br>&gt; From: Andrey Konovalov &lt;<a href data-email-masked rel=3D"nofoll=
ow">andre...@google.com</a>&gt;
<br>&gt;
<br>&gt; This series updates KASAN to save alloc and free stack traces for
<br>&gt; secondary-level allocators that cache and reuse allocations intern=
ally
<br>&gt; instead of giving them back to the underlying allocator (e.g. memp=
ool).
<br>&gt;
<br>&gt; As a part of this change, introduce and document a set of KASAN ho=
oks:
<br>&gt;
<br>&gt; bool kasan_mempool_poison_pages(struct page *page, unsigned int or=
der);
<br>&gt; void kasan_mempool_unpoison_pages(struct page *page, unsigned int =
order);
<br>&gt; bool kasan_mempool_poison_object(void *ptr);
<br>&gt; void kasan_mempool_unpoison_object(void *ptr, size_t size);
<br>&gt;
<br>&gt; and use them in the mempool code.
<br>&gt;
<br>&gt; Besides mempool, skbuff and io_uring also cache allocations and al=
ready
<br>&gt; use KASAN hooks to poison those. Their code is updated to use the =
new
<br>&gt; mempool hooks.
<br>&gt;
<br>&gt; The new hooks save alloc and free stack traces (for normal kmalloc=
 and
<br>&gt; slab objects; stack traces for large kmalloc objects and page_allo=
c are
<br>&gt; not supported by KASAN yet), improve the readability of the users&=
#39; code,
<br>&gt; and also allow the users to prevent double-free and invalid-free b=
ugs;
<br>&gt; see the patches for the details.
<br>&gt;
<br>&gt; There doesn&#39;t appear to be any conflicts with the KASAN patche=
s that are
<br>&gt; currently in mm, but I rebased the patchset on top just in case.
<br>&gt;
<br>&gt; Changes RFC-&gt;v1:
<br>&gt; - New patch &quot;mempool: skip slub_debug poisoning when KASAN is=
 enabled&quot;.
<br>&gt; - Replace mempool_use_prealloc_only API with mempool_alloc_preallo=
cated.
<br>&gt; - Avoid triggering slub_debug-detected corruptions in mempool test=
s.
<br>&gt;
<br>&gt; Andrey Konovalov (21):
<br>&gt;   kasan: rename kasan_slab_free_mempool to kasan_mempool_poison_ob=
ject
<br>&gt;   kasan: move kasan_mempool_poison_object
<br>&gt;   kasan: document kasan_mempool_poison_object
<br>&gt;   kasan: add return value for kasan_mempool_poison_object
<br>&gt;   kasan: introduce kasan_mempool_unpoison_object
<br>&gt;   kasan: introduce kasan_mempool_poison_pages
<br>&gt;   kasan: introduce kasan_mempool_unpoison_pages
<br>&gt;   kasan: clean up __kasan_mempool_poison_object
<br>&gt;   kasan: save free stack traces for slab mempools
<br>&gt;   kasan: clean up and rename ____kasan_kmalloc
<br>&gt;   kasan: introduce poison_kmalloc_large_redzone
<br>&gt;   kasan: save alloc stack traces for mempool
<br>&gt;   mempool: skip slub_debug poisoning when KASAN is enabled
<br>&gt;   mempool: use new mempool KASAN hooks
<br>&gt;   mempool: introduce mempool_use_prealloc_only
<br>&gt;   kasan: add mempool tests
<br>&gt;   kasan: rename pagealloc tests
<br>&gt;   kasan: reorder tests
<br>&gt;   kasan: rename and document kasan_(un)poison_object_data
<br>&gt;   skbuff: use mempool KASAN hooks
<br>&gt;   io_uring: use mempool KASAN hook
<br>&gt;
<br>&gt;  include/linux/kasan.h   | 161 +++++++-
<br>&gt;  include/linux/mempool.h |   1 +
<br>&gt;  io_uring/alloc_cache.h  |   5 +-
<br>&gt;  mm/kasan/common.c       | 221 ++++++----
<br>&gt;  mm/kasan/kasan_test.c   | 870 +++++++++++++++++++++++++++--------=
-----
<br>&gt;  mm/mempool.c            |  67 +++-
<br>&gt;  mm/slab.c               |  10 +-
<br>&gt;  mm/slub.c               |   4 +-
<br>&gt;  net/core/skbuff.c       |  10 +-
<br>&gt;  9 files changed, 954 insertions(+), 395 deletions(-)
<br>
<br>Acked-by: Marco Elver &lt;<a href data-email-masked rel=3D"nofollow">el=
...@google.com</a>&gt;
<br></blockquote></div>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion on the web visit <a href=3D"https://groups.google.c=
om/d/msgid/kasan-dev/a9639593-c438-4cdb-b571-dfb0d2008aacn%40googlegroups.c=
om?utm_medium=3Demail&utm_source=3Dfooter">https://groups.google.com/d/msgi=
d/kasan-dev/a9639593-c438-4cdb-b571-dfb0d2008aacn%40googlegroups.com</a>.<b=
r />

------=_Part_38243_2066470211.1706071812321--

------=_Part_38242_161557240.1706071812321--
