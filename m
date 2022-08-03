Return-Path: <kasan-dev+bncBCCMH5WKTMGRBF4HVGLQMGQEH2EBM5Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33a.google.com (mail-ot1-x33a.google.com [IPv6:2607:f8b0:4864:20::33a])
	by mail.lfdr.de (Postfix) with ESMTPS id E35FD588996
	for <lists+kasan-dev@lfdr.de>; Wed,  3 Aug 2022 11:44:56 +0200 (CEST)
Received: by mail-ot1-x33a.google.com with SMTP id w89-20020a9d3662000000b0061d33226869sf6179325otb.21
        for <lists+kasan-dev@lfdr.de>; Wed, 03 Aug 2022 02:44:56 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1659519895; cv=pass;
        d=google.com; s=arc-20160816;
        b=h4oNQeQvtMXvJDSeKEwZKEUN4rR3RKO36POJaJhljdovCq+19G/24Md+assd30/wk4
         U4a19tQnLd4XIb1hraDAg0YDMFhu8A9EEdj4pq3MjKRwkqsrmfMWaHvsxNxhywA3Naub
         CUq0S5mK4BBEDPMS2VTF3n938Dc6uwSknKLg9om6Qq34MHqWKFkceUoUmjVcy9lXSzOH
         VV+g6iwKAafQUB1XyVJPMUk3OtVXbwl5eoaQ9BE5L6JgFXjuoF/dHH5EhmGPTpLq3+Q6
         cmURDPxTvO7OROyfAY99eHpwryLMwUdsS7BlBftrak9O77NCIs/Ht+EC2m2j1+//wq8s
         4/yA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=HBMWYeacCrh/OJKa/u18v5vxCWuMay5GwCAp6s3Dm4Y=;
        b=yBtO/H5oxagUTbO4BiBQxlqgR0nVnn5yHaDTCoxFHK3Rb5HiRZmqXoptP92nrRSTXq
         EQKGIC7f2po5SR6hMdNf2LQQxNOeFZ469sS8wmkCwhDUUNuDlKFmP6JRbuxtQY+yZ0c/
         wmLppZUh9misrn3ZATctsNCVqyN/1wPzGey/IPR0QV3MYrpnJ/KKRQoMHsX/eRzcXaQ8
         53Y8UKQJ6XNkg3trTDW91gGfFMxd2z0kQ3l4o7/iVLObkVWYzBsRBmokhpegHagUhvmr
         ARt1aaNGv6O+KAKOd5vW10Ih/Cuiddw+iv7sBFrnTRYEVOupa9Iq7zVyvXKtyOu0qSPm
         GFDg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=FPrKKTFm;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::1135 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=HBMWYeacCrh/OJKa/u18v5vxCWuMay5GwCAp6s3Dm4Y=;
        b=ZA8UuxQkuJF5PjswTzry9OZQllTSzs2+e8Y6KP/z37PwtZbqGKT1gwXgJ4jTHVAkDW
         gQWItHyvVf1oUzLOzbguXEuSmKWFwbonArYQbDTyjzJByBX58SNh7jANsxd6Q47iT2Tc
         SgJFfT7KEW2vsO/CQuYi7h8eS4YQDu6qLUg6uOCybJuWrc1lFXH5aZLYz5fNa5XQIo0P
         hc1d3emjhVQ6bRYcskT/pd4p6zv37N4+LrgYBYEHsUQQRhg8X+Ywu7N1kMQPZUJXrQH2
         h0tFsUrX8s0aQoaE8eaxPg09klstwMsUoU7yHVrXIH2oXZ94ZLi0h52krkEAMteO7JD3
         nXug==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=HBMWYeacCrh/OJKa/u18v5vxCWuMay5GwCAp6s3Dm4Y=;
        b=cx00Ykbb73Tle4cPEZpzOslc0BT5VhFaP9+cKN0qCsnHdEC0rz6J9d1WhsOfA8wNL1
         8hrdrZMFS0f7r9L0axQINLFXV35+zKMrLl9hCq6sBDp4pwHkSHTE9hRlCtrt8BGWP82j
         uuwwhzDUbW7x2UOPyNdrRiy249ILAXSzy6ldtv2+q5E0efcg/Gg7cu0pROyd91htO47q
         rkude1qJhN3jvXHhwelUxX1CYJGP5Cl8/qvY7aO6q8LVFXuiNIdZyNCVLD7vs1GmPl3I
         nqW7yw2YoppVlApZOpfkWYa8GkcWH4Nl/bbLbBkttld7c/bGTJCENxHplzDMZUnER9q9
         YZZw==
X-Gm-Message-State: ACgBeo3NIQBgkuFJzvln93HUvYCRHu6Qe6PpjlRZEfCp+lJmmlumqa2w
	g+wZMnlNZvwOR171Um0eBiI=
X-Google-Smtp-Source: AA6agR5+qup574opH1PQBg7K8UA6c29K9inLQNHY3x+NytIvYQ+9nq2XvljBpd+ONf6on7IJJoCrKg==
X-Received: by 2002:a05:6870:344c:b0:10c:236a:79f8 with SMTP id i12-20020a056870344c00b0010c236a79f8mr1615002oah.24.1659519895772;
        Wed, 03 Aug 2022 02:44:55 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6808:1992:b0:342:6547:bf34 with SMTP id
 bj18-20020a056808199200b003426547bf34ls1133212oib.2.-pod-prod-gmail; Wed, 03
 Aug 2022 02:44:55 -0700 (PDT)
X-Received: by 2002:a05:6808:f8e:b0:33b:2156:e741 with SMTP id o14-20020a0568080f8e00b0033b2156e741mr1290302oiw.256.1659519895208;
        Wed, 03 Aug 2022 02:44:55 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1659519895; cv=none;
        d=google.com; s=arc-20160816;
        b=q8wIs2KP7d1Hd4IQHhg61lLG4rtCms3+3HCwi2NsACK0Tfw+vD09Vku9WAz0BmQdc1
         RzRhliEz29Qq4YIY94gjAMhcuTUcOowo/cun5lm88Z8HWWOZIZX/fq6KJKaVpPZmo1WJ
         Gu5dqvNjrO2DeZ32Yi8Rf6GUigcJQNFN24hpzlBzqw7cOnFtfRxkXQFw9QWFj7WEIv2E
         fQLyXQZjJlsiyhKhr9uEib1zF6CMriO98R1q6LBefRy/ryiSS3jxrKxqStuNONw/qb9u
         /3CJHvPrxwJjxR1iNcMyFEsHeNOvEC7xYSQXsevutBQeF6XK7zUWxR1bv23Kh98Q+QXu
         IGcg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=Y5TvyICc8d9t41nnsu7puTvMuWTSp2+6bN2hR6XdoD8=;
        b=oKze5dQ0CuhidrSBzZQE32qFn9qtesmnCk5KEKXe+zuAoGtf9HPsiEKkytsWhIb7gi
         DfN3/6Snw6u5QLV8612PdTcrFXJTUc3H/TKGj2iTYYcP5/xYVSFfCYG71aUPc5JjOMJw
         Nd9CuBVbs32aeymnK6KX8u23+RGNo/WaPzHESVm04yCChSw0+7GrT3GyD8f4GLzROG6D
         AWjqjo/1LxLwleNPZbb/4IOk2fqSwYDhuPKEqKexk28lXd48k9ZkryML150rqwu0My5O
         3hpQ7egz2IvxRES6HcmUIx/hKyFH7RbaH426Ipo8oXf37T815SYBCPGmEWG2jrTc9TvR
         8oKg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=FPrKKTFm;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::1135 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x1135.google.com (mail-yw1-x1135.google.com. [2607:f8b0:4864:20::1135])
        by gmr-mx.google.com with ESMTPS id u16-20020a0568301f5000b0061c81be91e8si842316oth.4.2022.08.03.02.44.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 03 Aug 2022 02:44:55 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::1135 as permitted sender) client-ip=2607:f8b0:4864:20::1135;
Received: by mail-yw1-x1135.google.com with SMTP id 00721157ae682-32194238c77so165879257b3.4
        for <kasan-dev@googlegroups.com>; Wed, 03 Aug 2022 02:44:55 -0700 (PDT)
X-Received: by 2002:a0d:d40d:0:b0:322:d4c0:c6f6 with SMTP id
 w13-20020a0dd40d000000b00322d4c0c6f6mr23100302ywd.428.1659519894650; Wed, 03
 Aug 2022 02:44:54 -0700 (PDT)
MIME-Version: 1.0
References: <20220701142310.2188015-1-glider@google.com> <20220701142310.2188015-11-glider@google.com>
 <CANpmjNOYqXSw5+Sxt0+=oOUQ1iQKVtEYHv20=sh_9nywxXUyWw@mail.gmail.com>
In-Reply-To: <CANpmjNOYqXSw5+Sxt0+=oOUQ1iQKVtEYHv20=sh_9nywxXUyWw@mail.gmail.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 3 Aug 2022 11:44:18 +0200
Message-ID: <CAG_fn=W2EUjS8AX1Odunq1==dV178s_-w3hQpyrFBr=Auo-Q-A@mail.gmail.com>
Subject: Re: [PATCH v4 10/45] libnvdimm/pfn_dev: increase MAX_STRUCT_PAGE_SIZE
To: Marco Elver <elver@google.com>, Dan Williams <dan.j.williams@intel.com>
Cc: Alexander Viro <viro@zeniv.linux.org.uk>, Alexei Starovoitov <ast@kernel.org>, 
	Andrew Morton <akpm@linux-foundation.org>, Andrey Konovalov <andreyknvl@google.com>, 
	Andy Lutomirski <luto@kernel.org>, Arnd Bergmann <arnd@arndb.de>, Borislav Petkov <bp@alien8.de>, 
	Christoph Hellwig <hch@lst.de>, Christoph Lameter <cl@linux.com>, David Rientjes <rientjes@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Eric Dumazet <edumazet@google.com>, 
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>, Herbert Xu <herbert@gondor.apana.org.au>, 
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
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=FPrKKTFm;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::1135
 as permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

(+ Dan Williams)
(resending with patch context included)

On Mon, Jul 11, 2022 at 6:27 PM Marco Elver <elver@google.com> wrote:
>
> On Fri, 1 Jul 2022 at 16:23, Alexander Potapenko <glider@google.com> wrot=
e:
> >
> > KMSAN adds extra metadata fields to struct page, so it does not fit int=
o
> > 64 bytes anymore.
>
> Does this somehow cause extra space being used in all kernel configs?
> If not, it would be good to note this in the commit message.
>
I actually couldn't verify this on QEMU, because the driver never got loade=
d.
Looks like this increases the amount of memory used by the nvdimm
driver in all kernel configs that enable it (including those that
don't use KMSAN), but I am not sure how much is that.

Dan, do you know how bad increasing MAX_STRUCT_PAGE_SIZE can be?

>
> > Signed-off-by: Alexander Potapenko <glider@google.com>
>
> Reviewed-by: Marco Elver <elver@google.com>
>
> > ---
> > Link: https://linux-review.googlesource.com/id/I353796acc6a850bfd7bb342=
aa1b63e616fc614f1
> > ---
> >  drivers/nvdimm/nd.h       | 2 +-
> >  drivers/nvdimm/pfn_devs.c | 2 +-
> >  2 files changed, 2 insertions(+), 2 deletions(-)
> >
> > diff --git a/drivers/nvdimm/nd.h b/drivers/nvdimm/nd.h
> > index ec5219680092d..85ca5b4da3cf3 100644
> > --- a/drivers/nvdimm/nd.h
> > +++ b/drivers/nvdimm/nd.h
> > @@ -652,7 +652,7 @@ void devm_namespace_disable(struct device *dev,
> >                 struct nd_namespace_common *ndns);
> >  #if IS_ENABLED(CONFIG_ND_CLAIM)
> >  /* max struct page size independent of kernel config */
> > -#define MAX_STRUCT_PAGE_SIZE 64
> > +#define MAX_STRUCT_PAGE_SIZE 128
> >  int nvdimm_setup_pfn(struct nd_pfn *nd_pfn, struct dev_pagemap *pgmap)=
;
> >  #else
> >  static inline int nvdimm_setup_pfn(struct nd_pfn *nd_pfn,
> > diff --git a/drivers/nvdimm/pfn_devs.c b/drivers/nvdimm/pfn_devs.c
> > index 0e92ab4b32833..61af072ac98f9 100644
> > --- a/drivers/nvdimm/pfn_devs.c
> > +++ b/drivers/nvdimm/pfn_devs.c
> > @@ -787,7 +787,7 @@ static int nd_pfn_init(struct nd_pfn *nd_pfn)
> >                  * when populating the vmemmap. This *should* be equal =
to
> >                  * PMD_SIZE for most architectures.
> >                  *
> > -                * Also make sure size of struct page is less than 64. =
We
> > +                * Also make sure size of struct page is less than 128.=
 We
> >                  * want to make sure we use large enough size here so t=
hat
> >                  * we don't have a dynamic reserve space depending on
> >                  * struct page size. But we also want to make sure we n=
otice
> > --
> > 2.37.0.rc0.161.g10f37bed90-goog
> >



--=20
Alexander Potapenko
Software Engineer

Google Germany GmbH
Erika-Mann-Stra=C3=9Fe, 33
80636 M=C3=BCnchen

Gesch=C3=A4ftsf=C3=BChrer: Paul Manicle, Liana Sebastian
Registergericht und -nummer: Hamburg, HRB 86891
Sitz der Gesellschaft: Hamburg

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG_fn%3DW2EUjS8AX1Odunq1%3D%3DdV178s_-w3hQpyrFBr%3DAuo-Q-A%40mai=
l.gmail.com.
