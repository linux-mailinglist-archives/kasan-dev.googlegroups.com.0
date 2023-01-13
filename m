Return-Path: <kasan-dev+bncBCMIZB7QWENRBBFAQSPAMGQEHSKMKFI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x240.google.com (mail-lj1-x240.google.com [IPv6:2a00:1450:4864:20::240])
	by mail.lfdr.de (Postfix) with ESMTPS id DD575668FE7
	for <lists+kasan-dev@lfdr.de>; Fri, 13 Jan 2023 09:02:13 +0100 (CET)
Received: by mail-lj1-x240.google.com with SMTP id by44-20020a05651c1a2c00b0028b68d58538sf88610ljb.11
        for <lists+kasan-dev@lfdr.de>; Fri, 13 Jan 2023 00:02:13 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1673596933; cv=pass;
        d=google.com; s=arc-20160816;
        b=csVntXCeCuS1eGkjjlGQNJXqcDePMNZyEm/WSzL4Fx6iXQF/ZLeONa2n4lAeB2O1T2
         /ywvP9f3xFhn86mIFmKsFVbAFa3YQXvRZVUonxYl+SXwCUtEeNR95nyj0lokxZcJnm2L
         2xYgAXUa6UbtMQMn/hbJ+f1tSC4JIVpqKLZeJig4ibSPGGP6RezwPzl3BrdKGjZukCOE
         /2fpWBbmSr78l3FKB3zRnlCinHtAtFv/b6dcPlCnbNvQwBaJs5Plj45fL4IQVc8k2R8W
         u/b/y7CW+1DoPxsXhmBWaotPS18xXK9tS/uZmyCvgd35AOk96omdjCGSl2KQ3kbcbrCa
         37TQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=HLGnQO8VkBaRgvhEAstngwGhia0AdG7hjcWhKI/56xg=;
        b=HJPtuIUq1Joi4qRkHFc/1q1JVONR1BFTPyS5yD6O9UGD3vOlU29qrjRwrL6iuv2vuO
         zFRZIsn4NwHl2je8NxS1lq4dy/uAkVsnx/+RQsrjd+x7lbkTNUGAafvIDqNsG8kHPlU9
         jwDMeDYdiWUbBKpspcLKqHJUssVAQv7S1B+UpYADhIuTgRakdO5yfnvv7SJ/FzbJvmWG
         +qqyyYJs1l7aLtu3alt5itIp1hVNWJ/o/W/tGqciiXgykV5wbSD0+qrK66q839tT3NWF
         KOVzBSe8e8Qg1L1yPgB++JMoQHpA5BAs+gKzQRr3+lkwN6kE8T2rwgbe4fqO7mKbr+eH
         LJLA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=mqO98eOB;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::134 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=HLGnQO8VkBaRgvhEAstngwGhia0AdG7hjcWhKI/56xg=;
        b=kXt8ini7J4Rb2QqtRovm6hBrBduShJ6OvTnPvKoFmdhpTyitbw3W2iZ8XwLoGJmenG
         uFbGmGhXyd7Kiv9rbHqniyGrCHdWcuF6NTyYoN7aIhSfVFPBSrlHOrK8D6JKUtT+Lu0S
         uvZAEe7L43R+Z4mxY4hKduBJyvy2+4bIK3R6Y3TTnwXEbE/6Toz8qkEfzIBxB8yVQhkJ
         /dN+8n0Vh7JCLBZItHttWvhldx2evHJH67Owmlnf/+1rv1owPmQMzVjGvO25s2HcLrr8
         JI7xU9+d7/Zrv1D/Vw85C7WWBfhnUuoksXpRBdAsYh2AR0UOZ6es1iLXjoOOlH/OBoGM
         FSJA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-gm-message-state:from:to:cc
         :subject:date:message-id:reply-to;
        bh=HLGnQO8VkBaRgvhEAstngwGhia0AdG7hjcWhKI/56xg=;
        b=rIERVkmH7cMDS3p6sdaHYBVY4O069LgTJmDqvbsvur8kflh1Hl6JJXOcaQoACeZqnD
         SlliD0WBW62HjazsSKvMW8JSy6Fy9otfJ9i9PHypw0AzT1uyiKNUHdGP+SwBPwO03Vg9
         x6bud+t/UGKxfHTHbFVUdY7Xypht6bLzZ4VD73SWSNigXo/TUHsg1QOML0IFSHAAyTC3
         7L6uqzRcTmLcN+xwPAkT5OrC8Wl2PxN/h/5iU6zmGO7ZcpMOygZk19OGJ5na7LJ9mhgv
         w35XjNEU0YwOQVwc04l+CTsrmpYvSZGGuP8YC9dr+lR6+vbJL1GUmerHUbxNPKZHMiXp
         m46g==
X-Gm-Message-State: AFqh2kpjrSV0dBn4JiOxpPIUVq0/NiQ+AY5a6hgf0j/zozQl42XGxQTF
	dI+qnXUMsJJv0kQjOFsfUug=
X-Google-Smtp-Source: AMrXdXu9GVXXRcPV7BTpAlGzkNo5WlB66+j+ZpdOk8In3x9MDK1Cl6bx3SMp72Vdj5aMzd6V7Ezwvg==
X-Received: by 2002:a05:6512:21d2:b0:4cb:92:9423 with SMTP id d18-20020a05651221d200b004cb00929423mr3631115lft.348.1673596933146;
        Fri, 13 Jan 2023 00:02:13 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:214f:b0:4c8:8384:83f3 with SMTP id
 s15-20020a056512214f00b004c8838483f3ls2885571lfr.3.-pod-prod-gmail; Fri, 13
 Jan 2023 00:02:11 -0800 (PST)
X-Received: by 2002:a05:6512:2513:b0:4b5:7433:cfe6 with SMTP id be19-20020a056512251300b004b57433cfe6mr22268637lfb.45.1673596931783;
        Fri, 13 Jan 2023 00:02:11 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1673596931; cv=none;
        d=google.com; s=arc-20160816;
        b=w27GGGQbjasxylAXqnYE15osF+6qJ5Yci/bhcmuRKbPdw1y8uaYP8rtxNvROoij3jG
         A1KgGXy70f/KqInScPoJKnkPslNw72CVI3HrOF2IQ9jd46SvX8Hw+lpbECZuQa4AvQQH
         rXYjRv143f2WcXSzHEKQu8oI9hmqX10Ho5cQGjttXgI5EAOiBY182hitpI/4vzJBOapG
         RIqe0p0/fmGv9Gqea7wLcStcJzQLqJBawhg39pbKipkr5jf1Uk+yvqa57GaDbbzbx3ZQ
         /1EiAkJtp1rr0RaIt+BgupEaVpaMPYt8s1a++nxPU8ejgCOLgbPRgwZi8Tz/nh2p3fRw
         ENjw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=Dd0gSl4CE2V3d5G56HYqss/GOHVFV1yZ9nbqL6AwD9A=;
        b=dBpTzeZovyjxtpsAA0tXnQOeMZPW/n5IEqSB9LsZeGe24jDjGq0KLUgPV/GwYEVADL
         48PLk0pOTWcGnpvlj0xU0hF53c0mymCjQDapjr390T0riYzePFCreFkhwCHhUFeKLrYX
         Hht/fWWLo6e5r37eZxlBeClnvnlQs+QcyP9HjaY1epabgQgZkt73NAVT6dBqi4n9PMv4
         yAbVqBxfcEn/yr6vEwH1jtmv16GIsBbjkmZMBhKHLJ4MMT9V69XuO3+R8v+ZP1THqF5w
         iLCYJLHgBv/sBA9yy43U4BZFqeopGgsWXKWtOdpS4uSzTn2JXzHN/ayzRyfdRTU05EuO
         Lv+A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=mqO98eOB;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::134 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-lf1-x134.google.com (mail-lf1-x134.google.com. [2a00:1450:4864:20::134])
        by gmr-mx.google.com with ESMTPS id j11-20020a056512344b00b004b49cc7bf6asi925591lfr.9.2023.01.13.00.02.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 13 Jan 2023 00:02:11 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::134 as permitted sender) client-ip=2a00:1450:4864:20::134;
Received: by mail-lf1-x134.google.com with SMTP id b3so31998684lfv.2
        for <kasan-dev@googlegroups.com>; Fri, 13 Jan 2023 00:02:11 -0800 (PST)
X-Received: by 2002:a05:6512:6c6:b0:4a4:77a8:45a4 with SMTP id
 u6-20020a05651206c600b004a477a845a4mr3595816lff.654.1673596931130; Fri, 13
 Jan 2023 00:02:11 -0800 (PST)
MIME-Version: 1.0
References: <20230103075603.12294-1-Kuan-Ying.Lee@mediatek.com>
 <CACT4Y+b5hbCod=Gj6oGxFrq5CaFPbz5T9A0nomzhWooiXQy5aA@mail.gmail.com> <edbcce8a1e9e772e3a3fd032cd4600bd5677c877.camel@mediatek.com>
In-Reply-To: <edbcce8a1e9e772e3a3fd032cd4600bd5677c877.camel@mediatek.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 13 Jan 2023 09:01:58 +0100
Message-ID: <CACT4Y+Yx+8tjTvE5oR3qzHa4oMoPoj=+BTgcFZHA8jwxgtp1Pg@mail.gmail.com>
Subject: Re: [PATCH] kasan: infer the requested size by scanning shadow memory
To: =?UTF-8?B?S3Vhbi1ZaW5nIExlZSAo5p2O5Yag56mOKQ==?= <Kuan-Ying.Lee@mediatek.com>
Cc: "linux-kernel@vger.kernel.org" <linux-kernel@vger.kernel.org>, 
	"linux-mediatek@lists.infradead.org" <linux-mediatek@lists.infradead.org>, 
	=?UTF-8?B?UXVuLXdlaSBMaW4gKOael+e+pOW0tCk=?= <Qun-wei.Lin@mediatek.com>, 
	"linux-mm@kvack.org" <linux-mm@kvack.org>, "andreyknvl@gmail.com" <andreyknvl@gmail.com>, 
	=?UTF-8?B?Q2hpbndlbiBDaGFuZyAo5by16Yym5paHKQ==?= <chinwen.chang@mediatek.com>, 
	"kasan-dev@googlegroups.com" <kasan-dev@googlegroups.com>, 
	"akpm@linux-foundation.org" <akpm@linux-foundation.org>, 
	"ryabinin.a.a@gmail.com" <ryabinin.a.a@gmail.com>, 
	"linux-arm-kernel@lists.infradead.org" <linux-arm-kernel@lists.infradead.org>, 
	"glider@google.com" <glider@google.com>, "vincenzo.frascino@arm.com" <vincenzo.frascino@arm.com>, 
	"matthias.bgg@gmail.com" <matthias.bgg@gmail.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=mqO98eOB;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::134
 as permitted sender) smtp.mailfrom=dvyukov@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Dmitry Vyukov <dvyukov@google.com>
Reply-To: Dmitry Vyukov <dvyukov@google.com>
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

On Fri, 13 Jan 2023 at 08:59, 'Kuan-Ying Lee (=E6=9D=8E=E5=86=A0=E7=A9=8E)'=
 via kasan-dev
<kasan-dev@googlegroups.com> wrote:
>
> On Mon, 2023-01-09 at 07:51 +0100, Dmitry Vyukov wrote:
> > On Tue, 3 Jan 2023 at 08:56, 'Kuan-Ying Lee' via kasan-dev
> > <kasan-dev@googlegroups.com> wrote:
> > >
> > > We scan the shadow memory to infer the requested size instead of
> > > printing cache->object_size directly.
> > >
> > > This patch will fix the confusing generic kasan report like below.
> > > [1]
> > > Report shows "cache kmalloc-192 of size 192", but user
> > > actually kmalloc(184).
> > >
> > > =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
> > > BUG: KASAN: slab-out-of-bounds in _find_next_bit+0x143/0x160
> > > lib/find_bit.c:109
> > > Read of size 8 at addr ffff8880175766b8 by task kworker/1:1/26
> > > ...
> > > The buggy address belongs to the object at ffff888017576600
> > >  which belongs to the cache kmalloc-192 of size 192
> > > The buggy address is located 184 bytes inside of
> > >  192-byte region [ffff888017576600, ffff8880175766c0)
> > > ...
> > > Memory state around the buggy address:
> > >  ffff888017576580: fb fb fb fb fb fb fb fb fc fc fc fc fc fc fc fc
> > >  ffff888017576600: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
> > > > ffff888017576680: 00 00 00 00 00 00 00 fc fc fc fc fc fc fc fc fc
> > >
> > >                                         ^
> > >  ffff888017576700: fc fc fc fc fc fc fc fc fc fc fc fc fc fc fc fc
> > >  ffff888017576780: fc fc fc fc fc fc fc fc fc fc fc fc fc fc fc fc
> > > =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
> > >
> > > After this patch, report will show "cache kmalloc-192 of size 184".
> > >
> > > Link:
> > > https://urldefense.com/v3/__https://bugzilla.kernel.org/show_bug.cgi?=
id=3D216457__;!!CTRNKA9wMg0ARbw!mLNcuZ83c39d0Xkut-WMY3CcvZcAYDuLCmv4mu7IAld=
w4_n4i6XvX8GORBfjOadWxOa6d-ODQdx6ZCSvB2g13Q$
> > > $   [1]
> > >
> > > Signed-off-by: Kuan-Ying Lee <Kuan-Ying.Lee@mediatek.com>
> > > ---
> > >  mm/kasan/kasan.h          |  5 +++++
> > >  mm/kasan/report.c         |  3 ++-
> > >  mm/kasan/report_generic.c | 18 ++++++++++++++++++
> > >  3 files changed, 25 insertions(+), 1 deletion(-)
> > >
> > > diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
> > > index 32413f22aa82..7bb627d21580 100644
> > > --- a/mm/kasan/kasan.h
> > > +++ b/mm/kasan/kasan.h
> > > @@ -340,8 +340,13 @@ static inline void
> > > kasan_print_address_stack_frame(const void *addr) { }
> > >
> > >  #ifdef CONFIG_KASAN_GENERIC
> > >  void kasan_print_aux_stacks(struct kmem_cache *cache, const void
> > > *object);
> > > +int kasan_get_alloc_size(void *object_addr, struct kmem_cache
> > > *cache);
> > >  #else
> > >  static inline void kasan_print_aux_stacks(struct kmem_cache
> > > *cache, const void *object) { }
> > > +static inline int kasan_get_alloc_size(void *object_addr, struct
> > > kmem_cache *cache)
> > > +{
> > > +       return cache->object_size;
> > > +}
> > >  #endif
> > >
> > >  bool kasan_report(unsigned long addr, size_t size,
> > > diff --git a/mm/kasan/report.c b/mm/kasan/report.c
> > > index 1d02757e90a3..6de454bb2cad 100644
> > > --- a/mm/kasan/report.c
> > > +++ b/mm/kasan/report.c
> > > @@ -236,12 +236,13 @@ static void describe_object_addr(const void
> > > *addr, struct kmem_cache *cache,
> > >  {
> > >         unsigned long access_addr =3D (unsigned long)addr;
> > >         unsigned long object_addr =3D (unsigned long)object;
> > > +       int real_size =3D kasan_get_alloc_size((void *)object_addr,
> > > cache);
> > >         const char *rel_type;
> > >         int rel_bytes;
> > >
> > >         pr_err("The buggy address belongs to the object at %px\n"
> > >                " which belongs to the cache %s of size %d\n",
> > > -               object, cache->name, cache->object_size);
> > > +               object, cache->name, real_size);
> > >
> > >         if (access_addr < object_addr) {
> > >                 rel_type =3D "to the left";
> > > diff --git a/mm/kasan/report_generic.c b/mm/kasan/report_generic.c
> > > index 043c94b04605..01b38e459352 100644
> > > --- a/mm/kasan/report_generic.c
> > > +++ b/mm/kasan/report_generic.c
> > > @@ -43,6 +43,24 @@ void *kasan_find_first_bad_addr(void *addr,
> > > size_t size)
> > >         return p;
> > >  }
> > >
> > > +int kasan_get_alloc_size(void *addr, struct kmem_cache *cache)
> > > +{
> > > +       int size =3D 0;
> > > +       u8 *shadow =3D (u8 *)kasan_mem_to_shadow(addr);
> > > +
> > > +       while (size < cache->object_size) {
> > > +               if (*shadow =3D=3D 0)
> > > +                       size +=3D KASAN_GRANULE_SIZE;
> > > +               else if (*shadow >=3D 1 && *shadow <=3D
> > > KASAN_GRANULE_SIZE - 1)
> > > +                       size +=3D *shadow;
> > > +               else
> > > +                       return size;
> > > +               shadow++;
> >
> > This only works for out-of-bounds reports, but I don't see any checks
> > for report type. Won't this break reporting for all other report
> > types?
> >
>
> I think it won't break reporting for other report types.
> This function is only called by slab OOB and UAF.

I meant specifically UAF reports.
During UAF there are no 0s in the object shadow.

> > I would also print the cache name anyway. Sometimes reports are
> > perplexing and/or this logic may return a wrong result for some
> > reason. The total object size may be useful to understand harder
> > cases.
> >
>
> Ok. I will keep the cache name and the total object_size.
>
> > > +       }
> > > +
> > > +       return cache->object_size;
> > > +}
> > > +
> > >  static const char *get_shadow_bug_type(struct kasan_report_info
> > > *info)
> > >  {
> > >         const char *bug_type =3D "unknown-crash";
>
> --
> You received this message because you are subscribed to the Google Groups=
 "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an=
 email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgi=
d/kasan-dev/edbcce8a1e9e772e3a3fd032cd4600bd5677c877.camel%40mediatek.com.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CACT4Y%2BYx%2B8tjTvE5oR3qzHa4oMoPoj%3D%2BBTgcFZHA8jwxgtp1Pg%40mai=
l.gmail.com.
