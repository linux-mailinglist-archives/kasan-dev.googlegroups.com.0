Return-Path: <kasan-dev+bncBCUJ7YGL3QFBBSET6KLQMGQEFDDOBZI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53a.google.com (mail-pg1-x53a.google.com [IPv6:2607:f8b0:4864:20::53a])
	by mail.lfdr.de (Postfix) with ESMTPS id 0060F596980
	for <lists+kasan-dev@lfdr.de>; Wed, 17 Aug 2022 08:25:15 +0200 (CEST)
Received: by mail-pg1-x53a.google.com with SMTP id 15-20020a63020f000000b0041b578f43f9sf4919638pgc.11
        for <lists+kasan-dev@lfdr.de>; Tue, 16 Aug 2022 23:25:14 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1660717513; cv=pass;
        d=google.com; s=arc-20160816;
        b=ik67Rg9zB/HRpoBPxfoXCCxWg+Lz+p5eQWcj9VqYpjSr7qea+kYVR+ArkQQJo6BpHk
         Gs4DQjbVoK/JwH/pNj+e7tOoJwEQ1ZWq26z9VPHvOeUp2x30EaWk+Xormsksx+sbxyYs
         33MtCn9f9JNOeq7qyRgLRmk09U3Vl+B2vErjezHgfkf1Vr1kUmjnkNRGfPpfL0sXC7Mx
         48kMv/LjxTDh2MztXFNvJQwrL9QtRUWewzTp3IcsEIOj6LtVQEdmksauDkXOGfrCwNHX
         njcAJRhot4Kif8EDAbdD3MxhASpQhVrtYGmiK2KOXDdTlOlef+O7KwjmUv5KIgdnEQYX
         K0aw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=ChcZ2/13l58cN9R0NX04rZjVt6S6qKMfsugZ8+JXtck=;
        b=Ayz9HpOCwYf5606g9mRfW41LZo/2pJ5yrXa0q3VlIH4AM0rUlCTOLPeCaQGHz2GOKx
         i8BJ5sOeuuHGojAzXdKmxxrEj//zSxK0pEc2NzoHo/F+4KFAZZdf2VlP2bK3KPLpw23z
         tRBLY/fCpdndbCrS7i22sqDjucMTeb2Wog2R7Zr3wMqiOVA5bZruCtsZMlD+6T64rWZy
         bnnNmhVH7egA9ZjF7pNUvx5rAtFSvfnJ/tXPOtG+NnZqEqXuFabdNaK+JOQ3VdNuUY7T
         PbG5HnTwHQTKVJ5BwsPU5PdBEH9lpmdJ3tx1p6GwG5EaYU3KZ3eXl2DN/VoDtz2gtSeD
         0DaQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linuxfoundation.org header.s=korg header.b=z9agusHF;
       spf=pass (google.com: domain of gregkh@linuxfoundation.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=gregkh@linuxfoundation.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linuxfoundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-transfer-encoding
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:from:to:cc;
        bh=ChcZ2/13l58cN9R0NX04rZjVt6S6qKMfsugZ8+JXtck=;
        b=JLkC58J31LjByXfALBvizvrkviI3mD23T+2f14H/tV9tZryWYMW1k5edMc3Lv0XKGe
         radfBSDuP2ZuIgczu5+rVE3pg9l3RE/b5cJMzRxSOirKALNmOeTiMZnHcgIUNpCapJo7
         7/hS5jrRUbL/5upXh4ldU5H3gZgtt9YKajtqYqkGEoWZUAABRVrWdXvbYpJ6jy213ZYi
         xrWZpRjL/Fewvs7QpjD1XTc5IhBA0W3SfFLNXicSAvPEsh7NzlClXqg0KVdaSyPi9ZeB
         WUU8SOv47j/W4VSR07510YOGSw1VEF4qELAvrXoTgfd1yBVPAjwVpoDEQN4SjfWv9Q5b
         z6Rg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:x-gm-message-state
         :sender:from:to:cc;
        bh=ChcZ2/13l58cN9R0NX04rZjVt6S6qKMfsugZ8+JXtck=;
        b=TdGfL5tpdwngmMmh/TPgGig5hI+9yOfarq2Fbpo2OtiiQgxdx2f8an6naQDjcCRY6e
         T6gTzqdF5KqrytLc3Lv1INYVxYU4lgFIT43VyY0gbLtpU2Bzsxb/3oqlyH/SDL9TxT3I
         YFnj4/h+eA6M7SFXuagf6inh0XUOItjVqhrA0ZNtxe8Z9+MasVggqCOnoHeKZF+yHp8o
         Gvu3tk84vXCoDlDOz27cV8d5Imi/U9VhTsl9PGocCZKyB+/pSU5/HjNed7Qt35LKHNBg
         E1DCHK1CEUc+4r6kTQR5uZ3bPX1HAgyGnaJ653MYEwGuZuv6iYFL3CWyxFogjvY/vjGD
         xrDA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACgBeo3Qi9mSxrUh7K2/hsF9mutnRlMoM1WHR7L/31//0+/oBeP4euam
	PCtGAs0D51SuVi4WKu2AQuk=
X-Google-Smtp-Source: AA6agR5Gc3SoZihLWznSwBhD6IU1f8h/zrz7toFlD5s6thiN7LEraVkVkxiQcL6BFTZlR4OmC/4dDw==
X-Received: by 2002:aa7:80d0:0:b0:52d:f9c6:bb14 with SMTP id a16-20020aa780d0000000b0052df9c6bb14mr24436674pfn.57.1660717513272;
        Tue, 16 Aug 2022 23:25:13 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:8145:0:b0:52f:1c5a:72d5 with SMTP id t66-20020a628145000000b0052f1c5a72d5ls7265329pfd.9.-pod-prod-gmail;
 Tue, 16 Aug 2022 23:25:12 -0700 (PDT)
X-Received: by 2002:a05:6a00:1a88:b0:52f:52df:ce1d with SMTP id e8-20020a056a001a8800b0052f52dfce1dmr24584924pfv.13.1660717512245;
        Tue, 16 Aug 2022 23:25:12 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1660717512; cv=none;
        d=google.com; s=arc-20160816;
        b=zB8KZdQhoP10I+u6+MhOpEFtkPEXnhESooFJPr5xqMzRwxxtaaxu3e8NbZM8h3HZxt
         SiJ3mJA0JO2km7UjAWj3ylNTzvg0FgsNtDLxxmFBfKQAEqB7ntfj9BqpsgUZpFuBQNhx
         rHdS88Ql5oD84FowDMkDuDivMl/CObMKMvSro0nMFTapZd/VYJjh1pC6ppN2J9JPGCrO
         0MBK/7FCvlgXZXWnHpcG6/h+VXSsF9gT3iTlXRmu/B/nzz1t3PtZhVH2+H5rDS+u7wvE
         d4AExqJrHDgCXs/1gK6Pmwq0xQGoGxuKvB+/tzpi1WkMqEdyg/COMwleQettPQTDazF2
         GXDA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=VZZQ5b5Oz9Ac/nCTBWNu3RcMZrU+mYc5GwLDshgu0VA=;
        b=pcoex5RWw3Xw/AwJyWkEJz8p89mqa4HjUa6rkgYwGYqXHO1aFcIt/lcFFJH7ANwVH8
         YAhyYjR3nDMG9v1miRkW/CcOpipnHLA82ZHolqxIXvpQrmxRguL4IzaiTI8+8BkvsJlL
         2Pfs634HEHsRw8RoM4AykAgHK6sqqUBGLU8F7dM64Ae5aLMeGKXrSXSM6nPsCkzm6TuA
         7+MgUmtquQpI1fEaA4ttRrgGV2bs9z2Zqb7HfrojFfcszbL92flqOscjR5I5aM6EMRvy
         RBShaz+/6Zvz6a8fR3jlnrS4gPpr08Pr7uKDk07N1bX51RwbNpSZyBcRC9jAGWthpa35
         d1Ag==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linuxfoundation.org header.s=korg header.b=z9agusHF;
       spf=pass (google.com: domain of gregkh@linuxfoundation.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=gregkh@linuxfoundation.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linuxfoundation.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id p5-20020a170902e74500b001641217de25si24039plf.1.2022.08.16.23.25.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 16 Aug 2022 23:25:12 -0700 (PDT)
Received-SPF: pass (google.com: domain of gregkh@linuxfoundation.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id AB08260B90;
	Wed, 17 Aug 2022 06:25:11 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 36EE7C433C1;
	Wed, 17 Aug 2022 06:25:09 +0000 (UTC)
Date: Wed, 17 Aug 2022 08:25:06 +0200
From: Greg Kroah-Hartman <gregkh@linuxfoundation.org>
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Will Deacon <will@kernel.org>, Yee Lee <Yee.Lee@mediatek.com>,
	Marco Elver <elver@google.com>, Max Schulze <max.schulze@online.de>,
	"linux-arm-kernel@lists.infradead.org" <linux-arm-kernel@lists.infradead.org>,
	"catalin.marinas@arm.com" <catalin.marinas@arm.com>,
	"naush@raspberrypi.com" <naush@raspberrypi.com>,
	"glider@google.com" <glider@google.com>,
	"dvyukov@google.com" <dvyukov@google.com>,
	"kasan-dev@googlegroups.com" <kasan-dev@googlegroups.com>
Subject: Re: kmemleak: Cannot insert 0xffffff806e24f000 into the object
 search tree (overlaps existing) [RPi CM4]
Message-ID: <YvyJwrCNUdKHwxeQ@kroah.com>
References: <b33b33bc-2d06-1bcd-2df7-43678962b728@online.de>
 <20220815124705.GA9950@willie-the-truck>
 <CANpmjNPrDW5FRf3PdzAUsjEtHgaWVTJ2CNr0=e732fEUf4FTmQ@mail.gmail.com>
 <SI2PR03MB57530BCDBB59A9E2DCE38DCA906B9@SI2PR03MB5753.apcprd03.prod.outlook.com>
 <20220816142628.GA11512@willie-the-truck>
 <20220816163943.672fe3285bc391b48e431e54@linux-foundation.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <20220816163943.672fe3285bc391b48e431e54@linux-foundation.org>
X-Original-Sender: gregkh@linuxfoundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linuxfoundation.org header.s=korg header.b=z9agusHF;       spf=pass
 (google.com: domain of gregkh@linuxfoundation.org designates
 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=gregkh@linuxfoundation.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linuxfoundation.org
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

On Tue, Aug 16, 2022 at 04:39:43PM -0700, Andrew Morton wrote:
> On Tue, 16 Aug 2022 15:26:29 +0100 Will Deacon <will@kernel.org> wrote:
>=20
> > On Tue, Aug 16, 2022 at 10:52:19AM +0000, Yee Lee (=E6=9D=8E=E5=BB=BA=
=E8=AA=BC) wrote:
> > > The kfence patch(07313a2b29ed) is based on the prior changes in
> > > kmemleak(0c24e061196c2 , merged in v6.0-rc1), but it shows up earlier=
 in
> > > v5.19.=20
> > >=20
> > > @akpm
> > > Andrew, sorry that the short fix tag caused confusing. Can we pull ou=
t the
> > > patch(07313a2b29e) in v5.19.x?
> > >=20
> > > Kfence: (07313a2b29ed) https://github.com/torvalds/linux/commit/07313=
a2b29ed1079eaa7722624544b97b3ead84b
> > > Kmemleak: (0c24e061196c2) https://github.com/torvalds/linux/commit/0c=
24e061196c21d53328d60f4ad0e5a2b3183343
> >=20
> > Hmm, so if I'm understanding correctly then:
> >=20
> >  - The kfence fix (07313a2b29ed) depends on a kmemleak change (0c24e061=
196c2)
> >    but the patches apply cleanly on their own.
> >=20
> >  - The kmemleak change landed in the v6.0 merge window, but the kfence =
fix
> >    landed in 5.19 (and has a fixes tag)
> >=20
> > So it sounds like we can either:
> >=20
> >  1. Revert 07313a2b29ed in the stable trees which contain it and then f=
ix
> >     the original issue some other way.
>=20
> 07313a2b29ed should not be in the stable tree.  It did not have a
> cc:stable and we've asked the stable tree maintainers not to blindly
> backport everything that has a Fixes: tag.
>=20
> How did this happen?

I do not see 07313a2b29ed in any stable tree or release that I can
find, am I missing something?

thanks,

greg k-h

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/YvyJwrCNUdKHwxeQ%40kroah.com.
