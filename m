Return-Path: <kasan-dev+bncBD4L7DEGYINBBBGF5KKQMGQEHQGDI4Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3f.google.com (mail-io1-xd3f.google.com [IPv6:2607:f8b0:4864:20::d3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 8019E55BED5
	for <lists+kasan-dev@lfdr.de>; Tue, 28 Jun 2022 08:41:10 +0200 (CEST)
Received: by mail-io1-xd3f.google.com with SMTP id m3-20020a6bbc03000000b0067277968473sf6749231iof.19
        for <lists+kasan-dev@lfdr.de>; Mon, 27 Jun 2022 23:41:10 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1656398469; cv=pass;
        d=google.com; s=arc-20160816;
        b=xeONjMlc64Wh03Wgacm0ZGDGh5OF5d/5wFxArVZ0KgK2vM9guM4+E4fZQ2uBaQB8GV
         t6il3GbiIOlCth41BmolR5nHxL0JpK5+aOf4IiygeE9hxodz4T6BuB+Aem0KhWy2TOAA
         KmNFZCERuAZo6C4CppIWGI4iu2PD+11PNwjHddjzmviFCJjezsd3S7YcixiNLpXQ1Oee
         eZRI1WrPZ+bk9wnypWGbg/ZyOG/JLnIH8yGNMN6m1Ek3IFlh4VxAC3PQ0BZjxTdyK0v9
         Bw9iV2TeEAcIe/g6Ko3SZWByMTX5Fq3Eiw1ZGeEqZJ64+FDIWPCE5nVrLjSg+9kLpAw2
         V+3g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:date:cc:to:from:subject:message-id:dkim-signature;
        bh=1h+GijbuY00eBXC1nPVOhTXb10Dq8yeSZwxJCVxIGxM=;
        b=khKZPH3Bf25ZYq+eFAcpTiVIvjrQFfFcL0NThSq7dIrE36HQ/1xc1dfx3b9saDd9OR
         60shk59W2aU5isYXn8UEF8aV+B1+wvcn/joG/sKMI/ox+MGc/gdZJpG1GgDZG+ZEHEcY
         qH7WSNLiKFL/viOq0y/vpgRUYgpRiIcIrfd48eQ21VTocYFq4LMq/YmDTsq5735eLKw1
         MQK88XqH6BogNegyS4z6dIHQeZ2m0naAFO/U89TrMUlAcIiEimh4fSyxCUndQo9jYCS/
         KVBuXem/krjolPvQfdtc1/IeMHTKru5ct56eTFArsNbJeCVwzgTdUOnFQKjWA4dkrxjG
         P6Jw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of yee.lee@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=yee.lee@mediatek.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=message-id:subject:from:to:cc:date:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=1h+GijbuY00eBXC1nPVOhTXb10Dq8yeSZwxJCVxIGxM=;
        b=baLmyAIPSq3L2eieO+yS+kckBraMZPjgRSnVxPfyCe+6/0QnNJaYcRTqvh5KOoAdKi
         2ZveL/6KiDfBT74hYnYhBXDAD6eyKl5Tbw0ff9eBHVHxLBK7Rt6RPz0v7F+PMTx60KAV
         +lba5WuZBpqsV3h1DqIvx52q/C7mq6n/15PPpZIkDMrxH2CiOssICCB8bOpuji8YVVk/
         2+JTU6ApzOExQ2cD69qe5IyJV1O/xwh1aJq8WjkGOiyiwWf8cHrN+ZlH+TFMWKovar3d
         L54KMYgsaSw4UI6PExtBZizaba74RCFziSueYKEALm4+H1o1QMZCGEawUBraG7S/RGpD
         v8XQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:message-id:subject:from:to:cc:date:in-reply-to
         :references:mime-version:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=1h+GijbuY00eBXC1nPVOhTXb10Dq8yeSZwxJCVxIGxM=;
        b=bP2rFCwhlGFxVnOyhH4GfpoPJq7vkUYSKwFfC20Z+pcqqIg8sktxBR/bEm3hQLWl89
         LfR2XcfJPIQ9pyYXO8Ld/3T3TjtvpdyY2cgAH8vEcJof0issBPV9t1NmZIBM9xTUwGMc
         Fag5pcRqm2rwH8fEGZfuo4FpLW8J361yEGJffBK4vjPI9DOcJMUaytc0ve/aWlYLXV6H
         yUCS194z2Fv8S0z2FVWmYBIyZXYs0UbvkWVLbITDYhDAIleRDiZ2jjkTVhFKO3xa9ClP
         RIcvsSHUFr3VCk2/tfgakp+GjtMgGovMIY/yYgxMA//zL6ztsmtVOOvRTHn5gKGmjM5m
         5s+Q==
X-Gm-Message-State: AJIora9J6+XhypqgumN9mgUVYRO/OcL8JvmnAfsXDy98agoaf8S3liU/
	5Bnrw+lEjz83vCFYld1sjOU=
X-Google-Smtp-Source: AGRyM1vnBwBO/mNN7IQkZUNFMeMWDnybNK7gZv2OXRMT2ar8Y6GJMXElr9dPnWpDMdtkGHKIgrcPEw==
X-Received: by 2002:a05:6638:238f:b0:33c:98bc:2124 with SMTP id q15-20020a056638238f00b0033c98bc2124mr5650531jat.30.1656398468717;
        Mon, 27 Jun 2022 23:41:08 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6602:2b8a:b0:645:b6c7:1c9c with SMTP id
 r10-20020a0566022b8a00b00645b6c71c9cls3036542iov.4.gmail; Mon, 27 Jun 2022
 23:41:08 -0700 (PDT)
X-Received: by 2002:a05:6602:2c4e:b0:657:4115:d9e4 with SMTP id x14-20020a0566022c4e00b006574115d9e4mr8343719iov.91.1656398468252;
        Mon, 27 Jun 2022 23:41:08 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1656398468; cv=none;
        d=google.com; s=arc-20160816;
        b=HRHPIu9usgffHH7DKCEClRL4Ey4lYVN4G7ZFboV6hZs8BjS97eiS6n0p+528mcN5z7
         lnBhbx+8z8dotJb4/W/a1IPSyVdk7Gy8Tmp/wSNAhscl3pLGysslA+79LgoAXaz9Y4hK
         lSzZ75Ve+0iK0Zdv0k36bI8CIG8dZig0fdtf/Y7XjlF8dTKWXPvn/ujcPrhvGNkab9Jg
         ihOUFwpr6Vu25WBdW1ttLIcKlrDu3lbzJ6icZLnydys2x46lOcXZp3fUUZoizPejCo+b
         ZUqok6188WZOv6cSSQuicEQhUzj8KaOleu9+U0STYJOu9EJV9Bxwp0uj1kYl2b87/2kL
         oh/A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:references:in-reply-to:date:cc:to:from:subject
         :message-id;
        bh=YzqQIMEhrsIhrLBGFKZKzc02lgPdNGB9Mb+A2CTuIGI=;
        b=dyHAGw0gyS6nA7Nqi2DdoFUXV8roVvClZ2ML0w8RaF52LbW1XIP03vOI64l28+zu0e
         lOkvoMUNrboC5dAJRCzSKjJkuw0a2jtT1oBRJMMjn4hzOQ3tBnMX4X+UEIkIeYwy5AT+
         p4RU73xXua2eSqxM+OHkVIO+6rPNZRB6+vTIfoPYv8aS7Owe8kOQMbEVeHzk2dKYQ+bX
         Z3kxwG2b1QiGnBVrv+knNoXP0DUeajccY+EvZ999G/27Z+nmfCuHjULsNLFGbmrDuj2I
         /3loz/L75T/41p+72gCqweuZSD450QSLh/njdS8EmiJoTkdNtMk8XBdUiQ5s2P91id4N
         sPRA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of yee.lee@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=yee.lee@mediatek.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=mediatek.com
Received: from mailgw02.mediatek.com ([210.61.82.184])
        by gmr-mx.google.com with ESMTPS id h39-20020a022b27000000b00339d8343d66si400337jaa.2.2022.06.27.23.41.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 27 Jun 2022 23:41:07 -0700 (PDT)
Received-SPF: pass (google.com: domain of yee.lee@mediatek.com designates 210.61.82.184 as permitted sender) client-ip=210.61.82.184;
X-UUID: 6aeff03f869c429582b9b7894315f850-20220628
X-CID-P-RULE: Release_Ham
X-CID-O-INFO: VERSION:1.1.7,REQID:8b82d7a6-3c56-4d5a-9a83-3eb6da7f8dcc,OB:0,LO
	B:0,IP:0,URL:0,TC:0,Content:-5,EDM:0,RT:0,SF:45,FILE:0,RULE:Release_Ham,AC
	TION:release,TS:40
X-CID-INFO: VERSION:1.1.7,REQID:8b82d7a6-3c56-4d5a-9a83-3eb6da7f8dcc,OB:0,LOB:
	0,IP:0,URL:0,TC:0,Content:-5,EDM:0,RT:0,SF:45,FILE:0,RULE:Release_Ham,ACTI
	ON:release,TS:40
X-CID-META: VersionHash:87442a2,CLOUDID:d7a9f685-57f0-47ca-ba27-fe8c57fbf305,C
	OID:ea37aff06c38,Recheck:0,SF:28|17|19|48,TC:0,Content:0,EDM:-3,IP:nil,URL
	:1,File:nil,QS:nil,BEC:nil,COL:0
X-UUID: 6aeff03f869c429582b9b7894315f850-20220628
Received: from mtkcas11.mediatek.inc [(172.21.101.40)] by mailgw02.mediatek.com
	(envelope-from <yee.lee@mediatek.com>)
	(Generic MTA with TLSv1.2 ECDHE-RSA-AES256-SHA384 256/256)
	with ESMTP id 1904066030; Tue, 28 Jun 2022 14:40:50 +0800
Received: from mtkcas11.mediatek.inc (172.21.101.40) by
 mtkmbs11n1.mediatek.inc (172.21.101.185) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384) id 15.2.792.3;
 Tue, 28 Jun 2022 14:40:50 +0800
Received: from mtksdccf07 (172.21.84.99) by mtkcas11.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1497.2 via Frontend
 Transport; Tue, 28 Jun 2022 14:40:49 +0800
Message-ID: <9c6fcb1c178a923f2406466a3f9f2345e4e7a1c1.camel@mediatek.com>
Subject: Re: [PATCH 1/1] mm: kfence: skip kmemleak alloc in kfence_pool
From: "'Yee Lee' via kasan-dev" <kasan-dev@googlegroups.com>
To: Marco Elver <elver@google.com>
CC: <linux-kernel@vger.kernel.org>, Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>, Andrew Morton
	<akpm@linux-foundation.org>, Matthias Brugger <matthias.bgg@gmail.com>, "open
 list:KFENCE" <kasan-dev@googlegroups.com>, "open list:MEMORY MANAGEMENT"
	<linux-mm@kvack.org>, "moderated list:ARM/Mediatek SoC support"
	<linux-arm-kernel@lists.infradead.org>, "moderated list:ARM/Mediatek SoC
 support" <linux-mediatek@lists.infradead.org>, <catalin.marinas@arm.com>
Date: Tue, 28 Jun 2022 14:40:49 +0800
In-Reply-To: <CANpmjNPfkFjUteMCDzUSPmTKbpnSfjmWqp9ft8vb-v=B8eeRKw@mail.gmail.com>
References: <20220623111937.6491-1-yee.lee@mediatek.com>
	 <20220623111937.6491-2-yee.lee@mediatek.com>
	 <CANpmjNN-jsZoVmJWD2Dz6O3_YVjy0av6e0iD-+OYXpik1LbLvg@mail.gmail.com>
	 <bdfd039fbde06113071f773ae6d5635ff4664e2c.camel@mediatek.com>
	 <CANpmjNPfkFjUteMCDzUSPmTKbpnSfjmWqp9ft8vb-v=B8eeRKw@mail.gmail.com>
Content-Type: multipart/alternative; boundary="=-tlhIpc4LLWzE61Oh4jJE"
X-Mailer: Evolution 3.28.5-0ubuntu0.18.04.2
MIME-Version: 1.0
X-MTK: N
X-Original-Sender: yee.lee@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of yee.lee@mediatek.com designates 210.61.82.184 as
 permitted sender) smtp.mailfrom=yee.lee@mediatek.com;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=mediatek.com
X-Original-From: Yee Lee <yee.lee@mediatek.com>
Reply-To: Yee Lee <yee.lee@mediatek.com>
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

--=-tlhIpc4LLWzE61Oh4jJE
Content-Type: text/plain; charset="UTF-8"

On Fri, 2022-06-24 at 10:28 +0200, Marco Elver wrote:
> On Fri, 24 Jun 2022 at 10:20, 'Yee Lee' via kasan-dev
> <kasan-dev@googlegroups.com> wrote:
> > 
> > On Thu, 2022-06-23 at 13:59 +0200, Marco Elver wrote:
> > > On Thu, 23 Jun 2022 at 13:20, yee.lee via kasan-dev
> > > <kasan-dev@googlegroups.com> wrote:
> > > > 
> > > > From: Yee Lee <yee.lee@mediatek.com>
> > > > 
> > > > Use MEMBLOCK_ALLOC_NOLEAKTRACE to skip kmemleak registration
> > > > when
> > > > the kfence pool is allocated from memblock. And the
> > > > kmemleak_free
> > > > later can be removed too.
> > > 
> > > Is this purely meant to be a cleanup and non-functional change?
> > > 
> > > > Signed-off-by: Yee Lee <yee.lee@mediatek.com>
> > > > 
> > > > ---
> > > >  mm/kfence/core.c | 18 ++++++++----------
> > > >  1 file changed, 8 insertions(+), 10 deletions(-)
> > > > 
> > > > diff --git a/mm/kfence/core.c b/mm/kfence/core.c
> > > > index 4e7cd4c8e687..0d33d83f5244 100644
> > > > --- a/mm/kfence/core.c
> > > > +++ b/mm/kfence/core.c
> > > > @@ -600,14 +600,6 @@ static unsigned long
> > > > kfence_init_pool(void)
> > > >                 addr += 2 * PAGE_SIZE;
> > > >         }
> > > > 
> > > > -       /*
> > > > -        * The pool is live and will never be deallocated from
> > > > this
> > > > point on.
> > > > -        * Remove the pool object from the kmemleak object
> > > > tree, as
> > > > it would
> > > > -        * otherwise overlap with allocations returned by
> > > > kfence_alloc(), which
> > > > -        * are registered with kmemleak through the slab post-
> > > > alloc
> > > > hook.
> > > > -        */
> > > > -       kmemleak_free(__kfence_pool);
> > > 
> > > This appears to only be a non-functional change if the pool is
> > > allocated early. If the pool is allocated late using page-alloc,
> > > then
> > > there'll not be a kmemleak_free() on that memory and we'll have
> > > the
> > > same problem.
> > 
> > Do you mean the kzalloc(slab_is_available) in memblock_allc()? That
> > implies that MEMBLOCK_ALLOC_NOLEAKTRACE has no guarantee skipping
> > kmemleak_alloc from this. (Maybe add it?)
> 
> No, if KFENCE is initialized through kfence_init_late() ->
> kfence_init_pool_late() -> kfence_init_pool().
Thanks for the information.

But as I known, page-alloc does not request kmemleak areas.
So the current kfence_pool_init_late() would cause another kmemleak
warning on unknown freeing. 

Reproducing test: (kfence late enable + kmemleak debug on)

/ # echo 500 > /sys/module/kfence/parameters/sample_interval
[  153.433518] kmemleak: Freeing unknown object at 0xffff0000c0600000
[  153.433804] CPU: 0 PID: 100 Comm: sh Not tainted 5.19.0-rc3-74069-
gde5c208d533a-dirty #1
[  153.434027] Hardware name: linux,dummy-virt (DT)
[  153.434265] Call trace:
[  153.434331]  dump_backtrace+0xdc/0xfc
[  153.434962]  show_stack+0x18/0x24
[  153.435106]  dump_stack_lvl+0x64/0x7c
[  153.435232]  dump_stack+0x18/0x38
[  153.435347]  kmemleak_free+0x184/0x1c8
[  153.435462]  kfence_init_pool+0x16c/0x194
[  153.435587]  param_set_sample_interval+0xe0/0x1c4
[  153.435694]  param_attr_store+0x98/0xf4
[  153.435804]  module_attr_store+0x24/0x3c
[  153.435910]  sysfs_kf_write+0x3c/0x50
...(skip)
[  153.444496] kfence: initialized - using 524288 bytes for 63 objects
at 0x00000000a3236b01-0x00000000901655d3
/ # 

Hence, now there are two issues to solve.
(1) (The original)To prevent the undesired kmemleak scanning on the
kfence pool. As Cataline's suggestion, we can just apply
kmemleak_ignore_phys instead of free it at all. 
ref: https://lore.kernel.org/linux-mm/YrWPg3xIHbm9bFxP@arm.com/

(2) The late-allocated kfence pool doesn't need to go through
kmemleak_free. We can relocate the opeartion to
kfence_init_pool_early() to seperate them. 
That is, kfence_init_pool_early(memblock) has it and
kfence_init_pool_late(page alloc) does not. 

The draft is like the following.

diff --git a/mm/kfence/core.c b/mm/kfence/core.c
index 11a954763be9..a52db7f06c04 100644
--- a/mm/kfence/core.c
+++ b/mm/kfence/core.c
@@ -591,14 +591,6 @@ static unsigned long kfence_init_pool(void)
                addr += 2 * PAGE_SIZE;
        }

-       /*
-        * The pool is live and will never be deallocated from this
point on.
-        * Remove the pool object from the kmemleak object tree, as it
would
-        * otherwise overlap with allocations returned by
kfence_alloc(), which
-        * are registered with kmemleak through the slab post-alloc
hook.
-        */
-       kmemleak_free(__kfence_pool);
-
        return 0;
 }

@@ -611,8 +603,16 @@ static bool __init kfence_init_pool_early(void)

        addr = kfence_init_pool();

-       if (!addr)
+       if (!addr) {
+               /*
+                * The pool is live and will never be deallocated from
this point on.
+                * Ignore the pool object from the kmemleak phys object
tree, as it would
+                * otherwise overlap with allocations returned by
kfence_alloc(), which
+                * are registered with kmemleak through the slab post-
alloc hook.
+                */
+               kmemleak_ignore_phys(__pa(__kfence_pool));
                return true;
+       }

        /*
         * Only release unprotected pages, and do not try to go back
and change

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/9c6fcb1c178a923f2406466a3f9f2345e4e7a1c1.camel%40mediatek.com.

--=-tlhIpc4LLWzE61Oh4jJE
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<html dir=3D"ltr"><head></head><body style=3D"text-align:left; direction:lt=
r;"><div>On Fri, 2022-06-24 at 10:28 +0200, Marco Elver wrote:</div><blockq=
uote type=3D"cite" style=3D"margin:0 0 0 .8ex; border-left:2px #729fcf soli=
d;padding-left:1ex"><div>On Fri, 24 Jun 2022 at 10:20, 'Yee Lee' via kasan-=
dev</div><div>&lt;<a href=3D"mailto:kasan-dev@googlegroups.com">kasan-dev@g=
ooglegroups.com</a>&gt; wrote:</div><blockquote type=3D"cite" style=3D"marg=
in:0 0 0 .8ex; border-left:2px #729fcf solid;padding-left:1ex"><div><br></d=
iv><div>On Thu, 2022-06-23 at 13:59 +0200, Marco Elver wrote:</div><blockqu=
ote type=3D"cite" style=3D"margin:0 0 0 .8ex; border-left:2px #729fcf solid=
;padding-left:1ex"><div>On Thu, 23 Jun 2022 at 13:20, yee.lee via kasan-dev=
</div><div>&lt;<a href=3D"mailto:kasan-dev@googlegroups.com">kasan-dev@goog=
legroups.com</a>&gt; wrote:</div><blockquote type=3D"cite" style=3D"margin:=
0 0 0 .8ex; border-left:2px #729fcf solid;padding-left:1ex"><div><br></div>=
<div>From: Yee Lee &lt;<a href=3D"mailto:yee.lee@mediatek.com">yee.lee@medi=
atek.com</a>&gt;</div><div><br></div><div>Use MEMBLOCK_ALLOC_NOLEAKTRACE to=
 skip kmemleak registration when</div><div>the kfence pool is allocated fro=
m memblock. And the kmemleak_free</div><div>later can be removed too.</div>=
</blockquote><div><br></div><div>Is this purely meant to be a cleanup and n=
on-functional change?</div><div><br></div><blockquote type=3D"cite" style=
=3D"margin:0 0 0 .8ex; border-left:2px #729fcf solid;padding-left:1ex"><div=
>Signed-off-by: Yee Lee &lt;<a href=3D"mailto:yee.lee@mediatek.com">yee.lee=
@mediatek.com</a>&gt;</div><div><br></div><div>---</div><div>&nbsp;mm/kfenc=
e/core.c | 18 ++++++++----------</div><div>&nbsp;1 file changed, 8 insertio=
ns(+), 10 deletions(-)</div><div><br></div><div>diff --git a/mm/kfence/core=
.c b/mm/kfence/core.c</div><div>index 4e7cd4c8e687..0d33d83f5244 100644</di=
v><div>--- a/mm/kfence/core.c</div><div>+++ b/mm/kfence/core.c</div><div>@@=
 -600,14 +600,6 @@ static unsigned long kfence_init_pool(void)</div><div>&n=
bsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp=
;&nbsp;&nbsp;&nbsp;addr +=3D 2 * PAGE_SIZE;</div><div>&nbsp;&nbsp;&nbsp;&nb=
sp;&nbsp;&nbsp;&nbsp;&nbsp;}</div><div><br></div><div>-&nbsp;&nbsp;&nbsp;&n=
bsp;&nbsp;&nbsp;&nbsp;/*</div><div>-&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nb=
sp;&nbsp;* The pool is live and will never be deallocated from this</div><d=
iv>point on.</div><div>-&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;* R=
emove the pool object from the kmemleak object tree, as</div><div>it would<=
/div><div>-&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;* otherwise over=
lap with allocations returned by</div><div>kfence_alloc(), which</div><div>=
-&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;* are registered with kmem=
leak through the slab post-alloc</div><div>hook.</div><div>-&nbsp;&nbsp;&nb=
sp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;*/</div><div>-&nbsp;&nbsp;&nbsp;&nbsp;&nbs=
p;&nbsp;&nbsp;kmemleak_free(__kfence_pool);</div></blockquote><div><br></di=
v><div>This appears to only be a non-functional change if the pool is</div>=
<div>allocated early. If the pool is allocated late using page-alloc, then<=
/div><div>there'll not be a kmemleak_free() on that memory and we'll have t=
he</div><div>same problem.</div></blockquote><div><br></div><div>Do you mea=
n the kzalloc(slab_is_available) in memblock_allc()? That</div><div>implies=
 that MEMBLOCK_ALLOC_NOLEAKTRACE has no guarantee skipping</div><div>kmemle=
ak_alloc from this. (Maybe add it?)</div></blockquote><div><br></div><div>N=
o, if KFENCE is initialized through kfence_init_late() -&gt;</div><div>kfen=
ce_init_pool_late() -&gt; kfence_init_pool().</div></blockquote><div>Thanks=
 for the information.</div><div><br></div><div>But as I known, page-alloc d=
oes not request kmemleak areas.</div><div>So the current kfence_pool_init_l=
ate() would cause another kmemleak warning on unknown freeing.&nbsp;</div><=
div><br></div><div>Reproducing test: (kfence late enable + kmemleak debug o=
n)</div><div><br></div><div>/ # echo 500 &gt; /sys/module/kfence/parameters=
/sample_interval</div><div>[&nbsp;&nbsp;153.433518] kmemleak: Freeing unkno=
wn object at 0xffff0000c0600000</div><div>[&nbsp;&nbsp;153.433804] CPU: 0 P=
ID: 100 Comm: sh Not tainted 5.19.0-rc3-74069-gde5c208d533a-dirty #1</div><=
div>[&nbsp;&nbsp;153.434027] Hardware name: linux,dummy-virt (DT)</div><div=
>[&nbsp;&nbsp;153.434265] Call trace:</div><div>[&nbsp;&nbsp;153.434331]&nb=
sp;&nbsp;dump_backtrace+0xdc/0xfc</div><div>[&nbsp;&nbsp;153.434962]&nbsp;&=
nbsp;show_stack+0x18/0x24</div><div>[&nbsp;&nbsp;153.435106]&nbsp;&nbsp;dum=
p_stack_lvl+0x64/0x7c</div><div>[&nbsp;&nbsp;153.435232]&nbsp;&nbsp;dump_st=
ack+0x18/0x38</div><div>[&nbsp;&nbsp;153.435347]&nbsp;&nbsp;kmemleak_free+0=
x184/0x1c8</div><div>[&nbsp;&nbsp;153.435462]&nbsp;&nbsp;kfence_init_pool+0=
x16c/0x194</div><div>[&nbsp;&nbsp;153.435587]&nbsp;&nbsp;param_set_sample_i=
nterval+0xe0/0x1c4</div><div>[&nbsp;&nbsp;153.435694]&nbsp;&nbsp;param_attr=
_store+0x98/0xf4</div><div>[&nbsp;&nbsp;153.435804]&nbsp;&nbsp;module_attr_=
store+0x24/0x3c</div><div>[&nbsp;&nbsp;153.435910]&nbsp;&nbsp;sysfs_kf_writ=
e+0x3c/0x50</div><div>...(skip)</div><div>[&nbsp;&nbsp;153.444496] kfence: =
initialized - using 524288 bytes for 63 objects at 0x00000000a3236b01-0x000=
00000901655d3</div><div>/ #&nbsp;</div><div><br></div><div>Hence, now there=
 are two issues to solve.</div><div>(1) (The original)To prevent the undesi=
red kmemleak scanning on the kfence pool. As Cataline's suggestion, we can =
just apply kmemleak_ignore_phys instead of free it at all.&nbsp;</div><div>=
ref: <a href=3D"https://lore.kernel.org/linux-mm/YrWPg3xIHbm9bFxP@arm.com/"=
>https://lore.kernel.org/linux-mm/YrWPg3xIHbm9bFxP@arm.com/</a></div><div><=
br></div><div>(2) The late-allocated kfence pool doesn't need to go through=
 kmemleak_free. We can relocate the opeartion to kfence_init_pool_early() t=
o seperate them.&nbsp;</div><div>That is, kfence_init_pool_early(memblock) =
has it and kfence_init_pool_late(page alloc) does not.&nbsp;</div><div><br>=
</div><div>The draft is like the following.</div><div><br></div><div>diff -=
-git a/mm/kfence/core.c b/mm/kfence/core.c</div><div>index 11a954763be9..a5=
2db7f06c04 100644</div><div>--- a/mm/kfence/core.c</div><div>+++ b/mm/kfenc=
e/core.c</div><div>@@ -591,14 +591,6 @@ static unsigned long kfence_init_po=
ol(void)</div><div>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&n=
bsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;addr +=3D 2 * PAGE_SIZE;</div><div>=
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;}</div><div><br></div><div>=
-&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;/*</div><div>-&nbsp;&nbsp;&nbsp;=
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;* The pool is live and will never be dealloca=
ted from this point on.</div><div>-&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbs=
p;&nbsp;* Remove the pool object from the kmemleak object tree, as it would=
</div><div>-&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;* otherwise ove=
rlap with allocations returned by kfence_alloc(), which</div><div>-&nbsp;&n=
bsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;* are registered with kmemleak thro=
ugh the slab post-alloc hook.</div><div>-&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbs=
p;&nbsp;&nbsp;*/</div><div>-&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;kmeml=
eak_free(__kfence_pool);</div><div>-</div><div>&nbsp;&nbsp;&nbsp;&nbsp;&nbs=
p;&nbsp;&nbsp;&nbsp;return 0;</div><div>&nbsp;}</div><div><br></div><div>@@=
 -611,8 +603,16 @@ static bool __init kfence_init_pool_early(void)</div><di=
v><br></div><div>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;addr =3D k=
fence_init_pool();</div><div><br></div><div>-&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;=
&nbsp;&nbsp;if (!addr)</div><div>+&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp=
;if (!addr) {</div><div>+&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&n=
bsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;/*</div><div>+&nbsp;&nbsp;&nbsp;&nb=
sp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;=
* The pool is live and will never be deallocated from this point on.</div><=
div>+&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbs=
p;&nbsp;&nbsp;&nbsp;&nbsp;* Ignore the pool object from the kmemleak phys o=
bject tree, as it would</div><div>+&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbs=
p;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;* otherwise overlap=
 with allocations returned by kfence_alloc(), which</div><div>+&nbsp;&nbsp;=
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nb=
sp;&nbsp;* are registered with kmemleak through the slab post-alloc hook.</=
div><div>+&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp=
;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;*/</div><div>+&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;=
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;kmemleak_ignore=
_phys(__pa(__kfence_pool));</div><div>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&=
nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;return true;</di=
v><div>+&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;}</div><div><br></div><di=
v>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;/*</div><div>&nbsp;&nbsp;=
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;* Only release unprotected pages,=
 and do not try to go back and change</div><div></div></body></html>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion on the web visit <a href=3D"https://groups.google.c=
om/d/msgid/kasan-dev/9c6fcb1c178a923f2406466a3f9f2345e4e7a1c1.camel%40media=
tek.com?utm_medium=3Demail&utm_source=3Dfooter">https://groups.google.com/d=
/msgid/kasan-dev/9c6fcb1c178a923f2406466a3f9f2345e4e7a1c1.camel%40mediatek.=
com</a>.<br />

--=-tlhIpc4LLWzE61Oh4jJE--
