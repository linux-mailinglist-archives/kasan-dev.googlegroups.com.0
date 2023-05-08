Return-Path: <kasan-dev+bncBCLL3W4IUEDRBIEN4WRAMGQEK7CK72A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x139.google.com (mail-lf1-x139.google.com [IPv6:2a00:1450:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id 941016FB68B
	for <lists+kasan-dev@lfdr.de>; Mon,  8 May 2023 20:59:45 +0200 (CEST)
Received: by mail-lf1-x139.google.com with SMTP id 2adb3069b0e04-4ec790b902bsf2540921e87.1
        for <lists+kasan-dev@lfdr.de>; Mon, 08 May 2023 11:59:45 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1683572385; cv=pass;
        d=google.com; s=arc-20160816;
        b=ST52DxUOO6NwdZMJJ4kT0Nl3a00oxxR/iJfwxsUBHhzrdU2Tct4VtJtwH9zD64KwVN
         BWQ78p1qcWNfrCUcqDX7AWuhAUb2skn+gclsum0yzCARej+jK8uiRSttKIhxQMbakBud
         HWNyitM496KDj60UWCLjsxNduZ4icupK3xrWg8sQdV7OFn+IXOfziuq515pOLvBI/e8H
         x8iNcMZ1QqE2vlz1sGvZ1wYzIwxiI4f142kgnYwaWI+B/AI/MIrTYLAJnu4FlSc5GrID
         F4xwCTDS9Dhf3AyGzACFXGMi9W1WnpGfkdvCnjfV2wYU8hnmpVw4RXQSwxlJFHGVYe7t
         85hw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :mime-version:references:in-reply-to:message-id:subject:cc:to:from
         :date:sender:dkim-signature;
        bh=7NMUho7hXOFuDL6mvUEu92PIckMQznpf4iFLDAEVpuQ=;
        b=d2QIBl/I1JxbVUF34SM9nAWZknUEQqiNzr5Do1gZiBtYyMyVtNMLWYZHRSbTps9b4K
         rHUNPUx4Mx5m0gxcI6VlR9bB9LjrrsUpFWKmVtELCmcbF9smi9yKc+2oIwhKglXRZNVB
         vHYHgkHHADDQ54vrckoyMn6ajLwwHdEdNaTYcxrz2LkeJDG06gSxVH/AyoPJ7kr4Wjg/
         y4brpMVgBGlxwl+LbCkmtVoeqF0fmFoCPaq+pjOj35Wxi+2iftvykTHbyjrAZxPofS28
         8dw9RqJvW3jwnaIvNlnml6iHcuuLNm44oUQToSaEsL+ocHCjyU3YEOeUUhFskZsT266J
         luyg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@tesarici.cz header.s=mail header.b=oMA1JDBf;
       spf=pass (google.com: domain of petr@tesarici.cz designates 77.93.223.253 as permitted sender) smtp.mailfrom=petr@tesarici.cz;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=tesarici.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1683572385; x=1686164385;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:mime-version:references
         :in-reply-to:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=7NMUho7hXOFuDL6mvUEu92PIckMQznpf4iFLDAEVpuQ=;
        b=QSQqcpVY7W/yB9pZ7hmtvjCBVb2FYdcCXxlphqEPLDP2pxAndNDo+MmOTdeTzyWRB8
         1RlUBuTOIUVQfaMWWjp5v+OGshXuMqrGNRjZfNuAJiJBNfMfVay0WzVatSsHu4E4RBoH
         9Xpv7fJZA/R+zk2Gr1pqqdmEci8jv/rlFEqe9CjdC51S/d1JZMsan8o2ANlU5KYsMEQ+
         sUQvDSv55szadw7z3nvOa9VllLkxsvDqZoZO4euhwSMlaYmttwaOGSInmn177eNdnWkk
         /b76BTdXRYssbdR7/aGGFoX56wd9HcmsKqoUAJ5ph7bUeWNgwswVKaEFVBqgV9gk7IQZ
         OLxg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1683572385; x=1686164385;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=7NMUho7hXOFuDL6mvUEu92PIckMQznpf4iFLDAEVpuQ=;
        b=Mzfsdggpuxpp4kNg9cT3xRbZkalZIATmX+U3+nFiiU8/47DgiD5vWUwUIuy/tYaIco
         q0gpi6Db/kQGC8M9aWVBvRTpDiRkhFLNwFis0qNXNL++fx54TUNd49dJnYXvIsjnaYzL
         zywt6LtnHt2t1HqcWsTj3YbCIeV63NEjODc66uuyoVRYKZVOG1m2GbHj18Zd9MhxarP4
         1TBtLrc2qmHdrrRuPfdM6I+6RjzWvXdJZPVQzqHHoiuqev3VnmbW09W4SUcy3n94hne9
         tZOw+excJNfKDfLWhCagLgWhb+IvXL/7QvGsdmziE86M+qm4WlJ9FWSrpeaiZFjVkbi4
         2uyQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AC+VfDxKqi2V9wjEZu0WqUWGe7TJi2qClN/LE8h+Ed7FPSy5GKx1Ci5W
	PgrQECh8lFHZ5Jm4cotj6HI=
X-Google-Smtp-Source: ACHHUZ4z0UlJ1k1MwkAELsyb0RskrbJFcJy31Degsvk9jZySWRZdaP61XCSBU1pk+Bb2pam8fcCjqg==
X-Received: by 2002:a05:651c:412:b0:2a8:d183:47a5 with SMTP id 18-20020a05651c041200b002a8d18347a5mr38297lja.8.1683572384746;
        Mon, 08 May 2023 11:59:44 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:1606:b0:2ac:81ce:1bc1 with SMTP id
 f6-20020a05651c160600b002ac81ce1bc1ls23538ljq.0.-pod-prod-04-eu; Mon, 08 May
 2023 11:59:43 -0700 (PDT)
X-Received: by 2002:a05:6512:21ad:b0:4ef:ec96:f97 with SMTP id c13-20020a05651221ad00b004efec960f97mr46267lft.6.1683572383450;
        Mon, 08 May 2023 11:59:43 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1683572383; cv=none;
        d=google.com; s=arc-20160816;
        b=gcv/HA6Bu+Q4N/xslNnK1ACmL7eU8zQfowFhARUdbdFMAVRaajOK6xE/spyNEQIhtc
         BDUW9a1R3d8lzh/t6dxMEYqfd5YEALjgqjfMqPv0wyyVNcsSj6pyjdBjzLb0uw1pdD3W
         Es6ecVBxpDQqd3O14Bv6LZFx2SZHHRCSrUEZprr6B59DU9lmaflVnr9cWzW8JJ71Ylvp
         1kJyh5falkRszxqv1TpOWBiCl2EGsh9c5zTXzeoe7o2K5+5tj3ZZK2WCBE2leQD99ek9
         iXD4T4Q4/sE+USQQICFaeOhutoESr/GGYUwAMs2bAtoEo+xfnyymqdJ4Y3D2kwMDCs85
         Q5Rw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=uZkqx7aKUtaW85glkXkWc2KSVWl1+jLzvm0vqmvOK4k=;
        b=0kD7GtEaBxOlIg6l+5rIngdHAW+iBB3e2R5/Gr9iHvXdWx2SaOS0NnJ6IDlf+HMU9x
         GSPgMb96+6TUGV5NgeC86DCswq/LGELhwE+pJkdWt5t6eucLHjA4azI+UIajHEzBV3yX
         x73woiEFDcfbA5dBBtf+/lS/7pkS7fJZ9IMCuBdwm6s7uBKsokT+X0dF0mW6ZzhREhAo
         6OYQcUW5D9KvPPX45nIDoudeRHLyYS8YSqSNKzEA+PiCK4xB/zsi8tO0dR408clu1275
         OY3OX4d1v00YsVS++bJjPIS05pg0KdAsRMXEH8sNzqhzxT7whuOjxLynmsOMwo1q9Mto
         SgNg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@tesarici.cz header.s=mail header.b=oMA1JDBf;
       spf=pass (google.com: domain of petr@tesarici.cz designates 77.93.223.253 as permitted sender) smtp.mailfrom=petr@tesarici.cz;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=tesarici.cz
Received: from bee.tesarici.cz (bee.tesarici.cz. [77.93.223.253])
        by gmr-mx.google.com with ESMTPS id h7-20020a0565123c8700b004f24cc1c786si56604lfv.7.2023.05.08.11.59.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 08 May 2023 11:59:43 -0700 (PDT)
Received-SPF: pass (google.com: domain of petr@tesarici.cz designates 77.93.223.253 as permitted sender) client-ip=77.93.223.253;
Received: from meshulam.tesarici.cz (dynamic-2a00-1028-83b8-1e7a-4427-cc85-6706-c595.ipv6.o2.cz [IPv6:2a00:1028:83b8:1e7a:4427:cc85:6706:c595])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange ECDHE (P-256) server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by bee.tesarici.cz (Postfix) with ESMTPSA id 46D7A15660F;
	Mon,  8 May 2023 20:59:41 +0200 (CEST)
Date: Mon, 8 May 2023 20:59:39 +0200
From: Petr =?UTF-8?B?VGVzYcWZw61r?= <petr@tesarici.cz>
To: Kent Overstreet <kent.overstreet@linux.dev>
Cc: Michal Hocko <mhocko@suse.com>, Suren Baghdasaryan <surenb@google.com>,
 akpm@linux-foundation.org, vbabka@suse.cz, hannes@cmpxchg.org,
 roman.gushchin@linux.dev, mgorman@suse.de, dave@stgolabs.net,
 willy@infradead.org, liam.howlett@oracle.com, corbet@lwn.net,
 void@manifault.com, peterz@infradead.org, juri.lelli@redhat.com,
 ldufour@linux.ibm.com, catalin.marinas@arm.com, will@kernel.org,
 arnd@arndb.de, tglx@linutronix.de, mingo@redhat.com,
 dave.hansen@linux.intel.com, x86@kernel.org, peterx@redhat.com,
 david@redhat.com, axboe@kernel.dk, mcgrof@kernel.org, masahiroy@kernel.org,
 nathan@kernel.org, dennis@kernel.org, tj@kernel.org, muchun.song@linux.dev,
 rppt@kernel.org, paulmck@kernel.org, pasha.tatashin@soleen.com,
 yosryahmed@google.com, yuzhao@google.com, dhowells@redhat.com,
 hughd@google.com, andreyknvl@gmail.com, keescook@chromium.org,
 ndesaulniers@google.com, gregkh@linuxfoundation.org, ebiggers@google.com,
 ytcoode@gmail.com, vincent.guittot@linaro.org, dietmar.eggemann@arm.com,
 rostedt@goodmis.org, bsegall@google.com, bristot@redhat.com,
 vschneid@redhat.com, cl@linux.com, penberg@kernel.org,
 iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com, glider@google.com,
 elver@google.com, dvyukov@google.com, shakeelb@google.com,
 songmuchun@bytedance.com, jbaron@akamai.com, rientjes@google.com,
 minchan@google.com, kaleshsingh@google.com, kernel-team@android.com,
 linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org,
 iommu@lists.linux.dev, linux-arch@vger.kernel.org,
 linux-fsdevel@vger.kernel.org, linux-mm@kvack.org,
 linux-modules@vger.kernel.org, kasan-dev@googlegroups.com,
 cgroups@vger.kernel.org
Subject: Re: [PATCH 00/40] Memory allocation profiling
Message-ID: <20230508205939.0b5b485c@meshulam.tesarici.cz>
In-Reply-To: <ZFkjRBCExpXfI+O5@moria.home.lan>
References: <20230501165450.15352-1-surenb@google.com>
	<ZFIMaflxeHS3uR/A@dhcp22.suse.cz>
	<CAJuCfpHxbYFxDENYFfnggh1D8ot4s493PQX0C7kD-JLvixC-Vg@mail.gmail.com>
	<ZFN1yswCd9wRgYPR@dhcp22.suse.cz>
	<ZFfd99w9vFTftB8D@moria.home.lan>
	<20230508175206.7dc3f87c@meshulam.tesarici.cz>
	<ZFkb1p80vq19rieI@moria.home.lan>
	<20230508180913.6a018b21@meshulam.tesarici.cz>
	<ZFkjRBCExpXfI+O5@moria.home.lan>
X-Mailer: Claws Mail 4.1.1 (GTK 3.24.37; x86_64-suse-linux-gnu)
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: petr@tesarici.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@tesarici.cz header.s=mail header.b=oMA1JDBf;       spf=pass
 (google.com: domain of petr@tesarici.cz designates 77.93.223.253 as permitted
 sender) smtp.mailfrom=petr@tesarici.cz;       dmarc=pass (p=NONE sp=NONE
 dis=NONE) header.from=tesarici.cz
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

On Mon, 8 May 2023 12:28:52 -0400
Kent Overstreet <kent.overstreet@linux.dev> wrote:

> On Mon, May 08, 2023 at 06:09:13PM +0200, Petr Tesa=C5=99=C3=ADk wrote:
> > Sure, although AFAIK the index does not cover all possible config
> > options (so non-x86 arch code is often forgotten). However, that's the
> > less important part.
> >=20
> > What do you do if you need to hook something that does conflict with an
> > existing identifier? =20
>=20
> As already happens in this patchset, rename the other identifier.
>=20
> But this is C, we avoid these kinds of conflicts already because the
> language has no namespacing

This statement is not accurate, but I agree there's not much. Refer to
section 6.2.3 of ISO/IEC9899:2018 (Name spaces of identifiers).

More importantly, macros also interfere with identifier scoping, e.g.
you cannot even have a local variable with the same name as a macro.
That's why I dislike macros so much.

But since there's no clear policy regarding macros in the kernel, I'm
merely showing a downside; it's perfectly fine to write kernel code
like this as long as the maintainers agree that the limitation is
acceptable and outweighed by the benefits.

Petr T

> it's going to be a pretty rare situtaion
> going forward. Most of the hooking that will be done is done with this
> patchset, and there was only one identifier that needed to be renamed.
>=20

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/20230508205939.0b5b485c%40meshulam.tesarici.cz.
