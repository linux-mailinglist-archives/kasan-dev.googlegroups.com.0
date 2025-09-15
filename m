Return-Path: <kasan-dev+bncBCKPFB7SXUERBXVNT7DAMGQEW7ZO6LI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x640.google.com (mail-pl1-x640.google.com [IPv6:2607:f8b0:4864:20::640])
	by mail.lfdr.de (Postfix) with ESMTPS id F288FB57404
	for <lists+kasan-dev@lfdr.de>; Mon, 15 Sep 2025 11:05:36 +0200 (CEST)
Received: by mail-pl1-x640.google.com with SMTP id d9443c01a7336-26776d064e7sf4724135ad.2
        for <lists+kasan-dev@lfdr.de>; Mon, 15 Sep 2025 02:05:36 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757927135; cv=pass;
        d=google.com; s=arc-20240605;
        b=Hxu3640kika3C7zjrTuEDmd/WnF2IAWGb50VkGClZKyipHCIEn0J6VFKWOj14WLGSV
         Az5wNe1TA18IUVma0UDDxJ5hRWyjPyTYthtKdl/f/Inm2vc4WoQ8KkKTq8JpMXZHTrbE
         BmCvKXzswFdqzo8TYj0OeP2b0rP6eKVuLfdxb5TJcW/NrdwnOppnwTfi2LmxxrrYrDqK
         mb1J3EIAMWblOulB98Yhd7k06v991REj1NM6D4B0idm1ZjYlcHTJo5pj51pcmpXcxXLh
         qkkN2o6zhpCuxr2OeCQdXfe6uqQFy723BDm3OJzCBJd7LT75jG3X145xHQFQn/1cdCUh
         V/8Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:dkim-signature;
        bh=yt55b7nBdzJYvdffC7OoQ2yOC8a5ZTyXQhCqgPnvh4o=;
        fh=TlW0Ccc7lBmLroF/GGTUo7BeuiqryGeYsCVyVwqRS1I=;
        b=GaBac/XNbuIlGru01ycxB2n7iYV+VkzdNX+/7k52cGDBZlbRqou/FbcEevPmYztNwa
         tcETMClzoGx1CziSXq2aUVwsDCIKbhIBxEY9LkGyaJ6JmXJ8gELh5lzcbWz42HRsaVYF
         LZikcMqWCw3k82r6h8MECcTaO54Jk1QL+VGq1TZPFHueEMA/sakfej5lOCm3fsrxSA6L
         12EZpnO22BcelLCLZVGP4AE93bvpdjRSTPp5BNv41rP1o4QxtSTGQwaOVsOGKbvSLpon
         Llu/49qzBS4fFns6VVsh+y0vjJG3fH5x8xULSc7hbCBPzhXpq/QOppGa3SiXCp14xfF9
         MfRg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=SfVoNwF1;
       spf=pass (google.com: domain of bhe@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=bhe@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757927135; x=1758531935; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:from:to:cc:subject
         :date:message-id:reply-to;
        bh=yt55b7nBdzJYvdffC7OoQ2yOC8a5ZTyXQhCqgPnvh4o=;
        b=Tp6XHqhS+rfFjpjLyatiAeoGtNTQG0u8U2htY6YiMiA+1Zjla0ZbK8aoAuQfrOMFDN
         o6aSyhu+nnB+rzb+8Tem11W08MoRDYc3UwovWH9pnztbL1wc0SYj1Fhs50yV1M8QQFVa
         eqRYLUsK7Mb/dEOdYM7E6BnWwakiw9++WvxfK7pmptBWumCwbtjjMtyphqsSdF2UpEDD
         2urQcyePxlEMXzHrBRsOIuwgSETUQ/6I24AJMlzwbG3S2uONZ5z90rtshDSmBYjEFeSf
         WSBn9VWv/Db1g0H0J9ruT3tQ19CYW0v9RQzMaHzzWMM/xb/Tw77LKTTlxzGTigq2XTCX
         V8TA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757927135; x=1758531935;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=yt55b7nBdzJYvdffC7OoQ2yOC8a5ZTyXQhCqgPnvh4o=;
        b=v06b+QVhNdkHyozhpGfbtIP+1NjEw3ZFC0yv8MfNXEN5Xzu9CY6R0+tQsO7eBv9/RI
         GM8b0rCDddkAcqu0VEetKx70wGGlyY+IZgVCp+1VYqZM2jDWVhYAYJnjxm04GZDJOQqs
         nIuH2qJ0xZPCHvsa4/gXoVK/AGH4y8e/sxlKuHNfpY4kkGa4hImOOeJIBq3xPXHJecuP
         rPHvxzkfgXxBrvfLLmUedTu1OirYIVFAI95aN8KbYJh02IhxNLjhUI4ovN2j6ZACObr2
         rYOzXuX2A6vGkdt9t+r6KLoVbk0eEFMIqIc86CSvAYgUUsLoW+Z+t4I8rRkY5kUmS5zJ
         /8sA==
X-Forwarded-Encrypted: i=2; AJvYcCWyzjKjBgi8mJhWBuprpxi6nQk73m4bJMPFHhz/+d276ljtoc7KYsRBX9vNavVmgykjcZZ9GQ==@lfdr.de
X-Gm-Message-State: AOJu0YxekzdSgWbqUbitRJMrAZNd8zK2ka47HPH5reeIun8j1SIZXepn
	QTTfNCEtzvVjE7Gu0EXOdjLL+zDXgiSVMVVRAdVUAdbQs19awCHI/gPQ
X-Google-Smtp-Source: AGHT+IH6hx3M2E5ckmGf6/tbhsM8EqMsGen28SMak356TtHExVSjcdGAPguABMAVqxSLsGMbNNV4Og==
X-Received: by 2002:a17:902:ce90:b0:24c:c1b3:604 with SMTP id d9443c01a7336-25d243eff78mr176703885ad.1.1757927135461;
        Mon, 15 Sep 2025 02:05:35 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd6Y7wFiADxmKlTrPO3Ex41nIm3sUkeS6voAZMNf61UgvQ==
Received: by 2002:a17:902:cf4b:b0:267:ac34:9e67 with SMTP id
 d9443c01a7336-267ac34af2fls1351665ad.2.-pod-prod-07-us; Mon, 15 Sep 2025
 02:05:34 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCX3Viu9gDgI37VF6tw64Rzo1d2cyiCRZAFSGi1646hZjznnYDjcB0QMWc/ZLBJ08iOhrpsmqDqhXpo=@googlegroups.com
X-Received: by 2002:a17:902:f54d:b0:267:95ad:8cb8 with SMTP id d9443c01a7336-26795ad8e4fmr17467925ad.44.1757927133757;
        Mon, 15 Sep 2025 02:05:33 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1757927133; cv=none;
        d=google.com; s=arc-20240605;
        b=Jci4knx5XAtGmYPtntJujfisMORqmNrBdZiI2MbDrTWSeYo5QglN7MluLX2eMKQ13T
         GGhNqoVstDksIukKkt4Xp6NZjBf9u3Nt/NK1rN5B8KQ9RI5fIk8VOCNj9irFJELACRyG
         NzArt2SsgRo6+tcPqxhMILSgcG9fIhP0MI7W70ik34LzNPaw7AIBLaT8Zt45uDZlKXWO
         f8543lFbFAxpwoeR95fJIYRIk+lXhG1fwP+S1vK/kIi5DrJNnRMMBGNS7dGDo91uceGW
         a2DBSv7Esb4qCmXuzGXDSqeIgpKdkpudl8bryukzm0Y0b5icxAoyHyy78IuT5X2fGRNp
         vlXw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=KvJ9L1p3rbhqt/V3V+FfG1d8fzkSxXKReu1b/znpF7c=;
        fh=GR+ceodrJOyTQ0CLbhPvIW8Q/qIAKR/ZHcCENq2A82I=;
        b=SUPF/WQc7gakjoXVGCIwwNSl11zNnAeSy2LtSbpTRhoZk7AAnc/F/XZpbT5qp+LA9s
         qRz8RE3+PpnQ5upvZTCRfKOMTYtPBqoJx8XiM4b1HDBDHaD5KUXlwdFXRSZeZdpOl8+i
         5kc1WGz74ZqekedEKXY/O+RpDkvTLis7np/BuwvGFt1DXHPK/VqbSZxWCRJwZwA+KCuL
         YTwKNzBpGZNqehGI/4BlTC7IREmKbc8ny/Gmnulbik3OUC6w+otnPvI7iLjlvH4zNAU3
         I8GIXghkMvqJPCEEQ0uz653tqbK+mbT4r9Gm/tB8zfPaWy7TQLalhYoGboPCd/du1ZPj
         +46Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=SfVoNwF1;
       spf=pass (google.com: domain of bhe@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=bhe@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.129.124])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-267251c74c0si614165ad.3.2025.09.15.02.05.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 15 Sep 2025 02:05:33 -0700 (PDT)
Received-SPF: pass (google.com: domain of bhe@redhat.com designates 170.10.129.124 as permitted sender) client-ip=170.10.129.124;
Received: from mx-prod-mc-08.mail-002.prod.us-west-2.aws.redhat.com
 (ec2-35-165-154-97.us-west-2.compute.amazonaws.com [35.165.154.97]) by
 relay.mimecast.com with ESMTP with STARTTLS (version=TLSv1.3,
 cipher=TLS_AES_256_GCM_SHA384) id us-mta-351-88ufwEDMO5aVH_vHDZb24g-1; Mon,
 15 Sep 2025 05:05:29 -0400
X-MC-Unique: 88ufwEDMO5aVH_vHDZb24g-1
X-Mimecast-MFC-AGG-ID: 88ufwEDMO5aVH_vHDZb24g_1757927127
Received: from mx-prod-int-03.mail-002.prod.us-west-2.aws.redhat.com (mx-prod-int-03.mail-002.prod.us-west-2.aws.redhat.com [10.30.177.12])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by mx-prod-mc-08.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTPS id CF3DC18002CA;
	Mon, 15 Sep 2025 09:05:26 +0000 (UTC)
Received: from localhost (unknown [10.72.112.195])
	by mx-prod-int-03.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTPS id BA10719560A2;
	Mon, 15 Sep 2025 09:05:24 +0000 (UTC)
Date: Mon, 15 Sep 2025 17:05:19 +0800
From: "'Baoquan He' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrey Konovalov <andreyknvl@gmail.com>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>, snovitoll@gmail.com,
	glider@google.com, dvyukov@google.com, elver@google.com,
	linux-mm@kvack.org, vincenzo.frascino@arm.com,
	akpm@linux-foundation.org, kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org, kexec@lists.infradead.org,
	sj@kernel.org, lorenzo.stoakes@oracle.com,
	christophe.leroy@csgroup.eu
Subject: Re: [PATCH v3 00/12] mm/kasan: make kasan=on|off work for all three
 modes
Message-ID: <aMfWz4gwFNMx7x82@MiWiFi-R3L-srv>
References: <20250820053459.164825-1-bhe@redhat.com>
 <CA+fCnZdfv+D7sfRtWgbbFAmWExggzC2by8sDaK7hXfTS7viY8w@mail.gmail.com>
 <aLlJtTeNMdtZAA9B@MiWiFi-R3L-srv>
 <CA+fCnZf2fGTQ6PpoKxDqkOtwcdwyPYx2cFwQw+3xAjOVxjoh6w@mail.gmail.com>
 <75a2eb31-3636-44d4-b2c9-3a24646499a4@gmail.com>
 <CA+fCnZf7jYPUyqHqonWhDKVi9eeN6aaaByMTBYCQrv2-8+hngQ@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <CA+fCnZf7jYPUyqHqonWhDKVi9eeN6aaaByMTBYCQrv2-8+hngQ@mail.gmail.com>
X-Scanned-By: MIMEDefang 3.0 on 10.30.177.12
X-Original-Sender: bhe@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=SfVoNwF1;
       spf=pass (google.com: domain of bhe@redhat.com designates
 170.10.129.124 as permitted sender) smtp.mailfrom=bhe@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
X-Original-From: Baoquan He <bhe@redhat.com>
Reply-To: Baoquan He <bhe@redhat.com>
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

On 09/05/25 at 10:34pm, Andrey Konovalov wrote:
> On Fri, Sep 5, 2025 at 7:12=E2=80=AFPM Andrey Ryabinin <ryabinin.a.a@gmai=
l.com> wrote:
> >
> > > But have you tried running kasan=3Doff + CONFIG_KASAN_STACK=3Dy +
> > > CONFIG_VMAP_STACK=3Dy (+ CONFIG_KASAN_VMALLOC=3Dy)? I would expect th=
is
> > > should causes crashes, as the early shadow is mapped as read-only and
> > > the inline stack instrumentation will try writing into it (or do the
> > > writes into the early shadow somehow get ignored?..).
> >
> > It's not read-only, otherwise we would crash very early before full sha=
dow
> > setup and won't be able to boot at all. So writes still happen, and sha=
dow
> > checked, but reports are disabled.
> >
> > So the patchset should work, but it's a little bit odd feature. With ka=
san=3Doff we still
> > pay x2-x3 performance penalty of compiler instrumentation and get nothi=
ng in return.
> > So the usecase for this is if you don't want to compile and manage addi=
tional kernel binary
> > (with CONFIG_KASAN=3Dn) and don't care about performance at all.

Thanks a lot for your careful reviewing, and sorry for late reply.

About kasan=3Doff, we use static key to detect that, wondering if we will
have x2-x3 performance penalty. Not only can kdump get the benefit, but I
can think of one case where people may use kasan enabled kernel to detect
MM issues, while use kasan=3Doff to make sure kasan code itself won't make
trouble. E.g you tested a normal kernel and it has no problem, while
kasan enabled kernel will trigger issue, sometime do we doubt kasan
code? In this case, kasan=3Doff can prove its inonence?

This could be trivial, while I don't see much kasan=3Doff introducing will
impact the old kasan performance and stir the current kasan implementation
code. We have got the kasan_arch_is_ready() anyway.


>=20
> Ack. So kasan=3Doff would work but it's only benefit would be to avoid
> the RAM overhead.

Right, I built kernel with below configs on, kasan=3Doff|on works very
well.

=3D=3D=3D=3D=3D
CONFIG_KASAN=3Dy
CONFIG_CC_HAS_KASAN_MEMINTRINSIC_PREFIX=3Dy
CONFIG_KASAN_GENERIC=3Dy
CONFIG_KASAN_INLINE=3Dy
CONFIG_KASAN_STACK=3Dy
CONFIG_KASAN_VMALLOC=3Dy
CONFIG_KASAN_KUNIT_TEST=3Dm
...
CONFIG_VMAP_STACK=3Dy
=3D=3D=3D=3D=3D

>=20
> Baoquan, I'd be in favor of implementing kasan.vmalloc=3Doff instead of
> kasan=3Doff. This seems to both (almost) solve the RAM overhead problem
> you're having (AFAIU) and also seems like a useful feature on its own
> (similar to CONFIG_KASAN_VMALLOC=3Dn but via command-line). The patches
> to support kasan.vmalloc=3Doff should also be orthogonal to the
> Sabyrzhan's series.
>=20
> If you feel strongly that the ~1/8th RAM overhead (coming from the
> physmap shadow and the slab redzones) is still unacceptable for your
> use case (noting that the performance overhead (and the constant
> silent detection of false-positive bugs) would still be there), I
> think you can proceed with your series (unless someone else is
> against).

Yeah, that would be great if we can also avoid any not needed memory
consumption for kdump.

>=20
> I also now get what you meant that with your patches for the kasan=3Doff
> support, Sabyrzhan's CONFIG_ARCH_DEFER_KASAN would not be required
> anymore: as every architecture would need a kasan_enabled() check,
> every architecture would effectively need the CONFIG_ARCH_DEFER_KASAN
> functionality (i.e. the static key to switch off KASAN).

Exactly. In this case, the code with the static key enabling or
disabling is clearer than CONFIG_ARCH_DEFER_KASAN setting or not.

>=20
> Nevertheless, I still like the unification of the static keys usage
> and the KASAN initialization calls that the Sabyrzhan's series
> introduces, so I would propose to rebase your patches on top of his
> (even though you would remove CONFIG_ARCH_DEFER_KASAN, but that seems
> like a simple change) or pick out the related parts from his patches
> (but this might not be the best approach in case someone discovers a
> reason why kasan=3Doff is a bad idea and we need to abandon the
> kasan=3Doff series).

Here I understand your reviewing policy. While I would like to explain a
little about my posting. I planned to do this job in 2023, made draft
patches on x86 for generic kasan, I dind't go further to try sw_tags
mode on arm64 because other things interrupted me. This year, I made
plan to disable some kernel features not necessary for kdump kernel,
mainly by adding kernel parameter like ima=3D I made, and later the
kasan=3Doff.

aa9bb1b32594 ima: add a knob ima=3D to allow disabling IMA in kdump kernel

When I made patch and posted, I didn't see Sabyrzhan's patches because I
usually don't go through mm mailing list. If I saw his patch earlier, I
would have suggested him to solve this at the same time.

About Sabyrzhan's patch sereis, I have picked up part of his patches and
credit the author to Sabyrzhan in below patchset.

[PATCH 0/4] mm/kasan: remove kasan_arch_is_ready()
https://lore.kernel.org/all/20250812130933.71593-1-bhe@redhat.com/T/#u

About reposting of this series, do you think which one is preferred:

1) Firstly merge Sabyrzhan's patch series, I reverted them and apply for
   my patchset.

2) Credit the author of patch 1,2,3 of this patch series to Sabyrzhan
   too as below, because Sabyrzhan do the unification of the static keys
   usage and the KASAN initialization calls earlier:

[PATCH v3 01/12] mm/kasan: add conditional checks in functions to return di=
rectly if kasan is disabled
[PATCH v3 02/12] mm/kasan: move kasan=3D code to common place
[PATCH v3 03/12] mm/kasan/sw_tags: don't initialize kasan if it's disabled

commit ac4004af0e1e8798d11c9310e500a88116d90271
Author: Baoquan He <bhe@redhat.com>
Date:   Mon Jan 2 08:58:36 2023 +0800

    x86/kasan: check if kasan is available

commit cddd343bdbf5d0331695da8100380fc4b8b47464
Author: Baoquan He <bhe@redhat.com>
Date:   Sun Jan 1 20:57:51 2023 +0800

    mm/kasan: allow generic and sw_tags to be set in kernel cmdline
   =20
    Signed-off-by: Baoquan He <bhe@redhat.com>

commit b149886995ecb2e464fee0cdd3a814035fc87226
Author: Baoquan He <bhe@redhat.com>
Date:   Sun Jan 1 21:07:29 2023 +0800

    x86/kasan: allow to disable kasan during boot time

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/a=
MfWz4gwFNMx7x82%40MiWiFi-R3L-srv.
