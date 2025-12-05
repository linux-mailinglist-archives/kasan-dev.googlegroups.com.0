Return-Path: <kasan-dev+bncBCKPFB7SXUERBXMPZLEQMGQE5NNF64Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x339.google.com (mail-ot1-x339.google.com [IPv6:2607:f8b0:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id D8A39CA65E3
	for <lists+kasan-dev@lfdr.de>; Fri, 05 Dec 2025 08:21:03 +0100 (CET)
Received: by mail-ot1-x339.google.com with SMTP id 46e09a7af769-7c7595cde21sf3309223a34.2
        for <lists+kasan-dev@lfdr.de>; Thu, 04 Dec 2025 23:21:03 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1764919262; cv=pass;
        d=google.com; s=arc-20240605;
        b=FJVCwDHDseJTHObcpLcSAYM2wNFNm3SuR6r6V49wEiGtnetPyimqW8KmMpbKUmraE/
         BIk9TyDDU7tyGJ16rty21D6CgyvZZEPKWhNBNkM/J5vh0E4TbcmFlVQfQULOfc60wLL6
         sSGECY1FNIyCeLYSJ2BTErLn/eWLdz3cq1tq9/6r591pZNNOa8yn3pHc9vawp0bEAlah
         dwtgl7RNQeWnRVAmRWN4wlxmDL0dQkObJzruOnCPhTAZZvnLh1Jm0ZwUBV7bxEZWS0ej
         KQJtwH1V7MH3ZihwSsqcrYPhZqEh6+0/jUM0gVLDRebPUNRcZVo5yOx1AnumJTuLYeXm
         jMvg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:dkim-signature;
        bh=Bh0vTTOM9cM78bEoTtzykC2wYm9Jkp1DTfsuZBrcuF0=;
        fh=fdSHFQ1G0lLb3T/kBtHAfnKhgYSJsWI5TFHSN3jLgR8=;
        b=j5omziUm60r0m1jim2xpKJjoWkZf44ghuVzYH27Y7VxSDDJSN9Du5lRl1NUaApjiYY
         S4MfkaMnjxPmUICIVX+sbVD4QN829MI0XMCPVNo9+ys957AiEO1gwlVVDX6S5yrCaBiL
         VsZoOov/QjiEl2p8JOn7AOLDjTt16asDVMwf2eQcPLfi/ZW7CJYdmvw9WJjOGQ57N+WN
         xQjOMaBJvfFjA8/Gl7PkagSOzQgRfb1XTcw0QawxGvbGBBKibNe8otaUkdxD8UJ5SssS
         +e3l4+rKTe0IDMfb2UP/cnon8N06Aakyx6L2NoJ2O30xQ99U2z5kab26G8yMt0N7hu2A
         THxg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=BhJ61rdo;
       spf=pass (google.com: domain of bhe@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=bhe@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1764919262; x=1765524062; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:from:to:cc:subject
         :date:message-id:reply-to;
        bh=Bh0vTTOM9cM78bEoTtzykC2wYm9Jkp1DTfsuZBrcuF0=;
        b=mDQMxSRGQSPX0yYov0TbEKJp43Izo/IyHL7YfvaNx3ISAex6o6cGmUV1zr8WZYYdZ4
         mBD8WRIGW8O4Ujk0BQURQXHXXbCVBxLuwD8RfqVOuGi287xNWm0NHOzssMTNanHavNqn
         95sDwgCBeVBtqhyhLbMbW/5XT1Iixt+Dxe5l0lWNGvF0LmItjO1hhvY7oyrwHzyzhh1w
         +IiodOb+ao+d/stTcgIFV2fPPvF2SsOv7qMA2hgOGA1yfjl+3SDzkpWRUk1rwQnmuDyP
         7Smz64NdTZX+B1+43GZMPQKtA79Jb5BtuTLZp99nShR/OigOt5MwTlT9YVNhVlxvqjz0
         pU1w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1764919262; x=1765524062;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=Bh0vTTOM9cM78bEoTtzykC2wYm9Jkp1DTfsuZBrcuF0=;
        b=SYKm59AAToLDC/45Ob7aSH2MVcL6FeLos+MrlPauJedlPuUob2gbpTZM4gsLMxAl2D
         X+YNBZxuFRVhKR8WBgQLgiDQ3I3GyP1JnN6SslWqyfchti2BW92B4mhiPpN6NLYVohQb
         2gVsGDtbp9WzJF4jxc11KhdIf2EL4I8/80fJDQZSctCgCgI7nWquOQeGfbhQyEX19Plf
         T2MPREeXEfwLINekeAUokDLu24z89vWZJqf8XrpC5HvC4SOtLqZZTeuSxqreaRGw80+J
         LlY/2y635KXIn/lz7AC7z5lfTX2iovrPOeUD2NgyaCLFwlFMPwn/IWvcOfZaaJElIfr3
         MW8g==
X-Forwarded-Encrypted: i=2; AJvYcCURw1Its3H4OveCiJjE1M9QT/JHFk3cA7NMSsILlPZBWB4bPs2/JPbqMzPDanIHENdQHLq67Q==@lfdr.de
X-Gm-Message-State: AOJu0YxkYXeojMs/qTa4shQF6oUuS10/GaC0+j1oMtDAsVwprrca0DQX
	h7lbvyDpeiyNzpSM3bSG+/wlOdYc8rcvB2NuEEU64FtkKlWt+Toj+eba
X-Google-Smtp-Source: AGHT+IEs63VoZ5AffxQCyh0b098quRSe+63UQgbqo46wrZ5Fpm0vlXip/LbDOBieilytU3YM2P/hig==
X-Received: by 2002:a05:6830:439e:b0:7c7:6219:6852 with SMTP id 46e09a7af769-7c94db86ebfmr6479946a34.28.1764919262112;
        Thu, 04 Dec 2025 23:21:02 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+bIdyIb25Pq8qWyDHoYIBb+w4jGy7qcGf6CQ2DJaQc64g=="
Received: by 2002:a05:6820:28c1:b0:657:5773:7b4b with SMTP id
 006d021491bc7-6597d0d680bls554005eaf.1.-pod-prod-03-us; Thu, 04 Dec 2025
 23:21:01 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCX74rAE3SkYtOErzeEJ4raMC+4rdmhFxk4LaWjFO/UvmypvMHoTZCSpe62KQ371k9JbvKq1jBiIDQk=@googlegroups.com
X-Received: by 2002:a05:6830:919:b0:7c7:66f7:2caf with SMTP id 46e09a7af769-7c94dab06dbmr5832838a34.10.1764919261116;
        Thu, 04 Dec 2025 23:21:01 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1764919261; cv=none;
        d=google.com; s=arc-20240605;
        b=TZ1AlDVexad+nXDoz2INDh0XVEiX20yGQ4bVAr0WLmoZbBwMuUQhHU1cBc9jGMEOgK
         NjCaX57vuC9We5goXX8qeehTRpxOd65MCRlBvX9XgxLjJs3TtvC8JJUNwiPIAxyNvsz3
         /K3caazJuVU2shYH7NidVasMKl/f3W/soRXF808Fk+Ah4nIT5l9qqERxvVlDRX25eO1z
         E4EktSaERiSTgIHOYs0T9EDWU0n2DvnhzEaeoaTqGuHomli0JGxxJh+9BG1joA5o9ev4
         8G+jNUbnODAte2ZutWlJAFYykezzb22GgeD9IcLKc3Pg1PuKm6xNP52WKY1FERqckN/5
         9ZKg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=Qz0Looyy1EKTh6igJJhb5SyOqLVdyy67umD/p6pJLsU=;
        fh=bMZBJix3YMSVI/m5jYA+cZd5+5N920UloQTCzaIamYQ=;
        b=aR/tUz6mWre9LIGFFnYSZGUIAYRsyMFDtYQpxvllwNStl1WTd0dpiwdd6cXtV+qLUu
         yAlVq/5tXazALmBtDjUPv099lzKHSwd6aKdCndE55q0ieGQb2fpnm7UV6N6yxyeUyZZ9
         ebsI4CPtcjhWcdd9p98+OMVNPX48SVdOVZVOv9LQnsAz3Nbn3fDbJ0UFQGOvZ8QZaH2C
         Th34oY4D4Rv10wqj6nYCecpeT1YLiMOLLPx0o2SV3vhKpDmPHKzGsR/RYE7ehWWn6GQT
         3ykdz4GpDjkVHuWETEv0xUslRud20rBH0/rdwA6A6cP5i9q6cX3zvvUipa53qTbl6lzc
         2xaQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=BhJ61rdo;
       spf=pass (google.com: domain of bhe@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=bhe@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.129.124])
        by gmr-mx.google.com with ESMTPS id 46e09a7af769-7c95a6be254si206031a34.0.2025.12.04.23.21.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 04 Dec 2025 23:21:00 -0800 (PST)
Received-SPF: pass (google.com: domain of bhe@redhat.com designates 170.10.129.124 as permitted sender) client-ip=170.10.129.124;
Received: from mx-prod-mc-01.mail-002.prod.us-west-2.aws.redhat.com
 (ec2-54-186-198-63.us-west-2.compute.amazonaws.com [54.186.198.63]) by
 relay.mimecast.com with ESMTP with STARTTLS (version=TLSv1.3,
 cipher=TLS_AES_256_GCM_SHA384) id us-mta-433-SWZoQuqHO1mLKMvsCtHm1A-1; Fri,
 05 Dec 2025 02:20:54 -0500
X-MC-Unique: SWZoQuqHO1mLKMvsCtHm1A-1
X-Mimecast-MFC-AGG-ID: SWZoQuqHO1mLKMvsCtHm1A_1764919252
Received: from mx-prod-int-05.mail-002.prod.us-west-2.aws.redhat.com (mx-prod-int-05.mail-002.prod.us-west-2.aws.redhat.com [10.30.177.17])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by mx-prod-mc-01.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTPS id EBD551956055;
	Fri,  5 Dec 2025 07:20:51 +0000 (UTC)
Received: from localhost (unknown [10.72.112.128])
	by mx-prod-int-05.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTPS id ADBA01953986;
	Fri,  5 Dec 2025 07:20:50 +0000 (UTC)
Date: Fri, 5 Dec 2025 15:20:46 +0800
From: "'Baoquan He' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrey Konovalov <andreyknvl@gmail.com>
Cc: linux-mm@kvack.org, ryabinin.a.a@gmail.com, glider@google.com,
	dvyukov@google.com, vincenzo.frascino@arm.com,
	akpm@linux-foundation.org, kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org, kexec@lists.infradead.org,
	elver@google.com, sj@kernel.org, lorenzo.stoakes@oracle.com,
	snovitoll@gmail.com, christophe.leroy@csgroup.eu
Subject: Re: [PATCH v4 01/12] mm/kasan: add conditional checks in functions
 to return directly if kasan is disabled
Message-ID: <aTKHzmxR3JA2R7qD@fedora>
References: <20251128033320.1349620-1-bhe@redhat.com>
 <20251128033320.1349620-2-bhe@redhat.com>
 <CA+fCnZfDYHUVKX-hdX3SgmuvJEU-U+MuUJGjs-wJJnfRDHz2sw@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <CA+fCnZfDYHUVKX-hdX3SgmuvJEU-U+MuUJGjs-wJJnfRDHz2sw@mail.gmail.com>
X-Scanned-By: MIMEDefang 3.0 on 10.30.177.17
X-Original-Sender: bhe@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=BhJ61rdo;
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

On 12/04/25 at 05:38pm, Andrey Konovalov wrote:
> On Fri, Nov 28, 2025 at 4:33=E2=80=AFAM Baoquan He <bhe@redhat.com> wrote=
:
> >
> > The current codes only check if kasan is disabled for hw_tags
> > mode. Here add the conditional checks for functional functions of
> > generic mode and sw_tags mode.
> >
> > This is prepared for later adding kernel parameter kasan=3Don|off for
> > all three kasan modes.
> >
> > Signed-off-by: Baoquan He <bhe@redhat.com>
> > ---
> >  mm/kasan/generic.c    | 17 +++++++++++++++--
> >  mm/kasan/init.c       |  6 ++++++
> >  mm/kasan/quarantine.c |  3 +++
> >  mm/kasan/report.c     |  4 +++-
> >  mm/kasan/shadow.c     | 11 ++++++++++-
> >  mm/kasan/sw_tags.c    |  3 +++
> >  6 files changed, 40 insertions(+), 4 deletions(-)
> >
> > diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
> > index 2b8e73f5f6a7..aff822aa2bd6 100644
> > --- a/mm/kasan/generic.c
> > +++ b/mm/kasan/generic.c
> > @@ -214,12 +214,13 @@ bool kasan_byte_accessible(const void *addr)
> >
> >  void kasan_cache_shrink(struct kmem_cache *cache)
> >  {
> > -       kasan_quarantine_remove_cache(cache);
> > +       if (kasan_enabled())
>=20
> Please move these checks to include/linux/kasan.h and add __helpers to
> consistent with how it's done for other KASAN annotation calls.
> Otherwise eventually these checks start creeping into lower level
> functions and the logic of checking when and whether KASAN is enabled
> becomes a mess.

Not sure if I got it correctly. Are you suggesting it should be done
like kasan_populate_vmalloc()/__kasan_populate_vmalloc(),
kasan_release_vmalloc()/__kasan_release_vmalloc()?

>=20
>=20
>=20
> > +               kasan_quarantine_remove_cache(cache);
> >  }
> >
> >  void kasan_cache_shutdown(struct kmem_cache *cache)
> >  {
> > -       if (!__kmem_cache_empty(cache))
> > +       if (kasan_enabled() && !__kmem_cache_empty(cache))
> >                 kasan_quarantine_remove_cache(cache);
> >  }
> >
> > @@ -239,6 +240,9 @@ void __asan_register_globals(void *ptr, ssize_t siz=
e)
> >         int i;
> >         struct kasan_global *globals =3D ptr;
> >
> > +       if (!kasan_enabled())
> > +               return;
> > +
> >         for (i =3D 0; i < size; i++)
> >                 register_global(&globals[i]);
> >  }
> > @@ -369,6 +373,9 @@ void kasan_cache_create(struct kmem_cache *cache, u=
nsigned int *size,
> >         unsigned int rem_free_meta_size;
> >         unsigned int orig_alloc_meta_offset;
> >
> > +       if (!kasan_enabled())
> > +               return;
> > +
> >         if (!kasan_requires_meta())
> >                 return;
> >
> > @@ -518,6 +525,9 @@ size_t kasan_metadata_size(struct kmem_cache *cache=
, bool in_object)
> >  {
> >         struct kasan_cache *info =3D &cache->kasan_info;
> >
> > +       if (!kasan_enabled())
> > +               return 0;
> > +
> >         if (!kasan_requires_meta())
> >                 return 0;
> >
> > @@ -543,6 +553,9 @@ void kasan_record_aux_stack(void *addr)
> >         struct kasan_alloc_meta *alloc_meta;
> >         void *object;
> >
> > +       if (!kasan_enabled())
> > +               return;
> > +
> >         if (is_kfence_address(addr) || !slab)
> >                 return;
> >
> > diff --git a/mm/kasan/init.c b/mm/kasan/init.c
> > index f084e7a5df1e..c78d77ed47bc 100644
> > --- a/mm/kasan/init.c
> > +++ b/mm/kasan/init.c
> > @@ -447,6 +447,9 @@ void kasan_remove_zero_shadow(void *start, unsigned=
 long size)
> >         unsigned long addr, end, next;
> >         pgd_t *pgd;
> >
> > +       if (!kasan_enabled())
> > +               return;
> > +
> >         addr =3D (unsigned long)kasan_mem_to_shadow(start);
> >         end =3D addr + (size >> KASAN_SHADOW_SCALE_SHIFT);
> >
> > @@ -482,6 +485,9 @@ int kasan_add_zero_shadow(void *start, unsigned lon=
g size)
> >         int ret;
> >         void *shadow_start, *shadow_end;
> >
> > +       if (!kasan_enabled())
> > +               return 0;
> > +
> >         shadow_start =3D kasan_mem_to_shadow(start);
> >         shadow_end =3D shadow_start + (size >> KASAN_SHADOW_SCALE_SHIFT=
);
> >
> > diff --git a/mm/kasan/quarantine.c b/mm/kasan/quarantine.c
> > index 6958aa713c67..a6dc2c3d8a15 100644
> > --- a/mm/kasan/quarantine.c
> > +++ b/mm/kasan/quarantine.c
> > @@ -405,6 +405,9 @@ static int __init kasan_cpu_quarantine_init(void)
> >  {
> >         int ret =3D 0;
> >
> > +       if (!kasan_enabled())
> > +               return 0;
> > +
> >         ret =3D cpuhp_setup_state(CPUHP_AP_ONLINE_DYN, "mm/kasan:online=
",
> >                                 kasan_cpu_online, kasan_cpu_offline);
> >         if (ret < 0)
> > diff --git a/mm/kasan/report.c b/mm/kasan/report.c
> > index 62c01b4527eb..884357fa74ed 100644
> > --- a/mm/kasan/report.c
> > +++ b/mm/kasan/report.c
> > @@ -576,7 +576,9 @@ bool kasan_report(const void *addr, size_t size, bo=
ol is_write,
> >         unsigned long irq_flags;
> >         struct kasan_report_info info;
> >
> > -       if (unlikely(report_suppressed_sw()) || unlikely(!report_enable=
d())) {
> > +       if (unlikely(report_suppressed_sw()) ||
> > +           unlikely(!report_enabled()) ||
> > +           !kasan_enabled()) {
> >                 ret =3D false;
> >                 goto out;
> >         }
> > diff --git a/mm/kasan/shadow.c b/mm/kasan/shadow.c
> > index 29a751a8a08d..f73a691421de 100644
> > --- a/mm/kasan/shadow.c
> > +++ b/mm/kasan/shadow.c
> > @@ -164,6 +164,8 @@ void kasan_unpoison(const void *addr, size_t size, =
bool init)
> >  {
> >         u8 tag =3D get_tag(addr);
> >
> > +       if (!kasan_enabled())
> > +               return;
> >         /*
> >          * Perform shadow offset calculation based on untagged address,=
 as
> >          * some of the callers (e.g. kasan_unpoison_new_object) pass ta=
gged
> > @@ -277,7 +279,8 @@ static int __meminit kasan_mem_notifier(struct noti=
fier_block *nb,
> >
> >  static int __init kasan_memhotplug_init(void)
> >  {
> > -       hotplug_memory_notifier(kasan_mem_notifier, DEFAULT_CALLBACK_PR=
I);
> > +       if (kasan_enabled())
> > +               hotplug_memory_notifier(kasan_mem_notifier, DEFAULT_CAL=
LBACK_PRI);
> >
> >         return 0;
> >  }
> > @@ -658,6 +661,9 @@ int kasan_alloc_module_shadow(void *addr, size_t si=
ze, gfp_t gfp_mask)
> >         size_t shadow_size;
> >         unsigned long shadow_start;
> >
> > +       if (!kasan_enabled())
> > +               return 0;
> > +
> >         shadow_start =3D (unsigned long)kasan_mem_to_shadow(addr);
> >         scaled_size =3D (size + KASAN_GRANULE_SIZE - 1) >>
> >                                 KASAN_SHADOW_SCALE_SHIFT;
> > @@ -694,6 +700,9 @@ int kasan_alloc_module_shadow(void *addr, size_t si=
ze, gfp_t gfp_mask)
> >
> >  void kasan_free_module_shadow(const struct vm_struct *vm)
> >  {
> > +       if (!kasan_enabled())
> > +               return;
> > +
> >         if (IS_ENABLED(CONFIG_UML))
> >                 return;
> >
> > diff --git a/mm/kasan/sw_tags.c b/mm/kasan/sw_tags.c
> > index c75741a74602..6c1caec4261a 100644
> > --- a/mm/kasan/sw_tags.c
> > +++ b/mm/kasan/sw_tags.c
> > @@ -79,6 +79,9 @@ bool kasan_check_range(const void *addr, size_t size,=
 bool write,
> >         u8 *shadow_first, *shadow_last, *shadow;
> >         void *untagged_addr;
> >
> > +       if (!kasan_enabled())
> > +               return true;
> > +
> >         if (unlikely(size =3D=3D 0))
> >                 return true;
> >
> > --
> > 2.41.0
> >
>=20

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/a=
TKHzmxR3JA2R7qD%40fedora.
