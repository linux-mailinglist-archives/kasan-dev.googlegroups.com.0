Return-Path: <kasan-dev+bncBCKPFB7SXUERBR5O33EQMGQEM52NFBQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf38.google.com (mail-qv1-xf38.google.com [IPv6:2607:f8b0:4864:20::f38])
	by mail.lfdr.de (Postfix) with ESMTPS id 4E84DCAECEA
	for <lists+kasan-dev@lfdr.de>; Tue, 09 Dec 2025 04:28:09 +0100 (CET)
Received: by mail-qv1-xf38.google.com with SMTP id 6a1803df08f44-88237204cc8sf136072576d6.2
        for <lists+kasan-dev@lfdr.de>; Mon, 08 Dec 2025 19:28:09 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1765250888; cv=pass;
        d=google.com; s=arc-20240605;
        b=PSdAxuDQOOa6tNiDXAgOV76MwrjdwwcgWj3c1PuF661Q5WQCnsgrTORH/aPW0zsOSP
         uZqd+iybxc9SucDtxc0qgPmn+tvSJnGHTmqQ/rCz2iLDrm/kOAm1tIg5jxKhZNlXlY1W
         uj87GgvJpfsd4VFZiZGfYni3zIl45+ko4PeDKJHCPP0ODlXQ19cQ57GzU/nJe4H7upXK
         wlLRVhUPYMYmcJYpV3gt3v/X6AclfpnIF7xImKBrKPQTm7FWtYr5kK33l242AReMnpWD
         EygvtQvFxpAp0jHzirBRdqzdp+XsYyRjCe+atD+UmYrXM6uOh+SiK7dItHVWyM4EYtDC
         Ndww==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:dkim-signature;
        bh=pt4MRWhCY0ZCHLFd2RVtgSoZt3uEKPuUx7VStMYAyyc=;
        fh=jwvl2R7ldh79KTJNS/9jDCqJPwYjU5GhvanuF2PFmMA=;
        b=LAsreQBYzwwvRSLLCPC/QCyTptUCsJJB7Sz52CMtVEyNFOLIUVOPVjtUlLtCBjneQm
         fAMSZIGdU5EO4FClhJVkW1f0M4RNAvqTw62oy4+WUFYc1qMMs7XGHAYZZs5+VNXcKGWw
         YlVxlvJJPExUi+7zVI/vC1DLpzlouN9AX0HCSzkfSr6ROGWDguIyDQKYaBd9oUsc5le+
         eyKDIUsSzrw1oAxH83dzWSOli/yn/iPzEfuxszXSS3KxCO0pvKzvD8AWuQGT9OLD2Rmw
         MTVYQ5ksO3lKMY0eMnEnLJLtnWCUzfInFT00N77BQbGgsHlbdHPSRRBq9SnDkABsrOuP
         ulkA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=a59KgZ+A;
       spf=pass (google.com: domain of bhe@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=bhe@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1765250888; x=1765855688; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:from:to:cc:subject
         :date:message-id:reply-to;
        bh=pt4MRWhCY0ZCHLFd2RVtgSoZt3uEKPuUx7VStMYAyyc=;
        b=FkX11RdHNjawYcz7FchKF8mxlNAykgv9S8/oHlLGdIPAnDz623TZ9+OpSyHH2Da/Bw
         xGlJtNeSbVFU4qVLKE3ZePVH6NppHlsgOtNq/EXvYPPQMfEyM04aiiD7rSsX4FfT0cku
         pkJC70/p8Duw69Sw/dKd3LyEUflnS4lagnmJMlRpvx/1JeTYHFb0vHJrzyOekYJnY6tg
         Q+uYFD9/wdx4Lu0gFyonrtQ1kN7gYUPBxRhXLsQ/kvVP8E1LaOIbNRhSZlTKIhSVxHpb
         wYhz1A8WzlDMLJQ/Vd4FMLXsyDc812uKp0+9L2k18t8/Vh+9I0sf76hu9hWX5wfcAYJl
         u6FQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1765250888; x=1765855688;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=pt4MRWhCY0ZCHLFd2RVtgSoZt3uEKPuUx7VStMYAyyc=;
        b=pSVQm08oycjtxEiCKkIYzagW4Td/f/rP2EAofJ/PV/SSRtSjEVqRz7JoHtN7iNyFH/
         7132hZe364We9twJMoiwxB3/U5lSzrQGdiHsyvYwHTV+BxOhpYJhDTKAdPho2ojZp6Rx
         DZcGGyPJ0jf4WyCNNnQfL/9A0QmBjSbVaRbZF2AW3kkcFDxfMpcf6amXbjRJwZocumPr
         rwJbjasjIzt7OvKBRoE1c3zaCzNFmHAaL4MgxcsHOxo2RPpKSh3zWSJ/RJOi8niZTgqx
         p+AN8Ilwb+tP2YlM+9AXS8p0UQwFaSWgr9VErQnjyQHPLT9uUEEf42BANHdLYSTtAnpq
         zFUQ==
X-Forwarded-Encrypted: i=2; AJvYcCWCVngndeHS0f8Wx1qWX1NiEkYgX5uO3hiG7Uo6Ncyog9HBY3e7Qxk9AWN6gny7yp5VV5OU6g==@lfdr.de
X-Gm-Message-State: AOJu0YyZXg3c914aPZ4e9++XNd8t08rISl+jpxRlqva/1ktT2D2LzH0+
	/vNC4he5jt3NtgnBejLdqn01p7dCgI2KBn3W5r2jv6q0HFAQEwfk/z/b
X-Google-Smtp-Source: AGHT+IGnJc7pVY6xhsn9PfW+S/49M9UPR5t2fwmeo/ZQOYiKmn0hEK3UWTe7f+lTrwZd80U7byBnxw==
X-Received: by 2002:ad4:5ecc:0:b0:729:9b59:bba6 with SMTP id 6a1803df08f44-8883dc307d4mr165677066d6.34.1765250887739;
        Mon, 08 Dec 2025 19:28:07 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWZCoQ05r8sGR2/TPQHFwuBgQF3X+Fl0XNdIDlurW5+oxQ=="
Received: by 2002:ad4:5ae1:0:b0:880:59ee:bbc with SMTP id 6a1803df08f44-88825e4f675ls52620396d6.1.-pod-prod-09-us;
 Mon, 08 Dec 2025 19:28:06 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCV49YViuVskGKFNGAkBPERdbbuWuBZRSmRaL96ybUkdwPLQY8wBNPZvvbR7cysWO/88++TCAGDYVG8=@googlegroups.com
X-Received: by 2002:a05:6122:1828:b0:55b:9c1c:85d7 with SMTP id 71dfb90a1353d-55e8460c76cmr3492849e0c.3.1765250886678;
        Mon, 08 Dec 2025 19:28:06 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1765250886; cv=none;
        d=google.com; s=arc-20240605;
        b=hfqCvvXixc/A7/JLG7hEjHUMVNlWMOLlRjD24fjnYvF3Dmw/sTGWmrzi8hnWikH+BW
         8CXKo5l5/yc93hJ6SLabNwoh72Qen/R/nG/O3/uhcyFiu/qPu2Qxqg+FeXZUbuavtDHx
         JyZOpwIjn72gB+wLg91OUuD/clR1GCHMdc1NOu1CPzIXMcmywaz7DeTo6BR+yWEKCqEY
         HiddOdjcIYUG7+rmxel9ZSMg7BkLWka48JcqpwCfYt6iZ+g9ppInFuRc5gfgfGOhG/ul
         zJoLzS32hoz4V45qOGimT0gEO8/nOXa2pxblDTceDUs1W4lRf+BPOHkCFiFMR7N+fhQI
         YmfA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=NbFVdOXb1Nr6+8TD5KZltub496iqTHAYaOUL7OnbUgQ=;
        fh=bMZBJix3YMSVI/m5jYA+cZd5+5N920UloQTCzaIamYQ=;
        b=j+FWo8cRpGaHZF0Q0vJWcKDK/PkUA8l65cCpr0IpePjFrK647TzT1nolqHEfXndvtK
         ZyQVKLcYLENhyQyUry8xO1TLHTPybly7bYC9kZsZcdpfFOhi+rtLQix2gF8sfVNrhPZ5
         yIfdvxP3X6Ks7DqhdmXkyyfkPRXN+TVgB7s6yBI16wr1p0zCyJtDR3Wdm1zAZywksKUR
         Te9a29D1FjlXLkAHQsAIg6g6/17CIkw0iThFiJoLw0uSW8iCdAtsqNgWxQwPWVVL7D+L
         6T9OvOcrDIueQOX3NPzqH1r1qVolTbKjaqKwAddaHreCcWLpdS2et9jofswYKAkzuEr5
         wvWg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=a59KgZ+A;
       spf=pass (google.com: domain of bhe@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=bhe@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.129.124])
        by gmr-mx.google.com with ESMTPS id 71dfb90a1353d-55e6c9cded0si494050e0c.5.2025.12.08.19.28.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 08 Dec 2025 19:28:06 -0800 (PST)
Received-SPF: pass (google.com: domain of bhe@redhat.com designates 170.10.129.124 as permitted sender) client-ip=170.10.129.124;
Received: from mx-prod-mc-05.mail-002.prod.us-west-2.aws.redhat.com
 (ec2-54-186-198-63.us-west-2.compute.amazonaws.com [54.186.198.63]) by
 relay.mimecast.com with ESMTP with STARTTLS (version=TLSv1.3,
 cipher=TLS_AES_256_GCM_SHA384) id us-mta-251-P4iN0WunM0CoN3RLOuYODw-1; Mon,
 08 Dec 2025 22:28:00 -0500
X-MC-Unique: P4iN0WunM0CoN3RLOuYODw-1
X-Mimecast-MFC-AGG-ID: P4iN0WunM0CoN3RLOuYODw_1765250878
Received: from mx-prod-int-03.mail-002.prod.us-west-2.aws.redhat.com (mx-prod-int-03.mail-002.prod.us-west-2.aws.redhat.com [10.30.177.12])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by mx-prod-mc-05.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTPS id A24091956088;
	Tue,  9 Dec 2025 03:27:57 +0000 (UTC)
Received: from localhost (unknown [10.72.112.51])
	by mx-prod-int-03.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTPS id 2678719560AD;
	Tue,  9 Dec 2025 03:27:54 +0000 (UTC)
Date: Tue, 9 Dec 2025 11:27:50 +0800
From: "'Baoquan He' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrey Konovalov <andreyknvl@gmail.com>
Cc: linux-mm@kvack.org, ryabinin.a.a@gmail.com, glider@google.com,
	dvyukov@google.com, vincenzo.frascino@arm.com,
	akpm@linux-foundation.org, kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org, kexec@lists.infradead.org,
	elver@google.com, sj@kernel.org, lorenzo.stoakes@oracle.com,
	snovitoll@gmail.com, christophe.leroy@csgroup.eu
Subject: Re: [PATCH v4 02/12] mm/kasan: move kasan= code to common place
Message-ID: <aTeXNkWx/U8MB9hf@MiWiFi-R3L-srv>
References: <20251128033320.1349620-1-bhe@redhat.com>
 <20251128033320.1349620-3-bhe@redhat.com>
 <CA+fCnZeHZ4+8GOn0untumM0TE9TeSHqja9kAsbEb-+jbEFNQQQ@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <CA+fCnZeHZ4+8GOn0untumM0TE9TeSHqja9kAsbEb-+jbEFNQQQ@mail.gmail.com>
X-Scanned-By: MIMEDefang 3.0 on 10.30.177.12
X-Original-Sender: bhe@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=a59KgZ+A;
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

On 12/04/25 at 05:39pm, Andrey Konovalov wrote:
> On Fri, Nov 28, 2025 at 4:33=E2=80=AFAM Baoquan He <bhe@redhat.com> wrote=
:
> >
> > This allows generic and sw_tags to be set in kernel cmdline too.
> >
> > When at it, rename 'kasan_arg' to 'kasan_arg_disabled' as a bool
> > variable. And expose 'kasan_flag_enabled' to kasan common place
> > too.
>=20
> This asks to be two separate patches.

Makes sense to me, thanks..

>=20
> >
> > This is prepared for later adding kernel parameter kasan=3Don|off for
> > all three kasan modes.
> >
> > Signed-off-by: Baoquan He <bhe@redhat.com>
> > ---
> >  include/linux/kasan-enabled.h |  4 +++-
> >  mm/kasan/common.c             | 20 ++++++++++++++++++--
> >  mm/kasan/hw_tags.c            | 28 ++--------------------------
> >  3 files changed, 23 insertions(+), 29 deletions(-)
> >
> > diff --git a/include/linux/kasan-enabled.h b/include/linux/kasan-enable=
d.h
> > index 9eca967d8526..b05ec6329fbe 100644
> > --- a/include/linux/kasan-enabled.h
> > +++ b/include/linux/kasan-enabled.h
> > @@ -4,13 +4,15 @@
> >
> >  #include <linux/static_key.h>
> >
> > -#if defined(CONFIG_ARCH_DEFER_KASAN) || defined(CONFIG_KASAN_HW_TAGS)
>=20
> These changes of moving/removing CONFIG_ARCH_DEFER_KASAN also seem to
> belong to a separate patch (or should be combined with patch 12?); the
> commit message does not even mention them.

Yes, combining tit with patch 12 sounds great. I will move patch 12 to
earlier oder.

>=20
> > +extern bool kasan_arg_disabled;
> > +
> >  /*
> >   * Global runtime flag for KASAN modes that need runtime control.
> >   * Used by ARCH_DEFER_KASAN architectures and HW_TAGS mode.
> >   */
> >  DECLARE_STATIC_KEY_FALSE(kasan_flag_enabled);
>=20
> So kasan_flag_enabled is now always exposed here...
>=20
> >
> > +#if defined(CONFIG_ARCH_DEFER_KASAN) || defined(CONFIG_KASAN_HW_TAGS)
>=20
> but the functions that use it are not. Why?

Good question. I didn't consider this reasonably. At the beginning, I
thought it could cause problem if people has specified 'kasan=3Doff'
before patch 12 when bisecting. That's why put kasan_arg_disabled and
kasan_flag_enabled declaration outside of any ifdeffery scope. Now after
reconsiderring, putting patch 12 earlier can solve the problem.

Thanks for careful reivewing, all suggestions are good and taken.

>=20
>=20
> >  /*
> >   * Runtime control for shadow memory initialization or HW_TAGS mode.
> >   * Uses static key for architectures that need deferred KASAN or HW_TA=
GS.
> > diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> > index 1d27f1bd260b..ac14956986ee 100644
> > --- a/mm/kasan/common.c
> > +++ b/mm/kasan/common.c
> > @@ -32,14 +32,30 @@
> >  #include "kasan.h"
> >  #include "../slab.h"
> >
> > -#if defined(CONFIG_ARCH_DEFER_KASAN) || defined(CONFIG_KASAN_HW_TAGS)
> >  /*
> >   * Definition of the unified static key declared in kasan-enabled.h.
> >   * This provides consistent runtime enable/disable across KASAN modes.
> >   */
> >  DEFINE_STATIC_KEY_FALSE(kasan_flag_enabled);
> >  EXPORT_SYMBOL_GPL(kasan_flag_enabled);
> > -#endif
> > +
> > +bool kasan_arg_disabled __ro_after_init;
> > +/* kasan=3Doff/on */
> > +static int __init early_kasan_flag(char *arg)
> > +{
> > +       if (!arg)
> > +               return -EINVAL;
> > +
> > +       if (!strcmp(arg, "off"))
> > +               kasan_arg_disabled =3D true;
> > +       else if (!strcmp(arg, "on"))
> > +               kasan_arg_disabled =3D false;
> > +       else
> > +               return -EINVAL;
> > +
> > +       return 0;
> > +}
> > +early_param("kasan", early_kasan_flag);
> >
> >  struct slab *kasan_addr_to_slab(const void *addr)
> >  {
> > diff --git a/mm/kasan/hw_tags.c b/mm/kasan/hw_tags.c
> > index 1c373cc4b3fa..709c91abc1b1 100644
> > --- a/mm/kasan/hw_tags.c
> > +++ b/mm/kasan/hw_tags.c
> > @@ -22,12 +22,6 @@
> >
> >  #include "kasan.h"
> >
> > -enum kasan_arg {
> > -       KASAN_ARG_DEFAULT,
> > -       KASAN_ARG_OFF,
> > -       KASAN_ARG_ON,
> > -};
> > -
> >  enum kasan_arg_mode {
> >         KASAN_ARG_MODE_DEFAULT,
> >         KASAN_ARG_MODE_SYNC,
> > @@ -41,7 +35,6 @@ enum kasan_arg_vmalloc {
> >         KASAN_ARG_VMALLOC_ON,
> >  };
> >
> > -static enum kasan_arg kasan_arg __ro_after_init;
> >  static enum kasan_arg_mode kasan_arg_mode __ro_after_init;
> >  static enum kasan_arg_vmalloc kasan_arg_vmalloc __initdata;
> >
> > @@ -81,23 +74,6 @@ unsigned int kasan_page_alloc_sample_order =3D PAGE_=
ALLOC_SAMPLE_ORDER_DEFAULT;
> >
> >  DEFINE_PER_CPU(long, kasan_page_alloc_skip);
> >
> > -/* kasan=3Doff/on */
> > -static int __init early_kasan_flag(char *arg)
> > -{
> > -       if (!arg)
> > -               return -EINVAL;
> > -
> > -       if (!strcmp(arg, "off"))
> > -               kasan_arg =3D KASAN_ARG_OFF;
> > -       else if (!strcmp(arg, "on"))
> > -               kasan_arg =3D KASAN_ARG_ON;
> > -       else
> > -               return -EINVAL;
> > -
> > -       return 0;
> > -}
> > -early_param("kasan", early_kasan_flag);
> > -
> >  /* kasan.mode=3Dsync/async/asymm */
> >  static int __init early_kasan_mode(char *arg)
> >  {
> > @@ -222,7 +198,7 @@ void kasan_init_hw_tags_cpu(void)
> >          * When this function is called, kasan_flag_enabled is not yet
> >          * set by kasan_init_hw_tags(). Thus, check kasan_arg instead.
> >          */
> > -       if (kasan_arg =3D=3D KASAN_ARG_OFF)
> > +       if (kasan_arg_disabled)
> >                 return;
> >
> >         /*
> > @@ -240,7 +216,7 @@ void __init kasan_init_hw_tags(void)
> >                 return;
> >
> >         /* If KASAN is disabled via command line, don't initialize it. =
*/
> > -       if (kasan_arg =3D=3D KASAN_ARG_OFF)
> > +       if (kasan_arg_disabled)
> >                 return;
> >
> >         switch (kasan_arg_mode) {
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
TeXNkWx/U8MB9hf%40MiWiFi-R3L-srv.
