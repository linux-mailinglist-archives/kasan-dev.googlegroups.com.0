Return-Path: <kasan-dev+bncBCCJX7VWUANBBTOF6CAAMGQEOSVCCCY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103b.google.com (mail-pj1-x103b.google.com [IPv6:2607:f8b0:4864:20::103b])
	by mail.lfdr.de (Postfix) with ESMTPS id CFA4D30F817
	for <lists+kasan-dev@lfdr.de>; Thu,  4 Feb 2021 17:37:34 +0100 (CET)
Received: by mail-pj1-x103b.google.com with SMTP id b20sf2448374pjh.8
        for <lists+kasan-dev@lfdr.de>; Thu, 04 Feb 2021 08:37:34 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1612456653; cv=pass;
        d=google.com; s=arc-20160816;
        b=t5PRYQurgXY8HB5Xfi7bNwzrGK5HK/kFFOGeeDw8XkVqIXsJ6T3JCL1fAIA4Wry5W2
         P5JO4fPNUSYfIh/GgO0MPULA6erMetmBYNR9oC1qEV+Yy9fulv8T7XO8yyGHVF9YTTKN
         iZO9uwXrdn2zlrhmISPcYvWpJN0tpdOzL2AiY0CGr0sGKn4UGbzogPBeG94RMUpz0b5E
         TjTwjg4oBtSpha5DO1nB5zcqKQ+sQrACgTu4PyZHi0ccX7a0NGy2QOomoaq81GOegfgj
         Iq6Dn0EaY4OSJ5iK1dOlsutPsI4GP+oLFNDVAiJdtngqg9ncGOGXQMbwR1oezoeBQEpL
         xaVg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :mime-version:references:in-reply-to:message-id:date:subject:cc:to
         :from:sender:dkim-signature:dkim-signature;
        bh=J0A3uNexPnPOoB6QiCV++kxveVvSt5Sjk2gUSvjN0lM=;
        b=eeOD1h8xPH1w0M9XXrdSw/T3H42mhMgFbzx2idleIWh2xL6IQVxqsIFytFKCrOECZK
         +exbBUdOhHoPI/4lptQ/isBwA7BBw2eWSju+i5gKocqbXpFS+a2e0R0IRoYlicEXhJ2r
         sp9AV94MRGsrPxeSFcYQF1LaeIJzT+F2VReawB8LD9u9E4d7CXc8J5XgGtfYSJvI1QwD
         z4xVnnWrEngn0Wul/auklePtaSbS8z3h341Aw7WkatWYCJnIVUZtve1Zuca2HLdo2Gq7
         9EOxE6UNVC8xCttN4t45s+l2O16VPXRwpxOB6EvHGLeLYWJyl0T0Rvxca3S/ZmVvA6CN
         kEyg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=Qs76dodt;
       spf=pass (google.com: domain of lecopzer@gmail.com designates 2607:f8b0:4864:20::42d as permitted sender) smtp.mailfrom=lecopzer@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=J0A3uNexPnPOoB6QiCV++kxveVvSt5Sjk2gUSvjN0lM=;
        b=bgT4491k4Hta5iigVo4fZXBXy20YOlOcsXMYw57UoxxByDJFSJUP4bqJ5QqEDdFQj9
         4UTRCy/7BQe/f1tFhmbWAzX0Ls3mOat+T5+DO3VenGcSHvvU6Tx8Yt84fos3MO4SLvKw
         jrVKBHsyMQKsfgMg0U1pNJ8/E8+zkx/DFFzEG4RVvT1VTGsnI8LoG3ln4GNj/33lEITg
         k1JIUpZy9tFeo+N8q71NFpWegenjHFBCLkD5eIt0DP9NBhFSXGN6ceg60jmophOYwHKT
         oKHO7GDfA7zxp+fOgBD7pBThe4G9WSZ3+37MQy3Bvb6Nqe9LotSvMOQq1d42Wbc10m4K
         lU2Q==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=J0A3uNexPnPOoB6QiCV++kxveVvSt5Sjk2gUSvjN0lM=;
        b=UXDakDuCWIEowPh4O8DYg8dNGxUq3X1uqM6NlfkL4fIuotjojCaLZE5roqrsnlxw24
         To8Ra+RJz8TCM+yaD9d6W2HYp1dBHE2cbd6ZO7CgFj7dG0MMflqgw7Bel/Bh4OuQKuTR
         drsoiZcoDFMKB9Om0f+0hmgdqHOCvKWYfg5T3xwP+GK6w17sLYQFvyPRiNqKr94ne0FW
         kAGB/FMRDY+ohS6EZ8zxujzntTVu/oJkO91LdKdtGNJr6/hsXfp/epB3h3w7ij6xLjMN
         mMRuabMYFDIG1hNiXAY0hC6MrNdXq8fwNCReeI+RvXs5IExIWZFtIztjI51H6UmfPeER
         gn+w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=J0A3uNexPnPOoB6QiCV++kxveVvSt5Sjk2gUSvjN0lM=;
        b=V9bH91BuMjYcUi0bjTyXJfW7be5TNW2HRqVOi5mv1uf9NNnnMlXd28trU76rdlbJqC
         w0m8/5D4PHP3iRXV9fOzmkgKscgj8WLstjSvSh22CrIUbuHsz1cs37QXUSUENm6K13Lj
         /C7RBQZo9l2N0hvY5I4QT9651oRvLZRvCNo09b5GHbHHBIcz0S1lbaN8bQSfi/I91JMp
         1yvX/Hen6iXb+LPXPNhyIdAlbSgDkZV2r5c7wkZ2UqUIacIy1QR3g/p0fHe/s4GGCKsO
         OssmPwf8aPjeiQbcCg6mz5m0+sNMBKUTw7VcsgUZMC+IDJXlo1JMyRPXPz2RcsC/qRiM
         2SKw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533yoczecBWPFW3IV7uhuq3UuBtS7TMo09VApI248PX/ggtBo6ef
	dNgsNegKtbJ2eDP3mcv5ovs=
X-Google-Smtp-Source: ABdhPJxz6hyt49RSZWKiQcHFxr2uu2Z4wTYPOk4ojWJ/OsmrWtY2BJKO9tQdW/D3EB5i9bYFBDDJCg==
X-Received: by 2002:a63:5b43:: with SMTP id l3mr9641617pgm.369.1612456653562;
        Thu, 04 Feb 2021 08:37:33 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:8b8a:: with SMTP id ay10ls2944552plb.5.gmail; Thu,
 04 Feb 2021 08:37:33 -0800 (PST)
X-Received: by 2002:a17:90b:204d:: with SMTP id ji13mr320966pjb.51.1612456653006;
        Thu, 04 Feb 2021 08:37:33 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1612456653; cv=none;
        d=google.com; s=arc-20160816;
        b=NeHtY9pul0Mp7ABhqKoJSB5nKCioHMbjKDdjkeaO/FPm3ap6DV4PY5WoeuT1Kk3yd5
         JU5/kzsYDAN7UlC+UM0piKSGyr+jpWneH2kEiXDpBTlYS0Hw3N26lJZ6d+FNW3oY3QmS
         6MGEp2kd8Jzhcwg74fQS8qyKPGM/A/eGs0T1IMGCchRkUe22J/QOFbyl25kT0SnATgCd
         eL4DZZ43IO673RtNQMHA8lOWrkb5gcrQV60fPrCZ3wktySZTmeD8qhDgOBioJJNuoB+v
         u2uwjEr+sWzxABXRhKy0l8n0pdPmxi8L2vimhSb+AVMaWpvFgbU6iSENnuIBKMFMOaBe
         2qHw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=nwObsRzKSVhqA/EbWV8d9m9v2JwQDreOVTF8iuaBQ+g=;
        b=CwoOxknRUXETE3wG96PgKHQRd2wWuw7HHUGtBqEbve7IQnLfmy977ybmmGbBcH+D/K
         UdsRl3pKUCzfvSyaBuXtLPNhqa+4MkbOKpJZ8+DQf5iqbfUMyCjoZKtFtFz3cse5iqxl
         RlqwOiH97MS+Dyc5eaiErhmUyptkC/Dd511ZJ/EOcw2DHvcE3VMmxogq2aasfahfz0pE
         TfSZsPwf8n8FuqyIB7dx4V0q7Fa2pGqda7E1KF5KJgLT7++abAREr+2Acy3vsicwKjaV
         1L/amVs8VvixC3h71YAHEF+3bVV1KM82cdSaYJSN3rIDW+dlMMAeGsJ5MaSM0mYNOf8V
         GcBg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=Qs76dodt;
       spf=pass (google.com: domain of lecopzer@gmail.com designates 2607:f8b0:4864:20::42d as permitted sender) smtp.mailfrom=lecopzer@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pf1-x42d.google.com (mail-pf1-x42d.google.com. [2607:f8b0:4864:20::42d])
        by gmr-mx.google.com with ESMTPS id f24si571850pju.1.2021.02.04.08.37.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 04 Feb 2021 08:37:32 -0800 (PST)
Received-SPF: pass (google.com: domain of lecopzer@gmail.com designates 2607:f8b0:4864:20::42d as permitted sender) client-ip=2607:f8b0:4864:20::42d;
Received: by mail-pf1-x42d.google.com with SMTP id w14so2453542pfi.2
        for <kasan-dev@googlegroups.com>; Thu, 04 Feb 2021 08:37:32 -0800 (PST)
X-Received: by 2002:a62:e217:0:b029:1c1:59ed:ae73 with SMTP id a23-20020a62e2170000b02901c159edae73mr77195pfi.6.1612456652596;
        Thu, 04 Feb 2021 08:37:32 -0800 (PST)
Received: from localhost.localdomain (61-230-45-44.dynamic-ip.hinet.net. [61.230.45.44])
        by smtp.gmail.com with ESMTPSA id 9sm2371133pgw.61.2021.02.04.08.37.26
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 04 Feb 2021 08:37:31 -0800 (PST)
From: Lecopzer Chen <lecopzer@gmail.com>
To: will@kernel.org
Cc: akpm@linux-foundation.org,
	andreyknvl@google.com,
	ardb@kernel.org,
	aryabinin@virtuozzo.com,
	broonie@kernel.org,
	catalin.marinas@arm.com,
	dan.j.williams@intel.com,
	dvyukov@google.com,
	glider@google.com,
	gustavoars@kernel.org,
	kasan-dev@googlegroups.com,
	lecopzer.chen@mediatek.com,
	lecopzer@gmail.com,
	linux-arm-kernel@lists.infradead.org,
	linux-kernel@vger.kernel.org,
	linux-mediatek@lists.infradead.org,
	linux-mm@kvack.org,
	linux@roeck-us.net,
	robin.murphy@arm.com,
	rppt@kernel.org,
	tyhicks@linux.microsoft.com,
	vincenzo.frascino@arm.com,
	yj.chiang@mediatek.com
Subject: Re: [PATCH v2 1/4] arm64: kasan: don't populate vmalloc area for CONFIG_KASAN_VMALLOC
Date: Fri,  5 Feb 2021 00:37:21 +0800
Message-Id: <20210204163721.91295-1-lecopzer@gmail.com>
X-Mailer: git-send-email 2.25.1
In-Reply-To: <20210204150100.GE20815@willie-the-truck>
References: <20210204150100.GE20815@willie-the-truck>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: lecopzer@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=Qs76dodt;       spf=pass
 (google.com: domain of lecopzer@gmail.com designates 2607:f8b0:4864:20::42d
 as permitted sender) smtp.mailfrom=lecopzer@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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


> On Thu, Feb 04, 2021 at 10:46:12PM +0800, Lecopzer Chen wrote:
> > > On Sat, Jan 09, 2021 at 06:32:49PM +0800, Lecopzer Chen wrote:
> > > > Linux support KAsan for VMALLOC since commit 3c5c3cfb9ef4da9
> > > > ("kasan: support backing vmalloc space with real shadow memory")
> > > >
> > > > Like how the MODULES_VADDR does now, just not to early populate
> > > > the VMALLOC_START between VMALLOC_END.
> > > > similarly, the kernel code mapping is now in the VMALLOC area and
> > > > should keep these area populated.
> > > >
> > > > Signed-off-by: Lecopzer Chen <lecopzer.chen@mediatek.com>
> > > > ---
> > > > =C2=A0arch/arm64/mm/kasan_init.c | 23 ++++++++++++++++++-----
> > > > =C2=A01 file changed, 18 insertions(+), 5 deletions(-)
> > > >
> > > > diff --git a/arch/arm64/mm/kasan_init.c b/arch/arm64/mm/kasan_init.=
c
> > > > index d8e66c78440e..39b218a64279 100644
> > > > --- a/arch/arm64/mm/kasan_init.c
> > > > +++ b/arch/arm64/mm/kasan_init.c
> > > > @@ -214,6 +214,7 @@ static void __init kasan_init_shadow(void)
> > > > =C2=A0{
> > > > =C2=A0 u64 kimg_shadow_start, kimg_shadow_end;
> > > > =C2=A0 u64 mod_shadow_start, mod_shadow_end;
> > > > + u64 vmalloc_shadow_start, vmalloc_shadow_end;
> > > > =C2=A0 phys_addr_t pa_start, pa_end;
> > > > =C2=A0 u64 i;
> > > >
> > > > @@ -223,6 +224,9 @@ static void __init kasan_init_shadow(void)
> > > > =C2=A0 mod_shadow_start =3D (u64)kasan_mem_to_shadow((void *)MODULE=
S_VADDR);
> > > > =C2=A0 mod_shadow_end =3D (u64)kasan_mem_to_shadow((void *)MODULES_=
END);
> > > >
> > > > + vmalloc_shadow_start =3D (u64)kasan_mem_to_shadow((void *)VMALLOC=
_START);
> > > > + vmalloc_shadow_end =3D (u64)kasan_mem_to_shadow((void *)VMALLOC_E=
ND);
> > > > +
> > > > =C2=A0 /*
> > > > =C2=A0 =C2=A0* We are going to perform proper setup of shadow memor=
y.
> > > > =C2=A0 =C2=A0* At first we should unmap early shadow (clear_pgds() =
call below).
> > > > @@ -241,12 +245,21 @@ static void __init kasan_init_shadow(void)
> > > >
> > > > =C2=A0 kasan_populate_early_shadow(kasan_mem_to_shadow((void *)PAGE=
_END),
> > > > =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=
=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0(void *)mod_shadow_start);
> > > > - kasan_populate_early_shadow((void *)kimg_shadow_end,
> > > > - =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =
=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0(void *)KASAN_SHADOW_END);
> > > > + if (IS_ENABLED(CONFIG_KASAN_VMALLOC)) {
> > >
> > > Do we really need yet another CONFIG option for KASAN? What's the use=
-case
> > > for *not* enabling this if you're already enabling one of the KASAN
> > > backends?
> >
> > As I know, KASAN_VMALLOC now only supports KASAN_GENERIC and also
> > KASAN_VMALLOC uses more memory to map real shadow memory (1/8 of vmallo=
c va).
>
> The shadow is allocated dynamically though, isn't it?

Yes, but It's still a cost.

> > There should be someone can enable KASAN_GENERIC but can't use VMALLOC
> > due to memory issue.
>
> That doesn't sound particularly realistic to me. The reason I'm pushing h=
ere
> is because I would _really_ like to move to VMAP stack unconditionally, a=
nd
> that would effectively force KASAN_VMALLOC to be set if KASAN is in use.
>
> So unless there's a really good reason not to do that, please can we make
> this unconditional for arm64? Pretty please?

I think it's fine since we have a good reason.
Also if someone have memory issue in KASAN_VMALLOC,
they can use SW_TAG, right?

However the SW_TAG/HW_TAG is not supported VMALLOC yet.
So the code would be like

	if (IS_ENABLED(CONFIG_KASAN_GENERIC))
		/* explain the relationship between=20
		 * KASAN_GENERIC and KASAN_VMALLOC in arm64
		 * XXX: because we want VMAP stack....
		 */
		kasan_populate_early_shadow((void *)vmalloc_shadow_end,
					    (void *)KASAN_SHADOW_END);
	else {
		kasan_populate_early_shadow((void *)kimg_shadow_end,
					    (void *)KASAN_SHADOW_END);
		if (kimg_shadow_start > mod_shadow_end)
			kasan_populate_early_shadow((void *)mod_shadow_end,
						    (void *)kimg_shadow_start);
	}

and the arch/arm64/Kconfig will add
	select KASAN_VMALLOC if KASAN_GENERIC

Is this code same as your thought?

BRs,
Lecopzer

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/20210204163721.91295-1-lecopzer%40gmail.com.
