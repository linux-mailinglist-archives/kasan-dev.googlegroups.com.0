Return-Path: <kasan-dev+bncBAABBPHFYHBQMGQEWJF23AQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63c.google.com (mail-pl1-x63c.google.com [IPv6:2607:f8b0:4864:20::63c])
	by mail.lfdr.de (Postfix) with ESMTPS id 8A2C7B0111C
	for <lists+kasan-dev@lfdr.de>; Fri, 11 Jul 2025 04:11:10 +0200 (CEST)
Received: by mail-pl1-x63c.google.com with SMTP id d9443c01a7336-23dc7d3e708sf9416435ad.3
        for <lists+kasan-dev@lfdr.de>; Thu, 10 Jul 2025 19:11:10 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1752199869; cv=pass;
        d=google.com; s=arc-20240605;
        b=apElCGAVmeIaHaQ7+4joq1m4NiQ1+sf7pKONwYxujlwjLbQx7XtjXiqxFmIW2FkWb8
         1i0oGaRVEFFwS0BSBaPWRzv0IlMDczgvSpTJIiZ1FzCbpiNndolHFRKrpwv2GNMlD2Jm
         n5PyKeK8neIMHGRV+yTPprn4gESrtOIHUtgChZSAx4qDWaLOIDM4IFRV1uElu3V3VD6u
         8QPPHB3VDrp106bu/Vct5ybqHP7+RxijmiQJHbji9JjWmpOwE57qOeM4w+oOT8q30qS2
         R3uX2gkKUSjsyIZvIS3JBujr/KkBzs5/QCHHS/FadbRrOtCW7j8ZzQ/MH185aO0bCULh
         6BOg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=qhK70V5daj4o3V3cdu6/g1gnEdFJNA+O65P1UHI75/Y=;
        fh=VxHU723zO4BMQ0a4xvWMUP42Sekjd7w0y3fibb4EIMM=;
        b=QIviU+RCFMMcgx24J/qxxnNzqBy5+P0feHryXTVu9eIjGxybt7OnqubbJvHR46BdTZ
         L1AUyzW62kGl2wqDL5c3gENHO2aW6ESQAdpn79nvfG85m6wqV50cWI6al42nW+gXoF5I
         6Dymswae6HHd94Hku358XJkrbUoS34etVvXSCblYFhCDg9KR3p4ylQmJvTcylc3Quz01
         H0pJQi8tq+vVqYnvYB3ymzWCor/Lt4PZgHt2gxxpXl2RgP+KGC3HrzZ1x4UF8JXCFVrm
         7d4lDwjN0NReYsf58ISVDa4Th0yeTz4RZBWEle36CtQndcRmsOosWT2aYRS392R1n5QV
         H2aA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of byungchul@sk.com designates 166.125.252.92 as permitted sender) smtp.mailfrom=byungchul@sk.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1752199869; x=1752804669; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:user-agent:in-reply-to:content-transfer-encoding
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=qhK70V5daj4o3V3cdu6/g1gnEdFJNA+O65P1UHI75/Y=;
        b=bx2JGBGprg+/b+/ZP0kjzJEtFzqWzAJipCFdF6fxj5LTfgemn76QAdWiec6qEn5lhZ
         r8SmYmaGfQ/qAv//tHe9jnghoEycCRj+ram8/ZUG5nh1xTQ8/NJCSUM7cKSfxAQPL7YY
         5pupViqVyP+brLthXFaLieaQAwwYtw7xrHsHx7VoH4fZaYBsokWh1IabChyLvfA356GD
         3xAjQgMcy1I1miW+nHwmG1YzzPLfq/n+gTcmcirwwZERE5s3W3gRADunp/0aQ8YORDRF
         y0fqjAEJNn1kvBGm72qP93lVdcrpJIRRSta7TNj56ASL3lC4szD+dBzbMwwmHt0FJgkf
         liKw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1752199869; x=1752804669;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:user-agent
         :in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=qhK70V5daj4o3V3cdu6/g1gnEdFJNA+O65P1UHI75/Y=;
        b=CfHeN698Pc3g+vl23nqopjEkmvlKcfMjI9AVeOc0WeevKh/qmtwzF8rbkbaCRmmPaU
         OqL92oplFSbv4xYXryDFtJHlc4ersgHC011VdDjWwNwBbaYTypPanO6vfiW24fsSkW7q
         YPmxaDm5PjlATEwkPcRE4QyUJ836Vd/EJ6G0FxXGFK6vt1jlj7tHXDCSM7/ui8mMPec1
         DYR7r3JAG85X7aD0GxAd7a1oakZW0ud0so90Da0e4Q0ZOCU19VVgLQ4lGyaSFqAj6RaF
         nJLBt5y3EoyHD2/baK6qVVMhMBmU+9ohCqoRvqUVRFoHJvzNwbXlbNBgMy7Jf0kiJ1QT
         ewFA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXzM/39fP1p/3oPQDDjv7YLvb4bvUTVC9YDAbUkiMPCWEhmDZjM5qgW6s3itSHamKo1H6KYtA==@lfdr.de
X-Gm-Message-State: AOJu0YynRDbiOHZQD8eRoRmwPUpA9J5LZfJ21NyOj4oJ2g6lPO1mhxYF
	2pbCRci90NHZnYEJfzN0OaAA7meADjESsQ9qiLt0uPMMevMXC+j4FlOz
X-Google-Smtp-Source: AGHT+IHObPoNFx2qr/N5aM6CDElfpvUMEzPhqguwCBzjeqwH0g8+UEXMwYZw9opoyh9oy5FjIysdTQ==
X-Received: by 2002:a17:902:e78c:b0:23d:deca:6eb5 with SMTP id d9443c01a7336-23dee27d5bcmr16930415ad.28.1752199868875;
        Thu, 10 Jul 2025 19:11:08 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcy6yIKI//ADBDDxO089ChE++jjDlF/kNagwIATdxfF/A==
Received: by 2002:a17:903:24e:b0:231:e735:850a with SMTP id
 d9443c01a7336-23de2dfa1f9ls15111255ad.1.-pod-prod-09-us; Thu, 10 Jul 2025
 19:11:07 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUztuwoSgQM4ew/c3BCuv1b7khJZ4+7LtXbowwi3jqOSuCtNvKcXX6tp9pXsvmwigll+CXvO2XgwJ0=@googlegroups.com
X-Received: by 2002:a17:903:1a0b:b0:23d:ed96:e2b6 with SMTP id d9443c01a7336-23dee2a09c6mr19738305ad.44.1752199867641;
        Thu, 10 Jul 2025 19:11:07 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1752199867; cv=none;
        d=google.com; s=arc-20240605;
        b=XbqhwphO+KE/QY/08n+rpniydRq8p5B++2YbN7UtbLIB+CKkAvOvonbRN9C37I2W3e
         n/lr+vy+msHAgstasfcPBdMf+UidIhCG+3Z3thmjpYwnpTaPBTNtBKM62eZA1EBb5wuA
         D3irPd4QDfR6U4L7YUQ9C78c7oSXnrM/cmfgw+NFmfcPZLIRaewyM+ZvGFNO+TEdDvqm
         M8fW6PO4VXfX2NcCUVdLuU0sh1u4G3a89GMf5VHhcSoX7PVBQhgnFQDtFRzLnkm/6lKn
         G1GRgpwROKym2MNYcsyOJExG4/Y4hU/Lhj4u3qbe4vRylMS8ZybdOJYJS1sgUk/b9VTR
         V06w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=user-agent:in-reply-to:content-transfer-encoding
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date;
        bh=M4FuFyIhaKWQ9IY1d9E8e2SU3FPYmT8fAOBa1QqKOVE=;
        fh=UbV6yiLW7GyO9E7pnXMyfVYw3hT2aRfAZh/vGGa2El4=;
        b=cfj+LukPsy9Y4g1JdmQ31mYz/zLzyQeMU6XGCaTm/nPcae+arkiUD3kByJRpYbgfUm
         WcsZWpDOmNa6enLM5fJFQw4xrHezXzSbfgVOJsqCifugaWrx+q1wSRbizLeOtGSS9Nm/
         mc93eFdcGvPgoAAaqODwJCaXI8C6DpSwSLYYg84tQtFx67TCwbhxcMAwpfSIrg97Bv3K
         3L6nBQra9GnKzyleYCihbwvGxmT4mmuJMd9stHBGxaGBiRScvWLEk3lG9b2/VgJEFz1E
         RwFC5KdbGlUXzadC8Rn8Sn84s+ZLS5x7DWSBsXijfd9VSKWsv9pj2yBipzgwfKm/Uib0
         SSSA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of byungchul@sk.com designates 166.125.252.92 as permitted sender) smtp.mailfrom=byungchul@sk.com
Received: from invmail4.hynix.com (exvmail4.hynix.com. [166.125.252.92])
        by gmr-mx.google.com with ESMTP id d9443c01a7336-23de4333b5csi1168575ad.10.2025.07.10.19.11.06
        for <kasan-dev@googlegroups.com>;
        Thu, 10 Jul 2025 19:11:07 -0700 (PDT)
Received-SPF: pass (google.com: domain of byungchul@sk.com designates 166.125.252.92 as permitted sender) client-ip=166.125.252.92;
X-AuditID: a67dfc5b-681ff7000002311f-17-687072b9b6c9
Date: Fri, 11 Jul 2025 11:11:00 +0900
From: Byungchul Park <byungchul@sk.com>
To: Andrey Konovalov <andreyknvl@gmail.com>
Cc: Yeoreum Yun <yeoreum.yun@arm.com>, akpm@linux-foundation.org,
	glider@google.com, dvyukov@google.com, vincenzo.frascino@arm.com,
	bigeasy@linutronix.de, clrkwllms@kernel.org, rostedt@goodmis.org,
	max.byungchul.park@gmail.com, ysk@kzalloc.com,
	kasan-dev@googlegroups.com, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org, linux-rt-devel@lists.linux.dev,
	kernel_team@skhynix.com
Subject: Re: [PATCH v2] kasan: remove kasan_find_vm_area() to prevent
 possible deadlock
Message-ID: <20250711021100.GA4320@system.software.com>
References: <20250703181018.580833-1-yeoreum.yun@arm.com>
 <CA+fCnZcMpi6sUW2ksd_r1D78D8qnKag41HNYCHz=HM1-DL71jg@mail.gmail.com>
 <20250711020858.GA78977@system.software.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <20250711020858.GA78977@system.software.com>
User-Agent: Mutt/1.9.4 (2018-02-28)
X-Brightmail-Tracker: H4sIAAAAAAAAA+NgFtrJIsWRmVeSWpSXmKPExsXC9ZZnoe7OooIMg6/fNS3mrF/DZvF94nR2
	i2kXJzFbLHvyj8liwsM2dov2j3uZLVY8u89kcXnXHDaLe2v+s1pcWn2BxeLCxF5Wi30dD5gs
	9v77yWIx94uhxZfVq9gc+D3WzFvD6LFz1l12j5Z9t9g9Fmwq9dgz8SSbx6ZVnUDi0yR2j4W/
	XzB7vDt3jt3jxIzfLB4vNs9k9Pi8SS6AJ4rLJiU1J7MstUjfLoEr4/WUSWwFJ4QrOtYdZG5g
	3MfbxcjJISFgInH52RoWGHvz8dvMIDaLgKrE7J/vmEBsNgF1iRs3foLFRQS0JSbc+AVUz8XB
	LNDGLPFn811WkISwQKRE87ZrYA28AuYSzU9nghUJCaxnlPj16idUQlDi5MwnYNuYgab+mXcJ
	aCoHkC0tsfwfB0RYXqJ562ywZZwClhKvp2xlB7FFBZQlDmw7zgQyU0JgGbvE8/NLmSGulpQ4
	uOIGywRGwVlIVsxCsmIWwopZSFYsYGRZxSiUmVeWm5iZY6KXUZmXWaGXnJ+7iREYoctq/0Tv
	YPx0IfgQowAHoxIPr8Pq/Awh1sSy4srcQ4wSHMxKIrzrfAsyhHhTEiurUovy44tKc1KLDzFK
	c7AoifMafStPERJITyxJzU5NLUgtgskycXBKNTBKeBz6yvDh+PZ8DdbUkoN8iw5FzH4Vlc0l
	MmH219LrNoopYnXpC+6pm1dyr9zLHq7NdvvXhWnSHx9sWr7HY9Lm20uLz++NWDrB47/G+kd3
	tmxxPfn01NmFJ126196uC5vzQFa8Sr4jOztZpbnzckZx5or1+q3TK7dOTJx89JmHyrLLlVcz
	TUPuK7EUZyQaajEXFScCAB4frvrMAgAA
X-Brightmail-Tracker: H4sIAAAAAAAAA+NgFlrAIsWRmVeSWpSXmKPExsXC5WfdrLuzqCDDoPuktMWc9WvYLL5PnM5u
	Me3iJGaLZU/+MVlMeNjGbtH+cS+zxYpn95ksDs89yWpxedccNot7a/6zWlxafYHF4sLEXlaL
	fR0PmCz2/vvJYjH3i6HFl9Wr2BwEPNbMW8PosXPWXXaPln232D0WbCr12DPxJJvHplWdQOLT
	JHaPhb9fMHu8O3eO3ePEjN8sHi82z2T0WPziA5PH501yAbxRXDYpqTmZZalF+nYJXBmvp0xi
	KzghXNGx7iBzA+M+3i5GTg4JAROJzcdvM4PYLAKqErN/vmMCsdkE1CVu3PgJFhcR0JaYcOMX
	SxcjFwezQBuzxJ/Nd1lBEsICkRLN266BNfAKmEs0P50JViQksJ5R4tern1AJQYmTM5+wgNjM
	QFP/zLsENJUDyJaWWP6PAyIsL9G8dTbYMk4BS4nXU7ayg9iiAsoSB7YdZ5rAyDcLyaRZSCbN
	Qpg0C8mkBYwsqxhFMvPKchMzc0z1irMzKvMyK/SS83M3MQLjbVntn4k7GL9cdj/EKMDBqMTD
	67A6P0OINbGsuDL3EKMEB7OSCO8634IMId6UxMqq1KL8+KLSnNTiQ4zSHCxK4rxe4akJQgLp
	iSWp2ampBalFMFkmDk6pBsY718TSjfVnFbI07tWb/Jj77yyxzhvpdYqHVRizjy94rv5+l8tJ
	Ywe9STF39VZLvY8QWVUnaW55LCBWWkY9aYmmgdb0k2F63oz1jNIXefxUWq4tavfuC565/nu+
	9HnvqCkF1iktiwT2+QesrlqjsvbA1Y6WhYt/7KxPO95du4tr87WY2SGy15VYijMSDbWYi4oT
	AQ9n3/KzAgAA
X-CFilter-Loop: Reflected
X-Original-Sender: byungchul@sk.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of byungchul@sk.com designates 166.125.252.92 as
 permitted sender) smtp.mailfrom=byungchul@sk.com
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

On Fri, Jul 11, 2025 at 11:08:58AM +0900, Byungchul Park wrote:
> On Thu, Jul 10, 2025 at 02:43:15PM +0200, Andrey Konovalov wrote:
> > On Thu, Jul 3, 2025 at 8:10=E2=80=AFPM Yeoreum Yun <yeoreum.yun@arm.com=
> wrote:
> > >
> > > find_vm_area() couldn't be called in atomic_context.
> > > If find_vm_area() is called to reports vm area information,
> > > kasan can trigger deadlock like:
> > >
> > > CPU0                                CPU1
> > > vmalloc();
> > >  alloc_vmap_area();
> > >   spin_lock(&vn->busy.lock)
> > >                                     spin_lock_bh(&some_lock);
> > >    <interrupt occurs>
> > >    <in softirq>
> > >    spin_lock(&some_lock);
> > >                                     <access invalid address>
> > >                                     kasan_report();
> > >                                      print_report();
> > >                                       print_address_description();
> > >                                        kasan_find_vm_area();
> > >                                         find_vm_area();
> > >                                          spin_lock(&vn->busy.lock) //=
 deadlock!
> > >
> > > To prevent possible deadlock while kasan reports, remove kasan_find_v=
m_area().
> > >
> > > Fixes: c056a364e954 ("kasan: print virtual mapping info in reports")
> > > Reported-by: Yunseong Kim <ysk@kzalloc.com>
> > > Signed-off-by: Yeoreum Yun <yeoreum.yun@arm.com>
> >=20
> > As a fix:
> >=20
> > Acked-by: Andrey Konovalov <andreyknvl@gmail.com>
> >=20
> > But it would be great to figure out a way to eventually restore this
> > functionality; I'll file a bug for this once this patch lands. The
> > virtual mapping info helps with real issues: e.g. just recently it
> > helped me to quickly see the issue that caused a false-positive report
>=20
> I checked the critical section by &vn->busy.lock in find_vm_area().  The
> time complextity looks O(log N).  I don't think an irq disabled section
> of O(log N) is harmful.  I still think using
> spin_lock_irqsave(&vn->busy.lock) can resolve this issue with no worry
> of significant irq delay.  Am I missing something?

I prefer this one tho.

	Byungchul
>=20
> If it's unacceptable for some reasons, why don't we introduce kind of
> try_find_vm_area() using trylock so as to go ahead only if there's no
> lock contention?
>=20
> 	Byungchul
>=20
> > [1].
> >=20
> > [1] https://lore.kernel.org/all/CA+fCnZfzHOFjVo43UZK8H6h3j=3DOHjfF13oFJ=
vT0P-SM84Oc4qQ@mail.gmail.com/

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/2=
0250711021100.GA4320%40system.software.com.
