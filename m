Return-Path: <kasan-dev+bncBCS2NBWRUIFBB36PV6XAMGQE4IDQSDA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53c.google.com (mail-ed1-x53c.google.com [IPv6:2a00:1450:4864:20::53c])
	by mail.lfdr.de (Postfix) with ESMTPS id 1489D853E11
	for <lists+kasan-dev@lfdr.de>; Tue, 13 Feb 2024 23:06:41 +0100 (CET)
Received: by mail-ed1-x53c.google.com with SMTP id 4fb4d7f45d1cf-55ffc81c768sf2656308a12.1
        for <lists+kasan-dev@lfdr.de>; Tue, 13 Feb 2024 14:06:41 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1707862000; cv=pass;
        d=google.com; s=arc-20160816;
        b=tw/VxwLjPMyZGmOFQm/cnGPL6g5YAnq7sSCc7CCE4lTxGYcBhRQOXErSARrn39oOK/
         hI2EPhMr7M7i0bcGKvqpG+2UzAeZWkTHfHmTaBWhPKscdLCcJ7Wjm7G/OMEgIQCpQo+J
         FOAdBgSawuIHN829KYLF1ijPURNrbWVWox//f5444pQ4WHsb+GO98I+3yjBC81CHTBW5
         uuG98YFKo31n/212ntvAwoXphnaY9mFb1LzxfzrLHPx2SnmNlgPbW1kyzpFcxTKfN8Ti
         L+XJtZLd5riPQGJPJLMGXqnGcYhxQXGBXzqBaLM3gBcwETAaiQuu1QlI7kNblAJQpcW/
         UkSg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=5x05L9mRgpeRuZz0Q9Jb63g3V/feUJ9XCKCOMgB6o5I=;
        fh=Ejy23eXVwxcRizhVVtzKpaWg14OuYEXHvRSyK+98QXw=;
        b=0jrT2eZ6LGDMX7XhtRU4RuRrTM3Xmk2RvjPFWF/fxIDd6ZG7G6vH7KVoHiRjRVRc73
         uCS2xdQq2/tJz1mFpAz3YNI8PYPJoa9MHM5eu5H346qly4158ghkh2b16bqtgsMd/ULS
         9OVquhUpKmaCCBqQuHkYq0103Zf3NagP38JXGQXAd1/QvaoWtfPrudk5lEIySd/Jjw4D
         H+/yWg81FhWEfVahf6Zr8vLWrokKhfQUx6un0IRaGYxWMH+ti1EFngfltESWFDC5Y3fk
         s5ZqoPO/gF5L+FmqXWDOvhiRYM877ruIfxHU84aFH/w2xhbvtqkRx2wD9N1fphtkN408
         rUCA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=rGEbbs21;
       spf=pass (google.com: domain of kent.overstreet@linux.dev designates 2001:41d0:1004:224b::ab as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1707862000; x=1708466800; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-transfer-encoding
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=5x05L9mRgpeRuZz0Q9Jb63g3V/feUJ9XCKCOMgB6o5I=;
        b=PpTGi9XNMZIpG+okTgMAI0DIqvFRQH2e+gGO9RHNHVmA2ARHYr6GtX1EB7EDn754/J
         FiaXY1PWkdGiUmr5/iXfCOuG8zKybaWkTkgTk3crdAD7BnHFSIytAQ+sm74zvgsV1WCs
         TrSWvmZ5q5DAlkGWCa5zbsIL7JNyr66FTk3BkgSvpETxCQX+BZPs5QDY8m5uVy2OaxrJ
         UX8DMYU17CXxopfVn3Gyx9cSIre9+q6eOBMPcdd7vTw4r3FBs8oXA892Xy7ZtFVaRUqy
         p13DuRU2NbXv45dCt5F/Fv4q7KB5ZSXyg57ACfUzm3RzCq70u1VdZL7W1JchWpmn0Bg7
         4few==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1707862000; x=1708466800;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=5x05L9mRgpeRuZz0Q9Jb63g3V/feUJ9XCKCOMgB6o5I=;
        b=IEe9eQnJbQsmRUaX4ibLouX9asvh8ibt8GKyRyBBLtPoGzq9WE+aAwr3XM4881mPu+
         mVzkdUWUo7D8NHHRhOuYw55sFbg72LaD2IMUo/AFl0+YrEQidJXP0L0CV7LKewOPj4wt
         r7Aak3Ish4UXh3KPBM+ZrW46ph/UHuRrFlujYFrCyn1UeWtpFDvyTHFhX1WwO7Wm3226
         bwz9smMoYTvISkoKJo3s0HroiEap4gO1QUczNvE+zhHkb4YBDd08jn9yADQRXw57+nYL
         1J/7ehTT1us6AWIADpAj/4Rb6P1Ejd09aJ+aVCLx4IzveftI6kI5SDaNnkUtoqLDtwak
         H7Tg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCU1JQuv41xA4MTjmxs8JXlAIZOVexRfyUrtMxix/EK+Z4RPA4p/d53Oh6wYuqwGOqPTxHZzbig6J+sB8xQtsLns6kXhEXACMg==
X-Gm-Message-State: AOJu0YydXMumAxSOlaJZrfCwQ2nUB4LiuW6OM1ogYrnt3vqyME/z5Nt9
	Ru+PuYpp/aLKLEYL3ifHi0+iAwqhtIW4+2iIiYpzXm9vYuZOhZTC
X-Google-Smtp-Source: AGHT+IFMUdOKOIGaf6g9omDzA3NSGxsGi/J/IYkzLDEzsGq25Y0ObLHJAE6W4M7HtsnkCFnzy5gk3A==
X-Received: by 2002:aa7:c715:0:b0:55f:f94d:cf76 with SMTP id i21-20020aa7c715000000b0055ff94dcf76mr620380edq.27.1707862000134;
        Tue, 13 Feb 2024 14:06:40 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:5d4:b0:562:1a24:52af with SMTP id
 n20-20020a05640205d400b005621a2452afls179719edx.0.-pod-prod-05-eu; Tue, 13
 Feb 2024 14:06:38 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVgG/O5MfsFpuV17xDbn2n+1onTMSRnolo9AQlYex5XcqBSBrt6t78k34OzAOd3fvc9Fe/WVi7EGdluZFUMe2aT7uC9bWnfLgbKGQ==
X-Received: by 2002:aa7:d752:0:b0:560:c8cb:c2c8 with SMTP id a18-20020aa7d752000000b00560c8cbc2c8mr677238eds.11.1707861998214;
        Tue, 13 Feb 2024 14:06:38 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1707861998; cv=none;
        d=google.com; s=arc-20160816;
        b=XfshY0NdS3ni0f9DvEOb5/pUqOV+u4CrKkwRdT9cTy8G9n5mQCLrfIuaIfx3pvXPDs
         r4vN7xTV8s3IE/sj7v27V9JB/ifmX2NP1/bHhyc/Rb2BirbF3nPcOf0beSqQ0yluUHBJ
         z96blV1LSJOYQGivtMfyllJULp1K2w5XC8XyutR9ME2oHX9lAreE+BRnliOtud8OIyQE
         ueSaS0UqjwKaW1Ele5ouQvgEIIkD2iMGOXRHYhmwF+LYL7b/amKCvALhIlZVHmm08nSs
         cwYGze17ifp1pBEzWgwpfpaOPTzoZieiltZRFla95dYJ6sy21EMKx9lovPlYWHjXrHTa
         eDVA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from
         :dkim-signature:date;
        bh=zK5QLIW85nz1zVFqkUnOGvmwzlA1XAn7Um1knwojFcg=;
        fh=uv6VTq1Vw1n39JLk2ft1XmQOKQjHGx8HBYaf+UZJ5zw=;
        b=oEIvCXJ6Hm3FYNgnRCQUnzrQdok9X98BxHzQWcpEdGNc3aCVy9AxI9VNFGqCzP+nHV
         gmVGIl8/QXiNnzXHtuwSWYJvUk2DjuzOiL2RRTw91kM/BI757o3YbAGN5JZYRzxugzAA
         KfzLy7y0G4WPckILdYtsz1yfWnUXrWd+2h90KD0/9Ysq3T7vGMvubHCf8RI36rNa3WHW
         hDvwk0DzczAg2CIqcaLtc9NqbGb2/OCDCHdiNpVCzKLohcCDZzm81+3C1ilyyTcJ9jC8
         Mel4wRcpQ0j7VUc//LvcCfwJ3KuopKU4hUd9wtdv73Q1eblxbMzbWQjbaBTK/ff5vZoL
         c45w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=rGEbbs21;
       spf=pass (google.com: domain of kent.overstreet@linux.dev designates 2001:41d0:1004:224b::ab as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
X-Forwarded-Encrypted: i=1; AJvYcCXzAO2M9XLYkz6uT9+NDyPZ+eFrBItEXGVbVFpO7LBpg4Q4XlENG057GKzDW7KcvM0oZrby9eNgLdd6bSKQY42a0LEENITuQiYiaw==
Received: from out-171.mta0.migadu.com (out-171.mta0.migadu.com. [2001:41d0:1004:224b::ab])
        by gmr-mx.google.com with ESMTPS id b90-20020a509f63000000b005610f27d125si967469edf.0.2024.02.13.14.06.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 13 Feb 2024 14:06:38 -0800 (PST)
Received-SPF: pass (google.com: domain of kent.overstreet@linux.dev designates 2001:41d0:1004:224b::ab as permitted sender) client-ip=2001:41d0:1004:224b::ab;
Date: Tue, 13 Feb 2024 17:06:24 -0500
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: Kent Overstreet <kent.overstreet@linux.dev>
To: Andy Shevchenko <andy.shevchenko@gmail.com>
Cc: Suren Baghdasaryan <surenb@google.com>, akpm@linux-foundation.org, 
	mhocko@suse.com, vbabka@suse.cz, hannes@cmpxchg.org, roman.gushchin@linux.dev, 
	mgorman@suse.de, dave@stgolabs.net, willy@infradead.org, liam.howlett@oracle.com, 
	corbet@lwn.net, void@manifault.com, peterz@infradead.org, juri.lelli@redhat.com, 
	catalin.marinas@arm.com, will@kernel.org, arnd@arndb.de, tglx@linutronix.de, 
	mingo@redhat.com, dave.hansen@linux.intel.com, x86@kernel.org, peterx@redhat.com, 
	david@redhat.com, axboe@kernel.dk, mcgrof@kernel.org, masahiroy@kernel.org, 
	nathan@kernel.org, dennis@kernel.org, tj@kernel.org, muchun.song@linux.dev, 
	rppt@kernel.org, paulmck@kernel.org, pasha.tatashin@soleen.com, 
	yosryahmed@google.com, yuzhao@google.com, dhowells@redhat.com, hughd@google.com, 
	andreyknvl@gmail.com, keescook@chromium.org, ndesaulniers@google.com, 
	vvvvvv@google.com, gregkh@linuxfoundation.org, ebiggers@google.com, 
	ytcoode@gmail.com, vincent.guittot@linaro.org, dietmar.eggemann@arm.com, 
	rostedt@goodmis.org, bsegall@google.com, bristot@redhat.com, vschneid@redhat.com, 
	cl@linux.com, penberg@kernel.org, iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com, 
	glider@google.com, elver@google.com, dvyukov@google.com, shakeelb@google.com, 
	songmuchun@bytedance.com, jbaron@akamai.com, rientjes@google.com, minchan@google.com, 
	kaleshsingh@google.com, kernel-team@android.com, linux-doc@vger.kernel.org, 
	linux-kernel@vger.kernel.org, iommu@lists.linux.dev, linux-arch@vger.kernel.org, 
	linux-fsdevel@vger.kernel.org, linux-mm@kvack.org, linux-modules@vger.kernel.org, 
	kasan-dev@googlegroups.com, cgroups@vger.kernel.org, Andy Shevchenko <andy@kernel.org>, 
	Michael Ellerman <mpe@ellerman.id.au>, Benjamin Herrenschmidt <benh@kernel.crashing.org>, 
	Paul Mackerras <paulus@samba.org>, "Michael S. Tsirkin" <mst@redhat.com>, 
	Jason Wang <jasowang@redhat.com>, Noralf =?utf-8?Q?Tr=C3=B8nnes?= <noralf@tronnes.org>
Subject: Re: [PATCH v3 01/35] lib/string_helpers: Add flags param to
 string_get_size()
Message-ID: <bicga3cv554ey4lby2twq3jw4tkkzx7mreakicf22sna63ye4x@x5di6km5x7fn>
References: <20240212213922.783301-1-surenb@google.com>
 <20240212213922.783301-2-surenb@google.com>
 <CAHp75Vek3DEYLHnpUDBo_bYSd-ksN_66=LQ5s0Z+EhnNvhybpw@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <CAHp75Vek3DEYLHnpUDBo_bYSd-ksN_66=LQ5s0Z+EhnNvhybpw@mail.gmail.com>
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: kent.overstreet@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=rGEbbs21;       spf=pass
 (google.com: domain of kent.overstreet@linux.dev designates
 2001:41d0:1004:224b::ab as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
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

On Tue, Feb 13, 2024 at 10:26:48AM +0200, Andy Shevchenko wrote:
> On Mon, Feb 12, 2024 at 11:39=E2=80=AFPM Suren Baghdasaryan <surenb@googl=
e.com> wrote:
> >
> > From: Kent Overstreet <kent.overstreet@linux.dev>
> >
> > The new flags parameter allows controlling
> >  - Whether or not the units suffix is separated by a space, for
> >    compatibility with sort -h
> >  - Whether or not to append a B suffix - we're not always printing
> >    bytes.
> >
> > Signed-off-by: Kent Overstreet <kent.overstreet@linux.dev>
> > Signed-off-by: Suren Baghdasaryan <surenb@google.com>
>=20
> ...
>=20
> You can move the below under --- cutter, so it won't pollute the git hist=
ory.
>=20
> > Cc: Andy Shevchenko <andy@kernel.org>
> > Cc: Michael Ellerman <mpe@ellerman.id.au>
> > Cc: Benjamin Herrenschmidt <benh@kernel.crashing.org>
> > Cc: Paul Mackerras <paulus@samba.org>
> > Cc: "Michael S. Tsirkin" <mst@redhat.com>
> > Cc: Jason Wang <jasowang@redhat.com>
> > Cc: "Noralf Tr=C3=B8nnes" <noralf@tronnes.org>
> > Cc: Jens Axboe <axboe@kernel.dk>
> > ---
>=20
> ...
>=20
> > --- a/include/linux/string_helpers.h
> > +++ b/include/linux/string_helpers.h
> > @@ -17,14 +17,13 @@ static inline bool string_is_terminated(const char =
*s, int len)
>=20
> ...
>=20
> > -/* Descriptions of the types of units to
> > - * print in */
> > -enum string_size_units {
> > -       STRING_UNITS_10,        /* use powers of 10^3 (standard SI) */
> > -       STRING_UNITS_2,         /* use binary powers of 2^10 */
> > +enum string_size_flags {
> > +       STRING_SIZE_BASE2       =3D (1 << 0),
> > +       STRING_SIZE_NOSPACE     =3D (1 << 1),
> > +       STRING_SIZE_NOBYTES     =3D (1 << 2),
> >  };
>=20
> Do not kill documentation, I already said that. Or i.o.w. document this.
> Also the _SIZE is ambigous (if you don't want UNITS, use SIZE_FORMAT.
>=20
> Also why did you kill BASE10 here? (see below as well)

As you should be able to tell from the name, it's a set of flags.

> > --- a/lib/string_helpers.c
> > +++ b/lib/string_helpers.c
> > @@ -19,11 +19,17 @@
> >  #include <linux/string.h>
> >  #include <linux/string_helpers.h>
> >
> > +enum string_size_units {
> > +       STRING_UNITS_10,        /* use powers of 10^3 (standard SI) */
> > +       STRING_UNITS_2,         /* use binary powers of 2^10 */
> > +};
>=20
> Why do we need this duplication?

Because otherwise a lot more code would have to change.
>=20
> It seems most of my points from the previous review were refused...

Look, Andy, this is a pretty tiny part of the patchset, yet it's been
eating up a pretty disproprortionate amount of time and your review
feedback has been pretty unhelpful - asking for things to be broken up
in ways that would not be bisectable, or (as here) re-asking the same
things that I've already answered and that should've been obvious.

The code works. If you wish to complain about anything being broken, or
if you can come up with anything more actionable than what you've got
here, I will absolutely respond to that, but otherwise I'm just going to
leave things where they sit.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/bicga3cv554ey4lby2twq3jw4tkkzx7mreakicf22sna63ye4x%40x5di6km5x7fn=
.
