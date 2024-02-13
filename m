Return-Path: <kasan-dev+bncBCS2NBWRUIFBB2MCWCXAMGQEPAO4U2A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x340.google.com (mail-wm1-x340.google.com [IPv6:2a00:1450:4864:20::340])
	by mail.lfdr.de (Postfix) with ESMTPS id C98CE854068
	for <lists+kasan-dev@lfdr.de>; Wed, 14 Feb 2024 00:55:22 +0100 (CET)
Received: by mail-wm1-x340.google.com with SMTP id 5b1f17b1804b1-411e25bcf0esf931375e9.0
        for <lists+kasan-dev@lfdr.de>; Tue, 13 Feb 2024 15:55:22 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1707868522; cv=pass;
        d=google.com; s=arc-20160816;
        b=yKP6WvSXu13aDOSIPRqMVZvRgDPooKCDBAeXaeAqYG2lPkRJlkYTIvtvCAgEPLo9L5
         tDfdQWBSD5ZMKjCV9Wo2kRc0epA71oluNLECkOqAbkYND1Naaw6ubdXQd93irwLAmtsN
         7pTKeclUJ7ltD7DpzkoPbVbzahHtsCQQ2JEOrUGH0BV+q+X1djSBDsmI709v0WmJ9VYg
         vjLzfLXJVF/V2Cl7dhyatitGkYVDi9b1bn9QDYMvRQiyIcvv4mjDDf/Fk7jtCk0mGeTA
         Y+/M/EMPrld5GHaZx662wFmEuOuB0faZsmkP5AxYKEYfjaJ1iYbma7enKbhOLMGCMIIV
         AD/Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=KS42nkR0WIyGP2YIYd+cCZOHH1qBHDQ6e7p8Qlw2lfk=;
        fh=cR6zN01i46Qk/x85LoEoqlwnuEwkC1z5FQSnPKzKKuM=;
        b=sOdDN4tM1SKWzk0K30g2robDmIUDs8tAMpP/fc4yLSPLh41V5c9SkZOdpZ3VJ+79LS
         fzF06CtxihopdDBeM7h8Tbus95G9GAAdY84/MAS7M/8iAkirHmKffDCZqnGVRLeavT8K
         iB8TGEdPRTcb/LTXDMc2zxtbflDEWfeaVXLo25raO0X2xEVcXRzXxej0QrqvXT7+TCiD
         vcK1vUFLE5MQI/VZoiPnclWXCcHoagwBDap3pTYyG20TkVJUzWDphblbLxass90S1HEe
         BveXE6Se2peJdEhQHWS3/v5ZSTmJFIvx2mMzm7akyYCCmlRzGoWaUA4q4KIBJLlMGnFq
         yZqw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=ukudvr1a;
       spf=pass (google.com: domain of kent.overstreet@linux.dev designates 2001:41d0:1004:224b::b9 as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1707868522; x=1708473322; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-transfer-encoding
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=KS42nkR0WIyGP2YIYd+cCZOHH1qBHDQ6e7p8Qlw2lfk=;
        b=Ax7tvFsvLPwv/+ZrLtgBJn93FdW6XjD1u8oXIhyieH6wmFzyXbdHruTf9gdu4uarP5
         FyU0GWXWHoVSeuPqbX+OVQwtV53U9EQf+M3DyVWCDrNSxFRAqrkr4ObdPOfi0zwlqgYR
         M9dBLugF//vc8xNXBgfwx7h8ZNCiDjCca9M2Sha2CSLI5fEEeZSI4L8eNmAvl2YEfsr7
         XGx92qll8ywdzUyQVgZXQKn0dDPbWQbzsWwUqw+m0QGu2snsq+UFptMqtVvF0TxY4VYQ
         x28FLiZxOijTQ8PDi1/47SLH0rxjKSbnpRBghP89P3cVU6SekjI5uPrKPWGmqz+xakPA
         Ke3Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1707868522; x=1708473322;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=KS42nkR0WIyGP2YIYd+cCZOHH1qBHDQ6e7p8Qlw2lfk=;
        b=FY95MK1Hmu2VRfBcnwEea/NEEGvhKn+r13PoXxrv0Zgw/i5z9LV5l9fiQDi2B45jn7
         e6L2g1G+H40D5t0mbTKRTMwlCJ2i1+5Pc0NTO+6MgUbcfqcCOTRdzV2kopBCSZ/WHIZE
         l94vBckRtPAz5K+tyhYTjviila5sElhIWlJzu0he5Buy+XPPCxuqr4oc3xMMApYa5AFI
         1a9ymNaAXNtqpNhzn5a6YuwvCWdLO25Dkwgbbmww99++p8SqxiUhbBo/lXL3/CcYUaDd
         2DwPc2tgXe8VaTUZgqzSdBlh4mvWANkcq9uXyc104IduJ9hd8rnqGdurdlZNxCYM2w0v
         /wKA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUjMG+B45OX9CG2v/yAr1OlY3kTBoI358V1YryyEd/Qm45eZKiTKN+d/3ef8utXmj3vSao3x52OOQ//OAco4LJBtBNP3VZBCQ==
X-Gm-Message-State: AOJu0YzLgvqjJzbeIlm0yPGdxNobBOAcUOUIRHxUiUzf1wCJYZrn4JuZ
	9sSFPPRMqsQsh54HL8uEYNhTOdv08EEphQGNKULDh8XgBTFcVbPf
X-Google-Smtp-Source: AGHT+IEn1VAudhJUEijU6BdIrjzIdeHA/N7j7YPg4z715mRifl4WfOEIl3adEVKNvnN9OzrMV1Z10A==
X-Received: by 2002:a05:600c:3d8f:b0:40f:d34d:d4ea with SMTP id bi15-20020a05600c3d8f00b0040fd34dd4eamr1003681wmb.31.1707868521692;
        Tue, 13 Feb 2024 15:55:21 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:1d97:b0:411:c390:d06b with SMTP id
 p23-20020a05600c1d9700b00411c390d06bls578844wms.0.-pod-prod-08-eu; Tue, 13
 Feb 2024 15:55:19 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUNIRSqdC1FBENkq/KaaxHIt7sU9lG9OUhe5ZkhOaTAgZQqVehkPbjlMT+v1OrZR97FnRf2URZ+jJ569KWMvk/T7ljZeW6qMj10Gg==
X-Received: by 2002:a05:600c:6020:b0:411:d273:910e with SMTP id az32-20020a05600c602000b00411d273910emr973373wmb.5.1707868519597;
        Tue, 13 Feb 2024 15:55:19 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1707868519; cv=none;
        d=google.com; s=arc-20160816;
        b=ytqVXdoRDLdNFN8qvmH8cLRCwJMXiE7ecUdv3YxNgzSvCbN6T3fwVOpE2sLiOV3Z/R
         otzm3HQVIYl6kfISJwBjeP5koiU1uMKFrSXXWosMFxK9rUNkq+Jjdxuf3iRgGqbYduQY
         pdsJuWV/mqN2PR0D4sm7OaR3epk9K3uLHsUrtGlaXMZ2hHvtZirdY/40fNsiE2r9Gc0m
         34svq5w+jt1+Hh994P5K3bTUE/Ps6j9z0KzxxSkekchj5nhlgeFqU+QcmyV2SrogJv10
         yAIls/tkft6l7dFqenxOI0Ld9pfNk1oTAks6pqN0XzuADiXBFxRRuxP9dwKEiF/CxFXL
         DRsw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from
         :dkim-signature:date;
        bh=7lYndZ54iAip9ue1kfzMMJiei98FQfeXzYAkwe/hBTc=;
        fh=KvXhSEcv6i0+W7PoVMP+M7gYMK6wgudKZNQqYbbkkck=;
        b=e6+1zOTW7JIuExkB0uKZlxxs0Qrcmo9lsHW0TEkzv6OO433tW2vqpmshcipOtWrQcY
         MVCILSm1oZZFa1iY6dsUA7ole+N3go56eLqrvHAoPVtdmp4TYdl59hNvZddpW+oIE7KF
         X0wJzX+j+ifw7D2Rbvzkq6Pw1d91akD7LIMCh1+E+vjqSLQPSlfaSFDZNloShs8GBghO
         /No1csqdqCw8KcUG21TSZX8Qi9ujvjl0klA7otpI3IFvEEbOvJXi8pqRX9pJshyCbB/q
         raG1vl/+PYLG5z3T6qDT2VCGXG50JfvlDvytFpPvJ0FryVZc03pT/10sDJaVUaIB2M9K
         xKDw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=ukudvr1a;
       spf=pass (google.com: domain of kent.overstreet@linux.dev designates 2001:41d0:1004:224b::b9 as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-185.mta0.migadu.com (out-185.mta0.migadu.com. [2001:41d0:1004:224b::b9])
        by gmr-mx.google.com with ESMTPS id p15-20020a05600c1d8f00b00411e5e21c2bsi9176wms.0.2024.02.13.15.55.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 13 Feb 2024 15:55:19 -0800 (PST)
Received-SPF: pass (google.com: domain of kent.overstreet@linux.dev designates 2001:41d0:1004:224b::b9 as permitted sender) client-ip=2001:41d0:1004:224b::b9;
Date: Tue, 13 Feb 2024 18:55:02 -0500
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
Message-ID: <qjuicq6spjc7lwnsmcqthgcrwckgrbceombsxtcycol42smlzq@ufdlxckvfi6t>
References: <20240212213922.783301-1-surenb@google.com>
 <20240212213922.783301-2-surenb@google.com>
 <CAHp75Vek3DEYLHnpUDBo_bYSd-ksN_66=LQ5s0Z+EhnNvhybpw@mail.gmail.com>
 <CAHp75VcftSPtAjOH-96wdyVhAYWAbOzZtfgm6J2Vwt1=-QTb=Q@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <CAHp75VcftSPtAjOH-96wdyVhAYWAbOzZtfgm6J2Vwt1=-QTb=Q@mail.gmail.com>
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: kent.overstreet@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=ukudvr1a;       spf=pass
 (google.com: domain of kent.overstreet@linux.dev designates
 2001:41d0:1004:224b::b9 as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
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

On Tue, Feb 13, 2024 at 10:29:34AM +0200, Andy Shevchenko wrote:
> On Tue, Feb 13, 2024 at 10:26=E2=80=AFAM Andy Shevchenko
> <andy.shevchenko@gmail.com> wrote:
> >
> > On Mon, Feb 12, 2024 at 11:39=E2=80=AFPM Suren Baghdasaryan <surenb@goo=
gle.com> wrote:
> > >
> > > From: Kent Overstreet <kent.overstreet@linux.dev>
> > >
> > > The new flags parameter allows controlling
> > >  - Whether or not the units suffix is separated by a space, for
> > >    compatibility with sort -h
> > >  - Whether or not to append a B suffix - we're not always printing
> > >    bytes.
>=20
> And you effectively missed to _add_ the test cases for the modified code.
> Formal NAK for this, the rest is discussable, the absence of tests is not=
.

Eh?

The core algorihtm for printing out a number in human readable units;
that's definitely worth a test, and I assume there already is one - I
didn't touch that.

But whether or not the units suffix has a space, or a B suffix? That's
not going to break in subtle ways; that either works or it doesn't.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/qjuicq6spjc7lwnsmcqthgcrwckgrbceombsxtcycol42smlzq%40ufdlxckvfi6t=
.
