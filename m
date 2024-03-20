Return-Path: <kasan-dev+bncBCCMH5WKTMGRBPOL5KXQMGQED3PL5BQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe3b.google.com (mail-vs1-xe3b.google.com [IPv6:2607:f8b0:4864:20::e3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 342FB880E27
	for <lists+kasan-dev@lfdr.de>; Wed, 20 Mar 2024 10:00:47 +0100 (CET)
Received: by mail-vs1-xe3b.google.com with SMTP id ada2fe7eead31-4769925b023sf328657137.1
        for <lists+kasan-dev@lfdr.de>; Wed, 20 Mar 2024 02:00:47 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1710925246; cv=pass;
        d=google.com; s=arc-20160816;
        b=hbMu0MhFHX5E5JuvKwlldFJB/8W7DOh2zan516rf3MBobwdTxs96aDlm0K1MSKu8+x
         NrwTlO7z04AuCfpHOlIZ+vVdn2cBKWuC/aUnBtZ0O+HA4PzJ4Sf81SJQlQEtQ4GVcWth
         kCDKhiCvipeM5zhdt1MhxdzuDxe6UjD9FkvasAQ16lkiURjnzGJo+j6L6X/R2LXILbYi
         Jd3PldChppVmBPyGSLosA3hCrWVkYOzzpGRdgsu67COanbfmHAUtodoaPrxmI1bK5uVY
         bc8sRp+m8xKcA1IrfZcqDuir2dbSs/lE9fenvTsfWzEEJLaQ2itoIEfqhaxpovewsuQr
         m+JQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=2x0Sa5+AvhEDHkX0IE+qOAHl/3u3UiKfTL4p4cMkrpQ=;
        fh=SrgHZK7u1DzKV0+XfX3rKvnFGHpebyZgLV192omEGqw=;
        b=v0GhBKI2hLJ2UASYBUfqLq7Q2HgH5u7gjJFiyBU7XtTJHB6BHkJbLjPlnJHu2vBoJJ
         oWy6+Om940hotiVjEhfHfoE9m/oY/Ohu1zjLoF4lnYA33CO48fD68Mx8NxreJlD/4pPr
         D+p2s3E9PYUs8/cMNrkBK7cZJE7fyIW4mJeIX7wmP6uJIcdFp+GGMu1Ck08WV65QAVi4
         u22BaRmGOWA3FEJidxJZD7Bz9w9HUgvIGolCODbYMhzOE6QHacgsxslfre0+fvHDSC5J
         uAls/x2jjUkaWeTw4aEBxgTChF9pcN5JoaHPNUGyhYRJPgHloljO1LKFcZ9LGz8FeGol
         qx/A==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=QN2pfzlL;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f34 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1710925246; x=1711530046; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=2x0Sa5+AvhEDHkX0IE+qOAHl/3u3UiKfTL4p4cMkrpQ=;
        b=iDht6QEy/OMHfYQph/trcAzG0P4E/FE3kt4S4wCnUO3AY8gkDpwVawM/yAJzRnnLOo
         wEEC8TxLYfL3fz8ivlGYBphu6T8LQb3m0sdSCvd2btorO4BkOQdVUmH1xMrtSrT0MP5Y
         bhES8IY2OWyBXWJpV8KQCSfdSpiLk7+KRcmv11KTirmqNLAvBat2al/kZjopRyK4puOx
         ykbeI4u9OqMnU7gUsUDA0tNcRnx/GWFlYSTSRSZg7rfqjiE8/as3GVeMMgtvNvC/LC6d
         tmPek1gnbwUCtBD2y9tA9lPbU1lu+RSnAyqJfTN2cVB+EmyZKdUCalxcTgmH6+KRWk4k
         92Pg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1710925246; x=1711530046;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=2x0Sa5+AvhEDHkX0IE+qOAHl/3u3UiKfTL4p4cMkrpQ=;
        b=iipP2m1XYjBERqjgdiVzfqnStyDShGQa0Vtx38S9St9DF2hhFcikdDL2OYtg8pCU35
         Wrb0nbHHPZho5+EWXZyjp/n15xTMOvIY3VnLK1+Ezrts03UFCH9J6EEaAmZGW/FdY9+K
         EksTW+sDgyTjp6K0Nx+PEf8KzWLZRJruENXL+GaPG8y6tKBp4UsgB9mUaCBmXpHadPvu
         3ZnLx5zbh3TShnYEVoMVws+jdTW9X+UhdRGF6Xq/sz/U2h79LDUZvfOnqFnxfs8B0Iy1
         /78Hyhue4CW9Ose9V64yfSWTm7n5MTWb8ImcV8WO53Tko00Y9YbOmeC95HVopX9MQJXH
         CNdQ==
X-Forwarded-Encrypted: i=2; AJvYcCXe+YEJM+lx3uFTvZuzX8CyVmY2xqlyTPn+4IEAnz1av3LM80TW4k+U9vxI8bnn6fRHWv2T+V4vymsDqvvehTxS39qEUEJHhA==
X-Gm-Message-State: AOJu0YwXHEPpDLwdkXksn7u3AO01z3GGv6Uhd89/EsAhxjR3BalkJ+3a
	/vnG/s8dlSHb0gXVIf9A7Z2NgUf0EQetOFVM091p9yTJ/+AILnoR
X-Google-Smtp-Source: AGHT+IFxNcg3CBUDSSgOIBtRgh7SidSfMFiRAqPOzewcsxS9XlvAGTLNG17fvvEL64st5a5xF0qhKw==
X-Received: by 2002:a05:6122:333:b0:4cc:4cdd:3faa with SMTP id d19-20020a056122033300b004cc4cdd3faamr3930946vko.0.1710925245665;
        Wed, 20 Mar 2024 02:00:45 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:626:b0:68f:c7e6:37e3 with SMTP id
 a6-20020a056214062600b0068fc7e637e3ls152157qvx.1.-pod-prod-04-us; Wed, 20 Mar
 2024 02:00:45 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXG7wIdMsWdPmjQBaXr1vgZjuKbfyO+UetPXhTBCacABOFoaZxVLwl2InqQmMAENGQGezwviKIi+4znA2oHErAOyVFfzTIRZAIX6g==
X-Received: by 2002:ac5:c7b7:0:b0:4d4:1b6a:7924 with SMTP id d23-20020ac5c7b7000000b004d41b6a7924mr11245615vkn.8.1710925244977;
        Wed, 20 Mar 2024 02:00:44 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1710925244; cv=none;
        d=google.com; s=arc-20160816;
        b=u9U329Lzw665c0cCt6fQz7S14euvvqBPyjScxsIzF5OaXZmanDrNQs/E95Y5XAOE4L
         68gbS1fVH7rgLCRWIOsbjYf3Ur5Rmfnwy+M1Rp2awbNEVdBsSAAZPyuDkHZBdLFq7DIa
         IA22426j6wOc7oZ0poo0S6cEnBd3uXsIVobLtFhMEt3+Nyg+2Ag/WKlfEhSfTiG2jcGJ
         SWNej+QmyaxSxfRUIqoR53cdVISsBs+GtMACMKTI00vCKIsON/7r7ok4g5LxRMwVaxiP
         2Yfv6Usb/QNBXS/WLCH8tZjrud+0B7zqcVNmeWbdV1yjDXzx6MsVBMbEpCM9maCBQwS4
         uQTg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=X/kfxvi+pcqoUxKaQPTH3Bpr3S7uOGIOTjzRG7qFRLM=;
        fh=qqoPlotmNKwLjvqSVylFwUFOq+45CeLepYMGvUVqRHk=;
        b=cniUSzflR9JgNLP77EUH50GaiXHxAp9a7S428cckTFKf91AptEY5sIsY9OK1WdMpqf
         cCfoWCNhrj9HHJl/Aen3gNWixcLAOI6S23pk2EeMx/Lyg5hV93E68lLOfVmI+SCIRVhw
         RjEk12chWHQjAzpPLUJPge4YNB7MrW8Gbjy+KkY7zpNK6MHsIviJNf2Vrzg3quOU8az8
         6eokkoj3JQ/9RThdUkQDW9+BGglh/BWDl0NJUeOWJGb5XuRkAewdV1tLwGLd6KBHAxOs
         SlxA+T466zYAALqdZUvwdrQXdy4uDHdLH7IQe+vwNx2dh0ESNgn4JnRtj9yMXcuPqoPj
         00wg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=QN2pfzlL;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f34 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf34.google.com (mail-qv1-xf34.google.com. [2607:f8b0:4864:20::f34])
        by gmr-mx.google.com with ESMTPS id s26-20020ac5cb5a000000b004d406833c17si1296587vkl.3.2024.03.20.02.00.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 20 Mar 2024 02:00:44 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f34 as permitted sender) client-ip=2607:f8b0:4864:20::f34;
Received: by mail-qv1-xf34.google.com with SMTP id 6a1803df08f44-6918781a913so30439276d6.3
        for <kasan-dev@googlegroups.com>; Wed, 20 Mar 2024 02:00:44 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWCvp8F/IYVsyZFHyXq6B0xuxx8HMD14ytChLCdiyONRyiLpfhtLqDEibCt/jwpVLQZsILHcFViOUoBZbh8JiFkvvRdbgi+tCXcWg==
X-Received: by 2002:a05:6214:183:b0:690:c334:a5ca with SMTP id
 q3-20020a056214018300b00690c334a5camr19018977qvr.59.1710925244501; Wed, 20
 Mar 2024 02:00:44 -0700 (PDT)
MIME-Version: 1.0
References: <20240319163656.2100766-1-glider@google.com> <20240319163656.2100766-2-glider@google.com>
 <CAHk-=wh_L4gKHEo6JVZxTZ7Rppgz1b5pt2MJyJ2mZ-A8-Mp0Qg@mail.gmail.com>
In-Reply-To: <CAHk-=wh_L4gKHEo6JVZxTZ7Rppgz1b5pt2MJyJ2mZ-A8-Mp0Qg@mail.gmail.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 20 Mar 2024 10:00:05 +0100
Message-ID: <CAG_fn=Wms_wnbfFSD6YAmzBZKxh2anX1t=9ehPyoNE8JW-7MVw@mail.gmail.com>
Subject: Re: [PATCH v1 2/3] instrumented.h: add instrument_memcpy_before, instrument_memcpy_after
To: Linus Torvalds <torvalds@linux-foundation.org>
Cc: akpm@linux-foundation.org, linux-kernel@vger.kernel.org, 
	linux-mm@kvack.org, kasan-dev@googlegroups.com, tglx@linutronix.de, 
	x86@kernel.org, Dmitry Vyukov <dvyukov@google.com>, Marco Elver <elver@google.com>, 
	Tetsuo Handa <penguin-kernel@i-love.sakura.ne.jp>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=QN2pfzlL;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f34 as
 permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

On Tue, Mar 19, 2024 at 6:52=E2=80=AFPM Linus Torvalds
<torvalds@linux-foundation.org> wrote:
>
> On Tue, 19 Mar 2024 at 09:37, Alexander Potapenko <glider@google.com> wro=
te:
> >
> > +/**
> > + * instrument_memcpy_after - add instrumentation before non-instrument=
ed memcpy
>
> Spot the cut-and-paste.
>
>              Linus

Nice catch, will fix.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG_fn%3DWms_wnbfFSD6YAmzBZKxh2anX1t%3D9ehPyoNE8JW-7MVw%40mail.gm=
ail.com.
