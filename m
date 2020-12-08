Return-Path: <kasan-dev+bncBD63B2HX4EPBBSV3X37AKGQEDUYQ66I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3c.google.com (mail-yb1-xb3c.google.com [IPv6:2607:f8b0:4864:20::b3c])
	by mail.lfdr.de (Postfix) with ESMTPS id E002A2D2E67
	for <lists+kasan-dev@lfdr.de>; Tue,  8 Dec 2020 16:37:47 +0100 (CET)
Received: by mail-yb1-xb3c.google.com with SMTP id z1sf6001368ybg.22
        for <lists+kasan-dev@lfdr.de>; Tue, 08 Dec 2020 07:37:47 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1607441867; cv=pass;
        d=google.com; s=arc-20160816;
        b=buG2ZCvFdRKoLd1JtxVLHPC2KyXMt4NEnKXv4XwbupeYx6mnSeTdoKsDPNg348U7Ju
         3us5TpETqEe76uJfkNqqTyR5oxKVQaeuqbaqgRUVlh9I4UeQ5G2DqHhtG/bO5t00LeMQ
         ZYI3647AEaDaPg+ViA7f/kl4dDQM2bqi0skXI5lcxHd/GHMKCSXOslry5mVEcx+C1xOn
         8/w3KhL3260vXZGF8s5OAV4ckBCQaJnHoOODggqmA7kAk3CxXOqvLTmA34ndKDiL5LfW
         nHA3Zok1weAOTQx0rgLMgWzwAOeVMq1VhRg7TyzkflhlJRNEk8/ZvfV3PYsXOG4p3F9F
         T5uw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:dkim-signature;
        bh=DsKasOHbXkM7Xs+ZlCVl2u3XJRDOJvIwcLreQwl4LnA=;
        b=vUuhNa19CvaC/JBaPmRvigE6xtN78xJflVz/y1+4VyTUbRT7Y58320lhwMrApXcA1c
         KlB7Ot7a6rUmmf7mB5V8ZPj93jCdcwHB9gi5yu2OHx46+ckJtlNEw8yNwCn0ufBgqTT+
         9bngI2dnM6JkGi4O9c0wZB2vhih96Cjbl0AwMTQg/2xSh83JVfdB9ILKfkdC9j45E5xF
         4pLKZ3WGauR2eU8nHlr/n/smD3u705LPb9k5Kdg2loGVYruvUorke3r9cSL2sSddDOZy
         8lE5YLc/anQbUTurrrARstM7FM3ktbL1gCXMUH5pVXJ/pusKJ0B6HOhQs6cb25kuiNX7
         sysQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@purestorage.com header.s=google header.b=DpwWR3Xw;
       spf=pass (google.com: domain of joern@purestorage.com designates 2607:f8b0:4864:20::52b as permitted sender) smtp.mailfrom=joern@purestorage.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=purestorage.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:content-transfer-encoding:in-reply-to
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=DsKasOHbXkM7Xs+ZlCVl2u3XJRDOJvIwcLreQwl4LnA=;
        b=SS0blGKSUfdfqF+38801CX+bTEEsHeny5AlkPsiTNKR1QWbDxoMCntYXfSqB8MPkju
         NNPqNYruAGxZEZbS76jWOXLq0QJaPs1nsr4NoKmUnNbR1bV+iqKXtjcDXkCdByxRQLTr
         x60yJw1DWL98HvXFkTolG+jhhwryZ8BpFVZ8/4CX+0XXofiTvYmJUc8YwAmXU4M8RfiH
         PMrCgXmhKiLmuFH/iQir7bmVSxACJvFE2oxvIzay14iZAxSXnWxX0odnDzMD4L7AYDvJ
         L+mdAh2ygEV6Rbc3vgL5hMJXCpMqdJxXYr486myL0NWZv/2gbMPSbNjh4ue+Xt92flw3
         au0Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:content-transfer-encoding
         :in-reply-to:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:x-spam-checked-in-group
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=DsKasOHbXkM7Xs+ZlCVl2u3XJRDOJvIwcLreQwl4LnA=;
        b=Vio1IV0EIdt/AqmEvf50737zv7prj78zyWr18G5goXOJFm5aAFHUT3SVt2HyogRcOV
         ai8vJmQ/uznvBq/Xbhnk/nIqy8Nslx0Xa79hFz/pOypb3KQRqDzs7OVbNVUVttvHXRzc
         D9HVYqgiMPvoQAaZ0opkAfuQ4Y/E07zfalOASQSfIIbPtv2Mi0SxmXodQrzyD4PnHzje
         kFB8A49S+xWexktpJ490Vd9R0eyH3iCsD22hERz9lCnZJK6TWoLKn3BIYB4ZrcOoHGM+
         hQAOqR7IfrIDVYup9VUwS8l9LanpH5xyl50uXbwPQyUXYkXocR6HcT5t6x2bqAU1NEU/
         FZ2w==
X-Gm-Message-State: AOAM5325EmRx9qg3KSTEwG6TOQPQwEYoityWd8kL51GSMQrskBjDOoWo
	VUF25nUiRqOZeEB9rdjrcx4=
X-Google-Smtp-Source: ABdhPJyVUhEOydRtBMyvCwGiXkbaKoG6tAM13UldiZJSQwaBV0pcHO23aoZTjNK1jXn9PMiMdiv8dg==
X-Received: by 2002:a25:810c:: with SMTP id o12mr31397911ybk.74.1607441866809;
        Tue, 08 Dec 2020 07:37:46 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:b581:: with SMTP id q1ls9912063ybj.6.gmail; Tue, 08 Dec
 2020 07:37:46 -0800 (PST)
X-Received: by 2002:a25:2c3:: with SMTP id 186mr30821635ybc.205.1607441866388;
        Tue, 08 Dec 2020 07:37:46 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1607441866; cv=none;
        d=google.com; s=arc-20160816;
        b=jCsVrB1XPDxwlXW+rKH07RwIPttbnI5CaH8csUm1SuLB3RgLT2qYlhwlGyYu8HMq4b
         5/kmzA5IGg0aXePqjh60B7aOij6HYRM3u7kX/HJFidtv9bt3q851UWZpn4164lzCHzbX
         LdIuwm/4WSnJNRDdweRJ9hUmM2pG0jmHMTiQfO4CSyCdKfpjyGp7jmSu17j909Jf1Ong
         3WBYPEA4mQKt64SoJG2UttbWfisSR/K+77m7rob7JyAhnhPjrkVt0nlbIBYC77CwKYQI
         dylGWqY2cT6V5vEC1xQy6GDlX3Z+u/O1kFR8v/4OUl0t0pAyXIoJWFpUBUnuhbBPtay/
         b/ww==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=OKH1Sd6eu3RHRznGi68vKul95JMNcEIQGGdw3yOt5w0=;
        b=vVGKeIIraWzUD0fqhR0b8Uyw9f1KZVdB66bMIrn2JQ26saB3I+32ruKT4+BocBejHY
         lOvPk2ipomB4mdb88mqjUDIIMgoKkCzi0W5DWjsGMCOhKH8p+Sc98pNHBDFR1DHDcXMb
         KAcEtI/0bzKDshiEno9hiqppHvNCr0NLS7e0G9K30eSRh5JGQc6ND/eofdZMpWwwZzGc
         i3okAfO8+t8puQ26H33U2tf/Nyv9Pq6/Mw7bYKGLWbi5+GCqRmKhik6Zeyl5aWKP2j6L
         ewRtjsGjWjvdCAYHduij+cOCRayi1SkiC3u80tHdBKKPZHkBtMoex5l83M5Mc4IPlUDE
         cGqg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@purestorage.com header.s=google header.b=DpwWR3Xw;
       spf=pass (google.com: domain of joern@purestorage.com designates 2607:f8b0:4864:20::52b as permitted sender) smtp.mailfrom=joern@purestorage.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=purestorage.com
Received: from mail-pg1-x52b.google.com (mail-pg1-x52b.google.com. [2607:f8b0:4864:20::52b])
        by gmr-mx.google.com with ESMTPS id u13si1202010ybk.0.2020.12.08.07.37.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 08 Dec 2020 07:37:46 -0800 (PST)
Received-SPF: pass (google.com: domain of joern@purestorage.com designates 2607:f8b0:4864:20::52b as permitted sender) client-ip=2607:f8b0:4864:20::52b;
Received: by mail-pg1-x52b.google.com with SMTP id w16so12472026pga.9
        for <kasan-dev@googlegroups.com>; Tue, 08 Dec 2020 07:37:46 -0800 (PST)
X-Received: by 2002:a17:90a:f288:: with SMTP id fs8mr4678894pjb.184.1607441865657;
        Tue, 08 Dec 2020 07:37:45 -0800 (PST)
Received: from cork (dyndsl-091-248-004-182.ewe-ip-backbone.de. [91.248.4.182])
        by smtp.gmail.com with ESMTPSA id x5sm4001224pjr.38.2020.12.08.07.37.43
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 08 Dec 2020 07:37:44 -0800 (PST)
Date: Tue, 8 Dec 2020 07:37:40 -0800
From: =?UTF-8?B?J0rDtnJuIEVuZ2VsJyB2aWEga2FzYW4tZGV2?= <kasan-dev@googlegroups.com>
To: Marco Elver <elver@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>,
	kasan-dev <kasan-dev@googlegroups.com>,
	Alexander Potapenko <glider@google.com>
Subject: Re: GWP-ASAN
Message-ID: <20201208153740.GC2140704@cork>
References: <CACT4Y+Z=zNsJ6uOTiLr6Vpwq-ARewwptvyWUEkBgC1UOdt=EnA@mail.gmail.com>
 <CANpmjNPy3aJak_XqYeGq11gkTLFTQyuXTGR8q8cYuHA-tHSDRg@mail.gmail.com>
 <20201014134905.GG3567119@cork>
 <CANpmjNPGd5GUZ0O0NuqTMBgBbv3J1irxm16ATxuhYJJWKvoUTA@mail.gmail.com>
 <20201014145149.GH3567119@cork>
 <CANpmjNPuuCsbV5CwQ5evcxaWd-p=vc4ZGmR0gOdbxdJvL2M8aQ@mail.gmail.com>
 <20201206164145.GH1228220@cork>
 <CANpmjNNZDuRo+1UZam=pZFij=QHR9sSa-BaNGrgVse-PjQF5zw@mail.gmail.com>
 <20201206201045.GI1228220@cork>
 <X83nnTV62M/ZXFDR@elver.google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <X83nnTV62M/ZXFDR@elver.google.com>
X-Original-Sender: joern@purestorage.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@purestorage.com header.s=google header.b=DpwWR3Xw;       spf=pass
 (google.com: domain of joern@purestorage.com designates 2607:f8b0:4864:20::52b
 as permitted sender) smtp.mailfrom=joern@purestorage.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=purestorage.com
X-Original-From: =?iso-8859-1?Q?J=F6rn?= Engel <joern@purestorage.com>
Reply-To: =?iso-8859-1?Q?J=F6rn?= Engel <joern@purestorage.com>
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

On Mon, Dec 07, 2020 at 09:28:13AM +0100, Marco Elver wrote:
>=20
> That seems reasonable, but our benchmarks suggested something else.
>=20
> We had a naive version, although that version used a per-CPU counter to
> enter KFENCE. It did:
>=20
> 	if (count-- <=3D 0) { allocate with KFENCE; reset count to non-zero valu=
e; }
>=20
> I ran benchmarks where count was (2^31)-1, so only the branch and
> decrement were in the fast-path. That resulted in a 3% throughput
> reduction of the benchmark we ran (sysbench I/O). Details here:
> https://github.com/google/kasan/issues/72#issuecomment-655549813
>=20
> I hardly believe that the per-CPU decrement alone contributed to the 3%
> system throughput reduction.

The decrement requires a write, so it is noticeably more expensive than
a simple compare&branch.  But that should still be on the order of 1
cycle or maybe 1.5 cycles, not 3%.

My best explanation right now would be the various non-linear effects.
Top of the list is that adding perfectly-predicted branches still get
added to branch history and effectively reduce the history when
predicting other branches.  Daniel Lemire demonstrated effects like
that.
https://www.infoq.com/articles/making-code-faster-taming-branches/

> But coming up with a one-size-fits all solution based on benchmarks and
> incomplete data is hard, so let's try the following: If you're already
> willing to trade off 1-3% performance at the cost of much higher sample
> rates, by all means -- and do feel free to switch the static branch to a
> dynamic branch. We can make this a Kconfig option, and compile KFENCE
> with one or the other. For your usecase, that might be the right
> trade-off. For ours probably not, because we were getting negative
> feedback even thinking about adding a new dynamic branch to the
> allocator fast path. :-)

Heh!  I've given similar feedback to others. :)

J=C3=B6rn

--
Ninety percent of everything is crap.
-- Sturgeon's Law

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/20201208153740.GC2140704%40cork.
