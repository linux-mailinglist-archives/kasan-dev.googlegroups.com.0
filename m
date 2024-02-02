Return-Path: <kasan-dev+bncBAABB4736KWQMGQEJRYO4PI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13c.google.com (mail-lf1-x13c.google.com [IPv6:2a00:1450:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id 00B0D846D45
	for <lists+kasan-dev@lfdr.de>; Fri,  2 Feb 2024 11:03:33 +0100 (CET)
Received: by mail-lf1-x13c.google.com with SMTP id 2adb3069b0e04-51134ecace6sf653839e87.3
        for <lists+kasan-dev@lfdr.de>; Fri, 02 Feb 2024 02:03:32 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1706868212; cv=pass;
        d=google.com; s=arc-20160816;
        b=nocSb7GiGHPJIobwbfryHrg2kug6RyDceyHqC/a+NviK6tjKHJ0Glj4t0tSd4qbKvj
         g5jV+pTDoecL6hIqyWU6cFuiFOCDPL5jM18PVK0FCmjjlwutuGyjjWF68fVl6/SCDG9f
         e+0A1hlBiiDYQjUzlM4jcsRoNcugOQHaIDKAsslHjh8bTnBnCaQ+zE4BK/vEythphavz
         EGDqhoXvTX/Wvc+hR8rsUgAPJMemEr+XH2zDNQBeRM1QsvhKLBNIVX37hsppvwAIm9Kr
         EZFsEoeylYog68ltMoK90W2+8yd9/Y8Y2qhkYZ6FEO7ES/0BaM4rlBAkiHA9AWwhZBde
         oKGA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=ToupetuLwu/OSNSDCFmeFn9LwIHKn4/AD2emOukIlNA=;
        fh=Na+8CwzhFkKQ+Pnjs/YKFaH61yHyZCdyAbi9q+fSZZA=;
        b=fMMp3AcmMYPnEnopEI544fGT60FsNXBshhyLwcsdraOEREHbr8/Zq3sGGZqkXCUkNE
         7Ln5vDHZfsxlHRJFUlbVIpLG2gOLuUtmFD8a99ecbbP9rBc4y7S9ZSHg9LO9boZKR8iE
         bI0QPJg+yT5sZixKk3k28rOB80mcaJOkE4zjcCWAr0cPIAfZ9fhqSd9iemwgfukAntJF
         txaVZeDzHYF5TD5rbABiyd+UEbb0xZ+oFDY3kFpLBW+sezSxOXp6PWBjGAdnxAMj1LPt
         F1aoZBlLmA63zpVyMU+MhBlQqSdC4d/FjBiMAhOOzM+XSC7mzjzYW1ONehmxkrI3OI0A
         j3fA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@tum.de header.s=tu-postout21 header.b=RPVzcIDU;
       spf=pass (google.com: domain of paul.heidekrueger@tum.de designates 129.187.255.138 as permitted sender) smtp.mailfrom=paul.heidekrueger@tum.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=tum.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1706868212; x=1707473012; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-transfer-encoding
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=ToupetuLwu/OSNSDCFmeFn9LwIHKn4/AD2emOukIlNA=;
        b=II9lG55pteOTPI/8No+w/8uWQsRD7tWcAPMyJ3en6K9dz53xyw1QYAmhx5R/za4GbJ
         Lelp8GnlZHcf/SsPPPiS/K0rmnY6jQgrzwhHcwYmozwhPm+reUkylQ27KxTTEOam3oA8
         p4teZCmQ5dlebgCQuDe4cZhv5QC0mBn9CN7rBgsUGJNNP5RMD5dHSjEl2ogo1npBKfLi
         ihsRDWFc4+MIrkQfY+kkOrm+YFMyQjVY7Rj8EAK6VPkT4cfZSxKekfq5y9gquTly5KSv
         GS4B4TcvwXAny7CjXeHGcEIOEGjZZpiUcBh29Nh4eCMrAXqpiCEqQEziG31UOn2Dvje0
         KW0Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1706868212; x=1707473012;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=ToupetuLwu/OSNSDCFmeFn9LwIHKn4/AD2emOukIlNA=;
        b=Sc7y2iHl3Xl01UIyxiIDDNG6zq6WftvmQHk9EoB7avh7ESoUv48ExYX4952KEBbB7Y
         cBSaGjUyJZCJ8viCF3u+QvZGVPolLepC2ToRhMGUV8DouPyDOt/Jiz3EBWrTqffIb3fh
         bCn72bVMEmZQsNHxqkz1aVgzOtl4x4RLMkb7lCZQwZXZKrFiWlTkM/ijMr4Z5u84ERKK
         Xi2oAXOMZSUgCvxMTArPDnCtx3PLcDefiA8ytFZ2gb8dSwTLxiGICRq4Sz1Ys3VEvwJr
         uI4rrWkA6i4lQXferEf3zUOb1DhFA4MM3/n3t9ZcDSa6yrYDHrI51HrWiMnI+/B0QQvi
         QcrQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yws9TVY2+hc0zedTf7mD4WJGpgYxsNANIhK8ZQEUibxOwo7BSkg
	LHSMSiMP2qDqQbPPH2+9fV79mPf992kaPqHOLA/Hn8IAniTF8NzH
X-Google-Smtp-Source: AGHT+IGb7jnG2PgHA7mpPx75nB/cBwDWUS5ce5tC2ZV2eTye0JdYqPmmgaONDgse/7FI3CM+77Goaw==
X-Received: by 2002:ac2:4c3a:0:b0:511:3701:95fc with SMTP id u26-20020ac24c3a000000b00511370195fcmr727574lfq.24.1706868211541;
        Fri, 02 Feb 2024 02:03:31 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:e9e:b0:511:3755:64b with SMTP id
 bi30-20020a0565120e9e00b005113755064bls241205lfb.1.-pod-prod-07-eu; Fri, 02
 Feb 2024 02:03:30 -0800 (PST)
X-Received: by 2002:a05:6512:4023:b0:511:3356:dffc with SMTP id br35-20020a056512402300b005113356dffcmr1721157lfb.14.1706868209790;
        Fri, 02 Feb 2024 02:03:29 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1706868209; cv=none;
        d=google.com; s=arc-20160816;
        b=m3B04pUWEspV4PlYzDd9J7eD2NTp21aHyXGqM7f2QbDUYHg9kzMsTm+Y0R+paLuutW
         qfdh2vGGEB6tMtrb+IFaZBTiY4r4MbuYDlLw/XVkotVetDgp8CIXcEqj98gt2oYX8Pru
         fQxsuHaNPEQJ5L/h4uN4AUp6pej8lLljK9EBj+xPzm/hewd2/hJLK/sTHEvcTHNeMlfP
         Y6TPSH8aquloBOtPRRNiywbedrGsZi7gg+GCZFkE1siDU6YbZ3LzvgU/e4J14MqK7Gah
         C9JZ6fmnZ8jbRvOpyFZLWzVSjVy0y36h6kdI5AgF+IhNTx+EJ6SYNUphaCY3OhqkRtLi
         gewQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=IRwZ7u3dYjdCFrPcqazENsa1lO8v+rGpqJG9/l92qYo=;
        fh=Na+8CwzhFkKQ+Pnjs/YKFaH61yHyZCdyAbi9q+fSZZA=;
        b=ykvERGEsHtMsk0SU+GT8rdHwbkuzbZezfbxcVzQJclkYSY1xL4Ku8jaDuc8zRvg3Xv
         sOK2PGp8FtDth7vqYdl2ASE6jQNRECQ/mltjrMQpKh/DDEld/2bdAP5eVxnmHsZFNIAv
         nBmPVCQkPVRESFc4wb8ZhjSk2/Iq/fhmXl7KwGeXX3PG8Gz5FmbI8X1k7axKlPzVk99S
         3rRSNNuDxj5eVFkXFL81Ms7mxZ8bC+dyFr30U/Gr0ve5xP46EqZ1LeCp27HxFJ+X0L0Y
         Rl6XjUCG+//6dkDo25CHgQia0K2RsEORZAg43abL3ZrWt/K4p0Crl/wsX1U6qsUwkAR+
         6eZg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@tum.de header.s=tu-postout21 header.b=RPVzcIDU;
       spf=pass (google.com: domain of paul.heidekrueger@tum.de designates 129.187.255.138 as permitted sender) smtp.mailfrom=paul.heidekrueger@tum.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=tum.de
X-Forwarded-Encrypted: i=0; AJvYcCU5aCUXST1mj/FHwmpO0lbuYYvwpke7bNpGrT2Ej8rCKIcyrP7OZh2NPpMUmCjDzTn9baBeq9hstKmuE4B2/A6Gi/Nh2C9D48vkMw==
Received: from postout2.mail.lrz.de (postout2.mail.lrz.de. [129.187.255.138])
        by gmr-mx.google.com with ESMTPS id be38-20020a056512252600b005100f83603fsi72001lfb.2.2024.02.02.02.03.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 02 Feb 2024 02:03:29 -0800 (PST)
Received-SPF: pass (google.com: domain of paul.heidekrueger@tum.de designates 129.187.255.138 as permitted sender) client-ip=129.187.255.138;
Received: from lxmhs52.srv.lrz.de (localhost [127.0.0.1])
	by postout2.mail.lrz.de (Postfix) with ESMTP id 4TRBDc2LD0zyVJ;
	Fri,  2 Feb 2024 11:03:28 +0100 (CET)
X-Virus-Scanned: by amavisd-new at lrz.de in lxmhs52.srv.lrz.de
X-Spam-Flag: NO
X-Spam-Score: -2.882
X-Spam-Level: 
X-Spam-Status: No, score=-2.882 tagged_above=-999 required=5
	tests=[ALL_TRUSTED=-1, BAYES_00=-1.9, DMARC_ADKIM_RELAXED=0.001,
	DMARC_ASPF_RELAXED=0.001, DMARC_POLICY_NONE=0.001,
	LRZ_CT_PLAIN_ISO8859_1=0.001, LRZ_DMARC_FAIL=0.001,
	LRZ_DMARC_FAIL_NONE=0.001, LRZ_DMARC_POLICY=0.001,
	LRZ_DMARC_TUM_FAIL=0.001, LRZ_DMARC_TUM_REJECT=3.5,
	LRZ_DMARC_TUM_REJECT_PO=-3.5, LRZ_ENVFROM_FROM_MATCH=0.001,
	LRZ_ENVFROM_TUM_S=0.001, LRZ_FROM_ENVFROM_ALIGNED_STRICT=0.001,
	LRZ_FROM_HAS_A=0.001, LRZ_FROM_HAS_AAAA=0.001,
	LRZ_FROM_HAS_MDOM=0.001, LRZ_FROM_HAS_MX=0.001,
	LRZ_FROM_HOSTED_DOMAIN=0.001, LRZ_FROM_NAME_IN_ADDR=0.001,
	LRZ_FROM_PHRASE=0.001, LRZ_FROM_TUM_S=0.001, LRZ_HAS_CT=0.001,
	LRZ_HAS_IN_REPLY_TO=0.001, LRZ_HAS_MIME_VERSION=0.001,
	LRZ_HAS_SPF=0.001, LRZ_MSGID_LONG_50=0.001, LRZ_MSGID_NO_FQDN=0.001,
	LRZ_NO_UA_HEADER=0.001, LRZ_SUBJ_FW_RE=0.001,
	LRZ_URL_PLAIN_SINGLE=0.001, T_SCC_BODY_TEXT_LINE=-0.01]
	autolearn=no autolearn_force=no
Received: from postout2.mail.lrz.de ([127.0.0.1])
	by lxmhs52.srv.lrz.de (lxmhs52.srv.lrz.de [127.0.0.1]) (amavisd-new, port 20024)
	with LMTP id 8CO4Xq_tL921; Fri,  2 Feb 2024 11:03:25 +0100 (CET)
Received: from pine.fritz.box (unknown [IPv6:2001:a61:2531:301:2520:4fa:71b2:b582])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by postout2.mail.lrz.de (Postfix) with ESMTPSA id 4TRBDX3p7czyV1;
	Fri,  2 Feb 2024 11:03:24 +0100 (CET)
Date: Fri, 2 Feb 2024 11:03:18 +0100
From: Paul =?utf-8?Q?Heidekr=C3=BCger?= <paul.heidekrueger@tum.de>
To: Marco Elver <elver@google.com>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, kasan-dev@googlegroups.com, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org
Subject: Re: Re: [PATCH RFC v2] kasan: add atomic tests
Message-ID: <nrknx5hi3nw7t4kitfweifcwyb436udyxldcclwwyf4cyyhvh5@upebu24mfibo>
References: <20240131210041.686657-1-paul.heidekrueger@tum.de>
 <CANpmjNPvQ16mrQOTzecN6ZpYe+N8dBw8V+Mci53CBgC2sx84Ew@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <CANpmjNPvQ16mrQOTzecN6ZpYe+N8dBw8V+Mci53CBgC2sx84Ew@mail.gmail.com>
X-Original-Sender: paul.heidekrueger@tum.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@tum.de header.s=tu-postout21 header.b=RPVzcIDU;       spf=pass
 (google.com: domain of paul.heidekrueger@tum.de designates 129.187.255.138 as
 permitted sender) smtp.mailfrom=paul.heidekrueger@tum.de;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=tum.de
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

On 01.02.2024 10:38, Marco Elver wrote:
> On Wed, 31 Jan 2024 at 22:01, Paul Heidekr=C3=BCger <paul.heidekrueger@tu=
m.de> wrote:
> >
> > Hi!
> >
> > This RFC patch adds tests that detect whether KASan is able to catch
> > unsafe atomic accesses.
> >
> > Since v1, which can be found on Bugzilla (see "Closes:" tag), I've made
> > the following suggested changes:
> >
> > * Adjust size of allocations to make kasan_atomics() work with all KASa=
n modes
> > * Remove comments and move tests closer to the bitops tests
> > * For functions taking two addresses as an input, test each address in =
a separate function call.
> > * Rename variables for clarity
> > * Add tests for READ_ONCE(), WRITE_ONCE(), smp_load_acquire() and smp_s=
tore_release()
> >
> > I'm still uncelar on which kinds of atomic accesses we should be testin=
g
> > though. The patch below only covers a subset, and I don't know if it
> > would be feasible to just manually add all atomics of interest. Which
> > ones would those be exactly?
>=20
> The atomics wrappers are generated by a script. An exhaustive test
> case would, if generated by hand, be difficult to keep in sync if some
> variants are removed or renamed (although that's probably a relatively
> rare occurrence).
>=20
> I would probably just cover some of the most common ones that all
> architectures (that support KASAN) provide. I think you are already
> covering some of the most important ones, and I'd just say it's good
> enough for the test.
>=20
> > As Andrey pointed out on Bugzilla, if we
> > were to include all of the atomic64_* ones, that would make a lot of
> > function calls.
>=20
> Just include a few atomic64_ cases, similar to the ones you already
> include for atomic_. Although beware that the atomic64_t helpers are
> likely not available on 32-bit architectures, so you need an #ifdef
> CONFIG_64BIT.
>=20
> Alternatively, there is also atomic_long_t, which (on 64-bit
> architectures) just wraps atomic64_t helpers, and on 32-bit the
> atomic_t ones. I'd probably opt for the atomic_long_t variants, just
> to keep it simpler and get some additional coverage on 32-bit
> architectures.

If I were to add some atomic_long_* cases, e.g. atomic_long_read() or=20
atomic_long_write(), in addition to the test cases I already have, wouldn't=
 that=20
mean that on 32-bit architectures we would have the same test case twice be=
cause=20
atomic_read() and long_atomic_read() both boil down to raw_atomic_read() an=
d=20
raw_atomic_write() respectively? Or did I misunderstand and I should only b=
e=20
covering long_atomic_* functions whose atomic_* counterpart doesn't exist i=
n the=20
test cases already?

> > Also, the availability of atomics varies between architectures; I did m=
y
> > testing on arm64. Is something like gen-atomic-instrumented.sh required=
?
>=20
> I would not touch gen-atomic-instrumented.sh for the test.
>=20
> > Many thanks,
> > Paul
> >
> > CC: Marco Elver <elver@google.com>
> > CC: Andrey Konovalov <andreyknvl@gmail.com>
> > Closes: https://bugzilla.kernel.org/show_bug.cgi?id=3D214055
> > Signed-off-by: Paul Heidekr=C3=BCger <paul.heidekrueger@tum.de>
> > ---
> >  mm/kasan/kasan_test.c | 50 +++++++++++++++++++++++++++++++++++++++++++
> >  1 file changed, 50 insertions(+)
> >
> > diff --git a/mm/kasan/kasan_test.c b/mm/kasan/kasan_test.c
> > index 8281eb42464b..1ab4444fe4a0 100644
> > --- a/mm/kasan/kasan_test.c
> > +++ b/mm/kasan/kasan_test.c
> > @@ -1150,6 +1150,55 @@ static void kasan_bitops_tags(struct kunit *test=
)
> >         kfree(bits);
> >  }
> >
> > +static void kasan_atomics_helper(struct kunit *test, void *unsafe, voi=
d *safe)
> > +{
> > +       int *i_safe =3D (int *)safe;
> > +       int *i_unsafe =3D (int *)unsafe;
> > +
> > +       KUNIT_EXPECT_KASAN_FAIL(test, READ_ONCE(*i_unsafe));
> > +       KUNIT_EXPECT_KASAN_FAIL(test, WRITE_ONCE(*i_unsafe, 42));
> > +       KUNIT_EXPECT_KASAN_FAIL(test, smp_load_acquire(i_unsafe));
> > +       KUNIT_EXPECT_KASAN_FAIL(test, smp_store_release(i_unsafe, 42));
> > +       KUNIT_EXPECT_KASAN_FAIL(test, atomic_read(unsafe));
> > +       KUNIT_EXPECT_KASAN_FAIL(test, atomic_set(unsafe, 42));
> > +       KUNIT_EXPECT_KASAN_FAIL(test, atomic_add(42, unsafe));
> > +       KUNIT_EXPECT_KASAN_FAIL(test, atomic_sub(42, unsafe));
> > +       KUNIT_EXPECT_KASAN_FAIL(test, atomic_inc(unsafe));
> > +       KUNIT_EXPECT_KASAN_FAIL(test, atomic_dec(unsafe));
> > +       KUNIT_EXPECT_KASAN_FAIL(test, atomic_and(42, unsafe));
> > +       KUNIT_EXPECT_KASAN_FAIL(test, atomic_andnot(42, unsafe));
> > +       KUNIT_EXPECT_KASAN_FAIL(test, atomic_or(42, unsafe));
> > +       KUNIT_EXPECT_KASAN_FAIL(test, atomic_xor(42, unsafe));
> > +       KUNIT_EXPECT_KASAN_FAIL(test, atomic_xchg(unsafe, 42));
> > +       KUNIT_EXPECT_KASAN_FAIL(test, atomic_cmpxchg(unsafe, 21, 42));
> > +       KUNIT_EXPECT_KASAN_FAIL(test, atomic_try_cmpxchg(unsafe, safe, =
42));
> > +       KUNIT_EXPECT_KASAN_FAIL(test, atomic_try_cmpxchg(safe, unsafe, =
42));
> > +       KUNIT_EXPECT_KASAN_FAIL(test, atomic_sub_and_test(42, unsafe));
> > +       KUNIT_EXPECT_KASAN_FAIL(test, atomic_dec_and_test(unsafe));
> > +       KUNIT_EXPECT_KASAN_FAIL(test, atomic_inc_and_test(unsafe));
> > +       KUNIT_EXPECT_KASAN_FAIL(test, atomic_add_negative(42, unsafe));
> > +       KUNIT_EXPECT_KASAN_FAIL(test, atomic_add_unless(unsafe, 21, 42)=
);
> > +       KUNIT_EXPECT_KASAN_FAIL(test, atomic_inc_not_zero(unsafe));
> > +       KUNIT_EXPECT_KASAN_FAIL(test, atomic_inc_unless_negative(unsafe=
));
> > +       KUNIT_EXPECT_KASAN_FAIL(test, atomic_dec_unless_positive(unsafe=
));
> > +       KUNIT_EXPECT_KASAN_FAIL(test, atomic_dec_if_positive(unsafe));
> > +}
> > +
> > +static void kasan_atomics(struct kunit *test)
> > +{
> > +       int *a1, *a2;
>=20
> If you're casting it to void* below and never using as an int* in this
> function, just make these void* (the sizeof can just be sizeof(int)).
>=20
> > +       a1 =3D kzalloc(48, GFP_KERNEL);
> > +       KUNIT_ASSERT_NOT_ERR_OR_NULL(test, a1);
> > +       a2 =3D kzalloc(sizeof(*a1), GFP_KERNEL);
> > +       KUNIT_ASSERT_NOT_ERR_OR_NULL(test, a1);
> > +
> > +       kasan_atomics_helper(test, (void *)a1 + 48, (void *)a2);
>=20
> We try to ensure (where possible) that the KASAN tests are not
> destructive to the rest of the kernel. I think the size of "48" was
> chosen to fall into the 64-byte size class, similar to the bitops. I
> would just copy that comment, so nobody attempts to change it in
> future. :-)

And yes to all the rest - thanks for the feedback!

> > +       kfree(a1);
> > +       kfree(a2);
>=20
> Thanks,
> -- Marco

Many thanks,
Paul

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/nrknx5hi3nw7t4kitfweifcwyb436udyxldcclwwyf4cyyhvh5%40upebu24mfibo=
.
