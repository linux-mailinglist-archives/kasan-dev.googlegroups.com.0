Return-Path: <kasan-dev+bncBAABBQNRU6XAMGQELZZLPTA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x139.google.com (mail-lf1-x139.google.com [IPv6:2a00:1450:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id 62C7B850EF4
	for <lists+kasan-dev@lfdr.de>; Mon, 12 Feb 2024 09:37:22 +0100 (CET)
Received: by mail-lf1-x139.google.com with SMTP id 2adb3069b0e04-51169a55bddsf3023692e87.0
        for <lists+kasan-dev@lfdr.de>; Mon, 12 Feb 2024 00:37:22 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1707727041; cv=pass;
        d=google.com; s=arc-20160816;
        b=N1ZHjmZH5iskT/L2j2M4XMTdITLPab9P3vsYhGhuL950/ihtR9iJGeEqbiWxc7JQi+
         x4AMoS+n5pEK2LYT9PzbKFM0SBi68TeDmkkEvlMPOEffBbxCVQ2oXqHeFMRDkmHFw+dL
         lZjuBA5cRHt//BbIxpKPykHab7rVGoWMCXeO8w7Ax/rOd2ZS6YqhQwuFUb9wxc2sTAS/
         X94DvuN/MrrblfX4I1Owdd6a89QmJtQVbXc4mdpHTkvbNQSYkyPGOspcoivt1Gw+TaM2
         1tCFaEHDMhBcx8QcEew7O5Di5kf6PSrFrWZkBNqnVNiPUItBm/y08rOWvqeZAV3bioJ3
         s5HQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=1KYZi/Mld3MkzFyAOTW8GhWdQmUaTlohljRamV4qDDY=;
        fh=WXK5DTrQl56ydsfHm8oDz0e6fvaMDtT3DWWdoLNWImc=;
        b=qigiBxA3u0sjZ9ufSGksfbQ6iQ4icQoOQ5w4kFvn0rBG4K/viQdwQ5DTbFK4kZhffI
         j8jHZsTwyxWa1OcLwSwWbOTyh7YlnK0egkpcZPz8JWozSKsSEl+jZUCn1VkNPeCwtWlz
         1jdlrrupJJFhSr6h2/KidW1RUOvJJaoUxDsOdgeQepNj8YJk/kRRV9SmiiBordzYgiQl
         +pCVXH3Y9E/PfwxVI7nlCxMAvRNMW5ibrk8hiM1CRm34FxXiL8AUzVaAnH3UylRLRyUK
         xf1uEPkBAJmTx5xG4z1tpZk9NX1ypvAbf0WVdllj3j8859QC3let5j48xLlAXjYNIH+K
         bAUA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@tum.de header.s=tu-postout21 header.b="YsH696/s";
       spf=pass (google.com: domain of paul.heidekrueger@tum.de designates 129.187.255.137 as permitted sender) smtp.mailfrom=paul.heidekrueger@tum.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=tum.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1707727041; x=1708331841; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-transfer-encoding
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=1KYZi/Mld3MkzFyAOTW8GhWdQmUaTlohljRamV4qDDY=;
        b=Uj+OnKdkUcrcD5354CbrJ7HYtNla4if3L+zZQBIgs94XZbb61hmQ3OMosakHp2umwi
         1S/UhbJPUo3TTm9dYLMfNwPkswgx5lw1KKd+qWlJkxv9c+5cMEWSUZu2jc6SHnlX42X3
         ZACiBKGEVStFGF1krbPRkHvYH7v55YzL7hk8JHQ/BxlYSIccR8K2UbQijlv8ZrfPwc29
         B+Z4tBr6xMCtCa2t/Evgo9frjUujSQzgwWWBeEBIG8OCFOoLF5WyYN77HcLYkbl5+Uiw
         6dWXFXBVHt/vH7keyio1UwZL5hWu66K32L0xRu/efNTRJ/OaPAzNkR5IyosHXMOTKGoZ
         3kCQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1707727041; x=1708331841;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=1KYZi/Mld3MkzFyAOTW8GhWdQmUaTlohljRamV4qDDY=;
        b=UM1SIWWo7anYBVy9OTOv+aKLaaWcSVmAH25enJYRf00eRcbssTNSuQm0v8FgJWA+90
         ww3noT4VHQQ/o0lfKRc97crc4+ON4eV4cP8kV90rXZnd60nKzSXXkeu+Sfl9kxz8QUMB
         pq8rQf7MP4FWWod5Q/obJs+X3unBwMu88Wb6+6DF03G74V1qlUosMraKXNAy150N8gqp
         OATMrLAjq9UX7LS4aY4xLeFOEuxDKW7gDWoZjruCtuqAWk2UsiwzNv30uUFR+SBQJNVk
         qb7BJPlAeMtlF5Z0ymDv5wfSrfatJQcwR+r4ra3WL5SOZ5kyx17clF+577SmUF5e38DD
         WZdA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCW61kFMQOoi0mU49gV+kGbHVu72fkJfoPemObxTIkEgNNCjgUVka1CVS/T++yTvoAVBOP1ROFZKp/YdiiVhCSEs1XirwKKZ/A==
X-Gm-Message-State: AOJu0Yy7b9PqDZYWZxSyBeFari6GEp0BW8g4Ki7hGVZBDYlAjZJlxPHP
	FmKcGJtP0vUDyf7ULs/HA2LZ7zwl0LxYfqbQVB00PS3B4PcUvJWW
X-Google-Smtp-Source: AGHT+IE+WCUY8PbGumr/sE/DitbJJFqpd5MblFCzGOfPdDUc7rl47Rl7YooFFRfc2Nl1DQjHH4VvlQ==
X-Received: by 2002:a19:ee0e:0:b0:511:6534:61d4 with SMTP id g14-20020a19ee0e000000b00511653461d4mr3510371lfb.35.1707727041207;
        Mon, 12 Feb 2024 00:37:21 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:238d:b0:511:7247:5108 with SMTP id
 c13-20020a056512238d00b0051172475108ls23876lfv.1.-pod-prod-08-eu; Mon, 12 Feb
 2024 00:37:19 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCW1mnggaY5x8g/Z/vj/HRTX2EB6a+Z7Q5Q2/+4tW8JY30a/hfBE/RUxWCPWCcO0GEHXCKEATZFTwAVMiatorFQgCIN3f+2VkY0MRQ==
X-Received: by 2002:a05:6512:39c9:b0:511:83b3:a9a9 with SMTP id k9-20020a05651239c900b0051183b3a9a9mr3913837lfu.14.1707727039534;
        Mon, 12 Feb 2024 00:37:19 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1707727039; cv=none;
        d=google.com; s=arc-20160816;
        b=csDhWa4EmayfrHqgOiy4McLfFnSKsUDmuIZLT49//k2TWze4KhI3nRLoLButriFcYQ
         U2TDnU/w4dKQ6BgwZM9bNQXySqzuSr6IGnxrQbv7MnpkDZ6HvLb7CagY0NG96OVRKSVf
         yh7C/z+l5Zm/6GjXNyFXnAdbP+uLDF33CEzpduVkKMBnOQFfeZR9THma0jobgvVBN8bP
         dMz03f6MtGcZ6a5tKzAsyfMRV5qRwBAny2Ui83ijmYvO1gOreAEFMImcuv6D4JXX76k1
         9rA5tfcxXHgKh6GCUZzTi+dS2+g2ZQp7YwxuxU8izcV4yV4odmBdFBhCi7cVnf9EWQO3
         9MfQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=VZ6d/zgmfTClc6OwNU6RH/iu8z70YYeUrmCoby2+s+Q=;
        fh=vRW8VMN1VIk9cNXbQ5StyPzz2iYllV2kU+19KRO5QN4=;
        b=bfQyOiUyfTheGcRSs7IWx/SgSEPLmQDy19uExKwByQZ+iZIt254Wgdjiua8UVSg5AN
         Wwd4XP4Q6TS3NYurmIsezva3Q01cTKsdM/LmOudG5v2ym4GVtHctcNFNyam152YR2si+
         DqQqpB/XKSJcJZPaLNBncZXCoN7yR2pf4uHqQJW2Br+FnV5uKMSCbKMHEuGva5vBg0ac
         hPhxxE3T8cAJdYk3aZWv4sb+65e9FFtPkglgskz73P0techBxOhcZ1Y62+36ToR/puUS
         tQqXJcHDB3KTzF4eKDvLEa2DogNiMIGXyLV76GCB5VZ+nM1z+GpDYg9OrtbKQmKoBtzV
         x9rg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@tum.de header.s=tu-postout21 header.b="YsH696/s";
       spf=pass (google.com: domain of paul.heidekrueger@tum.de designates 129.187.255.137 as permitted sender) smtp.mailfrom=paul.heidekrueger@tum.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=tum.de
X-Forwarded-Encrypted: i=1; AJvYcCX21gkHUwxIVSvxsHbWs0sT8UCA7RFITzY3T3JRcgUA8fHKhao02NrMA+p7Ii3JP5Iuq5yIFS5Jp4dUbxYdbZGofvSgkpLGEYJ6uA==
Received: from postout1.mail.lrz.de (postout1.mail.lrz.de. [129.187.255.137])
        by gmr-mx.google.com with ESMTPS id k10-20020ac24f0a000000b0051186f110b6si313036lfr.8.2024.02.12.00.37.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 12 Feb 2024 00:37:19 -0800 (PST)
Received-SPF: pass (google.com: domain of paul.heidekrueger@tum.de designates 129.187.255.137 as permitted sender) client-ip=129.187.255.137;
Received: from lxmhs51.srv.lrz.de (localhost [127.0.0.1])
	by postout1.mail.lrz.de (Postfix) with ESMTP id 4TYHrZ2sWtzyVF;
	Mon, 12 Feb 2024 09:37:18 +0100 (CET)
X-Virus-Scanned: by amavisd-new at lrz.de in lxmhs51.srv.lrz.de
X-Spam-Flag: NO
X-Spam-Score: -2.879
X-Spam-Level: 
X-Spam-Status: No, score=-2.879 tagged_above=-999 required=5
	tests=[ALL_TRUSTED=-1, BAYES_00=-1.9, DMARC_ADKIM_RELAXED=0.001,
	DMARC_ASPF_RELAXED=0.001, DMARC_POLICY_NONE=0.001,
	LRZ_CT_PLAIN_UTF8=0.001, LRZ_DMARC_FAIL=0.001,
	LRZ_DMARC_FAIL_NONE=0.001, LRZ_DMARC_POLICY=0.001,
	LRZ_DMARC_TUM_FAIL=0.001, LRZ_DMARC_TUM_REJECT=3.5,
	LRZ_DMARC_TUM_REJECT_PO=-3.5, LRZ_ENVFROM_FROM_MATCH=0.001,
	LRZ_ENVFROM_TUM_S=0.001, LRZ_FROM_ENVFROM_ALIGNED_STRICT=0.001,
	LRZ_FROM_HAS_A=0.001, LRZ_FROM_HAS_AAAA=0.001,
	LRZ_FROM_HAS_MDOM=0.001, LRZ_FROM_HAS_MX=0.001,
	LRZ_FROM_HOSTED_DOMAIN=0.001, LRZ_FROM_NAME_IN_ADDR=0.001,
	LRZ_FROM_PHRASE=0.001, LRZ_FROM_TUM_S=0.001, LRZ_HAS_CT=0.001,
	LRZ_HAS_IN_REPLY_TO=0.001, LRZ_HAS_MIME_VERSION=0.001,
	LRZ_HAS_SPF=0.001, LRZ_HAS_URL_HTTP=0.001, LRZ_MSGID_LONG_50=0.001,
	LRZ_MSGID_NO_FQDN=0.001, LRZ_NO_UA_HEADER=0.001, LRZ_SUBJ_FW_RE=0.001,
	LRZ_URL_HTTP_SINGLE=0.001, LRZ_URL_PLAIN_SINGLE=0.001,
	LRZ_URL_SINGLE_UTF8=0.001, T_SCC_BODY_TEXT_LINE=-0.01]
	autolearn=no autolearn_force=no
Received: from postout1.mail.lrz.de ([127.0.0.1])
	by lxmhs51.srv.lrz.de (lxmhs51.srv.lrz.de [127.0.0.1]) (amavisd-new, port 20024)
	with LMTP id I03PoRHcZDqc; Mon, 12 Feb 2024 09:37:17 +0100 (CET)
Received: from pine.fritz.box (unknown [IPv6:2001:a61:25f3:6e01:57f:7a4d:e41f:6949])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by postout1.mail.lrz.de (Postfix) with ESMTPSA id 4TYHrX4fqszyTl;
	Mon, 12 Feb 2024 09:37:16 +0100 (CET)
Date: Mon, 12 Feb 2024 09:37:10 +0100
From: Paul =?utf-8?Q?Heidekr=C3=BCger?= <paul.heidekrueger@tum.de>
To: Andrey Konovalov <andreyknvl@gmail.com>
Cc: akpm@linux-foundation.org, dvyukov@google.com, elver@google.com, 
	glider@google.com, kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, 
	linux-mm@kvack.org, ryabinin.a.a@gmail.com, vincenzo.frascino@arm.com, 
	Mark Rutland <mark.rutland@arm.com>
Subject: Re: [PATCH v2] kasan: add atomic tests
Message-ID: <mofzkwb2a2wr5z7kg2fe3lowzdca7kqvol5hevhj5dcs5pxvu2@7d4gydk3enon>
References: <20240202113259.3045705-1-paul.heidekrueger@tum.de>
 <20240211091720.145235-1-paul.heidekrueger@tum.de>
 <CA+fCnZcfUyqzok0yV2uvsDdhiT95Y-KYnozY77y04YDBwKhj-Q@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <CA+fCnZcfUyqzok0yV2uvsDdhiT95Y-KYnozY77y04YDBwKhj-Q@mail.gmail.com>
X-Original-Sender: paul.heidekrueger@tum.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@tum.de header.s=tu-postout21 header.b="YsH696/s";       spf=pass
 (google.com: domain of paul.heidekrueger@tum.de designates 129.187.255.137 as
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

On 12.02.2024 00:16, Andrey Konovalov wrote:
> On Sun, Feb 11, 2024 at 10:17=E2=80=AFAM Paul Heidekr=C3=BCger
> <paul.heidekrueger@tum.de> wrote:
> >
> > Test that KASan can detect some unsafe atomic accesses.
> >
> > As discussed in the linked thread below, these tests attempt to cover
> > the most common uses of atomics and, therefore, aren't exhaustive.
> >
> > CC: Marco Elver <elver@google.com>
> > CC: Andrey Konovalov <andreyknvl@gmail.com>
> > Link: https://lore.kernel.org/all/20240131210041.686657-1-paul.heidekru=
eger@tum.de/T/#u
> > Closes: https://bugzilla.kernel.org/show_bug.cgi?id=3D214055
> > Reviewed-by: Marco Elver <elver@google.com>
> > Tested-by: Marco Elver <elver@google.com>
> > Acked-by: Mark Rutland <mark.rutland@arm.com>
> > Signed-off-by: Paul Heidekr=C3=BCger <paul.heidekrueger@tum.de>
> > ---
> > Changes PATCH v1 -> PATCH v2:
> > * Make explicit cast implicit as per Mark's feedback
> > * Increase the size of the "a2" allocation as per Andrey's feedback
> > * Add tags
> >
> > Changes PATCH RFC v2 -> PATCH v1:
> > * Remove casts to void*
> > * Remove i_safe variable
> > * Add atomic_long_* test cases
> > * Carry over comment from kasan_bitops_tags()
> >
> > Changes PATCH RFC v1 -> PATCH RFC v2:
> > * Adjust size of allocations to make kasan_atomics() work with all KASa=
n modes
> > * Remove comments and move tests closer to the bitops tests
> > * For functions taking two addresses as an input, test each address in =
a separate function call.
> > * Rename variables for clarity
> > * Add tests for READ_ONCE(), WRITE_ONCE(), smp_load_acquire() and smp_s=
tore_release()
> >
> >  mm/kasan/kasan_test.c | 79 +++++++++++++++++++++++++++++++++++++++++++
> >  1 file changed, 79 insertions(+)
> >
> > diff --git a/mm/kasan/kasan_test.c b/mm/kasan/kasan_test.c
> > index 8281eb42464b..7bf09699b145 100644
> > --- a/mm/kasan/kasan_test.c
> > +++ b/mm/kasan/kasan_test.c
> > @@ -1150,6 +1150,84 @@ static void kasan_bitops_tags(struct kunit *test=
)
> >         kfree(bits);
> >  }
> >
> > +static void kasan_atomics_helper(struct kunit *test, void *unsafe, voi=
d *safe)
> > +{
> > +       int *i_unsafe =3D unsafe;
> > +
> > +       KUNIT_EXPECT_KASAN_FAIL(test, READ_ONCE(*i_unsafe));
> > +       KUNIT_EXPECT_KASAN_FAIL(test, WRITE_ONCE(*i_unsafe, 42));
> > +       KUNIT_EXPECT_KASAN_FAIL(test, smp_load_acquire(i_unsafe));
> > +       KUNIT_EXPECT_KASAN_FAIL(test, smp_store_release(i_unsafe, 42));
> > +
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
> > +
> > +       KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_read(unsafe));
> > +       KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_set(unsafe, 42));
> > +       KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_add(42, unsafe));
> > +       KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_sub(42, unsafe));
> > +       KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_inc(unsafe));
> > +       KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_dec(unsafe));
> > +       KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_and(42, unsafe));
> > +       KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_andnot(42, unsafe));
> > +       KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_or(42, unsafe));
> > +       KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_xor(42, unsafe));
> > +       KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_xchg(unsafe, 42));
> > +       KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_cmpxchg(unsafe, 21, 4=
2));
> > +       KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_try_cmpxchg(unsafe, s=
afe, 42));
> > +       KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_try_cmpxchg(safe, uns=
afe, 42));
> > +       KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_sub_and_test(42, unsa=
fe));
> > +       KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_dec_and_test(unsafe))=
;
> > +       KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_inc_and_test(unsafe))=
;
> > +       KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_add_negative(42, unsa=
fe));
> > +       KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_add_unless(unsafe, 21=
, 42));
> > +       KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_inc_not_zero(unsafe))=
;
> > +       KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_inc_unless_negative(u=
nsafe));
> > +       KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_dec_unless_positive(u=
nsafe));
> > +       KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_dec_if_positive(unsaf=
e));
> > +}
> > +
> > +static void kasan_atomics(struct kunit *test)
> > +{
> > +       void *a1, *a2;
> > +
> > +       /*
> > +        * Just as with kasan_bitops_tags(), we allocate 48 bytes of me=
mory such
> > +        * that the following 16 bytes will make up the redzone.
> > +        */
> > +       a1 =3D kzalloc(48, GFP_KERNEL);
> > +       KUNIT_ASSERT_NOT_ERR_OR_NULL(test, a1);
> > +       a2 =3D kzalloc(sizeof(atomic_long_t), GFP_KERNEL);
> > +       KUNIT_ASSERT_NOT_ERR_OR_NULL(test, a1);
>=20
> This should check for a2, not a1. Sorry for not spotting this before.

No need to apologise. I'm the one who made the mistake, so I'm the one who=
=20
should've spotted it in the first place :-)

> > +
> > +       /* Use atomics to access the redzone. */
> > +       kasan_atomics_helper(test, a1 + 48, a2);
> > +
> > +       kfree(a1);
> > +       kfree(a2);
> > +}
> > +
> >  static void kmalloc_double_kzfree(struct kunit *test)
> >  {
> >         char *ptr;
> > @@ -1553,6 +1631,7 @@ static struct kunit_case kasan_kunit_test_cases[]=
 =3D {
> >         KUNIT_CASE(kasan_strings),
> >         KUNIT_CASE(kasan_bitops_generic),
> >         KUNIT_CASE(kasan_bitops_tags),
> > +       KUNIT_CASE(kasan_atomics),
> >         KUNIT_CASE(kmalloc_double_kzfree),
> >         KUNIT_CASE(rcu_uaf),
> >         KUNIT_CASE(workqueue_uaf),
> > --
> > 2.40.1
> >
>=20
> With the mentioned change:
>=20
> Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>
>=20
> Thank you!

Just sent v3.

Many thanks,
Paul

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/mofzkwb2a2wr5z7kg2fe3lowzdca7kqvol5hevhj5dcs5pxvu2%407d4gydk3enon=
.
