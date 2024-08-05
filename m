Return-Path: <kasan-dev+bncBCQ2XPNX7EOBB2PFYK2QMGQEWMGAT7Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23a.google.com (mail-lj1-x23a.google.com [IPv6:2a00:1450:4864:20::23a])
	by mail.lfdr.de (Postfix) with ESMTPS id 495D2947A45
	for <lists+kasan-dev@lfdr.de>; Mon,  5 Aug 2024 13:09:31 +0200 (CEST)
Received: by mail-lj1-x23a.google.com with SMTP id 38308e7fff4ca-2ef23b417bcsf94130891fa.0
        for <lists+kasan-dev@lfdr.de>; Mon, 05 Aug 2024 04:09:31 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1722856170; cv=pass;
        d=google.com; s=arc-20160816;
        b=PhUo15EFAqYQsRNEC3FBJdD5EbHZFm5H/khAKZF7nr1UWKoZ+fmR5vBIbvWMSi5tyg
         jpjxf6zZ/Wk4LDjI8A6MskwmqgRs0I57KZ2S2/T7M3irF9ila6lMt1TuSHwHaz1W4Jqo
         /Q7qc+n27V7yHPRmzgFkkzc3K/y1IjVMoVSE3JMZJmpgsFNhhiRuD79L2crOj8f9d22N
         iMbK/xv6vk/ZZ59N0iBgSiLeLIrUNoqTLTk8QZim8FmYHlWfMPqVGElV/JVhS81i4AZ8
         1CY5kKEixHNOmJYTYFM6NoRUBZNwqfvhfky7rXPtQIaIZTK1G57FpHAxBlDvcRwPHprU
         BhEQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=w+bhIjgM26Gx0qKqAwVFD7v4K3Ho9SQO8lbzBHiO7r8=;
        fh=PaRr1gr+dGk7eCKi3+lLg2wptaYOrT6zhr47tQv3xvM=;
        b=o0nGoiVQSqGf41YWOb3Vbe8yyrIvFcrHyWskGs9vpcM9ufdEh31jIWBm8yKBf4Ha8B
         QipCkrEI+GZltiUWMEan7WdgaS0j7xBedwRmXojrhuMDYuJOtYoYF3tH7qfxbiTCHr32
         lXHM6qsVp+ACxiR6PWiSjcg9O6PgcKYT0ZwYpD2COqZcILb0fU4TuDu62RHmdSG7yxwB
         YJqV4YmNqDg0VMMl3RTflDEGASdwimQ4T5V/vt2Toa+jdVQTVdwMdKhVKSehIawvEAWf
         u70p8rqoGJ0uX95otAbEjmPZPYPTlixDqpRFMihmXx7bslTpvWs/ESd5CNuJBCiJN5qF
         HJXw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=FjD3zLoo;
       spf=pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::535 as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1722856170; x=1723460970; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=w+bhIjgM26Gx0qKqAwVFD7v4K3Ho9SQO8lbzBHiO7r8=;
        b=bPWg9B0sc2ExeBKQXuPIR1KQoJdoekWCL7+hB78buqhjQSPFdUrMUY5WDxTLmdbhxH
         lt3ztEY1BYn4j6GndxwdEuUnsGVqBYwp8Pz2u4RmrMQ1KuiPBxnnHgRgSAgc/CUxxRGi
         55em9GuoDWwpFvNgZneH+it+sEtRyySeJNyUUVKMjxhGFLFW0IpnHoo78pPAkDU/kQw8
         /aJZzXd21ZpgErZYSkaANtQaTPoXpAfKjpChR0RcPkQEGhJYnxwE4R/LGH7JhF7VS0FS
         FFtVXJH01+6cG7gMw01azoHmSHP6+Gkz+Nw606ieM1IXB4sFsCbh6cr9Qrvs1vP5ajhq
         4/WQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1722856170; x=1723460970;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=w+bhIjgM26Gx0qKqAwVFD7v4K3Ho9SQO8lbzBHiO7r8=;
        b=sz9/dieKPS8FbabvKov0YgESyEGQhulxKAfbBiyyLG+cqq7Lgq8UT9grBV6MA35C2m
         UakJD1TOZUnODTOZfHszAMV300WzdIsb1o3bM7G13akrN5GKLtMrz28IPNuZc0gBhRZ8
         EmJaZ+WvN1u0xxLqUsy+iY/dPBIhJoFeKoZdeq2VUfjhP3yJV3/qAg2Q3rU1MoMfgk8C
         eqxNQeFcuOeOoxdvKj7SVejYejWupnDbnj69r+SmlNcq2nvvzVmd5EmKige41gSEm4Td
         Fu974HyD8IwCvTTW7RHWkLlVIXFZgRFPYO2ZYUOAXMxA9wEMfrwJWAGuOPoAPU39lijE
         c3ew==
X-Forwarded-Encrypted: i=2; AJvYcCW/mOHGu5knJaj09i03Xpnd8hz0GiP/0ccyr60RzyVCtrK0j8PArfICQb+aO8QfFaSeI4vBrTOkQJCbQblodbO5c303GNhcaA==
X-Gm-Message-State: AOJu0Yzz9vl8yCrI6WPl8nAsrsUH3/ceNKtdOpP5MCt3WI8H9tRkFDou
	tiNlhJEWLwRHx+VlpG/6rNX8+XmELZkHozMOO1PIg6TOlJqTbKBR
X-Google-Smtp-Source: AGHT+IHWUC1HIHMbezdIUikpfk6a3ZrRFAgrs/j5BVHxKBG0TClCgWMsXN3ua9OheM8q0S2lv41I8Q==
X-Received: by 2002:a2e:868e:0:b0:2ef:2b08:1747 with SMTP id 38308e7fff4ca-2f15aa91609mr77644611fa.13.1722856169533;
        Mon, 05 Aug 2024 04:09:29 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:3b08:b0:426:68ce:c965 with SMTP id
 5b1f17b1804b1-428ede1ce1fls7312775e9.1.-pod-prod-01-eu; Mon, 05 Aug 2024
 04:09:28 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCW0F0SsmWt7H6reL5/QkfTwls28leYhLgcRE3qpvOC15nqKrrYVL8XYXWRd8zQNJkGQUA15gV9VZqUw+RPwubproD6D0YU1GopLcA==
X-Received: by 2002:a05:600c:3b17:b0:426:58cb:8ca3 with SMTP id 5b1f17b1804b1-428e6b07c64mr71835965e9.21.1722856167659;
        Mon, 05 Aug 2024 04:09:27 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1722856167; cv=none;
        d=google.com; s=arc-20160816;
        b=WLWAmgKTYm0uqusa8D63CrSqr5a3/7xhmTpQg5b/I59yAdCxLcFX3tFRONPvC+j+bK
         rrC9iMktDGrWaWH+XxD/3zV+zcTkwBJutVQYivCS8mhMXGkwn+01MrzNyDzlRr9x9BSM
         fNkyntOBJJHDN2OYa4iaNc6smYl/d8FIdZ2VI7q300uWpQRYCXIAVNtgRp5Nb+fsn/aS
         Dv2mqJGgMejnciW3Ki8edCsRPxdWLGwvy0ivS+9DoN0K6Vx8J9sDJ3jdaexnHQa7CgU9
         gCYnKRLW5lDrpyOD9z/zEaXWhnMiZ7GqcSitfz0zehDJxfwEQxYOyp1H5Fwgo0wltikc
         qwSQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=l4Lfr7cWJZWVAHEZdC4tIJBE0idMw63JeT0pm5BZ7xI=;
        fh=0vTCJY98PnapMlzqKu5Idm4TPvST8oOPHfbJNr3bATM=;
        b=Ypl27YNE5I6O7T0BY4OLAUZqQP0yE78bvT5903wKbjCua8cMJjDtzhl8sCUR2qazK5
         F/kHDSTqdBAaqJaif9bXwYKUPabhS/A60hNmk8+Dt+FT6SQROkRawhvf3DtC+4cwSMsU
         DPQ+Aj4w126m3BhvMn/kF9fG3E6pwH4DY54m1hD3y5Ucn7ynKwt8WJyFJbzsAvA8mW7D
         mWyeLa0QXKLKBjXWA4sZlDRxKPOo1PVmgfIAGVQ6UgCRtbk0eERA/FsCB6MWg2bDYzZl
         9ngf8nhL7VSP/0/f51zEOXjszVUKZlARBCLuoCuC8toR2EFlIzwiIfkSv1VmD32mj1EH
         vEhQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=FjD3zLoo;
       spf=pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::535 as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-ed1-x535.google.com (mail-ed1-x535.google.com. [2a00:1450:4864:20::535])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-428f2114617si2865395e9.0.2024.08.05.04.09.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 05 Aug 2024 04:09:27 -0700 (PDT)
Received-SPF: pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::535 as permitted sender) client-ip=2a00:1450:4864:20::535;
Received: by mail-ed1-x535.google.com with SMTP id 4fb4d7f45d1cf-5b9fe5ea355so10731a12.0
        for <kasan-dev@googlegroups.com>; Mon, 05 Aug 2024 04:09:27 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXSK0BKZmQeLX/LICEZXi8XLgk9vkf5B6h3QiljcLBe+sT8gwr/MbGenRxEfPsIebFZBmeKGjaQlX9w23lUToOKYi6peFGlahusZw==
X-Received: by 2002:a05:6402:35d4:b0:5b4:df4a:48bb with SMTP id
 4fb4d7f45d1cf-5b9c1e5e74emr228803a12.0.1722856166424; Mon, 05 Aug 2024
 04:09:26 -0700 (PDT)
MIME-Version: 1.0
References: <20240802-kasan-tsbrcu-v6-0-60d86ea78416@google.com>
 <20240802-kasan-tsbrcu-v6-2-60d86ea78416@google.com> <CANpmjNNadRtLijEZLgE3HpyCGW=gkhunsFZ9FmwFZrpyWGUrnA@mail.gmail.com>
In-Reply-To: <CANpmjNNadRtLijEZLgE3HpyCGW=gkhunsFZ9FmwFZrpyWGUrnA@mail.gmail.com>
From: "'Jann Horn' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 5 Aug 2024 13:08:50 +0200
Message-ID: <CAG48ez2Jsc2V1NfN1YOnx0e3-3BaVSdac7p_y9gnYL=9VW6cOw@mail.gmail.com>
Subject: Re: [PATCH v6 2/2] slub: Introduce CONFIG_SLUB_RCU_DEBUG
To: Marco Elver <elver@google.com>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Christoph Lameter <cl@linux.com>, Pekka Enberg <penberg@kernel.org>, David Rientjes <rientjes@google.com>, 
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, Vlastimil Babka <vbabka@suse.cz>, 
	Roman Gushchin <roman.gushchin@linux.dev>, Hyeonggon Yoo <42.hyeyoo@gmail.com>, 
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, linux-mm@kvack.org, 
	syzbot+263726e59eab6b442723@syzkaller.appspotmail.com
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: jannh@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=FjD3zLoo;       spf=pass
 (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::535 as
 permitted sender) smtp.mailfrom=jannh@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
X-Original-From: Jann Horn <jannh@google.com>
Reply-To: Jann Horn <jannh@google.com>
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

On Mon, Aug 5, 2024 at 11:02=E2=80=AFAM Marco Elver <elver@google.com> wrot=
e:
> On Fri, 2 Aug 2024 at 22:32, Jann Horn <jannh@google.com> wrote:
> >
> > Currently, KASAN is unable to catch use-after-free in SLAB_TYPESAFE_BY_=
RCU
> > slabs because use-after-free is allowed within the RCU grace period by
> > design.
> >
> > Add a SLUB debugging feature which RCU-delays every individual
> > kmem_cache_free() before either actually freeing the object or handing =
it
> > off to KASAN, and change KASAN to poison freed objects as normal when t=
his
> > option is enabled.
> >
> > For now I've configured Kconfig.debug to default-enable this feature in=
 the
> > KASAN GENERIC and SW_TAGS modes; I'm not enabling it by default in HW_T=
AGS
> > mode because I'm not sure if it might have unwanted performance degrada=
tion
> > effects there.
> >
> > Note that this is mostly useful with KASAN in the quarantine-based GENE=
RIC
> > mode; SLAB_TYPESAFE_BY_RCU slabs are basically always also slabs with a
> > ->ctor, and KASAN's assign_tag() currently has to assign fixed tags for
> > those, reducing the effectiveness of SW_TAGS/HW_TAGS mode.
> > (A possible future extension of this work would be to also let SLUB cal=
l
> > the ->ctor() on every allocation instead of only when the slab page is
> > allocated; then tag-based modes would be able to assign new tags on eve=
ry
> > reallocation.)
> >
> > Tested-by: syzbot+263726e59eab6b442723@syzkaller.appspotmail.com
> > Signed-off-by: Jann Horn <jannh@google.com>
>
> Acked-by: Marco Elver <elver@google.com>

Thanks!

> Looks good - let's see what the fuzzers will find with it. :-)
>
> Feel free to ignore the below comments if there isn't a v+1.
[...]
> > +config SLUB_RCU_DEBUG
> > +       bool "Enable UAF detection in TYPESAFE_BY_RCU caches (for KASAN=
)"
> > +       depends on SLUB_DEBUG
> > +       depends on KASAN # not a real dependency; currently useless wit=
hout KASAN
>
> This comment is odd. If it's useless without KASAN then it definitely
> depends on KASAN. I suppose the code compiles without KASAN, but I
> think that's secondary.

In my mind, SLUB_RCU_DEBUG is a mechanism on top of which you could
build several things - and currently only the KASAN integration is
built on top of it, but more stuff could be added in the future, like
some SLUB poisoning. So it's currently not useful unless you also
enable KASAN, but SLUB_RCU_DEBUG doesn't really depend on KASAN - it's
the other way around, KASAN has an optional dependency on
SLUB_RCU_DEBUG.

[...]
> > +#ifdef CONFIG_SLUB_RCU_DEBUG
> > +static void slab_free_after_rcu_debug(struct rcu_head *rcu_head)
> > +{
> > +       struct rcu_delayed_free *delayed_free =3D
> > +                       container_of(rcu_head, struct rcu_delayed_free,=
 head);
>
> Minor: Some of these line breaks are unnecessary (kernel allows 100+
> cols) - but up to you if you want to change it.

https://www.kernel.org/doc/html/latest/process/coding-style.html#breaking-l=
ong-lines-and-strings
says 80 columns is still preferred unless that makes the code less
readable, that's why I'm still usually breaking at 80 columns.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG48ez2Jsc2V1NfN1YOnx0e3-3BaVSdac7p_y9gnYL%3D9VW6cOw%40mail.gmai=
l.com.
