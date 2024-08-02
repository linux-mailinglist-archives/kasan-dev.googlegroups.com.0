Return-Path: <kasan-dev+bncBCQ2XPNX7EOBBO5CWW2QMGQEFVJTAYA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x240.google.com (mail-lj1-x240.google.com [IPv6:2a00:1450:4864:20::240])
	by mail.lfdr.de (Postfix) with ESMTPS id C239F94651C
	for <lists+kasan-dev@lfdr.de>; Fri,  2 Aug 2024 23:35:56 +0200 (CEST)
Received: by mail-lj1-x240.google.com with SMTP id 38308e7fff4ca-2ef311ad4bcsf83771591fa.0
        for <lists+kasan-dev@lfdr.de>; Fri, 02 Aug 2024 14:35:56 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1722634556; cv=pass;
        d=google.com; s=arc-20160816;
        b=1AdBzorf8lYc2Gig1NIxicxwaj9Bt8cy24sAL+/eIfnNJZ10zc3LADxjoWBNSXhdkZ
         pxu+RrUe0J/HSQuND50qOqE7BVtTMIrbdByKSUiTsSYiC9qYYtrwXrD5g834ycYWb+5T
         9hgCNcf1fbSfIKS//ra6UDfm8sK9tJW134SLYRfela17ku+qy/2yh7MyJvFmFBFbznmr
         KhsXWGrzVmGZso3RaPfy7iYANCUpcQ5Vkd5DRQ8L6ujTWcPTQ5XpVjMw5NHztp+Bg6+u
         ClQigPfvSO5GFM52fC1TUOzSEg90F6Po6hgOxYoYLNXAYsd4sYaj32khCTHRFnxh02Cd
         TxHw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=L1+Pd8xS5u1YizAbUBjh9tWkQKFiw4MUX3+r+aMRFCk=;
        fh=DqylATs6HcEN0cqo0aCKarv4I9RM7RIhMaELO13tMm0=;
        b=i9s55YYeLbVKxxk5jV4T9Thl+VFYf+TRrGYwOopSnuMR8kEAPb2QR9UTN+sJyXDqP6
         tLjdeEs/JU5MLCme0orTSRTn8SuaCVgQt9YcgZPZmrrl8HJ7U+jYafEbZEnyCiwVFjNO
         LOKSWuDMPd2L3JkBcbGNQm0Gh8QydSSdWoYb6nK2O3YAse7yhtCjDOuWvWjkyxq1ZVdY
         an2VFeuZ8dGqOBykttAJpLfyBncEAXwjIuuTtZepymNCI6dv3rtTRMmHgcGl5nY6eVe9
         emxzbc8dMgUsh9Cyqq4GNiDGfviq5d5rQrQCcDnZp+JoVwaKBcaUec8VwDUjULGdqojD
         0bIQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=BXTkHrut;
       spf=pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::532 as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1722634556; x=1723239356; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=L1+Pd8xS5u1YizAbUBjh9tWkQKFiw4MUX3+r+aMRFCk=;
        b=bVSJsQzwzqX4hoY4jyDAt0UeHpr0sAyPdA5l5D4k29HqpCsluwKh1Dc4QUV3NgNDqM
         q+cOKmBmgEovCrIK0L8Z6I/DVcWdBdgQqUfffS2lMXn1/yeqWEnyVhuVjoA8bh17xCbi
         fZ6NWHXjFBQgHF8atB1AFXUIBMYL+HS74plkuX8yuEFucKV2HSENqLp/HmNzC87CbEd3
         AymC5G5BM7cwzRh/fCyA/MKL/Qvpi15tSGq7jZV9G2gWqWGtw7Qmd9Q06TA4YdC5W5SI
         csXphtwm2Y0yxVf/oFYxkd5B9E2kdfyltyuX25OJN5sME5hMEbH6QSXTZDPA1ZhGvxS0
         o7Xw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1722634556; x=1723239356;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=L1+Pd8xS5u1YizAbUBjh9tWkQKFiw4MUX3+r+aMRFCk=;
        b=e5NcKXZvGT3zNGlGoKmYXWG3fn2pUi57TBBhqtfUyzQ4yZuc7h7mD7WOJcBeg0oFkC
         nj7jQPO46sYbPM7+kw5r67Ccrfh2p5Hlyz7BpljuvYgMZUuV7Gcquf/A4VRTMd40xmgd
         hwuW31FFUuYLcur21X4AY5B7iXPjuneJgGHWtXW41DXHvhEaA81On87eYXuyD1Og4g1Z
         VvgFAWhAEZmlCutnhh65BKKc277/fc9AHseFzLP9dXHhcUtrQiNmNyAXYhPD3iVzXdQk
         i3TwpmxGTNREYBDPTkIQD3PHVV+PuLAZymY+zVE0BOxIqjypBUO7NgsPZcFZRiC4CLmt
         rfUg==
X-Forwarded-Encrypted: i=2; AJvYcCWCTH699Bsvo7PszMVBjso//080O4Ik6E48vVkYp+3PdCUGo4Y52K20x6Tkl23lkBa/Kkxt3KJUxmagtRLcMQl2vPgkS9vKIw==
X-Gm-Message-State: AOJu0YxmOF4569DcI/2821/C7uFDF4ibinCG5JgMFfBGBBVGcv5gvFvv
	VVhH7UktzHnQoPAF5DI5Tet7PeRi92Tl7xYlbe4DQoK41yN2dK9G
X-Google-Smtp-Source: AGHT+IG+3jSQEkUNzp/xQ4h4hhnUSykGkpzSZ/O7A+pQ3qtCWI1dsdFrEwmiXSkyoq+TIIhz08bLzQ==
X-Received: by 2002:a2e:6a0f:0:b0:2ef:2bb4:45d with SMTP id 38308e7fff4ca-2f15aa83cfemr31806531fa.9.1722634555427;
        Fri, 02 Aug 2024 14:35:55 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:2281:0:b0:2f0:1cb8:9ec5 with SMTP id 38308e7fff4ca-2f16a31169als1521841fa.0.-pod-prod-09-eu;
 Fri, 02 Aug 2024 14:35:53 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWeSOyLRiOQvl26vhG87e6ObsQ6tFst8uCz6RtbZNsdgwIGNvPmeZoZscqAgWDMEJd3i+zu/1XC9aWGRV5iwYsod9GhYFh2ssUaOQ==
X-Received: by 2002:a2e:720a:0:b0:2ee:7dfe:d99c with SMTP id 38308e7fff4ca-2f15ab0c434mr35738551fa.31.1722634552688;
        Fri, 02 Aug 2024 14:35:52 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1722634552; cv=none;
        d=google.com; s=arc-20160816;
        b=N0O04KQl31YYJ0u2Q0AperhRRazAHndztnk7R5v7i18MDZPdlN9LSo2E+BYLUAe7y4
         0NMj8xQsKuTOy1Ti6pzn0grIELahTn+WzMwy98dleyHxN45ww6YkXVBbgU2uiN/Fy3X4
         p+1i0qM3f58Nb1ambMmiDK4lV2SX8+h8XracD6o2NzSpOZDuJOLibgKlHfeEBvb9LkxP
         55jp2F6kdtqrc8K1AgWcc3MBCH1DukLhP6uO12hCBEBE84gdc9YEem/vM8QOUYwW5M2Y
         YP38K3R0rrDA0uMS8p0xk50AGvRhruOseG10Jdknj/Yy9b8Nzl8E6YzBT9WmkixF81FM
         q1FA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=MxX+FJ8xaCVT8A2gxdlfc9WkbMjiHVlxlmKzCUZ8Z4U=;
        fh=yFIYPZbg5OjU5EsBklANIv0FZh24DNuXNlO0mMEUH2k=;
        b=Q0Ry+40KrFfGu/HL8zOCAMDoOAL1GbLr3NJrCXp+4GsAPQrNbcwkkgyBP2wWaMXhmM
         KKqMtTsTHpo+Vj40DqdJBZqkU+M2BpR/+6wBBjxuYmyVjXoHVl+FD0Rim3kTlt7aIHzf
         PROy7pGPFqhwXThp1gz2DV1r0sZQJB4NUOSDhHFPAPmlzNOTa901cW0ECMsApTYOfHzA
         H9n8Z/rnQGYMuL4FWtrvAgUuKslfHx+ADBXgqL22aWcuEcedLWSah0HAhXOJM4wgK4UI
         75DK5hV2GZd9hiN6OIMb9lKWdLTGEDs52CTdf4B4vmGt64C0kBFiuZJSgYdHCAgIopOU
         gwBQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=BXTkHrut;
       spf=pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::532 as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-ed1-x532.google.com (mail-ed1-x532.google.com. [2a00:1450:4864:20::532])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-2f15e25d3fasi483761fa.3.2024.08.02.14.35.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 02 Aug 2024 14:35:52 -0700 (PDT)
Received-SPF: pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::532 as permitted sender) client-ip=2a00:1450:4864:20::532;
Received: by mail-ed1-x532.google.com with SMTP id 4fb4d7f45d1cf-5a18a5dbb23so59352a12.1
        for <kasan-dev@googlegroups.com>; Fri, 02 Aug 2024 14:35:52 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWoqEZFuGn7PdaGRKAdONDgIGOQ7DvngpEy9/qMXBVV+wWbsZlHw1AFNDnzzwYtKX6U9n0ssy3qfHtB3OPD0vnQwOjpqw0hEic3Ew==
X-Received: by 2002:a05:6402:5244:b0:57d:32ff:73ef with SMTP id
 4fb4d7f45d1cf-5b9c72cadf8mr9047a12.6.1722634551325; Fri, 02 Aug 2024 14:35:51
 -0700 (PDT)
MIME-Version: 1.0
References: <20240802-kasan-tsbrcu-v6-0-60d86ea78416@google.com>
 <20240802-kasan-tsbrcu-v6-2-60d86ea78416@google.com> <CA+fCnZeaphqQvZTdmJ2EFDXx2V26Fut_R1Lt2DmPC0osDL0wyA@mail.gmail.com>
In-Reply-To: <CA+fCnZeaphqQvZTdmJ2EFDXx2V26Fut_R1Lt2DmPC0osDL0wyA@mail.gmail.com>
From: "'Jann Horn' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 2 Aug 2024 23:35:14 +0200
Message-ID: <CAG48ez0ggtaV8MF-bzzS2=zKg-3nfG1G_QaqGdesAJpQSj39TQ@mail.gmail.com>
Subject: Re: [PATCH v6 2/2] slub: Introduce CONFIG_SLUB_RCU_DEBUG
To: Andrey Konovalov <andreyknvl@gmail.com>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Christoph Lameter <cl@linux.com>, 
	Pekka Enberg <penberg@kernel.org>, David Rientjes <rientjes@google.com>, 
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, Vlastimil Babka <vbabka@suse.cz>, 
	Roman Gushchin <roman.gushchin@linux.dev>, Hyeonggon Yoo <42.hyeyoo@gmail.com>, 
	Marco Elver <elver@google.com>, kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, 
	linux-mm@kvack.org, syzbot+263726e59eab6b442723@syzkaller.appspotmail.com
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: jannh@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=BXTkHrut;       spf=pass
 (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::532 as
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

On Fri, Aug 2, 2024 at 10:54=E2=80=AFPM Andrey Konovalov <andreyknvl@gmail.=
com> wrote:
> On Fri, Aug 2, 2024 at 10:32=E2=80=AFPM Jann Horn <jannh@google.com> wrot=
e:
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
[...]
> > diff --git a/mm/kasan/kasan_test.c b/mm/kasan/kasan_test.c
[...]
> > +static void kmem_cache_rcu_uaf(struct kunit *test)
> > +{
> > +       char *p;
> > +       size_t size =3D 200;
> > +       struct kmem_cache *cache;
> > +
> > +       KASAN_TEST_NEEDS_CONFIG_ON(test, CONFIG_SLUB_RCU_DEBUG);
>
> Ah, notice another thing: this test might fail of someone enables
> CONFIG_SLUB_RCU_DEBUG with HW_TAGS, right? I think we need another
> check here.

Why? I realize that HW_TAGS can't detect UAF in a TYPESAFE_BY_RCU slab
after an object has been reused, but here we do no other allocations,
so the object should still be free. And the kmalloc_uaf test also
doesn't check for HW_TAGS.

The one thing I know of that could make this test spuriously fail
would be an allocation failure in the SLUB code for delayed freeing
(but that'd only happen under memory pressure, which I think normally
doesn't exist when kunit tests run).

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG48ez0ggtaV8MF-bzzS2%3DzKg-3nfG1G_QaqGdesAJpQSj39TQ%40mail.gmai=
l.com.
