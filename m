Return-Path: <kasan-dev+bncBDEKVJM7XAHRB2XXS3YQKGQEFVVHG5Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x339.google.com (mail-wm1-x339.google.com [IPv6:2a00:1450:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id EBE08142DC8
	for <lists+kasan-dev@lfdr.de>; Mon, 20 Jan 2020 15:40:42 +0100 (CET)
Received: by mail-wm1-x339.google.com with SMTP id w205sf3773556wmb.5
        for <lists+kasan-dev@lfdr.de>; Mon, 20 Jan 2020 06:40:42 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1579531242; cv=pass;
        d=google.com; s=arc-20160816;
        b=cESiIUCKw/L/t9VhcFXBrbm5/Q/3ThvG6FGIbi3E7RU7VeGIIBpRRRF8FjpF5/3r/z
         P7nB3l+MUx0djKu2OLTplpbIpZWXnTBS8aS2wPrNLC2RYR/ZkEFzZbK8UtOfrpUZ4H4z
         gRD/JItURBWAT8Y19iTLgsoNhQS8wz+G5nYh8X+79WGoLUTtL1bFjWx5wSxMQKw5kHOq
         udqakPE3ps6gOewAgSSJv8x7rr31xrWzc30t/3M7ASGzJ1lhDeY0G4Rdy+KR2pAs2zE3
         e2lZQ3i3X4cLaWiZSPSTgLoNQfqdAsgrx122fFXo1HHHs+GVNT6hBr14vakUiC8eEqFU
         e67A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=xs86y1t6tuK0j3YHlJOIaPQleeYsVtWBvIcE2cwAyJ4=;
        b=XeE8+HAsoe3GCKsjB0+NSby0I6/Yt/650ieG3eo44fgmX2KQ0gB4MSwMYdkA/sPzRP
         6GH/lMQ+W/mEaKIV8R4HwDa6G14IgFKnkydtxBJvqxLPnx/+Fj9prvtcA3/ol+bch5yd
         N6gFB4IHQ9INaBI3DRxNNmZ3fBpAsFuhdbE0HIrg0x1WrnGRk0nT4acvebMCbdXCO095
         GKfABnQroIR6nnByPC9dGx9CfMx7s6hU3DI26+Vd5GbMUGUAmFoc0Y+Y6krv2pEz9UWY
         ncHi5BrHLvgiWoZieWGO+aju0D++6bU70JzkiidTGykO/QLgtZ5QvkVIVjUqScL+cHsm
         9tBQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=neutral (google.com: 212.227.126.130 is neither permitted nor denied by best guess record for domain of arnd@arndb.de) smtp.mailfrom=arnd@arndb.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=xs86y1t6tuK0j3YHlJOIaPQleeYsVtWBvIcE2cwAyJ4=;
        b=q6GNcIJl1cw8KH+ySxDbKJLGBxAirzl3a6rKwtBjI2hgYgu5oU1bkn9v8x/AARtpJj
         nPvS0l9K9/k1icp310epMSx6MchVVkPsq3HfLPzQ5HzvuCax76kIMWXwB7/jk+29FPC+
         K0YQyU4/abeRLQ6jlOmJFAELNeFGbhVy5Ma0BsnKKtcUifrVOqAPmI6onEUpc5JrQS4P
         +cuZgt8qm+42u6j2KxEVcFRbqwZczhLh4zJwwS7L8eyzbQo80AOipRheaxErscNdj32t
         i/k0j8ap/0LvQlvt7fTzqvxDZJoEDLr5TIySHtNtbwsGXwNEmb2zKjYSN+OwoIW5gHHm
         7QxQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=xs86y1t6tuK0j3YHlJOIaPQleeYsVtWBvIcE2cwAyJ4=;
        b=s0ZbTlEZsVUfPrOjzYbALBDIeIPAsgmRdhFvKC0LocUhwmKJJ/QAO+1uEkJ2UVuM3B
         YiIXP6wm87rv1dIZuib0dZE+o+5rw656e5FxeInmu4ZeNfmik7klT4Ilf11uw7n56WdE
         X9owqIhM+pxz7mMH167+ns5GPW1IEnL7VORJmeYqa5g+nCdkEjCC2VnyDNLd1Bt3aDWH
         mApq6YrXJHfUGL9P+odkO3bT4hPIqKfupZU/d8203VgET8jxeLJZNFZXrB9qXwPVuWyx
         QZacB2TycO+DniPQLjGZg2BnaEi13Egc4r3bsYvmTJaY/dYK2Jc9RO+D3B1um/9qgxfu
         PCVQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAXVkesuOdNUIWQTQzbCn0jsHByjkHIwvPVpr5YhtXEwH1YvCBgR
	btvZpA91PvLB0mNDKNLeaNM=
X-Google-Smtp-Source: APXvYqwMVHTIy+9mza8vMOd1rL5Dx6Ys4vFRJzFJ4eqOHxJ39wfW7AUw6UxxNg/RGZuykiw7Mrqn8A==
X-Received: by 2002:adf:eb0a:: with SMTP id s10mr17788610wrn.320.1579531242644;
        Mon, 20 Jan 2020 06:40:42 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:6303:: with SMTP id i3ls2646759wru.13.gmail; Mon, 20 Jan
 2020 06:40:42 -0800 (PST)
X-Received: by 2002:a5d:44cd:: with SMTP id z13mr19086396wrr.104.1579531242025;
        Mon, 20 Jan 2020 06:40:42 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1579531242; cv=none;
        d=google.com; s=arc-20160816;
        b=DrWqLTV7CrTFZSPf147D6vgMDEbscUjeiIWJ/C0fl0bwR7TbAMH2aZUXJ75/hWqAwO
         Hr6XXDEG6qEBxejO53mxmyj3GaCY8RliPmkO3y5QRxVBlq+6GM23mrn6vxrKY/XnSKLG
         vWCfX2KcyH6fkgjVgG2rAi9xhK7rPx5jGl4osWSkYGwY9ltxvv6h8ny7/YXUa/18/4Zs
         xT7HaGiI+frpjyWBXu1gIinntkKXE7NLb5UT2S8xraSfry7HmZQ2s32WW8zmmY7yBPeW
         vCxMDLDRs95+um5C9d9gaiIl6jKu9b7nL/JyZmJi46FjKJIE/04Mk/6Mhh1rabG3EDGB
         chdQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version;
        bh=bGy4Y3DN9bfeRHks2Q+AssnVpWwL2EAEAa6tTvnssZA=;
        b=hTHQp6cH/0k1dqTVG+HES7lzUehR04c0lWawrGztbmq0QFuNjxQiSkgqqvJVeM//12
         g9sZWwTVCrdw3Kc08vhOYEduCyU6YvMwa8PfIX1VdwGVpzINlj3Zw4AvGwCjnsxgcS11
         MpmwV96PfHIActAOZzNO1zvML3Nd2xk/hdvWOIL6JPEEs87tZk/WRYCWxNWTnpIaxfQk
         wg52woRyk3KWHRVwy3nN7Gy70I+7r+APpeDafDMm2I1BxNUjN57DM7bcvcmNJES7eWQ5
         rhRE1Cdf8rPlImvk7V0+5SPe7rjnoKTCYHtK15p/R1yZowye52PhaK7ri2r61kgcaqqv
         EetQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=neutral (google.com: 212.227.126.130 is neither permitted nor denied by best guess record for domain of arnd@arndb.de) smtp.mailfrom=arnd@arndb.de
Received: from mout.kundenserver.de (mout.kundenserver.de. [212.227.126.130])
        by gmr-mx.google.com with ESMTPS id g3si1389909wrw.5.2020.01.20.06.40.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 20 Jan 2020 06:40:41 -0800 (PST)
Received-SPF: neutral (google.com: 212.227.126.130 is neither permitted nor denied by best guess record for domain of arnd@arndb.de) client-ip=212.227.126.130;
Received: from mail-qt1-f178.google.com ([209.85.160.178]) by
 mrelayeu.kundenserver.de (mreue009 [212.227.15.129]) with ESMTPSA (Nemesis)
 id 1MYeV1-1j72TK1SXD-00VkpT for <kasan-dev@googlegroups.com>; Mon, 20 Jan
 2020 15:40:41 +0100
Received: by mail-qt1-f178.google.com with SMTP id w30so27764991qtd.12
        for <kasan-dev@googlegroups.com>; Mon, 20 Jan 2020 06:40:41 -0800 (PST)
X-Received: by 2002:ac8:709a:: with SMTP id y26mr20880033qto.304.1579531240224;
 Mon, 20 Jan 2020 06:40:40 -0800 (PST)
MIME-Version: 1.0
References: <20200115165749.145649-1-elver@google.com> <CAK8P3a3b=SviUkQw7ZXZF85gS1JO8kzh2HOns5zXoEJGz-+JiQ@mail.gmail.com>
 <CANpmjNOpTYnF3ssqrE_s+=UA-2MpfzzdrXoyaifb3A55_mc0uA@mail.gmail.com>
 <CAK8P3a3WywSsahH2vtZ_EOYTWE44YdN+Pj6G8nt_zrL3sckdwQ@mail.gmail.com>
 <CANpmjNMk2HbuvmN1RaZ=8OV+tx9qZwKyRySONDRQar6RCGM1SA@mail.gmail.com>
 <CAK8P3a066Knr-KC2v4M8Dr1phr0Gbb2KeZZLQ7Ana0fkrgPDPg@mail.gmail.com>
 <CANpmjNO395-atZXu_yEArZqAQ+ib3Ack-miEhA9msJ6_eJsh4g@mail.gmail.com> <CANpmjNOH1h=txXnd1aCXTN8THStLTaREcQpzd5QvoXz_3r=8+A@mail.gmail.com>
In-Reply-To: <CANpmjNOH1h=txXnd1aCXTN8THStLTaREcQpzd5QvoXz_3r=8+A@mail.gmail.com>
From: Arnd Bergmann <arnd@arndb.de>
Date: Mon, 20 Jan 2020 15:40:24 +0100
X-Gmail-Original-Message-ID: <CAK8P3a0p9Y8080T-RR2pp-p2_A0FBae7zB-kSq09sMZ_X7AOhw@mail.gmail.com>
Message-ID: <CAK8P3a0p9Y8080T-RR2pp-p2_A0FBae7zB-kSq09sMZ_X7AOhw@mail.gmail.com>
Subject: Re: [PATCH -rcu] asm-generic, kcsan: Add KCSAN instrumentation for bitops
To: Marco Elver <elver@google.com>
Cc: "Paul E. McKenney" <paulmck@kernel.org>, Andrey Konovalov <andreyknvl@google.com>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	"linux-kernel@vger.kernel.org" <linux-kernel@vger.kernel.org>, Michael Ellerman <mpe@ellerman.id.au>, 
	christophe leroy <christophe.leroy@c-s.fr>, Daniel Axtens <dja@axtens.net>, 
	linux-arch <linux-arch@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Provags-ID: V03:K1:AvelpdZZ7vjhe4hrzcs0bZXPUmOj6GKAz4mIv39d5t+D359t9zS
 RpOQkpsataUsahkDr51RsN+196XoXivIk50bpu2aFiGCAbA6yoYLb8/L4TYY2vnrhlq1CqP
 KLOdTWxlebURbFNHpx1xH+zk3XCdani0+FqGuJ2Buf0/hyyur/gJ+vkctrc0J4sW5w7oGpc
 AjhByI6UVSN7MWfrPDzAQ==
X-Spam-Flag: NO
X-UI-Out-Filterresults: notjunk:1;V03:K0:NdI01PA0gaQ=:Rlyci6KNTqQrgiwIwZS4Ac
 OrOhdahWhd+Lyodd2Y8Xavn7WggrusraV0yiC7Rygwo5p7ZRbrF0als3VLSzILAJGO245r+9w
 9vWWrt2lLu4CRinaT1ebzXEpXimeaKo12J8l0FV+B/YrxZQwLbUNzRqvikRIJenDh/g1ulH6/
 S4ykuvbnwt3IFZHp88nXnY4UPum3gKk7/39CwWU8mB/7mlFeweHnw8iXZb1lXOOTLkJgmr/P0
 R3MjMCkWfmwM6/yf4dGTCdBHePUCc0r6amKAWSEsUcPwr/F5RN2mAY41Mo/mCNyVZF79m88Xd
 Brwyls/aU7G3n6B4cLCmEQY24hNYEUia19AUCEhzi4Z3qcYzYERtK4/NuyGC5VGeJZHTOmY/M
 mRfykfa6QaZMXrNx+4PDtZMYF1KsGaoV7xU7LAh+GaBxuLaos2A1b5TxDWB8VAvU1Aio1Ie8a
 ZL4Al8X+c/2nH0zajxoRYPMS1XJXyqvzIzSZ6e0tOn2J0ZxVH+LMUE7FHPP1wMiCyUET2k9b2
 RT5LeKVQesqipxgwAaIfCh3lGHIgtqG/IhZ5gwHGD+4/bRMoJEU5fR1hs7PgzWEQKt5Vn84RE
 YjKnJnPLRVHxlWzl3m3tMCLabyfyP/gZO69Ecr1ifdJnsaAOkee9wx3YxnLiD6mIPmjf1yakG
 TzMCNbotBS2mAWVs1rigGyo1saGXBpBRz/M42jfuyliIhPzxV6oaNma2lurCQ+fmmRzkSLzgQ
 /vHsatQ0CEXGw0TboiBP7ouTjn0LRnqay9VITATkm1iBvt+7fNs6ajZJ2RyGt7UM00XKnm/5F
 63E8gcU8ECF1PagMbYgI7vWWtrc7bZTYTjEA3iGvTWhlT7c3tpeTgkSUgauYaPW5MGZjdkLQ0
 UJSdNV/i/WuaIaAD2d2g==
X-Original-Sender: arnd@arndb.de
X-Original-Authentication-Results: gmr-mx.google.com;       spf=neutral
 (google.com: 212.227.126.130 is neither permitted nor denied by best guess
 record for domain of arnd@arndb.de) smtp.mailfrom=arnd@arndb.de
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

On Mon, Jan 20, 2020 at 3:23 PM Marco Elver <elver@google.com> wrote:
> On Fri, 17 Jan 2020 at 14:14, Marco Elver <elver@google.com> wrote:
> > On Fri, 17 Jan 2020 at 13:25, Arnd Bergmann <arnd@arndb.de> wrote:
> > > On Wed, Jan 15, 2020 at 9:50 PM Marco Elver <elver@google.com> wrote:

> > > If you can't find any, I would prefer having the simpler interface
> > > with just one set of annotations.
> >
> > That's fair enough. I'll prepare a v2 series that first introduces the
> > new header, and then applies it to the locations that seem obvious
> > candidates for having both checks.
>
> I've sent a new patch series which introduces instrumented.h:
>    http://lkml.kernel.org/r/20200120141927.114373-1-elver@google.com

Looks good to me, feel free to add

Acked-by: Arnd Bergmann <arnd@arndb.de>

if you are merging this through your own tree or someone else's,
or let me know if I should put it into the asm-generic git tree.

     Arnd

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAK8P3a0p9Y8080T-RR2pp-p2_A0FBae7zB-kSq09sMZ_X7AOhw%40mail.gmail.com.
