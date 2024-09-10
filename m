Return-Path: <kasan-dev+bncBCCMH5WKTMGRBENLQG3QMGQEWFK3SFY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x439.google.com (mail-pf1-x439.google.com [IPv6:2607:f8b0:4864:20::439])
	by mail.lfdr.de (Postfix) with ESMTPS id 870FE9739B8
	for <lists+kasan-dev@lfdr.de>; Tue, 10 Sep 2024 16:20:03 +0200 (CEST)
Received: by mail-pf1-x439.google.com with SMTP id d2e1a72fcca58-718d51f33a6sf4212315b3a.2
        for <lists+kasan-dev@lfdr.de>; Tue, 10 Sep 2024 07:20:03 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1725978002; cv=pass;
        d=google.com; s=arc-20240605;
        b=NdJeXjmHOllZiykvYnhpPDtMsF7Nnk5lMcyLhr9rlWIsKKEuhrl92aD7DgvR1bcoW4
         QLf/zYLdk3/Jf+gSjsD9pFPSgAqJ6TcBS4T8T5ZvXqytvyDUNXV3pvOl7VgJzPwoSzfE
         TnJ5pWdVSFc2WuQXeDfv8lM7lyv8n6r31zF1ZmqSZJUm/7erMn0yoE3EuKosetnD9q6r
         D/OzQRMvlffql0OPGCp8u3EFteNetCaKJsl0vIzNk1GktE/hxFekEYwsk380argJHXDg
         uw7xLzS6Y+ZK1mT52USQgWA7n4ca83JwsiQe1POV4e6Aw0crNBJ41JOKI4v0hU++YP1A
         b+fw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=JyOfurftKzY6ZcWX2eCRHX70DQPaJxu6kUCCQ0I+8Sw=;
        fh=IF9OxQax1R4rkMWfq7eFL4Hhn+YbCbCmzZRxSMcrqpk=;
        b=RwzW0vaq9K0CZEbIJJsvfQKJjMuHEICvayIb/1sREBwG2Oe7kuKPLGxEO4K0XoDvPO
         FS71rhcMwo7CK/qbE368xLUr+9v7ZAiHF4Iu+WH3MD+KYMhGWyBBmvuIg2VlXgQJwZau
         PR3NYRvdfvhXV7Cm+zJq8+/FNJBAuFgzeCREg71cWU3qOsXkyDdurfVT8+vUErUFvK5/
         PSl4avkQA4v5N5MBR91COohgPSIBbBXCfvHIgujL4CtN5s99Dsvp0wGfnQ2/timuT3+e
         mRfuzYWDcnEOaIsXMvQNxHlSn4ja5ZTFGkb1IFucuC81uX28Uu9BwLoWP7E0GnqvONKN
         aFUA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=tICHAKOW;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::735 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1725978002; x=1726582802; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=JyOfurftKzY6ZcWX2eCRHX70DQPaJxu6kUCCQ0I+8Sw=;
        b=E28auHjFZUbOKiOot3q2eTEgCH566eSh/JcrCmS+NcM1Spwq3jxiUE3UFDaIkwKzat
         fzlvTmkmVG9BIkZcmCmNr3KwMrizbd6bQrFeIPs5FELgSxjs6MtZTvhwALwyr5yp7LzL
         ALzwn6tqXiqVNevR0Sc/WRn+67VHdXWf2d8X7ODdFcTf+W6toRX2Z8fX5YZPJKZ2JQ0X
         +3k1Gkt/X58TR6zwE1X5jEZBuZCBeTTxASSaYS3QXkfD7dY2QUhsnWCj+LO51HtKnxxr
         AAZ/WioTH0Qv7zDclPLjqQCe/G78W3DeIbh22QWlawh4EIxp/Q4nCA5K1LLHqdPr00EI
         bRNA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1725978002; x=1726582802;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=JyOfurftKzY6ZcWX2eCRHX70DQPaJxu6kUCCQ0I+8Sw=;
        b=dwY7plBq3IMWXnP74QHpzjxKOJxMIQKGBDzYs9xOICAajdzVh1Tlwq/bt/LwTyoZqD
         0rLxehP2vu1Itl/jBI7emL4jsxl9va2qNyJc8vaZrhQF/bEPMch72pgWTL7s9Q0NK4vE
         MU6bFX42f4DUavT4VYzPq7ryumYjJJc3f0E0vq5WLGLS0MCXK7k1ABOe2yl7kfFDCCgU
         9X3uJtaSgwYb9QrZMCtDGdBlGYwBe/zdEYQAzjNFz0sCgfOwMcKwURPGigO+RMai+qgu
         yK0RrlNwNA7M+K6fBhFZFSO9lbkKDnLO1vvnMhG2gl3g89qR81aT72x44c0yFEB+Ylbr
         uqVg==
X-Forwarded-Encrypted: i=2; AJvYcCXg4cdL7uqmL9L46ZUZ4y8OeYk+1dfiWpY8hA2RLfikZJdmFjmz5ZnUDzie9EEoiw9q+/8Otg==@lfdr.de
X-Gm-Message-State: AOJu0YwE84I0wQw/q39cq0LW4DZxx0b/oqCnia94xEEbSJsAUFe/vliw
	dKOlm156igphXhxiIh4M2PxUhD2ibL2k5NppufuGiol1LBngQQvV
X-Google-Smtp-Source: AGHT+IELhgg46luvKQyxymGiStCFzgrjMPRvLf5KeIBWLtgDxLg9ZCryuZ4y2aUiq4zMvOYHnXinCw==
X-Received: by 2002:a05:6a00:3cce:b0:718:d516:a02a with SMTP id d2e1a72fcca58-718d5ee0339mr19107225b3a.19.1725978001642;
        Tue, 10 Sep 2024 07:20:01 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:b89:b0:714:2859:13fd with SMTP id
 d2e1a72fcca58-718d502f470ls3275678b3a.1.-pod-prod-07-us; Tue, 10 Sep 2024
 07:20:00 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUFoo2HpvBjT/THyrMGwPqRc2HMRdgROoRZUThLS5jC//Y/SDNekucgZ4l6+8NshZkV5hMi1iVdn1s=@googlegroups.com
X-Received: by 2002:a05:6a00:2284:b0:718:ebdc:6c81 with SMTP id d2e1a72fcca58-718ebdc6d61mr9013796b3a.26.1725978000514;
        Tue, 10 Sep 2024 07:20:00 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1725978000; cv=none;
        d=google.com; s=arc-20240605;
        b=ftYRPIQ1HLUhTPmnuz/i7AELtD9h+RFz6gnHhnIyODQYWO0fsCs8JKdFVioJMHNfb8
         8/sVOv1ONMhV2qSxTvBNXi51KfgzWXdWKF6bvIgXX2prOBDNWYulXX3CtnQPeg/LT+b6
         9Deq+jtjEeWi8uz8MqZcRzfW68xUglvZT1tW8Agsark/nUtajGZkYn+P/RHYmNvZGkjR
         oHkln43/KaXZ3Q9KdqXVXesyPS8x6DNjSOSgHxiwIpP11pWtYWaR636iuPJrMvOQ6CjS
         yx7zf8GyEeL+d9E+kXpt2iUeFz45TRYBkJMPAbZvFD7LboaOKR0tMC4wsCKavIRwLgl1
         4m7Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=Jx0Skg+LeZzo5wW4Rr/X6Np29gcXKRlYjoaHnTmyULQ=;
        fh=ppxk46EpQJYpZsqAMC7t8YF2OAJi0D9ABN4DH1pcfb4=;
        b=Kdt2WoUQf2wYUBGSofHWmj0nLiFW2PYx0uuq4AcplKGDeh/8esq3VUEjb+grzb9uGi
         lj7xjnof8AVpnbpN7ul5TGEZnQ9vDyPVjRdSjWp79OD/vQgmrF7JSVdgIUjtseWkKLfP
         wXVROsV0xa3wSDd2qj+N3XZTPuq2R04zYTCHcNzroAGquD6pldn06JqjCQneGFg4YBYP
         wbuYT2RjJx4RH083M2z1NtiK3Py+H3g/gHwoRSwA9/Gp4iia+ltjy2FXHwa6i8I3oxj9
         yg5+Weqx5uSOIo9s9SwaLNhW2qm4FAvvAyZo0RKwQ1MgamiM3pAXFsNT0DyNP8waSZGR
         GsXg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=tICHAKOW;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::735 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-qk1-x735.google.com (mail-qk1-x735.google.com. [2607:f8b0:4864:20::735])
        by gmr-mx.google.com with ESMTPS id d2e1a72fcca58-719091955d5si90259b3a.5.2024.09.10.07.20.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 10 Sep 2024 07:20:00 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::735 as permitted sender) client-ip=2607:f8b0:4864:20::735;
Received: by mail-qk1-x735.google.com with SMTP id af79cd13be357-7a9b3cd75e5so180225685a.0
        for <kasan-dev@googlegroups.com>; Tue, 10 Sep 2024 07:20:00 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCX4OUqnHpGm2cH/CiyiZUVHem8UiFYQFtsaPiKhsvXJ0ij7RSLjeX9ojBnsTvl6WnX+TBHiTi3n0SI=@googlegroups.com
X-Received: by 2002:a05:6214:390e:b0:6bf:7d3c:a64d with SMTP id
 6a1803df08f44-6c52850ddcdmr172364426d6.32.1725977999107; Tue, 10 Sep 2024
 07:19:59 -0700 (PDT)
MIME-Version: 1.0
References: <20240909012958.913438-1-feng.tang@intel.com> <20240909012958.913438-5-feng.tang@intel.com>
 <4b7670e1-072a-46e6-bfd7-0937cdc7d329@suse.cz> <ZuBURfScdtDbSBeo@feng-clx.sh.intel.com>
In-Reply-To: <ZuBURfScdtDbSBeo@feng-clx.sh.intel.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 10 Sep 2024 16:19:19 +0200
Message-ID: <CAG_fn=U=tkh-mLThLsupNRsKRHkxPL__U_eFSCCbmeHTdoA6Hg@mail.gmail.com>
Subject: Re: [PATCH 4/5] kunit: kfence: Make KFENCE_TEST_REQUIRES macro
 available for all kunit case
To: Feng Tang <feng.tang@intel.com>
Cc: Vlastimil Babka <vbabka@suse.cz>, Andrew Morton <akpm@linux-foundation.org>, 
	Christoph Lameter <cl@linux.com>, Pekka Enberg <penberg@kernel.org>, David Rientjes <rientjes@google.com>, 
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, Roman Gushchin <roman.gushchin@linux.dev>, 
	Hyeonggon Yoo <42.hyeyoo@gmail.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Marco Elver <elver@google.com>, Shuah Khan <skhan@linuxfoundation.org>, 
	David Gow <davidgow@google.com>, Danilo Krummrich <dakr@kernel.org>, linux-mm@kvack.org, 
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=tICHAKOW;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::735 as
 permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
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

On Tue, Sep 10, 2024 at 4:14=E2=80=AFPM Feng Tang <feng.tang@intel.com> wro=
te:
>
> On Tue, Sep 10, 2024 at 03:17:10PM +0200, Vlastimil Babka wrote:
> > On 9/9/24 03:29, Feng Tang wrote:
> > > KFENCE_TEST_REQUIRES macro is convenient for judging if a prerequisit=
e of a
> > > test case exists. Lift it into kunit/test.h so that all kunit test ca=
ses
> > > can benefit from it.
> > >
> > > Signed-off-by: Feng Tang <feng.tang@intel.com>
Reviewed-by: Alexander Potapenko <glider@google.com>

(assuming KUNIT maintainers are fine with the change)

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG_fn%3DU%3Dtkh-mLThLsupNRsKRHkxPL__U_eFSCCbmeHTdoA6Hg%40mail.gm=
ail.com.
