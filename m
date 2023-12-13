Return-Path: <kasan-dev+bncBDW2JDUY5AORBAUD5GVQMGQE75E7TGY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83e.google.com (mail-qt1-x83e.google.com [IPv6:2607:f8b0:4864:20::83e])
	by mail.lfdr.de (Postfix) with ESMTPS id 5B5A7812376
	for <lists+kasan-dev@lfdr.de>; Thu, 14 Dec 2023 00:42:59 +0100 (CET)
Received: by mail-qt1-x83e.google.com with SMTP id d75a77b69052e-425a6272642sf85766031cf.3
        for <lists+kasan-dev@lfdr.de>; Wed, 13 Dec 2023 15:42:59 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1702510978; cv=pass;
        d=google.com; s=arc-20160816;
        b=QaS3eeQxVnzxecOXhN2n1rtplpfdcyTPs9Q9jwaUGAVBGLrbfjU/z+QQehtTcNZWlu
         sBLQ3OhWx0CmH1RUro1ZpW8OGZAA7Um95qvFvDBiIL5MEDYJafl6a+Mtu3r1l8rFyQ6B
         aLEZ4CaciB4bxx+5IShY15aJl6bDWSoujM9jStkHd1OicZJPZyuhZU4uuNw/em+BwIqX
         WcY2SCcPnnLMCPY5gUsYanO+50Bn8Ys1ol/KkOkURLX+1M+g9NcaSwEvDpwoEOuGtJ/X
         tzhY1hYtAX2depQAmucfl/kOgpaNxxID2SJqyiFpWzYHeq7cO3ncYd2EGHWRKgOLo3cA
         W+pA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=TNh+gX4rf282merJjH9i8hZYK4w971PCU+S1x3inl2A=;
        fh=mcsOkjSKiIVqZTSI0nnbwoKVuIQQbBRaZcAvv5Fi9PY=;
        b=KwrlF5nknflpOAbyGiA2UAIb3yEQv0K++IlmsjaS7eQQLNMcCRHZyo61GhuBAvkwL0
         nK6KB4Nr2Lell7Vbhlccxo44PPqNGjjz5dVbvY6nnOIVrnnhICmK1zZJ6bbhQSmbRXj2
         6v/F9DH2RxMCG+ZXE+rvTSX9+J1/J/NArjRiFOsA10pMsdFjVHWqD9D0LafXdf3DE4Xt
         ZO4tRMFW9q87BRWxBY8R/vYp/9X3bf9a38Qvh6JeZp59S7W/LfXkNGTY+IMjhuo+03S4
         qRlQIfcIg/y55x+W58Vh0JA9aWH9dEONK0W1U7sRbsTOAT89QH9P/cvjj5JwQRg/ZXN2
         nfkA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=mWFsj8Uo;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::c2e as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1702510978; x=1703115778; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=TNh+gX4rf282merJjH9i8hZYK4w971PCU+S1x3inl2A=;
        b=O7Opbw4hUaHcSDc2rHOeczWm987M8LZbm5NUT8upzkfRTtmLsW0goeZq9/ZQtdIJB8
         5C3XcEUg8VgpK5fv86vCpt5SitqeUZYBGSNgSg0x+hOmLRoKzjqIq+u/jRiCzUwYUaDT
         /wWO4lj7iqFCl8S+Idha7ytLUyQ2On4In8LHvyd534RJcLOezq+69E0ttae62/xihD5Y
         uu95Q+EHbuOTX+TTcMt2BIKishv6Hr8RO/kzu6YhERf0zfwQUUtb3AQU2Q4FPPfAHXBV
         KOBr+ibaMCdj3oeUUT6agoPHxNaAkZkWPs/IaBReIiRlEcsk8JN3TTeCQadNRJ6byiNj
         gW5A==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1702510978; x=1703115778; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=TNh+gX4rf282merJjH9i8hZYK4w971PCU+S1x3inl2A=;
        b=FAl9Utz0BXZ68QdLeR/GHOEMYcE69TQoTHvO14n+sRKHCVSXnTNTtM8AZJe1o0gey/
         irPowau07b8UgxlzYtL5blBj07zPuXpGCZ8Kvj0gH8XGk/CTvObqh9nR4aTUlXZxxBea
         FvFBgTBCWWluCFP5fjaXUHGUlQDRye+ugo9HLaQRV4Qh/WCsH2tuwDwNuITFNQlWLutI
         Fbsopb0pEeNNLI/ISDD3Mk+SD2vwqSjXFQhbAHQMlSEsx41e5n0lsJYGGiHsGl5XKofs
         f6hjNlgFK4flHA3VUH5/oy4p6DO4r8V+TwwUUYezQX+A7dLqY3td0S2nID4ApFxSIGK6
         qwnw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1702510978; x=1703115778;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=TNh+gX4rf282merJjH9i8hZYK4w971PCU+S1x3inl2A=;
        b=boXN6opMp6/LkaD89jhiL9r5kQHMShwdZ+s+sOKWlT/BL7+7lSqzKfdZ5Vki0sSxfz
         7P3PeEwMjTJjdOSh7Wf+keZZN6Gu9HswsqIGs6MyjIfPyraJxczmOg4rq7ElFYOOLqEb
         +rP3C4bDSKb7fUcKe82C0aAOyWwagXCShNNFF+xIFRv2s/U9WW9Kxfo7HQzZdgJ5R2pv
         qKNqHdYlpA+QpW9uGRN8SKTi5/ovu0L/FoOsV/0aXgn7Ri8X8lY7LUrKtBetEq55YlEO
         WTxfDBGxe2gg/9Y3QwCwkdvyTsNHFUfZyipVitMVwW+xqQH0pPqpLMMDNIEy10z33OFz
         gZcQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YzSYcMf1wd2CoOCLFxDutioQixmBbFVxfB9q7rCw35qpEy3Rgjg
	cCxUTSCXPFftR02x+o2W5qs=
X-Google-Smtp-Source: AGHT+IHcB8oCDfoNWtYotQHm6rZEwt7P62MHsuRqAviswGBPmnkPYSa5kGNHu77yIW/qBLl35LljBQ==
X-Received: by 2002:a05:622a:1043:b0:425:4043:96de with SMTP id f3-20020a05622a104300b00425404396demr11427299qte.107.1702510978159;
        Wed, 13 Dec 2023 15:42:58 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:622a:1aa4:b0:423:a0d4:8c61 with SMTP id
 s36-20020a05622a1aa400b00423a0d48c61ls3003380qtc.2.-pod-prod-09-us; Wed, 13
 Dec 2023 15:42:57 -0800 (PST)
X-Received: by 2002:a05:622a:144e:b0:425:4043:96d9 with SMTP id v14-20020a05622a144e00b00425404396d9mr12578296qtx.102.1702510977347;
        Wed, 13 Dec 2023 15:42:57 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1702510977; cv=none;
        d=google.com; s=arc-20160816;
        b=znipCEBbmNKdZ7k42T4FcHJoN2ooSSuugkKe4dxg8DSyJw5iCCzMNJob3EfJxzSMCf
         QMpe9F4lPIUpHEbW3USQfBm3g/gZqqFNqBd3icIZPVbLV9VGcWZwWhQXbZcjkW1aROh5
         QnkUFeDZpqt5WL2uy8EdEAibZGwHQ5hOhlp0xHlSfR6p6syuLr0I/ts5B8xilp32JHx0
         YjRFXj9xs2ZB++WTjmzYUi+UwuXshoX0TOOZkEUGGjF/F1Ag2yHv7SZlSemO3SLdjQVm
         fxOn9s8EzM0z1CNXFhKmSXU9mNlG2yXJ8VbC/VQqdm2xvsMz/Q79UyzBvmDd0sp2YJZv
         6dhA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=irtsiUCUylZGPtSeScUGgZwEzBoaabXmknnY3lf14ec=;
        fh=mcsOkjSKiIVqZTSI0nnbwoKVuIQQbBRaZcAvv5Fi9PY=;
        b=gfNeTouljuxWGpSEun/EniVqqLHUWQ33UsccPfHnHKWuy6hckhYPCgdJTXW+IyyQFF
         Dy/0S/wYP2kMlE0tb9nTQOkroHo3xJKEXFQ18q7mZPJTDEZ1dsUervzl2G/S7dbxHwUg
         bY5eHn6sXHi3ZHeYECmZM9MqM665pgVz7ZWNlVwlHBpE86EzKIch0MjE/RJmul0E/Kkt
         jRS4khMWjLFOY1ev1doPnv+pt0Cb/pJmhPgvdZHfwsZzZZ/NqkhwLZB3UynqF3HKmgOz
         lJ7t9pfWuVIoB6UrKvpJtQd7als2NsgMGf6xGwbo5GPeuV41R/kmNXzI1whp6pzBuPV3
         mv6w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=mWFsj8Uo;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::c2e as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-oo1-xc2e.google.com (mail-oo1-xc2e.google.com. [2607:f8b0:4864:20::c2e])
        by gmr-mx.google.com with ESMTPS id fz5-20020a05622a5a8500b00423e5a4fb24si2333930qtb.0.2023.12.13.15.42.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 13 Dec 2023 15:42:57 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::c2e as permitted sender) client-ip=2607:f8b0:4864:20::c2e;
Received: by mail-oo1-xc2e.google.com with SMTP id 006d021491bc7-59148c1ad35so1154382eaf.2
        for <kasan-dev@googlegroups.com>; Wed, 13 Dec 2023 15:42:57 -0800 (PST)
X-Received: by 2002:a05:6358:99a0:b0:16b:fe18:27fc with SMTP id
 j32-20020a05635899a000b0016bfe1827fcmr10609380rwb.31.1702510976965; Wed, 13
 Dec 2023 15:42:56 -0800 (PST)
MIME-Version: 1.0
References: <20231212232659.18839-1-npache@redhat.com> <CA+fCnZeE1g7F6UDruw-3v5eTO9u_jcROG4Hbndz8Bnr62Opnyg@mail.gmail.com>
 <CAA1CXcBdNd0rSW+oAm24hpEj5SM48XGc2AWagRcSDNv96axQ9w@mail.gmail.com>
In-Reply-To: <CAA1CXcBdNd0rSW+oAm24hpEj5SM48XGc2AWagRcSDNv96axQ9w@mail.gmail.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Thu, 14 Dec 2023 00:42:46 +0100
Message-ID: <CA+fCnZd4-Hx3vOXdBawiSNPrQ+OZ+fhuAmK3f4TLfDWVmDX9Fw@mail.gmail.com>
Subject: Re: [PATCH] kunit: kasan_test: disable fortify string checker on kmalloc_oob_memset
To: Nico Pache <npache@redhat.com>
Cc: linux-kernel@vger.kernel.org, linux-mm@kvack.org, 
	kasan-dev@googlegroups.com, akpm@linux-foundation.org, 
	vincenzo.frascino@arm.com, dvyukov@google.com, glider@google.com, 
	ryabinin.a.a@gmail.com
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=mWFsj8Uo;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::c2e
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Wed, Dec 13, 2023 at 10:42=E2=80=AFPM Nico Pache <npache@redhat.com> wro=
te:
>
> > > diff --git a/mm/kasan/kasan_test.c b/mm/kasan/kasan_test.c
> > > index 8281eb42464b..5aeba810ba70 100644
> > > --- a/mm/kasan/kasan_test.c
> > > +++ b/mm/kasan/kasan_test.c
> > > @@ -493,14 +493,17 @@ static void kmalloc_oob_memset_2(struct kunit *=
test)
> > >  {
> > >         char *ptr;
> > >         size_t size =3D 128 - KASAN_GRANULE_SIZE;
> > > +       size_t size2 =3D 2;
> >
> > Let's name this variable access_size or memset_size. Here and in the
> > other changed tests.
>
> Hi Andrey,
>
> I agree that is a better variable name, but I chose size2 because
> other kasan tests follow the same pattern.

These other tests use size1 and size2 to refer to different sizes of
krealloc allocations, which seems reasonable.

> Please let me know if you still want me to update it given that info
> and I'll send a V2.

Yes, please update the name.

Thank you!

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CA%2BfCnZd4-Hx3vOXdBawiSNPrQ%2BOZ%2BfhuAmK3f4TLfDWVmDX9Fw%40mail.=
gmail.com.
