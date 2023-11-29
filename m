Return-Path: <kasan-dev+bncBDL65RUQNMIMDZU2VMDBUBHOPAYYC@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3f.google.com (mail-oa1-x3f.google.com [IPv6:2001:4860:4864:20::3f])
	by mail.lfdr.de (Postfix) with ESMTPS id C34C17FCD92
	for <lists+kasan-dev@lfdr.de>; Wed, 29 Nov 2023 04:42:58 +0100 (CET)
Received: by mail-oa1-x3f.google.com with SMTP id 586e51a60fabf-1fa1e468769sf5278590fac.1
        for <lists+kasan-dev@lfdr.de>; Tue, 28 Nov 2023 19:42:58 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1701229377; cv=pass;
        d=google.com; s=arc-20160816;
        b=lJ3Pk24Gs9c0t5UUrkqmIOjnL8jL7tIA7FZz3eu6Keip5BfSvcDHuha5KuB/ZI/Z4A
         5SV33M3updWl2mRHJRzdFRMty8c3XIz6kut86O/XhG3d3GzXJYLRgL0lJKvNViO8Pxng
         hEvNPa8sDajs+Ym1WNGwm8oFCGE6Wc/pfjiUnKNQJInnafNbmNzD7ZmlTHd85Zxe+/u0
         3cSy6ao6kZD/Vr54Bc5j1pacBG/ARRZPqNkyY8aCZH21V1Nvdp3QRy1subEWRcBS88iZ
         WuMhuDrdVLDRwkSboPFCWdMjeCVBWsdkxnidyZQ3T9nVuK12DSwqj2HQUDR7lcyVSDAE
         NiKg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :mime-version:references:in-reply-to:message-id:date:subject:cc:to
         :from:dkim-signature;
        bh=ThW6Zih+dT4N7fwjq09Mux1KPkyyXnSIqQlC5neX59U=;
        fh=C3BGX6WzveSruk7xpblocBRdDzA/ZbjAL7CnB2/12Jg=;
        b=euMK3Q8/f9wiSiiKU+TEdEwG5M1BBKAuqv9b1FlD2GGnAgiTm2Cr9W1YLyglxYrSO0
         eEHNySgFDrID3xgI99sAlSaC0iqXTSNaIIn6V1WHWGS0RVyN+mTH2cxyHdy+nweG0v3K
         XVIEdpjPqUOODa68e15Hse6Ki11TrTvYS/VPPA8CSAos6d2KwqlD3Ptx4dq/2E95Kj6T
         6CeIZpn1LDDFZYwyKKMoyJluCDhbZPeGuGB0DYnRotNmRvvXDDR354hi+V0IChWVZMQJ
         /mzqft9B7QhQ2yq/VRYpnxsPFKh1Cc30bb7ABiECtJToFTfbxz3RoNgPlhqz4PrCTjM2
         P9Dw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=hri4SC49;
       spf=pass (google.com: domain of haibo.li@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=haibo.li@mediatek.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1701229377; x=1701834177; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:from:to:cc:subject:date
         :message-id:reply-to;
        bh=ThW6Zih+dT4N7fwjq09Mux1KPkyyXnSIqQlC5neX59U=;
        b=ezvsSDU11irdPcNbepFgfiU6uMXXfxUXwO4kfRnu8wGyQbSjjeYJDdgPdebz3XINTc
         h1WqcX/kLhBnQj1fjU05GryXBqeL4XXy0h5lNHGCujWeoPlJi0k7P5cGF966ZGnUBL1A
         /z0iGItRfy+PU3zQvmFIV9vbidxO4QYzUwC8MHXxqdhg2YwLayYqLj9KrSAXNhvBztaa
         JDaS4TrDTmQscqFe4Zwg1OwqrV+2RbytcC2ffV1skB/YEHMJGLTeCXlokGprzRRFF6TR
         NWHlA8lJnDsE9g3XVtC/I2M1R4XdAo6yLj/KdX/iUVnwAYFtOV4fQaZzIJGGMXXuQzNB
         Qbhg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1701229377; x=1701834177;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=ThW6Zih+dT4N7fwjq09Mux1KPkyyXnSIqQlC5neX59U=;
        b=U6KZz+Ti0g+0aObXPwV4/H6/vnOMe+s9HWcB3+MqslpQqsnIGpmzPAt0XWUZfm5s7x
         Q128SOcxWVkg6NUqgDmv+nyI09kpKgrEvD+TvLzB6XO9Q6jBkp1g0/rpdxERAYpWYyrj
         RD17i1JDbcJDt9pR8FfcuvIUY83K39z+ra4IngigathHdyw+XbHOPHbQOkiJ9EErHVLl
         edH+xQ5QSv8wvG0iaAGqAl05nW8greLDN6Xmr+jwEcgwFlj4qE6buTw2FvQaq+ZK0A49
         dfhJWzZle7AzfdhkQmNPd/GxVWw3uhyu9Cce2McPsjHYbL93ULwOfmWRa5ogX12Vt6MF
         wmTw==
X-Gm-Message-State: AOJu0YyhUFAatdktKOTT/DC/sk08+oSAkGrCZz5f3Cu4odEot3C20Q+u
	ZdKF7WFUmh8lPH9sICFp8U8=
X-Google-Smtp-Source: AGHT+IFG+MkB3ivhwhntkKGx52HVzDHfr/RGs+NrNua0oMnDScBvnGezKg8tiRbbLrOUh3Nd8v2U0Q==
X-Received: by 2002:a05:6871:e70f:b0:1fa:132a:9b00 with SMTP id qa15-20020a056871e70f00b001fa132a9b00mr20730884oac.1.1701229377389;
        Tue, 28 Nov 2023 19:42:57 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6871:3386:b0:1fa:a4a0:84be with SMTP id
 ng6-20020a056871338600b001faa4a084bels126967oac.2.-pod-prod-09-us; Tue, 28
 Nov 2023 19:42:56 -0800 (PST)
X-Received: by 2002:a05:6870:96a1:b0:1f4:d2df:c53c with SMTP id o33-20020a05687096a100b001f4d2dfc53cmr22224286oaq.24.1701229376767;
        Tue, 28 Nov 2023 19:42:56 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1701229376; cv=none;
        d=google.com; s=arc-20160816;
        b=cNQb2ZxnL3MWXvewmirgPT7fLeDkCovfJ5e5+aGkxeXGAJH5hKmkdpYbJrtQNDKpY2
         h+oWQsi/+vnvqX17FOsRGo8mMnHcLeWWeA6CSxSi1siISFsv+Njs521JaufgpZU9BgZ0
         trl1OwP7euFQDFUeZGQBNFKz8wYNemYuUkPXMSi5IcTHe6PsMNLuUXtJS9aHh3UQg9DH
         i+JTlvAYDwpjeZM0H2Ghh4yBt7e7ZB8bZ0+oE6HDMe+1Fl6dUkwiJbfIUYZ8nzfqwUwA
         bxMHf9lxbSEts7rGfAQ6RopwAsNKrJOJwKu2GqwgAPR8UkZ/RhMlLahwYYFUJfeAldk0
         SQHg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=MFrmkl3FpVdv2jTHH29SfVBZoqzJBE5Ed5AoaMdUtQc=;
        fh=C3BGX6WzveSruk7xpblocBRdDzA/ZbjAL7CnB2/12Jg=;
        b=wM8mTVNYAFizGo6Lgc0Go6d4GPhXQhMLjlIETULxJV2VkHem4EIfZlo4Vng2Kk2h+B
         3UgHpC8DtgaChlQ3oQYB5/L5X7ZbkxwkNbmyFxskvGmxwkrSpF2IuMXNrhEx54qL0dVP
         Dgl340HF0Y1vANpt4mAFkZn+4mcmyyk2v5oaQHt+UYlskrRxfRGLzHc2WThum3tQQ4FR
         fW1nQvH4VpanpME6EfMgdUAoboCYim+m5N7L4Hf7tiAZqjuGa3/chXt8wn5Kr80uHluH
         IA7asuLVOkNbQzWA9OahaBbafIDYuErjbDpQY3h5E98KgIbIoaLqG97OHtu9/SrXSSt3
         XSGA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=hri4SC49;
       spf=pass (google.com: domain of haibo.li@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=haibo.li@mediatek.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=mediatek.com
Received: from mailgw02.mediatek.com ([210.61.82.184])
        by gmr-mx.google.com with ESMTPS id w4-20020a9d77c4000000b006d84d3144e4si63041otl.4.2023.11.28.19.42.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 28 Nov 2023 19:42:56 -0800 (PST)
Received-SPF: pass (google.com: domain of haibo.li@mediatek.com designates 210.61.82.184 as permitted sender) client-ip=210.61.82.184;
X-UUID: 5e2ae1268e6911ee8051498923ad61e6-20231129
X-CID-P-RULE: Release_Ham
X-CID-O-INFO: VERSION:1.1.34,REQID:48c3a553-c321-4064-bbc9-c944b9c6db31,IP:0,U
	RL:0,TC:0,Content:0,EDM:0,RT:0,SF:0,FILE:0,BULK:0,RULE:Release_Ham,ACTION:
	release,TS:0
X-CID-META: VersionHash:abefa75,CLOUDID:54083173-1bd3-4f48-b671-ada88705968c,B
	ulkID:nil,BulkQuantity:0,Recheck:0,SF:817|102,TC:nil,Content:0|-5,EDM:-3,I
	P:nil,URL:11|1,File:nil,Bulk:nil,QS:nil,BEC:nil,COL:0,OSI:0,OSA:0,AV:0,LES
	:1,SPR:NO,DKR:0,DKP:0,BRR:0,BRE:0
X-CID-BVR: 1,FCT|NGT
X-CID-BAS: 1,FCT|NGT,0,_
X-CID-FACTOR: TF_CID_SPAM_SNR,TF_CID_SPAM_ULN
X-UUID: 5e2ae1268e6911ee8051498923ad61e6-20231129
Received: from mtkmbs13n1.mediatek.inc [(172.21.101.193)] by mailgw02.mediatek.com
	(envelope-from <haibo.li@mediatek.com>)
	(Generic MTA with TLSv1.2 ECDHE-RSA-AES256-GCM-SHA384 256/256)
	with ESMTP id 1607420559; Wed, 29 Nov 2023 11:42:49 +0800
Received: from mtkmbs13n2.mediatek.inc (172.21.101.108) by
 mtkmbs10n2.mediatek.inc (172.21.101.183) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.2.1118.26; Wed, 29 Nov 2023 11:42:48 +0800
Received: from mszsdtlt102.gcn.mediatek.inc (10.16.4.142) by
 mtkmbs13n2.mediatek.inc (172.21.101.73) with Microsoft SMTP Server id
 15.2.1118.26 via Frontend Transport; Wed, 29 Nov 2023 11:42:48 +0800
From: "'Haibo Li' via kasan-dev" <kasan-dev@googlegroups.com>
To: <andreyknvl@gmail.com>
CC: <akpm@linux-foundation.org>, <angelogioacchino.delregno@collabora.com>,
	<dvyukov@google.com>, <glider@google.com>, <haibo.li@mediatek.com>,
	<kasan-dev@googlegroups.com>, <linux-arm-kernel@lists.infradead.org>,
	<linux-kernel@vger.kernel.org>, <linux-mediatek@lists.infradead.org>,
	<linux-mm@kvack.org>, <lkp@intel.com>, <matthias.bgg@gmail.com>,
	<ryabinin.a.a@gmail.com>, <vincenzo.frascino@arm.com>,
	<xiaoming.yu@mediatek.com>
Subject: Re: [PATCH] fix comparison of unsigned expression < 0
Date: Wed, 29 Nov 2023 11:42:47 +0800
Message-ID: <20231129034247.226365-1-haibo.li@mediatek.com>
X-Mailer: git-send-email 2.34.3
In-Reply-To: <CA+fCnZcLwXn6crGF1E1cY3TknMaUN=H8-_hp0-cC+s8-wj95PQ@mail.gmail.com>
References: <CA+fCnZcLwXn6crGF1E1cY3TknMaUN=H8-_hp0-cC+s8-wj95PQ@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-TM-AS-Product-Ver: SMEX-14.0.0.3152-9.1.1006-23728.005
X-TM-AS-Result: No-10--15.269300-8.000000
X-TMASE-MatchedRID: L8tZF6zWW2q0m/IROg5s5fHkpkyUphL9HTzSJQBZgdFqI8duabhZa/79
	6l+IAtl+w8XU8bLzT9L5qR7J2CotBvww9Stut6YHmNvbnzNu6oLTDXgcUlCNowFbHA9TqNLQmtk
	ZkOzLak8jjoep8ZitK6EZtwWhhaEgAYINegaglbBc/msUC5wFQX4rryovYbmmQ4pQeOTu+8UY20
	f1wrB11n4I3WRiw3QYqULTfmF5uZHqi7LDVhVKr51U1lojafr//5QRvrl2CZCo+b+yOP0oGFC9o
	pMYDUg2585VzGMOFzA9wJeM2pSaRbxAi7jPoeEQftwZ3X11IV0=
X-TM-AS-User-Approved-Sender: No
X-TM-AS-User-Blocked-Sender: No
X-TMASE-Result: 10--15.269300-8.000000
X-TMASE-Version: SMEX-14.0.0.3152-9.1.1006-23728.005
X-TM-SNTS-SMTP: 9998098F6E1CA8C593C63DD30B494B533A460EDFA2BA4999AF9EE84F9D7D46BD2000:8
X-MTK: N
X-Original-Sender: haibo.li@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@mediatek.com header.s=dk header.b=hri4SC49;       spf=pass
 (google.com: domain of haibo.li@mediatek.com designates 210.61.82.184 as
 permitted sender) smtp.mailfrom=haibo.li@mediatek.com;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=mediatek.com
X-Original-From: Haibo Li <haibo.li@mediatek.com>
Reply-To: Haibo Li <haibo.li@mediatek.com>
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

> On Wed, Nov 29, 2023 at 2:22=E2=80=AFAM Andrew Morton <akpm@linux-foundat=
ion.org> wrote:
> >
> > On Tue, 28 Nov 2023 15:55:32 +0800 Haibo Li <haibo.li@mediatek.com> wro=
te:
> >
> > > Kernel test robot reported:
> > >
> > > '''
> > > mm/kasan/report.c:637 kasan_non_canonical_hook() warn:
> > > unsigned 'addr' is never less than zero.
> > > '''
> > > The KASAN_SHADOW_OFFSET is 0 on loongarch64.
> > >
> > > To fix it,check the KASAN_SHADOW_OFFSET before do comparison.
> > >
> > > --- a/mm/kasan/report.c
> > > +++ b/mm/kasan/report.c
> > > @@ -634,10 +634,10 @@ void kasan_non_canonical_hook(unsigned long add=
r)
> > >  {
> > >       unsigned long orig_addr;
> > >       const char *bug_type;
> > > -
> > > +#if KASAN_SHADOW_OFFSET > 0
> > >       if (addr < KASAN_SHADOW_OFFSET)
> > >               return;
> > > -
> > > +#endif
> >
> > We'd rather not add ugly ifdefs for a simple test like this.  If we
> > replace "<" with "<=3D", does it fix?  I suspect that's wrong.
>
> Changing the comparison into "<=3D" would be wrong.
>
> But I actually don't think we need to fix anything here.
>
> This issue looks quite close to a similar comparison with 0 issue
> Linus shared his opinion on here:
>
> https://lore.kernel.org/all/Pine.LNX.4.58.0411230958260.20993@ppc970.osdl=
.org/
>
> I don't know if the common consensus with the regard to issues like
> that changed since then. But if not, perhaps we can treat this kernel
> test robot report as a false positive.
>
> Thanks!

Thanks for the information.Let's keep it as unchanged.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/20231129034247.226365-1-haibo.li%40mediatek.com.
