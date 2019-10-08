Return-Path: <kasan-dev+bncBAABBNGZ6HWAKGQEABHPHXQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x639.google.com (mail-pl1-x639.google.com [IPv6:2607:f8b0:4864:20::639])
	by mail.lfdr.de (Postfix) with ESMTPS id 2FB7BCF7B1
	for <lists+kasan-dev@lfdr.de>; Tue,  8 Oct 2019 13:02:14 +0200 (CEST)
Received: by mail-pl1-x639.google.com with SMTP id f8sf10581235plj.10
        for <lists+kasan-dev@lfdr.de>; Tue, 08 Oct 2019 04:02:14 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1570532532; cv=pass;
        d=google.com; s=arc-20160816;
        b=hZoo8CKHnC7EYTDYnlQLczc5R08/qsuFI37wOK/4jHb+XfUQsmnW2Dibd2Z7aAFmFi
         1jyCsn8fvCWdfjgSgDw9Uc3YA1HiR0ABif87xan0ynmbkh1a+jwdwInbyV1h2DLbhzOZ
         7DUHsM2YZ1wSilNZ9q413bHyexG/CbaKRn9BW/it0Li0Kd3xTJuxrtU4r+1vUPVEvAX3
         xFlvfhmGP+SDCQc/LEKZ80vogm3kOmd0+Of8+KXFj7vOsWEXPh51o0wIo6uDuR/VR7o7
         799PzWu5djA2QtsWN8QoPwcdZi4psOMwaErEOpcGvkl3pPChX5mvMwhajfwWAaYJCfYa
         UJMA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version
         :content-transfer-encoding:references:in-reply-to:date:cc:to:from
         :subject:message-id:sender:dkim-signature;
        bh=qy8Z1CbF+ONJ9FufCi8x4WF0ih+ojJaD1LHWkSeDwhs=;
        b=IK7i1wg9v2JFSIrHJjc2oIoDok7zhAlUVvMQImIWZVWcDhGDDLQRJqM5dLSOyzT4kr
         Co7k/cs2HoTFz8+vUTgH3My7QNZb3NSHJeS1YPpYE11V0ktm6RgOBRcs8WdhgFioaSSV
         4PEOB6jrBWbBNhpk+lnyXpvbqgCS+LwyzE6k9JsDatiWTxpxJ3BPC/1RDfzfSyUcp5vT
         M1n2UQ025nqCK9Y8I5ooONDUSfojg3XDGJRpXJVXjBd/69UKVp5hdJzI858971VpLml1
         tBKLOaAeQoU4xj8He7WWh+Ldb83xrWEVdaFE8A6uqvmYHez14VC1iaqjFD+d/0HfSQiS
         fd4g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:message-id:subject:from:to:cc:date:in-reply-to:references
         :content-transfer-encoding:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=qy8Z1CbF+ONJ9FufCi8x4WF0ih+ojJaD1LHWkSeDwhs=;
        b=Lxnp7IYVs4LnBkLsYsk24XOVoD9sn0cTl4MHuK95lGeU1aYUuYNfjWavgjj8pM+ptJ
         vqC4a2Daru0+tdwZWdlHDwEv7X6uyAjZ0Zg1nrcxH/P/PId5cKTer28UTVmc+Ygunn8Z
         2cybiKCIG2PEfyXFuHuoaoApxe0mBCRS3ujs6VfdAvxsotM9XTHX5PPHXE1ov7t+2FMG
         VHAn2chvDAYnqMfuB47dOnc2Kf/ANOcr92vH6zn/FMFlcjozEVKvO3bdZgQAfIjPOtsi
         DQFM2REzV5KUGaLpTx/Px1ggTo426vkitVI7SAGtevOJIGfJVhbTdhuubZtQhs9sem0Z
         rN9w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:message-id:subject:from:to:cc:date
         :in-reply-to:references:content-transfer-encoding:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=qy8Z1CbF+ONJ9FufCi8x4WF0ih+ojJaD1LHWkSeDwhs=;
        b=Wa1oogJPX4lFqO4TSbnxsot8use1eQ0N+tOt/G7R9hd0/xD7CUu/iYv5X0wZ8nHaHT
         29Ai4zcoP4bBr/kKDqcPD+dvjHw35OZWGB+av4O0hb8mD5/2QX8t33g5l6zChwJcMdFp
         XOe9Nq0I6ms+YBEzUq9ASqhyS6j3shKq0NMaPXm8+r7v2G1QxczfBnm3GX0PL0oyISCY
         QupnSeRLm3RsZDbdCQTwWWWvhIYYYViUe1ZQdsrSiVeieh9GSPdzhDmMff/1t1CpXxAb
         jsCIQAymqeGA8WC8Szl22+wo6xnSmxcROrue46bHQOByJI/r2pDnVmtq/mlVFd1iCDQJ
         y7ww==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAVvuerFLzNfOe0k+xJMl/h02TCJk/v89/UrUm7sTTkBh03A+MSH
	fOb7XlWqF3BJ2gPh+66Ha3Y=
X-Google-Smtp-Source: APXvYqxdB9ReoUjHVVHUNb00T57fB1ABRs+UaSAOZeMKlsH+0NH7XfxlHgN+mbyRz3H/hzY7OtPXAg==
X-Received: by 2002:a17:902:7b84:: with SMTP id w4mr34680011pll.63.1570532532528;
        Tue, 08 Oct 2019 04:02:12 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:5844:: with SMTP id m65ls838359pfb.11.gmail; Tue, 08 Oct
 2019 04:02:12 -0700 (PDT)
X-Received: by 2002:a65:6792:: with SMTP id e18mr4650162pgr.166.1570532532244;
        Tue, 08 Oct 2019 04:02:12 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1570532532; cv=none;
        d=google.com; s=arc-20160816;
        b=0apJCCP2g93oKShRHZXV4iyI8f/+fy1ACkYWR0Ehp3aAP6aDwPhF6etDHzAa2sW5ce
         TBe6LT7B0Mle4UzfsnhDSzdWoKZwYNWsR0TG6LGXDWDTXmuQ5kHWuQcjmnvCK8G8NBEP
         2uUCXR/QJGTZAerTmvegvtEHLPexjwLO7J6oY+QtZ937MEkpG1SJVpgxmAWKHIqMDMIq
         HCLhhoo/eBx6N8wIrWKNcT4ZlZ5U+rXuEIo//IyXQAXVLzEr8cC9n16tJeuhWQR1P+2o
         2kFPOck5DQNiGj3XqaLDjzPpIJkfQ6UjN4NpZwZmR7XSDU04yuKcq5j+B/gHjFExSmyC
         YfyQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:content-transfer-encoding:references:in-reply-to:date
         :cc:to:from:subject:message-id;
        bh=niXLb4WE6D3jywSURJlr6nYe9PpS7j6WSx/C8tajXLg=;
        b=XIDBJNROtsVUsBoUIK3jwqQIOjyUj/rH9m8A8UDl29ir7tlx5BbioIeXAQj2/7oKo+
         mVuM8N45oi6/OoqaH336RnZaIiKyVaXfXQp6EuqO6N32F/x3xjwI6Y6Ax4uXjkuctNif
         eG4+j7TKzNsIKzW8jD1rByuEYfmlpf4VuRwVdcpoGAK8ppihvEeZ6PBYu8QcXMeeaLOM
         aTcWLRlMGN3oVoovED3XO7iY5OMGkx9Dl0Hy6S4Ck30i1uLj9ItNopMA1dI2NkYuHJJl
         YkRzdnMX05iYeegGYe5SaQFUhObv9kOL87+UkT2YP3CTbu83wqytce6iL/y0k8ZTd5yo
         ic2A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw02.mediatek.com ([210.61.82.184])
        by gmr-mx.google.com with ESMTP id x197si1423949pgx.5.2019.10.08.04.02.11
        for <kasan-dev@googlegroups.com>;
        Tue, 08 Oct 2019 04:02:12 -0700 (PDT)
Received-SPF: pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) client-ip=210.61.82.184;
X-UUID: 814ed363ca79487d969aaa2a5840218c-20191008
X-UUID: 814ed363ca79487d969aaa2a5840218c-20191008
Received: from mtkcas07.mediatek.inc [(172.21.101.84)] by mailgw02.mediatek.com
	(envelope-from <walter-zh.wu@mediatek.com>)
	(Cellopoint E-mail Firewall v4.1.10 Build 0809 with TLS)
	with ESMTP id 2095119737; Tue, 08 Oct 2019 19:02:09 +0800
Received: from mtkcas08.mediatek.inc (172.21.101.126) by
 mtkmbs07n2.mediatek.inc (172.21.101.141) with Microsoft SMTP Server (TLS) id
 15.0.1395.4; Tue, 8 Oct 2019 19:02:07 +0800
Received: from [172.21.84.99] (172.21.84.99) by mtkcas08.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1395.4 via Frontend
 Transport; Tue, 8 Oct 2019 19:02:07 +0800
Message-ID: <1570532528.4686.102.camel@mtksdccf07>
Subject: Re: [PATCH] kasan: fix the missing underflow in memmove and memcpy
 with CONFIG_KASAN_GENERIC=y
From: Walter Wu <walter-zh.wu@mediatek.com>
To: Qian Cai <cai@lca.pw>
CC: Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin
	<aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, Matthias
 Brugger <matthias.bgg@gmail.com>, LKML <linux-kernel@vger.kernel.org>,
	kasan-dev <kasan-dev@googlegroups.com>, Linux-MM <linux-mm@kvack.org>, Linux
 ARM <linux-arm-kernel@lists.infradead.org>,
	<linux-mediatek@lists.infradead.org>, wsd_upstream
	<wsd_upstream@mediatek.com>
Date: Tue, 8 Oct 2019 19:02:08 +0800
In-Reply-To: <B53A3CC0-CEA6-4E1C-BC38-19315D949F38@lca.pw>
References: <1570515358.4686.97.camel@mtksdccf07>
	 <B53A3CC0-CEA6-4E1C-BC38-19315D949F38@lca.pw>
Content-Type: text/plain; charset="UTF-8"
X-Mailer: Evolution 3.2.3-0ubuntu6
Content-Transfer-Encoding: quoted-printable
MIME-Version: 1.0
X-MTK: N
X-Original-Sender: walter-zh.wu@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as
 permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
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

On Tue, 2019-10-08 at 05:47 -0400, Qian Cai wrote:
>=20
> > On Oct 8, 2019, at 2:16 AM, Walter Wu <walter-zh.wu@mediatek.com> wrote=
:
> >=20
> > It is an undefined behavior to pass a negative numbers to
> >    memset()/memcpy()/memmove(), so need to be detected by KASAN.
>=20
> Why can=E2=80=99t this be detected by UBSAN?

I don't know very well in UBSAN, but I try to build ubsan kernel and
test a negative number in memset and kmalloc_memmove_invalid_size(), it
look like no check.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/1570532528.4686.102.camel%40mtksdccf07.
