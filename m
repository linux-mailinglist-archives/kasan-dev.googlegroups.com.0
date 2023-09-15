Return-Path: <kasan-dev+bncBAABB7OMSCUAMGQEJIPZSOI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3b.google.com (mail-yb1-xb3b.google.com [IPv6:2607:f8b0:4864:20::b3b])
	by mail.lfdr.de (Postfix) with ESMTPS id A6F7B7A1AD4
	for <lists+kasan-dev@lfdr.de>; Fri, 15 Sep 2023 11:40:14 +0200 (CEST)
Received: by mail-yb1-xb3b.google.com with SMTP id 3f1490d57ef6-d818fb959f4sf1986090276.1
        for <lists+kasan-dev@lfdr.de>; Fri, 15 Sep 2023 02:40:14 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1694770813; cv=pass;
        d=google.com; s=arc-20160816;
        b=QE4IGZW5ko70/OoCOuDsHXQl5C5Fc/y1A+yK7M31Elcc/+5uWTa/F+FtR5lYnlHSAv
         dYAvXvq7ReGner6ehsyneWkIC8pH5cIkjmjj6B6fn8Wrq7aUo3Bh9OokzCDaUE9/XEdu
         RIzKv2ptX+sT/7U0emHxM3fCzjr50jAR8myGzaLY6JaHtU3T/Ibm8NCKyYwth1VRkg/V
         DNGz2jTND/TC7J2C4lt/86dqPsnNtUMPCzgxibXu6o5Q6w+d4wAxQyxNVgmXzI7O+mkh
         bBZPI1DWZvHWN/uFO1CiEqvSqgAOPdImKrdPoLWOYsMe6+5Th3bcahIugZ1n12IjlOpj
         sa0g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :mime-version:references:in-reply-to:message-id:date:subject:cc:to
         :from:dkim-signature;
        bh=v1prxuLdf+29ZCNZ8KYUXVZCx/I5R07CV+++4mQU9Vc=;
        fh=9W6fMjLKHGrquBIRDKUoF2po9JTlKPgy7nmb88Wy/eo=;
        b=tLzGrgnRb2MDXfQynQ2OO221SLtaKYerbz/tz9X7JQ2Re40rQjkIuMXXYs5+Mh1cVc
         hNN5Bi2q5DB2u/1Ld5zPqFbYTn+nkt8WPL/9Va+xhOY4hmd8IsUVY8TZp/4PzixyI24a
         an3nud24Ug/+nxLjiq06DE8vw1Hgc+2d4IvpBQkORYwCPs8sZO0TC3TCtOwA3yt7GChf
         BcGitawrKuYTM+ThvwRtJ3BZ3/1Pn6tVIATrK6nvd1vstryDHzNN+n/fROOf5xUEOThx
         453V9Rjwl+etPYIaX5pRCmsLf/PSLirouyDc8rYB1BkyBBxvnDphSByhGQyjT6gOW2x+
         lRCw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=MM3euV1t;
       spf=pass (google.com: domain of haibo.li@mediatek.com designates 60.244.123.138 as permitted sender) smtp.mailfrom=haibo.li@mediatek.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1694770813; x=1695375613; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:from:to:cc:subject:date
         :message-id:reply-to;
        bh=v1prxuLdf+29ZCNZ8KYUXVZCx/I5R07CV+++4mQU9Vc=;
        b=FpLeC1B2DOM65di+DlJ3F/N2bOE6K0S07GGdLuCnaK94uVKiyeTm1cJcwUdAwZRM5y
         CJRNtu0JcdrCdcSaAvJgnokjdINgyCLOaM5SBBm0yL8zyRXt5oGmog1ZK6ahBhRRHiZ6
         5kECPYzEyt8uxnl8wLzdH6FE2Va+yqSS9KVOwT47jconrBcKVBIChPJye/ZXXmzvBmp8
         n/aBmyBoo2JeD2k/ZmP42sb01IYdTaFrMPumAFRhiDLtwwTJqCmeOwnf34yMZhb3DWCY
         3i8+4DwIRtu9CNszkznlejvM6C/rEvdE+dIB637BIizzDzCGpZfM54tFfx+t4eAGmZbn
         mmWw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1694770813; x=1695375613;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=v1prxuLdf+29ZCNZ8KYUXVZCx/I5R07CV+++4mQU9Vc=;
        b=CREzzN/CSONcVOjRXLdPKbCd9Y9v4Vg19PViLZIIxad8guRrBbmX0MX/L/XxxJz0xj
         SXxaKMvWX0VzEs7OkY+VhFwtwRgfRHtp0zITIq8w8AFIuNcTTsb+/MdI64MEdTki2zxr
         ycSt239vRBU8hPSKC+gsOyz2cGBp2njQGZROW1vlqKXq7isDakEbtbkTked0HmaolW7l
         Bx5qehWc80XyZ8suol78tctlj45NIc3IhMvcyL1iWRe7XeNtNqWvb0H4eDmlG1Q1PMCK
         DszhOIzPyM3EmbvuofyIGuBRivv0Fel2RrjPpc0A4DQKIXkZe05X8DxHpDstNxBPBKwE
         qQEw==
X-Gm-Message-State: AOJu0YxyLN6O7+rNT6fLz/ArtClCFxcANXChaXfUvvZpdSYgSdfWje0S
	59aj5FKN2opOIjvMiyM+LMg=
X-Google-Smtp-Source: AGHT+IFyhdgMraG4rH8H4HiGSOymUgOC1cwrtLVrzLJEPR73SDa6bXa80nD0VFKukKr6580qEO63TQ==
X-Received: by 2002:a25:41ca:0:b0:d4d:f8f4:e409 with SMTP id o193-20020a2541ca000000b00d4df8f4e409mr863998yba.57.1694770813252;
        Fri, 15 Sep 2023 02:40:13 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:cb56:0:b0:d81:a379:3087 with SMTP id b83-20020a25cb56000000b00d81a3793087ls60298ybg.2.-pod-prod-07-us;
 Fri, 15 Sep 2023 02:40:12 -0700 (PDT)
X-Received: by 2002:a0d:e695:0:b0:59b:d391:eb71 with SMTP id p143-20020a0de695000000b0059bd391eb71mr1107729ywe.11.1694770812456;
        Fri, 15 Sep 2023 02:40:12 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1694770812; cv=none;
        d=google.com; s=arc-20160816;
        b=NaVfbNyPdnx/IYC0+16pJCw32sKaqLxwIG6sHFqb411Kvte9f5zqhSJSfOba6eg5sM
         14B22utBR8x3i0xNN0jQJe91V4nSiOkhCcbPU7YzNFsSnnXS7RFBJ2g3F4P78zdlX5Z+
         qPEFNyZ0Bno7nhU3BcpVtI9GJ3qf9ZHZqVbyo/h4G/wb1LJWGu3N3TVCpfD0o7nCdp9Z
         t/Yabubnm1WtgLjohJSecyMFtiVxdmnPWD0f9bDRPF0hgdENbwvEufZsdKpmiS5wFBLy
         mUG1MRHTYfkH5qSkTv46SVPnuO8VxxE5vH8oYGFPE03Jpi0jgTjbcS0s2grMp/2bh6D9
         aRpA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=1OuoRlRhal85zHHNkvOTaN3Ke5AHVAChxHwJa2fHozc=;
        fh=9W6fMjLKHGrquBIRDKUoF2po9JTlKPgy7nmb88Wy/eo=;
        b=zdSAZSKLiN9/SGJTUODp8j3jfR+Arr/K04rqIIZj71k+T7i+fJ8h3GfJG7hyuFU8gb
         w5KWGxDCekQmIMZtIhPyRKO4EqiiTGsdVhmd7Iiu3VnLAZhMaQ6qS/S4AgDPYsgLexoR
         h0aDT8bf9v+jt9bh3y2YmWpi+P0T64RIDwNf26gIiMR2DWrJeExaCPJGgF1rENCofXnz
         hqtwQEjWB/2NaXXiG9N4fB5xev0T0oCc/W+J5CYNcQTWzQGt+JmxeroWE8Gd8zjPQmsH
         axPZIvdejb5TsbA4isIiD/6nCrLr7tBGAdRT1rk1QAtERKHv1mPZNXlFmEHwFiZ/j+tj
         RtVw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=MM3euV1t;
       spf=pass (google.com: domain of haibo.li@mediatek.com designates 60.244.123.138 as permitted sender) smtp.mailfrom=haibo.li@mediatek.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=mediatek.com
Received: from mailgw01.mediatek.com ([60.244.123.138])
        by gmr-mx.google.com with ESMTPS id r85-20020a819a58000000b00594e93a8b11si396467ywg.1.2023.09.15.02.40.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 15 Sep 2023 02:40:12 -0700 (PDT)
Received-SPF: pass (google.com: domain of haibo.li@mediatek.com designates 60.244.123.138 as permitted sender) client-ip=60.244.123.138;
X-UUID: da8d3ac853ab11eea33bb35ae8d461a2-20230915
X-CID-P-RULE: Release_Ham
X-CID-O-INFO: VERSION:1.1.31,REQID:22c0bd65-c731-4d9e-bcf0-de69c4a8e593,IP:0,U
	RL:0,TC:0,Content:0,EDM:0,RT:0,SF:0,FILE:0,BULK:0,RULE:Release_Ham,ACTION:
	release,TS:0
X-CID-META: VersionHash:0ad78a4,CLOUDID:ce0bbdef-9a6e-4c39-b73e-f2bc08ca3dc5,B
	ulkID:nil,BulkQuantity:0,Recheck:0,SF:817|102,TC:nil,Content:0|-5,EDM:-3,I
	P:nil,URL:0,File:nil,Bulk:nil,QS:nil,BEC:nil,COL:0,OSI:0,OSA:0,AV:0,LES:1,
	SPR:NO,DKR:0,DKP:0,BRR:0,BRE:0
X-CID-BVR: 1,FCT|NGT
X-CID-BAS: 1,FCT|NGT,0,_
X-CID-FACTOR: TF_CID_SPAM_SNR
X-UUID: da8d3ac853ab11eea33bb35ae8d461a2-20230915
Received: from mtkmbs11n1.mediatek.inc [(172.21.101.185)] by mailgw01.mediatek.com
	(envelope-from <haibo.li@mediatek.com>)
	(Generic MTA with TLSv1.2 ECDHE-RSA-AES256-GCM-SHA384 256/256)
	with ESMTP id 1770198016; Fri, 15 Sep 2023 17:40:06 +0800
Received: from mtkmbs13n1.mediatek.inc (172.21.101.193) by
 mtkmbs13n2.mediatek.inc (172.21.101.108) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.2.1118.26; Fri, 15 Sep 2023 17:40:04 +0800
Received: from mszsdtlt101.gcn.mediatek.inc (10.16.4.141) by
 mtkmbs13n1.mediatek.inc (172.21.101.73) with Microsoft SMTP Server id
 15.2.1118.26 via Frontend Transport; Fri, 15 Sep 2023 17:40:04 +0800
From: "'Haibo Li' via kasan-dev" <kasan-dev@googlegroups.com>
To: <haibo.li@mediatek.com>
CC: <akpm@linux-foundation.org>, <andreyknvl@gmail.com>,
	<angelogioacchino.delregno@collabora.com>, <dvyukov@google.com>,
	<glider@google.com>, <jannh@google.com>, <kasan-dev@googlegroups.com>,
	<linux-arm-kernel@lists.infradead.org>, <linux-kernel@vger.kernel.org>,
	<linux-mediatek@lists.infradead.org>, <linux-mm@kvack.org>,
	<mark.rutland@arm.com>, <matthias.bgg@gmail.com>, <ryabinin.a.a@gmail.com>,
	<vincenzo.frascino@arm.com>, <xiaoming.yu@mediatek.com>
Subject: Re: [PATCH] kasan:fix access invalid shadow address when input is illegal
Date: Fri, 15 Sep 2023 17:40:04 +0800
Message-ID: <20230915094004.113104-1-haibo.li@mediatek.com>
X-Mailer: git-send-email 2.34.3
In-Reply-To: <20230915024559.32806-1-haibo.li@mediatek.com>
References: <20230915024559.32806-1-haibo.li@mediatek.com>
MIME-Version: 1.0
Content-Transfer-Encoding: quoted-printable
Content-Type: text/plain; charset="UTF-8"
X-MTK: N
X-Original-Sender: haibo.li@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@mediatek.com header.s=dk header.b=MM3euV1t;       spf=pass
 (google.com: domain of haibo.li@mediatek.com designates 60.244.123.138 as
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

> > On Thu, Sep 14, 2023 at 10:41=C3=A2=E2=82=AC=C2=AFPM Jann Horn <jannh@g=
oogle.com> wrote:

> > >

> > > > Accessing unmapped memory with KASAN always led to a crash when

> > > > checking shadow memory. This was reported/discussed before. To impr=
ove

> > > > crash reporting for this case, Jann added kasan_non_canonical_hook =
and

> > > > Mark integrated it into arm64. But AFAIU, for some reason, it stopp=
ed

> > > > working.

> > > >

> > > > Instead of this patch, we need to figure out why

> > > > kasan_non_canonical_hook stopped working and fix it.

> > > >

> > > > This approach taken by this patch won't work for shadow checks adde=
d

> > > > by compiler instrumentation. It only covers explicitly checked

> > > > accesses, such as via memcpy, etc.

> > >

> > > FWIW, AFAICS kasan_non_canonical_hook() currently only does anything

> > > under CONFIG_KASAN_INLINE;

> >=20

> > Ah, right. I was thinking about the inline mode, but the patch refers

> > to the issue with the outline mode.

> >=20

> > However, I just checked kasan_non_canonical_hook for SW_TAGS with the

> > inline mode: it does not work when accessing 0x42ffffb80aaaaaaa, the

> > addr < KASAN_SHADOW_OFFSET check fails. It appears there's something

> > unusual about how instrumentation calculates the shadow address. I

> > didn't investigate further yet.

Sorry to miss this message.

I checked inline mode just now.kasan_non_canonical_hook can print=20

something like below:

Unable to handle kernel paging request at virtual address ffffffb80aaaaaaa

KASAN: maybe wild-memory-access in range [0xffffff80aaaaaaa0-0xffffff80aaaa=
aaaf]

...

[ffffffb80aaaaaaa] pgd=3D000000005d3d6003, p4d=3D000000005d3d6003, pud=3D00=
0000005d3d6003,

pmd=3D0000000000000000

...

pc : __hwasan_check_x20_67043363+0x4/0x34

lr : do_ib_ob+0x108/0x114

...

Call trace:

 __hwasan_check_x20_67043363+0x4/0x34

 die_selftest+0x68/0x80

 param_attr_store+0xec/0x164

 module_attr_store+0x34/0x4c

 sysfs_kf_write+0x78/0x8c

 kernfs_fop_write_iter+0x154/0x214

 vfs_write+0x36c/0x4c4

 ksys_write+0x98/0x110

 __arm64_sys_write+0x3c/0x48

 invoke_syscall+0x58/0x154

 el0_svc_common+0xe8/0x120

 do_el0_svc_compat+0x2c/0x38

 el0_svc_compat+0x34/0x84

 el0t_32_sync_handler+0x78/0xb4

 el0t_32_sync+0x194/0x198



When addr < KASAN_SHADOW_OFFSET meets,the original addr_has_metadata should=
 return false

and trigger kasan_report in kasan_check_range.

> >=20

> > > I think the idea when I added that was that

> > > it assumes that when KASAN checks an access in out-of-line

> > > instrumentation or a slowpath, it will do the required checks to avoi=
d

> > > this kind of fault?

> >=20

> > Ah, no, KASAN doesn't do it.

> >=20

> > However, I suppose we could add what the original patch proposes for

> > the outline mode. For the inline mode, it seems to be pointless, as

> > most access checks happen though the compiler inserted code anyway.

> >=20

> > I also wonder how much slowdown this patch will introduce.

> >=20

> > Haibo, could you check how much slower the kernel becomes with your

> > patch? If possible, with all GENERIC/SW_TAGS and INLINE/OUTLINE

> > combinations.

> >=20

> > If the slowdown is large, we can just make kasan_non_canonical_hook

> > work for both modes (and fix it for SW_TAGS).

>=20

> Thanks.

> The patch checks each shadow address,so it introduces extra overhead.

> Now kasan_non_canonical_hook only works for CONFIG_KASAN_INLINE.

> And CONFIG_KASAN_OUTLINE is set in my case.

> Is it possible to make kasan_non_canonical_hook works for both=20

> INLINE and OUTLINE by simply remove the "#ifdef CONFIG_KASAN_INLINE"?

> Since kasan_non_canonical_hook is only used after kernel fault,it=20

> is better if there is no limit.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/20230915094004.113104-1-haibo.li%40mediatek.com.
