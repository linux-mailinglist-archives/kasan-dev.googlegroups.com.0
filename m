Return-Path: <kasan-dev+bncBAABBDENUCUAMGQEPGWJU3Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13d.google.com (mail-il1-x13d.google.com [IPv6:2607:f8b0:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id 0E03C7A4420
	for <lists+kasan-dev@lfdr.de>; Mon, 18 Sep 2023 10:13:02 +0200 (CEST)
Received: by mail-il1-x13d.google.com with SMTP id e9e14a558f8ab-34fc05464f6sf24810265ab.2
        for <lists+kasan-dev@lfdr.de>; Mon, 18 Sep 2023 01:13:01 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1695024780; cv=pass;
        d=google.com; s=arc-20160816;
        b=jLOg/0VLPveen6HgbBY7hzFVxLQKzgJGGUytdErngCNbIHTfBCKO9lyo4RmAi3AE34
         ePQT5CkENeocouPTguMYqBbv5HxgiaOY/BjnyMGtOZ/gQWvtWSiQgztnx+bo21Kt5Mtx
         JusjFoCKNZcNFqIBpA2oNcfweMhUlDI2uqmDLnWFdFGxfxDf2xn++oNDOCvXVC4I1MWE
         5hrig2oOjOhc29932icFhuFMNK67NNcSrCIADaGk5rT0o/iIC5H96lUWAHb3jM4IS6eC
         ldbiWalpXrm6atonScxBqhQlo8NLWQDLkqSvXshlP5Yzpubgda66XutkLwXwy0qfV+Cv
         krOw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=PEFbCMV28BVzKGngA4hg83Wb065M8Rbi7Qvl2ZURH/w=;
        fh=quWeMy9LUQERXE1LL/Ay2SAkvxBaX4iLTgIQ431JY+I=;
        b=yAoSCEbgm5/EnX3PKuoQvsZq0yrbj9zdVkfse6/U+GjLPFVh4IIz0eiXtoKWXvfXpG
         7aQ7OZt6fqas/t9WEx96mr3d1vw06QrZ2xG/pfdscBjuq0APJVQgDpQ6XqgLJE8F0IMD
         ReZqMiBFEk6HfHUJ0aSsc9CN5euyerxR4mRcM4kkt2PvBXz79+dKYMtFTNh0e09I45Y0
         IJOmxQ/sRymMpIdaBiWRSbCXUXtbnIoj3j1KFPhCpBneD+/An/CAc/zrtzKAmTTzqW89
         265lD7HKLqjEFCc0GwRKijZii69mtMrCnYYiNCVYXt82L7kxBA2QP0yaEbbbWLCPHQ43
         SByg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=afTrg5B8;
       spf=pass (google.com: domain of haibo.li@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=haibo.li@mediatek.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1695024780; x=1695629580; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=PEFbCMV28BVzKGngA4hg83Wb065M8Rbi7Qvl2ZURH/w=;
        b=IUTrxDNoGlY0Q7yYNty2o1FZySk/NyouzY2kbSYrnsYHzUghAZd26A2hYNCZQte6N7
         RnkKxNobZKkwB87CKcE7bSiLKHncbGAny72cW++pSI5HtH//4jI5YDTN993DhWB91DZR
         KMI9DEx07oezGEH3CoBzwfShQeSD21q/Ctd54UBWHPLsPEEJoQyLAyBdNRupLqZprK5D
         HU6OdnnRH9i/Qo3PBvxA13IWQrV+BjGFbZZHjtQwQDQLEIy9MWFo2uM9wB5QMUxB2bF4
         t2EkgcoKPThKvpPsxbWJzZAvxZr5c/C1uOA6rbUqV194qiVYod+e3FW9NfdWY6W0JKlw
         cG5Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1695024780; x=1695629580;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=PEFbCMV28BVzKGngA4hg83Wb065M8Rbi7Qvl2ZURH/w=;
        b=HQKo8l0BkWk27kl55Zm506f8rCnfoHlwV6VqhlF0w0XAETA7hUeoatK6TVQV5BuRZl
         /ErpIoUa6dzUMqN3DC7QdzEyLBSCXADhOSwSY68N8fgWVkpKokq9UTpGUGOviFQoAf7h
         iNE2RMycbqIaGFEstMKBuHCuopWIHoF/DpNaEnpMcd5PIhHrcydIq6T71NJgnhWGsq6U
         JkzvabuCiEUjrZ1TCYCAar6ArGgAIEVHdrkdJcB78NgT8MNNLcdGQ/Mrd/YOExfhwTf9
         zAXg3h5CodR4D0ydaSL+FRT8P/bVe09/3IUNnBck0cDgOnTBaXl4y4y5IUl0WZkgYISX
         bqXA==
X-Gm-Message-State: AOJu0Yx5YSaAM34oHaPP4Pkd16B7ciBmTzyQCYgV6O5vtCFN7ChvIt1O
	j+0KhAMwBQpRyOdAqskT2A4=
X-Google-Smtp-Source: AGHT+IHnqaLvUnFmOuTXHJ8vVzB/mXuqCwd0urIpILj3JfGZ2um+juJfGdlFvFNF73tRG/sXxC+P8w==
X-Received: by 2002:a92:dc42:0:b0:34f:d9db:66c4 with SMTP id x2-20020a92dc42000000b0034fd9db66c4mr4662007ilq.30.1695024780659;
        Mon, 18 Sep 2023 01:13:00 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:bd06:0:b0:349:3346:c3e0 with SMTP id c6-20020a92bd06000000b003493346c3e0ls405599ile.1.-pod-prod-09-us;
 Mon, 18 Sep 2023 01:13:00 -0700 (PDT)
X-Received: by 2002:a05:6e02:14c1:b0:34f:70ec:d4cf with SMTP id o1-20020a056e0214c100b0034f70ecd4cfmr10534224ilk.8.1695024779966;
        Mon, 18 Sep 2023 01:12:59 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1695024779; cv=none;
        d=google.com; s=arc-20160816;
        b=uNT3fuqF4PRd5UnyRWvRaiYqq56Ho3Mf51KBp2k9UAkMHVTFAyjjECmrxeJFgxX9Sw
         HIwpyXarSoGaCfKLkErqdw0OvvOys8K0HRPmvEiTdfNOYVaqdqtXneL0jGexk+7TjiQX
         F9avr1UFUVXzvCO/tahukZuQxMEvHvaW7ZBIboIkrbXEUDmsIrQD1HnEW2911UaBNWcx
         QrmFjJDGfCJL1miRuI/Sn21J16T9yq+32CFaKh/rXTRtWXWWgoCHAJy6e0ezlh99Om7k
         O3AM4T8hVhqqgpsgAjciwYmhEu9SdkkUvEz6ztU0kGABUnLPaW0jPjofcS1G40mV+acN
         myXg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=kqnvu8e5BxdxEQxTzumthghfrEuZ7r4SRpLOXCrpQuo=;
        fh=quWeMy9LUQERXE1LL/Ay2SAkvxBaX4iLTgIQ431JY+I=;
        b=RUmEQ2bCVIuXvVuoHJXOSP0xh/VGL/2GeUs0cW8vl9XfTIU/JCSrMcvSrT9nOZb/bp
         XR6v2MFQQSSUWAHR83X/NPqMd7C/hxRN4XXbezkIrpqIhFau7jJzUImEqFWsa0roZC1b
         arrwdvXTPzSJi6VDjRTrAa778Jzm0n53rmq3MOjk3GO2tlg0GlkJEHMIGCF0pLljYncG
         S4uNg0OMA4wBk99z7m07vkpaSXi5FfLIG4F5Ko6a0p4CW4ltO6QYgq6Thz7cxXay5RLO
         wQjXo6rm392NSM4SaMcgeV/Ptr7iS0ZCIP29Zzjizpsi8+T8fvmuibT1msmZif+mXMeH
         V3bQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=afTrg5B8;
       spf=pass (google.com: domain of haibo.li@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=haibo.li@mediatek.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=mediatek.com
Received: from mailgw02.mediatek.com ([210.61.82.184])
        by gmr-mx.google.com with ESMTPS id h1-20020a02cd21000000b00430a46a98a8si1322190jaq.5.2023.09.18.01.12.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 18 Sep 2023 01:12:59 -0700 (PDT)
Received-SPF: pass (google.com: domain of haibo.li@mediatek.com designates 210.61.82.184 as permitted sender) client-ip=210.61.82.184;
X-UUID: 2a4b6dfe55fb11ee8051498923ad61e6-20230918
X-CID-CACHE: Type:Local,Time:202309181525+08,HitQuantity:1
X-CID-P-RULE: Release_Ham
X-CID-O-INFO: VERSION:1.1.31,REQID:174f19b8-8a83-47d6-a4cb-e9ebe732735d,IP:0,U
	RL:0,TC:0,Content:0,EDM:0,RT:0,SF:0,FILE:0,BULK:0,RULE:Release_Ham,ACTION:
	release,TS:0
X-CID-META: VersionHash:0ad78a4,CLOUDID:c600d2ef-9a6e-4c39-b73e-f2bc08ca3dc5,B
	ulkID:nil,BulkQuantity:0,Recheck:0,SF:817|102,TC:nil,Content:0|-5,EDM:-3,I
	P:nil,URL:0,File:nil,Bulk:nil,QS:nil,BEC:nil,COL:0,OSI:0,OSA:0,AV:0,LES:1,
	SPR:NO,DKR:0,DKP:0,BRR:0,BRE:0
X-CID-BVR: 1,FCT|NGT
X-CID-BAS: 1,FCT|NGT,0,_
X-CID-FACTOR: TF_CID_SPAM_SNR
X-UUID: 2a4b6dfe55fb11ee8051498923ad61e6-20230918
Received: from mtkmbs10n1.mediatek.inc [(172.21.101.34)] by mailgw02.mediatek.com
	(envelope-from <haibo.li@mediatek.com>)
	(Generic MTA with TLSv1.2 ECDHE-RSA-AES256-GCM-SHA384 256/256)
	with ESMTP id 109002278; Mon, 18 Sep 2023 16:12:52 +0800
Received: from mtkmbs13n2.mediatek.inc (172.21.101.108) by
 MTKMBS14N1.mediatek.inc (172.21.101.75) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.2.1118.26; Mon, 18 Sep 2023 16:12:51 +0800
Received: from mszsdtlt102.gcn.mediatek.inc (10.16.4.142) by
 mtkmbs13n2.mediatek.inc (172.21.101.73) with Microsoft SMTP Server id
 15.2.1118.26 via Frontend Transport; Mon, 18 Sep 2023 16:12:51 +0800
From: "'Haibo Li' via kasan-dev" <kasan-dev@googlegroups.com>
To: <jannh@google.com>
CC: <akpm@linux-foundation.org>, <andreyknvl@gmail.com>,
	<angelogioacchino.delregno@collabora.com>, <dvyukov@google.com>,
	<glider@google.com>, <haibo.li@mediatek.com>, <kasan-dev@googlegroups.com>,
	<linux-arm-kernel@lists.infradead.org>, <linux-kernel@vger.kernel.org>,
	<linux-mediatek@lists.infradead.org>, <linux-mm@kvack.org>,
	<mark.rutland@arm.com>, <matthias.bgg@gmail.com>, <ryabinin.a.a@gmail.com>,
	<vincenzo.frascino@arm.com>, <xiaoming.yu@mediatek.com>
Subject: Re: [PATCH] kasan:fix access invalid shadow address when input is illegal
Date: Mon, 18 Sep 2023 16:12:50 +0800
Message-ID: <20230918081250.143237-1-haibo.li@mediatek.com>
X-Mailer: git-send-email 2.34.3
In-Reply-To: <CAG48ez3GSubTFA8+hw=YDZoVHC79JVwNi+xFTQt9ssy_+O1aaw@mail.gmail.com>
References: <CAG48ez3GSubTFA8+hw=YDZoVHC79JVwNi+xFTQt9ssy_+O1aaw@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-TM-AS-Product-Ver: SMEX-14.0.0.3152-9.1.1006-23728.005
X-TM-AS-Result: No-10--15.802200-8.000000
X-TMASE-MatchedRID: HXSqh3WYKfs4HKI/yaqRmya1MaKuob8PfjJOgArMOCZb6PBUqmq+Uq7d
	jM7nXzpjKDVpUrn+OoQmNpzri1sed7Ud2R7XKvn3dAg4yd14qARUXmZR3qwgxiS30GKAkBxWqjK
	1cw/inhPUdOHHz4uZ2bNVqZo4wx+HlOGdJawUY9voGS5BmR0KUThaxI2If9ReK7S6qybDnxlvKp
	xZPgVlFySl042qLBGShRAr0eCrd7QLd3u89FoqUbiMC5wdwKqdvtVce6w5+K/US7RV+C9GRaPFj
	JEFr+olwXCBO/GKkVqOhzOa6g8KrZRMZUCEHkRt
X-TM-AS-User-Approved-Sender: No
X-TM-AS-User-Blocked-Sender: No
X-TMASE-Result: 10--15.802200-8.000000
X-TMASE-Version: SMEX-14.0.0.3152-9.1.1006-23728.005
X-TM-SNTS-SMTP: 526554D9131F0E7FF150090659C59FFAFE008B7EB75342DF66FB39481924F4332000:8
X-MTK: N
X-Original-Sender: haibo.li@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@mediatek.com header.s=dk header.b=afTrg5B8;       spf=pass
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

> On Fri, Sep 15, 2023 at 6:51 PM Andrey Konovalov <andreyknvl@gmail.com> wrote:
> > On Fri, Sep 15, 2023 at 4:46 AM 'Haibo Li' via kasan-dev
> > <kasan-dev@googlegroups.com> wrote:
> > >
> > > The patch checks each shadow address,so it introduces extra overhead.
> >
> > Ack. Could still be fine, depends on the overhead.
> >
> > But if the message printed by kasan_non_canonical_hook is good enough
> > for your use case, I would rather stick to that.
If we check shadow address before invalid access,
we get below message before oops:
"
BUG: KASAN: invalid-access in do_ib_ob+0xf4/0x110
Read of size 8 at addr caffff80aaaaaaaa by task sh/100
"

We get below message while using kasan_non_canonical_hook:
"
Unable to handle kernel paging request at virtual address ffffff80aaaaaaaa
KASAN: maybe wild-memory-access in range [0xfffffc0aaaaaaaa0-0xfffffc0aaaaaaaaf]
"

Both indicate the original accessed address which causes oops.

> >
> > > Now kasan_non_canonical_hook only works for CONFIG_KASAN_INLINE.
> > >
> > > And CONFIG_KASAN_OUTLINE is set in my case.
> > >
> > > Is it possible to make kasan_non_canonical_hook works for both
> > > INLINE and OUTLINE by simply remove the "#ifdef CONFIG_KASAN_INLINE"?
> >
> > Yes, it should just work if you remove the ifdefs in mm/kasan/report.c
> > and in include/linux/kasan.h.
> >
> > Jann, do you have any objections to enabling kasan_non_canonical_hook
> > for the outline mode too?
>
> No objections from me.

Thanks.
Shall I send a new patch to fix this problem by using kasan_non_canonical_hook

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230918081250.143237-1-haibo.li%40mediatek.com.
