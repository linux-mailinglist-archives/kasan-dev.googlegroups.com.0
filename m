Return-Path: <kasan-dev+bncBCN7B3VUS4CRBL5V4X7QKGQEO4FWTBI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x240.google.com (mail-oi1-x240.google.com [IPv6:2607:f8b0:4864:20::240])
	by mail.lfdr.de (Postfix) with ESMTPS id 6AA1D2EFE46
	for <lists+kasan-dev@lfdr.de>; Sat,  9 Jan 2021 08:26:40 +0100 (CET)
Received: by mail-oi1-x240.google.com with SMTP id x4sf8218440oia.8
        for <lists+kasan-dev@lfdr.de>; Fri, 08 Jan 2021 23:26:40 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610177199; cv=pass;
        d=google.com; s=arc-20160816;
        b=BURJ/0bSHOoI1V2UHcIJHTF1p8EDqY4RpVfwIWQDYUq9u+WoWY/eeWvPU1jR0ZO3Ej
         krh+DfNIQZdh3mefDLwhNjk9/A7bXMbvKeE8LjIlh7XD0g9cOqxB78euZrA2dFm4FAGj
         WEGspuseuQrQKGNjkcZnUimRkq9RuNcG0TjP5hjQ6gpXgd1lRf+pSBPMMq/a0WlR0h/N
         JcuXuTwBNi+ddzRo/pmUy9465j3/l5rfsag3nyZRtClRU2yJzAoVVafMvlmWaXIaFOgp
         2ahCst9ozeNGtx5NFmFXYdgS+rZy4SnpyPKEVpUXInYALF1H1eX2exc6591LAjFWf6kf
         KC4Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=9JiESuWMJw6feIKHMpZoPanA+xoK7ij3gxbjpRL4nOw=;
        b=0WJEqyc08YkY/MxJxzIyrX2JvU7PW16CiOjjHXM+1ycGYRVNzxJqNxrye7jXugCqu4
         7ULpePmvcXCKqfBpSTPtz4AlGBNdSwod7EoMxcPC6JKlQr1DzO9sKEBDH/2KSsR8DvK9
         F9+xOS7ejoNV+fXRho0YjBB86ytcjzXObfJC1apL1p6TnKaOrlRg6o5FfEu9nPO34uCo
         CpTN2PiIfR6E8CBH5Cc5i0C3nqlIP7WBQFi8toI3F3cN6I1iyU69SgaJ5/QJ0UpNlyVb
         tLfkNvvEtjHaQj1FZg3vwbD94Pm+kFBPnFIrILy6EkuaxqiCsKUaLexPJo63YYpi+0kK
         b+4A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of lecopzer.chen@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=lecopzer.chen@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=9JiESuWMJw6feIKHMpZoPanA+xoK7ij3gxbjpRL4nOw=;
        b=DwEu+XzSuytJpPc+gFQgoFQkLilFcdyejnu+N6ABVqAMv+PSv2UF8o4SZ0Kmx1tcqM
         c1g+tg6n9bxfgDn6ckqRfbqfcMn9crb2qAUdOrvLd3SQuSowGJGdYFomsVhd2lCYsf2u
         EkJmW8rbIqabbVyf+BznIthz3sQWdAeP8CGK/DHJSv+oLq6h2UmlPDi/toDQanbYuqzi
         jfiXoaN1DoMo3t9PeYNbds5Z5omqYploa65lxijoXOCoJl1FVLLrFKjgUZjB1rExx6D7
         TZgNIYYoTDLJL1R0lhQ23vCObicNTkdNyfNCABwUyDloNIh4ymyvxmkssP1YSX5O0/JE
         qe5A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=9JiESuWMJw6feIKHMpZoPanA+xoK7ij3gxbjpRL4nOw=;
        b=BO2pyjF6Mw4t4Z/1EqyCV15QTv6xzTAWQBbY9mhs/Feb46GOpbJAd+gx8VQOr1eJu8
         +QepTIItiwhA/PbGdWTzZiTBF/YLzqflMUbbO3TMvPEmPXX2sbsA/YmhU6w9IHw79YYj
         znMdiGrVN/Xw8eQpfLIstZtnMDMpykbgLZQzfOkZNwxZeii83PQMTsUCBAWT8EW4nTjQ
         KmnjqdQoECa7doxBqMsx2KcloMT9coiPxqijU/CqlUaOcidUK6jQ6rtmYS3cLh3Z2EV4
         tguLWvE8ufti3ZFsRgccmxPVOQ4Kk5O8pAdoW/nzaOxTTtFuM/ta9jqh3nFm3VSYmtJ1
         vxEw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532UmBJ/yrWUzGee8j5MtVlNhZC4IhO+xqGPAVCTqdGhHRI5Ic+q
	+mRSpt4pWqzH25rOJ4N92jM=
X-Google-Smtp-Source: ABdhPJzpQ57X2ZFblv2UCbKL36Dw0A1NZwke50dUsqir1xSK2bGEJrBMrDq0dgTr+cL5CnhhrmW4TA==
X-Received: by 2002:aca:d603:: with SMTP id n3mr4518633oig.35.1610177199177;
        Fri, 08 Jan 2021 23:26:39 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:2413:: with SMTP id n19ls3501576oic.7.gmail; Fri, 08 Jan
 2021 23:26:38 -0800 (PST)
X-Received: by 2002:aca:c1d6:: with SMTP id r205mr4536389oif.37.1610177198840;
        Fri, 08 Jan 2021 23:26:38 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610177198; cv=none;
        d=google.com; s=arc-20160816;
        b=ILw1HuTyvK25aTKO0FpmNlVuZEsuGmSu5F8rICq2cD824GNi+s5+A0acalFFtrcml3
         eDApAAp2IAUbVnidCD1heUPJRHatzFDfflEd5B9qd8oMpX8zkKXsjpcWYeDYXg1zwq6L
         +1JcYsoQZFdyqYjmv1/9FgYK+l1piDJXe922dv5K6+JC+VBzGL1fs2Ihzesu3WlLkH1y
         uMx64XGGyri19IWuLa0rZXBV+DhiNXSdP7lEuiicJUF4VX351kJVs480LvUFnr5+7ggy
         ht+Id1Ido6Z+NtrqX9mt9B6x+0vsbNujjv3znit6Yaeht2J31KEv/ToXjMTUU7QlH4YP
         TXJQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:references:in-reply-to:message-id:date:subject:cc:to
         :from;
        bh=6ipcxwCCPiy/ELhCXNSStvata4gj35fgjSJmFEM4RM8=;
        b=gES08ZFk+DaN+FZc9UaxL52LJvmdmXZtuup1LUyWHE2k8pt/OhDwGDNWXSVRpBHwPv
         xBZpy/sTe2fMvgl6/FCNGr06N8iIwWae9u5YXjM2527GBI2anCTgvvvSPtYIarYxjBNw
         x8QbnuCKGUYNuwgHQ8Gi2hSWK3kg90vT0ObSWTKAtYZyP2x888dvAbMLk63o715qxKMM
         PQ0UOLhLWjKr4ejS9+Fbnx9t+Z0abXz91G/X9JS/rVHUxQJOCQJfA41bgOg5EKuXuctX
         zi8XbCbWY2sidx8Ws5Z/oNoZIN6Vmf88zXvad57o5jDl4dRCextpbkY99PjydBB3HrSO
         oCSQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of lecopzer.chen@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=lecopzer.chen@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw02.mediatek.com ([210.61.82.184])
        by gmr-mx.google.com with ESMTP id v23si1567174otn.0.2021.01.08.23.26.38
        for <kasan-dev@googlegroups.com>;
        Fri, 08 Jan 2021 23:26:38 -0800 (PST)
Received-SPF: pass (google.com: domain of lecopzer.chen@mediatek.com designates 210.61.82.184 as permitted sender) client-ip=210.61.82.184;
X-UUID: 2bf8f8f83d444d7cb12be7145ef8876b-20210109
X-UUID: 2bf8f8f83d444d7cb12be7145ef8876b-20210109
Received: from mtkcas10.mediatek.inc [(172.21.101.39)] by mailgw02.mediatek.com
	(envelope-from <lecopzer.chen@mediatek.com>)
	(Cellopoint E-mail Firewall v4.1.14 Build 0819 with TLSv1.2 ECDHE-RSA-AES256-SHA384 256/256)
	with ESMTP id 1367188255; Sat, 09 Jan 2021 15:26:34 +0800
Received: from MTKCAS06.mediatek.inc (172.21.101.30) by
 mtkmbs05n1.mediatek.inc (172.21.101.15) with Microsoft SMTP Server (TLS) id
 15.0.1497.2; Sat, 9 Jan 2021 15:26:33 +0800
Received: from mtksdccf07.mediatek.inc (172.21.84.99) by MTKCAS06.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1497.2 via Frontend
 Transport; Sat, 9 Jan 2021 15:26:33 +0800
From: Lecopzer Chen <lecopzer.chen@mediatek.com>
To: <andreyknvl@google.com>
CC: <akpm@linux-foundation.org>, <aryabinin@virtuozzo.com>,
	<catalin.marinas@arm.com>, <dan.j.williams@intel.com>, <dvyukov@google.com>,
	<glider@google.com>, <kasan-dev@googlegroups.com>,
	<lecopzer.chen@mediatek.com>, <lecopzer@gmail.com>,
	<linux-arm-kernel@lists.infradead.org>, <linux-kernel@vger.kernel.org>,
	<linux-mediatek@lists.infradead.org>, <linux-mm@kvack.org>,
	<will@kernel.org>, <yj.chiang@mediatek.com>
Subject: Re: [PATCH 3/3] arm64: Kconfig: support CONFIG_KASAN_VMALLOC
Date: Sat, 9 Jan 2021 15:26:33 +0800
Message-ID: <20210109072633.7234-1-lecopzer.chen@mediatek.com>
X-Mailer: git-send-email 2.18.0
In-Reply-To: <CAAeHK+wc-DU2pUma43JtomOSy0Z6smGKwQoG_R+uKzByu3oZ9w@mail.gmail.com>
References: <CAAeHK+wc-DU2pUma43JtomOSy0Z6smGKwQoG_R+uKzByu3oZ9w@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-MTK: N
X-Original-Sender: lecopzer.chen@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of lecopzer.chen@mediatek.com designates 210.61.82.184 as
 permitted sender) smtp.mailfrom=lecopzer.chen@mediatek.com;       dmarc=pass
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

Hi Andrey,
 
> On Sun, Jan 3, 2021 at 6:13 PM Lecopzer Chen <lecopzer@gmail.com> wrote:
> >
> > Now I have no device to test for HW_TAG, so keep it not selected
> > until someone can test this.
> >
> > Signed-off-by: Lecopzer Chen <lecopzer.chen@mediatek.com>
> > ---
> >  arch/arm64/Kconfig | 1 +
> >  1 file changed, 1 insertion(+)
> >
> > diff --git a/arch/arm64/Kconfig b/arch/arm64/Kconfig
> > index 05e17351e4f3..29ab35aab59e 100644
> > --- a/arch/arm64/Kconfig
> > +++ b/arch/arm64/Kconfig
> > @@ -136,6 +136,7 @@ config ARM64
> >         select HAVE_ARCH_JUMP_LABEL
> >         select HAVE_ARCH_JUMP_LABEL_RELATIVE
> >         select HAVE_ARCH_KASAN if !(ARM64_16K_PAGES && ARM64_VA_BITS_48)
> > +       select HAVE_ARCH_KASAN_VMALLOC if (HAVE_ARCH_KASAN && !KASAN_HW_TAGS)
> 
> KASAN_VMALLOC currently "depends on" KASAN_GENERIC. I think we should
> either do "HAVE_ARCH_KASAN && KASAN_GENERIC" here as well, or just do
> "if HAVE_ARCH_KASAN".

Thanks for the correctness, I'll change to the following in V2 patch.
	"select HAVE_ARCH_KASAN_VMALLOC if HAVE_ARCH_KASAN"

Let KASAN_VMALLOC depend on the mode it supports to avoid modifying
two places if KASAN_VMALLOC can support other than GENERIC in the future.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210109072633.7234-1-lecopzer.chen%40mediatek.com.
