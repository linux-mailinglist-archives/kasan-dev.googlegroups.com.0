Return-Path: <kasan-dev+bncBCN7B3VUS4CRBIX64X7QKGQEZKUSFXA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3d.google.com (mail-yb1-xb3d.google.com [IPv6:2607:f8b0:4864:20::b3d])
	by mail.lfdr.de (Postfix) with ESMTPS id B605B2EFEE5
	for <lists+kasan-dev@lfdr.de>; Sat,  9 Jan 2021 11:02:11 +0100 (CET)
Received: by mail-yb1-xb3d.google.com with SMTP id e74sf18452054ybh.19
        for <lists+kasan-dev@lfdr.de>; Sat, 09 Jan 2021 02:02:11 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610186530; cv=pass;
        d=google.com; s=arc-20160816;
        b=X2WNvsdp9chN3AWCGvU4YwSXinPUyG0GXe/QxtrPKcyPgOYMMPUaZWIRRgLxsh7QJD
         u9trmSo1A/T0QLqKpHe2+ywe2kVFoeB/uumbzrXq9MMq/F3VoE6X8j0e2KprMQfLbimX
         IA9VIr1UsyaNzAp9K4Nire4AA53cGMidyMOpEsLWHHokcJoHI0yLwR/lVRzTp2L3CZG2
         RSBtNzddyk4k2ds17THgGklM6/DEM6a7iwNUi5kWltl6YXuuJ3njrHKlYGOGAgIA90SF
         FsIDhivf57UhkG5rakUUYnxhSnf9VZnpDM6CwnAL6VVPJGgGeCs3f1hv/vp/lpQUk8Vj
         JZZw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=VGM3snHUwKFZggSCat9WLgkwoIe2vQchfbkAM+J1Ej4=;
        b=o6qs95HRNQU2ROKDaer2cGL9VVeuAuCodD9dc2pJ5rH5vVG82ea3V6BndIJvhLlRaC
         UC0Nh73EVlxRWvUZyf+GGfHtU4Cd/g0Z3kaHDnvo6012te1dLjNyotC6jCgH6B09U2nQ
         h9YfXcQ4NyvwQFnXKIoeRg4g0zZIG1r56Rwx2Un+HvZQ/bli2ecfCo8je3MyiRBmChha
         oT5d43VkG7DU+z3+2gIzxL5w2j4zKSOGzoMaWck44MQVG00l28JXh+Iw+7aD8MS+/ZyZ
         0PpFzmHbgSjF2L0DGD2Td1+57M7X1W5R+5CEVlbSZA07W0KygilSne1lmS5MQxOHGQ0b
         j0Dg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of lecopzer.chen@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=lecopzer.chen@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=VGM3snHUwKFZggSCat9WLgkwoIe2vQchfbkAM+J1Ej4=;
        b=PhN9bAohojzb7fZKdATNsdBOrbPf/ZdPWjCxh3WaCeUw7TB45oEpnTbmyt+XvgVat5
         pu67JTWLa19tVaXp/Wbrn3YX/mZ6MjOWupogbJ42PQXxCo3fReLMD4rkoWqPmTMxQxhL
         PAsL1avqm02eAoD8kqX/bNqixaPmwtjs2k3ylx9QTeH03LSaaaNFSkI9GyBV/SRIQR/t
         AePu73oQpRoYBkiOczNLu0NvWRENnb6q2zZX4YyRRTGT1+FQjI7tpzplopPUCvPqYOIY
         5+0eCEBMOaAuvK3gg8akja0AOMtT2gmyBpgxYW0W/55g2IlrDWIe0nigN6GzSeDW/aG4
         79WQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=VGM3snHUwKFZggSCat9WLgkwoIe2vQchfbkAM+J1Ej4=;
        b=mvDxEEAMJCI9dOGupsjCTPxE5XmuJXxv4Q9KKUWuUCXMPJfeCaV6K7dLE6KZmj3aA+
         vQqpFx4imGOIl5P3/i/D3bH17lln/vylrG3JPNnDluR4N4UAHcVXSx2VnGgV/txVXOmc
         e/PEVpP72nj9w89myENaUugTYU91ntJr7hAOX6sE5JtBHGpoaFn6hy/DGJDF3wdoOox0
         ar0TGjxGC2S6tETo8YUFD4A+KQaA7kSzF8I82DyeOehynV2UHWCD+ePEMZqO8OnNqO4H
         y+GKeBaJYEWNevBVGNTBNdnZavFXH8fjUPTjdoPhbjKtLU7sLQ3VmTEthTpzN/bq3e5c
         WgXQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533KIlvrW3bzPhCZ9tmD4W0zkyRJdwkJnIbRUn6b2C+hxo4OAZXC
	D9RGeX090DadUdMmj31bTzQ=
X-Google-Smtp-Source: ABdhPJyUR49dC0ycnoiJAEnvC1aUw0arpsA90CgE7CsryaJfASdSWSJ8qVAeLKmJiKgWo2TsRkNyxg==
X-Received: by 2002:a25:680c:: with SMTP id d12mr12066801ybc.336.1610186530644;
        Sat, 09 Jan 2021 02:02:10 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:77cc:: with SMTP id s195ls7001112ybc.2.gmail; Sat, 09
 Jan 2021 02:02:10 -0800 (PST)
X-Received: by 2002:a25:11c2:: with SMTP id 185mr5410460ybr.74.1610186530145;
        Sat, 09 Jan 2021 02:02:10 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610186530; cv=none;
        d=google.com; s=arc-20160816;
        b=WNpKtbcrl9gczuSr2KWhKhXJLfIXJ5hqWYZxyzrFpW43W53nxKO5wiALbHzT7sLJ3O
         WXyp6cXxTVID4jyL686YZVcMOZlyG0q08zTZnBnNdCxA8LDadrqCOAC0br45yANzSaCO
         GZXnaxVssmsEQVm4ncKm/v8An01cm23M58E63jiuPvdguxtzZONC9M+NW/rZIKCVTl1Z
         qvX0UewjPaem4UsxxwPpJvO7g62COLyOmGA4nNw1+eMTosxPC7p83ZtR2XfKgzkubUNf
         uGwhfwtbo+9MwFvVkOzOlEhC8l6XVkFQlG2o2jkR+mPcPgDk7jknupMesecIJ3g89s4z
         cK6w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:references:in-reply-to:message-id:date:subject:cc:to
         :from;
        bh=YG8KjhZAtA2CGgaoD7jtcb6NCb7UzcTC5rtwehW1LcM=;
        b=IpZ5AGKqZkGAwpeNDQsFJev/ULTJ1RWs2ghy9ZHEzdwcd4YgLLdUKb3tAbki2p8QGB
         swjpr7VB8F+Qw2My92jyW3m6MP37XtDVvl5jI3IRRcOLNI1ancEM75cX/87pmt+naHic
         kkCwv3+8IUqVnTNhwh1gc+6S/m7XEayXk+5Jamb8IHcQsb30b1lTNFMYbyDcgGOALfdV
         ApPHNYBvoJ1x4+uMmEmVyX0KhGJFuYDHFNcF9RmiCF9sqqL1vMrsiRdwDVjXGXpQwhF+
         xKG1Gt7rJflDg50bSg6EZ001k0IfAsKJbmdUXf9PBUfS0Mv6Vjz/GjSIqOoV53YvPV7s
         1vlg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of lecopzer.chen@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=lecopzer.chen@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw02.mediatek.com ([210.61.82.184])
        by gmr-mx.google.com with ESMTP id k6si1034927ybd.5.2021.01.09.02.02.09
        for <kasan-dev@googlegroups.com>;
        Sat, 09 Jan 2021 02:02:09 -0800 (PST)
Received-SPF: pass (google.com: domain of lecopzer.chen@mediatek.com designates 210.61.82.184 as permitted sender) client-ip=210.61.82.184;
X-UUID: f39892b479ab475689c41d9738a38158-20210109
X-UUID: f39892b479ab475689c41d9738a38158-20210109
Received: from mtkcas06.mediatek.inc [(172.21.101.30)] by mailgw02.mediatek.com
	(envelope-from <lecopzer.chen@mediatek.com>)
	(Cellopoint E-mail Firewall v4.1.14 Build 0819 with TLSv1.2 ECDHE-RSA-AES256-SHA384 256/256)
	with ESMTP id 625812715; Sat, 09 Jan 2021 18:02:06 +0800
Received: from mtkcas11.mediatek.inc (172.21.101.40) by
 mtkmbs08n1.mediatek.inc (172.21.101.55) with Microsoft SMTP Server (TLS) id
 15.0.1497.2; Sat, 9 Jan 2021 18:02:05 +0800
Received: from mtksdccf07.mediatek.inc (172.21.84.99) by mtkcas11.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1497.2 via Frontend
 Transport; Sat, 9 Jan 2021 18:02:05 +0800
From: Lecopzer Chen <lecopzer.chen@mediatek.com>
To: <ardb@kernel.org>
CC: <akpm@linux-foundation.org>, <andreyknvl@google.com>,
	<aryabinin@virtuozzo.com>, <catalin.marinas@arm.com>,
	<dan.j.williams@intel.com>, <dvyukov@google.com>, <glider@google.com>,
	<kasan-dev@googlegroups.com>, <lecopzer.chen@mediatek.com>,
	<lecopzer@gmail.com>, <linux-arm-kernel@lists.infradead.org>,
	<linux-kernel@vger.kernel.org>, <linux-mediatek@lists.infradead.org>,
	<linux-mm@kvack.org>, <will@kernel.org>, <yj.chiang@mediatek.com>
Subject: Re: [PATCH 0/3] arm64: kasan: support CONFIG_KASAN_VMALLOC
Date: Sat, 9 Jan 2021 18:02:05 +0800
Message-ID: <20210109100205.11359-1-lecopzer.chen@mediatek.com>
X-Mailer: git-send-email 2.18.0
In-Reply-To: <CAMj1kXHFOQMV_4pYp9u9u++2jjQbHuLU95KeJTzrWXZWQTe_Tg@mail.gmail.com>
References: <CAMj1kXHFOQMV_4pYp9u9u++2jjQbHuLU95KeJTzrWXZWQTe_Tg@mail.gmail.com>
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

Hi Ard,

> On Fri, 8 Jan 2021 at 19:31, Andrey Konovalov <andreyknvl@google.com> wrote:
> >
> > On Sun, Jan 3, 2021 at 6:12 PM Lecopzer Chen <lecopzer@gmail.com> wrote:
> > >
> > > Linux supports KAsan for VMALLOC since commit 3c5c3cfb9ef4da9
> > > ("kasan: support backing vmalloc space with real shadow memory")
> > >
> > > Acroding to how x86 ported it [1], they early allocated p4d and pgd,
> > > but in arm64 I just simulate how KAsan supports MODULES_VADDR in arm64
> > > by not to populate the vmalloc area except for kimg address.
> > >
> > > Test environment:
> > >     4G and 8G Qemu virt,
> > >     39-bit VA + 4k PAGE_SIZE with 3-level page table,
> > >     test by lib/test_kasan.ko and lib/test_kasan_module.ko
> > >
> > > It also works in Kaslr with CONFIG_RANDOMIZE_MODULE_REGION_FULL,
> > > but not test for HW_TAG(I have no proper device), thus keep
> > > HW_TAG and KASAN_VMALLOC mutual exclusion until confirming
> > > the functionality.
> > >
> > >
> > > [1]: commit 0609ae011deb41c ("x86/kasan: support KASAN_VMALLOC")
> > >
> > > Signed-off-by: Lecopzer Chen <lecopzer.chen@mediatek.com>
> >
> > Hi Lecopzer,
> >
> > Thanks for working on this!
> >
> > Acked-by: Andrey Konovalov <andreyknvl@google.com>
> > Tested-by: Andrey Konovalov <andreyknvl@google.com>
> >
> > for the series along with the other two patches minding the nit in patch #3.
> >
> > Will, Catalin, could you please take a look at the arm changes?
> >
> > Thanks!
> >
> 
> 
> If vmalloc can now be backed with real shadow memory, we no longer
> have to keep the module region in its default location when KASLR and
> KASAN are both enabled.
> 
> So the check on line 164 in arch/arm64/kernel/kaslr.c should probably
> be updated to reflect this change.
> 

I've tested supporting module region randomized and It looks fine
in some easy test(insmod some modules).

I'll add this to patch v2, thanks for your suggestion.

BRs,
Lecopzer

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210109100205.11359-1-lecopzer.chen%40mediatek.com.
