Return-Path: <kasan-dev+bncBCN7B3VUS4CRBGHXZGAAMGQEBR33GOA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x93d.google.com (mail-ua1-x93d.google.com [IPv6:2607:f8b0:4864:20::93d])
	by mail.lfdr.de (Postfix) with ESMTPS id E56F5307206
	for <lists+kasan-dev@lfdr.de>; Thu, 28 Jan 2021 09:53:45 +0100 (CET)
Received: by mail-ua1-x93d.google.com with SMTP id o24sf1262405uap.15
        for <lists+kasan-dev@lfdr.de>; Thu, 28 Jan 2021 00:53:45 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1611824025; cv=pass;
        d=google.com; s=arc-20160816;
        b=mVI79jwST4FDEWpCylcD1DELhQUrIzKVT3xCE1UqKyfCmHtSCKHhKt/aFb4b17rmpI
         RDiaVTcxF60JOUjjXC2V4UPyrgS/HEl5BIazBa/6QdQiASxt+TmLUCpKNTLfsaKVW241
         3N09flXKq7ma/1J971YP+cooPehWhbrFtWTZGq/VDQrk9mAjItydB3pLd3IytIxcC1sT
         Je81tAp1emuH3j40OnfiPR1KpSQkB/ZBfltNZfu6wLsAj1t4FL64RhtqxF/B1M1WMLHR
         et54Yn3PKxxXg1PZPq6VN2XJ1FP+CsccdG3YTavQPhhHmo8NVDIMXeoJSwrXjcRcFt2K
         t++A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=YqfgfYRMh+EEXQFgJnSJn6S0L/vTHoqrCgKCHSmERPU=;
        b=vgvDKXAtPQ8Vbzu/lXYCT/Hb9z1ukc6ruynYifeN3ORu1NUXeAfuspMPGx78F7DRLQ
         miEmZTKVqzx/AATXsnPvyokHvkRUU6qryxOlfiC/qNKjDZC461TCf7e8/jMlAIosXuC4
         m4yfAgjfaI2CRSVWUiDisZQdT/eF6d1mq+lYw9hxMhXN3WE3YjhsYSlrTygNKPFy5+ht
         Kyc708cRI9x8vy4kf8bl+gDb+TENlevi0qtoxspZkTRVtxcXwXdZTS1frOWqX4sjMZt9
         eG9PapDsTByGhrDz5ktYW4BlIAqVTDtpLV6lCrSZmL4AEo1C29rNc4re7oNT/kBXQMLU
         4R0w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of lecopzer.chen@mediatek.com designates 210.61.82.183 as permitted sender) smtp.mailfrom=lecopzer.chen@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=YqfgfYRMh+EEXQFgJnSJn6S0L/vTHoqrCgKCHSmERPU=;
        b=AS1pTazwkTifte6hZVj53Aa9G4ZFlufneEDRBtFRFfDRdD+155no6Kq/J8b+ox2E1a
         MY/cBP1vuijbdkASHCEzQ0Ju7HQfNlRANyPDFun4VoCtlENYXpLcO1sWOMxT11v88hFs
         1R7FXfDZ8QxwVZ85qbMfxCqqZ9/P1Wi2Q6tOdCC9qCr/IVP9+I1f5n5NfxP/R3LXluSP
         RuRT5j/+ZYvuj9Ntqc2KdMQ8lZnq7ALCfZDyKig2wNevXxmidReksvx457rhwaUIuU7K
         RruDVOMJVX5Dd8x9+XwNYzgXiTnsouEZ0BKBI/oXXtLLqbZ3jnjkb+jLlvE+P+wk5YxP
         hO0g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=YqfgfYRMh+EEXQFgJnSJn6S0L/vTHoqrCgKCHSmERPU=;
        b=Ha0riXtFDhQ3mGDW3JCNpY1eobYgHsEjnj6nQ7qj58CTVKT58vyc+HIw0EZpTGxtHu
         DFCBNv+NlBPE4A+swmnPr/wmmXtGlKQ/3Xd+fDgZXbLdgvuwNP/ntkTEgX71B3SXBuC6
         Dety3huHgRYfseBt+PN6mQZHQh6QM/qiVGktPubEVEG2V5V1ekbqhoFC6JQed0ibwBbH
         cVIO2mTe8ji9Gf0D7PGH/tzKvGLz+t45moQj/Gd7U7g9drgh/uhxR5wDqQpXcngJr+c+
         BV5AJx8y/lJJiftG63k7kivfcy1pONe2Y+dwM0BhJPj9zqFos1Wd96jwfsdyPoMT5VFR
         HL8w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532EbRpfHMCoWQu8r7EgMmEYkWZZT0gH6bTsHD1XZ1MKIpi437uC
	Dvg2QKS40F1vflmPyh0sOw4=
X-Google-Smtp-Source: ABdhPJxAKeeXqOFut/ATETp8QZtnYDreMc2q8tBr/Zn2gdPcXPPm0wOjhsXC3F5aIrCVVNDbe94tEg==
X-Received: by 2002:a9f:25a1:: with SMTP id 30mr10559179uaf.135.1611824024772;
        Thu, 28 Jan 2021 00:53:44 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:f515:: with SMTP id u21ls620940vsn.2.gmail; Thu, 28 Jan
 2021 00:53:44 -0800 (PST)
X-Received: by 2002:a67:d20d:: with SMTP id y13mr10556778vsi.13.1611824024320;
        Thu, 28 Jan 2021 00:53:44 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1611824024; cv=none;
        d=google.com; s=arc-20160816;
        b=XaObjsDcoL1rTH5Yzj5cM3c6IIjPB8Ug86MqfuVHo7RdTCtxZhyJQVDNZTLtbuMu4c
         F+9t/otgCJfKjHycI58TBosZJjKJiFNGb11mAyiwpSj9fGjrpPLh1iKijzsPPljnav+0
         RtmCOzyq7veyWV4+0ucoGQGJd7hzsKzpoJ3d8eYjvY8wNTCHVTrqvzyLArI8zn8brFxf
         Sc7oPqXshcDs7JpFOyJ6Fx9SPDACSomnVouNh9aKP453qBTeo1WEAtJdpMy0PJewU1bv
         rzSUr65rhmjpWmGzy/EcBBxmO6ldRllaHXeT4ja4xTBizupP7YP9ARU9STf1MgAc6vV3
         bkhg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:references:in-reply-to:message-id:date:subject:cc:to
         :from;
        bh=iKYjFx5q1wpC6o92Yurha9CyVAhB5Glv68g9FDx/NaA=;
        b=XNS8h0IMtD+MmRa5U0WzKcu7/cmUfJywWB0LOn9yzgx0KpDj5uyzwdn9V/FowmtUEY
         xIK6tnjEl5MEhntIc1t52Ukw5FLEJ/jVS3MM4jbnmwzmkmHbDcpNVjDON5z0SIF9MOL6
         4czMKRKXe7gA8gxJFpTTt/ZvqXG1JjXsJKzkSrRrU6+14izPJ+ipeCQm4ZVrjX8uNMFO
         Gavdm5r7h88yWbwHaIiYAImTeKurjoKjIldRZvOBEPVb3TV+QPHrRAOzKx90dPxl5mtk
         mCZxcvfQdkVbxxva1nFBFCSe0oqxypmTs/wK1qRZ4G3Gzf459u3nQ6bswozxJLO2E5e0
         hcFg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of lecopzer.chen@mediatek.com designates 210.61.82.183 as permitted sender) smtp.mailfrom=lecopzer.chen@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw01.mediatek.com ([210.61.82.183])
        by gmr-mx.google.com with ESMTP id e11si351065vkp.4.2021.01.28.00.53.43
        for <kasan-dev@googlegroups.com>;
        Thu, 28 Jan 2021 00:53:43 -0800 (PST)
Received-SPF: pass (google.com: domain of lecopzer.chen@mediatek.com designates 210.61.82.183 as permitted sender) client-ip=210.61.82.183;
X-UUID: 57b2bc63e7094583a534d65b5d68bc02-20210128
X-UUID: 57b2bc63e7094583a534d65b5d68bc02-20210128
Received: from mtkexhb01.mediatek.inc [(172.21.101.102)] by mailgw01.mediatek.com
	(envelope-from <lecopzer.chen@mediatek.com>)
	(Cellopoint E-mail Firewall v4.1.14 Build 0819 with TLSv1.2 ECDHE-RSA-AES256-SHA384 256/256)
	with ESMTP id 449940059; Thu, 28 Jan 2021 16:53:38 +0800
Received: from mtkcas11.mediatek.inc (172.21.101.40) by
 mtkmbs05n1.mediatek.inc (172.21.101.15) with Microsoft SMTP Server (TLS) id
 15.0.1497.2; Thu, 28 Jan 2021 16:53:36 +0800
Received: from mtksdccf07.mediatek.inc (172.21.84.99) by mtkcas11.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1497.2 via Frontend
 Transport; Thu, 28 Jan 2021 16:53:36 +0800
From: Lecopzer Chen <lecopzer.chen@mediatek.com>
To: <will@kernel.org>
CC: <akpm@linux-foundation.org>, <andreyknvl@google.com>, <ardb@kernel.org>,
	<aryabinin@virtuozzo.com>, <broonie@kernel.org>, <catalin.marinas@arm.com>,
	<dan.j.williams@intel.com>, <dvyukov@google.com>, <glider@google.com>,
	<gustavoars@kernel.org>, <kasan-dev@googlegroups.com>,
	<lecopzer.chen@mediatek.com>, <lecopzer@gmail.com>,
	<linux-arm-kernel@lists.infradead.org>, <linux-kernel@vger.kernel.org>,
	<linux-mediatek@lists.infradead.org>, <linux-mm@kvack.org>,
	<linux@roeck-us.net>, <robin.murphy@arm.com>, <rppt@kernel.org>,
	<tyhicks@linux.microsoft.com>, <vincenzo.frascino@arm.com>,
	<yj.chiang@mediatek.com>
Subject: Re: [PATCH v2 4/4] arm64: kaslr: support randomized module area with KASAN_VMALLOC
Date: Thu, 28 Jan 2021 16:53:26 +0800
Message-ID: <20210128085326.22553-1-lecopzer.chen@mediatek.com>
X-Mailer: git-send-email 2.18.0
In-Reply-To: <20210127230413.GA1016@willie-the-truck>
References: <20210127230413.GA1016@willie-the-truck>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-MTK: N
X-Original-Sender: lecopzer.chen@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of lecopzer.chen@mediatek.com designates 210.61.82.183 as
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

 
> On Sat, Jan 09, 2021 at 06:32:52PM +0800, Lecopzer Chen wrote:
> > After KASAN_VMALLOC works in arm64, we can randomize module region
> > into vmalloc area now.
> > 
> > Test:
> > 	VMALLOC area ffffffc010000000 fffffffdf0000000
> > 
> > 	before the patch:
> > 		module_alloc_base/end ffffffc008b80000 ffffffc010000000
> > 	after the patch:
> > 		module_alloc_base/end ffffffdcf4bed000 ffffffc010000000
> > 
> > 	And the function that insmod some modules is fine.
> > 
> > Suggested-by: Ard Biesheuvel <ardb@kernel.org>
> > Signed-off-by: Lecopzer Chen <lecopzer.chen@mediatek.com>
> > ---
> >  arch/arm64/kernel/kaslr.c  | 18 ++++++++++--------
> >  arch/arm64/kernel/module.c | 16 +++++++++-------
> >  2 files changed, 19 insertions(+), 15 deletions(-)
> > 
> > diff --git a/arch/arm64/kernel/kaslr.c b/arch/arm64/kernel/kaslr.c
> > index 1c74c45b9494..a2858058e724 100644
> > --- a/arch/arm64/kernel/kaslr.c
> > +++ b/arch/arm64/kernel/kaslr.c
> > @@ -161,15 +161,17 @@ u64 __init kaslr_early_init(u64 dt_phys)
> >  	/* use the top 16 bits to randomize the linear region */
> >  	memstart_offset_seed = seed >> 48;
> >  
> > -	if (IS_ENABLED(CONFIG_KASAN_GENERIC) ||
> > -	    IS_ENABLED(CONFIG_KASAN_SW_TAGS))
> > +	if (!IS_ENABLED(CONFIG_KASAN_VMALLOC) &&
> > +	    (IS_ENABLED(CONFIG_KASAN_GENERIC) ||
> 
> CONFIG_KASAN_VMALLOC depends on CONFIG_KASAN_GENERIC so why is this
> necessary?
> 
> Will

CONFIG_KASAN_VMALLOC=y means CONFIG_KASAN_GENERIC=y
but CONFIG_KASAN_GENERIC=y doesn't means CONFIG_KASAN_VMALLOC=y

So this if-condition allows only KASAN rather than
KASAN + KASAN_VMALLOC enabled.

Please correct me if I'm wrong.

thanks,
Lecopzer


 


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210128085326.22553-1-lecopzer.chen%40mediatek.com.
