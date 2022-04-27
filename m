Return-Path: <kasan-dev+bncBCN7B3VUS4CRBYFIUWJQMGQEVIGJ4CI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x239.google.com (mail-oi1-x239.google.com [IPv6:2607:f8b0:4864:20::239])
	by mail.lfdr.de (Postfix) with ESMTPS id A612E5118C7
	for <lists+kasan-dev@lfdr.de>; Wed, 27 Apr 2022 16:34:09 +0200 (CEST)
Received: by mail-oi1-x239.google.com with SMTP id c3-20020acab303000000b003226fc84078sf1002975oif.8
        for <lists+kasan-dev@lfdr.de>; Wed, 27 Apr 2022 07:34:09 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1651070048; cv=pass;
        d=google.com; s=arc-20160816;
        b=jSn+dAmEN4NUvfauuyBqSrz+sQYSd7OxefaxodxvpTIaKis3t8Z0LDOQGGzncKjvUs
         cJLZoOKKO9AEIEkkY767lgSeIoJ/sMBfvjUzbTKKxWBOBtROiKfG06Hfoqgz7gASfBFD
         +SCb+9DopNzkMvn6GNcle8QeFzHhg8fTLRFOlhtLAHJiMkV6MMw97JeuVSFVXdKBPMcm
         feIFBNBUt4NgsODXeyAPT3gn7k0B5I0L7CVYoCdBIB7NIKYLau/XUR5FW8tXp6Wo3T6u
         csOsO1HfBjYCeDw1jlm9rsqBYpm+Y7Ca4hrlg7jmln48llcVxC9oyCl5Eb6aPfA7meKI
         2UwA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=+tuUwanN91A7lrKTKQ1giO5ALuK/kphhAaCxOhX5wzI=;
        b=NNwEibd4IqwRfVLgB0cxYpgUiDk1fFjpIjHAMu1Hwh5UCZfbXLxZY9wS6bn7e94qDB
         i2+x1aOs+ebuGLZzrSXZHUzpHCj62SxT3FnQcU3fKSptdqysQ+1s6ICMimXCSfR2kP1n
         4fPolQEp+pl59BTsx3r4LmkpVqmQHFKp/EYHfRNXphL+Yt5Kw8ppBb+TV452DYGQGXG3
         w1oPVoG1RIpURwJQONxjm1Et2gutxmcd17CabA687ToI3KslOXgYThpMpObOAnh0C6+j
         o7X6rUq3mZpnERhj3GGyFg/SUNt4bDHv+khdiXe3uZTC2tlokYkkOtBwXb6FucplX5kT
         ZPuw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of lecopzer.chen@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=lecopzer.chen@mediatek.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=+tuUwanN91A7lrKTKQ1giO5ALuK/kphhAaCxOhX5wzI=;
        b=XNGTG6w2uj1CmMHvYGtsZFU2wJGAfrmgm4Ob/fFvnak6voHwR69iUJ6AvRo6Xe2W+x
         +l3HXGtHOyz0iiKUXXiDyd3bJHsx1fIm/wt6p5XXXIzcegZWTtnC2i69qiiy5l7YrySb
         lgkWywVcCgGx+Z2kZmy0CT6fhnR7vZ5cyz/0oDiO/9NSckydBZwKGuggkZdooYHDVJe9
         kndi6dE+a3VnsO/pguQMn/UJy23nPiXsBZm18C9VwikJBtUxfFvJuqdAxD88eub06qS/
         /lF+ENCypv5EhbKWlay1XVfIWaqaTqk8ChcTYaqBa0f4gyMn7VQcraw4DNMz61cNfkFh
         amQQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:from:to:cc:subject:date:message-id:in-reply-to
         :references:mime-version:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=+tuUwanN91A7lrKTKQ1giO5ALuK/kphhAaCxOhX5wzI=;
        b=WzZWXS6NfyjYkHUuT8Dx49BcswXOz7Rs7g3lTJahy2ZfrTsJ/nsMh2DEwH3INjxm2a
         cTUQSZppc4d3XuarhtJQnPHre0KigFWoHw1navr1s1nR31OTPGNZw1giQFzHiTskjhp0
         S8cvBNQph//yLvBiGfmDyyT8wALmWCso1aXRTKIRUhxd8K7Sh2Lt/6LjeuWN67fepEIy
         ahRXbGXvEb2BPtUWnCOo4ZRWLbLH5KQEZr96jlrlO3kHwx8TaGBH+bgTGJPEQf/G2qYj
         K4d0s3O3ELsgrRwJ605JV0jdJF5kcl0U+2TmP+Gu6/TZsoND1pIJjUI02MR8UiYEm73e
         t86A==
X-Gm-Message-State: AOAM532YJHgMrm8HBNDwHBqrMQUV+R7w2s2aIk9kIEyjOssOygPjsQpZ
	IIY4UhFF5lSJn1F2eTLCHB4=
X-Google-Smtp-Source: ABdhPJwMVD1ZrAJ0xP1NKUAFuOHE5aYZfUAtDLRG8ZiGrO5EtHzfRfEUKq6p5lbCFgNticuRgpL4eA==
X-Received: by 2002:a05:6870:e30e:b0:de:ecf4:df7e with SMTP id z14-20020a056870e30e00b000deecf4df7emr12478759oad.114.1651070048519;
        Wed, 27 Apr 2022 07:34:08 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6871:154:b0:e9:6abf:f9bb with SMTP id
 z20-20020a056871015400b000e96abff9bbls2251035oab.7.gmail; Wed, 27 Apr 2022
 07:34:08 -0700 (PDT)
X-Received: by 2002:a05:6870:f619:b0:e9:6d65:4aae with SMTP id ek25-20020a056870f61900b000e96d654aaemr3294981oab.126.1651070048060;
        Wed, 27 Apr 2022 07:34:08 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1651070048; cv=none;
        d=google.com; s=arc-20160816;
        b=gltZQ6U66FRthVEKmB1q+8FXYGzFz5fpAu6OM5Hc2f2PhupicyFanzWc7M6aZZisiR
         9QLkFwrNyt9KpBdcUVmHKs4NqF+81mFGMS82WAUgulTEy9onPbcuaLjqA0YsNJOQnPDY
         D8mFFfMtSWfKFrw9qrZfnlTiLblja3/R+OCzQHLwV0IOw7+o5ewrrMs6hh/F2n8Ggz1+
         bjqdiBjVonwzAqUQdrr3fyL6zO28I/pZepYFMLW0pyGRspcT4u1ZzkO2SW9BxtoI9h/C
         BEs6wlPtPjyCADJ76uYTQYy2/v2Pj1cftnr7p/XDZhpGwhEeK7pRUTgvTRO/4q5f7OLg
         eU2g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:references:in-reply-to:message-id:date:subject:cc:to
         :from;
        bh=4dF5ya6nBR5UQlAwm3Dqx9bqsNHhKHzw/3h01MsAJck=;
        b=iM7fTlC3+slP1pgvcLu59xnNZx+NRv1kLKaSwiFCP8/VUxvwA8IHAlxSiyQqj6qytU
         ScOWCfi8gA+htS7488h00NEke5A/7nbiMMt9AfZCB0OX/2DaTpKY6h/IDOJgNvxOFFdQ
         6HkP2UQC/qHW0un6MIqAF5OZVo8FOgNQ5teygqtHkCvVc5tQv1dA+5eBsDqT2F+cBzbh
         piSbFPBUoCFmnDq5+g8p0NZaXw2Djq9lx8izqj5Nb9h1vp7jVFZpUKnhYPLRAxXWQ9sP
         AoT+JFU7uGg3BNlqvJWUbyFqk+rJjm9Zid1Zrda+Q1mtgASqg2aUSSx5s5lrYeZvaI8D
         glig==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of lecopzer.chen@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=lecopzer.chen@mediatek.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=mediatek.com
Received: from mailgw02.mediatek.com ([210.61.82.184])
        by gmr-mx.google.com with ESMTPS id m13-20020a05683023ad00b005c43e14b02bsi125303ots.3.2022.04.27.07.34.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 27 Apr 2022 07:34:07 -0700 (PDT)
Received-SPF: pass (google.com: domain of lecopzer.chen@mediatek.com designates 210.61.82.184 as permitted sender) client-ip=210.61.82.184;
X-UUID: c48886751da04506850b1248e72e9b27-20220427
X-CID-P-RULE: Release_Ham
X-CID-O-INFO: VERSION:1.1.4,REQID:7598e579-d76e-43ac-96c0-13c7b47018c8,OB:0,LO
	B:0,IP:0,URL:0,TC:0,Content:0,EDM:0,RT:0,SF:0,FILE:0,RULE:Release_Ham,ACTI
	ON:release,TS:0
X-CID-META: VersionHash:faefae9,CLOUDID:8e73ea2e-6199-437e-8ab4-9920b4bc5b76,C
	OID:IGNORED,Recheck:0,SF:nil,TC:nil,Content:-5,EDM:-3,File:nil,QS:0,BEC:ni
	l
X-UUID: c48886751da04506850b1248e72e9b27-20220427
Received: from mtkexhb02.mediatek.inc [(172.21.101.103)] by mailgw02.mediatek.com
	(envelope-from <lecopzer.chen@mediatek.com>)
	(Generic MTA with TLSv1.2 ECDHE-RSA-AES256-SHA384 256/256)
	with ESMTP id 2090439662; Wed, 27 Apr 2022 22:34:03 +0800
Received: from mtkexhb02.mediatek.inc (172.21.101.103) by
 mtkmbs10n1.mediatek.inc (172.21.101.34) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384) id
 15.2.792.15; Wed, 27 Apr 2022 22:34:02 +0800
Received: from mtkcas10.mediatek.inc (172.21.101.39) by mtkexhb02.mediatek.inc
 (172.21.101.103) with Microsoft SMTP Server (TLS) id 15.0.1497.2; Wed, 27 Apr
 2022 22:33:49 +0800
Received: from mtksdccf07.mediatek.inc (172.21.84.99) by mtkcas10.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1497.2 via Frontend
 Transport; Wed, 27 Apr 2022 22:33:49 +0800
From: "'Lecopzer Chen' via kasan-dev" <kasan-dev@googlegroups.com>
To: <linus.walleij@linaro.org>
CC: <andreyknvl@gmail.com>, <anshuman.khandual@arm.com>, <ardb@kernel.org>,
	<arnd@arndb.de>, <dvyukov@google.com>, <geert+renesas@glider.be>,
	<glider@google.com>, <kasan-dev@googlegroups.com>,
	<lecopzer.chen@mediatek.com>, <linux-arm-kernel@lists.infradead.org>,
	<linux-kernel@vger.kernel.org>, <linux@armlinux.org.uk>,
	<lukas.bulwahn@gmail.com>, <mark.rutland@arm.com>, <masahiroy@kernel.org>,
	<matthias.bgg@gmail.com>, <rmk+kernel@armlinux.org.uk>,
	<ryabinin.a.a@gmail.com>, <yj.chiang@mediatek.com>
Subject: Re: [PATCH v5 0/2] arm: kasan: support CONFIG_KASAN_VMALLOC
Date: Wed, 27 Apr 2022 22:33:49 +0800
Message-ID: <20220427143349.15651-1-lecopzer.chen@mediatek.com>
X-Mailer: git-send-email 2.18.0
In-Reply-To: <CACRpkda_hpTVxKftKBqRvBtC-KN8c9NWHFJDV10TN4JOR7CQCw@mail.gmail.com>
References: <CACRpkda_hpTVxKftKBqRvBtC-KN8c9NWHFJDV10TN4JOR7CQCw@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-MTK: N
X-Original-Sender: lecopzer.chen@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of lecopzer.chen@mediatek.com designates 210.61.82.184 as
 permitted sender) smtp.mailfrom=lecopzer.chen@mediatek.com;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=mediatek.com
X-Original-From: Lecopzer Chen <lecopzer.chen@mediatek.com>
Reply-To: Lecopzer Chen <lecopzer.chen@mediatek.com>
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

> On Wed, Apr 27, 2022 at 11:59 AM Lecopzer Chen
> <lecopzer.chen@mediatek.com> wrote:
> 
> > Since the framework of KASAN_VMALLOC is well-developed,
> > It's easy to support for ARM that simply not to map shadow of VMALLOC
> > area on kasan_init.
> >
> > Since the virtual address of vmalloc for Arm is also between
> > MODULE_VADDR and 0x100000000 (ZONE_HIGHMEM), which means the shadow
> > address has already included between KASAN_SHADOW_START and
> > KASAN_SHADOW_END.
> > Thus we need to change nothing for memory map of Arm.
> >
> > This can fix ARM_MODULE_PLTS with KASan, support KASan for higmem
> > and support CONFIG_VMAP_STACK with KASan.
> 
> Excellent Lecopzer,
> 
> can you put these patches into Russell's patch tracker so he can pick them?
> https://www.armlinux.org.uk/developer/patches/
> 
> Yours,
> Linus Walleij


I've added
9202/1 	kasan: support CONFIG_KASAN_VMALLOC
9203/1 	kconfig: fix MODULE_PLTS for KASAN with KASAN_VMALLOC

Thank you very much

BRs,
Lecopzer

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220427143349.15651-1-lecopzer.chen%40mediatek.com.
