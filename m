Return-Path: <kasan-dev+bncBDY7XDHKR4OBBU5Z62GAMGQEOA3SGSA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x537.google.com (mail-pg1-x537.google.com [IPv6:2607:f8b0:4864:20::537])
	by mail.lfdr.de (Postfix) with ESMTPS id CDC4A45B19A
	for <lists+kasan-dev@lfdr.de>; Wed, 24 Nov 2021 03:00:52 +0100 (CET)
Received: by mail-pg1-x537.google.com with SMTP id t1-20020a6564c1000000b002e7f31cf59fsf193975pgv.14
        for <lists+kasan-dev@lfdr.de>; Tue, 23 Nov 2021 18:00:52 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1637719251; cv=pass;
        d=google.com; s=arc-20160816;
        b=QTbplUkUxUKtzYavRVZvE/hlzih8JxjtVnC246Ro8ggOicCvG/NfqPXl/YpOeYb15b
         WDg6HSi5xZAeH1VfGZoLeVfAdjYFcmgYw5LEHVwJ/T02JpYt76XJB/AdTc+IA4DSLvh/
         RwQpH2g0lYMgL+zv6SBZX/52mdCVFFzPwYfPBvnLtatQuy4K7Eo2Gq15b2tg1vMkOGqJ
         9BwLA4iHcNoLH8MLelPB9iJgW4w6O7DBcaYLu5cuZvgsrnbrtNGvNNnOwCYLMBsTKJRc
         LaVBWABDTjd7tT4y1TYdac5RwafRa1mhr0drsVP79KzolKQW9sKfINmcUKCI44HJWVqk
         roSQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :date:cc:to:from:subject:message-id:sender:dkim-signature;
        bh=i6sJ/bhrBDwi5l59L14pgtD45W7mPhvt/+ZguQBhyEY=;
        b=bZdw0BfkFrJAIhyeIS1uoN6O1uHAwmCNPuDu/MURZHj8maOhSURvZmso2154nT0slu
         v+e7LXy4sXV4g7y/WR7LVmMJ42l48YbQc6/Z9nmbd+R/ABgKon4I+MxY7X6hcyJj16PD
         4peyfNnAJdQUA0PUj+TKmOcDvlc+kFSA6qeIKFJ7+Sl7x5VzCaku79NvOxv8icH8gqBj
         WuQ4tBQYsM2IsZxisusjqZuhvXcWPHLTNqjtMs7CtptxnUmvByCivfRYtrLH3q3jpnOj
         av4pjTuRTZedqMwsWrc/BIO8TiPJ9bnkToKr5P7f7+mNIIfbGrHi+P3DmdVGQG3fe0go
         PvPg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of kuan-ying.lee@mediatek.com designates 60.244.123.138 as permitted sender) smtp.mailfrom=kuan-ying.lee@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:message-id:subject:from:to:cc:date:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=i6sJ/bhrBDwi5l59L14pgtD45W7mPhvt/+ZguQBhyEY=;
        b=WGtJIQ8MpEz9RajpzwG6tCpcRJn4X4CF/2+Ec8XST3WXVOYRzzX358wfIVZ7o8XWSC
         76ZUFHzh1NuLJl2S4+y/BfXjJD6dR3m5syZnrBrp+hYiSC6VbMD9omozzFgd44Lc6iRm
         vbe50hRp8fnnjVSRcr5yNOLBy1AxkybsiOLQUdAbvNntb/wWECJLKBvt2P5NinDsyI7j
         1BS1pCvD5qzag41DWY7yfkpg9v12GUR8vev9D72nOKH2a4eLyQA0zRa6W82lmpptbWWM
         h2tmSODhzc/5XZXcZSxhR8qI/7fdZUmlx1dpUPUACYz5za7WBH0b6IZOB3HQcm1NdjsZ
         ZWMA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:message-id:subject:from:to:cc:date
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=i6sJ/bhrBDwi5l59L14pgtD45W7mPhvt/+ZguQBhyEY=;
        b=xOHKceDwqpcOsmlzM7Hqz0vdI5CYSuX3GQt3NqyXyzdt47WEnJnFaDZSAhDOa/V07p
         MSy105B+WzrmvxklMlW7IPwUzjouIn1XiDlHiFGtux4x4JX+hYAOmsY7Grpx9NVNTggg
         +pFoJc81dDM+7GQ6/EmH6Yc/VPPRNCTdrNRBriEPkVhmK0fLgiB1YKt9vYUn335WZHYY
         65cLrNMoXh/U604Dn1ABQq5leS4ZVV3ai2p1hd3FuXgoVvKDZhDcAhf1c8MoW/ZTv+/D
         e8jFcmF/ZGuwxyperScb69rMM7HdLzN2B06SobqR1d4/CQLdjVqua8r2oXGl1YPz9rWg
         rBwg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533GS/C8y4EGDGJP03EPdiBswcjTodnNEmWANqCFxe5jmeFy7ezM
	OhiTwSmOqrv/j6AfnO2ByMs=
X-Google-Smtp-Source: ABdhPJxeTlgHnZ7ekUweV1k+pxK60n3v7TGb+a23T0TTtkzDMsnwa3LBcEsntRObpkBRBNqCqRKnVg==
X-Received: by 2002:a17:902:aa43:b0:143:e20b:f37f with SMTP id c3-20020a170902aa4300b00143e20bf37fmr13085475plr.65.1637719251240;
        Tue, 23 Nov 2021 18:00:51 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:903:244f:: with SMTP id l15ls7756793pls.8.gmail; Tue, 23
 Nov 2021 18:00:50 -0800 (PST)
X-Received: by 2002:a17:902:ec8f:b0:142:11b8:eaaa with SMTP id x15-20020a170902ec8f00b0014211b8eaaamr13165685plg.81.1637719250671;
        Tue, 23 Nov 2021 18:00:50 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1637719250; cv=none;
        d=google.com; s=arc-20160816;
        b=iJplSKGTQc90vIkAKvgLKl5eR7sKYpx5EZwk5zD9fTQRoIBeMVdm5V8xl60I1Us4x3
         xjX3F2lxMncVQGH3Dsl0V3E6iPfbhRVqzDyxeiFx2dyJX+ZJj+avmQD8idSiYSAhz4NN
         bu+u+rwUFroYx7jylRQTw/wqCTs+OwGhDK6jBz+xbFSWK6ES3kp4VWzkKyy8ibd+Sm69
         JOGEYXgE1M7sNmTHyA2NrYsqBuvQeIS3LhsGEFCSu4mNixRGUeeV/Pd6PpSQ7Lh9eCFH
         3oItKkEKYyjRUdw9KeTmnIP2k9gndr2jDbgOJ4ijNT69kbdVPBY0AYRPh+3wmMjPn0mZ
         7Duw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to:date
         :cc:to:from:subject:message-id;
        bh=7CzAIKKMk4W1fUBZqdbfxpO8VBjcogJU9mg0JvZS7a0=;
        b=hPwObPlXanEkuWxDGElRujdjsGsHxa0dIvqm7Ro2K8bKVY+ILbWeo0itQbcShiMVyL
         15biQbJ7p52E0ZEVViPNRFgmjqVFHgd3iqS2obtAeMWgfYT8x6ywlo9db0JTmV27G5Y8
         SV/oTWqbGk8LCL2HQA5W7vmGKIOolWWgkL6hLWoCxNc2KLonwpw0q/ecYM7iL6IIp8k/
         gBw41kxFTG3mvP9AABTZiQT/w4KTCTAmzE7nax5lvjGkTtb9fAYc408VPLwJ9nTaWKVR
         KpTA4UrYBBu8Nj5XajDbsF8VNf8peMF8mEkLa9a9k6NfU6yoRe5wAmYm9rk4PWifZn9e
         Zpiw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of kuan-ying.lee@mediatek.com designates 60.244.123.138 as permitted sender) smtp.mailfrom=kuan-ying.lee@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw01.mediatek.com ([60.244.123.138])
        by gmr-mx.google.com with ESMTPS id w4si1357955pjr.3.2021.11.23.18.00.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 23 Nov 2021 18:00:50 -0800 (PST)
Received-SPF: pass (google.com: domain of kuan-ying.lee@mediatek.com designates 60.244.123.138 as permitted sender) client-ip=60.244.123.138;
X-UUID: 232f9541005f4ef69e9d870df16a0b23-20211124
X-UUID: 232f9541005f4ef69e9d870df16a0b23-20211124
Received: from mtkexhb01.mediatek.inc [(172.21.101.102)] by mailgw01.mediatek.com
	(envelope-from <kuan-ying.lee@mediatek.com>)
	(Generic MTA with TLSv1.2 ECDHE-RSA-AES256-SHA384 256/256)
	with ESMTP id 940110250; Wed, 24 Nov 2021 10:00:46 +0800
Received: from mtkcas11.mediatek.inc (172.21.101.40) by
 mtkmbs07n2.mediatek.inc (172.21.101.141) with Microsoft SMTP Server (TLS) id
 15.0.1497.2; Wed, 24 Nov 2021 10:00:45 +0800
Received: from mtksdccf07 (172.21.84.99) by mtkcas11.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1497.2 via Frontend
 Transport; Wed, 24 Nov 2021 10:00:45 +0800
Message-ID: <3de431c5711c0f6475f54e89c3de601e1279752a.camel@mediatek.com>
Subject: Re: [PATCH] kmemleak: fix kmemleak false positive report with HW
 tag-based kasan enable
From: Kuan-Ying Lee <Kuan-Ying.Lee@mediatek.com>
To: Andrew Morton <akpm@linux-foundation.org>
CC: Andrey Konovalov <andreyknvl@gmail.com>, Catalin Marinas
	<catalin.marinas@arm.com>, Matthias Brugger <matthias.bgg@gmail.com>, Chinwen
 Chang =?UTF-8?Q?=28=E5=BC=B5=E9=8C=A6=E6=96=87=29?=
	<chinwen.chang@mediatek.com>, Nicholas Tang
 =?UTF-8?Q?=28=E9=84=AD=E7=A7=A6=E8=BC=9D=29?= <nicholas.tang@mediatek.com>,
	Yee Lee =?UTF-8?Q?=28=E6=9D=8E=E5=BB=BA=E8=AA=BC=29?= <Yee.Lee@mediatek.com>,
	"linux-mm@kvack.org" <linux-mm@kvack.org>, "linux-kernel@vger.kernel.org"
	<linux-kernel@vger.kernel.org>, "linux-arm-kernel@lists.infradead.org"
	<linux-arm-kernel@lists.infradead.org>, "linux-mediatek@lists.infradead.org"
	<linux-mediatek@lists.infradead.org>, kasan-dev <kasan-dev@googlegroups.com>,
	<james.hsu@mediatek.com>, <kuan-ying.lee@mediatek.com>
Date: Wed, 24 Nov 2021 10:00:45 +0800
In-Reply-To: <20211119144359.b70d2fde7631bd14cd9652e3@linux-foundation.org>
References: <20211118054426.4123-1-Kuan-Ying.Lee@mediatek.com>
	 <754511d9a0368065768cc3ad8037184d62c3fbd1.camel@mediatek.com>
	 <CA+fCnZddknY6XLychkAUkf9eYvEW4z9Oyr8cZb2QfBMDkJ23zg@mail.gmail.com>
	 <c5cfd0c41dee93cd923762a6e0d61baea52cec8d.camel@mediatek.com>
	 <20211119144359.b70d2fde7631bd14cd9652e3@linux-foundation.org>
Content-Type: text/plain; charset="UTF-8"
X-Mailer: Evolution 3.28.5-0ubuntu0.18.04.2
MIME-Version: 1.0
X-MTK: N
X-Original-Sender: Kuan-Ying.Lee@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of kuan-ying.lee@mediatek.com designates 60.244.123.138
 as permitted sender) smtp.mailfrom=kuan-ying.lee@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
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

On Sat, 2021-11-20 at 06:43 +0800, Andrew Morton wrote:
> On Fri, 19 Nov 2021 23:12:55 +0800 Kuan-Ying Lee <
> Kuan-Ying.Lee@mediatek.com> wrote:
> 
> > > > > Call sequence:
> > > > > ptr = kmalloc(size, GFP_KERNEL);
> > > > > page = virt_to_page(ptr);
> > > > > kfree(page_address(page));
> > > > > ptr = kmalloc(size, GFP_KERNEL);
> > > 
> > > How is this call sequence valid? page_address returns the address
> > > of
> > > the start of the page, while kmalloced object could have been
> > > located
> > > in the middle of it.
> > 
> > Thanks for pointing out. I miss the offset.
> > 
> > It should be listed as below.
> > 
> > ptr = kmalloc(size, GFP_KERNEL);
> > page = virt_to_page(ptr);
> > offset = offset_in_page(ptr);
> > kfree(page_address(page) + offset);
> > ptr = kmalloc(size, GFP_KERNEL);
> 
> I updated the changelog to reflect this.

Thanks for updating changelog. :)

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/3de431c5711c0f6475f54e89c3de601e1279752a.camel%40mediatek.com.
