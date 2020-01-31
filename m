Return-Path: <kasan-dev+bncBAABBP5NZ3YQKGQEAVXCQLI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-xc3f.google.com (mail-yw1-xc3f.google.com [IPv6:2607:f8b0:4864:20::c3f])
	by mail.lfdr.de (Postfix) with ESMTPS id EEBE814E749
	for <lists+kasan-dev@lfdr.de>; Fri, 31 Jan 2020 03:53:52 +0100 (CET)
Received: by mail-yw1-xc3f.google.com with SMTP id j9sf5369178ywg.14
        for <lists+kasan-dev@lfdr.de>; Thu, 30 Jan 2020 18:53:52 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1580439232; cv=pass;
        d=google.com; s=arc-20160816;
        b=ZX3cRmtOmtXbbLuN0vDa+rQbwYePNSXxw1+wmy6Niw24K4TJfBtF2+iqhf1E7p5fd/
         ey0jChIshOILNcXGX3J2Hs/mLkurEFyCRP2z+pDmKymR1IUrCFXyjuhd7efb1e/LbG0X
         p5NCQW3+KaBtB/2RRGDpTatjnBOFTxs+qTULKZJkPLoWcrRx+8np2dnwLje1xSbsyNcD
         qX5iGXZ2hItBC68gXuPLt596L8Gy2RM1ORBMHERuE9dqkbb0X2MKXia2QIUbE3J9scI/
         CnZFWbNfPgelHkVQ1djrlaCY/NAo0jYpKjKBkyrdNBNH8UsQqeVWGggg6UGdqxVnwLHe
         aB1g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :date:cc:to:from:subject:message-id:sender:dkim-signature;
        bh=XVBVTEZ5joK/b58l+I/AJnMfAAM051Gtqv+U85xcqiA=;
        b=RzOqFuQ87VOgGb8CkZZXa6P3L52FJNli7KiYDSCxpolRUdqpVfJRLMLQ/kdjjl6Ynm
         03NXOloaSGnqypGgkWf9Q0eN91DqGiVBtSy/yQJ9RKmZmw72ChPnjWfyE1BiGvM6Vo0u
         82NCmKmyavZlsbnJETqoKUeYwgDo+/+tapxXLYaw5RadsDs9Naie7Gx3mhUaaZN73L81
         MfDFGbEdJkcKzT76Qe6SO3i1ZBsqpt8p2z9+thC/dznNS75dPUXa3xCrY23YfXQmkWiS
         pwIMZssMz6g+jyXBXzBCvqFzrsPk+WupoSoDaHkQK5giezaivUTHvFynZxp65Od2AqYD
         cS/g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=kU2cMA3o;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:message-id:subject:from:to:cc:date:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=XVBVTEZ5joK/b58l+I/AJnMfAAM051Gtqv+U85xcqiA=;
        b=qLVZ07C0WjnIa02saCmxt4H8V0tx2TDYC0OV4muL2yla1y84UsVAufaVp1QDfU9XBO
         e+1rxQwM+KSWLRnO4rKapq5adGlLmW+kZhdVVWeIH6wdltclubxu8/61KrUlMt2twfwY
         V5ZNGR0tWE1HTFlh/bhCB1CoRr25CBuJyTXQuvUUhudNV1F9+6XPz42DSFKN7+EGS3TQ
         PkXcgqk9Q+1Ki3bkcZcTDs06jHbHYg8EHxn5M3ywxQl2TwIvJiWXOIJTstX17zuyKMjM
         9+rPlJCTOcsTBlyxDCYRE92IEa4Lpmk8qL+vefLj+JyDRxeAyLJGwuekguHsg1L/5LCL
         xCtg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:message-id:subject:from:to:cc:date
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=XVBVTEZ5joK/b58l+I/AJnMfAAM051Gtqv+U85xcqiA=;
        b=Ja1gYo3suxxjcGuvRt/w6GU475m+kkNWFQ4IrlOjsuQfYWBMVqVza50oJTB/53I5Jx
         SJWOE3GtREbd74MWGbGBu3db/fY239XHjnCqgpUpMzm+CP1a4Uu8YSjHxhzqKfOr6zMO
         6fbg9ZQXUn930z9zQkxy/M+FqlwuxHqqPl5xN2XtmYQrvxa8WIZdIkjePkNwFOnFE47A
         fgVy4OA12k2nfEtuug6vgfChEmZ1yGV9xPoaTKqQ8HVLl4x9l3xH0cPr7rSJDRgGtk/l
         NGimKhy7UnDYiWo7GY6w68QxCjnwWqJwt7XufkZl/Ckotq5wBGtQDlVZdUGSJvGFxPGb
         tMnw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAUDXAd5XqCcbFn2W1WcLJhdFBHlpjql1grWAijdeKywx436aRkm
	ryvfAABYwWoeJas2wywyhnQ=
X-Google-Smtp-Source: APXvYqxKov0ZOMxeOOHds0pFUci+zUk1s2ebKasoEx0AXXmXsoLliuOCHFZS/nVbes6db4JuTmDHHQ==
X-Received: by 2002:a81:f006:: with SMTP id p6mr6512134ywm.483.1580439231830;
        Thu, 30 Jan 2020 18:53:51 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:5d09:: with SMTP id r9ls104313ybb.2.gmail; Thu, 30 Jan
 2020 18:53:51 -0800 (PST)
X-Received: by 2002:a25:8601:: with SMTP id y1mr6735413ybk.193.1580439231468;
        Thu, 30 Jan 2020 18:53:51 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1580439231; cv=none;
        d=google.com; s=arc-20160816;
        b=aqxRG8X1/l2BsrTpSO7V8foM/Q0vqn9Hn+ig2a4leS7E/pNbsDAyqj49qfEGNsvr4d
         G29epJDvVSuRaBU+4pva9aQ8hdrAEABHYFZB31/weKuFxqpl5qtIP+sewHf8bLksRiqZ
         DlDZmDU5F7MXDtHBvL4OrkVnK63rG/D1BCR/oR4DUVHVzbhDJ9V69JPV8tsrkzH5lidj
         6m8XDLgPawv/k2ACGCpUabkha1z+qYwJyb/aI54C1+ZhQ0r+Ra3PIkhHu/VLJ83n8TP+
         Aje0FyiiXm+AZ/3gNQQYAZa+0Y1ZPk6jl7ZmOPayXxjYA2IslieHhTwCsmdv/UGL+UN6
         Djwg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to:date
         :cc:to:from:subject:message-id:dkim-signature;
        bh=J/YS9xrz7SE39sg55EiuDt9slMVYOmJaP+90r0kGMF8=;
        b=P0n3Shp3U2f34iOEF04DMKfd9ydQgrEuHeGwVBZERYcNOQDJTnZa9fkGjdJ09fxsV9
         6eNl6ea5gxC+bsNzQ7zVf4I5X3ROb1JCoy7G0TrVO7QOFqUmm84CJKAapVorEuIlmcxq
         mWGAfurmXy2VCxPRxli2JGbOUcUixX9yEwXrDUmd8+q4wy8XQc/oAnTniK6qDqfC/NM2
         Ff3GAW1GuGFbg1D+nFHbwMgZd3vgiAhraoMe9u0AhS0jKfD7QdlS9m2LAPir+DaN4xXF
         qNndQoM8hiXjwCcwdmfP6ay5kVrXs9GdSxORQS+3AMnkUVOGCDRtDLJMWqwxEtwufm4n
         i6Xg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=kU2cMA3o;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw02.mediatek.com ([210.61.82.184])
        by gmr-mx.google.com with ESMTP id p187si361468ywe.1.2020.01.30.18.53.50
        for <kasan-dev@googlegroups.com>;
        Thu, 30 Jan 2020 18:53:51 -0800 (PST)
Received-SPF: pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) client-ip=210.61.82.184;
X-UUID: 2ed2632f77c344a2a0c204df28cb0362-20200131
X-UUID: 2ed2632f77c344a2a0c204df28cb0362-20200131
Received: from mtkcas09.mediatek.inc [(172.21.101.178)] by mailgw02.mediatek.com
	(envelope-from <walter-zh.wu@mediatek.com>)
	(Cellopoint E-mail Firewall v4.1.10 Build 0809 with TLS)
	with ESMTP id 646680630; Fri, 31 Jan 2020 10:53:46 +0800
Received: from MTKCAS06.mediatek.inc (172.21.101.30) by
 mtkmbs07n1.mediatek.inc (172.21.101.16) with Microsoft SMTP Server (TLS) id
 15.0.1395.4; Fri, 31 Jan 2020 10:53:02 +0800
Received: from [172.21.84.99] (172.21.84.99) by MTKCAS06.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1395.4 via Frontend
 Transport; Fri, 31 Jan 2020 10:51:23 +0800
Message-ID: <1580439225.11126.34.camel@mtksdccf07>
Subject: Re: [PATCH v4 2/2] kasan: add test for invalid size in memmove
From: Walter Wu <walter-zh.wu@mediatek.com>
To: Andrew Morton <akpm@linux-foundation.org>
CC: Andrey Ryabinin <aryabinin@virtuozzo.com>, Dmitry Vyukov
	<dvyukov@google.com>, Alexander Potapenko <glider@google.com>, "Matthias
 Brugger" <matthias.bgg@gmail.com>, "kasan-dev@googlegroups.com"
	<kasan-dev@googlegroups.com>, "linux-mm@kvack.org" <linux-mm@kvack.org>,
	"linux-kernel@vger.kernel.org" <linux-kernel@vger.kernel.org>,
	"linux-arm-kernel@lists.infradead.org"
	<linux-arm-kernel@lists.infradead.org>, wsd_upstream
	<wsd_upstream@mediatek.com>, "linux-mediatek@lists.infradead.org"
	<linux-mediatek@lists.infradead.org>
Date: Fri, 31 Jan 2020 10:53:45 +0800
In-Reply-To: <20200130181613.1bfb8df8e73a280512cab8ef@linux-foundation.org>
References: <20191112065313.7060-1-walter-zh.wu@mediatek.com>
	 <619b898f-f9c2-1185-5ea7-b9bf21924942@virtuozzo.com>
	 <1580355838.11126.5.camel@mtksdccf07>
	 <20200130181613.1bfb8df8e73a280512cab8ef@linux-foundation.org>
Content-Type: text/plain; charset="UTF-8"
X-Mailer: Evolution 3.2.3-0ubuntu6
MIME-Version: 1.0
X-MTK: N
X-Original-Sender: walter-zh.wu@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@mediatek.com header.s=dk header.b=kU2cMA3o;       spf=pass
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

On Thu, 2020-01-30 at 18:16 -0800, Andrew Morton wrote:
> On Thu, 30 Jan 2020 11:43:58 +0800 Walter Wu <walter-zh.wu@mediatek.com> wrote:
> 
> > On Fri, 2019-11-22 at 06:21 +0800, Andrey Ryabinin wrote:
> > > 
> > > On 11/12/19 9:53 AM, Walter Wu wrote:
> > > > Test negative size in memmove in order to verify whether it correctly
> > > > get KASAN report.
> > > > 
> > > > Casting negative numbers to size_t would indeed turn up as a large
> > > > size_t, so it will have out-of-bounds bug and be detected by KASAN.
> > > > 
> > > > Signed-off-by: Walter Wu <walter-zh.wu@mediatek.com>
> > > > Reviewed-by: Dmitry Vyukov <dvyukov@google.com>
> > > 
> > > Reviewed-by: Andrey Ryabinin <aryabinin@virtuozzo.com>
> > 
> > Hi Andrey, Dmitry, Andrew,
> > 
> > Would you tell me why this patch-sets don't merge into linux-next tree?
> > We lost something?
> > 
> 
> In response to [1/2] Andrey said "So let's keep this code as this" and
> you said "I will send a new v5 patch tomorrow".  So we're awaiting a v5
> patchset?
> 

Hi Andrew,

The [1/2] patch discussion shows below. Thanks for Dimitry help to
explain it. So that v4 patchset got Andrey's signature. Because I see
Andrey said "But I see you point now. No objections to the patch in that
case."

@Andrey, if I have an incorrect understanding, please let me know. 
Thanks for your help.

https://lkml.org/lkml/2019/11/21/1019
https://lkml.org/lkml/2019/11/21/1020


Walter

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1580439225.11126.34.camel%40mtksdccf07.
