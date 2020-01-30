Return-Path: <kasan-dev+bncBAABBBFCZHYQKGQEHEIID4A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53d.google.com (mail-pg1-x53d.google.com [IPv6:2607:f8b0:4864:20::53d])
	by mail.lfdr.de (Postfix) with ESMTPS id 97C4114D564
	for <lists+kasan-dev@lfdr.de>; Thu, 30 Jan 2020 04:44:05 +0100 (CET)
Received: by mail-pg1-x53d.google.com with SMTP id d129sf1084883pgc.17
        for <lists+kasan-dev@lfdr.de>; Wed, 29 Jan 2020 19:44:05 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1580355844; cv=pass;
        d=google.com; s=arc-20160816;
        b=JpBv9GYtZzorjCOYoTiD8JF1IzLKxnERMAeF+vxWv6dUz/tgMTypgqDum79+xyL6B5
         /1/n8UFoP+KKHYv2TFmVkmr/qCtcY+Y5v1L7OQrulHFH0t4lC00CJQ2ReDEXm6lqyScq
         1zfKxRsORVeSYObXvTsYPWFehzeOsBlzyqwRY+b87Ow0sM5EQMerlFBdJPU4KFI18JBx
         ylwjEPI7LBWZAvCWHdbgatYNKKn1xXzkUZewIDzMPK9z7LjfK77EBNx6/k2Wm/zTMnLt
         9uSKa8QXbKxIqU2QrWqQoqeqG4jpDvyuVYRr1xCTMqGkv6UyA+EaLYpAHUS72HIrZgvL
         etMg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :date:cc:to:from:subject:message-id:sender:dkim-signature;
        bh=4A4tnnk6IcfDsTqWwZjdDiuA70BqalypjwrvPSrW5fM=;
        b=kAwzxgzEKsV3IdBY4wb+pC8IJhcQxXNosUNvS0cR069co6Akda6Gwl1jqnJGs9jkSv
         3rO19g7mK5eRoDuGahSvb8dRTm74j+01RDYHtBuCJUvHP3yMnY3wtK2xSyCtjj6dv6Po
         vy801uLLxDBZ1bWv78UGrnHJmNiFs+5pbC11b+hA9u/X+nRVduTGhhaYRooPOpnWm6DT
         AIF6gIr5F+jF9VFetwEdHs1cWxFbZDjsK3k/b5gZPZeL+QvZZuiB42YkTKEBjO0vV7S1
         hzRpv2KuvyUQCXYZXZtjq3g34g3JUNVn9K+AQYLQwGAgzffdBPmDkwo3IUUB+a/jcVcV
         sQZQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=LvZByeUm;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:message-id:subject:from:to:cc:date:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=4A4tnnk6IcfDsTqWwZjdDiuA70BqalypjwrvPSrW5fM=;
        b=ICMFzHD2ndGnNfOhsaag7j5oUCu5U4+7+/KMhzj+YSTdJwBP872pfFD0VstqC1eCYj
         a9yZcK/no8G2pn32DBV6T94aVnUU8Lbxp4wIWV72REXykpMN2kZG5hY46CjjZVV4B4C5
         IFpSHnbJtJmWLofqncQwU/EEyUswGYtg9b6eWJrg1oLHRZa1ntMPD8x4QYz+BJ75MjUB
         ZmNt3LjMCWlR9HXGVRnj2l6SaNDqpIpcrepoUuWgYlLusOMYpP0tHaaxEo23xitD0b98
         VWTrO4uDQ6KV1X0vcQOavapj9eATX+umah22Vm5YTkkvoI1M5pLrzIkwYFjUiXB7fBWB
         aRPg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:message-id:subject:from:to:cc:date
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=4A4tnnk6IcfDsTqWwZjdDiuA70BqalypjwrvPSrW5fM=;
        b=B/tPTt9NHvsD/MYKQKfkHyzoYHYcL76sBBVO849Ju9EgMYpcCE/DHVzB5TMepU/LjV
         gYY5AtVwaBkU8CcB1dgu5XRRLs7sehO78KVLc/XFxOWT7RPJsB1VwWsGbkDi8Ylm+LMX
         28rAnSN+SQJ5BYA6clo3HHMc/zNX1LfvW8AEXgkHNAGQGKGsV5xgYOZTgW2dNXcDdVFQ
         LEOuCCqiquMI0WhjRLuQuWe+7jtC8qpW/jc94gFzhWkhgx4/d3jAQ4ac+kweGROjxXbr
         9iD2Utbsa/92SmTKPQIdKtyGHTyMgo/PWllBMlaVq/zABOzKS1MsDcMMpSh5Gssz8BN8
         cBYQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAV0E+OaYxcmD38Mwpb1VHvkxh0trQAyyctiCAiULyPw5YPbhFau
	rfT+j/g3WRA9qBPYwcGGH6M=
X-Google-Smtp-Source: APXvYqw3ldHc5meuwoOOb4or90prl7LksxgUSwlFxewegyXFWaml80Ijp/wDiQOGy/udTdqKIQ0vow==
X-Received: by 2002:a63:5a23:: with SMTP id o35mr2558449pgb.4.1580355844180;
        Wed, 29 Jan 2020 19:44:04 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:6483:: with SMTP id y125ls715309pfb.9.gmail; Wed, 29 Jan
 2020 19:44:03 -0800 (PST)
X-Received: by 2002:a65:49ca:: with SMTP id t10mr2648082pgs.37.1580355843763;
        Wed, 29 Jan 2020 19:44:03 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1580355843; cv=none;
        d=google.com; s=arc-20160816;
        b=tsvmevKBofdDU8UnnUpWgITZzLgXAzf0/tVCe2+74H5I6NVht9OC1P/kjJjged5A85
         k/tbT7BZbd6+aM29sMCLZWWd4tvOTKwwl12AOHWinm193jhAr1WzvtVtT6jz+pcRqGmX
         1TNVZUYYZ5TWCIEccAjabsuIXIFBKSK0m3lrgO2wbUyEEz0dBu8KFcpENOUqSaEiNEnP
         RnswpWOIo5D6bb0m30trlt+5WLElvN6z3f1AUY3Kg01zwkB0htcOhY7DcFnwiPwTuM5/
         4AL/gtzm3adUx2Z4dJSX9sSTSg3K0CIKjTvmXfD3h36ahcJgBmxbTnqkRIpEyJbgXaH5
         1F/g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to:date
         :cc:to:from:subject:message-id:dkim-signature;
        bh=3bvai5RkNO6CsB90bdkSQOYb8Boyue9WmpvdjPAjYrE=;
        b=X9LFAG34Vcf4vTYH+8Cd5mDHh4UvnEESIlBBuEflQinLNOtI8OBxCxH+HCVWI8GpJI
         6vYPydyfk5xCu4tFxmoxn2obgEwtXG2Ju2Q92AXIE76RpxlVXeTVVlih65QDXwYVDvZ9
         DdfeinaTiPH/8anKTAC3vR4VqI6utHaDkLT05CXzR5oWmZ+VsGDHt6ffDocgdJXORBPV
         pg/virQOlIXsmwASo13NVphfPh8fNzE6zwLLb1ZLtLpCU0rhshqbq71vaofBcIH5M6cT
         /AVpxLCiPnM8H/3jV3DKHJmJYSLsXFOWkXuohL7VeaZoTDyfIIP73co22x3djjQVZlT2
         ul6g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=LvZByeUm;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw02.mediatek.com ([210.61.82.184])
        by gmr-mx.google.com with ESMTP id f8si198323plr.2.2020.01.29.19.44.03
        for <kasan-dev@googlegroups.com>;
        Wed, 29 Jan 2020 19:44:03 -0800 (PST)
Received-SPF: pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) client-ip=210.61.82.184;
X-UUID: b27cc1cbc00d4125a60e144d1168b3d8-20200130
X-UUID: b27cc1cbc00d4125a60e144d1168b3d8-20200130
Received: from mtkcas07.mediatek.inc [(172.21.101.84)] by mailgw02.mediatek.com
	(envelope-from <walter-zh.wu@mediatek.com>)
	(Cellopoint E-mail Firewall v4.1.10 Build 0809 with TLS)
	with ESMTP id 1456654747; Thu, 30 Jan 2020 11:43:59 +0800
Received: from mtkcas08.mediatek.inc (172.21.101.126) by
 mtkmbs07n1.mediatek.inc (172.21.101.16) with Microsoft SMTP Server (TLS) id
 15.0.1395.4; Thu, 30 Jan 2020 11:43:15 +0800
Received: from [172.21.84.99] (172.21.84.99) by mtkcas08.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1395.4 via Frontend
 Transport; Thu, 30 Jan 2020 11:44:02 +0800
Message-ID: <1580355838.11126.5.camel@mtksdccf07>
Subject: Re: [PATCH v4 2/2] kasan: add test for invalid size in memmove
From: Walter Wu <walter-zh.wu@mediatek.com>
To: Andrey Ryabinin <aryabinin@virtuozzo.com>, Dmitry Vyukov
	<dvyukov@google.com>, Andrew Morton <akpm@linux-foundation.org>
CC: Alexander Potapenko <glider@google.com>, Dmitry Vyukov
	<dvyukov@google.com>, Matthias Brugger <matthias.bgg@gmail.com>,
	"kasan-dev@googlegroups.com" <kasan-dev@googlegroups.com>,
	"linux-mm@kvack.org" <linux-mm@kvack.org>, "linux-kernel@vger.kernel.org"
	<linux-kernel@vger.kernel.org>, "linux-arm-kernel@lists.infradead.org"
	<linux-arm-kernel@lists.infradead.org>, wsd_upstream
	<wsd_upstream@mediatek.com>, "linux-mediatek@lists.infradead.org"
	<linux-mediatek@lists.infradead.org>, Andrew Morton
	<akpm@linux-foundation.org>
Date: Thu, 30 Jan 2020 11:43:58 +0800
In-Reply-To: <619b898f-f9c2-1185-5ea7-b9bf21924942@virtuozzo.com>
References: <20191112065313.7060-1-walter-zh.wu@mediatek.com>
	 <619b898f-f9c2-1185-5ea7-b9bf21924942@virtuozzo.com>
Content-Type: text/plain; charset="UTF-8"
X-Mailer: Evolution 3.2.3-0ubuntu6
MIME-Version: 1.0
X-MTK: N
X-Original-Sender: walter-zh.wu@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@mediatek.com header.s=dk header.b=LvZByeUm;       spf=pass
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

On Fri, 2019-11-22 at 06:21 +0800, Andrey Ryabinin wrote:
> 
> On 11/12/19 9:53 AM, Walter Wu wrote:
> > Test negative size in memmove in order to verify whether it correctly
> > get KASAN report.
> > 
> > Casting negative numbers to size_t would indeed turn up as a large
> > size_t, so it will have out-of-bounds bug and be detected by KASAN.
> > 
> > Signed-off-by: Walter Wu <walter-zh.wu@mediatek.com>
> > Reviewed-by: Dmitry Vyukov <dvyukov@google.com>
> 
> Reviewed-by: Andrey Ryabinin <aryabinin@virtuozzo.com>

Hi Andrey, Dmitry, Andrew,

Would you tell me why this patch-sets don't merge into linux-next tree?
We lost something?

Thanks for your help.

Walter

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1580355838.11126.5.camel%40mtksdccf07.
