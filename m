Return-Path: <kasan-dev+bncBAABBCMYRLUAKGQEEAZDGHI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83d.google.com (mail-qt1-x83d.google.com [IPv6:2607:f8b0:4864:20::83d])
	by mail.lfdr.de (Postfix) with ESMTPS id 80FE8449DE
	for <lists+kasan-dev@lfdr.de>; Thu, 13 Jun 2019 19:46:50 +0200 (CEST)
Received: by mail-qt1-x83d.google.com with SMTP id p43sf12452617qtk.23
        for <lists+kasan-dev@lfdr.de>; Thu, 13 Jun 2019 10:46:50 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1560448009; cv=pass;
        d=google.com; s=arc-20160816;
        b=qcqq5erW2n23buQ+3DxaIXtLx2dBtkdzLPbsFsxtj467H8RmuDF/pz9i9M5rK08JhJ
         XIUueARVYx1PV+W1Eds5XRbucC+w02HC8AwCXfmSl6Z097cjaWuZj8hFM6DEa8xQ4yAx
         2gV7as3wEss6+rWxy5D40bSlxa62lecKs8S/a7gh2iUo4fYAxDnH1P2u3CbFSex8pdeY
         jWfJ927WHcd36a8AzgOK7urOSKXgPTDcRU+Rrj0l2yk2gLVAhIqGU9QfyLSyjz5L4mb/
         /U+5nKxB00R9QjJkAxfU9Qxl7iPro8m7k0aX3YYvJ4KoILwCnzHnpKQoAySdz4QR03a3
         hPXA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :date:cc:to:from:subject:message-id:sender:dkim-signature;
        bh=5RigpeY011qMYhjnhTECo+ZE17sF5PqMVQn/RtiquXg=;
        b=mJEAozmnbZDUK148C4xCmJvFqoqMxOLco4a7rLByovL/dOcqzQdmCDOFa12qeDPG88
         Sw/ou88JP7kxd4Tyk5qXNqKYw+SI9rtZmbaLbkZOgPHJEnHeZH1FUiKnX90bAj6jTsNj
         RnuS96+EPi7cMnAxP4cIT1hQ6aE8Kbu88gwsAXNAWw/WSgym6y6gJvpvIOOZTEae4tdu
         Xj7OboJPTSwKiaqP8o2Vn7EONrgzsiYA3M3VveUXk3WzHRWFqtgoag4CTgun2nDiUBNW
         NwZYgivxCgNBGMF/btnyaajn9eiQafWltgUyjOa3eMK/zhrYb7ZpzGduV/RFjaT6X9U7
         08SQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:message-id:subject:from:to:cc:date:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=5RigpeY011qMYhjnhTECo+ZE17sF5PqMVQn/RtiquXg=;
        b=AwNLyWukNZx0Z2Uz4O7P+2QcB7zHlcl3oQt4JZ1d9aui1qEoiMmVLB/hyF3ui+BvwY
         cbyzSAoZkmmvFs48DpLYErpf1qvCGDK12FbpO5xhguU7t/gk69LJlF/5+c9jN8jVPW2E
         H3a/dpcpWrmhIOfqVbLiQFmUoJWR4sZR+QM3FSxmzx3L87+39B8GncNVllmG0zOu29zH
         +6xOBlIOuCbHaVr6ZyenFFbmDWhHlDN0oZxdLVCXDYdNW3nCprGsNFpbB1r75LHw0yLe
         mKX01vQjnXIyTsoUIOc26EOP7YAZ+100ZDIJ/ywwLe0/MfZw8hWLHEj//YOZbAlTXaoJ
         0Hww==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:message-id:subject:from:to:cc:date
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=5RigpeY011qMYhjnhTECo+ZE17sF5PqMVQn/RtiquXg=;
        b=g9mbt3/zNXdoEhO1P8cfjoz4e+Pp1tJrk23SsV0fC4vV2s4QF3j33+W/AQaRSEEo0v
         mptP0RGfMeDBIkdcsSPy/tkz042sQSyRWsUq3EjmrSRTfvvjNTsw1JSxfXIX8xp6y21H
         8Ncivwxo7XO0bqVi0DM93VIia7ZII4ep0xy9XcrXRjLjVd+Qqlbj9sM9RTHhqmEEC/pJ
         eM6HpTEHeESA+xSwgnUuzByGrNvWurnr/XpE94nHesNfPBQlezCbfNakh2eY8qx74fZH
         fLvkkbBPeX/YPxoobmaKa1LrURGoEyjRxqOZVOmPNGx/UGWKYEEbdyqaC4heJpmMjlRN
         VtGA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAWBcu9/Z8993xhKIj5D6RrFLdm6oDp6W4ogy6FT6f7m3BiJo45v
	sCgc+j1uBxiMv1HB4PNpAR0=
X-Google-Smtp-Source: APXvYqyRuopTWLcfaPnjddjFIeIiNe8uZydN//jgjdQ8UqyVHRA1PH66PSgbK/98tRJTBEDbdJejKA==
X-Received: by 2002:ac8:877:: with SMTP id x52mr77292666qth.328.1560448009629;
        Thu, 13 Jun 2019 10:46:49 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:7609:: with SMTP id t9ls1688790qtq.0.gmail; Thu, 13 Jun
 2019 10:46:49 -0700 (PDT)
X-Received: by 2002:ac8:d8:: with SMTP id d24mr47291685qtg.284.1560448009330;
        Thu, 13 Jun 2019 10:46:49 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1560448009; cv=none;
        d=google.com; s=arc-20160816;
        b=QJPzP3tn928atvQfW4p/5uUb1RFhiTBE3+yPBdYfT6VytI+27yoemnyl/3BBslQQAC
         kxzIf0f9HkYDI3+uM1MfcdTLzyGHjO20t3haTZ//o5o+xysVWWtv7X9P3nyPPq07Jipj
         ak9tAIbJGllfkUdpREvBZgrA4WKezTGy4vlG8ikllJijBouQqsoIYT5cejLdUQiuXSZI
         ADaOcTqFEubRonVDRii7tn7mJZqEvW5Rb77rLiLcT72UQErDSg2wH2NoVGSiPfsNbGxV
         9DwrkitOGLxuugLdepPxeEBpqCG7Z67nT0c1fE+eq7/iIRIvH5HtdEvtpA4H38AHquBw
         aNDg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:content-transfer-encoding:references:in-reply-to:date
         :cc:to:from:subject:message-id;
        bh=lEzlxuvpSMrNR4n7z6yfIaw8K7RTxUxdTVJa0UdpOPk=;
        b=E124ydrY12ugZIMP/RW8DLzsSawuZzD3mCqNSB5vRmdHntDmvLBDT27N5yHmD5oFsY
         9uOEnPpIFJAIX9aYoUQEBG3ud2HQw3kKOvw0e+TGMb8rwVWPD5fW3NMlmLRTY3X/nzkC
         M9tp9wxinp+E7XeC+qVX4WkF0mC6Bi3g1OOm//ACFJhVxZsDO8IT2BCTM+DrBPwSN2Lc
         xXrmLICyPLnx/XsA7/BJ8bvD36dpMZsljUsZKFMcFsdT3xMCS4D1FskqB7I0QpvVZgqS
         R4PH4kZKmxFXYhqXilsgsbVTyTZMmCK/seeWx3rdfxdhKvhwyL0ZT2L83hr14n0weFqK
         CAlg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com
Received: from mailgw01.mediatek.com ([210.61.82.183])
        by gmr-mx.google.com with ESMTPS id m55si30140qtm.0.2019.06.13.10.46.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 13 Jun 2019 10:46:48 -0700 (PDT)
Received-SPF: pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) client-ip=210.61.82.183;
X-UUID: 1bc9fbe28e904bcf97072f05f18c0602-20190614
X-UUID: 1bc9fbe28e904bcf97072f05f18c0602-20190614
Received: from mtkcas06.mediatek.inc [(172.21.101.30)] by mailgw01.mediatek.com
	(envelope-from <walter-zh.wu@mediatek.com>)
	(mhqrelay.mediatek.com ESMTP with TLS)
	with ESMTP id 795620865; Fri, 14 Jun 2019 01:46:41 +0800
Received: from mtkcas08.mediatek.inc (172.21.101.126) by
 mtkmbs08n2.mediatek.inc (172.21.101.56) with Microsoft SMTP Server (TLS) id
 15.0.1395.4; Fri, 14 Jun 2019 01:46:39 +0800
Received: from [172.21.84.99] (172.21.84.99) by mtkcas08.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1395.4 via Frontend
 Transport; Fri, 14 Jun 2019 01:46:39 +0800
Message-ID: <1560447999.15814.15.camel@mtksdccf07>
Subject: Re: [PATCH v3] kasan: add memory corruption identification for
 software tag-based mode
From: Walter Wu <walter-zh.wu@mediatek.com>
To: Andrey Ryabinin <aryabinin@virtuozzo.com>
CC: Alexander Potapenko <glider@google.com>, Dmitry Vyukov
	<dvyukov@google.com>, Christoph Lameter <cl@linux.com>, Pekka Enberg
	<penberg@kernel.org>, David Rientjes <rientjes@google.com>, Joonsoo Kim
	<iamjoonsoo.kim@lge.com>, Matthias Brugger <matthias.bgg@gmail.com>, "Martin
 Schwidefsky" <schwidefsky@de.ibm.com>, Arnd Bergmann <arnd@arndb.de>, "Vasily
 Gorbik" <gor@linux.ibm.com>, Andrey Konovalov <andreyknvl@google.com>, "Jason
 A . Donenfeld" <Jason@zx2c4.com>, Miles Chen <miles.chen@mediatek.com>,
	<kasan-dev@googlegroups.com>, <linux-kernel@vger.kernel.org>,
	<linux-mm@kvack.org>, <linux-arm-kernel@lists.infradead.org>,
	<linux-mediatek@lists.infradead.org>, <wsd_upstream@mediatek.com>
Date: Fri, 14 Jun 2019 01:46:39 +0800
In-Reply-To: <da7591c9-660d-d380-d59e-6d70b39eaa6b@virtuozzo.com>
References: <20190613081357.1360-1-walter-zh.wu@mediatek.com>
	 <da7591c9-660d-d380-d59e-6d70b39eaa6b@virtuozzo.com>
Content-Type: text/plain; charset="UTF-8"
X-Mailer: Evolution 3.2.3-0ubuntu6
MIME-Version: 1.0
X-TM-SNTS-SMTP: 73E573334F60FA682523A92B528AE4E79ADB9EB515874F36690B616CC9E25A672000:8
X-MTK: N
X-Original-Sender: walter-zh.wu@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as
 permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com
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

On Thu, 2019-06-13 at 15:27 +0300, Andrey Ryabinin wrote:
> 
> On 6/13/19 11:13 AM, Walter Wu wrote:
> > This patch adds memory corruption identification at bug report for
> > software tag-based mode, the report show whether it is "use-after-free"
> > or "out-of-bound" error instead of "invalid-access" error.This will make
> > it easier for programmers to see the memory corruption problem.
> > 
> > Now we extend the quarantine to support both generic and tag-based kasan.
> > For tag-based kasan, the quarantine stores only freed object information
> > to check if an object is freed recently. When tag-based kasan reports an
> > error, we can check if the tagged addr is in the quarantine and make a
> > good guess if the object is more like "use-after-free" or "out-of-bound".
> > 
> 
> 
> We already have all the information and don't need the quarantine to make such guess.
> Basically if shadow of the first byte of object has the same tag as tag in pointer than it's out-of-bounds,
> otherwise it's use-after-free.
> 
> In pseudo-code it's something like this:
> 
> u8 object_tag = *(u8 *)kasan_mem_to_shadow(nearest_object(cacche, page, access_addr));
> 
> if (access_addr_tag == object_tag && object_tag != KASAN_TAG_INVALID)
> 	// out-of-bounds
> else
> 	// use-after-free

Thanks your explanation.
I see, we can use it to decide corruption type.
But some use-after-free issues, it may not have accurate free-backtrace.
Unfortunately in that situation, free-backtrace is the most important.
please see below example

In generic KASAN, it gets accurate free-backrace(ptr1).
In tag-based KASAN, it gets wrong free-backtrace(ptr2). It will make
programmer misjudge, so they may not believe tag-based KASAN.
So We provide this patch, we hope tag-based KASAN bug report is the same
accurate with generic KASAN.

---
    ptr1 = kmalloc(size, GFP_KERNEL);
    ptr1_free(ptr1);

    ptr2 = kmalloc(size, GFP_KERNEL);
    ptr2_free(ptr2);

    ptr1[size] = 'x';  //corruption here


static noinline void ptr1_free(char* ptr)
{
    kfree(ptr);
}
static noinline void ptr2_free(char* ptr)
{
    kfree(ptr);
}
---


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To post to this group, send email to kasan-dev@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1560447999.15814.15.camel%40mtksdccf07.
For more options, visit https://groups.google.com/d/optout.
