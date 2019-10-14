Return-Path: <kasan-dev+bncBAABBRFWR7WQKGQEPJTW67I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3b.google.com (mail-io1-xd3b.google.com [IPv6:2607:f8b0:4864:20::d3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 67563D5981
	for <lists+kasan-dev@lfdr.de>; Mon, 14 Oct 2019 04:19:50 +0200 (CEST)
Received: by mail-io1-xd3b.google.com with SMTP id a22sf24385874ioq.23
        for <lists+kasan-dev@lfdr.de>; Sun, 13 Oct 2019 19:19:50 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1571019589; cv=pass;
        d=google.com; s=arc-20160816;
        b=M/xmWs7jggz2+QvRToAo/9sXAb1++zQPm8JDGgrNhg95Daqi6Xxa3a8r4ZCLKWp8x2
         ZvSB+Txu+3ydKdiwfLRDMOO96XSUz5NHVBtv729WjawlLJAKuavUYMub9A3PnNPuRgoq
         s9lPzGCzZp5XgIeU0Dmcxwvl584w91QqAeSs1J0PO5ei9YOp2ouwprVEBQh2T0jmZHSl
         qMefmnvx3ZasiHYq0XNN0dJjgkcjAgWdNakpYxgw1cfKHM2xvYXN0rV1vluQh+632LFU
         qLiO6e6zdhDXiuqjcoxQxKeycJW42R3DZiPm3ofbU+JmFPJOOmlSUfd5jDvGUUfOjuLE
         ahPg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :date:cc:to:from:subject:message-id:sender:dkim-signature;
        bh=L1a3QsJvQVGFUItXw/ZQYo1eSHIE37fSrct5bfKHU8U=;
        b=aJah+tsYj2K2wogB2afValYyXOtvoMwuF0KPQRDzX0tNEMeUOevQEmytrH9lA4r4QT
         7HaUn3os+BP880AyK6NRwrAsQnm+PLxpryxL+ihzk9IojmG9f6UazlWtFVqWEOBFfM3Z
         tNpvFSiHmvG8IC1ZTwJqrb0AtchM+o3ELJ7REjm1Tt2aljb94b83lQnYaI8HdZTtnJBd
         utqhGyaOL6TNFUUCBRwtJQw4X9gmX7PIRBxzKfvT1iM1GJ03J80KZbkEtbJGQCcN5fOv
         rnEgP4KlbHxZgvqgpXfD+shk57bacwJkhIiFdxnG00JuSbf6NkpA838KciAN+lmP0++h
         KNJg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:message-id:subject:from:to:cc:date:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=L1a3QsJvQVGFUItXw/ZQYo1eSHIE37fSrct5bfKHU8U=;
        b=jyRwsL2B4w1Wm/9qttbCs2DNUsMLoEh3lA/8AZ2e6ESXrFyGyr6i+dVZfhYhJbfmc0
         MPTTC31256DCjzt6erQwwLXiCEQq1Cq2WBxp6G2EPSseCnnmpf/sBQblX0Nkx2fHByL6
         RjCjgKzi089zRZ2cVsTaP4h7lwiIGAyprbeJsftTnIfT6Vpnan8EOqXRNKtdXGOgrIqq
         hyIEM+NIpXSF22G/B5D01V4WxBirXYBWqnJT1hL9bLtxTAITMy7AOa32vrnO7Jf/MjUz
         7sfdsiEPK6JQdArDf+XvJxrRPg32nTXrTorhElRyM+vH60ALBdJJf0cQO66Lm2RC3mUo
         0Jxg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:message-id:subject:from:to:cc:date
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=L1a3QsJvQVGFUItXw/ZQYo1eSHIE37fSrct5bfKHU8U=;
        b=eUj7782+QI/u+eIIksHM8AWcCOR2Te08Wofex+Ow6xMENLL8c57FqQS9QB6uxij1vQ
         5Q6SqyQfpJmFAuNHnrz3h65yo7QvsZIE4Oa1MZ06EjiCkIKrLPSNkUqCq25qLFT0Fd5E
         roKi2GUk5jxS0gmFDqqTUoFZiJ8zrX4Mi4SaOzV92F+vsocQ7G4YxhMoXDT6qBsZ+Ip2
         U+zUw2gxGPy3pDVYCJ/N62GY/ABKB9e22EwWg8BsQZXWuSlPT7YAOW4ska8TJhOYCYgA
         kKBo+UDIUzrURGaarA4H+ZaK0PIgD0r0OpDGVeNWuZ6iXIkCr4nGGwvi6FTKZYcJHmu9
         PSoQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAVxD+VBQo50k8ekwSOtjkUljYd0TWav9kX9t8RNaLalweSfCfju
	8jQH57wm7LTXS+/5ec/bhsw=
X-Google-Smtp-Source: APXvYqwn5iySuQCz5AU4yWjuGY7D5mZrF1AqU8n2LdNoUWOUNuPIJiD2elnXdFW0AgGj8/SpF64KVQ==
X-Received: by 2002:a5e:db46:: with SMTP id r6mr15402057iop.287.1571019588978;
        Sun, 13 Oct 2019 19:19:48 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a02:c6b9:: with SMTP id o25ls1920296jan.3.gmail; Sun, 13 Oct
 2019 19:19:48 -0700 (PDT)
X-Received: by 2002:a02:7124:: with SMTP id n36mr7940251jac.90.1571019588675;
        Sun, 13 Oct 2019 19:19:48 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1571019588; cv=none;
        d=google.com; s=arc-20160816;
        b=QpoPFVmBR4zJyK2ztrwTnSRnaZosH1PHGINBw0RgObu56k13t/q6qtfRWrpmIvOaMv
         bHoIiW2FAGr+XEQ69YcHyeszfBHMppNudoHIKRTvRE1tWlgxw1VSHSThmV3UQ3nMiiFn
         8CA1DGtc1dIWzYen8TLxmoMun+yLHK3Y3gVL7HCmWxRqSa5TJNNc5R/FfBLbCCYii1J7
         ln/Vjr/+3KloqmkL7IoGfj/fNnULcxOtmCANlUvWxVkGU+f9H6roNctHzlw0IqaosAje
         ebO0YogqmWHazU5ZjwtR+ruGMUrQ7p6SGAH7eAkcejqY5snva1/XPRSSCv2+CQyikP8I
         BpsA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:content-transfer-encoding:references:in-reply-to:date
         :cc:to:from:subject:message-id;
        bh=5kmVFN1f9lFrdbPJWhmDkpTllSTKgW4kOPHCZocwYdA=;
        b=OVTe3j/hc1Sbp7Vg7q5lPQ/HF5IZ/uvc5nzmppdkJ9y0ZXEF1bisI3N2dlVyRYj4Fd
         jsMYa8M84H17e4IWkLOw/3xmsjXVt8j47NDYPnCNPciQk9m4Pf7rzAMpDdZBKxDONYNP
         0oDRkmys2uM9XtDMMf66y56ml+/vYUjKA0yMBvM4ZKZNUmDItweGcbX4acUHvCMalcb5
         sFQ4fWwrmDDny/NRnJwwjFB2O1qgIB9Ea8xU8S9DT7HLMucDt3R8gzfltqqU3DqjhYoD
         pB3STf+LT+8nDV+rRzxrks+XOf7ZhhxQvHr3ugEjt1LSYudwDR6Y5xU7tsF+aWFLMF48
         47Ww==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw02.mediatek.com ([210.61.82.184])
        by gmr-mx.google.com with ESMTP id n201si728430iod.3.2019.10.13.19.19.47
        for <kasan-dev@googlegroups.com>;
        Sun, 13 Oct 2019 19:19:48 -0700 (PDT)
Received-SPF: pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) client-ip=210.61.82.184;
X-UUID: fcb45f13d48f4e009d0c4926b41054a7-20191014
X-UUID: fcb45f13d48f4e009d0c4926b41054a7-20191014
Received: from mtkmrs01.mediatek.inc [(172.21.131.159)] by mailgw02.mediatek.com
	(envelope-from <walter-zh.wu@mediatek.com>)
	(Cellopoint E-mail Firewall v4.1.10 Build 0809 with TLS)
	with ESMTP id 800004060; Mon, 14 Oct 2019 10:19:43 +0800
Received: from MTKCAS06.mediatek.inc (172.21.101.30) by
 mtkmbs07n2.mediatek.inc (172.21.101.141) with Microsoft SMTP Server (TLS) id
 15.0.1395.4; Mon, 14 Oct 2019 10:19:40 +0800
Received: from [172.21.84.99] (172.21.84.99) by MTKCAS06.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1395.4 via Frontend
 Transport; Mon, 14 Oct 2019 10:19:41 +0800
Message-ID: <1571019582.26230.8.camel@mtksdccf07>
Subject: Re: [PATCH] kasan: fix the missing underflow in memmove and memcpy
 with CONFIG_KASAN_GENERIC=y
From: Walter Wu <walter-zh.wu@mediatek.com>
To: Dmitry Vyukov <dvyukov@google.com>
CC: Qian Cai <cai@lca.pw>, Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>, Matthias Brugger
	<matthias.bgg@gmail.com>, LKML <linux-kernel@vger.kernel.org>, kasan-dev
	<kasan-dev@googlegroups.com>, Linux-MM <linux-mm@kvack.org>, Linux ARM
	<linux-arm-kernel@lists.infradead.org>, <linux-mediatek@lists.infradead.org>,
	wsd_upstream <wsd_upstream@mediatek.com>
Date: Mon, 14 Oct 2019 10:19:42 +0800
In-Reply-To: <CACT4Y+Zbx-2yR-mN5GioaKUgGH1TpTE2D-OgLbR2Dy09ezyGGQ@mail.gmail.com>
References: <1570532528.4686.102.camel@mtksdccf07>
	 <D2B6D82F-AE5F-4A45-AC0C-BE5DA601FDC3@lca.pw>
	 <CACT4Y+Zbx-2yR-mN5GioaKUgGH1TpTE2D-OgLbR2Dy09ezyGGQ@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
X-Mailer: Evolution 3.2.3-0ubuntu6
MIME-Version: 1.0
X-MTK: N
X-Original-Sender: walter-zh.wu@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
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

On Tue, 2019-10-08 at 14:11 +0200, Dmitry Vyukov wrote:
> On Tue, Oct 8, 2019 at 1:42 PM Qian Cai <cai@lca.pw> wrote:
> > > On Oct 8, 2019, at 7:02 AM, Walter Wu <walter-zh.wu@mediatek.com> wrote:
> > > I don't know very well in UBSAN, but I try to build ubsan kernel and
> > > test a negative number in memset and kmalloc_memmove_invalid_size(), it
> > > look like no check.
> >
> > It sounds like more important to figure out why the UBSAN is not working in this case rather than duplicating functionality elsewhere.
> 
> Detecting out-of-bounds accesses is the direct KASAN responsibility.
> Even more direct than for KUBSAN. We are not even adding
> functionality, it's just a plain bug in KASAN code, it tricks itself
> into thinking that access size is 0.
> Maybe it's already detected by KUBSAN too?

Thanks for your response.
I survey the KUBSAN, it don't check size is negative in
memset/memcpy/memmove, we try to verify our uni testing too, it don't
report the bug in KUBSAN, so it needs to report this bug by KASAN. The
reason is like what you said. so we still send the patch.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1571019582.26230.8.camel%40mtksdccf07.
