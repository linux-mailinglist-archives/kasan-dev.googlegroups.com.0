Return-Path: <kasan-dev+bncBD64ZMV5YYBRB55RT62QMGQEE4RFEJQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3d.google.com (mail-oa1-x3d.google.com [IPv6:2001:4860:4864:20::3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 2DF2893FCF9
	for <lists+kasan-dev@lfdr.de>; Mon, 29 Jul 2024 20:01:29 +0200 (CEST)
Received: by mail-oa1-x3d.google.com with SMTP id 586e51a60fabf-26466d6435fsf4074503fac.2
        for <lists+kasan-dev@lfdr.de>; Mon, 29 Jul 2024 11:01:29 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1722276088; cv=pass;
        d=google.com; s=arc-20160816;
        b=PpOG5cqGJ04AlB3cdgFLh+tLe9oYJMFIXynIbtN3yxxwNW05ohQTrrFUIGK4EIvXzK
         QtNgcnxC0nZ+gInCR4kUN7ASro9GIV/TEeA1feppAC+4EA6g04VkAl0wgMz0CaDgQLEr
         /EkRMTNlRkbhO1FZD/80kHoFPlq7dBGzfHTYk44yGbaM4aBSKTcopGmjBppuYeyQ3XdS
         9DKgNiY7XV/imHg4a4wThZ5U7wtPRAo/Tu/JmC4v/5TViK+AKRH7nbVoKFM1ScWN3EX+
         +zI+h7A4jwlSZU7xpcGHr3EHo6Uj5ti1NN/9IB365sItZh1iE9Zuh3nlzRzcMwgL9MSA
         d2eQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=KXGyQKhKgBcyVuAJsUSqK4/uMpRUr4YEuaBD5JmM7IU=;
        fh=p5QnLU4HEdx3NSE8cGcrhT19HA84xtctCgoI8YGcElU=;
        b=jSoqrXpVJYWIpoILkpaE8J37c04s0zWCPrsmVM4IKYlecDseJnHV9VvTEcPCKhEqz9
         /ju1dYGBxLRbzhJ4PGfpMF0p4y1G6rNHHBGvSm0lU2QkEbrbyKyD5IKuogH90VvpiDkC
         vQ9pI3hRapyPE7bJxAuPNzy3Pm6XpG/uWoCGIZyKJ1RfCRiXaU4pAUOSiKkouVqwRtnx
         q3xNe26TVCf5XPDRdDphGd+PQR1RS/DG7ArAbaRH7fXpxAEQ9K11bxlMyaD7SmjSF1h3
         es5vsKZVdNdJOafOqqxjHdQXxGKHCAyagZPKOM/S9cZD72i85Osdh5F32UdkQTB3bsjp
         vmtg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@rowland.harvard.edu header.s=google header.b=tEhQPI8U;
       spf=pass (google.com: domain of stern@g.harvard.edu designates 2607:f8b0:4864:20::82e as permitted sender) smtp.mailfrom=stern@g.harvard.edu;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=rowland.harvard.edu;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1722276088; x=1722880888; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-transfer-encoding
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=KXGyQKhKgBcyVuAJsUSqK4/uMpRUr4YEuaBD5JmM7IU=;
        b=FeGDS4PoKLGkS+wEjjOAD8UpSLBSpZq3pYWDRnTWQKuEJYlrlqV3Owp3cQPX4j7UUR
         P42Ob50KBewbEavPeEdKX6HxDjefaONEhK18OVaRQqR0uQHNnPW9vjVRSr1ASDYGLedc
         JVkAJVBefvZxpnRMYOM7PVSjfy74ptCuQdh7qrOIyWlza82Jd5+jLeJlVWWcC43s8P0s
         OUiY0jli0iO2WQz3cU1oEo1sQ7om3Zrvq3U34RBJMPiZms2Dk5F5erPkxFXZVwGifQzr
         6VFdECmfDixarZyykyLCjVIsFibv39TLjGClBEXT2lTsd41vuhK4nLst0JxIE7HGZmao
         IvDg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1722276088; x=1722880888;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=KXGyQKhKgBcyVuAJsUSqK4/uMpRUr4YEuaBD5JmM7IU=;
        b=p9Lp8oHPdJe14waYKX1YBlWDdmuwkFysFpKUezxYb6cSBnKZJMofyAcNnqI1QWUmSn
         uYTqTQD2SPX8fNRxDo+sHmsObEIPSNFC+WRFHG862YoBE2rckVuniV8u7GQB/cWejauF
         J6Apqo0/J0w8oexkpq33xovGvWEYBmopK+zUmA7SvAjSYOFGhjj6HRnWS0nsu/xYfqY/
         l5DXp1hm66i+EiSGmqNWIwzuGq85juGg/sZUitx9FCa7CyYh7Cz9ENJhQAN/Qa2ObsSk
         dIIeRmrBksO4WxUhmlU8lUkvWrXkPk4+jkiYH8tEngF44eq2gnrbl2v1dP2CKPqf5SN0
         AGVg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWye7C3wFx8juhwVB6kdN8hFf3dczP/PjBe+s28ltmCAeQWSYbhyZXzlKyliTqAxXA+G7sIVUc4h4O0TjpqRhh80kVfEBcpPw==
X-Gm-Message-State: AOJu0Yym3xzuAhTUj2SlTuOIkxrmOhyfy3bi0wMfLW48ROqRfE7RLSD4
	b3V/TyQNmlnMSN7yU+9XLDUFAVzmadeAJmr+S8b1vduPVxgtECn/
X-Google-Smtp-Source: AGHT+IGMx2YCMclbsJrOx3rwFq4l2feHWVCTCCRjCs64kU263gOM1C0N0kgflOOhQSPEM76qCvd0kw==
X-Received: by 2002:a05:6870:a2cf:b0:260:f827:243c with SMTP id 586e51a60fabf-267d4d37ed9mr10056866fac.12.1722276087694;
        Mon, 29 Jul 2024 11:01:27 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6871:5286:b0:25c:b2bf:2226 with SMTP id
 586e51a60fabf-2649ff52797ls5350111fac.1.-pod-prod-07-us; Mon, 29 Jul 2024
 11:01:26 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVWfVy0912x9barXjD8AEUd+9oPEMG4LtLIyzyRBr1ovjsiKgAnMCBfY0unUZ3JbN3W7WU1E+giNKKX7pGua/LSAf/WxhqHKqHtNQ==
X-Received: by 2002:a05:6870:b6a5:b0:254:b5b9:3552 with SMTP id 586e51a60fabf-267d4eef22fmr11794911fac.33.1722276086661;
        Mon, 29 Jul 2024 11:01:26 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1722276086; cv=none;
        d=google.com; s=arc-20160816;
        b=pqR3QK7G5tUQ/aLfSUrXVNMTA6edv+lg4eBbZLkoh/03AzA7SHgL7lchCs2QwKuNUq
         8BbeL3TcAoeEnq9vH82KKdIACgvo7VQ7HcF8xl7oz08qkoi0dB1ggHsBE/cFzPRmtJN3
         kcCcLvs2ZxV6Rn3TP14SeKeBg4qY6UzdMmABMow2G9bVbRiountsjOp+d6m/nsTvMzLO
         YUqAN9DR13cwxVX1gSxctBvKCd5lWQuyyB6FMcs1nfaQLIT9NSQdSfnietbn6Ana8MVb
         JGYDCAbfmSHgVT5WFn3Q921Fv74PsYiEBiYiceMm128n+JKQeUEx4MX/oUnSbV+zpLz4
         wVFw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=Nd1WXiUiTtwYxOMtFvVlG67gP5owuM6QDVES/bBhfKI=;
        fh=+v4x0zlMlhAKBGs9nFr+QYfbiYlU8vOgQWXHvW/Qz6E=;
        b=GIGKox6MUlAn6ZNPgNz5/7PAohJPYvfUjWE0U1O6rLM9GruqM0BEZgslltM6A6Cn0B
         toNbzO7UdvTqVrv479g7WsANzAJ5Z0Zm3omHah+RejibUQGnJ8qVrRgK7CU7D1LzFw7o
         ABHDSE9/WrqOsVYV0IAysUSZRO+OI8QlveWPXzPq1ZYFSgK690a+LNz+KHdtgEBIob2l
         pAlcCVVB68awit+0hjVniokNwnmRtobePs7An/EiqJ1mr79jBj5Yo2yc2a6FBt3Kyat0
         ZlMMe6imC8hULyIkyKQ5xW+prhQbZY13bVUfNPwLjboQcE2XRI8V5dCBvNVtITYfyfZ8
         AOKQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@rowland.harvard.edu header.s=google header.b=tEhQPI8U;
       spf=pass (google.com: domain of stern@g.harvard.edu designates 2607:f8b0:4864:20::82e as permitted sender) smtp.mailfrom=stern@g.harvard.edu;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=rowland.harvard.edu;
       dara=pass header.i=@googlegroups.com
Received: from mail-qt1-x82e.google.com (mail-qt1-x82e.google.com. [2607:f8b0:4864:20::82e])
        by gmr-mx.google.com with ESMTPS id af79cd13be357-7a1d744521esi50880485a.5.2024.07.29.11.01.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 29 Jul 2024 11:01:26 -0700 (PDT)
Received-SPF: pass (google.com: domain of stern@g.harvard.edu designates 2607:f8b0:4864:20::82e as permitted sender) client-ip=2607:f8b0:4864:20::82e;
Received: by mail-qt1-x82e.google.com with SMTP id d75a77b69052e-44feaa08040so21676581cf.2
        for <kasan-dev@googlegroups.com>; Mon, 29 Jul 2024 11:01:26 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWWNCtanL0004BdWgw6eUAyXdccXIAykaqA2dLzMw97hvPDobb4Dp/1A2sAJ93dyJVyJbe4SSdjeVQedgeMG6UitFy0UlNZtfHyXw==
X-Received: by 2002:a05:622a:1791:b0:43f:fc16:6b3f with SMTP id d75a77b69052e-45004f1378dmr135514091cf.34.1722276086083;
        Mon, 29 Jul 2024 11:01:26 -0700 (PDT)
Received: from rowland.harvard.edu (iolanthe.rowland.org. [192.131.102.54])
        by smtp.gmail.com with ESMTPSA id d75a77b69052e-44fe8147635sm44235931cf.31.2024.07.29.11.01.25
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 29 Jul 2024 11:01:25 -0700 (PDT)
Date: Mon, 29 Jul 2024 14:01:22 -0400
From: Alan Stern <stern@rowland.harvard.edu>
To: Andrey Konovalov <andreyknvl@gmail.com>
Cc: Marcello Sylvester Bauer <sylv@sylv.io>, andrey.konovalov@linux.dev,
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
	Dmitry Vyukov <dvyukov@google.com>,
	Aleksandr Nogikh <nogikh@google.com>,
	Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>, kasan-dev@googlegroups.com,
	Andrew Morton <akpm@linux-foundation.org>, linux-mm@kvack.org,
	linux-usb@vger.kernel.org, linux-kernel@vger.kernel.org,
	syzbot+2388cdaeb6b10f0c13ac@syzkaller.appspotmail.com,
	syzbot+17ca2339e34a1d863aad@syzkaller.appspotmail.com,
	stable@vger.kernel.org
Subject: Re: [PATCH] usb: gadget: dummy_hcd: execute hrtimer callback in
 softirq context
Message-ID: <d4ed3fb2-0d59-4376-af12-de4cd2167b18@rowland.harvard.edu>
References: <20240729022316.92219-1-andrey.konovalov@linux.dev>
 <baae33f5602d8bcd38b48cd6ea4617c8e17d8650.camel@sylv.io>
 <CA+fCnZcWvtnTrST3PrORdPwmo0m2rrE+S-hWD74ZU_4RD6mSPA@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <CA+fCnZcWvtnTrST3PrORdPwmo0m2rrE+S-hWD74ZU_4RD6mSPA@mail.gmail.com>
X-Original-Sender: stern@rowland.harvard.edu
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@rowland.harvard.edu header.s=google header.b=tEhQPI8U;
       spf=pass (google.com: domain of stern@g.harvard.edu designates
 2607:f8b0:4864:20::82e as permitted sender) smtp.mailfrom=stern@g.harvard.edu;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=rowland.harvard.edu;
       dara=pass header.i=@googlegroups.com
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

On Mon, Jul 29, 2024 at 06:14:30PM +0200, Andrey Konovalov wrote:
> On Mon, Jul 29, 2024 at 10:26=E2=80=AFAM Marcello Sylvester Bauer <sylv@s=
ylv.io> wrote:
> >
> > Hi Andrey,
>=20
> Hi Marcello,
>=20
> > Thanks for investigating and finding the cause of this problem. I have
> > already submitted an identical patch to change the hrtimer to softirq:
> > https://lkml.org/lkml/2024/6/26/969
>=20
> Ah, I missed that, that's great!
>=20
> > However, your commit messages contain more useful information about the
> > problem at hand. So I'm happy to drop my patch in favor of yours.
>=20
> That's very considerate, thank you. I'll leave this up to Greg - I
> don't mind using either patch.
>=20
> > Btw, the same problem has also been reported by the intel kernel test
> > robot. So we should add additional tags to mark this patch as the fix.
> >
> >
> > Reported-by: kernel test robot <oliver.sang@intel.com>
> > Closes:
> > https://lore.kernel.org/oe-lkp/202406141323.413a90d2-lkp@intel.com
> > Acked-by: Marcello Sylvester Bauer <sylv@sylv.io>
>=20
> Let's also add the syzbot reports mentioned in your patch:
>=20
> Reported-by: syzbot+c793a7eca38803212c61@syzkaller.appspotmail.com
> Closes: https://syzkaller.appspot.com/bug?extid=3Dc793a7eca38803212c61
> Reported-by: syzbot+1e6e0b916b211bee1bd6@syzkaller.appspotmail.com
> Closes: https://syzkaller.appspot.com/bug?extid=3D1e6e0b916b211bee1bd6
>=20
> And I also found one more:
>=20
> Reported-by: syzbot+edd9fe0d3a65b14588d5@syzkaller.appspotmail.com
> Closes: https://syzkaller.appspot.com/bug?extid=3Dedd9fe0d3a65b14588d5

You need to be careful about claiming that this patch will fix those bug=20
reports.  At least one of them (the last one above) still fails with the=20
patch applied.  See:

https://lore.kernel.org/linux-usb/ade15714-6aa3-4988-8b45-719fc9d74727@rowl=
and.harvard.edu/

and the following response.

Alan Stern

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/d4ed3fb2-0d59-4376-af12-de4cd2167b18%40rowland.harvard.edu.
