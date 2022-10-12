Return-Path: <kasan-dev+bncBC27HSOJ44LBBI7DTSNAMGQE7KFNTEI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33b.google.com (mail-wm1-x33b.google.com [IPv6:2a00:1450:4864:20::33b])
	by mail.lfdr.de (Postfix) with ESMTPS id E48085FCD29
	for <lists+kasan-dev@lfdr.de>; Wed, 12 Oct 2022 23:29:07 +0200 (CEST)
Received: by mail-wm1-x33b.google.com with SMTP id v191-20020a1cacc8000000b003bdf7b78dccsf10616280wme.3
        for <lists+kasan-dev@lfdr.de>; Wed, 12 Oct 2022 14:29:07 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1665610147; cv=pass;
        d=google.com; s=arc-20160816;
        b=FdOqUMZNv+8/557IllCQh5TgWDOEzqNzq4lLkGIui8VEHloTdm6C+B9Gnq//4ijZRh
         +PMcmD8tSDyNq3zOi5DKy/y8O+iuobQYb3R+mTkwtvJlN21Aiok+35aQBeggxBS60MNy
         ux+AC3dCGCIdqS0ySdHApygIi3ZIfJqi0aSuTrVnxjNq3Z+39MmWP1ctFTdHQjQHcgwI
         AC1n6H5tBU4hFavOnEZRqPZi6pxGOr+ea8MjqvZQmbMrv92InWIpWq/5p/WWG5FnaIvm
         dYUVcHKnS8DtDQPIbnpcDYTHDT6qcDXivxeQQSQDKYOTJBPJLeoFRrm98tiRDC5wxqt5
         eKVg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:mime-version
         :accept-language:in-reply-to:references:message-id:date:thread-index
         :thread-topic:subject:cc:to:from:sender:dkim-signature;
        bh=OUeoUp2Q/S/IqG7vhy6sauG3ilywTpcWDRr0obfTcl4=;
        b=bzxeOuiIXyUPK1awAWgk37rGCp2pH7cC0Zb1MxSOWAhYR6Dv+kwIwkAE/l7L4AHFqe
         79DWFFJ3LjC6zkfDbgmopubIVsUhSGSVBhXY9d4y7/yNC30aVSddvczHQJv/LdP9O1xL
         qZctR1Tzb4I4PNGbMMonFsscnk+YVFdzgDIUounKUI65odCW5RYriyS2TKAevVqZyylX
         Uaxig+GOnhC5+X2+qul/NqLUUrLWku5Y73ykDMyuxCUt1HgnZCSjLWgdUKVhOLGbv0Hr
         QKKhD8HRuzRdAV0qs7RvvEYMjD0Lljcwfy1tyrfaYLUbmLLefJDYDczNtHBHRVf7ULnD
         xZYw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of david.laight@aculab.com designates 185.58.86.151 as permitted sender) smtp.mailfrom=david.laight@aculab.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=aculab.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-language:mime-version:accept-language
         :in-reply-to:references:message-id:date:thread-index:thread-topic
         :subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=OUeoUp2Q/S/IqG7vhy6sauG3ilywTpcWDRr0obfTcl4=;
        b=lETiOGkiRhxiTLlPNLJsiRBtdtcm33/o0rMcSg9DFUFq5iiDDfVBfU2DLdS2DZPKUK
         wcZyNS115bgVReZIEEXXiS8g8abX7uFBf4oxUpMl06gjamJzawwu7SpI1XpN+08F2sNg
         xV8V9ejd42kY6lK7/OtsSiu9N/orNJnJoK0sIXHu+5wNdGvCGG0DYP3IkbCJbiJd1w7Q
         GjVcviiFOHYBddxG9EipDi/N+jXsnyXLiwvUiwyYLjO83KL1TCIH7mqzGSnH8IVHHB4F
         bezsOg4NFeQJpQDIgVKvJcqYT6I+n6QiQXGDIvNnBSXqOC9s6xKLD/Sj1XV6rxXIKzVU
         d/HQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-language:mime-version:accept-language:in-reply-to
         :references:message-id:date:thread-index:thread-topic:subject:cc:to
         :from:x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=OUeoUp2Q/S/IqG7vhy6sauG3ilywTpcWDRr0obfTcl4=;
        b=csmKLVfE23AZOW5XoovSYiqUtoy6U0vqssUh7Od1qhADvU6f/nIfU3q9AzNXICl0RU
         ffptMXRHvir/MMCozgRcfQ5NRBpi/fGn+LLoawEeFQyLlQtxhnra08/XM1fOt9H43czM
         wZRhxVZ6hadk3CexNjqIXE2o+6m6tlkHi6I8Jf33LpwLKoMWrrZ+5Q47ymsvYwFLXrl6
         rC/IdUqVly8ye9jNzPYTz2CKdBbgO3+SycsulR3UIs61IuUJU3Zflom4G4IdaNhkLZEj
         3f/6XXkuWrStg9RjamS9OebGi0RlYC1VAigtJmpmHNrqv7wEV2KfbVaZz/te8L4vInWc
         fXBQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf1wYwbODIS18QVj/FgnZj77xQPzU8J4YxqLiKYBCF7zipQhQ+op
	uMu4bX9rk8uuWr2NLW14hS0=
X-Google-Smtp-Source: AMsMyM6GSLsr9hV58819yBFkyhIaDby9/jfgcRRd3F5z65NGrVCuE9yEaeteCLggwQtbAVq8QwGqag==
X-Received: by 2002:a5d:456b:0:b0:230:9e5b:c64c with SMTP id a11-20020a5d456b000000b002309e5bc64cmr10801029wrc.211.1665610147379;
        Wed, 12 Oct 2022 14:29:07 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:26c2:0:b0:3c4:89fe:ecec with SMTP id m185-20020a1c26c2000000b003c489feececls946060wmm.0.-pod-preprod-gmail;
 Wed, 12 Oct 2022 14:29:06 -0700 (PDT)
X-Received: by 2002:a05:600c:19c7:b0:3c6:dd03:2b26 with SMTP id u7-20020a05600c19c700b003c6dd032b26mr150350wmq.37.1665610146381;
        Wed, 12 Oct 2022 14:29:06 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1665610146; cv=none;
        d=google.com; s=arc-20160816;
        b=yjoXddnTviNetFAyY0bYxymbP65w+/mfzxsT3+na2JqcyY2w+Juy+3rFxQN15wExd7
         gcZWn4vr9khGpBebGe4QXbVbQOOP5Zto886AaS3On4/V277UOUIFrimCN8Ye/9Oqg+A6
         A77XrYN/sCcUkP92cRumlAxUNTQq0qgRsZKW+CBqZCdROgMK3MOG8FyAK+NzhOFchWgN
         jsD4Cfg6wKg2VIjQh92awE7UakiHbV0AWieS3LDKKTuXY8kbm7zQeyDR8qonFJDwuGn4
         OZyIJfYoAro3trgsRY/19vY/w8Ka+6ie/w12UQJ2OYivUXZpqBz2NpiapfuhLFP/mqP6
         vE/Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:mime-version
         :accept-language:in-reply-to:references:message-id:date:thread-index
         :thread-topic:subject:cc:to:from;
        bh=DLr+AazHKqvd37FIJspzgJ5v0CvIeseJ+7IB12p8OSQ=;
        b=npgSDbRGMiRUInb4mCZre1Fa1uX4nlOb1km27rLVXMw4kABgO5LzKL7l9b+t1KFsIe
         L+3T0MPLEnldw0//6N9De2Toy6dTvmpBKilL5JnMoe47lIxWKBl98WERIfxTTlbWVJ+7
         5PCnpGRZT/x6Wc6NGhOpXNafpj9wTbQd3YFJ0aFb2DyT8mx0kGCeLC88bpnG6GEfB0k0
         LfJqUwZ4eDF8CewtB3xQ9XURi66twba61SOq//baMF+CseqZfFiz6SvDdjEXn1uW/kVj
         I7xbqEL3gwZDN7rZUPkwYJST5NkIFvpAT4sjMTvTejjpG0iqkfANOjQIFD0XbL2SWtfV
         ycOw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of david.laight@aculab.com designates 185.58.86.151 as permitted sender) smtp.mailfrom=david.laight@aculab.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=aculab.com
Received: from eu-smtp-delivery-151.mimecast.com (eu-smtp-delivery-151.mimecast.com. [185.58.86.151])
        by gmr-mx.google.com with ESMTPS id bd24-20020a05600c1f1800b003c6b7cd552bsi135918wmb.1.2022.10.12.14.29.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 12 Oct 2022 14:29:06 -0700 (PDT)
Received-SPF: pass (google.com: domain of david.laight@aculab.com designates 185.58.86.151 as permitted sender) client-ip=185.58.86.151;
Received: from AcuMS.aculab.com (156.67.243.121 [156.67.243.121]) by
 relay.mimecast.com with ESMTP with STARTTLS (version=TLSv1.2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384) id
 uk-mta-269-WPghBqosPyeNkdeVSYELTw-1; Wed, 12 Oct 2022 22:29:04 +0100
X-MC-Unique: WPghBqosPyeNkdeVSYELTw-1
Received: from AcuMS.Aculab.com (10.202.163.6) by AcuMS.aculab.com
 (10.202.163.6) with Microsoft SMTP Server (TLS) id 15.0.1497.38; Wed, 12 Oct
 2022 22:29:02 +0100
Received: from AcuMS.Aculab.com ([::1]) by AcuMS.aculab.com ([::1]) with mapi
 id 15.00.1497.040; Wed, 12 Oct 2022 22:29:02 +0100
From: David Laight <David.Laight@ACULAB.COM>
To: 'Joe Perches' <joe@perches.com>, "Jason A. Donenfeld" <Jason@zx2c4.com>,
	"linux-kernel@vger.kernel.org" <linux-kernel@vger.kernel.org>
CC: "linux-fbdev@vger.kernel.org" <linux-fbdev@vger.kernel.org>,
	"linux-doc@vger.kernel.org" <linux-doc@vger.kernel.org>,
	"linux-wireless@vger.kernel.org" <linux-wireless@vger.kernel.org>,
	"dri-devel@lists.freedesktop.org" <dri-devel@lists.freedesktop.org>,
	"linux-mm@kvack.org" <linux-mm@kvack.org>, "linux-sctp@vger.kernel.org"
	<linux-sctp@vger.kernel.org>, "target-devel@vger.kernel.org"
	<target-devel@vger.kernel.org>, "linux-mtd@lists.infradead.org"
	<linux-mtd@lists.infradead.org>, "linux-stm32@st-md-mailman.stormreply.com"
	<linux-stm32@st-md-mailman.stormreply.com>, "drbd-dev@lists.linbit.com"
	<drbd-dev@lists.linbit.com>, "dev@openvswitch.org" <dev@openvswitch.org>,
	"rds-devel@oss.oracle.com" <rds-devel@oss.oracle.com>,
	"linux-scsi@vger.kernel.org" <linux-scsi@vger.kernel.org>,
	"dccp@vger.kernel.org" <dccp@vger.kernel.org>, "linux-rdma@vger.kernel.org"
	<linux-rdma@vger.kernel.org>, "kasan-dev@googlegroups.com"
	<kasan-dev@googlegroups.com>, "lvs-devel@vger.kernel.org"
	<lvs-devel@vger.kernel.org>, "SHA-cyfmac-dev-list@infineon.com"
	<SHA-cyfmac-dev-list@infineon.com>, "coreteam@netfilter.org"
	<coreteam@netfilter.org>, "tipc-discussion@lists.sourceforge.net"
	<tipc-discussion@lists.sourceforge.net>, "linux-ext4@vger.kernel.org"
	<linux-ext4@vger.kernel.org>, "linux-media@vger.kernel.org"
	<linux-media@vger.kernel.org>, "linux-actions@lists.infradead.org"
	<linux-actions@lists.infradead.org>, "linux-nfs@vger.kernel.org"
	<linux-nfs@vger.kernel.org>, "linux-block@vger.kernel.org"
	<linux-block@vger.kernel.org>, "dmaengine@vger.kernel.org"
	<dmaengine@vger.kernel.org>, "linux-nvme@lists.infradead.org"
	<linux-nvme@lists.infradead.org>, "linux-hams@vger.kernel.org"
	<linux-hams@vger.kernel.org>, "ceph-devel@vger.kernel.org"
	<ceph-devel@vger.kernel.org>, "linux-arm-kernel@lists.infradead.org"
	<linux-arm-kernel@lists.infradead.org>, "cake@lists.bufferbloat.net"
	<cake@lists.bufferbloat.net>, "brcm80211-dev-list.pdl@broadcom.com"
	<brcm80211-dev-list.pdl@broadcom.com>, "linux-raid@vger.kernel.org"
	<linux-raid@vger.kernel.org>, "netdev@vger.kernel.org"
	<netdev@vger.kernel.org>, "linux-usb@vger.kernel.org"
	<linux-usb@vger.kernel.org>, "linux-mmc@vger.kernel.org"
	<linux-mmc@vger.kernel.org>, "linux-f2fs-devel@lists.sourceforge.net"
	<linux-f2fs-devel@lists.sourceforge.net>, "linux-xfs@vger.kernel.org"
	<linux-xfs@vger.kernel.org>, "netfilter-devel@vger.kernel.org"
	<netfilter-devel@vger.kernel.org>, "linux-crypto@vger.kernel.org"
	<linux-crypto@vger.kernel.org>, "linux-fsdevel@vger.kernel.org"
	<linux-fsdevel@vger.kernel.org>, "linuxppc-dev@lists.ozlabs.org"
	<linuxppc-dev@lists.ozlabs.org>
Subject: RE: [PATCH v1 3/5] treewide: use get_random_u32() when possible
Thread-Topic: [PATCH v1 3/5] treewide: use get_random_u32() when possible
Thread-Index: AQHY3m9QJDmwhr5XuUa4Hi/RfD23ja4LRXVg
Date: Wed, 12 Oct 2022 21:29:02 +0000
Message-ID: <d45bd258e033453b85a137112e7694e1@AcuMS.aculab.com>
References: <20221005214844.2699-1-Jason@zx2c4.com>
	 <20221005214844.2699-4-Jason@zx2c4.com>
 <f8ad3ba44d28dec1a5f7626b82c5e9c2aeefa729.camel@perches.com>
In-Reply-To: <f8ad3ba44d28dec1a5f7626b82c5e9c2aeefa729.camel@perches.com>
Accept-Language: en-GB, en-US
X-MS-Has-Attach: 
X-MS-TNEF-Correlator: 
x-ms-exchange-transport-fromentityheader: Hosted
x-originating-ip: [10.202.205.107]
MIME-Version: 1.0
X-Mimecast-Spam-Score: 0
X-Mimecast-Originator: aculab.com
Content-Language: en-US
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: david.laight@aculab.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of david.laight@aculab.com designates 185.58.86.151 as
 permitted sender) smtp.mailfrom=david.laight@aculab.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=aculab.com
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

From: Joe Perches
> Sent: 12 October 2022 20:17
> 
> On Wed, 2022-10-05 at 23:48 +0200, Jason A. Donenfeld wrote:
> > The prandom_u32() function has been a deprecated inline wrapper around
> > get_random_u32() for several releases now, and compiles down to the
> > exact same code. Replace the deprecated wrapper with a direct call to
> > the real function.
> []
> > diff --git a/drivers/infiniband/hw/cxgb4/cm.c b/drivers/infiniband/hw/cxgb4/cm.c
> []
> > @@ -734,7 +734,7 @@ static int send_connect(struct c4iw_ep *ep)
> >  				   &ep->com.remote_addr;
> >  	int ret;
> >  	enum chip_type adapter_type = ep->com.dev->rdev.lldi.adapter_type;
> > -	u32 isn = (prandom_u32() & ~7UL) - 1;
> > +	u32 isn = (get_random_u32() & ~7UL) - 1;
> 
> trivia:
> 
> There are somewhat odd size mismatches here.
> 
> I had to think a tiny bit if random() returned a value from 0 to 7
> and was promoted to a 64 bit value then truncated to 32 bit.
> 
> Perhaps these would be clearer as ~7U and not ~7UL

That makes no difference - the compiler will generate the same code.

The real question is WTF is the code doing?
The '& ~7u' clears the bottom 3 bits.
The '- 1' then sets the bottom 3 bits and decrements the
(random) high bits.

So is the same as get_random_u32() | 7.
But I bet the coder had something else in mind.

	David

-
Registered Address Lakeside, Bramley Road, Mount Farm, Milton Keynes, MK1 1PT, UK
Registration No: 1397386 (Wales)

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/d45bd258e033453b85a137112e7694e1%40AcuMS.aculab.com.
