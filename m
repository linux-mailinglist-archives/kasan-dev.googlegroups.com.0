Return-Path: <kasan-dev+bncBC27HSOJ44LBBF6476MQMGQEXN6MBCY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x237.google.com (mail-lj1-x237.google.com [IPv6:2a00:1450:4864:20::237])
	by mail.lfdr.de (Postfix) with ESMTPS id 3DA065F75DB
	for <lists+kasan-dev@lfdr.de>; Fri,  7 Oct 2022 11:15:04 +0200 (CEST)
Received: by mail-lj1-x237.google.com with SMTP id bs15-20020a05651c194f00b0026e5b8c0bd7sf297812ljb.21
        for <lists+kasan-dev@lfdr.de>; Fri, 07 Oct 2022 02:15:04 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1665134103; cv=pass;
        d=google.com; s=arc-20160816;
        b=LKXL868RIVePBOCkcAnyQMOTdDjAUnPuDqOAcq76SWzvk+1GA6jR+Q5Xw18H0HGH8H
         v3wp5c/ntemv7r++cJV6KrbBftZBWePobA+he6hhOksW0G/aCA4vfpmzsCRJQUR1eVMm
         4RBhSzU/o1RKUKqvxJNpKcVcWbmiq9yUiYWzScufyImE/WE+7kMkPSe6YYt9qJqRKMGd
         JTdnmOjRfxiM50q3fz4rnwR8liMJmpdEVfn8oNtSDH1Vy04cgjru7udz1a6panLOg30y
         EhGxPj6KnEMrMqDKMYYhBM5Yg2WaMureO4kFXVlsGklTBVX09nKq6tgPbwBR4bLJU2X3
         /h+A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:mime-version
         :accept-language:in-reply-to:references:message-id:date:thread-index
         :thread-topic:subject:cc:to:from:sender:dkim-signature;
        bh=g4ezM3FgMZkOP1koT+W26iuXdXSPLKOcsGY6DcAMc0k=;
        b=DTrgYfdrcsYYKaUQzEC8BOtaz0YyLBkK1P6Uang9XvflKVTwaKS29OGw5+YIRCwvaQ
         AtFWvnZI+IkDqdQpCZ802UyVEwO6iSZWTsbF+KVDwdVCVD3cBITic5dMRXX6pJCJOZ9s
         l5mH29NdWF4plbJb+p7r6rLGTkZ4n2H8AjFlWhlNIBKjQB3QwhQDWmHQDafZiRuDi8Gu
         KN/85221bjS/ERrh7EWvSkGFiaYQ2AkmagS6tQ9YSCshi62nks0gBS80ovttw4Gh0b0z
         H0npJ2GWyasGdQ3KD9+mqkJR/LlP+Rfnyipg4SAMrIVns/7UjVpOlsrQeuQ2NzNMmjUt
         +1RQ==
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
        bh=g4ezM3FgMZkOP1koT+W26iuXdXSPLKOcsGY6DcAMc0k=;
        b=fyE2TPIBkw00FiwmR660d4CWW1uUDKmZQiW4iixcY17BisbYMs0mOl/O/us+pjA/qA
         lqVXi7K298rpcz1MHFhug6xps4kq7Vs8Kv5y+V5saHXz55kPKodkMhMoQ/6mG8R78JsH
         ao+UybgzbNrEgLjy/4rYNHj+pncBzF5zEtztlkE1k7ts0WBMj6Y1Wny7PS7xt3aG8tcL
         /M6oQA8Gk2XS60DHgza501aigDMrV1C1vyR8I11H1DmBWZ+M4b8xP28Zh8Zu34Mdk0/+
         S/657Jyg3DHzHZrUwDDEMvoU3Jk8I8FFGqVYrM2s7nsEHO7siN7M5/PkoCmMcMebH6DJ
         hpDw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-language:mime-version:accept-language:in-reply-to
         :references:message-id:date:thread-index:thread-topic:subject:cc:to
         :from:x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=g4ezM3FgMZkOP1koT+W26iuXdXSPLKOcsGY6DcAMc0k=;
        b=ubk7zs8AXG0vHePg4xcgfDB0FJDJfOGWyavxU0AIgz4SBKOmWCLkxF6DFAeY7Ae4Sd
         aQ+G3Bkul35c2y+ApG5QA6RyzkSgxwGXFkYxlOBeGwd97GxmuA8hpsB3YzbCB6bqvhAh
         FpTKVzkq3CLERFi/koIIJkuHYZBAmC+yQ6i31gQE66Dii0Eb/iFzQbd3CNuId/eFelNq
         HSeTANskFfu2ftNsBFhf12ZGel+ZUfO3pkzzetANEv8USNYGyOfNJEhLLc5BH9fy7oII
         if86jqy1BNxorskPo6lqxRGzDIX6ia+a7sO8XrGYeKnq6faF4cUu1voMRG9pRI04fGaG
         3NKA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf2kA/qoSSuDw7gU/ehZ0M5H0flLO5wQ505M+KAvMFpD1I2bVHwP
	tQ6DPTZGLHcux5TF0tHqn1Y=
X-Google-Smtp-Source: AMsMyM4w+tV4evcoH15ETUh4DjNY+QMPp2zbM9O75qfNYYsQ9S79cCVAdaZBqfOnxVc+CEJNfMOpnA==
X-Received: by 2002:a05:6512:258e:b0:4a2:802d:f5ee with SMTP id bf14-20020a056512258e00b004a2802df5eemr1353198lfb.129.1665134103494;
        Fri, 07 Oct 2022 02:15:03 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3689:b0:494:6c7d:cf65 with SMTP id
 d9-20020a056512368900b004946c7dcf65ls775060lfs.2.-pod-prod-gmail; Fri, 07 Oct
 2022 02:15:02 -0700 (PDT)
X-Received: by 2002:a05:6512:511:b0:4a1:d9f3:ea10 with SMTP id o17-20020a056512051100b004a1d9f3ea10mr1637689lfb.555.1665134102179;
        Fri, 07 Oct 2022 02:15:02 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1665134102; cv=none;
        d=google.com; s=arc-20160816;
        b=0TrXdYl9rpxAIto18x6zT3ZrzQQBPe8jtXpJIH0dTQpEDnDgzb2tjGLnzUWGKpJX+8
         eJr4L1eTvl8efY2RnfaanHohBcnZUTLqrmNYevPAFiKnwG9WUw8DhX5vZNdqSGKj/Nac
         AdmrBb1u6wm34cPR1RpiZzHtoO38gba+vcg/CpF3rhf5VP1rcZY4/MJ770/shNy02D8q
         RQgCnj/+aZ9oTh5ZAeSGETKMsnopQ/IUGHFfIfAiO6tEtX3ZYGkIVECx6l1gW5hk7i4x
         7tvgWYC2mtYhsxgSJex/AWimmcRfKgJNBwWJtm8w0KnPoeABCA/GtVNxyQHA563Xia8p
         1QWg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:mime-version
         :accept-language:in-reply-to:references:message-id:date:thread-index
         :thread-topic:subject:cc:to:from;
        bh=zKlYbjeLuB7bA0pn24cz/1rON10LIqEFb6OUBcULHAE=;
        b=Yb9oDYDVqeJKyNrHR9Nq5ThVcIBMmrOOp3xQUC1TWPy7+k72aeA1++iQ9BFFj2DhXF
         ayf6eG4Q50fOBkJzS2iA5kcu2acHq7NTCnDM9u1t+tPI5jsu8/VVvk8ynZcQjg8b+u/5
         igZKC2jnjpHb2/JR7Ku51mYAh/OH/UEIsufgWCiGkyMy+ukjyrqqXYorRFXlrz1WFJfP
         p4AJu9NzR2Dl/cl6D8rGJXbJo2z/Z1HZHPmbqEJzEOwa1dtH4XaWXenQvP2SLPGwm0ky
         tqRv2ALK0xoX6VGk05+KGvVGbErlYYq6O7QnacbpZ+bHf6LcV+tErfQs5ODpt6Cf7eh5
         YEpQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of david.laight@aculab.com designates 185.58.86.151 as permitted sender) smtp.mailfrom=david.laight@aculab.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=aculab.com
Received: from eu-smtp-delivery-151.mimecast.com (eu-smtp-delivery-151.mimecast.com. [185.58.86.151])
        by gmr-mx.google.com with ESMTPS id w15-20020a05651234cf00b00498f2bdfdcdsi68035lfr.3.2022.10.07.02.15.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 07 Oct 2022 02:15:02 -0700 (PDT)
Received-SPF: pass (google.com: domain of david.laight@aculab.com designates 185.58.86.151 as permitted sender) client-ip=185.58.86.151;
Received: from AcuMS.aculab.com (156.67.243.121 [156.67.243.121]) by
 relay.mimecast.com with ESMTP with STARTTLS (version=TLSv1.2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384) id
 uk-mta-165-SM2il4aTNXS-NQtWmWJl3A-1; Fri, 07 Oct 2022 10:14:58 +0100
X-MC-Unique: SM2il4aTNXS-NQtWmWJl3A-1
Received: from AcuMS.Aculab.com (10.202.163.6) by AcuMS.aculab.com
 (10.202.163.6) with Microsoft SMTP Server (TLS) id 15.0.1497.38; Fri, 7 Oct
 2022 10:14:54 +0100
Received: from AcuMS.Aculab.com ([::1]) by AcuMS.aculab.com ([::1]) with mapi
 id 15.00.1497.040; Fri, 7 Oct 2022 10:14:54 +0100
From: David Laight <David.Laight@ACULAB.COM>
To: 'Christophe Leroy' <christophe.leroy@csgroup.eu>, "Jason A. Donenfeld"
	<Jason@zx2c4.com>
CC: "linux-kernel@vger.kernel.org" <linux-kernel@vger.kernel.org>,
	"patches@lists.linux.dev" <patches@lists.linux.dev>, Andreas Noever
	<andreas.noever@gmail.com>, Andrew Morton <akpm@linux-foundation.org>, "Andy
 Shevchenko" <andriy.shevchenko@linux.intel.com>, Borislav Petkov
	<bp@alien8.de>, Catalin Marinas <catalin.marinas@arm.com>,
	=?utf-8?B?Q2hyaXN0b3BoIELDtmhtd2FsZGVy?= <christoph.boehmwalder@linbit.com>,
	Christoph Hellwig <hch@lst.de>, Daniel Borkmann <daniel@iogearbox.net>, "Dave
 Airlie" <airlied@redhat.com>, Dave Hansen <dave.hansen@linux.intel.com>,
	"David S . Miller" <davem@davemloft.net>, Eric Dumazet <edumazet@google.com>,
	Florian Westphal <fw@strlen.de>, Greg Kroah-Hartman
	<gregkh@linuxfoundation.org>, "H . Peter Anvin" <hpa@zytor.com>, "Heiko
 Carstens" <hca@linux.ibm.com>, Helge Deller <deller@gmx.de>, Herbert Xu
	<herbert@gondor.apana.org.au>, Huacai Chen <chenhuacai@kernel.org>, "Hugh
 Dickins" <hughd@google.com>, Jakub Kicinski <kuba@kernel.org>, "James E . J .
 Bottomley" <jejb@linux.ibm.com>, Jan Kara <jack@suse.com>, Jason Gunthorpe
	<jgg@ziepe.ca>, Jens Axboe <axboe@kernel.dk>, Johannes Berg
	<johannes@sipsolutions.net>, Jonathan Corbet <corbet@lwn.net>, "Jozsef
 Kadlecsik" <kadlec@netfilter.org>, KP Singh <kpsingh@kernel.org>, Kees Cook
	<keescook@chromium.org>, Marco Elver <elver@google.com>, "Mauro Carvalho
 Chehab" <mchehab@kernel.org>, Michael Ellerman <mpe@ellerman.id.au>, "Pablo
 Neira Ayuso" <pablo@netfilter.org>, Paolo Abeni <pabeni@redhat.com>, "Peter
 Zijlstra" <peterz@infradead.org>, Richard Weinberger <richard@nod.at>,
	"Russell King" <linux@armlinux.org.uk>, Theodore Ts'o <tytso@mit.edu>,
	"Thomas Bogendoerfer" <tsbogend@alpha.franken.de>, Thomas Gleixner
	<tglx@linutronix.de>, Thomas Graf <tgraf@suug.ch>, Ulf Hansson
	<ulf.hansson@linaro.org>, Vignesh Raghavendra <vigneshr@ti.com>, WANG Xuerui
	<kernel@xen0n.name>, Will Deacon <will@kernel.org>, Yury Norov
	<yury.norov@gmail.com>, "dri-devel@lists.freedesktop.org"
	<dri-devel@lists.freedesktop.org>, "kasan-dev@googlegroups.com"
	<kasan-dev@googlegroups.com>, "kernel-janitors@vger.kernel.org"
	<kernel-janitors@vger.kernel.org>, "linux-arm-kernel@lists.infradead.org"
	<linux-arm-kernel@lists.infradead.org>, "linux-block@vger.kernel.org"
	<linux-block@vger.kernel.org>, "linux-crypto@vger.kernel.org"
	<linux-crypto@vger.kernel.org>, "linux-doc@vger.kernel.org"
	<linux-doc@vger.kernel.org>, "linux-fsdevel@vger.kernel.org"
	<linux-fsdevel@vger.kernel.org>, "linux-media@vger.kernel.org"
	<linux-media@vger.kernel.org>, "linux-mips@vger.kernel.org"
	<linux-mips@vger.kernel.org>, "linux-mm@kvack.org" <linux-mm@kvack.org>,
	"linux-mmc@vger.kernel.org" <linux-mmc@vger.kernel.org>,
	"linux-mtd@lists.infradead.org" <linux-mtd@lists.infradead.org>,
	"linux-nvme@lists.infradead.org" <linux-nvme@lists.infradead.org>,
	"linux-parisc@vger.kernel.org" <linux-parisc@vger.kernel.org>,
	"linux-rdma@vger.kernel.org" <linux-rdma@vger.kernel.org>,
	"linux-s390@vger.kernel.org" <linux-s390@vger.kernel.org>,
	"linux-um@lists.infradead.org" <linux-um@lists.infradead.org>,
	"linux-usb@vger.kernel.org" <linux-usb@vger.kernel.org>,
	"linux-wireless@vger.kernel.org" <linux-wireless@vger.kernel.org>,
	"linuxppc-dev@lists.ozlabs.org" <linuxppc-dev@lists.ozlabs.org>,
	"loongarch@lists.linux.dev" <loongarch@lists.linux.dev>,
	"netdev@vger.kernel.org" <netdev@vger.kernel.org>,
	"sparclinux@vger.kernel.org" <sparclinux@vger.kernel.org>, "x86@kernel.org"
	<x86@kernel.org>, =?utf-8?B?VG9rZSBIw7hpbGFuZC1Kw7hyZ2Vuc2Vu?=
	<toke@toke.dk>, Chuck Lever <chuck.lever@oracle.com>, Jan Kara <jack@suse.cz>
Subject: RE: [PATCH v3 3/5] treewide: use get_random_u32() when possible
Thread-Topic: [PATCH v3 3/5] treewide: use get_random_u32() when possible
Thread-Index: AQHY2asa0LDp17FxT0u8eu+L+6kCF64CocNw
Date: Fri, 7 Oct 2022 09:14:54 +0000
Message-ID: <e0c127f9e80146c19fab9f987bb2f588@AcuMS.aculab.com>
References: <20221006165346.73159-1-Jason@zx2c4.com>
 <20221006165346.73159-4-Jason@zx2c4.com>
 <848ed24c-13ef-6c38-fd13-639b33809194@csgroup.eu>
 <CAHmME9raQ4E00r9r8NyWJ17iSXE_KniTG0onCNAfMmfcGar1eg@mail.gmail.com>
 <f10fcfbf-2da6-cf2d-6027-fbf8b52803e9@csgroup.eu>
 <6396875c-146a-acf5-dd9e-7f93ba1b4bc3@csgroup.eu>
In-Reply-To: <6396875c-146a-acf5-dd9e-7f93ba1b4bc3@csgroup.eu>
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

From: Christophe Leroy
> Sent: 06 October 2022 18:43
...
> But taking into account that sp must remain 16 bytes aligned, would it
> be better to do something like ?
> 
> 	sp -= prandom_u32_max(PAGE_SIZE >> 4) << 4;

That makes me think...
If prandom_u32_max() is passed a (constant) power of 2 it doesn't
need to do the multiply, it can just do a shift right.

Doesn't it also always get a 32bit random value?
So actually get_random_u32() & PAGE_MASK & ~0xf is faster!

When PAGE_SIZE is 4k, PAGE_SIZE >> 4 is 256 so it could use:
	get_ramdom_u8() << 4

You also seem to have removed prandom_u32() in favour of
get_random_u32() but have added more prandom_xxxx() functions.

	David

-
Registered Address Lakeside, Bramley Road, Mount Farm, Milton Keynes, MK1 1PT, UK
Registration No: 1397386 (Wales)

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/e0c127f9e80146c19fab9f987bb2f588%40AcuMS.aculab.com.
