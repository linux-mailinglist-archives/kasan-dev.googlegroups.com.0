Return-Path: <kasan-dev+bncBDLKPY4HVQKBBZE57SMQMGQEHXBAMEA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x138.google.com (mail-lf1-x138.google.com [IPv6:2a00:1450:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id 92ED65F6CBB
	for <lists+kasan-dev@lfdr.de>; Thu,  6 Oct 2022 19:22:45 +0200 (CEST)
Received: by mail-lf1-x138.google.com with SMTP id z15-20020ac25def000000b004a060fcd1d5sf852647lfq.7
        for <lists+kasan-dev@lfdr.de>; Thu, 06 Oct 2022 10:22:45 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1665076965; cv=pass;
        d=google.com; s=arc-20160816;
        b=BC/WdEWVTnupxloN4lEEWE7FtiI1xCiInftTsfwdUdb4pERJLxnzenu5G41ei8OKi4
         /0Z/dBf8DueOlROamONcQVFV7s5xDG6CakNiG/qxHERErqDvmYBsm+Jsk2vsiqqORQwA
         4JMGri7Nt4zMBNXFVprm8c5PdGtmG3C7v4DIUBht7l4b3jTTM+KYv6lnFQzKbDGcm1mZ
         f19WPOTHEv1X9Gl2Q2E+IFZX9x67XGc/8OKA51/508SXAvl6VJXoElFNVADAczTWpnTG
         nS8FsoPuq3RESHHreftayzBA+sMI7LkUU69RMFJ40KA0r+vnr/pCs0CfMftCMo6jJt1x
         MPxg==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version
         :content-transfer-encoding:content-id:user-agent:content-language
         :accept-language:in-reply-to:references:message-id:date:thread-index
         :thread-topic:subject:cc:to:from:sender:dkim-signature;
        bh=mCR8qC5Ibe0N3ydSfhnIdMP6YPWryScH7rnLSwAqyqM=;
        b=yvx6z5lsEMYrpdOWXNBSSBL59Cjr+/5q7RhiheRbnx/DFjne7dgKhXWHNh5ewrDlqb
         TiD9L3GWBl4fyDWqQAN7viI7dHQe0sj6Ws5iM/2TZmV+3HYZp640h9uygxRb+zyepiNV
         Lk7ckfxOPbuVqMOkfq/ecdA2bx0hVZsjM+XvuH54dgyGH9xdY5v8qzl4mcTcqrXo5oDU
         Ga7eBFawCue/D+Rvy+qFeimtp817df3MQaOKHmtCBgNbOg2yrwpbl4A8+JiDQaJtgV3n
         zAm9GAHwo0FqvuaNMrSWBzC3PeibEcW0MycTwwWLhUlrbjklQohwfdV9GQQjamP4vTuF
         3WuQ==
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@csgroup.eu header.s=selector1 header.b=KWPR9kmI;
       arc=pass (i=1 spf=pass spfdomain=csgroup.eu dkim=pass dkdomain=csgroup.eu dmarc=pass fromdomain=csgroup.eu);
       spf=pass (google.com: domain of christophe.leroy@csgroup.eu designates 40.107.12.74 as permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:content-transfer-encoding:content-id
         :user-agent:content-language:accept-language:in-reply-to:references
         :message-id:date:thread-index:thread-topic:subject:cc:to:from:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=mCR8qC5Ibe0N3ydSfhnIdMP6YPWryScH7rnLSwAqyqM=;
        b=nK9aG+Dqg5wXy3RGeUUl6RvL08f3vYOiM1aEpTLKH1ST0oMpZd6/6PZu6udOi1eE75
         Eb0aIk1j/pEknQVZ7z55cvZlStQuKMOsQJh9e/CNtAhi9c7ihMATQ+jxau2QpZuq1JFl
         mbdG6g0zeSoy+lkf0ursQiYihJpHx2wtFBtusQoO3aohgU6DQc9hqJis56A0VeTJ3Tyr
         XWwbFnIyhKUDqCKKaaAoGfbytyFmucx4GMP+X2xsSITWnZMKOjpuY7h+XkoOwYiQSVJb
         FcNzbDZ806Bg6BiKvwz21zr+dy92ciEvFrvkF9Mn0E7Rt2c6aGeUYxTYrXK3Mpg3G76a
         YKKg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :content-transfer-encoding:content-id:user-agent:content-language
         :accept-language:in-reply-to:references:message-id:date:thread-index
         :thread-topic:subject:cc:to:from:x-gm-message-state:sender:from:to
         :cc:subject:date:message-id:reply-to;
        bh=mCR8qC5Ibe0N3ydSfhnIdMP6YPWryScH7rnLSwAqyqM=;
        b=WvtHqh8aps33NU6V1oMZnbulZt5daWyg02hQR3kFoY8CNMVCpTVzccFgGbVZWMpl+f
         GJadNP9eWyrpGWx6dQBrnoxpSce4dVgbFdH1VVR4b3fe2XCtVpThn4gEr6+0kY0zk4De
         K6wxZrIzku5TkNwUD7aKpmWQQs6KBk51+2CeIIHragN6N3CIVa/MTtQQHmXVUDR9rRqX
         xhLY9BUoVOn+QOI4JLzbECBK4R/AmLLElYzL/c3D2I9GQ/nDF33v8NQaU53SJq3fuzyl
         pmQsuhaD+AFKLeEG+oKJUBTZaGKUpPlnEoGKBOk9A90LxRArKI3flfBHF1RHh3oY5lrA
         5CEw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf2bBm099gJ5M8mXWaK/wdT1X3hf1HLPCwQ+1ruynW2En3wgRW3O
	zHiCLntIIp4e6gj9Ys0A/Zw=
X-Google-Smtp-Source: AMsMyM6b+pGG+aBtawHk8QtIBB2LrPK3F8mx3hgVdEnKb7m/pgfaZFprv846gxdbXFVpOSyisKLqoA==
X-Received: by 2002:a2e:6e0e:0:b0:26d:ce12:2495 with SMTP id j14-20020a2e6e0e000000b0026dce122495mr291720ljc.82.1665076964861;
        Thu, 06 Oct 2022 10:22:44 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:91d5:0:b0:261:d944:1ee6 with SMTP id u21-20020a2e91d5000000b00261d9441ee6ls540111ljg.0.-pod-prod-gmail;
 Thu, 06 Oct 2022 10:22:43 -0700 (PDT)
X-Received: by 2002:a05:651c:1111:b0:26c:6b0f:472c with SMTP id e17-20020a05651c111100b0026c6b0f472cmr253311ljo.384.1665076963699;
        Thu, 06 Oct 2022 10:22:43 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1665076963; cv=pass;
        d=google.com; s=arc-20160816;
        b=bs96ieQEKcIKNq2wsjtkjrgDul9b7DrhTF58LwDRZR8UCnG8yfTMjqviQGi0JZsZtg
         n0enUqQ8gHGaoqjuCMZzUbE6iOyMKbMbzX5Bg3uazjJmDHnnljw0g6BjLWq1kA1XiZI6
         +v/kUoc9SLCQY4HTd1KpGj66wsuZPC3qHfK25yrvYG0Q9Z3yFNcbukIYo+7M5DKmhAio
         GOThIQjIYaQB3M0Okat7yjh2HjXsnINYFvhMtbEnsSwD4wWwZcqaqe1raVW5eQvOoc4G
         QJq0x46Fbv2IkxlSt32CmyfxkVtxqmYw92gndeoFmC2FEQU48jkaZ9sXtxlSbva8rZ76
         p+2w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:content-transfer-encoding:content-id:user-agent
         :content-language:accept-language:in-reply-to:references:message-id
         :date:thread-index:thread-topic:subject:cc:to:from:dkim-signature;
        bh=JEJ0X/HXgPcxrMfMufxKj+fUp6CJ4LGRqrwHihOttYA=;
        b=xSV9VV3d4fJwOwfZpQO0l/69I7CHeEBi67O1mA4U61BjJ2Jn6/z2k7LqufW6/D1nhg
         wqO9GmSNdUYcvK+KYb7zUpa4pamlu4/y4ftS6kQy+F5hpX0mWEWvAKsOAym6FihL33nA
         37Kc3M4+BU54Zzm0c7AMk4vuMqsaSahVu6IeTOOcy+svIcJc8UE+f0glHMWCnM4Dv0i3
         chfoKYbZIM3MTz9f0HKZfcz28Xh5JBUhxZFZHt6R3zgX9DBOB4w2pbZmKEcdtckSXGLG
         tG1O7t+lMki1wRT0lk2QVRgYsTXg3WOWCq+obnbKCh9dcUTnI6N3xOstX5FDw2fcl0Ql
         RgZg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@csgroup.eu header.s=selector1 header.b=KWPR9kmI;
       arc=pass (i=1 spf=pass spfdomain=csgroup.eu dkim=pass dkdomain=csgroup.eu dmarc=pass fromdomain=csgroup.eu);
       spf=pass (google.com: domain of christophe.leroy@csgroup.eu designates 40.107.12.74 as permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu
Received: from FRA01-PR2-obe.outbound.protection.outlook.com (mail-eopbgr120074.outbound.protection.outlook.com. [40.107.12.74])
        by gmr-mx.google.com with ESMTPS id p8-20020a2eb988000000b0026bfbc4be3csi650998ljp.7.2022.10.06.10.22.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 06 Oct 2022 10:22:43 -0700 (PDT)
Received-SPF: pass (google.com: domain of christophe.leroy@csgroup.eu designates 40.107.12.74 as permitted sender) client-ip=40.107.12.74;
ARC-Seal: i=1; a=rsa-sha256; s=arcselector9901; d=microsoft.com; cv=none;
 b=age+G8iNIrVuEPOWbvb64N1s1USQwpQYHDphwTRYsk7f049KgAOO1CMxm4ATg/h6weCOn+Cch+cjG6aomqJCIrQ+VxvLQy9U2+qa1gX9LjsHKJKUI85NOkQoY7DfwcjGsxJ/tnNSbWj5g+zKuzpasAkQ2fJydPt7Qy6NH7ZFTMi4Rx2FyuJj7lUM55sOHx0g6wXXREUciyLu2hy6G0yOmrJJBulk28l0IB1yNcjNwNrRteOjGWocmSS5uVRAVzjXEkQT/YMi6cnKMAEZ9scUkH+xTp0WbK+3AFM2K1lOm70Zy10VIKgP788NzHFNcmphvrjNkmv5daS6s7sVtDoH9w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector9901;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=JEJ0X/HXgPcxrMfMufxKj+fUp6CJ4LGRqrwHihOttYA=;
 b=fmxfi2VsHrRf06I5XmIHvbcleiPcvX9xEIk7hk6RL094aW53m2G4QNcazT5IGEg4rk7G5IEVp3HgMEqw5dkNtnwEakokhJThToRlO+SlABDLeahGu2FYtE7FEO/GhgQZC8R1/Mm7XZTaseKj/yp5d5v95QTv5N5ICqV45PC8VDXuf9RZTms2kXiNRR/16NASEpzFw2x7xsVDwK3X+x/r0pHAUwDkf65ALopvVOTh1Kl20LT1PVxQ8MheAyBArLS/fx1N2RNd72WDafDgsZ6uv4KChOeOPrToSTiOwY7m1zvgWTtyZYrYqWVxzEEOrWdJpK9g8bVzJoC07qsp5TxDGg==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=csgroup.eu; dmarc=pass action=none header.from=csgroup.eu;
 dkim=pass header.d=csgroup.eu; arc=none
Received: from MRZP264MB2988.FRAP264.PROD.OUTLOOK.COM (2603:10a6:501:31::15)
 by PR0P264MB2471.FRAP264.PROD.OUTLOOK.COM (2603:10a6:102:1e2::12) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.5676.39; Thu, 6 Oct
 2022 17:22:41 +0000
Received: from MRZP264MB2988.FRAP264.PROD.OUTLOOK.COM
 ([fe80::c854:380d:c901:45af]) by MRZP264MB2988.FRAP264.PROD.OUTLOOK.COM
 ([fe80::c854:380d:c901:45af%5]) with mapi id 15.20.5676.036; Thu, 6 Oct 2022
 17:22:41 +0000
From: Christophe Leroy <christophe.leroy@csgroup.eu>
To: "Jason A. Donenfeld" <Jason@zx2c4.com>, "linux-kernel@vger.kernel.org"
	<linux-kernel@vger.kernel.org>, "patches@lists.linux.dev"
	<patches@lists.linux.dev>
CC: Andreas Noever <andreas.noever@gmail.com>, Andrew Morton
	<akpm@linux-foundation.org>, Andy Shevchenko
	<andriy.shevchenko@linux.intel.com>, Borislav Petkov <bp@alien8.de>, Catalin
 Marinas <catalin.marinas@arm.com>, =?utf-8?B?Q2hyaXN0b3BoIELDtmhtd2FsZGVy?=
	<christoph.boehmwalder@linbit.com>, Christoph Hellwig <hch@lst.de>, Daniel
 Borkmann <daniel@iogearbox.net>, Dave Airlie <airlied@redhat.com>, Dave
 Hansen <dave.hansen@linux.intel.com>, "David S . Miller"
	<davem@davemloft.net>, Eric Dumazet <edumazet@google.com>, Florian Westphal
	<fw@strlen.de>, Greg Kroah-Hartman <gregkh@linuxfoundation.org>, "H . Peter
 Anvin" <hpa@zytor.com>, Heiko Carstens <hca@linux.ibm.com>, Helge Deller
	<deller@gmx.de>, Herbert Xu <herbert@gondor.apana.org.au>, Huacai Chen
	<chenhuacai@kernel.org>, Hugh Dickins <hughd@google.com>, Jakub Kicinski
	<kuba@kernel.org>, "James E . J . Bottomley" <jejb@linux.ibm.com>, Jan Kara
	<jack@suse.com>, Jason Gunthorpe <jgg@ziepe.ca>, Jens Axboe
	<axboe@kernel.dk>, Johannes Berg <johannes@sipsolutions.net>, Jonathan Corbet
	<corbet@lwn.net>, Jozsef Kadlecsik <kadlec@netfilter.org>, KP Singh
	<kpsingh@kernel.org>, Kees Cook <keescook@chromium.org>, Marco Elver
	<elver@google.com>, Mauro Carvalho Chehab <mchehab@kernel.org>, Michael
 Ellerman <mpe@ellerman.id.au>, Pablo Neira Ayuso <pablo@netfilter.org>, Paolo
 Abeni <pabeni@redhat.com>, Peter Zijlstra <peterz@infradead.org>, Richard
 Weinberger <richard@nod.at>, Russell King <linux@armlinux.org.uk>, Theodore
 Ts'o <tytso@mit.edu>, Thomas Bogendoerfer <tsbogend@alpha.franken.de>, Thomas
 Gleixner <tglx@linutronix.de>, Thomas Graf <tgraf@suug.ch>, Ulf Hansson
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
	<x86@kernel.org>
Subject: Re: [PATCH v3 4/5] treewide: use get_random_bytes when possible
Thread-Topic: [PATCH v3 4/5] treewide: use get_random_bytes when possible
Thread-Index: AQHY2aROlLqkBYztHUmTuAtdwYDXna4BnTAA
Date: Thu, 6 Oct 2022 17:22:41 +0000
Message-ID: <0eea033d-7018-c777-f3e8-2239916aed9b@csgroup.eu>
References: <20221006165346.73159-1-Jason@zx2c4.com>
 <20221006165346.73159-5-Jason@zx2c4.com>
In-Reply-To: <20221006165346.73159-5-Jason@zx2c4.com>
Accept-Language: fr-FR, en-US
Content-Language: en-US
X-MS-Has-Attach: 
X-MS-TNEF-Correlator: 
user-agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101
 Thunderbird/102.3.1
x-ms-publictraffictype: Email
x-ms-traffictypediagnostic: MRZP264MB2988:EE_|PR0P264MB2471:EE_
x-ms-office365-filtering-correlation-id: e2a27763-3ea2-4f5b-fdf4-08daa7bf5fbe
x-ms-exchange-senderadcheck: 1
x-ms-exchange-antispam-relay: 0
x-microsoft-antispam: BCL:0;
x-microsoft-antispam-message-info: 20r9Tx2pwuKezrfaWAbS82QYH8y7YVUeqQPOOI+bDEW8wTwryUJNqpp3xxMSnSjyNuIMQHothQsS7OsbwdxyN+OUMd6+xb/PATGsFKK4hxGhgvPt/AaYARMTFSRs+z9sOR5wJkY6jxnhzPyKe03cQZgvbw1ld+Hm/7aw0l9mhkA2mWhPD/pEEB3ppP7pVThHWxkB9E6n93DvgoSPqyi41EsXru5E85TK0qSdMqxV097wftKe/yd0agul3Pb/VH08M6qD3DX0wrYXm6HcAT6bs6EInM78nJE6wwWMac2JE1fnxYKH/Nq6ZQiypcRMeD8IayogbpYf1HVplqEfx9fogQG9whNChKSEX2TUGZFomY/j4VXqWYma13u/GVYQJmKBIYy0UR5Exa4epINzX0TIQXq4JgWyuPjR/nn5/an/q+Juw790UVQTv2eg1iaHjr0J6R7M+hxdLpJJ0a/xbh4jmNkSXRmcucY0lg9HxCWaX+1VxWDAoSY5bcOsNp005aZMSb46MC6fZyD4M5Xew0dun+LGfI7E0eBZF30z/Laz6oYr2NbfGVBUxAMoDuTazm3O6kdw0+9BCUQqDwZZgAtYo6tuE8GMQauG0/88bIBIyOFFn0kFCiouz0kLoK9WSLM09y55W2XXKPSRk+Yqt4FgpT3WCWZquCwVreH6YelVcjYTeM6OiJMWI+FIpATLQTeyf4s2XHK6iTbG0wz6KNucERq1HG7u08FnEbs+qbtN8lSDCd9hIErZ9IU0JEQWqEWgAHIF5KBiaM0zFqblqywltlsjBSWARMksHekBcnyxZpOHJvMUL/Qz+r/xhj7M1FBxOTazuGrmiYBPbZUmdcslUQ==
x-forefront-antispam-report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:MRZP264MB2988.FRAP264.PROD.OUTLOOK.COM;PTR:;CAT:NONE;SFS:(13230022)(4636009)(346002)(136003)(376002)(396003)(366004)(39860400002)(451199015)(83380400001)(186003)(2616005)(31696002)(38100700002)(38070700005)(66574015)(122000001)(4744005)(44832011)(7336002)(7366002)(7406005)(7416002)(2906002)(41300700001)(5660300002)(8936002)(6486002)(478600001)(26005)(6512007)(6506007)(8676002)(4326008)(64756008)(66476007)(66556008)(66946007)(76116006)(71200400001)(91956017)(316002)(54906003)(110136005)(86362001)(66446008)(36756003)(31686004)(45980500001)(43740500002);DIR:OUT;SFP:1101;
x-ms-exchange-antispam-messagedata-chunkcount: 1
x-ms-exchange-antispam-messagedata-0: =?utf-8?B?UnVzTlhtSTZPNE9wZ05ERFgwcGFIY0l6bXNKZGJqOVpGRjRDS1dua05SRmZh?=
 =?utf-8?B?UDE1UTQyTmpuUjk2VFJiYTYzc0pRN3hlSGpkK2t4ZGZMM0pPOEE1TmNpVFFa?=
 =?utf-8?B?S0FBL1d2dW1vK1NKR3VtbmZxQiswTUxXdFpBM2pjcHJJSGF4VlBUVlhmaWg4?=
 =?utf-8?B?WWE0Q244dWE2MndBRWRaSU01V0M5bG81Wis5SlJIcUJoTTFVSkN0RHk5cy83?=
 =?utf-8?B?QXFrNVovU2dmT3lza2tFaERZaHo5VTRrTkJoOVg4ODN6eUsxWGFpSDdkZnZM?=
 =?utf-8?B?MmQrTFBOaXNsbnpQVXEweUxEd2pjSzRlVUFrVGNLN3MzajJDbmwwZ2Y0dEtF?=
 =?utf-8?B?QmtOSkZqamZWcjk1RFM3RXUrWTBNN2NpVjAyNm5razRCNDVPZW8rbkgrdklF?=
 =?utf-8?B?anVqWkpDSklhMVpVd0htQXBZNFJtdDloU1dhaDg4cDEyTGcvZUpjaksxbzlR?=
 =?utf-8?B?RDNHV2NZSnZXNzFvcnN5WkVIT285cElNK0QyNitjLzFhaDBsWWZWOXVwV2E0?=
 =?utf-8?B?VGZvajNEbWNwZjlleG4zRmVhSmMzaWhzcFZsT0ZhTHlhbEJoK1lFT0VVVU90?=
 =?utf-8?B?MFlGcDZoVVNMN01GMG5NaFRYTUFGR2hieU5hMnlDZjllMDQvZlN4U01uSWlV?=
 =?utf-8?B?NHMva3h3SmgxcTRZZkxMUmx0YnZKRzJCZGloSUFQMVZqZ0JERzhxN3l1d0Rw?=
 =?utf-8?B?ZUpYdGZlWkoxcjNIUDJaQ3Rocms5NDB4SjIvWEVxOElROUlhZGRsQmJwaWgv?=
 =?utf-8?B?YkhRV2ZKSTUrQ0x3ajFFVWR0eUdJZnNjYU0rMmdSUVZqRFZpQTVjb3ZwaDJN?=
 =?utf-8?B?TUx0YnpjaG5kVmNKcVZhclIxcUhySVlzdCtkdzQvdWFOTVBva3d3Z2htbVZw?=
 =?utf-8?B?QzdGMExMVkZEUG9EYU0vWU9SekNqTFpVNTlTb3d6TVhwLzJmQWRucEhUY3I1?=
 =?utf-8?B?aDFqUDZlMkdSckdpYUJscy92K0x1UUhqY0dBZWhIdWdCS2hFN3RxdEJ3TE9U?=
 =?utf-8?B?bXd4azFpUXRzVVJRUGNYTnlJdGpEQ2Q1RVNkVkg4MHBnYlFodUNnZk85ekZV?=
 =?utf-8?B?NGVmUCtUYnFPeHBQM1NpOUJEZHBEb2pvaEJwZFVoVUYxQklwQyt4YkUvUUJn?=
 =?utf-8?B?VTNPdURMRXZ4cWZQa1Y3dloxSjBnZkNDdGFBYm9ka3FOeENaQThQbDNWbWUw?=
 =?utf-8?B?U2RXRmtpUmZ1Tk8yMk8wbmRMVjV6b01PNjdYVndsb25ub1BpN2pQdTF3Z3pw?=
 =?utf-8?B?K1FrVnhrazM1L0pwVWNHSUt1TWN3Z1UxVWFzR3lJYVZsZ3ZnR3Fnb0dPbDFZ?=
 =?utf-8?B?Z3RpUHVlL0JOV2FBK0VtdU9BZmgwNkZuRGRHZk8xL01GeWpSd2JJWDNWRzNY?=
 =?utf-8?B?M0NKV21nbjd2RzlPNXk4UHBXeG9jbGgveDdsL2FCckJvSjluY3pCSktPSzZX?=
 =?utf-8?B?RlBPcWErb3BibXFMRGEraFlyMlRwZUtvb2NpV1MwcmEweTVsVWppRGxJdy9h?=
 =?utf-8?B?TFB5LzlmN1R3YlozMUtlTDdwYm5JeWl4eTVabGR6MURQY0xtdUJJbm5mVFBW?=
 =?utf-8?B?dGs1RUFNcGRaSk83Zkw1MXorVjBuazc5WkVyd0JrSHBxcDZjcVpsQ1V4L29W?=
 =?utf-8?B?S0FNOTFDWUFPVElGUWRMU25LVCtsQVNyU0RDbnJvK2x5RlMxNVRaSnpqWjFT?=
 =?utf-8?B?ekJBdmw3bjlzMGVockJaRjVkRFEzeXVxai9td1pPb1d0RUFMU09vNFpNdjR6?=
 =?utf-8?B?TXB6aUhlSFdxVm1CRFh2ckRiR3J2cWxTaDg5ODlMa09sZnBkclZGWUhKakQ5?=
 =?utf-8?B?Y1h0TVZpVU9Sa3pUd2pIdnhOUGNiNnZFY0w2ZjI1THpRVzQ4YUpJWjhGT2F6?=
 =?utf-8?B?TW9hWnppSzIwYmNnelE0a2E3SnZ2K1FWQVd4OGpXeWh2bWJ5c1lvTGVybnc4?=
 =?utf-8?B?K01MbG1qbUM3N1ZhMnZsSHp2cUVWYTd1TXVOT09DMFFJc09JamN2amlxc2ZN?=
 =?utf-8?B?MmhCSzBZQmo3Q0lKdVUrZ1pRNmFNdi9PUTVPRVBnQzFYYmZvT0J0SGh2dGVp?=
 =?utf-8?B?OHRqSDUvQWtycnFFVXp4TnBnMWYySkhqUGdnNjlGY0dIS055T2NGL2UrZERI?=
 =?utf-8?B?cDlSbjAxdUNLQWUxSmNyRmV2K2ZMRyt0RDB1VjRhTnlKbVpFNis2bUZuUGNo?=
 =?utf-8?Q?pqY6jRBVOR0sNVmTO6IUDJw=3D?=
Content-Type: text/plain; charset="UTF-8"
Content-ID: <944C3E8CB2B01D44B74BB4038DDFEDBA@FRAP264.PROD.OUTLOOK.COM>
Content-Transfer-Encoding: quoted-printable
MIME-Version: 1.0
X-OriginatorOrg: csgroup.eu
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-AuthSource: MRZP264MB2988.FRAP264.PROD.OUTLOOK.COM
X-MS-Exchange-CrossTenant-Network-Message-Id: e2a27763-3ea2-4f5b-fdf4-08daa7bf5fbe
X-MS-Exchange-CrossTenant-originalarrivaltime: 06 Oct 2022 17:22:41.3134
 (UTC)
X-MS-Exchange-CrossTenant-fromentityheader: Hosted
X-MS-Exchange-CrossTenant-id: 9914def7-b676-4fda-8815-5d49fb3b45c8
X-MS-Exchange-CrossTenant-mailboxtype: HOSTED
X-MS-Exchange-CrossTenant-userprincipalname: pTHm9BWHosgLsHe/r9X0INoJ+/FB5Kooii7fNm9KKWGwNrY4ZYq2KxYscZa7ptaYPFNiL9EevIzry/WEHTlBENklIU57c8mwdJeGgS2nL3E=
X-MS-Exchange-Transport-CrossTenantHeadersStamped: PR0P264MB2471
X-Original-Sender: christophe.leroy@csgroup.eu
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@csgroup.eu header.s=selector1 header.b=KWPR9kmI;       arc=pass
 (i=1 spf=pass spfdomain=csgroup.eu dkim=pass dkdomain=csgroup.eu dmarc=pass
 fromdomain=csgroup.eu);       spf=pass (google.com: domain of
 christophe.leroy@csgroup.eu designates 40.107.12.74 as permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu
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



Le 06/10/2022 =C3=A0 18:53, Jason A. Donenfeld a =C3=A9crit=C2=A0:
> The prandom_bytes() function has been a deprecated inline wrapper around
> get_random_bytes() for several releases now, and compiles down to the
> exact same code. Replace the deprecated wrapper with a direct call to
> the real function.
>=20
> Reviewed-by: Kees Cook <keescook@chromium.org>
> Signed-off-by: Jason A. Donenfeld <Jason@zx2c4.com>

Reviewed-by: Christophe Leroy <christophe.leroy@csgroup.eu> (Powerpc part)

> ---
>   arch/powerpc/crypto/crc-vpmsum_test.c       |  2 +-
>=20
> diff --git a/arch/powerpc/crypto/crc-vpmsum_test.c b/arch/powerpc/crypto/=
crc-vpmsum_test.c
> index c1c1ef9457fb..273c527868db 100644
> --- a/arch/powerpc/crypto/crc-vpmsum_test.c
> +++ b/arch/powerpc/crypto/crc-vpmsum_test.c
> @@ -82,7 +82,7 @@ static int __init crc_test_init(void)
>  =20
>   			if (len <=3D offset)
>   				continue;
> -			prandom_bytes(data, len);
> +			get_random_bytes(data, len);
>   			len -=3D offset;
>  =20
>   			crypto_shash_update(crct10dif_shash, data+offset, len);

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/0eea033d-7018-c777-f3e8-2239916aed9b%40csgroup.eu.
