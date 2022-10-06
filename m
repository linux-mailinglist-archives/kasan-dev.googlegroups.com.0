Return-Path: <kasan-dev+bncBDA5BKNJ6MIBBNVF7OMQMGQEIY22XWA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23e.google.com (mail-lj1-x23e.google.com [IPv6:2a00:1450:4864:20::23e])
	by mail.lfdr.de (Postfix) with ESMTPS id 739E65F673A
	for <lists+kasan-dev@lfdr.de>; Thu,  6 Oct 2022 15:05:59 +0200 (CEST)
Received: by mail-lj1-x23e.google.com with SMTP id e22-20020a2e8ed6000000b0026dd0b881d4sf708504ljl.5
        for <lists+kasan-dev@lfdr.de>; Thu, 06 Oct 2022 06:05:59 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1665061559; cv=pass;
        d=google.com; s=arc-20160816;
        b=t46/S08FA5Je2LKqWvytEIApLwIjpnvrwDo2RCshr/3yT9CDkUFtaBZGOIUdizhKBd
         vAo2vhmSOoKgZmgYZ4MJ+QrpyYoYm+5asPi00hW+kUtpoyEKRmh/tkhVjgcSPr1kvuV+
         XTHltMILaSDZ12HIaQjCnIa8tbIFhlxjfsTyIj/AvF5m4peOsHJTaUqOY+rnAFF1v5xo
         SqsDFuaWCdf5vvhj8I7HzTzlYWcZZ4WXEvlNx/eBLV6lqNd4jawnxmEnxdMe6EDAWPi+
         ShLtXc7IAJ8t4LyG8ofq8KOCaYveV0Uew8IaPaISfqIQ9oiIyt+QTmVTbZNP6urpBLdX
         larQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:organization:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=avQStzZJdX1lD4r4hMLLgSGxXW7xOSiWbJwCnaVEUWM=;
        b=eZqqARrwZ8qo9rNqTDq+8zEDidqPwH4UyeyTUNOfBFs1Pe2xkSSnosRC3mFEeuFlKd
         g3DtlvxVu5AeCoc8jPpWx7si3dU1B4XkjyDCGH2u6c+iUe3BBeyHCOzJzmLXKNOHT26Q
         p83dMx9HPvsDkpdQxIZGMOjjEYFMfA6WCv96hRTIWj2czu4EgOW+plm7V1Se7/4tNumh
         ixF60IYFUIMnoeF1/UcdO+YTk9a1nSWUt7XJHMwn2WVfSturP/cXkm5lKSPDQKo+W7yL
         gYuOEUbTWgijm0x8E4D3gGvAXPAiGXaMujR7hyFMFiuWVqRtYFvYgnPs+M9PNRhFv+PX
         0smg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=klOdu9BD;
       spf=pass (google.com: best guess record for domain of andriy.shevchenko@linux.intel.com designates 134.134.136.31 as permitted sender) smtp.mailfrom=andriy.shevchenko@linux.intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:organization:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :from:to:cc:subject:date;
        bh=avQStzZJdX1lD4r4hMLLgSGxXW7xOSiWbJwCnaVEUWM=;
        b=nCsaH0935VemMlnmrdiWVC1Q48DCV66eMhveLy+WRm1O8FjUTfHHeg3wg1dcACwOS0
         m09EcSixvbBWCmP6MedDZ3LDcAMe7e7U5oytOr3ej2/MzvB1lTXcFxrEW/8pOPcewfD5
         oie2pKQ6ZVUX76RU0occACMVeTxQcubBCgJlifz6/+yt0KCBcqrKB18wrOUPs58KYqrC
         LilW6Og5gOE74wEflqCoj3i7x0FmBw/0x/MwF86TlW86UUfE4+3iwJNK+1AiRbT2J3ps
         cCGVR24SFEgTWrwoZIZzslLOCuj4wyn5MQA0hOgIgfuxZHbCGilt+t7NrugcWWr+yUU/
         gDlw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:organization
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:x-gm-message-state:sender:from:to:cc
         :subject:date;
        bh=avQStzZJdX1lD4r4hMLLgSGxXW7xOSiWbJwCnaVEUWM=;
        b=03aKlCUq62gJerNinDZmbMpSNrDOUv4h5ij2nsq6XxfwC3T9PZLFbE6bGif2JmR1p2
         0g59l3HXZfmFvyOQk2UTWx93LRbOkM3O9V3SwsQedsk13K8WIrd53x2mBcLLgx7FHWyo
         ydhR1ZUwCGL57M2HxO76Kr0RvXhDmuh8FHjFxDn8aHMZmpgbRRRCy9StPE5zl0cWs+Sy
         W/Q4GTiTkvm032nNCbloxHDinL/DxLzJyAPLg9aVZH1/l16JdqcpTN+yOpoTY8Gr/dae
         mgriv6wUSdyoiCNBoW29XtNDCK3Anz3dLBX3M70d0XKcvjvxS+pNg8PvyqrLkUCAgJnr
         4uYA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf3BZb2KXOAVD3A+V00S8nei5kIpohsDeqL0chOCmf4CqluqmMG6
	wwBAWNKQjXoLr+EPbOkg8ME=
X-Google-Smtp-Source: AMsMyM7IUPZX4unrSFgpeeFhu1HUq3y2kX6kDAVYE/LQBYdvoCCD7fuwDFmbvtDrMOHsDX8KqPgwvg==
X-Received: by 2002:ac2:46da:0:b0:4a2:2963:71b0 with SMTP id p26-20020ac246da000000b004a2296371b0mr1755896lfo.600.1665061558871;
        Thu, 06 Oct 2022 06:05:58 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:4ec6:0:b0:4a2:3951:eac8 with SMTP id p6-20020ac24ec6000000b004a23951eac8ls1236399lfr.0.-pod-prod-gmail;
 Thu, 06 Oct 2022 06:05:57 -0700 (PDT)
X-Received: by 2002:ac2:5611:0:b0:4a2:7d0d:bf7a with SMTP id v17-20020ac25611000000b004a27d0dbf7amr449027lfd.60.1665061557695;
        Thu, 06 Oct 2022 06:05:57 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1665061557; cv=none;
        d=google.com; s=arc-20160816;
        b=bEGdwklz1KgvvJkwLVgdX1mIF7gIPfHsxGzTozLQ+KuEDW220h8afVYiwKTRFrxbBV
         zoz/rh5Xkq0zcBgwg1TpaQEM3IzEURk2HxLMhgHIMMXg1SZspDri/1ucz044AVmLUGLi
         Bkc1PvZvnA2dh9kwQsXk6LEcYHALxsko7uuGEPDfX87+OxlV4tymqc1xyhoqIlfEA1GK
         y0Rnm4cBJM4Qt4UuDhXIrmL5mZSUhgKatg1FFLegFQDQkJL/Jx7MEnG5f+a1ItcHMA3f
         vfE61CjuOR/2h6v9Za+JXlvToZYaaZQ5vIKngjpcyeB2354d3Ir/KNfzVOTKFH7WmQmr
         hSfw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=organization:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:dkim-signature;
        bh=0ENsN90teNsuQpmekN7b+hdYLbg48hC1jdG1eR+cyBQ=;
        b=b1kCEnm7IcJMGvMO5PB7kRblNi6orw41NVkoA0zlXHbkX0DWswyoawPxsPdsxQ5PO3
         lDKAztTa8wIG4uf422/nBTQp/UTFPt6gMC7KtFy3KhZ3Te8DzdIxGcHl2bzp5+jSq9Ix
         ESGkbHi+AIe/DE8y9fdE+uBx1ZEd6tNXCTvAUOkibtZ8a737S/G3cBwejFTJSS+OWEfp
         TRsKQEr3DVyeVKuYvIcQSprY1J3pw+hsIrOAOZtlQRgDy5U6pHC/wp4LAe709+zl4BUi
         C97TVkVzPwAts43b3JoGyb3OC5bhUCeBKiUgjBvcPHu2unIlw2iCr8tVgHe/QZhzvWTQ
         Ffuw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=klOdu9BD;
       spf=pass (google.com: best guess record for domain of andriy.shevchenko@linux.intel.com designates 134.134.136.31 as permitted sender) smtp.mailfrom=andriy.shevchenko@linux.intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mga06.intel.com (mga06b.intel.com. [134.134.136.31])
        by gmr-mx.google.com with ESMTPS id r12-20020ac25f8c000000b004a222ff195esi494943lfe.11.2022.10.06.06.05.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 06 Oct 2022 06:05:57 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of andriy.shevchenko@linux.intel.com designates 134.134.136.31 as permitted sender) client-ip=134.134.136.31;
X-IronPort-AV: E=McAfee;i="6500,9779,10491"; a="365374657"
X-IronPort-AV: E=Sophos;i="5.95,163,1661842800"; 
   d="scan'208";a="365374657"
Received: from orsmga003.jf.intel.com ([10.7.209.27])
  by orsmga104.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 06 Oct 2022 06:05:55 -0700
X-ExtLoop1: 1
X-IronPort-AV: E=McAfee;i="6500,9779,10491"; a="575816142"
X-IronPort-AV: E=Sophos;i="5.95,163,1661842800"; 
   d="scan'208";a="575816142"
Received: from smile.fi.intel.com ([10.237.72.54])
  by orsmga003.jf.intel.com with ESMTP; 06 Oct 2022 06:05:33 -0700
Received: from andy by smile.fi.intel.com with local (Exim 4.96)
	(envelope-from <andriy.shevchenko@linux.intel.com>)
	id 1ogQZ0-0039VB-0C;
	Thu, 06 Oct 2022 16:05:22 +0300
Date: Thu, 6 Oct 2022 16:05:21 +0300
From: Andy Shevchenko <andriy.shevchenko@linux.intel.com>
To: Jason Gunthorpe <jgg@ziepe.ca>
Cc: "Jason A. Donenfeld" <Jason@zx2c4.com>,
	Kees Cook <keescook@chromium.org>, linux-kernel@vger.kernel.org,
	Ajay Singh <ajay.kathat@microchip.com>,
	Akinobu Mita <akinobu.mita@gmail.com>,
	Alexandre Torgue <alexandre.torgue@foss.st.com>,
	Amitkumar Karwar <amitkarwar@gmail.com>,
	Andreas Dilger <adilger.kernel@dilger.ca>,
	Andreas =?iso-8859-1?Q?F=E4rber?= <afaerber@suse.de>,
	Andreas Noever <andreas.noever@gmail.com>,
	Andrew Lunn <andrew@lunn.ch>,
	Andrew Morton <akpm@linux-foundation.org>,
	Andrii Nakryiko <andrii@kernel.org>,
	Andy Gospodarek <andy@greyhouse.net>,
	Andy Lutomirski <luto@kernel.org>,
	Anil S Keshavamurthy <anil.s.keshavamurthy@intel.com>,
	Anna Schumaker <anna@kernel.org>,
	Arend van Spriel <aspriel@gmail.com>,
	Ayush Sawal <ayush.sawal@chelsio.com>,
	Borislav Petkov <bp@alien8.de>, Chao Yu <chao@kernel.org>,
	Christoph =?iso-8859-1?Q?B=F6hmwalder?= <christoph.boehmwalder@linbit.com>,
	Christoph Hellwig <hch@lst.de>,
	Christophe Leroy <christophe.leroy@csgroup.eu>,
	Chuck Lever <chuck.lever@oracle.com>,
	Claudiu Beznea <claudiu.beznea@microchip.com>,
	Cong Wang <xiyou.wangcong@gmail.com>,
	Dan Williams <dan.j.williams@intel.com>,
	Daniel Borkmann <daniel@iogearbox.net>,
	"Darrick J . Wong" <djwong@kernel.org>,
	Dave Hansen <dave.hansen@linux.intel.com>,
	David Ahern <dsahern@kernel.org>,
	"David S . Miller" <davem@davemloft.net>,
	Dennis Dalessandro <dennis.dalessandro@cornelisnetworks.com>,
	Dick Kennedy <dick.kennedy@broadcom.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Eric Dumazet <edumazet@google.com>, Florian Westphal <fw@strlen.de>,
	Franky Lin <franky.lin@broadcom.com>,
	Ganapathi Bhat <ganapathi017@gmail.com>,
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
	Gregory Greenman <gregory.greenman@intel.com>,
	"H . Peter Anvin" <hpa@zytor.com>, Hannes Reinecke <hare@suse.de>,
	Hans Verkuil <hverkuil@xs4all.nl>,
	Hante Meuleman <hante.meuleman@broadcom.com>,
	Hao Luo <haoluo@google.com>, Haoyue Xu <xuhaoyue1@hisilicon.com>,
	Heiner Kallweit <hkallweit1@gmail.com>,
	Helge Deller <deller@gmx.de>,
	Herbert Xu <herbert@gondor.apana.org.au>,
	Hideaki YOSHIFUJI <yoshfuji@linux-ipv6.org>,
	Hugh Dickins <hughd@google.com>,
	Igor Mitsyanko <imitsyanko@quantenna.com>,
	Ilya Dryomov <idryomov@gmail.com>, Ingo Molnar <mingo@redhat.com>,
	Jack Wang <jinpu.wang@ionos.com>, Jaegeuk Kim <jaegeuk@kernel.org>,
	Jaehoon Chung <jh80.chung@samsung.com>,
	Jakub Kicinski <kuba@kernel.org>,
	Jamal Hadi Salim <jhs@mojatatu.com>,
	"James E . J . Bottomley" <jejb@linux.ibm.com>,
	James Smart <james.smart@broadcom.com>, Jan Kara <jack@suse.com>,
	Jay Vosburgh <j.vosburgh@gmail.com>,
	Jean-Paul Roubelat <jpr@f6fbb.org>,
	Jeff Layton <jlayton@kernel.org>, Jens Axboe <axboe@kernel.dk>,
	Jiri Olsa <jolsa@kernel.org>, Jiri Pirko <jiri@resnulli.us>,
	Johannes Berg <johannes@sipsolutions.net>,
	John Fastabend <john.fastabend@gmail.com>,
	John Stultz <jstultz@google.com>, Jon Maloy <jmaloy@redhat.com>,
	Jonathan Corbet <corbet@lwn.net>,
	Jozsef Kadlecsik <kadlec@netfilter.org>,
	Julian Anastasov <ja@ssi.bg>, KP Singh <kpsingh@kernel.org>,
	Kalle Valo <kvalo@kernel.org>, Keith Busch <kbusch@kernel.org>,
	Lars Ellenberg <lars.ellenberg@linbit.com>,
	Leon Romanovsky <leon@kernel.org>,
	Manish Rangankar <mrangankar@marvell.com>,
	Manivannan Sadhasivam <mani@kernel.org>,
	Marcelo Ricardo Leitner <marcelo.leitner@gmail.com>,
	Marco Elver <elver@google.com>,
	"Martin K . Petersen" <martin.petersen@oracle.com>,
	Martin KaFai Lau <martin.lau@linux.dev>,
	Masami Hiramatsu <mhiramat@kernel.org>,
	Mauro Carvalho Chehab <mchehab@kernel.org>,
	Maxime Coquelin <mcoquelin.stm32@gmail.com>,
	"Md . Haris Iqbal" <haris.iqbal@ionos.com>,
	Michael Chan <michael.chan@broadcom.com>,
	Michael Ellerman <mpe@ellerman.id.au>,
	Michael Jamet <michael.jamet@intel.com>,
	Michal Januszewski <spock@gentoo.org>,
	Mika Westerberg <mika.westerberg@linux.intel.com>,
	Miquel Raynal <miquel.raynal@bootlin.com>,
	Namjae Jeon <linkinjeon@kernel.org>,
	"Naveen N . Rao" <naveen.n.rao@linux.ibm.com>,
	Neil Horman <nhorman@tuxdriver.com>,
	Nicholas Piggin <npiggin@gmail.com>,
	Nilesh Javali <njavali@marvell.com>,
	OGAWA Hirofumi <hirofumi@mail.parknet.co.jp>,
	Pablo Neira Ayuso <pablo@netfilter.org>,
	Paolo Abeni <pabeni@redhat.com>,
	Peter Zijlstra <peterz@infradead.org>,
	Philipp Reisner <philipp.reisner@linbit.com>,
	Potnuri Bharat Teja <bharat@chelsio.com>,
	Pravin B Shelar <pshelar@ovn.org>,
	Rasmus Villemoes <linux@rasmusvillemoes.dk>,
	Richard Weinberger <richard@nod.at>,
	Rohit Maheshwari <rohitm@chelsio.com>,
	Russell King <linux@armlinux.org.uk>,
	Sagi Grimberg <sagi@grimberg.me>,
	Santosh Shilimkar <santosh.shilimkar@oracle.com>,
	Sergey Matyukevich <geomatsi@gmail.com>,
	Sharvari Harisangam <sharvari.harisangam@nxp.com>,
	Simon Horman <horms@verge.net.au>, Song Liu <song@kernel.org>,
	Stanislav Fomichev <sdf@google.com>,
	Steffen Klassert <steffen.klassert@secunet.com>,
	Stephen Boyd <sboyd@kernel.org>,
	Stephen Hemminger <stephen@networkplumber.org>,
	Sungjong Seo <sj1557.seo@samsung.com>,
	Theodore Ts'o <tytso@mit.edu>, Thomas Gleixner <tglx@linutronix.de>,
	Thomas Graf <tgraf@suug.ch>,
	Thomas Sailer <t.sailer@alumni.ethz.ch>,
	Toke =?iso-8859-1?Q?H=F8iland-J=F8rgensen?= <toke@toke.dk>,
	Trond Myklebust <trond.myklebust@hammerspace.com>,
	Ulf Hansson <ulf.hansson@linaro.org>,
	Varun Prakash <varun@chelsio.com>,
	Veaceslav Falico <vfalico@gmail.com>,
	Vignesh Raghavendra <vigneshr@ti.com>,
	Vinay Kumar Yadav <vinay.yadav@chelsio.com>,
	Vinod Koul <vkoul@kernel.org>, Vlad Yasevich <vyasevich@gmail.com>,
	Wenpeng Liang <liangwenpeng@huawei.com>,
	Xinming Hu <huxinming820@gmail.com>, Xiubo Li <xiubli@redhat.com>,
	Yehezkel Bernat <YehezkelShB@gmail.com>,
	Ying Xue <ying.xue@windriver.com>,
	Yishai Hadas <yishaih@nvidia.com>, Yonghong Song <yhs@fb.com>,
	Yury Norov <yury.norov@gmail.com>,
	brcm80211-dev-list.pdl@broadcom.com, cake@lists.bufferbloat.net,
	ceph-devel@vger.kernel.org, coreteam@netfilter.org,
	dccp@vger.kernel.org, dev@openvswitch.org,
	dmaengine@vger.kernel.org, drbd-dev@lists.linbit.com,
	dri-devel@lists.freedesktop.org, kasan-dev@googlegroups.com,
	linux-actions@lists.infradead.org,
	linux-arm-kernel@lists.infradead.org, linux-block@vger.kernel.org,
	linux-crypto@vger.kernel.org, linux-doc@vger.kernel.org,
	linux-ext4@vger.kernel.org, linux-f2fs-devel@lists.sourceforge.net,
	linux-fbdev@vger.kernel.org, linux-fsdevel@vger.kernel.org,
	linux-hams@vger.kernel.org, linux-media@vger.kernel.org,
	linux-mm@kvack.org, linux-mmc@vger.kernel.org,
	linux-mtd@lists.infradead.org, linux-nfs@vger.kernel.org,
	linux-nvme@lists.infradead.org, linux-raid@vger.kernel.org,
	linux-rdma@vger.kernel.org, linux-scsi@vger.kernel.org,
	linux-sctp@vger.kernel.org,
	linux-stm32@st-md-mailman.stormreply.com, linux-usb@vger.kernel.org,
	linux-wireless@vger.kernel.org, linux-xfs@vger.kernel.org,
	linuxppc-dev@lists.ozlabs.org, lvs-devel@vger.kernel.org,
	netdev@vger.kernel.org, netfilter-devel@vger.kernel.org,
	rds-devel@oss.oracle.com, SHA-cyfmac-dev-list@infineon.com,
	target-devel@vger.kernel.org, tipc-discussion@lists.sourceforge.net
Subject: Re: [PATCH v1 1/5] treewide: use prandom_u32_max() when possible
Message-ID: <Yz7SkWBbabFQrecB@smile.fi.intel.com>
References: <20221005214844.2699-1-Jason@zx2c4.com>
 <20221005214844.2699-2-Jason@zx2c4.com>
 <202210052035.A1020E3@keescook>
 <Yz7N5WsqmKiUl+6b@zx2c4.com>
 <Yz7QN3cbKABexzoB@ziepe.ca>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <Yz7QN3cbKABexzoB@ziepe.ca>
Organization: Intel Finland Oy - BIC 0357606-4 - Westendinkatu 7, 02160 Espoo
X-Original-Sender: andriy.shevchenko@linux.intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=klOdu9BD;       spf=pass
 (google.com: best guess record for domain of andriy.shevchenko@linux.intel.com
 designates 134.134.136.31 as permitted sender) smtp.mailfrom=andriy.shevchenko@linux.intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
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

On Thu, Oct 06, 2022 at 09:55:19AM -0300, Jason Gunthorpe wrote:
> On Thu, Oct 06, 2022 at 06:45:25AM -0600, Jason A. Donenfeld wrote:
> > On Wed, Oct 05, 2022 at 09:16:50PM -0700, Kees Cook wrote:
> > > On Wed, Oct 05, 2022 at 11:48:40PM +0200, Jason A. Donenfeld wrote:
> > > > Rather than incurring a division or requesting too many random bytes for
> > > > the given range, use the prandom_u32_max() function, which only takes
> > > > the minimum required bytes from the RNG and avoids divisions.
> > > 
> > > Yes please!
> > > 
> > > Since this is a treewide patch, it's helpful for (me at least) doing
> > > reviews to detail the mechanism of the transformation.
> > 
> > This is hand done. There were also various wrong seds done. And then I'd
> > edit the .diff manually, and then reapply it, as an iterative process.
> > No internet on the airplane, and oddly no spatch already on my laptop (I
> > think I had some Gentoo ocaml issues at some point and removed it?).
> > 
> > > e.g. I imagine this could be done with something like Coccinelle and
> > 
> > Feel free to check the work here by using Coccinelle if you're into
> > that.
> 
> Generally these series are a lot easier to review if it is structured
> as a patches doing all the unusual stuff that had to be by hand
> followed by an unmodified Coccinelle/sed/etc handling the simple
> stuff.
> 
> Especially stuff that is reworking the logic beyond simple
> substitution should be one patch per subsystem not rolled into a giant
> one patch conversion.
> 
> This makes the whole workflow better because the hand-done stuff can
> have a chance to flow through subsystem trees.

+1 to all arguments for the splitting.

I looked a bit into the code I have the interest to, but I won't spam people
with not-so-important questions / comments / tags, etc.

-- 
With Best Regards,
Andy Shevchenko


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/Yz7SkWBbabFQrecB%40smile.fi.intel.com.
