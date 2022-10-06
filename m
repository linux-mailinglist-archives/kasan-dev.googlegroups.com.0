Return-Path: <kasan-dev+bncBCLI747UVAFRBWM77OMQMGQEYJZ7ASY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43a.google.com (mail-wr1-x43a.google.com [IPv6:2a00:1450:4864:20::43a])
	by mail.lfdr.de (Postfix) with ESMTPS id 863685F66E7
	for <lists+kasan-dev@lfdr.de>; Thu,  6 Oct 2022 14:53:46 +0200 (CEST)
Received: by mail-wr1-x43a.google.com with SMTP id m3-20020adfc583000000b0022cd60175bbsf493234wrg.6
        for <lists+kasan-dev@lfdr.de>; Thu, 06 Oct 2022 05:53:46 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1665060826; cv=pass;
        d=google.com; s=arc-20160816;
        b=tvEoJ07r2DuA+nSBO4TC+UuSHntDXJh0Uvy9rnQuHHhDRYR4CkMNjrkquetrvIX4Cg
         d96cSP8n+/4J3UV/wQcqaRwJKUw/GiUz2VUeVWAHJYpREBNs+Rt8ajAqb1mWcyAk6hPI
         mTZloYqYt7HuPs9Lr6MTBZnGShpnbFU8Hg95BjR1yWhKHbVc9o1RvHWozf7nFKRGCjer
         VodL3DaKVszbYhkPrr+2bYY9qC70wvdJh/Ja7IJ6nwyPBt9W+b1qDX8eVUKJw27EMuek
         vTuIb84HnpKlN6Ab3Xip2/V1RGxmywYdxbjuwHq5pNcHEWu/8v+9vdQY9IirmCQY+767
         lNrw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=tHGg+hYwmxZ6T2UfHg3BZF/DppRg5cbK5yQpvjJYsLU=;
        b=iImxNFrBxrULd0ro0KIpwSvAeQgDILlQFZM5jcVjdtFhLtcSvU2POlmfp1NY7UUqvD
         4r+JwyUxUoETb229LLiy5vv5ryREUyY5gJhH11WaWrgGn7dqa55e7sogVGereTMO2c1z
         yvUnBQ+Lk1CXU69BTEn5LtMNolcx7Fj7CodMiMcixy01Ga4y07rbBS0tvUn6Guob9PgM
         omYr2Lc+37bFuS947KH03tiFPS/c34txsmG4Sgyc7DSWksho5lAKRFs8CB4AFfQZ5Th7
         ImGaHcA1c2QxCFEscy8Pv6NZcGmB0jsUaS+ke02fBIzeL+XnNXJqQoEqh77mR0x8qxGt
         +fAQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@zx2c4.com header.s=20210105 header.b=JFNs4Haz;
       spf=pass (google.com: domain of srs0=tiop=2h=zx2c4.com=jason@kernel.org designates 145.40.68.75 as permitted sender) smtp.mailfrom="SRS0=tIOp=2H=zx2c4.com=Jason@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=zx2c4.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date;
        bh=tHGg+hYwmxZ6T2UfHg3BZF/DppRg5cbK5yQpvjJYsLU=;
        b=KC2r7KktVBvt73yBNSadmyf2cdCdAQ589C0/87riBlfidflEGKbPBB1ts5erqW2LIQ
         xmQrfXN+oHzIVI5wS1elLKKQOLeNQhzcklS23pmtELYCXcl4KAEO3JrQ2M2lmVNnEr0U
         Dnzand1NJ8veQ/RICpU5vneEfvD9UpEuwwg4+SojvtuZIkOGjYTekhLFAThAsaJbvOlG
         DUj2SdnAr072feoT72Islm9wV9N8pak9bniBUVakSzSO2KcFwrCE/cHQ+ZYwIla0v5Yx
         pWbvv9Znx9nM3AZUj/zwIh1U9DbqrXgxlaEbqN9zxvRX3EVswhLQr8xHleC2EUqJCWyj
         I8cA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:from:to:cc:subject:date;
        bh=tHGg+hYwmxZ6T2UfHg3BZF/DppRg5cbK5yQpvjJYsLU=;
        b=XJNc3x1YHdBaOUNv+LOg87eVRJYt5KlYamDgk66s3m38UW0NckeHMXzYPRi2TLrfj7
         CFFJ0exL30pCWtArzTvv0QS3FpXextSzRP1JA0QJRYLEa1OVvMPy3D2ByTCbhNQXqdXS
         uB8Idnl7WRrlb29MtH2d9W08SCW/pGevkBxtmVVnAnA2SWJkTG5PCBr446DoUef74daF
         fseLPPdWUmkS82jz97JHMkMjKaDS69Jzx/vSvVw4f+8jNxaZGsiTyu23shelY5pyYCau
         rI1jOkj2oMEUAOfjOkwzck0CKuHU2+QU3hYYJqkA/X3RgJ+KUR7xealWRFL90xNzo+ov
         SzDA==
X-Gm-Message-State: ACrzQf2bX8h1bE/cECWLlGcNDJ6hbJyQwB6Che8pyjsNV+GpxJCF4zP3
	46HCdDLqInlgJrSoMWMmlpY=
X-Google-Smtp-Source: AMsMyM7nipKsRcytXEAqWbXD4jVEk0Lk9rd9P6Z2fdbL5ozOauiseTetIruj1Zmi264PfIEaI6g20w==
X-Received: by 2002:adf:fb10:0:b0:22c:caa4:da2d with SMTP id c16-20020adffb10000000b0022ccaa4da2dmr3189472wrr.139.1665060826092;
        Thu, 06 Oct 2022 05:53:46 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a7b:c857:0:b0:3b4:62fa:43a7 with SMTP id c23-20020a7bc857000000b003b462fa43a7ls966045wml.3.-pod-control-gmail;
 Thu, 06 Oct 2022 05:53:45 -0700 (PDT)
X-Received: by 2002:a05:600c:19cd:b0:3b9:af1f:1b3b with SMTP id u13-20020a05600c19cd00b003b9af1f1b3bmr6721664wmq.37.1665060825068;
        Thu, 06 Oct 2022 05:53:45 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1665060825; cv=none;
        d=google.com; s=arc-20160816;
        b=kVMdgjuT4YCRkEy/MwBDFM/p8+irY2XU8S3+laiMwNNk820u4dOGedhH7I2N6yn7Hg
         gKGQTKoOrB3AQSs4c7Pd2sblvwRPp6Szew8bdfMKVT3DpszEQRtSPa4rLTp7jetxoBz3
         rMx0+CNnldC7/DBmLO9nnO6jCoH6T1VRyiI8AgATn6tk/Kj8pLHWFjciLDF674P8Syjg
         nOTtwNdCUtGKM+vzejGZfg6VnAQ2tEjtawM54AKm9lTxigexkJhku6Y3261TWLTWvoMq
         Qb6zyGoFtfB5wrP+cEudHyAYaDCkij2OIzwrbe0nuOgpd3jbsRun3Jcq588RqBH88P7X
         H9Ow==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=+Hkd+03ZPFCZHL4SytFYjQxSlVLh/tCnsKNFxa5wK+g=;
        b=UVcY+60UebDozvy9dXJZowt2It9Kt06c1yod/03CzR4UskABaP9ViFbssDo28KY02w
         c3IpjkZv5VsFB0b/xMiGRE32BDvZHRY9Ky0u1HhcGtmCsRh5PapWZV5QNXY5un/AVztE
         955M2eaGAVEWUlbQHiwlnTxTGiaDwOQqJ4QgPdZu6kIQz2gCvv5hfTGZY+FZsWqMLxdT
         bpyEnsMCS46MR6g+mAqdNtKAO31wFayyzlGJIOE+Q75svMYqyn/xTxHmGzPQYZTQYDyf
         S9MRKOQDaFGfRtmnd1iY1LkB/jxTv0AgFPrpM+jhvbwn3ULDWeqhQJ25JmmaeQ1t+l3j
         sylQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@zx2c4.com header.s=20210105 header.b=JFNs4Haz;
       spf=pass (google.com: domain of srs0=tiop=2h=zx2c4.com=jason@kernel.org designates 145.40.68.75 as permitted sender) smtp.mailfrom="SRS0=tIOp=2H=zx2c4.com=Jason@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=zx2c4.com
Received: from ams.source.kernel.org (ams.source.kernel.org. [145.40.68.75])
        by gmr-mx.google.com with ESMTPS id ay42-20020a05600c1e2a00b003c0bfaada2esi92074wmb.1.2022.10.06.05.53.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 06 Oct 2022 05:53:45 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=tiop=2h=zx2c4.com=jason@kernel.org designates 145.40.68.75 as permitted sender) client-ip=145.40.68.75;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by ams.source.kernel.org (Postfix) with ESMTPS id 90876B82089;
	Thu,  6 Oct 2022 12:53:44 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 65819C433D6;
	Thu,  6 Oct 2022 12:53:28 +0000 (UTC)
Received: by mail.zx2c4.com (ZX2C4 Mail Server) with ESMTPSA id 82a088b4 (TLSv1.3:TLS_AES_256_GCM_SHA384:256:NO);
	Thu, 6 Oct 2022 12:53:26 +0000 (UTC)
Date: Thu, 6 Oct 2022 06:53:14 -0600
From: "'Jason A. Donenfeld' via kasan-dev" <kasan-dev@googlegroups.com>
To: Kees Cook <keescook@chromium.org>
Cc: linux-kernel@vger.kernel.org, Ajay Singh <ajay.kathat@microchip.com>,
	Akinobu Mita <akinobu.mita@gmail.com>,
	Alexandre Torgue <alexandre.torgue@foss.st.com>,
	Amitkumar Karwar <amitkarwar@gmail.com>,
	Andreas Dilger <adilger.kernel@dilger.ca>,
	Andreas =?utf-8?Q?F=C3=A4rber?= <afaerber@suse.de>,
	Andreas Noever <andreas.noever@gmail.com>,
	Andrew Lunn <andrew@lunn.ch>,
	Andrew Morton <akpm@linux-foundation.org>,
	Andrii Nakryiko <andrii@kernel.org>,
	Andy Gospodarek <andy@greyhouse.net>,
	Andy Lutomirski <luto@kernel.org>,
	Andy Shevchenko <andriy.shevchenko@linux.intel.com>,
	Anil S Keshavamurthy <anil.s.keshavamurthy@intel.com>,
	Anna Schumaker <anna@kernel.org>,
	Arend van Spriel <aspriel@gmail.com>,
	Ayush Sawal <ayush.sawal@chelsio.com>,
	Borislav Petkov <bp@alien8.de>, Chao Yu <chao@kernel.org>,
	Christoph =?utf-8?Q?B=C3=B6hmwalder?= <christoph.boehmwalder@linbit.com>,
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
	Jason Gunthorpe <jgg@ziepe.ca>, Jay Vosburgh <j.vosburgh@gmail.com>,
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
	Toke =?utf-8?Q?H=C3=B8iland-J=C3=B8rgensen?= <toke@toke.dk>,
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
Subject: Re: [PATCH v1 0/5] treewide cleanup of random integer usage
Message-ID: <Yz7PusEN5TG1PvJZ@zx2c4.com>
References: <20221005214844.2699-1-Jason@zx2c4.com>
 <202210052148.B11CBC60@keescook>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <202210052148.B11CBC60@keescook>
X-Original-Sender: jason@zx2c4.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@zx2c4.com header.s=20210105 header.b=JFNs4Haz;       spf=pass
 (google.com: domain of srs0=tiop=2h=zx2c4.com=jason@kernel.org designates
 145.40.68.75 as permitted sender) smtp.mailfrom="SRS0=tIOp=2H=zx2c4.com=Jason@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=zx2c4.com
X-Original-From: "Jason A. Donenfeld" <Jason@zx2c4.com>
Reply-To: "Jason A. Donenfeld" <Jason@zx2c4.com>
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

On Wed, Oct 05, 2022 at 09:55:43PM -0700, Kees Cook wrote:
> It'd be nice to capture some (all?) of the above somewhere. Perhaps just
> a massive comment in the header?

I'll include (something like) this in some "how to use" documentation
I'm working on separately.

> > I've CC'd get_maintainers.pl, which is a pretty big list. Probably some
> > portion of those are going to bounce, too, and everytime you reply to
> > this thread, you'll have to deal with a bunch of bounces coming
> > immediately after. And a recipient list this big will probably dock my
> > email domain's spam reputation, at least temporarily. Sigh. I think
> > that's just how it goes with treewide cleanups though. Again, let me
> > know if I'm doing it wrong.
> 
> I usually stick to just mailing lists and subsystem maintainers.

Lord have mercy I really wish I had done that. I supremely butchered the
sending of this, and then tried to save it by resubmitting directly to
vger with the same message ID but truncated CC, which mostly worked, but
the whole thing is a mess. I'll trim this to subsystem maintainers and
resubmit a v2 right away, rather than having people wade through the
mess.

To any one who's reading this: no more replies to v1! It clogs the
tubes.

> If any of the subsystems ask you to break this up (I hope not), I've got

Oh god I surely hope not. Sounds like a massive waste of time and
paperwork.

Jason

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/Yz7PusEN5TG1PvJZ%40zx2c4.com.
