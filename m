Return-Path: <kasan-dev+bncBCLI747UVAFRBBM47OMQMGQEYSYXAQA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53d.google.com (mail-ed1-x53d.google.com [IPv6:2a00:1450:4864:20::53d])
	by mail.lfdr.de (Postfix) with ESMTPS id 40D595F6654
	for <lists+kasan-dev@lfdr.de>; Thu,  6 Oct 2022 14:45:58 +0200 (CEST)
Received: by mail-ed1-x53d.google.com with SMTP id dz21-20020a0564021d5500b004599f697666sf1466097edb.18
        for <lists+kasan-dev@lfdr.de>; Thu, 06 Oct 2022 05:45:58 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1665060358; cv=pass;
        d=google.com; s=arc-20160816;
        b=CD+OHEswjfuFhMOjg6+C6v03wE+Nhbbax4CAdEV5K5yikvV75TGsBwgPBy1N49PTtT
         pO54064c82w3IlsFlJKVtIRZfsORzOZ1iJboc5sTKwvtCc6wdO+v+j6thj8cCfEELqjm
         WY5E4YdnS8Pf7+8Qxb4eYXcqmxsz4pgQs/VUlWYGMc/YjUN2CRvkOO0fqZYBgKO47XEO
         p4j7mFaeguAn5jYr7lACMdTlXG++AhH8Im1qJXDZzAHcTUUldUlY5MI0Aq190qjnvz91
         zdSlnf59tmQ6bDZ9JTWZLBptqaYa3qPPZkouDFzh773pLxavPz7ymQES29eieNW69lCn
         JeQQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=A9H4t5HCsFed65o+t+vnnnqHgjMSOkkT6Yew4JpV6nc=;
        b=YpKe3DRTU2gaCWNeut87KS250/kBj0ysIuRrDG6jdIfZ0nv797uwbG83nW5s6euIVF
         SMA4TqoUse4P9Fzb1ZWHGgl+OB0e2hVebjMZOGqS2mdmbaXlgLgmp63f35GLECZMjo40
         h3clSB4w61L7w4VXbAAiZElPE+zCQ3/8hCD+oS0xu/FkbM634Plhj8y0oIQiJTZlAzdm
         hEMXmqdMg+U1m5lPZVcZjh3hqBrdOkGXSD50ULaTHxPSd29t2tjVyq4Hz2YfWRPkAB9Q
         Pm0hdkAS5KGbEZ5kkdfD/Jqh81+vxz9el7UubW01lYlze38NYO4mku73C2FsJfWB2CYg
         kvZQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@zx2c4.com header.s=20210105 header.b=gqKJ5uKA;
       spf=pass (google.com: domain of srs0=tiop=2h=zx2c4.com=jason@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom="SRS0=tIOp=2H=zx2c4.com=Jason@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=zx2c4.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date;
        bh=A9H4t5HCsFed65o+t+vnnnqHgjMSOkkT6Yew4JpV6nc=;
        b=pmezzRgdr/s61SWjAxpX/gf+3reu2kys+JL5YHBHopUK5YH5+SBnwbyPu2mPkM3IPT
         t+FiyWYSEL5eb9zcIexgW0R8Vz6nh1o/3+HHaA1pzp3xk6aAq/uyhWwE9TAyCR5Afm47
         MyPacIvAorljwfomlAV/VjSkcbQFysbxfQ4DeeOLUav//Impe5wEcMpe1Npa7FE74Cty
         NEYpFkMjqVbVNcYBG0feOkOJ88TSeTFY18xU5f7p0dH9yIVUp60tS3kNkROCv89oBLhd
         TxDp2tg7oNltWYjhAAOry9M6D3WDCcsyIDW5DN2oYLq08vPHufVbxOpKygLPbDggKPuP
         cNFg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:from:to:cc:subject:date;
        bh=A9H4t5HCsFed65o+t+vnnnqHgjMSOkkT6Yew4JpV6nc=;
        b=WW6nCLj9HpR93IZT7eEFdGbZZXfDNLDdDDEAtLwNZrM25STEw88Kt0nXl11cN8jWfZ
         HR6Jm2jl9FfPtsYbRY3Q7KecqVE1GeSZK0TdpGpnU/sLQ85Hxaxv1lB0EWGRD2IoRE6/
         ekxQgw18A3XnxmM5ObaO4l4840iUU28fODZSvxyAHgtP+7SLNTR2gmQReHYPD2wUTKWU
         MVhykeKcbsVJx1NQxFDa6ItI+DAXcSFB8PIrZY1mp3gTv1E/hZ+E7OTS+Ql4YjcoXQd9
         uONfrHGMF7e6SDm8h4UokjtJFtb4iftvKTV4SObYuWbQr/8GJz9hOgbMCJpALnAvpqtI
         nxEQ==
X-Gm-Message-State: ACrzQf1QMcfm2uMkkLHl92TOgU+syFzfJgEW0gyff56t0Q+Oeu8LgOr4
	zuWLwOr8oPK/oL9FiGDZBJY=
X-Google-Smtp-Source: AMsMyM7NOT1P/ShhftIOGZiMohB3VDlUIyhzpEVHq5k+XhV2VCuq8KDgiD48YQjbatHbfra/Xq7y4Q==
X-Received: by 2002:a17:906:5a5e:b0:78d:2ed1:5b07 with SMTP id my30-20020a1709065a5e00b0078d2ed15b07mr3961946ejc.38.1665060357706;
        Thu, 06 Oct 2022 05:45:57 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:a3d2:b0:780:f131:b4d9 with SMTP id
 ca18-20020a170906a3d200b00780f131b4d9ls864008ejb.11.-pod-prod-gmail; Thu, 06
 Oct 2022 05:45:56 -0700 (PDT)
X-Received: by 2002:a17:906:844a:b0:77c:1d87:b81e with SMTP id e10-20020a170906844a00b0077c1d87b81emr3741138ejy.675.1665060356677;
        Thu, 06 Oct 2022 05:45:56 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1665060356; cv=none;
        d=google.com; s=arc-20160816;
        b=TW7uwEjdYBGmEXDs2KZV4iU6CSd+jrcmcrO/pQkv47IMAIWyZPpHTgq02BCCCTag63
         /vFId5PsFnxVKvVm7xGOV3SoxYiGCWR3jt+Ye6XPBKeUJ8IWhNsDiOItqVMTc/SLGzvh
         3h/xzhmxp4WIn0YHnks0srAWPWATE7mxJVdgcLX7gLW127wgmk1G5Qsf/YayQ722WZeV
         hIu820hnL2hN9bZKuBYZBvMQPok4GDoANdQgVpWzr73JMj6Qzr19oLhhWjWaFIUk2ERH
         A6obCMsvVSaLkuvIeAPsVgp2GoJm/uDWUbUb0jQLBIj89ND/BTvqjisCJQRPrUiiCMqM
         lJqw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=8dWFI8h4OMBAtrqSOGO78rNNmSB/3Qreg0w0Og/94qc=;
        b=ob8n5EWoGxhEteP+2bcVSHMpAg0y+jyGtCAcUAZlH5NtgTfXx/55+yjbJQ36OzRRv5
         QThZh/Iq6AbFLzZxRILstLW8x2L+sR7d1/dP5HTaRiCNQ1KnR0X4eLNHuxP+ROi+H3ME
         Y+5HfNCwwnnmRmo221YRx3yinT4h91zuAhtLNT47W26AyYSF8zXJQtLGP9wQbdpnG3eh
         uhmSakCkXLUQsfuH+61G25/6lnvx0cjRUSwpAcTmEygIQTYMLinCRn8k+CP8dVmImHie
         wpFfDB8hL+ZNsWZAk33mbhGzMr4WKpKjkEFdSEZgS0hua7kY5/4ZwahGk9AC/UzJzNk5
         LB8A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@zx2c4.com header.s=20210105 header.b=gqKJ5uKA;
       spf=pass (google.com: domain of srs0=tiop=2h=zx2c4.com=jason@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom="SRS0=tIOp=2H=zx2c4.com=Jason@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=zx2c4.com
Received: from ams.source.kernel.org (ams.source.kernel.org. [2604:1380:4601:e00::1])
        by gmr-mx.google.com with ESMTPS id by4-20020a0564021b0400b004595ce68e4asi283684edb.5.2022.10.06.05.45.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 06 Oct 2022 05:45:56 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=tiop=2h=zx2c4.com=jason@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) client-ip=2604:1380:4601:e00::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by ams.source.kernel.org (Postfix) with ESMTPS id 6F88CB8206F;
	Thu,  6 Oct 2022 12:45:56 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 6BBD6C433B5;
	Thu,  6 Oct 2022 12:45:39 +0000 (UTC)
Received: by mail.zx2c4.com (ZX2C4 Mail Server) with ESMTPSA id c546cd47 (TLSv1.3:TLS_AES_256_GCM_SHA384:256:NO);
	Thu, 6 Oct 2022 12:45:37 +0000 (UTC)
Date: Thu, 6 Oct 2022 06:45:25 -0600
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
Subject: Re: [PATCH v1 1/5] treewide: use prandom_u32_max() when possible
Message-ID: <Yz7N5WsqmKiUl+6b@zx2c4.com>
References: <20221005214844.2699-1-Jason@zx2c4.com>
 <20221005214844.2699-2-Jason@zx2c4.com>
 <202210052035.A1020E3@keescook>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <202210052035.A1020E3@keescook>
X-Original-Sender: jason@zx2c4.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@zx2c4.com header.s=20210105 header.b=gqKJ5uKA;       spf=pass
 (google.com: domain of srs0=tiop=2h=zx2c4.com=jason@kernel.org designates
 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom="SRS0=tIOp=2H=zx2c4.com=Jason@kernel.org";
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

Hi Kees,

On Wed, Oct 05, 2022 at 09:16:50PM -0700, Kees Cook wrote:
> On Wed, Oct 05, 2022 at 11:48:40PM +0200, Jason A. Donenfeld wrote:
> > Rather than incurring a division or requesting too many random bytes for
> > the given range, use the prandom_u32_max() function, which only takes
> > the minimum required bytes from the RNG and avoids divisions.
> 
> Yes please!
> 
> Since this is a treewide patch, it's helpful for (me at least) doing
> reviews to detail the mechanism of the transformation.

This is hand done. There were also various wrong seds done. And then I'd
edit the .diff manually, and then reapply it, as an iterative process.
No internet on the airplane, and oddly no spatch already on my laptop (I
think I had some Gentoo ocaml issues at some point and removed it?).

> e.g. I imagine this could be done with something like Coccinelle and

Feel free to check the work here by using Coccinelle if you're into
that.

> >  static inline int ubi_dbg_is_bitflip(const struct ubi_device *ubi)
> >  {
> >  	if (ubi->dbg.emulate_bitflips)
> > -		return !(prandom_u32() % 200);
> > +		return !(prandom_u32_max(200));
> >  	return 0;
> >  }
> >  
> 
> Because some looks automated (why the parens?)

I saw this before going out and thought I'd fixed it but I guess I sent
the wrong one.

Jason

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/Yz7N5WsqmKiUl%2B6b%40zx2c4.com.
