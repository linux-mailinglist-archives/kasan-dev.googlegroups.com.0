Return-Path: <kasan-dev+bncBCLI747UVAFRBNXY66MQMGQEMPRGOVA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23c.google.com (mail-lj1-x23c.google.com [IPv6:2a00:1450:4864:20::23c])
	by mail.lfdr.de (Postfix) with ESMTPS id 223615F5BF5
	for <lists+kasan-dev@lfdr.de>; Wed,  5 Oct 2022 23:50:47 +0200 (CEST)
Received: by mail-lj1-x23c.google.com with SMTP id bx10-20020a05651c198a00b0026c1cdb5b4csf42971ljb.2
        for <lists+kasan-dev@lfdr.de>; Wed, 05 Oct 2022 14:50:47 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1665006646; cv=pass;
        d=google.com; s=arc-20160816;
        b=lV9aYzCrlRdh4yPo6yhrdr7KbXRQfJX90k7ZhjZ2suURCbkmH3kAo1Z/F0sN7t5UAg
         i+KczvJIpLMNnnEEJzb5SAx8eNbT4UpWATnRIjDMAum6diKVatmepn6ySAYBcsixElPU
         Gyv2IOxQa9km1/fwAOuyEXOQF5PJMcILgbb0jq4KQ4kGhp2RjdREB+O0I67eguAcmV6O
         +2CQpxpYajKw7gnKwlrv0AcuLTeZqk2V913F2jnelZiQAytSLdsj+ilQgi6+Kbz5rvbx
         M0GLuD5murEXOFO95jOaAbzGfeDGDnBR+Jo7hvmbKTT3LhDRBBhQr6MqfZAW02Ox0jCj
         JdXw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=YYklz1ZX/8swO9x+dzaOxIDtn8HR0Av7QxmGMAViAK4=;
        b=guwrEwaMxH/VVKpvLWHxkc5D6YuH89UPJeuiCT330QYK69QdweVq5WvdPXiNGsoOow
         O5hJM0vtDDQvXOVAZwe2Dt1Dj7bvlQpN+kHnSDFpklVO+dI5kPlr4APFeclQyklq3scR
         ZpoegcBuOix8GC+RCALkrEc6SxZG4YcBJApeDKQ+AbPePAzsvLQb9ibSugnsDm2/J4sE
         qInzJEeUPEEnqSWbLxi4EQRzA4bMblV+nBnNTAYMj8ljB5gOlY3bI//Z6PylGICyX0T/
         vlZjb0UrDyHZpTMR15c1UmkT4BaYhmEx3mB5FSK1jgbMQaiS4WSx+XkcHPBhNNroK5zt
         utfA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@zx2c4.com header.s=20210105 header.b=TzZYmEv4;
       spf=pass (google.com: domain of srs0=wwun=2g=zx2c4.com=jason@kernel.org designates 145.40.68.75 as permitted sender) smtp.mailfrom="SRS0=WwUN=2G=zx2c4.com=Jason@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=zx2c4.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date;
        bh=YYklz1ZX/8swO9x+dzaOxIDtn8HR0Av7QxmGMAViAK4=;
        b=E+fxXyWIRlXhs6wVpeezJ2r+WxBBy77xFe64+3GlT0W9Mlgx2rfSdWOrPmsW6BfkPP
         pV1pG8XCHTX2pcutP3H/inAI5jLauaYFt0XszHTp8MxhKGTabL9iN1cNKsR4BuCKiLGS
         0oEMX++f2aEkAKJhige7ydx39zCO8UeWUulOTJ84Ma2BwvcZxFsHQNOXLCfcSKDbIxXC
         apTzcqaC6fcvD/bVtgUvOVzmzHjcEV53W3k62D7Eme4jBwg1KPt05i+LYnvQymFgDY6x
         lmIwpeGONvqPgWAH3N8zgPl3VKNVcriSSd2AKD5DfPlcf3mrfWLBh8zNbvPTAJvKU9Ev
         WL3w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-gm-message-state:from:to:cc:subject:date;
        bh=YYklz1ZX/8swO9x+dzaOxIDtn8HR0Av7QxmGMAViAK4=;
        b=spgYeqyReFMm8iHX82ffcJZfGBOGWeu3Dj9xowiZUF8uOyYz0vA9soIpAsibAUOpox
         rlU4mAFbzGWPF3zj7S90x3LU05r9tjeUsvJiTJhhpv4OiaxDbsYilcXH1O2BuhzckshI
         9y7lzKWDzQRk80fD9VShwznywx8Th73BFxeDxdaCi8v8gdlyYdZdYASiUo7o9WVpYo3H
         WBEnvbLhx5KWkl1GR3WNgIB5ZBNMRAVBTzmG/HfXFTmHU3HdjYtt/3DM+NpwQdJDmvC6
         7Qlqt9Qs0jrlwb9blcIIlZnTC6c8AbStYK3xxZKm2O6BfWvmb8BOW9rhxeJVDeQmXX1q
         1eSQ==
X-Gm-Message-State: ACrzQf3M6JWA1f1mOf9hCrGM9sFiXJv6s7Y3en/nt7j3mAx5DBIdphP9
	UdM0m4HGILPENjGcKj0KlB0=
X-Google-Smtp-Source: AMsMyM44rYN6R12OrU+SAJ/jE6x+3RRhvkQT+jdwbU7AowPZaRduV0/6L/E6wCIlK4OVcLSIbTJvAg==
X-Received: by 2002:a2e:960b:0:b0:26d:fd28:7da7 with SMTP id v11-20020a2e960b000000b0026dfd287da7mr609946ljh.404.1665006646421;
        Wed, 05 Oct 2022 14:50:46 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3689:b0:494:6c7d:cf65 with SMTP id
 d9-20020a056512368900b004946c7dcf65ls181818lfs.2.-pod-prod-gmail; Wed, 05 Oct
 2022 14:50:45 -0700 (PDT)
X-Received: by 2002:a05:6512:3055:b0:498:f7f5:53a3 with SMTP id b21-20020a056512305500b00498f7f553a3mr617418lfb.367.1665006645266;
        Wed, 05 Oct 2022 14:50:45 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1665006645; cv=none;
        d=google.com; s=arc-20160816;
        b=xOMtNu/n+MwY2LO+litqkVUTz6j5rP9PVghXNsd8bL+SeieoC0FIkNrKlFWtJZv6DM
         lP39dmLwYzh6gBy+T3Mcq7sU5V/ujKwrtJ+BHXY/DH8OigJHZUvSLsX9ZaJdYmXWvcUF
         4SerOR2pMyoZkk2Hd/g9nosxkTkh+4mkV3C5TDeoGDwgA7q5UaJ/X6ualojIv2QsFtYa
         Iekvyx22UeQz5X1cF/bdGHw/vuOq5+mxWbuuoPkTb1ijMl/WWsqyZCXMsP7iBveafiUH
         ZJuE/ZY2aQxye/F5yqPuN9xMyr8p6WyWhswhZO7RL5BRbhpeu6PLTWGg2GEdeB+OmGe0
         DF1Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=Mw6mQIkw0EUTS+KZQ2KSjRHdoL9NDRAH5QoihL5z5WY=;
        b=IKkGBZOdY9ycMx1FwkpxawL1XJ8AisPI9UhYUpZSSgap3w629TFdC9egkRyEu8tgrK
         k8fgCPZozWumyA5XM0fIcMpganw0MBPEAIoj2uXxKY4TslEdPTR4EekF9BBIhCsdTXNR
         z36q0B1TaoXK9tLmEsJKFc1VaXYOOAQT724/I/skZ164vme/GHSrGWd2IRoMzO3I1NhQ
         dJamUOsOnVPvWwXdUAMqLXqP4/xelW3YJe/QNptfQ/bUocbAaOZ46FzjwbcvqXTv0U7u
         J9QKVfKJDvINdTdTf4XqPzf4O9+5uXxmKRzIrEKTS1DmhlgOGPj917CvINoHRbL1S4To
         HaaA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@zx2c4.com header.s=20210105 header.b=TzZYmEv4;
       spf=pass (google.com: domain of srs0=wwun=2g=zx2c4.com=jason@kernel.org designates 145.40.68.75 as permitted sender) smtp.mailfrom="SRS0=WwUN=2G=zx2c4.com=Jason@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=zx2c4.com
Received: from ams.source.kernel.org (ams.source.kernel.org. [145.40.68.75])
        by gmr-mx.google.com with ESMTPS id h3-20020a05651c124300b0026df6ec3a3csi186005ljh.8.2022.10.05.14.50.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 05 Oct 2022 14:50:45 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=wwun=2g=zx2c4.com=jason@kernel.org designates 145.40.68.75 as permitted sender) client-ip=145.40.68.75;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by ams.source.kernel.org (Postfix) with ESMTPS id 95013B81F64;
	Wed,  5 Oct 2022 21:50:44 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 8AD85C4314E;
	Wed,  5 Oct 2022 21:50:28 +0000 (UTC)
Received: by mail.zx2c4.com (ZX2C4 Mail Server) with ESMTPSA id 65668bfc (TLSv1.3:TLS_AES_256_GCM_SHA384:256:NO);
	Wed, 5 Oct 2022 21:50:16 +0000 (UTC)
From: "'Jason A. Donenfeld' via kasan-dev" <kasan-dev@googlegroups.com>
To: linux-kernel@vger.kernel.org
Cc: "Jason A. Donenfeld" <Jason@zx2c4.com>,
	Ajay Singh <ajay.kathat@microchip.com>,
	Akinobu Mita <akinobu.mita@gmail.com>,
	Alexandre Torgue <alexandre.torgue@foss.st.com>,
	Amitkumar Karwar <amitkarwar@gmail.com>,
	Andreas Dilger <adilger.kernel@dilger.ca>,
	=?UTF-8?q?Andreas=20F=C3=A4rber?= <afaerber@suse.de>,
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
	Borislav Petkov <bp@alien8.de>,
	Chao Yu <chao@kernel.org>,
	=?UTF-8?q?Christoph=20B=C3=B6hmwalder?= <christoph.boehmwalder@linbit.com>,
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
	Eric Dumazet <edumazet@google.com>,
	Florian Westphal <fw@strlen.de>,
	Franky Lin <franky.lin@broadcom.com>,
	Ganapathi Bhat <ganapathi017@gmail.com>,
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
	Gregory Greenman <gregory.greenman@intel.com>,
	"H . Peter Anvin" <hpa@zytor.com>,
	Hannes Reinecke <hare@suse.de>,
	Hans Verkuil <hverkuil@xs4all.nl>,
	Hante Meuleman <hante.meuleman@broadcom.com>,
	Hao Luo <haoluo@google.com>,
	Haoyue Xu <xuhaoyue1@hisilicon.com>,
	Heiner Kallweit <hkallweit1@gmail.com>,
	Helge Deller <deller@gmx.de>,
	Herbert Xu <herbert@gondor.apana.org.au>,
	Hideaki YOSHIFUJI <yoshfuji@linux-ipv6.org>,
	Hugh Dickins <hughd@google.com>,
	Igor Mitsyanko <imitsyanko@quantenna.com>,
	Ilya Dryomov <idryomov@gmail.com>,
	Ingo Molnar <mingo@redhat.com>,
	Jack Wang <jinpu.wang@ionos.com>,
	Jaegeuk Kim <jaegeuk@kernel.org>,
	Jaehoon Chung <jh80.chung@samsung.com>,
	Jakub Kicinski <kuba@kernel.org>,
	Jamal Hadi Salim <jhs@mojatatu.com>,
	"James E . J . Bottomley" <jejb@linux.ibm.com>,
	James Smart <james.smart@broadcom.com>,
	Jan Kara <jack@suse.com>,
	Jason Gunthorpe <jgg@ziepe.ca>,
	Jay Vosburgh <j.vosburgh@gmail.com>,
	Jean-Paul Roubelat <jpr@f6fbb.org>,
	Jeff Layton <jlayton@kernel.org>,
	Jens Axboe <axboe@kernel.dk>,
	Jiri Olsa <jolsa@kernel.org>,
	Jiri Pirko <jiri@resnulli.us>,
	Johannes Berg <johannes@sipsolutions.net>,
	John Fastabend <john.fastabend@gmail.com>,
	John Stultz <jstultz@google.com>,
	Jon Maloy <jmaloy@redhat.com>,
	Jonathan Corbet <corbet@lwn.net>,
	Jozsef Kadlecsik <kadlec@netfilter.org>,
	Julian Anastasov <ja@ssi.bg>,
	KP Singh <kpsingh@kernel.org>,
	Kalle Valo <kvalo@kernel.org>,
	Kees Cook <keescook@chromium.org>,
	Keith Busch <kbusch@kernel.org>,
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
	Simon Horman <horms@verge.net.au>,
	Song Liu <song@kernel.org>,
	Stanislav Fomichev <sdf@google.com>,
	Steffen Klassert <steffen.klassert@secunet.com>,
	Stephen Boyd <sboyd@kernel.org>,
	Stephen Hemminger <stephen@networkplumber.org>,
	Sungjong Seo <sj1557.seo@samsung.com>,
	Theodore Ts'o <tytso@mit.edu>,
	Thomas Gleixner <tglx@linutronix.de>,
	Thomas Graf <tgraf@suug.ch>,
	Thomas Sailer <t.sailer@alumni.ethz.ch>,
	=?UTF-8?q?Toke=20H=C3=B8iland-J=C3=B8rgensen?= <toke@toke.dk>,
	Trond Myklebust <trond.myklebust@hammerspace.com>,
	Ulf Hansson <ulf.hansson@linaro.org>,
	Varun Prakash <varun@chelsio.com>,
	Veaceslav Falico <vfalico@gmail.com>,
	Vignesh Raghavendra <vigneshr@ti.com>,
	Vinay Kumar Yadav <vinay.yadav@chelsio.com>,
	Vinod Koul <vkoul@kernel.org>,
	Vlad Yasevich <vyasevich@gmail.com>,
	Wenpeng Liang <liangwenpeng@huawei.com>,
	Xinming Hu <huxinming820@gmail.com>,
	Xiubo Li <xiubli@redhat.com>,
	Yehezkel Bernat <YehezkelShB@gmail.com>,
	Ying Xue <ying.xue@windriver.com>,
	Yishai Hadas <yishaih@nvidia.com>,
	Yonghong Song <yhs@fb.com>,
	Yury Norov <yury.norov@gmail.com>,
	brcm80211-dev-list.pdl@broadcom.com,
	cake@lists.bufferbloat.net,
	ceph-devel@vger.kernel.org,
	coreteam@netfilter.org,
	dccp@vger.kernel.org,
	dev@openvswitch.org,
	dmaengine@vger.kernel.org,
	drbd-dev@lists.linbit.com,
	dri-devel@lists.freedesktop.org,
	kasan-dev@googlegroups.com,
	linux-actions@lists.infradead.org,
	linux-arm-kernel@lists.infradead.org,
	linux-block@vger.kernel.org,
	linux-crypto@vger.kernel.org,
	linux-doc@vger.kernel.org,
	linux-ext4@vger.kernel.org,
	linux-f2fs-devel@lists.sourceforge.net,
	linux-fbdev@vger.kernel.org,
	linux-fsdevel@vger.kernel.org,
	linux-hams@vger.kernel.org,
	linux-media@vger.kernel.org,
	linux-mm@kvack.org,
	linux-mmc@vger.kernel.org,
	linux-mtd@lists.infradead.org,
	linux-nfs@vger.kernel.org,
	linux-nvme@lists.infradead.org,
	linux-raid@vger.kernel.org,
	linux-rdma@vger.kernel.org,
	linux-scsi@vger.kernel.org,
	linux-sctp@vger.kernel.org,
	linux-stm32@st-md-mailman.stormreply.com,
	linux-usb@vger.kernel.org,
	linux-wireless@vger.kernel.org,
	linux-xfs@vger.kernel.org,
	linuxppc-dev@lists.ozlabs.org,
	lvs-devel@vger.kernel.org,
	netdev@vger.kernel.org,
	netfilter-devel@vger.kernel.org,
	rds-devel@oss.oracle.com,
	SHA-cyfmac-dev-list@infineon.com,
	target-devel@vger.kernel.org,
	tipc-discussion@lists.sourceforge.net
Subject: [PATCH v1 5/5] prandom: remove unused functions
Date: Wed,  5 Oct 2022 23:48:44 +0200
Message-Id: <20221005214844.2699-6-Jason@zx2c4.com>
In-Reply-To: <20221005214844.2699-1-Jason@zx2c4.com>
References: <20221005214844.2699-1-Jason@zx2c4.com>
MIME-Version: 1.0
X-Original-Sender: jason@zx2c4.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@zx2c4.com header.s=20210105 header.b=TzZYmEv4;       spf=pass
 (google.com: domain of srs0=wwun=2g=zx2c4.com=jason@kernel.org designates
 145.40.68.75 as permitted sender) smtp.mailfrom="SRS0=WwUN=2G=zx2c4.com=Jason@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=zx2c4.com
X-Original-From: "Jason A. Donenfeld" <Jason@zx2c4.com>
Reply-To: "Jason A. Donenfeld" <Jason@zx2c4.com>
Content-Type: text/plain; charset="UTF-8"
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

With no callers left of prandom_u32() and prandom_bytes(), remove these
deprecated wrappers.

Signed-off-by: Jason A. Donenfeld <Jason@zx2c4.com>
---
 include/linux/prandom.h | 12 ------------
 1 file changed, 12 deletions(-)

diff --git a/include/linux/prandom.h b/include/linux/prandom.h
index 78db003bc290..e0a0759dd09c 100644
--- a/include/linux/prandom.h
+++ b/include/linux/prandom.h
@@ -12,18 +12,6 @@
 #include <linux/percpu.h>
 #include <linux/random.h>
 
-/* Deprecated: use get_random_u32 instead. */
-static inline u32 prandom_u32(void)
-{
-	return get_random_u32();
-}
-
-/* Deprecated: use get_random_bytes instead. */
-static inline void prandom_bytes(void *buf, size_t nbytes)
-{
-	return get_random_bytes(buf, nbytes);
-}
-
 struct rnd_state {
 	__u32 s1, s2, s3, s4;
 };
-- 
2.37.3

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20221005214844.2699-6-Jason%40zx2c4.com.
