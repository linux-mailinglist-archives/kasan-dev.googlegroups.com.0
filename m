Return-Path: <kasan-dev+bncBCLI747UVAFRB2XX66MQMGQE3FLKW4A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33c.google.com (mail-wm1-x33c.google.com [IPv6:2a00:1450:4864:20::33c])
	by mail.lfdr.de (Postfix) with ESMTPS id 4EA6A5F5BE6
	for <lists+kasan-dev@lfdr.de>; Wed,  5 Oct 2022 23:49:31 +0200 (CEST)
Received: by mail-wm1-x33c.google.com with SMTP id d5-20020a05600c34c500b003b4fb42ccdesf1480416wmq.8
        for <lists+kasan-dev@lfdr.de>; Wed, 05 Oct 2022 14:49:31 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1665006571; cv=pass;
        d=google.com; s=arc-20160816;
        b=ka3Q//JD20UQ3u9fRC4GBr0GpDYcsQL5Mqg3tmtOM3MXB6rnKnhgm9A6fA894zpCOP
         zO2Qmh1Hn8zg3DYwfdbH/qGBN5hoH00Hw2ve5H7l1l/HOkStHuNuGfeYoBqI6ob5ooZv
         ofBNxfrSOaVzOzXCiVsdXodsS+lEaZB2gyP9sfQnkrb+NccLnuRy8HdZBRF5KuW1MLpx
         hRWzUXaiowiyRA6FZ7/ju0+1iouKqsnViJP/GSP7ZNCWUkNBnKxdPX2agEnvPu5h42AD
         LRyZqxcDuT+wFW7qb6imUfOHC2M5gfs8/iBphBvcn2FzuBTFtOiU7NcdAy9GfgJvbB/F
         KDyQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :mime-version:message-id:date:subject:cc:to:from:dkim-signature;
        bh=lrCTWDLRDFWCPrFcYGRV1H/ShUPhE9V8fK9GUiktIcY=;
        b=WTT4J/FWjYtGkGAR56PEoBi6T2XpT8Xiv6uVFJtz89mq3IskIukdVGdKvCkEtDGq/G
         Q/05Zh0pNwdTkjFeq5Yd8iqqs4VKwj0UetrHc4IsOFG41fzbHPjZbJiuw3qLeJC09BaJ
         WDF6BhCoDu3TDnp6dJT7p5gIa24qk5wCOWGQSAFEKa5QFQoIfdemVunwMyk1uJDY2jcH
         yAKq8UJGrIab96eSqsQdIkkoMjw1zwK7R0mBlnRbYB1PYK4YF4d8bBTp4W0j4+MI0DOr
         ojVRs4cVi75F1VxCpF1oUk55lbg/+QgpnRKbZia7/whxqD8fnf9E5D8zXvU/jo45gbR8
         m9ng==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@zx2c4.com header.s=20210105 header.b=Qhkl413I;
       spf=pass (google.com: domain of srs0=wwun=2g=zx2c4.com=jason@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom="SRS0=WwUN=2G=zx2c4.com=Jason@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=zx2c4.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:from:to:cc:subject:date;
        bh=lrCTWDLRDFWCPrFcYGRV1H/ShUPhE9V8fK9GUiktIcY=;
        b=RFN+bHJZjC6d32Y8PhIAyVeUM5Xe9U8MFENy/o9nLYxeSh85Cop8OC7CwZjbh/2WMx
         1tXqeHjPI0FNe/SjYBqQZkGbokiaQiLS2SUW13or2bcFlAnn6bFZRPBZN0iWnCCaN1gv
         /n0ddxLU/PYQPYd4rvMureaJV7+uxddkyCSe16/0+qyEMEvd69LmOhk6nfqfBLYGAzCr
         YrLqFN+4haIpbyGPzInXsza6tjABAHmCVFYpwlPo0txlV5VJQ7jjU26eNBFo9DaNyrTN
         R9KgpjveEu10sJyTkhGFlzIRujTaEnpHbgNT2W+sgq6d6sSdEELdJ2GSv/r6qkeub12g
         ZXmQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:x-gm-message-state:from:to:cc:subject:date;
        bh=lrCTWDLRDFWCPrFcYGRV1H/ShUPhE9V8fK9GUiktIcY=;
        b=7aUd4lZ5EvEn1pxYBn0BE5gwR4qODzCPO6t3iLePqjpfnjCOn/48mPCAd1LBCwRxlQ
         FVR0oNrcT/J2TSTCr74iFl/TNtKLYMyMFypJQEbXjDXZVqf6aUyuP2yiq6GRSIyGG51h
         FvVTN4/Axnl8DNvPZgAW1c3zT+hTYtuEukbuXoQBweylnEFZHHGbGzyLyi5B4+m+k4yu
         QNz3uvH6Uj3QyeRTaOGDIOHY6DFEl9PnB4eA/yFL4LG3OebRKNm1uhVB/nG/ZNWkaayr
         HOvYiyNZ70qlapXPYsWGEZ9vTg41+UaaCYoR1ITLiGa8u0JZvUkfiF+Jct/QHz7vDXqb
         /jlA==
X-Gm-Message-State: ACrzQf06OhEhfKoWvDHykXsSTlBksUBgG/HCmDDA++OhWpZexOJCdZZE
	acNHLXBcdYDkQMr4jiaqbPE=
X-Google-Smtp-Source: AMsMyM40I3nGMfzaSGC3L4gnOO9qlGHYQxUxd3wQ49vwwEIFHHpWeuNOmetRtNeUVIcqOlg2R6FNog==
X-Received: by 2002:a7b:ca46:0:b0:3b4:7ff1:4fcc with SMTP id m6-20020a7bca46000000b003b47ff14fccmr4782811wml.47.1665006570604;
        Wed, 05 Oct 2022 14:49:30 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:2745:b0:3b4:a307:9032 with SMTP id
 5-20020a05600c274500b003b4a3079032ls73829wmw.2.-pod-control-gmail; Wed, 05
 Oct 2022 14:49:29 -0700 (PDT)
X-Received: by 2002:a7b:ca53:0:b0:3b4:90c4:e07 with SMTP id m19-20020a7bca53000000b003b490c40e07mr1019882wml.150.1665006569462;
        Wed, 05 Oct 2022 14:49:29 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1665006569; cv=none;
        d=google.com; s=arc-20160816;
        b=ldE1RHUfWRk9Y0y69kTHe4lv5b75t2xW6zMQpjzOruSMDvHYSho3P/iQ0awtDayrjx
         RIOD2iJu3Xw0MRV2ZTmPrOg4fjMcTp8adkPGO+spyzDoH/cWhV3VXC5vJL5brXtsZ/+p
         0kfvwuuwL7znEPTYONupw0XhdvcWvSqjr2K0fNpKyL2qQUuUGMr0U44OYSECo7MOIFDz
         HX8uq8wySHHC8s9ppS1wtE35BXemULRT6plrK14ujrjiSGvFYZ484l6LXWB4I3NHyW+n
         Zb8v3P80bGcwTmSgo4R9uJUDcawk/9QCoQhUWW4U2omHLt8TTJFV8nz8E+lF/787+1i3
         DvNA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=kCoSuUs9/UuRmM69QeDy2i9LHinxGmdLR45ZcTaEirk=;
        b=z8VtdLNaKuEEohuD/lsG17V9F46YrfnZYpEQgZ2pPu6ZYIv3/+XxU3oo9wgW5pW5XY
         u6FT0afjd73A4gPAGZhVKrnwk8f00tq9n0ODoedTj/YU+Xn8op0usjND27Yv55Qia+X/
         BmcPqbzM+c3L9Ppx2Sd6UauMIKCxO3kaEJewnqp3MLAzGMd7egQnw80+Kcj/zP0KrABn
         XJMfuy+9r7iUguPEvifiJbk8o1cXUC0dlzFltx9QShUU8d0o3H/L3VGeIhZn58+ZFdBM
         7IWa5oV0/29Mhlag4kESDm0W4ZAN+tzjxj/Uav9FrUBVVxylIAUnSxpBAjzOb46tyUR/
         EWSw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@zx2c4.com header.s=20210105 header.b=Qhkl413I;
       spf=pass (google.com: domain of srs0=wwun=2g=zx2c4.com=jason@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom="SRS0=WwUN=2G=zx2c4.com=Jason@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=zx2c4.com
Received: from ams.source.kernel.org (ams.source.kernel.org. [2604:1380:4601:e00::1])
        by gmr-mx.google.com with ESMTPS id 125-20020a1c1983000000b003a66dd18895si290528wmz.4.2022.10.05.14.49.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 05 Oct 2022 14:49:29 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=wwun=2g=zx2c4.com=jason@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) client-ip=2604:1380:4601:e00::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by ams.source.kernel.org (Postfix) with ESMTPS id 0C4BDB81EC9;
	Wed,  5 Oct 2022 21:49:29 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id D5AA6C433D6;
	Wed,  5 Oct 2022 21:49:12 +0000 (UTC)
Received: by mail.zx2c4.com (ZX2C4 Mail Server) with ESMTPSA id 837ac4b0 (TLSv1.3:TLS_AES_256_GCM_SHA384:256:NO);
	Wed, 5 Oct 2022 21:49:10 +0000 (UTC)
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
Subject: [PATCH v1 0/5] treewide cleanup of random integer usage
Date: Wed,  5 Oct 2022 23:48:39 +0200
Message-Id: <20221005214844.2699-1-Jason@zx2c4.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: jason@zx2c4.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@zx2c4.com header.s=20210105 header.b=Qhkl413I;       spf=pass
 (google.com: domain of srs0=wwun=2g=zx2c4.com=jason@kernel.org designates
 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom="SRS0=WwUN=2G=zx2c4.com=Jason@kernel.org";
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

Hi folks,

This is a five part treewide cleanup of random integer handling. The
rules for random integers are:

- If you want a secure or an insecure random u64, use get_random_u64().
- If you want a secure or an insecure random u32, use get_random_u32().
  * The old function prandom_u32() has been deprecated for a while now
    and is just a wrapper around get_random_u32().
- If you want a secure or an insecure random u16, use get_random_u16().
- If you want a secure or an insecure random u8, use get_random_u8().
- If you want secure or insecure random bytes, use get_random_bytes().
  * The old function prandom_bytes() has been deprecated for a while now
    and has long been a wrapper around get_random_bytes().
- If you want a non-uniform random u32, u16, or u8 bounded by a certain
  open interval maximum, use prandom_u32_max().
  * I say "non-uniform", because it doesn't do any rejection sampling or
    divisions. Hence, it stays within the prandom_* namespace.

These rules ought to be applied uniformly, so that we can clean up the
deprecated functions, and earn the benefits of using the modern
functions. In particular, in addition to the boring substitutions, this
patchset accomplishes a few nice effects:

- By using prandom_u32_max() with an upper-bound that the compiler can
  prove at compile-time is =E2=89=A465536 or =E2=89=A4256, internally get_r=
andom_u16()
  or get_random_u8() is used, which wastes fewer batched random bytes,
  and hence has higher throughput.

- By using prandom_u32_max() instead of %, when the upper-bound is not a
  constant, division is still avoided, because prandom_u32_max() uses
  a faster multiplication-based trick instead.

- By using get_random_u16() or get_random_u8() in cases where the return
  value is intended to indeed be a u16 or a u8, we waste fewer batched
  random bytes, and hence have higher throughput.

So, based on those rules and benefits from following them, this patchset
breaks down into the following five steps:

1) Replace `prandom_u32() % max` and variants thereof with
   prandom_u32_max(max).

2) Replace `(type)get_random_u32()` and variants thereof with
   get_random_u16() or get_random_u8(). I took the pains to actually
   look and see what every lvalue type was across the entire tree.

3) Replace remaining deprecated uses of prandom_u32() with
   get_random_u32().=20

4) Replace remaining deprecated uses of prandom_bytes() with
   get_random_bytes().

5) Remove the deprecated and now-unused prandom_u32() and
   prandom_bytes() inline wrapper functions.

I was thinking of taking this through my random.git tree (on which this
series is currently based) and submitting it near the end of the merge
window, or waiting for the very end of the 6.1 cycle when there will be
the fewest new patches brewing. If somebody with some treewide-cleanup
experience might share some wisdom about what the best timing usually
winds up being, I'm all ears.

I've CC'd get_maintainers.pl, which is a pretty big list. Probably some
portion of those are going to bounce, too, and everytime you reply to
this thread, you'll have to deal with a bunch of bounces coming
immediately after. And a recipient list this big will probably dock my
email domain's spam reputation, at least temporarily. Sigh. I think
that's just how it goes with treewide cleanups though. Again, let me
know if I'm doing it wrong.

Please take a look!

Thanks,
Jason

Cc: Ajay Singh <ajay.kathat@microchip.com>
Cc: Akinobu Mita <akinobu.mita@gmail.com>
Cc: Alexandre Torgue <alexandre.torgue@foss.st.com>
Cc: Amitkumar Karwar <amitkarwar@gmail.com>
Cc: Andreas Dilger <adilger.kernel@dilger.ca>
Cc: Andreas F=C3=A4rber <afaerber@suse.de>
Cc: Andreas Noever <andreas.noever@gmail.com>
Cc: Andrew Lunn <andrew@lunn.ch>
Cc: Andrew Morton <akpm@linux-foundation.org>
Cc: Andrii Nakryiko <andrii@kernel.org>
Cc: Andy Gospodarek <andy@greyhouse.net>
Cc: Andy Lutomirski <luto@kernel.org>
Cc: Andy Shevchenko <andriy.shevchenko@linux.intel.com>
Cc: Anil S Keshavamurthy <anil.s.keshavamurthy@intel.com>
Cc: Anna Schumaker <anna@kernel.org>
Cc: Arend van Spriel <aspriel@gmail.com>
Cc: Ayush Sawal <ayush.sawal@chelsio.com>
Cc: Borislav Petkov <bp@alien8.de>
Cc: Chao Yu <chao@kernel.org>
Cc: Christoph B=C3=B6hmwalder <christoph.boehmwalder@linbit.com>
Cc: Christoph Hellwig <hch@lst.de>
Cc: Christophe Leroy <christophe.leroy@csgroup.eu>
Cc: Chuck Lever <chuck.lever@oracle.com>
Cc: Claudiu Beznea <claudiu.beznea@microchip.com>
Cc: Cong Wang <xiyou.wangcong@gmail.com>
Cc: Dan Williams <dan.j.williams@intel.com>
Cc: Daniel Borkmann <daniel@iogearbox.net>
Cc: Darrick J. Wong <djwong@kernel.org>
Cc: Dave Hansen <dave.hansen@linux.intel.com>
Cc: David Ahern <dsahern@kernel.org>
Cc: David S. Miller <davem@davemloft.net>
Cc: Dennis Dalessandro <dennis.dalessandro@cornelisnetworks.com>
Cc: Dick Kennedy <dick.kennedy@broadcom.com>
Cc: Dmitry Vyukov <dvyukov@google.com>
Cc: Eric Dumazet <edumazet@google.com>
Cc: Florian Westphal <fw@strlen.de>
Cc: Franky Lin <franky.lin@broadcom.com>
Cc: Ganapathi Bhat <ganapathi017@gmail.com>
Cc: Greg Kroah-Hartman <gregkh@linuxfoundation.org>
Cc: Gregory Greenman <gregory.greenman@intel.com>
Cc: H. Peter Anvin <hpa@zytor.com>
Cc: Hannes Reinecke <hare@suse.de>
Cc: Hans Verkuil <hverkuil@xs4all.nl>
Cc: Hante Meuleman <hante.meuleman@broadcom.com>
Cc: Hao Luo <haoluo@google.com>
Cc: Haoyue Xu <xuhaoyue1@hisilicon.com>
Cc: Heiner Kallweit <hkallweit1@gmail.com>
Cc: Helge Deller <deller@gmx.de>
Cc: Herbert Xu <herbert@gondor.apana.org.au>
Cc: Hideaki YOSHIFUJI <yoshfuji@linux-ipv6.org>
Cc: Hugh Dickins <hughd@google.com>
Cc: Igor Mitsyanko <imitsyanko@quantenna.com>
Cc: Ilya Dryomov <idryomov@gmail.com>
Cc: Ingo Molnar <mingo@redhat.com>
Cc: Jack Wang <jinpu.wang@ionos.com>
Cc: Jaegeuk Kim <jaegeuk@kernel.org>
Cc: Jaehoon Chung <jh80.chung@samsung.com>
Cc: Jakub Kicinski <kuba@kernel.org>
Cc: Jamal Hadi Salim <jhs@mojatatu.com>
Cc: James E.J. Bottomley <jejb@linux.ibm.com>
Cc: James Smart <james.smart@broadcom.com>
Cc: Jan Kara <jack@suse.com>
Cc: Jason Gunthorpe <jgg@ziepe.ca>
Cc: Jay Vosburgh <j.vosburgh@gmail.com>
Cc: Jean-Paul Roubelat <jpr@f6fbb.org>
Cc: Jeff Layton <jlayton@kernel.org>
Cc: Jens Axboe <axboe@kernel.dk>
Cc: Jiri Olsa <jolsa@kernel.org>
Cc: Jiri Pirko <jiri@resnulli.us>
Cc: Johannes Berg <johannes@sipsolutions.net>
Cc: John Fastabend <john.fastabend@gmail.com>
Cc: John Stultz <jstultz@google.com>
Cc: Jon Maloy <jmaloy@redhat.com>
Cc: Jonathan Corbet <corbet@lwn.net>
Cc: Jozsef Kadlecsik <kadlec@netfilter.org>
Cc: Julian Anastasov <ja@ssi.bg>
Cc: KP Singh <kpsingh@kernel.org>
Cc: Kalle Valo <kvalo@kernel.org>
Cc: Kees Cook <keescook@chromium.org>
Cc: Keith Busch <kbusch@kernel.org>
Cc: Lars Ellenberg <lars.ellenberg@linbit.com>
Cc: Leon Romanovsky <leon@kernel.org>
Cc: Manish Rangankar <mrangankar@marvell.com>
Cc: Manivannan Sadhasivam <mani@kernel.org>
Cc: Marcelo Ricardo Leitner <marcelo.leitner@gmail.com>
Cc: Marco Elver <elver@google.com>
Cc: Martin K. Petersen <martin.petersen@oracle.com>
Cc: Martin KaFai Lau <martin.lau@linux.dev>
Cc: Masami Hiramatsu <mhiramat@kernel.org>
Cc: Mauro Carvalho Chehab <mchehab@kernel.org>
Cc: Maxime Coquelin <mcoquelin.stm32@gmail.com>
Cc: Md. Haris Iqbal <haris.iqbal@ionos.com>
Cc: Michael Chan <michael.chan@broadcom.com>
Cc: Michael Ellerman <mpe@ellerman.id.au>
Cc: Michael Jamet <michael.jamet@intel.com>
Cc: Michal Januszewski <spock@gentoo.org>
Cc: Mika Westerberg <mika.westerberg@linux.intel.com>
Cc: Miquel Raynal <miquel.raynal@bootlin.com>
Cc: Namjae Jeon <linkinjeon@kernel.org>
Cc: Naveen N. Rao <naveen.n.rao@linux.ibm.com>
Cc: Neil Horman <nhorman@tuxdriver.com>
Cc: Nicholas Piggin <npiggin@gmail.com>
Cc: Nilesh Javali <njavali@marvell.com>
Cc: OGAWA Hirofumi <hirofumi@mail.parknet.co.jp>
Cc: Pablo Neira Ayuso <pablo@netfilter.org>
Cc: Paolo Abeni <pabeni@redhat.com>
Cc: Peter Zijlstra <peterz@infradead.org>
Cc: Philipp Reisner <philipp.reisner@linbit.com>
Cc: Potnuri Bharat Teja <bharat@chelsio.com>
Cc: Pravin B Shelar <pshelar@ovn.org>
Cc: Rasmus Villemoes <linux@rasmusvillemoes.dk>
Cc: Richard Weinberger <richard@nod.at>
Cc: Rohit Maheshwari <rohitm@chelsio.com>
Cc: Russell King <linux@armlinux.org.uk>
Cc: Sagi Grimberg <sagi@grimberg.me>
Cc: Santosh Shilimkar <santosh.shilimkar@oracle.com>
Cc: Sergey Matyukevich <geomatsi@gmail.com>
Cc: Sharvari Harisangam <sharvari.harisangam@nxp.com>
Cc: Simon Horman <horms@verge.net.au>
Cc: Song Liu <song@kernel.org>
Cc: Stanislav Fomichev <sdf@google.com>
Cc: Steffen Klassert <steffen.klassert@secunet.com>
Cc: Stephen Boyd <sboyd@kernel.org>
Cc: Stephen Hemminger <stephen@networkplumber.org>
Cc: Sungjong Seo <sj1557.seo@samsung.com>
Cc: Theodore Ts'o <tytso@mit.edu>
Cc: Thomas Gleixner <tglx@linutronix.de>
Cc: Thomas Graf <tgraf@suug.ch>
Cc: Thomas Sailer <t.sailer@alumni.ethz.ch>
Cc: Toke H=C3=B8iland-J=C3=B8rgensen <toke@toke.dk>
Cc: Trond Myklebust <trond.myklebust@hammerspace.com>
Cc: Ulf Hansson <ulf.hansson@linaro.org>
Cc: Varun Prakash <varun@chelsio.com>
Cc: Veaceslav Falico <vfalico@gmail.com>
Cc: Vignesh Raghavendra <vigneshr@ti.com>
Cc: Vinay Kumar Yadav <vinay.yadav@chelsio.com>
Cc: Vinod Koul <vkoul@kernel.org>
Cc: Vlad Yasevich <vyasevich@gmail.com>
Cc: Wenpeng Liang <liangwenpeng@huawei.com>
Cc: Xinming Hu <huxinming820@gmail.com>
Cc: Xiubo Li <xiubli@redhat.com>
Cc: Yehezkel Bernat <YehezkelShB@gmail.com>
Cc: Ying Xue <ying.xue@windriver.com>
Cc: Yishai Hadas <yishaih@nvidia.com>
Cc: Yonghong Song <yhs@fb.com>
Cc: Yury Norov <yury.norov@gmail.com>
Cc: brcm80211-dev-list.pdl@broadcom.com
Cc: cake@lists.bufferbloat.net
Cc: ceph-devel@vger.kernel.org
Cc: coreteam@netfilter.org
Cc: dccp@vger.kernel.org
Cc: dev@openvswitch.org
Cc: dmaengine@vger.kernel.org
Cc: drbd-dev@lists.linbit.com
Cc: dri-devel@lists.freedesktop.org
Cc: kasan-dev@googlegroups.com
Cc: linux-actions@lists.infradead.org
Cc: linux-arm-kernel@lists.infradead.org
Cc: linux-block@vger.kernel.org
Cc: linux-crypto@vger.kernel.org
Cc: linux-doc@vger.kernel.org
Cc: linux-ext4@vger.kernel.org
Cc: linux-f2fs-devel@lists.sourceforge.net
Cc: linux-fbdev@vger.kernel.org
Cc: linux-fsdevel@vger.kernel.org
Cc: linux-hams@vger.kernel.org
Cc: linux-kernel@vger.kernel.org
Cc: linux-media@vger.kernel.org
Cc: linux-mm@kvack.org
Cc: linux-mmc@vger.kernel.org
Cc: linux-mtd@lists.infradead.org
Cc: linux-nfs@vger.kernel.org
Cc: linux-nvme@lists.infradead.org
Cc: linux-raid@vger.kernel.org
Cc: linux-rdma@vger.kernel.org
Cc: linux-scsi@vger.kernel.org
Cc: linux-sctp@vger.kernel.org
Cc: linux-stm32@st-md-mailman.stormreply.com
Cc: linux-usb@vger.kernel.org
Cc: linux-wireless@vger.kernel.org
Cc: linux-xfs@vger.kernel.org
Cc: linuxppc-dev@lists.ozlabs.org
Cc: lvs-devel@vger.kernel.org
Cc: netdev@vger.kernel.org
Cc: netfilter-devel@vger.kernel.org
Cc: rds-devel@oss.oracle.com
Cc: SHA-cyfmac-dev-list@infineon.com
Cc: target-devel@vger.kernel.org
Cc: tipc-discussion@lists.sourceforge.net

Jason A. Donenfeld (5):
  treewide: use prandom_u32_max() when possible
  treewide: use get_random_{u8,u16}() when possible
  treewide: use get_random_u32() when possible
  treewide: use get_random_bytes when possible
  prandom: remove unused functions

 Documentation/networking/filter.rst           |  2 +-
 arch/powerpc/crypto/crc-vpmsum_test.c         |  2 +-
 arch/x86/mm/pat/cpa-test.c                    |  4 +-
 block/blk-crypto-fallback.c                   |  2 +-
 crypto/async_tx/raid6test.c                   |  2 +-
 crypto/testmgr.c                              | 94 +++++++++----------
 drivers/block/drbd/drbd_receiver.c            |  4 +-
 drivers/dma/dmatest.c                         |  2 +-
 drivers/infiniband/core/cma.c                 |  2 +-
 drivers/infiniband/hw/cxgb4/cm.c              |  4 +-
 drivers/infiniband/hw/cxgb4/id_table.c        |  4 +-
 drivers/infiniband/hw/hfi1/tid_rdma.c         |  2 +-
 drivers/infiniband/hw/hns/hns_roce_ah.c       |  5 +-
 drivers/infiniband/hw/mlx4/mad.c              |  2 +-
 drivers/infiniband/ulp/ipoib/ipoib_cm.c       |  2 +-
 drivers/infiniband/ulp/rtrs/rtrs-clt.c        |  3 +-
 drivers/md/raid5-cache.c                      |  2 +-
 drivers/media/common/v4l2-tpg/v4l2-tpg-core.c |  2 +-
 .../media/test-drivers/vivid/vivid-radio-rx.c |  4 +-
 drivers/mmc/core/core.c                       |  4 +-
 drivers/mmc/host/dw_mmc.c                     |  2 +-
 drivers/mtd/nand/raw/nandsim.c                |  8 +-
 drivers/mtd/tests/mtd_nandecctest.c           | 12 +--
 drivers/mtd/tests/speedtest.c                 |  2 +-
 drivers/mtd/tests/stresstest.c                | 19 +---
 drivers/mtd/ubi/debug.c                       |  2 +-
 drivers/mtd/ubi/debug.h                       |  6 +-
 drivers/net/bonding/bond_main.c               |  2 +-
 drivers/net/ethernet/broadcom/bnxt/bnxt.c     |  2 +-
 drivers/net/ethernet/broadcom/cnic.c          |  5 +-
 .../chelsio/inline_crypto/chtls/chtls_cm.c    |  4 +-
 .../chelsio/inline_crypto/chtls/chtls_io.c    |  4 +-
 drivers/net/ethernet/rocker/rocker_main.c     |  8 +-
 drivers/net/hamradio/baycom_epp.c             |  2 +-
 drivers/net/hamradio/hdlcdrv.c                |  2 +-
 drivers/net/hamradio/yam.c                    |  2 +-
 drivers/net/phy/at803x.c                      |  2 +-
 drivers/net/wireguard/selftest/allowedips.c   | 16 ++--
 .../broadcom/brcm80211/brcmfmac/p2p.c         |  2 +-
 .../net/wireless/intel/iwlwifi/mvm/mac-ctxt.c |  2 +-
 .../net/wireless/marvell/mwifiex/cfg80211.c   |  4 +-
 .../wireless/microchip/wilc1000/cfg80211.c    |  2 +-
 .../net/wireless/quantenna/qtnfmac/cfg80211.c |  2 +-
 drivers/nvme/common/auth.c                    |  2 +-
 drivers/scsi/cxgbi/cxgb4i/cxgb4i.c            |  4 +-
 drivers/scsi/fcoe/fcoe_ctlr.c                 |  4 +-
 drivers/scsi/lpfc/lpfc_hbadisc.c              |  6 +-
 drivers/scsi/qedi/qedi_main.c                 |  2 +-
 drivers/target/iscsi/cxgbit/cxgbit_cm.c       |  2 +-
 drivers/thunderbolt/xdomain.c                 |  2 +-
 drivers/video/fbdev/uvesafb.c                 |  2 +-
 fs/ceph/inode.c                               |  2 +-
 fs/ceph/mdsmap.c                              |  2 +-
 fs/exfat/inode.c                              |  2 +-
 fs/ext2/ialloc.c                              |  2 +-
 fs/ext4/ialloc.c                              |  4 +-
 fs/ext4/ioctl.c                               |  4 +-
 fs/ext4/mmp.c                                 |  2 +-
 fs/ext4/super.c                               |  7 +-
 fs/f2fs/gc.c                                  |  2 +-
 fs/f2fs/namei.c                               |  2 +-
 fs/f2fs/segment.c                             |  8 +-
 fs/fat/inode.c                                |  2 +-
 fs/nfsd/nfs4state.c                           |  4 +-
 fs/ubifs/debug.c                              | 10 +-
 fs/ubifs/journal.c                            |  2 +-
 fs/ubifs/lpt_commit.c                         | 14 +--
 fs/ubifs/tnc_commit.c                         |  2 +-
 fs/xfs/libxfs/xfs_alloc.c                     |  2 +-
 fs/xfs/libxfs/xfs_ialloc.c                    |  4 +-
 fs/xfs/xfs_error.c                            |  2 +-
 fs/xfs/xfs_icache.c                           |  2 +-
 fs/xfs/xfs_log.c                              |  2 +-
 include/linux/prandom.h                       | 12 ---
 include/net/netfilter/nf_queue.h              |  2 +-
 include/net/red.h                             |  2 +-
 include/net/sock.h                            |  2 +-
 kernel/kcsan/selftest.c                       |  4 +-
 kernel/time/clocksource.c                     |  2 +-
 lib/fault-inject.c                            |  2 +-
 lib/find_bit_benchmark.c                      |  4 +-
 lib/random32.c                                |  4 +-
 lib/reed_solomon/test_rslib.c                 | 12 +--
 lib/sbitmap.c                                 |  4 +-
 lib/test_fprobe.c                             |  2 +-
 lib/test_kprobes.c                            |  2 +-
 lib/test_list_sort.c                          |  2 +-
 lib/test_objagg.c                             |  2 +-
 lib/test_rhashtable.c                         |  6 +-
 lib/test_vmalloc.c                            | 19 +---
 lib/uuid.c                                    |  2 +-
 mm/shmem.c                                    |  2 +-
 net/802/garp.c                                |  2 +-
 net/802/mrp.c                                 |  2 +-
 net/ceph/mon_client.c                         |  2 +-
 net/ceph/osd_client.c                         |  2 +-
 net/core/neighbour.c                          |  2 +-
 net/core/pktgen.c                             | 47 +++++-----
 net/core/stream.c                             |  2 +-
 net/dccp/ipv4.c                               |  4 +-
 net/ipv4/datagram.c                           |  2 +-
 net/ipv4/igmp.c                               |  6 +-
 net/ipv4/inet_connection_sock.c               |  2 +-
 net/ipv4/inet_hashtables.c                    |  2 +-
 net/ipv4/ip_output.c                          |  2 +-
 net/ipv4/route.c                              |  2 +-
 net/ipv4/tcp_cdg.c                            |  2 +-
 net/ipv4/tcp_ipv4.c                           |  4 +-
 net/ipv4/udp.c                                |  2 +-
 net/ipv6/addrconf.c                           |  8 +-
 net/ipv6/ip6_flowlabel.c                      |  2 +-
 net/ipv6/mcast.c                              | 10 +-
 net/ipv6/output_core.c                        |  2 +-
 net/mac80211/rc80211_minstrel_ht.c            |  2 +-
 net/mac80211/scan.c                           |  2 +-
 net/netfilter/ipvs/ip_vs_conn.c               |  2 +-
 net/netfilter/ipvs/ip_vs_twos.c               |  4 +-
 net/netfilter/nf_nat_core.c                   |  4 +-
 net/netfilter/xt_statistic.c                  |  2 +-
 net/openvswitch/actions.c                     |  2 +-
 net/packet/af_packet.c                        |  2 +-
 net/rds/bind.c                                |  2 +-
 net/sched/act_gact.c                          |  2 +-
 net/sched/act_sample.c                        |  2 +-
 net/sched/sch_cake.c                          |  8 +-
 net/sched/sch_netem.c                         | 22 ++---
 net/sched/sch_pie.c                           |  2 +-
 net/sched/sch_sfb.c                           |  2 +-
 net/sctp/socket.c                             |  4 +-
 net/sunrpc/auth_gss/gss_krb5_wrap.c           |  4 +-
 net/sunrpc/cache.c                            |  2 +-
 net/sunrpc/xprt.c                             |  2 +-
 net/sunrpc/xprtsock.c                         |  2 +-
 net/tipc/socket.c                             |  2 +-
 net/unix/af_unix.c                            |  2 +-
 net/xfrm/xfrm_state.c                         |  2 +-
 136 files changed, 304 insertions(+), 339 deletions(-)

--=20
2.37.3

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/20221005214844.2699-1-Jason%40zx2c4.com.
