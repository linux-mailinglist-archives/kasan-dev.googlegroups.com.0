Return-Path: <kasan-dev+bncBCLI747UVAFRBCEU7OMQMGQE6ZQLXXI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3e.google.com (mail-oa1-x3e.google.com [IPv6:2001:4860:4864:20::3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 90FAE5F660E
	for <lists+kasan-dev@lfdr.de>; Thu,  6 Oct 2022 14:28:58 +0200 (CEST)
Received: by mail-oa1-x3e.google.com with SMTP id 586e51a60fabf-131b0926096sf919277fac.22
        for <lists+kasan-dev@lfdr.de>; Thu, 06 Oct 2022 05:28:58 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1665059337; cv=pass;
        d=google.com; s=arc-20160816;
        b=eatRnCi4oXXOyxXcB4q4rUwIvWKk+9XNof7BcKRlQqwc9dqeWipSY6YwqfIkQVyc9a
         a/gIgceekVT577LUuhwRYUaff1KdSrgFpZJSkEGGG1rN0YdBk7fXMxJkxE/71MwufK7D
         DC5UsQBmGBBN4PhmNTzCH0BPc73pcg0b+F1wkpa6DdYhHVxs4Weuiif9Liz5v18U4K8E
         CgHQvRu6uQSv4lQL9GMT7aYTvb+fB4hEtr1u0asv510cgRFE8BJtvuGu3iBwkAhyIXjw
         YqDlBBXLjA1+tW3gtCaUs4PQL+9S1vckVQEEDKxn1nsqffrFk/W9rhwY/fbkXJQ55XWf
         CxAQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=h1PdhlXj9Xs9nHHdmtZXRLBFgbLyTH624nMo4dGFANI=;
        b=n+wRAkOBcK8H07VEDcDLGcp3i9qXOfvHSzfPpvc63EBCTAoKIuD41781bQ6vkjPFXg
         S4MHxZ35ovJvaKj5/6nOdWaLLRbRN+hTYTgeWSMOtQxWpRgB6tElvEFscZjAVgZFaSlf
         uhpWynfdxWNxK1ITNgp++GpRFHaZbXizg/GuuXGV8yvXRL2jo2PSZurQIhnPNU9/XlGg
         hxURomSSnBayx6ynhNHh/2xD0yEX396ujJzoHO9N7MIBSOP7WWLUmAunieIFPLuk39A7
         WVawHtCnET1sT7pWDfimhZ7EPsMrp7+K0pn2mTgIDvIa2j7/2Q9uF6Fl2+cqT9Su1dxN
         ER+w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@zx2c4.com header.s=20210105 header.b=OS8t32IG;
       spf=pass (google.com: domain of srs0=tiop=2h=zx2c4.com=jason@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom="SRS0=tIOp=2H=zx2c4.com=Jason@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=zx2c4.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date;
        bh=h1PdhlXj9Xs9nHHdmtZXRLBFgbLyTH624nMo4dGFANI=;
        b=bQ3Ai/og0JMK/NI86U+00A6QCohzr2IRadoN3RwTmhi3239ASQqH7GTqzr2e+A0i+r
         S2WKizP4rsMXtl+im/n54j8xn82KbG7G+Z8F86Ife17Gda4um/oa5giW88DnZqhGc183
         mA55c0GUxepQQ63/U/1F9f/+J9xXuYol2sKY1pqlAE3hCKudhEOmZ/T7V2izp6p7vgBs
         rUjqjOnDqBHi09bi+EdsEde27fF4znUOCGOWL0z0PGf49HIeP6iJbypZwiWmLrLbHG+u
         vfSdhVTvBV0hZgEYJyHwk8RZOR974fKvUV8qP47QI5gnWHPHnXq2/TRFMxHOb1/hDjH5
         axTA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:from:to:cc:subject:date;
        bh=h1PdhlXj9Xs9nHHdmtZXRLBFgbLyTH624nMo4dGFANI=;
        b=EPCyWJRFNJuLXjWjsV/80p4PthmxMRuVL46BsjM7eV+l26tw4P2hQdd+Ev5jxRAGNt
         XTixs63/AGJYcNjnVGdN73+EDHZ9auI8FT6npdxs/HfSj02SZ6bqEnJlXZHMEn72+Iah
         H+tt7Nsflx253e02AG09Ne8xnRJ03TCv686bNi7slGrm5uok/eBKfrQeh0MZqLskT3IE
         Z7fyGNSabrdlhJg6KeRtmvzz/l4Ez9/jlvsXR0XmKcdjAaMOpcmY5vzdBOYiNbDblN2Z
         81NkJczZFFfINKTGNzwmjei64oOpN5HTO/RwqTfbrFZApk0uhFLhpGtJMoLZ3EEjpXC9
         8jug==
X-Gm-Message-State: ACrzQf2ZkH8TVep2IhvUWp0gATmHg9m3k1z0tDez221g6AnyY198sOwb
	mQBcG/vfipo34kEhM/PPD7M=
X-Google-Smtp-Source: AMsMyM7kHhB1UgKyoX13/BcXfxtrcI+qU1cNaObdzKwcTHMVhNntSz/kMy8psSjgXask1gNjMUpl3Q==
X-Received: by 2002:a4a:ac8c:0:b0:47f:90f3:4116 with SMTP id b12-20020a4aac8c000000b0047f90f34116mr1342713oon.49.1665059337156;
        Thu, 06 Oct 2022 05:28:57 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:b315:b0:131:a6c1:508 with SMTP id
 a21-20020a056870b31500b00131a6c10508ls530001oao.7.-pod-prod-gmail; Thu, 06
 Oct 2022 05:28:56 -0700 (PDT)
X-Received: by 2002:a05:6870:5b86:b0:11c:67ba:71dc with SMTP id em6-20020a0568705b8600b0011c67ba71dcmr5216064oab.289.1665059336467;
        Thu, 06 Oct 2022 05:28:56 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1665059336; cv=none;
        d=google.com; s=arc-20160816;
        b=IrW8cIbUWckWi0qMzrGQpkqF/M1FM+FiEN8KwMF+hI21wgcUTpwQUKPDxrWbr+V6iN
         l4SBwT2ZCQ32lkwIRk/Ujl2NfWLCZ6ueKq6xpeOBnO0OE9BmGU5xCffnGZf+Hnjf9b1J
         czRklHW9hpiIVmBF5m+F7OyrZyDgcyyQi+hUVEl5JHn2Ztd9+ZDjnHVaKD6O6VjQZr2T
         ZKQubw9u7BY9HWi2BeY8UIU5CG+aGCQX/YgIEEVazPFY5xKtLO4jZuS6IcS/STbbs42N
         yBUZeqqFEv86vi190xZ7ul5yG8PPgSk/1agdp6APHvh5950GrFfrVnS7/o5la5p/4wcp
         RjdQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=5CT4nH/m4137cke6a9HxB/7vcArAWSQRa4usYkfKNrg=;
        b=wEt0w+J401xYnmUgQ97OmehbcrsVvgRW04xOLCQaGPDVDqr5j6oIrkMD5DIhWNSKaU
         QCbNutOJqJjEzFoQ8w9bTRNk8EY0481dLuUzxqlNRu3d9WcX3lVn/I/PJsLYiH/6pbRM
         40gz4L3D0QP/KRwUrMkKDm3lxU2HJtYdf5sUxNhj5WLF+up1Pun2daNFAS9ulYhZMKUv
         F7oGH69NB4qfyKgHqT6jIVSZeB+IQtqVbY6vUqaTWl+J5iy5HiHTDrMVnla115MJ4LgK
         Hj918EhAEB79gQul8gu5wS6bJHsIbBAFeAMVKCgknfLpKCR3sX2nmzEfBAG2470u0Tgk
         7V1w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@zx2c4.com header.s=20210105 header.b=OS8t32IG;
       spf=pass (google.com: domain of srs0=tiop=2h=zx2c4.com=jason@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom="SRS0=tIOp=2H=zx2c4.com=Jason@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=zx2c4.com
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id p2-20020a4ad442000000b00475fdcaf44asi833316oos.2.2022.10.06.05.28.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 06 Oct 2022 05:28:56 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=tiop=2h=zx2c4.com=jason@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id 9D56561943;
	Thu,  6 Oct 2022 12:28:55 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 4C9BAC433C1;
	Thu,  6 Oct 2022 12:28:40 +0000 (UTC)
Received: by mail.zx2c4.com (ZX2C4 Mail Server) with ESMTPSA id 5a4d154b (TLSv1.3:TLS_AES_256_GCM_SHA384:256:NO);
	Thu, 6 Oct 2022 12:28:38 +0000 (UTC)
Date: Thu, 6 Oct 2022 06:28:26 -0600
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
Subject: Re: [PATCH v1 2/5] treewide: use get_random_{u8,u16}() when possible
Message-ID: <Yz7J6j3cXDLK7O6A@zx2c4.com>
References: <20221005214844.2699-1-Jason@zx2c4.com>
 <20221005214844.2699-3-Jason@zx2c4.com>
 <202210052126.B34A2C62@keescook>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <202210052126.B34A2C62@keescook>
X-Original-Sender: jason@zx2c4.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@zx2c4.com header.s=20210105 header.b=OS8t32IG;       spf=pass
 (google.com: domain of srs0=tiop=2h=zx2c4.com=jason@kernel.org designates
 139.178.84.217 as permitted sender) smtp.mailfrom="SRS0=tIOp=2H=zx2c4.com=Jason@kernel.org";
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

On Wed, Oct 05, 2022 at 09:38:02PM -0700, Kees Cook wrote:
> > diff --git a/lib/test_vmalloc.c b/lib/test_vmalloc.c
> > index 56ffaa8dd3f6..0131ed2cd1bd 100644
> > --- a/lib/test_vmalloc.c
> > +++ b/lib/test_vmalloc.c
> > @@ -80,7 +80,7 @@ static int random_size_align_alloc_test(void)
> >  	int i;
> >  
> >  	for (i = 0; i < test_loop_count; i++) {
> > -		rnd = prandom_u32();
> > +		rnd = get_random_u8();
> >  
> >  		/*
> >  		 * Maximum 1024 pages, if PAGE_SIZE is 4096.
> 
> This wasn't obvious either, but it looks like it's because it never
> consumes more than u8?

Right. The only uses of that are %23 and %10 later on down.

Jason

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/Yz7J6j3cXDLK7O6A%40zx2c4.com.
