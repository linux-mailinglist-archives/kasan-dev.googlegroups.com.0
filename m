Return-Path: <kasan-dev+bncBCF5XGNWYQBRBWGU7GMQMGQEQB2FBWY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa3c.google.com (mail-vk1-xa3c.google.com [IPv6:2607:f8b0:4864:20::a3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 035F45F60B8
	for <lists+kasan-dev@lfdr.de>; Thu,  6 Oct 2022 07:40:42 +0200 (CEST)
Received: by mail-vk1-xa3c.google.com with SMTP id v67-20020a1fac46000000b003a2699aa42fsf132178vke.8
        for <lists+kasan-dev@lfdr.de>; Wed, 05 Oct 2022 22:40:41 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1665034841; cv=pass;
        d=google.com; s=arc-20160816;
        b=EBwv+yTCiueIxmXCeWk+xATVzW3ZYoz943EmAQxGbhTzApo3svfPfTsK62JWIptRCV
         CmSukwetJs2gJI3xnX/8oULfq341QWqvh/EzMH4hUUktx0dAGcIAjr64kRY8eaDr704+
         ObXS0WW9HHJp0ZXUXp4/kZoYFO5RKtAY57tQnoIVqrDc+vkCCnGMdctLoTu7U6YxtEnM
         pOmrYANcZ/0e9ObT5kOIQ7/N/F13Q71EP+I0SMdTsCslZhOZWi1tDUCIeVBAlV8C8sHU
         y/cl1uNnImAHgyxwY1iuj8GHkpbCVwsZdvEzjq45lEbe9vgNpCAJNEoh5o58tHqZLV96
         zDjQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=BmgexZ/Ias3vdzTWy0xbP7hZ4qIEes1oHrZllrFA24Y=;
        b=JPvPk662Kr0FTII1gbyoR0mAhFM71lsdbXhayM5Eyy72JUn27gBj+aIROi/+CD0x8h
         J/F5A8tQ2Pv5DZ6kU+AJLAXugbIFpyp7JmWZlmY4typXiYqC1nopsBy1Sk7SUiSc77wr
         An0/HoLFj+qM38BoJHMLKzAFO22/dDDqPbelgfUo2EKdmX//H8+mtJP6iRIw+MUWdWZS
         f6nzxu/aTYnRSbgn0hsuu5jutF+coRepQra7RoUwvk/3ORoovUsnJPgBF6mF5NpGcETk
         CoTC8K3HSt+rz2jS+USv2C/Kh6dfBWz+aPbYTBZa595WvQKKbdbVu4aYzi4pTikAgxxC
         F7gQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=HIlnByPT;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::432 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date;
        bh=BmgexZ/Ias3vdzTWy0xbP7hZ4qIEes1oHrZllrFA24Y=;
        b=tvIUUMmNYj3JfEHe+IW4J+hb+UGawlq/9gdIaOnICuscN8WeBX963+dCPKH/ciZ2Es
         uA955gJT7PdwQRHMnnwBL6Gyo6EL1JeXcdkbLzKzhEruQgsQTXFyzmwdUiEwAC9GKP+0
         d3cp+zXtNpJTyRwofKqAdUU0650LDmi+TuJei7JyTcGT0m6o48BpSV+besVeszjeIeZe
         rZHgiNzz3ZF6u2PQvY0Qow0GUhrz0td9JMfwcUcsBrdmxAF7G1KdyTKA6ndddF8HesHD
         e2DwpcvXBbwmeDrgoan5rAeYDxiZ4pD4QQvxNX5QdcswuZqSLarRHYOMwxKYkVe74NYX
         Ya1g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:sender:from:to:cc:subject:date;
        bh=BmgexZ/Ias3vdzTWy0xbP7hZ4qIEes1oHrZllrFA24Y=;
        b=TqzT5l//N/1a9JfFRFEglZdyQ3hjYc3iDHAzc32oeoHZEOdOVqB7DgwgoVLjpsgKG9
         CVYDJ5PfMNDZxTobZiQANAVbf6Yzs3cYsLtSe0ITPOJNaDRBKiQLV2GO38whR1vbvuQK
         g2e5lIzqDsD4lNlN+ykJxfseRG7S/IZE3IvkHg733VMsM6P/3zAkLCSk7SfMid+c9BHO
         oLuMguM6HRd0rUkNcVePd/h4Dwug5j9+H1gU1WGdyzdgUC4W2hBG60uaK2XxYT6JODC3
         i+6OAm1XTuMNoFgmxJSdjub+Zh2vpnCAC3QYwApTiRR6gXd/tLD5Si/nQCVUpxp4KWrw
         s2KA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf1zoVM9BLT2UNJSnPxUR5x2OarqxJFzXGSAYXrFBE4RWmIa7Jk5
	5rC2ByeEvkBdcbbHrr3qQ64=
X-Google-Smtp-Source: AMsMyM6z4rop/WhFsqHTCbp1D5KLNEJ56GBQCsyX/nDiuiL36lZbxQk82RJqhI9s4w9XRPpli/LXfw==
X-Received: by 2002:a1f:e444:0:b0:3ab:2991:56d1 with SMTP id b65-20020a1fe444000000b003ab299156d1mr1602764vkh.16.1665034840920;
        Wed, 05 Oct 2022 22:40:40 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9f:3e8b:0:b0:3d6:8a5d:19c5 with SMTP id x11-20020a9f3e8b000000b003d68a5d19c5ls58734uai.3.-pod-prod-gmail;
 Wed, 05 Oct 2022 22:40:40 -0700 (PDT)
X-Received: by 2002:ab0:29cd:0:b0:3c6:4caf:3b2f with SMTP id i13-20020ab029cd000000b003c64caf3b2fmr1708074uaq.50.1665034840211;
        Wed, 05 Oct 2022 22:40:40 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1665034840; cv=none;
        d=google.com; s=arc-20160816;
        b=KlNWwp6C+9uQjTlU3R1vyvvlXxlADdkRn3qqCt+tiyyjL2KE0/4QnkMlmKmwNmYnWy
         AKobXEUVA0T8V1XvpYhxQUkCx33Mvsel7b3M6J/6COw1BeTFlDYhO0a8L+FlcTh+W9zn
         OU2rDoeC2pZRKaXNqQNYZw9+IGT5BtVHXZkBPJvGoeq90rCTnliIndoia0ApR4RxBj8u
         sPn5EUdifdHxTKrMkj6meshQlMC4eBs5xLqyhUVxWjGPC/2vy45nsfxlwpgj/g7w6ZN2
         GonhFNaupCjdNJnfSs19sGu97YQZiJiMTbi7PQFmVIfCGaYOXzpGc4nXT79rPMbRlAIM
         zQ9A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=7rD76ImKhWSr9uLkAh+d+zcZYfUm0ip9Vo7hna38oSs=;
        b=SoxOSOZzaN0wnHZ/DoAkzLfXgBPOxtliwrGJsH3NxeZJh8LQdSsrQtZB7rr2oQxNeG
         m3pulI7jIWXR9ZLRDM+SOTLxe8ynKNoEwPdltczC/azTcUUjPrVPRPwf54iomcMtdbQt
         48hlAZ7buo+D/5Sl798X6BFDZkgjUosZ6sS68hk0BkBInUPVralMUVukQz4Fyl99Q7DF
         x/7hZCMGXXr7XBjEIC/oMiH7vGyz5Re+WUN0K62s3EDJlvrB+vQG8/VOVKwa54UwFAgm
         bEnj0n+jTZ04a9Vt64Him1GXj/8a8oIFaNxDnGcVdJ5lIRuvGjRajadKlHynpCSktUOd
         r9Cw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=HIlnByPT;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::432 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Received: from mail-pf1-x432.google.com (mail-pf1-x432.google.com. [2607:f8b0:4864:20::432])
        by gmr-mx.google.com with ESMTPS id s15-20020a056102364f00b003a6d6357b85si150607vsu.1.2022.10.05.22.40.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 05 Oct 2022 22:40:40 -0700 (PDT)
Received-SPF: pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::432 as permitted sender) client-ip=2607:f8b0:4864:20::432;
Received: by mail-pf1-x432.google.com with SMTP id i6so1128066pfb.2
        for <kasan-dev@googlegroups.com>; Wed, 05 Oct 2022 22:40:40 -0700 (PDT)
X-Received: by 2002:a62:1e83:0:b0:545:6896:188 with SMTP id e125-20020a621e83000000b0054568960188mr3405556pfe.51.1665034839333;
        Wed, 05 Oct 2022 22:40:39 -0700 (PDT)
Received: from www.outflux.net (smtp.outflux.net. [198.145.64.163])
        by smtp.gmail.com with ESMTPSA id i25-20020a056a00225900b00561cf757749sm2160539pfu.183.2022.10.05.22.40.37
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 05 Oct 2022 22:40:38 -0700 (PDT)
Date: Wed, 5 Oct 2022 22:40:36 -0700
From: Kees Cook <keescook@chromium.org>
To: "Jason A. Donenfeld" <Jason@zx2c4.com>
Cc: linux-kernel@vger.kernel.org, Ajay Singh <ajay.kathat@microchip.com>,
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
	Andy Shevchenko <andriy.shevchenko@linux.intel.com>,
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
Subject: Re: [PATCH v1 0/5] treewide cleanup of random integer usage
Message-ID: <202210052240.23F1699@keescook>
References: <20221005214844.2699-1-Jason@zx2c4.com>
 <202210052148.B11CBC60@keescook>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <202210052148.B11CBC60@keescook>
X-Original-Sender: keescook@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=HIlnByPT;       spf=pass
 (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::432
 as permitted sender) smtp.mailfrom=keescook@chromium.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=chromium.org
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
> If any of the subsystems ask you to break this up (I hope not), I've got
> this[1], which does a reasonable job of splitting a commit up into
> separate commits for each matching subsystem.

[1] https://github.com/kees/kernel-tools/blob/trunk/split-on-maintainer

-- 
Kees Cook

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/202210052240.23F1699%40keescook.
