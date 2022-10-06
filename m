Return-Path: <kasan-dev+bncBCF5XGNWYQBRBDN47GMQMGQEQCMIM5A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x37.google.com (mail-oa1-x37.google.com [IPv6:2001:4860:4864:20::37])
	by mail.lfdr.de (Postfix) with ESMTPS id AAF595F6048
	for <lists+kasan-dev@lfdr.de>; Thu,  6 Oct 2022 06:48:14 +0200 (CEST)
Received: by mail-oa1-x37.google.com with SMTP id 586e51a60fabf-1278be3dc4csf446874fac.15
        for <lists+kasan-dev@lfdr.de>; Wed, 05 Oct 2022 21:48:14 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1665031693; cv=pass;
        d=google.com; s=arc-20160816;
        b=JpJCYpBloqDBaD1lYBiMV+Yamm29SGL7lA1fY+pCNwIcsa477VxLLkjkaZrEqQ/fDh
         O6g8K6vivwzG20ensHmyn/vWEw1MRuTH5YHwoWP/MOVgurZ7mYGJ56QnRExtGS8k2plR
         bb9yyn2kugw4DDWfn7/oKVqrysVQnf1v/NVI5DdHHuZHpxmITLPhgKksyKVeM8ryOYhb
         4KCnUhJb3FFq+zimU2Ks3w95yA/BdDaikWKIB73Gau9fqI6TOvSqWkhAIwyUPCUQajwq
         OilxVnnrpWQbUUVXOIlt2qPuMePM7KAZiTSH7X0H97Bwh76uyl5mupZnfYDz5MOKPouz
         Rl1w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=sPC7Qt/XyxormiECV3743ozni+pDgPh+DU43MvsWVhc=;
        b=NtWffvgYKbaQea/PICan8bzpU1wGtPB2FizOQeZv+MoE772eC8XGCSrISEazCEzrmQ
         NDgjdILODpozagAIVYmsvfIkGk/aXOt39fP40ZGu4E1+Xg7oXZRwzSvdd1YzuOeHUQmj
         hwREjGCEhG8RpYCXPCC3ssRLr4WFLXJcpSKvGu8Pl/hMNi3ybES7dbhbHF809h2RRIhq
         kvEsWDmPMcN0UPdwGAEIXwweKoXci3roWYWT7McT1SSG4qi0819jiJqitXUlZV66zoSj
         N3QMowq32tl2JMqtRGxbkpiYGp1gwlw9BNRtxcRDFwCCuQR/Lpo6y1JoIXtJpUM/J0ra
         ykVA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=VDYXzBjT;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::52d as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date;
        bh=sPC7Qt/XyxormiECV3743ozni+pDgPh+DU43MvsWVhc=;
        b=jhF7wiTUSSXZux8Zou/LnB47dNJXLKU2fX17I9f8J8Rws4MK+ygQuS8ArIU8FpuQpJ
         JoBCi2FqrDzkZDQGsUa4KOazSSFVnqPfDadSPSszvUk6hT8RR4RiIznDT16blAAi131F
         ixcZWb0lbxJbXjWxqWALAF3M/EJTAcK6IDY+TcCLmN7+XMnqOJcUsLdTI4eKcLUj46MK
         IpWQA7OmO2Ag4KfD6m+3q0E+RZU29Y96fX2MxMcrML1WQhMZuP74SoQXY22z6qn78hds
         keAzn1hYpD22NcCwHK20SgBqL6w1bvhF4EqmaVLgyzf/DmiVCXA3uiXDY4OI85Tvrwrk
         bhRQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:sender:from:to:cc:subject:date;
        bh=sPC7Qt/XyxormiECV3743ozni+pDgPh+DU43MvsWVhc=;
        b=g5EXe9DPgx6aoekCSR3z+yOKLU7H7zgFADBR0T2qyD/99yaNAmIvU/nZ8A+1GNiGT8
         h5B0b8SupAC0GXOvCs7HRcE/R3aVMRrA1QdreoMJ4sPhNeF6KfB821AvYEZ3k9INfBFo
         EJZVrlmt7wlEO/AeDCk/PhIoxqqLl/eKDwiBXu8sOLPVb0Ny69UNuqpbUhrWu43uvEoA
         PBmQwjAIvok8irE8jPn7MCKGfMiEU5BLjAPfYXHRkDvl1rsHgWWkUB2t/PTVmZoftXFA
         uKBl5yFBgJK/tdDJrC0tFYehD1VxDR+TqKwMiIOWDD+4Ahpk41mwIfN+U20E22WrdDd1
         8RxQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf0nZEPO7uSU7RTmWg8YMlvctNXtCHjMINSDge4fcaDOqV/Y1Zxa
	F9I4AwTjzXwCzxtma9psteI=
X-Google-Smtp-Source: AMsMyM4t5ibkf7H9UPgHmdePbGfkZJqHXF3MEQ7XOlO9BYj5QZ8ojfzQyAHS7SLwLI+su7wHlWW2fg==
X-Received: by 2002:a05:6808:ecd:b0:34d:8ab0:912 with SMTP id q13-20020a0568080ecd00b0034d8ab00912mr3898420oiv.89.1665031693472;
        Wed, 05 Oct 2022 21:48:13 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:bb83:0:b0:350:a26c:b39c with SMTP id l125-20020acabb83000000b00350a26cb39cls206079oif.4.-pod-prod-gmail;
 Wed, 05 Oct 2022 21:48:12 -0700 (PDT)
X-Received: by 2002:a05:6808:f01:b0:34f:cabc:4c9a with SMTP id m1-20020a0568080f0100b0034fcabc4c9amr3980917oiw.26.1665031692729;
        Wed, 05 Oct 2022 21:48:12 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1665031692; cv=none;
        d=google.com; s=arc-20160816;
        b=UsSmviOo74S+W477fiUhEeIMv/l4Q77xyqW23kTUl3eIyWXJqT25h1nHZROI1y5OxE
         X2G/wmCqHTxxfcSvwZRsIJPCkeEcyNcA0iQfPrBg5OEcIYD3sJCD5tu3r8hgy3BKQczm
         ryD02CS5l4qoBy1HMJrgOMQMd2od8NInyzUU3tAvl2a1wPTKW5J280s+jS4ctOt3HVqy
         QZE+BNJnp1cqdXv/QkzeEajusQB+D5Eq24xjWnnAP5fu7zNzj/qWKFKO3XBlAc5FB8AT
         hmPHFVCYtvIsiLQip57J/cbGwLdOfaQMrFNFmS4Hl7112bOO3vB0b/TqRo/hBgXRXCfU
         e8rA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=Zga/kwguXOa9tZGzF2X+ZLpnzxGRszRa7j7kheBbr2g=;
        b=xqsJVjsFCiHlJvnnzkVwnO9yrQ8qX4rDzC8SOI6WqaK/v1/ep71TuMMHYpxMuF8ds4
         rAvvDEUnvQIO0pTPTTykSIuIOs+X1JADiwcVwf0kBKp0A4Q42wcYnxr4kvdpyXc1cJ+A
         IapIRvTXfMAelkwFq3DKdKgyInR4CbxgS1qoChL4U5Tj08YgJoWId6VN4PLLYCx8AIdz
         YZk2pjWVn8NpJ0c0hJgAoPALwMW1OdkPwAstkRkoE/0zPiImPs+Fpb0zw+EdirndDg9l
         YaS0pZvHqsTxiE5WdVSDhkYrAOSs1j7YOXxkS5w4Vaxa7ttOtL42Qe3yrvyt6hoDQfDM
         wZtA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=VDYXzBjT;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::52d as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Received: from mail-pg1-x52d.google.com (mail-pg1-x52d.google.com. [2607:f8b0:4864:20::52d])
        by gmr-mx.google.com with ESMTPS id 62-20020aca0641000000b00353b3a946f0si582605oig.1.2022.10.05.21.48.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 05 Oct 2022 21:48:12 -0700 (PDT)
Received-SPF: pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::52d as permitted sender) client-ip=2607:f8b0:4864:20::52d;
Received: by mail-pg1-x52d.google.com with SMTP id 195so887190pga.1
        for <kasan-dev@googlegroups.com>; Wed, 05 Oct 2022 21:48:12 -0700 (PDT)
X-Received: by 2002:a63:1e05:0:b0:451:31d0:8c0f with SMTP id e5-20020a631e05000000b0045131d08c0fmr2789689pge.227.1665031691970;
        Wed, 05 Oct 2022 21:48:11 -0700 (PDT)
Received: from www.outflux.net (smtp.outflux.net. [198.145.64.163])
        by smtp.gmail.com with ESMTPSA id ij28-20020a170902ab5c00b00178af82a000sm11255510plb.122.2022.10.05.21.48.10
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 05 Oct 2022 21:48:10 -0700 (PDT)
Date: Wed, 5 Oct 2022 21:48:09 -0700
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
Subject: Re: [PATCH v1 4/5] treewide: use get_random_bytes when possible
Message-ID: <202210052148.AA3C7BB@keescook>
References: <20221005214844.2699-1-Jason@zx2c4.com>
 <20221005214844.2699-5-Jason@zx2c4.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20221005214844.2699-5-Jason@zx2c4.com>
X-Original-Sender: keescook@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=VDYXzBjT;       spf=pass
 (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::52d
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

On Wed, Oct 05, 2022 at 11:48:43PM +0200, Jason A. Donenfeld wrote:
> The prandom_bytes() function has been a deprecated inline wrapper around
> get_random_bytes() for several releases now, and compiles down to the
> exact same code. Replace the deprecated wrapper with a direct call to
> the real function.
> 
> Signed-off-by: Jason A. Donenfeld <Jason@zx2c4.com>

Global search/replace matches. :)

Reviewed-by: Kees Cook <keescook@chromium.org>

-- 
Kees Cook

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/202210052148.AA3C7BB%40keescook.
