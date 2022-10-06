Return-Path: <kasan-dev+bncBCLI747UVAFRBNNG7OMQMGQEZKXFU5Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe3e.google.com (mail-vs1-xe3e.google.com [IPv6:2607:f8b0:4864:20::e3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 4502E5F6753
	for <lists+kasan-dev@lfdr.de>; Thu,  6 Oct 2022 15:08:06 +0200 (CEST)
Received: by mail-vs1-xe3e.google.com with SMTP id a126-20020a676684000000b003a6eeb4e8b7sf411810vsc.1
        for <lists+kasan-dev@lfdr.de>; Thu, 06 Oct 2022 06:08:06 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1665061685; cv=pass;
        d=google.com; s=arc-20160816;
        b=gDQxGDPGclkTWIFXdbDXuIPsJbWhKxt71qOkSZjDX08UxtTeEhZBkfo7ftJO9YyMh5
         otF1+k9OPJ/ml20je1YvJtnb0/fStUVcB5W3uZVy6CT4NOk9S4DTjF/3l+iB3hDy/oSO
         gYRLeuGNda2vCE2vywehkN+GSMRFrMNYV+Lub+hvVHmaWaQ9UFMsGABRVu5W/OubVtQz
         UskJWPTOBYDFiO9drlj4M8McC1DM+C1vxzvvW3UCGe+E4zvg0e14jjry2UEnehAzBKii
         8nzAHzUcybBbUUV2g13UP05fHSqqJfR5AwQNZSe3q5R1DVzS0TbayKdQ1sCV8i6sCy4g
         b/WQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=djrnbHtR2esJLX7XKjcV/lNae0KrDgFIXDK9QvNqRtk=;
        b=o2vqh4nlQbjFcHTRDZUJ/Iq3gbTIohlA7tyUXDd8LBxQ4p/RHKsN8qNvKmz+Xq+E8I
         26iTbB6/1b0eXrc1o3LZ+fdM9ZLPdq4qbcpFcAg4eyQEDxFBaY2PvnVcpQ095XlgHWeT
         WuiGbg7y7ZsQZmqsVvC2O9P1EcwY1Z19s9mJFLKSovPc3GYPqQCb3T9Y2lldeNJlZYH9
         aCJssyYDYHEkJn5nHWMT+msb+vRnxh9jRDAGwGINC/9cq8S2lZyrWyO6rimPXxYwJHpe
         gikyez9dBJ5wOcvOZKRhhXEVZENQwI0ghK+e/VF5XAsKXT5itzCaYCRImsVhuMzsRV3L
         Mu2g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@zx2c4.com header.s=20210105 header.b=VNr9iNqP;
       spf=pass (google.com: domain of srs0=tiop=2h=zx2c4.com=jason@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom="SRS0=tIOp=2H=zx2c4.com=Jason@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=zx2c4.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date;
        bh=djrnbHtR2esJLX7XKjcV/lNae0KrDgFIXDK9QvNqRtk=;
        b=qer7r24ccW1Ygx00USyEl9+uT07Fey1WUWYretn7G3iGyIGVw65ZfqO7Suz9Pu8QRz
         xn2ayujZjlGwHcI4UUUnJJdjaBfiv4ncD3oZkg4Y+l2Ef/BHAKY72D/xeKx0ChDfp9kC
         xizSZ6EH4bJaL6hDgNxOwnM47O0GOSCPDnpZdLpLQz9X6ee1VCTxm2jY5wE4kyGr5FFd
         7stJs67hP77idHKSR9OI0oEHL1CC9uRsg/Dod9CQ2S/ph4SPQh7qcBmxoPZ5E2tbMcpH
         W19GtB1s9h2218ZdP6mp1fUuFJIU/DcUh+1AiYWEtsGHlKbiJY8wYf5s33e92cQWcZB1
         erUQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc:subject:date;
        bh=djrnbHtR2esJLX7XKjcV/lNae0KrDgFIXDK9QvNqRtk=;
        b=dIVTz+ZaFKlQC5hlMJsTKhWWFpzb9zchND6tzADAf29fUsz3OoTq0K476p/uZmWejP
         NHjCnsBcWPk19xadFW9VUKVp8KpDcVNW2uQkpyKSuLcil54ERXhSMC7lmnlGC2A4OtLK
         xZzMiSo/Mc54XS15diPX/guVS9RBjsgdgYIHzImpSB9Mle0g1Hb73oudTOe0GOBTwMgC
         1RvI4JzL6bTSy99ixZmrnJJA5DLdCX7XF9tInUIosxYoMx2ofLDeyEQ0nNrR8LZfjgg4
         A82LN7vGsbtCNBZmlGRcU2KEf+MM/AGeYIJSWsMafrIZgT0TOwaRGOuuJ8VC7/FSRZiS
         AZFQ==
X-Gm-Message-State: ACrzQf2Hfb+kEFgCtfo2pdLeNIbNhLN1enmgIr2AwDUgIokTISz+nun2
	BMvYyd4cDPsXX9/rkyn9CzE=
X-Google-Smtp-Source: AMsMyM4Hx1TcHoi3YozeOvnrREIlhFSeWR+4GqG1UN2AeoAD/CrBNHqdD3mhuDxfV/blWdXTZhflWQ==
X-Received: by 2002:ab0:7296:0:b0:3da:cc37:fa1 with SMTP id w22-20020ab07296000000b003dacc370fa1mr2598484uao.30.1665061685118;
        Thu, 06 Oct 2022 06:08:05 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:e1c9:0:b0:3a6:cece:295 with SMTP id p9-20020a67e1c9000000b003a6cece0295ls355692vsl.1.-pod-prod-gmail;
 Thu, 06 Oct 2022 06:08:04 -0700 (PDT)
X-Received: by 2002:a67:d99d:0:b0:3a6:ec71:1fc9 with SMTP id u29-20020a67d99d000000b003a6ec711fc9mr2146773vsj.39.1665061681745;
        Thu, 06 Oct 2022 06:08:01 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1665061681; cv=none;
        d=google.com; s=arc-20160816;
        b=LpkARl092K82j7q6l0ENT6rlFPJfE/e8Fb+0bhw7Lb0NEO++qQ/SHhKyvQS43b7WRP
         MaKobj6OFqmJGNDxgpyqoeNOKGVYqOplIEh6S1WdyE2cR7uqbtM5CdshZyXRA23aPxCI
         SWD3HfgBRzH+dhPthBXOUT2ryLI7i2IVPDegck5EiNnud5aMeTO5fLM+MoBoeiu1rSXS
         JAJvGrV5c6wQCjjFiO8+azdzEEMpRoxYxjq4vtZ4AXN0JqeGazSDtjQZeoHigQXK/ZiX
         r4ug2uam/tXJAFdWBZfKdAI8eFEwExsDxxcp2UBbJBZBtepJbh6Op/q+fFtsLyxel1+r
         SgjQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Ot8N/NmxnMNw5DlaW1IKdsMRDrHlZI2nii4+1SScqOw=;
        b=RaU3lvj3ARf1InSg0P2tTscCbS8WIy2gZNQ6e/0no4gIyhA/fUjUcFSbGsghjWRX+2
         yzPtcMfk253iFVIf04j6GmJnqGbp0boziDWBOe6h+I/g+h9NZfsN+jdF7fHbAt26g0E+
         Z2HKzSaF/abhhzBTvjb2XWDtloC0E/HGBMTb+JFe4cFVp/uz7XG37n/ftiT4vhWTFQwb
         pt/cSEAjg92AaXdRiGVloD7DmrWBIDZlGiPHIP99dgeLIe0qOg32H1msCvWF6XLu7gxB
         Oc/jBdFdtEACb/ezMRG19VNmDkMHqOsTdy2IPWYDzF0BmtuyzUdB54Y6OLjGLAjTcVCQ
         y1iw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@zx2c4.com header.s=20210105 header.b=VNr9iNqP;
       spf=pass (google.com: domain of srs0=tiop=2h=zx2c4.com=jason@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom="SRS0=tIOp=2H=zx2c4.com=Jason@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=zx2c4.com
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id ay22-20020a056130031600b003d919da0471si1238599uab.1.2022.10.06.06.08.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 06 Oct 2022 06:08:00 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=tiop=2h=zx2c4.com=jason@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id 90B8A61910
	for <kasan-dev@googlegroups.com>; Thu,  6 Oct 2022 13:08:00 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id C28ABC433D6
	for <kasan-dev@googlegroups.com>; Thu,  6 Oct 2022 13:07:59 +0000 (UTC)
Received: by mail.zx2c4.com (ZX2C4 Mail Server) with ESMTPSA id dd56fdf1 (TLSv1.3:TLS_AES_256_GCM_SHA384:256:NO)
	for <kasan-dev@googlegroups.com>;
	Thu, 6 Oct 2022 13:07:57 +0000 (UTC)
Received: by mail-vs1-f51.google.com with SMTP id 3so1929299vsh.5
        for <kasan-dev@googlegroups.com>; Thu, 06 Oct 2022 06:07:50 -0700 (PDT)
X-Received: by 2002:a1f:1b45:0:b0:3a7:ba13:11ce with SMTP id
 b66-20020a1f1b45000000b003a7ba1311cemr2288446vkb.3.1665061655693; Thu, 06 Oct
 2022 06:07:35 -0700 (PDT)
MIME-Version: 1.0
References: <20221005214844.2699-1-Jason@zx2c4.com> <20221005214844.2699-4-Jason@zx2c4.com>
 <20221006084331.4bdktc2zlvbaszym@quack3> <Yz7LCyIAHC6l5mG9@zx2c4.com> <Yz7Rl7BXamKQhRzH@smile.fi.intel.com>
In-Reply-To: <Yz7Rl7BXamKQhRzH@smile.fi.intel.com>
From: "'Jason A. Donenfeld' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 6 Oct 2022 07:07:24 -0600
X-Gmail-Original-Message-ID: <CAHmME9r2u86Ga1UL_yD6x44OX84UJbRQyfhhDjF1daXyaYsbEw@mail.gmail.com>
Message-ID: <CAHmME9r2u86Ga1UL_yD6x44OX84UJbRQyfhhDjF1daXyaYsbEw@mail.gmail.com>
Subject: Re: [f2fs-dev] [PATCH v1 3/5] treewide: use get_random_u32() when possible
To: Andy Shevchenko <andriy.shevchenko@linux.intel.com>
Cc: Jan Kara <jack@suse.cz>, Andrew Lunn <andrew@lunn.ch>, "Darrick J . Wong" <djwong@kernel.org>, 
	Ulf Hansson <ulf.hansson@linaro.org>, dri-devel@lists.freedesktop.org, 
	Andrii Nakryiko <andrii@kernel.org>, Hans Verkuil <hverkuil@xs4all.nl>, linux-sctp@vger.kernel.org, 
	"Md . Haris Iqbal" <haris.iqbal@ionos.com>, Miquel Raynal <miquel.raynal@bootlin.com>, 
	Christoph Hellwig <hch@lst.de>, Andy Gospodarek <andy@greyhouse.net>, Sergey Matyukevich <geomatsi@gmail.com>, 
	Rohit Maheshwari <rohitm@chelsio.com>, Michael Ellerman <mpe@ellerman.id.au>, ceph-devel@vger.kernel.org, 
	Christophe Leroy <christophe.leroy@csgroup.eu>, Jozsef Kadlecsik <kadlec@netfilter.org>, 
	Nilesh Javali <njavali@marvell.com>, Jean-Paul Roubelat <jpr@f6fbb.org>, 
	Dick Kennedy <dick.kennedy@broadcom.com>, Jay Vosburgh <j.vosburgh@gmail.com>, 
	Potnuri Bharat Teja <bharat@chelsio.com>, Vinay Kumar Yadav <vinay.yadav@chelsio.com>, linux-nfs@vger.kernel.org, 
	Nicholas Piggin <npiggin@gmail.com>, Igor Mitsyanko <imitsyanko@quantenna.com>, 
	Andy Lutomirski <luto@kernel.org>, linux-hams@vger.kernel.org, 
	Thomas Gleixner <tglx@linutronix.de>, Trond Myklebust <trond.myklebust@hammerspace.com>, 
	linux-raid@vger.kernel.org, Neil Horman <nhorman@tuxdriver.com>, 
	Hante Meuleman <hante.meuleman@broadcom.com>, 
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>, linux-usb@vger.kernel.org, 
	Michael Chan <michael.chan@broadcom.com>, linux-kernel@vger.kernel.org, 
	Varun Prakash <varun@chelsio.com>, Chuck Lever <chuck.lever@oracle.com>, 
	netfilter-devel@vger.kernel.org, Masami Hiramatsu <mhiramat@kernel.org>, 
	Jiri Olsa <jolsa@kernel.org>, Jan Kara <jack@suse.com>, linux-fsdevel@vger.kernel.org, 
	Lars Ellenberg <lars.ellenberg@linbit.com>, linux-media@vger.kernel.org, 
	Claudiu Beznea <claudiu.beznea@microchip.com>, 
	Sharvari Harisangam <sharvari.harisangam@nxp.com>, linux-fbdev@vger.kernel.org, 
	linux-doc@vger.kernel.org, linux-mmc@vger.kernel.org, 
	Dave Hansen <dave.hansen@linux.intel.com>, Song Liu <song@kernel.org>, 
	Eric Dumazet <edumazet@google.com>, target-devel@vger.kernel.org, 
	John Stultz <jstultz@google.com>, Stanislav Fomichev <sdf@google.com>, 
	Gregory Greenman <gregory.greenman@intel.com>, drbd-dev@lists.linbit.com, dev@openvswitch.org, 
	Leon Romanovsky <leon@kernel.org>, Helge Deller <deller@gmx.de>, Hugh Dickins <hughd@google.com>, 
	James Smart <james.smart@broadcom.com>, 
	Anil S Keshavamurthy <anil.s.keshavamurthy@intel.com>, Pravin B Shelar <pshelar@ovn.org>, 
	Julian Anastasov <ja@ssi.bg>, coreteam@netfilter.org, Veaceslav Falico <vfalico@gmail.com>, 
	Yonghong Song <yhs@fb.com>, Namjae Jeon <linkinjeon@kernel.org>, linux-crypto@vger.kernel.org, 
	Santosh Shilimkar <santosh.shilimkar@oracle.com>, Ganapathi Bhat <ganapathi017@gmail.com>, 
	linux-actions@lists.infradead.org, Simon Horman <horms@verge.net.au>, 
	Jaegeuk Kim <jaegeuk@kernel.org>, Mika Westerberg <mika.westerberg@linux.intel.com>, 
	Andrew Morton <akpm@linux-foundation.org>, OGAWA Hirofumi <hirofumi@mail.parknet.co.jp>, 
	Hao Luo <haoluo@google.com>, "Theodore Ts'o" <tytso@mit.edu>, Stephen Boyd <sboyd@kernel.org>, 
	Dennis Dalessandro <dennis.dalessandro@cornelisnetworks.com>, Florian Westphal <fw@strlen.de>, 
	=?UTF-8?Q?Andreas_F=C3=A4rber?= <afaerber@suse.de>, 
	Jon Maloy <jmaloy@redhat.com>, Vlad Yasevich <vyasevich@gmail.com>, 
	Anna Schumaker <anna@kernel.org>, Yehezkel Bernat <YehezkelShB@gmail.com>, 
	Haoyue Xu <xuhaoyue1@hisilicon.com>, Heiner Kallweit <hkallweit1@gmail.com>, 
	linux-wireless@vger.kernel.org, 
	Marcelo Ricardo Leitner <marcelo.leitner@gmail.com>, Rasmus Villemoes <linux@rasmusvillemoes.dk>, 
	linux-nvme@lists.infradead.org, Michal Januszewski <spock@gentoo.org>, 
	linux-mtd@lists.infradead.org, kasan-dev@googlegroups.com, 
	Cong Wang <xiyou.wangcong@gmail.com>, Thomas Sailer <t.sailer@alumni.ethz.ch>, 
	Ajay Singh <ajay.kathat@microchip.com>, Xiubo Li <xiubli@redhat.com>, 
	Sagi Grimberg <sagi@grimberg.me>, Daniel Borkmann <daniel@iogearbox.net>, 
	Jonathan Corbet <corbet@lwn.net>, linux-rdma@vger.kernel.org, lvs-devel@vger.kernel.org, 
	linux-arm-kernel@lists.infradead.org, 
	"Naveen N . Rao" <naveen.n.rao@linux.ibm.com>, Ilya Dryomov <idryomov@gmail.com>, 
	Paolo Abeni <pabeni@redhat.com>, Pablo Neira Ayuso <pablo@netfilter.org>, Marco Elver <elver@google.com>, 
	Kees Cook <keescook@chromium.org>, Yury Norov <yury.norov@gmail.com>, 
	"James E . J . Bottomley" <jejb@linux.ibm.com>, Jamal Hadi Salim <jhs@mojatatu.com>, KP Singh <kpsingh@kernel.org>, 
	Borislav Petkov <bp@alien8.de>, Keith Busch <kbusch@kernel.org>, 
	Dan Williams <dan.j.williams@intel.com>, Mauro Carvalho Chehab <mchehab@kernel.org>, 
	Franky Lin <franky.lin@broadcom.com>, Arend van Spriel <aspriel@gmail.com>, linux-ext4@vger.kernel.org, 
	Wenpeng Liang <liangwenpeng@huawei.com>, 
	"Martin K . Petersen" <martin.petersen@oracle.com>, Xinming Hu <huxinming820@gmail.com>, 
	linux-stm32@st-md-mailman.stormreply.com, Jeff Layton <jlayton@kernel.org>, 
	linux-xfs@vger.kernel.org, netdev@vger.kernel.org, 
	Ying Xue <ying.xue@windriver.com>, Manish Rangankar <mrangankar@marvell.com>, 
	"David S . Miller" <davem@davemloft.net>, =?UTF-8?B?VG9rZSBIw7hpbGFuZC1Kw7hyZ2Vuc2Vu?= <toke@toke.dk>, 
	Vignesh Raghavendra <vigneshr@ti.com>, Peter Zijlstra <peterz@infradead.org>, 
	"H . Peter Anvin" <hpa@zytor.com>, Alexandre Torgue <alexandre.torgue@foss.st.com>, 
	Amitkumar Karwar <amitkarwar@gmail.com>, linux-mm@kvack.org, 
	Andreas Dilger <adilger.kernel@dilger.ca>, Ayush Sawal <ayush.sawal@chelsio.com>, 
	Andreas Noever <andreas.noever@gmail.com>, Jiri Pirko <jiri@resnulli.us>, 
	linux-f2fs-devel@lists.sourceforge.net, Jack Wang <jinpu.wang@ionos.com>, 
	Steffen Klassert <steffen.klassert@secunet.com>, rds-devel@oss.oracle.com, 
	Herbert Xu <herbert@gondor.apana.org.au>, linux-scsi@vger.kernel.org, 
	dccp@vger.kernel.org, Richard Weinberger <richard@nod.at>, Russell King <linux@armlinux.org.uk>, 
	Jason Gunthorpe <jgg@ziepe.ca>, SHA-cyfmac-dev-list@infineon.com, 
	Ingo Molnar <mingo@redhat.com>, Jakub Kicinski <kuba@kernel.org>, 
	John Fastabend <john.fastabend@gmail.com>, Maxime Coquelin <mcoquelin.stm32@gmail.com>, 
	Manivannan Sadhasivam <mani@kernel.org>, Michael Jamet <michael.jamet@intel.com>, Kalle Valo <kvalo@kernel.org>, 
	Akinobu Mita <akinobu.mita@gmail.com>, linux-block@vger.kernel.org, 
	dmaengine@vger.kernel.org, Hannes Reinecke <hare@suse.de>, 
	Dmitry Vyukov <dvyukov@google.com>, Jens Axboe <axboe@kernel.dk>, cake@lists.bufferbloat.net, 
	brcm80211-dev-list.pdl@broadcom.com, Yishai Hadas <yishaih@nvidia.com>, 
	Hideaki YOSHIFUJI <yoshfuji@linux-ipv6.org>, linuxppc-dev@lists.ozlabs.org, 
	David Ahern <dsahern@kernel.org>, Philipp Reisner <philipp.reisner@linbit.com>, 
	Stephen Hemminger <stephen@networkplumber.org>, 
	=?UTF-8?Q?Christoph_B=C3=B6hmwalder?= <christoph.boehmwalder@linbit.com>, 
	Vinod Koul <vkoul@kernel.org>, tipc-discussion@lists.sourceforge.net, 
	Thomas Graf <tgraf@suug.ch>, Johannes Berg <johannes@sipsolutions.net>, 
	Sungjong Seo <sj1557.seo@samsung.com>, Martin KaFai Lau <martin.lau@linux.dev>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: jason@zx2c4.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@zx2c4.com header.s=20210105 header.b=VNr9iNqP;       spf=pass
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

On Thu, Oct 6, 2022 at 7:01 AM Andy Shevchenko
<andriy.shevchenko@linux.intel.com> wrote:
>
> On Thu, Oct 06, 2022 at 06:33:15AM -0600, Jason A. Donenfeld wrote:
> > On Thu, Oct 06, 2022 at 10:43:31AM +0200, Jan Kara wrote:
>
> ...
>
> > > The code here is effectively doing the
> > >
> > >     parent_group = prandom_u32_max(ngroups);
> > >
> > > Similarly here we can use prandom_u32_max(ngroups) like:
> > >
> > >             if (qstr) {
> > >                     ...
> > >                     parent_group = hinfo.hash % ngroups;
> > >             } else
> > >                     parent_group = prandom_u32_max(ngroups);
> >
> > Nice catch. I'll move these to patch #1.
>
> I believe coccinelle is able to handle this kind of code as well

I'd be extremely surprised. The details were kind of non obvious. I
just spent a decent amount of time manually checking those blocks, to
make sure we didn't wind up with different behavior, given the
variable reuse.

Jason

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAHmME9r2u86Ga1UL_yD6x44OX84UJbRQyfhhDjF1daXyaYsbEw%40mail.gmail.com.
