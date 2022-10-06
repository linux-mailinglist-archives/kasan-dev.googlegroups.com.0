Return-Path: <kasan-dev+bncBDYLL6FFTACRBFVQ7GMQMGQELGDSQ7Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x37.google.com (mail-oa1-x37.google.com [IPv6:2001:4860:4864:20::37])
	by mail.lfdr.de (Postfix) with ESMTPS id 9A6395F6008
	for <lists+kasan-dev@lfdr.de>; Thu,  6 Oct 2022 06:22:47 +0200 (CEST)
Received: by mail-oa1-x37.google.com with SMTP id 586e51a60fabf-13237320c16sf420057fac.16
        for <lists+kasan-dev@lfdr.de>; Wed, 05 Oct 2022 21:22:47 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1665030166; cv=pass;
        d=google.com; s=arc-20160816;
        b=WjqLXHuPnhIdEobHWgs55lIrOqBajoEIf6X2lOpd016wTpkjeR6jNtVlzAv/faIZAR
         SaodiZdosIkiB+siIK+6j0BwFN/AmuU0fTOF47rjfIfirjCjSE2RAd5rX7oDfw7ZCaZw
         pFRw4oXjhaWBfxQSUfDwOOIGPSJtw30QHrToVM3V7iqdDYvanE8HeGh+beKUnofR62eC
         B6XlbLZ4Jci4JgHDh568K9bRDeUu5sSqGezDCm92tFmvTsU5S1hJTK+NXtrD3jZHaxns
         77h+/RoYM8QEB10pZGIk581FipkDK+tjpK9JQo9iUJXhQopPwtIxLLPaMZ1Vj0L2NUA6
         EnIw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=0PhSHJUD15l5W/fxpYhQPKS9gORVZ3jeBSLiwxM0RIg=;
        b=trREr6B+lUKfo4qGhjDtvX94Nr64ex5AB21+K/jbcruc68YFVDyuGJZ5DNTgwdpRMD
         rjbhYb40NaT8yMLV8Ik15P3IEb2/yGJajPt+P2ybS1PbYpufm34otjh6fVQ0kDxYWAKu
         jWr+OkihvT9C+CXDaq+VKoDT2MBvnrNGH1EOLkxYNg6N80nDoad1Pr38z7jOGiLeK93C
         OICAhH7ySFQ9gBtP9NgLL6j2JREX+aIjYXLtFrsclSzj1vVGYCVLAyiPRmX/PkQ1nqR0
         JbL1Alj8JRUD37q0e0uRBw7wzadbtiElznWSWlLsqfAKdMjmuf/J5Q7a+8bnfNw4AMgd
         MqCQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=ocUSwvib;
       spf=pass (google.com: domain of kpsingh@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=kpsingh@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:in-reply-to
         :references:mime-version:sender:from:to:cc:subject:date;
        bh=0PhSHJUD15l5W/fxpYhQPKS9gORVZ3jeBSLiwxM0RIg=;
        b=DibY73wDYE9JsZY03BW1zf+jocDsLVUk12t9WkRkFceq07x2nYj+pzlnqNPwIyk09Y
         OzaUCWN0et5Prn4uWwe2pE3My9xe9xnZKleVHfKQodHigJKWloS+H/1+7F+QywYHN9vo
         cT2/OX5ka3Do2M/l2SxTGP1zSb5QwHQQAM9OGiexGSSpAHGGvPAEx7C4TrVKH02zqnXs
         ZcEGqHir5tOgNUPtIUUqPs4KBxo33eLvY54C760TlZukoTVznfhZE9HvXrWBqeGO8PaA
         Dr2ziOTDmO+TL24VWMWEI7zEJZfGy9kirml0Pqrr8OBlqWi0abkUb0YMpnyYVHlAAkd3
         Giyg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:sender:from:to:cc:subject:date;
        bh=0PhSHJUD15l5W/fxpYhQPKS9gORVZ3jeBSLiwxM0RIg=;
        b=fM3DQRgy4EUv70XlpyOC1KBGrJGM1L35zLwzf/A4erGASuzbMcSAORkvmQH/maW3/f
         M+q5wciybnU/ertNnnaakYYtRGPpklIvemdM+oIsABLF8onzmfU4BIRJP2ETgpgQOeIU
         uFByFv4TZqRE7oYONaEtHaGXvEToVBLRzZUMD/B9YRnN0O2bYt0vcjfoNsJ0r641nGHB
         LrVNq736QMmcx95n2nCJ2ZaiTOE+owYhBWvbIP5dgCLSNTG3SWHejY7KuFWgwvUnzu/h
         4fJYoif9Bi+W9MTG43ePWqSBm+htPkEOhpMO/Z0N/QKVcAknKjoFLykn11MpQd97glY9
         ub5w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf0oKviFydolAo+NPCNyDYiwC0txBacYMxGU88I72SS3i1i8ncku
	rbAGuVOq4RMrZXJxCINBNUo=
X-Google-Smtp-Source: AMsMyM6ucGnY4PFr/bQog6x9Xk0L1fMoWWRHpZRJoKV6QdsgFSfolxgo3NqioNF4gI3xV+S1T7YqCQ==
X-Received: by 2002:a05:6870:5804:b0:12a:f192:27de with SMTP id r4-20020a056870580400b0012af19227demr1565125oap.224.1665030166104;
        Wed, 05 Oct 2022 21:22:46 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:370:0:b0:61c:ac06:86ce with SMTP id 103-20020a9d0370000000b0061cac0686cels98316otv.0.-pod-prod-gmail;
 Wed, 05 Oct 2022 21:22:45 -0700 (PDT)
X-Received: by 2002:a05:6830:628b:b0:660:d639:f380 with SMTP id ce11-20020a056830628b00b00660d639f380mr1095366otb.181.1665030165725;
        Wed, 05 Oct 2022 21:22:45 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1665030165; cv=none;
        d=google.com; s=arc-20160816;
        b=SvSP8vDNTCx3a2PejvpCBETIqiS+eYqMIFgJJPJnVlcUtsW1V0SlCS4u0eE9UjpsIF
         NNMVcavKus3cnFy2u8na8q2Y1LK732RubrYxKdkT5QhGTHR1eWlflh61e454Q7ODCQPP
         6DYrfMe4b+DdEk4e0A3qsPcGsTvpN7OALQWORnhvxLoalhYw/XQQMTisKh0tXjVPk5C4
         iFWCHQ37W93FsNKtkfzbyI7+WS48xPc5rGM4dmT4aRIDVNXMw3zxcCWvkXgdCb6NAwZw
         WVeNQrB2YIWAlZKEkRWyHSOnPTPP+PW9qiJ319sCUidZhEksYufj+luCwFLTQvWJCtce
         RJbg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=79D/+k/bRZXhGBAaempdgng3l68Zp7pbnLAWamJJEQU=;
        b=r4j0LAMPAh3j3wwsCwkysMVQPrVZuWzyHkVasK5TKTwtZl+UjlRh1z9Xm8tVBdzHmY
         JiB2j8ZeGrzKcEq83SveuXZu7N8244C7xtJliCKWz4oyt3LO/GClfCRzXDtNouXmCcXw
         +3EHVAcvJvzraHR940OvEQ2LCcdZBPEhY/9xTxBNbHW2svsxpJjoirqxJBjezMMssINi
         mfHWOOXs3PI5TILP3JM6uzXIFHmn/hiX41CwuDJ3/vhm6fU5VwtEhugwKwH2nY/9Och3
         ly/j+WFptqhTgrHudJ0zSOFZ8vZkqD3al5qvs32ATx0g4gqVmt9wog0GJl22Thzn2pKt
         3ULg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=ocUSwvib;
       spf=pass (google.com: domain of kpsingh@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=kpsingh@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id y10-20020a056871010a00b0013191afecb8si709371oab.2.2022.10.05.21.22.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 05 Oct 2022 21:22:45 -0700 (PDT)
Received-SPF: pass (google.com: domain of kpsingh@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id 7541361896
	for <kasan-dev@googlegroups.com>; Thu,  6 Oct 2022 04:22:45 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 854A0C4FF81
	for <kasan-dev@googlegroups.com>; Thu,  6 Oct 2022 04:22:43 +0000 (UTC)
Received: by mail-ed1-f49.google.com with SMTP id y100so1118058ede.6
        for <kasan-dev@googlegroups.com>; Wed, 05 Oct 2022 21:22:43 -0700 (PDT)
X-Received: by 2002:a2e:7318:0:b0:26d:fdd9:6b2 with SMTP id
 o24-20020a2e7318000000b0026dfdd906b2mr1076019ljc.156.1665030148829; Wed, 05
 Oct 2022 21:22:28 -0700 (PDT)
MIME-Version: 1.0
References: <20221005214844.2699-1-Jason@zx2c4.com> <20221005214844.2699-2-Jason@zx2c4.com>
 <202210052035.A1020E3@keescook>
In-Reply-To: <202210052035.A1020E3@keescook>
From: KP Singh <kpsingh@kernel.org>
Date: Wed, 5 Oct 2022 21:22:17 -0700
X-Gmail-Original-Message-ID: <CACYkzJ6w6DitDk9uoEyyNeg+HmNHZx_tckJ_=EroqmT=CN3VBA@mail.gmail.com>
Message-ID: <CACYkzJ6w6DitDk9uoEyyNeg+HmNHZx_tckJ_=EroqmT=CN3VBA@mail.gmail.com>
Subject: Re: [PATCH v1 1/5] treewide: use prandom_u32_max() when possible
To: Kees Cook <keescook@chromium.org>
Cc: "Jason A. Donenfeld" <Jason@zx2c4.com>, linux-kernel@vger.kernel.org, 
	Ajay Singh <ajay.kathat@microchip.com>, Akinobu Mita <akinobu.mita@gmail.com>, 
	Alexandre Torgue <alexandre.torgue@foss.st.com>, Amitkumar Karwar <amitkarwar@gmail.com>, 
	Andreas Dilger <adilger.kernel@dilger.ca>, =?UTF-8?Q?Andreas_F=C3=A4rber?= <afaerber@suse.de>, 
	Andreas Noever <andreas.noever@gmail.com>, Andrew Lunn <andrew@lunn.ch>, 
	Andrew Morton <akpm@linux-foundation.org>, Andrii Nakryiko <andrii@kernel.org>, 
	Andy Gospodarek <andy@greyhouse.net>, Andy Lutomirski <luto@kernel.org>, 
	Andy Shevchenko <andriy.shevchenko@linux.intel.com>, 
	Anil S Keshavamurthy <anil.s.keshavamurthy@intel.com>, Anna Schumaker <anna@kernel.org>, 
	Arend van Spriel <aspriel@gmail.com>, Ayush Sawal <ayush.sawal@chelsio.com>, 
	Borislav Petkov <bp@alien8.de>, Chao Yu <chao@kernel.org>, 
	=?UTF-8?Q?Christoph_B=C3=B6hmwalder?= <christoph.boehmwalder@linbit.com>, 
	Christoph Hellwig <hch@lst.de>, Christophe Leroy <christophe.leroy@csgroup.eu>, 
	Chuck Lever <chuck.lever@oracle.com>, Claudiu Beznea <claudiu.beznea@microchip.com>, 
	Cong Wang <xiyou.wangcong@gmail.com>, Dan Williams <dan.j.williams@intel.com>, 
	Daniel Borkmann <daniel@iogearbox.net>, "Darrick J . Wong" <djwong@kernel.org>, 
	Dave Hansen <dave.hansen@linux.intel.com>, David Ahern <dsahern@kernel.org>, 
	"David S . Miller" <davem@davemloft.net>, 
	Dennis Dalessandro <dennis.dalessandro@cornelisnetworks.com>, 
	Dick Kennedy <dick.kennedy@broadcom.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Eric Dumazet <edumazet@google.com>, Florian Westphal <fw@strlen.de>, Franky Lin <franky.lin@broadcom.com>, 
	Ganapathi Bhat <ganapathi017@gmail.com>, Greg Kroah-Hartman <gregkh@linuxfoundation.org>, 
	Gregory Greenman <gregory.greenman@intel.com>, "H . Peter Anvin" <hpa@zytor.com>, 
	Hannes Reinecke <hare@suse.de>, Hans Verkuil <hverkuil@xs4all.nl>, 
	Hante Meuleman <hante.meuleman@broadcom.com>, Hao Luo <haoluo@google.com>, 
	Haoyue Xu <xuhaoyue1@hisilicon.com>, Heiner Kallweit <hkallweit1@gmail.com>, 
	Helge Deller <deller@gmx.de>, Herbert Xu <herbert@gondor.apana.org.au>, 
	Hideaki YOSHIFUJI <yoshfuji@linux-ipv6.org>, Hugh Dickins <hughd@google.com>, 
	Igor Mitsyanko <imitsyanko@quantenna.com>, Ilya Dryomov <idryomov@gmail.com>, 
	Ingo Molnar <mingo@redhat.com>, Jack Wang <jinpu.wang@ionos.com>, 
	Jaegeuk Kim <jaegeuk@kernel.org>, Jaehoon Chung <jh80.chung@samsung.com>, 
	Jakub Kicinski <kuba@kernel.org>, Jamal Hadi Salim <jhs@mojatatu.com>, 
	"James E . J . Bottomley" <jejb@linux.ibm.com>, James Smart <james.smart@broadcom.com>, Jan Kara <jack@suse.com>, 
	Jason Gunthorpe <jgg@ziepe.ca>, Jay Vosburgh <j.vosburgh@gmail.com>, Jean-Paul Roubelat <jpr@f6fbb.org>, 
	Jeff Layton <jlayton@kernel.org>, Jens Axboe <axboe@kernel.dk>, Jiri Olsa <jolsa@kernel.org>, 
	Jiri Pirko <jiri@resnulli.us>, Johannes Berg <johannes@sipsolutions.net>, 
	John Fastabend <john.fastabend@gmail.com>, John Stultz <jstultz@google.com>, 
	Jon Maloy <jmaloy@redhat.com>, Jonathan Corbet <corbet@lwn.net>, 
	Jozsef Kadlecsik <kadlec@netfilter.org>, Julian Anastasov <ja@ssi.bg>, Kalle Valo <kvalo@kernel.org>, 
	Keith Busch <kbusch@kernel.org>, Lars Ellenberg <lars.ellenberg@linbit.com>, 
	Leon Romanovsky <leon@kernel.org>, Manish Rangankar <mrangankar@marvell.com>, 
	Manivannan Sadhasivam <mani@kernel.org>, Marcelo Ricardo Leitner <marcelo.leitner@gmail.com>, 
	Marco Elver <elver@google.com>, "Martin K . Petersen" <martin.petersen@oracle.com>, 
	Martin KaFai Lau <martin.lau@linux.dev>, Masami Hiramatsu <mhiramat@kernel.org>, 
	Mauro Carvalho Chehab <mchehab@kernel.org>, Maxime Coquelin <mcoquelin.stm32@gmail.com>, 
	"Md . Haris Iqbal" <haris.iqbal@ionos.com>, Michael Chan <michael.chan@broadcom.com>, 
	Michael Ellerman <mpe@ellerman.id.au>, Michael Jamet <michael.jamet@intel.com>, 
	Michal Januszewski <spock@gentoo.org>, Mika Westerberg <mika.westerberg@linux.intel.com>, 
	Miquel Raynal <miquel.raynal@bootlin.com>, Namjae Jeon <linkinjeon@kernel.org>, 
	"Naveen N . Rao" <naveen.n.rao@linux.ibm.com>, Neil Horman <nhorman@tuxdriver.com>, 
	Nicholas Piggin <npiggin@gmail.com>, Nilesh Javali <njavali@marvell.com>, 
	OGAWA Hirofumi <hirofumi@mail.parknet.co.jp>, Pablo Neira Ayuso <pablo@netfilter.org>, 
	Paolo Abeni <pabeni@redhat.com>, Peter Zijlstra <peterz@infradead.org>, 
	Philipp Reisner <philipp.reisner@linbit.com>, Potnuri Bharat Teja <bharat@chelsio.com>, 
	Pravin B Shelar <pshelar@ovn.org>, Rasmus Villemoes <linux@rasmusvillemoes.dk>, 
	Richard Weinberger <richard@nod.at>, Rohit Maheshwari <rohitm@chelsio.com>, 
	Russell King <linux@armlinux.org.uk>, Sagi Grimberg <sagi@grimberg.me>, 
	Santosh Shilimkar <santosh.shilimkar@oracle.com>, Sergey Matyukevich <geomatsi@gmail.com>, 
	Sharvari Harisangam <sharvari.harisangam@nxp.com>, Simon Horman <horms@verge.net.au>, 
	Song Liu <song@kernel.org>, Stanislav Fomichev <sdf@google.com>, 
	Steffen Klassert <steffen.klassert@secunet.com>, Stephen Boyd <sboyd@kernel.org>, 
	Stephen Hemminger <stephen@networkplumber.org>, Sungjong Seo <sj1557.seo@samsung.com>, 
	"Theodore Ts'o" <tytso@mit.edu>, Thomas Gleixner <tglx@linutronix.de>, Thomas Graf <tgraf@suug.ch>, 
	Thomas Sailer <t.sailer@alumni.ethz.ch>, =?UTF-8?B?VG9rZSBIw7hpbGFuZC1Kw7hyZ2Vuc2Vu?= <toke@toke.dk>, 
	Trond Myklebust <trond.myklebust@hammerspace.com>, Ulf Hansson <ulf.hansson@linaro.org>, 
	Varun Prakash <varun@chelsio.com>, Veaceslav Falico <vfalico@gmail.com>, 
	Vignesh Raghavendra <vigneshr@ti.com>, Vinay Kumar Yadav <vinay.yadav@chelsio.com>, Vinod Koul <vkoul@kernel.org>, 
	Vlad Yasevich <vyasevich@gmail.com>, Wenpeng Liang <liangwenpeng@huawei.com>, 
	Xinming Hu <huxinming820@gmail.com>, Xiubo Li <xiubli@redhat.com>, 
	Yehezkel Bernat <YehezkelShB@gmail.com>, Ying Xue <ying.xue@windriver.com>, 
	Yishai Hadas <yishaih@nvidia.com>, Yonghong Song <yhs@fb.com>, Yury Norov <yury.norov@gmail.com>, 
	brcm80211-dev-list.pdl@broadcom.com, cake@lists.bufferbloat.net, 
	ceph-devel@vger.kernel.org, coreteam@netfilter.org, dccp@vger.kernel.org, 
	dev@openvswitch.org, dmaengine@vger.kernel.org, drbd-dev@lists.linbit.com, 
	dri-devel@lists.freedesktop.org, kasan-dev@googlegroups.com, 
	linux-actions@lists.infradead.org, linux-arm-kernel@lists.infradead.org, 
	linux-block@vger.kernel.org, linux-crypto@vger.kernel.org, 
	linux-doc@vger.kernel.org, linux-ext4@vger.kernel.org, 
	linux-f2fs-devel@lists.sourceforge.net, linux-fbdev@vger.kernel.org, 
	linux-fsdevel@vger.kernel.org, linux-hams@vger.kernel.org, 
	linux-media@vger.kernel.org, linux-mm@kvack.org, linux-mmc@vger.kernel.org, 
	linux-mtd@lists.infradead.org, linux-nfs@vger.kernel.org, 
	linux-nvme@lists.infradead.org, linux-raid@vger.kernel.org, 
	linux-rdma@vger.kernel.org, linux-scsi@vger.kernel.org, 
	linux-sctp@vger.kernel.org, linux-stm32@st-md-mailman.stormreply.com, 
	linux-usb@vger.kernel.org, linux-wireless@vger.kernel.org, 
	linux-xfs@vger.kernel.org, linuxppc-dev@lists.ozlabs.org, 
	lvs-devel@vger.kernel.org, netdev@vger.kernel.org, 
	netfilter-devel@vger.kernel.org, rds-devel@oss.oracle.com, 
	SHA-cyfmac-dev-list@infineon.com, target-devel@vger.kernel.org, 
	tipc-discussion@lists.sourceforge.net
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: kpsingh@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=ocUSwvib;       spf=pass
 (google.com: domain of kpsingh@kernel.org designates 139.178.84.217 as
 permitted sender) smtp.mailfrom=kpsingh@kernel.org;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=kernel.org
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

On Wed, Oct 5, 2022 at 9:16 PM Kees Cook <keescook@chromium.org> wrote:
>
> On Wed, Oct 05, 2022 at 11:48:40PM +0200, Jason A. Donenfeld wrote:
> > Rather than incurring a division or requesting too many random bytes for
> > the given range, use the prandom_u32_max() function, which only takes
> > the minimum required bytes from the RNG and avoids divisions.
>
> Yes please!
>
> Since this is a treewide patch, it's helpful for (me at least) doing
> reviews to detail the mechanism of the transformation.
>
> e.g. I imagine this could be done with something like Coccinelle and
>
> @no_modulo@
> expression E;
> @@
>
> -       (prandom_u32() % (E))
> +       prandom_u32_max(E)
>
> > diff --git a/drivers/mtd/ubi/debug.h b/drivers/mtd/ubi/debug.h
> > index 118248a5d7d4..4236c799a47c 100644
> > --- a/drivers/mtd/ubi/debug.h
> > +++ b/drivers/mtd/ubi/debug.h
> > @@ -73,7 +73,7 @@ static inline int ubi_dbg_is_bgt_disabled(const struct ubi_device *ubi)
> >  static inline int ubi_dbg_is_bitflip(const struct ubi_device *ubi)
> >  {
> >       if (ubi->dbg.emulate_bitflips)
> > -             return !(prandom_u32() % 200);
> > +             return !(prandom_u32_max(200));
> >       return 0;
> >  }
> >
>
> Because some looks automated (why the parens?)
>
> > @@ -393,14 +387,11 @@ static struct test_driver {
> >
> >  static void shuffle_array(int *arr, int n)
> >  {
> > -     unsigned int rnd;
> >       int i, j;
> >
> >       for (i = n - 1; i > 0; i--)  {
> > -             rnd = prandom_u32();
> > -
> >               /* Cut the range. */
> > -             j = rnd % i;
> > +             j = prandom_u32_max(i);
> >
> >               /* Swap indexes. */
> >               swap(arr[i], arr[j]);
>
> And some by hand. :)
>
> Reviewed-by: Kees Cook <keescook@chromium.org>

Thanks!

Reviewed-by: KP Singh <kpsingh@kernel.org>


>
> --
> Kees Cook

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACYkzJ6w6DitDk9uoEyyNeg%2BHmNHZx_tckJ_%3DEroqmT%3DCN3VBA%40mail.gmail.com.
