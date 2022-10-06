Return-Path: <kasan-dev+bncBCLI747UVAFRBWNF7OMQMGQEGJBZ4ZY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43b.google.com (mail-pf1-x43b.google.com [IPv6:2607:f8b0:4864:20::43b])
	by mail.lfdr.de (Postfix) with ESMTPS id 805F95F673D
	for <lists+kasan-dev@lfdr.de>; Thu,  6 Oct 2022 15:06:35 +0200 (CEST)
Received: by mail-pf1-x43b.google.com with SMTP id 124-20020a620582000000b0056177a9e489sf1134413pff.22
        for <lists+kasan-dev@lfdr.de>; Thu, 06 Oct 2022 06:06:35 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1665061594; cv=pass;
        d=google.com; s=arc-20160816;
        b=rNWJgy16rshdrffsA4zV0aWFMh35+6V9j7hGeYlPhmVhVSsmnRj7oDeoO7kQXW23yS
         y54x712xK9yfyoUjYV82PXa6PYF9TfLm+20TXGdM6Qgf+T8FGSDlc3uQhf0DIMSSmZGO
         59HyvIgsezEacSBalJDsdUbar42ecmzcM7as1wXQgnc1KD51fnPB0wioXpfwJhnVcpWu
         eNivrqLmm1xn4i4tx+gYGEdR+LhcV+VfvLGqmJ+c/q5WKXlA6jptcQWIkKyzSpRybZ1k
         ZxmkszZH9pi2lKKvZyiTI7uBMXesK0nKzGRh3kM8grzcKUX8wO3sNpXRClOEAPPK7gZ/
         Ua1w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=kjsi7UcFVjr/PsmoJpxLTaC3WmnxHBGRO+9s+qYGOKA=;
        b=qaufIyTyUfeRZs35jrD6hwJ31kleRbruOfqkD9b/PGmTc9gqO+iwK8/5U1cVPQT+Xa
         jtboKTt74mjts27FxEZn1VNpFOlV4P8U6ZSG5n50IS/rw7sssz4Boj24NfB67XMT2bQx
         WhFSZLhpSOTbbmK+1Z2HNjCbAhqnQHMH+aRAju/uywUAqFM/T+E1jIsQJ0sQ24+F34K+
         DK2+CMX6xSG2nsQkaPypuwWGLTpi9XdPBJG05+DLePB7iivn6MmkRsoTpLebRmvGLFJ6
         tMPd4qxHMvaJ7wZJDm+sWzMaby/dpLpUviJfeF2bNlfhDsEGRCaj91OmkHEfrLecndJD
         ynAw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@zx2c4.com header.s=20210105 header.b=AuLKX8Dr;
       spf=pass (google.com: domain of srs0=tiop=2h=zx2c4.com=jason@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom="SRS0=tIOp=2H=zx2c4.com=Jason@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=zx2c4.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=kjsi7UcFVjr/PsmoJpxLTaC3WmnxHBGRO+9s+qYGOKA=;
        b=D31Sk8ln+eIVwoyebUMNq6ZzibIG65MPUFunwrWpjaB6iqv58QpngdVD7qjNFDyPQe
         hC8EwTQC4FNxxCHNPuYY6eUABJ7/SNMYfURFRtTV2OKuJGm/JIu6zciophvs+73kHr/w
         Pegs7aoYrrgXLi7M7FU2jBDciy7Kh/MDY8KiFXxVWxKzPurdotDkL/3pMIGENMAmmVXD
         pTR/8ClDK5P9xJXHygL7TJ9z66l23+HZ57+2W2bwJY09PW2ynTbd3Uk2v1wKDbXBn1vV
         lVdpGgrd24H8HzhiqJgaN1PAvpSOTVXZ+cXAgrOFiVSOd9jXexCgAP4UVvMnC2pxwloY
         Q3CQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=kjsi7UcFVjr/PsmoJpxLTaC3WmnxHBGRO+9s+qYGOKA=;
        b=z5si8V4WqdGnDU7JSkq9JJtGFuhVYzXAbxhsafe0zWdUcPGJdqIdgQzTKNkqpiQvgf
         KjYKF9iGMce/96RRezvvvYHkVXnIh5xIonyr8yb2MCAnTzGFRqjDJ8ph5DkziQtTyF9N
         6f0oXdonusqLC4dh/7QdmF3cXoLFbJfiwfrQiND1olfkFNCLgv8JcAfOd0TjmuF/kBkY
         +dIEgJAErSixSGNbCyPUiFB5zQ1qsmLYg/XYEZk49WYeGMl7M70aqW87d3978n5tSq4t
         KuAWYR5Qwn6bg1+QsHHm0FZdu+ajZ3At5mjfeWGGFmX46b5+XlQUKIOeiVc1Todg6rYC
         3O4w==
X-Gm-Message-State: ACrzQf06X9MFp/uG1HLkEFMwgjpEUnXfqgaRAKymUs6XjS8Fb7gXPiKt
	Cs4XBlWlmpaq2inRNRyO7fM=
X-Google-Smtp-Source: AMsMyM4erTVKrDmjl6dnSVoN07mmjze3AP2JRRirXteJAyPBxcuUIceiwUfyohBm8dAfikn0HhvmNA==
X-Received: by 2002:a65:6042:0:b0:440:56aa:d5cf with SMTP id a2-20020a656042000000b0044056aad5cfmr4550656pgp.81.1665061594027;
        Thu, 06 Oct 2022 06:06:34 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:903:32c1:b0:17a:6fa:2290 with SMTP id
 i1-20020a17090332c100b0017a06fa2290ls1626871plr.3.-pod-prod-gmail; Thu, 06
 Oct 2022 06:06:33 -0700 (PDT)
X-Received: by 2002:a17:90b:1e01:b0:202:ee2b:c856 with SMTP id pg1-20020a17090b1e0100b00202ee2bc856mr10493521pjb.29.1665061593309;
        Thu, 06 Oct 2022 06:06:33 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1665061593; cv=none;
        d=google.com; s=arc-20160816;
        b=H4lvQYV4tEnir4+XWKXvITPZuvvadH50OOJ0M5/Y0469wuAdmTFrp/7UKoCsJ5Gbrm
         iibFO2J9wCYYTLFkyiYojVsBSOdyxhF8F9mpIMD2DbmBsLc1lKfLSchBwT4b36c1p1Gj
         9eRTOoi7SQs39zMSPh1Xpb53WTZMxPEvCFg0tPcKiEBnUS8QXVa0PKa19sF1iArFagbw
         LgIaIGG29H6e6nV2O/rwVVttkzAOM2d7fhqgUiEXlwXjSHMpIVbMlfmLtrPpWO2VHHZd
         jM3svuYQZcQU3KOma9s63nIhNVc+m1wf9EqLsJIrzG2AIL+8sfJomkoE7FdT/5GEuGm0
         YgKA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=pA8UwcaEH1EIaWBd+j+3kMQvSGVLEaIn/zvGprOy4bY=;
        b=JgP9eSYUSQ5MToMILiyp/NZQUZlQKZpc1IG2WrEahkXh9/24WSjk3tzOEUt7aY2ONI
         VtucqfprcZmpakG54iMpRKvsK70XxOEgLX0/L9KEP9jisyWyEJwGV4odotnygmBbbHCA
         bET0BbpIyliochoYQ7590MH3AUgUy4LEyij0mfF+7l/bbeqePFQnB+ZC/NZo9Omnyl8F
         ESaohBLbp3XtB5Mbz4H4DwQqU4jcd21eCbp080X1IVxQ12urWqeSXijOgJaq1vGgWWtU
         pUsr55k0spM69MB5W17Egu39dGs1/H5D95eS4h473Yi0PHIaorgVJHwrV0AuYInY6lSx
         h9gQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@zx2c4.com header.s=20210105 header.b=AuLKX8Dr;
       spf=pass (google.com: domain of srs0=tiop=2h=zx2c4.com=jason@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom="SRS0=tIOp=2H=zx2c4.com=Jason@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=zx2c4.com
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id n47-20020a056a000d6f00b005624b6ebf96si173116pfv.3.2022.10.06.06.06.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 06 Oct 2022 06:06:33 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=tiop=2h=zx2c4.com=jason@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id C3114619AF
	for <kasan-dev@googlegroups.com>; Thu,  6 Oct 2022 13:06:32 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 65477C4347C
	for <kasan-dev@googlegroups.com>; Thu,  6 Oct 2022 13:06:32 +0000 (UTC)
Received: by mail.zx2c4.com (ZX2C4 Mail Server) with ESMTPSA id f6dd0634 (TLSv1.3:TLS_AES_256_GCM_SHA384:256:NO)
	for <kasan-dev@googlegroups.com>;
	Thu, 6 Oct 2022 13:06:22 +0000 (UTC)
Received: by mail-pj1-f44.google.com with SMTP id t12-20020a17090a3b4c00b0020b04251529so1643296pjf.5
        for <kasan-dev@googlegroups.com>; Thu, 06 Oct 2022 06:06:19 -0700 (PDT)
X-Received: by 2002:a1f:e0c4:0:b0:3ab:191d:e135 with SMTP id
 x187-20020a1fe0c4000000b003ab191de135mr2112405vkg.41.1665061560263; Thu, 06
 Oct 2022 06:06:00 -0700 (PDT)
MIME-Version: 1.0
References: <20221005214844.2699-1-Jason@zx2c4.com> <20221005214844.2699-4-Jason@zx2c4.com>
 <Yz7OdfKZeGkpZSKb@ziepe.ca>
In-Reply-To: <Yz7OdfKZeGkpZSKb@ziepe.ca>
From: "'Jason A. Donenfeld' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 6 Oct 2022 07:05:48 -0600
X-Gmail-Original-Message-ID: <CAHmME9r_vNRFFjUvqx8QkBddg_kQU=FMgpk9TqOVZdvX6zXHNg@mail.gmail.com>
Message-ID: <CAHmME9r_vNRFFjUvqx8QkBddg_kQU=FMgpk9TqOVZdvX6zXHNg@mail.gmail.com>
Subject: Re: [PATCH v1 3/5] treewide: use get_random_u32() when possible
To: Jason Gunthorpe <jgg@ziepe.ca>
Cc: linux-kernel@vger.kernel.org, Ajay Singh <ajay.kathat@microchip.com>, 
	Akinobu Mita <akinobu.mita@gmail.com>, Alexandre Torgue <alexandre.torgue@foss.st.com>, 
	Amitkumar Karwar <amitkarwar@gmail.com>, Andreas Dilger <adilger.kernel@dilger.ca>, 
	=?UTF-8?Q?Andreas_F=C3=A4rber?= <afaerber@suse.de>, 
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
	Jay Vosburgh <j.vosburgh@gmail.com>, Jean-Paul Roubelat <jpr@f6fbb.org>, Jeff Layton <jlayton@kernel.org>, 
	Jens Axboe <axboe@kernel.dk>, Jiri Olsa <jolsa@kernel.org>, Jiri Pirko <jiri@resnulli.us>, 
	Johannes Berg <johannes@sipsolutions.net>, John Fastabend <john.fastabend@gmail.com>, 
	John Stultz <jstultz@google.com>, Jon Maloy <jmaloy@redhat.com>, Jonathan Corbet <corbet@lwn.net>, 
	Jozsef Kadlecsik <kadlec@netfilter.org>, Julian Anastasov <ja@ssi.bg>, KP Singh <kpsingh@kernel.org>, 
	Kalle Valo <kvalo@kernel.org>, Kees Cook <keescook@chromium.org>, 
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
X-Original-Sender: jason@zx2c4.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@zx2c4.com header.s=20210105 header.b=AuLKX8Dr;       spf=pass
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

On Thu, Oct 6, 2022 at 6:47 AM Jason Gunthorpe <jgg@ziepe.ca> wrote:
>
> On Wed, Oct 05, 2022 at 11:48:42PM +0200, Jason A. Donenfeld wrote:
>
> > index 14392c942f49..499a425a3379 100644
> > --- a/drivers/infiniband/hw/cxgb4/cm.c
> > +++ b/drivers/infiniband/hw/cxgb4/cm.c
> > @@ -734,7 +734,7 @@ static int send_connect(struct c4iw_ep *ep)
> >                                  &ep->com.remote_addr;
> >       int ret;
> >       enum chip_type adapter_type = ep->com.dev->rdev.lldi.adapter_type;
> > -     u32 isn = (prandom_u32() & ~7UL) - 1;
> > +     u32 isn = (get_random_u32() & ~7UL) - 1;
>
> Maybe this wants to be written as
>
> (prandom_max(U32_MAX >> 7) << 7) | 7
>
> ?

Holy smokes. Yea I guess maybe? It doesn't exactly gain anything or
make the code clearer though, and is a little bit more magical than
I'd like on a first pass.

>
> > diff --git a/drivers/infiniband/ulp/ipoib/ipoib_cm.c b/drivers/infiniband/ulp/ipoib/ipoib_cm.c
> > index fd9d7f2c4d64..a605cf66b83e 100644
> > --- a/drivers/infiniband/ulp/ipoib/ipoib_cm.c
> > +++ b/drivers/infiniband/ulp/ipoib/ipoib_cm.c
> > @@ -465,7 +465,7 @@ static int ipoib_cm_req_handler(struct ib_cm_id *cm_id,
> >               goto err_qp;
> >       }
> >
> > -     psn = prandom_u32() & 0xffffff;
> > +     psn = get_random_u32() & 0xffffff;
>
>  prandom_max(0xffffff + 1)

That'd work, but again it's not more clear. Authors here are going for
a 24-bit number, and masking seems like a clear way to express that.

Jason

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAHmME9r_vNRFFjUvqx8QkBddg_kQU%3DFMgpk9TqOVZdvX6zXHNg%40mail.gmail.com.
