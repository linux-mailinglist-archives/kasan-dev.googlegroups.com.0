Return-Path: <kasan-dev+bncBCLI747UVAFRBKMW7OMQMGQENDRJDFI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-x1140.google.com (mail-yw1-x1140.google.com [IPv6:2607:f8b0:4864:20::1140])
	by mail.lfdr.de (Postfix) with ESMTPS id 9D5C85F661E
	for <lists+kasan-dev@lfdr.de>; Thu,  6 Oct 2022 14:33:46 +0200 (CEST)
Received: by mail-yw1-x1140.google.com with SMTP id 00721157ae682-355bdeba45bsf17288797b3.0
        for <lists+kasan-dev@lfdr.de>; Thu, 06 Oct 2022 05:33:46 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1665059625; cv=pass;
        d=google.com; s=arc-20160816;
        b=PDW6cUJT1OWclAacQO7eVe2k4wLew6VyVfGEiXuhhozJwJvIsG7TRDkiFT/K58zaGO
         lJIvTemVf2L53+5oLP+GDLOhANEsy5zY4UZLKRbhLkfoMor8k6tNO+JmmXBOIYWe5ErL
         Y3N/pCW3FXoZvIWg2nEqul9mz5XRuqJ/4B7H7wsmQKe3/HcefqnURglLS9IPUN8d4trv
         MV+GIxWHmO1UcuZn4itwurVVmczcaOFk6QthVK04uzgGozAfqzwZn9Nvy4pkCcdqBHOC
         ongxNdh0Lb8NrEkg0LyD3613bdcg4UMZxWEsO0MqZGrjEU2mWKsfvceVxp/jZ0Iegs6n
         i/nQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=lsoT1fh/yE2gBIrFp/rlyESYXniFBaWpIj1UaVQUepk=;
        b=gj57Jza4UEdN00LSKq+si0KbIzxt7VrDmwmcLJx3rAqpCdecPg2kgS4Fzagmz/Inwr
         qhsjPBH8dDaPUvLhskPKiJRnCVZ6pcH3t1FRj5mBbJHxGANhigmxdzAuHR+k1NUzi27a
         InC8W4sgfIqP//oF0t5A+hBcqeFuQV/+3wMr6N9xUd9Ok2fYewZnRUymciYDJ97J9tBv
         LqxsmSEOUy5ft47vrP7Svo2Z8nhdWUzkt6Tw5R1g1o6K+GkdFidocfoVYIxd01wl1qUw
         FHEIy0irZsiUz1//DMVDF/RqPP4ZeNfoDXvYl9P+omFqCLHSCeKpDPQ18Q5aowjZF0Dh
         m0xA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@zx2c4.com header.s=20210105 header.b=boaVkmFe;
       spf=pass (google.com: domain of srs0=tiop=2h=zx2c4.com=jason@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom="SRS0=tIOp=2H=zx2c4.com=Jason@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=zx2c4.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date;
        bh=lsoT1fh/yE2gBIrFp/rlyESYXniFBaWpIj1UaVQUepk=;
        b=ppUPGkW1AGjCmP3VrBLY+zNyZeBS/fUCxlefln2X+haKfISiP6gfe+Wn9DrhpnLQI9
         /JpofcM9KoXKRYBBlFrTS7fRNfmn8UOkPkb9po5cKpEM7E3z8ERt/lt0+/FnTzwIot8L
         UJB7YrLsqQUC8i01q6JCXJDmTlvIK0wsRz+YTQs360mhWUp7NU+8sopVXzgTdxmQBwa+
         b57xZKAfF6mKIvm32GZ6q+mRN9UI0ZVj5a5eLiMB4nY7cnR29tE87sJtSigUiUFWouks
         69Rv4nuvp0mpyPP3bahOS3brLAAmYvqDOCqdQHaT5kQqNdRVOlqjOFjyHXmrgjlMGMYo
         UCrA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:from:to:cc:subject:date;
        bh=lsoT1fh/yE2gBIrFp/rlyESYXniFBaWpIj1UaVQUepk=;
        b=ZS9MTOAqti8yCUwgDgcjxTVO4FsSCgYIPCChDGoXDg7ehbmb1GKMnA+avIAu2Gqr9r
         lffdKfai7pC9JtDzd78rlawJNVAJnG9R3Sd7jduZZtWtLIKMjvLsWTID1y28qeyZe4Wr
         fZgKY0tjXVi/7a5sKcmUbjDaY+3qh5/XgHRjIVKx5/E1ErJnb23jnRkv5aHNobeD8yOS
         EDPSvvWOvmV86OdR+R5xpj/E3MvzE6GJYDICE7gPvFkkKgrkpUqTaowa2aFSiRCLuYEC
         B8ZjbHv49YnBHsIKWsnO5W9+isJaXU1fi3wtSvQxf2CN7R6+oU0vaATDP4C5V04UX4Te
         0/7A==
X-Gm-Message-State: ACrzQf1d4CywPmwLp97BGS6Rl/aI8zizsIZ2vVSbvcMEcqhSjX8FjCO8
	vhg6vuPqt1Cd+dKqNe52quM=
X-Google-Smtp-Source: AMsMyM6ywHDpClxW7hKgVww2GoP1wWFWtaj8D+y6mHEdtDZHpCRg9aR73scew8ufTrXmn/V07oScDw==
X-Received: by 2002:a25:8411:0:b0:6a2:d934:f0c3 with SMTP id u17-20020a258411000000b006a2d934f0c3mr4440684ybk.397.1665059625337;
        Thu, 06 Oct 2022 05:33:45 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a81:480c:0:b0:345:895d:35eb with SMTP id v12-20020a81480c000000b00345895d35ebls686261ywa.2.-pod-prod-gmail;
 Thu, 06 Oct 2022 05:33:44 -0700 (PDT)
X-Received: by 2002:a81:48d6:0:b0:355:8d0a:d8a1 with SMTP id v205-20020a8148d6000000b003558d0ad8a1mr4120058ywa.467.1665059624845;
        Thu, 06 Oct 2022 05:33:44 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1665059624; cv=none;
        d=google.com; s=arc-20160816;
        b=RBceaA0AaYCqyan9j4GLerKDkHCRf5mKNbXw3mFhpBvo7AUYPKN/7m58L9Tdl2GQIv
         uk8yLrb0mavW89LhzVM5FiBLsNdVSfUxUAhCt7KjqQNrTyMahwvw6wmN/5lHd3XPNr1c
         ky/3TSjOjamxnLYKh+XSK+lPvU+nr8/OQX6L394Kru0QgevEKgZcMv0t2WGhlmxsYxAY
         33NIko0/e/7BKCEgQyyrsimmJ8t5eXza0Xk5uuWBo+SbWsi6Lguuxj9coEm5Oz05TFJ4
         NGBaJt14dJjjoVxR3S1UnOOvlRmKneWv7siwEh1Jiz+A5pFownpMSE+Mh41jw//mtWwj
         DYUA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=PDyor0OPorRMVekuFSJiAglRmrxBh1riIl1rICqIsks=;
        b=h/M/Kdi2Yhh2ZesUTQl6XbPdkOioFaY743LI3+rkG4j3P90qUnygvtP0jHdQCg7el2
         PeDI4WxxdJmVdZrl335EUsznEIqMHd82mJp5gzhXfZ9e10IpbxOS24viNh0QL3V27rS4
         YpfKcm2OQvQYIOHKiFt3CKnBkymmewv7555SaCMUsU4Fyj5/SQe1mcVrQwfvurCtD6IA
         Tbp7ckEyMQAUgEEQ83HOeatyp2DD/qQ0XBvyIRFyI90/YZz3QLdUA0zm6Pn2OGnJLd5U
         YQ4wimZlRoblGurbpauSYldsaxdf/h+GLm36KPyrC8kf9lMMdwT4RxyGOHGJTM34hyh/
         N2VA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@zx2c4.com header.s=20210105 header.b=boaVkmFe;
       spf=pass (google.com: domain of srs0=tiop=2h=zx2c4.com=jason@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom="SRS0=tIOp=2H=zx2c4.com=Jason@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=zx2c4.com
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id s132-20020a25778a000000b006be3d17ff2asi358503ybc.1.2022.10.06.05.33.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 06 Oct 2022 05:33:44 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=tiop=2h=zx2c4.com=jason@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id 4BD8A6189D;
	Thu,  6 Oct 2022 12:33:44 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 84CC2C433D6;
	Thu,  6 Oct 2022 12:33:28 +0000 (UTC)
Received: by mail.zx2c4.com (ZX2C4 Mail Server) with ESMTPSA id 2c48390d (TLSv1.3:TLS_AES_256_GCM_SHA384:256:NO);
	Thu, 6 Oct 2022 12:33:26 +0000 (UTC)
Date: Thu, 6 Oct 2022 06:33:15 -0600
From: "'Jason A. Donenfeld' via kasan-dev" <kasan-dev@googlegroups.com>
To: Jan Kara <jack@suse.cz>
Cc: Andrew Lunn <andrew@lunn.ch>, "Darrick J . Wong" <djwong@kernel.org>,
	Ulf Hansson <ulf.hansson@linaro.org>,
	dri-devel@lists.freedesktop.org,
	Andrii Nakryiko <andrii@kernel.org>,
	Hans Verkuil <hverkuil@xs4all.nl>, linux-sctp@vger.kernel.org,
	"Md . Haris Iqbal" <haris.iqbal@ionos.com>,
	Miquel Raynal <miquel.raynal@bootlin.com>,
	Christoph Hellwig <hch@lst.de>,
	Andy Gospodarek <andy@greyhouse.net>,
	Sergey Matyukevich <geomatsi@gmail.com>,
	Rohit Maheshwari <rohitm@chelsio.com>,
	Michael Ellerman <mpe@ellerman.id.au>, ceph-devel@vger.kernel.org,
	Christophe Leroy <christophe.leroy@csgroup.eu>,
	Jozsef Kadlecsik <kadlec@netfilter.org>,
	Nilesh Javali <njavali@marvell.com>,
	Jean-Paul Roubelat <jpr@f6fbb.org>,
	Dick Kennedy <dick.kennedy@broadcom.com>,
	Jay Vosburgh <j.vosburgh@gmail.com>,
	Potnuri Bharat Teja <bharat@chelsio.com>,
	Vinay Kumar Yadav <vinay.yadav@chelsio.com>,
	linux-nfs@vger.kernel.org, Nicholas Piggin <npiggin@gmail.com>,
	Igor Mitsyanko <imitsyanko@quantenna.com>,
	Andy Lutomirski <luto@kernel.org>, linux-hams@vger.kernel.org,
	Thomas Gleixner <tglx@linutronix.de>,
	Trond Myklebust <trond.myklebust@hammerspace.com>,
	linux-raid@vger.kernel.org, Neil Horman <nhorman@tuxdriver.com>,
	Hante Meuleman <hante.meuleman@broadcom.com>,
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
	linux-usb@vger.kernel.org, Michael Chan <michael.chan@broadcom.com>,
	linux-kernel@vger.kernel.org, Varun Prakash <varun@chelsio.com>,
	Chuck Lever <chuck.lever@oracle.com>,
	netfilter-devel@vger.kernel.org,
	Masami Hiramatsu <mhiramat@kernel.org>,
	Jiri Olsa <jolsa@kernel.org>, Jan Kara <jack@suse.com>,
	linux-fsdevel@vger.kernel.org,
	Lars Ellenberg <lars.ellenberg@linbit.com>,
	linux-media@vger.kernel.org,
	Claudiu Beznea <claudiu.beznea@microchip.com>,
	Sharvari Harisangam <sharvari.harisangam@nxp.com>,
	linux-fbdev@vger.kernel.org, linux-doc@vger.kernel.org,
	linux-mmc@vger.kernel.org,
	Dave Hansen <dave.hansen@linux.intel.com>,
	Song Liu <song@kernel.org>, Eric Dumazet <edumazet@google.com>,
	target-devel@vger.kernel.org, John Stultz <jstultz@google.com>,
	Stanislav Fomichev <sdf@google.com>,
	Gregory Greenman <gregory.greenman@intel.com>,
	drbd-dev@lists.linbit.com, dev@openvswitch.org,
	Leon Romanovsky <leon@kernel.org>, Helge Deller <deller@gmx.de>,
	Hugh Dickins <hughd@google.com>,
	James Smart <james.smart@broadcom.com>,
	Anil S Keshavamurthy <anil.s.keshavamurthy@intel.com>,
	Pravin B Shelar <pshelar@ovn.org>, Julian Anastasov <ja@ssi.bg>,
	coreteam@netfilter.org, Veaceslav Falico <vfalico@gmail.com>,
	Yonghong Song <yhs@fb.com>, Namjae Jeon <linkinjeon@kernel.org>,
	linux-crypto@vger.kernel.org,
	Santosh Shilimkar <santosh.shilimkar@oracle.com>,
	Ganapathi Bhat <ganapathi017@gmail.com>,
	linux-actions@lists.infradead.org,
	Simon Horman <horms@verge.net.au>, Jaegeuk Kim <jaegeuk@kernel.org>,
	Mika Westerberg <mika.westerberg@linux.intel.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	OGAWA Hirofumi <hirofumi@mail.parknet.co.jp>,
	Hao Luo <haoluo@google.com>, Theodore Ts'o <tytso@mit.edu>,
	Stephen Boyd <sboyd@kernel.org>,
	Dennis Dalessandro <dennis.dalessandro@cornelisnetworks.com>,
	Florian Westphal <fw@strlen.de>,
	Andreas =?utf-8?Q?F=C3=A4rber?= <afaerber@suse.de>,
	Jon Maloy <jmaloy@redhat.com>, Vlad Yasevich <vyasevich@gmail.com>,
	Anna Schumaker <anna@kernel.org>,
	Yehezkel Bernat <YehezkelShB@gmail.com>,
	Haoyue Xu <xuhaoyue1@hisilicon.com>,
	Heiner Kallweit <hkallweit1@gmail.com>,
	linux-wireless@vger.kernel.org,
	Marcelo Ricardo Leitner <marcelo.leitner@gmail.com>,
	Rasmus Villemoes <linux@rasmusvillemoes.dk>,
	linux-nvme@lists.infradead.org,
	Michal Januszewski <spock@gentoo.org>,
	linux-mtd@lists.infradead.org, kasan-dev@googlegroups.com,
	Cong Wang <xiyou.wangcong@gmail.com>,
	Thomas Sailer <t.sailer@alumni.ethz.ch>,
	Ajay Singh <ajay.kathat@microchip.com>,
	Xiubo Li <xiubli@redhat.com>, Sagi Grimberg <sagi@grimberg.me>,
	Daniel Borkmann <daniel@iogearbox.net>,
	Jonathan Corbet <corbet@lwn.net>, linux-rdma@vger.kernel.org,
	lvs-devel@vger.kernel.org, linux-arm-kernel@lists.infradead.org,
	"Naveen N . Rao" <naveen.n.rao@linux.ibm.com>,
	Ilya Dryomov <idryomov@gmail.com>, Paolo Abeni <pabeni@redhat.com>,
	Pablo Neira Ayuso <pablo@netfilter.org>,
	Marco Elver <elver@google.com>, Kees Cook <keescook@chromium.org>,
	Yury Norov <yury.norov@gmail.com>,
	"James E . J . Bottomley" <jejb@linux.ibm.com>,
	Jamal Hadi Salim <jhs@mojatatu.com>, KP Singh <kpsingh@kernel.org>,
	Borislav Petkov <bp@alien8.de>, Keith Busch <kbusch@kernel.org>,
	Dan Williams <dan.j.williams@intel.com>,
	Mauro Carvalho Chehab <mchehab@kernel.org>,
	Franky Lin <franky.lin@broadcom.com>,
	Arend van Spriel <aspriel@gmail.com>, linux-ext4@vger.kernel.org,
	Wenpeng Liang <liangwenpeng@huawei.com>,
	"Martin K . Petersen" <martin.petersen@oracle.com>,
	Xinming Hu <huxinming820@gmail.com>,
	linux-stm32@st-md-mailman.stormreply.com,
	Jeff Layton <jlayton@kernel.org>, linux-xfs@vger.kernel.org,
	netdev@vger.kernel.org, Ying Xue <ying.xue@windriver.com>,
	Manish Rangankar <mrangankar@marvell.com>,
	"David S . Miller" <davem@davemloft.net>,
	Toke =?utf-8?Q?H=C3=B8iland-J=C3=B8rgensen?= <toke@toke.dk>,
	Vignesh Raghavendra <vigneshr@ti.com>,
	Peter Zijlstra <peterz@infradead.org>,
	"H . Peter Anvin" <hpa@zytor.com>,
	Alexandre Torgue <alexandre.torgue@foss.st.com>,
	Amitkumar Karwar <amitkarwar@gmail.com>, linux-mm@kvack.org,
	Andreas Dilger <adilger.kernel@dilger.ca>,
	Ayush Sawal <ayush.sawal@chelsio.com>,
	Andreas Noever <andreas.noever@gmail.com>,
	Jiri Pirko <jiri@resnulli.us>,
	linux-f2fs-devel@lists.sourceforge.net,
	Jack Wang <jinpu.wang@ionos.com>,
	Steffen Klassert <steffen.klassert@secunet.com>,
	rds-devel@oss.oracle.com, Herbert Xu <herbert@gondor.apana.org.au>,
	linux-scsi@vger.kernel.org, dccp@vger.kernel.org,
	Richard Weinberger <richard@nod.at>,
	Russell King <linux@armlinux.org.uk>,
	Jason Gunthorpe <jgg@ziepe.ca>, SHA-cyfmac-dev-list@infineon.com,
	Ingo Molnar <mingo@redhat.com>, Jakub Kicinski <kuba@kernel.org>,
	John Fastabend <john.fastabend@gmail.com>,
	Maxime Coquelin <mcoquelin.stm32@gmail.com>,
	Manivannan Sadhasivam <mani@kernel.org>,
	Michael Jamet <michael.jamet@intel.com>,
	Kalle Valo <kvalo@kernel.org>,
	Akinobu Mita <akinobu.mita@gmail.com>, linux-block@vger.kernel.org,
	dmaengine@vger.kernel.org, Hannes Reinecke <hare@suse.de>,
	Andy Shevchenko <andriy.shevchenko@linux.intel.com>,
	Dmitry Vyukov <dvyukov@google.com>, Jens Axboe <axboe@kernel.dk>,
	cake@lists.bufferbloat.net, brcm80211-dev-list.pdl@broadcom.com,
	Yishai Hadas <yishaih@nvidia.com>,
	Hideaki YOSHIFUJI <yoshfuji@linux-ipv6.org>,
	linuxppc-dev@lists.ozlabs.org, David Ahern <dsahern@kernel.org>,
	Philipp Reisner <philipp.reisner@linbit.com>,
	Stephen Hemminger <stephen@networkplumber.org>,
	Christoph =?utf-8?Q?B=C3=B6hmwalder?= <christoph.boehmwalder@linbit.com>,
	Vinod Koul <vkoul@kernel.org>,
	tipc-discussion@lists.sourceforge.net, Thomas Graf <tgraf@suug.ch>,
	Johannes Berg <johannes@sipsolutions.net>,
	Sungjong Seo <sj1557.seo@samsung.com>,
	Martin KaFai Lau <martin.lau@linux.dev>
Subject: Re: [f2fs-dev] [PATCH v1 3/5] treewide: use get_random_u32() when
 possible
Message-ID: <Yz7LCyIAHC6l5mG9@zx2c4.com>
References: <20221005214844.2699-1-Jason@zx2c4.com>
 <20221005214844.2699-4-Jason@zx2c4.com>
 <20221006084331.4bdktc2zlvbaszym@quack3>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20221006084331.4bdktc2zlvbaszym@quack3>
X-Original-Sender: jason@zx2c4.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@zx2c4.com header.s=20210105 header.b=boaVkmFe;       spf=pass
 (google.com: domain of srs0=tiop=2h=zx2c4.com=jason@kernel.org designates
 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom="SRS0=tIOp=2H=zx2c4.com=Jason@kernel.org";
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

On Thu, Oct 06, 2022 at 10:43:31AM +0200, Jan Kara wrote:
> The code here is effectively doing the
> 
> 	parent_group = prandom_u32_max(ngroups);
> 
> Similarly here we can use prandom_u32_max(ngroups) like:
> 
> 		if (qstr) {
> 			...
> 			parent_group = hinfo.hash % ngroups;
> 		} else
> 			parent_group = prandom_u32_max(ngroups);

Nice catch. I'll move these to patch #1.


> > diff --git a/fs/ext4/mmp.c b/fs/ext4/mmp.c
> > index 9af68a7ecdcf..588cb09c5291 100644
> > --- a/fs/ext4/mmp.c
> > +++ b/fs/ext4/mmp.c
> > @@ -265,7 +265,7 @@ static unsigned int mmp_new_seq(void)
> >  	u32 new_seq;
> >  
> >  	do {
> > -		new_seq = prandom_u32();
> > +		new_seq = get_random_u32();
> >  	} while (new_seq > EXT4_MMP_SEQ_MAX);
> 
> OK, here we again effectively implement prandom_u32_max(EXT4_MMP_SEQ_MAX + 1).
> Just presumably we didn't want to use modulo here because EXT4_MMP_SEQ_MAX
> is rather big and so the resulting 'new_seq' would be seriously
> non-uniform.

I'm not handling this during this patch set, but if in the course of
review we find enough places that want actually uniformly bounded
integers, I'll implement efficient rejection sampling to clean up these
cases, with something faster and general, and add a new function for it.
So far this is the first case to come up, but we'll probably eventually
find others. So I'll make note of this.

Jason

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/Yz7LCyIAHC6l5mG9%40zx2c4.com.
