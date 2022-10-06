Return-Path: <kasan-dev+bncBD5LDHXSYUMRBNNK7KMQMGQEYIXRPFA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23f.google.com (mail-lj1-x23f.google.com [IPv6:2a00:1450:4864:20::23f])
	by mail.lfdr.de (Postfix) with ESMTPS id B914D5F62F4
	for <lists+kasan-dev@lfdr.de>; Thu,  6 Oct 2022 10:43:34 +0200 (CEST)
Received: by mail-lj1-x23f.google.com with SMTP id v4-20020a2ea444000000b00261e0d5bc25sf460237ljn.19
        for <lists+kasan-dev@lfdr.de>; Thu, 06 Oct 2022 01:43:34 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1665045814; cv=pass;
        d=google.com; s=arc-20160816;
        b=vNdCgGIo7H5vz+BVMXpQFMSRP3o336/XgGgF9vWQlVO1zYN9YudHTI4hcWc4MMZXyJ
         iqJdRETvBfqIaVSmLQ8vjpuJlttlu6Utt733wk8imxut5lb2xae8YcZ4mIduh92cRZPU
         FtyKzHu1XHfv7aNhXjWtrSJnfypm25g6e7WbcRp113tZ2vckN7Cltu/s7u9vMG7syjF5
         4gQyvSwSmtkZdFiYTpcXZgGEagbI7bbNi35r1D/XTyuR/8y+pFdIqelMu4UUPCzVg59J
         5zH876ziZlFR4LX55IaHM07pxtUj34ehe5jsqr0TwDI4u/qybj+/9V6W0mF1aLZphWdT
         eVsA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=3UqaHzvW9eRry1imwEQuFBaQWnLyLFw/KSJDG3G0umM=;
        b=JyyiVvixAkGL1R+JENtB6am3eXeUB57bTX76lxd6WvQt6/UCp1RSUAPXp+An4ABJ4O
         FWfeyuI6QFKQUFi8QyhR0eZF6kZ8APntmhi7cmtZ0NUb4qlewP/7oWcK4g7OvrJy9Fjc
         BLjgYVnEgytQxEjICG2hYs4i7NzXvQhHXCxONvvQEk2/D8vA8g5ySity7wH/Iz/nmsJE
         VoWh4gxFVPt7I3Yc08zaN3/6vTARn5YhQhr2WtMGBpYOqqCQvVU0oyc+dCKbUJqYVG+F
         q+vtLvNwJhjClkF+PMaw1rFBN8cY8G4fhm21SZglh3ILrjgiwK2IB9GF/gpAZ3IcBeyN
         iCYA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=C+mCUjvr;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=softfail (google.com: domain of transitioning jack@suse.cz does not designate 2001:67c:2178:6::1c as permitted sender) smtp.mailfrom=jack@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date;
        bh=3UqaHzvW9eRry1imwEQuFBaQWnLyLFw/KSJDG3G0umM=;
        b=Ctb1pFaNCsm7hjxtEJLEsstubdxV4UECGdmWqoKE3IiFDik0wJcNlcEITY3lWIqnHX
         z/wFAaSdj6oiZmF/He5LYuo/0rssgSo95ce1OV21xgGlAzXUjw+i/a5gsljUjy5KMchp
         iuHP4fPI8rKxKlMnFexmAtBquR/UjNEMAaSaoqqYn8XGVgfJq/FToztGIH2dcE97RwEi
         10wwARS+xeEdbsMyP0TpRjheDqTgc+rljCvI7SqgPUMMy2DgNtkYVcnkyygEiiuIJav6
         sTCRhLwq19Z3mN3CQj53urQew09g5mSTCCslPVgLcFWkZ3zsFqfe5G+g9sOnTC0zYv1T
         p4Ew==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:sender:from:to:cc:subject:date;
        bh=3UqaHzvW9eRry1imwEQuFBaQWnLyLFw/KSJDG3G0umM=;
        b=VUpVgLKQ4W/034Jv0gEKGCNUL01rY6I77qfbVP0pYbB/yBANgkql85BYIUNvkOYWTJ
         y3WE1TZgPAlEsDYvXe5wWu8e5avST7UAp2biCFOZ4txHGYs7Zls0ZCFVOYmwEwknqsg3
         pyYtod+C7O6Riq+oDQzGSJtua6pecZyD7U65ghfQo24febj9TOb2/cXVJ6ZjsHq7qWlu
         T45hWnKJ39QF/g6KOIn9Y9C1L8BrFgz+KsmWw5Wdg8XuV8uOQJeVFaPIRBg7Fv3Omblb
         D2n3SyZEskUrKJtQ2nEBMZvGRZb24k1vhlDz8gvqmMVMh6VnKWE54Iloru1QTuOsmnBx
         KKeQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf2rpbr0RCrLdIuFA7g+U0Vs9a/UUNdr5R4+c+M5hD8UfJf0VTDr
	kzMMbs4cgdMyMDdvvvRQM+k=
X-Google-Smtp-Source: AMsMyM7kdJVCioiJRTC1y8SWp+efQZBEhL6C5M+bJtH2z7YkSFK81B7nMtLWn6uOluv2PjKy99UrgQ==
X-Received: by 2002:a05:651c:101:b0:250:896d:f870 with SMTP id a1-20020a05651c010100b00250896df870mr1408383ljb.235.1665045814076;
        Thu, 06 Oct 2022 01:43:34 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:9097:0:b0:26d:fb4f:eb20 with SMTP id l23-20020a2e9097000000b0026dfb4feb20ls255368ljg.10.-pod-prod-gmail;
 Thu, 06 Oct 2022 01:43:32 -0700 (PDT)
X-Received: by 2002:a05:651c:1a23:b0:26b:fcbf:5c29 with SMTP id by35-20020a05651c1a2300b0026bfcbf5c29mr1245326ljb.307.1665045812853;
        Thu, 06 Oct 2022 01:43:32 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1665045812; cv=none;
        d=google.com; s=arc-20160816;
        b=QIbdrekJTEvXXQuQKBkIskiZLJfhmlEFV4k1BsF52L527vemec0DqKcE4JvkrZWu7E
         GVGwtzNVK3jcnIeWbE9K9z/WyB5esABiil1YKBpcAUEeMgv2X9hAajNCtRko0aDbEvwX
         93DPnrNPogCp7pkfMRQ4cqnid+m6TOoJKlSTcjUlUT93luqzsyWBt8j06TXtpyqAIkPH
         vbgIlAiUkZi7RzKa7zDQe77gu/dusd+KNgHWV9rUZV1WGJJw3sXr2ZOnREVe3A3KUtJM
         1R+NyH3cFC/nroqaEsfyI+Fm5M6nEqjwRG1A367I4/fFXXe1gkANDCUSjHN6NLeqSLjU
         5lgw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature:dkim-signature;
        bh=T7S6oIxhAYkW+alnUKWtP6uIux66B8EsW4GqVBZ8bto=;
        b=x5kayOjACO2WZn+9GmVSXWApL2GqHdTDTCuAr5ZZ48GIvzgdFQIlXAKyGMIKf+MdAV
         /xErkUe0vl0KQFDdblNvjopuJWdvX3LYDBQ6a2q4NW2FLKi2OH2BrrR7zaCAcSzSvIPe
         T+QmTieY+LSebNd6Ejc8pyw4Qk9SHPXcL7iFCAFRYPsxnk+bASN1w6SydIg/+tHfTEHm
         98LYo7epIiZCXzDMFURmkekacEjLLVFxblff1RN/94hMeRj1Ad1+RVTI0gkYUx8yZGbV
         tgVsIPrdwcv27GY1ep3rPcqwxw60g0N556khW7lpjoTz8hL+YSHEsuTJtcUU3XwlsyQw
         9V0A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=C+mCUjvr;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=softfail (google.com: domain of transitioning jack@suse.cz does not designate 2001:67c:2178:6::1c as permitted sender) smtp.mailfrom=jack@suse.cz
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [2001:67c:2178:6::1c])
        by gmr-mx.google.com with ESMTPS id z4-20020a05651c11c400b0026bf7cf2a41si588398ljo.2.2022.10.06.01.43.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 06 Oct 2022 01:43:32 -0700 (PDT)
Received-SPF: softfail (google.com: domain of transitioning jack@suse.cz does not designate 2001:67c:2178:6::1c as permitted sender) client-ip=2001:67c:2178:6::1c;
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id 0596A219D6;
	Thu,  6 Oct 2022 08:43:32 +0000 (UTC)
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by imap2.suse-dmz.suse.de (Postfix) with ESMTPS id D8FAD1376E;
	Thu,  6 Oct 2022 08:43:31 +0000 (UTC)
Received: from dovecot-director2.suse.de ([192.168.254.65])
	by imap2.suse-dmz.suse.de with ESMTPSA
	id 4CR4NDOVPmPNPAAAMHmgww
	(envelope-from <jack@suse.cz>); Thu, 06 Oct 2022 08:43:31 +0000
Received: by quack3.suse.cz (Postfix, from userid 1000)
	id 56F62A0668; Thu,  6 Oct 2022 10:43:31 +0200 (CEST)
Date: Thu, 6 Oct 2022 10:43:31 +0200
From: Jan Kara <jack@suse.cz>
To: "Jason A. Donenfeld" <Jason@zx2c4.com>
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
	Kalle Valo <kvalo@kernel.org>, Kees Cook <keescook@chromium.org>,
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
Subject: Re: [PATCH v1 3/5] treewide: use get_random_u32() when possible
Message-ID: <20221006084331.4bdktc2zlvbaszym@quack3>
References: <20221005214844.2699-1-Jason@zx2c4.com>
 <20221005214844.2699-4-Jason@zx2c4.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20221005214844.2699-4-Jason@zx2c4.com>
X-Original-Sender: jack@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=C+mCUjvr;       dkim=neutral
 (no key) header.i=@suse.cz header.s=susede2_ed25519;       spf=softfail
 (google.com: domain of transitioning jack@suse.cz does not designate
 2001:67c:2178:6::1c as permitted sender) smtp.mailfrom=jack@suse.cz
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

On Wed 05-10-22 23:48:42, Jason A. Donenfeld wrote:
> The prandom_u32() function has been a deprecated inline wrapper around
> get_random_u32() for several releases now, and compiles down to the
> exact same code. Replace the deprecated wrapper with a direct call to
> the real function.
> 
> Signed-off-by: Jason A. Donenfeld <Jason@zx2c4.com>

...

> diff --git a/fs/ext2/ialloc.c b/fs/ext2/ialloc.c
> index 998dd2ac8008..e439a872c398 100644
> --- a/fs/ext2/ialloc.c
> +++ b/fs/ext2/ialloc.c
> @@ -277,7 +277,7 @@ static int find_group_orlov(struct super_block *sb, struct inode *parent)
>  		int best_ndir = inodes_per_group;
>  		int best_group = -1;
>  
> -		group = prandom_u32();
> +		group = get_random_u32();
>  		parent_group = (unsigned)group % ngroups;
>  		for (i = 0; i < ngroups; i++) {
>  			group = (parent_group + i) % ngroups;

The code here is effectively doing the

	parent_group = prandom_u32_max(ngroups);

> diff --git a/fs/ext4/ialloc.c b/fs/ext4/ialloc.c
> index f73e5eb43eae..954ec9736a8d 100644
> --- a/fs/ext4/ialloc.c
> +++ b/fs/ext4/ialloc.c
> @@ -465,7 +465,7 @@ static int find_group_orlov(struct super_block *sb, struct inode *parent,
>  			ext4fs_dirhash(parent, qstr->name, qstr->len, &hinfo);
>  			grp = hinfo.hash;
>  		} else
> -			grp = prandom_u32();
> +			grp = get_random_u32();

Similarly here we can use prandom_u32_max(ngroups) like:

		if (qstr) {
			...
			parent_group = hinfo.hash % ngroups;
		} else
			parent_group = prandom_u32_max(ngroups);

> diff --git a/fs/ext4/mmp.c b/fs/ext4/mmp.c
> index 9af68a7ecdcf..588cb09c5291 100644
> --- a/fs/ext4/mmp.c
> +++ b/fs/ext4/mmp.c
> @@ -265,7 +265,7 @@ static unsigned int mmp_new_seq(void)
>  	u32 new_seq;
>  
>  	do {
> -		new_seq = prandom_u32();
> +		new_seq = get_random_u32();
>  	} while (new_seq > EXT4_MMP_SEQ_MAX);

OK, here we again effectively implement prandom_u32_max(EXT4_MMP_SEQ_MAX + 1).
Just presumably we didn't want to use modulo here because EXT4_MMP_SEQ_MAX
is rather big and so the resulting 'new_seq' would be seriously
non-uniform.

								Honza
-- 
Jan Kara <jack@suse.com>
SUSE Labs, CR

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20221006084331.4bdktc2zlvbaszym%40quack3.
