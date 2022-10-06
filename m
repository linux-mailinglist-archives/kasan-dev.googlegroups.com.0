Return-Path: <kasan-dev+bncBCF5XGNWYQBRBUV77GMQMGQEXTZBZOI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3d.google.com (mail-qv1-xf3d.google.com [IPv6:2607:f8b0:4864:20::f3d])
	by mail.lfdr.de (Postfix) with ESMTPS id EC9155F6057
	for <lists+kasan-dev@lfdr.de>; Thu,  6 Oct 2022 06:55:47 +0200 (CEST)
Received: by mail-qv1-xf3d.google.com with SMTP id dn14-20020a056214094e00b004b1a231394esf464484qvb.13
        for <lists+kasan-dev@lfdr.de>; Wed, 05 Oct 2022 21:55:47 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1665032146; cv=pass;
        d=google.com; s=arc-20160816;
        b=o37SRrvwrG9t3+NBMfW+32AUHZCIFGI8TDeQZUe8TzNzRdUDxJy+sHf2KVVGYS51eH
         oNAZ0zUBjLH6faxV7RpNdjBIMbNzSUsTlTkbLz4WJu00jxBUlOpfgNCdHv0NEfARPo59
         LmuEwXobSRGfFCeuooJ7jQaclpkDU8UA5M/dJkYUfHzCBLSjTIVXf0F9OJQSK9xPMyCj
         JVAGt0dHd7KqE0A6fusI72sm+L/D1ZQvYdFug3pKpTNf0Iwi2HOLypESuMqbqcN4nr3U
         q8lXu+pQcoXoSrVFl3OSYnzRCccws1op0P10esrzVe/5waV/s2pEztcYOpuzdfFIbCGB
         vSLg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=/0JimkujQuEa0YDTLtnV8Xa4epbN4SWvlaaj6c+tdKw=;
        b=JmjTKfu0tpqUYyi5hVg1y33x7TD8DJNM+ps5v356EeJcmzOirMP647HYaggj0L3Ybq
         0hXCiqUGXqeJiPWX0GCE9BGKf3mBaUEesMmk1h22OZDhLUnMJsd4ho1bEGCCkrR3Xh/4
         BNZh0pdmtE+yUtHngvx6+3wycLEpBSoKsgqigU9wnl1MNZhsYCojjtkS6PgE2kTK/68p
         yZD2TO+Tfrlexrg/H2z8TeEICUNfUFSROqyRjTROVL1pp+HSCAGVB8tzfyfooRMMMaDg
         b7mQUREPsLMJf46Bu91XqiDWxkoJKcRh6cHQwh1fZj4XpBVPLyZcKH8/m5jqbzk427bd
         bqdw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=e0wWc8f7;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::536 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-transfer-encoding
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:from:to:cc:subject:date;
        bh=/0JimkujQuEa0YDTLtnV8Xa4epbN4SWvlaaj6c+tdKw=;
        b=CZkIZpP2lh30KB5IA8i5wvefnvXYTovqJ4V3BvIsnQ1gDdGIbDMiHAtQ/OsrJU318M
         Rk5WLxJUvQI3cb3YWu41fH+aI1zxgtjZIkBjvgbevYByyvjMUTjuTlwWkbqIdLUEtbvM
         95IFUG7z0IU5B+PYqtEqHS5OrdDatgdkAh47tS118iy8gX5BaRQHAtiHkpr1sgUq2XO5
         R8x+t0ipxq2I52wuTU5eMR0IxvWHdub9Rb/9fqtcdyLaaViF1uM9M49wVb3gq7sYbtGW
         9TDgVc1SLcQ+suQoK+RAjev2nKuYnRwj0qAQpabvi0wYouYlqm4KPKaNz7Xkco0bOryW
         xp7g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:x-gm-message-state
         :sender:from:to:cc:subject:date;
        bh=/0JimkujQuEa0YDTLtnV8Xa4epbN4SWvlaaj6c+tdKw=;
        b=jf7HkUv6j28yRxNwbMU8wgOkO3FT9UgYQFY9BI3XuPlX5/0NOmKA6YILAr93gNNpv7
         GOOmriR3njqKcW0S5oC49UN009arM9BJPh6AIuf1S3M0SDdGVRxysXYS5lyE5M6VuWih
         oFtIKHITL8pFjqR1L3PvAEkJp+g3l/z5dyuyQGWXFJldh8zl7JcLTtkID1jIF6IeIsDl
         WZJ+Ja7wRSIHvJtLTi7lNhTpUGWYMfTXKXzdk5xWXluEftTio70T+AmwbEQs6B8+9odv
         IIlUOoDbsnmjC7xiJ+Z2qMroL9UMTYsxjNNalRWEeshuCtAfDhqpmqBBAMSBmszlh9oZ
         DVfg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf3EuUtHe+Gs6d9+PkeLBDeG6y6C9ojUx1gQXUjpD8vAkD9d3mag
	TYa1/7VPLqjsx8833Zb3yvQ=
X-Google-Smtp-Source: AMsMyM677VEylFOTeljjUx5i+ieDlXlYu7wHMGncFRG3JwXJX2eaDKUlNUVhdW62d/OOLDKqR3QzUg==
X-Received: by 2002:ae9:e401:0:b0:6e5:291d:4073 with SMTP id q1-20020ae9e401000000b006e5291d4073mr1336671qkc.635.1665032146591;
        Wed, 05 Oct 2022 21:55:46 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:622a:1b9e:b0:35b:b0fa:af8b with SMTP id
 bp30-20020a05622a1b9e00b0035bb0faaf8bls516974qtb.8.-pod-prod-gmail; Wed, 05
 Oct 2022 21:55:46 -0700 (PDT)
X-Received: by 2002:ac8:5705:0:b0:35c:d722:175d with SMTP id 5-20020ac85705000000b0035cd722175dmr2086583qtw.192.1665032146057;
        Wed, 05 Oct 2022 21:55:46 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1665032146; cv=none;
        d=google.com; s=arc-20160816;
        b=WlAH1LErX/VgPU53SyJaC3UpN2gt6Ubk8nkdKt8ni56HpZ3US0En/BpchRIBnzpve1
         rhIsUNrENesp5drp669uOC9ONujvNnium2VerZv3v2eJQw7vfSdh/nOLjs4ruuiWUVS4
         oWk7D85wRA9P5J8sCcVA0P4jcw2qv8tEY2H47Hjuj9NY1PWZ5O3ufJ80oqydktO/krIe
         2jU7dhKHbqwVPcNEbF1NLwglOfe4Q3dfYoZs9nfO2o60Jz1PSrw0sGFoZtgdY7A9Gu/l
         fx9pIoizBC2T+CW32Vv5NGVQueojOf/NiZc5Uqm83Ti/VgfGDuIiMtzupp9n/Hx+A6mP
         foyg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=51dSYIsgEywaJmdEPyI7vbp82hVQfJ6jQKHayIqsWH8=;
        b=W29YJTjS6aW30yUKtBEucMRyJmI5JNQxe3OddgG0+LIXT3peEdgF06WVBUjz/VCrZ9
         5CzBJIvgFwkh65wuvaIpR5/Wba+LLucHIq6Pl35HdyWUrGiVgG5SMilEwIhJ0M9svcvv
         whFLFTanrzKUEVwjs8v5OQ7reB77ByDzXB0BwDv5tdtqen2sLl5dShlxvb01Muac+GUc
         260xTyw1gDoNS+CzxxXFplnAIZbW8sy3Cv4tnOgc7hse2zjr+gFwJ69b3E2myD3klllW
         7aErO3azezIyqrryK11cisgbW/DhtHl4lEbrnRnpmHtMlqnb6J4Y8rdF25hPUgfioy3G
         aXsQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=e0wWc8f7;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::536 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Received: from mail-pg1-x536.google.com (mail-pg1-x536.google.com. [2607:f8b0:4864:20::536])
        by gmr-mx.google.com with ESMTPS id y22-20020a05620a25d600b006cec0e4b3f0si1018231qko.1.2022.10.05.21.55.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 05 Oct 2022 21:55:46 -0700 (PDT)
Received-SPF: pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::536 as permitted sender) client-ip=2607:f8b0:4864:20::536;
Received: by mail-pg1-x536.google.com with SMTP id e129so850325pgc.9
        for <kasan-dev@googlegroups.com>; Wed, 05 Oct 2022 21:55:46 -0700 (PDT)
X-Received: by 2002:a63:1508:0:b0:438:eb90:52d1 with SMTP id v8-20020a631508000000b00438eb9052d1mr2937734pgl.252.1665032145585;
        Wed, 05 Oct 2022 21:55:45 -0700 (PDT)
Received: from www.outflux.net (smtp.outflux.net. [198.145.64.163])
        by smtp.gmail.com with ESMTPSA id r17-20020a635d11000000b00459a36795cbsm679773pgb.42.2022.10.05.21.55.44
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 05 Oct 2022 21:55:44 -0700 (PDT)
Date: Wed, 5 Oct 2022 21:55:43 -0700
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
Message-ID: <202210052148.B11CBC60@keescook>
References: <20221005214844.2699-1-Jason@zx2c4.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <20221005214844.2699-1-Jason@zx2c4.com>
X-Original-Sender: keescook@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=e0wWc8f7;       spf=pass
 (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::536
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

On Wed, Oct 05, 2022 at 11:48:39PM +0200, Jason A. Donenfeld wrote:
> Hi folks,
>=20
> This is a five part treewide cleanup of random integer handling. The
> rules for random integers are:
>=20
> - If you want a secure or an insecure random u64, use get_random_u64().
> - If you want a secure or an insecure random u32, use get_random_u32().
>   * The old function prandom_u32() has been deprecated for a while now
>     and is just a wrapper around get_random_u32().
> - If you want a secure or an insecure random u16, use get_random_u16().
> - If you want a secure or an insecure random u8, use get_random_u8().
> - If you want secure or insecure random bytes, use get_random_bytes().
>   * The old function prandom_bytes() has been deprecated for a while now
>     and has long been a wrapper around get_random_bytes().
> - If you want a non-uniform random u32, u16, or u8 bounded by a certain
>   open interval maximum, use prandom_u32_max().
>   * I say "non-uniform", because it doesn't do any rejection sampling or
>     divisions. Hence, it stays within the prandom_* namespace.
>=20
> These rules ought to be applied uniformly, so that we can clean up the
> deprecated functions, and earn the benefits of using the modern
> functions. In particular, in addition to the boring substitutions, this
> patchset accomplishes a few nice effects:
>=20
> - By using prandom_u32_max() with an upper-bound that the compiler can
>   prove at compile-time is =E2=89=A465536 or =E2=89=A4256, internally get=
_random_u16()
>   or get_random_u8() is used, which wastes fewer batched random bytes,
>   and hence has higher throughput.
>=20
> - By using prandom_u32_max() instead of %, when the upper-bound is not a
>   constant, division is still avoided, because prandom_u32_max() uses
>   a faster multiplication-based trick instead.
>=20
> - By using get_random_u16() or get_random_u8() in cases where the return
>   value is intended to indeed be a u16 or a u8, we waste fewer batched
>   random bytes, and hence have higher throughput.
>=20
> So, based on those rules and benefits from following them, this patchset
> breaks down into the following five steps:
>=20
> 1) Replace `prandom_u32() % max` and variants thereof with
>    prandom_u32_max(max).
>=20
> 2) Replace `(type)get_random_u32()` and variants thereof with
>    get_random_u16() or get_random_u8(). I took the pains to actually
>    look and see what every lvalue type was across the entire tree.
>=20
> 3) Replace remaining deprecated uses of prandom_u32() with
>    get_random_u32().=20
>=20
> 4) Replace remaining deprecated uses of prandom_bytes() with
>    get_random_bytes().
>=20
> 5) Remove the deprecated and now-unused prandom_u32() and
>    prandom_bytes() inline wrapper functions.
>=20
> I was thinking of taking this through my random.git tree (on which this
> series is currently based) and submitting it near the end of the merge
> window, or waiting for the very end of the 6.1 cycle when there will be
> the fewest new patches brewing. If somebody with some treewide-cleanup
> experience might share some wisdom about what the best timing usually
> winds up being, I'm all ears.

It'd be nice to capture some (all?) of the above somewhere. Perhaps just
a massive comment in the header?

> I've CC'd get_maintainers.pl, which is a pretty big list. Probably some
> portion of those are going to bounce, too, and everytime you reply to
> this thread, you'll have to deal with a bunch of bounces coming
> immediately after. And a recipient list this big will probably dock my
> email domain's spam reputation, at least temporarily. Sigh. I think
> that's just how it goes with treewide cleanups though. Again, let me
> know if I'm doing it wrong.

I usually stick to just mailing lists and subsystem maintainers.

If any of the subsystems ask you to break this up (I hope not), I've got
this[1], which does a reasonable job of splitting a commit up into
separate commits for each matching subsystem.

Showing that a treewide change can be reproduced mechanically helps with
keeping it together as one bit treewide patch, too, I've found. :)

Thank you for the cleanup! The "u8 rnd =3D get_random_u32()" in the tree
has bothered me for a loooong time.

-Kees

--=20
Kees Cook

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/202210052148.B11CBC60%40keescook.
