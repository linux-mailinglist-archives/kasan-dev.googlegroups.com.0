Return-Path: <kasan-dev+bncBCF5XGNWYQBRBLNX7GMQMGQE6EV4ECQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53e.google.com (mail-pg1-x53e.google.com [IPv6:2607:f8b0:4864:20::53e])
	by mail.lfdr.de (Postfix) with ESMTPS id C17C75F6033
	for <lists+kasan-dev@lfdr.de>; Thu,  6 Oct 2022 06:38:07 +0200 (CEST)
Received: by mail-pg1-x53e.google.com with SMTP id s68-20020a632c47000000b00434e0e75076sf485753pgs.7
        for <lists+kasan-dev@lfdr.de>; Wed, 05 Oct 2022 21:38:07 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1665031086; cv=pass;
        d=google.com; s=arc-20160816;
        b=h2iJwZHJCfJ/ULurW8RtFP4KB5Ko4yMAQK8wO2IY509zWNkFvSfTcyjOYaAwGTl5UC
         qy56Wb2JI7jq4fp4cImLhUj+p6FKZkDi6s9u5QOWj4xOFeQLOGt0Xk3IuZtjRjdzhJMY
         HYC22iKCn5iasIXbRQH2s/Jz6v0FtcKvvsmpGW5KCuJeOZ1rOqh+5iroLlbLnpyDacda
         KgGBSSPxUhHfGNSoqObxTkDnOWaOeAcymo4nj3CziT0YYI4zkLnGMs835XK6I9Y0Ggr9
         MLEZOIOZe80lbyTvytElC6vjn4+7oWkvcnygpBw8NRcWQVYbFsK9gtO6lnJbHVklUGzI
         eGrw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=YBtRLI6NmRX2euQ+g3B76zHYcHZixsnWvicNO5n7pBA=;
        b=YLjul2DUkNrGZDnN9+SWb5CDm0kiLT1EH3ISTFsDtvIymSVjjsizt81yCbj31R6178
         LbtHiKONiy1G2lAfwr23mGXh5qXA1TSDW8cmD1z+7+AQ7M/muqX+7OmzbB5IZwJ995ad
         MqJ/ZEdDGYPtzZDATa1xlAQ7RU0VWpK/LZA6BgYetsCzX/Bj85LxNeuaSHmANXazAksf
         kYJQtEfccck+aMhaxnmlgNWxHj+hIAcsxpmGBeY6RIrtGYZ9duzQ5xnV60IdEGQqB00V
         eKHzLzIXBpC9Vc8xMTVNgxYjoA+a9QpYDHHEGY4wxKjEGz9s6yO8seUGVYV+2e4oLpy5
         HqnA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=FnhfzhzY;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::62d as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date;
        bh=YBtRLI6NmRX2euQ+g3B76zHYcHZixsnWvicNO5n7pBA=;
        b=X/psIjYNy7kegQzEqEK+DZqXrACN4cGu3BcSo5DZ4MDmaXAC9nTdwEN8kZ+zGN+5+x
         ECBOHWvCxUxg+0xTOw+lzO7bSH5tzgjM7USD7K/E9fQp/i1dP5rsaIJxOf2j1ERIy6Bk
         8jbmPM2I7XpOxGtojMuE6h5uBRzlxxKaWQTV589ntEuSeir11C8W000i7g11L+vjNNpI
         GROKNTH4z3Zw/yTdK9y2iqwABu9L0keks7h6Xz2uxn8VEXR2I/ApRXJ63sJWz8HBrILr
         QRrgxMUA30X67VxLOpUshC61UX2IGeIyBN8lUpP5g9ay1qC365hPkhoWsVfGmA0UOW0a
         lWgQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:sender:from:to:cc:subject:date;
        bh=YBtRLI6NmRX2euQ+g3B76zHYcHZixsnWvicNO5n7pBA=;
        b=HQqlQnp3QF5aUbqMIlDjQQ79hMjvGNu/8FuXbm9TftzHPz2BdYjTpF6h1+bIP+5NhK
         E39HPHScsoL7vlYLR6vFiX8UpSIEi82H1xkgLghKskE1Xk9ijwXmPNJIOgY3Okjx3rER
         VKgL1fV47kE2CqwAZldQsrrSHr2FbYGAs4JgiBKHr9TYgtLjdvIi2FGTNXpt+B6rD91e
         i+nGlmnULH9+riJ2NIBRQJvIyomskAqi/n0wV+JHTK6Xy2lyadTLWcKXWIMWHz1gdY5c
         D1e4dSwoyXa61sHjOS+Jsk40o7ERcaR+EpjrfUFIDZHQEFviA5+gOaknoWe5K7ExDEXH
         Hs4g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf3Vh2c0BZZeqDyGP0aRcFyrCZLOpTxrAcqU8VhJ0QtuSngY1+el
	vZuwKxr2/FWzljZnrgutaFM=
X-Google-Smtp-Source: AMsMyM47VbW30Yb6rJJqHfQ3juDTwfVUls8DBqvUVeTvb7WhrrpdWHY2B4xv/XeEcZk2FVdu6Mx3MQ==
X-Received: by 2002:a63:2:0:b0:42f:6169:f396 with SMTP id 2-20020a630002000000b0042f6169f396mr2804690pga.249.1665031086021;
        Wed, 05 Oct 2022 21:38:06 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:2ec5:b0:205:ed57:7e7c with SMTP id
 h5-20020a17090a2ec500b00205ed577e7cls756056pjs.2.-pod-control-gmail; Wed, 05
 Oct 2022 21:38:05 -0700 (PDT)
X-Received: by 2002:a17:902:70c4:b0:17c:f9fe:3200 with SMTP id l4-20020a17090270c400b0017cf9fe3200mr2835364plt.1.1665031085306;
        Wed, 05 Oct 2022 21:38:05 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1665031085; cv=none;
        d=google.com; s=arc-20160816;
        b=UtDv7zMSOJ9zGmnY7w/WAjPEgAH9q3quaL1UxR8k8WJsJ8Z/SsCGEXEj45im7kB4Nz
         8I8jmruAnGRlNfwTR6UVojYfPb7LLGRixt3CCTXUzjxuRQXSfI4uXOV+iZ3qKTECqrdo
         KovFtahY7cM3ZBD9nr0K/54ggkPApOV9x1/WmEfupL/tlmbfLwzgDJgFtrZ7jZyn25dV
         6ToFp6ri5jpI2Rsnv3im1PGb+N20ElrhHtu+J8k8rItR9k+ANJFlM9eReRtUhApLz06P
         yY5eiX0agSUuBWuuM76SQVHZX50C91zTjRHl6GoZylxHGB2lXzLK+z2FMDjvDX5k1CZA
         Li6w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=+S5GQGZ6/D/Mg+joUObE0SvwDFyqkvRT2sP5/5vRQvk=;
        b=uz1oWX0gUU+deO80TWtQ8/oPWUUfCtYOJWi9G7deYFTOR0IhlRrfn9wudBzBUNWjBy
         tc23cNE6g8bfwou+4Wsm5o45lil4uWzi4kdaXfW9ZGmUODpgt5Y5UpozUvxihz//k14C
         TFNJUOQD/zstS7LsmdAiKUYexanLyZRDFdentsEr7Q7X7lbcvXW0kOV40RETvk9fxAcT
         YfKDhl9rCsEGoFI7/I9Fxm1epUeuDEXBrguidWRwFbrIHbjeGOh1Z7bkYnwXcvCOI04Q
         oS8BbvfcxCOBbOR1d06CX0pq1sCdgFJrne1ZlMzSnp+sOqWaUaa0ugKrAPSDJzgDYPst
         /CzQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=FnhfzhzY;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::62d as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Received: from mail-pl1-x62d.google.com (mail-pl1-x62d.google.com. [2607:f8b0:4864:20::62d])
        by gmr-mx.google.com with ESMTPS id x10-20020a056a000bca00b00543762c333dsi814056pfu.1.2022.10.05.21.38.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 05 Oct 2022 21:38:05 -0700 (PDT)
Received-SPF: pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::62d as permitted sender) client-ip=2607:f8b0:4864:20::62d;
Received: by mail-pl1-x62d.google.com with SMTP id x6so640741pll.11
        for <kasan-dev@googlegroups.com>; Wed, 05 Oct 2022 21:38:05 -0700 (PDT)
X-Received: by 2002:a17:90b:3a85:b0:203:2044:c26 with SMTP id om5-20020a17090b3a8500b0020320440c26mr3224861pjb.109.1665031084920;
        Wed, 05 Oct 2022 21:38:04 -0700 (PDT)
Received: from www.outflux.net (smtp.outflux.net. [198.145.64.163])
        by smtp.gmail.com with ESMTPSA id i65-20020a626d44000000b0055f1db26b3csm9683731pfc.37.2022.10.05.21.38.03
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 05 Oct 2022 21:38:03 -0700 (PDT)
Date: Wed, 5 Oct 2022 21:38:02 -0700
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
Subject: Re: [PATCH v1 2/5] treewide: use get_random_{u8,u16}() when possible
Message-ID: <202210052126.B34A2C62@keescook>
References: <20221005214844.2699-1-Jason@zx2c4.com>
 <20221005214844.2699-3-Jason@zx2c4.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20221005214844.2699-3-Jason@zx2c4.com>
X-Original-Sender: keescook@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=FnhfzhzY;       spf=pass
 (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::62d
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

On Wed, Oct 05, 2022 at 11:48:41PM +0200, Jason A. Donenfeld wrote:
> Rather than truncate a 32-bit value to a 16-bit value or an 8-bit value,
> simply use the get_random_{u8,u16}() functions, which are faster than
> wasting the additional bytes from a 32-bit value.
> 
> Signed-off-by: Jason A. Donenfeld <Jason@zx2c4.com>

Same question about "mechanism of transformation".

> diff --git a/drivers/net/ethernet/chelsio/inline_crypto/chtls/chtls_cm.c b/drivers/net/ethernet/chelsio/inline_crypto/chtls/chtls_cm.c
> index ddfe9208529a..ac452a0111a9 100644
> --- a/drivers/net/ethernet/chelsio/inline_crypto/chtls/chtls_cm.c
> +++ b/drivers/net/ethernet/chelsio/inline_crypto/chtls/chtls_cm.c
> @@ -1467,7 +1467,7 @@ static void make_established(struct sock *sk, u32 snd_isn, unsigned int opt)
>  	tp->write_seq = snd_isn;
>  	tp->snd_nxt = snd_isn;
>  	tp->snd_una = snd_isn;
> -	inet_sk(sk)->inet_id = prandom_u32();
> +	inet_sk(sk)->inet_id = get_random_u16();
>  	assign_rxopt(sk, opt);
>  
>  	if (tp->rcv_wnd > (RCV_BUFSIZ_M << 10))

This one I had to go look at -- inet_id is u16, so yeah. :)

> diff --git a/lib/test_vmalloc.c b/lib/test_vmalloc.c
> index 56ffaa8dd3f6..0131ed2cd1bd 100644
> --- a/lib/test_vmalloc.c
> +++ b/lib/test_vmalloc.c
> @@ -80,7 +80,7 @@ static int random_size_align_alloc_test(void)
>  	int i;
>  
>  	for (i = 0; i < test_loop_count; i++) {
> -		rnd = prandom_u32();
> +		rnd = get_random_u8();
>  
>  		/*
>  		 * Maximum 1024 pages, if PAGE_SIZE is 4096.

This wasn't obvious either, but it looks like it's because it never
consumes more than u8?

> diff --git a/net/netfilter/nf_nat_core.c b/net/netfilter/nf_nat_core.c
> index 7981be526f26..57c7686ac485 100644
> --- a/net/netfilter/nf_nat_core.c
> +++ b/net/netfilter/nf_nat_core.c
> @@ -468,7 +468,7 @@ static void nf_nat_l4proto_unique_tuple(struct nf_conntrack_tuple *tuple,
>  	if (range->flags & NF_NAT_RANGE_PROTO_OFFSET)
>  		off = (ntohs(*keyptr) - ntohs(range->base_proto.all));
>  	else
> -		off = prandom_u32();
> +		off = get_random_u16();
>  
>  	attempts = range_size;

Yup, u16 off;

> diff --git a/net/sched/sch_sfb.c b/net/sched/sch_sfb.c
> index 2829455211f8..7eb70acb4d58 100644
> --- a/net/sched/sch_sfb.c
> +++ b/net/sched/sch_sfb.c
> @@ -379,7 +379,7 @@ static int sfb_enqueue(struct sk_buff *skb, struct Qdisc *sch,
>  		goto enqueue;
>  	}
>  
> -	r = prandom_u32() & SFB_MAX_PROB;
> +	r = get_random_u16() & SFB_MAX_PROB;
>  
>  	if (unlikely(r < p_min)) {
>  		if (unlikely(p_min > SFB_MAX_PROB / 2)) {

include/uapi/linux/pkt_sched.h:#define SFB_MAX_PROB 0xFFFF

Reviewed-by: Kees Cook <keescook@chromium.org>

-- 
Kees Cook

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/202210052126.B34A2C62%40keescook.
