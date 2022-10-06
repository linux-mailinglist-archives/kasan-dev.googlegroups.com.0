Return-Path: <kasan-dev+bncBCF5XGNWYQBRBNNN7GMQMGQEUIP6SHQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3a.google.com (mail-io1-xd3a.google.com [IPv6:2607:f8b0:4864:20::d3a])
	by mail.lfdr.de (Postfix) with ESMTPS id C48275F5FF9
	for <lists+kasan-dev@lfdr.de>; Thu,  6 Oct 2022 06:16:54 +0200 (CEST)
Received: by mail-io1-xd3a.google.com with SMTP id a21-20020a5d89d5000000b006b97a46422esf401359iot.5
        for <lists+kasan-dev@lfdr.de>; Wed, 05 Oct 2022 21:16:54 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1665029813; cv=pass;
        d=google.com; s=arc-20160816;
        b=hR2VWnIXmyhbeYLnzrmdrkoifwJrMF/x+cZ86YK6dEWR9nVg/+hc8ok7deHu4TYDo/
         tUHBbEu6kzrwm0e7G3db7xA5v5jnEXMZpnTFtupSuxGC6q72vI8VcBndNZq0yHpsd861
         iM50Vf1ZtTnyCb+C3EwoHWXqjxQTPTalW5dSfShgJSkhTB6ISw5qnrdFNE8NjUqgm3Ij
         +2yYkkhEEP5MG7g0bpu8ZRLlotuflQGlFq9U2X4YuCmdpwvg0H7wb7W8H7pgGCU2Xc/W
         AAFI6GG3I7GoGP1Azhu2urB1n3NSeG04vrT+/xIyLV/LVlK1n0r9hu+PEUpQTeI2Co4h
         dY3Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=pxHT6BmxY7f1fTFHTbM09vBwGSuoCiupDKomqcY3udk=;
        b=eyam6rLYEU1HHIsZ3JL8ZJUMlsUS/unJqZU6OApbl01afHhvOmdz5LNQOk2xbYJuHt
         uLncLgyYMgw2WVV3OkzlPgX763hS/iG1A2SG093CTuFXKo8LHkDpMYSPt1k07dBRZqzg
         g9nZTqWHGPt7YIvUhI/7FFEdnO2AzjSfulM6tnh8Njwmp6pmyUQSerIJg4AWGYsmBREi
         KKpADmTbmRh4lL76SKBKuRXzVu1D6Gdf3LJ8A/uONemumUyDzUGRFieAvzrBo2tlq51m
         oVtQXliSJRuBe9Nno43zAPsliwg7piRNH9lFdpotlpd2sqBrbm99BxFkboqZarEDVu/Q
         OsMQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=WgCBVOxT;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::629 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date;
        bh=pxHT6BmxY7f1fTFHTbM09vBwGSuoCiupDKomqcY3udk=;
        b=CL57yb2p83dWDiWiT323HutYWvPgP42pgSOtfSoLdhTEOMOpaANG+eaMUS21nH2ef8
         sWLGsg7MGyFsaMNRQxdQQelLvJN17UDSFL7AtZu/Vrf5wbPSb5ERk2cUEzHRRzTUAzDZ
         6xqhQJcWrMonUwIYmDtTRxqXtphnnEKYG47N4oqiF5PbrpYqx44gQm541ogOH9sf0Z2M
         VnhuwleWb8G0yqNxmhqsWYVt4QIcVyLeIubnQMrBFb4qywU/dwXzilV5mB3aE974ZyA8
         twfkWDP49Cf6KrX93kOILiaHMnthIvAfuB3DkkF2wHkJZGaOzdr+oEqWLk4sMr5mh/ZB
         Hf/Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:sender:from:to:cc:subject:date;
        bh=pxHT6BmxY7f1fTFHTbM09vBwGSuoCiupDKomqcY3udk=;
        b=jvHE9Z92p20YrReJ1cZdUngGioJyWk+FWNjisIjETQPUH0AT7yZxUAWBWY011dpOUd
         e+U/R8Ljh9L/iHACRyP/mbFL0gGvYphDAwYE62AKU9JnIB89oGaKDBJ1F7FqPdGI8xYE
         8mFaU0L3uEaaZrzwBoN+UtNtN++rk24aGct/ozUDieSmW9+PX4hq5DTUtYcUJDePauNL
         PXgf2QFLQxaMpLwcSJbcQoY/c3+hhiXj2ghYIWPl3j7oW+bYhnPY1C44sK47G8YFvTgc
         pLq3fcryE2cTxTUBZoAVxYQ8VTCIaXUy6EgvlcoNwbgIQ3RdsxTloOAQSI/6WrO1pjey
         J0rg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf3bQElL0vHBCYZVzZzEyAj/BJERVDYnttyTKxJHk77O2zpmHp2r
	Khv6rK8qKMOv2VQ5G6sz+8s=
X-Google-Smtp-Source: AMsMyM54cTaaq7Bvwv0UX0c9MnSW8iWIDFqRNMAPLmhX03sD4xU8rUlE3f/o8VzgP0GFBWsSRTB6mA==
X-Received: by 2002:a05:6602:2b94:b0:6a4:7b57:ecfb with SMTP id r20-20020a0566022b9400b006a47b57ecfbmr1440600iov.8.1665029813334;
        Wed, 05 Oct 2022 21:16:53 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6638:cc3:b0:358:3c05:7ea9 with SMTP id
 e3-20020a0566380cc300b003583c057ea9ls164251jak.3.-pod-prod-gmail; Wed, 05 Oct
 2022 21:16:52 -0700 (PDT)
X-Received: by 2002:a02:cbb4:0:b0:362:a0b8:3efe with SMTP id v20-20020a02cbb4000000b00362a0b83efemr1489318jap.88.1665029812765;
        Wed, 05 Oct 2022 21:16:52 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1665029812; cv=none;
        d=google.com; s=arc-20160816;
        b=kRFb0K18jtx0DeLts7XeIUU9foIelNdxqlGJ777LHxi2N60/7p7pZAPDNLr74CdzA/
         zjCanTvKJZabRiCtkPz8q7pmwpEzJpeX4558Mm5IgLlLqEkR6sWFnCPayvlghfT3mUlP
         CJnizKLhWcvVdQdhbW1A9//cKCSTypn6bpSnHgLmyfKQOeDO+KP0lBQhQ0EVnqG0BDaQ
         1m0AIyozNg/y6TV7Ko2hMVU31lmjWzOzTE3FBkjLTVebxZKHDvYQg8sQQoobcHOlony2
         iZfONNhikI1r+hz18PILEh0QXE14iEUe/Lv1/iwnK3K7t72CbTuRRFuRKCAogUSF7WSt
         uedg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=WbAjddv7dJAWgX74vxMdFtfHq8KnIvmUd6IHydPVZWw=;
        b=jhyz/54344YiYQoJOgL8k+qCYCY58wOe7279eOH0GPFo46rkHjkfnaWxY3gWCZMjmK
         juI5+Z5cRm3oKBaNe0wP1ZIl4B77ffVIbX0G+Do/Z+xXfLJq2H4gVtoNnLfYczeYTZlU
         bwnSVbdaB+Zasxr31D8Nx/+Avap8ew6y/BtsfLS1H2RZc1ZQVJBUIckvGG/7Zl5T3SYg
         udoBgzDDv9WCF09fJ2oG3iWUsY54ZGcdWgWXim5DSeSNYV9Ke/3mwgMuALxc+/pn/5En
         +D97YJnMJejKyuej1QMCEJyN5BpraIZgW+peu+yWlDR8EYdO0zySRPIqv7k31PduDT1l
         Ck4Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=WgCBVOxT;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::629 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Received: from mail-pl1-x629.google.com (mail-pl1-x629.google.com. [2607:f8b0:4864:20::629])
        by gmr-mx.google.com with ESMTPS id z6-20020a056e02088600b002e8ece90ea6si785850ils.1.2022.10.05.21.16.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 05 Oct 2022 21:16:52 -0700 (PDT)
Received-SPF: pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::629 as permitted sender) client-ip=2607:f8b0:4864:20::629;
Received: by mail-pl1-x629.google.com with SMTP id u24so603974plq.12
        for <kasan-dev@googlegroups.com>; Wed, 05 Oct 2022 21:16:52 -0700 (PDT)
X-Received: by 2002:a17:902:e5c3:b0:178:192c:6b3b with SMTP id u3-20020a170902e5c300b00178192c6b3bmr2833394plf.92.1665029812350;
        Wed, 05 Oct 2022 21:16:52 -0700 (PDT)
Received: from www.outflux.net (smtp.outflux.net. [198.145.64.163])
        by smtp.gmail.com with ESMTPSA id z17-20020aa79911000000b0056242774037sm1822393pff.194.2022.10.05.21.16.51
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 05 Oct 2022 21:16:51 -0700 (PDT)
Date: Wed, 5 Oct 2022 21:16:50 -0700
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
Subject: Re: [PATCH v1 1/5] treewide: use prandom_u32_max() when possible
Message-ID: <202210052035.A1020E3@keescook>
References: <20221005214844.2699-1-Jason@zx2c4.com>
 <20221005214844.2699-2-Jason@zx2c4.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20221005214844.2699-2-Jason@zx2c4.com>
X-Original-Sender: keescook@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=WgCBVOxT;       spf=pass
 (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::629
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

On Wed, Oct 05, 2022 at 11:48:40PM +0200, Jason A. Donenfeld wrote:
> Rather than incurring a division or requesting too many random bytes for
> the given range, use the prandom_u32_max() function, which only takes
> the minimum required bytes from the RNG and avoids divisions.

Yes please!

Since this is a treewide patch, it's helpful for (me at least) doing
reviews to detail the mechanism of the transformation.

e.g. I imagine this could be done with something like Coccinelle and

@no_modulo@
expression E;
@@

-	(prandom_u32() % (E))
+	prandom_u32_max(E)

> diff --git a/drivers/mtd/ubi/debug.h b/drivers/mtd/ubi/debug.h
> index 118248a5d7d4..4236c799a47c 100644
> --- a/drivers/mtd/ubi/debug.h
> +++ b/drivers/mtd/ubi/debug.h
> @@ -73,7 +73,7 @@ static inline int ubi_dbg_is_bgt_disabled(const struct ubi_device *ubi)
>  static inline int ubi_dbg_is_bitflip(const struct ubi_device *ubi)
>  {
>  	if (ubi->dbg.emulate_bitflips)
> -		return !(prandom_u32() % 200);
> +		return !(prandom_u32_max(200));
>  	return 0;
>  }
>  

Because some looks automated (why the parens?)

> @@ -393,14 +387,11 @@ static struct test_driver {
>  
>  static void shuffle_array(int *arr, int n)
>  {
> -	unsigned int rnd;
>  	int i, j;
>  
>  	for (i = n - 1; i > 0; i--)  {
> -		rnd = prandom_u32();
> -
>  		/* Cut the range. */
> -		j = rnd % i;
> +		j = prandom_u32_max(i);
>  
>  		/* Swap indexes. */
>  		swap(arr[i], arr[j]);

And some by hand. :)

Reviewed-by: Kees Cook <keescook@chromium.org>

-- 
Kees Cook

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/202210052035.A1020E3%40keescook.
