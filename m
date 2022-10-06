Return-Path: <kasan-dev+bncBCF5XGNWYQBRB3FX7GMQMGQE4AYYQAA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1037.google.com (mail-pj1-x1037.google.com [IPv6:2607:f8b0:4864:20::1037])
	by mail.lfdr.de (Postfix) with ESMTPS id ED61B5F6035
	for <lists+kasan-dev@lfdr.de>; Thu,  6 Oct 2022 06:39:09 +0200 (CEST)
Received: by mail-pj1-x1037.google.com with SMTP id pj13-20020a17090b4f4d00b0020b0a13cba4sf336483pjb.0
        for <lists+kasan-dev@lfdr.de>; Wed, 05 Oct 2022 21:39:09 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1665031148; cv=pass;
        d=google.com; s=arc-20160816;
        b=S6HdQsJMKvNNx5zHQWpbmWtBiosDWan7CirBsDEgmRtPK6KpGfwU4ooodY67TTzWqC
         pBcWRmDoLTIj1qE/BwFQts1VTAEDYIjXvsOqVqGUWNmwY/SoGkJC6c8vjYSV/YacpBjR
         7CeKxsuGiqmSVwzp+HK1NDSOekaJsApQ9NmwO8VRwvJHrqeTfbjBmhWL06BVKSqDMT7z
         k9IUv4HkRRgt1Ie1RGAfTv+116YnO8AWYeYpxTTWlSI7E6B1lhhCX02ZEZ3cNCGUF5L2
         2K87Xh0SKILQ/MnNN1HfCbZ9rqU7Qtbl7gpTk68k0SoraJM/bPTbgfN5EfOsiD+m2p4e
         8Iwg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=UqFgmXnw9OwRljDY/OjP42B2u3HCUKsZVbihZU4qz0k=;
        b=X3kOvTvk9ibTm7BXbw+ceYwrYMHqMzyFLq/p6GcM/P5xaZAFv+UR5D5PFwfoZ/6HIO
         HYOlM4FblJ3zoj8/t0U2zWMWH9m9mtzWMWmGJi3O6f71LJPwBTHn4C/cdxHXbM5Uay0S
         Qmt9YnZ9AG0k0ra/T81Rdw9TZvYD+hV0yVKhuHtubo5oJPJoEkM0Jm1+hEl7zENBZ2hS
         NH1/b2Wg4k2pocC79oVEYvGbS6GFUo+/U4ghaTvHhmYU9EC58XqefbbC+xhXyXm/c+LB
         DyXR8jSGntclnq1fE/K5ck1OULv/3dEHgTcU11FFvbpVAjOfNcfOCJ09D2rPED6rdkWr
         /1+Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=Fcbv6b+y;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::429 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date;
        bh=UqFgmXnw9OwRljDY/OjP42B2u3HCUKsZVbihZU4qz0k=;
        b=sgY6wJPBo67WOVASxIPy0vfRTI4P+1MKozEWyt/FcEEF7sD6SPlmzT9Wwjs7OucL7x
         p5Lg6vLzpMFse5lI/1q9pWjjhcXts5CW0Jgg8UZVBDtJZQXdSwz+YaqOl2SHypm5yMmF
         C4AytzkAoFkOpQlZOf9+a7n9dLQxfoKDVx1CIlxWsGHEkESsnlOfqqQgATWI92YQma5f
         /KcEBcN2Q+AY9uSxjxKNcf/BMgzq+VCBx4B5S+1K3vUDVUA8KHyu7Zlti/YhevAqzxtd
         DLZ9dW/ICxFzwAce/Cfa56dzAeWH2yGFktdrX2YsO3ww/H+C8+lcbFqtKTFhD2qN9jxy
         fXDg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:sender:from:to:cc:subject:date;
        bh=UqFgmXnw9OwRljDY/OjP42B2u3HCUKsZVbihZU4qz0k=;
        b=j1fhWLD8ElCZdBVuSJTDvlAh4W7wwWtXY6YwVtw+FVtevGFJz9IDJ6BKl45yZGxyym
         tUR58e9D9kzJPzml4lAKaSr2TcQJx3gAmr8F160RQTaD+jL4zblzRbQdfCDoPDGVCx2+
         /Idtbl1EMiCpOHK7n2pU4zpeAwjidMvXxhyH4UjaVNvN3hcbvxvl9rqU2Q3Ym24psTX7
         iGYRD/7aVmP9XiBet1yMQcZrpoByIcAcOfVhty+4Bkt/dQjVIEX9QeqkHtX9MZ3u/x3l
         LXKwytPiUt/vBK5hm9avPOOoe3tCsoNLSa/DpdAPbNZmW72z3ex+QzHxP4F95hs+AJ9F
         NLhg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf2ZC9jdK1MqsYfi3yyKcT4caQwi4Jo0xVM70eKL7ZfcgQ+WtGuJ
	WMWlzV+Oq348e4GmsDglM+I=
X-Google-Smtp-Source: AMsMyM7ykFdcOYmQ+tU1Uvq6Kl8i6gKpIqlpw+1B/3xnoJYiqh9hsTUokw7bMUp3dvWeg75Z2ichmQ==
X-Received: by 2002:a17:902:8bc3:b0:178:8563:8e42 with SMTP id r3-20020a1709028bc300b0017885638e42mr2819685plo.0.1665031148364;
        Wed, 05 Oct 2022 21:39:08 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:b703:b0:20a:aa5f:5cea with SMTP id
 l3-20020a17090ab70300b0020aaa5f5ceals1805413pjr.0.-pod-preprod-gmail; Wed, 05
 Oct 2022 21:39:07 -0700 (PDT)
X-Received: by 2002:a17:90a:e7c3:b0:203:bbbb:e589 with SMTP id kb3-20020a17090ae7c300b00203bbbbe589mr8417602pjb.175.1665031147709;
        Wed, 05 Oct 2022 21:39:07 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1665031147; cv=none;
        d=google.com; s=arc-20160816;
        b=0ehJ1Dc1v4rGmC0GX6Vw4P+n1MfHSUbpm39qQ7N+bloPpkUbMkaHMRN5hNfc7ifK0a
         K/17WXragsTdrl22uqrNp0B8a6paRkER9/1OhldHZE3jziRS7bCEVCJAODv0UBIjMzFq
         nflmvO0RIXFG6Y6F5yWljQJWKlCxqBpAmaXYcxzAQdJYAg1/xOwTSgdwVTz6QTYUFPLL
         1TQD9tDgoIkJE43URp0UTHjlwIW14/YLQW0g6M/cCLyF+6PiA4PcEyLJhDKLKd/sidkz
         bMQ+x7zwoE0B0MQOlAOH+IkJF9hM+8X6z91l/j7MqIAFFehZx3YD4/qel5Kx0LI+3Pcw
         GgbA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=y1Ewt823HoXUJ+RVCiU5hfekdC+9m7ghxyBCLtj1eUk=;
        b=X0JQpBnI1Fox8aajeAE/4BJqIHleAGUGHdsVsZKenMmnejtenm9EV4InU3ulie/Iy3
         1qqI+Jei4eoeMqPlbaFsFnW59zWOi1hHa4B+vPoUUC391jFmjKq9B9IwULDJNcIXKUC/
         6aHf4m8DSEJxpQIB/5qS/GWrEK1Mv8mzVDWpfJbCrstCOjPVJbKErm4AdJhYFoSEkQIq
         RgRic7QzMZFEixC9nOIm2lCEF+d6+Elu95WiN43QlzcQxQmSTKMqOIf8TjR2/bIRnGfv
         K80RskJ10zyaJgAe5rgaB+0tHjtGXxYlqSQ4KJY/FVr/8RUh97CAk8qfACThOMGK0MZz
         abfw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=Fcbv6b+y;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::429 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Received: from mail-pf1-x429.google.com (mail-pf1-x429.google.com. [2607:f8b0:4864:20::429])
        by gmr-mx.google.com with ESMTPS id n11-20020a170902f60b00b00176b120432bsi716474plg.10.2022.10.05.21.39.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 05 Oct 2022 21:39:07 -0700 (PDT)
Received-SPF: pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::429 as permitted sender) client-ip=2607:f8b0:4864:20::429;
Received: by mail-pf1-x429.google.com with SMTP id 67so972317pfz.12
        for <kasan-dev@googlegroups.com>; Wed, 05 Oct 2022 21:39:07 -0700 (PDT)
X-Received: by 2002:a05:6a02:190:b0:43c:7997:4d69 with SMTP id bj16-20020a056a02019000b0043c79974d69mr2783084pgb.15.1665031147380;
        Wed, 05 Oct 2022 21:39:07 -0700 (PDT)
Received: from www.outflux.net (smtp.outflux.net. [198.145.64.163])
        by smtp.gmail.com with ESMTPSA id y16-20020a17090264d000b0016eef326febsm6272844pli.1.2022.10.05.21.39.05
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 05 Oct 2022 21:39:06 -0700 (PDT)
Date: Wed, 5 Oct 2022 21:39:03 -0700
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
Subject: Re: [PATCH v1 5/5] prandom: remove unused functions
Message-ID: <202210052138.A585E4CC@keescook>
References: <20221005214844.2699-1-Jason@zx2c4.com>
 <20221005214844.2699-6-Jason@zx2c4.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20221005214844.2699-6-Jason@zx2c4.com>
X-Original-Sender: keescook@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=Fcbv6b+y;       spf=pass
 (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::429
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

On Wed, Oct 05, 2022 at 11:48:44PM +0200, Jason A. Donenfeld wrote:
> With no callers left of prandom_u32() and prandom_bytes(), remove these
> deprecated wrappers.
> 
> Signed-off-by: Jason A. Donenfeld <Jason@zx2c4.com>

Reviewed-by: Kees Cook <keescook@chromium.org>

-- 
Kees Cook

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/202210052138.A585E4CC%40keescook.
