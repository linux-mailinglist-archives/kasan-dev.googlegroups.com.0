Return-Path: <kasan-dev+bncBDA5BKNJ6MIBBPFD7OMQMGQEF2UYZCQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13f.google.com (mail-lf1-x13f.google.com [IPv6:2a00:1450:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id 45B145F6718
	for <lists+kasan-dev@lfdr.de>; Thu,  6 Oct 2022 15:01:50 +0200 (CEST)
Received: by mail-lf1-x13f.google.com with SMTP id g8-20020ac24d88000000b004a22b2a7d27sf608063lfe.21
        for <lists+kasan-dev@lfdr.de>; Thu, 06 Oct 2022 06:01:50 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1665061308; cv=pass;
        d=google.com; s=arc-20160816;
        b=mc1L4BodunSandM2/gY7NdvRXpLq+/qYYurN/tf/sGMR/y0zyA5hgPSt1amsTYZeBi
         Ge11IxMYsWMNpUYGfd5v5uaM7Wzt9A2BeW6MC4KrLBtfzVDYm+c+iqaXthCtaO4ebe9L
         +dqVwzkTZ15xKQlJFCzxCFJTGWh4tEM224I0MK8qlv7POWxv6lxtzJpmTXXXOBsRuKK5
         rHBLI7Kk33NvkNBl1LGW1qpgkp23e63UGAXGIeeIIuot0m6yLtTN1/J51ABlc9LAfiM8
         S9DX+p2j8iXvsEZ0DMlIo3Y42HfbIrsbWyShIjCU9lJGOEmdHOs6t5Qqs/k32fQNgdRL
         0lnw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:organization:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=nC7p0A1jGjyBp5rLER0BGxGapPDeIm6ZLUR2ge3jz08=;
        b=eo4Jp9AGwQXveEzRr2hCzLzi06csmmp/glRMYeKmncmyFNBHobE+tz+5aQI3scm/Xq
         vCBH7JpoJdU5+1NP4yO/1SkHtHVCzkNzi6qmFqBdnegICqqYcPt35QlR9Vq6h0y6v6ka
         TJk+Uo9+myWxnc6CKngSiSCLNBBeUNkSJvJfrbiooYHStKCdmBJDoZ6aplBtQI9rJnKA
         Ryobd8Gc9oVcb3aEBq3GKRWvMB/06hFMfXJC691Xbt6g7sqF7CDEQplQH3j0wzMuiWex
         2m7O8u7+V7NjkpYxX7BhNvtb5+BGZ6ySYiVpcFKyxtIfKHs5J38HoDCGCxcotn6cGUxN
         6rXQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=TeGC5kcB;
       spf=pass (google.com: best guess record for domain of andriy.shevchenko@linux.intel.com designates 134.134.136.126 as permitted sender) smtp.mailfrom=andriy.shevchenko@linux.intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:organization:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :from:to:cc:subject:date;
        bh=nC7p0A1jGjyBp5rLER0BGxGapPDeIm6ZLUR2ge3jz08=;
        b=eRAXe+lNTWAhKIwQLQxpkNkrfKsSu9Al+BvZhAFdVipkBFb+/Chmj83NsleRb7owVD
         7kMxRzRFTTt14HGbAUMyhcPe42nfJvXdjVWlkaZ5rPLxG95YN97h5zBxQPexcBg/cS9y
         YzFDFH4Rjns/BqrnJo19XmbTr6fwjb/KqtfHiZcqP1KSHY50LxZk9Yya9JQIw0iD7/g/
         d19Z1i+tlsgoWsyxklb39wAJpcckQhLq/yUDJ6BZHvXQfl3R81McVGh6lPAfk1/Ly4+2
         f2T5KXadg8bRUkQ/vzzA8wx1UnSVM18FdcPwznE+rvY797UIjGa1cx6PgZhqdn4OONbe
         oHeQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:organization
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:x-gm-message-state:sender:from:to:cc
         :subject:date;
        bh=nC7p0A1jGjyBp5rLER0BGxGapPDeIm6ZLUR2ge3jz08=;
        b=RNpCOrgWkpyoexGZk51VlGzs3jdepwoib/Bv66MmpldITMJEx6Cr2x/Mh/rAsTFsRn
         IO7NpwEI9ZXB31gowtPFp5nib2si6NMlHmDTOl/xsJl8E+W81NX3jr/dDfzueTnsRiEs
         OohvK/rv9fc0rjoGrNlUbqdCzuBIs+mpKlZ2QkTS6w6xegqJCoz3zcZvhbqhCfj/pwls
         TK3oU8Bs195TIo9WOtpLHiJBkKBgqo8n4iv83/0h0m90kxhCQl6cQR9ljJMcslIaHgSh
         BLw1YfuG3kdCFtR6IY1yWQvpPkr+Ljqf2YEEQ0wIHSIsdUzI6e+HWY9oo9hLw6R0joyJ
         oJhw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf2WMQGobAEcH0ockSvWDVGwPOUA6tyuCfXRup36APQEmcui2eg2
	+8BHKOJ8bzVXz3Wf9qVEuuI=
X-Google-Smtp-Source: AMsMyM6oPR0zfIFQcn//y2t+Fro+HzNtYN4J+d1MRS8XXQeB1ZVE3DWEN1NxAboRudFHJ3FeKcLEsg==
X-Received: by 2002:a05:651c:1504:b0:26c:6331:3463 with SMTP id e4-20020a05651c150400b0026c63313463mr1817887ljf.30.1665061308535;
        Thu, 06 Oct 2022 06:01:48 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:9444:0:b0:26b:ff81:b7cb with SMTP id o4-20020a2e9444000000b0026bff81b7cbls378212ljh.6.-pod-prod-gmail;
 Thu, 06 Oct 2022 06:01:47 -0700 (PDT)
X-Received: by 2002:a2e:a90a:0:b0:261:d622:248c with SMTP id j10-20020a2ea90a000000b00261d622248cmr1686512ljq.332.1665061307046;
        Thu, 06 Oct 2022 06:01:47 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1665061307; cv=none;
        d=google.com; s=arc-20160816;
        b=U37Khpr7VuKFgusL8ICEgV5ypwVcKllmOMe6ooUqpyhG2K1wQ3yJAfzbFY/MfExI+/
         GPOlrKMf/7ZcS3ZBBWjLRcHLSj3MPue71CR92Zzmu+Ucpbbws/NKhl56Uk+8FBXkT/V5
         KxJbPPqnhhOhx0igy69Oj4IheXnbmTO1qsvvz1AQ6MTLgDcDhx3PZ/GJQsoUAaIkKbiP
         EHwCdDWei0smICh2FTIHFg4FcWAP+J6zQ3ZOk9wndkF6AzMca6Ha7OT3L6z02ILKq+yF
         zDwoqsrB+nSKz/hpIkZ+P6/xnKBsIqERqqdrKUvUNo0TXdef4IQ5+Asu/n/Nx1UFAs/U
         Bodw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=organization:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:dkim-signature;
        bh=SC0RJaj0XqcnHyLY9WHpzfuDADI6AKzBTh/+dHT4PDA=;
        b=ZlCcazUmGHG8R1wzlFwElljyaYwpyJANj92PacPt7uYAniOnIk1+yHgHxB4gPn+hRv
         FYDdGADGBKFZruyN8H36fUkzIDc0OnAdse/sfniPPlKf+ZG7Uysnk8osoKbovNxeuR5h
         3J6y6lOyQsr7kuPr5pl3jxpEFtkjLo0B8p234VXMq85y5Ltdwg3OMqRRMBN+tHNzHilA
         7YgWcYOOWjiGKGcHbTRudkOGzsSN8TcGkgaLRtyMuSt2CyRmdz0iN8/vxVF3avZe6svD
         b8TARoU/5P6XpQW+W9lazXxZYzCghAhMdmDr5CO0Qr+Uu4CulS5FwEMU9wo0/GO0Iwy4
         IEjQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=TeGC5kcB;
       spf=pass (google.com: best guess record for domain of andriy.shevchenko@linux.intel.com designates 134.134.136.126 as permitted sender) smtp.mailfrom=andriy.shevchenko@linux.intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mga18.intel.com (mga18.intel.com. [134.134.136.126])
        by gmr-mx.google.com with ESMTPS id q8-20020a0565123a8800b0048b224551b6si696552lfu.12.2022.10.06.06.01.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 06 Oct 2022 06:01:46 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of andriy.shevchenko@linux.intel.com designates 134.134.136.126 as permitted sender) client-ip=134.134.136.126;
X-IronPort-AV: E=McAfee;i="6500,9779,10491"; a="286660508"
X-IronPort-AV: E=Sophos;i="5.95,163,1661842800"; 
   d="scan'208";a="286660508"
Received: from fmsmga001.fm.intel.com ([10.253.24.23])
  by orsmga106.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 06 Oct 2022 06:01:43 -0700
X-ExtLoop1: 1
X-IronPort-AV: E=McAfee;i="6500,9779,10491"; a="767139941"
X-IronPort-AV: E=Sophos;i="5.95,163,1661842800"; 
   d="scan'208";a="767139941"
Received: from smile.fi.intel.com ([10.237.72.54])
  by fmsmga001.fm.intel.com with ESMTP; 06 Oct 2022 06:01:22 -0700
Received: from andy by smile.fi.intel.com with local (Exim 4.96)
	(envelope-from <andriy.shevchenko@linux.intel.com>)
	id 1ogQUx-0039Oq-2J;
	Thu, 06 Oct 2022 16:01:11 +0300
Date: Thu, 6 Oct 2022 16:01:11 +0300
From: Andy Shevchenko <andriy.shevchenko@linux.intel.com>
To: "Jason A. Donenfeld" <Jason@zx2c4.com>
Cc: Jan Kara <jack@suse.cz>, Andrew Lunn <andrew@lunn.ch>,
	"Darrick J . Wong" <djwong@kernel.org>,
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
	Andreas =?iso-8859-1?Q?F=E4rber?= <afaerber@suse.de>,
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
	Toke =?iso-8859-1?Q?H=F8iland-J=F8rgensen?= <toke@toke.dk>,
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
	Dmitry Vyukov <dvyukov@google.com>, Jens Axboe <axboe@kernel.dk>,
	cake@lists.bufferbloat.net, brcm80211-dev-list.pdl@broadcom.com,
	Yishai Hadas <yishaih@nvidia.com>,
	Hideaki YOSHIFUJI <yoshfuji@linux-ipv6.org>,
	linuxppc-dev@lists.ozlabs.org, David Ahern <dsahern@kernel.org>,
	Philipp Reisner <philipp.reisner@linbit.com>,
	Stephen Hemminger <stephen@networkplumber.org>,
	Christoph =?iso-8859-1?Q?B=F6hmwalder?= <christoph.boehmwalder@linbit.com>,
	Vinod Koul <vkoul@kernel.org>,
	tipc-discussion@lists.sourceforge.net, Thomas Graf <tgraf@suug.ch>,
	Johannes Berg <johannes@sipsolutions.net>,
	Sungjong Seo <sj1557.seo@samsung.com>,
	Martin KaFai Lau <martin.lau@linux.dev>
Subject: Re: [f2fs-dev] [PATCH v1 3/5] treewide: use get_random_u32() when
 possible
Message-ID: <Yz7Rl7BXamKQhRzH@smile.fi.intel.com>
References: <20221005214844.2699-1-Jason@zx2c4.com>
 <20221005214844.2699-4-Jason@zx2c4.com>
 <20221006084331.4bdktc2zlvbaszym@quack3>
 <Yz7LCyIAHC6l5mG9@zx2c4.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <Yz7LCyIAHC6l5mG9@zx2c4.com>
Organization: Intel Finland Oy - BIC 0357606-4 - Westendinkatu 7, 02160 Espoo
X-Original-Sender: andriy.shevchenko@linux.intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=TeGC5kcB;       spf=pass
 (google.com: best guess record for domain of andriy.shevchenko@linux.intel.com
 designates 134.134.136.126 as permitted sender) smtp.mailfrom=andriy.shevchenko@linux.intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
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

On Thu, Oct 06, 2022 at 06:33:15AM -0600, Jason A. Donenfeld wrote:
> On Thu, Oct 06, 2022 at 10:43:31AM +0200, Jan Kara wrote:

...

> > The code here is effectively doing the
> > 
> > 	parent_group = prandom_u32_max(ngroups);
> > 
> > Similarly here we can use prandom_u32_max(ngroups) like:
> > 
> > 		if (qstr) {
> > 			...
> > 			parent_group = hinfo.hash % ngroups;
> > 		} else
> > 			parent_group = prandom_u32_max(ngroups);
> 
> Nice catch. I'll move these to patch #1.

I believe coccinelle is able to handle this kind of code as well, so Kees'
proposal to use it seems more plausible since it's less error prone and more
flexible / powerful.

-- 
With Best Regards,
Andy Shevchenko


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/Yz7Rl7BXamKQhRzH%40smile.fi.intel.com.
