Return-Path: <kasan-dev+bncBCUO3AHUWUIRB6M47OMQMGQEFF24CPQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63f.google.com (mail-pl1-x63f.google.com [IPv6:2607:f8b0:4864:20::63f])
	by mail.lfdr.de (Postfix) with ESMTPS id 86FCC5F6685
	for <lists+kasan-dev@lfdr.de>; Thu,  6 Oct 2022 14:47:55 +0200 (CEST)
Received: by mail-pl1-x63f.google.com with SMTP id c12-20020a170903234c00b0017f695bf8f0sf1228498plh.6
        for <lists+kasan-dev@lfdr.de>; Thu, 06 Oct 2022 05:47:55 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1665060474; cv=pass;
        d=google.com; s=arc-20160816;
        b=bMpYD8RQlvm/a8ONVrioWgfqRxW8QPxc4cnKaLMsLJdJRD2HZl/6aOMdcI1qUutL/6
         W4Yvv+EOygK1ULDwK5m+dFmE7t5rw1D3OEeyXkF8ReTxHbWawwX89lqQtg8bjfxbeP+E
         SNy0FpB9mKsLSit961DfIkFekEFOutW2zeMWGNlqyNvAHVDlzLoVwpFsNiCGBH1hX64p
         4zIxFWFzfsPB6s8Dn/EMffR8mj3tZyj1QJsB8Kh60t5D1ln8MOHSliS2toa0y8ps2lK9
         153bwFyb6Eg2Ti1NG+d5NRYqWL7kuPAjBK8wgnF0mVqobjGj9SePPK+J+fGT4gj+hGFA
         9JQg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=NjrSMhvmIxpoKQk4amTX5iAz0mBUxeG8z+wS5cEkI4o=;
        b=TGUCr1K/clwSYIrdMrZle2RFmjfr0Yl6l2RPKP5lLOdf/JfCRanDqQewYfUq+rMJ8B
         Kqlij5uUfZLb76Ty8dQUFETcF9MhgiSuSghbrXhkli5Qd+qNF0mRecGZlivJTTKUcpFF
         20TW3FzFRrmoAaMaE9pAKnEPBFA++JHa2gphIvSz1LHxDynzUOowQx8XzBOzZOZIhsmn
         xdKM4E333rvLkXKH2vD0MYJ3UYtBIGl/Wl4K/Qn09jsEZfLA15tQwbFuwm+1FEFIfSsJ
         YNVK8INyOomJMJWxgBQzY1Q0Z+QrGnCxCd6QO0ijLwvClP7ZDrXoHTzb8MibAvxYr+MY
         rA2A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ziepe.ca header.s=google header.b=Mjk55TEb;
       spf=pass (google.com: domain of jgg@ziepe.ca designates 2607:f8b0:4864:20::f31 as permitted sender) smtp.mailfrom=jgg@ziepe.ca
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date;
        bh=NjrSMhvmIxpoKQk4amTX5iAz0mBUxeG8z+wS5cEkI4o=;
        b=t5wQqAmx2VTH1gN5rNYoiXQl9LVaeTZhyBwpa2ryaZmzZzQ8Gk8GhtEBA7NDsH62LB
         DM7vOb3TKvL46yCo7qh1Va/IEg42UuA0yVq69LZ6jVv829eTFbKmYjuXvlbREiRqFkTN
         +PISyr50JzZQ2hw93XZHkn/jIzQHr/sruHAHigxRrstjKvZtRLFKz4kH71tL6QbhG5sF
         SmzikHGqpxkbru3MLz+22oLySG4UODbKg65C9hPrWqgZ2zKNTpP+9f+m6s3x99rGFEWt
         dl4v5fx4WphpfBHPPVHhsg4/0GEljxe7KNQQfdISAA6aJ9WW//TpMu8wVJZa+YB2zD62
         KgjA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:sender:from:to:cc:subject:date;
        bh=NjrSMhvmIxpoKQk4amTX5iAz0mBUxeG8z+wS5cEkI4o=;
        b=stMXFT9pklJB6n6EZ5Y0+o3MD8GlTVYPPcqdJ4Rz+WEvdRs6W7iZmL0RXbdxqhCIN0
         PxEX5Hh5ELDWzllshueuZm5GIIrt1iSke0tIONld/yaN0/k+9WiVQ1CR2iFtvwV3Ddc+
         IhS0qIFJMtbw8QcLDZFx+h4Vce+L6y4Z2kaS8n+e2QfO5rVf8UavJ0fa7sKFvoJUBK/3
         s8o2Ug2OTjxYY7H5dXmR2gr/jkGTOgaDDNSCXbnwUVXCqOy78UH+do+lr4Atca1ZR+I1
         PEAkz9UZCcplQS8YQCFRn6bE1fqZl6DKTEsUkBziSEKKKoRDLF0pNlDAEuXUZs0vigQl
         9SuA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf1hAdDhQStjLuFwm9f1wz1RsSO621Ufa/tqj0i9L093DNCWpv2o
	d80cQd4LG+N6ZWJb0xmDUwc=
X-Google-Smtp-Source: AMsMyM7PrI5U5thiWrFH36Cbosva8mK+t1YuEycaaukg8Js7yd8zz3BUorHi5xpscNG+WoEKU1iqTQ==
X-Received: by 2002:a17:902:e751:b0:178:2976:41a0 with SMTP id p17-20020a170902e75100b00178297641a0mr4707494plf.12.1665060473733;
        Thu, 06 Oct 2022 05:47:53 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:903:32c1:b0:17a:6fa:2290 with SMTP id
 i1-20020a17090332c100b0017a06fa2290ls1597461plr.3.-pod-prod-gmail; Thu, 06
 Oct 2022 05:47:53 -0700 (PDT)
X-Received: by 2002:a17:903:2594:b0:17c:6117:2434 with SMTP id jb20-20020a170903259400b0017c61172434mr4457564plb.135.1665060473027;
        Thu, 06 Oct 2022 05:47:53 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1665060473; cv=none;
        d=google.com; s=arc-20160816;
        b=F2SXV6ZcQB6QjvL/fyQXUiridSsP+mWUtJuy3UF8wxgsMpO/qC88XEN6jgWVAv4xMw
         inEEnGNihv3AjNrKCC34YrO7n/R9koLNpd8zWbWR3GsxqJTwTNJt3yDI3JeUU86jFXGP
         s0ggWbiR5+3PGIt38n54H+gHS4vU3fUtj2NnNZxKKCwWfzroffguLuz088Iz3hMYrnqs
         GBsPSmd9/2Gs+/WjcoVM38MUM/CGEAjrUP+M/lxques9aa8KTADXzpXQMxya3ik6Dwcd
         CdS66Ozu6tkFmDgNSprpQGd2ebDS/dQWqMzEwtsJJbK1ammAhr9bHLbksuH76ocMwq0n
         0wbg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=eLAvQxPTrW61bFz1sANG5Y81u18aSgNqwRKiQkasIrQ=;
        b=MAPhgh5b2Vrai1WMTRpmJXX6oaT+yV7FwJ1PXIG3A3kryflCkCVSKK79jcRbdcpwrV
         M3YDxqszpGybeU2J0ZTW4hAgbcy5CS20yNiJ47M+dsx8mrczmegK0jLWgHKXUbwEnSMM
         AtwjQlWUaM4AUtpefExyXnyPuiFLytG+rc/oOoEM/Ye0WSoFm9nTbCPkhMJVuvLrv0ir
         bZco+Fe1ZMASXInoVqCdZpaaHVR0qTK6SMWJiqQQFHhkF2RHXQrMw39H7zz7K9kXP8+2
         6kI9y4RCV1X08TDNx0lDR9Ci3xxHrR0mxrt2z92YcVxAE4ETB3veG05yXiFu5on0iB4t
         UNsg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ziepe.ca header.s=google header.b=Mjk55TEb;
       spf=pass (google.com: domain of jgg@ziepe.ca designates 2607:f8b0:4864:20::f31 as permitted sender) smtp.mailfrom=jgg@ziepe.ca
Received: from mail-qv1-xf31.google.com (mail-qv1-xf31.google.com. [2607:f8b0:4864:20::f31])
        by gmr-mx.google.com with ESMTPS id o10-20020a170902d4ca00b0016d5fc78c8esi848515plg.7.2022.10.06.05.47.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 06 Oct 2022 05:47:52 -0700 (PDT)
Received-SPF: pass (google.com: domain of jgg@ziepe.ca designates 2607:f8b0:4864:20::f31 as permitted sender) client-ip=2607:f8b0:4864:20::f31;
Received: by mail-qv1-xf31.google.com with SMTP id i9so1094162qvu.1
        for <kasan-dev@googlegroups.com>; Thu, 06 Oct 2022 05:47:52 -0700 (PDT)
X-Received: by 2002:a05:6214:d06:b0:4ad:1fe1:9b49 with SMTP id 6-20020a0562140d0600b004ad1fe19b49mr3536957qvh.57.1665060472470;
        Thu, 06 Oct 2022 05:47:52 -0700 (PDT)
Received: from ziepe.ca (hlfxns017vw-47-55-122-23.dhcp-dynamic.fibreop.ns.bellaliant.net. [47.55.122.23])
        by smtp.gmail.com with ESMTPSA id j3-20020a05620a410300b006b5bf5d45casm20676675qko.27.2022.10.06.05.47.50
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 06 Oct 2022 05:47:50 -0700 (PDT)
Received: from jgg by wakko with local (Exim 4.95)
	(envelope-from <jgg@ziepe.ca>)
	id 1ogQI1-00A0xr-QZ;
	Thu, 06 Oct 2022 09:47:49 -0300
Date: Thu, 6 Oct 2022 09:47:49 -0300
From: Jason Gunthorpe <jgg@ziepe.ca>
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
	Jay Vosburgh <j.vosburgh@gmail.com>,
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
Message-ID: <Yz7OdfKZeGkpZSKb@ziepe.ca>
References: <20221005214844.2699-1-Jason@zx2c4.com>
 <20221005214844.2699-4-Jason@zx2c4.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20221005214844.2699-4-Jason@zx2c4.com>
X-Original-Sender: jgg@ziepe.ca
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ziepe.ca header.s=google header.b=Mjk55TEb;       spf=pass
 (google.com: domain of jgg@ziepe.ca designates 2607:f8b0:4864:20::f31 as
 permitted sender) smtp.mailfrom=jgg@ziepe.ca
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

On Wed, Oct 05, 2022 at 11:48:42PM +0200, Jason A. Donenfeld wrote:

> index 14392c942f49..499a425a3379 100644
> --- a/drivers/infiniband/hw/cxgb4/cm.c
> +++ b/drivers/infiniband/hw/cxgb4/cm.c
> @@ -734,7 +734,7 @@ static int send_connect(struct c4iw_ep *ep)
>  				   &ep->com.remote_addr;
>  	int ret;
>  	enum chip_type adapter_type = ep->com.dev->rdev.lldi.adapter_type;
> -	u32 isn = (prandom_u32() & ~7UL) - 1;
> +	u32 isn = (get_random_u32() & ~7UL) - 1;

Maybe this wants to be written as

(prandom_max(U32_MAX >> 7) << 7) | 7

?

> diff --git a/drivers/infiniband/ulp/ipoib/ipoib_cm.c b/drivers/infiniband/ulp/ipoib/ipoib_cm.c
> index fd9d7f2c4d64..a605cf66b83e 100644
> --- a/drivers/infiniband/ulp/ipoib/ipoib_cm.c
> +++ b/drivers/infiniband/ulp/ipoib/ipoib_cm.c
> @@ -465,7 +465,7 @@ static int ipoib_cm_req_handler(struct ib_cm_id *cm_id,
>  		goto err_qp;
>  	}
>  
> -	psn = prandom_u32() & 0xffffff;
> +	psn = get_random_u32() & 0xffffff;

 prandom_max(0xffffff + 1) 

?

Jason

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/Yz7OdfKZeGkpZSKb%40ziepe.ca.
