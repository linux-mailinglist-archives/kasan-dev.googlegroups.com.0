Return-Path: <kasan-dev+bncBCUO3AHUWUIRBO5A7OMQMGQEH55G5DI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x93d.google.com (mail-ua1-x93d.google.com [IPv6:2607:f8b0:4864:20::93d])
	by mail.lfdr.de (Postfix) with ESMTPS id 8F7CB5F66F3
	for <lists+kasan-dev@lfdr.de>; Thu,  6 Oct 2022 14:55:24 +0200 (CEST)
Received: by mail-ua1-x93d.google.com with SMTP id y44-20020ab048ef000000b003cd69b6e479sf617876uac.9
        for <lists+kasan-dev@lfdr.de>; Thu, 06 Oct 2022 05:55:24 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1665060923; cv=pass;
        d=google.com; s=arc-20160816;
        b=e4rzwFgS2tWjlzJkPfSy1QlgANNXQarsCV7p1NFRCjCf6hi4P7xCw0DoTGpeESbk+z
         e6Uy5F/l4b2m/EVO3STQxwIlr4DXE/gbZto3Jmk1stnSnJcpw0KrDfgtlDzz1RzNPx0D
         kP6c28Edo2dJfmoSAx9OBufXdl3xMQ4mKf+nzmHHFQti2U1GtfTIRuQtq2g8R2igUGpN
         eI6jLkfLmTFYR+PSTiLkA3osCYURNW+9Wfa1kBPFuCzQWeE6YiGckSY7RlWVx9s9ZUb4
         pfCUYFKGKfzIGJFZwUbyyBZBUsm8nVr3KJbM65mDT2I2sC7xzL6Q2rL/QxMtSnOZ6Lcp
         F4Pg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=we0EITLJExeMUBP5FLXEqAi8y1+TlQ3UtWeRm/1XiqY=;
        b=n5qenBjlLxJ1L/57znxn833mCz6pfFEve0UThwI6k69v3hLYadEPwCTK+QBAAAnkiv
         zeTQnfdY5XkQXmD2iQbSCVdn1D0yAf43Vz3DFwyq6QDbQeMyRfPIzrpqKQRP5zNm3XbS
         MuAOaOgcMs+Pn9PasXYhJ1YCBLMJJvIXwvZXONnGxrtT4iYIjPVbMmCEaqrT/xJK3ifp
         5M0MHXjVu7LTGIvTCUZ8q5dtajZXRQH0LmunU7XptY9JKmOiUjfRJicU5MebM22aJ+LZ
         ML4daZGNTxT493hkEFWVjQlhc5odNwtELdMKasp9jCUcH9rQpeaAB1eK/1e2FwbE/V8h
         4BMw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ziepe.ca header.s=google header.b=fRB9gEBB;
       spf=pass (google.com: domain of jgg@ziepe.ca designates 2607:f8b0:4864:20::833 as permitted sender) smtp.mailfrom=jgg@ziepe.ca
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date;
        bh=we0EITLJExeMUBP5FLXEqAi8y1+TlQ3UtWeRm/1XiqY=;
        b=ea1S4ltY22Xp8Q98aVYXGAZdBldubCUIIBp0f6PCyzSOOaLyetAWqB7tN5fgx9gonM
         gNn27VNwMr496aZvoWM5VczkvT0+EJvsptreo9Z723RxD3kVhcgTjpM6NwUaUtQbA/kg
         MHc7Te5DdFtte3+E4wJXfMPqxZMBliDA06/gSFiGvnJpvTtviX1vjxhs54Yu24Asztjl
         VeG8t/86qvVde/Gw0Qf8dJLiPxhDu0SVwWAuMKLMHiUCofQJed/Epj178mU7z/oqPPFb
         vo+T5tdtKnCPraz8EkxOrfFP0m0WucPpg08QLCB7hoD6z+sVkV/a/+xGOHyuLJ20wj3l
         cXng==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:sender:from:to:cc:subject:date;
        bh=we0EITLJExeMUBP5FLXEqAi8y1+TlQ3UtWeRm/1XiqY=;
        b=QMGThVtaUPxpnDQc+ZmuLqP235TTLVXVDqLxLOup2CEdnYmHDAdtOUeSY6aDzmdfac
         I2kKhBRJiEoQZg2BLSwEg4SEvonTOnZp4n/7nVNuXwfP5YRn7paja7UoRowb6ua5VeA0
         bn1Ya+aKo/nO4JCBgHvdx7JsOUNbUYz5iXtfAM6Vyug75LNNJ6XGU8tDxr8BJOqDuWLH
         tPPrASwu2GGgDc+yjcFoq1FeiXpQ58u3thT7FZxpJXQN9aorHSG6tc7q5wQsTy2AxXZf
         UVw4DhXiVsF0vZ7CfZzF9HDCV1TxWNLAJRim+qSNwI+GWVNlqArqHSlErgIcERRYuN5B
         uiHQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf2QQSOynOxhSVpT9CEVT+xupmo+lqMjxyM/EUjqb/uyByARG+bi
	isjrFHnKMRdCjmBpslyOhVQ=
X-Google-Smtp-Source: AMsMyM5X/RyKU4lCxJdhJtqc3tqCOtRzfGjJSFewB37Z8/QT7u4Jiwf/o5WjuxEqWiMHsaI7yexHlA==
X-Received: by 2002:a05:6102:15aa:b0:390:9b9b:f679 with SMTP id g42-20020a05610215aa00b003909b9bf679mr2203043vsv.34.1665060923325;
        Thu, 06 Oct 2022 05:55:23 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9f:3e8b:0:b0:3d6:8a5d:19c5 with SMTP id x11-20020a9f3e8b000000b003d68a5d19c5ls124082uai.3.-pod-prod-gmail;
 Thu, 06 Oct 2022 05:55:22 -0700 (PDT)
X-Received: by 2002:ab0:555c:0:b0:3d6:7cfb:18f9 with SMTP id u28-20020ab0555c000000b003d67cfb18f9mr2363973uaa.76.1665060922755;
        Thu, 06 Oct 2022 05:55:22 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1665060922; cv=none;
        d=google.com; s=arc-20160816;
        b=mZbm8uEYGy1rocPcfY+sjxLARtKDYlMW1tHFAfiF0z/m/Ife+W1GUJ783AoEQlL8zV
         dwXskNMw5rOSR91AgMnrCGjWi64s0X/07hjrm6SyTa7Y5HnBAzIjnnkxck8xezD4d7DR
         MBk2fZes3G2xQEQl3gOXW5UTe0Arh5bwoOkkr8nW6b1ugbtO7BZ5eHGaOdADvBgI3pJr
         n3Afd23EbB50JMV17uinyOMugzChvHgSeNu8wvytvy6RSfhBFjdIjIMBix4sDFyPBT3H
         I1lcnihAQhcYN7jvj9vMt/BGWMTwGm4Tf/LJRJMEOlz4qxk89tgZTSacScp+n8S5p4yO
         Re3w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=Tn+sqw4/yCgRf+qJVvhcwv0+F43hCZc6SWcnJkISat8=;
        b=hxScjGYi+yU6is3c8uWxBwY2YhVm8vuoN5UQPoiVSDmf0jY04pEYdYm0aFuimPYtLF
         oOX4VX21cWOw/r6UfBu5DGFjlxdvYpm4kfu6e1C2vFcmrWvgxYn4BLJ9EdRCwFQb8Dho
         VrQQ/Upsy35D3zQvI25S2F/mGmEkmoT8Av2w00+2bzcWhy95+ZU0MfXyJolv7ignHPPN
         7ZM8I21HHfxjJLceWPO8GB4gjfU1dt+PqbX0GbNEuTy1nqAxdnjRfUeHjZd7AFTYso2A
         Zi6Hd45ioqWJucyJ/mmuWNYGGN0Bnfk8gMRIgqovmGn97b3ArrwZRoxkchVlDV6+XU0y
         r2jA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ziepe.ca header.s=google header.b=fRB9gEBB;
       spf=pass (google.com: domain of jgg@ziepe.ca designates 2607:f8b0:4864:20::833 as permitted sender) smtp.mailfrom=jgg@ziepe.ca
Received: from mail-qt1-x833.google.com (mail-qt1-x833.google.com. [2607:f8b0:4864:20::833])
        by gmr-mx.google.com with ESMTPS id v201-20020a1f2fd2000000b003a42b7cdb27si913934vkv.4.2022.10.06.05.55.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 06 Oct 2022 05:55:22 -0700 (PDT)
Received-SPF: pass (google.com: domain of jgg@ziepe.ca designates 2607:f8b0:4864:20::833 as permitted sender) client-ip=2607:f8b0:4864:20::833;
Received: by mail-qt1-x833.google.com with SMTP id d15so874034qtw.8
        for <kasan-dev@googlegroups.com>; Thu, 06 Oct 2022 05:55:22 -0700 (PDT)
X-Received: by 2002:ac8:5a05:0:b0:35b:bac9:d3ff with SMTP id n5-20020ac85a05000000b0035bbac9d3ffmr3176264qta.374.1665060922186;
        Thu, 06 Oct 2022 05:55:22 -0700 (PDT)
Received: from ziepe.ca (hlfxns017vw-47-55-122-23.dhcp-dynamic.fibreop.ns.bellaliant.net. [47.55.122.23])
        by smtp.gmail.com with ESMTPSA id a16-20020a05620a16d000b006b58d8f6181sm18923537qkn.72.2022.10.06.05.55.20
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 06 Oct 2022 05:55:20 -0700 (PDT)
Received: from jgg by wakko with local (Exim 4.95)
	(envelope-from <jgg@ziepe.ca>)
	id 1ogQPH-00A172-Pm;
	Thu, 06 Oct 2022 09:55:19 -0300
Date: Thu, 6 Oct 2022 09:55:19 -0300
From: Jason Gunthorpe <jgg@ziepe.ca>
To: "Jason A. Donenfeld" <Jason@zx2c4.com>
Cc: Kees Cook <keescook@chromium.org>, linux-kernel@vger.kernel.org,
	Ajay Singh <ajay.kathat@microchip.com>,
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
Subject: Re: [PATCH v1 1/5] treewide: use prandom_u32_max() when possible
Message-ID: <Yz7QN3cbKABexzoB@ziepe.ca>
References: <20221005214844.2699-1-Jason@zx2c4.com>
 <20221005214844.2699-2-Jason@zx2c4.com>
 <202210052035.A1020E3@keescook>
 <Yz7N5WsqmKiUl+6b@zx2c4.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <Yz7N5WsqmKiUl+6b@zx2c4.com>
X-Original-Sender: jgg@ziepe.ca
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ziepe.ca header.s=google header.b=fRB9gEBB;       spf=pass
 (google.com: domain of jgg@ziepe.ca designates 2607:f8b0:4864:20::833 as
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

On Thu, Oct 06, 2022 at 06:45:25AM -0600, Jason A. Donenfeld wrote:
> Hi Kees,
> 
> On Wed, Oct 05, 2022 at 09:16:50PM -0700, Kees Cook wrote:
> > On Wed, Oct 05, 2022 at 11:48:40PM +0200, Jason A. Donenfeld wrote:
> > > Rather than incurring a division or requesting too many random bytes for
> > > the given range, use the prandom_u32_max() function, which only takes
> > > the minimum required bytes from the RNG and avoids divisions.
> > 
> > Yes please!
> > 
> > Since this is a treewide patch, it's helpful for (me at least) doing
> > reviews to detail the mechanism of the transformation.
> 
> This is hand done. There were also various wrong seds done. And then I'd
> edit the .diff manually, and then reapply it, as an iterative process.
> No internet on the airplane, and oddly no spatch already on my laptop (I
> think I had some Gentoo ocaml issues at some point and removed it?).
> 
> > e.g. I imagine this could be done with something like Coccinelle and
> 
> Feel free to check the work here by using Coccinelle if you're into
> that.

Generally these series are a lot easier to review if it is structured
as a patches doing all the unusual stuff that had to be by hand
followed by an unmodified Coccinelle/sed/etc handling the simple
stuff.

Especially stuff that is reworking the logic beyond simple
substitution should be one patch per subsystem not rolled into a giant
one patch conversion.

This makes the whole workflow better because the hand-done stuff can
have a chance to flow through subsystem trees.

Thanks,
Jason

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/Yz7QN3cbKABexzoB%40ziepe.ca.
