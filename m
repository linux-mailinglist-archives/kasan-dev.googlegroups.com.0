Return-Path: <kasan-dev+bncBCF5XGNWYQBRBZ527GMQMGQEA772MOY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x239.google.com (mail-oi1-x239.google.com [IPv6:2607:f8b0:4864:20::239])
	by mail.lfdr.de (Postfix) with ESMTPS id 239505F603F
	for <lists+kasan-dev@lfdr.de>; Thu,  6 Oct 2022 06:45:29 +0200 (CEST)
Received: by mail-oi1-x239.google.com with SMTP id w125-20020aca3083000000b00353f4eef3f8sf413954oiw.18
        for <lists+kasan-dev@lfdr.de>; Wed, 05 Oct 2022 21:45:29 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1665031528; cv=pass;
        d=google.com; s=arc-20160816;
        b=wpN/Y7jRSENaCXG1Kx7Kk0u47hmt6Wy6VAaDl95vF5nDS8l0vaD4BqqH7t3vKPFuX1
         1y4WUdlNt+2xOy+2Ki195wXriU1RvYX5YmdpgiB0eKY+j8L5wkiW3IcuihAPAkkxxwTc
         c4ZotqtCEJgnB+/qLI+4S5ZNmx9SPnu/Fk2BwLlyaFj1LDb1lE8tdfdeCUvjoWe7GLLQ
         GCzR9+IAC8Xn2TD7iOdctTRLARyo1j9th9VQ4UUc/+0B6ApcZm/SlhAFwtdTkw/T/AnE
         OoOxpTNEvlkBruw/xuecd2FWCHASwqr5p666WNqfFTvAsUzxL/EpaY3mzldHBxaiolPz
         3gVg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=bfEqGIsoJM2ABiqiqus8sOUbCV3CRTdiEU76eqqH+cg=;
        b=eYz5gbBRt0GuYCx5DRq5IcYVW8URzEgUthuQhoy+u39SRj41JaCZzAqrAuO+ireut7
         Bgz7FaMoxoQE3eQij7C03uikLKEM/ZwyvJAA3IqOwWGzNm7lbPSIvqGyjeWCDnxEGqf2
         89THS/fJOlxsMmaOWHP1u2AhGuFfviZtFvkRbTe9lpGpzFTHDkRFpMi77ZUzyDS0TUjw
         OUNyJgsl2flL9IxmY5s9grERPUjr3kp5kA8wRah2/qfayNwDbPDk+QQUedM9ohCwqKrR
         c18w/XYbSUEFJOaryiuBIWgdJh31xhor1aAs3eW8UNQkBQrgy1aa9qywGEqaPiZ1kM8v
         gf1g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=Pa5J7iVI;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::42c as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date;
        bh=bfEqGIsoJM2ABiqiqus8sOUbCV3CRTdiEU76eqqH+cg=;
        b=pu8dQbDa06l6FPJuU5rRoMb7xpBQYQanzxjaWLzQw0JF/xbWQ4OG0VFYu6EFJ1Y8TJ
         dKe8FvAVC0FjUPwwk9+TQBVnOvd8ExL7GJvpUK71JdPHeFNDsaOflkeOMxysBsrD7FEj
         wn7nxKxLkKsNNuBTENsCcRiu6j8teL0mMyr50R3kg2TrvuzGCWMSGrgHTdGfi2N3W65o
         M8JbJgo7ilXO1EtexlIPiPo0DoFyaHdaTUAlFPaOqDQdBVAxEGA0d+7Dh0BJ+S00Kzjc
         2zbgdL9spGsjFMInRYEiel81mnDfpBfkVWUYx5lr1bit14l0sxYpJf9XVBR0IT1MJ9Uf
         Ictg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:sender:from:to:cc:subject:date;
        bh=bfEqGIsoJM2ABiqiqus8sOUbCV3CRTdiEU76eqqH+cg=;
        b=o2pbuofurtPXH6LMPx3NWJ5QMnOikqzoXC3bTZLtH7qA/T/QyZUUvMTKjypQyOOaTM
         03msPhq53k+UFWYVABIltva48mGX1tdVbXxtEWtit7gfyoS5bYCcM+HdUXZyuTLV5B42
         B8LnEwP54YEstvGyjkcdHb5s2Rv7iZY6DmP+/Xsnvn4wWxK4/lbOowVIZFAP1HkhXbl8
         +jBgb5t/7P3KQyKD5uXUUTrwGaCc7EkZOrBOq++eo5j3ETPP+US4ld5tlSr7A5Q042BT
         NTf+bL4cRvgHaJhOYKFlp59jVwI2STOLerexRiJi3DOWaJ/sSssW6qTSSrFGX0mHn3gi
         +TAA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf0EXzc398eCkQCD03h7lYgGfVAMbmfMfG0ufrCC08AynsAuqFAP
	Nmmv/n4+sgnFpaDtfyc3ttM=
X-Google-Smtp-Source: AMsMyM5pby4h9feVznZ3Fx4bb9QDgdIoY48i7coinjaRfge3WWjQ5FhB0pvEsHFUnPR98vxkS4uE4Q==
X-Received: by 2002:a05:6808:238c:b0:351:3c64:6bb3 with SMTP id bp12-20020a056808238c00b003513c646bb3mr1445205oib.245.1665031527701;
        Wed, 05 Oct 2022 21:45:27 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:bb83:0:b0:350:a26c:b39c with SMTP id l125-20020acabb83000000b00350a26cb39cls204334oif.4.-pod-prod-gmail;
 Wed, 05 Oct 2022 21:45:27 -0700 (PDT)
X-Received: by 2002:a05:6808:bca:b0:350:b366:157 with SMTP id o10-20020a0568080bca00b00350b3660157mr1551063oik.3.1665031527304;
        Wed, 05 Oct 2022 21:45:27 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1665031527; cv=none;
        d=google.com; s=arc-20160816;
        b=g8BzV2Y1VqlMciV7lRt6SXGWt2i1AkT/c37jkePul8zZlBMzw6/W9BlHuVCOn3NnGJ
         fZwiPUWaTbgNwAZotJBgWVW2NevFVItb2bO9I8r9cL86RjnGn/zBlnwkhMaRpwu9IexL
         uHXzqvINCWX9bnR2XynSiPtpYF+8fJnwIBCewYVmCssIVZJLxkx+WnMNHPYyBsEoSYl5
         EEowJ+zu0wt7PCNkCazbX/KEvCB98qEgWbqQ/4OErkQHiwintOLlBTwwdYuLa/3ZZIaW
         upiRyRNKvs7jJ3oZhGkfyDds8jFP6UIUaCj2OklqeiDDqzUq5kNueiJ69UbQUJuVVyIm
         X8bQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=BXKZz/gOYpFYEK/kvAD1ks5ZMqdWWvWPR9euDTlMinY=;
        b=dJQ+3nJTM8BrpHe5YiFCMZA05Adxav6eGvRqN//CQ+W1CTFchCWAgFjyxvc8swBMHw
         ndiZvCzNe/Rcjp53RvjOtwQmJuDsiVRMC8RLOuu2sWeAd3kWY3L/dDEIaTTEAKhYLMGs
         ORUCQ++FC8CoWH5f95cVgX53n073fIcjhGSsxrOkIZvMYKFMqX7BsZ1fewg7Yfuirqfm
         ecZ0Dd0CIjPK8LT4el9WiQuchnrtMV1sDeZbWVuTTnkrOMgKUsfOr2/FZ9a39fkIRDnk
         ZNRlz59tqt5RJTt8mPZ7n2j2ES19KHmgBO2BoEvcM0LZc15NMzT3mvKdxm7SW5ZI9PcP
         anZQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=Pa5J7iVI;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::42c as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Received: from mail-pf1-x42c.google.com (mail-pf1-x42c.google.com. [2607:f8b0:4864:20::42c])
        by gmr-mx.google.com with ESMTPS id y10-20020a056871010a00b0013191afecb8si710809oab.2.2022.10.05.21.45.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 05 Oct 2022 21:45:27 -0700 (PDT)
Received-SPF: pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::42c as permitted sender) client-ip=2607:f8b0:4864:20::42c;
Received: by mail-pf1-x42c.google.com with SMTP id i3so997385pfk.9
        for <kasan-dev@googlegroups.com>; Wed, 05 Oct 2022 21:45:27 -0700 (PDT)
X-Received: by 2002:a63:290:0:b0:43c:20be:9f48 with SMTP id 138-20020a630290000000b0043c20be9f48mr2776168pgc.388.1665031526658;
        Wed, 05 Oct 2022 21:45:26 -0700 (PDT)
Received: from www.outflux.net (smtp.outflux.net. [198.145.64.163])
        by smtp.gmail.com with ESMTPSA id c144-20020a621c96000000b0054ee4b632dasm11702656pfc.169.2022.10.05.21.45.23
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 05 Oct 2022 21:45:24 -0700 (PDT)
Date: Wed, 5 Oct 2022 21:45:22 -0700
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
Subject: Re: [PATCH v1 4/5] treewide: use get_random_bytes when possible
Message-ID: <202210052144.5DA3690D@keescook>
References: <20221005214844.2699-1-Jason@zx2c4.com>
 <20221005214844.2699-5-Jason@zx2c4.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20221005214844.2699-5-Jason@zx2c4.com>
X-Original-Sender: keescook@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=Pa5J7iVI;       spf=pass
 (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::42c
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

On Wed, Oct 05, 2022 at 11:48:43PM +0200, Jason A. Donenfeld wrote:
> The prandom_bytes() function has been a deprecated inline wrapper around
> get_random_bytes() for several releases now, and compiles down to the
> exact same code. Replace the deprecated wrapper with a direct call to
> the real function.

Global search/replace matches. :)

Reviewed-by: Kees Cook <keescook@chromium.org>

-- 
Kees Cook

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/202210052144.5DA3690D%40keescook.
