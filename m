Return-Path: <kasan-dev+bncBCLI747UVAFRBF527OMQMGQEXKOOUBY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x539.google.com (mail-ed1-x539.google.com [IPv6:2a00:1450:4864:20::539])
	by mail.lfdr.de (Postfix) with ESMTPS id CEF985F6881
	for <lists+kasan-dev@lfdr.de>; Thu,  6 Oct 2022 15:50:15 +0200 (CEST)
Received: by mail-ed1-x539.google.com with SMTP id c6-20020a05640227c600b004521382116dsf1641130ede.22
        for <lists+kasan-dev@lfdr.de>; Thu, 06 Oct 2022 06:50:15 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1665064215; cv=pass;
        d=google.com; s=arc-20160816;
        b=Ax3IO4GscfNsduiogzT5op7e7hb9XHK2V/Jd2EX+UUTRlH+QpaN17+aZKoLscbXcuk
         5TLZhdQVDb8CWYPMXr/v4ZGsy9+LU+GAk5vCbXPfz0IU8/3usPUWc8qfWzj3OuSWo6VV
         rYXkbQUcjSSIEdIRQj84QYHGenYBZv1scsf843QpdKI7A98JYgJVP+6RWrIZYwHQ043h
         bwZij54TDUODUbW+3Ij5KBM5TgFQZwiMF9d2cGUpueNBd7LnemTctyQzNQn+VO4vHJrS
         ZT/V9IvbxugTQXsuujKqy/Oiv0TnIOMiu4ZrizWhRjmAHJkEF2+iWJ3qwNzgVmx8HsC+
         XD3g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:to
         :from:date:dkim-signature;
        bh=yqN13mxFYFa+p7WaGDgY76CRKsQcPVIjA5vzbijc5/M=;
        b=ndbVBNjMqCTFM3nAXX3yBt5KA63eQobe8JAjSls7qHbQFMedYcIYWTCKJMHP9jaxCL
         j+nkvw+oaenpIwgWm9NIKxXkZnTtUNh161ZsA941+8Z8zu5X2Ri7UKuBaeBCWeK14sO/
         dauXwnR2wLel8DL8h6xOhzS7+Myu9zH3oRy0bk43R1srQDtkwSvig+PywMzAe4hlqiVF
         YpGj++qtdc/RFAlSenqttsJFjVZjd+PnXm2jDvMtBOD3/j6ly2xqj1cE2AeG4uzhGRXf
         ECO9xB6Cd3XpSro7x1vYWIWznCn9ODPAkNFWkLMAX1No1ZBt76KbppDwnvYXjQTnA3O+
         6EAg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@zx2c4.com header.s=20210105 header.b=XQW+nWRK;
       spf=pass (google.com: domain of srs0=tiop=2h=zx2c4.com=jason@kernel.org designates 145.40.68.75 as permitted sender) smtp.mailfrom="SRS0=tIOp=2H=zx2c4.com=Jason@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=zx2c4.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:to
         :from:date:from:to:cc:subject:date;
        bh=yqN13mxFYFa+p7WaGDgY76CRKsQcPVIjA5vzbijc5/M=;
        b=pgLE6F1dWzZ/AMKhjFQ08vh5IcUCCCtftpjMZOiIWznJ/MMwoPU8/daiHrnKQIOyOL
         m7TTLqzFLR6Jcc0INrceuRmEeVM9FyF6LhKcIoDS+nKwIgEMNc3goGnosKOkqO7GMOzj
         2G4kI3rjRjxrrhnXV7WOuDKwAOIxsPjoP/Uqvp34dAByvPRJYW9NCOmbGHJPeyF3CJPv
         qOU9/NtlLlzTODyBfNpHvqF7UoUp/sLkcOEcSO0qQY37lFUI+TBLUwlUgCQsjxWLFKmL
         NW1hEhbk03BeCDt4awUdLbjqjUBUnbu5y+m3rnQ/ZJXr5p4nlRkM0Tz3PJwrxTdwqNQe
         oxRg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:to
         :from:date:x-gm-message-state:from:to:cc:subject:date;
        bh=yqN13mxFYFa+p7WaGDgY76CRKsQcPVIjA5vzbijc5/M=;
        b=4A12z14l6msgpnpONtnT/gy7NXvoDappaRarYTxisM73sdx3HYFjOSRzv5S5o8puHE
         Ycf68fFkEWI2NUhU/W5pNDwdKjiYqQ/SLSIsQ7MXTsSexE0EZ6C4oefn+hSnLQbxFozs
         Y7WkbXo+wop/IE3iF7k8PIpTLSfPspiJaRiOM+dkkWNSl4aEa8vYfingcaZMYYfBT16U
         edlyLqZxow2ucfl3I+HcRGP8WqJl4HNasZY62L0YD1jPVdPCgR7oX6GKYESNMZ20bT2l
         snieikHU+q0DJKjQ20lxoCu0wlfq7q+1KVuku11tE2Psxxffkd6ZuK78G9kyJv+hcirx
         5fig==
X-Gm-Message-State: ACrzQf0EuIUo5kfcAGOYLzxZ+RjoaEpYksntxmfbCocSjM3BrrAhfj8e
	8/ecU+Wmxe1w5nALfYXybWA=
X-Google-Smtp-Source: AMsMyM7WXiyiMgK/Gl9BbJAUQgLtnBNNC/+4ddY+Q7weVphgVzTxAxBKpwJunp4foD9XwYCFwyOJmw==
X-Received: by 2002:a17:907:1dd7:b0:78d:1fae:d27c with SMTP id og23-20020a1709071dd700b0078d1faed27cmr4118462ejc.519.1665064215473;
        Thu, 06 Oct 2022 06:50:15 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:a3d2:b0:780:f131:b4d9 with SMTP id
 ca18-20020a170906a3d200b00780f131b4d9ls989472ejb.11.-pod-prod-gmail; Thu, 06
 Oct 2022 06:50:14 -0700 (PDT)
X-Received: by 2002:a17:906:328c:b0:780:7574:ced2 with SMTP id 12-20020a170906328c00b007807574ced2mr4061188ejw.634.1665064214430;
        Thu, 06 Oct 2022 06:50:14 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1665064214; cv=none;
        d=google.com; s=arc-20160816;
        b=xpFUepdAxjRB11YsQ7P1kNZ22+SzmCUtnFW6FzjlWOuYT+WeRHEqdKVHl2eYBQ6lA7
         hN2Gx3BO5dnbDZUaCWP3sRm8DPp2UkDmBKxMTSME1TK7hBePHmfo//Hjc4wmCPwjdJo1
         5Y7Vp+5SIX1GCdP/0SW3zpakpp2s6xg9zJE3bHzIhXgRSUXAX5DhrFdY+slzNh+ha4df
         BvfxpmAyDMzAvdHWWIhr/f8tawSqWxrunBISpOOoHYl/roe8DNCjpLzWKVAexi/zmY1Z
         mi+YybzqFfJe2iqs7JpgQEBfip67R79kQ3iBAbDro+lCKHBAQ8nwbqz5xOZZ/5+jKlvg
         f3pg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:to:from:date:dkim-signature;
        bh=mEetLjJ38ygHBekWX+Dw1oorRVmw9Gz/icaPb6ZlUv4=;
        b=DkpZX+kUn190Ye82855ACZ5g6S2QQR0Ym+5bMiqJVtvGEBRTcgbfjBxnA3qavKxQ28
         /Scyl02LH1BXChBM/5WO8YK712O/5E72CpS47t0RJKMTOPQ603h0UEmcRyfyvbVhEcoO
         c7jYPlcmIfxe8njOjQVrYIRXs9PCdI5/hpynEzlwepJR1MVYZd2G2/iEq38uNFiqlJeB
         +tdLFocf1BZTQj/K7dDIILVkiNPX2BXWvTR9qlZ8BTnIRNxZmaoWvSrA1+3UhGUpwywH
         u9N49JRM30zUssyuZGW1+98+vbPAnwpNTIN+Qs8Uj/xt793Niau7QkV74P1DOhfoi4eL
         pdvw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@zx2c4.com header.s=20210105 header.b=XQW+nWRK;
       spf=pass (google.com: domain of srs0=tiop=2h=zx2c4.com=jason@kernel.org designates 145.40.68.75 as permitted sender) smtp.mailfrom="SRS0=tIOp=2H=zx2c4.com=Jason@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=zx2c4.com
Received: from ams.source.kernel.org (ams.source.kernel.org. [145.40.68.75])
        by gmr-mx.google.com with ESMTPS id w20-20020a50fa94000000b00459ff7667fasi20761edr.0.2022.10.06.06.50.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 06 Oct 2022 06:50:14 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=tiop=2h=zx2c4.com=jason@kernel.org designates 145.40.68.75 as permitted sender) client-ip=145.40.68.75;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by ams.source.kernel.org (Postfix) with ESMTPS id C2113B8206F;
	Thu,  6 Oct 2022 13:50:13 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 1536CC433B5;
	Thu,  6 Oct 2022 13:49:57 +0000 (UTC)
Received: by mail.zx2c4.com (ZX2C4 Mail Server) with ESMTPSA id ac8c61f2 (TLSv1.3:TLS_AES_256_GCM_SHA384:256:NO);
	Thu, 6 Oct 2022 13:49:56 +0000 (UTC)
Date: Thu, 6 Oct 2022 07:49:44 -0600
From: "'Jason A. Donenfeld' via kasan-dev" <kasan-dev@googlegroups.com>
To: linux-kernel@vger.kernel.org, Andrew Lunn <andrew@lunn.ch>,
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
	Varun Prakash <varun@chelsio.com>,
	Chuck Lever <chuck.lever@oracle.com>,
	netfilter-devel@vger.kernel.org,
	Masami Hiramatsu <mhiramat@kernel.org>,
	Jiri Olsa <jolsa@kernel.org>, Jan Kara <jack@suse.com>,
	linux-fsdevel@vger.kernel.org,
	Lars Ellenberg <lars.ellenberg@linbit.com>,
	linux-media@vger.kernel.org,
	Claudiu Beznea <claudiu.beznea@microchip.com>,
	Sharvari Harisangam <sharvari.harisangam@nxp.com>,
	linux-doc@vger.kernel.org, linux-mmc@vger.kernel.org,
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
	linux-fbdev@vger.kernel.org, linux-nvme@lists.infradead.org,
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
Subject: Re: [f2fs-dev] [PATCH v1 0/5] treewide cleanup of random integer
 usage
Message-ID: <Yz7c+LqDGjzd2QSd@zx2c4.com>
References: <20221005214844.2699-1-Jason@zx2c4.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20221005214844.2699-1-Jason@zx2c4.com>
X-Original-Sender: jason@zx2c4.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@zx2c4.com header.s=20210105 header.b=XQW+nWRK;       spf=pass
 (google.com: domain of srs0=tiop=2h=zx2c4.com=jason@kernel.org designates
 145.40.68.75 as permitted sender) smtp.mailfrom="SRS0=tIOp=2H=zx2c4.com=Jason@kernel.org";
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

A v2 that won't murder your mail setup is now available here:
https://lore.kernel.org/lkml/20221006132510.23374-1-Jason@zx2c4.com/

Please do not (attempt to) post more replies to v1, as it kicks up a
storm of angry MTAs.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/Yz7c%2BLqDGjzd2QSd%40zx2c4.com.
