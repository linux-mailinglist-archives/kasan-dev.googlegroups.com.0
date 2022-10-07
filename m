Return-Path: <kasan-dev+bncBCR45TXBS4JBBO7B76MQMGQEC2VLXLQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x339.google.com (mail-wm1-x339.google.com [IPv6:2a00:1450:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id 217BF5F7630
	for <lists+kasan-dev@lfdr.de>; Fri,  7 Oct 2022 11:26:20 +0200 (CEST)
Received: by mail-wm1-x339.google.com with SMTP id r186-20020a1c44c3000000b003c3c4e60e72sf47886wma.6
        for <lists+kasan-dev@lfdr.de>; Fri, 07 Oct 2022 02:26:20 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1665134779; cv=pass;
        d=google.com; s=arc-20160816;
        b=ZwqmltF3EmGloiKm/MTHD7I060pQsfw2uL5Fn/Lxo5cuMIkqVDyqNgGBx/0EvU2XeL
         QjMN9R7PglfV7t5/ox5iHt2sy5f9wCgZYq4Q4D3FId5mNOC3fToqYQ7Q4tOA8WxOKq4u
         TA+y1XXK9V8SJ4w/vxffGhULaCabGVxL+V4mrZrNElZAROW+YF6O5z60Clnm1ZcPW16B
         ZuVcdAllCo8E/f4aBncS393zp8OHIBzyEfMSs4crx76C+sik++4CRlM5JjnXZrCUsm31
         MLwzRpff1dZhHiA0AT/sPwd50sn4isKsa0mDfg1Ir31WWwECcN7y9Pm4oNA+4T58cWH6
         tcxg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=x5yHa/s8BLN556BXeXMi2TWes3rgBPYM34bQ4LXk4pg=;
        b=aSGX35RYUoroJRfILTH1AU4/DZT6h9s/g+vTrsxCLEs1DDrjkREFS8PW71si6FSBvq
         e113BQ0QxqPGIPglxztcxK7uF/qEgs98326onI0AhWhGVDjr6jcDKepeblX/OU/d7jSv
         K+1WQ8AWuwcTw1eXLedyBVkGujHl+jZ2VvMqX6jFWqaMgDfOELr2FL6JAFG+mMZm8ML1
         wsFIYFzcKrQDKpC9yrYKPSWMYrrAfcK5Gh3/RgrSK+BUtZvSRDH+3jf4Lp9MSbboOt77
         7HDQvQ4vEB/ENy+eY94LvheaSnaV2Ayheqpm8ft9RNDXPLXzoUbt1pQA6CbVwkj8ZqJd
         Cobw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=g2BSeu9T;
       spf=pass (google.com: best guess record for domain of mika.westerberg@linux.intel.com designates 192.55.52.151 as permitted sender) smtp.mailfrom=mika.westerberg@linux.intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=x5yHa/s8BLN556BXeXMi2TWes3rgBPYM34bQ4LXk4pg=;
        b=bT5cJPHrjQ/7Kzv19qXL5yVV5QHTDXR6oMHh006mEOdq70fDGAUKHFOZlHJ7YEAJGg
         kGVbEYB+EDbUuXuB6KNLz4WTh+Rbutp+WO6+Ca5WfXXOi+kntOWkOTk0P3O913peRoTm
         obuYhNbR3yieaqkF3WAzm1MUVKWDgRrQAiVv3OglP9HnYODd0KSK3SKou4c9dUQstWfU
         YV84S35Hck5zZk9HlKYpKm4nXYATzADAA3FKLQze4fqVcw7oMyHHkwO365vyX5xHioZL
         ip1YJtV1omaKlAr43bzEh3VHyXRKLSU0DJhYBb+DDAE/GpgJoMN/93Cj4unoIUD3Kcv5
         NlJg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=x5yHa/s8BLN556BXeXMi2TWes3rgBPYM34bQ4LXk4pg=;
        b=Vl4UJhxNRte6F2yKEl9o/nMTiPtaA60bJZxp7Wuy9+5sS9XodUQ5MtF+ZHsCCS3a1e
         CFZ2jopJrEhsX7KZMonYhS+jrOBmfQ698J1AxPbuLKWasCjGKMYvT8NHet3Ecm71JzjV
         Qxi0UQaqt8xonnJIhf/4odETxBwOUVMjKEbAf+3tfFvoYDwjYBBd54AyHHsu3qRmxdJy
         JtlWcR1dEnX2AaTlJjborsvxa9JCf+/hRx3kzVmxScZuonA0zoapKAYXwRIkBbfJt3fw
         nMJBOEwdmrrqaHr6Zg1JfXOFMgd+a2vhXLhaAVTN24zSWlDvCwzLANqryOux/W9VKZek
         bxyA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf3OOJAFO6+OraJIpU84lGqCZH5ks9bz1LZALen4iQlxD3DfZgQL
	C688rsK6nq3gIsXluDBlXYI=
X-Google-Smtp-Source: AMsMyM52niJFnp5KLO9Z6RoD4I+VPnBM73VEoXlCi10LPPIKYcjk6MPprA8qEAy8jlPFIleZkkl7ag==
X-Received: by 2002:a05:600c:430b:b0:3bd:fb21:4297 with SMTP id p11-20020a05600c430b00b003bdfb214297mr2735212wme.85.1665134779677;
        Fri, 07 Oct 2022 02:26:19 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:d22a:0:b0:228:ddd7:f40e with SMTP id k10-20020adfd22a000000b00228ddd7f40els7398876wrh.3.-pod-prod-gmail;
 Fri, 07 Oct 2022 02:26:18 -0700 (PDT)
X-Received: by 2002:adf:e309:0:b0:22c:c332:9af7 with SMTP id b9-20020adfe309000000b0022cc3329af7mr2612038wrj.217.1665134778420;
        Fri, 07 Oct 2022 02:26:18 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1665134778; cv=none;
        d=google.com; s=arc-20160816;
        b=wDxfmZIKeq8PhoJ77Uh6Vjp+vBTea5Pf0dBo5LkT9P9S0++Wh6DOEJA6DCHRW878zj
         GDieQOeR7l512yr0oTzBhjLoRr6zuUTVAImqEofNPcjwZ1xe/GmeR++OwdViF1KhSLYj
         GPKX7pONbDp95rupAjJfRZQpsORbxO2JKySYVuwiZ1ec8LsMkIPqkt5YXs2aIQSK0IT+
         9nDcNivJmm7TBAZw1q/VYaeou4wpnnRfrdaRTBdDO+nc4R7H9rf1B5EAKE4dENSV8G0F
         Fxaz6RT2Pp3gHZX1dYlt8vFsT6fy9bDTVlAi/gMb8fqNWmcETUI/8ZpFA1Bu7UqMb0H2
         G+ow==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=3YwzY3MP3YPbdRqSCGhY8rNr9yTTo5n2KnyGfml5P4s=;
        b=cWsoLnr1v+ZrlAaT5NiUTRhdwwoGwT6nsPv4Vm8qLFFNa2uprDyoTkXxjbxGTxeoK7
         AhyXxnBUYdPXZciAzGhiQGImhHjNeggBOyvp9RxQBcEQ52709UY7J3ETFsmX3s+BJ114
         3BAivU/z7BYEzfGsMuC/F/fcjO45KIi7notuhQtzhgWuGcffO0d57CE+5bJ8SK0wcGcT
         LW2zq0hiDyvA0dEwB5nzNDrQI291YdR30hgYAZzeFvl0XdHqyLHEFdHlEK31eIVFVUfm
         v+0/uc8yyzAhncUQx5uXZXDbjMMw5nVtCeBObY7jT5W0PsPvfY5RtHIdLKdq/ml3KbfX
         ZNZw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=g2BSeu9T;
       spf=pass (google.com: best guess record for domain of mika.westerberg@linux.intel.com designates 192.55.52.151 as permitted sender) smtp.mailfrom=mika.westerberg@linux.intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mga17.intel.com (mga17.intel.com. [192.55.52.151])
        by gmr-mx.google.com with ESMTPS id o2-20020a05600c058200b003be9f3ef216si71588wmd.1.2022.10.07.02.26.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 07 Oct 2022 02:26:18 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of mika.westerberg@linux.intel.com designates 192.55.52.151 as permitted sender) client-ip=192.55.52.151;
X-IronPort-AV: E=McAfee;i="6500,9779,10492"; a="284063789"
X-IronPort-AV: E=Sophos;i="5.95,166,1661842800"; 
   d="scan'208";a="284063789"
Received: from orsmga007.jf.intel.com ([10.7.209.58])
  by fmsmga107.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 07 Oct 2022 02:26:16 -0700
X-ExtLoop1: 1
X-IronPort-AV: E=McAfee;i="6500,9779,10492"; a="620199690"
X-IronPort-AV: E=Sophos;i="5.95,166,1661842800"; 
   d="scan'208";a="620199690"
Received: from black.fi.intel.com ([10.237.72.28])
  by orsmga007.jf.intel.com with ESMTP; 07 Oct 2022 02:26:03 -0700
Received: by black.fi.intel.com (Postfix, from userid 1001)
	id 6645E17E; Fri,  7 Oct 2022 12:26:23 +0300 (EEST)
Date: Fri, 7 Oct 2022 12:26:23 +0300
From: Mika Westerberg <mika.westerberg@linux.intel.com>
To: "Jason A. Donenfeld" <Jason@zx2c4.com>
Cc: linux-kernel@vger.kernel.org, patches@lists.linux.dev,
	Andreas Noever <andreas.noever@gmail.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Andy Shevchenko <andriy.shevchenko@linux.intel.com>,
	Borislav Petkov <bp@alien8.de>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Christoph B??hmwalder <christoph.boehmwalder@linbit.com>,
	Christoph Hellwig <hch@lst.de>,
	Christophe Leroy <christophe.leroy@csgroup.eu>,
	Daniel Borkmann <daniel@iogearbox.net>,
	Dave Airlie <airlied@redhat.com>,
	Dave Hansen <dave.hansen@linux.intel.com>,
	"David S . Miller" <davem@davemloft.net>,
	Eric Dumazet <edumazet@google.com>, Florian Westphal <fw@strlen.de>,
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
	"H . Peter Anvin" <hpa@zytor.com>,
	Heiko Carstens <hca@linux.ibm.com>, Helge Deller <deller@gmx.de>,
	Herbert Xu <herbert@gondor.apana.org.au>,
	Huacai Chen <chenhuacai@kernel.org>,
	Hugh Dickins <hughd@google.com>, Jakub Kicinski <kuba@kernel.org>,
	"James E . J . Bottomley" <jejb@linux.ibm.com>,
	Jan Kara <jack@suse.com>, Jason Gunthorpe <jgg@ziepe.ca>,
	Jens Axboe <axboe@kernel.dk>,
	Johannes Berg <johannes@sipsolutions.net>,
	Jonathan Corbet <corbet@lwn.net>,
	Jozsef Kadlecsik <kadlec@netfilter.org>,
	KP Singh <kpsingh@kernel.org>, Kees Cook <keescook@chromium.org>,
	Marco Elver <elver@google.com>,
	Mauro Carvalho Chehab <mchehab@kernel.org>,
	Michael Ellerman <mpe@ellerman.id.au>,
	Pablo Neira Ayuso <pablo@netfilter.org>,
	Paolo Abeni <pabeni@redhat.com>,
	Peter Zijlstra <peterz@infradead.org>,
	Richard Weinberger <richard@nod.at>,
	Russell King <linux@armlinux.org.uk>, Theodore Ts'o <tytso@mit.edu>,
	Thomas Bogendoerfer <tsbogend@alpha.franken.de>,
	Thomas Gleixner <tglx@linutronix.de>, Thomas Graf <tgraf@suug.ch>,
	Ulf Hansson <ulf.hansson@linaro.org>,
	Vignesh Raghavendra <vigneshr@ti.com>,
	WANG Xuerui <kernel@xen0n.name>, Will Deacon <will@kernel.org>,
	Yury Norov <yury.norov@gmail.com>, dri-devel@lists.freedesktop.org,
	kasan-dev@googlegroups.com, kernel-janitors@vger.kernel.org,
	linux-arm-kernel@lists.infradead.org, linux-block@vger.kernel.org,
	linux-crypto@vger.kernel.org, linux-doc@vger.kernel.org,
	linux-fsdevel@vger.kernel.org, linux-media@vger.kernel.org,
	linux-mips@vger.kernel.org, linux-mm@kvack.org,
	linux-mmc@vger.kernel.org, linux-mtd@lists.infradead.org,
	linux-nvme@lists.infradead.org, linux-parisc@vger.kernel.org,
	linux-rdma@vger.kernel.org, linux-s390@vger.kernel.org,
	linux-um@lists.infradead.org, linux-usb@vger.kernel.org,
	linux-wireless@vger.kernel.org, linuxppc-dev@lists.ozlabs.org,
	loongarch@lists.linux.dev, netdev@vger.kernel.org,
	sparclinux@vger.kernel.org, x86@kernel.org,
	Toke H??iland-J??rgensen <toke@toke.dk>,
	Chuck Lever <chuck.lever@oracle.com>, Jan Kara <jack@suse.cz>
Subject: Re: [PATCH v3 3/5] treewide: use get_random_u32() when possible
Message-ID: <Yz/wv0sqBR+J+jy+@black.fi.intel.com>
References: <20221006165346.73159-1-Jason@zx2c4.com>
 <20221006165346.73159-4-Jason@zx2c4.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20221006165346.73159-4-Jason@zx2c4.com>
X-Original-Sender: mika.westerberg@linux.intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=g2BSeu9T;       spf=pass
 (google.com: best guess record for domain of mika.westerberg@linux.intel.com
 designates 192.55.52.151 as permitted sender) smtp.mailfrom=mika.westerberg@linux.intel.com;
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

On Thu, Oct 06, 2022 at 10:53:44AM -0600, Jason A. Donenfeld wrote:
>  drivers/thunderbolt/xdomain.c                  |  2 +-

Acked-by: Mika Westerberg <mika.westerberg@linux.intel.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/Yz/wv0sqBR%2BJ%2Bjy%2B%40black.fi.intel.com.
