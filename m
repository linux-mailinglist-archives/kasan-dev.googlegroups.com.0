Return-Path: <kasan-dev+bncBCM2HQW3QYHRBSMWVD3QKGQEBOKAGTA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb38.google.com (mail-yb1-xb38.google.com [IPv6:2607:f8b0:4864:20::b38])
	by mail.lfdr.de (Postfix) with ESMTPS id 46AD11FCD3F
	for <lists+kasan-dev@lfdr.de>; Wed, 17 Jun 2020 14:23:38 +0200 (CEST)
Received: by mail-yb1-xb38.google.com with SMTP id b135sf2311082yba.11
        for <lists+kasan-dev@lfdr.de>; Wed, 17 Jun 2020 05:23:38 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1592396617; cv=pass;
        d=google.com; s=arc-20160816;
        b=ELqs8veiVcHrqa+hQAqd00RiI+JEbHK0h74MkR6TglX1hNbIp4o28mdNwz6YkU7WFQ
         LScdFCeMyRsMfsbBcsDhu8iVONazNciPcAFEt5Vc3BDH2mF5vG5VRifckPIaOzdHkhNh
         ndQQqoM+VCG46QngxaNL7h+0BaOLTDTLh7c3ezc6CbR5mAs+B0+F3Nn3ELP0+9T5Wsxz
         7iH1h61ZhbMUy99DQIQJzoemQwqNUmibqElv/B+0CvL7jFEgGIf3MUMx0Ewh9XnDHTNd
         vtaMVtgf4qOCFh3Of9WijoOuGFxQ0FK5TZAbTo6VaccyotphOO7Z/WU4CrBlPrFLZSBd
         SsaQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=C9o+94MQij/4gUg40kc8MPomKmsmgpezmNysm7T0iAQ=;
        b=Ala9U/htHOl94u7GtGaRCONtbBy9GPN05+sPg2ryXvBUMr6Ww0wMn7UbCPpG/6yaL7
         HUxKKpCva14VgJ1M6gQId145iUv0ioer3DH9L0hoIns7WIBgkAO86jCHcMMrZavG2BHk
         veQ+LTsez/wZrh13mXNFjyvkgR6nfpVVNiwqpL/KUsknW6bihR+0eU96uKI9K+3fbNXp
         9Digg169R1XtIhCJmWyzg8LLCPMK/SB3lai1QEGRZYExz0FODFMR9eBFN6qXrqAT0J7B
         4hBm99Ddtwh34BnPixqmm5dXv00PEh7Uq0CqGzA6bwqsbdFl367C26ac0XE0StxpE4vW
         1WUA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=bombadil.20170209 header.b=IQBU2NQm;
       spf=pass (google.com: best guess record for domain of willy@infradead.org designates 2607:7c80:54:e::133 as permitted sender) smtp.mailfrom=willy@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=C9o+94MQij/4gUg40kc8MPomKmsmgpezmNysm7T0iAQ=;
        b=ZrsgU4b2sSdnA1n4T8UJBoUuQgxdft9o+akBBv+X4RM2Ztu0DjWsaQE5Jl2le/0zhB
         VkAgo2mnfIob0jceAjmoAQFumdea1h1L7kaMH9xBVkeK2k5Rc61oOnar+4mFO2zjgzxV
         q+WYUywiHuZ194bxwF8YEOKZkEPNiqQZVknU5yOph0oeFgWfi+SDQqsulCBEhjYJODsd
         BOLgbQADUhiOG86gL30zpmRM4/0gYVPeZD4IqG1PewMfqVPzLzK7j+8YYHXGtN0XFN9X
         VJ545IwAVR1ZyZfFjvrTc9hx3A3ngC4Z+WLFSEnqB6ORSkVfibr/XdKp1FO5o4enxxUC
         FNMQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=C9o+94MQij/4gUg40kc8MPomKmsmgpezmNysm7T0iAQ=;
        b=b+tx/0cYV1/AJGU5NmInltMdbAQxBeypBQaYP9GNc4upqQaogSBhMJKU/GlD0npHEK
         bNkoj0rKcF/IeFvzPyEmltGaDUz4BpwB7EUVKqbmmidWH97NM+/izeHtvBQeHZsnTQbN
         4QOYkAGwUyMq/QJculos+p0z864D7Bp8KW2ZwWnwmYhe7p9HLp4XV1913D6FlEHgGgyK
         3FlifO9qqEsk3G4rSruvHtQKJVAfkwxS3MDCeQRRkc6+94TU/T+FATElvDFTalINKfhl
         WDzZIFL/s+WGQ9FFgToP3Z2O0XfkBJ22kR+YP4x7K/uLntzU5DdyK/1tAeDyYhBm6bLZ
         voNQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532dnojHCOIfvPevilguEKUOxICRv059b1tbnXfVFh2SgBgLNMPs
	S9AvP5V6cMrF6/qlRM1kCAw=
X-Google-Smtp-Source: ABdhPJx9ZoWLLVdgPSXhLlPO/ZzYRR68K9DyWm0P8WWg5tWggVCq91H95/MZFu3ARTIuyjRr0AGOhg==
X-Received: by 2002:a25:686:: with SMTP id 128mr12230265ybg.284.1592396617315;
        Wed, 17 Jun 2020 05:23:37 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:3412:: with SMTP id b18ls832503yba.8.gmail; Wed, 17 Jun
 2020 05:23:37 -0700 (PDT)
X-Received: by 2002:a25:af06:: with SMTP id a6mr13439618ybh.271.1592396617019;
        Wed, 17 Jun 2020 05:23:37 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1592396617; cv=none;
        d=google.com; s=arc-20160816;
        b=zme9JEBJutlbasdO07OlF+/+HmqyC3psctlf1odoKdOuYnYTT3YrE2NuBTAwSyDQJv
         iFNqizzlb6MkaCJsDhGRO7kUNw1XJHKs42+S+ZAIHePb7caQZPdZt2FuwFZPoUZPZDc9
         wwLYj9qcbJLqqeVXiUxO5RaRcg25pzEpgxyn9xT/x09nK3DofbJS2OzOwcmnqr+nMucV
         GgDCoS/AmDkAKZaJ2M9wcvVY7pfZoSGck2ch9SGokMUf4MpSDIHVQOLGwCd+gvn8Yudn
         ciS+E81JlqADEE3/OmsI2s5Psmm2ZDF+J/oUCJpE0P398qpq68qZmTwkZUQw6X260UXK
         MMGw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=kuxQjzZYMs0tFNd2RWRJXl84IRXkLYtgdsZsfAqzUYg=;
        b=QFESzbPMyilYakKDThk+RmGVkCCmdT0NaY633N2e1lmuwX/c+DcOmvc8lGtpspy4u/
         QKz/wnbr9srn7Av+shlKqheWzvwETy+mR91nyxmosLMg/EnuRSR4TXVioiPQpwOHLSvk
         2Qk4zPzO3sBLc/UXZRiAU3OYQgh0Y2+cklIVNKIgYPhJkmxdt2uS7LDNA1oJ4wWaYM9H
         +2r75UxRZfY1LszBq2NQIkfRSmI+qSgQ1oiIn/Uy5nctjrusyV1QvlnQMjRUrxQTvUAE
         bRvTgK56PIelBl4kFdiO9HcjdVefISzVCxKwk+DdeoFST5sgzVZ7xkrfxhBmfprSGQZA
         wupA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=bombadil.20170209 header.b=IQBU2NQm;
       spf=pass (google.com: best guess record for domain of willy@infradead.org designates 2607:7c80:54:e::133 as permitted sender) smtp.mailfrom=willy@infradead.org
Received: from bombadil.infradead.org (bombadil.infradead.org. [2607:7c80:54:e::133])
        by gmr-mx.google.com with ESMTPS id u126si1545305ybg.0.2020.06.17.05.23.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 17 Jun 2020 05:23:36 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of willy@infradead.org designates 2607:7c80:54:e::133 as permitted sender) client-ip=2607:7c80:54:e::133;
Received: from willy by bombadil.infradead.org with local (Exim 4.92.3 #3 (Red Hat Linux))
	id 1jlX69-0005Xm-3Z; Wed, 17 Jun 2020 12:23:21 +0000
Date: Wed, 17 Jun 2020 05:23:21 -0700
From: Matthew Wilcox <willy@infradead.org>
To: Michal Hocko <mhocko@kernel.org>
Cc: dsterba@suse.cz, Joe Perches <joe@perches.com>,
	Waiman Long <longman@redhat.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	David Howells <dhowells@redhat.com>,
	Jarkko Sakkinen <jarkko.sakkinen@linux.intel.com>,
	James Morris <jmorris@namei.org>,
	"Serge E. Hallyn" <serge@hallyn.com>,
	Linus Torvalds <torvalds@linux-foundation.org>,
	David Rientjes <rientjes@google.com>,
	Johannes Weiner <hannes@cmpxchg.org>,
	Dan Carpenter <dan.carpenter@oracle.com>,
	"Jason A . Donenfeld" <Jason@zx2c4.com>, linux-mm@kvack.org,
	keyrings@vger.kernel.org, linux-kernel@vger.kernel.org,
	linux-crypto@vger.kernel.org, linux-pm@vger.kernel.org,
	linux-stm32@st-md-mailman.stormreply.com,
	linux-amlogic@lists.infradead.org,
	linux-mediatek@lists.infradead.org, linuxppc-dev@lists.ozlabs.org,
	virtualization@lists.linux-foundation.org, netdev@vger.kernel.org,
	linux-ppp@vger.kernel.org, wireguard@lists.zx2c4.com,
	linux-wireless@vger.kernel.org, devel@driverdev.osuosl.org,
	linux-scsi@vger.kernel.org, target-devel@vger.kernel.org,
	linux-btrfs@vger.kernel.org, linux-cifs@vger.kernel.org,
	linux-fscrypt@vger.kernel.org, ecryptfs@vger.kernel.org,
	kasan-dev@googlegroups.com, linux-bluetooth@vger.kernel.org,
	linux-wpan@vger.kernel.org, linux-sctp@vger.kernel.org,
	linux-nfs@vger.kernel.org, tipc-discussion@lists.sourceforge.net,
	linux-security-module@vger.kernel.org,
	linux-integrity@vger.kernel.org
Subject: Re: [PATCH v4 0/3] mm, treewide: Rename kzfree() to kfree_sensitive()
Message-ID: <20200617122321.GJ8681@bombadil.infradead.org>
References: <20200616015718.7812-1-longman@redhat.com>
 <fe3b9a437be4aeab3bac68f04193cb6daaa5bee4.camel@perches.com>
 <20200616230130.GJ27795@twin.jikos.cz>
 <20200617003711.GD8681@bombadil.infradead.org>
 <20200617071212.GJ9499@dhcp22.suse.cz>
 <20200617110820.GG8681@bombadil.infradead.org>
 <20200617113157.GM9499@dhcp22.suse.cz>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20200617113157.GM9499@dhcp22.suse.cz>
X-Original-Sender: willy@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=bombadil.20170209 header.b=IQBU2NQm;
       spf=pass (google.com: best guess record for domain of
 willy@infradead.org designates 2607:7c80:54:e::133 as permitted sender) smtp.mailfrom=willy@infradead.org
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

On Wed, Jun 17, 2020 at 01:31:57PM +0200, Michal Hocko wrote:
> On Wed 17-06-20 04:08:20, Matthew Wilcox wrote:
> > If you call vfree() under
> > a spinlock, you're in trouble.  in_atomic() only knows if we hold a
> > spinlock for CONFIG_PREEMPT, so it's not safe to check for in_atomic()
> > in __vfree().  So we need the warning in order that preempt people can
> > tell those without that there is a bug here.
> 
> ... Unless I am missing something in_interrupt depends on preempt_count() as
> well so neither of the two is reliable without PREEMPT_COUNT configured.

preempt_count() always tracks whether we're in interrupt context,
regardless of CONFIG_PREEMPT.  The difference is that CONFIG_PREEMPT
will track spinlock acquisitions as well.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200617122321.GJ8681%40bombadil.infradead.org.
