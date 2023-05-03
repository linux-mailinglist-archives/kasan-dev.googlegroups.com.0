Return-Path: <kasan-dev+bncBCS2NBWRUIFBB7G4ZKRAMGQEGR3KNXY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x140.google.com (mail-lf1-x140.google.com [IPv6:2a00:1450:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id 2AAD16F5EAA
	for <lists+kasan-dev@lfdr.de>; Wed,  3 May 2023 20:57:01 +0200 (CEST)
Received: by mail-lf1-x140.google.com with SMTP id 2adb3069b0e04-4f0176dcc4fsf3238986e87.3
        for <lists+kasan-dev@lfdr.de>; Wed, 03 May 2023 11:57:01 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1683140220; cv=pass;
        d=google.com; s=arc-20160816;
        b=AK4cakeBjbFuQEW3B0lpRAxMYLZrz/rBB1DoEFf05oP5t7N7M0ZPqG+Iejo+Hp8ePt
         6zOkTdrRNkiYJhpv5SIUnBFpzRBisnZFMZ8XQCcmcUiFHFAIlmRjsZrQUaJLdT5bT9D7
         d5VTtnE0lhAr/YB+nek52kDGKKjB1iV59arE2rPE8eRkpga7SgpYJqSL2ZU5ROFjKvZE
         2kaQw9qTUR1+lJ9wW5hex4f3Pe8HgdtdoJNjSUdcNT6qRp6pwX71tjPfSPy53A6Ue8NM
         phakXOP9OalBpDxxrWYFhClNfnGxxjgMhMTX3B4+RKMbM/zk4FLx8EayOt1IIInUUTB2
         KXkA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=mucn40EHBD4fDrtISd57DenA+uDEx4vyCQv3EBfG0Kk=;
        b=QIsERkjbntmgl8rZpZDKy3S/U5Aox2zQroRbSQ0IcWSaQVbkJagD+L9Ximz4+8LQUl
         +xAfZYfBqjYx+jwZOmJm4c2gL30VjfGwM5AmVBFC7D0fUtm8L8ZAY97ZLyy5ON8Yf0Bk
         +iPEASJ1tA/TQkda2bWiK7sJynopeNtiWTnkcISbbUA5Pd7/jO6UzubLUuNPTC2qy1Aq
         WSn6VfVPwpieeQdTq60vP7JSR+lTlPofuDoyyD3531WWd4XPQ/VMBSfqFqc6UoJG018e
         Pr13XsRzvo2szyBKSZYaZ7f1TWTAJddIsQQkgx2VIdq022JdGoOgpBVVHEnXB3qYpowa
         etgw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=h1g4T3Qh;
       spf=pass (google.com: domain of kent.overstreet@linux.dev designates 91.218.175.43 as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1683140220; x=1685732220;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=mucn40EHBD4fDrtISd57DenA+uDEx4vyCQv3EBfG0Kk=;
        b=bWJ93dTqcs//hfmOdLrfg9xa4EN0OGzUr18EAHmOGHbSKQRyJTktGuLYlgS+sdFkJA
         5lQxvIQ6JKyOLwJUtSKC7sERGTaxl9RwIJciy9bvNCodGub6dW7O6L0WQuT2tr4zl896
         mqmFefTFisiktz/nZiT3MzZCtfLcfp+Q1Q1XF1FvQ/TeXJ/ykBj/36NmuP/UrySgK1NJ
         pxqIbIb6ff8mxBUBnZ6n89wq9ceav9bIoyBBVHwwdHssYDf3Ysjq7FwEU876N96d0YRu
         x8lBgZDFSCPy7JBW6RzGUKsX9PcpIB4cBJzhkJy1ZhwfY6WzHA8aSofYcxjWjk5nWhVO
         TTWg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1683140220; x=1685732220;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=mucn40EHBD4fDrtISd57DenA+uDEx4vyCQv3EBfG0Kk=;
        b=QnPa8TqIl6c5Qhjv8NmlRnv/zDtBeyh9tNaNANu17jUd8N6cPyIf/3PgzAtranIoYU
         Dip4Zm2/38pJx3SY/qO3dNpSdOX86mOkgaEkORR3X2AClK1QStdFLr9XgpUJlzPjUNoY
         XQUB6UGtnKbV/4PJfh2spscX+vQnOMT89m+gquB9/Jaws1ViNAPlhJiFkitiDaFbW3uw
         VkLI+t1nVda6S6VQH4usvFTT109seqxFHE/vrPLz3NojeZ4tTOQfTZYBldKk4ntNPBrt
         WdZQIPYAeMJmkOU0xeawz464dnBVFiitmSMQbO0HxC4LW7D97KGKTJvdkOF/5L33i+Dx
         Eojw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AC+VfDyeuIn32PIO+1Nujv+vEsBfYrxWon8Gzm1rVHG5tz2vF8Ielrd1
	yyqJ+b+t9qX4AMklKkKtfmc=
X-Google-Smtp-Source: ACHHUZ7xEC+bAbMmhv8LPKwJVfCK7RTXRWcYYbE0F7uQwNhM6DqyKaziPHaaKVCE/M+pzEKe1HhtMA==
X-Received: by 2002:a19:ae1a:0:b0:4ee:d4bd:346b with SMTP id f26-20020a19ae1a000000b004eed4bd346bmr1062029lfc.9.1683140220329;
        Wed, 03 May 2023 11:57:00 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:158d:b0:4ec:6fe6:9f26 with SMTP id
 bp13-20020a056512158d00b004ec6fe69f26ls1449524lfb.0.-pod-prod-gmail; Wed, 03
 May 2023 11:56:59 -0700 (PDT)
X-Received: by 2002:a05:6512:3761:b0:4f0:441:71a4 with SMTP id z1-20020a056512376100b004f0044171a4mr1083043lft.35.1683140218962;
        Wed, 03 May 2023 11:56:58 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1683140218; cv=none;
        d=google.com; s=arc-20160816;
        b=nC6Ffs0Hy0cq27GKLbjO9XTMBJvhGA/w+2OG98N2Az40Q1+l+gRO8d0CB9MzZwAY/F
         UHf5O8hPQH1po1QfJmMCOPRIPkGwbxU8cYDeJRbplvvp6KJfhe+3ZYfVrlA/DVD/WhMS
         B1LuKwrFcJ1mrPDPdS35AlrwMWbIJhKgzVaVnkkvyCP8CNJ4Y3wVjU5NUgGGUljIWUhc
         hUuqFH9tBBkaFDf2BbNnBF4gYw3UG+wYMJQOxLFv5hQVigy+ptLV9VUnXp0FQZyYtJf3
         /8kBebVs/5jEigEFjNaGIrDtSpPMXiyp8JOHu5f3uQJUg3Gpbm2ZgKVjFc0fuIfKBUll
         IMlQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:dkim-signature:date;
        bh=kvDb7bxJfzE9KfjpQKTTQijQZOsAXNXH2iadfpJ44Yc=;
        b=dUlF28W3DgmXJuxckmhA7v5GjOJq6XR+LSZgfmQK3QUpu9wqeHYgTe43mQQc/uJ+dk
         WFDOJE0LKN3pgMoeVcDju6wkL+e2m91biTevpSsPx0Ca0YQfgxjb/QUWzBB/BJP/BxI2
         D+JrDzXP2QUPIDJn6lJCwvYtNVdbe7PunUoAl1ZYrQjivETbiGkmM6FLbjtDuK1x0EhD
         YvpePBEJOqzuFuLsAYXBj5vRawl80i/5xIrUl3Wvo1c/uQnEdjMZ4F035k9N/kYqsIsE
         kmOIPX17TbUywOJxpoFL/bmt/fLOC5FUEQ0Z9CgZNxzXz3mZ1vuSjSw1YZ5F0URbIRyp
         DmRA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=h1g4T3Qh;
       spf=pass (google.com: domain of kent.overstreet@linux.dev designates 91.218.175.43 as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-43.mta0.migadu.com (out-43.mta0.migadu.com. [91.218.175.43])
        by gmr-mx.google.com with ESMTPS id g33-20020a0565123ba100b004efe97e3546si1921453lfv.10.2023.05.03.11.56.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 03 May 2023 11:56:58 -0700 (PDT)
Received-SPF: pass (google.com: domain of kent.overstreet@linux.dev designates 91.218.175.43 as permitted sender) client-ip=91.218.175.43;
Date: Wed, 3 May 2023 14:56:44 -0400
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: Kent Overstreet <kent.overstreet@linux.dev>
To: Tejun Heo <tj@kernel.org>
Cc: Johannes Weiner <hannes@cmpxchg.org>, Michal Hocko <mhocko@suse.com>,
	Suren Baghdasaryan <surenb@google.com>, akpm@linux-foundation.org,
	vbabka@suse.cz, roman.gushchin@linux.dev, mgorman@suse.de,
	dave@stgolabs.net, willy@infradead.org, liam.howlett@oracle.com,
	corbet@lwn.net, void@manifault.com, peterz@infradead.org,
	juri.lelli@redhat.com, ldufour@linux.ibm.com,
	catalin.marinas@arm.com, will@kernel.org, arnd@arndb.de,
	tglx@linutronix.de, mingo@redhat.com, dave.hansen@linux.intel.com,
	x86@kernel.org, peterx@redhat.com, david@redhat.com,
	axboe@kernel.dk, mcgrof@kernel.org, masahiroy@kernel.org,
	nathan@kernel.org, dennis@kernel.org, muchun.song@linux.dev,
	rppt@kernel.org, paulmck@kernel.org, pasha.tatashin@soleen.com,
	yosryahmed@google.com, yuzhao@google.com, dhowells@redhat.com,
	hughd@google.com, andreyknvl@gmail.com, keescook@chromium.org,
	ndesaulniers@google.com, gregkh@linuxfoundation.org,
	ebiggers@google.com, ytcoode@gmail.com, vincent.guittot@linaro.org,
	dietmar.eggemann@arm.com, rostedt@goodmis.org, bsegall@google.com,
	bristot@redhat.com, vschneid@redhat.com, cl@linux.com,
	penberg@kernel.org, iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com,
	glider@google.com, elver@google.com, dvyukov@google.com,
	shakeelb@google.com, songmuchun@bytedance.com, jbaron@akamai.com,
	rientjes@google.com, minchan@google.com, kaleshsingh@google.com,
	kernel-team@android.com, linux-doc@vger.kernel.org,
	linux-kernel@vger.kernel.org, iommu@lists.linux.dev,
	linux-arch@vger.kernel.org, linux-fsdevel@vger.kernel.org,
	linux-mm@kvack.org, linux-modules@vger.kernel.org,
	kasan-dev@googlegroups.com, cgroups@vger.kernel.org,
	Alexei Starovoitov <ast@kernel.org>,
	Andrii Nakryiko <andrii@kernel.org>
Subject: Re: [PATCH 00/40] Memory allocation profiling
Message-ID: <ZFKubD/lq7oB4svV@moria.home.lan>
References: <20230501165450.15352-1-surenb@google.com>
 <ZFIMaflxeHS3uR/A@dhcp22.suse.cz>
 <ZFIOfb6/jHwLqg6M@moria.home.lan>
 <ZFISlX+mSx4QJDK6@dhcp22.suse.cz>
 <ZFIVtB8JyKk0ddA5@moria.home.lan>
 <ZFKNZZwC8EUbOLMv@slm.duckdns.org>
 <20230503180726.GA196054@cmpxchg.org>
 <ZFKlrP7nLn93iIRf@slm.duckdns.org>
 <ZFKqh5Dh93UULdse@slm.duckdns.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <ZFKqh5Dh93UULdse@slm.duckdns.org>
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: kent.overstreet@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=h1g4T3Qh;       spf=pass
 (google.com: domain of kent.overstreet@linux.dev designates 91.218.175.43 as
 permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=linux.dev
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

On Wed, May 03, 2023 at 08:40:07AM -1000, Tejun Heo wrote:
> > Yeah, easy / default visibility argument does make sense to me.
> 
> So, a bit of addition here. If this is the thrust, the debugfs part seems
> rather redundant, right? That's trivially obtainable with tracing / bpf and
> in a more flexible and performant manner. Also, are we happy with recording
> just single depth for persistent tracking?

Not sure what you're envisioning?

I'd consider the debugfs interface pretty integral; it's much more
discoverable for users, and it's hardly any code out of the whole
patchset.

Single depth was discussed previously. It's what makes it cheap enough
to be always-on (saving stack traces is expensive!), and I find the
output much more usable than e.g. page owner.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ZFKubD/lq7oB4svV%40moria.home.lan.
