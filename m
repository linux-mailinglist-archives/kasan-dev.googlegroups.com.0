Return-Path: <kasan-dev+bncBAABBG7J4XAAMGQE4GZSYJI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13b.google.com (mail-il1-x13b.google.com [IPv6:2607:f8b0:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id 88632AAAD3F
	for <lists+kasan-dev@lfdr.de>; Tue,  6 May 2025 04:31:57 +0200 (CEST)
Received: by mail-il1-x13b.google.com with SMTP id e9e14a558f8ab-3d43541a706sf45079885ab.1
        for <lists+kasan-dev@lfdr.de>; Mon, 05 May 2025 19:31:57 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1746498716; cv=pass;
        d=google.com; s=arc-20240605;
        b=WBTPT/fALrnEdxFS5g3AmIPiXaaf4DqT5wQTm7WjjI4OuCJhqR0uLZ0hoiw9Rx9bob
         GxUG5T0D0KTbGyf6WC09onQilsZbBi4jVpN0Db6w4TXMpg0RIqd6d/JpCqeakg7p/7hP
         YTGPg92BDNcrkkt5kHd5A7L/+Hb3ve5L/nvbk0i5dHVzcNa8fB0wPjVhTPwXjvhlNXmP
         1vMOIJY74wzX4ajb7P3+9stRgeaGgVyym0FcMjQ1c/jjOANbi4z17Swdrp/n6xe3PpZm
         rjOcVm33HySpOsAmdFJLdFLe7afasEHTIsm7/lZY/9jVyj0jPhWpn2x0gTaC7H1fTCE7
         1HKw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:feedback-id:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:ex-qq-recipientcnt
         :sender:dkim-signature;
        bh=bSWDsu9YjZjKLcqPhLO/rh9loq59FmKOZeq9Q/lknaM=;
        fh=hXW2pGl0CHhO2VojsLGzJY+H+vyoviSoHLMQr+dUel8=;
        b=kAO65qt7Yg9rAhju0C33KxRBgr/vpxHt3YehDjHAafd6Nivchb7Cc+f05daoPGgXxF
         lrBq2TIsordMSS3p5IV1yzt/uKFJtUVpbLX5vePyoiERIS4Uk1wjuJMqJKfkYqYuWAOH
         8e+uYOjWoeIqFfrMcATqXcluKOJEIc6QlHnlidWxp1wF87C/IX9iFqUBru/W76PmXU13
         QWyfQFoZc7UpMdKW38Dv2fpw9Y//J7FsP/c4Km0bEoVgZL87Tk37LJDYcr8vrOOAELrX
         kf9A56DNFofPAR0Xc0AJhfBdDgWsv+kuKtTixJweLpygauMKFkn5KRNethvWsn2Nm5j0
         7h8g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@uniontech.com header.s=onoh2408 header.b=kafLiDKX;
       spf=pass (google.com: domain of chenlinxuan@uniontech.com designates 54.254.200.92 as permitted sender) smtp.mailfrom=chenlinxuan@uniontech.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=uniontech.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1746498716; x=1747103516; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:feedback-id:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:ex-qq-recipientcnt:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=bSWDsu9YjZjKLcqPhLO/rh9loq59FmKOZeq9Q/lknaM=;
        b=tjqrLMCBwlBT99jyxYZIaJHFMPO4CBptmxBJuY7UagBOE8eX9kzve2mjFPd2Lelx6W
         as6kMcijZs3hu0oj0rJvBWqUphRK4Ho6Sqy2wJ2levdy8Wyrm4+NkAJ7UjUtn26/K6jZ
         +ERfr4XNrCMd+Phmr9shKh3BnDbBGQwh6IC/tBZ7KBsYFwVZRv4fMF4ZgkCGThWNqSud
         gnzQs0lFDw99B/85EW2B8RCsHJDgl5dVDQCu0X7XEjRxx6jf0E55k+9Cj0+BweXxxjWg
         ywwnroomikDxO9goUsQXnDgDU+B8zGD/S/kK6Bzysbg9H/P5CxMoiC62SJ7kF0C4Q+Bx
         sYFA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1746498716; x=1747103516;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:feedback-id
         :mime-version:references:in-reply-to:message-id:date:subject:cc:to
         :from:ex-qq-recipientcnt:x-beenthere:x-gm-message-state:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=bSWDsu9YjZjKLcqPhLO/rh9loq59FmKOZeq9Q/lknaM=;
        b=cpUMVtQDlY8HZE/MedDAOaEIFX4nDXFbKHvhqWm7QInb7HHWhmVyYXfil2fgsa1Rx3
         AGS0aIWdLjBZA+xi9OgD+6N7aE5r2S2buZ4EFkvDaFQILT7QjmxRMEy4iXKGd6JldG45
         KLqtdSgIPloCWpxVU7iV/okowYKR92yYoj/iQM/IivGMQqS7rzxxuwahdkYRIKcrptJK
         +AWdkjaxijFUTV9wqar1DZh3m6Cva9cugUhp/eViDflLGYIWXiEdgyfyYKRSrlLy11nQ
         lTFraiwZY1sP1EN+BsQzU2Pv5kvXUPLV8FcM65+OCBOX+/zinhBZrkuhAQHmP8IgEK5o
         J7bA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXsxE3eOOfPpgEmaaRek4Xm8cfSgwQ1LekxyzBioJyPMSlzEgwkgBIN1+eCSWX0pJplSgRvdQ==@lfdr.de
X-Gm-Message-State: AOJu0YyLV47BQ51HlmjhmiWKwLqR6t6huzTV4Zi4DYlPat5W39USEwwr
	M2SKY67l/bhoF9c2LXtvo9Ic9S9vBjcDq74uBaBsE+89Mq0QQ+vj
X-Google-Smtp-Source: AGHT+IGKv8OhHRjICAkzo4diRtaabkP1ekNsDO36PqkAz1AZJMbpn0qz35C5k1HZ8sGIz9VRyKu/yg==
X-Received: by 2002:a05:6e02:378a:b0:3d3:dfb6:2203 with SMTP id e9e14a558f8ab-3da5b34518cmr93143445ab.19.1746498715783;
        Mon, 05 May 2025 19:31:55 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AVT/gBH2X/t3mYHCX/ELcUKyNridTLJAEnlV85grRBnXYzzPWw==
Received: by 2002:a05:6e02:16c5:b0:3d8:b690:4e94 with SMTP id
 e9e14a558f8ab-3d96e714729ls11432455ab.0.-pod-prod-09-us; Mon, 05 May 2025
 19:31:55 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCU8xkB0RxPaRzcbNQAEiRVzRHKQvWVTkh6wlQL/FJT8acXuEUXK+UgkJdzKPIeJpvUbRomo+a6i6dY=@googlegroups.com
X-Received: by 2002:a05:6e02:b2d:b0:3d8:2178:5c50 with SMTP id e9e14a558f8ab-3da5b323d7cmr89761615ab.14.1746498714977;
        Mon, 05 May 2025 19:31:54 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1746498714; cv=none;
        d=google.com; s=arc-20240605;
        b=LbxxzzcFZ71khZ0RdWlPUiHXn2C0badvKgIjMgYBVK1V0Jc6Pjdfn/QXMA+9Yz7ohu
         F+z1ouwj7RgmP3OYYXG7UBPshPlMO4LZ0+XkBDo5iERsdDi053PpmUteh6h4sm7Mky5b
         WuOtF/YMqS5tTE48/64nh5JD046ekYAwdGKC9ovW3u2FHuvifC0lg3kM/EvFmCS9RehD
         lJFWDZHpn3kblkEfklkziWDfQTqocHRuXmm/7T4y/NeimkNOwx/nIZVOPXs4H6/GBxDu
         TbVnRJsePQO/ucU6tPDvaXe3dVSE8dEYeYiGc6f9AiUx4hKnF/RIh9/lWBW9GIdAfybP
         Ud2Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=feedback-id:content-transfer-encoding:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:ex-qq-recipientcnt
         :dkim-signature;
        bh=RK8CB/ILucoxkojMLroxyaAqpj6rXkr8cb1h0tuO+FM=;
        fh=czsGLYwPf3nMqaD2mLokiq8OJaiFoqxOYJjLElCQXsQ=;
        b=aSAkTvnVIuTzYdwCLTCY/WdB4NKUoaU4/oryKFIpqD6O8oV8B9fr8zkJ8WnAnEiDCx
         7AkOqKjacyn9HRmd/lb8Khbk+6wJ3Ey9/L1Qz2MJwedXXuqPVDVIC/EM//Z8rmbnVK/A
         pfB1LjSFA1YAhQjxfHBPKC3aKJB6eLHe54+tbrg7vVwtyJj9I1zoX/HGWIgpvqN79Xmk
         uKNW+0V0s0Gh6ey5JjGYgwBfXFYofb69enWgeKT+nSwsfDJRsttQ8MZILCQVYUCJMMCG
         MdZHCtOUUjjI26sdoL3ePMlit1J9m6dw9EFY/2rh3xEWFIYxxJkapNYuV4itUbBBenal
         9ScQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@uniontech.com header.s=onoh2408 header.b=kafLiDKX;
       spf=pass (google.com: domain of chenlinxuan@uniontech.com designates 54.254.200.92 as permitted sender) smtp.mailfrom=chenlinxuan@uniontech.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=uniontech.com
Received: from smtpbgsg1.qq.com (smtpbgsg1.qq.com. [54.254.200.92])
        by gmr-mx.google.com with ESMTPS id 8926c6da1cb9f-4f88a731e3dsi626549173.0.2025.05.05.19.31.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 05 May 2025 19:31:54 -0700 (PDT)
Received-SPF: pass (google.com: domain of chenlinxuan@uniontech.com designates 54.254.200.92 as permitted sender) client-ip=54.254.200.92;
X-QQ-mid: esmtpsz17t1746498663t4c1b9905
X-QQ-Originating-IP: 2vhUXsJq6NqiLO1Htm0IxhFYAPx746WeA0MvTVyM9nk=
Received: from localhost.localdomain ( [113.57.152.160])
	by bizesmtp.qq.com (ESMTP) with 
	id ; Tue, 06 May 2025 10:30:59 +0800 (CST)
X-QQ-SSF: 0000000000000000000000000000000
X-QQ-GoodBg: 1
X-BIZMAIL-ID: 1353101163767275647
EX-QQ-RecipientCnt: 52
From: Chen Linxuan <chenlinxuan@uniontech.com>
To: hch@lst.de
Cc: akpm@linux-foundation.org,
	alex.williamson@redhat.com,
	andreyknvl@gmail.com,
	axboe@kernel.dk,
	boqun.feng@gmail.com,
	boris.ostrovsky@oracle.com,
	bp@alien8.de,
	changbin.du@intel.com,
	chenlinxuan@uniontech.com,
	dave.hansen@linux.intel.com,
	dvyukov@google.com,
	hannes@cmpxchg.org,
	hpa@zytor.com,
	jackmanb@google.com,
	jarkko@kernel.org,
	jgg@ziepe.ca,
	jgross@suse.com,
	justinstitt@google.com,
	kasan-dev@googlegroups.com,
	kbusch@kernel.org,
	kevin.tian@intel.com,
	kvm@vger.kernel.org,
	linux-integrity@vger.kernel.org,
	linux-kbuild@vger.kernel.org,
	linux-kernel@vger.kernel.org,
	linux-mm@kvack.org,
	linux-nvme@lists.infradead.org,
	llvm@lists.linux.dev,
	masahiroy@kernel.org,
	mathieu.desnoyers@efficios.com,
	mhocko@suse.com,
	mingo@redhat.com,
	morbo@google.com,
	nathan@kernel.org,
	nick.desaulniers+lkml@gmail.com,
	nicolas.schier@linux.dev,
	paulmck@kernel.org,
	peterhuewe@gmx.de,
	peterz@infradead.org,
	sagi@grimberg.me,
	shameerali.kolothum.thodi@huawei.com,
	surenb@google.com,
	tglx@linutronix.de,
	torvalds@linux-foundation.org,
	vbabka@suse.cz,
	virtualization@lists.linux.dev,
	wentao@uniontech.com,
	x86@kernel.org,
	xen-devel@lists.xenproject.org,
	yishaih@nvidia.com,
	ziy@nvidia.com
Subject: Re: [PATCH RFC v3 0/8] kernel-hacking: introduce CONFIG_NO_AUTO_INLINE
Date: Tue,  6 May 2025 10:30:53 +0800
Message-ID: <AB2D78307A5FD403+20250506023053.541751-1-chenlinxuan@uniontech.com>
X-Mailer: git-send-email 2.43.0
In-Reply-To: <20250429123504.GA13093@lst.de>
References: <20250429123504.GA13093@lst.de>
MIME-Version: 1.0
X-QQ-SENDSIZE: 520
Feedback-ID: esmtpsz:uniontech.com:qybglogicsvrgz:qybglogicsvrgz5a-1
X-QQ-XMAILINFO: OafsCT7BOK1+mEqFkAFO/dVMczu2FZrvEKzCd0rlgDDzHul7768pmhad
	0XxSv1vOUiBmCbcPem7QSoc7yTqqoyo0BfQAEkEVKjG1dpl/phYG/NvC5mhODu5SmxuPrk5
	D1RvCeQHqssNYACkan3dguFoL0ew38G2hqIF6+ye8Z8SNz9NbyUUp2l4W6OBkWUivv/AfUr
	gjmgGUnC86kClly/kvcJYk8WKRWYajgI0jss+DyvaVerdfx4h/ZmbUvvTeGDWj2PoUZIo1R
	q8HrXp2u2dk/kcphZT5u6RzmEIgliMQlxgLngtzZKfozxNvsTC5jxH2cbG1ojjYoX3lDOdr
	W54nGXP9AMtytMbwmIlbo9FoQ4nk3eIAlUHnTPE+al8+6XrnB+rVIE2q1I3gSmLgFwm8aoN
	vq1p2n/VMlKh4OS65Tdxn3KUrzN6CfpS4gOPmqz+hUdjG1k1xCgg81+bxuBdckodzqA92Mz
	Jbg0OZfC3bfAqNpThcePICdjyv4saeQumQOwRw8MfeyJtc9PWWMQaUEAwUhH1n9oCHc7Wh4
	QNAxG26q6gRK10ic3Un7clLGYXs8ETsB1uounP4o0xLMY/TA06Bi3/ueaV+YiX0FICGfw4e
	orwvlqogiT1JVAOSq0msEBji/ZH+oQb+PF8zBieobhbDPLl0mOR7t/AaX/5MO5B3EgtcF3v
	XitRotsIfq0uh0qSQIiDB8q2yPyj9ItlAqiA/iTayqqIYrrUAeOMfluoGt+Qjl0JnmjWn15
	PnKCFwxLs6aUM7A8qolpIuG0orZ3kTkJhGubtw/+rj84UcnEa0x1Qj1Y/RM4T5iyxQHJUyW
	Kt1aIsH4jP56bBVNv2ojGdGXdEBBfRX2dkXEfaFw6ykDtz/cUNFhnK0zGAFuyHTcFdP7ove
	HwYI+AY7oWfgVTb9++hITSIfeYt+e4caGy3JScvtBCET1cZlhCLjyr4oDkuUQ3EO8dJmMwM
	Mj747vahri9HVfH43P+GvEhl+xJSgbNERfpwCSsT3V0Uz4psPg7QV83wsFHoU9i+9mfqazR
	AdrbsszFzSwTPYBXnFqkDs6ExCSIU=
X-QQ-XMRINFO: MPJ6Tf5t3I/ycC2BItcBVIA=
X-QQ-RECHKSPAM: 0
X-Original-Sender: chenlinxuan@uniontech.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@uniontech.com header.s=onoh2408 header.b=kafLiDKX;       spf=pass
 (google.com: domain of chenlinxuan@uniontech.com designates 54.254.200.92 as
 permitted sender) smtp.mailfrom=chenlinxuan@uniontech.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=uniontech.com
Content-Type: text/plain; charset="UTF-8"
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

On Tue, 29 Apr 2025 14:35:04 +0200 Christoph Hellwig wrote:

> On Tue, Apr 29, 2025 at 12:06:04PM +0800, Chen Linxuan via B4 Relay wrote:
>
> > This series introduces a new kernel configuration option NO_AUTO_INLINE,
> > which can be used to disable the automatic inlining of functions.
> >
> > This will allow the function tracer to trace more functions
> > because it only traces functions that the compiler has not inlined.
>
> This still feels like a bad idea because it is extremely fragile.

I'm not entirely sure if we're on the same page regarding this issue.
However, I'd like to address the concerns about the fragility of NO_AUTO_INLINE.

Maintaining NO_AUTO_INLINE to function correctly is indeed challenging,
and I share some reservations about whether it should exist as a Kbuild option,
which is precisely why this patch series is submitted as an RFC.
I cannot even guarantee that I've addressed all existing issues in the current
kernel repository with this patch series, as testing all possible compilation
configurations is beyond my capabilities.

Looking at the functions where I've added __always_inline in this patch series,
nearly all of them require inlining specifically because their calls need to be
resolved at compile time.

The fundamental source of this fragility stems from the fact that compiler
auto-inlining decisions aren't well-defined. If these functions were to change
in the future for unrelated reasons - for example, if they became longer - and
the compiler consequently decided not to automatically inline them, these same
issues would surface regardless.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/AB2D78307A5FD403%2B20250506023053.541751-1-chenlinxuan%40uniontech.com.
