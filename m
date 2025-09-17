Return-Path: <kasan-dev+bncBD74H4NGEIIMNOFKYYDBUBCYPPBIA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23e.google.com (mail-lj1-x23e.google.com [IPv6:2a00:1450:4864:20::23e])
	by mail.lfdr.de (Postfix) with ESMTPS id 510CCB7C65A
	for <lists+kasan-dev@lfdr.de>; Wed, 17 Sep 2025 14:00:31 +0200 (CEST)
Received: by mail-lj1-x23e.google.com with SMTP id 38308e7fff4ca-3381cbfc1fbsf33325681fa.2
        for <lists+kasan-dev@lfdr.de>; Wed, 17 Sep 2025 05:00:31 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758110407; cv=pass;
        d=google.com; s=arc-20240605;
        b=XAoUuMm/d/t7d8qckd/UyTDb56RVjC7k05EUBrhI/ZgFcvv68HMGwyOL+KraYtlygN
         CCWS6I6He0wF4XrsbaKgj2rPhU8DiaOgZ8qi0XOAq1Tk/bnnDjObl1wjZp4uijRvE68v
         CJ+J3jhda9dqonCxadqaP5F7sW3996dGGargLLVO/IRV8FEBR/ymOEZEXU26Y7dC/Ldc
         xwAqQAdbfv5VGmBvHBPhjM0I8HsJi+9b5fOw5wM/xzr2W+NuTKBeB7jSS7Oi8pxp5zcH
         /pqUebo6bFoKsYDDaC9p0texYpoh9URPBar370mfNy5IDGNXrb9rJenAFNZKwnRnCf96
         gLkw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=BoJD1Fr1wPIjoqrBNYuXGUBnxGlGY5JLc9Ta5awO0iQ=;
        fh=sfO/dHfIbtexTAn5sV5b9UEocq0yjf7SkCl6DAMFGnA=;
        b=Qd7sz5j2ApPlXoEP+sTowIrA/4d8GGT3THG10YdDw/VdSF6Qb8NR8IeslsNHn+ICHr
         2jmz5Kf9imtkPpR3s4HKwD/tIsvT4f98Bdg2L0WBJATmJHS7XXcl1e+g80GBtLDHH7Ck
         iuyk6N6OjYVP8YjXIvZP3zmPrw2A+IUNRW7yoWR3hEaKZteJeeBdAbSAqqwFw1ipZ+jn
         vLhi9IV34euTkdy87fTRA5cfcMaUGJH6ttHFLbfjNYeYqEBx1WqlHMm+KcqcDhR8wjtd
         BiHIxc9Kr1b4vOhH5+8rEAru1FnlQy0lglgooS3Q2BvSgKMDYEJRSpvhjf9lYHLzSV5T
         f1LA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.de header.s=susede2_rsa header.b=fxQsuJDb;
       dkim=neutral (no key) header.i=@suse.de;
       dkim=pass header.i=@suse.de header.s=susede2_rsa header.b=fxQsuJDb;
       dkim=neutral (no key) header.i=@suse.de header.b=MQ0cdVXu;
       spf=pass (google.com: domain of pfalcato@suse.de designates 195.135.223.130 as permitted sender) smtp.mailfrom=pfalcato@suse.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=suse.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758110406; x=1758715206; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=BoJD1Fr1wPIjoqrBNYuXGUBnxGlGY5JLc9Ta5awO0iQ=;
        b=EZEu3fBKfxzzIzyW7E0hIFwCbFIT5Z/jpGAD3nHy5ZLXmQjBrKyBTgibtbiuUY0bus
         2gNzGEl0+fiPYPnok2d/W3xe8gG3hoBuarVC/QoC0MvW5icAMGjtBP7VKbOqcC8IfCP5
         xXGuzzFKmiY2J3COh+ltJi0+xOX8gBNqEX6DHyAWSpberm//H5HvVMVcQtFgKwCc2BQk
         NREruE09Dd2dK0T4ew2ZADl4qjet2P1Y6PEAafwvqgWVfl62j8jOtbIa3hIHBkasgOKV
         5uJNuTTdbSMoFN0ITPt6pA2e69kOUFJYBEQpGDgBJaP4sj8gyQ4uaiLtMHYMz8XKoXZy
         YaAQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758110406; x=1758715206;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=BoJD1Fr1wPIjoqrBNYuXGUBnxGlGY5JLc9Ta5awO0iQ=;
        b=L1vWruZTsS/p70+VSzurTp81VV1Pnl/IfWFADOgr4JuDTQv9UTQYSX8s3P6JEDTO5A
         w3RoDhyZ9MAghNJ+xcPCO9DpWgRWDGc0Cazt/gSjDN3j9/JezFPvnuc01eGLM651mek7
         Cd+i/5ks5QPkq42MM9QVBqZuCAZTeRaCTH3VQRwU9xg84VivlZINkZTQYw2KydZ0P56h
         331IwhHEqr6VZxlkd2IIX2yZNredkm/1ljD8MJzgkVEhg8NjzS3FjelcZp1v+aKAl5aZ
         My0jX4xa7ptCCRE1eRWXMxYB4K/HxiJvKWMW9adPU0VcAsZ6zZsISeFbYP6FHNo1LAlT
         9zXw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVN683ksFSLJmlSCB9muG6R9UyBelHuYVL/myHChyPySpIwVJAqjYVTCTHROEQX+8CqSBbWRg==@lfdr.de
X-Gm-Message-State: AOJu0Yz65l7vAfVmEEsEw9owmfOv4kSP5liJy6Vi1e2EsqMRR7lVhucY
	o3r3o+EX+iDfdTlaaL6JmkX7fpsLSff5Uxc2jBp/10Av9tZ0x/m23PgD
X-Google-Smtp-Source: AGHT+IErLG7cGQWBTZbN+WNS3mjeeCyoFEHEKpR4rvIHDNh/dxUy7YjGD9tHjfA4M3GVyKU2iCSG/Q==
X-Received: by 2002:a05:600c:a02:b0:45d:f7cb:8954 with SMTP id 5b1f17b1804b1-46202a0e763mr17576555e9.9.1758108743655;
        Wed, 17 Sep 2025 04:32:23 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd6Js+ne75iLRPCHlVQj9EUP5BxeF54wvdFwXmAkCcABsA==
Received: by 2002:a05:600c:1908:b0:45b:bd1e:2b11 with SMTP id
 5b1f17b1804b1-45f2d07f262ls21205165e9.0.-pod-prod-03-eu; Wed, 17 Sep 2025
 04:32:20 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUGesl16FZVcdwbfmbw75F9QKw5k78OUz3jza04a/USf057da9GyIegVpatX7ILk4MsuMbs0ELWV3Y=@googlegroups.com
X-Received: by 2002:a05:600c:4e09:b0:462:cd41:c2f8 with SMTP id 5b1f17b1804b1-462cd41c4c9mr12345285e9.5.1758108740220;
        Wed, 17 Sep 2025 04:32:20 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1758108740; cv=none;
        d=google.com; s=arc-20240605;
        b=jMau2Um/AsARs64HGaEno+Glb7gvP2vDn7VvMJ+mL3Ofmeti5OcioUArFpUwqSOK2N
         0eY+fattPv5PHKULHYGtU1AH2ZaMXiVTmNs8m/s+jzcFtvae6OE0jzvCfhmQ8K9fbcgW
         5H7vvqIESDGYg+zu3zxn6NOO1xyD6cgORIOVcJE6OHULhxB7nFDn2mDIyE5SYU4ouFst
         ZatmjDRyFN3057MMmCHxc9PsDXigua2egOD/w5dkCwWTwf+aBA33dxVQgFBCTMNnYArQ
         5ZdzYSRXBz1gGn2hvlFO4gWqynlqIqien24wpdLNnzNuxfU3b2SjxXPSN5ViAuM/jvMr
         QkRA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature:dkim-signature
         :dkim-signature:dkim-signature;
        bh=+Ap5mPSoqW5VngVWaJTgyJfGx7MJPhwio1kMAlldw6U=;
        fh=3+MH0ChJLBM72NzpB/XiB+Q7hxpuJ08qXy92Zn7JvPc=;
        b=Et1SQEirIuA6RYwKwxynyjIec9kDg/1NlXF/E2lIPiMSmMFKlMoVkgSFYlPbYaJX+6
         hFrES4Ool+Zk1XD1NkiLT0Blh/cyt+Gb7Oodh0CW4Dum5POv9GUn7IU1tz6VvkoRRSC4
         uHQiRzP6gTIryAMeWUMCv2/TNq3/6g4MZlgIFrBQpBMe2pPP42MIWEkbLBuDBBRl0HLI
         tOk6qTZqkjfohqkZw6/UAvfCLz0DiQFtQa+HbUftCvBNUE3q5QwPvWpmZkXyF4RMaVTK
         s8lrzeKJBJODFXlVXagxx11KdoCP2s97M5Qmc5gB400MWSBgh1PsQ+tp8OGAs76qs8Ke
         70NQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.de header.s=susede2_rsa header.b=fxQsuJDb;
       dkim=neutral (no key) header.i=@suse.de;
       dkim=pass header.i=@suse.de header.s=susede2_rsa header.b=fxQsuJDb;
       dkim=neutral (no key) header.i=@suse.de header.b=MQ0cdVXu;
       spf=pass (google.com: domain of pfalcato@suse.de designates 195.135.223.130 as permitted sender) smtp.mailfrom=pfalcato@suse.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=suse.de
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [195.135.223.130])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-45f3208575dsi1458955e9.0.2025.09.17.04.32.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 17 Sep 2025 04:32:20 -0700 (PDT)
Received-SPF: pass (google.com: domain of pfalcato@suse.de designates 195.135.223.130 as permitted sender) client-ip=195.135.223.130;
Received: from imap1.dmz-prg2.suse.org (imap1.dmz-prg2.suse.org [IPv6:2a07:de40:b281:104:10:150:64:97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id 9A2BB21E43;
	Wed, 17 Sep 2025 11:32:19 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id 202B113A92;
	Wed, 17 Sep 2025 11:32:16 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id GSeHBECcymi0TAAAD6G6ig
	(envelope-from <pfalcato@suse.de>); Wed, 17 Sep 2025 11:32:16 +0000
Date: Wed, 17 Sep 2025 12:32:10 +0100
From: Pedro Falcato <pfalcato@suse.de>
To: Lorenzo Stoakes <lorenzo.stoakes@oracle.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, 
	Jonathan Corbet <corbet@lwn.net>, Matthew Wilcox <willy@infradead.org>, 
	Guo Ren <guoren@kernel.org>, Thomas Bogendoerfer <tsbogend@alpha.franken.de>, 
	Heiko Carstens <hca@linux.ibm.com>, Vasily Gorbik <gor@linux.ibm.com>, 
	Alexander Gordeev <agordeev@linux.ibm.com>, Christian Borntraeger <borntraeger@linux.ibm.com>, 
	Sven Schnelle <svens@linux.ibm.com>, "David S . Miller" <davem@davemloft.net>, 
	Andreas Larsson <andreas@gaisler.com>, Arnd Bergmann <arnd@arndb.de>, 
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>, Dan Williams <dan.j.williams@intel.com>, 
	Vishal Verma <vishal.l.verma@intel.com>, Dave Jiang <dave.jiang@intel.com>, 
	Nicolas Pitre <nico@fluxnic.net>, Muchun Song <muchun.song@linux.dev>, 
	Oscar Salvador <osalvador@suse.de>, David Hildenbrand <david@redhat.com>, 
	Konstantin Komarov <almaz.alexandrovich@paragon-software.com>, Baoquan He <bhe@redhat.com>, Vivek Goyal <vgoyal@redhat.com>, 
	Dave Young <dyoung@redhat.com>, Tony Luck <tony.luck@intel.com>, 
	Reinette Chatre <reinette.chatre@intel.com>, Dave Martin <Dave.Martin@arm.com>, 
	James Morse <james.morse@arm.com>, Alexander Viro <viro@zeniv.linux.org.uk>, 
	Christian Brauner <brauner@kernel.org>, Jan Kara <jack@suse.cz>, 
	"Liam R . Howlett" <Liam.Howlett@oracle.com>, Vlastimil Babka <vbabka@suse.cz>, 
	Mike Rapoport <rppt@kernel.org>, Suren Baghdasaryan <surenb@google.com>, 
	Michal Hocko <mhocko@suse.com>, Hugh Dickins <hughd@google.com>, 
	Baolin Wang <baolin.wang@linux.alibaba.com>, Uladzislau Rezki <urezki@gmail.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Jann Horn <jannh@google.com>, linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org, 
	linux-fsdevel@vger.kernel.org, linux-csky@vger.kernel.org, linux-mips@vger.kernel.org, 
	linux-s390@vger.kernel.org, sparclinux@vger.kernel.org, nvdimm@lists.linux.dev, 
	linux-cxl@vger.kernel.org, linux-mm@kvack.org, ntfs3@lists.linux.dev, 
	kexec@lists.infradead.org, kasan-dev@googlegroups.com, Jason Gunthorpe <jgg@nvidia.com>, 
	iommu@lists.linux.dev, Kevin Tian <kevin.tian@intel.com>, Will Deacon <will@kernel.org>, 
	Robin Murphy <robin.murphy@arm.com>
Subject: Re: [PATCH v3 08/13] mm: add ability to take further action in
 vm_area_desc
Message-ID: <wabzfghapygwy3fzexbplmasrdzttt3nsgpmoj4kr6g7ldstkg@tthpx7de6tqk>
References: <cover.1758031792.git.lorenzo.stoakes@oracle.com>
 <9171f81e64fcb94243703aa9a7da822b5f2ff302.1758031792.git.lorenzo.stoakes@oracle.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <9171f81e64fcb94243703aa9a7da822b5f2ff302.1758031792.git.lorenzo.stoakes@oracle.com>
X-Spam-Level: 
X-Spam-Flag: NO
X-Rspamd-Queue-Id: 9A2BB21E43
X-Rspamd-Action: no action
X-Rspamd-Server: rspamd1.dmz-prg2.suse.org
X-Spamd-Result: default: False [-2.51 / 50.00];
	BAYES_HAM(-3.00)[100.00%];
	SUSPICIOUS_RECIPS(1.50)[];
	NEURAL_HAM_LONG(-1.00)[-1.000];
	MID_RHS_NOT_FQDN(0.50)[];
	R_DKIM_ALLOW(-0.20)[suse.de:s=susede2_rsa,suse.de:s=susede2_ed25519];
	NEURAL_HAM_SHORT(-0.20)[-1.000];
	MIME_GOOD(-0.10)[text/plain];
	MX_GOOD(-0.01)[];
	DKIM_SIGNED(0.00)[suse.de:s=susede2_rsa,suse.de:s=susede2_ed25519];
	FREEMAIL_ENVRCPT(0.00)[gmail.com];
	RBL_SPAMHAUS_BLOCKED_OPENRESOLVER(0.00)[2a07:de40:b281:104:10:150:64:97:from];
	TO_DN_SOME(0.00)[];
	FUZZY_RATELIMITED(0.00)[rspamd.com];
	MIME_TRACE(0.00)[0:+];
	ARC_NA(0.00)[];
	FREEMAIL_CC(0.00)[linux-foundation.org,lwn.net,infradead.org,kernel.org,alpha.franken.de,linux.ibm.com,davemloft.net,gaisler.com,arndb.de,linuxfoundation.org,intel.com,fluxnic.net,linux.dev,suse.de,redhat.com,paragon-software.com,arm.com,zeniv.linux.org.uk,suse.cz,oracle.com,google.com,suse.com,linux.alibaba.com,gmail.com,vger.kernel.org,lists.linux.dev,kvack.org,lists.infradead.org,googlegroups.com,nvidia.com];
	RCVD_TLS_ALL(0.00)[];
	DKIM_TRACE(0.00)[suse.de:+];
	RCVD_COUNT_TWO(0.00)[2];
	TO_MATCH_ENVRCPT_SOME(0.00)[];
	FROM_EQ_ENVFROM(0.00)[];
	FROM_HAS_DN(0.00)[];
	SPAMHAUS_XBL(0.00)[2a07:de40:b281:104:10:150:64:97:from];
	RCPT_COUNT_GT_50(0.00)[62];
	RCVD_VIA_SMTP_AUTH(0.00)[];
	RECEIVED_SPAMHAUS_BLOCKED_OPENRESOLVER(0.00)[2a07:de40:b281:106:10:150:64:167:received];
	R_RATELIMIT(0.00)[to_ip_from(RLzjiba8kn1xq17x95uu9jb85x)];
	MISSING_XM_UA(0.00)[];
	DBL_BLOCKED_OPENRESOLVER(0.00)[suse.de:dkim,imap1.dmz-prg2.suse.org:rdns,imap1.dmz-prg2.suse.org:helo]
X-Spam-Score: -2.51
X-Original-Sender: pfalcato@suse.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.de header.s=susede2_rsa header.b=fxQsuJDb;       dkim=neutral
 (no key) header.i=@suse.de;       dkim=pass header.i=@suse.de
 header.s=susede2_rsa header.b=fxQsuJDb;       dkim=neutral (no key)
 header.i=@suse.de header.b=MQ0cdVXu;       spf=pass (google.com: domain of
 pfalcato@suse.de designates 195.135.223.130 as permitted sender)
 smtp.mailfrom=pfalcato@suse.de;       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=suse.de
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

On Tue, Sep 16, 2025 at 03:11:54PM +0100, Lorenzo Stoakes wrote:
> Some drivers/filesystems need to perform additional tasks after the VMA is
> set up.  This is typically in the form of pre-population.
> 
> The forms of pre-population most likely to be performed are a PFN remap
> or the insertion of normal folios and PFNs into a mixed map.
> 
> We start by implementing the PFN remap functionality, ensuring that we
> perform the appropriate actions at the appropriate time - that is setting
> flags at the point of .mmap_prepare, and performing the actual remap at the
> point at which the VMA is fully established.
> 
> This prevents the driver from doing anything too crazy with a VMA at any
> stage, and we retain complete control over how the mm functionality is
> applied.
> 
> Unfortunately callers still do often require some kind of custom action,
> so we add an optional success/error _hook to allow the caller to do
> something after the action has succeeded or failed.

Do we have any idea for rules regarding ->mmap_prepare() and ->*_hook()?
It feels spooky to e.g grab locks in mmap_prepare, and hold them across core
mmap(). And I guess it might be needed?

> 
> This is done at the point when the VMA has already been established, so
> the harm that can be done is limited.
> 
> The error hook can be used to filter errors if necessary.
> 
> If any error arises on these final actions, we simply unmap the VMA
> altogether.
> 
> Also update the stacked filesystem compatibility layer to utilise the
> action behaviour, and update the VMA tests accordingly.
> 
> Signed-off-by: Lorenzo Stoakes <lorenzo.stoakes@oracle.com>
<snip>
> diff --git a/include/linux/mm_types.h b/include/linux/mm_types.h
> index 31b27086586d..aa1e2003f366 100644
> --- a/include/linux/mm_types.h
> +++ b/include/linux/mm_types.h
> @@ -775,6 +775,49 @@ struct pfnmap_track_ctx {
>  };
>  #endif
>  
> +/* What action should be taken after an .mmap_prepare call is complete? */
> +enum mmap_action_type {
> +	MMAP_NOTHING,		/* Mapping is complete, no further action. */
> +	MMAP_REMAP_PFN,		/* Remap PFN range. */
> +};
> +
> +/*
> + * Describes an action an mmap_prepare hook can instruct to be taken to complete
> + * the mapping of a VMA. Specified in vm_area_desc.
> + */
> +struct mmap_action {
> +	union {
> +		/* Remap range. */
> +		struct {
> +			unsigned long start;
> +			unsigned long start_pfn;
> +			unsigned long size;
> +			pgprot_t pgprot;
> +			bool is_io_remap;
> +		} remap;
> +	};
> +	enum mmap_action_type type;
> +
> +	/*
> +	 * If specified, this hook is invoked after the selected action has been
> +	 * successfully completed. Note that the VMA write lock still held.
> +	 *
> +	 * The absolute minimum ought to be done here.
> +	 *
> +	 * Returns 0 on success, or an error code.
> +	 */
> +	int (*success_hook)(const struct vm_area_struct *vma);
> +
> +	/*
> +	 * If specified, this hook is invoked when an error occurred when
> +	 * attempting the selection action.
> +	 *
> +	 * The hook can return an error code in order to filter the error, but
> +	 * it is not valid to clear the error here.
> +	 */
> +	int (*error_hook)(int err);

Do we need two hooks? It might be more ergonomic to simply have a:

	int (*finish)(int err);


	int random_driver_finish(int err)
	{
		if (err)
			pr_err("ahhhhhhhhh\n");
		mutex_unlock(&big_lock);
		return err;
	}

It's also unclear to me if/why we need the capability to switch error codes,
but I might've missed some discussion on this.


-- 
Pedro

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/wabzfghapygwy3fzexbplmasrdzttt3nsgpmoj4kr6g7ldstkg%40tthpx7de6tqk.
