Return-Path: <kasan-dev+bncBD74H4NGEIIP7H5KYYDBUBA64QZWO@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13a.google.com (mail-lf1-x13a.google.com [IPv6:2a00:1450:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id 02567B7E133
	for <lists+kasan-dev@lfdr.de>; Wed, 17 Sep 2025 14:40:46 +0200 (CEST)
Received: by mail-lf1-x13a.google.com with SMTP id 2adb3069b0e04-571c4a20e8asf3010043e87.3
        for <lists+kasan-dev@lfdr.de>; Wed, 17 Sep 2025 05:40:45 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758112845; cv=pass;
        d=google.com; s=arc-20240605;
        b=XYkDtFe+dbUw8AZTQojpsmgMfAYn2Wc6b+SgZmFl7kzkMsKRzQE6hqpY2AFWhtpwvK
         29ZgLWgRlfP5lvFX5bciTDvtq6iki6jxc+FxpEpvFBG8dGFryxDNs0XWOXp2lehxCTm9
         mK3GKfCjurIpyvkHJ/ZXWM5/cTC4nnUyEyhAp2zcxgM1noVKTAXfPFBZwt4h5ZS21Yj/
         DVi47x2YNwiezXu32ANtRWq9RU1omKRaaVEOBAfLHlGhhHOL2Ri8xdEAqx6gApglCEI7
         2/ktvB8D0Vdpf9I/zUTEVwXLtx2NL7tyLI8jRX0KK9O/x4f+d8A8+kk5qzrew+uBR7oM
         7v1A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=c2eHlFSqcv0Szc+5XRy2diFMiqYKbHv51Tex1wLNZEc=;
        fh=9ischKZTecXS7rjXV12uqYKUt//XpmjtnPyCzhWABlg=;
        b=BWnXmeLDpFVE2GpAIzVNxmtAKVx3ySWpSqG8R/7aW8JvYgLP/quwUfbJ4J6ifEKNMk
         iMtlGqzaTRFV9iFDhpWoVy9x8I4fSBSCoc5qT46eJHnRpBh8vnf0HDfe1pYF1kPdzIVh
         ZamI64vVbnGn/nzqZ+9zp9ouD5c1/Po43srOqPSzmvy6bB7fjYGcEtx/zGzYmUjHHJQP
         +WKAG6/JUVXEOSolNHwRHT/zkirN6dMrKAlkAFG/IJRCh5H4pUvRHsLa3KLEbM/I4Q0B
         SMmbcL9EGnSW0o7iX0cCReT3PTNmmOkveAU4rdf74HJUgPNrXvsj/dpjsap8Xiae0J0G
         QZsw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.de header.s=susede2_rsa header.b=lzKn6rsx;
       dkim=neutral (no key) header.i=@suse.de;
       dkim=pass header.i=@suse.de header.s=susede2_rsa header.b=lzKn6rsx;
       dkim=neutral (no key) header.i=@suse.de;
       spf=pass (google.com: domain of pfalcato@suse.de designates 195.135.223.130 as permitted sender) smtp.mailfrom=pfalcato@suse.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=suse.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758112845; x=1758717645; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=c2eHlFSqcv0Szc+5XRy2diFMiqYKbHv51Tex1wLNZEc=;
        b=eZ2aram/TKrDWf43637BxoE880DTsLyL5FEwLc2/wadMDmngqGBaQReLQKWfaPXINQ
         ymXTdkwg08XrhvjOB/66iKi6gSFTjE7x5adQqdlPi8mireNCk4dlCcVWktqe9L3Smpm4
         n7903jE/81wqeWZPViw0hp6ZR0S1ciPKPHeyAM0IgGnalKHvuy1PU1BV0ydEDFb0Fhwq
         l5kI8ls5En/2aSKW90YAMlsgRqfe5AkyqmQMPFqvfOCFOgVPyvhljH+Wql9TvpxPOyDd
         osJ4YBtCZHH+CO6UutDxtYRQ3RI+dPQwK1XsEX0dQkt07TejDFry6MZb508vVsWGI59J
         poMA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758112845; x=1758717645;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=c2eHlFSqcv0Szc+5XRy2diFMiqYKbHv51Tex1wLNZEc=;
        b=gkIns4zMlZuk8w5SvPxt9o0Gkdi4wo56utANS48wfOrgDl0mvfdR4AIvLHvjlEYxXS
         HjCBHpFg2Vv00W8X1Dcyw2xG2wa6THnxV66fJn3jntF4wCU3yLd9DcgXoTedWYsUniRK
         Awfayrq/LpRDMFDw4PQ3Cg4JCs27oCeE580Qsi3vT3D2Hdhb14SdTDyQwq4hfOoa6I2K
         9JEk1+yVjWATyKI9IRKZtaajG8+9Oc7VTdPCMwlxIleiclWpNiRQB4wULujkrxzNEjkz
         sk6mGd7LUozlzePBspA+wLoyEd58ESEIRIJ7Y9sCGVDOR6FukIFi5iSZ9ZXGMyFRZ9Ug
         rt1Q==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVtFOKaCpRekuqyxClkHkNmPNkVm6vunFcEPFGCRpqIT436cSpmFQiUvTE4ZNJgJalCg3iInA==@lfdr.de
X-Gm-Message-State: AOJu0Yx5NSHPCEEmh2TcX8YAFG2aZjxr9YqSETNQHzMIhUPNyc47dSG1
	uTZVk5jCUYvu9S6LNvln2sd35m2sWzm0BJqxltunVDmDlvax+EAuP5A7
X-Google-Smtp-Source: AGHT+IFKO5TlB1xHGSUaDVC2CicXPK+zfdrGppeiVLWK7P0MZ/NYqK+vJ66m80Eg63poqwdQ/lLphQ==
X-Received: by 2002:a17:907:3f23:b0:b04:669f:e722 with SMTP id a640c23a62f3a-b1bbad8ac09mr197015466b.32.1758105599829;
        Wed, 17 Sep 2025 03:39:59 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd56sjEEPobaLcakJsFsStei1tpY+evCvJOpwn9CLn7rkA==
Received: by 2002:a05:6402:1d49:b0:62f:330b:caf2 with SMTP id
 4fb4d7f45d1cf-62f330bccfbls2896047a12.1.-pod-prod-09-eu; Wed, 17 Sep 2025
 03:39:57 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWUthQjC/iezHuO+U3noJaXXkGY8ek1zsthfSsrw2pTNPJzZDEfR5Jolb1gJj8BM862CEjRBnaXshU=@googlegroups.com
X-Received: by 2002:a17:907:9716:b0:b0e:d477:4972 with SMTP id a640c23a62f3a-b1bb5599d88mr231965366b.25.1758105597057;
        Wed, 17 Sep 2025 03:39:57 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1758105597; cv=none;
        d=google.com; s=arc-20240605;
        b=TbVyW2QW2pC1gDUZ4N8prTFlPhLEE2J6XHydjj8N6JrqBcpQ6dmlRfYX/WSVumtiPe
         gSJqvr3FS8I2BcvYqG0XwCY3r2iYgQFMq0NteolhxpnTH73g+oAPrvk+kBDkgwo3GA3L
         ACcun+9mGAdi3dsIW8RKfFwWd2STlttmfZ36RwBhxVY2tCKJv86Z9/Oqux1K176Jok6W
         tuQtodP/e6MvCUPbzCxf3lnMJQsxfdagU84lmtPAhRYSKluIl9n5rTu9nO65FAdlI+TP
         8PKKF0xFPHeAexdV2lGXKbPEJ3ll0hivqXY1wkvsn7M3mDPmUHdVB9gTZJ8PVLoK0DcR
         Hk0A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature:dkim-signature
         :dkim-signature:dkim-signature;
        bh=BTjTogDxANa0Qzws4WbQ8f3o4nXNMeX98mY4+62yrZI=;
        fh=3+MH0ChJLBM72NzpB/XiB+Q7hxpuJ08qXy92Zn7JvPc=;
        b=ZWkmb4NRO9mSGQYkyAiyC0faG9S19x6XUHy5EvbVU9IfBlWQkWBwgogmNuIg9WO068
         qPbvd4L7W/TaZhnwevmMzWcbsPlT0KkAUrmj8XsiuNyo9+3/CedF2aocttmj97P6Z8Pt
         llEvo/y4ZXa0fw6YHwq9E1NNWTSklDH/xEc4EDLmTM10U2YchBSO6kP6NPc2wxAldBDE
         pFQCJ5wPMkmacCvIF/mY/oOuJr0yCG09VJH+GnqQAKfDRRgGzjlRqRkMyVdbLKL0Z+7f
         /DDHFWejCE2DIJljlLMqWgq52RIiU7bDXp9iXziXMRldLVVl/cwH/0eCWw8sOjNqgwTc
         H1qg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.de header.s=susede2_rsa header.b=lzKn6rsx;
       dkim=neutral (no key) header.i=@suse.de;
       dkim=pass header.i=@suse.de header.s=susede2_rsa header.b=lzKn6rsx;
       dkim=neutral (no key) header.i=@suse.de;
       spf=pass (google.com: domain of pfalcato@suse.de designates 195.135.223.130 as permitted sender) smtp.mailfrom=pfalcato@suse.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=suse.de
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [195.135.223.130])
        by gmr-mx.google.com with ESMTPS id a640c23a62f3a-b0b6642fdfbsi22764866b.0.2025.09.17.03.39.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 17 Sep 2025 03:39:57 -0700 (PDT)
Received-SPF: pass (google.com: domain of pfalcato@suse.de designates 195.135.223.130 as permitted sender) client-ip=195.135.223.130;
Received: from imap1.dmz-prg2.suse.org (unknown [10.150.64.97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id 579AB222CE;
	Wed, 17 Sep 2025 10:39:56 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id C98341368D;
	Wed, 17 Sep 2025 10:39:52 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id He73LfiPymjZOQAAD6G6ig
	(envelope-from <pfalcato@suse.de>); Wed, 17 Sep 2025 10:39:52 +0000
Date: Wed, 17 Sep 2025 11:39:43 +0100
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
Subject: Re: [PATCH v3 03/13] mm: add vma_desc_size(), vma_desc_pages()
 helpers
Message-ID: <qqfw52uzfa3upljmv2nkpqsob373kyckhujsit2wkzuzik3lkg@2qkiclab53zw>
References: <cover.1758031792.git.lorenzo.stoakes@oracle.com>
 <011a41d86fce1141acb5cc9af2cea3f4e42b5e69.1758031792.git.lorenzo.stoakes@oracle.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <011a41d86fce1141acb5cc9af2cea3f4e42b5e69.1758031792.git.lorenzo.stoakes@oracle.com>
X-Spam-Level: 
X-Spamd-Result: default: False [-2.30 / 50.00];
	BAYES_HAM(-3.00)[99.99%];
	SUSPICIOUS_RECIPS(1.50)[];
	NEURAL_HAM_LONG(-1.00)[-1.000];
	MID_RHS_NOT_FQDN(0.50)[];
	NEURAL_HAM_SHORT(-0.20)[-1.000];
	MIME_GOOD(-0.10)[text/plain];
	FREEMAIL_CC(0.00)[linux-foundation.org,lwn.net,infradead.org,kernel.org,alpha.franken.de,linux.ibm.com,davemloft.net,gaisler.com,arndb.de,linuxfoundation.org,intel.com,fluxnic.net,linux.dev,suse.de,redhat.com,paragon-software.com,arm.com,zeniv.linux.org.uk,suse.cz,oracle.com,google.com,suse.com,linux.alibaba.com,gmail.com,vger.kernel.org,lists.linux.dev,kvack.org,lists.infradead.org,googlegroups.com,nvidia.com];
	FREEMAIL_ENVRCPT(0.00)[gmail.com];
	FUZZY_RATELIMITED(0.00)[rspamd.com];
	DKIM_SIGNED(0.00)[suse.de:s=susede2_rsa,suse.de:s=susede2_ed25519];
	MIME_TRACE(0.00)[0:+];
	ARC_NA(0.00)[];
	RCVD_TLS_ALL(0.00)[];
	R_RATELIMIT(0.00)[to_ip_from(RL4ro17i1dnf4zni6sx1qqmcne)];
	MISSING_XM_UA(0.00)[];
	FROM_EQ_ENVFROM(0.00)[];
	FROM_HAS_DN(0.00)[];
	TO_DN_SOME(0.00)[];
	RCVD_COUNT_TWO(0.00)[2];
	RCPT_COUNT_GT_50(0.00)[62];
	TO_MATCH_ENVRCPT_SOME(0.00)[];
	RCVD_VIA_SMTP_AUTH(0.00)[];
	DBL_BLOCKED_OPENRESOLVER(0.00)[suse.de:email]
X-Spam-Flag: NO
X-Spam-Score: -2.30
X-Original-Sender: pfalcato@suse.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.de header.s=susede2_rsa header.b=lzKn6rsx;       dkim=neutral
 (no key) header.i=@suse.de;       dkim=pass header.i=@suse.de
 header.s=susede2_rsa header.b=lzKn6rsx;       dkim=neutral (no key)
 header.i=@suse.de;       spf=pass (google.com: domain of pfalcato@suse.de
 designates 195.135.223.130 as permitted sender) smtp.mailfrom=pfalcato@suse.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=suse.de
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

On Tue, Sep 16, 2025 at 03:11:49PM +0100, Lorenzo Stoakes wrote:
> It's useful to be able to determine the size of a VMA descriptor range
> used on f_op->mmap_prepare, expressed both in bytes and pages, so add
> helpers for both and update code that could make use of it to do so.
> 
> Signed-off-by: Lorenzo Stoakes <lorenzo.stoakes@oracle.com>
> Reviewed-by: Jan Kara <jack@suse.cz>
> Acked-by: David Hildenbrand <david@redhat.com>

Reviewed-by: Pedro Falcato <pfalcato@suse.de>
-- 
Pedro

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/qqfw52uzfa3upljmv2nkpqsob373kyckhujsit2wkzuzik3lkg%402qkiclab53zw.
