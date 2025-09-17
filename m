Return-Path: <kasan-dev+bncBD74H4NGEIIJTL5KYYDBUBC5DH6WC@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23d.google.com (mail-lj1-x23d.google.com [IPv6:2a00:1450:4864:20::23d])
	by mail.lfdr.de (Postfix) with ESMTPS id 4A477B7CC77
	for <lists+kasan-dev@lfdr.de>; Wed, 17 Sep 2025 14:10:04 +0200 (CEST)
Received: by mail-lj1-x23d.google.com with SMTP id 38308e7fff4ca-336cd3a26a1sf29142911fa.1
        for <lists+kasan-dev@lfdr.de>; Wed, 17 Sep 2025 05:10:04 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758111003; cv=pass;
        d=google.com; s=arc-20240605;
        b=NKpu5sTKpOYnbWHjQduvpMmFb4g4Kssd4NOx4C8let+AQ0GfHz0iORtcsLNtVuZcjb
         Xb9pMmcbd6NiE+r6uHsFQ/F1WYiQoMjcSXR271ZHt5rNlcWN3oruvY+rBI3NC1Ghuf2u
         UDQeQcogYDmmy/tpSzkTiZ6iuB5JmSMcihVwudp9trEYCLRvGxFpcs5hVzUfii6qcqQG
         wvcebamBWaqt+tuF959x2SDwrhR+X36qiobj7GziXuMf/68yzD94iobeaNQLHYMsTVy1
         r9VTHqwqekQxumxEKCgvjy3Ii76+yKT8PAgBdPkh2S7MUfzVsUIO96nBIgYwKkemrn3J
         qevg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=sBCS3qGnWVMEPhzWxZ4koh4nAdMoLBEVacPbT1dGTYI=;
        fh=h3teprn9JSSzUmmouFdQbnrrZt9cGenBE7oPo6fGlfo=;
        b=KJ5TGbWx8wOQbdYbn9oiSElkmXOJRp3fdzFsqKYvHp754DXndGffBr3GGNfStqmLL9
         Nz18h3nVEzSqonCr5hPZD4BV3EfsvKLgJernIS/w8zM6pzGr0LtT8/Eax05XCVY6gIke
         +Fo5REyJzF9pDO9MlJfGSLo+cdhoJafqoJGSxrDeKvh5Crg7XbQQQXtloyWmISx6/Lzb
         EhPIHD+ZRWlZLmAVS7V+zMJMzVw31+RydNEnTuIHPcc9yCmEBtfMQsA5Evmt+3ZwXUNL
         t3zRINc6Mvd1JValEzNSdK3wG25cdUMb9DZ1d060JealldzQy1FQ6zWuSGDG5az8nlDo
         wl7g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.de header.s=susede2_rsa header.b=qRDp6TyL;
       dkim=neutral (no key) header.i=@suse.de;
       dkim=pass header.i=@suse.de header.s=susede2_rsa header.b=qRDp6TyL;
       dkim=neutral (no key) header.i=@suse.de;
       spf=pass (google.com: domain of pfalcato@suse.de designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) smtp.mailfrom=pfalcato@suse.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=suse.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758111003; x=1758715803; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=sBCS3qGnWVMEPhzWxZ4koh4nAdMoLBEVacPbT1dGTYI=;
        b=dgZpqRbZoXdllJ3T3N1X4E6EZCuFwOSjCPh2oW7zMOfALVn1t7s7661EJbedPHiU13
         RiZmj3G43yOhgNu+gF//L4TKDb/sFiAVAfLsZ57FuuSSkYTONxTEebRf+lZAfJTqMQ7k
         UYCSNk7oFgqq/XPGZSc51hHVOisMcO+fzBScsyj5Lbvb46wlH03ldpHUEYEHVmhUNQSg
         ZCrYsI9BpJI62s8zXDl5nup0YfJD0OqHkWfjK0ApYtF+vUklHMImXOURbCOOxBgOjXh8
         fcb1dTugvDHmlrUxA45ykrSDt3AzHiUwbi4exT7BvYYOnJAjquona6NMYeLydyyHr6w8
         VQCQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758111003; x=1758715803;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=sBCS3qGnWVMEPhzWxZ4koh4nAdMoLBEVacPbT1dGTYI=;
        b=IqVLFZsbA8Ult9BJsOSDpLRbgNifmt81MltiKstXmkZFlHSOEAXVBmbzC7IwpKLBU9
         pV8e0ssB12tIhdOHA1yDZXdTFvjWZw5SZzgbL4mW3qozc2R5fdd8CcOHWhzC4sg7VcTY
         afW7K9/hH/27Iv5LIjew2giKhgBZcjY2K6qJmtH2UN1fAk9H7dNyZuv8UOmaUvoXnqYN
         5+5wXpnSOnRNYgS03kWpZcpV7HuN7SfGQijYnbP6Kf15JbAwnSJWMgzfULJnQNMsu0Tt
         RK6IKQ6cbbZFDxUi9yia1Y1dRIUX+Q0x2tbmQyMZ+edDtNoLXKD848dky4e76lzDc1UW
         G/XQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVGuzPjLo4EjAc2CUdN2hgxhkUrLeX1hmYPr+dMb5AL7mnOY0Hh7hzbqW2KRt84WWvskJ97lg==@lfdr.de
X-Gm-Message-State: AOJu0Yy0EJAh2BS2UEUkx54QpUPQK0md7JmIC8JjW/GUUglJnsiy4Niy
	Bt0enVizRG3hiDdIHMAGapBfejwZZfChaYSn5CCUsOkEnu5e4B7JZylU
X-Google-Smtp-Source: AGHT+IFOwq3RxXmQ4+Qcr5e/qr1GnJTZsF9Xf5n7vpL2F6Q6nkwiyWexT9aaTznAi1nAHkEbzQFh1A==
X-Received: by 2002:a05:651c:54c:b0:338:53d:3517 with SMTP id 38308e7fff4ca-35f64b1ad5cmr6531811fa.33.1758107546420;
        Wed, 17 Sep 2025 04:12:26 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd6FDWQkXvtVse3I/Ni2heHtpWwPWj7A+OGgA89Er35UdA==
Received: by 2002:a2e:b54b:0:b0:336:de7e:6efe with SMTP id 38308e7fff4ca-34eb180ca22ls13491921fa.2.-pod-prod-08-eu;
 Wed, 17 Sep 2025 04:12:23 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXN33RDLfUXjVELtZYY9rTq7LUSKDx3Hsxl8T2ANThn69e+3HjG4JdrbZbZfWPmUSSvy7IH6XCDV4I=@googlegroups.com
X-Received: by 2002:a2e:3809:0:b0:336:9427:3527 with SMTP id 38308e7fff4ca-35f6416c0a2mr3574971fa.21.1758107543437;
        Wed, 17 Sep 2025 04:12:23 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1758107543; cv=none;
        d=google.com; s=arc-20240605;
        b=iwP4V3kK2JDOcKTH7An2jNchrSxcQi2VRS0VUw6fYnu+vecMm4+vS5eNTXPerE6sqf
         hudKxaUs5cCpkqJ1H0s2NXQwvPccGAsc4IK0nwlrBEqL8aC32HNPrbIpT1mY2mbgphIJ
         XTpuFHGMY716hgyU0L4BE4OvQ280mBUzbXi4YRf3BGenesV4WcswfHjvv2yA0uj8omZB
         hB24gUEfv3MO7oDD+O2i7q2buPYx+eiiiQ+B04xus7qWvaumhqiClSHOVQP/BGUCC7/5
         +tekAOg8odXZGarqjPAnj+4Mi3oFu+U+gX12Kq2Go3vzO6bsDjX6CQ6H8fcBWMqvpSBq
         8HKQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature:dkim-signature
         :dkim-signature:dkim-signature;
        bh=qlHRHVHtHHtuuDqiW+QVhwCo9b5r8skmryrvZTDKlw8=;
        fh=3+MH0ChJLBM72NzpB/XiB+Q7hxpuJ08qXy92Zn7JvPc=;
        b=XiPOjtEqH6nUiCJDrENywbgUszi3rQCeBhcx5t3ANfWFTDVcWWiPv7EtZa9Q75hQmp
         YzwyfSN8qxj7j2IA/mfPXv88r7qUv5tA4gNvS4DLpiuao2so5en2e2qMk55pX4sIsRSR
         DqDj+l7ARaupgs3DvqJkdaKnLL4Y3rvaevBxS6boPuXzQQ7AwnUVsKHmENQeAZl6Dxqq
         79Qrsjz/4qb7IkOOmsdl62Ie1jOEjIxHohpe4lNH7J0jpAsu6JYsVVLphQk3NGsLbcX7
         FLKcJ29tOhoKRIN5L3EAUzgZp3pJs/8lWHJxXYyvL2ui9eLPsfQzOEWuIxNv5BIDsk8N
         jAew==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.de header.s=susede2_rsa header.b=qRDp6TyL;
       dkim=neutral (no key) header.i=@suse.de;
       dkim=pass header.i=@suse.de header.s=susede2_rsa header.b=qRDp6TyL;
       dkim=neutral (no key) header.i=@suse.de;
       spf=pass (google.com: domain of pfalcato@suse.de designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) smtp.mailfrom=pfalcato@suse.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=suse.de
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [2a07:de40:b251:101:10:150:64:2])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-35129dde56esi2578661fa.3.2025.09.17.04.12.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 17 Sep 2025 04:12:23 -0700 (PDT)
Received-SPF: pass (google.com: domain of pfalcato@suse.de designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) client-ip=2a07:de40:b251:101:10:150:64:2;
Received: from imap1.dmz-prg2.suse.org (unknown [10.150.64.97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id 8BA911F7AB;
	Wed, 17 Sep 2025 11:12:22 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id 0B4E01368D;
	Wed, 17 Sep 2025 11:12:18 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id MRcsO5KXymghRQAAD6G6ig
	(envelope-from <pfalcato@suse.de>); Wed, 17 Sep 2025 11:12:18 +0000
Date: Wed, 17 Sep 2025 12:12:17 +0100
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
Subject: Re: [PATCH v3 07/13] mm: introduce io_remap_pfn_range_[prepare,
 complete]()
Message-ID: <hfczgna46ok6zvh3xxgzdhf5t5nzqybpxkmvuulbzncagmgrcy@ase57zw2xsj5>
References: <cover.1758031792.git.lorenzo.stoakes@oracle.com>
 <3d8f72ece78c1b470382b6a1f12eef0eacd4c068.1758031792.git.lorenzo.stoakes@oracle.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <3d8f72ece78c1b470382b6a1f12eef0eacd4c068.1758031792.git.lorenzo.stoakes@oracle.com>
X-Spamd-Result: default: False [-2.30 / 50.00];
	BAYES_HAM(-3.00)[99.99%];
	SUSPICIOUS_RECIPS(1.50)[];
	NEURAL_HAM_LONG(-1.00)[-1.000];
	MID_RHS_NOT_FQDN(0.50)[];
	NEURAL_HAM_SHORT(-0.20)[-1.000];
	MIME_GOOD(-0.10)[text/plain];
	ARC_NA(0.00)[];
	TO_DN_SOME(0.00)[];
	MIME_TRACE(0.00)[0:+];
	FUZZY_RATELIMITED(0.00)[rspamd.com];
	RCVD_VIA_SMTP_AUTH(0.00)[];
	MISSING_XM_UA(0.00)[];
	FREEMAIL_ENVRCPT(0.00)[gmail.com];
	DKIM_SIGNED(0.00)[suse.de:s=susede2_rsa,suse.de:s=susede2_ed25519];
	FROM_EQ_ENVFROM(0.00)[];
	FROM_HAS_DN(0.00)[];
	FREEMAIL_CC(0.00)[linux-foundation.org,lwn.net,infradead.org,kernel.org,alpha.franken.de,linux.ibm.com,davemloft.net,gaisler.com,arndb.de,linuxfoundation.org,intel.com,fluxnic.net,linux.dev,suse.de,redhat.com,paragon-software.com,arm.com,zeniv.linux.org.uk,suse.cz,oracle.com,google.com,suse.com,linux.alibaba.com,gmail.com,vger.kernel.org,lists.linux.dev,kvack.org,lists.infradead.org,googlegroups.com,nvidia.com];
	R_RATELIMIT(0.00)[to_ip_from(RL4ro17i1dnf4zni6sx1qqmcne)];
	TO_MATCH_ENVRCPT_SOME(0.00)[];
	RCVD_COUNT_TWO(0.00)[2];
	RCVD_TLS_ALL(0.00)[];
	RCPT_COUNT_GT_50(0.00)[62];
	DBL_BLOCKED_OPENRESOLVER(0.00)[suse.de:email,oracle.com:email,imap1.dmz-prg2.suse.org:helo]
X-Spam-Flag: NO
X-Spam-Level: 
X-Spam-Score: -2.30
X-Original-Sender: pfalcato@suse.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.de header.s=susede2_rsa header.b=qRDp6TyL;       dkim=neutral
 (no key) header.i=@suse.de;       dkim=pass header.i=@suse.de
 header.s=susede2_rsa header.b=qRDp6TyL;       dkim=neutral (no key)
 header.i=@suse.de;       spf=pass (google.com: domain of pfalcato@suse.de
 designates 2a07:de40:b251:101:10:150:64:2 as permitted sender)
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

On Tue, Sep 16, 2025 at 03:11:53PM +0100, Lorenzo Stoakes wrote:
> We introduce the io_remap*() equivalents of remap_pfn_range_prepare() and
> remap_pfn_range_complete() to allow for I/O remapping via mmap_prepare.
> 
> We have to make some architecture-specific changes for those architectures
> which define customised handlers.
> 
> It doesn't really make sense to make this internal-only as arches specify
> their version of these functions so we declare these in mm.h.

Similar question to the remap_pfn_range patch.
> 
> Signed-off-by: Lorenzo Stoakes <lorenzo.stoakes@oracle.com>

Looks ok, but again, i'm no expert on this.

Acked-by: Pedro Falcato <pfalcato@suse.de>

-- 
Pedro

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/hfczgna46ok6zvh3xxgzdhf5t5nzqybpxkmvuulbzncagmgrcy%40ase57zw2xsj5.
