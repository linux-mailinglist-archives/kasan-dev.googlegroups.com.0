Return-Path: <kasan-dev+bncBC5I5WEMW4JBBLMURLDAMGQE6PWZAJQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x437.google.com (mail-wr1-x437.google.com [IPv6:2a00:1450:4864:20::437])
	by mail.lfdr.de (Postfix) with ESMTPS id 76D74B52BDB
	for <lists+kasan-dev@lfdr.de>; Thu, 11 Sep 2025 10:37:03 +0200 (CEST)
Received: by mail-wr1-x437.google.com with SMTP id ffacd0b85a97d-3d3d2472b92sf299426f8f.1
        for <lists+kasan-dev@lfdr.de>; Thu, 11 Sep 2025 01:37:03 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757579823; cv=pass;
        d=google.com; s=arc-20240605;
        b=GowHgfj2kO4Y7xajivE0qH0jd0JGl9xIxwqXoKOvSWK3usqhFKAHi+QKTTdZdVXV8g
         8FGgH9nV+wzcqoMCmfYWtEbbMBpPFPvYoDtyuRRlvS7M8hRbtShGvypk7DCpdACWxGCK
         xxUIeA2UOo8rZxQBL8Wd0dHIUY5DN0ZShdn4a5ptVWuxNL3SCLdDy6GZTmqjwbD32as+
         Tzxx/zxqBG+InNk5ZPSPeT89rSpLqp5TRI8wdiRmvCPqH87nfdVOdoF11dVlXNFSJPPd
         42vJ1ZQ3mexv0wCE0cqVLYD54sSBuITErYEZgzRjUQEXNkNg/QWaC7Y+51MIWffwohOE
         GNRA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=2YhFqmF5JoCHAP977qFx4raqIA+Z52iGy5nfuymtJ9M=;
        fh=WDh9E5amTWA0oyHRMkUUl3pAqT1ctCWDsvv0BF7A4OI=;
        b=MMEAGcZDM/hnGHqlAL8Bv9g1LrVOKLpipPmxhOLg1W5ddMz214E4CYVQaM9o/3JBJ+
         iBnTrKWnlbXThfNIF8UesEGHeXRMM3jub1K9nLALW5orHmQA/ycjvEvp/qX5E59FBmfc
         S82W6qJSNzsS4FsH11pixIqsAbnFS0eAz4Ts7zyY9TCLG2LyIZFqnisfq5Hxm6VxW60p
         QfjS1OLrFbImgqoVulRb6NToNLZ+sWouZiNLRVvS/VmMAmHqCu0NY2Sp2qczzKwriUY9
         0Z4xMhYOHLR5d59m59eoOoZzXJCpD1xv7A3g4WGYiy8IFZMef1fZppBvwgl93ikHMaKg
         ryTQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=gbVdZ5or;
       dkim=neutral (no key) header.i=@suse.cz;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=BXH35BNu;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of jack@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) smtp.mailfrom=jack@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757579823; x=1758184623; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=2YhFqmF5JoCHAP977qFx4raqIA+Z52iGy5nfuymtJ9M=;
        b=b+5JJBH/wkdnYCTYx//IseYqDGq1+6PveVWnhXKnn7tiptKn8BSRPmlv05rDHyhcFK
         yaiHSo41CNTDulBTArjxR5rWaEXuxFGPh2/RMQ2xurTr61WbuU2GqHDc32cDtST7+SFL
         STCoEXVmFwzKjIUQeRhrBQ7+1leIUGEt3ld8w0oxcjT9qBpEZFzSB4wUDx4wrowiq2M/
         W3BsuRNSCZTkB2TmXoKDhBn54XRCpudL5WeauBo5Rl9rw/7bDkcO77wM4CpWIPaF4DBl
         BUGfy83apJIsuKmiO6NrEUdHkgfqmXJScpdeyQMIj0DwzHPqCyae1lcSLDlzWa72ZVxE
         FVaw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757579823; x=1758184623;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=2YhFqmF5JoCHAP977qFx4raqIA+Z52iGy5nfuymtJ9M=;
        b=thJ1pXJohYmMa53NpFXorYqAy6StO4/bbvaVexPZXDxIzfXLWLpiIccyCwAx0l+iLX
         LJ6aRmGQAyTlRievkq0gMC97AOjwImwMOC7Z5nB1mbKw5cEVEpjnhPehpIb4VP/ye46U
         G4q3p0IScuYpZe21wOPp/q06NDYkD8AVoamnDVnH3VgcENOdnPyYHsw4U1Csowp5ZPle
         PXhAcdGB7Xol7g1i51BnfasgU9oYfRFjNdD/IQ7Xp1n0YfbTRX38iJ5WGSUVUhPK1+rv
         PySaze3bMygZk2hLTll+ZTRoEcA45uyrXECnSwyCN2Y19O45Ia5khfr4uHDBDlHwV0V2
         LtiQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUR7M0DcdUzCZL6lb0CRkNJWgaUsjA2I4xjTOirNNjfaHhdUbx0ISNXQdzvW8HfniONl7mGXw==@lfdr.de
X-Gm-Message-State: AOJu0YzxcboCmV9aHssAHmiotBXh16B9AmAHjtR1NtZVOCoWrEGeECTK
	3RTlciF2N6UesnG6ZN6D7R6s1A14e7PDhux7cUQHGCnM9hRSG9+HlXiw
X-Google-Smtp-Source: AGHT+IEMMN0hheFSE+4KV0wi9jXYJpufm77PiVQefUHITYzahGPRTPvchymK1ToYJ8MdyaU9Xt4IWg==
X-Received: by 2002:a05:6000:2203:b0:3d2:208c:45aa with SMTP id ffacd0b85a97d-3e64b82d62bmr14400109f8f.29.1757579822525;
        Thu, 11 Sep 2025 01:37:02 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdxIT3qopYO7zv2JTODp4FbziWK2afbt5tvn92QRrD4tg==
Received: by 2002:a05:600c:674f:b0:459:ddca:2012 with SMTP id
 5b1f17b1804b1-45dffc18bb5ls2652615e9.2.-pod-prod-05-eu; Thu, 11 Sep 2025
 01:36:59 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXb6yQqp+Fr4aL4FR1zhGkMwl0M7JGmySiAvX70frumRBXeo2NHOTHxewr18tocUmEyGOJByPrsfdU=@googlegroups.com
X-Received: by 2002:a05:600c:1d2a:b0:450:cabd:b4a9 with SMTP id 5b1f17b1804b1-45dddef7fcfmr137987255e9.29.1757579819675;
        Thu, 11 Sep 2025 01:36:59 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1757579819; cv=none;
        d=google.com; s=arc-20240605;
        b=UTIIcpFmB/NMmfYwQkL6AhmavUoN3dw+qlF96a+Uqcj8WD/9WjTRfCH4eJI/CMA/uP
         ++UM1AuGd/B7jgOFvepaJ6NyANxAi8HPHkD2lQp4cF8Cpqzy0iAswLyj/AEMc9jDbFx7
         T50s/vf49btYvopKaIaxX5Wweurk0rlJeTcA8eLtW6hduEPgsCMJgyYjnWTUUqW7G8Mk
         VeafaD5drW4a/ekHkiuDC6Lt3rb+v9uYx7p1yw514Iwu36+vmiRjzAzmgxVqzQYLbRT0
         NcYpBS6CPjRQiTA+gVuHUkm9uA725XVm5aToF11whtPlRFHDDINu+AdjgYS6ecPTxLQ8
         9Gqg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature:dkim-signature
         :dkim-signature:dkim-signature;
        bh=MVKatHAMv6K0HJB+fE+uvvzEY9BdzRg6mGSrDhfixOc=;
        fh=/v17VW8MchCHUgpXxAXTMs5Ee7lYsmC259Kuc6hqZT8=;
        b=B8Qk/YGFVVPEoRbayX4rwBuBvx541jVwvsBNlKNbR/Jb0Tf2KDgErHmgPdHX0VX92s
         PZdXXDE4EBJWDDfj4ScrE25T9MiwmywPe90aDnGUrK5WS4ZgBYFrEP2mkKAt/vzzS2uK
         k5kTDRN2QG5SQVxvmIVP5gyoq9MC/auCdTC7+z8WsX05I80gqYnCziCgRYAsezvYPFGB
         4JEPmHJ6U+KIgUCovmqGnoPwGx/pmEnA27qMiIbye0FwlRPSMXpiM8jNx+XGMEgo7HhZ
         x/l4G5De1H0j8A/jgXh9bTEfMTrFXVpIbk/ewWTnfbbI9DG55lk2xbYMhBrb6+moj5bO
         MzFw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=gbVdZ5or;
       dkim=neutral (no key) header.i=@suse.cz;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=BXH35BNu;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of jack@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) smtp.mailfrom=jack@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [2a07:de40:b251:101:10:150:64:2])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-45e0155dc80si366525e9.0.2025.09.11.01.36.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 11 Sep 2025 01:36:59 -0700 (PDT)
Received-SPF: pass (google.com: domain of jack@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) client-ip=2a07:de40:b251:101:10:150:64:2;
Received: from imap1.dmz-prg2.suse.org (imap1.dmz-prg2.suse.org [IPv6:2a07:de40:b281:104:10:150:64:97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id E8F2468606;
	Thu, 11 Sep 2025 08:36:58 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id D83BA1372E;
	Thu, 11 Sep 2025 08:36:58 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id mpvENCqKwmjOcgAAD6G6ig
	(envelope-from <jack@suse.cz>); Thu, 11 Sep 2025 08:36:58 +0000
Received: by quack3.suse.cz (Postfix, from userid 1000)
	id 8E4F6A0A2D; Thu, 11 Sep 2025 10:36:58 +0200 (CEST)
Date: Thu, 11 Sep 2025 10:36:58 +0200
From: Jan Kara <jack@suse.cz>
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
	Jann Horn <jannh@google.com>, Pedro Falcato <pfalcato@suse.de>, linux-doc@vger.kernel.org, 
	linux-kernel@vger.kernel.org, linux-fsdevel@vger.kernel.org, linux-csky@vger.kernel.org, 
	linux-mips@vger.kernel.org, linux-s390@vger.kernel.org, sparclinux@vger.kernel.org, 
	nvdimm@lists.linux.dev, linux-cxl@vger.kernel.org, linux-mm@kvack.org, 
	ntfs3@lists.linux.dev, kexec@lists.infradead.org, kasan-dev@googlegroups.com, 
	Jason Gunthorpe <jgg@nvidia.com>
Subject: Re: [PATCH v2 03/16] mm: add vma_desc_size(), vma_desc_pages()
 helpers
Message-ID: <afrz7upbj463hmejktsw2dxvvty7a7jtsibyn4fdlwwyrzogrh@c3svlrvl4job>
References: <cover.1757534913.git.lorenzo.stoakes@oracle.com>
 <5ac75e5ac627c06e62401dfda8c908eadac8dfec.1757534913.git.lorenzo.stoakes@oracle.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <5ac75e5ac627c06e62401dfda8c908eadac8dfec.1757534913.git.lorenzo.stoakes@oracle.com>
X-Spamd-Result: default: False [-2.51 / 50.00];
	BAYES_HAM(-3.00)[100.00%];
	SUSPICIOUS_RECIPS(1.50)[];
	NEURAL_HAM_LONG(-1.00)[-1.000];
	MID_RHS_NOT_FQDN(0.50)[];
	R_DKIM_ALLOW(-0.20)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	NEURAL_HAM_SHORT(-0.20)[-1.000];
	MIME_GOOD(-0.10)[text/plain];
	MX_GOOD(-0.01)[];
	RCVD_TLS_LAST(0.00)[];
	RCVD_COUNT_THREE(0.00)[3];
	DKIM_SIGNED(0.00)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	MIME_TRACE(0.00)[0:+];
	FUZZY_RATELIMITED(0.00)[rspamd.com];
	ARC_NA(0.00)[];
	FREEMAIL_ENVRCPT(0.00)[gmail.com];
	FREEMAIL_CC(0.00)[linux-foundation.org,lwn.net,infradead.org,kernel.org,alpha.franken.de,linux.ibm.com,davemloft.net,gaisler.com,arndb.de,linuxfoundation.org,intel.com,fluxnic.net,linux.dev,suse.de,redhat.com,paragon-software.com,arm.com,zeniv.linux.org.uk,suse.cz,oracle.com,google.com,suse.com,linux.alibaba.com,gmail.com,vger.kernel.org,lists.linux.dev,kvack.org,lists.infradead.org,googlegroups.com,nvidia.com];
	DKIM_TRACE(0.00)[suse.cz:+];
	TO_MATCH_ENVRCPT_SOME(0.00)[];
	FROM_EQ_ENVFROM(0.00)[];
	FROM_HAS_DN(0.00)[];
	TO_DN_SOME(0.00)[];
	DNSWL_BLOCKED(0.00)[2a07:de40:b281:104:10:150:64:97:from];
	RCVD_VIA_SMTP_AUTH(0.00)[];
	RCPT_COUNT_GT_50(0.00)[59];
	R_RATELIMIT(0.00)[to_ip_from(RLx5fqm8k6as49t7tzapjazi4f)];
	MISSING_XM_UA(0.00)[];
	DBL_BLOCKED_OPENRESOLVER(0.00)[suse.com:email]
X-Spam-Flag: NO
X-Spam-Level: 
X-Rspamd-Queue-Id: E8F2468606
X-Rspamd-Server: rspamd2.dmz-prg2.suse.org
X-Rspamd-Action: no action
X-Spam-Score: -2.51
X-Original-Sender: jack@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=gbVdZ5or;       dkim=neutral
 (no key) header.i=@suse.cz;       dkim=pass header.i=@suse.cz
 header.s=susede2_rsa header.b=BXH35BNu;       dkim=neutral (no key)
 header.i=@suse.cz;       spf=pass (google.com: domain of jack@suse.cz
 designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) smtp.mailfrom=jack@suse.cz
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

On Wed 10-09-25 21:21:58, Lorenzo Stoakes wrote:
> It's useful to be able to determine the size of a VMA descriptor range used
> on f_op->mmap_prepare, expressed both in bytes and pages, so add helpers
> for both and update code that could make use of it to do so.
> 
> Signed-off-by: Lorenzo Stoakes <lorenzo.stoakes@oracle.com>

Looks good, I presume more users will come later in the series :). Feel
free to add:

Reviewed-by: Jan Kara <jack@suse.cz>

								Honza

> ---
>  fs/ntfs3/file.c    |  2 +-
>  include/linux/mm.h | 10 ++++++++++
>  mm/secretmem.c     |  2 +-
>  3 files changed, 12 insertions(+), 2 deletions(-)
> 
> diff --git a/fs/ntfs3/file.c b/fs/ntfs3/file.c
> index c1ece707b195..86eb88f62714 100644
> --- a/fs/ntfs3/file.c
> +++ b/fs/ntfs3/file.c
> @@ -304,7 +304,7 @@ static int ntfs_file_mmap_prepare(struct vm_area_desc *desc)
>  
>  	if (rw) {
>  		u64 to = min_t(loff_t, i_size_read(inode),
> -			       from + desc->end - desc->start);
> +			       from + vma_desc_size(desc));
>  
>  		if (is_sparsed(ni)) {
>  			/* Allocate clusters for rw map. */
> diff --git a/include/linux/mm.h b/include/linux/mm.h
> index 892fe5dbf9de..0b97589aec6d 100644
> --- a/include/linux/mm.h
> +++ b/include/linux/mm.h
> @@ -3572,6 +3572,16 @@ static inline unsigned long vma_pages(const struct vm_area_struct *vma)
>  	return (vma->vm_end - vma->vm_start) >> PAGE_SHIFT;
>  }
>  
> +static inline unsigned long vma_desc_size(struct vm_area_desc *desc)
> +{
> +	return desc->end - desc->start;
> +}
> +
> +static inline unsigned long vma_desc_pages(struct vm_area_desc *desc)
> +{
> +	return vma_desc_size(desc) >> PAGE_SHIFT;
> +}
> +
>  /* Look up the first VMA which exactly match the interval vm_start ... vm_end */
>  static inline struct vm_area_struct *find_exact_vma(struct mm_struct *mm,
>  				unsigned long vm_start, unsigned long vm_end)
> diff --git a/mm/secretmem.c b/mm/secretmem.c
> index 60137305bc20..62066ddb1e9c 100644
> --- a/mm/secretmem.c
> +++ b/mm/secretmem.c
> @@ -120,7 +120,7 @@ static int secretmem_release(struct inode *inode, struct file *file)
>  
>  static int secretmem_mmap_prepare(struct vm_area_desc *desc)
>  {
> -	const unsigned long len = desc->end - desc->start;
> +	const unsigned long len = vma_desc_size(desc);
>  
>  	if ((desc->vm_flags & (VM_SHARED | VM_MAYSHARE)) == 0)
>  		return -EINVAL;
> -- 
> 2.51.0
> 
-- 
Jan Kara <jack@suse.com>
SUSE Labs, CR

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/afrz7upbj463hmejktsw2dxvvty7a7jtsibyn4fdlwwyrzogrh%40c3svlrvl4job.
