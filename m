Return-Path: <kasan-dev+bncBD74H4NGEIIOJHVKYYDBUBCIUDFYM@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23c.google.com (mail-lj1-x23c.google.com [IPv6:2a00:1450:4864:20::23c])
	by mail.lfdr.de (Postfix) with ESMTPS id CA5B9B7E25A
	for <lists+kasan-dev@lfdr.de>; Wed, 17 Sep 2025 14:42:27 +0200 (CEST)
Received: by mail-lj1-x23c.google.com with SMTP id 38308e7fff4ca-36077bb96d6sf1956141fa.3
        for <lists+kasan-dev@lfdr.de>; Wed, 17 Sep 2025 05:42:27 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758112947; cv=pass;
        d=google.com; s=arc-20240605;
        b=cJaMKo4ni1rPZplwMX+72baqNK60DUc4k3VZdJxpYndI/N0twQ1KQ5ZQiiq4t6A5dX
         UDfwZUz2xZ09JDfbpCNQBGZbg910pO4TCE0yNJifwLbIPOGIlF9ZQ1RBPJcRQq5UzcGS
         VlIOnc6a0e5MtBP8B15IcCigLEBrwrd58ulxzCFVlpDvKsQM4fdvKSi0ucdANja30Sml
         gQFgnoQ/xfK1QBt/g+7HykpPZDU8F23b/Suz9BnvrjhjDbSB8Eh1UW5/X0rUFG9sjabh
         s8NZPiHZSMGcMWPQZKEN1IcHvNoAESpW610ivWIx78ImthfKIWhnzwn1tBswLcXexI2x
         buqg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=PXCPDP0vQESb8aoKThjJm2sGH0Ktc6D20I0lH7K6sQ0=;
        fh=3D3t4JJ6cjzwdbGFm3fEMjsc4UKg6DoHTHf5ioREArs=;
        b=YbHVEXkbUOgzzMjY4MnWb5JOZ4s7UHrUNu7sKEp4cCEsCkcICuHVc7NN+96TK7ffxZ
         bGUCS+i7H3D5HZCbsArUv4ZZEPO7iClje6gJN6xRj0r4F+V+XMMWAm3pXqSJqW3Wyd5L
         Dg983/UDQfhuSDoC847Li/QQDyhBdSjcXQqmCQwnCaBQfttlaLLTCV+FyAah8B4K2MvO
         8TNPTzgkirClFmKjj88t+ycG005nCG0VZbtcghV4zKcT/yl+asyhVacDayeTztXn+zpB
         tEQIs+oU5FctsjMZZUhqtsrQmiDt48QRx/1+fbLzLBPx7TEmkTZUz1ZiMD4lPdJQ8aNM
         XKDQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.de header.s=susede2_rsa header.b="kNJ/uzXV";
       dkim=neutral (no key) header.i=@suse.de;
       dkim=pass header.i=@suse.de header.s=susede2_rsa header.b="kNJ/uzXV";
       dkim=neutral (no key) header.i=@suse.de;
       spf=pass (google.com: domain of pfalcato@suse.de designates 195.135.223.131 as permitted sender) smtp.mailfrom=pfalcato@suse.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=suse.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758112947; x=1758717747; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=PXCPDP0vQESb8aoKThjJm2sGH0Ktc6D20I0lH7K6sQ0=;
        b=IyUK/bhIjIaKWFi9Y+ABBx7yDfW5WoamfrlUWLiTVZiMr8COm0vI40I7YUaSWg3PUW
         sboHlext1V3HuzCyr0rSlTb5rl/jUuY5C71h5ZL7Ok58wJeFPJUpKwYRTASV2WSFEKlK
         7emHc5XS7roLZi5s/b0IHlGMqg9avwkPic3MNbijRuImFbKqWW61F1m8WAG6zXguBygV
         HO+SJXtVS8I71joZ0v5baaUBmTA3wWaiixRKZyy+46NcpYbkEtPNrHhxBLVKx+i10ZfW
         g3mTnO8czjlKhUS54lL1ngUetQFN6wcuPqebWbnptkog2XjG5LU74VliONOGqdBdB0nm
         E+Zw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758112947; x=1758717747;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=PXCPDP0vQESb8aoKThjJm2sGH0Ktc6D20I0lH7K6sQ0=;
        b=BUvjierLcdr7oq+m840oks7VrPWaALvFxQmBT6qkUbOa30b4/+n2Rnp7Pw4VzTSQk2
         G7/8Nj6B+NTdbUx+jWvhQqa/4aM3AKkHbxvR2qtwg138R64rmFcle86/aZfhXxlvspxS
         efugKXMoXkam59dcLHoi5Fy66mfDbhCTmbhJHrDr2qFYBmxTItw0HUmcDZrK1YPandXa
         RNjJSKnNi+piIbuK8pJ9Zc0tnZ0qarkIMBsPMt9kAiP3oY3fkCos+0AiVUdP59KZEu0V
         HAqjFJfLqQy5+vdp5gBLWpK+f432xSvPyQOfU6BehKR7izkoR+KD5cqQE3MywkxCe9E/
         uxNQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCW8QVZj02esKTk7BoiymHR/whHGhT5uFsliFo4XMKqPtnhfjZeVTecpFVcCfvRBAgEp9Rw5yw==@lfdr.de
X-Gm-Message-State: AOJu0YzHJsAGg+JETia3vCFzYR4zDeb4YrztzInnLlY7CD43qpHMclZJ
	rxfPXfYxruVTXRzpvx7D8eUnVFLUvNhlYr9fopMEAb8eqviTIMKkzX8s
X-Google-Smtp-Source: AGHT+IFLXyTTdK/XcBOxc3mO7rr5Bhp1Gg3KKFR01g9Q7MUGEijp/qtHoHGrrBrVoODW2NBzzMLVAA==
X-Received: by 2002:a05:6402:44c9:b0:62f:53fa:c3aa with SMTP id 4fb4d7f45d1cf-62f84446e76mr1566427a12.36.1758105444703;
        Wed, 17 Sep 2025 03:37:24 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd6jNA55gkULfIMA5+q1aKMI8Fyevx4QgmbC3lGA4DB49g==
Received: by 2002:aa7:cf07:0:b0:62f:9888:f350 with SMTP id 4fb4d7f45d1cf-62f9888fad8ls30340a12.1.-pod-prod-06-eu;
 Wed, 17 Sep 2025 03:37:22 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVOnFK35oI2K03FLIJkbAjX301Ql0Y5i7Wrg6tehsVh66d3Cf0UsyGKpJHg6nsuEbXFt9p6sxQyX14=@googlegroups.com
X-Received: by 2002:a17:907:6d29:b0:b04:5b3d:c305 with SMTP id a640c23a62f3a-b1bb0c43fbamr223698166b.17.1758105441949;
        Wed, 17 Sep 2025 03:37:21 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1758105441; cv=none;
        d=google.com; s=arc-20240605;
        b=ASGlTk60wgIvkJN7684YMPqGXb3GsGHqXtqB+bkRGs3Nipb9NU5UhxD7oMV58/Izi9
         7ZK3Aa/qYCuWa1C/V602zin7YRUXTRmYqzdNZ0U1rWxE/WIQGuz+s7UqwPPhswHdvptf
         AoMXdqSdRIFLROYLbPAt+efEjF82ayicAjSUKwCUQKWscvURlOjmbt+9LaBCspRIt9MV
         D3UJVvS4pD3U2rFGcd7AclyLbUj45A4lMgeURSpwDgbsKgLysSbHz2cp/JYrbxCPsvvh
         rZi9pNSESthwaioTVaYJLnPVX+rO4vgjbI6tVuKyLHyx7cbYL5orQT7SonDLoMZQgYmR
         1UBw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature:dkim-signature
         :dkim-signature:dkim-signature;
        bh=nZoP7xI9bh5cuZAC2MMMkkaHSM2qArN4UzTRm8GitpU=;
        fh=3+MH0ChJLBM72NzpB/XiB+Q7hxpuJ08qXy92Zn7JvPc=;
        b=dWjapK7N5BtSi+y31jz9eM/HDjGGCSh5fsarBO83t/sLMy3aAgakt9II7/9bDDJS7w
         gi6+N1qrzhIaLu4fgyMlz1ahvmbbrfh40t+xJVywwNI+i7GmbfMrl59W4BnBiJDLr7Mf
         ChMipMRdcNe7IilljDaL9bffgvr/mTWbtPMKTkaec70ImwnZtnU0+lNV6MkVcshxdWr3
         n5C6lV6F74vpjTysHSuuXavNM+ngCptYdbXFUCpSrOci5EoMxHB1FG+/sDDyRPBQJAS4
         FixxnqB9DnUiaDpLS7YyznnzQIzDuOpS73FOKlRdmx48gpx1I8e8RgmD0UptFPUY1LzJ
         GBOg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.de header.s=susede2_rsa header.b="kNJ/uzXV";
       dkim=neutral (no key) header.i=@suse.de;
       dkim=pass header.i=@suse.de header.s=susede2_rsa header.b="kNJ/uzXV";
       dkim=neutral (no key) header.i=@suse.de;
       spf=pass (google.com: domain of pfalcato@suse.de designates 195.135.223.131 as permitted sender) smtp.mailfrom=pfalcato@suse.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=suse.de
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [195.135.223.131])
        by gmr-mx.google.com with ESMTPS id 4fb4d7f45d1cf-62eda2fb03csi381502a12.4.2025.09.17.03.37.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 17 Sep 2025 03:37:21 -0700 (PDT)
Received-SPF: pass (google.com: domain of pfalcato@suse.de designates 195.135.223.131 as permitted sender) client-ip=195.135.223.131;
Received: from imap1.dmz-prg2.suse.org (unknown [10.150.64.97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id 5CAD71F7BC;
	Wed, 17 Sep 2025 10:37:21 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id BE4BD1368D;
	Wed, 17 Sep 2025 10:37:17 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id SZxDK12Pymj2OAAAD6G6ig
	(envelope-from <pfalcato@suse.de>); Wed, 17 Sep 2025 10:37:17 +0000
Date: Wed, 17 Sep 2025 11:37:07 +0100
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
Subject: Re: [PATCH v3 02/13] device/dax: update devdax to use mmap_prepare
Message-ID: <2jvm2x7krh7bkt43goiufksuxntncu2hxx67jos3i7zwj63jhh@rw47665pa25y>
References: <cover.1758031792.git.lorenzo.stoakes@oracle.com>
 <bfd55a49b89ebbdf2266d77c1f8df9339a99b97a.1758031792.git.lorenzo.stoakes@oracle.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <bfd55a49b89ebbdf2266d77c1f8df9339a99b97a.1758031792.git.lorenzo.stoakes@oracle.com>
X-Spam-Level: 
X-Spamd-Result: default: False [-2.30 / 50.00];
	BAYES_HAM(-3.00)[100.00%];
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
	DBL_BLOCKED_OPENRESOLVER(0.00)[suse.de:email,imap1.dmz-prg2.suse.org:helo]
X-Spam-Flag: NO
X-Spam-Score: -2.30
X-Original-Sender: pfalcato@suse.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.de header.s=susede2_rsa header.b="kNJ/uzXV";
       dkim=neutral (no key) header.i=@suse.de;       dkim=pass
 header.i=@suse.de header.s=susede2_rsa header.b="kNJ/uzXV";
       dkim=neutral (no key) header.i=@suse.de;       spf=pass (google.com:
 domain of pfalcato@suse.de designates 195.135.223.131 as permitted sender)
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

On Tue, Sep 16, 2025 at 03:11:48PM +0100, Lorenzo Stoakes wrote:
> The devdax driver does nothing special in its f_op->mmap hook, so
> straightforwardly update it to use the mmap_prepare hook instead.
> 
> Signed-off-by: Lorenzo Stoakes <lorenzo.stoakes@oracle.com>
> Acked-by: David Hildenbrand <david@redhat.com>
> Reviewed-by: Jan Kara <jack@suse.cz>

Acked-by: Pedro Falcato <pfalcato@suse.de>

> ---
>  drivers/dax/device.c | 32 +++++++++++++++++++++-----------
>  1 file changed, 21 insertions(+), 11 deletions(-)
> 
> diff --git a/drivers/dax/device.c b/drivers/dax/device.c
> index 2bb40a6060af..c2181439f925 100644
> --- a/drivers/dax/device.c
> +++ b/drivers/dax/device.c
> @@ -13,8 +13,9 @@
>  #include "dax-private.h"
>  #include "bus.h"
>  
> -static int check_vma(struct dev_dax *dev_dax, struct vm_area_struct *vma,
> -		const char *func)
> +static int __check_vma(struct dev_dax *dev_dax, vm_flags_t vm_flags,
> +		       unsigned long start, unsigned long end, struct file *file,
> +		       const char *func)
>  {
>  	struct device *dev = &dev_dax->dev;
>  	unsigned long mask;
> @@ -23,7 +24,7 @@ static int check_vma(struct dev_dax *dev_dax, struct vm_area_struct *vma,
>  		return -ENXIO;
>  
>  	/* prevent private mappings from being established */
> -	if ((vma->vm_flags & VM_MAYSHARE) != VM_MAYSHARE) {
> +	if ((vm_flags & VM_MAYSHARE) != VM_MAYSHARE) {
>  		dev_info_ratelimited(dev,
>  				"%s: %s: fail, attempted private mapping\n",
>  				current->comm, func);
> @@ -31,15 +32,15 @@ static int check_vma(struct dev_dax *dev_dax, struct vm_area_struct *vma,
>  	}
>  
>  	mask = dev_dax->align - 1;
> -	if (vma->vm_start & mask || vma->vm_end & mask) {
> +	if (start & mask || end & mask) {
>  		dev_info_ratelimited(dev,
>  				"%s: %s: fail, unaligned vma (%#lx - %#lx, %#lx)\n",
> -				current->comm, func, vma->vm_start, vma->vm_end,
> +				current->comm, func, start, end,
>  				mask);
>  		return -EINVAL;
>  	}
>  
> -	if (!vma_is_dax(vma)) {
> +	if (!file_is_dax(file)) {
>  		dev_info_ratelimited(dev,
>  				"%s: %s: fail, vma is not DAX capable\n",
>  				current->comm, func);
> @@ -49,6 +50,13 @@ static int check_vma(struct dev_dax *dev_dax, struct vm_area_struct *vma,
>  	return 0;
>  }
>  
> +static int check_vma(struct dev_dax *dev_dax, struct vm_area_struct *vma,
> +		     const char *func)
> +{
> +	return __check_vma(dev_dax, vma->vm_flags, vma->vm_start, vma->vm_end,
> +			   vma->vm_file, func);
> +}
> +

Side comment: I'm no DAX expert at all, but this check_vma() thing looks... smelly?
Besides the !dax_alive() check, I don't see the need to recheck vma limits at
every ->huge_fault() call. Even taking mremap() into account,
->get_unmapped_area() should Do The Right Thing, no?

-- 
Pedro

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/2jvm2x7krh7bkt43goiufksuxntncu2hxx67jos3i7zwj63jhh%40rw47665pa25y.
