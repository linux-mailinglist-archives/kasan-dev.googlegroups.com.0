Return-Path: <kasan-dev+bncBC5I5WEMW4JBBYMTRLDAMGQEIKCV3HY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13f.google.com (mail-lf1-x13f.google.com [IPv6:2a00:1450:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id ADA2FB52BCD
	for <lists+kasan-dev@lfdr.de>; Thu, 11 Sep 2025 10:35:47 +0200 (CEST)
Received: by mail-lf1-x13f.google.com with SMTP id 2adb3069b0e04-55f6af0affesf294716e87.1
        for <lists+kasan-dev@lfdr.de>; Thu, 11 Sep 2025 01:35:47 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757579747; cv=pass;
        d=google.com; s=arc-20240605;
        b=jscQ6s6jrXyVpFqRjqtHey0HUsadQqUGkzXiWjQTFiAIUiZnYKRpVfK2dd3gFxout4
         SYEb+iv8z5Am2jjNcHbJNWEbQQa/iJw+CCwzMVdFTCFjArnxeyDksCJTle3cM6WdMQBS
         Yc7+dPGtbxXMhwj4N83gZkwRbcb/8r8OUFdb2iBMznsI0J75xM7dw8XKEXwTT449Qx3X
         ANyCeYjCPA4SJr80Mg2epTBlLHNr9X7iPDkqs0XIqTk/Uy9WjoLrx3CdA2FtEkjkV848
         sdnODfKfY81RHWK3q2GyxkIgtk+YVNNRvc8KxUakViBq60DnsGFA5OZBPyepTFbYhTlO
         IHwg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=luWcNKSpaxAwnMI4gc1KAIpv0JMX7q+eYRY8/KhYw88=;
        fh=P/E7g1RUseY0m4KPizEkv4OBirgnlSu9vvQrR8EFSCY=;
        b=I4hgqnA5QZDl8fPoGFIkHpIMyAut+QtKIjoWgy5LsSUkF1eoSsln5zJUFJxglNE0ET
         3bE5GT0QU+062TEcW4AV2DA0Mh6DN8ohQxdIbqNncun4QaT8avK4r0wk28BypwIYO4oF
         +te0uU1WpsJPsQp2zZWzLL0aFq5Gws+pEewjN4icBxigDagIkySRiwFcGgiwNY6X1GiU
         QrgCwaWwVB6hhjuB7xzp/QPhBSHaQGH/+Ad4jH8xFJFZzxNXztpgGteo9y+lDVhRzbi3
         fQCIgtpEbBQkEh9Yb+dC/oqrWQvR8pLKuOLoWjRcdM345orHTnGdzT8Z32PmI6VsBf2E
         +vaw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b="V/2pNPLX";
       dkim=neutral (no key) header.i=@suse.cz;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b="V/2pNPLX";
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of jack@suse.cz designates 195.135.223.130 as permitted sender) smtp.mailfrom=jack@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757579747; x=1758184547; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=luWcNKSpaxAwnMI4gc1KAIpv0JMX7q+eYRY8/KhYw88=;
        b=xr8h6ZXrJkIt6nrbZ9vRWf36gdjGaDla0EUSVxSQpwD7DBpAHLQdpXYSifeWwcnRPm
         JjOVzxmCCehLMjuoUeY3P/F9+VYTaVk2Js51qvIIiBqQFez23JvEYV2zTGBBeoILcuoR
         dJicD9GoFAqqkIbmrweG5Rp0RoE7BgxwHCcjdLLfB1WcQtoumdZpC/EsODhHWGsWjn/G
         6JbsFOQjlVJWZC2+hQeJATzudTBm/OEMulwaO1DUNJwc816Wi2LJBZPuz+wgRrkWrrNE
         3E++Kc5LUZPG2zaR+ZtfCtQIAV+IsWl9FInbyE9l4fropvRZUWaNB9w1WArIo1gU/DXB
         rRZg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757579747; x=1758184547;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=luWcNKSpaxAwnMI4gc1KAIpv0JMX7q+eYRY8/KhYw88=;
        b=rYW7+Q7C1asdECnJriqh0u/Faet3PAzTvhtUCrbKUaPTR3xh5S5OCloU5gDpBttEvV
         R6aHd8wQHRsIVInCfUzhOmhsv5ZTVW6CYcRWUFyp6ueeKZJy3IGfa4h8K1yEyFgtjUGh
         5ceDl20C9ak+dJPr2jpqFsEz9g0d3CdUC+G/NGxem4plmmE2ayl/2Iu3ZCRIRBeCd8J1
         BJGu2m+NNzJIu/zyU2RndADLQXodIe0lPBDxA8j/0GPgIuu+hoF11baC5Z4N7zSkBOm1
         SnthwyvBzMubt5viPG15FuxPJpuz6/BSW++iC0G9rhhT9HpUANdOX7G/u0UqbHb26vIk
         USMA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWlqrZ80SEq3z1i1dTe5iJJ4qJP1Mi5mi84pgyzB4IbgubEPTnV50uHcG43Dsp87QNFPw6P+Q==@lfdr.de
X-Gm-Message-State: AOJu0YxQdesaP2Eb2KLkZKvsKXDi7SS6RAGbLKymgN2eKzx4u4JLC0zw
	Y2lxZ8WiW10rdL8OwVa7kPHg9NwXM5ZhTpYFFDBK+HeBPapAsMen1AX5
X-Google-Smtp-Source: AGHT+IE5cUrXXYxtn82yqBn1yCEiA4w6T+y4cZeIrgWa0ihUvYRttuTwNdMyyhUFLjAQp6ClvXZ2Dw==
X-Received: by 2002:a05:651c:1117:10b0:336:5d33:c394 with SMTP id 38308e7fff4ca-33b56213846mr58333781fa.33.1757579746351;
        Thu, 11 Sep 2025 01:35:46 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcCd6VXHeYDYKj+3HXrK8lAqk3hPs4+kL/LdhplMjVycw==
Received: by 2002:a05:651c:f0a:b0:335:7e09:e3da with SMTP id
 38308e7fff4ca-34eb1fc10f5ls1067441fa.2.-pod-prod-04-eu; Thu, 11 Sep 2025
 01:35:43 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCV7fmNrAgAQ771nBfb6b1WNDeth6XODLB/oMhktvif0wxMfN93qw+0ckzPlAHkgloWjN4bIsx5J4eU=@googlegroups.com
X-Received: by 2002:a05:651c:411a:b0:333:f113:cbab with SMTP id 38308e7fff4ca-33b5192ec23mr37602451fa.16.1757579743144;
        Thu, 11 Sep 2025 01:35:43 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1757579743; cv=none;
        d=google.com; s=arc-20240605;
        b=k3mKMm9RMpWo9gSGGqgWJpwWqR+u6hTuc5SwDcp8O80JUrp7KWMEav7qwJpZA7w/dG
         H/YqaoYK7PBi2+pxUM7yQ9N3pETj5ZIQnReifTztButrGhBPQFoDh/kPqkWaCcxJ0oCH
         l5j0WPXsCqPYu8ooK7jVPo7uokvSuEuTIKDknCEIjMYLGFHUB5mV/3+dfyPdAiKO3MNQ
         WEY3tEwFdiRIp0EcmTYsbCF43CwPzcalVBKB4x+CzFBUtWzgmzQ8N1uQieaFnZ6os8xJ
         lfGDeNdo/EHdYED/AsBNy7V1Vf/VG1n4zHn9F1mEYdT8eEImsqRXU6lMLSsRmyCFVyo2
         TG1g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature:dkim-signature
         :dkim-signature:dkim-signature;
        bh=KZHXjktAiNRSWCsp7mRo7oXVASySHuSrY3xtvxgr0Oo=;
        fh=/v17VW8MchCHUgpXxAXTMs5Ee7lYsmC259Kuc6hqZT8=;
        b=b3pSVr6Mv3lWdIK81vMjWoArYPxShc9O/LSkX0ZIR8h7/1Asq+enDOdFua5melQxX4
         PP6+wB+ZkYdxWbYZNc7EHo6hWaK/ZsUdPDd1lkI2E0OWJiG1d2i+zmxaoPKljWhFpb03
         hx81GXvMOzkxm3OSBO1pgAPPmEAZ1bDf8HKonnHIZJAn8otneMn0Uis/r6Tp8Dk0eIST
         RGJpkQ0N3A69Xit9o3Le3NMqM5bd4ooGaD8uxxGZMI+iP73disLvrYE13vbxk2EFaRtS
         mt7etnqpV43O+3qQd2iEP/gxPrFxieqgI/WajmyHsKIu5sS/ren2KV9ihmD701ul6eD/
         fMDA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b="V/2pNPLX";
       dkim=neutral (no key) header.i=@suse.cz;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b="V/2pNPLX";
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of jack@suse.cz designates 195.135.223.130 as permitted sender) smtp.mailfrom=jack@suse.cz
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [195.135.223.130])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-34f10020328si218541fa.0.2025.09.11.01.35.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 11 Sep 2025 01:35:43 -0700 (PDT)
Received-SPF: pass (google.com: domain of jack@suse.cz designates 195.135.223.130 as permitted sender) client-ip=195.135.223.130;
Received: from imap1.dmz-prg2.suse.org (unknown [10.150.64.97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id A4BA43F8BF;
	Thu, 11 Sep 2025 08:35:41 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id 93F831372E;
	Thu, 11 Sep 2025 08:35:41 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id 1yYeJN2JwmhYcgAAD6G6ig
	(envelope-from <jack@suse.cz>); Thu, 11 Sep 2025 08:35:41 +0000
Received: by quack3.suse.cz (Postfix, from userid 1000)
	id 48964A0A2D; Thu, 11 Sep 2025 10:35:41 +0200 (CEST)
Date: Thu, 11 Sep 2025 10:35:41 +0200
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
Subject: Re: [PATCH v2 02/16] device/dax: update devdax to use mmap_prepare
Message-ID: <fpdlink5oiu7dbx35qayavv4lq2qjvruyplo2bomvu7lnsz62h@uwoawxkmywo7>
References: <cover.1757534913.git.lorenzo.stoakes@oracle.com>
 <12f96a872e9067fa678a37b8616d12b2c8d1cc10.1757534913.git.lorenzo.stoakes@oracle.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <12f96a872e9067fa678a37b8616d12b2c8d1cc10.1757534913.git.lorenzo.stoakes@oracle.com>
X-Spamd-Result: default: False [-2.30 / 50.00];
	BAYES_HAM(-3.00)[100.00%];
	SUSPICIOUS_RECIPS(1.50)[];
	NEURAL_HAM_LONG(-1.00)[-1.000];
	MID_RHS_NOT_FQDN(0.50)[];
	NEURAL_HAM_SHORT(-0.20)[-1.000];
	MIME_GOOD(-0.10)[text/plain];
	FUZZY_RATELIMITED(0.00)[rspamd.com];
	RCVD_TLS_LAST(0.00)[];
	RCVD_COUNT_THREE(0.00)[3];
	MIME_TRACE(0.00)[0:+];
	DKIM_SIGNED(0.00)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	ARC_NA(0.00)[];
	FREEMAIL_ENVRCPT(0.00)[gmail.com];
	FREEMAIL_CC(0.00)[linux-foundation.org,lwn.net,infradead.org,kernel.org,alpha.franken.de,linux.ibm.com,davemloft.net,gaisler.com,arndb.de,linuxfoundation.org,intel.com,fluxnic.net,linux.dev,suse.de,redhat.com,paragon-software.com,arm.com,zeniv.linux.org.uk,suse.cz,oracle.com,google.com,suse.com,linux.alibaba.com,gmail.com,vger.kernel.org,lists.linux.dev,kvack.org,lists.infradead.org,googlegroups.com,nvidia.com];
	R_RATELIMIT(0.00)[to_ip_from(RLizrtjkoytmmoj3iud1rzij51)];
	FROM_EQ_ENVFROM(0.00)[];
	FROM_HAS_DN(0.00)[];
	TO_DN_SOME(0.00)[];
	TO_MATCH_ENVRCPT_SOME(0.00)[];
	RCVD_VIA_SMTP_AUTH(0.00)[];
	RCPT_COUNT_GT_50(0.00)[59];
	MISSING_XM_UA(0.00)[];
	DBL_BLOCKED_OPENRESOLVER(0.00)[suse.com:email]
X-Spam-Flag: NO
X-Spam-Level: 
X-Spam-Score: -2.30
X-Original-Sender: jack@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b="V/2pNPLX";
       dkim=neutral (no key) header.i=@suse.cz;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b="V/2pNPLX";
       dkim=neutral (no key) header.i=@suse.cz;       spf=pass (google.com:
 domain of jack@suse.cz designates 195.135.223.130 as permitted sender) smtp.mailfrom=jack@suse.cz
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

On Wed 10-09-25 21:21:57, Lorenzo Stoakes wrote:
> The devdax driver does nothing special in its f_op->mmap hook, so
> straightforwardly update it to use the mmap_prepare hook instead.
> 
> Acked-by: David Hildenbrand <david@redhat.com>
> Signed-off-by: Lorenzo Stoakes <lorenzo.stoakes@oracle.com>

Looks good. Feel free to add:

Reviewed-by: Jan Kara <jack@suse.cz>

								Honza

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
>  /* see "strong" declaration in tools/testing/nvdimm/dax-dev.c */
>  __weak phys_addr_t dax_pgoff_to_phys(struct dev_dax *dev_dax, pgoff_t pgoff,
>  		unsigned long size)
> @@ -285,8 +293,9 @@ static const struct vm_operations_struct dax_vm_ops = {
>  	.pagesize = dev_dax_pagesize,
>  };
>  
> -static int dax_mmap(struct file *filp, struct vm_area_struct *vma)
> +static int dax_mmap_prepare(struct vm_area_desc *desc)
>  {
> +	struct file *filp = desc->file;
>  	struct dev_dax *dev_dax = filp->private_data;
>  	int rc, id;
>  
> @@ -297,13 +306,14 @@ static int dax_mmap(struct file *filp, struct vm_area_struct *vma)
>  	 * fault time.
>  	 */
>  	id = dax_read_lock();
> -	rc = check_vma(dev_dax, vma, __func__);
> +	rc = __check_vma(dev_dax, desc->vm_flags, desc->start, desc->end, filp,
> +			 __func__);
>  	dax_read_unlock(id);
>  	if (rc)
>  		return rc;
>  
> -	vma->vm_ops = &dax_vm_ops;
> -	vm_flags_set(vma, VM_HUGEPAGE);
> +	desc->vm_ops = &dax_vm_ops;
> +	desc->vm_flags |= VM_HUGEPAGE;
>  	return 0;
>  }
>  
> @@ -377,7 +387,7 @@ static const struct file_operations dax_fops = {
>  	.open = dax_open,
>  	.release = dax_release,
>  	.get_unmapped_area = dax_get_unmapped_area,
> -	.mmap = dax_mmap,
> +	.mmap_prepare = dax_mmap_prepare,
>  	.fop_flags = FOP_MMAP_SYNC,
>  };
>  
> -- 
> 2.51.0
> 
-- 
Jan Kara <jack@suse.com>
SUSE Labs, CR

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/fpdlink5oiu7dbx35qayavv4lq2qjvruyplo2bomvu7lnsz62h%40uwoawxkmywo7.
