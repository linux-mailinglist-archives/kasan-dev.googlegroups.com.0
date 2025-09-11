Return-Path: <kasan-dev+bncBC5I5WEMW4JBBNMSRLDAMGQEXTP5CLI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x338.google.com (mail-wm1-x338.google.com [IPv6:2a00:1450:4864:20::338])
	by mail.lfdr.de (Postfix) with ESMTPS id C0816B52BAF
	for <lists+kasan-dev@lfdr.de>; Thu, 11 Sep 2025 10:32:54 +0200 (CEST)
Received: by mail-wm1-x338.google.com with SMTP id 5b1f17b1804b1-45cb5dbda9csf2762785e9.2
        for <lists+kasan-dev@lfdr.de>; Thu, 11 Sep 2025 01:32:54 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757579574; cv=pass;
        d=google.com; s=arc-20240605;
        b=KW5fZudRYdlq0FhKIYZubX76jeXYVE02SMRYRpBelebpYSmGeXi0GGshPdkJylRRak
         67xLBgUPFQwk6t5+j84ym1mWESTMWcjU5PCSy6RMYIjeAfmlPfyGQx6woc+gP84VKqoA
         7elphe9ZZp4DP1FwB1b4vAVuKt2B06eRVV8YaJI0XU61RDuGJmKm/BwBzo+KgpLPZskC
         hg14gQ91FFQ9XTbeb2BsJzRSBak37DjFMUBhvsPSC+6rIz+UTofiLhxCR1P6uDonM9Po
         8iP5OkzRoB/AIj4SC/HFEpyf1xpNvVnoSW5aekZx8RgxB0/MVfWv+emar3LP3pp4XOlG
         mC+A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=K9TAjK4lwOSE4+3N31ieblp3xMkW6wuMaHKuY7M7Mhs=;
        fh=907F9ZbAgySJKoE0f48QtZrJGQezH12Jlz13vUq3yiQ=;
        b=dL3gBUpWZgw5s8RTxuMpMTH4S6Y1iIntpFeaW9AGhD9a3dEjMphFUr4+j6qJ5zrRrH
         bNDp8hAEaphFl9+RX1qF0u4bJFJWHRXpsaAEngRUQx+x+QnwfY+IssAUlYhPn/DU01Ac
         DArMLAAKEZ1yxfVI5JU01VN+WdzIVTrS1pn4I3DbP98gUyqtkEh+S3JLPl9Lrb4R5Mzl
         WOg93+EOlcP5s5qk3Zc8wgXF5LTi7hI5JFooxfqVqp0dbm6WVwQGmMuuTxR8EXVGbiNo
         vl9ImFvLjcY6a8E9Q1LK0MRTmYANJ1gjLtOseIo4G3AnhbBxPRNNs4IiU5xXfS/Wcx+W
         vY4w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=g69g7tVg;
       dkim=neutral (no key) header.i=@suse.cz header.b=0Kn9GhCx;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b="Rlw8/zRp";
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of jack@suse.cz designates 195.135.223.131 as permitted sender) smtp.mailfrom=jack@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757579574; x=1758184374; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=K9TAjK4lwOSE4+3N31ieblp3xMkW6wuMaHKuY7M7Mhs=;
        b=G3ZSHLaZiKEfz7dWQEmecjEI8Khl/CcV4CECS051P4EETqwsC7IG5oApVwb5HBuziC
         UHe+6wXa2Dg1Hr7RGoAjMzoTwPwQnn+i5Ir4/aeu9nSv6LUqOLMTMtYIF/At1BvGZsuv
         NQFXHsOheY8bHi92/cbPuD4I9uCyx8hF6m6rKYEQ/BKCsg5HG9Hkj6ComReza9y2xkSf
         3yR+DGfrHuGvUYYEAVpgTmGPQ6W79lb54k1x5EzNX86xrkmNF3vJS81fpg0MG/tjIIb4
         HLe7lHi1VGovmYLaSRy1A0elcJUdcSMlGbVrM8UF/0o2xavUKRR9Kk3v2rSz2Kotn9Rv
         6vWw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757579574; x=1758184374;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=K9TAjK4lwOSE4+3N31ieblp3xMkW6wuMaHKuY7M7Mhs=;
        b=VirO0SIG0GL3dTYWZygrw1MvlgPGScKOXj7leE8KB0aS3yxbrmRvW6QalkaB47FhBH
         htcjcYsBtdo5o3GnT5e2cxQKeI0qhRNubczt2CkZR7gWxrkYENDOrKPY/EGoklRlSZbJ
         8jw+gidWvfuyOl+Q6fxqJmf1k+ePSLewk5Y8GycHSdTXrkfnMyoILOGNeXanHY/yVOF4
         C2GUcYC+VOt9bWET8a38erN9YXuXghcxkMBtptr921vbtt5M2PI+12uR5aiMStfQ1FZU
         Zug9GMG3AHqf3lW0CvFTOFhXluEiHAYPhGKd6Vn1H7Lz5vUimZSEbUI+EQtjGCBQlAVl
         jvNA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWqt5rDm/TeXWzcAeL7JH2OfYaqr1m7w+9+2BYAbKP4qL5J0ocZkkfksidC3O7gnh3I8XapEQ==@lfdr.de
X-Gm-Message-State: AOJu0YzH4xQPntIcz2il2DS9SdXIjhI2h48dCMb7fxosMWFB3ltRiCZA
	f3pNhDttK32gs3YifBfhesLu7w2OQI+zzcoOGAqyvuXv75rk5b6XpOzB
X-Google-Smtp-Source: AGHT+IGAOJHb/Xszp5uYNydSI9arP+mpO9mDPNWoXDkONl+mTpgsUPfg9uSzPZ7CGT+/gHwbj/iZzg==
X-Received: by 2002:a05:600c:1f91:b0:45d:d5df:ab2d with SMTP id 5b1f17b1804b1-45dddeef92cmr161897635e9.26.1757579573906;
        Thu, 11 Sep 2025 01:32:53 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcev/0FeCfD6kKdmQB6gDykVzxxzNvD3Xzopw4xTgEUGQ==
Received: by 2002:a05:600c:6090:b0:45b:bd1e:2b11 with SMTP id
 5b1f17b1804b1-45e01ba4d59ls2604395e9.0.-pod-prod-03-eu; Thu, 11 Sep 2025
 01:32:51 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXCX9ueeToGFLn1CoKxC0q1d45594kmfxjE8XAvWaSdUwOltutd6KiiWxUY3xYiBIH9CpbqkYoK1PQ=@googlegroups.com
X-Received: by 2002:a05:600c:4e13:b0:45b:79fd:cb3d with SMTP id 5b1f17b1804b1-45de19f4ea7mr173596395e9.36.1757579570684;
        Thu, 11 Sep 2025 01:32:50 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1757579570; cv=none;
        d=google.com; s=arc-20240605;
        b=hRA7o9XM0aKGdKoSqYKBtAr0n0og3ordTzRP0wqLr+oD86jgNKbTLzvpl5tRKT4Imz
         15DW+LqsctSQIBJZwx0CP+tLmfoRoo4NXqASN09ksvWUwDmP+Bn0QTdWZEhVdjuH5m39
         /YTKtcoyPUXVZFru518XHymvKoU/ZdWtgnSVAWejwve6mDh+GvxP2HOkAER0lCKC2Dtr
         3MWaUZLEVeaT5ZWWJ+llnSY518W2jgfDzKqEkmvV91GdAprUFa5yGuYtjhUK0kDfKbfd
         HetHKaqp7ZEVJv6GvyX9/Lo7BPPPyiwicaI4dDCba1T5ThW/1PLJXBUrls5boYE1NziJ
         9fOQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature:dkim-signature
         :dkim-signature:dkim-signature;
        bh=pePLUMNa380skWZ7luqeNYuVXr6xGvhkxPkdStUqzL8=;
        fh=/v17VW8MchCHUgpXxAXTMs5Ee7lYsmC259Kuc6hqZT8=;
        b=M6o/vG/X372/im78k+wUKj/0vE/T5EXKtl76MazdPgUS1+rYJtTe2hSxTFIlZV0MtU
         YYTLI+CxTJHFK4Lx6KOpWV+khmIC81BgnISqGS71BFGxIynYb3HP/7iAqqkZHg1Mmcov
         tDModN/0gghRApcgYJtHKn2y0l4LguqMZCxI3dTyusCHQI3011Wy9EQJTt/aBYGCF4Ns
         Sb7mQJupxi0tGsPaxKJ4RxGperV6+b1qAraijec/VVCQML7+RbwWMgCN9ZwPJkWz2P1E
         W6YqPAEMxVIIUQqAsLJ8Hv4EvEsq4hUTxNqMQviCysFyHshtJROjCouFuQiE0GnkZPZ7
         wtSg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=g69g7tVg;
       dkim=neutral (no key) header.i=@suse.cz header.b=0Kn9GhCx;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b="Rlw8/zRp";
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of jack@suse.cz designates 195.135.223.131 as permitted sender) smtp.mailfrom=jack@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [195.135.223.131])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-45e014a5655si233105e9.0.2025.09.11.01.32.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 11 Sep 2025 01:32:50 -0700 (PDT)
Received-SPF: pass (google.com: domain of jack@suse.cz designates 195.135.223.131 as permitted sender) client-ip=195.135.223.131;
Received: from imap1.dmz-prg2.suse.org (unknown [10.150.64.97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id E82216860D;
	Thu, 11 Sep 2025 08:32:49 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id C178813974;
	Thu, 11 Sep 2025 08:32:49 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id 0sg1LzGJwmhDcQAAD6G6ig
	(envelope-from <jack@suse.cz>); Thu, 11 Sep 2025 08:32:49 +0000
Received: by quack3.suse.cz (Postfix, from userid 1000)
	id 3E12AA0A2D; Thu, 11 Sep 2025 10:32:49 +0200 (CEST)
Date: Thu, 11 Sep 2025 10:32:49 +0200
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
Subject: Re: [PATCH v2 01/16] mm/shmem: update shmem to use mmap_prepare
Message-ID: <4lfedpbfjq6yexryq4jmdoycky762ewmw2thjm2h6wzgqda46a@p3wzpxlhe7ka>
References: <cover.1757534913.git.lorenzo.stoakes@oracle.com>
 <c328d14480808cb0e136db8090f2a203ade72233.1757534913.git.lorenzo.stoakes@oracle.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <c328d14480808cb0e136db8090f2a203ade72233.1757534913.git.lorenzo.stoakes@oracle.com>
X-Spam-Level: 
X-Spamd-Result: default: False [-2.30 / 50.00];
	BAYES_HAM(-3.00)[100.00%];
	SUSPICIOUS_RECIPS(1.50)[];
	NEURAL_HAM_LONG(-1.00)[-1.000];
	MID_RHS_NOT_FQDN(0.50)[];
	NEURAL_HAM_SHORT(-0.20)[-1.000];
	MIME_GOOD(-0.10)[text/plain];
	FUZZY_RATELIMITED(0.00)[rspamd.com];
	RCVD_VIA_SMTP_AUTH(0.00)[];
	ARC_NA(0.00)[];
	MISSING_XM_UA(0.00)[];
	MIME_TRACE(0.00)[0:+];
	TO_DN_SOME(0.00)[];
	FREEMAIL_ENVRCPT(0.00)[gmail.com];
	RCVD_COUNT_THREE(0.00)[3];
	DKIM_SIGNED(0.00)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	FROM_HAS_DN(0.00)[];
	FREEMAIL_CC(0.00)[linux-foundation.org,lwn.net,infradead.org,kernel.org,alpha.franken.de,linux.ibm.com,davemloft.net,gaisler.com,arndb.de,linuxfoundation.org,intel.com,fluxnic.net,linux.dev,suse.de,redhat.com,paragon-software.com,arm.com,zeniv.linux.org.uk,suse.cz,oracle.com,google.com,suse.com,linux.alibaba.com,gmail.com,vger.kernel.org,lists.linux.dev,kvack.org,lists.infradead.org,googlegroups.com,nvidia.com];
	R_RATELIMIT(0.00)[to_ip_from(RLizrtjkoytmmoj3iud1rzij51)];
	FROM_EQ_ENVFROM(0.00)[];
	RCVD_TLS_LAST(0.00)[];
	TO_MATCH_ENVRCPT_SOME(0.00)[];
	RCPT_COUNT_GT_50(0.00)[59];
	DBL_BLOCKED_OPENRESOLVER(0.00)[suse.com:email]
X-Spam-Flag: NO
X-Spam-Score: -2.30
X-Original-Sender: jack@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=g69g7tVg;       dkim=neutral
 (no key) header.i=@suse.cz header.b=0Kn9GhCx;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b="Rlw8/zRp";
       dkim=neutral (no key) header.i=@suse.cz;       spf=pass (google.com:
 domain of jack@suse.cz designates 195.135.223.131 as permitted sender) smtp.mailfrom=jack@suse.cz
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

On Wed 10-09-25 21:21:56, Lorenzo Stoakes wrote:
> This simply assigns the vm_ops so is easily updated - do so.
> 
> Reviewed-by: Baolin Wang <baolin.wang@linux.alibaba.com>
> Reviewed-by: David Hildenbrand <david@redhat.com>
> Signed-off-by: Lorenzo Stoakes <lorenzo.stoakes@oracle.com>

Looks good. Feel free to add:

Reviewed-by: Jan Kara <jack@suse.cz>

								Honza

> ---
>  mm/shmem.c | 9 +++++----
>  1 file changed, 5 insertions(+), 4 deletions(-)
> 
> diff --git a/mm/shmem.c b/mm/shmem.c
> index 45e7733d6612..990e33c6a776 100644
> --- a/mm/shmem.c
> +++ b/mm/shmem.c
> @@ -2938,16 +2938,17 @@ int shmem_lock(struct file *file, int lock, struct ucounts *ucounts)
>  	return retval;
>  }
>  
> -static int shmem_mmap(struct file *file, struct vm_area_struct *vma)
> +static int shmem_mmap_prepare(struct vm_area_desc *desc)
>  {
> +	struct file *file = desc->file;
>  	struct inode *inode = file_inode(file);
>  
>  	file_accessed(file);
>  	/* This is anonymous shared memory if it is unlinked at the time of mmap */
>  	if (inode->i_nlink)
> -		vma->vm_ops = &shmem_vm_ops;
> +		desc->vm_ops = &shmem_vm_ops;
>  	else
> -		vma->vm_ops = &shmem_anon_vm_ops;
> +		desc->vm_ops = &shmem_anon_vm_ops;
>  	return 0;
>  }
>  
> @@ -5217,7 +5218,7 @@ static const struct address_space_operations shmem_aops = {
>  };
>  
>  static const struct file_operations shmem_file_operations = {
> -	.mmap		= shmem_mmap,
> +	.mmap_prepare	= shmem_mmap_prepare,
>  	.open		= shmem_file_open,
>  	.get_unmapped_area = shmem_get_unmapped_area,
>  #ifdef CONFIG_TMPFS
> -- 
> 2.51.0
> 
-- 
Jan Kara <jack@suse.com>
SUSE Labs, CR

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/4lfedpbfjq6yexryq4jmdoycky762ewmw2thjm2h6wzgqda46a%40p3wzpxlhe7ka.
