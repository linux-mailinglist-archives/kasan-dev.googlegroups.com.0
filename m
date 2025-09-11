Return-Path: <kasan-dev+bncBC5I5WEMW4JBBFUVRLDAMGQENOR3TQQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x137.google.com (mail-lf1-x137.google.com [IPv6:2a00:1450:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id 1A20FB52BF1
	for <lists+kasan-dev@lfdr.de>; Thu, 11 Sep 2025 10:38:49 +0200 (CEST)
Received: by mail-lf1-x137.google.com with SMTP id 2adb3069b0e04-55f6a515516sf1171700e87.0
        for <lists+kasan-dev@lfdr.de>; Thu, 11 Sep 2025 01:38:49 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757579928; cv=pass;
        d=google.com; s=arc-20240605;
        b=RkVCDsPPteuU134KeVZc9vNrBFM7bN0aqrzFC6RWNzpv1x2IgrAyy9L++ryghyYne6
         I9YUNXRRHn+BxmEUv3QAGWN31o3WpsXoHltri9a6YrhChUoG0+MiEssKx0/23iPenYCN
         d8XcyahNNuEdOCG7CcPlV+sEIF/19LpGCj1O+3b6WBJXTYiK6uhoJ4vzoDBdVjUExT8e
         lzjDe0wHnVrJzG9gL8UJov+apNmauoA10AKwj7eQu/wBzCl5bFLm80vfkoxjKle6lpK8
         6cB3Vno6yY7izzbF1E/Ab5/ADhV2++RpbZxlqSWlntbXIHIAzsaHUS4nGPE7OU6hdmG6
         mjDQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=Hnb/LBSI6+XCe6X1mgd/lwGWrfWykZwd7Hl0r3sCilQ=;
        fh=GCg765eFHzcOjKKrSjduNLANApxWG4txLYW+pVqiy2U=;
        b=B9VIUh3DzkmpwKxGl8HiapsDIeOjk3KctlEGA4IKDn3oHbJ3aRhGWIUDyyeiUr6Ly4
         upV+iGsCqdpHcDLZkso2nCpsMIc4v5KyyuiaNgzvrIfD5WsNg9Sf9+Fg3KY0izok1I3r
         ldeSrU8i6vJsBfA0mEVjrsdIkIn7FRt1aeISD4paOE4wraQCdmj9KIy4tJqiJ32dguhC
         Bxbz7C97bFgkHvsJimTPC2o/TYa6dqXxX5ttkOK3TUNnqf8vfnj3wBgGO4CCYxoBXKSv
         mz8gp13kYh0OhSvewAfwfKzalqAudWKN01RntSukBZwZdcC9ww67D00KcwFwgDGGT+rL
         5Onw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=xB4gv7V3;
       dkim=neutral (no key) header.i=@suse.cz;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=xB4gv7V3;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of jack@suse.cz designates 195.135.223.130 as permitted sender) smtp.mailfrom=jack@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757579928; x=1758184728; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=Hnb/LBSI6+XCe6X1mgd/lwGWrfWykZwd7Hl0r3sCilQ=;
        b=nKKef7jkT/O9PpzlB5zawJ7HTY3hEyOc7nYL+19StlJMUHKm44gO+XsNe5lnuU8XXv
         DbVMO9pMqmqBHVsuc99oUDFDmrNX16TAJELMXt5dwS50iKo0tfGbuqfLv5gBAkVKG/Bh
         zBcIMI4XGMCuWUBACQYx9NepBEL1Vt+rVDBSHetEMnKnWAg/lM9RpC2VmsKUA/yfp2Fx
         3Ia9DEqeJh16siGy57dr14OMh4M6XPjFzkXzw/8TgzIc9xhFVbClFNo05bcA5qk72jpz
         aNWLylwyFT8TiYJnVcL5IR0y2wSW3cx5ZrEyOGh1Lo4YhB+qyo8B/qfyazXCxMg3KK4K
         0/Qg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757579928; x=1758184728;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=Hnb/LBSI6+XCe6X1mgd/lwGWrfWykZwd7Hl0r3sCilQ=;
        b=Py0S6VsfBeXf2qVmO0FgoF4Wo0rcGMCdd0eivFTlbkqeGWJkPfVV0jC0A91+zj98XS
         U9q2pQd6/mn+8MKwAluBrYp95zkFf41BlaukWB7Vj5r423jfTlifkt+/9v0GglM6OwZH
         DgTt+eKNzcPgKFg1WcBaVzcKXCmT8HyzJyZG6h5Qw1sDy11Gbev3gjelmdTA9IP0bcIM
         SYrqT+PCvygtRhjYAxwd0PqyPECX56HL31Jbb8+dc5Yiw2zeTp5q/wdwcvIMeVwYKxFG
         PutXqwvpJNxD3sfJmBLWRo7X7ylwGm6ym3zYtj6XbXSN5gaKLlAo8NSQaIAzHiMmYbiT
         ZZsg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWOdrMOU2BlbugbePHOg66ZLggHBeGvBzUNeM1KpaPRjXVmwQ5CCZ2NNhvvfjbpzLowZyfTWA==@lfdr.de
X-Gm-Message-State: AOJu0Yxs56q4ugijZtyLJfM5w+DKE5fns6ZVVZqUi5P5YbJdPw+6v05w
	2PlSPjRorCmV3+vwEjP9WM6cyAP4YY8cQgpBBK6auiPPBxFVQAthhqju
X-Google-Smtp-Source: AGHT+IFrdfoKQmjimyrZoe2A6nc+MkbAyURMNvu38Dmo83WQqI+64PWRAASz35twmuJiAf6WKrKEjw==
X-Received: by 2002:a05:6512:ea7:b0:55f:4072:d32e with SMTP id 2adb3069b0e04-56d757d0d5dmr776952e87.4.1757579927445;
        Thu, 11 Sep 2025 01:38:47 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZeTpRXqbbzKGsgZs/x3fLqwJ3mIWcWGlMoN8PvNLosTXw==
Received: by 2002:a05:6512:1356:b0:55f:799:5ce5 with SMTP id
 2adb3069b0e04-56b0af9ad25ls358091e87.1.-pod-prod-00-eu-canary; Thu, 11 Sep
 2025 01:38:44 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXl2hcY4uynxpP5tbZJVYih4+IfPWl6b5IF6flsswkWtIMOF9fds/Chi6XkNsTH+b63Ac4zxzqRajc=@googlegroups.com
X-Received: by 2002:ac2:51d0:0:b0:55f:6736:334a with SMTP id 2adb3069b0e04-56d7b42f8f4mr792285e87.26.1757579923859;
        Thu, 11 Sep 2025 01:38:43 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1757579923; cv=none;
        d=google.com; s=arc-20240605;
        b=BR+TvoNMrSxWZmgpH0In85070gRwQFpeDUiOmuvi1I+VW3M3PclyUbX6T4S9HheZrN
         SSeV2u7oAwkrp1ccbOaezGZHH+jS8JNHZHaqPsmHdVRyVGTm0VWvfHI/OKOlwrYLSbyJ
         7w7YrzYcGPOkzMsYilh6AsMF8GfLjlLxptnzveBGrr8zAlRuOlm4uswYxa18cj8aAx9j
         Kwju/dJYrxhsEd/rc44hK+/RWJ4tZ7wsq/xTUROMXH5INs+2qFG8lTH+IxfyzIV20RZq
         hYNOUhFCBOYgRatJcQCFMcJ8McK1aTskTuZEzIgYwiLROZQ7JVQyFPo22o1cApYdXiee
         j4tw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature:dkim-signature
         :dkim-signature:dkim-signature;
        bh=C9OZHv6l97MqIsXfPxgJwmp3fJXxpsxaT+6E3H63F4A=;
        fh=/v17VW8MchCHUgpXxAXTMs5Ee7lYsmC259Kuc6hqZT8=;
        b=VsZVW1vaGpp1I2Ty+ARVkuhOiDhXRu7CZVzb6l2PGGcS2YchcPGbRKAuVCQv5k4jhU
         cMqH4UQ1QNM3vn8e4JZlgTWxCPhjC/LGGuG0pwIKMGOfzZDocvAW1kYejdjTwpqF1mXQ
         TX6nR80SaWoveQO70h3FKixA9TVnPiO/PT+LCv7efqhjHv5XPUfDIvwsnF06EjYcj4kT
         iWFDKlBlB+uY31WqQTqsYLCN7CYQTWmRlobDRwz+hCYVAVQeDhNq/p2f+kk4DFFhteK4
         RrT9T39Lb+Qr/GqC5//iFPYTd9sObaURQD6gVeWJFi2b39zUDMSs4MShzvXKkWJJ1TBs
         9+cg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=xB4gv7V3;
       dkim=neutral (no key) header.i=@suse.cz;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=xB4gv7V3;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of jack@suse.cz designates 195.135.223.130 as permitted sender) smtp.mailfrom=jack@suse.cz
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [195.135.223.130])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-56e593da29dsi19328e87.1.2025.09.11.01.38.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 11 Sep 2025 01:38:43 -0700 (PDT)
Received-SPF: pass (google.com: domain of jack@suse.cz designates 195.135.223.130 as permitted sender) client-ip=195.135.223.130;
Received: from imap1.dmz-prg2.suse.org (unknown [10.150.64.97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id 9E8A93F958;
	Thu, 11 Sep 2025 08:38:42 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id 8EE661372E;
	Thu, 11 Sep 2025 08:38:42 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id RzXXIpKKwmiAcwAAD6G6ig
	(envelope-from <jack@suse.cz>); Thu, 11 Sep 2025 08:38:42 +0000
Received: by quack3.suse.cz (Postfix, from userid 1000)
	id 4D7CAA0A2D; Thu, 11 Sep 2025 10:38:42 +0200 (CEST)
Date: Thu, 11 Sep 2025 10:38:42 +0200
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
Subject: Re: [PATCH v2 04/16] relay: update relay to use mmap_prepare
Message-ID: <q5kr5klayp7wcdv5535etvhfcmsftf2h5pi2nhxjpxsyu4h6qt@e6fidg7kolk2>
References: <cover.1757534913.git.lorenzo.stoakes@oracle.com>
 <3e34bb15a386d64e308c897ea1125e5e24fc6fa4.1757534913.git.lorenzo.stoakes@oracle.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <3e34bb15a386d64e308c897ea1125e5e24fc6fa4.1757534913.git.lorenzo.stoakes@oracle.com>
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
	DBL_BLOCKED_OPENRESOLVER(0.00)[imap1.dmz-prg2.suse.org:helo,oracle.com:email,suse.com:email]
X-Spam-Flag: NO
X-Spam-Score: -2.30
X-Original-Sender: jack@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=xB4gv7V3;       dkim=neutral
 (no key) header.i=@suse.cz;       dkim=pass header.i=@suse.cz
 header.s=susede2_rsa header.b=xB4gv7V3;       dkim=neutral (no key)
 header.i=@suse.cz header.s=susede2_ed25519;       spf=pass (google.com:
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

On Wed 10-09-25 21:21:59, Lorenzo Stoakes wrote:
> It is relatively trivial to update this code to use the f_op->mmap_prepare
> hook in favour of the deprecated f_op->mmap hook, so do so.
> 
> Reviewed-by: David Hildenbrand <david@redhat.com>
> Signed-off-by: Lorenzo Stoakes <lorenzo.stoakes@oracle.com>

Looks good. Feel free to add:

Reviewed-by: Jan Kara <jack@suse.cz>

								Honza

> ---
>  kernel/relay.c | 33 +++++++++++++++++----------------
>  1 file changed, 17 insertions(+), 16 deletions(-)
> 
> diff --git a/kernel/relay.c b/kernel/relay.c
> index 8d915fe98198..e36f6b926f7f 100644
> --- a/kernel/relay.c
> +++ b/kernel/relay.c
> @@ -72,17 +72,18 @@ static void relay_free_page_array(struct page **array)
>  }
>  
>  /**
> - *	relay_mmap_buf: - mmap channel buffer to process address space
> - *	@buf: relay channel buffer
> - *	@vma: vm_area_struct describing memory to be mapped
> + *	relay_mmap_prepare_buf: - mmap channel buffer to process address space
> + *	@buf: the relay channel buffer
> + *	@desc: describing what to map
>   *
>   *	Returns 0 if ok, negative on error
>   *
>   *	Caller should already have grabbed mmap_lock.
>   */
> -static int relay_mmap_buf(struct rchan_buf *buf, struct vm_area_struct *vma)
> +static int relay_mmap_prepare_buf(struct rchan_buf *buf,
> +				  struct vm_area_desc *desc)
>  {
> -	unsigned long length = vma->vm_end - vma->vm_start;
> +	unsigned long length = vma_desc_size(desc);
>  
>  	if (!buf)
>  		return -EBADF;
> @@ -90,9 +91,9 @@ static int relay_mmap_buf(struct rchan_buf *buf, struct vm_area_struct *vma)
>  	if (length != (unsigned long)buf->chan->alloc_size)
>  		return -EINVAL;
>  
> -	vma->vm_ops = &relay_file_mmap_ops;
> -	vm_flags_set(vma, VM_DONTEXPAND);
> -	vma->vm_private_data = buf;
> +	desc->vm_ops = &relay_file_mmap_ops;
> +	desc->vm_flags |= VM_DONTEXPAND;
> +	desc->private_data = buf;
>  
>  	return 0;
>  }
> @@ -749,16 +750,16 @@ static int relay_file_open(struct inode *inode, struct file *filp)
>  }
>  
>  /**
> - *	relay_file_mmap - mmap file op for relay files
> - *	@filp: the file
> - *	@vma: the vma describing what to map
> + *	relay_file_mmap_prepare - mmap file op for relay files
> + *	@desc: describing what to map
>   *
> - *	Calls upon relay_mmap_buf() to map the file into user space.
> + *	Calls upon relay_mmap_prepare_buf() to map the file into user space.
>   */
> -static int relay_file_mmap(struct file *filp, struct vm_area_struct *vma)
> +static int relay_file_mmap_prepare(struct vm_area_desc *desc)
>  {
> -	struct rchan_buf *buf = filp->private_data;
> -	return relay_mmap_buf(buf, vma);
> +	struct rchan_buf *buf = desc->file->private_data;
> +
> +	return relay_mmap_prepare_buf(buf, desc);
>  }
>  
>  /**
> @@ -1006,7 +1007,7 @@ static ssize_t relay_file_read(struct file *filp,
>  const struct file_operations relay_file_operations = {
>  	.open		= relay_file_open,
>  	.poll		= relay_file_poll,
> -	.mmap		= relay_file_mmap,
> +	.mmap_prepare	= relay_file_mmap_prepare,
>  	.read		= relay_file_read,
>  	.release	= relay_file_release,
>  };
> -- 
> 2.51.0
> 
-- 
Jan Kara <jack@suse.com>
SUSE Labs, CR

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/q5kr5klayp7wcdv5535etvhfcmsftf2h5pi2nhxjpxsyu4h6qt%40e6fidg7kolk2.
