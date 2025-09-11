Return-Path: <kasan-dev+bncBC5I5WEMW4JBBF45RLDAMGQE6QOQ5OY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x237.google.com (mail-lj1-x237.google.com [IPv6:2a00:1450:4864:20::237])
	by mail.lfdr.de (Postfix) with ESMTPS id B74EBB52C4C
	for <lists+kasan-dev@lfdr.de>; Thu, 11 Sep 2025 10:55:53 +0200 (CEST)
Received: by mail-lj1-x237.google.com with SMTP id 38308e7fff4ca-336e13bf342sf2549571fa.3
        for <lists+kasan-dev@lfdr.de>; Thu, 11 Sep 2025 01:55:53 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757580952; cv=pass;
        d=google.com; s=arc-20240605;
        b=RCDOloVMD8HjpSeVt98QfAAYMI/w/G7csKuumzUuAGf3tE3SGzUuQXTA8o9D/aE1jg
         9cGVfIj2ht7XOrhwNLtMDwia5O0aiugfOTMt3NpT07Ll2HgEn9Aqw/i8xOy+O15ed0UN
         aem/tSNg4qMFfThujIcWNyhFi+6Wcke8kV0XFhUV5BSGqxp+2nBD+jhwv63YtIjhGHNM
         YizTB5ITUO2Iw2Enrj5aF7gs5HOnYZwuqHoL5LD1w5k6+Ac8WWznEpoeWojr7ZyHLhVk
         YJUTy5qctEruPnWFt/pmCjYKE3g1MBtGLgkwmf09tc1vDsxx0HkI+vR5/rwZFqrbNe4h
         j0qg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=VVhdtag/NPLP3TbEaanSVxTKlM77jl+cNUT/8Sjhb30=;
        fh=aKMJ3WYkTwhHzfns1gCWSn3Y0K7HeVjDCDAx4s7aZ1M=;
        b=VLsPIEw4YNVEoFYb8KxA8a3UqeHMY2+Jpp27pBGgGdOlM4To1E74pe1TtRJQKolapA
         /bmlqouoIZOmUFzmlMgTQeUCQwj+9lDZ8OzTUeUgLgLPhsaC4F49qTv2/qYr15zXueqz
         Y85Nd9OcHyjexPZUKfdzvm8NtWDYUXecmw976wf4Z2MasZxBS0q45MzvsqrnJFquX5th
         ogl2HgnLvlja4KKKTDErj8RAtCpMVZ0Q6y42oRZ4N1YoAvB/x4uSp0ulujPTpvOgBn0Q
         zrKG2v5Y15zsY0wd6Ul/jUtygOXX16OMvc7WPrYVHczzDbPW1xQUmNvU5fgkHkANaNrN
         v4Uw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=H06dORKL;
       dkim=neutral (no key) header.i=@suse.cz header.b=0iIQ+Ipq;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=H06dORKL;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of jack@suse.cz designates 195.135.223.131 as permitted sender) smtp.mailfrom=jack@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757580952; x=1758185752; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=VVhdtag/NPLP3TbEaanSVxTKlM77jl+cNUT/8Sjhb30=;
        b=U1P//alYCBHMQhW/fJEDWNPp8rpMMNLGoaLqs1L/SEUk8H43LeXLWkDRnfVyMwrkBX
         9kFU/vByNNSvCl8U+ustK3C4d8692U3h+ZDOsW+8elBuHI9sy2/QjBMmAXBTlExaz03m
         vmljktbnLhHIAT52Md8ROHr8psVuE9Jwsb6Jys6WjZH1HcVE9Xq3Js2GU9Q9BODw6VBb
         Vv6G4ZS3aTml0QD+jlqSSe/dfCrWe/dsD4P0RD1xkLBp4CvYABX/+hHQaDpCB2xX+zzR
         S1+JdqkbJpk5chQd5153lq7xGACfSJKG7773J7zKUERkIFz2ocLJtNuAKbm6GrfrImJS
         EfXQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757580952; x=1758185752;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=VVhdtag/NPLP3TbEaanSVxTKlM77jl+cNUT/8Sjhb30=;
        b=Nars4nXbLc8JjVwmd+EDQ4JPS4gK4XsqipScwMSfG3D7Hk4SxrgscVEILnbJxFfBDj
         bnYpVyvtFV+5ejs09EYzjf220vCewelqwK4b/1rEB8lBXikSa1X4EqTYoe2YXIOAktIb
         UyWONX4SoQwUuNh3cQwRax/uxTqhNl/SI9bJbYIrTP3i2xHeyFzuN0yBJRKKlhKaZbWR
         hVpgbNPKC+xDd62pYljjk5mIkhrqjxOh3ge8uNzH7nYmq3+CStmG2m0sicmfUCTBWHw3
         raHqv/4paccPyBARS2GMKR5Rww9blP/o28ui0OnGSXZfLPRbmI2ahGSTQw3rUqf5s7jG
         5I2A==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCX9ePxZolusuhWdrZAlDBG1FDngtqnpLy2MCGPHmSYoHNVfNuCFT2oukzzOuZpbOHOsaZF2iA==@lfdr.de
X-Gm-Message-State: AOJu0YyqhffGy1fSRsJQX3JcJfsClWNm8ihVX7PmIdONQe/nTaoJIhbW
	HbhPqzUXEcfbkINLUpytYkHtlmMayOwCvlu3OVrrCpN5YGcVOq5E6UWM
X-Google-Smtp-Source: AGHT+IGY1+QrpoGNPC2nMFpP5nBfGmIYZvZq/lIj5klHTBZ/Ym13xACmVdCU0VAMPKYnyYGq9OLUBQ==
X-Received: by 2002:a05:651c:211d:b0:336:831d:9e00 with SMTP id 38308e7fff4ca-33b5cbcebd8mr55515251fa.25.1757580952220;
        Thu, 11 Sep 2025 01:55:52 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZd2ANuHfXKUfNUpM9v2EKEiuI2tBBlP66PHIiuik3chpA==
Received: by 2002:a05:651c:25d5:10b0:336:c2ac:cd28 with SMTP id
 38308e7fff4ca-34ea8514d93ls397511fa.0.-pod-prod-05-eu; Thu, 11 Sep 2025
 01:55:49 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUaIYPb//Fu97uqXz8HUVSkPgTNY29WFZTDWRwG3SfEtRbk6h4FdYVZpA05ti0DoOPS9rqqKN52tpM=@googlegroups.com
X-Received: by 2002:a05:651c:2221:b0:337:f6f5:a164 with SMTP id 38308e7fff4ca-33b5cbceb98mr59342161fa.28.1757580948888;
        Thu, 11 Sep 2025 01:55:48 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1757580948; cv=none;
        d=google.com; s=arc-20240605;
        b=ksx2R2j2gRd4jqaBkhCb5GhtJ7r4ndswtRG7pMll5laZJd6n0V3UuAsu4SLOu+/lI+
         QVsDLew5/TSN8ZIt0b9ULmqfSWF6ia6JSsT0feI2epqvErKZzF8A+8Nx2ay8knNEdl0d
         +KDndOB2bngbmTV9fBeFSTRmnnlzcx6CbyK/3xHnTBxRrpLyGCdPuOhyrjsDoS+ywwX4
         f7xlJvYKua1kYEa8KSKBhei+cB/WgHfLD2wwEluo1xPz5js7YO1CIIROCzvavzOafqJ4
         wllgFAzW6Uf/+YJDhvK/vBMmO9J9yG/1vnxqofPmrBI9vriL7k+FfaAiJWrs8tte1JPJ
         j24g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature:dkim-signature
         :dkim-signature:dkim-signature;
        bh=g+JbXqJwzf7cOodAKH9xqcseUyaAMBde80ixVE0ZgKU=;
        fh=/v17VW8MchCHUgpXxAXTMs5Ee7lYsmC259Kuc6hqZT8=;
        b=Fp6DDusvquNCIU3F2LFtqhKHG0ZpD8tDKszXoOE0PR3raO+qGrfaOBSmrNFm6+YCz5
         T24M5oPczAxd03mZkKh0gleR8Hi52UI094P2xP/LlEhmMVC+6JkIE81HQeXyTJvM1GGS
         NjenTl+BaYTJP82QDpLUQkkCVakjcDlBsO8s4HpgfZbDr22UXZWqqVh9klksQK4y3VYL
         wBJ6xKdY4KOpUqzQAx8zS1g9zL5PekeuoQczSVIz0VWZsFyk2Ni0c04opSKPUlaBigDi
         pztUa3uqvJg6VYCWjGNLPoOXXkUN36HtKX+WllpHzP0i2mpBzbTxpZHRyiV96z2Mgp3u
         G1Uw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=H06dORKL;
       dkim=neutral (no key) header.i=@suse.cz header.b=0iIQ+Ipq;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=H06dORKL;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of jack@suse.cz designates 195.135.223.131 as permitted sender) smtp.mailfrom=jack@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [195.135.223.131])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-34f1b1b37c1si143551fa.7.2025.09.11.01.55.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 11 Sep 2025 01:55:48 -0700 (PDT)
Received-SPF: pass (google.com: domain of jack@suse.cz designates 195.135.223.131 as permitted sender) client-ip=195.135.223.131;
Received: from imap1.dmz-prg2.suse.org (unknown [10.150.64.97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id B730E68010;
	Thu, 11 Sep 2025 08:55:46 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id A7DA113301;
	Thu, 11 Sep 2025 08:55:46 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id Pmj1KJKOwmjpeAAAD6G6ig
	(envelope-from <jack@suse.cz>); Thu, 11 Sep 2025 08:55:46 +0000
Received: by quack3.suse.cz (Postfix, from userid 1000)
	id 5F916A0A2D; Thu, 11 Sep 2025 10:55:42 +0200 (CEST)
Date: Thu, 11 Sep 2025 10:55:42 +0200
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
Subject: Re: [PATCH v2 09/16] doc: update porting, vfs documentation for
 mmap_prepare actions
Message-ID: <xbz56k25ftkjbjpjpslqad5b77klaxg3ganckhbnwe3mf6vtpy@3ytagvaq4gk5>
References: <cover.1757534913.git.lorenzo.stoakes@oracle.com>
 <e50e91a6f6173f81addb838c5049bed2833f7b0d.1757534913.git.lorenzo.stoakes@oracle.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <e50e91a6f6173f81addb838c5049bed2833f7b0d.1757534913.git.lorenzo.stoakes@oracle.com>
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
	DBL_BLOCKED_OPENRESOLVER(0.00)[imap1.dmz-prg2.suse.org:helo,oracle.com:email,suse.cz:email,suse.com:email]
X-Spam-Flag: NO
X-Spam-Score: -2.30
X-Original-Sender: jack@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=H06dORKL;       dkim=neutral
 (no key) header.i=@suse.cz header.b=0iIQ+Ipq;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=H06dORKL;       dkim=neutral
 (no key) header.i=@suse.cz;       spf=pass (google.com: domain of
 jack@suse.cz designates 195.135.223.131 as permitted sender) smtp.mailfrom=jack@suse.cz
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

On Wed 10-09-25 21:22:04, Lorenzo Stoakes wrote:
> Now we have introduced the ability to specify that actions should be taken
> after a VMA is established via the vm_area_desc->action field as specified
> in mmap_prepare, update both the VFS documentation and the porting guide to
> describe this.
> 
> Signed-off-by: Lorenzo Stoakes <lorenzo.stoakes@oracle.com>

Looks good. Feel free to add:

Reviewed-by: Jan Kara <jack@suse.cz>

								Honza

> ---
>  Documentation/filesystems/porting.rst | 5 +++++
>  Documentation/filesystems/vfs.rst     | 4 ++++
>  2 files changed, 9 insertions(+)
> 
> diff --git a/Documentation/filesystems/porting.rst b/Documentation/filesystems/porting.rst
> index 85f590254f07..6743ed0b9112 100644
> --- a/Documentation/filesystems/porting.rst
> +++ b/Documentation/filesystems/porting.rst
> @@ -1285,3 +1285,8 @@ rather than a VMA, as the VMA at this stage is not yet valid.
>  The vm_area_desc provides the minimum required information for a filesystem
>  to initialise state upon memory mapping of a file-backed region, and output
>  parameters for the file system to set this state.
> +
> +In nearly all cases, this is all that is required for a filesystem. However, if
> +a filesystem needs to perform an operation such a pre-population of page tables,
> +then that action can be specified in the vm_area_desc->action field, which can
> +be configured using the mmap_action_*() helpers.
> diff --git a/Documentation/filesystems/vfs.rst b/Documentation/filesystems/vfs.rst
> index 486a91633474..9e96c46ee10e 100644
> --- a/Documentation/filesystems/vfs.rst
> +++ b/Documentation/filesystems/vfs.rst
> @@ -1236,6 +1236,10 @@ otherwise noted.
>  	file-backed memory mapping, most notably establishing relevant
>  	private state and VMA callbacks.
>  
> +	If further action such as pre-population of page tables is required,
> +	this can be specified by the vm_area_desc->action field and related
> +	parameters.
> +
>  Note that the file operations are implemented by the specific
>  filesystem in which the inode resides.  When opening a device node
>  (character or block special) most filesystems will call special
> -- 
> 2.51.0
> 
-- 
Jan Kara <jack@suse.com>
SUSE Labs, CR

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/xbz56k25ftkjbjpjpslqad5b77klaxg3ganckhbnwe3mf6vtpy%403ytagvaq4gk5.
