Return-Path: <kasan-dev+bncBD74H4NGEIIPBIFKYYDBUBEOFFK2I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13c.google.com (mail-lf1-x13c.google.com [IPv6:2a00:1450:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id 32EBBB7D9B0
	for <lists+kasan-dev@lfdr.de>; Wed, 17 Sep 2025 14:30:52 +0200 (CEST)
Received: by mail-lf1-x13c.google.com with SMTP id 2adb3069b0e04-56087e8494dsf5364934e87.3
        for <lists+kasan-dev@lfdr.de>; Wed, 17 Sep 2025 05:30:52 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758112251; cv=pass;
        d=google.com; s=arc-20240605;
        b=C1JQNOgFHxlSzUI0QDVtY3HsWQFkMtS1K7E+tW1XpKDir8RGZsTxWWyjmG8yRyuiGe
         wlzTlcXIzKXN4G0XC+WC01CvQwDwrLywjrl2vKtRk+zeSvGmNzIxRh/8s8BOcvgpJddM
         1VE1Ud93ftBHs+O4UXRvrHtRjIH1KFPePFuDuUZ3gqzPYsz9heplN6jwjXev+xxBeLYl
         ZhRstYD/3rT6/FMk8yqSNOILwYnXgJBaxjCRZp9cVcJpM7sdtyiDdIP0Nc8i3GK/eLi7
         hIzQtcs76Wp0Nky2R/oeUI1CThSBZ0PfmojnLr9zhxdh7SGcdIeXPTpkXcw1TSm7/0Vt
         A9Ig==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=McBzimNNMwAZdkJheNjEH02gtsKAPl1N4v/V1LoNt/s=;
        fh=nCNmDhJ3AIQIrSE4FvXhfBTWh3IBp25WsGt4ojCYcrM=;
        b=VmgaYudN7XB/cmza5jFZsTiA8yUw0b/+htgMJV/bEFIDB/l4JlbKCwfU84wcuyCLqr
         te+cJMLshwl+EQuDaGDKwYa8VwKfnJ4+8vvOGjaq7bUA6yMAWQqBwoa7C+WL4pM48KQC
         8ZMYQrYnipuhZlPGai/ThpPIelPFepRlUXWLgTcTYuPhSBNxeHl8c8fHeEKgUXFdHOBe
         EfnnbHYfdhH/ci55wxf5kC8ck6NKj9TFTn19t6GxIXOYBeNMYnhGQLoY1slM4BiX+cYn
         Zqyj3ddnjhM5pDXA8Dkzcb7elMnCnIK7fHYRoPGTBqMAjl9budaXP7j99OIrOO2Uw5Be
         LEbw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.de header.s=susede2_rsa header.b=DukI9feJ;
       dkim=neutral (no key) header.i=@suse.de;
       dkim=pass header.i=@suse.de header.s=susede2_rsa header.b=DukI9feJ;
       dkim=neutral (no key) header.i=@suse.de header.s=susede2_ed25519;
       spf=pass (google.com: domain of pfalcato@suse.de designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) smtp.mailfrom=pfalcato@suse.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=suse.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758112251; x=1758717051; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=McBzimNNMwAZdkJheNjEH02gtsKAPl1N4v/V1LoNt/s=;
        b=SwlvdxFJVc4WxPVpJTso13h59WkM4ny1CKyNja6E8wiE5FAAjZ5GEr+rAw0e5FVM31
         zigtFdLZpXpbc1sIqDU6oY/7ibqolZxa2aGyWbBcyExUkFduQ+g4bZSoV31WeZ6bjLUS
         egu4RXfxS/5xTBHVsFQV+o4i+r6UNFPmjBTYkW2nzW6rHHRzdJ1BlItzAGxW+mKYaUtf
         N+B2kzzOgEATC632bwmt4OOjds/PbxqkFVt7/Eykios1ZShkwwYfMbRU+7FScbeOoLiH
         iRBNlDgVM2/D+/MurQM/yO+r1QWcPJ1kSMEoY2sjZNmlObj/N+8i7yNEr/1lvTYtBreK
         kryA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758112251; x=1758717051;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=McBzimNNMwAZdkJheNjEH02gtsKAPl1N4v/V1LoNt/s=;
        b=T55RFxtPt4pufdBZpfVS1mN1CFUrPBmxbc46DejysoRRYhFJOx2LYr3LL3H8msH2lr
         OxkBh98AmZf/BxNF1CXu3SIa5THZuvS3S14ne8X6ya4eBy05l37oyIS5jK2BIUDIMfO1
         3kCxw/+O6zasR30IzYP/rtw9fH1KVAaHiH1wKeuyc4nfSN5Bld/0ULDxhaMGJvzVwptp
         iXYsGlhwl6drsaZzHcYE89gRdo+kUU9nv7dRUSwPceA+Ou4ttYSxxnZeuAVoQnq+OvxF
         UH8mwY2Kc4D/r7djntt4yFFNv+7YSpkQbhwbQ2eijWjHAiI++/z9D084kjJjIvgFS3zW
         vhBQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWhm9XeLoo4rQwy785l/yWXwTCOXxNGHdeWvgQs8GZTy2lGjDQ7FBtR3K79mMvqLWPNa/tkpw==@lfdr.de
X-Gm-Message-State: AOJu0Yyxb0+fMmsRY5sfgabfJUZZsoFKgS5+TnDLZbMklTU4Blr7YxIr
	xD8ysEhZafXC7JfiB9OjrAzS1+LYFISOePlWay64dxCKwl3SaJU4M24T
X-Google-Smtp-Source: AGHT+IFjtiAruqT/TrA2ZmNyBObj4uq9H+gkgXpZ9odPs3/DQu+f9Fac84/j3qzgJ3bvoUaiNtqr0g==
X-Received: by 2002:a05:600c:354b:b0:45f:27fb:8014 with SMTP id 5b1f17b1804b1-46202bf79b6mr16159115e9.3.1758105713024;
        Wed, 17 Sep 2025 03:41:53 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd78DHPHGioLU9wAvbotYnMAYf8WlL+QdMraGhzJ0Z5Rcg==
Received: by 2002:a05:600c:64c6:b0:456:241d:50bd with SMTP id
 5b1f17b1804b1-4603b053f7els11149535e9.2.-pod-prod-04-eu; Wed, 17 Sep 2025
 03:41:50 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUq+EfwKbHERfMEwF3BheI4jXkAPY2IjS/fN5Ni2B1haZ7t909XFd1f5GlB02talAYad+UxDMQJnio=@googlegroups.com
X-Received: by 2002:a05:6000:26c2:b0:3eb:4681:ac9e with SMTP id ffacd0b85a97d-3ecdf9f42c7mr1709448f8f.5.1758105710125;
        Wed, 17 Sep 2025 03:41:50 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1758105710; cv=none;
        d=google.com; s=arc-20240605;
        b=a5CMPczKqqvc6uqvMjRZewIX8IsI7PUIBsTiUrltCBCBqa/xW8pt5R+kRgppSdCEBU
         k5ikC9abN5WQ3K20OcTBwdAxPRkAhDzRmsWi7whM5CGtOTGXEfNgU6xg46W683HtarzD
         EUGIRMl92QFdeT7Xt2VH+YLUfFC/fAIGBkaTsEkGfHTE4sJ4pAzIwqAVy17KkR2XCcpK
         GFFPOQ1Uwt8itEP+L0DC025jKriGO10HwXicrRHXrLSl7Qlyejwn2+s1S5ARbk+1Al+O
         PfDrjSXWqMwrL+31QS4SA3eeOG4VkZQrtkbIb7g5ew+mXtx+fpFwRQFZU+RlQTVB+2AO
         ZlCg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature:dkim-signature
         :dkim-signature:dkim-signature;
        bh=Ofj744S0hdgV+oqudN+JHGPXOpDjYVMC07hCO7WqjNw=;
        fh=3+MH0ChJLBM72NzpB/XiB+Q7hxpuJ08qXy92Zn7JvPc=;
        b=On9q9Eft5ww7Aw5ubn8oIGBR3tCwiEzs+QjlE7DB1OdheTQ35x5Vi8czpffhem+CkS
         1/xNnbkrjj9vMBl43b+JIKtTrl3V1f8Qs1QGiMzJ6rDkRzeIyCwX89O1pLOS1vM97wmM
         YcG0nYigvBKt40Mh9yNiltzJTNEMF4GriygooyRrMmaDRxJNUhUXj8Hphs+sYyIGxHlQ
         0BUteh7xm+UCeDvEvzgMXP7ojk3oqyPciIj17V2LEMHKihWcny4beCjE1u8gypyg95b7
         E4JtI7dqHpdj63mYN85seZ7MaVkcIBnkA32rvAPmsqZEdRc8mn9KCcadLU88CdezhdkK
         RJLg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.de header.s=susede2_rsa header.b=DukI9feJ;
       dkim=neutral (no key) header.i=@suse.de;
       dkim=pass header.i=@suse.de header.s=susede2_rsa header.b=DukI9feJ;
       dkim=neutral (no key) header.i=@suse.de header.s=susede2_ed25519;
       spf=pass (google.com: domain of pfalcato@suse.de designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) smtp.mailfrom=pfalcato@suse.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=suse.de
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [2a07:de40:b251:101:10:150:64:1])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-45f32522420si1338625e9.1.2025.09.17.03.41.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 17 Sep 2025 03:41:50 -0700 (PDT)
Received-SPF: pass (google.com: domain of pfalcato@suse.de designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) client-ip=2a07:de40:b251:101:10:150:64:1;
Received: from imap1.dmz-prg2.suse.org (imap1.dmz-prg2.suse.org [IPv6:2a07:de40:b281:104:10:150:64:97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id ABBA222096;
	Wed, 17 Sep 2025 10:41:49 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id 33E9F1368D;
	Wed, 17 Sep 2025 10:41:46 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id gAoOCWqQymiEOgAAD6G6ig
	(envelope-from <pfalcato@suse.de>); Wed, 17 Sep 2025 10:41:46 +0000
Date: Wed, 17 Sep 2025 11:41:44 +0100
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
Subject: Re: [PATCH v3 04/13] relay: update relay to use mmap_prepare
Message-ID: <jrxexcuzlxpnfs2jhm7ecdh4kak5i4a6e5od4cm72fn3twwzms@vptu5rfimbez>
References: <cover.1758031792.git.lorenzo.stoakes@oracle.com>
 <ae3769daca38035aaa71ab3468f654c2032b9ccb.1758031792.git.lorenzo.stoakes@oracle.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <ae3769daca38035aaa71ab3468f654c2032b9ccb.1758031792.git.lorenzo.stoakes@oracle.com>
X-Spamd-Result: default: False [-2.51 / 50.00];
	BAYES_HAM(-3.00)[100.00%];
	SUSPICIOUS_RECIPS(1.50)[];
	NEURAL_HAM_LONG(-1.00)[-1.000];
	MID_RHS_NOT_FQDN(0.50)[];
	R_DKIM_ALLOW(-0.20)[suse.de:s=susede2_rsa,suse.de:s=susede2_ed25519];
	NEURAL_HAM_SHORT(-0.20)[-1.000];
	MIME_GOOD(-0.10)[text/plain];
	MX_GOOD(-0.01)[];
	FREEMAIL_ENVRCPT(0.00)[gmail.com];
	DKIM_SIGNED(0.00)[suse.de:s=susede2_rsa,suse.de:s=susede2_ed25519];
	MIME_TRACE(0.00)[0:+];
	FREEMAIL_CC(0.00)[linux-foundation.org,lwn.net,infradead.org,kernel.org,alpha.franken.de,linux.ibm.com,davemloft.net,gaisler.com,arndb.de,linuxfoundation.org,intel.com,fluxnic.net,linux.dev,suse.de,redhat.com,paragon-software.com,arm.com,zeniv.linux.org.uk,suse.cz,oracle.com,google.com,suse.com,linux.alibaba.com,gmail.com,vger.kernel.org,lists.linux.dev,kvack.org,lists.infradead.org,googlegroups.com,nvidia.com];
	ARC_NA(0.00)[];
	FUZZY_RATELIMITED(0.00)[rspamd.com];
	RCVD_TLS_ALL(0.00)[];
	DKIM_TRACE(0.00)[suse.de:+];
	R_RATELIMIT(0.00)[to_ip_from(RLzjiba8kn1xq17x95uu9jb85x)];
	RCVD_COUNT_TWO(0.00)[2];
	FROM_EQ_ENVFROM(0.00)[];
	FROM_HAS_DN(0.00)[];
	TO_DN_SOME(0.00)[];
	TO_MATCH_ENVRCPT_SOME(0.00)[];
	RECEIVED_SPAMHAUS_BLOCKED_OPENRESOLVER(0.00)[2a07:de40:b281:106:10:150:64:167:received];
	RCPT_COUNT_GT_50(0.00)[62];
	MISSING_XM_UA(0.00)[];
	RCVD_VIA_SMTP_AUTH(0.00)[];
	DBL_BLOCKED_OPENRESOLVER(0.00)[oracle.com:email,suse.de:email,suse.de:dkim]
X-Spam-Flag: NO
X-Spam-Level: 
X-Rspamd-Queue-Id: ABBA222096
X-Rspamd-Server: rspamd2.dmz-prg2.suse.org
X-Rspamd-Action: no action
X-Spam-Score: -2.51
X-Original-Sender: pfalcato@suse.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.de header.s=susede2_rsa header.b=DukI9feJ;       dkim=neutral
 (no key) header.i=@suse.de;       dkim=pass header.i=@suse.de
 header.s=susede2_rsa header.b=DukI9feJ;       dkim=neutral (no key)
 header.i=@suse.de header.s=susede2_ed25519;       spf=pass (google.com:
 domain of pfalcato@suse.de designates 2a07:de40:b251:101:10:150:64:1 as
 permitted sender) smtp.mailfrom=pfalcato@suse.de;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=suse.de
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

On Tue, Sep 16, 2025 at 03:11:50PM +0100, Lorenzo Stoakes wrote:
> It is relatively trivial to update this code to use the f_op->mmap_prepare
> hook in favour of the deprecated f_op->mmap hook, so do so.
> 
> Signed-off-by: Lorenzo Stoakes <lorenzo.stoakes@oracle.com>
> Reviewed-by: David Hildenbrand <david@redhat.com>

Reviewed-by: Pedro Falcato <pfalcato@suse.de>

-- 
Pedro

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/jrxexcuzlxpnfs2jhm7ecdh4kak5i4a6e5od4cm72fn3twwzms%40vptu5rfimbez.
