Return-Path: <kasan-dev+bncBD74H4NGEIINLG5KYYDBUBFCXMTOM@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x639.google.com (mail-ej1-x639.google.com [IPv6:2a00:1450:4864:20::639])
	by mail.lfdr.de (Postfix) with ESMTPS id C30B1B7D56A
	for <lists+kasan-dev@lfdr.de>; Wed, 17 Sep 2025 14:24:53 +0200 (CEST)
Received: by mail-ej1-x639.google.com with SMTP id a640c23a62f3a-afcb7338319sf588520566b.0
        for <lists+kasan-dev@lfdr.de>; Wed, 17 Sep 2025 05:24:53 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758111893; cv=pass;
        d=google.com; s=arc-20240605;
        b=fqnXCXldreCdYoUl4sL/aYgefDDaKHMoyncTnPCRcKJF2j3uDLzLKP18Fvtrf7oocC
         SB4IrGOabx06cVQbTSSFGRmflVErMCaFdhUW3F6cTg6/4c/MUfqORG7h24VvCOUug9fT
         40Xj3QhwRyBpMiF4/w7Z+KPrFEoJiCSAtEk5G1YghsOZMQjJCxmEdX9EaAJYOsP+Evq6
         PLTAu15Ifz60CqLPL4/H23sw+Hy8IjwmDSUqccTVBBe1QP75qYHQrswO64xuaEzoXWEV
         FBS/YTtz61t4O82utIgVdaLngZXd5wa8DYNgLjrFiS9a5jTQq6STcA2pKTpADZHLEEM0
         krWA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=qhw4HPi/DkzIsG6qNTLwz4tFGbOIOwbuVa0z6E+qdcU=;
        fh=r7lkYUdfIEqhqb9Z2GyWIMFsJEGb8WcmVe3lx5YAyNM=;
        b=dNDPq8BN7XsXyjj1HgHf/6+10R+VZkhMyC74kczZa1svgEdb59L7tDf9GmOXbAwVyG
         fRJpGd3dkn3veaeXHs9q3wRNH1ZBjMoJ6jmraWiStL673plCmkzLRPYVkIYG6l8p7+GX
         gjy0t6seYOEr44pFzuwVG1a8w/VlVq/DERWfd2TpRG9zhhx3ZzaB95LbIJu3qp62LARS
         awOU8qCV8y0aTgF27SpXuSs+d9FE52UYDjZp6RKRlsfaS7woFOl8Dy0KJtfAVmGvIuGW
         2pg17lTij4txvSnry3NKvgbjOaPl6tfFKQIGJG4bw9duuggGtPZWEO6E0DeFHadinSba
         TG6w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.de header.s=susede2_rsa header.b=DqGz99zL;
       dkim=neutral (no key) header.i=@suse.de;
       dkim=pass header.i=@suse.de header.s=susede2_rsa header.b=DqGz99zL;
       dkim=neutral (no key) header.i=@suse.de;
       spf=pass (google.com: domain of pfalcato@suse.de designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) smtp.mailfrom=pfalcato@suse.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=suse.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758111893; x=1758716693; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=qhw4HPi/DkzIsG6qNTLwz4tFGbOIOwbuVa0z6E+qdcU=;
        b=Dh8MNyhjSl+A6LJVgBawY2FogU+F0gF8C8s4LBoaKSzWm5PPOQYPqbVU2pkOEBPoor
         p2PFYpYZQy9jAPNCYJrKD05m+5XQLe8ePSzH+E1lTCvpbBxvtE59os/nz0UllWcqKQ1t
         l2Jv/ctY1UMuygpOjN67LEponJEwD2W67YLalgABj74liXk/66dvj87ditVb9JfS1PPT
         SHOqgEqxa4mEAUDVz+Z6JmpeAOHhrhZ6NR96XehRluKRequk6rXNc+BJHkjb32fv/yup
         SK1KW7IVJ+eYbULBKzHCNoAE8KK1CEqta9UiEfMX+k4PsdKH8ZJqjqtap69XgIyzJgsJ
         4GAQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758111893; x=1758716693;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=qhw4HPi/DkzIsG6qNTLwz4tFGbOIOwbuVa0z6E+qdcU=;
        b=XaWVbLni1QVNhcfQMuFWS/GC8Rpx7B54b4c7EPVi9JTtcI6wojj8OmfurYpHZPVAE4
         TtXoqqzU+2qFRWJBBDqGyvSUhr9USWTxNpb4mmz8jBSm4enQjOzLNLtVyt7JCB0Z1qBJ
         NwRyJazBeM/j3hj0Ojh9eBb8iW7s1ZTC0IJpZBSx2IZbtgyC56xeYP4Q3xfYl2b8eoOO
         atI3vJFmaaq0OUedLLV5Y8TEyAcaVjFwMd+tCVrX8kx3MF4DYmWHEceNXmUR02M1LwMI
         dFJf+50dk2WMvC2IqH32BgKm8eK+UEaoog42WeE4ToQcZM1hMTvZIfkpawPsLXU0yjiA
         uiDQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCV0CL4m61uVnlLVUXq5RhZyMN9qnF65WF1Ptx88Y3tspFP6Ylf/pZEbikGmJN6xXu++ZaPUVQ==@lfdr.de
X-Gm-Message-State: AOJu0Yzki2piTwCbgHGgAnYDxdCyn9jpQ61B4O/dC3QLV+IcahkEzpXV
	dTH4QlTajopokFSYYYO5IxQ0YWwT43sR64Zf7RKNC4h+nvKUSuJkR1Jw
X-Google-Smtp-Source: AGHT+IFAqThsNFa878868AhxnjXcNWBm+kSJWpWSCmUBdox1rEjxYFWfsTRPv7MVDEWaL2jCri/uSg==
X-Received: by 2002:a2e:b8c7:0:b0:351:786c:e52e with SMTP id 38308e7fff4ca-35f61f89555mr5684161fa.6.1758105046351;
        Wed, 17 Sep 2025 03:30:46 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd7f5Ow85XCtXn1RkI9BBxjqsbaSg7YW76PZzL2mGAkmnw==
Received: by 2002:a2e:bc0d:0:b0:35f:1b21:836f with SMTP id 38308e7fff4ca-35f1b30c78els2048491fa.1.-pod-prod-05-eu;
 Wed, 17 Sep 2025 03:30:43 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVwn4Z0+wK+qRk4zVxznMx1yB+Pj/2aBK4u+qH8LucNKGY9FUjhrsRaeeoZuSCSomKnwXGW0U1pE20=@googlegroups.com
X-Received: by 2002:a05:651c:1116:20b0:339:1b58:a58c with SMTP id 38308e7fff4ca-35f638c1ff6mr4135591fa.17.1758105043318;
        Wed, 17 Sep 2025 03:30:43 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1758105043; cv=none;
        d=google.com; s=arc-20240605;
        b=HKzfpCGJrIVvQdnbqOygxf8HODzmN6VL/EEmoSGmn+a8ydiYKRHI6t3wjPvzghO2+/
         2015L70ao5NuhcRYf/XcxmhPRq8HiP8KvdMsctTpiSSceh47/+foeXzZ3niBh+0baf5k
         ZWwW1DLjMega/d2WXtCzqhhIXqQZMT5xyNFxaXINJk2ow5LFs/Qp2lNiXneVxNrq3Cmn
         czJV9GSrjRd/UwbT5pLNRXIVsnCOJ+GVeTYRuC6cBNgTegAohyrAHfyBO2jwx9laYPvn
         8LaC1aibDLK6X4skbFskFZg74D1uyo0ihpTmx4y+Mm6uftzVIa+Kg9N4DiJxumTSx9zL
         TuOQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature:dkim-signature
         :dkim-signature:dkim-signature;
        bh=1zHHraw2A4XXMh05M5xDQ/FIBzoxt7xagq0j6ASLE/8=;
        fh=3+MH0ChJLBM72NzpB/XiB+Q7hxpuJ08qXy92Zn7JvPc=;
        b=YQbZG6pa6E+dAh+Q1XbqJF18qy5ihaEdqFvCcj/fVfddPV+Qp7VP0Oq58+iFD5H7bM
         xCKR7ideVQ4s5Pa/sE3v1qlbyMEFgBQpL0pjPAkKyIazabG5eUZKbJtwtqaun27YR91B
         Pa+XH4gcH0wbqZ6nIAUVYbExQoAcg3sHS1Gl1UOmzDupWgx0R0IEMhDvJZ2jeQ/tHx4V
         Xr7bdxZ45hsVfp/5kUMxtqUyC1kXWuW/8J9hLZxlkOVSqPsZhHQDtvShr7jQ+mfd5X0t
         H1in0qnuqBaF8b2XcB+7aDjbKI7TgrTxddJGsSur0Y+Jf9NpD10LW31iOF4k+MeEQIxm
         /edg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.de header.s=susede2_rsa header.b=DqGz99zL;
       dkim=neutral (no key) header.i=@suse.de;
       dkim=pass header.i=@suse.de header.s=susede2_rsa header.b=DqGz99zL;
       dkim=neutral (no key) header.i=@suse.de;
       spf=pass (google.com: domain of pfalcato@suse.de designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) smtp.mailfrom=pfalcato@suse.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=suse.de
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [2a07:de40:b251:101:10:150:64:2])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-351265c0e4fsi2563621fa.1.2025.09.17.03.30.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 17 Sep 2025 03:30:43 -0700 (PDT)
Received-SPF: pass (google.com: domain of pfalcato@suse.de designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) client-ip=2a07:de40:b251:101:10:150:64:2;
Received: from imap1.dmz-prg2.suse.org (unknown [10.150.64.97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id 698CD1F7A4;
	Wed, 17 Sep 2025 10:30:42 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id E6B6E1368D;
	Wed, 17 Sep 2025 10:30:38 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id pYOYNM6NymjANgAAD6G6ig
	(envelope-from <pfalcato@suse.de>); Wed, 17 Sep 2025 10:30:38 +0000
Date: Wed, 17 Sep 2025 11:30:37 +0100
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
Subject: Re: [PATCH v3 01/13] mm/shmem: update shmem to use mmap_prepare
Message-ID: <ixvivcg7sr6twekgyfgas7yl23nv7zi5bmn6xyqjvsvuituc4d@usfryzkaf7dm>
References: <cover.1758031792.git.lorenzo.stoakes@oracle.com>
 <cfefa4bad911f09d7accea74a605c49326be16d9.1758031792.git.lorenzo.stoakes@oracle.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <cfefa4bad911f09d7accea74a605c49326be16d9.1758031792.git.lorenzo.stoakes@oracle.com>
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
X-Spam-Level: 
X-Spam-Score: -2.30
X-Original-Sender: pfalcato@suse.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.de header.s=susede2_rsa header.b=DqGz99zL;       dkim=neutral
 (no key) header.i=@suse.de;       dkim=pass header.i=@suse.de
 header.s=susede2_rsa header.b=DqGz99zL;       dkim=neutral (no key)
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

On Tue, Sep 16, 2025 at 03:11:47PM +0100, Lorenzo Stoakes wrote:
> This simply assigns the vm_ops so is easily updated - do so.
> 
> Signed-off-by: Lorenzo Stoakes <lorenzo.stoakes@oracle.com>
> Reviewed-by: Baolin Wang <baolin.wang@linux.alibaba.com>
> Reviewed-by: David Hildenbrand <david@redhat.com>
> Reviewed-by: Jan Kara <jack@suse.cz>

Reviewed-by: Pedro Faclato <pfalcato@suse.de>

-- 
Pedro

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/ixvivcg7sr6twekgyfgas7yl23nv7zi5bmn6xyqjvsvuituc4d%40usfryzkaf7dm.
