Return-Path: <kasan-dev+bncBD74H4NGEIILNJFKYYDBUBGSGULCA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33b.google.com (mail-wm1-x33b.google.com [IPv6:2a00:1450:4864:20::33b])
	by mail.lfdr.de (Postfix) with ESMTPS id 10AFAB7DF2E
	for <lists+kasan-dev@lfdr.de>; Wed, 17 Sep 2025 14:37:51 +0200 (CEST)
Received: by mail-wm1-x33b.google.com with SMTP id 5b1f17b1804b1-45b98de0e34sf50321575e9.0
        for <lists+kasan-dev@lfdr.de>; Wed, 17 Sep 2025 05:37:51 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758112670; cv=pass;
        d=google.com; s=arc-20240605;
        b=AutagMoDE3gXzyGtbLmoc6Q5UnmXx4dndQsqKu5p2yjfSIlRP0ip3MxfGh9BQA+8U0
         23xH2mDifPmwtA/GtQ8c9nxGFfW+w5936OxsiKk3POHXmJEr2pB4v2N5J6Fy6koTsdWO
         RRW1CKULcK78KQ47lTO1bQoHuY6hGYGsFpo8wkrx3l3h72wEtgyBxEZrUq9lgYoDKkLn
         oW/H1I5+yGCD2aVZ6ARikHZ+ZTRRFBaN8KhqeUvD3b/f6M3KyJoA430CXMxf7HmjfevY
         XHgZ94Hqcld0IMFfU3F58rCToVb5rVGbWeTkvTfBY22dNueSkIOIjkSet3seNQ4Zxqda
         Coeg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=YIztXQslvqjEbb1eSatUexUQd/C/WO5GI4B8gbfXL2s=;
        fh=fhbhvkBpqENdnlgPV9OPg1s7ENw34LHbrlDvHwQOTbU=;
        b=cfl2X0NoM396uUMFOv+gGo/BWjFFJXoWidiLXI/KHTufr2J4b1/M6WnxuYy8dr45q/
         tF+tu9+xXLLK6Jpzg4z0Z4nve0/mfiePgD1vn57Q0xLAaoVe3BDt4cFE2X0CZS9u7WLK
         HNplYclxzxgSRxkknWm0v06h4Mym2Y7kpAp1y76hlZjo2h3Cl6H//yPmqoFTLb8uJuoD
         XuzbvvseK8NBuW+3/NdiLCdz6DqEaFjUkMnHQ2fb8AKqxGDe8ScQK4yWsrTR1Uj7LWAE
         l4m9iAxTNQaQanBD59sGamLYso+PHWg92G0kMZdWAGrC2KJvxl4ROxUHyB4mGD/HKY+T
         Lhmw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.de header.s=susede2_rsa header.b=niTkxtcE;
       dkim=neutral (no key) header.i=@suse.de;
       dkim=pass header.i=@suse.de header.s=susede2_rsa header.b=niTkxtcE;
       dkim=neutral (no key) header.i=@suse.de;
       spf=pass (google.com: domain of pfalcato@suse.de designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) smtp.mailfrom=pfalcato@suse.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=suse.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758112670; x=1758717470; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=YIztXQslvqjEbb1eSatUexUQd/C/WO5GI4B8gbfXL2s=;
        b=XXJxofZng5inTusRJZEhqN/2eY8bsVFV0kXIINGcSDDJE9ld/Hpbox9ZvDD3s9X2PS
         Y9rafq4UsuiXmPmviG9Ybf6SfMnMg5HrKOfMnfd36nDQ0krHAYuAZuZs450w/86YKElj
         D8WMYlSdk/y6RmnXlHlcJTzmdf63p0EeXafH7PmyqwxGRtr/eMBUQsZP2WpiTDvy7lnb
         7kgL5qIznGZUtG8AEVJ6t8obtd566Ae57u7EKVYeXVHencD5mbkbEO7/NbVwde5CrFgJ
         DhHBHN3nEDF4LmucoSYs0g2g7ZMfZ2vxxJZMBRDGj6YpVmypGEooxXw1YzmglhEcu1Ed
         1uag==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758112670; x=1758717470;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=YIztXQslvqjEbb1eSatUexUQd/C/WO5GI4B8gbfXL2s=;
        b=nRiRlSyOxRFVEXP9DZjZ+pd6u+Gjf+PBoaRXQ27yNhj/o0dxcfo58v6gG1ibh2gCvr
         IDolFV7LVMUmXY54spAsRFSnwdNfjqngF+0B63LpjMf8vgvzajQEVfceKUvcbd383Nrf
         e0u1rmQ847GZSwL6ZpueFzkGY/pP6MXHCw2381Zb2jAAsB5Tv8wHBreZrE/sALXV0+Z+
         v2y5/m1hNuJwPGqp+gf3vcGOqwj40BEclWJ52svJKAm9yz39QGwaTgFf3+/iTvB9RwUR
         dHmdEAbt7dR4IOED9+UfZ7ep9LrAeprjjOrRIlw6G7BkzFGdfGBRiGfP4Uad76oeJLnV
         ZBag==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUqIU9h+zi4I2Cy19dnvli193z6G8jQPcQyns7vap3Fs9XnZnSPndYfWO38HnOIXL+ve6aQXw==@lfdr.de
X-Gm-Message-State: AOJu0YzDHzr1Y+3yV+KBW/VviR1I7SIwReDzseDGhTwG1a02O/tXbBwS
	lHLjDFtB99Dr+iBGPFT5rp55SlNQUIOr8A609r5lxd0Ck9kX0GRk9wao
X-Google-Smtp-Source: AGHT+IGqf1HAtds7OvFtCFb2HVoLkj4IHB/pN7Yb4esPNVP0GxMP6bayIM1ICOg+hQdlWaP8wBvDWg==
X-Received: by 2002:a05:6402:21ce:b0:62f:6860:2d85 with SMTP id 4fb4d7f45d1cf-62f84213e57mr1616238a12.4.1758106167288;
        Wed, 17 Sep 2025 03:49:27 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd6uXIgylLNE3QEkDUYc/8DoH6fMXVpo25gBomoUKHLQGw==
Received: by 2002:a05:6402:5053:b0:61c:742d:7684 with SMTP id
 4fb4d7f45d1cf-62f169050bfls3157534a12.2.-pod-prod-02-eu; Wed, 17 Sep 2025
 03:49:24 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUG415X7ivRGeGfXvDkv4gJ2cBzhfEVVXBobAQbBaTUOUr9yx6+n1pNEPdJFRQ6esZMQXa9si+Mg/w=@googlegroups.com
X-Received: by 2002:a17:907:60cf:b0:b04:8358:7d96 with SMTP id a640c23a62f3a-b1bb935d92dmr205787666b.51.1758106164729;
        Wed, 17 Sep 2025 03:49:24 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1758106164; cv=none;
        d=google.com; s=arc-20240605;
        b=aYH545Vn95KSv3OjhgbHpscEcaGXtoHW+mkpxu4n3d9TzPYDcRuOIBLV6wt4EFUK0n
         85mKKstzH5OTUM8e/nqEsjcP/z7mjzYI75b0y8Ii+6+Rb8AddV3JOqaPOoGhXtj/kpb2
         ai3wR+Ws9LuUDfPUVGwD7q3OkDrzxXqhQBElGy8MnlHif7tiCZ/k7hn7PPqT2nK6znCL
         Zlp/S7+AXZLXsMmyBG0URIf/8QtcBK6Ktm6J8uXJl20YkP0NVYRTtH/vady1apnRldBV
         5ljLM7H5L0IFrfUOZhYu+jxNHENFg7ljKNz67XvSGvEd4hHZWeUaFvysz8+ofNXndpvd
         yEpQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature:dkim-signature
         :dkim-signature:dkim-signature;
        bh=u8t6SHPjmQz0qqNQrQ8pFqlRTGyimMO7f4zNnyjDmnw=;
        fh=3+MH0ChJLBM72NzpB/XiB+Q7hxpuJ08qXy92Zn7JvPc=;
        b=ORUKTj2RDrrj00TTNWb3mR1Hkaxv9846KxfBwMgrWKgy9axvA8edDn5oSyjQD4O9Im
         3zRRjq4ytj4otyflBVv2ZGh73awHEWGEBsRy60MBntQp1/m75ogwfHuOhdMjQ+8P60Yn
         eH4dDYX8xggYpvoESMBt2kYZVOyg4Edp2cmMq2Fvu+I44vFDrsj4FFoJELgOYShjReSb
         17uAI36ZldxghVjCj5pg4FXk8VnHgh/Fq9W/8f2Xegt4JIQq1/yIFFUkNlh9feeu0FsX
         s0nEwQwCAhxwe1OqjwuVd6JRK7cG/H+/XV+FmUay9wsS2wbfpT4ujAGmzr6Q84zvlWSz
         t2gw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.de header.s=susede2_rsa header.b=niTkxtcE;
       dkim=neutral (no key) header.i=@suse.de;
       dkim=pass header.i=@suse.de header.s=susede2_rsa header.b=niTkxtcE;
       dkim=neutral (no key) header.i=@suse.de;
       spf=pass (google.com: domain of pfalcato@suse.de designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) smtp.mailfrom=pfalcato@suse.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=suse.de
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [2a07:de40:b251:101:10:150:64:2])
        by gmr-mx.google.com with ESMTPS id 4fb4d7f45d1cf-62ed9fcbb47si365785a12.0.2025.09.17.03.49.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 17 Sep 2025 03:49:24 -0700 (PDT)
Received-SPF: pass (google.com: domain of pfalcato@suse.de designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) client-ip=2a07:de40:b251:101:10:150:64:2;
Received: from imap1.dmz-prg2.suse.org (imap1.dmz-prg2.suse.org [IPv6:2a07:de40:b281:104:10:150:64:97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id 054001F7B8;
	Wed, 17 Sep 2025 10:49:24 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id 66CFE1368D;
	Wed, 17 Sep 2025 10:49:20 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id 50PgFTCSymh8PQAAD6G6ig
	(envelope-from <pfalcato@suse.de>); Wed, 17 Sep 2025 10:49:20 +0000
Date: Wed, 17 Sep 2025 11:49:18 +0100
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
Subject: Re: [PATCH v3 05/13] mm/vma: rename __mmap_prepare() function to
 avoid confusion
Message-ID: <jokgdkyv4ca4sb7nl2wjkzxclhzhaee4p4luwj546tsdbylfei@laplfpugf3of>
References: <cover.1758031792.git.lorenzo.stoakes@oracle.com>
 <3063484588ffc8a74cca35e1f0c16f6f3d458259.1758031792.git.lorenzo.stoakes@oracle.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <3063484588ffc8a74cca35e1f0c16f6f3d458259.1758031792.git.lorenzo.stoakes@oracle.com>
X-Spamd-Result: default: False [-2.51 / 50.00];
	BAYES_HAM(-3.00)[100.00%];
	SUSPICIOUS_RECIPS(1.50)[];
	NEURAL_HAM_LONG(-1.00)[-1.000];
	MID_RHS_NOT_FQDN(0.50)[];
	R_DKIM_ALLOW(-0.20)[suse.de:s=susede2_rsa,suse.de:s=susede2_ed25519];
	NEURAL_HAM_SHORT(-0.20)[-1.000];
	MIME_GOOD(-0.10)[text/plain];
	MX_GOOD(-0.01)[];
	DKIM_SIGNED(0.00)[suse.de:s=susede2_rsa,suse.de:s=susede2_ed25519];
	FREEMAIL_ENVRCPT(0.00)[gmail.com];
	RBL_SPAMHAUS_BLOCKED_OPENRESOLVER(0.00)[2a07:de40:b281:104:10:150:64:97:from];
	TO_DN_SOME(0.00)[];
	FUZZY_RATELIMITED(0.00)[rspamd.com];
	MIME_TRACE(0.00)[0:+];
	ARC_NA(0.00)[];
	FREEMAIL_CC(0.00)[linux-foundation.org,lwn.net,infradead.org,kernel.org,alpha.franken.de,linux.ibm.com,davemloft.net,gaisler.com,arndb.de,linuxfoundation.org,intel.com,fluxnic.net,linux.dev,suse.de,redhat.com,paragon-software.com,arm.com,zeniv.linux.org.uk,suse.cz,oracle.com,google.com,suse.com,linux.alibaba.com,gmail.com,vger.kernel.org,lists.linux.dev,kvack.org,lists.infradead.org,googlegroups.com,nvidia.com];
	RCVD_TLS_ALL(0.00)[];
	DKIM_TRACE(0.00)[suse.de:+];
	RCVD_COUNT_TWO(0.00)[2];
	TO_MATCH_ENVRCPT_SOME(0.00)[];
	FROM_EQ_ENVFROM(0.00)[];
	FROM_HAS_DN(0.00)[];
	SPAMHAUS_XBL(0.00)[2a07:de40:b281:104:10:150:64:97:from];
	RCPT_COUNT_GT_50(0.00)[62];
	RCVD_VIA_SMTP_AUTH(0.00)[];
	RECEIVED_SPAMHAUS_BLOCKED_OPENRESOLVER(0.00)[2a07:de40:b281:106:10:150:64:167:received];
	R_RATELIMIT(0.00)[to_ip_from(RLzjiba8kn1xq17x95uu9jb85x)];
	MISSING_XM_UA(0.00)[];
	DBL_BLOCKED_OPENRESOLVER(0.00)[oracle.com:email,imap1.dmz-prg2.suse.org:helo,imap1.dmz-prg2.suse.org:rdns,suse.de:email,suse.de:dkim]
X-Spam-Flag: NO
X-Spam-Level: 
X-Rspamd-Queue-Id: 054001F7B8
X-Rspamd-Server: rspamd2.dmz-prg2.suse.org
X-Rspamd-Action: no action
X-Spam-Score: -2.51
X-Original-Sender: pfalcato@suse.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.de header.s=susede2_rsa header.b=niTkxtcE;       dkim=neutral
 (no key) header.i=@suse.de;       dkim=pass header.i=@suse.de
 header.s=susede2_rsa header.b=niTkxtcE;       dkim=neutral (no key)
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

On Tue, Sep 16, 2025 at 03:11:51PM +0100, Lorenzo Stoakes wrote:
> Now we have the f_op->mmap_prepare() hook, having a static function called
> __mmap_prepare() that has nothing to do with it is confusing, so rename
> the function to __mmap_setup().
> 
> Signed-off-by: Lorenzo Stoakes <lorenzo.stoakes@oracle.com>
> Reviewed-by: David Hildenbrand <david@redhat.com>

I would love to bikeshed on the new name (maybe something more descriptive?),
but I don't really mind.

Reviewed-by: Pedro Falcato <pfalcato@suse.de>

-- 
Pedro

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/jokgdkyv4ca4sb7nl2wjkzxclhzhaee4p4luwj546tsdbylfei%40laplfpugf3of.
