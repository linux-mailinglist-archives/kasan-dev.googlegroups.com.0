Return-Path: <kasan-dev+bncBD74H4NGEIIJLLNKYYDBUBBJC3VIC@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53d.google.com (mail-ed1-x53d.google.com [IPv6:2a00:1450:4864:20::53d])
	by mail.lfdr.de (Postfix) with ESMTPS id A747EB7CA92
	for <lists+kasan-dev@lfdr.de>; Wed, 17 Sep 2025 14:07:46 +0200 (CEST)
Received: by mail-ed1-x53d.google.com with SMTP id 4fb4d7f45d1cf-62f770119a0sf1436611a12.0
        for <lists+kasan-dev@lfdr.de>; Wed, 17 Sep 2025 05:07:46 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758110865; cv=pass;
        d=google.com; s=arc-20240605;
        b=Xro0lfUpqsL0PEY8jUx1FzJyUd4lVvU7RNiFcRIkRl/rkxhDhfFJusIHlY/6MGfCs3
         YKhGKE2uIXzZnaPya+XOUYVD9ONi5gKG9Gv6AX9o3zo7vNHGieyRGTtQxoBQMxOVGdZx
         IeXE1idFnFBUTEIoi/H6QaqC1P70sbc0JajfGxbu8msSnD7bulZeV2CrRYOgS+8QYUPb
         u9kX3u+KoeLrIINTjnHNI3T5V+mE5ytYsipDnSvXuTxSM5YNIBU1Tp5sSjDelq203og6
         hJa3Zqx5Ki6Xmw3UXSMJckFy9+PhLierNl9o184zzuwCwOopr5vE3rLXO4wh5ng1sK/E
         CA3w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=GSZokTkcLYFUKEJtyV3WyZNMwiDEIkZ4DFDbmlX8ICg=;
        fh=TFUqKE7u7fhG1AGYn/1pNtw5QS7z/i+EwHDTMLL/fGQ=;
        b=GJXF4NO1HSV6I96FwLPsoAJuSmiG5dcB/oXeyh1RK9CCzwr2aRX5v9ZlA7M7vqUdLk
         jv91JKFFGpd5xQei6umK6ZKt//j8FOp0SJObxBMhTGJxUNGuas43W0KLyisqgOxFBS5k
         MCdO/AneOqyLx5EMWEji5fj5DYBQQi8sP7j8LwtRl/TboSA20widLZH8sLyLr3hDqriY
         0vJtJvyS1WI9MJa67KGHqwuEq7+Xk/Jbg8uD69LomTfW1c34gHXjH+csIiwPvHvpfbX6
         4EKslA3U8jLM+WUxyDTDf9l0qW2UaYBfqWvDQcIJY65Q+dCk9ydYUKCMeRhtR+xPwSVR
         f4kA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.de header.s=susede2_rsa header.b=ptkrptGs;
       dkim=neutral (no key) header.i=@suse.de header.s=susede2_ed25519;
       dkim=pass header.i=@suse.de header.s=susede2_rsa header.b=ptkrptGs;
       dkim=neutral (no key) header.i=@suse.de;
       spf=pass (google.com: domain of pfalcato@suse.de designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) smtp.mailfrom=pfalcato@suse.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=suse.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758110865; x=1758715665; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=GSZokTkcLYFUKEJtyV3WyZNMwiDEIkZ4DFDbmlX8ICg=;
        b=FwH2k+8xqf3o3gun5gLZ1pdGFlhuyuY4ee4DJLj6bVUK34oBcKTDTqOphTaeuBqNLu
         9/MT3IZ0GqeVlrZ+ZNQIpXXCH/owK6IAMey+0xQbZShkiWTcVzpFfC6jzPgJa8NaR4lJ
         h0U5hPbNVpdhqROWCoEcBybIzRADimU5a75c8aiS3E9clpwpGZGXONSLEJj/hHF8xN8D
         jWm2w1px1kN2TgZHvxfRurLiS7ipqmbCQPHBgXwrHQVoRrScCGcyqOcWWPvznccQLrwS
         gZK1HxiAtMMkEI+DWG/alvzVIVAvfTeZ+6fM4op1o6/Sb5ozOsvhmyATKTSDdhz7iQot
         fIZg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758110865; x=1758715665;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=GSZokTkcLYFUKEJtyV3WyZNMwiDEIkZ4DFDbmlX8ICg=;
        b=crfZ+1Jw4WTc7aKW9KlbFWodm184qBRZCFxo6aBt855/431ZyplF7Mypdl6Aqf77FY
         eaiFk6S2xkHgVsxSGu6g58XFCDbJCISIPhI5MyZ+kQ6NPhGNVMKE72tfjXYfk81vdTZG
         axmoHdS3S1Yof6CY7EGWjZAdnosqVOXLm5kEvjVH05Qu+2TVcCZSNQMLZ6pLWcj1LoPO
         ZDkNLC40MNmj10VF+hg7g8rA7kkXxSab9zSzPbEBG3JhXiI3G+UzGypl7zkSilNdWBHP
         awMh1gQ2PY6rUXf1ewiXxpHJcIzNDt9xq6uiQ4/UiFXbe9cB82ralN6tdGR3XwQLFL5S
         3CHw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWcmScXfIBX/56n649++/3nMLPuBHovhUf1wH0Q9FGZ3d7/0zbdVVzVH7g1qisI5F8wSA4CjQ==@lfdr.de
X-Gm-Message-State: AOJu0YwlmIjT1hCRwuw+Dpddqcg7P4/Pq3UVMDxsMaadvqvbLfXUcrug
	OTUpDdapN6VHaL037qIs+bx7aFZmfn9fVHF+FgatVXO7eaD9LllITrCW
X-Google-Smtp-Source: AGHT+IEn12KAqxGkPokdf7dSRzxxX3KqXX1S4uvG9Y8NexvRAwVu0MW+6WQ6oiOiGk8J82lv43Lv/g==
X-Received: by 2002:a05:6000:2511:b0:3e7:9d76:beb5 with SMTP id ffacd0b85a97d-3ecdf9cc0b4mr1532397f8f.14.1758107285740;
        Wed, 17 Sep 2025 04:08:05 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd6oJ676fBTrWJfVVU8PNQuut4CQZ+TAWg5Qkpb5vgwKOg==
Received: by 2002:a05:6000:200f:b0:3e7:5e78:598 with SMTP id
 ffacd0b85a97d-3ecd7a10fe9ls820620f8f.2.-pod-prod-08-eu; Wed, 17 Sep 2025
 04:08:03 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWhN0kmeBR7QJdYXopiXMl8DDhWpTLaha9V4GwhQz2DwNUdpYfMm13QnlDkM0fj9BIqgL+Feln5eGc=@googlegroups.com
X-Received: by 2002:a5d:5d06:0:b0:3e5:31d3:e330 with SMTP id ffacd0b85a97d-3ecdf9ce69amr1698720f8f.25.1758107283102;
        Wed, 17 Sep 2025 04:08:03 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1758107283; cv=none;
        d=google.com; s=arc-20240605;
        b=FSzVuhn61Q92ZCzkkL+FryrNf5E2eIzgaZxuqRnO4cOtkwqNh5Gw5iKYGrHG+rLmOS
         hWTkzGsLZ2EW9zhySNBQEf2UGimWdAY8WQNtzgsZwrUGeU/qo8FmRWnK4uWcdaIP3njK
         iok25wla8sDpua8UGQ45etFsDBQbXhsqMC4KW3tmSjRC/m0LVgJdHY6fh+9vWD4eYlBv
         JPvHMYkqxNnljOYO8cO/4PvAZflS1fR61B4rH8jO3228U8VMjbDrJDzOEi9dLvJlD1Tp
         luY44CC5cpVAbl9aw0eHx0jaCuQqzyKu7u7sSEldqRBPpo/ABuCmdcnXEIdjOanoaiYd
         QvZg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature:dkim-signature
         :dkim-signature:dkim-signature;
        bh=8/j+TghCbMxS6Hr+M6Px03nxBiobgKniH+u2vLxerW8=;
        fh=3+MH0ChJLBM72NzpB/XiB+Q7hxpuJ08qXy92Zn7JvPc=;
        b=QRy5aEyZv4+0RvqGnc2tXe741ZupaFs+COccBlm6THd0p+B0bgvdWXBbs/JsfmVm6a
         lqJXznqGb8FCfBbhNCyikb0tgX26gf7I7YYsTmtsPFxXJdJFe/7rtMhvsUOVmy+oxm0w
         o3XDHoeuad5K0FwvMdkRQx5eBRayX7fD7+RORAgsb7YK1cXc4EYnqsvyJ21t2wPs54Us
         qCcO4vk8xzGznef3BMpmk5azcI/Mx1ajISozZ7rK4451wumZM9ZehY1QXMygKJW9opK7
         DzqAG99yPKIF0CSJwriT7OLod5OAMqqANBNvKw5F8XsoQBnXSvYrWMz7WChB/1pvkdIi
         7QuQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.de header.s=susede2_rsa header.b=ptkrptGs;
       dkim=neutral (no key) header.i=@suse.de header.s=susede2_ed25519;
       dkim=pass header.i=@suse.de header.s=susede2_rsa header.b=ptkrptGs;
       dkim=neutral (no key) header.i=@suse.de;
       spf=pass (google.com: domain of pfalcato@suse.de designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) smtp.mailfrom=pfalcato@suse.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=suse.de
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [2a07:de40:b251:101:10:150:64:1])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-3e7607e2f36si65256f8f.4.2025.09.17.04.08.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 17 Sep 2025 04:08:03 -0700 (PDT)
Received-SPF: pass (google.com: domain of pfalcato@suse.de designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) client-ip=2a07:de40:b251:101:10:150:64:1;
Received: from imap1.dmz-prg2.suse.org (imap1.dmz-prg2.suse.org [IPv6:2a07:de40:b281:104:10:150:64:97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id 709D02126A;
	Wed, 17 Sep 2025 11:08:02 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id D09581368D;
	Wed, 17 Sep 2025 11:07:58 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id 1iOPL46WymikQwAAD6G6ig
	(envelope-from <pfalcato@suse.de>); Wed, 17 Sep 2025 11:07:58 +0000
Date: Wed, 17 Sep 2025 12:07:52 +0100
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
Subject: Re: [PATCH v3 06/13] mm: add remap_pfn_range_prepare(),
 remap_pfn_range_complete()
Message-ID: <fdkqhtegozzwx3p4fqzkar7dfbzffn7xiz7ht365c3pe4x6hk3@zbfwoktrhci3>
References: <cover.1758031792.git.lorenzo.stoakes@oracle.com>
 <7c050219963aade148332365f8d2223f267dd89a.1758031792.git.lorenzo.stoakes@oracle.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <7c050219963aade148332365f8d2223f267dd89a.1758031792.git.lorenzo.stoakes@oracle.com>
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
	FUZZY_RATELIMITED(0.00)[rspamd.com];
	TO_DN_SOME(0.00)[];
	RBL_SPAMHAUS_BLOCKED_OPENRESOLVER(0.00)[2a07:de40:b281:104:10:150:64:97:from];
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
	DBL_BLOCKED_OPENRESOLVER(0.00)[oracle.com:email,suse.de:email,suse.de:dkim,imap1.dmz-prg2.suse.org:helo,imap1.dmz-prg2.suse.org:rdns]
X-Spam-Flag: NO
X-Spam-Level: 
X-Rspamd-Queue-Id: 709D02126A
X-Rspamd-Server: rspamd2.dmz-prg2.suse.org
X-Rspamd-Action: no action
X-Spam-Score: -2.51
X-Original-Sender: pfalcato@suse.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.de header.s=susede2_rsa header.b=ptkrptGs;       dkim=neutral
 (no key) header.i=@suse.de header.s=susede2_ed25519;       dkim=pass
 header.i=@suse.de header.s=susede2_rsa header.b=ptkrptGs;       dkim=neutral
 (no key) header.i=@suse.de;       spf=pass (google.com: domain of
 pfalcato@suse.de designates 2a07:de40:b251:101:10:150:64:1 as permitted
 sender) smtp.mailfrom=pfalcato@suse.de;       dmarc=pass (p=NONE sp=NONE
 dis=NONE) header.from=suse.de
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

On Tue, Sep 16, 2025 at 03:11:52PM +0100, Lorenzo Stoakes wrote:
> We need the ability to split PFN remap between updating the VMA and
> performing the actual remap, in order to do away with the legacy
> f_op->mmap hook.
> 
> To do so, update the PFN remap code to provide shared logic, and also make
> remap_pfn_range_notrack() static, as its one user, io_mapping_map_user()
> was removed in commit 9a4f90e24661 ("mm: remove mm/io-mapping.c").
> 
> Then, introduce remap_pfn_range_prepare(), which accepts VMA descriptor
> and PFN parameters, and remap_pfn_range_complete() which accepts the same
> parameters as remap_pfn_rangte().
                remap_pfn_range

> 
> remap_pfn_range_prepare() will set the cow vma->vm_pgoff if necessary, so
> it must be supplied with a correct PFN to do so.  If the caller must hold
> locks to be able to do this, those locks should be held across the
> operation, and mmap_abort() should be provided to revoke the lock should
> an error arise.
> 
> While we're here, also clean up the duplicated #ifdef
> __HAVE_PFNMAP_TRACKING check and put into a single #ifdef/#else block.
> 
> We would prefer to define these functions in mm/internal.h, however we
> will do the same for io_remap*() and these have arch defines that require
> access to the remap functions.
>

I'm confused. What's stopping us from declaring these new functions in
internal.h? It's supposed to be used by core mm only anyway?


> Signed-off-by: Lorenzo Stoakes <lorenzo.stoakes@oracle.com>

The changes themselves look OK to me, but I'm not super familiar with these
bits anyway.

Acked-by: Pedro Falcato <pfalcato@suse.de>

-- 
Pedro

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/fdkqhtegozzwx3p4fqzkar7dfbzffn7xiz7ht365c3pe4x6hk3%40zbfwoktrhci3.
