Return-Path: <kasan-dev+bncBC5I5WEMW4JBBYNT7PCQMGQECQ7V2QI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23a.google.com (mail-lj1-x23a.google.com [IPv6:2a00:1450:4864:20::23a])
	by mail.lfdr.de (Postfix) with ESMTPS id EE9D2B48F73
	for <lists+kasan-dev@lfdr.de>; Mon,  8 Sep 2025 15:28:03 +0200 (CEST)
Received: by mail-lj1-x23a.google.com with SMTP id 38308e7fff4ca-3381cbfc1fbsf11773941fa.2
        for <lists+kasan-dev@lfdr.de>; Mon, 08 Sep 2025 06:28:03 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757338082; cv=pass;
        d=google.com; s=arc-20240605;
        b=Wz0BWft282M8xsJO1XRgDQ94YxpRt/RaZcpXEttwxhlKST3GaqduhsWhbU1NIoIPvr
         6md8HgBGiicKRMONamVUDMua6xqTMg4ZDYWifTDVk6925SA7MPki1KaJidAoxsRCOcfK
         WwGC8+0QKyldqQT3MEeuULXKPuQNd6/ovEKs0YPWKv+DuDWZqiI75oCs1w2+wAVuCqwi
         SWFzW+xunAaRN386ECSOKWaCY8rY4ZpOFZdmAYo6J1viG76LHva9l/nGhhMWhbRNDz3V
         UP3Wp+is78ZoM/cBogiENeXfmOhlv7A+g8YcIJm+JzfYoRkK1coQqGw4zt2V7b5KJjIf
         dB9Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=HvzKLhXoBvV7zTACSouIrbpJkQDduEZP+jQsF34mJs8=;
        fh=5bTyzRFI07Cw/woIWy6uCcZk1XzV8cjPlw4EdplGq8Y=;
        b=WbXINzCg4kqdiP8yprsRqJqH3T7YK0LcOoYtONfEFWXHAo11aA9WsbTVEqnbsi6Zf8
         X3BiOD68/ynDim1Z6tYodgVdcCPkFBU1Cjx32f63EOIU7j6Y7KnSBMhvb560wgkSwlni
         80ZIp3BpuCzentuEzLKwwtrXJG9Q3QkUJskuMjOnnniHY54TVDwp+aXgo7T7p3Ud7XcS
         bQREiwKmz6swqZM//UraYSJwjdFNFZXbKMkMmakxz+ifb5frX78+Ug2R61dD25INFasZ
         sKhQJZFxJ9PrJrfOcx2SCksl6KRSMqQKtG0jjl+0rpza6Wifbga0ncNwRQHsrgjT6FHj
         KhAA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b="cYx/uSMK";
       dkim=neutral (no key) header.i=@suse.cz;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b="cYx/uSMK";
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of jack@suse.cz designates 195.135.223.130 as permitted sender) smtp.mailfrom=jack@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757338082; x=1757942882; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=HvzKLhXoBvV7zTACSouIrbpJkQDduEZP+jQsF34mJs8=;
        b=V9LmZvk/8Bwzn19y+n/K1/pfRisKNePNkruIhyOj0JAOXTIDHqujfqH/tm/+PeYQru
         33NVi9em9b143wKWe32XTOrdnlGV4EcCkPAAQAoyinI0eG5YyrZWXsgNIwM7+Cchiy+s
         bs7OKRwwKCtcuDnr9OYe1yJ6Gb6u4cY0hNklPW0tqwRf4Jo2B5e65UuXgV4GNEw8IWxH
         ygTBAyHxfSjrqwu2H/3QvFwHM7oRIRMRe+CoQyZhIqnQby/u5AX27EJSofITVKvoL00I
         rqLB3OWZvjqdvmoMNJlHoefnKzaQF2ZznTIlCTG5W0nTnzbr8QoRavDBW3yyHaEam6su
         ArRA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757338082; x=1757942882;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=HvzKLhXoBvV7zTACSouIrbpJkQDduEZP+jQsF34mJs8=;
        b=vC+pJJuPlvO8p6l6UFlJXqWu7kGftCOxJTAQLiUFkIouYo4ZNUOOtkL19HS6as822D
         +ppNWB0wMrVkwhWTsxAHQrY1ACPH70L5/27pmDpR6nU129Zxel2OgVqO7/EUWy2dYvn4
         21QwUkMnouNbp55ILstOZW6SUX5PTO2a0Zz33S8edWOQ0obpOl7cs24yIEis8NtoM/Cr
         NH2xmAa7YFDT3K1IjASf+JdbG14TG47OiLZAMyRZu7fRG3mzK053vov4rk3TZpuCy7KZ
         hhLlSsw7yqxuAYCSs91jHC4C3ILo1yMKhSiu8yIrsQkoVMKLoMTAsb/e8BVXtdDLKXbu
         PiAg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWAU+d82o9QGVaREp/Cmb4SCOY+Wex/OyZ2bMKC8n753zqrqW3ZUJuQGtoxibHYn/MCLMaqhw==@lfdr.de
X-Gm-Message-State: AOJu0Ywg5oYlPrt/eZjxDkkPUFFlYiTg1nZJfi0os0FXJEKlpt/5Xor1
	ELieV0pmejKRSka7XwNbpeb6VAJprriZ6FL32eVCEaTLGTHR52d8w6bp
X-Google-Smtp-Source: AGHT+IHM1fcDUYHd+PZgPQqTH8d2yjUAK0kxYpYrR4w7LZhXafimLWloxSAUwUaZtrrWLy2277SVug==
X-Received: by 2002:a2e:a992:0:b0:336:7aae:7c54 with SMTP id 38308e7fff4ca-33b51b178f2mr23891471fa.23.1757338081786;
        Mon, 08 Sep 2025 06:28:01 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcBomO0ms3uHGE+THnzWzFgCWZ9dqtAVKnTUeJQFYdiuQ==
Received: by 2002:a05:651c:2091:b0:336:ad13:b88c with SMTP id
 38308e7fff4ca-338d412e3d1ls3274591fa.2.-pod-prod-03-eu; Mon, 08 Sep 2025
 06:27:58 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVSvWbLHOzwW3e40Ht9wN00L/Wxwxjn8MxKOa7j3TE1UtGhoFuDAPWiHCwB5VhCiXGPF6ztx0qrqpE=@googlegroups.com
X-Received: by 2002:a05:6512:3b94:b0:55f:3ddb:2306 with SMTP id 2adb3069b0e04-5626310e5bdmr2175749e87.45.1757338078542;
        Mon, 08 Sep 2025 06:27:58 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1757338078; cv=none;
        d=google.com; s=arc-20240605;
        b=O2ple6LPHId8KQcPCaIFx1gUwBtxthhjatrf/bEKf66TtXCMKfSXkslbhX+irLshJh
         5rGiyFdWoqN80jzTS1kOESevTagL9ldnfS1K3GcTfgvVc2U03SJbrD7vvda0F97gFP8F
         pH6k6FjXUHCAVD3M8D46/OM+qMcj3Zh3Cv2OJQBIsD84JAkUU/xQOigyr3EpRP1JVADF
         NMgw4HVjL6ZiYXmCgQzoo0PPlINoF85gLW/Y90OWZnBEeKCTRg1ByqkDynTstJo7N13u
         5ICibXEGUTx9wMZW2JUchqHCSOPd2gPC+mDc7tzMWzQz9C6pra0tkxLjRsnKwOXhjV1a
         d4Ww==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature:dkim-signature
         :dkim-signature:dkim-signature;
        bh=BSVOtvPeLvl+UpiPHTfFfgs/48zgcwZMdviTSnSO1lU=;
        fh=/v17VW8MchCHUgpXxAXTMs5Ee7lYsmC259Kuc6hqZT8=;
        b=k300jPdU0AoeL8Gc26vz6VsBHJWspBBuos3d0An5+DgD0PHOwsho52VCGZWP+eq5Ap
         HUlhapX6zC9NrPx5KTLlXJWqG7UFhs0zpjKzaT8nqyzZasd4IsyySPrbeUXZUOtr5hFX
         roMxZjW1PcD9tBFZ2sgIDqEJTaUddXqePboM0mKn7/aV8F79yvAIizvf4bERg3Y/qUTH
         qWnHoPRk7slgWVw4LUhQJsALaWTVEAbkFz1myd0hej7bJq8fragqwo4RROwNqfkFdOa5
         u82Co9ONmcRMovieNnpllxvTvMcD9sF+Z3K6CCBsGlcA19QpvFsh+hX0eMg+iMlxOg7q
         fL/Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b="cYx/uSMK";
       dkim=neutral (no key) header.i=@suse.cz;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b="cYx/uSMK";
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of jack@suse.cz designates 195.135.223.130 as permitted sender) smtp.mailfrom=jack@suse.cz
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [195.135.223.130])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-5608ac88793si267711e87.5.2025.09.08.06.27.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 08 Sep 2025 06:27:58 -0700 (PDT)
Received-SPF: pass (google.com: domain of jack@suse.cz designates 195.135.223.130 as permitted sender) client-ip=195.135.223.130;
Received: from imap1.dmz-prg2.suse.org (unknown [10.150.64.97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id BF2BC265F7;
	Mon,  8 Sep 2025 13:27:56 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id AB74013869;
	Mon,  8 Sep 2025 13:27:56 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id xFqgKdzZvmjdNwAAD6G6ig
	(envelope-from <jack@suse.cz>); Mon, 08 Sep 2025 13:27:56 +0000
Received: by quack3.suse.cz (Postfix, from userid 1000)
	id 4EBA2A0A2D; Mon,  8 Sep 2025 15:27:52 +0200 (CEST)
Date: Mon, 8 Sep 2025 15:27:52 +0200
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
Subject: Re: [PATCH 00/16] expand mmap_prepare functionality, port more users
Message-ID: <tyoifr2ym3pzx4nwqhdwap57us3msusbsmql7do4pim5ku7qtm@wjyvh5bs633s>
References: <cover.1757329751.git.lorenzo.stoakes@oracle.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <cover.1757329751.git.lorenzo.stoakes@oracle.com>
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
 header.i=@suse.cz header.s=susede2_rsa header.b="cYx/uSMK";
       dkim=neutral (no key) header.i=@suse.cz;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b="cYx/uSMK";
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

Hi Lorenzo!

On Mon 08-09-25 12:10:31, Lorenzo Stoakes wrote:
> Since commit c84bf6dd2b83 ("mm: introduce new .mmap_prepare() file
> callback"), The f_op->mmap hook has been deprecated in favour of
> f_op->mmap_prepare.
> 
> This was introduced in order to make it possible for us to eventually
> eliminate the f_op->mmap hook which is highly problematic as it allows
> drivers and filesystems raw access to a VMA which is not yet correctly
> initialised.
> 
> This hook also introduces complexity for the memory mapping operation, as
> we must correctly unwind what we do should an error arises.
> 
> Overall this interface being so open has caused significant problems for
> us, including security issues, it is important for us to simply eliminate
> this as a source of problems.
> 
> Therefore this series continues what was established by extending the
> functionality further to permit more drivers and filesystems to use
> mmap_prepare.
> 
> After updating some areas that can simply use mmap_prepare as-is, and
> performing some housekeeping, we then introduce two new hooks:
> 
> f_op->mmap_complete - this is invoked at the point of the VMA having been
> correctly inserted, though with the VMA write lock still held. mmap_prepare
> must also be specified.
> 
> This expands the use of mmap_prepare to those callers which need to
> prepopulate mappings, as well as any which does genuinely require access to
> the VMA.
> 
> It's simple - we will let the caller access the VMA, but only once it's
> established. At this point unwinding issues is simple - we just unmap the
> VMA.
> 
> The VMA is also then correctly initialised at this stage so there can be no
> issues arising from a not-fully initialised VMA at this point.
> 
> The other newly added hook is:
> 
> f_op->mmap_abort - this is only valid in conjunction with mmap_prepare and
> mmap_complete. This is called should an error arise between mmap_prepare
> and mmap_complete (not as a result of mmap_prepare but rather some other
> part of the mapping logic).
> 
> This is required in case mmap_prepare wishes to establish state or locks
> which need to be cleaned up on completion. If we did not provide this, then
> this could not be permitted as this cleanup would otherwise not occur
> should the mapping fail between the two calls.

So seeing these new hooks makes me wonder: Shouldn't rather implement
mmap(2) in a way more similar to how other f_op hooks behave like ->read or
->write? I.e., a hook called at rather high level - something like from
vm_mmap_pgoff() or similar similar level - which would just call library
functions from MM for the stuff it needs to do. Filesystems would just do
their checks and call the generic mmap function with the vm_ops they want
to use, more complex users could then fill in the VMA before releasing
mmap_lock or do cleanup in case of failure... This would seem like a more
understandable API than several hooks with rules when what gets called.

								Honza

> 
> We then add split remap_pfn_range*() functions which allow for PFN remap (a
> typical mapping prepopulation operation) split between a prepare/complete
> step, as well as io_mremap_pfn_range_prepare, complete for a similar
> purpose.
> 
> From there we update various mm-adjacent logic to use this functionality as
> a first set of changes, as well as resctl and cramfs filesystems to round
> off the non-stacked filesystem instances.
> 
> 
> REVIEWER NOTE:
> ~~~~~~~~~~~~~~
> 
> I considered putting the complete, abort callbacks in vm_ops, however this
> won't work because then we would be unable to adjust helpers like
> generic_file_mmap_prepare() (which provides vm_ops) to provide the correct
> complete, abort callbacks.
> 
> Conceptually it also makes more sense to have these in f_op as they are
> one-off operations performed at mmap time to establish the VMA, rather than
> a property of the VMA itself.
> 
> Lorenzo Stoakes (16):
>   mm/shmem: update shmem to use mmap_prepare
>   device/dax: update devdax to use mmap_prepare
>   mm: add vma_desc_size(), vma_desc_pages() helpers
>   relay: update relay to use mmap_prepare
>   mm/vma: rename mmap internal functions to avoid confusion
>   mm: introduce the f_op->mmap_complete, mmap_abort hooks
>   doc: update porting, vfs documentation for mmap_[complete, abort]
>   mm: add remap_pfn_range_prepare(), remap_pfn_range_complete()
>   mm: introduce io_remap_pfn_range_prepare, complete
>   mm/hugetlb: update hugetlbfs to use mmap_prepare, mmap_complete
>   mm: update mem char driver to use mmap_prepare, mmap_complete
>   mm: update resctl to use mmap_prepare, mmap_complete, mmap_abort
>   mm: update cramfs to use mmap_prepare, mmap_complete
>   fs/proc: add proc_mmap_[prepare, complete] hooks for procfs
>   fs/proc: update vmcore to use .proc_mmap_[prepare, complete]
>   kcov: update kcov to use mmap_prepare, mmap_complete
> 
>  Documentation/filesystems/porting.rst |   9 ++
>  Documentation/filesystems/vfs.rst     |  35 +++++++
>  arch/csky/include/asm/pgtable.h       |   5 +
>  arch/mips/alchemy/common/setup.c      |  28 +++++-
>  arch/mips/include/asm/pgtable.h       |  10 ++
>  arch/s390/kernel/crash_dump.c         |   6 +-
>  arch/sparc/include/asm/pgtable_32.h   |  29 +++++-
>  arch/sparc/include/asm/pgtable_64.h   |  29 +++++-
>  drivers/char/mem.c                    |  80 ++++++++-------
>  drivers/dax/device.c                  |  32 +++---
>  fs/cramfs/inode.c                     | 134 ++++++++++++++++++--------
>  fs/hugetlbfs/inode.c                  |  86 +++++++++--------
>  fs/ntfs3/file.c                       |   2 +-
>  fs/proc/inode.c                       |  13 ++-
>  fs/proc/vmcore.c                      |  53 +++++++---
>  fs/resctrl/pseudo_lock.c              |  56 ++++++++---
>  include/linux/fs.h                    |   4 +
>  include/linux/mm.h                    |  53 +++++++++-
>  include/linux/mm_types.h              |   5 +
>  include/linux/proc_fs.h               |   5 +
>  include/linux/shmem_fs.h              |   3 +-
>  include/linux/vmalloc.h               |  10 +-
>  kernel/kcov.c                         |  40 +++++---
>  kernel/relay.c                        |  32 +++---
>  mm/memory.c                           | 128 +++++++++++++++---------
>  mm/secretmem.c                        |   2 +-
>  mm/shmem.c                            |  49 +++++++---
>  mm/util.c                             |  18 +++-
>  mm/vma.c                              |  96 +++++++++++++++---
>  mm/vmalloc.c                          |  16 ++-
>  tools/testing/vma/vma_internal.h      |  31 +++++-
>  31 files changed, 810 insertions(+), 289 deletions(-)
> 
> --
> 2.51.0
-- 
Jan Kara <jack@suse.com>
SUSE Labs, CR

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/tyoifr2ym3pzx4nwqhdwap57us3msusbsmql7do4pim5ku7qtm%40wjyvh5bs633s.
