Return-Path: <kasan-dev+bncBDXYDPH3S4OBBOOK66XAMGQEMY2TRAA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x537.google.com (mail-ed1-x537.google.com [IPv6:2a00:1450:4864:20::537])
	by mail.lfdr.de (Postfix) with ESMTPS id 75028869280
	for <lists+kasan-dev@lfdr.de>; Tue, 27 Feb 2024 14:35:54 +0100 (CET)
Received: by mail-ed1-x537.google.com with SMTP id 4fb4d7f45d1cf-558aafe9bf2sf4116144a12.1
        for <lists+kasan-dev@lfdr.de>; Tue, 27 Feb 2024 05:35:54 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1709040954; cv=pass;
        d=google.com; s=arc-20160816;
        b=k4Ur32BF9sWg28IjpE/SseWbdS9mDGM6wpfzkJ19M+YFXyQkr+kJ0uk9tNWdi6b8Uv
         JwbvytfSXgWnY1qd+7I1CqME0k5kW03G7HwEmuRj7OuXJ8v4Cw8krlzObIHBHrLFuLEk
         shwDow0As+XuBKBttddsAaA95BpxcA1FypC3BpreharSRlE8ytTZVW1S1DUGLGL1GeVx
         g9tW9x8B1bHjeX8BRwicBGpieZAXVZCHPu/DQgv87WFrXIniyXxp8vkiHIF9Ub5XxT0V
         sMYVcxXcEFjPWOElp2dimcQd1X5/D0u7TylkBoamkfo+PGIaTIVU7m9WPecT5fleFGQS
         g34g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=rXR88k4Ntu9eSdCTYhpvpqV5hkb0rWIst7Riz659xm8=;
        fh=zjKzkSVInTf2xyRLHAziRkB6Iy8N7LPkP2+Wlw0xaAM=;
        b=BdqQACtOPO2VP13DrtNQOwpotAOZMS5PgxxtbtJXup3WWN6P1PHHObm6EdgSYSG98+
         dEuWK1j0OsLWhz8s9ulgo9ijYdOn2ZuYjUA+xfoSODOuRUp8qzZ5RL2U7tUAzW5ur5u4
         tlsiZeHHKZ6KW6gqve8J7pgZp/3RLD2d+wOE/tcQZlRMjj7CuKa7Yd/vzUTtWfB6og1x
         rMFR7riJC9Sp675JI5hstTebJAp/ow9VS8POKNPUgMMonj/C/DLDVPFb9Ffcbce6qfga
         MX7wnZhXUIb0p5Vlcmdfm64jtF7VPMluqQi1T+0TgT63Sr6kqqRE4OKmE2vJ7Zu4lsRj
         RumA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=Si4g5Sei;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=Si4g5Sei;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1709040954; x=1709645754; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=rXR88k4Ntu9eSdCTYhpvpqV5hkb0rWIst7Riz659xm8=;
        b=jCGSSys4ZtZyk4Xf5yOoGqTq6VVO4vFbWIFiPLrvFx302dvC5pyr/IFAudMpoVryrD
         mcHuRIK0l3kROMfp/W/UqXLDWsKDN7QWuS1g50EuXQk9nlxU/jYwvQrU7O0IrVDE37A7
         WBvhpnNo2fMg3eb6PMMYf9q9FtpvDmZjXg0sScYbDoa00i+EW1E1BxU0lN4p0IEeeguA
         tQ/uPbErkiHQvozzVR+kRUpUDMSfyupL1mIQOifVpoBiVigj61Nw7A6iusJD7ssIlbqw
         vXtv3dmuOpHmRF+XuFfs6uzxTUSukaBNu3MlW/UUWMogyS8OZr+PK9MHOHKHCBHzEwvl
         xdMw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1709040954; x=1709645754;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=rXR88k4Ntu9eSdCTYhpvpqV5hkb0rWIst7Riz659xm8=;
        b=Hx+mg8LjY/fZCSjETFHQss/BVfZyqmv9snvtbL4rd++3SMhhSfHMCE+F0R8loecIB4
         EMxCnuAmeYo/Rl1s+Mbjgmhuccp2m2RWggCkX+d0HLTZqGDR8agBg9B6lPC1L8HPerAs
         OIeGQEo/j1c2UxTP6JYptabSuNWFIVb6veh6Q2eurg3BD+7wHOGpRSuZitE13LwrYtnq
         8F2JTRpjksvecQSGVYOVeMMY6aAqBSFubgjstqBlH3UfnJHb1nu/zTh8StD2fjLYZJDk
         edVvQ2VOImO21mPN2XsI53b3kmp2w+rcwjrsA/seRHdoGjc8TfjGRKimbTCMoAMhMfUO
         vgrQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVxy0t88Os2K0dlqPpp49EEa4NVAbonGvEgTRYJOPtgdyHX6/4WiTsPzEO27C/6jrtUU3POiVL2BFlPIXlyl6gatQJQlNJuNg==
X-Gm-Message-State: AOJu0Yy0CkSryXOqQ0mOB5pQUOJ23g230dv3UtwWxlAAj0q5LxKCmEkY
	/qCa46Vg+MVpm0HCfLURbX2Ecr48b0jGuu7sarYJrbQ8rez7Kp1x
X-Google-Smtp-Source: AGHT+IH6qYKG2vhCkfvwWW0ic/NGp50fRhX8xG/M2q7QthCNIPTxdtc9ivGhfSda5ZHHkffzp62Mig==
X-Received: by 2002:aa7:c697:0:b0:563:eca6:733c with SMTP id n23-20020aa7c697000000b00563eca6733cmr6676462edq.15.1709040953596;
        Tue, 27 Feb 2024 05:35:53 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:381b:b0:566:4ed2:65dd with SMTP id
 es27-20020a056402381b00b005664ed265ddls109655edb.2.-pod-prod-03-eu; Tue, 27
 Feb 2024 05:35:52 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUQNrprOOvi0YO5C//kKrkdg2jZTQF8BYfx9lhx+zecZPUUIg39TPHHXI3lAOHYMVEpxcRERWf7ALey7/rY8IFe64kuFIDf7GStsA==
X-Received: by 2002:a50:fb85:0:b0:566:4fdf:d819 with SMTP id e5-20020a50fb85000000b005664fdfd819mr308171edq.4.1709040951941;
        Tue, 27 Feb 2024 05:35:51 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1709040951; cv=none;
        d=google.com; s=arc-20160816;
        b=YoM6rR7/LDiJHutWXFZiT/AEkvswNAMTsbyhu60KnX/1ldT7JuJ6M6yQLtBwUDhSj9
         plleQdn0XPZ/G0GPyPnCGoWdtGqV3R1Dun/9AQnC7kcImPsgtYamuq4JSOE5T5FzTNBd
         HnlN3KCCSkNnF/EY5ddF46Y6EeE9x3gso8HjWqNypYogvolXuYkD1s13+a1G0ziKoj6q
         3uEmRG4/RIECEbgUgWoT1AhPt4A611RiIJ70tR3bQhcDykYbTIld7/zu8C7qFV3olD4I
         pKJm9Ugzm+sDE/ESAjYagVGY4vv0pbdxXXxr+spFypsw3UtygQJHJXN/oX8By7jwHnlE
         W5Ug==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature:dkim-signature:dkim-signature;
        bh=k1BLeq7Vl9qJ6EYRJ54haTpHogCVSh3EPlNJp9vn1oU=;
        fh=AROQU2KCH7NyZd+GSF5Ja6si3COSfc75C77I0os5n1k=;
        b=K89T46zEE/NirNfo1L/gY1jIdj2MHoQj63g5+TLS/Ypy3UQdLQ+COvb8YB43ls+/8Q
         YdMrOK5D/rSbDjUIVVVcLsTTT1uUT6fVzNZEbMbSWT5vX2MndB8CDvbcpTY+bf/kmUa2
         ZbRFxVIV8mfV9CzLXnnzTfuF3XebZuUG3nkchqUrYTnXlUWzFcWvBeRKttifeUtrFe0w
         56KurfcR9l3vtW0Zt668gpyyJBkCr18dEc13YL5KmLMIbm8V+/emGk2DmqzhrPgWTPIB
         suTgeDdVzTmCTfmiRFcrV1ALqmC3RDy95IQ0Ov/HEn+v/Kudr+ppdkwh/59YI+5v4NQf
         TTIg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=Si4g5Sei;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=Si4g5Sei;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [195.135.223.131])
        by gmr-mx.google.com with ESMTPS id bl20-20020a056402211400b005617c6b0e51si41073edb.4.2024.02.27.05.35.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 27 Feb 2024 05:35:51 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted sender) client-ip=195.135.223.131;
Received: from imap1.dmz-prg2.suse.org (imap1.dmz-prg2.suse.org [IPv6:2a07:de40:b281:104:10:150:64:97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id 5D9E61FD3E;
	Tue, 27 Feb 2024 13:35:51 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id 0512013A58;
	Tue, 27 Feb 2024 13:35:50 +0000 (UTC)
Received: from dovecot-director2.suse.de ([10.150.64.162])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id B094ADbl3WX2MAAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Tue, 27 Feb 2024 13:35:50 +0000
Message-ID: <67453a56-d4c2-4dc8-a5db-0a4665e40856@suse.cz>
Date: Tue, 27 Feb 2024 14:36:14 +0100
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v4 00/36] Memory allocation profiling
Content-Language: en-US
To: Suren Baghdasaryan <surenb@google.com>, akpm@linux-foundation.org
Cc: kent.overstreet@linux.dev, mhocko@suse.com, hannes@cmpxchg.org,
 roman.gushchin@linux.dev, mgorman@suse.de, dave@stgolabs.net,
 willy@infradead.org, liam.howlett@oracle.com,
 penguin-kernel@i-love.sakura.ne.jp, corbet@lwn.net, void@manifault.com,
 peterz@infradead.org, juri.lelli@redhat.com, catalin.marinas@arm.com,
 will@kernel.org, arnd@arndb.de, tglx@linutronix.de, mingo@redhat.com,
 dave.hansen@linux.intel.com, x86@kernel.org, peterx@redhat.com,
 david@redhat.com, axboe@kernel.dk, mcgrof@kernel.org, masahiroy@kernel.org,
 nathan@kernel.org, dennis@kernel.org, tj@kernel.org, muchun.song@linux.dev,
 rppt@kernel.org, paulmck@kernel.org, pasha.tatashin@soleen.com,
 yosryahmed@google.com, yuzhao@google.com, dhowells@redhat.com,
 hughd@google.com, andreyknvl@gmail.com, keescook@chromium.org,
 ndesaulniers@google.com, vvvvvv@google.com, gregkh@linuxfoundation.org,
 ebiggers@google.com, ytcoode@gmail.com, vincent.guittot@linaro.org,
 dietmar.eggemann@arm.com, rostedt@goodmis.org, bsegall@google.com,
 bristot@redhat.com, vschneid@redhat.com, cl@linux.com, penberg@kernel.org,
 iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com, glider@google.com,
 elver@google.com, dvyukov@google.com, shakeelb@google.com,
 songmuchun@bytedance.com, jbaron@akamai.com, rientjes@google.com,
 minchan@google.com, kaleshsingh@google.com, kernel-team@android.com,
 linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org,
 iommu@lists.linux.dev, linux-arch@vger.kernel.org,
 linux-fsdevel@vger.kernel.org, linux-mm@kvack.org,
 linux-modules@vger.kernel.org, kasan-dev@googlegroups.com,
 cgroups@vger.kernel.org
References: <20240221194052.927623-1-surenb@google.com>
From: Vlastimil Babka <vbabka@suse.cz>
In-Reply-To: <20240221194052.927623-1-surenb@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Spamd-Result: default: False [-1.80 / 50.00];
	 RCVD_VIA_SMTP_AUTH(0.00)[];
	 XM_UA_NO_VERSION(0.01)[];
	 SPAMHAUS_XBL(0.00)[2a07:de40:b281:104:10:150:64:97:from];
	 TO_DN_SOME(0.00)[];
	 R_RATELIMIT(0.00)[to_ip_from(RLcb476ir6xfzaroaj5pc7azzw)];
	 RCVD_COUNT_THREE(0.00)[3];
	 DKIM_TRACE(0.00)[suse.cz:+];
	 MX_GOOD(-0.01)[];
	 RCPT_COUNT_GT_50(0.00)[74];
	 FROM_EQ_ENVFROM(0.00)[];
	 MIME_TRACE(0.00)[0:+];
	 MID_RHS_MATCH_FROM(0.00)[];
	 BAYES_HAM(-3.00)[100.00%];
	 ARC_NA(0.00)[];
	 R_DKIM_ALLOW(-0.20)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	 FROM_HAS_DN(0.00)[];
	 FREEMAIL_ENVRCPT(0.00)[gmail.com];
	 TAGGED_RCPT(0.00)[];
	 MIME_GOOD(-0.10)[text/plain];
	 TO_MATCH_ENVRCPT_SOME(0.00)[];
	 DKIM_SIGNED(0.00)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	 DBL_BLOCKED_OPENRESOLVER(0.00)[suse.cz:dkim];
	 FUZZY_BLOCKED(0.00)[rspamd.com];
	 FREEMAIL_CC(0.00)[linux.dev,suse.com,cmpxchg.org,suse.de,stgolabs.net,infradead.org,oracle.com,i-love.sakura.ne.jp,lwn.net,manifault.com,redhat.com,arm.com,kernel.org,arndb.de,linutronix.de,linux.intel.com,kernel.dk,soleen.com,google.com,gmail.com,chromium.org,linuxfoundation.org,linaro.org,goodmis.org,linux.com,lge.com,bytedance.com,akamai.com,android.com,vger.kernel.org,lists.linux.dev,kvack.org,googlegroups.com];
	 RCVD_TLS_ALL(0.00)[];
	 SUSPICIOUS_RECIPS(1.50)[];
	 RBL_SPAMHAUS_BLOCKED_OPENRESOLVER(0.00)[2a07:de40:b281:104:10:150:64:97:from]
X-Rspamd-Server: rspamd1.dmz-prg2.suse.org
X-Rspamd-Queue-Id: 5D9E61FD3E
X-Spam-Level: 
X-Spam-Score: -1.80
X-Spam-Flag: NO
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=Si4g5Sei;       dkim=neutral
 (no key) header.i=@suse.cz header.s=susede2_ed25519;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=Si4g5Sei;       dkim=neutral
 (no key) header.i=@suse.cz header.s=susede2_ed25519;       spf=pass
 (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted
 sender) smtp.mailfrom=vbabka@suse.cz
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

On 2/21/24 20:40, Suren Baghdasaryan wrote:
> Overview:
> Low overhead [1] per-callsite memory allocation profiling. Not just for
> debug kernels, overhead low enough to be deployed in production.
> 
> Example output:
>   root@moria-kvm:~# sort -rn /proc/allocinfo
>    127664128    31168 mm/page_ext.c:270 func:alloc_page_ext
>     56373248     4737 mm/slub.c:2259 func:alloc_slab_page
>     14880768     3633 mm/readahead.c:247 func:page_cache_ra_unbounded
>     14417920     3520 mm/mm_init.c:2530 func:alloc_large_system_hash
>     13377536      234 block/blk-mq.c:3421 func:blk_mq_alloc_rqs
>     11718656     2861 mm/filemap.c:1919 func:__filemap_get_folio
>      9192960     2800 kernel/fork.c:307 func:alloc_thread_stack_node
>      4206592        4 net/netfilter/nf_conntrack_core.c:2567 func:nf_ct_alloc_hashtable
>      4136960     1010 drivers/staging/ctagmod/ctagmod.c:20 [ctagmod] func:ctagmod_start
>      3940352      962 mm/memory.c:4214 func:alloc_anon_folio
>      2894464    22613 fs/kernfs/dir.c:615 func:__kernfs_new_node
>      ...
> 
> Since v3:
>  - Dropped patch changing string_get_size() [2] as not needed
>  - Dropped patch modifying xfs allocators [3] as non needed,
>    per Dave Chinner
>  - Added Reviewed-by, per Kees Cook
>  - Moved prepare_slab_obj_exts_hook() and alloc_slab_obj_exts() where they
>    are used, per Vlastimil Babka
>  - Fixed SLAB_NO_OBJ_EXT definition to use unused bit, per Vlastimil Babka
>  - Refactored patch [4] into other patches, per Vlastimil Babka
>  - Replaced snprintf() with seq_buf_printf(), per Kees Cook
>  - Changed output to report bytes, per Andrew Morton and Pasha Tatashin
>  - Changed output to report [module] only for loadable modules,
>    per Vlastimil Babka
>  - Moved mem_alloc_profiling_enabled() check earlier, per Vlastimil Babka
>  - Changed the code to handle page splitting to be more understandable,
>    per Vlastimil Babka
>  - Moved alloc_tagging_slab_free_hook(), mark_objexts_empty(),
>    mark_failed_objexts_alloc() and handle_failed_objexts_alloc(),
>    per Vlastimil Babka
>  - Fixed loss of __alloc_size(1, 2) in kvmalloc functions,
>    per Vlastimil Babka
>  - Refactored the code in show_mem() to avoid memory allocations,
>    per Michal Hocko
>  - Changed to trylock in show_mem() to avoid blocking in atomic context,
>    per Tetsuo Handa
>  - Added mm mailing list into MAINTAINERS, per Kees Cook
>  - Added base commit SHA, per Andy Shevchenko
>  - Added a patch with documentation, per Jani Nikula
>  - Fixed 0day bugs
>  - Added benchmark results [5], per Steven Rostedt
>  - Rebased over Linux 6.8-rc5
> 
> Items not yet addressed:
>  - An early_boot option to prevent pageext overhead. We are looking into
>    ways for using the same sysctr instead of adding additional early boot
>    parameter.

I have reviewed the parts that integrate the tracking with page and slab
allocators, and besides some details to improve it seems ok to me. The
early boot option seems coming so that might eventually be suitable for
build-time enablement in a distro kernel.

The macros (and their potential spread to upper layers to keep the
information useful enough) are of course ugly, but guess it can't be
currently helped and I'm unable to decide whether it's worth it or not.
That's up to those providing their success stories I guess. If there's
at least a path ahead to replace that part with compiler support in the
future, great. So I'm not against merging this. BTW, do we know Linus's
opinion on the macros approach?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/67453a56-d4c2-4dc8-a5db-0a4665e40856%40suse.cz.
