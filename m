Return-Path: <kasan-dev+bncBCKMR55PYIGBB5FPW6XAMGQEL4UCCOQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53e.google.com (mail-ed1-x53e.google.com [IPv6:2a00:1450:4864:20::53e])
	by mail.lfdr.de (Postfix) with ESMTPS id E112A855DD6
	for <lists+kasan-dev@lfdr.de>; Thu, 15 Feb 2024 10:23:01 +0100 (CET)
Received: by mail-ed1-x53e.google.com with SMTP id 4fb4d7f45d1cf-5597da35ebbsf346857a12.2
        for <lists+kasan-dev@lfdr.de>; Thu, 15 Feb 2024 01:23:01 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1707988981; cv=pass;
        d=google.com; s=arc-20160816;
        b=fKos/wMZqNFvhgNsmPlyJ2YaPdVLtsCpVwWFIM9Uyr2L2tijDi1PYjMbd2NGUnFQ80
         mBB0Yv+xS1hYqQ4/6aEB/urjxKidxYmCu3k7XKz5Ah+/6CC8rJEjRxyvFUqMhQCHrdIN
         XtFnt1Db3HiofbIFsdlaAiNrjtA5r1kYcCphu+xbDVJlyDiiPbMW9Co/7R3kAhx+QABD
         NW5uXmHBQHuIzcDzfBKr+lZUyEwYX1Gl77ZdOLF6LARqJPGV2u8j835e0TaCKNhkSnNO
         PiYF7l2r7SojK7stMkEuu6Uu6FHOXX0CiC4xbbIVF6CciitA33Gyj547XP8g6n6r3DgF
         HjBg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=xgf7OPbuG9h5zutV7FyGvBOjgKj9X/YlRf8olQk6UJU=;
        fh=Q0x83mxwz7tJ7FvuJhVJXUI0HlhlJmaP8ox0HEhgp8U=;
        b=0BJdt+LhmAfUMNgQ3B+F0XTUOJ7tn6dDb5y1FQO6VGTM/W0kzT+MbMAQ07pA3cOwlz
         eVty2RXuNNlpEjlCA/JT5N1EvsDk4GIQ6JzJo3KYLcRy+hnNreOOov6fiMiSAuKpw3/K
         u24gRy2RzaJQ+uPHs8qL/4mbK1Mv4ott5CbFx7tsmZVZfc2XrcS7EE9kSRkIXBMdw+8z
         mKOdOQ4Lt+P2KEb5iXCmFCoe7qqgY+THFuvnX3rUNmKOeGLtd4smv74ClashYO/6fVF0
         OuYeA9eaI7XHm38n8n4PFcdyFHkRh+ZoL/onwsXA1+L47wieyY+hoAYFckwmKBz8+1pD
         1JBQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.com header.s=susede1 header.b=sfOAoS4D;
       dkim=pass header.i=@suse.com header.s=susede1 header.b=sfOAoS4D;
       spf=pass (google.com: domain of mhocko@suse.com designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) smtp.mailfrom=mhocko@suse.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=suse.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1707988981; x=1708593781; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=xgf7OPbuG9h5zutV7FyGvBOjgKj9X/YlRf8olQk6UJU=;
        b=ci+V+VNyjJtH2eXqLqV4RboJey6EsBEDgF8NTJoVSAXChN9Io1XX64ASG72AswggdF
         V6VogFG7E/OIHZloLFgYfGf5CfITKt8jHriQm8WHKfxZRA0KOhuNLrm9/3SYQA0u+8WW
         wlyv/HgG1nSkOBGu+BPuQS/9YVrok4ISPziIdwpPjOlwVIvvobjXGc55ybMAnNWLhwJ9
         db+Hbi88Av3GeLeH46XD8yRq1dPX50kM8T20BvxCNAuGWBj5fnm4LfPFnPSJlJhrzSeY
         hdptdCZU2afZwvBObNPGuHCekUr6yB/d7DhQPK9CG22L7ta5cnItFTYO9fWUD269j+Od
         Huog==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1707988981; x=1708593781;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=xgf7OPbuG9h5zutV7FyGvBOjgKj9X/YlRf8olQk6UJU=;
        b=Td5xmGFu8j172IQ2XhoLT8HZpLU8uTEUCPYpAlY0Cfaebj97xv1UbYazz46lLcIb3L
         w9vJmIkVBrRLGZJq2/iSx3ZjNBw0OV1+ENqGYbNFVi/tz1alR1vpjPtaHMaQ8zSqeCum
         fJ5NEzdJS6isgLQlUZd7pQr6K1KAGcFtOI/qmriz70bAc4MH2hPs/gi8HDn9b9J70gDn
         5zQYTwS7wWlMIgzwBo/YOyQ/AI34e+8868ikejrIUFkAePrTvaI1kLVk/gXiV0HOES0Q
         pcY0FMD3yWxthE5n6jyiNWrGWppgQfGH7u9PAhvDGC+vIdLYEsz4ZOo3+w+fvcvsag8d
         dFmA==
X-Forwarded-Encrypted: i=2; AJvYcCWxm8EawNxDw+oSZenDUEVhqxKOvuPaNVkkyza//OgwbwoQVe+QSVnXk32iDMkKAXIMSacz2yoBbJyElriS31q7iB/Hha5hvQ==
X-Gm-Message-State: AOJu0YwOq0hOrtfBuZWoxyvbBfHyLTQH8uCIxgVXhtuizj84NCgxRu9W
	V6f/OgdO7rZqRKbNQJQR7aKGzwFZQtyQ/cmvjm41/4O7zdY0GumZ
X-Google-Smtp-Source: AGHT+IGN5//ZZP/sNkaUsHFDTv3/pc2MJ5upKP6uGS7lBMB3P2D5FFp6fiGsizyOfSnh+/t5P81IPA==
X-Received: by 2002:a05:6402:742:b0:55f:c3c1:34e with SMTP id p2-20020a056402074200b0055fc3c1034emr907113edy.15.1707988980666;
        Thu, 15 Feb 2024 01:23:00 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:1241:b0:562:9650:48dd with SMTP id
 l1-20020a056402124100b00562965048ddls76505edw.0.-pod-prod-06-eu; Thu, 15 Feb
 2024 01:22:59 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVqxmI8RXFrqRmO9QlZgZ191stithGPVlpFpNQ/14D3rzgOvr9wbEXLs25MsQMlq13fkK07Epbebg6QHg+C8TDJTeDZx6NK3zEd2g==
X-Received: by 2002:a17:906:4544:b0:a3d:abd1:7035 with SMTP id s4-20020a170906454400b00a3dabd17035mr110507ejq.9.1707988978661;
        Thu, 15 Feb 2024 01:22:58 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1707988978; cv=none;
        d=google.com; s=arc-20160816;
        b=vREmdwQPOuQnLVzQBhLo0/hOwaqfm/f9goo+LSYW0j02msCf/dugaZl2T8vOH3XN4R
         /JVilRyEjtgPr5HsXqO2onDBU3XRKTGk3ewi+NQfXlW+iMyz2+OVv8EWFD9+xVGyDtPO
         npUkGuSMAbwaS9ttgZpszAIRG40dXereI+fX99nIBvZEGa/7ukboVPxkzwig7Xgg5awX
         mtFFSxjOxamWVNNIkaLoFeoim17Fwapno/I75YrBhfOBcATSjXEaq5QYuXILOSCJaDk8
         Ov0/R8Bh7LYQSuPDf2vfL/qwi191/PRrc86D9O2Fx+QDYpLGZSRk1bMuo6CK36U/HY5e
         QxAw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature:dkim-signature;
        bh=P0wAra6NNdsmQy/QOu3XOOm75y+sycyf1CReKWa3x/A=;
        fh=Ogq5Bz4Zz2qWMySoXrNTmv1uJW+gTwbteDGCKK45UbY=;
        b=uXiovKYDiViQwGhORal9pQ3NjLSZYcqCQt7WZjorIOv3AJ/n9JAcBjNy3CKkkD1IgH
         Fi64Iuu0UAuUxhLskBkDoHvPIZhCENbRC5kh4Ca0Ntfs7pFLMd6GAyLGrVeLGurz7K9+
         79HyTo3IPK+Oy1QT25SfsWSEmuFtGYh0wy6ZV2XNuOI463xU4LZ44LF1bABtfd44H6bH
         zpEPnyfKkMRtidHNwHmLgIICEX9H79dPqIccmVWZhjwUjShT9P6gIUnqUoXjeEjCaUbh
         0OYpKB0PWoDq57eIpKiyCMl9VXptJ1RHp7R9GsbE7HqAzTMcBy4SQ0Zq7hiK3wNbz7IH
         eU1g==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.com header.s=susede1 header.b=sfOAoS4D;
       dkim=pass header.i=@suse.com header.s=susede1 header.b=sfOAoS4D;
       spf=pass (google.com: domain of mhocko@suse.com designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) smtp.mailfrom=mhocko@suse.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=suse.com
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [2a07:de40:b251:101:10:150:64:1])
        by gmr-mx.google.com with ESMTPS id ne6-20020a1709077b8600b00a3d7c629a7asi28541ejc.1.2024.02.15.01.22.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 15 Feb 2024 01:22:58 -0800 (PST)
Received-SPF: pass (google.com: domain of mhocko@suse.com designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) client-ip=2a07:de40:b251:101:10:150:64:1;
Received: from imap1.dmz-prg2.suse.org (imap1.dmz-prg2.suse.org [IPv6:2a07:de40:b281:104:10:150:64:97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id 09D1621D8D;
	Thu, 15 Feb 2024 09:22:58 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id CED2B13A53;
	Thu, 15 Feb 2024 09:22:57 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id gyDbMfHXzWUfGQAAD6G6ig
	(envelope-from <mhocko@suse.com>); Thu, 15 Feb 2024 09:22:57 +0000
Date: Thu, 15 Feb 2024 10:22:57 +0100
From: "'Michal Hocko' via kasan-dev" <kasan-dev@googlegroups.com>
To: Suren Baghdasaryan <surenb@google.com>
Cc: akpm@linux-foundation.org, kent.overstreet@linux.dev, vbabka@suse.cz,
	hannes@cmpxchg.org, roman.gushchin@linux.dev, mgorman@suse.de,
	dave@stgolabs.net, willy@infradead.org, liam.howlett@oracle.com,
	corbet@lwn.net, void@manifault.com, peterz@infradead.org,
	juri.lelli@redhat.com, catalin.marinas@arm.com, will@kernel.org,
	arnd@arndb.de, tglx@linutronix.de, mingo@redhat.com,
	dave.hansen@linux.intel.com, x86@kernel.org, peterx@redhat.com,
	david@redhat.com, axboe@kernel.dk, mcgrof@kernel.org,
	masahiroy@kernel.org, nathan@kernel.org, dennis@kernel.org,
	tj@kernel.org, muchun.song@linux.dev, rppt@kernel.org,
	paulmck@kernel.org, pasha.tatashin@soleen.com,
	yosryahmed@google.com, yuzhao@google.com, dhowells@redhat.com,
	hughd@google.com, andreyknvl@gmail.com, keescook@chromium.org,
	ndesaulniers@google.com, vvvvvv@google.com,
	gregkh@linuxfoundation.org, ebiggers@google.com, ytcoode@gmail.com,
	vincent.guittot@linaro.org, dietmar.eggemann@arm.com,
	rostedt@goodmis.org, bsegall@google.com, bristot@redhat.com,
	vschneid@redhat.com, cl@linux.com, penberg@kernel.org,
	iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com, glider@google.com,
	elver@google.com, dvyukov@google.com, shakeelb@google.com,
	songmuchun@bytedance.com, jbaron@akamai.com, rientjes@google.com,
	minchan@google.com, kaleshsingh@google.com, kernel-team@android.com,
	linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org,
	iommu@lists.linux.dev, linux-arch@vger.kernel.org,
	linux-fsdevel@vger.kernel.org, linux-mm@kvack.org,
	linux-modules@vger.kernel.org, kasan-dev@googlegroups.com,
	cgroups@vger.kernel.org
Subject: Re: [PATCH v3 31/35] lib: add memory allocations report in show_mem()
Message-ID: <Zc3X8XlnrZmh2mgN@tiehlicka>
References: <20240212213922.783301-1-surenb@google.com>
 <20240212213922.783301-32-surenb@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20240212213922.783301-32-surenb@google.com>
X-Spam-Level: 
X-Spamd-Bar: /
X-Rspamd-Server: rspamd2.dmz-prg2.suse.org
X-Spamd-Result: default: False [0.38 / 50.00];
	 RCVD_VIA_SMTP_AUTH(0.00)[];
	 SPAMHAUS_XBL(0.00)[2a07:de40:b281:104:10:150:64:97:from];
	 TO_DN_SOME(0.00)[];
	 R_RATELIMIT(0.00)[to_ip_from(RLm3b7rx1h7ydj1zd5jb4wbfas)];
	 RCVD_COUNT_THREE(0.00)[3];
	 DKIM_TRACE(0.00)[suse.com:+];
	 MX_GOOD(-0.01)[];
	 RCPT_COUNT_GT_50(0.00)[73];
	 NEURAL_HAM_SHORT(-0.20)[-1.000];
	 FROM_EQ_ENVFROM(0.00)[];
	 MIME_TRACE(0.00)[0:+];
	 BAYES_HAM(-0.11)[66.22%];
	 ARC_NA(0.00)[];
	 R_DKIM_ALLOW(-0.20)[suse.com:s=susede1];
	 FROM_HAS_DN(0.00)[];
	 FREEMAIL_ENVRCPT(0.00)[gmail.com];
	 NEURAL_HAM_LONG(-1.00)[-1.000];
	 TAGGED_RCPT(0.00)[];
	 MIME_GOOD(-0.10)[text/plain];
	 TO_MATCH_ENVRCPT_SOME(0.00)[];
	 DKIM_SIGNED(0.00)[suse.com:s=susede1];
	 DBL_BLOCKED_OPENRESOLVER(0.00)[suse.com:dkim];
	 FUZZY_BLOCKED(0.00)[rspamd.com];
	 MID_RHS_NOT_FQDN(0.50)[];
	 FREEMAIL_CC(0.00)[linux-foundation.org,linux.dev,suse.cz,cmpxchg.org,suse.de,stgolabs.net,infradead.org,oracle.com,lwn.net,manifault.com,redhat.com,arm.com,kernel.org,arndb.de,linutronix.de,linux.intel.com,kernel.dk,soleen.com,google.com,gmail.com,chromium.org,linuxfoundation.org,linaro.org,goodmis.org,linux.com,lge.com,bytedance.com,akamai.com,android.com,vger.kernel.org,lists.linux.dev,kvack.org,googlegroups.com];
	 RCVD_TLS_ALL(0.00)[];
	 SUSPICIOUS_RECIPS(1.50)[]
X-Spam-Score: 0.38
X-Rspamd-Queue-Id: 09D1621D8D
X-Spam-Flag: NO
X-Original-Sender: mhocko@suse.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.com header.s=susede1 header.b=sfOAoS4D;       dkim=pass
 header.i=@suse.com header.s=susede1 header.b=sfOAoS4D;       spf=pass
 (google.com: domain of mhocko@suse.com designates 2a07:de40:b251:101:10:150:64:1
 as permitted sender) smtp.mailfrom=mhocko@suse.com;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=suse.com
X-Original-From: Michal Hocko <mhocko@suse.com>
Reply-To: Michal Hocko <mhocko@suse.com>
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

On Mon 12-02-24 13:39:17, Suren Baghdasaryan wrote:
[...]
> @@ -423,4 +424,18 @@ void __show_mem(unsigned int filter, nodemask_t *nodemask, int max_zone_idx)
>  #ifdef CONFIG_MEMORY_FAILURE
>  	printk("%lu pages hwpoisoned\n", atomic_long_read(&num_poisoned_pages));
>  #endif
> +#ifdef CONFIG_MEM_ALLOC_PROFILING
> +	{
> +		struct seq_buf s;
> +		char *buf = kmalloc(4096, GFP_ATOMIC);
> +
> +		if (buf) {
> +			printk("Memory allocations:\n");
> +			seq_buf_init(&s, buf, 4096);
> +			alloc_tags_show_mem_report(&s);
> +			printk("%s", buf);
> +			kfree(buf);
> +		}
> +	}
> +#endif

I am pretty sure I have already objected to this. Memory allocations in
the oom path are simply no go unless there is absolutely no other way
around that. In this case the buffer could be preallocated.

-- 
Michal Hocko
SUSE Labs

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/Zc3X8XlnrZmh2mgN%40tiehlicka.
