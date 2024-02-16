Return-Path: <kasan-dev+bncBDXYDPH3S4OBB2WGXSXAMGQEVXKID5A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13e.google.com (mail-lf1-x13e.google.com [IPv6:2a00:1450:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id 231F8857832
	for <lists+kasan-dev@lfdr.de>; Fri, 16 Feb 2024 09:57:16 +0100 (CET)
Received: by mail-lf1-x13e.google.com with SMTP id 2adb3069b0e04-51169a55bddsf1626264e87.0
        for <lists+kasan-dev@lfdr.de>; Fri, 16 Feb 2024 00:57:16 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1708073835; cv=pass;
        d=google.com; s=arc-20160816;
        b=0TQDAV84xrpQ4q3quuU5HGwISvTnaZBLwhS9GyBaoWtz/amydJHpLV7BcwuiLxj0/c
         oG+nXVbQSF0dQStExoXTm0jOeH+rFEdjFFyxSqlQsXSO3M+MwqZe6J6Upvp7cC76HYIV
         M/AvWeAn5HqFZDdPTeGLJlKa0a4K1CeIcrxBXK2lC7098oFXU444dcgMIHMjXyP5WGrY
         z0cizPLJeNUCWdE6OX5SHfibOPinSgewvQhntLQXY6cpDPEjR8n2NSH/WA0omYjuVROc
         c0TWW+ICZO1Pl3xkrqDJs80Ziqt2ta34WJZtSWv0UYGaXIAFLCXsA4QYHZAQho6BrNMz
         R4hQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=OHzoZu4QXXsKV8zlnKhT0CJ7JOBSe+GddgtJdxS6oCE=;
        fh=iA4p4sctoGzzAV5mTqACgsh2YIRm6cSkMMSoiW7hpFA=;
        b=CtSueiK3S0usW67Mq07R34kJBz3KMIrdSfphKMCGZATgtmvLeBZN6erx688RdcbiHc
         Qugd6dvXernqYzQejznF/Kf6Mmntihn8lkJumP2ZcdUGQATWN/zaTkyY1GnVY94ws6ia
         zG8JJzO9fs5oTc5ygkrq3mw7HihV3OvV9dy63jO07F4xHd1FZz6xbYkXuYfGlqpZ60ai
         8zKSUiVRTQQsqqN8xpbQmE9QXDsJ9fkl7I+kHZwuxVt9oQwMnYQHNKNrSGrdmJi//x6F
         84jH6KOxE/eUgCws/p3UuyrV6MUQCFga2ZycB3wrXshLZSKxzXPa6tUdteg5mkS4+HZG
         d2BQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=xqZAC8Nf;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=o6dFJHJY;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1708073835; x=1708678635; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=OHzoZu4QXXsKV8zlnKhT0CJ7JOBSe+GddgtJdxS6oCE=;
        b=YrFd1EmLqj8/ZBwgQxg4kDz0pBhTRdjFLjlNwFNpyBe7s1VpCsYEDOZqD460Gis7IQ
         MYehgUJjXyZ/OlN4CLW1yDC+B+wHOGVYeVTPRzAYG9Iv4wHiduLy47IRDj5wVtQNwEku
         9JoEi+LjQfWfVc1HJZtK7OzDXaX/yGSkNDWFE7Um3LA+gkBLxl1ZL6wSvOltPmYNrdP5
         UJiXu52ZlbF7kw+MTwF8tYrUvhI45AQBhR/lZKiy6XsI2zCS+ojsO+21U54vDkRfaJsJ
         s79XOzbTVt0VP2rMe9k11cuoofWGhb+VB7EBK7RNYOBBT48WBStzgdCO4LKlh0ZsaHYG
         wAIA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1708073835; x=1708678635;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=OHzoZu4QXXsKV8zlnKhT0CJ7JOBSe+GddgtJdxS6oCE=;
        b=RBANavpOYQ8qJA2bvOUrLEczqBLl3S/rzjcDsyOXB63JAFdZvJQ2QSceEe8bEMFkJC
         GhOYG4yTDzeEbULO8aasQqLCBHTROTF9tEaZ3oeO70xe05BiK4RjpLIk3Xx2W5PcrPdL
         vuoRl6S9dH2lsJUqntj9ciwVBwc2wab4UMM8/ZDYj2vVJ8Jv0fmNMRbZQEAWCR+AA72/
         G8ReH2Xq2N8H0cJqWjlN1g5DmwSiKJvSYDlF1j/AJZO3iWea+8GGcpqZJclRi5ncA28Y
         ryW2Jr/93sBmpYetLsZ6juqHWEtyprL5WEIb7Wj3THjaZbVJj6ZEM9fUYOSPnbZeAT4n
         WT+A==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUijW5OiMY/fKJnQoAAramj9JGbb31yylr0Bs+aievcpwqyvRkrztRgStbcC77FbamGp+ecbeDq5UZuWMAuPuMHIzhnTpNa7w==
X-Gm-Message-State: AOJu0YynCRvXByUIRC2KirOtlkNMtqxbpoNGr05KvQOESGvfF47JtV8/
	AkZz4JKXwHGJZy0coWp3ZJR8eNaydEfZyN7HRMIz0M10C/+TpbkA
X-Google-Smtp-Source: AGHT+IHplEA+6MR+eOrqJhYZVOcaHdO/UnbnDrO00afphAAlHmGTNhOkMLlnx5AKEPxllFYwh6yu9A==
X-Received: by 2002:a19:2d06:0:b0:511:8e4b:e4d4 with SMTP id k6-20020a192d06000000b005118e4be4d4mr3308121lfj.21.1708073835044;
        Fri, 16 Feb 2024 00:57:15 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:2355:b0:511:5b43:6c1b with SMTP id
 p21-20020a056512235500b005115b436c1bls334014lfu.2.-pod-prod-08-eu; Fri, 16
 Feb 2024 00:57:13 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWe5M+WHdSNVBEAdRWcsoFb1cfI7R9biA/Ea4kgjJIfSpR6Yyqtai5ztteAaqPV/u3NjqUGZtc65cAPZ7NhdpTUTSAwE71yakqAjQ==
X-Received: by 2002:a19:3803:0:b0:511:8cb1:7c9d with SMTP id f3-20020a193803000000b005118cb17c9dmr3016185lfa.24.1708073832752;
        Fri, 16 Feb 2024 00:57:12 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1708073832; cv=none;
        d=google.com; s=arc-20160816;
        b=wJcvnos02+0Tz6RDi+1bkkKHHWbjDLMT77TiTs0bcfzc+F1JVYpvag4W49x9OAm3bp
         4KyFU4N1tTyBTxR3Ig6DxHNk+LESh9vC7lNHUzWhU7tUl3OHJWMpgDRpQP7u7+iNuNLV
         7HGk6caC0PSZNBUb67pt4OoINJvHepDz8Y19tPxv9utihstyIx3+39dbFy0eR4EO63fa
         yAPzuONCIDt/h5ce0FgFUymhCYgg+1SoWwvZdcxDbqBc1HYW78pjJG5XhZ7xlyIIhD5d
         jKAXCbcnauxg8JgkqQTZ/YOPTcBf4tkz0PS3MsT5enrzJ3oFHQT4PUbCEGsELCD9V1BX
         679Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature:dkim-signature:dkim-signature;
        bh=6frag4EZ1jOwLxH7IawG8bVTXT73kvKmKsBZp1SHOo0=;
        fh=QRwoHi5AHykrsPeo9uUZ+S24npSTFJROfKJSvxyXrPg=;
        b=TmnhIay9YCb+eOq9QZGSHpVbwqALmr1pSHcFgsVCcc8hN8/y/0GWRpQPIVrHcgjiT8
         gpq2iTDNsEQ3Qi3wXA+pSI2Ex40wM/ppdHDIsfQjDETxoF8pFR2l3IvINNQyxwWpk9CK
         jUU0lZpt+OH9yJ+2TfQIhLSjfxnm9MqOiqQYaF1UjyCDvAyZkypWRINOZo9ltTDKduHw
         o0GeTJvY6DaWzyx3s6pyT3Njp5L5QVkoFe4xb4Wpt/Vl825f+Rp3AmFWzJpoA8NNMCBJ
         B24RiMo5qowiyQjBzmPBFAM9K+0rjDkWBDbED3BL8CJDv8qhbbuwqYcJRf//4B8ycMq5
         gPsQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=xqZAC8Nf;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=o6dFJHJY;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [195.135.223.131])
        by gmr-mx.google.com with ESMTPS id f12-20020a0565123b0c00b0051183785260si103736lfv.4.2024.02.16.00.57.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 16 Feb 2024 00:57:12 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted sender) client-ip=195.135.223.131;
Received: from imap1.dmz-prg2.suse.org (imap1.dmz-prg2.suse.org [IPv6:2a07:de40:b281:104:10:150:64:97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id BDE1A1FB4A;
	Fri, 16 Feb 2024 08:57:10 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id 309BB13A67;
	Fri, 16 Feb 2024 08:57:10 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id hBNOC2Yjz2U1ZQAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Fri, 16 Feb 2024 08:57:10 +0000
Message-ID: <f92ad1e3-2dde-4db2-9b76-96c6bbc6a208@suse.cz>
Date: Fri, 16 Feb 2024 09:57:09 +0100
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v3 13/35] lib: add allocation tagging support for memory
 allocation profiling
Content-Language: en-US
To: Suren Baghdasaryan <surenb@google.com>, akpm@linux-foundation.org
Cc: kent.overstreet@linux.dev, mhocko@suse.com, hannes@cmpxchg.org,
 roman.gushchin@linux.dev, mgorman@suse.de, dave@stgolabs.net,
 willy@infradead.org, liam.howlett@oracle.com, corbet@lwn.net,
 void@manifault.com, peterz@infradead.org, juri.lelli@redhat.com,
 catalin.marinas@arm.com, will@kernel.org, arnd@arndb.de, tglx@linutronix.de,
 mingo@redhat.com, dave.hansen@linux.intel.com, x86@kernel.org,
 peterx@redhat.com, david@redhat.com, axboe@kernel.dk, mcgrof@kernel.org,
 masahiroy@kernel.org, nathan@kernel.org, dennis@kernel.org, tj@kernel.org,
 muchun.song@linux.dev, rppt@kernel.org, paulmck@kernel.org,
 pasha.tatashin@soleen.com, yosryahmed@google.com, yuzhao@google.com,
 dhowells@redhat.com, hughd@google.com, andreyknvl@gmail.com,
 keescook@chromium.org, ndesaulniers@google.com, vvvvvv@google.com,
 gregkh@linuxfoundation.org, ebiggers@google.com, ytcoode@gmail.com,
 vincent.guittot@linaro.org, dietmar.eggemann@arm.com, rostedt@goodmis.org,
 bsegall@google.com, bristot@redhat.com, vschneid@redhat.com, cl@linux.com,
 penberg@kernel.org, iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com,
 glider@google.com, elver@google.com, dvyukov@google.com,
 shakeelb@google.com, songmuchun@bytedance.com, jbaron@akamai.com,
 rientjes@google.com, minchan@google.com, kaleshsingh@google.com,
 kernel-team@android.com, linux-doc@vger.kernel.org,
 linux-kernel@vger.kernel.org, iommu@lists.linux.dev,
 linux-arch@vger.kernel.org, linux-fsdevel@vger.kernel.org,
 linux-mm@kvack.org, linux-modules@vger.kernel.org,
 kasan-dev@googlegroups.com, cgroups@vger.kernel.org
References: <20240212213922.783301-1-surenb@google.com>
 <20240212213922.783301-14-surenb@google.com>
From: Vlastimil Babka <vbabka@suse.cz>
In-Reply-To: <20240212213922.783301-14-surenb@google.com>
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
	 RCPT_COUNT_GT_50(0.00)[73];
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
	 DBL_BLOCKED_OPENRESOLVER(0.00)[linux.dev:email,suse.cz:dkim];
	 FUZZY_BLOCKED(0.00)[rspamd.com];
	 FREEMAIL_CC(0.00)[linux.dev,suse.com,cmpxchg.org,suse.de,stgolabs.net,infradead.org,oracle.com,lwn.net,manifault.com,redhat.com,arm.com,kernel.org,arndb.de,linutronix.de,linux.intel.com,kernel.dk,soleen.com,google.com,gmail.com,chromium.org,linuxfoundation.org,linaro.org,goodmis.org,linux.com,lge.com,bytedance.com,akamai.com,android.com,vger.kernel.org,lists.linux.dev,kvack.org,googlegroups.com];
	 RCVD_TLS_ALL(0.00)[];
	 SUSPICIOUS_RECIPS(1.50)[]
X-Rspamd-Server: rspamd1.dmz-prg2.suse.org
X-Rspamd-Queue-Id: BDE1A1FB4A
X-Spam-Level: 
X-Spam-Score: -1.80
X-Spam-Flag: NO
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=xqZAC8Nf;       dkim=neutral
 (no key) header.i=@suse.cz header.s=susede2_ed25519;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=o6dFJHJY;       dkim=neutral
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

On 2/12/24 22:38, Suren Baghdasaryan wrote:
> Introduce CONFIG_MEM_ALLOC_PROFILING which provides definitions to easily
> instrument memory allocators. It registers an "alloc_tags" codetag type
> with /proc/allocinfo interface to output allocation tag information when
> the feature is enabled.
> CONFIG_MEM_ALLOC_PROFILING_DEBUG is provided for debugging the memory
> allocation profiling instrumentation.
> Memory allocation profiling can be enabled or disabled at runtime using
> /proc/sys/vm/mem_profiling sysctl when CONFIG_MEM_ALLOC_PROFILING_DEBUG=n.
> CONFIG_MEM_ALLOC_PROFILING_ENABLED_BY_DEFAULT enables memory allocation
> profiling by default.
> 
> Signed-off-by: Suren Baghdasaryan <surenb@google.com>
> Co-developed-by: Kent Overstreet <kent.overstreet@linux.dev>
> Signed-off-by: Kent Overstreet <kent.overstreet@linux.dev>
> ---
>  Documentation/admin-guide/sysctl/vm.rst |  16 +++
>  Documentation/filesystems/proc.rst      |  28 +++++
>  include/asm-generic/codetag.lds.h       |  14 +++
>  include/asm-generic/vmlinux.lds.h       |   3 +
>  include/linux/alloc_tag.h               | 133 ++++++++++++++++++++
>  include/linux/sched.h                   |  24 ++++
>  lib/Kconfig.debug                       |  25 ++++
>  lib/Makefile                            |   2 +
>  lib/alloc_tag.c                         | 158 ++++++++++++++++++++++++
>  scripts/module.lds.S                    |   7 ++
>  10 files changed, 410 insertions(+)
>  create mode 100644 include/asm-generic/codetag.lds.h
>  create mode 100644 include/linux/alloc_tag.h
>  create mode 100644 lib/alloc_tag.c
> 
> diff --git a/Documentation/admin-guide/sysctl/vm.rst b/Documentation/admin-guide/sysctl/vm.rst
> index c59889de122b..a214719492ea 100644
> --- a/Documentation/admin-guide/sysctl/vm.rst
> +++ b/Documentation/admin-guide/sysctl/vm.rst
> @@ -43,6 +43,7 @@ Currently, these files are in /proc/sys/vm:
>  - legacy_va_layout
>  - lowmem_reserve_ratio
>  - max_map_count
> +- mem_profiling         (only if CONFIG_MEM_ALLOC_PROFILING=y)
>  - memory_failure_early_kill
>  - memory_failure_recovery
>  - min_free_kbytes
> @@ -425,6 +426,21 @@ e.g., up to one or two maps per allocation.
>  The default value is 65530.
>  
>  
> +mem_profiling
> +==============
> +
> +Enable memory profiling (when CONFIG_MEM_ALLOC_PROFILING=y)
> +
> +1: Enable memory profiling.
> +
> +0: Disabld memory profiling.

      Disable

...

> +allocinfo
> +~~~~~~~
> +
> +Provides information about memory allocations at all locations in the code
> +base. Each allocation in the code is identified by its source file, line
> +number, module and the function calling the allocation. The number of bytes
> +allocated at each location is reported.

See, it even says "number of bytes" :)

> +
> +Example output.
> +
> +::
> +
> +    > cat /proc/allocinfo
> +
> +      153MiB     mm/slub.c:1826 module:slub func:alloc_slab_page

Is "module" meant in the usual kernel module sense? In that case IIRC is
more common to annotate things e.g. [xfs] in case it's really a module, and
nothing if it's built it, such as slub. Is that "slub" simply derived from
"mm/slub.c"? Then it's just redundant?

> +     6.08MiB     mm/slab_common.c:950 module:slab_common func:_kmalloc_order
> +     5.09MiB     mm/memcontrol.c:2814 module:memcontrol func:alloc_slab_obj_exts
> +     4.54MiB     mm/page_alloc.c:5777 module:page_alloc func:alloc_pages_exact
> +     1.32MiB     include/asm-generic/pgalloc.h:63 module:pgtable func:__pte_alloc_one
> +     1.16MiB     fs/xfs/xfs_log_priv.h:700 module:xfs func:xlog_kvmalloc
> +     1.00MiB     mm/swap_cgroup.c:48 module:swap_cgroup func:swap_cgroup_prepare
> +      734KiB     fs/xfs/kmem.c:20 module:xfs func:kmem_alloc
> +      640KiB     kernel/rcu/tree.c:3184 module:tree func:fill_page_cache_func
> +      640KiB     drivers/char/virtio_console.c:452 module:virtio_console func:alloc_buf
> +      ...
> +
> +
>  meminfo

...

> diff --git a/lib/Kconfig.debug b/lib/Kconfig.debug
> index 0be2d00c3696..78d258ca508f 100644
> --- a/lib/Kconfig.debug
> +++ b/lib/Kconfig.debug
> @@ -972,6 +972,31 @@ config CODE_TAGGING
>  	bool
>  	select KALLSYMS
>  
> +config MEM_ALLOC_PROFILING
> +	bool "Enable memory allocation profiling"
> +	default n
> +	depends on PROC_FS
> +	depends on !DEBUG_FORCE_WEAK_PER_CPU
> +	select CODE_TAGGING
> +	help
> +	  Track allocation source code and record total allocation size
> +	  initiated at that code location. The mechanism can be used to track
> +	  memory leaks with a low performance and memory impact.
> +
> +config MEM_ALLOC_PROFILING_ENABLED_BY_DEFAULT
> +	bool "Enable memory allocation profiling by default"
> +	default y

I'd go with default n as that I'd select for a general distro.

> +	depends on MEM_ALLOC_PROFILING
> +
> +config MEM_ALLOC_PROFILING_DEBUG
> +	bool "Memory allocation profiler debugging"
> +	default n
> +	depends on MEM_ALLOC_PROFILING
> +	select MEM_ALLOC_PROFILING_ENABLED_BY_DEFAULT
> +	help
> +	  Adds warnings with helpful error messages for memory allocation
> +	  profiling.
> +

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/f92ad1e3-2dde-4db2-9b76-96c6bbc6a208%40suse.cz.
