Return-Path: <kasan-dev+bncBCKMR55PYIGBBMHU3SXAMGQEPUQMIYQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x238.google.com (mail-lj1-x238.google.com [IPv6:2a00:1450:4864:20::238])
	by mail.lfdr.de (Postfix) with ESMTPS id DB4D085F7C6
	for <lists+kasan-dev@lfdr.de>; Thu, 22 Feb 2024 13:12:34 +0100 (CET)
Received: by mail-lj1-x238.google.com with SMTP id 38308e7fff4ca-2d243ef274esf35691791fa.1
        for <lists+kasan-dev@lfdr.de>; Thu, 22 Feb 2024 04:12:34 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1708603954; cv=pass;
        d=google.com; s=arc-20160816;
        b=vjDGE8DhBWcrOtaHzJKLiboNv4ff/zCbYPhn7Brn5UQiZTkzX33OT7usjDEKbiJRhA
         zXziv3BQab7MuvGM1obXldchWRkJjt4PbvcoILdHrYxEVq9ZbTcUn1VA2oKUf9F09BdV
         +K7NVcTK0IBXynxRCNz6Jt2puPur8WDbFxpbmGKr0rngbCdHTXcn5GuiZaXxUyZ1zb39
         AZSPBxpe6uyHzyVEdNMuWLwVo9eJ08jrCcgW/s8Rcdn5l2XRpQbNyH2UcWj8HT6hGmqg
         E9ZkWCtzANgOHpAS966pxow6ibSFAOh5GUtGv6+q4cT0Z1QUUIK+yS8R40nInXfH+W1j
         zC0A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:dkim-signature;
        bh=k9w/dZ9rAAcUIcupSD89bXOrvFwxRHAVGT49dScROY0=;
        fh=Nrj7y/kcvWb9OOduK1CJcbiFgh5dYzai6B6VuYk0u8A=;
        b=k0Fwj7R0dCEmOuJkdX9KH9O/keeGpUydXApMB0CR8eDZ5vhy0wmEKZNQ6YSG+diuri
         5FMpYGHS4VfWMcI0d/tjUnxLgUG7DZb6sqnzSWabaNfQXgYcB+60Iyra9c9GwZj2mOBp
         huL+cL3prr3p7LFz70sthhhVUSereMoiGMHvTaMr9o1e/In5gA4ac4m9rtQMsI28E84Z
         rCtIV+9LxA0MK4jZBScvgtXGke9OYr/k7An72DTexvVNTAmQbXGkfpNOc5JM2ocmLOjH
         W9bh4MwNVgiVRrxJp/lUgHjT4S2K35cT12pxQYzyK96YPiw6MVzOBp6xsf2qDSENC5Bw
         NzQA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.com header.s=susede1 header.b=FE4RHYf6;
       dkim=pass header.i=@suse.com header.s=susede1 header.b=nU7WDITh;
       spf=pass (google.com: domain of mhocko@suse.com designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) smtp.mailfrom=mhocko@suse.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=suse.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1708603954; x=1709208754; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:from:to:cc:subject
         :date:message-id:reply-to;
        bh=k9w/dZ9rAAcUIcupSD89bXOrvFwxRHAVGT49dScROY0=;
        b=JoYBRc8C2NVQyn0CW7III714yIYio/To5jhtXUwk6X5m3JvohzBGec/UtXIPehSWNb
         Rnkahxy3uG8HlSnnT0peeRavo6oQMa2Zszuqj6+kLPM5ETXYcmVMg2aa67f3O7VF/ES/
         UN8uqzYdbWT4AwVhyY91Xf1+w1vLpWlyFRsW7X/Ga2SL7bXQtZq3IBS1V9P8VN0rB0A4
         WZXw1eviXJ8enbtiAifXVBCFduApAr23Bumhi9bXMW1pa01F8dpWaRqkSAYrCIRfPRxU
         fwNKr8o2NkUjgAbDV67aHSyv+qvDiNMmtVMV+NA/7RWMp7nJlhzl8sIMz4NTNvi75IaI
         Ulbg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1708603954; x=1709208754;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=k9w/dZ9rAAcUIcupSD89bXOrvFwxRHAVGT49dScROY0=;
        b=c0sJGV0lKiD/gI31RycTgkhpRkpTVTu99hVWh5pM+V+klCBuTOqF9XxcvpxTrFjTd3
         ENSsTdXHQXPpORfVmUqbLKd5OvakMjQrAJtZ8y16BE++bVQt4I/bDs0v3m6QdF3RyExY
         smB0vfdMb3yvGCGR4fk3lSrMqVVHlJfptUABQHRPs/dkMNjPe7WiTdkQqXdMyvTk179Z
         zGKmSvRvaQctu+tizpni/En3IvFNB9M2KgUQ9hTMTbWmp5crpcokz0x6gE/NUIna3jq6
         +7p5On+26rQxHoCrUANorsGp5NDiFdhecwGr/vEFHF2C2xLF2z8lgB+7RF6i6B0RCjiW
         I4CQ==
X-Forwarded-Encrypted: i=2; AJvYcCXl1wrhf7K/K9HnFpeMmfprkiKlEhQJynX7FiAnisb2KvuB+AV24GVPEwC5GNzQ/vy8PcvHvjEHiOjaQgvJo81BwCunCKs2mg==
X-Gm-Message-State: AOJu0YzSxla3mT7JlSRcsBvyqVR9hc++5TMpViObeICXBKZ10CzaE2ws
	2naMHsaNrPexWH7HqwnBbBvtOXTSVcnGuGd+2SNH5uvTqHRSLArWwGE=
X-Google-Smtp-Source: AGHT+IEl7JCy6or6+Xo9c+5YUOtSb55fkBshYB06/KOu276cBZE1U1HtW80NAs5ZaKP97gtlqQgr5A==
X-Received: by 2002:a05:651c:b1f:b0:2d2:36ae:46a0 with SMTP id b31-20020a05651c0b1f00b002d236ae46a0mr9981366ljr.53.1708603952772;
        Thu, 22 Feb 2024 04:12:32 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:b74c:0:b0:2d2:451b:7a95 with SMTP id k12-20020a2eb74c000000b002d2451b7a95ls36804ljo.2.-pod-prod-08-eu;
 Thu, 22 Feb 2024 04:12:30 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUQ8SiLbe2hqbnXF+Ge1c06qejAwjJcCyxBT5kCK7Zaz0HfKarUbbw9OyoJQlM2RUaVLad2nFTzKazwMDlIiXb6CDTQLCISfYAoIw==
X-Received: by 2002:a05:651c:210:b0:2d2:42ff:483c with SMTP id y16-20020a05651c021000b002d242ff483cmr6283331ljn.33.1708603950553;
        Thu, 22 Feb 2024 04:12:30 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1708603950; cv=none;
        d=google.com; s=arc-20160816;
        b=Cj6gErNxrK6drCoTz6uZojnrMjUsh22vyEkivjmGAJhwoHIk0NOPULNR57dpVmz0qs
         MA9GodkF+bBii+i1KFMxpZI5KfbdbaeumFAfPZNxe8RtZ7ScBq7rUuKzIi72eOzWLjai
         THeBWUvljUNs2hZ1fbzGCTXdsBiKV9BkS1NmxvagDqgQSCER5pnAwHwKXobqheiQ+Y/C
         lbHh6GfQGKPK63tBXil8p7LTJN1nXDJRtbuihWenhL+kgPdHK2tKIvrV7Jz8Xi0Iw+q8
         kuVaQYjWEh+1M/24U2yXMauOv/OE4f4znPumn8hjDIaKMCmhOmY5F6gG6JVxwuao/D9M
         BwHg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date
         :dkim-signature:dkim-signature;
        bh=iDZS9rn1ORcB7JdPkuWo18rKAM4Uqo344IyJ6OSxvyU=;
        fh=Uv1Qjn8qwzHTZ90qIvfQWmAIrV9KYTXOePbvM/Nk5uc=;
        b=olvRBvm9/TzUvuXZs/hBVCMQ+BF8hV7Z33s+hJOb7vjs2LmffS+7YyxYQ9smaaBR6q
         DnhnC00rwGdWUCl66R27xdF9mWrtne6JhDV7f4wjSOOMLNhlfWqWP9yVKz+fWVt3PEVt
         SYwsL6Qzxeb+5Na55BRQiLiWNNHzHYjeO0h+YlzjkTOnWWj8pLbELK1RxKPHcHRscTc4
         WRp4HbKxHlYi14f8G/Z08NgToCIKUZYOZxa84i0u+0nVvF8IXntC1Q+aeoalQ1RQz6Vb
         kLZud4xCY0CRHH2NkWsy5kQGWOAWjXLq5VuqZiP9vCbDQpxgGdcN8Kh7zhgW77p6YYiS
         u8Fg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.com header.s=susede1 header.b=FE4RHYf6;
       dkim=pass header.i=@suse.com header.s=susede1 header.b=nU7WDITh;
       spf=pass (google.com: domain of mhocko@suse.com designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) smtp.mailfrom=mhocko@suse.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=suse.com
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [2a07:de40:b251:101:10:150:64:1])
        by gmr-mx.google.com with ESMTPS id n12-20020a05600c500c00b004126e2da65csi318587wmr.2.2024.02.22.04.12.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 22 Feb 2024 04:12:30 -0800 (PST)
Received-SPF: pass (google.com: domain of mhocko@suse.com designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) client-ip=2a07:de40:b251:101:10:150:64:1;
Received: from imap1.dmz-prg2.suse.org (imap1.dmz-prg2.suse.org [IPv6:2a07:de40:b281:104:10:150:64:97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id E029522040;
	Thu, 22 Feb 2024 12:12:29 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id B76F9133DC;
	Thu, 22 Feb 2024 12:12:29 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id tUIxLC0612VEJwAAD6G6ig
	(envelope-from <mhocko@suse.com>); Thu, 22 Feb 2024 12:12:29 +0000
Date: Thu, 22 Feb 2024 13:12:29 +0100
From: "'Michal Hocko' via kasan-dev" <kasan-dev@googlegroups.com>
To: Suren Baghdasaryan <surenb@google.com>
Cc: akpm@linux-foundation.org, kent.overstreet@linux.dev, vbabka@suse.cz,
	hannes@cmpxchg.org, roman.gushchin@linux.dev, mgorman@suse.de,
	dave@stgolabs.net, willy@infradead.org, liam.howlett@oracle.com,
	penguin-kernel@i-love.sakura.ne.jp, corbet@lwn.net,
	void@manifault.com, peterz@infradead.org, juri.lelli@redhat.com,
	catalin.marinas@arm.com, will@kernel.org, arnd@arndb.de,
	tglx@linutronix.de, mingo@redhat.com, dave.hansen@linux.intel.com,
	x86@kernel.org, peterx@redhat.com, david@redhat.com,
	axboe@kernel.dk, mcgrof@kernel.org, masahiroy@kernel.org,
	nathan@kernel.org, dennis@kernel.org, tj@kernel.org,
	muchun.song@linux.dev, rppt@kernel.org, paulmck@kernel.org,
	pasha.tatashin@soleen.com, yosryahmed@google.com, yuzhao@google.com,
	dhowells@redhat.com, hughd@google.com, andreyknvl@gmail.com,
	keescook@chromium.org, ndesaulniers@google.com, vvvvvv@google.com,
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
	cgroups@vger.kernel.org,
	Petr =?utf-8?B?VGVzYcWZw61r?= <petr@tesarici.cz>
Subject: Re: [PATCH v4 06/36] mm: enumerate all gfp flags
Message-ID: <Zdc6LUWnPOBRmtZH@tiehlicka>
References: <20240221194052.927623-1-surenb@google.com>
 <20240221194052.927623-7-surenb@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <20240221194052.927623-7-surenb@google.com>
X-Spamd-Result: default: False [1.69 / 50.00];
	 RCVD_VIA_SMTP_AUTH(0.00)[];
	 SPAMHAUS_XBL(0.00)[2a07:de40:b281:104:10:150:64:97:from];
	 RECEIVED_SPAMHAUS_BLOCKED_OPENRESOLVER(0.00)[2a07:de40:b281:106:10:150:64:167:received];
	 TO_DN_SOME(0.00)[];
	 R_RATELIMIT(0.00)[to_ip_from(RLm3b7rx1h7ydj1zd5jb4wbfas)];
	 RCVD_COUNT_THREE(0.00)[3];
	 DKIM_TRACE(0.00)[suse.com:+];
	 MX_GOOD(-0.01)[];
	 RCPT_COUNT_GT_50(0.00)[75];
	 FROM_EQ_ENVFROM(0.00)[];
	 MIME_TRACE(0.00)[0:+];
	 BAYES_HAM(-0.00)[22.90%];
	 ARC_NA(0.00)[];
	 R_DKIM_ALLOW(-0.20)[suse.com:s=susede1];
	 FROM_HAS_DN(0.00)[];
	 FREEMAIL_ENVRCPT(0.00)[gmail.com];
	 TAGGED_RCPT(0.00)[];
	 MIME_GOOD(-0.10)[text/plain];
	 TO_MATCH_ENVRCPT_SOME(0.00)[];
	 DKIM_SIGNED(0.00)[suse.com:s=susede1];
	 DBL_BLOCKED_OPENRESOLVER(0.00)[suse.com:dkim,suse.com:email];
	 FUZZY_BLOCKED(0.00)[rspamd.com];
	 MID_RHS_NOT_FQDN(0.50)[];
	 FREEMAIL_CC(0.00)[linux-foundation.org,linux.dev,suse.cz,cmpxchg.org,suse.de,stgolabs.net,infradead.org,oracle.com,i-love.sakura.ne.jp,lwn.net,manifault.com,redhat.com,arm.com,kernel.org,arndb.de,linutronix.de,linux.intel.com,kernel.dk,soleen.com,google.com,gmail.com,chromium.org,linuxfoundation.org,linaro.org,goodmis.org,linux.com,lge.com,bytedance.com,akamai.com,android.com,vger.kernel.org,lists.linux.dev,kvack.org,googlegroups.com,tesarici.cz];
	 RCVD_TLS_ALL(0.00)[];
	 SUSPICIOUS_RECIPS(1.50)[];
	 RBL_SPAMHAUS_BLOCKED_OPENRESOLVER(0.00)[2a07:de40:b281:104:10:150:64:97:from]
X-Rspamd-Server: rspamd1.dmz-prg2.suse.org
X-Spam-Score: 1.69
X-Rspamd-Queue-Id: E029522040
X-Spam-Level: *
X-Spam-Flag: NO
X-Spamd-Bar: +
X-Original-Sender: mhocko@suse.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.com header.s=susede1 header.b=FE4RHYf6;       dkim=pass
 header.i=@suse.com header.s=susede1 header.b=nU7WDITh;       spf=pass
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

On Wed 21-02-24 11:40:19, Suren Baghdasaryan wrote:
> Introduce GFP bits enumeration to let compiler track the number of used
> bits (which depends on the config options) instead of hardcoding them.
> That simplifies __GFP_BITS_SHIFT calculation.
>=20
> Suggested-by: Petr Tesa=C5=99=C3=ADk <petr@tesarici.cz>
> Signed-off-by: Suren Baghdasaryan <surenb@google.com>
> Reviewed-by: Kees Cook <keescook@chromium.org>

I thought I have responded to this patch but obviously not the case.
I like this change. Makes sense even without the rest of the series.
Acked-by: Michal Hocko <mhocko@suse.com>

It seems that KASAN flags already __GFP_BITS_SHIFT which just proves how
fragile this existing scheme is.

> ---
>  include/linux/gfp_types.h | 90 +++++++++++++++++++++++++++------------
>  1 file changed, 62 insertions(+), 28 deletions(-)
>=20
> diff --git a/include/linux/gfp_types.h b/include/linux/gfp_types.h
> index 1b6053da8754..868c8fb1bbc1 100644
> --- a/include/linux/gfp_types.h
> +++ b/include/linux/gfp_types.h
> @@ -21,44 +21,78 @@ typedef unsigned int __bitwise gfp_t;
>   * include/trace/events/mmflags.h and tools/perf/builtin-kmem.c
>   */
> =20
> +enum {
> +	___GFP_DMA_BIT,
> +	___GFP_HIGHMEM_BIT,
> +	___GFP_DMA32_BIT,
> +	___GFP_MOVABLE_BIT,
> +	___GFP_RECLAIMABLE_BIT,
> +	___GFP_HIGH_BIT,
> +	___GFP_IO_BIT,
> +	___GFP_FS_BIT,
> +	___GFP_ZERO_BIT,
> +	___GFP_UNUSED_BIT,	/* 0x200u unused */
> +	___GFP_DIRECT_RECLAIM_BIT,
> +	___GFP_KSWAPD_RECLAIM_BIT,
> +	___GFP_WRITE_BIT,
> +	___GFP_NOWARN_BIT,
> +	___GFP_RETRY_MAYFAIL_BIT,
> +	___GFP_NOFAIL_BIT,
> +	___GFP_NORETRY_BIT,
> +	___GFP_MEMALLOC_BIT,
> +	___GFP_COMP_BIT,
> +	___GFP_NOMEMALLOC_BIT,
> +	___GFP_HARDWALL_BIT,
> +	___GFP_THISNODE_BIT,
> +	___GFP_ACCOUNT_BIT,
> +	___GFP_ZEROTAGS_BIT,
> +#ifdef CONFIG_KASAN_HW_TAGS
> +	___GFP_SKIP_ZERO_BIT,
> +	___GFP_SKIP_KASAN_BIT,
> +#endif
> +#ifdef CONFIG_LOCKDEP
> +	___GFP_NOLOCKDEP_BIT,
> +#endif
> +	___GFP_LAST_BIT
> +};
> +
>  /* Plain integer GFP bitmasks. Do not use this directly. */
> -#define ___GFP_DMA		0x01u
> -#define ___GFP_HIGHMEM		0x02u
> -#define ___GFP_DMA32		0x04u
> -#define ___GFP_MOVABLE		0x08u
> -#define ___GFP_RECLAIMABLE	0x10u
> -#define ___GFP_HIGH		0x20u
> -#define ___GFP_IO		0x40u
> -#define ___GFP_FS		0x80u
> -#define ___GFP_ZERO		0x100u
> +#define ___GFP_DMA		BIT(___GFP_DMA_BIT)
> +#define ___GFP_HIGHMEM		BIT(___GFP_HIGHMEM_BIT)
> +#define ___GFP_DMA32		BIT(___GFP_DMA32_BIT)
> +#define ___GFP_MOVABLE		BIT(___GFP_MOVABLE_BIT)
> +#define ___GFP_RECLAIMABLE	BIT(___GFP_RECLAIMABLE_BIT)
> +#define ___GFP_HIGH		BIT(___GFP_HIGH_BIT)
> +#define ___GFP_IO		BIT(___GFP_IO_BIT)
> +#define ___GFP_FS		BIT(___GFP_FS_BIT)
> +#define ___GFP_ZERO		BIT(___GFP_ZERO_BIT)
>  /* 0x200u unused */
> -#define ___GFP_DIRECT_RECLAIM	0x400u
> -#define ___GFP_KSWAPD_RECLAIM	0x800u
> -#define ___GFP_WRITE		0x1000u
> -#define ___GFP_NOWARN		0x2000u
> -#define ___GFP_RETRY_MAYFAIL	0x4000u
> -#define ___GFP_NOFAIL		0x8000u
> -#define ___GFP_NORETRY		0x10000u
> -#define ___GFP_MEMALLOC		0x20000u
> -#define ___GFP_COMP		0x40000u
> -#define ___GFP_NOMEMALLOC	0x80000u
> -#define ___GFP_HARDWALL		0x100000u
> -#define ___GFP_THISNODE		0x200000u
> -#define ___GFP_ACCOUNT		0x400000u
> -#define ___GFP_ZEROTAGS		0x800000u
> +#define ___GFP_DIRECT_RECLAIM	BIT(___GFP_DIRECT_RECLAIM_BIT)
> +#define ___GFP_KSWAPD_RECLAIM	BIT(___GFP_KSWAPD_RECLAIM_BIT)
> +#define ___GFP_WRITE		BIT(___GFP_WRITE_BIT)
> +#define ___GFP_NOWARN		BIT(___GFP_NOWARN_BIT)
> +#define ___GFP_RETRY_MAYFAIL	BIT(___GFP_RETRY_MAYFAIL_BIT)
> +#define ___GFP_NOFAIL		BIT(___GFP_NOFAIL_BIT)
> +#define ___GFP_NORETRY		BIT(___GFP_NORETRY_BIT)
> +#define ___GFP_MEMALLOC		BIT(___GFP_MEMALLOC_BIT)
> +#define ___GFP_COMP		BIT(___GFP_COMP_BIT)
> +#define ___GFP_NOMEMALLOC	BIT(___GFP_NOMEMALLOC_BIT)
> +#define ___GFP_HARDWALL		BIT(___GFP_HARDWALL_BIT)
> +#define ___GFP_THISNODE		BIT(___GFP_THISNODE_BIT)
> +#define ___GFP_ACCOUNT		BIT(___GFP_ACCOUNT_BIT)
> +#define ___GFP_ZEROTAGS		BIT(___GFP_ZEROTAGS_BIT)
>  #ifdef CONFIG_KASAN_HW_TAGS
> -#define ___GFP_SKIP_ZERO	0x1000000u
> -#define ___GFP_SKIP_KASAN	0x2000000u
> +#define ___GFP_SKIP_ZERO	BIT(___GFP_SKIP_ZERO_BIT)
> +#define ___GFP_SKIP_KASAN	BIT(___GFP_SKIP_KASAN_BIT)
>  #else
>  #define ___GFP_SKIP_ZERO	0
>  #define ___GFP_SKIP_KASAN	0
>  #endif
>  #ifdef CONFIG_LOCKDEP
> -#define ___GFP_NOLOCKDEP	0x4000000u
> +#define ___GFP_NOLOCKDEP	BIT(___GFP_NOLOCKDEP_BIT)
>  #else
>  #define ___GFP_NOLOCKDEP	0
>  #endif
> -/* If the above are modified, __GFP_BITS_SHIFT may need updating */
> =20
>  /*
>   * Physical address zone modifiers (see linux/mmzone.h - low four bits)
> @@ -249,7 +283,7 @@ typedef unsigned int __bitwise gfp_t;
>  #define __GFP_NOLOCKDEP ((__force gfp_t)___GFP_NOLOCKDEP)
> =20
>  /* Room for N __GFP_FOO bits */
> -#define __GFP_BITS_SHIFT (26 + IS_ENABLED(CONFIG_LOCKDEP))
> +#define __GFP_BITS_SHIFT ___GFP_LAST_BIT
>  #define __GFP_BITS_MASK ((__force gfp_t)((1 << __GFP_BITS_SHIFT) - 1))
> =20
>  /**
> --=20
> 2.44.0.rc0.258.g7320e95886-goog

--=20
Michal Hocko
SUSE Labs

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/Zdc6LUWnPOBRmtZH%40tiehlicka.
