Return-Path: <kasan-dev+bncBDXYDPH3S4OBB76XX2XAMGQEKAZPYNI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x237.google.com (mail-lj1-x237.google.com [IPv6:2a00:1450:4864:20::237])
	by mail.lfdr.de (Postfix) with ESMTPS id C2879858560
	for <lists+kasan-dev@lfdr.de>; Fri, 16 Feb 2024 19:40:00 +0100 (CET)
Received: by mail-lj1-x237.google.com with SMTP id 38308e7fff4ca-2d0cfe644d6sf22201431fa.0
        for <lists+kasan-dev@lfdr.de>; Fri, 16 Feb 2024 10:40:00 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1708108800; cv=pass;
        d=google.com; s=arc-20160816;
        b=0ORRX4Doqx5emcWmX9H64dQBPxoZU5Mb5SzwZkeXIyvSShUmnwRVEkg8nFe7TgY8H4
         p/fnD16/2f60HI/yU/ti5eyanr3fI4w3oS53abgIdH0jZ5PPO58ndYXko/6H82JX9uDU
         2hKrLjrIctSFNO/GvjNP3BuEz16tKc1HDC5RUkx7lfCP1Z/NLetPt9PVngKQ3/4qr3KZ
         fPr4L6KG4ZJNjFmFNgDbdKAr/E2Fwbt1l1riQmGgCIrvRpQbk0qNg9CBiwPyUBxfhsBk
         xk2VGZbcdR1kGy1DoA8tmjcJn+sbyEq4uE6mr6IffQo7T39JMFLBw57DsiryjrE+LyUW
         V0/Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=xTLb0M/L6WeDeIsF3a/MaISRtE5DAO+2n55XWOL/3Mc=;
        fh=cwbnP6Appq2etSYL6THjx4OZLwCYR1GIFKpDMJa9M8s=;
        b=Bhy9WYUzgeKkOmiiOvo6i3CJildjvv5JEFeAlCeKzBm5tpp1/hC2B98pDl4+GdCF4S
         Qc6igaHnmdWX+St8/2ZN2TxxiYewHhIo5Sk8SUdzuLbSg7ImSmC5XEbeIF3b/7pRVIIN
         jTGxhLDEcorqa8UxwdimzhB6NKhklYfPGkvarwiBLI7JwxHszTZSGUVErdfs685RDUQ/
         f9ZjgfZtmDVGFcPdo3f+FnSdfTc/JkE0jDNx8l5Xb1cti3T+55BhiPWH2oNkECYuveOF
         NTu3WFA0vzswD6XLhSMumSXgqpNKb73DdhxayBahXxntf+JEuMwg4hrmJ7qMUjBOOC71
         2pWA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=T3D8vPec;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=T3D8vPec;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1708108800; x=1708713600; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=xTLb0M/L6WeDeIsF3a/MaISRtE5DAO+2n55XWOL/3Mc=;
        b=OkCSqnc3kwc4m2yQloMcA4epcpu7+q5+laCOZGwaiMapmpQRRnpYBxZyacC+BFu30z
         TJWgx9VI2u/Ddc7XdkkM+Nbm8CUKgenE37q3pDf3y1MdjVqZOQC6YSBwEohrWmoVJ9bu
         fr2saA0FY0iBlavXoHsKMa4AElnI1nZaMzwJErFQofvKf4g3V77jZkJ8IUy5rjavnfpt
         6ktE4cWgcZMhQ1b3UKKGq8sj9OzdwNeVGiY8fYjrLzzYA0AKKbOIEwJGUhik7aWy26Mw
         7YvUzrLgW1k6WBc0GilGds1gbr1EIF1UuzQ95mIZW19CM+ME0Ry77m5wch9Z1IgHMK1O
         skjQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1708108800; x=1708713600;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=xTLb0M/L6WeDeIsF3a/MaISRtE5DAO+2n55XWOL/3Mc=;
        b=Kdo2FBxcweZT5L4q3OLyHAxQTHONHQbBSXZB62uCTDpYtHuubv3KBu3MUlLabcZAhT
         Pp6M5CCnLHSYWBopuOpgmpHiMVGeiZIhP4sNn7TVUzvnwqvq71bj6spySAlVcb8xtxxh
         gU2J4So1DwhzLpqzW4qCYn89QLX2Y6xcQraP2cdf/fQAKvYGP+ip2s7UieMdiTtPTfwG
         5kdkDWT484fWhcniYw1afKlyEB4wKgaEPnEB3rY59SYORHtPYYf2cENqvNtgVWtqT5pg
         4njEMDo7WrmEvO7oBjPwXJSjd1G9vX61DBWFsMYHciBjsZUmEiGeeYrW5vP443iK7G0q
         8vtg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXPVxi9N4sFcWhYA2i4yLqEnjl/YQjdWJvb1iFRhXPvZeNH6HrNC8xMcr9du89q5EmK5wSljBOI4Sk0M1KlZ2JM3VHrOzNGwA==
X-Gm-Message-State: AOJu0YxrGcnvHC6s8gFajblK2etugPmOtutxWnIyU6LkSEVJ6JmdutWm
	p6iabHj6uyvvI7uLvkHY3BndUFegJjsxqoUoCZVIJxtz5de1xMdP
X-Google-Smtp-Source: AGHT+IFpXTljPxNxg2JqCmB9niaSPGVN/h91OpDZvreCkwUPCfLabF1MVGSgi6hG6vwhTxfjEM83WQ==
X-Received: by 2002:a2e:9e49:0:b0:2d1:276b:860 with SMTP id g9-20020a2e9e49000000b002d1276b0860mr4367258ljk.31.1708108799648;
        Fri, 16 Feb 2024 10:39:59 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:10af:b0:2d0:eb23:3b3e with SMTP id
 k15-20020a05651c10af00b002d0eb233b3els359753ljn.1.-pod-prod-01-eu; Fri, 16
 Feb 2024 10:39:58 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXwTG9SE2qxSHd2OCfOpG0+kCjWQRFXO0Sgu3sN+x19Le4DrmYLRyUE5dXav2iZkBaOfElRyAyboHR2roBa6khVbo0YSoyDHYNOCA==
X-Received: by 2002:a05:651c:2220:b0:2d2:25e4:4192 with SMTP id y32-20020a05651c222000b002d225e44192mr361593ljq.20.1708108797729;
        Fri, 16 Feb 2024 10:39:57 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1708108797; cv=none;
        d=google.com; s=arc-20160816;
        b=ehBwUb1EOwjHvMUtrZg7LsHtBFOYCyBZLg707RJs8pN93TwdcN0cqVKmOrN49L6Mfq
         QLvVlW/RByiEI5726YrmVn4o0+2hJIptVNUEY0TdstqIX40MYSFBDnvVGj8O+s/FzzlQ
         5Tm/FMgCyxsOqbgbJX0lmGWujvEaaQnAQkdH5GHUi1GYw0ca/cy37+Q2kEiJG1hV0Mh7
         hFa1Mv7ZiMCSrXwPptPs046XWWafrCXKpwj+9picCO/6mbj+7I1H5MBccSlHY1CtyO+1
         ufk2yZfESYFqY8/3aRES33GE2MGCdqTatJT5E5IIfOByS6M0AXFXDKc2odXh72yB2iOk
         rjJQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature:dkim-signature:dkim-signature;
        bh=owuEgnvOaosc1e6fEV37dsj+Uoc2y36g1E2N9MOPSbU=;
        fh=QRwoHi5AHykrsPeo9uUZ+S24npSTFJROfKJSvxyXrPg=;
        b=HQ7/rOaAIWR6iJwgU3uA0M53YYBfXZjalLdfyyedyjbhWjyKsF1uMEPt5bRL2HqoaI
         pSSV7fEXSB11zSlS3LsHe1nCcU6csw8xD9HZ3kzv4qNjRLueHQ/mksdz8v5FifjpZ8km
         yBJjOzaQtBdF+NKRVHkYJ99QgnaFl+O3JZRx1Z2Sb+uxh8Yk80k1R6r7GkFyDpO7FnjC
         jh8XMetaK98HpBdNDxVdsx/dnUa182gJfpY5IldKvewGmj3S0dgCeYmVTswDCyZnyvfX
         I4n/QwK4HmZROoEwp/Jr/srqn5NQLpm3AKE7sFFzJY9koIKod8ZdEx9BIUfwMnJlUw64
         rvWg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=T3D8vPec;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=T3D8vPec;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [2a07:de40:b251:101:10:150:64:1])
        by gmr-mx.google.com with ESMTPS id n24-20020a05600c181800b00411e6461fa7si107347wmp.1.2024.02.16.10.39.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 16 Feb 2024 10:39:57 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) client-ip=2a07:de40:b251:101:10:150:64:1;
Received: from imap1.dmz-prg2.suse.org (imap1.dmz-prg2.suse.org [IPv6:2a07:de40:b281:104:10:150:64:97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id 03DCB2206F;
	Fri, 16 Feb 2024 18:39:57 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id 6E0741398D;
	Fri, 16 Feb 2024 18:39:56 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id ya4MGvyrz2W6awAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Fri, 16 Feb 2024 18:39:56 +0000
Message-ID: <f0a56027-472d-44a6-aba5-912bd50ee3ae@suse.cz>
Date: Fri, 16 Feb 2024 19:39:56 +0100
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v3 32/35] codetag: debug: skip objext checking when it's
 for objext itself
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
 <20240212213922.783301-33-surenb@google.com>
From: Vlastimil Babka <vbabka@suse.cz>
In-Reply-To: <20240212213922.783301-33-surenb@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Spam-Level: 
X-Spamd-Bar: /
X-Rspamd-Server: rspamd2.dmz-prg2.suse.org
X-Spamd-Result: default: False [0.00 / 50.00];
	 RCVD_VIA_SMTP_AUTH(0.00)[];
	 XM_UA_NO_VERSION(0.01)[];
	 SPAMHAUS_XBL(0.00)[2a07:de40:b281:104:10:150:64:97:from];
	 TO_DN_SOME(0.00)[];
	 R_RATELIMIT(0.00)[to_ip_from(RLcb476ir6xfzaroaj5pc7azzw)];
	 RCVD_COUNT_THREE(0.00)[3];
	 DKIM_TRACE(0.00)[suse.cz:+];
	 MX_GOOD(-0.01)[];
	 RCPT_COUNT_GT_50(0.00)[73];
	 NEURAL_HAM_SHORT(-0.20)[-1.000];
	 FROM_EQ_ENVFROM(0.00)[];
	 MIME_TRACE(0.00)[0:+];
	 MID_RHS_MATCH_FROM(0.00)[];
	 ARC_NA(0.00)[];
	 R_DKIM_ALLOW(-0.20)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	 FROM_HAS_DN(0.00)[];
	 FREEMAIL_ENVRCPT(0.00)[gmail.com];
	 NEURAL_HAM_LONG(-1.00)[-1.000];
	 TAGGED_RCPT(0.00)[];
	 MIME_GOOD(-0.10)[text/plain];
	 TO_MATCH_ENVRCPT_SOME(0.00)[];
	 DKIM_SIGNED(0.00)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	 FUZZY_BLOCKED(0.00)[rspamd.com];
	 FREEMAIL_CC(0.00)[linux.dev,suse.com,cmpxchg.org,suse.de,stgolabs.net,infradead.org,oracle.com,lwn.net,manifault.com,redhat.com,arm.com,kernel.org,arndb.de,linutronix.de,linux.intel.com,kernel.dk,soleen.com,google.com,gmail.com,chromium.org,linuxfoundation.org,linaro.org,goodmis.org,linux.com,lge.com,bytedance.com,akamai.com,android.com,vger.kernel.org,lists.linux.dev,kvack.org,googlegroups.com];
	 RCVD_TLS_ALL(0.00)[];
	 SUSPICIOUS_RECIPS(1.50)[]
X-Spam-Score: 0.00
X-Rspamd-Queue-Id: 03DCB2206F
X-Spam-Flag: NO
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=T3D8vPec;       dkim=neutral
 (no key) header.i=@suse.cz header.s=susede2_ed25519;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=T3D8vPec;       dkim=neutral
 (no key) header.i=@suse.cz header.s=susede2_ed25519;       spf=pass
 (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1
 as permitted sender) smtp.mailfrom=vbabka@suse.cz
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

On 2/12/24 22:39, Suren Baghdasaryan wrote:
> objext objects are created with __GFP_NO_OBJ_EXT flag and therefore have
> no corresponding objext themselves (otherwise we would get an infinite
> recursion). When freeing these objects their codetag will be empty and
> when CONFIG_MEM_ALLOC_PROFILING_DEBUG is enabled this will lead to false
> warnings. Introduce CODETAG_EMPTY special codetag value to mark
> allocations which intentionally lack codetag to avoid these warnings.
> Set objext codetags to CODETAG_EMPTY before freeing to indicate that
> the codetag is expected to be empty.
> 
> Signed-off-by: Suren Baghdasaryan <surenb@google.com>
> ---
>  include/linux/alloc_tag.h | 26 ++++++++++++++++++++++++++
>  mm/slab.h                 | 25 +++++++++++++++++++++++++
>  mm/slab_common.c          |  1 +
>  mm/slub.c                 |  8 ++++++++
>  4 files changed, 60 insertions(+)
> 
> diff --git a/include/linux/alloc_tag.h b/include/linux/alloc_tag.h
> index 0a5973c4ad77..1f3207097b03 100644

...

> index c4bd0d5348cb..cf332a839bf4 100644
> --- a/mm/slab.h
> +++ b/mm/slab.h
> @@ -567,6 +567,31 @@ static inline struct slabobj_ext *slab_obj_exts(struct slab *slab)
>  int alloc_slab_obj_exts(struct slab *slab, struct kmem_cache *s,
>  			gfp_t gfp, bool new_slab);
>  
> +
> +#ifdef CONFIG_MEM_ALLOC_PROFILING_DEBUG
> +
> +static inline void mark_objexts_empty(struct slabobj_ext *obj_exts)
> +{
> +	struct slabobj_ext *slab_exts;
> +	struct slab *obj_exts_slab;
> +
> +	obj_exts_slab = virt_to_slab(obj_exts);
> +	slab_exts = slab_obj_exts(obj_exts_slab);
> +	if (slab_exts) {
> +		unsigned int offs = obj_to_index(obj_exts_slab->slab_cache,
> +						 obj_exts_slab, obj_exts);
> +		/* codetag should be NULL */
> +		WARN_ON(slab_exts[offs].ref.ct);
> +		set_codetag_empty(&slab_exts[offs].ref);
> +	}
> +}
> +
> +#else /* CONFIG_MEM_ALLOC_PROFILING_DEBUG */
> +
> +static inline void mark_objexts_empty(struct slabobj_ext *obj_exts) {}
> +
> +#endif /* CONFIG_MEM_ALLOC_PROFILING_DEBUG */
> +

I assume with alloc_slab_obj_exts() moved to slub.c, mark_objexts_empty()
could move there too.

>  static inline bool need_slab_obj_ext(void)
>  {
>  #ifdef CONFIG_MEM_ALLOC_PROFILING
> diff --git a/mm/slab_common.c b/mm/slab_common.c
> index 21b0b9e9cd9e..d5f75d04ced2 100644
> --- a/mm/slab_common.c
> +++ b/mm/slab_common.c
> @@ -242,6 +242,7 @@ int alloc_slab_obj_exts(struct slab *slab, struct kmem_cache *s,
>  		 * assign slabobj_exts in parallel. In this case the existing
>  		 * objcg vector should be reused.
>  		 */
> +		mark_objexts_empty(vec);
>  		kfree(vec);
>  		return 0;
>  	}
> diff --git a/mm/slub.c b/mm/slub.c
> index 4d480784942e..1136ff18b4fe 100644
> --- a/mm/slub.c
> +++ b/mm/slub.c
> @@ -1890,6 +1890,14 @@ static inline void free_slab_obj_exts(struct slab *slab)
>  	if (!obj_exts)
>  		return;
>  
> +	/*
> +	 * obj_exts was created with __GFP_NO_OBJ_EXT flag, therefore its
> +	 * corresponding extension will be NULL. alloc_tag_sub() will throw a
> +	 * warning if slab has extensions but the extension of an object is
> +	 * NULL, therefore replace NULL with CODETAG_EMPTY to indicate that
> +	 * the extension for obj_exts is expected to be NULL.
> +	 */
> +	mark_objexts_empty(obj_exts);
>  	kfree(obj_exts);
>  	slab->obj_exts = 0;
>  }

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/f0a56027-472d-44a6-aba5-912bd50ee3ae%40suse.cz.
