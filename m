Return-Path: <kasan-dev+bncBDXYDPH3S4OBBR65XSXAMGQEVOQPPDY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x338.google.com (mail-wm1-x338.google.com [IPv6:2a00:1450:4864:20::338])
	by mail.lfdr.de (Postfix) with ESMTPS id 20BB9857921
	for <lists+kasan-dev@lfdr.de>; Fri, 16 Feb 2024 10:45:45 +0100 (CET)
Received: by mail-wm1-x338.google.com with SMTP id 5b1f17b1804b1-411ffacbafdsf493585e9.1
        for <lists+kasan-dev@lfdr.de>; Fri, 16 Feb 2024 01:45:45 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1708076744; cv=pass;
        d=google.com; s=arc-20160816;
        b=vIU/z+vkCT6W5UXvAbNcbOTru6i+FYL903VoyrSJMNkzDPwN7jOzXyiQ35+Fh1PuDr
         e9hCmr8I5TN5hFei2SwKORLogv6sqK/3PCDxMkX1b6scsXxVrQAc8LDQyRYOdJKTOYvR
         cvuNENAHg98kC4Wc0+Szh77yjMdl4p/XYs6AglxZIUikUcchW8mvGAzGLdu8tKhP73zt
         2D8JP3GadrYb81bbUl51Pd0RspaViax3BcwuqzYa9zQGhBW+OOkbmnWTYfujn6ilziaE
         uAy93Xax5deLCmlrUQS1YCczv86N4KJ8CJ3KBf0HLrrrYoZI0ncD9k15pS0NTCqwV/PU
         FKOw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=QXw0dTpGvRhUaZCwjYeIC3TGsGhKswZtRdS60icaxs4=;
        fh=X2NwCsuduWDM1gFTvaP/cYg4wiE2BA61pDX3BsWqa9o=;
        b=Pd/McALPVR+18Etd1FLuzN8EbiEd2tv4wXXACFaRYOdrKeWYzxJGZ3lIN+ijHbDG9B
         Gu/xbzqdu0uug+2+OA7jw2AIyNr/RHepE05J9+Y9webEspGkebI4b8ulX0D7b+n5GHBD
         7Vs6RqFdtg1Jtx/RWhoiyn1a/UvN4sXw8WwCCK65tPhVO4g44WPLZp84AKx5sD4usKuD
         hBcgizdSg6+JfoIbnizPC33b2Frz3YkStUJDrYoWn3mbrVBoaKYHo96AY106bXW/5E6f
         4qGInAIruycpqxEUlXimo2qUKJw0hjRty9If+gxN/XVehM9nbgkV42DWVnpfx09Wg7k0
         Z24g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=K3GJLk0N;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=K3GJLk0N;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1708076744; x=1708681544; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=QXw0dTpGvRhUaZCwjYeIC3TGsGhKswZtRdS60icaxs4=;
        b=ao6ilpuIgEvMAKw26IkFGAkAM+2pb/NR7sN9uP2GVSoVbjvETQVhKEeFoKs1Tlis50
         Icy9mN3TEn9PYjuHTrkICFB84L0FqLz0iZ8HoCooj0To+MClECeDDhMfZoYlsClrmWWn
         RqAW6GZwcC5txD8oPQClpYspF+3inih5ztcebJkxWE1Xm3oUhipqfTWhll3M349/sJE2
         fz1RU0Ow52nuZ1OSC0Yz/nOJwBa+mgWHYT9DWFcnLzMPHR8xCXOD+ZeSNxtt42wnF4+Y
         op7IwY0b0pIIwhXKpgrQGvzEPAV617D8btvH2y9NtP8Do0JYCvk0RpFhWRqaLvZjY2dY
         ueyw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1708076744; x=1708681544;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=QXw0dTpGvRhUaZCwjYeIC3TGsGhKswZtRdS60icaxs4=;
        b=SQpUBv1ltwV3ze2xnE9t9yHlSiKOG1dAzGfV1Zo2FAV+ABoksQAgRdWOEPLLukOuNP
         5JbkxoCyg6Rm1QD3kx9HSXuDrPIywjYrV209+M0hDY3HscX56aXoHHVYEzYJRxZ7SfLC
         mWnvlNFAgpMluCWy8VCw0zOBKzumrmFAlK7YqIjGrzDT5kcNUE4WLn/v25z4WFVTg/yT
         iKZhlCETv/5Gl5oDn3RqaUrmtaBLUq3re9q9At3nS/lZs+6NKMxL7sZoLObhxmnOmuFO
         VGYgerw79N68I963T1cYIR9PNWa23CysvDHiWVUfwLSnFqrfiCHQmIA1HS0Kf8uZ7iK0
         2v1A==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWTg0U3+AhPUqjhTGPj0Y++fpIBYnigo0HPvCFbpK0/hbynlw6P0+uxTWVVbRMu+XZ2AvADRLnAbjaGlu+4rA01TzKN8vRo3w==
X-Gm-Message-State: AOJu0YyJmH1a8Sw01i8Qr1ziZMRiRgpytP8c+fjSPt7+IKRnqJbahMZ8
	mdSSjdkbONXbXIZgdGLn4znv6fw0vkTvFjiSqiCw5iHIg/O1GYe2
X-Google-Smtp-Source: AGHT+IFTVrgJXdoWV4x+iFVO92Gfovvfd9Ks9CRtdV7m82hy9xOsGbcxH101qeLE5LvNgvqK8bR1Fg==
X-Received: by 2002:a05:600c:34ca:b0:412:4731:a5cf with SMTP id d10-20020a05600c34ca00b004124731a5cfmr61898wmq.5.1708076744040;
        Fri, 16 Feb 2024 01:45:44 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:1da4:b0:412:4d5a:ad7f with SMTP id
 p36-20020a05600c1da400b004124d5aad7fls129669wms.2.-pod-prod-07-eu; Fri, 16
 Feb 2024 01:45:42 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUqg7J2M+rxhLYaezRy7D58y4rNT3S191vdMXnlwh2f9Tw7t6TkW0OzZtcycVKfCKat6S02YrXTPoo6vvntLHe+BH/m8UCqvVOeAQ==
X-Received: by 2002:a05:600c:1da1:b0:411:fb76:94ed with SMTP id p33-20020a05600c1da100b00411fb7694edmr3329744wms.30.1708076742206;
        Fri, 16 Feb 2024 01:45:42 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1708076742; cv=none;
        d=google.com; s=arc-20160816;
        b=qmFVD6cWC91X93j8Sez9xDvAiMu/ZPMr63/psjsnoa1aENpdzwVDthZaMcdbWzqliv
         KYj6Z1zaPnMrJiSViIEjjzhUiGIIuDC6gv6hRACBQcUD9yf/9Rbd7GwCCuxIfEZcFvJv
         WTd3kCQhSud3/dT3r9RLKcPWIDXEzyoTYjOmMKB4es899oQ9LktR+u1OhE3jeqzMqyOM
         VyKC3ZIFIWCV087ZwyQOJ2ymDp6t0vWE0iGUaK76qRiFK6oJLaxJ2+cW82/IdYyzSZAE
         wkbYXwA2vM5Jzyqv6KQ+zpqe7ZD1E/o7ktgGErpE7grcu72Lw6MzO2BpDvGOIFzfqbSr
         Eq6Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature:dkim-signature:dkim-signature;
        bh=iYMvNCYqDaBQbPMA0B0bnoIRN91Lu24uOJ7yYQTso7E=;
        fh=QRwoHi5AHykrsPeo9uUZ+S24npSTFJROfKJSvxyXrPg=;
        b=crMJW9olv95yCRR+M7Y8z5u32N4J4o0QDkwN+3ns8pevUrwMBULV5hpiWZH0P4Q9RT
         4zO/UP0RnruGgYYYTtwFPdScpFxE7x4cQeJjHu6M2Reenyq3kB1P/K/k5WEBhyeuEYGM
         naDSMhLV4jbb8pFFowRwDzZKswp9JdC4RBtfBletHiDYbxPNpOvVri5GWt0f/NbkhEbX
         pRhy2t6nG8AtLPnhB5+rGgon8hfMcWW1lIvX3oLd84WaIF93uvfv3+AeceiK23XzOiPu
         Scdu04G/cSbclIoRp8I6T6BPndW5hGfKWt1fI7nntFfskvDZuAEvtP8NQHJUUTkSNpnm
         pBSw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=K3GJLk0N;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=K3GJLk0N;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [195.135.223.131])
        by gmr-mx.google.com with ESMTPS id j25-20020a05600c1c1900b004120a09f45esi43867wms.1.2024.02.16.01.45.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 16 Feb 2024 01:45:42 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted sender) client-ip=195.135.223.131;
Received: from imap1.dmz-prg2.suse.org (imap1.dmz-prg2.suse.org [10.150.64.97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id 907091FB5D;
	Fri, 16 Feb 2024 09:45:41 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id DF6F313A39;
	Fri, 16 Feb 2024 09:45:40 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id rhsGNsQuz2WEcAAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Fri, 16 Feb 2024 09:45:40 +0000
Message-ID: <039a817d-20c4-487d-a443-f87e19727305@suse.cz>
Date: Fri, 16 Feb 2024 10:45:40 +0100
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v3 14/35] lib: introduce support for page allocation
 tagging
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
 <20240212213922.783301-15-surenb@google.com>
From: Vlastimil Babka <vbabka@suse.cz>
In-Reply-To: <20240212213922.783301-15-surenb@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Spamd-Result: default: False [-1.59 / 50.00];
	 ARC_NA(0.00)[];
	 RCVD_VIA_SMTP_AUTH(0.00)[];
	 XM_UA_NO_VERSION(0.01)[];
	 FROM_HAS_DN(0.00)[];
	 TO_DN_SOME(0.00)[];
	 FREEMAIL_ENVRCPT(0.00)[gmail.com];
	 MID_RHS_MATCH_FROM(0.00)[];
	 TAGGED_RCPT(0.00)[];
	 MIME_GOOD(-0.10)[text/plain];
	 BAYES_HAM(-3.00)[100.00%];
	 R_RATELIMIT(0.00)[to_ip_from(RL7fbg3f7cqn65nt4rpgoexbzo)];
	 RCVD_COUNT_THREE(0.00)[3];
	 DKIM_SIGNED(0.00)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	 TO_MATCH_ENVRCPT_SOME(0.00)[];
	 RCPT_COUNT_GT_50(0.00)[73];
	 FUZZY_BLOCKED(0.00)[rspamd.com];
	 FROM_EQ_ENVFROM(0.00)[];
	 MIME_TRACE(0.00)[0:+];
	 FREEMAIL_CC(0.00)[linux.dev,suse.com,cmpxchg.org,suse.de,stgolabs.net,infradead.org,oracle.com,lwn.net,manifault.com,redhat.com,arm.com,kernel.org,arndb.de,linutronix.de,linux.intel.com,kernel.dk,soleen.com,google.com,gmail.com,chromium.org,linuxfoundation.org,linaro.org,goodmis.org,linux.com,lge.com,bytedance.com,akamai.com,android.com,vger.kernel.org,lists.linux.dev,kvack.org,googlegroups.com];
	 RCVD_TLS_ALL(0.00)[];
	 SUSPICIOUS_RECIPS(1.50)[]
X-Spam-Level: 
X-Spam-Flag: NO
X-Spam-Score: -1.59
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=K3GJLk0N;       dkim=neutral
 (no key) header.i=@suse.cz header.s=susede2_ed25519;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=K3GJLk0N;       dkim=neutral
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

On 2/12/24 22:39, Suren Baghdasaryan wrote:
> Introduce helper functions to easily instrument page allocators by
> storing a pointer to the allocation tag associated with the code that
> allocated the page in a page_ext field.
> 
> Signed-off-by: Suren Baghdasaryan <surenb@google.com>
> Co-developed-by: Kent Overstreet <kent.overstreet@linux.dev>
> Signed-off-by: Kent Overstreet <kent.overstreet@linux.dev>
> +
> +#ifdef CONFIG_MEM_ALLOC_PROFILING
> +
> +#include <linux/page_ext.h>
> +
> +extern struct page_ext_operations page_alloc_tagging_ops;
> +extern struct page_ext *page_ext_get(struct page *page);
> +extern void page_ext_put(struct page_ext *page_ext);
> +
> +static inline union codetag_ref *codetag_ref_from_page_ext(struct page_ext *page_ext)
> +{
> +	return (void *)page_ext + page_alloc_tagging_ops.offset;
> +}
> +
> +static inline struct page_ext *page_ext_from_codetag_ref(union codetag_ref *ref)
> +{
> +	return (void *)ref - page_alloc_tagging_ops.offset;
> +}
> +
> +static inline union codetag_ref *get_page_tag_ref(struct page *page)
> +{
> +	if (page && mem_alloc_profiling_enabled()) {
> +		struct page_ext *page_ext = page_ext_get(page);
> +
> +		if (page_ext)
> +			return codetag_ref_from_page_ext(page_ext);

I think when structured like this, you're not getting the full benefits of
static keys, and the compiler probably can't improve that on its own.

- page is tested before the static branch is evaluated
- when disabled, the result is NULL, and that's again tested in the callers

> +	}
> +	return NULL;
> +}
> +
> +static inline void put_page_tag_ref(union codetag_ref *ref)
> +{
> +	page_ext_put(page_ext_from_codetag_ref(ref));
> +}
> +
> +static inline void pgalloc_tag_add(struct page *page, struct task_struct *task,
> +				   unsigned int order)
> +{
> +	union codetag_ref *ref = get_page_tag_ref(page);

So the more optimal way would be to test mem_alloc_profiling_enabled() here
as the very first thing before trying to get the ref.

> +	if (ref) {
> +		alloc_tag_add(ref, task->alloc_tag, PAGE_SIZE << order);
> +		put_page_tag_ref(ref);
> +	}
> +}
> +
> +static inline void pgalloc_tag_sub(struct page *page, unsigned int order)
> +{
> +	union codetag_ref *ref = get_page_tag_ref(page);

And same here.

> +	if (ref) {
> +		alloc_tag_sub(ref, PAGE_SIZE << order);
> +		put_page_tag_ref(ref);
> +	}
> +}
> +
> +#else /* CONFIG_MEM_ALLOC_PROFILING */
> +
> +static inline void pgalloc_tag_add(struct page *page, struct task_struct *task,
> +				   unsigned int order) {}
> +static inline void pgalloc_tag_sub(struct page *page, unsigned int order) {}
> +
> +#endif /* CONFIG_MEM_ALLOC_PROFILING */
> +
> +#endif /* _LINUX_PGALLOC_TAG_H */
> diff --git a/lib/Kconfig.debug b/lib/Kconfig.debug
> index 78d258ca508f..7bbdb0ddb011 100644
> --- a/lib/Kconfig.debug
> +++ b/lib/Kconfig.debug
> @@ -978,6 +978,7 @@ config MEM_ALLOC_PROFILING
>  	depends on PROC_FS
>  	depends on !DEBUG_FORCE_WEAK_PER_CPU
>  	select CODE_TAGGING
> +	select PAGE_EXTENSION
>  	help
>  	  Track allocation source code and record total allocation size
>  	  initiated at that code location. The mechanism can be used to track
> diff --git a/lib/alloc_tag.c b/lib/alloc_tag.c
> index 4fc031f9cefd..2d5226d9262d 100644
> --- a/lib/alloc_tag.c
> +++ b/lib/alloc_tag.c
> @@ -3,6 +3,7 @@
>  #include <linux/fs.h>
>  #include <linux/gfp.h>
>  #include <linux/module.h>
> +#include <linux/page_ext.h>
>  #include <linux/proc_fs.h>
>  #include <linux/seq_buf.h>
>  #include <linux/seq_file.h>
> @@ -124,6 +125,22 @@ static bool alloc_tag_module_unload(struct codetag_type *cttype,
>  	return module_unused;
>  }
>  
> +static __init bool need_page_alloc_tagging(void)
> +{
> +	return true;

So this means the page_ext memory overead is paid unconditionally once
MEM_ALLOC_PROFILING is compile time enabled, even if never enabled during
runtime? That makes it rather costly to be suitable for generic distro
kernels where the code could be compile time enabled, and runtime enabling
suggested in a debugging/support scenario. It's what we do with page_owner,
debug_pagealloc, slub_debug etc.

Ideally we'd have some vmalloc based page_ext flavor for later-than-boot
runtime enablement, as we now have for stackdepot. But that could be
explored later. For now it would be sufficient to add an early_param boot
parameter to control the enablement including page_ext, like page_owner and
other features do.

> +}
> +
> +static __init void init_page_alloc_tagging(void)
> +{
> +}
> +
> +struct page_ext_operations page_alloc_tagging_ops = {
> +	.size = sizeof(union codetag_ref),
> +	.need = need_page_alloc_tagging,
> +	.init = init_page_alloc_tagging,
> +};
> +EXPORT_SYMBOL(page_alloc_tagging_ops);


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/039a817d-20c4-487d-a443-f87e19727305%40suse.cz.
