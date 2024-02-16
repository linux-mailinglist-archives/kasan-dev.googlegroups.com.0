Return-Path: <kasan-dev+bncBDXYDPH3S4OBBVVFX2XAMGQEAKAHVOI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x138.google.com (mail-lf1-x138.google.com [IPv6:2a00:1450:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id 23056858300
	for <lists+kasan-dev@lfdr.de>; Fri, 16 Feb 2024 17:52:40 +0100 (CET)
Received: by mail-lf1-x138.google.com with SMTP id 2adb3069b0e04-5114a395d9csf1784864e87.0
        for <lists+kasan-dev@lfdr.de>; Fri, 16 Feb 2024 08:52:40 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1708102359; cv=pass;
        d=google.com; s=arc-20160816;
        b=JvIZYDJq7b7S2kIoHYhRIQCVl9HNE5zvxdU5t7nao4/MPFZWKDAVExia+mje7Srl9U
         ExjGC1T+6202Ut/K5NgR1oUIC7FfKaKLwEBJ/KIKiNUX83XVbfNIzPGePB6Na7T9/Acx
         xE7AjKd9C8q31hsWdWqBEXsw7RUyiANR4vGJzXKw5Gq9lXqcROP3tmmW2wnKxKd2QF1G
         riVQ4GL+XJFOEqBoZBAsitBF50BK0MKGveJO8U3/0WDNIMG3T19cv59iDHqfcvrT8P9n
         zazKEPGn9yS2tBosOpAAgiAyso1FdE2gbLtKgjeotIqdQdD7BQbr5c119EE2sQ3Jt5iR
         kNBQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=gE5AGsOy9Evj2/8UbKBOBXkSvbyLAa7KcR3pMqxZXZA=;
        fh=nLAsTR9amrmP+IRYFqssHLHFhz51BaDdRqqsFOggY7g=;
        b=MRLf57YDTdWfL5K1VW59K+HW+l8q23Ajdv33O4DNiHM+x1nGEJf2CbeJQFTN3iX9TA
         5RZpspondAm+NllNzmhylaPwPupNO7wAPIYhTktH68SuKP868HZbh4MkCADdJ0J9NL6+
         +fmhahewDTEeLlAPqi2TkMcKFG6RTvRF+xV0S1gE7YKsOb+DG7CHjvgGFvgmjEl6CRbZ
         DiADhj3VS6bj2OJUBGAck549SMeyJwuGsn1sVwJ4EVHKLrPmgmjG64BhCiPXEeNiiSVY
         9Al53plFqmG8ue6aZkeqOHNt3x2Tqab1scYTGd2AHp03t/0jiRDqV3H39MsDz8SI508w
         D1ag==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=gfwPmBXr;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=gfwPmBXr;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1708102359; x=1708707159; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=gE5AGsOy9Evj2/8UbKBOBXkSvbyLAa7KcR3pMqxZXZA=;
        b=W+rTq4PfZX/J+Ndd9MGYcxtlb8Lzabii2jjQDRIwAU6YEbjZxlOWdTf1+ZJS5ZvjEG
         aa/Sk+EGoPkkWUU/vgdxGfnBPbNpHNf1jxeqK9wJRMEYTxRZlfkn29+iTZtR/SyCfS9i
         sNIyrhWXIEi3mA1YcI9T2l2y6CjmpgHegxeYK3ctpDxS2VwlRDRnuJp6DNr1prZaEBsc
         Bnm9xlW3TJvXu6emaneOWYVjNMYo9DTNOaEzhFg1It76lGnwONgHSIj2XEgOL/QhwrB7
         HJkkWohwyGSlzdcyrjhKT+uwjYRO+U96sgq5GdncpC+NzW1XyoT8C3zBAtFQ8v13j0cM
         W3dQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1708102359; x=1708707159;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=gE5AGsOy9Evj2/8UbKBOBXkSvbyLAa7KcR3pMqxZXZA=;
        b=EP8rHBYEBqjQtyP/CUXxzcN0zZKibFm1BOhuSBrTo8d+6+ICnwSTJ8pU7OUWlqvaji
         /A8oORqpUooIj+MWxeiLZ0d0+9utVKKZ2jU7i73hAjG2gG7ypI8nXKB+wKsBjKfAHnUf
         SOOlqeQLI9Cp3cZ1Nc4KwuN27MWhUzmVm+Kadf44mrhoQEkgYkFh06RqxaqoBRPYg/B2
         cWf3L8T4xilHybrwX4NhyDDpIcPrXtX41ssbvx9cInQP8bn01F9eRFN6dLfyBnSL5CSE
         lii2KRZs+xLXZUOrum8JS0qRfqAtmWeTQ+LqgtGo/z8jczhrKDHWDV1L29zsYOWJ6ciJ
         RbDQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVJVgcGcAarDYYPjsBm2TVAz5cPlyM+U3nFQrDylfbSTvMPW1I9b7NcrnUftGGwIc3Y3gdv7afiWiHRdOHDMDQ+2pFMGHfdHQ==
X-Gm-Message-State: AOJu0YyFFxtaW4QOX0Ras61t71DyqIz1xcXckAF+Pk6sZqcc+HGnac+/
	0UCmPsTdDSe/mRbkJxMmScm7p/eFZWPF9Z+bkRmxJrBxeHgZbcvE
X-Google-Smtp-Source: AGHT+IErgDxmg/GdOxz1TrKwy0NyJre3fU7ttJZOu8MK4aTjrINk1fdkmtHYxTVV9+ep73miSUFGsg==
X-Received: by 2002:a05:6512:3133:b0:512:9cda:e015 with SMTP id p19-20020a056512313300b005129cdae015mr214394lfd.16.1708102358977;
        Fri, 16 Feb 2024 08:52:38 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:a4c9:0:b0:2d0:d408:eb74 with SMTP id p9-20020a2ea4c9000000b002d0d408eb74ls222448ljm.0.-pod-prod-00-eu;
 Fri, 16 Feb 2024 08:52:37 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVk8wudIb/btjlTqhs7DlQHk1Eworc3v+G7RTpOD5WD2keaGzwVxUgwXT0UI16arHiNTKEus9lF/5iHEvr8UUDpd7WI5r1V9uosXA==
X-Received: by 2002:a2e:a545:0:b0:2d1:931:e8d3 with SMTP id e5-20020a2ea545000000b002d10931e8d3mr3154303ljn.15.1708102357004;
        Fri, 16 Feb 2024 08:52:37 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1708102356; cv=none;
        d=google.com; s=arc-20160816;
        b=AEiuN48mOaB5m58iLpv/siVQKA49voXZbhlIbvkGJdtkzRbK4kWAEHWtwCzfjPBpP3
         rDsZf7PE56SRivdG1rzUkQhMXNSlul6Ej1DB/+57Dupl+wZ2u3lc5XaRbYChkRwnS2du
         IT7pzqKa52nfD2L4VMOEQjcE0h5EtIrYtESjQGFYwUueQQUGNp3ApR6xahT2I4tEq0JT
         K3c0KOpaaTM8tsfYnRimkn6sYc1I23hTdftALNaSyljokkwoXIk4n6jrsZ9Zfm9ZsbjA
         whzyyDf6bhNdNQOD2VKcdTquw2TRXUELzOtEtyf1zlZJKyhvk9ZE7eh8/YeCf80dsqy8
         ZA1A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature:dkim-signature:dkim-signature;
        bh=bjFfGHq1FbZX5RctuoEE2JMZaFbk7fCFrSUdFxCZeQM=;
        fh=QRwoHi5AHykrsPeo9uUZ+S24npSTFJROfKJSvxyXrPg=;
        b=GyAJmDG0EWQLTawoC5otWyS69iZ7LLkQ5oVHhL5jLLwlXwiuiMVLPeG/FiYGz4xbAn
         vaGDc5wlM0PR4gS53qsFDq19PcVSs6KyALh75QdGNhRM8JNuNeXc879s1J0Wo38XtFmg
         +ayJZJbAroYLF1rxEzVEnQAOqjDEsS9paZVaKoG1hzzGK6m5LJ1je7J+La5rv7o6uzqg
         wI3HS7MifJNh3yPHhHuaKdVSLmkLcsNaDRKNu9/oBWUjJPvUCqAcBXbVhHskiTrj1nIe
         RHKam2sY9UWvSawQ9UHdBUV8rCxwGRY53+vo1XYV+/EYMqKEv9Vy1ZlPy/UF+ElcWZm4
         A54Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=gfwPmBXr;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=gfwPmBXr;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [195.135.223.131])
        by gmr-mx.google.com with ESMTPS id g8-20020a2eb0c8000000b002d0f87fb1c4si4031ljl.1.2024.02.16.08.52.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 16 Feb 2024 08:52:36 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted sender) client-ip=195.135.223.131;
Received: from imap1.dmz-prg2.suse.org (imap1.dmz-prg2.suse.org [10.150.64.97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id 19EED1FB73;
	Fri, 16 Feb 2024 16:52:35 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id 7C8D71398D;
	Fri, 16 Feb 2024 16:52:34 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id rjARHtKSz2X4VAAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Fri, 16 Feb 2024 16:52:34 +0000
Message-ID: <a27189a9-b0fc-4705-bdd5-3ee0a5c23dd5@suse.cz>
Date: Fri, 16 Feb 2024 17:52:34 +0100
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v3 22/35] mm/slab: enable slab allocation tagging for
 kmalloc and friends
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
 <20240212213922.783301-23-surenb@google.com>
From: Vlastimil Babka <vbabka@suse.cz>
In-Reply-To: <20240212213922.783301-23-surenb@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Spam-Level: 
X-Spam-Score: -0.35
X-Spamd-Result: default: False [-0.35 / 50.00];
	 ARC_NA(0.00)[];
	 RCVD_VIA_SMTP_AUTH(0.00)[];
	 XM_UA_NO_VERSION(0.01)[];
	 FROM_HAS_DN(0.00)[];
	 TO_DN_SOME(0.00)[];
	 FREEMAIL_ENVRCPT(0.00)[gmail.com];
	 MID_RHS_MATCH_FROM(0.00)[];
	 TAGGED_RCPT(0.00)[];
	 MIME_GOOD(-0.10)[text/plain];
	 NEURAL_HAM_LONG(-1.00)[-1.000];
	 BAYES_HAM(-0.56)[81.00%];
	 R_RATELIMIT(0.00)[to_ip_from(RL7fbg3f7cqn65nt4rpgoexbzo)];
	 RCVD_COUNT_THREE(0.00)[3];
	 DKIM_SIGNED(0.00)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	 NEURAL_HAM_SHORT(-0.20)[-1.000];
	 TO_MATCH_ENVRCPT_SOME(0.00)[];
	 RCPT_COUNT_GT_50(0.00)[73];
	 FUZZY_BLOCKED(0.00)[rspamd.com];
	 FROM_EQ_ENVFROM(0.00)[];
	 MIME_TRACE(0.00)[0:+];
	 FREEMAIL_CC(0.00)[linux.dev,suse.com,cmpxchg.org,suse.de,stgolabs.net,infradead.org,oracle.com,lwn.net,manifault.com,redhat.com,arm.com,kernel.org,arndb.de,linutronix.de,linux.intel.com,kernel.dk,soleen.com,google.com,gmail.com,chromium.org,linuxfoundation.org,linaro.org,goodmis.org,linux.com,lge.com,bytedance.com,akamai.com,android.com,vger.kernel.org,lists.linux.dev,kvack.org,googlegroups.com];
	 RCVD_TLS_ALL(0.00)[];
	 SUSPICIOUS_RECIPS(1.50)[]
X-Spam-Flag: NO
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=gfwPmBXr;       dkim=neutral
 (no key) header.i=@suse.cz header.s=susede2_ed25519;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=gfwPmBXr;       dkim=neutral
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
> Redefine kmalloc, krealloc, kzalloc, kcalloc, etc. to record allocations
> and deallocations done by these functions.
> 
> Signed-off-by: Suren Baghdasaryan <surenb@google.com>
> Co-developed-by: Kent Overstreet <kent.overstreet@linux.dev>
> Signed-off-by: Kent Overstreet <kent.overstreet@linux.dev>


> -}
> +#define kvmalloc(_size, _flags)			kvmalloc_node(_size, _flags, NUMA_NO_NODE)
> +#define kvzalloc(_size, _flags)			kvmalloc(_size, _flags|__GFP_ZERO)
>  
> -static inline __alloc_size(1, 2) void *kvmalloc_array(size_t n, size_t size, gfp_t flags)

This has __alloc_size(1, 2)

> -{
> -	size_t bytes;
> -
> -	if (unlikely(check_mul_overflow(n, size, &bytes)))
> -		return NULL;
> +#define kvzalloc_node(_size, _flags, _node)	kvmalloc_node(_size, _flags|__GFP_ZERO, _node)
>  
> -	return kvmalloc(bytes, flags);
> -}
> +#define kvmalloc_array(_n, _size, _flags)						\
> +({											\
> +	size_t _bytes;									\
> +											\
> +	!check_mul_overflow(_n, _size, &_bytes) ? kvmalloc(_bytes, _flags) : NULL;	\
> +})

But with the calculation now done in a macro, that's gone?

> -static inline __alloc_size(1, 2) void *kvcalloc(size_t n, size_t size, gfp_t flags)

Same here...

> -{
> -	return kvmalloc_array(n, size, flags | __GFP_ZERO);
> -}
> +#define kvcalloc(_n, _size, _flags)		kvmalloc_array(_n, _size, _flags|__GFP_ZERO)

... transitively?

But that's for Kees to review, I'm just not sure if he missed it or it's fine.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/a27189a9-b0fc-4705-bdd5-3ee0a5c23dd5%40suse.cz.
