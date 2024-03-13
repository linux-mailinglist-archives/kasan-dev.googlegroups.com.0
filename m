Return-Path: <kasan-dev+bncBDXYDPH3S4OBBHW7Y2XQMGQEF7ILPNI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13e.google.com (mail-lf1-x13e.google.com [IPv6:2a00:1450:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id 5002487A8BB
	for <lists+kasan-dev@lfdr.de>; Wed, 13 Mar 2024 14:52:32 +0100 (CET)
Received: by mail-lf1-x13e.google.com with SMTP id 2adb3069b0e04-512e5939c7csf10078e87.1
        for <lists+kasan-dev@lfdr.de>; Wed, 13 Mar 2024 06:52:32 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1710337951; cv=pass;
        d=google.com; s=arc-20160816;
        b=RKmSFk3Eum9PuiovAr6SL8TTUkdxZjeyXOo4PVU3uFcwbqq3q20oxSuW7fnEsKbBTn
         Xpr40nATLX/tQjrS6y6s0uGU+MFLVYA+n+/rCe5Dax3vNHqislJ9l1m2UsYU/kO4PRBP
         DmYydKDQsoX3ar+oyvLr9K78GPxTNpWfSHD0ylxL2phT+dchKuXbzO8A3A3t0S6U+CQ1
         Ou7/fnbbnbCgQUria+xBxIKBBj0nQ7mpmaqEhxa5TT6Z+Qm9wU/Yry62JJzwoyTV16d4
         xu45NjZ4tOtcOLaRWRSDbodMfFvIZm+ypTLUQgKgtyBu8q6m6FHqQGLE5XF+uZLe1jj0
         NCrg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=H7tz7uhLPa23ua4DoPzTx8LtZQxeSFXpFJhq0BUdFcA=;
        fh=cUCcOh9H7zq+tJQ0cP746M+ZmrPXk0Bnk55KDk00Qfo=;
        b=vP6xisMGyZCRH8tmHoL9/LnGDPYPcPWmtWfLCmKhCSRiYRav41Jrpm/nSlF3FFKcXL
         158G1Tv9UtwTf/WU5G9z8fg0oUhamnki7SAt2W4N/hoGnUyeo4zQoABvLj0+PlxgofDI
         DV0m69JgXGCE3E0uL+CUfhdpr8+5Q1QVrNptlNRMb4cadLFd/Tv84tdVAzUSPV/9i0sb
         /YeZJIzlLsQYtGE9zjIYRbFKVSxATrTAMgmdU63n5C8agr5zmzjbBOiWH1Z5DVoVb6QN
         r7o0Hn0VXGZ3GGiWPK0/kOengHpIh9PpMqY+iVnoIxI7DQv0YcpA2iDaAceY3WBV7amF
         +MVQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=Maisu8p+;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=Maisu8p+;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1710337951; x=1710942751; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:content-language:references:cc
         :to:subject:user-agent:mime-version:date:message-id:sender:from:to
         :cc:subject:date:message-id:reply-to;
        bh=H7tz7uhLPa23ua4DoPzTx8LtZQxeSFXpFJhq0BUdFcA=;
        b=ukf7rXWzHauXiDUAjBGwf4bmfEEvTa2nQrHePe3bQeVkTVVHkKm7UmIzG7GXKDeu2q
         RJzIyHnu7I3mN9xt42eJIIx6h552YT7A2x/DXRDjBYXCdP/uxULAX6GBLjvORmn3E2HS
         5icIACD9OJxKF/qbeAw63J+HitURhRC7QkCADEmsVbNCB/7wEObty9hmWfwCZ/CufxKP
         58GJOMFPaC1ixqdaqPyoCTNOSTivcxZa5pmkfGbNPHNKsKL1c3tlEC6j/U3Jmof2qH18
         RDCqdjVScP5LuS3dwzqLeoAytCTfgFEXQFiq0pQyi2pysFYOKTOhBpyWtLMJyCrsN9Ss
         W/yQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1710337951; x=1710942751;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:content-language:references:cc:to:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=H7tz7uhLPa23ua4DoPzTx8LtZQxeSFXpFJhq0BUdFcA=;
        b=XxqS4XqBFMkMIPlCvv9SA0XPuKN6KwZJPYWhUubqhxR8ThZzwd3L8XN69ECOH4QJwF
         RM1jn5fuuiVLtRPJ8QaKZ/Qaq4iNTqU+HC9CUPuGsFO7l/lBlOyGUFjItI0xi1bdYhX3
         0J03pmxsfsNTPjyhdzjs4OQS2Gi4QeMhFaX+wukNGnwaBFBiV6xYL/e0B3EhlYWPS6wR
         2j8f9MnTgcVXfTsuUBmP1cheuKIIPUDg8+NKbCahP9IgO8iYXRPGiqXvKnJ0C/1DbjX7
         RG8UQkgkeQ6IPRKgMnyqf+2yPSnqbDjCoRZELRS4LzeyP4xXLixgj7r2Y541v1R9ZNrI
         TENQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVhaRpDkzq8YqavQ9710qM2oa6x2CMJQ370tuNYF33WThzQCQkHVrsBmKoAwpsjKUapzrTYVus6D6ndz9ZlGUBUMHCOh8dJnw==
X-Gm-Message-State: AOJu0YyigE73/anv4kKHJecUcr008rt9wusapOCekZ3cAck/qSYxNLGW
	DHvjwJ/v+HslFYoOK3SCBz63/MknjTqh3x/YLBAWJYLiON8fTUy9
X-Google-Smtp-Source: AGHT+IEpvI+rxwwDsiUaLPnPSWk7pxfSsZSv4f9Y/WWDr0rsrxXSGtxU7wGsZglZpIkUBSwtlxcP+A==
X-Received: by 2002:a05:6512:398c:b0:513:cce1:89ea with SMTP id j12-20020a056512398c00b00513cce189eamr9395lfu.3.1710337951076;
        Wed, 13 Mar 2024 06:52:31 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:4016:b0:513:1cf6:5526 with SMTP id
 br22-20020a056512401600b005131cf65526ls687159lfb.0.-pod-prod-03-eu; Wed, 13
 Mar 2024 06:52:29 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCX2M0dYiA3PgBNQ7l8bk1BsCy1VYop/cmQFo7Zx9b1h8t9/5IfRcSx5cgQpWB0HnIVw2e6OqimEYEwgatLvrCRsrXshz6VFbWih1Q==
X-Received: by 2002:a19:740c:0:b0:513:36f7:98cc with SMTP id v12-20020a19740c000000b0051336f798ccmr2211463lfe.55.1710337949124;
        Wed, 13 Mar 2024 06:52:29 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1710337949; cv=none;
        d=google.com; s=arc-20160816;
        b=Hvwld47P5krwQ0PcQPw03MZOWJGjwNJ8OZSIs5w1EVINBUdgKyIxwkP1O1hCcwe0Tb
         ZTOekaaOh3WGIC362/I4zzMUVB5zHMg4OiAx9u0dyZdeZcvoC+4d0+PsR+c7pXXGZQ1J
         Y09EprL4dV8E9/ypG70UG9IczyJeaeT/Ccp89ROq/qd6a23pKbx5+8zpFM+6lXxjVETN
         n7LZU2dxaqyTxlwzMnRlh8LWvbeJxSTndrV+zUT06RBSuOoCoMzbGgdphZ6iZwL5Nd+t
         +QV/EtwanVfkuqCbbLPbSNAViqd8Aol5d3IBQOSEj4syZrqVjRpiTt7oS65TO6ENJpTN
         ttOQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature:dkim-signature:dkim-signature;
        bh=XFhbbMRYCJAgLqELLxWLqfsH3hbHEF1BH4hx+bhAMaM=;
        fh=Q5QK3mEHpiSw50+k3en+vN00KR+pxr1dxz1JLzJfHmQ=;
        b=R/MGM0c1J0d2FR+7L1oRGDDpBycs4onMDnhSYHbTB79y2ZJA4qmHeZo8lAePFGclmo
         4I8HX7HJvj+QPvDDqGwb6ZhsjtW6Vxr4HtgpTZdjDyipsH82Qz10aAv20y43V0T8za4k
         O/YOfFQcuSjxNDkkBxtikHE8bD1BCgnWHM9a5T20queofDFCiHBu6CHNJAxa0r4BOWL8
         xQUfsF/oe+fk/jhDVZ5O33jv49r5xZbT1VRFyX204YN10PQutP1zU4H4xKdSj6+MWKNp
         cyLeQdxrr036VRSShePuDONknRFKBNdPZqAA5YqmqMRyex4AaByCfpGbDpHeUVARwBai
         YU4Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=Maisu8p+;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=Maisu8p+;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [195.135.223.131])
        by gmr-mx.google.com with ESMTPS id b24-20020a056512061800b005132cbccbb3si569285lfe.7.2024.03.13.06.52.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 13 Mar 2024 06:52:29 -0700 (PDT)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted sender) client-ip=195.135.223.131;
Received: from imap1.dmz-prg2.suse.org (imap1.dmz-prg2.suse.org [10.150.64.97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id 20C701F7CD;
	Wed, 13 Mar 2024 13:52:28 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id AAB161397F;
	Wed, 13 Mar 2024 13:52:27 +0000 (UTC)
Received: from dovecot-director2.suse.de ([10.150.64.162])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id E5Z1KZuv8WWIVAAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Wed, 13 Mar 2024 13:52:27 +0000
Message-ID: <b4e5a48f-9a43-4f80-a3e7-75c04dba9a0f@suse.cz>
Date: Wed, 13 Mar 2024 14:53:08 +0100
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v5 03/37] mm/slub: Mark slab_free_freelist_hook()
 __always_inline
To: Suren Baghdasaryan <surenb@google.com>, akpm@linux-foundation.org
Cc: kent.overstreet@linux.dev, mhocko@suse.com, hannes@cmpxchg.org,
 roman.gushchin@linux.dev, mgorman@suse.de, dave@stgolabs.net,
 willy@infradead.org, liam.howlett@oracle.com,
 penguin-kernel@i-love.sakura.ne.jp, corbet@lwn.net, void@manifault.com,
 peterz@infradead.org, juri.lelli@redhat.com, catalin.marinas@arm.com,
 will@kernel.org, arnd@arndb.de, tglx@linutronix.de, mingo@redhat.com,
 dave.hansen@linux.intel.com, x86@kernel.org, peterx@redhat.com,
 david@redhat.com, axboe@kernel.dk, mcgrof@kernel.org, masahiroy@kernel.org,
 nathan@kernel.org, dennis@kernel.org, jhubbard@nvidia.com, tj@kernel.org,
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
 aliceryhl@google.com, rientjes@google.com, minchan@google.com,
 kaleshsingh@google.com, kernel-team@android.com, linux-doc@vger.kernel.org,
 linux-kernel@vger.kernel.org, iommu@lists.linux.dev,
 linux-arch@vger.kernel.org, linux-fsdevel@vger.kernel.org,
 linux-mm@kvack.org, linux-modules@vger.kernel.org,
 kasan-dev@googlegroups.com, cgroups@vger.kernel.org
References: <20240306182440.2003814-1-surenb@google.com>
 <20240306182440.2003814-4-surenb@google.com>
Content-Language: en-US
From: Vlastimil Babka <vbabka@suse.cz>
In-Reply-To: <20240306182440.2003814-4-surenb@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Spam-Level: 
X-Spam-Score: -2.78
X-Spamd-Result: default: False [-2.78 / 50.00];
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
	 BAYES_HAM(-2.99)[99.94%];
	 R_RATELIMIT(0.00)[to_ip_from(RL7fbg3f7cqn65nt4rpgoexbzo)];
	 RCVD_COUNT_THREE(0.00)[3];
	 DKIM_SIGNED(0.00)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	 NEURAL_HAM_SHORT(-0.20)[-1.000];
	 TO_MATCH_ENVRCPT_SOME(0.00)[];
	 RCPT_COUNT_GT_50(0.00)[76];
	 DBL_BLOCKED_OPENRESOLVER(0.00)[suse.cz:email];
	 FUZZY_BLOCKED(0.00)[rspamd.com];
	 FROM_EQ_ENVFROM(0.00)[];
	 MIME_TRACE(0.00)[0:+];
	 FREEMAIL_CC(0.00)[linux.dev,suse.com,cmpxchg.org,suse.de,stgolabs.net,infradead.org,oracle.com,i-love.sakura.ne.jp,lwn.net,manifault.com,redhat.com,arm.com,kernel.org,arndb.de,linutronix.de,linux.intel.com,kernel.dk,nvidia.com,soleen.com,google.com,gmail.com,chromium.org,linuxfoundation.org,linaro.org,goodmis.org,linux.com,lge.com,bytedance.com,akamai.com,android.com,vger.kernel.org,lists.linux.dev,kvack.org,googlegroups.com];
	 RCVD_TLS_ALL(0.00)[];
	 SUSPICIOUS_RECIPS(1.50)[]
X-Spam-Flag: NO
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=Maisu8p+;       dkim=neutral
 (no key) header.i=@suse.cz header.s=susede2_ed25519;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=Maisu8p+;       dkim=neutral
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

On 3/6/24 19:24, Suren Baghdasaryan wrote:
> From: Kent Overstreet <kent.overstreet@linux.dev>
> 
> It seems we need to be more forceful with the compiler on this one.
> This is done for performance reasons only.
> 
> Signed-off-by: Kent Overstreet <kent.overstreet@linux.dev>
> Signed-off-by: Suren Baghdasaryan <surenb@google.com>
> Reviewed-by: Kees Cook <keescook@chromium.org>
> Reviewed-by: Pasha Tatashin <pasha.tatashin@soleen.com>

Reviewed-by: Vlastimil Babka <vbabka@suse.cz>

> ---
>  mm/slub.c | 6 +++---
>  1 file changed, 3 insertions(+), 3 deletions(-)
> 
> diff --git a/mm/slub.c b/mm/slub.c
> index 2ef88bbf56a3..0f3369f6188b 100644
> --- a/mm/slub.c
> +++ b/mm/slub.c
> @@ -2121,9 +2121,9 @@ bool slab_free_hook(struct kmem_cache *s, void *x, bool init)
>  	return !kasan_slab_free(s, x, init);
>  }
>  
> -static inline bool slab_free_freelist_hook(struct kmem_cache *s,
> -					   void **head, void **tail,
> -					   int *cnt)
> +static __fastpath_inline
> +bool slab_free_freelist_hook(struct kmem_cache *s, void **head, void **tail,
> +			     int *cnt)
>  {
>  
>  	void *object;

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/b4e5a48f-9a43-4f80-a3e7-75c04dba9a0f%40suse.cz.
