Return-Path: <kasan-dev+bncBDXYDPH3S4OBBL4OXKXAMGQE4LK7ZEY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x440.google.com (mail-wr1-x440.google.com [IPv6:2a00:1450:4864:20::440])
	by mail.lfdr.de (Postfix) with ESMTPS id B8BA6856F8A
	for <lists+kasan-dev@lfdr.de>; Thu, 15 Feb 2024 22:50:40 +0100 (CET)
Received: by mail-wr1-x440.google.com with SMTP id ffacd0b85a97d-33d11dc3acasf268476f8f.3
        for <lists+kasan-dev@lfdr.de>; Thu, 15 Feb 2024 13:50:40 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1708033840; cv=pass;
        d=google.com; s=arc-20160816;
        b=JWdRYoeM9oyIcb99DYqpTL+2adFURjkf/wWbHzcXpS5Q4fM57jdKk4p+Teky8tDMwN
         pAzwQDq6JJ10jI3Ihv8ELY82LTrwIhT19QuGU1oVN3FLbPX3446mn7uB193rh/qWuIbL
         JeO+jx11RW97ml6bg5kQFbHyZiVcc+PGqVlwmURqs+TgrysverDG9mbbRDqLsV1k2SR/
         2EpqlZQacNvbqpO5+EpQLTAo5s+vc8ro0pWJV9cwG2/ITMrTu/BaTmKsSVRgENXnfyF5
         Q6qtCZ+tH61vYZRLMPeChY5hS8paIIY9lNZlDUycDc+a+16NAl534EfYxdunaGdzIlNE
         l/dw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=BM4ziJb5DOSeNDCcOb4/Jcbd2c9MO8nTuBsZ8FIKI7g=;
        fh=eWsosPhQvl3IiSwxepb2usS5twr4it9R2XvKn4jy5wU=;
        b=B4+AaVHQvmlsDcumajjgx2XdShEXQFJ9dTGnasEvmVdwd6I07dqCQ2/pVb+5w2cX+o
         tijNjjkI0ZSl0eLoEC++/1XEDccGv0q1FmPkUb0KTh9YnK6Q0f6oAt/2z5pgKReLuuHk
         9lUATW1voqjkG/p53bPGz2CThZE96MX4uUHA1lVEtgpsMj+MqBu2m0Oj6f37Yuy3rV2Q
         IArY23sjc4hVkH6Hrtp9DhLbAFX/DZufxooCe6lvMHC9uUJGWej/SxwVs0FXJXeixNk6
         LMxWXVceeBekx42YCQBi1076gvVj+SZlEwvX/K9KGzeh9kp2Z1X5bVMOfSbaWzHfdT4U
         /ogg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=Dt8snzWR;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=Dt8snzWR;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1708033840; x=1708638640; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=BM4ziJb5DOSeNDCcOb4/Jcbd2c9MO8nTuBsZ8FIKI7g=;
        b=o3e3Twx0rAJK45cHBnJ+p3DiJHrBDaCQ2/eEILcr/xG3+n1DcDSUWZg1uw5raf5FGH
         H5/McIaweAQEeZpYdwKhbUbvW3SBHSTOdCrWpZ4v/p8d5ir5zA9CJ+kpFxwbgL922P3R
         exzPRJWTvQnkZWIieOinRr61QsG+FtqcHOgYWEoLEakqgBpbO2j48Z8tBIpyyXPMM471
         6oDmcu97KzbuL/SqNIqItXACS7tIB9NhbdhdI+2inwjCY77NZTHAVAu8Jo5yRphwAwnk
         fr6yMS80CUEYCAx8KYftT+7gcKsNXcbsON6N3EdVadCOFt7CVzuJGcJwXpppd0UVlCPw
         2Ujw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1708033840; x=1708638640;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=BM4ziJb5DOSeNDCcOb4/Jcbd2c9MO8nTuBsZ8FIKI7g=;
        b=JrhtZYtsvIXP6lKkNpx3LDabxWAw5mn8JQEnDN/VLzAssjqcgWDYeE9WiIm98WQRJB
         3jgJJamDxaZOxUzfFg5kD07JZrmSlOwSq4d479UOc5Bc+I10nnCHi6TlG7qAb5nIgdFJ
         27IsYiFxhsDl+nK9j2I738PKGMzBOAi5/Y6W5bNG4ikkRNpz6JOQwTkoOHoDDuIJCqKi
         vQvcaAMUbke71tRq0EZucW0z8pnyVLXX6w6eVbV9O9wLr3ogB/J/nDOqk9jBcDR4NDb0
         4vlGF+S1U9/ksqEg59PjENlseqxLrrQnwzjA8cPu4f3+Wt4VsrZgE5V4tjK5Yj959lJL
         tbKA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWYydfQQVf7Kkbe3KNbNv0T8sWElwxbIlUC8aiGnZFLk85ZrPCJdoEMC/+HeoghzZhwS+wTdBelZOo2svBMiD5KqIAs7EwLdg==
X-Gm-Message-State: AOJu0YxxIKLjqLhUF2CLCNoiPaRRG7CUBlh0CSkU8pqfBkR5Cpo9MVE3
	KAXDMy9QCkXBG7bD4H224vAmepafUSxIOQog7iNTP8UDso5Yo5vy
X-Google-Smtp-Source: AGHT+IGk9BUrlwlMeN4/HkY8PrOQ6Rrl6QW7rc0zHs+akGP7ASueo8lw+n2EDuzkaRJDG7AyhsaKug==
X-Received: by 2002:a5d:40d2:0:b0:33b:7353:b632 with SMTP id b18-20020a5d40d2000000b0033b7353b632mr2355328wrq.50.1708033839900;
        Thu, 15 Feb 2024 13:50:39 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:6648:0:b0:33b:5251:b7f5 with SMTP id f8-20020a5d6648000000b0033b5251b7f5ls49579wrw.1.-pod-prod-05-eu;
 Thu, 15 Feb 2024 13:50:38 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXVL+Sd6m18F6vBi3Jd+LD3KFmt/pyUmKPAIDv7XCgxJuFKqlUW9UHi5csfD/5IZiNgErXvdiAiovnZ4z7b0E06T3bBmmxAOsudaA==
X-Received: by 2002:a5d:65c3:0:b0:33d:1322:249f with SMTP id e3-20020a5d65c3000000b0033d1322249fmr1155995wrw.65.1708033838250;
        Thu, 15 Feb 2024 13:50:38 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1708033838; cv=none;
        d=google.com; s=arc-20160816;
        b=ggocUO274RahBqOujV2WJYIJYOLzTUvwQ+3NtXqTgzGnzcm+WM+Hb4Y/oUogiO4dx5
         3+gpUb/DayjCyhhQWgmjLdcwsgOCvpqdK5LHznRxupx3DswmJD8psheE2z+dq2MfYJE3
         +2Ylqd/RSukLaIR4L0suikxqB2Js+RZ2e3e/xCAOdqONe5NztJSfrL10vMClXiQjco11
         ReD3MTOIepChRPzPBWKrDh0CuHmdd7XrcSbZ00UDSowvczlsgsWEHuS3sAecBr0MnQwd
         0ZZiL9JHHsGqidqRYC+H1gxAwbSzaJNS/bbqX8ug+ZvvlvDhFcxyf4bAf2u5ZT5gKxIQ
         4Fqw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature:dkim-signature:dkim-signature;
        bh=PV2jhmuXtgna00Xa5XigbZslr56lI5Yx29VeaYM+7Zs=;
        fh=zavD0TZeR4oKBqoke+TEUomG+ov54Cafv7cv0und6TU=;
        b=Y3CQnMccdKvNQn796wYsA/FUhd9/rl/xanrE1+KGBh1JapOJz3r/TDgwO8ysJFTxPQ
         LrINsMDe4bPDBXCF9XKba/tcNNiBCBib2dSdJw1S1M/Id4+TTQS1rfRbettvdT0EcPBJ
         cKiFM2Mir2aXHyN2ML/4TUwtjkvuyOoFzwv23UpXUCiE6Y3b9eYCJZ7LY8qjG/O2H45k
         4eFRp5kcO+S0+vxSZW+UloQH6Lh37m/oyWXEK1ZPqMjTM2v5SXmIOrWmFUCASGhU2LD9
         dmEc17gjjQXyDwuGJEUg2ajZwdp1y5cNpOlsGRQnsZO/wbEN7X6vHJLhYaAj3JcRHHNA
         ghjg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=Dt8snzWR;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=Dt8snzWR;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [195.135.223.131])
        by gmr-mx.google.com with ESMTPS id v17-20020a5d6111000000b0033d13ee490fsi11730wrt.2.2024.02.15.13.50.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 15 Feb 2024 13:50:38 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted sender) client-ip=195.135.223.131;
Received: from imap1.dmz-prg2.suse.org (imap1.dmz-prg2.suse.org [10.150.64.97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id C20A71FB3D;
	Thu, 15 Feb 2024 21:50:37 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id 3743813A82;
	Thu, 15 Feb 2024 21:50:37 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id 6IIYDS2HzmWgTgAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Thu, 15 Feb 2024 21:50:37 +0000
Message-ID: <ab4b1789-910a-4cd6-802c-5012bf9d8984@suse.cz>
Date: Thu, 15 Feb 2024 22:50:36 +0100
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v3 07/35] mm/slab: introduce SLAB_NO_OBJ_EXT to avoid
 obj_ext creation
Content-Language: en-US
To: Kent Overstreet <kent.overstreet@linux.dev>
Cc: Suren Baghdasaryan <surenb@google.com>, akpm@linux-foundation.org,
 mhocko@suse.com, hannes@cmpxchg.org, roman.gushchin@linux.dev,
 mgorman@suse.de, dave@stgolabs.net, willy@infradead.org,
 liam.howlett@oracle.com, corbet@lwn.net, void@manifault.com,
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
References: <20240212213922.783301-1-surenb@google.com>
 <20240212213922.783301-8-surenb@google.com>
 <fbfab72f-413d-4fc1-b10b-3373cfc6c8e9@suse.cz>
 <tbqg7sowftykfj3rptpcbewoiy632fbgbkzemgwnntme4wxhut@5dlfmdniaksr>
From: Vlastimil Babka <vbabka@suse.cz>
In-Reply-To: <tbqg7sowftykfj3rptpcbewoiy632fbgbkzemgwnntme4wxhut@5dlfmdniaksr>
Content-Type: text/plain; charset="UTF-8"
X-Spamd-Result: default: False [1.41 / 50.00];
	 ARC_NA(0.00)[];
	 RCVD_VIA_SMTP_AUTH(0.00)[];
	 XM_UA_NO_VERSION(0.01)[];
	 FROM_HAS_DN(0.00)[];
	 TO_DN_SOME(0.00)[];
	 FREEMAIL_ENVRCPT(0.00)[gmail.com];
	 MID_RHS_MATCH_FROM(0.00)[];
	 TAGGED_RCPT(0.00)[];
	 MIME_GOOD(-0.10)[text/plain];
	 BAYES_HAM(-0.00)[35.88%];
	 R_RATELIMIT(0.00)[to_ip_from(RL7fbg3f7cqn65nt4rpgoexbzo)];
	 RCVD_COUNT_THREE(0.00)[3];
	 DKIM_SIGNED(0.00)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	 TO_MATCH_ENVRCPT_SOME(0.00)[];
	 RCPT_COUNT_GT_50(0.00)[73];
	 FUZZY_BLOCKED(0.00)[rspamd.com];
	 FROM_EQ_ENVFROM(0.00)[];
	 MIME_TRACE(0.00)[0:+];
	 FREEMAIL_CC(0.00)[google.com,linux-foundation.org,suse.com,cmpxchg.org,linux.dev,suse.de,stgolabs.net,infradead.org,oracle.com,lwn.net,manifault.com,redhat.com,arm.com,kernel.org,arndb.de,linutronix.de,linux.intel.com,kernel.dk,soleen.com,gmail.com,chromium.org,linuxfoundation.org,linaro.org,goodmis.org,linux.com,lge.com,bytedance.com,akamai.com,android.com,vger.kernel.org,lists.linux.dev,kvack.org,googlegroups.com];
	 RCVD_TLS_ALL(0.00)[];
	 SUSPICIOUS_RECIPS(1.50)[]
X-Spam-Level: *
X-Spam-Score: 1.41
X-Spam-Flag: NO
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=Dt8snzWR;       dkim=neutral
 (no key) header.i=@suse.cz header.s=susede2_ed25519;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=Dt8snzWR;       dkim=neutral
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

On 2/15/24 22:37, Kent Overstreet wrote:
> On Thu, Feb 15, 2024 at 10:31:06PM +0100, Vlastimil Babka wrote:
>> On 2/12/24 22:38, Suren Baghdasaryan wrote:
>> > Slab extension objects can't be allocated before slab infrastructure is
>> > initialized. Some caches, like kmem_cache and kmem_cache_node, are created
>> > before slab infrastructure is initialized. Objects from these caches can't
>> > have extension objects. Introduce SLAB_NO_OBJ_EXT slab flag to mark these
>> > caches and avoid creating extensions for objects allocated from these
>> > slabs.
>> > 
>> > Signed-off-by: Suren Baghdasaryan <surenb@google.com>
>> > ---
>> >  include/linux/slab.h | 7 +++++++
>> >  mm/slub.c            | 5 +++--
>> >  2 files changed, 10 insertions(+), 2 deletions(-)
>> > 
>> > diff --git a/include/linux/slab.h b/include/linux/slab.h
>> > index b5f5ee8308d0..3ac2fc830f0f 100644
>> > --- a/include/linux/slab.h
>> > +++ b/include/linux/slab.h
>> > @@ -164,6 +164,13 @@
>> >  #endif
>> >  #define SLAB_TEMPORARY		SLAB_RECLAIM_ACCOUNT	/* Objects are short-lived */
>> >  
>> > +#ifdef CONFIG_SLAB_OBJ_EXT
>> > +/* Slab created using create_boot_cache */
>> > +#define SLAB_NO_OBJ_EXT         ((slab_flags_t __force)0x20000000U)
>> 
>> There's
>>    #define SLAB_SKIP_KFENCE        ((slab_flags_t __force)0x20000000U)
>> already, so need some other one?
> 
> What's up with the order of flags in that file? They don't seem to
> follow any particular ordering.

Seems mostly in increasing order, except commit 4fd0b46e89879 broke it for
SLAB_RECLAIM_ACCOUNT?

> Seems like some cleanup is in order, but any history/context we should
> know first?

Yeah noted, but no need to sidetrack you.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ab4b1789-910a-4cd6-802c-5012bf9d8984%40suse.cz.
