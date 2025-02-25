Return-Path: <kasan-dev+bncBDXYDPH3S4OBBPMP7C6QMGQELAQA2AI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33c.google.com (mail-wm1-x33c.google.com [IPv6:2a00:1450:4864:20::33c])
	by mail.lfdr.de (Postfix) with ESMTPS id 2CA87A449BB
	for <lists+kasan-dev@lfdr.de>; Tue, 25 Feb 2025 19:11:11 +0100 (CET)
Received: by mail-wm1-x33c.google.com with SMTP id 5b1f17b1804b1-4393e89e910sf32799295e9.0
        for <lists+kasan-dev@lfdr.de>; Tue, 25 Feb 2025 10:11:11 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1740507070; cv=pass;
        d=google.com; s=arc-20240605;
        b=QcphxF8A66EOCefZoOOIk6LoC1Cgv1QTjhBvNnXLuFMpcKTV8AE0Dsf3aVojmMLfJi
         f6mzIBZd1/NqEf5/imb9uoxckV0DHjbares6vt6hpPmCVhCN9bZSbpffojAlCQwssToY
         6wjlGFnFuUKzjdBycXhc6y2DehutVpf3kNBX+0yNcnzMCMe+JbnJ9TINPFo2M7OpF3Ae
         4kFFAf/3vGu9uCjp4upHaJ2n/K778azmUg6/thjLY51IwYkUARkgdR8v2zXyZ3yp8i6d
         iHphGUCmLgS2OAa2CqTNa6GhpBHVzTODyyWqJ1o2TYuC5mwDV7S/AzBOpTsyv9LISFtt
         5IJQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:autocrypt:from
         :references:cc:to:content-language:subject:user-agent:mime-version
         :date:message-id:sender:dkim-signature;
        bh=AfeuNTv8wIyJTxUL6RRZOGmQ8DR+XLUZVSxv4LknpH0=;
        fh=5FC5zk6uza5+CVgQUIMDkxAA/iayP50a5Iu/lUBrjvo=;
        b=Vl+t2P+lyMjp/IGseX0Uu1mFtZjFJBJlpt8XYyA109CLPE9XiOap647/gEkycacVsP
         JUcgAOFQWEghybVam8E1Dy+ccrspOBhLWbZXlpAPhm70nwnDEvrf9R4wV43KJEe7XqJb
         +/OjLcNHPekCdsiZ/MR/W18pWZtj+8wpu39CYRJLkkZ0xNNiTT2JPeKgnfsRoRBTVkoJ
         mbz9UkG4phTUorPsKl5IMPxzgozVCkjvSjPZ/lZMofLq1e2V4gkGg8hpg7DZZnLb1XEH
         VCe5X4fkwJWHMz0TR9tC0Qyi3vANBtE6e02/V5H7UbgdwngJgKRTCqEMjWS3Gasygr3d
         Ge/Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=gL7SEbso;
       dkim=neutral (no key) header.i=@suse.cz;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=gL7SEbso;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1740507070; x=1741111870; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:autocrypt:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=AfeuNTv8wIyJTxUL6RRZOGmQ8DR+XLUZVSxv4LknpH0=;
        b=xcjljDgGXG7T3pZay4WLHqUPYWiPd81/Gk7LKo9cpE81BX71CTuDEgzKOduHE2N3jg
         x4YyLUC9+0fxiKNHqSthApxPzMX+r0jQob3DuVYNKZJ+rX2WU7p4NxhFpqzOnpymI1QO
         JckBwpNyhKdnAnwX8CceGor1fMMQWOCSnK0vSbN2gcfqO4CXku2XNlhrhIvW2wlOm31F
         0Ms9T9AtG1oMd8+L+FkHno39LzCQ/V5kdZz1bwsnJzJxnJc1cJE2snOb2Q7jTAlH0snx
         occpwVGOG7IYxjGZpA6grBKmwvdvCEf4+nhFdgsXgux/3JpUf1iqKkityZh4rIVhOB/2
         Wtcw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1740507070; x=1741111870;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :autocrypt:from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=AfeuNTv8wIyJTxUL6RRZOGmQ8DR+XLUZVSxv4LknpH0=;
        b=f8djrt654jkUN7U4I14Vy8Xg3ZjkRgaIgLvGBtgWBy9wjgPH8aY865mfI1TVmHfTuo
         gG2rzP5WPkkNwBaE3PdVr0Mr6xMRtSoA/aP0M3hhIvBsD3wDqQMXVuM65huuLKxO0WSX
         CJl3tlSbhr5HxN1ZslWEQT16rl8R/SnZmPR55uMpH2UhyW+kOfKkhZtvko0TOq34qXrs
         8vBcqKu8GwYlj2GjeMrTOEDkrtqTfjiactIWF6V9SUcbvgjP57BlhZmvfJakj05llKk5
         jzUER6+vnXrG/6dNVJbFChhk0VTBjULwbS2O7J28klPmpzMSkMFovJMMqJaKSKCaEERf
         NwAA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWKhnHmIyZB4eMraTUbR7+/QHOumaYqqOrnyIseAItBySkuIbYjo6KZqy/Ou45RUh/NuggeGg==@lfdr.de
X-Gm-Message-State: AOJu0YwBGhVqMkjfftX8QiAOsKfx91/So6ng8TL79qcIjhZ2rXvTrUCE
	//vySPKxa6IjdyhAJLChaOe+X8f/4xdHK6SiFOZzt/2lszQz6eOK
X-Google-Smtp-Source: AGHT+IEx3HSDb7Odb8hQlbJojplq6F4fF3ML8w5uom+fCQ8btXB5vKNfz6/PsY5actHnwZJ2XdCB/Q==
X-Received: by 2002:a05:600c:35cb:b0:439:942c:c1cd with SMTP id 5b1f17b1804b1-43ab0f41698mr40645695e9.15.1740507069670;
        Tue, 25 Feb 2025 10:11:09 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h=Adn5yVH0rjYGyw6/x/7QHhb85KDlQBqkqMkp2PpiKowUCRfgZQ==
Received: by 2002:a05:600c:19c6:b0:439:8ba7:4b1f with SMTP id
 5b1f17b1804b1-43ab12da72bls5102575e9.1.-pod-prod-06-eu; Tue, 25 Feb 2025
 10:11:07 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWnkU8zhytD/ZoqzSpP+dSvlRbuYnAVhICwTjoIxDg47YjF4EY8qWTmi3Ri9Zqzbopl1pGLaU0ZO6s=@googlegroups.com
X-Received: by 2002:a05:600c:5487:b0:439:9863:e876 with SMTP id 5b1f17b1804b1-43ab75011bbmr13591925e9.24.1740507067291;
        Tue, 25 Feb 2025 10:11:07 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1740507067; cv=none;
        d=google.com; s=arc-20240605;
        b=Lyqy7c5V53BsEFBUrxmhX/PbTRKAUQZq9WhZrBvEk2DdnCzpKGdTLpkUgy+3tclRfY
         ZE3doRYGlRzngaj1hYsyCvfHqwZinAxlpFPokZwQS4WaGCNWtOrRpSWmo8cY2imJipmB
         u8mt/RKhpgDSgyFM3vc7XiGRgqsWRzj0DAIKrbITXaMHgBQr/TH8IY6UWKQeLonYK7J9
         2AoWY0cQC90Ggr8dCVEc2yljkwROCM8Cb/v+wtK2/43EWM2K9uvAC4qn/Q0LrdyDnmZq
         SiyHXmz1ijt/x/xfxcWNmslnKQ9BW0yygubU5A6GePvTEaJNGubZNw86fMAsFU+yHnUr
         +crQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:autocrypt:from:references:cc
         :to:content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature:dkim-signature:dkim-signature;
        bh=5d/50A6zDnaZCHQYaZpq4chtHF+j1x/FzEEM/FXjYu8=;
        fh=sGQxV+Ls1Ivp3fL0+oIOF/WUu9JfdgutgYrv3phwnY8=;
        b=V2XYipoJvLAUDZIOKHPwOG5YsvIEIGzvv7ihdvFA4XDBOWXSAiigEi1mgbJS78IkAD
         7IadSrvDiodvKoYSsUQmkVfCS3+5CG9KLlSFJkh4YzsJp3PH/ChGT/CIzbcWuOTeuzSl
         B2NZ465CBV56y7y2ybFFm5fB6I3qbfVg2jFyh4y8ag8NkzxtrA1QJAKb+IdA7ZYRE4rQ
         PRBmd/W9+9kSddrJC8wzBsPnbE4+YQOcn2EobPoLs8iPq6Di+vl2u5ZMaUkQ5/XugmbW
         xkUZYIuhDdwzAE6nRZ60jQThAkXUTsBwTgZYUDpOim4d2eZBayq9+g9ELXU8smlPE/uS
         RzAQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=gL7SEbso;
       dkim=neutral (no key) header.i=@suse.cz;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=gL7SEbso;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [195.135.223.131])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-43ab2c4a57asi2738315e9.0.2025.02.25.10.11.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 25 Feb 2025 10:11:07 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted sender) client-ip=195.135.223.131;
Received: from imap1.dmz-prg2.suse.org (unknown [10.150.64.97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id AF68B1F44F;
	Tue, 25 Feb 2025 18:11:06 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id 6EB0113888;
	Tue, 25 Feb 2025 18:11:06 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id 2mdtGroHvmeZWwAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Tue, 25 Feb 2025 18:11:06 +0000
Message-ID: <cca361c8-2f03-40b9-872c-0949dc70cde8@suse.cz>
Date: Tue, 25 Feb 2025 19:11:05 +0100
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v2 6/7] mm, slab: call kvfree_rcu_barrier() from
 kmem_cache_destroy()
Content-Language: en-US
To: Uladzislau Rezki <urezki@gmail.com>, Keith Busch <keith.busch@gmail.com>
Cc: "Paul E. McKenney" <paulmck@kernel.org>,
 Joel Fernandes <joel@joelfernandes.org>,
 Josh Triplett <josh@joshtriplett.org>, Boqun Feng <boqun.feng@gmail.com>,
 Christoph Lameter <cl@linux.com>, David Rientjes <rientjes@google.com>,
 Steven Rostedt <rostedt@goodmis.org>,
 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>,
 Lai Jiangshan <jiangshanlai@gmail.com>, Zqiang <qiang.zhang1211@gmail.com>,
 Julia Lawall <Julia.Lawall@inria.fr>, Jakub Kicinski <kuba@kernel.org>,
 "Jason A. Donenfeld" <Jason@zx2c4.com>,
 Andrew Morton <akpm@linux-foundation.org>,
 Roman Gushchin <roman.gushchin@linux.dev>,
 Hyeonggon Yoo <42.hyeyoo@gmail.com>, linux-mm@kvack.org,
 linux-kernel@vger.kernel.org, rcu@vger.kernel.org,
 Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>,
 Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com,
 Jann Horn <jannh@google.com>, Mateusz Guzik <mjguzik@gmail.com>,
 linux-nvme@lists.infradead.org, leitao@debian.org
References: <20240807-b4-slab-kfree_rcu-destroy-v2-0-ea79102f428c@suse.cz>
 <20240807-b4-slab-kfree_rcu-destroy-v2-6-ea79102f428c@suse.cz>
 <Z7iqJtCjHKfo8Kho@kbusch-mbp> <2811463a-751f-4443-9125-02628dc315d9@suse.cz>
 <Z7xbrnP8kTQKYO6T@pc636> <ef97428b-f6e7-481e-b47e-375cc76653ad@suse.cz>
 <Z73p2lRwKagaoUnP@kbusch-mbp>
 <CAOSXXT6-oWjKPV1hzXa5Ra4SPQg0L_FvxCPM0Sh0Yk6X90h0Sw@mail.gmail.com>
 <Z74Av6tlSOqcfb-q@pc636>
From: Vlastimil Babka <vbabka@suse.cz>
Autocrypt: addr=vbabka@suse.cz; keydata=
 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
 EP+ylKVEKb0Q2A==
In-Reply-To: <Z74Av6tlSOqcfb-q@pc636>
Content-Type: text/plain; charset="UTF-8"
X-Spam-Score: -2.80
X-Spamd-Result: default: False [-2.80 / 50.00];
	BAYES_HAM(-3.00)[99.99%];
	SUSPICIOUS_RECIPS(1.50)[];
	NEURAL_HAM_LONG(-1.00)[-1.000];
	NEURAL_HAM_SHORT(-0.20)[-1.000];
	MIME_GOOD(-0.10)[text/plain];
	TAGGED_RCPT(0.00)[];
	RCVD_TLS_ALL(0.00)[];
	MIME_TRACE(0.00)[0:+];
	RCPT_COUNT_TWELVE(0.00)[29];
	RCVD_VIA_SMTP_AUTH(0.00)[];
	ARC_NA(0.00)[];
	FREEMAIL_TO(0.00)[gmail.com];
	FREEMAIL_ENVRCPT(0.00)[gmail.com];
	TO_DN_SOME(0.00)[];
	FROM_HAS_DN(0.00)[];
	FREEMAIL_CC(0.00)[kernel.org,joelfernandes.org,joshtriplett.org,gmail.com,linux.com,google.com,goodmis.org,efficios.com,inria.fr,zx2c4.com,linux-foundation.org,linux.dev,kvack.org,vger.kernel.org,googlegroups.com,lists.infradead.org,debian.org];
	MID_RHS_MATCH_FROM(0.00)[];
	FROM_EQ_ENVFROM(0.00)[];
	RCVD_COUNT_TWO(0.00)[2];
	TO_MATCH_ENVRCPT_ALL(0.00)[];
	DKIM_SIGNED(0.00)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	R_RATELIMIT(0.00)[to_ip_from(RLjmiudjgfgtmtcfdjcm7aqdap)]
X-Spam-Flag: NO
X-Spam-Level: 
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=gL7SEbso;       dkim=neutral
 (no key) header.i=@suse.cz;       dkim=pass header.i=@suse.cz
 header.s=susede2_rsa header.b=gL7SEbso;       dkim=neutral (no key)
 header.i=@suse.cz;       spf=pass (google.com: domain of vbabka@suse.cz
 designates 195.135.223.131 as permitted sender) smtp.mailfrom=vbabka@suse.cz
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

On 2/25/25 18:41, Uladzislau Rezki wrote:
> 
> but i had to adapt slightly the Vlastimil's test:

Great, works for me too, thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/cca361c8-2f03-40b9-872c-0949dc70cde8%40suse.cz.
