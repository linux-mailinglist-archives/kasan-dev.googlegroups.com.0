Return-Path: <kasan-dev+bncBDXYDPH3S4OBBQ4G6OXAMGQEHNIRGJA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x238.google.com (mail-lj1-x238.google.com [IPv6:2a00:1450:4864:20::238])
	by mail.lfdr.de (Postfix) with ESMTPS id C4EA3867D0B
	for <lists+kasan-dev@lfdr.de>; Mon, 26 Feb 2024 17:58:44 +0100 (CET)
Received: by mail-lj1-x238.google.com with SMTP id 38308e7fff4ca-2d244967778sf29971191fa.2
        for <lists+kasan-dev@lfdr.de>; Mon, 26 Feb 2024 08:58:44 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1708966724; cv=pass;
        d=google.com; s=arc-20160816;
        b=gomXL/FN1zmjCcrwzr9GjoW+diwzm4BLooeEhiQZAHUd5KI14L91/axtsOs7AV+MJ7
         0ar9eCHLHdk6pouaFT3a6iXb1r1S+35BaOyDjWzOYUoE3n33UbKeIQ0J5L8BK8ryBkAT
         Pjbpwu7UEV6idN5fE98xDzCbzTNS3aYaVak1RnaL7Fqz6lum/ucnCIp1JsAV97dI+hMU
         +36I7VDbicrV0uDDXlGD2TeSdd595OBzZHxLIeCc+YLiOcjunYHRmr+WKemjEQgJxx35
         saxsezs4ylJqBqNU1zE5fYoc4wRUw8mxO3tlnBo0s2Hjp+4lzmVjWYQ3l0f15BfB1so5
         i0hA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=E6T5RrP5UtAndSIgsyWWxWJtRhrBBnEdeXtvyyhY5OU=;
        fh=d9ANUDyjRh6nmhp+LlB921QmlSPn36asSKZ2zdcfrwc=;
        b=ihVPRrMp9GPAXMj+60YNwjq5vcGhfJCaDUW+YLG+yTbQsRHRiTjMSTCTZ5y1Of8+BB
         hGagXVj45Ed0IkWp668KqkT7qd5xCoi70emj8UfuGIT8+8Mby5xtwOV51KMRSpS72560
         K14l8YBgKGaXHxRI8XPAAfl83W9QrUN2cEiwxBouqlpX52q3PvSV/sRzOvu5fUD0vKdf
         wMQsBruVc+TOrVoeqOUmmsDP1qZ9gNW4ha4C5ek5o32J0YT9THHA+rRI8ZvaarWhO70q
         EUnOrGVnUw+J3AzscO41VvWdakaCnkcwJiIIqJ6Pd0KSlTl1LoSLCyXLf17LdwYo3ZJ5
         FZ/g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=jcYeMA68;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b="Q/Xv00rl";
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=jcYeMA68;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1708966724; x=1709571524; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=E6T5RrP5UtAndSIgsyWWxWJtRhrBBnEdeXtvyyhY5OU=;
        b=GF1VwKoB1Rw4iUKvJ9YDjEMIul1VtI46v9lA77MrinmrpMmHKrkv3rh0urNEheq3y4
         HEjpbpNeH6x07+ZGYFCVZDOrq41b45JTKg7JTTC/rZUkJD4VWCY7CmCyyaxYrcQd/0Ys
         GowrQs8Alwa4F2pY2AJFciRKZ221NF19K3cc1/DEi20vbxua3YoczZgsm0ZnvBHUmvPs
         cogA27zUpD1wtyfdcxVnxWyYdwbXOLa8GAsvOBoAZKrdU9pzibpo8QfFukJOZIb0vmbj
         4e7SS+ZDYDGZ+0QQfYWX3J/JdwHugGjYdsxGQtpv0spRXn8a2gGqkVMH8oa7K7h1iJyQ
         8shg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1708966724; x=1709571524;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=E6T5RrP5UtAndSIgsyWWxWJtRhrBBnEdeXtvyyhY5OU=;
        b=CTaJIfeI4SL621kHYi8op3GkyRM81wDHrXBRWbPfpRobvX1rP3EkI6F18cVs1U+lM1
         Asj80Gp4AGYQX6YlCrBeije0OXH9WiQt1L4oVFiImOd4TLNzEr5d8myMa2ItWWYTD8ud
         6wdKBo9HM01zjQQBMhnZJiWeoXlj3Iv/ZClv3MVO8H3Q5xZ6R1vZ8qoDGn+LbhO3Bee2
         y3eYy49Pq5efMRsWlQUemLKxHbSINQeBv3xXxe6TxdanS5PgrUQNbC2HXbTXQpPQ7NhH
         C+D8ahtCRoftZbhYXL7sThWfioUIXs12BSymtIYGPuAZPgsUFPfpLI17qv17Fa3+A+Wm
         5WWw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVbSyH5vAzzQVTjQ9WOEZFeRJ21NTiRnN3Dqt3Vd/3AP9OkkRlX2/7THQNWbU877ZfETXXHLDeRYLbV+NTmL8gK4S3n2dvWVw==
X-Gm-Message-State: AOJu0Yyfsa+a1uPiVEeue2jMWg+rqVlD8yPISexTPxfOymuq1gs9IEpF
	YTTgbnW+jKlu6cjGTX1jJVZ5Qa11hA+0GzAZSz9nIqnr47iWcDNv
X-Google-Smtp-Source: AGHT+IHnk/Hn2GIVTlLvWE/mXnVfzj74N2adxe/KSYUzNbo3R1awJp84N/+TuaCLJAO/4Xzhr+ZtJA==
X-Received: by 2002:a2e:be07:0:b0:2d2:84cb:c3d7 with SMTP id z7-20020a2ebe07000000b002d284cbc3d7mr4128564ljq.21.1708966723595;
        Mon, 26 Feb 2024 08:58:43 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:1e11:b0:412:97d7:5822 with SMTP id
 ay17-20020a05600c1e1100b0041297d75822ls1238189wmb.1.-pod-prod-03-eu; Mon, 26
 Feb 2024 08:58:42 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXiTFnh6USYFNlFEIKamikklWOcWrvvZjf66pEGBcEPdNZJn8eXhp6iqbxj/4M33kOj/MmcBQwyiKk4ldXxzwl6us1s5BExR/nhPw==
X-Received: by 2002:a05:600c:19d3:b0:412:a28b:84e0 with SMTP id u19-20020a05600c19d300b00412a28b84e0mr2897859wmq.23.1708966721838;
        Mon, 26 Feb 2024 08:58:41 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1708966721; cv=none;
        d=google.com; s=arc-20160816;
        b=ccy8aexvoF2MMywbSDOnfuabfP310ZR/X7FRQh95sqVHqwHO3VS05L8qALEg4tDpKo
         G6XSLKMbN8LwyoRhH4A62HvEdKOHtw/DPi8NCSdYvayETYKQWifg6jWgjilWAvIwyZnj
         gZNuldH2nJkUxTfB85WEWYbS78fOhb4t2VCJsAuNmou8+QEzQ/dP+GXHarPEHSEaeRcI
         TlaRGAncq2p8ergRHFfgS+Tzjx4YA0LQBWWI149ZZm7rih85b37mVoSy1vake4AekHh1
         arR1KizkL2I96SRO/Kh2KFO99l0RHsEMApiv6fe6mp3/xug4u73H/zTJUlY3krLM8a0F
         gNtA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature:dkim-signature:dkim-signature;
        bh=l0KFPjXNqVsEqy2ySF8st8aX9aaAa1NXHzLxm/9qX7E=;
        fh=AROQU2KCH7NyZd+GSF5Ja6si3COSfc75C77I0os5n1k=;
        b=Fmv4V2Xe2fg1skbEMpJ+KUp/6kzZuFyrqtbI+faf+V+VXEYtCVLuL4cyj15JNISICO
         ltvb5u59FTVOOLeyHZBLzn7WUzeqsYx9uXp6BVfpOPa74vstd0M75lsYXRSq9tTg3uKW
         3hmp1JuSADLTnY3PJHr3nrIxOXnVC42TuUJbrKEBa2MqorPoHhiL6VSV4vnStIiZwBxF
         hy4XkiHtoG3o8VsGrn4UfTyE2TVBoS0UMOynmZp6vOEoBh0g9clE0/ZZQjniS+e7IYEI
         1ukuDcUWAw5VQvNchJmnZ30DNQevsrjPxo3QFBdlRQYysGEjud1T25Ya5dmgFq9rKqV2
         9bzQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=jcYeMA68;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b="Q/Xv00rl";
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=jcYeMA68;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [2a07:de40:b251:101:10:150:64:1])
        by gmr-mx.google.com with ESMTPS id c40-20020a05600c4a2800b004127b4d36f1si464529wmp.0.2024.02.26.08.58.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 26 Feb 2024 08:58:41 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) client-ip=2a07:de40:b251:101:10:150:64:1;
Received: from imap1.dmz-prg2.suse.org (imap1.dmz-prg2.suse.org [IPv6:2a07:de40:b281:104:10:150:64:97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id 1B335225F5;
	Mon, 26 Feb 2024 16:58:41 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id 6763713A58;
	Mon, 26 Feb 2024 16:58:40 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id 5Hq7GEDD3GUxGAAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Mon, 26 Feb 2024 16:58:40 +0000
Message-ID: <a9ebb623-298d-4acf-bdd5-0025ccb70148@suse.cz>
Date: Mon, 26 Feb 2024 17:58:40 +0100
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v4 13/36] lib: prevent module unloading if memory is not
 freed
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
 <20240221194052.927623-14-surenb@google.com>
From: Vlastimil Babka <vbabka@suse.cz>
In-Reply-To: <20240221194052.927623-14-surenb@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Spamd-Result: default: False [0.45 / 50.00];
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
	 BAYES_HAM(-0.75)[84.09%];
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
	 SUSPICIOUS_RECIPS(1.50)[]
X-Rspamd-Server: rspamd1.dmz-prg2.suse.org
X-Spam-Score: 0.45
X-Rspamd-Queue-Id: 1B335225F5
X-Spam-Level: 
X-Spam-Flag: NO
X-Spamd-Bar: /
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=jcYeMA68;       dkim=neutral
 (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b="Q/Xv00rl";
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=jcYeMA68;
       dkim=neutral (no key) header.i=@suse.cz;       spf=pass (google.com:
 domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1 as
 permitted sender) smtp.mailfrom=vbabka@suse.cz
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
> Skip freeing module's data section if there are non-zero allocation tags
> because otherwise, once these allocations are freed, the access to their
> code tag would cause UAF.
> 
> Signed-off-by: Suren Baghdasaryan <surenb@google.com>

I know that module unloading was never considered really supported etc.
But should we printk something so the admin knows why it didn't unload, and
can go check those outstanding allocations?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/a9ebb623-298d-4acf-bdd5-0025ccb70148%40suse.cz.
