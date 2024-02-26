Return-Path: <kasan-dev+bncBDXYDPH3S4OBBQMD6OXAMGQEGC3GKYI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53d.google.com (mail-ed1-x53d.google.com [IPv6:2a00:1450:4864:20::53d])
	by mail.lfdr.de (Postfix) with ESMTPS id 9C70A867CAA
	for <lists+kasan-dev@lfdr.de>; Mon, 26 Feb 2024 17:52:18 +0100 (CET)
Received: by mail-ed1-x53d.google.com with SMTP id 4fb4d7f45d1cf-563df53b566sf1635381a12.2
        for <lists+kasan-dev@lfdr.de>; Mon, 26 Feb 2024 08:52:18 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1708966338; cv=pass;
        d=google.com; s=arc-20160816;
        b=oRxs9mv8KDywbkcmv/eVwayVMxaCfpNU0lyE9akg57BJayEjXnEtmx6sNfziHFNFy1
         cJllpMsxzfW/lfq9BMUjyaJ3QzdkGqQhDHHdDP1V4bZBkOKeaTEydWoMZ3EzuyENPQAE
         ky08FZs/M0/rGW9FuIoR840OigI+GKeYUdWb4yCeXBVSh79MUWfbEYbDa7HqgnFTyH+N
         KizLqDg8hfuvzK68SOpR65qf5n7SySjSuc+SXQdEVmioRsC9b0io3zzpXLQj+sdIMgCN
         Baopav3mQJpZu+QRl9O6X2D0BzPCqJtLryDet5qcXM0Em+vRwsmlcMcm98sjvrKKCgBz
         986w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=O8mICc3w+jeN8aJiN4TDwGDf9H9I0+RZFyJJCYscYW0=;
        fh=W4Su+bVAJ/nw+44n9IGpL2c8yEebf7PQA1RSGawLhnQ=;
        b=wj9MuCwyWiaNv++mEKNoN52NekPkv4dM20taqUemLeVBYl8IHfXwSfBHNZUMBa8WdT
         xp5EnAqtPg8qI9ueFlgU4evjJ1BfdiI8RkJLkkL0vWCrQOaltbR+n76ji6iMVOVjyvsP
         EL/nIL2TctOAVq+hZrAT0WOEiTxyn3MK3jVk2oF9pSOu8mZxrxs96v0wUd0DIKGKQVxB
         GECeY+h6XY8Ot2UQD8zhenCbq0x2xVJRtavaTcL8Jdr/wvaqpEiR0jqSfwllbTXwxAn7
         JrszaKQo8WqBNuy5OqgQVvJnz5LZpzrqAaYGMbEAWoSHAHMqaO+m5XDG8r8p1GWqA4iX
         ewqA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=mNSzhrjb;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=mNSzhrjb;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1708966338; x=1709571138; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=O8mICc3w+jeN8aJiN4TDwGDf9H9I0+RZFyJJCYscYW0=;
        b=wo//pnizCoB0Fdq/wbFPKVsjReMbFlyZbuMiwrn0gPa+lPEg3gQxERkJhogSB1LbNH
         u/FFWmzO1CRgJfs6dLkwzj1rP/1TwQTPRZgxoWiBw4R4SaIHq7uCu7lqBJ/CED/mEmxN
         1Qc/sM0qcVYrobLXbZSlZtFYovHW+pYAfMzt+BboEhxHJ8sJQWW8RwqLG9bWct4rQdU+
         mdXJqQPsTnt3WzBQ8GWNsTlxfg9pepE0juhnB3UexoBKwxwVCF+PZYjFA/1fSgEsWvne
         qM9FZ+OBzW6WP1CWFDbLxb4/FXABgZmfq4Ch/bFEp8FAfzQSEoFhmcprOL61J/RrHSaS
         NNVg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1708966338; x=1709571138;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=O8mICc3w+jeN8aJiN4TDwGDf9H9I0+RZFyJJCYscYW0=;
        b=lJguKDaS4F1SsNkPb/PnfWGwf3+OYJU4kzFyJH0+iaIyWhCrV+2YGrGLXoYBRYleKP
         RVq96fHM77GCOSxWUH1m8c1KfSS7ErcnmEq4Hz1TbQ2A17h0Zw5pzXGl3lzuIKRH2fS6
         ti0r56z/XqYHbOb9sVuRNfKJZZLu0OS1LC+8CGr4g5gteztT2xmx+olxTZkwl92HOH0k
         laZfF1AQLJuhJty+s+q1gSb4p7B1J28QUwlBf43aGnzyVcezMgrWyr+907Cjhig3L2g/
         O1ttlcqOoWTMOq4HAJet34hS0BWTlETyibN6R+uUzPDb0wW9A60fXNQ7o+nI0doqUTMQ
         vh7g==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCW8NnAPONa8MfQ5dR+pvtlLbKd6mqivb0Gab+7PoAMQN0JyU7Ar+uHzdSBnR3rXfraTdm0hqZRD7cca6Fba1dJ73oXAMk8zoA==
X-Gm-Message-State: AOJu0YzTEctNu5JIUpUOrs5Zawgz64ROC4cQ6E5q0f2ivsRu0mpdxGIV
	hnE5WDb/cZipqCnI4XCYvv/PdLwjL8jCaN/rzf71y7QRbooMI07s
X-Google-Smtp-Source: AGHT+IHH7X55nb6J66YzQq05EIUAudYKM2i43gAIEVU0S/1TobcelIkHcvtTpQVE/p1LHj5dQCwZtA==
X-Received: by 2002:aa7:d958:0:b0:565:3574:c71e with SMTP id l24-20020aa7d958000000b005653574c71emr4743395eds.28.1708966337503;
        Mon, 26 Feb 2024 08:52:17 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:3218:b0:561:505e:b9a8 with SMTP id
 g24-20020a056402321800b00561505eb9a8ls352022eda.2.-pod-prod-09-eu; Mon, 26
 Feb 2024 08:52:16 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWDjAJ1LR2CHdkVr4e7s7oQk2JO5G+/kEdLEs/32/I6WLTLJEmeoWqn0tW/TL4PmqaHrjBx5QyHEsqMYCjr88t28T94n2e91WsJug==
X-Received: by 2002:aa7:d0c9:0:b0:565:7d4a:1d4a with SMTP id u9-20020aa7d0c9000000b005657d4a1d4amr4742848edo.8.1708966335704;
        Mon, 26 Feb 2024 08:52:15 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1708966335; cv=none;
        d=google.com; s=arc-20160816;
        b=hMcnlnxl6GKOGNrgxyNdJj0qV5Q14r0poKxCS/YDfbxY4WQv25XXqHGMpsmv1TwJJA
         0cZrKoF4UbVOTxoN+N/Q/7eo00vV6It+xo8AGJkBo/PFQ9wefeYHCgdZsgu3GqJwi3RL
         74swNbN9J+cCtke3OpOAJa33eAmVrxNWt5f5GdPFc5J7nA88x+MvCLCL14JxZVzxHJEI
         qPkrbGqNKxA489CN5SEjGrqg1A7/yBx9ouwwfqIHcmSf8suq898Uvp3jsRZ6ev3cUYFu
         UDwLsmWBWFF2lLJtM7qY2tpJBe4UfQ38q+cU/OF32xJoMur1SsWQX6N3XltF9arK7mD8
         f7aw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature:dkim-signature:dkim-signature;
        bh=82epdJNA5r8/dKtfBgUmlYwzSR4ZoAcz6T/CRU9wBgg=;
        fh=AROQU2KCH7NyZd+GSF5Ja6si3COSfc75C77I0os5n1k=;
        b=JyHHRVBPOt2HUJDWRZESyufa7TfVvV/laEer+euOtJpb6EASXkB2PHBqek5qHWn67T
         djKxi12hRHjxITZXVwSNqAZzq6OAnKOpUwwO9PhBWdM3PQkrRkdCwqX9Ceg0FQ6MAXww
         nIsX3LPDPXrxBDhU0DvTq/xS5oN2HrCHvNaCUN02wgvWhKBaYrASGpP6p1f8A8NSj+Wc
         JwFQS3QMixtaNk0fGIfXGm35rdLcw/0q5Fq/PZKLURDnCfFFfE70RIIzQXk/uvfKCXWz
         07y357ims2M1RzYgfeiwoD6wIXe7if03IeIh9BzTIHIarkcMC+9OIRFJ/yRGO4JAUx3j
         VzqA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=mNSzhrjb;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=mNSzhrjb;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [2a07:de40:b251:101:10:150:64:2])
        by gmr-mx.google.com with ESMTPS id v24-20020a50d598000000b00564af3e693fsi493317edi.5.2024.02.26.08.52.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 26 Feb 2024 08:52:15 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) client-ip=2a07:de40:b251:101:10:150:64:2;
Received: from imap1.dmz-prg2.suse.org (imap1.dmz-prg2.suse.org [IPv6:2a07:de40:b281:104:10:150:64:97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id 207EA1FB5E;
	Mon, 26 Feb 2024 16:52:15 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id 6C73613A58;
	Mon, 26 Feb 2024 16:52:14 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id IOYhGb7B3GVLFgAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Mon, 26 Feb 2024 16:52:14 +0000
Message-ID: <206b677f-0523-482f-b42b-2cdaf7ab8db9@suse.cz>
Date: Mon, 26 Feb 2024 17:52:14 +0100
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v4 09/36] mm/slab: introduce SLAB_NO_OBJ_EXT to avoid
 obj_ext creation
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
 <20240221194052.927623-10-surenb@google.com>
From: Vlastimil Babka <vbabka@suse.cz>
In-Reply-To: <20240221194052.927623-10-surenb@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Spam-Level: 
X-Spamd-Bar: /
X-Rspamd-Server: rspamd2.dmz-prg2.suse.org
X-Spamd-Result: default: False [-0.51 / 50.00];
	 RCVD_VIA_SMTP_AUTH(0.00)[];
	 XM_UA_NO_VERSION(0.01)[];
	 SPAMHAUS_XBL(0.00)[2a07:de40:b281:104:10:150:64:97:from];
	 TO_DN_SOME(0.00)[];
	 R_RATELIMIT(0.00)[to_ip_from(RLcb476ir6xfzaroaj5pc7azzw)];
	 RCVD_COUNT_THREE(0.00)[3];
	 DKIM_TRACE(0.00)[suse.cz:+];
	 MX_GOOD(-0.01)[];
	 RCPT_COUNT_GT_50(0.00)[74];
	 NEURAL_HAM_SHORT(-0.20)[-1.000];
	 FROM_EQ_ENVFROM(0.00)[];
	 MIME_TRACE(0.00)[0:+];
	 MID_RHS_MATCH_FROM(0.00)[];
	 BAYES_HAM(-0.51)[80.12%];
	 ARC_NA(0.00)[];
	 R_DKIM_ALLOW(-0.20)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	 FROM_HAS_DN(0.00)[];
	 FREEMAIL_ENVRCPT(0.00)[gmail.com];
	 NEURAL_HAM_LONG(-1.00)[-1.000];
	 TAGGED_RCPT(0.00)[];
	 MIME_GOOD(-0.10)[text/plain];
	 TO_MATCH_ENVRCPT_SOME(0.00)[];
	 DKIM_SIGNED(0.00)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	 DBL_BLOCKED_OPENRESOLVER(0.00)[suse.cz:dkim,suse.cz:email];
	 FUZZY_BLOCKED(0.00)[rspamd.com];
	 FREEMAIL_CC(0.00)[linux.dev,suse.com,cmpxchg.org,suse.de,stgolabs.net,infradead.org,oracle.com,i-love.sakura.ne.jp,lwn.net,manifault.com,redhat.com,arm.com,kernel.org,arndb.de,linutronix.de,linux.intel.com,kernel.dk,soleen.com,google.com,gmail.com,chromium.org,linuxfoundation.org,linaro.org,goodmis.org,linux.com,lge.com,bytedance.com,akamai.com,android.com,vger.kernel.org,lists.linux.dev,kvack.org,googlegroups.com];
	 RCVD_TLS_ALL(0.00)[];
	 SUSPICIOUS_RECIPS(1.50)[]
X-Spam-Score: -0.51
X-Rspamd-Queue-Id: 207EA1FB5E
X-Spam-Flag: NO
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=mNSzhrjb;       dkim=neutral
 (no key) header.i=@suse.cz header.s=susede2_ed25519;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=mNSzhrjb;       dkim=neutral
 (no key) header.i=@suse.cz header.s=susede2_ed25519;       spf=pass
 (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2
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

On 2/21/24 20:40, Suren Baghdasaryan wrote:
> Slab extension objects can't be allocated before slab infrastructure is
> initialized. Some caches, like kmem_cache and kmem_cache_node, are created
> before slab infrastructure is initialized. Objects from these caches can't
> have extension objects. Introduce SLAB_NO_OBJ_EXT slab flag to mark these
> caches and avoid creating extensions for objects allocated from these
> slabs.
> 
> Signed-off-by: Suren Baghdasaryan <surenb@google.com>
> Reviewed-by: Kees Cook <keescook@chromium.org>

Reviewed-by: Vlastimil Babka <vbabka@suse.cz>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/206b677f-0523-482f-b42b-2cdaf7ab8db9%40suse.cz.
