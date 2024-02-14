Return-Path: <kasan-dev+bncBDXYDPH3S4OBBN5RWOXAMGQEFJTS7ZI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x340.google.com (mail-wm1-x340.google.com [IPv6:2a00:1450:4864:20::340])
	by mail.lfdr.de (Postfix) with ESMTPS id B6465854C51
	for <lists+kasan-dev@lfdr.de>; Wed, 14 Feb 2024 16:14:00 +0100 (CET)
Received: by mail-wm1-x340.google.com with SMTP id 5b1f17b1804b1-40fb505c97asf33378995e9.3
        for <lists+kasan-dev@lfdr.de>; Wed, 14 Feb 2024 07:14:00 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1707923640; cv=pass;
        d=google.com; s=arc-20160816;
        b=imYvv927arMWQlvV93K5UVMpV/21NyGA2ouvdRqWO1gnilEAFVfJ57PEpYWMcfMIZY
         CxDeMUu+lf3SJ+IzmHIRoU5HZEPgDDNGN7eARw+QVqfoYPpHtcyDxb3189iYi9c1b9q2
         O4N3UtnjBS7KSjL51KSxRtUVVXAxlaSHSbMA8V1MKep3HQ68S/mKwuF9IpakvRMbkf5N
         BHLV5+FG3kIoUE0bxkVgpNlMFzxHj1e2QCQdSDUTih5TswpOFAYUdTjRCceFkAk3DlAN
         /N9o86D0iFLq8xMnVfSZwz5M1YSYI/7/GCh7RkQJ+1B8EPT1o1FdYmzJQ8AnIJHmvjvR
         RbZg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=RjvUAdh1n+4A6i/U/WJwjF/A/k3nm08rQ1XVsHj1IDI=;
        fh=h2fJ0ZE1mYiezLM8zUtNvUPSbyUC0t05bTymmGGBjmk=;
        b=eqj8vK2WNFeW2519NsscCXL5BZvIopL6qfMyqP+P1XnK+Qyxwct+esT05R0dEtkkOd
         UGOznW1h21EJksDbP3S2j4dWVwsttS93/P30qMSNhjckjdoincaqO7pR9oJVwus0g1VZ
         XtFMBn4PrwjHwSgOiQhlLt2m4GJTKf/bLaRVuJ/7QYjHB6c9z5zxYL9gSpmx5fPyX+zL
         8vteo/aWl+EPjRP2sR8JuLynnD7jLh/9w/HEl/ZtIfrNhFlJrupDw4YBo5ghwBRci/fA
         Qfsids+Vc2SfZ82YgPEAwKCm4waXOxW4O8mzxHmI7VoLW6IxUfvLMF8cswVHejqrQX6I
         rM8A==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=gU3rk2X2;
       dkim=neutral (no key) header.i=@suse.cz;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=gU3rk2X2;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=IhXF164r;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1707923640; x=1708528440; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=RjvUAdh1n+4A6i/U/WJwjF/A/k3nm08rQ1XVsHj1IDI=;
        b=K04H5SGJzxbFgoxUXXxDpLzeKR1rOMjtu5WeGZPR8PtpzYNg5up7Xtmtp+DzyZ0j6E
         8O2J9QAdocBbBySrRX/Ht7uKTVQzTuzF3kTVr+rA/BQJmj46BdolYVaRJ4uWZ4dQp66k
         oB5LaAw1oU+a6pT92GbUWxCD8yPCJh2Ezh1RgGFO1ymmfIchEthxUySpkxE7UefkHtlZ
         JqUHv+4/lwp2DyN5Us4Wqo/4n98hDhCe3vZAQ5ERxvPOEtBinuyrDO3E0ILNYsChf6lD
         Ml+OPmyGjAToJzIf5Uk0PNzG5ulMXEsCJrs0bli4T7pzQLRFC8hFhxufLNZ8PLeUH4vr
         gPOg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1707923640; x=1708528440;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=RjvUAdh1n+4A6i/U/WJwjF/A/k3nm08rQ1XVsHj1IDI=;
        b=icPb+nUN6PDC2aqNGegrRFDhNl8/YccyqoKntLuqKajdv5JELLD3hUOEemoe3jMFEF
         XN9WXF6EFSY2pPJXFoh9+tORxEJeJ5kQtjedFdXCxP1xyEOdiBSO1xNT43CHBP3JtsNH
         17gHFnUkr7SUCEH5h99uk2tH+AvdyEE7Y+lNqpXRtfBGo9l5kLvA34cXsBeNYa0DNkqF
         SZ62r3mXWTAfv/LRojZ+IYb9EqgHIUqshOxJS7AG6rJgyWcdCcLuJl6udDoLJVl/MOKN
         iFDJ+k7j2Nsbcs0yXHZBm0dVJwY5mbKKoPx9eTMVtfiw27Qx2Luk9uU9pZOsXMlPYpuc
         NV/A==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXZw3jctVWO4qICeXFLy5yH0uTHZmc/R4K88eVfZEvAbfeGnoAvjbfiZSOMgzkvsM7UPrMdVJSp4p5xcdP2fAu/vvVFwUshHw==
X-Gm-Message-State: AOJu0YzUPZUFtkaVg9tZJqSCy1SiqEzSPwqwgg5JJ0dKtGovKKqQtA+U
	i7pFf6v4MhgoUQuCfCAXRSYvmzYSY3Wk+d19mbHmQwL8meg+/ns1
X-Google-Smtp-Source: AGHT+IFH8ElJl/3xi/A2/BlYzncrYABYe7AafcHXLRmVJ6jcf/IEYI3rbar4S3Vr0b8q2vfc5l9h0w==
X-Received: by 2002:a05:600c:3b23:b0:40f:d2f7:6e34 with SMTP id m35-20020a05600c3b2300b0040fd2f76e34mr2337443wms.33.1707923639838;
        Wed, 14 Feb 2024 07:13:59 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:1d83:b0:411:e806:70f5 with SMTP id
 p3-20020a05600c1d8300b00411e80670f5ls332583wms.0.-pod-prod-05-eu; Wed, 14 Feb
 2024 07:13:58 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCW8y8bBA/jm8XUTB+iTQycYWUZBecQx1588KCW+mZD3KQbXLlJhWkaVXcGoSf7QASc7nuJP567B+r8DLcleBQt6iAJA8CWY7bG27w==
X-Received: by 2002:a05:600c:519a:b0:411:e178:2a73 with SMTP id fa26-20020a05600c519a00b00411e1782a73mr1911795wmb.22.1707923638183;
        Wed, 14 Feb 2024 07:13:58 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1707923638; cv=none;
        d=google.com; s=arc-20160816;
        b=b/mAzD4MtZNGlexu4KVMxxi7En60LuZimeYopjaNNz3vqOd7IMhjwe9nZl8a7hsghf
         LQC8rZ42h+cZChhJUcuT8/sHDgL11bNQNK3RIfH2E8MwQspSoZg5UazNoY5Rf7YwC1Es
         FPDsCLymNheTHbLPaPlugYG1cd2DSABVv9+yaoKjxSaMCUyNvcEEWF4XTnjRHaNpOizB
         Pb1qvfw2aVlm/r+rGAbQM7ZY1KRYB6P6Qx7d7Qy0QGUhKb0tmjR1tfKuoZ7431MqgWwh
         MnJPu8bhsjQ8+3W+LO9wT0xHT1TNf5UDpwbDMpuAVg+GVD61EkpaSWpWWztrNAN+sSd6
         lcEg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature:dkim-signature:dkim-signature;
        bh=tikF5ShYKbO2WOghBk9vtGAaaUgiPj3VsQTjyNrj1PE=;
        fh=chEATD5xlBu9RnR+j/ks9svFMpbZ9rkn/PVH5+yPIVE=;
        b=Tr2K3nYRVG4pihM4esqYA8HfmnYFUFJr95u0JWw3SQX/5Vsy5Mk+ftc+8rDINmxXDJ
         5hwXIYy4nPMwwbOMk0syPa2WeHYwXDGmdSCzTQ9Z3VT57NwTS+/TM2+IkvQ8oT1xaHz5
         ETxsWS9+8At909lAy9kKXqTZ118Gwomk/cOUVYVSWSnfVpYie4EMzckW7w5pG4MwgQAC
         gwLYx4m2gSalYVQIrrXrZALXA4sweRHUzFF2DKzDSWgOrkcTI/Y63N2xEGxiCNd6kLX6
         CK9Gn+LHRP/Y5C1edY0lce7vCNzigE3+BPiZduQRCr/zosI0Pj4timeCCWSiKw1DDN3H
         Yn6Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=gU3rk2X2;
       dkim=neutral (no key) header.i=@suse.cz;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=gU3rk2X2;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=IhXF164r;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [2a07:de40:b251:101:10:150:64:2])
        by gmr-mx.google.com with ESMTPS id hn4-20020a05600ca38400b0040fd31815f3si181561wmb.0.2024.02.14.07.13.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 14 Feb 2024 07:13:58 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) client-ip=2a07:de40:b251:101:10:150:64:2;
Received: from imap1.dmz-prg2.suse.org (imap1.dmz-prg2.suse.org [IPv6:2a07:de40:b281:104:10:150:64:97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id 5DB891F801;
	Wed, 14 Feb 2024 15:13:57 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id 352AA13A6D;
	Wed, 14 Feb 2024 15:13:56 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id BizkC7TYzGVnIQAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Wed, 14 Feb 2024 15:13:56 +0000
Message-ID: <6370b20f-96fb-4918-bef0-7555563c9ce2@suse.cz>
Date: Wed, 14 Feb 2024 16:13:55 +0100
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v3 23/35] mm/slub: Mark slab_free_freelist_hook()
 __always_inline
Content-Language: en-US
To: Kent Overstreet <kent.overstreet@linux.dev>,
 Kees Cook <keescook@chromium.org>
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
 hughd@google.com, andreyknvl@gmail.com, ndesaulniers@google.com,
 vvvvvv@google.com, gregkh@linuxfoundation.org, ebiggers@google.com,
 ytcoode@gmail.com, vincent.guittot@linaro.org, dietmar.eggemann@arm.com,
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
 cgroups@vger.kernel.org
References: <20240212213922.783301-1-surenb@google.com>
 <20240212213922.783301-24-surenb@google.com> <202402121631.5954CFB@keescook>
 <3xhfgmrlktq55aggiy2beupy6hby33voxl65hqqxz55tivdbbi@j66oaehpauhz>
From: Vlastimil Babka <vbabka@suse.cz>
In-Reply-To: <3xhfgmrlktq55aggiy2beupy6hby33voxl65hqqxz55tivdbbi@j66oaehpauhz>
Content-Type: text/plain; charset="UTF-8"
X-Spam-Level: 
X-Rspamd-Server: rspamd2.dmz-prg2.suse.org
X-Spamd-Result: default: False [-1.66 / 50.00];
	 RCVD_VIA_SMTP_AUTH(0.00)[];
	 XM_UA_NO_VERSION(0.01)[];
	 SPAMHAUS_XBL(0.00)[2a07:de40:b281:104:10:150:64:97:from];
	 TO_DN_SOME(0.00)[];
	 R_RATELIMIT(0.00)[to_ip_from(RLcb476ir6xfzaroaj5pc7azzw)];
	 RCVD_COUNT_THREE(0.00)[3];
	 DKIM_TRACE(0.00)[suse.cz:+];
	 MX_GOOD(-0.01)[];
	 RCPT_COUNT_GT_50(0.00)[73];
	 NEURAL_HAM_SHORT(-0.20)[-0.989];
	 FROM_EQ_ENVFROM(0.00)[];
	 MIME_TRACE(0.00)[0:+];
	 MID_RHS_MATCH_FROM(0.00)[];
	 BAYES_HAM(-0.16)[69.25%];
	 ARC_NA(0.00)[];
	 R_DKIM_ALLOW(-0.20)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	 RCVD_DKIM_ARC_DNSWL_HI(-1.00)[];
	 FROM_HAS_DN(0.00)[];
	 FREEMAIL_ENVRCPT(0.00)[gmail.com];
	 NEURAL_HAM_LONG(-1.00)[-1.000];
	 TAGGED_RCPT(0.00)[];
	 MIME_GOOD(-0.10)[text/plain];
	 TO_MATCH_ENVRCPT_SOME(0.00)[];
	 DKIM_SIGNED(0.00)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	 FUZZY_BLOCKED(0.00)[rspamd.com];
	 FREEMAIL_CC(0.00)[google.com,linux-foundation.org,suse.com,cmpxchg.org,linux.dev,suse.de,stgolabs.net,infradead.org,oracle.com,lwn.net,manifault.com,redhat.com,arm.com,kernel.org,arndb.de,linutronix.de,linux.intel.com,kernel.dk,soleen.com,gmail.com,linuxfoundation.org,linaro.org,goodmis.org,linux.com,lge.com,bytedance.com,akamai.com,android.com,vger.kernel.org,lists.linux.dev,kvack.org,googlegroups.com];
	 RCVD_TLS_ALL(0.00)[];
	 SUSPICIOUS_RECIPS(1.50)[];
	 RCVD_IN_DNSWL_HI(-0.50)[2a07:de40:b281:106:10:150:64:167:received]
X-Spam-Score: -1.66
X-Rspamd-Queue-Id: 5DB891F801
X-Spam-Flag: NO
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=gU3rk2X2;       dkim=neutral
 (no key) header.i=@suse.cz;       dkim=pass header.i=@suse.cz
 header.s=susede2_rsa header.b=gU3rk2X2;       dkim=neutral (no key)
 header.i=@suse.cz header.s=susede2_ed25519 header.b=IhXF164r;       spf=pass
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

On 2/13/24 03:08, Kent Overstreet wrote:
> On Mon, Feb 12, 2024 at 04:31:14PM -0800, Kees Cook wrote:
>> On Mon, Feb 12, 2024 at 01:39:09PM -0800, Suren Baghdasaryan wrote:
>> > From: Kent Overstreet <kent.overstreet@linux.dev>
>> > 
>> > It seems we need to be more forceful with the compiler on this one.
>> 
>> Sure, but why?
> 
> Wasn't getting inlined without it, and that's one we do want inlined -
> it's only called in one place.

It would be better to mention this in the changelog so it's clear this is
for performance and not e.g. needed for the code tagging to work as expected.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/6370b20f-96fb-4918-bef0-7555563c9ce2%40suse.cz.
