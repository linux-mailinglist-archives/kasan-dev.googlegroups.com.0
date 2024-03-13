Return-Path: <kasan-dev+bncBDXYDPH3S4OBBE7XY2XQMGQEDM2NCDY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x140.google.com (mail-lf1-x140.google.com [IPv6:2a00:1450:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id D472387A9AB
	for <lists+kasan-dev@lfdr.de>; Wed, 13 Mar 2024 15:43:33 +0100 (CET)
Received: by mail-lf1-x140.google.com with SMTP id 2adb3069b0e04-513ca5dac68sf796770e87.3
        for <lists+kasan-dev@lfdr.de>; Wed, 13 Mar 2024 07:43:33 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1710341013; cv=pass;
        d=google.com; s=arc-20160816;
        b=cGXhVxiQmbpoefFzhs3+MTW4MTAfrKjOzGqlZf0WSA2uwSYDHVxNXh1ttCh2cW/0ll
         hvUqGDAUIj0QdWCWyephoypPbK9RtCZn5+Qj9dmMHfIlm6eLo9r6zpAWaWvDsPvaOgrL
         v02rVmkzUz1b3LwDTwQXn0CWI8x0xbustlM3JtuJnZDf6NKq8bCWqCdoMdkTurztcTPo
         6ZeCnpebUhkApKUz2WVl7YM8TQaGLG8MTPVcGqJ1j0hoiMNOtpYxF8Tx1L3I0QNWDhcc
         FqjbtL1OhAwyetXUqDn/cUV450mg3HjOyqAyZ1HVoGlNZVPJEVlQSnBeqsKI5JfPgzrY
         9rrQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=mGkSWTxsClVWi2tDrVTiN+WDWP8T/gsuHjsSPB6ib1s=;
        fh=QWGVRrHjuJ6veSV8hPxNoCQOWrm9XHcUNq9EK/Y7Hx4=;
        b=jKE8rocZRt+uCPBVNuTlj9fw1OUoaIO4KD53rgDzl6DVODBoUV8CIT5EXbDn1N0OoI
         /z1dlMh9KBOwx0KvMTcSQkzsRlg5FNoc5ks6P19hO5OA0ba+hzS1yg4vJgiubxPnHaIj
         v+hrcGpizVmbQiRUflr0iQx5JMkJIywC3l5onlPLveqTw3U5W2P3NvsqjSattp1GhOfI
         RpkwgQ+lv8GeVbZvzI/rjR9sljWLVYtVxeLHUXE3aBrUdoyF5jGnpOPedcDJPZ46CEuQ
         t30ouqjhE9TdPeITk8mVaXdiHmoOxyf+I0OWl5UKkCqyDIhy7dzvmdrQBGslRbW4OTFf
         9VHQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=Nmf6Xm61;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=Nmf6Xm61;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1710341013; x=1710945813; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=mGkSWTxsClVWi2tDrVTiN+WDWP8T/gsuHjsSPB6ib1s=;
        b=fiY7rUuJr2RTkVYgDobvsNW2HxANzkmbL3EsdVg6Xjcy8CGgjIQe/+VpMecXJ4nNAS
         0F98wy0EirIbF21dcFGEhsyor9/pjMWeBW4r461Pj0tGi3ZzvzMY8MNP9TAPZdFqOnMv
         hNUmCWTGbdth0pfFOmZgQW11aJOpLpIKcCveBRo/IiS+hJYLdQ4lpswFUcBcFXPYtLdA
         /gsN+khWVKrtiEYwe7zXwhPoMhU2nWUzvf/pFJgAjL6en4xYHuzi1tqUEJ3OxGLMmUEl
         HNQdwFiTvlPTb00GbRvlR5EKzlj6SPReRw9gpMGi23lHRhmCTtn8GnIDkSxM4jdjehxk
         Zdww==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1710341013; x=1710945813;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=mGkSWTxsClVWi2tDrVTiN+WDWP8T/gsuHjsSPB6ib1s=;
        b=uRyvnBSCZOYXu2X2PKiVPjnWkxRnRnKXtvVWAbnO1r4NB9lIDiAHpMkIJI1pMtjl/v
         JpINHIc8TzAIBxfGw8K/Bz+CH+6PdiURVca67Ojc7NWy87dWMFIOaedbDn4APz3cVbjl
         CTLFMeVVvRSJV3kLbytdQujq3Nx+MrPwBmM4M5/tZTRV89u9Q5DBEzSrtXWYJFnanvX5
         vUMHkjJ3oUI2X4uAnLHIirgZ6lqmmmsqOSeE4uDJxT68DloVUelTiUm0mJFIujClCrt3
         VmF/1Q4tc/+8upne+gW3YcCyZHWpZLuRN5fvnBCJysnshyzY1G61mhFJ09v9V5gmd1Ut
         eYlw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXv34pOcqj99z3hee1Min31/C8gxZlG0lIrPf4yMMPdD+eK28N+WTsq2rMluIANsRTEQ4qgJugJ1p590yX2YHPvYbZKNDXKHQ==
X-Gm-Message-State: AOJu0YxRaQRYdbG9hUtHcm2teQFuHz++LEezx08IwXLLqTSheQQn44Lc
	V++Yk1A3+1QavXrU3XbBzvdBOTeIEL/Yz5z2Ryr+6Icl/4Rx77lD
X-Google-Smtp-Source: AGHT+IFBgqxZfCuy7jTUABEgtUd86mkNjZPpWNAUjVbWrc4QgciaYACQ4YSusky22UTWT6NMeuZCIg==
X-Received: by 2002:a05:6512:368a:b0:513:c146:fc02 with SMTP id d10-20020a056512368a00b00513c146fc02mr2105337lfs.6.1710341011814;
        Wed, 13 Mar 2024 07:43:31 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:4005:b0:513:aa32:7fe3 with SMTP id
 br5-20020a056512400500b00513aa327fe3ls905623lfb.1.-pod-prod-02-eu; Wed, 13
 Mar 2024 07:43:30 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCW46wRdB/TbWBI/pK9SEoViw+Ido05gis+EgbpkeVKtfgo0pYP0Mw6Kma8l0oi1TUg1vEggTTWnX27vD/NN/puRuqmGFGB5Lllpfg==
X-Received: by 2002:ac2:499d:0:b0:513:af7a:8d56 with SMTP id f29-20020ac2499d000000b00513af7a8d56mr2357635lfl.44.1710341009634;
        Wed, 13 Mar 2024 07:43:29 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1710341009; cv=none;
        d=google.com; s=arc-20160816;
        b=wXR/f9tlPDQ+rt1Ak8eLI2uJQ1AdU3njn5Pt4X33BCjGoMI2PtUCFSKoYkRo3/IvQM
         7JPCJiIze/eT+4dROMyQszKtuEhG7zKL475Jx7LuOsEzCN7q/IwacLnqHaHcH7zFKVdM
         OoI4L250hiMd+IrBnC81YwoZyc5rNw38x80ZqSnyGUCBlVSdmLyhylMcTdODKJpOd8X2
         RlCmgBcmKvIkWWio2KBXWd8YJnwo4pvgyMf0GfkJNwATVLsQY0MAZv6lY0nDL+LRCuiW
         XAqt7vns9t2UOP80CtLXW2P1DgyEwNT7jxy8RBUe9VNx05zmXviiXAYvpgrHkGqkhRP8
         qJvQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature:dkim-signature:dkim-signature;
        bh=O3ouuLw+tQrb8/EbRY+xlkqcLCuq786lUp+bYp4r2zU=;
        fh=T/slm/RCgVOv9Z2m2Kuiq5NwRE9Ne3JjQWJHIJg2CLI=;
        b=HRsDAY/tc1Cgem84hn73C3chJC6T2gVwH9Hmuq+DR2eGuzvOoA5gZxfa7YtvdnSD8/
         tDO6JTYNW5rFnIucbIESn96lF9X0eDvJlHsoySC8CQVAOOfzbCD2tLKVyyJbc6CBidbp
         e8yo1v5DPuw/6VI01KXK2hjSh8fZjZ1jP9sgFfHPWa1H6SY4uS9nqex5N8LSzvvnc4t9
         NbtPVZ+KsYgG/d4Joav3lDvWEu8gbrrFuI4I8UeDHMSxYA6dbSslXgo5r3r4akOuLnex
         o4sg2A9DnVnbD9YpYNu1CCvURiPEmObzvuqQtc3w8oaBjTjyx8I529GDzII9f1rK2Lu3
         Re5A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=Nmf6Xm61;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=Nmf6Xm61;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [195.135.223.131])
        by gmr-mx.google.com with ESMTPS id k19-20020a05651210d300b00513a9d05166si443523lfg.9.2024.03.13.07.43.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 13 Mar 2024 07:43:29 -0700 (PDT)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted sender) client-ip=195.135.223.131;
Received: from imap1.dmz-prg2.suse.org (imap1.dmz-prg2.suse.org [IPv6:2a07:de40:b281:104:10:150:64:97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id C35421F7D4;
	Wed, 13 Mar 2024 14:43:28 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id 73FB413977;
	Wed, 13 Mar 2024 14:43:28 +0000 (UTC)
Received: from dovecot-director2.suse.de ([10.150.64.162])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id IMkYHJC78WXjZgAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Wed, 13 Mar 2024 14:43:28 +0000
Message-ID: <76c84f17-8b99-4f68-a6ac-a0db22f5ace3@suse.cz>
Date: Wed, 13 Mar 2024 15:44:13 +0100
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v5 20/37] mm: fix non-compound multi-order memory
 accounting in __free_pages
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
 songmuchun@bytedance.com, jbaron@akamai.com, aliceryhl@google.com,
 rientjes@google.com, minchan@google.com, kaleshsingh@google.com,
 kernel-team@android.com, linux-doc@vger.kernel.org,
 linux-kernel@vger.kernel.org, iommu@lists.linux.dev,
 linux-arch@vger.kernel.org, linux-fsdevel@vger.kernel.org,
 linux-mm@kvack.org, linux-modules@vger.kernel.org,
 kasan-dev@googlegroups.com, cgroups@vger.kernel.org
References: <20240306182440.2003814-1-surenb@google.com>
 <20240306182440.2003814-21-surenb@google.com>
From: Vlastimil Babka <vbabka@suse.cz>
In-Reply-To: <20240306182440.2003814-21-surenb@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Spamd-Bar: +
X-Spamd-Result: default: False [1.16 / 50.00];
	 RCVD_VIA_SMTP_AUTH(0.00)[];
	 XM_UA_NO_VERSION(0.01)[];
	 SPAMHAUS_XBL(0.00)[2a07:de40:b281:104:10:150:64:97:from];
	 TO_DN_SOME(0.00)[];
	 RCVD_COUNT_THREE(0.00)[3];
	 DKIM_TRACE(0.00)[suse.cz:+];
	 MX_GOOD(-0.01)[];
	 RCPT_COUNT_GT_50(0.00)[75];
	 FROM_EQ_ENVFROM(0.00)[];
	 MIME_TRACE(0.00)[0:+];
	 MID_RHS_MATCH_FROM(0.00)[];
	 BAYES_HAM(-0.04)[58.46%];
	 ARC_NA(0.00)[];
	 R_DKIM_ALLOW(-0.20)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	 FROM_HAS_DN(0.00)[];
	 FREEMAIL_ENVRCPT(0.00)[gmail.com];
	 TAGGED_RCPT(0.00)[];
	 MIME_GOOD(-0.10)[text/plain];
	 TO_MATCH_ENVRCPT_SOME(0.00)[];
	 DKIM_SIGNED(0.00)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	 DBL_BLOCKED_OPENRESOLVER(0.00)[suse.cz:email,suse.cz:dkim];
	 FUZZY_BLOCKED(0.00)[rspamd.com];
	 FREEMAIL_CC(0.00)[linux.dev,suse.com,cmpxchg.org,suse.de,stgolabs.net,infradead.org,oracle.com,i-love.sakura.ne.jp,lwn.net,manifault.com,redhat.com,arm.com,kernel.org,arndb.de,linutronix.de,linux.intel.com,kernel.dk,nvidia.com,soleen.com,google.com,gmail.com,chromium.org,linuxfoundation.org,linaro.org,goodmis.org,linux.com,lge.com,bytedance.com,akamai.com,android.com,vger.kernel.org,lists.linux.dev,kvack.org,googlegroups.com];
	 RCVD_TLS_ALL(0.00)[];
	 SUSPICIOUS_RECIPS(1.50)[];
	 RBL_SPAMHAUS_BLOCKED_OPENRESOLVER(0.00)[2a07:de40:b281:104:10:150:64:97:from]
X-Spam-Score: 1.16
X-Spam-Level: *
X-Rspamd-Queue-Id: C35421F7D4
X-Spam-Flag: NO
X-Rspamd-Server: rspamd1.dmz-prg2.suse.org
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=Nmf6Xm61;       dkim=neutral
 (no key) header.i=@suse.cz header.s=susede2_ed25519;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=Nmf6Xm61;       dkim=neutral
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
> When a non-compound multi-order page is freed, it is possible that a
> speculative reference keeps the page pinned. In this case we free all
> pages except for the first page, which will be freed later by the last
> put_page(). However put_page() ignores the order of the page being freed,
> treating it as a 0-order page. This creates a memory accounting imbalance
> because the pages freed in __free_pages() do not have their own alloc_tag
> and their memory was accounted to the first page. To fix this the first
> page should adjust its allocation size counter when "tail" pages are freed.
> 
> Reported-by: Vlastimil Babka <vbabka@suse.cz>
> Signed-off-by: Suren Baghdasaryan <surenb@google.com>

Reviewed-by: Vlastimil Babka <vbabka@suse.cz>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/76c84f17-8b99-4f68-a6ac-a0db22f5ace3%40suse.cz.
