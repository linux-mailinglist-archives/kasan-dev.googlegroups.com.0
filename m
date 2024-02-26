Return-Path: <kasan-dev+bncBDXYDPH3S4OBB57D6KXAMGQENHTBP7Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23d.google.com (mail-lj1-x23d.google.com [IPv6:2a00:1450:4864:20::23d])
	by mail.lfdr.de (Postfix) with ESMTPS id 3112C867A94
	for <lists+kasan-dev@lfdr.de>; Mon, 26 Feb 2024 16:44:57 +0100 (CET)
Received: by mail-lj1-x23d.google.com with SMTP id 38308e7fff4ca-2d291f09baasf2970291fa.0
        for <lists+kasan-dev@lfdr.de>; Mon, 26 Feb 2024 07:44:57 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1708962296; cv=pass;
        d=google.com; s=arc-20160816;
        b=GayoeoTSZ8p8KeVOeYOZnTZUZN19hqERSEXSyj6Vmogt+IB8m9D6oxJ21kPSpvnV2A
         qXcWNMsJ142/G/IBxXsNvUwfdAfvXqhjKBw2EDyvgtw9ZKPhMBaSG72o7AwXltctMXyh
         Zzk7+5MYGSXDf025G787KyEJAU37YVY+vGSxJ+huhx0VexyR89vjphNgYXH6uLbV70Ay
         3G/bxQQVjFJfuzgXaidVxXAsKpYPHAAdZz43rQapJJ8m9VhyO3u440kJZ918z52oXE8f
         sra0agMVFm+pfn8nocBjP+9aNe1NdNtz2+FYgrz94Cih0AMi2mPQVamVEI06CtXI1T+4
         R38A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=c3Y7EuxpP6p2inTUJkuKBlzAHtCi1pNGCBXHnY2HUhY=;
        fh=Ew3KwspSwyyg0//NvbCmJ8nrWvlmiYYF9T8cooNAluY=;
        b=rC7jesO6u+8Wptt+NBwriC0x+d0C/+j1+1LfyhXuvRomILGag3aM5Vh4k2Lxd2LDnx
         rNb/d9Wjo0EiE4YRJ7o1qEeYhg/ada4fUWnPcskugl4vduhbObDgj9mVmQHnfsm26Zfo
         ATB6SfzBJMzOgMmN2EXtqn5Q9HkodERw2kBnL+T7kfdUdMc4b81alDXvcR2ZeuyVd9cw
         B4SS3HdOD+VRsUzjk+/heqC37HlnX4Jlc1LkhP3FXl3oUksBaGVVhEnK3wazAiEO2wIc
         nA6O64L0QjlcUf6wS0A+ZYl/46if/k+g4vJ8Y/fbid12wkV8wJkHlbVimA4bkQpLdy+n
         xEZA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b="NOETsR1/";
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=Q25SrPtC;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1708962296; x=1709567096; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=c3Y7EuxpP6p2inTUJkuKBlzAHtCi1pNGCBXHnY2HUhY=;
        b=QyfeC92Or7V7DrhL1Rj8cdoivbTa68TDLuYsjX3MgXmha3hAlNhD4dPfzJfpmOFdgr
         kukcfcYyYsMP0aowmCKlL85h8CZCZ+og+Gs5ql2ZpK74CzlOhAdrS8/Owsquch4Z+OCu
         l5DSVVW31w7/9oOUHayQJhI5Tx/G3rdl4dPY6e3ai+Pd4g6yvKrTK9dEaWV7qpYBmqQ3
         ZC/SyiUjt5y+2ocePHcMLo+D7/eB8HLwxTqWvVIG34fpMjlh2Bcdeb3B7lELpJl0qWcG
         P2fePu7eaNbjH/+VWG/5fniCcxO3YI54ofdhPLjDP9fUwjKhOATpMQU7QQWhTlWAcI9V
         qXZw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1708962296; x=1709567096;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=c3Y7EuxpP6p2inTUJkuKBlzAHtCi1pNGCBXHnY2HUhY=;
        b=BVmp/LuTzbin8ukPCRaK7zmUyEzAMoCbw7/vRpM+fR5vmCwghBcWpgcphEm6DpTcwx
         fQbzpOxvp6xX5TJ4llVfx6DkSJKWOFq0xDdGTUG0gz5JACBd2KJKovGlX8cvPwTvTi1o
         QpOHB8B5Wh50NYIir+72FPj7q+M8kyB6dW89KpH6oUp29SMvgbYTLIdbf7BprjKN6rhq
         tdqvrlJQw6JUKsCk+Ggn7hvhoGwIuDtJwcx07ZqQ1X99VasOBtwlyk5ZSORpUMDgPBAO
         d37zUOe6YAOAD+uwczMj/jeuSdkzSavkLGspuoory/DALabRMrf0fgWHo0rCjWE0eO/B
         IJJg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWCdpIbf+xS7JL2hQL3h1tnciuEOppKzfUF0F3Z67xWNhL6cb4n5fxulr4BepD/Zj6968DmpeFhQZj6Vmp8/6gn9Gol5s0LqQ==
X-Gm-Message-State: AOJu0Yz827Clxqd888dE3V6V/lG5EPX+B8KTeQ4sF1kX7yPFrrg0hlw0
	Axxnae1NlmToBHlk0b5nHVSvvgdsHpVfeTmbKFtYiqmVh2DrINpY
X-Google-Smtp-Source: AGHT+IHY0qNjWoo191a9fcwbcON1r+Z7saVFgOkF9irjGu2drJ+l3we/7qOVP1pSF5Sc5YYjyON7fQ==
X-Received: by 2002:a2e:9881:0:b0:2d2:85d5:80c5 with SMTP id b1-20020a2e9881000000b002d285d580c5mr2847500ljj.40.1708962296000;
        Mon, 26 Feb 2024 07:44:56 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:bc1e:0:b0:2d2:7527:604d with SMTP id b30-20020a2ebc1e000000b002d27527604dls167411ljf.0.-pod-prod-03-eu;
 Mon, 26 Feb 2024 07:44:54 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXx1pBVwU8yGOdeYAnxrr9ZGmnoETaQ6QUIsX8IuHSbNAFSXRW4vAEm1lZiKQ3oBj6GwKTRUNWMbJUDN89XSc2aj46hdYrzHKWzLg==
X-Received: by 2002:a2e:a549:0:b0:2d2:6227:d30a with SMTP id e9-20020a2ea549000000b002d26227d30amr5412713ljn.2.1708962294037;
        Mon, 26 Feb 2024 07:44:54 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1708962294; cv=none;
        d=google.com; s=arc-20160816;
        b=a/jsxHw8pDJeUh1Ahn5KzopXn8X8yOzQNgaYVu2xIm85TwlTThPiDs1Ja4DjNMsmsP
         yEE95OfKSCGd/Zi2zbViSmZjWiPEyvbMXGQ6EeNeI1H4mGhn/ld8BSBRaeIlPfD/4VqE
         ctT2gWEdCpk0DzjSrjHvqArAoE70r3zSXiihF1Gf7DwbBw6fWp4QVOt3QXKFNhQzVPdD
         ueCTjo2eJWBbQEI6FIe1SZLHMRQJbyCyqsqi7dD7OpajQMHklI8TChvZqAoygOv4zk1n
         OOENXc0ZdkEePSPU++qNNlhvTg+M6+Kzu+0JN8iy3Jdhe2yfJMOl1OiMcXbt5h1gMJT0
         3cVA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature:dkim-signature:dkim-signature;
        bh=uO6nFRXFkR5BenyCu2zdHy6TynY7FaB2n2EEfF5vWuc=;
        fh=uHNWMypfvJIgzLUNJ/f7XBglIO7UNXG6xoMdd8q3Mvc=;
        b=jQ/RZcLiBAhzoQFEOFvnAoJajsg4k5JgzhMHkW6wJKTpxiF/4i9KZAq2fSneDft6M2
         LD1Tp0WfUgu1lJqB16SJpTmP6ewfJrLIJbvW19+Hr6CtEVMtzPNI7cd7y+uo0IXY3olH
         ykNVcUQDST1PZfzDnq5X4X8Wh0g2PV9O/X3KDdKk7hrRRq16uUKhce2S9I0LK4yCT0ss
         Llr+K8Vx1Ax7TCg8EIKaRzYcCRDv/rKUkE9TSQrH6hJJ942tJebLfm0UPwKZRV4a7Yp8
         I5xHlKN3aGIqFN6MPwc120k7GTa5uXVyzvklGq3UdNyXcWdGkcq1EBfIUUBWaSWkTI8K
         sFwQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b="NOETsR1/";
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=Q25SrPtC;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [195.135.223.131])
        by gmr-mx.google.com with ESMTPS id d20-20020a2e96d4000000b002d25688f527si235960ljj.1.2024.02.26.07.44.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 26 Feb 2024 07:44:53 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted sender) client-ip=195.135.223.131;
Received: from imap1.dmz-prg2.suse.org (imap1.dmz-prg2.suse.org [IPv6:2a07:de40:b281:104:10:150:64:97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id D87201FB62;
	Mon, 26 Feb 2024 15:44:52 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id 3E9C213A3A;
	Mon, 26 Feb 2024 15:44:52 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id Da2gDvSx3GU+BAAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Mon, 26 Feb 2024 15:44:52 +0000
Message-ID: <f68e7f17-c288-4dc9-9ae9-78015983f99c@suse.cz>
Date: Mon, 26 Feb 2024 16:44:51 +0100
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v4 05/36] fs: Convert alloc_inode_sb() to a macro
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
 cgroups@vger.kernel.org, Alexander Viro <viro@zeniv.linux.org.uk>
References: <20240221194052.927623-1-surenb@google.com>
 <20240221194052.927623-6-surenb@google.com>
From: Vlastimil Babka <vbabka@suse.cz>
In-Reply-To: <20240221194052.927623-6-surenb@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Spamd-Result: default: False [1.20 / 50.00];
	 ARC_NA(0.00)[];
	 RCVD_VIA_SMTP_AUTH(0.00)[];
	 R_DKIM_ALLOW(-0.20)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	 XM_UA_NO_VERSION(0.01)[];
	 FROM_HAS_DN(0.00)[];
	 TO_DN_SOME(0.00)[];
	 FREEMAIL_ENVRCPT(0.00)[gmail.com];
	 MID_RHS_MATCH_FROM(0.00)[];
	 TAGGED_RCPT(0.00)[];
	 MIME_GOOD(-0.10)[text/plain];
	 BAYES_HAM(-0.00)[36.17%];
	 R_RATELIMIT(0.00)[to_ip_from(RLcb476ir6xfzaroaj5pc7azzw)];
	 RCVD_COUNT_THREE(0.00)[3];
	 DKIM_SIGNED(0.00)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	 DKIM_TRACE(0.00)[suse.cz:+];
	 TO_MATCH_ENVRCPT_SOME(0.00)[];
	 RCPT_COUNT_GT_50(0.00)[75];
	 MX_GOOD(-0.01)[];
	 DBL_BLOCKED_OPENRESOLVER(0.00)[suse.cz:dkim,linux.dev:email];
	 FUZZY_BLOCKED(0.00)[rspamd.com];
	 FROM_EQ_ENVFROM(0.00)[];
	 MIME_TRACE(0.00)[0:+];
	 FREEMAIL_CC(0.00)[linux.dev,suse.com,cmpxchg.org,suse.de,stgolabs.net,infradead.org,oracle.com,i-love.sakura.ne.jp,lwn.net,manifault.com,redhat.com,arm.com,kernel.org,arndb.de,linutronix.de,linux.intel.com,kernel.dk,soleen.com,google.com,gmail.com,chromium.org,linuxfoundation.org,linaro.org,goodmis.org,linux.com,lge.com,bytedance.com,akamai.com,android.com,vger.kernel.org,lists.linux.dev,kvack.org,googlegroups.com,zeniv.linux.org.uk];
	 RCVD_TLS_ALL(0.00)[];
	 SUSPICIOUS_RECIPS(1.50)[]
X-Rspamd-Server: rspamd1.dmz-prg2.suse.org
X-Spam-Score: 1.20
X-Rspamd-Queue-Id: D87201FB62
X-Spam-Level: *
X-Spam-Flag: NO
X-Spamd-Bar: +
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b="NOETsR1/";
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=Q25SrPtC;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates
 195.135.223.131 as permitted sender) smtp.mailfrom=vbabka@suse.cz
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
> From: Kent Overstreet <kent.overstreet@linux.dev>
> 
> We're introducing alloc tagging, which tracks memory allocations by
> callsite. Converting alloc_inode_sb() to a macro means allocations will
> be tracked by its caller, which is a bit more useful.
> 
> Signed-off-by: Kent Overstreet <kent.overstreet@linux.dev>
> Signed-off-by: Suren Baghdasaryan <surenb@google.com>
> Cc: Alexander Viro <viro@zeniv.linux.org.uk>
> Reviewed-by: Kees Cook <keescook@chromium.org>
> ---
>  include/linux/fs.h | 6 +-----
>  1 file changed, 1 insertion(+), 5 deletions(-)
> 
> diff --git a/include/linux/fs.h b/include/linux/fs.h
> index 023f37c60709..08d8246399c3 100644
> --- a/include/linux/fs.h
> +++ b/include/linux/fs.h
> @@ -3010,11 +3010,7 @@ int setattr_should_drop_sgid(struct mnt_idmap *idmap,
>   * This must be used for allocating filesystems specific inodes to set
>   * up the inode reclaim context correctly.
>   */
> -static inline void *
> -alloc_inode_sb(struct super_block *sb, struct kmem_cache *cache, gfp_t gfp)

A __always_inline wouldn't have the same effect? Just wondering.

> -{
> -	return kmem_cache_alloc_lru(cache, &sb->s_inode_lru, gfp);
> -}
> +#define alloc_inode_sb(_sb, _cache, _gfp) kmem_cache_alloc_lru(_cache, &_sb->s_inode_lru, _gfp)
>  
>  extern void __insert_inode_hash(struct inode *, unsigned long hashval);
>  static inline void insert_inode_hash(struct inode *inode)

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/f68e7f17-c288-4dc9-9ae9-78015983f99c%40suse.cz.
