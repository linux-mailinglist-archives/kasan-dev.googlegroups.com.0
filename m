Return-Path: <kasan-dev+bncBDXYDPH3S4OBBDUVVG2QMGQEFGS33KA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x440.google.com (mail-wr1-x440.google.com [IPv6:2a00:1450:4864:20::440])
	by mail.lfdr.de (Postfix) with ESMTPS id 56AFD943205
	for <lists+kasan-dev@lfdr.de>; Wed, 31 Jul 2024 16:30:39 +0200 (CEST)
Received: by mail-wr1-x440.google.com with SMTP id ffacd0b85a97d-368448dfe12sf492621f8f.1
        for <lists+kasan-dev@lfdr.de>; Wed, 31 Jul 2024 07:30:39 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1722436239; cv=pass;
        d=google.com; s=arc-20160816;
        b=Xjb1E3vtpQbK03B7UadgdMlFffBwM+ltMvyzSzrKMSje3smuGrATTNBV9DnTSDGmOW
         Ru1NLYQHvynOzQwCtpLZLXcpBMrxl3hIvX3HolVKQ09iXJtfh9hd3hq3zCUuR89y1Qhd
         oR1tsCbONUFcBNQHcoqrCMdn3gbkcddrF3rBEQB3WHNYEzyMwudjJdYxCQOkGl01EHnu
         raXHLD+Y9Uqz+JEZrHKILMsmHXoyzuGTJBMuRyohDfkaYUYBXDvm48OG0WMfS7NW0MS8
         9ED1wd18/vfEqOBNG/XDQaL3KJlbacSiPVf+ucNnhdWlJQwIMV6D2WMsu2lWejXMXFU/
         Aiyg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:autocrypt:from
         :references:cc:to:content-language:subject:user-agent:mime-version
         :date:message-id:sender:dkim-signature;
        bh=QAhWDxzVyItezmbJOg+TCpmEe0oPExMxz7vV0Go0ON0=;
        fh=eF1lbW1q8INrMX4xw3YQpR8+KLfYDjOoYPOyACvrYoM=;
        b=wUCvtWH5nZLZRKdtdmKXpWsq0FTWFTSyyREjuZD+CNL/y3ZkpP882jc/CFxQDRN1u/
         GKtnMVf5h54jEAGlAWC481YVFKC/hbHwW/JVdTZGzq6C+DRLlKDpUE2mNPEkVatFd3tv
         UeosTqYh4jJjASDi+FKUvEd9rCho4o+b+so7PvZTxhhMJLeaEVyFtLWrjUdcj7Id8BIZ
         gInkvEwHxr2dCHFehX3RiMHOLtIzWcNHysHkM/voEbmf+Lt72/Lla/h7FagPtRqzN2//
         6B3T9Bp7ogdUfD3TLP7yujmP4mitAw+HUs6NFHe3Rii4DIOV8l9SH23uf1WspxC3/9h7
         Lr8w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=p0KWYzyW;
       dkim=neutral (no key) header.i=@suse.cz;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=p0KWYzyW;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.130 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1722436239; x=1723041039; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:autocrypt:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=QAhWDxzVyItezmbJOg+TCpmEe0oPExMxz7vV0Go0ON0=;
        b=Q7vpk5XQBBPCrfOo30likh+adCEu8JbEBN2+q+fb6a+ksMoExHrpYnQ8lm6L1IC8SK
         6NqAo9JU90antMlVnm7yzKNfs4DZuae3bnYkhcRBbY29Z570cGjUKj2fWXDCVuzT9166
         onTf2JzccyUotYE9oAXviSlPVTDA7zUMwH1seEeYDEvqU0fbOqyB/PUpIBctlTMcDTTU
         yHlIqwEyi7J0H23TXDUjVyPhtvNTYYK+6pgGErL/H9eM0IdY+RRU4Z0OOnJM+6nL9ts0
         KDwBA+ShV5nCV+DcGqrld2riwY8Xej0nsS6wbURBhKGTjjx8c3awbRC14+vuJX7hJs7/
         DBLA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1722436239; x=1723041039;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :autocrypt:from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=QAhWDxzVyItezmbJOg+TCpmEe0oPExMxz7vV0Go0ON0=;
        b=ElKed6roD0q2UzjscsRg16JB2uhRKSLtGn728g+LajNQXAIfg/wes7HgOkeqFOkjvR
         ELHMwtZyiSuUkOk8rfvDauRD45GihBzK/BM7G9bDGDllWjtnLWdRn8Nru/BE3zxSAQ1b
         +bEGnIv0MqB5RqvzFvWXxxL6WSaSmU1d5Vaoor3baXtR4JLakfCYaoUHM705xrhvRY8X
         DDdUeDL4icA5VN5nrosW5JdBZCTxzgcGgltf7GFHdwE58lmNeLSG1o042oumuZdRt6Gy
         V19XKyZex1Tz67ZI01QiTV30QGV4j2AsYwLLWuptBpv0v9Ny2lWuditShGQEwP0piWoi
         gUpA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVPX4tRBZOM6FaFkijyXullHHmbwPk+VlG9xWwPMcApGctlx8XBLXtT49hejdKNrXI2cZQmMlweRrTAybPLg6M3LlV1FFcpIA==
X-Gm-Message-State: AOJu0YwftMObGuoBcJ9Kj+/uxYfy72XHb00Q5KNrRFoPf3i3QHRGXLwW
	pZNnRw4f6Db0sbFQ7Lc5Grh7q2FbraK3GPGb2C2o+gBvUtxUczrl
X-Google-Smtp-Source: AGHT+IEeGTSdsmFjuWOTM70D3tTPPdf1zwo5OTkmJ83DmOxV0MG8sKdKEqtZlLSyasqK/eafwBIkfg==
X-Received: by 2002:a5d:66c4:0:b0:368:377a:e8bb with SMTP id ffacd0b85a97d-36b8c9062femr4040012f8f.28.1722436238330;
        Wed, 31 Jul 2024 07:30:38 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:4fd4:b0:428:1081:6352 with SMTP id
 5b1f17b1804b1-42828a26cecls5081355e9.2.-pod-prod-00-eu; Wed, 31 Jul 2024
 07:30:36 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXT+v7UIY22TrFqteqxtX5zxHvMKdWy6JTHkullQMPuBESpQYhKgBE0GvkVtRATSGsOSFL4gXQCVaZotLEoxG8i9HOAdU8YRyMRbw==
X-Received: by 2002:a5d:4009:0:b0:360:70e3:ef2b with SMTP id ffacd0b85a97d-36b8c8ea1c1mr4025480f8f.26.1722436236271;
        Wed, 31 Jul 2024 07:30:36 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1722436236; cv=none;
        d=google.com; s=arc-20160816;
        b=FSZsalq6clWU+IssmpmfvdaqrOGlqQiGQnMyS6ISjcFB3OKQvLLRPS2LaFjIWuqX2e
         aGD9HnsFfxancw7wRfDRTxv98XR5syKy8kSUOdMSBKLaRsDysP//4HCfm649SQDfOIqZ
         BHQhmhcpAoPiEl6SVgnUDiAzhEbnmjROE5xKjyds/3UmyGvkU3HzphuHXND1YXM3TwBB
         Bkilxop5v7ipMeTdsMy+hbgr1w+Ys2pRjGgQewM9QUuGZ81FAXMwXba2Uyq87OeBdsEW
         Gbir4mQ/RqP2TntFnxVe3v7WLag/nA7FMzdeggJLLidrH0YihXx6Sy/6GJNSON30gGdW
         40gg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:autocrypt:from:references:cc
         :to:content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature:dkim-signature:dkim-signature;
        bh=9tM0W7I0njbVjziqfb3oDmm539qCu3D95U35+py9AN8=;
        fh=y9l4G7aqW5TU3lbd4Ap/hSB5WZ6YqDiwLDlf8tUnClo=;
        b=SamfWZvz9EtPcolp5qNF4eKtTt6nVvTZF77YhQydi9/0iivB0SVHA/A1+3fHvfmNsX
         zUDEG7nTM/bLiGIkFAq+TH/LmVFq4FW3SgG5tMW8S3UFRQvoOqXeuO2NEtD2MWEMtNUm
         616iUnJhSmeKAzSjM1HVDAy+eodxu7cVDPLaRIhfNfg19N+d15xsVj1RgH3v2omC19XJ
         +X46/ZdXt5pMkFo8LPvRzT6Kp5J7i9G9UFf2dFzND5a+Lpz2zASjdTmy3GhO9ohQjQUC
         qs8bMoDhSw49YQKWvwCNYNN+vXj1g/MYLGtF3d9nwlqkyZrFqbtIAbIv4NqK8Lj+HeyD
         FzGQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=p0KWYzyW;
       dkim=neutral (no key) header.i=@suse.cz;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=p0KWYzyW;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.130 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [195.135.223.130])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-36b8f5e65e1si67714f8f.0.2024.07.31.07.30.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 31 Jul 2024 07:30:36 -0700 (PDT)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.223.130 as permitted sender) client-ip=195.135.223.130;
Received: from imap1.dmz-prg2.suse.org (imap1.dmz-prg2.suse.org [IPv6:2a07:de40:b281:104:10:150:64:97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id 98E2121A8C;
	Wed, 31 Jul 2024 14:30:35 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id 7F0ED13297;
	Wed, 31 Jul 2024 14:30:35 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id mySoHotKqmbIdAAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Wed, 31 Jul 2024 14:30:35 +0000
Message-ID: <f82fe3a3-58f1-4966-879b-fa978c6f350d@suse.cz>
Date: Wed, 31 Jul 2024 16:30:35 +0200
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH 1/2] mm: krealloc: consider spare memory for __GFP_ZERO
Content-Language: en-US
To: Danilo Krummrich <dakr@kernel.org>
Cc: akpm@linux-foundation.org, cl@linux.com, penberg@kernel.org,
 rientjes@google.com, iamjoonsoo.kim@lge.com, roman.gushchin@linux.dev,
 42.hyeyoo@gmail.com, linux-kernel@vger.kernel.org, linux-mm@kvack.org,
 kasan-dev <kasan-dev@googlegroups.com>
References: <20240730194214.31483-1-dakr@kernel.org>
 <66836dd6-b0c2-4f77-b2a3-c43296aa6c93@suse.cz>
 <Zql9KXRDBb5Ufpp-@pollux.localdomain>
From: Vlastimil Babka <vbabka@suse.cz>
Autocrypt: addr=vbabka@suse.cz; keydata=
 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
 EP+ylKVEKb0Q2A==
In-Reply-To: <Zql9KXRDBb5Ufpp-@pollux.localdomain>
Content-Type: text/plain; charset="UTF-8"
X-Rspamd-Server: rspamd2.dmz-prg2.suse.org
X-Spamd-Result: default: False [0.20 / 50.00];
	SUSPICIOUS_RECIPS(1.50)[];
	NEURAL_HAM_LONG(-1.00)[-1.000];
	R_DKIM_ALLOW(-0.20)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	MIME_GOOD(-0.10)[text/plain];
	MX_GOOD(-0.01)[];
	XM_UA_NO_VERSION(0.01)[];
	DKIM_SIGNED(0.00)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	FUZZY_BLOCKED(0.00)[rspamd.com];
	RBL_SPAMHAUS_BLOCKED_OPENRESOLVER(0.00)[2a07:de40:b281:104:10:150:64:97:from];
	ARC_NA(0.00)[];
	TO_MATCH_ENVRCPT_ALL(0.00)[];
	TO_DN_SOME(0.00)[];
	MIME_TRACE(0.00)[0:+];
	FREEMAIL_ENVRCPT(0.00)[gmail.com];
	FREEMAIL_CC(0.00)[linux-foundation.org,linux.com,kernel.org,google.com,lge.com,linux.dev,gmail.com,vger.kernel.org,kvack.org,googlegroups.com];
	RCVD_TLS_ALL(0.00)[];
	RCVD_COUNT_TWO(0.00)[2];
	MID_RHS_MATCH_FROM(0.00)[];
	FROM_EQ_ENVFROM(0.00)[];
	FROM_HAS_DN(0.00)[];
	SPAMHAUS_XBL(0.00)[2a07:de40:b281:104:10:150:64:97:from];
	RCPT_COUNT_SEVEN(0.00)[11];
	TAGGED_RCPT(0.00)[];
	RECEIVED_SPAMHAUS_BLOCKED_OPENRESOLVER(0.00)[2a07:de40:b281:106:10:150:64:167:received];
	DKIM_TRACE(0.00)[suse.cz:+];
	RCVD_VIA_SMTP_AUTH(0.00)[];
	DBL_BLOCKED_OPENRESOLVER(0.00)[suse.cz:dkim]
X-Spamd-Bar: /
X-Rspamd-Queue-Id: 98E2121A8C
X-Spam-Level: 
X-Rspamd-Action: no action
X-Spam-Flag: NO
X-Spam-Score: 0.20
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=p0KWYzyW;       dkim=neutral
 (no key) header.i=@suse.cz;       dkim=pass header.i=@suse.cz
 header.s=susede2_rsa header.b=p0KWYzyW;       dkim=neutral (no key)
 header.i=@suse.cz;       spf=pass (google.com: domain of vbabka@suse.cz
 designates 195.135.223.130 as permitted sender) smtp.mailfrom=vbabka@suse.cz
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

On 7/31/24 1:54 AM, Danilo Krummrich wrote:
> On Tue, Jul 30, 2024 at 11:14:16PM +0200, Vlastimil Babka wrote:
>> On 7/30/24 9:42 PM, Danilo Krummrich wrote:
>> > As long as krealloc() is called with __GFP_ZERO consistently, starting
>> > with the initial memory allocation, __GFP_ZERO should be fully honored.
>> > 
>> > However, if for an existing allocation krealloc() is called with a
>> > decreased size, it is not ensured that the spare portion the allocation
>> > is zeroed. Thus, if krealloc() is subsequently called with a larger size
>> > again, __GFP_ZERO can't be fully honored, since we don't know the
>> > previous size, but only the bucket size.
>> > 
>> > Example:
>> > 
>> > 	buf = kzalloc(64, GFP_KERNEL);
>> > 	memset(buf, 0xff, 64);
>> > 
>> > 	buf = krealloc(buf, 48, GFP_KERNEL | __GFP_ZERO);
>> > 
>> > 	/* After this call the last 16 bytes are still 0xff. */
>> > 	buf = krealloc(buf, 64, GFP_KERNEL | __GFP_ZERO);
>> > 
>> > Fix this, by explicitly setting spare memory to zero, when shrinking an
>> > allocation with __GFP_ZERO flag set or init_on_alloc enabled.
>> > 
>> > Signed-off-by: Danilo Krummrich <dakr@kernel.org>
>> > ---
>> >  mm/slab_common.c | 7 +++++++
>> >  1 file changed, 7 insertions(+)
>> > 
>> > diff --git a/mm/slab_common.c b/mm/slab_common.c
>> > index 40b582a014b8..cff602cedf8e 100644
>> > --- a/mm/slab_common.c
>> > +++ b/mm/slab_common.c
>> > @@ -1273,6 +1273,13 @@ __do_krealloc(const void *p, size_t new_size, gfp_t flags)
>> >  
>> >  	/* If the object still fits, repoison it precisely. */
>> >  	if (ks >= new_size) {
>> > +		/* Zero out spare memory. */
>> > +		if (want_init_on_alloc(flags)) {
>> > +			kasan_disable_current();
>> > +			memset((void *)p + new_size, 0, ks - new_size);
>> > +			kasan_enable_current();
>> 
>> If we do kasan_krealloc() first, shouldn't the memset then be legal
>> afterwards without the disable/enable dance?
> 
> No, we always write into the poisoned area. The following tables show what we do
> in the particular case:
> 
> Shrink
> ------
>           new        old
> 0         size       size        ks
> |----------|----------|----------|
> |   keep   |        poison       |  <- poison
> |--------------------------------|
> |   keep   |         zero        |  <- data
> 
> 
> Poison and zero things between old size and ks is not necessary, but we don't
> know old size, hence we have do it between new size and ks.
> 
> Grow
> ----
>           old        new
> 0         size       size        ks
> |----------|----------|----------|
> |       unpoison      |   keep   | <- poison
> |--------------------------------|
> |         keep        |   zero   | <- data
> 
> Zeroing between new_size and ks in not necessary in this case, since it must be
> zero already. But without knowing the old size we don't know whether we shrink
> and actually need to do something, or if we grow and don't need to do anything.
> 
> Analogously, we also unpoison things between 0 and old size for the same reason.

Thanks, you're right!

>> 
>> > +		}
>> > +
>> >  		p = kasan_krealloc((void *)p, new_size, flags);
>> >  		return (void *)p;
>> >  	}
>> > 
>> > base-commit: 7c3dd6d99f2df6a9d7944ee8505b195ba51c9b68
>> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/f82fe3a3-58f1-4966-879b-fa978c6f350d%40suse.cz.
