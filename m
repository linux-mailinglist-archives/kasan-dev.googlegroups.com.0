Return-Path: <kasan-dev+bncBDXYDPH3S4OBBWHHRHEAMGQE4JDCPWI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33d.google.com (mail-wm1-x33d.google.com [IPv6:2a00:1450:4864:20::33d])
	by mail.lfdr.de (Postfix) with ESMTPS id 512B1C1D222
	for <lists+kasan-dev@lfdr.de>; Wed, 29 Oct 2025 21:06:50 +0100 (CET)
Received: by mail-wm1-x33d.google.com with SMTP id 5b1f17b1804b1-476b8c02445sf3000165e9.1
        for <lists+kasan-dev@lfdr.de>; Wed, 29 Oct 2025 13:06:50 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1761768409; cv=pass;
        d=google.com; s=arc-20240605;
        b=XJO/vAV65Txln1B7P/vmonj7YaAMyiEzKIHW5o13/8UmGQ6F9uHDq8h3cz91BYip0Y
         Fj9SA5bnhL5gx/O2CypUlf1JqVRIRR1RcSr3VYq7xoW754OIe+TsZJHoYQORXgyIwiBA
         jmBowk+Ojf+pp3g7lf3/0Kwv42EqX56VTSRax+k5eHP+H1fS44ivb9S64zf1Lf2U6J1D
         NfZMUS9KpWryPwomnO0Z46ib8jFk55jWHA/Xg//Bgen/QHqL56SfOCgV7ryMX29QIdza
         wmuDT5IgVQHVrhpbeSTYEul/sm43CjMnnkBGF//ryjyxZoc5T5eWmSw3aCdjPvhoLVqV
         HYVA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:autocrypt:references:cc
         :to:from:content-language:subject:user-agent:mime-version:date
         :message-id:sender:dkim-signature;
        bh=/b0iaRH8nLwm3UcmsGED9tHwZjKH6uOiUho9xYPjv2w=;
        fh=G9z+w3pqSqzAQ6e7dSlVsd4QJeDEoAfGApy9YXpNXQE=;
        b=ltesDx0mQSNvYGHvJ/40GnKyRdAWESfiDf09Op6wF7gABasu88WpSPdMIbZr5vgyIs
         YKieOfFBhr8PKyIieihFpN53NdPDLlQIxgAkyKuwwBCDrz8I7o0uMBI9O/XAI+WuuOEJ
         Zrhb4vah+snJVQeNazZzs0DKnhNHdpgz7okQ2xOnfx1jFv5+xzxQ+Tcc7DwkzNM8Hay1
         a2nw+Gf/pS6Uy6G3+LeNur66Jc/ffqCAT3d3OoYrGgwgnvCJNnCKJ/uZatxB652T3DD8
         DJpSwY82MuEC86OVOCuPyfdcokfRRBHPifnQ7ayg5NIk1eoAAqvkziJp9OVoJ5LJWLHl
         6y1Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=r1GcIp4E;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=r1GcIp4E;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.130 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1761768409; x=1762373209; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:autocrypt:references:cc:to:from
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=/b0iaRH8nLwm3UcmsGED9tHwZjKH6uOiUho9xYPjv2w=;
        b=lAK9P+pZQz/hhdky5BHg1J0LDKc/Ua0O0/BynDYNSkgr+V3RnxSpVMJ+o+kitFOHgg
         ZY7hYtgfgdSMZdj0WODx/CaDtjPITbf0r02qr2U1EyftjbhJ9IHoQ4Szs5CF9I4dm5ds
         wSyA0Nj0rHRDh/wUxoicicUpog4Rctt1+rFncbQxnECapHpNcWRU5rHCt9nst7yZFcNM
         ZWtgZmjGxx7J1SrTrAEbWiDpJeOqe/+YzJSY5nzRyDhFu8n6X8kZHQM+i79KdSPhgNoH
         IEhwO3h/2DuKcE5ClovCoBnhPCdGyjjE3n4u3T0BGJ3rAg9wqQd27QLO/MA3NkO9XVJc
         gtSQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1761768409; x=1762373209;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :autocrypt:references:cc:to:from:content-language:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=/b0iaRH8nLwm3UcmsGED9tHwZjKH6uOiUho9xYPjv2w=;
        b=NwjphPTNPA5yVlwmPscGBzAQnZoHGsHff9hSO0AX82By0ncIN+5oTYHlQxw68Ivj2W
         Uy7I4UzNgQDXkHmNGXsj80BRQ3Cn30lUmtDdAHQkKzTd8SUbQoH0DUBb+eELrYY42CLw
         Ae99LDiSjK6/WT5bJCVcRXjVI8KWq2rfgCf76sUP1Cjyl0pSoUuC1LuMKXvFKfGauZiE
         cnP4S5LlXRQzXVxC3W4sHlLCEVoo8BwGPCORx06DY3bEKZPAdzYuUvGRCvVruMp5i3pQ
         3LTyONPimBjAjLvVS+O5rQ/8+QxjLvJwr34LQFN97PsUTvVs4Bzy2SBzrIz0VDNyeRAC
         6X3w==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUOSegANck2H/OwVejOfJ9QMZfsYA+063IQsZvLjvXHBmKLpv+Oa/djwtfTNaNgc57AM1rXYQ==@lfdr.de
X-Gm-Message-State: AOJu0YzAQOk/MtaZBbx1ZuLpJCka84t/Wmg2blb9V0PddzIqfywGI902
	Ec/tm230anCmTlze2hG3hgGM04TJw//qw9iMYADY6cCvCzPlfnqFmx54
X-Google-Smtp-Source: AGHT+IFL/yoLqsNHwWebie1ScLeljn/GOpMReniBQZA9GzrXMOA9GbVfSzHN+cFHTHeknR9IAmr3mg==
X-Received: by 2002:a05:600c:a09:b0:477:25b9:3917 with SMTP id 5b1f17b1804b1-47726871b86mr5289055e9.39.1761768409376;
        Wed, 29 Oct 2025 13:06:49 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+a07pgm3KXElaNKEGUqL08fYEVWJhqFaFOuj2hpsq+z8Q=="
Received: by 2002:a05:600c:c10f:b0:477:1176:3e9a with SMTP id
 5b1f17b1804b1-477279b8064ls833985e9.2.-pod-prod-09-eu; Wed, 29 Oct 2025
 13:06:46 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVdeZ66N2SewvUq6cDMwHOVC5Is6Wj4fo1LZQiEtlMwiCtBnyCUPLCkwZl6ooScc/RlHbSzZOtt+Jc=@googlegroups.com
X-Received: by 2002:a05:600c:64c8:b0:46e:4a30:2b0f with SMTP id 5b1f17b1804b1-47726822422mr6549165e9.29.1761768406519;
        Wed, 29 Oct 2025 13:06:46 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1761768406; cv=none;
        d=google.com; s=arc-20240605;
        b=U0yZRr5O6Jz1Tw6wn0DdxgKB2Ddx0bcpCutGXCLI4zaBXcP1T1YNxkT5NHqscZo71p
         bOskdBlYS6944NK8go7TtpgQtg0ZKs2gPjKaTAWgTEajBWyEqN4XfW4qur0sib8ungIv
         e+YMcy2MG5WCFBc3y3kOvSeMVvdl3YCweejLK+IbrqhsgPyZ5I5wK7zeeabZGjFZxdRb
         UpNg8SNJ7zy/sZXJ7iVCVmfuyxOQMa99nXMf2vKt/Jb6mFLK6v8EL+bzuKZ8Hp9uCJxd
         2dJYyMdmSiC+U1RKDrCepTVEM/eysrDxcFTY0sfU41pIgiYFKNK3mTo9pnaz9Y8qaUS8
         NU+g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:autocrypt:references:cc:to
         :from:content-language:subject:user-agent:mime-version:date
         :message-id:dkim-signature:dkim-signature:dkim-signature
         :dkim-signature;
        bh=3rh6Q8jxv14gwxuI/eCKLwRLYgtbNSRYJnHAM8bhJmk=;
        fh=wT+3rUFrxSfWDlIbk/kN62IDJ/K1d10IIhdAHgvNHAE=;
        b=WlZ/Ny9BPbySMokMD37MrricucUOQPl633/ngi3Pa1TWpTZCyCSxr/96/SYtLTuXh3
         R2TiougWqjTHkwGSFMtIkk2KE8xXw8+kdpjpQuGhQplLMZ3D4Wl8OjvhNqkb9PfkqPnb
         UPgKY6AYaNinCfkZU6QpiIwb6dQfkrnE/qd2EPF+breLwoocy2sljzC49Q3MiZCGx1eW
         dWT8QIoKPE0cO4CKZMuHTzyYfurfSiBXWFXKGcqTMVxAEVwA6PCH4BoVxwoTprthnGwy
         FZwLj13bRg8efxrvudZrrp9Qg2DK9R96JFl8uEoWMab+bIOOOTU5CDeicecNdVQ4i9yj
         Shyw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=r1GcIp4E;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=r1GcIp4E;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.130 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [195.135.223.130])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-429b526c2c8si9407f8f.8.2025.10.29.13.06.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 29 Oct 2025 13:06:46 -0700 (PDT)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.223.130 as permitted sender) client-ip=195.135.223.130;
Received: from imap1.dmz-prg2.suse.org (unknown [10.150.64.97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id 1222B3462A;
	Wed, 29 Oct 2025 20:06:46 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id DFDD61349D;
	Wed, 29 Oct 2025 20:06:45 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id i05ANtVzAmn6fQAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Wed, 29 Oct 2025 20:06:45 +0000
Message-ID: <3b6178b4-ee0b-46b1-b83e-15a0dadda97c@suse.cz>
Date: Wed, 29 Oct 2025 21:06:45 +0100
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH RFC 08/19] slab: handle kmalloc sheaves bootstrap
Content-Language: en-US
From: Vlastimil Babka <vbabka@suse.cz>
To: Harry Yoo <harry.yoo@oracle.com>
Cc: Andrew Morton <akpm@linux-foundation.org>,
 Christoph Lameter <cl@gentwo.org>, David Rientjes <rientjes@google.com>,
 Roman Gushchin <roman.gushchin@linux.dev>,
 Uladzislau Rezki <urezki@gmail.com>,
 "Liam R. Howlett" <Liam.Howlett@oracle.com>,
 Suren Baghdasaryan <surenb@google.com>,
 Sebastian Andrzej Siewior <bigeasy@linutronix.de>,
 Alexei Starovoitov <ast@kernel.org>, linux-mm@kvack.org,
 linux-kernel@vger.kernel.org, linux-rt-devel@lists.linux.dev,
 bpf@vger.kernel.org, kasan-dev@googlegroups.com
References: <20251023-sheaves-for-all-v1-0-6ffa2c9941c0@suse.cz>
 <20251023-sheaves-for-all-v1-8-6ffa2c9941c0@suse.cz>
 <aP8NMX48FLn8FPZD@hyeyoo> <982967fc-5636-46dc-83a1-ed3f4d98c8ae@suse.cz>
Autocrypt: addr=vbabka@suse.cz; keydata=
 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
 m6M14QORSWTLRg==
In-Reply-To: <982967fc-5636-46dc-83a1-ed3f4d98c8ae@suse.cz>
Content-Type: text/plain; charset="UTF-8"
X-Spam-Level: 
X-Spamd-Result: default: False [-4.30 / 50.00];
	BAYES_HAM(-3.00)[99.99%];
	NEURAL_HAM_LONG(-1.00)[-1.000];
	NEURAL_HAM_SHORT(-0.20)[-1.000];
	MIME_GOOD(-0.10)[text/plain];
	ARC_NA(0.00)[];
	FUZZY_RATELIMITED(0.00)[rspamd.com];
	MIME_TRACE(0.00)[0:+];
	RCPT_COUNT_TWELVE(0.00)[15];
	RCVD_TLS_ALL(0.00)[];
	RCVD_VIA_SMTP_AUTH(0.00)[];
	MID_RHS_MATCH_FROM(0.00)[];
	FREEMAIL_ENVRCPT(0.00)[gmail.com];
	DKIM_SIGNED(0.00)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	FROM_HAS_DN(0.00)[];
	FREEMAIL_CC(0.00)[linux-foundation.org,gentwo.org,google.com,linux.dev,gmail.com,oracle.com,linutronix.de,kernel.org,kvack.org,vger.kernel.org,lists.linux.dev,googlegroups.com];
	TO_DN_SOME(0.00)[];
	FROM_EQ_ENVFROM(0.00)[];
	TO_MATCH_ENVRCPT_ALL(0.00)[];
	RCVD_COUNT_TWO(0.00)[2];
	DBL_BLOCKED_OPENRESOLVER(0.00)[suse.cz:mid,imap1.dmz-prg2.suse.org:helo]
X-Spam-Flag: NO
X-Spam-Score: -4.30
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=r1GcIp4E;       dkim=neutral
 (no key) header.i=@suse.cz header.s=susede2_ed25519;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=r1GcIp4E;       dkim=neutral
 (no key) header.i=@suse.cz;       spf=pass (google.com: domain of
 vbabka@suse.cz designates 195.135.223.130 as permitted sender) smtp.mailfrom=vbabka@suse.cz
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

On 10/29/25 21:06, Vlastimil Babka wrote:
> On 10/27/25 07:12, Harry Yoo wrote:
>>> @@ -8549,6 +8559,74 @@ static struct kmem_cache * __init bootstrap(struct kmem_cache *static_cache)
>>>  	return s;
>>>  }
>>>  
>>> +/*
>>> + * Finish the sheaves initialization done normally by init_percpu_sheaves() and
>>> + * init_kmem_cache_nodes(). For normal kmalloc caches we have to bootstrap it
>>> + * since sheaves and barns are allocated by kmalloc.
>>> + */
>>> +static void __init bootstrap_cache_sheaves(struct kmem_cache *s)
>>> +{
>>> +	struct kmem_cache_args empty_args = {};
>>> +	unsigned int capacity;
>>> +	bool failed = false;
>>> +	int node, cpu;
>>> +
>>> +	capacity = calculate_sheaf_capacity(s, &empty_args);
>>> +
>>> +	/* capacity can be 0 due to debugging or SLUB_TINY */
>>> +	if (!capacity)
>>> +		return;
>> 
>> I think pcs->main should still be !NULL in this case?
> 
> It will remain to be set to bootstrap_sheaf, and with s->sheaf_capacity

... s->sheaf_capacity remaining 0

> things will continue to work.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/3b6178b4-ee0b-46b1-b83e-15a0dadda97c%40suse.cz.
