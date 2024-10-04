Return-Path: <kasan-dev+bncBDXYDPH3S4OBBWHF723QMGQESWJRYNQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33c.google.com (mail-wm1-x33c.google.com [IPv6:2a00:1450:4864:20::33c])
	by mail.lfdr.de (Postfix) with ESMTPS id E762998FF79
	for <lists+kasan-dev@lfdr.de>; Fri,  4 Oct 2024 11:18:17 +0200 (CEST)
Received: by mail-wm1-x33c.google.com with SMTP id 5b1f17b1804b1-42cb374f0cdsf9248605e9.0
        for <lists+kasan-dev@lfdr.de>; Fri, 04 Oct 2024 02:18:17 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1728033497; cv=pass;
        d=google.com; s=arc-20240605;
        b=IF/v24SlWnilh8Wrv+ainVAyY9ORD3XoEz6nJHRvhGqErgOHWxXN0Lc2zzWxnBE2wn
         z9ZSVTZhd165P7SK4TCfToSAyFf/RXOo8NxF+WJh7d4LD7ahS9Jo130NCvs5RmnvfMd7
         xsUxnHDLz72yN8uL1aH89tB+AW1S2bUg0X6hTobXW9B7yxK479f8XibT2bRHq4MOfBc5
         HOxPHn5objwzcVRJsqGehjQ6xW7CzEQN/TMRdwMRQV27i2sHVJqsHbMNdnnAHuAq9tER
         hWKZ7ASfptie7uQmcA1jnwzvxtQ9CB1hlfjwqtu8t0hios3fLBKnv5awZtZSw3Z21Po0
         YWxQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:autocrypt:from
         :content-language:references:cc:to:subject:user-agent:mime-version
         :date:message-id:sender:dkim-signature;
        bh=I25kRjV8pJsc5Ueskf2o8zRNIQJVimZSNts1/bSUNxk=;
        fh=dXfwKXDKomhN5fcrEv1EWMapZOqRo4x8VJvhADfG4lo=;
        b=BGr4xRijHGDbYvK1g332JMY9gGgRN4ttDO4b2i6x8IFltuoYPATD1YAuPNDXkJ0+UQ
         viMt66BrYtemSLRkbBAlsFjbixLbTeZq+vx11Cqz1v/uC2csq+N4HaKunWGFozvE+UVD
         sbjPlrrTn04NdzuTDYx+KYO2+AU6WHLB3IxjBP3DlLPkj2AZX+AuAOWEwAFaEsuCM2Qe
         9NENA3FVsMgJ+5KzuhiCAgUNG9IGLRPtab9XOhd+S5VWsuu/1fvOYukjYPSZF/SLleBd
         dTutIOIbBU98n1hpBqfwTF2qvMkqVKtRUUyP4j07s9T6pOZanG1Esha6JnVkOehcRrvP
         Y8cQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=Uj3a0tJL;
       dkim=neutral (no key) header.i=@suse.cz;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=Uj3a0tJL;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=QfQE8COh;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.130 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1728033497; x=1728638297; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:autocrypt:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=I25kRjV8pJsc5Ueskf2o8zRNIQJVimZSNts1/bSUNxk=;
        b=dWLPNh/1dAdaMpOmz/8yloNzDkHF3m757pxH2J1ZUVrZBWL+I/wXQcWkW+yEmqnxDi
         /bS6u+zddVLJDaQVuq7KgbSIzIGyo6yMqaEVCaGCKYx5MtGB+3zeLvN0LCA4Yi7kXSfr
         X2DQknSoMULiaHmUQgA81eQhSa+c4Cs0sby4FEXdaaGSQ1/n8soVtxxEX7fCxk24/yLW
         CTGuFQD4U3IwtHtyQgb7KJJsAA+lFNB+rnIGK9i4CkQ7SOiXTk3LBa1Cmp7kOtKvnpiq
         cRW4Ce/T5aH5VmjyyzjbGCKoChKTRCl9u/JcD067xHzg+WQctBHl9kfnsSqw1oO9rX08
         uPoA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1728033497; x=1728638297;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :autocrypt:from:content-language:references:cc:to:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=I25kRjV8pJsc5Ueskf2o8zRNIQJVimZSNts1/bSUNxk=;
        b=ZS97GeY3jC91EtJJ0xuCm2VvQ+wjIWqJG8fd9WCKLh+4goJug7SzKGKryd+agebPEp
         sXeT988UI+FHiwa6VOzyhhWpoK4fdK61HbAR1U/JCJQp8QwogZ2ejnt7YG4e0vNcF0k3
         bVpyiYuPxCrYVxEcLtwVnl0Cc9T75AHD0FsOL8NCuY8DArBWl5yk9XlMvj6vsQRQ4MIj
         1QbZwM/ID8FClSIXGmbJHloXzmZ6bidf4NvvRYeotbRtnpCUg4Xk+lDYtWI7M8l2/ZRW
         KQjWwmJQPYYWPoTOvTJ0JceGwEMhtZ2nnkC+cHSNIu608hUhUYYB6WWTrP22ztZ/jTxs
         3PRA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWiEPjT5oUSgj9inLrorcgNz9BwqIlJak1E+m5AcwokPpHO3qpiLzmo/hx237zFAf86NknyMw==@lfdr.de
X-Gm-Message-State: AOJu0YxWLr2Mbib6TezuPWmkbAIPmNrlZcqbZectQlAyu9q5dnitQS/I
	C6QMfzwfH3s+gKUoKJxS29YxICROAcxFTUlLpQiGfOrnJ/MId+tO
X-Google-Smtp-Source: AGHT+IG6pJhemJyUy+cOhC9ybfb9gTBeSoCeKRWWh0PFxXSUuxP5MzMOtQVyMwTTS91tmqXL6mOAjQ==
X-Received: by 2002:a05:600c:3b91:b0:42f:8515:e4ad with SMTP id 5b1f17b1804b1-42f856d271dmr11218655e9.14.1728033496554;
        Fri, 04 Oct 2024 02:18:16 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:19c6:b0:42c:b037:5fb1 with SMTP id
 5b1f17b1804b1-42f7e4d1be6ls5906065e9.1.-pod-prod-00-eu; Fri, 04 Oct 2024
 02:18:14 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWtEO7u6pT0uM3a5B2+f+Kv80K9x8ZWJr5sdbE7GDXZItlehkVBqPDWTvs3GTfSm3cumot025Il07E=@googlegroups.com
X-Received: by 2002:a05:600c:3589:b0:424:8743:86b4 with SMTP id 5b1f17b1804b1-42f7df1e5cfmr37802035e9.6.1728033494462;
        Fri, 04 Oct 2024 02:18:14 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1728033494; cv=none;
        d=google.com; s=arc-20240605;
        b=fQPsATZt2HiXx3ajZN26hgB1PY5Y0O5fp3oTSdvNsSHGVzAcgwMDaynxHuyHEbPw7h
         YopXtsuR0xk7aiWtrqf+/WQkBaT9rH7FRubfseF5LTEhrM/ej8qzfPsGat0BTqMy0bM2
         dJBBPWPQ1WEMrxkBEuuZacxSFjry584wOd1sIiG0KjryVDKc/Ppu57pdo9Jg41PRrjYT
         SEY76xpDd9bE4TW6iD72sXZnUexfP7m29SvztqwTvoTCMYUUY4pkGQlxReOM8NJD2CRd
         4LEcFUVULrcm4uz7CyY5bL3DOKVRjd7aA0oFxXI363I38MmckDVVex3p5gAfqopS2y/L
         dVfA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:autocrypt:from
         :content-language:references:cc:to:subject:user-agent:mime-version
         :date:message-id:dkim-signature:dkim-signature:dkim-signature
         :dkim-signature;
        bh=hJvWtxFfWRqgDS5wtzltJ9aaFP0PBIh4+i3oe2Vw3LE=;
        fh=5N1HThlDAESuEoE7HRX8vb2Wkw61+stOkYicktTdUig=;
        b=HGVGwlQaHRn6qbTbWHgaMS1oFdbD31alZgQy6kvQ/u5b8wWoA2Bh9BFW38QGDqHUGE
         +B344mGfBVJAUPFkvQSUhtWZy2qR4JUB+OxAiZqU8qX+U4D4KZu3ttjPoWmq9kvZokDY
         6zOpxYzovjQb2H9fAhD089Jakeq67eeG96wq4gEZJuV8K1+SkR+qm5L9vlQXhQ8101x+
         xH2g0HGScRkfZjHkMIXS58Bo+ybCM1le4ec47usdWEbSyhnCPgHJsGCLTGD0DBUI/J6l
         F/TOaKEIPLP31XF0/cVKi71S5ai8tzeDm7wBcVCQDhzpHZIHXa2sInaGBGL9EfSJEJEw
         JZ9A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=Uj3a0tJL;
       dkim=neutral (no key) header.i=@suse.cz;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=Uj3a0tJL;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=QfQE8COh;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.130 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [195.135.223.130])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-42f86717be9si440565e9.1.2024.10.04.02.18.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 04 Oct 2024 02:18:14 -0700 (PDT)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.223.130 as permitted sender) client-ip=195.135.223.130;
Received: from imap1.dmz-prg2.suse.org (imap1.dmz-prg2.suse.org [IPv6:2a07:de40:b281:104:10:150:64:97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id AF47D21E2C;
	Fri,  4 Oct 2024 09:18:13 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id 8309813A55;
	Fri,  4 Oct 2024 09:18:13 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id sMKfH9Wy/2YrCAAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Fri, 04 Oct 2024 09:18:13 +0000
Message-ID: <49ef066d-d001-411e-8db7-f064bdc2104c@suse.cz>
Date: Fri, 4 Oct 2024 11:18:13 +0200
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v2 0/5] mm/slub: Improve data handling of krealloc() when
 orig_size is enabled
To: Marco Elver <elver@google.com>
Cc: Feng Tang <feng.tang@intel.com>, Andrew Morton
 <akpm@linux-foundation.org>, Christoph Lameter <cl@linux.com>,
 Pekka Enberg <penberg@kernel.org>, David Rientjes <rientjes@google.com>,
 Joonsoo Kim <iamjoonsoo.kim@lge.com>,
 Roman Gushchin <roman.gushchin@linux.dev>,
 Hyeonggon Yoo <42.hyeyoo@gmail.com>, Andrey Konovalov
 <andreyknvl@gmail.com>, Shuah Khan <skhan@linuxfoundation.org>,
 David Gow <davidgow@google.com>, Danilo Krummrich <dakr@kernel.org>,
 Alexander Potapenko <glider@google.com>,
 Andrey Ryabinin <ryabinin.a.a@gmail.com>, Dmitry Vyukov
 <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>,
 linux-mm@kvack.org, kasan-dev@googlegroups.com,
 linux-kernel@vger.kernel.org, Eric Dumazet <edumazet@google.com>
References: <20240911064535.557650-1-feng.tang@intel.com>
 <d3dd32ba-2866-40ce-ad2b-a147dcd2bf86@suse.cz>
 <CANpmjNM5XjwwSc8WrDE9=FGmSScftYrbsvC+db+82GaMPiQqvQ@mail.gmail.com>
Content-Language: en-US
From: Vlastimil Babka <vbabka@suse.cz>
Autocrypt: addr=vbabka@suse.cz; keydata=
 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
 EP+ylKVEKb0Q2A==
In-Reply-To: <CANpmjNM5XjwwSc8WrDE9=FGmSScftYrbsvC+db+82GaMPiQqvQ@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
X-Rspamd-Queue-Id: AF47D21E2C
X-Spam-Level: 
X-Spamd-Result: default: False [-3.01 / 50.00];
	BAYES_HAM(-3.00)[100.00%];
	SUSPICIOUS_RECIPS(1.50)[];
	NEURAL_HAM_LONG(-1.00)[-1.000];
	R_DKIM_ALLOW(-0.20)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	NEURAL_HAM_SHORT(-0.20)[-1.000];
	MIME_GOOD(-0.10)[text/plain];
	MX_GOOD(-0.01)[];
	FUZZY_BLOCKED(0.00)[rspamd.com];
	ARC_NA(0.00)[];
	TAGGED_RCPT(0.00)[];
	RCVD_VIA_SMTP_AUTH(0.00)[];
	RCPT_COUNT_TWELVE(0.00)[21];
	MIME_TRACE(0.00)[0:+];
	RCVD_TLS_ALL(0.00)[];
	FREEMAIL_ENVRCPT(0.00)[gmail.com];
	TO_DN_SOME(0.00)[];
	FROM_HAS_DN(0.00)[];
	FREEMAIL_CC(0.00)[intel.com,linux-foundation.org,linux.com,kernel.org,google.com,lge.com,linux.dev,gmail.com,linuxfoundation.org,arm.com,kvack.org,googlegroups.com,vger.kernel.org];
	MID_RHS_MATCH_FROM(0.00)[];
	FROM_EQ_ENVFROM(0.00)[];
	RCVD_COUNT_TWO(0.00)[2];
	TO_MATCH_ENVRCPT_ALL(0.00)[];
	DKIM_SIGNED(0.00)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	DKIM_TRACE(0.00)[suse.cz:+]
X-Rspamd-Server: rspamd2.dmz-prg2.suse.org
X-Rspamd-Action: no action
X-Spam-Score: -3.01
X-Spam-Flag: NO
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=Uj3a0tJL;       dkim=neutral
 (no key) header.i=@suse.cz;       dkim=pass header.i=@suse.cz
 header.s=susede2_rsa header.b=Uj3a0tJL;       dkim=neutral (no key)
 header.i=@suse.cz header.s=susede2_ed25519 header.b=QfQE8COh;       spf=pass
 (google.com: domain of vbabka@suse.cz designates 195.135.223.130 as permitted
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

On 10/4/24 08:44, Marco Elver wrote:
> On Wed, 2 Oct 2024 at 12:42, Vlastimil Babka <vbabka@suse.cz> wrote:
>>
>> On 9/11/24 08:45, Feng Tang wrote:
>> > Danilo Krummrich's patch [1] raised one problem about krealloc() that
>> > its caller doesn't pass the old request size, say the object is 64
>> > bytes kmalloc one, but caller originally only requested 48 bytes. Then
>> > when krealloc() shrinks or grows in the same object, or allocate a new
>> > bigger object, it lacks this 'original size' information to do accurate
>> > data preserving or zeroing (when __GFP_ZERO is set).
>> >
>> > Thus with slub debug redzone and object tracking enabled, parts of the
>> > object after krealloc() might contain redzone data instead of zeroes,
>> > which is violating the __GFP_ZERO guarantees. Good thing is in this
>> > case, kmalloc caches do have this 'orig_size' feature, which could be
>> > used to improve the situation here.
>> >
>> > To make the 'orig_size' accurate, we adjust some kasan/slub meta data
>> > handling. Also add a slub kunit test case for krealloc().
>> >
>> > This patchset has dependency over patches in both -mm tree and -slab
>> > trees, so it is written based on linux-next tree '20240910' version.
>> >
>> > [1]. https://lore.kernel.org/lkml/20240812223707.32049-1-dakr@kernel.org/
>>
>> Thanks, added to slab/for-next
> 
> This series just hit -next, and we're seeing several "KFENCE: memory
> corruption ...". Here's one:
> https://lore.kernel.org/all/66ff8bf6.050a0220.49194.0453.GAE@google.com/
> 
> One more (no link):
> 
>> ==================================================================
>> BUG: KFENCE: memory corruption in xfs_iext_destroy_node+0xab/0x670 fs/xfs/libxfs/xfs_iext_tree.c:1051
>>
>> Corrupted memory at 0xffff88823bf5a0d0 [ 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 ] (in kfence-#172):
>> xfs_iext_destroy_node+0xab/0x670 fs/xfs/libxfs/xfs_iext_tree.c:1051
>> xfs_iext_destroy+0x66/0x100 fs/xfs/libxfs/xfs_iext_tree.c:1062
>> xfs_inode_free_callback+0x91/0x1d0 fs/xfs/xfs_icache.c:145
>> rcu_do_batch kernel/rcu/tree.c:2567 [inline]
> [...]
>>
>> kfence-#172: 0xffff88823bf5a000-0xffff88823bf5a0cf, size=208, cache=kmalloc-256
>>
>> allocated by task 5494 on cpu 0 at 101.266046s (0.409225s ago):
>> __do_krealloc mm/slub.c:4784 [inline]
>> krealloc_noprof+0xd6/0x2e0 mm/slub.c:4838
>> xfs_iext_realloc_root fs/xfs/libxfs/xfs_iext_tree.c:613 [inline]
> [...]
>>
>> freed by task 16 on cpu 0 at 101.573936s (0.186416s ago):
>> xfs_iext_destroy_node+0xab/0x670 fs/xfs/libxfs/xfs_iext_tree.c:1051
>> xfs_iext_destroy+0x66/0x100 fs/xfs/libxfs/xfs_iext_tree.c:1062
>> xfs_inode_free_callback+0x91/0x1d0 fs/xfs/xfs_icache.c:145
> [...]
>>
>> CPU: 0 UID: 0 PID: 16 Comm: ksoftirqd/0 Not tainted 6.12.0-rc1-next-20241003-syzkaller #0
>> Hardware name: Google Google Compute Engine/Google Compute Engine, BIOS Google 09/13/2024
>> ==================================================================
> 
> Unfortunately there's no reproducer yet it seems. Unless it's
> immediately obvious to say what's wrong, is it possible to take this
> series out of -next to confirm this series is causing the memory
> corruptions? Syzbot should then stop finding these crashes.

I think it's commit d0a38fad51cc7 doing in __do_krealloc()

-               ks = ksize(p);
+
+               s = virt_to_cache(p);
+               orig_size = get_orig_size(s, (void *)p);
+               ks = s->object_size;

so for kfence objects we don't get their actual allocation size but the
potentially larger bucket size?

I guess we could do:

ks = kfence_ksize(p) ?: s->object_size;

?

> Thanks,
> -- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/49ef066d-d001-411e-8db7-f064bdc2104c%40suse.cz.
