Return-Path: <kasan-dev+bncBDXYDPH3S4OBBPGLRXEAMGQEIFMXOEI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x337.google.com (mail-wm1-x337.google.com [IPv6:2a00:1450:4864:20::337])
	by mail.lfdr.de (Postfix) with ESMTPS id 016ECC20319
	for <lists+kasan-dev@lfdr.de>; Thu, 30 Oct 2025 14:18:54 +0100 (CET)
Received: by mail-wm1-x337.google.com with SMTP id 5b1f17b1804b1-4711899ab0asf8018815e9.2
        for <lists+kasan-dev@lfdr.de>; Thu, 30 Oct 2025 06:18:53 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1761830333; cv=pass;
        d=google.com; s=arc-20240605;
        b=N7/ElAyOJ5xyFKhEgzqFKeFDSQlXO41VQkX62Tq03//v/jmP6KkNtEWBEhYOgaFcCK
         1i0Dnj2UhS4Tg0UIsehAZInTxEsZq7sR1ZvI1RbOt5E9aYPITdgRqywXYKZemlaIWI2t
         74F2qkWSFMVtqoxwWJufdzuZvCsSsWfGOOWS/bY5lzLtMLuyyeYsZHtbvDpMelOF0JEC
         W3Itg82o3vKZwvMxSekceZk1zKV0LaCjMQ36sHzRcYCy5fW6FYDsIwZGUnn5GbJUyLKD
         Q9E4dA2+xiMuGYjPW5gxq0lPkjxoFADKlTQKqOj6pkCYfw2RDxxpyxRMvulid82sSca+
         gBwQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:autocrypt:from
         :references:cc:to:content-language:subject:user-agent:mime-version
         :date:message-id:sender:dkim-signature;
        bh=jAWBAHxRh/xHGOWb+JL5+rQQ4p2zb4yCTyvD+DeQhm0=;
        fh=xNxRNKN+dHhQbwZ5/8/NjYR9I3sYCWSjhfZkP+AH/Os=;
        b=ESbqvrKx7E7ITPDVeBAbr3MYG90CEaKIxRKRapCKDxEPCqlalt2jodmOugkKXP1O+G
         ZLZbzZAq/vuUrL5EewV3a4pa47axWXvHgm12eySEFR6nPoVpXUX+qwuLVZGbXKrbH9al
         veqa9kVWc05/vAHEVpV2FpdMrUlMUf1W98LX/CtcKrfsCv+/rMRYMRwLgaW/vBK0Uo5N
         QRpVDL76cw+5PKzdW3svYL/8rhzICA+6iX/l1XUipgLjJhJEuAk+D99bQJIiUFyZ40Kj
         FYt4t+hEC7laffH9igTS6MJU280LTbUS9y/8WnJ8GIwAngZ6V9GMHU30R/Fqkge27Dmo
         VdeQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=kX0etpTo;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=kX0etpTo;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1761830333; x=1762435133; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:autocrypt:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=jAWBAHxRh/xHGOWb+JL5+rQQ4p2zb4yCTyvD+DeQhm0=;
        b=G9x3cagIdMHJGLsD0opXwq9Ymoz7f4S1Stm1P44hbaAj6z9HHQuFAN5jZ8Z8mDjGtd
         RgZBiR7DeOZ93MzuRkdTKesMfN+z/R5AcfFVtLrEdopX/P8n2sOE8jJqSxgiQPJ9lC9Z
         kgE1c2cjHmHeKpK4lZ9ws08UlS5uaDT6s2eNAVZI/9c6xFniipYkKzLVgLBfyCt2vzV4
         x9jEwTSBlRcAaiTncZWKBL2Fj9bOKA0WfQQC54vAA6kyuq08GtIkqGae3NHAXJWWQ1eB
         J0hgaE+CpUVf7EU2R23VWFE3fgaKQGNdNHwoQsbkAxwnTPiCZRuYgjlgrlDEC73fNY2e
         a8Zw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1761830333; x=1762435133;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :autocrypt:from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=jAWBAHxRh/xHGOWb+JL5+rQQ4p2zb4yCTyvD+DeQhm0=;
        b=tv+45+XazCT1NfW6YzVVCgwyRfPQ5BHfeUXN1jCnr2am6zBLJO+n6NuAIN+kBAtVUT
         bfNH3eJavclfs8GqD43AT2dKl43+vCur3bKEo9FVkgt1fh6PcRpRAkeINH/zViarAnEm
         PqxglUxSt4L95rGEBeGE0mm17lZsjPefQJvMNcpP7RTPwy808wtK1/6DT/oJFMy4He1L
         nLVdtuTYxAeBxlRETD4cBlzUMMe7AkQCp/5zGUEeXKQmqJqpZB6/AkWFuKZNYhOVANdf
         oDuJlcXC4yGFHcisPMcviSu7hEPYrPL+p+SS2paRv/hO2LsVe5+6EG5sOclepviY/A9e
         9SQw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUtc3VXuw+odFbNEtv8AmIabtGr8BvVpPrnQoccVIDa7yBSO7MqF5Aa7cO100NjsHtKqNZnQA==@lfdr.de
X-Gm-Message-State: AOJu0YyzaUCrYk4gSnb8aZW03enhq3Px9Gf1qhTPrIF1sEQBcrj96RXK
	aZ9i+IgQ56HskKllbdvT8E3T8q1lSeNV4hWHwaOnAqUQoVOAkJ7og4Rz
X-Google-Smtp-Source: AGHT+IH5kLTb6Xa0PrWBvumYAoXrETEfB6olXIoGjLhEopohKvOKtg3Q9IFvq2rw+7qDkrn/W/W7AA==
X-Received: by 2002:a05:600c:6303:b0:46e:4329:a4d1 with SMTP id 5b1f17b1804b1-4772675fffdmr27431915e9.4.1761830333206;
        Thu, 30 Oct 2025 06:18:53 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+aj6oiFN/3Jep3P74E/5a6tlO7jDQQiw1hGSEkwMiMgqw=="
Received: by 2002:a05:600c:48a5:b0:46e:2d81:f59c with SMTP id
 5b1f17b1804b1-477279cd66els3888285e9.1.-pod-prod-08-eu; Thu, 30 Oct 2025
 06:18:48 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXSAS4csdP7GRasKPbQYAz301V9N5o5yz79yvtO7lzbyTUVqt+KvKB5CpyYpOcS83rhLNOAqx5byWo=@googlegroups.com
X-Received: by 2002:a05:600c:528f:b0:471:700:f281 with SMTP id 5b1f17b1804b1-47726872581mr28286675e9.25.1761830328157;
        Thu, 30 Oct 2025 06:18:48 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1761830328; cv=none;
        d=google.com; s=arc-20240605;
        b=fseEeqfzu59PnVwIAMJK/yNIJ1bn+66lDu+I/W+ZEHW/9280zOqlmO2pu5SCdN+qaa
         01dMnzO8ZtNJwPdCRnOnHvXWikDXY3TgrjKCvaf8hOkE6EAcxgWXuIKytOc3yWtIgWEq
         6ZjNk0+GqkWAQ73fF6sevmcNzVSBDlArvCN/ZD6w+rdgd7VGAl3VLQIcjW7LTP8NLte9
         oGpdTNWsH7c+3XQiB2lukdotyuyg1MdBN6IfaPgV1k6nAEvWRHWFWHKpCxeGO7q6UrTi
         xyfV8XEUyebp9SKH937Ko+QfLVuHIjEq7wkI9mRRHzzs7L7g3ZTlM7fFhbPD/TaaTpnW
         O8Dw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:autocrypt:from:references:cc
         :to:content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature:dkim-signature:dkim-signature;
        bh=CgjcxRthmM6PCoG1BiMHfp5HdQ/ejgbzHCetCjaVfDk=;
        fh=wT+3rUFrxSfWDlIbk/kN62IDJ/K1d10IIhdAHgvNHAE=;
        b=RMTk21e0EvDecuUUMpAnOrMFXMP5WxaBJT/EOTVL2od4q4bJdLQQKZvbINBuM/CFEm
         l/PmVTR3zKOPOYTEutujDtwclAyiUPxrsJ9ONWxlnrvV5b3Vo+Au1DDcoXZKbPkdiJSD
         PW0NU6eHQKIATcVgxigtbjwZ5q9eLl7N7aXe6s7dgKpCDzQwRO0B1ZOU1J7x8DLu3khH
         TsNnG8/ZhyChNtiWhjkXFCNK6GVFiIjv0dB3+qtO5eSSIMxZADM6AQG63aYyWPQQiw2r
         vMLDDlo1/k9b3uFUrmAGVpBpO5RT9xJkM/byFxnlylGdFflEBEDIxONL7zutluKASr0b
         k2qQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=kX0etpTo;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=kX0etpTo;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [195.135.223.131])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-47718b60564si714175e9.1.2025.10.30.06.18.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 30 Oct 2025 06:18:47 -0700 (PDT)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted sender) client-ip=195.135.223.131;
Received: from imap1.dmz-prg2.suse.org (imap1.dmz-prg2.suse.org [IPv6:2a07:de40:b281:104:10:150:64:97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id 06C7A1F6E6;
	Thu, 30 Oct 2025 13:18:47 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id DCE5913393;
	Thu, 30 Oct 2025 13:18:46 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id ovyeNbZlA2kjWgAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Thu, 30 Oct 2025 13:18:46 +0000
Message-ID: <2a95b2db-c487-440c-b95c-35549c8f5ba6@suse.cz>
Date: Thu, 30 Oct 2025 14:18:46 +0100
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH RFC 09/19] slab: add optimized sheaf refill from partial
 list
Content-Language: en-US
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
 <20251023-sheaves-for-all-v1-9-6ffa2c9941c0@suse.cz>
 <aP8dWDNiHVpAe7ak@hyeyoo> <113a75f7-6846-48e4-9709-880602d44229@suse.cz>
 <aQKsNPQe--6QMOg0@hyeyoo>
From: Vlastimil Babka <vbabka@suse.cz>
Autocrypt: addr=vbabka@suse.cz; keydata=
 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
 m6M14QORSWTLRg==
In-Reply-To: <aQKsNPQe--6QMOg0@hyeyoo>
Content-Type: text/plain; charset="UTF-8"
X-Rspamd-Queue-Id: 06C7A1F6E6
X-Rspamd-Server: rspamd2.dmz-prg2.suse.org
X-Spamd-Result: default: False [-4.51 / 50.00];
	BAYES_HAM(-3.00)[100.00%];
	NEURAL_HAM_LONG(-1.00)[-1.000];
	NEURAL_HAM_SHORT(-0.20)[-1.000];
	R_DKIM_ALLOW(-0.20)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	MIME_GOOD(-0.10)[text/plain];
	MX_GOOD(-0.01)[];
	RECEIVED_SPAMHAUS_BLOCKED_OPENRESOLVER(0.00)[2a07:de40:b281:106:10:150:64:167:received];
	FREEMAIL_ENVRCPT(0.00)[gmail.com];
	FUZZY_RATELIMITED(0.00)[rspamd.com];
	ARC_NA(0.00)[];
	RCVD_VIA_SMTP_AUTH(0.00)[];
	RCPT_COUNT_TWELVE(0.00)[15];
	MIME_TRACE(0.00)[0:+];
	RCVD_TLS_ALL(0.00)[];
	MID_RHS_MATCH_FROM(0.00)[];
	DKIM_SIGNED(0.00)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	FROM_HAS_DN(0.00)[];
	FREEMAIL_CC(0.00)[linux-foundation.org,gentwo.org,google.com,linux.dev,gmail.com,oracle.com,linutronix.de,kernel.org,kvack.org,vger.kernel.org,lists.linux.dev,googlegroups.com];
	TO_DN_SOME(0.00)[];
	FROM_EQ_ENVFROM(0.00)[];
	DBL_BLOCKED_OPENRESOLVER(0.00)[imap1.dmz-prg2.suse.org:helo,imap1.dmz-prg2.suse.org:rdns,suse.cz:mid,suse.cz:dkim];
	RCVD_COUNT_TWO(0.00)[2];
	TO_MATCH_ENVRCPT_ALL(0.00)[];
	DKIM_TRACE(0.00)[suse.cz:+]
X-Rspamd-Action: no action
X-Spam-Flag: NO
X-Spam-Score: -4.51
X-Spam-Level: 
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=kX0etpTo;       dkim=neutral
 (no key) header.i=@suse.cz header.s=susede2_ed25519;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=kX0etpTo;       dkim=neutral
 (no key) header.i=@suse.cz;       spf=pass (google.com: domain of
 vbabka@suse.cz designates 195.135.223.131 as permitted sender) smtp.mailfrom=vbabka@suse.cz
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

On 10/30/25 01:07, Harry Yoo wrote:
> On Wed, Oct 29, 2025 at 09:48:27PM +0100, Vlastimil Babka wrote:
>> (side note: gfpflags_allow_blocking() might be too conservative now that
>> sheafs will be the only caching layer, that condition could be perhaps
>> changed to gfpflags_allow_spinning() to allow some cheap refill).
> 
> Sounds good to me.

Hm now I realized the gfpflags_allow_blocking() check is there to make sure
we can take the local lock without trylock after obtaining a full sheaf, so
we can install it - because it should mean we're not in an interrupt
context. The fact we already succeeded trylock earlier should be enough, but
we'd run again into inventing ugly tricks to make lockdep happy.

Or we use trylock and have failure paths that are only possible to hit on RT
in practice...

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/2a95b2db-c487-440c-b95c-35549c8f5ba6%40suse.cz.
