Return-Path: <kasan-dev+bncBDXYDPH3S4OBBRNLRLEAMGQE3NCAYXI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x440.google.com (mail-wr1-x440.google.com [IPv6:2a00:1450:4864:20::440])
	by mail.lfdr.de (Postfix) with ESMTPS id 9E040C1D972
	for <lists+kasan-dev@lfdr.de>; Wed, 29 Oct 2025 23:31:34 +0100 (CET)
Received: by mail-wr1-x440.google.com with SMTP id ffacd0b85a97d-3f384f10762sf267615f8f.3
        for <lists+kasan-dev@lfdr.de>; Wed, 29 Oct 2025 15:31:34 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1761777094; cv=pass;
        d=google.com; s=arc-20240605;
        b=h4qjDTImSZq8U+WraCOHSvA65I8pmYsQlDWfwA8b7sJ8kQRe9LdTtsgPnjUVAFGIVO
         7LNOpQHAIsnHed/oZXEfZN19oBwQAGzfmGAb8U6fIe6YrrwHh7Ugfk7cOsRNRDK72K0S
         d44GHFi5tYZ+HFeYBQV7fuSRIuyEEDntezxnuKwqzXqspWCzBB1lZfJUtxoIkQhW8fZL
         lQkNAG0cL2jiRNHqegSczepRbVWczx04OTdGrU/lLivswUQhz+Aaf0IwhwvKJIBqf7yM
         ZsC5HR5BqiIAEQ2lawl8u7j6011YVB4jKvlPtzQw1VOXt8FpHl4+uHqEbGOErs+mEX3y
         EvkA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :in-reply-to:autocrypt:from:references:cc:to:content-language
         :subject:user-agent:mime-version:date:message-id:sender
         :dkim-signature;
        bh=XafleV6ZLYFyglawMC6NtDpLv7+iPP8U8VouYZhmXrk=;
        fh=f3/9Ev4Lc7LtTZVdUWdLdk/tKuoGu2lPMq5Oda7J//c=;
        b=ALuR9oBUs/iyreI+wChdjZ4di2g8gM0dk9uDo0HBNcyqEDG6YaELc/xZa9bBhXPuE2
         zaj+JSJJEChtmZuu60MXWU8LRTqIorEYVeVjtezDlMC5IqFlxVwyN1+QKJVGwEzewgM2
         aXtItuJY0huFJ2jzpUxKQquEvuPfG8QPGQecr27mOSpD/IAUHGbTiqHvlz8l5lPD0Wy2
         xXLptppa9OemM61ycvuU2EnNi91SpyjwRt/qFxBRzPNuR3eTI/YFdpmvxYaIqwAOtl1f
         RLnkjgZ0RpUVoxMSukqmk4q7FPU1mpmhOhpLQ0XZz70fuoKKeW2VPkvPcJwZRKwG4ybR
         UODg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=z3Ch5U8f;
       dkim=neutral (no key) header.i=@suse.cz;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=z3Ch5U8f;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1761777094; x=1762381894; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:in-reply-to:autocrypt
         :from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=XafleV6ZLYFyglawMC6NtDpLv7+iPP8U8VouYZhmXrk=;
        b=UMUzfqrXMgDLjthUVl1sdT3gjTQ/4XfG7n1lSGXuROjyzCUfn/oSI8GDz6gZhCUEkP
         gtprndl/CJKggGBNOHopqa5lVOjNYqxrLy9jsClQMLCHdrpA1rx3viMHfaHid1mL4ksG
         jd76FXjlAb/qRkY6fcKHllG2XOoy7qkI4m8pDSz6FwOYUfqDnjllbYdf4H0mxmPCtp/U
         cKbtYjxOHI+/XYu2jOdHe8xI+O6jHJnvYakglzvE/tUe4IXVNuwVwyna4Qn0DB6TsKn7
         e9OhM3im6mEW1/ZMQ8ooMh5PPXvW5pz9hYDKZlmwSmHf7MM6LfnB7mqarCxPbfKtXX32
         skzg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1761777094; x=1762381894;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:autocrypt:from:references:cc
         :to:content-language:subject:user-agent:mime-version:date:message-id
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=XafleV6ZLYFyglawMC6NtDpLv7+iPP8U8VouYZhmXrk=;
        b=TEEod0rsJJfiNNTwal26Thigj6nyLu9x1B8fztKvkoDmXHARGF1LVzfQIOBbxZ7Pwq
         HiIBlj75uiXX89/3ed9NZC5QwL1RBhy+2xEpHRRt2Z5a9MK7WEFSMcdujrq53VuqIfju
         hHL9j/P6CgBr/866dRCoxECkL0JjjNyqaEamX9s5g5Hi9icf4SVNSfKQ+fENORbCdK8M
         ak2MUfnIpDvwQSu0WhcGkobp0PGqZorNydmOwFibeJAcpw3Q7iP6padCN5rf+xd5R/LT
         fUif0TmEQ2GR7uJyCF2w8F5tTcS2TQZ+mHL+6pTpWSgfjPjTJ3I5Dlbv2d+NOMjG6Vtz
         Uvgw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWvu4l0Wfe3BRUoJS/gsFEU5M0g0i72ZLKPmKnxergNr3MtCMVdsP5JukV+IgZr83spuU/onA==@lfdr.de
X-Gm-Message-State: AOJu0YyHdpznW5UL/TwQqjpA2dGONft/qSkao3s9nst0a2ta+qKl0iHg
	tbeHzm7Ed7kiD8A8kSJG8J+nzM1TaUk8LcHGm/kHa2Ype2CMQVokQQk0
X-Google-Smtp-Source: AGHT+IHSS8iJpzfZ7MF+Ly3PoFigbKeq++eLpw9IXjFZWIQGt/peEa+C/2UiBklCQaa2E/gEKyqx/g==
X-Received: by 2002:a05:600c:b85:b0:476:57b4:72b6 with SMTP id 5b1f17b1804b1-4771e16e83emr43318255e9.8.1761777093732;
        Wed, 29 Oct 2025 15:31:33 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+b3buz/YG1jTgQtY31ErHjfKkGNzx+9VS4c7TF2QXd+bw=="
Received: by 2002:a05:600c:628e:b0:46f:c62b:4355 with SMTP id
 5b1f17b1804b1-477279cd870ls1267865e9.1.-pod-prod-03-eu; Wed, 29 Oct 2025
 15:31:31 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWJAJE0a74XWKRZ3CGTNyMcmtgyfNpExe/4xEK2HUpge2EiJE4YKybsT4N7kOXBtgIfx11k2rceehw=@googlegroups.com
X-Received: by 2002:a5d:64e5:0:b0:428:3fe5:6c45 with SMTP id ffacd0b85a97d-429aef837aemr3972804f8f.20.1761777090983;
        Wed, 29 Oct 2025 15:31:30 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1761777090; cv=none;
        d=google.com; s=arc-20240605;
        b=Iv5lDFrgb17eKU4VBEv3c/c3EyHUHmd0D65toRke2P8qGywTaoZhOByBYUfejmdS+8
         LgPdNEf3ABfrI3r6YPH3FGSExAZkpupBnUFqweCIFZaQuUqF5rjg6YQTEXWG7D2wN/AF
         9ObI17Zjg43LXWLWoctKDrB67ybBU6HrW4jFkaQlhlhgnUnTZm+6huwVhqNr/IV98eqZ
         Tm78MHUvVQplZ+5XkAXpJpj4dBeNH7KI3xo3FLRkp1yHHq4S8x/WcqWtZMypmFbTV4Hj
         Mvk4dwP3MOZIXPtBBxby+jpm1LgY0UvRjxr0NFLEZeB+0N48HXoWgvkeWQtQvgTaCBm+
         7XXw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:autocrypt:from:references:cc
         :to:content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature:dkim-signature:dkim-signature;
        bh=dh8+yU8fmyt+6MD4ipOXHynaGNBJYzYXvAUebA2Mox0=;
        fh=ZkncHXpnbLWcLI4CpJ6uugsCcSSvTK4Cn+vNUpK7HFk=;
        b=gjXXRQHR8bj00+XUOYuSeZbnVDWit3hoffVZcDenykLM9GeiL6kz9lvbU8jr81/bNL
         x97L0pu4Zx+L6t8Jm56PuoCLoE+pywoTfg4U47LXlcZZEBZs4/BZslF+nbS7r6k4wy5r
         NKwfLkYeGwWSsX8p1icJv2yXGInGkwakgf1Kin/NQ2Vz3iDVjoEgJkmEfnLsQ79tbZXB
         QmCcxraAr3Ej9oAgnR3niXtTyLwPBrw2PjU40g+EppPjHVQekaMc/qry4du1TYe15t4X
         MZKucq/1qJa+HcOHzmvsUANulD2Xg8x2YMYj1PNxm5aKMH1uw/ir0V3C5Hiy1nuZFCq1
         /sRg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=z3Ch5U8f;
       dkim=neutral (no key) header.i=@suse.cz;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=z3Ch5U8f;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [195.135.223.131])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-42995ff8f70si421324f8f.5.2025.10.29.15.31.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 29 Oct 2025 15:31:30 -0700 (PDT)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted sender) client-ip=195.135.223.131;
Received: from imap1.dmz-prg2.suse.org (unknown [10.150.64.97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id 8EDBB5CB0F;
	Wed, 29 Oct 2025 22:31:30 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id 6D7111349D;
	Wed, 29 Oct 2025 22:31:30 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id yRNXGsKVAmluCAAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Wed, 29 Oct 2025 22:31:30 +0000
Message-ID: <df8b155e-388d-4c62-8643-289052f2fc5e@suse.cz>
Date: Wed, 29 Oct 2025 23:31:30 +0100
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH RFC 11/19] slab: remove SLUB_CPU_PARTIAL
Content-Language: en-US
To: Alexei Starovoitov <alexei.starovoitov@gmail.com>
Cc: Andrew Morton <akpm@linux-foundation.org>,
 Christoph Lameter <cl@gentwo.org>, David Rientjes <rientjes@google.com>,
 Roman Gushchin <roman.gushchin@linux.dev>, Harry Yoo <harry.yoo@oracle.com>,
 Uladzislau Rezki <urezki@gmail.com>,
 "Liam R. Howlett" <Liam.Howlett@oracle.com>,
 Suren Baghdasaryan <surenb@google.com>,
 Sebastian Andrzej Siewior <bigeasy@linutronix.de>,
 Alexei Starovoitov <ast@kernel.org>, linux-mm <linux-mm@kvack.org>,
 LKML <linux-kernel@vger.kernel.org>, linux-rt-devel@lists.linux.dev,
 bpf <bpf@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>
References: <20251023-sheaves-for-all-v1-0-6ffa2c9941c0@suse.cz>
 <20251023-sheaves-for-all-v1-11-6ffa2c9941c0@suse.cz>
 <CAADnVQKBPF8g3JgbCrcGFx35Bujmta2vnJGM9pgpcLq1-wqLHg@mail.gmail.com>
From: Vlastimil Babka <vbabka@suse.cz>
Autocrypt: addr=vbabka@suse.cz; keydata=
 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
 m6M14QORSWTLRg==
In-Reply-To: <CAADnVQKBPF8g3JgbCrcGFx35Bujmta2vnJGM9pgpcLq1-wqLHg@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Spamd-Result: default: False [-2.80 / 50.00];
	BAYES_HAM(-3.00)[100.00%];
	SUSPICIOUS_RECIPS(1.50)[];
	NEURAL_HAM_LONG(-1.00)[-1.000];
	NEURAL_HAM_SHORT(-0.20)[-1.000];
	MIME_GOOD(-0.10)[text/plain];
	FREEMAIL_ENVRCPT(0.00)[gmail.com];
	RCVD_TLS_ALL(0.00)[];
	ARC_NA(0.00)[];
	RCVD_VIA_SMTP_AUTH(0.00)[];
	MIME_TRACE(0.00)[0:+];
	FUZZY_RATELIMITED(0.00)[rspamd.com];
	RCPT_COUNT_TWELVE(0.00)[16];
	TAGGED_RCPT(0.00)[];
	MID_RHS_MATCH_FROM(0.00)[];
	TO_DN_SOME(0.00)[];
	FROM_HAS_DN(0.00)[];
	FREEMAIL_CC(0.00)[linux-foundation.org,gentwo.org,google.com,linux.dev,oracle.com,gmail.com,linutronix.de,kernel.org,kvack.org,vger.kernel.org,lists.linux.dev,googlegroups.com];
	FREEMAIL_TO(0.00)[gmail.com];
	FROM_EQ_ENVFROM(0.00)[];
	RCVD_COUNT_TWO(0.00)[2];
	TO_MATCH_ENVRCPT_ALL(0.00)[];
	DKIM_SIGNED(0.00)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	DBL_BLOCKED_OPENRESOLVER(0.00)[imap1.dmz-prg2.suse.org:helo,suse.cz:mid,suse.cz:email]
X-Spam-Flag: NO
X-Spam-Score: -2.80
X-Spam-Level: 
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=z3Ch5U8f;       dkim=neutral
 (no key) header.i=@suse.cz;       dkim=pass header.i=@suse.cz
 header.s=susede2_rsa header.b=z3Ch5U8f;       dkim=neutral (no key)
 header.i=@suse.cz header.s=susede2_ed25519;       spf=pass (google.com:
 domain of vbabka@suse.cz designates 195.135.223.131 as permitted sender) smtp.mailfrom=vbabka@suse.cz
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

On 10/24/25 22:43, Alexei Starovoitov wrote:
> On Thu, Oct 23, 2025 at 6:53=E2=80=AFAM Vlastimil Babka <vbabka@suse.cz> =
wrote:
>>
>>  static bool has_pcs_used(int cpu, struct kmem_cache *s)
>> @@ -5599,21 +5429,18 @@ static void __slab_free(struct kmem_cache *s, st=
ruct slab *slab,
>>                 new.inuse -=3D cnt;
>>                 if ((!new.inuse || !prior) && !was_frozen) {

This line says "if slab is either becoming completely free (1), or becoming
partially free from being full (2)", and at the same time is not frozen (=
=3D
exclusively used as a c->slab by a cpu), we might need to take it off the
partial list (1) or add it there (2).

>>                         /* Needs to be taken off a list */
>> -                       if (!kmem_cache_has_cpu_partial(s) || prior) {

This line is best explained as a negation. If we have cpu partial lists, an=
d
the slab was full and becoming partially free (case (2)) we will put it on
the cpu partial list, so we will avoid the node partial list and thus don't
need the list_lock. But that's the negation, so if the opposite is true, we
do need it.

And since we're removing the cpu partial lists, we can't put it there even
in case (2) so there's no point in testing for it.
> I'm struggling to convince myself that it's correct.

It should be per above.

> Losing '|| prior' means that we will be grabbing
> this "speculative" spin_lock much more often.
> While before the change we need spin_lock only when
> slab was partially empty
> (assuming cpu_partial was on for caches where performance matters).

That's true. But still, it should happen rarely that slab transitions from
full to partial, it's only on the first free after it became full. Sheaves
should make this rare and prevent degenerate corner case scenarios (slab
oscillating between partial and full with every free/alloc). AFAIK the main
benefit of partial slabs was the batching of taking slabs out from node
partial list under single list_lock and that principle remains with "slab:
add optimized sheaf refill from partial list". This avoidance of list_lock
in slab transitions from full to partial was a nice secondary benefit, but
not crucial.

But yeah, the TODOs about meaningful stats gathering and benchmarking shoul=
d
answer that concern.

> Also what about later check:
> if (prior && !on_node_partial) {
>        spin_unlock_irqrestore(&n->list_lock, flags);
>        return;
> }

That's unaffected. It's actually for case (1), but we found it wasn't on th=
e
list so we are not removing it. But we had to take the list_lock to
determine on_node_partial safely.

> and
> if (unlikely(!prior)) {
>                 add_partial(n, slab, DEACTIVATE_TO_TAIL);

This is for case (2) and we re adding it.

> Say, new.inuse =3D=3D 0 then 'n' will be set,

That's case (1) so it was already on the partial list. We might just leave
it there with n->nr_partial < s->min_partial otherwise we goto slab_empty,
where it's removed and discarded.

> do we lose the slab?
> Because before the change it would be added to put_cpu_partial() ?

No, see above. Also the code already handled !kmem_cache_has_cpu_partial(s)
before. This patch simply assumes !kmem_cache_has_cpu_partial(s) is now
always true. You can see in __slab_free() it in fact only removes code that
became dead due to kmem_cache_has_cpu_partial(s) being now compile-time
constant false.

> but... since AI didn't find any bugs here, I must be wrong :)
It's tricky. I think we could add a "bool was_partial =3D=3D (prior !=3D NU=
LL)" or
something to make it more obvious, that one is rather cryptic.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/d=
f8b155e-388d-4c62-8643-289052f2fc5e%40suse.cz.
