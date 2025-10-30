Return-Path: <kasan-dev+bncBDXYDPH3S4OBBW4LR3EAMGQEVRXJPVQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33f.google.com (mail-wm1-x33f.google.com [IPv6:2a00:1450:4864:20::33f])
	by mail.lfdr.de (Postfix) with ESMTPS id 83512C20F70
	for <lists+kasan-dev@lfdr.de>; Thu, 30 Oct 2025 16:35:57 +0100 (CET)
Received: by mail-wm1-x33f.google.com with SMTP id 5b1f17b1804b1-4770eded72csf9314085e9.0
        for <lists+kasan-dev@lfdr.de>; Thu, 30 Oct 2025 08:35:57 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1761838557; cv=pass;
        d=google.com; s=arc-20240605;
        b=BF8PVVBohlWm2jID8IMRht7pSSJ/Q+DxFD3wBTtGP3n7Z1tiaAirF3LojdcGYvVek9
         0YB5XxRxiQOXtDBufWnRQNHs47TfRqE/lzkDcw/P/Ktx8jQkItTuYSj5gdTkwnh1VGLP
         GXP6BA1uxqTpxuXwbtt1rxAJz4Y0rhif7zi0pwFdexvD4LxN55JCyDgwkl6hCfwG6Q6f
         pdyOtx+RWqU7iyaXm9AA5OF6V5xM0229SmA8NE8xW8u7fGNJABRhP4CkKatmqFI36+Gx
         S5hjckn5ftC4m5JPkgCjP41hTbJYhRl2i8sRejh8s+e9ZjCw32n6DhzicbokKiB0cmZO
         2Jlg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :in-reply-to:autocrypt:from:references:cc:to:content-language
         :subject:user-agent:mime-version:date:message-id:sender
         :dkim-signature;
        bh=xazeTi4NWAD7+9I1WWKHtPkwUD8+ufA8EzYKwAVJ7hg=;
        fh=a0czmYEGSvBBo1wQK6Q2yR4W2zYEebrVnGU9oluGJqo=;
        b=VqJqoVZ4murOfWsdTNcgOqh3B+RGltBt8Pxbb4pCNL68Wbefs1Icw+IbWpK8wXTSwn
         w5ZERBjd5OG/4KDkhGgAbEP1DVtp/O6zddNfM8Cpmnzxfech4Wi3FXrWnYVZy5SFgSNX
         xPLjvXj8Tc7bndNKpxSYog95zpV+/injRX6XqcoYXI7KEXmbyR1xYx4zbGX8hVm7JsMb
         U6p72W67zI7BqpIRTVGXwoePl4OpUJFLrLxRtk5B3+JB5GI+RU9X30l/dYowYhstVpKh
         Rnc2lxd1SOSaKl7a98k4TMzyo2KtZIrKjIQ+g/aHhph5TP82hqB69TAcmIJ0GihB9cJA
         7ZWQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=rOatV9nf;
       dkim=neutral (no key) header.i=@suse.cz;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=rOatV9nf;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1761838557; x=1762443357; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:in-reply-to:autocrypt
         :from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=xazeTi4NWAD7+9I1WWKHtPkwUD8+ufA8EzYKwAVJ7hg=;
        b=FCHeALHbN08COy8IfCOODemKZH211uTPFQz/jZRCi/l3KXneKe+DP1gpTFk239Fdjl
         dCILV36x/s41ryuvlcSeOyBrqf22w4SLaP0Ah3graSqd4d/r4wpxIqXJXAR5Z/3t0eiM
         AEAYxQGz1nMUvSkklBceW5P5vRCnfsJYlmmkumqzZQyYtTxbhb5Q2dIb+NxV9CfjwhQS
         4MJex7/U+dtMNIm103WuTD6WEW6YqXDWBqgtQgHnEbf7XMZfsBPhXW77a2Bn8HGj8PBD
         ooDZP/xeDI+nOrfHpRzAEVvCunhnQlywzwcjbdCnw1bp34beZxgKW10516jn+6khGXuS
         k6DQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1761838557; x=1762443357;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:autocrypt:from:references:cc
         :to:content-language:subject:user-agent:mime-version:date:message-id
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=xazeTi4NWAD7+9I1WWKHtPkwUD8+ufA8EzYKwAVJ7hg=;
        b=sWLENJi02OBEO+imQelH12MQI9ZM9sCm2oqaP0989uE8VH1dtUxcYvfeMrDgDIDYRW
         otIvgpzdvabQqwjz6YblyGYoaeJNajWNuGGzbtl9EOpK3JleAFFNpsfnoFqXw7gPefs6
         3rMqMzcYCJrlvMqfCAAgrQTjV8RbiQLt5Ibn2P0qUhHrAt215cyYWwbpuXFm/NiGLp3T
         +tB/URc4ijgqAGGlGI6HQw/Bkr3GvfiWu80yubMI5F650Q7dEZm2k9XvI5AtEmw+MHxX
         zRcEOBtixauR7yJu4qr2mTie+JWlj0eSFokEj+bUBm+AeQHhJcRnoFx2OiMyfkmQk9nP
         GanQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVLnRYIRtIGAARWrpfmGTmLtweqAfMx/B3oc2UU+tvARqrdClnldb/gv0eVL9DKa7NuboYxTQ==@lfdr.de
X-Gm-Message-State: AOJu0YxdoXdgT7wddyq8aySe7c57SOnneD2p3yT/oY40AfOTRtFH2hVH
	7J2N1v+I/25s2pcqqW8V5mo5FLU1S9kVA6brC4V30YSiHMB6M1mc3dd4
X-Google-Smtp-Source: AGHT+IGe0EbyLlRQ9tNFvsGBgSefiYsonIq/uxZ291G1er4kM350BVKKf7f+uO6MvYHjB2fGN47GKA==
X-Received: by 2002:a05:600c:1913:b0:46e:59bd:f7e2 with SMTP id 5b1f17b1804b1-477301041ffmr2648085e9.11.1761838556332;
        Thu, 30 Oct 2025 08:35:56 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+Z57jZCxjnAteZ2ApZjXix1O6wPx/4J7Uj4i2empfmULQ=="
Received: by 2002:a7b:c4ca:0:b0:477:27f3:ca66 with SMTP id 5b1f17b1804b1-47727f3e09als2450165e9.0.-pod-prod-00-eu;
 Thu, 30 Oct 2025 08:35:53 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVWkZ402WthB+yX8Fnuwdkfycp1U2pMo30ggPasFaQR409KhL5eoDrQHmU7ieMOORdVP/5TFuGjkbs=@googlegroups.com
X-Received: by 2002:a05:600c:8288:b0:45d:5c71:769d with SMTP id 5b1f17b1804b1-477300ca65amr3161625e9.8.1761838553370;
        Thu, 30 Oct 2025 08:35:53 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1761838553; cv=none;
        d=google.com; s=arc-20240605;
        b=a+0qFeRoe9YZ1f68K8bq49HKRkcD07bIUnw1esHAYEbJIJbOA7XE+yrnGzy6zzfX63
         UpMmXegulAen7fSEOznGtWIrMWFHvVqKMyyUvK9Y4hO693ftE2nbkqUlwmHf3rwwkigb
         8kkkPlHl6gsja7ydkKR1M1WDHUQ6p5uHZKkL73UY8ytCYmzPoLTA1drK3EbQFiOyGuN4
         8iuTgc0TrL3uJwiW8LGURkrspvHZSvnH7DvlnzxcgGeJKn3UE5a9rUEtL2x75cMN6CLw
         rjm2w+nx6niba4UoPIIs7Fjz6WZQ/dn/cSaKmF+p1fvfu7auEDJBIaTaYBwtOsuNyeO8
         Qd+A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:autocrypt:from:references:cc
         :to:content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature:dkim-signature:dkim-signature;
        bh=2ZC7sKtccy7Dxtp0h0EbRBUPlnYDttAcegCDflOn07Q=;
        fh=csLZ9kt8QwTAorN0ANnsxid1QQsHmUoihvfJejg+xH8=;
        b=kHQUF7FWxnmtb2HQjA39Go8jZL3PHubrSXbX6mxxpeI+A8Ok7TgL8zgfFcjqP3vB0+
         F1QZHzVOqMo4MpqRpSbJneDjJRziIh5iqZitmt7LjtNxnA5S0jZHz+fz9ORZLUvfdUg1
         Jmt0ugf2gdJY6O7GazN4mdyX4C7mPFBW3+7AtwPWIuD5byM0OX/DTJV5uzZBst416SEf
         l3YnVGw4hqaSGewm3GKAjkMUg0xeHY2dRynftnIVFtyz9+ALMmRe4SqHt50W50m8ey8Y
         5kwJ9iMe7QZbzWpPW8Zg0Rn16FaTPLHHLH9xzHhZ9HpNz4gdM/x9uB/+Nl7+QlYoCZX0
         Bxzw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=rOatV9nf;
       dkim=neutral (no key) header.i=@suse.cz;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=rOatV9nf;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [2a07:de40:b251:101:10:150:64:2])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-47727fc5e0asi360365e9.0.2025.10.30.08.35.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 30 Oct 2025 08:35:53 -0700 (PDT)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) client-ip=2a07:de40:b251:101:10:150:64:2;
Received: from imap1.dmz-prg2.suse.org (unknown [10.150.64.97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id A1F371FB3E;
	Thu, 30 Oct 2025 15:35:52 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id 73D221396A;
	Thu, 30 Oct 2025 15:35:52 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id +AqSG9iFA2n+YwAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Thu, 30 Oct 2025 15:35:52 +0000
Message-ID: <5e8e6e92-ba8f-4fee-bd01-39aacdd30dbe@suse.cz>
Date: Thu, 30 Oct 2025 16:35:52 +0100
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH RFC 10/19] slab: remove cpu (partial) slabs usage from
 allocation paths
Content-Language: en-US
To: Alexei Starovoitov <alexei.starovoitov@gmail.com>
Cc: Harry Yoo <harry.yoo@oracle.com>,
 Andrew Morton <akpm@linux-foundation.org>, Christoph Lameter
 <cl@gentwo.org>, David Rientjes <rientjes@google.com>,
 Roman Gushchin <roman.gushchin@linux.dev>,
 Uladzislau Rezki <urezki@gmail.com>,
 "Liam R. Howlett" <Liam.Howlett@oracle.com>,
 Suren Baghdasaryan <surenb@google.com>,
 Sebastian Andrzej Siewior <bigeasy@linutronix.de>,
 Alexei Starovoitov <ast@kernel.org>, linux-mm <linux-mm@kvack.org>,
 LKML <linux-kernel@vger.kernel.org>, linux-rt-devel@lists.linux.dev,
 bpf <bpf@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>
References: <20251023-sheaves-for-all-v1-0-6ffa2c9941c0@suse.cz>
 <20251023-sheaves-for-all-v1-10-6ffa2c9941c0@suse.cz>
 <aQLqZjjq1SPD3Fml@hyeyoo> <06241684-e056-40bd-88cc-0eb2d9d062bd@suse.cz>
 <CAADnVQ+K-gWm6KKzKZ0vVwfT2H1UXSoaD=eA1aRUHpA5MCLAvA@mail.gmail.com>
From: Vlastimil Babka <vbabka@suse.cz>
Autocrypt: addr=vbabka@suse.cz; keydata=
 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
 m6M14QORSWTLRg==
In-Reply-To: <CAADnVQ+K-gWm6KKzKZ0vVwfT2H1UXSoaD=eA1aRUHpA5MCLAvA@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Spam-Level: 
X-Spamd-Result: default: False [-2.80 / 50.00];
	BAYES_HAM(-3.00)[100.00%];
	SUSPICIOUS_RECIPS(1.50)[];
	NEURAL_HAM_LONG(-1.00)[-1.000];
	NEURAL_HAM_SHORT(-0.20)[-1.000];
	MIME_GOOD(-0.10)[text/plain];
	FUZZY_RATELIMITED(0.00)[rspamd.com];
	TAGGED_RCPT(0.00)[];
	RCVD_TLS_ALL(0.00)[];
	ARC_NA(0.00)[];
	MIME_TRACE(0.00)[0:+];
	RCVD_VIA_SMTP_AUTH(0.00)[];
	RCPT_COUNT_TWELVE(0.00)[16];
	FREEMAIL_TO(0.00)[gmail.com];
	FREEMAIL_ENVRCPT(0.00)[gmail.com];
	DKIM_SIGNED(0.00)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	FROM_HAS_DN(0.00)[];
	FREEMAIL_CC(0.00)[oracle.com,linux-foundation.org,gentwo.org,google.com,linux.dev,gmail.com,linutronix.de,kernel.org,kvack.org,vger.kernel.org,lists.linux.dev,googlegroups.com];
	MID_RHS_MATCH_FROM(0.00)[];
	FROM_EQ_ENVFROM(0.00)[];
	RCVD_COUNT_TWO(0.00)[2];
	TO_MATCH_ENVRCPT_ALL(0.00)[];
	URIBL_BLOCKED(0.00)[suse.cz:email,suse.cz:mid,imap1.dmz-prg2.suse.org:helo];
	TO_DN_SOME(0.00)[]
X-Spam-Flag: NO
X-Spam-Score: -2.80
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=rOatV9nf;       dkim=neutral
 (no key) header.i=@suse.cz;       dkim=pass header.i=@suse.cz
 header.s=susede2_rsa header.b=rOatV9nf;       dkim=neutral (no key)
 header.i=@suse.cz;       spf=pass (google.com: domain of vbabka@suse.cz
 designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) smtp.mailfrom=vbabka@suse.cz
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

On 10/30/25 16:27, Alexei Starovoitov wrote:
> On Thu, Oct 30, 2025 at 6:09=E2=80=AFAM Vlastimil Babka <vbabka@suse.cz> =
wrote:
>>
>> On 10/30/25 05:32, Harry Yoo wrote:
>> > On Thu, Oct 23, 2025 at 03:52:32PM +0200, Vlastimil Babka wrote:
>> >> diff --git a/mm/slub.c b/mm/slub.c
>> >> index e2b052657d11..bd67336e7c1f 100644
>> >> --- a/mm/slub.c
>> >> +++ b/mm/slub.c
>> >> @@ -4790,66 +4509,15 @@ static void *___slab_alloc(struct kmem_cache =
*s, gfp_t gfpflags, int node,
>> >>
>> >>      stat(s, ALLOC_SLAB);
>> >>
>> >> -    if (IS_ENABLED(CONFIG_SLUB_TINY) || kmem_cache_debug(s)) {
>> >> -            freelist =3D alloc_single_from_new_slab(s, slab, orig_si=
ze, gfpflags);
>> >> -
>> >> -            if (unlikely(!freelist))
>> >> -                    goto new_objects;
>> >> -
>> >> -            if (s->flags & SLAB_STORE_USER)
>> >> -                    set_track(s, freelist, TRACK_ALLOC, addr,
>> >> -                              gfpflags & ~(__GFP_DIRECT_RECLAIM));
>> >> -
>> >> -            return freelist;
>> >> -    }
>> >> -
>> >> -    /*
>> >> -     * No other reference to the slab yet so we can
>> >> -     * muck around with it freely without cmpxchg
>> >> -     */
>> >> -    freelist =3D slab->freelist;
>> >> -    slab->freelist =3D NULL;
>> >> -    slab->inuse =3D slab->objects;
>> >> -    slab->frozen =3D 1;
>> >> -
>> >> -    inc_slabs_node(s, slab_nid(slab), slab->objects);
>> >> +    freelist =3D alloc_single_from_new_slab(s, slab, orig_size, gfpf=
lags);
>> >>
>> >> -    if (unlikely(!pfmemalloc_match(slab, gfpflags) && allow_spin)) {
>> >> -            /*
>> >> -             * For !pfmemalloc_match() case we don't load freelist s=
o that
>> >> -             * we don't make further mismatched allocations easier.
>> >> -             */
>> >> -            deactivate_slab(s, slab, get_freepointer(s, freelist));
>> >> -            return freelist;
>> >> -    }
>> >> +    if (unlikely(!freelist))
>> >> +            goto new_objects;
>> >
>> > We may end up in an endless loop in !allow_spin case?
>> > (e.g., kmalloc_nolock() is called in NMI context and n->list_lock is
>> > held in the process context on the same CPU)
>> >
>> > Allocate a new slab, but somebody is holding n->list_lock, so trylock =
fails,
>> > free the slab, goto new_objects, and repeat.
>>
>> Ugh, yeah. However, AFAICS this possibility already exists prior to this
>> patch, only it's limited to SLUB_TINY/kmem_cache_debug(s). But we should=
 fix
>> it in 6.18 then.
>> How? Grab the single object and defer deactivation of the slab minus one
>> object? Would work except for kmem_cache_debug(s) we open again a race f=
or
>> inconsistency check failure, and we have to undo the simple slab freeing=
 fix
>>  and handle the accounting issue differently again.
>> Fail the allocation for the debug case to avoid the consistency check
>> issues? Would it be acceptable for kmalloc_nolock() users?
>=20
> You mean something like:
> diff --git a/mm/slub.c b/mm/slub.c
> index a8fcc7e6f25a..e9a8b75f31d7 100644
> --- a/mm/slub.c
> +++ b/mm/slub.c
> @@ -4658,8 +4658,11 @@ static void *___slab_alloc(struct kmem_cache
> *s, gfp_t gfpflags, int node,
>         if (kmem_cache_debug(s)) {
>                 freelist =3D alloc_single_from_new_slab(s, slab,
> orig_size, gfpflags);
>=20
> -               if (unlikely(!freelist))
> +               if (unlikely(!freelist)) {
> +                       if (!allow_spin)
> +                               return NULL;
>                         goto new_objects;
> +               }
>=20
> or I misunderstood the issue?

Yeah that would be the easiest solution, if you can accept the occasional
allocation failures.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/5=
e8e6e92-ba8f-4fee-bd01-39aacdd30dbe%40suse.cz.
