Return-Path: <kasan-dev+bncBDXYDPH3S4OBBE6N7S6QMGQEJEV4WHQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x440.google.com (mail-wr1-x440.google.com [IPv6:2a00:1450:4864:20::440])
	by mail.lfdr.de (Postfix) with ESMTPS id 7931AA462F5
	for <lists+kasan-dev@lfdr.de>; Wed, 26 Feb 2025 15:35:02 +0100 (CET)
Received: by mail-wr1-x440.google.com with SMTP id ffacd0b85a97d-38f2cefb154sf4925733f8f.0
        for <lists+kasan-dev@lfdr.de>; Wed, 26 Feb 2025 06:35:02 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1740580502; cv=pass;
        d=google.com; s=arc-20240605;
        b=PxGzSI0ekO8LZhVGT6skkdGv/cwO4GcZZW8NQ5VOSzm91h7tFRN5iIhPy4Zckvv3z+
         PgAkUFnZeqAo8fdtezFzG/yS0JjGryJrLTzEr/5ZZVUVdeI7HW4zgwsYrC9ELVBZs7/G
         mrnGqE/PxQuXFtQuj+YXjqivXZfgNdYRkay8GLREoMZRylEqzQSURTu2MxDsLu+zK/gR
         s6KqzGAtN8Vx5LccLVCYtBvrJoUgKyfXYXwQwLRE+nGAP9PoLWo+Ri8ApVzjz+5tNxeY
         JyX/uCMF3UulKnKlFke6k/ZBTf4M+ovRPua8aWAHcRZQPXGnMDf/FK4DIhjRNTxo2MvI
         H5uQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-language:from
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=sZ4Iw32US5vlom988oj2KbYhQCW9iYeZmrXAvKkk9cg=;
        fh=x3Y3dvPMt5cD6x6T3yJ8IVFRWKva5xwRU86rG5E0E5w=;
        b=PzdSj3uUAo18hpZ42vVifSJEcbXmbKVUkB30NsVMl7jUMuRyOhKvf0ocZdwTwi8lMJ
         MXvuqavGUF7qOjQ5eUb7XTOrFXRt+nMQvEooc4OBOBJSkigD0UQMl7Br/Yl9aANU2IVl
         x+VPDdyVVBXYI0HJOUqDSUj0hzdo+eCj8B16gm9grOMtEslV4gAwp5duA3RatuJ2H60K
         V1PtnI7hYxF63Ia33WoT0bqQUqWqwlKpquOggyw9IiC7ITf7IkpjIPmLi5ueLD3LsCVq
         GSGf8yy8MZpW9i8QtqFM+rUEilCJ3uDP163IAp14SgqON1QsoT6tSBO7ZmC3V+//ORhC
         VJJQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=SnEImesK;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=rncUprZj;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=SnEImesK;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=rncUprZj;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1740580502; x=1741185302; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-language:from:references:cc
         :to:subject:user-agent:mime-version:date:message-id:sender:from:to
         :cc:subject:date:message-id:reply-to;
        bh=sZ4Iw32US5vlom988oj2KbYhQCW9iYeZmrXAvKkk9cg=;
        b=FMzEBnrMxuKItOb8oKfYl0o/D92X52H8T18qWsO+p4+Y1b86uxb2qmQPzpvtU3V+qJ
         RRMzAxzuZiQr9tGazqKTKtSCZShwFyMIOpdx0VLh6bVBnG7G0FBhIVYzugiQA1zyYf7N
         hFCg4tBgnKPW6mqsoFW0GvowfE4JWdxbTld8cPraOyczHVUjJsdkQnJzlfWCovPcZniT
         uW37VKtymc0gPuC3vwiRjc9KqWrXFBgfH/PdSLme5IcpC79HLxfjzfVxTlUqV5ZS7mfr
         whkhMZ2iz/yPkOhM5/PQp92fzJbObi0fmKnDCw9dH5BmDUQHJu9roFrUfxlp+WaXsCoJ
         M6Sw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1740580502; x=1741185302;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-language:from:references:cc:to:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=sZ4Iw32US5vlom988oj2KbYhQCW9iYeZmrXAvKkk9cg=;
        b=mDCaL0f/40Q6Qr/LOOkQ9+IBQ0c+Gpfk8zaBDlGzoiWh7kQeJB6MO/PmTAFLyXKuvA
         gEdCsEJDFTpltSZacbJoTGBRrhWvCK1La2J35r0EVUmjUXcD1PHZnWxO4ulBVTE06//A
         Zez1+M16+jrxTQzBTvOU4z7PfyklQWxOH0oRD9kVhOaS7rIqBHZwnm6WehUALY9py/RD
         2i9nPc5f8DnUFR5+2GGY70HQD0BPLbVy4P2UVX0hNc4Jg/Hz10BxWMwazrDPyWleMLBs
         Xxce+kkx0eajvmqZ7sSXolFHpT73fBa453fz8BunDToZN1T7nOG8n/NIRevYaiM3SHCA
         BwTg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVyjlzSs6Lg3AXmHCziHrR/XZG78Uxgl94XJVEF22MpE5QKKuDnnBv1I3jrbRjTjzq33Elzyg==@lfdr.de
X-Gm-Message-State: AOJu0Yxano5ZKQXIJ1Lq24H7DQKZrokj+uEazc2J8Vf8RF/Yt1olz9jt
	SVSOvxd9NEDL6dOOwsctIWq5JyKbBhoW0n1kiVLVmCWdrFOFdr4k
X-Google-Smtp-Source: AGHT+IFNjbkpreSyxVuwB1yaUpXS1aiOcvcTdM3FEs0bHiEs2CppD93Nvd1f/mPtH1iPKaQmVQSGBQ==
X-Received: by 2002:a5d:648f:0:b0:38f:2413:2622 with SMTP id ffacd0b85a97d-390d4fa354emr2650818f8f.47.1740580499643;
        Wed, 26 Feb 2025 06:34:59 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h=Adn5yVFaF7BmlN2BbUugYwmp8O3laqUdIUgVXwPyh9mhzz1JRg==
Received: by 2002:a5d:64af:0:b0:38f:2133:2c23 with SMTP id ffacd0b85a97d-390d4f509b2ls562967f8f.0.-pod-prod-09-eu;
 Wed, 26 Feb 2025 06:34:57 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVyeq4ZgBUZDqB6Qh1BGm1zXDoPFfwmnaLb0UdMLz0gwhC+3KVL+WB1PkjmUqjh6fHktvt2pxUSEWM=@googlegroups.com
X-Received: by 2002:a5d:5888:0:b0:390:d7e5:e8b2 with SMTP id ffacd0b85a97d-390d7e5e9a0mr1959521f8f.17.1740580497076;
        Wed, 26 Feb 2025 06:34:57 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1740580497; cv=none;
        d=google.com; s=arc-20240605;
        b=Cpowhx8JzCy3R7VG5Dfh1k2m01h1jZsS65OIQyDXHI2uHdQIyPf8Du/panYte0U1YQ
         3RjsQUcbeOsl7WTcTCv36TUUhjlbvgCQ/a917uXLD4oxeAUSUpz6EArKcJ0iJ7hRcaM9
         UUNvi1KMo7LiBf1w+VYoQSenzvHsLKzvINS7Aw7CgObEvtYvFWin3Yy68C9kZrr3sgu0
         MmNY29UGGHKw+rUTfb2MFq5JOjIonvx6B2yima81lGKSwuUeN9vwCnLZatekklBVGzH2
         GSyHhF8vBKkk72h0sdSG29h1RJW1/fzuuRTLy/5FyOiXaMFTRXOKzqyuBawJXpnmxmVy
         YAJA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:content-language:from
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature:dkim-signature:dkim-signature;
        bh=GqqQQsNA4ipMlgHM1b1lGDiKa6nAvwxuipFO3NvD51M=;
        fh=TPoXuV27OLbOhYz7xCVjlReilBuLfp/WWh5zLcJHusM=;
        b=ba3++/l49zC4JqAMoGsyDjeAjfEFZu7iB54I+eIJ6S3v10u7gePh6ZFr3rAv88a2nh
         73ng4XlF1OcxX9Bi3aoRx4B6WXAjcDqLozSRJiOpZZZw7a7gdbg3h0AEdZfyrHX5evaj
         8i5phVSJnAKHH/YZ21avTO0SF6kRb/HApnmMK1EnxRhZdu5gU7zDmb9+U67V3SFz3EFt
         a0lUcz0JJ4cPt5waZIYE8iajfCUChBPL3Qehp1FQks8ajAnWtdEyjJSt4Wd5rXHsc5DX
         JR/tt0YlE3Gb5x4b8CE+iymLsyeWaM9RuRIBbr2SsMMGB0BZ6hHFN1iLdmGMsQKgm5w6
         P0cg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=SnEImesK;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=rncUprZj;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=SnEImesK;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=rncUprZj;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [195.135.223.131])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-43ab374a2adsi2552175e9.1.2025.02.26.06.34.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 26 Feb 2025 06:34:57 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted sender) client-ip=195.135.223.131;
Received: from imap1.dmz-prg2.suse.org (imap1.dmz-prg2.suse.org [IPv6:2a07:de40:b281:104:10:150:64:97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id 4E9241F388;
	Wed, 26 Feb 2025 14:34:56 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id 2B29E1377F;
	Wed, 26 Feb 2025 14:34:56 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id elz1CZAmv2fWRgAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Wed, 26 Feb 2025 14:34:56 +0000
Message-ID: <93f03922-3d3a-4204-89c1-90ea4e1fc217@suse.cz>
Date: Wed, 26 Feb 2025 15:36:39 +0100
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v2 6/7] mm, slab: call kvfree_rcu_barrier() from
 kmem_cache_destroy()
To: Uladzislau Rezki <urezki@gmail.com>
Cc: Keith Busch <keith.busch@gmail.com>, "Paul E. McKenney"
 <paulmck@kernel.org>, Joel Fernandes <joel@joelfernandes.org>,
 Josh Triplett <josh@joshtriplett.org>, Boqun Feng <boqun.feng@gmail.com>,
 Christoph Lameter <cl@linux.com>, David Rientjes <rientjes@google.com>,
 Steven Rostedt <rostedt@goodmis.org>,
 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>,
 Lai Jiangshan <jiangshanlai@gmail.com>, Zqiang <qiang.zhang1211@gmail.com>,
 Julia Lawall <Julia.Lawall@inria.fr>, Jakub Kicinski <kuba@kernel.org>,
 "Jason A. Donenfeld" <Jason@zx2c4.com>,
 Andrew Morton <akpm@linux-foundation.org>,
 Roman Gushchin <roman.gushchin@linux.dev>,
 Hyeonggon Yoo <42.hyeyoo@gmail.com>, linux-mm@kvack.org,
 linux-kernel@vger.kernel.org, rcu@vger.kernel.org,
 Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>,
 Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com,
 Jann Horn <jannh@google.com>, Mateusz Guzik <mjguzik@gmail.com>,
 linux-nvme@lists.infradead.org, leitao@debian.org
References: <20240807-b4-slab-kfree_rcu-destroy-v2-6-ea79102f428c@suse.cz>
 <Z7iqJtCjHKfo8Kho@kbusch-mbp> <2811463a-751f-4443-9125-02628dc315d9@suse.cz>
 <Z7xbrnP8kTQKYO6T@pc636> <ef97428b-f6e7-481e-b47e-375cc76653ad@suse.cz>
 <Z73p2lRwKagaoUnP@kbusch-mbp>
 <CAOSXXT6-oWjKPV1hzXa5Ra4SPQg0L_FvxCPM0Sh0Yk6X90h0Sw@mail.gmail.com>
 <Z74Av6tlSOqcfb-q@pc636> <Z74KHyGGMzkhx5f-@pc636>
 <8d7aabb2-2836-4c09-9fc7-8bde271e7f23@suse.cz> <Z78lpfLFvNxjoTNf@pc636>
From: Vlastimil Babka <vbabka@suse.cz>
Content-Language: en-US
In-Reply-To: <Z78lpfLFvNxjoTNf@pc636>
Content-Type: text/plain; charset="UTF-8"
X-Rspamd-Queue-Id: 4E9241F388
X-Spam-Level: 
X-Spamd-Result: default: False [-3.01 / 50.00];
	BAYES_HAM(-3.00)[100.00%];
	SUSPICIOUS_RECIPS(1.50)[];
	NEURAL_HAM_LONG(-1.00)[-1.000];
	R_DKIM_ALLOW(-0.20)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	NEURAL_HAM_SHORT(-0.20)[-1.000];
	MIME_GOOD(-0.10)[text/plain];
	MX_GOOD(-0.01)[];
	TO_MATCH_ENVRCPT_ALL(0.00)[];
	DKIM_SIGNED(0.00)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	FUZZY_BLOCKED(0.00)[rspamd.com];
	FREEMAIL_TO(0.00)[gmail.com];
	ARC_NA(0.00)[];
	RCPT_COUNT_TWELVE(0.00)[29];
	RBL_SPAMHAUS_BLOCKED_OPENRESOLVER(0.00)[2a07:de40:b281:104:10:150:64:97:from];
	MIME_TRACE(0.00)[0:+];
	SPAMHAUS_XBL(0.00)[2a07:de40:b281:104:10:150:64:97:from];
	FREEMAIL_ENVRCPT(0.00)[gmail.com];
	FREEMAIL_CC(0.00)[gmail.com,kernel.org,joelfernandes.org,joshtriplett.org,linux.com,google.com,goodmis.org,efficios.com,inria.fr,zx2c4.com,linux-foundation.org,linux.dev,kvack.org,vger.kernel.org,googlegroups.com,lists.infradead.org,debian.org];
	RCVD_TLS_ALL(0.00)[];
	RCVD_COUNT_TWO(0.00)[2];
	MID_RHS_MATCH_FROM(0.00)[];
	FROM_EQ_ENVFROM(0.00)[];
	FROM_HAS_DN(0.00)[];
	TO_DN_SOME(0.00)[];
	RECEIVED_SPAMHAUS_BLOCKED_OPENRESOLVER(0.00)[2a07:de40:b281:106:10:150:64:167:received];
	RCVD_VIA_SMTP_AUTH(0.00)[];
	TAGGED_RCPT(0.00)[];
	DKIM_TRACE(0.00)[suse.cz:+];
	R_RATELIMIT(0.00)[to_ip_from(RLctujmen6hjyrx8fu4drawbuj)];
	DBL_BLOCKED_OPENRESOLVER(0.00)[suse.cz:dkim,suse.cz:mid]
X-Rspamd-Server: rspamd2.dmz-prg2.suse.org
X-Rspamd-Action: no action
X-Spam-Score: -3.01
X-Spam-Flag: NO
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=SnEImesK;       dkim=neutral
 (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=rncUprZj;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=SnEImesK;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519
 header.b=rncUprZj;       spf=pass (google.com: domain of vbabka@suse.cz
 designates 195.135.223.131 as permitted sender) smtp.mailfrom=vbabka@suse.cz
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

On 2/26/25 3:31 PM, Uladzislau Rezki wrote:
> On Wed, Feb 26, 2025 at 11:59:53AM +0100, Vlastimil Babka wrote:
>> On 2/25/25 7:21 PM, Uladzislau Rezki wrote:
>>>>
>>> WQ_MEM_RECLAIM-patch fixes this for me:
>>
>> Sounds good, can you send a formal patch then?
>>
> Do you mean both? Test case and fix? I can :)

Sure, but only the fix is for stable. Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/93f03922-3d3a-4204-89c1-90ea4e1fc217%40suse.cz.
