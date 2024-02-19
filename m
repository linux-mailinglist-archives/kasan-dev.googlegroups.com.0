Return-Path: <kasan-dev+bncBDXYDPH3S4OBBM5ZZSXAMGQEERISTFQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53e.google.com (mail-ed1-x53e.google.com [IPv6:2a00:1450:4864:20::53e])
	by mail.lfdr.de (Postfix) with ESMTPS id 4F30B859F6E
	for <lists+kasan-dev@lfdr.de>; Mon, 19 Feb 2024 10:17:40 +0100 (CET)
Received: by mail-ed1-x53e.google.com with SMTP id 4fb4d7f45d1cf-5644504261dsf1130976a12.1
        for <lists+kasan-dev@lfdr.de>; Mon, 19 Feb 2024 01:17:40 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1708334260; cv=pass;
        d=google.com; s=arc-20160816;
        b=xXgjxijbFoudHh/Lxxbivzdd8f6y8l/c9AEKHChHzLdjfLFcHtC56Z6JnnIZPyMOia
         kjRc2MDjpQP2uMDbfkCPF7h13WCGMBmHsMLZXgGNSeDU3J9ep2mUmY8ZLbzjZrg0nmMJ
         MQj23+3LkpO5l+FhAwJwrEmMAsmDjCHE1HCuVjC/Gq0hYKkWWzNGDAY/Ang7DSufFyap
         zznvYkj6uq+q+kUiyjrVpPg168o2DmJER/OEWrvHLaZN3OByDYdQ07Fq/UUFO5D7J4VF
         4XT1iMpac2gCRPali0Y6zybrpqbHLhio0PY3WoiV6LkMkoTNiSVwz/X3uCsE9EWe+jkn
         MzqA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :in-reply-to:from:references:cc:to:content-language:subject
         :user-agent:mime-version:date:message-id:sender:dkim-signature;
        bh=vzxIcyV5C9Ofk6kb0Z5v/2pbCpLZsSaRqkgQfiuQUzE=;
        fh=c+JOwaACzhW/wn6vj9WH88XfDJROQpYVrN03gNirOyQ=;
        b=BM7+247GoQFXqjrI30/7ha+GBqMSB2792H6AOeKiI/Fjyl87ki1yphpDkY0D7Ex7q7
         uVuvV8w8Qnruv6PdjM1GqsfedpVcjEEbBuB4B9z2tGvCemAMxXQGq+pIAfSGefqegIWN
         V1UiXN6ORNBwqnM9Hf2psJm4sU2YlWz+xN4Kt7QDWijbUaOO3QKLDKHoCibb0KEE+1TL
         aGJZrU56WTHS4M4YmZE8+GUwO/icVd9kgd1WviO4DQLV7MYcHkq/wPZJmRRUMMtv2ubR
         1XvSGBF2gplgKHhl2S6Ll0tmO1H36w3kzBZYUrNWq4yHkDHYie+3GK6VXLMPFzT37GYo
         ob/A==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b="MWMh6DJ/";
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=nhZfcUQl;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1708334260; x=1708939060; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:in-reply-to:from
         :references:cc:to:content-language:subject:user-agent:mime-version
         :date:message-id:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=vzxIcyV5C9Ofk6kb0Z5v/2pbCpLZsSaRqkgQfiuQUzE=;
        b=bk+BkuxBU703WYW/8qJzoa+D+EuenT1/32ysEX4E2X2BzHfxk4sR4u+HtX1EG6o2w3
         0jJyGOEStmrQdQc6BPs8fwO2ah/Luug93M4GDhfz+2XvgAQW9IGIMl2ymqkeuM7LzyYc
         HJK34muD1o0yhEp+xtB4LmeUILKs26nNKhRfz4ITHW+G1KiSwaeRJEvsrx7qqxpTMJyi
         9bIymcu3met96TUVbrePNvdQDyklW4D1p71QuYXzwXP2CKZkZ4yW/0WHNqM5rh20X1ud
         3N1OHrtyJhrJWnvpfKCwS51L9RYDkFOGPNd6QjmE6+jAAI3OnjKjbcpHoWSgn4aARJIi
         c2bw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1708334260; x=1708939060;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=vzxIcyV5C9Ofk6kb0Z5v/2pbCpLZsSaRqkgQfiuQUzE=;
        b=ELmZddIrMN/cxXdrlOtLSjt4MqwC6s76VdaeE2Ei0/T2XS7FYKzxcbF/2qb29bMgNy
         qwxuCi+lXizDCFGrN9PqU651DSRLMSb239CAz1Y1JOyS2uklD1NWC2vrPWH4Wkg2tQsP
         RIK1K5iHhTQvuEysvmoGWfpCLORLV1Xp5DJIo4oblbwDu1PCqey97pRtusNKY0e6Vtei
         YpUc2UqFvj6TjAc+G06k55vbH74nA9iRrEdvRSmt3UH5n7jVE7e3eitfiG0d1Q/MzzL/
         xr/ABSb+S6mNoB0cu2M+DQMJk9pUuSdE3PCqbs3E8Tpz8T4547cDRNgwKZumt/I5+xHY
         ikAg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXg1bcAQ7VfGXslrtLV+ps0DmffxYt45llvvSTNVXEgI6nvIiJ4Udp04F2NkWLdymZtLat54na0mXePox3gqSB7LyIUuqVcOg==
X-Gm-Message-State: AOJu0YzsYOpfy29td3pF4NDiHdLs90OW1xV+r57nQrFHS0a55VyGfo/Y
	BAaPg+wtqUyY4UABl0Y8QysEkq0fT1LFwqXgacnXcLbamJCH1GZPelM=
X-Google-Smtp-Source: AGHT+IE4xM58X3yMIBfHk0ycATEm4frX5kJQCtGEObzzDSRZ6MmA1Z0o7mTIU+/Z//sQpqMLQSvAjA==
X-Received: by 2002:a05:6402:1513:b0:561:33dd:621c with SMTP id f19-20020a056402151300b0056133dd621cmr10007296edw.7.1708334259258;
        Mon, 19 Feb 2024 01:17:39 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:3811:b0:563:c18b:4d80 with SMTP id
 es17-20020a056402381100b00563c18b4d80ls1070347edb.1.-pod-prod-00-eu; Mon, 19
 Feb 2024 01:17:37 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUowzDDjQHWigtly9D9O0M9D4UCJi+OMFU/6LaNCZCSSpnDcA4Wdo1Co5nPQyv5nofgqxCi9BKd4Z4CdCWCJF5+XRtEJV6f47uZQA==
X-Received: by 2002:a17:906:2315:b0:a3e:ce5a:ba62 with SMTP id l21-20020a170906231500b00a3ece5aba62mr351436eja.20.1708334257184;
        Mon, 19 Feb 2024 01:17:37 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1708334257; cv=none;
        d=google.com; s=arc-20160816;
        b=KT+UM3AFsuaJR9qtFDADCi6MBCYK0+ormNH160AsfGqSwdmQt4KUB2EQmjgkA7/RkN
         QQuLqaI/1gL4QUGb1h2SV0mfjvH5C4cBzmA6CQru5Lp5lxnlEUxVc7ApmY5ok+8bRo7U
         Pu0iuYbSwiYkO3LpUAVAZc/F3Y7tvYDJjfaJJYA6tkHzRd0AIHLj2WcBYPBG1Pc12hiM
         j5fCj98ngZVrz5guosHANEHnAESojctSWnCrwccbIoBfpPsv+CTG+gOc3wR4acp3AbJm
         6JCfoXyjUoFA4BZE/8QUKnI4ZnkdS10OlcFE+1X8XauBIDzKDiV7X+U+FVLFAPTZ/PmP
         yMNw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature:dkim-signature:dkim-signature;
        bh=vIC/a+gVDD7XPQtjCAkXOILzScqhk7P47GEkxD0UDQs=;
        fh=QztK4rQjHxCoQ80zMX5dYtPlMkQnkPEOOOAOxPi7Gts=;
        b=jqmGHWMCpZhtZf4agEe5N9tILbRj8ufuig8G5dg4WAY1tze4lGPF/8IW1OTu5u4qvI
         +0RPMcwoQUUZVc7me/TX1dhp73L+cG8jX179J6Ene7Ep6meWBiiWnnvKwUH6VQ7qF21M
         xfKfIIIiLWS1LsjMTmV7xVVEmOng0bga09ZkAp0fjxbg2579UzsLP53tuh3jVUdtplJa
         qQsFj6gfZhcsOfunt342l02wVlQLMMtC/p8q1s5PUnK2hXlRUaAOvbXGyPf174FLKHtd
         0ufy7TTFOQectQqIUdmKCWd6g257QErTAm+weUe1CV4fMaYyI6tx1C76kO5eUicxdjR8
         10ag==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b="MWMh6DJ/";
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=nhZfcUQl;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [2a07:de40:b251:101:10:150:64:2])
        by gmr-mx.google.com with ESMTPS id fx6-20020a170906b74600b00a3e643fea3fsi134848ejb.0.2024.02.19.01.17.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 19 Feb 2024 01:17:37 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) client-ip=2a07:de40:b251:101:10:150:64:2;
Received: from imap1.dmz-prg2.suse.org (imap1.dmz-prg2.suse.org [IPv6:2a07:de40:b281:104:10:150:64:97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id A57101F7E6;
	Mon, 19 Feb 2024 09:17:34 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id 18E5713647;
	Mon, 19 Feb 2024 09:17:34 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id gyquBa4c02VrEgAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Mon, 19 Feb 2024 09:17:34 +0000
Message-ID: <5bd3761f-217d-45bb-bcd2-797f82c8a44f@suse.cz>
Date: Mon, 19 Feb 2024 10:17:33 +0100
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v3 32/35] codetag: debug: skip objext checking when it's
 for objext itself
Content-Language: en-US
To: Suren Baghdasaryan <surenb@google.com>
Cc: akpm@linux-foundation.org, kent.overstreet@linux.dev, mhocko@suse.com,
 hannes@cmpxchg.org, roman.gushchin@linux.dev, mgorman@suse.de,
 dave@stgolabs.net, willy@infradead.org, liam.howlett@oracle.com,
 corbet@lwn.net, void@manifault.com, peterz@infradead.org,
 juri.lelli@redhat.com, catalin.marinas@arm.com, will@kernel.org,
 arnd@arndb.de, tglx@linutronix.de, mingo@redhat.com,
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
 cgroups@vger.kernel.org
References: <20240212213922.783301-1-surenb@google.com>
 <20240212213922.783301-33-surenb@google.com>
 <f0a56027-472d-44a6-aba5-912bd50ee3ae@suse.cz>
 <CAJuCfpGUTu7uhcR-23=0d3Wnn8ZbDtNwTaFnukd9qYYVHS9aSA@mail.gmail.com>
From: Vlastimil Babka <vbabka@suse.cz>
In-Reply-To: <CAJuCfpGUTu7uhcR-23=0d3Wnn8ZbDtNwTaFnukd9qYYVHS9aSA@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Spam-Level: 
X-Spamd-Bar: /
X-Rspamd-Server: rspamd2.dmz-prg2.suse.org
X-Spamd-Result: default: False [0.00 / 50.00];
	 RCVD_VIA_SMTP_AUTH(0.00)[];
	 XM_UA_NO_VERSION(0.01)[];
	 SPAMHAUS_XBL(0.00)[2a07:de40:b281:104:10:150:64:97:from];
	 TO_DN_SOME(0.00)[];
	 R_RATELIMIT(0.00)[to_ip_from(RLcb476ir6xfzaroaj5pc7azzw)];
	 RCVD_COUNT_THREE(0.00)[3];
	 DKIM_TRACE(0.00)[suse.cz:+];
	 MX_GOOD(-0.01)[];
	 RCPT_COUNT_GT_50(0.00)[73];
	 NEURAL_HAM_SHORT(-0.20)[-1.000];
	 FROM_EQ_ENVFROM(0.00)[];
	 MIME_TRACE(0.00)[0:+];
	 MID_RHS_MATCH_FROM(0.00)[];
	 ARC_NA(0.00)[];
	 R_DKIM_ALLOW(-0.20)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	 FROM_HAS_DN(0.00)[];
	 FREEMAIL_ENVRCPT(0.00)[gmail.com];
	 NEURAL_HAM_LONG(-1.00)[-1.000];
	 TAGGED_RCPT(0.00)[];
	 MIME_GOOD(-0.10)[text/plain];
	 TO_MATCH_ENVRCPT_SOME(0.00)[];
	 DKIM_SIGNED(0.00)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	 FUZZY_BLOCKED(0.00)[rspamd.com];
	 FREEMAIL_CC(0.00)[linux-foundation.org,linux.dev,suse.com,cmpxchg.org,suse.de,stgolabs.net,infradead.org,oracle.com,lwn.net,manifault.com,redhat.com,arm.com,kernel.org,arndb.de,linutronix.de,linux.intel.com,kernel.dk,soleen.com,google.com,gmail.com,chromium.org,linuxfoundation.org,linaro.org,goodmis.org,linux.com,lge.com,bytedance.com,akamai.com,android.com,vger.kernel.org,lists.linux.dev,kvack.org,googlegroups.com];
	 RCVD_TLS_ALL(0.00)[];
	 SUSPICIOUS_RECIPS(1.50)[]
X-Spam-Score: 0.00
X-Rspamd-Queue-Id: A57101F7E6
X-Spam-Flag: NO
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b="MWMh6DJ/";
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=nhZfcUQl;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates
 2a07:de40:b251:101:10:150:64:2 as permitted sender) smtp.mailfrom=vbabka@suse.cz
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

On 2/19/24 02:04, Suren Baghdasaryan wrote:
> On Fri, Feb 16, 2024 at 6:39=E2=80=AFPM Vlastimil Babka <vbabka@suse.cz> =
wrote:
>>
>> On 2/12/24 22:39, Suren Baghdasaryan wrote:
>> > objext objects are created with __GFP_NO_OBJ_EXT flag and therefore ha=
ve
>> > no corresponding objext themselves (otherwise we would get an infinite
>> > recursion). When freeing these objects their codetag will be empty and
>> > when CONFIG_MEM_ALLOC_PROFILING_DEBUG is enabled this will lead to fal=
se
>> > warnings. Introduce CODETAG_EMPTY special codetag value to mark
>> > allocations which intentionally lack codetag to avoid these warnings.
>> > Set objext codetags to CODETAG_EMPTY before freeing to indicate that
>> > the codetag is expected to be empty.
>> >
>> > Signed-off-by: Suren Baghdasaryan <surenb@google.com>
>> > ---
>> >  include/linux/alloc_tag.h | 26 ++++++++++++++++++++++++++
>> >  mm/slab.h                 | 25 +++++++++++++++++++++++++
>> >  mm/slab_common.c          |  1 +
>> >  mm/slub.c                 |  8 ++++++++
>> >  4 files changed, 60 insertions(+)
>> >
>> > diff --git a/include/linux/alloc_tag.h b/include/linux/alloc_tag.h
>> > index 0a5973c4ad77..1f3207097b03 100644
>>
>> ...
>>
>> > index c4bd0d5348cb..cf332a839bf4 100644
>> > --- a/mm/slab.h
>> > +++ b/mm/slab.h
>> > @@ -567,6 +567,31 @@ static inline struct slabobj_ext *slab_obj_exts(s=
truct slab *slab)
>> >  int alloc_slab_obj_exts(struct slab *slab, struct kmem_cache *s,
>> >                       gfp_t gfp, bool new_slab);
>> >
>> > +
>> > +#ifdef CONFIG_MEM_ALLOC_PROFILING_DEBUG
>> > +
>> > +static inline void mark_objexts_empty(struct slabobj_ext *obj_exts)
>> > +{
>> > +     struct slabobj_ext *slab_exts;
>> > +     struct slab *obj_exts_slab;
>> > +
>> > +     obj_exts_slab =3D virt_to_slab(obj_exts);
>> > +     slab_exts =3D slab_obj_exts(obj_exts_slab);
>> > +     if (slab_exts) {
>> > +             unsigned int offs =3D obj_to_index(obj_exts_slab->slab_c=
ache,
>> > +                                              obj_exts_slab, obj_exts=
);
>> > +             /* codetag should be NULL */
>> > +             WARN_ON(slab_exts[offs].ref.ct);
>> > +             set_codetag_empty(&slab_exts[offs].ref);
>> > +     }
>> > +}
>> > +
>> > +#else /* CONFIG_MEM_ALLOC_PROFILING_DEBUG */
>> > +
>> > +static inline void mark_objexts_empty(struct slabobj_ext *obj_exts) {=
}
>> > +
>> > +#endif /* CONFIG_MEM_ALLOC_PROFILING_DEBUG */
>> > +
>>
>> I assume with alloc_slab_obj_exts() moved to slub.c, mark_objexts_empty(=
)
>> could move there too.
>=20
> No, I think mark_objexts_empty() belongs here. This patch introduced
> the function and uses it. Makes sense to me to keep it all together.

Hi,

here I didn't mean moving between patches, but files. alloc_slab_obj_exts()
in slub.c means all callers of mark_objexts_empty() are in slub.c so it
doesn't need to be in slab.h

Also same thing with mark_failed_objexts_alloc() and
handle_failed_objexts_alloc() in patch 34/35.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/5bd3761f-217d-45bb-bcd2-797f82c8a44f%40suse.cz.
