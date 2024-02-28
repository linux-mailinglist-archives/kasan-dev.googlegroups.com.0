Return-Path: <kasan-dev+bncBDXYDPH3S4OBBOPW7WXAMGQEJBEAS4I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33d.google.com (mail-wm1-x33d.google.com [IPv6:2a00:1450:4864:20::33d])
	by mail.lfdr.de (Postfix) with ESMTPS id 8004986B723
	for <lists+kasan-dev@lfdr.de>; Wed, 28 Feb 2024 19:28:10 +0100 (CET)
Received: by mail-wm1-x33d.google.com with SMTP id 5b1f17b1804b1-4129026ca58sf76995e9.0
        for <lists+kasan-dev@lfdr.de>; Wed, 28 Feb 2024 10:28:10 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1709144890; cv=pass;
        d=google.com; s=arc-20160816;
        b=VLEKRTGejGY19F7K+hMWWUpXOPnSjvZBP/0zno6Udb1tzr7NiTE1jAoOPqqMJgBiTK
         7LOoLDdUovFBjcVhR88SNRHTMUBxB0zMPRTUwpXBIR0lgz6H+7U2CsMJS1Wf0iUhWq7I
         LOjqZHz9PE0ddXyi4rfGZ8Pi9pvVTn6Hpv+kuklslXq0ttm4BtUium+73Qy+F9llYw1A
         KH8gDH1F71NSZ391JwvGqelnOib22LBQjOEOrqAH7DwQu97X8ussjTnmBuho/kr4PJnQ
         NZ8MMYKnpRLsOoxQJq+kQ2PEi1PuoSmPLLDoLnJVLI/h0oqQ9KWbI5GKtGcIq/v5/xQs
         G8Ag==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :in-reply-to:from:references:cc:to:content-language:subject
         :user-agent:mime-version:date:message-id:sender:dkim-signature;
        bh=qx/J3WHYpQ1AOfN4tQe8Rwem4OFCvS+eSs5l0EJIxs8=;
        fh=l/PPp8mM6dlEwV2XWDbG5VbHTK2uG2RRYFkNtJIXp/A=;
        b=gVury/cvk50gohRM/cvfcQh1kVhm9k14ZqNfE+Twks3m4JN5/GABeVH68KGh5hzG0S
         t2U8052R4koJqm+9OLRVT9Xs0yYJm9DvjIzBeC97dzdHQVb0IEiHBOQ9OHT2BYhnwDcu
         OZQWoztv0BL7HD/Ol2iccfp80zb9kPzD9yrw0wHk6uwzNdu5fIyYe5uu5svPg07Zp/d2
         nBr2v3Pjp42+R5XN3T63sYDFsMuu4oqQ7EIbaQFSDbbUnkpiSR5kzcw+PbBmha15MF2W
         GLBk+hz4lnVLcxp3K9Kf3nViw53G3TgGqJWvefx1H5IAOA7z7ym3gfobu4FXlKP9JqI2
         Kuhw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=ZPxRODIg;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=lzwTXBmR;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1709144890; x=1709749690; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:in-reply-to:from
         :references:cc:to:content-language:subject:user-agent:mime-version
         :date:message-id:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=qx/J3WHYpQ1AOfN4tQe8Rwem4OFCvS+eSs5l0EJIxs8=;
        b=LOKkWFEJNpP9JqYYLr49n3gxC+UjvCYSWBEwh1dNAPF7VAbnClPrKMLyFrbLGlA+EE
         z8dBqYymeriX2HhaOvaWVPLh+oHAiozJDOE7lG2CB9uWukraxKpZXxQqYDsG039xmrpZ
         76E+4kQwOImXyYbrL3BdnvSgHCbMDmXrCMjhY4/mcBDAr+wJleI8wjFuvsHxWgFr4AQB
         Ls2i4PoFvWseeZErZPkR6/kF91AVKkzcyG881vd7q6sStWv4gdVfIGv5AOY4KivMMl6N
         wgpQYXARekNPYzgo1GpEGiyusCuanm+6T9MAgp5J6RZYE4ETxQyAnWrAQjd4MHQThFll
         3RCQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1709144890; x=1709749690;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=qx/J3WHYpQ1AOfN4tQe8Rwem4OFCvS+eSs5l0EJIxs8=;
        b=UWgUVLto6PH3PFnw7yYgE7zSrzP4DqxdViUVt7UqE9/+9sNdW8g7LoPbRmmDGUvjb5
         y/1d4ACjL/mq1x8utKKWJz/P6JPcqQT1TY2I4cgwb3bHjDYYKaIs5eKDcnvP77GGFSHr
         9m7lnolfK2hucL6K/y849oMB2V2qbA6UzD3zNAF/FTyYzDJTNdDNKoLeoQkG2euQfKZM
         5GYRw5QcEjxuDg2DRT4fsi/P3K249vf+2GwCZ/v1XGvrINyzSzEkEOdBsz2dTg/fh7+P
         C44WACT2+T1tkFyAs8xgiCCkZjudQOKXEGSpusIDGVwyRPvm17zIb7uBG3ZLel3aawmT
         VFMg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXdSSTkmz4I8+rpld3bTYvbWyNwnSmSXV4i+LANbzkXRp3TSstJtBHq17xZn6oq4YRnK5DsTB3eaZRrNnWjvLIOvTY8uvC2AQ==
X-Gm-Message-State: AOJu0YykZCksIT+W7k3c6UDm74bBI4F80FFCeFd/6MRXbztAwmce8K0N
	yP82Y2pJzVyGy6DR3XQH1L8BsZ7cAyLR+MGxa6mRg8WZQLRvxOjU
X-Google-Smtp-Source: AGHT+IGn26SQLPhnT9eYxY0c2/DL+9HYbgCv8zHUrNj2cg8bl72SQtf9F2mOVJ+76iW3bvtvdX5V/Q==
X-Received: by 2002:a05:600c:a386:b0:412:aa80:bdd9 with SMTP id hn6-20020a05600ca38600b00412aa80bdd9mr103266wmb.2.1709144889706;
        Wed, 28 Feb 2024 10:28:09 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:b4a6:0:b0:2d2:99e8:bbb8 with SMTP id q6-20020a2eb4a6000000b002d299e8bbb8ls19607ljm.1.-pod-prod-01-eu;
 Wed, 28 Feb 2024 10:28:08 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUkZFhE+E1YFJrWusl7mcz/rupBF1bOekaT96jq+KLyC9vwIp7KwOrkYnlsAZpH+dAv0+RCqJGCg3kicMM/ddMGxm8xlRKr6c+THQ==
X-Received: by 2002:ac2:4426:0:b0:513:b6:df57 with SMTP id w6-20020ac24426000000b0051300b6df57mr348232lfl.6.1709144887598;
        Wed, 28 Feb 2024 10:28:07 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1709144887; cv=none;
        d=google.com; s=arc-20160816;
        b=Vmqh95irm8PhSCtzqsiYY2wM/sBBmT4gCIZLcC9Hz5gfbjDzG3Kzze5bCXL5j1dVLK
         htGQ09EUaAQ1feiiX5pXdGo8HyuVymTg6j6qp4cns6NAlOzOgHkCBjBGDiFzghJrTJyc
         vDsvgYyneqjDHcT3GZXwZjM7jWhZJ/b/EWFJr8tZ0/7+GHKuVTGLRloxZ789fp8wLQEX
         rpUFwA5eVG0t3ojttEVE4OKGIylINEA+b5MN5MiOYluRTam8wxSwOOLQ3yUSwn0HT4oV
         WSW0kfZVBiD1OCJPAt0QvTrqzACQdtOzkeiY4AAVEtntihJs7qFQU7iN5n0G3+GyRPZr
         5MVA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature:dkim-signature:dkim-signature;
        bh=u5+mCXb2oxOlDfsxFtS236UJWrVmUWVW4KbIf8DfAn4=;
        fh=dOHsy3mSRCJvTZwWeFaoCuCHq/O8VVJOOHQkFc4Oa7s=;
        b=aEhFWDQIAHDbh2zcT1sTMePEgjtow8V3/I3xav94w/6KX1Xjt2cxncv9GV7Gz+DEt1
         h7TNs+Ckel2Jn0QEJuOhA8kaBkkqSBlY/ORnHcXSxCXw/BI+PPrC7iucBlv20RY1uRVo
         CVtsXNCGa2npUTat6XIaExmvXfyt/GrVPtoa54FLSbER6pkvLp4qxqfIRacxNh6NpR7B
         rf92GihfXTSRypZdshQdzxJU+log9nnV1yrh1rNuioltsBX8NiP6ZOLxElgPDulCt75u
         X0+OacthXL4y9uH8gZzVYi66WG/10pP4juoOCcXRbeZvpRg5aCRaOom58BP1fRAmgLR6
         2E+A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=ZPxRODIg;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=lzwTXBmR;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [2a07:de40:b251:101:10:150:64:1])
        by gmr-mx.google.com with ESMTPS id g17-20020a0565123b9100b00512f9756679si888lfv.6.2024.02.28.10.28.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 28 Feb 2024 10:28:07 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) client-ip=2a07:de40:b251:101:10:150:64:1;
Received: from imap1.dmz-prg2.suse.org (imap1.dmz-prg2.suse.org [IPv6:2a07:de40:b281:104:10:150:64:97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id 96C8E2259A;
	Wed, 28 Feb 2024 18:28:04 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id EFC7513A58;
	Wed, 28 Feb 2024 18:28:03 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id i+05OjN732V+LAAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Wed, 28 Feb 2024 18:28:03 +0000
Message-ID: <f494b8e5-f1ca-4b95-a8aa-01b9c4395523@suse.cz>
Date: Wed, 28 Feb 2024 19:28:03 +0100
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v4 19/36] mm: create new codetag references during page
 splitting
Content-Language: en-US
To: Suren Baghdasaryan <surenb@google.com>
Cc: akpm@linux-foundation.org, kent.overstreet@linux.dev, mhocko@suse.com,
 hannes@cmpxchg.org, roman.gushchin@linux.dev, mgorman@suse.de,
 dave@stgolabs.net, willy@infradead.org, liam.howlett@oracle.com,
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
 cgroups@vger.kernel.org
References: <20240221194052.927623-1-surenb@google.com>
 <20240221194052.927623-20-surenb@google.com>
 <2daf5f5a-401a-4ef7-8193-6dca4c064ea0@suse.cz>
 <CAJuCfpGt+zfFzfLSXEjeTo79gw2Be-UWBcJq=eL1qAnPf9PaiA@mail.gmail.com>
 <6db0f0c8-81cb-4d04-9560-ba73d63db4b8@suse.cz>
 <CAJuCfpEgh1OiYNE_uKG-BqW2x97sOL9+AaTX4Jct3=WHzAv+kg@mail.gmail.com>
From: Vlastimil Babka <vbabka@suse.cz>
In-Reply-To: <CAJuCfpEgh1OiYNE_uKG-BqW2x97sOL9+AaTX4Jct3=WHzAv+kg@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Spamd-Result: default: False [1.15 / 50.00];
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
	 BAYES_HAM(-0.05)[59.78%];
	 R_RATELIMIT(0.00)[to_ip_from(RLcb476ir6xfzaroaj5pc7azzw)];
	 RCVD_COUNT_THREE(0.00)[3];
	 DKIM_SIGNED(0.00)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	 DKIM_TRACE(0.00)[suse.cz:+];
	 TO_MATCH_ENVRCPT_SOME(0.00)[];
	 RCPT_COUNT_GT_50(0.00)[74];
	 MX_GOOD(-0.01)[];
	 DBL_BLOCKED_OPENRESOLVER(0.00)[suse.cz:dkim,suse.cz:email];
	 FUZZY_BLOCKED(0.00)[rspamd.com];
	 FROM_EQ_ENVFROM(0.00)[];
	 MIME_TRACE(0.00)[0:+];
	 FREEMAIL_CC(0.00)[linux-foundation.org,linux.dev,suse.com,cmpxchg.org,suse.de,stgolabs.net,infradead.org,oracle.com,i-love.sakura.ne.jp,lwn.net,manifault.com,redhat.com,arm.com,kernel.org,arndb.de,linutronix.de,linux.intel.com,kernel.dk,soleen.com,google.com,gmail.com,chromium.org,linuxfoundation.org,linaro.org,goodmis.org,linux.com,lge.com,bytedance.com,akamai.com,android.com,vger.kernel.org,lists.linux.dev,kvack.org,googlegroups.com];
	 RCVD_TLS_ALL(0.00)[];
	 SUSPICIOUS_RECIPS(1.50)[]
X-Rspamd-Server: rspamd1.dmz-prg2.suse.org
X-Spam-Score: 1.15
X-Rspamd-Queue-Id: 96C8E2259A
X-Spam-Level: *
X-Spam-Flag: NO
X-Spamd-Bar: +
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=ZPxRODIg;       dkim=neutral
 (no key) header.i=@suse.cz header.s=susede2_ed25519;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=lzwTXBmR;       dkim=neutral
 (no key) header.i=@suse.cz header.s=susede2_ed25519;       spf=pass
 (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1
 as permitted sender) smtp.mailfrom=vbabka@suse.cz
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

On 2/28/24 18:50, Suren Baghdasaryan wrote:
> On Wed, Feb 28, 2024 at 12:47=E2=80=AFAM Vlastimil Babka <vbabka@suse.cz>=
 wrote:
>=20
>>
>> Now this might be rare enough that it's not worth fixing if that would b=
e
>> too complicated, just FYI.
>=20
> Yeah. We can fix this by subtracting the "bytes" counter of the "head"
> page for all free_the_page(page + (1 << order), order) calls we do
> inside __free_pages(). But we can't simply use pgalloc_tag_sub()
> because the "calls" counter will get over-decremented (we allocated
> all of these pages with one call). I'll need to introduce a new
> pgalloc_tag_sub_bytes() API and use it here. I feel it's too targeted
> of a solution but OTOH this is a special situation, so maybe it's
> acceptable. WDYT?

Hmm I think there's a problem that once you fail put_page_testzero() and
detect you need to do this, the page might be already gone or reallocated s=
o
you can't get to the tag for decrementing bytes. You'd have to get it
upfront (I guess for "head && order > 0" cases) just in case it happens.
Maybe it's not worth the trouble for such a rare case.

>>
>>
>> > Every time
>> > one of these pages are freed that codetag's "bytes" and "calls"
>> > counters will be decremented. I think accounting will work correctly
>> > irrespective of where these pages are freed, in __free_pages() or by
>> > put_page().
>> >
>>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/f494b8e5-f1ca-4b95-a8aa-01b9c4395523%40suse.cz.
