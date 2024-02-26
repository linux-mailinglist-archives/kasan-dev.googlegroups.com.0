Return-Path: <kasan-dev+bncBDXYDPH3S4OBBTNL6GXAMGQEQFV4K3I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23a.google.com (mail-lj1-x23a.google.com [IPv6:2a00:1450:4864:20::23a])
	by mail.lfdr.de (Postfix) with ESMTPS id 3DFCC866DC4
	for <lists+kasan-dev@lfdr.de>; Mon, 26 Feb 2024 10:11:43 +0100 (CET)
Received: by mail-lj1-x23a.google.com with SMTP id 38308e7fff4ca-2d24324b7f1sf24564011fa.0
        for <lists+kasan-dev@lfdr.de>; Mon, 26 Feb 2024 01:11:43 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1708938702; cv=pass;
        d=google.com; s=arc-20160816;
        b=xVor9wP5vThRPedXmXhEncW1twnZ1P1zxvibHrS1HayrQAyRHlfBARn8eZM41GQI4T
         6mmBa4mJ45XMRQIiAhFIc+WWiZqZTd8EDd8VU+wpSySRmb+fP8PJNWVWP+U7oUaG+v84
         FC9zLpX0s0zKF/aFzIHu+4K07dgzh8vTbB5fCWAZA5ZQm+FaxA5lSDXtK9LzwZA3MT0D
         1o9C6nCfSj4Om78qAYhb2EqhoMp48exAzjsmCHeR/JdgwAYN0aVoHe9UsE8eVso8YXyc
         S6cdB669JkQCGK7Cyhl6CZufzZvKh/h4/6vPCR7Vhn1weW4u4AIAbQ7WCD7NRE+9mxol
         f3mw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=731bJF9Bm2uWsHfjpwaOjG4Z6hIOl/gkwR3KBmZDmlg=;
        fh=Ch4TUzQBJ67VhSy8PWdZFLAnjxq5AfYGcIGjnmPxixE=;
        b=t1iYGyLh97JaHcJ5nd54+1mFZBsKbC598d6qgJV50CML/U6yR9yEa/Nt+ssTYdS5Dx
         NL/rLYjTsktVr+Tv/0v3UPK9SKXS6wtDV0SqNfhj+M/s3lcFgY9PXoHvEsD0fV/n4wnF
         RgpqmL0P+uTuVEM9FlhC3Je3Lz9T3fMryNK8VCARuujQye+3Y4JfAWKrIoEOI+DR//Rd
         v/U+cA0xnCfvHFrlL8c1807051IbpeI1sMSgiyO6/fW1rALoPBG2jsyTZqD1hamz/MaM
         FOp3P98qvuwHcCnah2O2AHdCiDGjNvB5Sd6SwkonDtVrL5FnsXktNDjxe+51WlNQaGCb
         ixFQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b="k2/5MnNm";
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b="k2/5MnNm";
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1708938702; x=1709543502; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=731bJF9Bm2uWsHfjpwaOjG4Z6hIOl/gkwR3KBmZDmlg=;
        b=k0biXZJERC/QvTzHlUjot/h86s7d0ICyL/p+zaEUhqOaJhswa+G+pecr2StBBtbGWE
         hBIcX0BmDsL1XndypGdVwVi5oEI+IHD2RWawctCm0Q0k7LAer1QPrhcRa+DgRct4zCFy
         9FLd+RDGJW+UhlNhlbxLn4b1JYck3OoUMZ0qQjXCYR24i+94YB0+3wPUJzTW0GJuX0Ba
         vZLNmpdtfQ0AP3pX+AE9iTsgGlNtGKDyJUQs/4Yw0Em8j2hhppwVreCIT/QIbhK5i2cU
         BH5eiiKpmJx29c4HJLsvk7MAoL1XUK4+5gSHesTr21uj4xONpHehTRoUZwlKvJqGUjm6
         RVaw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1708938702; x=1709543502;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=731bJF9Bm2uWsHfjpwaOjG4Z6hIOl/gkwR3KBmZDmlg=;
        b=ZgpS2wKDCsR8G3o6cZ4R0wNPCSa1gLd0azeaaIApAq/mCzINXHQ77H5sQZz9lZgWqN
         Ig2OKv8hjaCqE/hQehQTaExfn1B6WfUhZw2/VRMHIGRwj7gbLS9o+ylH1v+hRuQunNMI
         krWeyBGULSojDdRviOYAnbaOpzb+VhEKYgXLRGamVI4a2/kiJQAn0fxmjvjzbsp0u+y1
         BtDhNiL/HGZnwboW3Ep/nRAfummZbDZS1QzsVt7FEJWeLro093Z9Js/J9t0AHECjfiks
         Hk1swAjiRAgLiYupYm1B0uwSXoq4TXpZpwBx7NRG87wOWjp68rZFFStmY6SVALr/7N+j
         U6Pg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWTuYsKxdyIHWat+D9bSlApdyVcmlbfTgpOEjsMeP4uZCYtkm1XthAuWog7pa1UOp0LsT/tp2vfc71JvdYQr+WvU6OFOEiaNw==
X-Gm-Message-State: AOJu0YyhDe5IbZuwe8BGgapTN22FmHF5OEMyE2lJxSYFXfTplnoGNHPI
	aj3YmpgrDDUsTNU+8QydmLtvWpEVMj9PMTDRToDGXPrLPhAQeueB
X-Google-Smtp-Source: AGHT+IEKUoaFYdMmXLxtp3Ha9yA37onMa3lnQdyHYice4+dHhjMRpB0lf4j1hbgSBth0KvlRxdkorg==
X-Received: by 2002:a2e:bc1b:0:b0:2d2:2948:afb with SMTP id b27-20020a2ebc1b000000b002d229480afbmr4537171ljf.24.1708938701341;
        Mon, 26 Feb 2024 01:11:41 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:2004:b0:2d2:509e:a90e with SMTP id
 s4-20020a05651c200400b002d2509ea90els1328225ljo.0.-pod-prod-02-eu; Mon, 26
 Feb 2024 01:11:39 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVnloL0nT/dCCyq6uVobICurwZJxxCw3zy3SLwtUXoGeH+HiNt943Zp8Ddfl2sf+5BCGswL6TuCc18BTgFf9J3IvmUJ4q/kGAqboA==
X-Received: by 2002:a05:6512:242:b0:512:b935:c542 with SMTP id b2-20020a056512024200b00512b935c542mr3864227lfo.59.1708938699376;
        Mon, 26 Feb 2024 01:11:39 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1708938699; cv=none;
        d=google.com; s=arc-20160816;
        b=BOIbQGd6iy51/Q9I8t7wcTIO5uRAILUYqqTW+6C3rmKk8DaJ9wtJUoVtZ33DHneB1O
         RZRlQnmUIXEqgSf9xyJLOEybkaJc3KLFOXKNlqIn1Hnn7qleEiscs5E0TsCnWynL0uLV
         dtgCJ1+Ss2xWhyuD6gENaE/hoArKb0F8pK49ueFu7pcK+JkOVjOsgf1gCP3GMBLzCDp5
         LQaM4m6ZEbIZgr3Mz7ZeIXJViawmbvI6NMjCkopileQTR92YFZKXoaOFgYt2ULZctXvT
         swvUPCNGge8AZyl8Pjf4gwg2aboJ/KRySSyTr/gWyNMHvJzhWuVTwDmdYnnAogYlP/uj
         6T2g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature:dkim-signature:dkim-signature;
        bh=89yAF6qEhgvcbbVCO+3NfAAxt3pVNwScA2PuWa4QdPY=;
        fh=jyw0yuciT2F0KPBQbCVGud4nsBa8/USV3Sjeu+QyfRQ=;
        b=Td5Fh8/sPNPDv9Y9LPZsagV+yJRTItOEbJEIEo9YfpIkLsBSxfioRnXtnJZrFOc2He
         0GGwJIU05S3vi0FpSZi2odVwVyEeONNtqdQ5w1sMfRoJ/z7DX+yqnKq9e8czt+XUFoP/
         b9lEhFk0fBGHjVmoaa5SchetP+FAERgIKq4o72kPv+Hpk/vMiM0xIfZBIw6V5hRYHqLi
         brvkdHYnnwx9rc50fQ8NJQcWsgxtj/UZGqu1AEUxXH87dYZMeOhd935YW0q97b9NHuuP
         bxagVHTx/+WEK8Ro8viNuDMWXj+fJtd23/z2bVVTXUqjAPZiRN2zVR5hH53c+OwM05hH
         tLHw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b="k2/5MnNm";
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b="k2/5MnNm";
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [2a07:de40:b251:101:10:150:64:2])
        by gmr-mx.google.com with ESMTPS id f44-20020a0565123b2c00b0051301760f3fsi26779lfv.5.2024.02.26.01.11.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 26 Feb 2024 01:11:39 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) client-ip=2a07:de40:b251:101:10:150:64:2;
Received: from imap1.dmz-prg2.suse.org (imap1.dmz-prg2.suse.org [10.150.64.97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id 7C4361F896;
	Mon, 26 Feb 2024 09:11:38 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id 53DAC13A58;
	Mon, 26 Feb 2024 09:11:38 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id zqYiFMpV3GV7HAAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Mon, 26 Feb 2024 09:11:38 +0000
Message-ID: <38f7952a-bee7-4a21-a89f-facff1803c41@suse.cz>
Date: Mon, 26 Feb 2024 10:11:38 +0100
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v2 0/3] cleanup of SLAB_ flags
Content-Language: en-US
To: Christoph Lameter <cl@linux.com>, Pekka Enberg <penberg@kernel.org>,
 David Rientjes <rientjes@google.com>, Joonsoo Kim <iamjoonsoo.kim@lge.com>,
 Andrew Morton <akpm@linux-foundation.org>,
 Roman Gushchin <roman.gushchin@linux.dev>,
 Hyeonggon Yoo <42.hyeyoo@gmail.com>, Andrey Ryabinin
 <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>,
 Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>,
 Vincenzo Frascino <vincenzo.frascino@arm.com>
Cc: Zheng Yejian <zhengyejian1@huawei.com>,
 Xiongwei Song <xiongwei.song@windriver.com>,
 Chengming Zhou <chengming.zhou@linux.dev>, linux-mm@kvack.org,
 linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com,
 Steven Rostedt <rostedt@goodmis.org>
References: <20240223-slab-cleanup-flags-v2-0-02f1753e8303@suse.cz>
From: Vlastimil Babka <vbabka@suse.cz>
In-Reply-To: <20240223-slab-cleanup-flags-v2-0-02f1753e8303@suse.cz>
Content-Type: text/plain; charset="UTF-8"
X-Spamd-Result: default: False [1.41 / 50.00];
	 ARC_NA(0.00)[];
	 RCVD_VIA_SMTP_AUTH(0.00)[];
	 XM_UA_NO_VERSION(0.01)[];
	 FROM_HAS_DN(0.00)[];
	 TO_DN_SOME(0.00)[];
	 FREEMAIL_ENVRCPT(0.00)[gmail.com];
	 TO_MATCH_ENVRCPT_ALL(0.00)[];
	 TAGGED_RCPT(0.00)[];
	 MIME_GOOD(-0.10)[text/plain];
	 MID_RHS_MATCH_FROM(0.00)[];
	 R_RATELIMIT(0.00)[to_ip_from(RLqdadssyy1w6u3twx3pq4jyny)];
	 RCVD_COUNT_THREE(0.00)[3];
	 DKIM_SIGNED(0.00)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	 BAYES_HAM(-0.00)[19.95%];
	 RCPT_COUNT_TWELVE(0.00)[19];
	 FREEMAIL_TO(0.00)[linux.com,kernel.org,google.com,lge.com,linux-foundation.org,linux.dev,gmail.com,arm.com];
	 FUZZY_BLOCKED(0.00)[rspamd.com];
	 FROM_EQ_ENVFROM(0.00)[];
	 MIME_TRACE(0.00)[0:+];
	 RCVD_TLS_ALL(0.00)[];
	 SUSPICIOUS_RECIPS(1.50)[]
X-Spam-Level: *
X-Spam-Score: 1.41
X-Spam-Flag: NO
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b="k2/5MnNm";
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b="k2/5MnNm";
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

On 2/23/24 19:27, Vlastimil Babka wrote:
> This started by the report that SLAB_MEM_SPREAD flag is dead (Patch 1).
> Then in the alloc profiling series we realized it's too easy to reuse an
> existing SLAB_ flag's value when defining a new one, by mistake.
> Thus let the compiler do that for us via a new helper enum (Patch 2).
> When checking if more flags are dead or could be removed, didn't spot
> any, but found out the SLAB_KASAN handling of preventing cache merging
> can be simplified since we now have an explicit SLAB_NO_MERGE (Patch 3).
> 
> The SLAB_MEM_SPREAD flag is now marked as unused and for removal, and
> has a value of 0 so it's a no-op. Patches to remove its usage can/will
> be submitted to respective subsystems independently of this series - the
> flag is already dead as of v6.8-rc1 with SLAB removed. The removal of
> dead cpuset_do_slab_mem_spread() code can also be submitted
> independently.
> 
> Signed-off-by: Vlastimil Babka <vbabka@suse.cz>

Pushed to slab/for-next

> ---
> Changes in v2:
> - Collect R-b, T-b (thanks!)
> - Unify all disabled flags's value to a sparse-happy zero with a new macro (lkp/sparse).
> - Rename __SF_BIT to __SLAB_FLAG_BIT (Roman Gushchin)
> - Rewrod kasan_cache_create() comment (Andrey Konovalov)
> - Link to v1: https://lore.kernel.org/r/20240220-slab-cleanup-flags-v1-0-e657e373944a@suse.cz
> 
> ---
> Vlastimil Babka (3):
>       mm, slab: deprecate SLAB_MEM_SPREAD flag
>       mm, slab: use an enum to define SLAB_ cache creation flags
>       mm, slab, kasan: replace kasan_never_merge() with SLAB_NO_MERGE
> 
>  include/linux/kasan.h |  6 ----
>  include/linux/slab.h  | 97 ++++++++++++++++++++++++++++++++++++---------------
>  mm/kasan/generic.c    | 22 ++++--------
>  mm/slab.h             |  1 -
>  mm/slab_common.c      |  2 +-
>  mm/slub.c             |  6 ++--
>  6 files changed, 79 insertions(+), 55 deletions(-)
> ---
> base-commit: 6613476e225e090cc9aad49be7fa504e290dd33d
> change-id: 20240219-slab-cleanup-flags-c864415ecc8e
> 
> Best regards,

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/38f7952a-bee7-4a21-a89f-facff1803c41%40suse.cz.
