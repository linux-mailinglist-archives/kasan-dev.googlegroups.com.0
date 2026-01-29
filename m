Return-Path: <kasan-dev+bncBDXYDPH3S4OBB35Q5TFQMGQE4WENFXQ@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id 8Ct9FnIYe2lCBQIAu9opvQ
	(envelope-from <kasan-dev+bncBDXYDPH3S4OBB35Q5TFQMGQE4WENFXQ@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Thu, 29 Jan 2026 09:21:06 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13c.google.com (mail-lf1-x13c.google.com [IPv6:2a00:1450:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id E3C0CAD701
	for <lists+kasan-dev@lfdr.de>; Thu, 29 Jan 2026 09:21:05 +0100 (CET)
Received: by mail-lf1-x13c.google.com with SMTP id 2adb3069b0e04-59e08e08e63sf466408e87.3
        for <lists+kasan-dev@lfdr.de>; Thu, 29 Jan 2026 00:21:05 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1769674865; cv=pass;
        d=google.com; s=arc-20240605;
        b=UWtwusszDjqiULLPhK4R9oY1RjCSlHivrSAgGHD83kT0ZveOXephHirUTmPeKHJMj2
         gH4C/tdgGUaqePidc9Zgs238jVfUe27dKT8rnJlw1/xiBcXAAYabaikoTVgJi77xucgF
         VJvN19jvAYrVpN54upFKtPxSMeYF8asRL/9s9trBNLSerc4R+cVodwlgFHvHR3fODiUs
         30PKwnclZe3CzHPUyfugn/yDP0pSfT90K+TLua04tmzQv7lFSyd9PyGLdAiUb3xP6ZqT
         E5RGGt+NhYjJFFfzuLvAHAU4+4Q0fjbYwgOHb4EOMBfDtMcCL5cBr2p5AAehz4piLrsx
         VnFw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:autocrypt:from
         :references:cc:to:content-language:subject:user-agent:mime-version
         :date:message-id:sender:dkim-signature;
        bh=w2BULPi5OW4UMJgtn+4SbmDJqWCK2uYztO9x+N57j2I=;
        fh=BbmbZ6Z+9HGsks4CsxSrexx4pCb2U6Yzt8CEotT3uaw=;
        b=LU6PXC5vRT2hwoHC6aHZybXDssuT8oL3rAux1boSI9Gt8aTaoPYVbZWsNPjHPwrsTl
         ix2TnSj4IMkj/dLQj1YPfYwzYDHY5EHMh5s99vTGDKz6cWp87Tds6z38HSmeFAbMtfho
         5i5VfztMTSTDwgH4v4ROWgCrwmrv5nTZyZwFQp1Kqwvzj4qAhFD6ARk9/toB3jXsjFXl
         1H/M9DoTMN3pi3AOH2FmIZ1StYQ/FgnvCT9gIK6Uq4RYKnQWD8nvhu9ASMHm2xxwLBPK
         7M4jd3aBz0vt11sRV8/M43FTzZkKl8Sya+wWHgcPTND4WBCh+kcbhb1WVh0zXWJohN6A
         aKIg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b="xR/0RAzK";
       dkim=neutral (no key) header.i=@suse.cz;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b="xR/0RAzK";
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1769674865; x=1770279665; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:autocrypt:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=w2BULPi5OW4UMJgtn+4SbmDJqWCK2uYztO9x+N57j2I=;
        b=geCUfDCkZlqNZzenM0d+KCFX3jjHs/pLtEco0i60Y/6QjgmA604gF/b/G4eB8Zbw0M
         5iC2gxzHh4rsoiHH5YdblH43FtHtMDZXvvO40n1Wl73IV8Z0UGjdHN6x3H47NOyjQA1y
         LLTKg2h9R4aut2PqFD+94D5Q1ZhZs1rCFJDmsbgjqMwfRi9aa4rGVdEX33+bbQLEKVSs
         MGV5zSOsJTnskRRnEGAdTfrIH+F+GUcvI57DNXJ05Ub7rHgUm81GsQnCsmyK1YYq4etS
         VmuiASxUVC/H6yesBkykHJQXLQMCFtRN5QPSHd5rO/poSKInAUBJ8XeAj+/ROzREYZhF
         AL+g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1769674865; x=1770279665;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :autocrypt:from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=w2BULPi5OW4UMJgtn+4SbmDJqWCK2uYztO9x+N57j2I=;
        b=SMSEL+YSon8QwLY1bGzl4+AN4QSJFVwtuKkIU8kTXXln+xXxMnPwMQeAVSpjnuFc9J
         50CaT7a2q99Wc+e3RWr/8JJR9Ngc1AXrykwx0bO6W8++iLrlQkdcoRowwLtpRpwqDh1M
         /SoILNR/9tO2VBlFgwQsZJzDmu402DyVe758Kjzj+Bo78zFLENWP+7ErLYuzxIgCa4qX
         51FDsDU6D+4E/AHjURrB9BW/51A1oWJoXjBX+Cs+nmYrQUEHW2b+8pXGorRNgK0N6KIv
         MKMfPJTFgOD6oQoRxCJD34OaIDj8DS/1fdSBK5inZCsLNGB9oVP8GwOhKddgX6CpWRFn
         y/MA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUF9FXpfk4N7y5LLW/9thfADnIdehLzF3hvMwpVhPPEvotZB9wz3Lhf5KVskxlJ3tKb3LCUXg==@lfdr.de
X-Gm-Message-State: AOJu0YwdDWcm247POii5e3Ir6beVRIn5H6hRTVNBXTaeP73gli/RjqsR
	fWsekO1pVqhsZs2zNEhS8rdAfp3I4U1DTIakvhE1JbpzmLeJYPj6AB9J
X-Received: by 2002:a05:6512:114d:b0:59d:f4dc:29ab with SMTP id 2adb3069b0e04-59e0412d076mr3089673e87.33.1769674864418;
        Thu, 29 Jan 2026 00:21:04 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+HybIqvG0s1Acv7fMDozM8dSunMtu38HpfpAZLwDQHZcQ=="
Received: by 2002:a2e:9e81:0:b0:383:1432:9561 with SMTP id 38308e7fff4ca-38637f5d412ls656201fa.0.-pod-prod-01-eu;
 Thu, 29 Jan 2026 00:21:01 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUdEhwi3jhpdMjpp8+LzaW9Bbwl8tMCgef8JRTcEvRRTQEMseR4VbwrEZPYyv9At8vIj14WB/aBtm4=@googlegroups.com
X-Received: by 2002:a2e:a54e:0:b0:382:ff8c:c9c3 with SMTP id 38308e7fff4ca-3861c81f213mr33263891fa.3.1769674861577;
        Thu, 29 Jan 2026 00:21:01 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1769674861; cv=none;
        d=google.com; s=arc-20240605;
        b=UAkezQBrxwL9BjsRuRbcfA3Ahv+sTZ82p9+x6IKVjyR2wM8u1yKvfvGHRnWIbcvipg
         5Djsa/LtgU3+GOESBqKB8vj18Wi4uJ+FBhNt+udwcKGQ6nbqYLx/UT4bibirrfRIy6sx
         F3FL35TU6vyUX+kgm2L3vZcG30zrCfNk/83nTtxEg20oDkFwsNGugI9FiRFRTJcDY7PH
         Fl+uFhxr86f8MrNeCvAIMn5pG6x0XqGjtJyoEZoPxWfyzy3/0rwP7QhO/WzuEpaBCAy2
         WCzSxDdRvbCWgOi8KQpaOKJyAD/jj6affJKIkqAXgYJMqLhTUe52LvSPVtkPmoWuIvMT
         Icxg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:autocrypt:from:references:cc
         :to:content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature:dkim-signature:dkim-signature;
        bh=bnoAjIEBZE3yHj9Uu6+mVva3GLy2AXgvwJcLgSTdq2E=;
        fh=IGvdOSJj5z2z4QJUKn17Cn2jNjDMsMnR2CrE4yEzswQ=;
        b=C+SZQACi/m9uI+7UrQIoOajDhfxGwBw1u8IBPVWrwJub3fxG8aF9SIHwEPFh2IE1fl
         +gcc4nEgxK0CiJG9UlMi0FMOoAu4o+IZvPJIhqUeYzcRymQ0qUU98BmBGB2LeGHCUEwH
         3QY6Tn8RdRknbTu5t66QtezYFO4pl/j5KC6Od9f9f3nfdNbpHjO7HBD/P+29eyqPy6aB
         wiGkLyzXZVI1DRWA0i50Dqpx6/SvB/lJgxXMBnPlpdckzAPgrPivM53OkYHltCNzeNWM
         /2celLdQ+yTB8ZnMfWFdRUsYc9oQIwigFJdYs3QHlxNMmKGrd2QO3uHedwbCKvl36lI3
         /cuQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b="xR/0RAzK";
       dkim=neutral (no key) header.i=@suse.cz;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b="xR/0RAzK";
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [2a07:de40:b251:101:10:150:64:1])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-38625c73cf8si1054891fa.3.2026.01.29.00.21.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 29 Jan 2026 00:21:01 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) client-ip=2a07:de40:b251:101:10:150:64:1;
Received: from imap1.dmz-prg2.suse.org (imap1.dmz-prg2.suse.org [IPv6:2a07:de40:b281:104:10:150:64:97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id 95ECA3402F;
	Thu, 29 Jan 2026 08:21:00 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id 6A90E3EA61;
	Thu, 29 Jan 2026 08:21:00 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id BxCwGWwYe2mbWgAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Thu, 29 Jan 2026 08:21:00 +0000
Message-ID: <2cd89ed5-0c8e-43f8-896d-1b7dee047fef@suse.cz>
Date: Thu, 29 Jan 2026 09:21:00 +0100
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v4 06/22] slab: add sheaves to most caches
Content-Language: en-US
To: Zhao Liu <zhao1.liu@intel.com>
Cc: Harry Yoo <harry.yoo@oracle.com>, Petr Tesarik <ptesarik@suse.com>,
 Christoph Lameter <cl@gentwo.org>, David Rientjes <rientjes@google.com>,
 Roman Gushchin <roman.gushchin@linux.dev>, Hao Li <hao.li@linux.dev>,
 Andrew Morton <akpm@linux-foundation.org>,
 Uladzislau Rezki <urezki@gmail.com>,
 "Liam R. Howlett" <Liam.Howlett@oracle.com>,
 Suren Baghdasaryan <surenb@google.com>,
 Sebastian Andrzej Siewior <bigeasy@linutronix.de>,
 Alexei Starovoitov <ast@kernel.org>, linux-mm@kvack.org,
 linux-kernel@vger.kernel.org, linux-rt-devel@lists.linux.dev,
 bpf@vger.kernel.org, kasan-dev@googlegroups.com
References: <20260123-sheaves-for-all-v4-0-041323d506f7@suse.cz>
 <20260123-sheaves-for-all-v4-6-041323d506f7@suse.cz>
 <aXsLKxukv60p3QWF@intel.com>
From: Vlastimil Babka <vbabka@suse.cz>
Autocrypt: addr=vbabka@suse.cz; keydata=
 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
 m6M14QORSWTLRg==
In-Reply-To: <aXsLKxukv60p3QWF@intel.com>
Content-Type: text/plain; charset="UTF-8"
X-Spam-Score: -4.51
X-Spam-Level: 
X-Spam-Flag: NO
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b="xR/0RAzK";
       dkim=neutral (no key) header.i=@suse.cz;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b="xR/0RAzK";
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates
 2a07:de40:b251:101:10:150:64:1 as permitted sender) smtp.mailfrom=vbabka@suse.cz
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
X-Rspamd-Server: lfdr
X-Spamd-Result: default: False [-1.71 / 15.00];
	ARC_ALLOW(-1.00)[google.com:s=arc-20240605:i=2];
	R_DKIM_ALLOW(-0.20)[googlegroups.com:s=20230601];
	MAILLIST(-0.20)[googlegroups];
	R_SPF_ALLOW(-0.20)[+ip6:2a00:1450:4000::/36];
	MIME_GOOD(-0.10)[text/plain];
	HAS_LIST_UNSUB(-0.01)[];
	TAGGED_FROM(0.00)[bncBDXYDPH3S4OBB35Q5TFQMGQE4WENFXQ];
	RCVD_TLS_LAST(0.00)[];
	FROM_HAS_DN(0.00)[];
	DMARC_NA(0.00)[suse.cz];
	FORGED_SENDER_MAILLIST(0.00)[];
	FREEMAIL_CC(0.00)[oracle.com,suse.com,gentwo.org,google.com,linux.dev,linux-foundation.org,gmail.com,linutronix.de,kernel.org,kvack.org,vger.kernel.org,lists.linux.dev,googlegroups.com];
	RCPT_COUNT_TWELVE(0.00)[18];
	MIME_TRACE(0.00)[0:+];
	DKIM_TRACE(0.00)[googlegroups.com:+];
	ASN(0.00)[asn:15169, ipnet:2a00:1450::/32, country:US];
	TO_DN_SOME(0.00)[];
	RCVD_COUNT_FIVE(0.00)[6];
	FROM_NEQ_ENVFROM(0.00)[vbabka@suse.cz,kasan-dev@googlegroups.com];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	NEURAL_HAM(-0.00)[-0.998];
	TAGGED_RCPT(0.00)[kasan-dev];
	MID_RHS_MATCH_FROM(0.00)[];
	RCVD_VIA_SMTP_AUTH(0.00)[];
	DBL_BLOCKED_OPENRESOLVER(0.00)[intel.com:email,oracle.com:email]
X-Rspamd-Queue-Id: E3C0CAD701
X-Rspamd-Action: no action

On 1/29/26 08:24, Zhao Liu wrote:
> On Fri, Jan 23, 2026 at 07:52:44AM +0100, Vlastimil Babka wrote:
>> Date: Fri, 23 Jan 2026 07:52:44 +0100
>> From: Vlastimil Babka <vbabka@suse.cz>
>> Subject: [PATCH v4 06/22] slab: add sheaves to most caches
>> X-Mailer: b4 0.14.3
>> 
>> In the first step to replace cpu (partial) slabs with sheaves, enable
>> sheaves for almost all caches. Treat args->sheaf_capacity as a minimum,
>> and calculate sheaf capacity with a formula that roughly follows the
>> formula for number of objects in cpu partial slabs in set_cpu_partial().
>> 
>> This should achieve roughly similar contention on the barn spin lock as
>> there's currently for node list_lock without sheaves, to make
>> benchmarking results comparable. It can be further tuned later.
>> 
>> Don't enable sheaves for bootstrap caches as that wouldn't work. In
>> order to recognize them by SLAB_NO_OBJ_EXT, make sure the flag exists
>> even for !CONFIG_SLAB_OBJ_EXT.
>> 
>> This limitation will be lifted for kmalloc caches after the necessary
>> bootstrapping changes.
>> 
>> Also do not enable sheaves for SLAB_NOLEAKTRACE caches to avoid
>> recursion with kmemleak tracking (thanks to Breno Leitao).
>> 
>> Reviewed-by: Suren Baghdasaryan <surenb@google.com>
>> Reviewed-by: Harry Yoo <harry.yoo@oracle.com>
>> Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
>> ---
>>  include/linux/slab.h |  6 ------
>>  mm/slub.c            | 56 ++++++++++++++++++++++++++++++++++++++++++++++++----
>>  2 files changed, 52 insertions(+), 10 deletions(-)
> 
> vm_area_cachep's capacity seems to be adjusted to 60 and
> maple_node_cache keeps 32 as the args setting.

Good to know. It is a bit larger.
Hm I could have probably applied the args capacity before doing the roundup
to make sheaf fill whole kmalloc size. Would add a few object for maple node
I guess.

> I still use will-it-scale to evaluate the impact of this patch, and
> performance results appear to be on par with previous ones (*) - doesn't
> have regression on my cases.
> 
> Based on the results of previous capacity adjustments testing, I think
> it shows that the capacity of the maple_node_cache appears to have the
> significant impact.
> 
> There may still be room for optimization in maple_node_cache. As a
> general-purpose algorithm at present, I think it has achieved its
> intended purpose based on my test results. So,
> 
> Tested-by: Zhao Liu <zhao1.liu@intel.com>

Thanks!

> 
> 
> (*): The previous ones include 2 cases:
>   1) w/o this series, and directly based on the previous commit ("slub:
>      keep empty main sheaf as spare in __pcs_replace_empty_main()").
>   2) w/o this single patch, and based on the previous patch 5.
> 
> Regards,
> Zhao
> 
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/2cd89ed5-0c8e-43f8-896d-1b7dee047fef%40suse.cz.
