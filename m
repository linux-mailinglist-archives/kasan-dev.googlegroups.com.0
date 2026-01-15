Return-Path: <kasan-dev+bncBDXYDPH3S4OBBRX2ULFQMGQEPV5BNYY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x538.google.com (mail-ed1-x538.google.com [IPv6:2a00:1450:4864:20::538])
	by mail.lfdr.de (Postfix) with ESMTPS id 9547FD23D7D
	for <lists+kasan-dev@lfdr.de>; Thu, 15 Jan 2026 11:11:20 +0100 (CET)
Received: by mail-ed1-x538.google.com with SMTP id 4fb4d7f45d1cf-64d5bec0e59sf673969a12.0
        for <lists+kasan-dev@lfdr.de>; Thu, 15 Jan 2026 02:11:20 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768471879; cv=pass;
        d=google.com; s=arc-20240605;
        b=Y0DKy58o0+BWwR5892sy6JMe/C9l/KE/Nt8DTAyehRHLwyoMLgK/Oh1PRFzFQma0D/
         GFGgiIJnmp4dQE3jT3Bk/8TgjcsYJv9BDthutMiN7bhOEk5D90IzwXF9WpeAc2x86dDr
         W5cs7hP+e8/9o/SIpbqEjf8YUT6ujUnf/geJyXq2IB06w2tmzCCAxDzd68LO6ISfCGnL
         aNIbvyeaECe5AArscEqKxnVFBoggYL0VWV/Dj3k6laj21uXsPo1SQZoN0iyDa6RISHl8
         r5EmmPb/Nh/QpU2KW5YTqYSuj2wk5yNp4JA3ojdNeeg/Tz/IHRAag5yD7vIaZeHnTxxR
         BWZQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:autocrypt:from
         :references:cc:to:content-language:subject:user-agent:mime-version
         :date:message-id:sender:dkim-signature;
        bh=9OeGfYDqgemXsQzCi4JeUnTRjscVr+hHUzIP+51npxg=;
        fh=3R5nJGo9giYB0nEnJrv3+tFXxupfelS1Ktu2zRLX8pg=;
        b=fpHbBoOFewM4vWcD7B9tqPfl/frvVAy02bi364+GKhG84pmB4hebRoBqHed87OTkLN
         seEQF5UWJyW2rmGWHgeMhqN5IJb/nD/0WoFB8D9cVcPLCcNM3uU7i/ruwBqwNCuoxbpK
         deSCqaj9ikGyXz+1anjEqqVhMayXeKk8YSUpNVEHuLSJEK/+AcVXPPGvi8C8h9H9lzgG
         cPkzBz/U26T7ZW3qfAB2teioAHSzFperT/LfPAwj7ug1Lf0Ezia6befj5DeYqcW/N36y
         XcEQYb+NYvwDqF3H624mzt/N/NJ7+pTWEorjiMgL7GoI/tHqVONk/zA/sB6YDGzOhJWE
         Udow==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=lWUu2Tbe;
       dkim=neutral (no key) header.i=@suse.cz;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=lWUu2Tbe;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768471879; x=1769076679; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:autocrypt:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=9OeGfYDqgemXsQzCi4JeUnTRjscVr+hHUzIP+51npxg=;
        b=vmxR++SAKExTTg3j0hGfCAAnSfJdQLF1EXY7xO7FhnWac66E15cprxjoYfgEH4enIj
         lrml9u3Qr5LYiLf+mjSnuqSrdeOGzuNfDy+F8YquDocBXDP7WJ5SwN6It8CnztS+pClc
         f14BzughUjs2ytBaQ4xZn5vNNP1FR6D8i7gVcTCIV+HfjW3PHcn/CLYD9hEr5Qif64nb
         sCYt4DE2izKQKqz2qaDSw3SxA3U6ApkOOBDG1Z2lpkrIUbxFz3zNOST/rt6svHFIgIuF
         3VgGUk4zJfNpJCnCalJLpRz0Y4poE3uXh7FG8DkmOXECJN+YcaKYIp0Q08bkqvWBFZKF
         QZjg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768471879; x=1769076679;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :autocrypt:from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=9OeGfYDqgemXsQzCi4JeUnTRjscVr+hHUzIP+51npxg=;
        b=aEwbIPIO15x31ECehvq24kIdoFsavBUlipCg+QjG1ZdkSY8+YccDb1HWF6yHbUNylo
         TL0PVMyOoAhiB9WVW9rDo50o+glo/LztkKYsJQwk0ylKd2D+sfMWGtIv6t8S6O/TSmMH
         nmL6kke2LcmuWWW0dyKh2iE6Z4bBBXk8horBU2SOA7fLJW+hbrI9sXIilqDdUlksEzn+
         5iRZyZDfxw+PrtVzc1OzoCWPx5x/pozKMYlQ+l4uaCeGIpW0Bkpjc2gTFUN/RhgKpBR2
         UwX9FJrKsHBUzuSF9cs+sV/yNcWoXKVx8hpeZ869HlR3feIa2vfEATIs0Ilg+pOdS3VV
         Tj0A==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXbMBW79XiV15tqwf0umVdZxEPNQcr5kpxTwBbZfsiIR4zdOSGWGSzgAJUGhI9eN0RZRFyDtQ==@lfdr.de
X-Gm-Message-State: AOJu0YwbHrX553Tk1+N8IGSS6XZmRyLFazoBPSWuXcdRqjK30ZkhxQyZ
	I1AzzY4iTlgKPC/wK391FWfvz/+B7Qbm/jGCfU7WqvjBlIi+8O0WsD2E
X-Received: by 2002:a17:907:9409:b0:b73:32c7:6e6a with SMTP id a640c23a62f3a-b8761087500mr501081066b.25.1768471879280;
        Thu, 15 Jan 2026 02:11:19 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+FBO/vJW25gEeMAcOtYjZCJUqXOBjxhqh84+OcTVGK2mA=="
Received: by 2002:aa7:d5c9:0:b0:644:f95b:b16f with SMTP id 4fb4d7f45d1cf-6541be8dd10ls543217a12.0.-pod-prod-08-eu;
 Thu, 15 Jan 2026 02:11:17 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXi2CIZ7yL3EdFmV5AFO4fIRTvgN/iPkYLPqkd8w7gxv2W/YZ4l2p1TSU775ug5gU3IBpQ0h/p3xL4=@googlegroups.com
X-Received: by 2002:a17:907:7851:b0:b87:6b9c:6386 with SMTP id a640c23a62f3a-b876b9c6cd0mr351587566b.56.1768471877106;
        Thu, 15 Jan 2026 02:11:17 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1768471877; cv=none;
        d=google.com; s=arc-20240605;
        b=PRWOStwyNbCtgNGDmKCMES4oJiMjy5UM0ZaIdTi+lSVq4ziyWGI5i3O0MDSKREPe34
         gCdaZZslTsdXt3X0RvmhTSP1F2faQEnEIs+QaYqx570IwV94I3H9hQbXxb/7hX4GtEFj
         nA9V9zFsBX3Y0gT8XF33WwO6KNyTmSmlCSilhX97rQGoTTEpR4NFjOrPqvWMNHMSlD9L
         WUNoYw9cjyv/fRFCNsFpmsOg6EwKyLVNxUsj/+/leBn/KzskY7Nvla98s5mhzeKFOsNK
         7KCe3mIm8c8w5xignippcOdhqY0FJLRPYzx/nmGXpwx5YyAF3Kq76aHPGdGO1NbIy+sP
         tvDg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:autocrypt:from:references:cc
         :to:content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature:dkim-signature:dkim-signature;
        bh=cgS+YfLmxtAaHSdATGA5HBi4gCQegNTgh7ni6TZTR30=;
        fh=F0Ugs/KnYVMrxGPEYvOB808vqz5Ww/CfFkiIgtC+gfU=;
        b=PbVKceD+0B16/FKoqmbt3Hicb69RHvBrOmJaDZDqDo9TTJZzFecAYt1DC036+BTqNf
         9MnPucK/nJKerHGsfYb2Z5BDgrjYK7DXekJjKAEEQoXdz8IfHXrU3aTFZus0a5JzhqDH
         onaN1EEnOwtILBTAfxMIGhOuRMkGYOXcRBHWHDGyQ8A+bsv39yCdD8FUY0CzfGfAZKmv
         EMirZHHFmSHkW9XfKPfP1ptzPxqtvrg31CLP8W2/PRvAlWUqDbk5rqGPtYp10yQ5HIL1
         /eIpNiq2uOCT2puhAka3i2Gteg8IOM1z0ZFxauX7di83jrpT5x3AqBYfZn1zsKUmxamp
         ciOg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=lWUu2Tbe;
       dkim=neutral (no key) header.i=@suse.cz;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=lWUu2Tbe;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [195.135.223.131])
        by gmr-mx.google.com with ESMTPS id a640c23a62f3a-b870d104efdsi28717566b.4.2026.01.15.02.11.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 15 Jan 2026 02:11:17 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted sender) client-ip=195.135.223.131;
Received: from imap1.dmz-prg2.suse.org (imap1.dmz-prg2.suse.org [IPv6:2a07:de40:b281:104:10:150:64:97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id 80B715BCEB;
	Thu, 15 Jan 2026 10:11:16 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id 6164D3EA63;
	Thu, 15 Jan 2026 10:11:16 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id Zbt1F0S9aGkJdQAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Thu, 15 Jan 2026 10:11:16 +0000
Message-ID: <66de652b-3c0d-4ad7-a23e-2a46e862edd7@suse.cz>
Date: Thu, 15 Jan 2026 11:11:16 +0100
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH RFC v2 05/20] slab: introduce percpu sheaves bootstrap
Content-Language: en-US
To: Hao Li <hao.li@linux.dev>
Cc: Harry Yoo <harry.yoo@oracle.com>, Petr Tesarik <ptesarik@suse.com>,
 Christoph Lameter <cl@gentwo.org>, David Rientjes <rientjes@google.com>,
 Roman Gushchin <roman.gushchin@linux.dev>,
 Andrew Morton <akpm@linux-foundation.org>,
 Uladzislau Rezki <urezki@gmail.com>,
 "Liam R. Howlett" <Liam.Howlett@oracle.com>,
 Suren Baghdasaryan <surenb@google.com>,
 Sebastian Andrzej Siewior <bigeasy@linutronix.de>,
 Alexei Starovoitov <ast@kernel.org>, linux-mm@kvack.org,
 linux-kernel@vger.kernel.org, linux-rt-devel@lists.linux.dev,
 bpf@vger.kernel.org, kasan-dev@googlegroups.com
References: <20260112-sheaves-for-all-v2-0-98225cfb50cf@suse.cz>
 <20260112-sheaves-for-all-v2-5-98225cfb50cf@suse.cz>
 <leaboap7yhlnvuxnxvqtl5kazbseimfq3efwfhaon74glfmmc3@paib6qlfee3i>
From: Vlastimil Babka <vbabka@suse.cz>
Autocrypt: addr=vbabka@suse.cz; keydata=
 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
 m6M14QORSWTLRg==
In-Reply-To: <leaboap7yhlnvuxnxvqtl5kazbseimfq3efwfhaon74glfmmc3@paib6qlfee3i>
Content-Type: text/plain; charset="UTF-8"
X-Spam-Score: -4.51
X-Spamd-Result: default: False [-4.51 / 50.00];
	BAYES_HAM(-3.00)[100.00%];
	NEURAL_HAM_LONG(-1.00)[-1.000];
	R_DKIM_ALLOW(-0.20)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	NEURAL_HAM_SHORT(-0.20)[-1.000];
	MIME_GOOD(-0.10)[text/plain];
	MX_GOOD(-0.01)[];
	RCPT_COUNT_TWELVE(0.00)[17];
	ARC_NA(0.00)[];
	RBL_SPAMHAUS_BLOCKED_OPENRESOLVER(0.00)[2a07:de40:b281:104:10:150:64:97:from];
	MIME_TRACE(0.00)[0:+];
	FUZZY_RATELIMITED(0.00)[rspamd.com];
	DKIM_SIGNED(0.00)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	TO_MATCH_ENVRCPT_ALL(0.00)[];
	FREEMAIL_ENVRCPT(0.00)[gmail.com];
	RCVD_TLS_ALL(0.00)[];
	TO_DN_SOME(0.00)[];
	SPAMHAUS_XBL(0.00)[2a07:de40:b281:104:10:150:64:97:from];
	FROM_EQ_ENVFROM(0.00)[];
	FROM_HAS_DN(0.00)[];
	FREEMAIL_CC(0.00)[oracle.com,suse.com,gentwo.org,google.com,linux.dev,linux-foundation.org,gmail.com,linutronix.de,kernel.org,kvack.org,vger.kernel.org,lists.linux.dev,googlegroups.com];
	RCVD_COUNT_TWO(0.00)[2];
	RECEIVED_SPAMHAUS_BLOCKED_OPENRESOLVER(0.00)[2a07:de40:b281:106:10:150:64:167:received];
	MID_RHS_MATCH_FROM(0.00)[];
	DKIM_TRACE(0.00)[suse.cz:+];
	RCVD_VIA_SMTP_AUTH(0.00)[];
	DBL_BLOCKED_OPENRESOLVER(0.00)[imap1.dmz-prg2.suse.org:rdns,imap1.dmz-prg2.suse.org:helo,suse.cz:dkim,suse.cz:mid]
X-Spam-Level: 
X-Rspamd-Action: no action
X-Rspamd-Queue-Id: 80B715BCEB
X-Rspamd-Server: rspamd1.dmz-prg2.suse.org
X-Spam-Flag: NO
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=lWUu2Tbe;       dkim=neutral
 (no key) header.i=@suse.cz;       dkim=pass header.i=@suse.cz
 header.s=susede2_rsa header.b=lWUu2Tbe;       dkim=neutral (no key)
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

On 1/13/26 13:49, Hao Li wrote:
> On Mon, Jan 12, 2026 at 04:16:59PM +0100, Vlastimil Babka wrote:
>> @@ -8641,12 +8690,10 @@ int do_kmem_cache_create(struct kmem_cache *s, const char *name,
>>  
>>  	set_cpu_partial(s);
>>  
>> -	if (s->sheaf_capacity) {
>> -		s->cpu_sheaves = alloc_percpu(struct slub_percpu_sheaves);
>> -		if (!s->cpu_sheaves) {
>> -			err = -ENOMEM;
>> -			goto out;
>> -		}
>> +	s->cpu_sheaves = alloc_percpu(struct slub_percpu_sheaves);
> 
> Since we allocate cpu_sheaves for all SLUB caches, the "if (!s->cpu_sheaves)"
> condition in has_pcs_used() should be always false in practice (unless I'm
> misunderstanding something). Would it make sense to change it to "if
> (!s->sheaf_capacity)" instead?

Right.

> Also, while trying to understand the difference between checking s->cpu_sheaves
> vs s->sheaf_capacity, I noticed that most occurrences of "if (s->cpu_sheaves)"
> (except the one in __kmem_cache_release) could be expressed as "if
> (s->sheaf_capacity)" as well.
> 
> And Perhaps we could introduce a small helper around "if (s->sheaf_capacity)" to
> make the intent a bit more explicit.

Good idea, will do. Thanks!


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/66de652b-3c0d-4ad7-a23e-2a46e862edd7%40suse.cz.
