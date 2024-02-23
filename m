Return-Path: <kasan-dev+bncBDXYDPH3S4OBB64V4OXAMGQEFUSDEQQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x339.google.com (mail-wm1-x339.google.com [IPv6:2a00:1450:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id BD14286183B
	for <lists+kasan-dev@lfdr.de>; Fri, 23 Feb 2024 17:42:36 +0100 (CET)
Received: by mail-wm1-x339.google.com with SMTP id 5b1f17b1804b1-40e4303faf0sf876105e9.1
        for <lists+kasan-dev@lfdr.de>; Fri, 23 Feb 2024 08:42:36 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1708706556; cv=pass;
        d=google.com; s=arc-20160816;
        b=fownyGg8kLN+bDzzTS09chtAmJlAVrrpF9Xipx7aov4WKvj9J4xUfZiEJ/8wWjnDOs
         HjYi5fb5nFqIcllqt7PyQ2pk5dUsDoi6u09N6EYvSvAWMMwgejoTfjbTukkF1BoCCayT
         tmu4u7iE6vowlv1QcN0uOKtKcnlDvqt5Ff5iY/3PFjEWGT9u0jByJP4GbrgxBoe1QsBz
         8To/WOr+4cyztKOwe1Zxgn/BvLEESf413pLGjtd43Kc4xQgo1//sBK4P4RLNY83JOPzE
         RHFP0cX1eJX2T/YuKQObGPxlWqjzc7AYxm+HC4i3aX8HPvHf3HUAqIyY8aSmRb3dbfAp
         Bbnw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=DG0DvG1AmqKWe4F7lI2Azj0heU87hEWO0GXwq+zykyc=;
        fh=BIJ8YKnY3tz0dGMYhNpGGxpHUxN4x8mtOn3LO0WrXes=;
        b=hjV7mqYgMSTi5SQVSMt/I7FxUIWeon1H6/ibQOe961cL1ZUStUD5XVmatHGDZ65B7F
         5ALXvQihq7+yezQE2d8MeddEVHswz+w3R+dX3ufRDePzwS6gvD/5S81R//jJtJI6DJNS
         zvqRWwbve3z6OoP2wu+8tdVWgBGhuoWdZKP90Hsegw3jSgVneUxioBrGfCC/fP37IU1p
         0GH6Yt4uxSnUKjTbes9K2ivgmc8qm0gec/ASOyBk/TzH73WcUNZx1rKFfXGEAc/k4RH0
         /52RKCHv71ch9NeOt9Y1Ov9nxemmF6s+iZ/Q8gsbTo0CkwkfOKaPZLVHJr0UFDMZjP2v
         etng==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=B0ENLgm3;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=jqf1noHa;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=B0ENLgm3;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.130 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1708706556; x=1709311356; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=DG0DvG1AmqKWe4F7lI2Azj0heU87hEWO0GXwq+zykyc=;
        b=LJotXpQZFq00ZMEBzlJ9IrVr28tMlhXlyonjHXGaUETgghIvgXgQXbLDa3nhwwvtB5
         zwIHQagx8dzQZLFm1m2UG1HchIrsovsV+Q32MK04KH3fT4qljeCs98FdbgL0EWkXeIC0
         4hxhQ0deWLVrORkyES6m51Zl2M7M6hXYifWGFw1OxtFoo38k/KoxnkXMFx5sacSFqcHm
         w6QQ2PU0z1c5LuH4vmY2gdzT7tla8qQVbccSNo265rZkWBqK8MJP2U1JeSo0ncdedLnF
         Xd53ZfwkTviBCWps09NPOtulxzEBFogp/z7W0VoNsCDNN2EDEZEMKLLNU/fMYfsUJgmn
         GfnA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1708706556; x=1709311356;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=DG0DvG1AmqKWe4F7lI2Azj0heU87hEWO0GXwq+zykyc=;
        b=Hr8l5pg3Adez45idTY+GMYCQDnacrWje1zVyTxmsQrUSheXaYygNFg5D/PdV7SjEFx
         nsWIqEq3V8+GD1GKXrVJ9bmIkhGUHOt3oxT58qWoJzGgQ7/XgMgnvXvPPQNe2BtwuoMp
         RQIwa0rOHfkW9BfadoY80dtjJdciI3QbugodwkDLBhxb/I3i3gTv9ZFPrRP0rjnLQs07
         gbEORGrwh/HigUBlN5NqbNiyo74TfVojftXXUR2O8kVfbTT5nbkCGw8n2J9ytXMcphCd
         aIct5Lc32A+k6bJpOBMtL8b/3unJTROce4Xc1E/Q6WuhJ3jV4EyDzaQ9A0AGX8PvxYnz
         dgyw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWeKf5DZ78rCgqdiEKBRECoZ7O/myWhI9BLMN8q+Qogpml4vRL/LCkxS+nQgpQJUW46tj63VDIUpAJS/8UDYs1KLKGTo1O2Fw==
X-Gm-Message-State: AOJu0Yz99lbyrsYGGhdXDYFRKlYSFnoE5YYVcs5kNpZCnQw8o8iOijRF
	G3VflnU7TWJojdvYbxoi8praDaCHVKlJtceGo8Bgr1OznuMVnF+e
X-Google-Smtp-Source: AGHT+IGuhkec1JaHYaX6kJULwSz8Dh1GNmikVQ3nhgP6EdwOglyyzzjBgtW7Av+14gro/EpzpSIhMw==
X-Received: by 2002:a05:600c:b9b:b0:412:97d9:3dba with SMTP id fl27-20020a05600c0b9b00b0041297d93dbamr54790wmb.4.1708706555659;
        Fri, 23 Feb 2024 08:42:35 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:158e:b0:512:dd1c:9617 with SMTP id
 bp14-20020a056512158e00b00512dd1c9617ls113613lfb.1.-pod-prod-08-eu; Fri, 23
 Feb 2024 08:42:33 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWnUJQpkAoYcewbaCmrTw8oJTJF1jxsg3VaPzp335VD32YrcSyJGma8SXMNp6Aw1jfgS0wx6EfJ939Nmh0ytf9MWsCrBp2ytP+G5Q==
X-Received: by 2002:a05:6512:2210:b0:512:d81f:c22e with SMTP id h16-20020a056512221000b00512d81fc22emr236405lfu.59.1708706553509;
        Fri, 23 Feb 2024 08:42:33 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1708706553; cv=none;
        d=google.com; s=arc-20160816;
        b=UOjmZej5K4CJUhwt1bOCF1dFh9rRM8HHwjPG0RRifO5VzDdbmvO6vtaR3ZZ/onfDhu
         t4zoe+30UFUlWFTDtU7GHBzZEL4PrxqtBIOnO3xBJU9PxLrS7Adda3gAgMFR79TlpOaf
         amMcQFXyrkPafTYGSNAyg1i2o2WF+CmajmVKJDtsXOG8O4MINxh/a2BNmOE7U6qtfA8y
         2aDn7xGRXEbwt2kJ2wwWrz0zxJgq+f/swmnC3gO6Ae0UfVP5hSwOLkqDTs6V76tUfFb6
         DPDyYbfUjcGypssc4JcHjsxUJsVejFqXgGwmCpoZXGD68ckG/Aow2pHT1XvsecfW1mii
         RiCg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature:dkim-signature:dkim-signature;
        bh=KFNMZIie6l19aBPMWRYEEnQsnBcUocAqPJ4rC3B7ytY=;
        fh=nQyVatozp7+OCSBx7hASNlgw7llnuXSQknvKg3daPQc=;
        b=SO8E1jsu0btKSihhAvmR7d8tyubIlxRcWvKw1BkgLM6TXT2oigsTmxp+p7F3D+xDJX
         I/OeacsaMzflb+zUYSsY036V6u93vIxsXjSbrox4tgedQbjbLNP+5fB7b2TrU2Zk2QCX
         oVddCimxdCAAMG+JAywJl82YnhMBLm6Xmdza3DSNY1ql9zHWAsXhrZpw1q38dmK0IN+5
         dkK5y5aPFJz00MFM2INuAsIg4RYC3USAoGwkq3jJvynQy9Qv5rw3tXvkRUZVwqQVyXNo
         glvLWjMemiPTktwM+2jFP5RUpFgiFBpBDaxV6qDyNnX7jr2yXkIjnIuuDkQGDPT4Qq6D
         gTrQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=B0ENLgm3;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=jqf1noHa;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=B0ENLgm3;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.130 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [195.135.223.130])
        by gmr-mx.google.com with ESMTPS id z2-20020a056512308200b0051183785260si581614lfd.4.2024.02.23.08.42.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 23 Feb 2024 08:42:33 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.223.130 as permitted sender) client-ip=195.135.223.130;
Received: from imap1.dmz-prg2.suse.org (imap1.dmz-prg2.suse.org [IPv6:2a07:de40:b281:104:10:150:64:97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id 7706421FB5;
	Fri, 23 Feb 2024 16:42:32 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id 443D6133DC;
	Fri, 23 Feb 2024 16:42:32 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id YCWsD/jK2GWUNAAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Fri, 23 Feb 2024 16:42:32 +0000
Message-ID: <0a30e148-2698-44d5-83c9-da102c0ba753@suse.cz>
Date: Fri, 23 Feb 2024 17:42:32 +0100
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH 2/3] mm, slab: use an enum to define SLAB_ cache creation
 flags
Content-Language: en-US
To: Roman Gushchin <roman.gushchin@linux.dev>
Cc: Christoph Lameter <cl@linux.com>, Pekka Enberg <penberg@kernel.org>,
 David Rientjes <rientjes@google.com>, Joonsoo Kim <iamjoonsoo.kim@lge.com>,
 Andrew Morton <akpm@linux-foundation.org>,
 Hyeonggon Yoo <42.hyeyoo@gmail.com>, Andrey Ryabinin
 <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>,
 Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>,
 Vincenzo Frascino <vincenzo.frascino@arm.com>,
 Zheng Yejian <zhengyejian1@huawei.com>,
 Xiongwei Song <xiongwei.song@windriver.com>,
 Chengming Zhou <chengming.zhou@linux.dev>, linux-mm@kvack.org,
 linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com
References: <20240220-slab-cleanup-flags-v1-0-e657e373944a@suse.cz>
 <20240220-slab-cleanup-flags-v1-2-e657e373944a@suse.cz>
 <ZdZCDEFX4_UuHSWR@P9FQF9L96D.corp.robot.car>
From: Vlastimil Babka <vbabka@suse.cz>
In-Reply-To: <ZdZCDEFX4_UuHSWR@P9FQF9L96D.corp.robot.car>
Content-Type: text/plain; charset="UTF-8"
X-Spam-Level: 
X-Spamd-Bar: /
X-Rspamd-Server: rspamd2.dmz-prg2.suse.org
X-Spamd-Result: default: False [-0.11 / 50.00];
	 RCVD_VIA_SMTP_AUTH(0.00)[];
	 XM_UA_NO_VERSION(0.01)[];
	 TO_DN_SOME(0.00)[];
	 R_RATELIMIT(0.00)[to_ip_from(RLycmwa99sdzp837p77658kns5)];
	 RCVD_COUNT_THREE(0.00)[3];
	 DKIM_TRACE(0.00)[suse.cz:+];
	 MX_GOOD(-0.01)[];
	 NEURAL_HAM_SHORT(-0.20)[-1.000];
	 FROM_EQ_ENVFROM(0.00)[];
	 MIME_TRACE(0.00)[0:+];
	 BAYES_HAM(-0.11)[66.23%];
	 MID_RHS_MATCH_FROM(0.00)[];
	 ARC_NA(0.00)[];
	 R_DKIM_ALLOW(-0.20)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	 FROM_HAS_DN(0.00)[];
	 FREEMAIL_ENVRCPT(0.00)[gmail.com];
	 TO_MATCH_ENVRCPT_ALL(0.00)[];
	 TAGGED_RCPT(0.00)[];
	 MIME_GOOD(-0.10)[text/plain];
	 NEURAL_HAM_LONG(-1.00)[-1.000];
	 DKIM_SIGNED(0.00)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	 RCPT_COUNT_TWELVE(0.00)[18];
	 FUZZY_BLOCKED(0.00)[rspamd.com];
	 FREEMAIL_CC(0.00)[linux.com,kernel.org,google.com,lge.com,linux-foundation.org,gmail.com,arm.com,huawei.com,windriver.com,linux.dev,kvack.org,vger.kernel.org,googlegroups.com];
	 RCVD_TLS_ALL(0.00)[];
	 SUSPICIOUS_RECIPS(1.50)[]
X-Spam-Score: -0.11
X-Rspamd-Queue-Id: 7706421FB5
X-Spam-Flag: NO
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=B0ENLgm3;       dkim=neutral
 (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=jqf1noHa;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=B0ENLgm3;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates
 195.135.223.130 as permitted sender) smtp.mailfrom=vbabka@suse.cz
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

On 2/21/24 19:33, Roman Gushchin wrote:
> On Tue, Feb 20, 2024 at 05:58:26PM +0100, Vlastimil Babka wrote:
>> The values of SLAB_ cache creation flagsare defined by hand, which is
>> tedious and error-prone. Use an enum to assign the bit number and a
>> __SF_BIT() macro to #define the final flags.
>> 
>> This renumbers the flag values, which is OK as they are only used
>> internally.
>> 
>> Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
>> +#define __SF_BIT(nr)	((slab_flags_t __force)(1U << (nr)))
> 
> I'd rename it to (__)SLAB_FLAG_BIT(), as SF is a bit cryptic, but not a strong
> preference. Otherwise looks really good to me, nice cleanup.

OK, it's also less likely that somebody would collide it.

> Reviewed-by: Roman Gushchin <roman.gushchin@linux.dev>
> 
> Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/0a30e148-2698-44d5-83c9-da102c0ba753%40suse.cz.
