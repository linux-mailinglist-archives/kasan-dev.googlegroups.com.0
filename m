Return-Path: <kasan-dev+bncBDXYDPH3S4OBBLEV4OXAMGQEYZUOMRA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53c.google.com (mail-ed1-x53c.google.com [IPv6:2a00:1450:4864:20::53c])
	by mail.lfdr.de (Postfix) with ESMTPS id 513A9861831
	for <lists+kasan-dev@lfdr.de>; Fri, 23 Feb 2024 17:41:18 +0100 (CET)
Received: by mail-ed1-x53c.google.com with SMTP id 4fb4d7f45d1cf-5648a1a85aasf18453a12.0
        for <lists+kasan-dev@lfdr.de>; Fri, 23 Feb 2024 08:41:18 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1708706478; cv=pass;
        d=google.com; s=arc-20160816;
        b=QNiwSqVKKiybs9fllEybEak+jedHIaLvao96DWqLXOmhIB1ORfiG3GVJh7d/Zup5Xk
         xrXWbTl3eh35/4lmc6QVKBzvkCuViHrGEG+2vVmax5TfDxue91BS9ci7nSZqLmjPfAAe
         EdzUKNngClQZaA3vsITIB9p8iqRj6SVUpwlGLcbIStTn5VKY00NCOA+kKyi6RGEYUKY1
         jen28lVtRJnP4O6zQ66bZOTcIqPhjPHdFEU/FKm5y6D3EabF08T9azbH2Kv673fZ54Yq
         4jnSuqYP0yJaNbWM4RhfO8q2meU7bkHPOmBqxWFmd32Z5KAZjs3Rp0rH3JghvxVH+USP
         EPCQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=J4NQGUUmpoK+LrbcOFCEMwjydmoKoO5x9iLqAyhqgc0=;
        fh=swB4DgQbwJ+HIHCYTZoMLC3ysst0YRvOWRyw3UwAM2w=;
        b=XGw8k1xT5CAOKWqMTq8yCIvecZVRn23oeZrG/zaRK8JFFQ2j41nor5dAGnFEEyC4tM
         yY8eNT1BLd4WV0ZzODB9xoiK7EWzAgXek1L6xrWHR3Xf8k5+doEtfC7wqIVd6+wJbL3B
         tvHHpvXZxl+AFv6J1OiSj5FxtWQqdYC18oSm7o1CvJRC8bNE8IMeLtH37je2s4F9NYbx
         C2be55FCWM6rB7+MM+euvi0CrmOn3KquliUJN1sFTaXZpsqY0fYBOVm0C47CTU4Rofw5
         U7VIy1BUuq22GpMnTFWsc22AUxwCz8JC9b4ZX5qDhpEH/LJJMx+UCxfweHzjfQfTsTbz
         /U0Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=eRPkpehn;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=eRPkpehn;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b="/IAv2tlZ";
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1708706478; x=1709311278; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=J4NQGUUmpoK+LrbcOFCEMwjydmoKoO5x9iLqAyhqgc0=;
        b=e8RBruWyRA4MQv/fxtkZZaa+dg5p5Qt5zzJxyEwSKlPK2wBtto4K5TnrK+Git6g2rJ
         oifSKIT9fGOkEhCVhlYgEjVAz0e3IWxKyGtUOg+ai16ZTcDv0RTIIkVl/byF5Di2oNYg
         3eIAvSjqJn1uR//Qn2KJaySlDGWeMRxulUgfxyldFX7c8nifSFit/BqPw51J72nQI+qa
         C01YcfC8jkoLf59Jhz0q/iiHvMKyzcyctp2YRSsqlftgezyd/Gdrs/2bEmEXeQeSOs8c
         b0MNkaUBN/sPzOHbn2Q67JsGj0eYm0goUp5JFhhKY41biOMYLHpdwfpQKPrY+es0sbIe
         rrcg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1708706478; x=1709311278;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=J4NQGUUmpoK+LrbcOFCEMwjydmoKoO5x9iLqAyhqgc0=;
        b=CgcrByASeitepqpfIZhXqDw2n/NpRdFmtMRxwyb/qudD7/Z7vrtsR9otUgGRXntamL
         MbXJogJv25745SNVzcauSfr+5Ox99FUc0bZu99mA7LuGvQw8+6mGOgE9AVwJg+v+/a3O
         MZJq8Hue+Qe2Svzi3xxA8ey9dT2zfdzB2z4oGs4c7sW4z8V2pIn1rWnF0egQ3Ly8ynDv
         NjFqizqoXDjXc4R1wBFocasZj2IcpTAgiozkJYU2rKuJVOweAO8t5DvK41X1ZmR4Cc2f
         mWu95x5Myb09C+QVQHwJlBH1WD7M/RTtUKggO3/AdRzKz8P63mgu15+T/8M6Rzoen0gN
         SDcA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWw0c976BQDkveaIGMYcGJdsOl51WcoNB7+6xCOdPRYwb97HsAEndLjy8WGXe7EYL6LzCviQU01+K4Ed2pkjuZk/WSceBl/8A==
X-Gm-Message-State: AOJu0Yxr0Cxa8hVcwdyeE4mMkP+zJ4EDDYv0YouwMAvpjEfMIuK3ZoLY
	oHQrc9NB00uwIQOUyRU0He3a5E2X138jhkxKGsbfjx5I1SOf2gAP
X-Google-Smtp-Source: AGHT+IHHEONY+RSURr+SD8EObwB9FbeQ0dCo33jplhw4w179AesepB8txe3xnFk4cYUWQL00AjD5XA==
X-Received: by 2002:a50:8a8c:0:b0:565:4c2a:c9b6 with SMTP id j12-20020a508a8c000000b005654c2ac9b6mr333702edj.0.1708706477118;
        Fri, 23 Feb 2024 08:41:17 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:3896:b0:564:7bfd:d156 with SMTP id
 fd22-20020a056402389600b005647bfdd156ls597786edb.0.-pod-prod-09-eu; Fri, 23
 Feb 2024 08:41:15 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWfoTcb9rhxMSv5mszG8iYmjOD7FAIluNVXngd4WbYUyrA1obT8CJHtbMdfLGTEe/VRN+d/9v7X4g6Zy0ZsgKvQHTjiN+qKe4cE/g==
X-Received: by 2002:a05:6402:3447:b0:564:5407:ce22 with SMTP id l7-20020a056402344700b005645407ce22mr228457edc.21.1708706475101;
        Fri, 23 Feb 2024 08:41:15 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1708706475; cv=none;
        d=google.com; s=arc-20160816;
        b=LI6JulxWrd2TsAYi3BqwPFmG4wzQeq2426SCuyuMLaoIaIFID6gZpROHLLUqg2oM1T
         4MRErGxR7XCPMH3g3gwfRyKlEcbOKSzA+uu1wJb5rOEuykJXw6sZGz6oa7tBJWYEMgZ9
         UoOZBUUEWw7h4vBLfSDS3+OttlsBkT5OzJnHu++e3fLg9kdngd+9OMAJ9OHruSXcLAds
         I3MMJn2qUw84r9zqWy9LxVRr4W7QmA+O/uLsR2brpcgn4DRnmXIWE9o93hUO9J2sWfEB
         9f8A8roLRvUR2SjOfmhhY6+1+YSxKB1upWwmZa3MzdTYyWkFOsvIWVZhc6Fa2G18OhGp
         P00Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature:dkim-signature:dkim-signature;
        bh=XAyabS4dUGUNPXWjy9UPvrWPskMGtOkshIYfRSgL3r4=;
        fh=8E4jWX/GLoJC+yn27t2YwgvATmBqv33vIQq6Q1qjTPg=;
        b=wujDIJWXbl3jiHzSK8Oi3aWER+tW9IWWRXOXgz3Xzq+fiY8yEvkgWyvDwiXMwaQGbY
         z0SY2g6qfqttoafhTF3Sgln53lL7U2E63OG2MaGyr97o9horWJ/Pp+QlfhGf43DCwbob
         giMnsE7lMZTlpi0jda+OulKRzQ/oQyeSsTi5+SgRIBoDnUgSymy8IIxpZXH28AErzLs7
         Kvw483o3OuyZRBoZRmYQCWu+I6kRx23NwPrDqiyNvF3ana1wjvHkDJ3HE9xgK9YAdMx4
         aRGw7e1xPLYzJxjiJ1Fcdlv/qDXaK1mbqKUU8W719OuxW+hUWxcznp/7K6s8CJ42OejF
         JDlw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=eRPkpehn;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=eRPkpehn;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b="/IAv2tlZ";
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [2a07:de40:b251:101:10:150:64:1])
        by gmr-mx.google.com with ESMTPS id m20-20020a50d7d4000000b00563fcbe92aasi1035245edj.0.2024.02.23.08.41.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 23 Feb 2024 08:41:15 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) client-ip=2a07:de40:b251:101:10:150:64:1;
Received: from imap1.dmz-prg2.suse.org (imap1.dmz-prg2.suse.org [IPv6:2a07:de40:b281:104:10:150:64:97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id 7A59421FB4;
	Fri, 23 Feb 2024 16:41:14 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id 527E2133DC;
	Fri, 23 Feb 2024 16:41:14 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id Ayq0E6rK2GWUNAAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Fri, 23 Feb 2024 16:41:14 +0000
Message-ID: <beb2b051-af97-4a6a-864c-e2c03cd8f624@suse.cz>
Date: Fri, 23 Feb 2024 17:41:14 +0100
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH 1/3] mm, slab: deprecate SLAB_MEM_SPREAD flag
Content-Language: en-US
To: Chengming Zhou <chengming.zhou@linux.dev>,
 "Song, Xiongwei" <Xiongwei.Song@windriver.com>,
 Roman Gushchin <roman.gushchin@linux.dev>
Cc: Christoph Lameter <cl@linux.com>, Pekka Enberg <penberg@kernel.org>,
 David Rientjes <rientjes@google.com>, Joonsoo Kim <iamjoonsoo.kim@lge.com>,
 Andrew Morton <akpm@linux-foundation.org>,
 Hyeonggon Yoo <42.hyeyoo@gmail.com>, Andrey Ryabinin
 <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>,
 Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>,
 Vincenzo Frascino <vincenzo.frascino@arm.com>,
 Zheng Yejian <zhengyejian1@huawei.com>,
 "linux-mm@kvack.org" <linux-mm@kvack.org>,
 "linux-kernel@vger.kernel.org" <linux-kernel@vger.kernel.org>,
 "kasan-dev@googlegroups.com" <kasan-dev@googlegroups.com>,
 Steven Rostedt <rostedt@goodmis.org>
References: <20240220-slab-cleanup-flags-v1-0-e657e373944a@suse.cz>
 <20240220-slab-cleanup-flags-v1-1-e657e373944a@suse.cz>
 <ZdZBN_K8yJTVIbtC@P9FQF9L96D.corp.robot.car>
 <CO1PR11MB51854DA6F03753F12A540293EC562@CO1PR11MB5185.namprd11.prod.outlook.com>
 <7e27b853-e10f-4034-bc81-2d5e5a03361a@linux.dev>
From: Vlastimil Babka <vbabka@suse.cz>
In-Reply-To: <7e27b853-e10f-4034-bc81-2d5e5a03361a@linux.dev>
Content-Type: text/plain; charset="UTF-8"
X-Spamd-Result: default: False [-1.80 / 50.00];
	 ARC_NA(0.00)[];
	 TO_DN_EQ_ADDR_SOME(0.00)[];
	 R_DKIM_ALLOW(-0.20)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	 XM_UA_NO_VERSION(0.01)[];
	 FROM_HAS_DN(0.00)[];
	 TO_DN_SOME(0.00)[];
	 FREEMAIL_ENVRCPT(0.00)[gmail.com];
	 TO_MATCH_ENVRCPT_ALL(0.00)[];
	 TAGGED_RCPT(0.00)[];
	 MIME_GOOD(-0.10)[text/plain];
	 RCVD_VIA_SMTP_AUTH(0.00)[];
	 MID_RHS_MATCH_FROM(0.00)[];
	 R_RATELIMIT(0.00)[to_ip_from(RLycmwa99sdzp837p77658kns5)];
	 RCVD_COUNT_THREE(0.00)[3];
	 DKIM_SIGNED(0.00)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	 DKIM_TRACE(0.00)[suse.cz:+];
	 MX_GOOD(-0.01)[];
	 RCPT_COUNT_TWELVE(0.00)[19];
	 BAYES_HAM(-3.00)[100.00%];
	 FUZZY_BLOCKED(0.00)[rspamd.com];
	 FROM_EQ_ENVFROM(0.00)[];
	 MIME_TRACE(0.00)[0:+];
	 FREEMAIL_CC(0.00)[linux.com,kernel.org,google.com,lge.com,linux-foundation.org,gmail.com,arm.com,huawei.com,kvack.org,vger.kernel.org,googlegroups.com,goodmis.org];
	 RCVD_TLS_ALL(0.00)[];
	 SUSPICIOUS_RECIPS(1.50)[]
X-Rspamd-Server: rspamd1.dmz-prg2.suse.org
X-Rspamd-Queue-Id: 7A59421FB4
X-Spam-Level: 
X-Spam-Score: -1.80
X-Spam-Flag: NO
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=eRPkpehn;       dkim=neutral
 (no key) header.i=@suse.cz header.s=susede2_ed25519;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=eRPkpehn;       dkim=neutral
 (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b="/IAv2tlZ";
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

On 2/22/24 03:32, Chengming Zhou wrote:
> On 2024/2/22 09:10, Song, Xiongwei wrote:
>> Hi Vlastimil,
>> 
>>> On Tue, Feb 20, 2024 at 05:58:25PM +0100, Vlastimil Babka wrote:
>>> 0;95;0c> The SLAB_MEM_SPREAD flag used to be implemented in SLAB, which was
>>>> removed.  SLUB instead relies on the page allocator's NUMA policies.
>>>> Change the flag's value to 0 to free up the value it had, and mark it
>>>> for full removal once all users are gone.
>>>>
>>>> Reported-by: Steven Rostedt <rostedt@goodmis.org>
>>>> Closes: https://lore.kernel.org/all/20240131172027.10f64405@gandalf.local.home/
>>>> Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
>>>
>>> Reviewed-by: Roman Gushchin <roman.gushchin@linux.dev>
>>>
>>> Do you plan to follow up with a patch series removing all usages?
>> 
>> If you are not available with it, I can do.
> 
> Actually, I have done it yesterday. Sorry, I just forgot this task. :)
> 
> I plan to send out it after this series merged in the slab branch. And
> I'm wondering is it better to put all diffs in one huge patch or split
> every diff to each patch?

I'd suggest you do a patch per subsystem (mostly different filesystems) and
send them out to respective maintainers to pick in their trees. I've talked
to David from btrfs and he suggested this way.

You don't need to wait for this series to be merged. The flag is already a
no-op as of 6.8-rc1. Also I'd suggest sending the patches individually. In a
series they wouldn't depend on each other anyway, and you would either have
to Cc maintainers separately per patch of the series, or everyone on
everything, and there would always be somebody who would prefer the other
way that you pick.

> Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/beb2b051-af97-4a6a-864c-e2c03cd8f624%40suse.cz.
