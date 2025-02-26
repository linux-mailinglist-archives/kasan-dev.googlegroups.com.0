Return-Path: <kasan-dev+bncBDXYDPH3S4OBB6PN7S6QMGQESK5G6BA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x340.google.com (mail-wm1-x340.google.com [IPv6:2a00:1450:4864:20::340])
	by mail.lfdr.de (Postfix) with ESMTPS id 1A55BA46549
	for <lists+kasan-dev@lfdr.de>; Wed, 26 Feb 2025 16:45:00 +0100 (CET)
Received: by mail-wm1-x340.google.com with SMTP id 5b1f17b1804b1-43ab456333asf15758185e9.1
        for <lists+kasan-dev@lfdr.de>; Wed, 26 Feb 2025 07:45:00 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1740584699; cv=pass;
        d=google.com; s=arc-20240605;
        b=QZrwDo1lOIayjEtc+1EVrNL2m8pjX3h5Pjn4EbhzHHLdQktuXM+foFBgq7WPSlG7pd
         nCUX5qnyv7U0Ur0BOtBH1J7OqPD69UTrzfxErAj61xWN7kp7szpAr6G+Ddh4FIpPX4B0
         eEwz2X0viaYkoTNOh5e9jKYYCi0Hf5hVipjIwv1GJBG5iyLXkK/ZCBvmaHURsCwjTvB8
         x4/o1oLMzmX5eQBnCj4/pS9QQWw4H8XvPi640VvqXyYjjmdXoIW8sxQ/JVNX6brk4aDx
         Ff/0yVT6zbT4F1Xwux6S9RuvVWmksZ6p5wvO5CrJ+iJDH4BZ5re++Ex5s76tLgsfl17G
         Aneg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-language:from
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=G19zyjOs/bU3zmh2KcgXnZubJVeCOZlY/rT5dwa0gdE=;
        fh=/A29qc8S97FnyquiJ+ECjukGP+Pi3fa4ENGKg+da3gs=;
        b=OtRVoIpeXNjrclaD7zG1xRd+4ICo/w2Xpd9Qh700dRryfUZAXqxNUKUwHEB/5mD+Sj
         3OUlmAiZIN+JvMEKK+SWXs/ZY4spaiYqHpsBB9ASeaYP3hAufy0I0NMdEdukyOxyHH/J
         WM6f/RIK5JJ/kypbqkEC4yPzm9e/Tgo7/IlgXaJeRJ3ZukC/Q2o//l/E1keqw+1IlP/R
         6z60bWhTdUilOh1vuzx4hNFrpwhaQ14VvENvM/BLZN0jFfoQu2tZjTb8PKFrGsMhPOLB
         rqy5ZxTvu/JtPlJr0SRc5G1XNyFN7F/pTkYDlpCa5IYZ9LHx51BDNI68F8hiJuXnQ3gX
         OWUg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=YkCGpM5I;
       dkim=neutral (no key) header.i=@suse.cz;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=YkCGpM5I;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1740584699; x=1741189499; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-language:from:references:cc
         :to:subject:user-agent:mime-version:date:message-id:sender:from:to
         :cc:subject:date:message-id:reply-to;
        bh=G19zyjOs/bU3zmh2KcgXnZubJVeCOZlY/rT5dwa0gdE=;
        b=HSFoZM2SEqnJtibQOu9QxZbW4IP9DSvzbayruZ5NIO1+66LLZqfWQ3/ezHJzHvvFRf
         9kc4SwYpaDVAOlDuDbMKHiuKwkwB+oFrxnoJCNSQsEDw/IcZYm1gD3FgTOvX3DEqoEqv
         eW7gQT5O/D4sPekWLh/wYsUKQbL7DxbZo9oVwLiHs6KqnBnK0fY212h4a47qSAm0J9rx
         m1XdX3hnqapmtdKzRe5KfqhGy5362gtULmg8HQwSVL4kDZsPdgaYz2WFNqAXN4iI6v/P
         ZgzTzfoQVMG3X0HckbRYYI9eVexMRmxxwcNdqaUE1FmMi7BZuwc0glN3fMgTIkymMr5W
         qYTQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1740584699; x=1741189499;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-language:from:references:cc:to:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=G19zyjOs/bU3zmh2KcgXnZubJVeCOZlY/rT5dwa0gdE=;
        b=pshYphr2k/FMd/HU5vXZXLRbRM4epFZ1XnpE3DkfBDpdwUhK3Yukk2ZLXPyKF9Npex
         ERRVXeg4PrHRd9BAeQPccJpAWNyMLszuyibvWdZb9W3GSWVcItG4LyEVbtWogX3E3kTP
         YAjO/Yf8bnr8TuJIgAdXtqucH1DwuCRQzNltnEuiAatrAacJqEmauOjXkyHfv+SAqh5Y
         B0NfygSIBayXFjfK5M6GZ13PxOhQulhfJamOyQcoebifE67jjLGYodAlAV3+7TKss0QX
         MY3vLDtDrYtXwJX7ut0G11XYVEZMkIpfuCZA5SEhHJrgVDBbyxtcVxyH8ZNd6vPxvVnH
         g/4g==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCW3sZHi/PkS1i5zqfp8tnj7oEpi4e3MP+GSJ50qu1QNCByRKFIQrOq61fg6282/0JlwSmEsIA==@lfdr.de
X-Gm-Message-State: AOJu0YyyHWzzp9A/0h3Yk7laiShbn1FRMPyYbYB/bWeHcMESQvidJLO7
	YnDtQpT3rwoJY73DN7bgQIQs5UfJjwqysszCJyAZJEOr0a6M3E/U
X-Google-Smtp-Source: AGHT+IE6N8v8YBNYKYejtNNyJbXZFIJI0Pi/BAKzVJpJ4FBJbXfWTpJMwkP+oMpvKFOKU9BBKZ7N5A==
X-Received: by 2002:a05:600c:3d19:b0:43a:b186:8abc with SMTP id 5b1f17b1804b1-43ab1868ac3mr79082255e9.2.1740584698389;
        Wed, 26 Feb 2025 07:44:58 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h=Adn5yVGBwUG52vA9NASBoj80Gb1ZoGUqZTSGfPq1hDsX1rNtiA==
Received: by 2002:a05:600c:19c6:b0:439:8439:5720 with SMTP id
 5b1f17b1804b1-43ab12dca90ls9972245e9.2.-pod-prod-05-eu; Wed, 26 Feb 2025
 07:44:56 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWW+h8/7h5L0Ex5rczxzx/fye+qWOzqPnyQZ3hlNnm+Fay1CVQROtmrQKDfha/itbiIeKEmhx7Qx2s=@googlegroups.com
X-Received: by 2002:a05:6000:1a86:b0:38c:5bc1:1f03 with SMTP id ffacd0b85a97d-390cc5f584dmr7515419f8f.7.1740584696037;
        Wed, 26 Feb 2025 07:44:56 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1740584696; cv=none;
        d=google.com; s=arc-20240605;
        b=EIMYkscGglCAu9S+9Vzzj4zaVZAHVbJgTccIkGoCqS8uMf/WkRv9ULvMogJpXnVLAW
         Cq9+5A24AfLLmYo+eTZzj/F6yDBcQbKc+kBzri2yFrDWQ87W9BdgzgGkw80YULIgBLD/
         hr9yaMDOaU/mcGRsxXgX496l40w2JI5OhmRRqUcbQXGgXU7SyiavmcMvKCPq0YGntoG4
         cgGPkbrofperwwRaxkzWeslmha96MbSA1z3ZUNeSC8gAg/+BCLjimdgguAXYk3Rs8H07
         rXeGlO5K0STNaHDRK/23BPKJ+WS2Z6n7UmdOxF8EuUZAt6YWlWd7GIDhlXMor6lVT/6H
         kUMQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:content-language:from
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature:dkim-signature:dkim-signature;
        bh=WT/e1NPqFVPRk0VeexpY3gu2bFX/ah2sTyCgZLZp0Ds=;
        fh=TPoXuV27OLbOhYz7xCVjlReilBuLfp/WWh5zLcJHusM=;
        b=INCJYix3u6XIBWy0DeutCEZqV42YdlGVe19W8fI41wmNyVzhXkVIT8YdqdIuYFw+kU
         5ibE5ODZgKXAK+MHUAyGs65l5oUxgk/xydauW2lEex4/Nt4LpAmkGM/D9fChr7T7RTCK
         lQ9VfuVDP3xugR1Q/dpyYn8P53WOkoixsRnlV+trd9BJZLw4elmW+NkAt3o1Dstjtx88
         HwJIMDB5PqTLCVryzvR2WTkRLinfMeupSeHTc56GI8z82rIHtDnlvSaBmc2u5WqEbWa6
         f+DTd5SOx/ccC+cCo0m5xf4C9ho6kWJkBTB6mUx8TJv0aoVCHYTuzj04OGU32uSb89iM
         whSg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=YkCGpM5I;
       dkim=neutral (no key) header.i=@suse.cz;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=YkCGpM5I;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [195.135.223.131])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-390cd8d7368si160335f8f.3.2025.02.26.07.44.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 26 Feb 2025 07:44:55 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted sender) client-ip=195.135.223.131;
Received: from imap1.dmz-prg2.suse.org (imap1.dmz-prg2.suse.org [IPv6:2a07:de40:b281:104:10:150:64:97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id 23D841F387;
	Wed, 26 Feb 2025 15:44:55 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id 0020413A53;
	Wed, 26 Feb 2025 15:44:54 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id xn9bO/Y2v2e0XwAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Wed, 26 Feb 2025 15:44:54 +0000
Message-ID: <8899bfa5-bd8b-4d34-a149-40f30d12cb1e@suse.cz>
Date: Wed, 26 Feb 2025 16:46:38 +0100
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
References: <2811463a-751f-4443-9125-02628dc315d9@suse.cz>
 <Z7xbrnP8kTQKYO6T@pc636> <ef97428b-f6e7-481e-b47e-375cc76653ad@suse.cz>
 <Z73p2lRwKagaoUnP@kbusch-mbp>
 <CAOSXXT6-oWjKPV1hzXa5Ra4SPQg0L_FvxCPM0Sh0Yk6X90h0Sw@mail.gmail.com>
 <Z74Av6tlSOqcfb-q@pc636> <Z74KHyGGMzkhx5f-@pc636>
 <8d7aabb2-2836-4c09-9fc7-8bde271e7f23@suse.cz> <Z78lpfLFvNxjoTNf@pc636>
 <93f03922-3d3a-4204-89c1-90ea4e1fc217@suse.cz> <Z782eoh-d48KXhTn@pc636>
From: Vlastimil Babka <vbabka@suse.cz>
Content-Language: en-US
In-Reply-To: <Z782eoh-d48KXhTn@pc636>
Content-Type: text/plain; charset="UTF-8"
X-Rspamd-Queue-Id: 23D841F387
X-Spam-Score: -3.01
X-Rspamd-Action: no action
X-Spamd-Result: default: False [-3.01 / 50.00];
	BAYES_HAM(-3.00)[100.00%];
	SUSPICIOUS_RECIPS(1.50)[];
	NEURAL_HAM_LONG(-1.00)[-1.000];
	R_DKIM_ALLOW(-0.20)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	NEURAL_HAM_SHORT(-0.20)[-1.000];
	MIME_GOOD(-0.10)[text/plain];
	MX_GOOD(-0.01)[];
	TO_MATCH_ENVRCPT_ALL(0.00)[];
	FUZZY_BLOCKED(0.00)[rspamd.com];
	FREEMAIL_TO(0.00)[gmail.com];
	DKIM_SIGNED(0.00)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	MIME_TRACE(0.00)[0:+];
	ARC_NA(0.00)[];
	FREEMAIL_ENVRCPT(0.00)[gmail.com];
	RCVD_TLS_ALL(0.00)[];
	RCPT_COUNT_TWELVE(0.00)[29];
	RCVD_COUNT_TWO(0.00)[2];
	FROM_EQ_ENVFROM(0.00)[];
	FROM_HAS_DN(0.00)[];
	FREEMAIL_CC(0.00)[gmail.com,kernel.org,joelfernandes.org,joshtriplett.org,linux.com,google.com,goodmis.org,efficios.com,inria.fr,zx2c4.com,linux-foundation.org,linux.dev,kvack.org,vger.kernel.org,googlegroups.com,lists.infradead.org,debian.org];
	MID_RHS_MATCH_FROM(0.00)[];
	RCVD_VIA_SMTP_AUTH(0.00)[];
	TAGGED_RCPT(0.00)[];
	DKIM_TRACE(0.00)[suse.cz:+];
	R_RATELIMIT(0.00)[to_ip_from(RLctujmen6hjyrx8fu4drawbuj)];
	TO_DN_SOME(0.00)[]
X-Rspamd-Server: rspamd1.dmz-prg2.suse.org
X-Spam-Flag: NO
X-Spam-Level: 
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=YkCGpM5I;       dkim=neutral
 (no key) header.i=@suse.cz;       dkim=pass header.i=@suse.cz
 header.s=susede2_rsa header.b=YkCGpM5I;       dkim=neutral (no key)
 header.i=@suse.cz;       spf=pass (google.com: domain of vbabka@suse.cz
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

On 2/26/25 4:42 PM, Uladzislau Rezki wrote:
> On Wed, Feb 26, 2025 at 03:36:39PM +0100, Vlastimil Babka wrote:
>> On 2/26/25 3:31 PM, Uladzislau Rezki wrote:
>>> On Wed, Feb 26, 2025 at 11:59:53AM +0100, Vlastimil Babka wrote:
>>>> On 2/25/25 7:21 PM, Uladzislau Rezki wrote:
>>>>>>
>>>>> WQ_MEM_RECLAIM-patch fixes this for me:
>>>>
>>>> Sounds good, can you send a formal patch then?
>>>>
>>> Do you mean both? Test case and fix? I can :)
>>
>> Sure, but only the fix is for stable. Thanks!
>>
> It is taken by Gregg if there is a Fixes tag in the commit.
> What do you mean: the fix is for stable? The current Linus
> tree is not suffering from this?

I just meant the fix should be a Cc: stable, and the testcase not.
mm/ has an exception from "anything with Fixes: can be taken to stable"

> 
> --
> Uladzislau Rezki

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/8899bfa5-bd8b-4d34-a149-40f30d12cb1e%40suse.cz.
