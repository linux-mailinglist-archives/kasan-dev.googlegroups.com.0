Return-Path: <kasan-dev+bncBDXYDPH3S4OBBCM5UO2QMGQEZMD4P6Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33f.google.com (mail-wm1-x33f.google.com [IPv6:2a00:1450:4864:20::33f])
	by mail.lfdr.de (Postfix) with ESMTPS id B377F941077
	for <lists+kasan-dev@lfdr.de>; Tue, 30 Jul 2024 13:29:14 +0200 (CEST)
Received: by mail-wm1-x33f.google.com with SMTP id 5b1f17b1804b1-4280ec27db9sf2258335e9.1
        for <lists+kasan-dev@lfdr.de>; Tue, 30 Jul 2024 04:29:14 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1722338954; cv=pass;
        d=google.com; s=arc-20160816;
        b=lONdMLO3Ke/+L3B842YtPQyORyPJy/1KqDkaYVFv1eSTI/m2Xf5ozaVmsGXKzWVjom
         UYx7AVYtGD7ylN5bGDlXEMGrucUBn7TOBeesXCz5C1SrtSbdw/3e/c/S1AgdNXMIVRTi
         3jMg4NtuSiBg2YmEw8AYJcUOwrpHL7Bseb2LVKZbEcgiNOKD153LUsYg1ylP1W+r4BtW
         FrQLGAi1YAoNcLZI9XyGLalbyWfzpp4YvfDCHCezhLT0Fn2fLNT5Z+3kFrKv+bbjAyjq
         bTVPhEgaGGaJUD1lA9G6KVf8QCahkDrnUwAn/Z27CZ2YS7qqk8NWdyykY3KSG3JmG8Yv
         KRDQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-language:from
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=CwWTznRCGGeMZOx5r2j907sbOJkWFMH3IVzJAtn9SiU=;
        fh=RoSk/hVujVs+shNQsI6szKXB2omaXwr+Zkh1y6MHSPo=;
        b=yyirCG0B13CAbVdUjsYb8n8mRpy4fic1POQJLbI6uzf41zsNxkY2zOdCl/7zRLfEbk
         UmY7CbZh1ca+nKrfBNN0oPYqH98cVwnPJwDvMF1hoF8L3m/XRWqSxqVckLI1NQnGzxOY
         3hhyCi9GvpZwn2/E1Ojtcq+L6cuNXx9FAvXB7ChwLuKRjldhWReC/ap7uUCaBQr3ZjKp
         n9AMxfwSxfd/sxFoH0dRyiee3SiR6hFhx+Uul4Xsx6MfJoyUHAqaIx9kdbm+suQLs7jY
         3zSBod05i2OvDxdTeSVVor0s82ocIZyhBGZVyXpE6Fx5b8CAfQMziLxdKtk3n1rbVvP7
         Ec1Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b="s8W1W/8Q";
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=0Zoogdzg;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1722338954; x=1722943754; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-language:from:references:cc
         :to:subject:user-agent:mime-version:date:message-id:sender:from:to
         :cc:subject:date:message-id:reply-to;
        bh=CwWTznRCGGeMZOx5r2j907sbOJkWFMH3IVzJAtn9SiU=;
        b=Xp5rfNiYGvf/y/e2pUC/+SWGk0K6FUIaNbfuMWr/Fr5HwhRReZ7AhszxDhCqDETuNh
         g9CdzcVf+DTGptfN/vis3aB4b1tPOFCgchGm8NGRk8re7bAvcdDPNxxrD9fCO3naHNtS
         +es8n9mT+iZhO4Z5dwZa2sIZPwppRizjgiL4cdrCZvwGMgY7lSQ3DhmJGW3YHNT1JsGA
         4hSKcCzAcV9pj67HRoB9Vi4rtBBsQmnhwaPr/sbgJTJdFO0RDf0Lq3HrnOg2Mssz+5r/
         OieXCWyvHTSdQFxkYzvLFXEf6AXZdvb6QgVJ/KFgtA5phSFLVlJx9BfcjMzQ9M+TS7W4
         4iPQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1722338954; x=1722943754;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-language:from:references:cc:to:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=CwWTznRCGGeMZOx5r2j907sbOJkWFMH3IVzJAtn9SiU=;
        b=vSJtK0somRg0DNrulIP/E2APLeG5GL5K6Gc+LKFnqchaJJ0r145KhsU9s6GRqcKfBf
         hjnCWR6rN+3Klb6P1sarc2LTsjIUyEES7UBiVqG750dRn97Nk3QJKylAyx1S47MyWH6v
         Q4/bL6ZO4WreSsTH7qCd/Qm8qqp9fyYxmgzJRATTI4m5hj1N+X96aMzFSy+MY0jxVjud
         O2kxV0nGGyPSujaVZODC6pe6ImZ1mcw1nmpT5tmNr9h4kdriYjoq7RpRR2tw5DbFWz3K
         OxDjvkx85eoo2FDqabp7Z65X7FzB5Fzhc2LX7yKScU5rEatlml27dYD+88FziG2z7jh6
         dlCQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXAoY/UYM85ofz29sg8QokPyC5KlBhlA4ugqca3mtRVjVPg9HhHB2CPCZOtGFBSZ2uhnVWjrcA5Qnm33SFlb3VxbBlJ2DEz4g==
X-Gm-Message-State: AOJu0YyQFNB8P1l6ljn1aqHfdnYA5D7WO6lSZ2IVYTiqqMc2gBK2Bqcz
	8dgRBDIzE82TE1kJZd2ev2eqE7Z1qfXpH8jzX9XXY/2dYMn9PFj/
X-Google-Smtp-Source: AGHT+IEC/DUHKAL/W4c3WFJ/HCi8KE8MTAHrmXibycsUSO783od7SaiICSyGaU51cwlYw9yJvefBmQ==
X-Received: by 2002:a05:6000:1a85:b0:367:9495:9016 with SMTP id ffacd0b85a97d-36b34d32d77mr7825377f8f.6.1722338953575;
        Tue, 30 Jul 2024 04:29:13 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:3c86:b0:425:68a1:9da9 with SMTP id
 5b1f17b1804b1-42803b6a203ls26248585e9.2.-pod-prod-09-eu; Tue, 30 Jul 2024
 04:29:11 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWMAgdx//1Rw9/lkb72ZpTW3wtPegDGa8pJW32zXGF387450sG8557jZd2QRnxgTpTrno1Ppbsdr6Mf+Aba0p7ndJ4sOlCYgxoDzw==
X-Received: by 2002:adf:e781:0:b0:367:9803:bfe7 with SMTP id ffacd0b85a97d-36b5d0c2263mr7709603f8f.53.1722338951605;
        Tue, 30 Jul 2024 04:29:11 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1722338951; cv=none;
        d=google.com; s=arc-20160816;
        b=nAKOJftHha/35pEtvDzdq7wgt5Yvz7Ujb0MSr3hCB9ax1I14hXtLyCQj2b0gfrefWr
         QzW4G3Zsz90/UsbZTow3s1PMr/+5KYz+d/3PKb4fARfK/uMk4sgfgzJJ6/RaQ+5q3u7N
         FiZbHQBRq8bIlgTaOvFo4BQSgip94HRVZJt9E5sb0vu7vtjIlmGd09WhzXoZ70kHbav9
         t5DLZEEZYlYgk7x3Qem0X/0rg/kxKUAvH3AuXRXU0SsLCdtj0VaRGhT8EN/OguCLMFb4
         1Iw1V9+ocBvN4jr2f0h4X42S+1RfrWPZ2t7z7//cro0k55tS2dO5PTxjljwyPAvznBUh
         8HsQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:content-language:from
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature:dkim-signature:dkim-signature;
        bh=EbSJA06fsKgiWYVag+Rs2XVRflnFRhGU36M+hqCROpI=;
        fh=HmT76vcs+zO1ZG5U/D+utUyYOLBDzdTx2ZsGVz/wSR0=;
        b=bvRNQPb7uRwpgITkoCSyyyxvwmlLXEVgW+DEvF3QCaeMHg4sKM00n4uw5S7NsnvZ5b
         9fZFraEsfcgZpt1oR2LDvSaQwe45fjfsatN9TnTtFI6wBGeMZ0IRi0HH2lkEYtmGh8kv
         dGqyfuOFS0ujFmRM94Zz8OBoOF6cmJ5sgjeU46U422LsibZPT8N8+19iYntP14vM2hmM
         V+r3fUSmB3NzRTOPm7Dbo6weV5wgl/gYK4JDAlNwN/qL0pdWOBiKF1c8Krc1Qbfyfcjs
         y8G6dEa21JHeMYQuIESaImYbMlTljeKZsb84nCta+rMFZmEn9DqZSLgDvrgUpFgw9lOZ
         akyA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b="s8W1W/8Q";
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=0Zoogdzg;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [2a07:de40:b251:101:10:150:64:2])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-36b8f5e65e1si19307f8f.0.2024.07.30.04.29.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 30 Jul 2024 04:29:11 -0700 (PDT)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) client-ip=2a07:de40:b251:101:10:150:64:2;
Received: from imap1.dmz-prg2.suse.org (imap1.dmz-prg2.suse.org [IPv6:2a07:de40:b281:104:10:150:64:97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id E9EFD1F7EB;
	Tue, 30 Jul 2024 11:29:09 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id CE01813983;
	Tue, 30 Jul 2024 11:29:09 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id j0SsMYXOqGZ6NwAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Tue, 30 Jul 2024 11:29:09 +0000
Message-ID: <6ae22d49-7dfd-44d4-8720-fd2903a05fee@suse.cz>
Date: Tue, 30 Jul 2024 13:30:47 +0200
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v5 2/2] slub: Introduce CONFIG_SLUB_RCU_DEBUG
To: Jann Horn <jannh@google.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>,
 Alexander Potapenko <glider@google.com>,
 Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>,
 Vincenzo Frascino <vincenzo.frascino@arm.com>,
 Andrew Morton <akpm@linux-foundation.org>, Christoph Lameter <cl@linux.com>,
 Pekka Enberg <penberg@kernel.org>, David Rientjes <rientjes@google.com>,
 Joonsoo Kim <iamjoonsoo.kim@lge.com>,
 Roman Gushchin <roman.gushchin@linux.dev>,
 Hyeonggon Yoo <42.hyeyoo@gmail.com>
Cc: Marco Elver <elver@google.com>, kasan-dev@googlegroups.com,
 linux-kernel@vger.kernel.org, linux-mm@kvack.org
References: <20240730-kasan-tsbrcu-v5-0-48d3cbdfccc5@google.com>
 <20240730-kasan-tsbrcu-v5-2-48d3cbdfccc5@google.com>
From: Vlastimil Babka <vbabka@suse.cz>
Content-Language: en-US
In-Reply-To: <20240730-kasan-tsbrcu-v5-2-48d3cbdfccc5@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Rspamd-Server: rspamd1.dmz-prg2.suse.org
X-Rspamd-Action: no action
X-Rspamd-Queue-Id: E9EFD1F7EB
X-Spam-Score: -2.80
X-Spam-Level: 
X-Spam-Flag: NO
X-Spamd-Result: default: False [-2.80 / 50.00];
	BAYES_HAM(-3.00)[100.00%];
	SUSPICIOUS_RECIPS(1.50)[];
	NEURAL_HAM_LONG(-1.00)[-1.000];
	R_DKIM_ALLOW(-0.20)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	MIME_GOOD(-0.10)[text/plain];
	XM_UA_NO_VERSION(0.01)[];
	MX_GOOD(-0.01)[];
	DKIM_SIGNED(0.00)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	FUZZY_BLOCKED(0.00)[rspamd.com];
	TO_MATCH_ENVRCPT_ALL(0.00)[];
	RCPT_COUNT_TWELVE(0.00)[17];
	ARC_NA(0.00)[];
	FREEMAIL_TO(0.00)[google.com,gmail.com,arm.com,linux-foundation.org,linux.com,kernel.org,lge.com,linux.dev];
	MIME_TRACE(0.00)[0:+];
	FREEMAIL_ENVRCPT(0.00)[gmail.com];
	RCVD_TLS_ALL(0.00)[];
	RCVD_COUNT_TWO(0.00)[2];
	FROM_EQ_ENVFROM(0.00)[];
	FROM_HAS_DN(0.00)[];
	TO_DN_SOME(0.00)[];
	DNSWL_BLOCKED(0.00)[2a07:de40:b281:104:10:150:64:97:from,2a07:de40:b281:106:10:150:64:167:received];
	TAGGED_RCPT(0.00)[];
	MID_RHS_MATCH_FROM(0.00)[];
	DKIM_TRACE(0.00)[suse.cz:+];
	RCVD_VIA_SMTP_AUTH(0.00)[];
	DBL_BLOCKED_OPENRESOLVER(0.00)[suse.cz:email,suse.cz:dkim]
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b="s8W1W/8Q";
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=0Zoogdzg;
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

On 7/30/24 1:06 PM, Jann Horn wrote:
> Currently, KASAN is unable to catch use-after-free in SLAB_TYPESAFE_BY_RCU
> slabs because use-after-free is allowed within the RCU grace period by
> design.
> 
> Add a SLUB debugging feature which RCU-delays every individual
> kmem_cache_free() before either actually freeing the object or handing it
> off to KASAN, and change KASAN to poison freed objects as normal when this
> option is enabled.
> 
> For now I've configured Kconfig.debug to default-enable this feature in the
> KASAN GENERIC and SW_TAGS modes; I'm not enabling it by default in HW_TAGS
> mode because I'm not sure if it might have unwanted performance degradation
> effects there.
> 
> Note that this is mostly useful with KASAN in the quarantine-based GENERIC
> mode; SLAB_TYPESAFE_BY_RCU slabs are basically always also slabs with a
> ->ctor, and KASAN's assign_tag() currently has to assign fixed tags for
> those, reducing the effectiveness of SW_TAGS/HW_TAGS mode.
> (A possible future extension of this work would be to also let SLUB call
> the ->ctor() on every allocation instead of only when the slab page is
> allocated; then tag-based modes would be able to assign new tags on every
> reallocation.)
> 
> Signed-off-by: Jann Horn <jannh@google.com>

Acked-by: Vlastimil Babka <vbabka@suse.cz> #slab

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/6ae22d49-7dfd-44d4-8720-fd2903a05fee%40suse.cz.
