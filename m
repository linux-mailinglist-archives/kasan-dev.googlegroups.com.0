Return-Path: <kasan-dev+bncBCO3JTUR7UBRBNV32SWAMGQEJMPWS3Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x238.google.com (mail-lj1-x238.google.com [IPv6:2a00:1450:4864:20::238])
	by mail.lfdr.de (Postfix) with ESMTPS id AE2D3822991
	for <lists+kasan-dev@lfdr.de>; Wed,  3 Jan 2024 09:41:28 +0100 (CET)
Received: by mail-lj1-x238.google.com with SMTP id 38308e7fff4ca-2cc83b19edesf80983771fa.1
        for <lists+kasan-dev@lfdr.de>; Wed, 03 Jan 2024 00:41:28 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1704271288; cv=pass;
        d=google.com; s=arc-20160816;
        b=yrb80zUIr/VtNMxw2jc1gczLbVxb5dIeaPGwvf2DcZPa/OXFNs8z5001+6crAw1Qj1
         Ab0Im0ZY7yHBm486FfosfeVLpx4A1/wutyxrr0PNuF7bkk8GpcwAs51inKe27hxVZcNe
         0AOR9iP8eO0bZKfyw2g1y2dL1kJBeQ7gvnX9K1vo+ruoGxMdAL3e0zLC8P2mSP98Ta2o
         oAXjJUWnQ5jfWQ6ouTD/4Ym6vP13Tea1AKn3BEXERXMVyllaRk0owlRoUMAyxWjpb1fB
         Y4ijXx5jd/t4mjyJ+1YyPbqeH866x1lduyE4Gk3w4jQTVGkJfg3IcQ6LiEtyTx3LDwKR
         1IyQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=/abQcnlsa7s8LS3iKiYX/MoK/3bFXQ2dVu8iav03Btc=;
        fh=uYnjiVNxbW5kI0u75v8U/Y/ao7NQ4m8EfWg99NPaynw=;
        b=oV/fSfPqlu6mRrYQl4ctQT2DIFeXxily/binnZvobAP66liUQo69W56X1JcR7HFdhS
         0PkeNWhCwlsnKLbIesPD4oiG+RUyiyMgYMMeUwGmHkl65JRZOTiGI5PymNyMRTcaQIBt
         RIuFXY8kRSr7JqSHRYeBXPhD4rEUfIWRw0GI2pczX56H4iY7/6rXP+hPgkFJ1/SDcPIK
         IraezkgYy8mhmrOMzQdgh/V145BIhL7FPGnDdAZzTSx77TM4dqik/LICMtC6V0fN0voJ
         c+ZYKWq754TpcfHmeNiwFW2W9hliki6UxDj7aVuS645cUVnECuH/IOuGssgJ5gd3Dt6w
         qIaw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.de header.s=susede2_rsa header.b=ucZdsDp3;
       dkim=neutral (no key) header.i=@suse.de;
       dkim=pass header.i=@suse.de header.s=susede2_rsa header.b="Ma2sj/R5";
       dkim=neutral (no key) header.i=@suse.de header.s=susede2_ed25519;
       spf=pass (google.com: domain of osalvador@suse.de designates 195.135.223.130 as permitted sender) smtp.mailfrom=osalvador@suse.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=suse.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1704271288; x=1704876088; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=/abQcnlsa7s8LS3iKiYX/MoK/3bFXQ2dVu8iav03Btc=;
        b=DHD6NbyToUbQpigE581JRcCYrcOt4BfciShve9KqOJDbUPhfULs2DUrd0cDY1Y885z
         bYZb+F0gEAtBBOiVLDC7CLCbCEXccTdMFr9qcvaRDYzWTfWIls83f8Lo3c7IUn0/G9GZ
         QbBhaNXiPhFa+4d/lRvCrRkTg5C0aZd5Ddl8ftXuFojg/mb3nslts6hco1CqW/2BGRmF
         i1WMqYto0RMLdjUNJeVnWBtwIVPZIqfGVHSsktbD1Gby8zfbXA31P29prLhfYisCWn3M
         4Yh82Etkfclv2w6SH2S3QEyD0Vn8vXFbOWOyg18rONArDWT3Xn1Leu/aGiVnUcCaETaa
         fKwg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1704271288; x=1704876088;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=/abQcnlsa7s8LS3iKiYX/MoK/3bFXQ2dVu8iav03Btc=;
        b=Ie1RiT9CtZ6JwUF9GL6GHuCYEfmCapQ/kMxMXHvE38QcLsxf1uMaYgp7DNan0hamUw
         80YzV+syEsW17SkrpM+XMnQ7PN2s2pVNteSck66WKvrStc3X3JGerkDde3gglsX58YY4
         /bmoXNAoONgRFbpoQ5FVkSbfzGOH/vXdgbYW/U6wA6fp9cmt3ALk3TE0o4XpVdmlA/Jy
         lUjn7/DaI5r6SRaBI7JlGG7tmLcSCCXFqKt46osQLPYUYi8qz1qZBK1lU6A8r4eqEcD5
         d+XNozJb1k0B/M8lqI5dvFrn9w5pU63afzui5uGmxk2hnjA4OPA65kLp10LA0emH1EYf
         eXWw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yy1eWjCKqfoWQYM1VOaPKGSdCDa8fd0KA19lNcrdZ0JDZzW4ZiS
	9inSatOJkqsIGa4A8qO/sCs=
X-Google-Smtp-Source: AGHT+IHu2ATCulnqjSD0iQ788Js4zx0UjAR4uIz7ClC7EeY5sl7x5DYEricGO0pcTX7BwQPaZTzd/Q==
X-Received: by 2002:a2e:9787:0:b0:2cc:b51b:239d with SMTP id y7-20020a2e9787000000b002ccb51b239dmr7966301lji.66.1704271286742;
        Wed, 03 Jan 2024 00:41:26 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:bc04:0:b0:2cd:d0c:af0e with SMTP id b4-20020a2ebc04000000b002cd0d0caf0els582077ljf.2.-pod-prod-09-eu;
 Wed, 03 Jan 2024 00:41:25 -0800 (PST)
X-Received: by 2002:a05:6512:3096:b0:50e:9d70:b7aa with SMTP id z22-20020a056512309600b0050e9d70b7aamr1803126lfd.1.1704271284828;
        Wed, 03 Jan 2024 00:41:24 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1704271284; cv=none;
        d=google.com; s=arc-20160816;
        b=cIEaNsKcilvE0xPo8Dx9nTVnTWICQ6WHu2E5mqJNAyyxxtrnjxghtZXTQdbBpSHMEF
         Xulw8sJeKWbFTdMKNRuq/zU0J+WrRuPM7nnc6DVyoh99afQHXrHcGFvbz3bS3Zqec+N6
         HEtUqGrkXKqHKB1y+Yf+eFSFIUfAfphId8jajz2Mf46vRYjGt3BEUt88uOmTkyd8ZnRD
         aXJqQ4onLpCNK/CeSFl38Lm2GuQicxMQh1EBIHMiQkwKqWykVRCnZiNeugBDga51NEG1
         ynNCHUG5eZE1H/Ojh7l2A8d6iLD1nQ0FSl5c1aNvSonTNx8fUPc3QEFKnIaBsq98FZ+2
         JpiQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature:dkim-signature
         :dkim-signature:dkim-signature;
        bh=KSXZ40//AYfGpTVhrABXJB2R3UQrzV4ODHYRuNkyzfE=;
        fh=uYnjiVNxbW5kI0u75v8U/Y/ao7NQ4m8EfWg99NPaynw=;
        b=Ff/p9Bg/gwJJAaAnJkxqajWfBR9IxtFj7iRITPwfxyza+HuHvv6zR5jcXXHRbhhYHn
         B/eL7yiUXLQOPpGubi8no7vBAAzEjGXdu13hUomh3CEald5He3V9NGsZ56aHGVILKdV4
         wT9M8XFamM+eJGyGMMfN7a5tRYHB9bYPgvqEdvhykJFt3WyJ2cyNddOUIv2ByN8FZfRq
         K5SM5kXOX/BqzShliSw+eac0nz3Wge4MsbMtzCUv2QQUTSUc3AUWmr+Hv3XOCuLRQihl
         tIF+MVVq/ilLr9gagBEtbfqkz8SxWU4CGMBuarR+6XPEB3SJjp7hl04MyLygbxH9Ax7Z
         PYHA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.de header.s=susede2_rsa header.b=ucZdsDp3;
       dkim=neutral (no key) header.i=@suse.de;
       dkim=pass header.i=@suse.de header.s=susede2_rsa header.b="Ma2sj/R5";
       dkim=neutral (no key) header.i=@suse.de header.s=susede2_ed25519;
       spf=pass (google.com: domain of osalvador@suse.de designates 195.135.223.130 as permitted sender) smtp.mailfrom=osalvador@suse.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=suse.de
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [195.135.223.130])
        by gmr-mx.google.com with ESMTPS id t3-20020a195f03000000b0050e6b19b855si1249333lfb.11.2024.01.03.00.41.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 03 Jan 2024 00:41:24 -0800 (PST)
Received-SPF: pass (google.com: domain of osalvador@suse.de designates 195.135.223.130 as permitted sender) client-ip=195.135.223.130;
Received: from imap1.dmz-prg2.suse.org (imap1.dmz-prg2.suse.org [IPv6:2a07:de40:b281:104:10:150:64:97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id 2005621EE8;
	Wed,  3 Jan 2024 08:41:22 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id 674AC1340C;
	Wed,  3 Jan 2024 08:41:21 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id 8W8DFrEdlWXVYQAAD6G6ig
	(envelope-from <osalvador@suse.de>); Wed, 03 Jan 2024 08:41:21 +0000
Date: Wed, 3 Jan 2024 09:42:12 +0100
From: Oscar Salvador <osalvador@suse.de>
To: andrey.konovalov@linux.dev
Cc: Andrew Morton <akpm@linux-foundation.org>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com,
	Evgenii Stepanov <eugenis@google.com>, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: Re: [PATCH v4 08/22] lib/stackdepot: rework helpers for
 depot_alloc_stack
Message-ID: <ZZUd5HWJONcLKRzJ@localhost.localdomain>
References: <cover.1700502145.git.andreyknvl@google.com>
 <71fb144d42b701fcb46708d7f4be6801a4a8270e.1700502145.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <71fb144d42b701fcb46708d7f4be6801a4a8270e.1700502145.git.andreyknvl@google.com>
X-Spam-Level: 
X-Rspamd-Server: rspamd1.dmz-prg2.suse.org
X-Spam-Level: 
X-Spamd-Bar: /
X-Spam-Flag: NO
X-Spamd-Result: default: False [-0.31 / 50.00];
	 ARC_NA(0.00)[];
	 RCVD_VIA_SMTP_AUTH(0.00)[];
	 R_DKIM_ALLOW(-0.20)[suse.de:s=susede2_rsa,suse.de:s=susede2_ed25519];
	 FROM_HAS_DN(0.00)[];
	 TO_DN_SOME(0.00)[];
	 FREEMAIL_ENVRCPT(0.00)[gmail.com];
	 TO_MATCH_ENVRCPT_ALL(0.00)[];
	 MIME_GOOD(-0.10)[text/plain];
	 RCVD_COUNT_THREE(0.00)[3];
	 DKIM_SIGNED(0.00)[suse.de:s=susede2_rsa,suse.de:s=susede2_ed25519];
	 DKIM_TRACE(0.00)[suse.de:+];
	 MX_GOOD(-0.01)[];
	 RCPT_COUNT_TWELVE(0.00)[12];
	 DBL_BLOCKED_OPENRESOLVER(0.00)[linux.dev:email,suse.de:dkim,suse.de:email];
	 FUZZY_BLOCKED(0.00)[rspamd.com];
	 FROM_EQ_ENVFROM(0.00)[];
	 MIME_TRACE(0.00)[0:+];
	 FREEMAIL_CC(0.00)[linux-foundation.org,gmail.com,google.com,suse.cz,googlegroups.com,kvack.org,vger.kernel.org];
	 RCVD_TLS_ALL(0.00)[];
	 RBL_SPAMHAUS_BLOCKED_OPENRESOLVER(0.00)[2a07:de40:b281:104:10:150:64:97:from]
X-Spam-Score: -0.31
X-Rspamd-Queue-Id: 2005621EE8
X-Original-Sender: osalvador@suse.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.de header.s=susede2_rsa header.b=ucZdsDp3;       dkim=neutral
 (no key) header.i=@suse.de;       dkim=pass header.i=@suse.de
 header.s=susede2_rsa header.b="Ma2sj/R5";       dkim=neutral (no key)
 header.i=@suse.de header.s=susede2_ed25519;       spf=pass (google.com:
 domain of osalvador@suse.de designates 195.135.223.130 as permitted sender)
 smtp.mailfrom=osalvador@suse.de;       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=suse.de
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

On Mon, Nov 20, 2023 at 06:47:06PM +0100, andrey.konovalov@linux.dev wrote:
> From: Andrey Konovalov <andreyknvl@google.com>
> 
> Split code in depot_alloc_stack and depot_init_pool into 3 functions:
> 
> 1. depot_keep_next_pool that keeps preallocated memory for the next pool
>    if required.
> 
> 2. depot_update_pools that moves on to the next pool if there's no space
>    left in the current pool, uses preallocated memory for the new current
>    pool if required, and calls depot_keep_next_pool otherwise.
> 
> 3. depot_alloc_stack that calls depot_update_pools and then allocates
>    a stack record as before.
> 
> This makes it somewhat easier to follow the logic of depot_alloc_stack
> and also serves as a preparation for implementing the eviction of stack
> records from the stack depot.
> 
> Reviewed-by: Alexander Potapenko <glider@google.com>
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

I have to say this simplifies the reading quite a lot.

Reviewed-by: Oscar Salvador <osalvador@suse.de>


-- 
Oscar Salvador
SUSE Labs

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ZZUd5HWJONcLKRzJ%40localhost.localdomain.
