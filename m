Return-Path: <kasan-dev+bncBDXYDPH3S4OBBOWFTPBAMGQESDWJKCQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x240.google.com (mail-lj1-x240.google.com [IPv6:2a00:1450:4864:20::240])
	by mail.lfdr.de (Postfix) with ESMTPS id 9CB68AD1EF4
	for <lists+kasan-dev@lfdr.de>; Mon,  9 Jun 2025 15:33:48 +0200 (CEST)
Received: by mail-lj1-x240.google.com with SMTP id 38308e7fff4ca-32a6ecca59asf24967161fa.3
        for <lists+kasan-dev@lfdr.de>; Mon, 09 Jun 2025 06:33:48 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1749476028; cv=pass;
        d=google.com; s=arc-20240605;
        b=IPCSFnYHVkU1nnyNgl6DqhmlbZpdTm4oaeJvdvEiQyRwsTEpd17FpUxAJczhXcx2Mi
         CrKPHTecyl9nPFnezfOSmAIy+9cJr8+x9ptvoJqw1ia3Sgo9Py5oVCdNqRCiITFVIxUW
         sMjDA90pNR7LgekD6U+cSVXUF1UGu/NRJX78UDOxgIShdiRwU1HyAJ3LvfBB3z5NqZ+d
         qvuFWfttuBk6+YhTmLrJa41ir6C87dp43LMO3fQfBZ4ZksUjnnisvJZ9/oHwKFTw/GWk
         679BSrHoErfl1IYHNdS7U21gBMFw0HtLZQMnOSSTEa6hHEjiET1miEUYQJitA3pQmvW9
         Vvwg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:autocrypt:from
         :references:cc:to:content-language:subject:user-agent:mime-version
         :date:message-id:sender:dkim-signature;
        bh=pEUTqIo2Ot6E5ct+nxbcqMsInnjEFY4dj7wJxmvITD0=;
        fh=e7BRT+fC9HMekviLqO8FAExgAFZtSkNMhsdUcBDsJhg=;
        b=EFK9t2Yx1bF9jm51AuwPwzs2xyuQcDGhajCfKzwcDhwqO9vgn3laecmwiXzwHaWMMe
         P6fDKwwA/u5dOrW5/FgUP71h4G7RjuU7RnYrQ/6U7zKDhYu/Wk2+t4YT9io8uAQoIBep
         L3XN2lvaw1+FVihE57gIm0X/AViEQM0WdeCg4aQjt3wqUuo/hmP91OU2YISzJ+uzUQIR
         pWaf6CH6ba0qF7yNufocmobiWl3tM73aCddNz8c0S9mCQhWgnuuNTq+UIjWj9g9xcVB4
         PSkVrQ6mZHrHseeWS1aHmqHIAYfkQ1msAetxm6tfov5nbde2B5WHtAqAFoAWr6WbpdK/
         1PAA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=t5Cr9vtk;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=t5Cr9vtk;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1749476028; x=1750080828; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:autocrypt:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=pEUTqIo2Ot6E5ct+nxbcqMsInnjEFY4dj7wJxmvITD0=;
        b=WOPBPiK8qNJbcWmSqLWbyt14ADG1nUuH0mVvIPXlwpdXT9Cl7LReiRvunbOJntbINE
         CoX+nqO9VlvWJGyw/4EJP/ljiVyz2l+R68E33lXhZCGoyk2wmLj+GeOG/08QqmlI+8aa
         p5x0aMvuCiczUiqJpxJWHKkCaBmFmoq7xODqrSj7JoAp6IXo1AZT/PWV5RZkdLpF8zdJ
         e6IShRP/tE+nDUuLPxlS/R4mgoP/DJJwa7aa4PPFwEVAR+qtKhKTDGpPV2HiG7t3L3Kb
         EjSAy20I0vEbBvgl+r7hRYX4+KmJoPUnv1EphS4Y6FU69bU+Nv4FdB0VPEqAknMPjBT+
         UUdg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1749476028; x=1750080828;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :autocrypt:from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=pEUTqIo2Ot6E5ct+nxbcqMsInnjEFY4dj7wJxmvITD0=;
        b=KR8cZIY/vWLAAYtOh6xbhg2iqdmvQTxIuyUKt+2AXqVF/W8PlXkQgxcZGrDQgDTwxA
         I8hueYLHpiSJYIBljz9Yc413PxIo90Wvdk6ntl36uCdlu4Egg/gzQcElZlnNo8tCl9TZ
         JHTeG9S8Ph+/HCANc9HK6srMNjs9eaQP0SpWIn7itlwnjLynXjb1nawqzPEBOpwd/svL
         pVVqtf5AMd6b5/eB9JuyXxCK4+509bGxqiVdGXIZdRIfH59HmvOTVf43NQxGV/2WO1O/
         cV6S4mdJ0l0YUzTndQvR/I5vkuBee4YKeuDGfqjlTTUahj11WxaPFWgIrAOzWZGN7j4n
         OoWg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUVIjtC4UdygfM1OA07nZo1Vb4DU6UUUIFiFIma1ES/kVEKHaBU/rDXC3TQkHvLy/zVlCBptw==@lfdr.de
X-Gm-Message-State: AOJu0Yzr7r0IQBfMbETOw9lyvNWW/qvd8YvAqVLAVnKhvedr08xrYTRg
	BxRlWG6o16FbawWUKCwv66j5vVmszFhJp0gNegos5CTZBfcFO7be/TNx
X-Google-Smtp-Source: AGHT+IE6AluAQ93thT6QQhoadAzO/4PZt3lwxKTJs4/MOwQ9MRwWYAE5xoiNGoDu3CoQgWjxUr8fpw==
X-Received: by 2002:a05:651c:212a:b0:32a:7122:58cc with SMTP id 38308e7fff4ca-32adfd33c45mr29374461fa.6.1749476027215;
        Mon, 09 Jun 2025 06:33:47 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZe4mLl/xUaVrzLDYyxoybFeJgF8SUSr4tlW/XY4g7RjaQ==
Received: by 2002:a2e:b8d1:0:b0:32a:6378:9bc2 with SMTP id 38308e7fff4ca-32ad1ae9dcels14402041fa.1.-pod-prod-06-eu;
 Mon, 09 Jun 2025 06:33:42 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWpAdhGPhio7m8Dpjhtt5CewIKRa/y2Fawr9UEKfFnSwDuQdX05PtnZhapizVRT4Fav8bd6n7ED4iw=@googlegroups.com
X-Received: by 2002:a2e:98d5:0:b0:32a:7e4c:e925 with SMTP id 38308e7fff4ca-32adfdacce7mr28702031fa.21.1749476022555;
        Mon, 09 Jun 2025 06:33:42 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1749476022; cv=none;
        d=google.com; s=arc-20240605;
        b=h/ROz5rDkC6kYQm6dsfOSaPJJt0scQTLtgRFPzN/UIO5Zwrz2GBCb/44TQkgPBPZ0q
         fIi+DtcKRfqF/dzg9GGDfFei1tR+xiX/K+hYQPe37Tq7k+z12khHqJfL3unWQgWfyNr6
         I0W+SrJreBN887YZzB7I8bg1Rq7v0MoZ4k5T/L9e+5P2Xq7+RIdljsMReuwnsGM7crMM
         Au5sJvELz8v15bB38G2PByi6PbQrnfI9kKmAA9CuHpbvNrx1+rXodPSReQQQYInsRrvE
         4ndW1wFIvcI+YP1AtELIupGsO7MYMeaaPlsOVe/VPvnFr0XnJ7/xxrs4Lpq+OypBDwjZ
         I42A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:autocrypt:from:references:cc
         :to:content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature:dkim-signature:dkim-signature;
        bh=DkX43O8ZpyW3PseGvyxGpDMDs1SN5hs29QDdK4x4MgI=;
        fh=9s7fZ0XQbDd7upnIQEsOS1/P+OvF9IkBLZq5DZcQ8T0=;
        b=TJePtNb1RmePdO2UX62GitOKwA2mOp8wP/3uDO0icznHa/j+dHQGOLkTcsyccWH9PF
         AIxt7DzUBlAU/btTt3H1CBEGooXQ4jmMUSbWwRKSd+GIXurIY1k1SbWjuimJ+zA18dYC
         K2wS8ehA/EcxuBjlUrZ/gI/Q7SL8F6gX255lxwXEVE/oyefZzfHaJiELpQxA6JW+ozZY
         qJT59AT3bSQwnyK01xw8osdmzXzKgRrBzdwRgtTlskqMK4NMIaX8dddlogNy030MoTrT
         AVsTjdSxNQOw9fOz/N0BOz3y/ONSac0g0PON6cPo2cBYYdClioD9top7HTV8UOGuFT9K
         aByQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=t5Cr9vtk;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=t5Cr9vtk;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [195.135.223.131])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-32ae1af7968si1647771fa.2.2025.06.09.06.33.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 09 Jun 2025 06:33:42 -0700 (PDT)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted sender) client-ip=195.135.223.131;
Received: from imap1.dmz-prg2.suse.org (unknown [10.150.64.97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id 902A41F38F;
	Mon,  9 Jun 2025 13:33:41 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id 7D3B8137FE;
	Mon,  9 Jun 2025 13:33:41 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id 00ZFHrXiRmjlXwAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Mon, 09 Jun 2025 13:33:41 +0000
Message-ID: <ff370b8b-a33f-47a2-9815-266225e68b8a@suse.cz>
Date: Mon, 9 Jun 2025 15:33:41 +0200
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH 08/10] kfence: Remove mention of PG_slab
Content-Language: en-US
To: "Matthew Wilcox (Oracle)" <willy@infradead.org>
Cc: Christoph Lameter <cl@gentwo.org>, David Rientjes <rientjes@google.com>,
 linux-mm@kvack.org, Harry Yoo <harry.yoo@oracle.com>,
 kasan-dev <kasan-dev@googlegroups.com>,
 Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>
References: <20250606222214.1395799-1-willy@infradead.org>
 <20250606222214.1395799-9-willy@infradead.org>
From: Vlastimil Babka <vbabka@suse.cz>
Autocrypt: addr=vbabka@suse.cz; keydata=
 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
 m6M14QORSWTLRg==
In-Reply-To: <20250606222214.1395799-9-willy@infradead.org>
Content-Type: text/plain; charset="UTF-8"
X-Spamd-Result: default: False [-4.30 / 50.00];
	BAYES_HAM(-3.00)[100.00%];
	NEURAL_HAM_LONG(-1.00)[-1.000];
	NEURAL_HAM_SHORT(-0.20)[-1.000];
	MIME_GOOD(-0.10)[text/plain];
	URIBL_BLOCKED(0.00)[suse.cz:mid,infradead.org:email,imap1.dmz-prg2.suse.org:helo];
	FUZZY_BLOCKED(0.00)[rspamd.com];
	DKIM_SIGNED(0.00)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	ARC_NA(0.00)[];
	TO_MATCH_ENVRCPT_ALL(0.00)[];
	MIME_TRACE(0.00)[0:+];
	FROM_HAS_DN(0.00)[];
	RCVD_TLS_ALL(0.00)[];
	RCVD_VIA_SMTP_AUTH(0.00)[];
	FROM_EQ_ENVFROM(0.00)[];
	TO_DN_SOME(0.00)[];
	RCVD_COUNT_TWO(0.00)[2];
	RCPT_COUNT_SEVEN(0.00)[8];
	MID_RHS_MATCH_FROM(0.00)[];
	DBL_BLOCKED_OPENRESOLVER(0.00)[infradead.org:email,suse.cz:mid]
X-Spam-Level: 
X-Spam-Flag: NO
X-Spam-Score: -4.30
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=t5Cr9vtk;       dkim=neutral
 (no key) header.i=@suse.cz header.s=susede2_ed25519;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=t5Cr9vtk;       dkim=neutral
 (no key) header.i=@suse.cz;       spf=pass (google.com: domain of
 vbabka@suse.cz designates 195.135.223.131 as permitted sender) smtp.mailfrom=vbabka@suse.cz
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

On 6/7/25 00:22, Matthew Wilcox (Oracle) wrote:
> Improve the documentation slightly, assuming I understood it correctly.

Assuming I understood it correctly, this is going to be fun part of
splitting struct slab from struct page. It gets __kfence_pool from memblock
allocator and then makes the corresponding struct pages look like slab
pages. Maybe it will be possible to simplify things so it won't have to
allocate struct slab for each page...

> Signed-off-by: Matthew Wilcox (Oracle) <willy@infradead.org>
> ---
>  mm/kfence/core.c | 4 ++--
>  1 file changed, 2 insertions(+), 2 deletions(-)
> 
> diff --git a/mm/kfence/core.c b/mm/kfence/core.c
> index 102048821c22..0ed3be100963 100644
> --- a/mm/kfence/core.c
> +++ b/mm/kfence/core.c
> @@ -605,8 +605,8 @@ static unsigned long kfence_init_pool(void)
>  	pages = virt_to_page(__kfence_pool);
>  
>  	/*
> -	 * Set up object pages: they must have PG_slab set, to avoid freeing
> -	 * these as real pages.
> +	 * Set up object pages: they must have PGTY_slab set to avoid freeing
> +	 * them as real pages.
>  	 *
>  	 * We also want to avoid inserting kfence_free() in the kfree()
>  	 * fast-path in SLUB, and therefore need to ensure kfree() correctly
	

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/ff370b8b-a33f-47a2-9815-266225e68b8a%40suse.cz.
