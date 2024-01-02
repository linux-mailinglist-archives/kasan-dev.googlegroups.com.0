Return-Path: <kasan-dev+bncBDXYDPH3S4OBBD7L2CWAMGQEAQGNLWI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33c.google.com (mail-wm1-x33c.google.com [IPv6:2a00:1450:4864:20::33c])
	by mail.lfdr.de (Postfix) with ESMTPS id 25B02821F44
	for <lists+kasan-dev@lfdr.de>; Tue,  2 Jan 2024 17:10:57 +0100 (CET)
Received: by mail-wm1-x33c.google.com with SMTP id 5b1f17b1804b1-40d45be1ce2sf45884095e9.1
        for <lists+kasan-dev@lfdr.de>; Tue, 02 Jan 2024 08:10:57 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1704211856; cv=pass;
        d=google.com; s=arc-20160816;
        b=HiCw/ei2iSe8Z/GLUV7kRgAAGvQMAkiJwPAYjMes+33vOOK8/iCUTY/2sIZ39AUHnE
         0AZM971ALtlY4VtKG+iSixmB0OmvWVASA68dHEPE3+yollPb9vOsNZPA4xHV4QSPRtBy
         W6VW7VaO4WU39dr1Mq+wnG8g3YrKKYpI90YsCJ8EjpcznFkevRsp+koIT2d4R0qsIYi9
         tYCXaq5fNh0XWc0o2mjGyypBXOdDMseewm1xrQ6XR+VcEoGMna9i1P592xTuf/SvmB6R
         4rVCchgpBmviLCY1LAUvgMs7Gd4Vu7sMvVlOxFfSUoCI9rAOasNKT36B4FJ+hCEIwRjy
         NonQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=1rpG4lzQDsBNsz8uBvv7/teFKEdbiLmAKFVAlrGT/0o=;
        fh=gtwm6qN9lskLrXqGcgQSmKN+lN7yfNQhDGa14RKei7M=;
        b=nG06iq7O2r9dGcLISj4sOE66mwlwbsznxeLajRuS1Y/J48GY1U0BGFUI4Q+nYBQmOQ
         Rg55CH8lPqqUaY6B0D8j0HoelwaWljN5XbfjTFk2TfBi/utkiXEGF4iLDd9O+Zo+Fv56
         FZDrf4u6+qRFc5jzeZtGzxz/AhyCDlRqSi5giTdZEUHuBBJXfFKDunYRBD3CL14pu48+
         t25bh1QBbvbKQMUoPkr6HqT/F5PjpfxVeqYomxwtFhUfZjbvZTwAGSCgQ3xzWmVICfwq
         R/PBv08lqTc0y1AO2k/zQ2pbYx4uEmyXmUTAekrgne/pWA0Xlf0O6pNY1Q+g9bvwFss9
         UWew==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=qjgwENPJ;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=1QTZh1Yz;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=qjgwENPJ;
       dkim=neutral (no key) header.i=@suse.cz header.b=1QTZh1Yz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.130 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1704211856; x=1704816656; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=1rpG4lzQDsBNsz8uBvv7/teFKEdbiLmAKFVAlrGT/0o=;
        b=dxlVZRlx1UkfRGsKEZt6jwTIKHY6YZPEQMUfvyIEpzgyBNibLLS4W6h+Byjdb5q0vW
         cpuvhGc3otcdug5T+SPajJAfadJlgLejK1zW7Sl4SGEVCSKw5UL/FwETLaAcRE488KYn
         IRMe8D27nP2S8O2AfpNHvv+TBfzEgCZp4hNXu+GYCZfaSodhrrwJfB2TgaAtVgiYdg3Z
         NUSYX/iDzziRmGiK1lC/c0PYELP3hBv8SjkdCmWbjmAJHD5eaK7l9BAF2yiAkOCIbWCG
         bMRCJE5x1AaeWlhOLNMzCom+3ykLhx6fyUl4fvvVmR8ynTHJcHTsZGCImTJTj1ezL789
         /UCQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1704211856; x=1704816656;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=1rpG4lzQDsBNsz8uBvv7/teFKEdbiLmAKFVAlrGT/0o=;
        b=rnd3WpRAp/fN572c7yKX/E3GiEgJCmnRjNGUFaVyXomATekqMAprdQdSwyMSj0Z0eb
         Hy5liGl3FTxewfU6cDHhwB05lmyVJmqQoxxMqE8BIlOBoxaf02bU7ti0aLFzBijK9y9g
         LzH/SP1/00Fhar17lpKop6FAhaG4WqU5EL9vWiH1mH0Ys1sY1HpwYFGjaxcfPZaf3lt+
         eqqC8wHZJ5ldfgBeG8hsG6i1m5eqhH1iXs9V3PvtP9jb5qXS+ftHopo9MRrjA2zLgvME
         j3WOfzAFETJO9YKEVSEOQv4SK+XOxan0sEfgcvjuOG0XFwOntMG+CqwToT8DBquZO/0G
         5xxg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YwymvBX2SAsPiMCOjd6myS9oAXjyUrlKVa/+MnborCfvca7jlGS
	3bxUnYa7Lb+sHHlsNPdT4fY=
X-Google-Smtp-Source: AGHT+IHsaVxiQL4sv6UIRAkJZ6DiUd/0fOxbAzG7790cTUzF++V+xI29CYa2bJj/YK/Q5ir07qwn3A==
X-Received: by 2002:a05:600c:154b:b0:40d:7dc8:7bb9 with SMTP id f11-20020a05600c154b00b0040d7dc87bb9mr2940732wmg.73.1704211856042;
        Tue, 02 Jan 2024 08:10:56 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:1884:b0:40d:5b90:2a3 with SMTP id
 x4-20020a05600c188400b0040d5b9002a3ls1190306wmp.1.-pod-prod-00-eu; Tue, 02
 Jan 2024 08:10:54 -0800 (PST)
X-Received: by 2002:a05:600c:1987:b0:40d:56c1:f73 with SMTP id t7-20020a05600c198700b0040d56c10f73mr6815659wmq.3.1704211854333;
        Tue, 02 Jan 2024 08:10:54 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1704211854; cv=none;
        d=google.com; s=arc-20160816;
        b=ndIAnbvoogxwIhHpUCfV10UJYJEVjNykwKzN6FE+ODDtjVpebTUFecZlxTRmL5G4FY
         m+uaoC0PkSqe6F7oxLUjjn+dbQjWjiZnzn4JV/0cOfYRq6iMEGiHvfcDHZEN4D/MJNga
         aXEWblSjWAAF5/zzINhM2mtxLgxvQiRAfTs/pZfGkhAZQMfbjNoAYmmk8uE5pivcjZQk
         7UzU156Ocva6iGfDoX1FALPhKk11Cregkayu2130fz9vjqINQli8SeYSdgoY13X26kHV
         NqzET5QGZ22xrKs2uahy5sdkP7QkRAeuylBGNEHR6GXLG/B2XHIwmG4t0ZfWcPl3Wqqd
         4o9Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature:dkim-signature:dkim-signature;
        bh=XVgL7DZ8mWAYcWGWuopXqY0ECrWRGDftGwQn5Ry+vCc=;
        fh=gtwm6qN9lskLrXqGcgQSmKN+lN7yfNQhDGa14RKei7M=;
        b=gTiCFEW5d3cOUj36dCAQDEyaJdF6u9bU0KsOA7T04WWNcSMPUBOQA4GjBSP0L+/6Bq
         1llxUIhHO97zSLZytED70etZU7mfIKaMGzy6Z9S3tdyJC7JwZ9C9cy1fG8NjRoGLFjUt
         wE2arBWYtI/utl7IT+s1wHandqrrnEFFPErmUiga/Nx3xyW6lqMj0wEbpDR7BdrOlMEk
         KM4bvVXVzJj/oKzeeZXwc3L+b+x/06CpxECo1wtV+qEiIXLoTMGoH49sHqYcXoca7OGP
         KheN+tMoZLGSRL0H4eN50ih8ls2zDbpgTIfGWATEweBiBo1PHv25PLKWnawfGrxZ+sNu
         u9Bg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=qjgwENPJ;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=1QTZh1Yz;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=qjgwENPJ;
       dkim=neutral (no key) header.i=@suse.cz header.b=1QTZh1Yz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.130 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [195.135.223.130])
        by gmr-mx.google.com with ESMTPS id o36-20020a05600c512400b0040d381febbbsi754425wms.1.2024.01.02.08.10.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 02 Jan 2024 08:10:54 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.223.130 as permitted sender) client-ip=195.135.223.130;
Received: from imap1.dmz-prg2.suse.org (imap1.dmz-prg2.suse.org [10.150.64.97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id 7B815210E9;
	Tue,  2 Jan 2024 16:10:53 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id 454BD1340C;
	Tue,  2 Jan 2024 16:10:53 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id f9+XEI01lGWlegAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Tue, 02 Jan 2024 16:10:53 +0000
Message-ID: <cd4c22c3-2901-4dee-b6b4-e6981848cb70@suse.cz>
Date: Tue, 2 Jan 2024 17:10:53 +0100
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v3 15/34] mm: slub: Unpoison the memchr_inv() return value
Content-Language: en-US
To: Ilya Leoshkevich <iii@linux.ibm.com>,
 Alexander Gordeev <agordeev@linux.ibm.com>,
 Alexander Potapenko <glider@google.com>,
 Andrew Morton <akpm@linux-foundation.org>, Christoph Lameter <cl@linux.com>,
 David Rientjes <rientjes@google.com>, Heiko Carstens <hca@linux.ibm.com>,
 Joonsoo Kim <iamjoonsoo.kim@lge.com>, Marco Elver <elver@google.com>,
 Masami Hiramatsu <mhiramat@kernel.org>, Pekka Enberg <penberg@kernel.org>,
 Steven Rostedt <rostedt@goodmis.org>, Vasily Gorbik <gor@linux.ibm.com>
Cc: Christian Borntraeger <borntraeger@linux.ibm.com>,
 Dmitry Vyukov <dvyukov@google.com>, Hyeonggon Yoo <42.hyeyoo@gmail.com>,
 kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org,
 linux-mm@kvack.org, linux-s390@vger.kernel.org,
 linux-trace-kernel@vger.kernel.org, Mark Rutland <mark.rutland@arm.com>,
 Roman Gushchin <roman.gushchin@linux.dev>,
 Sven Schnelle <svens@linux.ibm.com>
References: <20231213233605.661251-1-iii@linux.ibm.com>
 <20231213233605.661251-16-iii@linux.ibm.com>
From: Vlastimil Babka <vbabka@suse.cz>
In-Reply-To: <20231213233605.661251-16-iii@linux.ibm.com>
Content-Type: text/plain; charset="UTF-8"
X-Spam-Score: 1.37
X-Spamd-Result: default: False [1.37 / 50.00];
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
	 R_RATELIMIT(0.00)[to_ip_from(RL5nkphuxq5kxo98ppmuqoc8wo)];
	 RCVD_COUNT_THREE(0.00)[3];
	 DKIM_SIGNED(0.00)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	 BAYES_HAM(-0.04)[58.94%];
	 RCPT_COUNT_TWELVE(0.00)[24];
	 DBL_BLOCKED_OPENRESOLVER(0.00)[suse.cz:email];
	 FUZZY_BLOCKED(0.00)[rspamd.com];
	 FROM_EQ_ENVFROM(0.00)[];
	 MIME_TRACE(0.00)[0:+];
	 FREEMAIL_CC(0.00)[linux.ibm.com,google.com,gmail.com,googlegroups.com,vger.kernel.org,kvack.org,arm.com,linux.dev];
	 RCVD_TLS_ALL(0.00)[];
	 SUSPICIOUS_RECIPS(1.50)[]
X-Spam-Level: *
X-Spam-Flag: NO
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=qjgwENPJ;       dkim=neutral
 (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=1QTZh1Yz;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=qjgwENPJ;
       dkim=neutral (no key) header.i=@suse.cz header.b=1QTZh1Yz;
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

On 12/14/23 00:24, Ilya Leoshkevich wrote:
> Even though the KMSAN warnings generated by memchr_inv() are suppressed
> by metadata_access_enable(), its return value may still be poisoned.
> 
> The reason is that the last iteration of memchr_inv() returns
> `*start != value ? start : NULL`, where *start is poisoned. Because of
> this, somewhat counterintuitively, the shadow value computed by
> visitSelectInst() is equal to `(uintptr_t)start`.
> 
> The intention behind guarding memchr_inv() behind
> metadata_access_enable() is to touch poisoned metadata without
> triggering KMSAN, so unpoison its return value.
> 
> Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>

Acked-by: Vlastimil Babka <vbabka@suse.cz>

> ---
>  mm/slub.c | 2 ++
>  1 file changed, 2 insertions(+)
> 
> diff --git a/mm/slub.c b/mm/slub.c
> index 2d29d368894c..802702748925 100644
> --- a/mm/slub.c
> +++ b/mm/slub.c
> @@ -1076,6 +1076,7 @@ static int check_bytes_and_report(struct kmem_cache *s, struct slab *slab,
>  	metadata_access_enable();
>  	fault = memchr_inv(kasan_reset_tag(start), value, bytes);
>  	metadata_access_disable();
> +	kmsan_unpoison_memory(&fault, sizeof(fault));
>  	if (!fault)
>  		return 1;
>  
> @@ -1182,6 +1183,7 @@ static void slab_pad_check(struct kmem_cache *s, struct slab *slab)
>  	metadata_access_enable();
>  	fault = memchr_inv(kasan_reset_tag(pad), POISON_INUSE, remainder);
>  	metadata_access_disable();
> +	kmsan_unpoison_memory(&fault, sizeof(fault));
>  	if (!fault)
>  		return;
>  	while (end > fault && end[-1] == POISON_INUSE)

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/cd4c22c3-2901-4dee-b6b4-e6981848cb70%40suse.cz.
