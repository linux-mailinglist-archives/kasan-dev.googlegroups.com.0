Return-Path: <kasan-dev+bncBCO3JTUR7UBRB7VS2SWAMGQEDBYAUZI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x337.google.com (mail-wm1-x337.google.com [IPv6:2a00:1450:4864:20::337])
	by mail.lfdr.de (Postfix) with ESMTPS id 1BBDF822971
	for <lists+kasan-dev@lfdr.de>; Wed,  3 Jan 2024 09:23:27 +0100 (CET)
Received: by mail-wm1-x337.google.com with SMTP id 5b1f17b1804b1-40d68242598sf36607575e9.3
        for <lists+kasan-dev@lfdr.de>; Wed, 03 Jan 2024 00:23:27 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1704270206; cv=pass;
        d=google.com; s=arc-20160816;
        b=IFTrykD3h8hWwhVkUK76X5Ghmh9eQbsRKgZ8NcZ6ugCEZwP3bPPpsd0i+jX/rZjUKl
         gJ7mBEGTjuVftX02Y4Bv5CG3iBO0YWl2P2IV+ManrAZLG72/ULcsO0O02OXcr/NDIqSg
         QDt1Nep2DKhf2AwO3QDdFhuYEhvTqEVw3c6THmv3XZkkqoACZVNeFJEhVpUktg68CEw/
         XjKxZw5BDqh/TWgUdGHeGTKXwp6lB12qJoHScUHqmMG7JcjmVjH4p2CkLzlNRetE+o4Z
         jFS3Oj6Yc2Tgij2YtPMNbZgTHYpMP2UsXdGAxyipZHeLruyliCtEyXsjgWvcmaGWS7nq
         DhEg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=4d+ER6SlzEyYKtNag7diNAnRDt+UP+Y2YyDy7O78zrc=;
        fh=uYnjiVNxbW5kI0u75v8U/Y/ao7NQ4m8EfWg99NPaynw=;
        b=RXXH7DjllgEqvagtBIEihfiaDwu4MyfMPzPHoXmSNFPtxNKmg63XDWyl3yKy9KtIxF
         1PYwmkI2YYEMw8vs4ASFR60FNxMcMslsC3Htw72hFvpoKlEXccKDeLj2Ec1xnHc2S8+X
         uXUEdWQ8yBUnws4C6eJb5xaXRqoJ/ZL/zcKej3oPdp92zE/eoaOqWxtpfy7WrE9rR35x
         sP1SDQt5bugvSfGvZwFHDOIuW8Xhgx7/gax3SqBwuYVs6rZO5ZmfurqCYmLhMCGCtzcl
         G6BzmZQTMZD61Od3yEzw7IOnqCMRL9El8sfg+Ycc+/YJuQhcGiRTDHVIQLxfR2VvbLod
         QVmA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.de header.s=susede2_rsa header.b=iHCQVP8Q;
       dkim=neutral (no key) header.i=@suse.de header.s=susede2_ed25519;
       dkim=pass header.i=@suse.de header.s=susede2_rsa header.b="j8E1+H/D";
       dkim=neutral (no key) header.i=@suse.de header.s=susede2_ed25519;
       spf=pass (google.com: domain of osalvador@suse.de designates 195.135.223.130 as permitted sender) smtp.mailfrom=osalvador@suse.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=suse.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1704270206; x=1704875006; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=4d+ER6SlzEyYKtNag7diNAnRDt+UP+Y2YyDy7O78zrc=;
        b=F40rAyu3CnJHUAkc+FS9Q9Sm0c5ClDDLsuRjTVnqvUVJlbCmD/GFElZn2a4Dcr7+mj
         wTkKjJkznFU6YFnjpWo08fNRCa55JJmLlfd+P/5d1ujsIgNOyx9/VNVwZFWA8aBlF8Ft
         2RYXWZ+mIPYyCNpy+dsgNA/z42MHbZO/aPVbniTvxmoiw6ny2Y2reCBIzEQ0g5pnOTZ+
         Cdz+D/0WTZOvMniu07mrA8/3dFcqZttZ+fA9pdx6oTFjIu934W8rNuEv+89AvfJKiyM0
         n0rgqiEj4PwEg2wnLR4p4gWo375N4HdLGljU3qxLDC6B+fu0vYpwJKcBRV6rx2A8yjVr
         X58w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1704270206; x=1704875006;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=4d+ER6SlzEyYKtNag7diNAnRDt+UP+Y2YyDy7O78zrc=;
        b=Np1G557rtg8XnEUovYYLlh0giYOHbLOD9KnyDPfDII86QKU/6WUvC1gBlkHCQdzwty
         XX4V34z+A60KgJJHgsZ0V/G8pvTDpJnmY4T/pUNVDZF0Inyv8mZomhTheLDw/OJkmd60
         BmlHDIg2rWkZRdEhBOuMqacC9ktGshQwzLKDWqPNdq9U9nzuTTX3j8NkIqaSp+ma+J4d
         YYAVXbsA4Flj6xtaXDnQ0iOI/yOZViNofq+8z/e/gOdZQD+FY7w8gAww2h+L6k1kz2iD
         Q+iSyxHahvLMPtQZygzVtWHa1RtvdAN7G+ieHLKijqgRmy4DPyeBw6ADY8GADX3b4szS
         RQ+A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yw+stFhEVcgEJjJ4WCNLZdSIn4k7r3ZWrljQ1xJdtDRqlqozvtn
	/RE4ePODYxVk8IxfUAWLa78=
X-Google-Smtp-Source: AGHT+IGJHxqs13CfrWXP/WpSMgQL++DnogB6KunO9G1WIge7E9JzSGVLWKWN/rZKzQiQPdJfJ/kvlw==
X-Received: by 2002:a05:600c:3412:b0:40c:2b34:96ae with SMTP id y18-20020a05600c341200b0040c2b3496aemr4864676wmp.123.1704270206316;
        Wed, 03 Jan 2024 00:23:26 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:2111:b0:40d:5b7a:e32a with SMTP id
 u17-20020a05600c211100b0040d5b7ae32als1711548wml.1.-pod-prod-08-eu; Wed, 03
 Jan 2024 00:23:25 -0800 (PST)
X-Received: by 2002:a05:600c:81b:b0:40d:88e5:581a with SMTP id k27-20020a05600c081b00b0040d88e5581amr1205956wmp.9.1704270204663;
        Wed, 03 Jan 2024 00:23:24 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1704270204; cv=none;
        d=google.com; s=arc-20160816;
        b=CNqaZUobVt9SxJqi3wlsPAzN/iow1rIF4axWp5Kc5QYZ/1BlpmNkkjK7HJwvhhsV1y
         f8l07kNdvScC5YUs33czyffxa7DHbNdp6nujn1hu2usiZQ2sjg6rfuIz4iReOko6uSR9
         psbz7m4GheuiSMVW48hAH3FKz2uBToJnsqUNrTIhZ619rJoqf24SCGTZgyhe+Wf1bFdg
         xu+IO3OlWQz4P6ZNS0UGhFfPIAq9KdcjWNHRv2GA6kQ6Hs9Ar81nOmDXtL3mK94CNzJ4
         eY9DpmoFl3gtZ2aNwEPzxWpPxNaBv0VqgA48B6RMcImeQzj7BFCjum32KVxSWrUBKj+q
         2s+w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature:dkim-signature
         :dkim-signature:dkim-signature;
        bh=FGbDhAb1VSn1oyT4cWgIeM8OuXxB1azKP8xwd8px58k=;
        fh=uYnjiVNxbW5kI0u75v8U/Y/ao7NQ4m8EfWg99NPaynw=;
        b=bgipBHjGggI1labDf4eMpdJHF6VuK9DGe9LVw6WpEYXYfptk5nL2MI1zqUUhKizdJF
         UOjnkLgbCds0Czh/1PFTvBOagjt+Q8GAvqStwRrf9xU45E9d8XRcqG/4XJu4+uHyt4fq
         oluEjyTSBG04SDDMTje2CLIo+PBKCxaE2dp2a/FKLDhx8qVqKuTLww6mttpi6oZICeOq
         BI9Wjv1R7De1to20QA7blgKBMY1VV1O7vZg+Xc7mEhXF45miwr+2M1yw51vY6aFgYKZm
         TmRlPTivaIoYJyjWM8EFcEL2LcrXS2Wh6Wo6wGY/NgsHBY6TuMiEZe//aHrXFRdpxYbY
         BQfQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.de header.s=susede2_rsa header.b=iHCQVP8Q;
       dkim=neutral (no key) header.i=@suse.de header.s=susede2_ed25519;
       dkim=pass header.i=@suse.de header.s=susede2_rsa header.b="j8E1+H/D";
       dkim=neutral (no key) header.i=@suse.de header.s=susede2_ed25519;
       spf=pass (google.com: domain of osalvador@suse.de designates 195.135.223.130 as permitted sender) smtp.mailfrom=osalvador@suse.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=suse.de
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [195.135.223.130])
        by gmr-mx.google.com with ESMTPS id p30-20020a05600c1d9e00b0040d6d74d343si107980wms.0.2024.01.03.00.23.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 03 Jan 2024 00:23:24 -0800 (PST)
Received-SPF: pass (google.com: domain of osalvador@suse.de designates 195.135.223.130 as permitted sender) client-ip=195.135.223.130;
Received: from imap1.dmz-prg2.suse.org (imap1.dmz-prg2.suse.org [IPv6:2a07:de40:b281:104:10:150:64:97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id 528BD21E6E;
	Wed,  3 Jan 2024 08:23:22 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id A396D1340C;
	Wed,  3 Jan 2024 08:23:21 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id Mb0xJXkZlWUvXQAAD6G6ig
	(envelope-from <osalvador@suse.de>); Wed, 03 Jan 2024 08:23:21 +0000
Date: Wed, 3 Jan 2024 09:24:12 +0100
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
Subject: Re: [PATCH v4 05/22] lib/stackdepot: add depot_fetch_stack helper
Message-ID: <ZZUZrJzmkXOf_Wsa@localhost.localdomain>
References: <cover.1700502145.git.andreyknvl@google.com>
 <170d8c202f29dc8e3d5491ee074d1e9e029a46db.1700502145.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <170d8c202f29dc8e3d5491ee074d1e9e029a46db.1700502145.git.andreyknvl@google.com>
X-Spam-Level: 
X-Rspamd-Server: rspamd1.dmz-prg2.suse.org
X-Spam-Level: 
X-Spamd-Bar: /
X-Spam-Flag: NO
X-Spamd-Result: default: False [-0.74 / 50.00];
	 RCVD_VIA_SMTP_AUTH(0.00)[];
	 TO_DN_SOME(0.00)[];
	 RCVD_COUNT_THREE(0.00)[3];
	 DKIM_TRACE(0.00)[suse.de:+];
	 MX_GOOD(-0.01)[];
	 FROM_EQ_ENVFROM(0.00)[];
	 MIME_TRACE(0.00)[0:+];
	 BAYES_HAM(-0.43)[78.34%];
	 ARC_NA(0.00)[];
	 R_DKIM_ALLOW(-0.20)[suse.de:s=susede2_rsa,suse.de:s=susede2_ed25519];
	 FROM_HAS_DN(0.00)[];
	 FREEMAIL_ENVRCPT(0.00)[gmail.com];
	 TO_MATCH_ENVRCPT_ALL(0.00)[];
	 MIME_GOOD(-0.10)[text/plain];
	 DKIM_SIGNED(0.00)[suse.de:s=susede2_rsa,suse.de:s=susede2_ed25519];
	 RCPT_COUNT_TWELVE(0.00)[12];
	 DBL_BLOCKED_OPENRESOLVER(0.00)[suse.de:dkim,suse.de:email,linux.dev:email];
	 FUZZY_BLOCKED(0.00)[rspamd.com];
	 FREEMAIL_CC(0.00)[linux-foundation.org,gmail.com,google.com,suse.cz,googlegroups.com,kvack.org,vger.kernel.org];
	 RCVD_TLS_ALL(0.00)[];
	 RBL_SPAMHAUS_BLOCKED_OPENRESOLVER(0.00)[2a07:de40:b281:104:10:150:64:97:from]
X-Spam-Score: -0.74
X-Rspamd-Queue-Id: 528BD21E6E
X-Original-Sender: osalvador@suse.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.de header.s=susede2_rsa header.b=iHCQVP8Q;       dkim=neutral
 (no key) header.i=@suse.de header.s=susede2_ed25519;       dkim=pass
 header.i=@suse.de header.s=susede2_rsa header.b="j8E1+H/D";
       dkim=neutral (no key) header.i=@suse.de header.s=susede2_ed25519;
       spf=pass (google.com: domain of osalvador@suse.de designates
 195.135.223.130 as permitted sender) smtp.mailfrom=osalvador@suse.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=suse.de
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

On Mon, Nov 20, 2023 at 06:47:03PM +0100, andrey.konovalov@linux.dev wrote:
> From: Andrey Konovalov <andreyknvl@google.com>
> 
> Add a helper depot_fetch_stack function that fetches the pointer to
> a stack record.
> 
> With this change, all static depot_* functions now operate on stack pools
> and the exported stack_depot_* functions operate on the hash table.
> 
> Reviewed-by: Alexander Potapenko <glider@google.com>
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

Reviewed-by: Oscar Salvador <osalvador@suse.de>


-- 
Oscar Salvador
SUSE Labs

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ZZUZrJzmkXOf_Wsa%40localhost.localdomain.
