Return-Path: <kasan-dev+bncBDXYDPH3S4OBBDMS222AMGQET7XA4II@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x240.google.com (mail-lj1-x240.google.com [IPv6:2a00:1450:4864:20::240])
	by mail.lfdr.de (Postfix) with ESMTPS id CC40F931C10
	for <lists+kasan-dev@lfdr.de>; Mon, 15 Jul 2024 22:39:42 +0200 (CEST)
Received: by mail-lj1-x240.google.com with SMTP id 38308e7fff4ca-2ee90339092sf53799141fa.1
        for <lists+kasan-dev@lfdr.de>; Mon, 15 Jul 2024 13:39:42 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1721075982; cv=pass;
        d=google.com; s=arc-20160816;
        b=xMABH1LKltjeAN/OguyJRirrZM5WMDr3tGnZc2+Wmem8aLLoxqG0Dn+7SGQSaBHlTk
         W2w4RIf5rmIePN8IZHuAKqbLvq1+0H/jAbRedYozKfQTNxjkTB13mLugX8+EipD8Fr2j
         GmDQAAf2Uvdz5WGHN0JtptKFdKKdsVNj370CbVbxliPKMNdHh2pwQamMvv6BBHzhWeor
         o6movRyPCH2a/D4qHjwDapxVhc1DuVn+zm3ddw71vQAtxpbYbHQnEqkYZZLp8xYSWUIi
         NsITxNShZiNwCEE38Ii7Q77We1jVs2+N7uOI+D+nsGGbsFRg89qGo4QK5A0Qve1e5HNA
         WOeg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:autocrypt:from
         :references:cc:to:content-language:subject:user-agent:mime-version
         :date:message-id:sender:dkim-signature;
        bh=SWDOFAxL0RHAxo1b1s/88eq2nzxayDg8hsyn3kk27P8=;
        fh=9AiFcOL+gVNuOpaZj1iuzvBnkRdInUL7OxD0fd/Ztmc=;
        b=DgQNhDh1J21wK3EFSuFVlejRucjd0I4pBpYKW+AFo2tdguW/mpo8CtY1yPCbNM0koM
         2e1nLM9Mn7Hy1HqFVYiaB2/2y8R+nDcGHtm4ghdz8Qou3DMo8OvBCi4oXtxsqhRdD6gK
         tqAER86b8Fqn7vEM2i2tvjWZQjIiNvj5drJc+ZsN3FHY4UlaHaIZbar16kcq9f6vaZbq
         Z6hjUexneYKHf2aai8uuCY+kqfgo2fBs/zp5gN2Bdx/i7Pab0iGpZ0CJCek8qjY3yV8C
         zTTyMpEUgsxhn9njbCvtZifBIz8U5VbUA+MzLSdsG7gS1RXp7Q8a0xUYfyo3koW19Gsf
         PhvA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=orGAZVa7;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=EO6Fc55G;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=orGAZVa7;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=EO6Fc55G;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1721075982; x=1721680782; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:autocrypt:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=SWDOFAxL0RHAxo1b1s/88eq2nzxayDg8hsyn3kk27P8=;
        b=Ycyjl/3Gozpo63tkf0ZcH5M505SpNrShD6i5noM3A57ua+k9C5GEF1YNQmbdhaV6/y
         XtkyY1IHlOdIybfFFk442ulf39jyg30F2aMxcziUwqmZ/UWj1ziyAADKnQbwkQieu1bd
         0TrNyta7T9z6/r7C3+XOGbOuK34g1eBjnXZhw9UTgobmMi9JLlsJ9hpLDCelYVc9XQwd
         zJ1fqWRwmyH9NJi1Z9O1lXE2g+eXZ1Nq6erSbOEE9t3dF6P9/9+I3BbrA+nyIDP39bv2
         R3z0ticLAmFguKSjNYa24V9c/OM04EEjS8ey3LGyzgG+U2ox9O+3dsOrAEUSpsmiIYV+
         iPhg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1721075982; x=1721680782;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :autocrypt:from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=SWDOFAxL0RHAxo1b1s/88eq2nzxayDg8hsyn3kk27P8=;
        b=nlFFqftatvhlZKyCFLl5vVrkcM6iFbI0NyNGevWkDC/mVDzCSTlyLGbvnkYVmoZzbT
         bPLG7uBn58z1laPNX9tFom+M4zFeoYl15fmjf5sh7M4yWRzVd/ZTfD5yma5ynhEsWpXa
         2Ghm8xRVJjogk4U3+Jf40pva8B44SdK8+CLxUO3nCFLYF7PgIQriN28yICrsez/VBi3E
         YRwwOWEuAdVeADitmU1xTk0lqC0yWWQVE7jZI80QufmiDtdmXHG3Cmp34CgUj0Kbay3W
         Q+FFak1dgqU35YEcM6rxtlItAqbJhjKJHNSagI873/WhAQh+rnxAH894BjfCdKaaLozY
         8EdA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUD0eKuC4qS0F9jkmDQdJM2XP/l2u72KCTDAuIvvB66X7szQOExNy9xpeWn1wbDkv3p9g3VV96OXnryzNyvAqy+aie8Zp+c2g==
X-Gm-Message-State: AOJu0YxxdpAjKy21ThLWLaRlSoU9s33LuF4aDtUxEbMXz5o9BSIzRUa2
	sW7qWVbyW+W0zrd1mMXmvsJ2NfQY7wOLMKdTfnZGp9hld1T878PE
X-Google-Smtp-Source: AGHT+IHa0b4JuM1vz15ggx73qw8R02U46pDQPLfcfvTRHDTiIJCi/rvPFSSZe/Iyym3blrb2aq0MkA==
X-Received: by 2002:a2e:961a:0:b0:2ee:8aed:ddcd with SMTP id 38308e7fff4ca-2eef4159f26mr1510261fa.2.1721075981618;
        Mon, 15 Jul 2024 13:39:41 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:a554:0:b0:2ec:5504:285e with SMTP id 38308e7fff4ca-2eeddc7edf6ls9186601fa.2.-pod-prod-04-eu;
 Mon, 15 Jul 2024 13:39:39 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVKhZBTeJWw+86FcUNL6KruxpIXbQaIMK9MtiRVxDY98f4AWgJARZ7Xh4A6izDPKqj2J02ZlF91XTimPZFGsJdtF+TLkQHEkUYRlA==
X-Received: by 2002:a2e:87d3:0:b0:2ec:4d48:75f3 with SMTP id 38308e7fff4ca-2eef41ea184mr1265971fa.45.1721075979510;
        Mon, 15 Jul 2024 13:39:39 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1721075979; cv=none;
        d=google.com; s=arc-20160816;
        b=fc93onjktRgGNps6z9hCZN8FJ5g32HI+XLTspsr5ARz/kG6GunT8oLEJMkaAh5ZCzk
         7e5NS4dXjZi8tBOchxLk07X9diQqdqKK334oUHdJpyy4MNBldSiM9Wh7pBm/wlNsHXFQ
         brUhX8TeHFgQZCRD+vBeTRGueF7KvxHWDHSXwHj/4a0OM5+ROrj4dazvjPrQ3Go/PURf
         GhdD96a3iw2S376KOUm/oxg0HSASgLZljKLW/r33dBahhpDBo2IiZtXAtoaF/2N2TKPD
         vwSAxNIKSB5IJuY3iW8LPXzTyU49/I0KevAVXp719Rm1XY9CwyggFj4ZG58x9JurvAHU
         Nz5w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:autocrypt:from:references:cc
         :to:content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature:dkim-signature:dkim-signature;
        bh=13l4KWTF4acx+DoFosvJJOCp5skXW9ib/ek+T6Gj1BU=;
        fh=kPgoZ/TakvrG477Osm2XIQkgvYddNMQ0TlS2daNPXRg=;
        b=gjK5VdPUYzO1brsnYmp+Vcd+OssGAKsZT/2X7A+NRCdHU36Tj2gM4+BD2H2nZRbCgn
         u+5HhDwuyCj5gFV3v59UYl1D4bbEZoshyc56AQvFHKgH0iDsq06sfgajCDWaMeVRFI9y
         HPtAHadLdQoOmtRhN9oSgNFsgdEwkM+dl5rleT/xFFU6QSBupPDp7Of5DwkDVIWSWKcu
         Lnx+CbOcDm8G/vAzgpLuy//TemTdt7NpJhpW4ZqxK+fkFxL44XBE5jeqBjISGRPz31ko
         aaNk0mNa/pN+wg1qxHFXM+H13YSG+a/TFI5RMzgU+p+H/p/bPS06cf0RuUYF+Ea/UCch
         N6fg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=orGAZVa7;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=EO6Fc55G;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=orGAZVa7;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=EO6Fc55G;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [195.135.223.131])
        by gmr-mx.google.com with ESMTPS id 4fb4d7f45d1cf-59b275319aasi66746a12.4.2024.07.15.13.39.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 15 Jul 2024 13:39:39 -0700 (PDT)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted sender) client-ip=195.135.223.131;
Received: from imap1.dmz-prg2.suse.org (imap1.dmz-prg2.suse.org [IPv6:2a07:de40:b281:104:10:150:64:97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id A2D1C1F833;
	Mon, 15 Jul 2024 20:39:38 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id 6827F137EB;
	Mon, 15 Jul 2024 20:39:38 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id xIrMGAqJlWZ9VgAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Mon, 15 Jul 2024 20:39:38 +0000
Message-ID: <df0716ac-c995-498c-83ee-b8c25302f9ed@suse.cz>
Date: Mon, 15 Jul 2024 22:39:38 +0200
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH 00/14] replace call_rcu by kfree_rcu for simple
 kmem_cache_free callback
Content-Language: en-US
To: Uladzislau Rezki <urezki@gmail.com>
Cc: paulmck@kernel.org, "Jason A. Donenfeld" <Jason@zx2c4.com>,
 Jakub Kicinski <kuba@kernel.org>, Julia Lawall <Julia.Lawall@inria.fr>,
 linux-block@vger.kernel.org, kernel-janitors@vger.kernel.org,
 bridge@lists.linux.dev, linux-trace-kernel@vger.kernel.org,
 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>, kvm@vger.kernel.org,
 linuxppc-dev@lists.ozlabs.org, "Naveen N. Rao" <naveen.n.rao@linux.ibm.com>,
 Christophe Leroy <christophe.leroy@csgroup.eu>,
 Nicholas Piggin <npiggin@gmail.com>, netdev@vger.kernel.org,
 wireguard@lists.zx2c4.com, linux-kernel@vger.kernel.org,
 ecryptfs@vger.kernel.org, Neil Brown <neilb@suse.de>,
 Olga Kornievskaia <kolga@netapp.com>, Dai Ngo <Dai.Ngo@oracle.com>,
 Tom Talpey <tom@talpey.com>, linux-nfs@vger.kernel.org,
 linux-can@vger.kernel.org, Lai Jiangshan <jiangshanlai@gmail.com>,
 netfilter-devel@vger.kernel.org, coreteam@netfilter.org,
 kasan-dev <kasan-dev@googlegroups.com>
References: <e926e3c6-05ce-4ba6-9e2e-e5f3b37bcc23@suse.cz>
 <3b6fe525-626c-41fb-8625-3925ca820d8e@paulmck-laptop>
 <6711935d-20b5-41c1-8864-db3fc7d7823d@suse.cz> <ZnCDgdg1EH6V7w5d@pc636>
 <36c60acd-543e-48c5-8bd2-6ed509972d28@suse.cz> <ZnFT1Czb8oRb0SE7@pc636>
 <5c8b2883-962f-431f-b2d3-3632755de3b0@paulmck-laptop>
 <9967fdfa-e649-456d-a0cb-b4c4bf7f9d68@suse.cz>
 <6dad6e9f-e0ca-4446-be9c-1be25b2536dd@paulmck-laptop>
 <4cba4a48-902b-4fb6-895c-c8e6b64e0d5f@suse.cz> <ZnVInAV8BXhgAjP_@pc636>
From: Vlastimil Babka <vbabka@suse.cz>
Autocrypt: addr=vbabka@suse.cz; keydata=
 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
 EP+ylKVEKb0Q2A==
In-Reply-To: <ZnVInAV8BXhgAjP_@pc636>
Content-Type: text/plain; charset="UTF-8"
X-Spamd-Result: default: False [-4.50 / 50.00];
	BAYES_HAM(-3.00)[100.00%];
	NEURAL_HAM_LONG(-1.00)[-1.000];
	R_DKIM_ALLOW(-0.20)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	NEURAL_HAM_SHORT(-0.20)[-1.000];
	MIME_GOOD(-0.10)[text/plain];
	MX_GOOD(-0.01)[];
	XM_UA_NO_VERSION(0.01)[];
	DKIM_SIGNED(0.00)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	FREEMAIL_ENVRCPT(0.00)[gmail.com];
	FREEMAIL_TO(0.00)[gmail.com];
	RBL_SPAMHAUS_BLOCKED_OPENRESOLVER(0.00)[2a07:de40:b281:104:10:150:64:97:from];
	RCPT_COUNT_TWELVE(0.00)[29];
	FUZZY_BLOCKED(0.00)[rspamd.com];
	MIME_TRACE(0.00)[0:+];
	ARC_NA(0.00)[];
	TO_MATCH_ENVRCPT_ALL(0.00)[];
	FREEMAIL_CC(0.00)[kernel.org,zx2c4.com,inria.fr,vger.kernel.org,lists.linux.dev,efficios.com,lists.ozlabs.org,linux.ibm.com,csgroup.eu,gmail.com,lists.zx2c4.com,suse.de,netapp.com,oracle.com,talpey.com,netfilter.org,googlegroups.com];
	RCVD_TLS_ALL(0.00)[];
	RCVD_COUNT_TWO(0.00)[2];
	FROM_EQ_ENVFROM(0.00)[];
	FROM_HAS_DN(0.00)[];
	TO_DN_SOME(0.00)[];
	MID_RHS_MATCH_FROM(0.00)[];
	RCVD_VIA_SMTP_AUTH(0.00)[];
	RECEIVED_SPAMHAUS_BLOCKED_OPENRESOLVER(0.00)[2a07:de40:b281:106:10:150:64:167:received];
	DKIM_TRACE(0.00)[suse.cz:+];
	R_RATELIMIT(0.00)[to_ip_from(RLujeud1qp5x6qhm7ow61zc6bu)];
	DBL_BLOCKED_OPENRESOLVER(0.00)[imap1.dmz-prg2.suse.org:helo,imap1.dmz-prg2.suse.org:rdns,suse.cz:dkim]
X-Spam-Flag: NO
X-Rspamd-Server: rspamd1.dmz-prg2.suse.org
X-Rspamd-Action: no action
X-Spam-Score: -4.50
X-Spam-Level: 
X-Rspamd-Queue-Id: A2D1C1F833
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=orGAZVa7;       dkim=neutral
 (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=EO6Fc55G;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=orGAZVa7;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519
 header.b=EO6Fc55G;       spf=pass (google.com: domain of vbabka@suse.cz
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

On 6/21/24 11:32 AM, Uladzislau Rezki wrote:
> On Wed, Jun 19, 2024 at 11:28:13AM +0200, Vlastimil Babka wrote:
> One question. Maybe it is already late but it is better to ask rather than not.
> 
> What do you think if we have a small discussion about it on the LPC 2024 as a
> topic? It might be it is already late or a schedule is set by now. Or we fix
> it by a conference time.
> 
> Just a thought.

Sorry for the late reply. The MM MC turned out to be so packed I didn't even
propose a slab topic. We could discuss in hallway track or a BOF, but
hopefully if the current direction taken by my RFC brings no unexpected
surprise, and the necessary RCU barrier side is also feasible, this will be
settled by time of plumbers.

> --
> Uladzislau Rezki

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/df0716ac-c995-498c-83ee-b8c25302f9ed%40suse.cz.
