Return-Path: <kasan-dev+bncBDXYDPH3S4OBBXNNZ6VAMGQERZIBOXA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x238.google.com (mail-lj1-x238.google.com [IPv6:2a00:1450:4864:20::238])
	by mail.lfdr.de (Postfix) with ESMTPS id 511707EB7B4
	for <lists+kasan-dev@lfdr.de>; Tue, 14 Nov 2023 21:21:52 +0100 (CET)
Received: by mail-lj1-x238.google.com with SMTP id 38308e7fff4ca-2c520e0a9a7sf55084081fa.3
        for <lists+kasan-dev@lfdr.de>; Tue, 14 Nov 2023 12:21:52 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1699993311; cv=pass;
        d=google.com; s=arc-20160816;
        b=xx5ZMhdhvqbP7AopG9pwnUAHkNoeokBwpxElTNBeyFV1/qRjwIEBFonyejBPayl6U6
         o+mVTL5B7HaPCA4HtPAVWftGZadrAJ7NKj1zGQWzcLoAUY0s+qNgVNFO/p0qb5PNcIZO
         Zq8tLlSQeXqCxfXTBApaTpAQnzBaHFa+kUGEu+fP5+9faLbdbWJfdjCDfu6h3pd1NMf5
         7YlEXb5jwyW9sOOC1Fp5NIdWm2/bhU3oz4aijjyU1DK40HsIF5kwvrohCfF+gKaZ2kUZ
         bbC6FBFboSZPOjeNx4hVmKpCMGEbbvDdmSLXhdruxdqf7G7AhET/gBV6OnTEVW/ZjFqu
         Y1jQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=Vd1tA9LLa1sRV7OGVjYSJyMci06jICJOnxQ/lpoljRo=;
        fh=ZYn9MgmVpwKFi+h1WPMvL6yHYpyqaynezClwMkX7/CM=;
        b=I9UQR2s6doy45tDbdHoBqYuSzTr7PgWpl1QwTcSVjaOaHHN7wHuL0Nbaqja13tGXpF
         vHroDQU03fMaRvuRZggGuPMK5a63yjXNKMHANDsGEMX1g1Me2+85PSePQE71GCWXbkxf
         5X1zLuqYh0m7AN2uzU/g54bEjN4gNt4szUgUUFJZnhDhCXtVRIDuRvkaB7zA2FT/QXbB
         jBiqcwGupwDsrqFQzS1VGk6BcpaBTps16UzqZsMqwDyQKJR6osb3/J2DglTusU2mxSzn
         b4evT807ZsgXGc1auG45BptjQhXc7KW/+DCmh5o3mPM1vR7o36eXRZZOQn0NNJnLjcs+
         KKiA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=FB0fB5ml;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.29 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1699993311; x=1700598111; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=Vd1tA9LLa1sRV7OGVjYSJyMci06jICJOnxQ/lpoljRo=;
        b=LQ+HfGiKbhd+xhKCPD5sFbWq7rzhz0U30m0gPbg6vT1BgTH0pRJ2i70MtKMimrEX1Z
         tReFQCnNWNBe9m0v3ThIqnumF8s8cwSyrZo0jloIxAbJE94DtJzOmjdufvdBYDYcs+Zl
         o9Y6eliECmlNF1sfpIhGHfrf3gQ9NwJx2dA9EdtEhge1iuuGRwbsprZ1qy2iuhb8KmuU
         o0VrGXtCAYZkEw7Zo/xS9e83+esQCFUdpZQWJ7/QCpEbyIY2WWaf7mpwQXcYNs5rkofC
         FS8c4qdOQfQ6pMOYKspj5Gqx3DdA7x6OpWAhwNWUHTq3A4e7v/mbv7GsxuFeJqCrblEB
         IHew==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1699993311; x=1700598111;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=Vd1tA9LLa1sRV7OGVjYSJyMci06jICJOnxQ/lpoljRo=;
        b=s1pZSniUZi+g8JHo+glc8itGwBCnGr+2zJPxxPQ4i1MdaqU99F7GUCd2XRj7GbP42o
         VBynv0nlJHXbqngenR3Iz3TRBf+N9zPjfohToYx8JEawfgg204qRVxp2tx45uY4kWCX9
         2V3v3RMm1HIWc5tIsm87jNI/t1Cv3LoMYAeV7QKvXIOAlY4Ho9qkCyV8nV5X+q0KXRuv
         FQ7xhcq6UfMEnpO0f9ss14475dhmqIuF4ywSxebfjSUt6Rv5Im7I9DVnrvImWeVdAIzM
         6geKsrKqjAyvOCI6KX4RON4JEHwudYhAoxuoUDAA/LRoeQNe5aliG5iJ35Yx9lAtJSif
         zD+w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yxd/rjyXaGxKThvtmdnKdMWpz4FmWt4nXdMUA3UXUOF8Z219v25
	n2t1YpRDi3Ggb9E3p48CEQY=
X-Google-Smtp-Source: AGHT+IF2HQX2KOw5hrhTGvkc2sepQRU3WFFG8XUlfLH6aT7GbmLwRFcApYYstqPHyRCH0Z+/t08vPQ==
X-Received: by 2002:a2e:2e06:0:b0:2c5:d3c:8f4d with SMTP id u6-20020a2e2e06000000b002c50d3c8f4dmr2417188lju.13.1699993310046;
        Tue, 14 Nov 2023 12:21:50 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:9b53:0:b0:2bf:f55d:1df9 with SMTP id o19-20020a2e9b53000000b002bff55d1df9ls339396ljj.1.-pod-prod-05-eu;
 Tue, 14 Nov 2023 12:21:48 -0800 (PST)
X-Received: by 2002:a05:651c:170b:b0:2c5:ab3b:d676 with SMTP id be11-20020a05651c170b00b002c5ab3bd676mr2552658ljb.9.1699993308104;
        Tue, 14 Nov 2023 12:21:48 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1699993308; cv=none;
        d=google.com; s=arc-20160816;
        b=HVFURgsdKlup8optFloN1nNLEmQiv9D5noIk9P2JqrGHXw7uGiW9JlOhefl8tAENCn
         qpZ9yCH7/PMCWZ4kAsd2IXRf2wCEPK2+1VFC9t5qXd698XHsPblCIyJX3RnKdN92Cuke
         +yaQjsBbYrQfuVAQhxVlw20thqb30Y9n7xFgnEGNvq4L5uEi0GtVBOT8nOFWWrwXipHH
         9kzQ+j1rF/woJ3w2ji1hdPrHA25AD8TVC9L4m5nBfcmMvd/K2XefpPKKC34eXs3aAE/x
         2vFbbJKLWQzlcg2fRlZdQMYKx0eo0jx9qN0egbpPoLBzmAHhxZ1kK4/OlbDfT8S06ZJs
         Z2Kw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature;
        bh=zkDw8JxpkfmgcwQMuM79MHBZrTfS3XQLnbqEXbxd1e0=;
        fh=ZYn9MgmVpwKFi+h1WPMvL6yHYpyqaynezClwMkX7/CM=;
        b=ZQBQhmHkIIQ1jhpCgHksE6Zp6t++0n9C+n5D1Ru0dd11W9eFTYenK/R5dLAaExxStv
         2kOCMngqfTcQTHGIPrdepGHQ1lO7AGZpHUAhczfnKFgs1KmcY3NNs4ZyQkIZFDw9f+xy
         08qooZI9YvdZFblTbee5xikQdYObXDfcz34rFcqLmgtYQ3V3IqVVb5RTbnVOumtWaD9o
         jth4VMlw+uCK7b1Ctk64nT/p0y9YmX6mncty3tQrzXtEl2TFBU8JYf1vpNpN/XMz70mD
         LyWkBkQrzzGareEClM4+W/UUXbw5/Xl7X/QWhqTBd5vx3TCXqI8wYk2tRVfJ616XmOws
         vRhw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=FB0fB5ml;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.29 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [195.135.220.29])
        by gmr-mx.google.com with ESMTPS id b7-20020a2ebc07000000b002c28192fe0fsi283310ljf.0.2023.11.14.12.21.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 14 Nov 2023 12:21:48 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.220.29 as permitted sender) client-ip=195.135.220.29;
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id 1C9A7204B3;
	Tue, 14 Nov 2023 20:21:47 +0000 (UTC)
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by imap2.suse-dmz.suse.de (Postfix) with ESMTPS id C771113460;
	Tue, 14 Nov 2023 20:21:46 +0000 (UTC)
Received: from dovecot-director2.suse.de ([192.168.254.65])
	by imap2.suse-dmz.suse.de with ESMTPSA
	id cPTxL9rWU2UcXQAAMHmgww
	(envelope-from <vbabka@suse.cz>); Tue, 14 Nov 2023 20:21:46 +0000
Message-ID: <40819423-6ed3-73c4-43a8-7b43095b1443@suse.cz>
Date: Tue, 14 Nov 2023 21:21:46 +0100
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101
 Thunderbird/102.15.1
Subject: Re: [PATCH 10/20] mm/slab: move the rest of slub_def.h to mm/slab.h
Content-Language: en-US
To: Kees Cook <keescook@chromium.org>
Cc: David Rientjes <rientjes@google.com>, Christoph Lameter <cl@linux.com>,
 Pekka Enberg <penberg@kernel.org>, Joonsoo Kim <iamjoonsoo.kim@lge.com>,
 Andrew Morton <akpm@linux-foundation.org>,
 Hyeonggon Yoo <42.hyeyoo@gmail.com>,
 Roman Gushchin <roman.gushchin@linux.dev>, linux-mm@kvack.org,
 linux-kernel@vger.kernel.org, patches@lists.linux.dev,
 Andrey Ryabinin <ryabinin.a.a@gmail.com>,
 Alexander Potapenko <glider@google.com>,
 Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>,
 Vincenzo Frascino <vincenzo.frascino@arm.com>, Marco Elver
 <elver@google.com>, Johannes Weiner <hannes@cmpxchg.org>,
 Michal Hocko <mhocko@kernel.org>, Shakeel Butt <shakeelb@google.com>,
 Muchun Song <muchun.song@linux.dev>, kasan-dev@googlegroups.com,
 cgroups@vger.kernel.org
References: <20231113191340.17482-22-vbabka@suse.cz>
 <20231113191340.17482-32-vbabka@suse.cz> <202311132037.F4FA0B2@keescook>
From: Vlastimil Babka <vbabka@suse.cz>
In-Reply-To: <202311132037.F4FA0B2@keescook>
Content-Type: text/plain; charset="UTF-8"
X-Spam-Level: 
X-Spam-Score: -3.19
X-Spamd-Result: default: False [-3.19 / 50.00];
	 ARC_NA(0.00)[];
	 RCVD_VIA_SMTP_AUTH(0.00)[];
	 RCVD_TLS_ALL(0.00)[];
	 FROM_HAS_DN(0.00)[];
	 TO_DN_SOME(0.00)[];
	 FREEMAIL_ENVRCPT(0.00)[gmail.com];
	 TO_MATCH_ENVRCPT_ALL(0.00)[];
	 TAGGED_RCPT(0.00)[];
	 MIME_GOOD(-0.10)[text/plain];
	 NEURAL_HAM_LONG(-3.00)[-1.000];
	 MID_RHS_MATCH_FROM(0.00)[];
	 DKIM_SIGNED(0.00)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	 NEURAL_HAM_SHORT(-1.00)[-1.000];
	 BAYES_HAM(-0.59)[81.59%];
	 RCPT_COUNT_TWELVE(0.00)[23];
	 FUZZY_BLOCKED(0.00)[rspamd.com];
	 FROM_EQ_ENVFROM(0.00)[];
	 MIME_TRACE(0.00)[0:+];
	 FREEMAIL_CC(0.00)[google.com,linux.com,kernel.org,lge.com,linux-foundation.org,gmail.com,linux.dev,kvack.org,vger.kernel.org,lists.linux.dev,arm.com,cmpxchg.org,googlegroups.com];
	 RCVD_COUNT_TWO(0.00)[2];
	 SUSPICIOUS_RECIPS(1.50)[]
X-Spam-Flag: NO
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=FB0fB5ml;       dkim=neutral
 (no key) header.i=@suse.cz;       spf=pass (google.com: domain of
 vbabka@suse.cz designates 195.135.220.29 as permitted sender) smtp.mailfrom=vbabka@suse.cz
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

On 11/14/23 05:38, Kees Cook wrote:
> On Mon, Nov 13, 2023 at 08:13:51PM +0100, Vlastimil Babka wrote:
>> mm/slab.h is the only place to include include/linux/slub_def.h which
>> has allowed switching between SLAB and SLUB. Now we can simply move the
>> contents over and remove slub_def.h.
>> 
>> Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
> 
> Now is the chance to do any whitespace updates! I saw a few #defines
> that looked like they could be re-tab-aligned, but it's not a big deal. :P

Right, I did some updates to accomodate line length especially where
checkpatch complained, will check for the other ones too.

> Reviewed-by: Kees Cook <keescook@chromium.org>
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/40819423-6ed3-73c4-43a8-7b43095b1443%40suse.cz.
