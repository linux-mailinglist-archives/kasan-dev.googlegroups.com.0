Return-Path: <kasan-dev+bncBCO3JTUR7UBRB3ML3KWAMGQEZOBTTUQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53b.google.com (mail-ed1-x53b.google.com [IPv6:2a00:1450:4864:20::53b])
	by mail.lfdr.de (Postfix) with ESMTPS id 43D89823F5D
	for <lists+kasan-dev@lfdr.de>; Thu,  4 Jan 2024 11:18:23 +0100 (CET)
Received: by mail-ed1-x53b.google.com with SMTP id 4fb4d7f45d1cf-5560c5ff5f4sf215539a12.1
        for <lists+kasan-dev@lfdr.de>; Thu, 04 Jan 2024 02:18:23 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1704363503; cv=pass;
        d=google.com; s=arc-20160816;
        b=iNNOXEWgVwD6DOXHPEk5HCWCI4a+zeHfI3c6QklkWRzBuI7QCHs/d7pWdDKX0zOtdT
         HQte1D8aASB5LqlIupAZlpicI21U2mJ/KZYQZUcsvkHe3TzX9kr2ebL7Ir40zFk9Y6VT
         bxwBG/3XKSlEga5BnIJjOGzrMhqES6N2BvSnNkt13wCrpXAyTINTwvo9vjJSkeCF23/a
         kcV4H/yyEHQ6MJKH2xNtllm6vR/rZ4keu55OAtBLV42YUguZrZ41rnDOmfr8dCJN7Ru4
         w0sBrRM+2d3lWQsTizTlTVCxtvu3fFOqrjybcUzyFeQXxFz0w5z6wbrqtzM0QnevcATy
         9A6g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=eETzWjVXPqN9H/FN9eXQu4xrFxAY8140bJ5HvJuZZ9c=;
        fh=53DXi97tcefMoivpUvy7dXiy4v2aViPJRaUB+Wd+zTA=;
        b=qOfYVJnB/t5XfnpxlXaJV3EPpMoStVkApztWZFr0L/t4l6/PaULhMNTN6dpE7Hhy7b
         I3LpaRiCBJtYdXpA4fF00/wVSK+8ovJchFbzFyi7xnx3lLRenoz1xvsW7t6tJcxjQ1CI
         04jhQCm6arfoszq2xNi956AEKjjLsDFR8NRXVbIugKox5qd9K769sgs07LHzkma/NPWq
         D1mKZoWly/zxlU+Y822K1f/lF09VnHRGrXvyDZfb2CJSnHX2h2TWIUA2zKpuvBZ05tc+
         T2OqO/yM/kXZ0WnwZT7d8q35Th4+MHzkM8zJTUBearmDCpZqSWbl6IbG8KkPtO4cAfPq
         6crw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.de header.s=susede2_rsa header.b=EMvMPWHw;
       dkim=neutral (no key) header.i=@suse.de header.s=susede2_ed25519;
       dkim=pass header.i=@suse.de header.s=susede2_rsa header.b=EMvMPWHw;
       dkim=neutral (no key) header.i=@suse.de header.s=susede2_ed25519 header.b=Jco3uzab;
       spf=pass (google.com: domain of osalvador@suse.de designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) smtp.mailfrom=osalvador@suse.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=suse.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1704363503; x=1704968303; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=eETzWjVXPqN9H/FN9eXQu4xrFxAY8140bJ5HvJuZZ9c=;
        b=clwEm/fOex5sEi4r53jIvge4U2/7913y5/XQoGb2F2/45tg4CkdU35Z0l8OH1Jgs0S
         4MY++Ky25KgzoykR6Yc6XmRe2YA6JuyGnG4vkJf7tf/KBEeCKFus+ze8iECS6kBdiSwn
         2weP+PL0uxBeIajVgfzyZ9WwMYV4FhFp+vYJRzCCl+/fFBE2A62cZxQ3ncyzuU+Olqa/
         3+bb4Yjxo/WzQCckRQZug+6eUyfMTCtKWv0H75xDkFXBvkgDg3wFp+dOFZdQm1EbIVTh
         O2NEpifkwRbhvksqujVJ6OyZB7U41SVgAD5eo+H9xJvovIM3ffkyRRYT9TJX0lji0ECV
         pVpA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1704363503; x=1704968303;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=eETzWjVXPqN9H/FN9eXQu4xrFxAY8140bJ5HvJuZZ9c=;
        b=WW6/zIm4V6PqQilkRgVfNEMw9f/opx7ST0nmuv+ET8dwfLi9YtNK/mWDWeNjtuKDy9
         VnUWOEIU0XkVf+RF7qJqfge0g05mc/873hO1dyCuN0bQFNND8MDsYv9qcRmkXILASz4H
         6XDbDB3YrSrMl6h2DYWY7isMLQytgdpv3oQT+8MyvHVa9xHKRTGjR5EWC67vp139YYqQ
         y2mox67GDFzSgABHsIUcE2A8n6pH3yB5PZwTs/Gs+g8o+QmEgugJaM2b2y9yHzHCsa/U
         1FnAHYH04a9NnNgPLBehW5Q1PKxc7uIspooY/8V02aWlmE7r/bJEeTNrD/3grN9PCxV1
         A9Ig==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YxE5qEZ+NCexM/ucucBx5EUQ0BOPVxImRuRfeJzVWlz1/R0T/d/
	99Kodbr+cnTWTfVhhz68vqc=
X-Google-Smtp-Source: AGHT+IHBHT9Wig3TQCGDwdO1RTJq5cT1r3ntuUAZKt6eSb/IWunygnvqr5HfP3zJTrhkPXsegnrU+A==
X-Received: by 2002:a50:f690:0:b0:557:a3c:a952 with SMTP id d16-20020a50f690000000b005570a3ca952mr208660edn.82.1704363501582;
        Thu, 04 Jan 2024 02:18:21 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:210b:b0:554:e3f:5918 with SMTP id
 bl11-20020a056402210b00b005540e3f5918ls970963edb.0.-pod-prod-06-eu; Thu, 04
 Jan 2024 02:18:20 -0800 (PST)
X-Received: by 2002:aa7:cf98:0:b0:557:77d:3b65 with SMTP id z24-20020aa7cf98000000b00557077d3b65mr222908edx.23.1704363499735;
        Thu, 04 Jan 2024 02:18:19 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1704363499; cv=none;
        d=google.com; s=arc-20160816;
        b=iKE5DB/8zlydhO85rtMe3xR2YLDsIcM84t/SxqnK2vkkEkhMucgfCGcku3F4n4icsK
         fFvbLqSOExya7xS3gpc7E/bnleWhADLkpEcLpB/s0mku3FF2R6/GSDYztCyRfgIR7W0r
         m6V0DimLabMjZgzApaGOlIT4MR88VbVkgDwC4sW5OOI9K8JGSZDS8Kf7xC1a+na/GfAR
         DtjiezsXc2WLd4lYpEDa006R50MiN77l3A64h0SUTzgI+neMrNKWE5VrlbgyMtRF9VT0
         GufPy5+CKEhI78cERjAZ1d30wkTrH3yDNkJOm7bgFrp/BcC9nOCF9CNc7LEabtH8NRpR
         XTdQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature:dkim-signature
         :dkim-signature:dkim-signature;
        bh=Glk8o7g6rLUF+Y5xoK5c97MnCA6oOnTmvlAIcCHTwSw=;
        fh=53DXi97tcefMoivpUvy7dXiy4v2aViPJRaUB+Wd+zTA=;
        b=D7vXTqWS2Xs2nGXy7C/UH55ztcSGfY2JSAR0PO0BprZ0ScKv7yCs38PP3KAYHSRKpJ
         N2JRnr0+0SzCeuFRYPxK4WACLvsbIH+1a+7mDIUAaZossnsNvM4mSJs/gQPfQVRPaiZH
         HKGPdvO3IoOv1A4zm028Yz9u6xKZB6QfcV1U/rcPKymNd4K9TU7jVd6HipVX7rumxJmw
         xKr9if9yPxeest1nLWDkzDy/FWSZL80XALUem5LZcKNCJ+5+oF87Ht/F5pWIumBqDnQi
         coU3uN3MuOhcxHFUWWCqjf1DKu6wlxPS1dMeogpuMobxQFeInU6P5HgDerWuNzAJIia9
         9Yaw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.de header.s=susede2_rsa header.b=EMvMPWHw;
       dkim=neutral (no key) header.i=@suse.de header.s=susede2_ed25519;
       dkim=pass header.i=@suse.de header.s=susede2_rsa header.b=EMvMPWHw;
       dkim=neutral (no key) header.i=@suse.de header.s=susede2_ed25519 header.b=Jco3uzab;
       spf=pass (google.com: domain of osalvador@suse.de designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) smtp.mailfrom=osalvador@suse.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=suse.de
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [2a07:de40:b251:101:10:150:64:2])
        by gmr-mx.google.com with ESMTPS id f19-20020a0564021e9300b005533f8f54a2si667519edf.4.2024.01.04.02.18.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 04 Jan 2024 02:18:19 -0800 (PST)
Received-SPF: pass (google.com: domain of osalvador@suse.de designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) client-ip=2a07:de40:b251:101:10:150:64:2;
Received: from imap1.dmz-prg2.suse.org (imap1.dmz-prg2.suse.org [10.150.64.97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id 200711F7E5;
	Thu,  4 Jan 2024 10:18:19 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id 413F5137E8;
	Thu,  4 Jan 2024 10:18:18 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id /st8DOqFlmVUbwAAD6G6ig
	(envelope-from <osalvador@suse.de>); Thu, 04 Jan 2024 10:18:18 +0000
Date: Thu, 4 Jan 2024 11:19:09 +0100
From: Oscar Salvador <osalvador@suse.de>
To: Marco Elver <elver@google.com>
Cc: andrey.konovalov@linux.dev, Andrew Morton <akpm@linux-foundation.org>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com,
	Evgenii Stepanov <eugenis@google.com>, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: Re: [PATCH v4 17/22] lib/stackdepot: allow users to evict stack
 traces
Message-ID: <ZZaGHbaerKfli0Wu@localhost.localdomain>
References: <cover.1700502145.git.andreyknvl@google.com>
 <1d1ad5692ee43d4fc2b3fd9d221331d30b36123f.1700502145.git.andreyknvl@google.com>
 <ZZZx5TpqioairIMP@localhost.localdomain>
 <CANpmjNMWyVOvni-w-2Lx6WyEUnP+G_cLVELJv_-B4W1fMrQpnw@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANpmjNMWyVOvni-w-2Lx6WyEUnP+G_cLVELJv_-B4W1fMrQpnw@mail.gmail.com>
X-Spam-Level: 
X-Spam-Level: 
X-Spamd-Result: default: False [-0.10 / 50.00];
	 ARC_NA(0.00)[];
	 RCVD_VIA_SMTP_AUTH(0.00)[];
	 FROM_HAS_DN(0.00)[];
	 TO_DN_SOME(0.00)[];
	 FREEMAIL_ENVRCPT(0.00)[gmail.com];
	 TO_MATCH_ENVRCPT_ALL(0.00)[];
	 MIME_GOOD(-0.10)[text/plain];
	 RCVD_COUNT_THREE(0.00)[3];
	 DKIM_SIGNED(0.00)[suse.de:s=susede2_rsa,suse.de:s=susede2_ed25519];
	 RCPT_COUNT_TWELVE(0.00)[12];
	 FUZZY_BLOCKED(0.00)[rspamd.com];
	 FROM_EQ_ENVFROM(0.00)[];
	 MIME_TRACE(0.00)[0:+];
	 FREEMAIL_CC(0.00)[linux.dev,linux-foundation.org,gmail.com,google.com,suse.cz,googlegroups.com,kvack.org,vger.kernel.org];
	 RCVD_TLS_ALL(0.00)[];
	 BAYES_HAM(-0.00)[40.79%]
X-Spam-Score: -0.10
X-Spam-Flag: NO
X-Original-Sender: osalvador@suse.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.de header.s=susede2_rsa header.b=EMvMPWHw;       dkim=neutral
 (no key) header.i=@suse.de header.s=susede2_ed25519;       dkim=pass
 header.i=@suse.de header.s=susede2_rsa header.b=EMvMPWHw;       dkim=neutral
 (no key) header.i=@suse.de header.s=susede2_ed25519 header.b=Jco3uzab;
       spf=pass (google.com: domain of osalvador@suse.de designates
 2a07:de40:b251:101:10:150:64:2 as permitted sender) smtp.mailfrom=osalvador@suse.de;
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

On Thu, Jan 04, 2024 at 10:25:40AM +0100, Marco Elver wrote:
> I think a boolean makes the interface more confusing for everyone
> else. At that point stack_depot_put merely decrements the refcount and
> becomes a wrapper around refcount_dec, right?

Thanks Marco for the feedback.

Fair enough.

> I think you want to expose the stack_record struct anyway for your
> series, so why not simply avoid calling stack_depot_put and decrement
> the refcount with your own helper (there needs to be a new stackdepot
> function to return a stack_record under the pool_rwlock held as
> reader).

Yeah, that was something I was experimenting with my last version.
See [0], I moved the "stack_record" struct into the header so page_owner
can make sense of it. I guess that's fine right?
If so, I'd do as you mentioned, just decrementing it with my own helper
so no calls to stack_depot_put will be needed.

Regarding the locking, I yet have to check the patch that implements
the read/write lock, but given that page_owner won't be evicting
anything, do I still have to fiddle with the locks?

> Also, you need to ensure noone else calls stack_depot_put on the stack
> traces you want to keep. If there is a risk someone else may call
> stack_depot_put on them, it obviously won't work (I think the only
> option then is to introduce a way to pin stacks).

Well, since page_owner won't call stack_depot_put, I don't see
how someone else would be able to interfere there, so I think
I am safe there.

[0] https://patchwork.kernel.org/project/linux-mm/patch/20231120084300.4368-3-osalvador@suse.de/

-- 
Oscar Salvador
SUSE Labs

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ZZaGHbaerKfli0Wu%40localhost.localdomain.
