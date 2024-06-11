Return-Path: <kasan-dev+bncBCO3JTUR7UBRBOEBUCZQMGQEXTTI3BA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x338.google.com (mail-wm1-x338.google.com [IPv6:2a00:1450:4864:20::338])
	by mail.lfdr.de (Postfix) with ESMTPS id B4A5E903422
	for <lists+kasan-dev@lfdr.de>; Tue, 11 Jun 2024 09:46:01 +0200 (CEST)
Received: by mail-wm1-x338.google.com with SMTP id 5b1f17b1804b1-42159c69a28sf7674585e9.1
        for <lists+kasan-dev@lfdr.de>; Tue, 11 Jun 2024 00:46:01 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718091961; cv=pass;
        d=google.com; s=arc-20160816;
        b=fye0fBgIG6rPBb9WIocdEw6wlpQr+6wJpPkW4AYJ4oLxXko8WObaRQhJ92thvUEJz5
         RVxBuBmGyRPQlObcNwcsFykcLE9908Uw+OK48yg67seSZsONqL5cQmd3TY0H0ma1OogA
         hgheloslpju5ZVsLeq+tJ7OfZoWsgPf184QhPkFx/lAEl51pexqIUfffVQbDJXPCbAjZ
         CDzGbK1kTo5fJ6S+2aUWBbXYOiGAfcMgtEs4K/u5NzKW39js1ktWKBhLuYOUrvtKlYtc
         2TCSBxSm5vHg/3RT9EcWtSqY0N0rHfexFs5OIWKMOPwEo/S0C+cBnaIDbsOKDSE/2MbN
         wj2Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=/OnbXh+HGQZiBPzOHqaCtbEJNCqRzbeWl+lM/h0jbDg=;
        fh=3cXhc72QfIAsZSo9JLBl8rTrVANApY65b3cuWEUsd5k=;
        b=Q5TYSr/dZ4O2s5ls3iHbeEFxfELqTgK6yUxAu/Bf/EDHiCmhNgpEdtej9mePHM/T/r
         g4UNmK+Wce+z0Y9J41u/+vjryPEdVK/hs+FIYGGaMcsOUrrPi+OxfBxTXai9kRl8/XV5
         WIV39/3Aw7IjFMYFYLD0FCauRGzhoUaJPrd2Sna+db75IBs132WNH/7CRlMZMuXdoFBd
         U4YlIGYL0SoYeGTRQ5ML85fp7M4P6U30hmoIRduk+Cu6L4zd6vBj9atj9eKSZWxwbkuH
         Sx7AKNmHma59pAI+Ow1+0ivQAF7HqlP84+V1CaS4xiipII2tyqd8ObyIK3NTS7GM7bWz
         l3Tg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.de header.s=susede2_rsa header.b=u5mEgWuS;
       dkim=neutral (no key) header.i=@suse.de;
       dkim=pass header.i=@suse.de header.s=susede2_rsa header.b=beS+LyS4;
       dkim=neutral (no key) header.i=@suse.de header.s=susede2_ed25519 header.b="blQE/fLA";
       spf=pass (google.com: domain of osalvador@suse.de designates 195.135.223.130 as permitted sender) smtp.mailfrom=osalvador@suse.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=suse.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718091961; x=1718696761; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=/OnbXh+HGQZiBPzOHqaCtbEJNCqRzbeWl+lM/h0jbDg=;
        b=RvUctOClif4PYQ1udonqORI1S50Kg7d4kljHkPdQsXhjPvtR5kcuCjQh9FeI+u0Pjr
         Ll+fbYsgyoO01uvPGteQboFvJyLGpSkizR2KqrfF/s0STrejaTmkceYUtHW8ebrhRafb
         Zn2CC94UfTOVBp4alytXxphuuo8hfdhPzoCnWvgo0gMBM+bn/CIo74j6DMTrAXrzfLRm
         DeFmMwSl2O3qJ8jMiA1spiDC+GQM8+wJHXsD4nA0HoYbFc1aMaEBs1YIy/Bt3kLsPy1z
         dpd3tN9SZFc3ryIqgca0u1JnvPuj07BkyqkbDRXtSTRH9Mgtklno/pMf0IFL7e5okozR
         y16w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718091961; x=1718696761;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=/OnbXh+HGQZiBPzOHqaCtbEJNCqRzbeWl+lM/h0jbDg=;
        b=fwjbEVjYeyKZ2ukX+FrzjVZv/f8RababBH81CJ/QdPn6octjSwATvlNhXfEeUytInT
         +s+5GQQqXx7UGfYGmSYqJrehgkiFAGbUHSac6twusBXYjlkkVGaaRURAe/T6Xpy9FgMb
         GF4+Qw3SrBvxtPNtkscRfUxb1NjH1m7sL9LtfzlFJv4swHM7EZc0HKoCdsEcVBxrLsev
         vYI+cW6X5fSVY01X4G9qAYPpirnk1irL5OCFFMr+LtbmBshXm7H7hFWJ3n0gKR0QV5KO
         SWbBkPA5wne3fGSpHldkBfB7IWN0jPeWefe7rYD0M8XjXauOXeW56L7GQoSH18jutMJ9
         hjHQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCV2xNEywPa9qceNCHv8GaCLPomzw8VKTRLUvoegpkIAIdZC78jyft7fM9umr17P8BFKpHsniHJc+DY4THyksXSXb7AgsuoJ0Q==
X-Gm-Message-State: AOJu0Yxm2U3iIW2Zc8xT56Ono7gDjUBgsoIlCpfUpgIHDl+c5zqfUKMv
	9Pl/MgPnyHcM+EzB34jmbYCo8wyTeSj49+necXg/mKVc45Ip4gRx
X-Google-Smtp-Source: AGHT+IFM1qDWsHA+yW6VDCl/eHA0sGWzdwrrzToX35mgMWwAhL+G98qtNJJ7t/1bJlJDc8GD2itOXA==
X-Received: by 2002:a05:600c:35c8:b0:421:81b8:139a with SMTP id 5b1f17b1804b1-42181b813a0mr50599195e9.12.1718091960576;
        Tue, 11 Jun 2024 00:46:00 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:1d14:b0:421:7e41:1878 with SMTP id
 5b1f17b1804b1-4223457a769ls5080275e9.0.-pod-prod-07-eu; Tue, 11 Jun 2024
 00:45:59 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXA9+hVcF8SP/xFJ4KeunZ5n4m6PdC+jzACoJYCmGQ4NRizOdw35tC27u+wJoL1lWnn87XJL/tejYBeU1UUrL41xtWTQpt/ZDUN2w==
X-Received: by 2002:a05:600c:5121:b0:421:8193:e2fa with SMTP id 5b1f17b1804b1-4218193e891mr51131505e9.19.1718091958756;
        Tue, 11 Jun 2024 00:45:58 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718091958; cv=none;
        d=google.com; s=arc-20160816;
        b=tnMbsCjpDrCb61EetvFwgV24vuQrO+yYg5HupIXaEXTky4J2BmPXWOwj8BCxDWjRvP
         yX2tWzedNIr4EWW17tDGEyucpmifVA/io2Mnzread5Z2QZxtGSg47b8DZUrgTjkQ8yI9
         txKSz3C6qjBZ8MllOPVshRJm6IiSTj3YKHRcR+B7Ffa/XIsvnt0HurEKOM1JNdsqScUO
         sw7xFsohA5XpFrP8dG0CKmV5UTbYojfljijOK2ezS3BS1JSuPJidUOOyDbTMiLG2dcCW
         TST2AT0M6T9bE9capwmlqDSZCU4IHtsXIcaDLQfU/iwX2GdvSZOq2DE5ImK4/n45aFQI
         TTjg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature:dkim-signature
         :dkim-signature:dkim-signature;
        bh=HVao4QsDP4Z+JAjo5dOzj5sxwVNV/Y4USEllUqua+SQ=;
        fh=opXV1WEp03kbeubOZloyb10FoNtntQdRllRWblbVMRI=;
        b=krhPuteT+CKAmxiYj06iLalxPAAidBrlGG9BjALrH83bklUiv88VmiQbzwjlc9Lx3V
         rn5MUMZCFZNf2s8uG7Uaicov5uIDZPj+ElZuDBX/NYfr5rf++eS+N0AuACTokrsqWC59
         rUGfQdYdYDYQa5NTNLRA8dVV4kFJk23RP/ZPG0wybw1V5HuYpyEixakKAp09NrrbxXSe
         VlPwkY46wRzuFxUf41ExZJ9kkuSmFhKHTzwIV8IRZUPUXN6YFB3VtBfZfWNagzfklpN0
         ufx0+9WYN/GkIDaN2v0duAzBybZbFljBVIto/3W4H/OIWo+4LJVSEJVLD1Pk+9WxP5iy
         rUAQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.de header.s=susede2_rsa header.b=u5mEgWuS;
       dkim=neutral (no key) header.i=@suse.de;
       dkim=pass header.i=@suse.de header.s=susede2_rsa header.b=beS+LyS4;
       dkim=neutral (no key) header.i=@suse.de header.s=susede2_ed25519 header.b="blQE/fLA";
       spf=pass (google.com: domain of osalvador@suse.de designates 195.135.223.130 as permitted sender) smtp.mailfrom=osalvador@suse.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=suse.de
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [195.135.223.130])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-4224b8a158csi635025e9.0.2024.06.11.00.45.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 11 Jun 2024 00:45:58 -0700 (PDT)
Received-SPF: pass (google.com: domain of osalvador@suse.de designates 195.135.223.130 as permitted sender) client-ip=195.135.223.130;
Received: from imap1.dmz-prg2.suse.org (unknown [10.150.64.97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id 0B24722CCD;
	Tue, 11 Jun 2024 07:45:57 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id D8AB213A55;
	Tue, 11 Jun 2024 07:45:55 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id 4MdfMrMAaGYMUQAAD6G6ig
	(envelope-from <osalvador@suse.de>); Tue, 11 Jun 2024 07:45:55 +0000
Date: Tue, 11 Jun 2024 09:45:54 +0200
From: Oscar Salvador <osalvador@suse.de>
To: David Hildenbrand <david@redhat.com>
Cc: linux-kernel@vger.kernel.org, linux-mm@kvack.org,
	linux-hyperv@vger.kernel.org, virtualization@lists.linux.dev,
	xen-devel@lists.xenproject.org, kasan-dev@googlegroups.com,
	Andrew Morton <akpm@linux-foundation.org>,
	Mike Rapoport <rppt@kernel.org>,
	"K. Y. Srinivasan" <kys@microsoft.com>,
	Haiyang Zhang <haiyangz@microsoft.com>,
	Wei Liu <wei.liu@kernel.org>, Dexuan Cui <decui@microsoft.com>,
	"Michael S. Tsirkin" <mst@redhat.com>,
	Jason Wang <jasowang@redhat.com>,
	Xuan Zhuo <xuanzhuo@linux.alibaba.com>,
	Eugenio =?iso-8859-1?Q?P=E9rez?= <eperezma@redhat.com>,
	Juergen Gross <jgross@suse.com>,
	Stefano Stabellini <sstabellini@kernel.org>,
	Oleksandr Tyshchenko <oleksandr_tyshchenko@epam.com>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>, Dmitry Vyukov <dvyukov@google.com>
Subject: Re: [PATCH v1 2/3] mm/memory_hotplug: initialize memmap of
 !ZONE_DEVICE with PageOffline() instead of PageReserved()
Message-ID: <ZmgAsolx7SAHeDW7@localhost.localdomain>
References: <20240607090939.89524-1-david@redhat.com>
 <20240607090939.89524-3-david@redhat.com>
 <ZmZ_3Xc7fdrL1R15@localhost.localdomain>
 <5d9583e1-3374-437d-8eea-6ab1e1400a30@redhat.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <5d9583e1-3374-437d-8eea-6ab1e1400a30@redhat.com>
X-Spam-Level: 
X-Spamd-Result: default: False [-4.30 / 50.00];
	BAYES_HAM(-3.00)[100.00%];
	NEURAL_HAM_LONG(-1.00)[-1.000];
	NEURAL_HAM_SHORT(-0.20)[-0.999];
	MIME_GOOD(-0.10)[text/plain];
	DKIM_SIGNED(0.00)[suse.de:s=susede2_rsa,suse.de:s=susede2_ed25519];
	SUBJECT_HAS_EXCLAIM(0.00)[];
	ARC_NA(0.00)[];
	MIME_TRACE(0.00)[0:+];
	FUZZY_BLOCKED(0.00)[rspamd.com];
	RCPT_COUNT_TWELVE(0.00)[23];
	TO_MATCH_ENVRCPT_ALL(0.00)[];
	FROM_HAS_DN(0.00)[];
	RCVD_TLS_ALL(0.00)[];
	FROM_EQ_ENVFROM(0.00)[];
	TO_DN_SOME(0.00)[];
	RCVD_COUNT_TWO(0.00)[2];
	MISSING_XM_UA(0.00)[];
	RCVD_VIA_SMTP_AUTH(0.00)[];
	DBL_BLOCKED_OPENRESOLVER(0.00)[imap1.dmz-prg2.suse.org:helo]
X-Spam-Score: -4.30
X-Spam-Flag: NO
X-Original-Sender: osalvador@suse.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.de header.s=susede2_rsa header.b=u5mEgWuS;       dkim=neutral
 (no key) header.i=@suse.de;       dkim=pass header.i=@suse.de
 header.s=susede2_rsa header.b=beS+LyS4;       dkim=neutral (no key)
 header.i=@suse.de header.s=susede2_ed25519 header.b="blQE/fLA";
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

On Mon, Jun 10, 2024 at 10:56:02AM +0200, David Hildenbrand wrote:
> There are fortunately not that many left.
> 
> I'd even say marking them (vmemmap) reserved is more wrong than right: note
> that ordinary vmemmap pages after memory hotplug are not reserved! Only
> bootmem should be reserved.

Ok, that is a very good point that I missed.
I thought that hotplugged-vmemmap pages (not selfhosted) were marked as
Reserved, that is why I thought this would be inconsistent.
But then, if that is the case, I think we are safe as kernel can already
encounter vmemmap pages that are not reserved and it deals with them
somehow.

> Let's take at the relevant core-mm ones (arch stuff is mostly just for MMIO
> remapping)
> 
... 
> Any PageReserved user that I am missing, or why we should handle these
> vmemmap pages differently than the ones allocated during ordinary memory
> hotplug?

No, I cannot think of a reason why normal vmemmap pages should behave
different than self-hosted.

I was also confused because I thought that after this change
pfn_to_online_page() would be different for self-hosted vmemmap pages,
because I thought that somehow we relied on PageOffline(), but it is not
the case.

> In the future, we might want to consider using a dedicated page type for
> them, so we can stop using a bit that doesn't allow to reliably identify
> them. (we should mark all vmemmap with that type then)

Yes, a all-vmemmap pages type would be a good thing, so we do not have
to special case.

Just one last thing.
Now self-hosted vmemmap pages will have the PageOffline cleared, and that
will still remain after the memory-block they belong to has gone
offline, which is ok because those vmemmap pages lay around until the
chunk of memory gets removed.

Ok, just wanted to convince myself that there will no be surprises.

Thanks David for claryfing.
 

-- 
Oscar Salvador
SUSE Labs

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ZmgAsolx7SAHeDW7%40localhost.localdomain.
