Return-Path: <kasan-dev+bncBCO3JTUR7UBRBQ4IUCZQMGQEU33BIEQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x238.google.com (mail-lj1-x238.google.com [IPv6:2a00:1450:4864:20::238])
	by mail.lfdr.de (Postfix) with ESMTPS id 9C291903493
	for <lists+kasan-dev@lfdr.de>; Tue, 11 Jun 2024 10:01:09 +0200 (CEST)
Received: by mail-lj1-x238.google.com with SMTP id 38308e7fff4ca-2ebf0863242sf6243921fa.3
        for <lists+kasan-dev@lfdr.de>; Tue, 11 Jun 2024 01:01:09 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718092869; cv=pass;
        d=google.com; s=arc-20160816;
        b=lOPlbLKpVYorZriWfx7mS5zkNnxYfhoXPxHBInPbY2xKcvqpj/bMXDSswAqPOtfGKm
         HcpFAQWPQJKO3gSR6HC6AwjfLb3dgRIjBlXBfqwJCMFSy1N90gcBOKk91gnV32s3hCaj
         ySrxIhdt5Luudaua6WhYKnxqoHhPM/hzLMIyutP3EZ5S5br5ctj0gcMa5t8aBEPI5D+x
         GiQULXCwsgFC0wpxgfW7RyI396THOU6yeLjPYYvFcjpBUss3LCmAdIzlKcBtNuWiU5i3
         G3VFy+XN7nahkZlUK+J1/IDAmhBkbVOBWB+hC8FttPSX9AxlSzH2SaJeaKgNnHXxF3k+
         GOag==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=8Hmmh6p8twKbjiq6zBtaAIDfcaPqb88hNhc4xcDV3vs=;
        fh=ms2/fweSeWaosyWn0dQlYHH2N9K8QbMh+5Q1fHkdyS8=;
        b=JuWkIOCvGATErFSapON8t3s1wpvld8r2lhj1+U3sdYsL1aq7uFQ0k5TAAvkN8AdnQm
         KWZ1nHAEHbKmfmEOa5GtTvmXqj1Og3oddG11xGmosoLEDoPQAUec2Y1o7WeWEonvnu3B
         vyA3FNT9LRhyQ3/F4J6qgnbyJw1HgR1YuDrc755fKl621t+h51jMqIFgvmQYN7zIg+ax
         rpKKe68Hct5HdDLSyQ5u+jjaUc2l9UhFRwKXAm94UaKRKViodi/02VIPUEIs0M0ZN5OH
         Czp9lJ3K61VLu3Y92EAQsAin/CmDVPXGmMZZzC2e74xljlitvyKtFmnN6ootYKxSxIak
         r0mQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.de header.s=susede2_rsa header.b=eZBr7hv0;
       dkim=neutral (no key) header.i=@suse.de header.s=susede2_ed25519;
       dkim=pass header.i=@suse.de header.s=susede2_rsa header.b=eZBr7hv0;
       dkim=neutral (no key) header.i=@suse.de header.s=susede2_ed25519;
       spf=pass (google.com: domain of osalvador@suse.de designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) smtp.mailfrom=osalvador@suse.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=suse.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718092869; x=1718697669; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=8Hmmh6p8twKbjiq6zBtaAIDfcaPqb88hNhc4xcDV3vs=;
        b=baXZQEFkdLV3fcmO+CZzgr70KQfHCk92UWif7NNKMpapKzmqNO50C4nxXQnQM40Ub9
         lPtQrrXWpSOb0Wxbxj/+MVFIhcQGSgtp4iKEUBbPZa+HdJaqjl7O5g/tUlkQPBMwkJ2a
         C6sjioBRZqczByiiZgb3D29SeobzL7LikrtJ1e/300F/BmLnxBsTPmpxwe0k+NAXnhNy
         XXjQGb998PPlnbUqho4JZV7wbqtKqI+vj3mdwQCF1vpjkMKQy+P38Wy3MHyKcloyPnxB
         cnWJrJQFRGC1BTIMWofLn2BcdwSHGQ/uQC22KTqfqRxB4O/rbpYju3I5KZHD5moRspC6
         Gmvw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718092869; x=1718697669;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=8Hmmh6p8twKbjiq6zBtaAIDfcaPqb88hNhc4xcDV3vs=;
        b=o3h48RBeYsqtwp/qat8MJhtx1TLud8H2obzcMlVpDirYvkT6kEuBhrNlrZThD0iE6t
         yDOif9fYEvFXqH7Jgh9mgV1If9Rg2r9LNaEh72iRIFQ+1TmOUjNz3m3M51QVJT8TGyV3
         xOq9WX/RaYD1fXC39ToOar1sfDvTuDzDacKvqYViri5qzqfw3mXr0pxb0R3tmKF5HgHV
         9AS+aCv8doljrwi8WcHtTp6JamiG1bLbMZUNkqAHWzTAC7JSIYK6pbEOKFCUGLyt92y2
         ZXpF/c/vGLuVddlC250ZJhE53xwPiP08vIaYHWvpzoAVPgZ/Q4IfvpnAQso4RlrCRX/E
         rczg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXpvDY3kDGqfQFDJKtpmvlWy9mr1qX1qWzRXaqnklpBjZ7nqdJ76IkYKZzEWds2/16OiEF7s8j76obEY+YgfO2mgrUwvr1eYA==
X-Gm-Message-State: AOJu0Yxg2uHd4l6ZNaYeM5urHdoDuTVf/1hejLS2jx4M6T9j/LC2cg/r
	DegYK1RCGZqDzN+pj7d20nnovKuSMbM5UpTmJktA2pJDA4z9AULL
X-Google-Smtp-Source: AGHT+IEFuLpyAtOt41zK2aECJbuOJX873cl4pgOjgQyt9826A9QIRhe+v4y4ZMEDvnF7ePRaTJesgg==
X-Received: by 2002:a2e:7002:0:b0:2eb:f2cf:1e49 with SMTP id 38308e7fff4ca-2ebf2cf1ea9mr6603391fa.2.1718092868123;
        Tue, 11 Jun 2024 01:01:08 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:b532:0:b0:2eb:da1f:86af with SMTP id 38308e7fff4ca-2ebf0aafb95ls3385041fa.2.-pod-prod-07-eu;
 Tue, 11 Jun 2024 01:01:06 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVzuT1LvSFra6DBG2JUaA4IKUbw26rI4bN4RSul3C8+Yh/HbjFEkAVqXM2eoXwOXoq2hVE+Kz/dl4Ty6IGvrn+aWwguUOd7PL+WJw==
X-Received: by 2002:a2e:b888:0:b0:2eb:f422:7408 with SMTP id 38308e7fff4ca-2ebf42274camr6767661fa.36.1718092866119;
        Tue, 11 Jun 2024 01:01:06 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718092866; cv=none;
        d=google.com; s=arc-20160816;
        b=RyyXwZy+LTrGxBSW1+0m2+eGL0+34Rc9Dif28ktKBrShENdGCBX6F+6rvFsmYGe5NF
         S6v6uzUYWFj4TbTx3c+EWQ/gKDTAabyksPEuBj0htmKhnFGP2Cf+o0ABZY7/gX4YtAzI
         GIWu3HNr72a0ksoQtgtssVfN0M34OZbeCe8s5VYixV+K1fYjR7Ph0ZvgL8E0hLLcEvk7
         O68WuwRBhKVCbXdCRlpMOm8llZnZMgr16SPqc/kY/F+h91D7zCE9/fLZgWPZ59PYU1ML
         mxcNwRxKmKDVo3LksvJ9jE12bLXBb/Ka5+61JAS7s6BAVUFYOUnU+AmvWSSEIHGNzugV
         QURA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature:dkim-signature
         :dkim-signature:dkim-signature;
        bh=qHTLyIX7jLzbH1ivzBIljZd8gbAzcrr4kki4IuM/w4s=;
        fh=opXV1WEp03kbeubOZloyb10FoNtntQdRllRWblbVMRI=;
        b=neoQplrgYFKwKPq8cRgEF2ZwifLmoYiMDFFwIQuuEuqOCaxVA+EnxojpUXtsR0xpl+
         UeH5+klHkXnAm7gmtfkbuP+jsHT64gIYXlnCiZ53tzhAgbVf19YQ5P+XjlIsVnoTzpq6
         aXQR/QyD6+KK2NHSh8Mq8MA+WLdmUWRg1J4HD5FZJFUHTULMmLKP+ibtbj0QGUBZtrHo
         yiVpCMPz3pq3n8xvNJfxI+nhvk8AoqdNbX7s4sXUIQxXO8w13GcfdIxhNluXKoj/hC60
         dHJIvg4LGSETveohBnqFGxDCEcdxp1ocRHDct0YPCXVMHoF1slNasJ7xsdjgd0KWCF8S
         sPYA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.de header.s=susede2_rsa header.b=eZBr7hv0;
       dkim=neutral (no key) header.i=@suse.de header.s=susede2_ed25519;
       dkim=pass header.i=@suse.de header.s=susede2_rsa header.b=eZBr7hv0;
       dkim=neutral (no key) header.i=@suse.de header.s=susede2_ed25519;
       spf=pass (google.com: domain of osalvador@suse.de designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) smtp.mailfrom=osalvador@suse.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=suse.de
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [2a07:de40:b251:101:10:150:64:2])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-2eaebd92af8si1987141fa.1.2024.06.11.01.01.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 11 Jun 2024 01:01:06 -0700 (PDT)
Received-SPF: pass (google.com: domain of osalvador@suse.de designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) client-ip=2a07:de40:b251:101:10:150:64:2;
Received: from imap1.dmz-prg2.suse.org (unknown [10.150.64.97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id 3DCEE20560;
	Tue, 11 Jun 2024 08:01:05 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id 2124F13A55;
	Tue, 11 Jun 2024 08:01:04 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id cdtzBUAEaGY4VgAAD6G6ig
	(envelope-from <osalvador@suse.de>); Tue, 11 Jun 2024 08:01:04 +0000
Date: Tue, 11 Jun 2024 10:01:02 +0200
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
Message-ID: <ZmgEPgjyG4EfYkNM@localhost.localdomain>
References: <20240607090939.89524-1-david@redhat.com>
 <20240607090939.89524-3-david@redhat.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20240607090939.89524-3-david@redhat.com>
X-Spam-Level: 
X-Spamd-Result: default: False [-4.26 / 50.00];
	BAYES_HAM(-3.00)[100.00%];
	NEURAL_HAM_LONG(-1.00)[-1.000];
	NEURAL_HAM_SHORT(-0.16)[-0.822];
	MIME_GOOD(-0.10)[text/plain];
	RCVD_VIA_SMTP_AUTH(0.00)[];
	ARC_NA(0.00)[];
	MIME_TRACE(0.00)[0:+];
	MISSING_XM_UA(0.00)[];
	RCPT_COUNT_TWELVE(0.00)[23];
	SUBJECT_HAS_EXCLAIM(0.00)[];
	RCVD_TLS_ALL(0.00)[];
	DKIM_SIGNED(0.00)[suse.de:s=susede2_rsa,suse.de:s=susede2_ed25519];
	FROM_EQ_ENVFROM(0.00)[];
	FROM_HAS_DN(0.00)[];
	TO_DN_SOME(0.00)[];
	RCVD_COUNT_TWO(0.00)[2];
	FUZZY_BLOCKED(0.00)[rspamd.com];
	TO_MATCH_ENVRCPT_ALL(0.00)[];
	DBL_BLOCKED_OPENRESOLVER(0.00)[imap1.dmz-prg2.suse.org:helo,suse.de:email]
X-Spam-Score: -4.26
X-Spam-Flag: NO
X-Original-Sender: osalvador@suse.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.de header.s=susede2_rsa header.b=eZBr7hv0;       dkim=neutral
 (no key) header.i=@suse.de header.s=susede2_ed25519;       dkim=pass
 header.i=@suse.de header.s=susede2_rsa header.b=eZBr7hv0;       dkim=neutral
 (no key) header.i=@suse.de header.s=susede2_ed25519;       spf=pass
 (google.com: domain of osalvador@suse.de designates 2a07:de40:b251:101:10:150:64:2
 as permitted sender) smtp.mailfrom=osalvador@suse.de;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=suse.de
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

On Fri, Jun 07, 2024 at 11:09:37AM +0200, David Hildenbrand wrote:
> We currently initialize the memmap such that PG_reserved is set and the
> refcount of the page is 1. In virtio-mem code, we have to manually clear
> that PG_reserved flag to make memory offlining with partially hotplugged
> memory blocks possible: has_unmovable_pages() would otherwise bail out on
> such pages.
> 
> We want to avoid PG_reserved where possible and move to typed pages
> instead. Further, we want to further enlighten memory offlining code about
> PG_offline: offline pages in an online memory section. One example is
> handling managed page count adjustments in a cleaner way during memory
> offlining.
> 
> So let's initialize the pages with PG_offline instead of PG_reserved.
> generic_online_page()->__free_pages_core() will now clear that flag before
> handing that memory to the buddy.
> 
> Note that the page refcount is still 1 and would forbid offlining of such
> memory except when special care is take during GOING_OFFLINE as
> currently only implemented by virtio-mem.
> 
> With this change, we can now get non-PageReserved() pages in the XEN
> balloon list. From what I can tell, that can already happen via
> decrease_reservation(), so that should be fine.
> 
> HV-balloon should not really observe a change: partial online memory
> blocks still cannot get surprise-offlined, because the refcount of these
> PageOffline() pages is 1.
> 
> Update virtio-mem, HV-balloon and XEN-balloon code to be aware that
> hotplugged pages are now PageOffline() instead of PageReserved() before
> they are handed over to the buddy.
> 
> We'll leave the ZONE_DEVICE case alone for now.
> 
> Signed-off-by: David Hildenbrand <david@redhat.com>

Acked-by: Oscar Salvador <osalvador@suse.de> # for the generic
memory-hotplug bits


-- 
Oscar Salvador
SUSE Labs

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ZmgEPgjyG4EfYkNM%40localhost.localdomain.
