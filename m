Return-Path: <kasan-dev+bncBCO3JTUR7UBRBH7WTGZQMGQEEA4QDCA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x438.google.com (mail-wr1-x438.google.com [IPv6:2a00:1450:4864:20::438])
	by mail.lfdr.de (Postfix) with ESMTPS id AEE0B9019A2
	for <lists+kasan-dev@lfdr.de>; Mon, 10 Jun 2024 06:03:45 +0200 (CEST)
Received: by mail-wr1-x438.google.com with SMTP id ffacd0b85a97d-35f1dde2ee5sf614412f8f.3
        for <lists+kasan-dev@lfdr.de>; Sun, 09 Jun 2024 21:03:45 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1717992225; cv=pass;
        d=google.com; s=arc-20160816;
        b=yD0vcy72AJG5kYZGcoeW1zSpwc536C8bPrtgQ6SKoCWcCwEH2fS1wbvfRLSkQeP/lu
         2DAkZPJE44sJAarrL/a/50X2Fja8ZxIgCRUI0AF2db3+3tkUmOjoLlE76au5ttT63R8e
         3dNwJNs7n067f9mHJSDTvp/ItfJIOqMOXTQEAeECpH+qYEQ7Q7Bhr8Zu//AaaEAbpeYT
         8IG6xvS9bEs+XCvSg0MHmDY79nR5foqhgDvtGg6qhl72DV42asl6/8lK+q0qyt/p9TBl
         qcatvpDiWD5ipt3eAysDBZ5eWWNtZAmCbz6Bwn5iPuVYQA1wwzltanfudSRliqFAA+tf
         7nKA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=OB15qRry+obMSGcjyaF3QjQu87KsFCsexyqtGqMQlCI=;
        fh=sX9weYaEzbfpzEcTAIpa7XYu4nGxI8pda6dE+Hc5I1A=;
        b=Fds3uSvw5eRxreCzWMGXggLZKE7Vi2sArHPikH9scUWt6iQEq/WEqzXtKdx/Fk57D1
         14qTIvN9ohC/qEg1JyB+gkqLuiF8y0LaVCO8QvX0wPMOW58tiN3l96VDecrQl3597bPa
         utDf7HYz2vV5MZ5uHzC3qI2XfLRNr8kRocytkDYFpH9hnwOD6l8GSlBqIbX9kxHCbeSe
         eFncV3MNyx09W4uK0yU2Lufx7DIrAmR2TYAGP9HeSVzUimEIGYrDHx+M99+98/E2aWnh
         Vl73U2zYIoodmPe1yxy3ZBotLqGJ0FT07Wb4b8dP4tgv1yExdcVSAOMsS/T+bZ0kAriD
         Vb2A==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.de header.s=susede2_rsa header.b=ydtYYv4z;
       dkim=neutral (no key) header.i=@suse.de header.s=susede2_ed25519;
       dkim=pass header.i=@suse.de header.s=susede2_rsa header.b=ydtYYv4z;
       dkim=neutral (no key) header.i=@suse.de header.s=susede2_ed25519;
       spf=pass (google.com: domain of osalvador@suse.de designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) smtp.mailfrom=osalvador@suse.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=suse.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1717992225; x=1718597025; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=OB15qRry+obMSGcjyaF3QjQu87KsFCsexyqtGqMQlCI=;
        b=DrnzTpzISr52ToDJQGLbtujGRVJdlHPsb1m37IVnsg0TqbM5yo1iUU4NwBqai9/qOU
         nLyvstJtAtk6vkCHg0LjO3BZB0ngYmi7PMf3kJjFl1oHf51cg9r9bYe0RmXMydtWclBr
         AI5Ov0yp6FwgfDBPBaEZDVuwLkPXiRiSX11dX0oTPuUbKiOqJspe+s0vRprlAtxag8TE
         cEY5WYrtF4Twa8RVxZtHWXbli5Zc0YUYGl+QvaI5YLon5vhgRVWMADYzRTO0kUy2Ylb1
         KUDQc2UZ3CxeGt4YjEjZR8C3YcLhPKRh1JNEEn+vYuwHoCN11PzsrADRvRrvZSDzmgKa
         bwPQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1717992225; x=1718597025;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=OB15qRry+obMSGcjyaF3QjQu87KsFCsexyqtGqMQlCI=;
        b=u6z4cGWMDZHnkoA08xaPsWwGLqqF/ue9S9iR16UOXLiKozp4QTViTqp4Iz2Opw3bZz
         MPbGc5kEOkiG1hfJadYCUX6oKt70idg+lm2mGcNk3C+RFikV8yJGMdbCyoCMlAQ0+tAp
         E8zrclG7GhgZDNZ+wlPMbB/UlKSUlEtPO7aNX90v67pEMyLZymu+gZGiPl8HGr/XgHKx
         gy3oRltLMby3SDBBr2IDPaRAXYC3B8r39naUy07QEA1rxWQ/oZOKVORfaeSDT/JFM6el
         UsJEvYgLRRgwhtLROQQ/8j+NkBTvGHqWxOKaBVotr8zWeZE+gWGyp810rFDJHlodcXcZ
         Ac/g==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVl7qbRThAk/dZFwyQLOoMgmk1TepRdkIYsjZYmEr/vfTVLme8KfOiHVawItlYU1GT5/HAejYBqGZYUaV9Ck2MQe1TwP8sTBg==
X-Gm-Message-State: AOJu0YxMpNDCpbSwiEqM7Qo/6/VdmtbMya+A2xe4iydVpfaHd498Ce93
	GOXr/pxDNq4HpzLePhH4cA2BxmB+Ryn0jNb58edSX+882RB7eQgV
X-Google-Smtp-Source: AGHT+IFWKFYgw7/qG8stf86TjJSwCkIXJ+yXhUk7oZF0QRvRhqNFbTeziDS4J+Ycp+vIH619g7qV4w==
X-Received: by 2002:a5d:59ae:0:b0:35f:2471:198a with SMTP id ffacd0b85a97d-35f24711a69mr925729f8f.4.1717992224025;
        Sun, 09 Jun 2024 21:03:44 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:e70b:0:b0:35f:b57:e1c9 with SMTP id ffacd0b85a97d-35f0b57e309ls793252f8f.0.-pod-prod-02-eu;
 Sun, 09 Jun 2024 21:03:42 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCU4a00+KavU7BfybsWo2dxx6MYIuPNqETdp8CzNtelcIkIGfjnA+atEzHM+SaQhtKxWuSbXlHl07q1Dh0N+D9mzWB6tffzH3m5TRg==
X-Received: by 2002:a05:600c:46ce:b0:421:8179:610f with SMTP id 5b1f17b1804b1-42181796305mr24966745e9.34.1717992221808;
        Sun, 09 Jun 2024 21:03:41 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1717992221; cv=none;
        d=google.com; s=arc-20160816;
        b=thSxfD+FA5aAUtagfJcDNKbs1twQgXnecY2p6qyDXREq5eRjRM6Nu9N51lQ1BnAdqp
         aCFg/D5kN6cgShPWd44EDSHLnHlwa1mgoyA8gAoCv0gKp433SmBdv71qWzuaI+7HBWEf
         xVo/n0tdEHEEOwz7so0Fri9ZjqNXhVvk43tzAjPvjiflfMG4qvFCQ5vQ9dnhIncHxp3b
         PAVUOt9bA6BCaZFArFnse8lN4+z/Mu7lUUkcusgdYLUNr6hJQMtDJ7H/f46HOAKKJE+5
         9uki5Uy9aUUTEdZ+J0OJzJMtjfhKLTv3xE2ansTqnxwJrjWY4vkgJb6v25avfno98HGV
         NNew==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature:dkim-signature
         :dkim-signature:dkim-signature;
        bh=IYHZUWJMx20LtuFCKKBR+s4SdF/zVxwDIU/zuxJyVpA=;
        fh=opXV1WEp03kbeubOZloyb10FoNtntQdRllRWblbVMRI=;
        b=ieqRGv8NC6Uo7/iO0EQGUutleEUybVcbt4or18mzmyJ5EYxN8PYkr4giQICqp6K/45
         glVjy+2r/h7zj/35YZ/z1NqHabwmYX9SvV/H6ZTAHLv6H/8AFdeTqEyWVgvPUT7zjIS6
         7Edyqse5t6aNYmcdMBpQ3zO0lZUu1fC6OhLoMZVdFlUhnrNSVjxlWqgrirATZs+BI1Qr
         NeLIKQm3bQBATUVca0Z0aFv7gBtgd4Htr1vsew/iUT1pUtdV7VuRl+NwgpiFO+wP3pxY
         86+CD9T402IySN/pCXcrhI/gjh3iYzTucNQcYLsm1GY9iVAWroDbHOjx6zB/+L/f52tM
         ZaYg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.de header.s=susede2_rsa header.b=ydtYYv4z;
       dkim=neutral (no key) header.i=@suse.de header.s=susede2_ed25519;
       dkim=pass header.i=@suse.de header.s=susede2_rsa header.b=ydtYYv4z;
       dkim=neutral (no key) header.i=@suse.de header.s=susede2_ed25519;
       spf=pass (google.com: domain of osalvador@suse.de designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) smtp.mailfrom=osalvador@suse.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=suse.de
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [2a07:de40:b251:101:10:150:64:2])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-421802c68bdsi2163425e9.1.2024.06.09.21.03.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sun, 09 Jun 2024 21:03:41 -0700 (PDT)
Received-SPF: pass (google.com: domain of osalvador@suse.de designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) client-ip=2a07:de40:b251:101:10:150:64:2;
Received: from imap1.dmz-prg2.suse.org (unknown [10.150.64.97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id 48E781F74B;
	Mon, 10 Jun 2024 04:03:41 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id 2ECBB13A85;
	Mon, 10 Jun 2024 04:03:40 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id K/XmCBx7ZmbzEgAAD6G6ig
	(envelope-from <osalvador@suse.de>); Mon, 10 Jun 2024 04:03:40 +0000
Date: Mon, 10 Jun 2024 06:03:38 +0200
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
Subject: Re: [PATCH v1 1/3] mm: pass meminit_context to __free_pages_core()
Message-ID: <ZmZ7GgwJw4ucPJaM@localhost.localdomain>
References: <20240607090939.89524-1-david@redhat.com>
 <20240607090939.89524-2-david@redhat.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20240607090939.89524-2-david@redhat.com>
X-Spam-Flag: NO
X-Spam-Score: -4.30
X-Spam-Level: 
X-Spamd-Result: default: False [-4.30 / 50.00];
	BAYES_HAM(-3.00)[99.99%];
	NEURAL_HAM_LONG(-1.00)[-1.000];
	NEURAL_HAM_SHORT(-0.20)[-1.000];
	MIME_GOOD(-0.10)[text/plain];
	RCVD_VIA_SMTP_AUTH(0.00)[];
	ARC_NA(0.00)[];
	MIME_TRACE(0.00)[0:+];
	MISSING_XM_UA(0.00)[];
	RCPT_COUNT_TWELVE(0.00)[23];
	RCVD_TLS_ALL(0.00)[];
	DKIM_SIGNED(0.00)[suse.de:s=susede2_rsa,suse.de:s=susede2_ed25519];
	FUZZY_BLOCKED(0.00)[rspamd.com];
	FROM_HAS_DN(0.00)[];
	TO_DN_SOME(0.00)[];
	FROM_EQ_ENVFROM(0.00)[];
	TO_MATCH_ENVRCPT_ALL(0.00)[];
	RCVD_COUNT_TWO(0.00)[2];
	DBL_BLOCKED_OPENRESOLVER(0.00)[imap1.dmz-prg2.suse.org:helo]
X-Original-Sender: osalvador@suse.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.de header.s=susede2_rsa header.b=ydtYYv4z;       dkim=neutral
 (no key) header.i=@suse.de header.s=susede2_ed25519;       dkim=pass
 header.i=@suse.de header.s=susede2_rsa header.b=ydtYYv4z;       dkim=neutral
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

On Fri, Jun 07, 2024 at 11:09:36AM +0200, David Hildenbrand wrote:
> In preparation for further changes, let's teach __free_pages_core()
> about the differences of memory hotplug handling.
> 
> Move the memory hotplug specific handling from generic_online_page() to
> __free_pages_core(), use adjust_managed_page_count() on the memory
> hotplug path, and spell out why memory freed via memblock
> cannot currently use adjust_managed_page_count().
> 
> Signed-off-by: David Hildenbrand <david@redhat.com>

All looks good but I am puzzled with something.

> +	} else {
> +		/* memblock adjusts totalram_pages() ahead of time. */
> +		atomic_long_add(nr_pages, &page_zone(page)->managed_pages);
> +	}

You say that memblock adjusts totalram_pages ahead of time, and I guess
you mean in memblock_free_all()

 pages = free_low_memory_core_early()
 totalram_pages_add(pages);

but that is not ahead, it looks like it is upading __after__ sending
them to buddy?


-- 
Oscar Salvador
SUSE Labs

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ZmZ7GgwJw4ucPJaM%40localhost.localdomain.
