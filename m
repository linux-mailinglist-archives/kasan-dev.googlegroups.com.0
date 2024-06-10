Return-Path: <kasan-dev+bncBCO3JTUR7UBRBHUCTKZQMGQEHAGONOI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23f.google.com (mail-lj1-x23f.google.com [IPv6:2a00:1450:4864:20::23f])
	by mail.lfdr.de (Postfix) with ESMTPS id D379C9019BD
	for <lists+kasan-dev@lfdr.de>; Mon, 10 Jun 2024 06:29:20 +0200 (CEST)
Received: by mail-lj1-x23f.google.com with SMTP id 38308e7fff4ca-2ebe82e96e4sf3162111fa.0
        for <lists+kasan-dev@lfdr.de>; Sun, 09 Jun 2024 21:29:20 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1717993760; cv=pass;
        d=google.com; s=arc-20160816;
        b=eZnQxSgZHxrt1/hD4mPDqP01070hRE2TQaGELd4hz7CtBFuAjCr5vQPI4tZmuHDC/s
         mq0uKq4zeTiWrBo5eE/tuo7bBsJ25JCGq/k81I8Xm9kNYO7cXIm7XbCqkSzCNGUVazKr
         +2wxDFCEAEYDNq3tkoCEP3ZJJBTb6Zdv2WoBQYdOuxDtPnDhHELVpv7yw34ctcQxai5+
         czaNcUV62CrqdOrHiIXuCu0QNJlU7oCRkBRuNkQS8gSOzYuNlhj91v/s7XMKuFl0p1o2
         nUCGVpZek1LsWm9VYAtU9K6Ndveac7stGIPMKf4DxET2i50vuqnkGYLdADotb9gP0uK6
         7phQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=wvR713A6A0D7Y0YIi5RAezTTFrjzrKZ6t8SyLokDOKU=;
        fh=12PoeDrDsDfxXzZK6Qzivkc9gIPV9uU8L/DBvSmjqJ0=;
        b=I3ldMByvFFxY3/TwyIrJQ80um7J3A/N8QgdiQGN0ap4sqGrSncTx54Z5Mk8RDRF4CE
         bDyFayg6/sEIg8Hxdh+fwN8EOtQe8sAX0l3NNguFIzsO5DnKjM6SBAQb5Rqt9DhXrnRp
         4/b8dkK/4a0K9nu9inkg/9Xv09/Sg3lZFU+ARZF1rLgJ+GdZrrcfazmcJd8JvdsC1DFn
         MHW06skb9umAGsNHNysJFY25mHZeXVoMRKoPeqeU5CzNfmzdPRX/rKUi43/nzJc+3aC+
         ISQQgI3qByO2+k0XdovsAO4wTwCWah+yif8otBARgrwM3DrdBP3zKbCvbfmY06CZlBu1
         Etnw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.de header.s=susede2_rsa header.b=ouS1aMbV;
       dkim=neutral (no key) header.i=@suse.de header.s=susede2_ed25519 header.b=xMKg0LFz;
       dkim=pass header.i=@suse.de header.s=susede2_rsa header.b=ouS1aMbV;
       dkim=neutral (no key) header.i=@suse.de header.s=susede2_ed25519;
       spf=pass (google.com: domain of osalvador@suse.de designates 195.135.223.131 as permitted sender) smtp.mailfrom=osalvador@suse.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=suse.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1717993760; x=1718598560; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=wvR713A6A0D7Y0YIi5RAezTTFrjzrKZ6t8SyLokDOKU=;
        b=GRg09+iDtw9eZ1C6uwjuLKBf/lslZYHiN+Mm7MvolXpIJXbkbZ9TpQKxMf4bktY/Yr
         UKi1G7DCC7uBVPoGW/yIUkziLxbJxTNj3RP93X2YHYTgh5hpGkjQntjF4qYd1/jsQ/2M
         2cvnB2gDA2I3KrEXSUVHSaDob5f1iymVIYxLJ48NITODFZRw+y/Zk6ze2YIn0hmRbuUU
         hKDr9M+sn94IRv0c3+nrHF+avhe96dSusrjRphszwYcDbZvZ83Ksa8XwcU10AUjAX9eb
         KLS1ixm+cgX5oK8ADKOkTOShL6xPafILrx/tRJqAcIoLUnPBjxgDY31yYSZzIFsN70T6
         jPVw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1717993760; x=1718598560;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=wvR713A6A0D7Y0YIi5RAezTTFrjzrKZ6t8SyLokDOKU=;
        b=aQzSbIyk68YYpcBtrcEjPS+kSseWHcQA9MsXqk0gdnshI/dFVQETZLZIJ5Zk/Q7bEx
         wz1DyneQtGPK3D0sbyWx/11FyRCfllrVs1KFZ+5lx+dhikH6rCs04BFC1hHyL2aYiJJw
         1HKXi2BcFc/jACyetOlO3yRf3FBDRiSWFlx8JpcS37XQTV3Vk5FXVW+OGxiH5qWsjZHx
         yoVni/80bb2QJskgMYelg2kXXS/ISvvJiPzJYV6sBO+yEvebD0aOqCLRLKylE/pOFJu4
         BKkQs6LSWWMlohDJhBB1cnF1w3XNl0qHeLNv5sJlXGuwJt1oGaUJLpk+XXpX+WFYIHSk
         7CWA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXJQpUf7QfNzhjlsV0gm4BgkVuYgOmuBbIkwBl80X82b4drAIJDVKtS77yNDzv6Py57RmaaYN7uEGksBk76KYbqojFPUqGBSA==
X-Gm-Message-State: AOJu0YyzMTDvuwkgg8AU6qnAgg36VAu+xVjnNRAJeHIeczO4/P82svoT
	xgzKbXehn/ZN7Q0OKKs7QIaRCthxcax2AbnDMQK4vHCM+Lb4mPJc
X-Google-Smtp-Source: AGHT+IEoi9wSUN6m3gqo5zSbBopPlCvTLv56D3vbyYGFMuaNCbHj6SjN62Q+M6CWUPEWRtGmk1ZrVw==
X-Received: by 2002:a2e:968e:0:b0:2ea:eb13:daca with SMTP id 38308e7fff4ca-2eaeb13dc4bmr35551241fa.47.1717993759318;
        Sun, 09 Jun 2024 21:29:19 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:2db:b0:2ea:f437:4e01 with SMTP id
 38308e7fff4ca-2eaf43754a4ls9073171fa.0.-pod-prod-07-eu; Sun, 09 Jun 2024
 21:29:17 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCX/be6YFiGlyrcGL8+MXHtrleUlFWiDV47P/whaIdF6JitGhkjcT6rHWNyAx/rmW8KrsQx06DFj7dGNPwIB2FbonJrE6XNvwxmXPA==
X-Received: by 2002:a2e:88c6:0:b0:2ea:8291:c667 with SMTP id 38308e7fff4ca-2eadce24b75mr45687521fa.13.1717993757321;
        Sun, 09 Jun 2024 21:29:17 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1717993757; cv=none;
        d=google.com; s=arc-20160816;
        b=P3/ZroGaV4/SIl0lJ/4IBw41vnC5BZWxoDwTJ+7OyIaVOfv1+skPqVMTUaMHwlwkb0
         nhRuqu5II8iE0Fayhr3+ztKJUT0IUkiyQvhnCccgcUPsdhpDZRuHp6VTLZyBfHb30E6P
         l+YL6Nm+nIogB5Zw9nvji5xathbnJIaXbtyGCQPgpT7g1MWrhp/qTrUNNG9B+Ue7fACe
         5ExJqlvv5UvhTuzvXenikmBChN9WbdyzbKmT6uVqw0DBBmvLqGJVUSXIeZHXPtmb1LHi
         Q/8/BgNrjfQWqjRf2sIkImIeFTXIfTvJUChJgNTx+jCxa9CZhdE2485vFMFjNz2keAJm
         0jfQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature:dkim-signature
         :dkim-signature:dkim-signature;
        bh=dZ0M1mMkyIQjD9GHv7ILLIsJEt6S/v29bdhzDaDdHV0=;
        fh=opXV1WEp03kbeubOZloyb10FoNtntQdRllRWblbVMRI=;
        b=0bJlvggsDndmPI8UCqKuFGOt5RXF/LOEbC4kDPqUGeYHZTz74RCIlbv/guy6ypvSMw
         AiKhIW++7pvowaUeC6pJ+tIWGx679TTO1pDQlQD5lUE1o3YvCu5XcoquIaiEqfYZ1J5x
         jm4MLoK67u3A/C0s4HbZed3oJxtJK/JPAlnfzPtOx96s6Jfv3uiqlnSTP8B4IFP+nspq
         eCK1z2BagicqioXM7u2R4D7KIPSFulqf+G8EI+8+AlrFsSI2F8c6FnJLf49tfPf2KZhd
         J5G131LufCc7tcoLh8673DewW2zVA3PWmqS3+WmfUQpLMp/fep0+KorZin5ogy8xE2sA
         LurA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.de header.s=susede2_rsa header.b=ouS1aMbV;
       dkim=neutral (no key) header.i=@suse.de header.s=susede2_ed25519 header.b=xMKg0LFz;
       dkim=pass header.i=@suse.de header.s=susede2_rsa header.b=ouS1aMbV;
       dkim=neutral (no key) header.i=@suse.de header.s=susede2_ed25519;
       spf=pass (google.com: domain of osalvador@suse.de designates 195.135.223.131 as permitted sender) smtp.mailfrom=osalvador@suse.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=suse.de
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [195.135.223.131])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-2ebe234ed4fsi510611fa.3.2024.06.09.21.29.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sun, 09 Jun 2024 21:29:17 -0700 (PDT)
Received-SPF: pass (google.com: domain of osalvador@suse.de designates 195.135.223.131 as permitted sender) client-ip=195.135.223.131;
Received: from imap1.dmz-prg2.suse.org (unknown [10.150.64.97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id 6FD4C1F76E;
	Mon, 10 Jun 2024 04:29:16 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id 4E42513A7F;
	Mon, 10 Jun 2024 04:29:15 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id IEF7EBuBZmYbGAAAD6G6ig
	(envelope-from <osalvador@suse.de>); Mon, 10 Jun 2024 04:29:15 +0000
Date: Mon, 10 Jun 2024 06:29:13 +0200
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
Subject: Re: [PATCH v1 3/3] mm/memory_hotplug: skip
 adjust_managed_page_count() for PageOffline() pages when offlining
Message-ID: <ZmaBGSqchtEWnqM1@localhost.localdomain>
References: <20240607090939.89524-1-david@redhat.com>
 <20240607090939.89524-4-david@redhat.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20240607090939.89524-4-david@redhat.com>
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
	DBL_BLOCKED_OPENRESOLVER(0.00)[imap1.dmz-prg2.suse.org:helo,suse.de:email]
X-Spam-Score: -4.30
X-Spam-Flag: NO
X-Original-Sender: osalvador@suse.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.de header.s=susede2_rsa header.b=ouS1aMbV;       dkim=neutral
 (no key) header.i=@suse.de header.s=susede2_ed25519 header.b=xMKg0LFz;
       dkim=pass header.i=@suse.de header.s=susede2_rsa header.b=ouS1aMbV;
       dkim=neutral (no key) header.i=@suse.de header.s=susede2_ed25519;
       spf=pass (google.com: domain of osalvador@suse.de designates
 195.135.223.131 as permitted sender) smtp.mailfrom=osalvador@suse.de;
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

On Fri, Jun 07, 2024 at 11:09:38AM +0200, David Hildenbrand wrote:
> We currently have a hack for virtio-mem in place to handle memory
> offlining with PageOffline pages for which we already adjusted the
> managed page count.
> 
> Let's enlighten memory offlining code so we can get rid of that hack,
> and document the situation.
> 
> Signed-off-by: David Hildenbrand <david@redhat.com>

Acked-by: Oscar Salvador <osalvador@suse.de>

-- 
Oscar Salvador
SUSE Labs

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ZmaBGSqchtEWnqM1%40localhost.localdomain.
