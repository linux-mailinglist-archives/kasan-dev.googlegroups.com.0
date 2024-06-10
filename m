Return-Path: <kasan-dev+bncBCO3JTUR7UBRBU6PTOZQMGQENH5WNNA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33a.google.com (mail-wm1-x33a.google.com [IPv6:2a00:1450:4864:20::33a])
	by mail.lfdr.de (Postfix) with ESMTPS id D921B9020A5
	for <lists+kasan-dev@lfdr.de>; Mon, 10 Jun 2024 13:47:32 +0200 (CEST)
Received: by mail-wm1-x33a.google.com with SMTP id 5b1f17b1804b1-42181b5a099sf1684645e9.0
        for <lists+kasan-dev@lfdr.de>; Mon, 10 Jun 2024 04:47:32 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718020052; cv=pass;
        d=google.com; s=arc-20160816;
        b=yE9SYm8Q6IuVRxCAF/gw2DNkKw6aTdNShfoIk0PNBEEt3MGwnm/Qe4iwleDpztOihG
         IIfk3CndHA8Fiu0I3NDTRFcIS1eiyxNnD8RoTaBZ12SDiElkRxfXpy5ha8wRPyrZuC+U
         g42dAXLSuEhnAKClYS+W7gH8b2B3UgCo7BJt9P/DIbYM5nezWvpSLNPxDl3a54Irwh9+
         Z8aihzgY5oKexwIb7or0f87XUxVCSgIhJ2qKZAY9pnppl2d7G+YlhZ+1mlsUfFlW3+ab
         Yb4zU+spgFZ73gemI89HAcdXI6NSYEZjVTJmFo5HxnjrVLsOzUVWo1FMQgHNtUZIHq25
         cXEg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=Stwao5JdE0II9hSv5TTH4sPDEMlxT6rwO92Vsyo/IMk=;
        fh=RT99P5Rf5CLYrdBM6HQtLovHy5t+r8VAN++Q1VJTtEI=;
        b=D5t/RhhulW8BHht6uCxSBnCQ+gLljJJrrkcs97dByTXHQP7S8nitKThU0evP04HVwB
         0yHn4FYzOWQfw1l4kD15NhuXAf2cKZ+SARPzJ74DpBEkYej85EfnacyT3WLRAJ4oxJZU
         FRIVrzEuPLYjuiUabTYZrpy8Kba+aidPXltYRMByBZKAqutJMLwMFqTsyPgGvzVjzZQa
         QmYi7UIWMTwTYeoG6tZMYlqhnNksbiyFoYizTDDzs/+AsDoxkTlN9LTg5TVy7AblYvKi
         dtsDGGzZAQe+0IUy3rbfBgzfzAFv1Y4IrWbSLDxluEaiw2XB7wN10GSmUj3cgiHsFyPy
         AfCA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.de header.s=susede2_rsa header.b="jQO+Qx/4";
       dkim=neutral (no key) header.i=@suse.de header.s=susede2_ed25519;
       dkim=pass header.i=@suse.de header.s=susede2_rsa header.b="jQO+Qx/4";
       dkim=neutral (no key) header.i=@suse.de header.s=susede2_ed25519;
       spf=pass (google.com: domain of osalvador@suse.de designates 195.135.223.130 as permitted sender) smtp.mailfrom=osalvador@suse.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=suse.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718020052; x=1718624852; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=Stwao5JdE0II9hSv5TTH4sPDEMlxT6rwO92Vsyo/IMk=;
        b=SKl2zz7hKai+D15qGaqdPSZZzBqwaIR7NE2MJvqxXsXOG0cIDZb+/MizrCwvSHnJRC
         ToE8MbCLs6cFfZSX8J3lw7ZSFbJbAj6iUVrissiGcLd0+25CFitOmd4Cqm4uITcvX1+o
         wjbKVJBvS+05KTfaQgzrJeAUHXaZLB4rgYKLEeiDfcFl5xOyqatfWqw9FYiXvHo/0eU8
         w37rtA3c7tB7sgTPEbtnDXnlaEsdye3MgIylqYG0zsxmxV4R+FXDl3dzckHUzhrxSOpQ
         OjnwWJ29TYSddeogqLgm0au/g78hbf67zUinar3W8ql+M53fp9O/bZ5308kGwhbpdsCN
         Q5hQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718020052; x=1718624852;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=Stwao5JdE0II9hSv5TTH4sPDEMlxT6rwO92Vsyo/IMk=;
        b=v+RI0c+Dx/pLVZWbXDhpAqkFgMO+BCf+AVp6qQ/EPBivSm6y3wx2fJRTr2oRWTxh8S
         E+DannkPSu3AYNDDPdmcOGE3jI9lj5HWCJ3eEhQNhrqJb7efPW6sVjVKiP4hcMOadGHS
         C+kWeT7iV5pb+qPAFssnFcpV/lGRVOgSKf9i2ENj8EnGPK95Xwro50ONd5MhOBMSC/ZV
         FKC9YFw/Kb3BSr27HW5XFo4MSz+8UAk3yLyAYf/Xb38nNlTSLpBNazzbP4sP6RuNJlKw
         v7shrzqYgIvqR223Gm+Jkdga4e+ZGF9l401X/I1iCXAQLioLGf9SHtoK3QhaYvNqeiqU
         XTQg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWXj2eEpoEK98pqTczc3n1OB9i21saJz/aJcS6rH2jBMNZYzzJcBYLqHVENgF95BctrVX7+XY8gBJUbbU4SHy3GVDEqdOOeWg==
X-Gm-Message-State: AOJu0YyR/envBHPyAI5Nt224aMfKkgh2oCljuIMm0jT6GbFfBlRY0mv9
	aCQ0gzZyQWFf94fL93I3qoQzHz/NUIS0aceceSo999GJNg3b2g0m
X-Google-Smtp-Source: AGHT+IFTUbEqkRxOn6oP2Ip/rJyI3hGBzkvvkMSYG980nQ62a3QC1BVFWNqECebQkYOz3SX6H9EFIA==
X-Received: by 2002:a05:600c:1d9b:b0:421:6c54:3a8 with SMTP id 5b1f17b1804b1-4217c482e63mr2622595e9.7.1718020051662;
        Mon, 10 Jun 2024 04:47:31 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:1d01:b0:422:1589:d81c with SMTP id
 5b1f17b1804b1-4221589dbc1ls1085905e9.2.-pod-prod-03-eu; Mon, 10 Jun 2024
 04:47:30 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWEKsbD+hFHUCqpIwW1/vVicTY6eF/d7ubEh1cF7UlO7XtJaYqQ3lfAzv30NhcPpvmxL6v0XlLcHPPYQBvqa5Gfr2keUwxPCxG0zA==
X-Received: by 2002:a05:600c:198c:b0:421:819c:5d6b with SMTP id 5b1f17b1804b1-421819c5fdamr28013075e9.23.1718020049837;
        Mon, 10 Jun 2024 04:47:29 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718020049; cv=none;
        d=google.com; s=arc-20160816;
        b=tRBCXaNH8Z+tz7Idm33rLdJlrmSiqcgTLQUP4n+pAxNVHcH03arNggbNEL4GrPLB7v
         fW8lSEBvMYSRWs9koZPfuyt0e6e7ate3Xzt9W4Qr3dgRzZqx9juL4PdNEqviA5BFSrc6
         WRMTpPnawBk7+ZGZjQMpWW+RMa0LghICIXiEZQvokeLQB/k+ZODSLhfRIhKCRisp/tX9
         TMnGrOLRGmEQlcR6UaA9F+lgjs5cM+TWNOj2OMwvLq3KagPX2zmeKt/UyGs6kyItJzxu
         HrBP3pw2M49d3NJaF71cynEz6M5lUHnAVciRM2S0qIqrsbfu4Yk5vGnZD+kvEoc9gz3p
         3/LQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature:dkim-signature
         :dkim-signature:dkim-signature;
        bh=WJbUj0Me5/uIhq7+KJarpD1i6Sf3idu2woFatetNcL0=;
        fh=opXV1WEp03kbeubOZloyb10FoNtntQdRllRWblbVMRI=;
        b=gzGlJvQ45BReEqdxbDTbPsHogU2KlRcQCBc7rkNM3XgWcvdT2pchG1jODSznUJCLov
         8KGgZkCseORFo7HHFvfT31WXO1odkd8AmshnrokReEYGqqTChmMOk6oHNzsvO4TVmg2S
         v4r6t6HIXinOjTkRA74TEf8+owmJa1tCA+xXMq5Ab5IY2RuGB/69aZoTK757jnsSYmni
         c/rCdykXkZw2DzK0zU5dyrNLnj1c6MKhqUVm28AQsvxeM/e+B+AgC9xNL2TIFjJMeo4a
         qJ+ZK6VEhWluUuaHorL8a699ZX1YDz2BHtEmT/oidRCu4TKHcXTwYVV9CwGxZPZqiHp3
         txgQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.de header.s=susede2_rsa header.b="jQO+Qx/4";
       dkim=neutral (no key) header.i=@suse.de header.s=susede2_ed25519;
       dkim=pass header.i=@suse.de header.s=susede2_rsa header.b="jQO+Qx/4";
       dkim=neutral (no key) header.i=@suse.de header.s=susede2_ed25519;
       spf=pass (google.com: domain of osalvador@suse.de designates 195.135.223.130 as permitted sender) smtp.mailfrom=osalvador@suse.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=suse.de
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [195.135.223.130])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-421802c68bdsi2684775e9.1.2024.06.10.04.47.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 10 Jun 2024 04:47:29 -0700 (PDT)
Received-SPF: pass (google.com: domain of osalvador@suse.de designates 195.135.223.130 as permitted sender) client-ip=195.135.223.130;
Received: from imap1.dmz-prg2.suse.org (unknown [10.150.64.97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id 8172421A5B;
	Mon, 10 Jun 2024 11:47:29 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id 6843213A7F;
	Mon, 10 Jun 2024 11:47:28 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id 5brfFtDnZmbLFQAAD6G6ig
	(envelope-from <osalvador@suse.de>); Mon, 10 Jun 2024 11:47:28 +0000
Date: Mon, 10 Jun 2024 13:47:18 +0200
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
Message-ID: <ZmbnxrOuoarMbC6X@localhost.localdomain>
References: <20240607090939.89524-1-david@redhat.com>
 <20240607090939.89524-2-david@redhat.com>
 <ZmZ7GgwJw4ucPJaM@localhost.localdomain>
 <13070847-4129-490c-b228-2e52bd77566a@redhat.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <13070847-4129-490c-b228-2e52bd77566a@redhat.com>
X-Spam-Level: 
X-Spamd-Result: default: False [-4.30 / 50.00];
	BAYES_HAM(-3.00)[100.00%];
	NEURAL_HAM_LONG(-1.00)[-1.000];
	NEURAL_HAM_SHORT(-0.20)[-0.993];
	MIME_GOOD(-0.10)[text/plain];
	ARC_NA(0.00)[];
	MISSING_XM_UA(0.00)[];
	MIME_TRACE(0.00)[0:+];
	RCVD_VIA_SMTP_AUTH(0.00)[];
	RCVD_TLS_ALL(0.00)[];
	DKIM_SIGNED(0.00)[suse.de:s=susede2_rsa,suse.de:s=susede2_ed25519];
	FUZZY_BLOCKED(0.00)[rspamd.com];
	FROM_HAS_DN(0.00)[];
	RCPT_COUNT_TWELVE(0.00)[23];
	FROM_EQ_ENVFROM(0.00)[];
	TO_MATCH_ENVRCPT_ALL(0.00)[];
	RCVD_COUNT_TWO(0.00)[2];
	TO_DN_SOME(0.00)[]
X-Spam-Score: -4.30
X-Spam-Flag: NO
X-Original-Sender: osalvador@suse.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.de header.s=susede2_rsa header.b="jQO+Qx/4";
       dkim=neutral (no key) header.i=@suse.de header.s=susede2_ed25519;
       dkim=pass header.i=@suse.de header.s=susede2_rsa header.b="jQO+Qx/4";
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

On Mon, Jun 10, 2024 at 10:38:05AM +0200, David Hildenbrand wrote:
> On 10.06.24 06:03, Oscar Salvador wrote:
> > On Fri, Jun 07, 2024 at 11:09:36AM +0200, David Hildenbrand wrote:
> > > In preparation for further changes, let's teach __free_pages_core()
> > > about the differences of memory hotplug handling.
> > > 
> > > Move the memory hotplug specific handling from generic_online_page() to
> > > __free_pages_core(), use adjust_managed_page_count() on the memory
> > > hotplug path, and spell out why memory freed via memblock
> > > cannot currently use adjust_managed_page_count().
> > > 
> > > Signed-off-by: David Hildenbrand <david@redhat.com>
> > 
> > All looks good but I am puzzled with something.
> > 
> > > +	} else {
> > > +		/* memblock adjusts totalram_pages() ahead of time. */
> > > +		atomic_long_add(nr_pages, &page_zone(page)->managed_pages);
> > > +	}
> > 
> > You say that memblock adjusts totalram_pages ahead of time, and I guess
> > you mean in memblock_free_all()
> 
> And memblock_free_late(), which uses atomic_long_inc().

Ah yes.

 
> Right (it's suboptimal, but not really problematic so far. Hopefully Wei can
> clean it up and move it in here as well)

That would be great.

> For the time being
> 
> "/* memblock adjusts totalram_pages() manually. */"

Yes, I think that is better ;-)

Thanks!
 

-- 
Oscar Salvador
SUSE Labs

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ZmbnxrOuoarMbC6X%40localhost.localdomain.
