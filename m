Return-Path: <kasan-dev+bncBCO3JTUR7UBRBRF42SWAMGQEH6E2JNQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x340.google.com (mail-wm1-x340.google.com [IPv6:2a00:1450:4864:20::340])
	by mail.lfdr.de (Postfix) with ESMTPS id 88A4C8229A7
	for <lists+kasan-dev@lfdr.de>; Wed,  3 Jan 2024 09:43:49 +0100 (CET)
Received: by mail-wm1-x340.google.com with SMTP id 5b1f17b1804b1-40d91478247sf1963965e9.2
        for <lists+kasan-dev@lfdr.de>; Wed, 03 Jan 2024 00:43:49 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1704271429; cv=pass;
        d=google.com; s=arc-20160816;
        b=ysQLaQijIvRdwcUYnh2BRO3F+LdD5diFauMetLVvtrFd969BOzs30uKAGqiOnX8Z7i
         14SRFyGBVrco0gc/BEXJvnYXekvHquZi7f/lVhyTClLNMgOAHJ20fiA9yvGfEZinFhAh
         B8qEa8RR53XmAXV5be9pzUUrGktcKbz93EzuP2iBk6L5n3ARwuZyuzFVmg1+FSBMyEx6
         TeVt9QxZOGFj1AAh0HKAJiF7QBVgSPGoEbjUGEShsZR2tQlirA5EjmqAXDE++6noIIyK
         1n8mE28cagh6q3NPfFRxt2ATKR4GBvjfeUBA/gsBacVmNzzK1KnRLeUu5e2Fn+8ngccb
         OMiA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=LeJKwZY4h6zQpcwZ4+vkrSob6CxSGWRV8Ygp915iHlM=;
        fh=uYnjiVNxbW5kI0u75v8U/Y/ao7NQ4m8EfWg99NPaynw=;
        b=b7nvmXAzkZAESrKwV74+Gb4k0QQ6JrEJQ57z/mRN/V1IbwOf2ENiYQlcXf1/Q7iHZZ
         g2kJwumOUJ1DyMbtmHz+bxC3J0vpof/I/Q/bkQ9TQ/8RRks5ONA3uj0vpNksadB4ilqh
         FaNot+OUkol9ybq/32oSqgd95R3tO4Tv07in5q1Whrs5kgOngcte0h42+0sTJBqo2e8g
         tsiTLUp5sD0ObAaRa8E1ZSjkSHizmRO6KVCmylruubwq1j2RFWY5I5QIAy+w0oZGGrZT
         uvhQ6K7ciF92ruh5orpabneC6+VK2dEm6YJOn4/iL8BexzCr9ov0pW1ADnBbyz4EpkeV
         NDjg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.de header.s=susede2_rsa header.b=efssd6kr;
       dkim=neutral (no key) header.i=@suse.de header.s=susede2_ed25519;
       dkim=pass header.i=@suse.de header.s=susede2_rsa header.b=KCLEnSxJ;
       dkim=neutral (no key) header.i=@suse.de header.s=susede2_ed25519;
       spf=pass (google.com: domain of osalvador@suse.de designates 195.135.223.130 as permitted sender) smtp.mailfrom=osalvador@suse.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=suse.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1704271429; x=1704876229; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=LeJKwZY4h6zQpcwZ4+vkrSob6CxSGWRV8Ygp915iHlM=;
        b=ekbczuTWXeQPvXjqqjj80aFtcQer/ULSf6w+XJp2t3RQVEY9PYxv1Vec3zL90znXd6
         yshjjEOAsRT6Brqmvz1G4gaambxDZOp4/XlebryFKf0cKVPlSeLIV4xnhohkFUAMnLYj
         PHwSKc1ucPxvuQzL1azFvclDqmrii6nmq7PpJFmkik/aoism/Hl3/zZlwmQKEzoi4ovp
         qcxRh1Oq1lBcwY0ZfOrcdFFsbQ8m7vXAUwZXDn3q+3t3koRxBWUfriE1kQBMXh1sRa5M
         5kMcYQgg+svUgji/hSNaPTNcGq+mRkEl9Rl7scmB3EeGX/6snPakj6ercrdIA3G7VsCx
         HKHg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1704271429; x=1704876229;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=LeJKwZY4h6zQpcwZ4+vkrSob6CxSGWRV8Ygp915iHlM=;
        b=S40Ghu0YzHV0peTTFgEGRc/Xa2BSLWok6TOz10aMQDQujv1JK38dGwLnYz1ZWO69bS
         Db4eUIZ8+MMRE8XpENU/S/hhdAXQsClKikhlkEIlv0V6c4i72EV0aNLdp2qF24dFgx8A
         1f0I849FX6NVkIWDG/6JtMtpKVkGKXGnI9s6B9MZv75FsSUKS8FLQMblQSQpAslfalOQ
         FDs7lW7AVesvTMdqTov30tdxYj8IAILiHRT+EYHJDCSSiVPcHnZ5qSkNVMT8JM7Go5ui
         0St+v9PZ4gHq1g8hZDBW9tFY82vGyTKKIZ0arvcdXVz0YstoIiUKYysr7004wxxY/wcT
         O2gQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YzyYSIrp6PNz4ta0tiBEuQHisSTFRCGRAv0Eiq09xMDlIh4M2c1
	4xICw3xGSY62eDLtq1vtpAc=
X-Google-Smtp-Source: AGHT+IHJuDDhjTX4YSTQil1CbTtTThm549EkkkwxEAR6GKouGZvE8qGOt+nBa+Qmx0uuWfRLHobXbQ==
X-Received: by 2002:a05:600c:364f:b0:40d:71bd:37e1 with SMTP id y15-20020a05600c364f00b0040d71bd37e1mr4052633wmq.61.1704271428830;
        Wed, 03 Jan 2024 00:43:48 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:468e:b0:40d:2bc7:eb4 with SMTP id
 p14-20020a05600c468e00b0040d2bc70eb4ls3679709wmo.1.-pod-prod-06-eu; Wed, 03
 Jan 2024 00:43:47 -0800 (PST)
X-Received: by 2002:a05:600c:1c93:b0:40d:3571:cc13 with SMTP id k19-20020a05600c1c9300b0040d3571cc13mr11051182wms.9.1704271427099;
        Wed, 03 Jan 2024 00:43:47 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1704271427; cv=none;
        d=google.com; s=arc-20160816;
        b=i2wuc1QiMNcnpUTfcXjGxBTQbEz8DWb4KYmu9s1D8TKSE+Abh1E3/GGWwmvUwJVwfy
         pIlyFPGMhWbQc2X7I78aXCMYbmqvCsdkoSwMHFo0DjKhprcIUSlJpv8npQ82XaBJRujU
         nl514Wo66w6dZYexgxu7CAKVZ689RcDLjJm64SAN0KktocCYtPDwVpfBuRm+Y8HvFB9y
         7kRMuMS9ZcrQ5xLfNSP/NzIPB12QJNJE3hQmsx19shnXzsb1PFwZWiI5lwSDRuLzdSrF
         Uw4AsbLQPNd+yDyYplU4d7icPNEelCvkqs0joRIWVRCBZ+8WAMabC/A6jIcPr81XqZMG
         lfjg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature:dkim-signature
         :dkim-signature:dkim-signature;
        bh=Zux5DXsqyH6BF4yrGNwF3g4Ah5PlzMOsxiJLSpjUelg=;
        fh=uYnjiVNxbW5kI0u75v8U/Y/ao7NQ4m8EfWg99NPaynw=;
        b=hqYYZ4W1+OdxjSR3zIhYmolAmDwq7H/6vSXAuqonsYcwYT+kFq49al0seJpu7m89EE
         cw5LWufAOszyhhGJdkKtXt+5wQ3+jbPejkRpaeiD9GdZNvh01rwDpc7OtdW4ObtCYlGL
         Ze5aPTSJUC1uxCwSoITw/VGkzMjs3Z7Qo3iNAN5Fak4Tk6UWD1OPGHeipGvuYd2uO6hB
         wvI9p0mOpZHve0GVK6q/VF1jqIz5+OJ2MzAibHz5TLNOxap38cOcAQvLE/S5gqrH+OK4
         bfbJFJodMb1okIGN9+9jF4RepC3tEPnSoixNr5IWCIGuJYRdnY0rywT6xKBx1PEmfwuM
         oATQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.de header.s=susede2_rsa header.b=efssd6kr;
       dkim=neutral (no key) header.i=@suse.de header.s=susede2_ed25519;
       dkim=pass header.i=@suse.de header.s=susede2_rsa header.b=KCLEnSxJ;
       dkim=neutral (no key) header.i=@suse.de header.s=susede2_ed25519;
       spf=pass (google.com: domain of osalvador@suse.de designates 195.135.223.130 as permitted sender) smtp.mailfrom=osalvador@suse.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=suse.de
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [195.135.223.130])
        by gmr-mx.google.com with ESMTPS id p30-20020a05600c1d9e00b0040a25ec1ce5si36791wms.0.2024.01.03.00.43.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 03 Jan 2024 00:43:47 -0800 (PST)
Received-SPF: pass (google.com: domain of osalvador@suse.de designates 195.135.223.130 as permitted sender) client-ip=195.135.223.130;
Received: from imap1.dmz-prg2.suse.org (imap1.dmz-prg2.suse.org [IPv6:2a07:de40:b281:104:10:150:64:97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id 9A91D21EE8;
	Wed,  3 Jan 2024 08:43:44 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id E44B31340C;
	Wed,  3 Jan 2024 08:43:43 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id uGD7ND8elWV2YgAAD6G6ig
	(envelope-from <osalvador@suse.de>); Wed, 03 Jan 2024 08:43:43 +0000
Date: Wed, 3 Jan 2024 09:44:30 +0100
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
Subject: Re: [PATCH v4 09/22] lib/stackdepot: rename next_pool_required to
 new_pool_required
Message-ID: <ZZUebp1YZKzIN0VN@localhost.localdomain>
References: <cover.1700502145.git.andreyknvl@google.com>
 <fd7cd6c6eb250c13ec5d2009d75bb4ddd1470db9.1700502145.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <fd7cd6c6eb250c13ec5d2009d75bb4ddd1470db9.1700502145.git.andreyknvl@google.com>
X-Spam-Level: 
X-Spam-Level: 
X-Rspamd-Server: rspamd2.dmz-prg2.suse.org
X-Spamd-Result: default: False [-4.36 / 50.00];
	 RCVD_VIA_SMTP_AUTH(0.00)[];
	 SPAMHAUS_XBL(0.00)[2a07:de40:b281:104:10:150:64:97:from];
	 TO_DN_SOME(0.00)[];
	 RCVD_COUNT_THREE(0.00)[3];
	 DKIM_TRACE(0.00)[suse.de:+];
	 MX_GOOD(-0.01)[];
	 NEURAL_HAM_SHORT(-0.20)[-1.000];
	 FROM_EQ_ENVFROM(0.00)[];
	 MIME_TRACE(0.00)[0:+];
	 BAYES_HAM(-2.85)[99.38%];
	 ARC_NA(0.00)[];
	 R_DKIM_ALLOW(-0.20)[suse.de:s=susede2_rsa,suse.de:s=susede2_ed25519];
	 FROM_HAS_DN(0.00)[];
	 FREEMAIL_ENVRCPT(0.00)[gmail.com];
	 TO_MATCH_ENVRCPT_ALL(0.00)[];
	 MIME_GOOD(-0.10)[text/plain];
	 NEURAL_HAM_LONG(-1.00)[-1.000];
	 DKIM_SIGNED(0.00)[suse.de:s=susede2_rsa,suse.de:s=susede2_ed25519];
	 RCPT_COUNT_TWELVE(0.00)[12];
	 DBL_BLOCKED_OPENRESOLVER(0.00)[suse.de:dkim,suse.de:email,linux.dev:email];
	 FUZZY_BLOCKED(0.00)[rspamd.com];
	 FREEMAIL_CC(0.00)[linux-foundation.org,gmail.com,google.com,suse.cz,googlegroups.com,kvack.org,vger.kernel.org];
	 RCVD_TLS_ALL(0.00)[]
X-Spam-Score: -4.36
X-Rspamd-Queue-Id: 9A91D21EE8
X-Spam-Flag: NO
X-Original-Sender: osalvador@suse.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.de header.s=susede2_rsa header.b=efssd6kr;       dkim=neutral
 (no key) header.i=@suse.de header.s=susede2_ed25519;       dkim=pass
 header.i=@suse.de header.s=susede2_rsa header.b=KCLEnSxJ;       dkim=neutral
 (no key) header.i=@suse.de header.s=susede2_ed25519;       spf=pass
 (google.com: domain of osalvador@suse.de designates 195.135.223.130 as
 permitted sender) smtp.mailfrom=osalvador@suse.de;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=suse.de
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

On Mon, Nov 20, 2023 at 06:47:07PM +0100, andrey.konovalov@linux.dev wrote:
> From: Andrey Konovalov <andreyknvl@google.com>
> 
> Rename next_pool_required to new_pool_required.
> 
> This a purely code readability change: the following patch will change
> stack depot to store the pointer to the new pool in a separate variable,
> and "new" seems like a more logical name.
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ZZUebp1YZKzIN0VN%40localhost.localdomain.
