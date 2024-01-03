Return-Path: <kasan-dev+bncBCO3JTUR7UBRBS5O2SWAMGQERZY4H4Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x138.google.com (mail-lf1-x138.google.com [IPv6:2a00:1450:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id 3E3AC82295A
	for <lists+kasan-dev@lfdr.de>; Wed,  3 Jan 2024 09:14:06 +0100 (CET)
Received: by mail-lf1-x138.google.com with SMTP id 2adb3069b0e04-50e7f717704sf5041809e87.3
        for <lists+kasan-dev@lfdr.de>; Wed, 03 Jan 2024 00:14:06 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1704269645; cv=pass;
        d=google.com; s=arc-20160816;
        b=LvOZUe1+ixQJN8yl9aHHMIUpw/CgvWWGdLcXc8BwttDO+bNSUUP4P6gFn8nLwC/I+8
         10lK+5xgi3NITQF3CIHuLy6sWxeel0lTpLzFgL+88G1JAMtPdSVUQTFN8XgVu7cu7538
         MEuFyp6y5XhbS8weBYBKZh8r7jUAj6jDwlNNY1q9or/53T57P4gdC2pfvuP649SxNw9D
         SAaITGwpVTYvLR4QrbY+qHRCnxP/ogAIagMP29syNa/lzvIUiomHwQztBhWByspiIJh9
         sZji/WcssWGr6pX9qEGg7c+FvTdLPbIRnY1v9NASK3YM5w/Av+ZkuelON2NsEUyuSa5d
         vhAQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=4RNICaMy2MahYjhIEgjTgh+/anov6eHv9jqYOnMMuX0=;
        fh=uYnjiVNxbW5kI0u75v8U/Y/ao7NQ4m8EfWg99NPaynw=;
        b=HJxMgA5NbJepF92p07wQTe92SLaOvjcApNlGnHF1xwqXyA7RkkS6DIvlZpmvcmc/vF
         MvLs2FwehLx6E/vJ0+pZHreEUdcQK80Y8q1h2GXS9HXZs+P4An/4o1uaVMICz1WrW8hw
         8myZ55bKB3ajaEvgT+YzpZ58SExNJV0jpMDeGaa+RwE7terQQHEjdlFTEl7kHkZhDSeA
         mwmUvv+ChXfCJM+EO6NaskSZkzPcETWWse3o4F/nbkpDwXguteqwgRxGjgiTA5s5wTtz
         d5BtpwsMMWyhjvQyObo3p2zxFntqOJrTRftyKPrF6ozFE90pN3NKuePv5SZvqujKV9Ts
         yQkQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.de header.s=susede2_rsa header.b=c6DUitPQ;
       dkim=neutral (no key) header.i=@suse.de header.s=susede2_ed25519;
       dkim=pass header.i=@suse.de header.s=susede2_rsa header.b=HlW+xlJ2;
       dkim=neutral (no key) header.i=@suse.de header.s=susede2_ed25519;
       spf=pass (google.com: domain of osalvador@suse.de designates 195.135.223.131 as permitted sender) smtp.mailfrom=osalvador@suse.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=suse.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1704269645; x=1704874445; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=4RNICaMy2MahYjhIEgjTgh+/anov6eHv9jqYOnMMuX0=;
        b=BCrBsND174n0SsHXA6bR6xQjyVsZDuEvSGeq0arW3Dlwb6G/6pfRiHN7VrzjFE1XMx
         SR7Un7j/ZjB0vmOq2FB9CTKL0HbnWF0m6TNjyQ2O8EclUbtM5/Ryd18IKM7cjdSfAetl
         bwJ9jzi0FgPP9xg09bJH8nryYgDfcgMjDi8BhZaLFbGVvlknIa1fGuZBi5cNtvJeHnWV
         qFkgZilfwd7B8EjNyVOH2KX3tTbtovuj7nrU3XxjYYHaNA1xiWBrx50xrs4TU56ZYlVx
         NHHGD6PF39ZjalCc2wFTKaemmRFrUXMN5kXhWTXf+/7Ooc72Ht/Cctwg0GTF+V9iC6hy
         BAVw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1704269645; x=1704874445;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=4RNICaMy2MahYjhIEgjTgh+/anov6eHv9jqYOnMMuX0=;
        b=UN1D7fV5v3LMIjpyKQ+jGBF0jjW3jrnhQplGyp0sJ9o0D701QQFNPON+7z6Q1OvE8H
         xCzxa9kfYfl4PEGc6RSoauubj/8Ti+ZE+fmH5q/2JU69j/fe5Zt5VS6KIgwUAUjzVZ75
         tMw4L0GHBk80Bi6EmuxazXkWcsn+0K4vnAeqKq4kZTfmcKiUKu2sfYBVPWZjpqaiKYHj
         RR1wP+v6XTYKNri14r0Z/t5JcwFd2NsOx4Q78ygiBVtsjdCwpE7UcD5cFmPnwcRl9rfx
         UX0kBtlfFnqrbXiX049nscbyUhjt3x7FV5VOYDd96RCwwdbkoRCmIXiIo0wRopvz9N6i
         GnYQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yzmqx3E9uhzshY8BipRU9jYxOPcaajvj0TQNscnCt1M2D5MF3JK
	lNE44l8uKbToY9SZjh5oy2Q=
X-Google-Smtp-Source: AGHT+IHt5wcMAg6rK0VIUnV3yIC4ZNbZ1q8XlK67CTFJlH+6StbJB4CKT3DLr3wE7aWUO2IQ2rNzDg==
X-Received: by 2002:a05:6512:931:b0:50b:fdc8:2a7 with SMTP id f17-20020a056512093100b0050bfdc802a7mr7062384lft.51.1704269644150;
        Wed, 03 Jan 2024 00:14:04 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:1591:b0:50e:84a7:4567 with SMTP id
 bp17-20020a056512159100b0050e84a74567ls410305lfb.2.-pod-prod-06-eu; Wed, 03
 Jan 2024 00:14:02 -0800 (PST)
X-Received: by 2002:a05:6512:280c:b0:50e:7b0a:9a30 with SMTP id cf12-20020a056512280c00b0050e7b0a9a30mr7488492lfb.3.1704269642141;
        Wed, 03 Jan 2024 00:14:02 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1704269642; cv=none;
        d=google.com; s=arc-20160816;
        b=dbiHHioHgc/Gtyhh5uERgPN3ny5If1k33OdYVap4YrIUyskQJ7xAoGxHOO58XikNiB
         xqTWRQaa644QLMZ3GPpPnE9WSpqcuBkuDT+EBEgnmm9O4F+1ffn6ZLlerQq8DU1U0tqu
         fnhmv069Cmki3l2/Cq8Xm7WkA9dyrRXs3QMd4wPN1grMVnackihvBzgbSVUT0papZVX/
         f6GS5LPllJ8WlWtQ6yHqboKhKnsj1nHH4720LFrN/50P2aVT85F5rL2zx8sKZ4A4ELUC
         s5QlE4+qcO0BvWczXim+R7mFG3sMX8UCn/IqNZrAohay7WGSAv5JURGIN0RYIYcJa3ow
         iIsQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature:dkim-signature
         :dkim-signature:dkim-signature;
        bh=EHzT6aEuunaF8l957oLeyQUzYLU5v+V8f8tLm26sh6Q=;
        fh=uYnjiVNxbW5kI0u75v8U/Y/ao7NQ4m8EfWg99NPaynw=;
        b=q2YsLhFDts8iXrTRE5QZw5pei2P+yVJDp9PRdbzlRb+s9DcQAroaeBhJ+P4E0W9KMr
         hP/TpcRVE39AptSmqG7Z4IUCLIHr0EeznZtpQQDAfXVLXkGchMvhA8Aqd7GkdgiFKuMn
         7za2awlei9CasD6kLD72ySwJHxCo5qA7w33JDYrLdxGwFX8o8/AqP9qx5NoMwARi1GnH
         8QqvYHKp/PvMwX/+mWrVlV7lM8tDRVqj65lwaxvwAP3Z6YvJEZhVh36dUmZZV/WPn1XS
         EflaHKixjI7owdbwxIgPyVFcwXhKiETs9WQC1h5zcFs1wGB1lHEvFcdO7qAa/2hzc6re
         /U/w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.de header.s=susede2_rsa header.b=c6DUitPQ;
       dkim=neutral (no key) header.i=@suse.de header.s=susede2_ed25519;
       dkim=pass header.i=@suse.de header.s=susede2_rsa header.b=HlW+xlJ2;
       dkim=neutral (no key) header.i=@suse.de header.s=susede2_ed25519;
       spf=pass (google.com: domain of osalvador@suse.de designates 195.135.223.131 as permitted sender) smtp.mailfrom=osalvador@suse.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=suse.de
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [195.135.223.131])
        by gmr-mx.google.com with ESMTPS id y27-20020a19915b000000b0050e9f50087esi213654lfj.1.2024.01.03.00.14.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 03 Jan 2024 00:14:02 -0800 (PST)
Received-SPF: pass (google.com: domain of osalvador@suse.de designates 195.135.223.131 as permitted sender) client-ip=195.135.223.131;
Received: from imap1.dmz-prg2.suse.org (imap1.dmz-prg2.suse.org [10.150.64.97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id 1C6341F798;
	Wed,  3 Jan 2024 08:14:00 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id 4E2851340C;
	Wed,  3 Jan 2024 08:13:59 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id SfDJD0cXlWWaWgAAD6G6ig
	(envelope-from <osalvador@suse.de>); Wed, 03 Jan 2024 08:13:59 +0000
Date: Wed, 3 Jan 2024 09:14:49 +0100
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
Subject: Re: [PATCH v4 01/22] lib/stackdepot: print disabled message only if
 truly disabled
Message-ID: <ZZUXeSTWneflnRn6@localhost.localdomain>
References: <cover.1700502145.git.andreyknvl@google.com>
 <73a25c5fff29f3357cd7a9330e85e09bc8da2cbe.1700502145.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <73a25c5fff29f3357cd7a9330e85e09bc8da2cbe.1700502145.git.andreyknvl@google.com>
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
	 DBL_BLOCKED_OPENRESOLVER(0.00)[linux.dev:email,suse.de:email];
	 FUZZY_BLOCKED(0.00)[rspamd.com];
	 FROM_EQ_ENVFROM(0.00)[];
	 MIME_TRACE(0.00)[0:+];
	 FREEMAIL_CC(0.00)[linux-foundation.org,gmail.com,google.com,suse.cz,googlegroups.com,kvack.org,vger.kernel.org];
	 RCVD_TLS_ALL(0.00)[];
	 BAYES_HAM(-0.00)[40.46%]
X-Spam-Score: -0.10
X-Spam-Flag: NO
X-Original-Sender: osalvador@suse.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.de header.s=susede2_rsa header.b=c6DUitPQ;       dkim=neutral
 (no key) header.i=@suse.de header.s=susede2_ed25519;       dkim=pass
 header.i=@suse.de header.s=susede2_rsa header.b=HlW+xlJ2;       dkim=neutral
 (no key) header.i=@suse.de header.s=susede2_ed25519;       spf=pass
 (google.com: domain of osalvador@suse.de designates 195.135.223.131 as
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

On Mon, Nov 20, 2023 at 06:46:59PM +0100, andrey.konovalov@linux.dev wrote:
> From: Andrey Konovalov <andreyknvl@google.com>
> 
> Currently, if stack_depot_disable=off is passed to the kernel
> command-line after stack_depot_disable=on, stack depot prints a message
> that it is disabled, while it is actually enabled.
> 
> Fix this by moving printing the disabled message to
> stack_depot_early_init. Place it before the
> __stack_depot_early_init_requested check, so that the message is printed
> even if early stack depot init has not been requested.
> 
> Also drop the stack_table = NULL assignment from disable_stack_depot,
> as stack_table is NULL by default.
> 
> Fixes: e1fdc403349c ("lib: stackdepot: add support to disable stack depot")
> Reviewed-by: Marco Elver <elver@google.com>
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

Reviewed-by: Oscar Salvador <osalvador@suse.de>

-- 
Oscar Salvador
SUSE Labs

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ZZUXeSTWneflnRn6%40localhost.localdomain.
