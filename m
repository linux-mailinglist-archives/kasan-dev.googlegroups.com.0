Return-Path: <kasan-dev+bncBCO3JTUR7UBRB6FQ2SWAMGQEKJKRNDA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x140.google.com (mail-lf1-x140.google.com [IPv6:2a00:1450:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id 07F7E82296A
	for <lists+kasan-dev@lfdr.de>; Wed,  3 Jan 2024 09:19:07 +0100 (CET)
Received: by mail-lf1-x140.google.com with SMTP id 2adb3069b0e04-50e7ae03f5csf5227962e87.2
        for <lists+kasan-dev@lfdr.de>; Wed, 03 Jan 2024 00:19:07 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1704269946; cv=pass;
        d=google.com; s=arc-20160816;
        b=nxneC9uGbjNCJpeJhM/q8oiD9ddosSQMX6IPLzWjlk1Ue/42h+o4a733F7aE7GjP76
         N853isUXfArf52awEYNNWNlzwixp0oSw/euRVRV7OKjMxbSZajv1uUEuA4SmZAQ6/2UI
         dGA++3twftZaEE9xc4X7ltJlc7dR9mItCUt4m5PEUgzQ2wJEq7ju6cW7HTxWXpYT4KUj
         4TqNeX5i7q9RuDDOzkU5XplIxXOQvY3eiMf6RNO/1eS7Jm0D5pbIBq6ASQDlvonbXcSS
         FYH7AYRtiBzgAlGYGZWirDNUs8oRO9cO0rUZEWl6FJOePbwnVkcwHtgrTsFvaI6PzHIV
         mmpg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=KHq/2gmUkGPxSxbTs9CL4K62ootnr8pZhBbmyJoC+tc=;
        fh=uYnjiVNxbW5kI0u75v8U/Y/ao7NQ4m8EfWg99NPaynw=;
        b=p6Z+unSdGi1RKSssdc+D5bUTctDTwoDL2SunoH9156O4xIiToNRwgpyWSbuDzDgANv
         dC1ap93yatOj/rva9V8d0LShJ/wwW4Ul1Rf0ljMxd7gwr6WDQHvpYqXN2tpIe6X+NSP6
         ko2KSTbuzqphMmW/l4lLUTf5nDMLwNvBt67gdNwZFXuHCQWp1uBPd3hQP0QSZttN3Kvq
         1NGKbmzU/yGFJ7EALJ0tR3sWhrKMwEq4Lw69dEBfwO/6WYbSCwwJEbDtKb+lM+LtAKUB
         RREfC0or61LZyuHIrkiHuJ0Lor3YpyAz0/Vrooyn3EH6dbKLgkSR0zXxY1lMKfZ7QdvT
         XXWw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.de header.s=susede2_rsa header.b=1fiIcHij;
       dkim=neutral (no key) header.i=@suse.de header.s=susede2_ed25519;
       dkim=pass header.i=@suse.de header.s=susede2_rsa header.b=1fiIcHij;
       dkim=neutral (no key) header.i=@suse.de header.s=susede2_ed25519;
       spf=pass (google.com: domain of osalvador@suse.de designates 195.135.223.131 as permitted sender) smtp.mailfrom=osalvador@suse.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=suse.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1704269946; x=1704874746; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=KHq/2gmUkGPxSxbTs9CL4K62ootnr8pZhBbmyJoC+tc=;
        b=GOmy4FWJCkV+qhgMNjLSl/hnmO8mYJBUpdMNl+ABNqDIDxeydzWazjiuCrhSZTUiB3
         It4Ij8FICZstu9Xp+XcT32bTKPVp7tuyXDf5H8i5yH2jNQl7KAa/qL9OU7e2+R2ny+eH
         tZeanM57+uNPiCCq/2j9llgXx04au58DtTgSkwNACXq8F0qOAiCBLjhFmOxdUO7AyzAI
         QfeBNuW55G97EwkdyG1A5dOSsyD95AoKqp0OofxBRiQtW/x57WbFtLEoIvvqP1534erg
         2Zg7yZ9PRD7qLtv1BZAIgamnqSIw+xR/gGVXh0hL8BFnmpY1IorlgkeSmEsqUdJ/iW1D
         9/6Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1704269946; x=1704874746;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=KHq/2gmUkGPxSxbTs9CL4K62ootnr8pZhBbmyJoC+tc=;
        b=IUOUNm+jD5kdw9YnJbbLJuhVbCeRhUduVv+b2hp+5FR3fbAYKB/ipaXuTNVJxhAkTh
         Eyntv9PyvSRDTBVfu3fKSg6gN7JpU3m+XEBeggZw0QCkw1ciYG2c+2Q3Zl6gElU/Hwa5
         vI3GiVwcPRfZVxDMGpmt7GOHoqBqWE/UTQJoLwAOVq60vZK5RJgi5Y9vkzWiIvu0i3VR
         4mcJ8EvBO06T/G3jPBz6bFv9zgBO+hPIA5HtSZSmdpWve1bfqQaStjeYmemzsTjSvK8w
         nd+I9EqKSkFSt9aBeJ0UHG6Vkry/fxWXrlh+n9JceyhNM/t01cTTHWlwmorzeEgN1Ia4
         SubQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YwtcXelGl+YaTFXrYcztBICZMbnO7u1FeKj9IpdC70fatJU1UuU
	a1vzorGG+uQMmVJNINpxh5c=
X-Google-Smtp-Source: AGHT+IElcAvvjP7aL0vepJ1gBOam9n8nGRxvuG47ejE+1TkoFfOqDy9HkCY5yGCZBn4PbDpBXo4amA==
X-Received: by 2002:a05:6512:505:b0:50e:298d:29cb with SMTP id o5-20020a056512050500b0050e298d29cbmr8082535lfb.116.1704269945174;
        Wed, 03 Jan 2024 00:19:05 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:b83:b0:50e:6b52:2452 with SMTP id
 b3-20020a0565120b8300b0050e6b522452ls1329045lfv.0.-pod-prod-01-eu; Wed, 03
 Jan 2024 00:19:03 -0800 (PST)
X-Received: by 2002:a05:6512:968:b0:50e:55bb:a453 with SMTP id v8-20020a056512096800b0050e55bba453mr8044772lft.3.1704269943188;
        Wed, 03 Jan 2024 00:19:03 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1704269943; cv=none;
        d=google.com; s=arc-20160816;
        b=M7ti6AAiiDdkPozrHFho01PcdU8oEcCIYSeURI/iR76ks5ghiBvfPoGtwtRRv2rhXV
         Hffv1SF/OycQAa1Uvlmp0TsP6usiz5sfZ51JX0tXFndBdeFRfswJJyX4hC7D7T8OKHG1
         c0lfeDlXkrv1TRV+Htp1KwehgXztX1L7bQbyjeq6VrDyHW236II3SCOd52+F8SHfgJ8k
         5egH6HQCdEVhenirkYE2XmCdAcEIh2JtZvL7aNryxygnOIV/CvHg+YMP2J656/pvOlBp
         iCg5cNtIGSGFQkxXbs7llaWa4rdYVDtYgsxEAuTsb0xDiXxN/90U1xW9huKT6S4FDfQ6
         tiuA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature:dkim-signature
         :dkim-signature:dkim-signature;
        bh=V9esiW43PFp1nOnTYVzDQBW7TFJkdqXost6VpQW1eec=;
        fh=uYnjiVNxbW5kI0u75v8U/Y/ao7NQ4m8EfWg99NPaynw=;
        b=CXabO35rJLbCD9LDDOa5Cdl/NqGKPjO29+LB92yCRBtolxKcd0AxFjDp186wpAYEfU
         F6Bp3ucRgJTw2ic10p8TECcn/6y0hALBBlfLW/T7JehEAC1OfoVZRI5kJ9O4sth1Yshh
         2NBAVj4BKFYP5RRrqNQuUtj3HF1XD5EuT55uOFb/c1u/G0WniVvVZRPhUcChR35+OUTb
         UpUYXeyQe+IwnRYf/d3XpqDrwr4DCNHYn/OaqHhYFNeUWPnbLdCGQTdjepkQ0etLqCaO
         nxlfaJgmH7INArh1Ea83RhAZAhUzMoW9+ixFsgqjUL6VsbgydUzl3CifltyDrq46QooD
         k0Wg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.de header.s=susede2_rsa header.b=1fiIcHij;
       dkim=neutral (no key) header.i=@suse.de header.s=susede2_ed25519;
       dkim=pass header.i=@suse.de header.s=susede2_rsa header.b=1fiIcHij;
       dkim=neutral (no key) header.i=@suse.de header.s=susede2_ed25519;
       spf=pass (google.com: domain of osalvador@suse.de designates 195.135.223.131 as permitted sender) smtp.mailfrom=osalvador@suse.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=suse.de
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [195.135.223.131])
        by gmr-mx.google.com with ESMTPS id t3-20020a195f03000000b0050e6b19b855si1247389lfb.11.2024.01.03.00.19.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 03 Jan 2024 00:19:03 -0800 (PST)
Received-SPF: pass (google.com: domain of osalvador@suse.de designates 195.135.223.131 as permitted sender) client-ip=195.135.223.131;
Received: from imap1.dmz-prg2.suse.org (imap1.dmz-prg2.suse.org [10.150.64.97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id 5950B1F79B;
	Wed,  3 Jan 2024 08:19:02 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id A6D5C1340C;
	Wed,  3 Jan 2024 08:19:01 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id pYkFJnUYlWXsWwAAD6G6ig
	(envelope-from <osalvador@suse.de>); Wed, 03 Jan 2024 08:19:01 +0000
Date: Wed, 3 Jan 2024 09:19:52 +0100
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
Subject: Re: [PATCH v4 03/22] lib/stackdepot: simplify __stack_depot_save
Message-ID: <ZZUYqIOqjbSjxSft@localhost.localdomain>
References: <cover.1700502145.git.andreyknvl@google.com>
 <3b0763c8057a1cf2f200ff250a5f9580ee36a28c.1700502145.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <3b0763c8057a1cf2f200ff250a5f9580ee36a28c.1700502145.git.andreyknvl@google.com>
X-Spam-Level: 
X-Spam-Level: 
X-Spamd-Result: default: False [-0.44 / 50.00];
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
	 DBL_BLOCKED_OPENRESOLVER(0.00)[suse.de:email];
	 FUZZY_BLOCKED(0.00)[rspamd.com];
	 FROM_EQ_ENVFROM(0.00)[];
	 MIME_TRACE(0.00)[0:+];
	 FREEMAIL_CC(0.00)[linux-foundation.org,gmail.com,google.com,suse.cz,googlegroups.com,kvack.org,vger.kernel.org];
	 RCVD_TLS_ALL(0.00)[];
	 BAYES_HAM(-0.34)[76.25%]
X-Spam-Score: -0.44
X-Spam-Flag: NO
X-Original-Sender: osalvador@suse.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.de header.s=susede2_rsa header.b=1fiIcHij;       dkim=neutral
 (no key) header.i=@suse.de header.s=susede2_ed25519;       dkim=pass
 header.i=@suse.de header.s=susede2_rsa header.b=1fiIcHij;       dkim=neutral
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

On Mon, Nov 20, 2023 at 06:47:01PM +0100, andrey.konovalov@linux.dev wrote:
> From: Andrey Konovalov <andreyknvl@google.com>
> 
> The retval local variable in __stack_depot_save has the union type
> handle_parts, but the function never uses anything but the union's
> handle field.
> 
> Define retval simply as depot_stack_handle_t to simplify the code.
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ZZUYqIOqjbSjxSft%40localhost.localdomain.
