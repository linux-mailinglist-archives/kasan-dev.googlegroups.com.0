Return-Path: <kasan-dev+bncBCO3JTUR7UBRBI7QYWMAMGQERH45JAA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33f.google.com (mail-wm1-x33f.google.com [IPv6:2a00:1450:4864:20::33f])
	by mail.lfdr.de (Postfix) with ESMTPS id C26D55AA652
	for <lists+kasan-dev@lfdr.de>; Fri,  2 Sep 2022 05:27:36 +0200 (CEST)
Received: by mail-wm1-x33f.google.com with SMTP id v3-20020a1cac03000000b003a7012c430dsf2257065wme.3
        for <lists+kasan-dev@lfdr.de>; Thu, 01 Sep 2022 20:27:36 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1662089251; cv=pass;
        d=google.com; s=arc-20160816;
        b=tbaFzTipr+5KifeTZldWNjghvOWioP7P+n1ZExVcUh2/g6HaVDuAtDfpv6MQbK0HFr
         Kl8Aeh1ncj/DuR8a+9cbBz+x4Av8TIc1daHRFhe9Qiy3xYoYKFMUpCP8hgc7b0d9fcvd
         JYBx3cn4KbyZo1ZTuyE9YTrE58SJ+J9MjOknUcVOybB90jb5OFYAcpDuovn9QfAxySOI
         9GG45kVTymTmI64DAOYsE13/Wx+CNGpIeUkQyYRkYKU/HdTULK+6oZkQnd+iOIBTdnst
         Ecvhdb8jV0Y/XSodjwWTZQuBPpTKMo4BkyfDTA1L8C+wyV5xJqNnNVOtd8M2ciAQu+88
         Pl0g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=ZfK3Jce0OzKW4nzuOHnIu+X31Uxi5H40OQ1x+/MbawA=;
        b=n7w6wFmnI2AwvtUcwcC4Q5RBddxEwchMyTx6ekH6/DNWaLfLkkjw9xtIag/QePdGuK
         6jXcVR5IzMbe/HyKxbSVt5s7JSBCzZ/zdAo/FZFeVmgmxH89kXFHp/320nCr4ssT6mW0
         MVA3p+stik3khS58jje4ycXMi3KNsOx9OZ09ijlZVl0pf+yDljuWf/WKae9BCRwlD895
         U5jMq6HyJ2rcZCRTbwKtT2ztbqOpjx7A8kc/cpdJP0eSxwcIBEeGPBI0Tzo7LDEeMOxS
         HUXSoSJXkaSyTzUAdoy20iui5TAfwWhidtKKrBi3cyysf73RkJXeIoLkZy1dxJ5HIrTi
         N8gg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.de header.s=susede2_rsa header.b=c2i8KzQ8;
       dkim=neutral (no key) header.i=@suse.de;
       spf=pass (google.com: domain of osalvador@suse.de designates 195.135.220.29 as permitted sender) smtp.mailfrom=osalvador@suse.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=suse.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date;
        bh=ZfK3Jce0OzKW4nzuOHnIu+X31Uxi5H40OQ1x+/MbawA=;
        b=s20tZXgycJVohAU0xuZoK2cnOrTh/qdlAtGFLy3CsDrvlGDQ0a9uEsDkIoL1EJ2/FL
         KKAmQ9NnRGVE4om0+RdcF3JlhfeUJFuCgl0mTEsoB4Yk1OwaG0eCbFreDL5ArsfMzS6w
         AytYjNTxA5Q5fNzCV758VyTymE9Jx5DO7KPNl0LVpibODktOkgxUyYI7Z38gSeF+lkCA
         sXxwh8RLM56DWzRxPsjq5f59uRR3R/YQpwUMkG+diAbTEKm+FHrmVRqJ6COM4zzUUqUL
         AWZLYKsQstgezBOCbBelURwtTD2uHiATKpJ8ud7n7dAXjFCT6GZxVwPkkYNa4eYiLsXJ
         k9Gw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:sender:from:to:cc:subject:date;
        bh=ZfK3Jce0OzKW4nzuOHnIu+X31Uxi5H40OQ1x+/MbawA=;
        b=L+nikmkpqAiIi/9x7u1HfckLOSbQzUdp+6MnPqN86PFlAwaAQvM/2dLqpIiIWzhKDS
         TUUl39S7UwA5dAn+ojXQK5BcoHXtJNYHKaDFkyEF/lAgo8fz3NpCtBdxAdfATkkrlmfg
         wIoW8y0LGSpxXmB6PZk7muTKcmEOOEziJCTSanzEn9t40TpnvatpW8HJ6d3FMkrLiik3
         NY9+t82tLIKpjIslf+jPfN1QPPK2TGQvdN/jkmF2v1kLagJLDYxy4QAt21KfZdjFypMd
         SzMpWUZ6QaXBRXTnq6M+/hv0Dc1Cvu/atTCAZdN5bLQArcTgUgEq6jg6qK0IJCHfmz37
         G63w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACgBeo2MaBpAwMlUP+GfkOFuhrl1wammXIgQda85mJ7uZ4zmeaxRCi8g
	5ZqbT6l9+FlMw70PlHT/0bQ=
X-Google-Smtp-Source: AA6agR5/79wZlSjiGiAzAn+IgJNZ3ISsScxYT0IQ/JXPwJSALH3L0gRy/AtdU2XISODgrIaN+nyt9A==
X-Received: by 2002:a7b:cbd0:0:b0:3a6:9f6:a3e8 with SMTP id n16-20020a7bcbd0000000b003a609f6a3e8mr1195998wmi.13.1662089251193;
        Thu, 01 Sep 2022 20:27:31 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6000:247:b0:221:24a2:5cf with SMTP id
 m7-20020a056000024700b0022124a205cfls5652515wrz.0.-pod-prod-gmail; Thu, 01
 Sep 2022 20:27:30 -0700 (PDT)
X-Received: by 2002:a05:6000:100b:b0:226:d51d:8a76 with SMTP id a11-20020a056000100b00b00226d51d8a76mr14457249wrx.257.1662089250263;
        Thu, 01 Sep 2022 20:27:30 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1662089250; cv=none;
        d=google.com; s=arc-20160816;
        b=Cc5A/3N+iS10tVTJNnz129ZGO9RO1/CROuI3RszBh6adGutOPQnopZ1i5EN3sm/BgR
         jXYfxzKF+jYR/tyzs/lH/R/xxUxR8q+OUwr22/wJhryYmOO2RmX9eVav/O/P/98/UptS
         mbiMmJvp5ZKrUeVE/0fZtXQub5ZofR9HRmzMxyoFGRcPUygQzC1YVrL9vMayKvbgvXZu
         20+smIcSQHlysiSrgTX4P4quB7xpe0cWu6v9VmlTqVGD4KDGXimKiYK7MDArymi8kY/d
         wH68otZbp6t0//83msqYBdv9a89jjfiI4Ff1cNnS5A3kp65BkZo9PCDpEKzuPDpPgwJQ
         5sFQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature:dkim-signature;
        bh=GL6+2GXh/2nFgXmYIP+TgmK2lf7e53/uu6BPJeJrYkk=;
        b=c7s7Opc6BNnaP45odiAE6BxIx11+JW0+8o4sUpChTX6NiiFMRLOCJ1TJQ+WVFqIANi
         j5rP3nSYzQsjT09UF1nQX3sWCMdpEoooqtqAFJs5UUuzghHT+I5vovzHY9GJcW55+mrc
         XrLa7R9EAbdkBzwlcv0nQpQcJxEWTqCInf+3DpmZgGY//H/BiVAWt+kJQ6jq8bgcAJ0X
         k1iPdkm+X0wZRME6tGZa9nch8lv4j4NZhRQmZQLltU2wH3ENe6apDurXcXBLUSf5S1eJ
         QnO0qB/LgGdlquPA8zHHS17zW8N8TVYXlyISEJL57q8TWWPwF3v27UvT9CneoVrPdNPV
         1jeQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.de header.s=susede2_rsa header.b=c2i8KzQ8;
       dkim=neutral (no key) header.i=@suse.de;
       spf=pass (google.com: domain of osalvador@suse.de designates 195.135.220.29 as permitted sender) smtp.mailfrom=osalvador@suse.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=suse.de
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [195.135.220.29])
        by gmr-mx.google.com with ESMTPS id l3-20020a1ced03000000b003a5582cf0f0si66497wmh.0.2022.09.01.20.27.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 01 Sep 2022 20:27:30 -0700 (PDT)
Received-SPF: pass (google.com: domain of osalvador@suse.de designates 195.135.220.29 as permitted sender) client-ip=195.135.220.29;
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id E799E20A75;
	Fri,  2 Sep 2022 03:27:29 +0000 (UTC)
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by imap2.suse-dmz.suse.de (Postfix) with ESMTPS id 3D49B13328;
	Fri,  2 Sep 2022 03:27:29 +0000 (UTC)
Received: from dovecot-director2.suse.de ([192.168.254.65])
	by imap2.suse-dmz.suse.de with ESMTPSA
	id zr8aDCF4EWO9DAAAMHmgww
	(envelope-from <osalvador@suse.de>); Fri, 02 Sep 2022 03:27:29 +0000
Date: Fri, 2 Sep 2022 05:27:27 +0200
From: Oscar Salvador <osalvador@suse.de>
To: Marco Elver <elver@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, linux-kernel@vger.kernel.org,
	linux-mm@kvack.org, Michal Hocko <mhocko@suse.com>,
	Vlastimil Babka <vbabka@suse.cz>,
	Eric Dumazet <edumazet@google.com>,
	Waiman Long <longman@redhat.com>,
	Suren Baghdasaryan <surenb@google.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com
Subject: Re: [PATCH 1/3] lib/stackdepot: Add a refcount field in stack_record
Message-ID: <YxF4H5tu9cl9ePMD@localhost.localdomain>
References: <20220901044249.4624-1-osalvador@suse.de>
 <20220901044249.4624-2-osalvador@suse.de>
 <YxBsWu36eqUw03Dy@elver.google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <YxBsWu36eqUw03Dy@elver.google.com>
X-Original-Sender: osalvador@suse.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.de header.s=susede2_rsa header.b=c2i8KzQ8;       dkim=neutral
 (no key) header.i=@suse.de;       spf=pass (google.com: domain of
 osalvador@suse.de designates 195.135.220.29 as permitted sender)
 smtp.mailfrom=osalvador@suse.de;       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=suse.de
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

On Thu, Sep 01, 2022 at 10:24:58AM +0200, Marco Elver wrote:
> On Thu, Sep 01, 2022 at 06:42AM +0200, Oscar Salvador wrote:
> >  include/linux/stackdepot.h | 13 ++++++-
> >  lib/stackdepot.c           | 79 +++++++++++++++++++++++++++++++-------
> >  mm/kasan/common.c          |  3 +-
> 
> +Cc other kasan maintainers

Yeah, sorry about that, I should have CCed you guys.

> > +typedef enum stack_action {
> > +	STACK_ACTION_NONE,
> > +	STACK_ACTION_INC,
> > +}stack_action_t;
> > +
> 
> missing space after '}'. But please no unnecessary typedef, just 'enum
> stack_action' (and spelling out 'enum stack_action' elsewhere) is just
> fine.

Sure, will re-name it.

> 
> This is in the global namespace, so I'd call this
> stack_depot_action+STACK_DEPOT_ACTION_*.
> 
> However, .._ACTION_INC doesn't really say what's incremented. As an
> analog to stack_depot_dec_count(), perhaps .._ACTION_COUNT?

I guess we can go "STACK_DEPOT_ACTION_COUNT", or "STACK_DEPOT_ACTION_REF_INC",
but the latter seems rather baroque for my taste.

> In general it'd be nicer if there was stack_depot_inc_count() instead of
> this additional argument, but I see that for performance reasons you
> might not like that?

Yes, the first prototypes didn't have this stack_action_t thing,
but that implied that we had to look for the stack twice
in the __set_page_owner() case.

This way we only do that in the __reset_page_owner() case.

So yes, it's a trade-off performance vs LOC.

> > --- a/lib/stackdepot.c
> > +++ b/lib/stackdepot.c
> > @@ -63,6 +63,7 @@ struct stack_record {
> >  	u32 hash;			/* Hash in the hastable */
> >  	u32 size;			/* Number of frames in the stack */
> >  	union handle_parts handle;
> > +	refcount_t count;		/* Number of the same repeated stacks */
> 
> This will increase stack_record size for every user, even if they don't
> care about the count.
> 
> Is there a way to store this out-of-line somewhere?

That would require having some kind of e.g: dynamic struct and allocating
new links to stacks as they were created and increase the refcount there.

But that would be too much of complexity, I think.

As I read in your other thread, we can probably live with that, but
it is worth spelling out in the changelog.

> > +void stack_depot_dec_count(depot_stack_handle_t handle)
> > +{
> > +	struct stack_record *stack = NULL;
> > +
> > +	stack = stack_depot_getstack(handle);
> > +	if (stack) {
> > +	/*
> > +	 * page_owner creates some stacks via create_dummy_stack().
> > +	 * We are not interested in those, so make sure we only decrement
> > +	 * "valid" stacks.
> > +	 */
> 
> Comment indent is wrong.

Will fix it.

Thanks for taking the time to review the code Marco!


-- 
Oscar Salvador
SUSE Labs

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YxF4H5tu9cl9ePMD%40localhost.localdomain.
