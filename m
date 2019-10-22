Return-Path: <kasan-dev+bncBCDZVUN45ELBBUHVXTWQKGQERGIDX4A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33a.google.com (mail-ot1-x33a.google.com [IPv6:2607:f8b0:4864:20::33a])
	by mail.lfdr.de (Postfix) with ESMTPS id 024FFE0A82
	for <lists+kasan-dev@lfdr.de>; Tue, 22 Oct 2019 19:22:26 +0200 (CEST)
Received: by mail-ot1-x33a.google.com with SMTP id l7sf8925568otf.1
        for <lists+kasan-dev@lfdr.de>; Tue, 22 Oct 2019 10:22:25 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1571764945; cv=pass;
        d=google.com; s=arc-20160816;
        b=yUipw3Y7FiiIcwQjotTDmlaoS0FzGchCu+numkRhY5TzBUgq6tr5cmqfjrHk/Vyx2d
         FMcjohh0dznO8F2A6/Hf6CnamsSA0fMMp0QJ+U/Pt3x8xSOW1mjf/0tNi6uIpYdNC+He
         liGhtHBuc9aA3BTvCO/+Skh69PbDb++y8Noenol4Wu18ppi3J6r6wvTHwpJw9AgNxAb2
         USs4m2oai2ZBFEY5ZRIqyppDmOi3se0voMO6AZ0EmghIMCywGUq+OLEn9gMDC1n69O9x
         Gqy9W6eGG8T+pV9mx/DxYAUI0+bWWriv9mFlpDd3pE3IFijOEedErCTyqGP8cU/BxA+W
         5R+w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:user-agent
         :organization:references:in-reply-to:date:cc:to:from:subject
         :message-id:sender:dkim-signature;
        bh=cGUP8qLmyRT8lgWyEANmYEJViIWV1CuuVeDh00MC3Zs=;
        b=k3egpjvTpAw6q/G6WBivxka5BuK0eZYAaYeozRXkRw7lWTpXkzDfp7/lnMPzZ685sh
         qu94hxfF3jdDzDmWM2CnCqOanQSrHJnX4gVlURr8uc9WGVzZFqAEbUG5M/AjMNn6+o7q
         SYc4xjVTxKLt7g1hOorJ4WdFg/+LOHrb72dquhBYK0vl6HBp/IYT3Hoag4ZRpUViPemz
         y4zMltFT3fzFMfSeJ+ucOgPAoV3HPGRCnOVKkrD2eiyaryQnuOBNkPx1cx2/sUFYVSlN
         z/aA0zHo+mljsck4UKpz1JhUZ6gYyXe6pdqbFAuk20kEGxhPMmpIaY4wyFDCQDvxmAom
         SYPA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=KSrwysvh;
       spf=pass (google.com: domain of lyude@redhat.com designates 207.211.31.81 as permitted sender) smtp.mailfrom=lyude@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:message-id:subject:from:to:cc:date:in-reply-to:references
         :organization:user-agent:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=cGUP8qLmyRT8lgWyEANmYEJViIWV1CuuVeDh00MC3Zs=;
        b=iN/ph+uk4OE+svFGDbxinsXIBPu9Uu2c02MRh2DkSVQZTUcQIgK/NBDww2Or+KOmWm
         eAHW8Zvzk2/TuokWbkWVwBxYZTpxWswfHbN4enza6OT9IPGJ10ZW5aMnCm2elxHWeyon
         1ITbDNoSMDjd83m1Af56dPAwXhBRXayNr7XV6rzOqvJqWlkg8xuEkTzXHBSaBzqaonjI
         WTMqpSBQv0I7HeucQPCG3gUapjVHwW8tKhJjCVUk9yXTgcEEpWXA/mESlsxS+gdYHY5v
         fOk+mQYJX8Zoo3qUHxuoFPauJHz5oYGqjFt+Msq8t+sf/07fgg46ATev7dH2UeaDR3WD
         W9Kg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:message-id:subject:from:to:cc:date
         :in-reply-to:references:organization:user-agent:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=cGUP8qLmyRT8lgWyEANmYEJViIWV1CuuVeDh00MC3Zs=;
        b=NdBihYG2CYvv896Ja6sBzni2VsP/kMxOgUgBhGtLRVJP+k0JHUSSlqT8IhX4eZ43Zq
         uH5k+70E5iVd+wJ7jJALLYhG/yCIdPR4tV4y5Q5/FKBFSbhVO1BHbbABOl9Z333ZHxdj
         E9fzJKN7WBmgYY8nuf5wMUIB9GhO2QN9eeE3NZL3Z5rEbdp8ARvNMfpnbFpnFIkTHXvX
         1vW4rlCBzwKks/LPFleL0zoJW6RNlxwM8zBQYNZNYTsuQQ/kywD3Zisa8xVugILMUt6Z
         X68AV/KHVA3ntgLDk8rRBnHADScDY1ibTvD9S6m4okoAyabY62LD8uGDkVWCO3+nlQlj
         QcYQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAWdpNfv4GYc4P2hlOZjX7rOruQy1sQ0EL76g3hZzMMNvkONNJO5
	fF/6IM0YzxguwX4isClGyBM=
X-Google-Smtp-Source: APXvYqwJJB5q+vq7PFGeO28ds6ZBu5C6VOdrQKSSjNpF6xFzR9PBT8DMHQuChlFp+JLmH/9dRY++5A==
X-Received: by 2002:a9d:724c:: with SMTP id a12mr3846423otk.230.1571764944879;
        Tue, 22 Oct 2019 10:22:24 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:f4c9:: with SMTP id s192ls2907549oih.1.gmail; Tue, 22
 Oct 2019 10:22:24 -0700 (PDT)
X-Received: by 2002:aca:d44e:: with SMTP id l75mr4011503oig.44.1571764944544;
        Tue, 22 Oct 2019 10:22:24 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1571764944; cv=none;
        d=google.com; s=arc-20160816;
        b=na2nDLytHtAg05iyJrxcgEIi0BXwAh/p//MzJ5/KtXlpiaGDE5+V0WH+wXKbQS0AYS
         SbQpBOjce074uQ1aBmGjOhMDCoLKPxBNgS0VoAX7tKPvfkTusWR/ONY2EhwGJ8keSJXI
         ehHWhVT/9PFYf1QPOY4TCoFTLDNbG4gg//j3P6189RDcyMM/BEoFnUmVoPCjUdnFsqO4
         dfIMQOTSCBUFm+qqT3IhiyoYFeVC0QQDU969o8N9Afbj+HaqXtaPg8zlcnXCgqiCvaGk
         0XbwXKSC8spDvaQcH1MySw6V+Z9qjG4OhIqHUC0xzZFw2XZdjO/X7WPApSmdi6sVlu+H
         nB/g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:user-agent:organization
         :references:in-reply-to:date:cc:to:from:subject:message-id
         :dkim-signature;
        bh=DYe7sXZbkW6x0+4z45DRiC8jJviu2jpg3kuxyxWl3ng=;
        b=dOgJ4YEiq19WuxOd9RRA7z7A2KB8VhEVDj596eUA9OcgbubZlkbnsnJ/iwxlUUWGWt
         SdyAe9s4bhdNZF4OioMPy0lRdH+da/8/83Cqny0Q+Lhm2pwJYbEHJilq9z6DI76x26dk
         i11puU2qMMmu6JeAWt3tx+tASNYfAth3Ga0/wQJ9sOIabc5X03lo4MV8MLwut6CtZD/G
         bVySih1S/RIDuWoyKF2TZtB85/eF7FAVuvtMKfTmzjFblplLJ0DfWNG6pLmak/xBVTCV
         +wHcTQnQHTMlm+0d3RdJyvOu/fLqHca0rPC59yiLuRwwO2ZcCZoRNM5hII2xo7AW/CMi
         6DYg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=KSrwysvh;
       spf=pass (google.com: domain of lyude@redhat.com designates 207.211.31.81 as permitted sender) smtp.mailfrom=lyude@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-1.mimecast.com (us-smtp-1.mimecast.com. [207.211.31.81])
        by gmr-mx.google.com with ESMTPS id k184si1012960oih.0.2019.10.22.10.22.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 22 Oct 2019 10:22:24 -0700 (PDT)
Received-SPF: pass (google.com: domain of lyude@redhat.com designates 207.211.31.81 as permitted sender) client-ip=207.211.31.81;
Received: from mail-qk1-f200.google.com (mail-qk1-f200.google.com
 [209.85.222.200]) (Using TLS) by relay.mimecast.com with ESMTP id
 us-mta-71-oqj4NR1qNvu2cuSAbJCEEg-1; Tue, 22 Oct 2019 13:22:23 -0400
Received: by mail-qk1-f200.google.com with SMTP id c4so12768580qkg.22
        for <kasan-dev@googlegroups.com>; Tue, 22 Oct 2019 10:22:22 -0700 (PDT)
X-Received: by 2002:a05:6214:2a4:: with SMTP id m4mr63220qvv.165.1571764942125;
        Tue, 22 Oct 2019 10:22:22 -0700 (PDT)
X-Received: by 2002:a05:6214:2a4:: with SMTP id m4mr63188qvv.165.1571764941783;
        Tue, 22 Oct 2019 10:22:21 -0700 (PDT)
Received: from dhcp-10-20-1-11.bss.redhat.com ([144.121.20.162])
        by smtp.gmail.com with ESMTPSA id 81sm12662041qkd.73.2019.10.22.10.22.20
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 22 Oct 2019 10:22:21 -0700 (PDT)
Message-ID: <f1043a5f770b290b02e17b3114d80ce7f83a58a1.camel@redhat.com>
Subject: Re: [RFC] kasan: include the hashed pointer for an object's location
From: Lyude Paul <lyude@redhat.com>
To: Dmitry Vyukov <dvyukov@google.com>
Cc: Linux-MM <linux-mm@kvack.org>, kasan-dev <kasan-dev@googlegroups.com>, 
 Sean Paul <sean@poorly.run>, Daniel Vetter <daniel.vetter@ffwll.ch>, Andrey
 Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko
 <glider@google.com>, LKML <linux-kernel@vger.kernel.org>
Date: Tue, 22 Oct 2019 13:22:19 -0400
In-Reply-To: <CACT4Y+YQf-aje4jqSMop24af_GO8G_oPMfrJ9B7oo5_EudwHow@mail.gmail.com>
References: <20191022021810.3216-1-lyude@redhat.com>
	 <CACT4Y+YQf-aje4jqSMop24af_GO8G_oPMfrJ9B7oo5_EudwHow@mail.gmail.com>
Organization: Red Hat
User-Agent: Evolution 3.32.4 (3.32.4-1.fc30)
MIME-Version: 1.0
X-MC-Unique: oqj4NR1qNvu2cuSAbJCEEg-1
X-Mimecast-Spam-Score: 0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: lyude@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=KSrwysvh;
       spf=pass (google.com: domain of lyude@redhat.com designates
 207.211.31.81 as permitted sender) smtp.mailfrom=lyude@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
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

On Tue, 2019-10-22 at 04:27 +0200, Dmitry Vyukov wrote:
> On Tue, Oct 22, 2019 at 4:19 AM Lyude Paul <lyude@redhat.com> wrote:
> > The vast majority of the kernel that needs to print out pointers as a
> > way to keep track of a specific object in the kernel for debugging
> > purposes does so using hashed pointers, since these are "good enough".
> > Ironically, the one place we don't do this is within kasan. While
> > simply printing a hashed version of where an out of bounds memory access
> > occurred isn't too useful, printing out the hashed address of the object
> > in question usually is since that's the format most of the kernel is
> > likely to be using in debugging output.
> > 
> > Of course this isn't perfect though-having the object's originating
> > address doesn't help users at all that need to do things like printing
> > the address of a struct which is embedded within another struct, but
> > it's certainly better then not printing any hashed addresses. And users
> > which need to handle less trivial cases like that can simply fall back
> > to careful usage of %px.
> > 
> > Signed-off-by: Lyude Paul <lyude@redhat.com>
> > Cc: Sean Paul <sean@poorly.run>
> > Cc: Daniel Vetter <daniel.vetter@ffwll.ch>
> > Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
> > Cc: Alexander Potapenko <glider@google.com>
> > Cc: Dmitry Vyukov <dvyukov@google.com>
> > Cc: kasan-dev@googlegroups.com
> > ---
> >  mm/kasan/report.c | 5 +++--
> >  1 file changed, 3 insertions(+), 2 deletions(-)
> > 
> > diff --git a/mm/kasan/report.c b/mm/kasan/report.c
> > index 621782100eaa..0a5663fee1f7 100644
> > --- a/mm/kasan/report.c
> > +++ b/mm/kasan/report.c
> > @@ -128,8 +128,9 @@ static void describe_object_addr(struct kmem_cache
> > *cache, void *object,
> >         int rel_bytes;
> > 
> >         pr_err("The buggy address belongs to the object at %px\n"
> > -              " which belongs to the cache %s of size %d\n",
> > -               object, cache->name, cache->object_size);
> > +              " (aka %p) which belongs to the cache\n"
> > +              " %s of size %d\n",
> > +              object, object, cache->name, cache->object_size);
> 
> Hi Lyude,
> 
> This only prints hashed address for heap objects, but
> print_address_description() has 4 different code paths for different
> types of addresses (heap, global, stack, page). Plus there is a case
> for address without shadow.
> Should we print the hashed address at least for all cases in
> print_address_description()?

Yep-this is probably a good idea. Will send a respin in a little bit
> 
> 
> >         if (!addr)
> >                 return;
> > --
> > 2.21.0
> > 
-- 
Cheers,
	Lyude Paul

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/f1043a5f770b290b02e17b3114d80ce7f83a58a1.camel%40redhat.com.
