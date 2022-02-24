Return-Path: <kasan-dev+bncBDWLZXP6ZEPRBZPS3WIAMGQESBMRQ5Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23d.google.com (mail-lj1-x23d.google.com [IPv6:2a00:1450:4864:20::23d])
	by mail.lfdr.de (Postfix) with ESMTPS id 92CDA4C2BA0
	for <lists+kasan-dev@lfdr.de>; Thu, 24 Feb 2022 13:26:14 +0100 (CET)
Received: by mail-lj1-x23d.google.com with SMTP id v5-20020a2ea605000000b00246322afc8csf1001851ljp.4
        for <lists+kasan-dev@lfdr.de>; Thu, 24 Feb 2022 04:26:14 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1645705574; cv=pass;
        d=google.com; s=arc-20160816;
        b=bmk36a2FBl/1p3IiQMYEjVd6IbwAxTtKKvaK49Y9cmS+VQ7dydeYYzzs38NKLJDrCY
         WtiVtzg/BLdYEPd44yM8BfDa3Jy6E82on2o0ALk2xw99poh+KSCgl2L+7gZQVPSM1WlC
         RpDdWJ28GGM1aK04nafPNSsnczQx88x7nrbOM6V55RMOLviiTvh0gLL5lC824rV7P1B3
         9JLqcAoiY8/U8JekbuoEnL48wG3VM3MRxJRcrNmAgDaXHJqoJzMCQf8tiyTdiopwmfAV
         2MpxzXKgkFDuw2dzLdeU6lpOAjRAzscMns5lB98DQcoKE8WwZRrX03U2XKdUxoQEYBZI
         HQSw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:subject:from:references
         :cc:to:content-language:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=V+uJ7SQLsQID2/+2lKihepbadzzgWVxpg/y03KygVz0=;
        b=zTDZlnyD9KtbHS363idMDGvli4DubOwxc1Jsb86yTmGHpH6z0MD+RxNJNS4VUmrfJ3
         adrctyf7rwHSql/tgOWV4zFZU+ySbvBu/bFDIiC32FiNZducvG8aPi3FLqfcQj7UP9MN
         4tDjB3AftyuUwk6uUrtLYryyIh+6uyeAg4G1Usw4EX+CUA0nrphIGDq3zvRqIhVcPtzD
         MTopsWYMMIQegzJfC6xgob/dhrfolQHJYMaQTzol3YJUVsglrlHtXeTVWhAZH9MAfk2k
         nad3HuZrJgnAuLM0KW/DCwC0lArlIOI95veOcyqNJMzE9LlypaMz8WNIYgwsTLkGg0hU
         JqQw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=P4+Atof8;
       dkim=neutral (no key) header.i=@suse.cz header.b=TY7aQvrF;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.29 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:message-id:date:mime-version:user-agent:content-language:to
         :cc:references:from:subject:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=V+uJ7SQLsQID2/+2lKihepbadzzgWVxpg/y03KygVz0=;
        b=r7E0QdZc1doGc0+M+7ixp9LBnjCLb4dtmy71+hj45E+7Md0G4rjysPq8spzzLzBKN6
         8S2xUt1bV481Ws/RiA5PFkEs++fIcWGbn91dbeiQXM/XPj6pcsa8WD4R1ACVL0l2T+0B
         Sq549lxE2cEGoouvIsnxaXpRoCJ4o0UtI/0AYAty+slKcHFEeU/bo8hGwH5yaO9XqL8+
         u7DM5awRMZnmmTzsbLHU4sogQG7RmJOVWNDfssGRwFhhUY7xcWsMqyIb6ivbN8GuSycD
         vSuKRE1zKc20L22IjdWpQjpl0HuXowW/dMbYEZbWPpPEskW7/EzfyzIIz4OzuJ1lLuHg
         tQvg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:message-id:date:mime-version:user-agent
         :content-language:to:cc:references:from:subject:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=V+uJ7SQLsQID2/+2lKihepbadzzgWVxpg/y03KygVz0=;
        b=6ImBJQu9NE/DUujlLY29qso/U1Yyb4PzgJb3hCIPNec5CK9ze4uo+JDt3DXLdBqKtH
         9YE+15fSe75j+rM84eJ8GtMT9IIMzv8q7ILoBh/pwA5PrtD73oNyd4BYd2sL0DLZw074
         njc1u4/WT4X8Iq7oxjM2bvd3zQmqQcVdAhVdINvwpdrmnojHYaKpmP2cpQOsSCURh0Qj
         Ebn8Y4oV6PA5/jkB9nptJScWm7Ge6TehoPfThxemYkxZCkgUTX07O6McujwLzGTeoPdz
         zJE45Fi6NbEkUyyf4GXYH7qgIMGJxPZyhztJ18WZzOKwclgqbO2tWoEbwcjPS2+zbu+X
         8eNQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530WVtPzJ1E8Nzbai/Bwv+1l1sqfMiBdnd/GXLDn0E65/o3T0NOd
	1vfcrxq/IhM5usWHSabWyew=
X-Google-Smtp-Source: ABdhPJx1dUJM90+7A5won4nUjAym5OfwXHT091leDRvqcjmh9WNO/1XYwHeUUdW/BoEaob/h8u8i1g==
X-Received: by 2002:a2e:80c6:0:b0:246:3334:9778 with SMTP id r6-20020a2e80c6000000b0024633349778mr1729282ljg.443.1645705573957;
        Thu, 24 Feb 2022 04:26:13 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:a54a:0:b0:246:420e:ed3a with SMTP id e10-20020a2ea54a000000b00246420eed3als534213ljn.8.gmail;
 Thu, 24 Feb 2022 04:26:12 -0800 (PST)
X-Received: by 2002:a05:651c:307:b0:23b:1de6:5376 with SMTP id a7-20020a05651c030700b0023b1de65376mr1730503ljp.261.1645705572793;
        Thu, 24 Feb 2022 04:26:12 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1645705572; cv=none;
        d=google.com; s=arc-20160816;
        b=uC9KrJr2bN7qAM4+k50xyUXasiVnUbhSmKVhjxwG1a7pTiWxByrn5vb+R/hLMVyJMA
         VO2c11wjDmVGwZsimtZpTrRLe+GRv9Nk28yisonIJfmlhJJ7fyy93YHS3KWXWiT+NDuQ
         OsZPhxiNc0bJnh9v00uFbXi/aUBrCEDFKQDIljsWHTN13h6a+FfA/02UPF12iP7VvRYd
         GNRSR00MisT0ZnvJk0eLPrN66vf/XYDJXaRAxztqJnxE1YKEIfj5jmwZ0m1sp9iUJ35C
         uMdkmD1c5hqT0xYLCHClOqDXHLv+KzBeeRiVHf9OdiU/npCsKe5FYiW/SweyVWD0XXVw
         Sl5A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:subject:from:references:cc:to
         :content-language:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature;
        bh=iRlluuQbnUld5s/Ic1hGKrSMGDqTXKB3g6TTm6f3L7Y=;
        b=gEI56utw1NT3l5d8cIJHUyyufEROj326OS3OdUNAvpdoN0/SeJIpCjpxZSomhU3Sya
         ScVoZCu3EnFVCmO6FrJ3jQcmXekjqNwNgoTXehgyYs90Vt/1ZDyhAem12l1rE10Pgaig
         dzJm8+g5Pulwa+7UrcyCKoVeVSZCyCcjACIaPgfmb0WJyN1FTO2yh2FVsFEnSkO0RReX
         6DRVxVUWgqtvY/d3Un5IZol/N/Gkfg4ZsSA8xpdCuoj/84k97nKvD/f4KnPszeEDK42Z
         4Y7VBhFE046sB5PVDlJCXoai0BRbmQG5Dse2gvjS7Nf55dsAon0AsDspoKX2Ufu7Xs5m
         wXUw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=P4+Atof8;
       dkim=neutral (no key) header.i=@suse.cz header.b=TY7aQvrF;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.29 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [195.135.220.29])
        by gmr-mx.google.com with ESMTPS id z19si75135lfr.10.2022.02.24.04.26.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 24 Feb 2022 04:26:12 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.220.29 as permitted sender) client-ip=195.135.220.29;
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id 034F71F43D;
	Thu, 24 Feb 2022 12:26:12 +0000 (UTC)
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by imap2.suse-dmz.suse.de (Postfix) with ESMTPS id CA82913AD9;
	Thu, 24 Feb 2022 12:26:11 +0000 (UTC)
Received: from dovecot-director2.suse.de ([192.168.254.65])
	by imap2.suse-dmz.suse.de with ESMTPSA
	id qdrBMGN5F2J8AQAAMHmgww
	(envelope-from <vbabka@suse.cz>); Thu, 24 Feb 2022 12:26:11 +0000
Message-ID: <0e02416f-ef43-dc8a-9e8e-50ff63dd3c61@suse.cz>
Date: Thu, 24 Feb 2022 13:26:11 +0100
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101
 Thunderbird/91.6.1
Content-Language: en-US
To: Marco Elver <elver@google.com>
Cc: Hyeonggon Yoo <42.hyeyoo@gmail.com>, linux-mm@kvack.org,
 Roman Gushchin <guro@fb.com>, Andrew Morton <akpm@linux-foundation.org>,
 linux-kernel@vger.kernel.org, Joonsoo Kim <iamjoonsoo.kim@lge.com>,
 David Rientjes <rientjes@google.com>, Christoph Lameter <cl@linux.com>,
 Pekka Enberg <penberg@kernel.org>, Kees Cook <keescook@chromium.org>,
 kasan-dev <kasan-dev@googlegroups.com>,
 Andrey Konovalov <andreyknvl@gmail.com>
References: <20220221105336.522086-1-42.hyeyoo@gmail.com>
 <20220221105336.522086-2-42.hyeyoo@gmail.com>
 <4d42fcec-ff59-2e37-4d8f-a58e641d03c8@suse.cz>
 <CANpmjNMjgSKommNCrfyFuaz+3HQdW92ZSF_p26LQdmS0o3L98Q@mail.gmail.com>
From: Vlastimil Babka <vbabka@suse.cz>
Subject: Re: [PATCH 1/5] mm/sl[au]b: Unify __ksize()
In-Reply-To: <CANpmjNMjgSKommNCrfyFuaz+3HQdW92ZSF_p26LQdmS0o3L98Q@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=P4+Atof8;       dkim=neutral
 (no key) header.i=@suse.cz header.b=TY7aQvrF;       spf=pass (google.com:
 domain of vbabka@suse.cz designates 195.135.220.29 as permitted sender) smtp.mailfrom=vbabka@suse.cz
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

On 2/23/22 20:06, Marco Elver wrote:
> On Wed, 23 Feb 2022 at 19:39, Vlastimil Babka <vbabka@suse.cz> wrote:
>> On 2/21/22 11:53, Hyeonggon Yoo wrote:
>> > Only SLOB need to implement __ksize() separately because SLOB records
>> > size in object header for kmalloc objects. Unify SLAB/SLUB's __ksize().
>> >
>> > Signed-off-by: Hyeonggon Yoo <42.hyeyoo@gmail.com>
>> > ---
>> >  mm/slab.c        | 23 -----------------------
>> >  mm/slab_common.c | 29 +++++++++++++++++++++++++++++
>> >  mm/slub.c        | 16 ----------------
>> >  3 files changed, 29 insertions(+), 39 deletions(-)
>> >
>> > diff --git a/mm/slab.c b/mm/slab.c
>> > index ddf5737c63d9..eb73d2499480 100644
>> > --- a/mm/slab.c
>> > +++ b/mm/slab.c
>> > @@ -4199,27 +4199,4 @@ void __check_heap_object(const void *ptr, unsigned long n,
>> >  }
>> >  #endif /* CONFIG_HARDENED_USERCOPY */
>> >
>> > -/**
>> > - * __ksize -- Uninstrumented ksize.
>> > - * @objp: pointer to the object
>> > - *
>> > - * Unlike ksize(), __ksize() is uninstrumented, and does not provide the same
>> > - * safety checks as ksize() with KASAN instrumentation enabled.
>> > - *
>> > - * Return: size of the actual memory used by @objp in bytes
>> > - */
>> > -size_t __ksize(const void *objp)
>> > -{
>> > -     struct kmem_cache *c;
>> > -     size_t size;
>> >
>> > -     BUG_ON(!objp);
>> > -     if (unlikely(objp == ZERO_SIZE_PTR))
>> > -             return 0;
>> > -
>> > -     c = virt_to_cache(objp);
>> > -     size = c ? c->object_size : 0;
>>
>> This comes from commit a64b53780ec3 ("mm/slab: sanity-check page type when
>> looking up cache") by Kees and virt_to_cache() is an implicit check for
>> folio slab flag ...
>>
>> > -
>> > -     return size;
>> > -}
>> > -EXPORT_SYMBOL(__ksize);
>> > diff --git a/mm/slab_common.c b/mm/slab_common.c
>> > index 23f2ab0713b7..488997db0d97 100644
>> > --- a/mm/slab_common.c
>> > +++ b/mm/slab_common.c
>> > @@ -1245,6 +1245,35 @@ void kfree_sensitive(const void *p)
>> >  }
>> >  EXPORT_SYMBOL(kfree_sensitive);
>> >
>> > +#ifndef CONFIG_SLOB
>> > +/**
>> > + * __ksize -- Uninstrumented ksize.
>> > + * @objp: pointer to the object
>> > + *
>> > + * Unlike ksize(), __ksize() is uninstrumented, and does not provide the same
>> > + * safety checks as ksize() with KASAN instrumentation enabled.
>> > + *
>> > + * Return: size of the actual memory used by @objp in bytes
>> > + */
>> > +size_t __ksize(const void *object)
>> > +{
>> > +     struct folio *folio;
>> > +
>> > +     if (unlikely(object == ZERO_SIZE_PTR))
>> > +             return 0;
>> > +
>> > +     folio = virt_to_folio(object);
>> > +
>> > +#ifdef CONFIG_SLUB
>> > +     if (unlikely(!folio_test_slab(folio)))
>> > +             return folio_size(folio);
>> > +#endif
>> > +
>> > +     return slab_ksize(folio_slab(folio)->slab_cache);
>>
>> ... and here in the common version you now for SLAB trust that the folio
>> will be a slab folio, thus undoing the intention of that commit. Maybe
>> that's not good and we should keep the folio_test_slab() for both cases?
>> Although maybe it's also strange that prior this patch, SLAB would return 0
>> if the test fails, and SLUB would return folio_size(). Probably because with
>> SLUB this can be a large kmalloc here and with SLAB not. So we could keep
>> doing that in the unified version, or KASAN devs (CC'd) could advise
>> something better?
> 
> Is this a definitive failure case?

Yeah, if we called it on a supposed object pointer that turns out to be not
slab, it usually means some UAF, so a failure.

> My opinion here is that returning 0
> from ksize() in case of failure will a) provide a way to check for
> error, and b) if the size is used unconditionally to compute an
> address may be the more graceful failure mode (see comment added in
> 0d4ca4c9bab39 for what happens if we see invalid memory per KASAN
> being accessed).

Sounds good, thanks. Then the patch should be fixed up to keep checking for
slab flag and returning 0 otherwise for CONFIG_SLAB.
For SLUB we might fail to detect the failure case by assuming it was a large
kmalloc. Maybe we could improve and only assume that when folio_size() is
large enough that the corresponding allocation would actually be done as a
large kmalloc, and the object pointer is to the beginning of the folio?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/0e02416f-ef43-dc8a-9e8e-50ff63dd3c61%40suse.cz.
