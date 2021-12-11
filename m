Return-Path: <kasan-dev+bncBCKJJ7XLVUBBBNVD2KGQMGQEQCYFDSY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1040.google.com (mail-pj1-x1040.google.com [IPv6:2607:f8b0:4864:20::1040])
	by mail.lfdr.de (Postfix) with ESMTPS id ACF964713B3
	for <lists+kasan-dev@lfdr.de>; Sat, 11 Dec 2021 12:55:36 +0100 (CET)
Received: by mail-pj1-x1040.google.com with SMTP id iq9-20020a17090afb4900b001a54412feb0sf7690634pjb.1
        for <lists+kasan-dev@lfdr.de>; Sat, 11 Dec 2021 03:55:36 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1639223735; cv=pass;
        d=google.com; s=arc-20160816;
        b=SuOPhjEfK90q2HU8sIqk0zoPrJNpuKqSnYvTIoC7opp9MB/euMeyNNK2Q0mk5xVwVR
         NeUq2JdobaVmS6LPcZaJAjWufljc5m19e7XVyTAC6nt9FNS3UjqQ7Azmyht2dGZZ1G/r
         rZrb5/fOVlhMyF0pmCaKFA7YGa8H/pPIOkyDH+tKdiltc+sIoSit0GeYV2wmDjQ887HE
         1ogBFDutZgqPlgSUETf+XW9m0UpMtckqxhxcVXg6DyXyHvhQ/gSqv41VJ2R6KMBKsSS/
         3QH9GcTbgO1kvuxbj0WuxtZpB/WDDKz6PmBJL7WPrvOtd/hM0x/yTuweTo56qJNGS0eD
         stZw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature:dkim-signature;
        bh=QihctX0lnrGyzeVKEzX3YNpq0q1uV5SWdXS+WE/p4Ag=;
        b=RQYJYdmgX8+BMPhybIvPGePkpIdCle6KSOcNztD1MmfXrerpv2YPEbL4Zt0Bx/bjp+
         MnGsERSbE4GAh97O0SFWrD+Xgn6XwUV4M9eV97oSYtozdKrmPDgksKA5R/B6/+yJ5Mt6
         Llasx9Q3MC5bR5Nmj+kdRS8e/NrtcL/7iBzhfaX5YydA/5+MCjdTURaGgJdlBGCbgv5W
         dcMUUOnODdOT47/X4jbrM5iKox4m7eHNe6SFSu9Za1h2h9sPMvMxQxiyzNS4wwiISBp6
         fiV1iy8rdRd4TDOIiy98Y71KAvCWOSCwmDgR8wqytMYDiYDfHespT0qnpnCBoQ8XtkcJ
         xdWQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=gs09pHLi;
       spf=pass (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::430 as permitted sender) smtp.mailfrom=42.hyeyoo@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=QihctX0lnrGyzeVKEzX3YNpq0q1uV5SWdXS+WE/p4Ag=;
        b=VtHDeumicvFXtBUScNAwvk1ZOlG6uHdRCaBk34YLL0zk+2pn7ISYh2rolvda9siAJl
         S0Jj5lVth7EhvYUBigz8/iS734llgz+4AcluprmvsWg+RWgGWfLLSHSnsgM2bVGIzQzy
         tAuMdzjpLl21kZ6Rl5YhiJr2L3AIv5B6uEC5Zfu2U8ksExVnc37LYQmcuoxM0aEsdrlx
         51YT2AC2vxjvApXLrTmCm6fjkvCzUO+p0vHqCNwNZuVGwgpudNudetG6CzkksT3EML0r
         2FoZQkQAa2gKEI5lcxRoQxyuUI1VieMww+W/o5w30aGoNj9aHHakrL2gKXPjoHk8rFn7
         TnTg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=QihctX0lnrGyzeVKEzX3YNpq0q1uV5SWdXS+WE/p4Ag=;
        b=DySKJvjYYLtDc7R0K8Jtm5yXpIWKQ6sog4n+NYkqQ54Nb8XkZMvn4Rt6itsVLNhNti
         oSl7HFAzC6SX5esZB62kwFJOVd4FARXcKlLSdyj/Dx9Nghy82UBHwF/q4tiQitUO41tO
         MNi22AoNZqzBFDgP40i5LkaL6GTmXrQDw/ZIMwQ0xpJ5QXoWiAxKYs59I8Z4MnKX1OGA
         W/kMXbmSYl1p53m2CtVBeX6d8WXYS9QcVXleub1zV01VTIO25pcXPc9Pddhn9UlFgAqv
         rz7zMXP9FP48JrKPU41wQCA1SDhpURa1hz2oGQfqVYx8qOsnY++CaVxjsJqkyXY5ZLf1
         +65A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=QihctX0lnrGyzeVKEzX3YNpq0q1uV5SWdXS+WE/p4Ag=;
        b=3vb+ff29RAsHemaAmGv0ixTjSXwZLS3CFcDlrCaUWz7EuboLP8RhvaeWjgg3yZ4fJF
         8tNZaEzKwa+HQqrzaHgkHSdADq+GTIg6ljY5HP3skDCtQuH2FPgROytQLG0DNswBVR7S
         UI/LXYODBoo9mLdzt7m7nR0Icm5Qt2hUN5wYD5RKHdXLtQEUc9kEDfflBMnXuukoLOM4
         xyYwllQzgirNX0tg8DQaVf3A5FhaHoSNGJ5WNrjVpgXLHhTrbSWcFjE4BnBAQ339VRIl
         1/55VPxZ7DyNSdPKpbYIoE+EsASO+WmetI0CPTZHBXr2qvCZSboeASKjEmSGScEK9C1m
         X1Bg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530RzD4FJDDtn84DIRZQqVtNOg7nvafBQXWk3kvI+XW5F03iL9nD
	V2xP5yvFs8Cc2f3WRCowTbs=
X-Google-Smtp-Source: ABdhPJyGhgbA65Z2EJpNHeXdb/tZa2d3LqS12Jd7knvKrqQ216JxSWNowY8ZKweOMvw9oibpzpbfzw==
X-Received: by 2002:a17:902:7284:b0:142:728b:46a6 with SMTP id d4-20020a170902728400b00142728b46a6mr81924562pll.45.1639223734875;
        Sat, 11 Dec 2021 03:55:34 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:138d:: with SMTP id t13ls4224007pfg.10.gmail; Sat,
 11 Dec 2021 03:55:34 -0800 (PST)
X-Received: by 2002:a63:c7:: with SMTP id 190mr10643389pga.312.1639223734258;
        Sat, 11 Dec 2021 03:55:34 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1639223734; cv=none;
        d=google.com; s=arc-20160816;
        b=IzGb/iZkXlZUroPwKNzkE9zBdSGeoGiMj4sGIuLupv3JOaPaqXmstbsXBydyOYv1zr
         jPk9/Gzv1opTMqhfzhJ5fIfrqUrfF3qI/OiduN1yz60PXD3D5zxv3T4Xc9gTr81aHLGD
         Q5yM+Q0NJXht7rZ5YmSgvgzOX/wMOWPltJQ2ztYOi2VY4YRWkdRFBVzkyc88JNbktNoP
         21kAgwgRuZ8/wl2DzcNN4jdnrf+aXkQvogK0F1/zRIkB+NM+4LP5Qn9D3gAZLsm/Z/xU
         BW0W4v+txMqxWI/Ev2GY3PNkS84gW03gnMe3c1Sbnm6HXGclLotisAf+gEemZ4MRcAS4
         I2Aw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=8z6MGF2AYvRVQGXmgU3xITNKiS7vT0SuNIf6r0/o/DM=;
        b=dMh2+EDlEJYvAXL3kfnvDNMqNj81Rxp3Z9KqEEsBxmlhV2ZFYj95ntCKp3vtS/F3Du
         LvMIcPzL0joAQT3x8H9nFubjJz+ijzRrmzjf49AdKG7zWp+hjm66N3a0xhbRiMK4jONo
         02xLnhK8A3jYUyrtJHCdjDjsIc1paG8ibl2SaOPZLPE6JbdRiKeZvLkAGV3ahc7arY75
         IJmOA0vJieEJptqOQG/TsDHEENIQsp/KGQbvxBnKRqvFQUspo0b49Gybhkkp9RmbmMOz
         g+MT3kBDPKadLYT6yyWQCWR9AaaTIi1GL7GUgWvfzhTI1ZkQLudktrRGn07AhKuJcRHK
         q+Pw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=gs09pHLi;
       spf=pass (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::430 as permitted sender) smtp.mailfrom=42.hyeyoo@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pf1-x430.google.com (mail-pf1-x430.google.com. [2607:f8b0:4864:20::430])
        by gmr-mx.google.com with ESMTPS id s29si499050pgm.3.2021.12.11.03.55.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 11 Dec 2021 03:55:34 -0800 (PST)
Received-SPF: pass (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::430 as permitted sender) client-ip=2607:f8b0:4864:20::430;
Received: by mail-pf1-x430.google.com with SMTP id g18so10781303pfk.5
        for <kasan-dev@googlegroups.com>; Sat, 11 Dec 2021 03:55:34 -0800 (PST)
X-Received: by 2002:a05:6a00:1385:b0:4ad:580d:8a8 with SMTP id t5-20020a056a00138500b004ad580d08a8mr23014733pfg.10.1639223733929;
        Sat, 11 Dec 2021 03:55:33 -0800 (PST)
Received: from odroid ([114.29.23.242])
        by smtp.gmail.com with ESMTPSA id nl16sm1935442pjb.13.2021.12.11.03.55.30
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sat, 11 Dec 2021 03:55:33 -0800 (PST)
Date: Sat, 11 Dec 2021 11:55:27 +0000
From: Hyeonggon Yoo <42.hyeyoo@gmail.com>
To: Vlastimil Babka <vbabka@suse.cz>
Cc: Matthew Wilcox <willy@infradead.org>, Christoph Lameter <cl@linux.com>,
	David Rientjes <rientjes@google.com>,
	Joonsoo Kim <iamjoonsoo.kim@lge.com>,
	Pekka Enberg <penberg@kernel.org>, linux-mm@kvack.org,
	Andrew Morton <akpm@linux-foundation.org>, patches@lists.linux.dev,
	Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com
Subject: Re: [PATCH v2 31/33] mm/sl*b: Differentiate struct slab fields by
 sl*b implementations
Message-ID: <20211211115527.GA822127@odroid>
References: <20211201181510.18784-1-vbabka@suse.cz>
 <20211201181510.18784-32-vbabka@suse.cz>
 <20211210163757.GA717823@odroid>
 <f3f02e1e-88b2-a188-1679-9c6256d19c7a@suse.cz>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <f3f02e1e-88b2-a188-1679-9c6256d19c7a@suse.cz>
X-Original-Sender: 42.hyeyoo@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=gs09pHLi;       spf=pass
 (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::430
 as permitted sender) smtp.mailfrom=42.hyeyoo@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Fri, Dec 10, 2021 at 07:26:11PM +0100, Vlastimil Babka wrote:
> On 12/10/21 17:37, Hyeonggon Yoo wrote:
> > On Wed, Dec 01, 2021 at 07:15:08PM +0100, Vlastimil Babka wrote:
> >> With a struct slab definition separate from struct page, we can go further and
> >> define only fields that the chosen sl*b implementation uses. This means
> >> everything between __page_flags and __page_refcount placeholders now depends on
> >> the chosen CONFIG_SL*B.
> > 
> > When I read this patch series first, I thought struct slab is allocated
> > separately from struct page.
> > 
> > But after reading it again, It uses same allocated space of struct page.
> 
> Yes. Allocating it elsewhere is something that can be discussed later. It's
> not a simple clear win - more memory used, more overhead, complicated code...
>

Right. That is a something that can be discussed,
But I don't think there will be much win.

> > So, the code should care about fields that page allocator cares when
> > freeing page. (->mapping, ->refcount, ->flags, ...)
> > 
> > And, we can change offset of fields between page->flags and page->refcount,
> > If we care about the value of page->mapping before freeing it.
> > 
> > Did I get it right?
> 
> Yeah. Also whatever aliases with compound_head must not have bit zero set as
> that means a tail page.
> 

Oh I was missing that. Thank you.

Hmm then in struct slab, page->compound_head and slab->list_head (or
slab->rcu_head) has same offset. And list_head / rcu_head both store pointers.

then it has a alignment requirement. (address saved in list_head/rcu_head
should be multiple of 2)

Anyway, it was required long time before this patch,
so it is not a problem for this patch.

> >> Some fields exist in all implementations (slab_list)
> >> but can be part of a union in some, so it's simpler to repeat them than
> >> complicate the definition with ifdefs even more.
> > 
> > Before this patch I always ran preprocessor in my brain.
> > now it's MUCH easier to understand than before!
> > 
> >> 
> >> The patch doesn't change physical offsets of the fields, although it could be
> >> done later - for example it's now clear that tighter packing in SLOB could be
> >> possible.
> >>
> > 
> > Is there a benefit if we pack SLOB's struct slab tighter?
> 
> I don't see any immediate benefit, except avoiding the page->mapping alias
> as you suggested.
> 
> > ...
> > 
> >>  #ifdef CONFIG_MEMCG
> >>  	unsigned long memcg_data;
> >> @@ -47,7 +69,9 @@ struct slab {
> >>  	static_assert(offsetof(struct page, pg) == offsetof(struct slab, sl))
> >>  SLAB_MATCH(flags, __page_flags);
> >>  SLAB_MATCH(compound_head, slab_list);	/* Ensure bit 0 is clear */
> >> +#ifndef CONFIG_SLOB
> >>  SLAB_MATCH(rcu_head, rcu_head);
> > 
> > Because SLUB and SLAB sets slab->slab_cache = NULL (to set page->mapping = NULL),
> 
> Hm, now that you mention it, maybe it would be better to do a
> "folio->mapping = NULL" instead as we now have a more clearer view where we
> operate on struct slab, and where we transition between that and a plain
> folio. 

Oh, folio->mapping = NULL seems more intuitive.

And we can reorder fields of struct slab more flexibly with
folio->mapping = NULL because we have no reason to make page->mapping
and slab->slab_cache to have same offset.

So it should be done in separate patch for SLUB/SLAB.
Do you mind If I send a patch for this after some testing?

> This is IMHO part of preparing the folio for freeing, not a struct
> slab cleanup as struct slab doesn't need this cleanup.

I agree that. it's needed for folio, not for struct slab.

> > What about adding this?:
> > 
> > SLAB_MATCH(mapping, slab_cache);
> > 
> > there was SLAB_MATCH(slab_cache, slab_cache) but removed.
> 
> With the change suggested above, it wouldn't be needed as a safety check
> anymore.
> 

Okay.

> >> +#endif
> >>  SLAB_MATCH(_refcount, __page_refcount);
> >>  #ifdef CONFIG_MEMCG
> >>  SLAB_MATCH(memcg_data, memcg_data);
> > 
> > I couldn't find any functional problem on this patch.
> > but it seems there's some style issues.
> > 
> > Below is what checkpatch.pl complains.
> > it's better to fix them!
> 
> Not all checkpatch suggestions are correct and have to be followed, but I'll
> check what I missed. Thanks.
>

You're welcome.
They are just a typo in changelog and white space warnings.

So now, exept few style issues, I can't find any problem in this patch.
And this patch gives us much better view of struct slab.

Reviewed-by: Hyeonggon Yoo <42.hyeyoo@gmail.com>

Thanks,
Hyeonggon.

> > WARNING: Possible unwrapped commit description (prefer a maximum 75 chars per line)
> > #7: 
> > With a struct slab definition separate from struct page, we can go further and
> > 
> > WARNING: Possible repeated word: 'and'
> > #19: 
> > implementation. Before this patch virt_to_cache() and and cache_from_obj() was
> > 
> > WARNING: space prohibited between function name and open parenthesis '('
> > #49: FILE: mm/kfence/core.c:432:
> > +#elif defined (CONFIG_SLAB)
> > 
> > ERROR: "foo * bar" should be "foo *bar"
> > #73: FILE: mm/slab.h:20:
> > +void * s_mem;/* first object */
> > 
> > ERROR: "foo * bar" should be "foo *bar"
> > #111: FILE: mm/slab.h:53:
> > +void * __unused_1;
> > 
> > ERROR: "foo * bar" should be "foo *bar"
> > #113: FILE: mm/slab.h:55:
> > +void * __unused_2;
> > 
> > ---
> > Thanks,
> > Hyeonggon.
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211211115527.GA822127%40odroid.
