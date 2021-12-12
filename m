Return-Path: <kasan-dev+bncBCKJJ7XLVUBBBZ4722GQMGQEZEDUX7A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x239.google.com (mail-oi1-x239.google.com [IPv6:2607:f8b0:4864:20::239])
	by mail.lfdr.de (Postfix) with ESMTPS id D5E524718D3
	for <lists+kasan-dev@lfdr.de>; Sun, 12 Dec 2021 07:00:08 +0100 (CET)
Received: by mail-oi1-x239.google.com with SMTP id w131-20020acac689000000b002a813c6e600sf9456809oif.1
        for <lists+kasan-dev@lfdr.de>; Sat, 11 Dec 2021 22:00:08 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1639288807; cv=pass;
        d=google.com; s=arc-20160816;
        b=TwABkk4zCXQz3cvLrE5RhuezJdkPV2ufTsVXYaphyJfrkn9vKtoHrwl/rnlitTWvn2
         9mg42bJxiD9l6wJjUBDccpMamdQ68uEzIRpCRIwln3wXhxULBkKYSw0PI2OE6iN3gZRP
         U0ORpgVv6tlvuVBSwaNtMEXcSEumWNa0xZIkk/KmE0STRQRoz+ti2JtZwCNnGF20/YzH
         5jpVFU1XVNulSYAYMLmqgZ3dqiN4HDd/8FgLkweZwLgRy7j79hZCHrdcrI0d9MlOG/W5
         D71HMuI+/ibEgBxWCOoWn/rNznMCoKSILIgXq20bEmEmWKCs/a+vkaBwbcAPy44nhpZ4
         iPmw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature:dkim-signature;
        bh=2ewbHxk8JWVYU3f1S4DOE8vCkuQw/+5BGmrYHkHu+E0=;
        b=eghnt149cDr/3SOpxHAProzLUhzrgeD9lan0wOMd74m6HxtwwRhhHj7Rv5OlvyPVk6
         nd8UE5p/EDSeOQcXst+94yawLETGLJL5koOhcPbZ03HLu0CGCQG6aZmIjFke3EaofRAV
         btnbi2TjnAw4HL2b4H997nNJOkDSrOU3hnWSz5tCtyt7p1puIZR7wTTFImiEjM+mzM/M
         0nebxJCMuI1+OtUmvs8n3zWt5ap42FX38O+0GUgjHnKZyhWTMvRohurCesw6poXJCleS
         OBD/BT33YDrT/FgJx+sf1QP1c7EexrYR2w9ozbDWULCWUj5CYBgZn5T73AEtRw28dScD
         79GQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=Fx13XGlX;
       spf=pass (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::530 as permitted sender) smtp.mailfrom=42.hyeyoo@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=2ewbHxk8JWVYU3f1S4DOE8vCkuQw/+5BGmrYHkHu+E0=;
        b=Q4HuDJ3+GaEbrN6WUseXBYiAjuRyAUXmrReTXgo2dBI0GOqfCjve0Jtth4Yft6yTg/
         b42F5qrRYT9ANW05sB+E4GmrIIlC1l2Hmsb11PC5hXS7WqSYbTI0+ZRSh2ekGedIM1iz
         CbictjEkbh5P+1oKyv+g66SGax8kqYlSBeReaBnvVRsWfz63AuB0oOna14sLkNFQ5bsF
         RatQDB6kd7bzRfdAhvEHl9Vf9A10SJcw7NVtffhzIeIc4XBUhuh/Cuzmx/IwOhI7+nfm
         Q7iik2Uo3Ut1hLY7VC85jEuphGXoHAPvKmGUifT/LbcO9wbh956siFrB6ZNfI6CTyCPC
         CI9Q==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=2ewbHxk8JWVYU3f1S4DOE8vCkuQw/+5BGmrYHkHu+E0=;
        b=fS2ZJ2EnCtP51C5GYd8WuqDQLMW/OhunLkeFf48BCZ4Q4pV5phStKsm0Xvmwul5Zw8
         m+Bc+4Al6HgvHQTbctCeQtLLPcF/enc+z9UUQQvWVK1T04jMqC7v7ktJdJJjgNI1tFUE
         fkbv5yPdekkwo5f8ZvyMmLigw6lf6DQVCXI99NRadPMpP6rw1YQ/siuzvw9031Jlv//y
         PmmyslUXSHiPXM3zfJ7pDwQXgiKSaxes/d3Ng9whGyGADHc2+QLnJKKva6hV8HNrVJ6n
         oApd8TPD4X1EHjTB4IKoZKpH/HcC2a6B9A/XDhCAMk+BbPeliBeZVgP1zbBZoKFhbQ7k
         QNOA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=2ewbHxk8JWVYU3f1S4DOE8vCkuQw/+5BGmrYHkHu+E0=;
        b=UqsPoRsb0LxVDZE4PhYVTVZZjMnTOVb4LNhP5aPnpsnl1ErS8RVmIAoCm2obrN5RrH
         UjLzMERNfAok9U8HOfuZGbxslA0U97Z776l98iH2UCT2L2Ce9Qfs77Q4l5Tr4juUCynF
         goavGUHBp5/NxnIKf1HuE3Bh/Ai5/8ixS2ok5PwO6evisfrsT+A3HzG0YX7SuQYPdIYg
         t6NvjVsrxB0eZSUlJMLKSkp79If7IVmy32nbQYbS4X1ct7TNQ7izb3Hve2DCQwL5AS7Y
         1YN6Kiska2ocX8mZeF6CLckKm6VioLiSiahGlW69bXmD+bl7/zYemK2FNzR7uSDov6P2
         QVdA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531IfUmz9P1LGsYUuQTlHCdJJ8qMQsRlVf0vTZpA+xhlORyYz0qc
	isRzi2QwX/lsCMmGlJBRU8U=
X-Google-Smtp-Source: ABdhPJx1kRetmY3CxZtwEYafjqxyjxKGcmqfzcC4dDpo0SS60FzPsGXgKYylJfZ7u3yHjt36EwQS5w==
X-Received: by 2002:a05:6808:11c6:: with SMTP id p6mr21440834oiv.44.1639288807629;
        Sat, 11 Dec 2021 22:00:07 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6808:1921:: with SMTP id bf33ls716324oib.6.gmail; Sat,
 11 Dec 2021 22:00:07 -0800 (PST)
X-Received: by 2002:a05:6808:1709:: with SMTP id bc9mr21380682oib.130.1639288807327;
        Sat, 11 Dec 2021 22:00:07 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1639288807; cv=none;
        d=google.com; s=arc-20160816;
        b=xdDeSVjjcXAUys7u1hXZ6wbYz0+8MfPtCraECJRAxmFyfFRctICenptPYoE/3A5M87
         bq+0+ESkkDTi1oCf+zgr+haoC+DjOJAUhT0+pzOThL0gAaN9W9ySTznOj4kNk8n2ZGeh
         kBRZt7xyGQet4NH14lX2gQfO+qW4Um0VYihr5/lkt7cr/Bh5lW5xAEDv73W9iDcqDgFR
         Nqc/fAYM9968sqDEgBMMMlEBwLA810SSiKJZU5pL2yB4r0yCMfg72gJXopK+ou3u8s3X
         2NrpuX/RTQvyVGQ5a82fLSgJ7KnQgyvmpaF9pXt0kRei8edT/PASDX3Jb09D0MjHMVRI
         uJ0g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=kB9exNo42Y5DkFvS1nHe23MR4UO4ZzBwWX7LEeG3EKg=;
        b=Gsj9Szdc4BrtzNH5Hw2WCWQ89jtQpApPg+iKgnpl5OwHGQcpLZe7r2oe5VkNAf57wt
         OLzGic1fki0xaXA+Jw5Msz5KHxwF1oovFwzedo+/J3glsUbYqEHaIdwojtVQU90efP3I
         uV4rY3PKFMi/rxzcWbyHQOE9hKtG0nLKr/Q1F6CZJOaoyUzFM3CJAYeAvOyszGu/X84y
         f8uiDJA3+JPxJfOFrSAx9hb7HGgHARTNhRu/MLE1pIXEAcZhDrcXDbBV+sLVXbTsTweg
         Ksq9bN8JI3PzJZ4nHImBAIkr8n8Rt8fafKjNH7EMxr3qL/mKhY0KXW7jTMF091fAvO9T
         eW8A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=Fx13XGlX;
       spf=pass (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::530 as permitted sender) smtp.mailfrom=42.hyeyoo@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pg1-x530.google.com (mail-pg1-x530.google.com. [2607:f8b0:4864:20::530])
        by gmr-mx.google.com with ESMTPS id w29si750238oth.3.2021.12.11.22.00.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 11 Dec 2021 22:00:07 -0800 (PST)
Received-SPF: pass (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::530 as permitted sender) client-ip=2607:f8b0:4864:20::530;
Received: by mail-pg1-x530.google.com with SMTP id k4so11633453pgb.8
        for <kasan-dev@googlegroups.com>; Sat, 11 Dec 2021 22:00:07 -0800 (PST)
X-Received: by 2002:a63:5407:: with SMTP id i7mr37203096pgb.242.1639288806677;
        Sat, 11 Dec 2021 22:00:06 -0800 (PST)
Received: from odroid ([114.29.23.242])
        by smtp.gmail.com with ESMTPSA id ng9sm3492264pjb.4.2021.12.11.22.00.03
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sat, 11 Dec 2021 22:00:06 -0800 (PST)
Date: Sun, 12 Dec 2021 06:00:00 +0000
From: Hyeonggon Yoo <42.hyeyoo@gmail.com>
To: Matthew Wilcox <willy@infradead.org>
Cc: Vlastimil Babka <vbabka@suse.cz>, Christoph Lameter <cl@linux.com>,
	David Rientjes <rientjes@google.com>,
	Joonsoo Kim <iamjoonsoo.kim@lge.com>,
	Pekka Enberg <penberg@kernel.org>, linux-mm@kvack.org,
	Andrew Morton <akpm@linux-foundation.org>, patches@lists.linux.dev,
	Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com
Subject: Re: [PATCH v2 31/33] mm/sl*b: Differentiate struct slab fields by
 sl*b implementations
Message-ID: <20211212060000.GB882557@odroid>
References: <20211201181510.18784-1-vbabka@suse.cz>
 <20211201181510.18784-32-vbabka@suse.cz>
 <20211210163757.GA717823@odroid>
 <f3f02e1e-88b2-a188-1679-9c6256d19c7a@suse.cz>
 <YbTQk9Dj+kUYAX09@casper.infradead.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <YbTQk9Dj+kUYAX09@casper.infradead.org>
X-Original-Sender: 42.hyeyoo@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=Fx13XGlX;       spf=pass
 (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::530
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

On Sat, Dec 11, 2021 at 04:23:47PM +0000, Matthew Wilcox wrote:
> On Fri, Dec 10, 2021 at 07:26:11PM +0100, Vlastimil Babka wrote:
> > > Because SLUB and SLAB sets slab->slab_cache = NULL (to set page->mapping = NULL),
> > 
> > Hm, now that you mention it, maybe it would be better to do a
> > "folio->mapping = NULL" instead as we now have a more clearer view where we
> > operate on struct slab, and where we transition between that and a plain
> > folio. This is IMHO part of preparing the folio for freeing, not a struct
> > slab cleanup as struct slab doesn't need this cleanup.
> 
> Yes, I did that as part of "mm/slub: Convert slab freeing to struct slab"
> in my original series:
> 
> -       __ClearPageSlabPfmemalloc(page);
> +       __slab_clear_pfmemalloc(slab);
>         __ClearPageSlab(page);
> -       /* In union with page->mapping where page allocator expects NULL */
> -       page->slab_cache = NULL;
> +       page->mapping = NULL;

Didn't know your original patch series did it already.
Vlastimil, would you update that patch?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211212060000.GB882557%40odroid.
