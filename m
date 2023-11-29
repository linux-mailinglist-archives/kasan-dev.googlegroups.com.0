Return-Path: <kasan-dev+bncBCS5D2F7IUIIBXU6VMDBUBBACEWBG@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3b.google.com (mail-oa1-x3b.google.com [IPv6:2001:4860:4864:20::3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 8619D7FE21F
	for <lists+kasan-dev@lfdr.de>; Wed, 29 Nov 2023 22:37:05 +0100 (CET)
Received: by mail-oa1-x3b.google.com with SMTP id 586e51a60fabf-1f5acc3dcf2sf182142fac.1
        for <lists+kasan-dev@lfdr.de>; Wed, 29 Nov 2023 13:37:05 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1701293824; cv=pass;
        d=google.com; s=arc-20160816;
        b=TNGNhbNTH/0wdfVzO5+4fg25exKutE32HjRm5YJYhThQgcVvOIPJVnJ2ZJekbYZSC5
         PNgCmWdrMWAI52VV5YILNZwG6nXQDPiKCYvlY/Zp95IBIbswUC0EqnKOp8O9tTUjSz5T
         6nWGzg9fBKUflYa8U2Duzjl9UpldzDMPONAn9L4Or7ie8ZqygWzSEPJDGqa8RuLD8Su8
         0mCgS0RTflk0QtOgHkCxdf6v1W88Cp3mnc/IB0tmc06m5xC/klqRKH3vBvDV3JcIjOj4
         9XVd9sYAAfFEATruPDqx6MQBXtT4G6Wtpuf5Igu59AK2/r/Iv6p4GJs1i/cBNBKZBgFt
         J0Ww==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=xr85iuyNVGRskfZyuLV8mC6HZ2Q4cFegtS15nBKOCbM=;
        fh=sfyFUDc2Yxxc7p69NEOsj8/pSFZtRk/Y39NPcEotCLs=;
        b=Nx6qBKJ/7g8jlmHHFPeCKL5jypCpOl661EywMFYRNJF3An47f/96pdjNvl3wk7L9uP
         ZMHngBqKe77StkJvSXWZZmliNTi8kg5F+2nnd4tRQ4EP9X5Opq19N9hp1r58mlHr5njA
         ydWXyI6MSuZc4SUz2BLyDhVqFjjI3Pok2fwKL0XRbc8HfWQv2MMFD8m6rw8T6+bKQwT7
         mpannC1Z0Y00OOeCsO8yYuD6q0l/MohZ5SIzBJouL+kIKPpUiOj/EIPkfBYOmuhZbsdX
         fACB16QzuYQHl6Anv8bVQfGWxHR9wHp5+B5wBVvCj70gFGTn89nn6FoVhBfBVzGwJIhh
         KZ3g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b="Trk/qX+6";
       spf=none (google.com: infradead.org does not designate permitted sender hosts) smtp.mailfrom=willy@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1701293824; x=1701898624; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=xr85iuyNVGRskfZyuLV8mC6HZ2Q4cFegtS15nBKOCbM=;
        b=YtmdYFHxme3CkSnLNxRgwl+xvDd2x+CT68y2LyzKTWL8q8Jd70arHSNQJR5ucqizR1
         +SLx4Eu5xzK/8AbBvnGj8sYRAxMTHvtH9eThdjTXeBum9TiRyfevj50gwSRG+ah3/2IQ
         YYMdStnXUA3yrvIIaneTFLBkpKxNqw7QUDJ24YBxQ5z537kkK4XQxde4FhmNzyvhWdPV
         NszcDJchNS987HUozt5XQ/OV5eVl98ukmg9uhhuN1TaFTiMjPByUQm/D1lTdbK9tMWy6
         EkH9y1+9Afum0Cp17nU0uDPoCfjXci+8xnhjX/VrXFRXo2GCIXOZKpGOdZOgPu6lJmNX
         nr9g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1701293824; x=1701898624;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=xr85iuyNVGRskfZyuLV8mC6HZ2Q4cFegtS15nBKOCbM=;
        b=hEeisGcvfJFFu9h5syFMBORPK4yq8sobnp12SbZ5te++KVk4xPT6Ap49ACWPFVIYT2
         tnzrBzHTtdN4weSwqoU1NCs3aXAtPs2garZmzZFEN82UPBT6oN3ZGuheS4vSe3MS7Arn
         ehI9/F2ZEcTcidw41jK4yE6zXSOgkAhdE0K9xsxpe0HFbvqZHEMcvQny0s4yzUNunJVH
         9dj4dZ4o3+qpezISWDojyj5hwMBJJIlhPfYcqGRqGcp79Kkk5zamZHzWWKTeoJe8t8nZ
         E+JqO4xTqU+HFXTfCsyJX1ITJQ6J39vHRkew6w9ivvv4yczejBt1triz1zXwt/oy4tCa
         tDEg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YwUJQzVUxhRMX/wCvxa621ew7oBUfPV7phSSC74ovw3B5Z7X8Aw
	5XohW1WZSG0IXJvNNB6izpQ=
X-Google-Smtp-Source: AGHT+IHVmyYqvcFb5yBqKMXBhg7qGA2tEdBkB+6lhL1ALnytlWh1wOfohl9tCKlqT5uM0NN2RHFS8A==
X-Received: by 2002:a05:6870:9a14:b0:1fa:ca1:1f1c with SMTP id fo20-20020a0568709a1400b001fa0ca11f1cmr26444329oab.44.1701293824168;
        Wed, 29 Nov 2023 13:37:04 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:622a:1a91:b0:41c:d096:577c with SMTP id
 s17-20020a05622a1a9100b0041cd096577cls515901qtc.2.-pod-prod-07-us; Wed, 29
 Nov 2023 13:37:03 -0800 (PST)
X-Received: by 2002:a05:620a:a94:b0:76c:8fe1:604 with SMTP id v20-20020a05620a0a9400b0076c8fe10604mr523936qkg.13.1701293823772;
        Wed, 29 Nov 2023 13:37:03 -0800 (PST)
Received: by 2002:a05:620a:8ec3:b0:77d:cfff:33fb with SMTP id af79cd13be357-77dcfff3958ms85a;
        Wed, 29 Nov 2023 13:20:42 -0800 (PST)
X-Received: by 2002:a2e:9496:0:b0:2c9:bad8:3ac6 with SMTP id c22-20020a2e9496000000b002c9bad83ac6mr2888971ljh.30.1701292840903;
        Wed, 29 Nov 2023 13:20:40 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1701292840; cv=none;
        d=google.com; s=arc-20160816;
        b=Szhrqd3mvNCmr1rcwJlb0XZ0fbKzlKgV52rKFbkyPn24K2PakEO8WqFnS39JRfeP71
         tbEZpG9pf8ps+Oo3OsNKp/P9i7wwdpk16RuJ5EH22RR6FhZRz6UL+3ovE+IoLPsftK7u
         8QfrshpXJywgxRdyrk/JDxFRmSwZmkQ6fV5aF1kCKH5yy9w/ZgJ0Vu4n52b159bB+HvL
         qaKiGKJCLD9nw/6ZGVijNM1JlNsVJUZ4fhCl4IxQNOaZln4ZjDM3wSwdJ41Pj5I/5IfX
         0veP9LD+CdVyLYzAB7xlCewJ3nVOUGpoXntD1YLrYsVE+b/+OkvoUTVvf75JI5KYIXnC
         6QEw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=snbaImfv3zlormUNSdyLXEJtHqS0syGmg48S3ZeIobc=;
        fh=sfyFUDc2Yxxc7p69NEOsj8/pSFZtRk/Y39NPcEotCLs=;
        b=XtUI+yKMX2cVUhZO7TYOz9yy1CxyeU6/qH+UIWtDyRvJAvFJ/hvIzs/hO9NIx7gPLV
         QBwvL+ab0hTp7iJfT4LrwNxwTjUQCbnq7Gfa6SyyA30S7jpCV1ZOvGJWmaeoX5O5LAuH
         oHNP1KDkas0au+Hi84qokfHZ7G8Oad4wXIcx5hSNZm0lKg2JBsOQYkuNprofgt0MMfcR
         zr6h/xdvkHMoHPSLa+ZAwmVzMNgvuHaaGMDJ4UI9j054sSa8OG3gxEvi84X/alP+jCWT
         nJA8z3KKQWF+Ax9vN6BYkLyK5WVoM+2oyHETUAyWIdwMs3WH40oVWaPx1yMNnoLnNwSv
         CgPg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b="Trk/qX+6";
       spf=none (google.com: infradead.org does not designate permitted sender hosts) smtp.mailfrom=willy@infradead.org
Received: from casper.infradead.org (casper.infradead.org. [2001:8b0:10b:1236::1])
        by gmr-mx.google.com with ESMTPS id u20-20020a05600c139400b0040b47a6405bsi114710wmf.1.2023.11.29.13.20.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 29 Nov 2023 13:20:40 -0800 (PST)
Received-SPF: none (google.com: infradead.org does not designate permitted sender hosts) client-ip=2001:8b0:10b:1236::1;
Received: from willy by casper.infradead.org with local (Exim 4.94.2 #2 (Red Hat Linux))
	id 1r8Rye-00Dm4H-GD; Wed, 29 Nov 2023 21:20:12 +0000
Date: Wed, 29 Nov 2023 21:20:12 +0000
From: Matthew Wilcox <willy@infradead.org>
To: "Christoph Lameter (Ampere)" <cl@linux.com>
Cc: Vlastimil Babka <vbabka@suse.cz>, Pekka Enberg <penberg@kernel.org>,
	David Rientjes <rientjes@google.com>,
	Joonsoo Kim <iamjoonsoo.kim@lge.com>,
	"Liam R. Howlett" <Liam.Howlett@oracle.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Roman Gushchin <roman.gushchin@linux.dev>,
	Hyeonggon Yoo <42.hyeyoo@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>, Dmitry Vyukov <dvyukov@google.com>,
	linux-mm@kvack.org, linux-kernel@vger.kernel.org,
	maple-tree@lists.infradead.org, kasan-dev@googlegroups.com
Subject: Re: [PATCH RFC v3 0/9] SLUB percpu array caches and maple tree nodes
Message-ID: <ZWerDCdvVkAfsStz@casper.infradead.org>
References: <20231129-slub-percpu-caches-v3-0-6bcf536772bc@suse.cz>
 <b51bfc04-d770-3385-736a-01aa733c4622@linux.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <b51bfc04-d770-3385-736a-01aa733c4622@linux.com>
X-Original-Sender: willy@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=casper.20170209 header.b="Trk/qX+6";
       spf=none (google.com: infradead.org does not designate permitted sender
 hosts) smtp.mailfrom=willy@infradead.org
Precedence: list
Mailing-list: list kasan-dev@googlegroups.com; contact kasan-dev+owners@googlegroups.com
List-ID: <kasan-dev.googlegroups.com>
X-Google-Group-Id: 358814495539
List-Post: <https://groups.google.com/group/kasan-dev/post>, <mailto:kasan-dev@googlegroups.com>
List-Help: <https://groups.google.com/support/>, <mailto:kasan-dev+help@googlegroups.com>
List-Archive: <https://groups.google.com/group/kasan-dev
List-Subscribe: <https://groups.google.com/group/kasan-dev/subscribe>, <mailto:kasan-dev+subscribe@googlegroups.com>
List-Unsubscribe: <mailto:googlegroups-manage+358814495539+unsubscribe@googlegroups.com>,
 <https://groups.google.com/group/kasan-dev/subscribe>

On Wed, Nov 29, 2023 at 12:16:17PM -0800, Christoph Lameter (Ampere) wrote:
> Percpu arrays require the code to handle individual objects. Handling
> freelists in partial SLABS means that numerous objects can be handled at
> once by handling the pointer to the list of objects.

That works great until you hit degenerate cases like having one or two free
objects per slab.  Users have hit these cases and complained about them.
Arrays are much cheaper than lists, around 10x in my testing.

> In order to make the SLUB in page freelists work better you need to have
> larger freelist and that comes with larger page sizes. I.e. boot with
> slub_min_order=5 or so to increase performance.

That comes with its own problems, of course.

> Also this means increasing TLB pressure. The in page freelists of SLUB cause
> objects from the same page be served. The SLAB queueing approach
> results in objects being mixed from any address and thus neighboring objects
> may require more TLB entries.

Is that still a concern for modern CPUs?  We're using 1GB TLB entries
these days, and there are usually thousands of TLB entries.  This feels
like more of a concern for a 90s era CPU.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ZWerDCdvVkAfsStz%40casper.infradead.org.
