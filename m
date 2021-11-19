Return-Path: <kasan-dev+bncBCSJ7B6JQALRBMET4CGAMGQEAIULHFA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3a.google.com (mail-oo1-xc3a.google.com [IPv6:2607:f8b0:4864:20::c3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 6D5F74577C5
	for <lists+kasan-dev@lfdr.de>; Fri, 19 Nov 2021 21:31:46 +0100 (CET)
Received: by mail-oo1-xc3a.google.com with SMTP id 68-20020a4a0347000000b002c2ac2c476dsf6784471ooi.21
        for <lists+kasan-dev@lfdr.de>; Fri, 19 Nov 2021 12:31:46 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1637353905; cv=pass;
        d=google.com; s=arc-20160816;
        b=nY13hkPVipJqNrwsjvkGxo8jNpgxcpAmmlPjx+Joou8IsMyBpXs4otayAYOGxy4xRj
         84qfIOKHhYJkAMHAcfxHGPAXmPszf8o9VJGqvC0CNu3dibU3QuyNiJ1xLCg+3FUEfPgB
         A/Kl2T/dXJ6HmpSmqrJpZFYn5ZwssVvh3lgnj6Gb1F21aF6WjMwwTxIvlgfojGECDY0T
         JrTEJixxZ9Zj134XfdJ3lTd0hQ/UxY6dto57Z2DGv8h1c1PpTvvmB45SUZ/y7tCCJpBu
         BtvSVhR3UrQrBL0p/qi1ZENua9tCW1Duf2DUh5N9uhzV8uNMXN6WoHa2b9VAzRBNQtSr
         Yh5A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-disposition:in-reply-to
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=3bfyhZolZbgq6FBhJGUyv9i79YqLac+YFvuGCajeDFk=;
        b=FHLUk5rii6glv6azSdzoZHXhzgdwLgOx4wiALtySZc3sWAKD/xpAXd/PUzDj9v/47L
         9XpexK5+LSpW6QuXETbl3pVTQWF5TYwCb06CrmFeWDT/aIQHjrLkgn/FMlpjuzDTAF/S
         rTJvWvf2xQxKHhlOGP9bbOILV9E21D1KhPIglWkQjF1uzfeMAcE7UrpnXopGEc2MiJf3
         9VuRlmGPRUqSoucQjnGzqJ84rrVORHU1A3yPD6qUSugRiwzqKkAS5zoIQFEn1Hqjgfgs
         6aU2+HWwBqwFCRvDvNl6eqvt3kttFOcU/PIkhEF+2nCdk8+yDibgusFyn6gaZP6F7zhn
         /4lA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=MkC+wTlV;
       spf=pass (google.com: domain of jpoimboe@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=jpoimboe@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :in-reply-to:content-disposition:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=3bfyhZolZbgq6FBhJGUyv9i79YqLac+YFvuGCajeDFk=;
        b=bCEhp5I4+/FSiKtF5aTpBNCFg4kf9ebEtdUrllvHjcyTevmnk/zD5PbszIb6QJtJAB
         ziQdH6/hnR8BiBV4PGBQETT5ueV5GSuA0VZizWfLQvQG+TZEN3ePjzC40wVxeAxayGvh
         500qUWZzlpINlv/zWDAajPl8+94MIB6MStwNG0eHIUtQqjdp8ce68thULD5dtbx7Hnzg
         7wqAyIW5a3quiR1+H2XounEdU7kbP9LwQiiqFQxoI3b78FJKMdeFOOk8JPTWa60+aidJ
         5sgGiZcipLTtRP2/yX4isFOt/OHpJsgmNMqAQWJCDSosCoqIS7sh0EeuFX1FQ7KqvJRL
         oHvg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:in-reply-to:content-disposition
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=3bfyhZolZbgq6FBhJGUyv9i79YqLac+YFvuGCajeDFk=;
        b=bCTArcV8spiMbcvzU2mNF2u7DVqhN8c9hBdDHdwUOlPkj+bXOwXLYZ5VEgCLYnf+r6
         yGwjzJ1kNrFpyVh8l7rt+TZr7chfUyED0UoZpKy1CeN24NffGk4IoIb3Wq+JIn5tDsOe
         0/2/2uPqTavUmVNK/XEu6CADd4Lo8GFcPtRqGsiQh9U5TwfW+JQZQRaKdJeLlDiMaflR
         MpG3/TTh0o0w6O/k1asM3KaFfrIQuOyY41yqKpZjo0UqkpKQBnHaxnh+9hIo0+tNkox1
         QgM0ymq4z7sVhlLXkbTLMbcdZmSWLs1ioClWZw5VDCHpSBh44FqSSMUvGcLrJ9aiQajR
         F5eA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533MmX6Uf5HC+ORXAGUS9l2gkUirV1ZROACiLRo1C4dIUPuhT0LR
	YcoptKwTv9lymQTH6jLw48Y=
X-Google-Smtp-Source: ABdhPJw4gDQRNbVl0Ztrrg0rqRPr71tZCIPwBucXuJ7JX3ymQ8Zm+N6F83qskhhgl4S5/R+ZhebVIw==
X-Received: by 2002:a9d:6001:: with SMTP id h1mr6909133otj.257.1637353904916;
        Fri, 19 Nov 2021 12:31:44 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6830:3499:: with SMTP id c25ls321765otu.4.gmail; Fri, 19
 Nov 2021 12:31:44 -0800 (PST)
X-Received: by 2002:a05:6830:310c:: with SMTP id b12mr7080904ots.240.1637353904596;
        Fri, 19 Nov 2021 12:31:44 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1637353904; cv=none;
        d=google.com; s=arc-20160816;
        b=ugz415KMwTzqIGwaKsQv8BQOdphyP3AXMy8XRAkEMDFgcxNS4ld6ErEoKqIji6OuWk
         krGy7bqCYixB9dYOFJQskOwU6G4XgdiDB8EdQvjuo7lZvw+kvrnjuO8szoUqsH5/Tfvc
         tZkgxAK7EWARsTvlC2T6CzloqVLC9/t7EqFbHF4fQUccp4bBhb99Zc3U4/9+rBMnjQCI
         qcH/rJt0eBxHEsFVfKAW9lrlBmVtUgYNP2HKRCnDhaF9pytnn063NmBKNYBpgswhL6Yl
         vxTJH0hhT3aepq6FSDJMkb88J5ecPaAvz5RY/l1PamziwTeVyFPcH7nTai74mpLe+03H
         JqIQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-disposition:in-reply-to:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=P2sZkZbNWImGK5CgW7dFwBi8zGA25zK0xwbZ1WxQTIw=;
        b=BwS05mBcssCIJAkv0udKKTIFQaPK5asXLXvI0uzbhWjKs+iZ0JVUkWa+weDXXHDqu2
         Iki4OKCrRe3/jixH2GJMNVjkaA94g1muFavpnf5WDkgdvihLR9tkITB1f8UO3f6Ttq8G
         UKIr8XbybcMuesb8BQrcQrO3egIsBkVGNl+oirzb7SC7BSo5fPSwXa/r75RqkVsveShW
         3gBqhPCjLP06Ht0coIrSfqc+cY4nIoRvUM07m09HNbXmYppWrQ/Us97CW+zQE/OpkZpd
         lpVH1kDb2BKFtBpDEQ/kPROJpp3Kr9Omoc0ipOhRUHIq2t7pMsU9+O8TI623VhfHuUwM
         nwMg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=MkC+wTlV;
       spf=pass (google.com: domain of jpoimboe@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=jpoimboe@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.129.124])
        by gmr-mx.google.com with ESMTPS id bj28si140519oib.2.2021.11.19.12.31.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 19 Nov 2021 12:31:44 -0800 (PST)
Received-SPF: pass (google.com: domain of jpoimboe@redhat.com designates 170.10.129.124 as permitted sender) client-ip=170.10.129.124;
Received: from mail-qt1-f197.google.com (mail-qt1-f197.google.com
 [209.85.160.197]) by relay.mimecast.com with ESMTP with STARTTLS
 (version=TLSv1.2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 us-mta-51-3_o-6FK4N1G7l11wRGn3ew-1; Fri, 19 Nov 2021 15:31:40 -0500
X-MC-Unique: 3_o-6FK4N1G7l11wRGn3ew-1
Received: by mail-qt1-f197.google.com with SMTP id v32-20020a05622a18a000b002b04d0d410dso7817509qtc.11
        for <kasan-dev@googlegroups.com>; Fri, 19 Nov 2021 12:31:40 -0800 (PST)
X-Received: by 2002:ac8:7f52:: with SMTP id g18mr9425073qtk.190.1637353900226;
        Fri, 19 Nov 2021 12:31:40 -0800 (PST)
X-Received: by 2002:ac8:7f52:: with SMTP id g18mr9425020qtk.190.1637353899973;
        Fri, 19 Nov 2021 12:31:39 -0800 (PST)
Received: from treble ([2600:1700:6e32:6c00::35])
        by smtp.gmail.com with ESMTPSA id z13sm374393qkj.1.2021.11.19.12.31.37
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 19 Nov 2021 12:31:39 -0800 (PST)
Date: Fri, 19 Nov 2021 12:31:35 -0800
From: Josh Poimboeuf <jpoimboe@redhat.com>
To: Marco Elver <elver@google.com>
Cc: "Paul E. McKenney" <paulmck@kernel.org>,
	Alexander Potapenko <glider@google.com>,
	Boqun Feng <boqun.feng@gmail.com>, Borislav Petkov <bp@alien8.de>,
	Dmitry Vyukov <dvyukov@google.com>, Ingo Molnar <mingo@kernel.org>,
	Mark Rutland <mark.rutland@arm.com>,
	Peter Zijlstra <peterz@infradead.org>,
	Thomas Gleixner <tglx@linutronix.de>,
	Waiman Long <longman@redhat.com>, Will Deacon <will@kernel.org>,
	kasan-dev@googlegroups.com, linux-arch@vger.kernel.org,
	linux-doc@vger.kernel.org, linux-kbuild@vger.kernel.org,
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, x86@kernel.org
Subject: Re: [PATCH v2 23/23] objtool, kcsan: Remove memory barrier
 instrumentation from noinstr
Message-ID: <20211119203135.clplwzh3hyo5xddg@treble>
References: <20211118081027.3175699-1-elver@google.com>
 <20211118081027.3175699-24-elver@google.com>
MIME-Version: 1.0
In-Reply-To: <20211118081027.3175699-24-elver@google.com>
X-Mimecast-Spam-Score: 0
X-Mimecast-Originator: redhat.com
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
X-Original-Sender: jpoimboe@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=MkC+wTlV;
       spf=pass (google.com: domain of jpoimboe@redhat.com designates
 170.10.129.124 as permitted sender) smtp.mailfrom=jpoimboe@redhat.com;
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

On Thu, Nov 18, 2021 at 09:10:27AM +0100, Marco Elver wrote:
> @@ -1071,12 +1071,7 @@ static void annotate_call_site(struct objtool_file *file,
>  		return;
>  	}
>  
> -	/*
> -	 * Many compilers cannot disable KCOV with a function attribute
> -	 * so they need a little help, NOP out any KCOV calls from noinstr
> -	 * text.
> -	 */
> -	if (insn->sec->noinstr && sym->kcov) {
> +	if (insn->sec->noinstr && sym->removable_instr) {
>  		if (reloc) {
>  			reloc->type = R_NONE;
>  			elf_write_reloc(file->elf, reloc);

I'd love to have a clearer name than 'removable_instr', though I'm
having trouble coming up with something.

'profiling_func'?

Profiling isn't really accurate but maybe it gets the point across.  I'm
definitely open to other suggestions.

Also, the above code isn't very self-evident so there still needs to be
a comment there, like:

	/*
	 * Many compilers cannot disable KCOV or sanitizer calls with a
	 * function attribute so they need a little help, NOP out any
	 * such calls from noinstr text.
	 */

> @@ -1991,6 +1986,32 @@ static int read_intra_function_calls(struct objtool_file *file)
>  	return 0;
>  }
>  
> +static bool is_removable_instr(const char *name)


> +{
> +	/*
> +	 * Many compilers cannot disable KCOV with a function attribute so they
> +	 * need a little help, NOP out any KCOV calls from noinstr text.
> +	 */
> +	if (!strncmp(name, "__sanitizer_cov_", 16))
> +		return true;

A comment is good here, but the NOP-ing bit seems out of place.

-- 
Josh

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211119203135.clplwzh3hyo5xddg%40treble.
