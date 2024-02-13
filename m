Return-Path: <kasan-dev+bncBCF5XGNWYQBRBYHGVKXAMGQEKWA4PFI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63f.google.com (mail-pl1-x63f.google.com [IPv6:2607:f8b0:4864:20::63f])
	by mail.lfdr.de (Postfix) with ESMTPS id 9D83F8522ED
	for <lists+kasan-dev@lfdr.de>; Tue, 13 Feb 2024 01:10:09 +0100 (CET)
Received: by mail-pl1-x63f.google.com with SMTP id d9443c01a7336-1d93f4aad50sf195735ad.1
        for <lists+kasan-dev@lfdr.de>; Mon, 12 Feb 2024 16:10:09 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1707783008; cv=pass;
        d=google.com; s=arc-20160816;
        b=rZ7f1ZYLQNPm2yv062w66SMExROnokEdaI4Kn1f6oSODI3YMAZn0F2SyOqahU6H/2K
         brd70HwCqwE+5aKlcCJL/Rmrg3k1/ax4FQlrkbo/s3xzHk0vTCQtIcYxQM+MVL8HX7Ij
         /RmiEn1V2NfIISEt33DTABfUf1UbzdWvXVRv6dzxNpWvZcOMdJGMn3a4U5+C05JuvUY3
         BrAIoszs0QHMvld6gUeRelHoB+mIJ2GayZ4IFQoWIO2ANNKvjDm/YyZoOQpnzWpryLqJ
         91/KLCwj4qoNDJ47fAA2vo2A1MRfFAH+sV7qFdMy99+fcTFXxof9dmWgTbTJ7JwnYz56
         BdvQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=UXRKNnPOrjixpp/AtDafaNRy3YK/yX+Mblwi9RWrlUo=;
        fh=c8t0zlQUpMy/GE0UgFJSv3rA4TiGuC/AGC3cdZeGEJU=;
        b=PmBRKfLu7UWqbnejvOj1uN038FaoguChACQuh5PMgn6UNe962oIP5Et6t89fjTOKnA
         m14Q/KVu3AjNz75Xtzw1r5kQBmKA9yLoh5JKAe5IMxfvKQRLX2diJLj4Qd9dXWDOij0D
         375RbUtA7KTcIAHwYnPkV7X5LMYbl37QOC8a7wV3ghhIBgxApE/q7KXaKT1wD33g/yzy
         5Je2BqljEt85e++qf0x9N9mStpfwd302v2fLg3eWLkJ+SW2/xTl8h45nfzm6b+S22DBg
         n9KppF4enDgSXxYKuuBMIJOlSqp6D4lo+hPymTX54XdTCLITeGO5PxDfn38VqnegWwSM
         lxUg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b="Mkv5ZK/A";
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::429 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1707783008; x=1708387808; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=UXRKNnPOrjixpp/AtDafaNRy3YK/yX+Mblwi9RWrlUo=;
        b=Es2jkd5qD2TQDsD7G1Z9majuEL37HHSnH7+3O8og+H6VlD3tkQNfDP5KUaoBe6ICvn
         Ot+WpjEVsJShBUR7NuzWTXEbg+yJjvss2gIso/b53Q+TU3h3Yi8fdJyq+yLCezhq9eeR
         DVWghzzivSF2UUcilKE3j7+u8OaWYuBeeu005u/pnZTc0Bq77Ws8rYFqtNLODoaZKocs
         XFe+EB5AgFLbeHjD6ZVqVG0NXb1oo4GbHtA5l41yXhnOlYfFCopuKBhXc2z7gzbmdqGv
         jL7MLNLCsppytrdz56ewi9MrMS7gyXgsVZugp1KQ/AzczdkajYHq+H8dNOufv3NvmCch
         Khiw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1707783008; x=1708387808;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=UXRKNnPOrjixpp/AtDafaNRy3YK/yX+Mblwi9RWrlUo=;
        b=TkitCISNFQCMO/tO/FlG7jyeXE9HO1efTDOkTZETIv7GPF2KeHxd7sy03bgu3VU9J3
         QO2ZcmtUpWJcVfG9ElAC3KljnEoBLri6lmijX5d9VWW1KoysanLBYP3BokC1zU1rOOnJ
         yHxtHwfA2u/rfi7Cw2Mou3K3IpnP5cQwzb1hwGTglj8LYchKalhZLSnNC2tpGAfKlnhU
         6EfIFNTfAl5wYHrGnR7ULOOFsy/S+meyhdzC+jfBspaV/xaOJq/feEplytDKs257uWI+
         SMKJaqVG2FdMWTCTRAFaX9Lnvq5RUKUocxHc9aDYWnYk69p0/l/rXUxkfoAQrCH3Jcsq
         EDlg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVkTKYDwTCnIu0XaL3kFcZw8B6Xc9YbeoNF9BeFCAxJ03mfcztYoAcBrokzIL+MVXIhlMBZc9rsxaQeYxoVa4tC2lmdg9TUjw==
X-Gm-Message-State: AOJu0YwVhHHSjdFoqODE7lERzgb4AA5u6xcvL98Q6uhcQHILsPRxbJFv
	PlBpOLUmCSdiH9/rTuqvpL3L+OtqtzzsAznYlboXsUwrpkcHXIV8
X-Google-Smtp-Source: AGHT+IGMFcEbnAIOwkANMnRGMuvJ12VJFOMdiILL98dQhFIcrQOy99Vmqfi4Bf2TLH+tHfBXVDVBwQ==
X-Received: by 2002:a17:902:b20c:b0:1d9:3524:3db2 with SMTP id t12-20020a170902b20c00b001d935243db2mr12832plr.11.1707783008258;
        Mon, 12 Feb 2024 16:10:08 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:f78f:b0:21a:7a0c:9511 with SMTP id
 fs15-20020a056870f78f00b0021a7a0c9511ls283376oab.0.-pod-prod-00-us; Mon, 12
 Feb 2024 16:10:07 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXJXwiHtAjFb0B4qmrtf9pZUuc9CXaQrRAK78w4PAyVGPVwELnj1E0KgBGo9rZr4s28jb8O3wdZGhoZb8Dn6oIFjKJwH08676a6qg==
X-Received: by 2002:a05:6870:610c:b0:218:6d18:689d with SMTP id s12-20020a056870610c00b002186d18689dmr366876oae.17.1707783007198;
        Mon, 12 Feb 2024 16:10:07 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1707783007; cv=none;
        d=google.com; s=arc-20160816;
        b=r+mWYvF48xWRLQG3OX0Niln3e3MoHKOJAxbnPkX8dt+0/MERzMPyseOiBkbFFvRpy4
         kj4M95v4jgAPp4WLy6hAb6K2Xu7rFi6qbD7YdW5nho1W1zZ7AOBRG6T0/Ebm+b7+P8q+
         c3PhgJg33eI8pSXMgNtPSpKZuKPT2t9RqIxf9XuieKakModGm+wCoc4Z4i9cmHPD/H7D
         PdomzgFpO2S9nVcCx67qJYPWJfKbi6s64vg/PF0FYQLdGR57EtVTwn9+aJqu9a8opXvF
         cCS6n7SYpJhfbAn/DN5FP4XmqNEC/8r0D3Qjn98IY49ml/Eiz5cghI+pD0+519fgtgj/
         rI8g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=CVCj3/bUzmp/ihK8I5QTojP8ThiaEloYRG+XcmjM3wg=;
        fh=CxY1QkynP8jSLFwkQ4TgCbn3KYZr9HmXWDegEfmd3V0=;
        b=DEu4cLv2gPeuWIG3TIDz6T6tdPxCAF/hwdKTtWXqF15jQ7Yi2oS8k7TdvELsQUspZ2
         5zFbXO2dcpeuhzEoFwuHiDXmGenGzfONhWmmPOa/MAAtCyOXEWeaGrAZ6r7uQ3cXnghv
         /ETHy00EoiX+ZErQx8G0x8KGZSSlAXSHl2DaaolfgQ6b4JDxN6lNc5+DfVbI3ce1nwWT
         0uQ110i8Qx9iKM8GvjATO3yjdO2TA3PwoeOpoZB4XavsYn8neLo2T7BbiLLn/mW3V58C
         KCrHn0941IsC/5dsIuf8M2sZx/qBJOi+Uqmff2N8S6DqtYzlrPxu2GRmxJh9Q8eX82ub
         5FlA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b="Mkv5ZK/A";
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::429 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
X-Forwarded-Encrypted: i=1; AJvYcCVjX9n4xBDKhkkY+AjHk/3WZkF2lyQlE0mWeRf43m/K7wEivdyf5PfvFdpJUZhIr0tc4k84aj2O9U/6BxQbGG7RXIyaBEUXnMeyHw==
Received: from mail-pf1-x429.google.com (mail-pf1-x429.google.com. [2607:f8b0:4864:20::429])
        by gmr-mx.google.com with ESMTPS id ti22-20020a056871891600b0021a216d3a62si700020oab.5.2024.02.12.16.10.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 12 Feb 2024 16:10:07 -0800 (PST)
Received-SPF: pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::429 as permitted sender) client-ip=2607:f8b0:4864:20::429;
Received: by mail-pf1-x429.google.com with SMTP id d2e1a72fcca58-6e0dcf0a936so715482b3a.0
        for <kasan-dev@googlegroups.com>; Mon, 12 Feb 2024 16:10:07 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCVNEXb/C3opTUMqn+ZtMe+Bi/d3IYz4ksURwD/XXYxLo3gMlYKLZJF4feQFyRFc0T2fDZxCe41lLEDcR0OFMABvbn+oycbby7Txug==
X-Received: by 2002:a05:6a00:4fd5:b0:6e0:e64d:8da2 with SMTP id le21-20020a056a004fd500b006e0e64d8da2mr1514832pfb.14.1707783006424;
        Mon, 12 Feb 2024 16:10:06 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCVSwAySHXKx1pUrrLt55Zdm1EhMhKCx6ob3G7LFoadWJ962SsWvGkNWGLwN8ABMsjJcHo82VKcqfHdaZMMC3ZX8bsOVpIAn1GVyTr0qMTj+0OHs77XxyPp+cneEpG8Vvu5mriNkWXzs2VGJglCc8a5uMrzZ+Q5EPTh+PVyomZkA6d3etvY2gW+CpacE7VzChzFWp0UZ1v2PhmxtPs6udlgCYrEp7N7DewKcRhvMyjTwFZvVVZraA/zVXr/BI6kbq8hRw6xoQM50BR0VPsXtCk4Soe3KO59VQcI9uqOtzno5uQHiucZV9TFt9Pv0xz4rJEyeewF62QGqRaVl9h/Eig9qPBbxWxC1ekmon24FxjhDlLHtGfAmL0JIWsvJQtJ7i4pvrBA2ovaVbN2Axl3vHJoeBKDuuQ4Ra3I80lml2thHScWSw1zi1azW3xy7zwY4UCUlrnAhz997arbpJ4kkF/UceHW5D6V1zGjdoNrme3bVYynn5mGhECWbYhZHrqvoPyHFtw7ikSp/Bv32HZkSDIwVlIVDJIDlWv/4EB2g/k/CI6iJJITUhQwQr8NgkzqRpFBAdbHK591MrALuoPYthE623YQRoccEH1Y/S69Un788TScfzp7RkqO+EjrUJ1HSVlRHKOnbTFUh4EcNaPebtMwoKKNX8th7w/X4/yxvG+LA7ZmeEzPdo/5q7aoEzt6fFhjfV6+heqvroMrfW5aBQdGBvM8yclut2olJC7xlKUGdy3ztrhOyW+3yOtFd1aRJXgwfQBE5x2/wpOF8R486MqC88WW6Z0szhjFEtD8IJGMaf1XCf5/8wrLSwq4Qa0nyspIw1nt4u7uGbzr3v0Fx/SUDor7gXB84RKdnn2XNZUZjfIxgmPKkbUWZ/7ufHh6LoWnm8LhTD/sAftbB++jmE9X+vjsBGOGkAXfTIeNmR0BaSbjzySyeQL+yYxgnyMsTVf8Qme
 En4lxzghXl+QOTSW6G6gdCgLa36wILi2d3S4xdl130YDgxqd6TCrOUcYs5xFHYBMIuFlgGmo3CnRJMY9aYgCzR1ISbeFsqPfyAA7rF/aII4LP72of1YZH2Se//5g8e63sZ1MF7U66+4RPqz/o5A5gROZ0ZfqudQZJEvPThrbhckl5wTKT3morlEm74sYnBBbdB96L42wH0rBauEV9p4tG88xpVtsftmI07eg2BDLq4sK/7hSnZnh9M844sZLvgDay0rEINch5uVe22p7GRx+KHa6flRQ3HzPC+5z968sYBBhYC51QtD5SqwBYD4HZfJKlNK35MZCkM8NhBbe1zXqdlCwI4vhy/oGXTKH9Z334UzYNQrgpJKCQHwBj48WTTA+rfuF5IG9Pj9443fMheAHOAj3UI1rlvs3n3JGxrcc18GPzYe0+OyYdoHU7mPcw=
Received: from www.outflux.net ([198.0.35.241])
        by smtp.gmail.com with ESMTPSA id z5-20020a62d105000000b006e08437d2c6sm6612506pfg.12.2024.02.12.16.10.02
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 12 Feb 2024 16:10:02 -0800 (PST)
Date: Mon, 12 Feb 2024 16:10:02 -0800
From: Kees Cook <keescook@chromium.org>
To: Suren Baghdasaryan <surenb@google.com>
Cc: akpm@linux-foundation.org, kent.overstreet@linux.dev, mhocko@suse.com,
	vbabka@suse.cz, hannes@cmpxchg.org, roman.gushchin@linux.dev,
	mgorman@suse.de, dave@stgolabs.net, willy@infradead.org,
	liam.howlett@oracle.com, corbet@lwn.net, void@manifault.com,
	peterz@infradead.org, juri.lelli@redhat.com,
	catalin.marinas@arm.com, will@kernel.org, arnd@arndb.de,
	tglx@linutronix.de, mingo@redhat.com, dave.hansen@linux.intel.com,
	x86@kernel.org, peterx@redhat.com, david@redhat.com,
	axboe@kernel.dk, mcgrof@kernel.org, masahiroy@kernel.org,
	nathan@kernel.org, dennis@kernel.org, tj@kernel.org,
	muchun.song@linux.dev, rppt@kernel.org, paulmck@kernel.org,
	pasha.tatashin@soleen.com, yosryahmed@google.com, yuzhao@google.com,
	dhowells@redhat.com, hughd@google.com, andreyknvl@gmail.com,
	ndesaulniers@google.com, vvvvvv@google.com,
	gregkh@linuxfoundation.org, ebiggers@google.com, ytcoode@gmail.com,
	vincent.guittot@linaro.org, dietmar.eggemann@arm.com,
	rostedt@goodmis.org, bsegall@google.com, bristot@redhat.com,
	vschneid@redhat.com, cl@linux.com, penberg@kernel.org,
	iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com, glider@google.com,
	elver@google.com, dvyukov@google.com, shakeelb@google.com,
	songmuchun@bytedance.com, jbaron@akamai.com, rientjes@google.com,
	minchan@google.com, kaleshsingh@google.com, kernel-team@android.com,
	linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org,
	iommu@lists.linux.dev, linux-arch@vger.kernel.org,
	linux-fsdevel@vger.kernel.org, linux-mm@kvack.org,
	linux-modules@vger.kernel.org, kasan-dev@googlegroups.com,
	cgroups@vger.kernel.org
Subject: Re: [PATCH v3 31/35] lib: add memory allocations report in show_mem()
Message-ID: <202402121606.687E798B@keescook>
References: <20240212213922.783301-1-surenb@google.com>
 <20240212213922.783301-32-surenb@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20240212213922.783301-32-surenb@google.com>
X-Original-Sender: keescook@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b="Mkv5ZK/A";       spf=pass
 (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::429
 as permitted sender) smtp.mailfrom=keescook@chromium.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=chromium.org
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

On Mon, Feb 12, 2024 at 01:39:17PM -0800, Suren Baghdasaryan wrote:
> Include allocations in show_mem reports.
> 
> Signed-off-by: Kent Overstreet <kent.overstreet@linux.dev>
> Signed-off-by: Suren Baghdasaryan <surenb@google.com>
> ---
>  include/linux/alloc_tag.h |  2 ++
>  lib/alloc_tag.c           | 38 ++++++++++++++++++++++++++++++++++++++
>  mm/show_mem.c             | 15 +++++++++++++++
>  3 files changed, 55 insertions(+)
> 
> diff --git a/include/linux/alloc_tag.h b/include/linux/alloc_tag.h
> index 3fe51e67e231..0a5973c4ad77 100644
> --- a/include/linux/alloc_tag.h
> +++ b/include/linux/alloc_tag.h
> @@ -30,6 +30,8 @@ struct alloc_tag {
>  
>  #ifdef CONFIG_MEM_ALLOC_PROFILING
>  
> +void alloc_tags_show_mem_report(struct seq_buf *s);
> +
>  static inline struct alloc_tag *ct_to_alloc_tag(struct codetag *ct)
>  {
>  	return container_of(ct, struct alloc_tag, ct);
> diff --git a/lib/alloc_tag.c b/lib/alloc_tag.c
> index 2d5226d9262d..54312c213860 100644
> --- a/lib/alloc_tag.c
> +++ b/lib/alloc_tag.c
> @@ -96,6 +96,44 @@ static const struct seq_operations allocinfo_seq_op = {
>  	.show	= allocinfo_show,
>  };
>  
> +void alloc_tags_show_mem_report(struct seq_buf *s)
> +{
> +	struct codetag_iterator iter;
> +	struct codetag *ct;
> +	struct {
> +		struct codetag		*tag;
> +		size_t			bytes;
> +	} tags[10], n;
> +	unsigned int i, nr = 0;
> +
> +	codetag_lock_module_list(alloc_tag_cttype, true);
> +	iter = codetag_get_ct_iter(alloc_tag_cttype);
> +	while ((ct = codetag_next_ct(&iter))) {
> +		struct alloc_tag_counters counter = alloc_tag_read(ct_to_alloc_tag(ct));
> +
> +		n.tag	= ct;
> +		n.bytes = counter.bytes;
> +
> +		for (i = 0; i < nr; i++)
> +			if (n.bytes > tags[i].bytes)
> +				break;
> +
> +		if (i < ARRAY_SIZE(tags)) {
> +			nr -= nr == ARRAY_SIZE(tags);
> +			memmove(&tags[i + 1],
> +				&tags[i],
> +				sizeof(tags[0]) * (nr - i));
> +			nr++;
> +			tags[i] = n;
> +		}
> +	}
> +
> +	for (i = 0; i < nr; i++)
> +		alloc_tag_to_text(s, tags[i].tag);
> +
> +	codetag_lock_module_list(alloc_tag_cttype, false);
> +}
> +
>  static void __init procfs_init(void)
>  {
>  	proc_create_seq("allocinfo", 0444, NULL, &allocinfo_seq_op);
> diff --git a/mm/show_mem.c b/mm/show_mem.c
> index 8dcfafbd283c..d514c15ca076 100644
> --- a/mm/show_mem.c
> +++ b/mm/show_mem.c
> @@ -12,6 +12,7 @@
>  #include <linux/hugetlb.h>
>  #include <linux/mm.h>
>  #include <linux/mmzone.h>
> +#include <linux/seq_buf.h>
>  #include <linux/swap.h>
>  #include <linux/vmstat.h>
>  
> @@ -423,4 +424,18 @@ void __show_mem(unsigned int filter, nodemask_t *nodemask, int max_zone_idx)
>  #ifdef CONFIG_MEMORY_FAILURE
>  	printk("%lu pages hwpoisoned\n", atomic_long_read(&num_poisoned_pages));
>  #endif
> +#ifdef CONFIG_MEM_ALLOC_PROFILING
> +	{
> +		struct seq_buf s;
> +		char *buf = kmalloc(4096, GFP_ATOMIC);

Why 4096? Maybe use PAGE_SIZE instead?

> +
> +		if (buf) {
> +			printk("Memory allocations:\n");

This needs a printk prefix, or better yet, just use pr_info() or similar.

> +			seq_buf_init(&s, buf, 4096);
> +			alloc_tags_show_mem_report(&s);
> +			printk("%s", buf);

Once a seq_buf "consumes" a char *, please don't use any directly any
more. This should be:

			pr_info("%s", seq_buf_str(s));

Otherwise %NUL termination isn't certain. Very likely, given the use
case here, but let's use good hygiene. :)

> +			kfree(buf);
> +		}
> +	}
> +#endif
>  }
> -- 
> 2.43.0.687.g38aa6559b0-goog
> 

-- 
Kees Cook

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/202402121606.687E798B%40keescook.
