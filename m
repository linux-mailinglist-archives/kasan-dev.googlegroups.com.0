Return-Path: <kasan-dev+bncBAABB6UYXXFQMGQE5XGB4ZQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43d.google.com (mail-wr1-x43d.google.com [IPv6:2a00:1450:4864:20::43d])
	by mail.lfdr.de (Postfix) with ESMTPS id 14FC9D3C3B2
	for <lists+kasan-dev@lfdr.de>; Tue, 20 Jan 2026 10:35:56 +0100 (CET)
Received: by mail-wr1-x43d.google.com with SMTP id ffacd0b85a97d-43284edbbc8sf4096964f8f.0
        for <lists+kasan-dev@lfdr.de>; Tue, 20 Jan 2026 01:35:56 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768901755; cv=pass;
        d=google.com; s=arc-20240605;
        b=UC5HMUxXMvfAHeHgnFY4xeAOvcqcuYivLhUFFnxiyATEqSFilzUNFteSByEboPiU6C
         6yLzIArgFn7xKRIKJr+jmnDRW+M/HHA7dtGM5OfVCOG2uPxY7uXiFyX/EE8G8D2KDe5Q
         7DBURkTkZrW+5SBWX0z+Z26nb6DCattuhlZOGbfr1vE0JpFtKNQqQM8EORg0lEFGvUKx
         pHkO6jgdwVU4y//ZOCUnsIIP5hLL3EFveulFYuyl/NsBC/C4U2GJ0zroVRBdy7QuBIzX
         e6kDpUxQ2k0TGDF/FgzSe7CuY7WsCZnbZ71B1a2cll7bowR5/cXTrWYkFjhdlc7wrHsm
         d59g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=CSYiNQOZ9MPlBTMlFXLu5SH9z6SJoooQBpBu3eiTSeg=;
        fh=QEfdNTa0/TLakVqB86o9Z8SQKBPxbCawtuHLjLCpFtg=;
        b=DDzOkSYgKfLVhkzdvf2OBnH+//WI/bc3xSXdK9w2+7LqcyJjDLg68om/8Xn/T1M0hN
         29BzNHbxUbSz/yt1Q/f3a5wBH30Kd3MSaHD0LXuV6tJjbZwzQ89mXiMmwoWi/U2BwK4P
         Ty3IMcU6JR5Or0eVdY9rEb9lrtjIRfzQUYFy3to9mbNH3GiYje7ZjEILNb1w+k+nBMYX
         GILMUCZwUactSufyuFekRCLyauoSGhz8ztAol/XqLuof2jkQ5mMQA4cE1iQvwoyyCe72
         BA0KZuz1WftzA0psAcrcVzaNGOaErbgmPBOTjXaOWzRLWq9aO1fAv7YjOBaPAK4KTCQA
         Sm3A==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=h9jQrUkG;
       spf=pass (google.com: domain of hao.li@linux.dev designates 2001:41d0:203:375::ac as permitted sender) smtp.mailfrom=hao.li@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768901755; x=1769506555; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=CSYiNQOZ9MPlBTMlFXLu5SH9z6SJoooQBpBu3eiTSeg=;
        b=UrESimhetIKNFmh7Lpfbg/UMLQbLgRPisSPBvu31vOvTckbXLW6wvc7Z9W/a684gF1
         YSDkhiXWGCUZ51ScrwmrHlCHZLKVUV0TPy/9LCxIVhsjS8rMkIC99d0BSqa+DTYpF9Tc
         w7lx+pqv3AP35nrMifMVJJr/GOAnO+oy5vuRfK0Z6rSbl0Ds2s/fxycSA6Zo5o5aUDcy
         1DBnXwg8U7gwZJsXxg47qsyrk72GYlARFO58Bycfe0AQijfEQz1v2be2/KPcyKFDJsxg
         e2fNw/t0qngDHlGaPRiyBu72h4igu2YaKwhnpbiseG//ibN8dCEOIdDrEQ6P9NroGyhK
         +J8g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768901755; x=1769506555;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=CSYiNQOZ9MPlBTMlFXLu5SH9z6SJoooQBpBu3eiTSeg=;
        b=O6X1Sg12xQeXZUUCjh3CdGn6R3Tf6WjbSBSZH2xJMvUBCLUAeFevaeFyhDCrZLWLau
         D9lPLoy8VMOVQbFnzIJfaFx6Vow83rGDhygybPjjNmfuZlVe/pOz57nJC8MvDQP3Yf5c
         PoULziu2hriEqJmCFlWhdnqN8lO3EP0gNlLneYiNw7f56fpLBHsc7sV0r2yRomumJRMH
         KbhhM+ds37fP0SLmVAIgQUtTVww8PKna0XtQE0BdbeT6U/0sqxARVP2zXZMrMFrZ5Cv6
         sszcEe8obly7dNqrRlXNY8hTs8O/8+EU6hRn14IgiwzU6k6zunmfOMUTbaQGP9dubdB4
         hyhQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVR7EVQ5mgVg2GDRUafGsV3MpYDSk4sAC/yUfE0a69mzDWjRj96/XGfbVwJplbFGMNjWWspCA==@lfdr.de
X-Gm-Message-State: AOJu0YzsFebuMcrW6TyMhMvc/20Jxqyu4OQdVQKYiucaUG9F9TrLwd5E
	RrormmeMz8h5c3Q1vgGF6n/0mAm92Uq7WVN+Yk7twvfhSM8OCAk91IFU
X-Received: by 2002:a05:6000:2dc5:b0:430:f3fb:35fa with SMTP id ffacd0b85a97d-4358ff6f669mr1783056f8f.57.1768901755273;
        Tue, 20 Jan 2026 01:35:55 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+Ew5PyQKhMLo4Lut07c0VbxVl02s+w3JXsv7OPj6LCoGA=="
Received: by 2002:a05:6000:2484:b0:432:84f4:e9cd with SMTP id
 ffacd0b85a97d-435641732d7ls3368545f8f.1.-pod-prod-07-eu; Tue, 20 Jan 2026
 01:35:53 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXZVSrLS1MAKM8nGirBei8D9G0fWpgWNThhbDWpfXP2pywrz/F/BbP6+Ej1E90aSQ2wF4SEyN90PeE=@googlegroups.com
X-Received: by 2002:a5d:64e5:0:b0:432:b951:ea00 with SMTP id ffacd0b85a97d-4358ff628e9mr1799290f8f.51.1768901753539;
        Tue, 20 Jan 2026 01:35:53 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1768901753; cv=none;
        d=google.com; s=arc-20240605;
        b=k6FM5VxwbvB6FOxLcLgi6/12anWnGCCS5BQu0Fk7MJDo8CdS6W3szohQ6h7S7U9+IZ
         op7rfyeqU0/bugUFupFZWMkWlcFz+wZyuGeO2z+xK0x4cWJ+EkuIYd7ibww5hCM0sdPb
         TezsdoXJZUsmn/hjne+0CytlM4gA8Jn16bo0PpM98NwIWbz3MaLEYw/Y7ZdrE34J5p/+
         tL4N9LwDXfU9eFFOJ4m8BhOh2ekLDxk9LS4P7j4zXZOZPEqpLxBbLpaUPRdLyhUEKaJM
         SKw7EQ4ioOW8gW3SJafHIEoPsQeiKDI0DtYD4eVYMOzELXXfrtAHBqL5kSPWWS/ds0MP
         SHoA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:dkim-signature:date;
        bh=w/B47m2KmCAoDa1sKTOG2K86RewOM8wCFrwCd3QEgHw=;
        fh=2eNRZ9ECquILDe9T7DsfDKzbtYQIgOYM00xcI0sJ8bg=;
        b=ZgcL61JBTSe2NXz7UlP6fq5amp/QVJ0knDfERp/OmgKZVWz7AqHp3m/D6Sx16DwIE/
         Pb5Up5QBYvbCTJ13TireWQeeCVgcXAOmAlV2ljiQOq12kMsAUG533mJ4qNrE3j0jGTjW
         Fx5V/IqQNcjxNoNwpYcQagg3QlNPsl6Jel78atTgeD6HRvdNUN3U4L2NjlbAYt/q5Pka
         32/PtYpODTHN/HJmmsoIlx68Sr6hepBkFkkRGzchsjGK6r3zACmF6+Pn8DwaCZtfzmgW
         JTLjGivKqWm8E7jGzJo4FtG3h/xM47mwhFFi5kqd2h50rwf+MIc/WA+muhIgtocYPXyv
         aVvA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=h9jQrUkG;
       spf=pass (google.com: domain of hao.li@linux.dev designates 2001:41d0:203:375::ac as permitted sender) smtp.mailfrom=hao.li@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-172.mta1.migadu.com (out-172.mta1.migadu.com. [2001:41d0:203:375::ac])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-4356992141csi246090f8f.2.2026.01.20.01.35.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 20 Jan 2026 01:35:53 -0800 (PST)
Received-SPF: pass (google.com: domain of hao.li@linux.dev designates 2001:41d0:203:375::ac as permitted sender) client-ip=2001:41d0:203:375::ac;
Date: Tue, 20 Jan 2026 17:35:21 +0800
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: Hao Li <hao.li@linux.dev>
To: Vlastimil Babka <vbabka@suse.cz>
Cc: Harry Yoo <harry.yoo@oracle.com>, Petr Tesarik <ptesarik@suse.com>, 
	Christoph Lameter <cl@gentwo.org>, David Rientjes <rientjes@google.com>, 
	Roman Gushchin <roman.gushchin@linux.dev>, Andrew Morton <akpm@linux-foundation.org>, 
	Uladzislau Rezki <urezki@gmail.com>, "Liam R. Howlett" <Liam.Howlett@oracle.com>, 
	Suren Baghdasaryan <surenb@google.com>, Sebastian Andrzej Siewior <bigeasy@linutronix.de>, 
	Alexei Starovoitov <ast@kernel.org>, linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	linux-rt-devel@lists.linux.dev, bpf@vger.kernel.org, kasan-dev@googlegroups.com
Subject: Re: [PATCH v3 13/21] slab: remove defer_deactivate_slab()
Message-ID: <veqtpod2liqsi4mgcxndgaiyqlhupnymmj4pquueqziqyakmnk@fzympoan5pds>
References: <20260116-sheaves-for-all-v3-0-5595cb000772@suse.cz>
 <20260116-sheaves-for-all-v3-13-5595cb000772@suse.cz>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20260116-sheaves-for-all-v3-13-5595cb000772@suse.cz>
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: hao.li@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=h9jQrUkG;       spf=pass
 (google.com: domain of hao.li@linux.dev designates 2001:41d0:203:375::ac as
 permitted sender) smtp.mailfrom=hao.li@linux.dev;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=linux.dev
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

On Fri, Jan 16, 2026 at 03:40:33PM +0100, Vlastimil Babka wrote:
> There are no more cpu slabs so we don't need their deferred
> deactivation. The function is now only used from places where we
> allocate a new slab but then can't spin on node list_lock to put it on
> the partial list. Instead of the deferred action we can free it directly
> via __free_slab(), we just need to tell it to use _nolock() freeing of
> the underlying pages and take care of the accounting.
> 
> Since free_frozen_pages_nolock() variant does not yet exist for code
> outside of the page allocator, create it as a trivial wrapper for
> __free_frozen_pages(..., FPI_TRYLOCK).
> 
> Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
> ---
>  mm/internal.h   |  1 +
>  mm/page_alloc.c |  5 +++++
>  mm/slab.h       |  8 +-------
>  mm/slub.c       | 56 ++++++++++++++++++++------------------------------------
>  4 files changed, 27 insertions(+), 43 deletions(-)
> 

Looks good to me.
Reviewed-by: Hao Li <hao.li@linux.dev>

-- 
Thanks,
Hao

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/veqtpod2liqsi4mgcxndgaiyqlhupnymmj4pquueqziqyakmnk%40fzympoan5pds.
