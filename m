Return-Path: <kasan-dev+bncBCM2HQW3QYHRBJV776GQMGQENJ4BKZY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13e.google.com (mail-lf1-x13e.google.com [IPv6:2a00:1450:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id C0B5C47A353
	for <lists+kasan-dev@lfdr.de>; Mon, 20 Dec 2021 02:43:02 +0100 (CET)
Received: by mail-lf1-x13e.google.com with SMTP id d2-20020a0565123d0200b0040370d0d2fbsf3760305lfv.23
        for <lists+kasan-dev@lfdr.de>; Sun, 19 Dec 2021 17:43:02 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1639964582; cv=pass;
        d=google.com; s=arc-20160816;
        b=JVxhL2T9w8sBtR477yWlaNvAPxJtv3dahKNI+Rt/78UhIWtLmNNNaxY/jVMCMiuaVq
         gt1/g4E2S14qdb/Ad6bIpx6B4iMt8nI46HLiRRtE19Ks+wMQmCpYou7OXLjSIQukHjLh
         Fhm6dhiqAUAL6zNOalr6mPxs21lcVI40235OwouwybB9QCK01ChyWuOsp0eyHq6IftPD
         9AYoUh18ecmHMZTYCOlhspqiIghGsZSsWhu1lJRQUllDU7QWCmrenmdOS/yQgs+s9ovq
         I8yZGm4HoB17DVgfsKzp3EAcORt3HOxA3B/HzIBorUiYOxHpVaJK2WPokE/EV/WsMUmy
         VArQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=DhdKBlwqBOgnySyjKWq+2J0ZiES2RdmfExq1kr76Dbk=;
        b=KFPNfVyLPDSSnAkxKAlv1F3HRxYSks5BQ+bLuRUggNNv48qU/qdiitQPWnhdg/phbS
         smFxvjILUK3/ivVEPtTdHnVlxg0oh0mbSbHh56drPOm7r0G3ygy/w0MS80crJ2KRDVfW
         OWryKsvQrZbzoj/EDS8mfdZVmbIhecmyxIFqPkRE3eqYPn6FS+AzzuHvLX4AhAxshqxK
         O9DTPiK3JypkKNZmtpQOBY9SD3Bn+aAWieAhIJeWt6XM0OhvYTFaW13zGJHXVagFOTmn
         D0acUTp8vl0HkDY4fTpVMGW1a6UUy6/rnssFyOl0dajFVNkz9tDaV71f+StGsbZ5tyE1
         KMsA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=fbUn3fvK;
       spf=pass (google.com: best guess record for domain of willy@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) smtp.mailfrom=willy@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=DhdKBlwqBOgnySyjKWq+2J0ZiES2RdmfExq1kr76Dbk=;
        b=X1WcdGD8Ckrg8720ehmW/aci7aF3+/xLVsK60SZqY7JF7VdJ+b2mSt6NzG0dHK2Eo1
         9EkyA+sDVN/PdsMDVl5uGOjxY+JhfAoLNGCX4YvXREKybJbU+eLR8ij3IPuuaCWNYohj
         yqfSgPjQ93P4dqAPG7PwK+5D6RE6o0UQaW8KNdu+1yMbbtaNrNke1qR+HvkRA80gvyUa
         MFijBFU4VE0+09qhYoSpy0q1h/YnPTaYzSysU5PYLXHg8NXeegpjgNHr7mPxcnMd94Ek
         NCTv0NccGl6y6bIOK+iORsq+QQacMRJ9APO8kDGxZBpl/lxOKtdxxEkrLN8onfr0afSG
         hk4Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=DhdKBlwqBOgnySyjKWq+2J0ZiES2RdmfExq1kr76Dbk=;
        b=gSIJ3NPfKoLD5qEEgKw4iKGN5Fzmu/tC8gEnB8HQMrZsTfTnOwnnjhZDjNnUafs4VW
         NSwCviYUdbtvrYdsBE532DlUI+UxruJNz9mSyTy+/QNjEhHJwGQlZSwEQGHYf3UZhcge
         xehFdpFSPLB0lz1kX9UyQvjMDqln+iOhUqXMfBfoNgm8ngyyAccae1MlnMjp5x2wF7q3
         P79bP4V0bAgDGXDndcbUTAFMaJhihczWEwz8nl7IvuSQG9oCRKZhzAJM+a5wSYSlrhkH
         vOtwslogSdP97zdQvfo+kZ+i8Jadl/C7YHysU0kvMyxXwVZR5E77jneRsfbg0r61WakJ
         lIBg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531YAiBbqlfpig1VtE7CzhI4e4Bvb7SGSKgYeTBkKWOeQ68vYHNa
	OWGCDFQvN3fHbcA4V3eDqAU=
X-Google-Smtp-Source: ABdhPJzpZ4Idba8hNMJHEC5FtmW15WuHfKzotOZKSd7h/OuWmTEj6WTeScwhaUdDg2m//TrEOY+v8A==
X-Received: by 2002:a05:651c:246:: with SMTP id x6mr12581081ljn.24.1639964582264;
        Sun, 19 Dec 2021 17:43:02 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:234c:: with SMTP id p12ls1367307lfu.0.gmail; Sun,
 19 Dec 2021 17:43:01 -0800 (PST)
X-Received: by 2002:a05:6512:2149:: with SMTP id s9mr6605416lfr.96.1639964581228;
        Sun, 19 Dec 2021 17:43:01 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1639964581; cv=none;
        d=google.com; s=arc-20160816;
        b=qCFwdv7wvTItEKg4wbNlr1MNFtkseqU8Kg+IBw64mBKZ3yF/7P0/tFpZgOZFgNnApb
         7Nx4UHZ7NrcvAVAFI55QpRt1OMChH0tRI4ZkhuP6VboeqB0re+7P3Wdamx1Gx90J6s7m
         wGPzWP+K4XExmRzxMj7eKbHNqBMiWYcv6zYDsnbngOopVIo48j9eSbbWXLGcGUpB0AxB
         adSnN7Ac1jZQZrgasjXvb5IBC4KJgBS/7ysPNAKB3zthDVwcZFm5z9VJwGgird+ASfiL
         +3RBj22gVxpthvpWxHWUy0pZtJvHFfOW2BIH67gizvhs5wsVFYrki5KVuYrb6ZElV6j/
         RvAA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=k7fHWgKrjS6NSIvn5a4Jtgxmp/WhT9Wz1heA+PvFHEU=;
        b=UPRSSFNNaGJtskHHEoyInG6GHZzbxU2CJYpcFNB1LPytNBmpuqppLXCaCspQWnMUZQ
         5I+xIWmpaFchjzzLqTbLjhGPlnIiaFHUlEEdJLM3guTPx7D3bk9WzdANVQkWTk19iqk3
         rljSgYwXn8yHqh+P22spxyV1ruEDfc1YsqjTVFKPwUM4XLjqACNgIN2H1+qrCwL8wORe
         hBLJtZMUEdby9pvk497dr3fbTl0KrSKEfcKoBBkp8aHGrOM3ebrUaINnOeJiibXkZSZp
         laEeNSSCrx9iG2Nvi5Fo5s62nKFortPlqpJFJ+OmG4jy/gYH07C2QLGruqFhZqZ9FiGk
         79aw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=fbUn3fvK;
       spf=pass (google.com: best guess record for domain of willy@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) smtp.mailfrom=willy@infradead.org
Received: from casper.infradead.org (casper.infradead.org. [2001:8b0:10b:1236::1])
        by gmr-mx.google.com with ESMTPS id i21si356964lfv.10.2021.12.19.17.43.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sun, 19 Dec 2021 17:43:00 -0800 (PST)
Received-SPF: pass (google.com: best guess record for domain of willy@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) client-ip=2001:8b0:10b:1236::1;
Received: from willy by casper.infradead.org with local (Exim 4.94.2 #2 (Red Hat Linux))
	id 1mz7gr-001BXA-DH; Mon, 20 Dec 2021 01:42:13 +0000
Date: Mon, 20 Dec 2021 01:42:13 +0000
From: Matthew Wilcox <willy@infradead.org>
To: Vlastimil Babka <vbabka@suse.cz>
Cc: Roman Gushchin <guro@fb.com>, Christoph Lameter <cl@linux.com>,
	David Rientjes <rientjes@google.com>,
	Joonsoo Kim <iamjoonsoo.kim@lge.com>,
	Pekka Enberg <penberg@kernel.org>, linux-mm@kvack.org,
	Andrew Morton <akpm@linux-foundation.org>, patches@lists.linux.dev,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Andy Lutomirski <luto@kernel.org>, Borislav Petkov <bp@alien8.de>,
	cgroups@vger.kernel.org, Dave Hansen <dave.hansen@linux.intel.com>,
	David Woodhouse <dwmw2@infradead.org>,
	Dmitry Vyukov <dvyukov@google.com>,
	"H. Peter Anvin" <hpa@zytor.com>, Ingo Molnar <mingo@redhat.com>,
	iommu@lists.linux-foundation.org, Joerg Roedel <joro@8bytes.org>,
	Johannes Weiner <hannes@cmpxchg.org>,
	Julia Lawall <julia.lawall@inria.fr>, kasan-dev@googlegroups.com,
	Lu Baolu <baolu.lu@linux.intel.com>,
	Luis Chamberlain <mcgrof@kernel.org>,
	Marco Elver <elver@google.com>, Michal Hocko <mhocko@kernel.org>,
	Minchan Kim <minchan@kernel.org>, Nitin Gupta <ngupta@vflare.org>,
	Peter Zijlstra <peterz@infradead.org>,
	Sergey Senozhatsky <senozhatsky@chromium.org>,
	Suravee Suthikulpanit <suravee.suthikulpanit@amd.com>,
	Thomas Gleixner <tglx@linutronix.de>,
	Vladimir Davydov <vdavydov.dev@gmail.com>,
	Will Deacon <will@kernel.org>, x86@kernel.org,
	Hyeonggon Yoo <42.hyeyoo@gmail.com>
Subject: Re: [PATCH v2 00/33] Separate struct slab from struct page
Message-ID: <Yb/fdYbLunsVYRqQ@casper.infradead.org>
References: <20211201181510.18784-1-vbabka@suse.cz>
 <4c3dfdfa-2e19-a9a7-7945-3d75bc87ca05@suse.cz>
 <Ybk+0LKrsAJatILE@carbon.dhcp.thefacebook.com>
 <Ybp8a5JNndgCLy2w@carbon.dhcp.thefacebook.com>
 <86617be0-8aa8-67d2-08bd-1e06c3d12785@suse.cz>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <86617be0-8aa8-67d2-08bd-1e06c3d12785@suse.cz>
X-Original-Sender: willy@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=casper.20170209 header.b=fbUn3fvK;
       spf=pass (google.com: best guess record for domain of
 willy@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) smtp.mailfrom=willy@infradead.org
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

On Mon, Dec 20, 2021 at 01:47:54AM +0100, Vlastimil Babka wrote:
> > * mm/slub: Convert print_page_info() to print_slab_info()
> > Do we really need to explicitly convert slab_folio()'s result to (struct folio *)?
> 
> Unfortunately yes, as long as folio_flags() don't take const struct folio *,
> which will need some yak shaving.

In case anyone's interested ...

folio_flags calls VM_BUG_ON_PGFLAGS() which would need its second
argument to be const.

That means dump_page() needs to take a const struct page, which
means __dump_page() needs its argument to be const.

That calls ...

is_migrate_cma_page()
page_mapping()
page_mapcount()
page_ref_count()
page_to_pgoff()
page_to_pfn()
hpage_pincount_available()
head_compound_mapcount()
head_compound_pincount()
compound_order()
PageKsm()
PageAnon()
PageCompound()

... and at that point, I ran out of motivation to track down some parts
of this tarbaby that could be fixed.  I did do:

    mm: constify page_count and page_ref_count
    mm: constify get_pfnblock_flags_mask and get_pfnblock_migratetype
    mm: make compound_head const-preserving
    mm/page_owner: constify dump_page_owner

so some of those are already done.  But a lot of them just need to be
done at the same time.  For example, page_mapping() calls
folio_mapping() which calls folio_test_slab() which calls folio_flags(),
so dump_page() and page_mapping() need to be done at the same time.

One bit that could be broken off easily (I think ...) is PageTransTail()
PageTail(), PageCompound(), PageHuge(), page_to_pgoff() and
page_to_index().  One wrinkle is needed a temporary
TESTPAGEFLAGS_FALSE_CONST.  But I haven't tried it yet.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/Yb/fdYbLunsVYRqQ%40casper.infradead.org.
