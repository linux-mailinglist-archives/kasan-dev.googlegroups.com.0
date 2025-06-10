Return-Path: <kasan-dev+bncBC7OBJGL2MHBB27DUDBAMGQEFGUJCGQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83b.google.com (mail-qt1-x83b.google.com [IPv6:2607:f8b0:4864:20::83b])
	by mail.lfdr.de (Postfix) with ESMTPS id 9D51DAD38F1
	for <lists+kasan-dev@lfdr.de>; Tue, 10 Jun 2025 15:24:11 +0200 (CEST)
Received: by mail-qt1-x83b.google.com with SMTP id d75a77b69052e-4a461632999sf114835321cf.1
        for <lists+kasan-dev@lfdr.de>; Tue, 10 Jun 2025 06:24:11 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1749561836; cv=pass;
        d=google.com; s=arc-20240605;
        b=FmB+RS2xlKDgUShuftOuG6mqfWuwm2coArnj231KlMl5u4z0mwErE495GxzwM1RZ/o
         PyU/RpBoM2/IpDhbH/7fyobhH5lScaA6VbjjhVrBZ5CL7yb6I0wjVPiuctTWX0DlxgL9
         ahAL4Wvz6W/+kwmAhSQAHhlRh2b2jGq27O/zNTyh0HwLqogFt20q5haP+NDz3mzc7Ypt
         rHRw4W/rH18XVK2SvhkBG3moZRwEJsqWe3ELmrFmLFcAX1Jh1E25Eemg9e05WktabAfL
         snanNqS4cpLjro2z07cFwJgqErgp1JqIdquU4ghBLvpFuWVELlxkWQBeXVKdt3RY7kwD
         tRbg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=tFxudbMVQIUi35/A+MgxfdtLkhJ9/FNpBwg3rTiFjNI=;
        fh=hjb9ca/5OA2dzWcUwsz7P87AfbTOBqF6DjXk0+waXuE=;
        b=koKMCGO0ycLKGNA7V9NDSDwDQE8fqrSjCw6baUwnl024Mgv8LW+iMkm+MbdndEv6S9
         unAtMytPzSJs7uFx47mVmXwt/0MPuvmi7I3hfd7ng3yYy2qQjCpd2hSWfa911zFWk615
         DB+OgviCWYEu9YCYO39NoQUv16PHcTEbeTqwfItVe23j/suj+1qDuhoGHm+hZ2iymUF/
         HIPGeRrrhL0ZXgg9ysooEtIGQgi9IR4OMqZzO1QrFPsBel+y3elZ9BAdr6rZEJ9PBkyd
         EosgoTuxIrm0kt8v3OUZgZb0RHSdYV877G0VnpcYTwC3tAvTzQPWP0oMhyyWxBDe5PX/
         RKhw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=pO8A5QZQ;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::62f as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1749561836; x=1750166636; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=tFxudbMVQIUi35/A+MgxfdtLkhJ9/FNpBwg3rTiFjNI=;
        b=rJHqSPF9/AhQZOEr0kI5wPyhPfkOZESI0B61Q4AKUeket2J3bnrCDvGV3NuXZEa5dA
         P2b0IcKqmVSyjaBVQv7zXf8jWlbaUb2Y96vhQ+V09mzC8B+ruRmJsLykLksvceQNwWzq
         Xn7DBdWmrWJAGy8GF7vvLkmIPmfyKlw9D3EEjbvVFfXUtZ113/vcY+aDZzOG8ifCpiyC
         CyNV94/LF4xfTi+cKLP/k5ZF38OhcLRDd2KwvLTNMg0UkebyIWx8EaX2+CPN30WzFdpg
         VD/x6fR/j9RiIKVqrY4dby0KB8qRwkY00TqjyabW6vfyLXCc/xXLh33EmzJ/WsOQ8GNd
         ZzbA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1749561836; x=1750166636;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=tFxudbMVQIUi35/A+MgxfdtLkhJ9/FNpBwg3rTiFjNI=;
        b=HS3wA9H4QCCQCPCIZ3nhV4G+wCs/FAKhdviQWeiPMDQ7o+1wu4KocGJW3AlzYIZX6G
         3Tu8LHvHh0p6GuzGhxsqfAklt1zNdNLTd03xJJWoVJgxv9db4xY9nn7Tv48lkvi0razu
         Koib7s2t7etb7NbgH3Mf2xnNxUxPtptytldUwnfl5KIt1kGC1K+nZZl7WLXFIq1zjeZL
         WeLEBEk1glIZB9+RtkGuGpsVhT1mwrAvilxtjYVZxFE3anMjj3nX0gg4l1ixO9vAEAxR
         kQiZVh6LxA5SFFe6i34KloGzXfA7vUIc9T2WMFt88qdVGmirSFc1QEVGgaexB69h2bJb
         ZxJg==
X-Forwarded-Encrypted: i=2; AJvYcCUB2vik2iEFiAT6BnREApWWLYW1aldYVS9/F5k7lG3Ay0sEyPVsrkvgIgSS7SI4mqOpbugSSg==@lfdr.de
X-Gm-Message-State: AOJu0YyyuznC4psi0P7YMQMliqsGaZvH6HL8DnJ61JsJHNZ4h4jAZr4i
	BtyXg69J0ofVeSuH44Oukkaf7dMXfzz0auQNDYw/qImS/HIIKFuDHjm6
X-Google-Smtp-Source: AGHT+IHk7NPGooVD6f2SrUdy5L+zRNIHYZL1lQ+jY5AMTnn+ky6TOzMzhD2RWo2XNFWCA7mBCqVjtQ==
X-Received: by 2002:a05:6214:f6a:b0:6fa:be7e:c0be with SMTP id 6a1803df08f44-6fb24c9ed96mr43346126d6.34.1749561835944;
        Tue, 10 Jun 2025 06:23:55 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZewD6fM8iMxzPCKLM2gAfIEmmF7O70PEF3tJYfRuT2OXQ==
Received: by 2002:a05:6214:ca2:b0:6fa:e7bf:ec69 with SMTP id
 6a1803df08f44-6faffa9b35cls68185896d6.1.-pod-prod-02-us; Tue, 10 Jun 2025
 06:23:55 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVr/qNX3ojVNVf2CYFr80yz768jRv9ICjj9BknRVNXpUn7VxGfOjiq1akJedT0Vhyzphcf5mrLWsW4=@googlegroups.com
X-Received: by 2002:a05:6122:6598:b0:523:dd87:fe95 with SMTP id 71dfb90a1353d-53114b2b894mr2022946e0c.9.1749561834881;
        Tue, 10 Jun 2025 06:23:54 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1749561834; cv=none;
        d=google.com; s=arc-20240605;
        b=I0VZ3Zhf8+hDGBb8utVC0J2MgarnF5bHo8UphHKbLKJ5Jr/R5fMGBrn89Pay29fomA
         tuoTN8NzVLe73VEVfs+AO+bnojNTNF/nm7ZOAuFXqUCI9LrsktSW01TMuqwkUf5HEoNa
         uUmE60TH9BN8JS622LKAgp5pXNlGWhV2vyKsS65cnPyB62yuuyp2UPCPKe//JYFEj46o
         Z+vLhTByrNfPhuH0hMv+ePribDerrSuErXguXDio6SzyloiNkjKF7cufiqmhd7qxA2NN
         OLrFGzIi+ZokZBXx1oKdAGhaCjUZLmrpwAkLMA3Lzp5/rb5QvldWwcm7P3ItxzHB37qE
         f9Yg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=vRaW1CqfHzqyG0OPt07OWDx5jYTvbBKbwah24QkbGI0=;
        fh=i3vN4M2h5iEDqIypqeyaizzxan5nsOa4z3V/6y2cEW0=;
        b=cULlO+AtLYqtWeLluRqKHbHWUtWtMovkGAZQIq3CBwkPJeZoTvtOVZuByQX6pPab4x
         OCDIy6/bhgQzrVkXTISOVNRrYSRnOVva1j8Bb4YkYQD1WbbLLLjn0ouSclQXTnCvComx
         h9lq8FXLFJfqO7rS+WiXSxgA6fTDOZQKvol9S3vSazJ7acgXcnh4L6Jt67sBMXpLvVW2
         cSxbIJf12oUrjjR1d2MMEZzq3yieFkiVAiq19D1VJyYMsMshfR4kO1srfTA3h46DGYsG
         nFVPPxUx02sXIjWEQQ0caAWwG35G0/P1OV16O/tw96vWvKODWQLTBFmT+7Iic7wP7X0/
         Lg3A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=pO8A5QZQ;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::62f as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pl1-x62f.google.com (mail-pl1-x62f.google.com. [2607:f8b0:4864:20::62f])
        by gmr-mx.google.com with ESMTPS id 71dfb90a1353d-53113ba79e3si101239e0c.5.2025.06.10.06.23.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 10 Jun 2025 06:23:54 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::62f as permitted sender) client-ip=2607:f8b0:4864:20::62f;
Received: by mail-pl1-x62f.google.com with SMTP id d9443c01a7336-236377f00a1so7474085ad.3
        for <kasan-dev@googlegroups.com>; Tue, 10 Jun 2025 06:23:54 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXGaD2ELBhV1zvxyutOjUEgiWuvqwEGSHS0O1cBnyQnI5SuOf+XnZy/kCXFAyA3TjSJvKu9SnIWrak=@googlegroups.com
X-Gm-Gg: ASbGncvZxxsA3x8bSVJDblBTnI9Z7av+Op0Yjk/+lvbn6LbBw9qraSCrPWwrx3cIDFS
	vFXWbiPY6dbU0OXJUyBBPNH44es1/GVQagx5JwPH4ve/Wji0IeeVVRJdZ9vF6aNjfOmN0hqgaGP
	4Aa9NOUZz4gfi6wA9eE0ev9dUQP9A4ojxD1nGadQKzW+mhwgiX0FwJQLIssUiCZRoeo46TSdHq
X-Received: by 2002:a17:902:e888:b0:234:8a4a:ada5 with SMTP id
 d9443c01a7336-23638390915mr37412415ad.37.1749561833582; Tue, 10 Jun 2025
 06:23:53 -0700 (PDT)
MIME-Version: 1.0
References: <20250606222214.1395799-1-willy@infradead.org> <20250606222214.1395799-9-willy@infradead.org>
 <ff370b8b-a33f-47a2-9815-266225e68b8a@suse.cz> <aEb3bMaMoROWz3Pk@casper.infradead.org>
In-Reply-To: <aEb3bMaMoROWz3Pk@casper.infradead.org>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 10 Jun 2025 15:23:17 +0200
X-Gm-Features: AX0GCFtTJcTed3U6440yYHTEXfipib5aKPmkHTxU6Gll8_BS05WLR7SDouZ-yfU
Message-ID: <CANpmjNNTdxZ_LAjVB0-F+GN3E-0YehbQx+V+NLb=DK-TxeMfzA@mail.gmail.com>
Subject: Re: [PATCH 08/10] kfence: Remove mention of PG_slab
To: Matthew Wilcox <willy@infradead.org>
Cc: Vlastimil Babka <vbabka@suse.cz>, Christoph Lameter <cl@gentwo.org>, David Rientjes <rientjes@google.com>, 
	linux-mm@kvack.org, Harry Yoo <harry.yoo@oracle.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=pO8A5QZQ;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::62f as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

On Mon, 9 Jun 2025 at 17:02, Matthew Wilcox <willy@infradead.org> wrote:
>
> On Mon, Jun 09, 2025 at 03:33:41PM +0200, Vlastimil Babka wrote:
> > On 6/7/25 00:22, Matthew Wilcox (Oracle) wrote:
> > > Improve the documentation slightly, assuming I understood it correctly.
> >
> > Assuming I understood it correctly, this is going to be fun part of
> > splitting struct slab from struct page. It gets __kfence_pool from memblock
> > allocator and then makes the corresponding struct pages look like slab
> > pages. Maybe it will be possible to simplify things so it won't have to
> > allocate struct slab for each page...
>
> I've been looking at this and I'm not sure I understand it correctly
> either.  Perhaps the kfence people can weigh in.  It seems like the
> kfence pages are being marked as slab pages, but not being assigned to
> any particular slab cache?

They are marked as slab pages, because in kfree() there's the test for
folio_test_slab(..), which goes to free_large_kmalloc() if it's not a
slab page. But the kfence pool pages cannot be deallocated, given we
want to reuse them due to the particular layout of the pool (object
pages interleaved with guard pages, freed pages are only marked not
present to catch use-after-free).

But besides that they aren't real slab caches, given it's all managed
by kfence (each page can host at most 1 object, but those objects may
be of sizes up to PAGE_SIZE).

Some of this could be solved by adding more is_kfence_address()
checks, but that adds more branches in hot paths and more complexity
since some of the accounting and hooks are naturally shared with the
current design.

> Perhaps the right thing to do will be to allocate slabs for kfence
> objects.  Or kfence objects get their own memdesc type.  It's hard to
> say at this point.  My plan was to disable kfence (along with almost
> everything else) when CONFIG_PAGE_DIET is enabled, and then someone
> who understands what's going on can come in and do the necessary to
> re-enable it.

Assuming it's not a new default, and if this new feature disables most
slab debugging anyway, this appears reasonable.

> > > Signed-off-by: Matthew Wilcox (Oracle) <willy@infradead.org>
> > > ---
> > >  mm/kfence/core.c | 4 ++--
> > >  1 file changed, 2 insertions(+), 2 deletions(-)
> > >
> > > diff --git a/mm/kfence/core.c b/mm/kfence/core.c
> > > index 102048821c22..0ed3be100963 100644
> > > --- a/mm/kfence/core.c
> > > +++ b/mm/kfence/core.c
> > > @@ -605,8 +605,8 @@ static unsigned long kfence_init_pool(void)
> > >     pages = virt_to_page(__kfence_pool);
> > >
> > >     /*
> > > -    * Set up object pages: they must have PG_slab set, to avoid freeing
> > > -    * these as real pages.
> > > +    * Set up object pages: they must have PGTY_slab set to avoid freeing
> > > +    * them as real pages.

Acked-by: Marco Elver <elver@google.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNNTdxZ_LAjVB0-F%2BGN3E-0YehbQx%2BV%2BNLb%3DDK-TxeMfzA%40mail.gmail.com.
