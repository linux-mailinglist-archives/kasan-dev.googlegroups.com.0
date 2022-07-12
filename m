Return-Path: <kasan-dev+bncBC7OBJGL2MHBBQOOWWLAMGQEKEOCVHA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3b.google.com (mail-oa1-x3b.google.com [IPv6:2001:4860:4864:20::3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 098F05719C6
	for <lists+kasan-dev@lfdr.de>; Tue, 12 Jul 2022 14:21:23 +0200 (CEST)
Received: by mail-oa1-x3b.google.com with SMTP id 586e51a60fabf-106a48f2df7sf4233544fac.16
        for <lists+kasan-dev@lfdr.de>; Tue, 12 Jul 2022 05:21:23 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1657628481; cv=pass;
        d=google.com; s=arc-20160816;
        b=0ineN0ksiIVCLPLbw8nEIJYEWgqnIGBPtB8T8jvl6nkyFa9ehnW+VNpTjI1RhSZS5d
         N8Tcq0E2VBiI3JOjydfI3bkSvpoicoarVG56St+M163Zg+Ri9NsmBBJsRaZx+i+tuFRx
         y3UT4ICD0lO9YhVcaEeu73u1/13QNYimsxlIy+Ed+43vsxwsuk2TsTfc7fTQkw9uqSvv
         VcPQRDRVJA4OINPAK4coRNnfz14rMD+dDAbY+jpCpiETHpLTZYNpQ2TjEmmap99KCw8N
         MwTCLUZxziobHXJY7T9xqvnlW+Z53uiwW1h5iDc1hmZtYrD/bA6jDnNb8mu1wFjN3Mt5
         PM0g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=54D8EOp5B9fjr8kQ+Fj+u9bidfmSxgiNG1ldaYv/S00=;
        b=Hn8SgZ5BERQizLVKtWJGJBDYd2jvA+Jv/J9sC30YkYev7vIS2IdjF9mf9BmGsaIFhP
         9/6SfmyXRjLEpEJLmfd0FM5+SZt8i4FxeG5falP6T+SXJp0c7YTT6wZLO3cN3H4kcAuT
         Qfpi5D+ixTC24QR5wQJczrK9IvicgsxcLMNpu2i704KLhquO18vZKsfn4qBYWkxlFyrM
         HfnxCUasE08EB4Gv7U93xLyMQOcxCSYcIgAsv1eGiSloZ7jK3IcLkATgd1pHjUcUCF8N
         vFfaoOfmt1r3gwCBjnDc4CnI7pDxZzBW3fToLJxYNF+pukIkM1B/McQShLs8zTc2kqSP
         +7PA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=AdA9qT8w;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1132 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=54D8EOp5B9fjr8kQ+Fj+u9bidfmSxgiNG1ldaYv/S00=;
        b=fu0V/b9h+8UVGnCWRszg31dmxS2d+qgx1xe06n3hzWD9E1l770g7Vx9KgpXjnt9H5q
         qi4cPfesvUKShYNEgyn7HcngFldMAfGq8n1e0xyfRd6a+gSW38VU0hNo5UXAdplnKoqi
         MqiuOj9/rpgi/wyr1/SaP7txaES5ESu6co2bGRBJuM4qvHVokdnuxoIof0JX81kpAagk
         zW5Wt30+kZHHdCfcMyIxf7tecssrtkwC/L5PO2SZdF+2OAway7KA7x4rbuwRb6epuuzc
         cwiqPmbCiCtrPigZVKCnAPyuTV5BJXfqYcMPod67o3Fdqwr0uqim1DBaIt4yOVunN9Ii
         Jw0w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=54D8EOp5B9fjr8kQ+Fj+u9bidfmSxgiNG1ldaYv/S00=;
        b=uBzUh4g+KF9ovbFZoG8Hre9gwJM1NHgc+Rh2WpbCpMuftVxyJnsYfF10eVVjtFzBuc
         IiUkf1bvXDUfn5cN6EwFLqTGr84z9fLI1zlAQXsHbEy4T3XjGf8tMHxTFMGiX4BJfrhk
         mmqF9DCJDkFDOxk5dhExqU1tbg1mHRpmNGXW+Xx72x9Oln/IiR9jdl8BYhUvHevnSqeF
         6HgMIIZPoaBeVVn8T9u3v0whNAFgTnQUb2b25zmETAZuAfvoiO4uBwrx0fFdpap4weLU
         kg3JzppQ8Or74EkI/UaeFXhEhLB2b2ZT5MD4CYfDEwbgGSYELKLI3aW7gmfrIA+2CEQO
         ecHw==
X-Gm-Message-State: AJIora+OduiAzU2qXwuz9dRSYJQa7K1Q5jsgyXzIpfRtyHXRBLqhrBdy
	bVBiwP6EBAnFH+HuveLc/ZI=
X-Google-Smtp-Source: AGRyM1uJQdAK/hWdmRJNjGsy0gEFMIi2qljnAHtw4tyTCONj0bD/xfAb2AJMlIYZxn0be0nyG42jzg==
X-Received: by 2002:a05:6830:240a:b0:61c:5f83:fc58 with SMTP id j10-20020a056830240a00b0061c5f83fc58mr722423ots.376.1657628481538;
        Tue, 12 Jul 2022 05:21:21 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:fd8f:b0:10b:ee4f:8f9e with SMTP id
 ma15-20020a056870fd8f00b0010bee4f8f9els7939457oab.4.gmail; Tue, 12 Jul 2022
 05:21:21 -0700 (PDT)
X-Received: by 2002:a05:6870:58a2:b0:10b:91c7:e58 with SMTP id be34-20020a05687058a200b0010b91c70e58mr1589051oab.279.1657628481096;
        Tue, 12 Jul 2022 05:21:21 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1657628481; cv=none;
        d=google.com; s=arc-20160816;
        b=Gw7MomDHKQh5YIN25tZyYRth8rC097JS0RvGfWBzwJRR8ltpAgzVPK2soeC0YW7BgI
         SbohXBbvJZQJkytkrh4p6YLER3ToNEXskVTs+Wy1edFhTFJIeQG2ovym5zhmBGClHHwk
         yLNcbJ5Z+vfkKLfk1ixx5ujqPJBNTGIerFkawmwrhQIicogV46FxaZj0ZQ204WYTqSim
         tyOJzpsQsZ2h9lWgRxV4PHtWhrM9tRYUSdfQaTT9GoehtGOg/cG6M3EIZ0TGbU0JkryU
         F5rKLdXXCPhdtcNMepKESQ1qMyWclmfhPJlYEbEYbdVqqTp3HjX59OGPWYBTgMAIkv3o
         PO5A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=UaSHri8uX8QzRonJXk/9Ev1ksxotFizg9AxbyPG4jRk=;
        b=NVGmCjoA5STrllt1RtiKByvlC+fUTWff4+Yd5DgTNtfBct4qLaBOq7I2B97g403Wpy
         5YpPTtASb/7AsJ8CpMFAZPjEhnccHUI06sDzBGgk87Noyku2lDAqpNjSHPLkJ9vkN2K3
         PGAqAQFRWCU5PPSTD8a+U0LnDS/D7O5bmsxUI0r3Yq5Z7d4VAU+gZ5rM0dvSR8nB6mlo
         XIpRsGLHEFbBv1K+GqovRLjCA4stGeUgR8YT/tLYWze4PpIhwacd7qW/AlhSSLq24RgR
         QOiflcMMqpnnDoF6BSFo5+nRElKXaPJgxXK1PrAY8ajn4UUgEqPQuSBynEk7atczaKK9
         Gj7A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=AdA9qT8w;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1132 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x1132.google.com (mail-yw1-x1132.google.com. [2607:f8b0:4864:20::1132])
        by gmr-mx.google.com with ESMTPS id z189-20020aca33c6000000b00339c9e7c8ffsi325607oiz.5.2022.07.12.05.21.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 12 Jul 2022 05:21:21 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1132 as permitted sender) client-ip=2607:f8b0:4864:20::1132;
Received: by mail-yw1-x1132.google.com with SMTP id 00721157ae682-31c89111f23so79297977b3.0
        for <kasan-dev@googlegroups.com>; Tue, 12 Jul 2022 05:21:21 -0700 (PDT)
X-Received: by 2002:a81:1492:0:b0:31c:a1ff:9ec with SMTP id
 140-20020a811492000000b0031ca1ff09ecmr23857082ywu.327.1657628480468; Tue, 12
 Jul 2022 05:21:20 -0700 (PDT)
MIME-Version: 1.0
References: <20220701142310.2188015-1-glider@google.com> <20220701142310.2188015-15-glider@google.com>
In-Reply-To: <20220701142310.2188015-15-glider@google.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 12 Jul 2022 14:20:44 +0200
Message-ID: <CANpmjNP8kmZYRsdpHCni33W-Yjgy-ajCAuTE94zwUniyYt7WQw@mail.gmail.com>
Subject: Re: [PATCH v4 14/45] mm: kmsan: maintain KMSAN metadata for page operations
To: Alexander Potapenko <glider@google.com>
Cc: Alexander Viro <viro@zeniv.linux.org.uk>, Alexei Starovoitov <ast@kernel.org>, 
	Andrew Morton <akpm@linux-foundation.org>, Andrey Konovalov <andreyknvl@google.com>, 
	Andy Lutomirski <luto@kernel.org>, Arnd Bergmann <arnd@arndb.de>, Borislav Petkov <bp@alien8.de>, 
	Christoph Hellwig <hch@lst.de>, Christoph Lameter <cl@linux.com>, David Rientjes <rientjes@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Eric Dumazet <edumazet@google.com>, 
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>, Herbert Xu <herbert@gondor.apana.org.au>, 
	Ilya Leoshkevich <iii@linux.ibm.com>, Ingo Molnar <mingo@redhat.com>, Jens Axboe <axboe@kernel.dk>, 
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, Kees Cook <keescook@chromium.org>, 
	Mark Rutland <mark.rutland@arm.com>, Matthew Wilcox <willy@infradead.org>, 
	"Michael S. Tsirkin" <mst@redhat.com>, Pekka Enberg <penberg@kernel.org>, 
	Peter Zijlstra <peterz@infradead.org>, Petr Mladek <pmladek@suse.com>, 
	Steven Rostedt <rostedt@goodmis.org>, Thomas Gleixner <tglx@linutronix.de>, 
	Vasily Gorbik <gor@linux.ibm.com>, Vegard Nossum <vegard.nossum@oracle.com>, 
	Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com, linux-mm@kvack.org, 
	linux-arch@vger.kernel.org, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=AdA9qT8w;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1132 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
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

On Fri, 1 Jul 2022 at 16:23, Alexander Potapenko <glider@google.com> wrote:
>
> Insert KMSAN hooks that make the necessary bookkeeping changes:
>  - poison page shadow and origins in alloc_pages()/free_page();
>  - clear page shadow and origins in clear_page(), copy_user_highpage();
>  - copy page metadata in copy_highpage(), wp_page_copy();
>  - handle vmap()/vunmap()/iounmap();
>
> Signed-off-by: Alexander Potapenko <glider@google.com>
> ---
> v2:
>  -- move page metadata hooks implementation here
>  -- remove call to kmsan_memblock_free_pages()
>
> v3:
>  -- use PAGE_SHIFT in kmsan_ioremap_page_range()
>
> v4:
>  -- change sizeof(type) to sizeof(*ptr)
>  -- replace occurrences of |var| with @var
>  -- swap mm: and kmsan: in the subject
>  -- drop __no_sanitize_memory from clear_page()
>
> Link: https://linux-review.googlesource.com/id/I6d4f53a0e7eab46fa29f0348f3095d9f2e326850
> ---
>  arch/x86/include/asm/page_64.h |  12 ++++
>  arch/x86/mm/ioremap.c          |   3 +
>  include/linux/highmem.h        |   3 +
>  include/linux/kmsan.h          | 123 +++++++++++++++++++++++++++++++++
>  mm/internal.h                  |   6 ++
>  mm/kmsan/hooks.c               |  87 +++++++++++++++++++++++
>  mm/kmsan/shadow.c              | 114 ++++++++++++++++++++++++++++++
>  mm/memory.c                    |   2 +
>  mm/page_alloc.c                |  11 +++
>  mm/vmalloc.c                   |  20 +++++-
>  10 files changed, 379 insertions(+), 2 deletions(-)
>
> diff --git a/arch/x86/include/asm/page_64.h b/arch/x86/include/asm/page_64.h
> index baa70451b8df5..227dd33eb4efb 100644
> --- a/arch/x86/include/asm/page_64.h
> +++ b/arch/x86/include/asm/page_64.h
> @@ -45,14 +45,26 @@ void clear_page_orig(void *page);
>  void clear_page_rep(void *page);
>  void clear_page_erms(void *page);
>
> +/* This is an assembly header, avoid including too much of kmsan.h */

All of this code is under an "#ifndef __ASSEMBLY__" guard, does it matter?

> +#ifdef CONFIG_KMSAN
> +void kmsan_unpoison_memory(const void *addr, size_t size);
> +#endif
>  static inline void clear_page(void *page)
>  {
> +#ifdef CONFIG_KMSAN
> +       /* alternative_call_2() changes @page. */
> +       void *page_copy = page;
> +#endif
>         alternative_call_2(clear_page_orig,
>                            clear_page_rep, X86_FEATURE_REP_GOOD,
>                            clear_page_erms, X86_FEATURE_ERMS,
>                            "=D" (page),
>                            "0" (page)
>                            : "cc", "memory", "rax", "rcx");
> +#ifdef CONFIG_KMSAN
> +       /* Clear KMSAN shadow for the pages that have it. */
> +       kmsan_unpoison_memory(page_copy, PAGE_SIZE);

What happens if this is called before the alternative-call? Could this
(in the interest of simplicity) be moved above it? And if you used the
kmsan-checks.h header, it also doesn't need any "ifdef CONFIG_KMSAN"
anymore.

> +#endif
>  }

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNP8kmZYRsdpHCni33W-Yjgy-ajCAuTE94zwUniyYt7WQw%40mail.gmail.com.
