Return-Path: <kasan-dev+bncBDH7RNXZVMORBWWW3COQMGQELOGLIAQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x338.google.com (mail-ot1-x338.google.com [IPv6:2607:f8b0:4864:20::338])
	by mail.lfdr.de (Postfix) with ESMTPS id 7A2D665E29A
	for <lists+kasan-dev@lfdr.de>; Thu,  5 Jan 2023 02:43:56 +0100 (CET)
Received: by mail-ot1-x338.google.com with SMTP id l44-20020a0568302b2c00b006782da3829esf18422672otv.16
        for <lists+kasan-dev@lfdr.de>; Wed, 04 Jan 2023 17:43:56 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1672883035; cv=pass;
        d=google.com; s=arc-20160816;
        b=zl216Bv6ZFGS/b8+kLVt43OBdiGnYVxIYlcx//klibVhyUBKpc7l6EvJsbuZF/QdNn
         QoLGUVVC2E3pLanRuUlQVpbNHMGkPpW4OXFe6QgPK8wE8yJuPPBT3zSiI3JMlPSiISIJ
         mNFfNrED7sdaZUCph165spBxPesF1ywIUukjDCkGVWE8KCRHOuIYyj+9QgYvcNBA/hh8
         z7mXNzCA7SrCp4/iEMwDfj56ijc4DAQ6ZbyAT8zq7PPf/vR+OWRqjUynF9xvi7We1aVU
         pLf1erEm7Jja7Si+tcDLQFDgdv2LtKuxHuG7HdDiiYYsQjoT/wHX10H5BgCDTbkKidVx
         qXMw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :message-id:in-reply-to:subject:cc:to:from:date:dkim-signature;
        bh=PfFTACZ7xNMcNS4b3W85q99d4R3kqTFsj4qss6Rh2nQ=;
        b=VDEpEOHY+5Wa9f5RwYmoajykwQkIo6+c3FMGueQkDXbruJqz2mY4ZWgmXjRmuj5BkX
         QEWPgUE5qvZFI/Rrw9HfSvmSTf9gM9vHKzXRok/xTjle0STqoUqA0EpTAd36UrTOjVNf
         pEeayoOFJQ/FB2kL9UZygc+9W0HfqRBVbjpzEHOPTyNa25TnuMBtJ+bhteyInyeCrs8/
         dpMOalP6QzvwXj8r/QEUu09Z/K6sRjL1DUu9TH5OTI7JjqQKd0hj6wewhxoqKjTN/u+i
         LeZyOXuyPg5i/IgHpetOGLk4gWKMuNgRm8tXw7+PUfFo5fuCkdE5/OWL06FtsgFV+tEu
         /d0w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=aGe2tFaw;
       spf=pass (google.com: domain of rientjes@google.com designates 2607:f8b0:4864:20::102e as permitted sender) smtp.mailfrom=rientjes@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:message-id:in-reply-to:subject:cc:to:from:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=PfFTACZ7xNMcNS4b3W85q99d4R3kqTFsj4qss6Rh2nQ=;
        b=ooUavpzbg1bXurOc4buFYGOaK4EySs9FBT+/RHE7XmqnCqnjGsFHmNivod6MKcxuE8
         D5XSXN5bkRPe0UBT5QpPNYampDIkNjQi6e971BUAv/gCiP8YmncQRviR9JsOuCqW2uQu
         MM7P3ZbqZGNCefMSiBEwhgVVk5e/mZFm1BNYKKq9dRLMvJgoK3wDuuNFU4FbcTktHYnO
         GGCWj4TbVkd3Fomm3IBlceZzvYgbPPWojFQs2YBOOPL8g94ZFrvvCagr62N/fenqITwn
         HAwuTylEvVQ2KUPzl8t8FdCUIPVNUj4EiJWliKeHz5/pIYEklSJBZQdFBBTg3a9miHqj
         TfEg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:message-id:in-reply-to:subject:cc:to:from:date
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=PfFTACZ7xNMcNS4b3W85q99d4R3kqTFsj4qss6Rh2nQ=;
        b=6EkPxx+aU7u4cffNwjG07KhAWMBiwAHikylfdoINLoapIacZiEHSFtXJawutrqGD4u
         BJLkyElu37eJtwOwLw0c7R8logQaNAbmIBPZPNLOPbq+uY/gVa+AmZStK5UHp/eqKBtz
         5mZbZTGtktsxjxSF+PiKcPk5D3ajF6ezPoWCsUK3ve1zrGXPSHbdgMyueH5P7KtaCcie
         x1SZ8axrGwJI2Q2AgTPTsqCu3smtrhYVrXdG5zNV4qAq9BiJIpD6iEEaEINKI/7a9vDa
         hLv0Xcd6YovZeQVgK/e0WyV8jlxpaoa88CG8bstjMw/KAjtuT4ZWtXopo0ELLKj2KxGD
         vVeg==
X-Gm-Message-State: AFqh2krAxhu3ApQCtV0ZqqrTe9fvuXGPhQVt9PSc6/cjdBVHoafw1Y5J
	JBqbtl+r1LGl53Yryv4SKBY=
X-Google-Smtp-Source: AMrXdXtmaw6NOZszIlirWrkEwal2pof2oFb4TgC6RI0ppo5LM4QyGHXqJGJexHXlPtIofbDTcj2S5Q==
X-Received: by 2002:a05:6830:144e:b0:66e:f6cb:cb4e with SMTP id w14-20020a056830144e00b0066ef6cbcb4emr3135649otp.105.1672883034843;
        Wed, 04 Jan 2023 17:43:54 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a54:4f0b:0:b0:363:19d3:70f7 with SMTP id e11-20020a544f0b000000b0036319d370f7ls9167081oiy.9.-pod-prod-gmail;
 Wed, 04 Jan 2023 17:43:54 -0800 (PST)
X-Received: by 2002:aca:c0c6:0:b0:363:acf4:7f44 with SMTP id q189-20020acac0c6000000b00363acf47f44mr6825712oif.51.1672883034339;
        Wed, 04 Jan 2023 17:43:54 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1672883034; cv=none;
        d=google.com; s=arc-20160816;
        b=VUy/1Lw+fl2Mlez6sxC1CqkU7kB/fuSvJ3KBsgsMmaDZduuN5lutCxo/9jP3OZFG/Z
         uS8n4Zl/lDvLuYaPLS/SkRwX9t7tOj0KuGuA1t20QghaALUSyVrGF5rd4YSRDn/KtFC5
         UU+AuAuHmegG7pMr/4WCIUg+4YdZxPewyIDqMcPwFxldh0hjCTYX+JmmNqZkBpOmRYxN
         Jg0J7Uj9E9dRUa5bOmYdDvwGMgD4fbnP2MaWz4+2ehaeDYab1pTMXkLFp1hWHZnla9qF
         Q51dRcU6NtSa800D13Xtc4/iy+cHxWla1mhGbZGHOtJ9n4oHQP8TdFOngvg4ai+ELoN7
         e3Yw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:references:message-id:in-reply-to:subject:cc:to:from
         :date:dkim-signature;
        bh=qvbp9StBfREPm9I8aa88N5F9Rq5kJCaZobikFDCIkUs=;
        b=bMa9IzMfkMDXfNQI9NZRwIuH8vjTIyg9UPaHXue10rH1aY5EzAeiahw/yK2mh+9uXF
         Gp/dpkRazZj8Vb0J7LcrciIaONfKkItTC4nY91W/AevZOzOLnzAkZjjamBRPWxn/yczz
         MPwhYXr3QqVgms2/3WNKhy/c3GbAVLY/nl68x0eUIPknsQxBgmHZ2NG/cYJQbi8rVl0J
         WgB2FES4Qp4tjXhX6YO9LCOR/HlC+NFQsE6CsQMgex30hPSo6KTYny8TLU3H1IAxU84i
         8jDxG1ZyQu8w45UaS6dFuXskqutloftJCyTCWGP9NCcznLAZNkL5zYK3gz9F8ei1s06+
         KEPw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=aGe2tFaw;
       spf=pass (google.com: domain of rientjes@google.com designates 2607:f8b0:4864:20::102e as permitted sender) smtp.mailfrom=rientjes@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pj1-x102e.google.com (mail-pj1-x102e.google.com. [2607:f8b0:4864:20::102e])
        by gmr-mx.google.com with ESMTPS id 103-20020a9d0870000000b0066c427f94ecsi2894046oty.3.2023.01.04.17.43.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 04 Jan 2023 17:43:54 -0800 (PST)
Received-SPF: pass (google.com: domain of rientjes@google.com designates 2607:f8b0:4864:20::102e as permitted sender) client-ip=2607:f8b0:4864:20::102e;
Received: by mail-pj1-x102e.google.com with SMTP id c8-20020a17090a4d0800b00225c3614161so498767pjg.5
        for <kasan-dev@googlegroups.com>; Wed, 04 Jan 2023 17:43:54 -0800 (PST)
X-Received: by 2002:a17:902:9b95:b0:189:6d32:afeb with SMTP id y21-20020a1709029b9500b001896d32afebmr59plp.1.1672883033545;
        Wed, 04 Jan 2023 17:43:53 -0800 (PST)
Received: from [2620:15c:29:203:fc97:724c:15bb:25c7] ([2620:15c:29:203:fc97:724c:15bb:25c7])
        by smtp.gmail.com with ESMTPSA id l19-20020a170902d35300b0019290a36553sm11980965plk.63.2023.01.04.17.43.52
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 04 Jan 2023 17:43:52 -0800 (PST)
Date: Wed, 4 Jan 2023 17:43:51 -0800 (PST)
From: "'David Rientjes' via kasan-dev" <kasan-dev@googlegroups.com>
To: Aaron Thompson <dev@aaront.org>
cc: linux-mm@kvack.org, Mike Rapoport <rppt@kernel.org>, 
    "H. Peter Anvin" <hpa@zytor.com>, Alexander Potapenko <glider@google.com>, 
    Andrew Morton <akpm@linux-foundation.org>, 
    Andy Shevchenko <andy@infradead.org>, Ard Biesheuvel <ardb@kernel.org>, 
    Borislav Petkov <bp@alien8.de>, Darren Hart <dvhart@infradead.org>, 
    Dave Hansen <dave.hansen@linux.intel.com>, 
    Dmitry Vyukov <dvyukov@google.com>, Ingo Molnar <mingo@redhat.com>, 
    Marco Elver <elver@google.com>, Thomas Gleixner <tglx@linutronix.de>, 
    kasan-dev@googlegroups.com, linux-efi@vger.kernel.org, 
    linux-kernel@vger.kernel.org, platform-driver-x86@vger.kernel.org, 
    x86@kernel.org
Subject: Re: [PATCH 0/1] Pages not released from memblock to the buddy
 allocator
In-Reply-To: <010101857bbc3a41-173240b3-9064-42ef-93f3-482081126ec2-000000@us-west-2.amazonses.com>
Message-ID: <30478b4a-870b-bf48-76d0-a236a40e7674@google.com>
References: <010101857bbc3a41-173240b3-9064-42ef-93f3-482081126ec2-000000@us-west-2.amazonses.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: rientjes@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=aGe2tFaw;       spf=pass
 (google.com: domain of rientjes@google.com designates 2607:f8b0:4864:20::102e
 as permitted sender) smtp.mailfrom=rientjes@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: David Rientjes <rientjes@google.com>
Reply-To: David Rientjes <rientjes@google.com>
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

On Wed, 4 Jan 2023, Aaron Thompson wrote:

> Hi all,
> 
> (I've CC'ed the KMSAN and x86 EFI maintainers as an FYI; the only code change
> I'm proposing is in memblock.)
> 
> I've run into a case where pages are not released from memblock to the buddy
> allocator. If deferred struct page init is enabled, and memblock_free_late() is
> called before page_alloc_init_late() has run, and the pages being freed are in
> the deferred init range, then the pages are never released. memblock_free_late()
> calls memblock_free_pages() which only releases the pages if they are not in the
> deferred range. That is correct for free pages because they will be initialized
> and released by page_alloc_init_late(), but memblock_free_late() is dealing with
> reserved pages. If memblock_free_late() doesn't release those pages, they will
> forever be reserved. All reserved pages were initialized by memblock_free_all(),
> so I believe the fix is to simply have memblock_free_late() call
> __free_pages_core() directly instead of memblock_free_pages().
> 
> In addition, there was a recent change (3c20650982609 "init: kmsan: call KMSAN
> initialization routines") that added a call to kmsan_memblock_free_pages() in
> memblock_free_pages(). It looks to me like it would also be incorrect to make
> that call in the memblock_free_late() case, because the KMSAN metadata was
> already initialized for all reserved pages by kmsan_init_shadow(), which runs
> before memblock_free_all(). Having memblock_free_late() call __free_pages_core()
> directly also fixes this issue.
> 
> I encountered this issue when I tried to switch some x86_64 VMs I was running
> from BIOS boot to EFI boot. The x86 EFI code reserves all EFI boot services
> ranges via memblock_reserve() (part of setup_arch()), and it frees them later
> via memblock_free_late() (part of efi_enter_virtual_mode()). The EFI
> implementation of the VM I was attempting this on, an Amazon EC2 t3.micro
> instance, maps north of 170 MB in boot services ranges that happen to fall in
> the deferred init range. I certainly noticed when that much memory went missing
> on a 1 GB VM.
> 
> I've tested the patch on EC2 instances, qemu/KVM VMs with OVMF, and some real
> x86_64 EFI systems, and they all look good to me. However, the physical systems
> that I have don't actually trigger this issue because they all have more than 4
> GB of RAM, so their deferred init range starts above 4 GB (it's always in the
> highest zone and ZONE_DMA32 ends at 4 GB) while their EFI boot services mappings
> are below 4 GB.
> 
> Deferred struct page init can't be enabled on x86_32 so those systems are
> unaffected. I haven't found any other code paths that would trigger this issue,
> though I can't promise that there aren't any. I did run with this patch on an
> arm64 VM as a sanity check, but memblock=debug didn't show any calls to
> memblock_free_late() so that system was unaffected as well.
> 
> I am guessing that this change should also go the stable kernels but it may not
> apply cleanly (__free_pages_core() was __free_pages_boot_core() and
> memblock_free_pages() was __free_pages_bootmem() when this issue was first
> introduced). I haven't gone through that process before so please let me know if
> I can help with that.
> 
> This is the end result on an EC2 t3.micro instance booting via EFI:
> 
> v6.2-rc2:
>   # grep -E 'Node|spanned|present|managed' /proc/zoneinfo
>   Node 0, zone      DMA
>           spanned  4095
>           present  3999
>           managed  3840
>   Node 0, zone    DMA32
>           spanned  246652
>           present  245868
>           managed  178867
> 
> v6.2-rc2 + patch:
>   # grep -E 'Node|spanned|present|managed' /proc/zoneinfo
>   Node 0, zone      DMA
>           spanned  4095
>           present  3999
>           managed  3840
>   Node 0, zone    DMA32
>           spanned  246652
>           present  245868
>           managed  222816
> 

The above before + after seems useful information to include in the commit 
description of the change.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/30478b4a-870b-bf48-76d0-a236a40e7674%40google.com.
