Return-Path: <kasan-dev+bncBCMIZB7QWENRBDMSQWCAMGQE7M4KKXQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x440.google.com (mail-pf1-x440.google.com [IPv6:2607:f8b0:4864:20::440])
	by mail.lfdr.de (Postfix) with ESMTPS id EF123367E38
	for <lists+kasan-dev@lfdr.de>; Thu, 22 Apr 2021 11:59:42 +0200 (CEST)
Received: by mail-pf1-x440.google.com with SMTP id o129-20020a6292870000b0290241fe341603sf12694631pfd.14
        for <lists+kasan-dev@lfdr.de>; Thu, 22 Apr 2021 02:59:42 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1619085581; cv=pass;
        d=google.com; s=arc-20160816;
        b=qWygYWjoZFdofsDPnz//4twVrCso89aCpBXxgEXgNVhn+XnF1DFKc5tvV8O3POFNV3
         dw97U93eUqeS+WqWBkxYmADleL6nwQCHMrGdQnTs6cAq/kvkjxc1SBVA4LeaN9MiGqoV
         vRaspKfN2n7wuMtf1+eEVtwltSeEhs7tp6bb/DP7NRIPVsoGnytIC95NhJ5dMG1gTcZT
         h6ujTQQkJGorYSrxLrdDZLbX/hH4nQbku9NWyoDqHE37lQfi3BcX6+VGdEg04bujXZFb
         bOyFwtnmEN7aAKpMOu+I8Sshp3LjLbF00yq3AvUd0WuYP2xoOdGAEOw9SzGO5+HXJH2N
         rSmA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=znOo6RbOvzKlbd3zHEiyxD2iE/nuWw7GtQisKPj+0Y4=;
        b=UWfWqsDrcKp0JajRyr2x/+D/DLHnZPzeHFos87yG40OHiAvjWpOUYsV6+dDOkLSyqu
         exkP/5rFyPJm+QrzhAt7n7AXCMs+A5yrfyeKshuFzlGJ5lmsPFfO1EheUmMKg3AOqXus
         fbxHPXpCMWFRu/pNVNmvd2dCwTOICC/ym2AtUHzSSBT5uy8bKUHknR+1c1td8cPrL2kT
         WfvMmG/sslDl2S60K9IScb6FYMWy09W6fjLJCg2mN938FTanA3Ln1YOUuuBXLC6DmOgm
         PKQwRZeLLFg1harRz6fmKccVZzXD1iePyyNTIvByP/zuSqvBgM6N36EF0NH8lNdbKYvt
         OwsA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=BSbT79pH;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::730 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=znOo6RbOvzKlbd3zHEiyxD2iE/nuWw7GtQisKPj+0Y4=;
        b=c5Gcq/5AhgAjCIGVHi/wsT5Ztm4/AHgtNq1UtOz58rQKeL3U2XhtLW61aPFr4h1ilb
         +g91hAX/aeFcfG9onKIvNwsM8Ojqwmr4eSK7PyTwlv9GOguIZKqmpPgaVoHY04UHl2hb
         PPaDTilAIMrPNdlQbuWt0jRdtA2l4JGUnCzdXcnjEQpmrBjCEOUA7l/WbJSwHe5+nuUs
         g+nPmJl5EwxfgcPpFIy1lye8j7ZajYWwYnTSyCLnzjgCffMJZiUzT7qDz7nIaTUPrtgZ
         OR5WEhCvonBVxDJ4sVkCKP0Htwl5Q75+BNySTKCIrayBaberoBhq+U4ay+WEfFpRYlOU
         NYLA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=znOo6RbOvzKlbd3zHEiyxD2iE/nuWw7GtQisKPj+0Y4=;
        b=HdLXXSuKtWNXvENb478fDocFrJPYxeUKZ8pzYOeOEyCZGgjy96EsXnRnL2Hhwf0WuA
         igEfmzjWy/BNyYL6NGDw8bZlINAuUQScrOuDKmArT0cbSzjxZPfCT3m6FE1GIAJXWSGW
         uwFdJZBFKoWvn487vy9+MnG8TCm52k4gPo8PDpzLKUU9U1TvLtBwc+xNsidl7mrPz/fd
         AQH+tGizHVsjBuuQvvSd2cly+P4dXKuHt/sxQGW7e53jS71UensjPr50w5A3m9sX/U8l
         68PE8lU5y4cP5R9p7RVNajBsF9Cqj0AuTmoPzKepcMvVpWnhrCZvdscZLfMEaDfSIklT
         CaFg==
X-Gm-Message-State: AOAM531iGlLFeWmEnUiKf0xQIcbODxG8MosS4Ja0qQcJ5pU5RQgYcuph
	z06GEp7IV4XVvfu9e6VmXCk=
X-Google-Smtp-Source: ABdhPJxbf5FWgsERrRgPTkbqFEoOUPDGrwWDFwbNJE0dWXzc6JuDQ7hJiKH82fxcTw0e+4LJOv6s9g==
X-Received: by 2002:a17:90b:344a:: with SMTP id lj10mr16767610pjb.101.1619085581757;
        Thu, 22 Apr 2021 02:59:41 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:d385:: with SMTP id e5ls2552589pld.10.gmail; Thu, 22
 Apr 2021 02:59:40 -0700 (PDT)
X-Received: by 2002:a17:90a:9409:: with SMTP id r9mr3038508pjo.157.1619085580821;
        Thu, 22 Apr 2021 02:59:40 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1619085580; cv=none;
        d=google.com; s=arc-20160816;
        b=uPYgvcz6XmL/x4SpTUpKWsFNESXzEThUlCR1PVADTx7zGQeU6meE97XEUNLQrbiSKf
         nZVWaF+35vCSV96o0wRQivOn57gM5/xAUunV5lSEJG8yGXlMEwAIXziWIvQAVyJQUEOb
         VKzdMVD3qGN5PcXbjTDBmvUu9+wV1wwtnvxI4m9zcpMPxxwcisB5ly3n7SKlxnWRAFgv
         JeLHgNqzuQjWmETI4nw9qQ/+THu0nNEOzy8zCgoTX9A48Xbfr5CDs6h+CUzmqzlARoeb
         LQq/aGRwYDnDAC/cAP525yiM+AB5P/TSNvUsoXuGJth4fQaQGd0xnJTNyyALg7F6u7Gd
         dNVA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=oSjG3n4vs4c5Vfn7M5IAgCBt0t2W+qOflahbb5eE8zU=;
        b=lB1kxWmJDmQGn2jzQ834i5xxtnkdIOU1wpLIa8i/9kTJEjH2Ct6StS9lP2cbZUiiVq
         ckKOoyiYOQbUDqpWTo9jkYY9yorMqt+dP1p3TfpkdJJ6oDhkdsFjV5JVlcuSWSPWdztB
         4fj2OOkqTyKGPzXu1zOKU+H4gFP5q5zJL7KO6LIuQBW2E98ett6+R8ujGq++SRNkYEPN
         T18xSzvLQLbR3dPk+Y63wIQi0402vStNI0qaYKns6xTeakmY7r5Sx+W80z0fMmSUfofJ
         ufUFTPRMfSl2wVfbR3k8HjTorCTT3lL1QOwQtMbkQlyQoUh/grCc3nR7VdMC7Png5RU2
         22YQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=BSbT79pH;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::730 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x730.google.com (mail-qk1-x730.google.com. [2607:f8b0:4864:20::730])
        by gmr-mx.google.com with ESMTPS id v2si461119pgt.4.2021.04.22.02.59.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 22 Apr 2021 02:59:40 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::730 as permitted sender) client-ip=2607:f8b0:4864:20::730;
Received: by mail-qk1-x730.google.com with SMTP id 8so11938529qkv.8
        for <kasan-dev@googlegroups.com>; Thu, 22 Apr 2021 02:59:40 -0700 (PDT)
X-Received: by 2002:a05:620a:89d:: with SMTP id b29mr2864406qka.231.1619085579765;
 Thu, 22 Apr 2021 02:59:39 -0700 (PDT)
MIME-Version: 1.0
References: <CGME20210422081531epcas5p23d6c72ebf28a23b2efc150d581319ffa@epcas5p2.samsung.com>
 <1619079317-1131-1-git-send-email-maninder1.s@samsung.com> <CACT4Y+azDLjbNH0A8_G-yG4qg964f-sGiBNvfatYuTk5aBu9aw@mail.gmail.com>
In-Reply-To: <CACT4Y+azDLjbNH0A8_G-yG4qg964f-sGiBNvfatYuTk5aBu9aw@mail.gmail.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 22 Apr 2021 11:59:28 +0200
Message-ID: <CACT4Y+ZT47jPfHH-hgtqLre5wC-vy-yLN6Re3A-Oe2CQ+yAOvg@mail.gmail.com>
Subject: Re: [PATCH 1/2] mm/kasan: avoid duplicate KASAN issues from reporting
To: Maninder Singh <maninder1.s@samsung.com>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Andrew Morton <akpm@linux-foundation.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, Linux-MM <linux-mm@kvack.org>, 
	LKML <linux-kernel@vger.kernel.org>, AMIT SAHRAWAT <a.sahrawat@samsung.com>, 
	Vaneet Narang <v.narang@samsung.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=BSbT79pH;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::730
 as permitted sender) smtp.mailfrom=dvyukov@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Dmitry Vyukov <dvyukov@google.com>
Reply-To: Dmitry Vyukov <dvyukov@google.com>
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

On Thu, Apr 22, 2021 at 11:58 AM Dmitry Vyukov <dvyukov@google.com> wrote:
>
> On Thu, Apr 22, 2021 at 11:17 AM Maninder Singh <maninder1.s@samsung.com> wrote:
> >
> > when KASAN multishot is ON and some buggy code hits same code path
> > of KASAN issue repetetively, it can flood logs on console.
> >
> > Check for allocaton, free and backtrace path at time of KASAN error,
> > if these are same then it is duplicate error and avoid these prints
> > from KASAN.

Can this be tested with the kunit kasan tests? If yes, please add a
test for this new code.


> > Co-developed-by: Vaneet Narang <v.narang@samsung.com>
> > Signed-off-by: Vaneet Narang <v.narang@samsung.com>
> > Signed-off-by: Maninder Singh <maninder1.s@samsung.com>
> > ---
> >  mm/kasan/kasan.h  |  6 +++++
> >  mm/kasan/report.c | 67 +++++++++++++++++++++++++++++++++++++++++++++++
> >  2 files changed, 73 insertions(+)
> >
> > diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
> > index 78cf99247139..d14ccce246ba 100644
> > --- a/mm/kasan/kasan.h
> > +++ b/mm/kasan/kasan.h
> > @@ -102,6 +102,12 @@ struct kasan_access_info {
> >         unsigned long ip;
> >  };
> >
> > +struct kasan_record {
> > +       depot_stack_handle_t    bt_handle;
> > +       depot_stack_handle_t    alloc_handle;
> > +       depot_stack_handle_t    free_handle;
> > +};
>
> Hi Maninder,
>
> There is no need to declare this in the header, it can be declared
> more locally in report.h.
>
> > +
> >  /* The layout of struct dictated by compiler */
> >  struct kasan_source_location {
> >         const char *filename;
> > diff --git a/mm/kasan/report.c b/mm/kasan/report.c
> > index 87b271206163..4576de76991b 100644
> > --- a/mm/kasan/report.c
> > +++ b/mm/kasan/report.c
> > @@ -39,6 +39,10 @@ static unsigned long kasan_flags;
> >  #define KASAN_BIT_REPORTED     0
> >  #define KASAN_BIT_MULTI_SHOT   1
> >
> > +#define MAX_RECORDS            (200)
>
> s/MAX_RECORDS/KASAN_MAX_RECORDS/
>
> > +static struct kasan_record kasan_records[MAX_RECORDS];
>
> Since all fields in kasan_record are stack handles, the code will be
> simpler and more uniform, if we store just an array of handles w/o
> distinguishing between alloc/free/access.
>
> > +static int stored_kasan_records;
> > +
> >  bool kasan_save_enable_multi_shot(void)
> >  {
> >         return test_and_set_bit(KASAN_BIT_MULTI_SHOT, &kasan_flags);
> > @@ -360,6 +364,65 @@ void kasan_report_invalid_free(void *object, unsigned long ip)
> >         end_report(&flags, (unsigned long)object);
> >  }
> >
> > +/*
> > + * @save_report()
> > + *
> > + * returns false if same record is already saved.
>
> s/same/the same/
>
> > + * returns true if its new record and saved in database of KASAN.
>
> s/its/it's/
> s/database/the database/
>
> > + */
> > +static bool save_report(void *addr, struct kasan_access_info *info, u8 tag, unsigned long *flags)
> > +{
> > +       struct kasan_record record = {0};
> > +       depot_stack_handle_t bt_handle;
> > +       int i = 0;
> > +       const char *bug_type;
> > +       struct kasan_alloc_meta *alloc_meta;
> > +       struct kasan_track *free_track;
> > +       struct page *page;
> > +       bool ret = true;
> > +
> > +       kasan_disable_current();
> > +       spin_lock_irqsave(&report_lock, *flags);
>
> Reusing the caller flags looks strange, do we need it?
> But also the very next function start_report() also does the same
> dance: kasan_disable_current/spin_lock_irqsave. It feels reasonable to
> lock once, check for dups and return early if it's a dup.
>
> > +       bug_type = kasan_get_bug_type(info);
> > +       page = kasan_addr_to_page(addr);
> > +       bt_handle = kasan_save_stack(GFP_KERNEL);
>
> ASsign directly to record.bt_handle.
>
> > +       if (page && PageSlab(page)) {
> > +               struct kmem_cache *cache = page->slab_cache;
> > +               void *object = nearest_obj(cache, page, addr);
>
> Since you already declare new var in this block, move
> alloc_meta/free_track here as well.
>
> > +
> > +               alloc_meta = kasan_get_alloc_meta(cache, object);
> > +               free_track = kasan_get_free_track(cache, object, tag);
> > +               record.alloc_handle = alloc_meta->alloc_track.stack;
> > +               if (free_track)
> > +                       record.free_handle = free_track->stack;
> > +       }
> > +
> > +       record.bt_handle = bt_handle;
> > +
> > +       for (i = 0; i < stored_kasan_records; i++) {
> > +               if (record.bt_handle != kasan_records[i].bt_handle)
> > +                       continue;
> > +               if (record.alloc_handle != kasan_records[i].alloc_handle)
> > +                       continue;
> > +               if (!strncmp("use-after-free", bug_type, 15) &&
>
> Comparing strings is unreliable and will break in future. Compare
> handle with 0 instead, you already assume that 0 handle is "no
> handle".
>
> > +                       (record.free_handle != kasan_records[i].free_handle))
> > +                       continue;
> > +
> > +               ret = false;
> > +               goto done;
> > +       }
> > +
> > +       memcpy(&kasan_records[stored_kasan_records], &record, sizeof(struct kasan_record));
> > +       stored_kasan_records++;
>
> I think you just introduced an out-of-bounds write into KASAN, check
> for MAX_RECORDS ;)
>
>
> > +
> > +done:
> > +       spin_unlock_irqrestore(&report_lock, *flags);
> > +       kasan_enable_current();
> > +       return ret;
> > +}
> > +
> >  static void __kasan_report(unsigned long addr, size_t size, bool is_write,
> >                                 unsigned long ip)
> >  {
> > @@ -388,6 +451,10 @@ static void __kasan_report(unsigned long addr, size_t size, bool is_write,
> >         info.is_write = is_write;
> >         info.ip = ip;
> >
> > +       if (addr_has_metadata(untagged_addr) &&
>
> Why addr_has_metadata check?
> The kernel will probably crash later anyway, but from point of view of
> this code, I don't see reasons to not dedup wild accesses.
>
> > +               !save_report(untagged_addr, &info, get_tag(tagged_addr), &flags))
> > +               return;
> > +
> >         start_report(&flags);
> >
> >         print_error_description(&info);
> > --
> > 2.17.1
> >

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BZT47jPfHH-hgtqLre5wC-vy-yLN6Re3A-Oe2CQ%2ByAOvg%40mail.gmail.com.
