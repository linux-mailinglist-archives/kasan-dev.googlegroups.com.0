Return-Path: <kasan-dev+bncBDX4HWEMTEBRBFFB3H5QKGQEWNZQCAY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83a.google.com (mail-qt1-x83a.google.com [IPv6:2607:f8b0:4864:20::83a])
	by mail.lfdr.de (Postfix) with ESMTPS id E28842809C5
	for <lists+kasan-dev@lfdr.de>; Thu,  1 Oct 2020 23:56:37 +0200 (CEST)
Received: by mail-qt1-x83a.google.com with SMTP id h31sf4805898qtd.14
        for <lists+kasan-dev@lfdr.de>; Thu, 01 Oct 2020 14:56:37 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1601589397; cv=pass;
        d=google.com; s=arc-20160816;
        b=JjhrZnkIo3fqa5ErB1p92qliIw0Kwz4WYr2KVWR/iRmAzKR3pjtCK+wL8x1xGcvzNp
         O3zfVNtTu2sS0dQgbRdg2cCgAOvKQzL1AsvJqzLuL38xGRsfvx0aU5LFryjFuxEQrihf
         yjyMxotyWKmKAfUm5BlhNGTWJjb/EGbI01/OcsM5illKfREixu7XU+BLXiENJAt5Grs1
         4SQCY7xH7meedAak1tisN8nvakWhuVS61BKIH1krK9VLtjzG3hgzQW+HxZy4/vRMf+b3
         4BZt/tqSAuHWPG30t9KAeh3dH49UM+8ZE/F247MK944F7EJe5bHs8M/00lPZX6Iacl7O
         IHFQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=wG9Cy3x0/t47zN4w2QItEPMs9rAAxmNIdnUt5mtqV2g=;
        b=XVV5qggSraf7GDcaHXFE7YElkypwJpi2IffSCJKi4t1I+JemhjTW+E/EofqWcK7/rL
         1VXJt87gMrZBnXOaRx1x+sPd6JadkjWLxXEaJe7I3GnTWRRG69HAGKb/t2/jrxyaK5WY
         XinhQXtobrhktAdp+xyY2jM/L/ZP9zQobus5DojpVcJrtKOtCgHxzGX680XeGDp6GpD7
         sImpiaJ7OYvvpZDLJcXdLIoXpL8IDcx8RnQYN4ut+h/Ew2/2dO5Xo8nCCRHRTIH1VkPz
         5ZrbN97goW8TvJlJatI7lACeDfyPXgZm+pUkITdS4MJdqNyXPKDkS8T9wt30oH7phiqt
         nkcA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=mGj4QqCg;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::444 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=wG9Cy3x0/t47zN4w2QItEPMs9rAAxmNIdnUt5mtqV2g=;
        b=QW+RLuapzCgbf+Mi//NGH0K03qMRmaPf2HqKimpe7WxKPam+igSy7QHZHmdf9BAMmC
         X/85d3/AQv9jdbYYW2fDVkDCAg9Giv0sVlW6G4dcRQlCoCChldDvgo0OJVgcRHUqbcCG
         7iofBXHQu2RBkUDfwgKaEYSnyERPsu3ubnxQhuu4R/g+X3sEwKf2psr9z6cCShq5bl3B
         jNeWnNMLRos4JwXO+VHlWGT5PT/49ouJuDUkB8RWXB+Pp0uVLnF7gCph970n6SPZb428
         SzABrcXhUcDZS5DsqThL6aO5WD0DpWbPKBZ2ypvEgxbIaq/Uvw0hdH8OXsAEPTPGdP2e
         kFCQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=wG9Cy3x0/t47zN4w2QItEPMs9rAAxmNIdnUt5mtqV2g=;
        b=LLcvxVbuz6sirEoiMIrmgCRQwBMiOUuhtT4T+IJ48J4PkMWj058WRc2zEFrwGyLhcr
         XMia4T4Y5jAfYtD1s3ad9YLEcBqOShHk8P2wKxvtLsNExVAulkDVBbsI+8IW0G7lTjpj
         dqaJi5MVBHC2BdDMC76JTU8bSe5yRpAa+cEHOYu1lkYr0XiVITkiKVzxyI4esm4tTVi6
         LosSA+2ugkK/l23sBWfusqnJGcZ1mbeq3LMIAADSUbYpcRwvxyx8W31Y1avRfSlk13FU
         0wZLz53D1depFMM2UBIuLN38gb8n1pbYAMHPhHgsHQbFiqb44RWvu9R4onMzbwfZ1k91
         FfsQ==
X-Gm-Message-State: AOAM5306BXpvb7vkc5XiuEDfBp+UETxVysUqze4IsWneZy1sCb+JdBnx
	tcz1hfMf+0OSt4kVENkixjo=
X-Google-Smtp-Source: ABdhPJwshrBk5e0rZqJziRJeCM19Hjk3WoBwAfqcAT2inSata8RRZ+kFKniwlcGid2rnQKwyEXU+QA==
X-Received: by 2002:aed:2d83:: with SMTP id i3mr9916809qtd.198.1601589396827;
        Thu, 01 Oct 2020 14:56:36 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ae9:d802:: with SMTP id u2ls3209541qkf.5.gmail; Thu, 01 Oct
 2020 14:56:36 -0700 (PDT)
X-Received: by 2002:a05:620a:16b5:: with SMTP id s21mr9870148qkj.281.1601589396370;
        Thu, 01 Oct 2020 14:56:36 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1601589396; cv=none;
        d=google.com; s=arc-20160816;
        b=oG8RP9rv2hHTNJJMxkHR35J6HGiZdql2E9LL+2TuaSbgnHt+CSVhE9Zrl5lxlmriln
         1WxPM256jU1uCTIWakbzP4jx0fXpEnieb6+7CI/nRy2+e/UQbmT84QrnGQsUVKMRHkVd
         vwMF5DaorOzNK9No/RRdTMYbXIbMRzHxhRqtIMoV+ZUyjjlecObA0c/WEXp9/VF893GI
         klSZSTe7zcnSVTEpm1jrRWODpTcXvxhVj55JKIHSRpWdcelkKKik7K2LJWfWXFmDxC23
         jXEm6EPrVwLytsuxUO26EUyaUOT/zbYXeWeAz82J7dlj7REGtUd3lnOag2M1pOQXF0Rv
         axQg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=lYN4Jo8znVBvexmXtOTq7Vyw02r7hMLAu1E79NO6g4Y=;
        b=orWQ/DqloU3ioGLfzx5JNaPSytgRX51Kf011RHcH6VvWDnzcwMvIWEK+q8ZziBaK37
         ywjojCt5YNepTH+DKI+rfwTq5nYRizKP4g+CxXkPnHgE3Tq1ModirFZpmi6e5Iz+Q0bS
         gUcoLQ6F7N18MKNcX5nedTgwJa1gVrOY8WLmtQd0+ozcnIJrjFwZoexOArNaCHV93qJO
         1W9r4/RCAQbAePk7egP6l0AgLIBTcCf70mhmwElxap9sGGnlxqxGnOim6NtRWgGpLXZG
         V4uzQr+etNPl30cf9lv+GpaTY3fITlUckY4UjicRaflbZ+GoBXOvIYPwZHBK2MoKUi+Z
         GjIA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=mGj4QqCg;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::444 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pf1-x444.google.com (mail-pf1-x444.google.com. [2607:f8b0:4864:20::444])
        by gmr-mx.google.com with ESMTPS id h17si413209qtu.2.2020.10.01.14.56.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 01 Oct 2020 14:56:36 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::444 as permitted sender) client-ip=2607:f8b0:4864:20::444;
Received: by mail-pf1-x444.google.com with SMTP id x22so5931964pfo.12
        for <kasan-dev@googlegroups.com>; Thu, 01 Oct 2020 14:56:36 -0700 (PDT)
X-Received: by 2002:a63:2209:: with SMTP id i9mr7781306pgi.130.1601589395167;
 Thu, 01 Oct 2020 14:56:35 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1600987622.git.andreyknvl@google.com> <494045645c31b7f9298851118cb0b7f8964ac0f4.1600987622.git.andreyknvl@google.com>
 <20201001175402.GP4162920@elver.google.com>
In-Reply-To: <20201001175402.GP4162920@elver.google.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 1 Oct 2020 23:56:24 +0200
Message-ID: <CAAeHK+yFN1NbWBSrdjHDHT9-Fk+mYMpEy_jbW8gpkiANkT=z7g@mail.gmail.com>
Subject: Re: [PATCH v3 20/39] kasan: separate metadata_fetch_row for each mode
To: Marco Elver <elver@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Catalin Marinas <catalin.marinas@arm.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Elena Petrova <lenaptr@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	Will Deacon <will.deacon@arm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=mGj4QqCg;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::444
 as permitted sender) smtp.mailfrom=andreyknvl@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

On Thu, Oct 1, 2020 at 7:54 PM <elver@google.com> wrote:
>
> On Fri, Sep 25, 2020 at 12:50AM +0200, Andrey Konovalov wrote:
> > This is a preparatory commit for the upcoming addition of a new hardware
> > tag-based (MTE-based) KASAN mode.
>
> Not sure why I've only noticed this now, but all these patches seem to
> say "This is a preparatory commit" -- I don't think "commit" is
> applicable, and "This .. patch" is discouraged.

"This commit" is used all over the place if you do git log, so it
should be fine.

>
> Maybe just change it to say "This is to prepare for the upcoming ..."
> after the below paragraph?
>
> > Rework print_memory_metadata() to make it agnostic with regard to the
> > way metadata is stored. Allow providing a separate metadata_fetch_row()
> > implementation for each KASAN mode. Hardware tag-based KASAN will provide
> > its own implementation that doesn't use shadow memory.
>
> (i.e. move it here)
>
> > No functional changes for software modes.
> >
> > Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> > Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
>
> Other than that,
>
> Reviewed-by: Marco Elver <elver@google.com>

Thanks!

>
> > ---
> > Change-Id: I5b0ed1d079ea776e620beca6a529a861e7dced95
> > ---
> >  mm/kasan/kasan.h          |  8 ++++++
> >  mm/kasan/report.c         | 56 +++++++++++++++++++--------------------
> >  mm/kasan/report_generic.c |  5 ++++
> >  mm/kasan/report_sw_tags.c |  5 ++++
> >  4 files changed, 45 insertions(+), 29 deletions(-)
> >
> > diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
> > index 0bf669fad345..50b59c8f8be2 100644
> > --- a/mm/kasan/kasan.h
> > +++ b/mm/kasan/kasan.h
> > @@ -57,6 +57,13 @@
> >  #define KASAN_ABI_VERSION 1
> >  #endif
> >
> > +/* Metadata layout customization. */
> > +#define META_BYTES_PER_BLOCK 1
> > +#define META_BLOCKS_PER_ROW 16
> > +#define META_BYTES_PER_ROW (META_BLOCKS_PER_ROW * META_BYTES_PER_BLOCK)
> > +#define META_MEM_BYTES_PER_ROW (META_BYTES_PER_ROW * KASAN_GRANULE_SIZE)
> > +#define META_ROWS_AROUND_ADDR 2
> > +
> >  struct kasan_access_info {
> >       const void *access_addr;
> >       const void *first_bad_addr;
> > @@ -168,6 +175,7 @@ bool check_invalid_free(void *addr);
> >
> >  void *find_first_bad_addr(void *addr, size_t size);
> >  const char *get_bug_type(struct kasan_access_info *info);
> > +void metadata_fetch_row(char *buffer, void *row);
> >
> >  #ifdef CONFIG_KASAN_STACK_ENABLE
> >  void print_address_stack_frame(const void *addr);
> > diff --git a/mm/kasan/report.c b/mm/kasan/report.c
> > index 13b27675a696..3924127b4786 100644
> > --- a/mm/kasan/report.c
> > +++ b/mm/kasan/report.c
> > @@ -31,12 +31,6 @@
> >  #include "kasan.h"
> >  #include "../slab.h"
> >
> > -/* Metadata layout customization. */
> > -#define META_BYTES_PER_BLOCK 1
> > -#define META_BLOCKS_PER_ROW 16
> > -#define META_BYTES_PER_ROW (META_BLOCKS_PER_ROW * META_BYTES_PER_BLOCK)
> > -#define META_ROWS_AROUND_ADDR 2
> > -
> >  static unsigned long kasan_flags;
> >
> >  #define KASAN_BIT_REPORTED   0
> > @@ -236,55 +230,59 @@ static void print_address_description(void *addr, u8 tag)
> >       print_address_stack_frame(addr);
> >  }
> >
> > -static bool row_is_guilty(const void *row, const void *guilty)
> > +static bool meta_row_is_guilty(const void *row, const void *addr)
> >  {
> > -     return (row <= guilty) && (guilty < row + META_BYTES_PER_ROW);
> > +     return (row <= addr) && (addr < row + META_MEM_BYTES_PER_ROW);
> >  }
> >
> > -static int shadow_pointer_offset(const void *row, const void *shadow)
> > +static int meta_pointer_offset(const void *row, const void *addr)
> >  {
> > -     /* The length of ">ff00ff00ff00ff00: " is
> > -      *    3 + (BITS_PER_LONG/8)*2 chars.
> > +     /*
> > +      * Memory state around the buggy address:
> > +      *  ff00ff00ff00ff00: 00 00 00 05 fe fe fe fe fe fe fe fe fe fe fe fe
> > +      *  ...
> > +      *
> > +      * The length of ">ff00ff00ff00ff00: " is
> > +      *    3 + (BITS_PER_LONG / 8) * 2 chars.
> > +      * The length of each granule metadata is 2 bytes
> > +      *    plus 1 byte for space.
> >        */
> > -     return 3 + (BITS_PER_LONG/8)*2 + (shadow - row)*2 +
> > -             (shadow - row) / META_BYTES_PER_BLOCK + 1;
> > +     return 3 + (BITS_PER_LONG / 8) * 2 +
> > +             (addr - row) / KASAN_GRANULE_SIZE * 3 + 1;
> >  }
> >
> >  static void print_memory_metadata(const void *addr)
> >  {
> >       int i;
> > -     const void *shadow = kasan_mem_to_shadow(addr);
> > -     const void *shadow_row;
> > +     void *row;
> >
> > -     shadow_row = (void *)round_down((unsigned long)shadow,
> > -                                     META_BYTES_PER_ROW)
> > -             - META_ROWS_AROUND_ADDR * META_BYTES_PER_ROW;
> > +     row = (void *)round_down((unsigned long)addr, META_MEM_BYTES_PER_ROW)
> > +                     - META_ROWS_AROUND_ADDR * META_MEM_BYTES_PER_ROW;
> >
> >       pr_err("Memory state around the buggy address:\n");
> >
> >       for (i = -META_ROWS_AROUND_ADDR; i <= META_ROWS_AROUND_ADDR; i++) {
> > -             const void *kaddr = kasan_shadow_to_mem(shadow_row);
> > -             char buffer[4 + (BITS_PER_LONG/8)*2];
> > -             char shadow_buf[META_BYTES_PER_ROW];
> > +             char buffer[4 + (BITS_PER_LONG / 8) * 2];
> > +             char metadata[META_BYTES_PER_ROW];
> >
> >               snprintf(buffer, sizeof(buffer),
> > -                     (i == 0) ? ">%px: " : " %px: ", kaddr);
> > +                             (i == 0) ? ">%px: " : " %px: ", row);
> > +
> >               /*
> >                * We should not pass a shadow pointer to generic
> >                * function, because generic functions may try to
> >                * access kasan mapping for the passed address.
> >                */
> > -             memcpy(shadow_buf, shadow_row, META_BYTES_PER_ROW);
> > +             metadata_fetch_row(&metadata[0], row);
> > +
> >               print_hex_dump(KERN_ERR, buffer,
> >                       DUMP_PREFIX_NONE, META_BYTES_PER_ROW, 1,
> > -                     shadow_buf, META_BYTES_PER_ROW, 0);
> > +                     metadata, META_BYTES_PER_ROW, 0);
> >
> > -             if (row_is_guilty(shadow_row, shadow))
> > -                     pr_err("%*c\n",
> > -                             shadow_pointer_offset(shadow_row, shadow),
> > -                             '^');
> > +             if (meta_row_is_guilty(row, addr))
> > +                     pr_err("%*c\n", meta_pointer_offset(row, addr), '^');
> >
> > -             shadow_row += META_BYTES_PER_ROW;
> > +             row += META_MEM_BYTES_PER_ROW;
> >       }
> >  }
> >
> > diff --git a/mm/kasan/report_generic.c b/mm/kasan/report_generic.c
> > index ff067071cd28..de7a85c83106 100644
> > --- a/mm/kasan/report_generic.c
> > +++ b/mm/kasan/report_generic.c
> > @@ -122,6 +122,11 @@ const char *get_bug_type(struct kasan_access_info *info)
> >       return get_wild_bug_type(info);
> >  }
> >
> > +void metadata_fetch_row(char *buffer, void *row)
> > +{
> > +     memcpy(buffer, kasan_mem_to_shadow(row), META_BYTES_PER_ROW);
> > +}
> > +
> >  #ifdef CONFIG_KASAN_STACK_ENABLE
> >  static bool __must_check tokenize_frame_descr(const char **frame_descr,
> >                                             char *token, size_t max_tok_len,
> > diff --git a/mm/kasan/report_sw_tags.c b/mm/kasan/report_sw_tags.c
> > index c87d5a343b4e..add2dfe6169c 100644
> > --- a/mm/kasan/report_sw_tags.c
> > +++ b/mm/kasan/report_sw_tags.c
> > @@ -80,6 +80,11 @@ void *find_first_bad_addr(void *addr, size_t size)
> >       return p;
> >  }
> >
> > +void metadata_fetch_row(char *buffer, void *row)
> > +{
> > +     memcpy(buffer, kasan_mem_to_shadow(row), META_BYTES_PER_ROW);
> > +}
> > +
> >  void print_tags(u8 addr_tag, const void *addr)
> >  {
> >       u8 *shadow = (u8 *)kasan_mem_to_shadow(addr);
> > --
> > 2.28.0.681.g6f77f65b4e-goog
> >

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2ByFN1NbWBSrdjHDHT9-Fk%2BmYMpEy_jbW8gpkiANkT%3Dz7g%40mail.gmail.com.
