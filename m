Return-Path: <kasan-dev+bncBCMIZB7QWENRBS4RQWCAMGQE4LMK74I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x540.google.com (mail-pg1-x540.google.com [IPv6:2607:f8b0:4864:20::540])
	by mail.lfdr.de (Postfix) with ESMTPS id A37AF367E33
	for <lists+kasan-dev@lfdr.de>; Thu, 22 Apr 2021 11:58:36 +0200 (CEST)
Received: by mail-pg1-x540.google.com with SMTP id r27-20020a63441b0000b02901e65403d377sf12150082pga.14
        for <lists+kasan-dev@lfdr.de>; Thu, 22 Apr 2021 02:58:36 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1619085515; cv=pass;
        d=google.com; s=arc-20160816;
        b=f60bge7/BhCs7eYc7tOPE+7xXx/IKJkLdqbhPJg+8wdB/y59dQSr9MTdhn/vlCG0M1
         4bcvreUtTZIyBtT5zfNY3aVbRMjzJrJMJ6DXsjRHVBRrCw9KoZ4LAjwAJZ47sxYklydX
         Ff1GpcUv/JoLGIwrQNJpvAhoYISo57rRtWhhNlnCsHWQWR7e0ixhtAqvgqb/AxtEByvE
         imW9r9hnDQF1X5MJvIocFWwFwRs/4toz7GSuXD9UQ9/PFmZXNV1UI7oty4CUNzYlbcgZ
         Fa1haiRGUHkyu8mUEDIt69FMYWD5wivi47d0zEg4dJIx02E20FAn0a4RCwv9LgwUprIW
         In7A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=KuLVMhxhYqx4RZYa4d1Yw+oGLqKq/U73QD5nXs3JckY=;
        b=uTzaSo/4GAJAh9uOZJ5eJs9SrHXm3ij8h0gRJEvWYmAyymcga/8yPWU/Oq0pPIqtGc
         cy545f9ss80+rkQvytWAYY2X72BvLQwYUTQRF1X55dxkQ+AujJUy2Pi12d74qJsDPKgQ
         J+bzwsRWuyROGXtEXPt4JcJG4vQUBz3p+hOAlU/XyZ7l8ZJIKNZ5JMuadZ7cGHD/SeO/
         jDz60Xy2HaL+nn8izYpFAysCUOcdyEAkxc9USVK2MXWDgOK5rvAU8k7li7Y4r+MUxJnT
         Dg/72muaXwg0hPlaFkfdOm9FK/mULp9OvCTeli0ODyGq/CcJY6v+HacgnoL34IZ09j9f
         58Yg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=TYedG1fJ;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::82e as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=KuLVMhxhYqx4RZYa4d1Yw+oGLqKq/U73QD5nXs3JckY=;
        b=iiZy/yeu1xcxTbugx9jieBbkz6+Z3QYVTPTkSeFYHc5lDS0PWjGvwDDKx2nXpB/rRO
         AkvrBR4DL1S9DaEGgKpL/YCSmesMtKeB+ovbod5EOm9M61hapVKAHd00ZWd1ex/S9Z2c
         3V1HFzVbAdh9/Mn9A/kNRp/7BW+yQHlGX8nVLEoSwGpl5c0Ewdwb2Cy24Iay0fZN8snS
         jkO4viCS7dOC46jWoNcYLmIY5mBx2joObohkT6zCX2roR2tQDL/f6FYiKVCsiyv90lOA
         ZREzBu73FTrqM1W9aEvbxzaC4ajAq1Qx1prC124OfE6qwSmoNlZECAXlZEB2LTIL6Iwr
         ZUPA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=KuLVMhxhYqx4RZYa4d1Yw+oGLqKq/U73QD5nXs3JckY=;
        b=muJ0SaRFb9nKX0Lf53RYR/FIVL7UCRVf5zSUxkWyQ2Bzopri8ePQbFAGUByA8hDUdh
         Dka3sHot7Yql3YIn2PTUcEEphUe2Lw2sP5MoiV7Y0kLIapKv4Kb0QDP1MlRUHFuelzPq
         SsWS7eUxD49tRjqdJABLyH6FWHy/II2AuGG9BnrnPsltn+Lh/L2tTjiOvB6tkBnohOo3
         SVaC9pNAGHTyBxkMpxNFo34+cLXcBzo1jWDxF8b27gdXMn7K8Edi1TERrAl9HuEbTBvr
         Y/70dyY5yZ1AZ3Y3Zzl35r03smezPlIqXIYuY+Zcw+lWqoV3sFgdf4cRwidkt/k3gJdj
         qdpg==
X-Gm-Message-State: AOAM530AlhSVwJt5T6yb0siN49SIrgp8Jh9l3zGo7+dFFa8ZFInX+V66
	lLTRhn2XmcVBmsTR4tIh/UY=
X-Google-Smtp-Source: ABdhPJwg4hk1IaL+tRtmrHmSNfMEdV0HiZS3N4T0l2uQGlL6yg0yMMrmbXuZecHEyfqLsbfrFFcu0w==
X-Received: by 2002:a63:1d06:: with SMTP id d6mr2691790pgd.202.1619085515369;
        Thu, 22 Apr 2021 02:58:35 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:79d5:: with SMTP id u204ls1997351pfc.9.gmail; Thu, 22
 Apr 2021 02:58:34 -0700 (PDT)
X-Received: by 2002:a63:4848:: with SMTP id x8mr2630887pgk.362.1619085514787;
        Thu, 22 Apr 2021 02:58:34 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1619085514; cv=none;
        d=google.com; s=arc-20160816;
        b=Y0WBg+yL+RDVRaRraBiE1JyJBDZsCzHjSxDtAnA8FOh1o1t3upECmo05rtOsC6fWwS
         +KwpGSU3BGZlEseZInS1DNF2P+TdtCnetggSzvG+MgVc9QyJJC/vIXBNgY5ASwS9aZbR
         K3bMpkd2hlzEBDqQkcLvRmsHN0ALqCGfPBFcU2MjeQEZr6ShwtnlWxLfuAuco7ZP9q9W
         rC8oqOrPkaKn3maasUcGsgA203aDQ7yLUJTMXyxWVPaJaxm6QKBtv6Ntq5gTL2kuXRDd
         WYSC2F+dBJUSUGxQTuZ2yiUCE+wlx627UwnmTaSUXqvaXm82PipeZ8QZEFB4S9NqZ59n
         L9mg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=sVnJbmEkfxXnJEPDJlf6F38sWKPScLpz9CDnrIopbyM=;
        b=ENb0c/kykkg0rhs/zBOkMWNyGcmQZHt4YjNXzKY3pFhMunl/Bl5WmyqjTtT4H+++1M
         N7IXZsXHSooVK6WJwevS1LvPobnw4N7XyuwU+jRhbVvKiP3P3AgyF9cGsAJ88VQFWxKa
         VfmFFb2o1UUHZLzUpYg8XZaYpGbOxEij1T8cHVR+X+F4cZhei6LKOAVXHrV24/NT1Wun
         lvoBSTaXthcmXCSaZAATHJuyeqBjt/K0ankF5EO+Lw2MS5Y59p+bmK/2eBfSV/MwHeLk
         1SIzeMEWiIPUE5wbMEITPedRDST0isypuRugolv6+l5c680Wqtuoog76nIdpgWVoAYl2
         Oulg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=TYedG1fJ;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::82e as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x82e.google.com (mail-qt1-x82e.google.com. [2607:f8b0:4864:20::82e])
        by gmr-mx.google.com with ESMTPS id a8si342092plp.2.2021.04.22.02.58.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 22 Apr 2021 02:58:34 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::82e as permitted sender) client-ip=2607:f8b0:4864:20::82e;
Received: by mail-qt1-x82e.google.com with SMTP id a18so9565744qtj.10
        for <kasan-dev@googlegroups.com>; Thu, 22 Apr 2021 02:58:34 -0700 (PDT)
X-Received: by 2002:ac8:5c92:: with SMTP id r18mr2284877qta.66.1619085513632;
 Thu, 22 Apr 2021 02:58:33 -0700 (PDT)
MIME-Version: 1.0
References: <CGME20210422081531epcas5p23d6c72ebf28a23b2efc150d581319ffa@epcas5p2.samsung.com>
 <1619079317-1131-1-git-send-email-maninder1.s@samsung.com>
In-Reply-To: <1619079317-1131-1-git-send-email-maninder1.s@samsung.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 22 Apr 2021 11:58:22 +0200
Message-ID: <CACT4Y+azDLjbNH0A8_G-yG4qg964f-sGiBNvfatYuTk5aBu9aw@mail.gmail.com>
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
 header.i=@google.com header.s=20161025 header.b=TYedG1fJ;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::82e
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

On Thu, Apr 22, 2021 at 11:17 AM Maninder Singh <maninder1.s@samsung.com> wrote:
>
> when KASAN multishot is ON and some buggy code hits same code path
> of KASAN issue repetetively, it can flood logs on console.
>
> Check for allocaton, free and backtrace path at time of KASAN error,
> if these are same then it is duplicate error and avoid these prints
> from KASAN.
>
> Co-developed-by: Vaneet Narang <v.narang@samsung.com>
> Signed-off-by: Vaneet Narang <v.narang@samsung.com>
> Signed-off-by: Maninder Singh <maninder1.s@samsung.com>
> ---
>  mm/kasan/kasan.h  |  6 +++++
>  mm/kasan/report.c | 67 +++++++++++++++++++++++++++++++++++++++++++++++
>  2 files changed, 73 insertions(+)
>
> diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
> index 78cf99247139..d14ccce246ba 100644
> --- a/mm/kasan/kasan.h
> +++ b/mm/kasan/kasan.h
> @@ -102,6 +102,12 @@ struct kasan_access_info {
>         unsigned long ip;
>  };
>
> +struct kasan_record {
> +       depot_stack_handle_t    bt_handle;
> +       depot_stack_handle_t    alloc_handle;
> +       depot_stack_handle_t    free_handle;
> +};

Hi Maninder,

There is no need to declare this in the header, it can be declared
more locally in report.h.

> +
>  /* The layout of struct dictated by compiler */
>  struct kasan_source_location {
>         const char *filename;
> diff --git a/mm/kasan/report.c b/mm/kasan/report.c
> index 87b271206163..4576de76991b 100644
> --- a/mm/kasan/report.c
> +++ b/mm/kasan/report.c
> @@ -39,6 +39,10 @@ static unsigned long kasan_flags;
>  #define KASAN_BIT_REPORTED     0
>  #define KASAN_BIT_MULTI_SHOT   1
>
> +#define MAX_RECORDS            (200)

s/MAX_RECORDS/KASAN_MAX_RECORDS/

> +static struct kasan_record kasan_records[MAX_RECORDS];

Since all fields in kasan_record are stack handles, the code will be
simpler and more uniform, if we store just an array of handles w/o
distinguishing between alloc/free/access.

> +static int stored_kasan_records;
> +
>  bool kasan_save_enable_multi_shot(void)
>  {
>         return test_and_set_bit(KASAN_BIT_MULTI_SHOT, &kasan_flags);
> @@ -360,6 +364,65 @@ void kasan_report_invalid_free(void *object, unsigned long ip)
>         end_report(&flags, (unsigned long)object);
>  }
>
> +/*
> + * @save_report()
> + *
> + * returns false if same record is already saved.

s/same/the same/

> + * returns true if its new record and saved in database of KASAN.

s/its/it's/
s/database/the database/

> + */
> +static bool save_report(void *addr, struct kasan_access_info *info, u8 tag, unsigned long *flags)
> +{
> +       struct kasan_record record = {0};
> +       depot_stack_handle_t bt_handle;
> +       int i = 0;
> +       const char *bug_type;
> +       struct kasan_alloc_meta *alloc_meta;
> +       struct kasan_track *free_track;
> +       struct page *page;
> +       bool ret = true;
> +
> +       kasan_disable_current();
> +       spin_lock_irqsave(&report_lock, *flags);

Reusing the caller flags looks strange, do we need it?
But also the very next function start_report() also does the same
dance: kasan_disable_current/spin_lock_irqsave. It feels reasonable to
lock once, check for dups and return early if it's a dup.

> +       bug_type = kasan_get_bug_type(info);
> +       page = kasan_addr_to_page(addr);
> +       bt_handle = kasan_save_stack(GFP_KERNEL);

ASsign directly to record.bt_handle.

> +       if (page && PageSlab(page)) {
> +               struct kmem_cache *cache = page->slab_cache;
> +               void *object = nearest_obj(cache, page, addr);

Since you already declare new var in this block, move
alloc_meta/free_track here as well.

> +
> +               alloc_meta = kasan_get_alloc_meta(cache, object);
> +               free_track = kasan_get_free_track(cache, object, tag);
> +               record.alloc_handle = alloc_meta->alloc_track.stack;
> +               if (free_track)
> +                       record.free_handle = free_track->stack;
> +       }
> +
> +       record.bt_handle = bt_handle;
> +
> +       for (i = 0; i < stored_kasan_records; i++) {
> +               if (record.bt_handle != kasan_records[i].bt_handle)
> +                       continue;
> +               if (record.alloc_handle != kasan_records[i].alloc_handle)
> +                       continue;
> +               if (!strncmp("use-after-free", bug_type, 15) &&

Comparing strings is unreliable and will break in future. Compare
handle with 0 instead, you already assume that 0 handle is "no
handle".

> +                       (record.free_handle != kasan_records[i].free_handle))
> +                       continue;
> +
> +               ret = false;
> +               goto done;
> +       }
> +
> +       memcpy(&kasan_records[stored_kasan_records], &record, sizeof(struct kasan_record));
> +       stored_kasan_records++;

I think you just introduced an out-of-bounds write into KASAN, check
for MAX_RECORDS ;)


> +
> +done:
> +       spin_unlock_irqrestore(&report_lock, *flags);
> +       kasan_enable_current();
> +       return ret;
> +}
> +
>  static void __kasan_report(unsigned long addr, size_t size, bool is_write,
>                                 unsigned long ip)
>  {
> @@ -388,6 +451,10 @@ static void __kasan_report(unsigned long addr, size_t size, bool is_write,
>         info.is_write = is_write;
>         info.ip = ip;
>
> +       if (addr_has_metadata(untagged_addr) &&

Why addr_has_metadata check?
The kernel will probably crash later anyway, but from point of view of
this code, I don't see reasons to not dedup wild accesses.

> +               !save_report(untagged_addr, &info, get_tag(tagged_addr), &flags))
> +               return;
> +
>         start_report(&flags);
>
>         print_error_description(&info);
> --
> 2.17.1
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BazDLjbNH0A8_G-yG4qg964f-sGiBNvfatYuTk5aBu9aw%40mail.gmail.com.
