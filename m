Return-Path: <kasan-dev+bncBC7OBJGL2MHBBOMG36UQMGQEUL2LIRY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb40.google.com (mail-yb1-xb40.google.com [IPv6:2607:f8b0:4864:20::b40])
	by mail.lfdr.de (Postfix) with ESMTPS id 7168C7D512D
	for <lists+kasan-dev@lfdr.de>; Tue, 24 Oct 2023 15:14:35 +0200 (CEST)
Received: by mail-yb1-xb40.google.com with SMTP id 3f1490d57ef6-da03ef6fc30sf639702276.0
        for <lists+kasan-dev@lfdr.de>; Tue, 24 Oct 2023 06:14:35 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1698153274; cv=pass;
        d=google.com; s=arc-20160816;
        b=UH3kSyTd07ugv+lHDHbdSw8FFIhQmocoTLLEvfGBwuV4mznfS72R8YTsNEZyRA5kAP
         W7eAKziob5dZUJY8KePffAUqQI8/GKzwyhr3iiCzgNNScZgcd1OVsQrWCktcp/FG/gRs
         Y8JKkuNHaUlxSRft9hzWa+t9fuUVgLzFr/uAiYBkajQhOfyXERbJUT4coEWdftemEwPG
         mrQg8+OC60H5iD09xHlLdSetjZJKhTVlhyFUGNDT6Q/GwXmx0ZzMvNj9JnTdjeBfYYy/
         brdobngV89Ecykz4H5ajl/jHV3iIQRvGbFB92K2Ow0T8rHAnUsMVngowD6rusLmYF09j
         +mQw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=5TBXq3rk2ImPdMgOWhNcU2LfO9wCFnjIR61iadvI50U=;
        fh=3EgVQPQxbxv+XfZ2sWOggyb2K8Rxmj6Eg9mP1jVgo94=;
        b=ZDg3ue1YCNBbnuE+vZn6CXinuwIqeDARKD5aMAm/g0rY6S3Vc4/JUxj9iWCc033nHa
         Xel+DDVuSoIzfdMzQT1/d2R97d0xnJKNY+1Oq3aQBNnyPfJ08Lb3EAgtiZch2x7N9mXo
         w2P8z/r3lwAhVE6TjH7hyXzf4XIK0Xy39hoyi9kcMFyaWe9DD0HMGPpb6IWxlEgnfiUs
         wRTcp1pyH9oCwnJalkD2fGy3KClziEOg0PIb0CkrZdB2B/8cZna6FVxsZ5sOPvcs5Pab
         L3XwLPgU1AuVczVP3dQ2r984DEuksKG2wpzSfnCgdjYRsHLKsPu+LNPss2GJ7QGWVa2T
         ywuQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=0i1IF+4g;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::231 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1698153274; x=1698758074; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=5TBXq3rk2ImPdMgOWhNcU2LfO9wCFnjIR61iadvI50U=;
        b=OajsvM+bqxA02G5KMK5BEsSrdNp954eD9mn63Hl+vVOvZ3dFakEkd4atTis3EWoAaP
         X4T5hmMVhLu3jNxULGRCrDrwfxnRsDi37T/E413hlOJetTyyT9NPoJZcn4poS9kn4XvJ
         BNdgYKmYX3dQ3jTEE6i1lzpjVuqsM4l51U5pehr4V3I4yxpqsIlCDY3Zbg2GN9WKpa39
         33AQLn1zoYkjVlNPEplD3+NygVpPdWPMW6cGBJAkK1PShCiIFTi36aqkSDPn28MnuOUR
         0sp6w0ViGAbhJzMH6EFtJhSKsimOWxWumx0GSM5viLedUfXXbXGtqElCKB6M5RQuN72R
         EbQA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1698153274; x=1698758074;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=5TBXq3rk2ImPdMgOWhNcU2LfO9wCFnjIR61iadvI50U=;
        b=QLae2SW4BO1T8fcrJvKnvdwo5mJvsnk1AIcDTooPIOm7AzNXjDwM7Sn5R6012soYdi
         tYcgstvuhOGDdxOrWQoV9l+IO2BB0JOF4z6AhDkmCxmurKdvgb0f0M2l0fWp+uho+KWR
         T45/icQ/PK4KpCAetMbatgrn7uWrzBCDYuwGjhA4hE3gUOEU8/ZEMPdO5uyud/9gS9QN
         b95oWqI8T8Bb0DPs7px89DzjzDElh08qIHpK+k4Z4bh0xPD+AlKa4jR036YoFChNAc41
         wj6fKcHlDuCWDm+triFckb8c7roUo7+/rLcqXy4KVK8K1qKSt554rKAlmXr/DOJHCV+x
         8zFQ==
X-Gm-Message-State: AOJu0Yw0NeM2VIPfw31h7seUZvEhPC/STW3cwDDK/xq5eeD8oW7ddxCl
	AN8RtWDpHKWCj5uabVpcCPM=
X-Google-Smtp-Source: AGHT+IE/HLEa1+fCwGPReIQJlz2S5/M0jynij2CSTUV2gMleuRaygvxB+R2h41PFhXSdvb920+QTig==
X-Received: by 2002:a25:51c3:0:b0:d9b:b6:ad72 with SMTP id f186-20020a2551c3000000b00d9b00b6ad72mr12087567ybb.50.1698153273914;
        Tue, 24 Oct 2023 06:14:33 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:7755:0:b0:d86:29c:2155 with SMTP id s82-20020a257755000000b00d86029c2155ls1526796ybc.2.-pod-prod-01-us;
 Tue, 24 Oct 2023 06:14:33 -0700 (PDT)
X-Received: by 2002:a05:690c:dca:b0:5a8:a04:2c8f with SMTP id db10-20020a05690c0dca00b005a80a042c8fmr16325887ywb.2.1698153272813;
        Tue, 24 Oct 2023 06:14:32 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1698153272; cv=none;
        d=google.com; s=arc-20160816;
        b=cJWkHo6OWJ9MXcKlSXrxM1eW076lzFExV/lZq9Jujigi41e0/vEJr60AI/VmJb1kBV
         ZrvgWyJ5cbUTroc5ZVPl1hrsBRvBpOywCmjMSCXrl46e85le4eZ8HFQZYR83K9DKhs6P
         cPR69M9qe/bCs7nD8fHrQkmKoA//jZ6hBW1YNEsFoK9LXixiZe9dZ3JHymriHdtiNCJI
         Nx0d+gjysk0iqhm2sK4MHC9FISPtnJw3nDlXCnU6kohQrYl+Bt4HyIx6gSTM/gR40/o1
         hFsWtviavLpOKphISjcZPl5ECvD5vVZCeJh/qmYaRmVyZqM/wfT3R8Chnr6CJhzt9XXx
         0FUw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=nEr9urFwA/XFdZ4nlXaG4cbFnHUMhCkx9szJZ37Mwg4=;
        fh=3EgVQPQxbxv+XfZ2sWOggyb2K8Rxmj6Eg9mP1jVgo94=;
        b=ohbBhthruC8pniOLOdcWRYa+Pj0abXB0ghwI6c0hPF27ikH5+Pboes5Ddf9FJWPToa
         /o9Vwcd00N+1UeXrhzh6drND4yDjLbBzoFpMmuSvXnLo/7ISo0rlEejKzdSOp7vEnqjn
         TytM4fMbclUhXf4eZU8d9ai5NlyYx6ml5Lh8y7TYKINjmje2rWjwI1jjKsQMWxBuCwpE
         A2RMuE8QAZkdhovjcPkq8NEkQq8zg5hwWbU+rPDVfFawo9/itJpOyXDHtsplwmQ6rZco
         6+XgZxZPoLeWLz1f1my21dNDiKY3bXMa0++GUe/6CbUfVmYbZaLbALLbiwTRJpUG0NfU
         Rc+g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=0i1IF+4g;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::231 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x231.google.com (mail-oi1-x231.google.com. [2607:f8b0:4864:20::231])
        by gmr-mx.google.com with ESMTPS id dg10-20020a05690c0fca00b005a7d90c26a7si142002ywb.1.2023.10.24.06.14.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 24 Oct 2023 06:14:32 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::231 as permitted sender) client-ip=2607:f8b0:4864:20::231;
Received: by mail-oi1-x231.google.com with SMTP id 5614622812f47-3b2ec9a79bdso3223604b6e.3
        for <kasan-dev@googlegroups.com>; Tue, 24 Oct 2023 06:14:32 -0700 (PDT)
X-Received: by 2002:aca:d12:0:b0:3a7:6ff5:c628 with SMTP id
 18-20020aca0d12000000b003a76ff5c628mr13328519oin.11.1698153272314; Tue, 24
 Oct 2023 06:14:32 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1698077459.git.andreyknvl@google.com>
In-Reply-To: <cover.1698077459.git.andreyknvl@google.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 24 Oct 2023 15:13:54 +0200
Message-ID: <CANpmjNNoJQoWzODAbc4naq--b+LOfK76TCbx9MpL8+4x9=LTiw@mail.gmail.com>
Subject: Re: [PATCH v3 00/19] stackdepot: allow evicting stack traces
To: andrey.konovalov@linux.dev
Cc: Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com, 
	Evgenii Stepanov <eugenis@google.com>, Oscar Salvador <osalvador@suse.de>, 
	Andrew Morton <akpm@linux-foundation.org>, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=0i1IF+4g;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::231 as
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

On Mon, 23 Oct 2023 at 18:22, <andrey.konovalov@linux.dev> wrote:
[...]
> ---
>
> Changes v2->v3:
> - Fix null-ptr-deref by using the proper number of entries for
>   initializing the stack table when alloc_large_system_hash()
>   auto-calculates the number (see patch #12).
> - Keep STACKDEPOT/STACKDEPOT_ALWAYS_INIT Kconfig options not configurable
>   by users.
> - Use lockdep_assert_held_read annotation in depot_fetch_stack.
> - WARN_ON invalid flags in stack_depot_save_flags.
> - Moved "../slab.h" include in mm/kasan/report_tags.c in the right patch.
> - Various comment fixes.
>
> Changes v1->v2:
> - Rework API to stack_depot_save_flags(STACK_DEPOT_FLAG_GET) +
>   stack_depot_put.
> - Add CONFIG_STACKDEPOT_MAX_FRAMES Kconfig option.
> - Switch stack depot to using list_head's.
> - Assorted minor changes, see the commit message for each path.
>
> Andrey Konovalov (19):
>   lib/stackdepot: check disabled flag when fetching
>   lib/stackdepot: simplify __stack_depot_save
>   lib/stackdepot: drop valid bit from handles
>   lib/stackdepot: add depot_fetch_stack helper
>   lib/stackdepot: use fixed-sized slots for stack records

1. I know fixed-sized slots are need for eviction to work, but have
you evaluated if this causes some excessive memory waste now? Or is it
negligible?

If it turns out to be a problem, one way out would be to partition the
freelist into stack size classes; e.g. one for each of stack traces of
size 8, 16, 32, 64.

>   lib/stackdepot: fix and clean-up atomic annotations
>   lib/stackdepot: rework helpers for depot_alloc_stack
>   lib/stackdepot: rename next_pool_required to new_pool_required
>   lib/stackdepot: store next pool pointer in new_pool
>   lib/stackdepot: store free stack records in a freelist
>   lib/stackdepot: use read/write lock

2. I still think switching to the percpu_rwsem right away is the right
thing, and not actually a downside. I mentioned this before, but you
promised a follow-up patch, so I trust that this will happen. ;-)

>   lib/stackdepot: use list_head for stack record links
>   kmsan: use stack_depot_save instead of __stack_depot_save
>   lib/stackdepot, kasan: add flags to __stack_depot_save and rename
>   lib/stackdepot: add refcount for records
>   lib/stackdepot: allow users to evict stack traces
>   kasan: remove atomic accesses to stack ring entries
>   kasan: check object_size in kasan_complete_mode_report_info
>   kasan: use stack_depot_put for tag-based modes
>
>  include/linux/stackdepot.h |  59 ++++--
>  lib/Kconfig                |  10 +
>  lib/stackdepot.c           | 418 ++++++++++++++++++++++++-------------
>  mm/kasan/common.c          |   7 +-
>  mm/kasan/generic.c         |   9 +-
>  mm/kasan/kasan.h           |   2 +-
>  mm/kasan/report_tags.c     |  27 +--
>  mm/kasan/tags.c            |  24 ++-
>  mm/kmsan/core.c            |   7 +-
>  9 files changed, 365 insertions(+), 198 deletions(-)

Acked-by: Marco Elver <elver@google.com>

The series looks good in its current state. However, see my 2
higher-level comments above.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNNoJQoWzODAbc4naq--b%2BLOfK76TCbx9MpL8%2B4x9%3DLTiw%40mail.gmail.com.
