Return-Path: <kasan-dev+bncBCMIZB7QWENRB4GIQDYQKGQEMJFTGUI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43a.google.com (mail-pf1-x43a.google.com [IPv6:2607:f8b0:4864:20::43a])
	by mail.lfdr.de (Postfix) with ESMTPS id 5311213D631
	for <lists+kasan-dev@lfdr.de>; Thu, 16 Jan 2020 09:53:06 +0100 (CET)
Received: by mail-pf1-x43a.google.com with SMTP id d85sf12655146pfd.4
        for <lists+kasan-dev@lfdr.de>; Thu, 16 Jan 2020 00:53:06 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1579164785; cv=pass;
        d=google.com; s=arc-20160816;
        b=p0m3SbX0jaBmvwSZnPx/GARcBthy74wcRnqLMRtQKOOArqNNF7I75rgiU1rL70jtuD
         MdW8sDKLTyBjktxQDAfA+SuN5gd7mGqjY5vsxQGq5JF3PEXi4/u/ofsVjE4fmOrq3QE9
         cljIk1ov1guK9+zH+t03YQ/hAp9GTAjTEV37cQf50KpisHUPhzNC6kZOm+ce16AHpu+G
         Il2bfYjj2BQ9uliPZ8Wk7RNxm1/frxtmYgblWnI7Ytt5X0+MHq8ukUctPDjrvscu4Nfm
         m2ZNfSPELrkAmpuyLKw6r4Dk0rm2LJtFw7YgVgMmwhjryDyD+rMbesgenCJt/WIA1KfV
         O2Gw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=rhQXZxGd2rVI/FsPHi5f/DtPXNtELf8p+j3xJx8HaKM=;
        b=BJ+0ub5rikby9HoqQgMXg5nsDDH3bx6HXKAPH1X9YmK6FZqhTSlQqsaxATd8ajh6O2
         gWlLRcCCy3q1gCa5cjIQ0lXCcdY+yLV7jEpAs4Psn+5QgU2AUjcusX3QcrlhgIPze9iH
         /lE+53J3UBWeZL/eZrQvctGvYAL9qaC8xWj54pmqOqAqg74MMtT5UQXluh/J2noXwNPo
         qtwbMmcrF0m66Z+ZOxEPOY8v0a/IXxNiAl9vaIqoUe2fkEgk5jrAm9Y1I4qsgyccZDFn
         1x+sHBV9dboFwWoC6YGfsJ32vgniaUKdqqCrgZlQbjDBjvxMsfhYOoQAJlak06s8fC/C
         dvlw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Zi64Kg7K;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::842 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=rhQXZxGd2rVI/FsPHi5f/DtPXNtELf8p+j3xJx8HaKM=;
        b=WhUI6a/GL2VVIuTnunxtNTjSFDyOE6q1iNseOiVs7iew7nfuYf0iaO532kgYJUImos
         GHKUC9zhwf8cQh9cARHL1C3NGOPnsNEaZzyy4ErFbQthiK4FPBsNHQzT0KGTE1QD2+k6
         czbyzjvrGdhT22dIOZsUM0gmcs+AsZUQQlXEhLXayRXNvKGkBdVmzSrVoX7E6vF0gWRq
         ZbQAMoj2TDrZMaZlFask+OR+r777WEVSgnbKqqWilIiZZTdPRAgFzIrOMyoL1GxWeh0Y
         Buc9yUUqImdr0eQt8ZAdxfzmjZOnswnPK41o1mdJHF1OOCPDxaTvrFyRwOng59LJ7uYU
         a0cw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=rhQXZxGd2rVI/FsPHi5f/DtPXNtELf8p+j3xJx8HaKM=;
        b=H2DtRpvPYw4tMhqXEOT90whU+R2QfC93la+18Ke+ymnzSq+u/l3EATRRx9HmoE8iH4
         Seqi3i75IBBk9nCHrOCsxZx3EuSv6igYbtg95imw60BGYjnUMB7AW4Lr0u7BjkR8lOtn
         YFUIAHD8CEiEOTyQoB7ncV3DfkoBVbhtVnNUw/kZT1x2K1Z2Qkyvg03luUSEWXsjR+yi
         UHCjc1SDHe9P9AFsR1v7dzX7HHjitdpDFpf3oGBR4eEw5I+SuYKzzK5Uyr8qYalq68jw
         1bjxu5cA+HHbsYCygdqZ0+c+sBPV3K5pPsstsNvvsdfa+FvIYLKXEvC7+hZqI8N0YnMG
         0+ew==
X-Gm-Message-State: APjAAAWcNOponWHCHJiEueXgf8alZbXTJ63rjgDuNxrLJCCk4cOwXIlN
	TslmDTEM+0OxXg38rZWVYDg=
X-Google-Smtp-Source: APXvYqzSeeB7jw8udxUhYQ/FFrkVNaR3snKOFUleR5ufSev2c5DZV/vSkqM5UWg19a3sRt51FWevdQ==
X-Received: by 2002:a63:f5c:: with SMTP id 28mr38693356pgp.348.1579164784926;
        Thu, 16 Jan 2020 00:53:04 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:d207:: with SMTP id a7ls5857709pgg.1.gmail; Thu, 16 Jan
 2020 00:53:04 -0800 (PST)
X-Received: by 2002:a63:770c:: with SMTP id s12mr39466888pgc.25.1579164784528;
        Thu, 16 Jan 2020 00:53:04 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1579164784; cv=none;
        d=google.com; s=arc-20160816;
        b=EtgpB8GpGmFfL/tXuWbo8JgUEM2gjx6eTCK6l6epxJOb+pNvU8Qo1YspE6n72MiFWA
         8GMAQd8Mzceb8fow507oJlTIcgL7qiR5ZKnGuJa+j9i8MmSSdAkTibdE7+5G9hQWJKXL
         fiWYLmDbGDMtVKqwu9rarrdcSRkC2PYWxvLl/uS1WX4e8i+TFp9hduylnBQXPSGXhjxJ
         vQWsq2n+AIlRxo4J3EvZu9ycgRHht9pzSTwUfsk5ACAe4lGeY15aoGPc+GnhXAbVTu9/
         nTv9s2/zQOdQoMUa5hq+rNX1OJlHiZkML0wA63YD8Or4lbHaklJBT6EJyDVYFk2xi7Wk
         EX8A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=lq1lgQepAiLQTChN85kcSpVDrR+IKCYkY9dHTqAQDcM=;
        b=fc/ZDBqzFQjsZ0xKnK93AID9+oEnqeMywcrdXQ/r3wDlKu33X1FVxi8LUIM69aWAvZ
         k/ogbT6ba7gVFZybLchMDUmaUmX27WWy154Au5cntFfcA2iFHbzZSq9rAp0pojjIElhO
         qg2hQ7uWcSJhMkisYmwVZFGy2GDWaMcYlCgP/9bw1KlLWixjXQiV5wCMQ33qWnlaNRB9
         3lehmeMnpLVQ/zBfLjZxavvcBbWi606VGyU8UXXZx5TMJrdWhoguezAHqPptCeTJ5jGA
         FytoDs36Td4grwk1WL3m3pVXuXGaMIihmG3GvV49pkPDhEc92+oJ2JQGlrFZqwg9vqi4
         uoug==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Zi64Kg7K;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::842 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x842.google.com (mail-qt1-x842.google.com. [2607:f8b0:4864:20::842])
        by gmr-mx.google.com with ESMTPS id w2si754727pgt.2.2020.01.16.00.53.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 16 Jan 2020 00:53:04 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::842 as permitted sender) client-ip=2607:f8b0:4864:20::842;
Received: by mail-qt1-x842.google.com with SMTP id d18so18248804qtj.10
        for <kasan-dev@googlegroups.com>; Thu, 16 Jan 2020 00:53:04 -0800 (PST)
X-Received: by 2002:ac8:24c1:: with SMTP id t1mr1305434qtt.257.1579164783430;
 Thu, 16 Jan 2020 00:53:03 -0800 (PST)
MIME-Version: 1.0
References: <20200115182816.33892-1-trishalfonso@google.com>
In-Reply-To: <20200115182816.33892-1-trishalfonso@google.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 16 Jan 2020 09:52:52 +0100
Message-ID: <CACT4Y+b4+5PQvUeeHi=3g0my0WbaRaNEWY3P-MOVJXYSO7U5aA@mail.gmail.com>
Subject: Re: [RFC PATCH] UML: add support for KASAN under x86_64
To: Patricia Alfonso <trishalfonso@google.com>
Cc: Jeff Dike <jdike@addtoit.com>, Richard Weinberger <richard@nod.at>, anton.ivanov@cambridgegreys.com, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, David Gow <davidgow@google.com>, 
	Brendan Higgins <brendanhiggins@google.com>, linux-um@lists.infradead.org, 
	kasan-dev <kasan-dev@googlegroups.com>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=Zi64Kg7K;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::842
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

> +void kasan_init(void)
> +{
> +       kasan_map_memory((void *)KASAN_SHADOW_START, KASAN_SHADOW_SIZE);
> +
> +       // unpoison the kernel text which is form uml_physmem -> uml_reserved
> +       kasan_unpoison_shadow((void *)uml_physmem, physmem_size);
> +
> +       // unpoison the vmalloc region, which is start_vm -> end_vm
> +       kasan_unpoison_shadow((void *)start_vm, (end_vm - start_vm + 1));
> +
> +       init_task.kasan_depth = 0;
> +       pr_info("KernelAddressSanitizer initialized\n");
> +}

Was this tested with stack instrumentation? Stack instrumentation
changes what shadow is being read/written and when. We don't need to
get it working right now, but if it does not work it would be nice to
restrict the setting and leave some comment traces for future
generations.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2Bb4%2B5PQvUeeHi%3D3g0my0WbaRaNEWY3P-MOVJXYSO7U5aA%40mail.gmail.com.
