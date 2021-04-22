Return-Path: <kasan-dev+bncBC7OBJGL2MHBB7VXQSCAMGQEWWJTAWA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23a.google.com (mail-oi1-x23a.google.com [IPv6:2607:f8b0:4864:20::23a])
	by mail.lfdr.de (Postfix) with ESMTPS id 9DBB2367A21
	for <lists+kasan-dev@lfdr.de>; Thu, 22 Apr 2021 08:47:27 +0200 (CEST)
Received: by mail-oi1-x23a.google.com with SMTP id z200-20020aca4cd10000b02901865d9b3b3bsf6060551oia.3
        for <lists+kasan-dev@lfdr.de>; Wed, 21 Apr 2021 23:47:27 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1619074046; cv=pass;
        d=google.com; s=arc-20160816;
        b=IQhMqMaPAJySLl0uPrYOY+kcIqk5dXhmAqrkDmmhGOXHQbEvsMWZO7+xpvHmlDBlXR
         q4EjGRiKklY0ayI296hEj7QchD3QsZIkJrA3ArGRfbWunMp+Thg7ZrOSa1+0c7xvLgi6
         4CZGyS0FspxrqaY/am6K28s7KzszpyGfuzry0a1Nycph8g0kZMZ9r5ZkW+jGOP5x2B+k
         J0/sfJgZ1bihaMzqa6ORy916yNzWHHS47cNiBvXbvnUZijBGlQlQae2ndHdxfSnqRD00
         osUJhvrJ2GTjjtEZf9h4WP8qDDewLEFmGOF4FtsCXuav9UuqOYass/ehcHesoaDCNHZB
         4wcQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=PHvL/VAf5qRYfUARx3W6LQyIa0fyMJ0GlZh7hFJJ5LE=;
        b=z87+Pv0KxhyI1bjusJGy2ggB68l1yMbJfcZSWtbqYpgEjgDtOQbbgwOkdL7wUO8qxL
         JGpDkH4M08DFYDa99+A5QLh7CROmXBdkRPgEoO6lX75E1p+vK3EHNDmWMB3CSZg/fkLR
         IifujmgqtjhdxDVaWo0MQLpKvwzbkUxQ6kTH/JtaW37mgFRgSbROdDQw3vvPc2CPnLZO
         gmWALaOJ1KuboCZZRlk5+e/ChYrKMNLUkUzkeVPIHrrAEaOjQnDtdG9RUvwGJrNvUPGP
         Vlw3M9T7/Di2de1WepPgxj4kPwMSm0OQDRlh+W7cZaJ7IOoPqqzh23MNxJVsKIBdDrm8
         aCsQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="lA/wdfNn";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::233 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=PHvL/VAf5qRYfUARx3W6LQyIa0fyMJ0GlZh7hFJJ5LE=;
        b=fjNXSh9gTPKI9xrEtwm5cWMLcBI29wVmZXOKTC/Oe1xpO1iinUs2PNi5wVX8S5CLFu
         6vyMbakt+MA9jKpz2w7FXEJPy42yGcNv1RstHTary03HNLKCC0mgAyfbTyh0PAFVzNmx
         I4dwvJdxgQXpMrBkgZFe7zg3q+99gZ8C3QGYOMp9E5qEblQFTLPjJTiZN939bH74wWLI
         Zl+Q9W7ZpO3bA4cEI/iqVceWhJgVldqPlXBwhu6A9Tud5tb1Slomii3L7Wq8Fghj/vSM
         8YUc4pFFCU3Q+Recn2g/8/RLYT0Qk3CjM39n9/PY2QPmI9xJPEQbEGsaWve5w6B4K0V2
         z0bA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=PHvL/VAf5qRYfUARx3W6LQyIa0fyMJ0GlZh7hFJJ5LE=;
        b=tNje1yzB/A2ZmmIGVCCmn9eafy4w991RwtehXj0vGImc70qxeVBsUDnWheajsc7yjm
         DncMJ+bFCE6l+JBw1ZRymDhw5cNpYL8kFGUa7b7bWLVrcr4GVNB0idxAbT38OcQFaHAl
         eCcOJTtzl5GxpsT/3CtYPbw8SWaa26iwQI6ogube5oan1giKwjPzwEGVU20bhGz+TEQ3
         SysQtts5BJMe7LRm+vRCrGgH0pOmd1HepLpkAplfTkts8n/H/HFuQugxE5aA98K/yndU
         q2NqxQXInV+cBzev8rQ9IiUh0cRGBRQwO7kJnpPmY8ZEZ/M3WFOgEDwyrofHwKQfIiOJ
         EHNg==
X-Gm-Message-State: AOAM532y+I4LoHyP6f0ZS3vPXM8swlGJXebVo0RvZeG5sXSr1VEmqqVl
	vibIkjZXteJBNXuts/MACx4=
X-Google-Smtp-Source: ABdhPJy5+ZqsreGKBLnTJqKGjL0Y9LJhdicLbuM1kzF8OCiHinWC9cVKb/FcYwgGR4sjOiU0st8n0g==
X-Received: by 2002:a9d:7583:: with SMTP id s3mr1576942otk.367.1619074046666;
        Wed, 21 Apr 2021 23:47:26 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:6852:: with SMTP id c18ls1285590oto.11.gmail; Wed, 21
 Apr 2021 23:47:26 -0700 (PDT)
X-Received: by 2002:a9d:60c8:: with SMTP id b8mr1605138otk.67.1619074046320;
        Wed, 21 Apr 2021 23:47:26 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1619074046; cv=none;
        d=google.com; s=arc-20160816;
        b=owk+uugBuUGuSI5UK0YC7b4AChHW15X4TWZsLWUZ/GPJKGONASu/voSkEBVa0kXV7l
         Iw9sq8S0tpDVk9w8BFxu1Qpzt+pi5/2tYMyizkXPpKdHrI7luvKgKLCiRGLUzLGZekRR
         b+2wNwTbFYOnphektNubADS7TMtJp17r3ic6F1VJmxaTXHEYMZy9IxrH4kfyEBqeocud
         H+w3K1U9pMQbkI30YcczGJ0HbXjS3aslh37bKZEYiEBW3oYGgHbca/yLrzYr82Ic3PSy
         MIWoEb3S5H9juIB+NKnTHi3ctusBnicQasuzzR3ib4QBMGEDqR/Lfnv9B/YW7+H6Z49k
         rwZw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=wTjjN5jAG5wIij1DihAnfF2YGoCBK9l6YKfTSDtQuuw=;
        b=ZFgO+YwexNDzKQ3hEUcpdLBVnkQAEypzY4UrH9JfquVSuYaXQ0HTQHzWQvfBzGB2mB
         pb3dpQlWWwjGnTSqaOUD7KmAiwJ0IiW0UrwX7TpEsKPAS3Gi4rREwa+NFKmh/GBZ1oai
         PIkIn31xYc9qTM86IZX8xbQPpc1heAgalSH1PchnLbPksgbRI1Y5wTJUXfAeNbEugU9D
         zqYyOI9EHM+JSJQF7PCXb5osNStgutsjZVD8OWVCHolCQeBuE+xGo+/RtQ+UIQyEBvBg
         GlkGvvB5gfVAHlYRH1Ukmx+tWSUIVKU3UpeyYJly2P2+Zpacy5nkZN6+eRhbOSDlcDh0
         Y7bA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="lA/wdfNn";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::233 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x233.google.com (mail-oi1-x233.google.com. [2607:f8b0:4864:20::233])
        by gmr-mx.google.com with ESMTPS id t25si355013otc.4.2021.04.21.23.47.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 21 Apr 2021 23:47:26 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::233 as permitted sender) client-ip=2607:f8b0:4864:20::233;
Received: by mail-oi1-x233.google.com with SMTP id v6so17048269oiv.3
        for <kasan-dev@googlegroups.com>; Wed, 21 Apr 2021 23:47:26 -0700 (PDT)
X-Received: by 2002:aca:408a:: with SMTP id n132mr1231205oia.70.1619074045847;
 Wed, 21 Apr 2021 23:47:25 -0700 (PDT)
MIME-Version: 1.0
References: <CANpmjNM8wEJngK=J8Lt9npkZgrSWoRsqkdajErWEoY_=M1GW5A@mail.gmail.com>
 <43f8a3bf-34c5-0fc9-c335-7f92eaf23022@samsung.com> <dccaa337-f3e5-08e4-fe40-a603811bb13e@samsung.com>
 <CANpmjNP6-yKpxHqYFiA8Up-ujBQaeP7xyq1BrsV-NqMjJ-uHAQ@mail.gmail.com>
 <740077ce-efe1-b171-f807-bc5fd95a32ba@samsung.com> <f114ff4a-6612-0935-12ac-0e2ac18d896c@samsung.com>
 <CANpmjNM6bQpc49teN-9qQhCXoJXaek5stFGR2kPwDroSFBc0fw@mail.gmail.com>
 <cf6ed5cd-3202-65ce-86bc-6f1eba1b7d17@samsung.com> <CANpmjNPr_JtRC762ap8PQVmsFNY5YhHvOk0wNcPHq=ZQt-qxYg@mail.gmail.com>
 <YIBSg7Vi+U383dT7@elver.google.com> <CGME20210421182355eucas1p23b419002936ab5f1ffc25652135cc152@eucas1p2.samsung.com>
 <YIBtr2w/8KhOoiUA@elver.google.com> <dd99b921-3d79-a21f-8942-40fa5bf53190@samsung.com>
In-Reply-To: <dd99b921-3d79-a21f-8942-40fa5bf53190@samsung.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 22 Apr 2021 08:47:13 +0200
Message-ID: <CANpmjNPbMOUd_Wh5aHGdH8WLrYpyBFUpwx6g3Kj2D6eevvaU8w@mail.gmail.com>
Subject: Re: [PATCH v4 05/10] signal: Introduce TRAP_PERF si_code and si_perf
 to siginfo
To: Marek Szyprowski <m.szyprowski@samsung.com>
Cc: Peter Zijlstra <peterz@infradead.org>, 
	Alexander Shishkin <alexander.shishkin@linux.intel.com>, 
	Arnaldo Carvalho de Melo <acme@kernel.org>, Ingo Molnar <mingo@redhat.com>, Jiri Olsa <jolsa@redhat.com>, 
	Mark Rutland <mark.rutland@arm.com>, Namhyung Kim <namhyung@kernel.org>, 
	Thomas Gleixner <tglx@linutronix.de>, Alexander Potapenko <glider@google.com>, 
	Al Viro <viro@zeniv.linux.org.uk>, Arnd Bergmann <arnd@arndb.de>, 
	Christian Brauner <christian@brauner.io>, Dmitry Vyukov <dvyukov@google.com>, Jann Horn <jannh@google.com>, 
	Jens Axboe <axboe@kernel.dk>, Matt Morehouse <mascasa@google.com>, 
	Peter Collingbourne <pcc@google.com>, Ian Rogers <irogers@google.com>, Oleg Nesterov <oleg@redhat.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, linux-arch <linux-arch@vger.kernel.org>, 
	linux-fsdevel <linux-fsdevel@vger.kernel.org>, LKML <linux-kernel@vger.kernel.org>, 
	"the arch/x86 maintainers" <x86@kernel.org>, 
	"open list:KERNEL SELFTEST FRAMEWORK" <linux-kselftest@vger.kernel.org>, Geert Uytterhoeven <geert@linux-m68k.org>, 
	Bartlomiej Zolnierkiewicz <b.zolnierkie@samsung.com>, Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	linux-tegra@vger.kernel.org, jonathanh@nvidia.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="lA/wdfNn";       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::233 as
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

On Thu, 22 Apr 2021 at 08:12, Marek Szyprowski <m.szyprowski@samsung.com> wrote:
[...]
> > So I think we just have to settle on 'unsigned long' here. On many
> > architectures, like 32-bit Arm, the alignment of a structure is that of
> > its largest member. This means that there is no portable way to add
> > 64-bit integers to siginfo_t on 32-bit architectures.
> >
> > In the case of the si_perf field, word size is sufficient since the data
> > it contains is user-defined. On 32-bit architectures, any excess bits of
> > perf_event_attr::sig_data will therefore be truncated when copying into
> > si_perf.
> >
> > Feel free to test the below if you have time, but the below lets me boot
> > 32-bit arm which previously timed out. It also passes all the
> > static_asserts() I added (will send those as separate patches).
> >
> > Once I'm convinced this passes all others tests too, I'll send a patch.
>
> This fixes the issue I've observed on my test systems. Feel free to add:
>
> Reported-by: Marek Szyprowski <m.szyprowski@samsung.com>
>
> Tested-by: Marek Szyprowski <m.szyprowski@samsung.com>

Thank you for testing! It's been sent:
https://lkml.kernel.org/r/20210422064437.3577327-1-elver@google.com

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNPbMOUd_Wh5aHGdH8WLrYpyBFUpwx6g3Kj2D6eevvaU8w%40mail.gmail.com.
