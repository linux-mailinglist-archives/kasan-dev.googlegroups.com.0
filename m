Return-Path: <kasan-dev+bncBDV37XP3XYDRBZ5F5GPAMGQEKFBZUJY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33b.google.com (mail-wm1-x33b.google.com [IPv6:2a00:1450:4864:20::33b])
	by mail.lfdr.de (Postfix) with ESMTPS id 3CCD468659C
	for <lists+kasan-dev@lfdr.de>; Wed,  1 Feb 2023 12:54:16 +0100 (CET)
Received: by mail-wm1-x33b.google.com with SMTP id j24-20020a05600c1c1800b003dc4480f7bdsf944642wms.5
        for <lists+kasan-dev@lfdr.de>; Wed, 01 Feb 2023 03:54:16 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1675252455; cv=pass;
        d=google.com; s=arc-20160816;
        b=E9ND0YJDszw7T0zpJBNRBsVTZ2BJfzuyFLdJSFymylNcgdE9pA1p5cZaPih6gApR7X
         k+tNfm5miglMUlOM7jvZhMWAFQ2SHPQsSnTRgbWWRqWPGAVAGxkcLcVJkxRPfOYmxlC+
         gC0g+wn05aTxdJZKekc7NyBf9xuznz9z701rRISVoNcJJ/6reJVdtwYcFLkCL9EuIeOY
         Iz+Q9meyp+t82Z+uq6eWhw6+sIfPGDg1PHjfedtChSEgjE8n25YWdfeCBIILCVXF0ZOR
         SH3YZeIkXOUzr1x9EVhlETVlTOVt5KKWX5HuUmf2+XSn0dnZmLj0HYT6+UpObDDepMTn
         5C+A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=vKj7U8PRK4kpaKclLIXPfDbSKFJGc/TkuEMrPfG5rAg=;
        b=SGGnPwOSoffoPfAhfs/5pE8l3+EiFGH3ommZG2cupeGPSlLZm8ySsibNvnb2TohV7X
         nEHnB1VSaRL95Gmoz5O1K4cH/wPaAEVJ9fKSoVgsXDacWVO78BSHS0nNB/SiQ0FTnb0D
         hdytdHd/63JtMNAXAQC7i8W7SjcUj/Zembln0jd6UMCmhnuVbXsDhCkM+OfLOiDS/nSJ
         s+vrLxpPvLpOUyElancg4a6ILNDfZlHdZIJ3QAMdxRYsXimYhaIWSUtkKytDmSER1DjH
         3h2qVDUNaYvoCqpHpu4oIKOuX1pmEDtUy7wbhf0ajaeFdHvssGNZuMJpmQbHFbCmD5RM
         mOYQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=vKj7U8PRK4kpaKclLIXPfDbSKFJGc/TkuEMrPfG5rAg=;
        b=cBek6s+K6euNPRR5Uf/ftsD9waPm57J4JWGOd1X3ggAmko4uHa0ShxLmLEkr+O7I2m
         x8GqZiONOg/Iz/eSPEeXatzal5NV96hb1RUOe4IiD12+KUAqBFjCiXoPGqG/o9dyLRcQ
         m2p/7mK/F0Qd7lLq3hYTUcs/44X+v4nwUyPCipgTpAvUMBdFr4B8yZSOikSHtz3U18oe
         KpZFiKhHmPNQuEijYObgGkPFRUYmcAiBGvtJXY1hVIpjUFHorfC4rHrWlWaPKM1u3zFh
         gFSGRsYsZ6MQDZ4UmgkmgcWbLDmMFf+1Y5PGWkJTXlukKmHYMx1qO+hyATpnrrrnNtdU
         C5+Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=vKj7U8PRK4kpaKclLIXPfDbSKFJGc/TkuEMrPfG5rAg=;
        b=L9PUE+tsi+OoB+kioZ5taaon4ThwBXKBTeD3+3yOuPBH/EcG4nw5JXUXrGcvGsFEwi
         MQafGP6g4DUMPK+818uiyd+ri3aFnCnJRDFnCytyilDNBeSqmfqukQYRPLGjCdUTvsGh
         Wv3El5M1CHFlmCZjMTD7JHkUNVapeQB6UCSqny9jA5Dj8Qd2M+O0471Y3eovJbyrE3Qm
         M62d6Jtha17wIv26SAn5lt+/2X/DpsROX+7VNct6yQxt9ejhUCrqG0u45a11oIIjZEXW
         VKlSaWSb/+vUODb6mzf33u5ZP7jnZkpEqYtyB6NDj0wcQU6YQHfIVvCruNRHxD7EIU98
         h/pw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKUctpPE7zHPIF9oz6i7rtN4l6NhPE4qMq8Gb49LKmwRkK0b1WSZ
	MWv8ex8l7aLQ+n3pSA3xxcs=
X-Google-Smtp-Source: AK7set8mG67X6QitwU++BLQx7j/dTvHtUOWpGK5PAs1uzl6hCqUEN/YRBw8FPNjK9aF8bXcgNWwRaw==
X-Received: by 2002:adf:f752:0:b0:2bf:af2f:8961 with SMTP id z18-20020adff752000000b002bfaf2f8961mr105898wrp.700.1675252455669;
        Wed, 01 Feb 2023 03:54:15 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:e449:0:b0:2be:34f5:ab03 with SMTP id t9-20020adfe449000000b002be34f5ab03ls290162wrm.3.-pod-prod-gmail;
 Wed, 01 Feb 2023 03:54:14 -0800 (PST)
X-Received: by 2002:a5d:5904:0:b0:2bf:b9f2:6f88 with SMTP id v4-20020a5d5904000000b002bfb9f26f88mr1455150wrd.33.1675252454277;
        Wed, 01 Feb 2023 03:54:14 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1675252454; cv=none;
        d=google.com; s=arc-20160816;
        b=JH65ZcoUALCeLKk8DnBZG5igsOQHh+gOC8KvGHsPmTnd5sbNDP2BD8DB3mp/dzbNsX
         yvUPGv/ovtDvDmdAnVMtWQrq0haV6mfZAg4Z3TWbbs7FFqvn46iCbTm2ERbbxjhRZdXz
         31rCs/D/SYXdBxcWU40agQy1SoQ9VGTTTrRqHLRF9rCWUxSyLnESckZO1z5rtui7YRCv
         cqcL3pQa1MhNaO+Ld7UAQ88iKhnZLZ0ox52KW/y5R1fSQts8X/lsZFyqWyeAKcqWbK8j
         JlakqgYb07o2AGLuKTGjTOyCNKpcecckmYbRaK2UhwoG8/2kMdLK5A9WjbpkfHw9UBdm
         0Utg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date;
        bh=0LIBiuHXUmS0FjTfaxmY6167SkFjwchVXpef0Sdc2DI=;
        b=lebhb6xrVDdfZYrMMTfBqAY16M/CLMIS0wmJfGQTMdm/NiK6B4weqtsqKAQOhYLPAw
         9YqK9IMz7VoFfJMWTWhaFYvacVf45CD1Q5LDhjGTXQfTd/0E0rS4amhAybSfAk1+Xnbf
         gejX/q72dylf5qQVbLOE4NovxKgpmfuoHycLqCBRaqRTaaiLVdKWlfAxIdBA/uBCvmoK
         4JJc9E12F2OiQIhFOAE+2l0OVbjBGVfsMdf5hrNMONS2kHZ4r+Z65RR4gY1I2uK+T5Pd
         PDCcNtYQzjGD6iCuoHRATjXaSSiv/DRY+jEBOeHQAylUmEaGGjFbTTpD3Oq2d7rIuJBI
         Dhyg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id l15-20020a5d6d8f000000b002be1052742esi762521wrs.4.2023.02.01.03.54.14
        for <kasan-dev@googlegroups.com>;
        Wed, 01 Feb 2023 03:54:14 -0800 (PST)
Received-SPF: pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 8B95A4B3;
	Wed,  1 Feb 2023 03:54:55 -0800 (PST)
Received: from FVFF77S0Q05N (unknown [10.57.12.10])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 3FB993F882;
	Wed,  1 Feb 2023 03:54:11 -0800 (PST)
Date: Wed, 1 Feb 2023 11:54:08 +0000
From: Mark Rutland <mark.rutland@arm.com>
To: Dmitry Vyukov <dvyukov@google.com>
Cc: Marco Elver <elver@google.com>, Peter Zijlstra <peterz@infradead.org>,
	Ingo Molnar <mingo@redhat.com>,
	Arnaldo Carvalho de Melo <acme@kernel.org>,
	Alexander Shishkin <alexander.shishkin@linux.intel.com>,
	Jiri Olsa <jolsa@kernel.org>, Namhyung Kim <namhyung@kernel.org>,
	linux-perf-users@vger.kernel.org, linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com, Jann Horn <jannh@google.com>,
	Thomas Gleixner <tglx@linutronix.de>,
	Andrey Konovalov <andreyknvl@gmail.com>
Subject: Re: [PATCH v2] perf: Allow restricted kernel breakpoints on user
 addresses
Message-ID: <Y9pS4MNnFWOEO2Fr@FVFF77S0Q05N>
References: <20230127162409.2505312-1-elver@google.com>
 <Y9QUi7oU3nbdIV1J@FVFF77S0Q05N>
 <CANpmjNNGCf_NqS96iB+YLU1M+JSFy2tRRbuLfarkUchfesk2=A@mail.gmail.com>
 <Y9ef8cKrE4RJsrO+@FVFF77S0Q05N>
 <CANpmjNOEG2KPN+NaF37E-d8tbAExKvjVMAXUORC10iG=Bmk=vA@mail.gmail.com>
 <CACT4Y+Yriv_JYXm9N1YAMh+YuiT57irnF-vyCqxnTTux-2Ffwg@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CACT4Y+Yriv_JYXm9N1YAMh+YuiT57irnF-vyCqxnTTux-2Ffwg@mail.gmail.com>
X-Original-Sender: mark.rutland@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as
 permitted sender) smtp.mailfrom=mark.rutland@arm.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=arm.com
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

Hi Dmitry,

We raced to reply here, so there's more detail in my reply to Marco. I'm
providing minimal detail here, sorry for being terse! :)

On Wed, Feb 01, 2023 at 10:53:44AM +0100, Dmitry Vyukov wrote:
> On Wed, 1 Feb 2023 at 10:34, Marco Elver <elver@google.com> wrote:
> >
> > On Mon, 30 Jan 2023 at 11:46, Mark Rutland <mark.rutland@arm.com> wrote:
> > [...]
> > > > This again feels like a deficiency with access_ok(). Is there a better
> > > > primitive than access_ok(), or can we have something that gives us the
> > > > guarantee that whatever it says is "ok" is a userspace address?
> > >
> > > I don't think so, since this is contextual and temporal -- a helper can't give
> > > a single correct answert in all cases because it could change.
> >
> > That's fair, but unfortunate. Just curious: would
> > copy_from_user_nofault() reliably fail if it tries to access one of
> > those mappings but where access_ok() said "ok"?
> 
> I also wonder if these special mappings are ever accessible in a user
> task context?

No. The special mappings are actually distinct page tables from the user page
tables, so whenever userspace is executing and can issue a syscall, the user
page tables are installed.

The special mappings are only installed for transient periods within the
context of a user task. There *might* be some latent issues with work happening
in IPI context (e.g. perf user backtrace) on some architectures.

> If yes, can a racing process_vm_readv/writev mess with these special mappings?

No; those happen in task context, and cannot be invoked within the critical
section where the page tables with the special mappings are installed.

> We could use copy_from_user() to probe that the watchpoint address is
> legit. But I think the memory can be potentially PROT_NONE but still
> legit, so copy_from_user() won't work for these corner cases.

Please see my other reply; ahead-of-time checks cannot help here. An address
might be a legitimate user address and *also* transiently be a special mapping
(since the two aare in entirely separate page tables).

Thanks,
Mark.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/Y9pS4MNnFWOEO2Fr%40FVFF77S0Q05N.
