Return-Path: <kasan-dev+bncBDX4HWEMTEBRBSM62GAAMGQE5F5EZ6I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3f.google.com (mail-io1-xd3f.google.com [IPv6:2607:f8b0:4864:20::d3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 278F4308C1F
	for <lists+kasan-dev@lfdr.de>; Fri, 29 Jan 2021 19:09:15 +0100 (CET)
Received: by mail-io1-xd3f.google.com with SMTP id f7sf7564696ioz.3
        for <lists+kasan-dev@lfdr.de>; Fri, 29 Jan 2021 10:09:15 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1611943753; cv=pass;
        d=google.com; s=arc-20160816;
        b=rrsE2x7wUD0YI8iGV/o0ODVeQfZPUfqCmN/hItyBm/cnsVHkEq4O6uDE22rzyWWPnD
         YW77I1eeIk6wJ4IaNCtT0jopUmdg4vlBp5bKBKrn75eOTHuJcDld0yaVuMp107VHAFJf
         JHisxEnj6kanvNAlbFUAIZ8TKObhbXQM1xW4PYGRifMsUapwNrRPT42efyWAgtpp25Ga
         Oollwq1EJxrJze3PSSrX3CKNdzS+rRAzSJxIBXNYvSGhDd3YqwqSEEB0Qtmv7BfVi8Oa
         fw+Z3dnZN5aNcn/Uk9YOeIdawjrwYvNRM7K3G4SiD7aiqmTVDxjfw6tGprjJiYHO8RpX
         MG/A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=dMmjde/O5jXBocNa4deJ0d4ATSLAXnSUXZTDlik+Rj0=;
        b=s5cbh0YnvAeartxIdDbCWlW/wCFHtXblxKHSMHaXHj5d9Vp4DLU7FbpKVhFwSejfQm
         05Y3xDjnh9pegtcSCgJcD+GiTFiqRigjBZrEKMT50OZDyyZ/Q2P2gI6QPQ2asV1Pk9D1
         9UTEomRX3So80NjrQoOk3utxtT00qIiVJu5I4byi8T1VDFmaJX32Rx2Bz7ba/i4KftzW
         TIqHOyvRYBuQR15cGGgDF+D6EB61r9tA3RIuAuDiowDFXY/st/fj/GlECioluBGreoPy
         9NtvdaBC4HCBb+f3cWvL6bFJdqTIv3PCd+p6SKF1DIrODXLLKJxSbf8dd23SVzySXm58
         utwg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=FmG1cWU8;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::634 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=dMmjde/O5jXBocNa4deJ0d4ATSLAXnSUXZTDlik+Rj0=;
        b=nhcfa5byxSWveh+GfxzHZXhXFEDoz1JfHERiuMK6WIscaaa2TYErR0GOk/c2tkXSFj
         M87dEhBcjV0VGqt6wzZ1rupOEEsGMlEvecDNDsLhs+WVXU4xF0wT2uLkuX1AT1htlwD+
         SycBF7oHiSmYuoLGA8nWYfz/tzK2wxeBcc9BuL834aGxNKReZK1fHtdqF9WydnhRtjLI
         oa6MMyob0A2cCdLrRFAMERDvF/J7I7O3a9ep+6Z9wOgUICeyu5VcVz93BaYqTefjg8W0
         TslEFJ7oAczA1NO3tZq2W07JE4rSZKt63302Po9UsUwGKxOXwhu6PEq1oi7UreOUMq27
         io9g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=dMmjde/O5jXBocNa4deJ0d4ATSLAXnSUXZTDlik+Rj0=;
        b=Us84DsLpZwa5mGDq/yn28WB3vAi6gPZL0VXjucJBbM/tO74CwWoMNS7fNfpo+3svpQ
         uyTgdnvwTz4gGkv8DAhfC3QEwVaCx1tWzl+B7ZoNSSIDhUhx2MiDEaGQ+qzcKgnW4YnR
         V6OftaQmzTzG2oHgCcL4Cf824wEumBT82k8PMxKOUHdrw8yJue17QCEOMStbEkemgbaK
         rYUBJd808i7uVJQihuHE0EstP050sxN50GnjvcV6/+Ofu4+CZaU3L3d4kNreKjE1FCLJ
         H1gKg9XuUFBuhcNM4f2iEcdD9Xm69wDlTkNEhgm52byiOJXgmpsM7q4qPcMhvvnO7thH
         Ul/w==
X-Gm-Message-State: AOAM530+K+rKC6OmNWoYfJSfHZHA1g8iJOMj3IESIE8t7tOtV9bGbTJ1
	9r0e0GRzEFjL6Fy6mAtSmPY=
X-Google-Smtp-Source: ABdhPJyqLcu1DvJdTeTvTlj+NldayeRyM95H6UK9IY9UluOi/2a4pLUaaDB+4JEg2AmacXzRUo+1XA==
X-Received: by 2002:a05:6e02:1806:: with SMTP id a6mr4278334ilv.8.1611943753726;
        Fri, 29 Jan 2021 10:09:13 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6638:1687:: with SMTP id f7ls1187110jat.11.gmail; Fri,
 29 Jan 2021 10:09:13 -0800 (PST)
X-Received: by 2002:a05:6638:35a3:: with SMTP id v35mr5169547jal.36.1611943753345;
        Fri, 29 Jan 2021 10:09:13 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1611943753; cv=none;
        d=google.com; s=arc-20160816;
        b=Qz9MSeQWiDw6+SUByNZssiXTzg+qwNv693jlCKc4/hmZvSq38SbRy8Vaj5+w1jc5aK
         YwaV8w/oQHi1AvPjMgPwHvPvAzhFsPD5iamJQyBzGyt6I1WPGzXCdhbIUn1vTExh2owB
         QrBYL3aLDA5Kl1rWzLN9ZbX3iCwMOdm7krhHXpMRqAjOwFmFeLkrQALLWpjpsmLqraG/
         LCL4IUjrwX2S6BM5hqO3yFvfA9l15UjmBLllyX3Y03/8Bpe4XUY+F6buWlt4F6ukjIUA
         iAF8HSlW/+32KB/aeKLfYXQfPh3SeU4oXWp/bCh8bLY/4KUBon3ZrhnUEy2ogd4X2q3P
         s3UA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=+Q4AnktCopaaF8p4i4SvSgWzJSCfa/2k82Zci80Nw3E=;
        b=atrMMoixyHaZS6b320BhIXgl3PBJasvrwFhyWY1VbpO72Q/3KVPgLsvYcmfd+HUY+F
         eMzONVrYydQbYbRTflnDtv6k/A6NKg5feNgjuC02duU46jqX66njn/jB/+xeVkFxr8vH
         pp2GDyPv+9woL6p38yk2RyonAYoBe0PrKy07WeuczRmifVxDhcDyM350HBkgSiIIN4yO
         jKYZKl02NVtJYomuKucudoOkdE5+BJXOkw39Jg/wH6yzzJyzZBd8xWZBc2kASNYZgIk5
         vwO/mHppIMUhK9ESt2KTZRSI1ES/7whuVmL240Rs9DjAafTb14CUVUvBYCKcAqm8n/Fp
         TvWw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=FmG1cWU8;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::634 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pl1-x634.google.com (mail-pl1-x634.google.com. [2607:f8b0:4864:20::634])
        by gmr-mx.google.com with ESMTPS id d13si325733iow.0.2021.01.29.10.09.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 29 Jan 2021 10:09:13 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::634 as permitted sender) client-ip=2607:f8b0:4864:20::634;
Received: by mail-pl1-x634.google.com with SMTP id u15so5680457plf.1
        for <kasan-dev@googlegroups.com>; Fri, 29 Jan 2021 10:09:13 -0800 (PST)
X-Received: by 2002:a17:90a:ce10:: with SMTP id f16mr5677685pju.136.1611943752637;
 Fri, 29 Jan 2021 10:09:12 -0800 (PST)
MIME-Version: 1.0
References: <20210126134603.49759-1-vincenzo.frascino@arm.com>
 <20210126134603.49759-4-vincenzo.frascino@arm.com> <CAAeHK+xAbsX9Zz4aKXToNTrbgrrYck23ohGJHXvgeSTyZy=Odg@mail.gmail.com>
 <e5582f87-2987-a258-350f-1fac61822657@arm.com>
In-Reply-To: <e5582f87-2987-a258-350f-1fac61822657@arm.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 29 Jan 2021 19:09:00 +0100
Message-ID: <CAAeHK+x5O595yU9q03G8xPvwpU_3Y6bQhW=+09GziOuTPZNVHw@mail.gmail.com>
Subject: Re: [PATCH v9 3/4] kasan: Add report for async mode
To: Vincenzo Frascino <vincenzo.frascino@arm.com>, Alexander Potapenko <glider@google.com>
Cc: Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	LKML <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Catalin Marinas <catalin.marinas@arm.com>, 
	Will Deacon <will@kernel.org>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Marco Elver <elver@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=FmG1cWU8;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::634
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

On Fri, Jan 29, 2021 at 6:56 PM Vincenzo Frascino
<vincenzo.frascino@arm.com> wrote:
>
> Hi Andrey,
>
> On 1/29/21 5:40 PM, Andrey Konovalov wrote:
> > I suggest to call end_report(&flags, 0) here and check addr !=0 in
> > end_report() before calling trace_error_report_end().
> >
>
> Probably this is better as:
>
> if (!IS_ENABLED(CONFIG_KASAN_HW_TAGS))
>
> Because that condition passes always addr == 0.

Not sure I understand. Call report_end(&flags, 0) and then there do:

if (addr) trace_error_report_end(...);

Although maybe it makes sense to still trace all async bugs to address
0. Or to some magic address.

Alex, WDYT?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2Bx5O595yU9q03G8xPvwpU_3Y6bQhW%3D%2B09GziOuTPZNVHw%40mail.gmail.com.
