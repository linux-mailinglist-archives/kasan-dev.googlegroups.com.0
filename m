Return-Path: <kasan-dev+bncBDX4HWEMTEBRBAEV6D6QKGQE6P63VIY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x240.google.com (mail-oi1-x240.google.com [IPv6:2607:f8b0:4864:20::240])
	by mail.lfdr.de (Postfix) with ESMTPS id 3502E2C1441
	for <lists+kasan-dev@lfdr.de>; Mon, 23 Nov 2020 20:16:18 +0100 (CET)
Received: by mail-oi1-x240.google.com with SMTP id t24sf1155306oic.15
        for <lists+kasan-dev@lfdr.de>; Mon, 23 Nov 2020 11:16:18 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1606158977; cv=pass;
        d=google.com; s=arc-20160816;
        b=ccsmyUlddUu968dYpfAQXGlktibsA1LG4fJn5ao9IBk2bF9dP3ix1EmjTZg1bwD5md
         I8XtAEM6LpocjhJ13MZPcSX4sLKFC8a5Zka/kl9l8RTFUzg6agHAopHsAhdvqL2Yq7W8
         h9io5cSgWmNy4C7L2XX3KYI1d63ucnfGnCmapEBw9ULlSTSMegJ3KZOFTXn0hZx4/W5F
         PyFA5Y2c2uUUsdVPi8OJ25KvM6EswxMsUpn7YpH9NLGHiHRrFyHiIJEVyceFSBBeYh7G
         mbk4oZY2zY40TA3brg7jVOpkbYhZ0fk1FnSAhXtKP99JrnpGP/+xMnH8qL+NmCgitonJ
         x64w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=jruy+wrW65XckfEvkLsObgXVS4g9Hy4jB53iZNOZ0aY=;
        b=UVeDD5wwZTCSSSszahBEfcXw1dsWEeDvuGvDX75xfx4PmcP6UHm0z1NuTscRbYzn8B
         ZYVJcQxx+tR97n2cg0t4FGwu4HRq7G0d3x6u7jUB7kiOFmpGrtmmdAYbDtuawF4OFVRz
         QzSr5qRlpv+E4gBrWYvDQ+s4sPVcXFsLFqohobUK/+cCW6Iix0R96wAZv61XoOcIUkko
         X1s//22UosnC6m3hd7hqnhJcATKv00fBUdMu3g7fMAb54hTLZUBnvYUEHbFhduDXMYZT
         JZcACiZ4VxggYVq8sb4KQsTwQpip3gtW3dgDw/PvO2+EIk/p3wdC7Uq9S2AkXg8QY+K7
         Girw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=HVIOI1N8;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::544 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=jruy+wrW65XckfEvkLsObgXVS4g9Hy4jB53iZNOZ0aY=;
        b=YlljOGL6f0mHXohcqrm1vAuxQDZDr9a/oct4rXoK0SgCTCWeAkxF26FczXLO++1+FV
         6XZadVneNn0csPvKce73SkSyJufb4vjI0KtpueI80WTzK9b5uSNV/AXknMY373j+36sv
         N6RbRdtWkCACa4sG7DhEMQbtRrH1AasP66kb+318b7K0BMQbQBTXy4saHDbwirdZ1V69
         a5aEHHsywuFEheWFnDYBvFda5zNSdz+ngMyUqlOiDcLU/y89fpooEZ62ujWbvfA74gYg
         iVfJ2ktM9HYPyKrhXTE0oQYg7gFxZU8lg4e7BtgYg2OhKvEX8fDeNAkdQHsIfyoFj52x
         jF/A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=jruy+wrW65XckfEvkLsObgXVS4g9Hy4jB53iZNOZ0aY=;
        b=pteKJjw0Xg+ustSEQnlSgndpuR7jdfFsKtpO5x/VO3iph3vRP20BAu+tJMJdkHIgOs
         L867Pcq7YZ+eqLEN1zY8NEg+/6QOu1oeubNGwcRP2iY3YVUOxoJSYXUG23OCBVstEBJh
         IJOk9At6sPkvbe5WPIqmZ2e6bR4hdWkZTlyfWpGV6q9E5ZCAyFdKvrs/00GL1PN4NbbJ
         CKeqGKs38w2F0SglIaGWCLo36LqLudSZR+DR7fvAklhRTj10ZYSs2en8/5Wif63Y2g0v
         5SrS1a4i2EB14+cytovCbcBbSWuLy5NIfV7V3p6afMkVeFTqwO05rfuRl3xCA05eI2TB
         gLgw==
X-Gm-Message-State: AOAM533giUo63j9WfqakkK8havfCjn2Zn92x73dtYiwT3SQvKSu3f6hU
	4fd0eqtMJJkQLyKf2tonO44=
X-Google-Smtp-Source: ABdhPJy2yP1kFPbXTmcHvPYb5Tde67k7WCQS5CsjPiWJ8tOqywYVKBLBTV2tOJhqJEDkBIj+b8vtpQ==
X-Received: by 2002:aca:ec97:: with SMTP id k145mr241540oih.163.1606158976873;
        Mon, 23 Nov 2020 11:16:16 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:4fd0:: with SMTP id d199ls3641005oib.5.gmail; Mon, 23
 Nov 2020 11:16:16 -0800 (PST)
X-Received: by 2002:aca:7511:: with SMTP id q17mr276274oic.65.1606158976582;
        Mon, 23 Nov 2020 11:16:16 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1606158976; cv=none;
        d=google.com; s=arc-20160816;
        b=DMniviUug5CFa+Lr3oDAcNzNXHLTM010KQSOirwfb7xQcAQs1GQJ7Cjxuxbxyp7JIG
         zxG4BkZn5dZoti3/mjN8LBt42YeHP8No/OfM/aazETa/5e7/p1iaL0w7qlxRN0mLQil6
         5iI6R7zqdc3YLHaAKo/51+YQG/j+C+r3hoshW2HXatRvsTJ1r8BKu1Tg9Ibk/U/m1TEh
         sCqe01LR+UWpAv5q1RGgESpm3VscChlkvy9pmmXhJ7yZgawTfifmF/kG8RqXD2Kx5bUX
         Xku5Aa9nFHMPRZizQHgzr/PkY9CXwB+QoAB3D5VeGwEnW6nQSbEWV0z60b6Ktk++hE6n
         aEVg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=h9538eMr7aJDlDb1g4y3QM7S0Xn5CPIOZqgBkgQyEew=;
        b=vQBloyQcXWek6Sn2YQlnAQsp0dyMtk9hgJS4WatMFHmKk6yEujpxUMCF+B4oofQFe2
         PwtsmdTqNsTTaGjyDdlSzLs2G3DkjhDpZLktqEx7XeSubzAZyG5XS8jUFDY+S0QCuncg
         LU41qp2g4q22c/bRpLnx4sDUGJ9mk8AP+umiSqWk/aVISCSai18lS0ZDt7Y73aXhsXNC
         baCCmvd6UACkgiapa6E9F+8VLybEFN+eQNzOlDCVEdoySGSI33XIWOTqOxV8edxd66Tb
         HkcPjnbYud/ftRhUQKEkcp7YWiWImN0l3GVqpEfk+T2i+m2IFL+szjQmWk0upUNjrwdg
         xoxg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=HVIOI1N8;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::544 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pg1-x544.google.com (mail-pg1-x544.google.com. [2607:f8b0:4864:20::544])
        by gmr-mx.google.com with ESMTPS id f16si1117352otc.0.2020.11.23.11.16.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 23 Nov 2020 11:16:16 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::544 as permitted sender) client-ip=2607:f8b0:4864:20::544;
Received: by mail-pg1-x544.google.com with SMTP id v21so15173078pgi.2
        for <kasan-dev@googlegroups.com>; Mon, 23 Nov 2020 11:16:16 -0800 (PST)
X-Received: by 2002:a63:eb11:: with SMTP id t17mr787835pgh.286.1606158975788;
 Mon, 23 Nov 2020 11:16:15 -0800 (PST)
MIME-Version: 1.0
References: <cover.1605305978.git.andreyknvl@google.com> <52518837b34d607abbf30855b3ac4cb1a9486946.1605305978.git.andreyknvl@google.com>
 <CACT4Y+ZaRgqpgPRe5k5fVrhd_He5_6N55715YzwWcQyvxYUNRQ@mail.gmail.com> <CAAeHK+xv2UQyD1MtAiu8d=cRbJDNXQaaA-Qh+Eut3gRnLbJEMA@mail.gmail.com>
In-Reply-To: <CAAeHK+xv2UQyD1MtAiu8d=cRbJDNXQaaA-Qh+Eut3gRnLbJEMA@mail.gmail.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 23 Nov 2020 20:16:04 +0100
Message-ID: <CAAeHK+ydCcdtn7u=nyBDxqffk_eTKA=sOTQzTnQuNZj81HxEJQ@mail.gmail.com>
Subject: Re: [PATCH mm v3 17/19] kasan: clean up metadata allocation and usage
To: Dmitry Vyukov <dvyukov@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Catalin Marinas <catalin.marinas@arm.com>, 
	Will Deacon <will.deacon@arm.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, Linux-MM <linux-mm@kvack.org>, 
	LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=HVIOI1N8;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::544
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

On Mon, Nov 23, 2020 at 7:54 PM Andrey Konovalov <andreyknvl@google.com> wrote:
>
> > > @@ -168,6 +173,9 @@ void quarantine_put(struct kmem_cache *cache, void *object)
> > >         struct qlist_head temp = QLIST_INIT;
> > >         struct kasan_free_meta *meta = kasan_get_free_meta(cache, object);
> > >
> > > +       if (!meta)
> > > +               return;
> >
> > Humm... is this possible? If yes, we would be leaking the object here...
> > Perhaps BUG_ON with a comment instead.
>
> No, this isn't possible. Will turn this into a warning and add a comment.

Actually, looking as this some more, looks like with this change this
becomes possible. I think the best approach here is to not put such
objects into quarantine, and return proper value from
____kasan_slab_free() to avoid a leak. I'll fix this in the next
version.

Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2BydCcdtn7u%3DnyBDxqffk_eTKA%3DsOTQzTnQuNZj81HxEJQ%40mail.gmail.com.
