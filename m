Return-Path: <kasan-dev+bncBDW2JDUY5AORBXFGSCEAMGQELCJI3LQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13c.google.com (mail-lf1-x13c.google.com [IPv6:2a00:1450:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id 664953DBB75
	for <lists+kasan-dev@lfdr.de>; Fri, 30 Jul 2021 16:57:33 +0200 (CEST)
Received: by mail-lf1-x13c.google.com with SMTP id p16-20020a0565122350b029030e2ef98a19sf4128413lfu.22
        for <lists+kasan-dev@lfdr.de>; Fri, 30 Jul 2021 07:57:33 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1627657053; cv=pass;
        d=google.com; s=arc-20160816;
        b=GAeiC89pZgYYLtN26Xf/YDsaupa7TzhQFBrSpr+9KEN4sfBD5TVgvmnlOisqJv+ZFY
         5diDBTP8lkjNWCVTOvwWHsBEWwuGW/lxCnd+gzb8UAIr/aBiEcAUVx98ctDeuwBrTfmF
         fyqZg3JVVhfsN0KNSQ+oOvjGBhgd3Kh51JA5kNixT+kzRG6xnzN0C0Fg33kIZU+82ZG9
         jfeZgAPNP1AXLRYqXiVLdj5JeG96SO/L37wPJOL/KpKy0urZJ/VMoK/8ur2Oqduh+d9t
         d7O3dEtKTrYra7t++faniR2VBLV9UPnX35wOnbiemuSlJdFTQsO+ECziVDSwjpp3c+8o
         VwHg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=Kp8jklLT+Ddu8WYYd846Wtsh40hGhbweuPRlJtD9dAY=;
        b=uf0w7dLT+1nbhotZdxsxZQBIDr/vaHlGiXz+gSxGrFaP9cvEKPS2juHvsyv3iOkzHA
         W5c1E8xQZjk7wa6PhN3jh5wj4dvjIylsDn22juVtVdhN5PwOlcATHPmTuR2LekFE2j6D
         rSTOvzFZiKnSkBKpCowB8EjP2LLySMaGF7ANS7tC3fmKSbIz8cLi3wmYVoKQUhuyQZnT
         zel6S7KC/8nAJSxUk2f0+HuPP8KK0GWWA+tGggPT/f5Gw4DuPTJj0HkGEDg0goBhGaHS
         oafgj1u3Ekxz3OtsM1V9/UloynU3TOI/kpQq5vzccOZsv0XSQi6NF2l1Hp1el9qDjuU+
         OfcA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=qdwGk32T;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::52d as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Kp8jklLT+Ddu8WYYd846Wtsh40hGhbweuPRlJtD9dAY=;
        b=WEvv0iYAhQLJBE2+7gMnKckl/QZ4YwiPW1qHWjp0iNqmLvtzCq+pZEA58DV2sFgRQz
         scqWLs5bC3gfil+Gh+o1n7EsjWpcrBc5HR040Wum7jo6CgGqu6Z/cCZVTkBD4CSHlB7p
         pWCIOv1dVRT7MO2QSg9rj0CYWvzthzbxocFQd5sv5gYm31/h9oPNZ61GHb3Z6UGlH6ox
         ynd98uqjtvZmRX6sECbnT93ACyXtDpctPw1wdJcnl4l2Z7ZKedXk0h47kpSYbpoBdpYU
         NHTCqcvEOQQ2396+t8YEZOSM+U25BkVxropEeCZ3MYnfhQhxPJp7Mqb+q36Gz8O+Oxjs
         NybA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Kp8jklLT+Ddu8WYYd846Wtsh40hGhbweuPRlJtD9dAY=;
        b=e94Zdo+DFgaFYqnGA0cAoGoG6u+fQVZyVm+7fJdQiB+4LRv6QrXdOWE91FAxxDzjq/
         NGIB0DguusLzD5x3hg4P94xcqWrpldMsSH4xqH0KoT6jiH7ffto32fRHiYh9pgyqxjng
         rI6eDahuVr2tsnXCtD74Iss/FgTXPKV+TLzs+9+bEheodRt51ldgN+cZysmvhbD6dAQl
         67G9RwrMUY7AEsJvZCIUEl0FJsaS7JppaHTeBndFVmstJwTmORr4o+YM3P6fF+C8Sq82
         PvbxPQZNudJgwCffM0RUnZLFl5O6XHOtrTyM1Jpohe6Hj4Eg+H5uky4BnVoNoixtd0Rj
         jbcA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Kp8jklLT+Ddu8WYYd846Wtsh40hGhbweuPRlJtD9dAY=;
        b=gwMLo3WQJPyvyZPGz0WFhm+Si5jW4kP+Nl9pA0FRZpPVXcRi73tPJ+vfgQOCDutjEc
         D8W+yDM5UFYudFaqMtEAu9T+uPt0uOsaTEV9YqN9fCm+iPeuSe8117XFSZSqs6688fjX
         KrDC4kE0b1tHRVLV2I4uSsVrEuuhLFCMq2w97juRgU2oZ9s4B5qlhSbDY9vORf5wme8l
         gZBuUE1xHEHcYzDhXlDmvtD7kq4HTDJJDtlJUc7M3lu6ZJHEetk9RcFr6OugkJHdom3P
         ea75VwJIaIqEXdGxASZ6usVBFG/+TUJj2kF+y4K8rvNxuqYx6zjGSEV9CPk8FpRVE974
         We6w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5308pCOkRQtF4fOsKdVEB1PjRlBSkGuFSUgqVKgNivDFNQYxiddt
	KihoZDn2PcAIJH+09PR02kg=
X-Google-Smtp-Source: ABdhPJwZDs7+vCXOnhj7HXWh5GPCiAkKGTRimJ96wXhIMeUd+K9R+RM0f794+5g3EH0+1MuB+WTq+Q==
X-Received: by 2002:a05:6512:98a:: with SMTP id w10mr2154518lft.76.1627657052861;
        Fri, 30 Jul 2021 07:57:32 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3f02:: with SMTP id y2ls408335lfa.3.gmail; Fri, 30
 Jul 2021 07:57:31 -0700 (PDT)
X-Received: by 2002:ac2:5a0c:: with SMTP id q12mr2156201lfn.222.1627657051925;
        Fri, 30 Jul 2021 07:57:31 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1627657051; cv=none;
        d=google.com; s=arc-20160816;
        b=Q0nUOSbR0mafZAYeeOpy1S8mFzGy00A88Wbf9meGLl4JfRC7V0xf/bGqyNwk1sJ8rV
         3uz7eLszRccuTHp9TPiOAg/xD+dLVrWtP9Vi7PFVSqJhh778CPKE2Utrhf0OiGtRBA9o
         ArbaqcDJwXQDAoxvTYj4uqN/u2BuygYw3sTsKNmfGPbOd1AjBJrLGV7k+W8NGIaQFAsK
         VuUFgmiybwv29WBseEoq06junwd2+lXHQNavrQVzDPKhv6sYmTYj/y4tSVASiTIf/nD1
         kpa8amd9M+jGt0e9ab0SrldwailOLDLPPKw7wVoFh/h3LtXY6NsNSZuGMULaFuePwvWu
         QWAQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=/FskvzB/Uu7kITCTpEs9Kzb0h3ZTsKYWrhXodwFjiIk=;
        b=CDHEaijawd0UEFcdsuFxhXIfqqpWPvWe0bC5Rtky1IVDuMy+MgTPhtzkBQ17lT9bO3
         ZONAUVqakGqVbEF4jr9AYEsrsR2HTjNKQTOm7yMcqQLVat5Do9Y+Mrpw1FDRtGjkP48G
         c3NRDdnz8wKFmJi/gV5hWeqzeMLF8dor250qdMp3jDWXCxOdmcGkW7HJKu6ANuMi9EoW
         vQoT4sIp70k0RE+oGtZg9izCh4I5+k9oXZVytar2dBblxXmT5IVASFGwmN2/P1ie7JhV
         6AVEMwBEfyPK5BTFbnHAgp7sbzRrpnlK6+eWs0HJDJg6/MLEZ2APQQqyELITF30wyUXg
         UA3w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=qdwGk32T;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::52d as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-ed1-x52d.google.com (mail-ed1-x52d.google.com. [2a00:1450:4864:20::52d])
        by gmr-mx.google.com with ESMTPS id g5si83054lfj.3.2021.07.30.07.57.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 30 Jul 2021 07:57:31 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::52d as permitted sender) client-ip=2a00:1450:4864:20::52d;
Received: by mail-ed1-x52d.google.com with SMTP id ec13so13068446edb.0
        for <kasan-dev@googlegroups.com>; Fri, 30 Jul 2021 07:57:31 -0700 (PDT)
X-Received: by 2002:a50:eb88:: with SMTP id y8mr3436558edr.70.1627657051382;
 Fri, 30 Jul 2021 07:57:31 -0700 (PDT)
MIME-Version: 1.0
References: <20210727040021.21371-1-Kuan-Ying.Lee@mediatek.com>
 <20210727040021.21371-2-Kuan-Ying.Lee@mediatek.com> <CANpmjNM03Pag9OvBBVnWnSBePRxsT+BvZtBwrh_61Qzmvp+dvA@mail.gmail.com>
 <b6b96caf30e62996fa3b75ae8d146c9cc0dcbbf6.camel@mediatek.com> <20210727192217.GV13920@arm.com>
In-Reply-To: <20210727192217.GV13920@arm.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Fri, 30 Jul 2021 16:57:20 +0200
Message-ID: <CA+fCnZdprormHJHHuEMC07+OnHdC9MLb9PLpBnE1P9TvrVisfw@mail.gmail.com>
Subject: Re: [PATCH 1/2] kasan, mm: reset tag when access metadata
To: Catalin Marinas <catalin.marinas@arm.com>, Kuan-Ying Lee <Kuan-Ying.Lee@mediatek.com>
Cc: Marco Elver <elver@google.com>, Nicholas Tang <nicholas.tang@mediatek.com>, 
	Andrew Yang <andrew.yang@mediatek.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Alexander Potapenko <glider@google.com>, Chinwen Chang <chinwen.chang@mediatek.com>, 
	Andrew Morton <akpm@linux-foundation.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	"moderated list:ARM/Mediatek SoC support" <linux-mediatek@lists.infradead.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=qdwGk32T;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::52d
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Tue, Jul 27, 2021 at 9:22 PM Catalin Marinas <catalin.marinas@arm.com> wrote:
>
> On Tue, Jul 27, 2021 at 04:32:02PM +0800, Kuan-Ying Lee wrote:
> > On Tue, 2021-07-27 at 09:10 +0200, Marco Elver wrote:
> > > +Cc Catalin
> > >
> > > On Tue, 27 Jul 2021 at 06:00, Kuan-Ying Lee <
> > > Kuan-Ying.Lee@mediatek.com> wrote:
> > > >
> > > > Hardware tag-based KASAN doesn't use compiler instrumentation, we
> > > > can not use kasan_disable_current() to ignore tag check.
> > > >
> > > > Thus, we need to reset tags when accessing metadata.
> > > >
> > > > Signed-off-by: Kuan-Ying Lee <Kuan-Ying.Lee@mediatek.com>
> > >
> > > This looks reasonable, but the patch title is not saying this is
> > > kmemleak, nor does the description say what the problem is. What
> > > problem did you encounter? Was it a false positive?
> >
> > kmemleak would scan kernel memory to check memory leak.
> > When it scans on the invalid slab and dereference, the issue
> > will occur like below.
> >
> > So I think we should reset the tag before scanning.
> >
> > # echo scan > /sys/kernel/debug/kmemleak
> > [  151.905804]
> > ==================================================================
> > [  151.907120] BUG: KASAN: out-of-bounds in scan_block+0x58/0x170
> > [  151.908773] Read at addr f7ff0000c0074eb0 by task kmemleak/138
> > [  151.909656] Pointer tag: [f7], memory tag: [fe]
>
> It would be interesting to find out why the tag doesn't match. Kmemleak
> should in principle only scan valid objects that have been allocated and
> the pointer can be safely dereferenced. 0xfe is KASAN_TAG_INVALID, so it
> either goes past the size of the object (into the red zone) or it still
> accesses the object after it was marked as freed but before being
> released from kmemleak.
>
> With slab, looking at __cache_free(), it calls kasan_slab_free() before
> ___cache_free() -> kmemleak_free_recursive(), so the second scenario is
> possible. With slub, however, slab_free_hook() first releases the object
> from kmemleak before poisoning it. Based on the stack dump, you are
> using slub, so it may be that kmemleak goes into the object red zones.
>
> I'd like this clarified before blindly resetting the tag.

AFAIK, kmemleak scans the whole object including the leftover redzone
for kmalloc-allocated objects.

Looking at the report, there are 11 0xf7 granules, which amounts to
176 bytes, and the object is allocated from the kmalloc-256 cache. So
when kmemleak accesses the last 256-176 bytes, it causes faults, as
those are marked with KASAN_KMALLOC_REDZONE == KASAN_TAG_INVALID ==
0xfe.

Generally, resetting tags in kasan_disable/enable_current() section
should be fine to suppress MTE faults, provided those sections had
been added correctly in the first place.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZdprormHJHHuEMC07%2BOnHdC9MLb9PLpBnE1P9TvrVisfw%40mail.gmail.com.
