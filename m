Return-Path: <kasan-dev+bncBDX4HWEMTEBRB7UUSP5QKGQEUJFH2BA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3f.google.com (mail-yb1-xb3f.google.com [IPv6:2607:f8b0:4864:20::b3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 30E6B270043
	for <lists+kasan-dev@lfdr.de>; Fri, 18 Sep 2020 16:55:59 +0200 (CEST)
Received: by mail-yb1-xb3f.google.com with SMTP id p187sf5746708ybg.14
        for <lists+kasan-dev@lfdr.de>; Fri, 18 Sep 2020 07:55:59 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1600440958; cv=pass;
        d=google.com; s=arc-20160816;
        b=Eaf01qKDNj0+Flu6cYd5Ea8E7KoG91jxtxWmDb9BSRR6H/9MTkEWDRGMTJ9Wou31RS
         4pSxF/7JxV0+PEEglr6pCP9KcfdmFBEkVKrRUz5Z73jXTOiIrfixlgwUo/0PH6C8awxT
         10FGWeEOf5cEBw/V9G3wsVuk1ALKowyZE0vDHrZ3bWj027azWJAOZR6sm+lRjI9YIjCF
         zHB4RutuUoFJz5BFyxxxw0rItQ9hCSS41LGdmzeb60hUNidK6/aRKd4P6v9s32aFdM5F
         ZjaGay0s9UXOfcefeqoWbRwQ2Hok5pNSiKQ/cTlY4j7pHTW6dqB4yo2EJSKIfgxlw71y
         xHFw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=Izx4KT0pfM/7Rg19G6cOpL8aE/UG8HdZMBEkdp07lMw=;
        b=UAuarm2xNMhXF/uN1oqSpLEUcqjpYBB/Dj8SIbE7x5NinA/QozNL6BGUiEIghx4TLt
         dEjB7zt8dGgoO85ux4AAA6xzH5X9GPUypKUn2sbZ5rhv4ZHkGTnohyAjzEzW1ba9tzAG
         k78/3IZ1y+vwaqtnLPbgKUkWs4FKVrOrybbr+bN1z71qXy4JB07LUTEp2wu62opBIqJO
         8tLUeaxWG+duRRbcXWD1dtNSw14UO6MCDARtwmBEzZWVwIQ9+uu+kItc61iDlC1sLAbE
         l148JN39qraPbBSPu2h5xdvJWI+kxe+8fY+0BVaNabQPsLkSl4fR+Tg7uf2AlYQ+32LY
         EpyQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=szlsuR3S;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::642 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Izx4KT0pfM/7Rg19G6cOpL8aE/UG8HdZMBEkdp07lMw=;
        b=ZnWnBM+1FwRssPVPqEkf5pSqAUvSe5BsfwtZ52unvqU3vjI7lqHJ6Ifj2qpSh6V/U0
         /okUtHJIk/K3suek5cDBkLojIkyu+1hyfWlqgz2N3wBq9of7kEpvnjXOjDWrI1RByrPO
         NPnKq/4H8199k1wb0jav+Cx43w+JezhbkJ1BM+LGjN+XboeDm2+LH7wanW18VQIwAQUB
         ER9Alcz+UwIxsZD0QzrZq1HDBk+Ma8Y02lzafBLmMcDZDn0GOSWeeRrg/myy1zMJLZpm
         AWAdLqdAkVMCBAgWe3u69CtVEfJWCnwr0nyEOBr/mLJYveo7r4xvBMHsVlV2r67r/QuN
         mnfg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Izx4KT0pfM/7Rg19G6cOpL8aE/UG8HdZMBEkdp07lMw=;
        b=kCrWOPlwsNwh+AHrg8Yb2aYExEULi+EeizcrpWrb1qO0fkdJbb79Q6T/oqxKWGre05
         lwjO845suPANHBCIZadZU5kbwzVBiDOPU+IFzzk0876JFISlR3oDrU8QXfhwiS1LX8KC
         NhrmxuTx9N0L6iTqV+WpENgSHb/L5LQjLCyu9dBqgV8tESy97DRc64eh+6rAziWNwO2e
         eZQVz5lm89hJkdCDAvaRWTyFZZy8sISMJRFEyDYrY9tvLYyT8Q8z8xbcAF++DLJLAdCK
         VyKQMs6ONqGb+UBtMUr/QhgBexZLzyXBesVrUYvxwZupyVSeieyA2VOGvZhmHKqqbP0M
         GR0g==
X-Gm-Message-State: AOAM531VJZjVzSFd3ZCtnDOX6Rg2Uays17+kicmkgc7P0uH/KGgB4p9L
	PB0z0hy8UrzFCXWE3WNPuUo=
X-Google-Smtp-Source: ABdhPJzeBmzoExV8CQhbIDWZMKMxtipdBJaEiy8yChM8b9wJN8ke+PbxNsoMH0Jv29ieVGocV0PAAg==
X-Received: by 2002:a25:586:: with SMTP id 128mr50588134ybf.221.1600440958263;
        Fri, 18 Sep 2020 07:55:58 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:c550:: with SMTP id v77ls2536245ybe.8.gmail; Fri, 18 Sep
 2020 07:55:57 -0700 (PDT)
X-Received: by 2002:a25:b53:: with SMTP id 80mr27973737ybl.322.1600440957834;
        Fri, 18 Sep 2020 07:55:57 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1600440957; cv=none;
        d=google.com; s=arc-20160816;
        b=J4Zgrcuf0hruK6RQY0Mw9o/vxxsoqWmXYXiE5BIEMSBaQiWXZhzoAs/1tElL21R9PV
         6sQ80zqOi5TBpgXoP3Kaefjby8zff77Or93A3z3I0lXZEhzKlzWwz7vNagEBS+Fg621W
         0Vm2tzWTL8r6X4vXFT93aiV5RChbO9PqWSK4tkjnTsrLkoisEFCZdajoDYlJBf+sJqQ0
         hVHj77+4xF0bidYLMfJPULepZE4aOpkG8sfbzjeQOxSA68mN6/ECiH730DdQ7J3IpjHt
         UhGUgO8pqT2FR5XlZRlDNdFFbKU+gjSyymyCZBSO7WmtUgBFR/8331ADj01kf6godMBb
         7OSQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=F2wjI5wyvHuB1DQE3VdNJfmgr0lLxVLpaWfOkRz2kHI=;
        b=MK7d55gicf/wlqhprkC3bb7mgmKA/jF1r6hdESKuOhMFGqaHv2UinViAwxOCHgYniZ
         AHOUWm3k9WGekfatVEuUBtDUdO14PlYf9Aq4ipBdlKDEgFP2WnkY4AnsB6UBv+pzylOm
         TSuU1MdPh0EGtPKVP27H4x02OJKkewrMfV3ea7PAp0miD6A0B7JnUt8NUBPGANirqUsQ
         FI5MJSujJJa7nlXCDCfMDFNuYdrLFJITpwYoYUc6RKOERe1UehMu43uLm94+cVuo2De5
         g5vkuojo0/y4aOOK+7bPkD5pNLb9DswtuScVQ5xmso5UuBpwyie+wfWmBFign5APRxIQ
         tN3g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=szlsuR3S;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::642 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pl1-x642.google.com (mail-pl1-x642.google.com. [2607:f8b0:4864:20::642])
        by gmr-mx.google.com with ESMTPS id y189si218824yby.5.2020.09.18.07.55.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 18 Sep 2020 07:55:57 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::642 as permitted sender) client-ip=2607:f8b0:4864:20::642;
Received: by mail-pl1-x642.google.com with SMTP id e4so3106018pln.10
        for <kasan-dev@googlegroups.com>; Fri, 18 Sep 2020 07:55:57 -0700 (PDT)
X-Received: by 2002:a17:902:d888:b029:d0:cb2d:f274 with SMTP id
 b8-20020a170902d888b02900d0cb2df274mr33383728plz.13.1600440956745; Fri, 18
 Sep 2020 07:55:56 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1600204505.git.andreyknvl@google.com> <f511f01a413c18c71ba9124ee3c341226919a5e8.1600204505.git.andreyknvl@google.com>
 <20200918144423.GF2384246@elver.google.com>
In-Reply-To: <20200918144423.GF2384246@elver.google.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 18 Sep 2020 16:55:45 +0200
Message-ID: <CAAeHK+yJ=86KfVN5bSvXpawjNtLuG4zvsPVtcYCBQR_PPfV4Bw@mail.gmail.com>
Subject: Re: [PATCH v2 35/37] kasan, slub: reset tags when accessing metadata
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
 header.i=@google.com header.s=20161025 header.b=szlsuR3S;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::642
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

On Fri, Sep 18, 2020 at 4:44 PM Marco Elver <elver@google.com> wrote:
>
> On Tue, Sep 15, 2020 at 11:16PM +0200, Andrey Konovalov wrote:
> [...]
> >  static void set_track(struct kmem_cache *s, void *object,
> > @@ -583,7 +585,8 @@ static void set_track(struct kmem_cache *s, void *object,
> >               unsigned int nr_entries;
> >
> >               metadata_access_enable();
> > -             nr_entries = stack_trace_save(p->addrs, TRACK_ADDRS_COUNT, 3);
> > +             nr_entries = stack_trace_save(kasan_reset_tag(p->addrs),
> > +                                             TRACK_ADDRS_COUNT, 3);
>
> Suggested edit (below 100 cols):
>
> -               nr_entries = stack_trace_save(kasan_reset_tag(p->addrs),
> -                                               TRACK_ADDRS_COUNT, 3);
> +               nr_entries = stack_trace_save(kasan_reset_tag(p->addrs), TRACK_ADDRS_COUNT, 3);
>

Ah, yes, it's a 100 lines now :) Will do in v3, thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2ByJ%3D86KfVN5bSvXpawjNtLuG4zvsPVtcYCBQR_PPfV4Bw%40mail.gmail.com.
