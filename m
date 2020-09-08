Return-Path: <kasan-dev+bncBDDL3KWR4EBRBYU7335AKGQE5ETVAZQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf38.google.com (mail-qv1-xf38.google.com [IPv6:2607:f8b0:4864:20::f38])
	by mail.lfdr.de (Postfix) with ESMTPS id 0A254261250
	for <lists+kasan-dev@lfdr.de>; Tue,  8 Sep 2020 16:06:28 +0200 (CEST)
Received: by mail-qv1-xf38.google.com with SMTP id de12sf3699955qvb.12
        for <lists+kasan-dev@lfdr.de>; Tue, 08 Sep 2020 07:06:27 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1599573987; cv=pass;
        d=google.com; s=arc-20160816;
        b=nlxbhMwt7iWWQBx/PeTUB1JtmOlLqaEGN2MS4le8A+SNDTrIIYuIwLlsDo6du89CFU
         6ijcgBgB2tkbXfApjywmghLSfJN++93ZrTqBdZCCnjLxShuGvOxG0ITSf0f9H6oTKt9I
         l5wCZnGc6kjq8uQB9np2aoEu1/oG+UCuEwIkYrF5u7VPLso27wk/XNzvlaqrIE5hWPcv
         5KV+ZAfg7yu4DVCoaAi4ud0xoRfD2s13tbudSw/+bM3WVSvt3J3k1toBfw9vm1JI1D27
         hNXTUn5QDV9V/uA9bB9JGXri65lItrCD3onqOsGXXTmtKhAcenuRoIDHUzfB7QO+HNFa
         b+Kw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=wDZsQlGgy4FqjwQIwrEXAV03acYkOeL2udsT8GFAkcM=;
        b=TCRFHms7CFsrWzyZbBrIdBHsJUe+0HAJQ/MVDcpSHzffvywFoSE7GXa1dMie9t4XOU
         j5vtntxO9fopaeS1za7K3p/o4ehUCLt5C0VavJxfP6x7ZsqvAgsNxTVGdYbL2SCW1TJh
         kd1tuCYJaYlwFi3IGaI2LBsCaDyfQs9+/GEP2xDcupcvHhDl5Euj+g228WbT8/lwVZW6
         29+srYimsQ0e/Vu30F04InVQ/3Zyk+le9XYzkdfMr10+p/mrOSyOvy9g5KdeQJR+S8ZL
         /vuoJdks5r7c0rrZ9z1POjR+XXfo3uo2uzcN1H7BStJOvQ4s1Jm6hEquHd+4qzW8Ylsc
         cidQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=wDZsQlGgy4FqjwQIwrEXAV03acYkOeL2udsT8GFAkcM=;
        b=fpoEBRvmh7WzdIgKduZ9XL31DjE6I+QAcOv5e+nY+9QoNnZzci5G4ndF5h6uvNRO3O
         faLUfD/tWefOsYVKiABoABSV5Vue0fqbPWYs8G+yM8Aj09oSRH4A6U0rfV4BZ7F94rS4
         ruMSaKol51ErjrGNEkhmorsaGYDpJQB5fgWNwxjfooTmLMVs8UXFPmgWXr6TNgd++Kty
         VGhhfM6lyjjUhTfYLx8has6F4BpWxMkUZ5Y3YOMGyKzwbjazjxXYeBmCyQ/BL+m7dKD2
         u/94uP/kz51a6wBf8CYk/9GKFCRa23E8uTG9igP3Mk3LRL4IB71G+2dS9wG8/0apNQqw
         l4BA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=wDZsQlGgy4FqjwQIwrEXAV03acYkOeL2udsT8GFAkcM=;
        b=qlIM2nxoEWw9wFzSALgE+LxvDItUhOHyRdfUPXZF2j2HJLwTkAo+3GjNpGQQvqNM/m
         lMBTRG9iW3OmP79sa+s5ZAB0gDFj+iH+nUJNA+qLoruv6s0Z8f86R9EcslLRMsZHkDeo
         w2EqDeXOvUR075Znhe9OGAlZffiQuSeU1GCyC+Tx6GR3G2A5WpSO8Zc92HE1uIdkhMqD
         xt/m2ITudx21ifFzWVBPG0IZsu0hj/6yJWaAh2wiH0ZrEEoqR8SxEWN7ezasKYetgKqy
         adljhNnti905oo4/UEyEPNGfRmjfGRce2vupVXmdGRdbU386tHICLRYizf8Q4IKC38vp
         OK4g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532O2nl6lA+5ktFZOfqsWRAGdYWoeoa71TbAZInRJFuO/Wz8KxuQ
	lbqlhvdC2CzNyj9HeHUN6DY=
X-Google-Smtp-Source: ABdhPJza4x1UIHZQAZrd6Q8NRbR6jvZfMdj2ycV0E1wGonhHPFatFLwGhNDjuxHUrejYnE6o+i606A==
X-Received: by 2002:a05:6214:5cf:: with SMTP id t15mr193908qvz.119.1599573987126;
        Tue, 08 Sep 2020 07:06:27 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:620a:228d:: with SMTP id o13ls9546439qkh.9.gmail; Tue,
 08 Sep 2020 07:06:26 -0700 (PDT)
X-Received: by 2002:a37:6786:: with SMTP id b128mr235871qkc.396.1599573986425;
        Tue, 08 Sep 2020 07:06:26 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1599573986; cv=none;
        d=google.com; s=arc-20160816;
        b=ihU/SeXkF+5gibrur8YH/cgJXrDFz+snmnxw0onAAb4sFRbBJjsJ6XyVZ1QV7xVL0x
         xNcV4BZdZgDaok4vDII057Xs6He2UjXuI+DBy7A3P/W4fc8p9bUk8rDrUXzxigJcjSVg
         P/uh5VA0ojF9BARRu5LXeuSfLTpW5X0AoAwQSmVNhHw7f9ILJZs4wKZTA6I3YhMJqRkB
         YmTXWqSC2YQK9IyHhGV5W3Y9b/1isezaxJoWJdn4+uxR1h3m5zzqz/JgOiCfJF9dTsdF
         /vfNkYmSKXuOj6NVl1YCqguIWfAbF20hQrREJZLy8Avi9sOyOQol+1FpW/jDHDN57Hzy
         2/GQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=AUCwAbGfcmiyWAy7pWYJZE9xJYIble2uriaIWtRA0rs=;
        b=g+hVryNNEzeim/TMU77x+G9QzymXzirmB62AzrBQOo/91L303krPJ0a5+YwqIAl8QG
         /QRu92xtG4tQPvqsCVr3MycywC4DE+53LdhqoUSXeztX/QLErf3BnUt6LaKw1PHcIaXj
         qPcRz9XqY1qtOb7xHhd/hwAtxzOSDxGoWAfWzULZCnPahtSJFbgWZb8ty+ms/VXVY0Vn
         /9u9wIzfAezb/mEFHTAJpIjBCF0qteBO1AssiAii/UjfVqP8HaLh58JtJksld8PKFr1w
         KVXlHRoJNkNBfm+F+uNm/8bDzGO0jgUT3ruweJ9wgKhTgVD7OSqf+OZ2U0D1oQYc6upC
         4MeA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id e1si201031qka.0.2020.09.08.07.06.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 08 Sep 2020 07:06:26 -0700 (PDT)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from gaia (unknown [46.69.195.48])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id E9A062074B;
	Tue,  8 Sep 2020 14:06:22 +0000 (UTC)
Date: Tue, 8 Sep 2020 15:06:20 +0100
From: Catalin Marinas <catalin.marinas@arm.com>
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	kasan-dev <kasan-dev@googlegroups.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Elena Petrova <lenaptr@google.com>,
	Branislav Rankov <Branislav.Rankov@arm.com>,
	Kevin Brodsky <kevin.brodsky@arm.com>,
	Will Deacon <will.deacon@arm.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Linux ARM <linux-arm-kernel@lists.infradead.org>,
	Linux Memory Management List <linux-mm@kvack.org>,
	LKML <linux-kernel@vger.kernel.org>
Subject: Re: [PATCH 26/35] kasan, arm64: Enable TBI EL1
Message-ID: <20200908140620.GE25591@gaia>
References: <cover.1597425745.git.andreyknvl@google.com>
 <518da1e5169a4e343caa3c37feed5ad551b77a34.1597425745.git.andreyknvl@google.com>
 <20200827104033.GF29264@gaia>
 <CAAeHK+x_B+R3VcXndaQ=rwOExyQeFZEKZX-33oStiDFu1qePyg@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CAAeHK+x_B+R3VcXndaQ=rwOExyQeFZEKZX-33oStiDFu1qePyg@mail.gmail.com>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: catalin.marinas@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as
 permitted sender) smtp.mailfrom=cmarinas@kernel.org
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

On Tue, Sep 08, 2020 at 03:18:04PM +0200, Andrey Konovalov wrote:
> On Thu, Aug 27, 2020 at 12:40 PM Catalin Marinas
> <catalin.marinas@arm.com> wrote:
> >
> > On Fri, Aug 14, 2020 at 07:27:08PM +0200, Andrey Konovalov wrote:
> > > diff --git a/arch/arm64/mm/proc.S b/arch/arm64/mm/proc.S
> > > index 152d74f2cc9c..6880ddaa5144 100644
> > > --- a/arch/arm64/mm/proc.S
> > > +++ b/arch/arm64/mm/proc.S
> > > @@ -38,7 +38,7 @@
> > >  /* PTWs cacheable, inner/outer WBWA */
> > >  #define TCR_CACHE_FLAGS      TCR_IRGN_WBWA | TCR_ORGN_WBWA
> > >
> > > -#ifdef CONFIG_KASAN_SW_TAGS
> > > +#if defined(CONFIG_KASAN_SW_TAGS) || defined(CONFIG_KASAN_HW_TAGS)
> > >  #define TCR_KASAN_FLAGS TCR_TBI1
> > >  #else
> > >  #define TCR_KASAN_FLAGS 0
> >
> > I prefer to turn TBI1 on only if MTE is present. So on top of the v8
> > user series, just do this in __cpu_setup.
> 
> Started working on this, but realized that I don't understand what
> exactly is suggested here. TCR_KASAN_FLAGS are used in __cpu_setup(),
> so this already happens in __cpu_setup().
> 
> Do you mean that TBI1 should be enabled when CONFIG_ARM64_MTE is
> enabled, but CONFIG_KASAN_HW_TAGS is disabled?

What I meant is that we should turn TBI1 only when the MTE is present in
hardware (and the ARM64_MTE option is on). But I probably missed the way
MTE is used with KASAN.

So what happens if CONFIG_KASAN_HW_TAGS and CONFIG_ARM64_MTE are both on
but the hardware does not support MTE? Does KASAN still generate tagged
pointers? If yes, then the current patch is fine, we should always set
TBI1.

-- 
Catalin

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200908140620.GE25591%40gaia.
