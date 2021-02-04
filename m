Return-Path: <kasan-dev+bncBCCJX7VWUANBBSH36CAAMGQEX4DR25I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73d.google.com (mail-qk1-x73d.google.com [IPv6:2607:f8b0:4864:20::73d])
	by mail.lfdr.de (Postfix) with ESMTPS id 3DE1130FB74
	for <lists+kasan-dev@lfdr.de>; Thu,  4 Feb 2021 19:32:41 +0100 (CET)
Received: by mail-qk1-x73d.google.com with SMTP id u66sf3439154qkd.13
        for <lists+kasan-dev@lfdr.de>; Thu, 04 Feb 2021 10:32:41 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1612463560; cv=pass;
        d=google.com; s=arc-20160816;
        b=smg0s0MqZM0JtQ7U16+GJEcxufnyEVkrr3fwhHh8lMlpdh/v2BRTZrVk/LI/52fe9j
         tDLq/OPITBbdcFwR3Wyfsr3cO+qdVXBEExswv1EpfX9fXM/VELDg+9rse6JKD0/b1qwA
         UOjNYJUSLHrGOiR84PnM83JRUUpvslPnkWqUc5a18tCAcDHk3EhdbZHXBMEqEmd4TfWl
         to0F3H8G7oCI1fY1Kg7W70raRzaxtG7FJINJ4ZNU4jthGIQilW36dPbB8GFIDjfoGpx0
         FyZ75S6YuyNv5i7+xdUOywyroocr3CDTHcplgOYue8Y4cFzGMp2UzEt8ophB1bXYw45H
         T2UQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=ExPFLycKS5cdRRyryfHxalbLq8NjcCWKWbHnUylJ/xI=;
        b=PJtT3Eb/5Um3CVysEZfS+cSBSYWeAaQtRhM4AzX6ZJ2KnQFtxP02XntpXURNRAU604
         DyZsUmxCRZ5skrqHfqb57/1+NEWLJZhl+ND2ew5Zv79PLSecMxzdBQZLbJgoN8d0iZUU
         sOOEble0HykLa2gtmlBI5n8N65Qo3Ffaf6jPLuB06X4dgkvWGzWYvFeUw0K8XCVfHpKh
         A5gVEiwKLyYhwBKAQ02MuC4q53pA3HXI9L7D/JT1OfExN9iaD5i20hpc0SZ3P5lSsWUz
         Mn3P7sP6dPL8cjJoS/csu3huC2RxhrKyce+2TBz9z6oijf+YP+BIrJ4qNIH9M1q2DQXH
         PQoQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=EdUuwlQn;
       spf=pass (google.com: domain of lecopzer@gmail.com designates 2607:f8b0:4864:20::432 as permitted sender) smtp.mailfrom=lecopzer@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ExPFLycKS5cdRRyryfHxalbLq8NjcCWKWbHnUylJ/xI=;
        b=sqc5jDKDFX4vLCFWklVBddmN2EPMEdYKhuGGBnydToVO5DeggXOminEAe1nmUDlNb7
         BiB6czoCscTJx7PR+sIkZYr8Wlm6bu76ebBocjQK2uUjWicE23PzJWgjL5zg6RL+NtRD
         Pcv4GGGevjWQdkCFYXbHZqwOxs7U2hL2xIKuHNof4nB13h4X0ic5ekywhhgw1TECGnlr
         OIyguOKqR0/WK0ZqB52ESW5yhnJBhzDX9jMuSFXGCvBK+Hop3fgDnb7XQx5Q5k09zwlU
         z3tV+RPJ5vekpeZWEwxtZPdOJgmXYmpCWWUM1B5Koy/4alWh72nq8O9BwLh5Z9tVrU9T
         Vdcg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ExPFLycKS5cdRRyryfHxalbLq8NjcCWKWbHnUylJ/xI=;
        b=l00BH3vwhLfy2Y8RxTrX/isVb6Yq1DQXFaUJZvQ10Z1cutCh4ratUD56VJ99qVAV5S
         AV6mbsdz8ubKuiHiCpoC0hnLVK/yvhLe6EAlDZYB04NTsaak9AMC/Wpfr/wwIXLxFMPg
         LAN2dI4/6E50pOVmUEr8TrSw7t1RHQLE7AcfuEZ4JyqoKVj+PkkvMVuHg6jV7UL1D5Pq
         Jxguv18wrCj4uT905Xbk5jWMvQueAbBQUx5D5yDzEQRnTfrVtcnEUI/AsU46zGqraf1O
         jQ5Ux/C0PBM4cRio5hKajjL2UGq1EjPvaHsGWLXKuHX8ehG81Sovo7PfoudsDH9NiR52
         IQSg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ExPFLycKS5cdRRyryfHxalbLq8NjcCWKWbHnUylJ/xI=;
        b=USgKxbvPq/YS+DTe+pJBcvi3Q0h9a3WPOICFoYIUclAaGqCjYvcBceJb64I9UmHaTA
         +mCM5wkDOewOAlFhMkwg9TDNl02uHmNkyrdIr1l8p0ewksVehCaYt/N588DHQ+CAoR47
         pigpX1vAyLm0Yo+bcgH0mKHDCOFo8fRo0YdmSUVwrUKw87xCvWbOYOoK1RSH8Uv7O10l
         pOEsEeONeTu+wrSB/WsUcbjonKx3wr6qCRFTRJ5fIw/WVzZqWsc7QFUbDJjU9UXGKIEw
         jgrDmXPbYnieiDFqNWI0PBqaNSlNKtO2tq6J2WNqbg4X8HJVOmWA5/2SdpSk98KfedqO
         dQzQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532bGOtH0TdlMxhqml5vpjWV4q8pMY4CH49YwPmZWjYoRvf5tMbg
	ENfdPPn1AlsjyjeTPjVXYSs=
X-Google-Smtp-Source: ABdhPJwSLvxxotf+QAbu48ksLya6w2I36pVFuhyJt8gmmOIv+TP1ODIYqpeQ5egpr1TwWLlDt0mE6A==
X-Received: by 2002:a05:6214:136e:: with SMTP id c14mr710391qvw.59.1612463560146;
        Thu, 04 Feb 2021 10:32:40 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:4816:: with SMTP id g22ls2483118qtq.11.gmail; Thu, 04
 Feb 2021 10:32:39 -0800 (PST)
X-Received: by 2002:aed:2821:: with SMTP id r30mr872347qtd.364.1612463559677;
        Thu, 04 Feb 2021 10:32:39 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1612463559; cv=none;
        d=google.com; s=arc-20160816;
        b=LxTR3MshE7lx5L5xoOdQuK3YRd/7lY/P9xpx++IsJ8GBS5tNanA26mRwdMLF9wbTX7
         xKa7Kt4teyLMaX2gqE4xs09ZPtiCQqQqgbtuAc52kt/xLiOR/R5P54gMS0J+Q4QCRN4l
         pgVEn+C1z+v2jsrmwqQgPDBJ/MVXpydpftSl+/G2+W+WWmNPWyR6NCRbFZ0xFPtDDmqW
         OspG/+savUYKR7twSbc+1JEaerTePky51IzWDwWB/fmrXcqdMyLpodOv1WGyf0CtTYO4
         yeTA9/+Bx5Dbcxmt+z1MCvcBoFl+L13sLCOWqvcRkGqkjJwBzOukdYWHXNKQ9BPpNzUe
         PzzA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Vr29zfd+YKuYiJH6SfU+iXid1sSoH649Xg+y7HCfk/M=;
        b=W4ZAV24Cm4dx7b1/I55FYmtrh2CjA4eM/ikIkx7sPQb/TxPfx4kyZK/zf3+UQ0VEt1
         RRbWkmJ5RD5EiZ5g1kBOWF8NUXx1xuGB6rGoXjnGB9/4KrI6QuI5sE3wTB7JZsrvxMXM
         k4xUAbmhFbHjdIdpfszhh8PiTXgGenkjXY95w8fmldB6MmJ8GlmSvRnKkGmdXEA37eSj
         Sr7gu70HiqBfTIflBrBBn9mSIuDL0kNmQDgtIf1x056FhSmXSqYm9Ftsgv2EzvZFBA+d
         MG1AFfpUW5PhQqr3B+JfThihWLHKheGfzQqvZneOCP/s29znH6xDj/3L9NzhbLNiNIXv
         dAXQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=EdUuwlQn;
       spf=pass (google.com: domain of lecopzer@gmail.com designates 2607:f8b0:4864:20::432 as permitted sender) smtp.mailfrom=lecopzer@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pf1-x432.google.com (mail-pf1-x432.google.com. [2607:f8b0:4864:20::432])
        by gmr-mx.google.com with ESMTPS id j40si599560qtk.2.2021.02.04.10.32.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 04 Feb 2021 10:32:39 -0800 (PST)
Received-SPF: pass (google.com: domain of lecopzer@gmail.com designates 2607:f8b0:4864:20::432 as permitted sender) client-ip=2607:f8b0:4864:20::432;
Received: by mail-pf1-x432.google.com with SMTP id w18so2640045pfu.9
        for <kasan-dev@googlegroups.com>; Thu, 04 Feb 2021 10:32:39 -0800 (PST)
X-Received: by 2002:a63:4d52:: with SMTP id n18mr270960pgl.237.1612463558781;
 Thu, 04 Feb 2021 10:32:38 -0800 (PST)
MIME-Version: 1.0
References: <20210204124914.GC20468@willie-the-truck> <20210204155346.88028-1-lecopzer@gmail.com>
 <20210204175659.GC21303@willie-the-truck>
In-Reply-To: <20210204175659.GC21303@willie-the-truck>
From: Lecopzer Chen <lecopzer@gmail.com>
Date: Fri, 5 Feb 2021 02:32:27 +0800
Message-ID: <CANr2M1845fSW0kGw9mp4SOqSjQj0qV66eFrm4BU9szTSk=x+0Q@mail.gmail.com>
Subject: Re: [PATCH v2 0/4] arm64: kasan: support CONFIG_KASAN_VMALLOC
To: Will Deacon <will@kernel.org>
Cc: Andrew Morton <akpm@linux-foundation.org>, Andrey Konovalov <andreyknvl@google.com>, ardb@kernel.org, 
	aryabinin@virtuozzo.com, broonie@kernel.org, catalin.marinas@arm.com, 
	dan.j.williams@intel.com, dvyukov@google.com, glider@google.com, 
	gustavoars@kernel.org, kasan-dev@googlegroups.com, lecopzer.chen@mediatek.com, 
	linux-arm-kernel@lists.infradead.org, linux-kernel@vger.kernel.org, 
	linux-mediatek@lists.infradead.org, linux-mm@kvack.org, linux@roeck-us.net, 
	robin.murphy@arm.com, rppt@kernel.org, tyhicks@linux.microsoft.com, 
	vincenzo.frascino@arm.com, yj.chiang@mediatek.com
Content-Type: multipart/alternative; boundary="000000000000a26d8405ba86edb1"
X-Original-Sender: lecopzer@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=EdUuwlQn;       spf=pass
 (google.com: domain of lecopzer@gmail.com designates 2607:f8b0:4864:20::432
 as permitted sender) smtp.mailfrom=lecopzer@gmail.com;       dmarc=pass
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

--000000000000a26d8405ba86edb1
Content-Type: text/plain; charset="UTF-8"

On Thu, Feb 04, 2021 at 11:53:46PM +0800, Lecopzer Chen wrote:
> > > On Sat, Jan 09, 2021 at 06:32:48PM +0800, Lecopzer Chen wrote:
> > > > Linux supports KAsan for VMALLOC since commit 3c5c3cfb9ef4da9
> > > > ("kasan: support backing vmalloc space with real shadow memory")
> > > >
> > > > Acroding to how x86 ported it [1], they early allocated p4d and pgd,
> > > > but in arm64 I just simulate how KAsan supports MODULES_VADDR in
> arm64
> > > > by not to populate the vmalloc area except for kimg address.
> > >
> > > The one thing I've failed to grok from your series is how you deal with
> > > vmalloc allocations where the shadow overlaps with the shadow which has
> > > already been allocated for the kernel image. Please can you explain?
> >
> >
> > The most key point is we don't map anything in the vmalloc shadow
> address.
> > So we don't care where the kernel image locate inside vmalloc area.
> >
> >   kasan_map_populate(kimg_shadow_start, kimg_shadow_end,...)
> >
> > Kernel image was populated with real mapping in its shadow address.
> > I `bypass' the whole shadow of vmalloc area, the only place you can find
> > about vmalloc_shadow is
> >       kasan_populate_early_shadow((void *)vmalloc_shadow_end,
> >                       (void *)KASAN_SHADOW_END);
> >
> >       -----------  vmalloc_shadow_start
> >  |           |
> >  |           |
> >  |           | <= non-mapping
> >  |           |
> >  |           |
> >  |-----------|
> >  |///////////|<- kimage shadow with page table mapping.
> >  |-----------|
> >  |           |
> >  |           | <= non-mapping
> >  |           |
> >  ------------- vmalloc_shadow_end
> >  |00000000000|
> >  |00000000000| <= Zero shadow
> >  |00000000000|
> >  ------------- KASAN_SHADOW_END
> >
> > vmalloc shadow will be mapped 'ondemend', see kasan_populate_vmalloc()
> > in mm/vmalloc.c in detail.
> > So the shadow of vmalloc will be allocated later if anyone use its va.
>
> Indeed, but the question I'm asking is what happens when an on-demand
> shadow
> allocation from vmalloc overlaps with the shadow that we allocated early
> for
> the kernel image?
>
> Sounds like I have to go and read the code...
>

oh, sorry I misunderstood your question.

FWIW,
I think this won't happend because this mean vmalloc() provides va which
already allocated by kimg, as I know, vmalloc_init() will insert early
allocated vma into its vmalloc rb tree

> , and this early allocated vma will include  kernel image.

After quick review of mm init code,
this early allocated for vma is at map_kernel() in arch/arm64/mm/mmu.c



BRs
Lecopzer

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANr2M1845fSW0kGw9mp4SOqSjQj0qV66eFrm4BU9szTSk%3Dx%2B0Q%40mail.gmail.com.

--000000000000a26d8405ba86edb1
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<div dir=3D"auto"><div><br><br><div class=3D"gmail_quote"><div dir=3D"ltr" =
class=3D"gmail_attr"><br></div><blockquote class=3D"gmail_quote" style=3D"m=
argin:0 0 0 .8ex;border-left:1px #ccc solid;padding-left:1ex">On Thu, Feb 0=
4, 2021 at 11:53:46PM +0800, Lecopzer Chen wrote:<br>
&gt; &gt; On Sat, Jan 09, 2021 at 06:32:48PM +0800, Lecopzer Chen wrote:<br=
>
&gt; &gt; &gt; Linux supports KAsan for VMALLOC since commit 3c5c3cfb9ef4da=
9<br>
&gt; &gt; &gt; (&quot;kasan: support backing vmalloc space with real shadow=
 memory&quot;)<br>
&gt; &gt; &gt; <br>
&gt; &gt; &gt; Acroding to how x86 ported it [1], they early allocated p4d =
and pgd,<br>
&gt; &gt; &gt; but in arm64 I just simulate how KAsan supports MODULES_VADD=
R in arm64<br>
&gt; &gt; &gt; by not to populate the vmalloc area except for kimg address.=
<br>
&gt; &gt; <br>
&gt; &gt; The one thing I&#39;ve failed to grok from your series is how you=
 deal with<br>
&gt; &gt; vmalloc allocations where the shadow overlaps with the shadow whi=
ch has<br>
&gt; &gt; already been allocated for the kernel image. Please can you expla=
in?<br>
&gt; <br>
&gt; <br>
&gt; The most key point is we don&#39;t map anything in the vmalloc shadow =
address.<br>
&gt; So we don&#39;t care where the kernel image locate inside vmalloc area=
.<br>
&gt; <br>
&gt;=C2=A0 =C2=A0kasan_map_populate(kimg_shadow_start, kimg_shadow_end,...)=
<br>
&gt; <br>
&gt; Kernel image was populated with real mapping in its shadow address.<br=
>
&gt; I `bypass&#39; the whole shadow of vmalloc area, the only place you ca=
n find<br>
&gt; about vmalloc_shadow is<br>
&gt;=C2=A0 =C2=A0 =C2=A0 =C2=A0kasan_populate_early_shadow((void *)vmalloc_=
shadow_end,<br>
&gt;=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =
=C2=A0 =C2=A0(void *)KASAN_SHADOW_END);<br>
&gt; <br>
&gt;=C2=A0 =C2=A0 =C2=A0 =C2=A0-----------=C2=A0 vmalloc_shadow_start<br>
&gt;=C2=A0 |=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0|<br>
&gt;=C2=A0 |=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0| <br>
&gt;=C2=A0 |=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0| &lt;=3D non-mapping<=
br>
&gt;=C2=A0 |=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0|<br>
&gt;=C2=A0 |=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0|<br>
&gt;=C2=A0 |-----------|<br>
&gt;=C2=A0 |///////////|&lt;- kimage shadow with page table mapping.<br>
&gt;=C2=A0 |-----------|<br>
&gt;=C2=A0 |=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0|<br>
&gt;=C2=A0 |=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0| &lt;=3D non-mapping<=
br>
&gt;=C2=A0 |=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0|<br>
&gt;=C2=A0 ------------- vmalloc_shadow_end<br>
&gt;=C2=A0 |00000000000|<br>
&gt;=C2=A0 |00000000000| &lt;=3D Zero shadow<br>
&gt;=C2=A0 |00000000000|<br>
&gt;=C2=A0 ------------- KASAN_SHADOW_END<br>
&gt; <br>
&gt; vmalloc shadow will be mapped &#39;ondemend&#39;, see kasan_populate_v=
malloc()<br>
&gt; in mm/vmalloc.c in detail.<br>
&gt; So the shadow of vmalloc will be allocated later if anyone use its va.=
<br>
<br>
Indeed, but the question I&#39;m asking is what happens when an on-demand s=
hadow<br>
allocation from vmalloc overlaps with the shadow that we allocated early fo=
r<br>
the kernel image?<br>
<br>
Sounds like I have to go and read the code...<br></blockquote></div></div><=
div dir=3D"auto"><br></div><div dir=3D"auto">oh, sorry I misunderstood your=
 question.</div><div dir=3D"auto"><br></div><div dir=3D"auto">FWIW,</div><d=
iv dir=3D"auto">I think this won&#39;t happend because this mean vmalloc() =
provides va which already allocated by kimg, as I know, vmalloc_init() will=
 insert early allocated vma into its vmalloc rb tree</div><div dir=3D"auto"=
><div class=3D"gmail_quote"><blockquote class=3D"gmail_quote" style=3D"marg=
in:0 0 0 .8ex;border-left:1px #ccc solid;padding-left:1ex"></blockquote></d=
iv></div><div dir=3D"auto">, and this early allocated vma will include=C2=
=A0 kernel image.</div><div dir=3D"auto"><br></div><div dir=3D"auto">After =
quick review of mm init code,</div><div dir=3D"auto">this early allocated f=
or vma is at map_kernel() in arch/arm64/mm/mmu.c</div><div dir=3D"auto"><br=
></div><div dir=3D"auto"><br></div><div dir=3D"auto"><br></div><div dir=3D"=
auto">BRs</div><div dir=3D"auto">Lecopzer</div><div dir=3D"auto"><br></div>=
<div dir=3D"auto"><br></div><div dir=3D"auto"><div class=3D"gmail_quote"><b=
lockquote class=3D"gmail_quote" style=3D"margin:0 0 0 .8ex;border-left:1px =
#ccc solid;padding-left:1ex"></blockquote></div></div></div>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion on the web visit <a href=3D"https://groups.google.c=
om/d/msgid/kasan-dev/CANr2M1845fSW0kGw9mp4SOqSjQj0qV66eFrm4BU9szTSk%3Dx%2B0=
Q%40mail.gmail.com?utm_medium=3Demail&utm_source=3Dfooter">https://groups.g=
oogle.com/d/msgid/kasan-dev/CANr2M1845fSW0kGw9mp4SOqSjQj0qV66eFrm4BU9szTSk%=
3Dx%2B0Q%40mail.gmail.com</a>.<br />

--000000000000a26d8405ba86edb1--
