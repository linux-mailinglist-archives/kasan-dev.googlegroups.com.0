Return-Path: <kasan-dev+bncBCCMH5WKTMGRBHX7Q2HAMGQEJUM75OQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73a.google.com (mail-qk1-x73a.google.com [IPv6:2607:f8b0:4864:20::73a])
	by mail.lfdr.de (Postfix) with ESMTPS id 8954747BF1E
	for <lists+kasan-dev@lfdr.de>; Tue, 21 Dec 2021 12:50:56 +0100 (CET)
Received: by mail-qk1-x73a.google.com with SMTP id ay43-20020a05620a17ab00b0046dcc2fb1c7sf8121785qkb.2
        for <lists+kasan-dev@lfdr.de>; Tue, 21 Dec 2021 03:50:56 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1640087454; cv=pass;
        d=google.com; s=arc-20160816;
        b=QpaOe7O2UJmNMHPohKEdGyanoTSOiMLd60tG6S2D3ETum8gk9tuC7KP68giWmUfET1
         CXvm34xdAor2pVgyFG8MDHST8B8wcEOdf5P67PCtW4eZX3b8v2hPictzqnjDdNtP/fGy
         a+RYIODhnHn3QlXP64chqYIBpCj4Dvps1Erw3UBK79nB5s/dyAdi7ruVU3Jca+5Hl8//
         lZaHXW+sIFdUevq4yqSeJuGKbXvgq9SP4BBfdQAV7JuDhHCxIqk3uKJqninSiB0LovSC
         9c5KdHpoiq0h5UucO/fGLdr2uQlpxRPr8snSQUUzhgatVyX7nCLW06iaPVD1XSOLIsJ/
         Rpkg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=3jIy7WAlZ1+eaubJBDCh3M+Ktzf2Aj4I9gbDNlW+X1E=;
        b=ydsBwTlpKdzg9BGSweyhRDoBY4sgf3u3Ha4B5aYtK2DE+66S4BkS/QP5x/cb1upYhC
         CmlfqnSNEkmw1MeaR1De8L9+AyQ87ASon8tJgowJuUITXtxAeRlbL/fzVTSzOES/fwOg
         UwmxgVgfonb50TZNRWE7jYI7gKTEzvLhk3cFmuNw4nDM9+vpJEYhnnTJeY77Tltf6Ysn
         05DyLAVxJNL52MZT9HTHZr2DsNjkEBfsTiVbTwPTMF4gXffIRjuj/P+RqXqzidMVSqMx
         pSEQOoCppkaxQHHkp0OF1JPAbb4SzqfBBAoSEuQadQBVKlDz+480XLqCmEJISwzJgwcF
         guhw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=Jd1uTy1J;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::735 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=3jIy7WAlZ1+eaubJBDCh3M+Ktzf2Aj4I9gbDNlW+X1E=;
        b=azYT4zt5/aC/SAK0/gJwWZXdHB12BFQcSBk8LUTtKNXEi++GtGOXGMvI27yvHMW7tc
         8i6jChCcFO+vsfZgJA3Q7bORvsyOUOocYvsJjQRPG3ibozdurrnJBLYdGO9YQo5TydRP
         rrmk6Xhnk2zWODZ7qDUNqlLW48omo8TgzjPlQ1/gHWaY7bdOz1Yv7L7YkZZxY2Y/DDnC
         boidbbRriku9VnUF+b5OcfP8qo+QVfrSUMf60m6vqDPY15AvhZuO6NyhMW1UQcuC6yKd
         5u3t83DAM3TuFsR0akGp64D3jcRWaWfsvWJi2akUJCCJeViLrs3urczK3Z1TdRn+VsMt
         Ehog==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=3jIy7WAlZ1+eaubJBDCh3M+Ktzf2Aj4I9gbDNlW+X1E=;
        b=Va/JZOS2Gtp2IdN40DzpgpUpcWi0/HPfztSaDMWCQbs8GY8aPrbWAM/G6W1ZekHhYK
         tQ732usMOv/JP5SSWGEhNqS7wYjonmkjWorSiO2g8LEeA4PNYWTD5tAYsCDzkfT0KRmt
         ugShByCwZBSmOWQn37g8NJBKHoAcpvU90PZGOnMfGPApmrqAvbW6dza0aqu+5DbrfaTG
         8Nu5h2gJVV7APf4FSL44PFeiHTe8F0sJ5SmnTdgA/QlbOhbmKFowwMAq9KOTnvwIWASk
         MMzd0cFoMnpyvCtD2fQ6eGdJ4QoI+rZGtWMpkoj9nG0P+Y4C9iFieGiX9HSFfp9Phb0R
         i9iw==
X-Gm-Message-State: AOAM530PJdhLLQJO1qS83it9t0wpDC/xtBw5WVWJswx4+WDK5wVvTuB5
	XVU8uc6NBZ2TVVoNzMuIyUs=
X-Google-Smtp-Source: ABdhPJwAZlddkayOqOq/dgrjt0HqYhCkU6Sy+j+GdyHuXhA1fFPFy+TzAYEaqLA1oflwST/FRu6npA==
X-Received: by 2002:a05:620a:2550:: with SMTP id s16mr1551324qko.275.1640087454522;
        Tue, 21 Dec 2021 03:50:54 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:620a:4048:: with SMTP id i8ls9643501qko.2.gmail; Tue, 21
 Dec 2021 03:50:54 -0800 (PST)
X-Received: by 2002:a05:620a:2f9:: with SMTP id a25mr1586456qko.327.1640087454117;
        Tue, 21 Dec 2021 03:50:54 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1640087454; cv=none;
        d=google.com; s=arc-20160816;
        b=QhF4cquKYcSdr3rKaNnCSvrNK2Nr+ahXzJ2ysblPPEW16mE7e2tO0uNERCs9+GIqxU
         Ay7sNjvx6ntc1ceIILPF5ManHiJbZMnJ20YIjWbpumbCu9YVg12KBA47kWmag3hHKYaW
         Un3TwDYPLmawnc2IUt1tYU2aKJyaxEARm8aSgvQZe3N49mza3yXmYuMEwQnjKpbYnvX4
         aODgY7zvj8P15uu7GMYyvk9ImO2DvSq3eMR4onJQgHgVLO3gbQL1LFP8T4nK64ZLnYoc
         g/jZaA0cUurAfHM2hflVksRP+6HUHBCx8r4eET2moICChat3owY0c8hyed7cZ43mHZpc
         Gthw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=CKZ8wh0vEyxLoOe3LBJ6ThWF5mIZ4gbWo8APS57Mm8M=;
        b=cSF+ZLxosXHzLTR/3OI8gpqwywrM3YiokwRgIUyZ6AUNYqiqcifQzKMPEEghilwD89
         zeVks/6E+d0hDwiDMvTUfajxiuWyQiHrMLx+VXyIcU3uKkOQp0ssroHMPkq3YrAiTlJh
         sJf92/h0gyAMnrAC7dE/MFxAp9uWIZhFGYUOrYVIX7CYxpYvtnrYcyJqGuN2NrkVSM7j
         EAoqVKdjzwIiHwNA5pLslyefv6cm7tUCu/HdYGruUNiewnITCFwbTE/vDtG8kz+tDvsT
         VtZsVrB2gglE8PNHsgPQpW5Tri4lOitxaPbxrqpj7iXC+xtpkhqwLjnJcseV2TFQz+l+
         YWoA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=Jd1uTy1J;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::735 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x735.google.com (mail-qk1-x735.google.com. [2607:f8b0:4864:20::735])
        by gmr-mx.google.com with ESMTPS id u2si1340355qkp.6.2021.12.21.03.50.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 21 Dec 2021 03:50:54 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::735 as permitted sender) client-ip=2607:f8b0:4864:20::735;
Received: by mail-qk1-x735.google.com with SMTP id b67so12227331qkg.6
        for <kasan-dev@googlegroups.com>; Tue, 21 Dec 2021 03:50:54 -0800 (PST)
X-Received: by 2002:a05:620a:2955:: with SMTP id n21mr1581145qkp.581.1640087453160;
 Tue, 21 Dec 2021 03:50:53 -0800 (PST)
MIME-Version: 1.0
References: <cover.1640036051.git.andreyknvl@google.com> <516dc726dc6311d8bb9f1a90258190f628a3b636.1640036051.git.andreyknvl@google.com>
In-Reply-To: <516dc726dc6311d8bb9f1a90258190f628a3b636.1640036051.git.andreyknvl@google.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 21 Dec 2021 12:50:17 +0100
Message-ID: <CAG_fn=UJErkCbrF5f6RW8RbvKLV3k6Gxb-ZrjPMMbS5MvNtN0Q@mail.gmail.com>
Subject: Re: [PATCH mm v4 26/39] kasan, vmalloc: unpoison VM_ALLOC pages after mapping
To: andrey.konovalov@linux.dev
Cc: Marco Elver <elver@google.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux Memory Management List <linux-mm@kvack.org>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will@kernel.org>, 
	Mark Rutland <mark.rutland@arm.com>, Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Peter Collingbourne <pcc@google.com>, Evgenii Stepanov <eugenis@google.com>, LKML <linux-kernel@vger.kernel.org>, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=Jd1uTy1J;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::735 as
 permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

On Mon, Dec 20, 2021 at 11:02 PM <andrey.konovalov@linux.dev> wrote:
>
> From: Andrey Konovalov <andreyknvl@google.com>
>
> Make KASAN unpoison vmalloc mappings after they have been mapped in
> when it's possible: for vmalloc() (indentified via VM_ALLOC) and
> vm_map_ram().
>
> The reasons for this are:
>
> - For vmalloc() and vm_map_ram(): pages don't get unpoisoned in case
>   mapping them fails.
> - For vmalloc(): HW_TAGS KASAN needs pages to be mapped to set tags via
>   kasan_unpoison_vmalloc().
>
> As a part of these changes, the return value of __vmalloc_node_range()
> is changed to area->addr. This is a non-functional change, as
> __vmalloc_area_node() returns area->addr anyway.
>
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Reviewed-by: Alexander Potapenko <glider@google.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAG_fn%3DUJErkCbrF5f6RW8RbvKLV3k6Gxb-ZrjPMMbS5MvNtN0Q%40mail.gmail.com.
