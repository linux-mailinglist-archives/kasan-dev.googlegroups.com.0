Return-Path: <kasan-dev+bncBDX4HWEMTEBRBM5P335AKGQETSNDYLI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x138.google.com (mail-il1-x138.google.com [IPv6:2607:f8b0:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id 695132612D2
	for <lists+kasan-dev@lfdr.de>; Tue,  8 Sep 2020 16:39:48 +0200 (CEST)
Received: by mail-il1-x138.google.com with SMTP id v16sf5918339ilh.15
        for <lists+kasan-dev@lfdr.de>; Tue, 08 Sep 2020 07:39:48 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1599575987; cv=pass;
        d=google.com; s=arc-20160816;
        b=aFIX8fBp/p32NcuKvai4IMgvAGm7Fs0KNE68stUljv6PNIGYIXAgMHuRwwBGgxt0p0
         tvThQGIMl1lxcd0yz6tbe2sH5cSMxeI3OzK2cLnXr2Zz/o1YzA/3SRM1qVAUuCFPdgyE
         fNjPVS5+hUIKpvQIDnUUAufHslJFcd6cYnqER7fjauAA3H88jZF2xZwuayFXUNtBH+C5
         1SOQyPyuLbHlqbb5EX6pSw2IN2Kb3zb4mgumaSN7y26m4Lmh+bf0Lm3do4UkfEQ4mhZS
         hVQn0iVBq/RNWOsJFGI973zz6FvFuwLDBwxn6A3zj7pZeExXGUQ/9TvL2m5cjivyMXmL
         ZjEA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=VlBK5D0NINMHP5GtPj3mfZRUTCI62S57ZPJRfQ3BnWA=;
        b=s++O7pT8QWjte+EmV/yD3dQ32N/zjXQBXAWDM5Jp6luiXZ0i22oHrayi7Tz55BageZ
         G5os+WhTcx/hMpMmZsvpYdvcmm3TCDP8UnJh6Pwj8xw1qF8D60rlv8cPgarChSrrBM2u
         MhqR9nBXT3Zt0iKKrxeK9LI8ZxxTXFiW7cet+O5crI1HMl8NQCDL4paaysDjdWgDECwc
         3DFg+ofFH/TRK/kdc2D9sWopif2LdwQtvL6vyswgjjz3HZFy64MKkiL6bW1P83ldrErA
         Alufbzg5DBjOSjq8bdGW0E/D6a6IO4YP5FqhY3a21KEVI7W/D6sNbrqWMTQDvtfPRoSh
         To9Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=cv+LslJ4;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::1041 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=VlBK5D0NINMHP5GtPj3mfZRUTCI62S57ZPJRfQ3BnWA=;
        b=BJd+XupUdaze4iWkAg+xhGUA2IU1j7lyo+YdnsI9hSkguNGPW98uZ1EAa4Kzvgd326
         itrsMM8YSyktIaZTTOD7Xt+IwfOjhoQNxd6Em2ddTfans86Ja2HoOkJTGFHz6QJijGju
         pJhhTxjTOPmfGv02w6IZpLahEv6ZDbXJpkOEaoZLB8PMRcpIrorF2at8mxhCejyotyTY
         HeXofFMvv3QAIJqcv6lYWNPCl3CqTJhR85oohp8feKdzX4mxLdgKk0rzvRDZzP7narep
         JcHD10aVUpzq5qUSWCTlVfFfFAPEZH0wrKT5xa8JZ4UQTN25lFxxGYUbc8NsNKw78qiG
         Cfrg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=VlBK5D0NINMHP5GtPj3mfZRUTCI62S57ZPJRfQ3BnWA=;
        b=nQnpVCCF7zKUmMdL3cZJ3L2BXx/JlRlUerlJxdlw9bjFEscg9u9pdyu3kr1pdUw1aI
         rvBhDkN1QgCyc8UqrP8c1ZElWvyxg+0mx49gSj+ACc3JncjIZMDoruHKhhBN6eo9mbH6
         A4bWMXfuUgPnXISUgdj9iIVNhJhOQRI1ixx0ePbCOiKaBVrfvgh/1PMcSR/FroKmx8dN
         dndORc6usqfOMJ3ixaCBwiv68TrAhCoU2IzOeZ/WHUfzaP+WiIJnSCblnf/kOC5HEFLL
         9QI93/QNZQXtlDSewwec2GAdya1xfU13yD0B0eZ4RIoUrkXTa1rrf1pWrai5Md05yKz5
         QpZA==
X-Gm-Message-State: AOAM530A04zpkBuJndybc3s+0HMYAdXmwK5IPj+yw+MRIIlCoj42B3MJ
	d9q7TWdgnh0n8JxYs13bx6o=
X-Google-Smtp-Source: ABdhPJydOOdFOO22C/XbzpP0h+dNKiJRUREaTCC73s182gwT6MzZHTYxJO+PY4roUW3Y7CxKRMETkg==
X-Received: by 2002:a05:6638:144:: with SMTP id y4mr24023687jao.61.1599575987262;
        Tue, 08 Sep 2020 07:39:47 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:5bce:: with SMTP id c75ls2330236ilg.8.gmail; Tue, 08 Sep
 2020 07:39:47 -0700 (PDT)
X-Received: by 2002:a05:6e02:ef1:: with SMTP id j17mr8870313ilk.211.1599575986973;
        Tue, 08 Sep 2020 07:39:46 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1599575986; cv=none;
        d=google.com; s=arc-20160816;
        b=zBGVhakxuG4xvTG6VHf7OcLkWWNdRpulcBJf739pjmriFDkswoht9kp4Y0YOjm+rxW
         hXNJL4juFikpkF338GMbpo9/B5CZCwFjhGDnriaXmlz0SnAEwkKVU2tXrY3F/276l9Q7
         IFQXuSRLvr92BTSp7h/6b5iI2VvCXoDiMnwCpINeN4zv3rISbPJN6nUVJJ/x1EX8abLh
         d9cXfq6wlxtAYVNlU73yjCv/JloVJxVWeF5CN0wCBaAt6sm7Ox5PzXr1Au1SfVl1PGlN
         JpbQSz4Kr1Dl+KD0wmNR+9aci9XuVG2751L1/fRD9QaL8iTPWaFmppE6orummRnXUY6H
         orLA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=u6IZBEYdJUicGrUE54qThuMWVgXq8hL/oKiMR3tNmWw=;
        b=ciNFXWhGADOcbEebjK8uFKRrUIMOCPa5Hzabo7bpBKjBvXcG2ecKhKzCgyQS+B3kBA
         /CkrDh9bqGJS5BFh08aT6LvM7k7tp05FR8Gq/n6WGZZsWiXGeEjwF3Kejtq1Bk1BN/NW
         Gq1F4Nrcd1ufmIA+Tk7U1xXgFNEI4+5u24w6XSBJrf0gRQw2ldtX7D98uAa5hLJ4x2BR
         squk3S47G1uP79lyBPDqTffWW/9UDo+UvgAsyxqOyebVSIXSZKb8Hmsn/+pFwkOl/pkF
         2uXE8i4zXagJpVMUROpPNM60aahTjBucyFKfGGimhFgvQ4C7r2QZXKSOMzOlslBoFMQ4
         CYhw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=cv+LslJ4;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::1041 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pj1-x1041.google.com (mail-pj1-x1041.google.com. [2607:f8b0:4864:20::1041])
        by gmr-mx.google.com with ESMTPS id a13si335548ios.2.2020.09.08.07.39.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 08 Sep 2020 07:39:46 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::1041 as permitted sender) client-ip=2607:f8b0:4864:20::1041;
Received: by mail-pj1-x1041.google.com with SMTP id kk9so5763668pjb.2
        for <kasan-dev@googlegroups.com>; Tue, 08 Sep 2020 07:39:46 -0700 (PDT)
X-Received: by 2002:a17:90b:140c:: with SMTP id jo12mr4229667pjb.41.1599575986171;
 Tue, 08 Sep 2020 07:39:46 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1597425745.git.andreyknvl@google.com> <6a83a47d9954935d37a654978e96c951cc56a2f6.1597425745.git.andreyknvl@google.com>
In-Reply-To: <6a83a47d9954935d37a654978e96c951cc56a2f6.1597425745.git.andreyknvl@google.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 8 Sep 2020 16:39:35 +0200
Message-ID: <CAAeHK+y-gJ5JKcGZYfZutKtb=BoM3qfkOyoTi7CtW6apHUcCAw@mail.gmail.com>
Subject: Re: [PATCH 22/35] arm64: mte: Enable in-kernel MTE
To: Vincenzo Frascino <vincenzo.frascino@arm.com>, Catalin Marinas <catalin.marinas@arm.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Elena Petrova <lenaptr@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>, 
	Dmitry Vyukov <dvyukov@google.com>, kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=cv+LslJ4;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::1041
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

On Fri, Aug 14, 2020 at 7:28 PM Andrey Konovalov <andreyknvl@google.com> wrote:
>
> From: Vincenzo Frascino <vincenzo.frascino@arm.com>
>
> The Tag Checking operation causes a synchronous data abort as
> a consequence of a tag check fault when MTE is configured in
> synchronous mode.
>
> Enable MTE in Synchronous mode in EL1 to provide a more immediate
> way of tag check failure detection in the kernel.
>
> As part of this change enable match-all tag for EL1 to allow the
> kernel to access user pages without faulting. This is required because
> the kernel does not have knowledge of the tags set by the user in a
> page.
>
> Note: For MTE, the TCF bit field in SCTLR_EL1 affects only EL1 in a
> similar way as TCF0 affects EL0.
>
> Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
> ---
>  arch/arm64/kernel/cpufeature.c | 6 ++++++
>  1 file changed, 6 insertions(+)
>
> diff --git a/arch/arm64/kernel/cpufeature.c b/arch/arm64/kernel/cpufeature.c
> index 4d3abb51f7d4..4d94af19d8f6 100644
> --- a/arch/arm64/kernel/cpufeature.c
> +++ b/arch/arm64/kernel/cpufeature.c
> @@ -1670,6 +1670,9 @@ static void cpu_enable_mte(struct arm64_cpu_capabilities const *cap)
>         write_sysreg_s(0, SYS_TFSR_EL1);
>         write_sysreg_s(0, SYS_TFSRE0_EL1);
>
> +       /* Enable Match-All at EL1 */
> +       sysreg_clear_set(tcr_el1, 0, SYS_TCR_EL1_TCMA1);
> +
>         /*
>          * CnP must be enabled only after the MAIR_EL1 register has been set
>          * up. Inconsistent MAIR_EL1 between CPUs sharing the same TLB may
> @@ -1687,6 +1690,9 @@ static void cpu_enable_mte(struct arm64_cpu_capabilities const *cap)
>         mair &= ~MAIR_ATTRIDX(MAIR_ATTR_MASK, MT_NORMAL_TAGGED);
>         mair |= MAIR_ATTRIDX(MAIR_ATTR_NORMAL_TAGGED, MT_NORMAL_TAGGED);
>         write_sysreg_s(mair, SYS_MAIR_EL1);
> +
> +       /* Enable MTE Sync Mode for EL1 */
> +       sysreg_clear_set(sctlr_el1, SCTLR_ELx_TCF_MASK, SCTLR_ELx_TCF_SYNC);
>         isb();
>
>         local_flush_tlb_all();
> --
> 2.28.0.220.ged08abb693-goog
>

Should we change this commit to enable in-kernel MTE only if
KASAN_HW_TAGS is enabled?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2By-gJ5JKcGZYfZutKtb%3DBoM3qfkOyoTi7CtW6apHUcCAw%40mail.gmail.com.
