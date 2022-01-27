Return-Path: <kasan-dev+bncBCMIZB7QWENRBVG7ZKHQMGQEPONJ3GI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb38.google.com (mail-yb1-xb38.google.com [IPv6:2607:f8b0:4864:20::b38])
	by mail.lfdr.de (Postfix) with ESMTPS id 8B49F49E4E7
	for <lists+kasan-dev@lfdr.de>; Thu, 27 Jan 2022 15:44:38 +0100 (CET)
Received: by mail-yb1-xb38.google.com with SMTP id d65-20020a256844000000b00614359972a6sf6215178ybc.16
        for <lists+kasan-dev@lfdr.de>; Thu, 27 Jan 2022 06:44:38 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1643294677; cv=pass;
        d=google.com; s=arc-20160816;
        b=Kek0Lz/kle2IrBeE7seJWFHiKei8gygSv2Hgt0O4prPeAaYb38CVdnTVWrCSsNKjln
         xaFMp8WXOftENLW7JtAecAbmF8ld+WqrG/C/iaZo0t9GCytHBGtcyEuLGJCLNxtWBNcW
         aprtq2c+fJ7dTH5Qaj6wwZcWHmd0UZ3+4If91KooSeC/J5sDGXc8pylWsIeZs2KvwVpv
         vgR/0kb9LsaRVhYZZbq6iLGVyDWuuVh/i69Bxh8y9I6Zbev+f59AhQgnJksmCYGhRpyI
         U3L91wWzXGur2dXjF6ITeK2luJIW7bjIUprejMe07HmpRDvXrOyD9WJzJaATFrWncar5
         0gnA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=Hp4J1HEGGMP81hpLhSw/8dNW32XaZsd4xfX3AjWm1dQ=;
        b=R4+Uirs+XhoTqjQvLTcxmYrwFIBkbEm9aiGB9oKohPH/NrUjLEcUM8TrPR7ByPYYKJ
         O0heoB0C1UsUnxiEqs61HjctcJos+Gv7GsFHB1QTl/mkTUp/UpjvNdCo5BtZm5mzm/mf
         vh0gwxs1pH6kcT2Em8Cf1HqeXmsVagpDi86LF24+9zGOYqjzI5wJfEZozos14cJM1SJ7
         5+ylLpQzNcuwBlgE1IMXdrk0QxhkonfRUUMlsCdr8jbziAd2J+3CChbaYp0IHgiRuwyo
         P8xTab4WQqCEqUNwkeIeATJtcFS9QFsEtRBeoav0vWdTM7x5jVe7p2Hf0zzu8Ry8KkE7
         rs+w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=Ypwxd6R6;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::236 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Hp4J1HEGGMP81hpLhSw/8dNW32XaZsd4xfX3AjWm1dQ=;
        b=hq9b7xobQ23zKzo5pN0pA7xcOAvnoQ4MaB38Zi1HfmHMHtj4YjdyagXLITkFJ6228O
         gM9vGOwRMPAhGySLC7vJ/B2EqQn0Ba5F6XTVm9toNNCo1A4DGMoNIjI6/hltRKbHhdbX
         QLtGac+b4907EdDkYnu+zkmGJZ4FnQrinuGqXzkcp+Cnp8RFFI1lQUAab+753r1w8Kw1
         2aScx6HFsWHp8Nz2kvKgFhZo+byqzKQd0fosNUFMXS+xn1QIC21NfZn6H2YaoZaQCQfU
         eTwCFHrwONlQf1z++3ZCIxZQmph09Mf369HXUcWahj60YvycBzxkv7Y/XEmGxL6AWF6+
         1rkw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Hp4J1HEGGMP81hpLhSw/8dNW32XaZsd4xfX3AjWm1dQ=;
        b=DC0+fv5/XmtvimaViY7CqgJmQiN9jVEXgwbVmJmVPE7ZPUWP6v0kv+1eDyCiA0/xAm
         MvMFNc2BTnL5q5RUT8vFwealfAGwpHvy92XY27DtRDIOggZCGwfW/1RENSoEKTCM6v07
         ZT16Gsr7MGL/NWXey8t22pPG0GTGVZfKPdwNTBfmvRqmk0JcLKiaI3FOUwADrjvmp5BO
         Lob8ycLNGPh7Aae7UGHc38aqkOAQFknVZSAKKuVdcjRkPiBIHuxzSbADxSsk7gnCTZGw
         8qwuYVIcth1GRIXIEEvABVDtehnp6jlaANfl+TJcOYglxt5764fvjb/yZvm8+nHfGjhu
         JdKQ==
X-Gm-Message-State: AOAM530LpJ30g9E7r+u1h6KFi0B5EHFx3B/o0JiOVq/0I9c+krB6O7IP
	laHPv57Mu9Vb5EVmon4rXXg=
X-Google-Smtp-Source: ABdhPJy2/f1bTVaPw3n43QQBxO+3dcHYIWp3FMDtFrdKIEo6YiT/tnLDuKCzVMN9eIqbLyNMLZr2OQ==
X-Received: by 2002:a25:9c03:: with SMTP id c3mr5817694ybo.494.1643294676339;
        Thu, 27 Jan 2022 06:44:36 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:e790:: with SMTP id e138ls5791031ybh.0.gmail; Thu, 27
 Jan 2022 06:44:35 -0800 (PST)
X-Received: by 2002:a5b:5d1:: with SMTP id w17mr5910157ybp.112.1643294675884;
        Thu, 27 Jan 2022 06:44:35 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1643294675; cv=none;
        d=google.com; s=arc-20160816;
        b=rT6X7StE+idHzb2RDPZ+b0Ow2AFriQG81qeC9e0SuVqloEyi90n31FKoM7uQQ+qE3G
         oUGHzS0dacA9aWoVPM5377wk8JAZNC0ns3x2W80/0pFU60iaBUYBCIgOdegmG9liy/a6
         4g6hE6k5cEXKbswub7S/qXY3/6sPbr+VMq9dla4Qd2+Vt0y6i3suuvCgSrbY6LIyVeAT
         reOWgi5aDLjhk14VLK3NC7Y/jojL4wJLOGic6ZK5WhrJXbGLGJ5xIkj3eZnDUBXAhXki
         PCVHRmvWJKlsj9VCCewwOTMKAlNHa+EIhJjnbY+bGEhNZEYAcU43q1OX06CtcPl/VuKm
         zYgA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=darEVYQSE8nP3jpJzwSkUiUgFJtcguGHbAaA8wiRNaA=;
        b=plSodl8n0A3mCAM9QSTAKz9/cdlWJGtrQpjpnzC5a8v1t2eV/OVcKMf8OKonMP1vE+
         f141nGSPnZTDvIq+43o6PGFuvVyBcFGfsX92kKLrbz9ybCu4qaO5N4v58nM/M1f4V6le
         frKfZEjxYmhaT6ZY/gH322mVNL1nFVF1dHCAx+l1GX/p0Ncn8/tgg+Bnm0kO4SIBn+X+
         RVZ4FxxScMoRRRsqPSq6L4EoKLaktmpQOxBnLO+h+OyXQwJyEf9Mil+iYwAp4aHDXYZ8
         wEQBq47O+TQsbiTGmn8H7cxlmD3/iL23QwGPV5NTP7aUPiujkqZNTefGhY/F6JwjNrNC
         82aA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=Ypwxd6R6;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::236 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x236.google.com (mail-oi1-x236.google.com. [2607:f8b0:4864:20::236])
        by gmr-mx.google.com with ESMTPS id 16si136027ybl.0.2022.01.27.06.44.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 27 Jan 2022 06:44:35 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::236 as permitted sender) client-ip=2607:f8b0:4864:20::236;
Received: by mail-oi1-x236.google.com with SMTP id u129so6239414oib.4
        for <kasan-dev@googlegroups.com>; Thu, 27 Jan 2022 06:44:35 -0800 (PST)
X-Received: by 2002:a05:6808:b10:: with SMTP id s16mr2364269oij.307.1643294675382;
 Thu, 27 Jan 2022 06:44:35 -0800 (PST)
MIME-Version: 1.0
References: <20220126171232.2599547-1-jannh@google.com> <CACT4Y+b8ty07hAANzktksbbe5HdDM=jm6TSYLKawctpBmPfatw@mail.gmail.com>
 <CAG48ez3mfAwgkJp+GKLnbtgQoQVT78U+voRN09H5S=7Ewf+DgQ@mail.gmail.com>
In-Reply-To: <CAG48ez3mfAwgkJp+GKLnbtgQoQVT78U+voRN09H5S=7Ewf+DgQ@mail.gmail.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 27 Jan 2022 15:44:24 +0100
Message-ID: <CACT4Y+bOsS+veBKSMQX+Etz=93PZv-nhKYm4-Gmigmv551LCtg@mail.gmail.com>
Subject: Re: [PATCH] x86/csum: Add KASAN/KCSAN instrumentation
To: Jann Horn <jannh@google.com>
Cc: Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@redhat.com>, Borislav Petkov <bp@alien8.de>, 
	Dave Hansen <dave.hansen@linux.intel.com>, x86@kernel.org, 
	"H. Peter Anvin" <hpa@zytor.com>, linux-kernel@vger.kernel.org, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, kasan-dev@googlegroups.com, 
	Eric Dumazet <edumazet@google.com>, Christoph Hellwig <hch@lst.de>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=Ypwxd6R6;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::236
 as permitted sender) smtp.mailfrom=dvyukov@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Dmitry Vyukov <dvyukov@google.com>
Reply-To: Dmitry Vyukov <dvyukov@google.com>
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

On Wed, 26 Jan 2022 at 18:48, Jann Horn <jannh@google.com> wrote:
> > > In the optimized X86 version of the copy-with-checksum helpers, use
> > > instrument_*() before accessing buffers from assembly code so that KASAN
> > > and KCSAN don't have blind spots there.
> [...]
> > Can these potentially be called with KERNEL_DS as in some compat
> > syscalls? If so it's better to use instrument_copy_to/from_user.
> > Or probably it's better to use them anyway b/c we also want to know
> > about user accesses for uaccess logging and maybe other things.
>
> Christoph Hellwig has basically eradicated KERNEL_DS. :)
>
> In particular, on X86, set_fs(KERNEL_DS) doesn't really do anything
> anymore since commit 47058bb54b579 ("x86: remove address space
> overrides using set_fs()").

That's good!

But still need this for uaccess logging.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BbOsS%2BveBKSMQX%2BEtz%3D93PZv-nhKYm4-Gmigmv551LCtg%40mail.gmail.com.
