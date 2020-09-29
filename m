Return-Path: <kasan-dev+bncBDX4HWEMTEBRBXP4ZT5QKGQE5TIYAAQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x437.google.com (mail-pf1-x437.google.com [IPv6:2607:f8b0:4864:20::437])
	by mail.lfdr.de (Postfix) with ESMTPS id 5778E27D05E
	for <lists+kasan-dev@lfdr.de>; Tue, 29 Sep 2020 16:02:07 +0200 (CEST)
Received: by mail-pf1-x437.google.com with SMTP id k13sf3792834pfh.4
        for <lists+kasan-dev@lfdr.de>; Tue, 29 Sep 2020 07:02:07 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1601388126; cv=pass;
        d=google.com; s=arc-20160816;
        b=MMrokmnjHFOOFvvMbNXDZJT1+MEuqXEwYPYFiu2LLYmVhnYCVz+VKsPS0Pz11aw+De
         Gmof4n4eYcSeX9041CXRupbjEpBpdpV+WSvxrlOKrAWcCIfhTM+kCHWpYeUXt+49qQzH
         /oa3KmpH4V30Snqs2EQG/WnQxKuK6K6uUFbWHSWT0yjVhtm3vOwfzDC1xTxrhpJFXVOM
         Hqp+FwuCM16slXnVTfg53A4ZE1mbIBwViEiu8PEoBf6HoJKKCkD4HCzgcph+QUOOOIVJ
         7JOXyngTClIZeWvtrl4AMpxIDiu5fiBApcU7E1PbYy9TigKAZHEX11zKMSAXB9uNrR1n
         EwCw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=HuWMc+MNSd/EB8Hvn/vFKO0rmOAdCJfdHKFWIqBVUW8=;
        b=FpkNzK0VUP0I1rKD6nvZEMR7sPUXxBV8haOo6GmSN0x376rQRMLLFDxush8IQBwySv
         0BYXtTmRJFpb8PTWK4h603JZBcgH47oDFUx6Mli+a/k8BxUcfoHPuo8d93uzUHYPSGpl
         MK48Natq1pMtcgAfvHOnkQS0NHe7TSi0eNx0kfvHulKhPvEWx69TlvgUSVA8cBElGj6b
         ebFhIF38KkKCf3z6Cb0DZ68StrvZT9Wwh2wvMx+EnFUWgucpBN7nxtW3JcZtxopqj4B9
         Rwna1/GC9px5+awIC/pzdl7Z6wAiE1XgBWBM0+ytWzzg34Z3F3EvYzniZbO4OYZbaPca
         p0tA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=ICA6SzbA;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::444 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=HuWMc+MNSd/EB8Hvn/vFKO0rmOAdCJfdHKFWIqBVUW8=;
        b=HQddWiEQdCUDC73UpyT8aAe2A30RHi4lOKtJgoKQi/dFgBejDs0q2IkJCs1IUtbah/
         5D9EpUCRR3BhE4Cc5BQs2/DFbzndXmCKg+My0fdM4JkNPsWDMF2CRyzeVcgU4O7cANqZ
         At1xYu+aTEyW0jkcpcSYoUcLdHxe7953TASSDs0e5BEZyMUlWUUN0N4ke9gp091Fn1Tf
         nDHvNN+E/H2lQkWWRcFZnUZobJpcuU+rua5h3jQkjnkVdChZj0o6J2dSrUImDC2MORAC
         NaITcV751gACKSlFVKR30TWmno/XjziH0BUnUjsLf1W+VoAjWEANUqPZeya2+oMP05ov
         MwYQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=HuWMc+MNSd/EB8Hvn/vFKO0rmOAdCJfdHKFWIqBVUW8=;
        b=uSx5Qed0dS7cN2naTeVVcKJRdtm2pues0Jaq78xh1S8cAMnrkYbj4p+KVvEHGt9ejC
         Ok+jE23DlwHZXPITAiGIfdoyfFNHKzrwMmIUQdIaGqOW2BQh4q5cyQHjbgyW/c543wum
         bZ++VZFTG5uOFNxZafrl/3fxsMuUgH0j1++MQNErexSij7+A/xv9+sOtXxkJj+fcAcgL
         QeDhGM8w03/8cTmACtNWipv89cnoWtJV/nM5kmk4Hrf6bjDWHJrVgt1kkQdm+vYpujc0
         6plooYAbvKtuw3eUkGEexJmlnBDwxudh1oQlfhns6yWhQV3J5nG3CdqzUG+P6CePnOj1
         FEMg==
X-Gm-Message-State: AOAM5332pbXicGfRB5aGmZaYlV4N1AR9nnYIOFcR9sC9RN4no06GlfJm
	MWvQQcHb6LxdxDb+Y6lecoU=
X-Google-Smtp-Source: ABdhPJxS5EW5ifezmZ+ukZ2jUoT6bWXWStX+mrS9HogrMth9l4kDQPKhAYr7HBgl6WI8UqesROLXjw==
X-Received: by 2002:a63:d00f:: with SMTP id z15mr3509177pgf.453.1601388125985;
        Tue, 29 Sep 2020 07:02:05 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:1f54:: with SMTP id q20ls3200071pgm.0.gmail; Tue, 29 Sep
 2020 07:02:05 -0700 (PDT)
X-Received: by 2002:aa7:8b4f:0:b029:142:2501:35e9 with SMTP id i15-20020aa78b4f0000b0290142250135e9mr4223035pfd.73.1601388125358;
        Tue, 29 Sep 2020 07:02:05 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1601388125; cv=none;
        d=google.com; s=arc-20160816;
        b=ecgvSxhmCf9H1gNEkYDPndMdLxp/WVgN5EMak6GQ8ynn63vh1RgLi9g+GMTZCll+6y
         EdJcTp00OjeQltvgNwC1RC9Aoa2K56Ab7HE/Y8tA3Kf9XtP4bYrD+uf7tfjrcW28Pibp
         UXAGgl6o4bRUSzkpReLjkAquUtg7GWO52jy7tSFVedW1GsWAyIUoC2TClsc/ULjTHpMu
         XOCGHfYkPPlEz3X1qac7WSIylMOK3gEGIce4zanrK2BZZ49+E2MfasT1EKj7HtP7TESl
         qk54CdtiXQjlyvHvqs+lXllEeM8Xz15L0AKpE2C/34OnNhknYUIyr4anIPQYgbMcDjIR
         mN7A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=uOc+wQKeR9iMQFVgCW+E9/Ju05nBU+r7vf7w3Aw84Jc=;
        b=S5XycFpQPkVYfKAlVQQKGjym+hn3dE+FqkaX8W++p9tWdd234gF8fXMlAXoc/2fvG8
         baKggYT63bSbKLNkm7bvcv2NjAno6rKhz9J7qNchUSQXmzGOtdkmLgS/EKTXp/1BOpZv
         Q6PLP+4Dzno349wTX3ZfhzQ6L2CKMlQlNNEMyI0O+IVrysivXWensB26QR3qs5jm+q8v
         +UytcpjvFM5mR7tJHc52O6jZyqAwBvOaDBqS+y9bauPcF8jGevpD8YqHNij3ZKnIl9Fl
         ab5ErbGVWjptnU5Fly5iACYXkfvWwcNgIyv/Si/cWwp3fPv+/VkvFTfIUy4yckhfj1Id
         FUiA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=ICA6SzbA;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::444 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pf1-x444.google.com (mail-pf1-x444.google.com. [2607:f8b0:4864:20::444])
        by gmr-mx.google.com with ESMTPS id o13si346160pll.3.2020.09.29.07.02.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 29 Sep 2020 07:02:05 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::444 as permitted sender) client-ip=2607:f8b0:4864:20::444;
Received: by mail-pf1-x444.google.com with SMTP id q123so4653951pfb.0
        for <kasan-dev@googlegroups.com>; Tue, 29 Sep 2020 07:02:05 -0700 (PDT)
X-Received: by 2002:a62:1d51:0:b029:13e:d13d:a0fc with SMTP id
 d78-20020a621d510000b029013ed13da0fcmr4462384pfd.24.1601388124642; Tue, 29
 Sep 2020 07:02:04 -0700 (PDT)
MIME-Version: 1.0
References: <20200921132611.1700350-1-elver@google.com> <20200921132611.1700350-2-elver@google.com>
 <CAAeHK+zYP6xhAEcv75zdSt03V2wAOTed6vNBYReV_U7EsRmUBw@mail.gmail.com>
 <20200929131135.GA2822082@elver.google.com> <CAAeHK+y0aPAZ8zheD5vWFDR-9YCTR251i0F1pZ9QfXuiaW0r8w@mail.gmail.com>
 <CANpmjNOFpFkrSMFezcBFJODwBK5vRi8sSEzS3AvyFu3Y0ZqgVA@mail.gmail.com>
In-Reply-To: <CANpmjNOFpFkrSMFezcBFJODwBK5vRi8sSEzS3AvyFu3Y0ZqgVA@mail.gmail.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 29 Sep 2020 16:01:52 +0200
Message-ID: <CAAeHK+ycOZ1E1P8PGbZizYUE7EGkj90tJ8et0Ki79LZMAkJWXA@mail.gmail.com>
Subject: Re: [PATCH v3 01/10] mm: add Kernel Electric-Fence infrastructure
To: Marco Elver <elver@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Alexander Potapenko <glider@google.com>, 
	"H. Peter Anvin" <hpa@zytor.com>, "Paul E . McKenney" <paulmck@kernel.org>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Andy Lutomirski <luto@kernel.org>, 
	Borislav Petkov <bp@alien8.de>, Catalin Marinas <catalin.marinas@arm.com>, Christoph Lameter <cl@linux.com>, 
	Dave Hansen <dave.hansen@linux.intel.com>, David Rientjes <rientjes@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Eric Dumazet <edumazet@google.com>, 
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>, Hillf Danton <hdanton@sina.com>, 
	Ingo Molnar <mingo@redhat.com>, Jann Horn <jannh@google.com>, 
	Jonathan Cameron <Jonathan.Cameron@huawei.com>, Jonathan Corbet <corbet@lwn.net>, 
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, Kees Cook <keescook@chromium.org>, 
	Mark Rutland <mark.rutland@arm.com>, Pekka Enberg <penberg@kernel.org>, 
	Peter Zijlstra <peterz@infradead.org>, SeongJae Park <sjpark@amazon.com>, 
	Thomas Gleixner <tglx@linutronix.de>, Vlastimil Babka <vbabka@suse.cz>, Will Deacon <will@kernel.org>, 
	"the arch/x86 maintainers" <x86@kernel.org>, "open list:DOCUMENTATION" <linux-doc@vger.kernel.org>, 
	LKML <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linux Memory Management List <linux-mm@kvack.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=ICA6SzbA;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::444
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

On Tue, Sep 29, 2020 at 3:49 PM Marco Elver <elver@google.com> wrote:
>
> On Tue, 29 Sep 2020 at 15:48, Andrey Konovalov <andreyknvl@google.com> wrote:
> > On Tue, Sep 29, 2020 at 3:11 PM Marco Elver <elver@google.com> wrote:
> > >
> > > On Tue, Sep 29, 2020 at 02:42PM +0200, Andrey Konovalov wrote:
> > > [...]
> > > > > +        */
> > > > > +       index = (addr - (unsigned long)__kfence_pool) / (PAGE_SIZE * 2) - 1;
> > > >
> > > > Why do we subtract 1 here? We do have the metadata entry reserved for something?
> > >
> > > Above the declaration of __kfence_pool it says:
> > >
> > >         * We allocate an even number of pages, as it simplifies calculations to map
> > >         * address to metadata indices; effectively, the very first page serves as an
> > >         * extended guard page, but otherwise has no special purpose.
> > >
> > > Hopefully that clarifies the `- 1` here.
> >
> > So there are two guard pages at the beginning and only then a page
> > that holds an object?
>
> Yes, correct.

OK, I see. This isn't directly clear from the comment though, at least for me :)

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2BycOZ1E1P8PGbZizYUE7EGkj90tJ8et0Ki79LZMAkJWXA%40mail.gmail.com.
