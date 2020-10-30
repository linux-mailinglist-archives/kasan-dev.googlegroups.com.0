Return-Path: <kasan-dev+bncBCQ2XPNX7EOBBV765X6AKGQELNLXCLI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43c.google.com (mail-wr1-x43c.google.com [IPv6:2a00:1450:4864:20::43c])
	by mail.lfdr.de (Postfix) with ESMTPS id C2BD429FBA7
	for <lists+kasan-dev@lfdr.de>; Fri, 30 Oct 2020 03:49:59 +0100 (CET)
Received: by mail-wr1-x43c.google.com with SMTP id j15sf2075917wrd.16
        for <lists+kasan-dev@lfdr.de>; Thu, 29 Oct 2020 19:49:59 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1604026199; cv=pass;
        d=google.com; s=arc-20160816;
        b=RpIPnIwIVbPaoenaFcY6oKIlxojETmlXBXgG0DiK+A70V340jC0eMknt8avKTbK1aL
         mNwPue8af3lUm9Jb9Nliaoq/R35kE4Sdo10+F82uzlJnObBOXUUaXwYKwsS+8pN0F5lT
         gbK+p7T2PcDJv9APSLQA0CNlFn9SS/aFxdW8N1289X6AVK6gIe1obbPSw8yIFde2bSoY
         sQ418MD0VL6jLg2USzoll3uRYYT8EyJcVhJs/FyxZHEdF4mJKQm6mPGhnPe/j7GnASop
         jk4seNMNGYX/edQJhfcaTDDBQXGCd4SEVIvz3cy+e3K277LLCg5AYDTV0jBDCBiGLNLf
         X46w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=IwKEB0TIiWxAu8xZARrekhZ0ZJR+lm8XE8o8TBm5nHk=;
        b=RgaCNroX/6/xz6kL7ubD4T2U59Pu2TVGGF3dvUivSjPkspfrsZeFlsLwTbe2EfPMPC
         IPXOYnsko1bTAf3fqt7unEp/TCvR5Zw5Yxiyq01GkWz3v90Zr2WMQCz7mVamQvSbINKr
         lJ5knYsyROuuZLOWHxshOuUN91LycP0CsgRGFrZ4rqivdCCQrkUF3kQ2H4QXVwIWvG0i
         0oUN3c0VD05QPLpAGzyHWEgj2pDuQcvPipsF5F8rz5mpZnSDSGvAIu+gXebQn2j53/4e
         cEghLkGjOCpEnpc3RIVrv2f/LPUGYBzDSxz52E0h6mzg6KFlntYNneGMXgiyLGYOPSIF
         vxmA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=etxHYnTq;
       spf=pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::241 as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=IwKEB0TIiWxAu8xZARrekhZ0ZJR+lm8XE8o8TBm5nHk=;
        b=O1pHB8ORUPofau0h/dR0OXDBUZojRRg7cSgc6tZhorRa0JtzVsNuVxkLEKBIriT8OP
         pvCnF/CIY5qCyx3e6/8Xf/cPqV/lrGOKElo08suMTdlehYiJSpMbm4Y+CKCjccu9EG3N
         1vpB48cq34zIhJAEHKVrbb8vwAnCsh3Yjz5chQ4d+pWlJS3z7odL6lMAtYndefqDczLf
         v2DWXYxVLnpIkl0gw3UVD8WI7Mj3AMFH2abxuGgRS0iaE/noFHqf7xbp702Wbvgsj2co
         NFIsHzjsDZ4Idyt1ugU93KKp66OkzNnLcgy8GNX7N3hAjD2QL3X5Xz2ymdTZk+e39SKJ
         UCng==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=IwKEB0TIiWxAu8xZARrekhZ0ZJR+lm8XE8o8TBm5nHk=;
        b=roSYFYn+13do6/c052fa4vPpV7m7HmkOqooB6+UhvvMdpHjJMijZF25BIeV4G7OlMN
         2exGVmr9yKqEfLLb/WgHVVaG+PKdn3viK4IRAuswsz/qTpVqPpyja6YMvu96oAL7I2m6
         nYCvFkbjVz3RNVPcBAcGOAsgngtfJVT7f5FxctgALGkFyIXWr+HmH78Vh3h/lSVkuft1
         37IOhBGiobzSATFe+kxr6EVZOdBBKPL+2DfvfufcTkeTCC5e5YY37nCi97R+AJvMSDIf
         JyTZv/WpJeC9XQTm0tku7ILBnzM5WdNA82eBmtehZIU6FuSITK0OWj9ggbVaRTI5XPmW
         dyYg==
X-Gm-Message-State: AOAM531sAaIqJEHrXDQtbHZxQLoQVEsqHRkdwm2t1gygUxaNSoHDl55K
	p3w2gaDbbGDR8XnAEG2loII=
X-Google-Smtp-Source: ABdhPJyhHcAjthP1eQ/jLhnHBaIl2NdNuoWQB+ht6OJCBKo1/i8b01wS8LVUiGwcA1fSinDPCQbOsg==
X-Received: by 2002:a1c:28d4:: with SMTP id o203mr46084wmo.143.1604026199571;
        Thu, 29 Oct 2020 19:49:59 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:3d87:: with SMTP id k129ls864004wma.3.gmail; Thu, 29 Oct
 2020 19:49:58 -0700 (PDT)
X-Received: by 2002:a7b:c09a:: with SMTP id r26mr61964wmh.45.1604026198850;
        Thu, 29 Oct 2020 19:49:58 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1604026198; cv=none;
        d=google.com; s=arc-20160816;
        b=nhA8/HqXJ61cVlLZKbF7UqjHL8BB6Gr9Dmgp9WannQ9dHnr3H4fZ0pwmhW/Vuievtb
         bSRfciHrH8R/5p9qbYOMCk//0SCchMnz71Q+LYOgNVB1ekAyM1itJzs6r1kh8zhi0Erc
         tnSGpRTEZKC1FkqTKLIGkFbONAc3c3pJfAjEk8tViSDtZWGGVeOz3gf2hFPhv16iqkDW
         5oj8IXQM/nc6mDjfRcjaxwHYAiYQ921sAASu4m3eVGZ2BePELldqu1KYCjWiPNWMuJZY
         qr2XpWVpV30x/EplwOP7X+E3lfJb4Z856PgCJIT8PKzAcVarJeDHafB/Dcv1D61eJMp1
         J9HQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Z9WOxdh6RCpZm8X6kMwbW3XPGG0WSUUUAze88LfZLdE=;
        b=LJmZQ7X3m6mH025XwaFKTez6OxYQZS4vCP19YfdepHtmPnlgdIZi0Xn/dWKzagFyYJ
         UYMjmO1jpCXRrzcTS4uoGH0PsETO3cqqXXah26+zcjFYY8gICIPw5OMUNSoUZC2ZnLfm
         nICurGWSIZHzmDeR/qH/i9Pd/MucTdf7I6Am+hYz397v0H/nB5+3Z/AxKSS/3+/Vvi0A
         KFxftmVAHRzOKncPJETY02e9T18E3BYHjAuFOmOLgmJhBez8d4Z5gDuTz6uF4b+HJHRt
         weO85/h3rhbR9TsFF5qT2MpmO9NL6yXVG6+TtK1C3Z1Y2v47NN1MFXuY0Was80HR8MTm
         3qsg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=etxHYnTq;
       spf=pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::241 as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-lj1-x241.google.com (mail-lj1-x241.google.com. [2a00:1450:4864:20::241])
        by gmr-mx.google.com with ESMTPS id y14si162739wrq.0.2020.10.29.19.49.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 29 Oct 2020 19:49:58 -0700 (PDT)
Received-SPF: pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::241 as permitted sender) client-ip=2a00:1450:4864:20::241;
Received: by mail-lj1-x241.google.com with SMTP id x16so5386244ljh.2
        for <kasan-dev@googlegroups.com>; Thu, 29 Oct 2020 19:49:58 -0700 (PDT)
X-Received: by 2002:a05:651c:1313:: with SMTP id u19mr95728lja.47.1604026198405;
 Thu, 29 Oct 2020 19:49:58 -0700 (PDT)
MIME-Version: 1.0
References: <20201029131649.182037-1-elver@google.com> <20201029131649.182037-5-elver@google.com>
In-Reply-To: <20201029131649.182037-5-elver@google.com>
From: "'Jann Horn' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 30 Oct 2020 03:49:31 +0100
Message-ID: <CAG48ez1DxttDs6vj61c0jSGSbhoUmAW9_OSBSENrC-=hz-d+HA@mail.gmail.com>
Subject: Re: [PATCH v6 4/9] mm, kfence: insert KFENCE hooks for SLAB
To: Marco Elver <elver@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Alexander Potapenko <glider@google.com>, 
	"H . Peter Anvin" <hpa@zytor.com>, "Paul E . McKenney" <paulmck@kernel.org>, 
	Andrey Konovalov <andreyknvl@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Andy Lutomirski <luto@kernel.org>, Borislav Petkov <bp@alien8.de>, 
	Catalin Marinas <catalin.marinas@arm.com>, Christoph Lameter <cl@linux.com>, 
	Dave Hansen <dave.hansen@linux.intel.com>, David Rientjes <rientjes@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Eric Dumazet <edumazet@google.com>, 
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>, Hillf Danton <hdanton@sina.com>, 
	Ingo Molnar <mingo@redhat.com>, Jonathan Cameron <Jonathan.Cameron@huawei.com>, 
	Jonathan Corbet <corbet@lwn.net>, Joonsoo Kim <iamjoonsoo.kim@lge.com>, joern@purestorage.com, 
	Kees Cook <keescook@chromium.org>, Mark Rutland <mark.rutland@arm.com>, 
	Pekka Enberg <penberg@kernel.org>, Peter Zijlstra <peterz@infradead.org>, 
	SeongJae Park <sjpark@amazon.com>, Thomas Gleixner <tglx@linutronix.de>, Vlastimil Babka <vbabka@suse.cz>, 
	Will Deacon <will@kernel.org>, "the arch/x86 maintainers" <x86@kernel.org>, 
	"open list:DOCUMENTATION" <linux-doc@vger.kernel.org>, kernel list <linux-kernel@vger.kernel.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, Linux-MM <linux-mm@kvack.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: jannh@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=etxHYnTq;       spf=pass
 (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::241 as
 permitted sender) smtp.mailfrom=jannh@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Jann Horn <jannh@google.com>
Reply-To: Jann Horn <jannh@google.com>
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

On Thu, Oct 29, 2020 at 2:17 PM Marco Elver <elver@google.com> wrote:
> Inserts KFENCE hooks into the SLAB allocator.
[...]
> diff --git a/mm/slab.c b/mm/slab.c
[...]
> @@ -3416,6 +3427,11 @@ static void cache_flusharray(struct kmem_cache *cachep, struct array_cache *ac)
>  static __always_inline void __cache_free(struct kmem_cache *cachep, void *objp,
>                                          unsigned long caller)
>  {
> +       if (kfence_free(objp)) {
> +               kmemleak_free_recursive(objp, cachep->flags);
> +               return;
> +       }

This looks dodgy. Normally kmemleak is told that an object is being
freed *before* the object is actually released. I think that if this
races really badly, we'll make kmemleak stumble over this bit in
create_object():

kmemleak_stop("Cannot insert 0x%lx into the object search tree
(overlaps existing)\n",
      ptr);


> +
>         /* Put the object into the quarantine, don't touch it for now. */
>         if (kasan_slab_free(cachep, objp, _RET_IP_))
>                 return;

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAG48ez1DxttDs6vj61c0jSGSbhoUmAW9_OSBSENrC-%3Dhz-d%2BHA%40mail.gmail.com.
