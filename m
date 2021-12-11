Return-Path: <kasan-dev+bncBCM2HQW3QYHRB25O2OGQMGQECBW3KLI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x539.google.com (mail-ed1-x539.google.com [IPv6:2a00:1450:4864:20::539])
	by mail.lfdr.de (Postfix) with ESMTPS id BDEA34714CE
	for <lists+kasan-dev@lfdr.de>; Sat, 11 Dec 2021 17:53:00 +0100 (CET)
Received: by mail-ed1-x539.google.com with SMTP id 30-20020a508e5e000000b003f02e458b17sf10662253edx.17
        for <lists+kasan-dev@lfdr.de>; Sat, 11 Dec 2021 08:53:00 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1639241580; cv=pass;
        d=google.com; s=arc-20160816;
        b=0SuLyKpcuTn+otxbSxb2Qc2hjc5QiVZBWFitzQifnccaLFODCqxgE8PFvrq4AtiJuQ
         J8F393rTedyFysgsppBM8QgPRhi2n5eiXXrumLBm+7Buhh/4LimrytsmAlie/XKsOBhJ
         5B9dxmNiPiSH+68LxNcygvWBOhA70lJRTFWW3reJldT2h1Na2lEOfOtXOHDF6Lknl/1u
         OlCrEnGFbS0rtjdaqN1OHqIxpuBBVwZTs5J5OlDAA/KX3MV4ZmfMRj1S+cSnc9/h1Jxm
         v4Vw2NVg+gHb/5CSjLYB9PL3QC7+7I5V/K3gjLHN/z9ZQRSqr987Io8//bFQbyUbJZJ9
         jhUg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=x93opJUmluK+VsLh+8hFgEF3hPF7QuXth7Srf42KCxM=;
        b=wzTyeQMk3obxplJNBPnkiJtX7Sq0J68666tTHWduqitAN1HqyHOjXRswJcHnxlF89N
         hvBPqbrTrxZRV52ZXsMw4JJ8iNCzN2Iq7wvIPcjH7R1fvdzDmBbfOsHbWURtXIvs4QEA
         +o8SmqkzDLgoE0ot1KfSeTZyHNB7AOXdMsYi2pM3KUgcmb0vjYjalnSFHPBCLevOBU7Q
         m32QXlUzjrMzk07vw5rm4yK4g8d7RF4XyrPwsUpy1K848ncru4DgS7Z5N+gPxm/6Yv9q
         Vv3V3XPtRuVQKkQfgL0F2rvdjTKNbony5hRK8v/DIth1r0AJ71FnYMPNtAEw9IekGVrc
         vPgw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=BAKk3TlO;
       spf=pass (google.com: best guess record for domain of willy@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) smtp.mailfrom=willy@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=x93opJUmluK+VsLh+8hFgEF3hPF7QuXth7Srf42KCxM=;
        b=d2/NeHPyLmXxJ/VUwK26vucZZ8U4CVATMgh4nMyjJnxOgw4JuIJaw2CpRfK7tPS83W
         2falRFjDsxvH3iAIR+Nz2CSM6h0C8H8VTn64rIASEPI9jh2Qi2DN198YKGCZY0wG1/nS
         7930Dc21lVafgORgzdofQle3mne4j6QWRRNOyYruYsbPj0FBhd0SIzCIMf5Nnwne5SiJ
         G7ULjSbg+Srh2vo6NTmYRndS2tLGINZh31j9hVvRAVCep+Xk8Y+T/l3jPVsjZ/3XFt6k
         QLKgdjlabtLMp3h1R+MDrkdowUQDfhDzDmg3HoQmb6BAzImQwY6WExQuY64yLnypKUIW
         fWfA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=x93opJUmluK+VsLh+8hFgEF3hPF7QuXth7Srf42KCxM=;
        b=y1PlD3wPzPiYQmQF09dh4KggdfI/39T5TW8tB3S5/wOYnGq3x7aSJddzrugwVqWprg
         P/VHpJfdER8/8lhNSXHmUENbTlbNxHbccqvsKOd2s4YvkbjeftUIWgbJYQI8r+kKfzll
         VEpg01vP3bkRYjecXt5QY1y/bQF7f1KPfkAuT3MN9ABWPoOBVeqHMIkCGv1pcS4+tDzy
         Jy6OnHVXEk/lk9O0IJoj4/0suHSPwbfcstGUxMw+B8u1xvXFvvhKdnKaMVQ3npfEDyHM
         /r9vnxBe5vE2eo+pVW5v9P+dCGfMSh6qv9dzL0is/s0qYrdyWw4a3wa/6a6a0ddYx5wf
         Go0Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531XPGkTO49j69tqlVxFRuuBjzatl6P2Zeb7knxp5RGt3Xmi92jY
	E0m5s+4v8lJyxrXtyEcUmGU=
X-Google-Smtp-Source: ABdhPJyH6iOPZ+ZGAdqUQpMNzjdqrDrzwFr+vROdw/4Ufjx+YtPqNHta3H88pyKRhaeBtH1fpQrtqA==
X-Received: by 2002:a50:9eca:: with SMTP id a68mr48925910edf.127.1639241579256;
        Sat, 11 Dec 2021 08:52:59 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:c98f:: with SMTP id c15ls54233edt.0.gmail; Sat, 11 Dec
 2021 08:52:58 -0800 (PST)
X-Received: by 2002:a05:6402:2789:: with SMTP id b9mr46604068ede.28.1639241578379;
        Sat, 11 Dec 2021 08:52:58 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1639241578; cv=none;
        d=google.com; s=arc-20160816;
        b=hT3dTXyctyD5zA9KLBON0Y8zwlLRXHyDhJz7xDt3Mws5u6G3Pg2bzqWRpZwFgUTiIY
         giHdyqLKUyQV2zm820H0wlj0DdsSw6hVya+eV5ZJOBjazPSFEUseDd+OTANctPLXoAlh
         PveP+kxoKWsMuDksoe1I718y7hIdosacH04XXEwuxKodMd9Pqt3kweadPNHvv4xbm3RS
         gv5QLhkk5rDJxiV7PC+PVDU74chLM2jR/G4WQ4k0rwEEZfAI6CYXpAJ/rJzHVXkhEwOJ
         HowSkWzjfwczymsSqio602eI7pie++4Ke33zjXERAN7/quxECJSO7esYqMwA0m2tOeRH
         S/+w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=u/N0Z1R4JJJOrnFGUtTYcDRphW4OI/ZTkZQ/n5WMmxo=;
        b=v7Q6+kkx2pDe3KcLyNsS03EyS3KGY5dGa1CSacILDZir90I1TAFPG4OsO7QVDTczOD
         48iDGZ8FAxpzWL4PY3Ic6oGM98Tb2itsp6s4cStPGpgzDGkN4X/L3loIz8EkNMTd/sph
         dmUCjNmHrvgzJOx/B6sYmt7lOix/Mqebia9LOFh3IKJr2Zk/VIVX+Wq3UxIAt6e+04cm
         gWX4eMmCcEhmDSwqKwnVYFI9bmTK3BJcIj+pPS9H+6aTHyLzEwnQOFKFm7g/NJ0Tk8v7
         7uHbfwpmwsWglhJoc6+vRuOKTXHhE0HwBEB1jjM4By9f7a93Hn4Q7mHXPpU1rhICDPN0
         Zrqg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=BAKk3TlO;
       spf=pass (google.com: best guess record for domain of willy@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) smtp.mailfrom=willy@infradead.org
Received: from casper.infradead.org (casper.infradead.org. [2001:8b0:10b:1236::1])
        by gmr-mx.google.com with ESMTPS id e10si391898edz.5.2021.12.11.08.52.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sat, 11 Dec 2021 08:52:58 -0800 (PST)
Received-SPF: pass (google.com: best guess record for domain of willy@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) client-ip=2001:8b0:10b:1236::1;
Received: from willy by casper.infradead.org with local (Exim 4.94.2 #2 (Red Hat Linux))
	id 1mw5c7-00BKuT-BZ; Sat, 11 Dec 2021 16:52:47 +0000
Date: Sat, 11 Dec 2021 16:52:47 +0000
From: Matthew Wilcox <willy@infradead.org>
To: Hyeonggon Yoo <42.hyeyoo@gmail.com>
Cc: Vlastimil Babka <vbabka@suse.cz>, Christoph Lameter <cl@linux.com>,
	David Rientjes <rientjes@google.com>,
	Joonsoo Kim <iamjoonsoo.kim@lge.com>,
	Pekka Enberg <penberg@kernel.org>, linux-mm@kvack.org,
	Andrew Morton <akpm@linux-foundation.org>, patches@lists.linux.dev,
	Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com
Subject: Re: [PATCH v2 31/33] mm/sl*b: Differentiate struct slab fields by
 sl*b implementations
Message-ID: <YbTXXwVy/a+/9PCn@casper.infradead.org>
References: <20211201181510.18784-1-vbabka@suse.cz>
 <20211201181510.18784-32-vbabka@suse.cz>
 <20211210163757.GA717823@odroid>
 <f3f02e1e-88b2-a188-1679-9c6256d19c7a@suse.cz>
 <20211211115527.GA822127@odroid>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20211211115527.GA822127@odroid>
X-Original-Sender: willy@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=casper.20170209 header.b=BAKk3TlO;
       spf=pass (google.com: best guess record for domain of
 willy@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) smtp.mailfrom=willy@infradead.org
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

On Sat, Dec 11, 2021 at 11:55:27AM +0000, Hyeonggon Yoo wrote:
> On Fri, Dec 10, 2021 at 07:26:11PM +0100, Vlastimil Babka wrote:
> > On 12/10/21 17:37, Hyeonggon Yoo wrote:
> > > On Wed, Dec 01, 2021 at 07:15:08PM +0100, Vlastimil Babka wrote:
> > >> With a struct slab definition separate from struct page, we can go further and
> > >> define only fields that the chosen sl*b implementation uses. This means
> > >> everything between __page_flags and __page_refcount placeholders now depends on
> > >> the chosen CONFIG_SL*B.
> > > 
> > > When I read this patch series first, I thought struct slab is allocated
> > > separately from struct page.
> > > 
> > > But after reading it again, It uses same allocated space of struct page.
> > 
> > Yes. Allocating it elsewhere is something that can be discussed later. It's
> > not a simple clear win - more memory used, more overhead, complicated code...
> >
> 
> Right. That is a something that can be discussed,
> But I don't think there will be much win.

Oh no, there's a substantial win.  If we can reduce struct page to a
single pointer, that shrinks it from 64 bytes/4k to 8 bytes/4k.  Set
against that, you have to allocate the struct folio / struct slab / ...
but then it's one _per allocation_ rather than one per page.  So for
an order-2 allocation, it takes 32 bytes + 64 bytes (= 96 bytes)
rather than 4*64 = 256 bytes.  It's an even bigger win for larger
allocations, and it lets us grow the memory descriptors independently
of each other.

But it's also a substantial amount of work, so don't expect us to get
there any time soon.  Everything currently using struct page needs to
be converted to use another type, and that's just the pre-requisite
step.

Some more thoughts on this here:
https://lore.kernel.org/linux-mm/YXcLqcFhDq3uUwIj@casper.infradead.org/

> > Yeah. Also whatever aliases with compound_head must not have bit zero set as
> > that means a tail page.
> > 
> 
> Oh I was missing that. Thank you.
> 
> Hmm then in struct slab, page->compound_head and slab->list_head (or
> slab->rcu_head) has same offset. And list_head / rcu_head both store pointers.
> 
> then it has a alignment requirement. (address saved in list_head/rcu_head
> should be multiple of 2)
> 
> Anyway, it was required long time before this patch,
> so it is not a problem for this patch.

Yes, that's why there's an assert that the list_heads all line up.  This
requirement will go away if we do get separately allocated memory
descriptors (because that bottom bit is no longer PageTail).

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YbTXXwVy/a%2B/9PCn%40casper.infradead.org.
