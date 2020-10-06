Return-Path: <kasan-dev+bncBCQ2XPNX7EOBBC7T6L5QKGQEFFPI2NQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13d.google.com (mail-lf1-x13d.google.com [IPv6:2a00:1450:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id 96BB62851B1
	for <lists+kasan-dev@lfdr.de>; Tue,  6 Oct 2020 20:38:04 +0200 (CEST)
Received: by mail-lf1-x13d.google.com with SMTP id f7sf224309lfj.9
        for <lists+kasan-dev@lfdr.de>; Tue, 06 Oct 2020 11:38:04 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1602009484; cv=pass;
        d=google.com; s=arc-20160816;
        b=mwoCTyvZGFQkZzeHSMazYvyoaKqf2WSoAXLWrKyiJO7aYJ2BkyA/2ovvW+gN2IgkdO
         0I/J34iZv5irluaBvZNX0K5ZA0xkRoQO/Wfmj4apZu+4zrmbOsRVmOjeWXWwksJ5MpVd
         iuQyFJ4URhzcwsUzbXZCia/ICCb7U8wKCFclVJGpxBeBj/dyFnPpoREXDETeV1cxZX9B
         GUZaaUrk6LK+Lueq36cGmsM/oDG+nyxcqwQUw9FhNcKyQAxiCxW9Tod7nTiukyPMqJuv
         6pUZU70dN5rzs64z+OlwQO96kz62BvmYV4rFJn8NC25O81k6QPmD14B3qAElNLwqoTHK
         TF+Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=c0DqQzBXhnqFU7feDj0hope1+aJ8r1mMvUmnTxgDGIw=;
        b=obXE9xmveCuld45VHDqO6FcoufSNHVvZ2WT6ZZMSHckcgm6xXbMFEo5yIwshNgCcMh
         dtwFB48xwbfXhzff5NCLfErXKIG6oGQqW3kqZlr7k1m5ysmixBts25KyAGpBU9WHx2qs
         xOCYxp75QDxVgXMAzdi9wrWsF+NYgkNx2wkf+n7MN625T/x8iz+OGn9z+1Irjd/XBZch
         /VtSOTnigEvCZ4fOjr2t7wyVsVGjrXYeW97z+iwzSsA9I//DLx5ejQQUdlhlIQVQOnil
         xOdNAe8YbclgaqJI8PMpaGIsK/xOmz4MMNfmcSsOB9sd3cPvTTf4YF0gU9VPEwU4WlA8
         PqPg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=PM0JMNHP;
       spf=pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::641 as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=c0DqQzBXhnqFU7feDj0hope1+aJ8r1mMvUmnTxgDGIw=;
        b=JlXgnxtu1/8ozyT0rbz2lrZ5eKIdUtbSoruwfuH8BfhQbDHfoeh/G6EPuDNdlUM/BE
         kExDDmNyPD8Xpphe+31qBhnbT0akc0MqI/eQs+xeEikFLPdkNlTx8LziTDI5/VZ5PwQZ
         v7gSn+aXKcS6+oCX4bSEc5yxtDJO6Sa3oWCMF5VoImFrW5y8rYIZhrrVOS6iX6KwRpcL
         AH8BZqckSglxDJ7gs5bpFYbUf8iu3tbTYauqECmunRTDyhux5iHSeksMAEChU/FjEqbs
         MXQTvqQw95cWDFY/ojlAdqIZPrpVkoaWz3nUTsLh3g1U6YzXjdlfO7wUeQ9YslOWApBE
         OBcQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=c0DqQzBXhnqFU7feDj0hope1+aJ8r1mMvUmnTxgDGIw=;
        b=Xd0G3yZDcQdoKyAUvB+KY52GqV0q+VDuPg4j5zXvzLQEk7SdI0i+sRXVhrIpLsA0iy
         48xWTtS1+Ld8g6/Ew7lvBNVtEd6WigEGookCVVMdo8VyxlemdkpyXK+rYSwdm8Pq1Kdp
         PymRpP9UIa5zTdfwqEsOWkXHdTG4UoWEMaY3tQsIz+3nYTxt9StdJkD/R6qkCVwo7tyC
         TsS6b2htPBLQy8vHEwNG4loi2ju1D2qKyRA086edjgrMG15P4Jkmlj/TJlSV4IF0iGLR
         RLKFSOf/vRdVoDlZowbAJyICa3SxYO2zmH26fQuK1I/FcbGxwXM5L6cVhBw5ML1WkBfU
         cTPw==
X-Gm-Message-State: AOAM533ArLRK7CdGNH9FWA0jJHMRIGDmFqn8yWubq5vhEBLDEwBt7JvN
	09UyeayGphicsNTmgyBE1E8=
X-Google-Smtp-Source: ABdhPJzspQUPAn+w4MwGQcbwax/7bblbzzaAo8jX4kyGbYjC2787TJZaFbLvmP5f5nkCO2uLb5D+ag==
X-Received: by 2002:a19:650a:: with SMTP id z10mr1021432lfb.9.1602009484125;
        Tue, 06 Oct 2020 11:38:04 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a19:84c1:: with SMTP id g184ls113367lfd.3.gmail; Tue, 06 Oct
 2020 11:38:03 -0700 (PDT)
X-Received: by 2002:a19:8c4a:: with SMTP id i10mr1010268lfj.566.1602009482976;
        Tue, 06 Oct 2020 11:38:02 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1602009482; cv=none;
        d=google.com; s=arc-20160816;
        b=NOJNrokZQLEHQeFRSTH4XD1VAHJnhj6UNfrynpniKFsImDRk7Bxb5IsW1lTFWAwFSk
         t8wK+v5NGP/rNtpVWsuKMEmGXUZQkPAIly7a/tk1wu99OEZio+QcwOmPKFlt69wnmnZH
         qJ+yqrIoP7rHfgVuibKofUR6Z6P0oUDZ+zoDI2+A4G9SOt0Loh/ofwMp1fNlyUdvMCi9
         dB8PXHOY0Uvw2mSJZBCHXF1h+fMvtLO0p6CZIw6Xtvl4l3isIw9t1h5+3r4mGfc434Ih
         EnymrrBOteSUA0xvfcOkgM7Gczj4fTbu+brptv7CIYSoWPI+x03cbhEhds74pX396okg
         hnKg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=iiFZhuwHNBTR9+4Q7mOK5ZAfJhgSvj1um5FsudlQqFU=;
        b=VigLWDpxqSGHxAkJ/pvscTcFnaZGJkOsqW3dkBL2978Ax60Od1XiJ7oqO+j1DeFMSv
         4ZkiancISqvAKodoER4f9bOW4PKgmuwyUBksdW4W1SdBkQbscWuaIpt6MHJTr/oSJqc5
         EyHefL6IZ12Qfl3E4/AMBqvd0WjS4u1OnD/dYLsQliir6yRmJqt1BvAshCLX3N4lBRCE
         Wx3pdU9aw71EhxiVWfx+y/WOI6UC94xhH6cj8hpO8tQip8ijOK6p9aTIeDoe316n5rbW
         A6ER0WLO59t5mXOvoIEo9UWX0qJfxfSFX14dUPW6wEAzATP1iuBY7M+bXe0q9FwjY9tX
         D7kA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=PM0JMNHP;
       spf=pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::641 as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ej1-x641.google.com (mail-ej1-x641.google.com. [2a00:1450:4864:20::641])
        by gmr-mx.google.com with ESMTPS id o142si105817lff.6.2020.10.06.11.38.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 06 Oct 2020 11:38:02 -0700 (PDT)
Received-SPF: pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::641 as permitted sender) client-ip=2a00:1450:4864:20::641;
Received: by mail-ej1-x641.google.com with SMTP id h24so12547821ejg.9
        for <kasan-dev@googlegroups.com>; Tue, 06 Oct 2020 11:38:02 -0700 (PDT)
X-Received: by 2002:a17:906:9156:: with SMTP id y22mr981885ejw.184.1602009482216;
 Tue, 06 Oct 2020 11:38:02 -0700 (PDT)
MIME-Version: 1.0
References: <20200929183513.380760-1-alex.popov@linux.com> <91d564a6-9000-b4c5-15fd-8774b06f5ab0@linux.com>
 <CAG48ez1tNU_7n8qtnxTYZ5qt-upJ81Fcb0P2rZe38ARK=iyBkA@mail.gmail.com> <1b5cf312-f7bb-87ce-6658-5ca741c2e790@linux.com>
In-Reply-To: <1b5cf312-f7bb-87ce-6658-5ca741c2e790@linux.com>
From: "'Jann Horn' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 6 Oct 2020 20:37:35 +0200
Message-ID: <CAG48ez17s4NyH6r_Xjsx+Of7hsu6Nwp3Kwi+NjgP=3CY4_DHTA@mail.gmail.com>
Subject: Re: [PATCH RFC v2 0/6] Break heap spraying needed for exploiting use-after-free
To: Alexander Popov <alex.popov@linux.com>
Cc: Kees Cook <keescook@chromium.org>, Will Deacon <will@kernel.org>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Christoph Lameter <cl@linux.com>, Pekka Enberg <penberg@kernel.org>, 
	David Rientjes <rientjes@google.com>, Joonsoo Kim <iamjoonsoo.kim@lge.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Masahiro Yamada <masahiroy@kernel.org>, 
	Masami Hiramatsu <mhiramat@kernel.org>, Steven Rostedt <rostedt@goodmis.org>, 
	Peter Zijlstra <peterz@infradead.org>, Krzysztof Kozlowski <krzk@kernel.org>, 
	Patrick Bellasi <patrick.bellasi@arm.com>, David Howells <dhowells@redhat.com>, 
	Eric Biederman <ebiederm@xmission.com>, Johannes Weiner <hannes@cmpxchg.org>, 
	Laura Abbott <labbott@redhat.com>, Arnd Bergmann <arnd@arndb.de>, 
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>, Daniel Micay <danielmicay@gmail.com>, 
	Andrey Konovalov <andreyknvl@google.com>, Matthew Wilcox <willy@infradead.org>, 
	Pavel Machek <pavel@denx.de>, Valentin Schneider <valentin.schneider@arm.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, Linux-MM <linux-mm@kvack.org>, 
	Kernel Hardening <kernel-hardening@lists.openwall.com>, 
	kernel list <linux-kernel@vger.kernel.org>, notify@kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: jannh@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=PM0JMNHP;       spf=pass
 (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::641 as
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

On Tue, Oct 6, 2020 at 7:56 PM Alexander Popov <alex.popov@linux.com> wrote:
>
> On 06.10.2020 01:56, Jann Horn wrote:
> > On Thu, Oct 1, 2020 at 9:43 PM Alexander Popov <alex.popov@linux.com> wrote:
> >> On 29.09.2020 21:35, Alexander Popov wrote:
> >>> This is the second version of the heap quarantine prototype for the Linux
> >>> kernel. I performed a deeper evaluation of its security properties and
> >>> developed new features like quarantine randomization and integration with
> >>> init_on_free. That is fun! See below for more details.
> >>>
> >>>
> >>> Rationale
> >>> =========
> >>>
> >>> Use-after-free vulnerabilities in the Linux kernel are very popular for
> >>> exploitation. There are many examples, some of them:
> >>>  https://googleprojectzero.blogspot.com/2018/09/a-cache-invalidation-bug-in-linux.html
>
> Hello Jann, thanks for your reply.
>
> > I don't think your proposed mitigation would work with much
> > reliability against this bug; the attacker has full control over the
> > timing of the original use and the following use, so an attacker
> > should be able to trigger the kmem_cache_free(), then spam enough new
> > VMAs and delete them to flush out the quarantine, and then do heap
> > spraying as normal, or something like that.
>
> The randomized quarantine will release the vulnerable object at an unpredictable
> moment (patch 4/6).
>
> So I think the control over the time of the use-after-free access doesn't help
> attackers, if they don't have an "infinite spray" -- unlimited ability to store
> controlled data in the kernelspace objects of the needed size without freeing them.
>
> "Unlimited", because the quarantine size is 1/32 of whole memory.
> "Without freeing", because freed objects are erased by init_on_free before going
> to randomized heap quarantine (patch 3/6).
>
> Would you agree?

But you have a single quarantine (per CPU) for all objects, right? So
for a UAF on slab A, the attacker can just spam allocations and
deallocations on slab B to almost deterministically flush everything
in slab A back to the SLUB freelists?

> > Also, note that here, if the reallocation fails, the kernel still
> > wouldn't crash because the dangling object is not accessed further if
> > the address range stored in it doesn't match the fault address. So an
> > attacker could potentially try multiple times, and if the object
> > happens to be on the quarantine the first time, that wouldn't really
> > be a showstopper, you'd just try again.
>
> Freed objects are filled by zero before going to quarantine (patch 3/6).
> Would it cause a null pointer dereference on unsuccessful try?

Not as far as I can tell.

[...]
> >> N.B. There was NO performance optimization made for this version of the heap
> >> quarantine prototype. The main effort was put into researching its security
> >> properties (hope for your feedback). Performance optimization will be done in
> >> further steps, if we see that my work is worth doing.
> >
> > But you are pretty much inherently limited in terms of performance by
> > the effect the quarantine has on the data cache, right?
>
> Yes.
> However, the quarantine parameters can be adjusted.
>
> > It seems to me like, if you want to make UAF exploitation harder at
> > the heap allocator layer, you could do somewhat more effective things
> > with a probably much smaller performance budget. Things like
> > preventing the reallocation of virtual kernel addresses with different
> > types, such that an attacker can only replace a UAF object with
> > another object of the same type. (That is not an idea I like very much
> > either, but I would like it more than this proposal.) (E.g. some
> > browsers implement things along those lines, I believe.)
>
> That's interesting, thank you.

Just as some more context of how I think about this:

Preventing memory corruption, outside of stuff like core memory
management code, isn't really all *that* hard. There are schemes out
there for hardware that reliably protects the integrity of data
pointers, and such things. And if people can do that in hardware, we
can also emulate that, and we'll get the same protection in software.

The hard part is making it reasonably fast. And if you are willing to
accept the kind of performance impact that comes with gigantic
quarantine queues, there might be more effective things to spend that
performance on?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAG48ez17s4NyH6r_Xjsx%2BOf7hsu6Nwp3Kwi%2BNjgP%3D3CY4_DHTA%40mail.gmail.com.
