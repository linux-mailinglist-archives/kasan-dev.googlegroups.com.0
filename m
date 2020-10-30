Return-Path: <kasan-dev+bncBCCMH5WKTMGRBIOI576AKGQEANF2UNI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33d.google.com (mail-wm1-x33d.google.com [IPv6:2a00:1450:4864:20::33d])
	by mail.lfdr.de (Postfix) with ESMTPS id CC1BB2A01F6
	for <lists+kasan-dev@lfdr.de>; Fri, 30 Oct 2020 11:00:01 +0100 (CET)
Received: by mail-wm1-x33d.google.com with SMTP id r19sf1042825wmh.9
        for <lists+kasan-dev@lfdr.de>; Fri, 30 Oct 2020 03:00:01 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1604052001; cv=pass;
        d=google.com; s=arc-20160816;
        b=kETko0+OdcY19Gx4eShI+AXbq69Nnni6BFTWYkFn7iOJHotBkYLJUURHOHHaTjgdyI
         vV0O9dcE4IE22+1NDem0tLW4H++sF8QMLHdCoYIepGjBEmkoL92PSYBDhNvhmBoJH3g5
         YgK4hXBC+uHp/CYGIbbKxGlGzzcPjbH0eoifBLdJ4dE73tVe+q0D8cQsN6ki3YELvg7F
         0BTFJvX+fYjrCt0TXOPSSGXfC9WZMbP95wO0soh9ZkO/ytxeHdpsE9cCKeKCVudpYCuY
         Bai4gUc7WhKo3jz6vTm1x9I+acKGi28Qmb/nQl664UnccO6ZhtTzM0piSCWhCETHm4ov
         texw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=rAtpzOmFLx82f2VXQb3w5zwEWCpwf5F3MV0tqRI/+Ik=;
        b=0k6ZFffSFmVe1iMMhaOfUAC3f6m/DE7T0H5lf52MUjIXps0uC6LmcBkej5DMB6CamY
         DL6ElEQsmFi/2nkvL2nYclF7l8/yZkLUoPcKijoKUKSevaOOPCoRjsF7JHyyHehE+iE4
         6Q7eqrihf3w1LrPBDk2S52bpHykT/GZFFxhDF006H5q3UqKWM8ARfnqOW0xWDKSZvxrh
         t9FX0PSTM7pcoW91MqNHxqQjiEbEW9fuH8N5BlGCT5dQhlktFQC15R+fJNfO5EIIRzVK
         36MHQMzkqleFkQ8KqqCsQWe4ILNwhSbOVUFzVhO2p+sCsv0Z9sXruVh04cN0tHWX4svt
         2+7Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=MFhtam6c;
       spf=pass (google.com: domain of glider@google.com designates 2a00:1450:4864:20::442 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=rAtpzOmFLx82f2VXQb3w5zwEWCpwf5F3MV0tqRI/+Ik=;
        b=lIkvEd8H1uNkigRRVBRMZ/0IljBdl7g8AshrR6Gk6NAS9ufDfJAG2Xtd2xa60/luHB
         UMdonykxfnufxnJhP+ICyZz8BgRrD9w5DmYKPeBVilnqlRYrqHsixR+ebVCpH6POZnfz
         asa3W/jih66hJIKf6iejLZt4U+Vkst0c4+3Q6o2/wgs7UIGK7QD1tyRnKL3bob7t1xfY
         655MvcgYnfEb31upmVnNcohgT6RHR98+toDOflr4+CRz6C9jW+KV4Vqb1C6TWdTyN8jf
         ZPWQbs9iPeDRJgu+SHbZbrrgVJlpTY2urIAiAcymuRgAnmODfAFTqBAJqF0uy7Fn6zZZ
         FqXg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=rAtpzOmFLx82f2VXQb3w5zwEWCpwf5F3MV0tqRI/+Ik=;
        b=OXYcxoWiPXlaTbG+grGStnXrObZKRE9Oe213wE8wQHaWWsiW4njhOD6iipVy0Bw7MJ
         HvWXOTlpaQVkNAYMFcyA0UmlXMyDB4N6huEiOB1qIDoKEDkmLn4hHocMttAY/JRLPW9n
         /VtKXLcfMOkZhsckORgvdlmohbUZfqNSWeqZKwcypHqZIhCbNb2gdHZHb6YK+JhfNCyO
         9BU43bankjTUQk2aG0lt0QttmIVXmx9hisEWHeYCyB1pdL2H4FjR/Kw1r/s/npQhjccv
         DyLAFjkJT4f+OrlIXFC8EdpXn6UyfJ1BA7lE2HgZo93XkrTtBWHKT8Qgj+LhjOxqljTT
         hcuQ==
X-Gm-Message-State: AOAM530X6FxAgzGGhO11HgXwfhw8SI2a5F05YOeYiYK2gh1YEsRPUFyS
	oTomEylDk2rIuO52wmKM1EI=
X-Google-Smtp-Source: ABdhPJxPOuo0MrODBJKd6nzzF50jkAe0c4xLRAuqSxzw1qfFJTfUzBJliQkUIiD3QyLzVAOuXZYDoQ==
X-Received: by 2002:adf:f643:: with SMTP id x3mr2131955wrp.180.1604052001408;
        Fri, 30 Oct 2020 03:00:01 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:7e4e:: with SMTP id z75ls1371185wmc.0.canary-gmail; Fri,
 30 Oct 2020 03:00:00 -0700 (PDT)
X-Received: by 2002:aa7:ce8d:: with SMTP id y13mr1435763edv.65.1604052000481;
        Fri, 30 Oct 2020 03:00:00 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1604052000; cv=none;
        d=google.com; s=arc-20160816;
        b=znxsdtC8b+i+sGWEhQNUpoHWfatHeK8xcKiG2268C7XQ26cHbeYGtinmPEVP+/cacC
         Irx6sfpuriBlv2p300FgQmtTTvPRhFNJy/tMhA3XQ+7hjIxN+m7viGx/Mxog0ijLWMLg
         jaqOFL+raUUIFpqT0Bn4kD1hCRYOvFw4kXDr70aD/6TkqetfNwQXZZZlkezHl3AAbbDP
         duNzcZdDwqRoIxPefFS48uZ3eJ9BIkBiw2aA0pmBbquIOpedkTIR7VJ5NC3Dw6GuwXmZ
         o9rbrcmoUtS+t8A+kSQwG8swjAyv8k8/fMrdbnIF0I4CWO85o25Y6TFlYCXcM/BB3cD0
         qClQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=1kpn8tL60J6jUZj6S/8IL9NPr/GsyMly5AdFbYCZgvQ=;
        b=oV0l+mVRv/MECGn2/XRzSx0vWNrrw+fbbB1WpvpTsAMKaEdoauWLWy1FW+op3nbWOR
         mbt9aLR6pZni+XLkSsXTfmR/Be/ZiX0WIb9KuF891noG273hLy0BsOAWqNhJFZViNpgD
         5WXTFl3i5RNmcKFiAVIK1lwEjCIXqXsO85ZupPtTVfnwUq+qQlsFTBSS+rfxNQFdKlSa
         +umEevRWaPqvrkJcH1qb8HD18KEMVGudn+TgUP4qvAQCdFv3ngcq7m/CzfgM950o8Bst
         uE1XX8Sp6rp1IVQVJEGbwK1S2H+6OIOXMYal0/9S1OROqmnRLyJmNO6TGvkSej1CMVW/
         SSjA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=MFhtam6c;
       spf=pass (google.com: domain of glider@google.com designates 2a00:1450:4864:20::442 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x442.google.com (mail-wr1-x442.google.com. [2a00:1450:4864:20::442])
        by gmr-mx.google.com with ESMTPS id n7si132575edy.3.2020.10.30.03.00.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 30 Oct 2020 03:00:00 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2a00:1450:4864:20::442 as permitted sender) client-ip=2a00:1450:4864:20::442;
Received: by mail-wr1-x442.google.com with SMTP id t9so5722891wrq.11
        for <kasan-dev@googlegroups.com>; Fri, 30 Oct 2020 03:00:00 -0700 (PDT)
X-Received: by 2002:adf:ea49:: with SMTP id j9mr2008573wrn.391.1604051999974;
 Fri, 30 Oct 2020 02:59:59 -0700 (PDT)
MIME-Version: 1.0
References: <20201029131649.182037-1-elver@google.com> <20201029131649.182037-8-elver@google.com>
 <CAG48ez2ak7mWSSJJ3Zxd+cK1c5uZVqeF2zZ9HLtmXEoiG5=m-Q@mail.gmail.com>
In-Reply-To: <CAG48ez2ak7mWSSJJ3Zxd+cK1c5uZVqeF2zZ9HLtmXEoiG5=m-Q@mail.gmail.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 30 Oct 2020 10:59:48 +0100
Message-ID: <CAG_fn=Xq+E5s_2rVBm-cM4Bvfyn9Ar9fTHWtxeFFZkcAUBwHiQ@mail.gmail.com>
Subject: Re: [PATCH v6 7/9] kfence, Documentation: add KFENCE documentation
To: Jann Horn <jannh@google.com>
Cc: Marco Elver <elver@google.com>, Andrew Morton <akpm@linux-foundation.org>, 
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
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=MFhtam6c;       spf=pass
 (google.com: domain of glider@google.com designates 2a00:1450:4864:20::442 as
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

On Fri, Oct 30, 2020 at 3:50 AM Jann Horn <jannh@google.com> wrote:
>
> On Thu, Oct 29, 2020 at 2:17 PM Marco Elver <elver@google.com> wrote:
> > Add KFENCE documentation in dev-tools/kfence.rst, and add to index.
> [...]
> > +The KFENCE memory pool is of fixed size, and if the pool is exhausted,=
 no
> > +further KFENCE allocations occur. With ``CONFIG_KFENCE_NUM_OBJECTS`` (=
default
> > +255), the number of available guarded objects can be controlled. Each =
object
> > +requires 2 pages, one for the object itself and the other one used as =
a guard
> > +page; object pages are interleaved with guard pages, and every object =
page is
> > +therefore surrounded by two guard pages.
> > +
> > +The total memory dedicated to the KFENCE memory pool can be computed a=
s::
> > +
> > +    ( #objects + 1 ) * 2 * PAGE_SIZE
>
> Plus memory overhead from shattered hugepages. With the default object
> count, on x86, we allocate 2MiB of memory pool, but if we have to
> shatter a 2MiB hugepage for that, we may cause the allocation of one
> extra page table, or 4KiB. Of course that's pretty much negligible.
> But on arm64 it's worse, because there we have to disable hugepages in
> the linear map completely. So on a device with 4GiB memory, we might
> end up with something on the order of 4GiB/2MiB * 0x1000 bytes =3D 8MiB
> of extra L1 page tables that wouldn't have been needed otherwise -
> significantly more than the default memory pool size.

Note that with CONFIG_RODATA_FULL_DEFAULT_ENABLED (which is on by
default now) these hugepages are already disabled (see patch 3/9)

> If the memory overhead is documented, this detail should probably be
> documented, too.

But, yes, documenting that also makes sense.

> > +Using the default config, and assuming a page size of 4 KiB, results i=
n
> > +dedicating 2 MiB to the KFENCE memory pool.
> [...]
> > +For such errors, the address where the corruption as well as the inval=
idly
>
> nit: "the address where the corruption occurred" or "the address of
> the corruption"
>
> > +written bytes (offset from the address) are shown; in this representat=
ion, '.'
> > +denote untouched bytes. In the example above ``0xac`` is the value wri=
tten to
> > +the invalid address at offset 0, and the remaining '.' denote that no =
following
> > +bytes have been touched. Note that, real values are only shown for
> > +``CONFIG_DEBUG_KERNEL=3Dy`` builds; to avoid information disclosure fo=
r non-debug
> > +builds, '!' is used instead to denote invalidly written bytes.
> [...]
> > +KFENCE objects each reside on a dedicated page, at either the left or =
right
> > +page boundaries selected at random. The pages to the left and right of=
 the
> > +object page are "guard pages", whose attributes are changed to a prote=
cted
> > +state, and cause page faults on any attempted access. Such page faults=
 are then
> > +intercepted by KFENCE, which handles the fault gracefully by reporting=
 an
> > +out-of-bounds access.
>
> ... and marking the page as accessible so that the faulting code can
> continue (wrongly) executing.
>
>
> [...]
> > +Interface
> > +---------
> > +
> > +The following describes the functions which are used by allocators as =
well page
>
> nit: "as well as"?
>
>
>
> > +handling code to set up and deal with KFENCE allocations.



--=20
Alexander Potapenko
Software Engineer

Google Germany GmbH
Erika-Mann-Stra=C3=9Fe, 33
80636 M=C3=BCnchen

Gesch=C3=A4ftsf=C3=BChrer: Paul Manicle, Halimah DeLaine Prado
Registergericht und -nummer: Hamburg, HRB 86891
Sitz der Gesellschaft: Hamburg

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG_fn%3DXq%2BE5s_2rVBm-cM4Bvfyn9Ar9fTHWtxeFFZkcAUBwHiQ%40mail.gm=
ail.com.
