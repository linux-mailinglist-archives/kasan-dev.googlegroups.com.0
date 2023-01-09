Return-Path: <kasan-dev+bncBCCMH5WKTMGRBSGH56OQMGQEOHKUDOY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33e.google.com (mail-ot1-x33e.google.com [IPv6:2607:f8b0:4864:20::33e])
	by mail.lfdr.de (Postfix) with ESMTPS id C5DB0662218
	for <lists+kasan-dev@lfdr.de>; Mon,  9 Jan 2023 10:52:10 +0100 (CET)
Received: by mail-ot1-x33e.google.com with SMTP id cr28-20020a056830671c00b006774d5923ddsf4165463otb.4
        for <lists+kasan-dev@lfdr.de>; Mon, 09 Jan 2023 01:52:10 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1673257929; cv=pass;
        d=google.com; s=arc-20160816;
        b=QPgehPGGE7MWq2ahQF3xhV11ThFZgMmBFPErUfmpxiBrm7MTjG4xaVct/eDP16Gv/f
         p/7E2vy6+TxRwMvzSl6J5RrrJXp9RUxSneEq1FasJym8YCzzDhjq5Gl1ahNFgYlrbXbx
         kWVU+xufbQ3p+n+J9G9VTh04oYQEkx5MbHhmzg3vHkZkRfcoiW3ROrZ7F0cUA4CHv9f8
         spFWvWsB22WwuwP+V38gFO20Tzyk2s63dFCtYVNYC56gE/MPYt9ITL5ZseN1E6C0evL6
         sKZtRkiDJ7t9xAOKD+N3EOdAQRYlTKooGMaB26EFdYYPfwKgZ+yIUqlBfLmWK2p0mvzt
         cH7g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=vyWSSZ1/ENT6TEZXUAex8Qm+MDrIBlD9gbr/7sVHlDQ=;
        b=EeawCzPI1u3dFY6K69lsUmmQYUWZEJRPPL1pHbrxfuMU06FX4WHpAQzaLhWRnnbmCM
         fuim1oBn5+kqZgiksjG5Cwr5ivFaukBLtfFEQ7C7MAA74c27acIqXErTK4VFWXIGsZts
         ewddakaU+sC1fjF/iHUl6JQW9o8AM2qCQzhv6gaDaYrEwAmA+x2Zp60Wkk+/UZAzwH8F
         lZ+LGgBblwVA4qYqz32RXqgXDHpwoHMGn02DUZHXXu+HxNQfUwABRtTzlfYw9n7tX7Af
         F5i0dBjIJ5ypjvbJE8XbL8qqgFp7eH62O/vp6DV0D8N4UhGiBAgycGI6b542elZLdGvO
         xWRQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=DVfCyJ6P;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::1133 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=vyWSSZ1/ENT6TEZXUAex8Qm+MDrIBlD9gbr/7sVHlDQ=;
        b=Y7smGLQcbnbHOe25l+PDPbExEybru6590fIceh3ar4a4rGiIbz6A//GhXKxMYNg1ZW
         YTbFMP1NxiJnIdlpnUWasmUlJIUmK7GirUa9RXzpBZoxfAOU35SOz6y4RqzZGVuv7C6n
         5dlBW9AnL2sXDG/9jmysAYgCPvsnmZ2okhYkg3BeAP6KFZ79aXi1JXEQwaAhUotubla8
         e6nMb5fwSAqFKATmyklTzWQvxjAFE/LSJz2oS/OLrHNqKa6EWLHmyEy63JTq2zkdzYU1
         r1+yU7845QipRYFf+1OV0n0dx7YQGfTaurw77S3j/vdD3cLiNjYa/8uDxVCp0WcigGZq
         tmyQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-gm-message-state:from:to:cc
         :subject:date:message-id:reply-to;
        bh=vyWSSZ1/ENT6TEZXUAex8Qm+MDrIBlD9gbr/7sVHlDQ=;
        b=R3en8MnQuqdL3NClCIRQcKjqx9LFO5BDLAl37nDPqIS0W563Cz78Urv1AGkfOkzsv7
         0M9hRolQLQ2RsjzhVRX/sIYj0WSix63GK38+zeYP77hYe2tU43TrKVnISUgDSaDlnzzb
         rlca+t/xleqajh0lLemPhEHW/Yvx+95HyNzCWLVvdbvi+rN0CIFI6pO4FbIS4BP1L5J8
         ZQUD6o8AJ16RyDTAEqrxbnpp7+uzxZcclYUIarzRqiEAeZV7f/G3bQ9AWWBYfqW99te7
         vHhxxd6arUND1bhER3sBDmz8QFSCw9AUbV7NrofRousq1akTH5DdE/xEArpr00jhXWti
         e1hg==
X-Gm-Message-State: AFqh2krFXYEUqZl705/2iieLgZWCtn8V1XxjgsG89P7eeaYkPG5OyYx3
	XbBH/qTjcpnHuIg7NQY9PRc=
X-Google-Smtp-Source: AMrXdXsFmP1qB+zVGpnKr0Wbqx8eteMb2jrLgDZqBrcS7Yu8BUVlOobiwwYdnPdmelWUJdldB1Sx+w==
X-Received: by 2002:a05:6870:7991:b0:144:c281:11ed with SMTP id he17-20020a056870799100b00144c28111edmr3614753oab.167.1673257928212;
        Mon, 09 Jan 2023 01:52:08 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6830:26cd:b0:66c:7df0:d6be with SMTP id
 m13-20020a05683026cd00b0066c7df0d6bels1302513otu.8.-pod-prod-gmail; Mon, 09
 Jan 2023 01:52:07 -0800 (PST)
X-Received: by 2002:a05:6830:1252:b0:66d:a2:d0e with SMTP id s18-20020a056830125200b0066d00a20d0emr29304034otp.15.1673257927765;
        Mon, 09 Jan 2023 01:52:07 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1673257927; cv=none;
        d=google.com; s=arc-20160816;
        b=sn30pT/I64VzXWsoTYf5YtH5JlpC5/EHpw8zsWTk8o5PcajrudTee3ocLurGGoP/f3
         H+tuyCn9aKQfPYXIqGhp2L1zPlftU1CxDnC+FgqtncoJztufmdxLk90B/jxK9gQVHNDn
         GRkauFQ6UWyV237zbEg2xlBDwlas53La+3/OGeUHV4euhbJxE/PJ54oDirg7plaSDffn
         Y8GOAESR8qVMh/H4V6cB5myncOChxm27Dxaud58281sSZb6+Zg8/aofJVCQGeqh6n9BM
         gYWb+sQzSoYWh2tHovV+afhH0mWVV3SIStYtNN/etqkYr9igRdyPHJXYhNxF3u6Czqc9
         /d8Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=HAQX3MqHqmIeeOrJpELRmG+wNnU+MpmXY1sRh1DUmgw=;
        b=YaVPsSfv9Dd0YNCxJcFGC5aQj0N9fwyqKqbbbUo6XoXjv6UVEbf7TOgVWJUoCuA6QG
         gY22cVN0wtiryU/JKqWQlLeCzKzfl9ZbUss7oysbJ5dSUSuM6CAZEXQDuKcHHTIsY5Jp
         ymjC+xzohoAn2gt5YU0cWwcbsUYbcXi+/jGtTC7Y0DCaNfqlo8n9Dk1bsH5JVR6EhuJn
         Qv3rdnjbRjm2S/zNe0I9TsapkzlwhdNpoJCgV5eUQtaIK5qAYAJOdaykjFzhqiPX8RrZ
         cweotly2h0wp59Ty0fB/ufD7iQrxavwzyje8H+0xhE1ChaGkKuOZgUONu66Jarz0wq8H
         hFNQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=DVfCyJ6P;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::1133 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x1133.google.com (mail-yw1-x1133.google.com. [2607:f8b0:4864:20::1133])
        by gmr-mx.google.com with ESMTPS id cg15-20020a056830630f00b0066fe878940fsi675971otb.5.2023.01.09.01.52.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 09 Jan 2023 01:52:07 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::1133 as permitted sender) client-ip=2607:f8b0:4864:20::1133;
Received: by mail-yw1-x1133.google.com with SMTP id 00721157ae682-4b718cab0e4so105946357b3.9
        for <kasan-dev@googlegroups.com>; Mon, 09 Jan 2023 01:52:07 -0800 (PST)
X-Received: by 2002:a0d:f084:0:b0:4c2:51b:796c with SMTP id
 z126-20020a0df084000000b004c2051b796cmr993316ywe.144.1673257927353; Mon, 09
 Jan 2023 01:52:07 -0800 (PST)
MIME-Version: 1.0
References: <20220701142310.2188015-1-glider@google.com> <20220701142310.2188015-11-glider@google.com>
 <CANpmjNOYqXSw5+Sxt0+=oOUQ1iQKVtEYHv20=sh_9nywxXUyWw@mail.gmail.com>
 <CAG_fn=W2EUjS8AX1Odunq1==dV178s_-w3hQpyrFBr=Auo-Q-A@mail.gmail.com> <63b74a6e6a909_c81f0294a5@dwillia2-xfh.jf.intel.com.notmuch>
In-Reply-To: <63b74a6e6a909_c81f0294a5@dwillia2-xfh.jf.intel.com.notmuch>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 9 Jan 2023 10:51:30 +0100
Message-ID: <CAG_fn=WjrzaHLfgw7ByFvguHA8z0MA-ZB3Kd0d6CYwmZWVEgjA@mail.gmail.com>
Subject: Re: [PATCH v4 10/45] libnvdimm/pfn_dev: increase MAX_STRUCT_PAGE_SIZE
To: Dan Williams <dan.j.williams@intel.com>
Cc: Marco Elver <elver@google.com>, Alexander Viro <viro@zeniv.linux.org.uk>, 
	Alexei Starovoitov <ast@kernel.org>, Andrew Morton <akpm@linux-foundation.org>, 
	Andrey Konovalov <andreyknvl@google.com>, Andy Lutomirski <luto@kernel.org>, Arnd Bergmann <arnd@arndb.de>, 
	Borislav Petkov <bp@alien8.de>, Christoph Hellwig <hch@lst.de>, Christoph Lameter <cl@linux.com>, 
	David Rientjes <rientjes@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Eric Dumazet <edumazet@google.com>, Greg Kroah-Hartman <gregkh@linuxfoundation.org>, 
	Herbert Xu <herbert@gondor.apana.org.au>, Ilya Leoshkevich <iii@linux.ibm.com>, 
	Ingo Molnar <mingo@redhat.com>, Jens Axboe <axboe@kernel.dk>, Joonsoo Kim <iamjoonsoo.kim@lge.com>, 
	Kees Cook <keescook@chromium.org>, Mark Rutland <mark.rutland@arm.com>, 
	Matthew Wilcox <willy@infradead.org>, "Michael S. Tsirkin" <mst@redhat.com>, Pekka Enberg <penberg@kernel.org>, 
	Peter Zijlstra <peterz@infradead.org>, Petr Mladek <pmladek@suse.com>, 
	Steven Rostedt <rostedt@goodmis.org>, Thomas Gleixner <tglx@linutronix.de>, 
	Vasily Gorbik <gor@linux.ibm.com>, Vegard Nossum <vegard.nossum@oracle.com>, 
	Vlastimil Babka <vbabka@suse.cz>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux Memory Management List <linux-mm@kvack.org>, Linux-Arch <linux-arch@vger.kernel.org>, 
	LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=DVfCyJ6P;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::1133
 as permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
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

On Thu, Jan 5, 2023 at 11:09 PM Dan Williams <dan.j.williams@intel.com> wro=
te:
>
> Alexander Potapenko wrote:
> > (+ Dan Williams)
> > (resending with patch context included)
> >
> > On Mon, Jul 11, 2022 at 6:27 PM Marco Elver <elver@google.com> wrote:
> > >
> > > On Fri, 1 Jul 2022 at 16:23, Alexander Potapenko <glider@google.com> =
wrote:
> > > >
> > > > KMSAN adds extra metadata fields to struct page, so it does not fit=
 into
> > > > 64 bytes anymore.
> > >
> > > Does this somehow cause extra space being used in all kernel configs?
> > > If not, it would be good to note this in the commit message.
> > >
> > I actually couldn't verify this on QEMU, because the driver never got l=
oaded.
> > Looks like this increases the amount of memory used by the nvdimm
> > driver in all kernel configs that enable it (including those that
> > don't use KMSAN), but I am not sure how much is that.
> >
> > Dan, do you know how bad increasing MAX_STRUCT_PAGE_SIZE can be?
>
> Apologies I missed this several months ago. The answer is that this
> causes everyone creating PMEM namespaces on v6.1+ to lose double the
> capacity of their namespace even when not using KMSAN which is too
> wasteful to tolerate. So, I think "6e9f05dc66f9 libnvdimm/pfn_dev:
> increase MAX_STRUCT_PAGE_SIZE" needs to be reverted and replaced with
> something like:
>
> diff --git a/drivers/nvdimm/Kconfig b/drivers/nvdimm/Kconfig
> index 79d93126453d..5693869b720b 100644
> --- a/drivers/nvdimm/Kconfig
> +++ b/drivers/nvdimm/Kconfig
> @@ -63,6 +63,7 @@ config NVDIMM_PFN
>         bool "PFN: Map persistent (device) memory"
>         default LIBNVDIMM
>         depends on ZONE_DEVICE
> +       depends on !KMSAN
>         select ND_CLAIM
>         help
>           Map persistent memory, i.e. advertise it to the memory
>
>
> ...otherwise, what was the rationale for increasing this value? Were you
> actually trying to use KMSAN for DAX pages?

I was just building the kernel with nvdimm driver and KMSAN enabled.
Because KMSAN adds extra data to every struct page, it immediately hit
the following assert:

drivers/nvdimm/pfn_devs.c:796:3: error: call to
__compiletime_assert_330 declared with 'error' attribute: BUILD_BUG_ON
fE
                BUILD_BUG_ON(sizeof(struct page) > MAX_STRUCT_PAGE_SIZE);

The comment before MAX_STRUCT_PAGE_SIZE declaration says "max struct
page size independent of kernel config", but maybe we can afford
making it dependent on CONFIG_KMSAN (and possibly other config options
that increase struct page size)?

I don't mind disabling the driver under KMSAN, but having an extra
ifdef to keep KMSAN support sounds reasonable, WDYT?



--=20
Alexander Potapenko
Software Engineer

Google Germany GmbH
Erika-Mann-Stra=C3=9Fe, 33
80636 M=C3=BCnchen

Gesch=C3=A4ftsf=C3=BChrer: Paul Manicle, Liana Sebastian
Registergericht und -nummer: Hamburg, HRB 86891
Sitz der Gesellschaft: Hamburg

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG_fn%3DWjrzaHLfgw7ByFvguHA8z0MA-ZB3Kd0d6CYwmZWVEgjA%40mail.gmai=
l.com.
