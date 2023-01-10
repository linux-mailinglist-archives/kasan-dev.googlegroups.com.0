Return-Path: <kasan-dev+bncBCCMH5WKTMGRBDWN6SOQMGQEWRYCXUQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x240.google.com (mail-oi1-x240.google.com [IPv6:2607:f8b0:4864:20::240])
	by mail.lfdr.de (Postfix) with ESMTPS id 30DDA663BA6
	for <lists+kasan-dev@lfdr.de>; Tue, 10 Jan 2023 09:49:20 +0100 (CET)
Received: by mail-oi1-x240.google.com with SMTP id j8-20020a056808034800b0035eb41b5638sf3338056oie.14
        for <lists+kasan-dev@lfdr.de>; Tue, 10 Jan 2023 00:49:20 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1673340559; cv=pass;
        d=google.com; s=arc-20160816;
        b=OJNVJGLqe48b8rpxWwWfp/PIFACkZdPohYBIYwIzagAdIFMI7KSCex93TeCby3FzYg
         I50TZwRolXL93vyn9lJjBrkY+NyqguvwpvIJdMRrG62mKAhVYHrDltqxmW13phNZ3ZzK
         gmayvdG/N33qZfqWZSk/RVbuSb8sccrG3d4XjNAYeQZtD40PODI/OG0flxq9HgvrfHdS
         tVHNeUapGNXpL27WiKXrDVNWCjM8NCSLbLqYvegvJ23eeSAskZD8jR2VTcbxS3djEYrV
         0rn4hM09471xd9gqTwLNF7AnDrmGMsHT75GPJHoh/IZ/cW7xlFemFsbBR4s9k6qmX7vJ
         otCQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=fS+fiFL0AOt89oL+K1MdTUkQJGk5qrnqBshNXuvRmaM=;
        b=wT8H1xbWDwORg55NoDxi62EgtioFbuO+b+PjonzM+nKj0Kv6RpwQPrLBycbGzINjfm
         ho4UHDA+mXM5jPrGrZJtN/CINsgV6+VmDfTa1WWOCR497ppO/JGS/+ee9KFCQbw5llKA
         A1VG3z+ERx6Nsc2eYXa7ZQC6STsBPjwMOkba1uuke0oO3inRGnyzkSssEywtZ55D5+Wd
         7SwGBaQqao82/9ILy0gsSRi7MH6Pw0BOP9RAG+9jV1FxMi8BmMrXEEs1ZkcVJmLw0Wh1
         qSGeL0MU/07e5HmT5VMbDZ3kniH5A2jIdpGehYPn3MPIqt7v15DY/A/SbCeIwJjDRgY0
         axyg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=ATTDuPoh;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::112a as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=fS+fiFL0AOt89oL+K1MdTUkQJGk5qrnqBshNXuvRmaM=;
        b=bMXZBYE2n1jROiG9AwmtQVyeiqv9+PtTbeWsCkuLCMlBbhZukGxoWGwQkyVWUWNnIk
         Ve50C66G2hiQiQVPj8q+XpC/Nc+cTpdxeWF7eJVNVOJHmMSFyti6tXNkxmx9+ByRaMWV
         N89OhkJbUkFyZffi6bsDmKEmRUQEPV8TVKTKneUCERWqT3pLGZ7jBU1YvYHslT4rQcpF
         F13dXPBbaiYNt5sZKar+4MF/oXTzLbQIf6BaBFKAbq3AOiKt4dOw+4ogQ2bqsoBdLT0M
         o5pEfNrE7Xmu8sOISvnAHxuzO9VrsN8fK+nBdL0XhY1WUKGrUWtlUFAV6SsDTsr0uquh
         RR6w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-gm-message-state:from:to:cc
         :subject:date:message-id:reply-to;
        bh=fS+fiFL0AOt89oL+K1MdTUkQJGk5qrnqBshNXuvRmaM=;
        b=hWuey19Y8Dv0LQ8p1xVjxbKZMsv5I+vY3yKopB8KvZBFzrXXf3BTKMjtpvTUUoLWV5
         +20eQVHUtenDIdRvQm0kEjnQ3Qpr9Reuw+OvCkywiNmho9T1NgywCKwB4YH9uxTAbf8x
         kw0Q+bxgp1QSMHCJ//pIQahMzDecjV0DLrSN7fVCLdEzLit2YmqyXBCfA5Ytij4UdIy/
         yoisL8yDH/pXOSosRYW/kyKTCDVvqHj43FtZiRAJc2WniXQsC5ygY3v9XqIkuvHJxroJ
         XTyBFVrfeNXYkVsT/sbpceWyuP1NxBp7wVx8WGxHMKZnEVPBimW/BYn7F31knsl2ong6
         AOBQ==
X-Gm-Message-State: AFqh2kpK/ew8S7StG9KZQ+orNGw7x0wCY+wLDKt10mBk+D4X7RXTfQNC
	HyQ449i5fb/5fIuTwhCFkf8=
X-Google-Smtp-Source: AMrXdXv1NoNyr49wb5qFjY3/NJz5PemWOyh2Hi2lS/2ksFsdKPlyiyCu/owpUuBeZsgPtpjsZRXgcA==
X-Received: by 2002:aca:2406:0:b0:364:5615:500a with SMTP id n6-20020aca2406000000b003645615500amr325760oic.105.1673340558849;
        Tue, 10 Jan 2023 00:49:18 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:955c:b0:154:df53:5a8 with SMTP id
 v28-20020a056870955c00b00154df5305a8ls3567766oal.8.-pod-prod-gmail; Tue, 10
 Jan 2023 00:49:18 -0800 (PST)
X-Received: by 2002:a05:6870:3c0c:b0:13b:146:b7ef with SMTP id gk12-20020a0568703c0c00b0013b0146b7efmr30637543oab.14.1673340558431;
        Tue, 10 Jan 2023 00:49:18 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1673340558; cv=none;
        d=google.com; s=arc-20160816;
        b=M7z/oZ61fJuVbnXD+A/EtszFqLShcn8EBqDxCt/ctQlmg5LXfRDL3PlZjj6bUCG01A
         ZkSCXy9xIfx6SzCepFC4y1kwE7Oi3Lj58l3/5NVsd/5yRA2Len4Oua2T2hOtHBlqJFTr
         YO0B+JMOF22TszUot+fL5iH3zx42gVJR25xylEYuf52tCQvl6srT1lijIlnd2Ae0SSLu
         G1AKx5w9jiNQl8db+4FiY/uYGApuDyi1pvlNiwShsePent9At2RGopOLVulr2vlwfQEk
         0sG2NXEqdRaykIL4c7LYSIUU50109AAQ4MYxChZ4SmeK2Y/mlSspoub4NtNjVao5q8HF
         H/Xg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=WnOeOYalhwEQCO6UPq5gBGy6Ta3zdz6VrIAftglxGYY=;
        b=FpeQzaarkcQnEfbmksaDcddcXXq7LlTy7/H01Dhd0ak5isHPkSj2w6RlLvTEHeoyOc
         0qavQxJdbkCAfg+2qmM7Dr/ywzxRMzIBLqTb0snC2nE6jm/DR5lCIkZfDpiWRLZ8ZQUf
         teDYQNyHzdqc1i/y9300mnH5iru6TOgFbCcEgUcTa95ue7E5Bib0Qw0LZM1z/Wucirrr
         nF/ac8ZrsNtIMTw96i+1p+H4bBgEnelE6CLKLeWN5usw2hhWmuB3yaflJU7iDPfKK4Ag
         QKYZDLlAmI1tJsm2imguJicP3vPuyiRia4V7rKPNuuaB/Ii9aJQBpL1V7HFNlQLJifBZ
         0icg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=ATTDuPoh;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::112a as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x112a.google.com (mail-yw1-x112a.google.com. [2607:f8b0:4864:20::112a])
        by gmr-mx.google.com with ESMTPS id t16-20020a056871055000b00153d8f2e54dsi952383oal.2.2023.01.10.00.49.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 10 Jan 2023 00:49:18 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::112a as permitted sender) client-ip=2607:f8b0:4864:20::112a;
Received: by mail-yw1-x112a.google.com with SMTP id 00721157ae682-4a263c4ddbaso146303767b3.0
        for <kasan-dev@googlegroups.com>; Tue, 10 Jan 2023 00:49:18 -0800 (PST)
X-Received: by 2002:a81:c313:0:b0:3e5:4d1a:e506 with SMTP id
 r19-20020a81c313000000b003e54d1ae506mr2190904ywk.299.1673340557796; Tue, 10
 Jan 2023 00:49:17 -0800 (PST)
MIME-Version: 1.0
References: <20220701142310.2188015-1-glider@google.com> <20220701142310.2188015-11-glider@google.com>
 <CANpmjNOYqXSw5+Sxt0+=oOUQ1iQKVtEYHv20=sh_9nywxXUyWw@mail.gmail.com>
 <CAG_fn=W2EUjS8AX1Odunq1==dV178s_-w3hQpyrFBr=Auo-Q-A@mail.gmail.com>
 <63b74a6e6a909_c81f0294a5@dwillia2-xfh.jf.intel.com.notmuch>
 <CAG_fn=WjrzaHLfgw7ByFvguHA8z0MA-ZB3Kd0d6CYwmZWVEgjA@mail.gmail.com>
 <63bc8fec4744a_5178e29467@dwillia2-xfh.jf.intel.com.notmuch>
 <Y7z99mf1M5edxV4A@kroah.com> <63bd0be8945a0_5178e29414@dwillia2-xfh.jf.intel.com.notmuch>
In-Reply-To: <63bd0be8945a0_5178e29414@dwillia2-xfh.jf.intel.com.notmuch>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 10 Jan 2023 09:48:31 +0100
Message-ID: <CAG_fn=X9jBwAvz9gph-02WcLhv3MQkBpvkZAsZRMwEYyT8zVeQ@mail.gmail.com>
Subject: Re: [PATCH v4 10/45] libnvdimm/pfn_dev: increase MAX_STRUCT_PAGE_SIZE
To: Dan Williams <dan.j.williams@intel.com>
Cc: Greg Kroah-Hartman <gregkh@linuxfoundation.org>, Marco Elver <elver@google.com>, 
	Alexander Viro <viro@zeniv.linux.org.uk>, Alexei Starovoitov <ast@kernel.org>, 
	Andrew Morton <akpm@linux-foundation.org>, Andrey Konovalov <andreyknvl@google.com>, 
	Andy Lutomirski <luto@kernel.org>, Arnd Bergmann <arnd@arndb.de>, Borislav Petkov <bp@alien8.de>, 
	Christoph Hellwig <hch@lst.de>, Christoph Lameter <cl@linux.com>, David Rientjes <rientjes@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Eric Dumazet <edumazet@google.com>, 
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
 header.i=@google.com header.s=20210112 header.b=ATTDuPoh;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::112a
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

On Tue, Jan 10, 2023 at 7:55 AM Dan Williams <dan.j.williams@intel.com> wro=
te:
>
> Greg Kroah-Hartman wrote:
> > On Mon, Jan 09, 2023 at 02:06:36PM -0800, Dan Williams wrote:
> > > Alexander Potapenko wrote:
> > > > On Thu, Jan 5, 2023 at 11:09 PM Dan Williams <dan.j.williams@intel.=
com> wrote:
> > > > >
> > > > > Alexander Potapenko wrote:
> > > > > > (+ Dan Williams)
> > > > > > (resending with patch context included)
> > > > > >
> > > > > > On Mon, Jul 11, 2022 at 6:27 PM Marco Elver <elver@google.com> =
wrote:
> > > > > > >
> > > > > > > On Fri, 1 Jul 2022 at 16:23, Alexander Potapenko <glider@goog=
le.com> wrote:
> > > > > > > >
> > > > > > > > KMSAN adds extra metadata fields to struct page, so it does=
 not fit into
> > > > > > > > 64 bytes anymore.
> > > > > > >
> > > > > > > Does this somehow cause extra space being used in all kernel =
configs?
> > > > > > > If not, it would be good to note this in the commit message.
> > > > > > >
> > > > > > I actually couldn't verify this on QEMU, because the driver nev=
er got loaded.
> > > > > > Looks like this increases the amount of memory used by the nvdi=
mm
> > > > > > driver in all kernel configs that enable it (including those th=
at
> > > > > > don't use KMSAN), but I am not sure how much is that.
> > > > > >
> > > > > > Dan, do you know how bad increasing MAX_STRUCT_PAGE_SIZE can be=
?
> > > > >
> > > > > Apologies I missed this several months ago. The answer is that th=
is
> > > > > causes everyone creating PMEM namespaces on v6.1+ to lose double =
the
> > > > > capacity of their namespace even when not using KMSAN which is to=
o
> > > > > wasteful to tolerate. So, I think "6e9f05dc66f9 libnvdimm/pfn_dev=
:
> > > > > increase MAX_STRUCT_PAGE_SIZE" needs to be reverted and replaced =
with
> > > > > something like:
> > > > >
> > > > > diff --git a/drivers/nvdimm/Kconfig b/drivers/nvdimm/Kconfig
> > > > > index 79d93126453d..5693869b720b 100644
> > > > > --- a/drivers/nvdimm/Kconfig
> > > > > +++ b/drivers/nvdimm/Kconfig
> > > > > @@ -63,6 +63,7 @@ config NVDIMM_PFN
> > > > >         bool "PFN: Map persistent (device) memory"
> > > > >         default LIBNVDIMM
> > > > >         depends on ZONE_DEVICE
> > > > > +       depends on !KMSAN
> > > > >         select ND_CLAIM
> > > > >         help
> > > > >           Map persistent memory, i.e. advertise it to the memory
> > > > >
> > > > >
> > > > > ...otherwise, what was the rationale for increasing this value? W=
ere you
> > > > > actually trying to use KMSAN for DAX pages?
> > > >
> > > > I was just building the kernel with nvdimm driver and KMSAN enabled=
.
> > > > Because KMSAN adds extra data to every struct page, it immediately =
hit
> > > > the following assert:
> > > >
> > > > drivers/nvdimm/pfn_devs.c:796:3: error: call to
> > > > __compiletime_assert_330 declared with 'error' attribute: BUILD_BUG=
_ON
> > > > fE
> > > >                 BUILD_BUG_ON(sizeof(struct page) > MAX_STRUCT_PAGE_=
SIZE);
> > > >
> > > > The comment before MAX_STRUCT_PAGE_SIZE declaration says "max struc=
t
> > > > page size independent of kernel config", but maybe we can afford
> > > > making it dependent on CONFIG_KMSAN (and possibly other config opti=
ons
> > > > that increase struct page size)?
> > > >
> > > > I don't mind disabling the driver under KMSAN, but having an extra
> > > > ifdef to keep KMSAN support sounds reasonable, WDYT?
> > >
> > > How about a module parameter to opt-in to the increased permanent
> > > capacity loss?
> >
> > Please no, this isn't the 1990's, we should never force users to keep
> > track of new module parameters that you then have to support for
> > forever.
>
> Fair enough, premature enabling. If someone really wants this they can
> find this thread in the archives and ask for another solution like
> compile time override.
>
> >
> >
> > >
> > > -- >8 --
> > > >From 693563817dea3fd8f293f9b69ec78066ab1d96d2 Mon Sep 17 00:00:00 20=
01
> > > From: Dan Williams <dan.j.williams@intel.com>
> > > Date: Thu, 5 Jan 2023 13:27:34 -0800
> > > Subject: [PATCH] nvdimm: Support sizeof(struct page) > MAX_STRUCT_PAG=
E_SIZE
> > >
> > > Commit 6e9f05dc66f9 ("libnvdimm/pfn_dev: increase MAX_STRUCT_PAGE_SIZ=
E")
> > >
> > > ...updated MAX_STRUCT_PAGE_SIZE to account for sizeof(struct page)
> > > potentially doubling in the case of CONFIG_KMSAN=3Dy. Unfortunately t=
his
> > > doubles the amount of capacity stolen from user addressable capacity =
for
> > > everyone, regardless of whether they are using the debug option. Reve=
rt
> > > that change, mandate that MAX_STRUCT_PAGE_SIZE never exceed 64, but
> > > allow for debug scenarios to proceed with creating debug sized page m=
aps
> > > with a new 'libnvdimm.page_struct_override' module parameter.
> > >
> > > Note that this only applies to cases where the page map is permanent,
> > > i.e. stored in a reservation of the pmem itself ("--map=3Ddev" in "nd=
ctl
> > > create-namespace" terms). For the "--map=3Dmem" case, since the alloc=
ation
> > > is ephemeral for the lifespan of the namespace, there are no explicit
> > > restriction. However, the implicit restriction, of having enough
> > > available "System RAM" to store the page map for the typically large
> > > pmem, still applies.
> > >
> > > Fixes: 6e9f05dc66f9 ("libnvdimm/pfn_dev: increase MAX_STRUCT_PAGE_SIZ=
E")
> > > Cc: <stable@vger.kernel.org>
> > > Cc: Alexander Potapenko <glider@google.com>
> > > Cc: Marco Elver <elver@google.com>
> > > Reported-by: Jeff Moyer <jmoyer@redhat.com>
> > > ---
> > >  drivers/nvdimm/nd.h       |  2 +-
> > >  drivers/nvdimm/pfn_devs.c | 45 ++++++++++++++++++++++++++-----------=
--
> > >  2 files changed, 31 insertions(+), 16 deletions(-)
> > >
> > > diff --git a/drivers/nvdimm/nd.h b/drivers/nvdimm/nd.h
> > > index 85ca5b4da3cf..ec5219680092 100644
> > > --- a/drivers/nvdimm/nd.h
> > > +++ b/drivers/nvdimm/nd.h
> > > @@ -652,7 +652,7 @@ void devm_namespace_disable(struct device *dev,
> > >             struct nd_namespace_common *ndns);
> > >  #if IS_ENABLED(CONFIG_ND_CLAIM)
> > >  /* max struct page size independent of kernel config */
> > > -#define MAX_STRUCT_PAGE_SIZE 128
> > > +#define MAX_STRUCT_PAGE_SIZE 64
> > >  int nvdimm_setup_pfn(struct nd_pfn *nd_pfn, struct dev_pagemap *pgma=
p);
> > >  #else
> > >  static inline int nvdimm_setup_pfn(struct nd_pfn *nd_pfn,
> > > diff --git a/drivers/nvdimm/pfn_devs.c b/drivers/nvdimm/pfn_devs.c
> > > index 61af072ac98f..978d63559c0e 100644
> > > --- a/drivers/nvdimm/pfn_devs.c
> > > +++ b/drivers/nvdimm/pfn_devs.c
> > > @@ -13,6 +13,11 @@
> > >  #include "pfn.h"
> > >  #include "nd.h"
> > >
> > > +static bool page_struct_override;
> > > +module_param(page_struct_override, bool, 0644);
> > > +MODULE_PARM_DESC(page_struct_override,
> > > +            "Force namespace creation in the presence of mm-debug.")=
;
> >
> > I can't figure out from this description what this is for so perhaps it
> > should be either removed and made dynamic (if you know you want to debu=
g
> > the mm core, why not turn it on then?) or made more obvious what is
> > happening?
>
> I'll kill it and update the KMSAN Documentation that KMSAN has
> interactions with the NVDIMM subsystem that may cause some namespaces to
> fail to enable. That Documentation needs to be a part of this patch
> regardless as that would be the default behavior of this module
> parameter.
>
> Unfortunately, it can not be dynamically enabled because the size of
> 'struct page' is unfortunately recorded in the metadata of the device.
> Recall this is for supporting platform configurations where the capacity
> of the persistent memory exceeds or consumes too much of System RAM.
> Consider 4TB of PMEM consumes 64GB of space just for 'struct page'. So,
> NVDIMM subsystem has a mode to store that page array in a reservation on
> the PMEM device itself.

Sorry, I might be missing something, but why cannot we have

#ifdef CONFIG_KMSAN
#define MAX_STRUCT_PAGE_SIZE 128
#else
#define MAX_STRUCT_PAGE_SIZE 64
#endif

?

KMSAN is a debug-only tool, it already consumes more than two thirds
of the system memory, so you don't want to enable it in any production
environment anyway.

> KMSAN mandates either that all namespaces all the time reserve the extra
> capacity, or that those namespace cannot be mapped while KMSAN is
> enabled.

Struct page depends on a couple of config options that affect its
size, and has already been approaching the 64 byte boundary.
It is unfortunate that the introduction of KMSAN was the last straw,
but it could've been any other debug config that needs to store data
in the struct page.
Keeping the struct within cacheline size sounds reasonable for the
default configuration, but having a build-time assert that prevents us
from building debug configs sounds excessive.

> --
> You received this message because you are subscribed to the Google Groups=
 "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an=
 email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgi=
d/kasan-dev/63bd0be8945a0_5178e29414%40dwillia2-xfh.jf.intel.com.notmuch.



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
kasan-dev/CAG_fn%3DX9jBwAvz9gph-02WcLhv3MQkBpvkZAsZRMwEYyT8zVeQ%40mail.gmai=
l.com.
