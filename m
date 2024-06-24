Return-Path: <kasan-dev+bncBCCMH5WKTMGRBMFU4WZQMGQE6W3LYIY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x838.google.com (mail-qt1-x838.google.com [IPv6:2607:f8b0:4864:20::838])
	by mail.lfdr.de (Postfix) with ESMTPS id 20D729148E6
	for <lists+kasan-dev@lfdr.de>; Mon, 24 Jun 2024 13:36:18 +0200 (CEST)
Received: by mail-qt1-x838.google.com with SMTP id d75a77b69052e-44212083709sf98380661cf.0
        for <lists+kasan-dev@lfdr.de>; Mon, 24 Jun 2024 04:36:18 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1719228977; cv=pass;
        d=google.com; s=arc-20160816;
        b=s2B+BucBDuf+zFwnIvRaz0W/0W0LaDPQpXlkBOoPc/FAmxJzZs3wCaDVKy9QZHI3a7
         wWYJxUkQVR9UZ49WjQTBocXAJywT58lXbiBCewRItLWjF7+3DXsZ2SzAg7sJqE4I9+kh
         ou7iftoBal+XjxnTQZYK9AYhCog/0TalYpgEnPMSbO8hJ9uctV7OAeh1MrSniBXZ4qFe
         NFwnG+BVcJym8K44G/cuVdOE/+EfuRqFaNfOb6Qq7gQheatMazR3wkywrHQ+UUaB0Fph
         uRU6OaxHzSf8DBmQhEBIb16oeD/pqtoOikMfCDUSkqykQgX45ZHqVvHxb8ZxpgP9NaKM
         lvoQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=VKBny7vOpC3dtjtaIFG/nsnInwWNJBDgeDlRMyegBMI=;
        fh=H1GIaPvio6k8NBCO/SszAKA0uJsiPaxFQOKh0wpHX78=;
        b=SkrAagcFwHPJAYRzUdVdvFqf1tNYabhDlcNc13Lx6wzwcupibR2CnJzuYmxggp3lLX
         7D3nGslT3sbTkvEE/xI5oThlylHzVdWodfi9elDJkv361mhleilJLReqcKYOs34Selvb
         Eaq/7THYq2M2XcpS4KpoqsvrfU4buDT3NxndxvhNKWpwORTUBejy16l5y6yLQeNYTUch
         MYSh5/sI+yg637lAEmill19m4krnG5cj5GL9Y/+Jz4JyyUCcr2eIAI7Y9vs68n0RgoS0
         DLfPHMe/HfC+1FSo++VYYf6Zq1eBT4kQYp19wbrJ9Pu5bwOHlAg4tgGnlYQIWnUZKstJ
         dFcw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=RVFMn1Ix;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f36 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1719228977; x=1719833777; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=VKBny7vOpC3dtjtaIFG/nsnInwWNJBDgeDlRMyegBMI=;
        b=YQgbF27R+6fscIq0K+hkfivVkdPbnPCWKaCvfSrk83rduGVFEdOJT/kKgHlZ7PwR1Y
         idPMC1ZQce1CP/mLUqqHdiWG6JWHd2TltA4YTKvj1S9Lb3ON+ZpsCu6XwZthYytNV/yw
         IHcr0gqxhNqGBAblo3AxA1TfyvSTnr1TOqlR2P8U5t6kHsO4U/f4YOOk1TScmy2txFqV
         IYDU66YpjHVsq12Eie3nwPQ3YN08r8GfuWFEutrtzJuUDhX4H8xZCSUGvMxWkOOzTTL5
         uBoE0QdLjxJhIHULmL3Yj2xTNTANglzQa9rg+R9JZY5apJU9S4VgZpSfizZvmTNKmDqs
         tvog==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1719228977; x=1719833777;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=VKBny7vOpC3dtjtaIFG/nsnInwWNJBDgeDlRMyegBMI=;
        b=lbwxWNmaN/0nG5/xHnZKaMVozfZumw5lMOzThdJAe1FJCYJvSZAFUIH5ozgXMso5db
         PYytMpypIGVoZRMGhYb6Sjx0F+M8VJnSMid+C33eCIaqOhJFYJKrOTlYQJ5jPue22LxN
         uyUATfRsZcIwYlCPQE2E4J3r/K1K1u4hkm9fviP/4l8tOraVZ97ZfV8WJEWJDVtG43hF
         zqhM6O8fJlgTlPb5rcDJrxTch7D4URveAA5MxB/jgy7Jc00eNgSpcexaqUc4OmXrzLXG
         Rjfqp+z/79X6//lGnFkAL/TsJlahO2HQKCDneHg2E+BWozEGwB/KssM5Hy/da+kfDvNK
         4dyg==
X-Forwarded-Encrypted: i=2; AJvYcCULR8tq6yqKC1kp9LV02Aa/iAu+W3neVh3vS5V1lD7HV2QxBnmlDMqtVmCYQ8dzaoTWWA0/+QDULuAqtGdtI3hyGCAnzpcXrg==
X-Gm-Message-State: AOJu0YzAcC5mo8IC4NQHhpFsJ9pRxQla0ZjuyQIoiMUBZOJxSjMSfpdL
	GScZ/yVz37tTn+b1uxOLfTPHt1Wd/eJT+679h8ltIrsTaSV2hsLG
X-Google-Smtp-Source: AGHT+IGNttRQ/O6JW9nX+BVtR+mCWliWg4mktJQW73g0asd6he7KTyjIQKDUqM3dpf3aPKw27oHD0A==
X-Received: by 2002:ac8:5d11:0:b0:444:dd12:3e88 with SMTP id d75a77b69052e-444dd123f10mr38525281cf.26.1719228976650;
        Mon, 24 Jun 2024 04:36:16 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:5755:0:b0:440:5b30:b50c with SMTP id d75a77b69052e-444b49f1106ls96885921cf.0.-pod-prod-00-us;
 Mon, 24 Jun 2024 04:36:16 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUzEA4hJDIuiX/IM+iWOrNmwy8M7UVAoTHxVNv3gHNxKW3kABbidQ0GUrPjUJHYr257YSExmOM3hdano01TBN+cqnFXl1AJ32n5bQ==
X-Received: by 2002:a05:622a:1aa5:b0:444:d2df:e9d1 with SMTP id d75a77b69052e-444eecd698dmr3178651cf.17.1719228976028;
        Mon, 24 Jun 2024 04:36:16 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1719228976; cv=none;
        d=google.com; s=arc-20160816;
        b=d08cjU1/rXMCnwrt4nILHo1KuNlnD14QLL9W2zszLOUJCUQTquXvkb9TO51nYjHlQz
         F3MCO5F4MzvZm8WGnmECoMLiJKkm+gDfDQHtAxLutqxbU44eUoffuFvGYgw/NWYGjYEX
         /unYkJ7zdoYbhg6v5reQHtK6AsbyY6V6nrzI8BRER8H1Rn4SLJgBlKE3kQZ+XDq/RJ7k
         9nviJKlV+M7oc+Gl4RBx1PFjRzidxSWco08TkWN5sOKxG4jZnRU6YXrCp8UtVU86g3Kf
         JI/AjB1Nyx/5uCt4PIf+HS+BVhiIeKwXk9SVzM0YN/cjT+kv6RnREcCuC8SP3JAx0VUy
         HZCQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=5U7QN6cvQJU4zGPixeejlfpYJfaBPInKPn5SWZpCuUY=;
        fh=SBg0VfHqM6Ui5EXFivRQsJfCvJ/TA2mHl6tYt3Vojmg=;
        b=lMMIvLkHjH3jV+xsbYB6IKvKON43npe4abliAr4+JuL5wLT8R935+zDXiT3VYS6zyg
         ABbCrXhT8mBcpzthyzHHtfqSgVDbtI+wMMWMvHEv9K5KMrGvI/aVdIuy/ndSWYYpEj50
         xGzrvjeuYsJj76UqKS36TFoNLnKuzzu78BuYRWyIlIoQh/bLinEwAa8y6Oo1hjIdCall
         roXt/grvj6tPhfvPIC5uBU+wojyK3/niSlUYPAdCrY39j2vzBivYY1yCx37d1nxcwx1h
         DAtpReFSJsHbsvwaLc3RZzYIyTyapyxyv1Vp2NyUVXfaqXkRgVZ5H9ciLnRCEGUDftP0
         PEbQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=RVFMn1Ix;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f36 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf36.google.com (mail-qv1-xf36.google.com. [2607:f8b0:4864:20::f36])
        by gmr-mx.google.com with ESMTPS id d75a77b69052e-444d77e860fsi1835111cf.4.2024.06.24.04.36.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 24 Jun 2024 04:36:16 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f36 as permitted sender) client-ip=2607:f8b0:4864:20::f36;
Received: by mail-qv1-xf36.google.com with SMTP id 6a1803df08f44-6b4ffc2a7abso33658326d6.1
        for <kasan-dev@googlegroups.com>; Mon, 24 Jun 2024 04:36:15 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUCb6nd5yKU4PUeP3fFtDf3Z27/zKoY16Crmjjpl5JdWZA1/N+71WOxgyI/LxNOZnHekehHVcIXieaAw5rCZJwHKqx4wSZEEsQ9OA==
X-Received: by 2002:ad4:5dc2:0:b0:6af:c2ec:3313 with SMTP id
 6a1803df08f44-6b53223de5emr66145116d6.26.1719228975467; Mon, 24 Jun 2024
 04:36:15 -0700 (PDT)
MIME-Version: 1.0
References: <dgsgqssodokkzy6e7xreydep27ct2uldnc6eypmz3rwly6u6yq@3udi3sbubg7a>
 <CAG_fn=WvsGFFdJKr0hf_pqe4k5d5H_J+E4ZyrYCkAWKkDasEkQ@mail.gmail.com>
 <wlcfa6mheu2235sulno74tfjfxdcoy7syjqucqt44rfqcmtdzu@helxlktdfjcy> <6272eb74-ac87-4faa-844b-8a76faf14f6f@intel.com>
In-Reply-To: <6272eb74-ac87-4faa-844b-8a76faf14f6f@intel.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 24 Jun 2024 13:35:34 +0200
Message-ID: <CAG_fn=WN1T-jo3qL3aCbCGXZ2fh7aGSkfE4WhBEqznY-G1savw@mail.gmail.com>
Subject: Re: KMSAN stability
To: Dave Hansen <dave.hansen@intel.com>
Cc: "Kirill A. Shutemov" <kirill.shutemov@linux.intel.com>, Marco Elver <elver@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com, x86@kernel.org, 
	Dave Hansen <dave.hansen@linux.intel.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=RVFMn1Ix;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f36 as
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

On Fri, Jun 21, 2024 at 6:04=E2=80=AFPM Dave Hansen <dave.hansen@intel.com>=
 wrote:
>
> On 6/21/24 08:18, Kirill A. Shutemov wrote:
> > On Thu, Jun 20, 2024 at 04:12:28PM +0200, Alexander Potapenko wrote:
> >> Hi Kirill,
> >>
> >> KMSAN has limited support for non-default configs due to a lack of
> >> extensive testing beyond the syzbot config.
> > Thanks for the patchset that addressing reported issues.
> >
> > There's one more problematic option I've found: CONFIG_DEBUG_PREEMPT.
>
> It seems like testing using clang as the compiler is a bit lacking.  I'm
> a bit surprised there are so many bugs here.

Well, it's not Clang itself that is lacking testing: Clang builds with
all those debug configs are quite reliable.
The problem here is that KMSAN is doing pretty elaborate stuff on
every instrumented memory access, and when we enable any of the debug
configs on top of that, we often end up calling debug code from the
instrumentation code, and that debug code is instrumented, so there's
infinite recursion.

Because KMSAN is primarily used by syzbot, which already runs these
debug configs with faster tools (KASAN), they are indeed undertested,
and people keep running into incompatibilities like those Kirill
reported.

There are several possible approaches to addressing this, each having
its benefits and drawbacks.

1. Find all code that could be potentially called from
kmsan_virt_addr_valid(), mark it as noinstr, KMSAN_SANITIZE:=3Dn,
__no_sanitize_memory etc.
+ Debug configs still work
- If this code is called from somewhere else, it won't be
instrumented, so we can miss KMSAN errors in it.
- Future debug configs may introduce more instrumented code.

2. Provide simplified versions of primitives needed by KMSAN without
debug checks (e.g. preempt_disable(), pfn_valid(), phys_addr()) that
won't be instrumented.
+ Covers all existing and future debug configs.
- Code duplication is bad, we'll need to keep both implementations in
sync. (We could refactor the existing primitives though, so that there
is a single version for which checks can be disabled).

3. Disable low-level debugging configs under KMSAN.
+ No more issues with known problematic configs.
- Some people may actually want to have these configs enabled.
- New debug configs may still break in the absence of testing.

4. Use reentrancy counters to stop KMSAN functions from recursively
calling each other.
+ Is config-agnostic.
- This is brittle: there are situations in which we want instrumented
code called from KMSAN runtime to correctly initialize the metadata,
not just bail out
(e.g. when allocating heap storage for stack traces saved by KMSAN in
the stackdepot, we'd better not ignore the stores to freelist pointers
to avoid false positives later on).

--
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
kasan-dev/CAG_fn%3DWN1T-jo3qL3aCbCGXZ2fh7aGSkfE4WhBEqznY-G1savw%40mail.gmai=
l.com.
