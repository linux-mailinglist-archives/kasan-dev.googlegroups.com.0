Return-Path: <kasan-dev+bncBCF5XGNWYQBRBHX3335AKGQE446HVGQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53f.google.com (mail-pg1-x53f.google.com [IPv6:2607:f8b0:4864:20::53f])
	by mail.lfdr.de (Postfix) with ESMTPS id 64FAD2616E1
	for <lists+kasan-dev@lfdr.de>; Tue,  8 Sep 2020 19:21:36 +0200 (CEST)
Received: by mail-pg1-x53f.google.com with SMTP id 8sf89724pgm.0
        for <lists+kasan-dev@lfdr.de>; Tue, 08 Sep 2020 10:21:36 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1599585695; cv=pass;
        d=google.com; s=arc-20160816;
        b=zE/txO2hsc+koZZBbvZaUohzKGpTqMWYKRhixO3iN5Z7kqlO395cVHpq9n+a2iSPYo
         SFQCvHKKKwBqvHkoITkfbOhzyB/ollsr5n4pr/00eJVxmWKw1sAsH+ejh9SJW+CQwzno
         jC9AlyEWRhiCKRhYzmwvvP+vx8uvaAf5RJjdyPc8+ZJjy8m4f55HM6RmVe7IX7yTBZy7
         gTwKpAaaz9qqep1uLXBf7kp7z9LS0tMSz+XVQzS5hg1umUIdFEHos+UXsi/x5Jr6Onaa
         SdEorBL7Xom6+DNjLIp05HQTSwqKsIfjBCyabkUQgMnNZcLoTb0CEMl4dmlneu/nRF91
         CBGw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=wq8rI6PQBpWUdZ8eNKPdtayj02Tf0NcjQEX/xxGKxMY=;
        b=R8nsU+OI20olMA50xQh3jJeBNGJ70gIYe9gcbnkDvb/ZK/OkvGFikkSn60sQuHEWbp
         8FlYphxZT/5t7/u7sOlNUhESp1g3lLdwJxKVO+bdKrq6AO3bhZk/oleCmodKHvwjE6JF
         UiKZzDWStJT5yF3OT6MViT2lJJxSX3ycpVxkWpEdtINH4WBuNExIHG8fKUtu6rfMCwvk
         z9T3aG/gEs8kDQpG5EjCOEKYA5btDYSwNsixzDluKqX5ktz+HyvbHHY8g3Pqh708Skdn
         QkF6qkjo7zF6I0m5s4/hdc6llxMefezppfIPxYaMJyE3nVWqTJAXdKdglg/76fmj1fTE
         f3gA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=ICQDvF+r;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::1042 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=wq8rI6PQBpWUdZ8eNKPdtayj02Tf0NcjQEX/xxGKxMY=;
        b=AT+EAvyGu1mVtEGZgE9Weq2PqrFnt+5gdNdirRLtQToZvuYA7OowzoAQZskUtsRzAb
         DFaOQgHWafYTS3ZOkHtblNrkPNVwCpWVVfvQPTDLKl3XINP3VtmQj/9D9MV6ZsPaEnf+
         BHcGz9zUuZHk6diogzimLfvTTK0udPd64EYW7dTtzGbZEMkN0MjfBIGGa5ZHFQ+bkLoJ
         2GAeVZ1O0tO01aXHg+7duJV/0Ifhi9qF6dFcikrFMCEiYZm8e8GU8JePZDCpkzs/R9h6
         aRdUtl2RYCQXlIK13670DanrS4PY95WY/4slsaNdwjLphAP6m6FUEsNG3zLUm+AkxzsH
         e/cg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=wq8rI6PQBpWUdZ8eNKPdtayj02Tf0NcjQEX/xxGKxMY=;
        b=RBbLSPnxyfdS9WeOEzpFFwv+eIrITEGsdn9i/ocBY13cYAtHNl88jPDJPtQITGC/fh
         sky+oz7tDyQRkxTXAw9x8gy5Pl7oGGxbkR+0H66sgw89LVYwbZ3VrcwRNqlw2th/GgzP
         o1SDiubK+lDT+GIKO0nZQR3kz4peIJDdbnUfCGtb5mR5ukFSIw0wt6TYQlD22QvCZzt5
         KHeINd4m/pGcARRY8nHmjffYvidcSLHq8mEsJGLHMTQSxa9CRJaiQsvrkvC3gSrPBr0K
         jX7kOzdjt2IApFcAdLvFJKZLFsaOUGvT03bRsFH0KdV1H1otgHHUnBtanZ/TnPEKYnEy
         91rA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531t4NucGwXnaQIXoka4HTmoiDn9PNJ2UmbMtLjU2iMGDqtzkYkP
	8ji4+3EK8wl+lwBEWRYBNzM=
X-Google-Smtp-Source: ABdhPJzG8tTb6JLHkCURKxacpNyFJqRKHRjGddwei23Gr1QSdXipdkMFm0Um4M8nTbWJxFQ0L98Ssg==
X-Received: by 2002:a65:6282:: with SMTP id f2mr21472586pgv.163.1599585695122;
        Tue, 08 Sep 2020 10:21:35 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:714a:: with SMTP id g10ls24212pjs.2.canary-gmail;
 Tue, 08 Sep 2020 10:21:34 -0700 (PDT)
X-Received: by 2002:a17:902:c411:b029:d0:589f:6e1c with SMTP id k17-20020a170902c411b02900d0589f6e1cmr203022plk.0.1599585694507;
        Tue, 08 Sep 2020 10:21:34 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1599585694; cv=none;
        d=google.com; s=arc-20160816;
        b=pYzHBURbjp7RxuS2EEtp2biR5vMRB0K2Iyh2Rer3Jfq0+S9r4/ToJ8P6//axSa8Ws/
         X53mgfSG0w3edzqVk2g6og2KckWbiKwkhGtH3eMph+NcvT+SB05suPVycu4PRzguCb/m
         yoc6lLsV6I9eoALQIXyynB0o0L2fWs0iaklXCWBdZjpl9YpZfbVtW+DegTTW22Rzusgo
         tgZMsHfoAzeA0Yq7l9yqaKXgWl446t0cQ2AC4H74plWZy7xns4cMPFnpU/leCKNjdWkz
         A4nZnkSTpYfbHY161uSpGQmu7iCWXmbP2i6AiS3Y2IyoSkJdG2qlFDsuGykCniG7S3iC
         0jBQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=6Hzyipkee9UZGhxSyMM2F47dHct0fHx90e1igtsMR4E=;
        b=xcEGArljzXcWMf22alXEOiung6VwiNtlOPwhMVqMJMPk3jq5fhY6VLDNrrbfHuLjZE
         JIWjhZLKHfZZWGI0b/Taqob4TRPoCEy0ne7Lpmh/AdtNmzKTnIcvUs8dkZsGqsm7J4WU
         k/TdcEhYvsh2d+ypFtADy8ryd8h0punSablhXMaUx5R0EhAIc5VuoKTOWNhwSmIu/MiJ
         0Aqg75qWjPBT70H+NIiTyLFTfcVLSjsDP4kxPo+do9baDH+UNm2+WmEWxAU+Nul3WZ6T
         18LlGdq2PyFdVq/N3BfhA0kJ5Rj92yGMlZ2DWDJn0z9oLrdLgoCQo6NKHnFCxxp0/KLt
         VDxw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=ICQDvF+r;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::1042 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Received: from mail-pj1-x1042.google.com (mail-pj1-x1042.google.com. [2607:f8b0:4864:20::1042])
        by gmr-mx.google.com with ESMTPS id l2si6680pfd.0.2020.09.08.10.21.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 08 Sep 2020 10:21:34 -0700 (PDT)
Received-SPF: pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::1042 as permitted sender) client-ip=2607:f8b0:4864:20::1042;
Received: by mail-pj1-x1042.google.com with SMTP id b16so71343pjp.0
        for <kasan-dev@googlegroups.com>; Tue, 08 Sep 2020 10:21:34 -0700 (PDT)
X-Received: by 2002:a17:90b:1216:: with SMTP id gl22mr120500pjb.121.1599585694210;
        Tue, 08 Sep 2020 10:21:34 -0700 (PDT)
Received: from www.outflux.net (smtp.outflux.net. [198.145.64.163])
        by smtp.gmail.com with ESMTPSA id c1sm26685pfi.136.2020.09.08.10.21.33
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 08 Sep 2020 10:21:33 -0700 (PDT)
Date: Tue, 8 Sep 2020 10:21:32 -0700
From: Kees Cook <keescook@chromium.org>
To: Marco Elver <elver@google.com>
Cc: Arvind Sankar <nivedita@alum.mit.edu>,
	the arch/x86 maintainers <x86@kernel.org>,
	kasan-dev <kasan-dev@googlegroups.com>,
	LKML <linux-kernel@vger.kernel.org>,
	Andrey Konovalov <andreyknvl@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Alexander Potapenko <glider@google.com>
Subject: Re: [RFC PATCH 1/2] lib/string: Disable instrumentation
Message-ID: <202009081021.8E5957A1F@keescook>
References: <20200905222323.1408968-1-nivedita@alum.mit.edu>
 <20200905222323.1408968-2-nivedita@alum.mit.edu>
 <CANpmjNMnU03M0UJiLaHPkRipDuOZht0c9S3d40ZupQVNZLR+RA@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANpmjNMnU03M0UJiLaHPkRipDuOZht0c9S3d40ZupQVNZLR+RA@mail.gmail.com>
X-Original-Sender: keescook@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=ICQDvF+r;       spf=pass
 (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::1042
 as permitted sender) smtp.mailfrom=keescook@chromium.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=chromium.org
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

On Tue, Sep 08, 2020 at 11:39:11AM +0200, Marco Elver wrote:
> On Sun, 6 Sep 2020 at 00:23, Arvind Sankar <nivedita@alum.mit.edu> wrote:
> >
> > String functions can be useful in early boot, but using instrumented
> > versions can be problematic: eg on x86, some of the early boot code is
> > executing out of an identity mapping rather than the kernel virtual
> > addresses. Accessing any global variables at this point will lead to a
> > crash.
> >
> > Tracing and KCOV are already disabled, and CONFIG_AMD_MEM_ENCRYPT will
> > additionally disable KASAN and stack protector.
> >
> > Additionally disable GCOV, UBSAN, KCSAN, STACKLEAK_PLUGIN and branch
> > profiling, and make it unconditional to allow safe use of string
> > functions.
> >
> > Signed-off-by: Arvind Sankar <nivedita@alum.mit.edu>
> > ---
> >  lib/Makefile | 11 +++++++----
> >  1 file changed, 7 insertions(+), 4 deletions(-)
> >
> > diff --git a/lib/Makefile b/lib/Makefile
> > index a4a4c6864f51..5e421769bbc6 100644
> > --- a/lib/Makefile
> > +++ b/lib/Makefile
> > @@ -8,7 +8,6 @@ ccflags-remove-$(CONFIG_FUNCTION_TRACER) += $(CC_FLAGS_FTRACE)
> >  # These files are disabled because they produce lots of non-interesting and/or
> >  # flaky coverage that is not a function of syscall inputs. For example,
> >  # rbtree can be global and individual rotations don't correlate with inputs.
> > -KCOV_INSTRUMENT_string.o := n
> >  KCOV_INSTRUMENT_rbtree.o := n
> >  KCOV_INSTRUMENT_list_debug.o := n
> >  KCOV_INSTRUMENT_debugobjects.o := n
> > @@ -20,12 +19,16 @@ KCOV_INSTRUMENT_fault-inject.o := n
> >  # them into calls to themselves.
> >  CFLAGS_string.o := -ffreestanding
> >
> > -# Early boot use of cmdline, don't instrument it
> > -ifdef CONFIG_AMD_MEM_ENCRYPT
> > +# Early boot use of string functions, disable instrumentation
> > +GCOV_PROFILE_string.o := n
> > +KCOV_INSTRUMENT_string.o := n
> >  KASAN_SANITIZE_string.o := n
> > +UBSAN_SANITIZE_string.o := n
> > +KCSAN_SANITIZE_string.o := n
> 
> Ouch.
> 
> We have found manifestations of bugs in lib/string.c functions, e.g.:
>   https://groups.google.com/forum/#!msg/syzkaller-bugs/atbKWcFqE9s/x7AtoVoBAgAJ
>   https://groups.google.com/forum/#!msg/syzkaller-bugs/iGBUm-FDhkM/chl05uEgBAAJ
> 
> Is there any way this can be avoided?

Agreed: I would like to keep this instrumentation; it's a common place
to find bugs, security issues, etc.

-- 
Kees Cook

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/202009081021.8E5957A1F%40keescook.
