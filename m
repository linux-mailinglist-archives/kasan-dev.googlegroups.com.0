Return-Path: <kasan-dev+bncBDN5FEVB5YIRBYGFW3XAKGQEYQXY67I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-xc3d.google.com (mail-yw1-xc3d.google.com [IPv6:2607:f8b0:4864:20::c3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 97DA1FCE2C
	for <lists+kasan-dev@lfdr.de>; Thu, 14 Nov 2019 19:54:25 +0100 (CET)
Received: by mail-yw1-xc3d.google.com with SMTP id t19sf4863619ywf.1
        for <lists+kasan-dev@lfdr.de>; Thu, 14 Nov 2019 10:54:25 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1573757664; cv=pass;
        d=google.com; s=arc-20160816;
        b=ePKFq6mpE7YRFTyO/pZqkcKHYalEVirWa8nW+uj0qCgCQjumX48edIgnsioRX/Ol22
         ZWfCMSvrB8qrSAU/I91tih8Zd1AmBDWlcHKM+tKV0462q+rocQnsF6sxkpGSVQ44ki+r
         tSniffuI0LAo6j6vORsa8dv9PCc40ExHuNxT6/iQRtCwSOWWeDVyVUnHmm7wT8/HuT8d
         r9/EYZjkDY0di4OVU8HRm1Sixi9A8goV30iNlZ6f+f//1+Z0V3Npi+IBIHn7BbsOnF6W
         FYQOFTGYurP9McZVoPxsGqrQMzzJ208jrDryz4By6THMU/NPRUUcrUbrB9sAdULX6MRp
         sBYw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=2AQOjU3jZZKh5lDEgbX6piuMwD5PAGAnKsafl4nHFu4=;
        b=qwIfYc4wrt/WhEFs9Wud1di0n3UuBK9jfHhPdm6odai/P6BL5N0wdI8e5cqzXkSYe0
         v/5PXxmqSjv5unxYASuNHrmT31AvajQe9kiDWIZiYnDQA8oSSlHvQMjtlKAWzklULryH
         /cZipeSHY9uhYxkvt2KOKD5kIiM4xnY8vmQkVkSk4Mr9HXOyDw/l3YpPfYAJn+smw9PI
         2Qkg2wCuCPS9I55xPbplYbvfNhdkPiDGLST0tR1uIHGx2KqOpDoskc0YysVrloOzlxnt
         GqnAGHIjWTdMi0iNuPJV2KXlKY2QILb24kz1pmS4GxWRFnuVDQYK9+YUf4RZbBNfcauy
         Nq1A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of sean.j.christopherson@intel.com designates 134.134.136.126 as permitted sender) smtp.mailfrom=sean.j.christopherson@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=2AQOjU3jZZKh5lDEgbX6piuMwD5PAGAnKsafl4nHFu4=;
        b=lnLkzST2fA0GHnG+EnEynKiRa6lCAiJzZbhIsT/a112u4LosEl3HNOXljq4C02Qi48
         u2ELi3XtJQ0ErgMSI8Hn0u1LwLJvgca99TzBeninDWVSoPwgwlavCReV7d25DjVsA0yJ
         ekQ1tHuRrYWcFlc5YST/s+FfPfXYf/X/uUnpufv6hZW0OqhGOj8IPv862FtAmdxeAFql
         eUIZ3UetRSAz6hA2VaoK5CLCj6XI4GfuQEd1MhBT7eqxcDZjZJljboPwX64zT1WdMz2V
         4+EnZ8vXAXh18fcVVv0Y5yngu0IN9MxYHyJqK0UCXppNXKDdlvJNb1I9JqLj+XV5FpnU
         Al6Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=2AQOjU3jZZKh5lDEgbX6piuMwD5PAGAnKsafl4nHFu4=;
        b=BNm2dU4OAB33e0zeIFdHjCjzZZyGjERJdxJM8MmBPZZWSyv3UXSm1xfpz+K/yomKIu
         U7a9tetIezdaeYV9IIFFDbb+jSSKA4v2Ke0CZwVk11RWcXmdECnG3nywWiE2rmavCW89
         tJbLIjI35ztyzOhDUbwTcHTST4HZV0IAh/l/rsoj6XDR0V+wTfmhKONojC6TXAGR2NDS
         ycPvFK5qCTTppj2yu6+3kGMl930S8nCF6oXyP5kpUyHqlrchxpPD3+qbnegom6phPS/7
         xVz08D7BPUSDQjdB1ZogN4b/ugwGePqPLLdzI5WFVwJiufqq5qB1xVPQufsAjPgyz7na
         lD2Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAUQM1a/m9i5NuWRnu+zmws5u5yajKpT9UBs5pD+PSDercMk3TtA
	3DQnoVPdKnSt0NI8ZE4OHJA=
X-Google-Smtp-Source: APXvYqyfgi8mD5n2B9h97wAMIssOoGXYM0ySAoSF02LUdcYybloUzR2NMY2r0x9kyZxCJljLGl3yMA==
X-Received: by 2002:a25:ca17:: with SMTP id a23mr8559979ybg.385.1573757664559;
        Thu, 14 Nov 2019 10:54:24 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:abb2:: with SMTP id v47ls591092ybi.0.gmail; Thu, 14 Nov
 2019 10:54:23 -0800 (PST)
X-Received: by 2002:a25:cc91:: with SMTP id l139mr8842719ybf.271.1573757663068;
        Thu, 14 Nov 2019 10:54:23 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1573757663; cv=none;
        d=google.com; s=arc-20160816;
        b=fuzwEIcHDua3iVElAdckJWjvKsYCSeovs/gWHx2rmXiL/mP0XOs6Tk011PcSwDJsli
         uSfkbGW+GJeVhk4fwz0509fK+7Sz92QUqOO4PI33pdK8juJjuHqplMWehWxR8YScDrW9
         77MBw/qcOq6R5BZTQcVbRexmhD6yfzRM45K0Mcf0rKv7Nnxzz9i2QaVMMs7Ut8Qd+SyS
         HyXp9T3wMDf8zQtslTSbHo97ldQfMr45yo7XbIL8JmpKKOmuHD29vjTohYBWnGSkZdf+
         q7blTP7HQdz+li12ycvD2AzZ96LaA4UY2EtToQMIqUVFu89WpP7J2lMkr7CAwuIt6DMM
         kUzQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=eYO66rByNyZQCoFnwXduHhLEo3im1GgOalqtyBXrTgQ=;
        b=pkPKPU7s4e7y9mZPKvaXv+frl5Elo9c07G/eJruzTI2ITKpfcpJnOEx5IJKTZqYfMG
         lJR9AghSq5fqj1Vb1cyOlIo8EsrKmWMYOLZlPmNrOm0YwCE8DQcKWINtBrcA1dFejXJC
         IzRTbNwXpxQPNmyF0cI7+AWCSQNIH6ZvmSgSXlbL3rnA6CfIRb5ctwTT7lx3wxdd46d1
         DwdPlUjm+FOFkNQ3xaiikDykoLLF2kLnY5L+Ae/KErEoyQ3cEXBgZ2S94IW7ibq+T2jh
         LP+8aIsrfTB18dwNlkAm28icB2KkRTKSrkRSneyj55VdDxrkOFbeJmeJ72IDmbNGe2u3
         Lw5g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of sean.j.christopherson@intel.com designates 134.134.136.126 as permitted sender) smtp.mailfrom=sean.j.christopherson@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mga18.intel.com (mga18.intel.com. [134.134.136.126])
        by gmr-mx.google.com with ESMTPS id g82si177410ywc.0.2019.11.14.10.54.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 14 Nov 2019 10:54:23 -0800 (PST)
Received-SPF: pass (google.com: domain of sean.j.christopherson@intel.com designates 134.134.136.126 as permitted sender) client-ip=134.134.136.126;
X-Amp-Result: UNKNOWN
X-Amp-Original-Verdict: FILE UNKNOWN
X-Amp-File-Uploaded: False
Received: from fmsmga008.fm.intel.com ([10.253.24.58])
  by orsmga106.jf.intel.com with ESMTP/TLS/DHE-RSA-AES256-GCM-SHA384; 14 Nov 2019 10:54:21 -0800
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="5.68,304,1569308400"; 
   d="scan'208";a="203149189"
Received: from sjchrist-coffee.jf.intel.com (HELO linux.intel.com) ([10.54.74.41])
  by fmsmga008.fm.intel.com with ESMTP; 14 Nov 2019 10:54:20 -0800
Date: Thu, 14 Nov 2019 10:54:20 -0800
From: Sean Christopherson <sean.j.christopherson@intel.com>
To: Andy Lutomirski <luto@kernel.org>
Cc: Jann Horn <jannh@google.com>, Thomas Gleixner <tglx@linutronix.de>,
	Ingo Molnar <mingo@redhat.com>, Borislav Petkov <bp@alien8.de>,
	"H. Peter Anvin" <hpa@zytor.com>, X86 ML <x86@kernel.org>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	kasan-dev <kasan-dev@googlegroups.com>,
	LKML <linux-kernel@vger.kernel.org>
Subject: Re: [PATCH 2/3] x86/traps: Print non-canonical address on #GP
Message-ID: <20191114185420.GJ24045@linux.intel.com>
References: <20191112211002.128278-1-jannh@google.com>
 <20191112211002.128278-2-jannh@google.com>
 <20191114174630.GF24045@linux.intel.com>
 <CALCETrVmaN4BgvUdsuTJ8vdkaN1JrAfBzs+W7aS2cxxDYkqn_Q@mail.gmail.com>
 <20191114182043.GG24045@linux.intel.com>
 <CALCETrVOPT5Np9=4ypEipu5YtXyTRZhiYBQ1XZoDd2=_Q4s=yw@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CALCETrVOPT5Np9=4ypEipu5YtXyTRZhiYBQ1XZoDd2=_Q4s=yw@mail.gmail.com>
User-Agent: Mutt/1.5.24 (2015-08-30)
X-Original-Sender: sean.j.christopherson@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of sean.j.christopherson@intel.com designates
 134.134.136.126 as permitted sender) smtp.mailfrom=sean.j.christopherson@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
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

On Thu, Nov 14, 2019 at 10:41:06AM -0800, Andy Lutomirski wrote:
> On Thu, Nov 14, 2019 at 10:20 AM Sean Christopherson
> <sean.j.christopherson@intel.com> wrote:
> >
> > On Thu, Nov 14, 2019 at 10:00:35AM -0800, Andy Lutomirski wrote:
> > > On Thu, Nov 14, 2019 at 9:46 AM Sean Christopherson
> > > <sean.j.christopherson@intel.com> wrote:
> > > > > +     /*
> > > > > +      * For the user half, check against TASK_SIZE_MAX; this way, if the
> > > > > +      * access crosses the canonical address boundary, we don't miss it.
> > > > > +      */
> > > > > +     if (addr_ref <= TASK_SIZE_MAX)
> > > >
> > > > Any objection to open coding the upper bound instead of using
> > > > TASK_SIZE_MASK to make the threshold more obvious?
> > > >
> > > > > +             return;
> > > > > +
> > > > > +     pr_alert("dereferencing non-canonical address 0x%016lx\n", addr_ref);
> > > >
> > > > Printing the raw address will confuse users in the case where the access
> > > > straddles the lower canonical boundary.  Maybe combine this with open
> > > > coding the straddle case?  With a rough heuristic to hedge a bit for
> > > > instructions whose operand size isn't accurately reflected in opnd_bytes.
> > > >
> > > >         if (addr_ref > __VIRTUAL_MASK)
> > > >                 pr_alert("dereferencing non-canonical address 0x%016lx\n", addr_ref);
> > > >         else if ((addr_ref + insn->opnd_bytes - 1) > __VIRTUAL_MASK)
> > > >                 pr_alert("straddling non-canonical boundary 0x%016lx - 0x%016lx\n",
> > > >                          addr_ref, addr_ref + insn->opnd_bytes - 1);
> > > >         else if ((addr_ref + PAGE_SIZE - 1) > __VIRTUAL_MASK)
> > > >                 pr_alert("potentially straddling non-canonical boundary 0x%016lx - 0x%016lx\n",
> > > >                          addr_ref, addr_ref + PAGE_SIZE - 1);
> > >
> > > This is unnecessarily complicated, and I suspect that Jann had the
> > > right idea but just didn't quite explain it enough.  The secret here
> > > is that TASK_SIZE_MAX is a full page below the canonical boundary
> > > (thanks, Intel, for screwing up SYSRET), so, if we get #GP for an
> > > address above TASK_SIZE_MAX,
> >
> > Ya, I followed all that.  My point is that if "addr_ref + insn->opnd_bytes"
> > straddles the boundary then it's extremely likely the #GP is due to a
> > non-canonical access, i.e. the pr_alert() doesn't have to hedge (as much).
> 
> I suppose.  But I don't think we have a real epidemic of failed
> accesses to user memory between TASK_SIZE_MAX and the actual boundary
> that get #GP instead of #PF but fail for a reason other than
> non-canonicality :)

No argument there.

> I think we should just go back in time and fix x86_64 to either give
> #PF or at least give some useful page fault for a non-canonical
> address. The only difficulties I'm aware of is that Intel CPUs would
> either need to be redesigned better or would have slightly odd
> semantics for jumps to non-canonical addresses -- #PF in Intel's model
> of "RIP literally *can't* have a non-canonical value" would be a bit
> strange.  Also, my time machine is out of commission.

If you happen to fix your time machine, just go back a bit further and
change protected mode to push the faulting address onto the stack.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191114185420.GJ24045%40linux.intel.com.
