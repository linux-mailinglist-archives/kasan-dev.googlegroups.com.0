Return-Path: <kasan-dev+bncBDN5FEVB5YIRB7FVW3XAKGQE6ABYTEY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x537.google.com (mail-pg1-x537.google.com [IPv6:2607:f8b0:4864:20::537])
	by mail.lfdr.de (Postfix) with ESMTPS id E245EFCD40
	for <lists+kasan-dev@lfdr.de>; Thu, 14 Nov 2019 19:20:45 +0100 (CET)
Received: by mail-pg1-x537.google.com with SMTP id o3sf5130171pgb.16
        for <lists+kasan-dev@lfdr.de>; Thu, 14 Nov 2019 10:20:45 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1573755644; cv=pass;
        d=google.com; s=arc-20160816;
        b=GT6mnY+KelcD5NCdmMr4wtFUWj9y7U2V9EaxhCTmC+HOoonPS8Z4B4h76rGgRRbyma
         NWaXdfOVIt9v69Bdl1Wi7S9Nf1wPXjgQBeaAaJKNCm+d56gM/0+W3smpVaek0Cr5Dxv6
         PfCCRGHZVkzsF7qjs/rLgyIs+jYove1+lL9YdEYh3QdKmQga3k/BZJy6WQfJlQsU7g03
         PK8BVE9f9yOF2Hj6cLqC767KLUe31KhCWED+wf9GPV5/rm1sRv3csEbEDTxQOoCrboGa
         YhrM0ycsfqd3OIvidHISNiA63fswam5ACnwf09XrbIvTjE3y2oxM9/XopV8dTqucoFYk
         ufcg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=k/jB9f99UGllLTXimrBLvzJlmt/bP4JZ9uB3CzGqmjc=;
        b=EBqYuhKixAewFeqGDVkAAhg9mghYy3uyHKs/Aapnxsp0ZXWEabPXrJuKL/szij166g
         5G72lz5G26iTSy1uKNPmH5abT/04PVXASnTaJIXvwV5BRRHqqf4jN0AQgJ4rO5fgZd2L
         zIHsoBAV8qRNPXi7eRjLdYlFwbDNHXV0/+bFWKwyv4EHsl0WBFUroTFAh09KjA7BsocF
         3SttcBpaSBT0iyzlxDoV8pkP8xSV357h6YXwo4R9EGAxYsMsvAaMXCI/8+VBILay7Zo7
         b1iZwE+j+2Iss4+vwzLkaS7a+XkaroGiU8cSp23VJTETojPivzN4nhMv3EaUoOoBJNLp
         NKXg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of sean.j.christopherson@intel.com designates 192.55.52.136 as permitted sender) smtp.mailfrom=sean.j.christopherson@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=k/jB9f99UGllLTXimrBLvzJlmt/bP4JZ9uB3CzGqmjc=;
        b=ACFLEyPRkynrRsskWIflcM8R7TAupue6IjLGxATJIEwstTObnnt6tbmYoy1+Uewe6t
         gwnAzWmbRzY+wHrdGhkL9DfcgXlp74gek9tdc8ApPgpYfnW24BvZv4LpR63T6SdWni/X
         7mEERbYx1id25k5ho0XO8ei1szBCtG6iqExEg84cAqrA3TDi76grAB4vCN4pQ0n/VUB8
         QlJ/Y7QIkl7XSicBp3enla2LydS1OPx0ChvJTydBq1vv90hbLxy5/4z5LL8GwhwMXRDW
         ByXw550XsbiqRDfSP8sbsbZNq3mIEwo0bo881JEmPr1RL7vYH8AfoW6y0G4FLhWDlGnA
         NRVg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=k/jB9f99UGllLTXimrBLvzJlmt/bP4JZ9uB3CzGqmjc=;
        b=XuW2rps770/KcH0ujtA9Gyej9w7934KZq9jBlfe9nbtHPurEvFA1yWY/2DPp6suDEJ
         6SlBP5j0NMmhEMm7MqebBaBIe0iAsZnblbbpX/C1JMuD1rkR+LdMvw40EbsixWG9stbW
         NBqPiXkDE+ixE0iYEp/vXg6QmtfOypuH8Vxn4cLk3Q1W1NvEJ9BL4AMDIf6xusX+qSr4
         jKsuD57weK85usITsalVEYufQnT3lwnGIbRzEPcEIz2eaUegalumqdvhngareWphro/R
         TSxWmfAku+XimYw5YQaw2rhow43aqIvsF4jhe8mdADwuHhgr3YIjDMDaGmbk2SsMYZ4/
         q0Aw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAVOdJbdfQ5whrY+sQfST0YGq/YpmCIndiqPFFcA1xA3pKJNIQz7
	w/szEMZ1FZyaPb/kQYTMX/s=
X-Google-Smtp-Source: APXvYqxGUBKysifmuFM74fMjClt6Vz014M7w5euamrJRKO/8zjPIZHhNLyAMhpDWEUJxnAHfdbUskg==
X-Received: by 2002:a17:90a:6a0f:: with SMTP id t15mr14217619pjj.48.1573755644638;
        Thu, 14 Nov 2019 10:20:44 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:2144:: with SMTP id a62ls885194pje.5.canary-gmail;
 Thu, 14 Nov 2019 10:20:44 -0800 (PST)
X-Received: by 2002:a17:90a:7bcc:: with SMTP id d12mr14095596pjl.63.1573755644298;
        Thu, 14 Nov 2019 10:20:44 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1573755644; cv=none;
        d=google.com; s=arc-20160816;
        b=b9syEXEvWHEQOYtCstBhtCzAsYbdsv+sc9E39/GhTZ9uQR6HBNgUmatslKmfZG6Xif
         3E4mcAvS9I2Uio/gdnqktuTzv3P1ZVSzCo99y93PCEqZoLrQNwY5kEP/4Uj1LoQCGNDN
         ziYoQ66b5NcBcm4k9202QkqdecKBKIznAurBIz0kL79m5O8xPPBW2RnhlTGfSyKDF2Dq
         SL93VmVsQmzMIwFqDapqQmSC+0oX8xjwTdIC5BFKeGd6Sdu6NVDJ+uFHUjjWPtrjULfb
         NbICp/9IjaOhoZeYd/f6yaD9pS0TDqgUl6EmLhL0gn5xY1ZoXdRYYOes8BnxWUJfV4+c
         9e2g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=dPk/0yHrDS6hT6j/3rBF6ZdSdBhuM42tidnqcAnSwqo=;
        b=gLNysbXIUcgGhVRvKK8TI0EN3V2FWjPssNwgZepvg4D2yr3pt2E7jGtm3OpMSBVK9E
         iJ+qjSWiwTM231S5R1m65HxziC5zyZqp1iDymJdLC+W/yuxuIRq7pMIT5m01fKqC0sdG
         hfOxyyGdGkTQ4pznvdqdFLW+YT3bw2nH5D/Eb+9wejZeIONZ06Nva7M6xGlAm6hVA0gX
         mecNY70SWAgpC6iNki08FEf1LWYKhgtCVWa+Gi/DJZq2Y/kylZwAxFagWzMWz2eTyntr
         KdqEY0dPDVbLaEHDZ8uKIcvsuScAZNjYE16ZyYr6iqliT8zgIgpcovtZoU5sHmb4Jk2f
         cs0A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of sean.j.christopherson@intel.com designates 192.55.52.136 as permitted sender) smtp.mailfrom=sean.j.christopherson@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mga12.intel.com (mga12.intel.com. [192.55.52.136])
        by gmr-mx.google.com with ESMTPS id 102si274846plb.3.2019.11.14.10.20.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 14 Nov 2019 10:20:44 -0800 (PST)
Received-SPF: pass (google.com: domain of sean.j.christopherson@intel.com designates 192.55.52.136 as permitted sender) client-ip=192.55.52.136;
X-Amp-Result: UNKNOWN
X-Amp-Original-Verdict: FILE UNKNOWN
X-Amp-File-Uploaded: False
Received: from orsmga006.jf.intel.com ([10.7.209.51])
  by fmsmga106.fm.intel.com with ESMTP/TLS/DHE-RSA-AES256-GCM-SHA384; 14 Nov 2019 10:20:43 -0800
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="5.68,304,1569308400"; 
   d="scan'208";a="208198401"
Received: from sjchrist-coffee.jf.intel.com (HELO linux.intel.com) ([10.54.74.41])
  by orsmga006.jf.intel.com with ESMTP; 14 Nov 2019 10:20:43 -0800
Date: Thu, 14 Nov 2019 10:20:43 -0800
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
Message-ID: <20191114182043.GG24045@linux.intel.com>
References: <20191112211002.128278-1-jannh@google.com>
 <20191112211002.128278-2-jannh@google.com>
 <20191114174630.GF24045@linux.intel.com>
 <CALCETrVmaN4BgvUdsuTJ8vdkaN1JrAfBzs+W7aS2cxxDYkqn_Q@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CALCETrVmaN4BgvUdsuTJ8vdkaN1JrAfBzs+W7aS2cxxDYkqn_Q@mail.gmail.com>
User-Agent: Mutt/1.5.24 (2015-08-30)
X-Original-Sender: sean.j.christopherson@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of sean.j.christopherson@intel.com designates
 192.55.52.136 as permitted sender) smtp.mailfrom=sean.j.christopherson@intel.com;
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

On Thu, Nov 14, 2019 at 10:00:35AM -0800, Andy Lutomirski wrote:
> On Thu, Nov 14, 2019 at 9:46 AM Sean Christopherson
> <sean.j.christopherson@intel.com> wrote:
> > > +     /*
> > > +      * For the user half, check against TASK_SIZE_MAX; this way, if the
> > > +      * access crosses the canonical address boundary, we don't miss it.
> > > +      */
> > > +     if (addr_ref <= TASK_SIZE_MAX)
> >
> > Any objection to open coding the upper bound instead of using
> > TASK_SIZE_MASK to make the threshold more obvious?
> >
> > > +             return;
> > > +
> > > +     pr_alert("dereferencing non-canonical address 0x%016lx\n", addr_ref);
> >
> > Printing the raw address will confuse users in the case where the access
> > straddles the lower canonical boundary.  Maybe combine this with open
> > coding the straddle case?  With a rough heuristic to hedge a bit for
> > instructions whose operand size isn't accurately reflected in opnd_bytes.
> >
> >         if (addr_ref > __VIRTUAL_MASK)
> >                 pr_alert("dereferencing non-canonical address 0x%016lx\n", addr_ref);
> >         else if ((addr_ref + insn->opnd_bytes - 1) > __VIRTUAL_MASK)
> >                 pr_alert("straddling non-canonical boundary 0x%016lx - 0x%016lx\n",
> >                          addr_ref, addr_ref + insn->opnd_bytes - 1);
> >         else if ((addr_ref + PAGE_SIZE - 1) > __VIRTUAL_MASK)
> >                 pr_alert("potentially straddling non-canonical boundary 0x%016lx - 0x%016lx\n",
> >                          addr_ref, addr_ref + PAGE_SIZE - 1);
> 
> This is unnecessarily complicated, and I suspect that Jann had the
> right idea but just didn't quite explain it enough.  The secret here
> is that TASK_SIZE_MAX is a full page below the canonical boundary
> (thanks, Intel, for screwing up SYSRET), so, if we get #GP for an
> address above TASK_SIZE_MAX,

Ya, I followed all that.  My point is that if "addr_ref + insn->opnd_bytes"
straddles the boundary then it's extremely likely the #GP is due to a
non-canonical access, i.e. the pr_alert() doesn't have to hedge (as much).

> then it's either a #GP for a different
> reason or it's a genuine non-canonical access.

Heh, "canonical || !canonical" would be the options :-D

> 
> So I think that just a comment about this would be enough.
> 
> *However*, the printout should at least hedge a bit and say something
> like "probably dereferencing non-canonical address", since there are
> plenty of ways to get #GP with an operand that is nominally
> non-canonical but where the actual cause of #GP is different.  And I
> think this code should be skipped entirely if error_code != 0.
> 
> --Andy

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191114182043.GG24045%40linux.intel.com.
