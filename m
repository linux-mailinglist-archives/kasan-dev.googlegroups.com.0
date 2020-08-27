Return-Path: <kasan-dev+bncBDDL3KWR4EBRBMETT75AKGQEUMBTOMQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53b.google.com (mail-pg1-x53b.google.com [IPv6:2607:f8b0:4864:20::53b])
	by mail.lfdr.de (Postfix) with ESMTPS id B137B2547F0
	for <lists+kasan-dev@lfdr.de>; Thu, 27 Aug 2020 16:56:49 +0200 (CEST)
Received: by mail-pg1-x53b.google.com with SMTP id c3sf4464822pgq.9
        for <lists+kasan-dev@lfdr.de>; Thu, 27 Aug 2020 07:56:49 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1598540208; cv=pass;
        d=google.com; s=arc-20160816;
        b=j3Pu04bLSXT0lunN/RuzQcwZLHpMN8EA463OjvAzTIdLDf2RWzhzx7gnVUH9fYxjTK
         V9OTYM0XYJ9afcBNTNtIDmdHW9B09USVw+asKGR93CYQpRfS7LSMZEvKsW44DQ17Xw/b
         EDjJFLN1DVwJ8vrbb50ChY0Y8i9moyWlbXR4odhkflnZM3PQku89awWiVU354zuRXQSD
         u/LQLhleQLON/N6UC9QaPx8k11Ap/3aG6EoEt4lEb4NvHaDqQmTgU6ovXGjO0SMuDknK
         GbeDrR2FclJM0nycDDi2ya+WUJF3O0R/uc0t2dDnudtuFThJAt440/LQj/Ro7tRpkvB8
         HQag==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=y+nyk56bIaT1a/ezvVjQgwRIPlF842czZIhi2pUHrRI=;
        b=tA7yanXhBxw+jgGq3P/XG/lHjj0CsoK/4Hh+c9vxbcxGMSN6KIDLfEyd+UubaXsa5j
         bQ46wG2TDgaeFRtLD9ZoT642V2tDqKHAFJrENlAgoKkCoX2nKl55b/hcr1tvurA0jKZ6
         4yIOKe73p6eXb3dO4NbwX7fuzcAeUM8A7UtHrblfEDkiL8BvrQzelJOB2pzkIZwsiy9c
         W7Mtkdw+6+C5081v3bEdTDZACLof7/f1QijafxxDPW3DtbPJ0hRZRVwJ9dKH3kN7y6CY
         nV9UJc9TdOmbHCgoqzbCdTheFME1IQzNYHZK2orNaffHonr4vhiI/WgasUVk7Q84XkT7
         NTmQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=y+nyk56bIaT1a/ezvVjQgwRIPlF842czZIhi2pUHrRI=;
        b=LoJJdmOu51iN0bP91Tqa4fYC+bdoLI7a1QQ5YySHCabvoVVTSNfVoFz5AXizCWOTPk
         awKkUmJYM6adtb0PKs0A+LJcqI96w35hUhXPDc0+O6bAzjpok5BR+vHiMmia1Hj7a7QF
         8AU8Fkzeup+RmdGGzmT05OpwVrTZVl+gcblMTA6l7e+A/5U52SQW19GGrvRfaK5zDmzL
         e8lD2LWYd1P8v21qHVxrzwTEhr2zVMYHonoCikgcLmIM9dqN2l18eCkAVEyk2vGfIfXW
         NGb+Te1QhGE3mQTchWmf7ziOzlJJ46GCXBzJ6tnqblDaMeO5dIueq7hWCF4S8QZMpNoP
         4bnA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=y+nyk56bIaT1a/ezvVjQgwRIPlF842czZIhi2pUHrRI=;
        b=CRbH+rrUS7MgHM/NbWal6Ydsed1I2iF1PeTle8rX1t+7yXnlWMvphRbEYFGoh2dVOC
         aBu3RXmBx6I/d4SUCl825ZLkU38DdhCGAzBmbeHZHszLKa9ywDH9u1oNaujanGnoLLtd
         CreJymaxVAhG7rDpBlAlpTcK6AStwUxrVbkUG6rae8DQhqogb2dDObdwxeTbT1XzrXDW
         aHgspRWwHxaK6nAk5+znE9cBux9Lsl46VHch8Caa+jqzDvKOyYdOJ/ocCGm44gaZGEI3
         mjiUzw8uwtPfNXOjatoor8KWsaaws3rdgUQEICN+qoQUzB/wDWIP6nKNWosL/Pr1ec5n
         fk2w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5326+CMgYXvYGxIHmKeAZJrKGCB09Ua/paSflGtCHfcb5JMl6qQy
	ybDTXizQ1aJmEAlqScfdw6E=
X-Google-Smtp-Source: ABdhPJysm829yaDGfkA853yLPC4PRaxkl26i9812R/TBWPu8HjBIFYXWuaA+VaynwJ7YcpGihqGidQ==
X-Received: by 2002:a17:90a:7acb:: with SMTP id b11mr11429126pjl.171.1598540208294;
        Thu, 27 Aug 2020 07:56:48 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:bb8f:: with SMTP id m15ls1355231pls.5.gmail; Thu, 27
 Aug 2020 07:56:47 -0700 (PDT)
X-Received: by 2002:a17:90a:9c3:: with SMTP id 61mr11593445pjo.191.1598540207822;
        Thu, 27 Aug 2020 07:56:47 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1598540207; cv=none;
        d=google.com; s=arc-20160816;
        b=pSGtYdSYp7m5hmyo5D8pEiZe2qtlPgd04RBrIkZQplYCfdeZwMrpWjOZ6wqrFKsdlJ
         a0Jwpera49YcbMGDdEa33znp1py1PARkQPoLoFZrSimoDI6WqfV5WriFlt17xlnYRXCD
         1NR+owlLaDDbF9LGTWyFOBQ3B9tzGk2yq1lkWhj8H+BDmFbxR45Z22WSC+i0QYWZnTAe
         bUFFGKkIn3McDMctyPY0aobRWVMh7Xrx5KcQNJu/pJtPoh2gnHiKhuHZt5ndfSUlx8On
         ux7JcmsCZFfjYHEYf1wbUy3w8e4Gv0WAdHsKuHe7eFaFxq98kR5noBrdu4qyloSpRgeE
         T/UQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=+HYYYiBlApBpQA0AFmOQzcd+eJgql1GwaYohjBgYunY=;
        b=FBzWoUcFzVkfvu5y5RrVD13XvJpVA4GjC/lldNxAsDNbSIiYrH9DM+tw0M1QlZc5a1
         oQcWTJlPz3ce9tQUi2A3JK7GryKbzuRGxlLUzA/NFb3rtcnsXlOgzZq4Ahp/OsYtf8Is
         uR5cJEXDwvH8EJA1fSa6ORZSBhOPhqRBtQraCpM2Y3SpY5Q42fEooHFfR6rjgW+lGr9X
         vCPx2sRJeGmsQ0vpVGE6RpGNfR9nmI2yHVOirHMYfrExuyVFXvJiA0gEKz9kbSg37VvU
         rmIo3LzdWqzTBYqNdc44SwSuqA6u4hNmo9wym1Xe1WR9lg2SpNm5p4xBJSpEvB9rMC+A
         wg+Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id s14si145667pgj.1.2020.08.27.07.56.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 27 Aug 2020 07:56:47 -0700 (PDT)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from gaia (unknown [46.69.195.127])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 178032054F;
	Thu, 27 Aug 2020 14:56:44 +0000 (UTC)
Date: Thu, 27 Aug 2020 15:56:42 +0100
From: Catalin Marinas <catalin.marinas@arm.com>
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	kasan-dev <kasan-dev@googlegroups.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Elena Petrova <lenaptr@google.com>,
	Branislav Rankov <Branislav.Rankov@arm.com>,
	Kevin Brodsky <kevin.brodsky@arm.com>,
	Will Deacon <will.deacon@arm.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Linux ARM <linux-arm-kernel@lists.infradead.org>,
	Linux Memory Management List <linux-mm@kvack.org>,
	LKML <linux-kernel@vger.kernel.org>
Subject: Re: [PATCH 21/35] arm64: mte: Add in-kernel tag fault handler
Message-ID: <20200827145642.GO29264@gaia>
References: <cover.1597425745.git.andreyknvl@google.com>
 <f173aacd755e4644485c551198549ac52d1eb650.1597425745.git.andreyknvl@google.com>
 <20200827095429.GC29264@gaia>
 <CAAeHK+xHQDMsTehppknjNTEMFh18ufWB1XLUGdVFoc-QZ-mVrw@mail.gmail.com>
 <20200827131045.GM29264@gaia>
 <CAAeHK+xraz7E41b4LW6VW9xOH51UoZ+odNEDrDGtaJ71n=bQ3A@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CAAeHK+xraz7E41b4LW6VW9xOH51UoZ+odNEDrDGtaJ71n=bQ3A@mail.gmail.com>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: catalin.marinas@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as
 permitted sender) smtp.mailfrom=cmarinas@kernel.org
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

On Thu, Aug 27, 2020 at 03:34:42PM +0200, Andrey Konovalov wrote:
> On Thu, Aug 27, 2020 at 3:10 PM Catalin Marinas <catalin.marinas@arm.com> wrote:
> > On Thu, Aug 27, 2020 at 02:31:23PM +0200, Andrey Konovalov wrote:
> > > On Thu, Aug 27, 2020 at 11:54 AM Catalin Marinas
> > > <catalin.marinas@arm.com> wrote:
> > > > On Fri, Aug 14, 2020 at 07:27:03PM +0200, Andrey Konovalov wrote:
> > > > > +static int do_tag_recovery(unsigned long addr, unsigned int esr,
> > > > > +                        struct pt_regs *regs)
> > > > > +{
> > > > > +     report_tag_fault(addr, esr, regs);
> > > > > +
> > > > > +     /* Skip over the faulting instruction and continue: */
> > > > > +     arm64_skip_faulting_instruction(regs, AARCH64_INSN_SIZE);
> > > >
> > > > Ooooh, do we expect the kernel to still behave correctly after this? I
> > > > thought the recovery means disabling tag checking altogether and
> > > > restarting the instruction rather than skipping over it.
[...]
> > > Can we disable MTE, reexecute the instruction, and then reenable MTE,
> > > or something like that?
> >
> > If you want to preserve the MTE enabled, you could single-step the
> > instruction or execute it out of line, though it's a bit more convoluted
> > (we have a similar mechanism for kprobes/uprobes).
> >
> > Another option would be to attempt to set the matching tag in memory,
> > under the assumption that it is writable (if it's not, maybe it's fine
> > to panic). Not sure how this interacts with the slub allocator since,
> > presumably, the logical tag in the pointer is wrong rather than the
> > allocation one.
> >
> > Yet another option would be to change the tag in the register and
> > re-execute but this may confuse the compiler.
> 
> Which one of these would be simpler to implement?

Either 2 or 3 would be simpler (re-tag the memory location or the
pointer) with the caveats I mentioned. Also, does the slab allocator
need to touch the memory on free with a tagged pointer? Otherwise slab
may hit an MTE fault itself.

> Perhaps we could somehow only skip faulting instructions that happen
> in the KASAN test module?.. Decoding stack trace would be an option,
> but that's a bit weird.

If you want to restrict this to the KASAN tests, just add some
MTE-specific accessors with a fixup entry similar to get_user/put_user.
__do_kernel_fault() (if actually called) will invoke the fixup code
which skips the access and returns an error. This way KASAN tests can
actually verify that tag checking works, I'd find this a lot more
useful.

-- 
Catalin

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200827145642.GO29264%40gaia.
