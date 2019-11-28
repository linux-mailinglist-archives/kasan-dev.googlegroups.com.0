Return-Path: <kasan-dev+bncBDEPT3NHSUCBB4FT7XXAKGQEF3OCRZI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa40.google.com (mail-vk1-xa40.google.com [IPv6:2607:f8b0:4864:20::a40])
	by mail.lfdr.de (Postfix) with ESMTPS id 37D5910C388
	for <lists+kasan-dev@lfdr.de>; Thu, 28 Nov 2019 06:24:01 +0100 (CET)
Received: by mail-vk1-xa40.google.com with SMTP id n6sf11556632vke.22
        for <lists+kasan-dev@lfdr.de>; Wed, 27 Nov 2019 21:24:01 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1574918640; cv=pass;
        d=google.com; s=arc-20160816;
        b=Py5nfq+vxxAr0AA2kzzyfmWfQ2bypA0GgnMCgx4fHYzhB0JUnjkeidnM2lGuEb2e+j
         kZe/xVhWOTfHs+YTSjhggPqZinRWJwW9/a5JE+mVpCMU9FvENCOBfncXWRcTBNNtnjDA
         IaEy438VdFHWvNXSDwqwq7cfDmGO5406tyPR3hjvfKHyMVzsS4Fk4FNdnPUsgCEb5/9t
         OFWdZcJssmEYpGmIeBJ/VBrXPNkHTvWtsK58lihse3AERkUecAYmAfy4JTF6lXldKUAx
         uiSaIaLzCi/2MKx2qgPUz1MFIkdwIHIP8juOraHtIInlIA8Avqu6UkL/9yeg73CPejw4
         QPTQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=ABK1K5Yo8Ysn+H012oHfZXgg6rNhSg0d/1u10R8WI/U=;
        b=K9dE2vZjVawECnknoTOGmjfefSFxp+HTM9Yw+D26O+3dEI3ZJED5wVioqwtvlFFpfJ
         2UWFpscefhljwpiukMIg4Os2zbt7kPxQIe4Dvh40MIUlWD8f0YcF8aZykDQn284EmK/Y
         p721Mp5cAhz6G0sZ7SVwcRhi5xZwafnTOtuY6iQFubd66hvtqX0yfGtLcEVeZOGtrRm7
         SsypNDLJ65q394wLqERYEhXTgg7CEvxhMIrD3oDN+PeQNmVY7xk9JhqKD0P4983h9iOl
         4DQP9SQxTJk3asN0PcEUp5Vr/FDad9Y5yr+2TrBeIdM2+eDPRd6CDCF91lZglALl7O8z
         wxJQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=XFSzWRJH;
       spf=pass (google.com: domain of luto@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=luto@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ABK1K5Yo8Ysn+H012oHfZXgg6rNhSg0d/1u10R8WI/U=;
        b=Uq0GZ/ZcvvFxcFNOQMeDVzb535PkR2O0AO1V0bvqO2RIhDtV04OOqRiC7phKWjICOA
         /VA5sNzCks7HCqDDBsB+B0Bpra3QAYBRSIrZu67CN0xzzPpICEVM2eSP0tPgGyZzRZJD
         93YDaaxdJlxjhBosOgJD1WPTg04238gA1zTvnvzzVig0ne18+TE1yPRV1GbRD2UW1XUK
         CE1QbVo7Fu/+zYw6DIIaPXDeASxHY3fd6ii/tquwWMiqRn3RaP2+/MxKFe0FDDi7QYeP
         Q7v/FGUURtpZzrTt7NPU1A0Yoesq9f9yhW1/fcFqAFF+NRPJgZwWihTdLlKHYUTLZGAh
         ZFBg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ABK1K5Yo8Ysn+H012oHfZXgg6rNhSg0d/1u10R8WI/U=;
        b=hBMzG/H6elboLZzrL9jdPqDj8De97vQp1vCGNdxyGEMi2GqJmHj9yMkRv0orDnV6My
         PE30FeaUMbxBlWX8DXtj1ParkCHOMh3z7KAAHP/GsEnk5eEOonCkq99LH2gmsBlSLxCT
         UIDI74+MZtmG00eNp2VrS9XuCQnOQdR5fYATenxnVMgMcPzl0e9WqkdDzP386dp00G+K
         LjfJZnIqUJ3k+isREUeXXpjR44nqR671BU0QV9KJTL6m2L6rnwACzW4y8H8pZvG7cmst
         Yzs/9l0wUFjuTTLGdBRF3jEecw70J6wMimDCfGEoECHV3l/NobSR1zijEPq+QwvL7eSO
         QFKA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAVgQYTdxyjFk+CZCm3ew9C+C13yJXHnR/8MXzeiq2a8gFR1iJ/L
	a+9ZgodI/nvtVLl0slJ7WbQ=
X-Google-Smtp-Source: APXvYqypQCQteGBjC6zIbU/gB4/awVQzpidztSYQpm9KNnO1FwhoiOudc4kNVRcKGXqftrH3VGU9kQ==
X-Received: by 2002:a1f:1fce:: with SMTP id f197mr5608407vkf.29.1574918640134;
        Wed, 27 Nov 2019 21:24:00 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1f:4355:: with SMTP id q82ls18574vka.8.gmail; Wed, 27 Nov
 2019 21:23:59 -0800 (PST)
X-Received: by 2002:ac5:cd47:: with SMTP id n7mr5218351vkm.101.1574918639751;
        Wed, 27 Nov 2019 21:23:59 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1574918639; cv=none;
        d=google.com; s=arc-20160816;
        b=A/g3IOCki5wYtlum2hrv/zGoNlltHpJePlQfCJUC56SaEL+xaYmyTmGtT5uk5jMoJX
         cdd0MpGFNm5dJmkcrrS1u09JdBeYU0590DwlcJQ7okifK+B6xWrPOD8t4DleeB7EVL2F
         tyZq3piVTQOco/6kpuf5z930hPzClKYs7qX5FQsHwtO7GA1IEX7LaeIUaWDPjifb1m/R
         DEu2/5DkvmEJvKWsZYNBp9cvfYr+f2b4k+W6SG3sUlk+SxvdVTYAoJEWcfkW4fLmBwk4
         IRG5hlbTZEqw3nFKbBFygFduJ/1bj3NufaSRtME0oEPo+tUD9nEJpH+UyTlFhK2OFFiD
         BJsw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=bzUttRNE151cTmUOJMgHhpzo2iaBlcyRCWRztvBK5kI=;
        b=EbP4bP/GrtONxKZcXnSdIXugsn62f1wMPbA+fUJylyTXsGhCEH7Nq78NsJvJ08FK5K
         iLCPaMf2N/7I8vhlfwpd+2d4HDPs/SsjlI6x4N3bxiSLx/xqJ+mtWURX1qyzTZE9Dw+H
         t5tsh3FO9r2T4S/SAsh3xDzxBtGfU3H4Va+R0efrH1iZXCfuGjuRdy/c4RUjJ7py9rkD
         dpiuWg7Q7vFq19yFjergeOiiIJyPUmn5ttKxRV8S+3VOLTF/SD9pbAwM/sAt4Lm1Ci0J
         511HvbCth0tyfyruYZ+dOD9ur2WGCGzCVwzqNLxvPEC3pBDqitgh2jZWxydrYOE7tgVj
         LZFQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=XFSzWRJH;
       spf=pass (google.com: domain of luto@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=luto@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id h143si629135vkh.1.2019.11.27.21.23.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 27 Nov 2019 21:23:59 -0800 (PST)
Received-SPF: pass (google.com: domain of luto@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from mail-wr1-f43.google.com (mail-wr1-f43.google.com [209.85.221.43])
	(using TLSv1.2 with cipher ECDHE-RSA-AES128-GCM-SHA256 (128/128 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 59F0C21736
	for <kasan-dev@googlegroups.com>; Thu, 28 Nov 2019 05:23:58 +0000 (UTC)
Received: by mail-wr1-f43.google.com with SMTP id a15so29469612wrf.9
        for <kasan-dev@googlegroups.com>; Wed, 27 Nov 2019 21:23:58 -0800 (PST)
X-Received: by 2002:adf:f491:: with SMTP id l17mr4133365wro.149.1574918636807;
 Wed, 27 Nov 2019 21:23:56 -0800 (PST)
MIME-Version: 1.0
References: <20191115191728.87338-1-jannh@google.com> <20191115191728.87338-2-jannh@google.com>
 <CALCETrVQ2NqPnED_E6Y6EsCOEJJcz8GkQhgcKHk7JVAyykq06A@mail.gmail.com> <CAG48ez2z8i1nosA1nGrVdXx1cXXwHBqe7CC5kMB2W=uxbsvkjg@mail.gmail.com>
In-Reply-To: <CAG48ez2z8i1nosA1nGrVdXx1cXXwHBqe7CC5kMB2W=uxbsvkjg@mail.gmail.com>
From: Andy Lutomirski <luto@kernel.org>
Date: Wed, 27 Nov 2019 21:23:44 -0800
X-Gmail-Original-Message-ID: <CALCETrXU-hetnH7CTz-Z2xPDAkawx6GdxGtYo0=Jqq1YnoXrWg@mail.gmail.com>
Message-ID: <CALCETrXU-hetnH7CTz-Z2xPDAkawx6GdxGtYo0=Jqq1YnoXrWg@mail.gmail.com>
Subject: Re: [PATCH v2 2/3] x86/traps: Print non-canonical address on #GP
To: Jann Horn <jannh@google.com>
Cc: Andy Lutomirski <luto@kernel.org>, Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@redhat.com>, 
	Borislav Petkov <bp@alien8.de>, "H. Peter Anvin" <hpa@zytor.com>, X86 ML <x86@kernel.org>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	LKML <linux-kernel@vger.kernel.org>, Andrey Konovalov <andreyknvl@google.com>, 
	Sean Christopherson <sean.j.christopherson@intel.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: luto@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=XFSzWRJH;       spf=pass
 (google.com: domain of luto@kernel.org designates 198.145.29.99 as permitted
 sender) smtp.mailfrom=luto@kernel.org;       dmarc=pass (p=NONE sp=NONE
 dis=NONE) header.from=kernel.org
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

On Wed, Nov 27, 2019 at 12:27 PM Jann Horn <jannh@google.com> wrote:
>
> On Sun, Nov 24, 2019 at 12:08 AM Andy Lutomirski <luto@kernel.org> wrote:
> > On Fri, Nov 15, 2019 at 11:17 AM Jann Horn <jannh@google.com> wrote:
> > > A frequent cause of #GP exceptions are memory accesses to non-canonical
> > > addresses. Unlike #PF, #GP doesn't come with a fault address in CR2, so
> > > the kernel doesn't currently print the fault address for #GP.
> > > Luckily, we already have the necessary infrastructure for decoding X86
> > > instructions and computing the memory address that is being accessed;
> > > hook it up to the #GP handler so that we can figure out whether the #GP
> > > looks like it was caused by a non-canonical address, and if so, print
> > > that address.
> [...]
> > > +static void print_kernel_gp_address(struct pt_regs *regs)
> > > +{
> > > +#ifdef CONFIG_X86_64
> > > +       u8 insn_bytes[MAX_INSN_SIZE];
> > > +       struct insn insn;
> > > +       unsigned long addr_ref;
> > > +
> > > +       if (probe_kernel_read(insn_bytes, (void *)regs->ip, MAX_INSN_SIZE))
> > > +               return;
> > > +
> > > +       kernel_insn_init(&insn, insn_bytes, MAX_INSN_SIZE);
> > > +       insn_get_modrm(&insn);
> > > +       insn_get_sib(&insn);
> > > +       addr_ref = (unsigned long)insn_get_addr_ref(&insn, regs);
> [...]
> > > +}
> >
> > Could you refactor this a little bit so that we end up with a helper
> > that does the computation?  Something like:
> >
> > int probe_insn_get_memory_ref(void **addr, size_t *len, void *insn_addr);
> >
> > returns 1 if there was a memory operand and fills in addr and len,
> > returns 0 if there was no memory operand, and returns a negative error
> > on error.
> >
> > I think we're going to want this for #AC handling, too :)
>
> Mmmh... the instruction decoder doesn't currently give us a reliable
> access size though. (I know, I'm using it here regardless, but it
> doesn't really matter here if the decoded size is too big from time to
> time... whereas I imagine that that'd matter quite a bit for #AC
> handling.) IIRC e.g. a MOVZX that loads 1 byte into a 4-byte register
> is decoded as having .opnd_bytes==4; and if you look through
> arch/x86/lib/insn.c, there isn't even anything that would ever set
> ->opnd_bytes to 1. You'd have to add some plumbing to get reliable
> access sizes. I don't want to add a helper for this before the
> underlying infrastructure actually works properly.

Fair enough.  Although, with #AC, we know a priori that the address is
unaligned, so we could at least print "Unaligned access at 0x%lx\n".
But we can certainly leave these details to someone else.

(For context, there are patches floating around to enable a formerly
secret CPU feature to generate #AC on a LOCK instruction that spans a
cache line.)

--Andy

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CALCETrXU-hetnH7CTz-Z2xPDAkawx6GdxGtYo0%3DJqq1YnoXrWg%40mail.gmail.com.
